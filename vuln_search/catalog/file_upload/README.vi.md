# File Upload Vulnerabilities

> Upload không giới hạn cho phép kẻ tấn công cài đặt web shell hoặc ghi đè tệp. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/file_upload_bsv.md`](../../../../Troubleshooting_Guide/file_upload_bsv.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A04:2021 Insecure Design
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Lỗ hổng upload tệp xảy ra khi ứng dụng cho phép người dùng tải lên tệp mà không kiểm tra đầy đủ
tên, loại, nội dung, hoặc nơi lưu trữ của chúng. Nếu sau đó máy chủ phục vụ hoặc thực thi các tệp đó,
kẻ tấn công có thể cài đặt một web shell hoặc ghi đè các tệp nhạy cảm.

## Cơ chế hoạt động (How it works)
Kẻ tấn công kiểm soát tên tệp, `Content-Type` khai báo, phần mở rộng, và các byte của tệp. Ứng dụng
kiểm tra sai cách: nó tin tưởng kiểu MIME do client cung cấp, chỉ kiểm tra một danh sách chặn
(blocklist) các phần mở rộng, hoặc lưu tệp bên trong web root nơi máy chủ sẽ thực thi nó. Upload một
tệp `.php`/`.jsp`/`.aspx` (hoặc vượt bộ lọc) rồi yêu cầu nó sẽ chạy mã của kẻ tấn công. Các thất bại
khác bao gồm path traversal trong tên tệp (ghi ra ngoài thư mục dự kiến), trình phân tích đi theo các
tham chiếu nhúng (SVG/XML XXE), và các tệp polyglot vừa thỏa mãn bộ kiểm tra vừa vẫn thực thi được.

## Tác động (Impact)
Thực thi mã từ xa (RCE) qua một web shell được cài đặt là hậu quả nổi bật nhất — chiếm toàn bộ máy chủ.
Các kết quả ít nghiêm trọng hơn nhưng vẫn đáng kể bao gồm ghi đè các tệp hiện có (cấu hình, nội dung
của người dùng khác), stored XSS qua HTML/SVG được tải lên, SSRF/đọc tệp thông qua XXE trong trình phân
tích ảnh, và từ chối dịch vụ qua các tệp quá khổ. Các trường hợp có khả năng RCE là nghiêm trọng.

## Cách phát hiện (How to detect)
- Tải lên một script vô hại (ví dụ một tệp `.php` in ra một marker) và yêu cầu URL đã lưu; việc thực
  thi marker xác nhận RCE.
- Dò logic bộ lọc: đổi header `Content-Type`, thử các phần mở rộng thay thế/kép
  (`shell.php.jpg`, `shell.pHp`, `shell.php5`, dấu chấm/khoảng trắng ở cuối, null byte), và kiểm tra
  xem việc xác thực dựa trên phần mở rộng, MIME, hay magic byte.
- Theo dõi phản hồi/header để tìm đường dẫn đã lưu; thử `../` trong tên tệp, và thử upload SVG/XML để
  làm lộ XXE.

## Khai thác (tóm tắt) (Exploitation)
Động tác cốt lõi là đưa một tệp thực thi được vào một vị trí mà máy chủ sẽ chạy, đánh bại bất kỳ cơ chế
xác thực nào đang có. Các kỹ thuật vượt qua bao gồm giả mạo `Content-Type: image/jpeg` trên một tệp
PHP, lạm dụng lỗ hổng của blocklist (`.phtml`, `.php5`, thay đổi chữ hoa/làm rối), thêm magic byte hợp
lệ hoặc `GIF89a` vào đầu để tạo polyglot, khai thác cấu hình `.htaccess`/máy chủ để làm cho một phần mở
rộng mới có thể thực thi, và dùng tên tệp đầy `../` để ghi ra ngoài thư mục upload. Upload SVG có thể
mang theo XXE để đọc tệp hoặc SSRF. Khi một web shell đã được cài đặt, yêu cầu nó với một tham số `cmd`
để chạy lệnh.

## Phòng chống (Defenses)
1. **Xác thực bằng danh sách cho phép (allow-list)** các phần mở rộng được phép và kiểm tra nội dung
   thực tế (magic byte / phát hiện kiểu phía máy chủ), không phải `Content-Type` do client cung cấp.
2. **Lưu các tệp upload bên ngoài web root** (hoặc trong object storage) và phục vụ chúng qua một handler
   đặt `Content-Disposition: attachment` và một `Content-Type` vô hại — không bao giờ để thư mục upload
   thực thi.
3. **Tạo tên tệp đã lưu** ở phía máy chủ (ngẫu nhiên/UUID); loại bỏ các thành phần đường dẫn để tên do
   kẻ tấn công cung cấp không thể traverse thư mục hoặc ghi đè các tệp hiện có.
4. **Tắt thực thi trong đường dẫn upload** (cấu hình web server: không có handler PHP/CGI, bỏ qua
   `.htaccess`) và áp đặt giới hạn kích thước.
5. Đối với upload ảnh/XML, mã hóa lại hoặc làm sạch tệp và tắt phân giải external-entity để vô hiệu hóa
   SVG/XXE và polyglot.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=File+Upload+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=File+Upload+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=File+Upload+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=File+Upload+Vulnerabilities
- **OSV** — https://osv.dev/list?q=File+Upload+Vulnerabilities
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `File Upload Vulnerabilities <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2017-12615` — Apache Tomcat: upload JSP qua phương thức PUT dẫn đến thực thi mã từ xa.
- `CVE-2021-22005` — VMware vCenter Server upload tệp tùy ý vào dịch vụ Analytics, nối chuỗi tới RCE.
- `CVE-2018-9206` — jQuery File Upload (Blueimp) upload không giới hạn, bị khai thác rộng rãi để cài web shell.

## Tham khảo (References)
- PortSwigger Web Security Academy — File upload vulnerabilities.
- OWASP — File Upload Cheat Sheet.
- OWASP — Unrestricted File Upload (Testing Guide / community page).
