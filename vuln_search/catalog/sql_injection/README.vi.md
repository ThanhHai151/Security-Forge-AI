# SQL Injection (Tấn công chèn mã SQL)

> Dữ liệu không tin cậy làm thay đổi câu truy vấn SQL, dẫn tới lộ hoặc sửa đổi cơ sở dữ liệu.
> **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/sql_injection.md`](../../../../Troubleshooting_Guide/sql_injection.md) ·
> **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** SQLi · A03:2021 Injection
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
SQL injection xảy ra khi dữ liệu người dùng nhập vào bị ghép trực tiếp vào câu lệnh SQL thay vì
được truyền dưới dạng tham số ràng buộc (bound parameter). Khi đó cơ sở dữ liệu sẽ phân tích phần
văn bản của kẻ tấn công như *cú pháp* truy vấn, cho phép họ thay đổi hành vi câu lệnh — đọc các bản
ghi khác, vượt qua xác thực, và trong một số cấu hình còn đọc/ghi file hoặc chạy lệnh hệ thống.

## Cơ chế hoạt động (How it works)
Ứng dụng dựng câu lệnh kiểu `… WHERE id = '` + input + `'`. Nhập `' OR '1'='1` làm điều kiện luôn
đúng; nhập `' UNION SELECT username,password FROM users-- ` ghép thêm một tập kết quả. Các biến thể:
- **In-band / UNION** — dữ liệu trả về trực tiếp trong phản hồi.
- **Blind boolean** — suy luận dữ liệu qua khác biệt đúng/sai trong phản hồi.
- **Blind time-based** — `SLEEP(5)` / `pg_sleep(5)` để suy luận dữ liệu qua độ trễ phản hồi.
- **Out-of-band** — rò rỉ dữ liệu qua DNS/HTTP khi kênh in-band bị chặn.

## Tác động (Impact)
Đọc (và thường là ghi) toàn bộ dữ liệu ứng dụng; vượt qua xác thực; trên một số nền tảng có thể
đọc/ghi file và RCE (`xp_cmdshell`, `INTO OUTFILE`, stacked queries). Thường là lỗ hổng mức
nghiêm trọng (critical), đủ gây rò rỉ dữ liệu quy mô lớn.

## Cách phát hiện (How to detect)
- Một dấu nháy đơn `'` gây lỗi 500 / lỗi SQL hoặc làm thay đổi kết quả.
- Payload boolean (`' AND 1=1--` so với `' AND 1=2--`) làm đảo phản hồi.
- Payload thời gian tạo độ trễ đo được và có thể kiểm soát.
- Ngữ cảnh số phản ứng với phép toán `1`, `1-0`, `1*1`.

## Khai thác (tóm tắt) (Exploitation)
Xác định điểm injection và ngữ cảnh (chuỗi hay số, kiểu dấu nháy), xác định số cột
(`ORDER BY` / `UNION SELECT NULL,…`), rồi trích xuất bằng UNION hoặc suy luận blind. Tự động hóa
bằng `sqlmap` sau khi đã xác nhận điểm khai thác. Bộ payload đầy đủ nằm trong tài liệu chuyên sâu.

## Phòng chống (Defenses)
1. **Truy vấn tham số hóa / prepared statement** ở mọi nơi (giải pháp gốc rễ).
2. Dùng ORM an toàn — không ghép chuỗi thô vào truy vấn.
3. Tài khoản DB theo nguyên tắc đặc quyền tối thiểu; tắt các tính năng nguy hiểm (stacked queries,
   `xp_cmdshell`).
4. Kiểm tra đầu vào theo danh sách cho phép (allow-list); WAF chỉ là lớp phòng thủ bổ sung, không
   phải biện pháp chính.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=SQL+Injection (thêm sản phẩm + phiên bản)
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=SQL+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=SQL+Injection (lọc Type=webapps)
- **GitHub Advisories** — https://github.com/advisories?query=sql+injection
- **OSV** — https://osv.dev/list?q=sql%20injection (gói mã nguồn mở)
- **Cộng đồng** — r/netsec, HackerOne Hacktivity (`weakness:"SQL Injection"`), blog PSIRT của hãng.
- _Mẹo tìm kiếm: xuất phát từ dấu hiệu sản phẩm phát hiện khi recon, ví dụ_
  `"<tên CMS> <phiên bản>" SQL injection`.

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2023-34362` — SQL injection trong MOVEit Transfer, bị nhóm Cl0p khai thác hàng loạt để đánh
  cắp dữ liệu.
- `CVE-2021-27101` — SQL injection trong Accellion FTA, dùng trong nhiều vụ rò rỉ dữ liệu.
- _Ví dụ kinh điển thời chưa có CVE: vô số ứng dụng ASP/PHP khoảng 2005–2010; xem "Bobby Tables", xkcd 327._

## Tham khảo (References)
- PortSwigger Web Security Academy — SQL injection.
- OWASP — SQL Injection Prevention Cheat Sheet.
