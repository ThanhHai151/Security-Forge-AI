# Hướng dẫn sử dụng trang Phòng thủ

Trang Phòng thủ rà soát một **thư mục dự án cục bộ** theo hai cách cùng lúc: **rà soát mã nguồn
tĩnh** quét source theo các lớp lỗ hổng đã ghi nhận, và **quét phụ thuộc (SCA)** để phát hiện các
gói có lỗ hổng đã biết. Mọi phát hiện đều là *đề xuất* — SecForge không bao giờ sửa mã của bạn.

> **Chỉ dùng khi được ủy quyền.** Chỉ rà soát dự án bạn sở hữu hoặc được phép đánh giá.

## Bước 1 — Trỏ tới dự án

Trong ô nhập, nhập **đường dẫn tuyệt đối** tới thư mục dự án cần rà soát, ví dụ
`D:\projects\my-app` (Windows) hoặc `/home/me/my-app` (Linux/macOS). Nhấn Enter hoặc bấm **Rà soát**.

## Bước 2 — (Tùy chọn) bật kiểm tra advisory trực tuyến

Tích **Kiểm tra advisory trực tuyến (OSV)** để đối chiếu phụ thuộc với cơ sở dữ liệu lỗ hổng OSV
công khai. Để **tắt** nếu muốn chạy hoàn toàn offline — phần rà soát mã vẫn hoạt động bình thường;
chỉ việc tra CVE của phụ thuộc mới cần mạng.

## Bước 3 — Chạy rà soát

Bấm **Rà soát**. Khi hoàn tất, tối đa hai mục sẽ hiện ra:

### Rà soát mã

Mỗi phát hiện hiển thị:

- huy hiệu **mức độ** (nghiêm trọng / cao / trung bình / thấp),
- **tệp:dòng** nơi phát hiện,
- một **thông điệp** ngắn mô tả vấn đề,
- **đoạn mã** vi phạm, và
- phần **khắc phục** mở rộng được, kèm hướng dẫn gia cố cụ thể theo lớp lỗ hổng.

Đầu mục có bảng đếm theo mức độ và số tệp đã quét. "Không có phát hiện" nghĩa là không khớp bộ chữ
ký — không đảm bảo mã an toàn tuyệt đối.

### Phụ thuộc

Các gói có lỗ hổng được liệt kê kèm:

- **tên@phiên_bản** của gói,
- **hệ sinh thái** và **nguồn** khai báo,
- các **advisory** có liên kết (bấm vào mã advisory để mở), và
- phiên bản mỗi lỗi được **sửa ở**.

Khi tắt kiểm tra trực tuyến, mục này hiển thị một gợi ý thay vì kết quả.

## Cần biết

- **Rà soát mã** dựa trên chữ ký trên tệp nguồn; **quét phụ thuộc** phân tích các tệp khai báo
  (ví dụ `package.json`, `requirements.txt`) rồi đối chiếu với advisory.
- Các phát hiện **chỉ mang tính tư vấn** — hãy tự áp dụng bản vá, rồi chạy lại để xác nhận lỗi đã hết.
- Trang này độc lập: nó không đưa dữ liệu vào sổ tay của trang Agent.
