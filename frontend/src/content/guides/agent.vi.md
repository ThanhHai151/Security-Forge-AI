# Hướng dẫn sử dụng trang Agent (Chuyên gia giám sát)

Trang Agent là một **bảng điều khiển tư vấn**. Bản thân SecForge không gọi mô hình AI và không
tác động vào mục tiêu — nó *lập kế hoạch* cho cuộc đánh giá rồi đưa cho **bạn** một bản tóm tắt để
**bạn** thực thi bằng một coding agent bên ngoài (ví dụ Claude Code). Mọi thứ agent tìm được sẽ
được ghi lại tại đây, nên sổ tay theo dõi độ bao phủ của từng mục tiêu qua nhiều phiên làm việc.

> **Chỉ dùng khi được ủy quyền.** Chỉ kiểm thử hệ thống bạn sở hữu hoặc được phép đánh giá.

## Bố cục

- **Trái — Sổ tay Hermes:** danh sách domain mục tiêu (và các subdomain phát hiện được).
- **Giữa — Danh mục lỗ hổng:** mọi kỹ thuật cho domain đang chọn, mỗi kỹ thuật một trạng thái.
- **Phải — Terminal + ngăn kéo:** nơi dán output của agent, cùng hai ngăn **Ask** và **Plan**.

## Bước 1 — Thêm mục tiêu

1. Tại **Domain mục tiêu** (góc trên bên trái), gõ một domain hoặc URL như `example.com`, rồi nhấn Enter hoặc nút **+**.
2. Để gắn một subdomain phát hiện được vào mục tiêu, bấm **+** ở hàng của mục tiêu đó.
3. **Click** một domain để chọn (danh mục bên phải sẽ cập nhật). **Double-click** — hoặc dùng menu hàng (**⋮ → Xem sơ đồ**) — để mở **sơ đồ tư duy** của nó.

## Bước 2 — Hỏi Chuyên gia giám sát

1. Mở ngăn **Ask** (nút kính lúp ở mép phải).
2. Ở ô **"Bạn muốn kiểm tra lỗi gì?"**, mô tả mục tiêu — ví dụ *"kiểm tra xác thực, phân quyền và endpoint /api/query"*.
3. Chọn **Chế độ quét**:
   - **Nhanh** — vài lớp lỗ hổng tác động cao, giới hạn thời gian (hợp cho phân loại nhanh / CI).
   - **Tiêu chuẩn** — bao phủ cân bằng toàn bộ bề mặt tấn công (mặc định).
   - **Sâu** — toàn diện, chủ động ghép chuỗi lỗ hổng.
4. Bấm **Hỏi chuyên gia giám sát**.

## Bước 3 — Đọc kế hoạch điều tra

Mở ngăn **Plan** để xem **thứ tự điều tra** đã xếp hạng, **loại ứng dụng** được nhận diện
(ví dụ "HR / quản lý nhân sự") và các **skill** được chọn. Bước đầu tiên tự động được đánh dấu
*đang xử lý* (viền vàng trên kỹ thuật đó trong danh mục).

## Bước 4 — Thực thi bằng coding agent của bạn

Đưa kế hoạch và skill cho agent bên ngoài (Claude Code). **SecForge tư vấn; agent thực thi** —
nó làm phần trinh sát, khai thác và tạo bằng chứng (PoC) thực tế trên mục tiêu. SecForge cố ý
không bao giờ tự gửi lưu lượng đến mục tiêu.

## Bước 5 — Báo cáo kết quả về (Terminal → Nạp kết quả)

Dán output thô của agent vào ô **Terminal** rồi bấm **Nạp kết quả**. SecForge lưu nguyên văn và
tự trích các dòng marker sau (mỗi dòng một marker, ở bất kỳ đâu trong văn bản):

```text
CONFIRMED: <tên kỹ thuật> [<mức độ>] — <bằng chứng / cách bạn xác nhận>
NEW_FINDING_TYPE: <nhãn ngắn> — JUSTIFICATION: <vì sao không thuộc nhóm có sẵn>
```

- `[<mức độ>]` không bắt buộc nhưng nên có: một trong `critical | high | medium | low | info`. Nó đặt mức độ cho báo cáo/SARIF của phát hiện đó (ví dụ lộ credential thật hoặc ghi toàn bộ CSDL không cần xác thực = `critical`).
- Nạp kết quả chỉ có thể nâng phát hiện lên **chưa xác nhận**. Đánh dấu **đã xác nhận** luôn là hành động có chủ đích của con người trong danh mục (Bước 6).

## Bước 6 — Theo dõi độ bao phủ (Danh mục lỗ hổng)

Ở cột giữa, dùng dropdown của mỗi kỹ thuật để đặt trạng thái — **chưa kiểm tra**, **chưa xác nhận**
hoặc **đã xác nhận** — và dùng bộ lọc để chỉ hiện một trạng thái. Click một kỹ thuật để xem nhanh
chuỗi khai thác; double-click để mở sơ đồ tư duy đầy đủ tập trung vào nó.

## Bước 7 — Xuất báo cáo

Bấm **Tải SARIF** để xuất các phát hiện đã/chưa xác nhận của domain thành tệp **SARIF 2.1.0** —
sẵn sàng tải lên CI hoặc GitHub code scanning. Mức độ lấy từ severity đã ghi của từng phát hiện
(nếu trống thì dùng mặc định theo lớp lỗ hổng).

## Cần biết

- Chế độ **Liên tục** đang khóa (đang thiết kế lại) — hãy dùng **Chạy đơn**.
- Sổ tay chỉ dành cho red-team. Rà soát mã nguồn và quét phụ thuộc nằm ở trang **Phòng thủ**.
- Không thao tác nào ở đây tự gây hại: SecForge chỉ tư vấn và ghi nhận — agent bên ngoài mới là bên hành động.
