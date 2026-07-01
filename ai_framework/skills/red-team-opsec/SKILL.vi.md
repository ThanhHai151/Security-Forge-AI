---
name: red-team-opsec
lang: vi
---

**Ngôn ngữ:** [English](SKILL.md) · Tiếng Việt

> Bản dịch của [`SKILL.md`](SKILL.md). Frontmatter chuẩn (tags, mappings, version) nằm ở bản
> tiếng Anh — đây là bản dịch phần nội dung.

## Khi nào dùng (When to Use)
Mọi cuộc đánh giá được ủy quyền mà việc không bị phát hiện có ý nghĩa (tức là theo mặc định). Nạp
skill này trước khi hành động trên mục tiêu trực tiếp, bất cứ khi nào bạn sắp sinh lưu lượng
mạng/máy chủ, hoặc khi cân nhắc một hành động ồn ào hơn có đáng hay không.

## Điều kiện tiên quyết (Prerequisites)
- Có ủy quyền/Rules of Engagement đã ký; host mục tiêu nằm trong `RunConfig.authorized_targets`.
- Có OPSEC pacing (`opsec_min_interval` / `opsec_jitter`) cho công việc trực tiếp.
- Tham chiếu sâu: [`docs/RED_TEAM_OPSEC.md`](../../../docs/RED_TEAM_OPSEC.md) (§0 ủy quyền,
  §1 Kim tự tháp Đau đớn, §2–§8 các lớp, §10 bản đồ nhanh ATT&CK).

## Quy trình (Workflow)
1. **Ủy quyền trước (§0).** Xác nhận mục tiêu trong phạm vi. Một manh mối ngoài phạm vi thì *ghi
   nhận và để yên* — không bao giờ theo đuổi.
2. **Chọn hành động ít-ồn-ào-nhất mà vẫn chứng minh được luận điểm.** Ưu tiên recon chỉ-đọc; một
   hành động thay-đổi-trạng-thái (`mutating`) phải được đề xuất cho người vận hành duyệt, không tự
   chạy.
3. **Biết mình đang ở đâu trên Kim tự tháp Đau đớn (§1).** Xoay IP / giả múi giờ là nước đi *rẻ và
   yếu nhất*. Né tránh bền vững là định hình lại vân tay công cụ/hành vi (JA4+, nhịp beacon) và TTP
   — đừng đốt công sức ở đáy kim tự tháp.
4. **Pacing + hòa lẫn (§2–§4).** Thêm khoảng nghỉ + jitter để nhịp không thành beacon; ưu tiên sống
   nhờ đất liền (LOTL) và lưu lượng trông hợp pháp thay vì để lại tạo tác lộ liễu.
5. **Chú ý các bề mặt tầng cao (§5–§8).** Danh tính/cloud (OAuth/token, Kerberos, toàn vẹn log
   cloud) và telemetry endpoint (EDR/ETW/AMSI) bị theo dõi sát như mạng; nạp skill tương ứng
   (`opsec-cloud-identity`, …) khi bề mặt đó có liên quan.
6. **Ghi nhận, đừng phá hủy (§0, §6).** Giữ nhật ký chính xác, có dấu thời gian cho mọi hành động;
   không bao giờ xóa log của khách hàng, làm hỏng dữ liệu, hay chống-pháp-y có tính phá hủy.

## Kiểm chứng (Verification)
- Mọi hành động có thể tái lập từ request/bước đã ghi log (chuỗi kiểm toán còn nguyên).
- Không chạm vào tài sản ngoài phạm vi; không phá hủy bằng chứng của khách hàng.
- Với mỗi hành động dễ bị chú ý, bạn có thể nêu **đối trọng phát hiện** của nó (người phòng thủ sẽ
  thấy nó ra sao) — nếu không nêu được, hãy tra mục tương ứng trong tài liệu sâu trước khi tiếp tục.
