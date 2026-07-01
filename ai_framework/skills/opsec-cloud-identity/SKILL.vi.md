---
name: opsec-cloud-identity
lang: vi
---

**Ngôn ngữ:** [English](SKILL.md) · Tiếng Việt

> Bản dịch của [`SKILL.md`](SKILL.md). Frontmatter chuẩn nằm ở bản tiếng Anh — đây là bản dịch nội dung.

## Khi nào dùng (When to Use)
Cuộc đánh giá chạm tới một **mặt phẳng điều khiển danh tính hoặc cloud** — Microsoft Entra ID /
Azure, AWS, GCP, hay Active Directory tại chỗ — và việc ẩn mình có ý nghĩa. Dấu hiệu: luồng
OAuth/consent, access/refresh token, ticket Kerberos, hoặc cấu hình audit cloud nằm trong phạm vi.
Bối cảnh đầy đủ và trích dẫn: [`docs/RED_TEAM_OPSEC.md` §7](../../../docs/RED_TEAM_OPSEC.md).

## Điều kiện tiên quyết (Prerequisites)
- Tenant/tài khoản/domain mục tiêu được ủy quyền trong `RunConfig.authorized_targets`.
- Hiểu rằng ở đây bề mặt phát hiện là **log và lần đăng nhập**, không phải EDR trên máy.
- Các bước thay-đổi-trạng-thái (đăng ký thiết bị, tắt log, giả ticket) được **đề xuất cho người vận
  hành duyệt**, không tự chạy.

## Quy trình (Workflow)
1. **Log cloud là mục tiêu Defense-Impairment (ATT&CK T1562.008).** Nếu cuộc đánh giá gồm kiểm thử
   toàn-vẹn-log, hãy biết ba nước đi — dừng (`StopLogging` / sink `disabled=true`), làm không đọc
   được (trỏ lại khóa KMS + thu hồi), chuyển hướng (bucket của kẻ tấn công) — và mỗi cái tự nó là
   một sự kiện đổi cấu hình. Ưu tiên *ghi nhận khoảng mù* hơn là thực thi nó.
2. **Danh tính: ưu tiên token/consent hơn mã độc (T1528 · T1550.001 · T1566).** OAuth consent
   phishing lạm dụng các client ID first-party hợp pháp (ví dụ VS Code) để lấy token `.default`;
   đường nâng cao đổi một refresh token của Authentication Broker lấy một **Primary Refresh Token**
   (SSO). Nhớ rằng PRT *thừa hưởng* một MFA đã thực hiện — nó không đánh bại MFA, và một chính sách
   Conditional Access yêu cầu thiết bị tuân thủ vẫn có thể chặn thiết bị lạ.
3. **AD: giả ticket, bỏ qua người gác (T1558).** Một **Silver Ticket** (TGS giả) không bao giờ chạm
   Domain Controller, nên sự kiện DC (4769) không phát ra — hãy đặt phát hiện ở phía máy chủ/dịch vụ.
4. **Hòa lẫn vào mẫu API/đăng-nhập bình thường**: tái dùng client ID, khu vực, và giờ làm việc được
   kỳ vọng; một token dùng từ vị trí bất khả thi hoặc một phiên `unbound` chính là dấu hiệu.

## Kiểm chứng (đối trọng phát hiện — xác nhận bạn nêu được nó)
- **Token/OAuth:** Entra ID Protection *Anomalous token* (offline), cảnh báo truy-cập-PRT của
  Defender for Endpoint, và tương quan đa-log (`app_id`, `resource_id`, `sign_in_session_status="unbound"`).
- **Log cloud:** sự kiện đổi cấu hình, trail cấp tổ chức, sink bất biến, luật sink-modification.
- **Kerberos:** săn vé RC4 (etype 0x17 — hiếm vì AES mặc định; Server 2025 ngừng RC4), xác thực PAC,
  bất thường 4624/4634 phía máy chủ. (Đừng dùng quy tắc đã bị bác "TGS không có TGT trước = Golden
  Ticket".)
