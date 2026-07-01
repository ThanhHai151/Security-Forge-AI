---
name: opsec-endpoint-evasion
lang: vi
---

**Ngôn ngữ:** [English](SKILL.md) · Tiếng Việt

> Bản dịch của [`SKILL.md`](SKILL.md). Frontmatter chuẩn nằm ở bản tiếng Anh — đây là bản dịch nội dung.

## Khi nào dùng (When to Use)
Cuộc đánh giá liên quan tới một **endpoint** (Windows, macOS, Linux, hoặc container) và bạn cần suy
luận về những gì EDR/telemetry của nó thấy được, hoặc về cách một payload được phát tán và cái gì
chặn nó. Skill này chỉ ở mức khái niệm + phát hiện — không có công thức bypass. Chiều sâu và nguồn:
[`docs/RED_TEAM_OPSEC.md` §8](../../../docs/RED_TEAM_OPSEC.md).

## Điều kiện tiên quyết (Prerequisites)
- Mục tiêu được ủy quyền; mọi hành động thay-đổi-trạng-thái được đề xuất cho người vận hành duyệt,
  không tự chạy.
- Biết cú tách ATT&CK v19: can thiệp kiểm soát là **Defense Impairment (TA0112)**; che giấu thuần
  túy là **Stealth (TA0005)** (§1).

## Quy trình (suy luận theo từng bề mặt)
1. **EDR Windows (§8.1).** Telemetry đến từ hook user-mode, kernel callback, và ETW. Các né tránh
   mức khái niệm (unhooking, direct/indirect syscall, can thiệp ETW/AMSI, BYOVD) đều là Defense
   Impairment — hãy coi chúng là *ồn ào với sensor nguồn-từ-kernel*, không miễn phí.
2. **macOS (§8.2).** Rào chắn: TCC (đồng thuận), Gatekeeper + notarization, `com.apple.quarantine`;
   EDR tiêu thụ Endpoint Security Framework (ESF). Từ **macOS 15.4**, ESF phát
   `ES_EVENT_TYPE_NOTIFY_TCC_MODIFY`, nên việc cấp/thu-hồi TCC nay quan sát được nguyên bản.
3. **Linux (§8.2).** Tấn công và phòng thủ cùng sống ở eBPF; tradecraft cổ điển (`LD_PRELOAD`,
   `memfd_create` không-tệp) bị đối phó bởi auditd và các sensor eBPF (Falco/Tetragon).
4. **Container/K8s (§8.2).** Dấu chân dịch sang đánh cắp token service-account, lạm dụng RBAC, và
   thoát container; phát hiện runtime là Falco + eBPF + K8s audit log.
5. **Phát tán (§8.3).** HTML smuggling (T1027.006) và ISO/LNK ưa tước bỏ **Mark-of-the-Web**; phòng
   thủ là lan truyền MOTW + SmartScreen + luật ASR.

## Kiểm chứng (nêu phát hiện cho từng bề mặt)
- **Windows:** phân tích call-stack kernel-ETW, Vulnerable-Driver Blocklist/HVCI, vắng-mặt-telemetry.
- **macOS:** sự kiện ESF `TCC_MODIFY` (15.4+) kèm ngữ cảnh instigator/service/right/reason; trước
  15.4 người phòng thủ chỉ có các thông điệp log riêng, mong manh của TCC daemon.
- **Linux/container:** luật runtime eBPF/Falco/Tetragon, auditd, K8s audit logging.
- **Phát tán:** Protected View / chặn macro trên tệp có MOTW, SmartScreen, luật ASR chặn tiến-trình-con.

> **Lưu ý:** phần endpoint/C2 của §8 rộng hơn mức được kiểm chứng đa-nguồn sâu (xem ghi chú độ phủ
> trong doc). Hãy coi chúng là chỉ dẫn tới các nguồn gốc trích trong §8/§12, không phải sự thật đã
> chốt — kiểm lại chi tiết hiện hành trước khi dựa vào.
