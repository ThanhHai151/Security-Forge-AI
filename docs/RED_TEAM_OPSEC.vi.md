# OPSEC, Ẩn mình & Né tránh cho Red-Team — tài liệu tham chiếu về tradecraft

> **Ngôn ngữ:** [English](RED_TEAM_OPSEC.md) · Tiếng Việt
>
> **Là gì:** một tài liệu tham chiếu mang tính khái niệm về cách một red team thực thụ giữ
> bí mật trong một cuộc đánh giá **được ủy quyền** — che giấu nguồn gốc của mình, hòa lẫn vào
> mạng và máy chủ của mục tiêu, quản lý các tạo tác (artifact) để lại, và tránh tự phơi bày
> danh tính — và, với mỗi khái niệm tấn công, là **đối trọng phát hiện của blue team** bắt được nó.
>
> **Vì sao nằm ở đây:** SecForge vừa là một framework tấn công ([`ai_framework/`](../ai_framework/README.md))
> vừa là một framework phòng thủ ([`defense/`](../defense/README.md)). Tradecraft ẩn mình là
> lớp phương pháp luận còn thiếu giữa hai bên: agent cần nó để mô phỏng một đối thủ thực thụ,
> và trụ cột phòng thủ cần nửa *phát hiện* để gia cố mục tiêu chống lại đúng những nước đi này.
> Tệp này là nguồn chung cho cả hai.
>
> **Phạm vi & an toàn:** đây là các nguyên tắc và phần *lý do* (tradecraft, mã MITRE ATT&CK, các
> tình huống thực tế, phát hiện), **không phải** vũ khí hóa — không có cấu hình cho người vận hành,
> hồ sơ malleable-C2, mã bypass, hay hướng dẫn thiết lập từng bước. Nó được viết chỉ dành cho công
> việc được ủy quyền, và cố ý ghép mỗi khái niệm né tránh với cách người phòng thủ nhìn thấy nó.
> Một số năng lực đã **thay đổi về tính khả thi theo thời gian** (và chính taxonomy của MITRE đã
> đổi vào 2025); những chỗ đó được đánh dấu ngay tại chỗ. Chỉ tiếng Anh (quy tắc dự án — bản dịch
> tiếng Việt này là ngoại lệ được yêu cầu rõ ràng).

Tài liệu này là phương pháp luận, không phải mã. Nó bổ trợ cho kho ngữ liệu lỗ hổng
([`KNOWLEDGE_BASE.md`](KNOWLEDGE_BASE.md)) — kho đó trả lời *"làm sao tôi tìm và chứng minh một
lỗ hổng?"*, còn tệp này trả lời *"một đối thủ thực thụ vận hành mà không bị nhìn thấy như thế nào,
và điều đó vẫn bị nhìn thấy ra sao?"* [System prompt của agent](../ai_framework/agent/system.py)
mang một phiên bản nén của §0–§1 làm các quy tắc thường trực cho mọi lần chạy.

---

## 0. Ủy quyền là toàn bộ cuộc chơi (đọc trước tiên)

Mọi thứ bên dưới **chỉ** hợp pháp và có đạo đức bên trong một cuộc đánh giá đã ký kết. Ranh giới duy
nhất tách một red teamer khỏi một tội phạm không phải là kỹ năng hay công cụ — mà là **sự ủy quyền và
ý định**. Thiếu một Rules of Engagement (RoE) đã ký và ủy quyền bằng văn bản, hoạt động y hệt là một
trọng tội theo **Đạo luật Lạm dụng và Gian lận Máy tính (CFAA)** của Hoa Kỳ (**18 U.S.C. § 1030**) và
các luật tương đương trên toàn thế giới. Quy tắc cứng của SecForge ("chỉ hành động chống lại các mục
tiêu được ủy quyền") không phải hình thức; nó là tiền đề khiến toàn bộ ngành này trở nên hợp pháp.

Trước bất kỳ hoạt động bí mật nào, một cuộc đánh giá thực thụ thiết lập:

- **Ủy quyền bằng văn bản** — một thư ủy quyền/phạm vi đã ký (tấm thư "get-out-of-jail-free") nêu tên
  các tài sản, dải IP, tên miền, và tài khoản trong phạm vi, các khung thời gian, và người ký của
  khách hàng có thẩm quyền cho phép. **NIST SP 800-115** coi ủy quyền bằng văn bản và RoE là những
  thành tố nền tảng được lập tài liệu *trước* bất kỳ kiểm thử kỹ thuật nào, và đi kèm một mẫu RoE
  chuyên biệt trong **Phụ lục B**. Ủy quyền phải được ký bởi một đại diện có thẩm quyền của tổ chức
  mục tiêu — không chỉ là một đầu mối IT.
- **Rules of Engagement (RoE)** — PTES tách hai khái niệm trong giai đoạn tiền cam kết: **phạm vi** =
  *cái gì* có thể được kiểm thử (với các loại trừ/tài nguyên cấm rõ ràng), và **RoE** = *cách* cuộc
  kiểm thử được tiến hành, những kỹ thuật nào được phép (ví dụ: social engineering có trong phạm vi
  không? phishing thật? tấn công từ chối dịch vụ — *không bao giờ* theo mặc định?), quy tắc xử lý dữ
  liệu, và các đầu mối leo thang. Vượt phạm vi (scope creep) là rủi ro pháp lý thực sự, không phải
  một sơ suất về phong cách.
- **Deconfliction (giải trừ xung đột)** — một kênh đã thỏa thuận trước và một đường liên lạc tin cậy
  để khi blue team phát hiện red team, đội ứng cứu có thể xác nhận "đó là cuộc kiểm thử được ủy quyền,
  đứng yên" thay vì kích hoạt một sự cố thật, lãng phí công sức IR, hành động pháp lý, hoặc chuyển giao
  cho cơ quan thực thi pháp luật.
- **Một điểm dừng cứng tại ranh giới phạm vi.** Một manh mối hứa hẹn nhưng ngoài phạm vi sẽ được **ghi
  nhận và để yên** — không bao giờ theo đuổi. Điều này phản chiếu quy tắc thường trực của agent.

> **Cốt lõi đạo đức — ghi nhận, đừng phá hủy.** Một tội phạm xóa bằng chứng để trốn tránh hậu quả.
> Một red team được ủy quyền làm điều ngược lại: nó giữ một **nhật ký có dấu thời gian, tỉ mỉ về mọi
> hành động** để cuộc đánh giá có thể tái lập, khách hàng có thể học hỏi, và chuỗi giám sát bằng chứng
> (chain-of-custody) được bảo toàn. "Xóa dấu chân của bạn" trong tài liệu này nghĩa là hiểu cách kẻ
> tấn công *giảm* dấu chân của chúng (và cách người phòng thủ phát hiện điều đó) — **không phải** thực
> hiện chống-pháp-y có tính phá hủy đối với hệ thống của khách hàng. Không bao giờ xóa log của khách
> hàng, làm hỏng dữ liệu của họ, hay làm suy giảm khả năng điều tra của họ. Hành vi chống-pháp-y hoặc
> can thiệp log chỉ được thực hiện **khi** đã được ủy quyền trước rõ ràng trong RoE, đối với một tạo
> tác được kiểm soát, có thông báo, và được ghi log — chuẩn mực là tính tái lập, không phải sự phá hủy.

Phần còn lại của tài liệu này giả định mọi kỹ thuật đều được thực hiện bên trong những rào chắn này.

---

## 1. Nền tảng OPSEC — chỉ dấu, dấu chân, và Kim tự tháp Đau đớn

**Operational Security (OPSEC)** là một kỷ luật năm bước của chính phủ/Bộ Quốc phòng Hoa Kỳ (NIST/CNSSI):
*xác định thông tin & chỉ dấu trọng yếu → phân tích mối đe dọa → phân tích điểm yếu → đánh giá rủi ro →
áp dụng biện pháp đối phó.* Nó có tính **chu kỳ**, không hoàn toàn tuần tự. Áp dụng vào an ninh tấn công,
các vai trò bị đảo ngược — "đối thủ" cần bị chối bỏ chính là **blue team / SOC** — và "thông tin trọng
yếu" mà người vận hành phải bảo vệ là bất cứ điều gì cho phép người phòng thủ **phát hiện, quy kết, hoặc
trục xuất** họ (ý định, năng lực, hoạt động, và các giới hạn của cuộc đánh giá).

Hai khái niệm xuyên suốt toàn bộ chủ đề:

- **Chỉ dấu (Indicator / IoC).** Dữ liệu bắt nguồn từ một hành động có thể phát hiện mà đối thủ có thể
  ghép lại — "một mảnh của một câu đố lớn hơn." Ví dụ của người vận hành: một IP nguồn, một tên miền,
  một hash tệp, một dấu vân tay TLS, một user-agent đặc trưng, một khoảng nhịp beacon nhất quán, một
  dấu thời gian, một locale bàn phím. Mỗi chỉ dấu là một sợi chỉ mà người phòng thủ có thể kéo.
- **Dấu chân (Footprint).** Tổng thể dấu vết quan sát được mà một chiến dịch để lại trên các bề mặt
  mạng, máy chủ, danh tính, và OSINT. Tradecraft tốt *giảm thiểu* và *chuẩn hóa* dấu chân để nó hòa lẫn
  với hoạt động hợp pháp thay vì loại bỏ nó (bạn không thể loại bỏ).

### Kim tự tháp Đau đớn (mô hình tư duy cho toàn bộ §2–§6)

**Pyramid of Pain** của David Bianco (2013) xếp hạng các chỉ dấu theo mức độ nó tốn kém cho *đối thủ*
khi người phòng thủ chối bỏ chúng:

| Tầng | Chỉ dấu | Chi phí để người vận hành thay đổi |
|------|---------|-------------------------------------|
| Đáy | Giá trị hash | Không đáng kể |
| ↓ | **Địa chỉ IP** | **Không đáng kể** |
| ↓ | Tên miền | Phiền toái (tiền bạc, lan truyền DNS) |
| ↓ | Tạo tác mạng/máy chủ | Phiền toái |
| ↓ | Công cụ | Thách thức |
| Đỉnh | **TTP** (chiến thuật, kỹ thuật, quy trình) | **Khó — không thể dễ dàng từ bỏ phương pháp của mình** |

Bài học cốt lõi, và cách diễn đạt trung thực cho chính các ví dụ của người dùng: **đổi một IP nguồn
("IP giả") là nước đi rẻ nhất có thể — rẻ cho người vận hành *và* rẻ cho người phòng thủ để đánh bại.**
Cuộc so kè bền vững diễn ra gần *đỉnh* kim tự tháp, tại các dấu vân tay công cụ/hành vi (JA3/JARM, các
mẫu beaconing) và TTP. Một chiến dịch chỉ xoay vòng IP và giả mạo múi giờ thì chưa thay đổi được điều gì
thực sự làm tổn thương một người phòng thủ có năng lực.

*Nguồn: attackiq.com/glossary/pyramid-of-pain-2, activecountermeasures.com "hunt what hurts",
Bianco (2013).*

### Taxonomy né tránh — MITRE ATT&CK (cú tách tactic của 2025)

> **Thay đổi framework — ĐÃ XÁC NHẬN, không phải "trôi dạt" (kiểm chứng trạng thái hiện tại tại
> attack.mitre.org).** Tactic lịch sử **Defense Evasion (TA0005)** đã được **tách thành hai tactic**
> trong ATT&CK hiện hành (v19):
> - **TA0005 được đổi tên thành "Stealth"** — các hành vi *che giấu* thuần túy: né tránh, làm rối, hoặc
>   bắt chước hoạt động bình thường để không thể phân biệt với hoạt động lành tính, **mà không** sửa đổi
>   các kiểm soát an ninh.
> - **TA0112 "Defense Impairment"** (mới) — các kỹ thuật *làm suy yếu, vô hiệu hóa, hoặc can thiệp* các
>   kiểm soát an ninh, pipeline, và công cụ để người phòng thủ mất khả năng quan sát.
>
> Việc tái tổ chức là có thật: **Impair Defenses (T1562)** cũ và các sub-technique của nó
> (.001 Disable/Modify Tools, .006 Indicator Blocking) đã được gộp vào **T1685 "Disable or Modify Tools"**
> mới dưới TA0112; **T1687 "Exploitation for Defense Impairment"** được thêm vào và "Exploitation for
> Defense Evasion" cũ được đổi tên thành **T1211 "Exploitation for Stealth."** Bất kỳ báo cáo/phát hiện
> nào vẫn ánh xạ tới "TA0005 = né tránh+làm suy yếu" hoặc tới T1562.001/.006 nay có một điểm mù ở cấp
> tactic. **Các mỏ neo ổn định là các ID kỹ thuật** (T1070, T1036, T1027, T1218, T1055, T1497…), vốn
> tồn tại qua lần đổi tên; tài liệu trước 2025 gọi TA0005 là "Defense Evasion" với ~40 kỹ thuật phản
> ánh phiên bản ≤ v18. Hãy trích dẫn các URL có phiên bản cho taxonomy lịch sử.

Về mặt khái niệm, các kỹ thuật một người vận hành dùng để ẩn mình vẫn rơi vào các họ dễ nhận biết —
Masquerading (T1036), Indicator Removal (T1070), nội dung Obfuscated/Encrypted (T1027), System Binary
Proxy Execution (T1218), Process Injection (T1055), Virtualization/Sandbox Evasion (T1497), và tập
can-thiệp-kiểm-soát nay đã tách riêng dưới TA0112. Tài liệu này tổ chức chúng thành **năm lớp vận hành
(§2–§6)** và ánh xạ chúng lại trong bảng ở §8, độc lập với việc gán nhãn tactic của MITRE.

---

## 2. Mạng & hạ tầng — che giấu nguồn ("IP giả")

### Tradecraft (phần *lý do*)

- **Đây là vấn đề proxy (ATT&CK T1090).** Che giấu nguồn nằm dưới Command-and-Control → **Proxy**:
  định tuyến qua một trung gian "để tránh các kết nối trực tiếp" và che đích C2 thật. Các sub-technique:
  Internal (.001), External (.002), Multi-hop (.003), Domain Fronting (.004). (attack.mitre.org/techniques/T1090)
- **Redirector, không phải kết nối trực tiếp.** Một **redirector** là một host dùng-một-lần, hướng ra
  internet, đứng trước team server để mục tiêu không bao giờ chạm vào backend. Khi người phòng thủ chặn
  IP callback, họ chỉ đốt redirector, vốn "dễ dàng thay thế mà không phải xây lại team server." Đây
  chính là lý do một IP nguồn tĩnh đơn lẻ là một thất bại OPSEC: nó là một điểm xoay bền vững mà, một
  khi bị đánh dấu, tương quan *toàn bộ* hoạt động từng chạm vào nó. (bluescreenofjeff Red-Team-Infrastructure-Wiki)
- **Đánh đổi VPN vs Tor.** Một VPN là một trung gian *có thể thấy* IP + đích của bạn và có thể ghi log
  hoặc bị buộc cung cấp — **kín đáo nhưng có thể quy kết**. Tor phân tán sự tin cậy qua ~hàng nghìn
  relay (guard biết IP của bạn, exit biết đích của bạn, tách biệt về mặt cấu trúc) — **không thể quy kết
  theo thiết kế nhưng lộ liễu**: danh sách exit-node là công khai và dễ dàng bị chặn, nó chậm, và vẫn
  dễ bị tấn công tương quan lưu lượng đầu-cuối. (ivpn.net privacy-guides; arXiv 2004.09063)
- **Proxy dân cư / xoay vòng & mạng ORB.** IP datacenter dễ bị đánh dấu theo ASN; proxy **dân cư
  (residential)** mượn IP hộ gia đình và hòa lẫn với lưu lượng người dùng thường ngày. Các mạng "ORB"
  (operational relay box) của nhà nước xuất phát từ các thiết bị có **vị trí địa lý gần mục tiêu** để
  lưu lượng "hòa lẫn hoặc không bất thường" — một ISP dân cư ngay trong thành phố của mục tiêu.
  (Mandiant/Google "China-Nexus ORB Networks"; netacea.com; cảnh báo proxy dân cư của FBI)
- **Sống nhờ đám mây (living off the cloud).** Lấy lưu lượng từ các dải của hyperscaler
  (AWS/GCP/Azure/Cloudflare) thừa hưởng uy tín của nhà cung cấp, nên chặn-theo-uy-tín và gỡ bỏ trở nên
  kém hiệu quả. (cybersecuritynews.com "attackers abuse cloud services")

### Đối trọng phát hiện (blue team / góc nhìn [`defense/`](../defense/README.md))

- **Nguồn cấp uy tín & threat-intel:** blocklist, passive DNS, BGP/WHOIS; **Tor** bị bắt bằng cách khớp
  với danh sách exit-node công bố của Tor Project; CSDL VPN/proxy/datacenter làm mới nhiều lần mỗi ngày.
  Microsoft Entra ID Protection cung cấp các phát hiện *Anonymous IP*, *Malicious IP*, và *nation-state IP*.
  (learn.microsoft.com/entra/id-protection)
- **Bất thường địa lý / du hành bất khả thi (impossible-travel)** đánh dấu các đăng nhập ở khoảng cách xa
  trong một khung thời gian bất khả thi — **nhưng với một điểm mù đã được ghi nhận:** các IP phi vật lý
  (VPN/cloud) bị *loại trừ* khỏi việc chấm điểm impossible-travel, và đó chính xác là lý do một proxy dân
  cư gần về địa lý né được nó. (learn.microsoft.com/defender-cloud-apps anomaly policy)
- **Chỉ dấu IP đang mất giá trị như một biện pháp phòng thủ.** GreyNoise (2026): ~**78% IP tấn công dân
  cư chỉ được thấy nhiều nhất hai lần** trước khi xoay vòng đi — chặn dựa-trên-nguồn-cấp về mặt cấu trúc
  là muộn, nên phát hiện đang chuyển sang **hành vi và vân tay thiết bị**. Mandiant theo dõi các mạng ORB
  "như những thực thể tiến hóa tương tự các nhóm APT," chứ không phải IoC tĩnh. Đây là Kim tự tháp Đau đớn
  trong thực tế: đuổi theo IP là một trò thua thiệt cho cả hai bên. (greynoise.io; Mandiant ORB)

---

## 3. OPSEC về thời gian, locale & định thời ("múi giờ giả")

Đây là nơi "xóa dấu chân" và "giả múi giờ" gặp thực tế: dấu thời gian và các tạo tác locale nằm trong số
những rò rỉ *quy kết* mạnh nhất, và lịch sử đầy rẫy những người vận hành bị bắt bởi chúng.

### Tradecraft & các rò rỉ quy kết đã được ghi nhận

- **Dấu thời gian biên dịch → múi giờ người vận hành.** Trường `TimeDateStamp` của một tệp PE thường bị
  để nguyên; qua một tập mẫu lớn đã được quy kết, thời điểm biên dịch tụ lại thành một dải "9-giờ-tới-5"
  dài 8–12 giờ tiết lộ múi giờ làm việc của người vận hành. **Rich header** không được ghi tài liệu là
  "một yếu tố rất mạnh cho quy kết" — trong **Olympic Destroyer**, một Rich header bị quên cùng một dấu
  thời gian biên dịch đã gắn một mẫu với một thời điểm cụ thể. (0xc0decafe.com PE-timestamps; Securelist
  "devil's in the Rich header")
- **Tạo tác locale / bàn phím / ngôn ngữ.** Các tài nguyên PE nhúng một mã ngôn ngữ; nếu không được đặt,
  locale của hệ thống build sẽ rò rỉ vào. Mã độc của **Sony Pictures** mang các tài nguyên ngôn ngữ Hàn;
  ATT&CK **System Language Discovery (T1614.001)** ghi nhận mã độc kiểm tra bố cục bàn phím / ngôn ngữ UI
  để tránh chạy tại một số quốc gia (Ryuk/Cuba/DarkSide đi kèm danh sách "không-cài-đặt" cho các nước CIS)
  "để giảm nguy cơ thu hút sự chú ý của các cơ quan thực thi pháp luật cụ thể."
  (blog.korelogic.com; attack.mitre.org/techniques/T1614/001)
- **Tình huống tiêu biểu — APT1 (Mandiant, 2013):** ~97% trong số 1.905 lần đăng nhập của người vận hành
  dùng **IP đăng ký tại Thượng Hải trên hệ thống tiếng Trung Giản thể** với bố cục "Chinese (Simplified)
  — US Keyboard", và hoạt động đi theo một **ngày làm việc 8 giờ sáng–5 giờ chiều giờ Thượng Hải** —
  gắn nhóm này với PLA Unit 61398. Giờ làm việc đồng thời là *vỏ bọc* và một *đòn bẩy quy kết*.
  (Báo cáo Mandiant APT1)
- **Định thời beacon — sleep & jitter.** Một callback đều đặn hoàn hảo là dễ phát hiện, nên người vận
  hành thêm **jitter** (biến thiên khoảng nhịp ngẫu nhiên) và **sleep** dài để đi "thấp và chậm", và
  điều chỉnh callback vào **giờ hành chính** của mục tiêu để chúng không nổi bật như một bất thường
  ngoài-giờ. (thedfirreport.com Cobalt Strike defender's guide pt.2)
- **"Xóa dấu chân" nghĩa là gì ở lớp này — Timestomp (T1070.006).** Sửa đổi mốc thời gian MACE của một
  tệp để khớp với các tệp lân cận. Trên NTFS, mốc thời gian `$STANDARD_INFORMATION` (`$SI`) mà người dùng
  thấy được là có thể sửa được, trong khi `$FILE_NAME` (`$FN`) đòi hỏi tương tác ở tầng kernel/sâu hơn,
  nên các tác nhân tiên tiến thực hiện **"double timestomping"** để đánh bại việc so sánh `$SI`/`$FN` —
  đã được quan sát với **APT29** khớp thời gian của web-shell với các tệp lân cận.
  (attack.mitre.org/techniques/T1070/006)

> **Trung thực về "giả mạo" — các tín hiệu này có thể làm giả *và* đã được dùng làm cờ giả (false flag).**
> **Lazarus** cài các chuỗi tiếng Nga phiên âm vụng về và **Olympic Destroyer** chế tạo các tín hiệu chỉ
> về bốn quốc gia khác nhau để đánh lạc hướng quy kết. Bài học đi cả hai chiều: một người vận hành *có
> thể* giả múi giờ/locale, và do đó người phòng thủ phải coi bất kỳ tín hiệu múi giờ/locale đơn lẻ nào là
> **gián tiếp — hãy chứng thực bằng TTP, hạ tầng, và trùng lặp mã** trước khi quy kết. (BAE "Lazarus
> false-flag"; Securelist)

### Đối trọng phát hiện

- **Bản đồ nhiệt dấu-thời-gian-biên-dịch & giờ-làm-việc** (ngày-trong-tuần × giờ) từ các mẫu đã quy kết —
  đã trình diễn với APT1 (Thượng Hải 8–5). Cạm bẫy công cụ: một số công cụ hiển thị `TimeDateStamp` theo
  UTC, số khác âm thầm địa phương hóa — hãy chuẩn hóa về UTC.
- **Beaconing tồn tại qua jitter về mặt thống kê.** Chuyển từ "tìm chu kỳ hoàn hảo" sang "tìm một kết nối
  *bền bỉ*, lưu lượng thấp tới một đích." Các công cụ như **RITA** chấm điểm log Zeek về tính chu kỳ/nhất
  quán; phân tích FFT/miền-tần-số bắt bất kỳ tần số lặp lại nào. **Lưu ý:** các luật khoảng-cố-định ngây
  thơ bị đánh bại hoàn toàn bởi jitter cao (một thử nghiệm: *không* phát hiện được gì với jitter ±45%).
  (hunt.io c2-beaconing; deeptempo.ai)
- **Pháp y timestomp:** so sánh `$SI` với `$FN`, theo dõi **Sysmon Event ID 2 (FileCreateTime)** tương
  quan với EID 11 (FileCreate), và `SetFileTime`/`touch -r` trong các bối cảnh lạ; double-timestomping bị
  bắt bằng cách dựa vào **USN Journal** (một `BasicInfoChange` ghi lại thời gian sửa đổi *thực* ngay cả
  khi dấu thời gian Explorer bị làm giả) và tương quan `$MFT`/`$LogFile`. (attack.mitre.org T1070.006;
  andreafortuna.org USN journal)

---

## 4. Hòa lẫn lưu lượng — trông giống HTTPS/DNS bình thường

### Tradecraft (phần *lý do*)

- **Vân tay TLS (JA3 / JA3S) là thứ thực sự làm tổn thương.** Vì TLS Client/Server Hello ở dạng cleartext,
  **JA3** băm danh sách cipher/extension của client và **JA3S** của server — lấy vân tay *công cụ* "bất kể
  IP đích, tên miền, hay chứng chỉ." Công cụ mặc định có một vân tay ổn định, nên một người vận hành xoay
  vòng IP/tên miền nhưng không bao giờ định hình lại hồ sơ TLS của mình thì vẫn dễ dàng bị gom cụm. Đây là
  lý do né-tránh-chỉ-bằng-IP (§2) là yếu. (Salesforce Engineering "TLS fingerprinting with JA3 and JA3S")
- **Hồ sơ Malleable C2** định hình lại yêu cầu/phản hồi HTTP(S)/DNS của một implant — header, URI, body,
  thậm chí cả handshake — để bắt chước các dịch vụ lành tính (ví dụ trông giống Windows Update / Slack).
  *Mặc định vs tùy chỉnh rất quan trọng:* các hồ sơ đã biết/mặc định vấp phải chữ ký; hồ sơ tùy chỉnh né
  được phát hiện thông thường. (Unit 42 "Cobalt Strike Malleable C2")
- **DNS-over-HTTPS / đào hầm DNS (DNS tunneling)** mã hóa dữ liệu trong các nhãn subdomain gửi tới các name
  server của kẻ tấn công; **DoH** đi trên cổng 443 và "hòa lẫn vào HTTPS thông thường," né tránh ghi log ở
  tầng DNS — một phương án dự phòng ẩn phổ biến khi HTTP(S) bị lọc. (nec.com ChamelDoH analysis)
- **Tên miền được phân loại / cũ / na ná + chứng chỉ hợp lệ.** Tên miền tốn nhiều hơn để thay đổi so với
  IP (đăng ký + lan truyền DNS), và đó là lý do tên miền cũ, được phân loại trước và các chứng chỉ
  Let's-Encrypt hợp lệ là một *khoản đầu tư* tradecraft — một bước lên trên Kim tự tháp Đau đớn. (picussecurity.com)

> **Domain fronting — TÍNH KHẢ THI ĐÃ THAY ĐỔI (được đánh dấu, quan trọng).** Kỹ thuật cổ điển đặt một
> **tên miền mặt tiền tin cậy trong DNS/SNI** và tên miền C2 thật chỉ trong **HTTP Host header**, để một
> CDN dùng chung định tuyến theo Host header sau khi TLS được kết thúc. **Cloudflare đã vô hiệu hóa nó
> ~2015; AWS CloudFront và Google đều chặn nó vào tháng 4/2018** (CloudFront nay trả về HTTP **421** khi
> SNI/Host không khớp); **Azure chặn hoàn toàn vào 2024.** *Domain fronting cổ điển chống lại các CDN lớn
> đã chết.* Các biến thể "domainless" (SNI trống) và mượn-tên-miền chỉ còn tồn tại trên các nhà cung cấp
> không kiểm tra sự tương đẳng SNI/Host, và **ECH (Encrypted Client Hello)** mới nổi có thể hồi sinh khả
> năng kháng phát-hiện-thụ-động — **hãy kiểm chứng lại theo từng nhà cung cấp trước khi dựa vào bất cứ điều
> gì ở đây.** (Tiền lệ thực tế: Mandiant ghi nhận **APT29** fronting C2 qua CDN của Google bằng Tor+`meek`
> trong ~2 năm.) (en.wikipedia.org/wiki/Domain_fronting; AWS Security Blog; Mandiant APT29)

### Đối trọng phát hiện

- **JA3/JA3S** phát hiện mã độc bằng *cách* nó giao tiếp, không phải *cái gì*; kết hợp vân tay client+server
  làm rõ các socket phổ biến. Lưu ý: đây là một *điểm xoay chứ không phải bằng chứng*, phải xử lý **GREASE**
  của Google, và sinh ra dương tính giả.
- **JARM** chủ động lấy vân tay một *server* (10 Client Hello được chế tác → hash 62 ký tự); các framework
  C2 triển khai đồng nhất, nên ví dụ **80% các C2 Trickbot đang hoạt động chia sẻ một JARM** với zero trùng
  lặp trong top 1M của Alexa. Lưu ý: không phải bằng chứng của ác ý (Burp Collaborator / Java tổng quát có
  thể khớp), và nó có thể bị **giả mạo/ngẫu nhiên hóa**. (Salesforce Engineering JARM)
- **Phát hiện domain-fronting:** kiểm tra HTTPS xem có **SNI ≠ Host không khớp** không (ATT&CK M1020).
- **Phát hiện bất thường DNS:** subdomain dài entropy cao, các đợt NXDOMAIN (DGA), beaconing theo định thời
  truy vấn, các đợt tăng loại-bản-ghi hiếm (TXT/NULL), client dùng resolver ngoài / DoH không được phép.
  DoH làm xói mòn khả năng thấy nội dung → chuyển sang tương quan metadata + endpoint/process.
  (nec.com; Cisco Talos "detecting DGA"; ATT&CK T1568.002)

---

## 5. Né tránh ở máy chủ & endpoint — sống nhờ đất liền, và các bề mặt phòng thủ

### 5.1 Living off the Land (phần *lý do*)

- **LOTL / LOLBins / GTFOBins.** Dùng các nhị phân hệ thống hợp pháp, đã có sẵn, thường được ký, thay vì
  thả công cụ. Vì chúng được tin cậy, các hành động độc hại "hòa lẫn với hoạt động hệ thống bình thường" —
  chuyển hoạt động từ *độc hại* sang chỉ đơn thuần *đáng ngờ* — và để lại ít tạo tác trên đĩa hơn nhiều
  (thường không có tệp để cách ly hay băm hash). Dự án **LOLBAS** (Windows) và **GTFOBins** (Unix) lập danh
  mục những cái này, mỗi mục được ánh xạ tới ATT&CK. (lolbas-project.github.io; gtfobins.org; securityhq.com)
  - **Đây nay là chuẩn mực, không phải ngoại lệ:** báo cáo 2025 của CrowdStrike cho thấy **79% các phát
    hiện trong 2024 là không-có-mã-độc (malware-free)** (tăng từ 40% vào 2019). **Volt Typhoon** (2023)
    duy trì quyền truy cập vào hạ tầng trọng yếu của Mỹ trong nhiều tháng chỉ dùng *độc quyền* các công cụ
    tích hợp sẵn của Windows. (crowdstrike.com 2025 Global Threat Report; CISA AA23-144a)
- **Các kỹ thuật ATT&CK chính:** System Binary Proxy Execution **T1218** (rundll32/mshta/regsvr32/msiexec
  proxy việc thực thi để né các phòng thủ dựa-trên-chữ-ký); Command & Scripting Interpreter **T1059**
  (PowerShell/cmd/bash — hạng #2 và #3 trong top kỹ thuật 2025 của Red Canary); Masquerading **T1036**
  ("đổi tên các tiện ích hệ thống có thể lạm dụng để né giám sát là một dạng Masquerading"); Ingress Tool
  Transfer **T1105** (dùng certutil/BITSAdmin/curl để kéo payload tự thân đã là LOTL).

### 5.2 Các bề mặt kiểm soát phòng thủ (bề mặt phát hiện, không phải công thức bypass)

Người vận hành *nhận thức* về những bề mặt này vì chúng tồn tại để bắt kẻ tấn công; hiểu chúng là điều cho
phép trụ cột [`defense/`](../defense/README.md) suy luận về các lỗ hổng độ phủ. Can thiệp vào bất kỳ cái nào
trong số chúng nay là **Defense Impairment (TA0112)** — tập từng gọi là Impair Defenses (T1562), tái tổ chức
thành **T1685** và các anh em (xem §1).

- **AMSI (Antimalware Scan Interface)** gửi nội dung script/macro tới engine AV *sau khi giải rối nhưng
  trước khi thực thi*, nên trên-đĩa vs. trong-bộ-nhớ không còn quan trọng đối với khả năng thấy script —
  đây chính là bề mặt bắt PowerShell, WSH, Office VBA, và tải .NET động bị làm rối/không-tệp. Đó là lý do
  nó là một mục tiêu can thiệp hàng đầu.
  ([learn.microsoft.com AMSI portal](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal); redcanary.com AMSI data source)
- **ETW (Event Tracing for Windows)** là xương sống telemetry toàn hệ điều hành — **provider** phát ra sự
  kiện, **controller/session** cấu hình việc truy vết, **consumer** đọc nó — và nó làm nền cho phần lớn
  telemetry an ninh (bao gồm AMSI và provider Threat-Intelligence được bảo vệ bởi PPL). Chuyển hướng hoặc
  vô hiệu hóa một session làm mù các sensor.
  ([learn.microsoft.com About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing))
- **Windows event logging** ghi lại hoạt động hậu-khai-thác — do đó cả việc vô hiệu hóa nó (trước đây
  T1562.002 Disable Windows Event Logging) và xóa nó (Indicator Removal T1070.001, xem §6).
- **EDR & BYOVD (cấp danh mục).** EDR tổng hợp telemetry về process/thread/nạp-image/registry/mạng và API,
  phần lớn bắt nguồn từ ETW. **Bring-Your-Own-Vulnerable-Driver (BYOVD)** nạp một driver được ký hợp pháp
  nhưng có lỗ hổng để chạy trong không gian kernel và làm mù các phòng thủ — một cách tiếp cận
  Defense-Impairment đã được ghi nhận (trước đây dưới T1562.001).

### Đối trọng phát hiện

- **Telemetry process trả lời LOTL.** Ghi log dòng lệnh của Windows mặc định tắt; **Sysmon** lấp khoảng
  trống — Event ID 1 (tạo process với đầy đủ dòng lệnh + tiến trình cha + hash), ID 7 (nạp image/DLL →
  side-loading), ID 10 (ProcessAccess → đánh cắp credential từ LSASS), ID 11 (FileCreate), ID 12/13/14
  (registry). (learn.microsoft.com/sysinternals/sysmon; blackhillsinfosec.com)
- **Bất thường hành vi / cha-con:** một ứng dụng Office hoặc `explorer.exe` sinh ra
  `powershell.exe`/`cmd.exe`; PowerShell `EncodedCommand`/base64; các cmdlet tải-và-thực-thi; thực thi từ
  các thư mục temp. **Lập đường cơ sở (baseline)** các đối số/tiến-trình-cha/bối-cảnh-người-dùng bình
  thường của mỗi nhị phân rủi-ro-cao trước khi cảnh báo. (elastic.co "detecting command scripting interpreter")
- **Canh chừng những kẻ canh chừng (phát hiện can thiệp).** Thay đổi trace-session ETW nổi lên dưới dạng
  `Microsoft-Windows-Kernel-EventTracing` **Event ID 12**; **Sysmon ghi log thay đổi cấu hình của chính nó
  là Event ID 16** và trạng thái dịch vụ của nó là **Event ID 4** ("không cố che giấu bản thân"); telemetry
  AMSI đi trên provider ETW `Microsoft-Antimalware-Scan-Interface` (EID **1101**). Nguyên tắc chi phối:
  **cảnh báo trên sự *vắng mặt* của telemetry được kỳ vọng** (một sensor im lặng) và trên việc các provider
  công-cụ-an-ninh bị vô hiệu hóa hoặc hạ cấp. Với BYOVD, khớp việc nạp driver/image với các blocklist driver
  đã-biết-lỗ-hổng (HVCI). (attack.mitre.org T1562.006; redcanary.com)
- **Phần khó — kết chuỗi.** EDR bắt tốt việc lạm dụng *một* LOLBin đơn lẻ nhưng vật lộn khi mỗi bước trông
  bình thường một cách cô lập; điều này cần **tương quan chuỗi/dòng thời gian hành vi**, không phải cảnh báo
  đơn-sự-kiện. Kiểm soát phòng ngừa: AppLocker/WDAC, PowerShell Constrained Language Mode, luật ASR chặn
  các tiến trình con của Office. (eventpeeker.com; securityhq.com)

---

## 6. Quản lý tạo tác & dấu chân ("xóa dấu chân") — và vì sao xóa cục bộ là vô ích

Đây là phần "xóa dấu chân" của người dùng hỏi trực tiếp nhất — và phát hiện trung thực quan trọng nhất là
**đối mặt với telemetry hiện đại, xóa dấu chân cục bộ của bạn hầu như không hiệu quả, và *việc thử* thường
tạo ra một tín hiệu ồn ào hơn cả dấu chân ban đầu.**

### Bản kiểm kê dấu chân trên máy chủ

Một chiến dịch chạm vào: tệp (payload, công cụ), khóa registry (Run key, cấu hình ETW autologger),
**Prefetch** (bằng chứng thực thi `.pf`), **Shellbags** (bản ghi registry về việc truy cập thư mục),
Windows event log, và metadata NTFS — **`$MFT`** (mốc thời gian `$SI`/`$FN` cho từng tệp), **`$LogFile`**,
và **USN Journal** (`$Extend\$UsnJrnl:$J`, một nhật ký thay đổi), cộng với index slack của thư mục (`$I30`).
Điều then chốt: **USN Journal ghi lại *sự kiện, không chỉ trạng thái hiện tại*** — mỗi
tạo/xóa/đổi-tên/thay-đổi-dữ-liệu để lại một dấu vết ngay cả khi tệp sau đó bị xóa hoặc timestomp.
(unjaena.com Windows artifact guide; andreafortuna.org USN journal)

### Tradecraft (phần *lý do*) — giảm bớt, đừng phá hủy

- **Indicator Removal (ATT&CK T1070)** bao gồm xóa Windows event log (.001), xóa lịch sử lệnh, xóa tệp, và
  timestomping (.006, xem §3). *Nguyên tắc* mà người vận hành tối ưu là **sinh ra ít tạo tác hơn ngay từ
  đầu** (thực thi trong-bộ-nhớ/không-tệp, LOTL) thay vì dọn dẹp về sau — bởi vì dọn dẹp tự nó là một tạo tác.
- **Trong-bộ-nhớ / không-tệp (khái niệm).** Thực thi cư trú trong bộ nhớ — staging qua PowerShell, tiêm vào
  một process chủ, hoặc lưu nội dung bị làm rối trong Registry/WMI/event log (Obfuscated Files/Information
  **T1027**, gồm Fileless Storage T1027.011; Hide Artifacts **T1564**; Process Injection **T1055**) —
  giảm thiểu tạo tác *trên đĩa*. Nó **không** để lại *không* tạo tác: nó đánh đổi pháp y đĩa lấy **pháp y
  bộ nhớ và telemetry EDR/hành vi.**

> **Chuẩn mực chuyên nghiệp được nhắc lại (không thể thương lượng trong công việc được ủy quyền):** một red
> team **ghi nhận** dấu chân của mình; nó **không** phá hủy bằng chứng của khách hàng. Quy trình đúng là
> *tính tái lập và dọn dẹp có phối hợp, không phải phá hủy*: giữ nhật ký hoạt động của người vận hành và
> nhật ký công cụ để hoạt động có thể kiểm toán; gỡ bỏ implant/persistence phối hợp với khách hàng *sau*
> cuộc đánh giá, thay vì xóa bỏ khả năng phát hiện và học hỏi của khách hàng. Thao túng log trái phép và
> can thiệp bằng chứng là tội phạm; bất kỳ kiểm thử nào như vậy chỉ diễn ra dưới một điều khoản RoE rõ
> ràng. Xem §0. (redteam.guide RoE template; lorikeetsecurity.com)

### Đối trọng phát hiện — luận điểm "xóa cục bộ là vô ích"

- **Xóa một log tự nó gửi đi tiếng chuông báo động.** **Security Event ID 1102** ("audit log was cleared")
  và **System Event ID 104** ("log cleared") được ghi *trước* khi việc xóa hoàn tất; kết hợp với **Windows
  Event Forwarding (WEF)** chuyển các sự kiện được chọn tới một collector/SIEM được gia cố, hành động xóa
  sinh ra một cảnh báo được bảo toàn, độ trung thực cao. Service Control Manager EID 7035/7036 có thể tiết
  lộ dịch vụ EventLog bị dừng.
  ([learn.microsoft.com WEF for intrusion detection](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection);
  [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102); picussecurity.com T1562.002)
- **Telemetry đã rời khỏi tòa nhà.** Forwarding + lưu trữ SIEM chỉ-ghi-thêm/bất-biến (ví dụ Azure Monitor /
  Microsoft Sentinel ingestion) đặt các sự kiện ngoài tầm với của người vận hành ngay khoảnh khắc chúng được
  ghi; **khoảng trống trong các Event Record ID tuần tự** phản bội việc xóa giữa các khoảng forwarding.
  (startupdefense.io T1070.001 — chi tiết SIEM-bất-biến là nguồn thứ cấp)
- **Pháp y NTFS/journal đánh bại chống-pháp-y ở tầng đĩa.** So sánh `$SI`-với-`$FN` bắt được timestomping
  đơn; **USN Journal** và tương quan chéo `$MFT`+`$LogFile`+`$UsnJrnl` (*TriForce* của Cowen) bắt được
  double-timestomping và dấu vết tệp-đã-xóa; phân tích Prefetch phát hiện việc thực thi các tiện ích
  chống-pháp-y đã biết. (attack.mitre.org T1070.006; unjaena.com)
- **Pháp y bộ nhớ bắt được fileless.** `windows.malfind` của Volatility định vị mã được tiêm qua các thẻ VAD
  và các vùng RWX/`PAGE_EXECUTE_READWRITE` cùng các MZ header không được backing — bắt được tiêm PE
  reflective/ánh-xạ-thủ-công ngay cả sau khi tước header. (Điểm mù: tiêm DLL thông thường qua
  `LoadLibrary`/`CreateRemoteThread` hiển thị qua `dlllist`, không phải `malfind` — hãy kết hợp với
  `pslist`/`pstree`/`netscan`/`cmdline`.) AMSI vẫn kiểm tra nội dung script đã-giải-rối bất kể mã hóa; luật
  ASR chặn thực thi script bị-làm-rối. (volatilityfoundation wiki; cyberengage.org; redcanary.com AMSI)

**Tổng hợp:** phát hiện hiện đại đã dịch chuyển *lên* Kim tự tháp Đau đớn chính vì phần đáy (IP, hash, log
cục bộ) vừa rẻ để kẻ tấn công thay đổi *vừa* ngày càng kém hiệu quả khi thay đổi. Né tránh bền vững — và do
đó phát hiện bền vững — nằm ở hành vi, vân tay công cụ, và TTP. Một người vận hành hiểu điều này sẽ ngừng
lãng phí công sức vào dọn dẹp cục bộ; một người phòng thủ hiểu điều này sẽ ngừng dựa vào log-cục-bộ đơn lẻ
và chuyển tiếp (forward) mọi thứ.

---

## 7. Mô phỏng theo tình báo mối đe dọa & quy kết

Red teaming có giá trị nhất khi nó **mô phỏng một đối thủ cụ thể, liên quan** thay vì phô diễn các chiêu trò
chung chung — điều này kiểm tra xem liệu khách hàng có thể phát hiện *những mối đe dọa thực sự nhắm vào họ*
hay không (phòng thủ theo tình báo mối đe dọa — threat-informed defense).

- **Mô phỏng đối thủ (adversary emulation)** tái tạo các TTP được ánh xạ ATT&CK của một tác nhân có tên "một
  cách an toàn, có thể lặp lại." **Center for Threat-Informed Defense** của MITRE công bố các kế hoạch sẵn-
  sàng-chạy trong **Adversary Emulation Library** mở — các kế hoạch phạm vi đầy đủ cho các tác nhân có tên
  (ví dụ **APT29**, **FIN6**) và các kế hoạch micro/tập-trung-hành-vi (ví dụ web shell, liệt kê AD), mỗi cái
  có một `Infrastructure.md`. **MITRE ATT&CK Evaluations** đánh giá các sản phẩm EDR dựa trên những cái này.
  (ctid.mitre.org/resources/adversary-emulation-library; attack.mitre.org/resources/adversary-emulation-plans)
- **Các cơ sở quy kết mà người phòng thủ dùng** (và do đó là những gì mô phỏng phải cẩn trọng): TTP (đỉnh
  kim tự tháp), gom cụm hạ tầng (chứng chỉ/JARM/đăng ký/passive DNS dùng chung), định thời (giờ làm việc,
  thời gian biên dịch), và các tạo tác ngôn ngữ/locale (§3).
- **Mô phỏng được ủy quyền khác với hoạt động độc hại thật như thế nào — bốn ranh giới phân định:** nó
  **có phạm vi, được giải trừ xung đột, được ghi nhận, và có thể đảo ngược**, thực hiện đối với một môi
  trường đồng thuận với một framework chung (ATT&CK) để kết quả có thể đo lường. Một red team có thể *mô
  phỏng* hành vi cờ-giả của một đối thủ để kiểm tra các quy trình quy kết — nhưng nó không bao giờ thực sự
  vu oan một bên thứ ba hay phá hủy bằng chứng, và luôn để lại một dấu vết kiểm toán sạch cho khách hàng.

---

## 8. Bản đồ nhanh Kỹ thuật → ATT&CK → phát hiện

*(Các ID kỹ thuật là mỏ neo ổn định; nhãn tactic phản ánh cú tách Stealth / Defense-Impairment của 2025 — xem §1.)*

| Mục tiêu người vận hành | Lớp | ATT&CK | Tín hiệu phát hiện chính |
|-------------------------|-----|--------|--------------------------|
| Ẩn IP nguồn | Mạng | T1090 (Proxy) | Danh sách uy tín/Tor, impossible-travel, hành vi (nguồn cấp IP đang mất giá) |
| Hòa lẫn về địa lý | Mạng | T1090.003, T1584 | Gom cụm ORB/hạ tầng, ASN + neo hành vi |
| Trông giống HTTPS bình thường | Lưu lượng | T1071, T1573 | JA3/JA3S, JARM, chữ ký malleable-profile |
| Domain fronting | Lưu lượng | T1090.004 | SNI ≠ Host không khớp (kỹ thuật nay hầu như đã chết trên các CDN lớn) |
| Đào hầm DNS / DoH | Lưu lượng | T1071.004, T1568.002 | Bất thường entropy/NXDOMAIN/định thời; tương quan metadata |
| Giả múi giờ/locale | Quy kết | T1614.001, T1070.006 | Bản đồ nhiệt thời-gian-biên-dịch, $SI/$FN + USN journal, chứng thực (có thể giả) |
| Beacon thấp-và-chậm | Định thời | T1029, C2 | Phân tích bền bỉ RITA/FFT (đánh bại jitter về mặt thống kê) |
| Sống nhờ đất liền | Máy chủ | T1218, T1059, T1105 | Telemetry process Sysmon, cha-con + lập đường cơ sở |
| Ngụy trang nhị phân | Máy chủ | T1036 | Phân tích metadata/đường-dẫn LOLBin-đã-đổi-tên |
| Không-tệp / trong-bộ-nhớ | Máy chủ | T1027, T1055, T1564 | AMSI, telemetry tiêm của EDR, Volatility malfind |
| Làm suy yếu phòng thủ (AMSI/ETW/EDR) | Máy chủ | **T1685 / TA0112** (từng là T1562) | ETW EID 12, Sysmon EID 16/4, vắng-mặt-telemetry, blocklist driver |
| Loại bỏ chỉ dấu | Dấu chân | T1070 (.001/.006) | Event ID 1102/104 forwarding, tính bất biến SIEM, $MFT/USN journal |

---

## 9. Điều này ánh xạ vào SecForge như thế nào

- **Cho agent tấn công ([`ai_framework/`](../ai_framework/README.md)):** §0–§1 được biên dịch thành các quy
  tắc thường trực trong [system prompt](../ai_framework/agent/system.py) — ưu tiên ủy quyền, chọn hành động
  ít-ồn-ào-nhất mà vẫn chứng minh được luận điểm, ghi nhận mọi hành động, ở trong phạm vi, và đừng lãng phí
  công sức vào phá-hủy-tạo-tác cục bộ. Khi một cuộc đánh giá cần một kỹ thuật cụ thể, agent gợi lại nguyên
  tắc §2–§6 liên quan và [kho ngữ liệu KB](KNOWLEDGE_BASE.md).
- **Cho trụ cột phòng thủ ([`defense/`](../defense/README.md)):** *đối trọng phát hiện* của mỗi phần là danh
  mục kiểm tra cho "liệu mục tiêu này có thấy được cuộc tấn công không?" — khả năng thấy TLS/JA3, telemetry
  process (Sysmon), forwarding log/tính bất biến SIEM, giám sát can thiệp ETW/AMSI, giám sát bất thường DNS,
  và các điểm mù impossible-travel.
- **Cho kho tri thức / labs:** các thẻ [`vuln_search/catalog/`](../vuln_search/catalog/INDEX.md) bao quát
  *cái gì* để khai thác; tệp này bao quát *cách vận hành bí mật và cách điều đó bị bắt* — một người bạn đồng
  hành tự nhiên cho các bài tập [`labs/`](../labs/README.md) ghép một cuộc tấn công với phát hiện của nó.

---

## 10. Tài liệu tham khảo

Được nhóm theo phần; tất cả đều là các nguồn công khai, có thẩm quyền. Các mục có tính khả thi hoặc taxonomy
đã thay đổi, hoặc là nguồn thứ cấp/không chắc chắn, được đánh dấu trong §0–§6 và trong ghi chú kiểm chứng
bên dưới.

**Chuẩn mực, ủy quyền & học thuyết OPSEC**
- NIST SP 800-115 — https://csrc.nist.gov/pubs/sp/800/115/final ·
  PDF (gồm mẫu RoE ở Phụ lục B) — https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-115.pdf
- PTES Pre-engagement — http://www.pentest-standard.org/index.php/Pre-engagement ·
  https://pentest-standard.readthedocs.io/en/latest/preengagement_interactions.html
- RoE / CFAA 18 U.S.C. § 1030 framing — https://penetrationtestingauthority.com/rules-of-engagement-penetration-testing/ ·
  RoE template — https://redteam.guide/docs/Templates/roe_template/ · deconfliction — https://redteam.guide/docs/definitions/
- Quy trình OPSEC 5 bước — https://csrc.nist.gov/glossary/term/operations_security ·
  DoD CDSE — https://www.cdse.edu/Portals/124/Documents/student-guides/GS130-guide.pdf ·
  DTIC OPSEC guide — https://apps.dtic.mil/sti/pdfs/AD1038572.pdf

**MITRE ATT&CK (lưu ý cú tách Stealth / Defense-Impairment của 2025)**
- Stealth (TA0005, hiện hành) — https://attack.mitre.org/tactics/TA0005/ ·
  Defense Impairment (TA0112, mới) — https://attack.mitre.org/tactics/TA0112/ ·
  T1685 Disable or Modify Tools — https://attack.mitre.org/techniques/T1685/ ·
  Defense Evasion cũ (v15, trước tách) — https://attack.mitre.org/versions/v15/tactics/TA0005/ ·
  giải thích cú tách v19 — https://medium.com/mitre-attack/att-ck-v19-the-defense-evasion-split-ics-sub-techniques-new-ai-social-engineering-coverage-ff329cb65d66
- Kỹ thuật: T1090 (+.002/.003/.004), T1071(+.004), T1573, T1568(.002), T1583/T1584/T1608,
  T1614.001, T1070(+.001/.006), T1562(+.001/.002/.006), T1027(+.011), T1564, T1055, T1218, T1059,
  T1105, T1497(.003) — https://attack.mitre.org
- Adversary emulation — https://attack.mitre.org/resources/adversary-emulation-plans/ ·
  CTID Adversary Emulation Library — https://ctid.mitre.org/resources/adversary-emulation-library/ ·
  https://github.com/center-for-threat-informed-defense · ATT&CK Evaluations — https://www.attackiq.com/mitre-attack/

**Kim tự tháp Đau đớn (Pyramid of Pain)**
- https://www.attackiq.com/glossary/pyramid-of-pain-2/ ·
  https://www.activecountermeasures.com/hunt-what-hurts-the-pyramid-of-pain/ ·
  https://www.picussecurity.com/resource/glossary/what-is-pyramid-of-pain

**Mạng / hạ tầng**
- Red Team Infrastructure Wiki — https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki ·
  SpecterOps "Designing Effective Covert Red Team Attack Infrastructure" —
  https://bluescreenofjeff.com/2017-12-05-designing-effective-covert-red-team-attack-infrastructure/
- Mandiant "China-Nexus / ORB Networks" — https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks ·
  GreyNoise "IP Reputation Fails against the Rotation Economy" — https://www.greynoise.io/blog/invisible-army-why-ip-reputation-fails-against-rotation-economy ·
  iVPN Tor-vs-VPN — https://www.ivpn.net/privacy-guides/adversaries-and-anonymity-systems-the-basics/ ·
  Microsoft Entra ID Protection — https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks ·
  Defender for Cloud Apps anomaly policy — https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy

**Thời gian / locale / định thời**
- Mandiant APT1 report — https://services.google.com/fh/files/misc/mandiant-apt1-report.pdf ·
  Securelist "The devil's in the Rich header" — https://securelist.com/the-devils-in-the-rich-header/84348/ ·
  BAE "Lazarus' False Flag Malware" — https://baesystemsai.blogspot.com/2017/02/lazarus-false-flag-malware.html ·
  KoreLogic PE resource languages — https://blog.korelogic.com/blog/2014/12/23/resource_language_codes ·
  DFIR Report Cobalt Strike pt.2 — https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/ ·
  RITA/beaconing — https://hunt.io/glossary/c2-beaconing · jitter-defeats-rules — https://www.deeptempo.ai/blogs/evading-rule-based-detection---part-1-c2-beaconing

**Hòa lẫn lưu lượng**
- JA3/JA3S — https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/ ·
  JARM — https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/ ·
  Unit 42 Malleable C2 — https://unit42.paloaltonetworks.com/cobalt-strike-malleable-c2/ ·
  Domain fronting timeline — https://en.wikipedia.org/wiki/Domain_fronting ·
  AWS CloudFront protections — https://aws.amazon.com/blogs/security/enhanced-domain-protections-for-amazon-cloudfront-requests/ ·
  Mandiant APT29 domain fronting — https://cloud.google.com/blog/topics/threat-intelligence/apt29-domain-frontin/ ·
  ChamelDoH / DoH — https://www.nec.com/en/global/solutions/cybersecurity/blog/240920/index.html ·
  Cisco Talos "Detecting DGA" — https://blogs.cisco.com/security/talos/detecting-dga

**Máy chủ / LOTL / bề mặt phòng thủ / dấu chân**
- LOLBAS — https://lolbas-project.github.io/ · GTFOBins — https://gtfobins.org/ ·
  CrowdStrike 2025 Global Threat Report — https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/ ·
  CISA AA23-144a "Volt Typhoon" — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a ·
  Red Canary 2025 Threat Detection Report — https://redcanary.com/threat-detection-report/techniques/
- AMSI portal — https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal ·
  About Event Tracing (ETW) — https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing ·
  Windows Event Forwarding — https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection ·
  Event 1102 — https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102 ·
  Sysmon — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Red Canary AMSI data source — https://redcanary.com/blog/threat-detection/better-know-a-data-source/amsi/ ·
  CrowdStrike patchless AMSI — https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/ ·
  Picus T1562.002 — https://www.picussecurity.com/resource/blog/t1562-002-disable-windows-event-logging ·
  Black Hills Sysmon EID breakdown — https://www.blackhillsinfosec.com/a-sysmon-event-id-breakdown/ ·
  Elastic "Detecting Command & Scripting Interpreter" — https://www.elastic.co/blog/detecting-command-scripting-interpreter
- Volatility malfind — https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal ·
  https://www.cyberengage.org/post/volatility-plugins-plugin-window-malfind-let-s-talk-about-it ·
  USN Journal / NTFS forensics — https://andreafortuna.org/2025/09/06/usn-journal/ · https://www.unjaena.com/en/blog/windows-artifact-guide

> **Ghi chú kiểm chứng.** Các tuyên bố về mạng/máy chủ ở §2–§6 được hậu thuẫn bằng các lần tải trực tiếp
> nhiều nguồn (MITRE, Microsoft Learn, các blog kỹ thuật phát hiện của nhà cung cấp); ủy quyền/OPSEC ở §0–§1
> và mô phỏng ở §7 được neo vào NIST SP 800-115, PTES, và thư viện MITRE CTID. Các điểm không chắc chắn được
> đánh dấu: (a) **cú tách tactic ATT&CK 2025** đã được xác nhận là đang hoạt động, nhưng hãy coi ngày phát
> hành/chỉnh sửa chính xác là độ-tin-cậy-thấp — hãy kiểm chứng lại TA0005/TA0112/T1685 tại attack.mitre.org;
> (b) tính khả thi của domain-fronting và các loại trừ VPN/cloud của impossible-travel thay đổi theo thời
> gian — hãy kiểm chứng lại theo từng nhà cung cấp; (c) các event ID nội-bộ-provider của AMSI/ETW (1101/1201),
> chi tiết SIEM-bất-biến, ánh xạ sub-technique chính xác của BYOVD, và con số "80% mẫu dùng T1055" là nguồn
> thứ cấp/đơn-nguồn; (d) một vài nguồn trả về lỗi SSL/403 trong quá trình nghiên cứu (0xc0decafe PE-timestamps,
> Cobalt Strike JARM, trang cha T1562) và đã được chứng thực qua các trích đoạn chỉ mục tìm kiếm đối chiếu với
> tài liệu gốc.
