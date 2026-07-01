/**
 * Pentest tool reference — the tools you reach for during an engagement, grouped by
 * the phase you use them in. For AUTHORIZED testing, CTFs, and lab use only.
 *
 * Translatable fields (phase `name`/`blurb`, tool `blurb`) are authored as `{ en, vi }`
 * and resolved at render via `loc()`. Tool names, commands, links, tags, and `related`
 * slugs stay language-neutral.
 *
 * Each tool:
 *   { name, blurb, cmd?, href?, tags?, related? }
 *     cmd      — a representative invocation (illustrative, not a recipe)
 *     href     — official site / docs
 *     tags     — short keywords (also used by the search box)
 *     related  — Knowledge Base slugs this tool targets; rendered as links into /docs
 *                (unknown slugs are silently dropped, so this stays safe to edit)
 */
export const toolPhases = [
  {
    id: "recon",
    name: { en: "Reconnaissance & OSINT", vi: "Trinh sát & OSINT" },
    blurb: {
      en: "Map the attack surface — hosts, subdomains, and exposed services — before sending a single payload.",
      vi: "Vẽ bản đồ bề mặt tấn công — host, subdomain, và dịch vụ lộ ra — trước khi gửi bất kỳ payload nào.",
    },
    tools: [
      {
        name: "Nmap",
        blurb: {
          en: "Network and port scanner with service/version detection and a scripting engine.",
          vi: "Bộ quét mạng và cổng, có nhận diện dịch vụ/phiên bản và engine scripting.",
        },
        cmd: "nmap -sC -sV -p- -oA scan target",
        href: "https://nmap.org/book/man.html",
        tags: ["ports", "network", "scanner"],
      },
      {
        name: "Masscan",
        blurb: {
          en: "Asynchronous port scanner fast enough to sweep large ranges.",
          vi: "Bộ quét cổng bất đồng bộ, đủ nhanh để quét các dải địa chỉ lớn.",
        },
        cmd: "masscan -p1-65535 10.0.0.0/8 --rate 10000",
        href: "https://github.com/robertdavidgraham/masscan",
        tags: ["ports", "network", "fast"],
      },
      {
        name: "Amass",
        blurb: {
          en: "In-depth subdomain enumeration and attack-surface mapping (OWASP).",
          vi: "Liệt kê subdomain chuyên sâu và lập bản đồ bề mặt tấn công (OWASP).",
        },
        cmd: "amass enum -d example.com",
        href: "https://github.com/owasp-amass/amass",
        tags: ["subdomains", "osint", "dns"],
      },
      {
        name: "Subfinder",
        blurb: {
          en: "Fast passive subdomain discovery from many public sources.",
          vi: "Khám phá subdomain thụ động nhanh từ nhiều nguồn công khai.",
        },
        cmd: "subfinder -d example.com -all",
        href: "https://github.com/projectdiscovery/subfinder",
        tags: ["subdomains", "passive", "dns"],
      },
      {
        name: "theHarvester",
        blurb: {
          en: "OSINT collection of emails, names, subdomains, and hosts.",
          vi: "Thu thập OSINT: email, tên, subdomain, và host.",
        },
        cmd: "theHarvester -d example.com -b all",
        href: "https://github.com/laramies/theHarvester",
        tags: ["osint", "emails", "passive"],
      },
      {
        name: "dnsx",
        blurb: {
          en: "Fast, multi-purpose DNS toolkit for resolution and probing.",
          vi: "Bộ công cụ DNS đa năng, nhanh, để phân giải và thăm dò.",
        },
        cmd: "dnsx -l subs.txt -resp",
        href: "https://github.com/projectdiscovery/dnsx",
        tags: ["dns", "resolve"],
      },
      {
        name: "Shodan",
        blurb: {
          en: "Search engine for internet-connected hosts, services, and banners.",
          vi: "Công cụ tìm kiếm các host, dịch vụ, và banner kết nối Internet.",
        },
        href: "https://www.shodan.io",
        tags: ["osint", "internet", "search"],
      },
    ],
  },
  {
    id: "web-discovery",
    name: { en: "Web Discovery & Scanning", vi: "Khám phá & quét web" },
    blurb: {
      en: "Probe web apps — proxy traffic, fingerprint stacks, and brute content out of the dark.",
      vi: "Thăm dò ứng dụng web — proxy lưu lượng, nhận diện công nghệ, và dò tìm nội dung ẩn.",
    },
    tools: [
      {
        name: "Burp Suite",
        blurb: {
          en: "The de-facto web proxy: intercept, Repeater, Intruder, and an extensible scanner.",
          vi: "Web proxy phổ biến nhất: chặn bắt, Repeater, Intruder, và bộ quét mở rộng được.",
        },
        href: "https://portswigger.net/burp",
        tags: ["proxy", "intercept", "manual"],
        related: ["xss", "csrf", "sql_injection", "ssrf"],
      },
      {
        name: "OWASP ZAP",
        blurb: {
          en: "Open-source web proxy with an active/passive scanner and automation.",
          vi: "Web proxy mã nguồn mở với bộ quét chủ động/thụ động và tự động hóa.",
        },
        href: "https://www.zaproxy.org",
        tags: ["proxy", "scanner", "open-source"],
        related: ["xss", "sql_injection"],
      },
      {
        name: "ffuf",
        blurb: {
          en: "Fast web fuzzer for directories, files, vhosts, and parameters.",
          vi: "Bộ fuzz web nhanh cho thư mục, file, vhost, và tham số.",
        },
        cmd: "ffuf -u https://target/FUZZ -w wordlist.txt",
        href: "https://github.com/ffuf/ffuf",
        tags: ["fuzzing", "content", "discovery"],
        related: ["path_traversal"],
      },
      {
        name: "gobuster",
        blurb: {
          en: "Brute-force URIs, DNS subdomains, and virtual hosts.",
          vi: "Dò tìm URI, subdomain DNS, và virtual host.",
        },
        cmd: "gobuster dir -u https://target -w wordlist.txt",
        href: "https://github.com/OJ/gobuster",
        tags: ["fuzzing", "content", "dns"],
      },
      {
        name: "feroxbuster",
        blurb: {
          en: "Recursive content discovery written in Rust.",
          vi: "Khám phá nội dung đệ quy, viết bằng Rust.",
        },
        cmd: "feroxbuster -u https://target",
        href: "https://github.com/epi052/feroxbuster",
        tags: ["fuzzing", "recursive", "content"],
      },
      {
        name: "Nuclei",
        blurb: {
          en: "Template-driven scanner for known CVEs and misconfigurations.",
          vi: "Bộ quét theo template cho các CVE đã biết và lỗi cấu hình.",
        },
        cmd: "nuclei -u https://target -severity high,critical",
        href: "https://github.com/projectdiscovery/nuclei",
        tags: ["scanner", "templates", "cve"],
      },
      {
        name: "Nikto",
        blurb: {
          en: "Web server scanner for dangerous files and misconfigurations.",
          vi: "Bộ quét web server tìm file nguy hiểm và lỗi cấu hình.",
        },
        cmd: "nikto -h https://target",
        href: "https://github.com/sullo/nikto",
        tags: ["scanner", "server", "misconfig"],
        related: ["information_disclosure"],
      },
      {
        name: "httpx",
        blurb: {
          en: "Fast HTTP probing — status, titles, and tech detection at scale.",
          vi: "Thăm dò HTTP nhanh — trạng thái, tiêu đề, và nhận diện công nghệ ở quy mô lớn.",
        },
        cmd: "httpx -l hosts.txt -title -tech-detect",
        href: "https://github.com/projectdiscovery/httpx",
        tags: ["probe", "fingerprint", "http"],
      },
      {
        name: "WhatWeb",
        blurb: {
          en: "Fingerprint web technologies, frameworks, and versions.",
          vi: "Nhận diện công nghệ, framework, và phiên bản web.",
        },
        cmd: "whatweb https://target",
        href: "https://github.com/urbanadventurer/WhatWeb",
        tags: ["fingerprint", "recon"],
      },
      {
        name: "WPScan",
        blurb: {
          en: "WordPress vulnerability scanner for core, plugins, and themes.",
          vi: "Bộ quét lỗ hổng WordPress cho core, plugin, và theme.",
        },
        cmd: "wpscan --url https://target --enumerate vp",
        href: "https://wpscan.com",
        tags: ["wordpress", "cms", "scanner"],
      },
    ],
  },
  {
    id: "exploitation",
    name: { en: "Exploitation", vi: "Khai thác" },
    blurb: {
      en: "Turn a confirmed weakness into proof — automated where it helps, manual where it matters.",
      vi: "Biến điểm yếu đã xác nhận thành bằng chứng — tự động khi hữu ích, thủ công khi cần thiết.",
    },
    tools: [
      {
        name: "sqlmap",
        blurb: {
          en: "Automated detection and exploitation of SQL injection.",
          vi: "Tự động phát hiện và khai thác SQL injection.",
        },
        cmd: 'sqlmap -u "https://t/?id=1" --batch --dbs',
        href: "https://sqlmap.org",
        tags: ["sqli", "database", "automation"],
        related: ["sql_injection", "nosql_injection"],
      },
      {
        name: "Metasploit",
        blurb: {
          en: "Exploit development and delivery framework with a vast module library.",
          vi: "Framework phát triển và triển khai exploit với thư viện module khổng lồ.",
        },
        cmd: "msfconsole",
        href: "https://docs.metasploit.com",
        tags: ["exploit", "framework", "payloads"],
        related: ["insecure_deserialization"],
      },
      {
        name: "Commix",
        blurb: {
          en: "Automated detection and exploitation of command injection.",
          vi: "Tự động phát hiện và khai thác command injection.",
        },
        cmd: 'commix -u "https://t/?q=1"',
        href: "https://github.com/commixproject/commix",
        tags: ["command-injection", "automation"],
        related: ["os_command_injection"],
      },
      {
        name: "dalfox",
        blurb: {
          en: "Fast, parameter-aware XSS scanner and analyzer.",
          vi: "Bộ quét và phân tích XSS nhanh, nhận biết tham số.",
        },
        cmd: "dalfox url https://t/?q=1",
        href: "https://github.com/hahwul/dalfox",
        tags: ["xss", "scanner"],
        related: ["xss", "dom_based"],
      },
      {
        name: "tplmap",
        blurb: {
          en: "Detect and exploit server-side template injection.",
          vi: "Phát hiện và khai thác server-side template injection.",
        },
        cmd: 'tplmap -u "https://t/?q=1"',
        href: "https://github.com/epinna/tplmap",
        tags: ["ssti", "rce"],
        related: ["ssti"],
      },
      {
        name: "SSRFmap",
        blurb: {
          en: "Automate SSRF exploitation against a captured request.",
          vi: "Tự động khai thác SSRF dựa trên một request đã bắt được.",
        },
        cmd: "python3 ssrfmap.py -r req.txt -p url -m readfiles",
        href: "https://github.com/swisskyrepo/SSRFmap",
        tags: ["ssrf", "automation"],
        related: ["ssrf"],
      },
      {
        name: "XXEinjector",
        blurb: {
          en: "Automated XXE retrieval and out-of-band exploitation.",
          vi: "Tự động truy xuất XXE và khai thác ngoài băng (out-of-band).",
        },
        cmd: "ruby XXEinjector.rb --host=you --file=req.txt",
        href: "https://github.com/enjoiz/XXEinjector",
        tags: ["xxe", "oob"],
        related: ["xxe"],
      },
    ],
  },
  {
    id: "credentials",
    name: { en: "Credential Attacks", vi: "Tấn công thông tin đăng nhập" },
    blurb: {
      en: "Test authentication strength — online brute-forcing and offline hash cracking.",
      vi: "Kiểm tra độ mạnh của xác thực — brute-force trực tuyến và bẻ khóa hash ngoại tuyến.",
    },
    tools: [
      {
        name: "Hydra",
        blurb: {
          en: "Fast online login brute-forcer across many protocols.",
          vi: "Bộ brute-force đăng nhập trực tuyến nhanh, hỗ trợ nhiều giao thức.",
        },
        cmd: "hydra -L users.txt -P pass.txt target http-post-form",
        href: "https://github.com/vanhauser-thc/thc-hydra",
        tags: ["brute-force", "login", "online"],
        related: ["broken_authentication"],
      },
      {
        name: "John the Ripper",
        blurb: {
          en: "Versatile offline password cracker with smart rules.",
          vi: "Bộ bẻ mật khẩu ngoại tuyến đa năng với các quy tắc thông minh.",
        },
        cmd: "john --wordlist=rockyou.txt hashes.txt",
        href: "https://www.openwall.com/john",
        tags: ["cracking", "hashes", "offline"],
        related: ["broken_authentication"],
      },
      {
        name: "Hashcat",
        blurb: {
          en: "GPU-accelerated password recovery across hundreds of hash modes.",
          vi: "Khôi phục mật khẩu tăng tốc bằng GPU, hỗ trợ hàng trăm loại hash.",
        },
        cmd: "hashcat -m 0 hashes.txt rockyou.txt",
        href: "https://hashcat.net/hashcat",
        tags: ["cracking", "gpu", "hashes"],
      },
      {
        name: "Medusa",
        blurb: {
          en: "Parallel, modular network login brute-forcer.",
          vi: "Bộ brute-force đăng nhập mạng song song, dạng module.",
        },
        cmd: "medusa -h target -U users.txt -P pass.txt -M ssh",
        href: "https://github.com/jmk-foofus/medusa",
        tags: ["brute-force", "login", "parallel"],
      },
      {
        name: "CeWL",
        blurb: {
          en: "Generate a custom wordlist by spidering a target site.",
          vi: "Tạo wordlist tùy biến bằng cách thu thập từ trang mục tiêu.",
        },
        cmd: "cewl https://target -w words.txt",
        href: "https://github.com/digininja/CeWL",
        tags: ["wordlist", "recon"],
      },
    ],
  },
  {
    id: "api-auth",
    name: { en: "API, Auth & Tokens", vi: "API, xác thực & token" },
    blurb: {
      en: "Discover and abuse API surface — hidden parameters, routes, tokens, and GraphQL.",
      vi: "Khám phá và lạm dụng bề mặt API — tham số ẩn, route, token, và GraphQL.",
    },
    tools: [
      {
        name: "jwt_tool",
        blurb: {
          en: "Inspect and tamper JSON Web Tokens — alg confusion, weak keys, claim abuse.",
          vi: "Kiểm tra và can thiệp JSON Web Token — alg confusion, khóa yếu, lạm dụng claim.",
        },
        cmd: "python3 jwt_tool.py <token>",
        href: "https://github.com/ticarpi/jwt_tool",
        tags: ["jwt", "tokens", "auth"],
        related: ["jwt", "oauth"],
      },
      {
        name: "Arjun",
        blurb: {
          en: "Discover hidden HTTP parameters by inference.",
          vi: "Khám phá tham số HTTP ẩn bằng suy luận.",
        },
        cmd: "arjun -u https://target",
        href: "https://github.com/s0md3v/Arjun",
        tags: ["parameters", "discovery", "api"],
        related: ["api_security"],
      },
      {
        name: "kiterunner",
        blurb: {
          en: "Brute-force and discover API routes and endpoints at speed.",
          vi: "Dò tìm và khám phá route, endpoint API ở tốc độ cao.",
        },
        cmd: "kr scan https://target -w routes.kite",
        href: "https://github.com/assetnote/kiterunner",
        tags: ["api", "routes", "discovery"],
        related: ["api_security"],
      },
      {
        name: "graphw00f",
        blurb: {
          en: "Fingerprint the GraphQL engine behind an endpoint.",
          vi: "Nhận diện engine GraphQL phía sau một endpoint.",
        },
        cmd: "python3 main.py -d -t https://target/graphql",
        href: "https://github.com/dolevf/graphw00f",
        tags: ["graphql", "fingerprint"],
        related: ["graphql"],
      },
      {
        name: "InQL",
        blurb: {
          en: "GraphQL introspection, query generation, and testing (Burp extension).",
          vi: "Introspection, sinh truy vấn, và kiểm thử GraphQL (tiện ích mở rộng Burp).",
        },
        href: "https://github.com/doyensec/inql",
        tags: ["graphql", "introspection", "burp"],
        related: ["graphql"],
      },
      {
        name: "Postman",
        blurb: {
          en: "API client for crafting, chaining, and automating requests.",
          vi: "API client để soạn, nối chuỗi, và tự động hóa request.",
        },
        href: "https://www.postman.com",
        tags: ["api", "client", "requests"],
        related: ["api_security"],
      },
    ],
  },
  {
    id: "network",
    name: { en: "Network, MITM & Wireless", vi: "Mạng, MITM & không dây" },
    blurb: {
      en: "Watch and bend traffic on the wire — capture, intercept, poison, and crack.",
      vi: "Quan sát và can thiệp lưu lượng trên đường truyền — bắt gói, chặn, đầu độc, và bẻ khóa.",
    },
    tools: [
      {
        name: "Wireshark",
        blurb: {
          en: "Deep packet capture and protocol analysis with rich dissectors.",
          vi: "Bắt gói và phân tích giao thức chuyên sâu với nhiều bộ giải mã.",
        },
        href: "https://www.wireshark.org",
        tags: ["pcap", "analysis", "protocols"],
      },
      {
        name: "tcpdump",
        blurb: {
          en: "Command-line packet capture for quick, scriptable inspection.",
          vi: "Bắt gói qua dòng lệnh để kiểm tra nhanh, có thể script hóa.",
        },
        cmd: "tcpdump -i eth0 -w capture.pcap",
        href: "https://www.tcpdump.org",
        tags: ["pcap", "cli", "capture"],
      },
      {
        name: "Responder",
        blurb: {
          en: "Poison LLMNR/NBT-NS/mDNS to capture network credentials.",
          vi: "Đầu độc LLMNR/NBT-NS/mDNS để thu thập thông tin đăng nhập trong mạng.",
        },
        cmd: "responder -I eth0 -wf",
        href: "https://github.com/lgandx/Responder",
        tags: ["mitm", "credentials", "windows"],
      },
      {
        name: "bettercap",
        blurb: {
          en: "Swiss-army knife for network reconnaissance and MITM attacks.",
          vi: "Bộ công cụ đa năng cho trinh sát mạng và tấn công MITM.",
        },
        cmd: "bettercap -iface eth0",
        href: "https://www.bettercap.org",
        tags: ["mitm", "network", "arp"],
      },
      {
        name: "mitmproxy",
        blurb: {
          en: "Interactive HTTPS intercepting proxy with a CLI and web UI.",
          vi: "Proxy chặn HTTPS tương tác, có CLI và giao diện web.",
        },
        cmd: "mitmproxy -p 8080",
        href: "https://mitmproxy.org",
        tags: ["proxy", "intercept", "https"],
      },
      {
        name: "Aircrack-ng",
        blurb: {
          en: "Wi-Fi auditing suite for capturing and cracking WPA/WEP keys.",
          vi: "Bộ kiểm định Wi-Fi để bắt và bẻ khóa WPA/WEP.",
        },
        cmd: "aircrack-ng -w rockyou.txt capture.cap",
        href: "https://www.aircrack-ng.org",
        tags: ["wireless", "wifi", "cracking"],
      },
    ],
  },
  {
    id: "post-exploitation",
    name: { en: "Post-Exploitation & AD", vi: "Hậu khai thác & AD" },
    blurb: {
      en: "After a foothold — escalate, pivot, and chart paths through Active Directory.",
      vi: "Sau khi có chỗ đứng — leo thang, pivot, và lần theo đường tấn công trong Active Directory.",
    },
    tools: [
      {
        name: "Impacket",
        blurb: {
          en: "Python toolkit for crafting and abusing network protocols (SMB, Kerberos).",
          vi: "Bộ công cụ Python để tạo và lạm dụng các giao thức mạng (SMB, Kerberos).",
        },
        cmd: "impacket-secretsdump domain/user@target",
        href: "https://github.com/fortra/impacket",
        tags: ["smb", "kerberos", "toolkit"],
      },
      {
        name: "Mimikatz",
        blurb: {
          en: "Extract Windows credentials, tickets, and secrets from memory.",
          vi: "Trích xuất thông tin đăng nhập, ticket, và bí mật của Windows từ bộ nhớ.",
        },
        cmd: "sekurlsa::logonpasswords",
        href: "https://github.com/gentilkiwi/mimikatz",
        tags: ["credentials", "windows", "lsass"],
      },
      {
        name: "BloodHound",
        blurb: {
          en: "Reveal Active Directory attack paths through graph analysis.",
          vi: "Phát hiện đường tấn công trong Active Directory qua phân tích đồ thị.",
        },
        href: "https://github.com/SpecterOps/BloodHound",
        tags: ["active-directory", "graph", "paths"],
      },
      {
        name: "CrackMapExec",
        blurb: {
          en: "Swiss-army knife for assessing and pivoting across AD/SMB networks.",
          vi: "Bộ công cụ đa năng để đánh giá và pivot trong mạng AD/SMB.",
        },
        cmd: "crackmapexec smb targets.txt -u user -p pass",
        href: "https://github.com/Porchetta-Industries/CrackMapExec",
        tags: ["active-directory", "smb", "lateral"],
      },
      {
        name: "PEASS-ng",
        blurb: {
          en: "linPEAS / winPEAS scripts that enumerate privilege-escalation paths.",
          vi: "Bộ script linPEAS / winPEAS liệt kê các đường leo thang đặc quyền.",
        },
        cmd: "./linpeas.sh",
        href: "https://github.com/peass-ng/PEASS-ng",
        tags: ["privesc", "enumeration"],
      },
      {
        name: "Chisel",
        blurb: {
          en: "Fast TCP/UDP tunnel over HTTP for pivoting through restricted networks.",
          vi: "Đường hầm TCP/UDP nhanh qua HTTP để pivot xuyên mạng bị hạn chế.",
        },
        cmd: "chisel client you:8080 R:1080:socks",
        href: "https://github.com/jpillora/chisel",
        tags: ["tunnel", "pivot", "socks"],
      },
    ],
  },
  {
    id: "utilities",
    name: { en: "Utilities & Platform", vi: "Tiện ích & nền tảng" },
    blurb: {
      en: "The everyday glue — listeners, relays, data transforms, and the distro it all runs on.",
      vi: "Bộ keo hằng ngày — listener, relay, biến đổi dữ liệu, và bản phân phối chạy tất cả.",
    },
    tools: [
      {
        name: "Netcat",
        blurb: {
          en: "Read and write across TCP/UDP — listeners, shells, and quick transfers.",
          vi: "Đọc/ghi qua TCP/UDP — listener, shell, và truyền dữ liệu nhanh.",
        },
        cmd: "nc -lvnp 4444",
        href: "https://nmap.org/ncat",
        tags: ["networking", "shell", "listener"],
      },
      {
        name: "socat",
        blurb: {
          en: "Advanced bidirectional relay for sockets, files, and pipes.",
          vi: "Bộ chuyển tiếp hai chiều nâng cao cho socket, file, và pipe.",
        },
        cmd: "socat TCP-LISTEN:4444,reuseaddr -",
        href: "http://www.dest-unreach.org/socat",
        tags: ["relay", "tunnel", "shell"],
      },
      {
        name: "proxychains",
        blurb: {
          en: "Route any tool's traffic through a chain of proxies.",
          vi: "Định tuyến lưu lượng của bất kỳ công cụ nào qua một chuỗi proxy.",
        },
        cmd: "proxychains nmap -sT target",
        href: "https://github.com/haad/proxychains",
        tags: ["proxy", "pivot"],
      },
      {
        name: "CyberChef",
        blurb: {
          en: "The cyber 'Swiss-army knife' for encoding, encryption, and data ops.",
          vi: "'Dao đa năng' cho mã hóa, giải mã, và xử lý dữ liệu.",
        },
        href: "https://gchq.github.io/CyberChef",
        tags: ["encoding", "decode", "data"],
      },
      {
        name: "Kali Linux",
        blurb: {
          en: "Pentest-focused distro with hundreds of tools preinstalled.",
          vi: "Bản phân phối chuyên pentest, cài sẵn hàng trăm công cụ.",
        },
        href: "https://www.kali.org",
        tags: ["distro", "platform"],
      },
    ],
  },
];

export const toolStats = {
  total: toolPhases.reduce((n, p) => n + p.tools.length, 0),
  phases: toolPhases.length,
};
