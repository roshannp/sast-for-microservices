#!/bin/bash
# ============================================================
# Setup Script: Vulnerable Microservices Test Environment
# ============================================================
# Creates 5 realistic microservices with intentional OWASP
# vulnerabilities, real git commit history (including secrets
# that were "deleted" but remain in history), shared secrets
# across services, and vulnerable dependencies.
#
# Usage:
#   chmod +x setup_vulnerable_repos.sh
#   ./setup_vulnerable_repos.sh
#   python owasp_agent_v2.py --local ./vuln-org --org vuln-org --openai-key sk-xxx
# ============================================================

BASE="./vuln-org"
rm -rf "$BASE"
mkdir -p "$BASE"

GIT_NAME="Dev User"
GIT_EMAIL="dev@vuln-org.com"

init_repo() {
  local name=$1
  mkdir -p "$BASE/$name"
  cd "$BASE/$name"
  git init -q
  git config user.name "$GIT_NAME"
  git config user.email "$GIT_EMAIL"
  cd - > /dev/null
}

commit() {
  local repo=$1
  local msg=$2
  cd "$BASE/$repo"
  git add -A
  git commit -q -m "$msg"
  cd - > /dev/null
}

echo ""
echo "============================================================"
echo "  Building Vulnerable Microservice Test Environment"
echo "============================================================"

# ============================================================
# 1. auth-service  (Python/Flask)
#    Issues: hardcoded JWT secret, SQL injection, weak crypto,
#            JWT verify=False, debug mode, secrets in git history
# ============================================================
echo "  [1/5] auth-service..."
init_repo "auth-service"

# --- COMMIT 1: Initial implementation with hardcoded secrets ---
cat > "$BASE/auth-service/app.py" << 'PYEOF'
from flask import Flask, request, jsonify
import hashlib, sqlite3, jwt, os

app = Flask(__name__)

# JWT secret hardcoded (will "fix" this later)
JWT_SECRET = "super_secret_jwt_key_do_not_share"
DB_PASS = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DEBUG = True

def get_db():
    return sqlite3.connect("users.db")

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    # A02: MD5 for password hashing
    pwd_hash = hashlib.md5(password.encode()).hexdigest()

    # A03: SQL injection via string concatenation
    db = get_db()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + pwd_hash + "'"
    user = db.execute(query).fetchone()

    if user:
        # A07: JWT with no expiry
        token = jwt.encode({"user_id": user[0], "username": username},
                           JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/verify", methods=["POST"])
def verify_token():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        # A07: JWT verification disabled
        payload = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"valid": True, "user": payload})
    except Exception:
        return jsonify({"valid": False}), 401

@app.route("/user/<user_id>", methods=["GET"])
def get_user(user_id):
    # A01: No auth check, direct object reference
    db = get_db()
    # A03: SQL injection
    user = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    return jsonify({"user": user})

@app.route("/admin/users", methods=["GET"])
def list_all_users():
    # API4: No pagination, returns everything
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return jsonify({"users": users})

if __name__ == "__main__":
    app.run(debug=DEBUG)
PYEOF

cat > "$BASE/auth-service/requirements.txt" << 'EOF'
Flask==1.0.2
PyJWT==1.7.1
Werkzeug==0.15.3
requests==2.19.1
cryptography==2.3
Pillow==5.2.0
EOF

cat > "$BASE/auth-service/config.py" << 'EOF'
# Production config
DATABASE_URL = "postgresql://admin:admin123@prod-db:5432/users"
REDIS_URL = "redis://:redispassword123@prod-redis:6379"
STRIPE_SECRET_KEY = "sk_live_FAKE_BUT_REALISTIC_KEY_12345"
INTERNAL_API_KEY = "internal-shared-secret-key-changeme"
EOF

commit "auth-service" "feat: initial auth service implementation"

# --- COMMIT 2: "Fix" secrets (but history keeps them!) ---
sed -i 's/JWT_SECRET = "super_secret_jwt_key_do_not_share"/JWT_SECRET = os.getenv("JWT_SECRET", "fallback-still-bad")/' "$BASE/auth-service/app.py"
sed -i 's/DB_PASS = "admin123"/DB_PASS = os.getenv("DB_PASS")/' "$BASE/auth-service/app.py"
cat > "$BASE/auth-service/config.py" << 'EOF'
# Secrets moved to environment variables
DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
EOF
commit "auth-service" "fix: move secrets to environment variables (security review)"

# --- COMMIT 3: Add password reset (still vulnerable) ---
cat >> "$BASE/auth-service/app.py" << 'PYEOF'

import subprocess, os

@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.json.get("email")
    # A03: Command injection
    os.system(f"echo 'Reset link sent' | mail -s 'Reset' {email}")
    # A09: Logging password in plaintext
    print(f"Password reset requested for: {email} password={request.json.get('new_password')}")
    return jsonify({"message": "Reset email sent"})

@app.route("/profile", methods=["POST"])
def update_profile():
    # API3: Mass assignment - binds entire request body to user
    user_data = request.json
    db = get_db()
    db.execute("UPDATE users SET role=? WHERE id=?",
               (user_data.get("role"), user_data.get("id")))
    return jsonify({"updated": True})
PYEOF
commit "auth-service" "feat: add password reset and profile update endpoints"

# ============================================================
# 2. payment-service  (Python)
#    Issues: SSRF, hardcoded Stripe key, CORS *, pickle, BOLA
# ============================================================
echo "  [2/5] payment-service..."
init_repo "payment-service"

cat > "$BASE/payment-service/app.py" << 'PYEOF'
from flask import Flask, request, jsonify
import requests, pickle, hashlib, os

app = Flask(__name__)

# A02: Hardcoded API keys (same internal key as auth-service — cross-service!)
STRIPE_KEY = "sk_live_FAKE_BUT_REALISTIC_KEY_12345"
INTERNAL_API_KEY = "internal-shared-secret-key-changeme"
DB_PASS = "admin123"

# A05: CORS wildcard
from flask_cors import CORS
CORS(app, origins="*")

@app.route("/pay", methods=["POST"])
def process_payment():
    data = request.json
    user_id = data.get("user_id")
    amount  = data.get("amount")

    # A01: BOLA — no check that user_id matches authenticated user
    # A10: SSRF — webhook URL taken directly from user input
    webhook_url = data.get("webhook_url")
    if webhook_url:
        requests.post(webhook_url, json={"status": "paid", "amount": amount})

    return jsonify({"status": "success"})

@app.route("/invoice/<invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    # A01: BOLA — returns any invoice without ownership check
    # API1: Object ID direct from URL, no ownership check
    invoice = db.query(Invoice, id=invoice_id)
    return jsonify(invoice)

@app.route("/fetch-rates", methods=["POST"])
def fetch_exchange_rates():
    # A10: SSRF — user controls the URL
    url = request.args.get("source_url")
    response = requests.get(url)
    return jsonify(response.json())

@app.route("/load-session", methods=["POST"])
def load_session():
    # A08: Insecure deserialization
    session_data = request.get_data()
    session = pickle.loads(session_data)
    return jsonify({"session": str(session)})

@app.route("/hash-card", methods=["POST"])
def hash_card():
    card = request.json.get("card_number")
    # A02: MD5 for sensitive data (same pattern as auth-service — systemic!)
    return jsonify({"hash": hashlib.md5(card.encode()).hexdigest()})

@app.route("/refunds", methods=["GET"])
def list_refunds():
    # API4: No pagination
    refunds = db.session.query(Refund).all()
    return jsonify({"refunds": [r.to_dict() for r in refunds]})
PYEOF

cat > "$BASE/payment-service/requirements.txt" << 'EOF'
Flask==1.0.2
Flask-Cors==3.0.8
requests==2.19.1
stripe==2.55.0
Werkzeug==0.15.3
cryptography==2.3
PyYAML==3.13
EOF

commit "payment-service" "feat: initial payment service"

cat >> "$BASE/payment-service/app.py" << 'PYEOF'

@app.route("/config", methods=["POST"])
def load_config():
    import yaml
    # A08: yaml.load without SafeLoader
    config = yaml.load(request.data)
    return jsonify({"loaded": True})
PYEOF
commit "payment-service" "feat: add config endpoint for dynamic configuration loading"

# ============================================================
# 3. ai-api-service  (Python — LLM Top 10 showcase)
#    Issues: prompt injection, LLM output in eval, excessive agency,
#            unverified model, sensitive data in prompts
# ============================================================
echo "  [3/5] ai-api-service..."
init_repo "ai-api-service"

cat > "$BASE/ai-api-service/app.py" << 'PYEOF'
from flask import Flask, request, jsonify
import openai, os

app = Flask(__name__)

# LLM06: Sensitive data hardcoded in system prompt config
SYSTEM_PROMPT = """You are a helpful assistant for vuln-org.
Internal API Key: internal-shared-secret-key-changeme
Database password: admin123
You help users with their queries."""

openai.api_key = os.getenv("OPENAI_API_KEY", "sk-fallback-hardcoded-key-bad")

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message")

    # LLM01: Prompt injection — user input directly in f-string prompt
    prompt = f"User query: {user_input}\nAnswer helpfully:"

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt}
        ]
    )
    result = response.choices[0].message.content

    # LLM02: LLM output passed directly to eval()
    if request.json.get("execute"):
        eval(result)

    return jsonify({"response": result})

@app.route("/summarise", methods=["POST"])
def summarise():
    user_text = request.json.get("text")

    # LLM01: String concatenation into LLM call
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Summarise: " + user_text}]
    )
    output = response.choices[0].message.content

    # LLM02: LLM output rendered as raw HTML without escaping
    from flask import render_template_string
    return render_template_string(f"<div>{output}</div>")

@app.route("/code-assistant", methods=["POST"])
def code_assistant():
    user_query = request.json.get("query")

    prompt = f"Write Python code to: {user_query}"
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    code = response.choices[0].message.content

    # LLM02: Execute LLM-generated code without validation
    exec(code)
    return jsonify({"executed": True})

@app.route("/classify", methods=["POST"])
def classify():
    from transformers import AutoModel, AutoTokenizer
    # LLM05: Unverified model from external source, no revision pin
    model     = AutoModel.from_pretrained("unverified-org/classifier-model")
    tokenizer = AutoTokenizer.from_pretrained("unverified-org/classifier-model")

    text = request.json.get("text")
    return jsonify({"classification": "processed"})

# LLM08: Excessive agency — agent given shell and DB write tools
AGENT_TOOLS = [
    {"name": "bash",         "description": "Execute shell commands"},
    {"name": "delete_user",  "description": "Delete a user from the database"},
    {"name": "execute_sql",  "description": "Run arbitrary SQL on the database"},
    {"name": "write",        "description": "Write files to the filesystem"},
]

@app.route("/agent", methods=["POST"])
def run_agent():
    user_task = request.json.get("task")
    # LLM01: User task directly in prompt with tools including shell access
    prompt = f"Complete this task: {user_task}"
    # Agent has bash, delete, SQL write access — LLM08 excessive agency
    tools = AGENT_TOOLS
    return jsonify({"tools_available": [t["name"] for t in tools]})
PYEOF

cat > "$BASE/ai-api-service/requirements.txt" << 'EOF'
Flask==1.0.2
openai==0.28.0
transformers==4.28.0
torch==1.13.0
Werkzeug==0.15.3
requests==2.19.1
EOF

commit "ai-api-service" "feat: initial AI chat and code assistant service"

# Add a commit with a secret that gets "removed"
cat >> "$BASE/ai-api-service/app.py" << 'PYEOF'

# Temporary debug key - REMOVE BEFORE MERGE
ANTHROPIC_KEY = "sk-ant-api03-FAKE-BUT-REALISTIC-KEY-FOR-TESTING"
OPENAI_BACKUP = "sk-proj-FAKE-OPENAI-KEY-FOR-TESTING-PURPOSES-ONLY"
PYEOF
commit "ai-api-service" "debug: add backup API keys for testing"

# "Remove" the keys
sed -i '/ANTHROPIC_KEY/d; /OPENAI_BACKUP/d; /Temporary debug/d; /REMOVE BEFORE MERGE/d' "$BASE/ai-api-service/app.py"
commit "ai-api-service" "fix: remove debug API keys before production deploy"

# ============================================================
# 4. order-service  (Java — Web + API Top 10)
#    Issues: SQLi, hardcoded creds, JWT no expiry, mass assignment
# ============================================================
echo "  [4/5] order-service..."
init_repo "order-service"

mkdir -p "$BASE/order-service/src/main/java/com/vulnorg/orders"

cat > "$BASE/order-service/src/main/java/com/vulnorg/orders/OrderController.java" << 'JAVAEOF'
package com.vulnorg.orders;

import org.springframework.web.bind.annotation.*;
import io.jsonwebtoken.Jwts;
import java.sql.*;
import java.net.URL;
import java.security.MessageDigest;

@RestController
@RequestMapping("/api/v1/orders")
public class OrderController {

    // A02: Hardcoded credentials (same DB_PASS as Python services — systemic!)
    private static final String DB_URL = "jdbc:postgresql://prod-db:5432/orders";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "admin123";
    private static final String JWT_SECRET = "super_secret_jwt_key_do_not_share";
    private static final String INTERNAL_KEY = "internal-shared-secret-key-changeme";

    @GetMapping("/{orderId}")
    public Order getOrder(@PathVariable String orderId, HttpServletRequest request) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        // A03: SQL injection via string concatenation
        String query = "SELECT * FROM orders WHERE id = " + orderId;
        ResultSet rs = conn.createStatement().executeQuery(query);
        return mapToOrder(rs);
    }

    @PostMapping("/search")
    public List<Order> searchOrders(@RequestParam String keyword) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        // A03: SQL injection in search
        String query = "SELECT * FROM orders WHERE description LIKE '%" + keyword + "%'";
        ResultSet rs = conn.createStatement().executeQuery(query);
        return mapToList(rs);
    }

    @PostMapping("/")
    public Order createOrder(@RequestBody Order order) {
        // API3: Mass assignment — @RequestBody without @Valid
        // User can set internal fields like 'discount', 'approved', 'adminOverride'
        return orderRepository.save(order);
    }

    @GetMapping("/all")
    public List<Order> getAllOrders() {
        // API4: No pagination — returns all orders
        return orderRepository.findAll();
    }

    @PostMapping("/issue-token")
    public String issueToken(String userId) {
        // A07: JWT with no expiration set
        return Jwts.builder()
                   .claim("userId", userId)
                   .claim("role", "user")
                   .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256,
                             JWT_SECRET.getBytes())
                   .compact();
    }

    @GetMapping("/fetch-tracking")
    public String fetchTracking(@RequestParam String trackingUrl) throws Exception {
        // A10: SSRF — URL from user input
        URL url = new URL(trackingUrl);
        return url.openStream().toString();
    }

    @GetMapping("/hash-order")
    public String hashOrder(@RequestParam String orderId) throws Exception {
        // A02: MD5 for hashing (same pattern across all services — systemic!)
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(orderId.getBytes()));
    }
}
JAVAEOF

cat > "$BASE/order-service/src/main/java/com/vulnorg/orders/UserController.java" << 'JAVAEOF'
package com.vulnorg.orders;

import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    @PostMapping("/import")
    public String importUsers(@RequestBody byte[] data) throws Exception {
        // A08: Java deserialization on untrusted data
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        return "Imported: " + obj.toString();
    }

    @PostMapping("/run-report")
    public String runReport(@RequestParam String reportName) throws Exception {
        // A03: Command injection via Runtime.exec()
        Process p = Runtime.getRuntime().exec("python3 reports/" + reportName + ".py");
        return "Report running";
    }
}
JAVAEOF

cat > "$BASE/order-service/pom.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.vulnorg</groupId>
  <artifactId>order-service</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>2.3.1.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>io.jsonwebtoken</groupId>
      <artifactId>jjwt</artifactId>
      <version>0.9.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.struts</groupId>
      <artifactId>struts2-core</artifactId>
      <version>2.5.16</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.8</version>
    </dependency>
  </dependencies>
</project>
EOF

commit "order-service" "feat: initial order service with Java/Spring Boot"

# ============================================================
# 5. api-gateway  (Python — cross-cutting concerns)
#    Issues: CORS *, no rate limiting, SSRF, logging secrets,
#            passes auth token in HTTP logs
# ============================================================
echo "  [5/5] api-gateway..."
init_repo "api-gateway"

cat > "$BASE/api-gateway/gateway.py" << 'PYEOF'
from flask import Flask, request, jsonify, Response
import requests, logging, os, yaml

app = Flask(__name__)

# A05: CORS wildcard (THIRD service with this — systemic!)
from flask_cors import CORS
CORS(app, origins="*", allow_headers="*")

# A05: Debug mode
DEBUG = True

# A02: Hardcoded shared secret (appears in auth, payment, order, gateway — systemic!)
INTERNAL_API_KEY = "internal-shared-secret-key-changeme"
JWT_SECRET = "super_secret_jwt_key_do_not_share"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

SERVICES = {
    "auth":    "http://auth-service:5000",
    "payment": "http://payment-service:5001",
    "orders":  "http://order-service:8080",
    "ai":      "http://ai-api-service:5002",
}

@app.route("/<service>/<path:endpoint>", methods=["GET","POST","PUT","DELETE"])
def proxy(service, endpoint):
    if service not in SERVICES:
        return jsonify({"error": "Unknown service"}), 404

    # A09: Logging Authorization token (sensitive!)
    auth_token = request.headers.get("Authorization", "")
    logger.debug(f"Proxying request: service={service} token={auth_token} password={request.json.get('password','') if request.is_json else ''}")

    # A10: SSRF — user can override the upstream URL
    upstream = request.args.get("upstream_override") or SERVICES[service]
    target   = f"{upstream}/{endpoint}"

    resp = requests.request(
        method  = request.method,
        url     = target,
        headers = {k:v for k,v in request.headers if k != "Host"},
        json    = request.json,
    )
    return Response(resp.content, status=resp.status_code,
                    content_type=resp.headers.get("Content-Type"))

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "internal_key": INTERNAL_API_KEY,  # A09: Exposing secret in health endpoint
        "debug": DEBUG,
    })

@app.route("/config/reload", methods=["POST"])
def reload_config():
    config_data = request.data
    # A08: yaml.load without SafeLoader
    config = yaml.load(config_data)
    return jsonify({"reloaded": True})

# API9: Multiple stale API versions
@app.route("/api/v1/<path:path>")
@app.route("/api/v2/<path:path>")
@app.route("/api/v3/<path:path>")
def versioned_proxy(path):
    # All versions active simultaneously, no auth on v1/v2
    return proxy("auth", path)
PYEOF

cat > "$BASE/api-gateway/requirements.txt" << 'EOF'
Flask==1.0.2
Flask-Cors==3.0.8
requests==2.19.1
PyYAML==3.13
Werkzeug==0.15.3
urllib3==1.24.1
Jinja2==2.10
EOF

commit "api-gateway" "feat: initial API gateway implementation"

cat >> "$BASE/api-gateway/gateway.py" << 'PYEOF'

@app.route("/admin/run", methods=["POST"])
def admin_run():
    import subprocess, os
    cmd = request.json.get("command")
    # A03: Command injection, no auth check
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})
PYEOF
commit "api-gateway" "feat: add admin command runner for ops team"

echo ""
echo "============================================================"
echo "  Done! Vulnerable microservice org created at: $BASE"
echo ""
echo "  Services:"
echo "    auth-service    (Python/Flask)  — JWT, SQLi, weak crypto"
echo "    payment-service (Python/Flask)  — SSRF, pickle, CORS *"
echo "    ai-api-service  (Python)        — Prompt injection, eval(LLM)"
echo "    order-service   (Java/Spring)   — SQLi, deserialization"
echo "    api-gateway     (Python/Flask)  — SSRF, CORS *, logging secrets"
echo ""
echo "  Cross-service patterns:"
echo "    INTERNAL_API_KEY = 'internal-shared-secret-key-changeme' (all 5)"
echo "    JWT_SECRET       = 'super_secret_jwt_key_do_not_share'   (4 services)"
echo "    DB_PASS          = 'admin123'                            (3 services)"
echo "    MD5 hashing      = 3 services (systemic pattern)"
echo "    CORS wildcard    = 3 services (systemic pattern)"
echo "    DEBUG=True       = 2 services"
echo ""
echo "  Git history secrets (deleted but still in history):"
echo "    ai-api-service  — Anthropic + OpenAI keys added then removed"
echo "    auth-service    — AWS keys committed then 'fixed'"
echo ""
echo "  Run the agent:"
echo "    python owasp_agent_v2.py \\"
echo "      --local $BASE \\"
echo "      --org vuln-org \\"
echo "      --openai-key sk-xxx"
echo "============================================================"
echo ""
