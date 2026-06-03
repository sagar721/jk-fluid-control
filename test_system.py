import urllib.request
import urllib.error
import json
import time
import sys
import subprocess
import os

BASE_URL = "http://127.0.0.1:8765"

def print_status(test_name, passed, detail=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} | {test_name:<40} {detail}")
    return passed

def make_request(path, method="GET", data=None, token=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_data = json.dumps(data).encode('utf-8') if data else None
    req = urllib.request.Request(url, data=req_data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
            
    try:
        with urllib.request.urlopen(req) as res:
            res_body = res.read().decode('utf-8')
            return res.getcode(), json.loads(res_body) if res_body else {}, res.headers
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode('utf-8'))
        except:
            body = {}
        return e.code, body, e.headers
    except Exception as e:
        return 500, {"error": str(e)}, {}

def run_all_tests():
    print("======================================================================")
    print("          JK FLUID CONTROLS CRM - SYSTEM & INTEGRATION TEST HARNESS   ")
    print("======================================================================")
    
    # 1. Health Checks
    code, body, _ = make_request("/api/health")
    db_ok = body.get("database_ready") is True
    print_status("System Health Check", code == 200, f"Status: {body.get('ok')}")
    print_status("Database Connection Status", db_ok, f"Engine: {body.get('database_engine')}")
    
    # 2. Login Verification for all 4 Roles
    roles = {
        "Admin": "admin@jkfluidcontrols.com",
        "Manager": "manager@jkfluidcontrols.com",
        "Sales": "sales@jkfluidcontrols.com",
        "Viewer": "viewer@jkfluidcontrols.com"
    }
    tokens = {}
    
    for role, email in roles.items():
        code, body, _ = make_request("/api/auth/login", "POST", {"email": email, "password": "demo123"})
        passed = (code == 200 and "access_token" in body)
        tokens[role] = body.get("access_token") if passed else None
        print_status(f"Authentication - {role}", passed, f"Token: {tokens[role][:15] if passed else 'Failed'}...")

    if not all(tokens.values()):
        print("❌ Critical Auth Failure: Unable to obtain access tokens for all roles. Exiting.")
        sys.exit(1)

    # 3. RBAC Enforcement Checks (Viewer vs Manager vs Sales)
    # Test: Viewer cannot modify data (should return 403)
    viewer_token = tokens["Viewer"]
    admin_token = tokens["Admin"]
    
    # Attempt to create a company as Viewer
    test_company = {"id": "c-test-1", "name": "Test Company Limited", "industry": "Industrial Valves"}
    code, body, _ = make_request("/api/companies", "POST", test_company, token=viewer_token)
    print_status("RBAC - Viewer Write Blocked", code == 403, f"Status: {code} (Forbidden expected)")
    
    # Attempt to create a company as Admin (should succeed)
    code, body, _ = make_request("/api/companies", "POST", test_company, token=admin_token)
    print_status("RBAC - Admin Write Allowed", code == 201 or code == 200, f"Status: {code} (Success expected)")
    
    # 4. Read Modules / Data Loading
    for module in ["companies", "contacts", "inquiries", "quotations", "orders", "activities"]:
        code, body, _ = make_request(f"/api/{module}", "GET", token=admin_token)
        print_status(f"Module Data Loading - {module.capitalize()}", code == 200, f"Count: {len(body)}")
        
    # 5. Dashboard Summary Loading
    code, body, _ = make_request("/api/summary", "GET", token=admin_token)
    print_status("Dashboard Summary Loading", code == 200, f"Metrics: {list(body.keys())}")
    
    # 6. CRUD Validation (Edit & Delete)
    # Edit company as Admin
    edit_company = {"name": "Test Company Limited (Updated)", "industry": "Valves & Controls"}
    code, body, _ = make_request("/api/companies/c-test-1", "PATCH", edit_company, token=admin_token)
    print_status("CRUD - Edit Company", code == 200, f"Status: {code}")
    
    # Delete company as Admin
    code, body, _ = make_request("/api/companies/c-test-1", "DELETE", token=admin_token)
    print_status("CRUD - Delete Company", code == 200, f"Status: {code}")
    
    # 7. AI Assistant Integration
    code, body, _ = make_request("/api/ai/assistant", "POST", {"prompt": "Hello, suggest follow-up template"}, token=admin_token)
    # Since OpenAI key is present in environment, it should succeed. If not, it uses the fallback response.
    print_status("AI Assistant Integration", code == 200, f"Answer: {body.get('answer', '')[:50]}...")
    
    # 8. Rate Limiting Check
    rate_limited = False
    print("Testing Rate Limiter (making 12 requests in rapid succession to /api/generate-message)...")
    for _ in range(12):
        code, body, _ = make_request("/api/generate-message", "POST", {"prompt": "Generate a sales pitch"}, token=admin_token)
        if code == 429:
            rate_limited = True
            break
    print_status("Rate Limiter Hardening", rate_limited, "Returned 429 Too Many Requests as expected")

    # 9. Performance Benchmark
    print("\nRunning Performance Benchmarks...")
    latencies = []
    for _ in range(5):
        start = time.time()
        make_request("/api/summary", "GET", token=admin_token)
        latencies.append((time.time() - start) * 1000)
    avg_latency = sum(latencies) / len(latencies)
    print_status("Performance - Dashboard Latency", avg_latency < 100, f"Average Latency: {avg_latency:.2f}ms")

if __name__ == "__main__":
    run_all_tests()
