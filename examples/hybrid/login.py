"""Adapt the login payload and response fields to your authorized test app.

Copy to <ARTEX workDir>/auth/login.py. Supply credentials in the backend's
environment: ARTEX_LOGIN_SECRET_USER_A_USERNAME / ARTEX_LOGIN_SECRET_USER_A_PASSWORD, etc.
Only JSON is printed to stdout; diagnostics must not contain secrets.
"""
import http.cookiejar
import json
import os
import urllib.request

profile = os.environ["ARTEX_AUTH_PROFILE"]
base = os.environ["ARTEX_TARGET_BASE_URL"].rstrip("/")
prefix = "ARTEX_LOGIN_SECRET_" + profile.upper() + "_"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
payload = json.dumps({
    "username": os.environ[prefix + "USERNAME"],
    "password": os.environ[prefix + "PASSWORD"],
}).encode()
with opener.open(urllib.request.Request(
    base + "/api/login", data=payload,
    headers={"Content-Type": "application/json"}, method="POST",
), timeout=15) as response:
    login = json.load(response)

# Example app returns {"user":{"id":...,"role":...}} after login and
# /api/me returns {"id":...}. Change this mapping for your application.
print(json.dumps({
    "cookies": [{"Name": c.name, "Value": c.value, "Domain": c.domain,
                 "Path": c.path, "Secure": c.secure} for c in jar],
    "headers": {},
    "identity": {"subject": str(login["user"]["id"]),
                 "role": login["user"].get("role", "user")},
}))
