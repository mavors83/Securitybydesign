# Fixture con pattern sicuri: lo scanner non deve segnalare nulla di attivo.
import hashlib, hmac, os, secrets, subprocess
import requests
import yaml
from defusedxml.ElementTree import fromstring

token = secrets.token_urlsafe(32)
digest = hashlib.sha256(data).hexdigest()
cache_key = hashlib.md5(body, usedforsecurity=False).hexdigest()
resp = requests.get(url, timeout=(3, 10))
subprocess.run(["/usr/bin/pdftotext", "-layout", str(src), str(dst)], check=True, timeout=30)
cfg = yaml.safe_load(stream)
legacy = yaml.load(stream, Loader=yaml.SafeLoader)
cur.execute("SELECT * FROM users WHERE id = %s AND tenant_id = %s", (user_id, tenant_id))
logger.info("login attempt user_id=%s outcome=%s", user_id, outcome)
password = os.environ["DB_PASSWORD"]
db_password = "<REPLACE_ME>"
api_key = "${API_KEY}"
password_field = "password"
label = "Select an option from the list " + suffix
ALLOWED_HOSTS = ["payments.example.com"]
DEBUG = False
SESSION_COOKIE_SECURE = True
model.eval()
ok = hmac.compare_digest(expected, received)
print("value: %s" % value)
order_ids = [4111111111111111, 1700000000000]
# sbd-ignore: P-CRYPTO-01 hash usato solo come chiave di cache, nessun uso di sicurezza
etag = hashlib.md5(body).hexdigest()
