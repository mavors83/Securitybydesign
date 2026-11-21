# Fixture con pattern volutamente insicuri: NON usare come esempio.
import hashlib, pickle, random, subprocess, os, tempfile, yaml
import requests

# sbd-expect-next: P-CRYPTO-01
digest = hashlib.md5(data).hexdigest()
# sbd-expect-next: P-CRYPTO-02
cipher = AES.new(key, AES.MODE_ECB)
# sbd-expect-next: P-CRYPTO-03
legacy = DES3.new(key, DES3.MODE_CBC, iv)
# sbd-expect-next: P-CRYPTO-04
reset_token = "".join(random.choice(ALPHABET) for _ in range(32))
# sbd-expect-next: P-TLS-01
resp = requests.get(url, verify=False)
# sbd-expect-next: P-EXEC-01
result = eval(user_expression)
# sbd-expect-next: P-EXEC-03
subprocess.run("convert " + filename, shell=True)
# sbd-expect-next: P-DESER-01
obj = pickle.loads(payload)
# sbd-expect-next: P-DESER-02
cfg = yaml.load(stream)
# sbd-expect-next: P-XXE-01
parser = etree.XMLParser(resolve_entities=True)
# sbd-expect-next: P-SQLI-01
cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
# sbd-expect-next: P-SQLI-02
qs = Customer.objects.extra(where=["name = '%s'" % name])
# sbd-expect-next: P-NOSQL-01
db.users.find({"$where": "this.name == '" + name + "'"})
# sbd-expect-next: P-XSS-01
html = mark_safe(user_bio)
# sbd-expect-next: P-WEB-01
CORS_ALLOW_ALL_ORIGINS = True
# sbd-expect-next: P-WEB-02
@csrf_exempt
# sbd-expect-next: P-WEB-03
DEBUG = True
# sbd-expect-next: P-WEB-04
SESSION_COOKIE_SECURE = False
# sbd-expect-next: P-WEB-05
ALLOWED_HOSTS = ["*"]
# sbd-expect-next: P-AUTH-01
claims = jwt.decode(token, options={"verify_signature": False})
# sbd-expect-next: P-LOG-01
logger.info(f"login attempt user={user} password={password}")
# sbd-expect-next: P-SHELL-02
os.chmod(path, 0o777)
# sbd-expect-next: P-MISC-01
tmp = tempfile.mktemp()
# Soppressione senza motivazione: il finding resta attivo
# sbd-expect-next: P-CRYPTO-01
etag = hashlib.sha1(body).hexdigest()  # sbd-ignore: P-CRYPTO-01
