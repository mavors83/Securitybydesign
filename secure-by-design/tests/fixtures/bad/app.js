// Fixture con pattern volutamente insicuri: NON usare come esempio.
const { exec } = require("child_process");
// sbd-expect-next: P-CRYPTO-01
const etag = crypto.createHash("md5").update(body).digest("hex");
// sbd-expect-next: P-CRYPTO-04
const sessionId = Math.random().toString(36).slice(2);
// sbd-expect-next: P-TLS-01
const agent = new https.Agent({ rejectUnauthorized: false });
// sbd-expect-next: P-EXEC-01
exec(`convert ${req.query.file} out.png`);
// sbd-expect-next: P-EXEC-02
const fn = new Function("a", req.body.code);
// sbd-expect-next: P-EXEC-04
require("child_process").execSync("ls " + dir);
// sbd-expect-next: P-SQLI-01
db.query("SELECT * FROM orders WHERE id = " + req.params.id);
// sbd-expect-next: P-SQLI-02
await prisma.$queryRawUnsafe(query);
// sbd-expect-next: P-XSS-01
element.innerHTML = comment.text;
// sbd-expect-next: P-WEB-01
app.use(cors());
// sbd-expect-next: P-WEB-04
res.cookie("session", id, { httpOnly: false });
// sbd-expect-next: P-AUTH-01
jwt.verify(token, key, { algorithms: ["none"] });
// sbd-expect-next: P-AUTH-02
const claims = jwt.decode(token);
// sbd-expect-next: P-LOG-01
console.log("auth header", req.headers.authorization);
