// Fixture con pattern sicuri: lo scanner non deve segnalare nulla.
import { randomBytes, timingSafeEqual } from "node:crypto";
import { execFile } from "node:child_process";
const token = randomBytes(32).toString("base64url");
await run("/usr/bin/pdftotext", ["-layout", inputPath, outputPath]);
await pool.query("SELECT * FROM orders WHERE id = $1 AND tenant_id = $2", [id, user.tenantId]);
await prisma.$queryRaw`SELECT * FROM orders WHERE id = ${id} AND tenant_id = ${tenantId}`;
const m = /([a-z]+)/.exec(input);
element.textContent = comment.text;
element.innerHTML = "";
container.innerHTML = DOMPurify.sanitize(html);
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
res.cookie("__Host-session", id, { secure: true, httpOnly: true, sameSite: "lax", path: "/" });
const { payload } = await jwtVerify(token, JWKS, { issuer, audience, algorithms: ["ES256"] });
const shuffled = items.sort(() => Math.random() - 0.5);
console.log("request completed", { requestId, status });
const transporter = nodemailer.createTransport({ host, port: 587, secure: false });
