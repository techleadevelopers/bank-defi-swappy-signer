import express from "express";
import crypto from "crypto";
import TronWebPkg from "tronweb";
import { z } from "zod";
import "dotenv/config";
import { Pool } from "pg";
import { HDKey } from "@scure/bip32";

const EnvSchema = z.object({
  SIGNER_PRIVATE_KEY: z.string().min(32),
  TRON_XPRV: z.string().optional(),
  SIGNER_HMAC_SECRET: z.string().min(32),
  TRON_FULLNODE_URL: z.string().url().default("https://api.trongrid.io"),
  TRON_SOLIDITY_URL: z.string().url().default("https://api.trongrid.io"),
  ALLOW_DEST: z.string().optional(), // comma-separated
  ALLOW_TOKEN_CONTRACTS: z.string().optional(), // comma-separated
  HMAC_MAX_SKEW_SEC: z.coerce.number().default(60),
  DATABASE_URL: z.string().optional()
});

const env = EnvSchema.parse(process.env);

const TronWeb = TronWebPkg?.TronWeb || TronWebPkg?.default?.TronWeb || TronWebPkg;
const tronWeb = new TronWeb({
  fullHost: env.TRON_FULLNODE_URL,
  solidityNode: env.TRON_SOLIDITY_URL,
  eventServer: env.TRON_SOLIDITY_URL,
  privateKey: env.SIGNER_PRIVATE_KEY,
});

const SIGNER_ADDR = tronWeb.address.fromPrivateKey(env.SIGNER_PRIVATE_KEY);
const hdRoot = env.TRON_XPRV ? HDKey.fromExtendedKey(env.TRON_XPRV) : null;

// DB (idempotência persistida)
const pool = env.DATABASE_URL
  ? new Pool({ connectionString: env.DATABASE_URL })
  : null;

async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS signer_idempotency (
      id SERIAL PRIMARY KEY,
      endpoint TEXT NOT NULL,
      idempotency_key TEXT NOT NULL,
      tx_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(endpoint, idempotency_key)
    );
  `);
}
initDb().catch((e) => {
  console.error("Erro ao inicializar DB idempotência", e);
  process.exit(1);
});

// Body: amount como string pra evitar float
const BodySchema = z.object({
  to: z.string().min(20),
  amount: z.string().min(1), // "12.345678"
  tokenContract: z.string().min(30),
  idempotencyKey: z.string().min(8),
});

const app = express();
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// Idempotência (trocar pra Redis/DB em prod)
const idem = new Map();
// Anti-replay mínimo (trocar pra Redis/DB em prod)
const nonceSeen = new Map();

function isHex64(s) {
  return typeof s === "string" && /^[0-9a-f]{64}$/i.test(s);
}

function verifyHmac(req) {
  const sig = req.headers["x-signer-hmac"];
  const ts = req.headers["x-ts"];
  const nonce = req.headers["x-nonce"];

  if (typeof sig !== "string" || !isHex64(sig)) return { ok: false, msg: "HMAC inválido" };
  if (typeof ts !== "string" || typeof nonce !== "string" || nonce.length < 8) return { ok: false, msg: "ts/nonce ausente" };

  const now = Math.floor(Date.now() / 1000);
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum) || Math.abs(now - tsNum) > env.HMAC_MAX_SKEW_SEC) return { ok: false, msg: "timestamp fora da janela" };

  // Anti-replay simples (5 min)
  const nonceKey = `${ts}:${nonce}`;
  if (nonceSeen.has(nonceKey)) return { ok: false, msg: "replay detectado" };
  nonceSeen.set(nonceKey, Date.now());
  setTimeout(() => nonceSeen.delete(nonceKey), 5 * 60 * 1000).unref?.();

  const body = req.rawBody || Buffer.from("");
  const dataToSign = Buffer.concat([Buffer.from(`${ts}.${nonce}.`), body]);

  const digest = crypto.createHmac("sha256", env.SIGNER_HMAC_SECRET).update(dataToSign).digest("hex");
  try {
    return {
      ok: crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(digest, "hex")),
      msg: "ok",
    };
  } catch {
    return { ok: false, msg: "HMAC inválido" };
  }
}

function parseUnits6(amountStr) {
  // "12.345678" -> 12345678n
  if (!/^\d+(\.\d{1,6})?$/.test(amountStr)) throw new Error("amount inválido (use até 6 decimais)");
  const [intPart, decPart = ""] = amountStr.split(".");
  const dec = (decPart + "000000").slice(0, 6);
  return BigInt(intPart) * 1_000_000n + BigInt(dec);
}

function allowlist(str, value) {
  if (!str) return true;
  const allowed = str.split(",").map((s) => s.trim()).filter(Boolean);
  return allowed.includes(value);
}

async function idemGet(endpoint, key) {
  if (pool) {
    const { rows } = await pool.query(
      "SELECT tx_id FROM signer_idempotency WHERE endpoint = $1 AND idempotency_key = $2 LIMIT 1",
      [endpoint, key]
    );
    return rows[0]?.tx_id || null;
  }
  return idem.get(`${endpoint}:${key}`) || null;
}

async function idemSet(endpoint, key, txId) {
  if (pool) {
    await pool.query(
      "INSERT INTO signer_idempotency (endpoint, idempotency_key, tx_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
      [endpoint, key, txId]
    );
  } else {
    idem.set(`${endpoint}:${key}`, txId);
  }
}

app.post("/sign/transfer", async (req, res) => {
  const h = verifyHmac(req);
  if (!h.ok) return res.status(401).json({ error: h.msg });

  const parsed = BodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "payload inválido", details: parsed.error.issues });

  const { to, amount, tokenContract, idempotencyKey } = parsed.data;

  if (!allowlist(env.ALLOW_DEST, to)) return res.status(403).json({ error: "destino não permitido" });
  if (!allowlist(env.ALLOW_TOKEN_CONTRACTS, tokenContract)) return res.status(403).json({ error: "tokenContract não permitido" });

  const cached = await idemGet("single.transfer", idempotencyKey);
  if (cached) return res.json({ txId: cached, idempotent: true });

  try {
    const amountUnits = parseUnits6(amount);

    const tx = await tronWeb.transactionBuilder.triggerSmartContract(
      tokenContract,
      "transfer(address,uint256)",
      { feeLimit: 10_000_000 },
      [
        { type: "address", value: to },
        { type: "uint256", value: amountUnits.toString() },
      ],
      tronWeb.address.toHex(SIGNER_ADDR) // 🔒 from travado no signer
    );

    if (!tx?.transaction) throw new Error("Falha ao construir tx");

    const signed = await tronWeb.trx.sign(tx.transaction, env.SIGNER_PRIVATE_KEY);
    const broadcast = await tronWeb.trx.sendRawTransaction(signed);

    if (!broadcast?.result || !broadcast?.txid) throw new Error(`Broadcast falhou: ${JSON.stringify(broadcast)}`);

    await idemSet("single.transfer", idempotencyKey, broadcast.txid);
    return res.json({ txId: broadcast.txid, from: SIGNER_ADDR });
  } catch (err) {
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

// HD transfer a partir de derivationIndex (requer TRON_XPRV)
const HdBodySchema = z.object({
  derivationIndex: z.number().int().nonnegative(),
  to: z.string().min(20),
  amount: z.string().min(1), // decimal string com até 6 casas
  tokenContract: z.string().min(30),
  idempotencyKey: z.string().min(8),
});

app.post("/sign/hd/transfer", async (req, res) => {
  if (!hdRoot) return res.status(400).json({ error: "TRON_XPRV não configurado" });
  const h = verifyHmac(req);
  if (!h.ok) return res.status(401).json({ error: h.msg });

  const parsed = HdBodySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "payload inválido", details: parsed.error.issues });
  const { derivationIndex, to, amount, tokenContract, idempotencyKey } = parsed.data;

  if (!allowlist(env.ALLOW_DEST, to)) return res.status(403).json({ error: "destino não permitido" });
  if (!allowlist(env.ALLOW_TOKEN_CONTRACTS, tokenContract)) return res.status(403).json({ error: "tokenContract não permitido" });

  const cached = await idemGet("hd.transfer", idempotencyKey);
  if (cached) return res.json({ txId: cached, idempotent: true });

  try {
    // path padrão m/44'/195'/0'/0/{index}
    const child = hdRoot
      .deriveChild(44 | 0x80000000)
      .deriveChild(195 | 0x80000000)
      .deriveChild(0 | 0x80000000)
      .deriveChild(0)
      .deriveChild(derivationIndex);
    if (!child.privateKey) throw new Error("Child private key ausente");
    const childAddr = tronWeb.address.fromPrivateKey(child.privateKey);

    const amountUnits = parseUnits6(amount);

    const tx = await tronWeb.transactionBuilder.triggerSmartContract(
      tokenContract,
      "transfer(address,uint256)",
      { feeLimit: 10_000_000 },
      [
        { type: "address", value: to },
        { type: "uint256", value: amountUnits.toString() },
      ],
      tronWeb.address.toHex(childAddr)
    );

    if (!tx?.transaction) throw new Error("Falha ao construir tx");

    const signed = await tronWeb.trx.sign(tx.transaction, child.privateKey);
    const broadcast = await tronWeb.trx.sendRawTransaction(signed);
    if (!broadcast?.result || !broadcast?.txid) throw new Error(`Broadcast falhou: ${JSON.stringify(broadcast)}`);

    await idemSet("hd.transfer", idempotencyKey, broadcast.txid);
    return res.json({ txId: broadcast.txid, from: childAddr });
  } catch (err) {
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

const port = process.env.PORT || 4001;
app.listen(port, () => console.log(`Signer listening on ${port} | addr=${SIGNER_ADDR}`));
