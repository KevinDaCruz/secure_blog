import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import jwt from "jsonwebtoken";

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "secure-blog-test-"));
const DB_PATH = path.join(tmpDir, "test.db");
process.env.DB_PATH = DB_PATH;
const SECRET = crypto.randomBytes(48).toString("base64");
process.env.JWT_SECRET = SECRET;
process.env.JWT_EXPIRES_IN = "15m";

// Capture de tout ce que le serveur écrit dans la console.
const logs = [];
for (const method of ["log", "info", "warn", "error"]) {
  const original = console[method];
  console[method] = (...args) => {
    logs.push(args.map(String).join(" "));
    if (process.env.DEBUG) original(...args);
  };
}

const { default: app } = await import("../src/app.js");

let server;
let baseUrl;
const responseBodies = [];

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://localhost:${server.address().port}`;
});

after(() => {
  server.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

async function request(urlPath, { method = "GET", body, rawBody, cookie } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(baseUrl + urlPath, {
    method,
    headers,
    body: rawBody ?? (body && JSON.stringify(body)),
  });
  const text = await res.text();
  responseBodies.push(text);
  return { res, text, json: () => JSON.parse(text) };
}

function authCookie(res) {
  return res.headers.getSetCookie().find((c) => c.startsWith("access_token="));
}

function tokenFromResponse(res) {
  return authCookie(res)?.split(";")[0].split("=")[1];
}

// Mot de passe facilement repérable pour pouvoir le chercher partout.
const PASSWORD = "Pl41nT3xt-Canary!";
const credentials = { username: "alice", password: PASSWORD };
let cookie;
let validToken;
let user;

describe("inscription", () => {
  test("crée l'utilisateur sans jamais renvoyer le mot de passe ni son hash", async () => {
    const { res, json } = await request("/api/register", { method: "POST", body: credentials });
    assert.equal(res.status, 201);
    assert.deepEqual(Object.keys(json().user).sort(), ["id", "role", "username"]);
    assert.equal(tokenFromResponse(res), undefined, "pas de connexion automatique à l'inscription");
  });

  test("identifiant déjà pris -> 409", async () => {
    const { res } = await request("/api/register", {
      method: "POST",
      body: { username: "ALICE", password: "autre-mot-de-passe" },
    });
    assert.equal(res.status, 409);
  });

  test("mot de passe trop court -> 400", async () => {
    const { res } = await request("/api/register", { method: "POST", body: { username: "bob", password: "court" } });
    assert.equal(res.status, 400);
  });
});

describe("connexion par JWT", () => {
  test("/api/me sans jeton -> 401", async () => {
    const { res } = await request("/api/me");
    assert.equal(res.status, 401);
  });

  test("mauvais mot de passe -> 401 sans cookie", async () => {
    const { res } = await request("/api/login", { method: "POST", body: { ...credentials, password: "mauvais-mdp" } });
    assert.equal(res.status, 401);
    assert.equal(tokenFromResponse(res), undefined);
  });

  test("utilisateur inconnu -> même réponse que mauvais mot de passe", async () => {
    const { res, json } = await request("/api/login", { method: "POST", body: { username: "nobody", password: PASSWORD } });
    assert.equal(res.status, 401);
    assert.equal(json().error, "Identifiants invalides");
  });

  test("login correct pose le JWT dans un cookie HttpOnly + Secure + SameSite=Strict", async () => {
    const { res, json } = await request("/api/login", { method: "POST", body: credentials });
    assert.equal(res.status, 200);
    user = json().user;
    assert.equal(user.username, "alice");
    assert.equal(json().token, undefined, "le jeton ne doit pas être exposé dans le corps");

    const setCookie = authCookie(res);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /Secure/);
    assert.match(setCookie, /SameSite=Strict/);
    assert.match(setCookie, /Max-Age=900/);

    validToken = tokenFromResponse(res);
    cookie = `access_token=${validToken}`;
    const decoded = jwt.decode(validToken, { complete: true });
    assert.equal(decoded.header.alg, "HS256");
    assert.equal(decoded.payload.exp - decoded.payload.iat, 15 * 60, "expiration courte (15 min)");
  });

  test("la session persiste d'une requête à l'autre (rafraîchissement de page)", async () => {
    for (let i = 0; i < 3; i++) {
      const { res, json } = await request("/api/me", { cookie });
      assert.equal(res.status, 200);
      assert.equal(json().user.username, "alice");
    }
  });

  test("les routes d'écriture sont protégées", async () => {
    assert.equal((await request("/api/posts", { method: "POST", body: { title: "t", content: "c" } })).res.status, 401);
    const { res } = await request("/api/posts", { method: "POST", cookie, body: { title: "Hello", content: "Premier article" } });
    assert.equal(res.status, 201);
    assert.equal((await request("/api/posts")).json().posts.length, 1);
  });

  test("logout efface le cookie", async () => {
    const { res } = await request("/api/logout", { method: "POST", cookie });
    assert.equal(res.status, 204);
    assert.match(authCookie(res), /access_token=;/);
    assert.match(authCookie(res), /Expires=Thu, 01 Jan 1970/);
  });
});

describe("critère TP2 : rejet systématique des jetons expirés ou altérés", () => {
  const claims = () => ({ username: "alice", role: "user" });
  const signOpts = () => ({
    algorithm: "HS256",
    issuer: "secure-blog",
    audience: "secure-blog-api",
    subject: String(user.id),
  });
  const reencode = (token, mutate) => {
    const [header, payload, signature] = token.split(".");
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    mutate(data);
    return [header, Buffer.from(JSON.stringify(data)).toString("base64url"), signature].join(".");
  };

  async function assertRejected(token, expectedCode) {
    for (const [method, urlPath, body] of [
      ["GET", "/api/me"],
      ["POST", "/api/posts", { title: "x", content: "y" }],
      ["DELETE", "/api/posts/1"],
    ]) {
      const { res, json } = await request(urlPath, { method, body, cookie: token && `access_token=${token}` });
      assert.equal(res.status, 401, `${method} ${urlPath} doit renvoyer 401`);
      assert.equal(json().code, expectedCode);
      if (expectedCode !== "NO_TOKEN") {
        assert.match(authCookie(res), /Expires=Thu, 01 Jan 1970/, "le cookie invalide doit être effacé");
      }
    }
  }

  test("sans jeton", async () => {
    await assertRejected(undefined, "NO_TOKEN");
  });

  test("jeton expiré (signature pourtant valide)", async () => {
    const expired = jwt.sign({ ...claims(), exp: Math.floor(Date.now() / 1000) - 1 }, SECRET, signOpts());
    await assertRejected(expired, "TOKEN_EXPIRED");
  });

  test("payload modifié (élévation de rôle) sans re-signer", async () => {
    await assertRejected(reencode(validToken, (p) => (p.role = "admin")), "TOKEN_INVALID");
  });

  test("prolongation de l'expiration sans re-signer", async () => {
    await assertRejected(reencode(validToken, (p) => (p.exp += 365 * 24 * 3600)), "TOKEN_INVALID");
  });

  test("usurpation d'un autre utilisateur (sub modifié) sans re-signer", async () => {
    await assertRejected(reencode(validToken, (p) => (p.sub = "999")), "TOKEN_INVALID");
  });

  test("signature altérée", async () => {
    const [header, payload, signature] = validToken.split(".");
    const flipped = (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    await assertRejected([header, payload, flipped].join("."), "TOKEN_INVALID");
  });

  test("signature supprimée", async () => {
    const [header, payload] = validToken.split(".");
    await assertRejected(`${header}.${payload}.`, "TOKEN_INVALID");
  });

  test("signé avec un autre secret", async () => {
    const token = jwt.sign(claims(), "un-autre-secret-de-plus-de-32-caracteres!!", signOpts());
    await assertRejected(token, "TOKEN_INVALID");
  });

  test('algorithme "none" (jeton non signé)', async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({ ...claims(), role: "admin", sub: String(user.id), iat: Math.floor(Date.now() / 1000) }),
    ).toString("base64url");
    await assertRejected(`${header}.${payload}.`, "TOKEN_INVALID");
  });

  test("algorithme non autorisé (HS512 avec le bon secret)", async () => {
    await assertRejected(jwt.sign(claims(), SECRET, { ...signOpts(), algorithm: "HS512" }), "TOKEN_INVALID");
  });

  test("mauvais émetteur / audience", async () => {
    await assertRejected(jwt.sign(claims(), SECRET, { ...signOpts(), issuer: "autre-app" }), "TOKEN_INVALID");
    await assertRejected(jwt.sign(claims(), SECRET, { ...signOpts(), audience: "autre-api" }), "TOKEN_INVALID");
  });

  test("chaîne quelconque", async () => {
    await assertRejected("pas-un-jwt", "TOKEN_INVALID");
  });
});

describe("critère TP1 (non-régression) : aucune trace de mot de passe en clair", () => {
  test("une requête JSON malformée contenant le mot de passe n'est ni journalisée ni renvoyée", async () => {
    const { res, text } = await request("/api/login", {
      method: "POST",
      rawBody: `{"username":"alice","password":"${PASSWORD}"`,
    });
    assert.equal(res.status, 400);
    assert.ok(!text.includes(PASSWORD));
  });

  test("en base : uniquement un hash bcrypt (coût 12)", () => {
    const db = new DatabaseSync(DB_PATH, { readOnly: true });
    const row = db.prepare("SELECT * FROM users WHERE username = 'alice'").get();
    db.close();
    assert.match(row.password_hash, /^\$2b\$12\$.{53}$/);
    assert.ok(!Object.values(row).some((v) => String(v).includes(PASSWORD)));
  });

  test("dans les fichiers de la base (octets bruts, y compris WAL/journal)", () => {
    for (const file of fs.readdirSync(tmpDir)) {
      const bytes = fs.readFileSync(path.join(tmpDir, file));
      assert.ok(!bytes.includes(PASSWORD), `mot de passe trouvé dans ${file}`);
    }
  });

  test("dans le payload du JWT (lisible par quiconque intercepte le jeton)", () => {
    const payload = JSON.stringify(jwt.decode(validToken));
    assert.ok(!payload.includes(PASSWORD));
    assert.ok(!payload.includes("$2b$"), "le hash ne doit pas non plus être dans le jeton");
    assert.deepEqual(Object.keys(jwt.decode(validToken)).sort(), ["aud", "exp", "iat", "iss", "role", "sub", "username"]);
  });

  test("dans les logs du serveur", () => {
    assert.ok(logs.length > 0, "le logger doit avoir écrit des lignes");
    assert.ok(!logs.some((line) => line.includes(PASSWORD)));
  });

  test("dans les réponses HTTP", () => {
    assert.ok(!responseBodies.some((body) => body.includes(PASSWORD) || body.includes("$2b$")));
  });
});
