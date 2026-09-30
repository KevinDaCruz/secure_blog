import { Router } from "express";
import bcrypt from "bcrypt";
import { store, DuplicateUserError } from "../data/store.js";
import { requireAuth } from "../middlewares/auth.js";
import { signAccessToken } from "../utils/jwt.js";
import { setAuthCookie, clearAuthCookie } from "../utils/cookie.js";

const router = Router();
const SALT_ROUNDS = 12;
// Hash factice : on fait tourner bcrypt même si l'utilisateur n'existe pas,
// pour ne pas révéler par le temps de réponse quels identifiants existent.
const DUMMY_HASH = bcrypt.hashSync("dummy-password", SALT_ROUNDS);

// Seuls ces champs sortent de la couche données : jamais le hash.
const publicUser = ({ id, username, role }) => ({ id, username, role });

function validateCredentials(body) {
  const { username, password } = body ?? {};
  if (typeof username !== "string" || typeof password !== "string") return null;
  const trimmed = username.trim();
  // 72 octets = limite de bcrypt, au-delà le reste du mot de passe serait ignoré.
  if (!/^[a-zA-Z0-9_-]{3,30}$/.test(trimmed) || password.length < 8 || Buffer.byteLength(password) > 72) {
    return null;
  }
  return { username: trimmed, password };
}

router.post("/register", async (req, res) => {
  const creds = validateCredentials(req.body);
  if (!creds) {
    return res.status(400).json({
      error: "Identifiant (3-30 caractères alphanumériques) et mot de passe (8-72 caractères) requis",
    });
  }

  const passwordHash = await bcrypt.hash(creds.password, SALT_ROUNDS);
  try {
    const user = store.createUser({ username: creds.username, passwordHash });
    res.status(201).json({ user: publicUser(user) });
  } catch (err) {
    if (err instanceof DuplicateUserError) {
      return res.status(409).json({ error: "Identifiant déjà utilisé" });
    }
    throw err;
  }
});

router.post("/login", async (req, res) => {
  const creds = validateCredentials(req.body);
  const user = creds && store.findUserByUsername(creds.username);
  const valid = await bcrypt.compare(creds?.password ?? "", user?.passwordHash ?? DUMMY_HASH);

  if (!user || !valid) {
    return res.status(401).json({ error: "Identifiants invalides" });
  }

  setAuthCookie(res, signAccessToken(user));
  // Le jeton n'est PAS renvoyé dans le corps : le JS du front n'a jamais à le manipuler.
  res.json({ user: publicUser(user) });
});

router.post("/logout", (req, res) => {
  clearAuthCookie(res);
  res.status(204).end();
});

router.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

export default router;
