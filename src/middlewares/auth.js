import jwt from "jsonwebtoken";
import { config } from "../config.js";
import { verifyAccessToken } from "../utils/jwt.js";
import { clearAuthCookie } from "../utils/cookie.js";

// Aucune lecture en base ni en session : l'identité est entièrement portée par le jeton signé.
export function requireAuth(req, res, next) {
  const token = req.cookies?.[config.cookie.name];

  if (!token) {
    return res.status(401).json({ error: "Authentification requise", code: "NO_TOKEN" });
  }

  try {
    const payload = verifyAccessToken(token);
    req.user = { id: Number(payload.sub), username: payload.username, role: payload.role };
    return next();
  } catch (err) {
    // Jeton inutilisable : on le retire du navigateur pour ne pas le renvoyer en boucle.
    clearAuthCookie(res);

    if (err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: "Session expirée, veuillez vous reconnecter", code: "TOKEN_EXPIRED" });
    }
    return res.status(401).json({ error: "Jeton invalide", code: "TOKEN_INVALID" });
  }
}
