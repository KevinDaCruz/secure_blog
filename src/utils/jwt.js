import jwt from "jsonwebtoken";
import { config } from "../config.js";

const { secret, expiresIn, algorithm, issuer, audience } = config.jwt;

// Le payload est seulement encodé (base64url), pas chiffré : aucune donnée sensible dedans.
export function signAccessToken(user) {
  return jwt.sign(
    { username: user.username, role: user.role },
    secret,
    { algorithm, expiresIn, issuer, audience, subject: String(user.id) },
  );
}

// Lève TokenExpiredError / JsonWebTokenError si le jeton est expiré ou altéré.
// `algorithms` est fixé explicitement pour bloquer "alg: none" et toute
// substitution d'algorithme.
export function verifyAccessToken(token) {
  return jwt.verify(token, secret, { algorithms: [algorithm], issuer, audience });
}
