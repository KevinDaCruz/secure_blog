import ms from "ms";
import { config } from "../config.js";

const baseOptions = {
  httpOnly: true, // inaccessible depuis JavaScript -> protège du vol par XSS
  secure: true, // envoyé uniquement en HTTPS (localhost est toléré par les navigateurs)
  sameSite: "strict", // jamais envoyé sur une requête cross-site -> protège du CSRF
  path: "/",
};

export function setAuthCookie(res, token) {
  res.cookie(config.cookie.name, token, {
    ...baseOptions,
    // Le cookie disparaît en même temps que le jeton expire.
    maxAge: ms(config.jwt.expiresIn),
  });
}

export function clearAuthCookie(res) {
  res.clearCookie(config.cookie.name, baseOptions);
}
