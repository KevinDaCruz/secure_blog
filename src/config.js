const secret = process.env.JWT_SECRET;

// On refuse de démarrer avec un secret absent ou trop faible :
// un secret devinable permet de forger n'importe quel jeton.
if (!secret || secret.length < 32) {
  throw new Error("JWT_SECRET manquant ou trop court (32 caractères minimum)");
}

export const config = {
  port: Number(process.env.PORT) || 3000,
  jwt: {
    secret,
    expiresIn: process.env.JWT_EXPIRES_IN || "15m",
    algorithm: "HS256",
    issuer: "secure-blog",
    audience: "secure-blog-api",
  },
  cookie: {
    name: "access_token",
  },
};
