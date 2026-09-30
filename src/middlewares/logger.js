// Journal des requêtes : méthode, URL, statut et durée uniquement.
// Le corps des requêtes n'est jamais journalisé (il contient les mots de passe).
export function requestLogger(req, res, next) {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${ms.toFixed(1)}ms`);
  });
  next();
}
