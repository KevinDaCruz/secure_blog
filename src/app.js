import path from "node:path";
import express from "express";
import cookieParser from "cookie-parser";
import { requestLogger } from "./middlewares/logger.js";
import authRoutes from "./routes/auth.js";
import postRoutes from "./routes/posts.js";

const app = express();

app.disable("x-powered-by");
app.use(requestLogger);
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());
app.use(express.static(path.join(import.meta.dirname, "../public")));

app.use("/api", authRoutes);
app.use("/api/posts", postRoutes);

app.use((req, res) => res.status(404).json({ error: "Route introuvable" }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // Une erreur de parsing JSON contient le corps brut de la requête (donc potentiellement
  // le mot de passe) : on ne la journalise pas et on ne la renvoie pas au client.
  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "JSON invalide" });
  }
  console.error(err.stack);
  res.status(500).json({ error: "Erreur interne" });
});

export default app;
