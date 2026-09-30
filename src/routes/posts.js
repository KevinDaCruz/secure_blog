import { Router } from "express";
import { store } from "../data/store.js";
import { requireAuth } from "../middlewares/auth.js";

const router = Router();

// Lecture publique
router.get("/", (req, res) => {
  res.json({ posts: store.listPosts() });
});

// Écriture protégée
router.post("/", requireAuth, (req, res) => {
  const { title, content } = req.body ?? {};
  if (typeof title !== "string" || !title.trim() || typeof content !== "string" || !content.trim()) {
    return res.status(400).json({ error: "Titre et contenu requis" });
  }
  const post = store.createPost({
    title: title.trim().slice(0, 200),
    content: content.trim().slice(0, 10_000),
    authorId: req.user.id,
  });
  res.status(201).json({ post });
});

router.delete("/:id", requireAuth, (req, res) => {
  const post = store.findPost(Number(req.params.id));
  if (!post) return res.status(404).json({ error: "Article introuvable" });

  if (post.author.id !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: "Vous ne pouvez supprimer que vos articles" });
  }
  store.deletePost(post.id);
  res.status(204).end();
});

export default router;
