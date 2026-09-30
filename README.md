# SecureBlog v2 — Authentification par JWT

API Express d'un blog :
- mots de passe hachés avec **bcrypt** ;
- authentification **stateless** par **JWT**, transmis dans un cookie `HttpOnly` + `Secure` + `SameSite` ;
- application conteneurisée avec **Docker**.

| Version | TP | Authentification |
|---|---|---|
| v1 | TP1 | Session serveur (`express-session`) |
| v2 | TP2 | JWT signé en cookie, API stateless |

## Lancer le projet

### Avec Docker (recommandé)

```bash
cp .env.example .env   # puis renseigner JWT_SECRET (32 caractères minimum)
docker compose up -d --build
```

L'application est disponible sur http://localhost:3000 (le port se change avec `PORT` dans `.env`). La base SQLite est stockée dans le volume `blog-data` : les comptes survivent au redémarrage du conteneur.

### Sans Docker

```bash
npm install
npm start      # Node ≥ 22.13 (module node:sqlite intégré)
npm test       # 28 tests
```

## Routes

Les routes sont identiques à celles de la v1 : le front n'a pas changé d'une ligne.

| Méthode | Route | Accès |
|---|---|---|
| POST | `/api/register` | public : hache le mot de passe avec bcrypt et crée l'utilisateur |
| POST | `/api/login` | public : vérifie avec `bcrypt.compare` et pose le cookie `access_token` |
| POST | `/api/logout` | efface le cookie |
| GET | `/api/me` | **protégée** |
| GET | `/api/posts` | public |
| POST | `/api/posts` | **protégée** |
| DELETE | `/api/posts/:id` | **protégée** (auteur ou admin) |

---

## TP2 — Authentification par JWT

### Génération du jeton ([src/utils/jwt.js](src/utils/jwt.js))

- Signature **HS256** avec `jsonwebtoken`. Le secret vient de l'environnement, et le serveur refuse de démarrer s'il fait moins de 32 caractères.
- **Expiration courte** : 15 minutes (`JWT_EXPIRES_IN`).
- Claims `sub` (id utilisateur), `iss` et `aud`. Le payload ne contient que `username` et `role` : un JWT est encodé, pas chiffré.

### Transport dans un cookie ([src/utils/cookie.js](src/utils/cookie.js))

- `HttpOnly` : le JavaScript de la page ne peut pas lire le jeton, donc une faille XSS ne permet pas de le voler.
- `Secure` : le cookie n'est envoyé qu'en HTTPS. Chrome et Firefox font une exception pour `http://localhost`.
- `SameSite=Strict` : le cookie n'est jamais envoyé depuis un site tiers, ce qui protège du CSRF.
- `Max-Age` est aligné sur la durée de vie du jeton.
- Le jeton n'est **jamais** renvoyé dans le corps de la réponse.

### Middleware de vérification ([src/middlewares/auth.js](src/middlewares/auth.js))

- `jwt.verify` est appelé avec `algorithms: ["HS256"]` **imposé**, ce qui bloque `alg: none` et les substitutions d'algorithme. `iss` et `aud` sont vérifiés.
- Aucune lecture de session ni de base : l'identité vient uniquement du jeton signé. L'API est donc **stateless**.
- Un jeton absent, expiré ou invalide renvoie un **401**, et le cookie fautif est effacé. Le code `TOKEN_EXPIRED` permet au front de distinguer une session expirée.

### Critère de réussite : un JWT expiré ou altéré est systématiquement rejeté

Les tests ([test/auth.test.js](test/auth.test.js)) vérifient que chaque route protégée renvoie un 401 dans tous ces cas :
- jeton expiré, même correctement signé ;
- payload modifié sans re-signer : élévation de rôle, prolongation de `exp`, usurpation d'un autre `sub` ;
- signature altérée ou supprimée ;
- jeton signé avec un autre secret ;
- `alg: none` et algorithme non autorisé (HS512) ;
- mauvais émetteur ou mauvaise audience ;
- chaîne qui n'est pas un JWT.

### Sans régression pour l'utilisateur

- Mêmes routes, mêmes réponses : le front ([public/index.html](public/index.html)) est strictement identique à la v1.
- Le navigateur envoie le cookie tout seul, donc l'utilisateur reste connecté après un rafraîchissement.
- Les comptes créés en v1 fonctionnent en v2 : même base, mêmes hashs bcrypt.
- À expiration du jeton, l'utilisateur est renvoyé proprement vers le formulaire de connexion.
- Tous les tests de la v1 (hors tests propres aux sessions) sont conservés comme tests de non-régression.

---

## TP1 — Aucune trace de mot de passe en clair (toujours valable)

| Où un mot de passe pourrait fuiter | Mesure |
|---|---|
| Base de données | Seul le hash bcrypt (coût 12) est stocké. |
| Réponses HTTP | `publicUser()` ne renvoie que `id`, `username` et `role`. |
| JWT | Ni le mot de passe ni le hash dans le payload (vérifié par un test). |
| Logs | Le logger n'écrit que la méthode, l'URL, le statut et la durée ([src/middlewares/logger.js](src/middlewares/logger.js)). |
| Erreurs | Une erreur de parsing JSON contient le corps brut de la requête : elle n'est ni journalisée ni renvoyée. |
| Image Docker | `.env` est exclu de l'image ; les secrets sont injectés au lancement par `env_file`. |

Les tests utilisent un mot de passe témoin et le cherchent dans la base (y compris les octets bruts du fichier), dans le JWT, dans les logs et dans toutes les réponses HTTP.

**Autres mesures** :
- même message et même temps de réponse, que le compte existe ou non (hash bcrypt factice) ;
- requêtes SQL préparées ;
- mot de passe limité à 72 octets (au-delà, bcrypt ignore la fin) ;
- conteneur exécuté sans les droits root (utilisateur `node`), avec un healthcheck.

## Limites connues

- **Révocation** : un JWT reste valide jusqu'à son expiration, même après un logout. Le logout efface le cookie du navigateur, mais un jeton volé avant resterait utilisable. C'est le prix du stateless, limité par l'expiration de 15 minutes. Pour aller plus loin : un refresh token révocable stocké en base, ou une liste noire de `jti`.
- **Changement de rôle** : un changement de rôle ne prend effet qu'au prochain login, puisque le rôle est dans le jeton.
- **Safari** : il peut refuser un cookie `Secure` sur `http://localhost`. Tester avec Chrome ou Firefox, ou placer l'application derrière HTTPS.
- **Rate limiting** : absent sur `/api/login`, à ajouter en production (`express-rate-limit`).
