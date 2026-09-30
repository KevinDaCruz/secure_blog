FROM node:24-alpine

ENV NODE_ENV=production
WORKDIR /app

# Dépendances d'abord : cette couche reste en cache tant que package*.json ne change pas.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY public ./public

# L'application tourne sans les droits root ; seul /app/data est accessible en écriture.
RUN mkdir -p /app/data && chown node:node /app/data
USER node

ENV PORT=3000 DB_PATH=/app/data/secure-blog.db
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:3000/api/posts > /dev/null || exit 1

CMD ["node", "src/server.js"]
