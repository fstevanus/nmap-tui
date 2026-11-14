# nmap-web container image
# Runs as root so nmap can use raw sockets (SYN scan, OS detection, etc.).
# Alpine base keeps the image small; nmap-scripts/nselibs provide NSE scripts.
FROM node:22-alpine

# nmap + NSE scripts + ncat/nping. --no-cache keeps apk lists out of the image.
RUN apk add --no-cache nmap nmap-scripts nmap-nselibs nmap-ncat nmap-nping ca-certificates

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY server.js ./
COPY lib ./lib
COPY public ./public

ENV NODE_ENV=production \
    NMAP_UI_HOST=127.0.0.1 \
    NMAP_UI_PORT=8787 \
    NMAP_UI_DATA_DIR=/data \
    NMAP_UI_CONCURRENCY=2 \
    NMAP_UI_HISTORY=200

VOLUME /data
EXPOSE 8787

# Health check via the API (node is available; no curl in alpine by default).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.NMAP_UI_PORT||8787)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "server.js"]
