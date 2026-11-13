# nmap-web container image
# Runs as root so nmap can use raw sockets (SYN scan, OS detection, etc.).
# Networking is chosen at runtime: --network host on Linux (full nmap
# experience), or port mapping + NET_RAW/NET_ADMIN caps on macOS/Windows/
# rootless (see README).
FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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

# Health check via the API (no curl in this image, use node's fetch).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.NMAP_UI_PORT||8787)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "server.js"]
