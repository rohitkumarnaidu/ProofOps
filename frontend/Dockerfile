# ProofOps UI image (M19b): node build stage + nginx serve stage.
# M19 keeps the M00.1 promises (pinned tags only, self-HEALTHCHECK) and fulfills
# the Dockerfile's own note: unprivileged 8080 + nginx USER (no root).
FROM node:24-alpine AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.ts tsconfig*.json ./
COPY src ./src
# Same-origin by default: the bundle uses the /api prefix and nginx proxies it
# to the api service. VITE_API_URL stays overridable for a deliberately
# split-origin deployment, but leaving it unset is the correct default -- an
# absolute cross-origin URL cannot work here, because the backend ships no CORS
# middleware and no OPTIONS preflight handler.
# ARG defaults to /api, not "". An empty ARG is a real, reachable state that Vite
# inlines verbatim, and the resulting same-origin-no-prefix bundle fetches the SPA
# fallback for every API path (HTTP 200 + HTML -> {} -> blank white screen).
# Defaulting the ARG to /api means the correct value is what you get by doing
# nothing; an explicit override still wins for a deliberately split-origin deploy.
ARG VITE_API_URL="/api"
ARG VITE_PROOFOPS_API_KEY=""
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_PROOFOPS_API_KEY=$VITE_PROOFOPS_API_KEY
RUN npm run build

# Unprivileged variant (not stock nginx:1.27-alpine): with `USER nginx`
# below, the stock image crash-loops — /var/cache/nginx is root-owned
# (mkdir client_temp: permission denied, proven by daemon boot log at
# c3cb09e). The unprivileged image pre-chowns cache/run/conf dirs for
# UID 101 and listens on 8080 by default, matching our conf + HEALTHCHECK.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY frontend.nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O /dev/null http://localhost:8080/ || exit 1
