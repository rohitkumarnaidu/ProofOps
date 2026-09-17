# ProofOps UI image (M19b): node build stage + nginx serve stage.
# M19 keeps the M00.1 promises (pinned tags only, self-HEALTHCHECK) and fulfills
# the Dockerfile's own note: unprivileged 8080 + nginx USER (no root).
FROM node:24-alpine AS build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY index.html vite.config.ts tsconfig*.json ./
COPY src ./src
RUN npm run build

FROM nginx:1.27-alpine
COPY frontend.nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O /dev/null http://localhost:8080/ || exit 1
