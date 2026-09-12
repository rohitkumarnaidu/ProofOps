# Placeholder until Step 28 React scaffold lands; serves static stub via nginx.
# SECURITY NOTE (M00.1): stays root because nginx must bind privileged :80.
# M19 moves to an unprivileged listen port + USER. No host mounts, no caps added.
FROM nginx:1.27-alpine
COPY public /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O /dev/null http://localhost/ || exit 1
