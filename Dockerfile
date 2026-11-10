FROM node:24.22.1-alpine AS runtime
WORKDIR /app

FROM runtime AS dev
