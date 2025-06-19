FROM node:18-alpine AS runtime
WORKDIR /app

FROM runtime AS dev
