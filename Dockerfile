FROM node:24.22.2-alpine AS runtime
WORKDIR /app

FROM runtime AS dev
RUN echo '//signageos-524256255273.d.codeartifact.eu-central-1.amazonaws.com/npm/private/:_authToken="${NPM_AUTH_TOKEN}"' > /root/.npmrc
RUN npm install -g pnpm@12
