FROM node:22-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine AS runtime

ENV NODE_ENV=production
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# The base image bundles npm's own CLI and its node_modules globally.
# It is not needed at runtime (the container only runs `node dist/server.js`)
# and its transitive deps periodically pick up HIGH/CRITICAL CVEs, so drop it
# from the shipped image instead of carrying that vulnerable surface area.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

COPY --from=build /app/dist ./dist

USER node
EXPOSE 3000

CMD ["node", "dist/server.js"]
