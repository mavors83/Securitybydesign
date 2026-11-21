# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npm_token,env=NPM_TOKEN npm ci --ignore-scripts
COPY . .
RUN npm run build
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
WORKDIR /app
COPY --from=build --chown=65532:65532 /app/dist ./dist
ENV DB_PASSWORD_FILE=/run/secrets/db_password
USER 65532:65532
CMD ["dist/server.js"]
