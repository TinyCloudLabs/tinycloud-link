FROM --platform=linux/amd64 node:22-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM --platform=linux/amd64 node:22-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=build /app/dist ./dist
COPY migrations ./migrations

CMD ["node", "dist/index.js"]
