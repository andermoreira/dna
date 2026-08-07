FROM node:20-alpine

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

RUN mkdir -p /app/data /app/public && chown -R node:node /app

USER node

EXPOSE 3000

CMD ["node", "src/index.js"]
