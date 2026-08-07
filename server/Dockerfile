FROM node:20-alpine

RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./
RUN npm install

RUN mkdir -p /app/data /app/public

EXPOSE 3000

CMD ["node", "src/index.js"]
