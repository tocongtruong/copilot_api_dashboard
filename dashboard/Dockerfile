FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache wget

COPY package.json ./
RUN npm install --production

COPY server.js ./
COPY public/ ./public/

RUN mkdir -p /data

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
  CMD wget --spider -q http://localhost:3000/ || exit 1

CMD ["node", "server.js"]
