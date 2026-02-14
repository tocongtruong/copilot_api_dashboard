FROM node:22-alpine
WORKDIR /app

RUN apk add --no-cache wget

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public/ ./public/

RUN mkdir -p /data

ENV NODE_ENV=production
ENV DB_PATH=/data/dashboard.db

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --spider -q http://localhost:3000/ || exit 1

CMD ["node", "server.js"]
