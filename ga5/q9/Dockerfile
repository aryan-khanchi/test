FROM node:20-bookworm-slim

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

COPY src ./src

RUN mkdir -p /data
ENV DATA_DIR=/data
ENV PORT=8080

EXPOSE 8080
CMD ["node", "src/server.js"]
