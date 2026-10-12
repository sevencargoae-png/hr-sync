FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js plans.js ./
COPY lib/ ./lib/
COPY routes/ ./routes/
ENV PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
