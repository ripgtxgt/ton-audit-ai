FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
# Copy sample contracts
COPY --from=builder /app/src/samples ./dist/samples
EXPOSE 3099
CMD ["node", "dist/server.js"]
