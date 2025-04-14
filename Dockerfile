# Sử dụng base image có hỗ trợ Puppeteer
FROM ghcr.io/puppeteer/puppeteer:latest

# Tạo thư mục app
WORKDIR /app

# Copy source code
COPY . .

# Cài đặt dependencies
RUN npm install

# Chạy server
CMD ["node", "server.js"]