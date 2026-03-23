FROM debian:bookworm-slim

RUN apt update && apt install -y nginx && \
	apt clean && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /var/www/html/index.html
COPY tor_meme.webp /var/www/html/tor_meme.webp

CMD ["nginx", "-g", "daemon off;"]
