FROM debian:bookworm-slim

RUN apt update && apt install -y nginx && \
	apt clean && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /var/www/html/index.html
COPY hidden_service_0.png /var/www/html/hidden_service_0.png
COPY hidden_service_1.png /var/www/html/hidden_service_1.png
COPY hidden_service_2.png /var/www/html/hidden_service_2.png

CMD ["nginx", "-g", "daemon off;"]
 