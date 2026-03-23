FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y lftp && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY entrypoint.sh .
COPY topsecret.txt .

RUN chmod +x entrypoint.sh

CMD [ "./entrypoint.sh" ]
