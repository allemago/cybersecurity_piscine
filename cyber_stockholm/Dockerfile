FROM debian:13-slim

RUN apt-get update && apt-get install -y \
	g++ \
	make \
	libsodium-dev && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /home

COPY infection/ infection/

WORKDIR /app

COPY Makefile .
COPY src/ src/
COPY include/ include/

RUN make

CMD ["/bin/bash"]
