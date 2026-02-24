FROM debian:bookworm-slim

RUN apt update && apt install -y \
	tor \
	torsocks \
	openssh-client \
	curl && \
	apt clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
