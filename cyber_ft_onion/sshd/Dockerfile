FROM debian:bookworm-slim

RUN apt update && apt install -y openssh-server && \
	apt clean && rm -rf /var/lib/apt/lists/* && \
	mkdir -p /run/sshd && \
	ssh-keygen -A

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D"]
