FROM debian:bookworm-slim

RUN apt update && apt install -y tor && \
	apt clean && rm -rf /var/lib/apt/lists/* && \
	mkdir -p /var/lib/tor/hidden_service

COPY torrc /etc/tor/torrc

RUN chown -R debian-tor:debian-tor /var/lib/tor && \
	chmod 700 /var/lib/tor && \
	chmod 700 /var/lib/tor/hidden_service

USER debian-tor

CMD ["tor", "-f", "/etc/tor/torrc"]
