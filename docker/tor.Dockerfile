# Use Alpine Linux as the base image
FROM alpine:3.22

# Update the package index / Install Tor, curl and openrc without caching package index
RUN apk update && apk add --no-cache tor curl openrc \
    && rc-update add tor

# Expose Tor's default SOCKS port
EXPOSE 9050

# Copy the Tor configuration file
COPY config/torrc /etc/tor/torrc

# Change to the Tor user
USER tor

# Start Tor with specified config and run in foreground
CMD ["tor", "-f", "/etc/tor/torrc", "--RunAsDaemon", "0"]