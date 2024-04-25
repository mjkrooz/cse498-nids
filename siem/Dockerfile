FROM php:8.2-apache
COPY ./shared /root/shared
COPY ./src /var/www/html/
RUN chmod -R +r ./

# Install syslog-ng

RUN apt-get update
RUN apt-get install -y systemd syslog-ng tcpdump

# Create the log file for the SIEM to watch

RUN touch /var/log/fromapache
RUN chmod +r /var/log/fromapache

# Expose ports 514 and 8080

EXPOSE 514
EXPOSE 8080

# Start syslog-ng and listen in the background using the client config

#CMD service syslog-ng start
#CMD syslog-ng -vde -f /root/shared/syslog-ng_client

#ENTRYPOINT /bin/bash