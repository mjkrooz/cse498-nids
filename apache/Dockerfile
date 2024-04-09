FROM ubuntu:22.04

ENV HOME /root
WORKDIR /root

COPY ./src ./src
COPY ./shared ./shared


RUN apt-get update
RUN apt-get install software-properties-common -y
RUN apt-get install -y iputils-ping

# Get up-to-date Golang repositories and update packages

RUN add-apt-repository -y ppa:longsleep/golang-backports
RUN apt-get update

# Extract Apache 2.4.49

RUN tar -xzf ./shared/apache2.4.49.tar.gz -C /usr/local/

# Install Apache dependencies.

RUN apt-get install libaprutil1 -y

# Prepare Apache for exploitation

RUN sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" /usr/local/apache2/conf/httpd.conf
RUN sed -i "0,/denied/s/denied/granted/" /usr/local/apache2/conf/httpd.conf
RUN sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" /usr/local/apache2/conf/httpd.conf
RUN sed -i "0,/denied/s/denied/granted/" /usr/local/apache2/conf/httpd.conf
RUN sed -i -E "s|all denied|all granted|g; s|#(.* cgid_.*)|\1|g" /usr/local/apache2/conf/httpd.conf

# Expose the vulnerable version of Apache

EXPOSE 8081

# Install syslog-ng

RUN apt-get install -y syslog-ng

# Install Go

RUN apt-get install golang-go -y

# Init and run NIDS

WORKDIR /root/src

RUN apt-get install libpcap-dev -y

RUN go mod tidy
RUN go build
#RUN ./test1 0

# Start syslog-ng and listen in the background using the client config

#CMD service syslog-ng start
#CMD syslog-ng -vde -f ../shared/syslog-ng_client

# Start Apache

#ENTRYPOINT ["/usr/local/apache2/bin/httpd"]
#CMD ["-k", "start"]
#CMD ["/usr/local/apache2/bin/httpd", "-k", "start"]
ENTRYPOINT /usr/local/apache2/bin/httpd -k start && /bin/bash