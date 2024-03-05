FROM ubuntu:22.04

ENV HOME /root
WORKDIR /root

COPY ./src ./src
COPY ./shared ./shared


RUN apt update
RUN apt install software-properties-common -y

# Get up-to-date Golang repositories and update packages

RUN add-apt-repository ppa:longsleep/golang-backports
RUN apt update

# Extract Apache 2.4.49

RUN tar -xzf ./shared/apache2.4.49.tar.gz -C /usr/local/

# Install Apache dependencies.

RUN apt install libaprutil1 -y

# Prepare Apache for exploitation

RUN sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" /usr/local/apache2/conf/httpd.conf
RUN sed -i "0,/denied/s/denied/granted/" /usr/local/apache2/conf/httpd.conf
RUN sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" /usr/local/apache2/conf/httpd.conf
RUN sed -i "0,/denied/s/denied/granted/" /usr/local/apache2/conf/httpd.conf
RUN sed -i -E "s|all denied|all granted|g; s|#(.* cgid_.*)|\1|g" /usr/local/apache2/conf/httpd.conf

# Expose the vulnerable version of Apache

EXPOSE 80

# Install Go

RUN apt install golang-go -y

# Init and run NIDS

WORKDIR /root/src

RUN apt install libpcap-dev -y

RUN go mod tidy
RUN go build
#RUN ./test1 0

# Start Apache

#ENTRYPOINT ["/usr/local/apache2/bin/httpd"]
#CMD ["-k", "start"]
#CMD ["/usr/local/apache2/bin/httpd", "-k", "start"]
ENTRYPOINT /usr/local/apache2/bin/httpd -k start && /bin/bash