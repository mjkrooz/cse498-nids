# CSE 498 Host-Based Intrusion Detection System (NIDS) Testing

This Docker setup has three containers: 

1. A vulnerable Apache 2.4.49 server, along with the prototype HIDS.
2. A SIEM that receives Apache logs and HIDS alerts from the vulnerable Apache server.
3. An attacker using MSFConsole to run an exploit against the vulnerable Apache server.

# Quick Start

1. Build and start the containers:
    ```shell
   sudo docker-compose up -d 
   ```
2. Start syslog-ng from the host:
    ```shell
   sudo ./start_syslog.sh
   ```
3. In one terminal, start the HIDS:
   ```shell
    sudo docker-compose exec apache bash -c "./test1 0"
    ```
4. In another terminal, enter the attacker container and execute the exploit:
   ```shell
    sudo docker-compose exec -it attacker bash
    > ./shared/exploit.sh
    ```
5. Access/refresh the SIEM webpage at `http://127.0.0.1:8081`

# Usage

## Setup

Use the following to build and start the containers:

```
sudo docker-compose up -d
```

## Apache

Once the Apache 2.4.49 container is running, use the following to enter a shell:

```
sudo docker exec -it apache bash
```

And then run the following to start the HIDS prototype using the first network device:

```
./test1 0
```

The output from this executable will be printed in the terminal, stating which received packets match the rules described in `apache/src/emerging-exploit.rules`.

The `test` executable is built from Go files in the `apache/src` directory in the repository. The argument to the executable is a numerical ID for the interface to listen on. Running `./test` will provide a list of devices, along with the numerical ID to reference the device.

### Web Interface

The website for the vulnerable Apache version can be visited at:

```
http://192.168.123.10
```

A simple "It Works!" should be displayed.

## syslog-ng Startup

Before the HIDS and SIEM can communicate correctly, syslog-ng needs to be started. There is a bash script to do so that can be run from the host.

```shell
sudo ./start_syslog.sh
```

## SIEM

The SIEM interface will already be prepared. The web interface can be accessed at:

```
http://127.0.0.1:8080
```
The interface will show a list of alerts from the HIDS, a pie chart, and a list of all logs.

## Attacker

After starting the HIDS on Apache, run the following command to enter a shell for the attacker:

```
sudo docker exec -it attacker bash
```

Run the following command to send a simple HTTP request to the Apache server:

```
curl 192.168.123.10
```

The output should appear as follows:

```html
<html><body><h1>It works!</h1></body></html>
```

Note also the output from the HIDS, which does not consider this request to be malicious.

Next, use the following command to automatically run the exploit using MSFConsole:

```
./shared/exploit.sh
```

Review the output of MSFConsole, which states that the Apache server is vulnerable. A reverse shell will then be presented, showing the attack to be a success.

Review the output from the HIDS, which determined the request to be malicious. In particular, the request attempts to traverse the filesystem using `../`, albeit as url-encoded.

Lastly, refresh the SIEM page, which will now display the alert in its own list and the pie chart will be updated to reflect the new alert.