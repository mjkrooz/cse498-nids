# CSE 498 Network Intrusion Detection System (NIDS) Testing

This Docker setup has two containers: 

1. A vulnerable Apache 2.4.49 server, along with the prototype NIDS.
2. An attacker using MSFConsole to run an exploit against the vulnerable Apache server.

## Setup

Use the following to build and start the containers:

```
docker-compose up
```

# Usage

## Apache

Once the Apache 2.4.49 container is running, use the following to enter a shell:

```
docker exec -it apache bash
```

And then run the following to start the NIDS prototype:

```
./test1 0
```

The output from this executable will be printed in the terminal, stating which received packets match the rules described in `apache/src/emerging-exploit.rules`.

The `test` executable is built from Go files in the `apache/src` directory in the repository. The argument to the executable is a numerical ID for the interface to listen on. Running `./test` will provide a list of devices, along with the numerical ID to reference the device.

## Attacker

After starting the NIDS on Apache, run the following command to enter a shell for the attacker:

```
docker exec -it attacker bash
```

Run the following command to send a simple HTTP request to the Apache server:

```
curl 192.168.123.10
```

The output should appear as follows:

```html
<html><body><h1>It works!</h1></body></html>
```

Note also the output from the NIDS, which does not consider this request to be malicious.

Next, use the following command to automatically run the exploit using MSFConsole:

```
./shared/exploit.sh
```

Review the output of MSFConsole, which states that the Apache server is vulnerable. A reverse shell will then be presented, showing the attack to be a success.

Review the output from the NIDS, which determined the request to be malicious. In particular, the request attempts to traverse the filesystem using `../`, albeit as url-encoded.