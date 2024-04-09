docker exec --privileged siem bash -c "service syslog-ng start && syslog-ng -e -f /root/shared/syslog-ng_server"

# logger -T -n 127.0.0.1 -P 514 from siem