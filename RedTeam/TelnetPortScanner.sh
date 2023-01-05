#!/bin/bash
#Ip of the server to scan || you can potentially also use the URL
server=192.168.1.20
#Define the ports that will be scanned example scans the Non-ephemeral ports only (0-1023)
for port in {1..1023}
do 
	telnet $server $port > /dev/null 2>&1 <<EOF
EOF
	if [ $? -eq 0 ]; then
		echo "Port $port is open"
	fi
done
	