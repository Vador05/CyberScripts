#!/bin/bash

if [ "$1" == "" ] # If there is no argument
  then
    echo "Please review your input"
    echo "Syntax: ./PingScan.sh 192.168.0.1 24"
    echo "first argument is the IP and the second the network mask in CIDR notation"
    echo "If no mask is found a 24 bit mask will be used for the scan"
    
  else
    MASK=24

    if [ "$2" != "" ]; then
      MASK = "$2"
    fi
    IP=$1
    IFS=. read -r i1 i2 i3 i4 <<< $IP
    IFS=. read -r xx m1 m2 m3 m4 <<< $(for a in $(seq 1 32); do if [ $(((a - 1) % 8)) -eq 0 ]; then echo -n .; fi; if [ $a -le $MASK ]; then echo -n 1; else echo -n 0; fi; done)
    NETADDR = `printf "%d.%d.%d.%d\n" "$((i1 & (2#$m1)))" "$((i2 & (2#$m2)))" "$((i3 & (2#$m3)))" "$((i4 & (2#$m4)))"`

    for ip in `seq 1 254`; do
      ping -c1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 &
    done
  fi
