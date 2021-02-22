#!/bin/bash
masscan --rate=3000 -e tun0 -p1-65535 $1 > $2
mkdir Scan-results
mkdir Scan-results/$2
cat $2 | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr "\n" ',' | sed 's/,$//' > Scan-results/$2/$2-ports
rm $2
ports=`cat Scan-results/$2/$2-ports`
nmap -T4 -Pn -sV -sC -oA Scan-results/$2/$2-version $1 -p$ports
rm Scan-results/$2/$2-version.xml
rm Scan-results/$2/$2-version.gnmap
