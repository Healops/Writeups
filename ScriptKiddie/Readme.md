ScriptKiddie
============
Enumeration
------
For port scanning I'll use following script
````
#!/bin/bash
masscan --rate=3000 -e tun0 -p1-65535 $1 > $2
mkdir Scan-results/$2
cat $2 | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr "\n" ',' | sed 's/,$//' > Scan-results/$2/$2-ports
rm $2
ports=`cat Scan-results/$2/$2-ports`
nmap -T4 -Pn -sV -sC -oA Scan-results/$2/$2-version $1 -p$ports
rm Scan-results/$2/$2-version.xml
rm Scan-results/$2/$2-version.gnmap
````
````
./Scan-script.sh 10.10.10.226 ScriptKiddie
````
There are some open ports
```
# Nmap 7.91 scan initiated Sat Feb  6 23:42:44 2021 as: nmap -T4 -Pn -sV -sC -oA Scan-results/ScriptKiddie/ScriptKiddie-version -p22,5000 10.129.72.252
Nmap scan report for 10.129.72.252
Host is up (0.19s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb  6 23:43:03 2021 -- 1 IP address (1 host up) scanned in 18.61 seconds
```
SSH works at standart port 22 and http service at uncommon port 5000

After editing /etc/host let's see a web page on skriptkiddie.htb:5000
```
10.10.10.226    scriptkiddie.htb
```

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/Web%20page.PNG)

Foothold
---
There are three options available
Nmap, msfvenom and searchsploit are executed on the server and we can see the result
![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/nmap.PNG)

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/msfvenom.PNG)

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/searchsploit.PNG)
