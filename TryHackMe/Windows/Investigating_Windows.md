# Investigating Windows
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

This is a challenge that is exactly what is says on the tin, there are a few challenges around investigating a windows machine that has been previously compromised.

Connect to the machine using RDP. The credentials the machine are as follows:

Username: Administrator
Password: letmein123!

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

Tags
--
* Windows
* Mimikatz
* Event Viewer
* Firewall with Advanced Security
* Forensics

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

## Questions

### Whats the version and year of the windows machine?
By CMD run:
```
winver

Windows Server 2016
```

### Which user logged in last?
Check all the users we get by:
```
net user

Administrator Jenny John DefaultAccount Guest
```
And then check all of them by:
```
net user administrator | findstr /B /C:"Last logon"

Last logon 9/16/2022 7:41:39 PM
```
Then:
```
net user Jenny | findstr /B /C:"Last logon"

Last logon Never
```
And:
```
net user John | findstr /B /C:"Last logon"

Last logon 3/2/2019 5:48:32 PM
```
So the last logged user is Administrator.

### When did John log onto the system last?

As we see above, `Last logon 3/2/2019 5:48:32 PM`.

### What IP does the system connect to when it first starts?

When we start the machine at the beginning, a terminal opens for connecting to `10.34.2.3`.

### What two accounts had administrative privileges (other than the Administrator user)?

By CMD, run:
```
net localgroup administrators

Administrator
Guest
Jenny
```

### Whats the name of the scheduled task that is malicous.

In this case we can open the Task Scheduler and see on the root hive several scheduled tasks. Analyze them one by one by checking the "Actions" tab for looking at the running process.

In our case the malicious one is `Clean file system` because it runs `C:\TMP\nc.ps1 -l 1348`.

### What file was the task trying to run daily?

By reading the answer above, it is `nc.ps1`.

### What port did this file listen locally for?

By reading the answer above, it is `1348`.

### When did Jenny last logon?

By looking the second question above, her last logon is `Never`.

### At what date did the compromise take place?

By looking inside the server, in `C:\inetpub\wwwroot` we can see suspicious `shell.gif` file that has `March 02 2019` as "Date modified" value.

### At what time did Windows first assign special privileges to a new logon?

By CMD, run:
```
wevtutil qe security /f:text /c:1 "/q:*[System[(EventID=4672)]]"

<SNIP>
03/02/2019 08:14:30 AM
<SNIP>
```
Note that `/c:1` shows only the first (oldest) output. Without it we get a lot of output objects. Note also that the question could be wrongly because the first event does not work. The correct answer is `03/02/2019 04:04:49 PM`.

### What tool was used to get Windows passwords?

As you can see inside `C:\TMP`, mimikatz is used.

### What was the attackers external control and command servers IP?

Let's give a look inside `C:\Windows\System32\drivers\etc\hosts`:
```
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
76.32.97.132 google.com
76.32.97.132 www.google.com
```
The last IP address is suspicious, indeed `76.32.97.132` is the IP address of the command & control server.

### What was the extension name of the shell uploaded via the servers website?

In `C:\inetpub\wwwroot\` we have `shell.gif`, `b.jsp` and `tests.jsp` files. The dangerous file to behave like shell seems to be `b.jsp`.

### What was the last port the attacker opened?

For checking the opened ports, we need to open "Windows Firewall with Advanced Security" and check for "Inbound Rules" because they are the kind of rules could be interesting for an attacker. There, we can see a rule called "Allow outside connections for development" that is suspicious. The opened local port is `1337`.

### Check for DNS poisoning, what site was targeted?

Looking for `C:\Windows\System32\drivers\etc\hosts`, we can see that the malicious command & control server IP is associated to `google.com`.