# Anthem
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Windows
* Crawling
* Hidden Files

Tools used
--
* nmap
* Zaproxy
* rdesktop

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.244.36
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.244.36 -p- -Pn -T5 -vvv

<SNIP>
Discovered open port 80/tcp on 10.10.244.36
Discovered open port 3389/tcp on 10.10.244.36
<SNIP>
80/tcp   open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Anthem.com - Welcome to our blog
| http-robots.txt: 4 disallowed entries 
|_/bin/ /config/ /umbraco/ /umbraco_client/
<SNIP>
```
So we can access to the resources inside `robots.txt`:
```
UmbracoIsTheBest!

# Use for all search robots
User-agent: *

# Define the directories not to crawl
Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/
```
It contains also a password: `UmbracoIsTheBest!`.

The challenge asks us for the name of the Administrator. Inside the page `http://10.10.244.36/archive/a-cheers-to-our-it-department/` there is a poem dedicated to the admin. If we google it, we find the name `Solomon Grundy`.

By checking the articles in the website, we see an article of Jane Doe, and her email as JD@anthem.com. It means that the email of the administrator is SG@anthem.com.

Now the challenge asks us for finding for flags deployed across the website. We can use a web crawler as Zaproxy and at the end of the result search for `THM` string:
* The first one is on view-source:http://10.10.244.36/archive/we-are-hiring/
* The second one is on view-source:http://10.10.244.36/authors/
* The third one is on http://10.10.244.36/authors/
* The fourth one is on view-source:http://10.10.244.36/archive/a-cheers-to-our-it-department/

Since on the web login page we get always a SessionTimeout message, let's try to login directly by RDP to the server by using `SG` as username:
```
remmina -c rdp://sg@10.10.244.36
```
In general, in case you need to login by RDP and need to use a shared folder with your host, use:
```
rdesktop -r sound:local -r disk:SharedFolderName=/usr/share/windows/mimikatz -P 10.10.244.36
```
Inside the machine, in the Desktop we can easily retrive the user flag inside `user.txt`.

For privilege escalation, just enable "hidden files" view and in `C:\` you will see an hidden `backup` folder. Inside it there is a `restore.txt` file inaccessible by the user. Checking the permissions on this file, we see no groups are assigned to it, but by clicking on "Advanced" button, we note that `SG` user is the owner. In this manner, we can assign "Full Control" permission on `SG` user. It contains the password of Administrator user.

Now, we can go to `C:\Users\Administrator\Desktop` and read the `root.txt` content.