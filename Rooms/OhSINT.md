# OhSINT
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Tags
--
* OSINT

Tools used
--
* exiftool
* https://wigle.net

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* The target is the owner of an image

Phase 1: OSINT
--
The purpose of this challenge is to get  all the possible information just by a single image.

The image is the Windows XP background. Let's take metadata information:
```
exiftool WindowsXP.jpg

ExifTool Version Number         : 12.42
File Name                       : WindowsXP.jpg
Directory                       : Downloads
File Size                       : 234 kB
File Modification Date/Time     : 2022:08:20 23:35:15+02:00
File Access Date/Time           : 2022:08:20 23:35:15+02:00
File Inode Change Date/Time     : 2022:08:20 23:35:15+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 11.27
GPS Latitude                    : 54 deg 17' 41.27" N
GPS Longitude                   : 2 deg 15' 1.33" W
Copyright                       : OWoodflint
Image Width                     : 1920
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1920x1080
Megapixels                      : 2.1
GPS Latitude Ref                : North
GPS Longitude Ref               : West
GPS Position                    : 54 deg 17' 41.27" N, 2 deg 15' 1.33" W
```

Question: **What is this users avatar of?**

The question is a little tricky. We cannot get the answer directly by the photo, but we can use some metadata and search on Internet some additional information. Let's search on Internet the Copyright value `OWoodflint`.

We will get mainly two interesting URLs:
* https://twitter.com/owoodflint
* https://github.com/OWoodfl1nt/people_finder
* https://oliverwoodflint.wordpress.com/author/owoodflint/

According these results, the only avatar we see it is on Twitter account, so the answer is `cat`.

Question: **What cirty is this person in?**

It is not related to the place where the image has been taken, so the GPS Position metadata is useless. Looking on these URLs, on the GitHub one it is reported `London`.

Question: **Whats the SSID of the WAP he connected to?**

The only information we have related to WiFi is the BSSID from his Twitter account: `B4:5D:50:AA:86:41`.

For getting the SSID from the BSSID, we need to use an online service: https://wigle.net

We need to register an account there, then View -> Advanced Search -> WiFi/Cell Detail tab, type the BSSID and click on Query.

You will get `UnileverWiFi` as SSID.

Question: **What is his personal email address?**

Go on GitHub readme page or move to "Pull requests", select the shown pull request and click on the "Files changed" tab. The email is `OWoodflint@gmail.com`.

Question: **What site did you find his email address on?**

Github

Question: **Where has he gone on holiday?**

Go on his Wordpress blog, you will be noticed he is currently in `New York`.

Question: **What is this persons password?**

It is on the Wordpress blog homepage. Password: `pennYDr0pper.!`.