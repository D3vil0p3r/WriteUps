# CTF collection Vol.1

![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Tags
--
* Encoding
* Steganography

Tools used
--
* CyberChef
* Ghidra
* Bless
* stegosuite
* steghide

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* The target is the owner of an image

## Task 2: What does the base said?

Can you decode the following?

VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==

Solution:
```
echo -n "VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==" | base64 -d
```

## Task 3: Meta meta

Meta! meta! meta! meta...................................

Solution:
```
strings Findme.jpg | grep THM
```

## Task 4: Mon, are we going to be okay?

Something is hiding. That's all you need to know.

Solution:
```
steghide extract -sf Extinction.jpg
cat Final_message.txt
```

## Task 5: Erm......Magick 

Huh, where is the flag? THM{wh173_fl46}

Solution: just insert that flag.

## Task 6: QRrrrr

Such technology is quite reliable.

Solution:
Upload `QR.png` to https://4qrcode.com/scan-qr-code.php and you will get the flag.

## Task 7: Reverse it or read it?

Both works, it's all up to you.

Solution:
Open `hello.hello` by Ghidra and search THM inside the reversed file content:
```
00101149 48 8d 3d        LEA        RDI,[s_THM{345y_f1nd_345y_60}_00102008]          = "THM{345y_f1nd_345y_60}"
```

## Task 8: Another decoding stuff

Can you decode it?

3agrSy1CewF9v8ukcSkPSYm3oKUoByUpKG4L

Solution:

We can use **From Base58** in CyberChef.

## Task 9: Left or right

Left, right, left, right... Rot 13 is too mainstream. Solve this

MAF{atbe_max_vtxltk}

Solution:

We can use **ROT 13** in CyberChef.

## Task 10: Make a comment

No downloadable file, no ciphered or encoded text. Huh .......

Solution:

Right-click on that part of the website and click on "Inspect". You will get the flag.

## Task 11: Can you fix it?

I accidentally messed up with this PNG file. Can you help me fix it? Thanks, ^^

Solution:

Open the image file by **Bless** and add the HEX bytes for PNG files, that are `89 50 4E 47` and delete `23 33 44 5F` because the first four bytes must be followed by `0D 0A 1A 0A`. Then, open the image file by `eog spoil.png` for getting the flag.

## Task 12: Read it

Some hidden flag inside Tryhackme social account.

Solution:

Search "TryHackMe social Reddit" on Google. One of the first results should contains the flag.

## Task 13: Spin my head

What is this?

++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>>++++++++++++++.------------.+++++.>+++++++++++++++++++++++.<<++++++++++++++++++.>>-------------------.---------.++++++++++++++.++++++++++++.<++++++++++++++++++.+++++++++.<+++.+.>----.>++++.

Solution:

This string is encoded as BrainFuck. Decode it by https://www.splitbrain.org/_static/ook/

## Task 14: An exclusive!

Exclusive strings for everyone!

S1: 44585d6b2368737c65252166234f20626d
S2: 1010101010101010101010101010101010

Solution:

Compute the XOR between the two strings by https://xor.pw, then use CyberChef with **From Hex** for getting the flag.

## Task 15: Binary walk

Please exfiltrate my file :)

Solution:
```
binwalk -e hell.jpg
cat _hell.jpg.extracted/hello_there.txt
```

## Task 16: Darkness

There is something lurking in the dark.

Solution:

Use https://github.com/rajan98/StegoSuit. Use `python -m pip install opencv-python pillow tk` for installing missing dependencies.

## Task 17: A sounding QR

How good is your listening skill?

Solution:

Upload `QRCTF.png` to https://4qrcode.com/scan-qr-code.php and you will get a SoundCloud link. Open it and you will listen a voice spelling the flag content.

## Task 18: Dig up the past

Sometimes we need a 'machine' to dig the past

Targetted website: https://www.embeddedhacker.com/
Targetted time: 2 January 2020

Solution:

Use Wayback Machine for visit the provided URL on the provided date, and check the page source code.

## Task 19: Uncrackable!

Can you solve the following? By the way, I lost the key. Sorry >.<

MYKAHODTQ{RVG_YVGGK_FAL_WXF}

Flag format: TRYHACKME{FLAG IN ALL CAP}

Solution:

Use Vigenere Cipher by https://cryptii.com/pipes/vigenere-cipher and use "thm" as key.

## Task 20: Small bases

Decode the following text.

581695969015253365094191591547859387620042736036246486373595515576333693

Solution:

Need to decode this decimal string to hex and then to ascii. Let's do this by Python:
```python
python
>>> n = 581695969015253365094191591547859387620042736036246486373595515576333693
>>> h = hex(n)[2:]
>>> bytearray.fromhex(h).decode()
```

## Task 21: Read the packet

I just hacked my neighbor's WiFi and try to capture some packet. He must be up to no good. Help me find it.

Solution:

Open `flag.pcapng` file by Wireshark and extract HTTP objects. Identify `flag.txt` object, save it and read its content.