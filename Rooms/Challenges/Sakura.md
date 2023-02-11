# Sakura
![tryhackme_logo](https://user-images.githubusercontent.com/83867734/185771149-cb02c6f2-8476-4ab3-a626-cca8db0a08bf.png)

Difficulty: **Easy**

Tags
--
* OSINT

Tools used
--
* exiftool
* sherlock

Machines
--
Attacker:
* Name: attacker_machine
* Operating System: Athena OS
* IP Address: 10.18.98.39

Victim:
* The target is the owner of an image

## Task 1: Introduction

No important.

## Task 2: Tip-Off

By an image on this link https://raw.githubusercontent.com/OsintDojo/public/3f178408909bc1aae7ea2f51126984a8813b0901/sakurapwnedletter.svg, we need to find the username of the attacker. We can read the page source code or we can save the image and use `exiftool`:
```
wget https://raw.githubusercontent.com/OsintDojo/public/3f178408909bc1aae7ea2f51126984a8813b0901/sakurapwnedletter.svg

exiftool sakurapwnedletter.svg

ExifTool Version Number         : 12.50
File Name                       : sakurapwnedletter.svg
Directory                       : .
File Size                       : 850 kB
File Modification Date/Time     : 2023:02:11 14:46:40+01:00
File Access Date/Time           : 2023:02:11 14:46:40+01:00
File Inode Change Date/Time     : 2023:02:11 14:46:40+01:00
File Permissions                : -rw-r--r--
File Type                       : SVG
File Type Extension             : svg
MIME Type                       : image/svg+xml
Xmlns                           : http://www.w3.org/2000/svg
Image Width                     : 116.29175mm
Image Height                    : 174.61578mm
View Box                        : 0 0 116.29175 174.61578
SVG Version                     : 1.1
ID                              : svg8
Version                         : 0.92.5 (2060ec1f9f, 2020-04-08)
Docname                         : pwnedletter.svg
Export-filename                 : /home/SakuraSnowAngelAiko/Desktop/pwnedletter.png
Export-xdpi                     : 96
Export-ydpi                     : 96
Metadata ID                     : metadata5
Work Format                     : image/svg+xml
Work Type                       : http://purl.org/dc/dcmitype/StillImage
Work Title       
```
We get the attacker username from `Export-Filename` field: `SakuraSnowAngelAiko`.

## Task 3: Reconnaissance

Now we must retrieve the email address of the attacker. We can use `sherlock` for checking on which websites the found username is registered:
```
sherlock SakuraSnowAngelAiko

[*] Checking username SakuraSnowAngelAiko on:

[+] Arduino: https://create.arduino.cc/projecthub/SakuraSnowAngelAiko
[+] Facebook: https://www.facebook.com/SakuraSnowAngelAiko
[+] GitHub: https://www.github.com/SakuraSnowAngelAiko
[+] Reddit: https://www.reddit.com/user/SakuraSnowAngelAiko
[+] Tinder: https://www.tinder.com/@SakuraSnowAngelAiko
[+] koo: https://www.kooapp.com/profile/SakuraSnowAngelAiko
[+] zoomit: https://www.zoomit.ir/user/SakuraSnowAngelAiko

[*] Results: 7

[!] End:  The processing has been finished.
```
If we give a look on its GitHub profile, we see a PGP repository storing a public key. We can decode its content (removing the first and the last lines) and among the characters we will see the email address:
```
echo -n "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grbk" | base64 -d

 h\^B5|f70
<8 A1X7+˱gp7e0Ey_&B3iβe\`=(GYK:*a[/1H=\Л4QirsCY,|V(HS`2ߖR3!#FBk:Z0V%H;f)Ѓ!Y'D8Z3[5}4wj9:n~txrzvs1Ր+5m/rcah}Pdl(HWfƻҶܢ[8[Nf81H/FVmF)2Mx\+NG'u.W6E~;.;hV[6x'sAԐ( SakuraSnowAngel83@protonmail.com
>!Q';&ҔP`
         	
                	
	

	ҔP
]BX^ٍrԂ,^^z%*Y-F,CԠBF9Z#(spC88犇m߱}zPKRA_.49hQSͭV'[L;BѕVo
                                                      QWr|1^Dc\E`ӹ^T\5w0ܩOETcН%d﫟<M@qJJc␪*XʕLDoC$,xax.qJyX"ˬ:Sf}9
gtOP;^cӘ*&,H3yvMy`

                  &+#D<p4R}՝xY)NVfG	n$}]Hs$v`/,@aBF]aG:1F3S!\lwr˃Q&)#/%vYܥeBNw*$rmXHcHƳ1/ǩ-	wα{@_&(;WCmo'w\:ܒDF1>ݰR&vt9tcuTL"󔿕u-F#Uq,ÿwmGîa}o#ڎ)8~_[ׄ@D1v$[8mez[lkp2۪.:K=A
                                                                                                                                                                            U5)8Uz6hUbDCf(σW2R
&!Q';&ҔP`
         	
	ҔPB
$SHʷvWv%L $RS"-+S2h)rj&U[F%)jTףr
z+8Ѡ4--+xko
V{.NzoU
       tH?pRΖsY	5uFf-~n)wv|gH^ִD.8/jz-GQoP7>]֭9k
#1+*y^lRW_g^1'Dvd߱@c%Ю>mIёjwbivӠ#u+^	zQ\̛Xc)base64: invalid input
```
So, the email address is `SakuraSnowAngel83@protonmail.com`.

Now it is asked to find the name and surname of the attacker. From GitHub we get the name `Aiko`. By Sherlock, we don't get social media showing name and surname of the attacker, so, if we try to google `SakuraSnowAngelAiko Aiko`, we find some Instagram profile of `Aiko Abe` that is the real full name of the attacker.

## Task 4

Here we must take some additional information from its GitHub account.

What cryptocurrency does the attacker own a cryptocurrency wallet for? Ethereum, indeed the attacker has a repository called `ETH` with a `miningscript` file inside it.
 
What is the attacker's cryptocurrency wallet address? Opening `miningscript`, click on History and select the oldest commit. You will see `stratum://0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef.Aiko:pswd@eu1.ethermine.org:4444` so the cryptocurrency wallet address is `0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef`.

What mining pool did the attacker receive payments from on January 23, 2021 UTC? From the information above, the mining pool the attacker received payments from on January 23 was `ethermine`. For getting this information, we can also visit https://www.blockchain.com/explorer and search for the attacker wallet address.

What other cryptocurrency did the attacker exchange with using their cryptocurrency wallet? blockchain.com/explorer is a good website but does not provide all information we need. For answering this question, we can visit https://etherscan.io/ where we type the attacker wallet address. From there we see further transactions, and we can focus on the column "To" that contains some transactions to "Tether: USDT Stablecoin". So, the answer is `Tether`.


## Task 5: Taunt

We received this message from the attacker https://raw.githubusercontent.com/OsintDojo/public/main/taunt.png and now we are aware he has more than one account. Let's retrieve more information.

What is the attacker's current Twitter handle? The screenshot contains a username `AikoAbe3`. Google it and you will see a Twitter profile of `sakuraloveraiko`.

What is the URL for the location where the attacker saved their WiFi SSIDs and passwords? From a Twitter post on the attacker profile, we see an HEX string: `0a5c6e136a98a60b8a21643ce8c15a74`.

According to the track of the exercise, we need to find information related to this in the Dark Web. Furthermore, on the Twitter post, the attacker says "Not too concerned about someone else finding them on the Dark Web. Anyone who wants them will have to do a real DEEP search to find where I PASTEd them." so, by focusing on capital letters, it is an hint for Deep Paste service. Deep Paste is an onion service that is able to search for pastebin contents by starting from a keyword.

The working Deep Paste URL is http://depasteon6cqgrykzrgya52xglohg5ovyuyhte3ll7hzix7h5ldfqsyd.onion and from there we can search for `0a5c6e136a98a60b8a21643ce8c15a74`. Just note that, currently, on Deep Paste website is reported it will be closed soon.

By the way, the information we get from this search is:
```
Saving here so I do not forget

School WiFi Computer Lab: 			GTRI-Device		GTgfettt4422!@
Mcdonalds: 					Buffalo-G-19D0-1        Macdonalds2020
School WiFi: 					GTvisitor		GTFree123
City Free WiFi: 				HIROSAKI_Free_Wi-Fi 	H_Free934!
Home WiFi: 					DK1F-G			Fsdf324T@@
```
Due to a bug on the flag submission field, the accepted flag refers to an old hash, so it is `http://deepv2w7p33xa4pwxzwi2ps4j62gfxpyp44ezjbmpttxz3owlsp4ljid.onion/show.php?md5=b2b37b3c106eb3f86e2340a3050968e2`.

What is the BSSID for the attacker's Home WiFi? Let's use https://wigle.net, login on it, click on "View" -> "Advanced Search" and, on "SSID / Network Name", search for `DK1F-G` and click on "Query". Tou will get `84:AF:EC:34:FC:F8` as BSSID.

## Task 6: Homebound

What airport is closest to the location the attacker shared a photo from prior to getting on their flight? From Twitter, we have an image of cherry blossoms. In the photo, the Washington Memorial appears in the distance. I used a map to look for airports near the Washington Memorial, and found Ronald Reagan Washington National Airport, which has airport code DCA.

Note, taking the image from the Twitter post will link it to https://pbs.twimg.com/media/Esh-uTvUcAc-sXC?format=jpg&name=small. For having a better resolution, just change the link as the following: https://pbs.twimg.com/media/Esh-uTvUcAc-sXC?format=png&name=large. If you zoom, you can see the Washington monument.

What airport did the attacker have their last layover in? Here we must refer to the photo at "First Class Lounge, Sakura Lounge". By searching on Google "skytrax 5 star airlines", we can visit their main website at https://skytraxratings.com, and scrolling down, we can switch "Airlines" to "Airports" and "All Regions" to "Asia". When we click "Browse selection", filter the results by 5 Stars (since on the photo there are 5 stars on SKYTRAX), and we get few results. The correct airport is Tokyo Haneda Airport (HND).

What lake can be seen in the map shared by the attacker as they were on their final flight home? By looking on that map photo he shared on Twitter, there is a small lake. By searching on Google Maps near Tokyo Haneda Airport, and going to north, there is a lake called "Lake Inawashiro".

What city does the attacker likely consider "home"? Go back to https://wigle.net and from the information retrieved in the previous task about the Home WiFi, extract the latitude and longitude coordinates and insert them on Google Maps. You will discover the city is Hirosaki.