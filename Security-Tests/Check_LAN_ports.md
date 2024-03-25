Per effettuare dei test su porte LAN, è necessario avere, oltre che l’indirizzo MAC, ma anche l’indirizzo IP dell’asset collegato alla porta.

Nel caso in cui non è possibile recuperare l’indirizzo IP, è possibile ottenerlo guardando sul retro del dispositivo oppure, se collegato ad un box esterno su cui è collegato il cavo Ethernet, al suo retro; oppure eseguendo:
```
arp -a
```
da un client collegato alla stessa rete del dispositivo e recuperare l’indirizzo IP relativo all’indirizzo MAC del dispositivo.

Prima di procedere, prima di inserire il cavo Ethernet, bisogna disabilitare l’interfaccia di rete sul computer utilizzato per il test (e.g., Kali Linux).

Questo è importante per evitare l’innesco di allarmi che causano anche il blocco delle porte mediante il NAC, e quindi un impatto negativo sul test e sull’eventuale utilizzo da parte degli utenti di asset collegati alle porte impattate.

Nello specifico, all’interno di Kali Linux, individuare l’interfaccia di rete, ad esempio `eth0`, e spegnerla mediante:
```
ifconfig eth0 down
```
Successivamente, tramite `macchanger`, cambiare (spoofing) il MAC dell’endpoint Kali Linux con il MAC dell’asset collegato alla porta LAN:
```
macchanger -m 34:9f:7b:cb:bd:e3 eth0
```
poi, verificare che effettivamente ha memorizzato il nuovo indirizzo MAC:
```
ifconfig eth0
```
Se compare il nuovo MAC address, staccare il cavo Ethernet dall’asset interessato e collegarlo all’endpoint Kali Linux, e riabilitare l’interfaccia di rete:
```
ifconfig eth0 up
```
Se il servizio di networking in Kali Linux viene riavviato, l’indirizzo MAC dell’interfaccia di rete viene resettato al suo valore originale.

Assumendo che il DHCP sia attivo e che quindi l’indirizzo IP viene assegnato automaticamente, è possibile eseguire:
```
dhclient eth0
```
Se il comando termina correttamente, è possibile eseguire:
```
ifconfig eth0
```
per verificare che l’indirizzo IP è stato correttamente assegnato all’interfaccia di rete dell’endpoint Kali Linux.

Se invece il comando non termina, o la porta LAN è stata bloccata a causa di un allarme innescato, oppure il DHCP non è attivo. Nel caso in cui il DHCP non sia attivo, è possibile assegnare staticamente l’indirizzo IP che è assegnato all’asset, mediante:
```
ifconfig eth0 <indirizzo ip> netmask <netmask>
```
Nel caso in cui le impostazioni precedenti sono effettuate con successo, è possibile effettuare i test necessari, ad esempio provare a contattare altri server sulla stessa rete per controllare se son raggiungibili dall’indirizzo IP assegnato in quella porta, oppure controllare se Internet è raggiungibile, ad esempio:
```
ping 8.8.8.8
ping 10.x.x.x
```
Infine, bisogna fare un test sull'asset per essere sicuri che, nonostante le regole ristrette applicate mediante NAC, l'asset continui a funzionare.

Nel caso in cui non funzioni, provare ad effettuare un ping da un client verso l’indirizzo IP dell'asset. Se la destinazione è irraggiungibile, se c'è una scatoletta con il cavo LAN inserito che porta poi all'asset, bisogna staccare il cavo di alimentazione dalla scatoletta e riattaccarlo.
