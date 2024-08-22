---
author: Lenam  
pubDatetime: 2024-07-18T15:22:00Z  
title: WriteUp Yincana - Vulnyx  
slug: yincana-writeup-vulnyx-es  
featured: true  
draft: false  
ogImage: "assets/yincana/OpenGraph.png"  
tags:  
  - writeup  
  - vulnyx  
  - xxe  
  - xslt  
  - password cracking  
  - binary planting  
  - sudo 
description:  
  Disfruta de la máquina Yincana y no olvides regalar flores. ;)  
lang: es  
---

Como siempre, pido disculpas por los errores ortográficos y por no conocer los nombres de las técnicas; soy un desarrollador que se adentra en el mundo del hacking. Creo que esta vez es una máquina difícil, aunque alguien puede encontrar formas más fáciles de comprometerla.

Para la creación, he utilizado algunas de las tecnologías con las que he trabajado durante mi vida profesional: PHP, XSLT, y NodeJs. Es un CTF difícil, y se necesita paciencia.

Disfruta de la máquina Yincana y **no olvides regalar flores**. 😉

Habilidades: XXE, XSLT, IDOR?, Cracking de contraseñas (SHA2, RSA).

## Tabla de contenido 

## Enumeración

`$ nmap -sV -sC -A -p 80,22 192.168.1.120 -oN nmap2.txt -vvv  `

<img alt="Imágen" src="/assets/yincana/img_p0_1.png"/>

<img alt="Imágen" src="/assets/yincana/img_p0_2.png" />

<img alt="Imágen" src="/assets/yincana/img_p0_3.png" />

`$ gobuster dir --url http://192.168.1.120/ --wordlist **/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt** -x .php,.htm,.html,.txt,.db,.bak,.pdf -t 20`

<img alt="Imágen" src="/assets/yincana/img_p0_4.png" />

En la página chat.html, encontramos esta información. La fecha se actualiza cada minuto, y encontramos un nombre de dominio.

<img alt="Imágen" src="/assets/yincana/img_p1_3.png" />

`# echo "192.168.1.120 yincana.nyx" >> /etc/hosts`

<img alt="Imágen" src="/assets/yincana/img_p1_1.png" />

Continuamos buscando archivos esta vez en el host virtual yincana.nyx.

<img alt="Imágen" src="/assets/yincana/img_p1_2.png" />

`$ gobuster dir --url http://yincana.nyx/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.htm,.html,.txt,.db,.bak,.pdf -t 20 `

<img alt="Imágen" src="/assets/yincana/img_p2_1.png" />

Parece que el archivo image.php?id=1 es para mostrar o descargar imágenes de las páginas:

<img alt="Imágen" src="/assets/yincana/img_p2_2.png" />

Si buscamos subdominios, no encontraremos ninguno.

## Intrusión

Ingresamos nuestra IP en la URL y comenzamos a escuchar con netcat; parece que recibimos una señal.

<img alt="Imágen" src="/assets/yincana/img_p3_1.png" />

Creamos una página de ejemplo que muestre algo, la enviamos y buscamos la imagen en images.php?id=X, la encontramos.

<img alt="Imágen" src="/assets/yincana/img_p3_3.png" />

Si observamos más de cerca, parece ser un "navegador sin cabeza" (puppeteer o un sistema similar).

<img alt="Imágen" src="/assets/yincana/img_p3_2.png" />

Usamos una pequeña lista de puertos comunes para HTTP.

<https://github.com/danielmiessler/SecLists/blob/master/Discovery/Infrastructure/common-http-ports.txt>

y creamos un script en JavaScript para analizar puertos locales utilizando el navegador sin cabeza.

<img alt="Imágen" src="/assets/yincana/img_p4_1.png" />

y descubrimos el puerto 80 (al que ya teníamos acceso desde fuera) y el puerto 7001 (probablemente solo accesible desde localhost, ya que no lo encontramos con nmap desde fuera).

<img alt="Imágen" src="/assets/yincana/img_p4_2.png" />

Creamos otro script con un iframe para ver la imagen de lo que hay en el puerto local 7001.

<img alt="Imágen" src="/assets/yincana/img_p4_3.png" />

y obtenemos un mensaje: "Need url parameter", parece ser el servicio interno que maneja la generación de estas imágenes, añadimos el parámetro URL con “file:///etc/passwd” y seguimos probando, también pide “Need id parameter”, así que pasamos ambos:

<img alt="Imágen" src="/assets/yincana/img_p5_1.png" />

Ahora en yincana.nyx/image.php?id=41 obtenemos

<img alt="Imágen" src="/assets/yincana/img_p5_2.png" />

y en yincana.nyx/image.php?id=200 obtenemos

<img alt="Imágen" src="/assets/yincana/img_p5_3.png" />

Ya tenemos un LFI.

Buscando y escaneando varios archivos locales para obtener información e intentar RCE (logs, variables de entorno, archivos de configuración, ...) encuentro el id_rsa del usuario jazmin, pero lo obtengo en una imagen y tengo que convertirlo a texto para usarlo.

<img alt="Imágen" src="/assets/yincana/img_p6_1.png" /><img alt="Imágen" src="/assets/yincana/img_p6_2.png" />

Instalo tesseract OCR.

`$ sudo apt install tesseract-ocr`

Modifico la imagen con GIMP para darle más resolución, contraste y solo tomar la parte del texto. Además de tesseract-ocr, también pruebo Google Lens App (una buena opción), Gemini, ChatGPT (problemas de la IA con filtros de seguridad, prompts largos), y otros OCRs en línea, no puedo obtener una clave completamente correcta de la imagen.

Analizo el texto en busca de caracteres inaceptables y lo comparo visualmente con la imagen para corregir algunos errores.

Al final, después de un esfuerzo, obtengo una clave id_rsa correcta pero cifrada para jazmin.

<img alt="Imágen" src="/assets/yincana/img_p7_1.png" />

La crackeamos con john y rockyou.txt muy rápidamente ;)

<img alt="Imágen" src="/assets/yincana/img_p7_2.png" />

<img alt="Imágen" src="/assets/yincana/img_p7_3.png" />

Iniciamos sesión con el usuario jazmin y el id_rsa en el servidor a través de ssh con la frase de paso “flores”:

<img alt="Imágen" src="/assets/yincana/img_p7_4.png" />

Podemos cambiar a otro usuario con un nombre de flor y a otro usuario con un nombre de flor en un bucle recursivo usando sudo -u usuario /bin/bash.

Hay alrededor de 50 usuarios con nombres de flores y podemos cambiar de uno a otro usando sudo para bash. Es como un pez que se muerde la cola y cada usuario puede ejecutar bash como el siguiente.

<img alt="Imágen" src="/assets/yincana/img_p8_1.png" />

Están los usuarios normales (root, mail, www-data, …), 50 usuarios con nombres de flores y un usuario llamado “manel”.

¡Tenemos acceso a todos los usuarios con nombres de flores!

En el directorio de inicio de jazmin, parece que está la aplicación que expone el servicio del puerto 7001 y se utiliza para crear las imágenes de la página de flores.

<img alt="Imágen" src="/assets/yincana/img_p8_2.png" />

Por otro lado, también encontramos los dos sitios web, el predeterminado de Apache con los archivos chat.html e index.html, y el sitio web de flores.

En el archivo index.php del sitio web de flores, vemos que las credenciales de la base de datos se obtienen de las variables de entorno.

<img alt="Imágen" src="/assets/yincana/img_p9_1.png" />

Intentamos leer las variables de entorno del servidor Apache, pero no podemos, o intentamos iniciar sesión como www-data insertando una reverse shell, pero no tenemos permisos en las carpetas públicas del sitio web, ni hemos encontrado un LFI real donde podamos incluir un archivo para interpretar en PHP. Al final, encontramos las credenciales de la base de datos configuradas en el host virtual yincana.nyx.conf.

<img alt="Imágen" src="/assets/yincana/img_p9_2.png" />

Ingresamos a la base de datos para examinar el contenido y encontramos una tabla de usuarios con sus contraseñas (aparentemente hasheadas).

<img alt="Imágen" src="/assets/yincana/img_p10_1.png" />


Obtenemos todos los datos posibles, comentarios de la base de datos, tabla de usuarios y campos. Encontramos un comentario en el campo de contraseñas de la tabla de usuarios que indica el tipo de hash (SHA256).

<img alt="Imágen" src="/assets/yincana/img_p10_3.png" />

Intentamos crackear las contraseñas, pero solo logramos crackear la contraseña del usuario "margarita".

<img alt="Imágen" src="/assets/yincana/img_p10_2.png" />

Intentamos acceder vía SSH con el usuario margarita y la contraseña flores, pero no tenemos acceso. Sin embargo, teníamos acceso a todos los usuarios con nombres de flores, así que accedemos al usuario “margarita” desde el usuario “jazmin”.

<img alt="Imágen" src="/assets/yincana/img_p11_2.png" />

Ahora podemos ejecutar el binario xsltproc como manel con la contraseña de margarita.

Verificamos qué es este binario y para qué sirve; es un procesador XSLT, lo usamos para intentar XXE. No está en gtfobins, pero aún se puede abusar de su privilegio sudo.

Información del binario.

<img alt="Imágen" src="/assets/yincana/img_p11_1.png" />

Podemos leer archivos con privilegios de usuario manel (XXE), intentamos leer la clave RSA, pero no tiene una. Intentamos leer la bandera user.txt.

<img alt="Imágen" src="/assets/yincana/img_p12_1.png" />

Procesamos el XSL del archivo XML con el binario xsltproc usando sudo y el usuario manel:

Hemos obtenido la primera bandera user.txt.

<img alt="Imágen" src="/assets/yincana/img_p12_2.png" />

Creamos una clave id_rsa para intentar incluir la clave pública en los authorized_keys de manel y usarla para conectarnos vía SSH.

<img alt="Imágen" src="/assets/yincana/img_p12_3.png" />

Podemos ejecutar el binario xsltproc con sudo, la contraseña de margarita como manel y el parámetro “output”. Esto nos permite crear archivos con contenido procesado por el xslt con privilegios de manel.

Creamos un archivo XML sin datos y otro con el XSLT para procesarlo y obtener id_rsa.pub como resultado.

<img alt="Imágen" src="/assets/yincana/img_p13_1.png" />

Ejecutamos el siguiente comando para intentar incluir la clave pública RSA en el usuario manel.

`margarita@yincana:/tmp$ sudo -u manel /usr/bin/xsltproc -o /home/manel/.ssh/authorized_keys crea_rsa.xml datos.xml` 

<img alt="Imágen" src="/assets/yincana/img_p13_2.png" />

Intentamos acceder a manel vía SSH con la clave RSA generada desde nuestro kali.

<img alt="Imágen" src="/assets/yincana/img_p13_3.png" />
  
También podríamos realizar escritura de archivos privilegiada utilizando EXSLT, más información en:
<https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection#write-files-with-exslt-extension>

¡Genial! Accedemos al usuario manel, el primer usuario sin nombre de flor.

Por curiosidad, el archivo authorized_keys se ve así, lo arreglamos.

<img alt="Imágen" src="/assets/yincana/img_p14_1.png" />

## Obtener la bandera root.txt

Repasemos: Tenemos acceso a todos los usuarios con nombres de flores y al usuario manel. Intentamos escalar privilegios al usuario root o obtener la bandera root.

Usamos pspy64 para monitorear los procesos que podría estar ejecutando root.

<img alt="Imágen" src="/assets/yincana/img_p14_2.png" />

Encontramos un proceso de root para el archivo xsltproc que utilizamos anteriormente y parece que crea los mensajes para el /chat.html inicial.

<img alt="Imágen" src="/assets/yincana/img_p14_3.png" />

Podemos modificar el archivo /home/mensaje.xml involucrado en este proceso porque el usuario manel pertenece al grupo backupchat.

<img alt="Imágen" src="/assets/yincana/img_p14_4.png" />

El archivo contiene los datos (en formato XML) de los mensajes de chat que se muestran en la página inicial, modificamos el archivo /home/mensajes.xml para intentar obtener la bandera root.txt a través de XXE.

<img alt="Imágen" src="/assets/yincana/img_p15_1.png" />

Esperamos 1 o 2 minutos y la bandera root.txt aparecerá en la dirección inicial:

http://192.168.1.120/chat.html

<img alt="Imágen" src="/assets/yincana/img_p15_2.png" />

## Escalada

No hemos logrado la escalada de privilegios.

Intentamos la escritura de archivos con EXSLT, pero para lograrlo necesitamos modificar el archivo de estilo XSL y solo podemos modificar el archivo de datos XML, o no sabemos o no podemos hacerlo.

Analizamos el proceso utilizado para la lectura de archivos privilegiada para obtener más información. Obtenemos /etc/shadow pero no podemos crackear la contraseña de root. Intentamos leer datos de los directorios /proc/, /root, etc.

Después de un tiempo, muchos de los archivos no se pueden ver porque contienen caracteres no permitidos en XML o bytes nulos, algunos sí podemos ver y al mirar los archivos encontramos la tarea CRON programada:

<img alt="Imágen" src="/assets/yincana/img_p16_1.png" />

Encontramos dos tareas configuradas, la que estamos explotando con XSLT y otra que ejecuta un "chatbackup" el 1 de enero de cada año. Buscamos ese archivo y lo encontramos en nuestro directorio, podemos modificarlo pero tendríamos que esperar hasta el 1 de enero para ejecutarlo. Pero esto nos da una pista.

<img alt="Imágen" src="/assets/yincana/img_p16_2.png" />

La tarea puede ejecutar este archivo porque está incluido en el PATH (primer recuadro rojo en la imagen del crontab) del directorio /home/manel/.local/bin.

<img alt="Imágen" src="/assets/yincana/img_p16_3.png" />

El comando que se ejecuta cada minuto usa "date" sin una ruta absoluta.

<img alt="Imágen" src="/assets/yincana/img_p17_1.png" />
<img alt="Imágen" src="/assets/yincana/img_p17_2.png" />

Buscamos dónde se encuentra el binario date, y está en /usr/bin/date, dado que la ruta /home/manel/.local/bin tiene permisos de escritura y viene antes de /usr/bin, podemos intentar reemplazar “date” con nuestro “date” malicioso.

<img alt="Imágen" src="/assets/yincana/img_p17_3.png" />
<img alt="Imágen" src="/assets/yincana/img_p17_4.png" />

Esperamos un minuto para ver si aparece un bash con SUID en /tmp.

<img alt="Imágen" src="/assets/yincana/img_p17_5.png" />

¡Felicidades, somos root!

