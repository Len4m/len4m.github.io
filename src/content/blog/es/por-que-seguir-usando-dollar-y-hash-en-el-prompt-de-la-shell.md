---
author: Lenam
pubDatetime: 2025-12-12T00:00:00Z
title: "Por qué seguir usando $ y # en el prompt de la shell"
urlSlug: por-que-usar-dollar-hash-prompt-shell
featured: false
draft: false
ogImage: "../../../assets/images/opinion/prompt-simbol.png"
tags:
    - linux
    - shell
    - prompt
    - opinion
description:
  "Artículo de opinión sobre por qué seguir usando los símbolos $ y # en el prompt de la shell para distinguir de un vistazo entre usuario normal y root."
lang: es
translationId: por-que-seguir-usando-dollar-y-hash-en-el-prompt-de-la-shell
---

## Tabla de contenido

## En defensa del humilde `$` y del temible `#`

*(opinión totalmente subjetiva, pero con cariño)*

Este post **no** es un writeup de CTF, ni un exploit 0day, ni nada útil para ganar puntos en un scoreboard.
Es simplemente un rant cariñoso sobre algo que veo cada vez más: gente quitando el `$` y el `#` del prompt.

Sí, esos símbolos viejunos que indican:

* `$` → usuario normal
* `#` → root (aka: “si te equivocas aquí, lloras”)

Y yo vengo a decir:

> **por favor, no los matemos todavía.**

## El prompt: ese cartelito que te avisa antes de liarla

Llámalo prompt, path, cursor, “donde escribo comandos”, da igual.
Ese trocito de texto antes de lo que tecleas no es decoración: es **información crítica**.

```text
$ comando   <- usuario normal
# comando   <- root
```

Con un solo carácter sabes:

> ¿Lo que voy a hacer rompe *mi* usuario… o rompe *el servidor de producción*?

Sin `whoami`, sin `id`, sin mirar nada. Lo ves de reojo y listo.

## ¿Por qué algunos hackers pasan del `$` y `#`?

Porque en el mundillo del hacking y la administración de sistemas siempre estamos probando cosas raras en el prompt, así que no sorprende que, por el motivo que sea, mucha gente se cargue el `$` y el `#`.

Veo muchos prompts de este estilo:

```text
❯
λ
»
```

O temas de zsh/fish súper currados, con:

* usuario, host, ruta
* branch de git
* exit code
* la fase de la luna si te despistas

…pero ni rastro de `$` o `#`.

Las razones típicas:

* “Queda más limpio / minimalista”
* “Yo ya lo distingo por colores”
* “Yo *sé* en qué estoy, no necesito eso”

Muy bien. Hasta que sales de tu cueva.

## El día que los colores no te pueden salvar

El argumento “yo uso colores” se rompe muy rápido:

* En Markdown, README, blogs, writeups…
  El color normalmente desaparece.
  Ejemplo:

  ```text
  # iptables -F
  ```

  En tu terminal lo tenías en rojo nuclear con fondo radioactivo.
  En el blog: texto plano y cara de “bueno, esto será seguro, ¿no?”.

* En una TTY cutre, un contenedor random o una máquina remota sin tu config de zsh, tu tema favorito no existe.

* En una captura de pantalla, en un PDF o en un monitor malo en plena charla o conferencia, los colores se ven regulín, pero el `#` se sigue entendiendo igual.

El color mola, sí. Pero **no viaja bien**.
El carácter, sí.

## Ejemplos donde el `#` debería darte escalofríos

Es mucho más fácil ver el peligro así:

```text
# iptables -F
# userdel -r usuario-que-no-era
# mv /etc /etc.bak
# mysql -e 'DROP DATABASE produccion;'
```

Que así:

```text
❯ iptables -F
❯ userdel -r usuario-que-no-era
❯ mv /etc /etc.bak
❯ mysql -e 'DROP DATABASE produccion;'
```

En el segundo caso, si no tienes contexto, parece un script cualquiera.
En el primero, el `#` ya te está gritando:

> Oye, esto no es un juguete, ¿seguro que quieres darle a Enter?

No te va a salvar siempre, pero es **un freno mental gratis**.

## Documentación, writeups y CTFs

En CTFs y writeups, el `$` y `#` son oro puro:

* `$` → lo puedes copiar como user normal
* `#` → esto es cosa de root / sudo

Ejemplo típico en un writeup:

```text
$ sudo -l
# cat /root/root.txt
```

Aunque estés leyendo rápido, tu cerebro entiende: “ah, vale, aquí ya soy root”.
Sin colores, sin plugins, sin nada. En un PDF, en un blog, donde sea.

Si quitas esos símbolos, obligas al lector a **adivinar el contexto**. Y bastante tenemos ya con pelear con filtros, WAFs, payloads URL-encodeados tres veces, race conditions y logs llenos de 500 registros como para también pelear con el prompt.

## El argumento de la estética

Sí, lo sé: un prompt tipo:

```text
┌─[ctfer@kali]─[~/ctf/machine]
└──╼ $
```

queda más “pro” que un triste:

```text
$
```

Y no hay ningún problema en montar un prompt guapo.
Pero no cuesta nada que termine en:

* `$` si eres user
* `#` si eres root

Puedes tener:

* colores
* git
* hora
* exit code
* entorno (prod/stage/dev)

…y aún así dejar que **un carácter al final resuma tus privilegios**.

## Esto no es un estándar, es un rant

Todo esto es simplemente **mi opinión de usuario cascarrabias de shell**:

* ¿Quieres un prompt con emojis y sin `$` ni `#`? Adelante.
* ¿Quieres un único símbolo `❯` para todo? Tu terminal, tus normas.
* ¿Quieres vivir peligrosamente sin saber cuándo eres root? Tú sabrás 😂

Yo solo defiendo que, en un mundo de:

* capturas de pantalla,
* blogs de CTF,
* markdown sin color,
* sesiones SSH random,

el viejo `$` y el viejo `#` siguen siendo **la forma más barata y efectiva de ver los privilegios de un vistazo**.

No es nostalgia. Es pura comodidad.

## TL;DR

* `$` → usuario normal
* `#` → root
* Son feos, pero extremadamente útiles.
* Colores y temas chulos están bien, pero no sustituyen al símbolo.
* En writeups, documentación y CTFs ayudan muchísimo a entender el contexto.

Y al final, como siempre en este mundillo:

> Hackea como quieras, configura tu shell como quieras…
> pero si dejas el `$` y el `#`, desde luego no te estás haciendo daño a ti mismo.

Gracias por leer hasta aquí. Ojalá te haya convencido un poco y, si no, tampoco pasa nada: al final, lo importante es que cada cual sea feliz con su prompt. 😊
