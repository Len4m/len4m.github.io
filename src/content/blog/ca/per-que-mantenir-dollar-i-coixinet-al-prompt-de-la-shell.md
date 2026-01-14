---
author: Lenam
pubDatetime: 2025-12-12T00:00:00Z
title: "Per què val la pena mantenir $ i # al prompt de la shell"
urlSlug: per-que-usar-dollar-coixinet-prompt-shell
featured: false
draft: false
ogImage: "../../../assets/images/opinion/prompt-simbol.png"
tags:
    - linux
    - shell
    - prompt
    - opinion
description:
  "Article d'opinió sobre per què té sentit continuar usant els símbols $ i # al prompt de la shell per veure d'una ullada si ets usuari normal o root."
lang: ca
translationId: por-que-seguir-usando-dollar-y-hash-en-el-prompt-de-la-shell
---

## Taula de continguts

## En defensa de l'humil `$` i del temible `#`

*(opinió totalment subjectiva, però amb afecte)*

Aquest post **no** és un writeup de CTF, ni un exploit 0day, ni res útil per guanyar punts en un scoreboard.
És simplement un rant afectuós sobre alguna cosa que veig cada cop més: gent traient el `$` i el `#` del prompt.

Sí, aquests símbols d'abans que indiquen:

* `$` → usuari normal
* `#` → root (aka: "si t'equivoques aquí, plores")

I jo vinc a dir:

> **si us plau, no els matem encara.**

## El prompt: aquest cartell que t'avisa abans de fer-la

Digues-li prompt, path, cursor, "on escric comandes", tant se val.
Aquest tros de text abans del que teclees no és decoració: és **informació crítica**.

```text
$ comanda   <- usuari normal
# comanda   <- root
```

Amb un sol caràcter saps:

> El que faré trenca *el meu* usuari… o trenca *el servidor de producció*?

Sense `whoami`, sense `id`, sense mirar res. Ho veus de reüll i ja està.

## Per què alguns hackers passen del `$` i `#`?

Perquè al món del hacking i l'administració de sistemes sempre estem provant coses rares al prompt, així que no sorprèn que, pel motiu que sigui, molta gent es carregui el `$` i el `#`.

Veig molts prompts d'aquest estil:

```text
❯
λ
»
```

O temes de zsh/fish súper currats, amb:

* usuari, host, ruta
* branch de git
* exit code
* la fase de la lluna si et despistes

…però ni rastre de `$` o `#`.

Les raons típiques:

* "Queda més net / minimalista"
* "Jo ja ho distingeixo pels colors"
* "Jo *sé* en què estic, no necessito això"

Molt bé. Fins que surts de la teva cova.

## El dia que els colors no et poden salvar

L'argument "jo faig servir colors" es trenca molt ràpid:

* En Markdown, README, blogs, writeups…
  El color normalment desapareix.
  Exemple:

  ```text
  # iptables -F
  ```

  A la teva terminal ho tenies en vermell nuclear amb fons radioactiu.
  Al blog: text pla i cara de "bé, això serà segur, no?".

* En una TTY cutreta, un contenidor random o una màquina remota sense la teva config de zsh, el teu tema favorit no existeix.

* En una captura de pantalla, en un PDF o en un monitor dolent en plena xerrada o conferència, els colors es veuen regulín, però el `#` es continua entenent igual.

El color mola, sí. Però **no viatja bé**.
El caràcter, sí.

## Exemples on el `#` hauria de fer-te esgarrifances

És molt més fàcil veure el perill així:

```text
# iptables -F
# userdel -r usuari-que-no-era
# mv /etc /etc.bak
# mysql -e 'DROP DATABASE produccio;'
```

Que així:

```text
❯ iptables -F
❯ userdel -r usuari-que-no-era
❯ mv /etc /etc.bak
❯ mysql -e 'DROP DATABASE produccio;'
```

En el segon cas, si no tens context, sembla un script qualsevol.
En el primer, el `#` ja t'està cridant:

> Ei, això no és una joguina, segur que vols prémer Enter?

No et salvarà sempre, però és **un fre mental gratis**.

## Documentació, writeups i CTFs

En CTFs i writeups, el `$` i `#` són or pur:

* `$` → ho pots copiar com a user normal
* `#` → això és cosa de root / sudo

Exemple típic en un writeup:

```text
$ sudo -l
# cat /root/root.txt
```

Encara que estiguis llegint ràpid, el teu cervell entén: "ah, vale, aquí ja soc root".
Sense colors, sense plugins, sense res. En un PDF, en un blog, on sigui.

Si treus aquests símbols, obligues el lector a **endevinar el context**. I ja en tenim prou amb barallar-nos amb filtres, WAFs, payloads URL-encodeats tres vegades, race conditions i logs plens de 500 registres com per també barallar-nos amb el prompt.

## L'argument de l'estètica

Sí, ja ho sé: un prompt tipus:

```text
┌─[ctfer@kali]─[~/ctf/machine]
└──╼ $
```

queda més "pro" que un trist:

```text
$
```

I no hi ha cap problema en muntar un prompt bonic.
Però no costa res que acabi en:

* `$` si ets user
* `#` si ets root

Pots tenir:

* colors
* git
* hora
* exit code
* entorn (prod/stage/dev)

…i tot i així deixar que **un caràcter al final resumeixi els teus privilegis**.

## Això no és un estàndard, és un rant

Tot això és simplement **la meva opinió d'usuari rondinaire de shell**:

* Vols un prompt amb emojis i sense `$` ni `#`? Endavant.
* Vols un únic símbol `❯` per a tot? El teu terminal, les teves normes.
* Vols viure perillosament sense saber quan ets root? Tu sabràs 😂

Jo només defenso que, en un món de:

* captures de pantalla,
* blogs de CTF,
* markdown sense color,
* sessions SSH random,

el vell `$` i el vell `#` continuen sent **la forma més barata i efectiva de veure els privilegis d'una ullada**.

No és nostàlgia. És pura comoditat.

## TL;DR

* `$` → usuari normal
* `#` → root
* Són lletjos, però extremadament útils.
* Colors i temes xulos estan bé, però no substitueixen el símbol.
* En writeups, documentació i CTFs ajuden moltíssim a entendre el context.

I al final, com sempre en aquest món:

> Hackeja com vulguis, configura la teva shell com vulguis…
> però si deixes el `$` i el `#`, sens dubte no t'estàs fent mal a tu mateix.

Gràcies per llegir fins aquí. Tant de bo t'hagi convençut una mica i, si no, tampoc passa res: al final, l'important és que cadascú sigui feliç amb el seu prompt. 😊
