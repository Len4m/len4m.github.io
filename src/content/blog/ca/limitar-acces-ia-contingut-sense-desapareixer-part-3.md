---
author: Lenam
pubDatetime: 2026-01-18T00:00:00Z
title: "Com limitar l'accés de la intel·ligència artificial al teu contingut sense desaparèixer de la web (Part 3 - Més reducció de tokens)"
urlSlug: limitar-acces-ia-contingut-sense-desapareixer-part-3
featured: false
draft: false
ogImage: "../../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph3.png"
tags:
    - ai
    - privacy
    - web
    - opinion
    - ia-limitation
    - security
    - tokens
    - toon
description:
  "Com adaptar el contingut alternatiu per reduir tokens utilitzant TOON i altres tècniques."
lang: ca
translationId: limitar-acceso-ia-contenido-sin-desaparecer-parte-3
---

![reduir tokens](../../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph3.png)

*TOON, resums compactes i un patró pràctic per publicar ja sense regalar tokens.*

**Sèrie:**
- [Part 1: Introducció](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-1/)
- [Part 2: Estratègies tècniques](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-2/)
- **Part 3: Més reducció de tokens**

## Taula de continguts

## De la Part 2 a la Part 3

A la [Part 2](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-2/) vam veure com bloquejar, permetre i servir contingut alternatiu als bots. Aquí tanco la sèrie amb una pregunta concreta: **si ja mostraré un resum a la IA, com ho faig de manera que consumeixi els mínims tokens possibles sense perdre context?**

Aquest article proposa un format simple (TOON) i un flux de publicació que pots aplicar avui mateix.

## L'objectiu: menys tokens, mateix context

No busquem ocultar-ho tot: busquem **optimitzar què veu la IA**. L'objectiu és que un bot pugui:

* entendre de què va l'article,
* enllaçar-lo correctament,
* i evitar ingerir el text complet.

Això implica **resums molt compactes** i una estructura pensada per reduir tokens.

## Què és TOON (Token-Oriented Object Notation)

**TOON** és un format compacte i llegible que **codifica el model de dades JSON** per a prompts de LLM, amb l'objectiu de reduir tokens sense perdre estructura. La documentació oficial el defineix com una representació “compacta i llegible” del model JSON per a prompts. [TOON: Token-Oriented Object Notation](https://toonformat.dev/)

Tot i que TOON no es va dissenyar específicament per **compartir contingut a internet**, sí que es va pensar per **reduir tokens** i **millorar la comprensió per part dels models**. Per això és ideal per publicar continguts que consumiran màquines.

A més, hi ha **benchmarks públics** que mesuren comprensió i recuperació de dades: TOON assoleix un **73,9% de precisió** davant del **69,7% en JSON** i fa servir **un 39,6% menys de tokens** en els datasets provats. [Benchmarks de TOON](https://toonformat.dev/guide/benchmarks)

Pensa en TOON com un equivalent ultra-resumit del teu article: **títol, URL canònica, resum mínim, punts clau i etiquetes**. Tota la resta sobra.

### Principis de disseny TOON

* **Camps curts i estables**: claus breus, valors compactes.
* **Res de prosa llarga**: el resum és màxim 1-2 línies.
* **Sense duplicació**: evita repetir el mateix amb altres paraules.
* **Sense farciment**: adjectius i context superflu fora.
* **Canònic sempre**: un enllaç clar a la URL completa.

### Plantilla TOON mínima (exemple)

Els camps TOON recomanats estan dissenyats per ser fàcilment comprensibles pels models de llenguatge, però com que no és un estàndard tancat, pots incloure qualsevol camp o estructura que necessitis per descriure el teu contingut: `author`, `modified`, `title`, `category` o qualsevol altra clau o estructura de dades TOON que tingui sentit en el teu cas.

Exemple realista per a un article:

```yaml
ver: 1
type: article
lang: es
url: https://tusitio.com/post/estrategia-hibrida
use: index=1,cite=1,train=0,derive=0
sum: Estrategia híbrida para controlar crawlers IA sin perder visibilidad ni regalar contenido completo.
k: [bloqueo_selectivo|feed_compacto|control_semantico|menos_tokens]
ent: [robots.txt|nginx|ai_crawlers]
ts: 2026-01-15
```

#### Noms de camps (per què aquests i no altres)

* `ver`: més clar que `v`, més curt que `version`.
* `type`: universal en datasets.
* `lang`: estàndard reconegut pels LLMs.
* `url`: universal i esperat.
* `use`: semàntica directa.
* `sum`: molt comú en datasets.
* `k`: abreviatura àmpliament usada.
* `ent`: estàndard informal per a entitats.

Mínim viable real:

* `type`: context immediat del contingut.
* `lang`: interpretació lingüística correcta.
* `url`: font canònica per a citació.
* `sum`: resposta immediata sense inferència.

Amb aquests 4 camps, un LLM pot **respondre, resumir i citar**.

#### Camp `use` (nucli ètic-tècnic)

És una **proposta sense efecte vinculant**: el bot pot ignorar-la, però també podria fer-la servir en el futur per entendre el context i respectar les teves preferències.

Format compacte:

```yaml
use: index=1,cite=1,train=0,derive=0
```

Interpretació natural per a qualsevol LLM:

* `index=1`: es pot indexar.
* `cite=1`: es pot citar amb enllaç.
* `train=0`: no entrenar.
* `derive=0`: no persistir derivats.

### TOON per a un article vs TOON per a llistats

Un **TOON d'article** és útil per explicar un contingut concret amb el mínim de tokens. Un **TOON de llistat** (per exemple, darrers articles, guies o productes) és encara més valuós perquè **estalvies tokens en bloc**: comparteixes camps una sola vegada i redueixes molta repetició.

En llistats, TOON brilla pel patró **tabular**: declares els camps una vegada i després només envies files. Això baixa moltíssim el cost quan hi ha 10, 50 o 200 entrades.

**Exemple: llistat compacte d'articles**

```yaml
toon: 1
list: articles
articles[3]{id,url,tit,summary,updated}:
  parte-1,/blog/limitar-acceso-ia-contenido-sin-desaparecer-parte-1,Intro,Ideas base y contexto,2026-01-10
  parte-2,/blog/limitar-acceso-ia-contenido-sin-desaparecer-parte-2,Estrategias,Control técnico para bots,2026-01-14
  parte-3,/blog/limitar-acceso-ia-contenido-sin-desaparecer-parte-3,TOON,Más reducción de tokens,2026-01-18
```

Si publiques un feed o un índex de continguts, un TOON de llistat **redueix tokens de manera molt més agressiva** que un per article.

## Tècniques addicionals de reducció de tokens

TOON és el contenidor. Aquestes tècniques ajuden a **compactar el contingut**:

* **Resum jeràrquic**: un titular + 3 punts clau.
* **Llistes en lloc de paràgrafs**: menys tokens i més densitat informativa.
* **Entitats i conceptes clau**: anomena l'essencial (tecnologies, normes, riscos).
* **Eliminar redundàncies**: no repeteixis la mateixa idea amb sinònims.
* **Zero cites llargues**: enllaça la font en lloc de copiar.

## Proposta pràctica perquè funcioni avui

Això **funciona avui de forma segura** i seria molt positiu continuar treballant en aquesta direcció, creant **formats i propostes estandarditzades** per a la compartició d'informació cap a màquines, amb l'objectiu clar de **reduir el consum energètic** i la quantitat de **tokens** necessaris.


Aquest és un flux **mínim viable** i realista:

1. **Crea un fitxer TOON per article**
   - Ruta suggerida: `/ia-content/slug.toon`
   - Format: text pla

2. **Afegeix-lo al teu `llms.txt`**

```markdown
# /llms.txt (ejemplo, formato Markdown)
# Mi sitio
> Contenido técnico con alternativas compactas para IA.

Aquí publico TOONs por artículo y listados compactos para IA.

## Contenido alternativo
- [TOON Parte 3](https://tu-dominio.com/ia-content/limitar-acceso-ia-contenido-sin-desaparecer-parte-3.toon): Resumen TOON del artículo.
- [TOON Listado](https://tu-dominio.com/ia-content/indice.toon): Índice compacto de artículos.
```

3. **Enllaça el TOON des de l'HTML**

```html
<link rel="alternate" type="text/plain" href="/ia-content/limitar-acceso-ia-contenido-sin-desaparecer-parte-3.toon">
```

4. **Ajusta `robots.txt`** per permetre als bots d'IA accedir a `/ia-content/` i limitar l'HTML complet (com a la Part 2).

Amb aquest flux ja tens una versió accessible per a bots **amb un cost de tokens molt baix** i sense canviar el contingut humà.

## Quant es pot reduir?

Depèn de la mida de l'article, però l'ordre de magnitud és clar: **passes de milers de tokens a desenes o pocs centenars**. És a dir, menys cost energètic, menys còmput i menys exposició del contingut complet.

Si vols mesurar-ho, usa qualsevol tokenitzador del teu model objectiu i compara l'HTML o l'article complet amb el TOON resumit. El salt és immediat.

### Eines per mesurar tokens

* **TOON Playground**: enganxa el teu JSON i compara tokens entre JSON i TOON en temps real. [TOON Playground](https://toonformat.dev/playground.html)
* **OpenAI Tokenizer**: eina oficial per comptar tokens en textos i prompts. [OpenAI Tokenizer](https://platform.openai.com/tokenizer)
* **Chase Adams Tokenization Playground**: compara tokens entre formats amb presets. [Format Tokenization Exploration](https://www.curiouslychase.com/playground/format-tokenization-exploration?mode=preset&size=small-simple&structure=uniform-flat)

## Límits i advertències

* **TOON no és un estàndard**: fes-lo servir com a format pràctic, no com a garantia d'adopció. A la documentació proposen utilitzar el MIME type `text/toon` (tot i que encara no està registrat oficialment a IANA) i l'extensió `.toon`.
* **Mentre no existeixi un estàndard comú**: és l'aproximació més raonable avui per reduir tokens sense perdre context.
* **Alternatives vàlides**: pots publicar també JSON, Markdown o text pla si encaixen millor amb el teu flux, encara que TOON ofereix la millor relació entre reducció de tokens i comprensió per part dels models (especialment en llistats estructurats).
* **Evita cloaking amb cercadors clàssics** si la teva prioritat és SEO (no serveixis contingut diferent a Googlebot llevat que ho controlis bé).

## Checklist ràpid

* [ ] Tinc un TOON per article a `/ia-content/`.
* [ ] El meu `llms.txt` apunta a aquests fitxers.
* [ ] El meu HTML enllaça el TOON amb `rel="alternate"`.
* [ ] El meu `robots.txt` separa entrenament vs cerca.
* [ ] El meu servidor web separa entrenament vs cerca.

> Si finalment no et preocupa el consum energètic però tens un servei en producció (sobretot si utilitza llistes d'objectes amb JSON), **fer servir TOON t'estalviarà diners**. I a qui sí ens preocupa l'impacte mediambiental, ens tindràs més contents.

## Referències i recursos

* Part 1: [Com limitar l'accés de la intel·ligència artificial al teu contingut sense desaparèixer de la web (Part 1 - Introducció)](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-1/)
* Part 2: [Com limitar l'accés de la intel·ligència artificial al teu contingut sense desaparèixer de la web (Part 2 - Estratègies tècniques)](/ca/posts/limitar-acces-ia-contingut-sense-desapareixer-part-2/)
* llms.txt (proposta): [https://llmstxt.org/](https://llmstxt.org/)
* ai-robots-txt (repositori): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)
* TOON (documentació oficial): [https://toonformat.dev/](https://toonformat.dev/)
* TOON Benchmarks (precisió i tokens): [https://toonformat.dev/guide/benchmarks](https://toonformat.dev/guide/benchmarks)
* TOON Playground (comparació JSON vs TOON): [https://toonformat.dev/playground.html](https://toonformat.dev/playground.html)
* OpenAI Tokenizer: [https://platform.openai.com/tokenizer](https://platform.openai.com/tokenizer)
* Chase Adams Tokenization Playground [Format Tokenization Exploration](https://www.curiouslychase.com/playground/format-tokenization-exploration?mode=preset&size=small-simple&structure=uniform-flat)
