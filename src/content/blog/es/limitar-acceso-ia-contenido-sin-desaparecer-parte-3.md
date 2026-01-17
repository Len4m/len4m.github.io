---
author: Lenam
pubDatetime: 2026-01-18T00:00:00Z
title: "Cómo limitar el acceso de la inteligencia artificial a tu contenido sin desaparecer de la web (Parte 3 - Más reducción de tokens)"
urlSlug: limitar-acceso-ia-contenido-sin-desaparecer-parte-3
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
  "Cómo adaptar el contenido alternativo para reducir tokens usando TOON y otras técnicas."
lang: es
translationId: limitar-acceso-ia-contenido-sin-desaparecer-parte-3
---

![reducir tokens](../../../assets/images/limitar-acceso-ia-contenido-sin-desaparecer/OpenGraph3.png)

*TOON, resúmenes compactos y un patrón práctico para publicar ya sin regalar tokens.*

**Serie:**
- [Parte 1: Introducción](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-1/)
- [Parte 2: Estrategias técnicas](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-2/)
- **Parte 3: Más reducción de tokens**

## Tabla de contenido

## De la Parte 2 a la Parte 3

En la [Parte 2](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-2/) vimos cómo bloquear, permitir y servir contenido alternativo a bots. Aquí cierro la serie con una pregunta concreta: **si ya voy a mostrar un resumen a la IA, ¿cómo lo hago de forma que consuma los mínimos tokens posibles sin perder contexto?**

Este artículo propone un formato simple (TOON) y un flujo de publicación que puedes aplicar hoy mismo.

## El objetivo: menos tokens, mismo contexto

No buscamos ocultar todo: buscamos **optimizar qué ve la IA**. El objetivo es que un bot pueda:

* entender de qué va el artículo,
* enlazarlo correctamente,
* y evitar ingerir el texto completo.

Eso implica **resúmenes muy compactos** y una estructura pensada para reducir tokens.

## Qué es TOON (Token-Oriented Object Notation)

**TOON** es un formato compacto y legible que **codifica el modelo de datos JSON** para prompts de LLM, con el objetivo de reducir tokens sin perder estructura. La documentación oficial lo define como una representación “compacta y legible” del modelo JSON para prompts. [TOON: Token-Oriented Object Notation](https://toonformat.dev/)

Aunque TOON no se diseñó específicamente para **compartir contenido en internet**, sí fue pensado para **reducir tokens** y **mejorar la comprensión por parte de los modelos**. Por eso es ideal para publicar contenidos que consumirán máquinas.

Además, hay **benchmarks públicos** que miden comprensión y recuperación de datos: TOON alcanza un **73,9% de precisión** frente a **69,7% en JSON** y usa **un 39,6% menos de tokens** en los datasets probados. [Benchmarks de TOON](https://toonformat.dev/guide/benchmarks)

Piensa en TOON como un equivalente ultra-resumido de tu artículo: **título, URL canónica, resumen mínimo, puntos clave y etiquetas**. Todo lo demás sobra.

### Principios de diseño TOON

* **Campos cortos y estables**: claves breves, valores compactos.
* **Nada de prosa larga**: el resumen es máximo 1-2 líneas.
* **Sin duplicidad**: evita repetir lo mismo con otras palabras.
* **Sin relleno**: adjetivos y contexto superfluo fuera.
* **Canónico siempre**: un enlace claro a la URL completa.

### Plantilla TOON mínima (ejemplo)

Los campos TOON recomendados están diseñados para ser fácilmente comprensibles por los modelos de lenguaje, pero al no ser un estándar cerrado, puedes incluir cualquier campo o estructura que necesites para describir tu contenido: `author`, `modified`, `title`, `category` o cualquier otra clave o estructura de datos TOON que tenga sentido en tu caso.

Ejemplo realista para un artículo:

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

#### Nombres de campos (por qué estos y no otros)

* `ver`: más claro que `v`, más corto que `version`.
* `type`: universal en datasets.
* `lang`: estándar reconocido por LLMs.
* `url`: universal y esperado.
* `use`: semántica directa.
* `sum`: muy común en datasets.
* `k`: abreviatura ampliamente usada.
* `ent`: estándar informal para entidades.

Mínimo viable real:

* `type`: contexto inmediato del contenido.
* `lang`: interpretación lingüística correcta.
* `url`: fuente canónica para citación.
* `sum`: respuesta inmediata sin inferencia.

Con estos 4 campos, un LLM puede **responder, resumir y citar**.

#### Campo `use` (núcleo ético-técnico)

Es una **propuesta sin efecto vinculante**: el bot puede ignorarla, pero también podría usarla en un futuro para entender el contexto y respetar tus preferencias.

Formato compacto:

```yaml
use: index=1,cite=1,train=0,derive=0
```

Interpretación natural para cualquier LLM:

* `index=1`: se puede indexar.
* `cite=1`: se puede citar con enlace.
* `train=0`: no entrenar.
* `derive=0`: no persistir derivados.

### TOON para un artículo vs TOON para listados

Un **TOON de artículo** es útil para explicar un contenido concreto con el mínimo de tokens. Un **TOON de listado** (por ejemplo, últimos artículos, guías o productos) es aún más valioso porque **ahorras tokens en bloque**: compartes campos una sola vez y reduces mucha repetición.

En listados, TOON brilla por el patrón **tabular**: declaras los campos una vez y luego solo envías filas. Eso baja muchísimo el coste cuando hay 10, 50 o 200 entradas.

**Ejemplo: listado compacto de artículos**

```yaml
toon: 1
list: articles
articles[3]{id,url,tit,summary,updated}:
  parte-1,/blog/limitar-acceso-ia-contenido-sin-desaparecer-parte-1,Intro,Ideas base y contexto,2026-01-10
  parte-2,/blog/limitar-acceso-ia-contenido-sin-desaparecer-parte-2,Estrategias,Control técnico para bots,2026-01-14
  parte-3,/blog/limitar-acceso-ia-contenido-sin-desaparecer-parte-3,TOON,Más reducción de tokens,2026-01-18
```

Si publicas un feed o un índice de contenidos, un TOON de listado **reduce tokens de forma mucho más agresiva** que uno por artículo.

## Técnicas adicionales de reducción de tokens

TOON es el contenedor. Estas técnicas ayudan a **compactar el contenido**:

* **Resumen jerárquico**: un titular + 3 puntos clave.
* **Listas en vez de párrafos**: menos tokens y más densidad informativa.
* **Entidades y conceptos clave**: nombra lo esencial (tecnologías, normas, riesgos).
* **Eliminar redundancias**: no repitas la misma idea con sinónimos.
* **Cero citas largas**: enlaza a la fuente en lugar de copiar.

## Propuesta práctica para que funcione hoy

Esto **funciona hoy de forma segura** y sería muy positivo seguir trabajando en esta dirección, creando **formatos y propuestas estandarizadas** para la compartición de información hacia máquinas, con el objetivo claro de **reducir el consumo energético** y la cantidad de **tokens** necesarios.


Este es un flujo **mínimo viable** y realista:

1. **Crea un fichero TOON por artículo**
   - Ruta sugerida: `/ia-content/slug.toon`
   - Formato: texto plano

2. **Añádelo a tu `llms.txt`**

```markdown
# /llms.txt (ejemplo, formato Markdown)
# Mi sitio
> Contenido técnico con alternativas compactas para IA.

Aquí publico TOONs por artículo y listados compactos para IA.

## Contenido alternativo
- [TOON Parte 3](https://tu-dominio.com/ia-content/limitar-acceso-ia-contenido-sin-desaparecer-parte-3.toon): Resumen TOON del artículo.
- [TOON Listado](https://tu-dominio.com/ia-content/indice.toon): Índice compacto de artículos.
```

3. **Enlaza el TOON desde el HTML**

```html
<link rel="alternate" type="text/plain" href="/ia-content/limitar-acceso-ia-contenido-sin-desaparecer-parte-3.toon">
```

4. **Ajusta `robots.txt`** para permitir a bots de IA acceder a `/ia-content/` y limitar el HTML completo (como en la Parte 2).

Con este flujo ya tienes una versión accesible para bots **con un coste de tokens muy bajo** y sin cambiar el contenido humano.

## ¿Cuánto se puede reducir?

Depende del tamaño del artículo, pero el orden de magnitud es claro: **pasas de miles de tokens a decenas o pocos cientos**. Es decir, menos coste energético, menos cómputo y menos exposición del contenido completo.

Si quieres medirlo, usa cualquier tokenizador de tu modelo objetivo y compara el HTML o el artículo completo frente al TOON resumido. El salto es inmediato.

### Herramientas para medir tokens

* **TOON Playground**: pega tu JSON y compara tokens entre JSON y TOON en tiempo real. [TOON Playground](https://toonformat.dev/playground.html)
* **OpenAI Tokenizer**: herramienta oficial para contar tokens en textos y prompts. [OpenAI Tokenizer](https://platform.openai.com/tokenizer)
* **Chase Adams Tokenization Playground**: compara tokens entre formatos con presets. [Format Tokenization Exploration](https://www.curiouslychase.com/playground/format-tokenization-exploration?mode=preset&size=small-simple&structure=uniform-flat)

## Límites y advertencias

* **TOON no es un estándar**: úsalo como formato práctico, no como garantía de adopción. En la documentación proponen utilizar el MIME type `text/toon` (aunque aún no está registrado oficialmente en IANA) y la extensión `.toon`.
* **Mientras no exista un estándar común**: es la aproximación más razonable hoy para reducir tokens sin perder contexto.
* **Alternativas válidas**: puedes publicar también JSON, Markdown o texto plano si encajan mejor con tu flujo, aunque TOON ofrece la mejor relación entre reducción de tokens y comprensión por parte de los modelos (especialmente en listados estructurados).
* **Evita cloaking con buscadores clásicos** si tu prioridad es SEO (no sirvas contenido distinto a Googlebot salvo que lo controles bien).

## Checklist rápido

* [ ] Tengo un TOON por artículo en `/ia-content/`.
* [ ] Mi `llms.txt` apunta a esos archivos.
* [ ] Mi HTML enlaza el TOON con `rel="alternate"`.
* [ ] Mi `robots.txt` separa entrenamiento vs búsqueda.
* [ ] Mi servidor web separa entrenamiento vs búsqueda.

> Si finalmente no te preocupa el consumo energético pero tienes un servicio en producción (sobre todo si utiliza listas de objetos con JSON), **usar TOON te ahorrará dinero**. Y a quienes sí nos preocupa el impacto medioambiental, nos tendrás más contentos.

## Referencias y recursos

* Parte 1: [Cómo limitar el acceso de la inteligencia artificial a tu contenido sin desaparecer de la web (Parte 1 - Introducción)](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-1/)
* Parte 2: [Cómo limitar el acceso de la inteligencia artificial a tu contenido sin desaparecer de la web (Parte 2 - Estrategias técnicas)](/es/posts/limitar-acceso-ia-contenido-sin-desaparecer-parte-2/)
* llms.txt (propuesta): [https://llmstxt.org/](https://llmstxt.org/)
* ai-robots-txt (repositorio): [https://github.com/ai-robots-txt/ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)
* TOON (documentación oficial): [https://toonformat.dev/](https://toonformat.dev/)
* TOON Benchmarks (precisión y tokens): [https://toonformat.dev/guide/benchmarks](https://toonformat.dev/guide/benchmarks)
* TOON Playground (comparación JSON vs TOON): [https://toonformat.dev/playground.html](https://toonformat.dev/playground.html)
* OpenAI Tokenizer: [https://platform.openai.com/tokenizer](https://platform.openai.com/tokenizer)
* Chase Adams Tokenization Playground [Format Tokenization Exploration](https://www.curiouslychase.com/playground/format-tokenization-exploration?mode=preset&size=small-simple&structure=uniform-flat)