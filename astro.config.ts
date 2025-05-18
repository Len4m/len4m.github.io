import { defineConfig } from "astro/config";
import tailwind from "@astrojs/tailwind";
import react from "@astrojs/react";
import remarkToc from "remark-toc";
import remarkCollapse from "remark-collapse";
import sitemap from "@astrojs/sitemap";
import { i18n, filterSitemapByDefaultLocale } from "astro-i18n-aut/integration";
import { SITE } from "./src/config";

const defaultLocale = "en";
const locales = {
  en: "en", // the `defaultLocale` value must present in `locales` keys
  es: "es",
  ca: "ca",
};


// https://astro.build/config
export default defineConfig({
  site: SITE.website,
  trailingSlash: "always",
  build: {
    format: "directory",
  },
  integrations: [
    tailwind({
      applyBaseStyles: false,
    }),
    react(),
    i18n({
      locales,
      defaultLocale,
      redirectDefaultLocale: true,
      exclude: [
        "pages/posts/[slug]/index.astro",
        "pages/es/posts/[slug]/index.astro",
        "pages/ca/posts/[slug]/index.astro",

        "pages/tags/index.astro",
        "pages/ca/tags/index.astro",
        "pages/es/tags/index.astro",
        "pages/tags/[tag]/index.astro",
        "pages/tags/[tag]/[page].astro",
        "pages/es/tags/[tag]/index.astro",
        "pages/es/tags/[tag]/[page].astro",
        "pages/ca/tags/[tag]/index.astro",
        "pages/ca/tags/[tag]/[page].astro",

        "pages/**/*.md",
        "pages/*.md",
        "pages/**/*.ts",
        "pages/*.ts",
      ]
    }),
    sitemap({
      i18n: {
        locales,
        defaultLocale,
      },
      filter: filterSitemapByDefaultLocale({ defaultLocale }),
    }),
  ],
  markdown: {

    remarkPlugins: [
      [remarkToc, { 
        heading: 'Table of contents|Tabla de contenido|Taula de continguts'
       }],
      [remarkCollapse, {
        summary: function (tit: string) {
          switch (tit) {
            case 'Tabla de contenido':
              return `Abrir ${tit.toLowerCase()}`;
            case 'Taula de continguts':
              return `Obrir ${tit.toLowerCase()}`;
            default:
              return `Open ${tit.toLowerCase()}`;
          }
        },
        test: "Table of contents|Tabla de contenido|Taula de continguts"
      }],
    ],
    shikiConfig: {
      theme: "one-dark-pro",
      wrap: true,
    },
  },
  vite: {
    build: {
      minify: 'terser',
      terserOptions: {
        format: {
          comments: /@preserve|^!/  // Preserva los comentarios con @preserve o /*! */
        },
      },
    },
    optimizeDeps: {
      exclude: ["@resvg/resvg-js"],
    },
  },
  scopedStyleStrategy: "where",
});