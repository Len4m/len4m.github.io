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
  en: "en-US", // the `defaultLocale` value must present in `locales` keys
  es: "es-ES",
  ca: "ca-ES",
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
      [remarkToc, { heading: 'Table of contents|Tabla de contenido|Taula de continguts' }],
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
    optimizeDeps: {
      exclude: ["@resvg/resvg-js"],
    },
  },
  scopedStyleStrategy: "where",
});
