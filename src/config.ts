import type { Site, SocialObjects } from "./types";


export const SITE: Site = {
  website: "https://len4m.github.io/",
  author: "Lenam",
  profile: "https://len4m.github.io/",
  desc: "Lenam's personal blog. Here you will find information about CTFs, hacking, programming, artificial intelligence, and technology in general.",
  title: "Lenam",
  ogImage: "assets/avatar.png",
  lightAndDarkMode: true,
  postPerIndex: 3,
  postPerPage: 4,
  scheduledPostMargin: 15 * 60 * 1000, // 15 minutes
};

export var LOCALE = {
  lang: "en", // html lang code. Set this empty and default will be "en"
  langTag: ["en-EN", "es-ES", "ca-ES"], // BCP 47 Language Tags. Set this empty [] to use the environment default
} ;

export const LOGO_IMAGE = {
  enable: false,
  svg: false,
  width: 34,
  height: 34,
}; 

export const SOCIALS: SocialObjects = [
  {
    name: "Github",
    href: "https://github.com/Len4m",
    linkTitle: ` ${SITE.title} on Github`,
    active: true,
  },
  {
    name: "LinkedIn",
    href: "",
    linkTitle: `${SITE.title} on LinkedIn`,
    active: false,
  },
  {
    name: "Mail",
    href: "mailto:lenamgenx@protonmail.com",
    linkTitle: `Send an email to ${SITE.title}`,
    active: true,
  },
  {
    name: "Twitch",
    href: "",
    linkTitle: `${SITE.title} on Twitch`,
    active: false,
  },
  {
    name: "Discord",
    href: "https://discordapp.com/channels/@me/1239384881180573707/",
    linkTitle: `${SITE.title} on Discord`,
    active: true,
  },
];
