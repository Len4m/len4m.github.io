import { slug as slugger } from "github-slugger";

const normalizeString = (str: string): string => {
  return str.normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // Elimina diacríticos
    .toLowerCase()
    .trim();
};

export const slugifyStr = (str: string) => {
  const normalized = normalizeString(str);
  return slugger(normalized);
};

export const slugifyAll = (arr: string[]) => arr.map(str => slugifyStr(str));
