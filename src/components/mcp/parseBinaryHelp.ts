import type { ParsedParameter } from './types';

/**
 * Parser mejorado para texto de ayuda de binarios
 * Basado en técnicas del parser de Fig (https://github.com/withfig/cli-help-parser)
 */
export function parseBinaryHelp(helpText: string): ParsedParameter[] {
  const parameters: ParsedParameter[] = [];
  
  // Limpiar texto de caracteres de control
  const cleanText = helpText.replace(/\b/g, ''); // Remover backspace characters
  
  // Regex principal inspirado en Fig parser
  // Maneja mejor los casos edge y formatos variados
  const mainPattern = /^\s+(?=-)(?:(-[a-zA-Z0-9])?,?\s?)?(--[a-zA-Z0-9_-]+)?(?:[=\s](?=[^\s]).*?\s)?\s+(.*?)(?=^\s+-|^[^\s]|$)/gms;
  
  // Regex para argumentos posicionales
  const positionalPattern = /^\s*([A-Z_]+)\s+(.*?)(?=^\s*[A-Z_]|$)/gms;
  
  // Regex para opciones con formato especial (ej: -f, --file=FILE)
  const specialFormatPattern = /^\s+(?:(-[a-zA-Z0-9])?,?\s?)?(--[a-zA-Z0-9_-]+(?:=[A-Z_]+)?)\s+(.*?)(?=^\s+-|^[^\s]|$)/gms;
  
  let match;
  
  // Procesar con el patrón principal
  while ((match = mainPattern.exec(cleanText)) !== null) {
    const [, shortFlag, longFlag, description] = match;
    
    if (shortFlag || longFlag) {
      const names = [shortFlag, longFlag].filter(Boolean);
      
      names.forEach(name => {
        if (name) {
          const param = createParameter(name, description, 'flag');
          if (!isDuplicate(parameters, param)) {
            parameters.push(param);
          }
        }
      });
    }
  }
  
  // Procesar argumentos posicionales
  while ((match = positionalPattern.exec(cleanText)) !== null) {
    const [, argName, description] = match;
    
    if (argName && !argName.match(/^(USAGE|SYNOPSIS|OPTIONS|ARGUMENTS|COMMANDS|EXAMPLES|SEE ALSO)$/i)) {
      const param = createParameter(argName, description, 'argument');
      if (!isDuplicate(parameters, param)) {
        parameters.push(param);
      }
    }
  }
  
  // Procesar formato especial
  while ((match = specialFormatPattern.exec(cleanText)) !== null) {
    const [, , longFlag, description] = match;
    
    if (longFlag && longFlag.includes('=')) {
      // Es una opción que toma valor
      const [flagName, argType] = longFlag.split('=');
      const param = createParameter(flagName, description, 'option');
      param.takesValue = true;
      param.expectsValue = true;
      param.defaultValue = argType;
      
      if (!isDuplicate(parameters, param)) {
        parameters.push(param);
      }
    }
  }
  
  // Post-procesamiento inteligente
  return postProcessParameters(parameters);
}

/**
 * Crea un parámetro con valores por defecto inteligentes
 */
function createParameter(name: string, description: string, type: 'flag' | 'option' | 'argument'): ParsedParameter {
  // Limpiar nombre
  const cleanName = name.replace(/[\[\]{}]/g, '');
  
  // Limpiar descripción
  const cleanDescription = description
    .replace(/\n\s+/gm, ' ') // Normalizar saltos de línea
    .replace(/^\s*[,;]\s*/, '') // Remover comas y puntos y coma al inicio
    .replace(/\s+/, ' ') // Normalizar espacios
    .trim();
  
  // Detectar si toma valor basado en patrones en la descripción
  const takesValue = detectTakesValue(cleanName, cleanDescription);
  const expectsValue = detectExpectsValue(cleanName, cleanDescription);
  const required = detectRequired(cleanName, cleanDescription);
  
  return {
    name: cleanName,
    description: cleanDescription,
    type,
    required,
    takesValue,
    expectsValue,
    position: undefined
  };
}

/**
 * Detecta si un parámetro toma valor basado en patrones
 */
function detectTakesValue(name: string, description: string): boolean {
  const valuePatterns = [
    /<[^>]+>/, // <FILE>, <DIR>, etc.
    /\[[^\]]+\]/, // [FILE], [DIR], etc.
    /=/, // --file=FILE
    /\b(file|path|dir|directory|url|port|host|user|password|key|value|name|id|number|count|time|date|format|type|mode|level|size|limit|timeout|retry|attempt|version|tag|branch|commit|hash|checksum|sum|md5|sha1|sha256)\b/i,
    /\b(required|mandatory|needed|specify|provide|give|enter|input|set|define|configure|specify)\b/i
  ];
  
  return valuePatterns.some(pattern => 
    pattern.test(name) || pattern.test(description)
  );
}

/**
 * Detecta si un parámetro espera valor
 */
function detectExpectsValue(name: string, description: string): boolean {
  const expectsPatterns = [
    /<[^>]+>/, // <FILE>
    /\[[^\]]+\]/, // [FILE]
    /=/, // --file=FILE
    /\b(file|path|dir|directory|url|port|host|user|password|key|value|name|id|number|count|time|date|format|type|mode|level|size|limit|timeout|retry|attempt|version|tag|branch|commit|hash|checksum|sum|md5|sha1|sha256)\b/i
  ];
  
  return expectsPatterns.some(pattern => 
    pattern.test(name) || pattern.test(description)
  );
}

/**
 * Detecta si un parámetro es requerido
 */
function detectRequired(name: string, description: string): boolean {
  const requiredPatterns = [
    /<[^>]+>/, // <FILE> (sin corchetes)
    /\b(required|mandatory|needed|must|essential|obligatory|compulsory)\b/i,
    /^[A-Z_]+$/, // Nombres en mayúsculas suelen ser requeridos
    /\b(positional|argument)\b/i
  ];
  
  const optionalPatterns = [
    /\[[^\]]+\]/, // [FILE] (con corchetes)
    /\b(optional|default|if not specified|when not given)\b/i,
    /^-[a-zA-Z0-9]$/, // Flags cortos suelen ser opcionales
    /^--[a-zA-Z0-9_-]+$/, // Flags largos suelen ser opcionales
    /\b(flag|switch|toggle)\b/i
  ];
  
  const isRequired = requiredPatterns.some(pattern => 
    pattern.test(name) || pattern.test(description)
  );
  
  const isOptional = optionalPatterns.some(pattern => 
    pattern.test(name) || pattern.test(description)
  );
  
  // Si hay conflicto, priorizar patrones de requerido
  return isRequired || (!isOptional && (name.match(/^[A-Z_]+$/) !== null));
}

/**
 * Verifica si un parámetro es duplicado
 */
function isDuplicate(parameters: ParsedParameter[], newParam: ParsedParameter): boolean {
  return parameters.some(param => param.name === newParam.name);
}

/**
 * Post-procesamiento inteligente de parámetros
 */
function postProcessParameters(parameters: ParsedParameter[]): ParsedParameter[] {
  return parameters
    .filter(param => param.name && param.description) // Remover parámetros vacíos
    .map(param => {
      // Mejorar detección de tipos
      if (param.name.startsWith('-') || param.name.startsWith('--')) {
        if (param.takesValue || param.expectsValue) {
          param.type = 'option';
        } else {
          param.type = 'flag';
        }
      } else {
        param.type = 'argument';
      }
      
      // Limpiar descripción final
      param.description = param.description
        .replace(/\([^)]*\)/g, '') // Remover paréntesis con contenido
        .replace(/\s+/, ' ') // Normalizar espacios
        .trim();
      
      return param;
    })
    .filter((param, index, self) => 
      index === self.findIndex(p => p.name === param.name)
    ); // Remover duplicados finales
} 