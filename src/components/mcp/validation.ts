// Patrones de validación para nombres seguros
export const VALIDATION_PATTERNS = {
  // Nombres de binarios: letras, números, guiones, guiones bajos y puntos
  // No puede empezar con guión, no puede tener espacios ni caracteres especiales
  binaryName: /^[a-zA-Z][a-zA-Z0-9._-]*$/,
  
  // Nombres de servidores: similar a binarios pero puede incluir puntos para subdominios
  // Formato: nombre-servidor o nombre.servidor
  serverName: /^[a-zA-Z][a-zA-Z0-9._-]*$/,
  
  // Versiones: formato semver básico (x.y.z)
  version: /^[0-9]+\.[0-9]+\.[0-9]+$/
};

// Longitudes máximas permitidas
export const MAX_LENGTHS = {
  binaryName: 50,
  serverName: 63,
  description: 200,
  version: 20
};

// Caracteres prohibidos que podrían causar problemas de seguridad
export const FORBIDDEN_CHARS = {
  binaryName: /[<>:"|?*\x00-\x1f]/g,
  serverName: /[<>:"|?*\x00-\x1f]/g
};

// Comandos peligrosos del sistema
const DANGEROUS_COMMANDS = [
  'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd', 'shred', 'wipe',
  'sudo', 'su', 'chmod', 'chown', 'passwd', 'useradd', 'userdel',
  'kill', 'killall', 'pkill', 'systemctl', 'service', 'init',
  'halt', 'reboot', 'shutdown', 'poweroff', 'exec', 'eval'
];

// Palabras reservadas para nombres de servidores
const RESERVED_WORDS = [
  'admin', 'root', 'system', 'internal', 'private', 'secret',
  'password', 'token', 'key', 'auth', 'login', 'session'
];

// Traducciones de mensajes de error
const ERROR_MESSAGES = {
  en: {
    binaryNameEmpty: 'Binary name cannot be empty',
    binaryNameTooLong: (max: number) => `Binary name cannot exceed ${max} characters`,
    binaryNameForbiddenChars: 'Binary name contains forbidden characters',
    binaryNameInvalidFormat: 'Binary name must start with a letter and can only contain letters, numbers, dots, hyphens and underscores',
    binaryNameDangerousCommand: 'System commands are not allowed for security reasons',
    serverNameEmpty: 'Server name cannot be empty',
    serverNameTooLong: (max: number) => `Server name cannot exceed ${max} characters`,
    serverNameForbiddenChars: 'Server name contains forbidden characters',
    serverNameInvalidFormat: 'Server name must start with a letter and can only contain letters, numbers, dots, hyphens and underscores',
    serverNameReservedWord: (word: string) => `Server name cannot contain reserved words like "${word}"`,
    versionEmpty: 'Version cannot be empty',
    versionTooLong: (max: number) => `Version cannot exceed ${max} characters`,
    versionInvalidFormat: 'Version must follow the format x.y.z (e.g., 1.0.0)'
  },
  es: {
    binaryNameEmpty: 'El nombre del binario no puede estar vacío',
    binaryNameTooLong: (max: number) => `El nombre del binario no puede exceder ${max} caracteres`,
    binaryNameForbiddenChars: 'El nombre del binario contiene caracteres no permitidos',
    binaryNameInvalidFormat: 'El nombre del binario debe empezar con una letra y solo puede contener letras, números, puntos, guiones y guiones bajos',
    binaryNameDangerousCommand: 'No se permiten comandos del sistema por seguridad',
    serverNameEmpty: 'El nombre del servidor no puede estar vacío',
    serverNameTooLong: (max: number) => `El nombre del servidor no puede exceder ${max} caracteres`,
    serverNameForbiddenChars: 'El nombre del servidor contiene caracteres no permitidos',
    serverNameInvalidFormat: 'El nombre del servidor debe empezar con una letra y solo puede contener letras, números, puntos, guiones y guiones bajos',
    serverNameReservedWord: (word: string) => `El nombre del servidor no puede contener palabras reservadas como "${word}"`,
    versionEmpty: 'La versión no puede estar vacía',
    versionTooLong: (max: number) => `La versión no puede exceder ${max} caracteres`,
    versionInvalidFormat: 'La versión debe seguir el formato x.y.z (ej: 1.0.0)'
  },
  ca: {
    binaryNameEmpty: 'El nom del binari no pot estar buit',
    binaryNameTooLong: (max: number) => `El nom del binari no pot excedir ${max} caràcters`,
    binaryNameForbiddenChars: 'El nom del binari conté caràcters no permesos',
    binaryNameInvalidFormat: 'El nom del binari ha de començar amb una lletra i només pot contenir lletres, números, punts, guions i guions baixos',
    binaryNameDangerousCommand: 'No es permeten comandaments del sistema per seguretat',
    serverNameEmpty: 'El nom del servidor no pot estar buit',
    serverNameTooLong: (max: number) => `El nom del servidor no pot excedir ${max} caràcters`,
    serverNameForbiddenChars: 'El nom del servidor conté caràcters no permesos',
    serverNameInvalidFormat: 'El nom del servidor ha de començar amb una lletra i només pot contenir lletres, números, punts, guions i guions baixos',
    serverNameReservedWord: (word: string) => `El nom del servidor no pot contenir paraules reservades com "${word}"`,
    versionEmpty: 'La versió no pot estar buida',
    versionTooLong: (max: number) => `La versió no pot excedir ${max} caràcters`,
    versionInvalidFormat: 'La versió ha de seguir el format x.y.z (ex: 1.0.0)'
  }
};

// Función para validar nombre de binario
export function validateBinaryName(
  name: string, 
  lang: 'en' | 'es' | 'ca' = 'en',
  securityEnabled: boolean = false
): { isValid: boolean; error?: string } {
  const messages = ERROR_MESSAGES[lang];
  
  if (!name.trim()) {
    return { isValid: false, error: messages.binaryNameEmpty };
  }
  
  if (name.length > MAX_LENGTHS.binaryName) {
    return { 
      isValid: false, 
      error: messages.binaryNameTooLong(MAX_LENGTHS.binaryName)
    };
  }
  
  if (FORBIDDEN_CHARS.binaryName.test(name)) {
    return { 
      isValid: false, 
      error: messages.binaryNameForbiddenChars
    };
  }
  
  if (!VALIDATION_PATTERNS.binaryName.test(name)) {
    return { 
      isValid: false, 
      error: messages.binaryNameInvalidFormat
    };
  }
  
  // Verificar que no sea un comando peligroso solo si la seguridad está habilitada
  if (securityEnabled && DANGEROUS_COMMANDS.includes(name.toLowerCase())) {
    return { 
      isValid: false, 
      error: messages.binaryNameDangerousCommand
    };
  }
  
  return { isValid: true };
}

// Función para validar nombre de servidor
export function validateServerName(
  name: string, 
  lang: 'en' | 'es' | 'ca' = 'en',
  securityEnabled: boolean = false
): { isValid: boolean; error?: string } {
  const messages = ERROR_MESSAGES[lang];
  
  if (!name.trim()) {
    return { isValid: false, error: messages.serverNameEmpty };
  }
  
  if (name.length > MAX_LENGTHS.serverName) {
    return { 
      isValid: false, 
      error: messages.serverNameTooLong(MAX_LENGTHS.serverName)
    };
  }
  
  if (FORBIDDEN_CHARS.serverName.test(name)) {
    return { 
      isValid: false, 
      error: messages.serverNameForbiddenChars
    };
  }
  
  if (!VALIDATION_PATTERNS.serverName.test(name)) {
    return { 
      isValid: false, 
      error: messages.serverNameInvalidFormat
    };
  }
  
  // Verificar que no contenga secuencias peligrosas solo si la seguridad está habilitada
  if (securityEnabled) {
    const lowerName = name.toLowerCase();
    for (const pattern of RESERVED_WORDS) {
      if (lowerName.includes(pattern)) {
        return { 
          isValid: false, 
          error: messages.serverNameReservedWord(pattern)
        };
      }
    }
  }
  
  return { isValid: true };
}

// Función para validar versión
export function validateVersion(version: string, lang: 'en' | 'es' | 'ca' = 'en'): { isValid: boolean; error?: string } {
  const messages = ERROR_MESSAGES[lang];
  
  if (!version.trim()) {
    return { isValid: false, error: messages.versionEmpty };
  }
  
  if (version.length > MAX_LENGTHS.version) {
    return { 
      isValid: false, 
      error: messages.versionTooLong(MAX_LENGTHS.version)
    };
  }
  
  if (!VALIDATION_PATTERNS.version.test(version)) {
    return { 
      isValid: false, 
      error: messages.versionInvalidFormat
    };
  }
  
  return { isValid: true };
}

// Función para sanitizar entrada (remover caracteres peligrosos)
export function sanitizeInput(input: string, type: 'binaryName' | 'serverName'): string {
  let sanitized = input.trim();
  
  // Remover caracteres prohibidos
  sanitized = sanitized.replace(FORBIDDEN_CHARS[type], '');
  
  // Asegurar que empiece con letra
  if (sanitized && !/^[a-zA-Z]/.test(sanitized)) {
    sanitized = 'a' + sanitized;
  }
  
  // Limitar longitud
  const maxLength = type === 'binaryName' ? MAX_LENGTHS.binaryName : MAX_LENGTHS.serverName;
  if (sanitized.length > maxLength) {
    sanitized = sanitized.substring(0, maxLength);
  }
  
  return sanitized;
} 