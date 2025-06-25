const fs = require('fs');
const path = require('path');

// Leer el archivo de traducciones
const translationsPath = path.join(__dirname, 'src/components/mcp/translations.ts');
const translationsContent = fs.readFileSync(translationsPath, 'utf8');

// Extraer todas las claves de traducción del tipo Translations
const translationKeys = [];
const regex = /(\w+):\s*"[^"]*"/g;
let match;
while ((match = regex.exec(translationsContent)) !== null) {
  translationKeys.push(match[1]);
}

console.log(`Total de claves de traducción encontradas: ${translationKeys.length}`);

// Buscar archivos TypeScript/TSX que usan traducciones
const searchDirs = [
  'src/components/mcp',
  'src/components'
];

const usedTranslations = new Set();
const unusedTranslations = new Set(translationKeys);

// Función para buscar traducciones en un archivo
function searchTranslationsInFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    
    // Buscar patrones más específicos de traducciones
    const patterns = [
      /t\.(\w+)/g,  // t.nombre
      /\{t\.(\w+)\}/g,  // {t.nombre}
      /t\[(\w+)\]/g,  // t['nombre']
    ];
    
    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const key = match[1];
        // Filtrar palabras que no parecen ser traducciones
        if (!isLikelyNotTranslation(key)) {
          usedTranslations.add(key);
          unusedTranslations.delete(key);
        }
      }
    });
  } catch (error) {
    console.error(`Error leyendo ${filePath}:`, error.message);
  }
}

// Función para filtrar palabras que probablemente no son traducciones
function isLikelyNotTranslation(key) {
  const notTranslations = [
    // Tipos de React/TypeScript
    'FC', 'FormEvent', 'ChangeEvent', 'HTMLInputElement', 'HTMLTextAreaElement',
    // Métodos de JavaScript
    'createElement', 'getElementById', 'querySelectorAll', 'replace', 'split', 'trim',
    'style', 'value', 'checked', 'body', 'head', 'documentElement',
    // Otros
    'py', 'label', 'title', 'placeholder'
  ];
  
  return notTranslations.includes(key) || 
         key.length < 3 || 
         /^[A-Z]/.test(key) || // Empieza con mayúscula (probablemente un tipo)
         /[A-Z]{2,}/.test(key); // Contiene múltiples mayúsculas consecutivas
}

// Buscar en todos los archivos
searchDirs.forEach(dir => {
  if (fs.existsSync(dir)) {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
      if (file.endsWith('.tsx') || file.endsWith('.ts')) {
        const filePath = path.join(dir, file);
        searchTranslationsInFile(filePath);
      }
    });
  }
});

// Buscar también en McpCreator.tsx
searchTranslationsInFile('src/components/McpCreator.tsx');

console.log('\n=== TRADUCCIONES UTILIZADAS ===');
console.log(`Total utilizadas: ${usedTranslations.size}`);
Array.from(usedTranslations).sort().forEach(key => {
  console.log(`✅ ${key}`);
});

console.log('\n=== TRADUCCIONES NO UTILIZADAS ===');
console.log(`Total no utilizadas: ${unusedTranslations.size}`);
Array.from(unusedTranslations).sort().forEach(key => {
  console.log(`❌ ${key}`);
});

// Verificar si hay traducciones que se usan pero no están definidas
const definedTranslations = new Set(translationKeys);
const missingTranslations = [];

// Buscar todas las referencias t.xxx en el código
const allFiles = [];
searchDirs.forEach(dir => {
  if (fs.existsSync(dir)) {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
      if (file.endsWith('.tsx') || file.endsWith('.ts')) {
        allFiles.push(path.join(dir, file));
      }
    });
  }
});
allFiles.push('src/components/McpCreator.tsx');

allFiles.forEach(filePath => {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const tRegex = /t\.(\w+)/g;
    let match;
    while ((match = tRegex.exec(content)) !== null) {
      const key = match[1];
      if (!definedTranslations.has(key) && !missingTranslations.includes(key) && !isLikelyNotTranslation(key)) {
        missingTranslations.push(key);
      }
    }
  } catch (error) {
    // Ignorar errores de archivos que no existen
  }
});

if (missingTranslations.length > 0) {
  console.log('\n=== TRADUCCIONES FALTANTES (se usan pero no están definidas) ===');
  missingTranslations.sort().forEach(key => {
    console.log(`⚠️  ${key}`);
  });
}

console.log('\n=== RESUMEN ===');
console.log(`✅ Utilizadas: ${usedTranslations.size}`);
console.log(`❌ No utilizadas: ${unusedTranslations.size}`);
console.log(`⚠️  Faltantes: ${missingTranslations.length}`);
console.log(`📊 Total definidas: ${translationKeys.length}`); 