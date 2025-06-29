import fs from 'fs';
import path from 'path';

// Script para corregir las rutas de imágenes en todos los archivos markdown
// Cambia ../../assets/images/ por ../assets/images/

function findAllMarkdownFiles(dir) {
  const files = [];
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      files.push(...findAllMarkdownFiles(fullPath));
    } else if (item.endsWith('.md')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

function fixImagePaths(filePath) {
  console.log(`🔍 Revisando: ${filePath}`);
  
  let content = fs.readFileSync(filePath, 'utf-8');
  let changes = 0;
  
  // Buscar y reemplazar rutas de imágenes incorrectas
  const originalContent = content;
  
  // Reemplazar ../../assets/images/ por ../assets/images/
  content = content.replace(/\.\.\/\.\.\//g, '../');
  
  // Contar cambios
  const matches = originalContent.match(/\.\.\/\.\.\//g);
  if (matches) {
    changes = matches.length;
  }
  
  if (changes > 0) {
    fs.writeFileSync(filePath, content);
    console.log(`✅ Corregido: ${path.basename(filePath)} - ${changes} rutas arregladas`);
  } else {
    console.log(`ℹ️  Sin cambios: ${path.basename(filePath)}`);
  }
  
  return changes;
}

// Ejecutar el script
console.log('🚀 Iniciando corrección de rutas de imágenes...\n');

const blogDir = 'src/content/blog';
const markdownFiles = findAllMarkdownFiles(blogDir);

console.log(`📁 Encontrados ${markdownFiles.length} archivos markdown\n`);

let totalChanges = 0;

for (const file of markdownFiles) {
  totalChanges += fixImagePaths(file);
}

console.log(`\n✨ Corrección completada:`);
console.log(`   - ${markdownFiles.length} archivos revisados`);
console.log(`   - ${totalChanges} rutas corregidas en total`);

if (totalChanges > 0) {
  console.log('\n🎉 ¡Todas las rutas de imágenes han sido corregidas!');
  console.log('   Ahora las imágenes deberían cargarse correctamente.');
} else {
  console.log('\n✅ No se encontraron rutas incorrectas.')
} 