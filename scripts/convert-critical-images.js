import fs from 'fs';
import path from 'path';

// Script para convertir archivos específicos a MDX cuando necesites optimización máxima
// Uso: node scripts/convert-critical-images.js archivo1.md archivo2.md

const filesToConvert = process.argv.slice(2);

if (filesToConvert.length === 0) {
  console.log('Uso: node scripts/convert-critical-images.js archivo1.md archivo2.md');
  console.log('Ejemplo: node scripts/convert-critical-images.js debugme-writeup-dockerlabs.md');
  process.exit(1);
}

function convertToMdx(filePath) {
  const fullPath = path.join('src/content/blog', filePath);
  
  if (!fs.existsSync(fullPath)) {
    console.log(`❌ Archivo no encontrado: ${fullPath}`);
    return;
  }
  
  let content = fs.readFileSync(fullPath, 'utf-8');
  
  // Agregar imports de imágenes al inicio del archivo
  const imageImports = [];
  const imageReplacements = [];
  let imageCounter = 0;
  
  // Encontrar todas las imágenes
  const imageMatches = content.matchAll(/!\[([^\]]*)\]\(([^)]+)\)/g);
  
  for (const match of imageMatches) {
    const [fullMatch, alt, src] = match;
    
    if (src.startsWith('../../assets/images/')) {
      const imageName = `image${imageCounter++}`;
      const importPath = src.replace('../../', '../');
      
      imageImports.push(`import ${imageName} from '${importPath}';`);
      
      // Reemplazar con componente Image
      const imageComponent = `<Image src={${imageName}} alt="${alt}" loading="eager" decoding="async" />`;
      imageReplacements.push({ fullMatch, replacement: imageComponent });
    }
  }
  
  if (imageImports.length > 0) {
    // Agregar imports después del frontmatter
    const frontmatterEnd = content.indexOf('---', 3) + 3;
    const beforeContent = content.slice(0, frontmatterEnd);
    const afterContent = content.slice(frontmatterEnd);
    
    const importsSection = `
import { Image } from 'astro:assets';
${imageImports.join('\n')}
`;
    
    content = beforeContent + importsSection + afterContent;
    
    // Aplicar reemplazos de imágenes
    for (const { fullMatch, replacement } of imageReplacements) {
      content = content.replace(fullMatch, replacement);
    }
    
    // Cambiar extensión a .mdx
    const newPath = fullPath.replace('.md', '.mdx');
    fs.writeFileSync(newPath, content);
    
    // Eliminar archivo .md original
    fs.unlinkSync(fullPath);
    
    console.log(`✅ Convertido: ${filePath} → ${path.basename(newPath)}`);
    console.log(`   - ${imageImports.length} imágenes optimizadas`);
  } else {
    console.log(`ℹ️  No se encontraron imágenes para optimizar en: ${filePath}`);
  }
}

filesToConvert.forEach(convertToMdx);

console.log('\n✨ Conversión completada. Recuerda actualizar los enlaces en tu navegación si es necesario.'); 