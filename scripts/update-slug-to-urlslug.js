import { readFileSync, writeFileSync } from 'fs';
import { readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const blogDir = join(__dirname, '../src/content/blog');

// Recursively get all markdown files
function getAllMdFiles(dir, fileList = []) {
  const files = readdirSync(dir);
  files.forEach(file => {
    const filePath = join(dir, file);
    if (statSync(filePath).isDirectory()) {
      getAllMdFiles(filePath, fileList);
    } else if (file.endsWith('.md')) {
      fileList.push(filePath);
    }
  });
  return fileList;
}

const files = getAllMdFiles(blogDir);
let updated = 0;

files.forEach(filePath => {
  const content = readFileSync(filePath, 'utf-8');
  
  // Check if file has slug: in frontmatter
  if (content.includes('\nslug:')) {
    // Replace slug: with urlSlug:
    const newContent = content.replace(/^slug:/m, 'urlSlug:');
    writeFileSync(filePath, newContent, 'utf-8');
    updated++;
    console.log(`✓ Updated: ${filePath.replace(blogDir + '/', '')}`);
  }
});

console.log(`\n✅ Updated ${updated} files from slug: to urlSlug:`);



