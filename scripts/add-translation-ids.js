import { readFileSync, writeFileSync, readdirSync, statSync } from 'fs';
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

// Group files by base name (without language prefix)
const postsByBaseName = {};

files.forEach(fullPath => {
  const content = readFileSync(fullPath, 'utf-8');
  const relativePath = fullPath.replace(blogDir + '/', '');
  
  // Extract base name (remove es/ or ca/ prefix and .md extension)
  let baseName = relativePath.replace(/^(es|ca)\//, '').replace(/\.md$/, '');
  
  if (!postsByBaseName[baseName]) {
    postsByBaseName[baseName] = [];
  }
  
  postsByBaseName[baseName].push({
    path: fullPath,
    file: relativePath,
    content,
    baseName
  });
});

// Process posts that have multiple language versions
let updated = 0;

Object.entries(postsByBaseName).forEach(([baseName, posts]) => {
  if (posts.length > 1) {
    // This post has multiple language versions
    const translationId = baseName;
    
    posts.forEach(({ path, content }) => {
      // Check if translationId already exists
      if (content.includes('translationId:')) {
        return; // Skip if already has translationId
      }
      
      // Find the lang field to insert translationId after it
      const langMatch = content.match(/^lang:\s*([^\n]+)/m);
      
      if (langMatch) {
        const langLine = langMatch[0];
        const newContent = content.replace(
          langLine,
          `${langLine}\ntranslationId: ${translationId}`
        );
        
        writeFileSync(path, newContent, 'utf-8');
        updated++;
        console.log(`✓ Updated: ${path.replace(blogDir + '/', '')}`);
      }
    });
  }
});

console.log(`\n✅ Updated ${updated} files with translationId`);

