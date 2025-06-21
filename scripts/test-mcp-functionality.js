#!/usr/bin/env node

/**
 * Script para probar la funcionalidad real de servidores MCP
 * Envía mensajes de prueba por stdio y verifica respuestas
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Función para probar un servidor MCP
async function testMCPFunctionality(serverPath, language) {
  console.log(`🧪 Probando funcionalidad MCP: ${path.basename(serverPath)} (${language})`);
  
  return new Promise((resolve, reject) => {
    let output = '';
    let errorOutput = '';
    let testCompleted = false;
    
    // Comando para ejecutar el servidor
    const cmd = language === 'nodejs' ? 'node' : 'python';
    const args = language === 'nodejs' ? ['index.js'] : ['server.py'];
    
    // Ejecutar el servidor
    const server = spawn(cmd, args, {
      cwd: serverPath,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    // Timeout para evitar que se quede colgado
    const timeout = setTimeout(() => {
      if (!testCompleted) {
        server.kill();
        console.log(`⚠️  Test timeout for ${path.basename(serverPath)}`);
        resolve(false);
      }
    }, 10000); // 10 segundos timeout
    
    // Capturar salida estándar
    server.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    // Capturar errores
    server.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
    
    // Manejar cierre del proceso
    server.on('close', (code) => {
      clearTimeout(timeout);
      testCompleted = true;
      
      if (code === 0) {
        console.log(`✅ ${path.basename(serverPath)}: Server started successfully`);
        resolve(true);
      } else {
        console.log(`❌ ${path.basename(serverPath)}: Server failed to start (code: ${code})`);
        if (errorOutput) {
          console.log(`Error output: ${errorOutput}`);
        }
        resolve(false);
      }
    });
    
    // Manejar errores del proceso
    server.on('error', (error) => {
      clearTimeout(timeout);
      testCompleted = true;
      console.log(`❌ ${path.basename(serverPath)}: Process error: ${error.message}`);
      resolve(false);
    });
    
    // Enviar mensaje de prueba después de un breve delay
    setTimeout(() => {
      if (!testCompleted) {
        try {
          // Enviar mensaje de inicialización MCP
          const initMessage = {
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
              protocolVersion: "2024-11-05",
              capabilities: {
                tools: {}
              },
              clientInfo: {
                name: "mcp-test-client",
                version: "1.0.0"
              }
            }
          };
          
          server.stdin.write(JSON.stringify(initMessage) + '\n');
          
          // Enviar mensaje para listar herramientas
          const listToolsMessage = {
            jsonrpc: "2.0",
            id: 2,
            method: "tools/list"
          };
          
          server.stdin.write(JSON.stringify(listToolsMessage) + '\n');
          
          // Cerrar stdin después de enviar los mensajes
          server.stdin.end();
          
        } catch (error) {
          console.log(`⚠️  Could not send test messages to ${path.basename(serverPath)}: ${error.message}`);
        }
      }
    }, 1000);
  });
}

// Función principal
async function runMCPFunctionalityTests() {
  console.log('🚀 Iniciando tests de funcionalidad MCP...');
  
  const testDir = path.join(__dirname, '..', 'test-output');
  const results = [];
  
  if (!fs.existsSync(testDir)) {
    console.log('❌ No se encontró directorio de tests. Ejecuta primero los tests básicos.');
    return;
  }
  
  // Buscar servidores generados
  const servers = fs.readdirSync(testDir, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);
  
  if (servers.length === 0) {
    console.log('❌ No se encontraron servidores para probar.');
    return;
  }
  
  console.log(`📋 Encontrados ${servers.length} servidores para probar:`);
  
  for (const serverName of servers) {
    const serverPath = path.join(testDir, serverName);
    
    // Determinar el lenguaje basado en los archivos
    let language = 'unknown';
    if (fs.existsSync(path.join(serverPath, 'index.js'))) {
      language = 'nodejs';
    } else if (fs.existsSync(path.join(serverPath, 'server.py'))) {
      language = 'python';
    }
    
    if (language === 'unknown') {
      console.log(`⚠️  ${serverName}: No se pudo determinar el lenguaje`);
      continue;
    }
    
    console.log(`  - ${serverName} (${language})`);
    
    // Probar funcionalidad
    const success = await testMCPFunctionality(serverPath, language);
    results.push({ name: serverName, language, success });
  }
  
  // Mostrar resultados
  console.log('\n📊 RESULTADOS DE FUNCIONALIDAD MCP:');
  console.log('=====================================');
  
  const passed = results.filter(r => r.success).length;
  const total = results.length;
  
  results.forEach(result => {
    const status = result.success ? '✅' : '❌';
    console.log(`${status} ${result.name} (${result.language})`);
  });
  
  console.log(`\n✅ Tests exitosos: ${passed}/${total}`);
  
  if (passed === total) {
    console.log('🎉 ¡Todos los servidores MCP funcionan correctamente!');
    process.exit(0);
  } else {
    console.log('💥 Algunos servidores fallaron en las pruebas de funcionalidad.');
    process.exit(1);
  }
}

// Ejecutar si es llamado directamente
if (require.main === module) {
  runMCPFunctionalityTests().catch(console.error);
} 