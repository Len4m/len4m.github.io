#!/usr/bin/env node

const { generateNodeJSTemplate, generatePythonTemplate } = require('./temp-compiled/templates/templates');

// Configuración de prueba
const testConfig = {
  name: 'test-server',
  description: 'Test MCP server for validation',
  version: '1.0.0',
  binaryName: 'ls',
  workingDirectory: '/tmp',
  timeout: 60
};

const testParams = [
  {
    name: '--all',
    description: 'Show all files including hidden ones',
    type: 'flag',
    required: false,
    takesValue: false,
    expectsValue: false
  },
  {
    name: '--long',
    description: 'Use long listing format',
    type: 'flag',
    required: false,
    takesValue: false,
    expectsValue: false
  },
  {
    name: 'directory',
    description: 'Directory to list',
    type: 'argument',
    required: false,
    takesValue: true,
    expectsValue: true,
    position: 1
  }
];

const testSecurityConfig = {
  enabled: true,
  level: 'intermediate',
  restrictions: {
    allowedHosts: ['localhost', '127.0.0.1'],
    forbiddenPatterns: ['rm -rf', 'format'],
    maxExecutionTime: 30,
    maxMemoryMB: 512
  },
  sandboxing: {
    useContainer: false,
    networkIsolation: false,
    filesystemRestrictions: ['/tmp', '/home'],
    runAsUser: 'nobody'
  },
  parameterSecurity: [],
  validation: {
    enableInputSanitization: true,
    enableOutputFiltering: false,
    enableCommandWhitelist: true
  }
};

console.log('🧪 Testing MCP Template Generation...\n');

// Probar generación de template Node.js
console.log('📦 Testing Node.js Template:');
try {
  const nodejsTemplate = generateNodeJSTemplate(testConfig, testParams, testSecurityConfig);
  console.log('✅ Node.js template generated successfully');
  console.log(`📏 Template length: ${nodejsTemplate.length} characters`);
  
  // Verificar que contiene elementos clave
  const nodejsChecks = [
    { name: 'Server import', check: nodejsTemplate.includes('@modelcontextprotocol/sdk/server') },
    { name: 'Server name', check: nodejsTemplate.includes('test-server') },
    { name: 'Binary name', check: nodejsTemplate.includes('ls') },
    { name: 'Timeout config', check: nodejsTemplate.includes('timeout:') },
    { name: 'Working directory', check: nodejsTemplate.includes('/tmp') },
    { name: 'Security code', check: nodejsTemplate.includes('CONFIGURACIÓN DE SEGURIDAD') },
    { name: 'Parameter definitions', check: nodejsTemplate.includes('--all') && nodejsTemplate.includes('--long') },
    { name: 'Command building', check: nodejsTemplate.includes('command +=') }
  ];
  
  nodejsChecks.forEach(check => {
    console.log(`  ${check.check ? '✅' : '❌'} ${check.name}`);
  });
  
} catch (error) {
  console.log('❌ Node.js template generation failed:', error.message);
}

console.log('\n🐍 Testing Python Template:');
try {
  const pythonTemplate = generatePythonTemplate(testConfig, testParams, testSecurityConfig);
  console.log('✅ Python template generated successfully');
  console.log(`📏 Template length: ${pythonTemplate.length} characters`);
  
  // Verificar que contiene elementos clave
  const pythonChecks = [
    { name: 'MCP imports', check: pythonTemplate.includes('from mcp.server') },
    { name: 'Server name', check: pythonTemplate.includes('test-server') },
    { name: 'Binary name', check: pythonTemplate.includes('ls') },
    { name: 'Timeout config', check: pythonTemplate.includes('timeout=') },
    { name: 'Working directory', check: pythonTemplate.includes('/tmp') },
    { name: 'Security code', check: pythonTemplate.includes('CONFIGURACIÓN DE SEGURIDAD') },
    { name: 'Parameter definitions', check: pythonTemplate.includes('--all') && pythonTemplate.includes('--long') },
    { name: 'Command building', check: pythonTemplate.includes('command.append') }
  ];
  
  pythonChecks.forEach(check => {
    console.log(`  ${check.check ? '✅' : '❌'} ${check.name}`);
  });
  
} catch (error) {
  console.log('❌ Python template generation failed:', error.message);
}

// Probar sin parámetros
console.log('\n🔧 Testing templates without parameters:');
try {
  const nodejsTemplateNoParams = generateNodeJSTemplate(testConfig, [], testSecurityConfig);
  const pythonTemplateNoParams = generatePythonTemplate(testConfig, [], testSecurityConfig);
  
  console.log('✅ Node.js template without params generated');
  console.log('✅ Python template without params generated');
  
  // Verificar que maneja correctamente el caso sin parámetros
  console.log(`  ${nodejsTemplateNoParams.includes('No parameters to extract') ? '✅' : '❌'} Node.js handles no params`);
  console.log(`  ${pythonTemplateNoParams.includes('No parameters to extract') ? '✅' : '❌'} Python handles no params`);
  
} catch (error) {
  console.log('❌ Template generation without params failed:', error.message);
}

// Probar sin seguridad
console.log('\n🔓 Testing templates without security:');
try {
  const noSecurityConfig = { ...testSecurityConfig, enabled: false };
  const nodejsTemplateNoSec = generateNodeJSTemplate(testConfig, testParams, noSecurityConfig);
  const pythonTemplateNoSec = generatePythonTemplate(testConfig, testParams, noSecurityConfig);
  
  console.log('✅ Node.js template without security generated');
  console.log('✅ Python template without security generated');
  
  // Verificar que no incluye código de seguridad
  console.log(`  ${!nodejsTemplateNoSec.includes('CONFIGURACIÓN DE SEGURIDAD') ? '✅' : '❌'} Node.js no security code`);
  console.log(`  ${!pythonTemplateNoSec.includes('CONFIGURACIÓN DE SEGURIDAD') ? '✅' : '❌'} Python no security code`);
  
} catch (error) {
  console.log('❌ Template generation without security failed:', error.message);
}

console.log('\n🎉 Template validation completed!'); 