// Test para verificar que las plantillas incluyen todos los campos configurables
const { generateNodeJSTemplate, generatePythonTemplate } = require('./temp-compiled/templates/templates');

// Configuración de prueba con todos los campos
const testConfig = {
  name: 'test-server',
  description: 'Test server for template validation',
  version: '1.0.0',
  binaryName: 'test-command',
  workingDirectory: '/tmp/test'
};

// Parámetros de prueba con todos los campos configurables
const testParams = [
  {
    name: '--flag',
    description: 'A test flag',
    type: 'flag',
    required: false,
    defaultValue: 'true',
    takesValue: false,
    expectsValue: false,
    position: undefined
  },
  {
    name: '--option',
    description: 'A test option',
    type: 'option',
    required: true,
    defaultValue: 'default-value',
    takesValue: true,
    expectsValue: true,
    position: undefined
  },
  {
    name: 'argument',
    description: 'A test argument',
    type: 'argument',
    required: true,
    defaultValue: undefined,
    takesValue: true,
    expectsValue: true,
    position: 1
  }
];

const securityConfig = {
  enabled: true,
  level: 'basic',
  restrictions: {
    allowedHosts: ['localhost'],
    forbiddenPatterns: ['rm -rf'],
    maxExecutionTime: 30,
    allowedUsers: ['user'],
    maxMemoryMB: 512
  },
  sandboxing: {
    useContainer: false,
    networkIsolation: false,
    filesystemRestrictions: [],
    runAsUser: 'nobody'
  },
  parameterSecurity: [],
  validation: {
    enableInputSanitization: true,
    enableOutputFiltering: false,
    enableCommandWhitelist: false
  }
};

console.log('Testing Node.js template...');
const nodejsTemplate = generateNodeJSTemplate(testConfig, testParams, securityConfig);

// Verificar que incluye todos los campos
const nodejsChecks = [
  'default: true',
  "default: 'default-value'",
  'takesValue: true',
  'expectsValue: true',
  'position: 1',
  'required: true',
  'required: false'
];

console.log('Node.js template checks:');
nodejsChecks.forEach(check => {
  const found = nodejsTemplate.includes(check);
  console.log(`  ${check}: ${found ? '✅' : '❌'}`);
});

console.log('\nTesting Python template...');
const pythonTemplate = generatePythonTemplate(testConfig, testParams, securityConfig);

// Verificar que incluye todos los campos
const pythonChecks = [
  '"default": true',
  '"default": "default-value"',
  '"takesValue": true',
  '"expectsValue": true',
  '"position": 1',
  '"required": true',
  '"required": false'
];

console.log('Python template checks:');
pythonChecks.forEach(check => {
  const found = pythonTemplate.includes(check);
  console.log(`  ${check}: ${found ? '✅' : '❌'}`);
});

console.log('\n✅ Template validation completed!'); 