"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateNodeJSTemplate = generateNodeJSTemplate;
function generateNodeJSTemplate(config, params, securityConfig) {
    const securityCode = generateSecurityCode(config, securityConfig);
    // Limpiar el nombre para que sea válido como nombre de clase en JavaScript
    const className = config.name.replace(/[^a-zA-Z0-9]/g, '') + 'Server';
    const paramDefinitions = params.map(param => {
        const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
        const type = param.type === 'flag' ? 'boolean' : 'string';
        const required = param.required ? 'true' : 'false';
        // Escapar descripción para comillas simples: saltos de línea, comillas y caracteres especiales
        const description = param.description
            .replace(/'/g, "\\'")
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t');
        // Construir definición de parámetro con todos los campos
        let paramDef = `    ${cleanName}: {
      type: '${type}',
      description: '${description}',
      required: ${required}`;
        // Añadir defaultValue si existe
        if (param.defaultValue !== undefined) {
            const defaultValue = param.type === 'flag' ? param.defaultValue : `'${param.defaultValue.replace(/'/g, "\\'")}'`;
            paramDef += `,
      default: ${defaultValue}`;
        }
        // Añadir campos específicos del tipo
        if (param.type === 'option') {
            paramDef += `,
      takesValue: ${param.takesValue},
      expectsValue: ${param.expectsValue}`;
        }
        else if (param.type === 'argument' && param.position !== undefined) {
            paramDef += `,
      position: ${param.position}`;
        }
        paramDef += `
    }`;
        return paramDef;
    }).join(',\n');
    const paramNames = params.map(p => p.name.replace(/[^a-zA-Z0-9]/g, '_'));
    const requiredParams = params.filter(p => p.required).map(p => `'${p.name.replace(/[^a-zA-Z0-9]/g, '_')}'`);
    const commandBuilding = params.map(param => {
        const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
        if (param.type === 'flag') {
            return `          if (${cleanName}) command += ' ${param.name}';`;
        }
        else if (param.type === 'option') {
            if (param.takesValue && param.expectsValue) {
                if (param.name.includes('=')) {
                    return `          if (${cleanName}) command += ' ${param.name.replace('=', '')}=' + ${cleanName};`;
                }
                else {
                    return `          if (${cleanName}) command += ' ${param.name} ' + ${cleanName};`;
                }
            }
            else if (param.takesValue) {
                return `          if (${cleanName}) command += ' ${param.name}';`;
            }
            else {
                return `          if (${cleanName}) command += ' ${param.name}';`;
            }
        }
        else {
            return `          if (${cleanName}) command += ' ' + ${cleanName};`;
        }
    }).join('\n');
    // Manejar caso cuando no hay parámetros
    const paramDestructuring = paramNames.length > 0 ? `const { ${paramNames.join(', ')} } = request.params.arguments || {};` : '// No parameters to extract';
    const requiredArray = requiredParams.length > 0 ? `[${requiredParams.join(', ')}]` : '[]';
    const executionCode = securityConfig.enabled ?
        `          // Validar seguridad antes de ejecutar
          try {
            validateSecurityConstraints({ ${paramNames.length > 0 ? paramNames.join(', ') : ''} }, command);
          } catch (securityError) {
            return {
              content: [{
                type: 'text',
                text: \`❌ Security validation failed: \${securityError.message}\\n\\nThis command was blocked due to security restrictions. Please review the command and try again with different parameters.\`
              }]
            };
          }
          
          // Ejecutar comando de forma segura
          try {
            const result = await executeSecurely('${config.binaryName}', command.split(' ').slice(1), '${config.workingDirectory || ''}');
            return {
              content: [{
                type: 'text',
                text: result || 'Command executed successfully'
              }]
            };
          } catch (execError) {
            return {
              content: [{
                type: 'text',
                text: \`❌ Command execution failed: \${execError.message}\`
              }]
            };
          }` :
        `          // Execute command
          try {
            const options = {};
            if ('${config.workingDirectory || ''}' && '${config.workingDirectory || ''}' !== '') {
              options.cwd = '${config.workingDirectory || ''}';
            }
            const { stdout, stderr } = await execAsync(command, options);
            
            if (stderr) {
              console.warn('Command stderr:', stderr);
            }
            
            return {
              content: [{
                type: 'text',
                text: stdout || 'Command executed successfully'
              }]
            };
          } catch (error) {
            return {
              content: [{
                type: 'text',
                text: \`❌ Command execution failed: \${error.message}\`
              }]
            };
          }`;
    return `#!/usr/bin/env node
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  ListToolsRequestSchema,
  CallToolRequestSchema
} = require('@modelcontextprotocol/sdk/types.js');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
${securityCode}

// Crear el servidor MCP
const server = new Server(
  {
    name: '${config.name}',
    version: '${config.version}',
    description: '${config.description}'
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

// Registrar herramientas disponibles
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'execute_${config.binaryName}',
        description: 'Execute ${config.binaryName} command with parameters. This tool allows you to run ${config.binaryName} commands with various options and arguments.',
        inputSchema: {
          type: 'object',
          properties: {
${paramDefinitions}
          },
          required: ${requiredArray}
        }
      }
    ]
  };
});

// Manejar llamadas a herramientas
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === 'execute_${config.binaryName}') {
    try {
      // Extraer parámetros
      ${paramDestructuring}
      
      // Construir comando
      let command = '${config.binaryName}';
${commandBuilding}
      
${executionCode}
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: \`❌ Unexpected error: \${error.message}\`
        }]
      };
    }
  } else {
    throw new Error(\`Unknown tool: \${request.params.name}\`);
  }
});

// Conectar el servidor
async function main() {
  try {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('${config.name} MCP Server running on stdio');
  } catch (error) {
    console.error('Fatal error in main():', error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
`;
}
function generateSecurityCode(config, securityConfig) {
    if (!securityConfig.enabled)
        return '';
    let securityCode = `
// ==================== CONFIGURACIÓN DE SEGURIDAD ====================

// Validaciones de seguridad
function validateSecurityConstraints(args, command) {
  // Validar patrones prohibidos
  const forbiddenPatterns = ${JSON.stringify(securityConfig.restrictions.forbiddenPatterns || [])};
  for (const pattern of forbiddenPatterns) {
    if (command.includes(pattern)) {
      throw new Error(\`Forbidden pattern detected: \${pattern}\`);
    }
  }
  
  // Validar hosts permitidos
  const allowedHosts = ${JSON.stringify(securityConfig.restrictions.allowedHosts || [])};
  if (allowedHosts.length > 0) {
    const hostArg = args.host || args.target || args.url;
    if (hostArg && !allowedHosts.includes(hostArg)) {
      throw new Error(\`Host not allowed: \${hostArg}\`);
    }
  }
  
  // Validar usuarios permitidos
  const allowedUsers = ${JSON.stringify(securityConfig.restrictions.allowedUsers || [])};
  if (allowedUsers.length > 0) {
    const currentUser = process.env.USER || process.env.USERNAME || 'unknown';
    if (!allowedUsers.includes(currentUser)) {
      throw new Error(\`User not allowed: \${currentUser}\`);
    }
  }
}

// Ejecución segura de comandos
async function executeSecurely(binary, args, workingDir) {
  // Validar que el binario está permitido (solo el binario configurado)
  const allowedBinary = '${config.binaryName}';
  if (binary !== allowedBinary) {
    throw new Error(\`Binary not allowed: \${binary}\`);
  }
  
  // Ejecutar con restricciones
  const options = {
    timeout: ${securityConfig.restrictions.maxExecutionTime * 1000 || 30000},
    maxBuffer: ${securityConfig.restrictions.maxMemoryMB * 1024 * 1024 || 1024 * 1024}
  };
  
  if (workingDir && workingDir !== '') {
    options.cwd = workingDir;
  }
  
  const { stdout, stderr } = await execAsync(binary + ' ' + args.join(' '), options);
  
  if (stderr) {
    console.warn('Command stderr:', stderr);
  }
  
  return stdout;
}

// ==================== FIN CONFIGURACIÓN DE SEGURIDAD ====================
`;
    return securityCode;
}
