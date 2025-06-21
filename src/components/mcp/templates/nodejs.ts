import type { ServerConfig, ParsedParameter, SecurityConfig } from '../types';

export function generateNodeJSTemplate(config: ServerConfig, params: ParsedParameter[], securityConfig: SecurityConfig): string {
  const securityCode = generateSecurityCode(securityConfig);
  
  // Limpiar el nombre para que sea válido como nombre de clase en JavaScript
  const className = config.name.replace(/[^a-zA-Z0-9]/g, '') + 'Server';
  
  const paramDefinitions = params.map(param => {
    const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
    const type = param.type === 'flag' ? 'boolean' : 'string';
    const required = param.required ? 'true' : 'false';
    const description = param.description.replace(/'/g, "\\'");
    
    return `    ${cleanName}: {
      type: '${type}',
      description: '${description}',
      required: ${required}
    }`;
  }).join(',\n');

  const paramNames = params.map(p => p.name.replace(/[^a-zA-Z0-9]/g, '_'));
  const requiredParams = params.filter(p => p.required).map(p => `'${p.name.replace(/[^a-zA-Z0-9]/g, '_')}'`);

  const commandBuilding = params.map(param => {
    const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
    
    if (param.type === 'flag') {
      return `if (${cleanName}) command += ' ${param.name}';`;
    } else if (param.type === 'option') {
      if (param.takesValue && param.expectsValue) {
        if (param.name.includes('=')) {
          return `if (${cleanName}) command += ' ${param.name.replace('=', '')}=' + ${cleanName};`;
        } else {
          return `if (${cleanName}) command += ' ${param.name} ' + ${cleanName};`;
        }
      } else if (param.takesValue) {
        return `if (${cleanName}) command += ' ${param.name}';`;
      } else {
        return `if (${cleanName}) command += ' ${param.name}';`;
      }
    } else {
      return `if (${cleanName}) command += ' ' + ${cleanName};`;
    }
  }).join('\n      ');

  const executionCode = securityConfig.enabled ? 
    `        // Validar seguridad antes de ejecutar
        try {
          validateSecurityConstraints({ ${paramNames.join(', ')} }, command);
        } catch (securityError) {
          return {
            content: [{
              type: 'text',
              text: \`❌ Security validation failed: \${securityError.message}\n\nThis command was blocked due to security restrictions. Please review the command and try again with different parameters.\`
            }]
          };
        }
        
        // Ejecutar comando de forma segura
        try {
          const result = await executeSecurely('${config.binaryName}', command.split(' ').slice(1), '${config.workingDirectory}');
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
    `        // Execute command
        try {
          const options = {};
          if ('workingDirectory' in config && config.workingDirectory) {
            options.cwd = config.workingDirectory;
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

  return `const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
${securityCode}

class ${className} extends Server {
  constructor() {
    super({
      name: '${config.name}',
      version: '${config.version}',
      description: '${config.description}'
    });
  }

  async initialize() {
    // Register tools
    this.registerTool({
      name: 'execute_${config.binaryName}',
      description: 'Execute ${config.binaryName} command with parameters. This tool allows you to run ${config.binaryName} commands with various options and arguments.',
      inputSchema: {
        type: 'object',
        properties: {
${paramDefinitions}
        },
        required: [${requiredParams.join(', ')}]
      }
    }, async (args) => {
      try {
        // Extract parameters
        const { ${paramNames.join(', ')} } = args;
        
        // Build command
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
    });
  }
}

(async () => {
  const server = new ${className}();
  await server.connect(new StdioServerTransport());
})();
`;
}

function generateSecurityCode(securityConfig: SecurityConfig): string {
  if (!securityConfig.enabled) return '';

  let securityCode = `
// ==================== CONFIGURACIÓN DE SEGURIDAD ====================

// Validaciones de seguridad
function validateSecurityConstraints(params, command) {`;

  // Validaciones básicas según el nivel de seguridad
  if (securityConfig.level === 'basic') {
    securityCode += `
  // Validaciones básicas de seguridad
  if (command.includes('rm -rf') || command.includes('format') || command.includes('dd if=')) {
    throw new Error('Comando peligroso detectado');
  }`;
  } else if (securityConfig.level === 'intermediate') {
    securityCode += `
  // Validaciones intermedias de seguridad
  const dangerousCommands = ['rm -rf', 'format', 'dd if=', 'mkfs', 'fdisk', 'parted'];
  for (const dangerous of dangerousCommands) {
    if (command.includes(dangerous)) {
      throw new Error('Comando peligroso detectado: ' + dangerous);
    }
  }`;
  } else if (securityConfig.level === 'advanced') {
    securityCode += `
  // Validaciones avanzadas de seguridad
  const dangerousCommands = ['rm -rf', 'format', 'dd if=', 'mkfs', 'fdisk', 'parted', 'chmod 777', 'chown root'];
  const dangerousPatterns = [/\\brm\\s+.*-rf/, /\\bformat\\b/, /\\bdd\\s+if=/, /\\bmkfs\\b/, /\\bfdisk\\b/];
  
  for (const dangerous of dangerousCommands) {
    if (command.includes(dangerous)) {
      throw new Error('Comando peligroso detectado: ' + dangerous);
    }
  }
  
  for (const pattern of dangerousPatterns) {
    if (pattern.test(command)) {
      throw new Error('Patrón peligroso detectado en comando');
    }
  }`;
  }

  if (securityConfig.restrictions.allowedHosts.length > 0) {
    securityCode += `
  // Validar hosts permitidos
  const allowedHosts = ${JSON.stringify(securityConfig.restrictions.allowedHosts)};
  if (params.host && !allowedHosts.includes(params.host)) {
    throw new Error('Host no autorizado: ' + params.host);
  }`;
  }

  if (securityConfig.restrictions.forbiddenPatterns.length > 0) {
    securityCode += `
  // Validar patrones prohibidos
  const forbiddenPatterns = ${JSON.stringify(securityConfig.restrictions.forbiddenPatterns)};
  for (const pattern of forbiddenPatterns) {
    if (command.toLowerCase().includes(pattern.toLowerCase())) {
      throw new Error('Comando contiene patrón prohibido: ' + pattern);
    }
  }`;
  }

  if (securityConfig.restrictions.allowedUsers.length > 0) {
    securityCode += `
  // Validar usuarios permitidos
  const allowedUsers = ${JSON.stringify(securityConfig.restrictions.allowedUsers)};
  const currentUser = process.env.USER || process.env.USERNAME || 'unknown';
  if (!allowedUsers.includes(currentUser)) {
    throw new Error('Usuario no autorizado: ' + currentUser);
  }`;
  }

  if (securityConfig.validation.enableInputSanitization) {
    securityCode += `
  // Sanitizar entrada
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string') {
      // Remover caracteres peligrosos básicos
      params[key] = value.replace(/[;&|]/g, '').replace(/\`/g, '').replace(/\$/g, '');
    }
  }`;
  }

  // Validaciones de parámetros específicos
  if (securityConfig.parameterSecurity.length > 0) {
    securityCode += `
  // Validaciones de parámetros específicos
  const parameterValidations = ${JSON.stringify(securityConfig.parameterSecurity)};
  for (const validation of parameterValidations) {
    const paramValue = params[validation.name];
    if (paramValue !== undefined) {
      if (validation.allowedValues && !validation.allowedValues.includes(paramValue)) {
        throw new Error(\`Valor no permitido para \${validation.name}: \${paramValue}\`);
      }
      if (validation.pattern && !new RegExp(validation.pattern).test(paramValue)) {
        throw new Error(\`Formato inválido para \${validation.name}: \${paramValue}\`);
      }
      if (validation.maxLength && paramValue.length > validation.maxLength) {
        throw new Error(\`\${validation.name} excede la longitud máxima de \${validation.maxLength} caracteres\`);
      }
    }
  }`;
  }

  securityCode += `
}

// Función para ejecutar comandos de forma segura
async function executeSecurely(binaryName, args, workingDirectory) {
  return new Promise((resolve, reject) => {
    const timeout = ${securityConfig.restrictions.maxExecutionTime * 1000};
    const options = {
      timeout: timeout,
      maxBuffer: ${securityConfig.restrictions.maxMemoryMB * 1024 * 1024}
    };
    if (workingDirectory) {
      options.cwd = workingDirectory;
    }
    const child = exec(binaryName + ' ' + args.join(' '), options, (error, stdout, stderr) => {
      if (error) {
        if (error.code === 'ETIMEDOUT') {
          reject(new Error('Comando excedió el tiempo límite de ejecución'));
        } else {
          reject(new Error(\`Error ejecutando comando: \${error.message}\`));
        }
        return;
      }
      
      if (stderr) {
        console.warn('Command stderr:', stderr);
      }
      
      resolve(stdout || 'Command executed successfully');
    });
  });
}
`;
  return '';
}