import type { ServerConfig, ParsedParameter, SecurityConfig } from '../types';

export function generatePythonTemplate(config: ServerConfig, params: ParsedParameter[], securityConfig: SecurityConfig): string {
  const securityCode = generateSecurityCode(securityConfig);
  
  const paramDefinitions = params.map(param => {
    const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
    const type = param.type === 'flag' ? 'bool' : 'str';
    const required = param.required ? 'True' : 'False';
    const description = param.description.replace('"', '\\"');
    
    return `        "${cleanName}": {
            "type": "${type}",
            "description": "${description}",
            "required": ${required}
        }`;
  }).join(',\n');

  const paramNames = params.map(p => p.name.replace(/[^a-zA-Z0-9]/g, '_'));
  const requiredParams = params.filter(p => p.required).map(p => `"${p.name.replace(/[^a-zA-Z0-9]/g, '_')}"`);

  const commandBuilding = params.map(param => {
    const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
    
    if (param.type === 'flag') {
      return `if ${cleanName}:\n            command.append("${param.name}")`;
    } else if (param.type === 'option') {
      if (param.takesValue && param.expectsValue) {
        if (param.name.includes('=')) {
          return `if ${cleanName}:\n            command.extend(["${param.name.replace('=', '')}=", str(${cleanName})])`;
        } else {
          return `if ${cleanName}:\n            command.extend(["${param.name}", str(${cleanName})])`;
        }
      } else if (param.takesValue) {
        return `if ${cleanName}:\n            command.append("${param.name}")`;
      } else {
        return `if ${cleanName}:\n            command.append("${param.name}")`;
      }
    } else {
      return `if ${cleanName}:\n            command.append(str(${cleanName}))`;
    }
  }).join('\n        ');

  const executionCode = securityConfig.enabled ?
    `            # Validar seguridad antes de ejecutar
            try:
                validate_security_constraints({${paramNames.map(name => `"${name}": ${name}`).join(', ')}}, ' '.join(command))
            except ValueError as security_error:
                return {
                    "content": [{
                        "type": "text",
                        "text": f"❌ Security validation failed: {security_error}\\n\\nThis command was blocked due to security restrictions. Please review the command and try again with different parameters."
                    }]
                }
            
            # Ejecutar comando de forma segura
            try:
                result_output = execute_securely(command, timeout=${securityConfig.restrictions.maxExecutionTime})
                return {
                    "content": [{
                        "type": "text",
                        "text": result_output or "Command executed successfully"
                    }]
                }
            except Exception as exec_error:
                return {
                    "content": [{
                        "type": "text",
                        "text": f"❌ Command execution failed: {exec_error}"
                    }]
                }` :
    `            # Execute command
            try:
                result = subprocess.run(
                    command, 
                    capture_output=True, 
                    text=True, 
                    check=True,
                    timeout=300  # 5 minute timeout
                )
                
                if result.stderr:
                    print(f"Command stderr: {result.stderr}")
                
                return {
                    "content": [{
                        "type": "text",
                        "text": result.stdout or "Command executed successfully"
                    }]
                }
            except subprocess.TimeoutExpired:
                return {
                    "content": [{
                        "type": "text",
                        "text": "❌ Command execution timed out"
                    }]
                }
            except subprocess.CalledProcessError as e:
                return {
                    "content": [{
                        "type": "text",
                        "text": f"❌ Command failed: {e.stderr}"
                    }]
                }
            except Exception as e:
                return {
                    "content": [{
                        "type": "text",
                        "text": f"❌ Unexpected error: {str(e)}"
                    }]
                }`;

  return `import asyncio
import subprocess
from typing import Dict, Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool
${securityCode}

class ${config.name.charAt(0).toUpperCase() + config.name.slice(1)}Server(Server):
    def __init__(self):
        super().__init__(
            name="${config.name}",
            version="${config.version}",
            description="${config.description}"
        )

    async def initialize(self):
        # Register tools
        await self.register_tool(
            Tool(
                name="execute_${config.binaryName}",
                description="Execute ${config.binaryName} command with parameters. This tool allows you to run ${config.binaryName} commands with various options and arguments.",
                input_schema={
                    "type": "object",
                    "properties": {
${paramDefinitions}
                    },
                    "required": [${requiredParams.join(', ')}]
                }
            ),
            self.execute_${config.binaryName}
        )

    async def execute_${config.binaryName}(self, args: Dict[str, Any]):
        try:
            # Extract parameters
            ${paramNames.map(name => `${name} = args.get("${name}")`).join('\n            ')}
            
            # Build command
            command = ["${config.binaryName}"]
            ${commandBuilding}
            
${executionCode}
            
        except Exception as e:
            return {
                "content": [{
                    "type": "text",
                    "text": f"❌ Unexpected error: {str(e)}"
                }]
            }

async def main():
    server = ${config.name.charAt(0).toUpperCase() + config.name.slice(1)}Server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)

if __name__ == "__main__":
    asyncio.run(main())
`;
}

function generateSecurityCode(securityConfig: SecurityConfig): string {
  if (!securityConfig.enabled) return '';

  let securityCode = `
# ==================== CONFIGURACIÓN DE SEGURIDAD ====================

# Validaciones de seguridad
def validate_security_constraints(params, command):`;

  // Validaciones básicas según el nivel de seguridad
  if (securityConfig.level === 'basic') {
    securityCode += `
    # Validaciones básicas de seguridad
    if 'rm -rf' in command or 'format' in command or 'dd if=' in command:
        raise ValueError('Comando peligroso detectado')`;
  } else if (securityConfig.level === 'intermediate') {
    securityCode += `
    # Validaciones intermedias de seguridad
    dangerous_commands = ['rm -rf', 'format', 'dd if=', 'mkfs', 'fdisk', 'parted']
    for dangerous in dangerous_commands:
        if dangerous in command:
            raise ValueError(f'Comando peligroso detectado: {dangerous}')`;
  } else if (securityConfig.level === 'advanced') {
    securityCode += `
    # Validaciones avanzadas de seguridad
    import re
    dangerous_commands = ['rm -rf', 'format', 'dd if=', 'mkfs', 'fdisk', 'parted', 'chmod 777', 'chown root']
    dangerous_patterns = [r'\\brm\\s+.*-rf', r'\\bformat\\b', r'\\bdd\\s+if=', r'\\bmkfs\\b', r'\\bfdisk\\b']
    
    for dangerous in dangerous_commands:
        if dangerous in command:
            raise ValueError(f'Comando peligroso detectado: {dangerous}')
    
    for pattern in dangerous_patterns:
        if re.search(pattern, command):
            raise ValueError('Patrón peligroso detectado en comando')`;
  }

  if (securityConfig.restrictions.allowedHosts.length > 0) {
    securityCode += `
    # Validar hosts permitidos
    allowed_hosts = ${JSON.stringify(securityConfig.restrictions.allowedHosts)}
    if 'host' in params and params['host'] not in allowed_hosts:
        raise ValueError(f"Host no autorizado: {params['host']}")`;
  }

  if (securityConfig.restrictions.forbiddenPatterns.length > 0) {
    securityCode += `
    # Validar patrones prohibidos
    forbidden_patterns = ${JSON.stringify(securityConfig.restrictions.forbiddenPatterns)}
    for pattern in forbidden_patterns:
        if pattern.lower() in command.lower():
            raise ValueError(f"Comando contiene patrón prohibido: {pattern}")`;
  }

  if (securityConfig.restrictions.allowedUsers.length > 0) {
    securityCode += `
    # Validar usuarios permitidos
    import os
    allowed_users = ${JSON.stringify(securityConfig.restrictions.allowedUsers)}
    current_user = os.environ.get('USER') or os.environ.get('USERNAME') or 'unknown'
    if current_user not in allowed_users:
        raise ValueError(f"Usuario no autorizado: {current_user}")`;
  }

  if (securityConfig.validation.enableInputSanitization) {
    securityCode += `
    # Sanitizar entrada
    import re
    for key, value in params.items():
        if isinstance(value, str):
            # Remover caracteres peligrosos básicos
            value = value.replace(';', '').replace('&', '').replace('|', '')
            value = value.replace('\`', '').replace('$', '')
            params[key] = value`;
  }

  // Validaciones de parámetros específicos
  if (securityConfig.parameterSecurity.length > 0) {
    securityCode += `
    # Validaciones de parámetros específicos
    import re
    parameter_validations = ${JSON.stringify(securityConfig.parameterSecurity)}
    for validation in parameter_validations:
        param_value = params.get(validation['name'])
        if param_value is not None:
            if 'allowedValues' in validation and param_value not in validation['allowedValues']:
                raise ValueError(f"Valor no permitido para {validation['name']}: {param_value}")
            if 'pattern' in validation and not re.search(validation['pattern'], param_value):
                raise ValueError(f"Formato inválido para {validation['name']}: {param_value}")
            if 'maxLength' in validation and len(param_value) > validation['maxLength']:
                raise ValueError(f"{validation['name']} excede la longitud máxima de {validation['maxLength']} caracteres")`;
  }

  securityCode += `

# Función para ejecutar comandos de forma segura
def execute_securely(command, timeout):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        
        if result.stderr:
            print(f"Command stderr: {result.stderr}")
        
        return result.stdout or "Command executed successfully"
    except subprocess.TimeoutExpired:
        raise Exception("Comando excedió el tiempo límite de ejecución")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error ejecutando comando: {e.stderr}")
    except Exception as e:
        raise Exception(f"Error inesperado: {str(e)}")`;

  return securityCode;
} 