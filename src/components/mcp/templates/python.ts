import type { ServerConfig, ParsedParameter, SecurityConfig } from '../types';

export function generatePythonTemplate(config: ServerConfig, params: ParsedParameter[], securityConfig: SecurityConfig): string {
  const securityCode = generateSecurityCode(config, securityConfig);
  
  // Limpiar el nombre para que sea válido como nombre de clase en Python
  const className = config.name.replace(/[^a-zA-Z0-9]/g, '') + 'Server';
  
  const paramDefinitions = params && params.length > 0 ? params.map(param => {
    const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
    const type = param.type === 'flag' ? 'boolean' : 'string';
    const required = param.required ? 'True' : 'False';
    // Escapar descripción para comillas dobles en Python: saltos de línea, comillas y caracteres especiales
    const description = param.description
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
    
    // Construir definición de parámetro con todos los campos
    let paramDef = `            "${cleanName}": {
                "type": "${type}",
                "description": "${description}",
                "required": ${required}`;
    
    // Añadir defaultValue solo si no es flag
    if (param.defaultValue !== undefined && param.type !== 'flag') {
      const defaultValue = `"${param.defaultValue.replace(/"/g, '\\"')}"`;
      paramDef += `,
                "default": ${defaultValue}`;
    }
    
    // Añadir campos específicos del tipo
    if (param.type === 'option') {
      paramDef += `,
                "takesValue": ${param.takesValue},
                "expectsValue": ${param.expectsValue}`;
    } else if (param.type === 'argument' && param.position !== undefined) {
      paramDef += `,
                "position": ${param.position}`;
    }
    
    paramDef += `\n            }`;
    
    return paramDef;
  }).join(',\n') : '';

  const paramNames = params && params.length > 0 ? params.map(p => p.name.replace(/[^a-zA-Z0-9]/g, '_')) : [];
  const requiredParams = params && params.length > 0 ? params.filter(p => p.required).map(p => `"${p.name.replace(/[^a-zA-Z0-9]/g, '_')}"`) : [];

  // Separar argumentos posicionales de flags/opciones para construir el comando en el orden correcto
  const positionalArgs = params && params.length > 0 ? params.filter(p => p.type === 'argument').sort((a, b) => (a.position || 0) - (b.position || 0)) : [];
  const flagsAndOptions = params && params.length > 0 ? params.filter(p => p.type !== 'argument') : [];

  const commandBuilding = `
            # Add positional arguments first (in order)
${positionalArgs.map(param => {
    const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
    return `            if ${cleanName}:
                command.append(str(${cleanName}))`;
  }).join('\n')}
            
            # Add flags and options
${flagsAndOptions.map(param => {
    const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
    
    if (param.type === 'flag') {
      return `            if ${cleanName}:
                command.append("${param.name}")`;
    } else if (param.type === 'option') {
      if (param.takesValue && param.expectsValue) {
        if (param.name.includes('=')) {
          return `            if ${cleanName}:
                command.append("${param.name.replace('=', '')}=" + str(${cleanName}))`;
        } else {
          return `            if ${cleanName}:
                command.extend(["${param.name}", str(${cleanName})])`;
        }
      } else if (param.takesValue) {
        return `            if ${cleanName}:
                command.append("${param.name}")`;
      } else {
        return `            if ${cleanName}:
                command.append("${param.name}")`;
      }
    } else {
      return `            if ${cleanName}:
                command.append(str(${cleanName}))`;
    }
  }).join('\n')}`;

  // Manejar caso cuando no hay parámetros
  const paramExtraction = paramNames.length > 0 ? paramNames.map(name => `            ${name} = arguments.get("${name}")`).join('\n') : '            # No parameters to extract';
  const requiredArray = requiredParams.length > 0 ? `[${requiredParams.join(', ')}]` : '[]';

  // Código de ejecución corregido - sin bloques try-catch anidados
  const executionCode = securityConfig.enabled ? 
    `            # Validar seguridad antes de ejecutar
            validate_security_constraints({${paramNames.length > 0 ? paramNames.map(name => `"${name}": ${name}`).join(', ') : ''}}, command)
            
            # Ejecutar comando de forma segura
            result = execute_securely("${config.binaryName}", command[1:] if len(command) > 1 else [], "${config.workingDirectory || ''}", ${config.timeout || 30})
            return [TextContent(
                type="text",
                text=result or "Command executed successfully"
            )]` :
    `            # Execute command
            working_dir = "${config.workingDirectory || ''}"
            if working_dir == "":
                working_dir = None
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=working_dir,
                timeout=${config.timeout || 30}  # Configurable timeout
            )

            if result.stderr:
                print(f"Command stderr: {result.stderr}", file=sys.stderr)

            return [TextContent(
                type="text",
                text=result.stdout or "Command executed successfully"
            )]`;

  return `#!/usr/bin/env python3
"""
${config.name} MCP Server
${config.description}

Generated by MCP Creator - https://github.com/lenam-ai/mcp-creator
"""

import sys
import subprocess
import asyncio
from typing import Any, Dict, List, Optional, Union
import json
import os
import re
import time

# Importaciones MCP
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)
from pydantic import AnyUrl

${securityCode}

# Crear servidor MCP
server = Server("${config.name}")

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="execute_${config.binaryName}",
            description="Execute ${config.binaryName} command with parameters. This tool allows you to run ${config.binaryName} commands with various options and arguments.",
            inputSchema={
                "type": "object",
                "properties": {
${paramDefinitions}
                },
                "required": ${requiredArray}
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent | ImageContent | EmbeddedResource]:
    """Handle tool calls."""
    if name == "execute_${config.binaryName}":
        try:
            # Extract parameters
${paramExtraction}
            
            # Build command
            command = ["${config.binaryName}"]
${commandBuilding}
            
${executionCode}
        except Exception as error:
            return [TextContent(
                type="text",
                text=f"❌ Unexpected error: {error}"
            )]
    
    raise ValueError(f"Unknown tool: {name}")

def main():
    """Run the server using stdin/stdout streams."""
    async def arun():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="${config.name}",
                    server_version="${config.version}",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    asyncio.run(arun())

if __name__ == "__main__":
    main()
`;
}

function generateSecurityCode(config: ServerConfig, securityConfig: SecurityConfig): string {
  if (!securityConfig.enabled) return '';

  let securityCode = `
# ==================== CONFIGURACIÓN DE SEGURIDAD ====================

# Validaciones de seguridad
def validate_security_constraints(params: Dict[str, Any], command: List[str]) -> None:
    """Validate security constraints before command execution."""`;

  // Validaciones básicas según el nivel de seguridad
  if (securityConfig.level === 'basic') {
    securityCode += `
    # Validaciones básicas de seguridad
    dangerous_commands = ['rm -rf', 'format', 'dd if=']
    command_str = ' '.join(command)
    for dangerous in dangerous_commands:
        if dangerous in command_str:
            raise Exception(f'Comando peligroso detectado: {dangerous}')`;
  } else if (securityConfig.level === 'intermediate') {
    securityCode += `
    # Validaciones intermedias de seguridad
    dangerous_commands = ['rm -rf', 'format', 'dd if=', 'mkfs', 'fdisk', 'parted']
    command_str = ' '.join(command)
    for dangerous in dangerous_commands:
        if dangerous in command_str:
            raise Exception(f'Comando peligroso detectado: {dangerous}')`;
  } else if (securityConfig.level === 'advanced') {
    securityCode += `
    # Validaciones avanzadas de seguridad
    dangerous_commands = ['rm -rf', 'format', 'dd if=', 'mkfs', 'fdisk', 'parted', 'chmod 777', 'chown root']
    dangerous_patterns = [
        r'\\brm\\s+.*-rf',
        r'\\bformat\\b',
        r'\\bdd\\s+if=',
        r'\\bmkfs\\b',
        r'\\bfdisk\\b'
    ]
    
    command_str = ' '.join(command)
    for dangerous in dangerous_commands:
        if dangerous in command_str:
            raise Exception(f'Comando peligroso detectado: {dangerous}')
    
    for pattern in dangerous_patterns:
        if re.search(pattern, command_str):
            raise Exception('Patrón peligroso detectado en comando')`;
  }

  if (securityConfig.restrictions.allowedHosts && securityConfig.restrictions.allowedHosts.length > 0) {
    securityCode += `
    # Validar hosts permitidos
    allowed_hosts = ${JSON.stringify(securityConfig.restrictions.allowedHosts)}
    if 'host' in params and params['host'] not in allowed_hosts:
        raise Exception(f'Host no autorizado: {params["host"]}')`;
  }

  if (securityConfig.restrictions.forbiddenPatterns && securityConfig.restrictions.forbiddenPatterns.length > 0) {
    securityCode += `
    # Validar patrones prohibidos
    forbidden_patterns = ${JSON.stringify(securityConfig.restrictions.forbiddenPatterns)}
    command_str = ' '.join(command).lower()
    for pattern in forbidden_patterns:
        if pattern.lower() in command_str:
            raise Exception(f'Comando contiene patrón prohibido: {pattern}')`;
  }

  if (securityConfig.validation.enableInputSanitization) {
    securityCode += `
    # Sanitizar entrada
    for key, value in params.items():
        if isinstance(value, str):
            # Remover caracteres peligrosos básicos
            dangerous_chars = r"[;&|$]"
            params[key] = re.sub(dangerous_chars, "", str(value))`;
  }

  if (securityConfig.validation.enableOutputFiltering) {
    securityCode += `
    
def filter_output(output: str) -> str:
    """Filter sensitive information from command output."""
    if not output:
        return output
    
    # Remover información sensible
    sensitive_patterns = [
        r'password\\s*[:=]\\s*[^\\s]+',
        r'token\\s*[:=]\\s*[^\\s]+',
        r'key\\s*[:=]\\s*[^\\s]+',
        r'secret\\s*[:=]\\s*[^\\s]+'
    ]
    
    filtered_output = output
    for pattern in sensitive_patterns:
        filtered_output = re.sub(pattern, lambda m: m.group().split(':', 1)[0] + ': [REDACTED]', filtered_output, flags=re.IGNORECASE)
    
    return filtered_output`;
  }

  if (securityConfig.validation.enableCommandWhitelist) {
    securityCode += `
    # Lista blanca de comandos permitidos
    allowed_commands = ['${config.binaryName}']
    base_command = command[0] if command else ''
    
    if base_command not in allowed_commands:
        raise Exception(f'Comando no permitido: {base_command}')`;
  }

  // Validaciones de parámetros específicos
  if (securityConfig.parameterSecurity && securityConfig.parameterSecurity.length > 0) {
    securityCode += `
    # Validaciones de parámetros específicos
    parameter_validations = ${JSON.stringify(securityConfig.parameterSecurity)}
    for validation in parameter_validations:
        param_name = validation['name']
        param_value = params.get(param_name)
        if param_value is not None:
            if 'allowedValues' in validation and param_value not in validation['allowedValues']:
                raise Exception(f'Valor no permitido para {param_name}: {param_value}')
            if 'pattern' in validation and not re.match(validation['pattern'], str(param_value)):
                raise Exception(f'Formato inválido para {param_name}: {param_value}')
            if 'maxLength' in validation and len(str(param_value)) > validation['maxLength']:
                raise Exception(f'{param_name} excede la longitud máxima de {validation["maxLength"]} caracteres')`;
  }

  securityCode += `

def execute_securely(binary_name: str, args: List[str], working_directory: Optional[str] = None, timeout: Optional[int] = None) -> str:
    """Execute commands securely with restrictions."""
    try:
        # Build full command
        full_command = [binary_name] + args
        
        # Set working directory if provided
        cwd = working_directory if working_directory else None
        
        # Execute with restrictions
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        
        if result.stderr:
            print(f"Command stderr: {result.stderr}", file=sys.stderr)
        
        return result.stdout or "Command executed successfully"
        
    except subprocess.TimeoutExpired:
        raise Exception('Comando excedió el tiempo límite de ejecución')
    except Exception as error:
        raise Exception(f'Error ejecutando comando: {error}')
`;

  return securityCode;
} 