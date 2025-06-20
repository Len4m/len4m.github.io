# Validaciones de Seguridad - Creador de MCP

## Descripción General

Este documento describe las validaciones de seguridad implementadas en el Creador de MCP para proteger contra entradas maliciosas y asegurar que los nombres de binarios y servidores sean seguros para su uso en programación.

## Validaciones Implementadas

### 1. Validación de Nombres de Binarios

**Patrón permitido:** `^[a-zA-Z][a-zA-Z0-9_-]*$`

**Restricciones básicas (siempre aplicadas):**
- Debe empezar con una letra (a-z, A-Z)
- Solo permite letras, números, guiones (-) y guiones bajos (_)
- Longitud máxima: 50 caracteres
- No puede contener espacios ni caracteres especiales

**Restricciones de seguridad (solo cuando seguridad está habilitada):**
- Bloqueo de comandos del sistema peligrosos

**Caracteres prohibidos:**
- `< > : " | ? *` y caracteres de control (0x00-0x1f)
- Puntos (.) - para evitar confusiones con rutas
- Espacios y caracteres especiales

**Comandos peligrosos bloqueados (solo con seguridad habilitada):**
```javascript
const dangerousCommands = [
  'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd', 'shred', 'wipe',
  'sudo', 'su', 'chmod', 'chown', 'passwd', 'useradd', 'userdel',
  'kill', 'killall', 'pkill', 'systemctl', 'service', 'init',
  'halt', 'reboot', 'shutdown', 'poweroff', 'exec', 'eval'
];
```

### 2. Validación de Nombres de Servidores

**Patrón permitido:** `^[a-zA-Z][a-zA-Z0-9._-]*$`

**Restricciones básicas (siempre aplicadas):**
- Debe empezar con una letra (a-z, A-Z)
- Permite letras, números, puntos (.), guiones (-) y guiones bajos (_)
- Longitud máxima: 63 caracteres
- No puede contener espacios ni caracteres especiales

**Restricciones de seguridad (solo cuando seguridad está habilitada):**
- Bloqueo de palabras reservadas del sistema

**Palabras reservadas bloqueadas (solo con seguridad habilitada):**
```javascript
const reservedWords = [
  'admin', 'root', 'system', 'internal', 'private', 'secret',
  'password', 'token', 'key', 'auth', 'login', 'session'
];
```

### 3. Validación de Versiones

**Patrón permitido:** `^[0-9]+\.[0-9]+\.[0-9]+$`

**Restricciones:**
- Formato semver básico: x.y.z
- Solo números y puntos
- Longitud máxima: 20 caracteres
- No puede estar vacío

### 4. Sanitización de Entrada

**Funciones implementadas:**
- `sanitizeInput(input, type)`: Remueve caracteres peligrosos automáticamente
- Validación en tiempo real con feedback visual
- Límites de longitud automáticos
- Corrección automática de formato (ej: añadir letra inicial si falta)

## Comportamiento Condicional de Seguridad

### Cuando la Seguridad está **HABILITADA**:
- ✅ Se bloquean comandos del sistema peligrosos
- ✅ Se bloquean palabras reservadas en nombres de servidores
- ✅ Se muestran mensajes de advertencia naranja
- ✅ Validación estricta de seguridad

### Cuando la Seguridad está **DESHABILITADA**:
- ✅ Se permiten todos los comandos del sistema
- ✅ Se permiten todas las palabras reservadas
- ✅ Se muestran mensajes informativos azules
- ✅ Solo se aplican validaciones básicas de formato

## Beneficios de Seguridad

### 1. Prevención de Inyección de Comandos (solo con seguridad habilitada)
- Bloqueo de comandos del sistema peligrosos
- Validación estricta de caracteres permitidos
- Sanitización automática de entrada

### 2. Prevención de Confusión de Nombres (solo con seguridad habilitada)
- Evita nombres que puedan confundirse con rutas del sistema
- Bloqueo de palabras reservadas del sistema
- Validación de formato consistente

### 3. Protección contra Ataques
- Validación de longitud para prevenir buffer overflows
- Bloqueo de caracteres de control
- Prevención de nombres maliciosos

### 4. Experiencia de Usuario
- Feedback visual inmediato (bordes rojos en errores)
- Mensajes de error descriptivos
- Sanitización automática sin pérdida de funcionalidad
- Texto de ayuda contextual
- Indicadores de estado de seguridad

## Implementación Técnica

### Archivos Principales:
- `validation.ts`: Lógica de validación y sanitización
- `McpServerConfig.tsx`: Componente con validación en tiempo real
- `McpCreator.tsx`: Validación antes de generar código
- `translations.ts`: Mensajes de error y ayuda

### Flujo de Validación:
1. **Entrada del usuario** → Sanitización automática
2. **Validación en tiempo real** → Feedback visual
3. **Validación antes de generar** → Bloqueo si hay errores
4. **Generación de código** → Solo con datos válidos

### Parámetros de Validación:
```typescript
validateBinaryName(name: string, lang: 'en' | 'es' | 'ca', securityEnabled: boolean)
validateServerName(name: string, lang: 'en' | 'es' | 'ca', securityEnabled: boolean)
validateVersion(version: string, lang: 'en' | 'es' | 'ca')
```

## Ejemplos de Uso

### Con Seguridad Habilitada:
```
Binarios Válidos: ls, grep-tool, file_processor, my-app
Binarios Inválidos: rm, sudo, chmod, /usr/bin/ls

Servidores Válidos: ls-server, api.service, data-processor
Servidores Inválidos: admin-server, root.service, password-manager
```

### Con Seguridad Deshabilitada:
```
Binarios Válidos: ls, rm, sudo, chmod, grep-tool, file_processor
Servidores Válidos: ls-server, admin-server, root.service, api.service
```

### Versiones (siempre igual):
```
Válidas: 1.0.0, 2.1.3, 10.5.2
Inválidas: 1.0, v1.0.0, 1.0.0-beta
```

## Consideraciones de Seguridad

1. **Validación del lado del cliente:** Para experiencia de usuario
2. **Validación del lado del servidor:** Para seguridad real (implementar si es necesario)
3. **Sanitización automática:** Previene errores comunes
4. **Lista blanca de caracteres:** Más segura que lista negra
5. **Comportamiento condicional:** Permite flexibilidad según necesidades de seguridad

## Mantenimiento

- Revisar periódicamente la lista de comandos peligrosos
- Actualizar patrones de validación según necesidades
- Monitorear nuevos vectores de ataque
- Mantener traducciones actualizadas
- Evaluar si las restricciones de seguridad son apropiadas para cada caso de uso 