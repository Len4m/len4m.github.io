# Sistema de Testing Automatizado para Plantillas MCP

Este directorio contiene un sistema completo de testing automatizado que valida las plantillas MCP en entornos Docker limpios.

## 🚀 Características

- **Testing Básico**: Genera servidores simples y verifica estructura básica
- **Testing Avanzado**: Usa plantillas reales del proyecto con configuraciones complejas
- **Testing de Integración**: Verifica compilación del proyecto y tipos TypeScript
- **Containerización**: Todas las pruebas se ejecutan en contenedores Docker limpios
- **Multi-lenguaje**: Soporta tanto Node.js como Python
- **Reportes Detallados**: Proporciona reportes claros de éxito/fallo

## 📋 Prerrequisitos

- Docker instalado y corriendo
- Node.js 18+ 
- npm
- Acceso a internet (para descargar dependencias)

## 🗂️ Estructura de Archivos

```
scripts/
├── README.md                    # Esta documentación
├── run-all-tests.sh            # Script maestro que ejecuta todas las pruebas
├── test-mcp-templates.sh       # Tests básicos con casos simples
├── advanced-mcp-test.js        # Tests avanzados con plantillas reales
├── generate-server.js          # Generador de servidores para testing
└── test-docker/                # Archivos Docker para testing
    ├── docker-compose.test.yml
    ├── Dockerfile.nodejs-base
    ├── Dockerfile.python-base
    ├── test-nodejs-server.sh
    └── test-python-server.sh
```

## 🚀 Uso Rápido

### Ejecutar Todos los Tests

```bash
./scripts/run-all-tests.sh
```

### Ejecutar Tests Específicos

```bash
# Solo tests básicos
./scripts/run-all-tests.sh --basic

# Solo tests avanzados  
./scripts/run-all-tests.sh --advanced

# Solo tests de integración
./scripts/run-all-tests.sh --integration
```

### Ver Ayuda

```bash
./scripts/run-all-tests.sh --help
```

## 📊 Tipos de Testing

### 1. Tests Básicos

**Propósito**: Verificar que las plantillas generen código válido y funcional

**Casos de Prueba**:
- `ls-server` (Node.js): Servidor básico para comando `ls`
- `curl-server` (Python): Servidor básico para comando `curl`
- `echo-server` (Node.js): Servidor básico para comando `echo`
- `grep-server` (Python): Servidor básico para comando `grep`

**Validaciones**:
- ✅ Archivos necesarios se generan (`package.json`, `index.js`, `requirements.txt`, `server.py`)
- ✅ Sintaxis del código es válida
- ✅ Dependencias se instalan correctamente
- ✅ Módulos se pueden cargar sin errores

### 2. Tests Avanzados

**Propósito**: Probar configuraciones complejas y plantillas reales del proyecto

**Casos de Prueba**:
- `curl-advanced` (Node.js): Servidor cURL con múltiples parámetros y seguridad intermedia
- `file-processor` (Python): Procesador de archivos con seguridad avanzada

**Validaciones**:
- ✅ Plantillas reales del proyecto TypeScript se pueden usar
- ✅ Configuraciones de seguridad complejas funcionan
- ✅ Parámetros múltiples se manejan correctamente
- ✅ Validaciones de entrada/salida funcionan

### 3. Tests de Integración

**Propósito**: Verificar que el proyecto completo funcione correctamente

**Validaciones**:
- ✅ Proyecto se compila sin errores TypeScript
- ✅ Todas las plantillas existen en las ubicaciones correctas
- ✅ Traducciones están completas
- ✅ No hay errores de tipos

## 🐳 Arquitectura Docker

### Imágenes Base

- **`mcp-test-nodejs`**: Imagen Alpine con Node.js 18 y SDK de MCP
- **`mcp-test-python`**: Imagen Alpine con Python 3.11 y dependencias MCP

### Proceso de Testing

1. **Generación**: Se genera código usando las plantillas
2. **Containerización**: Código se copia a contenedor limpio
3. **Instalación**: Dependencias se instalan desde cero
4. **Validación**: Se ejecutan múltiples verificaciones
5. **Limpieza**: Contenedores e imágenes se limpian automáticamente

## 📝 Casos de Uso Ejemplo

### Desarrollo de Nuevas Plantillas

```bash
# Modificar plantillas en src/components/mcp/templates/
# Ejecutar tests para verificar cambios
./scripts/run-all-tests.sh --advanced
```

### CI/CD Pipeline

```bash
# En tu pipeline de CI/CD
./scripts/run-all-tests.sh
if [ $? -eq 0 ]; then
    echo "✅ Plantillas validadas - OK para deploy"
else
    echo "❌ Tests fallaron - Bloquear deploy"
    exit 1
fi
```

### Debugging de Problemas

```bash
# Ejecutar solo un tipo de test para diagnosticar
./scripts/run-all-tests.sh --basic

# Revisar archivos generados
ls -la test-output*/
```

## 🔧 Personalización

### Agregar Nuevos Casos de Prueba

**En tests básicos** (`test-mcp-templates.sh`):
```bash
# Agregar a la variable TEST_CASES
"nuevo-server|nuevo-binario|nodejs|Descripción del nuevo servidor"
```

**En tests avanzados** (`advanced-mcp-test.js`):
```javascript
// Agregar al array advancedTestCases
{
  name: "nuevo-server-avanzado",
  binaryName: "nuevo-binario",
  language: "python",
  description: "Servidor avanzado con configuración compleja",
  parameters: [...],
  securityConfig: {...}
}
```

### Configurar Docker Personalizado

Modifica los Dockerfiles en `test-docker/` para:
- Agregar nuevas dependencias
- Cambiar versiones de lenguajes
- Incluir herramientas adicionales

## 📊 Interpretación de Resultados

### Salida Exitosa

```
🎉 ¡TODOS LOS TESTS PASARON! Las plantillas MCP están listas para producción.

📋 Resumen de lo que se ha verificado:
   • Generación correcta de servidores Node.js y Python
   • Instalación de dependencias en contenedores limpios
   • Sintaxis y estructura de código válida
   • Compatibilidad con el SDK oficial de MCP
   • Configuraciones de seguridad funcionales
   • Traducciones completas en todos los idiomas
```

### Salida con Errores

```
💥 ALGUNOS TESTS FALLARON (1/3 pasaron)

🔧 Acciones recomendadas:
   • Revisar la generación básica de plantillas
   • Verificar las plantillas reales del proyecto
   • Corregir errores de compilación y tipos
```

## 🚨 Troubleshooting

### Error: "Docker no está corriendo"

```bash
# Iniciar Docker
sudo systemctl start docker
# o en macOS/Windows: abrir Docker Desktop
```

### Error: "Plantillas no encontradas"

```bash
# Verificar que estás en el directorio correcto del proyecto
ls -la src/components/mcp/templates/
```

### Error: "npm install -g @modelcontextprotocol/sdk failed"

```bash
# El SDK podría no estar disponible públicamente
# El script usará fallbacks automáticamente
```

### Error: "Tests básicos fallaron"

```bash
# Ejecutar individualmente para diagnosticar
./scripts/test-mcp-templates.sh
# Revisar logs detallados
```

## 🤝 Contribuir

Para agregar nuevas funcionalidades al sistema de testing:

1. Modifica los scripts según tus necesidades
2. Agrega nuevos casos de prueba
3. Actualiza esta documentación
4. Ejecuta todos los tests para verificar compatibilidad

## 📜 Licencia

Este sistema de testing forma parte del proyecto principal y sigue la misma licencia. 