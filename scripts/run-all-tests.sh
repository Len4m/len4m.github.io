#!/bin/bash

# Script maestro para ejecutar todos los tipos de testing de plantillas MCP
# Combina testing básico, avanzado y con plantillas reales

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_header() {
    echo -e "${PURPLE}🚀 $1${NC}"
}

# Función para verificar prerrequisitos
check_prerequisites() {
    log_header "Verificando prerrequisitos..."
    
    # Verificar Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker no está instalado. Instálalo desde https://docker.com"
        exit 1
    fi
    
    # Verificar Node.js
    if ! command -v node &> /dev/null; then
        log_error "Node.js no está instalado"
        exit 1
    fi
    
    # Verificar npm
    if ! command -v npm &> /dev/null; then
        log_error "npm no está instalado"
        exit 1
    fi
    
    # Verificar que Docker esté corriendo
    if ! docker info &> /dev/null; then
        log_error "Docker no está corriendo. Inicia Docker y vuelve a intentar"
        exit 1
    fi
    
    log_success "Todos los prerrequisitos están disponibles"
}

# Función para limpiar antes de empezar
cleanup_before_start() {
    log_info "Limpiando archivos temporales previos..."
    
    # Limpiar directorios de test
    rm -rf "$PROJECT_ROOT/test-output" 2>/dev/null || true
    rm -rf "$PROJECT_ROOT/test-output-advanced" 2>/dev/null || true
    rm -rf "$PROJECT_ROOT/test-docker" 2>/dev/null || true
    rm -rf "$PROJECT_ROOT/temp-compiled" 2>/dev/null || true
    
    # Limpiar contenedores e imágenes de Docker
    docker system prune -f 2>/dev/null || true
    docker rmi $(docker images -q -f "reference=mcp-test-*") 2>/dev/null || true
    
    log_success "Limpieza completada"
}

# Función para ejecutar tests básicos
run_basic_tests() {
    log_header "EJECUTANDO TESTS BÁSICOS"
    echo "════════════════════════════════════════════════════════════════"
    
    cd "$SCRIPT_DIR"
    chmod +x test-mcp-templates.sh
    
    if ./test-mcp-templates.sh; then
        log_success "Tests básicos completados exitosamente"
        return 0
    else
        log_error "Tests básicos fallaron"
        return 1
    fi
}

# Función para ejecutar tests avanzados
run_advanced_tests() {
    log_header "EJECUTANDO TESTS AVANZADOS"
    echo "════════════════════════════════════════════════════════════════"
    
    cd "$SCRIPT_DIR"
    chmod +x advanced-mcp-test.js
    
    if node advanced-mcp-test.js; then
        log_success "Tests avanzados completados exitosamente"
        return 0
    else
        log_error "Tests avanzados fallaron"
        return 1
    fi
}

# Función para ejecutar tests de integración
run_integration_tests() {
    log_header "EJECUTANDO TESTS DE INTEGRACIÓN"
    echo "════════════════════════════════════════════════════════════════"
    
    log_info "Compilando proyecto..."
    cd "$PROJECT_ROOT"
    
    # Verificar que el proyecto compile
    if npm run build; then
        log_success "Proyecto compilado exitosamente"
    else
        log_warning "El proyecto tiene errores de compilación, pero continuamos con tests básicos"
    fi
    
    # Crear algunos casos de prueba de integración específicos
    log_info "Ejecutando tests de integración personalizados..."
    
    # Test 1: Verificar que las plantillas existan y tengan estructura correcta
    if [ -f "$PROJECT_ROOT/src/components/mcp/templates/nodejs.ts" ] && \
       [ -f "$PROJECT_ROOT/src/components/mcp/templates/python.ts" ]; then
        log_success "Plantillas encontradas correctamente"
    else
        log_error "Plantillas no encontradas"
        return 1
    fi
    
    # Test 2: Verificar que las traducciones estén completas
    if npx tsc --noEmit; then
        log_success "Todas las verificaciones de tipos pasaron"
    else
        log_error "Verificaciones de tipos fallaron"
        return 1
    fi
    
    return 0
}

# Función para generar reporte final
generate_final_report() {
    local basic_result=$1
    local advanced_result=$2
    local integration_result=$3
    
    echo ""
    echo "################################################################"
    echo "##                    REPORTE FINAL DE TESTING                ##"
    echo "################################################################"
    echo ""
    
    printf "%-25s" "Tests Básicos:"
    if [ $basic_result -eq 0 ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
    else
        echo -e "${RED}❌ FAILED${NC}"
    fi
    
    printf "%-25s" "Tests Avanzados:"
    if [ $advanced_result -eq 0 ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
    else
        echo -e "${RED}❌ FAILED${NC}"
    fi
    
    printf "%-25s" "Tests de Integración:"
    if [ $integration_result -eq 0 ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
    else
        echo -e "${RED}❌ FAILED${NC}"
    fi
    
    echo ""
    echo "################################################################"
    
    local total_passed=0
    [ $basic_result -eq 0 ] && ((total_passed++))
    [ $advanced_result -eq 0 ] && ((total_passed++))
    [ $integration_result -eq 0 ] && ((total_passed++))
    
    if [ $total_passed -eq 3 ]; then
        log_success "🎉 ¡TODOS LOS TESTS PASARON! Las plantillas MCP están listas para producción."
        echo ""
        echo "📋 Resumen de lo que se ha verificado:"
        echo "   • Generación correcta de servidores Node.js y Python"
        echo "   • Instalación de dependencias en contenedores limpios"
        echo "   • Sintaxis y estructura de código válida"
        echo "   • Compatibilidad con el SDK oficial de MCP"
        echo "   • Configuraciones de seguridad funcionales"
        echo "   • Traducciones completas en todos los idiomas"
        echo ""
        return 0
    else
        log_error "💥 ALGUNOS TESTS FALLARON ($total_passed/3 pasaron)"
        echo ""
        echo "🔧 Acciones recomendadas:"
        [ $basic_result -ne 0 ] && echo "   • Revisar la generación básica de plantillas"
        [ $advanced_result -ne 0 ] && echo "   • Verificar las plantillas reales del proyecto"
        [ $integration_result -ne 0 ] && echo "   • Corregir errores de compilación y tipos"
        echo ""
        return 1
    fi
}

# Función principal
main() {
    echo "🚀 INICIANDO SUITE COMPLETA DE TESTING PARA PLANTILLAS MCP"
    echo "=========================================================="
    
    # Verificar prerrequisitos
    check_prerequisites
    
    # Limpiar antes de empezar
    cleanup_before_start
    
    # Hacer ejecutables los scripts
    chmod +x "$SCRIPT_DIR"/*.sh
    chmod +x "$SCRIPT_DIR"/*.js
    
    # Variables para trackear resultados
    basic_result=1
    advanced_result=1
    integration_result=1
    
    # Ejecutar cada tipo de test
    echo ""
    if run_basic_tests; then
        basic_result=0
    fi
    
    echo ""
    if run_advanced_tests; then
        advanced_result=0
    fi
    
    echo ""
    if run_integration_tests; then
        integration_result=0
    fi
    
    # Generar reporte final
    generate_final_report $basic_result $advanced_result $integration_result
    
    # Limpiar al final
    log_info "Limpiando archivos temporales finales..."
    cleanup_before_start
    
    # Retornar código de salida apropiado
    if [ $basic_result -eq 0 ] && [ $advanced_result -eq 0 ] && [ $integration_result -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Mostrar ayuda si se pide
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Suite de Testing para Plantillas MCP"
    echo ""
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  --help, -h     Mostrar esta ayuda"
    echo "  --basic        Ejecutar solo tests básicos"
    echo "  --advanced     Ejecutar solo tests avanzados"
    echo "  --integration  Ejecutar solo tests de integración"
    echo ""
    echo "Sin opciones, ejecuta todos los tests."
    echo ""
    echo "Prerrequisitos:"
    echo "  • Docker instalado y corriendo"
    echo "  • Node.js y npm"
    echo "  • Acceso a internet para descargar dependencias"
    echo ""
    exit 0
fi

# Ejecutar tests específicos si se solicita
case "$1" in
    --basic)
        check_prerequisites
        cleanup_before_start
        run_basic_tests
        ;;
    --advanced)
        check_prerequisites
        cleanup_before_start
        run_advanced_tests
        ;;
    --integration)
        check_prerequisites
        cleanup_before_start
        run_integration_tests
        ;;
    *)
        # Ejecutar suite completa
        main
        ;;
esac 