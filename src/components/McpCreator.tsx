import React, { useState, useEffect } from 'react';
import Editor from 'react-simple-code-editor';
import Prism from 'prismjs';
import 'prismjs/components/prism-clike';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-python';

interface Translations {
  title: string;
  label: string;
  placeholder: string;
  buttonText: string;
  processingText: string;
  instructions: string;
  step1: string;
  step2: string;
  step3: string;
  step4: string;
  characters: string;
  successMessage: string;
  errorMessage: string;
  binaryHelpLabel: string;
  binaryHelpPlaceholder: string;
  languageLabel: string;
  nodejs: string;
  python: string;
  serverConfigLabel: string;
  serverNameLabel: string;
  serverNamePlaceholder: string;
  serverDescriptionLabel: string;
  serverDescriptionPlaceholder: string;
  serverVersionLabel: string;
  serverVersionPlaceholder: string;
  binaryNameLabel: string;
  binaryNamePlaceholder: string;
  parseButtonText: string;
  parsingText: string;
  generateButtonText: string;
  generatingText: string;
  downloadButtonText: string;
  parsedParametersLabel: string;
  noParametersFound: string;
  copyToClipboard: string;
  copiedToClipboard: string;
  filterAll: string;
  filterFlags: string;
  filterOptions: string;
  filterArguments: string;
  takesValue: string;
  noParametersOfType: string;
  installationTitle: string;
  prerequisitesTitle: string;
  prerequisites1: string;
  prerequisites2: string;
  prerequisites3: string;
  installationStepsTitle: string;
  installationStep1: string;
  installationStep2: string;
  installationStep3: string;
  usingWithLLMsTitle: string;
  claudeDesktop: string;
  otherLLMs: string;
  testing: string;
  claudeDesktopLink: string;
  otherLLMsLink: string;
  testingText: string;
  securityNotesTitle: string;
  securityNote1: string;
  securityNote2: string;
  securityNote3: string;
  editParametersTitle: string;
  editParameterLabel: string;
  parameterNameLabel: string;
  parameterDescriptionLabel: string;
  parameterTypeLabel: string;
  parameterRequiredLabel: string;
  parameterTakesValueLabel: string;
  parameterExpectsValueLabel: string;
  saveChangesLabel: string;
  cancelLabel: string;
  yes: string;
  no: string;
  flag: string;
  option: string;
  argument: string;
  flagDescription: string;
  optionDescription: string;
  argumentDescription: string;
  flagHelp: string;
  optionHelp: string;
  argumentHelp: string;
  generateMCPHelp: string;
  addParameterLabel: string;
  deleteParameterLabel: string;
  addNewParameterLabel: string;
  newParameterLabel: string;
  newParameterPlaceholder: string;
  newParameterDescriptionLabel: string;
  newParameterDescriptionPlaceholder: string;
  analyzedParametersLabel: string;
  mcpDescription: string;
  mcpOfficialDocs: string;
  mcpOfficialDocsLink: string;
  claudeDesktopText: string;
  otherLLMsText: string;
  ollamaText: string;
  ollamaLink: string;
  configureMCPText: string;
  chatgptText: string;
  chatgptLink: string;
  chatgptHelpText: string;
  editCodeLabel: string;
  generatedCodeLabel: string;
  securityConfigLabel: string;
  enableSecurityLabel: string;
  securityLevelLabel: string;
  securityLevelBasic: string;
  securityLevelIntermediate: string;
  securityLevelAdvanced: string;
  restrictionsLabel: string;
  allowedHostsLabel: string;
  allowedHostsPlaceholder: string;
  forbiddenPatternsLabel: string;
  forbiddenPatternsPlaceholder: string;
  maxExecutionTimeLabel: string;
  allowedUsersLabel: string;
  allowedUsersPlaceholder: string;
  maxMemoryLabel: string;
  sandboxingLabel: string;
  useContainerLabel: string;
  networkIsolationLabel: string;
  filesystemRestrictionsLabel: string;
  filesystemRestrictionsPlaceholder: string;
  runAsUserLabel: string;
  runAsUserPlaceholder: string;
  validationLabel: string;
  enableInputSanitizationLabel: string;
  enableOutputFilteringLabel: string;
  enableCommandWhitelistLabel: string;
  parameterSecurityLabel: string;
  addParameterSecurityLabel: string;
  securityHelpText: string;
  securityBasicHelp: string;
  securityIntermediateHelp: string;
  securityAdvancedHelp: string;
}

interface ParsedParameter {
  name: string;
  description: string;
  type: 'option' | 'argument' | 'flag';
  required: boolean;
  defaultValue?: string;
  takesValue: boolean;
  expectsValue: boolean;
}

interface ServerConfig {
  name: string;
  description: string;
  version: string;
  binaryName: string;
}

interface ParameterSecurity {
  name: string;
  allowedValues?: string[];
  pattern?: string;
  maxLength?: number;
  sanitize?: boolean;
}

interface SecurityConfig {
  enabled: boolean;
  level: 'basic' | 'intermediate' | 'advanced';
  restrictions: {
    allowedHosts: string[];
    forbiddenPatterns: string[];
    maxExecutionTime: number;
    allowedUsers: string[];
    maxMemoryMB: number;
  };
  sandboxing: {
    useContainer: boolean;
    networkIsolation: boolean;
    filesystemRestrictions: string[];
    runAsUser: string;
  };
  parameterSecurity: ParameterSecurity[];
  validation: {
    enableInputSanitization: boolean;
    enableOutputFiltering: boolean;
    enableCommandWhitelist: boolean;
  };
}

const translations: Record<string, Translations> = {
  en: {
    title: "MCP Creator",
    label: "Paste your text here:",
    placeholder: "Paste the content you want to process...",
    buttonText: "Create MCP",
    processingText: "Processing...",
    instructions: "Instructions:",
    step1: "Paste the binary help text (e.g., 'ls --help' output)",
    step2: "Configure MCP server parameters",
    step3: "Choose programming language (Node.js or Python)",
    step4: "Generate and download your MCP",
    characters: "Characters:",
    successMessage: "MCP created successfully!",
    errorMessage: "Error creating MCP",
    binaryHelpLabel: "Binary Help Text:",
    binaryHelpPlaceholder: "Paste the output of 'command --help' here...",
    languageLabel: "Programming Language:",
    nodejs: "Node.js",
    python: "Python",
    serverConfigLabel: "Server Configuration:",
    serverNameLabel: "Server Name:",
    serverNamePlaceholder: "e.g., ls-server, chmod-server",
    serverDescriptionLabel: "Description:",
    serverDescriptionPlaceholder: "Brief description of the MCP server",
    serverVersionLabel: "Version:",
    serverVersionPlaceholder: "e.g., 1.0.0",
    binaryNameLabel: "Binary Name:",
    binaryNamePlaceholder: "e.g., ls, chmod",
    parseButtonText: "Parse Binary Help",
    parsingText: "Parsing...",
    generateButtonText: "Generate MCP",
    generatingText: "Generating...",
    downloadButtonText: "Download MCP",
    parsedParametersLabel: "Parsed Parameters:",
    noParametersFound: "No parameters found in the help text",
    copyToClipboard: "Copy to Clipboard",
    copiedToClipboard: "Copied!",
    filterAll: "All",
    filterFlags: "Flags",
    filterOptions: "Options",
    filterArguments: "Arguments",
    takesValue: "Takes value",
    noParametersOfType: "No parameters of this type found",
    installationTitle: "Installation & Usage Instructions:",
    prerequisitesTitle: "Prerequisites:",
    prerequisites1: "Ensure the binary command is installed and accessible in your system PATH",
    prerequisites2: "Install Node.js (for Node.js servers) or Python 3.8+ (for Python servers)",
    prerequisites3: "Install MCP SDK globally: <code className='bg-skin-fill px-1 rounded'>npm install -g @modelcontextprotocol/sdk</code> (Node.js) or <code className='bg-skin-fill px-1 rounded'>pip install mcp</code> (Python)",
    installationStepsTitle: "Installation Steps:",
    installationStep1: "Download the generated MCP server file",
    installationStep2: "No additional dependencies needed - the server uses Node.js built-in modules (util, child_process) or Python standard library",
    installationStep3: "Make the server executable: <code className='bg-skin-fill px-1 rounded'>chmod +x server.js</code> (Node.js) or ensure Python file has execute permissions",
    usingWithLLMsTitle: "Using with LLMs:",
    claudeDesktop: "Claude Desktop:",
    otherLLMs: "Other LLMs:",
    testing: "Testing:",
    claudeDesktopLink: "https://modelcontextprotocol.io/quickstart/user",
    otherLLMsLink: "https://modelcontextprotocol.io/docs/implementations/clients",
    testingText: "Run the server directly to verify it works: node server.js or python server.py",
    securityNotesTitle: "Security Notes:",
    securityNote1: "The generated server executes system commands - ensure proper security measures",
    securityNote2: "Review the generated code before deployment",
    securityNote3: "Consider running in a sandboxed environment for development and testing",
    editParametersTitle: "Edit Parameters",
    editParameterLabel: "Edit Parameter",
    parameterNameLabel: "Parameter Name",
    parameterDescriptionLabel: "Description",
    parameterTypeLabel: "Type",
    parameterRequiredLabel: "Required",
    parameterTakesValueLabel: "Takes Value",
    parameterExpectsValueLabel: "Expects Value",
    saveChangesLabel: "Save Changes",
    cancelLabel: "Cancel",
    yes: "Yes",
    no: "No",
    flag: "Flag",
    option: "Option",
    argument: "Argument",
    flagDescription: "Flag (-v, --verbose)",
    optionDescription: "Option (-o file, --output=file)",
    argumentDescription: "Argument (file1, file2)",
    flagHelp: "Flags: No values, always optional",
    optionHelp: "Options: Always take values and are optional",
    argumentHelp: "Arguments: Can be required or optional",
    generateMCPHelp: "Generate MCP server with configured parameters",
    addParameterLabel: "Add Parameter",
    deleteParameterLabel: "Delete Parameter",
    addNewParameterLabel: "Add New Parameter",
    newParameterLabel: "New Parameter",
    newParameterPlaceholder: "Enter the new parameter name",
    newParameterDescriptionLabel: "Description",
    newParameterDescriptionPlaceholder: "Enter the description for the new parameter",
    analyzedParametersLabel: "Analyzed Parameters",
    mcpDescription: "MCP (Model Context Protocol) is a protocol that enables LLMs to connect with external tools, data sources, and systems.",
    mcpOfficialDocs: "Official MCP documentation",
    mcpOfficialDocsLink: "https://modelcontextprotocol.io/docs/mcp",
    claudeDesktopText: "Add the server to your MCP configuration file",
    otherLLMsText: "Configure the MCP server path in your LLM's settings",
    ollamaText: "Ollama:",
    ollamaLink: "https://medium.com/data-science-in-your-pocket/model-context-protocol-mcp-using-ollama-e719b2d9fd7a",
    configureMCPText: "Configure MCP servers",
    chatgptText: "ChatGPT:",
    chatgptLink: "https://platform.openai.com/docs/mcp",
    chatgptHelpText: "See 'Connectors in ChatGPT' section in help center",
    editCodeLabel: "Edit Code",
    generatedCodeLabel: "Generated MCP Code:",
    securityConfigLabel: "Security Configuration",
    enableSecurityLabel: "Enable Security Features",
    securityLevelLabel: "Security Level",
    securityLevelBasic: "Basic",
    securityLevelIntermediate: "Intermediate", 
    securityLevelAdvanced: "Advanced",
    restrictionsLabel: "Execution Restrictions",
    allowedHostsLabel: "Allowed Hosts",
    allowedHostsPlaceholder: "localhost, 127.0.0.1, db.company.com",
    forbiddenPatternsLabel: "Forbidden Command Patterns",
    forbiddenPatternsPlaceholder: "DROP, DELETE, rm -rf, sudo",
    maxExecutionTimeLabel: "Max Execution Time (seconds)",
    allowedUsersLabel: "Allowed System Users",
    allowedUsersPlaceholder: "readonly, guest, limited",
    maxMemoryLabel: "Max Memory (MB)",
    sandboxingLabel: "Sandboxing Options",
    useContainerLabel: "Use Container Isolation",
    networkIsolationLabel: "Network Isolation",
    filesystemRestrictionsLabel: "Filesystem Restrictions",
    filesystemRestrictionsPlaceholder: "/tmp, /var/log, /home/user/data",
    runAsUserLabel: "Run as User",
    runAsUserPlaceholder: "nobody, readonly, limited",
    validationLabel: "Input/Output Validation",
    enableInputSanitizationLabel: "Enable Input Sanitization",
    enableOutputFilteringLabel: "Enable Output Filtering",
    enableCommandWhitelistLabel: "Enable Command Whitelist",
    parameterSecurityLabel: "Parameter Security",
    addParameterSecurityLabel: "Add Parameter Security Rule",
    securityHelpText: "Security features help protect your system from malicious or unintended command execution.",
    securityBasicHelp: "Basic security includes input validation and execution timeouts.",
    securityIntermediateHelp: "Intermediate security adds user restrictions and command filtering.",
    securityAdvancedHelp: "Advanced security includes container isolation and comprehensive sandboxing."
  },
  es: {
    title: "Creador de MCP",
    label: "Pega tu texto aquí:",
    placeholder: "Pega el contenido que quieres procesar...",
    buttonText: "Crear MCP",
    processingText: "Procesando...",
    instructions: "Instrucciones:",
    step1: "Pega el texto de ayuda del binario (ej: salida de 'ls --help')",
    step2: "Configura los parámetros del servidor MCP",
    step3: "Elige el lenguaje de programación (Node.js o Python)",
    step4: "Genera y descarga tu MCP",
    characters: "Caracteres:",
    successMessage: "¡MCP creado exitosamente!",
    errorMessage: "Error al crear MCP",
    binaryHelpLabel: "Texto de Ayuda del Binario:",
    binaryHelpPlaceholder: "Pega aquí la salida de 'comando --help'...",
    languageLabel: "Lenguaje de Programación:",
    nodejs: "Node.js",
    python: "Python",
    serverConfigLabel: "Configuración del Servidor:",
    serverNameLabel: "Nombre del Servidor:",
    serverNamePlaceholder: "ej: ls-server, chmod-server",
    serverDescriptionLabel: "Descripción:",
    serverDescriptionPlaceholder: "Descripción breve del servidor MCP",
    serverVersionLabel: "Versión:",
    serverVersionPlaceholder: "ej: 1.0.0",
    binaryNameLabel: "Nombre del Binario:",
    binaryNamePlaceholder: "e.g., ls, chmod",
    parseButtonText: "Analizar Ayuda del Binario",
    parsingText: "Analizando...",
    generateButtonText: "Generar MCP",
    generatingText: "Generando...",
    downloadButtonText: "Descargar MCP",
    parsedParametersLabel: "Parámetros Analizados:",
    noParametersFound: "No se encontraron parámetros en el texto de ayuda",
    copyToClipboard: "Copiar al Portapapeles",
    copiedToClipboard: "¡Copiado!",
    filterAll: "Todos",
    filterFlags: "Banderas",
    filterOptions: "Opciones",
    filterArguments: "Argumentos",
    takesValue: "Toma valor",
    noParametersOfType: "No se encontraron parámetros de este tipo",
    installationTitle: "Instalación & Instrucciones de Uso:",
    prerequisitesTitle: "Requisitos:",
    prerequisites1: "Asegúrate de que el comando binario esté instalado y accesible en tu PATH del sistema",
    prerequisites2: "Instala Node.js (para servidores Node.js) o Python 3.8+ (para servidores Python)",
    prerequisites3: "Instala SDK de MCP globalmente: <code className='bg-skin-fill px-1 rounded'>npm install -g @modelcontextprotocol/sdk</code> (Node.js) o <code className='bg-skin-fill px-1 rounded'>pip install mcp</code> (Python)",
    installationStepsTitle: "Pasos de Instalación:",
    installationStep1: "Descarga el archivo del servidor MCP generado",
    installationStep2: "No se necesitan dependencias adicionales - el servidor usa módulos integrados de Node.js (util, child_process) o biblioteca estándar de Python",
    installationStep3: "Haz el servidor ejecutable: <code className='bg-skin-fill px-1 rounded'>chmod +x server.js</code> (Node.js) o asegúrate de que el archivo Python tenga permisos de ejecución",
    usingWithLLMsTitle: "Uso con LLMs:",
    claudeDesktop: "Claude Desktop:",
    otherLLMs: "Otros LLMs:",
    testing: "Prueba:",
    claudeDesktopLink: "https://modelcontextprotocol.io/quickstart/user",
    otherLLMsLink: "https://modelcontextprotocol.io/docs/implementations/clients",
    testingText: "Ejecuta el servidor directamente para verificar que funciona: node server.js o python server.py",
    securityNotesTitle: "Notas de Seguridad:",
    securityNote1: "El servidor generado ejecuta comandos del sistema - asegúrate de tomar medidas de seguridad adecuadas",
    securityNote2: "Revisa el código generado antes de la implementación",
    securityNote3: "Considera ejecutar en un entorno sandboxeado para desarrollo y pruebas",
    editParametersTitle: "Editar Parámetros",
    editParameterLabel: "Editar Parámetro",
    parameterNameLabel: "Nombre del Parámetro",
    parameterDescriptionLabel: "Descripción",
    parameterTypeLabel: "Tipo",
    parameterRequiredLabel: "Requerido",
    parameterTakesValueLabel: "Toma Valor",
    parameterExpectsValueLabel: "Espera Valor",
    saveChangesLabel: "Guardar Cambios",
    cancelLabel: "Cancelar",
    yes: "Sí",
    no: "No",
    flag: "Bandera",
    option: "Opción",
    argument: "Argumento",
    flagDescription: "Bandera (-v, --verbose)",
    optionDescription: "Opción (-o archivo, --output=archivo)",
    argumentDescription: "Argumento (archivo1, archivo2)",
    flagHelp: "Banderas: No toman valores, siempre opcionales",
    optionHelp: "Opciones: Siempre toman valores y son opcionales",
    argumentHelp: "Argumentos: Pueden ser requeridos u opcionales",
    generateMCPHelp: "Genera el servidor MCP con los parámetros configurados",
    addParameterLabel: "Agregar Parámetro",
    deleteParameterLabel: "Eliminar Parámetro",
    addNewParameterLabel: "Agregar Nuevo Parámetro",
    newParameterLabel: "Nuevo Parámetro",
    newParameterPlaceholder: "Ingrese el nombre del nuevo parámetro",
    newParameterDescriptionLabel: "Descripción",
    newParameterDescriptionPlaceholder: "Ingrese la descripción del nuevo parámetro",
    analyzedParametersLabel: "Parámetros Analizados",
    mcpDescription: "MCP (Model Context Protocol) es un protocolo que permite a los LLMs conectarse con herramientas externas, fuentes de datos y sistemas.",
    mcpOfficialDocs: "Documentación oficial de MCP",
    mcpOfficialDocsLink: "https://modelcontextprotocol.io/docs/mcp",
    claudeDesktopText: "Agregar el servidor a tu archivo de configuración de MCP",
    otherLLMsText: "Configurar la ruta del servidor MCP en la configuración de tu LLM",
    ollamaText: "Ollama:",
    ollamaLink: "https://medium.com/data-science-in-your-pocket/model-context-protocol-mcp-using-ollama-e719b2d9fd7a",
    configureMCPText: "Configurar MCP servers",
    chatgptText: "ChatGPT:",
    chatgptLink: "https://platform.openai.com/docs/mcp",
    chatgptHelpText: "Ver sección 'Connectors in ChatGPT' en el centro de ayuda",
    editCodeLabel: "Editar Código",
    generatedCodeLabel: "Código MCP Generado:",
    securityConfigLabel: "Configuración de Seguridad",
    enableSecurityLabel: "Habilitar Características de Seguridad",
    securityLevelLabel: "Nivel de Seguridad",
    securityLevelBasic: "Básico",
    securityLevelIntermediate: "Intermedio",
    securityLevelAdvanced: "Avanzado",
    restrictionsLabel: "Restricciones de Ejecución",
    allowedHostsLabel: "Hosts Permitidos",
    allowedHostsPlaceholder: "localhost, 127.0.0.1, db.empresa.com",
    forbiddenPatternsLabel: "Patrones de Comandos Prohibidos",
    forbiddenPatternsPlaceholder: "DROP, DELETE, rm -rf, sudo",
    maxExecutionTimeLabel: "Tiempo Máximo de Ejecución (segundos)",
    allowedUsersLabel: "Usuarios del Sistema Permitidos",
    allowedUsersPlaceholder: "readonly, guest, limited",
    maxMemoryLabel: "Memoria Máxima (MB)",
    sandboxingLabel: "Opciones de Sandboxing",
    useContainerLabel: "Usar Aislamiento de Contenedor",
    networkIsolationLabel: "Aislamiento de Red",
    filesystemRestrictionsLabel: "Restricciones del Sistema de Archivos",
    filesystemRestrictionsPlaceholder: "/tmp, /var/log, /home/user/data",
    runAsUserLabel: "Ejecutar como Usuario",
    runAsUserPlaceholder: "nobody, readonly, limited",
    validationLabel: "Validación de Entrada/Salida",
    enableInputSanitizationLabel: "Habilitar Sanitización de Entrada",
    enableOutputFilteringLabel: "Habilitar Filtrado de Salida",
    enableCommandWhitelistLabel: "Habilitar Lista Blanca de Comandos",
    parameterSecurityLabel: "Seguridad de Parámetros",
    addParameterSecurityLabel: "Añadir Regla de Seguridad de Parámetro",
    securityHelpText: "Las características de seguridad ayudan a proteger tu sistema de ejecución maliciosa o no intencionada de comandos.",
    securityBasicHelp: "La seguridad básica incluye validación de entrada y timeouts de ejecución.",
    securityIntermediateHelp: "La seguridad intermedia añade restricciones de usuario y filtrado de comandos.",
    securityAdvancedHelp: "La seguridad avanzada incluye aislamiento de contenedor y sandboxing integral."
  },
  ca: {
    title: "Creador de MCP",
    label: "Enganxa el teu text aquí:",
    placeholder: "Enganxa el contingut que vols processar...",
    buttonText: "Crear MCP",
    processingText: "Processant...",
    instructions: "Instruccions:",
    step1: "Enganxa el text d'ajuda del binari (ex: sortida de 'ls --help')",
    step2: "Configura els paràmetres del servidor MCP",
    step3: "Tria el llenguatge de programació (Node.js o Python)",
    step4: "Genera i descarrega el teu MCP",
    characters: "Caràcters:",
    successMessage: "MCP creat amb èxit!",
    errorMessage: "Error en crear MCP",
    binaryHelpLabel: "Text d'Ajuda del Binari:",
    binaryHelpPlaceholder: "Enganxa aquí la sortida de 'comandament --help'...",
    languageLabel: "Llenguatge de Programació:",
    nodejs: "Node.js",
    python: "Python",
    serverConfigLabel: "Configuració del Servidor:",
    serverNameLabel: "Nom del Servidor:",
    serverNamePlaceholder: "ex: ls-server, chmod-server",
    serverDescriptionLabel: "Descripció:",
    serverDescriptionPlaceholder: "Descripció breu del servidor MCP",
    serverVersionLabel: "Versió:",
    serverVersionPlaceholder: "ex: 1.0.0",
    binaryNameLabel: "Nom del Binari:",
    binaryNamePlaceholder: "e.g., ls, chmod",
    parseButtonText: "Analitzar Ajuda del Binari",
    parsingText: "Analitzant...",
    generateButtonText: "Generar MCP",
    generatingText: "Generant...",
    downloadButtonText: "Descarregar MCP",
    parsedParametersLabel: "Paràmetres Analitzats:",
    noParametersFound: "No s'han trobat paràmetres al text d'ajuda",
    copyToClipboard: "Copiar al Porta-retalls",
    copiedToClipboard: "Copiat!",
    filterAll: "Tots",
    filterFlags: "Banderes",
    filterOptions: "Opcions",
    filterArguments: "Arguments",
    takesValue: "Toma valor",
    noParametersOfType: "No s'han trobat paràmetres d'aquest tipus",
    installationTitle: "Instal·lació & Instruccions d'Usuari:",
    prerequisitesTitle: "Requisits:",
    prerequisites1: "Assegura't que el comando binari estigui instal·lat i accesible en el teu PATH del sistema",
    prerequisites2: "Instala Node.js (per a servidors Node.js) o Python 3.8+ (per a servidors Python)",
    prerequisites3: "Instala SDK de MCP globalment: <code className='bg-skin-fill px-1 rounded'>npm install -g @modelcontextprotocol/sdk</code> (Node.js) o <code className='bg-skin-fill px-1 rounded'>pip install mcp</code> (Python)",
    installationStepsTitle: "Pasos d'Instal·lació:",
    installationStep1: "Descarrega el fitxer del servidor MCP generat",
    installationStep2: "No es necessiten dependències addicionals - el servidor usa mòduls integrats de Node.js (util, child_process) o biblioteca estàndard de Python",
    installationStep3: "Fes el servidor executable: <code className='bg-skin-fill px-1 rounded'>chmod +x server.js</code> (Node.js) o assegura't que el fitxer Python tingui permisos d'execució",
    usingWithLLMsTitle: "Usuari amb LLMs:",
    claudeDesktop: "Claude Desktop:",
    otherLLMs: "Altres LLMs:",
    testing: "Prova:",
    claudeDesktopLink: "https://modelcontextprotocol.io/quickstart/user",
    otherLLMsLink: "https://modelcontextprotocol.io/docs/implementations/clients",
    testingText: "Executa el servidor directament per verificar que funciona: node server.js o python server.py",
    securityNotesTitle: "Notes de Seguretat:",
    securityNote1: "El servidor generat executa comandes del sistema - assegura't de prendre mesures de seguretat adequades",
    securityNote2: "Revisa el codi generat abans de la implementació",
    securityNote3: "Considera executar en un entorn sandboxat per a desenvolupament i proves",
    editParametersTitle: "Editar Paràmetres",
    editParameterLabel: "Editar Paràmetre",
    parameterNameLabel: "Nom del Paràmetre",
    parameterDescriptionLabel: "Descripció",
    parameterTypeLabel: "Tipus",
    parameterRequiredLabel: "Requerit",
    parameterTakesValueLabel: "Toma Valor",
    parameterExpectsValueLabel: "Espera Valor",
    saveChangesLabel: "Guardar Canvis",
    cancelLabel: "Cancel·lar",
    yes: "Sí",
    no: "No",
    flag: "Bandera",
    option: "Opció",
    argument: "Argument",
    flagDescription: "Bandera (-v, --verbose)",
    optionDescription: "Opció (-o fitxer, --output=fitxer)",
    argumentDescription: "Argument (fitxer1, fitxer2)",
    flagHelp: "Banderes: No prenen valors, sempre opcionals",
    optionHelp: "Opcions: Sempre prenen valors i són opcionals",
    argumentHelp: "Arguments: Poden ser requerits o opcionals",
    generateMCPHelp: "Genera el servidor MCP amb els paràmetres configurats",
    addParameterLabel: "Afegir Paràmetre",
    deleteParameterLabel: "Eliminar Paràmetre",
    addNewParameterLabel: "Afegir Nou Paràmetre",
    newParameterLabel: "Nou Paràmetre",
    newParameterPlaceholder: "Introduïu el nom del nou paràmetre",
    newParameterDescriptionLabel: "Descripció",
    newParameterDescriptionPlaceholder: "Introduïu la descripció del nou paràmetre",
    analyzedParametersLabel: "Paràmetres Analitzats",
    mcpDescription: "MCP (Model Context Protocol) és un protocol que permet als LLMs connectar-se amb eines externes, fonts de dades i sistemes.",
    mcpOfficialDocs: "Documentació oficial de MCP",
    mcpOfficialDocsLink: "https://modelcontextprotocol.io/docs/mcp",
    claudeDesktopText: "Afegir el servidor a la teva configuració de MCP",
    otherLLMsText: "Configurar la ruta del servidor MCP en la configuració del teu LLM",
    ollamaText: "Ollama:",
    ollamaLink: "https://medium.com/data-science-in-your-pocket/model-context-protocol-mcp-using-ollama-e719b2d9fd7a",
    configureMCPText: "Configurar servidors MCP",
    chatgptText: "ChatGPT:",
    chatgptLink: "https://platform.openai.com/docs/mcp",
    chatgptHelpText: "Veure secció 'Connectors in ChatGPT' al centre d'ajuda",
    editCodeLabel: "Editar Codi",
    generatedCodeLabel: "Codi MCP Generat:",
    securityConfigLabel: "Configuració de Seguretat",
    enableSecurityLabel: "Habilitar Característiques de Seguretat",
    securityLevelLabel: "Nivell de Seguretat",
    securityLevelBasic: "Bàsic",
    securityLevelIntermediate: "Intermedi",
    securityLevelAdvanced: "Avançat",
    restrictionsLabel: "Restriccions d'Execució",
    allowedHostsLabel: "Hosts Permesos",
    allowedHostsPlaceholder: "localhost, 127.0.0.1, db.empresa.com",
    forbiddenPatternsLabel: "Patrons de Comandaments Prohibits",
    forbiddenPatternsPlaceholder: "DROP, DELETE, rm -rf, sudo",
    maxExecutionTimeLabel: "Temps Màxim d'Execució (segons)",
    allowedUsersLabel: "Usuaris del Sistema Permesos",
    allowedUsersPlaceholder: "readonly, guest, limited",
    maxMemoryLabel: "Memòria Màxima (MB)",
    sandboxingLabel: "Opcions de Sandboxing",
    useContainerLabel: "Usar Aïllament de Contenidor",
    networkIsolationLabel: "Aïllament de Xarxa",
    filesystemRestrictionsLabel: "Restriccions del Sistema d'Arxius",
    filesystemRestrictionsPlaceholder: "/tmp, /var/log, /home/user/data",
    runAsUserLabel: "Executar com a Usuari",
    runAsUserPlaceholder: "nobody, readonly, limited",
    validationLabel: "Validació d'Entrada/Sortida",
    enableInputSanitizationLabel: "Habilitar Sanitització d'Entrada",
    enableOutputFilteringLabel: "Habilitar Filtrat de Sortida",
    enableCommandWhitelistLabel: "Habilitar Llista Blanca de Comandaments",
    parameterSecurityLabel: "Seguretat de Paràmetres",
    addParameterSecurityLabel: "Afegir Regla de Seguretat de Paràmetre",
    securityHelpText: "Les característiques de seguretat ajuden a protegir el teu sistema d'execució maliciosa o no intencionada de comandaments.",
    securityBasicHelp: "La seguretat bàsica inclou validació d'entrada i timeouts d'execució.",
    securityIntermediateHelp: "La seguretat intermèdia afegeix restriccions d'usuari i filtrat de comandaments.",
    securityAdvancedHelp: "La seguretat avançada inclou aïllament de contenidor i sandboxing integral."
  }
};

export default function McpCreator() {
  const [inputText, setInputText] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentLang, setCurrentLang] = useState('en');
  const [isHydrated, setIsHydrated] = useState(false);
  const [language, setLanguage] = useState<'nodejs' | 'python'>('nodejs');
  const [serverConfig, setServerConfig] = useState<ServerConfig>({
    name: '',
    description: '',
    version: '1.0.0',
    binaryName: ''
  });
  const [parsedParameters, setParsedParameters] = useState<ParsedParameter[]>([]);
  const [isParsing, setIsParsing] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedCode, setGeneratedCode] = useState('');
  const [editableCode, setEditableCode] = useState('');
  const [copied, setCopied] = useState(false);
  const [currentTheme, setCurrentTheme] = useState<'light' | 'dark'>('light');

  // Función para cargar dinámicamente los temas de PrismJS
  const loadPrismTheme = (theme: 'light' | 'dark') => {
    // Remover tema anterior
    const existingTheme = document.getElementById('prism-theme');
    if (existingTheme) {
      existingTheme.remove();
    }

    // Cargar nuevo tema
    const link = document.createElement('link');
    link.id = 'prism-theme';
    link.rel = 'stylesheet';
    link.href = theme === 'dark' 
      ? 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-okaidia.min.css'
      : 'https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism.min.css';
    
    document.head.appendChild(link);
  };
  const [filterType, setFilterType] = useState<'all' | 'flag' | 'option' | 'argument'>('all');
  const [editingParameter, setEditingParameter] = useState<ParsedParameter | null>(null);
  const [editedParameter, setEditedParameter] = useState<ParsedParameter | null>(null);
  const [addingNewParameter, setAddingNewParameter] = useState(false);
  const [newParameter, setNewParameter] = useState<ParsedParameter>({
    name: '',
    description: '',
    type: 'option',
    required: false,
    takesValue: true,
    expectsValue: true
  });

  const [securityConfig, setSecurityConfig] = useState<SecurityConfig>({
    enabled: false,
    level: 'basic',
    restrictions: {
      allowedHosts: [],
      forbiddenPatterns: [],
      maxExecutionTime: 30,
      allowedUsers: [],
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
  });

  useEffect(() => {
    // Detectar idioma de la URL solo en el cliente
    const path = window.location.pathname;
    if (path.startsWith('/es/')) {
      setCurrentLang('es');
    } else if (path.startsWith('/ca/')) {
      setCurrentLang('ca');
    } else {
      setCurrentLang('en');
    }
    setIsHydrated(true);
    
    // Detectar tema inicial
    const detectTheme = () => {
      const theme = document.documentElement.getAttribute('data-theme') || 'light';
      setCurrentTheme(theme as 'light' | 'dark');
      loadPrismTheme(theme as 'light' | 'dark');
    };
    
    detectTheme();
    
    // Observar cambios de tema
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'attributes' && mutation.attributeName === 'data-theme') {
          const newTheme = document.documentElement.getAttribute('data-theme') || 'light';
          setCurrentTheme(newTheme as 'light' | 'dark');
          loadPrismTheme(newTheme as 'light' | 'dark');
        }
      });
    });
    
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme']
    });
    
    return () => observer.disconnect();
  }, []);

  // Aplicar estilos CSS al textarea y pre del editor para evitar ajuste de líneas
  useEffect(() => {
    const applyStyles = () => {
      // Estilos para el contenedor principal
      const containers = document.querySelectorAll('.code-editor-container');
      containers.forEach((container) => {
        const element = container as HTMLDivElement;
        element.style.overflow = 'auto';
        element.style.overflowX = 'auto';
        element.style.overflowY = 'auto';
      });

      // Estilos para el textarea
      const textareas = document.querySelectorAll('.code-editor-textarea');
      textareas.forEach((textarea) => {
        const element = textarea as HTMLTextAreaElement;
        element.style.whiteSpace = 'pre';
        element.style.wordWrap = 'normal';
        element.style.overflowWrap = 'normal';
        element.style.overflow = 'hidden';
        element.style.resize = 'none';
        element.style.minWidth = '100%';
        element.style.width = '100%';
      });

      // Estilos para el elemento pre (resaltado de sintaxis)
      const preElements = document.querySelectorAll('.code-editor-pre');
      preElements.forEach((pre) => {
        const element = pre as HTMLPreElement;
        element.style.whiteSpace = 'pre';
        element.style.wordWrap = 'normal';
        element.style.overflowWrap = 'normal';
        element.style.wordBreak = 'normal';
        element.style.overflow = 'visible';
        element.style.minWidth = '100%';
        element.style.width = 'max-content';
      });

      // Estilos para elementos code dentro del pre
      const codeElements = document.querySelectorAll('.code-editor-pre code');
      codeElements.forEach((code) => {
        const element = code as HTMLElement;
        element.style.whiteSpace = 'pre';
        element.style.wordWrap = 'normal';
        element.style.overflowWrap = 'normal';
        element.style.wordBreak = 'normal';
      });

      // Estilos para el div wrapper del editor
      const editorWrappers = document.querySelectorAll('.code-editor-container > div');
      editorWrappers.forEach((wrapper) => {
        const element = wrapper as HTMLDivElement;
        element.style.overflow = 'visible';
        element.style.minWidth = '100%';
      });
    };

    // Aplicar estilos inmediatamente
    applyStyles();
    
    // Aplicar estilos después de un pequeño delay para asegurar que el DOM esté listo
    const timeout = setTimeout(applyStyles, 100);
    
    return () => clearTimeout(timeout);
  }, [editableCode, generatedCode]);

  const t = translations[currentLang];

  // Funciones para generar código de seguridad
  const generateSecurityCode = (securityConfig: SecurityConfig, language: 'nodejs' | 'python'): string => {
    if (!securityConfig.enabled) return '';

    if (language === 'nodejs') {
      let securityCode = `
// ==================== CONFIGURACIÓN DE SEGURIDAD ====================

// Validaciones de seguridad
function validateSecurityConstraints(params, command) {`;

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

      securityCode += `
  return true;
}

// Ejecución segura con limitaciones
const { spawn } = require('child_process');

function executeSecurely(command, args, options = {}) {
  const execOptions = {
    timeout: ${securityConfig.restrictions.maxExecutionTime * 1000},
    maxBuffer: ${securityConfig.restrictions.maxMemoryMB * 1024 * 1024},
    ...options
  };

  return new Promise((resolve, reject) => {
    const child = spawn(command, args, execOptions);
    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error('Comando falló con código ' + code + ': ' + stderr));
      }
    });

    child.on('error', (error) => {
      reject(error);
    });
  });
}

// ==================== FIN CONFIGURACIÓN DE SEGURIDAD ====================
`;

      return securityCode;
    } else { // Python
      let securityCode = `
# ==================== CONFIGURACIÓN DE SEGURIDAD ====================

# Validaciones de seguridad
def validate_security_constraints(params, command):`;

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

      securityCode += `
    return True

# Ejecución segura con limitaciones
import subprocess

def execute_securely(command, timeout=${securityConfig.restrictions.maxExecutionTime}):
    """Ejecuta comando con limitaciones de seguridad"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Comando excedió el tiempo límite de {timeout} segundos")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Comando falló: {e.stderr}")

# ==================== FIN CONFIGURACIÓN DE SEGURIDAD ====================
`;

      return securityCode;
    }
  };

  // Función para parsear la ayuda del binario
  const parseBinaryHelp = (helpText: string): ParsedParameter[] => {
    const parameters: ParsedParameter[] = [];
    const lines = helpText.split('\n');
    
    // Patrones mejorados para diferentes tipos de opciones y argumentos
    const patterns = [
      // Opciones largas con argumentos: --option=VALUE o --option VALUE
      /^\s*([-]{2}[a-zA-Z0-9-]+)(?:[= ]([^,\n]+))?\s*(.+)?$/,
      // Opciones cortas y largas combinadas: -a, --all
      /^\s*([-][a-zA-Z0-9]),\s*([-]{2}[a-zA-Z0-9-]+)\s+(.+)$/,
      // Opciones cortas individuales: -a
      /^\s*([-][a-zA-Z0-9])\s+(.+)$/,
      // Opciones largas individuales: --all
      /^\s*([-]{2}[a-zA-Z0-9-]+)\s+(.+)$/,
      // Argumentos posicionales en mayúsculas: [FICHERO] o {target} o SERIALPORT
      /^\s*([A-Z_]+|[\[{][A-Z_]+[\]}])\s+(.+)$/,
      // Opciones con formato especial: -p <port ranges>
      /^\s*([-][a-zA-Z0-9])\s*[<\[][^>\]]+[>\]]\s+(.+)$/,
      // Opciones largas con formato especial: --script=<Lua scripts>
      /^\s*([-]{2}[a-zA-Z0-9-]+)\s*[<\[][^>\]]+[>\]]\s+(.+)$/,
      // Opciones con valores específicos: -m ascii, -t 0
      /^\s*([-][a-zA-Z0-9])\s+([a-zA-Z0-9:]+)\s+(.+)$/,
      // Opciones con valores numéricos: -a #, -r #
      /^\s*([-][a-zA-Z0-9])\s+#\s+(.+)$/,
      // Opciones largas con valores específicos: --from=PROPIETARIO_ACTUAL:GRUPO_ACTUAL
      /^\s*([-]{2}[a-zA-Z0-9-]+)=([A-Z_]+(?::[A-Z_]+)?)\s+(.+)$/,
      // Comandos disponibles: dir, dns, fuzz
      /^\s*([a-zA-Z0-9-]+)\s+(.+)$/,
      // Argumentos de uso: [OPCIÓN]..., MODO[,MODO]...
      /^\s*([\[{][A-Z_]+[\]}][.,]*)\s+(.+)$/
    ];

    let currentSection = '';
    let inUsageSection = false;
    let inOptionsSection = false;
    let inCommandsSection = false;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      
      // Detectar secciones importantes
      if (line.match(/^Usage:/) || line.match(/^Modo de empleo:/)) {
        inUsageSection = true;
        inOptionsSection = false;
        inCommandsSection = false;
        continue;
      }
      
      if (line.match(/^(Available Commands|Commands):/)) {
        inCommandsSection = true;
        inUsageSection = false;
        inOptionsSection = false;
        continue;
      }
      
      if (line.match(/^(General options|Options|Flags):/)) {
        inOptionsSection = true;
        inUsageSection = false;
        inCommandsSection = false;
        continue;
      }
      
      // Detectar secciones (títulos en mayúsculas)
      if (line.match(/^[A-Z][A-Z\s]+:$/)) {
        currentSection = line.replace(':', '').trim();
        inUsageSection = false;
        inOptionsSection = false;
        inCommandsSection = false;
        continue;
      }
      
      // Saltar líneas vacías o que no contengan opciones
      if (!line || 
          line.startsWith('Copyright') ||
          line.startsWith('Visit') ||
          line.startsWith('ayuda en línea') ||
          line.startsWith('Full documentation') ||
          line.startsWith('Report any') ||
          line.startsWith('Examples:') ||
          line.startsWith('Ejemplos:') ||
          line.startsWith('Use "') ||
          line.startsWith('Cada MODO') ||
          line.startsWith('El propietario') ||
          line.startsWith('Arguments:') ||
          line.startsWith('Options for')) {
        continue;
      }
      
      // Procesar cada patrón
      for (const pattern of patterns) {
        const match = line.match(pattern);
        if (match) {
          const [, option1, option2, description] = match;
          
          // Si tenemos dos opciones (formato -a, --all)
          if (option2 && option2.startsWith('--')) {
            // Añadir la opción corta
            parameters.push({
              name: option1,
              description: description || '',
              type: 'flag',
              required: false,
              takesValue: false,
              expectsValue: false
            });
            
            // Añadir la opción larga
            parameters.push({
              name: option2,
              description: description || '',
              type: option2.includes('=') ? 'option' : 'flag',
              required: false,
              takesValue: false,
              expectsValue: false
            });
            break;
          }
          
          // Opción individual
          if (option1) {
            const name = option1.trim();
            const desc = (option2 || description || '').trim();
            
            // Determinar el tipo de parámetro
            let type: 'option' | 'argument' | 'flag' = 'flag';
            let required = false;
            
            if (name.startsWith('--')) {
              // Opción larga
              if (name.includes('=') || desc.includes('<') || desc.includes('[') || desc.includes('#')) {
                type = 'option';
              } else {
                type = 'flag';
              }
            } else if (name.startsWith('-')) {
              // Opción corta
              if (desc.includes('<') || desc.includes('[') || desc.includes('=') || desc.includes('#')) {
                type = 'option';
              } else if (desc.match(/^[a-zA-Z0-9:]+/)) {
                // Si la descripción empieza con un valor específico, es una opción
                type = 'option';
              } else {
                type = 'flag';
              }
            } else {
              // Argumento posicional o comando
              if (inCommandsSection) {
                type = 'argument';
                required = false; // Los comandos son opcionales
              } else if (name.match(/^[A-Z_]+$/) || name.match(/^[\[{][A-Z_]+[\]}]/)) {
                type = 'argument';
                required = !name.includes('['); // Los argumentos entre [] son opcionales
              } else {
                type = 'argument';
                required = false;
              }
            }
            
            // Verificar si ya existe este parámetro
            const exists = parameters.find(p => p.name === name);
            if (!exists) {
              parameters.push({
                name,
                description: desc,
                type,
                required,
                takesValue: false,
                expectsValue: false
              });
            }
          }
          break;
        }
      }
      
      // Buscar líneas de continuación (descripciones multilínea)
      if (line.startsWith(' ') && parameters.length > 0) {
        const lastParam = parameters[parameters.length - 1];
        if (lastParam.description) {
          lastParam.description += ' ' + line.trim();
        }
      }
    }
    
    // Post-procesamiento: limpiar y mejorar descripciones
    parameters.forEach(param => {
      // Limpiar descripciones
      param.description = param.description
        .replace(/^\s*[,;]\s*/, '') // Remover comas y puntos y coma al inicio
        .replace(/\s+/, ' ') // Normalizar espacios
        .replace(/\([^)]*\)/g, '') // Remover paréntesis con contenido
        .trim();
      
      // Mejorar detección de tipos según convenciones
      if (param.name.startsWith('-') || param.name.startsWith('--')) {
        // Es una opción o flag
        if (param.description.includes('<') || 
            param.description.includes('=') || 
            param.description.includes('#') ||
            param.description.match(/^[a-zA-Z0-9:]+/)) {
          param.type = 'option';
          param.takesValue = true;
          param.expectsValue = true;
          param.required = false;
        } else {
          param.type = 'flag';
          param.takesValue = false;
          param.expectsValue = false;
          param.required = false;
        }
      } else {
        // Es un argumento posicional
        param.type = 'argument';
        param.takesValue = true;
        param.expectsValue = true;
        // required se mantiene como se detectó originalmente
      }
      
      // Limpiar nombres de parámetros
      param.name = param.name.replace(/[\[\]{}]/g, '');
    });
    
    // Filtrar parámetros duplicados y vacíos
    const uniqueParams = parameters.filter((param, index, self) => 
      param.name && 
      param.description && 
      index === self.findIndex(p => p.name === param.name)
    );
    
    return uniqueParams;
  };

  // Función para generar plantilla Node.js
  const generateNodeJSTemplate = (config: ServerConfig, params: ParsedParameter[]): string => {
    const securityCode = generateSecurityCode(securityConfig, 'nodejs');
    
    const paramDefinitions = params.map(param => {
      const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
      const type = param.type === 'flag' ? 'boolean' : 'string';
      const required = param.required ? 'true' : 'false';
      const description = param.description.replace(/'/g, "\\'");
      
      return `    ${cleanName}: {
      type: '${type}',
      description: '${description}',
      required: ${required}${param.takesValue ? ',\n      takesValue: true' : ''}${param.expectsValue ? ',\n      expectsValue: true' : ''}
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
        validateSecurityConstraints({ ${paramNames.join(', ')} }, command);
        
        // Ejecutar comando de forma segura
        const result = await executeSecurely('${config.binaryName}', command.split(' ').slice(1));
        return { content: result || 'Command executed successfully' };` :
      `        // Execute command
        const { stdout, stderr } = await execAsync(command);
        
        if (stderr) {
          console.warn('Command stderr:', stderr);
        }
        
        return { content: stdout || 'Command executed successfully' };`;

    return `const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
${securityCode}
class ${config.name.charAt(0).toUpperCase() + config.name.slice(1)}Server extends Server {
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
      description: 'Execute ${config.binaryName} command with parameters',
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
        throw new Error(\`Command execution failed: \${error.message}\`);
      }
    });
  }
}

const server = new ${config.name.charAt(0).toUpperCase() + config.name.slice(1)}Server();
server.listen(new StdioServerTransport());
`;
  };

  // Función para generar plantilla Python
  const generatePythonTemplate = (config: ServerConfig, params: ParsedParameter[]): string => {
    const securityCode = generateSecurityCode(securityConfig, 'python');
    
    const paramDefinitions = params.map(param => {
      const cleanName = param.name.replace(/[^a-zA-Z0-9]/g, '_');
      const type = param.type === 'flag' ? 'bool' : 'str';
      const required = param.required ? 'True' : 'False';
      const description = param.description.replace('"', '\\"');
      
      return `        "${cleanName}": {
            "type": "${type}",
            "description": "${description}",
            "required": ${required}${param.takesValue ? ',\n            "takesValue": True' : ''}${param.expectsValue ? ',\n            "expectsValue": True' : ''}
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
            validate_security_constraints({${paramNames.map(name => `"${name}": ${name}`).join(', ')}}, ' '.join(command))
            
            # Ejecutar comando de forma segura
            result_output = execute_securely(command, timeout=${securityConfig.restrictions.maxExecutionTime})
            return {"content": result_output or "Command executed successfully"}` :
      `            # Execute command
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                check=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.stderr:
                print(f"Command stderr: {result.stderr}")
            
            return {"content": result.stdout or "Command executed successfully"}`;

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
                description="Execute ${config.binaryName} command with parameters",
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
            
        except subprocess.TimeoutExpired:
            raise Exception("Command execution timed out")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Command failed: {e.stderr}")
        except Exception as e:
            raise Exception(f"Unexpected error: {str(e)}")

async def main():
    server = ${config.name.charAt(0).toUpperCase() + config.name.slice(1)}Server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)

if __name__ == "__main__":
    asyncio.run(main())
`;
  };

  const handleParse = async () => {
    if (!inputText.trim()) return;
    
    setIsParsing(true);
    try {
      const params = parseBinaryHelp(inputText);
      setParsedParameters(params);
    } catch (error) {
      console.error('Error parsing:', error);
    } finally {
      setIsParsing(false);
    }
  };

  const handleGenerate = async () => {
    if (!serverConfig.name || !serverConfig.binaryName || parsedParameters.length === 0) return;
    
    setIsGenerating(true);
    try {
      const template = language === 'nodejs' 
        ? generateNodeJSTemplate(serverConfig, parsedParameters)
        : generatePythonTemplate(serverConfig, parsedParameters);
      
      setGeneratedCode(template);
      setEditableCode(template);
    } catch (error) {
      console.error('Error generating:', error);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownload = () => {
    const codeToDownload = editableCode || generatedCode;
    if (!codeToDownload) return;
    
    const blob = new Blob([codeToDownload], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${serverConfig.binaryName}.${language === 'nodejs' ? 'js' : 'py'}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopyToClipboard = async () => {
    const codeToCopy = editableCode || generatedCode;
    if (codeToCopy) {
      try {
        await navigator.clipboard.writeText(codeToCopy);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        console.error('Failed to copy: ', err);
      }
    }
  };

  const handleEditParameter = (paramToEdit: ParsedParameter) => {
    setEditingParameter(paramToEdit);
    setEditedParameter({ ...paramToEdit });
  };

  const handleSaveParameter = () => {
    if (editingParameter && editedParameter) {
      const updatedParameters = parsedParameters.map(p =>
        p === editingParameter ? editedParameter : p
      );
      setParsedParameters(updatedParameters);
      setEditingParameter(null);
      setEditedParameter(null);
    }
  };

  const handleCancelEdit = () => {
    setEditingParameter(null);
    setEditedParameter(null);
  };

  const handleParameterChange = (field: keyof ParsedParameter, value: any) => {
    if (editedParameter) {
      setEditedParameter({ ...editedParameter, [field]: value });
    }
  };

  const handleDeleteParameter = (paramToDelete: ParsedParameter) => {
    const updatedParameters = parsedParameters.filter(p => p !== paramToDelete);
    setParsedParameters(updatedParameters);
  };

  const handleAddNewParameter = () => {
    setAddingNewParameter(true);
    setNewParameter({
      name: '',
      description: '',
      type: 'option',
      required: false,
      takesValue: true,
      expectsValue: true
    });
  };

  const handleSaveNewParameter = () => {
    if (newParameter.name.trim() && newParameter.description.trim()) {
      setParsedParameters([...parsedParameters, newParameter]);
      setAddingNewParameter(false);
      setNewParameter({
        name: '',
        description: '',
        type: 'option',
        required: false,
        takesValue: true,
        expectsValue: true
      });
    }
  };

  const handleCancelAddParameter = () => {
    setAddingNewParameter(false);
    setNewParameter({
      name: '',
      description: '',
      type: 'option',
      required: false,
      takesValue: true,
      expectsValue: true
    });
  };

  const handleNewParameterChange = (field: keyof ParsedParameter, value: any) => {
    setNewParameter(prev => ({
      ...prev,
      [field]: value
    }));
  };

  // Funciones de manejo para configuración de seguridad
  const handleSecurityToggle = () => {
    setSecurityConfig(prev => ({
      ...prev,
      enabled: !prev.enabled
    }));
  };

  const handleSecurityLevelChange = (level: 'basic' | 'intermediate' | 'advanced') => {
    setSecurityConfig(prev => ({
      ...prev,
      level
    }));
  };

  const handleSecurityFieldChange = (section: keyof SecurityConfig, field: string, value: any) => {
    setSecurityConfig(prev => {
      if (section === 'restrictions') {
        return {
          ...prev,
          restrictions: {
            ...prev.restrictions,
            [field]: value
          }
        };
      } else if (section === 'sandboxing') {
        return {
          ...prev,
          sandboxing: {
            ...prev.sandboxing,
            [field]: value
          }
        };
      } else if (section === 'validation') {
        return {
          ...prev,
          validation: {
            ...prev.validation,
            [field]: value
          }
        };
      }
      return prev;
    });
  };

  const handleArrayFieldChange = (section: keyof SecurityConfig, field: string, value: string) => {
    const values = value.split(',').map(v => v.trim()).filter(v => v);
    setSecurityConfig(prev => {
      if (section === 'restrictions') {
        return {
          ...prev,
          restrictions: {
            ...prev.restrictions,
            [field]: values
          }
        };
      } else if (section === 'sandboxing') {
        return {
          ...prev,
          sandboxing: {
            ...prev.sandboxing,
            [field]: values
          }
        };
      }
      return prev;
    });
  };

  return (
    <div className="my-8 p-6 border border-skin-border rounded-lg bg-skin-card shadow-sm">
      {/* Estilos CSS para el editor de código */}
      <style dangerouslySetInnerHTML={{
        __html: `
          .code-editor-container {
            overflow: auto !important;
            overflow-x: auto !important;
            overflow-y: auto !important;
          }
          .code-editor-container > div {
            overflow: visible !important;
            min-width: 100% !important;
          }
          .code-editor-textarea {
            white-space: pre !important;
            word-wrap: normal !important;
            overflow-wrap: normal !important;
            overflow: hidden !important;
            resize: none !important;
            min-width: 100% !important;
            width: 100% !important;
          }
          .code-editor-pre {
            white-space: pre !important;
            word-wrap: normal !important;
            overflow-wrap: normal !important;
            word-break: normal !important;
            overflow: visible !important;
            min-width: 100% !important;
            width: max-content !important;
          }
          .code-editor-pre code {
            white-space: pre !important;
            word-wrap: normal !important;
            overflow-wrap: normal !important;
            word-break: normal !important;
          }
        `
      }} />
      
      {isHydrated && (
        <>
          <h3 className="text-base font-semibold mb-4 text-skin-accent">
            {t.title}
          </h3>
          
          <form onSubmit={(e) => e.preventDefault()} className="space-y-6">
            {/* Binary Help Input */}
            <div>
              <label 
                htmlFor="binary-help" 
                className="block text-sm font-medium text-skin-base mb-2"
              >
                {t.binaryHelpLabel}
              </label>
              <textarea
                id="binary-help"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder={t.binaryHelpPlaceholder}
                className="w-full h-32 p-3 border border-skin-border rounded-md bg-skin-fill text-skin-base placeholder-skin-base/60 focus:outline-none focus:ring-2 focus:ring-skin-accent focus:border-transparent resize-vertical"
                required
              />
            </div>

            {/* Language Selection */}
            <div>
              <label className="block text-sm font-medium text-skin-base mb-2">
                {t.languageLabel}
              </label>
              <div className="flex space-x-4">
                <label className="flex items-center text-skin-base">
                  <input
                    type="radio"
                    value="nodejs"
                    checked={language === 'nodejs'}
                    onChange={(e) => setLanguage(e.target.value as 'nodejs' | 'python')}
                    className="mr-2"
                  />
                  {t.nodejs}
                </label>
                <label className="flex items-center text-skin-base">
                  <input
                    type="radio"
                    value="python"
                    checked={language === 'python'}
                    onChange={(e) => setLanguage(e.target.value as 'nodejs' | 'python')}
                    className="mr-2"
                  />
                  {t.python}
                </label>
              </div>
            </div>

            {/* Server Configuration */}
            <div>
              <h4 className="text-lg font-medium text-skin-base mb-3">{t.serverConfigLabel}</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <label className="block text-sm font-medium text-skin-base mb-1">
                    {t.binaryNameLabel}
                  </label>
                  <input
                    type="text"
                    value={serverConfig.binaryName}
                    onChange={(e) => setServerConfig({...serverConfig, binaryName: e.target.value})}
                    placeholder={t.binaryNamePlaceholder}
                    className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-skin-base mb-1">
                    {t.serverNameLabel}
                  </label>
                  <input
                    type="text"
                    value={serverConfig.name}
                    onChange={(e) => setServerConfig({...serverConfig, name: e.target.value})}
                    placeholder={t.serverNamePlaceholder}
                    className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-skin-base mb-1">
                    {t.serverDescriptionLabel}
                  </label>
                  <input
                    type="text"
                    value={serverConfig.description}
                    onChange={(e) => setServerConfig({...serverConfig, description: e.target.value})}
                    placeholder={t.serverDescriptionPlaceholder}
                    className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-skin-base mb-1">
                    {t.serverVersionLabel}
                  </label>
                  <input
                    type="text"
                    value={serverConfig.version}
                    onChange={(e) => setServerConfig({...serverConfig, version: e.target.value})}
                    placeholder={t.serverVersionPlaceholder}
                    className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                    required
                  />
                </div>
              </div>
            </div>

            {/* Security Configuration */}
            <div className="border border-skin-border rounded-lg p-4 bg-skin-fill">
              <div className="flex items-center justify-between mb-4">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={securityConfig.enabled}
                    onChange={handleSecurityToggle}
                    className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                  />
                  <span className="text-sm font-medium text-skin-base">{t.enableSecurityLabel}</span>
                </label>
              </div>

              {securityConfig.enabled && (
                <div className="space-y-6">
                  {/* Security Level */}
                  <div>
                    <label className="block text-sm font-medium text-skin-base mb-2">
                      {t.securityLevelLabel}
                    </label>
                    <div className="flex space-x-4">
                      <label className="flex items-center">
                        <input
                          type="radio"
                          value="basic"
                          checked={securityConfig.level === 'basic'}
                          onChange={() => handleSecurityLevelChange('basic')}
                          className="mr-2"
                        />
                        <span className="text-sm text-skin-base">{t.securityLevelBasic}</span>
                      </label>
                      <label className="flex items-center">
                        <input
                          type="radio"
                          value="intermediate"
                          checked={securityConfig.level === 'intermediate'}
                          onChange={() => handleSecurityLevelChange('intermediate')}
                          className="mr-2"
                        />
                        <span className="text-sm text-skin-base">{t.securityLevelIntermediate}</span>
                      </label>
                      <label className="flex items-center">
                        <input
                          type="radio"
                          value="advanced"
                          checked={securityConfig.level === 'advanced'}
                          onChange={() => handleSecurityLevelChange('advanced')}
                          className="mr-2"
                        />
                        <span className="text-sm text-skin-base">{t.securityLevelAdvanced}</span>
                      </label>
                    </div>
                    <p className="text-xs text-skin-base/70 mt-1">
                      {securityConfig.level === 'basic' && t.securityBasicHelp}
                      {securityConfig.level === 'intermediate' && t.securityIntermediateHelp}
                      {securityConfig.level === 'advanced' && t.securityAdvancedHelp}
                    </p>
                  </div>

                  {/* Execution Restrictions */}
                  <div>
                    <h5 className="text-md font-medium text-skin-base mb-3">{t.restrictionsLabel}</h5>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-skin-base mb-1">
                          {t.allowedHostsLabel}
                        </label>
                        <input
                          type="text"
                          value={securityConfig.restrictions.allowedHosts.join(', ')}
                          onChange={(e) => handleArrayFieldChange('restrictions', 'allowedHosts', e.target.value)}
                          placeholder={t.allowedHostsPlaceholder}
                          className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-skin-base mb-1">
                          {t.forbiddenPatternsLabel}
                        </label>
                        <input
                          type="text"
                          value={securityConfig.restrictions.forbiddenPatterns.join(', ')}
                          onChange={(e) => handleArrayFieldChange('restrictions', 'forbiddenPatterns', e.target.value)}
                          placeholder={t.forbiddenPatternsPlaceholder}
                          className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-skin-base mb-1">
                          {t.maxExecutionTimeLabel}
                        </label>
                        <input
                          type="number"
                          value={securityConfig.restrictions.maxExecutionTime}
                          onChange={(e) => handleSecurityFieldChange('restrictions', 'maxExecutionTime', parseInt(e.target.value) || 30)}
                          className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent text-sm"
                          min="1"
                          max="300"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-skin-base mb-1">
                          {t.maxMemoryLabel}
                        </label>
                        <input
                          type="number"
                          value={securityConfig.restrictions.maxMemoryMB}
                          onChange={(e) => handleSecurityFieldChange('restrictions', 'maxMemoryMB', parseInt(e.target.value) || 512)}
                          className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent text-sm"
                          min="64"
                          max="2048"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Validation Options */}
                  <div>
                    <h5 className="text-md font-medium text-skin-base mb-3">{t.validationLabel}</h5>
                    <div className="space-y-2">
                      <label className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={securityConfig.validation.enableInputSanitization}
                          onChange={(e) => handleSecurityFieldChange('validation', 'enableInputSanitization', e.target.checked)}
                          className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                        />
                        <span className="text-sm text-skin-base">{t.enableInputSanitizationLabel}</span>
                      </label>
                      <label className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={securityConfig.validation.enableOutputFiltering}
                          onChange={(e) => handleSecurityFieldChange('validation', 'enableOutputFiltering', e.target.checked)}
                          className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                        />
                        <span className="text-sm text-skin-base">{t.enableOutputFilteringLabel}</span>
                      </label>
                      <label className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={securityConfig.validation.enableCommandWhitelist}
                          onChange={(e) => handleSecurityFieldChange('validation', 'enableCommandWhitelist', e.target.checked)}
                          className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                        />
                        <span className="text-sm text-skin-base">{t.enableCommandWhitelistLabel}</span>
                      </label>
                    </div>
                  </div>

                  {/* Advanced Options */}
                  {securityConfig.level === 'advanced' && (
                    <div>
                      <h5 className="text-md font-medium text-skin-base mb-3">{t.sandboxingLabel}</h5>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <label className="flex items-center space-x-2">
                            <input
                              type="checkbox"
                              checked={securityConfig.sandboxing.useContainer}
                              onChange={(e) => handleSecurityFieldChange('sandboxing', 'useContainer', e.target.checked)}
                              className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                            />
                            <span className="text-sm text-skin-base">{t.useContainerLabel}</span>
                          </label>
                          <label className="flex items-center space-x-2">
                            <input
                              type="checkbox"
                              checked={securityConfig.sandboxing.networkIsolation}
                              onChange={(e) => handleSecurityFieldChange('sandboxing', 'networkIsolation', e.target.checked)}
                              className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                            />
                            <span className="text-sm text-skin-base">{t.networkIsolationLabel}</span>
                          </label>
                        </div>
                        <div className="space-y-2">
                          <div>
                            <label className="block text-sm font-medium text-skin-base mb-1">
                              {t.runAsUserLabel}
                            </label>
                            <input
                              type="text"
                              value={securityConfig.sandboxing.runAsUser}
                              onChange={(e) => handleSecurityFieldChange('sandboxing', 'runAsUser', e.target.value)}
                              placeholder={t.runAsUserPlaceholder}
                              className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent text-sm"
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md p-3">
                    <p className="text-sm text-blue-800 dark:text-blue-200">
                      <strong>💡 {t.securityHelpText}</strong>
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex space-x-4">
              <button
                type="button"
                onClick={handleParse}
                disabled={isParsing || !inputText.trim()}
                className="px-4 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              >
                {isParsing ? (
                  <span className="flex items-center">
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    {t.parsingText}
                  </span>
                ) : (
                  t.parseButtonText
                )}
              </button>

              <button
                type="button"
                onClick={handleGenerate}
                disabled={isGenerating || parsedParameters.length === 0 || !serverConfig.name || !serverConfig.binaryName}
                className="px-4 py-2 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              >
                {isGenerating ? (
                  <span className="flex items-center">
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    {t.generatingText}
                  </span>
                ) : (
                  t.generateButtonText
                )}
              </button>
            </div>

            {/* Parsed Parameters Display */}
            {parsedParameters.length > 0 && (
              <div className="mt-6 p-4 bg-skin-fill rounded-lg border border-skin-border">
                {/* Parámetros Analizados */}
                <div className="mb-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-xl font-semibold text-skin-base">
                      {t.analyzedParametersLabel}
                    </h3>
                    <button
                      type="button"
                      onClick={handleAddNewParameter}
                      className="flex items-center space-x-2 px-3 py-1.5 bg-skin-accent text-skin-inverted text-sm font-medium rounded-md hover:bg-skin-accent-hover transition-colors"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                      </svg>
                      <span>{t.addParameterLabel}</span>
                    </button>
                  </div>
                  <div className="text-sm text-skin-base bg-skin-fill px-2 py-1 rounded border border-skin-border inline-block">
                    Total: {parsedParameters.length} | 
                    Flags: {parsedParameters.filter(p => p.type === 'flag').length} | 
                    Options: {parsedParameters.filter(p => p.type === 'option').length} | 
                    Args: {parsedParameters.filter(p => p.type === 'argument').length}
                  </div>
                </div>
                
                {/* Filtros */}
                <div className="mb-4 flex flex-wrap gap-2">
                  <button 
                    type="button"
                    onClick={() => setFilterType('all')}
                    className={`px-3 py-1 text-xs rounded ${
                      filterType === 'all' 
                        ? 'bg-skin-accent text-skin-inverted' 
                        : 'bg-skin-fill text-skin-base hover:bg-skin-accent hover:text-skin-inverted'
                    }`}
                  >
                    {t.filterAll}
                  </button>
                  <button 
                    type="button"
                    onClick={() => setFilterType('flag')}
                    className={`px-3 py-1 text-xs rounded ${
                      filterType === 'flag' 
                        ? 'bg-blue-600 text-white' 
                        : 'bg-skin-fill text-skin-base hover:bg-blue-600 hover:text-white'
                    }`}
                  >
                    {t.filterFlags} ({parsedParameters.filter(p => p.type === 'flag').length})
                  </button>
                  <button 
                    type="button"
                    onClick={() => setFilterType('option')}
                    className={`px-3 py-1 text-xs rounded ${
                      filterType === 'option' 
                        ? 'bg-green-600 text-white' 
                        : 'bg-skin-fill text-skin-base hover:bg-green-600 hover:text-white'
                    }`}
                  >
                    {t.filterOptions} ({parsedParameters.filter(p => p.type === 'option').length})
                  </button>
                  <button 
                    type="button"
                    onClick={() => setFilterType('argument')}
                    className={`px-3 py-1 text-xs rounded ${
                      filterType === 'argument' 
                        ? 'bg-orange-600 text-white' 
                        : 'bg-skin-fill text-skin-base hover:bg-orange-600 hover:text-white'
                    }`}
                  >
                    {t.filterArguments} ({parsedParameters.filter(p => p.type === 'argument').length})
                  </button>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {parsedParameters
                    .filter(param => filterType === 'all' || param.type === filterType)
                    .map((param) => (
                    <div key={param.name} className="p-4 bg-skin-fill rounded-lg border border-skin-border flex flex-col justify-between hover:border-skin-accent transition-colors">
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <div className="font-mono text-base text-skin-accent break-all">{param.name}</div>
                          <div className="flex items-center space-x-1">
                            <button
                              type="button"
                              onClick={() => handleEditParameter(param)}
                              className="p-1.5 text-skin-base/70 hover:text-skin-accent bg-transparent hover:bg-skin-accent/10 rounded-md transition-all duration-200"
                              aria-label={t.editParameterLabel}
                              title={t.editParameterLabel}
                            >
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.536L16.732 3.732z" />
                              </svg>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteParameter(param)}
                              className="p-1.5 text-skin-base/70 hover:text-red-500 bg-transparent hover:bg-red-500/10 rounded-md transition-all duration-200"
                              aria-label={t.deleteParameterLabel}
                              title={t.deleteParameterLabel}
                            >
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                              </svg>
                            </button>
                          </div>
                        </div>
                        <p className="text-sm text-skin-base mb-3 line-clamp-3">{param.description}</p>
                      </div>
                      <div className="flex items-center space-x-3 text-xs">
                        <span className={`px-2 py-1 rounded-full text-white font-medium ${
                          param.type === 'flag' ? 'bg-blue-600' :
                          param.type === 'option' ? 'bg-green-600' :
                          'bg-orange-600'
                        }`}>
                          {param.type}
                        </span>
                        <span className="text-skin-base/70">
                          {param.type === 'argument' ? (param.required ? 'Obligatorio' : 'Opcional') : ''}
                          {param.type === 'option' ? 'Toma valor' : ''}
                          {param.type === 'flag' ? 'Sin valor' : ''}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
                
                {/* Modal de edición de parámetro */}
                {editingParameter && editedParameter && (
                  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-skin-fill p-6 rounded-lg max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto">
                      <h3 className="text-lg font-medium text-skin-base mb-4">{t.editParametersTitle}</h3>
                      
                      <div className="space-y-4">
                        <div>
                          <label className="block text-sm font-medium text-skin-base mb-1">
                            {t.parameterNameLabel}
                          </label>
                          <input
                            type="text"
                            value={editedParameter.name}
                            onChange={(e) => handleParameterChange('name', e.target.value)}
                            className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-skin-base mb-1">
                            {t.parameterDescriptionLabel}
                          </label>
                          <textarea
                            value={editedParameter.description}
                            onChange={(e) => handleParameterChange('description', e.target.value)}
                            className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent resize-vertical"
                            rows={3}
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-skin-base mb-1">
                            {t.parameterTypeLabel}
                          </label>
                          <select
                            value={editedParameter.type}
                            onChange={(e) => {
                              const newType = e.target.value as 'option' | 'argument' | 'flag';
                              
                              // Crear un nuevo objeto con todos los cambios
                              const updatedParameter = { ...editedParameter, type: newType };
                              
                              // Auto-configurar valores según el tipo
                              if (newType === 'flag') {
                                updatedParameter.takesValue = false;
                                updatedParameter.expectsValue = false;
                                updatedParameter.required = false;
                              } else if (newType === 'option') {
                                updatedParameter.takesValue = true;
                                updatedParameter.expectsValue = true;
                                updatedParameter.required = false;
                              } else if (newType === 'argument') {
                                updatedParameter.takesValue = true;
                                updatedParameter.expectsValue = true;
                                // required se mantiene como esté
                              }
                              
                              setEditedParameter(updatedParameter);
                            }}
                            className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                          >
                            <option value="flag">{t.flagDescription}</option>
                            <option value="option">{t.optionDescription}</option>
                            <option value="argument">{t.argumentDescription}</option>
                          </select>
                        </div>
                        
                        <div className="grid grid-cols-1 gap-4">
                          {editedParameter.type === 'argument' && (
                            <div>
                              <label className="flex items-center">
                                <input
                                  type="checkbox"
                                  checked={editedParameter.required}
                                  onChange={(e) => handleParameterChange('required', e.target.checked)}
                                  className="mr-2"
                                />
                                {t.parameterRequiredLabel} (Argumento obligatorio)
                              </label>
                              <p className="text-xs text-skin-base/60 mt-1">
                                {t.argumentHelp}
                              </p>
                            </div>
                          )}
                          
                          {editedParameter.type === 'option' && (
                            <div>
                              <div className="text-sm text-skin-base/70 mb-2">
                                <strong>{t.optionHelp}</strong>
                              </div>
                              <div className="text-xs text-skin-base/60 space-y-1">
                                <div>• takesValue: true (siempre)</div>
                                <div>• expectsValue: true (siempre)</div>
                                <div>• required: false (siempre)</div>
                              </div>
                            </div>
                          )}
                          
                          {editedParameter.type === 'flag' && (
                            <div>
                              <div className="text-sm text-skin-base/70 mb-2">
                                <strong>{t.flagHelp}</strong>
                              </div>
                              <div className="text-xs text-skin-base/60 space-y-1">
                                <div>• takesValue: false (siempre)</div>
                                <div>• expectsValue: false (siempre)</div>
                                <div>• required: false (siempre)</div>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex space-x-3 mt-6">
                        <button
                          type="button"
                          onClick={handleSaveParameter}
                          className="px-4 py-2 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors"
                        >
                          {t.saveChangesLabel}
                        </button>
                        <button
                          type="button"
                          onClick={handleCancelEdit}
                          className="px-4 py-2 bg-gray-600 text-white font-medium rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 transition-colors"
                        >
                          {t.cancelLabel}
                        </button>
                      </div>
                    </div>
                  </div>
                )}
                
                {/* Modal para añadir nuevo parámetro */}
                {addingNewParameter && (
                  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-skin-fill p-6 rounded-lg max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto">
                      <h3 className="text-lg font-medium text-skin-base mb-4">{t.addNewParameterLabel}</h3>
                      
                      <div className="space-y-4">
                        <div>
                          <label className="block text-sm font-medium text-skin-base mb-1">
                            {t.newParameterLabel}
                          </label>
                          <input
                            type="text"
                            value={newParameter.name}
                            onChange={(e) => handleNewParameterChange('name', e.target.value)}
                            placeholder={t.newParameterPlaceholder}
                            className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-skin-base mb-1">
                            {t.newParameterDescriptionLabel}
                          </label>
                          <textarea
                            value={newParameter.description}
                            onChange={(e) => handleNewParameterChange('description', e.target.value)}
                            placeholder={t.newParameterDescriptionPlaceholder}
                            className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent resize-vertical"
                            rows={3}
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-skin-base mb-1">
                            {t.parameterTypeLabel}
                          </label>
                          <select
                            value={newParameter.type}
                            onChange={(e) => {
                              const newType = e.target.value as 'option' | 'argument' | 'flag';
                              const updatedParameter = { ...newParameter, type: newType };
                              
                              if (newType === 'flag') {
                                updatedParameter.takesValue = false;
                                updatedParameter.expectsValue = false;
                                updatedParameter.required = false;
                              } else if (newType === 'option') {
                                updatedParameter.takesValue = true;
                                updatedParameter.expectsValue = true;
                                updatedParameter.required = false;
                              } else if (newType === 'argument') {
                                updatedParameter.takesValue = true;
                                updatedParameter.expectsValue = true;
                              }
                              
                              setNewParameter(updatedParameter);
                            }}
                            className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                          >
                            <option value="flag">{t.flagDescription}</option>
                            <option value="option">{t.optionDescription}</option>
                            <option value="argument">{t.argumentDescription}</option>
                          </select>
                        </div>
                        
                        <div className="grid grid-cols-1 gap-4">
                          {newParameter.type === 'argument' && (
                            <div>
                              <label className="flex items-center">
                                <input
                                  type="checkbox"
                                  checked={newParameter.required}
                                  onChange={(e) => handleNewParameterChange('required', e.target.checked)}
                                  className="mr-2"
                                />
                                {t.parameterRequiredLabel} (Argumento obligatorio)
                              </label>
                              <p className="text-xs text-skin-base/60 mt-1">
                                {t.argumentHelp}
                              </p>
                            </div>
                          )}
                          
                          {newParameter.type === 'option' && (
                            <div>
                              <div className="text-sm text-skin-base/70 mb-2">
                                <strong>{t.optionHelp}</strong>
                              </div>
                              <div className="text-xs text-skin-base/60 space-y-1">
                                <div>• takesValue: true (siempre)</div>
                                <div>• expectsValue: true (siempre)</div>
                                <div>• required: false (siempre)</div>
                              </div>
                            </div>
                          )}
                          
                          {newParameter.type === 'flag' && (
                            <div>
                              <div className="text-sm text-skin-base/70 mb-2">
                                <strong>{t.flagHelp}</strong>
                              </div>
                              <div className="text-xs text-skin-base/60 space-y-1">
                                <div>• takesValue: false (siempre)</div>
                                <div>• expectsValue: false (siempre)</div>
                                <div>• required: false (siempre)</div>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="flex space-x-3 mt-6">
                        <button
                          type="button"
                          onClick={handleSaveNewParameter}
                          disabled={!newParameter.name.trim() || !newParameter.description.trim()}
                          className="px-4 py-2 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          {t.saveChangesLabel}
                        </button>
                        <button
                          type="button"
                          onClick={handleCancelAddParameter}
                          className="px-4 py-2 bg-gray-600 text-white font-medium rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 transition-colors"
                        >
                          {t.cancelLabel}
                        </button>
                      </div>
                    </div>
                  </div>
                )}
                
                {parsedParameters.filter(param => filterType === 'all' || param.type === filterType).length === 0 && (
                  <div className="text-center py-8 text-skin-base/60">
                    {t.noParametersOfType} {filterType === 'all' ? '' : filterType}
                  </div>
                )}
                
                {/* Botón de generar MCP al final de los parámetros */}
                {parsedParameters.length > 0 && (
                  <div className="mt-6 pt-4 border-t border-skin-border">
                    <div className="flex justify-center">
                      <button
                        type="button"
                        onClick={handleGenerate}
                        disabled={isGenerating || !serverConfig.name || !serverConfig.binaryName}
                        className="px-6 py-3 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                      >
                        {isGenerating ? (
                          <span className="flex items-center">
                            <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            {t.generatingText}
                          </span>
                        ) : (
                          t.generateButtonText
                        )}
                      </button>
                    </div>
                    <p className="text-xs text-skin-base/60 text-center mt-2">
                      {t.generateMCPHelp}
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Generated Code Display with Editor */}
            {generatedCode && (
              <div className="mt-6">
                <div className="flex justify-between items-center mb-3">
                  <h4 className="text-lg font-medium text-skin-base">{t.generatedCodeLabel}</h4>
                  <div className="flex space-x-2">
                    <button
                      type="button"
                      onClick={handleCopyToClipboard}
                      className="px-3 py-1 bg-skin-accent text-skin-inverted text-sm rounded hover:bg-skin-accent-hover transition-colors"
                    >
                      {copied ? t.copiedToClipboard : t.copyToClipboard}
                    </button>
                    <button
                      type="button"
                      onClick={handleDownload}
                      className="px-3 py-1 bg-green-600 text-white text-sm rounded hover:bg-green-700 transition-colors"
                    >
                      {t.downloadButtonText}
                    </button>
                  </div>
                </div>
                <div 
                  className="code-editor-container border border-skin-border rounded-lg"
                  style={{
                    height: '500px',
                    maxHeight: '600px',
                    overflow: 'auto',
                    position: 'relative'
                  }}
                >
                  <div style={{ 
                    minWidth: 'max-content',
                    minHeight: '500px',
                    width: '100%'
                  }}>
                    <Editor
                      value={editableCode}
                      onValueChange={code => setEditableCode(code)}
                      highlight={code => Prism.highlight(code, language === 'nodejs' ? Prism.languages.js : Prism.languages.python, language === 'nodejs' ? 'javascript' : 'python')}
                      padding={16}
                      textareaClassName="code-editor-textarea"
                      preClassName="code-editor-pre"
                      style={{
                        fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", Menlo, monospace',
                        fontSize: 14,
                        backgroundColor: currentTheme === 'dark' ? 'rgb(39, 40, 34)' : 'rgb(250, 250, 250)',
                        color: currentTheme === 'dark' ? 'rgb(248, 248, 242)' : 'rgb(51, 51, 51)',
                        minHeight: '500px',
                        border: 'none',
                        outline: 'none',
                        resize: 'none',
                        width: '100%',
                        minWidth: 'max-content'
                      }}
                    />
                  </div>
                </div>
                <p className="text-xs text-skin-base/60 mt-2">
                  {t.editCodeLabel}: Puedes editar el código directamente en el editor de arriba
                </p>
              </div>
            )}
          </form>
          
          <div className="mt-8 p-4 bg-skin-fill rounded-lg border border-skin-border">
            <h2 className="text-base font-semibold mb-2">{t.installationTitle}</h2>
            <div className="space-y-4">
              <div>
                <h3 className="font-medium text-skin-base mb-2">{t.prerequisitesTitle}</h3>
                <ul className="list-disc list-inside space-y-1 text-sm text-skin-base/70">
                  <li>{t.prerequisites1}</li>
                  <li>{t.prerequisites2}</li>
                  <li dangerouslySetInnerHTML={{ __html: t.prerequisites3 }} />
                </ul>
              </div>
              
              <div>
                <h3 className="font-medium text-skin-base mb-2">{t.installationStepsTitle}</h3>
                <ol className="list-decimal list-inside space-y-1 text-sm text-skin-base/70">
                  <li>{t.installationStep1}</li>
                  <li dangerouslySetInnerHTML={{ __html: t.installationStep2 }} />
                  <li dangerouslySetInnerHTML={{ __html: t.installationStep3 }} />
                </ol>
              </div>
              
              <div>
                <h3 className="font-medium text-skin-base mb-2">{t.usingWithLLMsTitle}</h3>
                <ul className="list-disc list-inside space-y-1 text-sm text-skin-base/70">
                  <li><strong>{t.claudeDesktop}</strong> <a href={t.claudeDesktopLink} target="_blank" rel="noopener noreferrer" className="text-skin-accent hover:underline">{t.claudeDesktopText}</a></li>
                  <li><strong>{t.chatgptText}</strong> <a href={t.chatgptLink} target="_blank" rel="noopener noreferrer" className="text-skin-accent hover:underline">{t.chatgptHelpText}</a></li>
                  <li><strong>{t.ollamaText}</strong> <a href={t.ollamaLink} target="_blank" rel="noopener noreferrer" className="text-skin-accent hover:underline">{t.configureMCPText}</a></li>
                  <li><strong>{t.testing}</strong> {t.testingText}</li>
                </ul>
              </div>
              
              <div>
                <h3 className="font-medium text-skin-base mb-2">{t.securityNotesTitle}</h3>
                <ul className="list-disc list-inside space-y-1 text-sm text-skin-base/70">
                  <li>{t.securityNote1}</li>
                  <li>{t.securityNote2}</li>
                  <li>{t.securityNote3}</li>
                </ul>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
} 