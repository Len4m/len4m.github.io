import React, { useState, useEffect } from 'react';
import Editor from 'react-simple-code-editor';
import Prism from 'prismjs';
import 'prismjs/components/prism-clike';
import 'prismjs/components/prism-javascript';
import 'prismjs/components/prism-python';
import { translations } from './mcp/translations';
import McpBinaryHelpInput from './mcp/McpBinaryHelpInput';
import McpLanguageSelector from './mcp/McpLanguageSelector';
import McpServerConfig from './mcp/McpServerConfig';
import McpSecurityConfig from './mcp/McpSecurityConfig';
import McpParameters from './mcp/McpParameters';
import McpParameterModal from './mcp/McpParameterModal';
import McpInstructions from './mcp/McpInstructions';
import { generateNodeJSTemplate, generatePythonTemplate } from './mcp/templates';
import McpGenerateButton from './mcp/McpGenerateButton';

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

export default function McpCreator() {
  const [inputText, setInputText] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentLang, setCurrentLang] = useState<'en' | 'es' | 'ca'>('en');
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
    
    // Validar configuración del servidor antes de generar
    const { validateBinaryName, validateServerName, validateVersion } = await import('./mcp/validation');
    
    const binaryValidation = validateBinaryName(serverConfig.binaryName, currentLang, securityConfig.enabled);
    const serverValidation = validateServerName(serverConfig.name, currentLang, securityConfig.enabled);
    const versionValidation = validateVersion(serverConfig.version, currentLang);
    
    const validationErrors = [];
    
    if (!binaryValidation.isValid) {
      validationErrors.push(`${t.binaryNameLabel} ${binaryValidation.error}`);
    }
    
    if (!serverValidation.isValid) {
      validationErrors.push(`${t.serverNameLabel} ${serverValidation.error}`);
    }
    
    if (!versionValidation.isValid) {
      validationErrors.push(`${t.serverVersionLabel} ${versionValidation.error}`);
    }
    
    if (validationErrors.length > 0) {
      alert(`${t.validationErrors}\n${validationErrors.join('\n')}`);
      return;
    }
    
    setIsGenerating(true);
    try {
      const template = language === 'nodejs' 
        ? generateNodeJSTemplate(serverConfig, parsedParameters, securityConfig)
        : generatePythonTemplate(serverConfig, parsedParameters, securityConfig);
      
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

  const handleSaveParameter = (updatedParameter: ParsedParameter) => {
    if (editingParameter) {
      const updatedParameters = parsedParameters.map(p =>
        p === editingParameter ? updatedParameter : p
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
      const newEditedParameter = { ...editedParameter, [field]: value };
      setEditedParameter(newEditedParameter);
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

  const handleSaveNewParameter = (newParam?: ParsedParameter) => {
    const parameterToSave = newParam || newParameter;
    if (parameterToSave.name.trim() && parameterToSave.description.trim()) {
      setParsedParameters([...parsedParameters, parameterToSave]);
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
            <McpBinaryHelpInput
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder={t.binaryHelpPlaceholder}
              label={t.binaryHelpLabel}
              disabled={isParsing}
              />

            {/* Language Selection */}
            <McpLanguageSelector
              value={language}
                    onChange={(e) => setLanguage(e.target.value as 'nodejs' | 'python')}
              options={[
                { value: 'nodejs', label: t.nodejs },
                { value: 'python', label: t.python }
              ]}
            />

            {/* Server Configuration */}
            <McpServerConfig
              serverConfig={serverConfig}
              onChange={setServerConfig}
              t={t}
              currentLang={currentLang}
              securityConfig={securityConfig}
            />

            {/* Security Configuration */}
            <McpSecurityConfig
              securityConfig={securityConfig}
              onChange={setSecurityConfig}
              t={t}
            />

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

              <McpGenerateButton
                isGenerating={isGenerating}
                disabled={isGenerating || parsedParameters.length === 0 || !serverConfig.name || !serverConfig.binaryName}
                onClick={handleGenerate}
                t={t}
                className="px-4 py-2 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              />
            </div>

            {/* Parsed Parameters Display */}
            {parsedParameters.length > 0 && (
              <>
                <McpParameters
                  parsedParameters={parsedParameters}
                  filterType={filterType}
                  setFilterType={setFilterType}
                  onEditParameter={handleEditParameter}
                  onDeleteParameter={handleDeleteParameter}
                  onAddNewParameter={handleAddNewParameter}
                  t={t}
                />
                
                {/* Botón de generar MCP al final de los parámetros */}
                  <div className="mt-6 pt-4 border-t border-skin-border">
                    <div className="flex justify-center">
                    <McpGenerateButton
                      isGenerating={isGenerating}
                        disabled={isGenerating || !serverConfig.name || !serverConfig.binaryName}
                      onClick={handleGenerate}
                      t={t}
                    />
                    </div>
                    <p className="text-xs text-skin-base/60 text-center mt-2">
                      {t.generateMCPHelp}
                    </p>
                  </div>
              </>
                )}
          </form>

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
          
          <McpInstructions t={t} />
        </>
      )}

      {/* Modales de parámetros */}
      <McpParameterModal
        key={`edit-${editingParameter?.name || 'none'}`}
        isOpen={!!editingParameter}
        parameter={editedParameter}
        onSave={handleSaveParameter}
        onCancel={handleCancelEdit}
        onChange={handleParameterChange}
        t={t}
        isNew={false}
      />

      <McpParameterModal
        key="new-parameter"
        isOpen={addingNewParameter}
        parameter={newParameter}
        onSave={handleSaveNewParameter}
        onCancel={handleCancelAddParameter}
        onChange={handleNewParameterChange}
        t={t}
        isNew={true}
      />
    </div>
  );
} 