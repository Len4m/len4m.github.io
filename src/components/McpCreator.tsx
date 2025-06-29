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
import { parseBinaryHelp } from './mcp/parseBinaryHelp';
import type { ParsedParameter, ServerConfig, SecurityConfig, ParameterSecurity } from './mcp/types';

export default function McpCreator() {
  const [inputText, setInputText] = useState('');
  const [currentLang, setCurrentLang] = useState<'en' | 'es' | 'ca'>('en');
  const [isHydrated, setIsHydrated] = useState(false);
  const [language, setLanguage] = useState<'nodejs' | 'python'>('nodejs');
  const [serverConfig, setServerConfig] = useState<ServerConfig>({
    name: '',
    description: '',
    version: '1.0.0',
    binaryName: '',
    timeout: 30
  });
  const [parsedParameters, setParsedParameters] = useState<ParsedParameter[]>([]);
  const [isParsing, setIsParsing] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedCode, setGeneratedCode] = useState('');
  const [editableCode, setEditableCode] = useState('');
  const [copied, setCopied] = useState(false);
  const [currentTheme, setCurrentTheme] = useState<'light' | 'dark'>('light');
  const [showBinaryHelp, setShowBinaryHelp] = useState(false);

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
    expectsValue: true,
    position: undefined
  });

  const [securityConfig, setSecurityConfig] = useState<SecurityConfig>({
    enabled: false,
    level: 'basic',
    restrictions: {
      allowedHosts: [],
      forbiddenPatterns: [],
      maxExecutionTime: 30,
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
    if (!serverConfig.name || !serverConfig.binaryName) return;
    
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
      expectsValue: true,
      position: undefined
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
        expectsValue: true,
        position: undefined
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
      expectsValue: true,
      position: undefined
    });
  };

  const handleNewParameterChange = (field: keyof ParsedParameter, value: any) => {
    setNewParameter(prev => ({
      ...prev,
      [field]: value
    }));
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
          <h3 className="font-semibold mb-4 mt-0 text-skin-accent">
            {t.title}
          </h3>
          
          <form onSubmit={(e) => e.preventDefault()} className="space-y-6">
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

            {/* Parameters Section - Grouped with binary help input and detection */}
            <div className="border-t border-skin-border pt-6">
              <div className="flex justify-between items-center mb-4">
                <h3 className="font-semibold text-skin-base mt-3">{t.analyzedParametersLabel}</h3>
                <div className="flex space-x-2">
                  <button
                    type="button"
                    onClick={() => setShowBinaryHelp(!showBinaryHelp)}
                    className="px-3 py-1 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 transition-colors flex items-center space-x-1"
                  >
                    <span className="text-sm">{showBinaryHelp ? '▼' : '▶'}</span>
                    <span>{showBinaryHelp ? t.hideBinaryHelp : t.showBinaryHelp}</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleAddNewParameter}
                    className="px-3 py-1 bg-green-600 text-white text-sm rounded hover:bg-green-700 transition-colors"
                  >
                    {t.addNewParameterLabel}
                  </button>
                </div>
              </div>

              {/* Binary Help Input and Detection - Collapsible */}
              {showBinaryHelp && (
                <div className="mb-6 p-4 bg-skin-fill rounded-lg border border-skin-border">
                  <div className="mb-4">
                    <McpBinaryHelpInput
                      value={inputText}
                      onChange={(e) => setInputText(e.target.value)}
                      placeholder={t.binaryHelpPlaceholder}
                      label={t.binaryHelpLabel}
                      disabled={isParsing}
                    />
                  </div>
                  
                  <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
                    <button
                      type="button"
                      onClick={handleParse}
                      disabled={isParsing || !inputText.trim()}
                      className="px-4 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200 self-start"
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
                    
                    <div className="flex items-center text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded-md px-3 py-2">
                      <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-2 text-amber-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                      <span>{t.autoDetectionWarning}</span>
                    </div>
                  </div>
                </div>
              )}
              
              {parsedParameters.length > 0 ? (
                <McpParameters
                  parsedParameters={parsedParameters}
                  filterType={filterType}
                  setFilterType={setFilterType}
                  onEditParameter={handleEditParameter}
                  onDeleteParameter={handleDeleteParameter}
                  onAddNewParameter={handleAddNewParameter}
                  t={t}
                />
              ) : (
                <div className="text-center py-8 border-2 border-dashed border-skin-border rounded-lg">
                  <p className="text-skin-base/60 mb-4">{t.noParametersFound}</p>
                  <button
                    type="button"
                    onClick={handleAddNewParameter}
                    className="px-4 py-2 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 transition-colors duration-200"
                  >
                    {t.addNewParameterLabel}
                  </button>
                </div>
              )}
            </div>

            {/* Generate MCP Button - Show when we have basic config */}
            {serverConfig.name && serverConfig.binaryName && (
              <div className="flex justify-center pt-4">
                <McpGenerateButton
                  isGenerating={isGenerating}
                  disabled={isGenerating || !serverConfig.name || !serverConfig.binaryName}
                  onClick={handleGenerate}
                  t={t}
                  className="px-6 py-3 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                />
              </div>
            )}
          </form>

            {/* Generated Code Display with Editor */}
            {generatedCode && (
              <div className="mt-6">
                <div className="flex justify-between items-center mb-3">
                  <h2 className="font-semibold mt-0">{t.generatedCodeLabel}</h2>
                  <div className="flex space-x-2">
                    <button
                      type="button"
                      onClick={handleCopyToClipboard}
                      title={copied ? t.copiedToClipboard : t.copyToClipboard}
                      className={`px-3 py-2 text-sm rounded-md transition-all duration-200 flex items-center space-x-1 ${
                        copied 
                          ? 'bg-green-600 text-white' 
                          : 'bg-blue-600 text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500'
                      }`}
                    >
                      {copied ? (
                        <>
                          <span className="text-lg">✓</span>
                          <span>{t.copiedToClipboard}</span>
                        </>
                      ) : (
                        <>
                          <span className="text-lg">📋</span>
                          <span>{t.copyToClipboard}</span>
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={handleDownload}
                      title={t.downloadButtonText}
                      className="px-3 py-2 bg-green-600 text-white text-sm rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 transition-all duration-200 flex items-center space-x-1"
                    >
                      <span className="text-lg">⬇️</span>
                      <span>{t.downloadButtonText}</span>
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