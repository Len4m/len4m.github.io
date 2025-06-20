import React, { useState, useEffect } from 'react';
import type { ServerConfig, SecurityConfig } from './types';
import { 
  validateBinaryName, 
  validateServerName, 
  validateVersion,
  sanitizeInput 
} from './validation';

interface Props {
  serverConfig: ServerConfig;
  onChange: (config: ServerConfig) => void;
  t: any;
  currentLang: 'en' | 'es' | 'ca';
  securityConfig: SecurityConfig;
}

const McpServerConfig: React.FC<Props> = ({ serverConfig, onChange, t, currentLang, securityConfig }) => {
  const [errors, setErrors] = useState<{
    binaryName?: string;
    name?: string;
    version?: string;
  }>({});

  // Validar en tiempo real cuando cambian los valores
  useEffect(() => {
    const newErrors: typeof errors = {};
    
    // Validar nombre del binario
    if (serverConfig.binaryName) {
      const binaryValidation = validateBinaryName(serverConfig.binaryName, currentLang, securityConfig.enabled);
      if (!binaryValidation.isValid) {
        newErrors.binaryName = binaryValidation.error;
      }
    }
    
    // Validar nombre del servidor
    if (serverConfig.name) {
      const serverValidation = validateServerName(serverConfig.name, currentLang, securityConfig.enabled);
      if (!serverValidation.isValid) {
        newErrors.name = serverValidation.error;
      }
    }
    
    // Validar versión
    if (serverConfig.version) {
      const versionValidation = validateVersion(serverConfig.version, currentLang);
      if (!versionValidation.isValid) {
        newErrors.version = versionValidation.error;
      }
    }
    
    setErrors(newErrors);
  }, [serverConfig.binaryName, serverConfig.name, serverConfig.version, currentLang, securityConfig.enabled]);

  // Función para manejar cambios con sanitización
  const handleBinaryNameChange = (value: string) => {
    const sanitized = sanitizeInput(value, 'binaryName');
    onChange({ ...serverConfig, binaryName: sanitized });
  };

  const handleServerNameChange = (value: string) => {
    const sanitized = sanitizeInput(value, 'serverName');
    onChange({ ...serverConfig, name: sanitized });
  };

  return (
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
            onChange={e => handleBinaryNameChange(e.target.value)}
            placeholder={t.binaryNamePlaceholder}
            className={`w-full p-2 border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent ${
              errors.binaryName ? 'border-red-500' : 'border-skin-border'
            }`}
            required
          />
          {errors.binaryName && (
            <p className="text-xs text-red-500 mt-1">{errors.binaryName}</p>
          )}
          <p className="text-xs text-skin-base/60 mt-1">
            {t.binaryNameHelp}
            {securityConfig.enabled ? (
              <span className="block mt-1 text-orange-600">
                {t.securityEnabledBinary}
              </span>
            ) : (
              <span className="block mt-1 text-blue-600">
                {t.securityDisabledBinary}
              </span>
            )}
          </p>
        </div>
        <div>
          <label className="block text-sm font-medium text-skin-base mb-1">
            {t.serverNameLabel}
          </label>
          <input
            type="text"
            value={serverConfig.name}
            onChange={e => handleServerNameChange(e.target.value)}
            placeholder={t.serverNamePlaceholder}
            className={`w-full p-2 border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent ${
              errors.name ? 'border-red-500' : 'border-skin-border'
            }`}
            required
          />
          {errors.name && (
            <p className="text-xs text-red-500 mt-1">{errors.name}</p>
          )}
          <p className="text-xs text-skin-base/60 mt-1">
            {t.serverNameHelp}
            {securityConfig.enabled ? (
              <span className="block mt-1 text-orange-600">
                {t.securityEnabledServer}
              </span>
            ) : (
              <span className="block mt-1 text-blue-600">
                {t.securityDisabledServer}
              </span>
            )}
          </p>
        </div>
        <div>
          <label className="block text-sm font-medium text-skin-base mb-1">
            {t.serverDescriptionLabel}
          </label>
          <input
            type="text"
            value={serverConfig.description}
            onChange={e => onChange({ ...serverConfig, description: e.target.value })}
            placeholder={t.serverDescriptionPlaceholder}
            className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
            required
            maxLength={200}
          />
          <p className="text-xs text-skin-base/60 mt-1">
            {t.descriptionHelp}
          </p>
        </div>
        <div>
          <label className="block text-sm font-medium text-skin-base mb-1">
            {t.serverVersionLabel}
          </label>
          <input
            type="text"
            value={serverConfig.version}
            onChange={e => onChange({ ...serverConfig, version: e.target.value })}
            placeholder={t.serverVersionPlaceholder}
            className={`w-full p-2 border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent ${
              errors.version ? 'border-red-500' : 'border-skin-border'
            }`}
            required
          />
          {errors.version && (
            <p className="text-xs text-red-500 mt-1">{errors.version}</p>
          )}
          <p className="text-xs text-skin-base/60 mt-1">
            {t.versionHelp}
          </p>
        </div>
      </div>
    </div>
  );
};

export default McpServerConfig; 