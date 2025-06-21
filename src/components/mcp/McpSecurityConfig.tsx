import React from 'react';
import type { SecurityConfig } from './types';

interface Props {
  securityConfig: SecurityConfig;
  onChange: (config: SecurityConfig) => void;
  t: any;
}

const McpSecurityConfig: React.FC<Props> = ({ securityConfig, onChange, t }) => {
  const handleSecurityToggle = () => {
    onChange({
      ...securityConfig,
      enabled: !securityConfig.enabled
    });
  };

  const handleSecurityLevelChange = (level: 'basic' | 'intermediate' | 'advanced') => {
    onChange({
      ...securityConfig,
      level
    });
  };

  const handleSecurityFieldChange = (section: keyof SecurityConfig, field: string, value: any) => {
    if (section === 'restrictions') {
      onChange({
        ...securityConfig,
        restrictions: {
          ...securityConfig.restrictions,
          [field]: value
        }
      });
    } else if (section === 'sandboxing') {
      onChange({
        ...securityConfig,
        sandboxing: {
          ...securityConfig.sandboxing,
          [field]: value
        }
      });
    } else if (section === 'validation') {
      onChange({
        ...securityConfig,
        validation: {
          ...securityConfig.validation,
          [field]: value
        }
      });
    }
  };

  const handleArrayFieldChange = (section: keyof SecurityConfig, field: string, value: string) => {
    const values = value.split(',').map(v => v.trim()).filter(v => v);
    if (section === 'restrictions') {
      onChange({
        ...securityConfig,
        restrictions: {
          ...securityConfig.restrictions,
          [field]: values
        }
      });
    } else if (section === 'sandboxing') {
      onChange({
        ...securityConfig,
        sandboxing: {
          ...securityConfig.sandboxing,
          [field]: values
        }
      });
    }
  };

  return (
    <div className="border border-skin-border rounded-lg p-4 bg-skin-fill">
      <div className="flex items-center justify-between">
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
        <div className="space-y-6 mt-4">
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
                  <label className="flex items-center space-x-2 opacity-50 cursor-not-allowed">
                    <input
                      type="checkbox"
                      checked={securityConfig.sandboxing.useContainer}
                      onChange={(e) => handleSecurityFieldChange('sandboxing', 'useContainer', e.target.checked)}
                      className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                      disabled
                    />
                    <span className="text-sm text-skin-base">{t.useContainerLabel}</span>
                  </label>
                  <label className="flex items-center space-x-2 opacity-50 cursor-not-allowed">
                    <input
                      type="checkbox"
                      checked={securityConfig.sandboxing.networkIsolation}
                      onChange={(e) => handleSecurityFieldChange('sandboxing', 'networkIsolation', e.target.checked)}
                      className="h-4 w-4 text-skin-accent focus:ring-skin-accent border-skin-border rounded"
                      disabled
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
  );
};

export default McpSecurityConfig; 