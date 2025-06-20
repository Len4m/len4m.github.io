import React from 'react';
import type { ParsedParameter } from './types';

interface Props {
  isOpen: boolean;
  parameter: ParsedParameter | null;
  onSave: () => void;
  onCancel: () => void;
  onChange: (field: keyof ParsedParameter, value: any) => void;
  t: any;
  isNew?: boolean;
}

const McpParameterModal: React.FC<Props> = ({ 
  isOpen, 
  parameter, 
  onSave, 
  onCancel, 
  onChange, 
  t, 
  isNew = false 
}) => {
  if (!isOpen || !parameter) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-skin-fill p-6 rounded-lg max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-medium text-skin-base mb-4">
          {isNew ? t.addNewParameterLabel : t.editParametersTitle}
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-skin-base mb-1">
              {t.parameterNameLabel}
            </label>
            <input
              type="text"
              value={parameter.name}
              onChange={(e) => onChange('name', e.target.value)}
              placeholder={isNew ? t.newParameterPlaceholder : undefined}
              className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-skin-base mb-1">
              {t.parameterDescriptionLabel}
            </label>
            <textarea
              value={parameter.description}
              onChange={(e) => onChange('description', e.target.value)}
              placeholder={isNew ? t.newParameterDescriptionPlaceholder : undefined}
              className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent resize-vertical"
              rows={3}
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-skin-base mb-1">
              {t.parameterTypeLabel}
            </label>
            <select
              value={parameter.type}
              onChange={(e) => {
                const newType = e.target.value as 'option' | 'argument' | 'flag';
                
                // Crear un nuevo objeto con todos los cambios
                const updatedParameter = { ...parameter, type: newType };
                
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
                
                // Aplicar todos los cambios
                Object.entries(updatedParameter).forEach(([key, value]) => {
                  onChange(key as keyof ParsedParameter, value);
                });
              }}
              className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
            >
              <option value="flag">{t.flagDescription}</option>
              <option value="option">{t.optionDescription}</option>
              <option value="argument">{t.argumentDescription}</option>
            </select>
          </div>
          
          <div className="grid grid-cols-1 gap-4">
            {parameter.type === 'argument' && (
              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={parameter.required}
                    onChange={(e) => onChange('required', e.target.checked)}
                    className="mr-2"
                  />
                  {t.parameterRequiredLabel} (Argumento obligatorio)
                </label>
                <p className="text-xs text-skin-base/60 mt-1">
                  {t.argumentHelp}
                </p>
              </div>
            )}
            
            {parameter.type === 'option' && (
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
            
            {parameter.type === 'flag' && (
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
            onClick={onSave}
            disabled={isNew && (!parameter.name.trim() || !parameter.description.trim())}
            className="px-4 py-2 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {t.saveChangesLabel}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 bg-gray-600 text-white font-medium rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 transition-colors"
          >
            {t.cancelLabel}
          </button>
        </div>
      </div>
    </div>
  );
};

export default McpParameterModal; 