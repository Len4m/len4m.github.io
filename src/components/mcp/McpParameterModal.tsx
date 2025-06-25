import React, { useState, useEffect, useRef } from 'react';
import type { ParsedParameter } from './types';

interface Props {
  isOpen: boolean;
  parameter: ParsedParameter | null;
  onSave: (updatedParameter: ParsedParameter) => void;
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
  const [localParameter, setLocalParameter] = useState<ParsedParameter | null>(null);
  const modalKeyRef = useRef<string>('');

  // Inicializar el parámetro local solo cuando se abre el modal con un parámetro diferente
  useEffect(() => {
    if (isOpen && parameter) {
      const newKey = `${parameter.name}-${parameter.type}-${parameter.description}`;
      if (newKey !== modalKeyRef.current) {
        modalKeyRef.current = newKey;
        setLocalParameter({ ...parameter });
      }
    } else if (!isOpen) {
      modalKeyRef.current = '';
      setLocalParameter(null);
    }
  }, [isOpen, parameter]);

  if (!isOpen || !localParameter) return null;

  const handleTypeChange = (newType: 'option' | 'argument' | 'flag') => {
    // Actualizar el parámetro local
    const updatedParameter = { ...localParameter, type: newType };
    
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
    
    setLocalParameter(updatedParameter);
    
    // Propagar cambios al padre
    onChange('type', newType);
    onChange('takesValue', updatedParameter.takesValue);
    onChange('expectsValue', updatedParameter.expectsValue);
    if (newType !== 'argument') {
      onChange('required', updatedParameter.required);
    }
  };

  const handleFieldChange = (field: keyof ParsedParameter, value: any) => {
    const updatedParameter = { ...localParameter, [field]: value };
    setLocalParameter(updatedParameter);
    onChange(field, value);
  };

  const handleSave = () => {
    if (localParameter) {
      onSave(localParameter);
    }
  };

  // Función para generar placeholder dinámico según el tipo
  const getParameterNamePlaceholder = (type: 'option' | 'argument' | 'flag'): string => {
    switch (type) {
      case 'flag':
        return '--nombrebandera o -n';
      case 'option':
        return '--nombreopcion o -n';
      case 'argument':
        return 'NOMBRE_ARGUMENTO';
      default:
        return '';
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-skin-fill p-6 rounded-lg max-w-md w-full mx-4 max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-medium text-skin-base mb-4 mt-0">
          {isNew ? t.addNewParameterLabel : t.editParametersTitle}
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-skin-base mb-1">
              {t.parameterNameLabel}
            </label>
            <input
              type="text"
              value={localParameter.name}
              onChange={(e) => handleFieldChange('name', e.target.value)}
              placeholder={getParameterNamePlaceholder(localParameter.type)}
              className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-skin-base mb-1">
              {t.parameterDescriptionLabel}
            </label>
            <textarea
              value={localParameter.description}
              onChange={(e) => handleFieldChange('description', e.target.value)}
              placeholder={isNew ? t.newParameterDescriptionPlaceholder : undefined}
              className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent resize-vertical"
              rows={3}
            />
          </div>
          
          {/* Campo valor por defecto solo para option y argument */}
          {(localParameter.type === 'option' || localParameter.type === 'argument') && (
            <div>
              <label className="block text-sm font-medium text-skin-base mb-1">
                {t.parameterDefaultValueLabel || 'Default Value'}
              </label>
              <input
                type="text"
                value={localParameter.defaultValue || ''}
                onChange={(e) => handleFieldChange('defaultValue', e.target.value || undefined)}
                placeholder={t.parameterDefaultValuePlaceholder || 'e.g., true, false, "default text"'}
                className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
              />
              <p className="text-xs text-skin-base/60 mt-1">
                {t.parameterDefaultValueHelp || 'Optional default value for this parameter'}
              </p>
            </div>
          )}
          
          <div>
            <label className="block text-sm font-medium text-skin-base mb-1">
              {t.parameterTypeLabel}
            </label>
            <select
              value={localParameter.type}
              onChange={(e) => handleTypeChange(e.target.value as 'option' | 'argument' | 'flag')}
              className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
            >
              <option value="flag">{t.flagDescription}</option>
              <option value="option">{t.optionDescription}</option>
              <option value="argument">{t.argumentDescription}</option>
            </select>
          </div>
          
          <div className="grid grid-cols-1 gap-4">
            {(localParameter.type === 'argument' || localParameter.type === 'option' || localParameter.type === 'flag') && (
              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={localParameter.required}
                    onChange={(e) => handleFieldChange('required', e.target.checked)}
                    className="mr-2"
                  />
                  {t.parameterRequiredLabel}
                </label>
                <p className="text-xs text-skin-base/60 mt-1">
                  {localParameter.type === 'argument' && t.argumentHelp}
                  {localParameter.type === 'option' && t.optionHelp}
                  {localParameter.type === 'flag' && t.flagHelp}
                </p>
              </div>
            )}
            {localParameter.type === 'argument' && (
              <div>
                <label className="block text-sm font-medium text-skin-base mb-1">
                  {t.parameterPositionLabel}
                </label>
                <input
                  type="number"
                  min={1}
                  value={localParameter.position || ''}
                  onChange={(e) => handleFieldChange('position', e.target.value ? parseInt(e.target.value, 10) : undefined)}
                  placeholder={t.parameterPositionPlaceholder}
                  className="w-full p-2 border border-skin-border rounded-md bg-skin-fill text-skin-base focus:outline-none focus:ring-2 focus:ring-skin-accent"
                />
              </div>
            )}
          </div>
        </div>
        
        <div className="flex space-x-3 mt-6">
          <button
            type="button"
            onClick={handleSave}
            disabled={isNew && (!localParameter.name.trim() || !localParameter.description.trim())}
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