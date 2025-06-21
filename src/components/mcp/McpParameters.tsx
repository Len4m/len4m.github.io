import React from 'react';
import type { ParsedParameter } from './types';

interface Props {
  parsedParameters: ParsedParameter[];
  filterType: 'all' | 'flag' | 'option' | 'argument';
  setFilterType: (type: 'all' | 'flag' | 'option' | 'argument') => void;
  onEditParameter: (param: ParsedParameter) => void;
  onDeleteParameter: (param: ParsedParameter) => void;
  onAddNewParameter: () => void;
  t: any;
}

const McpParameters: React.FC<Props> = ({ 
  parsedParameters, 
  filterType, 
  setFilterType, 
  onEditParameter, 
  onDeleteParameter, 
  onAddNewParameter, 
  t 
}) => {
  const filteredParameters = parsedParameters.filter(param => 
    filterType === 'all' || param.type === filterType
  );

  return (
    <div className="mt-6 p-4 bg-skin-fill rounded-lg border border-skin-border">
      {/* Parámetros Analizados */}
      <div className="mb-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="mt-0">
            {t.analyzedParametersLabel}
          </h3>
          <button
            type="button"
            onClick={onAddNewParameter}
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
      
      <div className="grid grid-cols-2 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredParameters.map((param) => (
          <div key={param.name} className="p-4 bg-skin-fill rounded-lg border border-skin-border flex flex-col justify-between hover:border-skin-accent transition-colors">
            <div>
              <div className="flex items-center justify-between">
                <div className="font-mono text-base text-skin-accent break-all">{param.name}</div>
                <div className="flex items-center space-x-1">
                  <button
                    type="button"
                    onClick={() => onEditParameter(param)}
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
                    onClick={() => onDeleteParameter(param)}
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
              <p className="text-sm text-skin-base mb-3 line-clamp-3 mt-1">{param.description}</p>
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
      
      {filteredParameters.length === 0 && (
        <div className="text-center py-8 text-skin-base/60">
          {t.noParametersOfType} {filterType === 'all' ? '' : filterType}
        </div>
      )}
    </div>
  );
};

export default McpParameters; 