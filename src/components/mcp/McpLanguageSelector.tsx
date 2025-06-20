import React from 'react';

interface Option {
  value: 'nodejs' | 'python';
  label: string;
}

interface Props {
  value: 'nodejs' | 'python';
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  options: Option[];
}

const McpLanguageSelector: React.FC<Props> = ({ value, onChange, options }) => (
  <div>
    <label className="block text-sm font-medium text-skin-base mb-2">
      Lenguaje de Programación:
    </label>
    <div className="flex space-x-4">
      {options.map(opt => (
        <label key={opt.value} className="flex items-center text-skin-base">
          <input
            type="radio"
            value={opt.value}
            checked={value === opt.value}
            onChange={onChange}
            className="mr-2"
          />
          {opt.label}
        </label>
      ))}
    </div>
  </div>
);

export default McpLanguageSelector; 