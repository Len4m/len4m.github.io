import React from 'react';

interface Props {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
  placeholder: string;
  label: string;
  disabled?: boolean;
}

const McpBinaryHelpInput: React.FC<Props> = ({ value, onChange, placeholder, label, disabled }) => (
  <div>
    <label 
      htmlFor="binary-help" 
      className="block text-sm font-medium text-skin-base mb-2"
    >
      {label}
    </label>
    <textarea
      id="binary-help"
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      className="w-full h-32 p-3 border border-skin-border rounded-md bg-skin-fill text-skin-base placeholder-skin-base/60 focus:outline-none focus:ring-2 focus:ring-skin-accent focus:border-transparent resize-vertical"
      required
      disabled={disabled}
    />
  </div>
);

export default McpBinaryHelpInput; 