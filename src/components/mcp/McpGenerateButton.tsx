import React from 'react';

interface Props {
  isGenerating: boolean;
  disabled: boolean;
  onClick: () => void;
  t: any;
  className?: string;
}

const McpGenerateButton: React.FC<Props> = ({ 
  isGenerating, 
  disabled, 
  onClick, 
  t, 
  className = "px-6 py-3 bg-green-600 text-white font-medium rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
}) => {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={className}
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
  );
};

export default McpGenerateButton; 