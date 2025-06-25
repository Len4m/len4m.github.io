import React from 'react';

interface Props {
  t: any;
}

const McpInstructions: React.FC<Props> = ({ t }) => {
  return (
    <div className="mt-8 p-4 bg-skin-fill rounded-lg border border-skin-border">
      <h2 className="font-semibold mb-2 mt-0">{t.installationTitle}</h2>
      <div className="space-y-4">
        <div>
          <h3 className="font-medium text-skin-base mb-2">{t.prerequisitesTitle}</h3>
          <ul className="list-disc list-inside space-y-1 text-sm text-skin-base/70">
            <li>{t.prerequisites1}</li>
            <li dangerouslySetInnerHTML={{ __html: t.prerequisites2 }} />
            <li>{t.prerequisites3}</li>
          </ul>
        </div>
        
        <div>
          <h3 className="font-medium text-skin-base mb-2">{t.installationStepsTitle}</h3>
          <ol className="list-decimal list-inside space-y-1 text-sm text-skin-base/70">
            <li>{t.installationStep1}</li>
            <li dangerouslySetInnerHTML={{ __html: t.installationStep2 }} />
            <li dangerouslySetInnerHTML={{ __html: t.installationStep3 }} />
            <li>
              {t.installationStep4}
              <div className="mt-2 ml-4">
                <pre className="bg-skin-card border border-skin-border rounded p-3 text-xs overflow-x-auto">
                  <code>{t.claudeConfigExample}</code>
                </pre>
                <p className="text-xs text-skin-base/60 mt-1">
                  {t.claudeConfigHelp}
                </p>
              </div>
            </li>
          </ol>
        </div>
        
        <div>
          <h3 className="font-medium text-skin-base mb-2">{t.usingWithLLMsTitle}</h3>
          <ul className="list-disc list-inside space-y-1 text-sm text-skin-base/70">
            <li><strong>{t.claudeDesktop}</strong> <a href={t.claudeDesktopLink} target="_blank" rel="noopener noreferrer" className="text-skin-accent hover:underline">{t.claudeDesktopText}</a></li>
            <li><strong>{t.chatgptText}</strong> <a href={t.chatgptLink} target="_blank" rel="noopener noreferrer" className="text-skin-accent hover:underline">{t.chatgptHelpText}</a></li>
            <li><strong>{t.testing}</strong> {t.testingText}</li>
          </ul>
        </div>
        
        <div>
          <h3 className="font-medium text-skin-base mb-2">{t.securityNotesTitle}</h3>
          <ul className="list-disc list-inside space-y-1 text-sm text-skin-base/70">
            <li>{t.securityNote1}</li>
            <li>{t.securityNote2}</li>
            <li>{t.securityNote3}</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default McpInstructions; 