import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { translations } from '../lib/translations';

export type LanguageCode = 'es' | 'en' | 'qu';

interface LanguageContextType {
  lang: LanguageCode;
  setLang: (lang: LanguageCode) => void;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

export const LanguageProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [lang, setLangState] = useState<LanguageCode>(() => {
    try {
      const saved = localStorage.getItem('wachay_lang');
      return saved === 'es' || saved === 'en' || saved === 'qu' ? saved : 'es';
    } catch {
      return 'es';
    }
  });

  const setLang = (newLang: LanguageCode) => {
    setLangState(newLang);
    try {
      localStorage.setItem('wachay_lang', newLang);
      document.documentElement.lang = newLang;
    } catch (e) {
      console.error('Error saving language:', e);
    }
  };

  useEffect(() => {
    try {
      document.documentElement.lang = lang;
    } catch (e) {
      console.error('Error updating html lang:', e);
    }
  }, [lang]);

  const t = (key: string): string => {
    return translations[lang]?.[key] || translations['es']?.[key] || key;
  };

  return (
    <LanguageContext.Provider value={{ lang, setLang, t }}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = (): LanguageContextType => {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
};
