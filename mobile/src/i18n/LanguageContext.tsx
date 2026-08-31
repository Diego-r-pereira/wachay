import React, { createContext, useContext, useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { translations, Language } from './translations';

interface LanguageContextType {
  language: Language;
  t: typeof translations['es'];
  setLanguage: (lang: Language) => Promise<void>;
  toggleLanguage: () => Promise<void>;
}

const LanguageContext = createContext<LanguageContextType>({
  language: 'es',
  t: translations.es,
  setLanguage: async () => {},
  toggleLanguage: async () => {},
});

export const LanguageProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [language, setLangState] = useState<Language>('es');

  useEffect(() => {
    (async () => {
      try {
        const savedLang = await AsyncStorage.getItem('user_language');
        if (savedLang === 'en' || savedLang === 'es') {
          setLangState(savedLang);
        }
      } catch (e) {
        console.error('Error loading language preference', e);
      }
    })();
  }, []);

  const setLanguage = async (newLang: Language) => {
    setLangState(newLang);
    try {
      await AsyncStorage.setItem('user_language', newLang);
    } catch (e) {
      console.error('Error saving language preference', e);
    }
  };

  const toggleLanguage = async () => {
    const nextLang: Language = language === 'es' ? 'en' : 'es';
    await setLanguage(nextLang);
  };

  const currentTranslations = translations[language] || translations.es;

  return (
    <LanguageContext.Provider
      value={{
        language,
        t: currentTranslations,
        setLanguage,
        toggleLanguage,
      }}
    >
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = () => useContext(LanguageContext);
