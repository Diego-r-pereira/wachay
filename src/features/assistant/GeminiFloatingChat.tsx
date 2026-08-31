import React, { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { 
  Sparkles, 
  X, 
  Send, 
  Bot, 
  User, 
  BookOpen, 
  ShieldAlert, 
  Flame, 
  PhoneCall, 
  Trees, 
  HelpCircle,
  RotateCcw,
  Copy,
  Check
} from 'lucide-react';
import { useLanguage } from '../../context/LanguageContext';
import api from '../../services/api';

interface Message {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  sources?: string[];
}

export const GeminiFloatingChat: React.FC = () => {
  const { t, lang } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);
  const [inputMsg, setInputMsg] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'ai',
      text: t('assistant.welcome'),
    },
  ]);

  // Update welcome message dynamically when language changes if no user messages exist yet
  useEffect(() => {
    setMessages((prev) => {
      if (prev.length === 1 && prev[0].id === 'welcome') {
        return [
          {
            id: 'welcome',
            sender: 'ai',
            text: t('assistant.welcome'),
          },
        ];
      }
      return prev;
    });
  }, [lang, t]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen, isLoading]);

  const sendQuery = async (queryText: string) => {
    if (!queryText.trim() || isLoading) return;

    const userText = queryText.trim();
    setInputMsg('');

    const userMsg: Message = {
      id: Date.now().toString(),
      sender: 'user',
      text: userText,
    };

    setMessages((prev) => [...prev, userMsg]);
    setIsLoading(true);

    try {
      const res = await api.post('/ml/ask-ai', {
        message: userText,
        question: userText,
        lang: lang,
      });

      if (res.data && (res.data.response || res.data.answer)) {
        const aiMsg: Message = {
          id: (Date.now() + 1).toString(),
          sender: 'ai',
          text: res.data.response || res.data.answer,
          sources: res.data.sources || [],
        };
        setMessages((prev) => [...prev, aiMsg]);
      }
    } catch (err: any) {
      console.error('AI Ask error:', err);
      // Fallback local RAG response simulation in the active language
      const fallbackMsg: Message = {
        id: (Date.now() + 1).toString(),
        sender: 'ai',
        text: t('assistant.fallbackOffline'),
        sources: ['Directiva SERNAP Tunari - Art. 14', 'Manual de Contingencia SERNAP Cochabamba'],
      };
      setMessages((prev) => [...prev, fallbackMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    sendQuery(inputMsg);
  };

  const handleResetChat = () => {
    setMessages([
      {
        id: 'welcome',
        sender: 'ai',
        text: t('assistant.welcome'),
      },
    ]);
    setInputMsg('');
  };

  const handleCopyText = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const quickPromptChips = [
    { key: 'chip1', icon: Flame, text: t('assistant.chip1') },
    { key: 'chip2', icon: ShieldAlert, text: t('assistant.chip2') },
    { key: 'chip3', icon: Trees, text: t('assistant.chip3') },
    { key: 'chip4', icon: PhoneCall, text: t('assistant.chip4') },
  ];

  // Simple formatter for bold text (**text**)
  const renderFormattedText = (raw: string) => {
    const parts = raw.split(/(\*\*.*?\*\*)/g);
    return parts.map((part, idx) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={idx} className="font-semibold text-emerald-950 dark:text-emerald-200">{part.slice(2, -2)}</strong>;
      }
      return part;
    });
  };

  return (
    <div className="fixed bottom-6 right-6 z-50">
      
      {/* Floating Action Toggle Button */}
      {!isOpen && (
        <Button
          onClick={() => setIsOpen(true)}
          title={t('assistant.openToggle')}
          className="h-14 w-14 rounded-full bg-gradient-to-r from-[#3f644e] to-teal-700 hover:scale-105 text-white shadow-2xl transition-all border-2 border-white flex items-center justify-center relative group cursor-pointer"
        >
          <Sparkles className="w-6 h-6 text-amber-300 animate-pulse" />
          <span className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-emerald-400 border-2 border-white rounded-full"></span>
        </Button>
      )}

      {/* Expanded Chat Drawer Container */}
      {isOpen && (
        <div className="w-80 sm:w-96 h-[540px] bg-white dark:bg-slate-900 border border-[#3f644e]/30 rounded-2xl shadow-2xl flex flex-col overflow-hidden transition-all animate-in fade-in slide-in-from-bottom-5 duration-200">
          
          {/* Drawer Header */}
          <div className="bg-[#1c2c22] text-white p-3.5 flex items-center justify-between border-b border-[#3f644e]/30 shrink-0">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-[#3f644e]/30 border border-[#3f644e]">
                <Bot className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="font-bold text-xs tracking-tight flex items-center gap-1.5">
                  {t('assistant.title')}
                  <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-900/80 text-emerald-300">
                    {t('assistant.badge')}
                  </span>
                </h3>
                <div className="flex items-center gap-1 text-[10px] text-[#77877c]">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping inline-block"></span>
                  <span>{t('assistant.online')}</span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={handleResetChat}
                title={t('assistant.reset')}
                className="text-[#77877c] hover:text-amber-300 transition-colors p-1.5 rounded-md hover:bg-white/10 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                title={t('assistant.closeToggle')}
                className="text-[#77877c] hover:text-white transition-colors p-1.5 rounded-md hover:bg-white/10 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Messages Body */}
          <div className="flex-1 p-3 overflow-y-auto space-y-3 text-xs bg-[#fbfbf9]/60 dark:bg-slate-950/60">
            {messages.map((m) => (
              <div
                key={m.id}
                className={`flex gap-2 group ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {m.sender === 'ai' && (
                  <div className="w-6 h-6 rounded-full bg-[#3f644e] text-white flex items-center justify-center shrink-0 mt-0.5 shadow-xs">
                    <Bot className="w-3.5 h-3.5" />
                  </div>
                )}

                <div
                  className={`max-w-[82%] rounded-xl p-3 text-xs leading-relaxed relative ${
                    m.sender === 'user'
                      ? 'bg-[#3f644e] text-white rounded-tr-none shadow-xs'
                      : 'bg-white dark:bg-slate-900 text-[#203126] dark:text-slate-100 border border-[#e9e8e5] dark:border-slate-800 rounded-tl-none shadow-xs'
                  }`}
                >
                  <p className="whitespace-pre-line leading-relaxed">{renderFormattedText(m.text)}</p>
                  
                  {m.sources && m.sources.length > 0 && (
                    <div className="mt-2.5 pt-2 border-t border-[#3f644e]/15 text-[10px] text-[#77877c] dark:text-slate-400 flex items-center gap-1.5 flex-wrap">
                      <BookOpen className="w-3 h-3 text-[#3f644e] dark:text-emerald-400 shrink-0" />
                      <span className="font-medium">{t('assistant.sources')}</span>
                      <span className="bg-emerald-50 dark:bg-emerald-950/50 text-emerald-800 dark:text-emerald-300 px-1.5 py-0.5 rounded text-[9px] border border-emerald-200/50 dark:border-emerald-800/50">
                        {m.sources.join(', ')}
                      </span>
                    </div>
                  )}

                  {/* Copy Button on AI messages */}
                  {m.sender === 'ai' && m.id !== 'welcome' && (
                    <button
                      onClick={() => handleCopyText(m.id, m.text)}
                      title={t('assistant.copy')}
                      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1 text-[#77877c] hover:text-[#3f644e] dark:hover:text-emerald-400 rounded bg-white/80 dark:bg-slate-800/80 cursor-pointer shadow-2xs"
                    >
                      {copiedId === m.id ? (
                        <Check className="w-3 h-3 text-emerald-500" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  )}
                </div>

                {m.sender === 'user' && (
                  <div className="w-6 h-6 rounded-full bg-slate-700 text-white flex items-center justify-center shrink-0 mt-0.5 shadow-xs">
                    <User className="w-3.5 h-3.5" />
                  </div>
                )}
              </div>
            ))}

            {/* Quick Prompt Chips (Visible on initial conversation) */}
            {messages.length <= 3 && !isLoading && (
              <div className="mt-3 pt-2 border-t border-[#3f644e]/10 space-y-1.5 animate-in fade-in duration-300">
                <div className="flex items-center gap-1 text-[10px] font-semibold text-[#77877c] uppercase tracking-wider px-1">
                  <HelpCircle className="w-3 h-3 text-[#3f644e]" />
                  <span>{t('assistant.suggestionsTitle')}</span>
                </div>
                <div className="grid grid-cols-1 gap-1.5">
                  {quickPromptChips.map((chip) => {
                    const IconComponent = chip.icon;
                    return (
                      <button
                        key={chip.key}
                        onClick={() => sendQuery(chip.text)}
                        className="text-left text-[11px] p-2 rounded-lg bg-white/90 dark:bg-slate-800/90 hover:bg-[#3f644e]/10 dark:hover:bg-[#3f644e]/20 border border-[#3f644e]/20 hover:border-[#3f644e] text-[#203126] dark:text-slate-200 transition-all flex items-center gap-2 group cursor-pointer shadow-2xs"
                      >
                        <IconComponent className="w-3.5 h-3.5 text-[#3f644e] group-hover:scale-110 transition-transform shrink-0" />
                        <span className="line-clamp-1">{chip.text}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Modern Typing Wave Indicator */}
            {isLoading && (
              <div className="flex gap-2 items-center py-1 text-xs text-[#77877c] animate-in fade-in duration-200">
                <div className="w-6 h-6 rounded-full bg-[#3f644e] text-white flex items-center justify-center shrink-0">
                  <Bot className="w-3.5 h-3.5" />
                </div>
                <div className="bg-white dark:bg-slate-900 border border-[#e9e8e5] dark:border-slate-800 rounded-xl rounded-tl-none p-2.5 px-3.5 flex items-center gap-2 shadow-xs">
                  <div className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 bg-[#3f644e] rounded-full animate-bounce [animation-delay:-0.3s]"></span>
                    <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-bounce [animation-delay:-0.15s]"></span>
                    <span className="w-1.5 h-1.5 bg-teal-400 rounded-full animate-bounce"></span>
                  </div>
                  <span className="text-[10px] text-[#77877c] font-medium">{t('assistant.loading')}</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Chat Input Form */}
          <form onSubmit={handleSend} className="p-2.5 bg-white dark:bg-slate-900 border-t border-[#e9e8e5] dark:border-slate-800 flex gap-2 shrink-0">
            <Input
              placeholder={t('assistant.placeholder')}
              value={inputMsg}
              onChange={(e) => setInputMsg(e.target.value)}
              className="text-xs bg-[#fbfbf9] dark:bg-slate-800 focus-visible:ring-[#3f644e]"
            />
            <Button
              type="submit"
              disabled={isLoading || !inputMsg.trim()}
              size="icon"
              className="bg-[#3f644e] hover:bg-[#2e523b] text-white shrink-0 cursor-pointer disabled:opacity-50 transition-colors"
            >
              <Send className="w-4 h-4" />
            </Button>
          </form>

        </div>
      )}

    </div>
  );
};
