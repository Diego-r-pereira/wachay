import React, { useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TextInput,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { BrandColors } from '@/constants/theme';
import { PillBadge } from '../ui/PillBadge';
import { useLanguage } from '@/i18n/LanguageContext';

interface ChatMessage {
  sender: string;
  text: string;
  mode?: string;
}

interface WachayAIChatProps {
  chatHistory: ChatMessage[];
  chatMessage: string;
  chatLoading: boolean;
  onMessageChange: (text: string) => void;
  onSendMessage: () => void;
  onSendPresetMessage: (presetText: string) => void;
}

export const WachayAIChat: React.FC<WachayAIChatProps> = ({
  chatHistory,
  chatMessage,
  chatLoading,
  onMessageChange,
  onSendMessage,
  onSendPresetMessage,
}) => {
  const { t } = useLanguage();
  const scrollViewRef = useRef<ScrollView>(null);

  const presetChips = [
    t.chat.presetFire,
    t.chat.presetSmoke,
    t.chat.presetFirstAid,
    t.chat.presetPhones,
  ];

  useEffect(() => {
    scrollViewRef.current?.scrollToEnd({ animated: true });
  }, [chatHistory, chatLoading]);

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
    >
      {/* Top AI Header */}
      <View style={styles.header}>
        <View style={styles.headerTitleRow}>
          <View style={styles.botAvatar}>
            <Text style={styles.botEmoji}>🤖</Text>
          </View>
          <View>
            <Text style={styles.title}>{t.chat.title}</Text>
            <Text style={styles.subtitle}>{t.chat.subtitle}</Text>
          </View>
        </View>

        <PillBadge label={t.chat.badge} variant="teal" />
      </View>

      {/* Suggested Emergency Chips */}
      <View style={styles.chipsSection}>
        <Text style={styles.chipsLabel}>{t.chat.frequentTitle}</Text>
        <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.chipsScroll}>
          {presetChips.map((chip, i) => (
            <TouchableOpacity
              key={i}
              style={styles.chipButton}
              onPress={() => onSendPresetMessage(chip)}
            >
              <Text style={styles.chipText}>{chip}</Text>
            </TouchableOpacity>
          ))}
        </ScrollView>
      </View>

      {/* Messages Scroll Area */}
      <ScrollView
        ref={scrollViewRef}
        style={styles.messagesContainer}
        contentContainerStyle={styles.messagesContent}
        showsVerticalScrollIndicator={false}
      >
        {chatHistory.length === 0 ? (
          <View style={styles.emptyContainer}>
            <View style={styles.emptyIconCircle}>
              <Text style={{ fontSize: 32 }}>💬</Text>
            </View>
            <Text style={styles.emptyTitle}>{t.chat.emptyTitle}</Text>
            <Text style={styles.emptyDesc}>{t.chat.emptyDesc}</Text>
          </View>
        ) : (
          chatHistory.map((msg, idx) => {
            const isUser = msg.sender === 'user';
            return (
              <View
                key={idx}
                style={[
                  styles.bubble,
                  isUser ? styles.bubbleUser : styles.bubbleBot,
                ]}
              >
                <Text style={isUser ? styles.bubbleTextUser : styles.bubbleTextBot}>
                  {msg.text}
                </Text>
                {msg.mode && (
                  <View style={styles.modeTag}>
                    <Text style={styles.modeTagText}>
                      Modo: {msg.mode === 'gemini' ? t.chat.modeCloud : t.chat.modeLocal}
                    </Text>
                  </View>
                )}
              </View>
            );
          })
        )}

        {chatLoading && (
          <View style={[styles.bubble, styles.bubbleBot, styles.loadingBubble]}>
            <ActivityIndicator size="small" color={BrandColors.teal} />
            <Text style={styles.loadingText}>{t.chat.thinking}</Text>
          </View>
        )}
      </ScrollView>

      {/* Input Row */}
      <View style={styles.inputContainer}>
        <TextInput
          style={styles.input}
          value={chatMessage}
          onChangeText={onMessageChange}
          placeholder={t.chat.placeholder}
          placeholderTextColor={BrandColors.textMuted}
          multiline
        />
        <TouchableOpacity
          style={[styles.sendButton, (!chatMessage.trim() || chatLoading) && styles.sendButtonDisabled]}
          onPress={onSendMessage}
          disabled={!chatMessage.trim() || chatLoading}
        >
          <Text style={styles.sendIcon}>➔</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: BrandColors.darkObsidian,
    paddingHorizontal: 20,
    paddingTop: 10,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
    paddingTop: 8,
  },
  headerTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  botAvatar: {
    width: 38,
    height: 38,
    borderRadius: 19,
    backgroundColor: 'rgba(86, 134, 143, 0.2)',
    borderWidth: 1,
    borderColor: BrandColors.teal,
    justifyContent: 'center',
    alignItems: 'center',
  },
  botEmoji: {
    fontSize: 18,
  },
  title: {
    fontSize: 17,
    fontWeight: '900',
    color: BrandColors.textPrimary,
    letterSpacing: 1,
  },
  subtitle: {
    fontSize: 10,
    color: BrandColors.textSecondary,
    fontWeight: '600',
  },
  chipsSection: {
    marginBottom: 12,
  },
  chipsLabel: {
    fontSize: 11,
    color: BrandColors.textMuted,
    fontWeight: '700',
    marginBottom: 6,
    letterSpacing: 0.5,
  },
  chipsScroll: {
    gap: 8,
  },
  chipButton: {
    backgroundColor: BrandColors.surfaceElevated,
    borderWidth: 1,
    borderColor: 'rgba(86, 134, 143, 0.3)',
    borderRadius: 14,
    paddingVertical: 6,
    paddingHorizontal: 12,
  },
  chipText: {
    fontSize: 11,
    color: BrandColors.textPrimary,
    fontWeight: '600',
  },
  messagesContainer: {
    flex: 1,
  },
  messagesContent: {
    paddingVertical: 10,
    gap: 12,
  },
  emptyContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingTop: 40,
    paddingHorizontal: 20,
  },
  emptyIconCircle: {
    width: 64,
    height: 64,
    borderRadius: 32,
    backgroundColor: 'rgba(86, 134, 143, 0.15)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 14,
  },
  emptyTitle: {
    fontSize: 16,
    fontWeight: '800',
    color: BrandColors.textPrimary,
    marginBottom: 6,
  },
  emptyDesc: {
    fontSize: 13,
    lineHeight: 19,
    color: BrandColors.textSecondary,
    textAlign: 'center',
  },
  bubble: {
    maxWidth: '84%',
    borderRadius: 16,
    padding: 14,
  },
  bubbleUser: {
    alignSelf: 'flex-end',
    backgroundColor: BrandColors.forestSage,
    borderBottomRightRadius: 4,
  },
  bubbleBot: {
    alignSelf: 'flex-start',
    backgroundColor: BrandColors.surfaceElevated,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.08)',
    borderBottomLeftRadius: 4,
  },
  bubbleTextUser: {
    fontSize: 14,
    lineHeight: 20,
    color: '#FFFFFF',
    fontWeight: '500',
  },
  bubbleTextBot: {
    fontSize: 14,
    lineHeight: 20,
    color: BrandColors.textPrimary,
  },
  modeTag: {
    marginTop: 8,
    paddingTop: 6,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.08)',
  },
  modeTagText: {
    fontSize: 10,
    color: BrandColors.teal,
    fontWeight: '700',
  },
  loadingBubble: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  loadingText: {
    fontSize: 12,
    color: BrandColors.textSecondary,
    fontStyle: 'italic',
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    paddingVertical: 12,
    borderTopWidth: 1,
    borderTopColor: 'rgba(255, 255, 255, 0.06)',
  },
  input: {
    flex: 1,
    backgroundColor: BrandColors.surface,
    borderWidth: 1,
    borderColor: BrandColors.surfaceBorder,
    borderRadius: 20,
    paddingHorizontal: 16,
    paddingVertical: 10,
    fontSize: 14,
    color: BrandColors.textPrimary,
    maxHeight: 90,
  },
  sendButton: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: BrandColors.teal,
    justifyContent: 'center',
    alignItems: 'center',
  },
  sendButtonDisabled: {
    opacity: 0.4,
  },
  sendIcon: {
    fontSize: 18,
    color: '#FFFFFF',
    fontWeight: 'bold',
  },
});
