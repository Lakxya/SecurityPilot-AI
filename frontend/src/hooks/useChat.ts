import { useState, useEffect, useCallback, useRef } from 'react';
import { chatService, ChatMessageItem } from '../services/chatService';

export function useChat(projectId: string, activeDocType?: string, currentDocContent?: string) {
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamingText, setStreamingText] = useState('');
  const [error, setError] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  const loadHistory = useCallback(async () => {
    setIsLoadingHistory(true);
    try {
      const history = await chatService.fetchChatHistory(projectId);
      setMessages(history);
      setTimeout(scrollToBottom, 100);
    } catch {
      // Ignore initial history fetch error
    } finally {
      setIsLoadingHistory(false);
    }
  }, [projectId, scrollToBottom]);

  useEffect(() => {
    if (projectId) {
      loadHistory();
    }
  }, [projectId, loadHistory]);

  const sendMessage = useCallback(
    async (text: string) => {
      if (!text.trim() || isStreaming) return;

      const userMsg: ChatMessageItem = {
        role: 'user',
        content: text,
        doc_type: activeDocType,
        created_at: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, userMsg]);
      setIsStreaming(true);
      setStreamingText('');
      setError(null);

      setTimeout(scrollToBottom, 50);

      let accumulated = '';
      await chatService.streamChatMessage(
        projectId,
        text,
        activeDocType,
        currentDocContent,
        (chunk: string) => {
          accumulated += chunk;
          setStreamingText(accumulated);
          scrollToBottom();
        },
        () => {
          setIsStreaming(false);
          setMessages((prev) => [
            ...prev,
            {
              role: 'assistant',
              content: accumulated,
              doc_type: activeDocType,
              created_at: new Date().toISOString(),
            },
          ]);
          setStreamingText('');
          scrollToBottom();
        },
        (err: Error) => {
          setIsStreaming(false);
          setError(err.message);
        }
      );
    },
    [projectId, activeDocType, currentDocContent, isStreaming, scrollToBottom]
  );

  const clearHistory = useCallback(async () => {
    try {
      await chatService.clearChatHistory(projectId);
      setMessages([]);
    } catch (err) {
      console.error(err);
    }
  }, [projectId]);

  return {
    messages,
    isLoadingHistory,
    isStreaming,
    streamingText,
    error,
    messagesEndRef,
    sendMessage,
    clearHistory,
    loadHistory,
  };
}
