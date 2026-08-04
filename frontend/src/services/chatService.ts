import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export interface ChatMessageItem {
  id?: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  doc_type?: string | null;
  created_at?: string;
}

export const chatService = {
  getAuthHeaders(): HeadersInit {
    const token = authService.getToken();
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };
  },

  async fetchChatHistory(projectId: string): Promise<ChatMessageItem[]> {
    const res = await fetch(`${API_BASE_URL}/chat/history/${projectId}`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to fetch chat history.');
    }

    const data = await res.json();
    return data.messages;
  },

  async clearChatHistory(projectId: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/chat/history/${projectId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to clear chat history.');
    }
  },

  async streamChatMessage(
    projectId: string,
    message: string,
    docType?: string,
    currentDocContent?: string,
    onChunk?: (chunk: string) => void,
    onComplete?: () => void,
    onError?: (err: Error) => void
  ): Promise<void> {
    try {
      const token = authService.getToken();
      const response = await fetch(`${API_BASE_URL}/chat/message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          project_id: projectId,
          message,
          doc_type: docType,
          current_doc_content: currentDocContent,
          provider: 'mock',
        }),
      });

      if (!response.ok || !response.body) {
        throw new Error('Failed to connect to AI Copilot stream.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim()) continue;

          const eventMatch = line.match(/^event:\s*(.+)$/m);
          const dataMatch = line.match(/^data:\s*(.+)$/m);

          const eventType = eventMatch ? eventMatch[1].trim() : 'message';
          const dataStr = dataMatch ? dataMatch[1].trim() : '';

          if (eventType === 'end') {
            if (onComplete) onComplete();
            return;
          }

          if (eventType === 'error') {
            try {
              const parsed = JSON.parse(dataStr);
              if (onError) onError(new Error(parsed.error || 'Copilot stream error.'));
            } catch {
              if (onError) onError(new Error('Copilot stream error.'));
            }
            return;
          }

          if (eventType === 'message' && dataStr) {
            try {
              const parsed = JSON.parse(dataStr);
              if (parsed.chunk && onChunk) {
                onChunk(parsed.chunk);
              }
            } catch {
              // Ignore partial parse chunks
            }
          }
        }
      }

      if (onComplete) onComplete();
    } catch (err) {
      if (onError) onError(err instanceof Error ? err : new Error('Chat streaming failed.'));
    }
  },
};
