import { GeneratedDocumentSpec } from '../types/project';
import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export interface GenerateRequestPayload {
  doc_type: string;
  custom_instructions?: string;
  provider?: string;
}

export const generationService = {
  getAuthHeaders(): HeadersInit {
    const token = authService.getToken();
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };
  },

  async listProjectDocuments(projectId: string): Promise<GeneratedDocumentSpec[]> {
    const res = await fetch(`${API_BASE_URL}/generation/${projectId}/docs`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to fetch generated documents.');
    }

    return await res.json();
  },

  async fetchDocument(projectId: string, docType: string): Promise<GeneratedDocumentSpec> {
    const res = await fetch(`${API_BASE_URL}/generation/${projectId}/docs/${docType}`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error(`Document ${docType} not found.`);
    }

    return await res.json();
  },

  async fetchDocumentVersions(projectId: string, docType: string): Promise<GeneratedDocumentSpec[]> {
    const res = await fetch(`${API_BASE_URL}/generation/${projectId}/docs/${docType}/versions`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch version history for ${docType}.`);
    }

    return await res.json();
  },

  async fetchDocumentVersion(projectId: string, docType: string, version: number): Promise<GeneratedDocumentSpec> {
    const res = await fetch(`${API_BASE_URL}/generation/${projectId}/docs/${docType}/versions/${version}`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error(`Failed to fetch version ${version} for ${docType}.`);
    }

    return await res.json();
  },

  async saveDocument(projectId: string, docType: string, content: string): Promise<GeneratedDocumentSpec> {
    const res = await fetch(`${API_BASE_URL}/generation/${projectId}/docs/${docType}`, {
      method: 'PUT',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({ content }),
    });

    if (!res.ok) {
      throw new Error(`Failed to update document ${docType}.`);
    }

    return await res.json();
  },

  async streamDocument(
    projectId: string,
    payload: GenerateRequestPayload,
    onChunk: (chunk: string) => void,
    onComplete: () => void,
    onError: (err: Error) => void
  ): Promise<void> {
    try {
      const token = authService.getToken();
      const response = await fetch(`${API_BASE_URL}/generation/${projectId}/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok || !response.body) {
        throw new Error('Failed to initiate AI stream.');
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
            onComplete();
            return;
          }

          if (eventType === 'error') {
            try {
              const parsed = JSON.parse(dataStr);
              onError(new Error(parsed.error || 'AI generation stream error.'));
            } catch {
              onError(new Error('AI generation stream error.'));
            }
            return;
          }

          if (eventType === 'message' && dataStr) {
            try {
              const parsed = JSON.parse(dataStr);
              if (parsed.chunk) {
                onChunk(parsed.chunk);
              }
            } catch {
              // Ignore partial chunk parse failures
            }
          }
        }
      }

      onComplete();
    } catch (err) {
      onError(err instanceof Error ? err : new Error('Stream execution failed.'));
    }
  },
};
