import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export interface ProviderScore {
  provider: string;
  model: string;
  overall_quality_score: number;
  reasoning_score: number;
  security_score: number;
  completeness_score: number;
  compliance_coverage: number;
  word_count: number;
  generation_time_sec: number;
  estimated_cost: string;
}

export interface CompareSummary {
  artifact: string;
  winner_provider: string;
  winner_reason: string;
  scores: ProviderScore[];
}

export const compareService = {
  async streamCompare(
    projectId: string,
    artifact: string,
    providers: string[],
    onChunk: (provider: string, chunk: string) => void,
    onComplete: (summary: CompareSummary) => void,
    onError: (err: Error) => void
  ): Promise<void> {
    const token = authService.getToken();
    try {
      const response = await fetch(`${API_BASE_URL}/generation/${projectId}/compare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          artifact,
          providers,
        }),
      });

      if (!response.ok || !response.body) {
        throw new Error('Failed to start comparison stream.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const block of lines) {
          const eventMatch = block.match(/event:\s*(\w+)/);
          const dataMatch = block.match(/data:\s*(.+)/);

          const eventType = eventMatch ? eventMatch[1] : 'message';
          if (dataMatch) {
            try {
              const data = JSON.parse(dataMatch[1]);
              if (eventType === 'message' && data.provider && data.chunk) {
                onChunk(data.provider, data.chunk);
              } else if (eventType === 'end' && data.summary) {
                onComplete(data.summary);
              }
            } catch {
              // Ignore partial JSON chunks
            }
          }
        }
      }
    } catch (err) {
      onError(err instanceof Error ? err : new Error('Comparison stream error'));
    }
  },
};
