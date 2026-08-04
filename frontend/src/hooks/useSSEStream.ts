import { useState, useCallback } from 'react';
import { generationService, GenerateRequestPayload } from '../services/generationService';

export function useSSEStream() {
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamContent, setStreamContent] = useState('');
  const [error, setError] = useState<string | null>(null);

  const startStream = useCallback(async (projectId: string, payload: GenerateRequestPayload) => {
    setIsStreaming(true);
    setStreamContent('');
    setError(null);

    await generationService.streamDocument(
      projectId,
      payload,
      (chunk: string) => {
        setStreamContent((prev) => prev + chunk);
      },
      () => {
        setIsStreaming(false);
      },
      (err: Error) => {
        setIsStreaming(false);
        setError(err.message);
      }
    );
  }, []);

  const resetStream = useCallback(() => {
    setIsStreaming(false);
    setStreamContent('');
    setError(null);
  }, []);

  return {
    isStreaming,
    streamContent,
    error,
    startStream,
    resetStream,
  };
}
