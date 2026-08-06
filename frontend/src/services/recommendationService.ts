import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export interface ModelRecommendation {
  recommended_provider: string;
  recommended_model: string;
  confidence_score: number;
  rating_stars: number;
  reason: string;
  estimated_latency: string;
  estimated_cost: string;
  context_window: string;
  security_suitability_score: number;
  strengths: string[];
  weaknesses: string[];
  best_for_artifacts: string[];
}

export const recommendationService = {
  async getRecommendation(projectId: string, docType = 'README'): Promise<ModelRecommendation> {
    const token = authService.getToken();
    const res = await fetch(
      `${API_BASE_URL}/projects/${projectId}/recommendation?doc_type=${encodeURIComponent(docType)}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
      }
    );
    if (!res.ok) {
      throw new Error('Failed to fetch AI model recommendation');
    }
    return await res.json();
  },
};
