import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export interface AIProviderSpec {
  id: string;
  user_id: string;
  provider_name: string;
  masked_api_key: string;
  base_url?: string | null;
  model_name: string;
  is_default: boolean;
  is_active: boolean;
  created_at: string;
}

export interface AIProviderCreatePayload {
  provider_name: string;
  api_key?: string;
  base_url?: string;
  model_name: string;
  is_default?: boolean;
}

export const vaultService = {
  getAuthHeaders(): HeadersInit {
    const token = authService.getToken();
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };
  },

  async listProviders(): Promise<AIProviderSpec[]> {
    const res = await fetch(`${API_BASE_URL}/vault/providers`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) {
      throw new Error('Failed to retrieve AI vault credentials.');
    }
    const data = await res.json();
    return data.providers || [];
  },

  async createProvider(payload: AIProviderCreatePayload): Promise<AIProviderSpec> {
    const res = await fetch(`${API_BASE_URL}/vault/providers`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error('Failed to save provider credentials.');
    }
    return await res.json();
  },

  async deleteProvider(providerId: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/vault/providers/${providerId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) {
      throw new Error('Failed to revoke provider credential.');
    }
  },

  async testProvider(providerId: string): Promise<{ status: string; latency_ms: number }> {
    const res = await fetch(`${API_BASE_URL}/vault/providers/${providerId}/test`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) {
      throw new Error('Provider connection test failed.');
    }
    return await res.json();
  },
};
