import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export interface ProviderAssignmentSpec {
  artifact: string;
  provider: string;
  model: string;
  provider_id?: string | null;
  last_updated: string;
}

export interface AssignmentsMapResponse {
  project_id: string;
  assignments: Record<string, ProviderAssignmentSpec>;
}

export const providerAssignmentService = {
  getAuthHeaders(): HeadersInit {
    const token = authService.getToken();
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };
  },

  async getAssignments(projectId: string): Promise<Record<string, ProviderAssignmentSpec>> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}/providers`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) {
      throw new Error('Failed to retrieve project provider assignments.');
    }
    const data: AssignmentsMapResponse = await res.json();
    return data.assignments || {};
  },

  async updateAssignment(
    projectId: string,
    artifact: string,
    provider: string,
    model: string,
    providerId?: string
  ): Promise<ProviderAssignmentSpec> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}/providers/${artifact}`, {
      method: 'PUT',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({
        provider,
        model,
        provider_id: providerId || null,
      }),
    });
    if (!res.ok) {
      throw new Error('Failed to update provider assignment.');
    }
    return await res.json();
  },

  async removeAssignment(projectId: string, artifact: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}/providers/${artifact}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });
    if (!res.ok) {
      throw new Error('Failed to remove provider assignment.');
    }
  },
};
