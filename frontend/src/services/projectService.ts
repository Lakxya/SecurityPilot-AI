import { Project, ProjectCreatePayload, ProjectUpdatePayload, ProjectListResponse } from '../types/project';
import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export const projectService = {
  getAuthHeaders(): HeadersInit {
    const token = authService.getToken();
    return {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };
  },

  async listProjects(search?: string, status?: string): Promise<ProjectListResponse> {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (status) params.append('status', status);

    const queryString = params.toString() ? `?${params.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/projects/${queryString}`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to fetch project workspaces.');
    }

    return await res.json();
  },

  async getProject(projectId: string): Promise<Project> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}`, {
      method: 'GET',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to retrieve project details.');
    }

    return await res.json();
  },

  async createProject(payload: ProjectCreatePayload): Promise<Project> {
    const res = await fetch(`${API_BASE_URL}/projects/`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || 'Failed to create project workspace.');
    }

    return await res.json();
  },

  async updateProject(projectId: string, payload: ProjectUpdatePayload): Promise<Project> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}`, {
      method: 'PUT',
      headers: this.getAuthHeaders(),
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error('Failed to update project workspace.');
    }

    return await res.json();
  },

  async deleteProject(projectId: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}`, {
      method: 'DELETE',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to delete project workspace.');
    }
  },
};
