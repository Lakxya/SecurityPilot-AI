import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000/api/v1';

export const exportService = {
  getAuthHeaders(): HeadersInit {
    const token = authService.getToken();
    return {
      Authorization: `Bearer ${token}`,
    };
  },

  async downloadZipExport(projectId: string, projectName: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}/export/zip`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to generate ZIP archive export.');
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${projectName.toLowerCase().replace(/\s+/g, '_')}_security_export.zip`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  async downloadBundleExport(projectId: string, projectName: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}/export/bundle`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to generate Markdown security bundle.');
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${projectName.toLowerCase().replace(/\s+/g, '_')}_bundle.md`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },

  async downloadJsonExport(projectId: string, projectName: string): Promise<void> {
    const res = await fetch(`${API_BASE_URL}/projects/${projectId}/export/json`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
    });

    if (!res.ok) {
      throw new Error('Failed to generate JSON spec export.');
    }

    const data = await res.json();
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${projectName.toLowerCase().replace(/\s+/g, '_')}_spec.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },
};
