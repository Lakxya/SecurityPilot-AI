import { AuthResponse, LoginPayload, RegisterPayload, User } from '../types/auth';

const API_BASE_URL = 'http://localhost:8000/api/v1';
const TOKEN_KEY = 'sec_pilot_access_token';

export const authService = {
  getToken(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
  },

  removeToken(): void {
    localStorage.removeItem(TOKEN_KEY);
  },

  async register(payload: RegisterPayload): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || 'Registration failed. Please check your details.');
    }

    const data: AuthResponse = await res.json();
    this.setToken(data.access_token);
    return data;
  },

  async login(payload: LoginPayload): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || 'Invalid email or password.');
    }

    const data: AuthResponse = await res.json();
    this.setToken(data.access_token);
    return data;
  },

  async getCurrentUser(): Promise<User> {
    const token = this.getToken();
    if (!token) {
      throw new Error('No authentication token found.');
    }

    const res = await fetch(`${API_BASE_URL}/auth/me`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!res.ok) {
      this.removeToken();
      throw new Error('Session expired. Please log in again.');
    }

    return await res.json();
  },

  logout(): void {
    this.removeToken();
  },
};
