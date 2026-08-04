export type UserRole = 'SUPER_ADMIN' | 'ORG_ADMIN' | 'SECURITY_ENGINEER' | 'DEVELOPER' | 'AUDITOR';

export interface User {
  id: string;
  email: string;
  full_name?: string | null;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface RegisterPayload {
  email: string;
  password: string;
  full_name?: string;
  role?: UserRole;
}

export interface LoginPayload {
  email: string;
  password: string;
}
