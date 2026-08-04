export interface TechStackSpec {
  frontend?: string;
  backend?: string;
  database?: string;
  cloud?: string;
  container?: string;
}

export interface GeneratedDocumentSpec {
  id: string;
  project_id: string;
  doc_type: string;
  file_path: string;
  content: string;
  version: number;
  is_latest: boolean;
  created_at: string;
}

export interface Project {
  id: string;
  user_id: string;
  name: string;
  description?: string | null;
  tech_stack?: TechStackSpec | Record<string, string> | null;
  compliance_frameworks?: string[] | null;
  status: 'ACTIVE' | 'ARCHIVED';
  created_at: string;
  updated_at: string;
  documents?: GeneratedDocumentSpec[];
}

export interface ProjectCreatePayload {
  name: string;
  description?: string;
  tech_stack?: TechStackSpec | Record<string, string>;
  compliance_frameworks?: string[];
}

export interface ProjectUpdatePayload {
  name?: string;
  description?: string;
  tech_stack?: TechStackSpec | Record<string, string>;
  compliance_frameworks?: string[];
  status?: 'ACTIVE' | 'ARCHIVED';
}

export interface ProjectListResponse {
  projects: Project[];
  total: number;
}
