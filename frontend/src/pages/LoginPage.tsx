import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Button } from '../components/ui/Button';
import { SecurityMesh3D } from '../components/common/SecurityMesh3D';

export function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuth();
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login({ email, password });
      navigate('/dashboard');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Authentication failed. Please check your credentials.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans selection:bg-indigo-500/30 relative overflow-hidden">
      <SecurityMesh3D />
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center space-y-2 relative z-10">
        <Link to="/" className="inline-flex items-center gap-2.5 group">
          <div className="w-10 h-10 rounded-xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center font-bold text-xl group-hover:bg-indigo-600/30 transition-all">
            🛡️
          </div>
          <span className="font-bold text-2xl text-white tracking-tight">
            SecurityPilot<span className="text-indigo-400">AI</span>
          </span>
        </Link>
        <h2 className="mt-2 text-xl font-semibold text-slate-200">Sign in to your account</h2>
        <p className="text-xs text-slate-400">
          Enter your security credentials to access project workspaces
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-slate-900/80 border border-slate-800 backdrop-blur-md py-8 px-4 shadow-2xl rounded-xl sm:px-10">
          {error && (
            <div className="mb-6 bg-rose-500/10 border border-rose-500/20 text-rose-400 p-3.5 rounded-lg text-xs flex items-center gap-2">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          )}

          <form className="space-y-5" onSubmit={handleSubmit}>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Work Email Address
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="engineer@securitypilot.ai"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Password
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              />
            </div>

            <div className="pt-2">
              <Button
                type="submit"
                variant="emerald"
                size="md"
                className="w-full justify-center"
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Authenticating...' : 'Sign In'}
              </Button>
            </div>
          </form>

          <div className="mt-6 border-t border-slate-800 pt-6 text-center text-xs text-slate-400">
            Don&apos;t have an account?{' '}
            <Link to="/register" className="font-medium text-indigo-400 hover:text-indigo-300 transition-colors">
              Create an account
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
