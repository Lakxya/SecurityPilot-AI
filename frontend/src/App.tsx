import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col items-center justify-center p-4">
        <div className="max-w-md w-full bg-slate-800 border border-slate-700 rounded-xl p-6 shadow-2xl text-center space-y-4">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-bold text-xl">
            🛡️
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">SecurityPilotAI</h1>
          <p className="text-slate-400 text-sm">
            Frontend foundation initialized with React, Vite, TypeScript, Tailwind CSS, and React Router.
          </p>
          <div className="pt-2">
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Sprint 1 Foundation Ready
            </span>
          </div>
        </div>
        <Routes>
          <Route path="/" element={null} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
