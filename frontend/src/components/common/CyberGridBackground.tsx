import { useState, useEffect } from 'react';

export function CyberGridBackground() {
  const [cursorPos, setCursorPos] = useState<{ x: number; y: number }>({ x: -1000, y: -1000 });
  const [isIdle, setIsIdle] = useState(false);

  useEffect(() => {
    // Respect prefers-reduced-motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      return;
    }

    let idleTimer: NodeJS.Timeout;

    const handleMouseMove = (e: MouseEvent) => {
      setCursorPos({ x: e.clientX, y: e.clientY });
      setIsIdle(false);
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        setIsIdle(true);
      }, 2500);
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      clearTimeout(idleTimer);
    };
  }, []);

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none">
      {/* Phase A: Ultra-Light Animated Cyber Grid */}
      <div
        className="absolute inset-0 opacity-[0.035] bg-[linear-gradient(to_right,#6366f1_1px,transparent_1px),linear-gradient(to_bottom,#6366f1_1px,transparent_1px)] bg-[size:4rem_4rem] animate-grid-pan"
        aria-hidden="true"
      />

      {/* Radial Vignette Mask */}
      <div className="absolute inset-0 bg-radial from-transparent via-slate-950/60 to-slate-950" />

      {/* Phase C: Ambient Cursor Radial Light Spotlight */}
      <div
        className="absolute rounded-full pointer-events-none transition-opacity duration-700 ease-out"
        style={{
          left: `${cursorPos.x}px`,
          top: `${cursorPos.y}px`,
          width: '500px',
          height: '500px',
          transform: 'translate(-50%, -50%)',
          background: 'radial-gradient(circle, rgba(99, 102, 241, 0.08) 0%, rgba(6, 182, 212, 0.04) 40%, transparent 70%)',
          opacity: isIdle ? 0 : 1,
          filter: 'blur(40px)',
        }}
        aria-hidden="true"
      />
    </div>
  );
}
