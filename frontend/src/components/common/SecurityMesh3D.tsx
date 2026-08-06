import { useEffect, useRef } from 'react';

export function SecurityMesh3D() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Grid Node Points
    const rows = 12;
    const cols = 20;
    let step = 0;

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      ctx.strokeStyle = 'rgba(99, 102, 241, 0.08)';
      ctx.lineWidth = 1;

      step += 0.01;

      for (let i = 0; i < cols; i++) {
        for (let j = 0; j < rows; j++) {
          const x = (i / (cols - 1)) * width;
          const offsetY = Math.sin(step + i * 0.4 + j * 0.3) * 6;
          const y = (j / (rows - 1)) * height + (prefersReducedMotion ? 0 : offsetY);

          // Horizontal lines
          if (i < cols - 1) {
            const nextX = ((i + 1) / (cols - 1)) * width;
            const nextOffsetY = Math.sin(step + (i + 1) * 0.4 + j * 0.3) * 6;
            const nextY = (j / (rows - 1)) * height + (prefersReducedMotion ? 0 : nextOffsetY);

            ctx.beginPath();
            ctx.moveTo(x, y);
            ctx.lineTo(nextX, nextY);
            ctx.stroke();
          }

          // Subtle nodes
          if (i % 3 === 0 && j % 2 === 0) {
            ctx.fillStyle = 'rgba(16, 185, 129, 0.15)';
            ctx.beginPath();
            ctx.arc(x, y, 1.5, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      }

      if (!prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(render);
      }
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animationFrameId) cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0 opacity-40 select-none"
    />
  );
}
