import { useEffect, useRef } from 'react';

export interface CyberShield3DProps {
  size?: number;
  className?: string;
  isAnimated?: boolean;
}

export function CyberShield3D({ size = 120, className = '', isAnimated = true }: CyberShield3DProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let rotation = 0;

    // Respect prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const drawShield = () => {
      ctx.clearRect(0, 0, size, size);

      const cx = size / 2;
      const cy = size / 2;
      const scale = size / 100;

      ctx.save();
      ctx.translate(cx, cy);

      if (isAnimated && !prefersReducedMotion) {
        rotation += 0.008;
      }

      // Subtle 3D Y-axis perspective tilt
      const scaleX = Math.cos(rotation);

      // Outer Shield Perimeter (Electric Indigo Gradient)
      const grad = ctx.createLinearGradient(-35 * scaleX, -40, 35 * scaleX, 40);
      grad.addColorStop(0, '#6366f1');
      grad.addColorStop(0.5, '#4f46e5');
      grad.addColorStop(1, '#10b981');

      ctx.beginPath();
      ctx.moveTo(0 * scaleX, -40 * scale);
      ctx.lineTo(35 * scaleX, -30 * scale);
      ctx.lineTo(30 * scaleX, 10 * scale);
      ctx.lineTo(0 * scaleX, 40 * scale);
      ctx.lineTo(-30 * scaleX, 10 * scale);
      ctx.lineTo(-35 * scaleX, -30 * scale);
      ctx.closePath();

      ctx.strokeStyle = grad;
      ctx.lineWidth = 2.5 * scale;
      ctx.stroke();

      ctx.fillStyle = 'rgba(99, 102, 241, 0.08)';
      ctx.fill();

      // Inner Core Node (Emerald Active Pulse)
      ctx.beginPath();
      ctx.arc(0, 0, 8 * scale, 0, Math.PI * 2);
      ctx.fillStyle = '#10b981';
      ctx.shadowColor = '#10b981';
      ctx.shadowBlur = 10;
      ctx.fill();

      ctx.restore();

      if (isAnimated && !prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(drawShield);
      }
    };

    drawShield();

    return () => {
      if (animationFrameId) cancelAnimationFrame(animationFrameId);
    };
  }, [size, isAnimated]);

  return (
    <canvas
      ref={canvasRef}
      width={size}
      height={size}
      className={`inline-block pointer-events-none ${className}`}
    />
  );
}
