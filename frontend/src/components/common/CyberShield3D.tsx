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
    let angle = 0;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Generate ambient particle ring coordinates
    const particles = Array.from({ length: 12 }, (_, i) => ({
      orbitRadius: (size / 2) * (0.6 + (i % 3) * 0.15),
      angleOffset: (i * Math.PI * 2) / 12,
      speed: 0.005 + (i % 2) * 0.003,
      size: 1.5 + (i % 2) * 0.5,
    }));

    const drawHologram = () => {
      ctx.clearRect(0, 0, size, size);

      const cx = size / 2;
      const cy = size / 2;
      const scale = size / 100;

      if (isAnimated && !prefersReducedMotion) {
        angle += 0.012;
      }

      ctx.save();
      ctx.translate(cx, cy);

      // Breathing Ambient Aura Glow
      const glowAlpha = 0.12 + Math.sin(angle * 1.5) * 0.05;
      const glowGrad = ctx.createRadialGradient(0, 0, 10 * scale, 0, 0, 45 * scale);
      glowGrad.addColorStop(0, `rgba(99, 102, 241, ${glowAlpha * 1.5})`);
      glowGrad.addColorStop(0.6, `rgba(6, 182, 212, ${glowAlpha})`);
      glowGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');

      ctx.beginPath();
      ctx.arc(0, 0, 45 * scale, 0, Math.PI * 2);
      ctx.fillStyle = glowGrad;
      ctx.fill();

      // Outer Rotating Particle Rings
      particles.forEach((p) => {
        const currentAngle = p.angleOffset + angle * (p.speed * 80);
        const px = Math.cos(currentAngle) * (p.orbitRadius * scale * 0.7);
        const py = Math.sin(currentAngle) * (p.orbitRadius * scale * 0.7);

        ctx.beginPath();
        ctx.arc(px, py, p.size * scale, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(34, 211, 238, 0.6)';
        ctx.shadowColor = '#06b6d4';
        ctx.shadowBlur = 6;
        ctx.fill();
      });

      // Holographic Shield 3D Tilt Perspective
      const scaleX = Math.cos(angle * 0.8);

      // Primary Outer Laser Perimeter
      const strokeGrad = ctx.createLinearGradient(-35 * scaleX, -40, 35 * scaleX, 40);
      strokeGrad.addColorStop(0, '#6366f1');
      strokeGrad.addColorStop(0.5, '#06b6d4');
      strokeGrad.addColorStop(1, '#10b981');

      ctx.beginPath();
      ctx.moveTo(0 * scaleX, -38 * scale);
      ctx.lineTo(32 * scaleX, -28 * scale);
      ctx.lineTo(28 * scaleX, 12 * scale);
      ctx.lineTo(0 * scaleX, 38 * scale);
      ctx.lineTo(-28 * scaleX, 12 * scale);
      ctx.lineTo(-32 * scaleX, -28 * scale);
      ctx.closePath();

      ctx.strokeStyle = strokeGrad;
      ctx.lineWidth = 2.2 * scale;
      ctx.shadowColor = '#6366f1';
      ctx.shadowBlur = 12;
      ctx.stroke();

      ctx.fillStyle = 'rgba(99, 102, 241, 0.06)';
      ctx.fill();

      // Inner Core Pulse Node
      const pulseSize = (6 + Math.sin(angle * 3) * 1.5) * scale;
      ctx.beginPath();
      ctx.arc(0, 0, pulseSize, 0, Math.PI * 2);
      ctx.fillStyle = '#10b981';
      ctx.shadowColor = '#10b981';
      ctx.shadowBlur = 14;
      ctx.fill();

      ctx.restore();

      if (isAnimated && !prefersReducedMotion) {
        animationFrameId = requestAnimationFrame(drawHologram);
      }
    };

    drawHologram();

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
