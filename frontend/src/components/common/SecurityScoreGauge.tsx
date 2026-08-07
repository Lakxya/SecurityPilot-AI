import { useEffect, useState } from 'react';

export interface SecurityScoreGaugeProps {
  score?: number;
  size?: number;
  strokeWidth?: number;
  className?: string;
}

export function SecurityScoreGauge({
  score = 95,
  size = 120,
  strokeWidth = 10,
  className = '',
}: SecurityScoreGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Respect prefers-reduced-motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setAnimatedScore(score);
      return;
    }

    const duration = 1000;
    const steps = 40;
    const increment = score / steps;
    let current = 0;

    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setAnimatedScore(score);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.round(current));
      }
    }, duration / steps);

    return () => clearInterval(timer);
  }, [score]);

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  let color = '#10b981'; // Emerald (>= 85)
  let badgeText = 'EXCELLENT';
  let glowColor = 'rgba(16, 185, 129, 0.4)';

  if (score < 60) {
    color = '#ef4444'; // Red (< 60)
    badgeText = 'CRITICAL';
    glowColor = 'rgba(239, 68, 68, 0.4)';
  } else if (score < 85) {
    color = '#f59e0b'; // Yellow (< 85)
    badgeText = 'WARNING';
    glowColor = 'rgba(245, 158, 11, 0.4)';
  }

  return (
    <div className={`relative inline-flex flex-col items-center justify-center ${className}`}>
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background Track Circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        {/* Animated Progress Ring */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          style={{
            transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1)',
            filter: `drop-shadow(0 0 6px ${glowColor})`,
          }}
        />
      </svg>

      {/* Centered Score Label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center font-mono">
        <span className="text-xl sm:text-2xl font-extrabold text-white tracking-tight">
          {animatedScore}
        </span>
        <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider">/ 100</span>
      </div>

      <span
        className="mt-2 text-[9px] font-mono font-extrabold px-2 py-0.5 rounded border"
        style={{
          color,
          borderColor: color,
          backgroundColor: `${color}15`,
        }}
      >
        {badgeText}
      </span>
    </div>
  );
}
