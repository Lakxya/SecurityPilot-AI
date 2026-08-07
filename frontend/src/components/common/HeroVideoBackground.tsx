import { useState } from 'react';

export interface HeroVideoBackgroundProps {
  videoSrc?: string;
  className?: string;
}

export function HeroVideoBackground({
  videoSrc = '/hero-bg.mp4',
  className = '',
}: HeroVideoBackgroundProps) {
  const [hasError, setHasError] = useState(false);
  const [isLoaded, setIsLoaded] = useState(false);

  return (
    <div className={`absolute inset-0 overflow-hidden pointer-events-none z-0 ${className}`}>
      {!hasError && (
        <video
          autoPlay
          muted
          loop
          playsInline
          onLoadedData={() => setIsLoaded(true)}
          onError={() => setHasError(true)}
          className={`w-full h-full object-cover transition-opacity duration-1000 ${
            isLoaded ? 'opacity-25' : 'opacity-0'
          }`}
        >
          <source src={videoSrc} type="video/mp4" />
          <source src={videoSrc.replace('.mp4', '.webm')} type="video/webm" />
        </video>
      )}

      {/* Dark Overlay Backdrop */}
      <div className="absolute inset-0 bg-gradient-to-b from-slate-950/70 via-slate-950/90 to-slate-950" />
    </div>
  );
}
