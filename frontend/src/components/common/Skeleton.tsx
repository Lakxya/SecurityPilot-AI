import { HTMLAttributes } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export interface SkeletonProps extends HTMLAttributes<HTMLDivElement> {
  className?: string;
}

export function Skeleton({ className, ...props }: SkeletonProps) {
  return (
    <div
      className={twMerge(
        clsx(
          'skeleton-shimmer rounded-lg border border-slate-700/30 font-mono',
          className
        )
      )}
      {...props}
    />
  );
}

export function SkeletonCard() {
  return (
    <div className="bg-slate-900/60 border border-slate-800/80 rounded-xl p-6 space-y-4 animate-pulse">
      <div className="flex items-center justify-between">
        <Skeleton className="h-5 w-48" />
        <Skeleton className="h-4 w-16 rounded-full" />
      </div>
      <Skeleton className="h-12 w-full" />
      <div className="space-y-2 pt-2">
        <Skeleton className="h-3 w-20" />
        <div className="flex gap-2">
          <Skeleton className="h-5 w-14" />
          <Skeleton className="h-5 w-16" />
          <Skeleton className="h-5 w-12" />
        </div>
      </div>
      <div className="pt-4 border-t border-slate-800/60 flex justify-between items-center">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-7 w-28" />
      </div>
    </div>
  );
}
