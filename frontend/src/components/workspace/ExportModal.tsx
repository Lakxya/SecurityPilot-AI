import { useState } from 'react';
import { Dialog } from '../ui/Dialog';
import { Button } from '../ui/Button';
import { exportService } from '../../services/exportService';

export interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
  projectName: string;
}

export function ExportModal({ isOpen, onClose, projectId, projectName }: ExportModalProps) {
  const [selectedFormat, setSelectedFormat] = useState<'zip' | 'bundle' | 'json'>('zip');
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async () => {
    setIsExporting(true);
    try {
      if (selectedFormat === 'zip') {
        await exportService.downloadZipExport(projectId, projectName);
      } else if (selectedFormat === 'bundle') {
        await exportService.downloadBundleExport(projectId, projectName);
      } else {
        await exportService.downloadJsonExport(projectId, projectName);
      }
      onClose();
    } catch (err) {
      console.error('Export failed:', err);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Export Security Architecture Package"
      description={`Compile and download production security artifacts for ${projectName}`}
      maxWidth="md"
    >
      <div className="space-y-6">
        <div className="space-y-3">
          <label className="block text-xs font-medium text-slate-300">
            Select Export Package Format
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
            {[
              {
                id: 'zip',
                title: 'ZIP Archive',
                desc: 'Complete 13-artifact repository layout (README, docs, docker, k8s, terraform, ci)',
                icon: '📦',
              },
              {
                id: 'bundle',
                title: 'Markdown Bundle',
                desc: 'Single consolidated Markdown security specification document',
                icon: '📜',
              },
              {
                id: 'json',
                title: 'JSON Spec',
                desc: 'Structured machine-readable JSON specification format',
                icon: '🔌',
              },
            ].map((fmt) => {
              const isSelected = selectedFormat === fmt.id;
              return (
                <button
                  key={fmt.id}
                  type="button"
                  onClick={() => setSelectedFormat(fmt.id as 'zip' | 'bundle' | 'json')}
                  className={`p-3.5 rounded-xl border text-left transition-all flex flex-col justify-between ${
                    isSelected
                      ? 'bg-indigo-600/20 border-indigo-500/50 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-lg">{fmt.icon}</span>
                    <span className="text-xs font-bold">{fmt.title}</span>
                  </div>
                  <p className="text-[10px] text-slate-500 line-clamp-3 leading-relaxed">
                    {fmt.desc}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Action Controls */}
        <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
          <span className="text-[10px] font-mono text-slate-500">
            Includes manifest checksum metadata
          </span>
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="emerald"
              size="sm"
              onClick={handleExport}
              disabled={isExporting}
              icon={<span>⬇️</span>}
            >
              {isExporting ? 'Compiling Archive...' : 'Download Export Package'}
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
}
