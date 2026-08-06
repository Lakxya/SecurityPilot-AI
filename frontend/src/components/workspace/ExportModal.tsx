import { useState } from 'react';
import { Dialog } from '../ui/Dialog';
import { Button } from '../ui/Button';
import { exportService } from '../../services/exportService';
import { useToast } from '../../hooks/useToast';

export interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
  projectName: string;
}

export function ExportModal({ isOpen, onClose, projectId, projectName }: ExportModalProps) {
  const { showToast } = useToast();
  const [selectedFormat, setSelectedFormat] = useState<'zip' | 'bundle' | 'json' | 'pdf'>('zip');
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async () => {
    setIsExporting(true);
    try {
      if (selectedFormat === 'zip') {
        await exportService.downloadZipExport(projectId, projectName);
        showToast('success', 'ZIP Export Complete', 'Downloaded full project repository archive.');
      } else if (selectedFormat === 'bundle') {
        await exportService.downloadBundleExport(projectId, projectName);
        showToast('success', 'Markdown Bundle Complete', 'Downloaded consolidated specification document.');
      } else if (selectedFormat === 'pdf') {
        await exportService.downloadPdfReport(projectId, projectName);
        showToast('success', 'PDF Report Complete', 'Downloaded printable executive security report.');
      } else {
        await exportService.downloadJsonExport(projectId, projectName);
        showToast('success', 'JSON Spec Complete', 'Downloaded machine-readable JSON specification.');
      }
      onClose();
    } catch (err) {
      showToast('error', 'Export Failed', 'Unable to compile export package.');
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
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
            {[
              {
                id: 'zip',
                title: 'ZIP Archive',
                desc: 'Complete 13-artifact repository layout',
                icon: '📦',
              },
              {
                id: 'bundle',
                title: 'Markdown Bundle',
                desc: 'Single consolidated Markdown specification',
                icon: '📜',
              },
              {
                id: 'pdf',
                title: 'PDF Report',
                desc: 'Printable executive compliance audit report',
                icon: '📄',
              },
              {
                id: 'json',
                title: 'JSON Spec',
                desc: 'Machine-readable JSON specification format',
                icon: '🔌',
              },
            ].map((fmt) => {
              const isSelected = selectedFormat === fmt.id;
              return (
                <button
                  key={fmt.id}
                  type="button"
                  onClick={() => setSelectedFormat(fmt.id as 'zip' | 'bundle' | 'json' | 'pdf')}
                  className={`p-3 rounded-xl border text-left transition-all flex flex-col justify-between ${
                    isSelected
                      ? 'bg-indigo-600/20 border-indigo-500/50 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="text-base">{fmt.icon}</span>
                    <span className="text-xs font-bold">{fmt.title}</span>
                  </div>
                  <p className="text-[10px] text-slate-500 line-clamp-2 leading-relaxed">
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
            Press <kbd className="px-1 py-0.5 bg-slate-800 border border-slate-700 rounded text-slate-300">Esc</kbd> to cancel
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
              {isExporting ? 'Compiling Package...' : 'Download Export Package'}
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
}
