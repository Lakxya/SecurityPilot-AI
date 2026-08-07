import { useState } from 'react';
import { Package, FileText, File, Code, Download } from 'lucide-react';
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
      } else if (selectedFormat === 'bundle') {
        await exportService.downloadBundleExport(projectId, projectName);
      } else if (selectedFormat === 'json') {
        await exportService.downloadJsonExport(projectId, projectName);
      } else if (selectedFormat === 'pdf') {
        await exportService.downloadPdfReport(projectId, projectName);
      }
      showToast('success', 'Export Ready', `Downloaded ${selectedFormat.toUpperCase()} package.`);
      onClose();
    } catch {
      showToast('error', 'Export Failed', `Could not compile ${selectedFormat.toUpperCase()} package.`);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title="Export Security Blueprint Package"
      description="Download complete production-ready specifications, compliance docs, and deployment manifests"
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
                icon: <Package className="w-4 h-4 text-indigo-400" />,
              },
              {
                id: 'bundle',
                title: 'Markdown Bundle',
                desc: 'Single consolidated Markdown specification',
                icon: <FileText className="w-4 h-4 text-emerald-400" />,
              },
              {
                id: 'pdf',
                title: 'PDF Report',
                desc: 'Printable executive compliance audit report',
                icon: <File className="w-4 h-4 text-rose-400" />,
              },
              {
                id: 'json',
                title: 'JSON Spec',
                desc: 'Machine-readable JSON specification format',
                icon: <Code className="w-4 h-4 text-cyan-400" />,
              },
            ].map((fmt) => {
              const isSelected = selectedFormat === fmt.id;
              return (
                <button
                  key={fmt.id}
                  type="button"
                  onClick={() => setSelectedFormat(fmt.id as 'zip' | 'bundle' | 'json' | 'pdf')}
                  className={`p-3 rounded-xl border text-left transition-all flex flex-col justify-between cursor-pointer ${
                    isSelected
                      ? 'bg-indigo-600/20 border-indigo-500/50 text-white'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="shrink-0">{fmt.icon}</span>
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
          <span className="text-xs text-slate-400 font-mono">
            Target Project: <strong className="text-white">{projectName}</strong>
          </span>

          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={onClose}>
              Cancel
            </Button>
            <Button
              variant="emerald"
              size="sm"
              onClick={handleExport}
              disabled={isExporting}
              icon={<Download className="w-3.5 h-3.5" />}
            >
              {isExporting ? 'Packaging...' : 'Download Package'}
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
}
