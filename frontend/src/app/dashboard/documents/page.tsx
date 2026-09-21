"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { wafFetch } from "@/lib/api";
import {
  FileText,
  Upload,
  Download,
  Search,
  CheckCircle2,
  FileCode2,
  User,
  Plus,
  X
} from "lucide-react";

export default function DocumentsPage() {
  const [documents, setDocuments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showUploadModal, setShowUploadModal] = useState(false);

  // Upload Form State
  const [mrn, setMrn] = useState("MRN-10234");
  const [category, setCategory] = useState("Diagnostic Lab Report");
  const [description, setDescription] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState("");

  const loadDocuments = async () => {
    setLoading(true);
    // Fetch patients to aggregate documents
    const res = await wafFetch("/api/patients");
    setLoading(false);
    if (res.status === 200 && res.data?.patients) {
      // Gather documents from charts
      const docList: any[] = [];
      for (const p of res.data.patients) {
        const chartRes = await wafFetch(`/api/patients/${p.mrn}`);
        if (chartRes.status === 200 && chartRes.data?.chart?.documents) {
          chartRes.data.chart.documents.forEach((d: any) => {
            docList.push({ ...d, patient_name: p.name });
          });
        }
      }
      setDocuments(docList);
    }
  };

  useEffect(() => {
    loadDocuments();
  }, []);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;

    setUploading(true);
    setUploadSuccess("");

    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("category", category);
    formData.append("description", description || selectedFile.name);
    formData.append("uploaded_by", "Dr. Sarah Chen, MD");

    try {
      const response = await fetch(`http://localhost:8000/api/patients/${mrn}/documents/upload`, {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      setUploading(false);

      if (response.ok) {
        setUploadSuccess(`Saved ${data.file?.filename} to patient records.`);
        setSelectedFile(null);
        setDescription("");
        setShowUploadModal(false);
        loadDocuments();
      } else {
        alert("Upload error: " + (data.error || "Failed to store document"));
      }
    } catch (err: any) {
      setUploading(false);
      alert("Error: " + err.message);
    }
  };

  return (
    <div className="space-y-10">
      {/* Header Band */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-6 border-b border-hairline">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-ink" />
            <span className="text-xs uppercase tracking-widest text-muted font-medium">
              Diagnostic Archive
            </span>
          </div>
          <h1 className="font-display text-3xl sm:text-4xl text-ink font-light tracking-tight">
            Medical Documents & Lab Reports
          </h1>
          <p className="text-sm text-body mt-1">
            Centralized clinical diagnostic document repository &bull; Secure Encrypted Archive
          </p>
        </div>

        <button
          onClick={() => setShowUploadModal(true)}
          className="h-10 px-5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium transition-all shadow-sm flex items-center gap-2 self-start md:self-auto"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload Lab Document</span>
        </button>
      </div>

      {/* Documents Table */}
      <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-xl text-ink font-light">Stored Clinical Documents</h2>
          <span className="text-xs font-mono text-muted">{documents.length} Records</span>
        </div>

        <div className="overflow-x-auto -mx-4 sm:mx-0 px-4 sm:px-0">
          <table className="w-full text-left text-xs min-w-[650px]">
            <thead>
              <tr className="border-b border-hairline text-muted font-medium">
                <th className="pb-3 pl-3">FILENAME / ORIGINAL</th>
                <th className="pb-3">PATIENT</th>
                <th className="pb-3">CATEGORY</th>
                <th className="pb-3">SIZE / TYPE</th>
                <th className="pb-3">UPLOADED BY</th>
                <th className="pb-3 text-right pr-3">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    Loading clinical documents...
                  </td>
                </tr>
              ) : documents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    No diagnostic documents found in archive.
                  </td>
                </tr>
              ) : (
                documents.map((doc) => (
                  <tr key={doc.id} className="hover:bg-canvas-soft/80 transition-colors">
                    <td className="py-4 pl-3">
                      <div className="font-medium text-ink flex items-center gap-2">
                        <FileText className="w-4 h-4 text-muted shrink-0" />
                        <span>{doc.original_name || doc.filename}</span>
                      </div>
                      {doc.description && (
                        <span className="text-[11px] text-muted block pl-6">{doc.description}</span>
                      )}
                    </td>
                    <td className="py-4 text-body">
                      <div className="font-medium text-ink">{doc.patient_name || doc.patient_mrn}</div>
                      <span className="text-[11px] text-muted font-mono">{doc.patient_mrn}</span>
                    </td>
                    <td className="py-4 text-body">
                      <span className="px-2.5 py-0.5 rounded-pill bg-surface-strong text-body-strong border border-hairline text-[11px]">
                        {doc.category}
                      </span>
                    </td>
                    <td className="py-4 text-body font-mono text-[11px]">
                      {(doc.file_size / 1024).toFixed(1)} KB &bull; {doc.mime_type || "PDF"}
                    </td>
                    <td className="py-4 text-body">
                      <div>{doc.uploaded_by}</div>
                      <span className="text-[10px] text-muted font-mono">{doc.created_at || "2026-09-07"}</span>
                    </td>
                    <td className="py-4 text-right pr-3">
                      <a
                        href={`http://localhost:8000/api/documents/${doc.id}/download`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-pill bg-surface-strong hover:bg-ink hover:text-white text-ink text-xs font-medium border border-hairline transition-all"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Download</span>
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-surface-card border border-hairline rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-elevated relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-hairline">
              <div>
                <h3 className="font-display text-xl text-ink font-light">Upload Clinical Document</h3>
                <p className="text-xs text-muted">Attach diagnostic record to patient chart</p>
              </div>
              <button
                onClick={() => setShowUploadModal(false)}
                className="p-1 rounded-full hover:bg-surface-strong text-muted hover:text-ink transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleUpload} className="space-y-4 text-xs">
              <div>
                <label className="block font-medium text-body-strong mb-1">Patient MRN</label>
                <input
                  type="text"
                  value={mrn}
                  onChange={(e) => setMrn(e.target.value)}
                  placeholder="MRN-10234"
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink font-mono"
                  required
                />
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1">Document Category</label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                >
                  <option value="Diagnostic Lab Report">Diagnostic Lab Report</option>
                  <option value="Cardiology Diagnostics">Cardiology Diagnostics</option>
                  <option value="Radiology Imaging">Radiology Imaging</option>
                  <option value="Pulmonology Spirometry">Pulmonology Spirometry</option>
                  <option value="Surgical Consultation Summary">Surgical Consultation Summary</option>
                </select>
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1.5">Select File (PDF, Image, Text)</label>
                <input
                  type="file"
                  onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                  className="w-full text-xs text-body file:mr-4 file:py-2 file:px-4 file:rounded-pill file:border-0 file:text-xs file:font-medium file:bg-surface-strong file:text-ink hover:file:bg-hairline cursor-pointer"
                  required
                />
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1">Clinical Notes / Description</label>
                <textarea
                  rows={3}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="e.g. 12-lead ECG strip recording normal sinus rhythm..."
                  className="w-full p-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                />
              </div>

              <div className="pt-4 flex flex-col-reverse sm:flex-row sm:items-center sm:justify-end gap-3 border-t border-hairline">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  className="px-4 py-2.5 rounded-pill text-muted hover:text-ink text-center"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading || !selectedFile}
                  className="px-5 py-2.5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white font-medium shadow-sm transition-all text-center"
                >
                  {uploading ? "Uploading..." : "Upload & Save"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
