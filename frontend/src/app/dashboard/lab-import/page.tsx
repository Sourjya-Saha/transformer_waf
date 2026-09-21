"use client";

import React, { useState } from "react";
import { wafFetch } from "@/lib/api";
import { FileCode2, UploadCloud, AlertCircle, CheckCircle } from "lucide-react";

export default function LabImportPage() {
  const [xmlPayload, setXmlPayload] = useState(
    `<?xml version="1.0" encoding="UTF-8"?>\n<labResult patientMrn="MRN-10234">\n  <testName>Hemoglobin A1c</testName>\n  <value>6.4%</value>\n  <status>Normal</status>\n</labResult>`
  );
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setStatusMsg("");

    const res = await wafFetch("/api/lab-reports/import", {
      method: "POST",
      headers: { "Content-Type": "application/xml" },
      body: xmlPayload,
    });

    setLoading(false);

    if (res.status === 200 || res.status === 201) {
      setIsSuccess(true);
      setStatusMsg("XML laboratory payload ingested and recorded in repository.");
    } else {
      setIsSuccess(false);
      setStatusMsg(res.data?.error || res.data?.message || "Laboratory feed ingestion failed.");
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div>
        <div className="flex items-center gap-2 mb-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-ink" />
          <span className="text-xs uppercase tracking-widest text-muted font-medium">
            Clinical Integrations
          </span>
        </div>
        <h1 className="font-display text-3xl sm:text-4xl text-ink font-light tracking-tight">
          External Laboratory Feed Ingestion
        </h1>
        <p className="text-sm text-body mt-1">
          Structured XML &amp; CCD clinical report import repository.
        </p>
      </div>

      <div className="bg-surface-card border border-hairline rounded-2xl p-6 sm:p-8 shadow-card space-y-6">
        <div className="flex items-center gap-3 pb-4 border-b border-hairline">
          <div className="w-10 h-10 rounded-xl bg-surface-strong border border-hairline flex items-center justify-center text-ink">
            <FileCode2 className="w-5 h-5 opacity-80" />
          </div>
          <div>
            <h2 className="font-display text-lg text-ink font-light">Raw XML / CCD Report Ingestion</h2>
            <p className="text-xs text-muted">Direct interface for diagnostic lab equipment data feeds</p>
          </div>
        </div>

        {statusMsg && (
          <div
            className={`p-4 rounded-xl border text-xs flex items-start gap-3 animate-in fade-in duration-200 ${
              isSuccess
                ? "bg-emerald-50/70 border-emerald-200 text-emerald-900"
                : "bg-rose-50/70 border-rose-200 text-rose-900"
            }`}
          >
            {isSuccess ? (
              <CheckCircle className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />
            ) : (
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600 mt-0.5" />
            )}
            <span>{statusMsg}</span>
          </div>
        )}

        <form onSubmit={handleImport} className="space-y-5 text-xs">
          <div>
            <label className="block text-muted font-medium mb-1.5">
              Raw XML / HL7 Structured Payload
            </label>
            <textarea
              rows={9}
              value={xmlPayload}
              onChange={(e) => setXmlPayload(e.target.value)}
              placeholder="Paste clinical XML payload here..."
              className="w-full p-3.5 bg-canvas-soft border border-hairline-strong rounded-xl font-mono text-xs text-ink placeholder-muted focus:outline-none focus:border-ink"
              required
            />
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 bg-ink-primary hover:bg-ink-primary-active text-white font-medium text-xs rounded-pill shadow-sm transition-all flex items-center justify-center gap-2"
            >
              <UploadCloud className="w-4 h-4" />
              <span>{loading ? "Ingesting Payload..." : "Ingest Diagnostic XML Feed"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
