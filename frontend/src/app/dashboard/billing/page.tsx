"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { wafFetch } from "@/lib/api";
import {
  CreditCard,
  Search,
  CheckCircle2,
  AlertCircle,
  Shield,
  Building2,
  Calendar,
  DollarSign,
  ArrowUpRight,
  Plus,
  X
} from "lucide-react";

export default function BillingPage() {
  const [records, setRecords] = useState<any[]>([]);
  const [patients, setPatients] = useState<any[]>([]);
  const [searchId, setSearchId] = useState("");
  const [verifiedRecord, setVerifiedRecord] = useState<any>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [loadingRecords, setLoadingRecords] = useState(true);
  const [verifying, setVerifying] = useState(false);

  // Issue New Policy Form State
  const [showIssueModal, setShowIssueModal] = useState(false);
  const [patientMrn, setPatientMrn] = useState("");
  const [policyHolder, setPolicyHolder] = useState("");
  const [insuranceId, setInsuranceId] = useState("");
  const [providerName, setProviderName] = useState("");
  const [coverageType, setCoverageType] = useState("");
  const [copay, setCopay] = useState("");
  const [deductible, setDeductible] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [issuingPolicy, setIssuingPolicy] = useState(false);

  const loadBillingRecords = async () => {
    setLoadingRecords(true);
    const res = await wafFetch("/api/billing/records");
    setLoadingRecords(false);
    if (res.status === 200 && res.data?.records) {
      setRecords(res.data.records);
    }
  };

  const loadPatients = async () => {
    const res = await wafFetch("/api/patients");
    if (res.status === 200 && res.data?.patients) {
      setPatients(res.data.patients);
    }
  };

  useEffect(() => {
    loadBillingRecords();
    loadPatients();
  }, []);

  const handleIssuePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setIssuingPolicy(true);

    const generatedId = insuranceId.trim() || `INS-${Math.floor(10000 + Math.random() * 90000)}`;
    const rawCopay = copay.trim().replace(/^\$/, "");
    const rawDeductible = deductible.trim().replace(/^\$/, "");
    const formattedCopay = rawCopay ? `$${rawCopay}` : "$25.00";
    const formattedDeductible = rawDeductible ? `$${rawDeductible}` : "$500.00";

    const res = await wafFetch("/api/billing/records", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        insurance_id: generatedId,
        patient_mrn: patientMrn,
        policy_holder: policyHolder.trim() || "Primary Insured",
        provider_name: providerName.trim() || "Commercial Carrier",
        coverage_type: coverageType.trim() || "Standard Health Plan",
        copay: formattedCopay,
        deductible: formattedDeductible,
        valid_until: validUntil || "2027-12-31",
      }),
    });

    setIssuingPolicy(false);

    if (res.status === 200 || res.status === 201) {
      setShowIssueModal(false);
      setPatientMrn("");
      setPolicyHolder("");
      setInsuranceId("");
      setProviderName("");
      setCoverageType("");
      setCopay("");
      setDeductible("");
      setValidUntil("");
      loadBillingRecords();
      loadPatients();
    } else {
      alert("Failed to issue insurance policy: " + (res.data?.error || "Error"));
    }
  };

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchId.trim()) return;

    setVerifying(true);
    setVerifiedRecord(null);
    setVerifyError(null);

    const res = await wafFetch(`/api/billing/lookup?insurance_id=${encodeURIComponent(searchId.trim())}`);
    setVerifying(false);

    if (res.status === 200 && res.data?.status === "verified") {
      setVerifiedRecord(res.data);
    } else {
      setVerifyError(res.data?.error || `No policy record found matching ID "${searchId.trim()}".`);
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
              Revenue & Coverage
            </span>
          </div>
          <h1 className="font-display text-3xl sm:text-4xl text-ink font-light tracking-tight">
            Insurance & Billing Verification
          </h1>
          <p className="text-sm text-body mt-1">
            Real-time policy eligibility, copay determination, and patient claims management.
          </p>
        </div>
        <div>
          <button
            type="button"
            onClick={() => setShowIssueModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-ink-primary hover:bg-ink-primary-active text-white rounded-pill text-xs font-medium shadow-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Issue Policy Coverage</span>
          </button>
        </div>
      </div>

      {/* Issue Policy Modal */}
      {showIssueModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/40 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-surface-card border border-hairline-strong rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-2xl space-y-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-4 border-b border-hairline">
              <div>
                <h3 className="font-display text-xl text-ink font-light">Issue New Insurance Policy</h3>
                <p className="text-xs text-muted">Register and link coverage to a patient MRN</p>
              </div>
              <button
                type="button"
                onClick={() => setShowIssueModal(false)}
                className="p-1 rounded-full text-muted hover:text-ink hover:bg-surface-hover"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleIssuePolicy} className="space-y-4 text-xs">
              <div>
                <label className="block text-muted font-medium mb-1">Select Patient</label>
                <select
                  value={patientMrn}
                  onChange={(e) => {
                    const selMrn = e.target.value;
                    setPatientMrn(selMrn);
                    const sel = patients.find((p) => p.mrn === selMrn);
                    if (sel) {
                      setPolicyHolder(sel.name);
                      if (sel.insurance_id && sel.insurance_id !== "Self-Pay" && !sel.insurance_id.includes("None")) {
                        setInsuranceId(sel.insurance_id);
                      } else {
                        setInsuranceId(`INS-${Math.floor(10000 + Math.random() * 90000)}`);
                      }
                    }
                  }}
                  className="w-full px-3 py-2 bg-canvas-soft border border-hairline rounded-lg text-ink font-medium focus:outline-none focus:border-ink"
                  required
                >
                  <option value="" disabled>-- Select a Patient from Registry --</option>
                  {patients.map((p) => (
                    <option key={p.mrn} value={p.mrn}>
                      {p.name} ({p.mrn})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-muted font-medium mb-1">Policyholder (Subscriber Name)</label>
                <input
                  type="text"
                  required
                  value={policyHolder}
                  onChange={(e) => setPolicyHolder(e.target.value)}
                  placeholder="e.g. Jane Doe"
                  className="w-full px-3 py-2 bg-canvas-soft border border-hairline rounded-lg text-ink focus:outline-none focus:border-ink"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-muted font-medium mb-1">Insurance Carrier</label>
                  <input
                    type="text"
                    required
                    value={providerName}
                    onChange={(e) => setProviderName(e.target.value)}
                    placeholder="e.g. BlueCross BlueShield"
                    className="w-full px-3 py-2 bg-canvas-soft border border-hairline rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
                <div>
                  <label className="block text-muted font-medium mb-1">Coverage Plan Type</label>
                  <input
                    type="text"
                    required
                    value={coverageType}
                    onChange={(e) => setCoverageType(e.target.value)}
                    placeholder="e.g. Comprehensive Platinum PPO"
                    className="w-full px-3 py-2 bg-canvas-soft border border-hairline rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-muted font-medium mb-1">Copay</label>
                  <div className="relative">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted font-mono select-none">$</span>
                    <input
                      type="text"
                      required
                      value={copay}
                      onChange={(e) => setCopay(e.target.value.replace(/^\$/, ""))}
                      placeholder="25.00"
                      className="w-full pl-7 pr-3 py-2 bg-canvas-soft border border-hairline rounded-lg text-ink font-mono focus:outline-none focus:border-ink"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-muted font-medium mb-1">Deductible</label>
                  <div className="relative">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-muted font-mono select-none">$</span>
                    <input
                      type="text"
                      required
                      value={deductible}
                      onChange={(e) => setDeductible(e.target.value.replace(/^\$/, ""))}
                      placeholder="500.00"
                      className="w-full pl-7 pr-3 py-2 bg-canvas-soft border border-hairline rounded-lg text-ink font-mono focus:outline-none focus:border-ink"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-muted font-medium mb-1">Valid Until</label>
                  <input
                    type="date"
                    required
                    value={validUntil}
                    onChange={(e) => setValidUntil(e.target.value)}
                    className="w-full px-3 py-2 bg-canvas-soft border border-hairline rounded-lg text-ink font-mono focus:outline-none focus:border-ink"
                  />
                </div>
              </div>

              <div className="flex flex-col-reverse sm:flex-row sm:items-center sm:justify-end gap-3 pt-4 border-t border-hairline">
                <button
                  type="button"
                  onClick={() => setShowIssueModal(false)}
                  className="px-4 py-2.5 rounded-pill bg-canvas-soft hover:bg-surface-hover text-ink text-xs font-medium border border-hairline transition-all text-center"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={issuingPolicy}
                  className="px-6 py-2.5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium transition-all shadow-sm text-center"
                >
                  {issuingPolicy ? "Issuing Policy..." : "Issue & Link Coverage"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Verification Card */}
      <div className="bg-surface-card border border-hairline rounded-2xl p-6 sm:p-8 shadow-card space-y-6">
        <div>
          <h2 className="font-display text-xl text-ink font-light">Verify Patient Policy & Eligibility</h2>
          <p className="text-xs text-muted">Look up real-time policy benefits and active patient coverage</p>
        </div>

        <form onSubmit={handleVerify} className="max-w-xl">
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={searchId}
              onChange={(e) => setSearchId(e.target.value)}
              placeholder="e.g. INS-99210 or INS-77412"
              className="w-full px-4 py-2.5 bg-canvas-soft border border-hairline-strong rounded-pill text-xs text-ink placeholder-muted focus:outline-none focus:border-ink font-mono"
              required
            />
            <button
              type="submit"
              disabled={verifying}
              className="px-6 py-2.5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium shadow-sm transition-all shrink-0 text-center"
            >
              {verifying ? "Verifying..." : "Verify Policy"}
            </button>
          </div>
        </form>

        {verifyError && (
          <div className="p-4 rounded-xl bg-rose-50/70 border border-rose-200 text-rose-800 text-xs flex items-center gap-3 animate-in fade-in duration-200">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            <div>
              <span className="font-semibold block text-rose-900">Policy Verification Notice</span>
              <span className="text-rose-700">{verifyError}</span>
            </div>
          </div>
        )}

        {verifiedRecord && (
          <div className="p-6 rounded-2xl bg-canvas-soft border border-hairline space-y-4 animate-in fade-in duration-200">
            <div className="flex items-center justify-between pb-3 border-b border-hairline">
              <div className="flex items-center gap-2 text-emerald-800 font-semibold text-xs">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                <span>Active Verified Coverage</span>
              </div>
              <span className="px-2.5 py-0.5 rounded-pill bg-surface-card border border-hairline text-xs font-mono text-ink">
                {verifiedRecord.insurance_id}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
              <div>
                <span className="text-[10px] text-muted uppercase font-semibold block mb-0.5">Policyholder</span>
                <span className="font-medium text-ink">{verifiedRecord.policy_holder}</span>
              </div>
              <div>
                <span className="text-[10px] text-muted uppercase font-semibold block mb-0.5">Insurance Carrier</span>
                <span className="font-medium text-ink">{verifiedRecord.provider_name}</span>
              </div>
              <div>
                <span className="text-[10px] text-muted uppercase font-semibold block mb-0.5">Specialist Copay</span>
                <span className="font-mono font-medium text-ink">{verifiedRecord.copay}</span>
              </div>
              <div>
                <span className="text-[10px] text-muted uppercase font-semibold block mb-0.5">Annual Deductible</span>
                <span className="font-mono font-medium text-ink">{verifiedRecord.deductible}</span>
              </div>
            </div>

            <div className="pt-2 text-xs text-body border-t border-hairline/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span>Plan Coverage: <strong className="text-ink">{verifiedRecord.coverage}</strong></span>
              <span className="text-[11px] text-muted font-mono">Valid Through: {verifiedRecord.valid_until}</span>
            </div>
          </div>
        )}
      </div>

      {/* Policies Table */}
      <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-xl text-ink font-light">Active Patient Policies</h2>
          <span className="text-xs font-mono text-muted">{records.length} Policies</span>
        </div>

        <div className="overflow-x-auto -mx-4 sm:mx-0 px-4 sm:px-0">
          <table className="w-full text-left text-xs min-w-[650px]">
            <thead>
              <tr className="border-b border-hairline text-muted font-medium">
                <th className="pb-3 pl-3">POLICY ID</th>
                <th className="pb-3">SUBSCRIBER</th>
                <th className="pb-3">CARRIER & PLAN</th>
                <th className="pb-3">COPAY / DEDUCTIBLE</th>
                <th className="pb-3">STATUS</th>
                <th className="pb-3 text-right pr-3">PATIENT</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loadingRecords ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    Loading insurance records...
                  </td>
                </tr>
              ) : records.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    No insurance records registered in system.
                  </td>
                </tr>
              ) : (
                records.map((r) => (
                  <tr key={r.id} className="hover:bg-canvas-soft/80 transition-colors">
                    <td className="py-4 pl-3 font-mono font-medium text-ink">{r.insurance_id}</td>
                    <td className="py-4 font-medium text-ink">{r.policy_holder}</td>
                    <td className="py-4 text-body">
                      <div className="font-medium text-ink">{r.provider_name}</div>
                      <span className="text-[11px] text-muted">{r.coverage_type}</span>
                    </td>
                    <td className="py-4 text-body font-mono text-[11px]">
                      {r.copay} Copay &bull; {r.deductible} Deductible
                    </td>
                    <td className="py-4">
                      <span className="px-2.5 py-0.5 rounded-pill bg-emerald-50 text-emerald-800 border border-emerald-200 text-[10px] font-medium">
                        {r.status || "ACTIVE"}
                      </span>
                    </td>
                    <td className="py-4 text-right pr-3">
                      <Link
                        href={`/dashboard/patient/${r.patient_mrn}`}
                        className="inline-flex items-center gap-1 px-3 py-1 rounded-pill bg-surface-strong hover:bg-ink hover:text-white text-ink text-[11px] font-medium border border-hairline transition-all"
                      >
                        <span>Chart</span>
                        <ArrowUpRight className="w-3 h-3 opacity-70" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
