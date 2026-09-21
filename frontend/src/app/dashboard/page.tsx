"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { wafFetch } from "@/lib/api";
import {
  Users,
  Search,
  Plus,
  ArrowUpRight,
  Activity,
  Calendar,
  FileText,
  CreditCard,
  CheckCircle2,
  X,
  UserPlus
} from "lucide-react";

export default function DashboardPage() {
  const [patients, setPatients] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({
    active_patients: 0,
    scheduled_encounters: 0,
    diagnostic_reports: 0,
    clinical_notes: 0,
    active_prescriptions: 0,
    system_status: "Optimal"
  });
  const [searchQuery, setSearchQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [showNewModal, setShowNewModal] = useState(false);

  // New Patient Form State
  const [newName, setNewName] = useState("");
  const [newDob, setNewDob] = useState("");
  const [newGender, setNewGender] = useState("Female");
  const [newBlood, setNewBlood] = useState("");
  const [newDiagnosis, setNewDiagnosis] = useState("");
  const [newInsurance, setNewInsurance] = useState("");
  const [newPhysician, setNewPhysician] = useState("Dr. Sarah Chen, MD");
  const [newDepartment, setNewDepartment] = useState("Internal Medicine");
  const [newPhone, setNewPhone] = useState("");
  const [newAddress, setNewAddress] = useState("");
  const [newEmergencyContact, setNewEmergencyContact] = useState("");
  const [newAllergies, setNewAllergies] = useState("");
  const [creating, setCreating] = useState(false);

  const fetchStats = async () => {
    const res = await wafFetch("/api/dashboard/stats");
    if (res.status === 200 && res.data?.stats) {
      setStats(res.data.stats);
    }
  };

  const fetchPatients = async (q = "") => {
    setLoading(true);
    const endpoint = q ? `/api/patients?q=${encodeURIComponent(q)}` : "/api/patients";
    const res = await wafFetch(endpoint);
    setLoading(false);
    if (res.status === 200 && res.data?.patients) {
      setPatients(res.data.patients);
    }
    fetchStats();
  };

  useEffect(() => {
    fetchPatients();
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchPatients(searchQuery);
  };

  const handleCreatePatient = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);

    const res = await wafFetch("/api/patients", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: newName,
        dob: newDob,
        gender: newGender,
        blood_group: newBlood,
        diagnosis: newDiagnosis,
        insurance_id: newInsurance.trim() || "Self-Pay",
        primary_physician: newPhysician,
        department: newDepartment,
        phone: newPhone,
        address: newAddress,
        emergency_contact: newEmergencyContact,
        allergies: newAllergies,
      }),
    });

    setCreating(false);

    if (res.status === 200 || res.status === 201) {
      setShowNewModal(false);
      setNewName("");
      setNewDiagnosis("");
      fetchPatients();
    } else {
      alert("Failed to create patient: " + (res.data?.error || "Error"));
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
              Clinical Directory
            </span>
          </div>
          <h1 className="font-display text-3xl sm:text-4xl text-ink font-light tracking-tight">
            Patient Electronic Health Records
          </h1>
          <p className="text-sm text-body mt-1">
            Real-time longitudinal clinical records &bull; Secure Encrypted EHR
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowNewModal(true)}
            className="h-10 px-5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium transition-all shadow-sm flex items-center gap-2"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Admit New Patient</span>
          </button>
        </div>
      </div>

      {/* Metrics Row (Responsive Grid) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-surface-card border border-hairline shadow-card">
          <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block mb-1">
            Active Patients
          </span>
          <div className="font-display text-3xl text-ink font-light">{patients.length}</div>
          <span className="text-[11px] text-muted-soft block mt-1">Under Active Care</span>
        </div>

        <div className="p-5 rounded-xl bg-surface-card border border-hairline shadow-card">
          <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block mb-1">
            Scheduled Encounters
          </span>
          <div className="font-display text-3xl text-ink font-light">{stats.scheduled_encounters ?? 0}</div>
          <span className="text-[11px] text-muted-soft block mt-1">This Week</span>
        </div>

        <div className="p-5 rounded-xl bg-surface-card border border-hairline shadow-card">
          <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block mb-1">
            Diagnostic Reports
          </span>
          <div className="font-display text-3xl text-ink font-light">{stats.diagnostic_reports ?? 0}</div>
          <span className="text-[11px] text-muted-soft block mt-1">Archived Records</span>
        </div>

        <div className="p-5 rounded-xl bg-surface-card border border-hairline shadow-card">
          <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block mb-1">
            Clinical System Status
          </span>
          <div className="font-display text-2xl text-ink font-light flex items-center gap-2">
            <span>{stats.system_status || "Optimal"}</span>
          </div>
          <span className="text-[11px] text-emerald-600 block mt-1 flex items-center gap-1 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            HIPAA Compliant EHR
          </span>
        </div>
      </div>

      {/* Search & Directory Table */}
      <div className="bg-surface-card border border-hairline rounded-2xl p-4 sm:p-6 shadow-card space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <form onSubmit={handleSearch} className="flex-grow max-w-lg">
            <div className="relative">
              <Search className="w-4 h-4 text-muted absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by patient name, MRN, diagnosis, or clinician..."
                className="w-full pl-10 pr-24 py-2.5 bg-canvas-soft border border-hairline-strong rounded-pill text-xs text-ink placeholder-muted focus:outline-none focus:border-ink transition-colors"
              />
              <button
                type="submit"
                className="absolute right-1.5 top-1/2 -translate-y-1/2 px-3.5 py-1.5 bg-ink-primary hover:bg-ink-primary-active text-white text-[11px] font-medium rounded-pill transition-colors"
              >
                Search
              </button>
            </div>
          </form>

          {searchQuery && (
            <button
              onClick={() => {
                setSearchQuery("");
                fetchPatients("");
              }}
              className="text-xs text-muted hover:text-ink font-medium self-start sm:self-auto"
            >
              Clear Filter
            </button>
          )}
        </div>

        {/* Patients Table */}
        <div className="overflow-x-auto -mx-4 sm:mx-0 px-4 sm:px-0">
          <table className="w-full text-left text-xs min-w-[600px]">
            <thead>
              <tr className="border-b border-hairline text-muted font-medium">
                <th className="pb-3 pl-3">MRN</th>
                <th className="pb-3">PATIENT NAME</th>
                <th className="pb-3">DOB / GENDER</th>
                <th className="pb-3">DIAGNOSIS</th>
                <th className="pb-3">PRIMARY PHYSICIAN</th>
                <th className="pb-3 text-right pr-3">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    Loading records from MySQL database...
                  </td>
                </tr>
              ) : patients.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    No matching patient records found.
                  </td>
                </tr>
              ) : (
                patients.map((p) => (
                  <tr key={p.mrn} className="hover:bg-canvas-soft/80 transition-colors group">
                    <td className="py-4 pl-3 font-mono font-medium text-ink">{p.mrn}</td>
                    <td className="py-4 font-medium text-ink">
                      <div>{p.name}</div>
                      <span className="text-[11px] text-muted">{p.phone || "No phone"}</span>
                    </td>
                    <td className="py-4 text-body">
                      <div>{p.dob}</div>
                      <span className="text-[11px] text-muted">{p.gender} &bull; {p.blood_group}</span>
                    </td>
                    <td className="py-4 text-body max-w-xs truncate">{p.diagnosis}</td>
                    <td className="py-4 text-body">
                      <div>{p.primary_physician}</div>
                      <span className="text-[11px] text-muted">{p.department || "Internal Medicine"}</span>
                    </td>
                    <td className="py-4 text-right pr-3">
                      <Link
                        href={`/dashboard/patient/${p.mrn}`}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-pill bg-surface-strong hover:bg-ink hover:text-white text-ink text-xs font-medium border border-hairline transition-all shadow-sm"
                      >
                        <span>Open EHR Chart</span>
                        <ArrowUpRight className="w-3.5 h-3.5 opacity-70" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Admit Patient Modal */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-surface-card border border-hairline rounded-2xl p-5 sm:p-8 max-w-xl w-full shadow-elevated relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-hairline">
              <div>
                <h3 className="font-display text-2xl text-ink font-light">Admit New Patient</h3>
                <p className="text-xs text-muted">Register electronic health record in MySQL database</p>
              </div>
              <button
                onClick={() => setShowNewModal(false)}
                className="p-1 rounded-full hover:bg-surface-strong text-muted hover:text-ink transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreatePatient} className="space-y-4 text-xs">
              <div>
                <label className="block font-medium text-body-strong mb-1">Full Legal Name</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. Eleanor Vance"
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  required
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Date of Birth</label>
                  <input
                    type="date"
                    value={newDob}
                    onChange={(e) => setNewDob(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Gender</label>
                  <select
                    value={newGender}
                    onChange={(e) => setNewGender(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Female">Female</option>
                    <option value="Male">Male</option>
                    <option value="Non-binary">Non-binary</option>
                    <option value="Other">Other</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Blood Group</label>
                  <input
                    type="text"
                    value={newBlood}
                    onChange={(e) => setNewBlood(e.target.value)}
                    placeholder="e.g. O+"
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Contact Phone</label>
                  <input
                    type="text"
                    value={newPhone}
                    onChange={(e) => setNewPhone(e.target.value)}
                    placeholder="e.g. +1 (555) 789-0123"
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1">Primary Clinical Diagnosis</label>
                <input
                  type="text"
                  value={newDiagnosis}
                  onChange={(e) => setNewDiagnosis(e.target.value)}
                  placeholder="e.g. Primary Generalized Osteoarthritis"
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  required
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Attending Physician</label>
                  <select
                    value={newPhysician}
                    onChange={(e) => setNewPhysician(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Dr. Sarah Chen, MD">Dr. Sarah Chen, MD</option>
                    <option value="Dr. Marcus Vance, MD">Dr. Marcus Vance, MD</option>
                    <option value="Dr. Emily Watson, MD">Dr. Emily Watson, MD</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Primary Clinic / Dept</label>
                  <select
                    value={newDepartment}
                    onChange={(e) => setNewDepartment(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Internal Medicine">Internal Medicine</option>
                    <option value="Endocrinology">Endocrinology</option>
                    <option value="Cardiology">Cardiology</option>
                    <option value="Pulmonology">Pulmonology</option>
                    <option value="Orthopedic Surgery">Orthopedic Surgery</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Emergency Contact</label>
                  <input
                    type="text"
                    value={newEmergencyContact}
                    onChange={(e) => setNewEmergencyContact(e.target.value)}
                    placeholder="e.g. Spouse (+1 555-987-6543)"
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Residential Address</label>
                  <input
                    type="text"
                    value={newAddress}
                    onChange={(e) => setNewAddress(e.target.value)}
                    placeholder="e.g. 742 Evergreen Terrace, Springfield, IL"
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
              </div>

              <div className="pt-4 flex items-center justify-end gap-3 border-t border-hairline">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className="px-4 py-2 rounded-pill text-muted hover:text-ink hover:bg-surface-strong"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-5 py-2.5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white font-medium shadow-sm transition-all"
                >
                  {creating ? "Saving Patient..." : "Admit Patient"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
