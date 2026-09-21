"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { wafFetch, WAF_BASE_URL } from "@/lib/api";
import {
  ArrowLeft,
  User,
  HeartPulse,
  Pill,
  FileText,
  Calendar,
  Upload,
  Download,
  Plus,
  CheckCircle2,
  AlertCircle,
  Clock,
  Shield,
  Stethoscope,
  Send,
  Edit3,
  Trash2,
  AlertTriangle,
  X
} from "lucide-react";

export default function PatientChartPage() {
  const params = useParams();
  const router = useRouter();
  const mrn = (params?.mrn as string) || "MRN-10234";

  const [patient, setPatient] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"overview" | "notes" | "prescriptions" | "documents">("overview");

  // Edit Patient State
  const [showEditModal, setShowEditModal] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDob, setEditDob] = useState("");
  const [editGender, setEditGender] = useState("");
  const [editBlood, setEditBlood] = useState("");
  const [editDiagnosis, setEditDiagnosis] = useState("");
  const [editPhysician, setEditPhysician] = useState("");
  const [editDepartment, setEditDepartment] = useState("");
  const [editPhone, setEditPhone] = useState("");
  const [editAddress, setEditAddress] = useState("");
  const [editEmergencyContact, setEditEmergencyContact] = useState("");
  const [editAllergies, setEditAllergies] = useState("");
  const [editInsurance, setEditInsurance] = useState("");
  const [editStatus, setEditStatus] = useState("ACTIVE");
  const [updatingPatient, setUpdatingPatient] = useState(false);

  // Delete Patient State
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deletingPatient, setDeletingPatient] = useState(false);

  // Add Note Form State
  const [noteText, setNoteText] = useState("");
  const [noteTitle, setNoteTitle] = useState("");
  const [noteCategory, setNoteCategory] = useState("SOAP Progress Note");
  const [savingNote, setSavingNote] = useState(false);

  // Add Prescription Form State
  const [medName, setMedName] = useState("");
  const [medDosage, setMedDosage] = useState("");
  const [medFreq, setMedFreq] = useState("Twice daily with meals (BID)");
  const [durationValue, setDurationValue] = useState("");
  const [durationUnit, setDurationUnit] = useState("Days");
  const [medInstructions, setMedInstructions] = useState("");
  const [savingMed, setSavingMed] = useState(false);

  // File Upload State (BLOB Storage)
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileCategory, setFileCategory] = useState("Diagnostic Lab Report");
  const [fileDescription, setFileDescription] = useState("");
  const [uploadingFile, setUploadingFile] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState("");

  const loadPatientChart = async () => {
    setLoading(true);
    const res = await wafFetch(`/api/patients/${mrn}`);
    setLoading(false);
    if (res.status === 200 && res.data?.chart) {
      const p = res.data.chart;
      setPatient(p);
      setEditName(p.name || "");
      setEditDob(p.dob || "1990-01-01");
      setEditGender(p.gender || "Female");
      setEditBlood(p.blood_group || "O+");
      setEditDiagnosis(p.diagnosis || "");
      setEditPhysician(p.primary_physician || "Dr. Sarah Chen, MD");
      setEditDepartment(p.department || "Internal Medicine");
      setEditPhone(p.phone || "");
      setEditAddress(p.address || "");
      setEditEmergencyContact(p.emergency_contact || "");
      setEditAllergies(p.allergies || "");
      setEditInsurance(p.insurance_id || "");
      setEditStatus(p.status || "ACTIVE");
    }
  };

  useEffect(() => {
    loadPatientChart();
  }, [mrn]);

  const handleUpdatePatient = async (e: React.FormEvent) => {
    e.preventDefault();
    setUpdatingPatient(true);

    const res = await wafFetch(`/api/patients/${mrn}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: editName,
        dob: editDob,
        gender: editGender,
        blood_group: editBlood,
        diagnosis: editDiagnosis,
        primary_physician: editPhysician,
        department: editDepartment,
        phone: editPhone,
        address: editAddress,
        emergency_contact: editEmergencyContact,
        allergies: editAllergies,
        insurance_id: editInsurance,
        status: editStatus,
      }),
    });

    setUpdatingPatient(false);

    if (res.status === 200 && res.data?.patient) {
      setPatient(res.data.patient);
      setShowEditModal(false);
    } else {
      alert("Failed to update patient: " + (res.data?.error || "Error"));
    }
  };

  const handleDeletePatient = async () => {
    setDeletingPatient(true);
    const res = await wafFetch(`/api/patients/${mrn}`, {
      method: "DELETE",
    });
    setDeletingPatient(false);

    if (res.status === 200) {
      setShowDeleteModal(false);
      router.push("/dashboard");
    } else {
      alert("Failed to delete patient: " + (res.data?.error || "Error"));
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteText.trim()) return;

    setSavingNote(true);
    const res = await wafFetch(`/api/patients/${mrn}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        note: noteText,
        title: noteTitle,
        category: noteCategory,
        author: "Dr. Sarah Chen, MD",
      }),
    });
    setSavingNote(false);

    if (res.status === 200 || res.status === 201) {
      setNoteText("");
      loadPatientChart();
    } else {
      alert("Failed to save note: " + (res.data?.error || "Error"));
    }
  };

  const handleAddPrescription = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!medName.trim()) return;

    const formattedDuration =
      durationUnit === "Ongoing / Continuous"
        ? "Ongoing / Continuous"
        : `${durationValue} ${durationUnit}`;

    setSavingMed(true);
    const res = await wafFetch(`/api/patients/${mrn}/prescriptions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        medication_name: medName,
        dosage: medDosage,
        frequency: medFreq,
        duration: formattedDuration,
        instructions: medInstructions,
        prescribed_by: "Dr. Sarah Chen, MD",
      }),
    });
    setSavingMed(false);

    if (res.status === 200 || res.status === 201) {
      setMedName("");
      loadPatientChart();
    } else {
      alert("Failed to add prescription: " + (res.data?.error || "Error"));
    }
  };

  const handleFileUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;

    setUploadingFile(true);
    setUploadSuccess("");

    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("category", fileCategory);
    formData.append("description", fileDescription || selectedFile.name);
    formData.append("uploaded_by", "Dr. Sarah Chen, MD");

    try {
      const response = await fetch(`${WAF_BASE_URL}/api/patients/${mrn}/documents/upload`, {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      setUploadingFile(false);

      if (response.ok) {
        setUploadSuccess(`Document "${data.file?.filename}" uploaded successfully (${(data.file?.file_size / 1024).toFixed(1)} KB).`);
        setSelectedFile(null);
        setFileDescription("");
        loadPatientChart();
      } else {
        alert("Upload failed: " + (data.reason || data.error || data.message || "Server error"));
      }
    } catch (err: any) {
      setUploadingFile(false);
      alert(`Upload failed: Could not connect to the gateway at ${WAF_BASE_URL}. Ensure the WAF gateway (port 8000) and backend server (port 8080) are running.`);
    }
  };

  if (loading) {
    return (
      <div className="py-24 text-center">
        <div className="inline-flex items-center gap-2 text-muted text-sm font-medium">
          <span className="w-2 h-2 rounded-full bg-ink animate-ping" />
          <span>Loading Electronic Health Record...</span>
        </div>
      </div>
    );
  }

  if (!patient) {
    return (
      <div className="py-24 text-center">
        <h2 className="font-display text-2xl text-ink font-light">Patient Record Not Found</h2>
        <Link href="/dashboard" className="text-xs text-muted hover:text-ink mt-3 inline-block">
          &larr; Return to Patient Directory
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Top Back Navigation */}
      <div className="flex items-center justify-between pb-4 border-b border-hairline">
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 text-xs font-medium text-muted hover:text-ink transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to EHR Directory</span>
        </Link>
        <span className="text-xs font-mono text-muted">
          Record ID: <strong className="text-ink">{patient.mrn}</strong>
        </span>
      </div>

      {/* Patient Header Card (Magazine Style) */}
      <div className="bg-surface-card border border-hairline rounded-2xl p-6 sm:p-8 shadow-card relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5">
            <div className="w-16 h-16 rounded-full bg-gradient-mint flex items-center justify-center text-ink font-display text-2xl font-light shrink-0">
              {patient.name.split(" ").map((n: string) => n[0]).join("")}
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="font-display text-3xl sm:text-4xl text-ink font-light tracking-tight">
                  {patient.name}
                </h1>
                <span className="px-3 py-1 rounded-pill bg-surface-strong text-body-strong border border-hairline text-xs font-mono font-medium">
                  {patient.mrn}
                </span>
                <span className="px-3 py-1 rounded-pill bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs font-medium">
                  Active Inpatient
                </span>
              </div>
              <p className="text-xs text-muted mt-1.5 flex items-center gap-3 flex-wrap">
                <span>DOB: <strong className="text-body-strong font-medium">{patient.dob}</strong></span>
                <span>&bull;</span>
                <span>Gender: <strong className="text-body-strong font-medium">{patient.gender}</strong></span>
                <span>&bull;</span>
                <span>Blood: <strong className="text-body-strong font-medium">{patient.blood_group}</strong></span>
                <span>&bull;</span>
                <span>Phone: <strong className="text-body-strong font-medium">{patient.phone}</strong></span>
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="px-4 py-2.5 rounded-xl bg-canvas-soft border border-hairline text-left">
              <span className="text-[10px] uppercase font-semibold text-muted tracking-wider block">
                Primary Physician
              </span>
              <span className="text-xs font-medium text-ink block mt-0.5">
                {patient.primary_physician}
              </span>
            </div>
            {patient.insurance_id && patient.insurance_id !== "Self-Pay" && !patient.insurance_id.includes("None") && (
              <div className="px-4 py-2.5 rounded-xl bg-canvas-soft border border-hairline text-left">
                <span className="text-[10px] uppercase font-semibold text-muted tracking-wider block">
                  Insurance Policy
                </span>
                <span className="text-xs font-mono font-medium text-ink block mt-0.5">
                  {patient.insurance_id}
                </span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowEditModal(true)}
                className="h-10 px-4 rounded-pill bg-surface-card hover:bg-surface-strong text-ink border border-hairline text-xs font-medium transition-all shadow-sm flex items-center gap-1.5"
                title="Edit Patient Demographics & Record"
              >
                <Edit3 className="w-3.5 h-3.5 opacity-80" />
                <span>Edit Record</span>
              </button>
              <button
                onClick={() => setShowDeleteModal(true)}
                className="h-10 px-4 rounded-pill bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-medium transition-all shadow-sm flex items-center gap-1.5"
                title="Permanently Delete Patient Record"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-600" />
                <span>Delete</span>
              </button>
            </div>
          </div>
        </div>

        {/* Diagnosis & Allergy Summary */}
        <div className="mt-6 pt-5 border-t border-hairline grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div>
            <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block mb-1">
              Primary Clinical Diagnoses
            </span>
            <p className="text-body font-normal leading-relaxed">{patient.diagnosis}</p>
          </div>
          <div>
            <span className="text-[11px] font-semibold text-muted uppercase tracking-wider block mb-1">
              Documented Drug Allergies
            </span>
            <p className="text-rose-700 font-medium">{patient.allergies || "No Known Drug Allergies (NKDA)"}</p>
          </div>
        </div>
      </div>

      {/* 4 Tabs Menu */}
      <div className="flex items-center gap-2 border-b border-hairline pb-3 overflow-x-auto whitespace-nowrap -mx-4 sm:mx-0 px-4 sm:px-0">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-4 py-2 rounded-pill text-xs font-medium transition-all ${
            activeTab === "overview"
              ? "bg-ink-primary text-white shadow-sm"
              : "text-muted hover:text-ink hover:bg-surface-strong"
          }`}
        >
          Clinical Overview
        </button>
        <button
          onClick={() => setActiveTab("notes")}
          className={`px-4 py-2 rounded-pill text-xs font-medium transition-all ${
            activeTab === "notes"
              ? "bg-ink-primary text-white shadow-sm"
              : "text-muted hover:text-ink hover:bg-surface-strong"
          }`}
        >
          Progress Notes ({patient.notes?.length || 0})
        </button>
        <button
          onClick={() => setActiveTab("prescriptions")}
          className={`px-4 py-2 rounded-pill text-xs font-medium transition-all ${
            activeTab === "prescriptions"
              ? "bg-ink-primary text-white shadow-sm"
              : "text-muted hover:text-ink hover:bg-surface-strong"
          }`}
        >
          Prescriptions ({patient.prescriptions?.length || 0})
        </button>
        <button
          onClick={() => setActiveTab("documents")}
          className={`px-4 py-2 rounded-pill text-xs font-medium transition-all ${
            activeTab === "documents"
              ? "bg-ink-primary text-white shadow-sm"
              : "text-muted hover:text-ink hover:bg-surface-strong"
          }`}
        >
          Diagnostic Documents ({patient.documents?.length || 0})
        </button>
      </div>

      {/* Tab 1: Overview */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-6">
            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4">
              <h2 className="font-display text-xl text-ink font-light">Recent Clinical Encounters</h2>
              <div className="space-y-3">
                {patient.notes?.slice(0, 2).map((n: any) => (
                  <div key={n.id} className="p-4 rounded-xl bg-canvas-soft border border-hairline space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-semibold text-ink">{n.title || n.author}</span>
                      <span className="text-muted font-mono">{n.created_at || "2026-08-10"}</span>
                    </div>
                    <p className="text-xs text-body leading-relaxed">{n.text}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-3">
              <h2 className="font-display text-xl text-ink font-light">Active Medical Regimens</h2>
              <div className="divide-y divide-hairline">
                {patient.prescriptions?.map((p: any) => (
                  <div key={p.id} className="py-3 flex items-center justify-between text-xs">
                    <div>
                      <span className="font-medium text-ink block">{p.medication_name} ({p.dosage})</span>
                      <span className="text-muted text-[11px]">{p.frequency} &bull; {p.instructions}</span>
                    </div>
                    <span className="px-2.5 py-1 rounded-pill bg-emerald-50 text-emerald-800 text-[10px] font-medium">
                      {p.status || "ACTIVE"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="p-5 rounded-2xl bg-surface-card border border-hairline shadow-card space-y-3 text-xs">
              <span className="font-display text-lg text-ink font-light block">Patient Demographics</span>
              <div className="space-y-2 text-body">
                <div>Emergency Contact: <strong className="text-ink">{patient.emergency_contact}</strong></div>
                <div>Residential Address: <strong className="text-ink">{patient.address}</strong></div>
                <div>Primary Clinic: <strong className="text-ink">{patient.department || "Internal Medicine"}</strong></div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Progress Notes */}
      {activeTab === "notes" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4">
              <h2 className="font-display text-xl text-ink font-light">Clinical Progress Timeline</h2>
              <div className="space-y-4">
                {patient.notes?.map((n: any) => (
                  <div key={n.id} className="p-5 rounded-xl bg-canvas-soft border border-hairline space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <div>
                        <span className="font-medium text-ink block">{n.title || "Progress Encounter"}</span>
                        <span className="text-[11px] text-muted">{n.author || n.author_name} &bull; {n.author_role || "Clinician"}</span>
                      </div>
                      <span className="text-[11px] text-muted font-mono">{n.created_at || "2026-08-10"}</span>
                    </div>
                    <p className="text-xs text-body leading-relaxed pt-1 border-t border-hairline/60">
                      {n.text}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Add Note Form */}
          <div className="lg:col-span-5">
            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4 sticky top-24">
              <div>
                <h2 className="font-display text-xl text-ink font-light">Add Progress Note</h2>
                <p className="text-xs text-muted">Add clinical encounter notes to patient chart</p>
              </div>

              <form onSubmit={handleAddNote} className="space-y-3 text-xs">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Encounter Title</label>
                  <input
                    type="text"
                    value={noteTitle}
                    onChange={(e) => setNoteTitle(e.target.value)}
                    placeholder="e.g. Routine Diabetic Review & Follow-Up"
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                    required
                  />
                </div>

                <div>
                  <label className="block font-medium text-body-strong mb-1">Note Category</label>
                  <select
                    value={noteCategory}
                    onChange={(e) => setNoteCategory(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="SOAP Progress Note">SOAP Progress Note</option>
                    <option value="Consultation Review">Consultation Review</option>
                    <option value="Diagnostic Evaluation">Diagnostic Evaluation</option>
                    <option value="Discharge Summary">Discharge Summary</option>
                  </select>
                </div>

                <div>
                  <label className="block font-medium text-body-strong mb-1">Clinical Observations & Plan</label>
                  <textarea
                    rows={5}
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                    placeholder="Enter subjective symptoms, objective findings, assessment, and treatment plan..."
                    className="w-full p-3 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink leading-relaxed"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={savingNote}
                  className="w-full h-10 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium transition-all shadow-sm flex items-center justify-center gap-2"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>{savingNote ? "Saving Note..." : "Save Note to Record"}</span>
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Prescriptions */}
      {activeTab === "prescriptions" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4">
              <h2 className="font-display text-xl text-ink font-light">Active Prescriptions & Regimens</h2>
              <div className="divide-y divide-hairline">
                {patient.prescriptions?.map((p: any) => (
                  <div key={p.id} className="py-4 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <div className="font-semibold text-sm text-ink">{p.medication_name}</div>
                      <span className="px-2.5 py-0.5 rounded-pill bg-emerald-50 text-emerald-800 border border-emerald-200 text-[10px] font-medium">
                        {p.status || "ACTIVE"}
                      </span>
                    </div>
                    <div className="text-body flex items-center gap-3">
                      <span>Dosage: <strong className="text-ink">{p.dosage}</strong></span>
                      <span>&bull;</span>
                      <span>Frequency: <strong className="text-ink">{p.frequency}</strong></span>
                      <span>&bull;</span>
                      <span>Duration: <strong className="text-ink">{p.duration}</strong></span>
                    </div>
                    <p className="text-muted text-[11px] pt-1">
                      Instructions: {p.instructions} &bull; Prescribed by {p.prescribed_by}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Add Prescription Form */}
          <div className="lg:col-span-5">
            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4 sticky top-24">
              <div>
                <h2 className="font-display text-xl text-ink font-light">Prescribe Medication</h2>
                <p className="text-xs text-muted">Authorize new pharmaceutical order</p>
              </div>

              <form onSubmit={handleAddPrescription} className="space-y-3 text-xs">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Medication Name</label>
                  <input
                    type="text"
                    value={medName}
                    onChange={(e) => setMedName(e.target.value)}
                    placeholder="e.g. Metformin Hydrochloride"
                    className="w-full px-3.5 py-2 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                    required
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <label className="block font-medium text-body-strong mb-1">Dosage</label>
                    <input
                      type="text"
                      value={medDosage}
                      onChange={(e) => setMedDosage(e.target.value)}
                      placeholder="e.g. 500 mg"
                      className="w-full px-3.5 py-2 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                    />
                  </div>
                  <div>
                    <label className="block font-medium text-body-strong mb-1">Duration Period</label>
                    <div className="flex gap-1.5">
                      {durationUnit !== "Ongoing / Continuous" && (
                        <input
                          type="number"
                          min="1"
                          max="365"
                          value={durationValue}
                          onChange={(e) => setDurationValue(e.target.value)}
                          placeholder="30"
                          className="w-16 px-2.5 py-2 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink text-center font-mono"
                          required
                        />
                      )}
                      <select
                        value={durationUnit}
                        onChange={(e) => setDurationUnit(e.target.value)}
                        className="w-full px-2.5 py-2 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink text-xs"
                      >
                        <option value="Days">Days</option>
                        <option value="Weeks">Weeks</option>
                        <option value="Months">Months</option>
                        <option value="Ongoing / Continuous">Ongoing / Continuous</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div>
                  <label className="block font-medium text-body-strong mb-1">Frequency & Schedule</label>
                  <select
                    value={medFreq}
                    onChange={(e) => setMedFreq(e.target.value)}
                    className="w-full px-3.5 py-2 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Once daily in the morning (QAM)">Once daily in the morning (QAM)</option>
                    <option value="Once daily at bedtime (QHS)">Once daily at bedtime (QHS)</option>
                    <option value="Twice daily with meals (BID)">Twice daily with meals (BID)</option>
                    <option value="Three times daily (TID)">Three times daily (TID)</option>
                    <option value="Four times daily (QID)">Four times daily (QID)</option>
                    <option value="Every 4-6 hours as needed (PRN)">Every 4-6 hours as needed (PRN)</option>
                    <option value="Every 8 hours (Q8H)">Every 8 hours (Q8H)</option>
                    <option value="Every 12 hours (Q12H)">Every 12 hours (Q12H)</option>
                    <option value="Once weekly (QW)">Once weekly (QW)</option>
                    <option value="As directed by physician">As directed by physician</option>
                  </select>
                </div>

                <div>
                  <label className="block font-medium text-body-strong mb-1">Special Patient Instructions</label>
                  <textarea
                    rows={2}
                    value={medInstructions}
                    onChange={(e) => setMedInstructions(e.target.value)}
                    placeholder="e.g. Take with food. Do not crush or chew extended release tablets."
                    className="w-full p-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>

                <button
                  type="submit"
                  disabled={savingMed}
                  className="w-full h-10 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium transition-all shadow-sm flex items-center justify-center gap-2"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>{savingMed ? "Prescribing..." : "Authorize Prescription"}</span>
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Medical Documents & Direct File Upload */}
      {activeTab === "documents" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="font-display text-xl text-ink font-light">Diagnostic Files & Lab Reports</h2>
                  <p className="text-xs text-muted">Archived imaging scans, laboratory results, and clinical summaries</p>
                </div>
                <span className="px-3 py-1 rounded-pill bg-surface-strong text-ink text-xs font-mono">
                  {patient.documents?.length || 0} Files
                </span>
              </div>

              <div className="space-y-3">
                {patient.documents?.map((doc: any) => (
                  <div
                    key={doc.id}
                    className="p-4 rounded-xl bg-canvas-soft border border-hairline flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                  >
                    <div className="space-y-0.5">
                      <div className="font-semibold text-ink flex items-center gap-2">
                        <FileText className="w-4 h-4 text-muted" />
                        <span>{doc.original_name || doc.filename}</span>
                      </div>
                      <div className="text-[11px] text-muted">
                        {doc.category} &bull; {(doc.file_size / 1024).toFixed(1)} KB &bull; Uploaded by {doc.uploaded_by}
                      </div>
                      {doc.description && (
                        <p className="text-[11px] text-body">{doc.description}</p>
                      )}
                    </div>

                    <a
                      href={`http://localhost:8000/api/documents/${doc.id}/download`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-pill bg-surface-card hover:bg-ink hover:text-white text-ink border border-hairline text-xs font-medium transition-all shrink-0 self-start sm:self-center"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download</span>
                    </a>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Upload Document Form */}
          <div className="lg:col-span-5">
            <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4 sticky top-24">
              <div>
                <h2 className="font-display text-xl text-ink font-light">Upload Medical Document</h2>
                <p className="text-xs text-muted">Attach diagnostic record to patient chart</p>
              </div>

              {uploadSuccess && (
                <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />
                  <span>{uploadSuccess}</span>
                </div>
              )}

              <form onSubmit={handleFileUpload} className="space-y-4 text-xs">
                <div>
                  <label className="block font-medium text-body-strong mb-1.5">Select Medical File (PDF / Image / TXT)</label>
                  <input
                    type="file"
                    onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                    className="w-full text-xs text-body file:mr-4 file:py-2 file:px-4 file:rounded-pill file:border-0 file:text-xs file:font-medium file:bg-surface-strong file:text-ink hover:file:bg-hairline cursor-pointer"
                    required
                  />
                </div>

                <div>
                  <label className="block font-medium text-body-strong mb-1">Document Classification</label>
                  <select
                    value={fileCategory}
                    onChange={(e) => setFileCategory(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Diagnostic Lab Report">Diagnostic Lab Report</option>
                    <option value="Cardiology Diagnostics">Cardiology Diagnostics</option>
                    <option value="Radiology Imaging">Radiology Imaging</option>
                    <option value="Pathology Biopsy">Pathology Biopsy</option>
                    <option value="Consultation Summary">Consultation Summary</option>
                  </select>
                </div>

                <div>
                  <label className="block font-medium text-body-strong mb-1">Clinical Description / Summary</label>
                  <textarea
                    rows={3}
                    value={fileDescription}
                    onChange={(e) => setFileDescription(e.target.value)}
                    placeholder="e.g. 6-Month post-op MRI radiograph series..."
                    className="w-full p-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>

                <button
                  type="submit"
                  disabled={uploadingFile || !selectedFile}
                  className="w-full h-10 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium transition-all shadow-sm flex items-center justify-center gap-2"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>{uploadingFile ? "Uploading..." : "Upload Document"}</span>
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Edit Patient Details Modal */}
      {showEditModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-surface-card border border-hairline rounded-2xl p-6 sm:p-8 max-w-2xl w-full shadow-elevated relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-hairline">
              <div>
                <h3 className="font-display text-2xl text-ink font-light">Edit Patient Details</h3>
                <p className="text-xs text-muted">Update clinical electronic health record for {patient.mrn}</p>
              </div>
              <button
                onClick={() => setShowEditModal(false)}
                className="p-1 rounded-full hover:bg-surface-strong text-muted hover:text-ink transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleUpdatePatient} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Full Legal Name</label>
                  <input
                    type="text"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                    required
                  />
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Date of Birth</label>
                  <input
                    type="date"
                    value={editDob}
                    onChange={(e) => setEditDob(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink font-mono"
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Gender</label>
                  <select
                    value={editGender}
                    onChange={(e) => setEditGender(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Female">Female</option>
                    <option value="Male">Male</option>
                    <option value="Non-binary">Non-binary</option>
                    <option value="Other">Other</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Blood Group</label>
                  <input
                    type="text"
                    value={editBlood}
                    onChange={(e) => setEditBlood(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Contact Phone</label>
                  <input
                    type="text"
                    value={editPhone}
                    onChange={(e) => setEditPhone(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1">Primary Clinical Diagnoses</label>
                <textarea
                  rows={2}
                  value={editDiagnosis}
                  onChange={(e) => setEditDiagnosis(e.target.value)}
                  className="w-full p-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink leading-relaxed"
                  required
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Primary Physician</label>
                  <select
                    value={editPhysician}
                    onChange={(e) => setEditPhysician(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Dr. Sarah Chen, MD">Dr. Sarah Chen, MD</option>
                    <option value="Dr. Marcus Vance, MD">Dr. Marcus Vance, MD</option>
                    <option value="Dr. Emily Watson, MD">Dr. Emily Watson, MD</option>
                    <option value="Nurse Practitioner Miller, NP">Nurse Practitioner Miller</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Department / Clinic</label>
                  <select
                    value={editDepartment}
                    onChange={(e) => setEditDepartment(e.target.value)}
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

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Emergency Contact</label>
                  <input
                    type="text"
                    value={editEmergencyContact}
                    onChange={(e) => setEditEmergencyContact(e.target.value)}
                    placeholder="e.g. Family / Next of Kin"
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  />
                </div>
                {editInsurance && editInsurance !== "Self-Pay" && !editInsurance.includes("None") ? (
                  <div>
                    <label className="block font-medium text-body-strong mb-1">Active Insurance Policy</label>
                    <div className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline rounded-lg text-ink font-mono flex items-center justify-between text-xs">
                      <span>{editInsurance}</span>
                      <span className="text-[10px] text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">Issued &amp; Active</span>
                    </div>
                  </div>
                ) : null}
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1">Residential Address</label>
                <input
                  type="text"
                  value={editAddress}
                  onChange={(e) => setEditAddress(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                />
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1">Documented Drug Allergies</label>
                <input
                  type="text"
                  value={editAllergies}
                  onChange={(e) => setEditAllergies(e.target.value)}
                  placeholder="e.g. Penicillin, Sulfa"
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                />
              </div>

              <div className="pt-4 flex flex-col-reverse sm:flex-row sm:items-center sm:justify-end gap-3 border-t border-hairline">
                <button
                  type="button"
                  onClick={() => setShowEditModal(false)}
                  className="px-4 py-2.5 rounded-pill text-muted hover:text-ink text-center"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={updatingPatient}
                  className="px-5 py-2.5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white font-medium shadow-sm transition-all text-center"
                >
                  {updatingPatient ? "Saving Changes..." : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Patient Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-surface-card border border-rose-200 rounded-2xl p-6 sm:p-8 max-w-md w-full shadow-elevated space-y-5">
            <div className="w-12 h-12 rounded-full bg-rose-50 border border-rose-200 flex items-center justify-center text-rose-600">
              <AlertTriangle className="w-6 h-6" />
            </div>

            <div>
              <h3 className="font-display text-2xl text-ink font-light">Permanently Delete Record?</h3>
              <p className="text-xs text-muted mt-2 leading-relaxed">
                You are about to permanently delete the medical chart for <strong className="text-ink">{patient.name} ({patient.mrn})</strong>. This will permanently remove all associated progress notes, prescriptions, and diagnostic lab files from the database.
              </p>
            </div>

            <div className="pt-2 flex flex-col-reverse sm:flex-row sm:items-center sm:justify-end gap-3 border-t border-hairline">
              <button
                type="button"
                onClick={() => setShowDeleteModal(false)}
                disabled={deletingPatient}
                className="px-4 py-2.5 rounded-pill text-xs font-medium text-muted hover:text-ink text-center"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeletePatient}
                disabled={deletingPatient}
                className="px-5 py-2.5 rounded-pill bg-rose-600 hover:bg-rose-700 text-white text-xs font-medium shadow-sm transition-all flex items-center justify-center gap-1.5 text-center"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>{deletingPatient ? "Deleting Record..." : "Confirm Permanent Deletion"}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
