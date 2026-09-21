"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { wafFetch } from "@/lib/api";
import {
  Calendar,
  Clock,
  User,
  Plus,
  Building2,
  CheckCircle2,
  X,
  Stethoscope,
  ArrowUpRight
} from "lucide-react";

export default function AppointmentsPage() {
  const [appointments, setAppointments] = useState<any[]>([]);
  const [patients, setPatients] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);

  // Form State
  const [mrn, setMrn] = useState("");
  const [clinician, setClinician] = useState("Dr. Sarah Chen, MD");
  const [department, setDepartment] = useState("Internal Medicine");
  const [date, setDate] = useState("");
  const [time, setTime] = useState("09:00 AM");
  const [reason, setReason] = useState("");
  const [visitType, setVisitType] = useState("In-Person Consultation");
  const [submitting, setSubmitting] = useState(false);

  const fetchAppointments = async () => {
    setLoading(true);
    const res = await wafFetch("/api/appointments");
    setLoading(false);
    if (res.status === 200 && res.data?.appointments) {
      setAppointments(res.data.appointments);
    }
  };

  const fetchPatients = async () => {
    const res = await wafFetch("/api/patients");
    if (res.status === 200 && res.data?.patients) {
      setPatients(res.data.patients);
    }
  };

  useEffect(() => {
    fetchAppointments();
    fetchPatients();
  }, []);

  const handleBook = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    const formData = new URLSearchParams();
    formData.append("patient_mrn", mrn);
    formData.append("clinician_name", clinician);
    formData.append("department", department);
    formData.append("date", date);
    formData.append("time", time);
    formData.append("reason", reason);
    formData.append("visit_type", visitType);

    const res = await wafFetch("/api/appointments", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData.toString(),
    });

    setSubmitting(false);

    if (res.status === 200 || res.status === 201) {
      setShowModal(false);
      fetchAppointments();
    } else {
      alert("Failed to book appointment: " + (res.data?.error || "Error"));
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
              Scheduling & Encounters
            </span>
          </div>
          <h1 className="font-display text-3xl sm:text-4xl text-ink font-light tracking-tight">
            Clinical Appointments
          </h1>
          <p className="text-sm text-body mt-1">
            Outpatient scheduling, specialist consultations, and surgical procedure management.
          </p>
        </div>

        <button
          onClick={() => setShowModal(true)}
          className="h-10 px-5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-xs font-medium transition-all shadow-sm flex items-center gap-2 self-start md:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Schedule New Encounter</span>
        </button>
      </div>

      {/* Appointments List */}
      <div className="bg-surface-card border border-hairline rounded-2xl p-6 shadow-card space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-xl text-ink font-light">Upcoming Consultations</h2>
          <span className="text-xs font-mono text-muted">{appointments.length} Total Bookings</span>
        </div>

        <div className="overflow-x-auto -mx-4 sm:mx-0 px-4 sm:px-0">
          <table className="w-full text-left text-xs min-w-[650px]">
            <thead>
              <tr className="border-b border-hairline text-muted font-medium">
                <th className="pb-3 pl-3">DATE & TIME</th>
                <th className="pb-3">PATIENT</th>
                <th className="pb-3">CLINICIAN & DEPT</th>
                <th className="pb-3">REASON / ENCOUNTER TYPE</th>
                <th className="pb-3">STATUS</th>
                <th className="pb-3 text-right pr-3">CHART</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    Loading scheduled appointments...
                  </td>
                </tr>
              ) : appointments.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted">
                    No scheduled clinical appointments found.
                  </td>
                </tr>
              ) : (
                appointments.map((a) => (
                  <tr key={a.id} className="hover:bg-canvas-soft/80 transition-colors">
                    <td className="py-4 pl-3">
                      <div className="font-medium text-ink flex items-center gap-1.5">
                        <Calendar className="w-3.5 h-3.5 text-muted" />
                        <span>{a.appointment_date}</span>
                      </div>
                      <span className="text-[11px] text-muted font-mono block pl-5">{a.appointment_time}</span>
                    </td>
                    <td className="py-4 font-medium text-ink">
                      <div>{a.patient_name || a.patient_mrn}</div>
                      <span className="text-[11px] text-muted font-mono">{a.patient_mrn}</span>
                    </td>
                    <td className="py-4 text-body">
                      <div className="font-medium text-ink">{a.clinician_name}</div>
                      <span className="text-[11px] text-muted">{a.department}</span>
                    </td>
                    <td className="py-4 text-body max-w-xs">
                      <div>{a.reason}</div>
                      <span className="text-[11px] text-muted-soft">{a.visit_type}</span>
                    </td>
                    <td className="py-4">
                      <span className="px-2.5 py-0.5 rounded-pill bg-emerald-50 text-emerald-800 border border-emerald-200 text-[10px] font-medium">
                        {a.status || "CONFIRMED"}
                      </span>
                    </td>
                    <td className="py-4 text-right pr-3">
                      <Link
                        href={`/dashboard/patient/${a.patient_mrn}`}
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

      {/* Booking Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
          <div className="bg-surface-card border border-hairline rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-elevated relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6 pb-4 border-b border-hairline">
              <div>
                <h3 className="font-display text-xl text-ink font-light">Schedule Clinical Encounter</h3>
                <p className="text-xs text-muted">Book and record consultation in patient schedule</p>
              </div>
              <button
                onClick={() => setShowModal(false)}
                className="p-1 rounded-full hover:bg-surface-strong text-muted hover:text-ink transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleBook} className="space-y-4 text-xs">
              <div>
                <label className="block font-medium text-body-strong mb-1">Select Patient</label>
                <select
                  value={mrn}
                  onChange={(e) => {
                    const selectedMrn = e.target.value;
                    setMrn(selectedMrn);
                    const sel = patients.find((p) => p.mrn === selectedMrn);
                    if (sel) {
                      if (sel.primary_physician) setClinician(sel.primary_physician);
                      if (sel.department) setDepartment(sel.department);
                    }
                  }}
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink font-medium"
                  required
                >
                  <option value="" disabled>-- Select a Patient from Registry --</option>
                  {patients.map((p) => (
                    <option key={p.mrn} value={p.mrn}>
                      {p.name} ({p.mrn}) {p.diagnosis ? `— ${p.diagnosis}` : ""}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Attending Clinician</label>
                  <select
                    value={clinician}
                    onChange={(e) => setClinician(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Dr. Sarah Chen, MD">Dr. Sarah Chen, MD</option>
                    <option value="Dr. Marcus Vance, MD">Dr. Marcus Vance, MD</option>
                    <option value="Dr. Emily Watson, MD">Dr. Emily Watson, MD</option>
                    <option value="Nurse Practitioner Miller, NP">Nurse Practitioner Miller</option>
                  </select>
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Department</label>
                  <select
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="Internal Medicine">Internal Medicine</option>
                    <option value="Cardiology">Cardiology</option>
                    <option value="Pulmonology">Pulmonology</option>
                    <option value="Orthopedic Surgery">Orthopedic Surgery</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-body-strong mb-1">Encounter Date</label>
                  <input
                    type="date"
                    value={date}
                    onChange={(e) => setDate(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                    required
                  />
                </div>
                <div>
                  <label className="block font-medium text-body-strong mb-1">Time Slot</label>
                  <select
                    value={time}
                    onChange={(e) => setTime(e.target.value)}
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  >
                    <option value="09:00 AM">09:00 AM</option>
                    <option value="10:00 AM">10:00 AM</option>
                    <option value="11:15 AM">11:15 AM</option>
                    <option value="02:30 PM">02:30 PM</option>
                    <option value="04:00 PM">04:00 PM</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium text-body-strong mb-1">Reason for Visit</label>
                <textarea
                  rows={3}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="e.g. Routine diabetic review, blood pressure assessment, or follow-up consult..."
                  className="w-full p-3 bg-canvas-soft border border-hairline-strong rounded-lg text-ink focus:outline-none focus:border-ink"
                  required
                />
              </div>

              <div className="pt-4 flex flex-col-reverse sm:flex-row sm:items-center sm:justify-end gap-3 border-t border-hairline">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2.5 rounded-pill text-muted hover:text-ink text-center"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2.5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white font-medium shadow-sm transition-all text-center"
                >
                  {submitting ? "Booking Encounter..." : "Confirm & Book Encounter"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
