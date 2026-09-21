"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { wafFetch } from "@/lib/api";
import {
  ArrowRight,
  ShieldCheck,
  Stethoscope,
  Building2,
  Lock,
  Mail,
  User,
  CheckCircle2,
  Eye,
  EyeOff
} from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [department, setDepartment] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg("");

    if (isRegister) {
      const res = await wafFetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          email,
          password,
          full_name: fullName,
          role: "Attending Physician",
          department
        }),
      });
      setLoading(false);
      if (res.status === 200 || res.status === 201) {
        if (typeof window !== "undefined") {
          try {
            localStorage.setItem("medcore_user", JSON.stringify(res.data));
          } catch {}
        }
        router.push("/dashboard");
      } else {
        setErrorMsg(res.data?.error || "Registration failed. Please check credentials.");
      }
    } else {
      const res = await wafFetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      setLoading(false);
      if (res.status === 200) {
        if (typeof window !== "undefined") {
          try {
            localStorage.setItem("medcore_user", JSON.stringify(res.data));
          } catch {}
        }
        router.push("/dashboard");
      } else {
        setErrorMsg(res.data?.error || res.data?.message || "Invalid clinician credentials.");
      }
    }
  };

  return (
    <div className="relative overflow-hidden py-6 md:py-16">
      {/* Soft Atmospheric Gradient Orbs */}
      <div className="absolute -top-24 left-1/4 w-96 h-96 rounded-full orb-mint pointer-events-none -z-10 blur-3xl opacity-60" />
      <div className="absolute top-1/3 right-10 w-80 h-80 rounded-full orb-peach pointer-events-none -z-10 blur-3xl opacity-50" />
      <div className="absolute -bottom-20 left-10 w-96 h-96 rounded-full orb-lavender pointer-events-none -z-10 blur-3xl opacity-40" />

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-center">
        {/* Left Column: Editorial Brand & Vision */}
        <div className="lg:col-span-7 space-y-8">
          <div className="space-y-4">
            <h1 className="font-display text-4xl sm:text-5xl lg:text-[56px] text-ink font-light leading-[1.08] tracking-tight">
              The clinical operating system for modern medicine.
            </h1>
            <p className="text-body text-base sm:text-lg max-w-xl font-normal leading-relaxed">
              MedCore delivers quiet, editorial clarity to clinical workflows. Seamlessly unifying patient charts, diagnostic documents, prescriptions, and encrypted health records.
            </p>
          </div>

          {/* Value Highlights */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
            <div className="p-4 rounded-xl bg-surface-card border border-hairline shadow-card">
              <span className="font-display text-2xl text-ink font-light block mb-1">01</span>
              <h2 className="text-xs font-semibold text-ink uppercase tracking-wider mb-1">EHR Intelligence</h2>
              <p className="text-xs text-muted leading-relaxed">
                Structured clinical progress notes, vitals tracking, and longitudinal chart history.
              </p>
            </div>
            <div className="p-4 rounded-xl bg-surface-card border border-hairline shadow-card">
              <span className="font-display text-2xl text-ink font-light block mb-1">02</span>
              <h2 className="text-xs font-semibold text-ink uppercase tracking-wider mb-1">Diagnostic Repository</h2>
              <p className="text-xs text-muted leading-relaxed">
                Direct diagnostic document ingestion and streaming for laboratory reports and medical imagery.
              </p>
            </div>
          </div>
        </div>

        {/* Right Column: Authentication Card */}
        <div className="lg:col-span-5">
          <div className="bg-surface-card border border-hairline rounded-2xl p-6 sm:p-8 shadow-elevated relative">
            <div className="mb-6">
              <h2 className="font-display text-2xl text-ink font-light">
                {isRegister ? "Register Clinical Staff" : "Clinician Portal Access"}
              </h2>
              <p className="text-xs text-muted mt-1">
                {isRegister
                  ? "Create a verified clinician profile on the MedCore network."
                  : "Enter your staff credentials to access patient charts and records."}
              </p>
            </div>

            {errorMsg && (
              <div className="mb-5 p-3 rounded-xl bg-rose-50 border border-rose-100 text-rose-700 text-xs">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleAuth} className="space-y-4">
              {isRegister && (
                <>
                  <div>
                    <label className="block text-xs font-medium text-body-strong mb-1.5">
                      Full Name with Credentials
                    </label>
                    <input
                      type="text"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="e.g. Dr. Jane Smith, MD"
                      className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-sm text-ink focus:outline-none focus:border-ink transition-colors"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-body-strong mb-1.5">
                      Clinical Department
                    </label>
                    <input
                      type="text"
                      value={department}
                      onChange={(e) => setDepartment(e.target.value)}
                      placeholder="e.g. Cardiology / Internal Medicine"
                      className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-sm text-ink focus:outline-none focus:border-ink transition-colors"
                      required
                    />
                  </div>
                </>
              )}

              <div>
                <label className="block text-xs font-medium text-body-strong mb-1.5">
                  Staff Username / ID
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter username or staff ID"
                  className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-sm text-ink focus:outline-none focus:border-ink transition-colors"
                  required
                />
              </div>

              {isRegister && (
                <div>
                  <label className="block text-xs font-medium text-body-strong mb-1.5">
                    Official Hospital Email
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="clinician@medcore.health"
                    className="w-full px-3.5 py-2.5 bg-canvas-soft border border-hairline-strong rounded-lg text-sm text-ink focus:outline-none focus:border-ink transition-colors"
                    required
                  />
                </div>
              )}

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-medium text-body-strong">Security Password</label>
                  {!isRegister && (
                    <span className="text-[11px] text-muted hover:text-ink cursor-pointer">
                      Forgot password?
                    </span>
                  )}
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full px-3.5 py-2.5 pr-10 bg-canvas-soft border border-hairline-strong rounded-lg text-sm text-ink focus:outline-none focus:border-ink transition-colors"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-ink focus:outline-none transition-colors"
                    title={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 h-11 px-5 rounded-pill bg-ink-primary hover:bg-ink-primary-active text-white text-[15px] font-medium transition-all shadow-sm flex items-center justify-center gap-2 group"
              >
                {loading ? (
                  <span className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                ) : (
                  <>
                    <span>{isRegister ? "Create Clinician Account" : "Access EHR Dashboard"}</span>
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </>
                )}
              </button>
            </form>

            {/* Sign in / Sign up Mode Switcher */}
            <div className="mt-6 pt-5 border-t border-hairline text-center">
              <button
                type="button"
                onClick={() => {
                  setIsRegister(!isRegister);
                  setErrorMsg("");
                }}
                className="text-xs text-muted hover:text-ink font-medium transition-colors"
              >
                {isRegister ? "Already registered? Sign in" : "New clinician? Create account"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
