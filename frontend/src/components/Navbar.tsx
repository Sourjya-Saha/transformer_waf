"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Users,
  Calendar,
  FileText,
  CreditCard,
  LogOut,
  Menu,
  X
} from "lucide-react";

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeUser, setActiveUser] = React.useState<any>({
    full_name: "Dr. Sarah Chen",
    role: "Attending Physician",
    avatar_initials: "SC",
  });

  React.useEffect(() => {
    if (typeof window !== "undefined") {
      try {
        const stored = localStorage.getItem("medcore_user");
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed.full_name) setActiveUser(parsed);
        }
      } catch {}
    }
  }, [pathname]);

  // Close mobile menu on page change
  React.useEffect(() => {
    setMobileMenuOpen(false);
  }, [pathname]);

  const handleLogout = () => {
    if (typeof window !== "undefined") {
      try {
        localStorage.removeItem("medcore_user");
      } catch {}
    }
    router.push("/");
  };

  // If on login page, render simplified minimal nav
  if (pathname === "/") {
    return (
      <header className="w-full border-b border-hairline bg-canvas/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="font-display text-2xl text-ink tracking-tight">MedCore</span>
      
          </Link>
        </div>
      </header>
    );
  }

  const navLinks = [
    { name: "Patients", href: "/dashboard", icon: Users },
    { name: "Appointments", href: "/dashboard/appointments", icon: Calendar },
    { name: "Documents", href: "/dashboard/documents", icon: FileText },
    { name: "Billing & Insurance", href: "/dashboard/billing", icon: CreditCard },
  ];

  return (
    <header className="w-full border-b border-hairline bg-canvas/90 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-2">
        {/* Brand & Desktop Navigation */}
        <div className="flex items-center gap-4 xl:gap-8 min-w-0">
          <Link href="/dashboard" className="flex items-center gap-2 group shrink-0">
            <span className="font-display text-2xl text-ink tracking-tight group-hover:opacity-80 transition-opacity">
              MedCore
            </span>
          </Link>

          {/* Desktop Nav Menu (Shown on lg and wider) */}
          <nav className="hidden lg:flex items-center gap-1 xl:gap-1.5">
            {navLinks.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-pill text-[13px] font-medium whitespace-nowrap transition-all ${
                    isActive
                      ? "bg-surface-card text-ink border border-hairline shadow-sm"
                      : "text-muted hover:text-ink hover:bg-surface-strong"
                  }`}
                >
                  <Icon className="w-3.5 h-3.5 opacity-70" />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right Section: Clinician Badge, Logout, & Mobile Toggle */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          {/* Clinician Pill - Protected against vertical and horizontal overflow */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-pill bg-surface-card border border-hairline shadow-sm max-w-[160px] md:max-w-[200px] xl:max-w-[260px]">
            <div className="w-6 h-6 rounded-full bg-gradient-mint flex items-center justify-center text-[10px] font-bold text-ink shrink-0">
              {activeUser.avatar_initials || "MD"}
            </div>
            <div className="text-left min-w-0 flex-1 overflow-hidden">
              <span className="text-xs font-medium text-ink block truncate leading-tight">
                {activeUser.full_name || "Dr. Sarah Chen"}
              </span>
              <span className="text-[10px] text-muted truncate hidden md:block leading-tight">
                {activeUser.role || "Attending Physician"}
              </span>
            </div>
          </div>

          {/* Desktop Logout Button */}
          <button
            onClick={handleLogout}
            title="Sign Out of Session"
            className="hidden sm:flex items-center justify-center w-8 h-8 rounded-full hover:bg-surface-strong text-muted hover:text-ink transition-colors border border-transparent hover:border-hairline shrink-0"
          >
            <LogOut className="w-4 h-4" />
          </button>

          {/* Hamburger Menu Toggle for Mobile & Tablet (< lg) */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="lg:hidden flex items-center justify-center w-9 h-9 rounded-lg text-body hover:text-ink hover:bg-surface-strong transition-colors border border-hairline shrink-0"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile / Tablet Drawer (< lg) */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-t border-hairline bg-surface-card/95 backdrop-blur-md px-4 py-4 space-y-3 animate-in slide-in-from-top duration-200 shadow-xl">
          {/* Mobile Profile Card */}
          <div className="flex items-center gap-3 p-3 rounded-xl bg-canvas-soft border border-hairline">
            <div className="w-9 h-9 rounded-full bg-gradient-mint flex items-center justify-center text-xs font-bold text-ink shrink-0">
              {activeUser.avatar_initials || "MD"}
            </div>
            <div className="min-w-0 flex-1">
              <span className="text-xs font-semibold text-ink block truncate">
                {activeUser.full_name || "Dr. Sarah Chen, MD"}
              </span>
              <span className="text-[11px] text-muted block truncate">
                {activeUser.role || "Attending Physician"}
              </span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1">
            {navLinks.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                    isActive
                      ? "bg-ink-primary text-white shadow-sm"
                      : "text-muted hover:text-ink hover:bg-surface-strong"
                  }`}
                >
                  <Icon className="w-4 h-4 opacity-80" />
                  <span>{item.name}</span>
                </Link>
              );
            })}
          </nav>

          {/* Mobile Sign Out Button */}
          <div className="pt-2 border-t border-hairline">
            <button
              onClick={handleLogout}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-xs font-medium text-rose-700 bg-rose-50 hover:bg-rose-100 border border-rose-200 transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Sign Out of Session</span>
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
