import type { Metadata } from "next";
import "./globals.css";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "MedCore Health — Clinical Information & Records System",
  description: "Editorial-grade Electronic Health Records (EHR) & Clinical Operating System.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-canvas text-ink min-h-screen flex flex-col antialiased selection:bg-gradient-peach selection:text-ink">
        <Navbar />
        <main className="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-10 relative">
          {children}
        </main>
        <footer className="w-full border-t border-hairline py-6 bg-canvas text-center text-xs text-muted">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-2 sm:gap-0">
            <span className="font-display text-base text-ink font-light">MedCore</span>
            <span className="text-muted-soft text-[11px]">All clinical rights reserved &bull; HIPAA Compliant EHR</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
