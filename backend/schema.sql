-- ==============================================================================
-- MedCore Health Production Database Schema (MySQL 8.0+)
-- ==============================================================================
-- To execute in MySQL Workbench:
-- 1. Open MySQL Workbench and connect to your local MySQL instance.
-- 2. Open this file (File -> Open SQL Script...) or paste into a query tab.
-- 3. Click the Lightning Bolt (Execute) icon to create and populate the database.
-- ==============================================================================

CREATE DATABASE IF NOT EXISTS medcore_db;
USE medcore_db;

-- 1. Staff & User Accounts
CREATE TABLE IF NOT EXISTS staff_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    role VARCHAR(100) NOT NULL DEFAULT 'Attending Physician',
    department VARCHAR(100) NOT NULL DEFAULT 'General Medicine',
    license_number VARCHAR(100) DEFAULT 'MD-2026-9981',
    avatar_initials VARCHAR(10) DEFAULT 'SC',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Patients (Electronic Health Records)
CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mrn VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(150) NOT NULL,
    email VARCHAR(150) DEFAULT 'patient@medcore.health',
    phone VARCHAR(50) DEFAULT '+1 (555) 234-5678',
    dob DATE NOT NULL,
    gender VARCHAR(20) NOT NULL,
    blood_group VARCHAR(10) NOT NULL,
    insurance_id VARCHAR(50) NOT NULL,
    primary_physician VARCHAR(150) NOT NULL,
    department VARCHAR(100) NOT NULL DEFAULT 'Internal Medicine',
    diagnosis TEXT NOT NULL,
    allergies VARCHAR(255) DEFAULT 'Penicillin, Latex',
    emergency_contact VARCHAR(150) DEFAULT 'Spouse (+1 555-987-6543)',
    address VARCHAR(255) DEFAULT '742 Evergreen Terrace, Springfield, IL',
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Patient Clinical Progress Notes & Encounters
CREATE TABLE IF NOT EXISTS patient_notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_mrn VARCHAR(50) NOT NULL,
    author_name VARCHAR(150) NOT NULL,
    author_role VARCHAR(100) NOT NULL DEFAULT 'Attending Clinician',
    category VARCHAR(50) NOT NULL DEFAULT 'SOAP Progress Note',
    title VARCHAR(200) NOT NULL DEFAULT 'Clinical Encounter Note',
    note_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_mrn) REFERENCES patients(mrn) ON DELETE CASCADE
);

-- 4. Prescriptions & Medication Management
CREATE TABLE IF NOT EXISTS prescriptions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_mrn VARCHAR(50) NOT NULL,
    medication_name VARCHAR(150) NOT NULL,
    dosage VARCHAR(100) NOT NULL,
    frequency VARCHAR(100) NOT NULL,
    duration VARCHAR(100) NOT NULL,
    instructions TEXT NOT NULL,
    prescribed_by VARCHAR(150) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_mrn) REFERENCES patients(mrn) ON DELETE CASCADE
);

-- 5. Appointments & Scheduling
CREATE TABLE IF NOT EXISTS appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_mrn VARCHAR(50) NOT NULL,
    clinician_name VARCHAR(150) NOT NULL,
    department VARCHAR(100) NOT NULL,
    appointment_date DATE NOT NULL,
    appointment_time VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    visit_type VARCHAR(50) NOT NULL DEFAULT 'In-Person Consultation',
    status VARCHAR(50) NOT NULL DEFAULT 'CONFIRMED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_mrn) REFERENCES patients(mrn) ON DELETE CASCADE
);

-- 6. Medical Documents & Diagnostic BLOB File Repository
CREATE TABLE IF NOT EXISTS medical_files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_mrn VARCHAR(50) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL DEFAULT 'application/pdf',
    file_size INT NOT NULL DEFAULT 0,
    file_data LONGBLOB,
    category VARCHAR(100) NOT NULL DEFAULT 'Diagnostic Lab Report',
    description TEXT,
    uploaded_by VARCHAR(150) NOT NULL DEFAULT 'Clinical Staff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_mrn) REFERENCES patients(mrn) ON DELETE CASCADE
);

-- 7. Insurance & Billing Verification Records
CREATE TABLE IF NOT EXISTS insurance_records (
    id INT AUTO_INCREMENT PRIMARY KEY,
    insurance_id VARCHAR(50) NOT NULL UNIQUE,
    patient_mrn VARCHAR(50) NOT NULL,
    policy_holder VARCHAR(150) NOT NULL,
    provider_name VARCHAR(150) NOT NULL DEFAULT 'BlueCross BlueShield',
    coverage_type VARCHAR(100) NOT NULL DEFAULT 'Comprehensive Platinum PPO',
    copay VARCHAR(50) NOT NULL DEFAULT '$25.00',
    deductible VARCHAR(50) NOT NULL DEFAULT '$500.00',
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    valid_until DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_mrn) REFERENCES patients(mrn) ON DELETE CASCADE
);

-- ==============================================================================
-- Initial Seed Data
-- ==============================================================================

-- Staff Users
INSERT INTO staff_users (username, email, password_hash, full_name, role, department, avatar_initials) VALUES
('dr_chen', 's.chen@medcore.health', 'SecretStaff2026!', 'Dr. Sarah Chen, MD', 'Attending Physician', 'Endocrinology & Internal Medicine', 'SC'),
('dr_vance', 'm.vance@medcore.health', 'SecretStaff2026!', 'Dr. Marcus Vance, MD', 'Chief of Cardiology', 'Cardiovascular Medicine', 'MV'),
('dr_watson', 'e.watson@medcore.health', 'SecretStaff2026!', 'Dr. Emily Watson, MD', 'Senior Surgeon', 'Orthopedic Surgery', 'EW'),
('nurse_miller', 'a.miller@medcore.health', 'SecretStaff2026!', 'Nurse Practitioner Miller, NP', 'Head Clinical Nurse', 'Ambulatory Care', 'NM')
ON DUPLICATE KEY UPDATE full_name=VALUES(full_name);

-- Patients
INSERT INTO patients (mrn, name, email, phone, dob, gender, blood_group, insurance_id, primary_physician, department, diagnosis, allergies) VALUES
('MRN-10234', 'Jane Doe', 'jane.doe@example.com', '+1 (555) 234-8910', '1984-05-12', 'Female', 'A+', 'INS-99210', 'Dr. Sarah Chen, MD', 'Endocrinology', 'Type 2 Diabetes Mellitus, Essential Hypertension', 'Penicillin'),
('MRN-10235', 'Robert Miller', 'r.miller@example.com', '+1 (555) 432-1100', '1972-11-23', 'Male', 'O+', 'INS-77412', 'Dr. Marcus Vance, MD', 'Cardiology', 'Coronary Artery Disease, Hyperlipidemia', 'Latex, Sulfa Drugs'),
('MRN-10236', 'Elena Rostova', 'elena.r@example.com', '+1 (555) 876-5432', '1991-03-30', 'Female', 'B+', 'INS-44109', 'Dr. Sarah Chen, MD', 'Pulmonology', 'Moderate Persistent Asthma, Seasonal Allergic Rhinitis', 'Aspirin, NSAIDs'),
('MRN-10237', 'David Kim', 'dkim65@example.com', '+1 (555) 345-6789', '1965-08-19', 'Male', 'AB-', 'INS-88321', 'Dr. Emily Watson, MD', 'Orthopedics', 'Osteoarthritis of Right Knee, Mild Spinal Stenosis', 'None Known')
ON DUPLICATE KEY UPDATE name=VALUES(name);

-- Clinical Notes
INSERT INTO patient_notes (patient_mrn, author_name, author_role, category, title, note_text, created_at) VALUES
('MRN-10234', 'Dr. Sarah Chen, MD', 'Attending Physician', 'Progress Note', 'Routine Diabetic Review', 'Patient reports stable morning fasting blood glucose at 108 mg/dL. Compliant with Metformin 500mg BID and 30-minute daily walking regimen. HbA1c improved to 6.4%. Vital signs normal.', '2026-08-10 09:30:00'),
('MRN-10234', 'Nurse Practitioner Miller, NP', 'Head Nurse', 'Nursing Assessment', 'Blood Pressure Check', 'Follow-up blood pressure reading measured 134/84 mmHg. Recommended continuing low-sodium DASH diet. Recheck scheduled in 3 months.', '2026-08-18 14:15:00'),
('MRN-10235', 'Dr. Marcus Vance, MD', 'Chief of Cardiology', 'Cardiology Consult', 'Post-Stent Follow-Up', 'Patient underwent 6-month coronary angiography evaluation. Resting ECG reveals normal sinus rhythm without ST-T changes. Tolerating Atorvastatin 40mg and Dual Antiplatelet Therapy.', '2026-07-22 11:00:00'),
('MRN-10236', 'Dr. Sarah Chen, MD', 'Attending Physician', 'Pulmonary Consult', 'Asthma Control Review', 'Spirometry demonstrates FEV1/FVC ratio at 82% post-bronchodilator. Refilled Fluticasone/Salmeterol inhaler. Patient reminded on asthma action plan.', '2026-06-04 10:45:00'),
('MRN-10237', 'Dr. Emily Watson, MD', 'Senior Surgeon', 'Surgical Follow-Up', 'Right Knee Joint Assessment', 'Administered ultrasound-guided corticosteroid injection into right knee suprapatellar bursa. Significant reduction in pain and improved range of motion on flexion.', '2026-08-01 13:10:00');

-- Prescriptions
INSERT INTO prescriptions (patient_mrn, medication_name, dosage, frequency, duration, instructions, prescribed_by) VALUES
('MRN-10234', 'Metformin Hydrochloride', '500 mg', 'Twice daily (BID)', '90 Days', 'Take with meals morning and evening to minimize gastrointestinal discomfort.', 'Dr. Sarah Chen, MD'),
('MRN-10234', 'Lisinopril', '10 mg', 'Once daily in the morning', '90 Days', 'Monitor blood pressure weekly and report persistent dry cough.', 'Dr. Sarah Chen, MD'),
('MRN-10235', 'Atorvastatin Calcium', '40 mg', 'Once daily at bedtime', '90 Days', 'Take at night - routine hepatic panel scheduled in 6 months.', 'Dr. Marcus Vance, MD'),
('MRN-10235', 'Clopidogrel (Plavix)', '75 mg', 'Once daily', '180 Days', 'Do not discontinue without cardiologist approval.', 'Dr. Marcus Vance, MD'),
('MRN-10236', 'Advair Diskus (Fluticasone/Salmeterol)', '250/50 mcg', '1 inhalation BID', '60 Days', 'Rinse mouth with water after each inhalation.', 'Dr. Sarah Chen, MD'),
('MRN-10237', 'Meloxicam', '15 mg', 'Once daily with food', '30 Days', 'Use for osteoarthritis flare-ups as needed.', 'Dr. Emily Watson, MD');

-- Appointments
INSERT INTO appointments (patient_mrn, clinician_name, department, appointment_date, appointment_time, reason, visit_type, status) VALUES
('MRN-10234', 'Dr. Sarah Chen, MD', 'Endocrinology', '2026-09-15', '10:00 AM', 'Quarterly diabetic metabolic panel & renal function review', 'In-Person Consultation', 'CONFIRMED'),
('MRN-10235', 'Dr. Marcus Vance, MD', 'Cardiology', '2026-09-18', '02:30 PM', 'Annual stress echocardiogram and lipid profile assessment', 'Specialist Consultation', 'CONFIRMED'),
('MRN-10236', 'Dr. Sarah Chen, MD', 'Pulmonology', '2026-09-22', '11:15 AM', 'Seasonal asthma allergy check and peak flow spirometry', 'Follow-up Encounter', 'CONFIRMED'),
('MRN-10237', 'Dr. Emily Watson, MD', 'Orthopedic Surgery', '2026-09-25', '09:00 AM', 'Right knee post-injection mobility evaluation and X-ray', 'Procedure Follow-up', 'CONFIRMED');

-- Insurance Records
INSERT INTO insurance_records (insurance_id, patient_mrn, policy_holder, provider_name, coverage_type, copay, deductible, valid_until) VALUES
('INS-99210', 'MRN-10234', 'Jane Doe', 'BlueCross BlueShield', 'Comprehensive Platinum PPO', '$25.00', '$500.00', '2027-12-31'),
('INS-77412', 'MRN-10235', 'Robert Miller', 'Aetna Health', 'Executive Premier Choice HMO', '$30.00', '$750.00', '2027-10-31'),
('INS-44109', 'MRN-10236', 'Elena Rostova', 'UnitedHealthcare', 'Standard Preferred POS', '$40.00', '$1,000.00', '2027-08-31'),
('INS-88321', 'MRN-10237', 'David Kim', 'Medicare Senior Care', 'Medicare Advantage Plus Part C', '$15.00', '$250.00', '2028-01-31')
ON DUPLICATE KEY UPDATE coverage_type=VALUES(coverage_type);

-- Initial Mock Files stored as text/BLOB
INSERT INTO medical_files (patient_mrn, filename, original_name, mime_type, file_size, file_data, category, description, uploaded_by) VALUES
('MRN-10234', 'metabolic_panel_2026.pdf', 'Comprehensive_Metabolic_Panel.pdf', 'application/pdf', 1420, 'CONFIDENTIAL MEDICAL RECORD\nPatient: Jane Doe (MRN-10234)\nComprehensive Metabolic Panel Results:\nGlucose: 108 mg/dL (Normal)\nBUN: 14 mg/dL\nCreatinine: 0.9 mg/dL\neGFR: >60 mL/min\nSodium: 140 mEq/L\nPotassium: 4.2 mEq/L', 'Laboratory Diagnostics', 'Complete metabolic profile and renal panel', 'Dr. Sarah Chen, MD'),
('MRN-10235', 'cardiac_echocardiogram_2026.pdf', 'Echocardiogram_Summary_Report.pdf', 'application/pdf', 1890, 'CONFIDENTIAL MEDICAL RECORD\nPatient: Robert Miller (MRN-10235)\nTransthoracic Echocardiogram:\nLeft Ventricular Ejection Fraction (LVEF): 58%\nNo segmental wall motion abnormalities.\nValvular function within normal physiological limits.', 'Cardiology Diagnostics', 'Post-stent 6-month resting echocardiography', 'Dr. Marcus Vance, MD'),
('MRN-10236', 'pulmonary_spirometry_2026.pdf', 'Spirometry_PFT_Report.pdf', 'application/pdf', 1650, 'CONFIDENTIAL MEDICAL RECORD\nPatient: Elena Rostova (MRN-10236)\nPulmonary Function Test (PFT):\nPre-Bronchodilator FEV1: 2.45 L (74% predicted)\nPost-Bronchodilator FEV1: 2.82 L (85% predicted)\nPositive 15% bronchodilator responsiveness.', 'Pulmonology Diagnostics', 'Annual spirometry evaluation for asthma', 'Dr. Sarah Chen, MD'),
('MRN-10237', 'knee_radiograph_xray_2026.pdf', 'Right_Knee_XRay_Radiology.pdf', 'application/pdf', 2150, 'CONFIDENTIAL MEDICAL RECORD\nPatient: David Kim (MRN-10237)\nRight Knee Radiograph (AP & Lateral):\nModerate narrowing of the medial joint compartment.\nMild subchondral sclerosis and marginal osteophytosis.', 'Radiology Imaging', 'Standing weight-bearing right knee radiograph series', 'Dr. Emily Watson, MD')
ON DUPLICATE KEY UPDATE description=VALUES(description);
