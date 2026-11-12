"""MySQL Database Connection & Query Manager for MedCore Health Backend.

Provides connection pooling and executes queries against the MySQL medcore_db database.
Supports Patient Records, Staff Auth, Progress Notes, Prescriptions, Appointments,
and Binary BLOB Document Management.
"""
import os
import pymysql
import pymysql.cursors
from typing import Dict, Any, List, Optional, Tuple
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "sourjya@1614")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "medcore_db")


def get_db_connection():
    """Establishes connection to MySQL database."""
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        connect_timeout=3
    )


def ensure_schema():
    """Ensures all necessary columns and tables exist in MySQL without manual steps."""
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # 1. Migrate staff_users columns
                staff_cols = [
                    ("email", "VARCHAR(150) NULL DEFAULT 'staff@medcore.health'"),
                    ("department", "VARCHAR(100) NOT NULL DEFAULT 'General Medicine'"),
                    ("license_number", "VARCHAR(100) DEFAULT 'MD-2026-9981'"),
                    ("avatar_initials", "VARCHAR(10) DEFAULT 'MD'")
                ]
                for col, spec in staff_cols:
                    try:
                        cursor.execute(f"ALTER TABLE staff_users ADD COLUMN {col} {spec}")
                    except Exception:
                        pass

                # Update initial staff details if needed
                try:
                    cursor.execute("UPDATE staff_users SET email='s.chen@medcore.health', department='Endocrinology & Internal Medicine', avatar_initials='SC' WHERE username='dr_chen'")
                    cursor.execute("UPDATE staff_users SET email='m.vance@medcore.health', department='Cardiovascular Medicine', avatar_initials='MV' WHERE username='dr_vance'")
                    cursor.execute("UPDATE staff_users SET email='e.watson@medcore.health', department='Orthopedic Surgery', avatar_initials='EW' WHERE username='dr_watson'")
                    cursor.execute("UPDATE staff_users SET email='a.miller@medcore.health', department='Ambulatory Care', avatar_initials='NM' WHERE username='nurse_miller'")
                except Exception:
                    pass

                # 2. Migrate patients columns
                patient_cols = [
                    ("email", "VARCHAR(150) DEFAULT 'patient@medcore.health'"),
                    ("phone", "VARCHAR(50) DEFAULT '+1 (555) 234-5678'"),
                    ("department", "VARCHAR(100) NOT NULL DEFAULT 'Internal Medicine'"),
                    ("allergies", "VARCHAR(255) DEFAULT 'Penicillin, Latex'"),
                    ("emergency_contact", "VARCHAR(150) DEFAULT 'Spouse (+1 555-987-6543)'"),
                    ("address", "VARCHAR(255) DEFAULT '742 Evergreen Terrace, Springfield, IL'"),
                    ("status", "VARCHAR(50) NOT NULL DEFAULT 'ACTIVE'")
                ]
                for col, spec in patient_cols:
                    try:
                        cursor.execute(f"ALTER TABLE patients ADD COLUMN {col} {spec}")
                    except Exception:
                        pass

                # Make insurance_id nullable
                try:
                    cursor.execute("ALTER TABLE patients MODIFY COLUMN insurance_id VARCHAR(100) NULL")
                except Exception:
                    pass

                # 3. Ensure supplementary tables exist
                cursor.execute("""
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
                    )
                """)

                cursor.execute("""
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
                    )
                """)

                cursor.execute("""
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
                    )
                """)

                cursor.execute("""
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
                    )
                """)

                cursor.execute("""
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
                    )
                """)
        finally:
            conn.close()
    except Exception as e:
        print(f"[DB WARN] Database schema auto-migration skipped: {e}")


# Run schema check on startup
ensure_schema()


class DatabaseManager:
    """Manages all clinical queries, persistence, and transactions with MySQL."""

    # ==========================================================================
    # 1. Staff Users & Authentication
    # ==========================================================================
    @staticmethod
    def authenticate_staff(username_or_email: str, password: str = "") -> Optional[Dict[str, Any]]:
        if not username_or_email or not password:
            return None
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, username, email, password_hash, full_name, role, department, license_number, avatar_initials FROM staff_users WHERE username = %s OR email = %s",
                    (username_or_email, username_or_email)
                )
                user = cursor.fetchone()
                if user and user.get("password_hash") == password:
                    return {
                        "status": "authenticated",
                        "user": user["username"],
                        "email": user["email"],
                        "full_name": user["full_name"],
                        "role": user["role"],
                        "department": user["department"],
                        "license_number": user.get("license_number", "MD-2026"),
                        "avatar_initials": user.get("avatar_initials", "MD"),
                        "token": f"medcore-jwt-{user['username']}-session"
                    }
                return None
        finally:
            conn.close()

    @staticmethod
    def register_staff(username: str, email: str, password: str, full_name: str, role: str, department: str) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Check for existing user
                cursor.execute("SELECT id FROM staff_users WHERE username = %s OR email = %s", (username, email))
                existing = cursor.fetchone()
                if existing:
                    return {"error": "Username or email is already registered", "status": "conflict"}

                initials = "".join([part[0].upper() for part in full_name.split()[:2]]) or "MD"
                cursor.execute(
                    "INSERT INTO staff_users (username, email, password_hash, full_name, role, department, avatar_initials) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (username, email, password, full_name, role, department, initials)
                )
                return {
                    "status": "created",
                    "id": cursor.lastrowid,
                    "username": username,
                    "email": email,
                    "full_name": full_name,
                    "role": role,
                    "department": department,
                    "avatar_initials": initials,
                    "token": f"medcore-jwt-{username}-session"
                }
        finally:
            conn.close()

    @staticmethod
    def get_all_staff() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, username, email, full_name, role, department, license_number, avatar_initials FROM staff_users ORDER BY id ASC")
                return cursor.fetchall()
        finally:
            conn.close()

    # ==========================================================================
    # 2. Patients & EHR Records
    # ==========================================================================
    @staticmethod
    def get_all_patients(query: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                if query:
                    sql = "SELECT * FROM patients WHERE name LIKE %s OR mrn LIKE %s OR diagnosis LIKE %s OR primary_physician LIKE %s"
                    pattern = f"%{query}%"
                    cursor.execute(sql, (pattern, pattern, pattern, pattern))
                else:
                    cursor.execute("SELECT * FROM patients ORDER BY id ASC")
                rows = cursor.fetchall()
                for r in rows:
                    if hasattr(r.get("dob"), "strftime"):
                        r["dob"] = r["dob"].strftime("%Y-%m-%d")
                    if hasattr(r.get("created_at"), "strftime"):
                        r["created_at"] = r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                return rows
        finally:
            conn.close()

    @staticmethod
    def get_patient_by_mrn(mrn: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM patients WHERE mrn = %s", (mrn,))
                patient = cursor.fetchone()
                if not patient:
                    return None

                if hasattr(patient.get("dob"), "strftime"):
                    patient["dob"] = patient["dob"].strftime("%Y-%m-%d")
                if hasattr(patient.get("created_at"), "strftime"):
                    patient["created_at"] = patient["created_at"].strftime("%Y-%m-%d %H:%M:%S")

                # Fetch notes
                cursor.execute(
                    "SELECT id, author_name AS author, author_role, category, title, note_text AS text, created_at FROM patient_notes WHERE patient_mrn = %s ORDER BY id DESC",
                    (mrn,)
                )
                notes = cursor.fetchall()
                for n in notes:
                    if hasattr(n.get("created_at"), "strftime"):
                        n["created_at"] = n["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                patient["notes"] = notes

                # Fetch prescriptions
                cursor.execute(
                    "SELECT id, medication_name, dosage, frequency, duration, instructions, prescribed_by, status, created_at FROM prescriptions WHERE patient_mrn = %s ORDER BY id DESC",
                    (mrn,)
                )
                prescriptions = cursor.fetchall()
                for p in prescriptions:
                    if hasattr(p.get("created_at"), "strftime"):
                        p["created_at"] = p["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                patient["prescriptions"] = prescriptions

                # Fetch documents
                cursor.execute(
                    "SELECT id, filename, original_name, mime_type, file_size, category, description, uploaded_by, created_at FROM medical_files WHERE patient_mrn = %s ORDER BY id DESC",
                    (mrn,)
                )
                docs = cursor.fetchall()
                for d in docs:
                    if hasattr(d.get("created_at"), "strftime"):
                        d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                patient["documents"] = docs
                patient["lab_reports"] = [d["filename"] for d in docs]

                # Fetch appointments
                cursor.execute(
                    "SELECT id, clinician_name, department, appointment_date, appointment_time, reason, visit_type, status, created_at FROM appointments WHERE patient_mrn = %s ORDER BY id DESC",
                    (mrn,)
                )
                appts = cursor.fetchall()
                for a in appts:
                    if hasattr(a.get("appointment_date"), "strftime"):
                        a["appointment_date"] = a["appointment_date"].strftime("%Y-%m-%d")
                    if hasattr(a.get("created_at"), "strftime"):
                        a["created_at"] = a["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                patient["appointments"] = appts

                return patient
        finally:
            conn.close()

    @staticmethod
    def create_patient(data: Dict[str, Any]) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Generate new MRN if not provided
                mrn = data.get("mrn")
                if not mrn:
                    cursor.execute("SELECT MAX(id) as max_id FROM patients")
                    row = cursor.fetchone()
                    next_num = (row["max_id"] or 10237) + 1
                    mrn = f"MRN-{next_num}"

                cursor.execute(
                    """INSERT INTO patients (mrn, name, email, phone, dob, gender, blood_group, insurance_id, primary_physician, department, diagnosis, allergies, emergency_contact, address)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        mrn,
                        data.get("name", "New Patient"),
                        data.get("email", "patient@medcore.health"),
                        data.get("phone", "+1 (555) 000-0000"),
                        data.get("dob", "1990-01-01"),
                        data.get("gender", "Other"),
                        data.get("blood_group", "O+"),
                        data.get("insurance_id") if (data.get("insurance_id") and data.get("insurance_id").strip() and data.get("insurance_id") != "Self-Pay") else None,
                        data.get("primary_physician", "Dr. Sarah Chen, MD"),
                        data.get("department", "Internal Medicine"),
                        data.get("diagnosis", "Observation and health maintenance"),
                        data.get("allergies", "No known drug allergies (NKDA)"),
                        data.get("emergency_contact", "Family"),
                        data.get("address", "Springfield, IL")
                    )
                )
                return {"status": "created", "mrn": mrn, "id": cursor.lastrowid}
        finally:
            conn.close()

    @staticmethod
    def update_patient(mrn: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM patients WHERE mrn = %s", (mrn,))
                existing = cursor.fetchone()
                if not existing:
                    return None

                allowed_cols = [
                    "name", "email", "phone", "dob", "gender", "blood_group",
                    "insurance_id", "primary_physician", "department", "diagnosis",
                    "allergies", "emergency_contact", "address", "status"
                ]
                fields = []
                values = []
                for col in allowed_cols:
                    if col in data and data[col] is not None:
                        fields.append(f"{col} = %s")
                        values.append(data[col])

                if fields:
                    values.append(mrn)
                    sql = f"UPDATE patients SET {', '.join(fields)} WHERE mrn = %s"
                    cursor.execute(sql, tuple(values))

            return DatabaseManager.get_patient_by_mrn(mrn)
        finally:
            conn.close()

    @staticmethod
    def delete_patient(mrn: str) -> bool:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM patients WHERE mrn = %s", (mrn,))
                return cursor.rowcount > 0
        finally:
            conn.close()

    # ==========================================================================
    # 3. Clinical Progress Notes
    # ==========================================================================
    @staticmethod
    def add_patient_note(mrn: str, author_name: str, note_text: str, category: str = "Progress Note", title: str = "Clinical Encounter Note") -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO patient_notes (patient_mrn, author_name, category, title, note_text) VALUES (%s, %s, %s, %s, %s)",
                    (mrn, author_name, category, title, note_text)
                )
                note_id = cursor.lastrowid
                return {
                    "id": note_id,
                    "patient_mrn": mrn,
                    "author": author_name,
                    "category": category,
                    "title": title,
                    "text": note_text
                }
        finally:
            conn.close()

    # ==========================================================================
    # 4. Prescriptions
    # ==========================================================================
    @staticmethod
    def add_prescription(mrn: str, medication_name: str, dosage: str, frequency: str, duration: str, instructions: str, prescribed_by: str) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO prescriptions (patient_mrn, medication_name, dosage, frequency, duration, instructions, prescribed_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (mrn, medication_name, dosage, frequency, duration, instructions, prescribed_by)
                )
                return {
                    "id": cursor.lastrowid,
                    "patient_mrn": mrn,
                    "medication_name": medication_name,
                    "dosage": dosage,
                    "frequency": frequency,
                    "duration": duration,
                    "instructions": instructions,
                    "prescribed_by": prescribed_by
                }
        finally:
            conn.close()

    # ==========================================================================
    # 5. Medical BLOB File Repository (Upload & Download)
    # ==========================================================================
    @staticmethod
    def save_medical_file(
        patient_mrn: str,
        filename: str,
        original_name: str,
        mime_type: str,
        file_size: int,
        file_bytes: bytes,
        category: str = "Diagnostic Lab Report",
        description: str = "",
        uploaded_by: str = "Clinical Staff"
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO medical_files (patient_mrn, filename, original_name, mime_type, file_size, file_data, category, description, uploaded_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (patient_mrn, filename, original_name, mime_type, file_size, file_bytes, category, description, uploaded_by)
                )
                return {
                    "id": cursor.lastrowid,
                    "patient_mrn": patient_mrn,
                    "filename": filename,
                    "original_name": original_name,
                    "mime_type": mime_type,
                    "file_size": file_size,
                    "category": category,
                    "uploaded_by": uploaded_by
                }
        finally:
            conn.close()

    @staticmethod
    def get_file_by_id(file_id: int) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM medical_files WHERE id = %s", (file_id,))
                return cursor.fetchone()
        finally:
            conn.close()

    @staticmethod
    def get_document_content(filename: str) -> str:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT file_data FROM medical_files WHERE filename = %s OR original_name = %s LIMIT 1", (filename, filename))
                row = cursor.fetchone()
                if row and row["file_data"]:
                    data = row["file_data"]
                    if isinstance(data, bytes):
                        return data.decode("utf-8", errors="replace")
                    return str(data)
                return f"Medical Document Record: {filename}\nStatus: Retrieved from Clinical Lab Archive"
        finally:
            conn.close()

    # ==========================================================================
    # 6. Appointments & Scheduling
    # ==========================================================================
    @staticmethod
    def get_all_appointments() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """SELECT a.id, a.patient_mrn, p.name as patient_name, a.clinician_name, a.department,
                              a.appointment_date, a.appointment_time, a.reason, a.visit_type, a.status, a.created_at
                       FROM appointments a
                       LEFT JOIN patients p ON a.patient_mrn = p.mrn
                       ORDER BY a.appointment_date ASC, a.appointment_time ASC"""
                )
                rows = cursor.fetchall()
                for r in rows:
                    if hasattr(r.get("appointment_date"), "strftime"):
                        r["appointment_date"] = r["appointment_date"].strftime("%Y-%m-%d")
                    if hasattr(r.get("created_at"), "strftime"):
                        r["created_at"] = r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
                return rows
        finally:
            conn.close()

    @staticmethod
    def create_appointment(mrn: str, clinician_name: str, department: str, date_str: str, time_str: str, reason: str, visit_type: str = "In-Person Consultation") -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO appointments (patient_mrn, clinician_name, department, appointment_date, appointment_time, reason, visit_type)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (mrn, clinician_name, department, date_str, time_str, reason, visit_type)
                )
                return {
                    "id": cursor.lastrowid,
                    "patient_mrn": mrn,
                    "clinician_name": clinician_name,
                    "department": department,
                    "appointment_date": date_str,
                    "appointment_time": time_str,
                    "reason": reason,
                    "visit_type": visit_type,
                    "status": "CONFIRMED"
                }
        finally:
            conn.close()

    # ==========================================================================
    # 7. Insurance & Billing
    # ==========================================================================
    @staticmethod
    def get_all_insurance_records() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """SELECT i.*, p.name as patient_name
                       FROM insurance_records i
                       LEFT JOIN patients p ON i.patient_mrn = p.mrn
                       ORDER BY i.id ASC"""
                )
                rows = cursor.fetchall()
                for r in rows:
                    if hasattr(r.get("valid_until"), "strftime"):
                        r["valid_until"] = r["valid_until"].strftime("%Y-%m-%d")
                return rows
        finally:
            conn.close()

    @staticmethod
    def create_insurance_record(
        insurance_id: str,
        patient_mrn: str,
        policy_holder: str,
        provider_name: str = "BlueCross BlueShield",
        coverage_type: str = "Comprehensive Platinum PPO",
        copay: str = "$25.00",
        deductible: str = "$500.00",
        valid_until: str = "2027-12-31"
    ) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # If insurance_id not provided, auto-generate e.g. INS-XXXXX
                if not insurance_id:
                    cursor.execute("SELECT MAX(id) as max_id FROM insurance_records")
                    row = cursor.fetchone()
                    next_id = (row["max_id"] or 100) + 1
                    insurance_id = f"INS-{next_id}09"

                cursor.execute(
                    """INSERT INTO insurance_records (insurance_id, patient_mrn, policy_holder, provider_name, coverage_type, copay, deductible, valid_until)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                       ON DUPLICATE KEY UPDATE provider_name=VALUES(provider_name), coverage_type=VALUES(coverage_type), copay=VALUES(copay), deductible=VALUES(deductible), valid_until=VALUES(valid_until)""",
                    (insurance_id, patient_mrn, policy_holder, provider_name, coverage_type, copay, deductible, valid_until)
                )

                # Also update patient's insurance_id on patients table
                try:
                    cursor.execute("UPDATE patients SET insurance_id = %s WHERE mrn = %s", (insurance_id, patient_mrn))
                except Exception:
                    pass

                return {
                    "id": cursor.lastrowid,
                    "insurance_id": insurance_id,
                    "patient_mrn": patient_mrn,
                    "policy_holder": policy_holder,
                    "provider_name": provider_name,
                    "coverage_type": coverage_type,
                    "copay": copay,
                    "deductible": deductible,
                    "valid_until": valid_until,
                    "status": "ACTIVE"
                }
        finally:
            conn.close()

    @staticmethod
    def lookup_insurance(insurance_id: str) -> Dict[str, Any]:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """SELECT i.*, p.name as patient_name
                       FROM insurance_records i
                       LEFT JOIN patients p ON i.patient_mrn = p.mrn
                       WHERE i.insurance_id = %s""",
                    (insurance_id,)
                )
                row = cursor.fetchone()
                if row:
                    if hasattr(row.get("valid_until"), "strftime"):
                        row["valid_until"] = row["valid_until"].strftime("%Y-%m-%d")
                    return {
                        "status": "verified",
                        "insurance_id": row["insurance_id"],
                        "patient_mrn": row["patient_mrn"],
                        "patient_name": row.get("patient_name", row["policy_holder"]),
                        "policy_holder": row["policy_holder"],
                        "provider_name": row["provider_name"],
                        "coverage": row["coverage_type"],
                        "copay": row["copay"],
                        "deductible": row["deductible"],
                        "valid_until": row["valid_until"]
                    }
                return None
        finally:
            conn.close()

    # ==========================================================================
    # 8. Dashboard Live Metrics & System Aggregates
    # ==========================================================================
    @staticmethod
    def get_dashboard_stats() -> Dict[str, Any]:
        """Calculates live metrics directly from MySQL tables with resilient fallbacks."""
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                def safe_count(table: str) -> int:
                    try:
                        cursor.execute(f"SELECT COUNT(*) AS count FROM {table}")
                        row = cursor.fetchone()
                        return int(row["count"]) if row and "count" in row else 0
                    except Exception:
                        return 0

                patient_count = safe_count("patients")
                appointment_count = safe_count("appointments")
                document_count = safe_count("medical_files")
                note_count = safe_count("patient_notes")
                prescription_count = safe_count("prescriptions")

                return {
                    "active_patients": patient_count,
                    "scheduled_encounters": appointment_count,
                    "diagnostic_reports": document_count,
                    "clinical_notes": note_count,
                    "active_prescriptions": prescription_count,
                    "system_status": "Optimal"
                }
        finally:
            conn.close()
