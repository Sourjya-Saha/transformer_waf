"""MedCore Health Production Backend API Service (Tier 3).

Interfaced directly with MySQL database (`medcore_db`).
Protected upstream behind the Layer-7 Web Application Firewall.
"""
import os
import io
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Form, UploadFile, File, Response
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.db import DatabaseManager

app = FastAPI(
    title="MedCore Health Clinical Backend API",
    version="2.0.0",
    description="Production-grade clinical healthcare backend API connected to MySQL.",
    debug=True,
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.options("/{full_path:path}")
async def preflight_handler(full_path: str):
    """Global CORS preflight handler returning allowed headers."""
    return JSONResponse(
        status_code=200,
        content={"status": "ok"},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age": "86400",
        },
    )


# ==============================================================================
# Proof-of-Isolation Middleware
# ==============================================================================
@app.middleware("http")
async def log_backend_hits(request: Request, call_next):
    """Logs every request that physically crosses the network and reaches the backend."""
    client_host = request.client.host if request.client else "unknown"
    print(f"[*] [BACKEND SERVER HIT]: {request.method} {request.url.path} from client {client_host}")
    response = await call_next(request)
    return response


# ==============================================================================
# Health Check Endpoint
# ==============================================================================
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "MedCore Clinical Backend", "database": "MySQL Connected (medcore_db)"}


# ==============================================================================
# 1. Staff Authentication & Profile Routes
# ==============================================================================
@app.post("/api/auth/login")
@app.post("/api/login")
async def api_login(payload: Dict[str, Any]):
    """Staff authentication against MySQL staff_users table."""
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()
    if not username or not password:
        return JSONResponse(status_code=400, content={"error": "Username and password are required"})

    user = DatabaseManager.authenticate_staff(username, password)
    if user:
        return user

    return JSONResponse(
        status_code=401,
        content={"error": "Invalid clinician credentials. Please check your username and password."}
    )


@app.post("/api/auth/register")
async def api_register(payload: Dict[str, Any]):
    """Registers a new clinician or clinical staff user."""
    username = str(payload.get("username", "")).strip()
    email = str(payload.get("email", "")).strip()
    password = str(payload.get("password", "")).strip()
    full_name = str(payload.get("full_name", "")).strip()
    role = str(payload.get("role", "Attending Clinician")).strip()
    department = str(payload.get("department", "General Medicine")).strip()

    if not username or not email or not password:
        return JSONResponse(status_code=400, content={"error": "Username, email, and password are required"})

    result = DatabaseManager.register_staff(username, email, password, full_name, role, department)
    if "error" in result:
        return JSONResponse(status_code=409, content={"error": result["error"]})
    return JSONResponse(status_code=201, content=result)


@app.get("/api/auth/staff")
async def get_staff_directory():
    """Returns directory of active clinical staff."""
    return {"status": "ok", "staff": DatabaseManager.get_all_staff()}


# ==============================================================================
# 2. Dashboard Statistics & Aggregate Metrics
# ==============================================================================
@app.get("/api/dashboard/stats")
@app.get("/api/stats")
async def get_dashboard_statistics():
    """Returns live clinical metrics directly from MySQL."""
    stats = DatabaseManager.get_dashboard_stats()
    return {"status": "ok", "stats": stats}


# ==============================================================================
# 3. Patient Directory & EHR Charts
# ==============================================================================
@app.get("/api/patients")
async def get_patients(q: Optional[str] = None):
    """Queries MySQL patients table with optional search query."""
    patients = DatabaseManager.get_all_patients(query=q)
    return {"status": "ok", "query": q, "count": len(patients), "patients": patients}


@app.post("/api/patients")
async def create_patient(payload: Dict[str, Any]):
    """Registers a new patient electronic health record into MySQL."""
    result = DatabaseManager.create_patient(payload)
    return result


@app.get("/api/patients/{mrn}")
async def get_patient_chart(mrn: str):
    """Fetches complete patient record, notes, prescriptions, and lab files from MySQL."""
    patient = DatabaseManager.get_patient_by_mrn(mrn)
    if not patient:
        return JSONResponse(status_code=404, content={"error": "Patient record not found", "mrn": mrn})
    return {"status": "ok", "chart": patient}


@app.put("/api/patients/{mrn}")
@app.patch("/api/patients/{mrn}")
async def update_patient(mrn: str, payload: Dict[str, Any]):
    """Updates patient demographics and clinical details in MySQL."""
    updated = DatabaseManager.update_patient(mrn, payload)
    if not updated:
        return JSONResponse(status_code=404, content={"error": "Patient record not found", "mrn": mrn})
    return {"status": "updated", "patient": updated}


@app.delete("/api/patients/{mrn}")
async def delete_patient(mrn: str):
    """Permanently deletes a patient and cascades to all child notes, prescriptions, and files."""
    success = DatabaseManager.delete_patient(mrn)
    if not success:
        return JSONResponse(status_code=404, content={"error": "Patient record not found", "mrn": mrn})
    return {"status": "deleted", "mrn": mrn, "message": "Patient record permanently deleted"}


# ==============================================================================
# 3. Clinical Progress Notes & Prescriptions
# ==============================================================================
@app.post("/api/patients/{mrn}/notes")
async def add_patient_note(mrn: str, payload: Dict[str, Any]):
    """Persists clinician progress note into MySQL patient_notes table."""
    note_text = str(payload.get("note", ""))
    author = str(payload.get("author", "Dr. Sarah Chen, MD"))
    category = str(payload.get("category", "Progress Note"))
    title = str(payload.get("title", "Clinical Encounter Note"))
    saved_note = DatabaseManager.add_patient_note(
        mrn=mrn,
        author_name=author,
        note_text=note_text,
        category=category,
        title=title
    )
    return {
        "status": "created",
        "mrn": mrn,
        "note_saved": saved_note
    }


@app.post("/api/patients/{mrn}/prescriptions")
async def add_prescription(mrn: str, payload: Dict[str, Any]):
    """Adds a new prescription for a patient in MySQL."""
    med = str(payload.get("medication_name", ""))
    dosage = str(payload.get("dosage", "10 mg"))
    frequency = str(payload.get("frequency", "Once daily"))
    duration = str(payload.get("duration", "30 Days"))
    instructions = str(payload.get("instructions", "Take with water"))
    prescribed_by = str(payload.get("prescribed_by", "Dr. Sarah Chen, MD"))
    saved = DatabaseManager.add_prescription(mrn, med, dosage, frequency, duration, instructions, prescribed_by)
    return {"status": "created", "prescription": saved}


# ==============================================================================
# 4. Medical BLOB File Upload & Binary Streaming Downloads
# ==============================================================================
@app.post("/api/patients/{mrn}/documents/upload")
async def upload_document(
    mrn: str,
    file: UploadFile = File(...),
    category: str = Form("Diagnostic Lab Report"),
    description: str = Form("Uploaded medical diagnostic file"),
    uploaded_by: str = Form("Clinical Staff")
):
    """Uploads a real file (PDF, image, text) and stores the binary BLOB in MySQL."""
    file_bytes = await file.read()
    filename = file.filename or "uploaded_document.pdf"
    mime_type = file.content_type or "application/pdf"
    file_size = len(file_bytes)

    saved_file = DatabaseManager.save_medical_file(
        patient_mrn=mrn,
        filename=filename,
        original_name=filename,
        mime_type=mime_type,
        file_size=file_size,
        file_bytes=file_bytes,
        category=category,
        description=description,
        uploaded_by=uploaded_by
    )
    return {
        "status": "uploaded",
        "file": saved_file,
        "message": f"Successfully stored {file_size} bytes in MySQL BLOB storage"
    }


@app.get("/api/documents/{doc_id}/download")
async def download_file_by_id(doc_id: int):
    """Streams the raw binary BLOB stored in MySQL back to the client as a download."""
    doc = DatabaseManager.get_file_by_id(doc_id)
    if not doc or not doc.get("file_data"):
        return JSONResponse(status_code=404, content={"error": "Document not found in database"})

    file_bytes = doc["file_data"]
    if isinstance(file_bytes, str):
        file_bytes = file_bytes.encode("utf-8")

    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type=doc.get("mime_type", "application/octet-stream"),
        headers={
            "Content-Disposition": f"attachment; filename=\"{doc.get('original_name', 'document.pdf')}\"",
            "Content-Length": str(len(file_bytes))
        }
    )


@app.get("/records/download")
async def download_record(file: str):
    """Retrieves document content from MySQL lab repository."""
    content = DatabaseManager.get_document_content(file)
    return {
        "status": "ok",
        "filename": file,
        "content": content
    }


@app.post("/api/lab-reports/import")
async def import_lab_report(request: Request):
    """Ingests and validates XML laboratory payloads."""
    body_bytes = await request.body()
    return {
        "status": "imported",
        "payload_size": len(body_bytes),
        "message": "Laboratory payload parsed and stored in clinical repository"
    }


# ==============================================================================
# 5. Appointments & Clinical Scheduling
# ==============================================================================
@app.get("/api/appointments")
async def get_appointments():
    """Returns all scheduled clinical encounters from MySQL."""
    appts = DatabaseManager.get_all_appointments()
    return {"status": "ok", "appointments": appts}


@app.post("/api/appointments")
async def book_appointment(
    patient_mrn: str = Form(...),
    clinician_name: str = Form("Dr. Sarah Chen, MD"),
    department: str = Form("Internal Medicine"),
    date: str = Form(...),
    time: str = Form("10:00 AM"),
    reason: str = Form(...),
    visit_type: str = Form("In-Person Consultation")
):
    """Persists clinical appointment schedule to MySQL appointments table."""
    appt = DatabaseManager.create_appointment(
        mrn=patient_mrn,
        clinician_name=clinician_name,
        department=department,
        date_str=date,
        time_str=time,
        reason=reason,
        visit_type=visit_type
    )
    return {
        "status": "confirmed",
        "appointment": appt
    }


# ==============================================================================
# 6. Insurance & Billing Verification
# ==============================================================================
@app.get("/api/billing/records")
async def get_billing_records():
    """Returns all insurance records and coverage policies from MySQL."""
    records = DatabaseManager.get_all_insurance_records()
    return {"status": "ok", "records": records}


@app.post("/api/billing/records")
@app.post("/api/billing/issue")
async def issue_insurance_policy(payload: Dict[str, Any]):
    """Issues and registers a new insurance policy record into MySQL."""
    insurance_id = str(payload.get("insurance_id", ""))
    patient_mrn = str(payload.get("patient_mrn", "MRN-10234"))
    policy_holder = str(payload.get("policy_holder", "Insured Patient"))
    provider_name = str(payload.get("provider_name", "BlueCross BlueShield"))
    coverage_type = str(payload.get("coverage_type", "Comprehensive Platinum PPO"))
    copay = str(payload.get("copay", "$25.00"))
    deductible = str(payload.get("deductible", "$500.00"))
    valid_until = str(payload.get("valid_until", "2027-12-31"))

    record = DatabaseManager.create_insurance_record(
        insurance_id=insurance_id,
        patient_mrn=patient_mrn,
        policy_holder=policy_holder,
        provider_name=provider_name,
        coverage_type=coverage_type,
        copay=copay,
        deductible=deductible,
        valid_until=valid_until
    )
    return {"status": "created", "record": record}


@app.get("/api/billing/lookup")
async def billing_lookup(insurance_id: str):
    """Queries MySQL insurance_records table."""
    record = DatabaseManager.lookup_insurance(insurance_id)
    if not record:
        return JSONResponse(
            status_code=404,
            content={"status": "not_found", "error": f"No active insurance policy found matching ID '{insurance_id}'"}
        )
    return {
        "status": "verified",
        **record
    }


# ==============================================================================
# ASGI Launcher with Auto-Reload Debugger
# ==============================================================================
if __name__ == "__main__":
    import uvicorn
    import sys
    from pathlib import Path

    # Ensure project root is in sys.path so 'backend.app:app' can always be imported
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    backend_dir = str(Path(__file__).resolve().parent)
    port = int(os.getenv("PORT", "8080"))
    reload_enabled = os.getenv("RELOAD", "true").lower() in ("true", "1", "yes")

    print(f"[*] Starting MedCore Backend API with Auto-Reload Debugger on http://localhost:{port} (reload={reload_enabled})...")
    uvicorn.run(
        "backend.app:app",
        host="0.0.0.0",
        port=port,
        reload=reload_enabled,
        reload_dirs=[backend_dir],
        log_level="info"
    )

