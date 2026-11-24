export type UserRole = 'Employee' | 'Manager' | 'HR' | 'Accounts' | 'Admin';

export interface AuthUser {
  id: string;
  username: string;
  email: string;
  fullName: string;
  role: UserRole;
  department: string;
  designation: string;
  managerId?: string | null;
  totpEnabled: boolean;
  mandatory2fa?: boolean;
  remainingRecoveryCodes?: number;
  permissions: string[];
  stepUpVerified?: boolean;
}

export interface NotificationItem {
  id: string;
  title: string;
  message: string;
  category: string;
  related_entity_type: string | null;
  related_entity_id: string | null;
  is_read: number;
  created_at: string;
}

export interface CandidateSummary {
  id: string;
  full_name: string;
  email: string;
  mobile: string;
  job_position: string;
  department: string;
  assigned_recruiter_id: string;
  recruiter_name?: string;
  recruiter_email?: string;
  experience_years: number;
  expected_ctc: string;
  notice_period_days: number;
  notes: string;
  email_confirmed_by_recruiter: number;
  status: string;
  doc_verification_status: string;
  hr_approved_by?: string | null;
  hr_approved_at?: string | null;
  offer_letter_sent_at?: string | null;
  created_at: string;
  updated_at: string;
  docSummary?: {
    uploaded_count: number;
    approved_count: number;
    rejected_count: number;
  };
}

export interface DocumentRequirement {
  id: string;
  doc_type: string;
  label: string;
  description: string;
  is_mandatory: number;
  is_enabled: number;
  allowed_extensions: string;
  max_size_mb: number;
  sort_order: number;
}

export interface CandidateDocumentRecord {
  id: string;
  doc_type: string;
  original_filename: string;
  mime_type: string;
  file_size_bytes: number;
  sha256_hash: string;
  malware_scan_status: string;
  malware_scan_detail: string;
  status: 'Pending' | 'Uploaded' | 'Approved' | 'Rejected' | 'Re-upload Required';
  rejection_reason: string | null;
  reviewer_name?: string | null;
  reviewed_at: string | null;
  version: number;
  is_current: number;
  uploaded_at: string;
  signedDownloadUrl?: string;
}

export interface CandidateChecklistEntry {
  requirement: DocumentRequirement;
  currentDocument: CandidateDocumentRecord | null;
  status: string;
  history: CandidateDocumentRecord[];
}

export interface CandidateInvitationRecord {
  id: string;
  purpose: string;
  expires_at: string;
  accepted_at: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
  sent_to_email: string;
  email_delivery_status: string;
  email_delivery_error: string | null;
  created_at: string;
}

export interface PortalChecklistItem {
  docType: string;
  label: string;
  description: string;
  isMandatory: boolean;
  maxSizeMb: number;
  allowedExtensions: string;
  status: 'Pending' | 'Uploaded' | 'Approved' | 'Rejected' | 'Re-upload Required';
  rejectionReason: string | null;
  uploadedFile: {
    filename: string;
    sizeBytes: number;
    version: number;
    uploadedAt: string;
  } | null;
  canUpload: boolean;
}

export interface EmployeeRecord {
  id: string;
  user_id: string | null;
  employee_code: string;
  full_name: string;
  email: string;
  mobile: string;
  department: string;
  designation: string;
  joining_date: string;
  employment_status: string;
  ctc_annual?: number;
  basic_salary?: number;
  hra?: number;
  allowances?: number;
  pf_number?: string;
  esi_number?: string;
  pan_number?: string;
  bank_name?: string;
  bank_account_masked?: string;
  ifsc_code?: string;
  source_candidate_id?: string | null;
}

export interface LeaveRecord {
  id: string;
  employee_id: string;
  employee_name: string;
  department: string;
  leave_type: string;
  start_date: string;
  end_date: string;
  days: number;
  reason: string;
  status: 'Pending' | 'Approved' | 'Rejected';
  created_at: string;
}

export interface PayrollRunRecord {
  id: string;
  month_year: string;
  total_gross: number;
  total_pf: number;
  total_esi: number;
  total_pt: number;
  total_tds: number;
  total_net: number;
  employee_count: number;
  status: string;
  processed_at: string;
}

export interface PayslipRecord {
  id: string;
  month_year: string;
  gross_pay: number;
  pf_deduction: number;
  esi_deduction: number;
  pt_deduction: number;
  tds_deduction: number;
  net_pay: number;
  status: string;
}

export interface SessionRecord {
  id: string;
  ip_address: string;
  device_label: string;
  created_at: string;
  last_active_at: string;
  expires_at: string;
  isCurrent: boolean;
}

export interface SecurityPolicy {
  require_2fa_for_employees: number;
  candidate_link_expiry_hours: number;
  max_upload_size_mb: number;
  lockout_threshold: number;
  lockout_duration_minutes: number;
  session_timeout_minutes: number;
  updated_by: string;
  updated_at: string;
}

export interface AuditLogRecord {
  id: string;
  actor_user_id: string | null;
  actor_label: string;
  actor_role: string;
  action: string;
  entity_type: string;
  entity_id: string | null;
  before_state_json: string | null;
  after_state_json: string | null;
  ip_address: string | null;
  metadata_json: string | null;
  created_at: string;
}
