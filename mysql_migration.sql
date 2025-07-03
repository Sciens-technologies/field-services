-- Migration script to convert MySQL schema to PostgreSQL
-- Notes:
-- 1. Replaced MySQL ENUM with TEXT and CHECK constraints
-- 2. Replaced TINYINT(1) with BOOLEAN
-- 3. Used BIGSERIAL for auto-incrementing primary keys
-- 4. Adjusted foreign key constraints to match PostgreSQL syntax
-- 5. Included all table modifications from the provided schema

-- Drop existing tables if they exist (in reverse order to avoid foreign key issues)
DROP TABLE IF EXISTS work_order_form_validation_logs CASCADE;
DROP TABLE IF EXISTS work_order_form_audit CASCADE;
DROP TABLE IF EXISTS work_order_form_sessions CASCADE;
DROP TABLE IF EXISTS work_order_form_attachments CASCADE;
DROP TABLE IF EXISTS work_order_form_steps CASCADE;
DROP TABLE IF EXISTS work_order_formdata CASCADE;
DROP TABLE IF EXISTS work_order_forms CASCADE;
DROP TABLE IF EXISTS work_order_templates CASCADE;
DROP TABLE IF EXISTS user_notification_preferences CASCADE;
DROP TABLE IF EXISTS user_activity_logs CASCADE;
DROP TABLE IF EXISTS notification_history CASCADE;
DROP TABLE IF EXISTS auth_tokens CASCADE;
DROP TABLE IF EXISTS support_tickets CASCADE;
DROP TABLE IF EXISTS system_feedback CASCADE;
DROP TABLE IF EXISTS work_centre_subcontractors CASCADE;
DROP TABLE IF EXISTS subcontractor_companies CASCADE;
DROP TABLE IF EXISTS picture_quality_metrics CASCADE;
DROP TABLE IF EXISTS picture_download_log CASCADE;
DROP TABLE IF EXISTS picture_annotation CASCADE;
DROP TABLE IF EXISTS ocr_techniques CASCADE;
DROP TABLE IF EXISTS picture_qualification CASCADE;
DROP TABLE IF EXISTS picture_metadata CASCADE;
DROP TABLE IF EXISTS offline_capture_queue CASCADE;
DROP TABLE IF EXISTS data_capture_validation_logs CASCADE;
DROP TABLE IF EXISTS other_request_capture CASCADE;
DROP TABLE IF EXISTS termination_capture CASCADE;
DROP TABLE IF EXISTS complaint_capture CASCADE;
DROP TABLE IF EXISTS subscription_capture CASCADE;
DROP TABLE IF EXISTS new_connection_capture CASCADE;
DROP TABLE IF EXISTS work_order_data_capture CASCADE;
DROP TABLE IF EXISTS work_order_reassign CASCADE;
DROP TABLE IF EXISTS work_order_feedback CASCADE;
DROP TABLE IF EXISTS work_order_attachments CASCADE;
DROP TABLE IF EXISTS work_order_status_logs CASCADE;
DROP TABLE IF EXISTS work_order_notes CASCADE;
DROP TABLE IF EXISTS work_order_acknowledgments CASCADE;
DROP TABLE IF EXISTS work_order_execution_anomalies CASCADE;
DROP TABLE IF EXISTS work_order_execution CASCADE;
DROP TABLE IF EXISTS anomalies CASCADE;
DROP TABLE IF EXISTS work_order_assignments CASCADE;
DROP TABLE IF EXISTS work_orders CASCADE;
DROP TABLE IF EXISTS work_centres CASCADE;
DROP TABLE IF EXISTS resource_requests CASCADE;
DROP TABLE IF EXISTS resource_types CASCADE;
DROP TABLE IF EXISTS resource_request_modules CASCADE;
DROP TABLE IF EXISTS device_health_logs CASCADE;
DROP TABLE IF EXISTS device_status_audit CASCADE;
DROP TABLE IF EXISTS device_registration_confirmations CASCADE;
DROP TABLE IF EXISTS device_assignments CASCADE;
DROP TABLE IF EXISTS device_artifacts CASCADE;
DROP TABLE IF EXISTS devices CASCADE;
DROP TABLE IF EXISTS user_auth_metadata CASCADE;
DROP TABLE IF EXISTS user_auth_providers CASCADE;
DROP TABLE IF EXISTS user_notifications CASCADE;
DROP TABLE IF EXISTS artifact_notification_events CASCADE;
DROP TABLE IF EXISTS notification_templates CASCADE;
DROP TABLE IF EXISTS user_status_audit CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Create users table
CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,
    uuid VARCHAR(75) UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    profile_image VARCHAR(256),
    preferred_lang VARCHAR(10),
    timezone_id VARCHAR(75),
    is_2fa_enabled BOOLEAN DEFAULT FALSE,
    activated BOOLEAN DEFAULT TRUE,
    status TEXT DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE', 'BLOCKED', 'DEACTIVATED')),
    external_id VARCHAR(75),
    token TEXT,
    activation_key VARCHAR(20),
    reset_key VARCHAR(20),
    login_ip VARCHAR(75),
    last_login_ip VARCHAR(75),
    login_date TIMESTAMP,
    last_login TIMESTAMP,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reset_at TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create roles table
CREATE TABLE roles (
    role_id BIGSERIAL PRIMARY KEY,
    role_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create user_roles table
CREATE TABLE user_roles (
    id BIGSERIAL PRIMARY KEY,
    role_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_users FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- Create permissions table
CREATE TABLE permissions (
    permission_id BIGSERIAL PRIMARY KEY,
    feature VARCHAR(100) NOT NULL,
    description TEXT,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE
);

-- Create role_permissions table
CREATE TABLE role_permissions (
    role_id BIGINT,
    permission_id BIGINT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

-- Create user_status_audit table
CREATE TABLE user_status_audit (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    changed_by VARCHAR(50) NOT NULL,
    old_status TEXT NOT NULL CHECK (old_status IN ('ACTIVE', 'INACTIVE', 'BLOCKED', 'DEACTIVATED')),
    new_status TEXT NOT NULL CHECK (new_status IN ('ACTIVE', 'INACTIVE', 'BLOCKED', 'DEACTIVATED')),
    reason TEXT NOT NULL,
    remarks TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create notification_templates table
CREATE TABLE notification_templates (
    template_id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    template_key VARCHAR(50) NOT NULL UNIQUE,
    subject VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    notification_type TEXT NOT NULL CHECK (notification_type IN ('EMAIL', 'SMS', 'PUSH', 'IN_APP')),
    active BOOLEAN DEFAULT TRUE,
    status VARCHAR(75),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create artifact_notification_events table
CREATE TABLE artifact_notification_events (
    event_id BIGSERIAL PRIMARY KEY,
    template_id BIGINT NOT NULL,
    initiated_by BIGINT,
    notification_scope TEXT NOT NULL DEFAULT 'INDIVIDUAL' CHECK (notification_scope IN ('INDIVIDUAL', 'GROUP', 'SERVICETYPE')),
    target_type TEXT CHECK (target_type IN ('USER', 'ROLE', 'SEGMENT')),
    target_value VARCHAR(255),
    custom_metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES notification_templates(template_id) ON DELETE CASCADE,
    FOREIGN KEY (initiated_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create user_notifications table
CREATE TABLE user_notifications (
    notification_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    target_type TEXT CHECK (target_type IN ('ROLE', 'SEGMENT', 'GROUP')),
    target_value VARCHAR(255),
    template_id BIGINT,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SENT', 'FAILED', 'READ')),
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP,
    read_at TIMESTAMP,
    CONSTRAINT user_notifications_check CHECK (
        (user_id IS NOT NULL AND target_type IS NULL AND target_value IS NULL) OR
        (user_id IS NULL AND target_type IS NOT NULL AND target_value IS NOT NULL)
    ),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (template_id) REFERENCES notification_templates(template_id) ON DELETE SET NULL
);

-- Create user_auth_providers table
CREATE TABLE user_auth_providers (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('LOCAL', 'AZURE', 'GOOGLE', 'FACEBOOK')),
    provider_user_id VARCHAR(150) NOT NULL,
    provider_username VARCHAR(150),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_user_provider UNIQUE (user_id, provider),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create user_auth_metadata table
CREATE TABLE user_auth_metadata (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    provider VARCHAR(50),
    external_user_id VARCHAR(100),
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create work_centres table
CREATE TABLE work_centres (
    work_centre_id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    registration_number VARCHAR(100) UNIQUE,
    tax_id VARCHAR(100),
    contact_email VARCHAR(150),
    contact_phone VARCHAR(50),
    website_url VARCHAR(255),
    address_line1 VARCHAR(255),
    address_line2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100),
    status VARCHAR(75) DEFAULT 'ACTIVE',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by BIGINT,
    updated_by BIGINT,
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create devices table
CREATE TABLE devices (
    device_id BIGSERIAL PRIMARY KEY,
    serial_number VARCHAR(100) UNIQUE,
    model VARCHAR(100),
    status TEXT DEFAULT 'REGISTERED' CHECK (status IN ('REGISTERED', 'ACTIVE', 'BLOCKED', 'DEACTIVATED', 'READY_TO_ACTIVATE')),
    last_communication TIMESTAMP,
    location VARCHAR(100),
    work_center_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_center_id) REFERENCES work_centres(work_centre_id) ON DELETE SET NULL
);

-- Create device_artifacts table
CREATE TABLE device_artifacts (
    artifact_id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('PURCHASED', 'LEASED', 'TRANSFERRED', 'DONATED', 'MANUFACTURED', 'OTHER')),
    source_reference VARCHAR(255),
    source_details JSONB,
    source_destination TEXT CHECK (source_destination IN ('REGIONAL_PLANET', 'CENTER_PLANET', 'OPERATIONAL_PLANET', 'WORK_CENTER', 'OTHER')),
    acquisition_date DATE DEFAULT CURRENT_DATE,
    added_by BIGINT,
    remarks TEXT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (added_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create device_assignments table
CREATE TABLE device_assignments (
    assignment_id BIGSERIAL PRIMARY KEY,
    device_id BIGINT NOT NULL,
    user_id BIGINT,
    role TEXT CHECK (role IN ('TECHNICIAN', 'SUPERVISOR', 'MANAGER', 'ADMIN', 'WAREHOUSE', 'OTHER')),
    assigned_by_user_id BIGINT,
    assigned_by_role TEXT CHECK (assigned_by_role IN ('TECHNICIAN', 'SUPERVISOR', 'MANAGER', 'ADMIN', 'WAREHOUSE', 'OTHER')),
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unassigned_at TIMESTAMP,
    status VARCHAR(50),
    active BOOLEAN DEFAULT TRUE,
    CONSTRAINT device_assignments_check_type CHECK (
        (user_id IS NOT NULL AND role IS NULL) OR
        (user_id IS NULL AND role IS NOT NULL)
    ),
    CONSTRAINT device_assignments_check_assigner CHECK (
        (assigned_by_user_id IS NOT NULL AND assigned_by_role IS NULL) OR
        (assigned_by_user_id IS NULL AND assigned_by_role IS NOT NULL)
    ),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (assigned_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create device_registration_confirmations table
CREATE TABLE device_registration_confirmations (
    confirmation_id BIGSERIAL PRIMARY KEY,
    device_id BIGINT,
    functional_admin_id BIGINT,
    confirmed_at TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (functional_admin_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create device_status_audit table
CREATE TABLE device_status_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    device_id BIGINT,
    status_before VARCHAR(50),
    status_after VARCHAR(50),
    reason TEXT,
    changed_by_user_id BIGINT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create device_health_logs table
CREATE TABLE device_health_logs (
    health_id BIGSERIAL PRIMARY KEY,
    device_id BIGINT,
    battery_status VARCHAR(20),
    network_status VARCHAR(20),
    touch_screen VARCHAR(20),
    camera_status VARCHAR(20),
    gps_status VARCHAR(20),
    logtext JSONB,
    logged_by BIGINT,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (logged_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create resource_request_modules table
CREATE TABLE resource_request_modules (
    module_id BIGSERIAL PRIMARY KEY,
    module_key VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create resource_types table
CREATE TABLE resource_types (
    resource_type_id BIGSERIAL PRIMARY KEY,
    type_key VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create resource_requests table
CREATE TABLE resource_requests (
    request_id BIGSERIAL PRIMARY KEY,
    module_id BIGINT NOT NULL,
    module_reference_id BIGINT NOT NULL,
    requested_by BIGINT NOT NULL,
    resource_type_id BIGINT NOT NULL,
    resource_description TEXT,
    quantity INT DEFAULT 1,
    priority TEXT DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'URGENT')),
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'FULFILLED')),
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (module_id) REFERENCES resource_request_modules(module_id) ON DELETE CASCADE,
    FOREIGN KEY (resource_type_id) REFERENCES resource_types(resource_type_id) ON DELETE CASCADE,
    FOREIGN KEY (requested_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create work_orders table
CREATE TABLE work_orders (
    work_order_id BIGSERIAL PRIMARY KEY,
    wo_number VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255),
    description TEXT,
    work_order_type VARCHAR(100),
    customer_id VARCHAR(100),
    customer_name VARCHAR(255),
    location VARCHAR(255),
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    scheduled_date TIMESTAMP,
    due_date TIMESTAMP,
    priority TEXT DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'URGENT')),
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'REJECTED')),
    created_by BIGINT,
    work_centre_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (work_centre_id) REFERENCES work_centres(work_centre_id) ON DELETE SET NULL
);

-- Create work_order_assignments table
CREATE TABLE work_order_assignments (
    assignment_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    assigned_by BIGINT NOT NULL,
    reassigned BOOLEAN DEFAULT FALSE,
    reassignment_reason TEXT,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    subject VARCHAR(255),
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create anomalies table
CREATE TABLE anomalies (
    anomaly_id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE
);

-- Create work_order_execution table
CREATE TABLE work_order_execution (
    execution_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    gps_lat DECIMAL(10,8),
    gps_long DECIMAL(11,8),
    parts_used TEXT,
    synced BOOLEAN DEFAULT FALSE,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create work_order_execution_anomalies table
CREATE TABLE work_order_execution_anomalies (
    id BIGSERIAL PRIMARY KEY,
    execution_id BIGINT NOT NULL,
    anomaly_id BIGINT NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (execution_id) REFERENCES work_order_execution(execution_id) ON DELETE CASCADE,
    FOREIGN KEY (anomaly_id) REFERENCES anomalies(anomaly_id) ON DELETE RESTRICT
);

-- Create work_order_acknowledgments table
CREATE TABLE work_order_acknowledgments (
    ack_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT,
    customer_signature TEXT,
    remarks TEXT,
    acknowledged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create work_order_notes table
CREATE TABLE work_order_notes (
    note_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    added_by BIGINT NOT NULL,
    note TEXT,
    note_type TEXT DEFAULT 'FIELD_AGENT' CHECK (note_type IN ('FIELD_AGENT', 'REVIEWER', 'SYSTEM')),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (added_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create work_order_status_logs table
CREATE TABLE work_order_status_logs (
    status_log_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    previous_status VARCHAR(50),
    new_status VARCHAR(50),
    changed_by BIGINT,
    reason TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create work_order_attachments table
CREATE TABLE work_order_attachments (
    attachment_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    file_path TEXT,
    file_name VARCHAR(255),
    type TEXT CHECK (type IN ('IMAGE', 'DOCUMENT', 'SIGNATURE')),
    uploaded_by BIGINT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create work_order_feedback table
CREATE TABLE work_order_feedback (
    feedback_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    feedback_by BIGINT,
    feedback_type TEXT CHECK (feedback_type IN ('REVIEW', 'REWORK_REQUEST', 'COMMENT')),
    comments TEXT,
    feedback_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (feedback_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create work_order_reassign table
CREATE TABLE work_order_reassign (
    reassign_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    reason TEXT,
    reassign_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create work_order_data_capture table
CREATE TABLE work_order_data_capture (
    capture_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    request_type TEXT NOT NULL CHECK (request_type IN ('NEW_CONNECTION', 'SUBSCRIPTION', 'COMPLAINT', 'TERMINATION', 'OTHER')),
    agent_id BIGINT NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    offline_captured BOOLEAN DEFAULT FALSE,
    synced BOOLEAN DEFAULT TRUE,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create new_connection_capture table
CREATE TABLE new_connection_capture (
    capture_id BIGINT PRIMARY KEY,
    installation_checklist TEXT,
    initial_meter_reading DECIMAL(10,2),
    customer_contact VARCHAR(100),
    customer_address TEXT,
    id_proof_type VARCHAR(50),
    id_proof_number VARCHAR(100),
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Create subscription_capture table
CREATE TABLE subscription_capture (
    capture_id BIGINT PRIMARY KEY,
    plan_name VARCHAR(100),
    billing_cycle VARCHAR(50),
    service_features TEXT,
    discount_applied BOOLEAN DEFAULT FALSE,
    activation_status TEXT DEFAULT 'PENDING' CHECK (activation_status IN ('PENDING', 'ACTIVE', 'FAILED')),
    customer_preferences TEXT,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Create complaint_capture table
CREATE TABLE complaint_capture (
    capture_id BIGINT PRIMARY KEY,
    issue_description TEXT,
    affected_service VARCHAR(100),
    resolution_status TEXT DEFAULT 'UNRESOLVED' CHECK (resolution_status IN ('UNRESOLVED', 'IN_PROGRESS', 'RESOLVED')),
    attempted_fixes TEXT,
    evidence_url TEXT,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Create termination_capture table
CREATE TABLE termination_capture (
    capture_id BIGINT PRIMARY KEY,
    final_meter_reading DECIMAL(10,2),
    disconnect_status TEXT DEFAULT 'PENDING' CHECK (disconnect_status IN ('DISCONNECTED', 'PENDING')),
    termination_reason TEXT,
    service_end_date DATE,
    final_billing_info TEXT,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Create other_request_capture table
CREATE TABLE other_request_capture (
    capture_id BIGINT PRIMARY KEY,
    custom_notes TEXT,
    additional_instructions TEXT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Create data_capture_validation_logs table
CREATE TABLE data_capture_validation_logs (
    validation_id BIGSERIAL PRIMARY KEY,
    capture_id BIGINT NOT NULL,
    field_name VARCHAR(100),
    error_message TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Create offline_capture_queue table
CREATE TABLE offline_capture_queue (
    queue_id BIGSERIAL PRIMARY KEY,
    capture_id BIGINT NOT NULL,
    device_id VARCHAR(100),
    sync_status TEXT DEFAULT 'PENDING' CHECK (sync_status IN ('PENDING', 'SYNCED', 'FAILED')),
    last_attempt TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Create picture_metadata table
CREATE TABLE picture_metadata (
    picture_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    request_type TEXT NOT NULL CHECK (request_type IN ('NEW_CONNECTION', 'SUBSCRIPTION', 'COMPLAINT', 'TERMINATION', 'OTHER')),
    meter_number VARCHAR(100),
    supply_point_number VARCHAR(100),
    cycle VARCHAR(50),
    location VARCHAR(255),
    file_name VARCHAR(255),
    file_path TEXT NOT NULL,
    file_format VARCHAR(10),
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create picture_qualification table
CREATE TABLE picture_qualification (
    qualification_id BIGSERIAL PRIMARY KEY,
    picture_id BIGINT NOT NULL,
    qualified_by BIGINT NOT NULL,
    qualification_status TEXT NOT NULL CHECK (qualification_status IN ('OK', 'NOT_OK')),
    comments TEXT,
    qualified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (picture_id) REFERENCES picture_metadata(picture_id) ON DELETE CASCADE,
    FOREIGN KEY (qualified_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create ocr_techniques table
CREATE TABLE ocr_techniques (
    ocr_id BIGSERIAL PRIMARY KEY,
    technique_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE
);

-- Create picture_annotation table
CREATE TABLE picture_annotation (
    annotation_id BIGSERIAL PRIMARY KEY,
    picture_id BIGINT NOT NULL,
    annotated_by BIGINT NOT NULL,
    ocr_id BIGINT NOT NULL,
    annotation_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (picture_id) REFERENCES picture_metadata(picture_id) ON DELETE CASCADE,
    FOREIGN KEY (annotated_by) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (ocr_id) REFERENCES ocr_techniques(ocr_id) ON DELETE RESTRICT
);

-- Create picture_download_log table
CREATE TABLE picture_download_log (
    download_id BIGSERIAL PRIMARY KEY,
    picture_id BIGINT,
    downloaded_by BIGINT NOT NULL,
    is_batch BOOLEAN DEFAULT FALSE,
    format VARCHAR(10),
    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (picture_id) REFERENCES picture_metadata(picture_id) ON DELETE SET NULL,
    FOREIGN KEY (downloaded_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create picture_quality_metrics table
CREATE TABLE picture_quality_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    agent_id BIGINT NOT NULL,
    total_uploaded INT DEFAULT 0,
    total_ok INT DEFAULT 0,
    total_not_ok INT DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create subcontractor_companies table
CREATE TABLE subcontractor_companies (
    subcontractor_id BIGSERIAL PRIMARY KEY,
    company_name VARCHAR(255) NOT NULL,
    telephone VARCHAR(50),
    email VARCHAR(150),
    description TEXT,
    location VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE
);

-- Create work_centre_subcontractors table
CREATE TABLE work_centre_subcontractors (
    assignment_id BIGSERIAL PRIMARY KEY,
    work_centre_id BIGINT NOT NULL,
    subcontractor_id BIGINT NOT NULL,
    assigned_by BIGINT NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (work_centre_id) REFERENCES work_centres(work_centre_id) ON DELETE CASCADE,
    FOREIGN KEY (subcontractor_id) REFERENCES subcontractor_companies(subcontractor_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create system_feedback table
CREATE TABLE system_feedback (
    feedback_id VARCHAR(75) PRIMARY KEY,
    user_id VARCHAR(75) NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('BUG', 'FEATURE', 'IMPROVEMENT', 'OTHER')),
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    priority TEXT DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'URGENT')),
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'IN_REVIEW', 'RESOLVED', 'CLOSED')),
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(uuid) ON DELETE CASCADE
);

-- Create support_tickets table
CREATE TABLE support_tickets (
    ticket_id VARCHAR(75) PRIMARY KEY,
    user_id VARCHAR(75) NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('TECHNICAL', 'BILLING', 'ACCOUNT', 'SERVICE', 'OTHER')),
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    priority TEXT DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'URGENT')),
    status TEXT DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(uuid) ON DELETE CASCADE
);

-- Create auth_tokens table
CREATE TABLE auth_tokens (
    token_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    token_type VARCHAR(50) DEFAULT 'bearer',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP,
    device_info JSONB,
    ip_address VARCHAR(45),
    status VARCHAR(50) DEFAULT 'ACTIVE',
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create notification_history table
CREATE TABLE notification_history (
    history_id BIGSERIAL PRIMARY KEY,
    notification_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('EMAIL', 'SMS', 'PUSH', 'IN_APP')),
    status TEXT DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SENT', 'FAILED', 'DELIVERED', 'READ')),
    error_message TEXT,
    delivery_timestamp TIMESTAMP,
    delivery_metadata JSONB,
    retry_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (notification_id) REFERENCES user_notifications(notification_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create user_activity_logs table
CREATE TABLE user_activity_logs (
    log_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    activity_type VARCHAR(100) NOT NULL,
    activity_details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'SUCCESS',
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create user_notification_preferences table
CREATE TABLE user_notification_preferences (
    preference_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    notification_type VARCHAR(100) NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('EMAIL', 'SMS', 'PUSH', 'IN_APP')),
    is_enabled BOOLEAN DEFAULT TRUE,
    frequency VARCHAR(50) DEFAULT 'IMMEDIATE',
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    CONSTRAINT uq_user_notification_pref UNIQUE (user_id, notification_type, channel),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create work_order_templates table
CREATE TABLE work_order_templates (
    template_id BIGSERIAL PRIMARY KEY,
    work_order_type VARCHAR(50) NOT NULL,
    form_type VARCHAR(100) NOT NULL,
    template JSONB NOT NULL,
    version VARCHAR(20) DEFAULT '1.0',
    active BOOLEAN DEFAULT TRUE,
    created_by BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create work_order_forms table
CREATE TABLE work_order_forms (
    form_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    work_order_type VARCHAR(50) NOT NULL,
    template_id BIGINT NOT NULL,
    status VARCHAR(75) DEFAULT 'PENDING',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id) ON DELETE CASCADE,
    FOREIGN KEY (template_id) REFERENCES work_order_templates(template_id) ON DELETE CASCADE
);

-- Create work_order_formdata table
CREATE TABLE work_order_formdata (
    formdata_id BIGSERIAL PRIMARY KEY,
    form_id BIGINT NOT NULL,
    session_id VARCHAR(75) NOT NULL UNIQUE,
    data JSONB NOT NULL,
    progress DECIMAL(5,2) DEFAULT 0.00,
    status VARCHAR(20) DEFAULT 'IN_PROGRESS',
    current_step INTEGER DEFAULT 1,
    form_type VARCHAR(32) DEFAULT 'ZDEV',
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (form_id) REFERENCES work_order_forms(form_id) ON DELETE CASCADE
);

-- Create work_order_form_steps table
CREATE TABLE work_order_form_steps (
    step_id BIGSERIAL PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    form_id BIGINT,
    step_number INTEGER NOT NULL,
    step_title VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    data JSONB,
    validation_status BOOLEAN DEFAULT FALSE,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id) ON DELETE CASCADE,
    FOREIGN KEY (form_id) REFERENCES work_order_forms(form_id) ON DELETE CASCADE
);

-- Create work_order_form_attachments table
CREATE TABLE work_order_form_attachments (
    attachment_id BIGSERIAL PRIMARY KEY,
    formdata_id BIGINT,
    step_number INTEGER,
    file_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    file_type VARCHAR(50),
    file_size BIGINT,
    uploaded_by BIGINT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Create work_order_form_sessions table
CREATE TABLE work_order_form_sessions (
    session_id VARCHAR(75) PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    device_info JSONB,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    sync_status VARCHAR(20) DEFAULT 'PENDING',
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create work_order_form_audit table
CREATE TABLE work_order_form_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    action VARCHAR(20) NOT NULL,
    old_data JSONB,
    new_data JSONB,
    changed_by BIGINT NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create work_order_form_validation_logs table
CREATE TABLE work_order_form_validation_logs (
    validation_id BIGSERIAL PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    step_number INTEGER NOT NULL,
    field_name VARCHAR(100) NOT NULL,
    error_message TEXT,
    is_valid BOOLEAN DEFAULT FALSE,
    validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id) ON DELETE CASCADE
);