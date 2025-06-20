-- MySQL Migration Script

-- First, disable foreign key checks for the session
SET FOREIGN_KEY_CHECKS = 0;

-- Drop all existing tables in reverse order of dependencies
DROP TABLE IF EXISTS work_centre_subcontractors;
DROP TABLE IF EXISTS subcontractor_companies;

DROP TABLE IF EXISTS picture_quality_metrics;
DROP TABLE IF EXISTS picture_download_log;
DROP TABLE IF EXISTS picture_annotation;
DROP TABLE IF EXISTS ocr_techniques;
DROP TABLE IF EXISTS picture_qualification;
DROP TABLE IF EXISTS picture_metadata;

DROP TABLE IF EXISTS offline_capture_queue;
DROP TABLE IF EXISTS data_capture_validation_logs;
DROP TABLE IF EXISTS other_request_capture;
DROP TABLE IF EXISTS termination_capture;
DROP TABLE IF EXISTS complaint_capture;
DROP TABLE IF EXISTS subscription_capture;
DROP TABLE IF EXISTS new_connection_capture;
DROP TABLE IF EXISTS work_order_data_capture;

DROP TABLE IF EXISTS work_order_reassign;
DROP TABLE IF EXISTS work_order_feedback;
DROP TABLE IF EXISTS work_order_attachments;
DROP TABLE IF EXISTS work_order_status_logs;
DROP TABLE IF EXISTS work_order_notes;
DROP TABLE IF EXISTS work_order_acknowledgments;
DROP TABLE IF EXISTS work_order_execution_anomalies;
DROP TABLE IF EXISTS work_order_execution;
DROP TABLE IF EXISTS anomalies;
DROP TABLE IF EXISTS work_order_assignments;
DROP TABLE IF EXISTS work_orders;
DROP TABLE IF EXISTS work_centres;

DROP TABLE IF EXISTS resource_requests;
DROP TABLE IF EXISTS resource_types;
DROP TABLE IF EXISTS resource_request_modules;

DROP TABLE IF EXISTS device_health_logs;
DROP TABLE IF EXISTS device_status_audit;
DROP TABLE IF EXISTS device_registration_confirmations;
DROP TABLE IF EXISTS device_assignments;
DROP TABLE IF EXISTS device_artifacts;
DROP TABLE IF EXISTS devices;

DROP TABLE IF EXISTS user_auth_metadata;
DROP TABLE IF EXISTS user_auth_providers;
DROP TABLE IF EXISTS user_notifications;
DROP TABLE IF EXISTS artifact_notification_events;
DROP TABLE IF EXISTS notification_templates;
DROP TABLE IF EXISTS user_status_audit;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;

-- Create base tables

-- Users Table
CREATE TABLE users (
    user_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    uuid VARCHAR(75) UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,         -- same as login
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    profile_image VARCHAR(256),                    -- image_url
    preferred_lang VARCHAR(10),                    -- lang_key
    timezone_id VARCHAR(75),
    
    is_2fa_enabled BOOLEAN DEFAULT FALSE,
    activated BOOLEAN DEFAULT TRUE,
    status ENUM('ACTIVE', 'INACTIVE', 'BLOCKED', 'DEACTIVATED') DEFAULT 'ACTIVE',

    external_id VARCHAR(75),
    token TEXT,                                    -- for optional session handling
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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY ux_users_username (username),
    UNIQUE KEY ux_users_email (email)
);

-- Roles Table
CREATE TABLE roles (
    role_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    role_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- User Roles Table
CREATE TABLE user_roles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    role_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_users FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- Permissions Table
CREATE TABLE permissions (
    permission_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    feature VARCHAR(100) NOT NULL,
    description TEXT,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1'
);

-- Role Permissions Table
CREATE TABLE role_permissions (
    role_id BIGINT,
    permission_id BIGINT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, 
    
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id),
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id)
);

-- User Status Audit Table
CREATE TABLE user_status_audit (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    changed_by VARCHAR(50) NOT NULL,  -- admin or system user who made the change
    old_status ENUM('ACTIVE', 'INACTIVE', 'BLOCKED', 'DEACTIVATED') NOT NULL,
    new_status ENUM('ACTIVE', 'INACTIVE', 'BLOCKED', 'DEACTIVATED') NOT NULL,
    reason TEXT NOT NULL,
    remarks TEXT,                     -- optional additional comment
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Notification Templates Table
CREATE TABLE notification_templates (
    template_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    template_key VARCHAR(50) NOT NULL UNIQUE,
    subject VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    notification_type ENUM('EMAIL','SMS','PUSH','IN_APP') NOT NULL,
    active TINYINT(1) DEFAULT '1',
    status VARCHAR(75) NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Artifact Notification Events Table
CREATE TABLE artifact_notification_events (
    event_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    template_id BIGINT NOT NULL,
    initiated_by BIGINT NULL, -- user/admin/system who triggered it
    notification_scope ENUM('INDIVIDUAL', 'GROUP', 'SERVICETYPE') NOT NULL DEFAULT 'INDIVIDUAL',
    target_type ENUM('USER', 'ROLE', 'SEGMENT') NULL, -- Optional
    target_value VARCHAR(255) NULL, -- JSON or comma-separated target IDs if GROUP
    custom_metadata JSON DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (template_id) REFERENCES notification_templates(template_id),
    FOREIGN KEY (initiated_by) REFERENCES users(user_id)
);

-- User Notifications Table
CREATE TABLE user_notifications (
    notification_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    -- Either direct user_id or group-based delivery
    user_id BIGINT NULL, -- for direct notification
    target_type ENUM('ROLE', 'SEGMENT', 'GROUP') NULL, -- for group-based
    target_value VARCHAR(255) NULL, -- e.g., 'FIELD_AGENT', 'ZONE_1', etc.

    template_id BIGINT DEFAULT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    status ENUM('PENDING','SENT','FAILED','READ') DEFAULT 'PENDING',
    metadata JSON DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME DEFAULT NULL,
    read_at DATETIME DEFAULT NULL,

    KEY user_id (user_id),
    KEY template_id (template_id),

    CONSTRAINT user_notifications_ibfk_1 FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT user_notifications_ibfk_2 FOREIGN KEY (template_id) REFERENCES notification_templates(template_id),

    -- XOR logic: either user_id OR (target_type + target_value)
    CHECK (
        (user_id IS NOT NULL AND target_type IS NULL AND target_value IS NULL) OR
        (user_id IS NULL AND target_type IS NOT NULL AND target_value IS NOT NULL)
    )
);

-- User Auth Providers Table
CREATE TABLE user_auth_providers (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    provider ENUM('LOCAL', 'AZURE', 'GOOGLE', 'FACEBOOK') NOT NULL,
    provider_user_id VARCHAR(150) NOT NULL, -- e.g., Azure OID, Google sub, etc.
    provider_username VARCHAR(150),         -- e.g., Azure UPN or email

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uq_user_provider (user_id, provider),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- User Auth Metadata Table
CREATE TABLE user_auth_metadata (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    provider VARCHAR(50), -- 'AZURE'
    external_user_id VARCHAR(100), -- Azure OID
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Work Centres Table
CREATE TABLE work_centres (
    work_centre_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    registration_number VARCHAR(100) UNIQUE,
    tax_id VARCHAR(100) NULL,
    
    contact_email VARCHAR(150) NULL,
    contact_phone VARCHAR(50) NULL,
    website_url VARCHAR(255) NULL,
    
    address_line1 VARCHAR(255) NULL,
    address_line2 VARCHAR(255) NULL,
    city VARCHAR(100) NULL,
    state VARCHAR(100) NULL,
    postal_code VARCHAR(20) NULL,
    country VARCHAR(100) NULL,

    status VARCHAR(75) DEFAULT 'ACTIVE',   -- or use ENUM if statuses are fixed
    active TINYINT(1) DEFAULT 1,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    created_by BIGINT NULL,
    updated_by BIGINT NULL,
    
    FOREIGN KEY (created_by) REFERENCES users(user_id),
    FOREIGN KEY (updated_by) REFERENCES users(user_id)
);

-- Devices Table
CREATE TABLE devices (
    device_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    serial_number VARCHAR(100) UNIQUE,
    model VARCHAR(100),
    status ENUM('REGISTERED', 'ACTIVE', 'BLOCKED', 'DEACTIVATED', 'READY_TO_ACTIVATE') DEFAULT 'REGISTERED',
    last_communication TIMESTAMP,
    location VARCHAR(100),
    work_center_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (work_center_id) REFERENCES work_centres(work_centre_id)
);

-- Device Artifacts Table
CREATE TABLE device_artifacts (
    artifact_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    device_id BIGINT NOT NULL,
    source_type ENUM(
        'PURCHASED',
        'LEASED',
        'TRANSFERRED',
        'DONATED',
        'MANUFACTURED',
        'OTHER'
    ) NOT NULL,
    source_reference VARCHAR(255) NULL,      -- e.g. Invoice number, vendor ID, transfer note
    source_details JSON NULL,                -- optional metadata like vendor info, shipment data
    source_destination ENUM(
        'REGIONAL_PLANET',
        'CENTER_PLANET',
        'OPERATIONAL_PLANET',
        'WORK_CENTER',
        'OTHER'
    ) NULL,                                  -- new column for destination category
    acquisition_date DATE DEFAULT CURRENT_DATE,
    added_by BIGINT NULL,                    -- user/admin who added the record
    remarks TEXT NULL,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (added_by) REFERENCES users(user_id)
);

-- Device Assignments Table
CREATE TABLE device_assignments (
    assignment_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    device_id BIGINT NOT NULL,

    user_id BIGINT NULL, -- for direct user assignment
    role ENUM(
        'TECHNICIAN',
        'SUPERVISOR',
        'MANAGER',
        'ADMIN',
        'WAREHOUSE',
        'OTHER'
    ) NULL, -- for role-based assignment

    assigned_by_user_id BIGINT NULL, -- admin user who assigned
    assigned_by_role ENUM(
        'TECHNICIAN',
        'SUPERVISOR',
        'MANAGER',
        'ADMIN',
        'WAREHOUSE',
        'OTHER'
    ) NULL, -- admin role who assigned

    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unassigned_at TIMESTAMP NULL,
    status VARCHAR(50),
    active TINYINT(1) DEFAULT 1,

    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (assigned_by_user_id) REFERENCES users(user_id),

    -- Enforce only one assignment type: user or role
    CHECK (
        (user_id IS NOT NULL AND role IS NULL) OR
        (user_id IS NULL AND role IS NOT NULL)
    ),

    -- Enforce only one assigner: assigned_by_user_id or assigned_by_role
    CHECK (
        (assigned_by_user_id IS NOT NULL AND assigned_by_role IS NULL) OR
        (assigned_by_user_id IS NULL AND assigned_by_role IS NOT NULL)
    )
);

-- Device Registration Confirmations Table
CREATE TABLE device_registration_confirmations (
    confirmation_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    device_id BIGINT,
    functional_admin_id BIGINT,
    confirmed_at TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (functional_admin_id) REFERENCES users(user_id)
);

-- Device Status Audit Table
CREATE TABLE device_status_audit (
    audit_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    device_id BIGINT,
    status_before VARCHAR(50),
    status_after VARCHAR(50),
    reason TEXT,
    changed_by_user_id BIGINT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (changed_by_user_id) REFERENCES users(user_id)
);

-- Device Health Logs Table
CREATE TABLE device_health_logs (
    health_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    device_id BIGINT,
    battery_status VARCHAR(20),
    network_status VARCHAR(20),
    touch_screen VARCHAR(20),
    camera_status VARCHAR(20),
    gps_status VARCHAR(20),
    -- logtext Json need add 
    logged_by BIGINT,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50),
    active TINYINT(1) DEFAULT 1,
    FOREIGN KEY (device_id) REFERENCES devices(device_id),
    FOREIGN KEY (logged_by) REFERENCES users(user_id)
);

-- Resource Request Modules Table
CREATE TABLE resource_request_modules (
    module_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    module_key VARCHAR(50) NOT NULL UNIQUE, -- e.g., 'DEVICE', 'WORK_ORDER'
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Resource Types Table
CREATE TABLE resource_types (
    resource_type_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    type_key VARCHAR(50) NOT NULL UNIQUE, -- e.g., 'MATERIAL', 'TOOL'
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Resource Requests Table
CREATE TABLE resource_requests (
    request_id BIGINT PRIMARY KEY AUTO_INCREMENT,

    module_id BIGINT NOT NULL, -- FK from resource_request_modules
    module_reference_id BIGINT NOT NULL, -- ID from external module (e.g., device_id, work_order_id)

    requested_by BIGINT NOT NULL,
    resource_type_id BIGINT NOT NULL, -- FK from resource_types
    resource_description TEXT,

    quantity INT DEFAULT 1,
    priority ENUM('LOW', 'MEDIUM', 'HIGH', 'URGENT') DEFAULT 'MEDIUM',
    status ENUM('PENDING', 'APPROVED', 'REJECTED', 'FULFILLED') DEFAULT 'PENDING',

    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    active TINYINT(1) DEFAULT 1,

    FOREIGN KEY (module_id) REFERENCES resource_request_modules(module_id),
    FOREIGN KEY (resource_type_id) REFERENCES resource_types(resource_type_id),
    FOREIGN KEY (requested_by) REFERENCES users(user_id)
);

-- Work Orders Table
CREATE TABLE work_orders (
    work_order_id BIGINT PRIMARY KEY AUTO_INCREMENT,
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
    priority ENUM('LOW', 'MEDIUM', 'HIGH', 'URGENT') DEFAULT 'MEDIUM',
    status ENUM('PENDING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'REJECTED') DEFAULT 'PENDING',
    created_by BIGINT,
    work_centre_id BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (created_by) REFERENCES users(user_id),
    FOREIGN KEY (work_centre_id) REFERENCES work_centres(work_centre_id)
);

-- Work Order Assignments Table
CREATE TABLE work_order_assignments (
    assignment_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    assigned_by BIGINT NOT NULL,
    reassigned BOOLEAN DEFAULT FALSE,
    reassignment_reason TEXT,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (agent_id) REFERENCES users(user_id),
    FOREIGN KEY (assigned_by) REFERENCES users(user_id)
);

-- Anomalies Table
CREATE TABLE anomalies (
    anomaly_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1'
);

-- Work Order Execution Table
CREATE TABLE work_order_execution (
    execution_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT,
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    gps_lat DECIMAL(10,8),
    gps_long DECIMAL(11,8),
    parts_used TEXT,
    synced BOOLEAN DEFAULT FALSE,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (agent_id) REFERENCES users(user_id)
);

-- Work Order Execution Anomalies Table
CREATE TABLE work_order_execution_anomalies (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    execution_id BIGINT NOT NULL,
    anomaly_id BIGINT NOT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    FOREIGN KEY (execution_id) REFERENCES work_order_execution(execution_id) ON DELETE CASCADE,
    FOREIGN KEY (anomaly_id) REFERENCES anomalies(anomaly_id) ON DELETE RESTRICT
);

-- Work Order Acknowledgments Table
CREATE TABLE work_order_acknowledgments (
    ack_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT,
    customer_signature TEXT,
    remarks TEXT,
    acknowledged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (agent_id) REFERENCES users(user_id)
);

-- Work Order Notes Table
CREATE TABLE work_order_notes (
    note_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    added_by BIGINT NOT NULL,
    note TEXT,
    note_type ENUM('FIELD_AGENT', 'REVIEWER', 'SYSTEM') DEFAULT 'FIELD_AGENT',
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (added_by) REFERENCES users(user_id)
);

-- Work Order Status Logs Table
CREATE TABLE work_order_status_logs (
    status_log_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    previous_status VARCHAR(50),
    new_status VARCHAR(50),
    changed_by BIGINT,
    reason TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (changed_by) REFERENCES users(user_id)
);

-- Work Order Attachments Table
CREATE TABLE work_order_attachments (
    attachment_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    file_path TEXT,
    file_name VARCHAR(255),
    type ENUM('IMAGE', 'DOCUMENT', 'SIGNATURE'),
    uploaded_by BIGINT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
);

-- Work Order Feedback Table
CREATE TABLE work_order_feedback (
    feedback_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    feedback_by BIGINT,
    feedback_type ENUM('REVIEW', 'REWORK_REQUEST', 'COMMENT'),
    comments TEXT,
    feedback_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (feedback_by) REFERENCES users(user_id)
);

-- Work Order Reassign Table
CREATE TABLE work_order_reassign (
    reassign_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    reason TEXT,
    reassign_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (agent_id) REFERENCES users(user_id)
);

-- Work Order Data Capture Table
CREATE TABLE work_order_data_capture (
    capture_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    request_type ENUM('NEW_CONNECTION', 'SUBSCRIPTION', 'COMPLAINT', 'TERMINATION', 'OTHER') NOT NULL,
    agent_id BIGINT NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    offline_captured BOOLEAN DEFAULT FALSE,
    synced BOOLEAN DEFAULT TRUE,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (agent_id) REFERENCES users(user_id)
);

-- New Connection Capture Table
CREATE TABLE new_connection_capture (
    capture_id BIGINT PRIMARY KEY,
    installation_checklist TEXT,
    initial_meter_reading DECIMAL(10,2),
    customer_contact VARCHAR(100),
    customer_address TEXT,
    id_proof_type VARCHAR(50),
    id_proof_number VARCHAR(100),
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Subscription Capture Table
CREATE TABLE subscription_capture (
    capture_id BIGINT PRIMARY KEY,
    plan_name VARCHAR(100),
    billing_cycle VARCHAR(50),
    service_features TEXT,
    discount_applied BOOLEAN DEFAULT FALSE,
    activation_status ENUM('PENDING', 'ACTIVE', 'FAILED') DEFAULT 'PENDING',
    customer_preferences TEXT,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Complaint Capture Table
CREATE TABLE complaint_capture (
    capture_id BIGINT PRIMARY KEY,
    issue_description TEXT,
    affected_service VARCHAR(100),
    resolution_status ENUM('UNRESOLVED', 'IN_PROGRESS', 'RESOLVED') DEFAULT 'UNRESOLVED',
    attempted_fixes TEXT,
    evidence_url TEXT,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Termination Capture Table
CREATE TABLE termination_capture (
    capture_id BIGINT PRIMARY KEY,
    final_meter_reading DECIMAL(10,2),
    disconnect_status ENUM('DISCONNECTED', 'PENDING') DEFAULT 'PENDING',
    termination_reason TEXT,
    service_end_date DATE,
    final_billing_info TEXT,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Other Request Capture Table
CREATE TABLE other_request_capture (
    capture_id BIGINT PRIMARY KEY,
    custom_notes TEXT,
    additional_instructions TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Data Capture Validation Logs Table
CREATE TABLE data_capture_validation_logs (
    validation_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    capture_id BIGINT NOT NULL,
    field_name VARCHAR(100),
    error_message TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    
    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Offline Capture Queue Table
CREATE TABLE offline_capture_queue (
    queue_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    capture_id BIGINT NOT NULL,
    device_id VARCHAR(100),
    sync_status ENUM('PENDING', 'SYNCED', 'FAILED') DEFAULT 'PENDING',
    last_attempt TIMESTAMP,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- Picture Metadata Table
CREATE TABLE picture_metadata (
    picture_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_order_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    request_type ENUM('NEW_CONNECTION', 'SUBSCRIPTION', 'COMPLAINT', 'TERMINATION', 'OTHER') NOT NULL,
    meter_number VARCHAR(100),
    supply_point_number VARCHAR(100),
    cycle VARCHAR(50),
    location VARCHAR(255),
    file_name VARCHAR(255),
    file_path TEXT NOT NULL,
    file_format VARCHAR(10), -- JPG, PNG, etc.
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (agent_id) REFERENCES users(user_id)
);

-- Picture Qualification Table
CREATE TABLE picture_qualification (
    qualification_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    picture_id BIGINT NOT NULL,
    qualified_by BIGINT NOT NULL,
    qualification_status ENUM('OK', 'NOT_OK') NOT NULL,
    comments TEXT,
    qualified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (picture_id) REFERENCES picture_metadata(picture_id) ON DELETE CASCADE,
    FOREIGN KEY (qualified_by) REFERENCES users(user_id)
);

-- OCR Techniques Table
CREATE TABLE ocr_techniques (
    ocr_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    technique_name VARCHAR(100) NOT NULL UNIQUE, -- e.g., 'Tesseract', 'Google Vision', 'Azure OCR'
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1'
);

-- Picture Annotation Table
CREATE TABLE picture_annotation (
    annotation_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    picture_id BIGINT NOT NULL,
    annotated_by BIGINT NOT NULL,
    ocr_id BIGINT NOT NULL, -- FK to OCR techniques
    annotation_data TEXT, -- e.g., extracted text, coordinates, etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (picture_id) REFERENCES picture_metadata(picture_id) ON DELETE CASCADE,
    FOREIGN KEY (annotated_by) REFERENCES users(user_id),
    FOREIGN KEY (ocr_id) REFERENCES ocr_techniques(ocr_id) ON DELETE RESTRICT
);

-- Picture Download Log Table
CREATE TABLE picture_download_log (
    download_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    picture_id BIGINT, -- NULL for batch download
    downloaded_by BIGINT NOT NULL,
    is_batch BOOLEAN DEFAULT FALSE,
    format VARCHAR(10), -- JPG, PNG, ZIP, etc.
    downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (picture_id) REFERENCES picture_metadata(picture_id) ON DELETE SET NULL,
    FOREIGN KEY (downloaded_by) REFERENCES users(user_id)
);

-- Picture Quality Metrics Table
CREATE TABLE picture_quality_metrics (
    metric_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    agent_id BIGINT NOT NULL,
    total_uploaded INT DEFAULT 0,
    total_ok INT DEFAULT 0,
    total_not_ok INT DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (agent_id) REFERENCES users(user_id)
);

-- Subcontractor Companies Table
CREATE TABLE subcontractor_companies (
    subcontractor_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    company_name VARCHAR(255) NOT NULL,
    telephone VARCHAR(50),
    email VARCHAR(150),
    description TEXT,
    location VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1'
);

-- Work Centre Subcontractors Table
CREATE TABLE work_centre_subcontractors (
    assignment_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    work_centre_id BIGINT NOT NULL,
    subcontractor_id BIGINT NOT NULL,
    assigned_by BIGINT NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (work_centre_id) REFERENCES work_centres(work_centre_id),
    FOREIGN KEY (subcontractor_id) REFERENCES subcontractor_companies(subcontractor_id),
    FOREIGN KEY (assigned_by) REFERENCES users(user_id)
);

-- Re-enable foreign key checks
SET FOREIGN_KEY_CHECKS = 1; 


ALTER TABLE device_assignments MODIFY COLUMN role ENUM('TECHNICIAN', 'SUPERVISOR', 'MANAGER', 'ADMIN', 'WAREHOUSE', 'AGENT') NULL;
ALTER TYPE devicestatus ADD VALUE 'BLOCKED';
ALTER TYPE devicestatus ADD VALUE 'ACTIVE';
ALTER TYPE devicestatus ADD VALUE 'BLOCKED';
ALTER TYPE devicestatus ADD VALUE 'DEACTIVATED';
-- AUTH TOKENS
-- ==============================
CREATE TABLE auth_tokens (
    token_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    token_type VARCHAR(50) DEFAULT 'bearer',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP NULL,
    device_info JSON,
    ip_address VARCHAR(45),
    status VARCHAR(50) DEFAULT 'ACTIVE',
    active TINYINT(1) DEFAULT 1,

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ==============================
-- NOTIFICATION HISTORY
-- ==============================
CREATE TABLE notification_history (
    history_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    notification_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    channel ENUM('EMAIL', 'SMS', 'PUSH', 'IN_APP') NOT NULL,
    status ENUM('PENDING', 'SENT', 'FAILED', 'DELIVERED', 'READ') DEFAULT 'PENDING',
    error_message TEXT,
    delivery_timestamp TIMESTAMP NULL,
    delivery_metadata JSON,
    retry_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active TINYINT(1) DEFAULT 1,

    FOREIGN KEY (notification_id) REFERENCES user_notifications(notification_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- ==============================
-- USER ACTIVITY LOGS
-- ==============================
CREATE TABLE user_activity_logs (
    log_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    activity_type VARCHAR(100) NOT NULL,
    activity_details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'SUCCESS',
    active TINYINT(1) DEFAULT 1,

    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- ==============================
-- USER NOTIFICATION PREFERENCES
-- ==============================
CREATE TABLE user_notification_preferences (
    preference_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    notification_type VARCHAR(100) NOT NULL,
    channel ENUM('EMAIL', 'SMS', 'PUSH', 'IN_APP') NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    frequency VARCHAR(50) DEFAULT 'IMMEDIATE',
    quiet_hours_start TIME NULL,
    quiet_hours_end TIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    active TINYINT(1) DEFAULT 1,

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE KEY uq_user_notification_pref (user_id, notification_type, channel)
);
