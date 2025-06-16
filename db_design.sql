-- users and profile module tables 

-- ==============================
-- USERS TABLE
-- ==============================
CREATE TYPE user_status_enum AS ENUM ('ACTIVE', 'INACTIVE', 'BLOCKED', 'DEACTIVATED');
CREATE TYPE work_order_status_enum AS ENUM ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'REJECTED');
CREATE TYPE notification_type_enum AS ENUM ('EMAIL', 'SMS', 'PUSH', 'IN_APP');
CREATE TYPE request_type_enum AS ENUM ('NEW_CONNECTION', 'SUBSCRIPTION', 'COMPLAINT', 'TERMINATION', 'OTHER');

CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,
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
    status user_status_enum DEFAULT 'ACTIVE',

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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT ux_users_username UNIQUE (username),
    CONSTRAINT ux_users_email UNIQUE (email)
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ==============================
-- ROLES TABLE
-- ==============================
CREATE TABLE roles (
    role_id BIGSERIAL PRIMARY KEY,
    role_name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75) DEFAULT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified_by VARCHAR(50),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ==============================
-- user_roles TABLE
-- ==============================
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

-- ==============================
-- PERMISSIONS
-- ==============================
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

-- ==============================
-- LOGS & NOTIFICATIONS
-- ==============================
CREATE TABLE notification_templates (
  template_id BIGSERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  template_key VARCHAR(50) NOT NULL,
  subject VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  notification_type notification_type_enum NOT NULL,
  active BOOLEAN DEFAULT TRUE,
  status VARCHAR(75),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY template_key (template_key)
);

-- artifact_notification_events
CREATE TABLE `artifact_notification_events` (
  `event_id` BIGINT NOT NULL AUTO_INCREMENT,
  `template_id` BIGINT NOT NULL,
  `initiated_by` BIGINT NULL, -- user/admin/system who triggered it
  `notification_scope` ENUM('INDIVIDUAL', 'GROUP', 'SERVICETYPE') NOT NULL DEFAULT 'INDIVIDUAL',
  `target_type` ENUM('USER', 'ROLE', 'SEGMENT') NULL, -- Optional
  `target_value` VARCHAR(255) NULL, -- JSON or comma-separated target IDs if GROUP
  `custom_metadata` JSON DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`event_id`),
  FOREIGN KEY (`template_id`) REFERENCES `notification_templates` (`template_id`),
  FOREIGN KEY (`initiated_by`) REFERENCES `users` (`user_id`)
);

-- user_notifications
CREATE TABLE `user_notifications` (
  `notification_id` BIGINT NOT NULL AUTO_INCREMENT,
  -- Either direct user_id or group-based delivery
  `user_id` BIGINT NULL, -- for direct notification
  `target_type` ENUM('ROLE', 'SEGMENT', 'GROUP') NULL, -- for group-based
  `target_value` VARCHAR(255) NULL, -- e.g., 'FIELD_AGENT', 'ZONE_1', etc.

  `template_id` BIGINT DEFAULT NULL,
  `title` VARCHAR(255) NOT NULL,
  `message` TEXT NOT NULL,
  `status` ENUM('PENDING','SENT','FAILED','READ') DEFAULT 'PENDING',
  `metadata` JSON DEFAULT NULL,
  `created_at` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  `sent_at` DATETIME DEFAULT NULL,
  `read_at` DATETIME DEFAULT NULL,

  PRIMARY KEY (`notification_id`),
  KEY `user_id` (`user_id`),
  KEY `template_id` (`template_id`),

  CONSTRAINT `user_notifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`),
  CONSTRAINT `user_notifications_ibfk_2` FOREIGN KEY (`template_id`) REFERENCES `notification_templates` (`template_id`),

  -- XOR logic: either user_id OR (target_type + target_value)
  CHECK (
    (user_id IS NOT NULL AND target_type IS NULL AND target_value IS NULL) OR
    (user_id IS NULL AND target_type IS NOT NULL AND target_value IS NOT NULL)
  )
);



-- ==============================
-- AUTHENTICATION SUPPORT
-- ==============================
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


-- DEVICE MANAGEMENT module tables 

-- ==============================
-- DEVICE MANAGEMENT
-- ==============================
-- device
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


-- device_artifacts
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



-- device_assignments
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

-- device_registration_confirmations
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

-- device_status_audit
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

-- device_health_logs
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




CREATE TABLE resource_request_modules (
    module_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    module_key VARCHAR(50) NOT NULL UNIQUE, -- e.g., 'DEVICE', 'WORK_ORDER'
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE resource_types (
    resource_type_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    type_key VARCHAR(50) NOT NULL UNIQUE, -- e.g., 'MATERIAL', 'TOOL'
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

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

-- work order module tables 
-- already this tables hirarchy have in eneo side for your understing purpose we creating this tables 
-- 1. work_centres I need to improve 
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

-- 2. work_orders
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
    priority VARCHAR(10) DEFAULT 'MEDIUM',
    status work_order_status_enum DEFAULT 'PENDING',
    created_by BIGINT REFERENCES users(user_id),
    work_centre_id BIGINT REFERENCES work_centres(work_centre_id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

-- 3. work_order_assignments
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

-- 4. anomalies (Master Table)

CREATE TABLE anomalies (
    anomaly_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1'
);
-- 5. work_order_execution
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

-- 6. work_order_execution_anomalies
CREATE TABLE work_order_execution_anomalies (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    execution_id BIGINT NOT NULL,
    anomaly_id BIGINT NOT NULL,
	 active TINYINT(1) NULL DEFAULT '1',
    FOREIGN KEY (execution_id) REFERENCES work_order_execution(execution_id) ON DELETE CASCADE,
    FOREIGN KEY (anomaly_id) REFERENCES anomalies(anomaly_id) ON DELETE RESTRICT
);

-- 7. work_order_acknowledgments
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

-- 8. work_order_notes
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

-- 9. work_order_status_logs
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

-- 10. work_order_attachments
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

-- 11. work_order_feedback
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

-- 12. work_order_reassign
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


-- data captured module tables

-- 1. work_order_data_capture
CREATE TABLE work_order_data_capture (
    capture_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT REFERENCES work_orders(work_order_id) NOT NULL,
    request_type request_type_enum NOT NULL,
    agent_id BIGINT REFERENCES users(user_id) NOT NULL,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    offline_captured BOOLEAN DEFAULT FALSE,
    synced BOOLEAN DEFAULT TRUE,
    status VARCHAR(75),
    active BOOLEAN DEFAULT TRUE
);

-- 2. new_connection_capture
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


-- 3. subscription_capture
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


-- 4. complaint_capture
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


-- 5. termination_capture
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


-- 6. other_request_capture
CREATE TABLE other_request_capture (
    capture_id BIGINT PRIMARY KEY,
    custom_notes TEXT,
    additional_instructions TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- 7. data_capture_validation_logs
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


-- 8. offline_capture_queue
CREATE TABLE offline_capture_queue (
    queue_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    capture_id BIGINT NOT NULL,
    device_id VARCHAR(100),
    sync_status ENUM('PENDING', 'SYNCED', 'FAILED') DEFAULT 'PENDING',
    last_attempt TIMESTAMP,
    active TINYINT(1) NULL DEFAULT '1',

    FOREIGN KEY (capture_id) REFERENCES work_order_data_capture(capture_id) ON DELETE CASCADE
);

-- picture module tables 

-- 1. picture_metadata
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


-- 2. picture_qualification
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

-- 3. ocr_techniques
CREATE TABLE ocr_techniques (
    ocr_id BIGINT PRIMARY KEY AUTO_INCREMENT,
    technique_name VARCHAR(100) NOT NULL UNIQUE, -- e.g., 'Tesseract', 'Google Vision', 'Azure OCR'
    description TEXT,
    status VARCHAR(75) NULL DEFAULT NULL,
    active TINYINT(1) NULL DEFAULT '1'
);

-- 4. picture_annotation
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

-- 5. picture_download_log
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


-- 6. picture_quality_metrics
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

-- admin modules tables 

-- 1. subcontractor_companies
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

-- 2. work_centre_subcontractors
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

-- ==============================
-- MISSING TABLES
-- ==============================

-- user_notification_preferences
CREATE TABLE user_notification_preferences (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(user_id) UNIQUE,
    email_enabled BOOLEAN DEFAULT TRUE,
    sms_enabled BOOLEAN DEFAULT FALSE,
    push_enabled BOOLEAN DEFAULT TRUE,
    in_app_enabled BOOLEAN DEFAULT TRUE,
    quiet_hours_start VARCHAR(5),  -- Format: "HH:MM"
    quiet_hours_end VARCHAR(5),    -- Format: "HH:MM"
    timezone VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- notification_history
CREATE TABLE notification_history (
    history_id BIGSERIAL PRIMARY KEY,
    notification_id BIGINT REFERENCES user_notifications(notification_id),
    status VARCHAR(20) NOT NULL,  -- SENT, FAILED, READ
    error_message TEXT,
    delivery_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    delivery_metadata JSONB
);

-- auth_tokens
CREATE TABLE auth_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(user_id) ON DELETE CASCADE,
    access_token TEXT NOT NULL UNIQUE,
    refresh_token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    ip_address VARCHAR(100),
    device_info TEXT
);