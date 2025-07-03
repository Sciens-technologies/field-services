-- users and profile module tables 

-- ==============================
-- USERS TABLE
-- ==============================
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

-- ==============================
-- ROLES TABLE
-- ==============================
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
CREATE TABLE `notification_templates` (
  `template_id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `template_key` varchar(50) NOT NULL,
  `subject` varchar(255) NOT NULL,
  `content` text NOT NULL,
  `notification_type` enum('EMAIL','SMS','PUSH','IN_APP') NOT NULL,
  `active` tinyint(1) DEFAULT '1',
  	status VARCHAR(75) NULL DEFAULT NULL,
   `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`template_id`),
  UNIQUE KEY `template_key` (`template_key`)
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
    work_centre_id BIGINT, -- NEW
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
	 active TINYINT(1) NULL DEFAULT '1',
	 
    FOREIGN KEY (created_by) REFERENCES users(user_id),
    FOREIGN KEY (work_centre_id) REFERENCES work_centres(work_centre_id) -- NEW
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
-- First create the ENUM types
CREATE TYPE feedback_category AS ENUM ('BUG', 'FEATURE', 'IMPROVEMENT', 'OTHER');
CREATE TYPE feedback_priority AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'URGENT');
CREATE TYPE feedback_status AS ENUM ('PENDING', 'IN_REVIEW', 'RESOLVED', 'CLOSED');

CREATE TYPE ticket_category AS ENUM ('TECHNICAL', 'BILLING', 'ACCOUNT', 'SERVICE', 'OTHER');
CREATE TYPE ticket_priority AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'URGENT');
CREATE TYPE ticket_status AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED');

-- Create SystemFeedback table
CREATE TABLE system_feedback (
    feedback_id VARCHAR(75) PRIMARY KEY,
    user_id VARCHAR(75) NOT NULL,
    category feedback_category NOT NULL,
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    priority feedback_priority DEFAULT 'MEDIUM',
    status feedback_status DEFAULT 'PENDING',
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    active BOOLEAN DEFAULT TRUE,
    
    FOREIGN KEY (user_id) REFERENCES users(uuid)
);

-- Create SupportTicket table
CREATE TABLE support_tickets (
    ticket_id VARCHAR(75) PRIMARY KEY,
    user_id VARCHAR(75) NOT NULL,
    category ticket_category NOT NULL,
    subject VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    priority ticket_priority DEFAULT 'MEDIUM',
    status ticket_status DEFAULT 'OPEN',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    active BOOLEAN DEFAULT TRUE,
    
    FOREIGN KEY (user_id) REFERENCES users(uuid)
);
- ==============================
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
  ALTER TABLE work_order_assignments ADD COLUMN subject VARCHAR(255);
  
  CREATE TABLE work_order_templates (
    template_id BIGSERIAL PRIMARY KEY,
    work_order_type VARCHAR(10) NOT NULL,
    form_type VARCHAR(100) NOT NULL,
    template JSONB NOT NULL,
    version VARCHAR(20) DEFAULT '1.0',
    active BOOLEAN DEFAULT TRUE,
    created_by BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS work_order_forms (
    form_id BIGSERIAL PRIMARY KEY,
    work_order_id BIGINT NOT NULL,
    work_order_type VARCHAR(10) NOT NULL,
    template_id BIGINT NOT NULL,
    status VARCHAR(75) DEFAULT 'PENDING',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (work_order_id) REFERENCES work_orders(work_order_id),
    FOREIGN KEY (template_id) REFERENCES work_order_templates(template_id)
);

CREATE TABLE work_order_formdata (
    formdata_id BIGSERIAL PRIMARY KEY,
    form_id BIGINT NOT NULL,
    session_id VARCHAR(75) NOT NULL UNIQUE,
    data JSONB NOT NULL,
    progress DECIMAL(5,2) DEFAULT 0.00,
    status VARCHAR(20) DEFAULT 'IN_PROGRESS',
    current_step INTEGER DEFAULT 1,
    form_type VARCHAR(10) DEFAULT 'ZDEV',
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (form_id) REFERENCES work_order_forms(form_id)
);

CREATE TABLE work_order_form_steps (
    step_id BIGSERIAL PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    step_number INTEGER NOT NULL,
    step_title VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    data JSONB,
    validation_status BOOLEAN DEFAULT FALSE,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id)
);

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
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id),
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
);

CREATE TABLE work_order_form_sessions (
    session_id VARCHAR(75) PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    agent_id BIGINT NOT NULL,
    device_info JSON,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    sync_status VARCHAR(20) DEFAULT 'PENDING',
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id),
    FOREIGN KEY (agent_id) REFERENCES users(user_id)
);

CREATE TABLE work_order_form_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    action VARCHAR(20) NOT NULL,
    old_data JSONB,
    new_data JSONB,
    changed_by BIGINT NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id),
    FOREIGN KEY (changed_by) REFERENCES users(user_id)
);

CREATE TABLE work_order_form_validation_logs (
    validation_id BIGSERIAL PRIMARY KEY,
    formdata_id BIGINT NOT NULL,
    step_number INTEGER NOT NULL,
    field_name VARCHAR(100) NOT NULL,
    error_message TEXT,
    is_valid BOOLEAN DEFAULT FALSE,
    validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (formdata_id) REFERENCES work_order_formdata(formdata_id)
);
ALTER TABLE work_order_templates
    ALTER COLUMN work_order_type TYPE VARCHAR(50);
    
ALTER TABLE work_order_forms
    ALTER COLUMN work_order_type TYPE VARCHAR(50);

ALTER TABLE work_order_formdata
ALTER COLUMN form_type TYPE VARCHAR(32);

ALTER TABLE work_order_form_steps
ADD COLUMN form_id INTEGER;

ALTER TABLE work_order_form_steps
ADD COLUMN form_id INTEGER REFERENCES work_order_forms(form_id);


-- 1. Add the template_id column (nullable)
ALTER TABLE work_orders ADD COLUMN template_id BIGINT;
ALTER TABLE work_orders
  ADD CONSTRAINT fk_work_orders_template_id
  FOREIGN KEY (template_id) REFERENCES work_order_templates(template_id)
  ON DELETE SET NULL;

-- For ZDEV (Device Relevant)
UPDATE work_order_templates
SET category = 'ZDEV'
WHERE form_type IN (
  'LV Device Installation Form',
  'MV HV Device Installation Form',
  'LV Device Removal Form',
  'MV HV Device Removal',
  'LV device replacement form',
  'CUI Replacement',
  'MV HV Meter Replacement Form',
  'Circuit Breaker Replacement Form',
  'Voltage Transf Replacement Form',
  'Current Transf Replacement Form',
  'Modem Replacement Form',
  'Device Location Change Form',
  'Device Inspection Form',
  'Device Control Form',
  'LV Device normalization form',
  'MV Device Normalization Form',
  'Technical Disconnection Form',
  'Technical Reconnection Form',
  'Conversion Prepaid Postpaid Form',
  'Conversion Pospad Prepaid Form'
);

-- For ZNEW (New Connection Relevant)
UPDATE work_order_templates
SET category = 'ZNEW'
WHERE form_type IN (
  'Survey Order LV Form',
  'Survey Order MV HV Form',
  'Provisioning Order LV Form',
  'Provisioning Order MV HV Form'
);

-- For ZDDR (Dunning Relevant)
UPDATE work_order_templates
SET category = 'ZDDR'
WHERE form_type IN (
  'Technical Disconnection Form',
  'Technical Reconnection Form'
);

   UPDATE devices SET device_name = serial_number;