-- users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(100),
    password_hash TEXT NOT NULL,
    role_id INTEGER REFERENCES roles(id),
    status VARCHAR(20) CHECK (status IN ('active', 'inactive', 'blocked')) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notification_preferences JSONB DEFAULT '{}'::jsonb,
    blocked_at TIMESTAMP,
    block_reason TEXT
    work_center_id = Column(Integer, ForeignKey("work_centers.id"), nullable=True)
);


-- roles table
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);
CREATE TABLE user_activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    actor_id INTEGER NOT NULL,
    action VARCHAR(50),
    details TEXT,
    timestamp TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-- permissions table
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT
);

-- role_permissions table
CREATE TABLE role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE
);


-- auth_tokens table
CREATE TABLE auth_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    access_token TEXT NOT NULL UNIQUE,
    refresh_token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    ip_address VARCHAR(100),
    device_info TEXT
);

-- devices table
CREATE TABLE devices (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    device_type VARCHAR(100),
    serial_number VARCHAR(100) UNIQUE,
    location TEXT,
    gps_latitude DECIMAL(10, 6),
    gps_longitude DECIMAL(10, 6),
    manager_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- work_orders table (we can use state machine)
CREATE TABLE work_orders (
    id SERIAL PRIMARY KEY,
    title VARCHAR(150),
    description TEXT,
    status VARCHAR(30) CHECK (status IN ('pending', 'approved', 'rejected', 'in_progress', 'completed')),
    complition_pct 
    manager_id INTEGER REFERENCES users(id),
    agent_id INTEGER REFERENCES users(id),
    device_id INTEGER REFERENCES devices(id),
    target_complition_date TIMESTAMP,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- work_order_comments table
CREATE TABLE work_order_comments (
    id SERIAL PRIMARY KEY,
    work_order_id INTEGER REFERENCES work_orders(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    comment_type VARCHAR(30), CHECK (comment_type IN ('comment', 'feedback')) 
    comment_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- work_order_forms table
CREATE TABLE work_order_forms (
    id SERIAL PRIMARY KEY,
    work_order_id INTEGER REFERENCES work_orders(id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL,
    form_data JSONB,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- work_order_status_history table
CREATE TABLE work_order_status_history (
    id SERIAL PRIMARY KEY,
    work_order_id INTEGER REFERENCES work_orders(id) ON DELETE CASCADE,
    status VARCHAR(30),
    changed_by INTEGER REFERENCES users(id),
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    comment TEXT
);

-- agent_activity_logs table
CREATE TABLE agent_activity_logs (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES users(id),
    login_time TIMESTAMP,
    logout_time TIMESTAMP,
    ip_address VARCHAR(100),
    device_info TEXT
);

-- notifications table
CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(150),
    message TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- password_reset_tokens table
CREATE TABLE password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE feedback (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    subject VARCHAR(255),
    message TEXT,
    status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE user_notification_preference (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    preferences JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add work_center_id to users
CREATE TABLE work_centers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    location VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE users ADD COLUMN work_center_id INTEGER REFERENCES work_centers(id);
CREATE TABLE notification_history (
    id INT PRIMARY KEY,
    user_id INT,
    type VARCHAR(50),
    event VARCHAR(50),
    message TEXT,
    status VARCHAR(20),
    sent_at TIMESTAMP
);