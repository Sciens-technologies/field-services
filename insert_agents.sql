-- Insert new agent users
INSERT INTO users (user_id, username, email, password_hash, activated, created_by, created_at)
VALUES
  (101, 'agent1', 'agent1@example.com', 'hashedpassword1', TRUE, 'system', NOW()),
  (102, 'agent2', 'agent2@example.com', 'hashedpassword2', TRUE, 'system', NOW()),
  (103, 'agent3', 'agent3@example.com', 'hashedpassword3', TRUE, 'system', NOW());

-- Assign the 'agent' role (role_id=2) to each user
INSERT INTO user_roles (user_id, role_id, active, created_at)
VALUES
  (101, 2, TRUE, NOW()),
  (102, 2, TRUE, NOW()),
  (103, 2, TRUE, NOW()); 