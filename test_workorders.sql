-- Insert 15 work orders (COMPLETED, CANCELLED, REJECTED) and assignments for user_id 18

-- COMPLETED
INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
) VALUES
  (20001, NULL, 'WO-COMP-1', 'Completed Order 1', 'Test completed order 1', 'TYPE1', 'CUST1', 'Customer 1', 'Location 1', 0, 0, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', 'HIGH', 'COMPLETED', 4, 1, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', TRUE, 1021),
  (20002, NULL, 'WO-COMP-2', 'Completed Order 2', 'Test completed order 2', 'TYPE1', 'CUST2', 'Customer 2', 'Location 2', 0, 0, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', 'MEDIUM', 'COMPLETED', 4, 1, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', TRUE, 1025),
  (20003, NULL, 'WO-COMP-3', 'Completed Order 3', 'Test completed order 3', 'TYPE1', 'CUST3', 'Customer 3', 'Location 3', 0, 0, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', 'LOW', 'COMPLETED', 4, 1, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', TRUE, 1021),
  (20004, NULL, 'WO-COMP-4', 'Completed Order 4', 'Test completed order 4', 'TYPE1', 'CUST4', 'Customer 4', 'Location 4', 0, 0, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', 'HIGH', 'COMPLETED', 4, 1, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', TRUE, 1025),
  (20005, NULL, 'WO-COMP-5', 'Completed Order 5', 'Test completed order 5', 'TYPE1', 'CUST5', 'Customer 5', 'Location 5', 0, 0, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', 'MEDIUM', 'COMPLETED', 4, 1, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', TRUE, 1021),
  (20016, NULL, 'WO-COMP-ZDEV-1', 'Completed ZDEV Order 1', 'Test completed ZDEV order 1', 'TYPEZ', 'CUSTZ1', 'Customer Z1', 'Location Z1', 0, 0, NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', 'HIGH', 'COMPLETED', 4, 1, NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', TRUE, 1003),
  (20017, NULL, 'WO-COMP-ZDEV-2', 'Completed ZDEV Order 2', 'Test completed ZDEV order 2', 'TYPEZ', 'CUSTZ2', 'Customer Z2', 'Location Z2', 0, 0, NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', 'MEDIUM', 'COMPLETED', 4, 1, NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', TRUE, 1003);

-- CANCELLED
INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
) VALUES
  (20006, NULL, 'WO-CANC-1', 'Cancelled Order 1', 'Test cancelled order 1', 'TYPE2', 'CUST6', 'Customer 6', 'Location 6', 0, 0, NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', 'LOW', 'CANCELLED', 4, 1, NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', TRUE, 1025),
  (20007, NULL, 'WO-CANC-2', 'Cancelled Order 2', 'Test cancelled order 2', 'TYPE2', 'CUST7', 'Customer 7', 'Location 7', 0, 0, NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', 'HIGH', 'CANCELLED', 4, 1, NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', TRUE, 1021),
  (20008, NULL, 'WO-CANC-3', 'Cancelled Order 3', 'Test cancelled order 3', 'TYPE2', 'CUST8', 'Customer 8', 'Location 8', 0, 0, NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', 'MEDIUM', 'CANCELLED', 4, 1, NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', TRUE, 1025),
  (20009, NULL, 'WO-CANC-4', 'Cancelled Order 4', 'Test cancelled order 4', 'TYPE2', 'CUST9', 'Customer 9', 'Location 9', 0, 0, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 days', 'LOW', 'CANCELLED', 4, 1, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 days', TRUE, 1021),
  (20010, NULL, 'WO-CANC-5', 'Cancelled Order 5', 'Test cancelled order 5', 'TYPE2', 'CUST10', 'Customer 10', 'Location 10', 0, 0, NOW() - INTERVAL '1 days', NOW(), 'HIGH', 'CANCELLED', 4, 1, NOW() - INTERVAL '1 days', NOW(), TRUE, 1025);

-- REJECTED
INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
) VALUES
  (20011, NULL, 'WO-REJ-1', 'Rejected Order 1', 'Test rejected order 1', 'TYPE3', 'CUST11', 'Customer 11', 'Location 11', 0, 0, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', 'MEDIUM', 'REJECTED', 4, 1, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', TRUE, 1021),
  (20012, NULL, 'WO-REJ-2', 'Rejected Order 2', 'Test rejected order 2', 'TYPE3', 'CUST12', 'Customer 12', 'Location 12', 0, 0, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', 'LOW', 'REJECTED', 4, 1, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', TRUE, 1025),
  (20013, NULL, 'WO-REJ-3', 'Rejected Order 3', 'Test rejected order 3', 'TYPE3', 'CUST13', 'Customer 13', 'Location 13', 0, 0, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', 'HIGH', 'REJECTED', 4, 1, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', TRUE, 1021),
  (20014, NULL, 'WO-REJ-4', 'Rejected Order 4', 'Test rejected order 4', 'TYPE3', 'CUST14', 'Customer 14', 'Location 14', 0, 0, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', 'MEDIUM', 'REJECTED', 4, 1, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', TRUE, 1025),
  (20015, NULL, 'WO-REJ-5', 'Rejected Order 5', 'Test rejected order 5', 'TYPE3', 'CUST15', 'Customer 15', 'Location 15', 0, 0, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', 'LOW', 'REJECTED', 4, 1, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', TRUE, 1021),
  (20018, NULL, 'WO-REJ-ZDEV-1', 'Rejected ZDEV Order 1', 'Test rejected ZDEV order 1', 'TYPEZ', 'CUSTZ3', 'Customer Z3', 'Location Z3', 0, 0, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 days', 'LOW', 'REJECTED', 4, 1, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 days', TRUE, 1003),
  (20019, NULL, 'WO-REJ-ZDEV-2', 'Rejected ZDEV Order 2', 'Test rejected ZDEV order 2', 'TYPEZ', 'CUSTZ4', 'Customer Z4', 'Location Z4', 0, 0, NOW() - INTERVAL '1 days', NOW(), 'HIGH', 'REJECTED', 4, 1, NOW() - INTERVAL '1 days', NOW(), TRUE, 1003);

-- Assignments for each work order
INSERT INTO work_order_assignments (
  work_order_id, agent_id, assigned_by, reassigned, assigned_at, status, active, updated_at
) VALUES
  (20001, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20002, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20003, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20004, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20005, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20006, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20007, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20008, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20009, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20010, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20011, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20012, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20013, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20014, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20015, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20016, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20017, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20018, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (20019, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()); 




  -- Insert into work_orders table (COMPLETED work orders)
INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
) VALUES
  (30001, NULL, 'WO-COMP-1', 'Completed Order 1', 'Test completed order 1', 'TYPE1', 'CUST1', 'Customer 1', 'Location 1', 0.0, 0.0, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', 'HIGH', 'COMPLETED', 4, 1, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', TRUE, 1021),
  (30002, NULL, 'WO-COMP-2', 'Completed Order 2', 'Test completed order 2', 'TYPE1', 'CUST2', 'Customer 2', 'Location 2', 0.0, 0.0, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', 'MEDIUM', 'COMPLETED', 4, 1, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', TRUE, 1025),
  (30003, NULL, 'WO-COMP-3', 'Completed Order 3', 'Test completed order 3', 'TYPE1', 'CUST3', 'Customer 3', 'Location 3', 0.0, 0.0, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', 'LOW', 'COMPLETED', 4, 1, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', TRUE, 1021),
  (30004, NULL, 'WO-COMP-4', 'Completed Order 4', 'Test completed order 4', 'TYPE1', 'CUST4', 'Customer 4', 'Location 4', 0.0, 0.0, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', 'HIGH', 'COMPLETED', 4, 1, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', TRUE, 1025),
  (30005, NULL, 'WO-COMP-5', 'Completed Order 5', 'Test completed order 5', 'TYPE1', 'CUST5', 'Customer 5', 'Location 5', 0.0, 0.0, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', 'MEDIUM', 'COMPLETED', 4, 1, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', TRUE, 1021);

-- Insert into work_orders table (CANCELLED work orders)
INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
) VALUES
  (30006, NULL, 'WO-CANC-1', 'Cancelled Order 1', 'Test cancelled order 1', 'TYPE2', 'CUST6', 'Customer 6', 'Location 6', 0.0, 0.0, NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', 'LOW', 'CANCELLED', 4, 1, NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 days', TRUE, 1025),
  (30007, NULL, 'WO-CANC-2', 'Cancelled Order 2', 'Test cancelled order 2', 'TYPE2', 'CUST7', 'Customer 7', 'Location 7', 0.0, 0.0, NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', 'HIGH', 'CANCELLED', 4, 1, NOW() - INTERVAL '4 days', NOW() - INTERVAL '3 days', TRUE, 1021),
  (30008, NULL, 'WO-CANC-3', 'Cancelled Order 3', 'Test cancelled order 3', 'TYPE2', 'CUST8', 'Customer 8', 'Location 8', 0.0, 0.0, NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', 'MEDIUM', 'CANCELLED', 4, 1, NOW() - INTERVAL '3 days', NOW() - INTERVAL '2 days', TRUE, 1025),
  (30009, NULL, 'WO-CANC-4', 'Cancelled Order 4', 'Test cancelled order 4', 'TYPE2', 'CUST9', 'Customer 9', 'Location 9', 0. DO, 0.0, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', 'LOW', 'CANCELLED', 4, 1, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', TRUE, 1021),
  (30010, NULL, 'WO-CANC-5', 'Cancelled Order 5', 'Test cancelled order 5', 'TYPE2', 'CUST10', 'Customer 10', 'Location 10', 0.0, 0.0, NOW() - INTERVAL '1 day', NOW(), 'HIGH', 'CANCELLED', 4, 1, NOW() - INTERVAL '1 day', NOW(), TRUE, 1025);

-- Insert into work_orders table (REJECTED work orders)
INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
) VALUES
  (30011, NULL, 'WO-REJ-1', 'Rejected Order 1', 'Test rejected order 1', 'TYPE3', 'CUST11', 'Customer 11', 'Location 11', 0.0, 0.0, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', 'MEDIUM', 'REJECTED', 4, 1, NOW() - INTERVAL '10 days', NOW() - INTERVAL '9 days', TRUE, 1021),
  (30012, NULL, 'WO-REJ-2', 'Rejected Order 2', 'Test rejected order 2', 'TYPE3', 'CUST12', 'Customer 12', 'Location 12', 0.0, 0.0, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', 'LOW', 'REJECTED', 4, 1, NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 days', TRUE, 1025),
  (30013, NULL, 'WO-REJ-3', 'Rejected Order 3', 'Test rejected order 3', 'TYPE3', 'CUST13', 'Customer 13', 'Location 13', 0.0, 0.0, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', 'HIGH', 'REJECTED', 4, 1, NOW() - INTERVAL '8 days', NOW() - INTERVAL '7 days', TRUE, 1021),
  (30014, NULL, 'WO-REJ-4', 'Rejected Order 4', 'Test rejected order 4', 'TYPE3', 'CUST14', 'Customer 14', 'Location 14', 0.0, 0.0, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', 'MEDIUM', 'REJECTED', 4, 1, NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days', TRUE, 1025),
  (30015, NULL, 'WO-REJ-5', 'Rejected Order 5', 'Test rejected order 5', 'TYPE3', 'CUST15', 'Customer 15', 'Location 15', 0.0, 0.0, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', 'LOW', 'REJECTED', 4, 1, NOW() - INTERVAL '6 days', NOW() - INTERVAL '5 days', TRUE, 1021);

-- Insert into work_order_assignments table
INSERT INTO work_order_assignments (
  work_order_id, agent_id, assigned_by, reassigned, assigned_at, status, active, updated_at
) VALUES
  (30001, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30002, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30003, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30004, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30005, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30006, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30007, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30008, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30009, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30010, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30011, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30012, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30013, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30014, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW()),
  (30015, 4, 4, FALSE, NOW(), 'ACCEPTED', TRUE, NOW());