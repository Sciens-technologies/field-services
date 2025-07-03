-- Insert 20 Work Centers for Field Services Application
-- This script inserts diverse work centers with realistic data

INSERT INTO work_centres (
    name, 
    registration_number, 
    tax_id, 
    contact_email, 
    contact_phone, 
    website_url, 
    address_line1, 
    address_line2, 
    city, 
    state, 
    postal_code, 
    country, 
    status, 
    active, 
    created_at, 
    updated_at
) VALUES 
-- Urban Work Centers
('Metro Power Solutions', 'WC001-MPS', 'TAX-MPS-2024-001', 'info@metropowersolutions.com', '+1-555-0101', 'www.metropowersolutions.com', '123 Main Street', 'Suite 100', 'New York', 'NY', '10001', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Downtown Electrical Services', 'WC002-DES', 'TAX-DES-2024-002', 'contact@downtownelectrical.com', '+1-555-0102', 'www.downtownelectrical.com', '456 Broadway Avenue', 'Floor 3', 'Los Angeles', 'CA', '90001', 'USA', 'ACTIVE', true, NOW(), NOW()),

('City Grid Maintenance', 'WC003-CGM', 'TAX-CGM-2024-003', 'service@citygridmaintenance.com', '+1-555-0103', 'www.citygridmaintenance.com', '789 Oak Street', 'Building A', 'Chicago', 'IL', '60601', 'USA', 'ACTIVE', true, NOW(), NOW()),

-- Suburban Work Centers
('Suburban Power Systems', 'WC004-SPS', 'TAX-SPS-2024-004', 'info@suburbanpowersystems.com', '+1-555-0104', 'www.suburbanpowersystems.com', '321 Elm Road', 'Unit 5', 'Houston', 'TX', '77001', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Valley Electrical Co.', 'WC005-VEC', 'TAX-VEC-2024-005', 'contact@valleyelectrical.com', '+1-555-0105', 'www.valleyelectrical.com', '654 Pine Avenue', 'Suite 200', 'Phoenix', 'AZ', '85001', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Riverside Power Solutions', 'WC006-RPS', 'TAX-RPS-2024-006', 'service@riversidepower.com', '+1-555-0106', 'www.riversidepower.com', '987 River Drive', 'Building B', 'Philadelphia', 'PA', '19101', 'USA', 'ACTIVE', true, NOW(), NOW()),

-- Industrial Work Centers
('Industrial Power Systems', 'WC007-IPS', 'TAX-IPS-2024-007', 'info@industrialpowersystems.com', '+1-555-0107', 'www.industrialpowersystems.com', '147 Industrial Blvd', 'Warehouse 3', 'Detroit', 'MI', '48201', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Factory Grid Services', 'WC008-FGS', 'TAX-FGS-2024-008', 'contact@factorygridservices.com', '+1-555-0108', 'www.factorygridservices.com', '258 Factory Lane', 'Unit 10', 'San Antonio', 'TX', '78201', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Manufacturing Power Co.', 'WC009-MPC', 'TAX-MPC-2024-009', 'service@manufacturingpower.com', '+1-555-0109', 'www.manufacturingpower.com', '369 Production Road', 'Building C', 'San Diego', 'CA', '92101', 'USA', 'ACTIVE', true, NOW(), NOW()),

-- Rural Work Centers
('Rural Power Solutions', 'WC010-RPS', 'TAX-RPS-2024-010', 'info@ruralpowersolutions.com', '+1-555-0110', 'www.ruralpowersolutions.com', '741 Country Road', 'Farm Building', 'Dallas', 'TX', '75201', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Farmland Electrical', 'WC011-FE', 'TAX-FE-2024-011', 'contact@farmlandelectrical.com', '+1-555-0111', 'www.farmlandelectrical.com', '852 Rural Highway', 'Barn 2', 'San Jose', 'CA', '95101', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Agricultural Power Systems', 'WC012-APS', 'TAX-APS-2024-012', 'service@agriculturalpower.com', '+1-555-0112', 'www.agriculturalpower.com', '963 Farm Lane', 'Shed A', 'Austin', 'TX', '73301', 'USA', 'ACTIVE', true, NOW(), NOW()),

-- Coastal Work Centers
('Coastal Power Solutions', 'WC013-CPS', 'TAX-CPS-2024-013', 'info@coastalpowersolutions.com', '+1-555-0113', 'www.coastalpowersolutions.com', '159 Beach Boulevard', 'Pier 1', 'Jacksonville', 'FL', '32099', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Harbor Electrical Services', 'WC014-HES', 'TAX-HES-2024-014', 'contact@harborelectrical.com', '+1-555-0114', 'www.harborelectrical.com', '753 Marina Drive', 'Dock 3', 'Fort Worth', 'TX', '76101', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Port Power Systems', 'WC015-PPS', 'TAX-PPS-2024-015', 'service@portpowersystems.com', '+1-555-0115', 'www.portpowersystems.com', '456 Harbor Road', 'Terminal 2', 'Columbus', 'OH', '43201', 'USA', 'ACTIVE', true, NOW(), NOW()),

-- Mountain Work Centers
('Mountain Power Co.', 'WC016-MPC', 'TAX-MPC-2024-016', 'info@mountainpowerco.com', '+1-555-0116', 'www.mountainpowerco.com', '357 Summit Street', 'Cabin 1', 'Charlotte', 'NC', '28201', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Highland Electrical', 'WC017-HE', 'TAX-HE-2024-017', 'contact@highlandelectrical.com', '+1-555-0117', 'www.highlandelectrical.com', '468 Peak Avenue', 'Lodge B', 'San Francisco', 'CA', '94101', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Alpine Power Solutions', 'WC018-APS', 'TAX-APS-2024-018', 'service@alpinepowersolutions.com', '+1-555-0118', 'www.alpinepowersolutions.com', '579 Ridge Road', 'Station 3', 'Indianapolis', 'IN', '46201', 'USA', 'ACTIVE', true, NOW(), NOW()),

-- Desert Work Centers
('Desert Power Systems', 'WC019-DPS', 'TAX-DPS-2024-019', 'info@desertpowersystems.com', '+1-555-0119', 'www.desertpowersystems.com', '681 Oasis Drive', 'Building D', 'Seattle', 'WA', '98101', 'USA', 'ACTIVE', true, NOW(), NOW()),

('Arid Electrical Co.', 'WC020-AEC', 'TAX-AEC-2024-020', 'contact@aridelectrical.com', '+1-555-0120', 'www.aridelectrical.com', '792 Sand Street', 'Unit 7', 'Denver', 'CO', '80201', 'USA', 'ACTIVE', true, NOW(), NOW());

-- Verify the insert
SELECT 
    work_centre_id,
    name,
    registration_number,
    city,
    state,
    status,
    active
FROM work_centres 
ORDER BY work_centre_id;




INSERT INTO work_order_templates (template_id, work_order_type, form_type, template, version, active, created_by, created_at, updated_at)
VALUES
  (1001, 'INSTALLATION', 'LV Device Installation Form', '{}', '1.0', TRUE, 1, NOW(), NOW()),
  (1002, 'INSTALLATION', 'HV Device Installation Form', '{}', '1.0', TRUE, 1, NOW(), NOW());

INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
)
VALUES
  (2001, NULL, 'WO-1001', 'Install LV Device 1', 'Install LV device at customer site 1', 'INSTALLATION', 'CUST001', 'Customer 1', 'Location 1', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2002, NULL, 'WO-1002', 'Install LV Device 2', 'Install LV device at customer site 2', 'INSTALLATION', 'CUST002', 'Customer 2', 'Location 2', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2003, NULL, 'WO-1003', 'Install LV Device 3', 'Install LV device at customer site 3', 'INSTALLATION', 'CUST003', 'Customer 3', 'Location 3', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2004, NULL, 'WO-1004', 'Install LV Device 4', 'Install LV device at customer site 4', 'INSTALLATION', 'CUST004', 'Customer 4', 'Location 4', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2005, NULL, 'WO-1005', 'Install LV Device 5', 'Install LV device at customer site 5', 'INSTALLATION', 'CUST005', 'Customer 5', 'Location 5', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2006, NULL, 'WO-1006', 'Install HV Device 1', 'Install HV device at customer site 6', 'INSTALLATION', 'CUST006', 'Customer 6', 'Location 6', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2007, NULL, 'WO-1007', 'Install HV Device 2', 'Install HV device at customer site 7', 'INSTALLATION', 'CUST007', 'Customer 7', 'Location 7', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2008, NULL, 'WO-1008', 'Install HV Device 3', 'Install HV device at customer site 8', 'INSTALLATION', 'CUST008', 'Customer 8', 'Location 8', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2009, NULL, 'WO-1009', 'Install HV Device 4', 'Install HV device at customer site 9', 'INSTALLATION', 'CUST009', 'Customer 9', 'Location 9', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2010, NULL, 'WO-1010', 'Install HV Device 5', 'Install HV device at customer site 10', 'INSTALLATION', 'CUST010', 'Customer 10', 'Location 10', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2011, NULL, 'WO-1011', 'Install LV Device 6', 'Install LV device at customer site 11', 'INSTALLATION', 'CUST011', 'Customer 11', 'Location 11', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2012, NULL, 'WO-1012', 'Install LV Device 7', 'Install LV device at customer site 12', 'INSTALLATION', 'CUST012', 'Customer 12', 'Location 12', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2013, NULL, 'WO-1013', 'Install LV Device 8', 'Install LV device at customer site 13', 'INSTALLATION', 'CUST013', 'Customer 13', 'Location 13', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2014, NULL, 'WO-1014', 'Install LV Device 9', 'Install LV device at customer site 14', 'INSTALLATION', 'CUST014', 'Customer 14', 'Location 14', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2015, NULL, 'WO-1015', 'Install LV Device 10', 'Install LV device at customer site 15', 'INSTALLATION', 'CUST015', 'Customer 15', 'Location 15', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (2016, NULL, 'WO-1016', 'Install HV Device 6', 'Install HV device at customer site 16', 'INSTALLATION', 'CUST016', 'Customer 16', 'Location 16', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2017, NULL, 'WO-1017', 'Install HV Device 7', 'Install HV device at customer site 17', 'INSTALLATION', 'CUST017', 'Customer 17', 'Location 17', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2018, NULL, 'WO-1018', 'Install HV Device 8', 'Install HV device at customer site 18', 'INSTALLATION', 'CUST018', 'Customer 18', 'Location 18', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2019, NULL, 'WO-1019', 'Install HV Device 9', 'Install HV device at customer site 19', 'INSTALLATION', 'CUST019', 'Customer 19', 'Location 19', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002),
  (2020, NULL, 'WO-1020', 'Install HV Device 10', 'Install HV device at customer site 20', 'INSTALLATION', 'CUST020', 'Customer 20', 'Location 20', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1002);



  INSERT INTO work_order_templates (
  template_id, work_order_type, form_type, template, version, active, created_by, created_at, updated_at
) VALUES (
  2001,
  'INSTALLATION',
  'LV Device Installation Form',
  '{
  "steps": [
    {
      "step_number": 1,
      "step_title": "Work Order General informations (display mode)",
      "fields": [
        {"name": "bp_name", "label": "BP name", "type": "text", "display_only": true},
        {"name": "telephone_number", "label": "Telephone number", "type": "text", "display_only": true},
        {"name": "location_description", "label": "Location description", "type": "text", "display_only": true},
        {"name": "connection_object_address", "label": "Connection object address", "type": "text", "display_only": true},
        {"name": "activation_token", "label": "Activation token (if prepaid meter)", "type": "text", "display_only": true}
      ]
    },
    {
      "step_number": 2,
      "step_title": "Meter informations",
      "fields": [
        {"name": "meter_type", "label": "Meter type", "type": "text"},
        {"name": "meter_number", "label": "Meter number", "type": "text"},
        {"name": "modem", "label": "Modem (if smart meter)", "type": "text"},
        {"name": "meter_reads", "label": "Meter reads", "type": "text"}
      ]
    },
    {
      "step_number": 3,
      "step_title": "CIU informations",
      "fields": [
        {"name": "ciu_number", "label": "CIU number (If prepaid meter)", "type": "text"}
      ]
    },
    {
      "step_number": 4,
      "step_title": "Circuit breaker informations",
      "fields": [
        {"name": "circuit_breaker_number", "label": "Circuit breaker number", "type": "text"},
        {"name": "circuit_breaker_rating", "label": "Circuit breaker rating", "type": "text"}
      ]
    },
    {
      "step_number": 5,
      "step_title": "Transformer informations",
      "fields": [
        {"name": "transformers_number", "label": "Transformers number", "type": "text"}
      ]
    },
    {
      "step_number": 6,
      "step_title": "Seals informations",
      "fields": [
        {"name": "meter_box_seal_number", "label": "Meter box seal number", "type": "text"},
        {"name": "meter_seal_number", "label": "Meter seal number", "type": "text"}
      ]
    },
    {
      "step_number": 7,
      "step_title": "Request informations",
      "fields": [
        {"name": "installation_activity", "label": "Installation activity", "type": "text"},
        {"name": "installation_standing", "label": "Installation standing", "type": "text"},
        {"name": "subcontractor", "label": "Subcontractor (display)", "type": "text", "display_only": true},
        {"name": "field_agent_name", "label": "Field agent name (display)", "type": "text", "display_only": true},
        {"name": "field_agent_id", "label": "Field agent ID (display)", "type": "text", "display_only": true},
        {"name": "completion_date", "label": "Completion date (auto-populate)", "type": "date", "auto_populate": true},
        {"name": "observations", "label": "Observations", "type": "textarea"},
        {"name": "connection_object_address", "label": "Connection object address", "type": "text"},
        {"name": "gis_coordinates", "label": "GIS coordinates", "type": "text"},
        {"name": "attach_meter_picture", "label": "Attach meter picture", "type": "file"},
        {"name": "attach_commitment_form", "label": "Attach commitment form", "type": "file"},
        {"name": "customer_phone_number", "label": "Customer phone number", "type": "text"}
      ]
    }
  ]
}',
  '1.0',
  TRUE,
  1,
  NOW(),
  NOW()
);






UPDATE work_order_templates
SET template = '{
  "steps": [
    {
      "step_number": 1,
      "step_title": "Work Order General informations (display mode)",
      "fields": [
        {"name": "bp_name", "label": "BP name", "type": "text", "display_only": true},
        {"name": "telephone_number", "label": "Telephone number", "type": "text", "display_only": true},
        {"name": "location_description", "label": "Location description", "type": "text", "display_only": true},
        {"name": "connection_object_address", "label": "Connection object address", "type": "text", "display_only": true},
        {"name": "activation_token", "label": "Activation token (if prepaid meter)", "type": "text", "display_only": true}
      ]
    },
    {
      "step_number": 2,
      "step_title": "Meter informations",
      "fields": [
        {"name": "meter_type", "label": "Meter type", "type": "text"},
        {"name": "meter_number", "label": "Meter number", "type": "text"},
        {"name": "modem", "label": "Modem (if smart meter)", "type": "text"},
        {"name": "meter_reads", "label": "Meter reads", "type": "text"}
      ]
    },
    {
      "step_number": 3,
      "step_title": "CIU informations",
      "fields": [
        {"name": "ciu_number", "label": "CIU number (If prepaid meter)", "type": "text"}
      ]
    },
    {
      "step_number": 4,
      "step_title": "Circuit breaker informations",
      "fields": [
        {"name": "circuit_breaker_number", "label": "Circuit breaker number", "type": "text"},
        {"name": "circuit_breaker_rating", "label": "Circuit breaker rating", "type": "text"}
      ]
    },
    {
      "step_number": 5,
      "step_title": "Transformer informations",
      "fields": [
        {"name": "transformers_number", "label": "Transformers number", "type": "text"}
      ]
    },
    {
      "step_number": 6,
      "step_title": "Seals informations",
      "fields": [
        {"name": "meter_box_seal_number", "label": "Meter box seal number", "type": "text"},
        {"name": "meter_seal_number", "label": "Meter seal number", "type": "text"}
      ]
    },
    {
      "step_number": 7,
      "step_title": "Request informations",
      "fields": [
        {"name": "installation_activity", "label": "Installation activity", "type": "text"},
        {"name": "installation_standing", "label": "Installation standing", "type": "text"},
        {"name": "subcontractor", "label": "Subcontractor (display)", "type": "text", "display_only": true},
        {"name": "field_agent_name", "label": "Field agent name (display)", "type": "text", "display_only": true},
        {"name": "field_agent_id", "label": "Field agent ID (display)", "type": "text", "display_only": true},
        {"name": "completion_date", "label": "Completion date (auto-populate)", "type": "date", "auto_populate": true},
        {"name": "observations", "label": "Observations", "type": "textarea"},
        {"name": "connection_object_address", "label": "Connection object address", "type": "text"},
        {"name": "gis_coordinates", "label": "GIS coordinates", "type": "text"},
        {"name": "attach_meter_picture", "label": "Attach meter picture", "type": "file"},
        {"name": "attach_commitment_form", "label": "Attach commitment form", "type": "file"},
        {"name": "customer_phone_number", "label": "Customer phone number", "type": "text"}
      ]
    }
  ]
}'
WHERE template_id = (SELECT template_id FROM work_orders WHERE work_order_id = 2001);


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