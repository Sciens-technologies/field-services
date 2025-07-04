ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(128);
UPDATE work_order_templates SET category = 'ZDEV' WHERE template_id = 1001;
UPDATE work_order_templates SET category = 'ZDEV' WHERE template_id = 1002;
INSERT INTO work_order_templates (
  template_id, work_order_type, form_type, template, version, active, created_by, created_at, updated_at, category
) VALUES
(1003, 'REMOVAL', 'LV Device Removal Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1004, 'REMOVAL', 'MV/HV Device Removal', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1005, 'REPLACEMENT', 'LV device replacement form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1006, 'REPLACEMENT', 'CUI Replacement', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1007, 'REPLACEMENT', 'MV HV Meter Replacement Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1008, 'REPLACEMENT', 'Circuit Breaker Replacement Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1009, 'REPLACEMENT', 'Voltage Transf Replacement Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1010, 'REPLACEMENT', 'Current Transf Replacement Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1011, 'REPLACEMENT', 'Modem Replacement Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1012, 'CHANGE', 'Device Location Change Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1013, 'INSPECTION', 'Device Inspection Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1014, 'CONTROL', 'Device Control Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1015, 'NORMALIZATION', 'LV Device normalization form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1016, 'NORMALIZATION', 'MV Device Normalization Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1017, 'DISCONNECTION', 'Technical Disconnection Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1018, 'RECONNECTION', 'Technical Reconnection Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1019, 'CONVERSION', 'Conversion Prepaid Postpaid Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1020, 'CONVERSION', 'Conversion Pospad Prepaid Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDEV'),
(1021, 'SURVEY', 'Survey Order LV Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZNEW'),
(1022, 'SURVEY', 'Survey Order MV HV Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZNEW'),
(1023, 'PROVISIONING', 'Provisioning Order LV Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZNEW'),
(1024, 'PROVISIONING', 'Provisioning Order MV HV Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZNEW'),
(1025, 'DISCONNECTION', 'Technical Disconnection Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDDR'),
(1026, 'RECONNECTION', 'Technical Reconnection Form', '{}', '1.0', TRUE, 1, NOW(), NOW(), 'ZDDR');

INSERT INTO work_orders (
  work_order_id, device_id, wo_number, title, description, work_order_type, customer_id, customer_name,
  location, latitude, longitude, scheduled_date, due_date, priority, status, created_by, work_centre_id,
  created_at, updated_at, active, template_id
)
VALUES
  (1021, NULL, 'WO-1021', 'Install LV Device 21', 'Install LV device at customer site 21', 'INSTALLATION', 'CUST021', 'Customer 21', 'Location 21', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1001),
  (1022, NULL, 'WO-1022', 'Install LV Device 22', 'Install LV device at customer site 22', 'INSTALLATION', 'CUST022', 'Customer 22', 'Location 22', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 2, NOW(), NOW(), TRUE, 1001),
  (1023, NULL, 'WO-1023', 'Install LV Device 23', 'Install LV device at customer site 23', 'INSTALLATION', 'CUST023', 'Customer 23', 'Location 23', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 3, NOW(), NOW(), TRUE, 1001),
  (1024, NULL, 'WO-1024', 'Install LV Device 24', 'Install LV device at customer site 24', 'INSTALLATION', 'CUST024', 'Customer 24', 'Location 24', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 4, NOW(), NOW(), TRUE, 1001),
  (1025, NULL, 'WO-1025', 'Install LV Device 25', 'Install LV device at customer site 25', 'INSTALLATION', 'CUST025', 'Customer 25', 'Location 25', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 5, NOW(), NOW(), TRUE, 1001),
  (1031, NULL, 'WO-1031', 'Install MV/HV Device 31', 'Install MV/HV device at customer site 31', 'INSTALLATION', 'CUST031', 'Customer 31', 'Location 31', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 6, NOW(), NOW(), TRUE, 1002),
  (1032, NULL, 'WO-1032', 'Install MV/HV Device 32', 'Install MV/HV device at customer site 32', 'INSTALLATION', 'CUST032', 'Customer 32', 'Location 32', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 7, NOW(), NOW(), TRUE, 1002),
  (1033, NULL, 'WO-1033', 'Install MV/HV Device 33', 'Install MV/HV device at customer site 33', 'INSTALLATION', 'CUST033', 'Customer 33', 'Location 33', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 8, NOW(), NOW(), TRUE, 1002),
  (1034, NULL, 'WO-1034', 'Install MV/HV Device 34', 'Install MV/HV device at customer site 34', 'INSTALLATION', 'CUST034', 'Customer 34', 'Location 34', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 9, NOW(), NOW(), TRUE, 1002),
  (1035, NULL, 'WO-1035', 'Install MV/HV Device 35', 'Install MV/HV device at customer site 35', 'INSTALLATION', 'CUST035', 'Customer 35', 'Location 35', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 10, NOW(), NOW(), TRUE, 1002),
  (1041, NULL, 'WO-1041', 'Remove LV Device 41', 'Remove LV device at customer site 41', 'REMOVAL', 'CUST041', 'Customer 41', 'Location 41', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 11, NOW(), NOW(), TRUE, 1003),
  (1042, NULL, 'WO-1042', 'Remove LV Device 42', 'Remove LV device at customer site 42', 'REMOVAL', 'CUST042', 'Customer 42', 'Location 42', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 12, NOW(), NOW(), TRUE, 1003),
  (1043, NULL, 'WO-1043', 'Remove LV Device 43', 'Remove LV device at customer site 43', 'REMOVAL', 'CUST043', 'Customer 43', 'Location 43', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 13, NOW(), NOW(), TRUE, 1003),
  (1044, NULL, 'WO-1044', 'Remove LV Device 44', 'Remove LV device at customer site 44', 'REMOVAL', 'CUST044', 'Customer 44', 'Location 44', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 14, NOW(), NOW(), TRUE, 1003),
  (1045, NULL, 'WO-1045', 'Remove LV Device 45', 'Remove LV device at customer site 45', 'REMOVAL', 'CUST045', 'Customer 45', 'Location 45', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 15, NOW(), NOW(), TRUE, 1003),
  (1051, NULL, 'WO-1051', 'Remove MV/HV Device 51', 'Remove MV/HV device at customer site 51', 'REMOVAL', 'CUST051', 'Customer 51', 'Location 51', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 16, NOW(), NOW(), TRUE, 1004),
  (1052, NULL, 'WO-1052', 'Remove MV/HV Device 52', 'Remove MV/HV device at customer site 52', 'REMOVAL', 'CUST052', 'Customer 52', 'Location 52', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 17, NOW(), NOW(), TRUE, 1004),
  (1053, NULL, 'WO-1053', 'Remove MV/HV Device 53', 'Remove MV/HV device at customer site 53', 'REMOVAL', 'CUST053', 'Customer 53', 'Location 53', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 18, NOW(), NOW(), TRUE, 1004),
  (1054, NULL, 'WO-1054', 'Remove MV/HV Device 54', 'Remove MV/HV device at customer site 54', 'REMOVAL', 'CUST054', 'Customer 54', 'Location 54', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 19, NOW(), NOW(), TRUE, 1004),
  (1055, NULL, 'WO-1055', 'Remove MV/HV Device 55', 'Remove MV/HV device at customer site 55', 'REMOVAL', 'CUST055', 'Customer 55', 'Location 55', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 20, NOW(), NOW(), TRUE, 1004),
  (1061, NULL, 'WO-1061', 'Replace LV Device 61', 'Replace LV device at customer site 61', 'REPLACEMENT', 'CUST061', 'Customer 61', 'Location 61', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1005),
  (1062, NULL, 'WO-1062', 'Replace LV Device 62', 'Replace LV device at customer site 62', 'REPLACEMENT', 'CUST062', 'Customer 62', 'Location 62', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 2, NOW(), NOW(), TRUE, 1005),
  (1063, NULL, 'WO-1063', 'Replace LV Device 63', 'Replace LV device at customer site 63', 'REPLACEMENT', 'CUST063', 'Customer 63', 'Location 63', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 3, NOW(), NOW(), TRUE, 1005),
  (1064, NULL, 'WO-1064', 'Replace LV Device 64', 'Replace LV device at customer site 64', 'REPLACEMENT', 'CUST064', 'Customer 64', 'Location 64', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 4, NOW(), NOW(), TRUE, 1005),
  (1065, NULL, 'WO-1065', 'Replace LV Device 65', 'Replace LV device at customer site 65', 'REPLACEMENT', 'CUST065', 'Customer 65', 'Location 65', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 5, NOW(), NOW(), TRUE, 1005),
  (1071, NULL, 'WO-1071', 'CUI Replacement 71', 'CUI replacement at customer site 71', 'REPLACEMENT', 'CUST071', 'Customer 71', 'Location 71', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 6, NOW(), NOW(), TRUE, 1006),
  (1072, NULL, 'WO-1072', 'CUI Replacement 72', 'CUI replacement at customer site 72', 'REPLACEMENT', 'CUST072', 'Customer 72', 'Location 72', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 7, NOW(), NOW(), TRUE, 1006),
  (1073, NULL, 'WO-1073', 'CUI Replacement 73', 'CUI replacement at customer site 73', 'REPLACEMENT', 'CUST073', 'Customer 73', 'Location 73', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 8, NOW(), NOW(), TRUE, 1006),
  (1074, NULL, 'WO-1074', 'CUI Replacement 74', 'CUI replacement at customer site 74', 'REPLACEMENT', 'CUST074', 'Customer 74', 'Location 74', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 9, NOW(), NOW(), TRUE, 1006),
  (1075, NULL, 'WO-1075', 'CUI Replacement 75', 'CUI replacement at customer site 75', 'REPLACEMENT', 'CUST075', 'Customer 75', 'Location 75', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 10, NOW(), NOW(), TRUE, 1006),
  (1081, NULL, 'WO-1081', 'Replace MV HV Meter 81', 'Replace MV HV meter at customer site 81', 'REPLACEMENT', 'CUST081', 'Customer 81', 'Location 81', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 11, NOW(), NOW(), TRUE, 1007),
  (1082, NULL, 'WO-1082', 'Replace MV HV Meter 82', 'Replace MV HV meter at customer site 82', 'REPLACEMENT', 'CUST082', 'Customer 82', 'Location 82', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 12, NOW(), NOW(), TRUE, 1007),
  (1083, NULL, 'WO-1083', 'Replace MV HV Meter 83', 'Replace MV HV meter at customer site 83', 'REPLACEMENT', 'CUST083', 'Customer 83', 'Location 83', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 13, NOW(), NOW(), TRUE, 1007),
  (1084, NULL, 'WO-1084', 'Replace MV HV Meter 84', 'Replace MV HV meter at customer site 84', 'REPLACEMENT', 'CUST084', 'Customer 84', 'Location 84', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 14, NOW(), NOW(), TRUE, 1007),
  (1085, NULL, 'WO-1085', 'Replace MV HV Meter 85', 'Replace MV HV meter at customer site 85', 'REPLACEMENT', 'CUST085', 'Customer 85', 'Location 85', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 15, NOW(), NOW(), TRUE, 1007),
  (1091, NULL, 'WO-1091', 'Replace Circuit Breaker 91', 'Replace circuit breaker at customer site 91', 'REPLACEMENT', 'CUST091', 'Customer 91', 'Location 91', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 16, NOW(), NOW(), TRUE, 1008),
  (1092, NULL, 'WO-1092', 'Replace Circuit Breaker 92', 'Replace circuit breaker at customer site 92', 'REPLACEMENT', 'CUST092', 'Customer 92', 'Location 92', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 17, NOW(), NOW(), TRUE, 1008),
  (1093, NULL, 'WO-1093', 'Replace Circuit Breaker 93', 'Replace circuit breaker at customer site 93', 'REPLACEMENT', 'CUST093', 'Customer 93', 'Location 93', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 18, NOW(), NOW(), TRUE, 1008),
  (1094, NULL, 'WO-1094', 'Replace Circuit Breaker 94', 'Replace circuit breaker at customer site 94', 'REPLACEMENT', 'CUST094', 'Customer 94', 'Location 94', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 19, NOW(), NOW(), TRUE, 1008),
  (1095, NULL, 'WO-1095', 'Replace Circuit Breaker 95', 'Replace circuit breaker at customer site 95', 'REPLACEMENT', 'CUST095', 'Customer 95', 'Location 95', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 20, NOW(), NOW(), TRUE, 1008),
  (1101, NULL, 'WO-1101', 'Replace Voltage Transf 101', 'Replace voltage transf at customer site 101', 'REPLACEMENT', 'CUST101', 'Customer 101', 'Location 101', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1009),
  (1102, NULL, 'WO-1102', 'Replace Voltage Transf 102', 'Replace voltage transf at customer site 102', 'REPLACEMENT', 'CUST102', 'Customer 102', 'Location 102', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 2, NOW(), NOW(), TRUE, 1009),
  (1103, NULL, 'WO-1103', 'Replace Voltage Transf 103', 'Replace voltage transf at customer site 103', 'REPLACEMENT', 'CUST103', 'Customer 103', 'Location 103', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 3, NOW(), NOW(), TRUE, 1009),
  (1104, NULL, 'WO-1104', 'Replace Voltage Transf 104', 'Replace voltage transf at customer site 104', 'REPLACEMENT', 'CUST104', 'Customer 104', 'Location 104', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 4, NOW(), NOW(), TRUE, 1009),
  (1105, NULL, 'WO-1105', 'Replace Voltage Transf 105', 'Replace voltage transf at customer site 105', 'REPLACEMENT', 'CUST105', 'Customer 105', 'Location 105', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 5, NOW(), NOW(), TRUE, 1009),
  (1111, NULL, 'WO-1111', 'Replace Current Transf 111', 'Replace current transf at customer site 111', 'REPLACEMENT', 'CUST111', 'Customer 111', 'Location 111', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 6, NOW(), NOW(), TRUE, 1010),
  (1112, NULL, 'WO-1112', 'Replace Current Transf 112', 'Replace current transf at customer site 112', 'REPLACEMENT', 'CUST112', 'Customer 112', 'Location 112', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 7, NOW(), NOW(), TRUE, 1010),
  (1113, NULL, 'WO-1113', 'Replace Current Transf 113', 'Replace current transf at customer site 113', 'REPLACEMENT', 'CUST113', 'Customer 113', 'Location 113', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 8, NOW(), NOW(), TRUE, 1010),
  (1114, NULL, 'WO-1114', 'Replace Current Transf 114', 'Replace current transf at customer site 114', 'REPLACEMENT', 'CUST114', 'Customer 114', 'Location 114', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 9, NOW(), NOW(), TRUE, 1010),
  (1115, NULL, 'WO-1115', 'Replace Current Transf 115', 'Replace current transf at customer site 115', 'REPLACEMENT', 'CUST115', 'Customer 115', 'Location 115', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 10, NOW(), NOW(), TRUE, 1010),
  (1121, NULL, 'WO-1121', 'Replace Modem 121', 'Replace modem at customer site 121', 'REPLACEMENT', 'CUST121', 'Customer 121', 'Location 121', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 11, NOW(), NOW(), TRUE, 1011),
  (1122, NULL, 'WO-1122', 'Replace Modem 122', 'Replace modem at customer site 122', 'REPLACEMENT', 'CUST122', 'Customer 122', 'Location 122', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 12, NOW(), NOW(), TRUE, 1011),
  (1123, NULL, 'WO-1123', 'Replace Modem 123', 'Replace modem at customer site 123', 'REPLACEMENT', 'CUST123', 'Customer 123', 'Location 123', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 13, NOW(), NOW(), TRUE, 1011),
  (1124, NULL, 'WO-1124', 'Replace Modem 124', 'Replace modem at customer site 124', 'REPLACEMENT', 'CUST124', 'Customer 124', 'Location 124', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 14, NOW(), NOW(), TRUE, 1011),
  (1125, NULL, 'WO-1125', 'Replace Modem 125', 'Replace modem at customer site 125', 'REPLACEMENT', 'CUST125', 'Customer 125', 'Location 125', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 15, NOW(), NOW(), TRUE, 1011),
  (1131, NULL, 'WO-1131', 'Device Location Change 131', 'Device location change at customer site 131', 'CHANGE', 'CUST131', 'Customer 131', 'Location 131', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 16, NOW(), NOW(), TRUE, 1012),
  (1132, NULL, 'WO-1132', 'Device Location Change 132', 'Device location change at customer site 132', 'CHANGE', 'CUST132', 'Customer 132', 'Location 132', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 17, NOW(), NOW(), TRUE, 1012),
  (1133, NULL, 'WO-1133', 'Device Location Change 133', 'Device location change at customer site 133', 'CHANGE', 'CUST133', 'Customer 133', 'Location 133', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 18, NOW(), NOW(), TRUE, 1012),
  (1134, NULL, 'WO-1134', 'Device Location Change 134', 'Device location change at customer site 134', 'CHANGE', 'CUST134', 'Customer 134', 'Location 134', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 19, NOW(), NOW(), TRUE, 1012),
  (1135, NULL, 'WO-1135', 'Device Location Change 135', 'Device location change at customer site 135', 'CHANGE', 'CUST135', 'Customer 135', 'Location 135', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 20, NOW(), NOW(), TRUE, 1012),
  (1141, NULL, 'WO-1141', 'Device Inspection 141', 'Device inspection at customer site 141', 'INSPECTION', 'CUST141', 'Customer 141', 'Location 141', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1013),
  (1142, NULL, 'WO-1142', 'Device Inspection 142', 'Device inspection at customer site 142', 'INSPECTION', 'CUST142', 'Customer 142', 'Location 142', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 2, NOW(), NOW(), TRUE, 1013),
  (1143, NULL, 'WO-1143', 'Device Inspection 143', 'Device inspection at customer site 143', 'INSPECTION', 'CUST143', 'Customer 143', 'Location 143', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 3, NOW(), NOW(), TRUE, 1013),
  (1144, NULL, 'WO-1144', 'Device Inspection 144', 'Device inspection at customer site 144', 'INSPECTION', 'CUST144', 'Customer 144', 'Location 144', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 4, NOW(), NOW(), TRUE, 1013),
  (1145, NULL, 'WO-1145', 'Device Inspection 145', 'Device inspection at customer site 145', 'INSPECTION', 'CUST145', 'Customer 145', 'Location 145', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 5, NOW(), NOW(), TRUE, 1013),
  (1151, NULL, 'WO-1151', 'Device Control 151', 'Device control at customer site 151', 'CONTROL', 'CUST151', 'Customer 151', 'Location 151', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 6, NOW(), NOW(), TRUE, 1014),
  (1152, NULL, 'WO-1152', 'Device Control 152', 'Device control at customer site 152', 'CONTROL', 'CUST152', 'Customer 152', 'Location 152', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 7, NOW(), NOW(), TRUE, 1014),
  (1153, NULL, 'WO-1153', 'Device Control 153', 'Device control at customer site 153', 'CONTROL', 'CUST153', 'Customer 153', 'Location 153', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 8, NOW(), NOW(), TRUE, 1014),
  (1154, NULL, 'WO-1154', 'Device Control 154', 'Device control at customer site 154', 'CONTROL', 'CUST154', 'Customer 154', 'Location 154', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 9, NOW(), NOW(), TRUE, 1014),
  (1155, NULL, 'WO-1155', 'Device Control 155', 'Device control at customer site 155', 'CONTROL', 'CUST155', 'Customer 155', 'Location 155', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 10, NOW(), NOW(), TRUE, 1014),
  (1161, NULL, 'WO-1161', 'LV Device Normalization 161', 'LV device normalization at customer site 161', 'NORMALIZATION', 'CUST161', 'Customer 161', 'Location 161', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 11, NOW(), NOW(), TRUE, 1015),
  (1162, NULL, 'WO-1162', 'LV Device Normalization 162', 'LV device normalization at customer site 162', 'NORMALIZATION', 'CUST162', 'Customer 162', 'Location 162', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 12, NOW(), NOW(), TRUE, 1015),
  (1163, NULL, 'WO-1163', 'LV Device Normalization 163', 'LV device normalization at customer site 163', 'NORMALIZATION', 'CUST163', 'Customer 163', 'Location 163', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 13, NOW(), NOW(), TRUE, 1015),
  (1164, NULL, 'WO-1164', 'LV Device Normalization 164', 'LV device normalization at customer site 164', 'NORMALIZATION', 'CUST164', 'Customer 164', 'Location 164', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 14, NOW(), NOW(), TRUE, 1015),
  (1165, NULL, 'WO-1165', 'LV Device Normalization 165', 'LV device normalization at customer site 165', 'NORMALIZATION', 'CUST165', 'Customer 165', 'Location 165', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 15, NOW(), NOW(), TRUE, 1015),
  (1171, NULL, 'WO-1171', 'MV Device Normalization 171', 'MV device normalization at customer site 171', 'NORMALIZATION', 'CUST171', 'Customer 171', 'Location 171', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 16, NOW(), NOW(), TRUE, 1016),
  (1172, NULL, 'WO-1172', 'MV Device Normalization 172', 'MV device normalization at customer site 172', 'NORMALIZATION', 'CUST172', 'Customer 172', 'Location 172', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 17, NOW(), NOW(), TRUE, 1016),
  (1173, NULL, 'WO-1173', 'MV Device Normalization 173', 'MV device normalization at customer site 173', 'NORMALIZATION', 'CUST173', 'Customer 173', 'Location 173', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 18, NOW(), NOW(), TRUE, 1016),
  (1174, NULL, 'WO-1174', 'MV Device Normalization 174', 'MV device normalization at customer site 174', 'NORMALIZATION', 'CUST174', 'Customer 174', 'Location 174', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 19, NOW(), NOW(), TRUE, 1016),
  (1175, NULL, 'WO-1175', 'MV Device Normalization 175', 'MV device normalization at customer site 175', 'NORMALIZATION', 'CUST175', 'Customer 175', 'Location 175', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 20, NOW(), NOW(), TRUE, 1016),
  (1181, NULL, 'WO-1181', 'Technical Disconnection 181', 'Technical disconnection at customer site 181', 'DISCONNECTION', 'CUST181', 'Customer 181', 'Location 181', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1017),
  (1182, NULL, 'WO-1182', 'Technical Disconnection 182', 'Technical disconnection at customer site 182', 'DISCONNECTION', 'CUST182', 'Customer 182', 'Location 182', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 2, NOW(), NOW(), TRUE, 1017),
  (1183, NULL, 'WO-1183', 'Technical Disconnection 183', 'Technical disconnection at customer site 183', 'DISCONNECTION', 'CUST183', 'Customer 183', 'Location 183', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 3, NOW(), NOW(), TRUE, 1017),
  (1184, NULL, 'WO-1184', 'Technical Disconnection 184', 'Technical disconnection at customer site 184', 'DISCONNECTION', 'CUST184', 'Customer 184', 'Location 184', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 4, NOW(), NOW(), TRUE, 1017),
  (1185, NULL, 'WO-1185', 'Technical Disconnection 185', 'Technical disconnection at customer site 185', 'DISCONNECTION', 'CUST185', 'Customer 185', 'Location 185', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 5, NOW(), NOW(), TRUE, 1017),
  (1191, NULL, 'WO-1191', 'Technical Reconnection 191', 'Technical reconnection at customer site 191', 'RECONNECTION', 'CUST191', 'Customer 191', 'Location 191', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 6, NOW(), NOW(), TRUE, 1018),
  (1192, NULL, 'WO-1192', 'Technical Reconnection 192', 'Technical reconnection at customer site 192', 'RECONNECTION', 'CUST192', 'Customer 192', 'Location 192', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 7, NOW(), NOW(), TRUE, 1018),
  (1193, NULL, 'WO-1193', 'Technical Reconnection 193', 'Technical reconnection at customer site 193', 'RECONNECTION', 'CUST193', 'Customer 193', 'Location 193', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 8, NOW(), NOW(), TRUE, 1018),
  (1194, NULL, 'WO-1194', 'Technical Reconnection 194', 'Technical reconnection at customer site 194', 'RECONNECTION', 'CUST194', 'Customer 194', 'Location 194', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 9, NOW(), NOW(), TRUE, 1018),
  (1195, NULL, 'WO-1195', 'Technical Reconnection 195', 'Technical reconnection at customer site 195', 'RECONNECTION', 'CUST195', 'Customer 195', 'Location 195', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 10, NOW(), NOW(), TRUE, 1018),
  (1201, NULL, 'WO-1201', 'Conversion Prepaid Postpaid 201', 'Conversion prepaid to postpaid at customer site 201', 'CONVERSION', 'CUST201', 'Customer 201', 'Location 201', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 11, NOW(), NOW(), TRUE, 1019),
  (1202, NULL, 'WO-1202', 'Conversion Prepaid Postpaid 202', 'Conversion prepaid to postpaid at customer site 202', 'CONVERSION', 'CUST202', 'Customer 202', 'Location 202', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 12, NOW(), NOW(), TRUE, 1019),
  (1203, NULL, 'WO-1203', 'Conversion Prepaid Postpaid 203', 'Conversion prepaid to postpaid at customer site 203', 'CONVERSION', 'CUST203', 'Customer 203', 'Location 203', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 13, NOW(), NOW(), TRUE, 1019),
  (1204, NULL, 'WO-1204', 'Conversion Prepaid Postpaid 204', 'Conversion prepaid to postpaid at customer site 204', 'CONVERSION', 'CUST204', 'Customer 204', 'Location 204', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 14, NOW(), NOW(), TRUE, 1019),
  (1205, NULL, 'WO-1205', 'Conversion Prepaid Postpaid 205', 'Conversion prepaid to postpaid at customer site 205', 'CONVERSION', 'CUST205', 'Customer 205', 'Location 205', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 15, NOW(), NOW(), TRUE, 1019),
  (1211, NULL, 'WO-1211', 'Conversion Pospad Prepaid 211', 'Conversion postpaid to prepaid at customer site 211', 'CONVERSION', 'CUST211', 'Customer 211', 'Location 211', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 16, NOW(), NOW(), TRUE, 1020),
  (1212, NULL, 'WO-1212', 'Conversion Pospad Prepaid 212', 'Conversion postpaid to prepaid at customer site 212', 'CONVERSION', 'CUST212', 'Customer 212', 'Location 212', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 17, NOW(), NOW(), TRUE, 1020),
  (1213, NULL, 'WO-1213', 'Conversion Pospad Prepaid 213', 'Conversion postpaid to prepaid at customer site 213', 'CONVERSION', 'CUST213', 'Customer 213', 'Location 213', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 18, NOW(), NOW(), TRUE, 1020),
  (1214, NULL, 'WO-1214', 'Conversion Pospad Prepaid 214', 'Conversion postpaid to prepaid at customer site 214', 'CONVERSION', 'CUST214', 'Customer 214', 'Location 214', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 19, NOW(), NOW(), TRUE, 1020),
  (1215, NULL, 'WO-1215', 'Conversion Pospad Prepaid 215', 'Conversion postpaid to prepaid at customer site 215', 'CONVERSION', 'CUST215', 'Customer 215', 'Location 215', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 20, NOW(), NOW(), TRUE, 1020),
  (1221, NULL, 'WO-1221', 'Survey Order LV 221', 'Survey order LV at customer site 221', 'SURVEY', 'CUST221', 'Customer 221', 'Location 221', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1021),
  (1222, NULL, 'WO-1222', 'Survey Order LV 222', 'Survey order LV at customer site 222', 'SURVEY', 'CUST222', 'Customer 222', 'Location 222', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 2, NOW(), NOW(), TRUE, 1021),
  (1223, NULL, 'WO-1223', 'Survey Order LV 223', 'Survey order LV at customer site 223', 'SURVEY', 'CUST223', 'Customer 223', 'Location 223', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 3, NOW(), NOW(), TRUE, 1021),
  (1224, NULL, 'WO-1224', 'Survey Order LV 224', 'Survey order LV at customer site 224', 'SURVEY', 'CUST224', 'Customer 224', 'Location 224', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 4, NOW(), NOW(), TRUE, 1021),
  (1225, NULL, 'WO-1225', 'Survey Order LV 225', 'Survey order LV at customer site 225', 'SURVEY', 'CUST225', 'Customer 225', 'Location 225', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 5, NOW(), NOW(), TRUE, 1021),
  (1231, NULL, 'WO-1231', 'Survey Order MV HV 231', 'Survey order MV HV at customer site 231', 'SURVEY', 'CUST231', 'Customer 231', 'Location 231', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 6, NOW(), NOW(), TRUE, 1022),
  (1232, NULL, 'WO-1232', 'Survey Order MV HV 232', 'Survey order MV HV at customer site 232', 'SURVEY', 'CUST232', 'Customer 232', 'Location 232', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 7, NOW(), NOW(), TRUE, 1022),
  (1233, NULL, 'WO-1233', 'Survey Order MV HV 233', 'Survey order MV HV at customer site 233', 'SURVEY', 'CUST233', 'Customer 233', 'Location 233', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 8, NOW(), NOW(), TRUE, 1022),
  (1234, NULL, 'WO-1234', 'Survey Order MV HV 234', 'Survey order MV HV at customer site 234', 'SURVEY', 'CUST234', 'Customer 234', 'Location 234', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 9, NOW(), NOW(), TRUE, 1022),
  (1235, NULL, 'WO-1235', 'Survey Order MV HV 235', 'Survey order MV HV at customer site 235', 'SURVEY', 'CUST235', 'Customer 235', 'Location 235', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 10, NOW(), NOW(), TRUE, 1022),
  (1241, NULL, 'WO-1241', 'Provisioning Order LV 241', 'Provisioning order LV at customer site 241', 'PROVISIONING', 'CUST241', 'Customer 241', 'Location 241', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 11, NOW(), NOW(), TRUE, 1023),
  (1242, NULL, 'WO-1242', 'Provisioning Order LV 242', 'Provisioning order LV at customer site 242', 'PROVISIONING', 'CUST242', 'Customer 242', 'Location 242', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 12, NOW(), NOW(), TRUE, 1023),
  (1243, NULL, 'WO-1243', 'Provisioning Order LV 243', 'Provisioning order LV at customer site 243', 'PROVISIONING', 'CUST243', 'Customer 243', 'Location 243', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 13, NOW(), NOW(), TRUE, 1023),
  (1244, NULL, 'WO-1244', 'Provisioning Order LV 244', 'Provisioning order LV at customer site 244', 'PROVISIONING', 'CUST244', 'Customer 244', 'Location 244', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 14, NOW(), NOW(), TRUE, 1023),
  (1245, NULL, 'WO-1245', 'Provisioning Order LV 245', 'Provisioning order LV at customer site 245', 'PROVISIONING', 'CUST245', 'Customer 245', 'Location 245', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 15, NOW(), NOW(), TRUE, 1023),
  (1251, NULL, 'WO-1251', 'Provisioning Order MV HV 251', 'Provisioning order MV HV at customer site 251', 'PROVISIONING', 'CUST251', 'Customer 251', 'Location 251', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 16, NOW(), NOW(), TRUE, 1024),
  (1252, NULL, 'WO-1252', 'Provisioning Order MV HV 252', 'Provisioning order MV HV at customer site 252', 'PROVISIONING', 'CUST252', 'Customer 252', 'Location 252', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 17, NOW(), NOW(), TRUE, 1024),
  (1253, NULL, 'WO-1253', 'Provisioning Order MV HV 253', 'Provisioning order MV HV at customer site 253', 'PROVISIONING', 'CUST253', 'Customer 253', 'Location 253', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 18, NOW(), NOW(), TRUE, 1024),
  (1254, NULL, 'WO-1254', 'Provisioning Order MV HV 254', 'Provisioning order MV HV at customer site 254', 'PROVISIONING', 'CUST254', 'Customer 254', 'Location 254', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 19, NOW(), NOW(), TRUE, 1024),
  (1255, NULL, 'WO-1255', 'Provisioning Order MV HV 255', 'Provisioning order MV HV at customer site 255', 'PROVISIONING', 'CUST255', 'Customer 255', 'Location 255', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 20, NOW(), NOW(), TRUE, 1024),
  (1261, NULL, 'WO-1261', 'Technical Disconnection (ZDDR) 261', 'Technical disconnection (ZDDR) at customer site 261', 'DISCONNECTION', 'CUST261', 'Customer 261', 'Location 261', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 1, NOW(), NOW(), TRUE, 1025),
  (1262, NULL, 'WO-1262', 'Technical Disconnection (ZDDR) 262', 'Technical disconnection (ZDDR) at customer site 262', 'DISCONNECTION', 'CUST262', 'Customer 262', 'Location 262', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 2, NOW(), NOW(), TRUE, 1025),
  (1263, NULL, 'WO-1263', 'Technical Disconnection (ZDDR) 263', 'Technical disconnection (ZDDR) at customer site 263', 'DISCONNECTION', 'CUST263', 'Customer 263', 'Location 263', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 3, NOW(), NOW(), TRUE, 1025),
  (1264, NULL, 'WO-1264', 'Technical Disconnection (ZDDR) 264', 'Technical disconnection (ZDDR) at customer site 264', 'DISCONNECTION', 'CUST264', 'Customer 264', 'Location 264', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 4, NOW(), NOW(), TRUE, 1025),
  (1265, NULL, 'WO-1265', 'Technical Disconnection (ZDDR) 265', 'Technical disconnection (ZDDR) at customer site 265', 'DISCONNECTION', 'CUST265', 'Customer 265', 'Location 265', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 5, NOW(), NOW(), TRUE, 1025),
  (1271, NULL, 'WO-1271', 'Technical Reconnection (ZDDR) 271', 'Technical reconnection (ZDDR) at customer site 271', 'RECONNECTION', 'CUST271', 'Customer 271', 'Location 271', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 6, NOW(), NOW(), TRUE, 1026),
  (1272, NULL, 'WO-1272', 'Technical Reconnection (ZDDR) 272', 'Technical reconnection (ZDDR) at customer site 272', 'RECONNECTION', 'CUST272', 'Customer 272', 'Location 272', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 7, NOW(), NOW(), TRUE, 1026),
  (1273, NULL, 'WO-1273', 'Technical Reconnection (ZDDR) 273', 'Technical reconnection (ZDDR) at customer site 273', 'RECONNECTION', 'CUST273', 'Customer 273', 'Location 273', 0, 0, NOW(), NOW(), 'LOW', 'PENDING', 1, 8, NOW(), NOW(), TRUE, 1026),
  (1274, NULL, 'WO-1274', 'Technical Reconnection (ZDDR) 274', 'Technical reconnection (ZDDR) at customer site 274', 'RECONNECTION', 'CUST274', 'Customer 274', 'Location 274', 0, 0, NOW(), NOW(), 'HIGH', 'PENDING', 1, 9, NOW(), NOW(), TRUE, 1026),
  (1275, NULL, 'WO-1275', 'Technical Reconnection (ZDDR) 275', 'Technical reconnection (ZDDR) at customer site 275', 'RECONNECTION', 'CUST275', 'Customer 275', 'Location 275', 0, 0, NOW(), NOW(), 'MEDIUM', 'PENDING', 1, 10, NOW(), NOW(), TRUE, 1026);
