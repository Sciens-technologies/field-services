# API Endpoints Documentation

## Table of Contents
- [Users API](#users-api)
- [Admin API](#admin-api)
- [Work Orders API](#work-orders-api)
- [Device API](#device-api)
- [Forms API](#forms-api)

---

# Users API (`/api/v1`)

| Method | Path | Purpose | Auth | Parameters | Request Body | Response |
|--------|------|---------|------|------------|--------------|----------|
| POST   | /login | Authenticate user and get access token | No | None | `{ "username": str, "password": str }` | `{ token, user, roles }` |
| POST   | /logout | Log out user and revoke token | Yes | `email` (query) | None | `{ message }` |
| POST   | /signup | Register first user (super admin) | No | None | `SignupRequest` | `UserResponse` |
| GET    | /session/status | Check if session is valid | Yes | None | None | `{ active, last_activity, user }` |
| GET    | /profile | Get current user's profile | Yes | None | None | `UserResponse` |
| PUT    | /profile | Update current user's profile | Yes | None | `UserUpdate` | `UserResponse` |
| POST   | /change-password | Change password | Yes | None | `{ current_password, new_password }` | `{ message }` |
| POST   | /forgot-password | Initiate password reset | No | `email` (query) | None | `{ message, reset_key, email }` |
| POST   | /reset-password | Reset password with key | No | `reset_key`, `new_password` (query) | None | `{ message }` |
| GET    | /notifications/preferences | Get notification preferences | Yes | None | None | `{ email, sms, push }` |
| PUT    | /notifications/preferences | Update notification preferences | Yes | None | `NotificationPreferencesUpdate` | `{ email_enabled, sms_enabled, push_enabled }` |
| POST   | /feedback | Submit system feedback | Yes | None | `SystemFeedbackRequest` | `SystemFeedbackResponse` |
| POST   | /tickets | Create support ticket | Yes | None | `SupportTicketCreate` | `SupportTicketResponse` |

---

# Admin API (`/api/v1/admin`)

| Method | Path | Purpose | Auth | Parameters | Request Body | Response |
|--------|------|---------|------|------------|--------------|----------|
| POST   | /users/{user_id}/deactivate/ | Deactivate a user | Admin | `user_id` (path), `reason` (query) | None | `{ message }` |
| POST   | /users/{user_id}/reactivate/ | Reactivate a user | Admin | `user_id` (path) | None | `{ message, user_id, status }` |
| GET    | /users | List users with filters | Admin | `name`, `email`, `role_name`, `status` (query) | None | `List[UserResponseWithoutPassword]` |
| POST   | /users | Create a new user | Admin | None | `UserCreate` | `UserResponse` (with password) |
| GET    | /notifications/history/ | Get notification history | Admin | `limit`, `offset` (query) | None | `{ total, notifications }` |
| POST   | /roles | Create a new role | Admin | None | `RoleCreate` | `RoleResponse` |
| GET    | /roles | List roles | Admin | `name`, `page`, `limit` (query) | None | `List[RoleResponse]` |
| POST   | /permissions | Create a new permission | Admin | None | `PermissionCreate` | `PermissionResponse` |
| GET    | /permissions | List permissions | Admin | `feature`, `page`, `limit` (query) | None | `List[PermissionResponse]` |
| PATCH  | /roles/{role_id}/permissions | Update role permissions | Admin | `role_id` (path) | `PermissionAssignment` | `List[PermissionResponse]` |

---

# Work Orders API (`/api/v1/work-orders`)

| Method | Path | Purpose | Auth | Parameters | Request Body | Response |
|--------|------|---------|------|------------|--------------|----------|
| POST   | /assign | Assign a work order to agent | Yes | None | `WorkOrderAssignmentCreate` | `WorkOrderAssignmentResponse` |
| PUT    | /{assignment_id}/reassign | Reassign a work order | Yes | `assignment_id` (path) | `WorkOrderReassignmentCreate` | `WorkOrderAssignmentResponse` |
| POST   | /{work_order_id}/acknowledge | Acknowledge work order | Yes | `work_order_id` (path) | `WorkOrderAcknowledgmentCreate` | `WorkOrderAssignmentResponse` |
| GET    | /{work_order_id} | Get work order details | Yes | `work_order_id` (path) | None | `WorkOrderDetailResponse` |

---

# Device API (`/api/v1/device`)

| Method | Path | Purpose | Auth | Parameters | Request Body | Response |
|--------|------|---------|------|------------|--------------|----------|
| POST   | /devices | Create a new device | Admin | None | `DeviceCreate` | `DeviceResponse` |
| GET    | / | List all devices | Admin | `model`, `status`, `work_center_id` (query) | None | `List[DeviceResponse]` |
| PUT    | /{device_id} | Update device details | Admin | `device_id` (path) | `DeviceUpdate` | `DeviceResponse` |
| POST   | /{device_id}/assign | Assign device to user | Admin | `device_id` (path) | `DeviceAssignmentCreate` | `DeviceAssignmentResponse` |
| GET    | /{device_id}/assignments | List device assignments | Admin | `device_id` (path) | None | `List[DeviceAssignmentResponse]` |
| PATCH  | /{device_id}/block | Block/unblock device | Admin | `device_id` (path) | `BlockDeviceRequest` | `{ device_id, new_status, message }` |
| POST   | /{device_id}/deactivate | Deactivate device | Admin | `device_id` (path), `reason` (query) | None | `{ message, pending_work_orders, available_devices }` |
| POST   | /{device_id}/activate | Activate device | Admin | `device_id` (path) | None | `{ message }` |

---

# Forms API (`/api/v1/forms`)

| Method | Path | Purpose | Auth | Parameters | Request Body | Response |
|--------|------|---------|------|------------|--------------|----------|
| GET    | /work-order/{work_order_id}/templet | Get work order template | Yes | `work_order_id` (path) | None | `WorkOrderFormResponse` |
| POST   | /work-order/{work_order_id} | Save/update form data | Yes | `work_order_id` (path) | `dict` (form data) | `WorkOrderFormResponse` |
| GET    | /work-order/{work_order_id} | Get form data | Yes | `work_order_id` (path) | None | `FormDataResponse` |

---

## Notes
- **Auth:** 'Admin' means the user must have `admin` or `super_admin` role. 'Yes' means any authenticated user.
- **Request/Response Models:** See `api/schemas.py` for detailed field definitions.
- **Sample requests/responses** can be provided for each endpoint if needed. Let us know if you want those included.
- **All endpoints except login, signup, forgot/reset password require a Bearer JWT token.** 