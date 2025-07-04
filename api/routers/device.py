from fastapi import APIRouter, Depends, HTTPException, Path, Query, Body, status, UploadFile, File
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from typing import List, Optional, cast
import csv
import io
import pandas as pd

from db.database import get_db
from db.models import (
    Device,
    DeviceArtifact,
    DeviceAssignment,
    DeviceStatusAudit,
    DeviceHealthLog,
    WorkOrderAssignment,
    WorkCentre,
    User,
    UserRole,
    DeviceAssignmentRole,
    WorkOrder,
    WorkOrderStatus
)

from api.schemas import (
    DeviceCreate,
    DeviceUpdate,
    DeviceResponse,
    DeviceUpdateResponse,
    DeviceArtifactCreate,
    DeviceArtifactResponse,
    DeviceAssignmentCreate,
    DeviceAssignmentResponse,
    BlockDeviceRequest,
    DeactivateDevicePayload,
    AssignmentStatus,
    DeviceStatus
)

from api.services.users import admin_required, get_current_user, role_required
from api.utils.util import trigger_device_block_notification, user_is_agent

device_router = APIRouter()

def map_user_role_to_assignment_role(user_role_name: str) -> str:
    """
    Map user role names to valid DeviceAssignmentRole enum values.
    Handles case-insensitive mapping.
    """
    role_mapping = {
        "super_admin": "SUPERVISOR",
        "admin": "ADMIN", 
        "supervisor": "SUPERVISOR",
        "manager": "MANAGER",
        "agent": "AGENT",
        "other": "OTHER",
    }
    return role_mapping.get(user_role_name.lower(), "OTHER")


@device_router.post("/devices", response_model=DeviceResponse)
@role_required(["admin", "super_admin", "supervisor"])
async def create_device(
    device: DeviceCreate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new device in the devices table.
    """
    existing_device = db.query(Device).filter(Device.serial_number == device.serial_number).first()
    if existing_device:
        raise HTTPException(status_code=400, detail="Device with this serial number already exists.")

    try:
        new_device = Device(
            serial_number=device.serial_number,
            device_name=device.device_name,
            model=device.model,
            status=DeviceStatus.REGISTERED,
            active=True
        )
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        return _device_to_response(new_device)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Error creating device: {str(e)}")
    
@device_router.get("/", response_model=List[DeviceResponse], status_code=200)
@role_required(["admin", "super_admin", "supervisor"])
async def list_devices(
    model: Optional[str] = Query(None),
    status_: Optional[str] = Query(None, alias="status"),
    work_center_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all devices, with optional filters, plus work_order_count
    (count of active work-orders assigned to the same agent).
    """
    query = db.query(Device).filter(Device.active.is_(True))

    if model:
        query = query.filter(Device.model.ilike(f"%{model}%"))

    if status_:
        try:
            query = query.filter(Device.status == DeviceStatus(status_.upper()))
        except ValueError:
            raise HTTPException(400, "Invalid device status")

    if work_center_id:
        query = query.filter(Device.work_center_id == work_center_id)

    # 👉 correct eager-loading path
    query = query.options(
        joinedload(Device.work_centre),
        joinedload(Device.assignments)               # device → DeviceAssignment
            .joinedload(DeviceAssignment.user)       # → User (agent)
    )

    devices = query.all()
    out: list[DeviceResponse] = []

    for device in devices:
        active_assignment = next((da for da in device.assignments if da.active), None)
        work_order_count = 0
        assignment_user_id = None
        assignment_username = None
        assignment_assigned_at = None
        assignment_user_email = None
        assignment_user_name = None
        if active_assignment and active_assignment.user:
            user = active_assignment.user
            user_id = user.user_id
            assignment_user_id = user_id
            assignment_username = user.username
            assignment_user_email = user.email
            assignment_user_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
            assignment_assigned_at = active_assignment.assigned_at
            work_order_count = (
                db.query(WorkOrderAssignment)
                .filter(
                    WorkOrderAssignment.agent_id == user_id,
                    WorkOrderAssignment.active.is_(True),
                )
                .count()
            )
        out.append(
            DeviceResponse(
                device_id=cast(int, device.device_id),
                serial_number=cast(str, device.serial_number),
                device_name=cast(str, device.device_name or ""),
                model=cast(Optional[str], device.model),
                status=cast(DeviceStatus, device.status or DeviceStatus.REGISTERED),
                last_communication=cast(Optional[datetime], device.last_communication),
                created_at=cast(datetime, device.created_at),
                updated_at=cast(datetime, device.updated_at or device.created_at),
                active=cast(bool, device.active if device.active is not None else True),
                work_order_count=work_order_count,
                category="GENERAL",
                assignment_user_id=assignment_user_id,
                assignment_username=assignment_username,
                assignment_assigned_at=assignment_assigned_at,
                assignment_user_email=assignment_user_email,
                assignment_user_name=assignment_user_name
            )
        )

    return out

@device_router.put("/{serial_number}", response_model=DeviceUpdateResponse)
@role_required(["admin", "super_admin", "supervisor"])
async def update_device(
    serial_number: str, 
    payload: DeviceUpdate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update the details of a device by serial number.
    - **serial_number**: str (path) - The serial number of the device to update
    - **payload**: DeviceUpdate - The fields to update
    """
    device = db.query(Device).filter(Device.serial_number == serial_number).first()
    if not device:
        raise HTTPException(404, detail="Device not found")
    for field, value in payload.dict(exclude_unset=True).items():
        setattr(device, field, value)
    db.query(Device).filter(Device.serial_number == serial_number).update(
        {"updated_at": datetime.utcnow()},
        synchronize_session="fetch"
    )
    db.commit()
    db.refresh(device)
    # Get assignment info
    assignment = next((a for a in device.assignments if a.active and a.unassigned_at is None), None)
    agent = assignment.user if assignment else None
    assignment_user_email = agent.email if agent else None
    assignment_user_name = f"{agent.first_name or ''} {agent.last_name or ''}".strip() if agent else None
    return DeviceUpdateResponse(
        serial_number=str(device.serial_number),
        device_name=str(device.device_name or ""),
        model=str(device.model) if device.model is not None else None,
        status=DeviceStatus(device.status) if device.status is not None else DeviceStatus.REGISTERED,
        assignment_user_email=assignment_user_email,
        assignment_user_name=assignment_user_name
    )

@device_router.post(
    "/{serial_number}/assign",
    response_model=DeviceAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
)
@role_required(["admin", "super_admin", "supervisor"])
async def assign_device(
    serial_number: str,
    payload: DeviceAssignmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # 1. Validate input
    if not payload.user_email:
        raise HTTPException(status_code=400, detail="user_email is required")

    # 2. Check if device exists
    device = db.query(Device).filter(Device.serial_number == serial_number).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device_id = device.device_id

    # 3. Look up user by email
    user = db.query(User).filter(User.email == payload.user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 4. Check if device is already assigned to someone (and active)
    existing_assignment = db.query(DeviceAssignment).filter(
        DeviceAssignment.device_id == device_id,
        DeviceAssignment.active == True
    ).first()
    if existing_assignment:
        raise HTTPException(
            status_code=400,
            detail=f"Device {serial_number} is already assigned to another user."
        )

    # 5. Check if user already has a device assigned
    device_assignment = db.query(DeviceAssignment).filter(
        DeviceAssignment.user_id == user.user_id,
        DeviceAssignment.active == True
    ).first()
    print(f"Device assignment for user: {device_assignment}")
    if device_assignment:
        print(f"Device: {device}")
        print(f"Device status: '{device.status}' (raw)")
        print(f"Device active: {device.active} (type: {type(device.active)})")
        raise HTTPException(
            status_code=400,
            detail=f"User {payload.user_email} already has a device assigned."
        )

    # 6. Determine user role for assignment from user's roles
    user_role = "AGENT"  # Default role
    if user.roles:
        user_role_name = user.roles[0].role.role_name if user.roles[0].role else "AGENT"
        user_role = map_user_role_to_assignment_role(user_role_name)

    # 7. Determine assigned_by_role from current user's roles
    assigned_by_role = "ADMIN"  # Default role
    current_user_roles = db.query(UserRole).filter(UserRole.user_id == current_user.user_id).all()
    if current_user_roles:
        assigned_by_role_name = current_user_roles[0].role.role_name if current_user_roles[0].role else "ADMIN"
        assigned_by_role = map_user_role_to_assignment_role(assigned_by_role_name)

    # 8. Assign the device
    assignment = DeviceAssignment(
        device_id=device_id,
        user_id=user.user_id,
        role=user_role,
        assigned_by_user_id=current_user.user_id,
        assigned_by_role=assigned_by_role,
        status="ACTIVE",
        active=True,
        assigned_at=datetime.utcnow()
    )

    db.add(assignment)
    # Set device status to ACTIVE when assigned
    db.query(Device).filter(Device.device_id == device_id).update({"status": DeviceStatus.ACTIVE, "active": True}, synchronize_session="fetch")
    db.commit()
    db.refresh(assignment)
    assignment_id = assignment.assignment_id
    if not isinstance(assignment_id, int):
        assignment_id = assignment_id.__int__()
    return DeviceAssignmentResponse(
        assignment_id=assignment_id,
        status=str(assignment.status) if assignment.status is not None else None,
        active=bool(assignment.active),
        subject=str(assignment.subject) if assignment.subject is not None else None,
        assigned_user_email=str(user.email) if user.email is not None else None,
        assigned_user_name=f"{user.first_name or ''} {user.last_name or ''}".strip()
    )

@device_router.get("/{serial_number}/assignments", response_model=List[DeviceAssignmentResponse])
@role_required(["admin", "super_admin", "supervisor"])
async def list_assignments(
    serial_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.serial_number == serial_number).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    assignments = db.query(DeviceAssignment).filter(DeviceAssignment.device_id == device.device_id).all()
    if not assignments:
        raise HTTPException(status_code=404, detail="No assignments found for this device")
    out = []
    for a in assignments:
        user = a.user
        assignment_id = a.assignment_id
        if not isinstance(assignment_id, int):
            assignment_id = assignment_id.__int__()
        out.append(DeviceAssignmentResponse(
            assignment_id=assignment_id,
            status=str(a.status) if a.status is not None else None,
            active=bool(a.active),
            subject=str(a.subject) if a.subject is not None else None,
            assigned_user_email=user.email if user else None,
            assigned_user_name=f"{user.first_name or ''} {user.last_name or ''}".strip() if user else None
        ))
    return out

@device_router.patch("/{serial_number}/block", status_code=200)
@role_required(["admin", "super_admin", "supervisor"])
async def block_or_unblock_device(
    serial_number: str,
    request: BlockDeviceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = db.query(Device).filter(Device.serial_number == serial_number).first()
    if not device:
        raise HTTPException(404, "Device not found")
    device_id = device.device_id
    target_status = DeviceStatus.BLOCKED if request.block else DeviceStatus.ACTIVE
    if cast(DeviceStatus, device.status) == target_status:
        return {"message": f"Device already {target_status.value.lower()}"}
    db.query(Device).filter(Device.device_id == device_id).update(
        {
            "status": target_status,
            "active": target_status == DeviceStatus.ACTIVE
        },
        synchronize_session="fetch"
    )
    db.query(DeviceAssignment).filter(
        DeviceAssignment.device_id == device_id,
        DeviceAssignment.active.is_(True)
    ).update(
        {
            DeviceAssignment.status: AssignmentStatus.BLOCKED
            if request.block
            else AssignmentStatus.ASSIGNED
        },
        synchronize_session="fetch"
    )
    db.commit()
    return {
        "serial_number": serial_number,
        "new_status": target_status,
        "message": "Device blocked" if request.block else "Device unblocked",
    }

@device_router.post(
    "/{serial_number}/deactivate",
    status_code=status.HTTP_200_OK
)
@role_required(["admin", "super_admin", "supervisor"])
async def deactivate_device(
    serial_number: str,
    reason: str = Query("", max_length=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.serial_number == serial_number).first()
    if not device:
        raise HTTPException(404, detail="Device not found")
    device_id = device.device_id
    if cast(DeviceStatus, device.status) == DeviceStatus.DEACTIVATED:
        return {"message": "Device already deactivated"}
    audit = DeviceStatusAudit(
        device_id=device.device_id,
        status_before=device.status,
        status_after=DeviceStatus.DEACTIVATED,
        reason=reason,
        changed_by_user_id=current_user.user_id,
    )
    db.add(audit)
    db.query(Device).filter(Device.device_id == device_id).update(
        {
            "status": DeviceStatus.DEACTIVATED,
            "active": False,
            "updated_at": datetime.utcnow()
        },
        synchronize_session="fetch"
    )
    db.query(DeviceAssignment).filter(
        DeviceAssignment.device_id == device_id,
        DeviceAssignment.active == True
    ).update(
        {
            DeviceAssignment.active: False,
            DeviceAssignment.unassigned_at: datetime.utcnow(),
            DeviceAssignment.status: "UNASSIGNED"
        },
        synchronize_session="fetch"
    )
    agent_ids = [
        row[0] for row in db.query(DeviceAssignment.user_id)
        .filter(DeviceAssignment.device_id == device_id, DeviceAssignment.active == False)
        .all()
    ]
    work_order_ids = db.query(WorkOrderAssignment.work_order_id).filter(
        WorkOrderAssignment.agent_id.in_(agent_ids),
        WorkOrderAssignment.active == True
    )
    open_wos = db.query(WorkOrder).filter(
        WorkOrder.work_order_id.in_(work_order_ids),
        WorkOrder.status.in_([
            WorkOrderStatus.PENDING.value,
            WorkOrderStatus.IN_PROGRESS.value
        ])
    ).all()
    pending_work_orders = [
        {
            "work_order_id": wo.work_order_id,
            "wo_number": wo.wo_number,
            "status": wo.status
        }
        for wo in open_wos
    ]
    available_devices = db.query(Device).filter(
        Device.device_id != device_id,
        Device.active == True,
        Device.status == DeviceStatus.ACTIVE.value
    ).all()
    available_devices_response = [
        {
            "device_id": d.device_id,
            "serial_number": d.serial_number
        }
        for d in available_devices
    ]
    db.commit()
    return {
        "message": f"Device {serial_number} deactivated successfully.",
        "pending_work_orders": pending_work_orders,
        "available_devices": available_devices_response
    }

@device_router.post("/{serial_number}/activate", status_code=200)
@role_required(["admin", "super_admin", "supervisor"])
async def activate_device(
    serial_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.serial_number == serial_number).first()
    if not device:
        raise HTTPException(404, detail="Device not found")
    device_id = device.device_id
    if cast(DeviceStatus, device.status) == DeviceStatus.ACTIVE:
        return {"message": "Device is already active"}
    if cast(DeviceStatus, device.status) != DeviceStatus.DEACTIVATED:
        raise HTTPException(400, detail="Only deactivated devices can be activated")
    db.query(Device).filter(Device.device_id == device_id).update(
        {
            "status": DeviceStatus.ACTIVE,
            "active": True,
            "updated_at": datetime.utcnow()
        },
        synchronize_session="fetch"
    )
    audit = DeviceStatusAudit(
        device_id=device.device_id,
        status_before=device.status,
        status_after=DeviceStatus.ACTIVE,
        reason="Manual reactivation",
        changed_by_user_id=current_user.user_id
    )
    db.add(audit)
    db.commit()
    return {"message": f"Device {serial_number} activated successfully."}

@device_router.get("/status-summary")
async def device_status_summary(db: Session = Depends(get_db)):
    """
    Get a summary of devices by status (e.g., REGISTERED, IN_SERVICE, OUT_OF_SERVICE, etc.).
    """
    status_counts = (
        db.query(Device.status, func.count(Device.device_id))
        .group_by(Device.status)
        .all()
    )
    # Convert enum values to plain strings for dashboard readability
    return {str(status.value) if hasattr(status, 'value') else str(status): count for status, count in status_counts}

@device_router.get("/dashboard-stats")
@role_required(["admin", "super_admin", "supervisor"])
async def device_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get dashboard statistics: total devices, active devices, deactivated devices.
    """
    total_devices = db.query(Device).count()
    active_devices = db.query(Device).filter(Device.active == True).count()
    deactivated_devices = db.query(Device).filter(Device.active == False).count()
    return {
        "total_devices": total_devices,
        "active_devices": active_devices,
        "deactivated_devices": deactivated_devices,
    }

@device_router.post("/devices/bulk-upload", summary="Bulk upload devices via CSV or Excel", description="Admin or Supervisor can upload a CSV or Excel file to create multiple devices at once.")
@role_required(["admin", "super_admin", "supervisor"])
async def bulk_upload_devices(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    results = {"created": 0, "failed": 0, "errors": []}

    if file.filename and file.filename.endswith(".csv"):
        content = file.file.read()
        decoded = content.decode("utf-8").splitlines()
        reader = csv.DictReader(decoded)
    elif file.filename and file.filename.endswith(".xlsx"):
        content = file.file.read()
        df = pd.read_excel(io.BytesIO(content))
        reader = df.to_dict(orient="records")
    else:
        raise HTTPException(status_code=400, detail="Only .csv or .xlsx files are supported.")

    for idx, row in enumerate(reader, 1):
        try:
            serial_number = row.get("serial_number") or ""
            device_name = row.get("device_name") or ""
            model = row.get("model") or None
            if not serial_number or not device_name:
                raise ValueError("Missing required device field: serial_number or device_name")
            device_data = DeviceCreate(
                serial_number=serial_number,
                device_name=device_name,
                model=model
            )
            existing_device = db.query(Device).filter(Device.serial_number == device_data.serial_number).first()
            if existing_device:
                raise ValueError(f"Device with serial_number {device_data.serial_number} already exists.")
            new_device = Device(
                serial_number=device_data.serial_number,
                device_name=device_data.device_name,
                model=device_data.model,
                status=DeviceStatus.REGISTERED,
                active=True
            )
            db.add(new_device)
            db.commit()
            db.refresh(new_device)
            results["created"] += 1
        except Exception as e:
            db.rollback()
            results["failed"] += 1
            results["errors"].append({"row": idx, "error": str(e)})
    return results

@device_router.patch("/{serial_number}/ready-to-activate", status_code=200)
@role_required(["admin", "super_admin", "supervisor"])
async def ready_to_activate_device(
    serial_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.serial_number == serial_number).first()
    if not device:
        raise HTTPException(404, "Device not found")
    device_id = device.device_id
    db.query(Device).filter(Device.device_id == device_id).update(
        {"status": DeviceStatus.READY_TO_ACTIVATE, "active": True, "updated_at": datetime.utcnow()},
        synchronize_session="fetch"
    )
    db.commit()
    return {"serial_number": serial_number, "new_status": DeviceStatus.READY_TO_ACTIVATE, "message": "Device set to READY_TO_ACTIVATE."}

def _device_to_response(device: Device) -> DeviceResponse:
    # Get current active assignment
    assignment = next(
        (a for a in device.assignments if a.active and a.unassigned_at is None),
        None,
    )
    agent = assignment.user if assignment else None
    assignment_user_id = agent.user_id if agent else None
    assignment_username = agent.username if agent else None
    assignment_user_email = agent.email if agent else None
    assignment_user_name = f"{agent.first_name or ''} {agent.last_name or ''}".strip() if agent else None
    assignment_assigned_at = assignment.assigned_at if assignment else None
    # Count active work orders assigned to the same user
    open_statuses = {"PENDING", "ASSIGNED", "IN_PROGRESS"}
    work_order_count = 0
    if agent:
        work_order_count = sum(
            1
            for woa in agent.agent_work_order_assignments
            if woa.active and woa.work_order and woa.work_order.status.name in open_statuses
        )
    print(f"Device assignment: {assignment}")
    if assignment:
        print(f"Device: {device}")
        device_status = None
        if device is not None and device.status is not None:
            device_status = str(device.status).strip().upper()
        print(f"Device status: '{device_status}'")
        print(f"Device active: {device.active} (type: {type(device.active)})")
    return DeviceResponse(
        device_id=cast(int, device.device_id),
        serial_number=cast(str, device.serial_number),
        device_name=cast(str, device.device_name or ""),
        model=cast(Optional[str], device.model),
        status=cast(DeviceStatus, device.status or DeviceStatus.REGISTERED),
        last_communication=cast(Optional[datetime], device.last_communication),
        created_at=cast(datetime, device.created_at),
        updated_at=cast(datetime, device.updated_at or device.created_at),
        active=cast(bool, device.active if device.active is not None else True),
        work_order_count=work_order_count,
        category="GENERAL",
        assignment_user_id=assignment_user_id,
        assignment_username=assignment_username,
        assignment_assigned_at=assignment_assigned_at,
        assignment_user_email=assignment_user_email,
        assignment_user_name=assignment_user_name
    )