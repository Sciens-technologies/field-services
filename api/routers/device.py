from fastapi import APIRouter, Depends, HTTPException, Path, Query, Body, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, and_, or_
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from typing import List, Optional, cast

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
    DeviceArtifactCreate,
    DeviceArtifactResponse,
    DeviceAssignmentCreate,
    DeviceAssignmentResponse,
    BlockDeviceRequest,
    DeactivateDevicePayload,
    AssignmentStatus,
    DeviceStatus
)

from api.services.users import admin_required, get_current_user
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
@admin_required
def create_device(
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

    if device.work_center_id:
        work_center = db.query(WorkCentre).filter(WorkCentre.work_centre_id == device.work_center_id).first()
        if not work_center:
            raise HTTPException(status_code=400, detail="Invalid work_center_id: Work center does not exist.")

    try:
        new_device = Device(
            serial_number=device.serial_number,
            model=device.model,
            location=device.location,
            work_center_id=device.work_center_id,
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
@admin_required
def list_devices(
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
        if active_assignment and active_assignment.user:
            user_id = active_assignment.user.user_id
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
                model=cast(Optional[str], device.model),
                status=cast(DeviceStatus, device.status),
                last_communication=cast(Optional[datetime], device.last_communication),
                location=cast(Optional[str], device.location),
                work_center_id=cast(Optional[int], device.work_center_id),
                created_at=cast(datetime, device.created_at),
                updated_at=cast(datetime, device.updated_at or device.created_at),
                active=cast(bool, device.active),
                work_order_count=work_order_count,
            )
        )

    return out

@device_router.put("/{device_id}", response_model=DeviceResponse)
@admin_required
def update_device(
    device_id: int, 
    payload: DeviceUpdate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update the details of a device by device ID.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    for field, value in payload.dict(exclude_unset=True).items():
        setattr(device, field, value)

    # Use SQLAlchemy update instead of direct assignment
    db.query(Device).filter(Device.device_id == device_id).update(
        {"updated_at": datetime.utcnow()},
        synchronize_session="fetch"
    )
    db.commit()
    db.refresh(device)
    return _device_to_response(device)

@device_router.post(
    "/{device_id}/assign",
    response_model=DeviceAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
)
@admin_required
def assign_device(
    device_id: int,
    payload: DeviceAssignmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # 1. Validate input
    if not payload.user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    # 2. Check if device exists
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # 3. Check if device is already assigned to someone (and active)
    existing_assignment = db.query(DeviceAssignment).filter(
        DeviceAssignment.device_id == device_id,
        DeviceAssignment.active == True
    ).first()
    if existing_assignment:
        raise HTTPException(
            status_code=400,
            detail=f"Device {device_id} is already assigned to another user."
        )

    # 4. Check if user already has a device assigned
    user_has_device = db.query(DeviceAssignment).filter(
        DeviceAssignment.user_id == payload.user_id,
        DeviceAssignment.active == True
    ).first()
    if user_has_device:
        raise HTTPException(
            status_code=400,
            detail=f"User {payload.user_id} already has a device assigned."
        )

    # 5. Load user with roles
    user = (
        db.query(User)
        .options(joinedload(User.roles).joinedload(UserRole.role))
        .filter(User.user_id == payload.user_id)
        .first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

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
        user_id=payload.user_id,
        role=user_role,
        assigned_by_user_id=current_user.user_id,
        assigned_by_role=assigned_by_role,
        status="ASSIGNED",
        active=True,
        assigned_at=datetime.utcnow()
    )

    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    return DeviceAssignmentResponse.from_orm(assignment)

@device_router.get("/{device_id}/assignments", response_model=List[DeviceAssignmentResponse])
@admin_required
def list_assignments(
    device_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    assignments = db.query(DeviceAssignment).filter(DeviceAssignment.device_id == device_id).all()

    if not assignments:
        raise HTTPException(status_code=404, detail="No assignments found for this device")

    return [DeviceAssignmentResponse.from_orm(a) for a in assignments]



@device_router.patch("/{device_id}/block", status_code=200)
@admin_required
def block_or_unblock_device(
    device_id: int,
    request: BlockDeviceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    # What status are we moving to?
    target_status = DeviceStatus.BLOCKED if request.block else DeviceStatus.ACTIVE
    if cast(DeviceStatus, device.status) == target_status:
        return {"message": f"Device already {target_status.value.lower()}"}

    # ── 1. audit – omitted here for brevity ────────────────────────────

    # ── 2. update the device itself using SQLAlchemy update ────────────────────────────────────
    db.query(Device).filter(Device.device_id == device_id).update(
        {
            "status": target_status,
            "active": target_status == DeviceStatus.ACTIVE
        },
        synchronize_session="fetch"
    )

    # ── 3. cascade to assignments ──────────────────────────────────────
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
        "device_id": device_id,
        "new_status": target_status,
        "message": "Device blocked" if request.block else "Device unblocked",
    }

@device_router.post(
    "/{device_id}/deactivate",
    status_code=status.HTTP_200_OK
)
@admin_required
def deactivate_device(
    device_id: int,
    reason: str = Query("", max_length=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    if cast(DeviceStatus, device.status) == DeviceStatus.DEACTIVATED:
        return {"message": "Device already deactivated"}

    # 1. Create audit entry
    audit = DeviceStatusAudit(
        device_id=device.device_id,
        status_before=device.status,
        status_after=DeviceStatus.DEACTIVATED,
        reason=reason,
        changed_by_user_id=current_user.user_id,
    )
    db.add(audit)

    # 2. Deactivate the device
    db.query(Device).filter(Device.device_id == device_id).update(
        {
            "status": DeviceStatus.DEACTIVATED,
            "active": False,
            "updated_at": datetime.utcnow()
        },
        synchronize_session="fetch"
    )

    # 3. Deactivate all device assignments
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

    # 4. Get all agents linked to this device
    agent_ids = [
        row[0] for row in db.query(DeviceAssignment.user_id)
        .filter(DeviceAssignment.device_id == device_id, DeviceAssignment.active == False)
        .all()
    ]

    # 5. Get pending/in-progress work orders assigned to these agents
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

    # 6. Get available replacement devices
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
        "message": f"Device {device_id} deactivated successfully.",
        "pending_work_orders": pending_work_orders,
        "available_devices": available_devices_response
    }

@device_router.post("/{device_id}/activate", status_code=200)
@admin_required
def activate_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    if cast(DeviceStatus, device.status) == DeviceStatus.ACTIVE:
        return {"message": "Device is already active"}

    if cast(DeviceStatus, device.status) != DeviceStatus.DEACTIVATED:
        raise HTTPException(400, detail="Only deactivated devices can be activated")

    # Optional: validate assignments or health logs here

    # Update status using SQLAlchemy update
    db.query(Device).filter(Device.device_id == device_id).update(
        {
            "status": DeviceStatus.ACTIVE,
            "active": True,
            "updated_at": datetime.utcnow()
        },
        synchronize_session="fetch"
    )

    # Log audit
    audit = DeviceStatusAudit(
        device_id=device.device_id,
        status_before=device.status,
        status_after=DeviceStatus.ACTIVE,
        reason="Manual reactivation",
        changed_by_user_id=current_user.user_id
    )
    db.add(audit)

    db.commit()

    return {"message": f"Device {device_id} activated successfully"}


def _device_to_response(device: Device) -> DeviceResponse:
    # Get current active assignment
    assignment = next(
        (a for a in device.assignments if a.active and a.unassigned_at is None),
        None,
    )

    agent = assignment.user if assignment else None

    # Count active work orders assigned to the same user
    open_statuses = {"PENDING", "ASSIGNED", "IN_PROGRESS"}
    work_order_count = 0

    if agent:
        work_order_count = sum(
            1
            for woa in agent.agent_work_order_assignments
            if woa.active and woa.work_order and woa.work_order.status.name in open_statuses
        )

    return DeviceResponse(
        device_id=cast(int, device.device_id),
        serial_number=cast(str, device.serial_number),
        model=cast(Optional[str], device.model),
        status=cast(DeviceStatus, device.status),
        last_communication=cast(Optional[datetime], device.last_communication),
        location=cast(Optional[str], device.location),
        work_center_id=cast(Optional[int], device.work_center_id),
        created_at=cast(datetime, device.created_at),
        updated_at=cast(datetime, device.updated_at or device.created_at),
        active=cast(bool, device.active),
        work_order_count=work_order_count,
    )