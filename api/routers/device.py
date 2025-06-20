from fastapi import APIRouter, Depends, HTTPException,Path,Query,Body
from sqlalchemy.orm import Session
from sqlalchemy import func,and_
from datetime import datetime
from db.database import get_db
from db.models import Device, WorkOrder, User, DeviceStatus,WorkCentre,WorkOrderAssignment,DeviceAssignment,WorkOrderStatus
from api.schemas import DeviceCreate, DeviceResponse,BlockDeviceRequest,DeactivateDevicePayload
from api.services.users import get_current_user
from typing import Optional, cast
from sqlalchemy import or_
from api.utils.util import trigger_device_block_notification, user_is_agent
from datetime import datetime as dt
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, joinedload

from db.database           import get_db
from db.models import (
    Device,
    DeviceArtifact,
    DeviceAssignment,
    DeviceStatusAudit,
    DeviceHealthLog,
    WorkOrderAssignment,
    WorkCentre,
    User,
    UserRole
)
from api.schemas   import (
    DeviceCreate,
    DeviceUpdate,
    DeviceResponse,
    DeviceArtifactCreate,
    DeviceArtifactResponse,
    DeviceAssignmentCreate,
    DeviceAssignmentResponse,
    DeviceAssignmentRole,
)
from api.services.users    import admin_required, get_current_user

device_router = APIRouter()

def map_user_role_to_assignment_role(user_role_name: str) -> str:
    """
    Map user role names to valid DeviceAssignmentRole enum values.
    Only TECHNICIAN, SUPERVISOR, and OTHER are valid in the database.
    """
    role_mapping = {
        "super_admin": "SUPERVISOR",
        "admin": "SUPERVISOR", 
        "technician": "TECHNICIAN",
        "supervisor": "SUPERVISOR",
        "manager": "SUPERVISOR",
        "warehouse": "OTHER",
        "agent": "TECHNICIAN",
    }
    return role_mapping.get(user_role_name.lower(), "OTHER")

@device_router.post("/devices", response_model=DeviceResponse)
def create_device(device: DeviceCreate, db: Session = Depends(get_db)):
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
            status=DeviceStatus.REGISTERED.value,
            active=True
        )
        db.add(new_device)
        db.commit()
        
        # Set updated_at after creation
        new_device.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(new_device)
        
        return DeviceResponse.from_orm(new_device)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Error creating device: {str(e)}")
    
@device_router.get("/", response_model=List[DeviceResponse])
def list_devices(
    model: Optional[str] = Query(None),
    status_: Optional[str] = Query(None, alias="status"),
    work_center_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """
    List all devices with optional filters for model, status, and work_center_id.
    """
    query = db.query(Device).filter(Device.active.is_(True))

    if model:
        query = query.filter(Device.model.ilike(f"%{model}%"))

    if status_:
        try:
            status_enum = DeviceStatus(status_.upper())
        except ValueError:
            raise HTTPException(400, detail="Invalid device status")
        query = query.filter(Device.status == status_enum.value)

    if work_center_id:
        query = query.filter(Device.work_center_id == work_center_id)

    devices = query.options(joinedload(Device.work_centre)).all()
    # Handle devices with None updated_at values
    for device in devices:
        if device.updated_at is None:
            device.updated_at = device.created_at or datetime.utcnow()
    
    return [DeviceResponse.from_orm(d) for d in devices]

@device_router.put("/{device_id}", response_model=DeviceResponse)
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    db: Session = Depends(get_db),
    # _: None = Depends(admin_required),  # ← this is correct
):

    """
    Update the details of a device by device ID.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    for field, value in payload.dict(exclude_unset=True).items():
        setattr(device, field, value)

    device.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(device)
    return DeviceResponse.from_orm(device)

@device_router.post(
    "/{device_id}/assign",
    response_model=DeviceAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def assign_device(
    device_id: int,
    payload: DeviceAssignmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    #  _: None = Depends(admin_required),
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

    # Get the user's primary role for assignment
    user_role = "TECHNICIAN"  # Default role
    if user.roles:
        # Get the first role name (you might want to prioritize certain roles)
        user_role_name = user.roles[0].role.role_name if user.roles[0].role else "TECHNICIAN"
        user_role = map_user_role_to_assignment_role(user_role_name)

    # 6. Get current user's role for assignment tracking
    current_user_roles = db.query(UserRole).filter(UserRole.user_id == current_user.user_id).all()
    assigned_by_role = "SUPERVISOR"  # Default role
    if current_user_roles:
        # Get the first role name (you might want to prioritize certain roles)
        assigned_by_role_name = current_user_roles[0].role.role_name if current_user_roles[0].role else "SUPERVISOR"
        assigned_by_role = map_user_role_to_assignment_role(assigned_by_role_name)

    # 6. Assign the device
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
def list_assignments(device_id: int, db: Session = Depends(get_db)):
    """
    List active assignments for a specified device.
    """
    assignments = (
        db.query(DeviceAssignment)
        .filter(DeviceAssignment.device_id == device_id,
                DeviceAssignment.active == True)
        .all()
    )
    return [
        DeviceAssignmentResponse.from_orm(a)
        for a in assignments
    ]

@device_router.post("/{device_id}/status", status_code=status.HTTP_200_OK)
@admin_required
async def change_device_status(
    device_id: int,
    new_status: DeviceStatus = Query(...), 
    reason: str = Query("", max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Change the status of a device and log the change in device status audit.
    """
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    audit = DeviceStatusAudit(
        device_id=device_id,
        status_before=device.status,
        status_after=new_status.value,
        reason=reason,
        changed_by_user_id=current_user.user_id,
    )
    device.status = new_status.value
    device.updated_at = datetime.utcnow()

    db.add(audit)
    db.commit()

    return {"message": "Device status updated successfully"}

@device_router.patch("/{device_id}/block", status_code=200)
@admin_required
async def block_or_unblock_device(
    device_id: int,
    request: BlockDeviceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1. Fetch device
    device = (
        db.query(Device)
        .filter(Device.device_id == device_id)
        .first()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    print("[DEBUG] Block request received for device_id =", device.device_id)
    print("[DEBUG] Device status before =", device.status)
    print("[DEBUG] Request block flag =", request.block)

    # 2. Determine target status
    target_status = DeviceStatus.BLOCKED.value if request.block else DeviceStatus.ACTIVE.value
    if device.status == target_status:
        return {
            "message": f"Device already {DeviceStatus(device.status).name.lower()}",
            "device_id": device.device_id,
            "status": DeviceStatus(device.status),
        }

    # 3. Audit
    audit = DeviceStatusAudit(
        device_id=device.device_id,
        status_before=device.status,
        status_after=target_status,
        reason=request.reason,
        changed_by_user_id=current_user.user_id,
    )
    db.add(audit)

    # 4. Update device
    device.status = target_status
    device.updated_at = datetime.utcnow()
    device.active = True if target_status == DeviceStatus.ACTIVE.value else False
    db.commit()
    db.refresh(device)

    # 5. Trigger notification
    if target_status == DeviceStatus.BLOCKED.value:
        try:
            trigger_device_block_notification(
                db=db,
                device=device,
                reason=request.reason,
                admin_user=current_user,
            )
            db.commit()
        except Exception as exc:
            db.rollback()
            print(f"[WARN] Notification failed: {exc}")

    # 6. Response
    return {
        "message": (
            "Device blocked successfully."
            if request.block else
            "Device unblocked successfully."
        ),
        "device_id": device.device_id,
        "timestamp": audit.changed_at.isoformat(),
        "reason": request.reason,
    }

@device_router.post(
    "/{device_id}/deactivate",
    status_code=status.HTTP_200_OK,
)
@admin_required
async def deactivate_device(
    device_id: int,
    reason: str = Query("", max_length=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    if device.status == DeviceStatus.DEACTIVATED.value:
        return {"message": "Device already deactivated"}

    audit = DeviceStatusAudit(
        device_id=device.device_id,
        status_before=device.status,
        status_after=DeviceStatus.DEACTIVATED.value,
        reason=reason,
        changed_by_user_id=current_user.user_id,
    )
    device.status = DeviceStatus.DEACTIVATED.value
    device.active = False
    device.updated_at = datetime.utcnow()

    open_wos = (
        db.query(WorkOrder)
        .filter(
            WorkOrder.device_id == device_id,
            WorkOrder.status.in_([
                WorkOrderStatus.PENDING.value,
                WorkOrderStatus.IN_PROGRESS.value
            ])
        )
        .all()
    )

    pending_work_orders = [
        {
            "work_order_id": wo.work_order_id,
            "wo_number": wo.wo_number,
            "status": wo.status
        }
        for wo in open_wos
    ]
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
    available_devices = db.query(Device).filter(
        Device.device_id != device_id,
        Device.active.is_(True),
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
async def activate_device(
    device_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, detail="Device not found")

    if device.status == DeviceStatus.ACTIVE.value:
        return {"message": "Device is already active"}

    if device.status != DeviceStatus.DEACTIVATED.value:
        raise HTTPException(400, detail="Only deactivated devices can be activated")

    # Optional: validate assignments or health logs here

    # Update status
    device.status = DeviceStatus.ACTIVE.value
    device.active = True
    device.updated_at = datetime.utcnow()

    # Log audit
    audit = DeviceStatusAudit(
        device_id=device.device_id,
        status_before=device.status,
        status_after=DeviceStatus.ACTIVE.value,
        changed_by_user_id=current_user.user_id,
        reason="Manual reactivation"
    )
    db.add(audit)

    db.commit()

    return {"message": f"Device {device_id} activated successfully"}

@device_router.post("/{device_id}/admin-approve", status_code=200)
@admin_required
async def approve_device_by_admin(device_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    if device.status != DeviceStatus.REGISTERED.value:
        raise HTTPException(400, detail="Only REGISTERED devices can be approved")

    device.status = DeviceStatus.READY_TO_ACTIVATE.value
    device.admin_approved_at = datetime.utcnow()
    db.commit()
    return {"message": f"Device {device_id} approved by admin and ready to activate."}



def _device_to_response(db: Session, device: Device, work_order_count: int = 0) -> DeviceResponse:
    return DeviceResponse(
        device_id=device.device_id,
        serial_number=device.serial_number,
        model=device.model,
        status=device.status,
        last_communication=device.last_communication,
        location=device.location,
        work_center_id=device.work_center_id,
        created_at=device.created_at,
        updated_at=device.updated_at,
        active=device.active,
        work_order_count=work_order_count,
    )
