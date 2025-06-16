from fastapi import APIRouter, Depends, HTTPException,Path,Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime
from db.database import get_db
from db.models import Device, WorkOrder, User, DeviceStatus,WorkCentre,WorkOrderAssignment,DeviceAssignment
from api.schemas import DeviceCreate, DeviceResponse,BlockDeviceRequest
from api.services.users import get_current_user
from typing import Optional
from sqlalchemy import or_
device_router = APIRouter()

# api/routers/device.py
from datetime import datetime
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
)
from api.schemas   import (
    DeviceCreate,
    DeviceUpdate,
    DeviceResponse,
    DeviceArtifactCreate,
    DeviceArtifactResponse,
    DeviceAssignmentCreate,
    DeviceAssignmentResponse,
)
from api.services.users    import admin_required, get_current_user

device_router = APIRouter()


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
            status=DeviceStatus.REGISTERED,
            active=True
        )
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        return new_device
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
    query = db.query(Device).filter(Device.active == True)

    if model:
        query = query.filter(Device.model.ilike(f"%{model}%"))

    if status_:
        try:
            status_enum = DeviceStatus(status_.upper())
        except ValueError:
            raise HTTPException(400, detail="Invalid device status")
        query = query.filter(Device.status == status_enum)

    if work_center_id:
        query = query.filter(Device.work_center_id == work_center_id)

    devices = query.options(joinedload(Device.work_center)).all()
    return [_device_to_response(db, d) for d in devices]


@device_router.put("/{device_id}", response_model=DeviceResponse, dependencies=[Depends(admin_required)])
def update_device(device_id: int, payload: DeviceUpdate, db: Session = Depends(get_db)):
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
    return _device_to_response(db, device)

@device_router.post("/{device_id}/assign", response_model=DeviceAssignmentResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(admin_required)])
def assign_device(device_id: int, payload: DeviceAssignmentCreate, db: Session = Depends(get_db)):
    """
    Assign a device to a user or a role.
    """
    if payload.user_id is None and payload.role is None:
        raise HTTPException(400, detail="Provide either user_id or role")

    assignment = DeviceAssignment(
        device_id=device_id,
        user_id=payload.user_id,
        role=payload.role,
        assigned_by_user_id=payload.assigned_by_user_id,
        assigned_by_role=payload.assigned_by_role,
        status="ASSIGNED",
        active=True,
    )
    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    return assignment

@device_router.get("/{device_id}/assignments", response_model=List[DeviceAssignmentResponse])
def list_assignments(device_id: int, db: Session = Depends(get_db)):
    """
    List active assignments for a specified device.
    """
    return (
        db.query(DeviceAssignment)
        .filter(DeviceAssignment.device_id == device_id,
                DeviceAssignment.active == True)
        .all()
    )

@device_router.post("/{device_id}/status", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(admin_required)])
def change_device_status(
    device_id: int,
    new_status: DeviceStatus = Query(...), 
    reason: str = Query("", max_length=500),
    current_admin: User = Depends(admin_required),
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
        status_after=new_status,
        reason=reason,
        changed_by_user_id=current_admin.user_id,
    )
    device.status = new_status
    device.updated_at = datetime.utcnow()

    db.add(audit)
    db.commit()

@device_router.patch("/{device_id}/block", status_code=200,
                     dependencies=[Depends(admin_required)])
def block_or_unblock_device(
    device_id: int,
    request: BlockDeviceRequest,
    db: Session = Depends(get_db),
    current_admin: User = Depends(admin_required),
):
    """
    Toggle a device between **ACTIVE** and **BLOCKED**.

    * Only an authenticated *admin* (checked by `admin_required`) may call this
      endpoint.
    * A short audit record is written each time the status changes.
    """

    
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

  
    target_status = "BLOCKED" if request.block else "ACTIVE"

    if device.status == target_status:
        return {
            "message": f"Device already {device.status.lower()}",
            "device_id": device.device_id,
            "status": device.status,
        }

    audit = DeviceStatusAudit(
        device_id         = device.device_id,
        status_before     = device.status,
        status_after      = target_status,
        reason            = request.reason,
        changed_by_user_id= current_admin.user_id,
    )
    db.add(audit)

    device.status     = target_status
    device.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(device)

    return {
        "message": f"Device status updated to {device.status}",
        "device_id": device.device_id,
        "status": device.status,
    }

def _device_to_response(db: Session, device: Device, work_order_count: int = 0) -> DeviceResponse:
    return DeviceResponse(
        device_id         = device.device_id,
        serial_number     = device.serial_number,
        model             = device.model,
        status            = device.status,
        last_communication= device.last_communication,
        location          = device.location,
        work_center_id    = device.work_center_id,
        created_at        = device.created_at,
        updated_at        = device.updated_at,
        active            = device.active,
        work_order_count  = work_order_count,
    )
