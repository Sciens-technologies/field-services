from datetime import datetime
from typing import Optional, cast, List, Any
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Body,
    Request,
    Response,
    Path,
)
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, select, update, func
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel
from sqlalchemy.sql.schema import Column as SAColumn
from fastapi.responses import JSONResponse
import asyncio

from db.database import get_db
from db.models import (
    WorkOrder,
    WorkOrderAssignment,
    User,
    UserActivityLog,
    WorkOrderStatusLog,
)
from api.schemas import (
    WorkOrderAssignmentCreate,
    WorkOrderAssignmentResponse,
    WorkOrderStatus,
    WorkOrderDetailResponse,
    WorkOrderStatusLogResponse,
)
from auth.auth import get_current_user
from api.services.users import get_user_roles

router = APIRouter(prefix="/work-orders", tags=["work-orders"])


# Additional schemas for reassignment and acknowledgment
class WorkOrderReassignmentCreate(BaseModel):
    agent_id: int
    subject: Optional[str] = None
    reassignment_reason: Optional[str] = None


class WorkOrderAcknowledgmentCreate(BaseModel):
    status: str
    remarks: Optional[str] = None


class WorkOrderStartRequest(BaseModel):
    work_order_id: int


class WorkOrderStartResponse(BaseModel):
    work_order_id: int
    wo_number: str
    status: str
    updated_at: datetime
    message: str


@router.post(
    "/assign",
    response_model=WorkOrderAssignmentResponse,
    summary="Assign a work order to an agent",
    description="Assigns a work order to a specified agent. The work order must be in PENDING or NEW status.",
    status_code=status.HTTP_201_CREATED,
)
async def assign_work_order(
    assignment: WorkOrderAssignmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Assign a work order to an agent.

    Args:
        assignment: The work order assignment details (work_order_id and agent_id)
        current_user: Currently authenticated user (will be used as assigned_by)
        db: Database session

    Returns:
        WorkOrderAssignmentResponse: The created assignment

    Raises:
        HTTPException: If work order or agent not found, or if work order status is invalid
    """
    try:
        # Validate input: require either work_order_id or wo_number
        if not getattr(assignment, "work_order_id", None) and not getattr(
            assignment, "wo_number", None
        ):
            raise HTTPException(
                status_code=422,
                detail="Either work_order_id or wo_number must be provided.",
            )
        # Lookup work order by ID or wo_number
        work_order = None
        if getattr(assignment, "work_order_id", None):
            stmt = select(WorkOrder).where(
                and_(
                    WorkOrder.work_order_id == assignment.work_order_id,
                    WorkOrder.active.is_(True),
                )
            )
            work_order = db.execute(stmt).scalar_one_or_none()
        if not work_order:
            raise HTTPException(
                status_code=404, detail="Work order not found or inactive"
            )
        work_order_status = db.scalar(
            select(WorkOrder.status).where(
                WorkOrder.work_order_id == work_order.work_order_id
            )
        )
        # Only allow assignment if status is PENDING or NEW
        if work_order_status not in [WorkOrderStatus.PENDING, "NEW"]:
            raise HTTPException(
                status_code=400,
                detail="Work order must be in PENDING or NEW status to assign",
            )
        # Validate agent
        stmt = select(User).where(
            and_(User.user_id == assignment.agent_id, User.activated.is_(True))
        )
        agent = db.execute(stmt).scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found or inactive")
        # Check agent's active (IN_PROGRESS) assignments
        active_count = db.scalar(
            select(func.count())
            .select_from(WorkOrderAssignment)
            .join(
                WorkOrder, WorkOrderAssignment.work_order_id == WorkOrder.work_order_id
            )
            .where(
                and_(
                    WorkOrderAssignment.agent_id == assignment.agent_id,
                    WorkOrderAssignment.active.is_(True),
                    WorkOrder.status == WorkOrderStatus.IN_PROGRESS,
                )
            )
        )
        if active_count is None:
            active_count = 0
        if active_count >= 5:
            raise HTTPException(
                status_code=400,
                detail="Agent already has 5 active (IN_PROGRESS) work orders",
            )
        # Check for existing active assignment
        stmt = select(WorkOrderAssignment).where(
            and_(
                WorkOrderAssignment.work_order_id == work_order.work_order_id,
                WorkOrderAssignment.active.is_(True),
            )
        )
        existing_assignment = db.execute(stmt).scalar_one_or_none()
        if existing_assignment:
            raise HTTPException(
                status_code=400, detail="Work order already has an active assignment"
            )
        # Create assignment
        new_assignment = WorkOrderAssignment(
            work_order_id=work_order.work_order_id,
            agent_id=assignment.agent_id,
            assigned_by=current_user.user_id,
            reassigned=False,
            assigned_at=datetime.utcnow(),
            status="PENDING",
            active=True,
        )
        db.add(new_assignment)
        # Log activity
        log = UserActivityLog(
            user_id=assignment.agent_id,
            actor_id=current_user.user_id,
            action="assign_work_order",
            details=f"Assigned work order {work_order.wo_number} to agent {assignment.agent_id}",
            timestamp=datetime.utcnow(),
        )
        db.add(log)
        db.commit()
        db.refresh(new_assignment)
        assignment_dict = new_assignment.__dict__
        return WorkOrderAssignmentResponse(
            assignment_id=assignment_dict["assignment_id"],
            work_order_id=assignment_dict["work_order_id"],
            wo_number=str(work_order.wo_number),
            agent_id=assignment_dict["agent_id"],
            reassigned=assignment_dict["reassigned"],
            assigned_at=assignment_dict["assigned_at"],
            status=assignment_dict["status"],
            active=assignment_dict["active"],
        )
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid reference in request")
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.put(
    "/{assignment_id}/reassign",
    response_model=WorkOrderAssignmentResponse,
    summary="Reassign a work order to a different agent",
    description="Reassigns a work order from its current agent to a new agent. The work order must be in PENDING, NEW, or REJECTED status.",
    status_code=status.HTTP_200_OK,
)
async def reassign_work_order(
    assignment_id: int,
    reassignment: WorkOrderReassignmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Reassign a work order to a different agent.

    Args:
        assignment_id: The ID of the current assignment
        reassignment: The reassignment details (new agent_id and optional reason)
        current_user: Currently authenticated user (will be used as assigned_by)
        db: Database session

    Returns:
        WorkOrderAssignmentResponse: The new assignment

    Raises:
        HTTPException: If work order or agent not found, or if work order status is invalid
    """
    try:
        # Try to get active assignment first
        stmt = select(WorkOrderAssignment).where(
            and_(
                WorkOrderAssignment.assignment_id == assignment_id,
                WorkOrderAssignment.active.is_(True),
            )
        )
        current_assignment = db.execute(stmt).scalar_one_or_none()

        # If not found, try to get the assignment by id (even if inactive)
        if not current_assignment:
            stmt = select(WorkOrderAssignment).where(
                WorkOrderAssignment.assignment_id == assignment_id
            )
            current_assignment = db.execute(stmt).scalar_one_or_none()

        # If still not found, try to get the most recent REJECTED assignment for the same work_order
        if not current_assignment:
            # Find the most recent REJECTED assignment for this work order
            stmt = (
                select(WorkOrderAssignment)
                .where(
                    and_(
                        WorkOrderAssignment.work_order_id
                        == assignment_id,  # fallback: assignment_id is work_order_id
                        WorkOrderAssignment.status == "REJECTED",
                    )
                )
                .order_by(WorkOrderAssignment.assigned_at.desc())
            )
            current_assignment = db.execute(stmt).scalar_one_or_none()

        if not current_assignment:
            raise HTTPException(
                status_code=404, detail="No assignment found to reassign"
            )

        # Get work order
        work_order = (
            db.query(WorkOrder)
            .options(
                joinedload(WorkOrder.assignments), joinedload(WorkOrder.status_logs)
            )
            .filter(
                WorkOrder.work_order_id == current_assignment.work_order_id,
                WorkOrder.active.is_(True),
            )
            .first()
        )
        if not work_order:
            raise HTTPException(status_code=404, detail="Work order not found")

        # Get work order status
        work_order_status = db.scalar(
            select(WorkOrder.status).where(
                WorkOrder.work_order_id == work_order.work_order_id
            )
        )
        # Only allow reassignment if status is PENDING, NEW, or REJECTED
        if work_order_status not in [
            WorkOrderStatus.PENDING,
            "NEW",
            WorkOrderStatus.REJECTED,
            "REJECTED",
        ]:
            raise HTTPException(
                status_code=400,
                detail="Work order must be in PENDING, NEW, or REJECTED status to reassign",
            )

        # Check if current assignment is already ACCEPTED - prevent reassignment of accepted work orders
        current_assignment_status = db.scalar(
            select(WorkOrderAssignment.status).where(
                WorkOrderAssignment.assignment_id == current_assignment.assignment_id
            )
        )
        if current_assignment_status == "ACCEPTED":
            raise HTTPException(
                status_code=400,
                detail="Cannot reassign work order that has been acknowledged as ACCEPTED. Only REJECTED work orders can be reassigned.",
            )

        # Only allow reassignment of PENDING or REJECTED assignments
        if current_assignment_status not in ["PENDING", "REJECTED"]:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot reassign work order with assignment status '{current_assignment_status}'. Only PENDING or REJECTED assignments can be reassigned.",
            )

        # Validate new agent
        stmt = select(User).where(
            and_(User.user_id == reassignment.agent_id, User.activated.is_(True))
        )
        agent = db.execute(stmt).scalar_one_or_none()
        if not agent:
            raise HTTPException(
                status_code=404, detail="New agent not found or inactive"
            )

        # Check agent's active (IN_PROGRESS) assignments
        active_count = db.scalar(
            select(func.count())
            .select_from(WorkOrderAssignment)
            .join(
                WorkOrder, WorkOrderAssignment.work_order_id == WorkOrder.work_order_id
            )
            .where(
                and_(
                    WorkOrderAssignment.agent_id == reassignment.agent_id,
                    WorkOrderAssignment.active.is_(True),
                    WorkOrder.status == WorkOrderStatus.IN_PROGRESS,
                )
            )
        )
        if active_count is None:
            active_count = 0
        if active_count >= 5:
            raise HTTPException(
                status_code=400,
                detail="Agent already has 5 active (IN_PROGRESS) work orders",
            )

        # Get current agent ID
        current_agent_id = db.scalar(
            select(WorkOrderAssignment.agent_id).where(
                WorkOrderAssignment.assignment_id == current_assignment.assignment_id
            )
        )

        # Prevent reassignment to same agent
        if current_agent_id == reassignment.agent_id:
            raise HTTPException(
                status_code=400, detail="Cannot reassign to the same agent"
            )

        # Create new assignment
        new_assignment = WorkOrderAssignment(
            work_order_id=current_assignment.work_order_id,
            agent_id=reassignment.agent_id,
            assigned_by=current_user.user_id,
            reassigned=True,
            subject=reassignment.subject,
            reassignment_reason=reassignment.reassignment_reason,
            assigned_at=datetime.utcnow(),
            status="PENDING",
            active=True,
        )
        db.add(new_assignment)

        # Deactivate current assignment
        update_stmt = (
            update(WorkOrderAssignment)
            .where(
                WorkOrderAssignment.assignment_id == current_assignment.assignment_id
            )
            .values(active=False)
        )
        db.execute(update_stmt)

        # Log activity with reassignment reason
        log = UserActivityLog(
            user_id=reassignment.agent_id,
            actor_id=current_user.user_id,
            action="reassign_work_order",
            details=f"Reassigned work order {work_order.wo_number} from agent {current_agent_id} to agent {reassignment.agent_id}. Reason: {reassignment.reassignment_reason or ''}",
            timestamp=datetime.utcnow(),
        )
        db.add(log)

        db.commit()
        db.refresh(new_assignment)

        # Convert model to response schema
        assignment_dict = new_assignment.__dict__
        return WorkOrderAssignmentResponse(
            assignment_id=assignment_dict["assignment_id"],
            work_order_id=assignment_dict["work_order_id"],
            wo_number=str(work_order.wo_number),
            agent_id=assignment_dict["agent_id"],
            reassigned=assignment_dict["reassigned"],
            assigned_at=assignment_dict["assigned_at"],
            status=assignment_dict["status"],
            active=assignment_dict["active"],
        )

    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Invalid reference in request")
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/{work_order_id}/acknowledge",
    response_model=WorkOrderAssignmentResponse,
    summary="Acknowledge a work order assignment",
    description="Allows an agent to acknowledge their assigned work order. This updates the assignment status to 'ACCEPTED' or 'REJECTED' and optionally records remarks.",
    status_code=status.HTTP_200_OK,
)
async def acknowledge_work_order(
    work_order_id: int,
    acknowledgment: WorkOrderAcknowledgmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Acknowledge a work order assignment.

    Args:
        work_order_id: The ID of the work order to acknowledge
        acknowledgment: The acknowledgment details (status and optional remarks)
        current_user: Currently authenticated user (must be the assigned agent)
        db: Database session

    Returns:
        WorkOrderAssignmentResponse: The updated assignment

    Raises:
        HTTPException: If work order not found, or if user is not the assigned agent
    """
    try:
        # Validate status
        valid_statuses = {"ACCEPTED", "REJECTED"}
        status_value = acknowledgment.status.upper() if acknowledgment.status else None
        if status_value not in valid_statuses:
            raise HTTPException(
                status_code=422,
                detail="Status must be either 'ACCEPTED' or 'REJECTED'.",
            )
        if status_value == "REJECTED" and (
            not acknowledgment.remarks or not acknowledgment.remarks.strip()
        ):
            raise HTTPException(
                status_code=422,
                detail="Remarks are required when status is 'REJECTED'.",
            )

        # Get the work order first to check if it exists and is active
        work_order = (
            db.query(WorkOrder)
            .filter(
                WorkOrder.work_order_id == work_order_id, WorkOrder.active.is_(True)
            )
            .first()
        )
        if not work_order:
            raise HTTPException(
                status_code=404, detail="Work order not found or inactive"
            )

        # Get the active assignment for this work order
        assignment = (
            db.query(WorkOrderAssignment)
            .filter(
                WorkOrderAssignment.work_order_id == work_order_id,
                WorkOrderAssignment.active.is_(True),
            )
            .first()
        )
        if not assignment:
            raise HTTPException(
                status_code=404, detail="No active assignment found for this work order"
            )

        # Get the agent_id as a plain value directly from the database
        agent_id_value = db.scalar(
            select(WorkOrderAssignment.agent_id).where(
                WorkOrderAssignment.assignment_id == assignment.assignment_id
            )
        )
        if agent_id_value is None:
            raise HTTPException(
                status_code=500, detail="Assignment agent_id is not a valid value"
            )
        if not isinstance(agent_id_value, int):
            raise HTTPException(
                status_code=500, detail="Assignment agent_id is not an integer value"
            )
        if agent_id_value != int(current_user.user_id):  # type: ignore
            raise HTTPException(
                status_code=403,
                detail="Only the assigned agent can acknowledge this work order",
            )

        # Check if the work order is already acknowledged
        if assignment.status in ["ACCEPTED", "REJECTED"]:
            raise HTTPException(
                status_code=400,
                detail=f"Work order is already {assignment.status.lower()}",
            )

        # Get work order status
        work_order_status = db.scalar(
            select(WorkOrder.status).where(
                WorkOrder.work_order_id == work_order.work_order_id
            )
        )

        # Update assignment status and deactivate if rejected
        update_values = {"status": status_value, "updated_at": datetime.utcnow()}
        if status_value == "REJECTED":
            update_values["active"] = False

        update_stmt = (
            update(WorkOrderAssignment)
            .where(WorkOrderAssignment.assignment_id == assignment.assignment_id)
            .values(**update_values)
        )
        db.execute(update_stmt)

        # Log activity
        log = UserActivityLog(
            user_id=current_user.user_id,
            actor_id=current_user.user_id,
            action="acknowledge_work_order",
            details=f"Acknowledged work order {work_order.wo_number} with status {status_value}. Remarks: {acknowledgment.remarks or 'None'}",
            timestamp=datetime.utcnow(),
        )
        db.add(log)

        db.commit()
        db.refresh(assignment)

        # Convert model to response schema
        assignment_dict = assignment.__dict__
        return WorkOrderAssignmentResponse(
            assignment_id=assignment_dict["assignment_id"],
            work_order_id=assignment_dict["work_order_id"],
            wo_number=str(work_order.wo_number),
            agent_id=assignment_dict["agent_id"],
            reassigned=assignment_dict["reassigned"],
            assigned_at=assignment_dict["assigned_at"],
            status=status_value,
            active=assignment_dict["active"],
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/{work_order_id}",
    response_model=WorkOrderDetailResponse,
    summary="Get details of a work order",
    description="Retrieves detailed information about a work order, including its assignments and status logs.",
    status_code=status.HTTP_200_OK,
)
async def get_work_order(work_order_id: int, db: Session = Depends(get_db)):
    """
    Get details of a work order.

    Args:
        work_order_id: The ID of the work order to retrieve
        db: Database session

    Returns:
        WorkOrderDetailResponse: The detailed information about the work order

    Raises:
        HTTPException: If work order not found
    """
    try:
        work_order = (
            db.query(WorkOrder)
            .options(
                joinedload(WorkOrder.assignments), joinedload(WorkOrder.status_logs)
            )
            .filter(
                WorkOrder.work_order_id == work_order_id, WorkOrder.active.is_(True)
            )
            .first()
        )
        if not work_order:
            raise HTTPException(status_code=404, detail="Work order not found")

        assignments = (
            db.query(WorkOrderAssignment)
            .filter(
                WorkOrderAssignment.work_order_id == work_order_id,
                WorkOrderAssignment.active.is_(True),
            )
            .all()
        )

        status_logs = (
            db.query(WorkOrderStatusLog)
            .filter(WorkOrderStatusLog.work_order_id == work_order_id)
            .all()
        )

        assignment_responses = [
            WorkOrderAssignmentResponse(
                assignment_id=int(getattr(a, "assignment_id")),
                work_order_id=int(getattr(a, "work_order_id")),
                wo_number=str(getattr(work_order, "wo_number")),
                agent_id=int(getattr(a, "agent_id")),
                reassigned=bool(getattr(a, "reassigned")),
                assigned_at=getattr(a, "assigned_at"),
                status=str(getattr(a, "status"))
                if getattr(a, "status") is not None
                else None,
                active=bool(getattr(a, "active")),
            )
            for a in assignments
        ]

        status_log_responses = [
            WorkOrderStatusLogResponse(
                status_log_id=int(getattr(s, "status_log_id")),
                status=str(getattr(s, "status")),
                changed_at=getattr(s, "changed_at"),
                changed_by=int(getattr(s, "changed_by")),
            )
            for s in status_logs
        ]

        return WorkOrderDetailResponse(
            work_order_id=int(getattr(work_order, "work_order_id")),
            wo_number=str(getattr(work_order, "wo_number")),
            title=str(getattr(work_order, "title")),
            description=str(getattr(work_order, "description"))
            if getattr(work_order, "description") is not None
            else None,
            work_order_type=str(getattr(work_order, "work_order_type"))
            if getattr(work_order, "work_order_type") is not None
            else None,
            customer_id=str(getattr(work_order, "customer_id"))
            if getattr(work_order, "customer_id") is not None
            else None,
            customer_name=str(getattr(work_order, "customer_name"))
            if getattr(work_order, "customer_name") is not None
            else None,
            scheduled_date=getattr(work_order, "scheduled_date"),
            due_date=getattr(work_order, "due_date"),
            priority=str(getattr(work_order, "priority")),
            status=str(getattr(work_order, "status")),
            created_by=int(getattr(work_order, "created_by")),
            work_centre_id=int(getattr(work_order, "work_centre_id")),
            created_at=getattr(work_order, "created_at"),
            updated_at=getattr(work_order, "updated_at"),
            active=bool(getattr(work_order, "active")),
            assignments=assignment_responses,
            status_logs=status_log_responses,
        )
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
