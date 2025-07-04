from datetime import datetime
from typing import Optional, cast, List, Any, Union
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Body,
    Request,
    Response,
    Path,
    Query,
)
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, select, update, func, cast, String
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
    WorkOrderTemplate,
    WorkOrderStatus,
    UserRole,
    Role,
)
from api.schemas import (
    WorkOrderAssignmentCreate,
    WorkOrderAssignmentResponse,
    WorkOrderStatus,
    WorkOrderDetailResponse,
    WorkOrderStatusLogResponse,
    AssignedWorkOrdersResponse,
)
from auth.auth import get_current_user
from api.services.users import get_user_roles, role_required

router = APIRouter(prefix="/work-orders", tags=["work-orders"])


# Additional schemas for reassignment and acknowledgment
class WorkOrderReassignmentCreate(BaseModel):
    agent_email: str
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


class WorkOrderStatusChangeRequest(BaseModel):
    new_status: str
    remarks: Optional[str] = None


@router.get("/status-summary")
@role_required(["admin", "super_admin", "supervisor"])
async def work_order_status_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get a summary of work orders by status (pending, in progress, completed, etc.).
    Always returns all statuses, even if their count is zero.
    Also returns the total number of work orders as 'total_workorders'.
    """
    # Step 1: Get all possible statuses
    all_statuses = [status.value for status in WorkOrderStatus]

    # Step 2: Initialize all counts to 0
    status_counts = {status: 0 for status in all_statuses}

    # Step 3: Query actual counts from the database
    db_counts = (
        db.query(WorkOrder.status, func.count(WorkOrder.work_order_id))
        .group_by(WorkOrder.status)
        .all()
    )
    for status, count in db_counts:
        # If status is an enum, use .value, else use as is
        key = status.value if hasattr(status, 'value') else str(status)
        status_counts[key] = count

    # Step 6: Return only the status counts (no total_workorders or total_field_agents)
    return status_counts


@router.get("/list", response_model=List[WorkOrderDetailResponse])
@role_required(["admin", "super_admin", "supervisor"])
async def get_all_work_orders(
    category: Optional[str] = None,
    priority: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get all work orders, optionally filtered by category, priority, and status.
    """
    try:
        query = db.query(WorkOrder).filter(WorkOrder.active.is_(True))
        if category:
            # Join with WorkOrderTemplate to filter by template category
            query = query.join(WorkOrderTemplate, WorkOrder.template_id == WorkOrderTemplate.template_id)
            query = query.filter(WorkOrderTemplate.category.ilike(category))
        if priority:
            query = query.filter(WorkOrder.priority.ilike(priority))
        if status:
            query = query.filter(WorkOrder.status.ilike(status))
        work_orders = query.all()
        result = []
        for work_order in work_orders:
            # Fetch template to get category
            template = None
            template_id = getattr(work_order, 'template_id', None)
            if template_id is not None:
                template = db.query(WorkOrderTemplate).filter_by(template_id=template_id).first()
            category_val = getattr(template, 'category', 'ZDEV') if template else 'ZDEV'

            # Get assignments and status logs
            assignments = db.query(WorkOrderAssignment).filter(
                WorkOrderAssignment.work_order_id == work_order.work_order_id,
                WorkOrderAssignment.active.is_(True),
            ).all()
            status_logs = db.query(WorkOrderStatusLog).filter(
                WorkOrderStatusLog.work_order_id == work_order.work_order_id
            ).all()
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
                    active=True if getattr(a, "active", None) in (True, 1) else False,
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
            result.append(WorkOrderDetailResponse(
                work_order_id=int(getattr(work_order, "work_order_id")),
                wo_number=str(getattr(work_order, "wo_number")),
                title=str(getattr(work_order, "title")),
                description=str(getattr(work_order, "description")) if getattr(work_order, "description") is not None else None,
                work_order_type=str(getattr(work_order, "work_order_type")) if getattr(work_order, "work_order_type") is not None else None,
                customer_id=str(getattr(work_order, "customer_id")) if getattr(work_order, "customer_id") is not None else None,
                customer_name=str(getattr(work_order, "customer_name")) if getattr(work_order, "customer_name") is not None else None,
                scheduled_date=getattr(work_order, "scheduled_date"),
                due_date=getattr(work_order, "due_date"),
                priority=str(getattr(work_order, "priority")),
                status=str(getattr(work_order, "status")),
                created_by=int(getattr(work_order, "created_by")),
                work_centre_id=int(getattr(work_order, "work_centre_id")),
                created_at=getattr(work_order, "created_at"),
                updated_at=getattr(work_order, "updated_at"),
                active=True if getattr(work_order, "active", None) in (True, 1) else False,
                assignments=assignment_responses,
                status_logs=status_log_responses,
                category=category_val
            ))
        return result
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/assign",
    response_model=WorkOrderAssignmentResponse,
    summary="Assign a work order to an agent",
    description="Assigns a work order to a specified agent. The work order must be in PENDING or NEW status.",
    status_code=status.HTTP_201_CREATED,
)
@role_required(["admin", "super_admin", "supervisor"])
async def assign_work_order(
    assignment: WorkOrderAssignmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Assign a work order to an agent.

    Args:
        assignment: The work order assignment details (wo_number and agent_email)
        current_user: Currently authenticated user (will be used as assigned_by)
        db: Database session

    Returns:
        WorkOrderAssignmentResponse: The created assignment

    Raises:
        HTTPException: If work order or agent not found, or if work order status is invalid
    """
    try:
        # Require wo_number
        if not getattr(assignment, "wo_number", None):
            raise HTTPException(
                status_code=422,
                detail="wo_number must be provided.",
            )
        # Lookup work order by wo_number
        work_order = db.query(WorkOrder).filter(WorkOrder.wo_number == assignment.wo_number).first()
        if not work_order:
            raise HTTPException(
                status_code=404, detail="Work order not found"
            )
        # Only allow assignment if status is PENDING or REJECTED
        if work_order.status not in [WorkOrderStatus.PENDING, WorkOrderStatus.REJECTED]:
            raise HTTPException(
                status_code=400,
                detail="Work order must be in PENDING or REJECTED status to assign or reassign",
            )
        # Validate agent by email
        agent = db.query(User).filter(User.email == assignment.agent_email, User.activated.is_(True)).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found or inactive")
        agent_id = agent.user_id
        # Check agent's active (IN_PROGRESS) assignments
        active_count = db.scalar(
            select(func.count())
            .select_from(WorkOrderAssignment)
            .join(
                WorkOrder, WorkOrderAssignment.work_order_id == WorkOrder.work_order_id
            )
            .where(
                and_(
                    WorkOrderAssignment.agent_id == agent_id,
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
            agent_id=agent_id,
            assigned_by=current_user.user_id,
            reassigned=False,
            assigned_at=datetime.utcnow(),
            status="PENDING",
            active=True,
        )
        db.add(new_assignment)
        # Set work order status to IN_PROGRESS on assignment
        work_order.status = WorkOrderStatus.IN_PROGRESS.value  # type: ignore
        # Log activity
        log = UserActivityLog(
            user_id=agent_id,
            actor_id=current_user.user_id,
            action="assign_work_order",
            details=f"Assigned work order {work_order.wo_number} to agent {agent_id}",
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
@role_required(["admin", "super_admin", "supervisor"])
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
        reassignment: The reassignment details (new agent_email and optional reason)
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
            .filter(WorkOrder.work_order_id == current_assignment.work_order_id)
            .first()
        )
        if not work_order:
            raise HTTPException(status_code=404, detail="Work order not found")
        # Only allow reassignment if status is PENDING, NEW, or REJECTED
        status_val = getattr(work_order.status, 'value', work_order.status)
        if str(status_val).upper() not in ["PENDING", "NEW", "REJECTED"]:
            raise HTTPException(
                status_code=400,
                detail="Work order must be in PENDING, NEW, or REJECTED status to reassign",
            )
        # On reassignment, set status to IN_PROGRESS
        work_order.status = WorkOrderStatus.IN_PROGRESS.value  # type: ignore
        db.commit()

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
        agent = db.query(User).filter(User.email == reassignment.agent_email, User.activated.is_(True)).first()
        if not agent:
            raise HTTPException(
                status_code=404, detail="New agent not found or inactive"
            )
        agent_id = agent.user_id

        # Check agent's active (IN_PROGRESS) assignments
        active_count = db.scalar(
            select(func.count())
            .select_from(WorkOrderAssignment)
            .join(
                WorkOrder, WorkOrderAssignment.work_order_id == WorkOrder.work_order_id
            )
            .where(
                and_(
                    WorkOrderAssignment.agent_id == agent_id,
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
        if current_agent_id == agent_id:
            raise HTTPException(
                status_code=400, detail="Cannot reassign to the same agent"
            )

        # Create new assignment
        new_assignment = WorkOrderAssignment(
            work_order_id=current_assignment.work_order_id,
            agent_id=agent_id,
            assigned_by=current_user.user_id,
            reassigned=True,
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
            user_id=agent_id,
            actor_id=current_user.user_id,
            action="reassign_work_order",
            details=f"Reassigned work order {work_order.wo_number} from agent {current_agent_id} to agent {agent_id}. Reason: {reassignment.reassignment_reason or ''}",
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
    "/{wo_number}/acknowledge",
    response_model=WorkOrderAssignmentResponse,
    summary="Acknowledge a work order assignment",
    description="Allows an agent or supervisor to acknowledge a work order assignment. This updates the assignment status to 'ACCEPTED' or 'REJECTED' and optionally records remarks.",
    status_code=status.HTTP_200_OK,
)
@role_required(["admin", "super_admin", "supervisor", "agent"])
async def acknowledge_work_order(
    wo_number: str,
    acknowledgment: WorkOrderAcknowledgmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Find the work order
    work_order = db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
    if not work_order:
        raise HTTPException(status_code=404, detail="Work order not found")
    # Only allow if status is IN_PROGRESS
    if work_order.status != WorkOrderStatus.IN_PROGRESS.value: # type: ignore
        raise HTTPException(status_code=400, detail="Work order must be IN_PROGRESS to acknowledge")
    # Find the active assignment
    assignment = db.query(WorkOrderAssignment).filter(
        WorkOrderAssignment.work_order_id == work_order.work_order_id,
        WorkOrderAssignment.active == True
    ).first()
    if not assignment:
        raise HTTPException(status_code=404, detail="No active assignment found")
    # Only assigned agent or supervisor can acknowledge
    if current_user.user_id != assignment.agent_id and not any(role.role.role_name in ["super_admin", "admin", "supervisor"] for role in current_user.roles): # type: ignore
        raise HTTPException(status_code=403, detail="Only the assigned agent or supervisor can acknowledge")
    # If REJECTED, remarks required
    if acknowledgment.status == "REJECTED" and not acknowledgment.remarks:
        raise HTTPException(status_code=400, detail="Remarks required when rejecting a work order")
    # Update assignment and work order status (case-insensitive)
    status_upper = str(acknowledgment.status).upper()
    assignment.status = status_upper  # type: ignore
    if status_upper == "REJECTED":
        work_order.status = WorkOrderStatus.REJECTED.value  # type: ignore
    elif status_upper == "ACCEPTED":
        work_order.status = WorkOrderStatus.IN_PROGRESS.value  # type: ignore
    assignment.updated_at = datetime.utcnow()  # type: ignore
    db.commit()
    db.refresh(assignment)
    return WorkOrderAssignmentResponse(
        assignment_id=int(getattr(assignment, "assignment_id")),
        work_order_id=int(getattr(assignment, "work_order_id")),
        wo_number=str(getattr(work_order, "wo_number")),
        agent_id=int(getattr(assignment, "agent_id")),
        reassigned=bool(getattr(assignment, "reassigned")),
        assigned_at=getattr(assignment, "assigned_at"),
        status=str(getattr(assignment, "status")) if getattr(assignment, "status") is not None else None,
        active=True if getattr(assignment, "active", None) in (True, 1) else False,
    )


@router.get(
    "",
    response_model=Union[WorkOrderDetailResponse, AssignedWorkOrdersResponse],
    summary="Get details of a work order",
    description="Retrieves detailed information about a work order, including its assignments and status logs. Also returns all work orders assigned to the current user (agent). If wo_number is not provided, returns all assigned work orders only.",
    status_code=status.HTTP_200_OK,
)
@role_required(["admin", "super_admin", "supervisor", "agent"])
async def get_work_order(
    wo_number: Optional[str] = Query(None, description="wo_number of the work order to retrieve"),
    category: Optional[str] = Query(None, description="Filter by template category"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    status_: Optional[str] = Query(None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Define required fields at the start of the function
    required_fields = [
        'work_order_id', 'wo_number', 'title', 'priority', 'status', 'created_by', 'work_centre_id', 'created_at', 'updated_at', 'active'
    ]
    if wo_number:
        work_order = db.query(WorkOrder).filter_by(wo_number=wo_number).first()
        if not work_order:
            raise HTTPException(status_code=404, detail="Work order not found")
        for field in required_fields:
            if getattr(work_order, field, None) is None:
                raise HTTPException(status_code=500, detail=f"Work order missing required field: {field}")
        # Fetch category from related WorkOrderTemplate
        template = db.query(WorkOrderTemplate).filter_by(template_id=work_order.template_id).first()
        category_val = getattr(template, 'category', 'ZDEV') if template else 'ZDEV'
        work_order_detail = WorkOrderDetailResponse(
            work_order_id=getattr(work_order, 'work_order_id'),
            wo_number=getattr(work_order, 'wo_number'),
            title=getattr(work_order, 'title'),
            description=getattr(work_order, 'description', None),
            work_order_type=getattr(work_order, 'work_order_type', None),
            customer_id=getattr(work_order, 'customer_id', None),
            customer_name=getattr(work_order, 'customer_name', None),
            scheduled_date=getattr(work_order, 'scheduled_date', None),
            due_date=getattr(work_order, 'due_date', None),
            priority=getattr(work_order, 'priority'),
            status=getattr(work_order, 'status'),
            created_by=getattr(work_order, 'created_by'),
            work_centre_id=getattr(work_order, 'work_centre_id'),
            work_centre_name=getattr(work_order.work_centre, 'name', None) if hasattr(work_order, 'work_centre') and work_order.work_centre else None,
            created_at=getattr(work_order, 'created_at'),
            updated_at=getattr(work_order, 'updated_at'),
            active=getattr(work_order, 'active'),
            assignments=[],  # Fill with actual assignments if needed
            status_logs=[],  # Fill with actual status logs if needed
            category=category_val
        )
        return work_order_detail
    else:
        query = db.query(WorkOrder).join(WorkOrderAssignment).filter(
            WorkOrderAssignment.agent_id == current_user.user_id
        )
        if category:
            query = query.join(WorkOrderTemplate, WorkOrder.template_id == WorkOrderTemplate.template_id)
            query = query.filter(WorkOrderTemplate.category.ilike(category))
        if priority:
            query = query.filter(cast(WorkOrder.priority, String).ilike(priority))
        if status_:
            query = query.filter(cast(WorkOrder.status, String).ilike(status_))
        assignments = query.all()
        assigned_work_orders = []
        for wo in assignments:
            skip = False
            for field in required_fields:
                if getattr(wo, field, None) is None:
                    skip = True
                    break
            if skip:
                continue
            # Fetch category from related WorkOrderTemplate
            template = db.query(WorkOrderTemplate).filter_by(template_id=wo.template_id).first()
            category_val = getattr(template, 'category', 'ZDEV') if template else 'ZDEV'
            assigned_work_orders.append(WorkOrderDetailResponse(
                work_order_id=getattr(wo, 'work_order_id'),
                wo_number=getattr(wo, 'wo_number'),
                title=getattr(wo, 'title'),
                description=getattr(wo, 'description', None),
                work_order_type=getattr(wo, 'work_order_type', None),
                customer_id=getattr(wo, 'customer_id', None),
                customer_name=getattr(wo, 'customer_name', None),
                scheduled_date=getattr(wo, 'scheduled_date', None),
                due_date=getattr(wo, 'due_date', None),
                priority=getattr(wo, 'priority'),
                status=getattr(wo, 'status'),
                created_by=getattr(wo, 'created_by'),
                work_centre_id=getattr(wo, 'work_centre_id'),
                work_centre_name=getattr(wo.work_centre, 'name', None) if hasattr(wo, 'work_centre') and wo.work_centre else None,
                created_at=getattr(wo, 'created_at'),
                updated_at=getattr(wo, 'updated_at'),
                active=getattr(wo, 'active'),
                assignments=[],  # Fill with actual assignments if needed
                status_logs=[],  # Fill with actual status logs if needed
                category=category_val
            ))
        return AssignedWorkOrdersResponse(assigned_work_orders=assigned_work_orders)


# --- New endpoint to mark a work order as COMPLETED ---
@router.post("/{wo_number}/complete", summary="Mark work order as completed")
@role_required(["admin", "super_admin", "supervisor", "agent"])
async def complete_work_order(
    wo_number: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Mark a work order as COMPLETED. Only allowed if status is IN_PROGRESS.
    """
    work_order = db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
    if not work_order:
        raise HTTPException(status_code=404, detail="Work order not found")
    # Only allow completion if status is IN_PROGRESS
    if work_order.status != WorkOrderStatus.IN_PROGRESS.value: # type: ignore
        raise HTTPException(status_code=400, detail="Only IN_PROGRESS work orders can be completed")
    # Check if user is allowed: admin/super_admin/supervisor or assigned agent
    allowed_roles = {"admin", "super_admin", "supervisor"}
    user_roles = {role.role.role_name for role in current_user.roles}
    if not (user_roles & allowed_roles):
        # If not admin/super_admin/supervisor, check if agent is assigned
        assignment = db.query(WorkOrderAssignment).filter(
            WorkOrderAssignment.work_order_id == work_order.work_order_id,
            WorkOrderAssignment.active == True
        ).first()
        if assignment is None or assignment.agent_id != current_user.user_id: # type: ignore
            raise HTTPException(status_code=403, detail="Only the assigned agent or allowed roles can complete the work order")
    work_order.status = WorkOrderStatus.COMPLETED.value  # type: ignore
    db.commit()
    return {"detail": "Work order marked as COMPLETED"}
