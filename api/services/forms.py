from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import and_, select, update, func
from sqlalchemy.exc import IntegrityError
import uuid
import json
import os
from pathlib import Path

from db.models import (
    WorkOrder, WorkOrderTemplate, WorkOrderForm, WorkOrderFormData,
    WorkOrderFormStep, WorkOrderFormAttachment, WorkOrderFormSession,
    WorkOrderFormAudit, WorkOrderFormValidationLog, User
)
from api.schemas import (
    FormDataSaveRequest, FormDataSubmitRequest, FormSyncRequest,
    WorkOrderFormResponse, FormDataResponse, FormStepResponse,
    FormAttachmentResponse, FormSessionResponse, FormSyncResponse,
    InstallationFormSaveRequest
)
from sqlalchemy.sql.schema import Column

INSTALLATION_FORM_TYPES = [
    "LV Device Installation Form",
    "MV HV Device Installation Form",
    "LV device removal form",
    "MV HV Device Removal",
    "LV device replacement form",
    "MV HV Meter Replacement Form",
    "Circuit Breaker Replacement Form",
    "Voltage Transf Replacement Form",
    "Current Transf Replacement Form",
    "Modem Replacement Form",
    "Device Location Change Form",
    "Device Configuration Change Form",
    "Device Calibration Form",
    "Device Maintenance Form",
    "Device Testing Form",
    "Device Commissioning Form",
    "Device Decommissioning Form",
    "Device Troubleshooting Form",
    "Device Upgrade Form",
    "Device Migration Form"
]

def get_val(val):
    # Helper to extract value from SQLAlchemy Column or return as is
    if hasattr(val, 'value'):
        return val.value
    if hasattr(val, '__call__'):
        return val()
    return val

def ensure_dict(val):
    if isinstance(val, dict):
        return val
    if hasattr(val, 'items'):
        return dict(val)
    if isinstance(val, bytes):
        return json.loads(val.decode())
    return {}

def safe_datetime(val):
    # Return a datetime or now
    if val is None or isinstance(val, Column):
        return datetime.utcnow()
    return val

class FormService:
    def __init__(self, db: Session):
        self.db = db

    def get_work_order_template(self, work_order_id: int) -> WorkOrderFormResponse:
        """
        Get work order and its template for installation forms.
        """
        # Get work order
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get template
        template_id = getattr(work_order, 'template_id')
        template = self.db.query(WorkOrderTemplate).filter(
            WorkOrderTemplate.template_id == template_id
        ).first()
        if template is None:
            raise ValueError(f"Template not found for work order {work_order_id}")

        # Validate form type
        template_name = getattr(template, 'form_type')
        if template_name not in INSTALLATION_FORM_TYPES:
            raise ValueError(f"Form type '{template_name}' is not supported for installation forms")

        # Extract template data
        template_data = getattr(template, 'template')
        if template_data is None:
            template_data = {}

        return WorkOrderFormResponse(
            work_order_id=getattr(work_order, 'work_order_id'),
            work_order_type="INSTALLATION",
            form_type=template_name,
            template=template_data,
            form_data=None,
            steps=[],
            attachments=[],
            sessions=[]
        )

    def save_or_update_form_data(self, work_order_id: int, request: InstallationFormSaveRequest) -> WorkOrderFormResponse:
        """
        Save or update form data for a work order and return form details with template.
        """
        # Validate work order exists
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get form type from work order template
        template_id = getattr(work_order, 'template_id')
        template = self.db.query(WorkOrderTemplate).filter(
            WorkOrderTemplate.template_id == template_id
        ).first()
        form_type = getattr(template, 'form_type') if template else "Unknown"
        template_data = getattr(template, 'template') if template else {}
        total_steps = len(template_data.get('steps', [])) if template_data else 1

        # Get form by work_order_id
        form = self.db.query(WorkOrderForm).filter(WorkOrderForm.work_order_id == work_order_id).first()
        if form is None:
            # Create new form
            form = WorkOrderForm(
                work_order_id=work_order_id,
                work_order_type=form_type,
                template_id=template_id,
                status="PENDING",
                active=True
            )
            self.db.add(form)
            self.db.commit()
            self.db.refresh(form)

        # Check if form data already exists for this form_id and session_id
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.form_id == form.form_id,
            WorkOrderFormData.session_id == request.session_id
        ).first()

        # If session_id is missing or already exists for another form, generate a new one
        session_id_missing = request.session_id is None or request.session_id == ""
        session_id_duplicate = False
        if form_data is not None:
            session_id_duplicate = bool(form_data.form_id != form.form_id)
        if session_id_missing or session_id_duplicate:
            request.session_id = str(uuid.uuid4())
            form_data = None  # Force creation of new form data

        if form_data is None:
            # Create new form data
            form_data = WorkOrderFormData(
                form_id=form.form_id,
                session_id=request.session_id,
                form_type=form_type,
                current_step=request.current_step,
                progress=request.progress,
                data=request.data.dict() if hasattr(request.data, 'dict') else request.data,
                last_updated=datetime.utcnow(),
                active=True
            )
            self.db.add(form_data)
        else:
            # Update existing form data
            setattr(form_data, 'form_type', form_type)
            setattr(form_data, 'current_step', request.current_step)
            setattr(form_data, 'progress', request.progress)
            setattr(form_data, 'data', request.data.dict() if hasattr(request.data, 'dict') else request.data)
            setattr(form_data, 'last_updated', datetime.utcnow())

        self.db.commit()
        self.db.refresh(form_data)

        return WorkOrderFormResponse(
            work_order_id=work_order_id,
            work_order_type="INSTALLATION",
            form_type=form_type,
            template=template_data,
            form_data=FormDataResponse(
                formdata_id=getattr(form_data, 'formdata_id'),
                session_id=getattr(form_data, 'session_id'),
                data=getattr(form_data, 'data'),
                progress=getattr(form_data, 'progress'),
                status="COMPLETED" if getattr(form_data, 'progress', 0) >= 100 else "IN_PROGRESS",
                current_step=getattr(form_data, 'current_step'),
                form_type=getattr(form_data, 'form_type'),
                last_updated=getattr(form_data, 'last_updated'),
                active=getattr(form_data, 'active'),
            ),
            steps=[],
            attachments=[],
            sessions=[]
        )

    def get_form_data(self, work_order_id: int) -> Optional[FormDataResponse]:
        """
        Get saved form data for a work order.
        """
        # Validate work order exists
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get form by work_order_id
        form = self.db.query(WorkOrderForm).filter(WorkOrderForm.work_order_id == work_order_id).first()
        if form is None:
            return None

        # Get form data by form_id
        form_data = self.db.query(WorkOrderFormData).filter(WorkOrderFormData.form_id == form.form_id).first()
        if form_data is None:
            return None

        return FormDataResponse(
            formdata_id=getattr(form_data, 'formdata_id'),
            session_id=getattr(form_data, 'session_id'),
            data=getattr(form_data, 'data'),
            progress=getattr(form_data, 'progress'),
            status="COMPLETED" if getattr(form_data, 'progress', 0) >= 100 else "IN_PROGRESS",
            current_step=getattr(form_data, 'current_step'),
            form_type=getattr(form_data, 'form_type'),
            last_updated=getattr(form_data, 'last_updated'),
            active=getattr(form_data, 'active'),
        )

    def validate_form_type(self, form_type: str) -> bool:
        """
        Validate if the form type is supported for installation forms.
        """
        return form_type in INSTALLATION_FORM_TYPES

    def get_form_progress(self, work_order_id: int) -> Dict[str, Any]:
        """
        Get form progress for a work order.
        """
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            return {
                "work_order_id": work_order_id,
                "progress": 0.0,
                "current_step": 0,
                "total_steps": 0,
                "status": "NOT_STARTED"
            }

        return {
            "work_order_id": work_order_id,
            "progress": getattr(form_data, 'progress', 0.0),
            "current_step": getattr(form_data, 'current_step', 0),
            "total_steps": getattr(form_data, 'total_steps', 0),
            "status": "IN_PROGRESS" if getattr(form_data, 'progress', 0) < 100 else "COMPLETED"
        }

    def delete_form_data(self, work_order_id: int) -> bool:
        """
        Delete form data for a work order.
        """
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            return False

        self.db.delete(form_data)
        self.db.commit()
        return True

    def get_form_statistics(self, work_order_id: int) -> Dict[str, Any]:
        """
        Get form statistics for a work order.
        """
        # Get work order
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get form data
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        # Get template for total steps
        template_id = getattr(work_order, 'template_id')
        template = self.db.query(WorkOrderTemplate).filter(
            WorkOrderTemplate.template_id == template_id
        ).first()
        
        template_data = getattr(template, 'template') if template else {}
        total_steps = len(template_data.get('steps', [])) if template_data else 0

        if form_data is None:
            return {
                "work_order_id": work_order_id,
                "total_steps": total_steps,
                "completed_steps": 0,
                "progress": 0.0,
                "status": "NOT_STARTED",
                "last_updated": None
            }

        current_step = getattr(form_data, 'current_step', 0)
        progress = getattr(form_data, 'progress', 0.0)
        last_updated = getattr(form_data, 'last_updated')

        return {
            "work_order_id": work_order_id,
            "total_steps": total_steps,
            "completed_steps": current_step,
            "progress": progress,
            "status": "COMPLETED" if progress >= 100 else "IN_PROGRESS",
            "last_updated": last_updated
        }

    def get_work_order_form(self, work_order_id: int, session_id: Optional[str] = None) -> WorkOrderFormResponse:
        """
        Get complete work order form with template and data.
        """
        # Get work order
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get template
        template_id = getattr(work_order, 'template_id')
        template = self.db.query(WorkOrderTemplate).filter(
            WorkOrderTemplate.template_id == template_id
        ).first()
        
        if template is None:
            raise ValueError(f"Template not found for work order {work_order_id}")

        template_name = getattr(template, 'form_type')
        template_data = getattr(template, 'template') or {}

        # Get form data
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        form_data_response = None
        if form_data is not None:
            form_data_response = FormDataResponse(
                formdata_id=getattr(form_data, 'formdata_id'),
                session_id=getattr(form_data, 'session_id'),
                data=getattr(form_data, 'data'),
                progress=getattr(form_data, 'progress'),
                status="COMPLETED" if getattr(form_data, 'progress', 0) >= 100 else "IN_PROGRESS",
                current_step=getattr(form_data, 'current_step'),
                form_type=getattr(form_data, 'form_type'),
                last_updated=getattr(form_data, 'last_updated'),
                active=getattr(form_data, 'active'),
            )

        return WorkOrderFormResponse(
            work_order_id=work_order_id,
            work_order_type="INSTALLATION",
            form_type=template_name,
            template=template_data,
            form_data=form_data_response,
            steps=[],
            attachments=[],
            sessions=[]
        )

    def save_form_data(self, work_order_id: int, save_request: FormDataSaveRequest, user_id: int) -> FormDataResponse:
        """
        Save form data for a work order.
        """
        # Validate work order exists
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get template for form type
        template_id = getattr(work_order, 'template_id')
        template = self.db.query(WorkOrderTemplate).filter(
            WorkOrderTemplate.template_id == template_id
        ).first()
        
        form_type = getattr(template, 'form_type') if template else "Unknown"
        template_data = getattr(template, 'template') or {}
        total_steps = len(template_data.get('steps', [])) if template_data else 1

        # Check if form data already exists
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            # Create new form data
            form_data = WorkOrderFormData(
                work_order_id=work_order_id,
                session_id=save_request.session_id,
                form_type=form_type,
                current_step=save_request.current_step,
                total_steps=total_steps,
                progress=save_request.progress,
                data=save_request.data,
                last_updated=datetime.utcnow()
            )
            self.db.add(form_data)
        else:
            # Update existing form data
            setattr(form_data, 'session_id', save_request.session_id)
            setattr(form_data, 'form_type', form_type)
            setattr(form_data, 'current_step', save_request.current_step)
            setattr(form_data, 'total_steps', total_steps)
            setattr(form_data, 'progress', save_request.progress)
            setattr(form_data, 'data', save_request.data)
            setattr(form_data, 'last_updated', datetime.utcnow())

        self.db.commit()
        self.db.refresh(form_data)

        return FormDataResponse(
            formdata_id=getattr(form_data, 'formdata_id'),
            session_id=getattr(form_data, 'session_id'),
            data=getattr(form_data, 'data'),
            progress=getattr(form_data, 'progress'),
            status="COMPLETED" if getattr(form_data, 'progress', 0) >= 100 else "IN_PROGRESS",
            current_step=getattr(form_data, 'current_step'),
            form_type=getattr(form_data, 'form_type'),
            last_updated=getattr(form_data, 'last_updated'),
            active=getattr(form_data, 'active'),
        )

    def submit_form(self, work_order_id: int, submit_request: FormDataSubmitRequest, user_id: int) -> FormDataResponse:
        """
        Submit completed form data for a work order.
        """
        # Validate work order exists
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get template for form type
        template_id = getattr(work_order, 'template_id')
        template = self.db.query(WorkOrderTemplate).filter(
            WorkOrderTemplate.template_id == template_id
        ).first()
        
        form_type = getattr(template, 'form_type') if template else "Unknown"
        template_data = getattr(template, 'template') or {}
        total_steps = len(template_data.get('steps', [])) if template_data else 1

        # Check if form data already exists
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            # Create new form data
            form_data = WorkOrderFormData(
                work_order_id=work_order_id,
                session_id=submit_request.session_id,
                form_type=form_type,
                current_step=submit_request.current_step,
                total_steps=total_steps,
                progress=submit_request.progress,
                data=submit_request.data,
                last_updated=datetime.utcnow()
            )
            self.db.add(form_data)
        else:
            # Update existing form data
            setattr(form_data, 'session_id', submit_request.session_id)
            setattr(form_data, 'form_type', form_type)
            setattr(form_data, 'current_step', submit_request.current_step)
            setattr(form_data, 'total_steps', total_steps)
            setattr(form_data, 'progress', submit_request.progress)
            setattr(form_data, 'data', submit_request.data)
            setattr(form_data, 'last_updated', datetime.utcnow())

        self.db.commit()
        self.db.refresh(form_data)

        return FormDataResponse(
            formdata_id=getattr(form_data, 'formdata_id'),
            session_id=getattr(form_data, 'session_id'),
            data=getattr(form_data, 'data'),
            progress=getattr(form_data, 'progress'),
            status="COMPLETED" if getattr(form_data, 'progress', 0) >= 100 else "IN_PROGRESS",
            current_step=getattr(form_data, 'current_step'),
            form_type=getattr(form_data, 'form_type'),
            last_updated=getattr(form_data, 'last_updated'),
            active=getattr(form_data, 'active'),
        )

    def sync_form_data(self, work_order_id: int, sync_request: FormSyncRequest, user_id: int) -> FormSyncResponse:
        """
        Sync form data from device to server.
        """
        # Validate work order exists
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get or create form data
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            # Create new form data
            form_data = WorkOrderFormData(
                work_order_id=work_order_id,
                session_id=sync_request.session_id,
                form_type="SYNCED_FORM",
                current_step=sync_request.current_step,
                total_steps=1,
                progress=sync_request.progress,
                data=sync_request.data,
                last_updated=datetime.utcnow()
            )
            self.db.add(form_data)
        else:
            # Update existing form data
            setattr(form_data, 'session_id', sync_request.session_id)
            setattr(form_data, 'current_step', sync_request.current_step)
            setattr(form_data, 'progress', sync_request.progress)
            setattr(form_data, 'data', sync_request.data)
            setattr(form_data, 'last_updated', datetime.utcnow())

        self.db.commit()

        return FormSyncResponse(
            session_id=sync_request.session_id,
            sync_status="SUCCESS",
            message="Form data synced successfully",
            last_updated=datetime.utcnow()
        )

    def get_form_sessions(self, work_order_id: int) -> List[FormSessionResponse]:
        """
        Get all form sessions for a work order.
        """
        # Validate work order exists
        work_order = self.db.query(WorkOrder).filter(WorkOrder.work_order_id == work_order_id).first()
        if work_order is None:
            raise ValueError(f"Work order with ID {work_order_id} not found")

        # Get form data
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            return []

        return [FormSessionResponse(
            session_id=getattr(form_data, 'session_id'),
            progress=getattr(form_data, 'progress', 0.0),
            current_step=getattr(form_data, 'current_step', 0),
            last_updated=getattr(form_data, 'last_updated'),
            sync_status="SYNCED",
            agent_id=getattr(form_data, 'agent_id', 0)
        )] 