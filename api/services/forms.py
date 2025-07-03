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
    FormAttachmentResponse, FormSessionResponse, FormSyncResponse
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

    def _filter_form_data_by_progress(self, raw_data: dict, current_step: int, progress: float) -> dict:
        """
        Filter form data to only include data up to the current step where the form is filled.
        
        Args:
            raw_data: The complete form data
            current_step: The current step number (0-based)
            progress: The progress percentage (0-100)
            
        Returns:
            Filtered data containing only filled steps/fields
        """
        if not isinstance(raw_data, dict):
            return raw_data
        
        # If progress is 100%, return all data
        if progress >= 100:
            return raw_data
        
        # If no progress, return empty data
        if progress <= 0 or current_step <= 0:
            return {}
        
        filtered_data = {}
        
        # Handle different form data structures
        if 'steps' in raw_data and isinstance(raw_data['steps'], list):
            # Step-based form structure
            filtered_data['steps'] = raw_data['steps'][:current_step]
            
            # Copy other metadata
            for key, value in raw_data.items():
                if key != 'steps':
                    filtered_data[key] = value
                    
        elif 'fields' in raw_data and isinstance(raw_data['fields'], dict):
            # Field-based form structure
            filtered_data['fields'] = {}
            fields = raw_data['fields']
            
            # Calculate how many fields should be included based on progress
            total_fields = len(fields)
            if total_fields > 0:
                fields_to_include = int((progress / 100) * total_fields)
                field_keys = list(fields.keys())[:fields_to_include]
                
                for key in field_keys:
                    filtered_data['fields'][key] = fields[key]
            
            # Copy other metadata
            for key, value in raw_data.items():
                if key != 'fields':
                    filtered_data[key] = value
                    
        elif 'form_data' in raw_data and isinstance(raw_data['form_data'], dict):
            # Nested form_data structure
            filtered_data['form_data'] = {}
            form_data = raw_data['form_data']
            
            # Calculate how many items should be included based on progress
            total_items = len(form_data)
            if total_items > 0:
                items_to_include = int((progress / 100) * total_items)
                item_keys = list(form_data.keys())[:items_to_include]
                
                for key in item_keys:
                    filtered_data['form_data'][key] = form_data[key]
            
            # Copy other metadata
            for key, value in raw_data.items():
                if key != 'form_data':
                    filtered_data[key] = value
                    
        else:
            # Generic structure - filter based on progress percentage
            total_keys = len(raw_data)
            if total_keys > 0:
                keys_to_include = int((progress / 100) * total_keys)
                keys = list(raw_data.keys())[:keys_to_include]
                
                for key in keys:
                    filtered_data[key] = raw_data[key]
        
        return filtered_data

    def get_work_order_template(self, wo_number: str) -> WorkOrderFormResponse:
        """
        Get work order and its template for installation forms.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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

        # Get category
        category = getattr(template, 'category', 'ZDEV')

        return WorkOrderFormResponse(
            work_order_id=work_order_id,
            wo_number=wo_number,
            work_order_type=getattr(work_order, 'work_order_type'),
            form_type=getattr(template, 'form_type'),
            template=getattr(template, 'template'),
            form_data=None,
            steps=[],
            attachments=[],
            sessions=[],
            category=getattr(template, 'category', 'ZDEV')
        )

    def save_or_update_form_data(self, wo_number: str, request: dict) -> WorkOrderFormResponse:
        """
        Save or update form data for a work order and return form details with template.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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

        # First, check if form data already exists for this form_id
        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.form_id == form.form_id
        ).first()

        # If no form data exists for this form, create new one
        if form_data is None:
            session_id = request.get('session_id') or str(uuid.uuid4())
            # Check if this session_id already exists globally
            existing_session = self.db.query(WorkOrderFormData).filter(
                WorkOrderFormData.session_id == session_id
            ).first()
            if existing_session:
                session_id = str(uuid.uuid4())
            form_data = WorkOrderFormData(
                form_id=form.form_id,
                session_id=session_id,
                form_type=form_type,
                current_step=request.get('current_step', 0),
                progress=request.get('progress', 0.0),
                data=request.get('data'),
                last_updated=datetime.utcnow(),
                active=True
            )
            self.db.add(form_data)
        else:
            # Update existing form data
            session_id = request.get('session_id')
            if session_id and session_id != form_data.session_id:
                existing_session = self.db.query(WorkOrderFormData).filter(
                    WorkOrderFormData.session_id == session_id
                ).first()
                if not existing_session:
                    setattr(form_data, 'session_id', session_id)
            setattr(form_data, 'form_type', form_type)
            setattr(form_data, 'current_step', request.get('current_step', 0))
            setattr(form_data, 'progress', request.get('progress', 0.0))
            setattr(form_data, 'data', request.get('data'))
            setattr(form_data, 'last_updated', datetime.utcnow())

        self.db.commit()
        self.db.refresh(form_data)

        # Get progress value safely
        progress_value = getattr(form_data, 'progress', 0.0)
        if progress_value is None:
            progress_value = 0.0

        return WorkOrderFormResponse(
            work_order_id=work_order_id,
            wo_number=wo_number,
            work_order_type="INSTALLATION",
            form_type=form_type,
            template=template_data,
            form_data=FormDataResponse(
                formdata_id=getattr(form_data, 'formdata_id'),
                session_id=getattr(form_data, 'session_id'),
                data=getattr(form_data, 'data') or {},
                progress=progress_value,
                status="COMPLETED" if progress_value >= 100 else "IN_PROGRESS",
                current_step=getattr(form_data, 'current_step'),
                form_type=getattr(form_data, 'form_type'),
                last_updated=getattr(form_data, 'last_updated'),
                active=getattr(form_data, 'active'),
            ),
            steps=[],
            attachments=[],
            sessions=[],
            category=getattr(template, 'category', 'ZDEV')
        )

    def get_form_data(self, wo_number: str) -> Optional[FormDataResponse]:
        """
        Get saved form data for a work order.
        Only returns data up to the current step where the form is filled.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

        # Get form by work_order_id
        form = self.db.query(WorkOrderForm).filter(WorkOrderForm.work_order_id == work_order_id).first()
        if form is None:
            return None

        # Get form data by form_id
        form_data = self.db.query(WorkOrderFormData).filter(WorkOrderFormData.form_id == form.form_id).first()
        if form_data is None:
            return None

        # Get progress value safely
        progress_value = getattr(form_data, 'progress', 0.0)
        if progress_value is None:
            progress_value = 0.0

        # Get current step
        current_step = getattr(form_data, 'current_step', 0)
        
        # Get the raw data
        raw_data = getattr(form_data, 'data') or {}
        
        # Filter data to only include filled steps/fields up to current_step
        filtered_data = self._filter_form_data_by_progress(raw_data, current_step, progress_value)

        return FormDataResponse(
            formdata_id=getattr(form_data, 'formdata_id'),
            session_id=getattr(form_data, 'session_id'),
            data=filtered_data,
            progress=progress_value,
            status="COMPLETED" if progress_value >= 100 else "IN_PROGRESS",
            current_step=current_step,
            form_type=getattr(form_data, 'form_type'),
            last_updated=getattr(form_data, 'last_updated'),
            active=getattr(form_data, 'active'),
        )

    def validate_form_type(self, form_type: str) -> bool:
        """
        Validate if the form type is supported for installation forms.
        """
        return form_type in INSTALLATION_FORM_TYPES

    def get_form_progress(self, wo_number: str) -> Dict[str, Any]:
        """
        Get form progress for a work order.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            return {"wo_number": wo_number, "progress": 0.0, "current_step": 0, "total_steps": 0, "status": "NOT_STARTED"}
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            return {
                "wo_number": wo_number,
                "progress": 0.0,
                "current_step": 0,
                "total_steps": 0,
                "status": "NOT_STARTED"
            }

        # Get progress value safely
        progress_value = getattr(form_data, 'progress', 0.0)
        if progress_value is None:
            progress_value = 0.0

        return {
            "wo_number": wo_number,
            "progress": progress_value,
            "current_step": getattr(form_data, 'current_step', 0),
            "total_steps": getattr(form_data, 'total_steps', 0),
            "status": "IN_PROGRESS" if progress_value < 100 else "COMPLETED"
        }

    def delete_form_data(self, wo_number: str) -> bool:
        """
        Delete form data for a work order.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            return False
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

        form_data = self.db.query(WorkOrderFormData).filter(
            WorkOrderFormData.work_order_id == work_order_id
        ).first()

        if form_data is None:
            return False

        self.db.delete(form_data)
        self.db.commit()
        return True

    def get_form_statistics(self, wo_number: str) -> Dict[str, Any]:
        """
        Get form statistics for a work order.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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
                "wo_number": wo_number,
                "total_steps": total_steps,
                "completed_steps": 0,
                "progress": 0.0,
                "status": "NOT_STARTED",
                "last_updated": None
            }

        current_step = getattr(form_data, 'current_step', 0)
        progress = getattr(form_data, 'progress', 0.0)
        if progress is None:
            progress = 0.0
        last_updated = getattr(form_data, 'last_updated')

        return {
            "wo_number": wo_number,
            "total_steps": total_steps,
            "completed_steps": current_step,
            "progress": progress,
            "status": "COMPLETED" if progress >= 100 else "IN_PROGRESS",
            "last_updated": last_updated
        }

    def get_work_order_form(self, wo_number: str, session_id: Optional[str] = None) -> WorkOrderFormResponse:
        """
        Get complete work order form with template and data.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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
            # Get current step and progress
            current_step = getattr(form_data, 'current_step', 0)
            progress_value = getattr(form_data, 'progress', 0.0)
            if progress_value is None:
                progress_value = 0.0
            
            # Get the raw data and filter it
            raw_data = getattr(form_data, 'data') or {}
            filtered_data = self._filter_form_data_by_progress(raw_data, current_step, progress_value)
            
            form_data_response = FormDataResponse(
                formdata_id=getattr(form_data, 'formdata_id'),
                session_id=getattr(form_data, 'session_id'),
                data=filtered_data,
                progress=progress_value,
                status="COMPLETED" if progress_value >= 100 else "IN_PROGRESS",
                current_step=current_step,
                form_type=getattr(form_data, 'form_type'),
                last_updated=getattr(form_data, 'last_updated'),
                active=getattr(form_data, 'active'),
            )

        return WorkOrderFormResponse(
            work_order_id=work_order_id,
            wo_number=wo_number,
            work_order_type="INSTALLATION",
            form_type=template_name,
            template=template_data,
            form_data=form_data_response,
            steps=[],
            attachments=[],
            sessions=[],
            category=getattr(template, 'category', 'ZDEV')
        )

    def save_form_data(self, wo_number: str, save_request: FormDataSaveRequest, user_id: int) -> FormDataResponse:
        """
        Save form data for a work order.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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
            data=getattr(form_data, 'data') or {},
            progress=getattr(form_data, 'progress'),
            status="COMPLETED" if getattr(form_data, 'progress', 0) >= 100 else "IN_PROGRESS",
            current_step=getattr(form_data, 'current_step'),
            form_type=getattr(form_data, 'form_type'),
            last_updated=getattr(form_data, 'last_updated'),
            active=getattr(form_data, 'active'),
        )

    def submit_form(self, wo_number: str, submit_request: FormDataSubmitRequest, user_id: int) -> FormDataResponse:
        """
        Submit completed form data for a work order.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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
            data=getattr(form_data, 'data') or {},
            progress=getattr(form_data, 'progress'),
            status="COMPLETED" if getattr(form_data, 'progress', 0) >= 100 else "IN_PROGRESS",
            current_step=getattr(form_data, 'current_step'),
            form_type=getattr(form_data, 'form_type'),
            last_updated=getattr(form_data, 'last_updated'),
            active=getattr(form_data, 'active'),
        )

    def sync_form_data(self, wo_number: str, sync_request: FormSyncRequest, user_id: int) -> FormSyncResponse:
        """
        Sync form data from device to server.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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

    def get_form_sessions(self, wo_number: str) -> List[FormSessionResponse]:
        """
        Get all form sessions for a work order.
        """
        work_order = self.db.query(WorkOrder).filter(WorkOrder.wo_number == wo_number).first()
        if work_order is None:
            raise ValueError(f"Work order with WO number {wo_number} not found")
        work_order_id = getattr(work_order, 'work_order_id', None)
        if not isinstance(work_order_id, int):
            work_order_id = int(str(work_order_id))

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