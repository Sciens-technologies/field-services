# api/routers/forms.py

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from db.database import get_db
from api.services.forms import FormService
from api.schemas import (
    InstallationFormSaveRequest,  # You may need to adjust this schema for your installation forms
    WorkOrderFormResponse,
    FormDataResponse
)
from typing import Optional

router = APIRouter(
    prefix="/forms",
    tags=["forms"]
)

# 1. Get work order and its template
@router.get("/work-order/{work_order_id}/templet", response_model=WorkOrderFormResponse)
def get_work_order_template(
    work_order_id: int,
    db: Session = Depends(get_db)
):
    """
    Get work order and its template for installation forms.
    """
    try:
        form_service = FormService(db)
        return form_service.get_work_order_template(work_order_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# 2. Save or update form data
@router.post("/work-order/{work_order_id}", response_model=WorkOrderFormResponse)
def save_or_update_form_data(
    work_order_id: int,
    request: InstallationFormSaveRequest,
    db: Session = Depends(get_db)
):
    """
    Save or update form data for installation forms.
    """
    try:
        form_service = FormService(db)
        return form_service.save_or_update_form_data(work_order_id, request)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# 3. Get saved form data
@router.get("/work-order/{work_order_id}", response_model=FormDataResponse)
def get_form_data(
    work_order_id: int,
    db: Session = Depends(get_db)
):
    """
    Get partially or fully filled form data for installation forms.
    """
    try:
        form_service = FormService(db)
        result = form_service.get_form_data(work_order_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Form data not found")
        return result
    except HTTPException as e:
        raise e  # Let FastAPI handle HTTPException as intended
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")