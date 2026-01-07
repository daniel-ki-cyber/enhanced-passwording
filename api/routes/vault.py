"""Vault management endpoints.

Protected endpoints for password CRUD operations.
"""

from fastapi import APIRouter, Depends, HTTPException

from api.models import (
    PasswordEntry,
    PasswordSaveRequest,
    PasswordUpdateRequest,
    MessageResponse,
    PasswordHistoryResponse,
)
from api.dependencies import get_current_user
from core import (
    log_siem_event,
    save_password,
    load_all_passwords,
    update_password,
    delete_password,
    get_password_history,
)
from password_checker import check_password_strength


router = APIRouter(prefix="/vault", tags=["Vault"])


@router.get("", response_model=list[PasswordEntry])
async def list_passwords(user: str = Depends(get_current_user)):
    """List all saved passwords."""
    passwords = load_all_passwords()

    entries = []
    for label, data in passwords.items():
        strength, _ = check_password_strength(data["password"])
        entries.append(PasswordEntry(
            label=label,
            password=data["password"],
            created=data["created"],
            age_warning=data.get("age_warning"),
            strength=strength
        ))

    return entries


@router.get("/{label}", response_model=PasswordEntry)
async def get_password_entry(label: str, user: str = Depends(get_current_user)):
    """Get a specific password by label."""
    passwords = load_all_passwords()

    if label not in passwords:
        raise HTTPException(status_code=404, detail=f"Password '{label}' not found")

    data = passwords[label]
    strength, _ = check_password_strength(data["password"])

    return PasswordEntry(
        label=label,
        password=data["password"],
        created=data["created"],
        age_warning=data.get("age_warning"),
        strength=strength
    )


@router.post("", response_model=MessageResponse)
async def save_new_password(
    request: PasswordSaveRequest,
    user: str = Depends(get_current_user)
):
    """Save a new password to the vault."""
    passwords = load_all_passwords()
    if request.label in passwords:
        raise HTTPException(
            status_code=409,
            detail=f"Password with label '{request.label}' already exists. Use PUT to update."
        )

    if save_password(request.label, request.password):
        log_siem_event("password_saved", "SUCCESS", username=request.label)
        return MessageResponse(
            message=f"Password '{request.label}' saved successfully",
            success=True
        )
    else:
        raise HTTPException(status_code=500, detail="Failed to save password")


@router.put("/{label}", response_model=MessageResponse)
async def update_existing_password(
    label: str,
    request: PasswordUpdateRequest,
    user: str = Depends(get_current_user)
):
    """Update an existing password."""
    if update_password(label, request.new_password):
        log_siem_event("password_updated", "SUCCESS", username=label)
        return MessageResponse(
            message=f"Password '{label}' updated successfully",
            success=True
        )
    else:
        raise HTTPException(status_code=404, detail=f"Password '{label}' not found")


@router.delete("/{label}", response_model=MessageResponse)
async def delete_existing_password(
    label: str,
    user: str = Depends(get_current_user)
):
    """Delete a password from the vault."""
    if delete_password(label):
        log_siem_event("password_deleted", "SUCCESS", username=label)
        return MessageResponse(
            message=f"Password '{label}' deleted successfully",
            success=True
        )
    else:
        raise HTTPException(status_code=404, detail=f"Password '{label}' not found")


@router.get("/{label}/history", response_model=PasswordHistoryResponse)
async def get_history(label: str, user: str = Depends(get_current_user)):
    """Get password history for a label."""
    history = get_password_history(label)

    if not history:
        return PasswordHistoryResponse(
            label=label,
            history=[],
            count=0,
            message="No history found"
        )

    return PasswordHistoryResponse(
        label=label,
        history=[{"password": pwd, "index": i} for i, pwd in enumerate(history)],
        count=len(history)
    )
