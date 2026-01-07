"""Vault management endpoints.

Protected endpoints for password CRUD operations.
Uses generic error messages to prevent information disclosure and enumeration attacks.
Implements label validation to prevent injection and malformed input attacks.
"""

from fastapi import APIRouter, Depends, HTTPException

from api.models import (
    PasswordEntry,
    PasswordSaveRequest,
    PasswordUpdateRequest,
    MessageResponse,
    PasswordHistoryResponse,
    validate_label,
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

# Generic error messages to prevent information disclosure
# These messages don't reveal whether a specific label exists
NOT_FOUND_MESSAGE = "Resource not found or access denied"
CONFLICT_MESSAGE = "Unable to create resource - may already exist"
OPERATION_FAILED_MESSAGE = "Operation could not be completed"
INVALID_LABEL_MESSAGE = "Invalid label format"


def _validate_path_label(label: str) -> str:
    """Validate label from path parameter.

    Args:
        label: Raw label from URL path

    Returns:
        Validated and sanitized label

    Raises:
        HTTPException: 400 if label is invalid
    """
    try:
        return validate_label(label)
    except ValueError:
        raise HTTPException(status_code=400, detail=INVALID_LABEL_MESSAGE)


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
    label = _validate_path_label(label)
    passwords = load_all_passwords()

    if label not in passwords:
        # Generic message - doesn't confirm if label exists
        raise HTTPException(status_code=404, detail=NOT_FOUND_MESSAGE)

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
        # Generic message - doesn't explicitly confirm label exists
        raise HTTPException(status_code=409, detail=CONFLICT_MESSAGE)

    if save_password(request.label, request.password):
        log_siem_event("password_saved", "SUCCESS")
        return MessageResponse(
            message="Password saved successfully",
            success=True
        )
    else:
        raise HTTPException(status_code=500, detail=OPERATION_FAILED_MESSAGE)


@router.put("/{label}", response_model=MessageResponse)
async def update_existing_password(
    label: str,
    request: PasswordUpdateRequest,
    user: str = Depends(get_current_user)
):
    """Update an existing password."""
    label = _validate_path_label(label)
    if update_password(label, request.new_password):
        log_siem_event("password_updated", "SUCCESS")
        return MessageResponse(
            message="Password updated successfully",
            success=True
        )
    else:
        # Generic message - doesn't confirm if label exists
        raise HTTPException(status_code=404, detail=NOT_FOUND_MESSAGE)


@router.delete("/{label}", response_model=MessageResponse)
async def delete_existing_password(
    label: str,
    user: str = Depends(get_current_user)
):
    """Delete a password from the vault."""
    label = _validate_path_label(label)
    if delete_password(label):
        log_siem_event("password_deleted", "SUCCESS")
        return MessageResponse(
            message="Password deleted successfully",
            success=True
        )
    else:
        # Generic message - doesn't confirm if label exists
        raise HTTPException(status_code=404, detail=NOT_FOUND_MESSAGE)


@router.get("/{label}/history", response_model=PasswordHistoryResponse)
async def get_history(label: str, user: str = Depends(get_current_user)):
    """Get password history for a label."""
    label = _validate_path_label(label)
    history = get_password_history(label)

    # Return empty history with generic message (doesn't confirm label exists)
    if not history:
        return PasswordHistoryResponse(
            label=label,
            history=[],
            count=0,
            message="No history available"
        )

    return PasswordHistoryResponse(
        label=label,
        history=[{"password": pwd, "index": i} for i, pwd in enumerate(history)],
        count=len(history)
    )
