"""Password tools endpoints.

Public endpoints for password generation and checking.
"""

from fastapi import APIRouter, HTTPException

from api.models import (
    PasswordGenerateRequest,
    PasswordGenerateResponse,
    PasswordCheckRequest,
    PasswordCheckResponse,
    BreachCheckResponse,
)
from cli.generator import generate_password
from password_checker import check_password_with_breach
from breach_check import check_and_warn


router = APIRouter(tags=["Password Tools"])


@router.post("/generate", response_model=PasswordGenerateResponse)
async def generate_new_password(request: PasswordGenerateRequest):
    """Generate a secure random password."""
    try:
        password = generate_password(
            length=request.length,
            use_upper=request.use_upper,
            use_lower=request.use_lower,
            use_digits=request.use_digits,
            use_special=request.use_special
        )

        strength, feedback, breach_count = check_password_with_breach(
            password, check_online=True
        )

        return PasswordGenerateResponse(
            password=password,
            strength=strength,
            feedback=feedback,
            breach_count=breach_count
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/check", response_model=PasswordCheckResponse)
async def check_password(request: PasswordCheckRequest):
    """Check password strength and breach status."""
    strength, feedback, breach_count = check_password_with_breach(
        request.password,
        check_online=request.check_breach
    )

    return PasswordCheckResponse(
        strength=strength,
        feedback=feedback,
        breach_count=breach_count,
        is_breached=breach_count is not None and breach_count > 0
    )


@router.post("/breach-check", response_model=BreachCheckResponse)
async def check_breach_only(request: PasswordCheckRequest):
    """Check if password appears in known data breaches."""
    is_safe, message = check_and_warn(request.password)
    return BreachCheckResponse(is_safe=is_safe, message=message)
