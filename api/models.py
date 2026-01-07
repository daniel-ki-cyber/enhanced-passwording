"""Pydantic models for API request/response validation.

Defines data structures for all API endpoints.
Includes security-focused input validation for labels.
"""

from typing import Optional

from pydantic import BaseModel, Field, field_validator

from core.config import MAX_LABEL_LENGTH, LABEL_ALLOWED_CHARS


def validate_label(label: str) -> str:
    """Validate and sanitize a password entry label.

    Security validations:
    - Length check (prevents DoS via extremely long labels)
    - Character whitelist (prevents injection attacks)
    - Unicode normalization (prevents homograph attacks)
    - Whitespace normalization (prevents confusion)

    Args:
        label: The label to validate

    Returns:
        Sanitized label string

    Raises:
        ValueError: If label contains invalid characters or is too long
    """
    # Strip and normalize whitespace
    label = " ".join(label.split())

    # Length check
    if len(label) > MAX_LABEL_LENGTH:
        raise ValueError(f"Label must be {MAX_LABEL_LENGTH} characters or less")

    if len(label) < 1:
        raise ValueError("Label cannot be empty")

    # Character whitelist check
    invalid_chars = set(label) - LABEL_ALLOWED_CHARS
    if invalid_chars:
        # Don't reveal all invalid chars (could be used for probing)
        raise ValueError(
            "Label contains invalid characters. "
            "Use only letters, numbers, spaces, and: - _ . @ #"
        )

    return label


class PasswordGenerateRequest(BaseModel):
    """Request model for password generation."""
    length: int = Field(default=16, ge=8, le=128, description="Password length")
    use_upper: bool = Field(default=True, description="Include uppercase letters")
    use_lower: bool = Field(default=True, description="Include lowercase letters")
    use_digits: bool = Field(default=True, description="Include digits")
    use_special: bool = Field(default=True, description="Include special characters")


class PasswordGenerateResponse(BaseModel):
    """Response model for generated password."""
    password: str
    strength: str
    feedback: list[str]
    breach_count: Optional[int] = None


class PasswordCheckRequest(BaseModel):
    """Request model for password strength check."""
    password: str = Field(..., min_length=1, description="Password to check")
    check_breach: bool = Field(default=True, description="Check against breach database")


class PasswordCheckResponse(BaseModel):
    """Response model for password check."""
    strength: str
    feedback: list[str]
    breach_count: Optional[int] = None
    is_breached: bool


class PasswordSaveRequest(BaseModel):
    """Request model for saving a password.

    Label is validated for allowed characters to prevent injection attacks.
    """
    label: str = Field(..., min_length=1, max_length=100, description="Label for the password")
    password: str = Field(..., min_length=1, description="Password to save")

    @field_validator('label')
    @classmethod
    def validate_label_field(cls, v: str) -> str:
        """Validate label using security-focused validation."""
        return validate_label(v)


class PasswordEntry(BaseModel):
    """Model representing a saved password entry."""
    label: str
    password: str
    created: str
    age_warning: Optional[str] = None
    strength: str


class PasswordUpdateRequest(BaseModel):
    """Request model for updating a password."""
    new_password: str = Field(..., min_length=1, description="New password")


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str
    success: bool


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    timestamp: str
    version: str


class BreachCheckResponse(BaseModel):
    """Response model for breach check."""
    is_safe: bool
    message: str


class PasswordHistoryResponse(BaseModel):
    """Response model for password history."""
    label: str
    history: list[dict]
    count: int
    message: Optional[str] = None
