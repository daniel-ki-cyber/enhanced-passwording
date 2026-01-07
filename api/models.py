"""Pydantic models for API request/response validation.

Defines data structures for all API endpoints.
"""

from typing import Optional

from pydantic import BaseModel, Field


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
    """Request model for saving a password."""
    label: str = Field(..., min_length=1, max_length=100, description="Label for the password")
    password: str = Field(..., min_length=1, description="Password to save")


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
    vault_exists: bool


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
