"""Tests for FastAPI endpoints."""

import os
import sys
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from api.main import app


client = TestClient(app)


class TestPublicEndpoints:
    """Test public endpoints that don't require authentication."""

    def test_root_endpoint(self):
        """Root endpoint should return health status."""
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_health_endpoint(self):
        """Health endpoint should return detailed status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "vault_exists" in data

    def test_generate_password_default(self):
        """Generate password with default settings."""
        response = client.post("/generate", json={})
        assert response.status_code == 200
        data = response.json()
        assert "password" in data
        assert len(data["password"]) == 16  # Default length
        assert "strength" in data
        assert "feedback" in data

    def test_generate_password_custom_length(self):
        """Generate password with custom length."""
        response = client.post("/generate", json={"length": 32})
        assert response.status_code == 200
        assert len(response.json()["password"]) == 32

    def test_generate_password_invalid_length(self):
        """Invalid length should return 422."""
        response = client.post("/generate", json={"length": 5})  # Too short
        assert response.status_code == 422

    def test_generate_password_only_digits(self):
        """Generate password with only digits."""
        response = client.post("/generate", json={
            "length": 12,
            "use_upper": False,
            "use_lower": False,
            "use_digits": True,
            "use_special": False
        })
        assert response.status_code == 200
        password = response.json()["password"]
        assert password.isdigit()

    def test_check_password_strong(self):
        """Check a strong password."""
        response = client.post("/check", json={
            "password": "Tr0ub4dor&3#Xy9!",
            "check_breach": False  # Skip breach check for speed
        })
        assert response.status_code == 200
        data = response.json()
        assert data["strength"] == "Strong"
        assert data["is_breached"] == False

    def test_check_password_weak(self):
        """Check a weak password."""
        response = client.post("/check", json={
            "password": "password123",
            "check_breach": False
        })
        assert response.status_code == 200
        data = response.json()
        assert data["strength"] == "Weak"

    def test_check_password_common(self):
        """Check a common password."""
        response = client.post("/check", json={
            "password": "qwerty",
            "check_breach": False
        })
        assert response.status_code == 200
        data = response.json()
        assert data["strength"] == "Weak"
        assert any("common" in f.lower() for f in data["feedback"])

    def test_breach_check_endpoint(self):
        """Test breach check endpoint."""
        response = client.post("/breach-check", json={
            "password": "test_password_12345"
        })
        assert response.status_code == 200
        data = response.json()
        assert "is_safe" in data
        assert "message" in data


class TestProtectedEndpoints:
    """Test protected endpoints that require authentication."""

    def test_vault_list_no_auth(self):
        """Vault endpoints should require authentication."""
        response = client.get("/vault")
        assert response.status_code == 401

    def test_vault_get_no_auth(self):
        """Get specific password without auth should fail."""
        response = client.get("/vault/test")
        assert response.status_code == 401

    def test_vault_save_no_auth(self):
        """Save password without auth should fail."""
        response = client.post("/vault", json={
            "label": "test",
            "password": "testpass"
        })
        assert response.status_code == 401

    def test_vault_delete_no_auth(self):
        """Delete password without auth should fail."""
        response = client.delete("/vault/test")
        assert response.status_code == 401


class TestInputValidation:
    """Test input validation."""

    def test_generate_empty_body(self):
        """Empty body should use defaults."""
        response = client.post("/generate", json={})
        assert response.status_code == 200

    def test_check_empty_password(self):
        """Empty password should fail validation."""
        response = client.post("/check", json={"password": ""})
        assert response.status_code == 422

    def test_check_missing_password(self):
        """Missing password field should fail."""
        response = client.post("/check", json={})
        assert response.status_code == 422

    def test_save_empty_label(self):
        """Empty label should fail (401 without auth, 422 with auth)."""
        # Protected endpoint returns 401 before validation
        response = client.post("/vault", json={
            "label": "",
            "password": "testpass"
        })
        assert response.status_code == 401  # Auth required first
