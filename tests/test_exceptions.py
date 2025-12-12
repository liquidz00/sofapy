"""Tests for sofapy.exceptions module."""

from typing import TYPE_CHECKING

import pytest

from sofapy.exceptions import SofaError

if TYPE_CHECKING:
    pass


def test_sofa_error_default_message() -> None:
    """Test SofaError uses default message when none provided."""
    error = SofaError()

    assert str(error) == "An error occurred"
    assert error.message == "An error occurred"


def test_sofa_error_custom_message() -> None:
    """Test SofaError with custom message."""
    error = SofaError("Custom error message")

    assert str(error) == "Custom error message"
    assert error.message == "Custom error message"


def test_sofa_error_with_context() -> None:
    """Test SofaError with additional context kwargs."""
    error = SofaError("Error occurred", filename="test.py", line=42)

    assert "filename: test.py" in str(error)
    assert "line: 42" in str(error)
    assert error.context["filename"] == "test.py"
    assert error.context["line"] == 42


def test_sofa_error_context_empty_values_excluded() -> None:
    """Test SofaError excludes empty context values from message."""
    error = SofaError("Error occurred", filename="test.py", empty_value=None)

    assert "filename: test.py" in str(error)
    assert "empty_value" not in str(error)


def test_sofa_error_format_message() -> None:
    """Test SofaError format_message method."""
    error = SofaError("Test message", key1="value1", key2="value2")

    formatted = error.format_message()

    assert "Test message" in formatted
    assert "key1: value1" in formatted
    assert "key2: value2" in formatted


def test_sofa_error_format_message_no_context() -> None:
    """Test SofaError format_message with no context."""
    error = SofaError("Simple message")

    formatted = error.format_message()

    assert formatted == "Simple message"


def test_sofa_error_is_exception() -> None:
    """Test SofaError is a proper Exception subclass."""
    error = SofaError("Test")

    assert isinstance(error, Exception)


def test_sofa_error_can_be_raised() -> None:
    """Test SofaError can be raised and caught."""
    with pytest.raises(SofaError) as exc_info:
        raise SofaError("Test exception", code=500)

    assert "Test exception" in str(exc_info.value)
    assert exc_info.value.context["code"] == 500


def test_sofa_error_formatted_message_attribute() -> None:
    """Test SofaError stores formatted_message attribute."""
    error = SofaError("Message", context_key="context_value")

    assert error.formatted_message == str(error)
    assert "context_key: context_value" in error.formatted_message


def test_sofa_error_multiple_context_values() -> None:
    """Test SofaError with multiple context values."""
    error = SofaError(
        "Operation failed",
        operation="fetch",
        url="https://example.com",
        status_code=404,
        retry_count=3,
    )

    error_str = str(error)
    assert "operation: fetch" in error_str
    assert "url: https://example.com" in error_str
    assert "status_code: 404" in error_str
    assert "retry_count: 3" in error_str
