"""Unit test configuration: override the stack-up wait that the parent
conftest.py imposes. Unit tests don't need the docker stack -- they're pure
Cedar policy logic tests.
"""
import pytest


# Override the autouse wait_for_stack fixture from the parent conftest
@pytest.fixture(scope="session", autouse=True)
def wait_for_stack():
    """No-op for unit tests: don't require the docker stack."""
    yield