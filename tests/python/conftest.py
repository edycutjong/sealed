"""Shared pytest setup: make scripts/ and day0/ importable, forbid real network access in every test."""
import os
import socket
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("scripts", "day0"):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Any test that reaches a real socket fails loudly: mock the RPC/HTTP layer instead."""
    def guard(*_a, **_k):
        raise RuntimeError("network access is not allowed in unit tests; mock it")
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)


@pytest.fixture
def root():
    return ROOT
