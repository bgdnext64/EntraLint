"""Tests for entraid_ca_008 — No named locations defined."""

from entralint.checks.conditional_access.ca_no_named_locations.ca_no_named_locations import (
    CaNoNamedLocations,
)
from entralint.core.check import Status
from entralint.core.context import TenantContext


def _ctx(**kwargs) -> TenantContext:
    return TenantContext(**kwargs)


def test_fail_no_locations():
    ctx = _ctx(named_locations=[])
    findings = CaNoNamedLocations().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.FAIL


def test_pass_locations_exist():
    ctx = _ctx(named_locations=[
        {
            "id": "loc1",
            "displayName": "Corporate Office",
            "@odata.type": "#microsoft.graph.ipNamedLocation",
        },
    ])
    findings = CaNoNamedLocations().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert "1" in findings[0].title


def test_pass_multiple_locations():
    ctx = _ctx(named_locations=[
        {"id": "loc1", "displayName": "Office"},
        {"id": "loc2", "displayName": "VPN"},
    ])
    findings = CaNoNamedLocations().execute(ctx)
    assert len(findings) == 1
    assert findings[0].status == Status.PASS
    assert "2" in findings[0].title
