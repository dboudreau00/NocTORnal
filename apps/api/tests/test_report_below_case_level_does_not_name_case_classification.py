"""A report built below its case's own classification does not name that
classification.

When the case's labels are above the ceiling, its code, title and authority
are withheld and the document is marked from what is left in it, so the
egress gate may let it out. The case's own level is part of what was
withheld: a file cleared at CLEAR or GREEN must not say that it came from an
AMBER_STRICT or RED case.

No database: these are the statement's and the renderer's rules on a
hand-built report.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from noctornal_api.egress import Destination
from noctornal_api.reports import (
    WITHHELD_MARK,
    Redaction,
    Report,
    check_egress,
    render_markdown,
)


def _report(case_tlp: str, disclosure: str) -> Report:
    redaction = Redaction(
        built_at_tlp="CLEAR", ceiling_tlp="GREEN", case_tlp=case_tlp,
        nodes_withheld=0, edges_withheld=0, evidence_withheld=0,
        header_withheld=True, disclosure=disclosure)
    return Report(
        case={
            "code": WITHHELD_MARK,
            "title": WITHHELD_MARK,
            "summary": None,
            "status": None,
            "classification": case_tlp,
            "legal_basis": WITHHELD_MARK,
            "authority_ref": WITHHELD_MARK,
            "opened": None,
            "retention_until": None,
            "review_due": None,
        },
        redaction=redaction,
        summary={"entities": 0, "relationships": 0, "exhibits": 0,
                 "computed_over": "the redacted graph"},
        generated_by=uuid4())


@pytest.mark.parametrize("disclosure", ["NONE", "PRESENCE", "COUNT"])
@pytest.mark.parametrize("case_tlp", ["AMBER_STRICT", "RED"])
def test_a_released_report_does_not_name_a_case_level_above_its_mark(
        case_tlp, disclosure):
    report = _report(case_tlp, disclosure)
    assert check_egress(report, Destination.EXPORT).allowed
    released = render_markdown(report)
    assert case_tlp not in released
    assert case_tlp not in report.redaction.statement()
    # The reader is still told the header was withheld.
    assert "identifying detail is above that ceiling" in released


def test_a_report_that_carries_its_header_still_names_the_case_level():
    redaction = Redaction(
        built_at_tlp="AMBER", ceiling_tlp="AMBER", case_tlp="AMBER",
        nodes_withheld=0, edges_withheld=0, evidence_withheld=0)
    assert "from a case classified TLP:AMBER" in redaction.statement()
