"""Values shared by several modules, defined once."""

OPEN = "Open"
NOT_A_FINDING = "NotAFinding"
NOT_APPLICABLE = "Not_Applicable"
NOT_REVIEWED = "Not_Reviewed"
# The .ckl vocabulary, used everywhere (the .cklb file lower-cases it).
STATUSES = (OPEN, NOT_A_FINDING, NOT_APPLICABLE, NOT_REVIEWED)
CATS = ("CAT I", "CAT II", "CAT III")

# The dashboard repeats this text (src/lib.js); a test keeps the two equal.
DISCLAIMER = ("STIGWatch is an independent tool. It is not a DISA product and does not "
              "replace the SCAP Compliance Checker, Evaluate-STIG or an assessor's review.")


def compliance_percent(status: dict[str, int]) -> float | None:
    """NotAFinding / (Open + NotAFinding) in percent, one decimal; None when neither occurs.
    Not_Reviewed and Not_Applicable results are not counted."""
    decided = status.get(OPEN, 0) + status.get(NOT_A_FINDING, 0)
    return round(100.0 * status.get(NOT_A_FINDING, 0) / decided, 1) if decided else None
