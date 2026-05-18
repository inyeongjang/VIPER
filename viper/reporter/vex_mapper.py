from .vex_types import VexStatus


def decide_vex_status(
    sbom_affected: bool,
    reachable: bool | None = None,
    constraint_satisfied: bool | None = None,
    poc_success: bool | None = None,
    poc_verified: bool | None = None,
) -> VexStatus:
    """
    VEX 상태 결정 로직.

    우선순위:
    1. SBOM 기준 영향 없음 -> NOT_AFFECTED
    2. PoC 성공 + 검증 성공 -> EXPLOITABLE
    3. reachability 또는 constraint가 명확히 False -> NOT_EXPLOITABLE
    4. 불확실한 경우 -> UNDER_INVESTIGATION
    """

    if not sbom_affected:
        return VexStatus.NOT_AFFECTED

    if poc_success is True and poc_verified is True:
        return VexStatus.EXPLOITABLE

    if reachable is False:
        return VexStatus.NOT_EXPLOITABLE

    if constraint_satisfied is False:
        return VexStatus.NOT_EXPLOITABLE

    return VexStatus.UNDER_INVESTIGATION