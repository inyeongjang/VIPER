def analyze_vulnerability(
    cve_id: str,
    package_name: str,
    package_version: str,
    sbom_result: dict,
    reachability_result: dict | None = None,
    constraint_result: dict | None = None,
    poc_result: dict | None = None,
) -> dict:
    """
    여러 분석 결과를 하나의 판단용 dict로 정규화한다.
    """

    reachability_result = reachability_result or {}
    constraint_result = constraint_result or {}
    poc_result = poc_result or {}

    sbom_affected = _is_affected_by_sbom(
        package_name=package_name,
        package_version=package_version,
        sbom_result=sbom_result,
    )

    return {
        "cve_id": cve_id,
        "package": package_name,
        "version": package_version,
        "sbom_affected": sbom_affected,
        "reachable": reachability_result.get("reachable"),
        "taint_path": reachability_result.get("taint_path"),
        "constraint_satisfied": constraint_result.get("satisfied"),
        "constraints": constraint_result.get("constraints"),
        "poc_success": poc_result.get("success"),
        "poc_verified": poc_result.get("verified"),
        "poc_log": poc_result.get("log"),
    }


def _is_affected_by_sbom(
    package_name: str,
    package_version: str,
    sbom_result: dict,
) -> bool:
    """
    SBOM 안에 해당 package/version이 있는지 확인.
    일단 MVP에서는 이름과 버전이 일치하면 affected=True.
    """

    components = sbom_result.get("components", [])

    for component in components:
        name = component.get("name")
        version = component.get("version")

        if name == package_name and version == package_version:
            return True

    return False