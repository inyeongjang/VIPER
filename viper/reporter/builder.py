from datetime import datetime, timezone

from .mapper import decide_vex_status


def build_vex_statement(analysis_result: dict) -> dict:
    status = decide_vex_status(
        sbom_affected=analysis_result["sbom_affected"],
        reachable=analysis_result.get("reachable"),
        constraint_satisfied=analysis_result.get("constraint_satisfied"),
        poc_success=analysis_result.get("poc_success"),
        poc_verified=analysis_result.get("poc_verified"),
    )

    return {
        "vulnerability": analysis_result["cve_id"],
        "product": {
            "package": analysis_result["package"],
            "version": analysis_result["version"],
        },
        "status": status.value,
        "evidence": {
            "sbom_affected": analysis_result.get("sbom_affected"),
            "reachable": analysis_result.get("reachable"),
            "taint_path": analysis_result.get("taint_path"),
            "constraint_satisfied": analysis_result.get("constraint_satisfied"),
            "constraints": analysis_result.get("constraints"),
            "poc_success": analysis_result.get("poc_success"),
            "poc_verified": analysis_result.get("poc_verified"),
            "poc_log": analysis_result.get("poc_log"),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_vex_document(analysis_results: list[dict]) -> dict:
    return {
        "document_type": "VEX",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "statements": [
            build_vex_statement(result)
            for result in analysis_results
        ],
    }