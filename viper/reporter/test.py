from viper.reporter.vex_analyzer import analyze_vulnerability
from viper.reporter.vex_builder import build_vex_document
from viper.reporter.vex_exporter import export_vex_json


sbom_result = {
    "components": [
        {
            "name": "lodash",
            "version": "4.17.15",
        }
    ]
}

reachability_result = {
    "reachable": True,
    "taint_path": [
        "user_input",
        "merge",
        "vulnerable_sink",
    ],
}

constraint_result = {
    "satisfied": True,
    "constraints": [
        "attacker_controlled_object",
        "deep_merge_enabled",
    ],
}

poc_result = {
    "success": True,
    "verified": True,
    "log": "Prototype pollution confirmed.",
}

analysis_result = analyze_vulnerability(
    cve_id="CVE-2019-10744",
    package_name="lodash",
    package_version="4.17.15",
    sbom_result=sbom_result,
    reachability_result=reachability_result,
    constraint_result=constraint_result,
    poc_result=poc_result,
)

vex_doc = build_vex_document([analysis_result])

print(vex_doc)

export_vex_json(vex_doc, "outputs/vex.json")