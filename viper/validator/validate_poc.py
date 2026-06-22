def validate_poc(self) -> None:
    stage = "VALIDATE POC"

    with self._stage_indicator(stage):

        runner = PoCRunner()
        validator = Validator()

        for context in self.analysis_contexts:

            cve_id = context["cve_id"]
            vuln_type = context["vuln_type"]

            if not context["function_candidates"]:
                continue

            function_name = context["function_candidates"][0].name

            poc_result = next(
                (
                    item
                    for item in self.poc_results
                    if item["cve_id"] == cve_id
                ),
                None,
            )

            if not poc_result:
                continue

            poc_dir = Path("outputs/pocs") / cve_id

            run_result = runner.run_validation(
                cve_id=cve_id,
                repo_path=Path(self.repo_path),
                poc_dir=poc_dir,
            )

            execution_result = ExecutionResult(
                stdout=run_result.get("logs", ""),
                stderr="",
                exit_code=run_result.get("exit_code", 1),
                execution_time_ms=0,
                files_created=[],
                crashed=False,
            )

            validation = validator.validate(
                result=execution_result,
                vuln_type=vuln_type,
                function_name=function_name,
            )

            poc_result["verified"] = (
                validation.validation_result == "PASS"
            )

            poc_result["validation_reason"] = (
                validation.validation_reason
            )