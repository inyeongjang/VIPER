pocgen-project/
├── pyproject.toml
├── README.md
└── src/
    └── pocgen/
        ├── __init__.py
        ├── main.py
        │
        ├── core/
        │   ├── __init__.py
        │   ├── models.py
        │   ├── config.py
        │   └── pipeline.py
        │
        ├── analyzer/
        │   ├── __init__.py
        │   ├── repo_cloner.py
        │   ├── syft_runner.py
        │   ├── grype_runner.py
        │   └── codeql_runner.py
        │
        ├── generator/
        │   ├── __init__.py
        │   ├── poc_generator.py
        │   ├── context_builder.py
        │   ├── function_selector.py
        │   ├── snippet_selector.py
        │   ├── vuln_type_classifier.py
        │   ├── ollama_client.py
        │   └── prompts.py
        │
        ├── validator/
        │   ├── __init__.py
        │   ├── local_runner.py
        │   ├── sandbox.py
        │   └── validator.py
        │
        └── reporter/
            ├── __init__.py
            └── vex_builder.py