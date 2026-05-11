## Project Structure

```text
VIPER/
│
├── Dockerfile                  # Docker environment for Syft, Grype, CodeQL, Node.js
├── requirements.txt            # Python dependencies
├── README.md
│
├── outputs/                    # Generated analysis artifacts
│   ├── repos/                  # Cloned target repositories
│   ├── sbom/                   # Syft-generated SBOM files
│   ├── vulns/                  # Grype vulnerability reports
│   ├── codeql/                 # CodeQL databases and SARIF results
│   ├── pocs/                   # Generated PoC files
│   └── logs/                   # Pipeline execution logs
│
├── viper/
│   │
│   ├── main.py                 # CLI entry point
│   │
│   ├── core/
│   │   └── pipeline.py         # Main end-to-end pipeline orchestration
│   │
│   ├── analyzer/               # Static analysis layer
│   │   ├── repo_cloner.py      # Repository cloning and dependency installation
│   │   ├── syft_runner.py      # SBOM generation using Syft
│   │   ├── grype_runner.py     # Vulnerability detection using Grype
│   │   └── codeql_runner.py    # CodeQL database creation and analysis
│   │
│   ├── generator/              # PoC generation layer
│   │   │
│   │   ├── poc_generator.py    # LLM-based PoC generation
│   │   │
│   │   ├── context/            # Vulnerability context construction
│   │   │   ├── vuln_type_classifier.py
│   │   │   ├── function_selector.py
│   │   │   ├── snippet_selector.py
│   │   │   └── scripts/
│   │   │       └── extract_exports.js
│   │   │
│   │   ├── llm/
│   │   │   └── ollama_client.py
│   │   │
│   │   └── prompt/
│   │       └── poc_generation_prompt.py
│   │
│   ├── validator/              # PoC validation layer
│   │   └── (TODO)
│   │
│   └── reporter/               # Reporting and VEX generation
│       └── (TODO)
│
└── tests/                      # Optional test code
```
