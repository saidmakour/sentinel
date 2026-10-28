[![Python](https://img.shields.io/badge/python-%3E%3D3.13-blue?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/saidmakour/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/saidmakour/sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/saidmakour/sentinel)](https://github.com/saidmakour/sentinel)
[![GitHub stars](https://img.shields.io/github/stars/saidmakour/sentinel)](https://github.com/saidmakour/sentinel/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/saidmakour/sentinel)](https://github.com/saidmakour/sentinel/issues)
[![Last commit](https://img.shields.io/github/last-commit/saidmakour/sentinel)](https://github.com/saidmakour/sentinel/commits/main)
[![Ruff](https://img.shields.io/badge/lint-Ruff-orange?logo=ruff)](https://docs.astral.sh/ruff/)
[![Mypy](https://img.shields.io/badge/type%20checking-mypy-blue)](https://mypy.readthedocs.io/)
[![Pyright](https://img.shields.io/badge/type%20checking-Pyright-blue)](https://github.com/microsoft/pyright)
[![uv](https://img.shields.io/badge/package%20manager-uv-de5fe9?logo=uv)](https://docs.astral.sh/uv/)

![Image locale](./sentinel.png)

# Sentinel

**Sentinel** is an internal vulnerability scanner designed to identify,
normalize and evaluate security vulnerabilities affecting project
dependencies.

Sentinel analyzes dependency manifests and lock files, queries multiple
vulnerability sources, enriches findings with additional security
information and generates security reports.

---
📖 _Read this in other languages:_ [French](README.fr.md)

---

## Features

Sentinel currently provides:

- Dependency discovery and parsing
- Support for multiple package ecosystems
- Vulnerability detection
- Multiple vulnerability providers
- Vulnerability normalization and deduplication
- Vulnerability status tracking
- Severity classification
- CVSS information
- CISA KEV enrichment
- EPSS enrichment
- Remediation information
- Fixed-version detection
- Dependency security status
- Global security status
- Risk score calculation
- Scan history
- CLI interface
- REST API
- HTML, JSON, Markdown and SARIF reporting
- Database persistence
- Database migrations with Alembic
- PostgreSQL support
- Automated tests and static analysis

---

## Supported Ecosystems

Sentinel supports dependency analysis for several ecosystems.

### Python

- `requirements.txt`
- `Pipfile`
- `poetry.lock`
- `uv.lock`
- `pyproject.toml`

### Java

- Maven
- Gradle
- Gradle Kotlin DSL

### Node.js

- npm
- Yarn
- pnpm

### PHP

- Composer

## GO

- go.mod
- go.sum

## RUBY

- gemfile.lock
- gemfile

The plugins architecture is extensible and allows additional language
parsers and ecosystems to be added independently.

---

## Vulnerability Providers

Sentinel can retrieve vulnerability information from several sources:

- OSV
- NVD
- GitHub Security Advisories (GHSA)
- GitHub

Additional enrichment sources include:

- CISA Known Exploited Vulnerabilities (KEV)
- EPSS

Each provider is implemented independently and integrated through the
provider architecture.

---

## Architecture

The project follows a modular architecture separating scanning,
vulnerability retrieval, enrichment, normalization, security evaluation
and reporting.

```text
sentinel/
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── migrations/
│   └── versions/
│
├── sentinel/
│   ├── api/
│   │   ├── mappers/
│   │   ├── routers/
│   │   └── schemas/
│   │
│   ├── cli/
│   ├── config/
│   │
│   ├── doctor/
│   │   └── checks/
│   │
│   ├── dto/
│   ├── engine/
│   │
│   ├── enrichers/
│   │   ├── epss/
│   │   └── kev/
│   │
│   ├── enums/
│   ├── exceptions/
│   ├── log/
│   ├── models/
│   │
│   ├── plugins/
│   │   ├── go/
│   │   |   └── parseurs/
│   │   ├── java/
│   │   |   └── parseurs/
│   │   ├── node/
│   │   |   └── parseurs/
│   │   ├── php/
│   │   |   └── parseurs/
│   │   ├── python/
│   │   |   └── parseurs/
│   │   └── ruby/
│   │       └── parseurs/
│   │
│   ├── profiles/
│   │
│   ├── providers/
│   │   ├── ghsa/
│   │   ├── github/
│   │   ├── nvd/
│   │   └── osv/
│   │
│   ├── renderers/
│   ├── repositories/
│   │
│   ├── scanners/
│   │   └── parseurs/
│   ├── security/
│   │
│   ├── services/
│   │   └── version_comparators/
│   │
│   ├── sources/
│   │   └── git/
│   │       └── authentication/
│   │
│   └── utils/
│
├── tests/
│
├── .env.exemple
├── alembic.ini
├── pyproject.toml
├── README.fr.md
├── README.md
└── uv.lock
```
---

## Main components

### Engine

The engine coordinates the complete scanning process.

It is responsible for:

* 1 Discovering dependencies
* 2 Querying vulnerability providers
* 3 Enriching findings
* 4 Normalizing findings
* 5 Building the scan result
* 6 Calculating the security status
  
---

### Plugins

Plugins identify dependency files and extract dependencies from them.

Parsers are organized by ecosystem:

```text
plugins/
├── go/
├── java/
├── node/
├── php/
├── python/
└── ruby/
```
---

### Providers

Providers retrieve vulnerability information from external vulnerability databases.

```text
providers/
├── ghsa/
├── github/
├── nvd/
└── osv/
```
---

### Enrichers

Enrichers add additional security information to vulnerability findings.

```text
enrichers/
├── epss/
└── kev/
```
---

### Services

Services contain business logic such as:

* security status calculation
* dependency security evaluation
* risk scoring
* version comparison
* scan reporting
* Renderers

Renderers transform scan results into different report formats.

Supported formats include:

* HTML
* JSON
* Markdown
* SARIF
  
---

### API

The REST API is implemented with FastAPI.

```text
api/
├── mappers/
├── routers/
└── schemas/
```

---

## Requirements

Sentinel requires:

Python 3.13 or newer
PostgreSQL 16 or newer

For development:

Git
pytest
Ruff
mypy
Pyright

Docker is optional for local development but provides the recommended containerized PostgreSQL environment.

---

## Installation

### Clone the repository

```bash
git clone <repository-url>
cd sentinel
```

### Using PIP

#### Create a virtual environment

##### Windows

```PowerShell
py -3.13 -m venv .venv
```

Activate it:

```PowerShell
.venv\Scripts\activate
```

##### Linux / macOS

```bash
python3.13 -m venv .venv
source .venv/bin/activate
```

## Install Sentinel

Install the project:

```bash
pip install .
```

For development:

```bash
pip install ".[dev]"
```bash

For testing:

```bash
pip install ".[test]"
```

Or both:

```bash
pip install ".[dev,test]"
```

### Using UV


If `uv` is not already installed:

#### Windows

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

#### Linux / macOS

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Verify the installation:

```bash
uv --version
```

### Create the virtual environment

Sentinel requires **Python 3.13 or later**.

With `uv`, the virtual environment can be created automatically using the appropriate Python version:

```bash
uv venv --python 3.13
```

### Activate the environment

#### Windows — PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

#### Linux / macOS

```bash
source .venv/bin/activate
```

### Install Sentinel

#### Standard installation

```bash
uv pip install .
```

#### Development installation

```bash
uv pip install ".[dev]"
```

#### Installation with test dependencies

```bash
uv pip install ".[test]"
```

#### Development + test installation

```bash
uv pip install ".[dev,test]"
```


You can also run Sentinel commands directly with `uv`, without manually activating the virtual environment.

For example:

```bash
uv run sentinel --help
```

Run a scan:

```bash
uv run sentinel scan run
```

Run the tests:

```bash
uv run pytest
```

Check the code:

```bash
uv run ruff check .
uv run mypy sentinel
uv run pyright sentinel
```

---

## Configuration

Sentinel uses environment variables for configuration.

Create a .env file at the project root.

Example:

```text
APP_NAME=Sentinel
APP_VERSION=1.0.0
LOG_LEVEL=INFO
DEBUG=false

DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel

WORKSPACE=workspace
REPORT_PATH=reports
EXPORT_PATH=exports
DATABASE=database
LOGS=logs
CACHE=cache
TESTS=tests

MAX_WORKERS=4
MAX_RETRIES=3

OSV_ENABLED=true
OSV_BASE_URL=https://api.osv.dev/v1/query
OSV_DEFAULT_TIMEOUT=30

NVD_ENABLED=true
NVD_BASE_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxx

GHSA_ENABLED=true
GHSA_BASE_URL=https://api.github.com/advisories
GHSA_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

KEV_ENABLED=true
KEV_BASE_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

EPSS_ENABLED=true
EPSS_BASE_URL=https://api.first.org/data/v1/epss
EPSS_DEFAULT_TIMEOUT=30
EPSS_BATCH_SIZE=100
```

Sensitive credentials such as API keys and tokens should not be committed to the repository.

---

## Database

Sentinel uses SQLAlchemy for database access and Alembic for database migrations.

PostgreSQL is the target database for the application.

The database URL is configured through:

```text
DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel
```

The application obtains the database configuration through the DATABASE_URL environment variable.

### Alembic

Alembic manages the database schema.

Migration files are located under:

```text
migrations/
└── versions/
```

The Alembic configuration is located in:

```text
alembic.ini
```
The migration environment uses the application's SQLAlchemy engine and metadata.

### Run migrations

Apply all migrations:

```bash
alembic upgrade head
```

Check the current migration:

```bash
alembic current
```

Display migration history:

```bash
alembic history
```

Create a new migration:

```bash
alembic revision --autogenerate -m "description"
```

Review generated migrations before applying them.

## PostgreSQL

Sentinel can run with a locally installed PostgreSQL server or with the PostgreSQL container provided by Docker Compose.

The default Docker PostgreSQL configuration is:

```env
Database: sentinel
User:     sentinel
Password: sentinel
Port:     5432
```

The application container connects to PostgreSQL using the Docker service name:

```text
postgres
```

Therefore, inside Docker:

```env
DATABASE_URL=postgresql+psycopg://sentinel:sentinel@postgres:5432/sentinel
```

When running Sentinel directly on the host:

```env
DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel
```
---

## Docker

Docker configuration is located in:

```text
docker/
├── Dockerfile
├── docker-compose.yml
└── entrypoint.sh
```

The Docker environment consists of two services:

```text
PostgreSQL
    │
    ▼
Sentinel API
```

PostgreSQL uses a persistent Docker volume.

The PostgreSQL service includes a health check to ensure that the database is ready before Sentinel starts.

## Build the containers

From the project root:

```bash
docker compose -f docker/docker-compose.yml build
```

Start the application

```bash
docker compose -f docker/docker-compose.yml up
```

Start in detached mode:

```bash
docker compose -f docker/docker-compose.yml up -d
```

Stop the application

```bash
docker compose -f docker/docker-compose.yml down
```

The PostgreSQL data is stored in the Docker volume:

```bash
postgres_data
```

---

## API

Sentinel exposes a REST API implemented with FastAPI.

The application is started with:

```bash
uvicorn sentinel.api.app:app --host 0.0.0.0 --port 8000
```

The API is then available at:

```bash
http://localhost:8000
```

Interactive API documentation is available through FastAPI.

### Swagger UI:

```bash
http://localhost:8000/docs
```

ReDoc:

```bash
http://localhost:8000/redoc
```

When running through Docker, port 8000 is exposed by the Sentinel container.

---

## CLI

Sentinel provides a command-line interface.

After installation:

```bash
sentinel --help
                                                                                                                                                      
 Usage: sentinel [OPTIONS] COMMAND [ARGS]...                                                                                                          
                                                                                                                                                      
 Interface en ligne de commande Sentinel pour gérer les applications, les dépôts, les scans et les rapports.                                          
                                                                                                                                                      
╭─ Options──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.                                                           │
│ --show-completion             Show completion for the current shell, to copy it or customize the installation.                    │
│ --help                        Show this message and exit.                                                                         │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ sys     Exécuter les commandes système et de diagnostic de Sentinel.                                                              │
│ app     Gérer les applications enregistrées dans Sentinel.                                                                        │
│ repo    Gérer les dépôts de code associés aux applications.                                                                       │
│ scan    Lancer des scans sur les dépôts enregistrés.                                                                              │
│ report  Consulter les rapports de scan générés par Sentinel.                                                                      │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
The CLI is implemented in:

```text
sentinel/cli/
```

The application entry point is:

```bash
sentinel.main:main
```

## n process

A Sentinel scan follows the general pipeline below:

```text
Repository
    │
    ▼
Dependency discovery
    │
    ▼
Dependency parsing
    │
    ▼
Vulnerability providers
    │
    ├── OSV
    ├── NVD
    └── GHSA
    │
    ▼
Enrichment
    │
    ├── KEV
    └── EPSS
    │
    ▼
Finding normalization
    │
    ▼
Security evaluation
    │
    ├── Dependency Security Status
    ├── Security Status
    └── Risk Score
    │
    ▼
Scan Report
    │
    ├── HTML
    ├── JSON
    ├── Markdown
    └── SARIF
```

## Vulnerability status

Sentinel distinguishes between three vulnerability states:

```text
OPEN
RESOLVED
UNKNOWN
```

A finding is considered OPEN when the vulnerability affects the installed dependency version.

A finding is considered RESOLVED when the installed version is no longer affected according to the available vulnerability information.

**UNKNOWN** is used when Sentinel cannot reliably determine the affected status.

## Security status

Sentinel calculates a global security status from the findings.

The main states are:

* SECURE
* UNKNOWN
* AT_RISK
* CRITICAL

The general rules are:

* No findings → *SECURE*
* All findings resolved → *SECURE*
* Only unknown findings → *UNKNOWN*
* Open LOW/MEDIUM/HIGH findings → *AT_RISK*
* Open CRITICAL findings → *CRITICAL*
* Open findings associated with KEV can also result in CRITICAL

The security status is intended to provide a concise answer to the question:

Is the scanned project currently considered secure?

## Risk Score

Sentinel calculates a risk score from open vulnerability severities.

The current formula is:

```bash
Risk Score =
    Critical × 10
  + High × 5
  + Medium × 2
  + Low × 1
```

The score is intended as a relative risk indicator and should be interpreted together with the number, severity and status of findings.

## Reports

Sentinel supports several report formats.

### HTML

HTML reports are intended for human-readable security analysis.

### JSON

JSON reports provide a structured representation suitable for integration
with other applications.

### Markdown

Markdown reports are useful for documentation and source-control workflows.

### SARIF

SARIF reports are intended for integration with security tooling and
development platforms supporting the SARIF format.

## Tests

Tests are located under:

```bash
tests/
```

Run the complete test suite:

```bash
uv run pytest
```

Run tests with verbose output:

```bash
uv run pytest -vv
```

Run tests with coverage:

```bash
uv run pytest --cov=sentinel
```

Generate an HTML coverage report:

```bash
uv run pytest --cov=sentinel --cov-report=html
```

The generated report is placed under:

```
htmlcov/
```
---

## Code Quality

Sentinel uses several static analysis and security tools.


### Ruff

Run Ruff:

```bash
ruff check .
```

Format the project:

```bash
ruff format .
```

### mypy

Run mypy:

```bash
mypy sentinel
```

### Pyright

Run Pyright:

```bash
pyright
```

### Development checks

Before submitting changes, the following checks should pass:

```bash
pytest
ruff check .
mypy sentinel
pyright
bandit -r sentinel
```

---

## Project principles

Sentinel is designed around several principles:

* Modularity

* Scanners, providers, enrichers and renderers are independent components.

* Extensibility

*New ecosystems, vulnerability providers and report formats can be added without changing the complete scanning pipeline.

---

## Normalization

* Vulnerability information coming from different providers is normalized into a common internal representation.

* Deterministic security evaluation

* Security status and risk calculations are based on explicit rules.

* Separation of concerns

---

## The project separates:

* dependency discovery
* vulnerability retrieval
* enrichment
* normalization
* business rules
* persistence
* API
* reporting
* Security

Sentinel is a vulnerability analysis tool. Its results should be considered an important security signal but not as an absolute guarantee that a project is secure.

A result can depend on:

* vulnerability database coverage
* provider availability
* vulnerability metadata
* affected-version information
* dependency resolution
* unknown vulnerability states

A SECURE result therefore means that Sentinel did not identify an applicable open vulnerability according to the information available to the scanner at the time of the scan.

---

## Project Status

Sentinel is currently under active development.

Current major components include:

* Dependency scanners
* Vulnerability providers
* Vulnerability enrichment
* Finding normalization
* Security status evaluation
* Risk scoring
* Scan persistence
* PostgreSQL support
* Alembic migrations
* REST API
* CLI
* Report generation
* Automated tests
* Static analysis

## License

Sentinel is open-source software distributed under the License [GPL](https://www.gnu.org/licenses/licenses.html)