
[![Python](https://img.shields.io/badge/python-%3E%3D3.13-blue?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/saidmakour/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/saidmakour/sentinel/actions/workflows/ci.yml)
[![Ruff](https://img.shields.io/badge/lint-Ruff-orange?logo=ruff)](https://docs.astral.sh/ruff/)
[![Mypy](https://img.shields.io/badge/type%20checking-mypy-blue)](https://mypy.readthedocs.io/)
[![Pyright](https://img.shields.io/badge/type%20checking-Pyright-blue)](https://github.com/microsoft/pyright)
[![uv](https://img.shields.io/badge/package%20manager-uv-de5fe9?logo=uv)](https://docs.astral.sh/uv/)

![Image locale](./sentinel.png)

# Sentinel

**Sentinel** est un scanner de vulnérabilités interne destiné à identifier,
normaliser et évaluer les vulnérabilités de sécurité affectant les
dépendances d'un projet.

Sentinel analyse les fichiers de dépendances et les fichiers de verrouillage,
interroge plusieurs sources de vulnérabilités, enrichit les résultats avec
des informations de sécurité complémentaires et génère des rapports de
sécurité.

---
📖 _Lire dans une autre  langue :_ [Anglais](README.md)

## Fonctionnalités

Sentinel fournit actuellement les fonctionnalités suivantes :

- Détection des dépendances
- Analyse de plusieurs écosystèmes de packages
- Détection des vulnérabilités
- Interrogation de plusieurs sources de vulnérabilités
- Normalisation et déduplication des vulnérabilités
- Gestion du statut des vulnérabilités
- Classification par niveau de sévérité
- Gestion des informations CVSS
- Enrichissement CISA KEV
- Enrichissement EPSS
- Informations de remédiation
- Détection des versions corrigées
- Évaluation de la sécurité des dépendances
- Calcul du statut global de sécurité
- Calcul d'un score de risque
- Historique des scans
- Interface en ligne de commande (CLI)
- API REST
- Génération de rapports HTML, JSON, Markdown et SARIF
- Persistance des données
- Migrations de base de données avec Alembic
- Support de PostgreSQL
- Tests automatisés
- Analyse statique du code

---

# Écosystèmes supportés

Sentinel prend en charge l'analyse des dépendances de plusieurs
écosystèmes.

## Python

- `requirements.txt`
- `Pipfile`
- `poetry.lock`
- `uv.lock`
- `pyproject.toml`

## Java

- Maven
- Gradle
- Gradle Kotlin DSL

## Node.js

- npm
- Yarn
- pnpm

## PHP

- Composer

## GO

- go.mod
- go.sum

## RUBY

- gemfile.lock
- gemfile

L'architecture des plugins est extensible et permet d'ajouter de nouveaux
parseurs de language et de nouveaux écosystèmes indépendamment du reste de
l'application.

---

# Sources de vulnérabilités

Sentinel peut récupérer les informations de vulnérabilités auprès de
plusieurs sources :

- OSV
- NVD
- GitHub Security Advisories (GHSA)
- Github

Des sources complémentaires sont utilisées pour enrichir les résultats :

- CISA Known Exploited Vulnerabilities (KEV)
- EPSS

Chaque fournisseur est implémenté indépendamment et intégré à Sentinel via
l'architecture des providers.

---

# Architecture

Le projet utilise une architecture modulaire séparant les différentes
responsabilités : analyse des dépendances, récupération des vulnérabilités,
enrichissement, normalisation, évaluation de la sécurité et génération des
rapports.

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

# Principaux composants

## Engine

L'engine orchestre l'ensemble du processus de scan.

Il est notamment responsable de :

1. La découverte des dépendances
2. L'interrogation des providers de vulnérabilités
3. L'enrichissement des résultats
4. La normalisation des vulnérabilités
5. La construction du résultat du scan
6. Le calcul du statut de sécurité

## Plugnins

Les plugins identifient les fichiers de dépendances et extraient les dépendances qu'ils contiennent.

Les parseurs sont organisés par écosystème pour chaque language :

```text
plugins/
├── go/
├── java/
├── node/
├── php/
├── python/
└── ruby/
```

## Providers

Les providers récupèrent les informations de vulnérabilités depuis les différentes bases de données de sécurité.

```text
providers/
├── ghsa/
├── github/
├── nvd/
└── osv/
```

## Enrichers

Les enrichers ajoutent des informations complémentaires aux vulnérabilités.

```text
enrichers/
├── epss/
└── kev/
```

## Services

Les services contiennent la logique métier de l'application, notamment :

* le calcul du statut de sécurité ;
* l'évaluation de la sécurité des dépendances ;
* le calcul du score de risque ;
* la comparaison des versions ;
* la génération des rapports de scan.

## Renderers

Les renderers transforment les résultats d'un scan en différents formats de rapport.

Formats actuellement supportés :

* HTML
* JSON
* Markdown
* SARIF
* API

L'API REST est implémentée avec FastAPI.

```text
api/
├── mappers/
├── routers/
└── schemas/
```

## Prérequis

Sentinel nécessite :

* Python 3.13 ou supérieur
* PostgreSQL 16 ou supérieur

Pour le développement :

* Git
* pytest
* Ruff
* mypy
* Pyright

Docker est optionnel pour le développement local mais constitue le mode recommandé pour exécuter PostgreSQL dans un environnement conteneurisé.

## Installation

### Cloner le dépôt

```PowerShell
git clone <URL-DU-DEPOT>
cd sentinel
```
### Utilisation de PIP


#### Créer l'environnement virtuel

##### Windows

```PowerShell
py -3.13 -m venv .venv
```

#### Activer l'environnement :

```PowerShell
.venv\Scripts\activate
```

##### Linux / macOS

```bash
python3.13 -m venv .venv
source .venv/bin/activate
```

#### Installer Sentinel

Installation standard :

```bash
pip install .
```

Installation pour le développement :

```bash
pip install ".[dev]"
```

Installation des dépendances de test :

```bash
pip install ".[test]"
```

Installation développement + tests :

```bash
pip install ".[dev,test]"
```

### Utilisation d'UV

#### Installer `uv`

Si `uv` n'est pas encore installé :

##### Windows

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

##### Linux / macOS

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Vérifier l'installation :

```bash
uv --version
```

#### Créer l'environnement virtuel

Sentinel nécessite **Python 3.13 ou supérieur**.

Avec `uv`, l'environnement virtuel peut être créé automatiquement avec la version de Python appropriée :

```bash
uv venv --python 3.13
```

#### Activer l'environnement

##### Windows — PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

##### Linux / macOS

```bash
source .venv/bin/activate
```

#### Installer Sentinel

##### Installation standard

```bash
uv pip install .
```

##### Installation pour le développement

```bash
uv pip install ".[dev]"
```

##### Installation avec les dépendances de test

```bash
uv pip install ".[test]"
```

##### Installation développement + tests

```bash
uv pip install ".[dev,test]"
```

#### Utilisation avec `uv`

Il est également possible d'exécuter les commandes Sentinel directement avec `uv`, sans activer manuellement l'environnement virtuel.

Par exemple :

```bash
sentinel --help
```

Lancer un scan :

```bash
sentinel scan run 
```

Lancer les tests :

```bash
uv run pytest
```

Vérifier le code :

```bash
uv run ruff check .
uv run mypy sentinel
uv run pyright sentinel
```

### Configuration

Sentinel utilise des variables d'environnement pour sa configuration.

Créer un fichier .env à la racine du projet.

Exemple :

```env
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

Les informations sensibles, notamment les clés API et les tokens, ne doivent pas être versionnées dans le dépôt Git.

## Base de données

Sentinel utilise SQLAlchemy pour l'accès à la base de données et Alembic pour gérer les migrations du schéma.

PostgreSQL constitue la base de données cible de l'application.

L'URL de connexion est configurée avec la variable :

```env
DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel
```

La configuration de la base de données est récupérée par l'application via la variable d'environnement DATABASE_URL.

### Migrations Alembic

Alembic permet de gérer l'évolution du schéma de la base de données.

Les migrations sont stockées dans :

```text
migrations/
└── versions/
```

La configuration Alembic se trouve dans :

```text
alembic.ini
```

L'environnement Alembic utilise le moteur SQLAlchemy et les métadonnées des modèles de Sentinel.

### Appliquer les migrations

```bash
alembic upgrade head
```

### Afficher la migration courante

```bash
alembic current
```

### Afficher l'historique des migrations

```bash
alembic history
```

### Générer une migration

```bash
alembic revision --autogenerate -m "description"
```

Les migrations générées automatiquement doivent être vérifiées avant leur application.

## PostgreSQL

Sentinel peut fonctionner avec :

* une instance PostgreSQL installée directement sur la machine ;
* une instance PostgreSQL exécutée dans Docker.

La configuration PostgreSQL utilisée par Docker est :

```env
Base de données : sentinel
Utilisateur     : sentinel
Mot de passe    : sentinel
Port             : 5432
```

### Exécution locale

Lorsque Sentinel s'exécute directement sur la machine :

```env
DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel
```

### Exécution avec Docker

Lorsque Sentinel s'exécute dans Docker, PostgreSQL est accessible via le nom du service Docker :

```env
DATABASE_URL=postgresql+psycopg://sentinel:sentinel@postgres:5432/sentinel
```

## Docker

La configuration Docker est regroupée dans :

```text
docker/
├── Dockerfile
├── docker-compose.yml
└── entrypoint.sh
``` 

L'environnement Docker comprend deux services :

```text
PostgreSQL
    │
    ▼
Sentinel API
```

Le service PostgreSQL utilise un volume Docker persistant afin de conserver les données de la base.

Un healthcheck vérifie que PostgreSQL est disponible avant le démarrage du service Sentinel.

### Construire les images

Depuis la racine du projet :

```bash
docker compose -f docker/docker-compose.yml build
```

Démarrer l'application

```bash
docker compose -f docker/docker-compose.yml up
```

En arrière-plan :

```bash
docker compose -f docker/docker-compose.yml up -d
```

Arrêter l'application

```bash
docker compose -f docker/docker-compose.yml down
```

Les données PostgreSQL sont conservées dans le volume Docker :

```bash
postgres_data

```
## API REST

Sentinel expose une API REST développée avec FastAPI.

L'application peut être démarrée avec :

```bash
uvicorn sentinel.api.app:app --host 0.0.0.0 --port 8000
```

L'API est alors accessible à :

```bash
http://localhost:8000
```

### Documentation Swagger

```bash
http://localhost:8000/docs
```

### Documentation ReDoc

```bash
http://localhost:8000/redoc
```

Lorsqu'elle est exécutée avec Docker, l'API utilise le port `8000`.

## Interface en ligne de commande

Sentinel fournit également une interface en ligne de commande.

Après installation :

```bash
sentinel --help
                                                                                                                                                      
 Usage: sentinel [OPTIONS] COMMAND [ARGS]...                                                                                                          
                                                                                                                                                      
 Interface en ligne de commande Sentinel pour gérer les applications, les dépôts, les scans et les rapports.                                          
                                                                                                                                                      
╭─ Options───────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --install-completion          Install completion for the current shell.                                                    │
│ --show-completion             Show completion for the current shell, to copy it or customize the installation.             │
│ --help                        Show this message and exit.                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ sys     Exécuter les commandes système et de diagnostic de Sentinel.                                                        │
│ app     Gérer les applications enregistrées dans Sentinel.                                                                  │
│ repo    Gérer les dépôts de code associés aux applications.                                                                 │
│ scan    Lancer des scans sur les dépôts enregistrés.                                                                        │
│ report  Consulter les rapports de scan générés par Sentinel.                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### Commandes système

```bash
 sentinel sys --help
                                                                                                                                                             
 Usage: sentinel sys [OPTIONS] COMMAND [ARGS]...                                                                                                             
                                                                                                                                                             
 Exécuter les commandes système et de diagnostic de Sentinel.                                                                                                
                                                                                                                                                             
╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message end.                                                                                            │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ version  Afficher la version courante de Sentinel.                                                                                 │
│ init     Initialiser l'espace de travail                                                                                           │
│ doctor   Vérifier l'installation locale et les chemins                                                                             │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```

### Comandes repo

```bash
sentinel repo --help 
                                                                                                                                                                    
 Usage: sentinel repo [OPTIONS] COMMAND [ARGS]...                                                                                                                   
                                                                                                                                                                    
 Gérer les dépôts de code associés aux applications.                                                                                                                
                                                                                                                                                                    
╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                       │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ list_all  Lister tout dépôts                                                                                                      │
│ list      Lister les dépôts d'une application.                                                                                    │
│ add       Ajouter un dépôt à une application.                                                                                     │
│ delete    Supprimer un dépôt d'une application.                                                                                   │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```

### Commandes app

```bash
sentinel app --help
                                                                                                                                                                    
 Usage: sentinel app [OPTIONS] COMMAND [ARGS]...                                                                                                                    
                                                                                                                                                                    
 Gérer les applications enregistrées dans Sentinel.                                                                                                                 
                                                                                                                                                                    
╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and                                                                                              │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ create  Créer une nouvelle                                                                                                         │
│ list    Lister toutes les                                                                                                          │
│ show    Afficher le détail d'une aplication.                                                                                       │
│ delete  Supprimer une                                                                                                              │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```


### Commandes scan

```bash
sentinel scan --help
                                                                                                                                                                    
 Usage: sentinel scan [OPTIONS] COMMAND [ARGS]...                                                                                                                   
                                                                                                                                                                    
 Lancer des scans sur les dépôts enregistrés.                                                                                                                       
                                                                                                                                                                    
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ run  Lancer un scan sur un dépôt d'application.                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```

### Commandes report

```bash
sentinel report --help
                                                                                                                                                                    
 Usage: sentinel report [OPTIONS] COMMAND [ARGS]...                                                                                                                 
                                                                                                                                                                    
 Consulter les rapports de scan générés par Sentinel.                                                                                                               
                                                                                                                                                                    
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ latest   Afficher le rapport du dernier scan exécuté.                                                                     │
│ show     Afficher le rapport d'un scan précis.                                                                            │
│ history  Afficher l'historique des rapports de scan.                                                                      │
│ export   Exporter le rapport d'un scan.                                                                                   │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```

Utiliser chaque fois l'option `--help` pour connaitre les options et les arguments des commandes

Pour le projet sentiel :

1. Exec les commandes sys pour l'initialiation et les checks
2. Exec les commanades repo pour la création du répository
3. Exec les commandes app pour l'associer l'application au repository
4. Exec les commandes scan pour scanner le dépôt
5. Exec les commandes report pour exéporter les reports

```text
sentinel sys ....
    │
    ▼
sentinel repo add ...
    │
    ▼
sentinel app create ...
    │
    ▼
sentinel scan run ...
    │
    ▼
sentienl report export ...
```

Le code de la CLI se trouve dans :

```text
sentinel/cli/
```

Le point d'entrée est :
```bash
sentinel.main:main
```

## Processus de scan

Un scan Sentinel suit globalement le pipeline suivant :

```text
Projet / dépôt
      │
      ▼
Découverte des dépendances
      │
      ▼
Parsing des dépendances
      │
      ▼
Providers de vulnérabilités
      │
      ├── OSV
      ├── NVD
      ├── GHSA
      └── GitHUB
      │
      ▼
Enrichissement
      │
      ├── KEV
      └── EPSS
      │
      ▼
Normalisation des findings
      │
      ▼
Évaluation de la sécurité
      │
      ├── Statut des dépendances
      ├── Statut global
      └── Risk Score
      │
      ▼
Rapport de scan
      │
      ├── HTML
      ├── JSON
      ├── Markdown
      └── SARIF
```

## Statut des vulnérabilités

Sentinel distingue trois états principaux pour une vulnérabilité :

```text
OPEN
RESOLVED
UNKNOWN
```

### OPEN

La vulnérabilité affecte la version installée de la dépendance.

### RESOLVED

La version installée n'est plus considérée comme affectée selon les informations disponibles.

### UNKNOWN

Sentinel ne dispose pas d'informations suffisantes pour déterminer de manière fiable si la vulnérabilité affecte la version installée.

## Statut de sécurité

Sentinel calcule un statut global de sécurité à partir des findings.

Les principaux statuts sont :

```text
SECURE
UNKNOWN
AT_RISK
CRITICAL
```

Les règles générales sont les suivantes :

* Aucun finding → `SECURE`
* Tous les findings sont résolus → `SECURE`
* Uniquement des findings UNKNOWN → `UNKNOWN`
* Findings OPEN de sévérité LOW/MEDIUM/HIGH → `AT_RISK`
* Findings OPEN de sévérité CRITICAL → `CRITICAL`
* Un finding OPEN associé à KEV peut également conduire au statut `CRITICAL`

Le statut de sécurité fournit une réponse synthétique à la question :

Le projet analysé est-il actuellement considéré comme sécurisé ?

## Risk Score

Sentinel calcule un score de risque à partir des vulnérabilités ouvertes.

La formule actuelle est :

```bash
Risk Score =
    Critical × 10
  + High × 5
  + Medium × 2
  + Low × 1
```

Le Risk Score constitue un indicateur de risque relatif.

Il doit être interprété en complément :

* du nombre de vulnérabilités ;
* de leur sévérité ;
* de leur statut ;
* de la présence éventuelle dans KEV ;
* des informations de remédiation.

## Rapports

Sentinel prend en charge plusieurs formats de rapports.

### HTML

Les rapports HTML sont destinés à une analyse humaine des résultats.

### JSON

Les rapports JSON fournissent une représentation structurée des résultats, adaptée à une intégration avec d'autres applications.

### Markdown

Les rapports Markdown peuvent être utilisés dans la documentation et les workflows Git.

### SARIF

Le format SARIF est destiné à l'intégration avec les outils de sécurité et les plateformes compatibles avec ce standard.

## Tests

Les tests sont situés dans :

```bash
tests/
```

Exécuter l'ensemble des tests :

```bash
uv run pytest
```

Exécution détaillée :

```bash
uv run pytest -vv
```

Avec couverture :

```bash
uv run pytest --cov=sentinel
```

Générer un rapport HTML de couverture :

```bash
uv run pytest --cov=sentinel --cov-report=html
```

Le rapport est généré dans :

```bash
htmlcov/
```

## Qualité du code

Sentinel utilise plusieurs outils d'analyse statique et de sécurité.

### Ruff

#### Vérification du code :

```bash
uv run ruff check . --fix
```

#### Formatage :

```bash
uv run ruff format .
```

### mypy

```bash
uv run mypy sentinel
```

### Pyright

```bash
uv run pyright sentinel
````

## Vérifications de développement

Avant de valider une modification, les vérifications suivantes doivent passer :

```bash
uv run pytest
ruff check .
uv run mypy sentinel
uv run pyright sentinel
```

## Principes du projet

Sentinel repose sur plusieurs principes d'architecture.

### Modularité

Les scanners, providers, enrichers et renderers sont des composants indépendants.

### Extensibilité

De nouveaux écosystèmes, providers et formats de rapports peuvent être ajoutés sans modifier l'ensemble du pipeline de scan.

### Normalisation

Les informations provenant de plusieurs providers sont normalisées vers un modèle interne commun.

### Évaluation déterministe

Le statut de sécurité et le calcul du risque reposent sur des règles explicites.

### Séparation des responsabilités

Le projet sépare notamment :

* la découverte des dépendances ;
* l'analyse des dépendances ;
* la récupération des vulnérabilités ;
* l'enrichissement ;
* la normalisation ;
* la logique métier ;
* la persistance ;
* l'API ;
* la génération des rapports.

## Sécurité et limites

Sentinel est un outil d'analyse de vulnérabilités.

Ses résultats constituent un indicateur de sécurité important mais ne peuvent
pas être considérés comme une garantie absolue qu'un projet est sécurisé.

Les résultats peuvent notamment dépendre :

* de la couverture des bases de vulnérabilités ;
* de la disponibilité des providers ;
* de la qualité des métadonnées de vulnérabilités ;
* des informations concernant les versions affectées ;
* de la résolution des dépendances ;
* des vulnérabilités dont le statut ne peut pas être déterminé.

Ainsi, un statut SECURE signifie que Sentinel n'a identifié aucune vulnérabilité ouverte applicable selon les informations disponibles au moment du scan.

## État du projet

Sentinel est actuellement en développement actif.

Les principaux composants actuellement disponibles sont :

* scanners de dépendances ;
* providers de vulnérabilités ;
* enrichissement des vulnérabilités ;
* normalisation des findings ;
* évaluation du statut de sécurité ;
* calcul du Risk Score ;
* persistance des scans ;
* PostgreSQL ;
* migrations Alembic ;
* API REST ;
* interface CLI ;
* génération de rapports ;
* tests automatisés ;
* analyse statique du code.

## Licence

Sentinel est un logiciel open-source distribué sous la licence [GPL](https://www.gnu.org/licenses/licenses.html).


## Glossaire et abréviations

Cette section présente les principales abréviations et notions utilisées dans
Sentinel.

| Abréviation | Signification | Description |
|---|---|---|
| **API** | Application Programming Interface | Interface permettant à des applications ou services de communiquer entre eux. |
| **CVE** | Common Vulnerabilities and Exposures | Identifiant public standardisé attribué à une vulnérabilité de sécurité connue. Un CVE est généralement représenté sous la forme `CVE-AAAA-NNNNN`. |
| **CVSS** | Common Vulnerability Scoring System | Système de notation permettant d'évaluer la gravité technique d'une vulnérabilité, généralement sur une échelle de 0 à 10. |
| **EPSS** | Exploit Prediction Scoring System | Score estimant la probabilité qu'une vulnérabilité soit exploitée dans la nature. |
| **GHSA** | GitHub Security Advisory | Identifiant et base d'avis de sécurité publiés par GitHub concernant notamment les dépendances open source. |
| **KEV** | Known Exploited Vulnerabilities | Catalogue de vulnérabilités connues comme étant exploitées activement, maintenu par la CISA. |
| **NVD** | National Vulnerability Database | Base de données américaine de référence contenant notamment des informations sur les vulnérabilités CVE et leurs caractéristiques. |
| **OSV** | Open Source Vulnerabilities | Base de données de vulnérabilités open source développée notamment pour fournir des informations adaptées aux écosystèmes logiciels et aux versions de paquets. |
| **CISA** | Cybersecurity and Infrastructure Security Agency | Agence américaine chargée notamment de la cybersécurité et de la protection des infrastructures critiques. |
| **CWE** | Common Weakness Enumeration | Classification standardisée des types de faiblesses de sécurité dans les logiciels. |
| **JSON** | JavaScript Object Notation | Format texte structuré couramment utilisé pour échanger des données. |
| **SARIF** | Static Analysis Results Interchange Format | Format standard permettant de représenter et d'échanger des résultats d'analyse de sécurité ou de qualité du code. |
| **SQL** | Structured Query Language | Langage utilisé pour manipuler et interroger des bases de données relationnelles. |
| **ORM** | Object-Relational Mapping | Technique permettant de manipuler une base de données relationnelle à travers des objets Python. Sentinel utilise SQLAlchemy. |
| **CLI** | Command-Line Interface | Interface en ligne de commande permettant d'utiliser Sentinel depuis un terminal. |
| **HTTP** | HyperText Transfer Protocol | Protocole utilisé pour les communications entre clients et serveurs sur le Web. |
| **HTTPS** | HyperText Transfer Protocol Secure | Version sécurisée de HTTP utilisant TLS pour chiffrer les communications. |
| **TLS** | Transport Layer Security | Protocole cryptographique permettant notamment de sécuriser les communications réseau. |
| **URL** | Uniform Resource Locator | Adresse permettant d'identifier une ressource accessible sur un réseau. |
| **PyPI** | Python Package Index | Dépôt public de paquets Python. |
| **NPM** | Node Package Manager | Gestionnaire de paquets et écosystème principalement utilisé par JavaScript et Node.js. |
| **Maven** | Apache Maven | Outil de gestion de projets et de dépendances pour l'écosystème Java. |
| **Composer** | PHP Dependency Manager | Gestionnaire de dépendances pour l'écosystème PHP. |
| **SBOM** | Software Bill of Materials | Inventaire des composants logiciels et dépendances utilisés par une application. |
| **DB** | Database | Base de données. |
| **PostgreSQL** | PostgreSQL | Système de gestion de base de données relationnelle utilisé par Sentinel en environnement conteneurisé. |
| **SQLite** | SQLite | Système de base de données relationnelle embarqué. Utilisé notamment pour les environnements locaux ou de développement selon la configuration. |
| **Docker** | Docker | Plateforme de conteneurisation permettant d'exécuter une application et ses dépendances dans des environnements isolés. |
| **CI/CD** | Continuous Integration / Continuous Delivery | Pratiques permettant d'automatiser l'intégration, les tests et la livraison des logiciels. |

### Sources de vulnérabilités utilisées par Sentinel

Sentinel peut exploiter plusieurs sources de données afin de corréler et
d'enrichir les informations relatives aux vulnérabilités.

#### OSV

**OSV (Open Source Vulnerabilities)** est une base de données spécialisée
dans les vulnérabilités affectant les logiciels open source.

Sentinel l'utilise notamment pour rechercher les vulnérabilités associées
aux dépendances détectées lors d'un scan.

#### NVD

**NVD (National Vulnerability Database)** est une base de données de
vulnérabilités maintenue par le NIST aux États-Unis.

Elle fournit notamment des informations associées aux CVE, telles que les
scores CVSS, les descriptions et différentes métadonnées de vulnérabilité.

#### GHSA

**GHSA (GitHub Security Advisory)** désigne le système d'avis de sécurité
de GitHub.

Les identifiants GHSA permettent notamment d'identifier des vulnérabilités
affectant des bibliothèques et dépendances open source hébergées ou suivies
dans l'écosystème GitHub.

#### KEV

**KEV (Known Exploited Vulnerabilities)** désigne le catalogue de la CISA
regroupant les vulnérabilités dont l'exploitation est connue dans la nature.

Dans Sentinel, la présence d'une vulnérabilité dans le catalogue KEV constitue
un indicateur de risque important.

#### EPSS

**EPSS (Exploit Prediction Scoring System)** fournit une estimation de la
probabilité qu'une vulnérabilité soit exploitée dans la nature.

EPSS est donc différent de CVSS :

- **CVSS** mesure principalement la gravité technique d'une vulnérabilité ;
- **EPSS** estime la probabilité d'exploitation ;
- **KEV** indique qu'une exploitation est déjà connue.

### Exemple

Pour une vulnérabilité donnée, Sentinel peut ainsi disposer de plusieurs
indicateurs complémentaires :

```text
CVE
 │
 ├── CVSS  → gravité technique
 │
 ├── EPSS  → probabilité d'exploitation
 │
 ├── KEV   → exploitation connue
 │
 ├── OSV   → informations issues de l'écosystème open source
 │
 ├── NVD   → informations CVE / CVSS / métadonnées
 │
 └── GHSA  → avis de sécurité GitHub
```

Ces informations sont ensuite normalisées et utilisées par Sentinel pour déterminer le niveau de risque associé aux dépendances analysées.


### Une précision importante pour Sentinel

Je ferais aussi une distinction claire dans le README entre **identifiants**, **bases de données** et **indicateurs de risque** :

| Catégorie                     | Éléments      | Rôle dansSentine                                             |
|-------------------------------|---------------|--------------------------------------------------------------|
| **Identifiants**              | CVE, GHSA     | Identifier une vulnérabilité ou un avis                      |
| **Bases de vulnérabilités**   | OSV, NVD      | Fournir des informations sur les vulnérabilités              |
| **Évaluation du risque**      | CVSS, EPSS    | Évaluer respectivement gravité et probabilité d'exploitation |
| **Exploitation réelle**       | KEV           | Signaler une vulnérabilité connue comme exploitée            |
| **Classification**            | CWE           | Classifier le type de faiblesse                              |

Cette distinction est particulièrement intéressante pour Sentinel, car elle explique **pourquoi une vulnérabilité peut avoir plusieurs identifiants et plusieurs sources sans pour autant représenter plusieurs vulnérabilités différentes**.