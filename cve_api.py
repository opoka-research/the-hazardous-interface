#!/usr/bin/env python3
"""
Cybernomics API Server

Serves database vulnerability surface analysis data via REST API.
All classification logic is transparent and auditable via /v1/methodology.

Run: python3 cybernomics_api.py
Docs: http://localhost:8080/v1/docs
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional
from aiohttp import web
import aiohttp_cors

DATA_DIR = Path("./cve_data")
REPORT_DIR = Path("./reports")

# =============================================================================
# CLASSIFICATION TAXONOMY
# =============================================================================

IMPLEMENTATION_DEFECT_CWES = {
    119, 120, 121, 122,  # Buffer overflows
    125, 787,            # Out-of-bounds read/write
    416,                 # Use after free
    476,                 # NULL pointer dereference
    415,                 # Double free
    401,                 # Memory leak
    843,                 # Type confusion
    704,                 # Incorrect type conversion
    190, 191,            # Integer overflow/underflow
    362,                 # Race condition
    367,                 # TOCTOU
    617,                 # Reachable assertion
    369,                 # Divide by zero
    754,                 # Improper check for unusual conditions
}

INTERFACE_HAZARD_CWES = {
    89,                  # SQL Injection
    20,                  # Improper Input Validation
    74, 77, 78,          # Injection variants
    22,                  # Path Traversal
    287,                 # Improper Authentication
    306,                 # Missing Authentication
    288, 290,            # Authentication Bypass
    295,                 # Certificate Validation
    862,                 # Missing Authorization
    863,                 # Incorrect Authorization
    284, 285,            # Access Control
    732, 276,            # Permission Assignment
    269,                 # Improper Privilege Management
}

LOCATION_KEYWORDS = {
    "ORM": {
        "high": [
            "hibernate", "sqlalchemy", "activerecord", "active record",
            "sequelize", "prisma", "typeorm", "doctrine", "eloquent",
            "peewee", "django orm", "entity framework", "entityframework",
            "knex", "bookshelf", "objection", "mikro-orm", "mikroorm",
            "tortoise-orm", "sqlmodel", "pony orm", "storm orm",
            "object-relational mapper", "object relational mapper",
        ],
        "medium": ["orm", "query builder", "querybuilder", "model layer"],
    },
    "DRIVER": {
        "high": [
            "jdbc", "odbc", "libmysqlclient", "libpq", "mysqlclient",
            "psycopg", "psycopg2", "psycopg3", "pymysql", "mysql2",
            "node-postgres", "pg node", "go-sql-driver", "database/sql",
            "pdo_mysql", "pdo_pgsql", "pdo mysql", "pdo pgsql",
            "ado.net", "npgsql", "mysql connector", "mysql-connector",
            "postgres connector", "mongodb driver", "pymongo",
            "motor asyncio", "asyncpg",
        ],
        "medium": ["connector", "driver", "client library", "database client", "db client"],
    },
    "CLIENT": {
        "high": [
            "phpmyadmin", "pgadmin", "adminer", "heidisql", "heidi sql",
            "navicat", "dbeaver", "datagrip", "sequel pro", "sequelpro",
            "tableplus", "sqlyog", "toad", "mysql workbench", "workbench",
            "azure data studio", "dbvisualizer", "razorsql", "dbforge",
        ],
        "medium": ["admin panel", "admin interface", "web interface", "management interface"],
        "low": ["psql", "mysql client", "mongo shell", "mongosh"],
    },
    "EXTENSION": {
        "high": ["postgis", "timescaledb", "citus", "pg_stat", "pg_trgm", "pgcrypto"],
        "medium": ["extension", "plugin", "module", "addon", "contrib", "stored procedure", "udf"],
    },
    "ECOSYSTEM": {
        "high": [
            "wordpress", "drupal", "joomla", "magento", "prestashop",
            "woocommerce", "shopify", "opencart", "mediawiki", "moodle",
        ],
        "medium": ["laravel", "django", "rails", "spring", "express", "flask", "fastapi", "cms", "framework"],
        "low": ["application", "website", "portal", "platform"],
    },
    "CORE": {
        "high": ["mysqld", "postgres backend", "postmaster", "mongod", "mariadbd", "innodb", "myisam", "wiredtiger"],
        "medium": ["database server", "db server", "query optimizer", "query planner", "replication", "binlog", "wal"],
        "low": ["server", "daemon", "engine", "backend"],
    },
}

CONFIDENCE_SCORES = {"high": 0.9, "medium": 0.6, "low": 0.3}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class CVEClassification:
    cve_id: str
    product: str
    cwes: list[int]
    description: str
    category: str = "UNKNOWN"
    location: str = "UNKNOWN"
    location_confidence: float = 0.0
    is_downstream: bool = False
    has_cwe20: bool = False
    likely_misclassified_sqli: bool = False


# =============================================================================
# CLASSIFICATION LOGIC
# =============================================================================

def find_keyword_match(text: str, keyword: str) -> bool:
    escaped = re.escape(keyword)
    pattern = r'(?:^|[\s\-_.,;:!?()\[\]{}"/])' + escaped + r'(?:[\s\-_.,;:!?()\[\]{}"/]|$)'
    return bool(re.search(pattern, text, re.IGNORECASE))


def detect_location(description: str) -> tuple[str, float]:
    desc_lower = description.lower()
    matches = []
    
    for location, levels in LOCATION_KEYWORDS.items():
        for level, keywords in levels.items():
            confidence = CONFIDENCE_SCORES[level]
            for kw in keywords:
                if find_keyword_match(desc_lower, kw):
                    matches.append((location, confidence, kw))
    
    if not matches:
        return "UNKNOWN", 0.0
    
    specificity = ["ORM", "DRIVER", "CLIENT", "EXTENSION", "ECOSYSTEM", "CORE"]
    matches.sort(key=lambda m: (-m[1], specificity.index(m[0]) if m[0] in specificity else 99))
    return matches[0][0], matches[0][1]


def analyze_cwe20(cwes: list[int], description: str) -> tuple[bool, bool]:
    has_cwe20 = 20 in cwes
    if not has_cwe20:
        return False, False
    
    sqli_indicators = [
        "sql injection", "sqli", "sql query", "sql statement",
        "database query", "inject.*sql", "sql.*inject",
    ]
    desc_lower = description.lower()
    for indicator in sqli_indicators:
        if re.search(indicator, desc_lower):
            return True, True
    return True, False


def classify_cve(cve_id: str, cwes: list[int], description: str, product: str) -> CVEClassification:
    location, confidence = detect_location(description)
    has_cwe20, likely_misclassified = analyze_cwe20(cwes, description)
    
    has_impl_defect = bool(set(cwes) & IMPLEMENTATION_DEFECT_CWES)
    has_interface_hazard = bool(set(cwes) & INTERFACE_HAZARD_CWES)
    
    if has_interface_hazard:
        category = "INTERFACE_HAZARD"
        is_downstream = location in ["DRIVER", "ORM", "CLIENT", "EXTENSION", "ECOSYSTEM"]
    elif has_impl_defect:
        category = "IMPLEMENTATION_DEFECT"
        is_downstream = False
    else:
        category = "UNKNOWN"
        is_downstream = False
    
    return CVEClassification(
        cve_id=cve_id,
        product=product,
        cwes=cwes,
        description=description[:500],
        category=category,
        location=location,
        location_confidence=confidence,
        is_downstream=is_downstream,
        has_cwe20=has_cwe20,
        likely_misclassified_sqli=likely_misclassified,
    )


# =============================================================================
# DATA LOADING
# =============================================================================

def extract_cwes(cve: dict) -> list[int]:
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if match := re.match(r"CWE-(\d+)", val):
                cwes.append(int(match.group(1)))
    return cwes


def extract_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def load_all_cves() -> list[CVEClassification]:
    classifications = []
    
    for product_file in sorted(DATA_DIR.glob("*_cves.json")):
        product = product_file.stem.replace("_cves", "")
        
        with open(product_file) as f:
            data = json.load(f)
        
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            cwes = extract_cwes(cve)
            description = extract_description(cve)
            
            if not cwes:
                continue
            
            classification = classify_cve(cve_id, cwes, description, product)
            classifications.append(classification)
    
    return classifications


# =============================================================================
# STATISTICS COMPUTATION
# =============================================================================

class Stats:
    def __init__(self, classifications: list[CVEClassification]):
        self.all = classifications
        self._compute()
    
    def _compute(self):
        self.total = len(self.all)
        
        self.by_category = defaultdict(list)
        for c in self.all:
            self.by_category[c.category].append(c)
        
        self.by_product = defaultdict(lambda: defaultdict(list))
        for c in self.all:
            self.by_product[c.product][c.category].append(c)
        
        self.by_location = defaultdict(list)
        for c in self.all:
            self.by_location[c.location].append(c)
        
        self.interface_hazards = self.by_category["INTERFACE_HAZARD"]
        self.impl_defects = self.by_category["IMPLEMENTATION_DEFECT"]
        
        self.sqli_cves = [c for c in self.all if 89 in c.cwes]
        self.orm_cves = [c for c in self.all if c.location == "ORM"]
        self.cwe20_misclassified = [c for c in self.all if c.likely_misclassified_sqli]
    
    def summary(self) -> dict:
        ih = len(self.interface_hazards)
        id_ = len(self.impl_defects)
        unk = len(self.by_category["UNKNOWN"])
        
        ih_known = [c for c in self.interface_hazards if c.location != "UNKNOWN"]
        ih_downstream = [c for c in self.interface_hazards if c.is_downstream]
        
        sqli_known = [c for c in self.sqli_cves if c.location != "UNKNOWN"]
        sqli_downstream = [c for c in self.sqli_cves if c.is_downstream]
        sqli_core = len([c for c in self.sqli_cves if c.location == "CORE"])
        sqli_unknown = len([c for c in self.sqli_cves if c.location == "UNKNOWN"])
        
        orm_hazards = len([c for c in self.orm_cves if c.category == "INTERFACE_HAZARD"])
        
        return {
            "total_classified": self.total,
            "implementation_defects": {
                "count": id_,
                "percentage": round(id_ / self.total * 100, 1),
            },
            "interface_hazards": {
                "count": ih,
                "percentage": round(ih / self.total * 100, 1),
                "downstream_count": len(ih_downstream),
                "downstream_percentage_of_known": round(len(ih_downstream) / len(ih_known) * 100, 1) if ih_known else 0,
                "known_location_count": len(ih_known),
                "unknown_location_count": ih - len(ih_known),
            },
            "unknown_category": {
                "count": unk,
                "percentage": round(unk / self.total * 100, 1),
            },
            "hazard_to_defect_ratio": round(ih / id_, 2) if id_ > 0 else None,
            "sqli": {
                "total": len(self.sqli_cves),
                "percentage_of_all": round(len(self.sqli_cves) / self.total * 100, 1),
                "core_count": sqli_core,
                "core_percentage": round(sqli_core / len(self.sqli_cves) * 100, 1) if self.sqli_cves else 0,
                "downstream_count": len(sqli_downstream),
                "downstream_percentage_of_known": round(len(sqli_downstream) / len(sqli_known) * 100, 1) if sqli_known else 0,
                "known_location_count": len(sqli_known),
                "unknown_location_count": sqli_unknown,
                "unknown_location_percentage": round(sqli_unknown / len(self.sqli_cves) * 100, 1) if self.sqli_cves else 0,
            },
            "orm": {
                "total": len(self.orm_cves),
                "interface_hazards": orm_hazards,
                "hazard_rate": round(orm_hazards / len(self.orm_cves) * 100, 1) if self.orm_cves else 0,
            },
            "cwe20_likely_sqli": len(self.cwe20_misclassified),
        }
    
    def by_category_stats(self) -> dict:
        return {
            cat: {
                "count": len(cves),
                "percentage": round(len(cves) / self.total * 100, 1),
            }
            for cat, cves in self.by_category.items()
        }
    
    def by_location_stats(self) -> dict:
        ih = self.interface_hazards
        ih_known = [c for c in ih if c.location != "UNKNOWN"]
        return {
            loc: {
                "total": len(cves),
                "interface_hazards": len([c for c in cves if c.category == "INTERFACE_HAZARD"]),
                "percentage_of_all_hazards": round(len([c for c in cves if c.category == "INTERFACE_HAZARD"]) / len(ih) * 100, 1) if ih else 0,
                "percentage_of_known_hazards": round(len([c for c in cves if c.category == "INTERFACE_HAZARD"]) / len(ih_known) * 100, 1) if ih_known and loc != "UNKNOWN" else None,
                "is_downstream": loc in ["DRIVER", "ORM", "CLIENT", "EXTENSION", "ECOSYSTEM"],
            }
            for loc, cves in self.by_location.items()
        }
    
    def by_product_stats(self) -> dict:
        result = {}
        for prod, cats in self.by_product.items():
            total = sum(len(v) for v in cats.values())
            ih = cats["INTERFACE_HAZARD"]
            id_ = cats["IMPLEMENTATION_DEFECT"]
            downstream = [c for c in ih if c.is_downstream]
            result[prod] = {
                "total": total,
                "implementation_defects": {
                    "count": len(id_),
                    "percentage": round(len(id_) / total * 100, 1) if total else 0,
                },
                "interface_hazards": {
                    "count": len(ih),
                    "percentage": round(len(ih) / total * 100, 1) if total else 0,
                    "downstream_count": len(downstream),
                    "downstream_percentage": round(len(downstream) / len(ih) * 100, 1) if ih else 0,
                },
            }
        return result
    
    def sqli_stats(self) -> dict:
        by_loc = defaultdict(int)
        for c in self.sqli_cves:
            by_loc[c.location] += 1
        
        total = len(self.sqli_cves)
        known = {k: v for k, v in by_loc.items() if k != "UNKNOWN"}
        known_total = sum(known.values())
        downstream_locs = ["DRIVER", "ORM", "CLIENT", "EXTENSION", "ECOSYSTEM"]
        downstream_total = sum(v for k, v in known.items() if k in downstream_locs)
        
        by_location_detailed = {}
        for loc, count in by_loc.items():
            by_location_detailed[loc] = {
                "count": count,
                "percentage_of_all": round(count / total * 100, 1) if total else 0,
                "percentage_of_known": round(count / known_total * 100, 1) if known_total and loc != "UNKNOWN" else None,
                "is_downstream": loc in downstream_locs,
            }
        
        return {
            "total": total,
            "percentage_of_all_cves": round(total / self.total * 100, 1),
            "by_location": by_location_detailed,
            "known_location_total": known_total,
            "unknown_location_total": by_loc.get("UNKNOWN", 0),
            "unknown_location_percentage": round(by_loc.get("UNKNOWN", 0) / total * 100, 1) if total else 0,
            "downstream_total": downstream_total,
            "downstream_percentage_of_known": round(downstream_total / known_total * 100, 1) if known_total else 0,
            "core_total": by_loc.get("CORE", 0),
            "core_percentage_of_known": round(by_loc.get("CORE", 0) / known_total * 100, 1) if known_total else 0,
        }


# =============================================================================
# API HANDLERS
# =============================================================================

async def handle_summary(request: web.Request) -> web.Response:
    stats: Stats = request.app["stats"]
    return web.json_response(stats.summary())


async def handle_cves(request: web.Request) -> web.Response:
    stats: Stats = request.app["stats"]
    
    # Query params
    category = request.query.get("category")
    location = request.query.get("location")
    product = request.query.get("product")
    cwe = request.query.get("cwe")
    downstream = request.query.get("downstream")
    limit = min(int(request.query.get("limit", 100)), 1000)
    offset = int(request.query.get("offset", 0))
    
    results = stats.all
    
    if category:
        results = [c for c in results if c.category == category.upper()]
    if location:
        results = [c for c in results if c.location == location.upper()]
    if product:
        results = [c for c in results if c.product == product.lower()]
    if cwe:
        cwe_int = int(cwe)
        results = [c for c in results if cwe_int in c.cwes]
    if downstream:
        is_downstream = downstream.lower() == "true"
        results = [c for c in results if c.is_downstream == is_downstream]
    
    total = len(results)
    results = results[offset:offset + limit]
    
    return web.json_response({
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": [asdict(c) for c in results],
    })


async def handle_cve_detail(request: web.Request) -> web.Response:
    stats: Stats = request.app["stats"]
    cve_id = request.match_info["cve_id"].upper()
    
    for c in stats.all:
        if c.cve_id == cve_id:
            return web.json_response(asdict(c))
    
    return web.json_response({"error": "CVE not found"}, status=404)


async def handle_stats_category(request: web.Request) -> web.Response:
    stats: Stats = request.app["stats"]
    return web.json_response(stats.by_category_stats())


async def handle_stats_location(request: web.Request) -> web.Response:
    stats: Stats = request.app["stats"]
    return web.json_response(stats.by_location_stats())


async def handle_stats_product(request: web.Request) -> web.Response:
    stats: Stats = request.app["stats"]
    return web.json_response(stats.by_product_stats())


async def handle_stats_sqli(request: web.Request) -> web.Response:
    stats: Stats = request.app["stats"]
    return web.json_response(stats.sqli_stats())


async def handle_methodology(request: web.Request) -> web.Response:
    return web.json_response({
        "version": "2.0",
        "description": "Classification methodology for database CVE analysis",
        "categories": {
            "IMPLEMENTATION_DEFECT": {
                "description": "Bugs in vendor code - memory safety, concurrency, logic errors",
                "cwes": sorted(IMPLEMENTATION_DEFECT_CWES),
            },
            "INTERFACE_HAZARD": {
                "description": "Risks transferred to users by design - SQLi, auth complexity",
                "cwes": sorted(INTERFACE_HAZARD_CWES),
            },
        },
        "locations": {
            "CORE": "Database engine itself",
            "DRIVER": "Client libraries (JDBC, ODBC, libpq, etc.)",
            "ORM": "Object-relational mappers (Hibernate, SQLAlchemy, etc.)",
            "CLIENT": "Admin tools (phpMyAdmin, pgAdmin, etc.)",
            "EXTENSION": "Database extensions and plugins",
            "ECOSYSTEM": "Applications built on databases (WordPress, etc.)",
            "UNKNOWN": "Insufficient description data to classify",
        },
        "location_keywords": LOCATION_KEYWORDS,
        "confidence_scores": CONFIDENCE_SCORES,
        "downstream_locations": ["DRIVER", "ORM", "CLIENT", "EXTENSION", "ECOSYSTEM"],
        "notes": [
            "Interface Hazards in downstream locations exist BECAUSE the string-based protocol forces ecosystem tools to handle dangerous strings",
            "ORMs are mitigation layers that still inherit the hazard - they generate SQL strings underneath",
            "CWE-20 (Input Validation) often masks SQLi - we flag likely misclassifications",
            "UNKNOWN location means the CVE description lacked sufficient keywords to classify",
        ],
    })


async def handle_docs(request: web.Request) -> web.Response:
    docs = """
# Cybernomics API v1

Database vulnerability surface analysis - verifiable data for security research.

## Endpoints

### Summary
- `GET /v1/summary` - Headline statistics

### CVE Data
- `GET /v1/cves` - List CVEs (filterable)
  - `?category=INTERFACE_HAZARD|IMPLEMENTATION_DEFECT|UNKNOWN`
  - `?location=CORE|DRIVER|ORM|CLIENT|EXTENSION|ECOSYSTEM|UNKNOWN`
  - `?product=mysql|postgresql|mongodb|mariadb|sqlite`
  - `?cwe=89` (filter by CWE number)
  - `?downstream=true|false`
  - `?limit=100&offset=0`
- `GET /v1/cves/{cve_id}` - Single CVE detail

### Statistics
- `GET /v1/stats/by-category` - Implementation Defects vs Interface Hazards
- `GET /v1/stats/by-location` - CORE/DRIVER/ORM/CLIENT/etc breakdown
- `GET /v1/stats/by-product` - Per-database analysis
- `GET /v1/stats/sqli` - SQL injection (CWE-89) specific analysis

### Methodology
- `GET /v1/methodology` - Classification rules, CWE lists, keywords

## Key Findings

The data shows:
- 3.1x more Interface Hazards than Implementation Defects
- 79.1% of SQLi (known location) occurs OUTSIDE the database engine
- ORMs have 88.5% Interface Hazard rate despite being mitigation layers

## Source

Data: NIST NVD (PostgreSQL, MySQL, MariaDB, MongoDB, SQLite)
Research: Opoka Security Research, January 2026
"""
    return web.Response(text=docs, content_type="text/markdown")


# =============================================================================
# APP SETUP
# =============================================================================

def create_app() -> web.Application:
    app = web.Application()
    
    # Load data on startup
    print("Loading CVE data...")
    classifications = load_all_cves()
    print(f"Classified {len(classifications)} CVEs")
    
    app["classifications"] = classifications
    app["stats"] = Stats(classifications)
    
    # Routes
    app.router.add_get("/v1/docs", handle_docs)
    app.router.add_get("/v1/summary", handle_summary)
    app.router.add_get("/v1/cves", handle_cves)
    app.router.add_get("/v1/cves/{cve_id}", handle_cve_detail)
    app.router.add_get("/v1/stats/by-category", handle_stats_category)
    app.router.add_get("/v1/stats/by-location", handle_stats_location)
    app.router.add_get("/v1/stats/by-product", handle_stats_product)
    app.router.add_get("/v1/stats/sqli", handle_stats_sqli)
    app.router.add_get("/v1/methodology", handle_methodology)
    
    # CORS setup - allow all origins for development
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        )
    })
    
    # Apply CORS to all routes
    for route in list(app.router.routes()):
        cors.add(route)
    
    return app


if __name__ == "__main__":
    app = create_app()
    print("Starting Cybernomics API on http://localhost:8080")
    print("Docs: http://localhost:8080/v1/docs")
    web.run_app(app, host="0.0.0.0", port=8080)
