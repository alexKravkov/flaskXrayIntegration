"""
    Simulates db and loads the vulnerabilities from a json file located in data folder.

    Needs to be replaced with real database.
"""
import dataclasses
import json
import os
from dataclasses import dataclass

from exceptions.xray_integration_exceptions import XrayIntegrationError


@dataclass
class Vulnerability:
    cve: str
    version: str
    type: str
    source_id: str
    summary: str
    description: str
    cvss_v2: str
    cvss_v3: str
    severity: str
    url: str
    publish_date: str
    references: list


@dataclass
class ComponentData:
    component_id: str
    vulnerabilities: list[Vulnerability]


def load_vulnerabilities():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    file_path = os.path.join(dir_path, 'data', 'vulnerabilities.json')
    # data = json.loads(os.path.join(cwd, 'data', 'vulnerabilities.json'))
    with open(file_path) as f:
        return json.load(f)


def get_vuln_by_comp(comp_id: str) -> ComponentData:
    data = load_vulnerabilities()
    vulns = [ComponentData(**item) for item in data]
    for vuln in vulns:
        if vuln.component_id == comp_id:
            res = json.dumps(dataclasses.asdict(vuln))
            return res
    return None


def get_all_vulnerabilities() -> list[ComponentData]:
    try:
        data = load_vulnerabilities()
        vulns = [ComponentData(**item) for item in data]
        return vulns
    except XrayIntegrationError:
        print("Failed to parse vulnerabilities from source.")
