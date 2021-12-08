"""
    Simulates db and loads the vulnerabilities from a json file located in data folder.

    Needs to be replaced with real database.
"""
import json


def load_vulnerabilities():
    with open("./data/vulnerabilities.json") as f:
        return json.load(f)


vulns = load_vulnerabilities()
