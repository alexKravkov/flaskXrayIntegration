import json
import os

from flask import Flask, render_template, abort, request, jsonify

from exceptions.xray_integration_exceptions import XrayIntegrationError
from model import vulns

app = Flask(__name__)
cnt = 0


@app.route("/")
def welcome():
    return render_template("welcome.html", vulns=vulns)


@app.route("/vulnerabilities/<int:index>")
def vulnerabilities_view(index):
    try:
        vuln = vulns[index]
        return render_template("vulnerabilities.html",
                               comp_id=vuln['component_id'],
                               vuln=json.dumps(vuln,
                                               sort_keys=True,
                                               indent=4,
                                               separators=(',',':')),
                               index=index,
                               max_index=len(vulns)-1)
    except IndexError:
        abort(404)


@app.route("/api/checkauth")
def checkauth():
    try:
        header_api_key = request.headers.get('your-header-name')
        if header_api_key == os.getenv('INTEGRATION_KEY'):
            resp = jsonify(success=True)
            return resp
    except XrayIntegrationError:
        abort(500)


@app.route("/api/componentInfo/<component_id>", methods=['GET', 'POST'])
def componentInfo(component_id):
    try:
        body = request.get_json()
        for vuln in vulns:
            if component_id == vuln['component_id']:
                return vuln
            else:
                abort(404)
    except XrayIntegrationError:
        abort(500)



if __name__ == '__main__':
    app.run(debug=True)
