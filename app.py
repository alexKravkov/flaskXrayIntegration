import os

from flask import Flask, request, abort
from flask_restful import reqparse, Api, Resource
from model import get_vuln_by_comp

app = Flask(__name__)
api = Api(app)

parser = reqparse.RequestParser()
parser.add_argument('components', required=True)
parser.add_argument('context', required=True)
cnt = 0

health_check = {
    "valid": True,
    "error": ""
}


def check_api_key():
    """Check the Api key that was provided via headers."""
    response = health_check
    if 'apiKey' in request.headers:
        header = request.headers['apiKey']
        if header == os.getenv('API_KEY'):
            return response
        else:
            response['valid'] = False
            response['error'] = 'User api key is invalid'
            abort(401, response)
    else:
        abort(400, "Failed to read header.")


class Checkauth(Resource):
    """Validate authentication with api key."""
    def get(self):
        if check_api_key():
            return "Ok."


class ComponentInfo(Resource):
    """Receive a component info from server by component_id."""
    def post(self):
        components = {"components": []}
        if check_api_key():
            body = request.get_json()
            comps = [comp['component_id'] for comp in body['components']]
            for comp in comps:
                res = get_vuln_by_comp(comp)
                if res is not None:
                    components['components'].append(res)
        return components


api.add_resource(Checkauth, '/api/checkauth')
api.add_resource(ComponentInfo, '/api/componentInfo')

if __name__ == '__main__':
    app.run(debug=True)
