from waitress import serve
from backend.app import app
serve(app, host='0.0.0.0', port=5000)