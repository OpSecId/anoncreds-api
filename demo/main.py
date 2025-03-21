from app import create_app
from app.plugins.anoncreds import AnonCredsApi
from asyncio import run as _await

app = create_app()

if __name__ == "__main__":
    _await(AnonCredsApi().provision())
    app.run(host="0.0.0.0", port="5000", debug=True)
