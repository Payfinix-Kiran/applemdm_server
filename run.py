# run.py

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, ssl_context=('certificates/server_certificates/server.crt', 'certificates/server_certificates/server.key'))