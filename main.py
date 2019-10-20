from app import start

# Configure the client
config = {
    "issuer": "https://workshopX.curity.io/oauth/v2/oauth-anonymous",  # Configure to match your install
    "client_id": "",  # Configured in curity install
    "client_secret": "",  # Configured in curity install
    "redirect_uri": "",  # https://<projectname>.<username>.repl.co/callback
    "scope": "",
}

start(config)

