import os

DB_PATH = "users.db"

# FIX 4: the secret is no longer in the code. It is read from the environment,
# where the deployment system (or a secrets manager) provides it.
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
