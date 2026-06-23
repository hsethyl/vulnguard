from jinja2 import Environment

SECRET_KEY = "django-insecure-9d8f7a6b5c4e3d2f1a0b9c8d7e6f5a4b3c2d1e0f"
DEBUG = True
ALLOWED_HOSTS = ["*"]

env = Environment(autoescape=False)

BIND = "0.0.0.0"
