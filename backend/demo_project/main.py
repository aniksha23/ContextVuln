from app.config_loader import load_settings
from app.http_client import fetch


def run():
    cfg = load_settings("settings.yml")
    return fetch(cfg["url"])


if __name__ == "__main__":
    run()
