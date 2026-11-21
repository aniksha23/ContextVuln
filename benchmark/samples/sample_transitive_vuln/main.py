"""
Main application module for transitive vulnerability sample.
Entry point calls a helper in service.py which invokes yaml.load.
Expected: is_reachable = True, confidence = 0.7
"""
from .service import parse_untrusted_data


def handle_request():
    user_data = "role: guest"
    return parse_untrusted_data(user_data)


if __name__ == "__main__":
    handle_request()
