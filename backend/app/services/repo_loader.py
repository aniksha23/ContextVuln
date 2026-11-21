import os

def validate_repo_path(repo_path: str) -> str:
    """Validates and normalizes the target repository path."""
    abs_path = os.path.abspath(repo_path)
    if not os.path.exists(abs_path):
        # For Day-1 mock testing, allow virtual/sample paths without crashing
        return repo_path
    if not os.path.isdir(abs_path):
        raise ValueError(f"Target path is not a directory: {repo_path}")
    return abs_path