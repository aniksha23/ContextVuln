from typing import List
from app.core.schemas import ReachabilityResult

class ASTReachabilityAgent:
    """
    STUB IMPLEMENTATION (Owned by Member 2).
    Member 2 will replace this with full Python AST / Tree-sitter call-graph traversal.
    """
    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def build_graph(self) -> None:
        pass

    def check_reachability(self, target_symbols: List[str]) -> ReachabilityResult:
        # Simulate reachable path for yaml.load so frontend & scoring work on Day 1
        if any("yaml.load" in sym for sym in target_symbols):
            return ReachabilityResult(
                is_reachable=True,
                confidence=1.0,
                call_path=["app/routes.py:upload_config()", "app/parser.py:parse_yaml()", "yaml.load()"],
            )
        return ReachabilityResult(
            is_reachable=False,
            confidence=0.0,
            call_path=[],
        )