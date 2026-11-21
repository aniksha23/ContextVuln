"""
Benchmark Sample: Dynamic Constructs
Uses getattr, eval, and importlib.import_module for dynamic execution.
Expected: Limitations flagged by static analysis engine.
"""
import importlib


def dynamic_execution_helper(target_obj, attr_name: str, code: str):
    # Dynamic dispatch via getattr
    func = getattr(target_obj, attr_name)
    # Dynamic evaluation via eval
    eval(code)
    # Dynamic module import
    mod = importlib.import_module("os")
    return func()
