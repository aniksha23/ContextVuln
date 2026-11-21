import ast
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx
from pydantic import Field

from app.core.schemas import ReachabilityResult

IGNORED_DIRS = {
    "venv", ".venv", "env", ".env", ".git", "__pycache__",
    "node_modules", ".pytest_cache", "tests", "test", "build", "dist"
}


class ExtendedReachabilityResult(ReachabilityResult):
    """
    Extended Reachability result conforming to ReachabilityResult Pydantic schema,
    enriched with call-chain details, dynamic limitations, and search depth.
    """
    model_config = {"extra": "allow"}
    limitations: List[str] = Field(default_factory=list)
    call_trace: List[Dict[str, Any]] = Field(default_factory=list)
    depth: int = 0


class ASTReachabilityAgent:
    """
    Static AST & Directed Cross-File Call-Graph Engine (Member 2 / Agent 1).
    Constructs a networkx.DiGraph of functions, entry points, and external symbols,
    and performs reachability tracing from application entry points to vulnerable sinks.
    """

    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        self.graph: nx.DiGraph = nx.DiGraph()
        self.entry_points: Set[str] = set()
        self.limitations: List[str] = []
        self.warnings: List[str] = []

        # Internal registries
        self.module_to_file: Dict[str, str] = {}
        self.file_to_module: Dict[str, str] = {}
        self.parsed_asts: Dict[str, ast.AST] = {}
        self.function_defs: Dict[str, Dict[str, Any]] = {}
        self.class_defs: Dict[str, Dict[str, Any]] = {}
        self.import_tables: Dict[str, Dict[str, str]] = {}
        self.route_handlers: Set[str] = set()

    # ------------------------------------------------------------------
    # Step 1: Repository Discovery & AST Parsing
    # ------------------------------------------------------------------

    def _discover_python_files(self) -> List[Tuple[str, str]]:
        """
        Discovers all Python files to analyze.
        Returns list of (relative_file_path, absolute_file_path).
        """
        files_to_parse: List[Tuple[str, str]] = []

        if os.path.isfile(self.repo_path):
            rel_path = os.path.basename(self.repo_path).replace("\\", "/")
            files_to_parse.append((rel_path, self.repo_path))
            return files_to_parse

        if not os.path.isdir(self.repo_path):
            self.warnings.append(f"Target path does not exist: {self.repo_path}")
            return files_to_parse

        for root, dirs, files in os.walk(self.repo_path):
            # Prune non-application directories
            dirs[:] = [
                d for d in dirs
                if d not in IGNORED_DIRS and not any(part in IGNORED_DIRS for part in d.split(os.sep))
            ]

            for file in sorted(files):
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.repo_path).replace("\\", "/")
                    # Skip if any segment in rel_path is an ignored directory
                    path_segments = rel_path.split("/")
                    if any(seg in IGNORED_DIRS for seg in path_segments[:-1]):
                        continue
                    files_to_parse.append((rel_path, full_path))

        return files_to_parse

    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Reads file contents gracefully handling various encodings."""
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                with open(file_path, "r", encoding=enc) as f:
                    return f.read()
            except (UnicodeDecodeError, OSError):
                continue
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError as e:
            self.warnings.append(f"Failed to read file {file_path}: {e}")
            return None

    def _module_name_for_rel_path(self, rel_path: str) -> str:
        """Computes the canonical Python module name for a relative file path."""
        parts = rel_path.split("/")
        if parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]
        if parts[-1] == "__init__":
            parts = parts[:-1]
        mod_name = ".".join(parts)
        return mod_name if mod_name else "__main__"

    # ------------------------------------------------------------------
    # Step 2: Pass 1 - Symbol Table, Imports & Function Definitions
    # ------------------------------------------------------------------

    def _resolve_relative_import(self, current_module: str, import_module: Optional[str], level: int) -> str:
        """Resolves relative imports (e.g. from .service import ...) to canonical dotted module path."""
        parts = current_module.split(".")
        pkg_parts = parts[:-1] if len(parts) > 1 else []
        go_up = level - 1
        if go_up > 0:
            pkg_parts = pkg_parts[:-go_up] if len(pkg_parts) >= go_up else []

        if import_module:
            target_parts = pkg_parts + import_module.split(".")
        else:
            target_parts = pkg_parts
        return ".".join(filter(None, target_parts))

    def _is_route_decorator(self, dec_node: ast.AST) -> bool:
        """Detects web framework route decorators (@app.get, @app.route, @router.post, etc.)."""
        target = dec_node
        if isinstance(dec_node, ast.Call):
            target = dec_node.func
        if isinstance(target, ast.Attribute):
            route_methods = {"route", "get", "post", "put", "delete", "patch", "api_route", "websocket", "options", "head"}
            if target.attr in route_methods:
                return True
        elif isinstance(target, ast.Name):
            if target.id in {"route", "get", "post", "put", "delete", "patch"}:
                return True
        return False

    def _pass1_extract_symbols(self, rel_path: str, mod_name: str, tree: ast.AST) -> None:
        """Extracts imports, classes, functions, and route decorators for a single module."""
        import_table: Dict[str, str] = {}
        star_imports: List[str] = []

        # Extract module-level imports
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_alias = alias.asname or alias.name
                    import_table[local_alias] = alias.name
            elif isinstance(node, ast.ImportFrom):
                level = node.level
                base_mod = node.module or ""
                if level > 0:
                    resolved_mod = self._resolve_relative_import(mod_name, base_mod, level)
                else:
                    resolved_mod = base_mod

                for alias in node.names:
                    if alias.name == "*":
                        star_imports.append(resolved_mod)
                    else:
                        local_alias = alias.asname or alias.name
                        canonical = f"{resolved_mod}.{alias.name}" if resolved_mod else alias.name
                        import_table[local_alias] = canonical

        self.import_tables[mod_name] = import_table

        # Extract function definitions & classes
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_full = f"{mod_name}.{node.name}"
                self.class_defs[class_full] = {
                    "file_path": rel_path,
                    "module": mod_name,
                    "lineno": node.lineno,
                    "name": node.name,
                }
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_full = f"{class_full}.{item.name}"
                        self.function_defs[method_full] = {
                            "file_path": rel_path,
                            "module": mod_name,
                            "lineno": item.lineno,
                            "end_lineno": getattr(item, "end_lineno", item.lineno),
                            "name": item.name,
                            "is_method": True,
                            "class_name": node.name,
                        }
                        self.graph.add_node(
                            method_full,
                            type="function",
                            file_path=rel_path,
                            lineno=item.lineno,
                            name=item.name,
                        )
                        if any(self._is_route_decorator(d) for d in item.decorator_list):
                            self.route_handlers.add(method_full)
                            self.entry_points.add(method_full)

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # If already registered as method, skip
                func_full = f"{mod_name}.{node.name}"
                if func_full not in self.function_defs:
                    self.function_defs[func_full] = {
                        "file_path": rel_path,
                        "module": mod_name,
                        "lineno": node.lineno,
                        "end_lineno": getattr(node, "end_lineno", node.lineno),
                        "name": node.name,
                        "is_method": False,
                    }
                    self.graph.add_node(
                        func_full,
                        type="function",
                        file_path=rel_path,
                        lineno=node.lineno,
                        name=node.name,
                    )
                    if any(self._is_route_decorator(d) for d in node.decorator_list):
                        self.route_handlers.add(func_full)
                        self.entry_points.add(func_full)

    # ------------------------------------------------------------------
    # Step 3: Pass 2 - Call Expression Resolution & Directed Edge Construction
    # ------------------------------------------------------------------

    def _is_main_guard(self, test_node: ast.AST) -> bool:
        """Identifies `if __name__ == '__main__':` constructs."""
        if isinstance(test_node, ast.Compare):
            left = test_node.left
            ops = test_node.ops
            comps = test_node.comparators
            if len(ops) == 1 and isinstance(ops[0], ast.Eq) and len(comps) == 1:
                comp = comps[0]
                if (isinstance(left, ast.Name) and left.id == "__name__" and
                        isinstance(comp, ast.Constant) and comp.value == "__main__"):
                    return True
                if (isinstance(comp, ast.Name) and comp.id == "__name__" and
                        isinstance(left, ast.Constant) and left.value == "__main__"):
                    return True
        return False

    def _record_limitation(self, msg: str) -> None:
        """Records a dynamic analysis limitation, avoiding duplicate entries."""
        if msg not in self.limitations:
            self.limitations.append(msg)

    def _resolve_callee_symbol(
        self,
        func_node: ast.AST,
        mod_name: str,
        file_path: str,
        import_table: Dict[str, str],
        local_var_types: Dict[str, str],
        caller_node: str,
    ) -> Optional[str]:
        """
        Resolves an ast.Call function target into a canonical symbol string.
        Also resolves chained attribute calls and records intermediate edges.
        """
        # Case 1: Simple Name call e.g. load(), func()
        if isinstance(func_node, ast.Name):
            name = func_node.id

            # Dynamic constructs check
            if name in {"getattr", "setattr", "eval", "exec", "__import__"}:
                self._record_limitation(
                    f"Dynamic construct '{name}' detected at {file_path}:{getattr(func_node, 'lineno', 0)}"
                )
                return name

            if name in import_table:
                return import_table[name]

            if name in local_var_types:
                return local_var_types[name]

            # Current module function
            cand = f"{mod_name}.{name}"
            if cand in self.function_defs:
                return cand

            # Intra-project cross-module function matching
            for f_key in self.function_defs:
                if f_key.endswith(f".{name}"):
                    return f_key

            return name

        # Case 2: Attribute call e.g. yaml.load, urllib3.PoolManager().request
        if isinstance(func_node, ast.Attribute):
            attr = func_node.attr
            val = func_node.value

            # Dynamic import check e.g. importlib.import_module
            if isinstance(val, ast.Name) and val.id == "importlib" and attr in {"import_module", "__import__"}:
                self._record_limitation(
                    f"Dynamic import 'importlib.{attr}' detected at {file_path}:{getattr(func_node, 'lineno', 0)}"
                )

            # Attribute on a Call e.g. urllib3.PoolManager().request(...)
            if isinstance(val, ast.Call):
                inner_callee = self._resolve_callee_symbol(
                    val.func, mod_name, file_path, import_table, local_var_types, caller_node
                )
                if inner_callee:
                    # Add edge caller -> inner_callee
                    self._add_edge(caller_node, inner_callee, file_path, getattr(val, "lineno", 0), val)
                    return f"{inner_callee}.{attr}"
                return attr

            # Dotted chain e.g. urllib3.util.retry.Retry
            chain: List[str] = [attr]
            curr = val
            while isinstance(curr, ast.Attribute):
                chain.append(curr.attr)
                curr = curr.value

            if isinstance(curr, ast.Name):
                root_id = curr.id
                if root_id == "self":
                    # Method call on self
                    caller_info = self.function_defs.get(caller_node, {})
                    class_name = caller_info.get("class_name")
                    if class_name:
                        cand_method = f"{mod_name}.{class_name}.{attr}"
                        if cand_method in self.function_defs:
                            return cand_method

                resolved_root = import_table.get(root_id, local_var_types.get(root_id, root_id))
                chain.append(resolved_root)
                full_chain = ".".join(reversed(chain))

                # Check if matches an internal function
                if full_chain in self.function_defs:
                    return full_chain
                for f_key in self.function_defs:
                    if f_key.endswith(f".{full_chain}") or full_chain.endswith(f".{f_key}"):
                        return f_key

                # Check intra-directory module import (e.g. `service.parse_config`)
                parts = full_chain.split(".", 1)
                first_part = parts[0]
                for internal_mod in self.import_tables:
                    if internal_mod == first_part or internal_mod.endswith(f".{first_part}"):
                        internal_full = f"{internal_mod}.{parts[1]}"
                        if internal_full in self.function_defs:
                            return internal_full

                return full_chain

            if isinstance(curr, ast.Call):
                inner_callee = self._resolve_callee_symbol(
                    curr.func, mod_name, file_path, import_table, local_var_types, caller_node
                )
                if inner_callee:
                    self._add_edge(caller_node, inner_callee, file_path, getattr(curr, "lineno", 0), curr)
                    chain.append(inner_callee)
                    return ".".join(reversed(chain))

            return attr

        # Other complex calls
        self._record_limitation(
            f"Unresolved dynamic expression call at {file_path}:{getattr(func_node, 'lineno', 0)}"
        )
        return None

    def _add_edge(
        self,
        caller: str,
        callee: str,
        file_path: str,
        lineno: int,
        call_node: ast.AST,
    ) -> None:
        """Adds a directed edge caller -> callee to the call graph with rich metadata."""
        if not caller or not callee:
            return

        expr_str = ""
        try:
            expr_str = ast.unparse(call_node)
        except Exception:
            expr_str = str(callee)

        # Ensure both nodes exist
        if not self.graph.has_node(caller):
            self.graph.add_node(caller, type="caller", file_path=file_path, lineno=lineno)
        if not self.graph.has_node(callee):
            self.graph.add_node(callee, type="callee")

        self.graph.add_edge(
            caller,
            callee,
            file_path=file_path,
            line_number=lineno,
            call_expression=expr_str,
            is_direct=True,
        )

    def _pass2_traverse_body(
        self,
        nodes: List[ast.AST],
        mod_name: str,
        file_path: str,
        import_table: Dict[str, str],
        caller: str,
        local_vars: Dict[str, str],
    ) -> None:
        """Recursively inspects statements for assignments, dynamic dispatch, and function calls."""
        for node in nodes:
            processed_call_ids: Set[int] = set()

            # Track simple local variable assignments: e.g. pm = urllib3.PoolManager()
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    callee = self._resolve_callee_symbol(
                        node.value.func, mod_name, file_path, import_table, local_vars, caller
                    )
                    if callee:
                        self._add_edge(caller, callee, file_path, node.value.lineno, node.value)
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                local_vars[target.id] = callee
                    processed_call_ids.add(id(node.value))

            # Detect and resolve direct calls, skipping already-processed node.value in assignments
            for sub_node in ast.walk(node):
                if isinstance(sub_node, ast.Call) and id(sub_node) not in processed_call_ids:
                    callee = self._resolve_callee_symbol(
                        sub_node.func, mod_name, file_path, import_table, local_vars, caller
                    )
                    if callee:
                        self._add_edge(caller, callee, file_path, getattr(sub_node, "lineno", 0), sub_node)

    def _pass2_build_edges(self, rel_path: str, mod_name: str, tree: ast.AST) -> None:
        """Traverses the AST of a module to populate call-graph edges and detect entry points."""
        import_table = self.import_tables.get(mod_name, {})
        has_main_block = False

        for stmt in tree.body:
            # 1. if __name__ == '__main__': block
            if isinstance(stmt, ast.If) and self._is_main_guard(stmt.test):
                has_main_block = True
                main_caller = f"{mod_name}:<main>"
                self.entry_points.add(main_caller)
                self.graph.add_node(main_caller, type="entry_point", file_path=rel_path, lineno=stmt.lineno)

                local_vars: Dict[str, str] = {}
                self._pass2_traverse_body(stmt.body, mod_name, rel_path, import_table, main_caller, local_vars)

                # Any function called inside __main__ is also treated as an active entry-point function
                for succ in list(self.graph.successors(main_caller)):
                    if succ in self.function_defs:
                        self.entry_points.add(succ)

            # 2. Function and method definitions
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_full = f"{mod_name}.{stmt.name}"
                local_vars = {}
                # Include local imports defined inside the function
                func_import_table = dict(import_table)
                for item in stmt.body:
                    if isinstance(item, ast.Import):
                        for alias in item.names:
                            func_import_table[alias.asname or alias.name] = alias.name
                    elif isinstance(item, ast.ImportFrom):
                        for alias in item.names:
                            func_import_table[alias.asname or alias.name] = f"{item.module}.{alias.name}" if item.module else alias.name

                self._pass2_traverse_body(stmt.body, mod_name, rel_path, func_import_table, func_full, local_vars)

            # 3. Class definitions
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_full = f"{mod_name}.{stmt.name}.{item.name}"
                        local_vars = {}
                        self._pass2_traverse_body(item.body, mod_name, rel_path, import_table, method_full, local_vars)

            # 4. Top-level executable calls
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                mod_caller = f"{mod_name}:<module>"
                self.entry_points.add(mod_caller)
                self.graph.add_node(mod_caller, type="entry_point", file_path=rel_path, lineno=stmt.lineno)

                local_vars = {}
                callee = self._resolve_callee_symbol(
                    stmt.value.func, mod_name, rel_path, import_table, local_vars, mod_caller
                )
                if callee:
                    self._add_edge(mod_caller, callee, rel_path, stmt.lineno, stmt.value)
                    if callee in self.function_defs:
                        self.entry_points.add(callee)



    # ------------------------------------------------------------------
    # Step 4: Full Graph Construction Lifecycle
    # ------------------------------------------------------------------

    def build_graph(self) -> None:
        """Parses all Python files and builds the full repository call-graph."""
        files = self._discover_python_files()

        # Pass 1: Parse and register definitions
        for rel_path, full_path in files:
            source = self._read_file_safely(full_path)
            if source is None:
                continue

            try:
                tree = ast.parse(source, filename=rel_path)
            except (SyntaxError, ValueError) as err:
                self.warnings.append(f"Syntax/Parse error in {rel_path}: {err}")
                continue

            mod_name = self._module_name_for_rel_path(rel_path)
            self.module_to_file[mod_name] = rel_path
            self.file_to_module[rel_path] = mod_name
            self.parsed_asts[mod_name] = tree

            self._pass1_extract_symbols(rel_path, mod_name, tree)

        # Pass 2: Connect calls & build edges
        for mod_name, tree in self.parsed_asts.items():
            rel_path = self.module_to_file[mod_name]
            self._pass2_build_edges(rel_path, mod_name, tree)

        # Finalize entry points across the analyzed repository
        explicit_eps = {
            ep for ep in self.entry_points
            if ":<main>" in ep or ":<module>" in ep or ep in self.route_handlers
        }
        if explicit_eps:
            self.entry_points = explicit_eps
        else:
            # Fallback for standalone snippets/libraries without __main__ or routes:
            # Select public module-level functions with in_degree == 0
            func_nodes = [
                n for n in self.graph.nodes()
                if n in self.function_defs
                and not self.function_defs[n]["name"].startswith("_")
                and not self.function_defs[n].get("is_method", False)
            ]
            roots = [n for n in func_nodes if self.graph.in_degree(n) == 0]
            self.entry_points = set(roots if roots else func_nodes)

    # ------------------------------------------------------------------
    # Step 5: Reachability Tracing & Exact Confidence Scoring
    # ------------------------------------------------------------------

    def _find_matching_target_nodes(self, target_symbols: List[str]) -> Set[str]:
        """
        Finds all graph nodes that match vulnerable target symbols or their prefixes/variants.
        e.g., matching 'yaml.load', 'urllib3.util.retry.Retry', 'urllib3.PoolManager.request'.
        """
        matching: Set[str] = set()
        all_nodes = set(self.graph.nodes())

        for target in target_symbols:
            target = target.strip()
            if not target:
                continue

            for node in all_nodes:
                # 1. Exact match
                if node == target:
                    matching.add(node)
                    continue
                # 2. Suffix match: e.g. node = "urllib3.util.retry.Retry", target = "Retry"
                if node.endswith("." + target):
                    matching.add(node)
                    continue
                # 3. Target suffix match: e.g. target = "urllib3.util.retry.Retry", node = "Retry"
                if target.endswith("." + node):
                    matching.add(node)
                    continue
                # 4. Prefix match: e.g. node = "urllib3.PoolManager.request", target = "urllib3.PoolManager"
                if node.startswith(target + "."):
                    matching.add(node)
                    continue

        return matching

    def check_reachability(self, target_symbols: List[str]) -> ExtendedReachabilityResult:
        """
        Evaluates reachability from detected entry points to vulnerable target symbols.
        Returns:
            - is_reachable = True, confidence = 1.0 (Direct call, 1 hop)
            - is_reachable = True, confidence = 0.7 (Transitive call, >1 hops)
            - is_reachable = False, confidence = 0.0 (Unreachable)
        """
        if not target_symbols:
            return ExtendedReachabilityResult(
                is_reachable=False,
                confidence=0.0,
                call_path=[],
                limitations=self.limitations,
                call_trace=[],
                depth=0,
            )

        # Build graph on-demand if not already populated
        if self.graph.number_of_nodes() == 0:
            self.build_graph()

        matching_nodes = self._find_matching_target_nodes(target_symbols)
        if not matching_nodes:
            return ExtendedReachabilityResult(
                is_reachable=False,
                confidence=0.0,
                call_path=[],
                limitations=self.limitations,
                call_trace=[],
                depth=0,
            )

        shortest_path: Optional[List[str]] = None
        min_hops = float("inf")

        for ep in self.entry_points:
            if ep not in self.graph:
                continue
            for target_node in matching_nodes:
                if target_node not in self.graph:
                    continue
                if nx.has_path(self.graph, ep, target_node):
                    try:
                        path = nx.shortest_path(self.graph, ep, target_node)
                        hops = len(path) - 1
                        if hops < min_hops:
                            min_hops = hops
                            shortest_path = path
                    except nx.NetworkXNoPath:
                        continue

        if shortest_path is None or min_hops == float("inf"):
            return ExtendedReachabilityResult(
                is_reachable=False,
                confidence=0.0,
                call_path=[],
                limitations=self.limitations,
                call_trace=[],
                depth=0,
            )

        # Direct reachable (1 hop): confidence 1.0
        # Transitive reachable (>1 hops): confidence 0.7
        is_direct = (min_hops == 1)
        confidence = 1.0 if is_direct else 0.7

        # Assemble formatted call path and trace
        call_path: List[str] = []
        call_trace: List[Dict[str, Any]] = []

        for i in range(len(shortest_path) - 1):
            u = shortest_path[i]
            v = shortest_path[i + 1]
            edge_data = self.graph.get_edge_data(u, v) or {}

            file_path = edge_data.get("file_path", "")
            lineno = edge_data.get("line_number", 0)
            expr = edge_data.get("call_expression", "")

            call_trace.append({
                "file_path": file_path,
                "line_number": lineno,
                "caller": u,
                "callee": v,
                "call_expression": expr,
            })

            # Format application node: {file}:{lineno}:{func}()
            if ":<main>" in u:
                call_path.append(f"{file_path}:{lineno}:<main>()")
            elif ":<module>" in u:
                call_path.append(f"{file_path}:{lineno}:<module>()")
            else:
                func_info = self.function_defs.get(u, {})
                display_name = func_info.get("name", u.split(".")[-1])
                call_path.append(f"{file_path}:{lineno}:{display_name}()")

        # Append final callee target node
        final_target = shortest_path[-1]
        call_path.append(f"{final_target}()")

        return ExtendedReachabilityResult(
            is_reachable=True,
            confidence=confidence,
            call_path=call_path,
            limitations=self.limitations,
            call_trace=call_trace,
            depth=int(min_hops),
        )


# ----------------------------------------------------------------------
# Top-Level Helper Functions (Orchestrator & Integration Interface)
# ----------------------------------------------------------------------

def build_call_graph(repo_path: str) -> ASTReachabilityAgent:
    """
    Instantiates an ASTReachabilityAgent and builds the directed call graph.
    """
    agent = ASTReachabilityAgent(repo_path)
    agent.build_graph()
    return agent


def check_reachability(repo_path: str, target_symbols: List[str]) -> ExtendedReachabilityResult:
    """
    Top-level helper function to evaluate reachability in a repository for target symbols.
    """
    agent = ASTReachabilityAgent(repo_path)
    agent.build_graph()
    return agent.check_reachability(target_symbols)


def analyze_reachability(repo_path: str, target_symbols: List[str]) -> ExtendedReachabilityResult:
    """
    Alias helper function to evaluate reachability in a repository for target symbols.
    """
    return check_reachability(repo_path, target_symbols)
