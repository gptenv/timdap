#!/usr/bin/env python3
"""
Tim's Debug Environment Analyzer
authored by GPT-4o, Tim (a custom GPT-4.1-based GPT), and Sonnet 4 (Claude)

Usage as importable module:
    import timdap
    result = timdap.run_analysis()

Usages as executable:
    python3 timdap/ -h
    python3 -m timdap -h
    python3 timdap.py -h
    ./timdap.py -h
"""

import sys
import os
import subprocess
import threading
import socket
import time
import json

# Module-level constants and configuration
DEFAULT_DAP_PORT = 5567
DEFAULT_DAP_HOST = "127.0.0.1"
DEFAULT_OUTPUT_PATH = "timdap.analysis.output.json"

# The test script content - making this a module constant so it can be customized when imported
DEFAULT_BUGGY_CODE = """
def divide(a, b):
    return a / b

def main():
    x = 10
    y = 0  # BUG: Division by zero!
    print("About to divide...")
    result = divide(x, y)
    print("Result:", result)

if __name__ == '__main__':
    main()
"""


def safe_stderr_log(message):
    """
    Safely log warnings to stderr with error handling.
    This function is designed to work even in heavily restricted environments.
    """
    try:
        print(f"DEBUG_ANALYZER: {message}", file=sys.stderr)
    except:
        pass  # Even stderr might be compromised in some environments


def bytes_to_str(obj):
    """
    Recursively convert bytes objects to strings for JSON serialization.
    This handles the complex nested structures returned by the debug adapter protocol.
    """
    if isinstance(obj, dict):
        return {k: bytes_to_str(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bytes_to_str(i) for i in obj]
    elif isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except Exception:
            return obj.hex()  # fallback for non-utf-8 bytes
    else:
        return obj


class DebugAdapterController:
    """
    Manages the debug adapter process and provides a clean interface for DAP communication.
    This class encapsulates all the low-level socket and process management.
    """
    
    def __init__(self, host=DEFAULT_DAP_HOST, port=DEFAULT_DAP_PORT):
        self.host = host
        self.port = port
        self.adapter_cmd = ["debugpy-adapter", "--host", host, "--port", str(port)]
        self.adapter_proc = None
        self.adapter_ready = threading.Event()
        self.stdout_lines = []
        self.stderr_lines = []
        self.results = []
        self.seq = [1]  # Using list to allow modification in nested functions
        
    def start_adapter(self):
        """Start the debug adapter process and begin capturing its output."""
        self.adapter_proc = subprocess.Popen(
            self.adapter_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True
        )
        self.adapter_ready.set()
        
        # Read stdout/stderr asynchronously and save all output
        def read_stream(stream, lines):
            for line in stream:
                lines.append(line)
                
        t_out = threading.Thread(target=read_stream, args=(self.adapter_proc.stdout, self.stdout_lines))
        t_err = threading.Thread(target=read_stream, args=(self.adapter_proc.stderr, self.stderr_lines))
        t_out.daemon = True  # Ensure threads don't prevent cleanup
        t_err.daemon = True
        t_out.start()
        t_err.start()
        
        return t_out, t_err
    
    def cleanup(self):
        """Clean up the adapter process."""
        if self.adapter_proc and self.adapter_proc.poll() is None:
            try:
                self.adapter_proc.terminate()
                self.adapter_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                safe_stderr_log("Debug adapter didn't terminate gracefully, killing it")
                self.adapter_proc.kill()
            except Exception as e:
                safe_stderr_log(f"Error during adapter cleanup: {e}")

    def dap_send(self, sock, obj):
        """Send a Debug Adapter Protocol message."""
        data = json.dumps(obj).encode("utf-8")
        msg = f"Content-Length: {len(data)}\r\n\r\n".encode("utf-8") + data
        sock.sendall(msg)

    def dap_recv(self, sock, timeout=5):
        """Receive a Debug Adapter Protocol message."""
        sock.settimeout(timeout)
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = sock.recv(1)
            if not chunk:
                break
            header += chunk
        if not header:
            return None
        header, rest = header.split(b"\r\n\r\n", 1)
        clen = int([l for l in header.decode().split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1].strip())
        body = rest
        while len(body) < clen:
            more = sock.recv(clen - len(body))
            if not more:
                break
            body += more
        return body  # return raw JSON bytes

    def send(self, sock, cmd, args=None):
        """Send a command and wait for response, logging both for analysis."""
        obj = {"seq": self.seq[0], "type": "request", "command": cmd}
        if args is not None:
            obj["arguments"] = args
        self.dap_send(sock, obj)
        self.seq[0] += 1
        resp = self.dap_recv(sock)
        self.results.append({"sent": obj, "recv_raw": resp})
        return json.loads(resp) if resp else None


class EnvironmentIntrospector:
    """
    Handles the complex task of safely introspecting Python environments through DAP evaluate commands.
    This class contains all the logic for probing potentially restricted or modified environments.
    """
    
    def __init__(self, controller):
        self.controller = controller
        
    def evaluate_expression(self, sock, expression, frame_id=None, context="repl", timeout_override=None):
        """
        Use DAP evaluate command to run Python expressions in the debugger context.
        Enhanced with timeout and error handling for potentially hostile environments.
        """
        try:
            args = {
                "expression": expression,
                "context": context  # "repl", "watch", or "hover"
            }
            if frame_id is not None:
                args["frameId"] = frame_id
            
            # Store original socket timeout
            original_timeout = sock.gettimeout()
            
            # Use shorter timeout for potentially dangerous operations
            if timeout_override:
                sock.settimeout(timeout_override)
            
            resp = self.controller.send(sock, "evaluate", args)
            
            # Restore original timeout
            if timeout_override and original_timeout:
                sock.settimeout(original_timeout)
                
            return resp
            
        except socket.timeout:
            safe_stderr_log(f"Timeout evaluating expression: {expression[:100]}...")
            return {"success": False, "error": "timeout", "expression": expression}
        except Exception as e:
            safe_stderr_log(f"Exception evaluating expression '{expression[:100]}...': {str(e)}")
            return {"success": False, "error": str(e), "expression": expression}

    def capture_environment_state(self, sock, frame_id=None):
        """
        Capture comprehensive Python environment information using evaluate requests.
        This goes beyond what's visible in normal stack frame inspection.
        Enhanced with robust error handling for potentially modified/sandboxed environments.
        
        CRITICAL FIX: All expressions now properly import required modules using __import__()
        since the evaluation context may not have these modules in scope.
        """
        env_state = {"environment_introspection": {}, "failed_queries": [], "error_summary": {}}
        
        # Categorized introspection queries with risk levels and fallbacks
        # FIXED: All queries now properly import required modules within the expression
        
        # Low-risk queries that should work in most environments
        basic_queries = [
            ("sys_version", "__import__('sys').version"),
            ("sys_platform", "__import__('sys').platform"),
            ("python_version_info", "str(__import__('sys').version_info)"),
            ("globals_keys_safe", "list(globals().keys()) if hasattr(__builtins__, 'globals') else 'globals() not available'"),
            ("locals_keys_safe", "list(locals().keys()) if hasattr(__builtins__, 'locals') else 'locals() not available'"),
        ]
        
        # Medium-risk queries that might be restricted in sandboxes
        system_queries = [
            ("sys_modules_keys", "list(__import__('sys').modules.keys()) if hasattr(__import__('sys'), 'modules') else 'sys.modules blocked'"),
            ("sys_path", "__import__('sys').path if hasattr(__import__('sys'), 'path') else 'sys.path blocked'"),
            ("sys_executable", "getattr(__import__('sys'), 'executable', 'sys.executable not available')"),
            ("builtin_module_names", "getattr(__import__('sys'), 'builtin_module_names', 'builtin_module_names not available')"),
            ("builtins_dir_safe", "dir(__builtins__) if hasattr(__builtins__, '__dict__') or hasattr(__builtins__, '__dir__') else 'builtins inspection blocked'"),
        ]
        
        # Higher-risk queries that often get blocked or modified in sandboxes
        introspection_queries = [
            ("gc_available", "'gc' in __import__('sys').modules if hasattr(__import__('sys'), 'modules') else False"),
            ("gc_objects_count_safe", "len(__import__('gc').get_objects()) if 'gc' in __import__('sys').modules else 'gc module not available'"),
            ("inspect_available", "'inspect' in __import__('sys').modules if hasattr(__import__('sys'), 'modules') else False"),
            ("os_environ_access", "__import__('os').environ.get('PATH', 'ENV_ACCESS_BLOCKED') if 'os' in __import__('sys').modules else 'os module blocked'"),
            ("threading_available", "'threading' in __import__('sys').modules if hasattr(__import__('sys'), 'modules') else False"),
        ]
        
        # IPython/Jupyter detection queries
        jupyter_queries = [
            ("ipython_check_safe", "hasattr(__builtins__, 'get_ipython') if hasattr(__builtins__, '__dict__') else False"),
            ("get_ipython_callable", "callable(getattr(__builtins__, 'get_ipython', None)) if hasattr(__builtins__, 'get_ipython') else False"),
            ("ipython_instance_check", "get_ipython() is not None if hasattr(__builtins__, 'get_ipython') and callable(getattr(__builtins__, 'get_ipython', None)) else False"),
        ]
        
        # Sandbox detection queries (these are most likely to be blocked)
        security_queries = [
            ("sys_gettrace_available", "hasattr(__import__('sys'), 'gettrace') and callable(getattr(__import__('sys'), 'gettrace', None))"),
            ("sys_gettrace_result", "__import__('sys').gettrace() if hasattr(__import__('sys'), 'gettrace') else 'gettrace not available'"),
            ("sys_settrace_available", "hasattr(__import__('sys'), 'settrace') and callable(getattr(__import__('sys'), 'settrace', None))"),
            ("sys_getprofile_available", "hasattr(__import__('sys'), 'getprofile') and callable(getattr(__import__('sys'), 'getprofile', None))"),
             ("sys_setprofile_available", "hasattr(__import__('sys'), 'setprofile') and callable(getattr(__import__('sys'), 'setprofile', None))"),
            ("restricted_exec_check", "hasattr(__builtins__, 'eval') and hasattr(__builtins__, 'exec')"),
            ("import_restrictions", "hasattr(__builtins__, '__import__')"),
        ]
        
        # Library availability checks (often pre-loaded in data science environments)
        library_queries = [
            ("numpy_in_modules", "'numpy' in __import__('sys').modules if hasattr(__import__('sys'), 'modules') else 'unknown'"),
            ("pandas_in_modules", "'pandas' in __import__('sys').modules if hasattr(__import__('sys'), 'modules') else 'unknown'"),
            ("matplotlib_in_modules", "'matplotlib' in __import__('sys').modules if hasattr(__import__('sys'), 'modules') else 'unknown'"),
            ("jupyter_modules", "[mod for mod in __import__('sys').modules.keys() if 'jupyter' in mod.lower()] if hasattr(__import__('sys'), 'modules') else []"),
            ("ipykernel_modules", "[mod for mod in __import__('sys').modules.keys() if 'ipykernel' in mod.lower()] if hasattr(__import__('sys'), 'modules') else []"),
            ("debugpy_modules", "[mod for mod in __import__('sys').modules.keys() if 'debugpy' in mod.lower() or 'pydev' in mod.lower()] if hasattr(__import__('sys'), 'modules') else []"),
        ]
        
        # Process all query categories with appropriate timeouts and error handling
        all_query_sets = [
            ("basic", basic_queries, 2),      # 2 second timeout for basic queries
            ("system", system_queries, 3),   # 3 second timeout for system queries  
            ("introspection", introspection_queries, 5),  # 5 second timeout for introspection
            ("jupyter", jupyter_queries, 3), # 3 second timeout for Jupyter detection
            ("security", security_queries, 5), # 5 second timeout for security probes
            ("library", library_queries, 3), # 3 second timeout for library checks
        ]
        
        error_counts = {"timeout": 0, "blocked": 0, "exception": 0, "success": 0}
        
        for category, queries, timeout in all_query_sets:
            safe_stderr_log(f"Starting {category} queries (timeout: {timeout}s)")
            category_results = {}
            
            for name, expression in queries:
                try:
                    result = self.evaluate_expression(sock, expression, frame_id, timeout_override=timeout)
                    
                    if result and result.get("success"):
                        category_results[name] = {
                            "expression": expression,
                            "result": result.get("body", {}).get("result", ""),
                            "type": result.get("body", {}).get("type", ""),
                            "success": True,
                            "category": category
                        }
                        error_counts["success"] += 1
                    else:
                        # Determine failure type from DAP response
                        error_msg = result.get("message", "Unknown error") if result else "No response"
                        if result and result.get("error") == "timeout":
                            error_counts["timeout"] += 1
                            failure_type = "timeout"
                        elif any(blocked_indicator in error_msg.lower() for blocked_indicator in 
                                ["restricted", "blocked", "disabled", "not allowed", "permission"]):
                            error_counts["blocked"] += 1
                            failure_type = "blocked"
                        else:
                            error_counts["exception"] += 1
                            failure_type = "exception"
                        
                        category_results[name] = {
                            "expression": expression,
                            "success": False,
                            "error": error_msg,
                            "failure_type": failure_type,
                            "category": category
                        }
                        env_state["failed_queries"].append({
                            "name": name,
                            "expression": expression,
                            "error": error_msg,
                            "category": category
                        })
                        
                except Exception as e:
                    error_counts["exception"] += 1
                    safe_stderr_log(f"Exception in {category} query '{name}': {str(e)}")
                    category_results[name] = {
                        "expression": expression,
                        "success": False,
                        "error": f"Python exception: {str(e)}",
                        "failure_type": "exception",
                        "category": category
                    }
                    env_state["failed_queries"].append({
                        "name": name,
                        "expression": expression,
                        "error": str(e),
                        "category": category
                    })
            
            # Store results for this category
            env_state["environment_introspection"][category] = category_results
            safe_stderr_log(f"Completed {category} queries: {len([r for r in category_results.values() if r.get('success')])} succeeded, {len([r for r in category_results.values() if not r.get('success')])} failed")
        
        # Store error summary for analysis
        env_state["error_summary"] = error_counts
        
        # Special deep-dive queries with extra protection
        safe_stderr_log("Attempting deep-dive queries with extra protection")
        
        # Try to get detailed module information (this is often heavily restricted)
        # FIXED: Use __import__ to access sys.modules safely
        try:
            modules_detail = self.evaluate_expression(sock, 
                "[(name, getattr(mod, '__file__', 'built-in'), getattr(mod, '__version__', 'no-version')) for name, mod in __import__('sys').modules.items() if mod is not None][:50] if hasattr(__import__('sys'), 'modules') else 'sys.modules access blocked'", 
                frame_id, timeout_override=10)
            if modules_detail and modules_detail.get("success"):
                env_state["loaded_modules_detail"] = modules_detail.get("body", {})
            else:
                safe_stderr_log("Failed to get detailed module information")
                env_state["loaded_modules_detail"] = {"error": "access_blocked"}
        except Exception as e:
            safe_stderr_log(f"Exception getting module details: {str(e)}")
            env_state["loaded_modules_detail"] = {"error": str(e)}
        
        # Try to get IPython-specific information with careful error handling
        try:
            ipython_safe_check = self.evaluate_expression(sock, 
                "get_ipython() if hasattr(__builtins__, 'get_ipython') and callable(getattr(__builtins__, 'get_ipython', None)) else None", 
                frame_id, timeout_override=5)
            
            if ipython_safe_check and ipython_safe_check.get("success"):
                # Only proceed with deeper IPython introspection if basic check succeeded
                ipython_info = self.evaluate_expression(sock, 
                    "{'version': getattr(get_ipython(), 'version', 'unknown'), 'class': str(type(get_ipython())), 'has_magics': hasattr(get_ipython(), 'magics_manager')} if get_ipython() else None", 
                    frame_id, timeout_override=8)
                if ipython_info and ipython_info.get("success"):
                    env_state["ipython_details"] = ipython_info.get("body", {})
                else:
                    env_state["ipython_details"] = {"error": "ipython_introspection_blocked"}
            else:
                env_state["ipython_details"] = {"error": "ipython_not_available"}
        except Exception as e:
            safe_stderr_log(f"Exception during IPython introspection: {str(e)}")
            env_state["ipython_details"] = {"error": str(e)}
        
        safe_stderr_log(f"Environment capture complete. Success: {error_counts['success']}, Timeouts: {error_counts['timeout']}, Blocked: {error_counts['blocked']}, Exceptions: {error_counts['exception']}")
        
        return env_state


class DebugAnalyzer:
    """
    Main analyzer class that orchestrates the entire debugging and environment analysis process.
    This class provides the high-level interface for both interactive and programmatic use.
    """
    
    def __init__(self, host=DEFAULT_DAP_HOST, port=DEFAULT_DAP_PORT, buggy_code=None):
        self.controller = DebugAdapterController(host, port)
        self.introspector = EnvironmentIntrospector(self.controller)
        self.buggy_code = buggy_code or DEFAULT_BUGGY_CODE
        self.buggy_script = "buggy.py"
        
    def prepare_test_script(self):
        """Create the test script that will be debugged."""
        with open(self.buggy_script, "w") as f:
            f.write(self.buggy_code)
        safe_stderr_log(f"Created test script: {self.buggy_script}")

    def wait_for_event(self, sock, want_events, timeout=15):
        """Wait for specific debug adapter events."""
        t0 = time.time()
        while True:
            event = self.controller.dap_recv(sock, timeout=timeout)
            if not event:
                break
            self.controller.results.append({"event_raw": event})
            try:
                j = json.loads(event)
            except Exception:
                continue
            if j.get("event") in want_events:
                return j
            if time.time() - t0 > timeout:
                break
        return None

    def enumerate_vars(self, sock, variablesReference, max_depth=2, seen=None):
        """Recursively enumerate variables in the debug context."""
        if variablesReference == 0 or max_depth <= 0:
            return []
        seen = seen or set()
        if variablesReference in seen:
            return []
        seen.add(variablesReference)
        resp = self.controller.send(sock, "variables", {"variablesReference": variablesReference})
        variables = []
        if resp:
            variables = resp.get("body", {}).get("variables", [])
        enriched = []
        for var in variables:
            item = dict(var)
            if isinstance(var.get("variablesReference"), int) and var["variablesReference"] > 0:
                item["children"] = self.enumerate_vars(sock, var["variablesReference"], max_depth-1, seen)
            enriched.append(item)
        return enriched

    def enumerate_all_at_stop(self, sock, stopped_event, label):
        """
        Enhanced version that captures both the original stack/variable information
        plus comprehensive environment state using evaluate commands.
        """
        snapshot = {"label": label, "stopped_event": stopped_event, "threads": []}
        
        # Original stack frame and variable enumeration (unchanged)
        threads = self.controller.send(sock, "threads")
        primary_frame_id = None  # Track the primary frame for environment queries
        
        for thread in threads.get("body", {}).get("threads", []):
            tid = thread["id"]
            tlabel = thread["name"]
            frames_resp = self.controller.send(sock, "stackTrace", {"threadId": tid})
            frames = frames_resp.get("body", {}).get("stackFrames", []) if frames_resp else []
            stacklist = []
            
            for i, frame in enumerate(frames):
                if i == 0:  # Use the top frame for environment introspection
                    primary_frame_id = frame["id"]
                    
                frameinfo = {"frame": frame}
                scopes_resp = self.controller.send(sock, "scopes", {"frameId": frame["id"]})
                scopes = scopes_resp.get("body", {}).get("scopes", []) if scopes_resp else []
                scope_list = []
                for scope in scopes:
                    vref = scope["variablesReference"]
                    scope_vars = self.enumerate_vars(sock, vref, max_depth=2)
                    scope_list.append({
                        "scope": scope,
                        "variables": scope_vars
                    })
                frameinfo["scopes"] = scope_list
                stacklist.append(frameinfo)
                
            snapshot["threads"].append({
                "id": tid, "name": tlabel, "stack": stacklist
            })
        
        # NEW: Capture comprehensive environment state
        if primary_frame_id is not None:
            snapshot["environment_state"] = self.introspector.capture_environment_state(sock, primary_frame_id)
        else:
            # Fallback: try without specific frame context
            snapshot["environment_state"] = self.introspector.capture_environment_state(sock)
        
        self.controller.results.append(snapshot)
        return snapshot

    def run_analysis(self, output_path=None):
        """
        Run the complete debug analysis process.
        This is the main entry point for the analysis.
        
        Returns:
            dict: Complete analysis results including environment state and DAP traces
        """
        output_path = output_path or DEFAULT_OUTPUT_PATH
        
        safe_stderr_log("Starting debug environment analysis")
        
        # Prepare the test environment
        self.prepare_test_script()
        
        # Start the debug adapter
        adapter_thread = threading.Thread(target=self.controller.start_adapter)
        adapter_thread.daemon = True
        adapter_thread.start()
        time.sleep(2)
        self.controller.adapter_ready.wait()
        
        stopped_labels = ["entry", "breakpoint", "exception"]
        
        try:
            with socket.create_connection((self.controller.host, self.controller.port), timeout=10) as sock:
                safe_stderr_log("Connected to debug adapter")
                
                # 1. Initialize
                self.controller.send(sock, "initialize", {"adapterID": "debugpy"})

                # 2. Launch buggy script, stop on entry
                self.controller.send(sock, "launch", {
                    "name": "Python Debug",
                    "type": "python",
                    "request": "launch",
                    "program": self.buggy_script,
                    "console": "internalConsole",
                    "stopOnEntry": True
                })

                # 3. Set breakpoint at result line (line 7)
                self.controller.send(sock, "setBreakpoints", {
                    "source": {"path": self.buggy_script},
                    "breakpoints": [{"line": 7}]
                })

                # 4. Set exception breakpoints
                self.controller.send(sock, "setExceptionBreakpoints", {
                    "filters": ["raised", "uncaught"]
                })

                # 5. Configuration done
                self.controller.send(sock, "configurationDone")

                stop_count = 0
                while True:
                    stopped_event = self.wait_for_event(sock, ["stopped", "terminated", "exited"], timeout=20)
                    if not stopped_event:
                        break
                    if stopped_event.get("event") == "stopped":
                        label = stopped_labels[stop_count] if stop_count < len(stopped_labels) else f"stopped_{stop_count}"
                        safe_stderr_log(f"Analysis stop point: {label}")
                        self.enumerate_all_at_stop(sock, stopped_event, label)
                        stop_count += 1
                        thread_id = stopped_event["body"]["threadId"]
                        self.controller.send(sock, "continue", {"threadId": thread_id})
                    elif stopped_event.get("event") in ("terminated", "exited"):
                        self.controller.results.append({"final_event": stopped_event})
                        break

        except Exception as e:
            safe_stderr_log(f"Error during analysis: {e}")
            raise
        finally:
            # Clean up
            self.controller.cleanup()
            if adapter_thread.is_alive():
                adapter_thread.join(timeout=2)

        # Prepare final output
        safe_stderr_log("Preparing analysis results")
        serializable_results = bytes_to_str(self.controller.results)

        output_obj = {
            "dap_results": serializable_results,
            "adapter_stdout": "".join(self.controller.stdout_lines),
            "adapter_stderr": "".join(self.controller.stderr_lines)
        }

        # Save results to file
        try:
            output_obj_wrapper = {
                'output_file': output_path,
                'output_json': output_obj
            }

            output_json = json.dumps(output_obj_wrapper, indent=2)

            with open(output_path, "w") as f:
                f.write(output_json)
                
            safe_stderr_log(f"Analysis complete. Results saved to: {output_path}")

        except Exception as e:
            safe_stderr_log(f'Exception during output: {e}')
            # Still return the results even if file save fails
        
        return output_obj


# Module-level convenience functions for when used as a library
def run_analysis(host=DEFAULT_DAP_HOST, port=DEFAULT_DAP_PORT, output_path=None, buggy_code=None):
    """
    Convenience function for running analysis when imported as a module.
    
    Args:
        host: Debug adapter host (default: 127.0.0.1)
        port: Debug adapter port (default: 5567)
        output_path: Path for output file (default: timdap.analysis.output.json)
        buggy_code: Custom Python code to analyze (default: division by zero example)
        
    Returns:
        dict: Complete analysis results
    """
    analyzer = DebugAnalyzer(host=host, port=port, buggy_code=buggy_code)
    return analyzer.run_analysis(output_path=output_path)


# Main execution block - this runs when the module is executed directly
def main():
    """
    Main function for command-line execution.
    This handles argument parsing and provides a clean CLI interface.
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Debug Environment Analyzer - Forensic analysis of Python runtime environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python timdap.py                    # Run with defaults
  python timdap.py --port 5568        # Use different port
  python timdap.py --output results/  # Custom output path
        """
    )
    
    parser.add_argument("--host", default=DEFAULT_DAP_HOST, 
                       help=f"Debug adapter host (default: {DEFAULT_DAP_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_DAP_PORT,
                       help=f"Debug adapter port (default: {DEFAULT_DAP_PORT})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_PATH,
                       help=f"Output file path (default: {DEFAULT_OUTPUT_PATH})")
    
    args = parser.parse_args()
    
    try:
        result = run_analysis(
            host=args.host,
            port=args.port, 
            output_path=args.output
        )
        
        print("Analysis completed successfully!")
        print(f"Results saved to: {args.output}")
        print(f"DAP messages captured: {len(result.get('dap_results', []))}")
        
        # Print a brief summary of what was found
        dap_results = result.get('dap_results', [])
        env_snapshots = [r for r in dap_results if isinstance(r, dict) and 'environment_state' in r]
        
        if env_snapshots:
            print(f"Environment snapshots captured: {len(env_snapshots)}")
            for snapshot in env_snapshots:
                env_state = snapshot.get('environment_state', {})
                error_summary = env_state.get('error_summary', {})
                if error_summary:
                    print(f"  {snapshot.get('label', 'unknown')}: {error_summary.get('success', 0)} successful queries, {error_summary.get('blocked', 0)} blocked, {error_summary.get('timeout', 0)} timeouts")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        return 1


# This is the magic that makes the module work both as import and executable
if __name__ == "__main__":
    """
    This block executes when the module is run directly, either as:
    - python timdap.py
    - python timdap/
    - python -m timdap
    """
    sys.exit(main())

# When imported as a module, expose the key classes and functions
__all__ = [
    'DebugAnalyzer',
    'DebugAdapterController', 
    'EnvironmentIntrospector',
    'run_analysis',
    'safe_stderr_log',
    'bytes_to_str'
]
