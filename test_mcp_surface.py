# test_mcp_surface.py
# -*- coding: utf-8 -*-
import pytest

from headless_ida_mcp_server import server


@pytest.mark.unit
def test_engine_status_includes_modules_and_board():
    status = server._engine_status()
    assert isinstance(status["modules"], list)
    assert isinstance(status["dependencies"], dict) and "angr" in status["dependencies"]
    assert status["board"]["session_id"]
    assert "sandbox" in status


@pytest.mark.unit
def test_engine_diagnostics_includes_readiness():
    report = server._engine_diagnostics()
    assert "readiness" in report
    assert "ok" in report["readiness"]


KEEP_TOOLS = {"run_js", "set_binary_path", "open_ida_database", "engine_status",
              "engine_diagnostics", "decompile_function", "decompile_checked",
              "disassemble_function", "get_entry_points"}

DROP_TOOLS = {
    "engine_capabilities", "emulate_code", "trace_code", "strings_code",
    "scan_string_decryptors", "scan_string_call_sites", "emulate_function",
    "scan_string_decrypt_chains", "qiling_capabilities", "qiling_plan",
    "batch_strings_at", "write_strings_results", "rxstubs_stage_log_comments",
    "deobfuscation_scan", "deobfuscation_patch_preview", "stage_deobfuscation_patch",
    "ida_preview", "ida_commit", "ida_discard", "ida_undo", "ida_save_idb",
    "reverse_readiness_check", "angr_project_info", "angr_function_range",
    "angr_stage_result_comments", "get_function", "get_function_by_name",
    "get_function_by_address", "get_current_address", "get_current_function",
    "convert_number", "list_functions", "prepare_decompile",
    "get_prepare_decompile_status", "get_xrefs_to", "set_decompiler_comment",
    "set_disassembly_comment", "refresh_decompiler_widget", "refresh_decompiler_ctext",
    "rename_local_variable", "rename_function", "set_function_prototype",
    "save_idb_file", "save_ida_database",
}


@pytest.mark.unit
def test_mcp_surface_is_sandbox_first():
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("surface")
    server.register(mcp)
    names = set(mcp._tool_manager._tools.keys())
    assert names == KEEP_TOOLS
    assert not (DROP_TOOLS & names)


@pytest.mark.unit
def test_run_js_exposes_structured_option_default_off():
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("surface")
    server.register(mcp)
    fields = mcp._tool_manager._tools["run_js"].fn_metadata.arg_model.model_fields
    assert "structured" in fields
    assert fields["structured"].default is False


@pytest.mark.unit
def test_context_param_is_injected_not_exposed():
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("surface")
    server.register(mcp)
    fields = mcp._tool_manager._tools["engine_status"].fn_metadata.arg_model.model_fields
    assert "ctx" not in fields
