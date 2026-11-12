"""LlamaIndex tool wrappers around :class:`RuneboxClient`.

LlamaIndex is imported *lazily* inside :func:`make_runebox_tools` so the base
``runebox`` client keeps working without ``llama-index`` installed. Install the
extra with ``pip install rune-box[llamaindex]``.

Each returned :class:`~llama_index.core.tools.FunctionTool` converts governance
outcomes into a short, model-readable string rather than letting the exception
escape, so an agent can reason about a denial or approval gate instead of
crashing. The messages deliberately spell out the required behavior ("do not
retry", "pause for a human").
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List

from .client import RuneboxApprovalRequired, RuneboxClient, RuneboxDenied

if TYPE_CHECKING:  # only for type checkers; not evaluated at runtime
    from llama_index.core.tools import FunctionTool


def _format_denied(exc: RuneboxDenied) -> str:
    return (
        f"DENIED by policy: {exc.reason}. Do not retry this action; choose a "
        "different, allowed approach or report the block to the human."
    )


def _format_approval(exc: RuneboxApprovalRequired) -> str:
    return (
        f"APPROVAL REQUIRED (approval_id={exc.approval_id}): "
        f"{exc.reason or 'a human must sign off before this runs'}. "
        "Pause the task and ask the human to approve or deny."
    )


def make_runebox_tools(client: RuneboxClient) -> "List[FunctionTool]":
    """Build a list of LlamaIndex ``FunctionTool`` instances bound to ``client``.

    Covers the runebox tool surface: create/kill Citadel, shell, python, node,
    file read/write/list/search, and list-Conclave. Requires ``llama-index``
    (``pip install rune-box[llamaindex]``).
    """
    # Lazy import: keeps llama-index optional for users of the bare client.
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError(
            "LlamaIndex is required for make_runebox_tools(). "
            "Install it with: pip install rune-box[llamaindex]"
        ) from exc

    def _guard(fn):
        """Wrap a call so governance verdicts become model-friendly strings."""

        def wrapped(*args: Any, **kwargs: Any) -> str:
            try:
                result = fn(*args, **kwargs)
                return result if isinstance(result, str) else str(result)
            except RuneboxDenied as denied:
                return _format_denied(denied)
            except RuneboxApprovalRequired as approval:
                return _format_approval(approval)

        return wrapped

    @_guard
    def runebox_create_citadel(profile: str) -> str:
        """Provision a governed Citadel from a runebox Charter (e.g. 'dev').

        Returns the Citadel metadata including its id.
        """
        return str(client.create_sandbox(profile))

    @_guard
    def runebox_shell(sandbox: str, command: List[str], workdir: str = "") -> str:
        """Run a shell command (argv list, e.g. ['ls','-la']) in a Citadel.

        Returns verdict, exit_code, stdout, stderr.
        """
        return str(client.shell(sandbox, command, workdir))

    @_guard
    def runebox_python(sandbox: str, code: str) -> str:
        """Run a Python code snippet inside the Citadel."""
        return str(client.python(sandbox, code))

    @_guard
    def runebox_node(sandbox: str, code: str) -> str:
        """Run a Node.js code snippet inside the Citadel."""
        return str(client.node(sandbox, code))

    @_guard
    def runebox_read_file(sandbox: str, path: str) -> str:
        """Read a file's contents from the Citadel."""
        return client.read_file(sandbox, path)

    @_guard
    def runebox_write_file(sandbox: str, path: str, content: str) -> str:
        """Write content to a file in the Citadel."""
        return f"wrote {client.write_file(sandbox, path, content)} bytes to {path}"

    @_guard
    def runebox_list_files(sandbox: str, path: str) -> str:
        """List a directory in the Citadel."""
        return client.list_files(sandbox, path)

    @_guard
    def runebox_search_files(sandbox: str, query: str, path: str) -> str:
        """Search for a query string under a path in the Citadel."""
        return client.search_files(sandbox, query, path)

    @_guard
    def runebox_list_conclave() -> str:
        """List pending human-in-the-loop Conclave requests."""
        return str(client.list_approvals())

    @_guard
    def runebox_kill_citadel(sandbox: str) -> str:
        """Tear down a Citadel when the task is finished."""
        client.kill_sandbox(sandbox)
        return f"Citadel {sandbox} terminated"

    return [
        FunctionTool.from_defaults(fn=runebox_create_citadel),
        FunctionTool.from_defaults(fn=runebox_shell),
        FunctionTool.from_defaults(fn=runebox_python),
        FunctionTool.from_defaults(fn=runebox_node),
        FunctionTool.from_defaults(fn=runebox_read_file),
        FunctionTool.from_defaults(fn=runebox_write_file),
        FunctionTool.from_defaults(fn=runebox_list_files),
        FunctionTool.from_defaults(fn=runebox_search_files),
        FunctionTool.from_defaults(fn=runebox_list_conclave),
        FunctionTool.from_defaults(fn=runebox_kill_citadel),
    ]
