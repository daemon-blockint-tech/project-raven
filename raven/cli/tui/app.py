"""Raven TUI — claude-code-style interactive terminal app.

Architecture:
  * ``rich.console.Console`` for output (markdown, panels, spinners)
  * ``prompt_toolkit.PromptSession`` for the sticky bottom input with
    history, key bindings, and a bottom-toolbar status line.
  * Streaming agent responses rendered via ``rich.live.Live`` so tokens
    appear as they arrive (when the upstream provider supports it).
  * Ctrl+C interrupts the active agent call; Ctrl+D exits.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.spinner import Spinner

from raven.cli.tui import slash_commands, widgets

log = logging.getLogger(__name__)


class RavenTUI:
    """Top-level TUI app — owns the agent, console, and prompt session."""

    HISTORY_FILE = Path.home() / ".raven" / "tui_history"

    def __init__(
        self,
        agent: Any,
        version: str = "0.2.0",
        show_splash: bool = True,
    ) -> None:
        self.agent = agent
        self.version = version
        self.show_splash = show_splash
        self.console = Console()

        # session state
        self._steps_total = 0
        self._tokens_total = 0
        self._provider = agent._client_config.get("ai_provider", "openrouter")

        # build prompt_toolkit session (lazy import so tests don't need it)
        self._session = None

        # wire agent hooks
        self._install_hooks()

    # ------------------------------------------------------------------ #
    # Public                                                              #
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        """Run the main REPL loop until the user exits."""
        if self.show_splash:
            self._render_splash()

        session = self._get_session()

        while True:
            try:
                text = session.prompt(
                    "> ",
                    bottom_toolbar=self._bottom_toolbar,
                )
            except KeyboardInterrupt:
                # Ctrl+C at empty prompt → confirm exit
                self.console.print("[dim]Press Ctrl+D or type /exit to quit.[/]")
                continue
            except EOFError:
                # Ctrl+D → exit
                self.console.print("\n[dim]Goodbye.[/]")
                return

            text = (text or "").strip()
            if not text:
                continue

            # echo user input
            self.console.print(widgets.user_input_echo(text))

            # slash command?
            if text.startswith("/"):
                result = slash_commands.dispatch(self, text)
                if result == "exit":
                    self.console.print("[dim]Goodbye.[/]")
                    return
                continue

            # otherwise → agent turn
            self._run_agent_turn(text)

    # ------------------------------------------------------------------ #
    # Splash / status                                                     #
    # ------------------------------------------------------------------ #

    def _render_splash(self) -> None:
        self.console.print(widgets.splash_banner(self.version))
        self.console.print(widgets.welcome_message(
            model=self.agent.model,
            provider=self._provider,
            n_tools=len(self.agent._tools),
        ))
        self.console.print()

    def _bottom_toolbar(self):
        return widgets.status_bar(
            model=self.agent.model,
            provider=self._provider,
            steps=self._steps_total,
            tokens=self._tokens_total,
        )

    # ------------------------------------------------------------------ #
    # Prompt session                                                      #
    # ------------------------------------------------------------------ #

    def _get_session(self):
        if self._session is not None:
            return self._session

        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

        self.HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

        slash_names = ["/" + n for n in slash_commands.REGISTRY.keys()]
        completer = WordCompleter(slash_names, ignore_case=True, sentence=True)

        self._session = PromptSession(
            history=FileHistory(str(self.HISTORY_FILE)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=completer,
            complete_while_typing=False,
        )
        return self._session

    # ------------------------------------------------------------------ #
    # Agent turn                                                          #
    # ------------------------------------------------------------------ #

    def _run_agent_turn(self, user_text: str) -> None:
        """Send the user input through the agent and stream its reply."""
        self._stream_buffer = ""
        self._tool_start_times: dict = {}

        try:
            with self.console.status("[#a78bfa]Raven thinking…[/]", spinner="dots") as status:
                self._current_status = status
                result = self.agent.send(user_text)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]⚠ Interrupted.[/]")
            return
        except Exception as exc:
            self.console.print(f"\n[red]✗ Agent error:[/] {exc}")
            return
        finally:
            self._current_status = None

        # render final response
        self.console.print()
        self.console.print(widgets.agent_response_panel(result.content))
        self._steps_total += result.steps
        # crude token estimate
        self._tokens_total += len(result.content.split()) + sum(
            len(m.content.split()) for m in result.messages
        )

    # ------------------------------------------------------------------ #
    # Hooks → wire onto the agent                                          #
    # ------------------------------------------------------------------ #

    def _install_hooks(self) -> None:
        def on_tool_call(name: str, args: dict) -> None:
            self._tool_start_times[name] = time.perf_counter()
            # pause the status spinner so the line prints cleanly
            if getattr(self, "_current_status", None):
                self._current_status.stop()
            self.console.print(widgets.tool_call_line(name, args))
            if getattr(self, "_current_status", None):
                self._current_status.start()

        def on_tool_result(name: str, result: Any) -> None:
            start = self._tool_start_times.pop(name, time.perf_counter())
            duration = time.perf_counter() - start
            success = not (isinstance(result, dict) and "error" in result)
            preview = ""
            if isinstance(result, dict):
                if "error" in result:
                    preview = f"error: {result['error']}"
                elif "parsed" in result and isinstance(result["parsed"], dict):
                    first = next(iter(result["parsed"].items()), None)
                    if first:
                        preview = f"{first[0]}={first[1]}"
            elif isinstance(result, str):
                preview = result[:60]

            if getattr(self, "_current_status", None):
                self._current_status.stop()
            self.console.print(widgets.tool_result_line(name, success, duration, preview))
            if getattr(self, "_current_status", None):
                self._current_status.start()

        def on_error(exc: Exception) -> None:
            self.console.print(f"[red]✗[/] {type(exc).__name__}: {exc}")

        self.agent.on_tool_call = on_tool_call
        self.agent.on_tool_result = on_tool_result
        self.agent.on_error = on_error
