"""Rich renderables for the Raven TUI.

Provides:
  * splash banner (gradient-colored ASCII art)
  * status bar
  * tool-call panel
  * agent-response markdown panel
  * user-input echo line
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from rich.align import Align
from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text


# ---------------------------------------------------------------------------
# Splash
# ---------------------------------------------------------------------------

_LOGO_DIR = Path(__file__).resolve().parents[3] / "logo" / "ascii"
_PNG_PATH = _LOGO_DIR / "ascii-art.png"
_TXT_PATH = _LOGO_DIR / "ascii-art.txt"

# Gradient colors (deep purple → magenta) reminiscent of claude-code
_GRADIENT = [
    "#5b21b6", "#6d28d9", "#7c3aed", "#8b5cf6", "#a78bfa",
    "#c4b5fd", "#d8b4fe", "#e9d5ff", "#f0abfc", "#e879f9",
    "#d946ef", "#c026d3", "#a21caf", "#86198f", "#701a75",
    "#5b21b6", "#6d28d9", "#7c3aed", "#8b5cf6", "#a78bfa",
    "#c4b5fd", "#d8b4fe", "#e9d5ff", "#f0abfc", "#e879f9",
    "#d946ef",
]


def _pick_gradient(row_ratio: float) -> str:
    """Pick a gradient color from a 0..1 row ratio."""
    idx = min(int(row_ratio * len(_GRADIENT)), len(_GRADIENT) - 1)
    return _GRADIENT[idx]


def _render_png_banner(max_width: int = 80) -> Optional[Text]:
    """Render the PNG logo as colored unicode half-blocks with gradient.

    Each terminal row encodes two image rows (top half ▀ / bottom half █-bg).
    For our mostly black-on-white logo, we map dark pixels → gradient color,
    light pixels → transparent (default bg). Returns ``None`` on any failure.
    """
    try:
        from PIL import Image
    except ImportError:
        return None

    if not _PNG_PATH.exists():
        return None

    try:
        img = Image.open(_PNG_PATH).convert("RGBA")
    except Exception:
        return None

    # Downsample: terminal char ≈ 2x1 pixel ratio; target ~max_width chars wide
    src_w, src_h = img.size
    target_w = min(max_width, src_w)
    # height in *pixels* — each terminal row = 2 image rows
    target_h = max(1, int(src_h * (target_w / src_w) * 0.55))
    # half-blocks → image must have even height
    if target_h % 2:
        target_h += 1
    img = img.resize((target_w, target_h), Image.LANCZOS)
    pixels = img.load()

    text = Text()
    n_rows = target_h // 2

    for ty in range(n_rows):
        color = _pick_gradient(ty / max(1, n_rows - 1))
        for tx in range(target_w):
            top = pixels[tx, ty * 2]
            bot = pixels[tx, ty * 2 + 1]
            # treat dark pixels (low brightness OR opaque non-white) as "ink"
            top_ink = _is_ink(top)
            bot_ink = _is_ink(bot)
            if top_ink and bot_ink:
                text.append("█", style=color)
            elif top_ink:
                text.append("▀", style=color)
            elif bot_ink:
                text.append("▄", style=color)
            else:
                text.append(" ")
        text.append("\n")

    return text


def _is_ink(rgba) -> bool:
    """Return True if a pixel should be rendered as 'ink' (dark)."""
    r, g, b, a = rgba
    if a < 64:
        return False
    brightness = (0.299 * r + 0.587 * g + 0.114 * b)
    return brightness < 200


def _render_text_banner() -> Text:
    """Fallback: render the .txt logo with the gradient (line-by-line)."""
    try:
        raw = _TXT_PATH.read_text(encoding="utf-8")
    except OSError:
        return Text("PROJECT RAVEN", style="bold #a78bfa")
    lines = raw.splitlines()
    text = Text()
    n = max(1, len(lines) - 1)
    for i, line in enumerate(lines):
        text.append(line + "\n", style=_pick_gradient(i / n))
    return text


def splash_banner(version: str = "0.2.0", max_width: int = 80) -> RenderableType:
    """Render the logo (PNG preferred, .txt fallback) + tagline."""
    banner = _render_png_banner(max_width=max_width) or _render_text_banner()

    tagline = Text()
    tagline.append("\n  Project Raven  ", style="bold #a78bfa")
    tagline.append(f"v{version}\n", style="dim")
    tagline.append("  Autonomous Defense System — Multi-Provider AI\n", style="dim italic")

    return Group(Align.left(banner), Align.left(tagline))


def welcome_message(model: str, provider: str, n_tools: int) -> RenderableType:
    """Block shown immediately after the splash."""
    body = Text()
    body.append("  Model:    ", style="dim")
    body.append(f"{model}\n", style="bold #a78bfa")
    body.append("  Provider: ", style="dim")
    body.append(f"{provider}\n", style="bold #a78bfa")
    body.append("  Tools:    ", style="dim")
    body.append(f"{n_tools} registered\n\n", style="bold #a78bfa")
    body.append("  Type ", style="dim")
    body.append("/help", style="bold cyan")
    body.append(" for commands, ", style="dim")
    body.append("/exit", style="bold cyan")
    body.append(" to quit.\n", style="dim")
    return body


# ---------------------------------------------------------------------------
# Status bar
# ---------------------------------------------------------------------------

def status_bar(model: str, provider: str, steps: int = 0, tokens: int = 0) -> str:
    """Compact one-line status string for prompt_toolkit's bottom_toolbar.

    Returns a plain string (prompt_toolkit handles its own styling via
    FormattedText elsewhere).
    """
    parts = [
        f"⏺ {model}",
        f"{provider}",
        f"{steps} step{'s' if steps != 1 else ''}",
    ]
    if tokens:
        parts.append(f"{tokens:,} tokens")
    parts.append("Ctrl+C interrupt · Ctrl+D exit")
    return "  ".join(parts)


# ---------------------------------------------------------------------------
# Tool-call panel
# ---------------------------------------------------------------------------

def tool_call_line(name: str, args: Dict[str, Any]) -> RenderableType:
    """Single-line inline indicator while a tool runs."""
    args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
    t = Text()
    t.append("● ", style="bold yellow")
    t.append(name, style="bold")
    t.append(f"({args_str})", style="dim")
    return t


def tool_result_line(
    name: str,
    success: bool,
    duration: float,
    preview: str = "",
) -> RenderableType:
    """Single-line completion indicator with checkmark + duration."""
    t = Text()
    t.append("● " if success else "✗ ", style="bold green" if success else "bold red")
    t.append(name, style="bold")
    t.append(f"  [{duration:.2f}s]", style="dim cyan")
    if preview:
        t.append(f"  → {preview[:80]}", style="dim")
    return t


def tool_call_panel(
    name: str,
    args: Dict[str, Any],
    result: Optional[str] = None,
    duration: float = 0.0,
    success: bool = True,
) -> RenderableType:
    """Boxed panel for a complete tool call (input + output preview)."""
    args_str = "\n".join(f"  {k} = {v!r}" for k, v in args.items())
    body = Text()
    body.append("args:\n", style="dim bold")
    body.append(args_str + "\n", style="dim")
    if result:
        body.append("\nresult:\n", style="dim bold")
        body.append(result[:500] + ("…" if len(result) > 500 else ""), style="white")
    border = "green" if success else "red"
    title = f"● {name}  [{duration:.2f}s]"
    return Panel(body, title=title, border_style=border, expand=False)


# ---------------------------------------------------------------------------
# Agent response panel
# ---------------------------------------------------------------------------

def agent_response_panel(content: str) -> RenderableType:
    """Markdown-rendered agent response inside a subtle panel."""
    md = Markdown(content or "")
    return Panel(
        md,
        title="[bold #a78bfa]Raven[/]",
        title_align="left",
        border_style="#7c3aed",
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# User input echo
# ---------------------------------------------------------------------------

def user_input_echo(text: str) -> RenderableType:
    """Subtle gray echo of what the user typed."""
    t = Text()
    t.append("> ", style="bold cyan")
    t.append(text, style="bold")
    return t
