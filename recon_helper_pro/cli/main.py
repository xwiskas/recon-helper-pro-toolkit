"""The Recon Helper Pro command line (PRD 11).

This module renders; it never recons. Every command builds an
:class:`~recon_helper_pro.core.engine.Engine` and asks it to do the work, which
is what keeps the CLI and the future dashboard honest about sharing one engine.
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from .. import APP_NAME, __version__
from ..core.config import VERBOSITY_LEVELS, cloud_sync_warning
from ..core.engine import Engine, RunOutcome
from ..core.errors import RHPError, ScopeError
from ..core.models import Engagement, RunStatus, SeverityHint
from ..core.reporting import write_report
from ..core.safety import AGREEMENT_TEXT, AGREEMENT_VERSION
from ..core.scope import ScopeDecision, parse_scope_entry

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=f"{APP_NAME} - a learner-first recon companion for authorized targets.",
)
engagement_app = typer.Typer(no_args_is_help=True, help="Create and switch engagements.")
scope_app = typer.Typer(no_args_is_help=True, help="Manage what you are authorized to contact.")
config_app = typer.Typer(no_args_is_help=True, help="Read and change settings.")
app.add_typer(engagement_app, name="engagement")
app.add_typer(scope_app, name="scope")
app.add_typer(config_app, name="config")

STATE: dict[str, Any] = {"data_dir": None, "verbosity": None, "engine": None}

STATUS_STYLE = {
    RunStatus.COMPLETED: "green",
    RunStatus.PARTIAL: "yellow",
    RunStatus.FAILED: "red",
    RunStatus.CANCELLED: "magenta",
    RunStatus.RUNNING: "cyan",
    RunStatus.QUEUED: "dim",
}

SEVERITY_STYLE = {
    SeverityHint.HIGH: "bold red",
    SeverityHint.MEDIUM: "yellow",
    SeverityHint.LOW: "cyan",
    SeverityHint.INFO: "dim",
}


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------
def get_engine() -> Engine:
    if STATE["engine"] is None:
        engine = Engine.open(STATE["data_dir"])
        engine.clear_cancel()
        _install_signal_handler(engine)
        STATE["engine"] = engine
    return STATE["engine"]


def _install_signal_handler(engine: Engine) -> None:
    def handler(signum: int, frame: Any) -> None:
        engine.cancel.cancel()
        err_console.print(
            "\n[yellow]Cancelling...[/yellow] finishing the current step and keeping "
            "whatever has already been collected."
        )

    try:
        signal.signal(signal.SIGINT, handler)
    except (ValueError, OSError):  # not the main thread, or unsupported platform
        pass


def verbosity(engine: Engine) -> str:
    if STATE["verbosity"]:
        return str(STATE["verbosity"])
    return str(engine.settings.get("verbosity", "beginner"))


def banner() -> None:
    console.print(
        Panel.fit(
            f"[bold]{APP_NAME}[/bold] {__version__}\n"
            "[dim]Read-only reconnaissance. Only point this at systems you are "
            "authorized to test.[/dim]",
            border_style="cyan",
        )
    )


def fail(message: str, code: int = 1) -> None:
    err_console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(code)


def require_engagement(engine: Engine, engagement_id: int | None = None) -> Engagement:
    if engagement_id is not None:
        engagement = engine.db.get_engagement(engagement_id)
        if engagement is None:
            fail(f"No engagement with id {engagement_id}.")
        return engagement  # type: ignore[return-value]
    engagement = engine.current_engagement()
    if engagement is None:
        fail(
            "No engagement selected. Create one with:\n"
            '  rhp engagement new "My first engagement"'
        )
    return engagement  # type: ignore[return-value]


def parse_params(values: list[str] | None) -> dict[str, Any]:
    """Turn ``--param key=value`` pairs into typed module parameters."""
    params: dict[str, Any] = {}
    for item in values or []:
        if "=" not in item:
            fail(f"--param expects key=value, got {item!r}.")
        key, _, raw = item.partition("=")
        lowered = raw.strip().lower()
        if lowered in {"true", "false"}:
            params[key.strip()] = lowered == "true"
        elif raw.strip().lstrip("-").isdigit():
            params[key.strip()] = int(raw.strip())
        else:
            params[key.strip()] = raw.strip()
    return params


@app.callback()
def main(
    data_dir: Optional[Path] = typer.Option(
        None, "--data-dir", help="Where to keep the database, artifacts and exports."
    ),
    level: Optional[str] = typer.Option(
        None, "--verbosity", help=f"One of: {', '.join(VERBOSITY_LEVELS)}."
    ),
) -> None:
    """Global options."""
    if level and level not in VERBOSITY_LEVELS:
        fail(f"--verbosity must be one of {', '.join(VERBOSITY_LEVELS)}.")
    STATE["data_dir"] = str(data_dir) if data_dir else None
    STATE["verbosity"] = level


# --------------------------------------------------------------------------
# Rendering helpers
# --------------------------------------------------------------------------
def show_before(outcome_module: Any, lesson: Any, level: str) -> None:
    if level == "quiet" or lesson.is_empty():
        return
    body = lesson.before if level == "beginner" else lesson.before.split("\n\n")[0]
    if not body:
        return
    console.print(
        Panel(
            Markdown(body),
            title=f"What this does - {lesson.title}",
            subtitle=f"contact mode: {outcome_module.mode.value}",
            border_style="blue",
        )
    )


def show_outcome(outcome: RunOutcome, level: str) -> None:
    status = outcome.status
    style = STATUS_STYLE.get(status, "white")
    console.print(
        f"[{style}]{status.value}[/{style}] "
        f"{outcome.module.id} - {outcome.saved_observations} observation(s), "
        f"{outcome.saved_findings} finding(s), {outcome.recorded_assets} asset(s), "
        f"{outcome.requests} request(s) to the target"
    )

    for error in outcome.result.errors:
        err_console.print(f"  [red]![/red] {error}")
    if level != "quiet":
        for warning in outcome.result.warnings:
            console.print(f"  [yellow]-[/yellow] {warning}")

    if outcome.result.observations and level != "quiet":
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("type", style="cyan", no_wrap=True)
        table.add_column("value")
        table.add_column("confidence", style="dim")
        limit = 40 if level == "beginner" else 15
        for observation in outcome.result.observations[:limit]:
            table.add_row(
                observation.type,
                observation.normalized_value[:110],
                observation.confidence.value,
            )
        console.print(table)
        if len(outcome.result.observations) > limit:
            console.print(
                f"  [dim]... and {len(outcome.result.observations) - limit} more "
                "(see 'rhp report').[/dim]"
            )

    for finding in outcome.result.findings:
        severity_style = SEVERITY_STYLE.get(finding.severity_hint, "white")
        console.print(
            Panel(
                Markdown(
                    f"{finding.interpretation_text}\n\n"
                    f"**Limitations.** {finding.limitations}"
                ),
                title=f"[{severity_style}]hint: {finding.title}[/{severity_style}]",
                subtitle=(
                    f"severity hint {finding.severity_hint.value} - "
                    f"confidence {finding.confidence.value} - not a confirmed vulnerability"
                ),
                border_style=severity_style,
            )
        )

    if level == "beginner" and outcome.lesson.after:
        console.print(
            Panel(
                Markdown(outcome.lesson.after),
                title="How to read this",
                border_style="green",
            )
        )
    if level == "beginner" and outcome.lesson.next_steps:
        console.print("[bold]Suggested next steps[/bold]")
        for step in outcome.lesson.next_steps:
            console.print(f"  - {step}")


def confirm_override(module: Any, decision: ScopeDecision, assume_yes: bool) -> bool:
    """Warn-but-allow, as chosen in the PRD - with the warning made real."""
    console.print(
        Panel(
            f"[yellow]{decision.reason}[/yellow]\n\n"
            f"'{module.name}' has contact mode [bold]{module.mode.value}[/bold], so running it "
            "would send a request to a destination that is not in your engagement scope.\n\n"
            "Only continue if you are certain you are authorized to contact it. Your answer is "
            "recorded in the activity log and appears in the report.",
            title="Out of scope",
            border_style="yellow",
        )
    )
    if assume_yes:
        console.print("[yellow]--yes was given: proceeding and recording the override.[/yellow]")
        return True
    return typer.confirm("Contact this out-of-scope destination anyway?", default=False)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
@app.command()
def init(
    accept: bool = typer.Option(
        False, "--accept", help="Accept the agreement without the interactive prompt."
    ),
) -> None:
    """First-run setup and the authorization acknowledgment."""
    banner()
    engine = get_engine()
    warning = cloud_sync_warning(engine.paths.data_dir)
    console.print(f"Data directory: [bold]{engine.paths.data_dir}[/bold]")
    if warning:
        console.print(Panel(warning, title="Storage location", border_style="yellow"))

    if engine.is_authorized():
        console.print("[green]The authorization agreement is already accepted.[/green]")
    else:
        console.print(Panel(AGREEMENT_TEXT, title="Please read", border_style="red"))
        if not accept and not typer.confirm(
            f"Do you accept this agreement (version {AGREEMENT_VERSION})?", default=False
        ):
            fail("Not accepted. Nothing was configured.", code=2)
        engine.accept_agreement()
        console.print("[green]Accepted and recorded.[/green]")

    console.print(
        "\nNext: create an engagement and declare your scope.\n"
        '  rhp engagement new "Practice run"\n'
        "  rhp scope add example.com\n"
        "  rhp recon example.com"
    )


@engagement_app.command("new")
def engagement_new(
    name: str = typer.Argument(..., help="A name for this piece of work."),
    description: str = typer.Option("", "--description", "-d"),
) -> None:
    """Create an engagement and select it."""
    engine = get_engine()
    if engine.db.get_engagement_by_name(name):
        fail(f"An engagement called {name!r} already exists.")
    engagement = engine.db.create_engagement(name, description)
    engine.save_state(engagement_id=engagement.id)
    console.print(f"[green]Created[/green] engagement {engagement.id}: {engagement.name}")
    console.print("Now declare your scope, for example: [bold]rhp scope add example.com[/bold]")


@engagement_app.command("list")
def engagement_list() -> None:
    """List engagements."""
    engine = get_engine()
    current = engine.current_engagement()
    table = Table(title="Engagements")
    table.add_column("id", justify="right")
    table.add_column("name")
    table.add_column("created")
    table.add_column("scope", justify="right")
    table.add_column("runs", justify="right")
    for engagement in engine.db.list_engagements():
        assert engagement.id is not None
        marker = " [cyan](current)[/cyan]" if current and current.id == engagement.id else ""
        table.add_row(
            str(engagement.id),
            engagement.name + marker,
            engagement.created_at,
            str(len(engine.db.list_scope_entries(engagement.id))),
            str(len(engine.db.list_runs(engagement.id, limit=10_000))),
        )
    console.print(table)


@engagement_app.command("use")
def engagement_use(engagement_id: int = typer.Argument(...)) -> None:
    """Select the engagement later commands act on."""
    engine = get_engine()
    engagement = require_engagement(engine, engagement_id)
    engine.save_state(engagement_id=engagement.id)
    console.print(f"[green]Using[/green] engagement {engagement.id}: {engagement.name}")


@scope_app.command("add")
def scope_add(
    entry: str = typer.Argument(..., help="host, *.wildcard, IP, CIDR, optionally scheme/port."),
) -> None:
    """Declare something you are authorized to contact."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    try:
        parsed = parse_scope_entry(entry)
    except ScopeError as exc:
        fail(str(exc))
        return
    saved = engine.add_scope(engagement.id, parsed)
    console.print(f"[green]Added[/green] scope entry {saved.id}: {saved.type.value} {saved.display()}")
    if saved.type.value == "host":
        console.print(
            "[dim]Exact-host semantics: this authorizes that host only. Add "
            f"'*.{saved.value}' if subdomains are also in scope.[/dim]"
        )


@scope_app.command("list")
def scope_list() -> None:
    """Show the current scope."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    entries = engine.db.list_scope_entries(engagement.id)
    if not entries:
        console.print("[yellow]No scope entries yet.[/yellow] Add one with 'rhp scope add'.")
        return
    table = Table(title=f"Scope for {engagement.name}")
    table.add_column("id", justify="right")
    table.add_column("type")
    table.add_column("entry")
    for entry in entries:
        table.add_row(str(entry.id), entry.type.value, entry.display())
    console.print(table)
    console.print(
        "[dim]Always blocked regardless of scope: link-local (169.254.0.0/16, fe80::/10) "
        "and cloud metadata endpoints.[/dim]"
    )


@scope_app.command("remove")
def scope_remove(entry_id: int = typer.Argument(...)) -> None:
    """Remove a scope entry."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    if engine.remove_scope(engagement.id, entry_id):
        console.print(f"[green]Removed[/green] scope entry {entry_id}.")
    else:
        fail(f"No scope entry {entry_id} in this engagement.")


@app.command()
def modules() -> None:
    """List the bundled modules, their contact mode and budget."""
    engine = get_engine()
    table = Table(title="Bundled modules (v1 loads no third-party modules)")
    table.add_column("id", style="cyan")
    table.add_column("name")
    table.add_column("mode")
    table.add_column("budget", justify="right")
    table.add_column("optional tools")
    for row in engine.module_table():
        tools = ", ".join(
            f"{name} [green]detected[/green]" if version else f"{name} [dim]absent[/dim]"
            for name, version in row["detected_tools"].items()
        )
        table.add_row(
            row["id"],
            row["name"],
            row["mode"],
            str(row["request_budget"]),
            tools or "[dim]none[/dim]",
        )
    console.print(table)
    console.print(
        "[dim]Every capability works with no external tools installed; the tools above only "
        "add depth.[/dim]"
    )


@app.command()
def run(
    module_id: str = typer.Argument(..., help="Module id, as listed by 'rhp modules'."),
    target: str = typer.Argument(..., help="Domain, host, IP or URL."),
    param: Optional[list[str]] = typer.Option(None, "--param", "-p", help="key=value."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm an out-of-scope override."),
) -> None:
    """Run one module against one target."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    level = verbosity(engine)

    try:
        module = engine.registry.require(module_id)
    except KeyError as exc:
        fail(str(exc))
        return

    if not engine.is_authorized():
        fail("Run 'rhp init' and accept the agreement first.", code=2)

    override = False
    decision = engine.preflight(engagement.id, module, target)
    if decision is not None and not decision.allowed:
        if decision.blocked:
            fail(decision.reason, code=3)
        if not confirm_override(module, decision, yes):
            fail("Not confirmed. No request was sent.", code=4)
        override = True

    show_before(module, engine.teaching.lesson(module.teaching_key), level)
    try:
        outcome = engine.run_module(
            engagement,
            module_id,
            target,
            params=parse_params(param),
            override_confirmed=override,
            override_reason="confirmed on the command line" if override else "",
            progress=(lambda message: console.print(f"[dim]  {message}[/dim]"))
            if level != "quiet"
            else None,
        )
    except RHPError as exc:
        fail(str(exc))
        return

    show_outcome(outcome, level)
    if outcome.status in (RunStatus.FAILED,):
        raise typer.Exit(1)


@app.command()
def recon(
    domain: str = typer.Argument(..., help="The domain to walk the guided recipe against."),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", help="Run every step without pausing (for scripts)."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Automatically confirm out-of-scope overrides."
    ),
    only: Optional[list[str]] = typer.Option(
        None, "--only", help="Run only these module ids, in this order."
    ),
    report_after: bool = typer.Option(True, "--report/--no-report", help="Write a report at the end."),
) -> None:
    """The guided golden path: registration, DNS, hostnames, certificate, web, report."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    level = verbosity(engine)
    banner()

    if not engine.is_authorized():
        fail("Run 'rhp init' and accept the agreement first.", code=2)

    scope = engine.scope_for(engagement.id)
    if len(scope) == 0:
        console.print(
            Panel(
                f"This engagement has no scope yet, so every step that contacts {domain} "
                "will ask you to confirm an out-of-scope override.\n\n"
                f"If you are authorized to test it, declare that first:\n"
                f"  [bold]rhp scope add {domain}[/bold]",
                title="No scope declared",
                border_style="yellow",
            )
        )

    def confirm(module: Any, decision: ScopeDecision) -> bool:
        if non_interactive:
            if yes:
                return True
            console.print(
                f"[yellow]Skipping {module.id}: {decision.reason} "
                "(--non-interactive without --yes never overrides scope.)[/yellow]"
            )
            return False
        return confirm_override(module, decision, yes)

    def before_step(step: Any) -> bool:
        console.rule(f"[bold]Step {step.index}/{step.total}: {step.module.name}[/bold]")
        show_before(step.module, step.lesson, level)
        if non_interactive or level != "beginner":
            return True
        return typer.confirm("Run this step?", default=True)

    failures = 0
    completed = 0
    for step in engine.run_recipe(
        engagement,
        domain,
        module_ids=only,
        before_step=before_step,
        confirm=confirm,
        progress=(lambda message: console.print(f"[dim]  {message}[/dim]"))
        if level != "quiet"
        else None,
    ):
        if step.outcome is None:
            console.print(f"[yellow]Skipped {step.module.id}: {step.skipped_reason}[/yellow]")
            continue
        show_outcome(step.outcome, level)
        completed += 1
        if step.outcome.status is RunStatus.FAILED:
            failures += 1

    console.rule("[bold]Recon complete[/bold]")
    console.print(
        f"{completed} step(s) ran, {failures} failed. A failed step never stops the workflow - "
        "the gap is recorded in the report's coverage table."
    )
    if report_after:
        _write_report(engine, engagement)


@app.command()
def assets() -> None:
    """Assets recorded for the current engagement (recorded, never auto-contacted)."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    rows = engine.db.list_assets(engagement.id)
    if not rows:
        console.print("[yellow]No assets recorded yet.[/yellow]")
        return
    table = Table(title=f"Assets - {engagement.name}")
    table.add_column("kind")
    table.add_column("value")
    table.add_column("in scope")
    table.add_column("found by")
    for asset in rows:
        table.add_row(
            asset.kind.value,
            asset.value,
            "[green]yes[/green]" if asset.in_scope else "[dim]no[/dim]",
            asset.discovered_by,
        )
    console.print(table)
    console.print(
        "[dim]Discovered assets are never contacted automatically. Add one to scope "
        "deliberately if you are authorized to test it.[/dim]"
    )


@app.command()
def findings() -> None:
    """Interpretations recorded for the current engagement."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    rows = engine.db.findings_for_engagement(engagement.id)
    if not rows:
        console.print("[yellow]No findings yet.[/yellow]")
        return
    table = Table(title=f"Findings - {engagement.name} (interpretations, not confirmations)")
    table.add_column("severity hint")
    table.add_column("confidence")
    table.add_column("title")
    table.add_column("asset")
    for row in rows:
        table.add_row(
            str(row.get("severity_hint")),
            str(row.get("confidence")),
            str(row.get("title")),
            str(row.get("asset_value") or "-"),
        )
    console.print(table)


@app.command()
def runs(limit: int = typer.Option(20, "--limit")) -> None:
    """Recent runs and their status."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    table = Table(title=f"Runs - {engagement.name}")
    table.add_column("id", justify="right")
    table.add_column("module")
    table.add_column("mode")
    table.add_column("target")
    table.add_column("status")
    table.add_column("requests", justify="right")
    table.add_column("started")
    for item in engine.db.list_runs(engagement.id, limit=limit):
        style = STATUS_STYLE.get(item.status, "white")
        table.add_row(
            str(item.id),
            item.module,
            item.mode.value,
            item.target,
            f"[{style}]{item.status.value}[/{style}]",
            str(item.request_count),
            item.started_at,
        )
    console.print(table)


@app.command()
def activity(limit: int = typer.Option(30, "--limit")) -> None:
    """The activity log: every run and every override."""
    engine = get_engine()
    engagement = require_engagement(engine)
    assert engagement.id is not None
    table = Table(title=f"Activity - {engagement.name}")
    table.add_column("when")
    table.add_column("module")
    table.add_column("mode")
    table.add_column("target")
    table.add_column("requests", justify="right")
    table.add_column("outcome")
    table.add_column("override")
    for event in engine.db.list_activity(engagement.id, limit=limit):
        table.add_row(
            str(event.get("timestamp")),
            str(event.get("module")),
            str(event.get("mode")),
            str(event.get("target")),
            str(event.get("request_count")),
            str(event.get("outcome")),
            str(event.get("override_reason") or "-"),
        )
    console.print(table)


def _write_report(engine: Engine, engagement: Engagement) -> None:
    report = write_report(engine.db, engine.teaching, engagement, engine.paths.exports_dir)
    console.print(f"[green]Report written:[/green] {report.path}")


@app.command()
def report(
    engagement_id: Optional[int] = typer.Option(None, "--engagement", "-e"),
    show: bool = typer.Option(False, "--show", help="Also print the report to the terminal."),
) -> None:
    """Generate the Markdown report for an engagement."""
    engine = get_engine()
    engagement = require_engagement(engine, engagement_id)
    written = write_report(engine.db, engine.teaching, engagement, engine.paths.exports_dir)
    console.print(f"[green]Report written:[/green] {written.path}")
    if show:
        console.print(Markdown(written.markdown))


@app.command()
def cancel() -> None:
    """Ask a running module or workflow (in this or another process) to stop."""
    engine = get_engine()
    engine.request_cancel()
    console.print(
        "[yellow]Cancellation requested.[/yellow] A running workflow will stop at its next "
        "checkpoint and keep whatever it has already collected."
    )


@app.command()
def purge(
    engagement_id: Optional[int] = typer.Option(None, "--engagement", "-e"),
    artifacts_only: bool = typer.Option(
        False, "--artifacts-only", help="Delete stored raw artifacts but keep the engagement."
    ),
    expired_only: bool = typer.Option(
        False, "--expired-only", help="Only delete artifacts past the retention window."
    ),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Delete stored raw artifacts, or an entire engagement's data."""
    engine = get_engine()
    if expired_only:
        removed = engine.prune_artifacts(engagement_id)
        console.print(f"[green]Pruned[/green] {removed} artifact(s) past their retention window.")
        return

    engagement = require_engagement(engine, engagement_id)
    assert engagement.id is not None
    what = "raw artifacts" if artifacts_only else "ALL data (artifacts, runs, findings, scope)"
    if not yes and not typer.confirm(
        f"Delete {what} for engagement {engagement.id} ({engagement.name})?", default=False
    ):
        fail("Nothing was deleted.", code=2)

    if artifacts_only:
        removed = engine.purge_artifacts(engagement.id)
        console.print(f"[green]Deleted[/green] {removed} artifact(s).")
    else:
        removed = engine.purge_engagement(engagement.id)
        console.print(
            f"[green]Deleted[/green] engagement {engagement.id} and {removed} artifact(s)."
        )


@app.command()
def define(term: Optional[str] = typer.Argument(None, help="Leave empty to list all terms.")) -> None:
    """Glossary."""
    engine = get_engine()
    if not term:
        console.print("Terms: " + ", ".join(engine.teaching.terms()))
        return
    match = engine.teaching.define(term)
    if match is None:
        fail(f"No glossary entry for {term!r}. Try 'rhp define' to list them all.")
        return
    name, body = match
    console.print(Panel(Markdown(body), title=name, border_style="cyan"))


@config_app.command("list")
def config_list() -> None:
    """Show every setting and its current value."""
    engine = get_engine()
    table = Table(title="Settings")
    table.add_column("key", style="cyan")
    table.add_column("value")
    for key, value in sorted(engine.settings.items()):
        table.add_row(key, str(value))
    console.print(table)


@config_app.command("set")
def config_set(key: str = typer.Argument(...), value: str = typer.Argument(...)) -> None:
    """Change a setting."""
    engine = get_engine()
    from ..core.config import DEFAULTS

    if key not in DEFAULTS:
        fail(f"Unknown setting {key!r}. See 'rhp config list'.")
    engine.db.set_setting(key, value)
    console.print(f"[green]Set[/green] {key} = {engine.settings.get(key)}")


@config_app.command("reset")
def config_reset(key: str = typer.Argument(...)) -> None:
    """Restore a setting to its default."""
    engine = get_engine()
    engine.db.delete_setting(key)
    console.print(f"[green]Reset[/green] {key} to {engine.settings.get(key)}")


@app.command()
def web(
    port: int = typer.Option(8765, "--port", "-p", help="Port to listen on."),
    host: str = typer.Option("127.0.0.1", "--host", help="Loopback addresses only."),
    open_browser: bool = typer.Option(
        True, "--open/--no-open", help="Open the dashboard in your browser."
    ),
) -> None:
    """Launch the local dashboard on the loopback interface."""
    engine = get_engine()
    try:
        from ..web.server import serve
    except ImportError as exc:  # pragma: no cover - only when deps are missing
        fail(
            "The dashboard needs fastapi, uvicorn and jinja2. Reinstall with "
            f"'pip install -e .' to pull them in. ({exc})"
        )
        return

    console.print(
        Panel(
            "The dashboard binds to the loopback interface only and requires the session "
            "token in the link below. It drives the same engine as this CLI - scope, "
            "budgets, redaction and the activity log all apply exactly as they do here.",
            title="Starting the dashboard",
            border_style="cyan",
        )
    )
    try:
        serve(engine, host=host, port=port, open_browser=open_browser)
    except RHPError as exc:
        fail(str(exc), code=2)
    except OSError as exc:
        fail(f"Could not listen on {host}:{port} ({exc}). Try another port with --port.")


@app.command()
def version() -> None:
    """Print the version."""
    console.print(f"{APP_NAME} {__version__}")


def entrypoint() -> None:  # pragma: no cover - console-script wrapper
    try:
        app()
    except RHPError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    entrypoint()
