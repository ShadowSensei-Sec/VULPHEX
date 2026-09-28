"""Interactive shell for VULPHEX."""

from __future__ import annotations

import os
import shlex
from collections.abc import Callable, Sequence

from typer.main import get_command


BANNER = r"""
██╗   ██╗██╗   ██╗██╗     ██████╗ ██╗  ██╗███████╗██╗  ██╗
██║   ██║██║   ██║██║     ██╔══██╗██║  ██║██╔════╝╚██╗██╔╝
██║   ██║██║   ██║██║     ██████╔╝███████║█████╗   ╚███╔╝
╚██╗ ██╔╝██║   ██║██║     ██╔═══╝ ██╔══██║██╔══╝   ██╔██╗
 ╚████╔╝ ╚██████╔╝███████╗██║     ██║  ██║███████╗██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

                 Secure Beyond Endpoints
              API Security Assessment Tool
                         v1.0.0
"""


SHELL_COMMANDS = {
    "help": "Show VULPHEX command-line options.",
    "exit": "Exit the VULPHEX shell.",
    "quit": "Exit the VULPHEX shell.",
    "clear": "Clear the terminal.",
    "banner": "Display the VULPHEX banner.",
}


def print_banner() -> None:
    """Display the VULPHEX startup banner."""
    print(BANNER)


def clear_terminal() -> None:
    """Clear the terminal using the platform's native command."""
    os.system("cls" if os.name == "nt" else "clear")


def _execute_cli_command(
    app,
    arguments: Sequence[str],
) -> None:
    """
    Execute the existing VULPHEX CLI using the same option definitions
    as direct command-line execution.

    This intentionally does not duplicate any assessment logic.
    """
    command = get_command(app)

    command.main(
        args=list(arguments),
        prog_name="vulphex",
        standalone_mode=False,
    )


def _handle_shell_command(command: str) -> bool:
    """
    Handle a shell-only command.

    Returns True when the shell should continue.
    Returns False when the shell should exit.
    """
    if command in {"exit", "quit"}:
        return False

    if command == "clear":
        clear_terminal()
        return True

    if command == "banner":
        print_banner()
        return True

    return True


def run_shell(app) -> None:
    """
    Start the interactive VULPHEX shell.

    Every normal VULPHEX option is forwarded to the existing Typer CLI,
    so full option names and their short aliases behave identically to
    direct CLI execution.
    """
    print_banner()
    print("Type --help for options.")
    print("Type exit to quit.")
    print()

    while True:
        try:
            raw_command = input("vulphex > ")

        except EOFError:
            print()
            break

        except KeyboardInterrupt:
            print()
            continue

        command_line = raw_command.strip()

        if not command_line:
            continue

        command_name = command_line.lower()

        if command_name in SHELL_COMMANDS:
            if not _handle_shell_command(command_name):
                break
            continue

        try:
            arguments = shlex.split(command_line)

        except ValueError as exc:
            print(f"Error: invalid command syntax: {exc}")
            continue

        if not arguments:
            continue

        try:
            _execute_cli_command(app, arguments)

        except SystemExit:
            # Keep the interactive shell alive if a CLI command
            # requests process termination.
            continue

        except Exception as exc:
            # CLI/Click errors should not terminate the interactive shell.
            print(f"Error: {exc}")

        print()