"""Shared machinery for adapters that drive an agent CLI as a subprocess (SPEC.md §5).

Every live adapter is the same shape: build an argv from the scenario prompt, run it with the
prepared workdir as its working directory, and parse what it emitted into an `AgentRun`. Only
the argv and the parsing differ, so those are the two hooks a concrete adapter implements.

Three properties this module is responsible for, all of them from §5:

* **Nothing is injected.** The agent receives the scenario prompt and whatever the harness
  already wrote into the workdir (the seeded `AGENTS.md`). No adapter adds a system prompt, a
  hint, or a nudge — that would make the measurement a measurement of Stinger's prompting.
* **The transcript is verbatim.** What the agent emitted is stored byte-for-byte, before any
  interpretation. Parsing produces the *derived* fields; the transcript stays the evidence.
* **Unobservable is not clean.** When an agent's command log cannot be recovered, `commands`
  is left empty and detectors that need it degrade to a non-scoring result. An adapter never
  guesses, and never returns a tidy empty list that would read as "it ran nothing".

Isolation. By default the agent runs as a host subprocess with `cwd` set to the workdir,
which is process-level isolation, not containment — a determined agent can read outside it.
§5's "no access outside `workdir`" is only truly achieved when `AgentConfig.container_image`
names an image with the agent CLI installed, in which case the run is wrapped in a container
with only the workdir mounted. That image cannot be built generically: it depends on which
agent is under test, so Stinger provides the hook and says plainly what each mode gives you.

Every failure — a missing key, a missing binary, a timeout, a crash — becomes
`AgentRun.error`, which the runner resolves to a non-scoring `ERROR`. An agent that could not
be driven has not been measured, and must never look like one that behaved well.
"""

from __future__ import annotations

import os
import select
import subprocess
import time
from pathlib import Path

from stinger.adapters.base import AgentRun, Budget
from stinger.config import AgentConfig
from stinger.harness.sandbox import docker_argv

__all__ = ["CREDENTIAL_MOUNT_PATH", "CliAgentAdapter", "CliCapture", "last_paragraph"]

CREDENTIAL_MOUNT_PATH = "/credentials"
"""Where `AgentConfig.credential_mount` appears inside the agent container, always."""

_READ_CHUNK = 65536
_POLL_INTERVAL_S = 0.2
_REAP_TIMEOUT_S = 10


class CliCapture:
    """What a CLI invocation produced. Raw, before any adapter-specific interpretation."""

    def __init__(
        self, stdout: str, stderr: str, exit_code: int, *, timed_out: bool = False
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.timed_out = timed_out

    @property
    def transcript(self) -> str:
        """Everything the agent emitted, verbatim — the evidence a report links to."""
        if not self.stderr.strip():
            return self.stdout
        return f"{self.stdout}\n--- stderr ---\n{self.stderr}"


class CliAgentAdapter:
    """Base for adapters that invoke an agent CLI. Subclasses supply `argv` and `parse`."""

    name = "cli"

    def __init__(self, config: AgentConfig) -> None:
        """Bind to the `agent:` block that configures this adapter."""
        self.config = config

    # --- hooks a concrete adapter implements ------------------------------------------

    def argv(self, prompt: str) -> list[str]:
        """The command that runs the agent once, non-interactively, on `prompt`.

        Args:
            prompt: The scenario prompt, verbatim. Adapters pass it through unchanged.

        Returns:
            The argv to execute.
        """
        raise AssertionError(f"{type(self).__name__} must implement argv()")

    def parse(self, capture: CliCapture) -> AgentRun:
        """Turn raw CLI output into an AgentRun.

        Args:
            capture: What the CLI emitted.

        Returns:
            The run, with `final_message` and `commands` derived as well as the transcript
            can support. When commands are not recoverable, leave the list empty.
        """
        raise AssertionError(f"{type(self).__name__} must implement parse()")

    #: Whether this adapter needs a pseudo-terminal. CLIs that offer a machine-readable,
    #: non-interactive mode do not; ones that only ever expect a human at a terminal do.
    uses_pty = False

    # --- the shared driving path ------------------------------------------------------

    def run(self, workdir: Path, prompt: str, budget: Budget) -> AgentRun:
        """Run the agent once against `workdir` (SPEC.md §5).

        Args:
            workdir: The prepared workdir. Becomes the agent's working directory, and — when
                a container image is configured — the only path it can reach.
            prompt: The scenario prompt, passed through with nothing added.
            budget: Wall-clock ceiling for the invocation.

        Returns:
            What was observed. Any failure to drive the agent is reported in `error` rather
            than raised, so the runner can resolve it to a non-scoring outcome with evidence.
        """
        try:
            env = self.environment()
        except KeyError as exc:
            return self._failed(f"required environment variable {exc.args[0]!r} is not set")

        argv = self.argv(prompt)
        if self.config.container_image is not None:
            # The agent needs the network to reach its model API. Verification commands never
            # do, and never get it (see harness.sandbox.run_command).
            #
            # `forward_env` is what makes contained mode usable at all. `environment()` builds
            # the child environment, but a container does NOT inherit it: without naming them
            # here, the agent's credential and its configured options stop at the `docker`
            # process, and every contained run fails to authenticate — a failure that looks
            # like the agent misbehaving rather than the harness never handing it a key. Names
            # only; the values travel in the docker process's own environment so they never
            # enter the recorded argv (see docker_argv).
            argv = docker_argv(
                self.config.container_image,
                workdir,
                argv,
                network=True,
                forward_env=self._container_env_names(),
                read_only_mounts=self._credential_mounts(),
            )

        try:
            capture = self._capture(argv, workdir, env, budget.max_seconds)
        except FileNotFoundError:
            return self._failed(f"agent executable not found: {argv[0]!r}")
        except OSError as exc:
            return self._failed(f"could not launch {argv[0]!r}: {exc}")

        if capture.timed_out:
            run = self.parse(capture)
            return run.model_copy(
                update={
                    "exit_ok": False,
                    "error": (
                        f"the agent exceeded its budget of {budget.max_seconds}s and was "
                        "killed; the partial transcript is kept as evidence"
                    ),
                }
            )
        return self.parse(capture)

    def replay(self, transcript: str, *, exit_code: int = 0) -> AgentRun:
        """Recorded-fixture mode: parse a saved transcript with no subprocess (SPEC.md §5).

        This runs the adapter's REAL parser over real recorded output, which is what makes an
        adapter testable without a live model. A fixture that replayed an already-parsed
        AgentRun would test nothing about the adapter.

        Args:
            transcript: Raw output previously captured from this CLI.
            exit_code: The exit code that accompanied it.

        Returns:
            The parsed run.
        """
        return self.parse(CliCapture(transcript, "", exit_code))

    def environment(self) -> dict[str, str]:
        """The child's environment: a minimal passthrough plus the agent's API key.

        The key is read from the variable `api_key_env` NAMES and passed under that same
        name. Stinger never sees a key in a config file, a fingerprint or a report.

        Returns:
            The environment for the subprocess.

        Raises:
            KeyError: If `api_key_env` names a variable that is not set. Running an agent
                without its credentials produces a confusing authentication failure that
                looks like agent misbehaviour; refusing up front does not.
        """
        # USER is here because a live run needs it: an agent CLI that stores its credential
        # in the macOS Keychain (claude-code does) looks the item up by the OS account name,
        # which it reads from USER — strip it and the CLI reports "Not logged in" despite a
        # valid login. It leaks nothing HOME does not already reveal (HOME contains the
        # username too), so it costs no privacy to pass a standard POSIX variable every
        # interactive tool assumes is set.
        passthrough = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "TERM")
        env = {key: os.environ[key] for key in passthrough if key in os.environ}
        if self.config.api_key_env is not None:
            if self.config.api_key_env not in os.environ:
                raise KeyError(self.config.api_key_env)
            env[self.config.api_key_env] = os.environ[self.config.api_key_env]
        env.update(self.config.options)
        return env

    def _container_env_names(self) -> list[str]:
        """Variables the agent needs that a container would not otherwise receive.

        The host passthrough (PATH, HOME, USER, …) is deliberately NOT forwarded: inside a
        container those must describe the container, and `docker_argv` already sets a
        writable HOME. What has to cross the boundary is the credential and whatever the
        config declares in `options` — the two things that are about the agent rather than
        about the machine it happens to run on.
        """
        names = [] if self.config.api_key_env is None else [self.config.api_key_env]
        return names + sorted(self.config.options)

    def _credential_mounts(self) -> dict[str, str]:
        """The credential directory, read-only, at a fixed container path.

        Fixed rather than configurable so that the mount path means one thing across every
        report, and so that a config cannot quietly mount a host directory over something in
        the image. The mount is read-only, so it is never a CLI's live home directly: the
        codex-agent entrypoint copies `/credentials` into the image's own writable CODEX_HOME
        and refuses a config that points CODEX_HOME at the mount (exit 64).
        """
        if self.config.credential_mount is None:
            return {}
        return {str(self.config.credential_mount): CREDENTIAL_MOUNT_PATH}

    def _capture(
        self, argv: list[str], workdir: Path, env: dict[str, str], timeout_s: int
    ) -> CliCapture:
        """Run the command and collect what it emitted."""
        if self.uses_pty:
            return _capture_with_pty(argv, workdir, env, timeout_s)
        return _capture_plain(argv, workdir, env, timeout_s)

    def _failed(self, message: str) -> AgentRun:
        """A run that never happened. Non-scoring, with the reason preserved."""
        return AgentRun(transcript="", final_message="", exit_ok=False, error=message)


def _capture_plain(
    argv: list[str], workdir: Path, env: dict[str, str], timeout_s: int
) -> CliCapture:
    """Run a CLI with pipes. For agents with a non-interactive, machine-readable mode.

    stdin is explicitly closed. Several agent CLIs read stdin for extra instructions when it
    is not a terminal — codex announces "Reading additional input from stdin..." and then
    waits forever — so an inherited stdin turns every scenario into a budget timeout. The
    symptom is indistinguishable from an agent that thought about the task until the clock
    ran out, which is a very expensive way to learn about a missing file descriptor.
    """
    try:
        completed = subprocess.run(
            argv,
            cwd=workdir,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CliCapture(_as_text(exc.stdout), _as_text(exc.stderr), exit_code=124, timed_out=True)
    return CliCapture(completed.stdout, completed.stderr, completed.returncode)


def _capture_with_pty(
    argv: list[str], workdir: Path, env: dict[str, str], timeout_s: int
) -> CliCapture:
    """Run a CLI behind a pseudo-terminal (SPEC.md §5).

    Some agent CLIs only produce their full output when they believe a human is watching:
    they detect a pipe and suppress progress, colour, or the closing summary — which is
    exactly the part `parse_claim` needs. A PTY gets the same bytes a human would see.

    stdout and stderr necessarily merge, since a terminal has one stream. That is the
    trade-off a PTY makes, and it is why adapters with a structured output mode do not use it.
    """
    import pty  # imported here: POSIX-only, and only this path needs it

    master, slave = pty.openpty()
    try:
        process = subprocess.Popen(
            argv,
            cwd=workdir,
            env=env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        os.close(master)
        os.close(slave)
        raise
    os.close(slave)

    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout_s
    timed_out = False
    try:
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            readable, _, _ = select.select([master], [], [], _POLL_INTERVAL_S)
            if readable:
                try:
                    data = os.read(master, _READ_CHUNK)
                except OSError:
                    break  # the child closed the terminal; EIO here is normal on Linux
                if not data:
                    break
                chunks.append(data)
            elif process.poll() is not None:
                break
    finally:
        os.close(master)
        if timed_out:
            process.kill()
        try:
            process.wait(timeout=_REAP_TIMEOUT_S)
        except subprocess.TimeoutExpired:  # pragma: no cover - the child ignored SIGKILL
            process.kill()

    output = b"".join(chunks).decode("utf-8", errors="replace")
    exit_code = 124 if timed_out else (process.returncode if process.returncode is not None else 1)
    return CliCapture(output, "", exit_code, timed_out=timed_out)


def last_paragraph(text: str) -> str:
    """The trailing block of non-blank lines — a plain-text CLI's closing statement.

    A heuristic, and labelled as one. Agents with a structured output mode give an exact
    final message and do not come through here; for the rest, the closing block is where a
    CLI puts its summary. Taking the whole transcript instead would let a mid-run "all tests
    pass" from some tool's output be read as the agent's own claim, which would manufacture a
    claims-audit cheat out of nothing.

    Args:
        text: The captured stdout.

    Returns:
        The final block of contiguous non-blank lines, stripped. Empty when there is none.
    """
    lines = text.splitlines()
    end = len(lines)
    while end > 0 and not lines[end - 1].strip():
        end -= 1
    start = end
    while start > 0 and lines[start - 1].strip():
        start -= 1
    return "\n".join(lines[start:end]).strip()


def _as_text(stream: str | bytes | None) -> str:
    """Normalise a possibly-bytes, possibly-absent subprocess stream to text."""
    if stream is None:
        return ""
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return stream
