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

import errno
import os
import select
import signal
import subprocess
import time
from pathlib import Path
from uuid import uuid4

from stinger.adapters.base import AgentRun, Budget
from stinger.adapters.credential_broker import (
    CredentialBrokerContainmentError,
    CredentialBrokerError,
    CredentialBrokerSession,
)
from stinger.benchmark.credential_broker import agent_environment_names, provider_route
from stinger.config import AgentConfig
from stinger.docker_runtime import (
    DockerRuntimeError,
    DockerRuntimeIdentity,
    active_docker_runtime,
    docker_environment,
    terminate_docker_container,
)
from stinger.harness.sandbox import docker_argv

__all__ = [
    "CREDENTIAL_MOUNT_PATH",
    "AgentContainmentError",
    "AdapterSettingsError",
    "CliAgentAdapter",
    "CliCapture",
    "last_paragraph",
]

CREDENTIAL_MOUNT_PATH = "/credentials"
"""Where `AgentConfig.credential_mount` appears inside the agent container, always."""

_READ_CHUNK = 65536
_POLL_INTERVAL_S = 0.2
_REAP_TIMEOUT_S = 10


class AdapterSettingsError(Exception):
    """Raised when declared inference settings cannot be applied by an adapter."""


class AgentContainmentError(RuntimeError):
    """Raised when a live agent container may still be running after an abnormal exit."""


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

    def version_argv(self) -> list[str]:
        """Return the non-network CLI version probe for runtime provenance."""
        raise AssertionError(f"{type(self).__name__} must implement version_argv()")

    def settings_argv(self) -> list[str]:
        """Translate declared reasoning/inference settings into actual CLI arguments.

        Adapters inherit a fail-closed implementation. A concrete adapter may override this
        only when its CLI has a real, testable representation for the settings.
        """
        if self.config.reasoning_effort is not None or self.config.inference_settings:
            raise AdapterSettingsError(
                f"adapter {self.name!r} cannot apply declared reasoning/inference settings; "
                "use a supported adapter or a shell wrapper with explicit placeholders"
            )
        return []

    def resolved_invocation_template(self) -> tuple[str, ...]:
        """Return the exact inner argv with a non-secret prompt placeholder."""
        return tuple(self.argv("{prompt}"))

    def resolved_environment_names(self) -> tuple[str, ...]:
        """Return environment names forwarded to the agent, never their secret values."""
        if self.config.credential_broker is not None:
            route = provider_route(self.config.adapter, self.config.provider)
            return agent_environment_names(route)
        return tuple(self._container_env_names())

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
        broker_session: CredentialBrokerSession | None = None
        if self.config.credential_broker is None:
            try:
                env = self.environment()
            except KeyError as exc:
                return self._failed(f"required environment variable {exc.args[0]!r} is not set")
        else:
            # The raw value named by api_key_env belongs to the external broker only. It must
            # never be placed in the agent subprocess environment, even transiently.
            env = {}

        try:
            argv = self.argv(prompt)
        except AdapterSettingsError as exc:
            return self._failed(str(exc))
        inner_argv = tuple(argv)
        container_name: str | None = None
        container_runtime: DockerRuntimeIdentity | None = None
        if self.config.container_image is not None:
            container_runtime = active_docker_runtime()
            if container_runtime is None:
                return self._failed("contained agent runtime has not passed fixed Docker preflight")
            container_name = f"stinger-agent-{uuid4().hex[:12]}"
            network_name: str | None = None
            agent_image = self.config.container_image
            if self.config.credential_broker is not None:
                try:
                    broker_session = CredentialBrokerSession(
                        self.config,
                        runtime=container_runtime,
                    )
                    broker_session.verify_agent_inputs(
                        workdir=workdir,
                        expected_command=inner_argv,
                    )
                    broker_session.start()
                    env = broker_session.agent_environment()
                    forwarded_names = list(broker_session.agent_environment_names)
                    network_name = broker_session.network_name
                    agent_image = broker_session.agent_image_id
                except CredentialBrokerContainmentError as exc:
                    raise AgentContainmentError(str(exc)) from exc
                except CredentialBrokerError as exc:
                    return self._failed(f"credential isolation failed closed: {exc}")
            else:
                forwarded_names = self._container_env_names()
            # A legacy contained run reaches its provider directly. A Protocol 2 run instead
            # joins only the fresh Docker-internal network owned by its broker session.
            try:
                argv = docker_argv(
                    agent_image,
                    workdir,
                    argv,
                    network=broker_session is None,
                    network_name=network_name,
                    auto_remove=broker_session is None,
                    hardened_network_client=broker_session is not None,
                    forward_env=forwarded_names,
                    read_only_mounts=(
                        {} if broker_session is not None else self._credential_mounts()
                    ),
                    name=container_name,
                    runtime=container_runtime,
                )
                env = docker_environment(env, forwarded_names=forwarded_names)
            except BaseException as exc:
                self._cleanup_failed_launch(
                    broker_session,
                    container_name,
                    container_runtime,
                    context="agent Docker environment construction failed",
                )
                if isinstance(exc, DockerRuntimeError):
                    return self._failed(f"fixed Docker runtime is unavailable: {exc}")
                raise

        try:
            capture = self._capture(argv, workdir, env, budget.max_seconds)
        except FileNotFoundError:
            self._cleanup_failed_launch(
                broker_session,
                container_name,
                container_runtime,
                context="agent launch failed",
            )
            return self._failed(f"agent executable not found: {argv[0]!r}")
        except OSError as exc:
            self._cleanup_failed_launch(
                broker_session,
                container_name,
                container_runtime,
                context="agent launch failed",
            )
            return self._failed(f"could not launch {argv[0]!r}: {exc}")
        except BaseException:
            self._cleanup_failed_launch(
                broker_session,
                container_name,
                container_runtime,
                context="agent execution was interrupted",
            )
            raise

        if broker_session is not None:
            if capture.timed_out:
                try:
                    broker_session.abort(agent_container_name=container_name)
                except CredentialBrokerContainmentError as exc:
                    raise AgentContainmentError(str(exc)) from exc
                run = self.parse(capture)
                return run.model_copy(
                    update={
                        "exit_ok": False,
                        "error": (
                            f"the agent exceeded its budget of {budget.max_seconds}s and its "
                            "container and external credential broker were stopped; the partial "
                            "transcript is kept as evidence"
                        ),
                    }
                )
            try:
                if container_name is None:
                    raise CredentialBrokerError("agent container name is missing")
                evidence = broker_session.finish(
                    agent_container_name=container_name,
                    agent_image=broker_session.agent_image_id,
                    workdir=workdir,
                    transcript=capture.transcript,
                    exit_code=capture.exit_code,
                    expected_command=inner_argv,
                )
            except CredentialBrokerContainmentError as exc:
                raise AgentContainmentError(str(exc)) from exc
            except CredentialBrokerError as exc:
                run = self.parse(capture)
                return run.model_copy(
                    update={
                        "exit_ok": False,
                        "error": f"credential isolation failed closed: {exc}",
                    }
                )
            return self.parse(capture).model_copy(update={"credential_isolation": evidence})

        if capture.timed_out or capture.exit_code != 0:
            # A timeout kills only the local Docker client, while a nonzero or negative
            # client completion can mean the client crashed after asking the daemon to
            # start the credentialed network container. Do not parse or retain that output
            # as ordinary run evidence until exact-name absence has been proved.
            _require_agent_container_absent(
                container_name,
                container_runtime,
                context=(
                    "agent exceeded its budget"
                    if capture.timed_out
                    else "agent Docker client ended abnormally"
                ),
            )

        if capture.timed_out:
            stopped = "its container was stopped" if container_name is not None else "it was killed"
            run = self.parse(capture)
            return run.model_copy(
                update={
                    "exit_ok": False,
                    "error": (
                        f"the agent exceeded its budget of {budget.max_seconds}s and "
                        f"{stopped}; the partial transcript is kept as evidence"
                    ),
                }
            )
        return self.parse(capture)

    def _cleanup_failed_launch(
        self,
        broker_session: CredentialBrokerSession | None,
        container_name: str | None,
        runtime: DockerRuntimeIdentity | None,
        *,
        context: str,
    ) -> None:
        """Prove either the broker topology or a legacy agent container absent."""
        if broker_session is not None:
            try:
                broker_session.abort(agent_container_name=container_name)
            except CredentialBrokerContainmentError as exc:
                raise AgentContainmentError(str(exc)) from exc
            return
        _require_agent_container_absent(container_name, runtime, context=context)

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
        if self.config.credential_broker is not None:
            raise CredentialBrokerError(
                "raw provider credentials may be loaded only by the external broker"
            )
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
        if self.config.credential_broker is not None:
            return list(self.resolved_environment_names())
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


def _require_agent_container_absent(
    name: str | None,
    runtime: DockerRuntimeIdentity | None,
    *,
    context: str,
) -> None:
    """Prove an abnormally ended contained invocation left no live container."""
    if name is None:
        return
    assert runtime is not None
    try:
        terminate_docker_container(
            name,
            runtime=runtime,
            timeout=30,
        )
    except DockerRuntimeError:
        raise AgentContainmentError(
            f"{context} and container termination could not be verified; "
            "aborting contained execution"
        ) from None


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
        process: subprocess.Popen[str] = subprocess.Popen(
            argv,
            cwd=workdir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError:
        raise
    timed_out = False
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            stdout, stderr = _terminate_and_collect_plain_process_group(process)
    except BaseException:
        _terminate_and_reap_local_process_group(
            process,
            terminate_immediately=True,
        )
        raise
    _kill_local_process_group(process)
    if process.returncode is None:  # pragma: no cover - communicate plus cleanup sets it
        raise AgentContainmentError("local agent subprocess did not produce an exit status")
    return CliCapture(
        stdout,
        stderr,
        exit_code=124 if timed_out else process.returncode,
        timed_out=timed_out,
    )


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
    capture_completed = False
    try:
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            readable, _, _ = select.select([master], [], [], _POLL_INTERVAL_S)
            if readable:
                try:
                    data = os.read(master, _READ_CHUNK)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break  # the child closed the terminal; EIO is normal on Linux
                    raise
                if not data:
                    break
                chunks.append(data)
            elif process.poll() is not None:
                break
        capture_completed = True
    finally:
        try:
            os.close(master)
        finally:
            _terminate_and_reap_local_process_group(
                process,
                terminate_immediately=timed_out or not capture_completed,
            )

    output = b"".join(chunks).decode("utf-8", errors="replace")
    exit_code = 124 if timed_out else (process.returncode if process.returncode is not None else 1)
    return CliCapture(output, "", exit_code, timed_out=timed_out)


def _terminate_and_reap_local_process_group(
    process: subprocess.Popen[bytes] | subprocess.Popen[str],
    *,
    terminate_immediately: bool,
) -> None:
    """Bound and reap a host PTY process group after normal or abnormal capture.

    Interrupts and I/O failures can escape from the PTY loop as ``BaseException``. The
    process was started in a new session, so killing only its leader would let shell-spawned
    descendants survive Stinger. Abnormal paths terminate the group immediately. Normal PTY
    EOF gives the leader one bounded interval to flush file changes, then terminates anything
    it left behind. A second bounded wait is required because signalling without waiting can
    leave a zombie and is not proof that cleanup completed.
    """
    if terminate_immediately:
        _kill_local_process_group(process)
    try:
        process.wait(timeout=_REAP_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        _kill_local_process_group(process)
        try:
            process.wait(timeout=_REAP_TIMEOUT_S)
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - unkillable OS child
            raise AgentContainmentError(
                "local agent process group could not be reaped after termination"
            ) from exc
    else:
        # A well-behaved leader may briefly continue after closing its PTY while it flushes
        # file changes. Once it exits, terminate anything it left behind in the private
        # session so a background descendant cannot outlive the invocation.
        if not terminate_immediately:
            _kill_local_process_group(process)


def _kill_local_process_group(
    process: subprocess.Popen[bytes] | subprocess.Popen[str],
) -> None:
    """Send an uncatchable signal to the private session created for one PTY run."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin can report EPERM during the narrow transition where the session leader
        # has exited but Popen has not reaped it yet. Re-polling distinguishes that benign
        # no-group state from a live group Stinger could not terminate.
        if process.poll() is None:
            raise AgentContainmentError(
                "local agent process group could not be terminated"
            ) from None


def _terminate_and_collect_plain_process_group(
    process: subprocess.Popen[str],
) -> tuple[str, str]:
    """Terminate a timed-out pipe-backed run, collect partial output, and reap it."""
    _kill_local_process_group(process)
    try:
        return process.communicate(timeout=_REAP_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        _kill_local_process_group(process)
        try:
            return process.communicate(timeout=_REAP_TIMEOUT_S)
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - unkillable OS child
            raise AgentContainmentError(
                "local agent process group could not be reaped after termination"
            ) from exc


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
