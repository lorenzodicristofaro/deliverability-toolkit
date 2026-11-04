"""Docker helpers for the unbound integration tests. Needs the docker CLI (compose + buildx)."""

from __future__ import annotations

import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UNBOUND_IP = "172.28.53.2"
UNBOUND_PORT = 5353


def run(*args: str, timeout: int = 240, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=REPO, capture_output=True, text=True, timeout=timeout, check=check
    )


@dataclass
class Answer:
    rcode: str
    flags: set[str]
    answers: list[tuple[str, str]]  # (type, rdata) of the answer section
    raw: str


def parse_drill(output: str) -> Answer:
    rcode = re.search(r"rcode: (\w+)", output)
    flags = re.search(r"^;; flags: ([a-z ]*);", output, re.M)
    if rcode is None or flags is None:
        raise ValueError(f"not a drill response:\n{output}")
    answers: list[tuple[str, str]] = []
    in_answer = False
    for line in output.splitlines():
        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
        elif line.startswith(";;"):
            in_answer = False
        elif in_answer and line.strip():
            parts = line.split("\t")
            if len(parts) >= 5:
                answers.append((parts[3], parts[4]))
    return Answer(rcode.group(1), set(flags.group(1).split()), answers, output)


def host_probe_is_unbound(output: str) -> bool:
    """True if drill output from a host-side probe looks like Unbound resolving for us.

    A host mDNS responder (avahi) may own 127.0.0.1:5353: it times out, answers garbage or
    refuses, none of which is Unbound. Only a NOERROR answer with RA (recursion available) and
    AD (validated) or answer records counts as a resolution by our resolver.
    """
    try:
        ans = parse_drill(output)
    except ValueError:
        return False  # timeout / not a DNS response
    return ans.rcode == "NOERROR" and "ra" in ans.flags and ("ad" in ans.flags or bool(ans.answers))


class Stack:
    """A throwaway compose project running the `unbound` profile (project name unique per run)."""

    def __init__(self) -> None:
        self.project = f"dtkit{os.getpid()}{uuid.uuid4().hex[:6]}"

    def compose(self, *args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
        return run(
            "docker", "compose", "-p", self.project, "--profile", "unbound", *args, timeout=timeout
        )

    def up(self) -> None:
        self.compose("up", "-d", "--build", "--wait", "--wait-timeout", "180", "unbound")

    def down(self, volumes: bool = False) -> None:
        args = ["down", "--remove-orphans"]
        if volumes:
            args += ["-v", "--rmi", "local"]
        self.compose(*args)

    @property
    def network(self) -> str:
        return f"{self.project}_dns"

    @property
    def container(self) -> str:
        return f"{self.project}-unbound-1"

    @property
    def image(self) -> str:
        return f"{self.project}-unbound"

    @property
    def volume(self) -> str:
        return f"{self.project}_unbound-data"

    def drill(
        self, *query: str, server: str = UNBOUND_IP, port: int = UNBOUND_PORT, network: str = ""
    ) -> Answer:
        """Run drill from a throwaway container (same image) on the given network (default dns)."""
        return parse_drill(self.drill_raw(*query, server=server, port=port, network=network))

    def drill_raw(
        self, *query: str, server: str = UNBOUND_IP, port: int = UNBOUND_PORT, network: str = ""
    ) -> str:
        proc = run(
            "docker",
            "run",
            "--rm",
            "--network",
            network or self.network,
            "--entrypoint",
            "drill",
            self.image,
            "-p",
            str(port),
            f"@{server}",
            *query,
            timeout=60,
            check=False,
        )
        return proc.stdout
