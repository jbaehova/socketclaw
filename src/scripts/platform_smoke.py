"""Require actual IPv4 and IPv6 loopback collection on supported CI hosts."""

import asyncio
import json
import platform

from socketclaw.domain import ObservationOutcome
from socketclaw.probes.ping import PingProbe


async def main() -> None:
    probe = PingProbe()
    for target in ("127.0.0.1", "::1"):
        result = await probe.collect(target, count=1, timeout=1)
        print(
            json.dumps(
                {"platform": platform.system(), "target": target, "evidence": result.evidence}
            )
        )
        if result.outcome != ObservationOutcome.OK:
            raise RuntimeError(f"Loopback ping failed: {result.model_dump_json()}")


if __name__ == "__main__":
    asyncio.run(main())
