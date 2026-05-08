from __future__ import annotations

import asyncio
import logging

from .config import load_config_from_env
from .logging import configure_logging
from .smtp_server import SmtpProxyServer


async def main() -> None:
    config = load_config_from_env()
    configure_logging(config.log_level)
    server = SmtpProxyServer(config)
    await server.start()
    logging.getLogger(__name__).info(
        "SimpleLogin SMTP proxy listening on %s:%s dry_run=%s",
        config.host,
        server.port,
        config.dry_run,
    )
    await server.serve_forever()


def cli() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli()
