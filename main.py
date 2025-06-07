"""
    Starts the email server, no web UI!
"""
from email_server.server_runner import start_server
from email_server.tool_box import get_logger
import asyncio
import sys

logger = get_logger()

if __name__ == '__main__':
    try:
        logger.info('Server started')
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info('Server interrupted by user')
        sys.exit(0)
    except Exception as e:
        logger.error(f'Server error: {e}')
        sys.exit(1)