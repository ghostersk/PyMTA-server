from email_server import start_server, logger
import asyncio
import sys

if __name__ == '__main__':
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        logger.info('Server interrupted by user')
        sys.exit(0)
    except Exception as e:
        logger.error(f'Server error: {e}')
        sys.exit(1)