"""Entry point for Venice X Bot."""
import logging
from config import Config
from bot import VeniceBot


def main():
    logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL), format=Config.LOG_FORMAT)
    try:
        Config.validate()
        VeniceBot().run()
    except ValueError as e:
        logging.critical(f"Config error: {e}")
    except Exception as e:
        logging.critical(f"Fatal: {e}", exc_info=True)


if __name__ == "__main__":
    main()
