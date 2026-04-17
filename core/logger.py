import logging
import os
import sys

def setup_logger(name, log_file="pentest_toolkit.log", level=logging.INFO):
    """
    Sets up a consolidated logger for the penetration testing tool.
    Logs to both console (stdout) and file.
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(level)

        # Create log formatters
        console_formatter = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s', datefmt='%H:%M:%S')
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] - %(message)s')

        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File Handler
        try:
            # ensure logs directory exists
            os.makedirs("logs", exist_ok=True)
            file_handler = logging.FileHandler(os.path.join("logs", log_file))
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Failed to setup file logging: {e}")

    return logger
