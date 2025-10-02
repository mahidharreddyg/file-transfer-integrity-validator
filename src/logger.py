import logging
import os

def get_logger(name="app"):
    os.makedirs("logs", exist_ok=True)
    log_file = os.path.join("logs", "app.log")

    logger = logging.getLogger(name)
    if not logger.hasHandlers():  # prevent duplicate handlers
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(fh)
    return logger
