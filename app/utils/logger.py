import logging


class Logger:
    def __init__(self, name: str = "Main"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(levelname)s : %(asctime)s | %(name)s  | %(message)s"
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def info(self, message, **kwargs):
        """Log info message with optional parameters"""
        self.logger.info(message, **kwargs)

    def error(self, message, **kwargs):
        """Log error message with optional parameters like exc_info"""
        self.logger.error(message, **kwargs)

    def debug(self, message, **kwargs):
        """Log debug message with optional parameters"""
        self.logger.debug(message, **kwargs)

    def warning(self, message, **kwargs):
        """Log warning message with optional parameters"""
        self.logger.warning(message, **kwargs)

    def critical(self, message, **kwargs):
        """Log critical message with optional parameters"""
        self.logger.critical(message, **kwargs)

    def exception(self, message, **kwargs):
        """Log exception with automatic exc_info=True"""
        self.logger.exception(message, **kwargs)
