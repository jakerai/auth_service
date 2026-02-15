class Logger:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_logger(*args, **kwargs)
        return cls._instance

    def _init_logger(self, name="auth_service_logger", log_file="logs/app.log"):
        import logging
        from logging.handlers import RotatingFileHandler
        import os
        from src.core.tracing import RequestIdFilter

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)

            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] [traceId=%(request_id)s] "
                "[%(filename)s:%(lineno)d %(funcName)s] %(message)s"
            )

            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            ch.setFormatter(formatter)
            ch.addFilter(RequestIdFilter())
            self.logger.addHandler(ch)

            fh = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=10)
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            fh.addFilter(RequestIdFilter())
            self.logger.addHandler(fh)

    def get_logger(self):
        return self.logger
