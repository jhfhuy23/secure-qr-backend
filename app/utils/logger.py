import logging
import sys
from contextvars import ContextVar

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True


handler = logging.StreamHandler(sys.stdout)
handler.addFilter(RequestIdFilter())

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s req_id=%(request_id)s %(message)s",
    handlers=[handler],
)

logger = logging.getLogger("secure_qr")