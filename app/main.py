import uuid
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.routers import scan, blacklist, report, statistics, admin, auth
from app.security.rate_limiter import limiter
from app.utils.logger import logger, request_id_var
from app.utils.error_codes import ErrorCode
from app.utils.api_error import AppException, build_error_response

app = FastAPI(
    title="Secure QR Scanner API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

#  Rate limiter 
app.state.limiter = limiter

#  CORS 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

#  Request ID + logging middleware 
@app.middleware("http")
async def log_requests(request: Request, call_next):
    req_id  = str(uuid.uuid4())[:8]
    token   = request_id_var.set(req_id)
    request.state.request_id = req_id

    start    = time.time()
    response = await call_next(request)
    duration = int((time.time() - start) * 1000)

    logger.info(
        f"method={request.method} path={request.url.path} "
        f"status={response.status_code} ms={duration} "
        f"ip={request.client.host}"
    )
    request_id_var.reset(token)
    return response


#  Exception handlers 

@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException):
    req_id = getattr(request.state, "request_id", "-")
    return JSONResponse(
        status_code=exc.status_code,
        content=build_error_response(
            error_code=exc.error_code,
            message=exc.detail,
            field=exc.field,
            request_id=req_id,
        ),
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    req_id = getattr(request.state, "request_id", "-")
    return JSONResponse(
        status_code=429,
        content=build_error_response(
            error_code=ErrorCode.RATE_LIMIT_EXCEEDED,
            message="Too many requests. Please slow down.",
            request_id=req_id,
        ),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", "-")
    first  = exc.errors()[0]
    field  = ".".join(str(loc) for loc in first["loc"] if loc != "body")
    return JSONResponse(
        status_code=422,
        content=build_error_response(
            error_code=ErrorCode.VALIDATION_ERROR,
            message=first["msg"],
            field=field or None,
            request_id=req_id,
        ),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "-")
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content=build_error_response(
            error_code=ErrorCode.INTERNAL_ERROR,
            message="An unexpected error occurred.",
            request_id=req_id,
        ),
    )


#  Routers 
app.include_router(scan.router,       prefix="/api/v1", tags=["Scan"])
app.include_router(blacklist.router,  prefix="/api/v1", tags=["Blacklist"])
app.include_router(report.router,     prefix="/api/v1", tags=["Report"])
app.include_router(statistics.router, prefix="/api/v1", tags=["Statistics"])
app.include_router(admin.router,      prefix="/api/v1", tags=["Admin"])
app.include_router(auth.router,       prefix="/api/v1", tags=["Auth"])