from enum import Enum


class ErrorCode(str, Enum):
    # Blacklist
    BLACKLIST_ENTRY_NOT_FOUND    = "BLACKLIST_ENTRY_NOT_FOUND"
    BLACKLIST_ENTRY_ALREADY_EXISTS = "BLACKLIST_ENTRY_ALREADY_EXISTS"

    # Reports
    REPORT_NOT_FOUND             = "REPORT_NOT_FOUND"
    REPORT_ALREADY_REVIEWED      = "REPORT_ALREADY_REVIEWED"
    REVIEW_MISSING_FIELDS        = "REVIEW_MISSING_FIELDS"

    # Scan
    INVALID_URL_TARGET           = "INVALID_URL_TARGET"

    # Auth
    UNAUTHORIZED                 = "UNAUTHORIZED"
    FORBIDDEN                    = "FORBIDDEN"
    INVALID_CREDENTIALS          = "INVALID_CREDENTIALS"

    # Validation
    VALIDATION_ERROR             = "VALIDATION_ERROR"

    # Rate limiting
    RATE_LIMIT_EXCEEDED          = "RATE_LIMIT_EXCEEDED"

    # Generic
    NOT_FOUND                    = "NOT_FOUND"
    INTERNAL_ERROR               = "INTERNAL_ERROR"