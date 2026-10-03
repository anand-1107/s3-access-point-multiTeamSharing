from fastapi import APIRouter, HTTPException, Request
from app.models import AccessCheckRequest, AccessCheckResponse

router = APIRouter(prefix="/s3-access", tags=["Access Verification"])


@router.post(
    "/check-access",
    summary="Check Team/User Access",
    description="Evaluate whether an IAM user's configured team allows the requested prefix and operation. This is an application-level decision demo. It may perform read-only IAM and Access Point configuration lookups, but does not submit S3 data requests or simulate all AWS policy sources.",
    response_model=AccessCheckResponse,
    response_model_exclude_none=True,
)
def check_access(body: AccessCheckRequest, request: Request):
    try:
        return request.app.state.user_service.check_access(body)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        message = str(exc)
        status = 403 if "AccessDenied" in message or "403" in message else 502
        raise HTTPException(status_code=status, detail=message)
