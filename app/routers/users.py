from fastapi import APIRouter, HTTPException, Request
from app.models import UserConfig

router = APIRouter(prefix="/s3-access", tags=["User Operations"])


def service(request: Request):
    return request.app.state.user_service


@router.post("/add-user", summary="Add User", description="Ensure the IAM user exists and assign it to the selected team's IAM group.")
def add_user(body: UserConfig, request: Request):
    try:
        return service(request).add_or_update(body)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        message = str(exc)
        status = 403 if "AccessDenied" in message or "403" in message else 502
        raise HTTPException(status_code=status, detail=message)


@router.put("/update-user", summary="Update User", description="Change the team IAM group assigned to this user.")
def update_user(body: UserConfig, request: Request):
    try:
        return service(request).add_or_update(body, require_existing=True)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        message = str(exc)
        status = 403 if "AccessDenied" in message or "403" in message else 502
        raise HTTPException(status_code=status, detail=message)


@router.get("/get-user/{username}", summary="Get User")
def get_user(username: str, request: Request):
    record = service(request).get_user(username)
    if not record:
        raise HTTPException(status_code=404, detail="User assignment not found")
    return record


@router.get("/list-users", summary="List Users")
def list_users(request: Request):
    return {"users": service(request).list_users()}


@router.delete("/remove-user/{username}", summary="Remove User")
def remove_user(username: str, request: Request):
    try:
        return service(request).remove_user(username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
