# Rate Limiting — Integration Patch

`slowapi` is the standard FastAPI-compatible rate limiter (wraps `limits`).
It reads the client IP from the request and enforces per-route limits.

---

## 1. Add to `requirements.txt`

```
slowapi>=0.1.9
```

---

## 2. `main.py` — wire up the limiter

Add after the existing imports:

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
```

Create the limiter (uses client IP as key):

```python
limiter = Limiter(key_func=get_remote_address)
```

After `app = FastAPI(...)` and before middleware:

```python
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

---

## 3. `src/routes/auth.py` — decorate the two sensitive endpoints

Add at the top of the file with the other imports:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address
limiter = Limiter(key_func=get_remote_address)
```

Then decorate:

```python
@router.post("/login")
@limiter.limit("10/minute")
async def login(body: LoginRequest, response: Response, request: Request):
    ...

@router.post("/auth/create-account")
@limiter.limit("5/minute")
async def create_account(body: RegisterStep5Request, request: Request):
    ...
```

`request: Request` must be an explicit parameter (not just injected by
FastAPI) for slowapi to find it — check that both handlers already
have it. `login` does; add `request: Request` to `create_account` if
it doesn't have it yet.

---

## 4. What the limits map to in `config.py`

The settings already define:

```python
rate_limit_login: str = "10/minute"
rate_limit_register: str = "5/minute"
```

You can make the decorators read these dynamically:

```python
@limiter.limit(lambda: get_settings().rate_limit_login)
```

---

## 5. Optional — also rate-limit PoW and email endpoints

These are the first two steps of registration and are the cheapest
to spam:

```python
@router.post("/auth/pow")
@limiter.limit("20/minute")
async def init_pow(request: Request):
    ...

@router.post("/auth/submit-email")
@limiter.limit("5/minute")
async def submit_email(body: RegisterStep2Request, request: Request):
    ...
```
