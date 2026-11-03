"""FastAPI dependencies: shared app objects, one DB session per request, rate limiting."""

import math
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from scam_linker.api.ratelimit import SlidingWindowLimiter
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher
from scam_linker.linker.config import ScoringConfig


@dataclass
class AppContext:
    """Long-lived objects created once in create_app() and shared by all requests."""

    engine: Engine
    session_factory: sessionmaker[Session]
    fetcher: SafeFetcher
    dns: DnsClient
    scoring: ScoringConfig
    collect_limiter: SlidingWindowLimiter


def get_context(request: Request) -> AppContext:
    context: AppContext = request.app.state.context
    return context


Context = Annotated[AppContext, Depends(get_context)]


def get_session(context: Context) -> Iterator[Session]:
    """One session per request, always closed afterwards."""
    with context.session_factory() as session:
        yield session


DbSession = Annotated[Session, Depends(get_session)]


def limit_collection(request: Request, context: Context) -> None:
    """429 Too Many Requests if this client has triggered too many collections recently."""
    client = request.client.host if request.client else "unknown"
    retry_after = context.collect_limiter.check(client)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many collection requests; slow down.",
            headers={"Retry-After": str(math.ceil(retry_after))},
        )


RateLimited = Depends(limit_collection)
