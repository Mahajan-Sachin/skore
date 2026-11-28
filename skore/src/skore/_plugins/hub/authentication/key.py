"""Manage API keys used to authenticate with ``skore hub``."""

from __future__ import annotations

from collections.abc import Generator
from typing import Literal

from skore._plugins.hub.authentication import registry
from skore._plugins.hub.authentication.host import ensure_host_is_valid


class KeyExistsError(Exception):
    """Raised when an API key already exists for a host and workspace."""


def keys() -> Generator[tuple[int, str, str]]:
    """Yield ``(id, host, workspace)`` keys stored in the local registry."""
    yield from registry.local.keys()


@ensure_host_is_valid
def generate(
    *,
    host: str | None = None,
    workspace: str,
    name: str | None = None,
    expires: Literal["1", "3", "6", "never"] = "never",
    timeout: int = 600,
    force: bool = False,
    aliases: list[str] | None = None,
) -> None:
    """
    Generate an API key on the hub and store it in the local registry.

    Parameters
    ----------
    host : str or None, default=None
        Hub backend URI. If omitted, ``SKORE_HUB_URI`` is used.
    workspace : str
        Workspace the API key is scoped to.
    name : str or None, default=None
        Name of the API key. A random name is used when omitted.
    expires : {"1", "3", "6", "never"}, default="never"
        Lifetime of the API key, in months, or ``"never"``.
    timeout : int, default=600
        Seconds to wait for interactive authentication.
    force : bool, default=False
        Replace an existing key for the same host and workspace.
    aliases : list of str, optional
        Alternative URIs (such as frontend hosts) associated with the API key.

    Raises
    ------
    KeyExistsError
        A key already exists and ``force`` is false.
    PermissionError
        The user cannot create a key for ``workspace``.
    ValueError
        ``host`` was omitted and ``SKORE_HUB_URI`` is unset.
    """
    assert host is not None

    existing_aliases: list[str] = []
    if old := registry.local.get(host=host, workspace=workspace):
        if not force:
            raise KeyExistsError(
                f"An API key for host:{host!r} and workspace:{workspace!r} already "
                "exists; use force option to overwrite it."
            )

        existing_aliases = old.aliases
        registry.local.delete(host=host, workspace=workspace)
        registry.distant.revoke(host=host, id=old.id, timeout=timeout)

    new = registry.distant.generate(
        host=host,
        workspace=workspace,
        name=name,
        expires=expires,
        timeout=timeout,
    )

    combined_aliases = list(dict.fromkeys((aliases or []) + existing_aliases))
    registry.local.set(
        id=new.id,
        host=host,
        workspace=workspace,
        key=new.key,
        aliases=combined_aliases if combined_aliases else None,
    )


@ensure_host_is_valid
def add_alias(*, host: str | None = None, workspace: str, alias: str) -> None:
    """
    Associate an alias with an existing API key.

    Parameters
    ----------
    host : str or None, default=None
        Hub backend URI. If omitted, ``SKORE_HUB_URI`` is used.
    workspace : str
        Workspace associated with the API key.
    alias : str
        Alternative URI to associate with the key.
    """
    assert host is not None
    registry.local.add_alias(host=host, workspace=workspace, alias=alias)


@ensure_host_is_valid
def get(*, host: str | None = None, workspace: str) -> str | None:
    """
    Return the API key for ``host`` and ``workspace``.

    Parameters
    ----------
    host : str or None, default=None
        Hub backend URI. If omitted, ``SKORE_HUB_URI`` is used.
    workspace : str
        Workspace associated with the API key.

    Returns
    -------
    str or None
        The API key, or ``None`` if none is stored.

    Raises
    ------
    ValueError
        ``host`` was omitted and ``SKORE_HUB_URI`` is unset.
    """
    assert host is not None

    return (
        (key := registry.local.get(host=host, workspace=workspace)) and key.key or None
    )


@ensure_host_is_valid
def revoke(*, host: str | None = None, workspace: str, timeout: int = 600) -> None:
    """
    Remove the API key from the local registry and revoke it.

    Parameters
    ----------
    host : str or None, default=None
        Hub backend URI. If omitted, ``SKORE_HUB_URI`` is used.
    workspace : str
        Workspace associated with the API key.
    timeout : int, default=600
        Seconds to wait for interactive authentication.

    Raises
    ------
    ValueError
        ``host`` was omitted and ``SKORE_HUB_URI`` is unset.
    """
    assert host is not None

    if key := registry.local.get(host=host, workspace=workspace):
        registry.local.delete(host=host, workspace=workspace)
        registry.distant.revoke(host=host, id=key.id, timeout=timeout)
