# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""Tests for the ATTACHMENT_REQUIRE_EXTENSIONS / ATTACHMENT_ALLOW_EXTENSIONS
helpers.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from lambda_function import (
    attachment_extension,
    has_required_attachment,
    parse_extensions,
)


def test_parse_extensions_normalizes_case_and_dots() -> None:
    assert parse_extensions('XML, .TXT ,pdf') == {'xml', 'txt', 'pdf'}


def test_parse_extensions_empty_string_is_empty_set() -> None:
    assert parse_extensions('') == set()


def test_parse_extensions_ignores_blank_entries() -> None:
    assert parse_extensions('xml,, ,txt') == {'xml', 'txt'}


def test_attachment_extension_from_filename() -> None:
    assert (
        attachment_extension('invoice.XML', 'application/octet-stream')
        == 'xml'
    )


def test_attachment_extension_falls_back_to_content_type() -> None:
    assert attachment_extension(None, 'image/jpeg') == 'jpg'


def test_attachment_extension_unknown_content_type_is_empty() -> None:
    assert attachment_extension(None, 'application/x-does-not-exist') == ''


def test_has_required_attachment_passes_when_unset(
    make_eml: Callable[..., bytes],
) -> None:
    raw_email = make_eml(attachments=[('note.txt', b'hello')])
    assert has_required_attachment(raw_email) is True


def test_has_required_attachment_passes_when_matching(
    make_eml: Callable[..., bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('ATTACHMENT_REQUIRE_EXTENSIONS', 'xml')
    raw_email = make_eml(
        attachments=[('doc.xml', b'<a/>'), ('note.txt', b'hi')]
    )
    assert has_required_attachment(raw_email) is True


def test_has_required_attachment_fails_when_no_match(
    make_eml: Callable[..., bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('ATTACHMENT_REQUIRE_EXTENSIONS', 'xml')
    raw_email = make_eml(attachments=[('note.txt', b'hello')])
    assert has_required_attachment(raw_email) is False


def test_has_required_attachment_fails_when_no_attachments(
    make_eml: Callable[..., bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv('ATTACHMENT_REQUIRE_EXTENSIONS', 'xml')
    raw_email = make_eml(attachments=[])
    assert has_required_attachment(raw_email) is False
