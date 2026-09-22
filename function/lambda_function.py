# Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
# SPDX-License-Identifier: MIT

"""
Forward an SES-received email as a signed webhook.

This function receives an inbound email notification from an Amazon SES
receipt rule (invoked directly, without an SNS topic in between), downloads
the raw MIME message from the S3 bucket where the receipt rule stored it,
and forwards it as a signed webhook so a downstream system can process it
(for example, to create a support ticket).

The SES "Lambda" receipt action never includes the email body, only
metadata (see "mail" and "receipt" objects below), so an "S3" action must
be placed before the "Lambda" action in the same receipt rule to store the
raw message. The object key SES uses in that bucket is always the
message's "messageId".

The webhook body is always an envelope of the form:

    {"meta": {"source": "aws-ses", "format": "...", "version": "1.0.0"},
     "data": {...}}

"format" (WEBHOOK_FORMAT) selects which builder in DATA_BUILDERS produces
"data", so the shape of "data" is fully determined by "format". Adding a
new output format only requires adding a new builder function here.
"""

# modules used by this function
import hashlib
import hmac
import json
from base64 import b64encode
from datetime import datetime
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from os import getenv
from typing import Any

import boto3
import requests


class LambdaFunctionException(Exception):
    """Raised for invalid configuration or an unexpected webhook response."""


# S3 client created once and reused across invocations (execution context
# reuse)
s3_client = boto3.client('s3')

ENVELOPE_SOURCE = 'aws-ses'
ENVELOPE_VERSION = '1.0.0'

# a GRAY or PROCESSING_FAILED spam verdict doesn't mean the email should be
# dropped, but it shouldn't be trusted as much as a PASS either, so it's
# mapped to "Spam" to get the same downstream priority as a confirmed FAIL
SPAM_STATUS_MAP = {
    'PASS': 'NotSpam',
    'FAIL': 'Spam',
    'GRAY': 'Spam',
    'PROCESSING_FAILED': 'Spam',
}


# ----------------------------------------------------------------------
# Function that fetches the raw email stored in S3 by the SES receipt rule
# ----------------------------------------------------------------------


def get_raw_email(message_id: str) -> bytes:
    """Fetch the raw MIME message that SES stored in S3 for message_id."""
    # allows running a local test without AWS credentials or network access
    local_test_file = getenv('SES_LOCAL_TEST_EML_FILE')
    if local_test_file:
        with open(local_test_file, 'rb') as f:
            return f.read()
    bucket = getenv('SES_S3_BUCKET')
    if bucket is None:
        raise LambdaFunctionException('SES_S3_BUCKET is not set')
    key_prefix = getenv('SES_S3_KEY_PREFIX', '')
    response = s3_client.get_object(Bucket=bucket, Key=key_prefix + message_id)
    return response['Body'].read()


# ----------------------------------------------------------------------
# "ses" format: the envelope's own native representation, no MIME parsing
# ----------------------------------------------------------------------


def build_data_ses(
    mail: dict[str, Any], receipt: dict[str, Any], raw_email: bytes
) -> dict[str, Any]:
    """Build the "data" payload for the "ses" output format."""
    return {
        'ses': {
            'mail': mail,
            'receipt': receipt,
        },
        'email_base64': b64encode(raw_email).decode('ascii'),
    }


# ----------------------------------------------------------------------
# "postal" format: matches the JSON shape Postal sends for HTTP endpoints
# configured with Encoding=BodyAsJSON and Format=Hash, confirmed against
# Postal's own source (app/senders/http_sender.rb)
# ----------------------------------------------------------------------


def build_data_postal(
    mail: dict[str, Any], receipt: dict[str, Any], raw_email: bytes
) -> dict[str, Any]:
    """Build the "data" payload for the "postal" output format."""
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    text_part = message.get_body(preferencelist=('plain',))
    html_part = message.get_body(preferencelist=('html',))

    attachments: list[dict[str, Any]] = []
    for part in message.iter_attachments():
        content = part.get_content()
        if isinstance(content, str):
            content = content.encode('utf-8')
        attachments.append(
            {
                'filename': part.get_filename(),
                'content_type': part.get_content_type(),
                'size': len(content),
                'data': b64encode(content).decode('ascii'),
            }
        )

    recipients = receipt.get('recipients') or mail.get('destination') or [None]
    spam_status = SPAM_STATUS_MAP.get(
        receipt.get('spamVerdict', {}).get('status'), 'Spam'
    )
    received_at = datetime.fromisoformat(
        mail['timestamp'].replace('Z', '+00:00')
    )

    return {
        # SES's messageId is an opaque string, not the sequential integer ID
        # Postal uses, so it's reused as-is for both "id" and "token"
        'id': mail['messageId'],
        'token': mail['messageId'],
        'rcpt_to': recipients[0],
        'mail_from': mail.get('source'),
        'subject': message.get('subject'),
        'message_id': message.get('message-id'),
        'timestamp': received_at.timestamp(),
        'size': len(raw_email),
        'spam_status': spam_status,
        'bounce': False,
        # SES doesn't report whether the original SMTP session used TLS
        'received_with_ssl': None,
        'to': message.get('to'),
        'cc': message.get('cc'),
        'from': message.get('from'),
        'date': message.get('date'),
        'in_reply_to': message.get('in-reply-to'),
        'references': message.get('references'),
        'reply_to': message.get('reply-to'),
        'plain_body': (
            text_part.get_content() if text_part is not None else None
        ),
        'html_body': (
            html_part.get_content() if html_part is not None else None
        ),
        'auto_submitted': message.get('auto-submitted'),
        'attachment_quantity': len(attachments),
        'attachments': attachments,
    }


DATA_BUILDERS = {
    'ses': build_data_ses,
    'postal': build_data_postal,
}


def build_envelope(
    mail: dict[str, Any], receipt: dict[str, Any], raw_email: bytes
) -> dict[str, Any]:
    """Build the full webhook envelope for the given SES mail/receipt."""
    webhook_format = getenv('WEBHOOK_FORMAT', 'postal')
    if webhook_format not in DATA_BUILDERS:
        raise LambdaFunctionException(
            'Unknown WEBHOOK_FORMAT: %(format)s' % {'format': webhook_format}
        )
    return {
        'meta': {
            'source': ENVELOPE_SOURCE,
            'format': webhook_format,
            'version': ENVELOPE_VERSION,
        },
        'data': DATA_BUILDERS[webhook_format](mail, receipt, raw_email),
    }


# ----------------------------------------------------------------------
# Functions that sign and send the webhook request
# ----------------------------------------------------------------------


def sign_hmac(payload_bytes: bytes) -> dict[str, str]:
    """Sign payload_bytes with HMAC-SHA256, returning the signature header."""
    webhook_secret = getenv('WEBHOOK_SECRET')
    if webhook_secret is None:
        raise LambdaFunctionException('WEBHOOK_SECRET is not set')
    signature_prefix = getenv('WEBHOOK_SIGNATURE_PREFIX', '')
    digest = hmac.new(
        webhook_secret.encode('utf-8'), payload_bytes, hashlib.sha256
    ).hexdigest()
    return {'X-Webhook-Signature-256': signature_prefix + digest}


def sign_none(payload_bytes: bytes) -> dict[str, str]:
    """Return no signature headers (WEBHOOK_SIGNATURE=none)."""
    return {}


SIGNERS = {
    'hmac': sign_hmac,
    'none': sign_none,
}


def send_webhook(envelope: dict[str, Any]) -> requests.Response:
    """POST the envelope to WEBHOOK_URL, signed per WEBHOOK_SIGNATURE."""
    webhook_url = getenv('WEBHOOK_URL')
    if webhook_url is None:
        raise LambdaFunctionException('WEBHOOK_URL is not set')
    webhook_signature = getenv('WEBHOOK_SIGNATURE', 'hmac')
    if webhook_signature not in SIGNERS:
        raise LambdaFunctionException(
            'Unknown WEBHOOK_SIGNATURE: %(scheme)s'
            % {'scheme': webhook_signature}
        )
    payload_bytes = json.dumps(envelope, ensure_ascii=False).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    headers.update(SIGNERS[webhook_signature](payload_bytes))
    response = requests.post(
        webhook_url, data=payload_bytes, headers=headers, timeout=10
    )
    if response.status_code >= HTTPStatus.MULTIPLE_CHOICES:
        raise LambdaFunctionException(
            'Webhook request to %(url)s failed with status '
            '%(status)s: %(body)s'
            % {
                'url': webhook_url,
                'status': response.status_code,
                'body': response.text,
            }
        )
    return response


# ----------------------------------------------------------------------
# Main function invoked directly by the SES receipt rule's Lambda action
# ----------------------------------------------------------------------


def process_ses_record(record: dict[str, Any]) -> None:
    """Fetch, build and send the webhook for a single SES record."""
    mail = record['ses']['mail']
    receipt = record['ses']['receipt']
    raw_email = get_raw_email(mail['messageId'])
    envelope = build_envelope(mail, receipt, raw_email)
    send_webhook(envelope)


def lambda_handler(event: dict[str, Any], context: object) -> dict[str, str]:
    """Entry point invoked by the SES receipt rule's Lambda action."""
    for record in event.get('Records', []):
        process_ses_record(record)
    # only relevant when the receipt rule invokes this function with the
    # "RequestResponse" invocation type, ignored otherwise
    return {'disposition': 'CONTINUE'}


# ----------------------------------------------------------------------
# Test case
# ----------------------------------------------------------------------

# runs this function if this file is the one being executed
# useful to test this Lambda function locally, without AWS credentials, by
# setting SES_LOCAL_TEST_EML_FILE to the path of a raw .eml file
if __name__ == '__main__':
    test_event = {
        'Records': [
            {
                'eventSource': 'aws:ses',
                'ses': {
                    'mail': {
                        'timestamp': '2026-08-10T12:00:00.000Z',
                        'source': 'sender@example.com',
                        'messageId': getenv(
                            'SES_LOCAL_TEST_MESSAGE_ID',
                            'local-test-message-id',
                        ),
                        'destination': ['support@example.com'],
                    },
                    'receipt': {
                        'recipients': ['support@example.com'],
                        'spamVerdict': {'status': 'PASS'},
                        'virusVerdict': {'status': 'PASS'},
                        'spfVerdict': {'status': 'PASS'},
                        'dkimVerdict': {'status': 'PASS'},
                        'dmarcVerdict': {'status': 'PASS'},
                    },
                },
            }
        ],
    }
    result = lambda_handler(test_event, None)
    print(json.dumps(result))
