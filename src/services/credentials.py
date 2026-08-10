#!/usr/bin/env python3
"""
CredentialsService — Secure API key storage via SecretService / libsecret
"""

import logging

import gi

gi.require_version("Secret", "1")
from gi.repository import Secret

logger = logging.getLogger("alpha.credentials")


class CredentialsService:
    SCHEMA = Secret.Schema.new(
        "io.github.d3msudo.clamguard.VirusTotal",
        Secret.SchemaFlags.NONE,
        {"api": Secret.SchemaAttributeType.STRING},
    )

    def store_vt_key(self, api_key: str) -> bool:
        try:
            Secret.password_store_sync(
                self.SCHEMA,
                {"api": "virustotal"},
                Secret.COLLECTION_DEFAULT,
                "ClamGuard VirusTotal API Key",
                api_key,
                None,
            )
            return True
        except Exception as e:  # noqa: BLE001 - libsecret può sollevare vari errori
            logger.error(f"Failed to store key: {e}")
            return False

    def get_vt_key(self) -> str:
        try:
            return (
                Secret.password_lookup_sync(self.SCHEMA, {"api": "virustotal"}, None)
                or ""
            )
        except Exception as e:  # noqa: BLE001 - libsecret può sollevare vari errori
            logger.error(f"Failed to retrieve key: {e}")
            return ""
