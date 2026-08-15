#!/usr/bin/env python3
import unittest
from unittest.mock import patch

from src.services.credentials import CredentialsService


class TestQuarantineKeyStorage(unittest.TestCase):
    """QA #3 (alto): store_quarantine_key()/get_quarantine_key() sono i
    metodi che permettono a window.py di generare e persistere (via
    libsecret) la chiave AES-256 usata per attivare per davvero
    QuarantineManager.set_encryption() quando l'utente accende lo switch
    "Encrypt quarantined files" — prima inesistenti, il toggle non
    cifrava nulla."""

    def test_store_and_retrieve_round_trip(self):
        service = CredentialsService()
        stored = {}

        def fake_store(_schema, attrs, _collection, _label, value, _cancellable):
            stored[attrs["api"]] = value
            return True

        def fake_lookup(_schema, attrs, _cancellable):
            return stored.get(attrs["api"])

        with (
            patch(
                "src.services.credentials.Secret.password_store_sync",
                side_effect=fake_store,
            ),
            patch(
                "src.services.credentials.Secret.password_lookup_sync",
                side_effect=fake_lookup,
            ),
        ):
            ok = service.store_quarantine_key("ZmFrZS1rZXk=")
            self.assertTrue(ok)
            retrieved = service.get_quarantine_key()

        self.assertEqual(retrieved, "ZmFrZS1rZXk=")

    def test_quarantine_key_does_not_collide_with_vt_key(self):
        """Le due chiavi condividono lo stesso Schema libsecret ma con
        l'attributo "api" diverso ("quarantine" vs "virustotal"): devono
        restare due segreti distinti, non sovrascriversi a vicenda."""
        service = CredentialsService()
        stored = {}

        def fake_store(_schema, attrs, _collection, _label, value, _cancellable):
            stored[attrs["api"]] = value
            return True

        def fake_lookup(_schema, attrs, _cancellable):
            return stored.get(attrs["api"])

        with (
            patch(
                "src.services.credentials.Secret.password_store_sync",
                side_effect=fake_store,
            ),
            patch(
                "src.services.credentials.Secret.password_lookup_sync",
                side_effect=fake_lookup,
            ),
        ):
            service.store_quarantine_key("quarantine-secret")
            service.store_vt_key("vt-secret")

            self.assertEqual(service.get_quarantine_key(), "quarantine-secret")
            self.assertEqual(service.get_vt_key(), "vt-secret")

    def test_get_quarantine_key_returns_empty_string_when_absent(self):
        service = CredentialsService()
        with patch(
            "src.services.credentials.Secret.password_lookup_sync",
            return_value=None,
        ):
            self.assertEqual(service.get_quarantine_key(), "")

    def test_store_quarantine_key_returns_false_on_failure(self):
        service = CredentialsService()
        with patch(
            "src.services.credentials.Secret.password_store_sync",
            side_effect=RuntimeError("no secret service"),
        ):
            self.assertFalse(service.store_quarantine_key("anything"))


if __name__ == "__main__":
    unittest.main()
