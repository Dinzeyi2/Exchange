import base64
import os
from pathlib import Path
from typing import Literal

import yaml
from cryptography.hazmat.primitives import serialization
from pydantic import Field, model_validator

from node.adapters.models import Model, lei_valid
from node.signer.backends import HsmSigner, SoftwareSigner
from node.transport.protocol import Peer


class Officer(Model):
    officer_id: str
    name: str
    roles: list[str]
    signing_key: str
    certificate_sha256: str
    certificate_path: str


class OidcSettings(Model):
    issuer: str
    audience: str
    jwks_file: str
    subjects: dict[str, str]
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    redirect_uri: str


class Settings(Model):
    node_id: str
    legal_name: str
    lei: str
    role: Literal["seller", "buyer", "agent", "borrower"]
    mode: Literal["production", "certification"] = "production"
    database_url_env: str = "EXCHANGE_DATABASE_URL"
    certificate: str
    tls_key: str
    signing_backend: Literal["pkcs11", "software"] = "pkcs11"
    signing_key: str
    agreement_key: str
    public_agreement_key: str
    public_signing_key: str
    hsm_module: str | None = None
    hsm_token: str | None = None
    hsm_key_label: str | None = None
    hsm_pin_env: str = "EXCHANGE_HSM_PIN"
    peer_port: int = Field(default=8443, ge=1, le=65535)
    officer_port: int = Field(default=9443, ge=1, le=65535)
    peer_host: str = "0.0.0.0"
    officer_host: str = "127.0.0.1"
    peers: list[Peer]
    officers: list[Officer]
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8080, ge=1, le=65535)
    oidc: OidcSettings | None = None
    officer_hsm_labels: dict[str, str] = Field(default_factory=dict)
    peer_officers: dict[str, dict[str, dict]] = Field(default_factory=dict)
    catalog_file: str | None = None
    document_template: str
    required_kyc_documents: list[str] = Field(
        default_factory=lambda: ["identity", "tax"]
    )
    payment_inbox: str
    payment_outbox: str
    pacs_xsd: str | None = None
    camt_xsd: str | None = None
    field_key_env: str = "EXCHANGE_FIELD_KEY"

    @model_validator(mode="after")
    def security(self):
        if not lei_valid(self.lei):
            raise ValueError("invalid institution LEI")
        if len({p.node_id for p in self.peers}) != len(self.peers):
            raise ValueError("duplicate peers")
        if self.node_id in {p.node_id for p in self.peers}:
            raise ValueError("node cannot peer with itself")
        if len({p.role for p in self.peers}) != len(self.peers):
            raise ValueError("one counterparty per role in v1 deployment")
        if {p.role for p in self.peers} != {"seller", "buyer", "agent", "borrower"} - {
            self.role
        }:
            raise ValueError("four distinct role identities required")
        if len({o.officer_id for o in self.officers}) != len(self.officers):
            raise ValueError("duplicate officers")
        if any(
            not p.endpoint.startswith("https://") or not lei_valid(p.lei)
            for p in self.peers
        ):
            raise ValueError("invalid peer identity")
        required = {
            "seller": {"administrator", "trader", "signatory"},
            "buyer": {"administrator", "loan_ops", "treasurer", "signatory"},
            "agent": {"administrator", "kyc", "officer", "signatory"},
            "borrower": {"administrator", "treasurer"},
        }[self.role]
        if not required.issubset({role for o in self.officers for role in o.roles}):
            raise ValueError("required local officer roles are missing")
        if (
            self.role == "agent"
            and sum("officer" in o.roles for o in self.officers) < 2
        ):
            raise ValueError("agent requires two different SSI control officers")
        if len({o.signing_key for o in self.officers}) != len(self.officers):
            raise ValueError("officer keys must be distinct")
        if len({o.certificate_sha256 for o in self.officers}) != len(self.officers):
            raise ValueError("officer TLS identities must be distinct")
        if len({p.signing_key for p in self.peers} | {self.public_signing_key}) != 4:
            raise ValueError("node signing identities must be distinct")
        if self.oidc:
            if not set(self.oidc.subjects.values()).issubset(
                {o.officer_id for o in self.officers}
            ):
                raise ValueError("OIDC officer mapping invalid")
            for endpoint in [
                self.oidc.issuer,
                self.oidc.authorization_endpoint,
                self.oidc.token_endpoint,
                self.oidc.redirect_uri,
            ]:
                if not endpoint.startswith("https://"):
                    raise ValueError("bank OIDC requires HTTPS")
        if self.mode == "production":
            if not self.catalog_file:
                raise ValueError("production requires bank-approved catalog policy")
            if not self.oidc or set(self.officer_hsm_labels) != {
                o.officer_id for o in self.officers
            }:
                raise ValueError(
                    "production requires bank OIDC and officer HSM key bindings"
                )
            if self.signing_backend != "pkcs11":
                raise ValueError("production requires PKCS#11 node signer")
            if not all(
                [
                    self.hsm_module,
                    self.hsm_token,
                    self.hsm_key_label,
                    self.pacs_xsd,
                    self.camt_xsd,
                ]
            ):
                raise ValueError(
                    "production requires HSM and payment scheme XSD configuration"
                )
        return self

    @classmethod
    def load(cls, path):
        with Path(path).open() as stream:
            return cls.model_validate(yaml.safe_load(stream))

    def signer(self):
        if self.signing_backend == "software":
            key = serialization.load_pem_private_key(
                Path(self.signing_key).read_bytes(), password=None
            )
            signer = SoftwareSigner(key)
        else:
            signer = HsmSigner(
                self.hsm_module,
                self.hsm_token,
                self.hsm_key_label,
                os.environ[self.hsm_pin_env],
                base64.b64decode(self.public_signing_key),
            )
        if signer.public_key != base64.b64decode(self.public_signing_key):
            raise ValueError("node key does not match configured identity")
        return signer

    def database_url(self):
        value = os.environ[self.database_url_env]
        if self.mode == "production" and not value.startswith("postgresql+psycopg://"):
            raise ValueError("production requires PostgreSQL")
        return value
