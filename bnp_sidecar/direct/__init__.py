"""Accès direct à BNP Paribas (lecture seule, expérimental).

Ce module ne dépend pas d'Enable Banking. Il reproduit le flux de connexion
PingFederate de la banque et interroge uniquement les endpoints de lecture
des comptes et des opérations.
"""

from .client import (
    BnpDirectClient,
    DirectAccount,
    DirectMFARequired,
    DirectTransaction,
    MfaDecision,
    MfaHandler,
    account_type,
    normalize_iban,
    parse_accounts_payload,
    parse_amount,
    parse_bnp_date,
    parse_transactions_payload,
    rib_to_iban,
)
from .login import (
    LOGIN_ENTRY,
    LoginForm,
    MfaButton,
    MfaChallenge,
    MfaField,
    MfaForm,
    MfaLink,
    build_login_form_data,
    is_mfa_page,
    parse_login_page,
    parse_mfa_page,
    positions_for_password,
)

__all__ = [
    "LOGIN_ENTRY",
    "BnpDirectClient",
    "DirectAccount",
    "DirectMFARequired",
    "DirectTransaction",
    "LoginForm",
    "MfaButton",
    "MfaChallenge",
    "MfaDecision",
    "MfaField",
    "MfaForm",
    "MfaHandler",
    "MfaLink",
    "account_type",
    "build_login_form_data",
    "is_mfa_page",
    "normalize_iban",
    "parse_accounts_payload",
    "parse_amount",
    "parse_bnp_date",
    "parse_login_page",
    "parse_mfa_page",
    "parse_transactions_payload",
    "positions_for_password",
    "rib_to_iban",
]
