"""Exact non-authorizing component advertisement; authority still uses original IPC."""
from web_request_profiles import PROFILES, MAX_REFERENCE_UNITS, MAX_PROPOSAL_UNITS

V3_WORKER_PROTOCOL={'setup_revisions':[1,2,3],'profiles':list(PROFILES),'reference_units':MAX_REFERENCE_UNITS,
    'proposal_units':MAX_PROPOSAL_UNITS,'transport':'fixed-egress-v1'}
V3_NATIVE_PROTOCOL={'protocol_revision':3,'reference_units':MAX_REFERENCE_UNITS,'review_seconds':180,'notification':'owned-native-v1'}
