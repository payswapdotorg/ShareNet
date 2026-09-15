# ShareNet VPN data-plane consumer rules (R4-004).
# The transport library intentionally requires no ProGuard/R8 keep rules yet:
# it exposes only its own Kotlin types and the VpnService declared in the
# manifest (kept automatically via the manifest merger).
