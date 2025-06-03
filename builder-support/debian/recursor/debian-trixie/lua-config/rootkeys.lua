-- readTrustAnchorsFromFile reads the DNSSEC trust anchors from the provided file
-- and reloads it every 24 hours.
readTrustAnchorsFromFile("/usr/share/dns/root.key")
