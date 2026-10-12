# Disable core dumps for login shells (defense-in-depth; the hard limit is already 0 via /etc/security/limits.conf).
ulimit -c 0
