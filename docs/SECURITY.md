# rdpserver — security model and notes

## Trust model

rdpserver is a TCP-facing RDP server.  Clients connect over the
public network; the server speaks TLS (1.2 or 1.3, 1.3 preferred)
for confidentiality and RDP on top.  The threat model assumes:

- A malicious client may send arbitrary bytes on the wire at any
  point in the handshake.
- A successful login grants code execution as the authenticated
  user; the authentication step must be irrevocable.
- The TLS certificate is the cryptographic anchor for "this is the
  server you think you're talking to."  The first-run self-signed
  cert in `tmp/server.{crt,key}` is for development only;
  production should install an operator-issued cert.

## Process model and privilege separation

| Process            | UID        | Notes                                  |
|--------------------|------------|----------------------------------------|
| `rdpd` listener    | root       | binds 3389, accepts, forks per conn    |
| `rdpd` worker      | root       | TLS, RDP wire, greeter, channel mux    |
| `rdp-sessionmgr`   | root       | owns PAM/bsd_auth + fork+setuid spawn  |
| `rdp-session`      | target user | spawns Xvfb + xterm, captures, injects |

Splitting the daemon and the session manager keeps the
network-facing surface separate from the credential-handling
surface.  On OpenBSD, each binary calls `pledge(2)` after init to
drop unneeded promises:

- `rdpd` worker: `stdio inet unix`
- `rdp-sessionmgr`: `stdio rpath wpath cpath unix proc exec id getpw dpath fattr`
- `rdp-session`: `stdio rpath wpath cpath unix proc`

The listener stays unpledged so it can `accept` + `fork` + drop to
worker.  Linux equivalents (seccomp-bpf, capsicum on FreeBSD) are
plumbed in configure but not yet enforced; they're the next item
under "hardening."

## Authentication paths

### Greeter + PAM / bsd_auth (default, supported)

The default flow shows an RDP-painted login dialog after TLS,
collects username/password, hands them to `rdp-sessionmgr` over an
AF_UNIX SOCK_SEQPACKET socket, which calls PAM (Linux/FreeBSD/
NetBSD) or `auth_userokay(3)` (OpenBSD).  Cleartext bytes live in
the worker process and the sessmgr for the duration of the call;
both `explicit_bzero` on the way out.  The socket is mode 0660
root:_rdpd.

### NLA / CredSSP / NTLMv2 (framework only, NOT supported)

The wire-level CredSSP/NTLMv2 plumbing is shipped but not
operational, and the daemon does NOT advertise `PROTOCOL_HYBRID` in
the X.224 negotiate response.  Clients sending `xfreerdp /sec:nla`
will see a clean negotiation failure and should retry with
`/sec:tls`.

Why NLA cannot work yet: the protocol seals the user's password
with a key derived from the user's NT hash.  To validate the
client's response and decrypt the sealed credentials the server
must know that hash.  In a domain-joined deployment this comes from
winbind / sssd / Active Directory; for a standalone Linux/BSD
server it requires either:

- a `pam_winbind` / `pam_sssd` stack with the host joined to AD,
- an explicit `/etc/rdp/users.smbpasswd` mapping users to NT hashes
  (rejected by every modern security baseline), or
- a custom PAM module that talks to a hash backend.

Until a `rdp_nla_get_nt_hash(user, domain, out_hash)` hook is
provided, the NLA flow fails at the `authInfo` decryption step and
returns `-1`.  The fuzz corpus covers the parsers
(`fuzz_parsers cssp` / `fuzz_parsers ntlm`) so the wire bits stay
robust.

## Memory safety

All protocol parsers run under `-fsanitize=address,undefined` in
the regress build (`./configure --enable-sanitizers && make
regress fuzz`).  An in-tree mini-fuzzer (`regress/fuzz/
fuzz_parsers`) drives every parser with random bytes; 2.1 million
iterations across three seeds under ASan + UBSan have found no
crashes, no out-of-bounds reads, no undefined behaviour.

The non-parsing code paths are not yet under sanitizers in CI
because there's no CI yet.

## Known gaps

| Item                                | Status                          |
|-------------------------------------|---------------------------------|
| NLA / CredSSP                       | wire only; no hash backend      |
| TLS cert pinning / channel binding  | not enforced                    |
| Rate-limited auth                   | per-source-IP, 5 fails / 60 s   |
| Session resume / reconnect          | deferred to v1.1                |
| seccomp-bpf (Linux)                 | detected, not wired             |
| capsicum (FreeBSD)                  | detected, not wired             |
| Audit logging                       | log lines only; no syslog facility tuning |
| Smart card / virtual channel auth   | out of scope for v1             |

## Reporting

Security issues: email `renaud@allard.it` directly; do not file a
public issue.
