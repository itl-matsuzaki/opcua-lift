#!/usr/bin/env python3
"""multi.py — build --multi scripts and decode what --multi writes.

The wire formats are documented in README.md; this is the reference
implementation of both directions, and what generated the sample scripts in
testcases/.  Standard library only — the C build has no Python dependency.

  build   multi.py build OUT SPEC [SPEC ...]
          SPEC = <service>:<body_file>[+<src>,<src_off>,<dst_off>,<len>]...
          A SPEC with at least one patch selects script v2 for the whole file.

            multi.py build s.script read:body.raw read:body.raw
            multi.py build s.script browse:b.raw 'browsenext:n.raw+0,12,9,16'

  decode  multi.py decode RESPONSES [--hex N]
          Reads what `opcua-lift --multi ... > RESPONSES` produced and prints
          one line per request: NodeId, response length, message type and the
          ResponseHeader's serviceResult.  '-' reads stdin.

            ./opcua-lift --multi s.script 4840 > out.bin
            multi.py decode out.bin
"""

import struct
import sys

# Binary request TypeIds (see README).  Call is 712: 713 is CallResponse.
SERVICES = {
    "read": 631,
    "write": 673,
    "browse": 527,
    "browsenext": 533,
    "call": 712,
}

LIFT_MAGIC = 0x5446494C   # "LIFT", framing of one response record
SCRIPT_MAGIC = b"LFTS"    # script v2 header
SCRIPT_VER = 2

STATUS_NAMES = {
    0x00000000: "Good",
    0x80000000: "Bad",
    0x80070000: "Bad_DecodingError",
    0x80080000: "Bad_EncodingLimitsExceeded",
    0x80200000: "Bad_IdentityTokenInvalid",
    0x803A0000: "Bad_NotReadable",
    0x803B0000: "Bad_NotWritable",
    0x804A0000: "Bad_ContinuationPointInvalid",
    0x81110000: "Bad_NotExecutable",
}

# Services whose response payload starts with an array of results that each
# begin with a StatusCode, so results[0] can be read without a full decoder.
# Read is deliberately absent: ReadResponse holds DataValues, which start with
# an encoding mask instead.
RESULT_IS_STATUS_FIRST = {527, 533, 673, 712}


def die(msg):
    print("multi.py: " + msg, file=sys.stderr)
    raise SystemExit(2)


def resolve_service(name):
    if name in SERVICES:
        return SERVICES[name]
    try:
        return int(name, 0)
    except ValueError:
        die("unknown service %r (use %s or a decimal NodeId)"
            % (name, "/".join(sorted(SERVICES))))


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------

def parse_spec(spec):
    """'<service>:<file>[+s,so,do,len]...' -> (node_id, body, [patches])."""
    parts = spec.split("+")
    head = parts[0]
    if ":" not in head:
        die("bad spec %r: expected <service>:<body_file>" % spec)
    name, path = head.split(":", 1)
    node_id = resolve_service(name)
    try:
        with open(path, "rb") as fh:
            body = fh.read()
    except OSError as e:
        die("cannot read body file %r: %s" % (path, e))

    patches = []
    for p in parts[1:]:
        fields = p.split(",")
        if len(fields) != 4:
            die("bad patch %r: expected <src>,<src_off>,<dst_off>,<len>" % p)
        try:
            src, src_off, dst_off, length = (int(f, 0) for f in fields)
        except ValueError:
            die("bad patch %r: fields must be integers" % p)
        if dst_off + length > len(body):
            die("patch %r writes past the end of %s (body is %d bytes)"
                % (p, path, len(body)))
        patches.append((src, src_off, dst_off, length))
    return node_id, body, patches


def build(argv):
    if len(argv) < 2:
        die("usage: multi.py build OUT SPEC [SPEC ...]")
    out_path, specs = argv[0], argv[1:]

    services = [parse_spec(s) for s in specs]
    v2 = any(patches for _, _, patches in services)

    for i, (_, _, patches) in enumerate(services):
        for src, _, _, _ in patches:
            if src >= i:
                die("service %d patches from response %d, which has not been "
                    "received yet (a patch may only read an earlier response)"
                    % (i, src))

    blob = b""
    if v2:
        blob += SCRIPT_MAGIC + struct.pack("<I", SCRIPT_VER)
    for node_id, body, patches in services:
        blob += struct.pack("<II", node_id, len(body)) + body
        if v2:
            blob += struct.pack("<I", len(patches))
            for patch in patches:
                blob += struct.pack("<IIII", *patch)

    with open(out_path, "wb") as fh:
        fh.write(blob)
    print("%s: %d requests, script v%d, %d bytes"
          % (out_path, len(services), 2 if v2 else 1, len(blob)))


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------

def nodeid_wire_len(buf, off):
    """Byte length of a binary-encoded NodeId at buf[off], or 0 if unreadable."""
    if off >= len(buf):
        return 0
    enc = buf[off] & 0x3F
    if enc == 0x00:
        return 2
    if enc == 0x01:
        return 4
    if enc == 0x02:
        return 7
    if enc in (0x03, 0x05):
        if off + 7 > len(buf):
            return 0
        n = struct.unpack_from("<i", buf, off + 3)[0]
        return 7 if n < 0 else 7 + n
    if enc == 0x04:
        return 19
    return 0


def skip_diagnostic_info(resp, off, depth=0):
    if depth > 8 or off >= len(resp):
        return None
    mask = resp[off]
    off += 1
    if mask & 0x80:
        return None
    for bit in range(4):                         # four Int32 fields
        if mask & (1 << bit):
            off += 4
    if mask & 0x10:                              # AdditionalInfo (String)
        n = struct.unpack_from("<i", resp, off)[0]
        off += 4 + max(n, 0)
    if mask & 0x20:                              # InnerStatusCode
        off += 4
    if mask & 0x40:                              # InnerDiagnosticInfo
        off = skip_diagnostic_info(resp, off, depth + 1)
    return off


def walk_response(resp):
    """-> (serviceResult, payload_offset), or (None, None) if unreadable.

    The ResponseHeader is variable length, so this walks it rather than
    assuming the 24-byte minimal form (see skip_response_header in
    opcua-lift.c — same reason, same failure mode if you get it wrong).
    """
    try:
        off = 24                                 # MSG transport header
        n = nodeid_wire_len(resp, off)           # response TypeId
        if n == 0:
            return None, None
        off += n
        if off + 16 > len(resp):
            return None, None
        status = struct.unpack_from("<I", resp, off + 12)[0]
        off += 16                                # timestamp, handle, result

        off = skip_diagnostic_info(resp, off)    # serviceDiagnostics
        if off is None:
            return status, None

        nstr = struct.unpack_from("<i", resp, off)[0]   # stringTable
        off += 4
        for _ in range(max(nstr, 0)):
            sl = struct.unpack_from("<i", resp, off)[0]
            off += 4 + max(sl, 0)

        n = nodeid_wire_len(resp, off)           # additionalHeader: ExtObj
        if n == 0:
            return status, None
        off += n
        enc = resp[off]
        off += 1
        if enc in (0x01, 0x02):
            bl = struct.unpack_from("<i", resp, off)[0]
            off += 4 + max(bl, 0)
        elif enc != 0x00:
            return status, None
        return status, (off if off <= len(resp) else None)
    except (struct.error, IndexError):
        return None, None


def first_result_status(node_id, resp, payload_off):
    """results[0]'s StatusCode for the services where that is unambiguous.

    Worth showing because a service can answer Good at the service level while
    every individual result failed — an unpatched BrowseNext is exactly that.
    """
    if node_id not in RESULT_IS_STATUS_FIRST or payload_off is None:
        return None
    try:
        count = struct.unpack_from("<i", resp, payload_off)[0]
        if count < 1:
            return None
        return struct.unpack_from("<I", resp, payload_off + 4)[0]
    except struct.error:
        return None


def decode(argv):
    hex_bytes = 0
    args = []
    i = 0
    while i < len(argv):
        if argv[i] == "--hex":
            if i + 1 >= len(argv):
                die("--hex needs a byte count")
            hex_bytes = int(argv[i + 1], 0)
            i += 2
        else:
            args.append(argv[i])
            i += 1
    if len(args) != 1:
        die("usage: multi.py decode RESPONSES [--hex N]")

    if args[0] == "-":
        blob = sys.stdin.buffer.read()
    else:
        with open(args[0], "rb") as fh:
            blob = fh.read()

    off = 0
    index = 0
    while off + 12 <= len(blob):
        magic, node_id, resp_len = struct.unpack_from("<III", blob, off)
        if magic != LIFT_MAGIC:
            die("record %d: bad magic 0x%08x (expected 0x%08x). Single-service "
                "mode writes raw response bytes, not framed records."
                % (index, magic, LIFT_MAGIC))
        off += 12
        if off + resp_len > len(blob):
            die("record %d: truncated (claims %d bytes, %d left)"
                % (index, resp_len, len(blob) - off))
        resp = blob[off:off + resp_len]
        off += resp_len

        if resp_len == 0:
            # Not a failure: the server answered nothing for this request and
            # the run carried on with the next one.
            print("[%d] node=%-4d len=0     (no response)" % (index, node_id))
        else:
            kind = resp[:4].decode("ascii", "replace")
            status, payload_off = walk_response(resp)
            if status is None:
                shown = "serviceResult=?"
            else:
                shown = "serviceResult=0x%08X %s" % (
                    status, STATUS_NAMES.get(status, ""))
            first = first_result_status(node_id, resp, payload_off)
            if first is not None:
                shown += "  results[0]=0x%08X %s" % (
                    first, STATUS_NAMES.get(first, ""))
            print("[%d] node=%-4d len=%-5d %s  %s"
                  % (index, node_id, resp_len, kind, shown.rstrip()))
            if hex_bytes:
                print("      %s" % resp[:hex_bytes].hex(" "))
        index += 1

    if off != len(blob):
        die("%d trailing bytes after the last record" % (len(blob) - off))
    if index == 0:
        die("no records found (empty input)")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__.rstrip())
        return 0
    cmd, argv = sys.argv[1], sys.argv[2:]
    if cmd == "build":
        build(argv)
    elif cmd == "decode":
        decode(argv)
    else:
        die("unknown command %r (build | decode)" % cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
