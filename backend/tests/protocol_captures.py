"""Captures for the five protocol families, built with Scapy.

The repository's real captures hold only SMTP, SSH and SMB, so FTP, POP3, IMAP, SIP
and RTP/RTCP sessions are generated here instead of being skipped. Everything is
crafted to be *dissected by TShark*, not merely to look right: the bytes follow the
protocols' wire formats (SSH binary packets, SMB1/SMB2 headers, NTLMSSP) so the
extractor is tested against a real dissector rather than a fixture of our own making.

Scapy builds the frames (addressing, TCP/UDP, checksums, timestamps); the protocol
payloads are written by hand where a byte-exact layout matters.
"""

from __future__ import annotations

import struct
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap
from scapy.layers.rtp import RTP

CLIENT = "10.10.0.10"
SERVER = "10.10.0.20"
BASE_EPOCH = 1_700_000_000.0

# --------------------------------------------------------------------------
# frame helpers
# --------------------------------------------------------------------------


def _stamp(packets: list, base: float, step: float = 0.01) -> list:
    for index, packet in enumerate(packets):
        packet.time = base + index * step
    return packets


def tcp_stream(
    exchanges: list[tuple[str, bytes]],
    *,
    src: str = CLIENT,
    sport: int,
    dst: str = SERVER,
    dport: int,
    base: float = BASE_EPOCH,
) -> list:
    """A complete TCP conversation: handshake, the given payloads, teardown.

    ``exchanges`` is a list of ``("c" | "s", payload)``; "c" is the client side.
    Sequence numbers are tracked so TShark sees a consistent stream and assigns it a
    ``tcp.stream``.
    """
    packets = []
    seq_c, seq_s = 1000, 5000
    packets.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c))
    seq_c += 1
    packets.append(
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c)
    )
    seq_s += 1
    packets.append(
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s)
    )
    for direction, payload in exchanges:
        if direction == "c":
            packets.append(
                Ether()
                / IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s)
                / Raw(payload)
            )
            seq_c += len(payload)
        else:
            packets.append(
                Ether()
                / IP(src=dst, dst=src)
                / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c)
                / Raw(payload)
            )
            seq_s += len(payload)
    packets.append(
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s)
    )
    packets.append(
        Ether()
        / IP(src=dst, dst=src)
        / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1)
    )
    packets.append(
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1)
    )
    return _stamp(packets, base)


def udp_exchange(
    datagrams: list[tuple[str, bytes]],
    *,
    src: str = CLIENT,
    sport: int,
    dst: str = SERVER,
    dport: int,
    base: float = BASE_EPOCH,
) -> list:
    packets = []
    for direction, payload in datagrams:
        if direction == "c":
            packets.append(Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload))
        else:
            packets.append(Ether() / IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / Raw(payload))
    return _stamp(packets, base)


def write(name: str, packets: list, dest: Path | None) -> Path:
    directory = Path(dest) if dest is not None else Path.cwd()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    wrpcap(str(path), packets)
    return path


# --------------------------------------------------------------------------
# email: SMTP, POP3, IMAP
# --------------------------------------------------------------------------


def smtp_exchanges(
    *,
    port: int = 25,
    greet: bool = True,
    senders: list[str] | None = None,
    recipients: list[str] | None = None,
    auth: bool = True,
    failures: int = 0,
) -> list[tuple[str, bytes]]:
    senders = senders or ["alice@lab.test"]
    recipients = recipients or ["bob@lab.test"]
    exchanges: list[tuple[str, bytes]] = []
    if greet:
        exchanges.append(("s", b"220 mail.lab.test ESMTP Postfix\r\n"))
    exchanges.append(("c", b"EHLO client.lab.test\r\n"))
    exchanges.append(
        (
            "s",
            b"250-mail.lab.test\r\n"
            b"250-PIPELINING\r\n"
            b"250-SIZE 10240000\r\n"
            b"250-AUTH PLAIN LOGIN CRAM-MD5\r\n"
            b"250-ENHANCEDSTATUSCODES\r\n"
            b"250 8BITMIME\r\n",
        )
    )
    if auth:
        # AUTH LOGIN: base64("\0"? no) - LOGIN sends the user name, then the password.
        exchanges.append(("c", b"AUTH LOGIN YWxpY2U=\r\n"))
        exchanges.append(("s", b"334 UGFzc3dvcmQ6\r\n"))
        exchanges.append(("c", b"czNjcjN0\r\n"))
        exchanges.append(("s", b"235 2.7.0 Authentication successful\r\n"))
    for _ in range(failures):
        exchanges.append(("c", b"AUTH LOGIN YWxpY2U=\r\n"))
        exchanges.append(("s", b"334 UGFzc3dvcmQ6\r\n"))
        exchanges.append(("c", b"d3Jvbmc=\r\n"))
        exchanges.append(("s", b"535 5.7.8 Authentication credentials invalid\r\n"))
    for sender in senders:
        exchanges.append(("c", f"MAIL FROM:<{sender}>\r\n".encode()))
        exchanges.append(("s", b"250 2.1.0 Ok\r\n"))
        for recipient in recipients:
            exchanges.append(("c", f"RCPT TO:<{recipient}>\r\n".encode()))
            exchanges.append(("s", b"250 2.1.5 Ok\r\n"))
        exchanges.append(("c", b"DATA\r\n"))
        exchanges.append(("s", b"354 End data with <CR><LF>.<CR><LF>\r\n"))
        exchanges.append(("c", b"Subject: report\r\n\r\nbody\r\n.\r\n"))
        exchanges.append(("s", b"250 2.0.0 Ok: queued as 1A2B3C\r\n"))
    exchanges.append(("c", b"QUIT\r\n"))
    exchanges.append(("s", b"221 2.0.0 Bye\r\n"))
    return exchanges


def pop3_exchanges() -> list[tuple[str, bytes]]:
    return [
        ("s", b"+OK POP3 server ready\r\n"),
        ("c", b"USER dave\r\n"),
        ("s", b"+OK dave is a valid mailbox\r\n"),
        ("c", b"PASS hunter2\r\n"),
        ("s", b"+OK Logged in\r\n"),
        ("c", b"STAT\r\n"),
        ("s", b"+OK 2 320\r\n"),
        ("c", b"LIST\r\n"),
        ("s", b"+OK 2 messages (320 octets)\r\n"),
        ("c", b"RETR 1\r\n"),
        ("s", b"+OK 160 octets\r\nSubject: report\r\n\r\nbody\r\n.\r\n"),
        ("c", b"DELE 1\r\n"),
        ("s", b"+OK message 1 deleted\r\n"),
        ("c", b"QUIT\r\n"),
        ("s", b"+OK POP3 server signing off\r\n"),
    ]


def imap_exchanges() -> list[tuple[str, bytes]]:
    return [
        ("s", b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready\r\n"),
        ("c", b"a1 CAPABILITY\r\n"),
        ("s", b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\na1 OK Capability completed\r\n"),
        ("c", b'a2 LOGIN erin "p@ss w0rd"\r\n'),
        ("s", b"a2 OK Logged in\r\n"),
        ("c", b"a3 SELECT INBOX\r\n"),
        ("s", b"* 2 EXISTS\r\n* FLAGS (\\Seen)\r\na3 OK [READ-WRITE] Select completed\r\n"),
        ("c", b"a4 FETCH 1:* (FLAGS)\r\n"),
        ("s", b"* 1 FETCH (FLAGS (\\Seen))\r\na4 OK Fetch completed\r\n"),
        ("c", b"a5 UID FETCH 100 (BODY.PEEK[HEADER])\r\n"),
        ("s", b"a5 OK Fetch completed\r\n"),
        ("c", b'a6 SELECT "Sent"\r\n'),
        ("s", b"a6 OK [READ-WRITE] Select completed\r\n"),
        ("c", b"a7 LOGOUT\r\n"),
        ("s", b"* BYE Logging out\r\na7 OK Logout completed\r\n"),
    ]


def email_capture(dest: Path | None = None) -> Path:
    """SMTP on 25, POP3 on 110 and IMAP on 143 in one capture."""
    packets: list = []
    packets += tcp_stream(smtp_exchanges(), sport=40201, dport=25, base=BASE_EPOCH)
    packets += tcp_stream(pop3_exchanges(), sport=40202, dport=110, base=BASE_EPOCH + 5)
    packets += tcp_stream(imap_exchanges(), sport=40203, dport=143, base=BASE_EPOCH + 10)
    packets.sort(key=lambda packet: packet.time)
    return write("email.pcap", packets, dest)


def smtp_submission_capture(dest: Path | None = None, *, failures: int = 2) -> Path:
    """SMTP on 587: no registered port (rule 2 decides) plus rejected AUTHs."""
    packets = tcp_stream(
        smtp_exchanges(port=587, failures=failures), sport=40211, dport=587, base=BASE_EPOCH
    )
    return write("smtp_submission.pcap", packets, dest)


def smtp_twin_capture(dest: Path | None = None) -> Path:
    """Two concurrent SMTP sessions to the same server: two rows, never merged."""
    packets = tcp_stream(smtp_exchanges(auth=False), sport=40261, dport=25, base=BASE_EPOCH + 120)
    packets += tcp_stream(
        smtp_exchanges(auth=False, senders=["carol@lab.test"], recipients=["dan@lab.test"]),
        sport=40262,
        dport=25,
        base=BASE_EPOCH + 120.5,
    )
    packets.sort(key=lambda packet: packet.time)
    return write("smtp_twin.pcap", packets, dest)


def smtp_midsession_capture(dest: Path | None = None, *, dport: int = 587) -> Path:
    """SMTP on the submission port with no greeting captured (rule 3 decides).

    Port 587 is not SMTP's registered port, so rule 1 cannot apply, and a capture that
    starts after the banner has no server-role message for rule 2 either.
    """
    exchanges = [
        ("c", b"EHLO client.lab.test\r\n"),
        ("s", b"250-mail.lab.test\r\n250 SIZE 10240000\r\n"),
        ("c", b"MAIL FROM:<carol@lab.test>\r\n"),
        ("s", b"250 2.1.0 Ok\r\n"),
        ("c", b"RCPT TO:<dave@lab.test>\r\n"),
        ("s", b"250 2.1.5 Ok\r\n"),
    ]
    packets = tcp_stream(exchanges, sport=40217, dport=dport, base=BASE_EPOCH + 30)
    return write("smtp_midsession.pcap", packets, dest)


def smtp_many_commands_capture(dest: Path | None = None, count: int = 55) -> Path:
    """One SMTP session with more senders and recipients than the caps allow."""
    senders = [f"sender{i:03d}@lab.test" for i in range(count)]
    packets = tcp_stream(
        smtp_exchanges(senders=senders, recipients=["bob@lab.test"], auth=False),
        sport=40221,
        dport=25,
        base=BASE_EPOCH,
    )
    return write("smtp_many.pcap", packets, dest)


# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------


def _ssh_packet(payload: bytes, *, padding: int = 8) -> bytes:
    """A pre-encryption SSH binary packet: length, padding length, payload, padding."""
    length = len(payload) + padding + 1
    return struct.pack(">IB", length, padding) + payload + bytes(padding)


def _ssh_name_list(names: list[str]) -> bytes:
    text = ",".join(names).encode()
    return struct.pack(">I", len(text)) + text


def ssh_kexinit() -> bytes:
    payload = b"\x14" + bytes(range(16))  # SSH_MSG_KEXINIT + cookie
    payload += _ssh_name_list(["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"])
    payload += _ssh_name_list(["ssh-ed25519", "rsa-sha2-512", "ecdsa-sha2-nistp256"])
    payload += _ssh_name_list(["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"])
    payload += _ssh_name_list(["chacha20-poly1305@openssh.com", "aes128-ctr"])
    payload += _ssh_name_list(["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512"])
    payload += _ssh_name_list(["hmac-sha2-256", "hmac-sha2-512"])
    payload += _ssh_name_list(["none"])
    payload += _ssh_name_list(["none"])
    payload += _ssh_name_list([])
    payload += _ssh_name_list([])
    payload += b"\x00" + struct.pack(">I", 0)  # first_kex_packet_follows, reserved
    return _ssh_packet(payload)


def ssh_capture(dest: Path | None = None) -> Path:
    """A client and server identification string, both KEXINITs and a DH exchange."""
    exchanges = [
        ("c", b"SSH-2.0-OpenSSH_9.6\r\n"),
        ("s", b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n"),
        ("c", ssh_kexinit()),
        ("s", ssh_kexinit()),
        ("c", _ssh_packet(b"\x1e" + struct.pack(">I", 32) + bytes(32))),  # SSH_MSG_KEXDH_INIT
        ("s", _ssh_packet(b"\x1f" + struct.pack(">I", 32) + bytes(32))),  # SSH_MSG_KEXDH_REPLY
    ]
    packets = tcp_stream(exchanges, sport=40231, dport=22, base=BASE_EPOCH)
    return write("ssh.pcap", packets, dest)


def ssh_offport_capture(dest: Path | None = None, *, dport: int = 2222) -> Path:
    """SSH on a port §1.2 does not list: the identification string decides the roles.

    This build's SSH heuristic dissects the banner on any TCP port, so this is the case
    where rule 1 cannot apply and rule 2's server-role message does.
    """
    exchanges = [
        ("c", b"SSH-2.0-OpenSSH_9.6\r\n"),
        ("s", b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n"),
        ("c", ssh_kexinit()),
        ("s", ssh_kexinit()),
    ]
    packets = tcp_stream(exchanges, sport=40233, dport=dport, base=BASE_EPOCH + 15)
    return write("ssh_offport.pcap", packets, dest)


# --------------------------------------------------------------------------
# FTP
# --------------------------------------------------------------------------


def ftp_exchanges(*, user: str = "anonymous", greeting: bool = True, pasv: bool = True) -> list[tuple[str, bytes]]:
    exchanges: list[tuple[str, bytes]] = []
    if greeting:
        exchanges.append(("s", b"220 ProFTPD Server (Debian) ready.\r\n"))
    exchanges.append(("c", f"USER {user}\r\n".encode()))
    exchanges.append(("s", b"331 Password required\r\n"))
    exchanges.append(("c", b"PASS guest@example.com\r\n"))
    exchanges.append(("s", b"230 User logged in\r\n"))
    exchanges.append(("c", b"TYPE I\r\n"))
    exchanges.append(("s", b"200 Type set to I\r\n"))
    exchanges.append(("c", b"CWD /pub/data\r\n"))
    exchanges.append(("s", b"250 CWD command successful\r\n"))
    exchanges.append(("c", b"PWD\r\n"))
    exchanges.append(("s", b'257 "/pub/data" is the current directory\r\n'))
    if pasv:
        exchanges.append(("c", b"PASV\r\n"))
        exchanges.append(("s", b"227 Entering Passive Mode (10,10,0,20,195,80).\r\n"))
    exchanges.append(("c", b"RETR report.pdf\r\n"))
    exchanges.append(("s", b"150 Opening BINARY mode data connection\r\n"))
    exchanges.append(("s", b"226 Transfer complete\r\n"))
    exchanges.append(("c", b"QUIT\r\n"))
    exchanges.append(("s", b"221 Goodbye.\r\n"))
    return exchanges


def ftp_capture(dest: Path | None = None, *, user: str = "anonymous") -> Path:
    """FTP on the registered port 21, with a passive-mode data connection."""
    packets: list = []
    packets += tcp_stream(ftp_exchanges(user=user), sport=40241, dport=21, base=BASE_EPOCH)
    # The data connection the PASV pair announced: 10.10.0.20:50000.
    packets += tcp_stream(
        [("s", b"PDF-DATA" * 200)],
        src=SERVER,
        sport=50000,
        dst=CLIENT,
        dport=40241,
        base=BASE_EPOCH + 3,
    )
    packets.sort(key=lambda packet: packet.time)
    return write("ftp.pcap", packets, dest)


def ftp_midsession_capture(dest: Path | None = None) -> Path:
    """FTP commands with no greeting, on a non-standard port (rule 3 decides)."""
    exchanges = [
        ("c", b"TYPE I\r\n"),
        ("s", b"200 Type set to I\r\n"),
        ("c", b"CWD /pub/data\r\n"),
        ("s", b"250 CWD command successful\r\n"),
        ("c", b"STOR upload.bin\r\n"),
        ("s", b"150 Opening BINARY mode data connection\r\n"),
        ("s", b"226 Transfer complete\r\n"),
    ]
    packets = tcp_stream(exchanges, sport=40243, dport=2121, base=BASE_EPOCH)
    return write("ftp_midsession.pcap", packets, dest)


# --------------------------------------------------------------------------
# SIP, RTP and RTCP
# --------------------------------------------------------------------------

SIP_INVITE = (
    b"INVITE sip:bob@lab.test SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 10.10.0.10:5062;branch=z9hG4bK1\r\n"
    b"From: Alice <sip:alice@lab.test>;tag=1a2b\r\n"
    b"To: Bob <sip:bob@lab.test>\r\n"
    b"Call-ID: 8f9e1c0a4d2b@lab.test\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"User-Agent: ShadowPackets-TestUA/1.0\r\n"
    b"Content-Type: application/sdp\r\n"
    b"Content-Length: 121\r\n"
    b"\r\n"
    b"v=0\r\no=alice 1 1 IN IP4 10.10.0.10\r\ns=call\r\n"
    b"c=IN IP4 10.10.0.10\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0 8\r\n"
)


def sip_exchanges() -> list[tuple[str, bytes]]:
    return [
        ("c", SIP_INVITE),
        ("s", b"SIP/2.0 100 Trying\r\nCall-ID: 8f9e1c0a4d2b@lab.test\r\nCSeq: 1 INVITE\r\n\r\n"),
        ("s", b"SIP/2.0 180 Ringing\r\nCall-ID: 8f9e1c0a4d2b@lab.test\r\nCSeq: 1 INVITE\r\n\r\n"),
        (
            "s",
            b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.10.0.10:5062\r\n"
            b"From: Alice <sip:alice@lab.test>;tag=1a2b\r\nTo: Bob <sip:bob@lab.test>;tag=9f8e\r\n"
            b"Call-ID: 8f9e1c0a4d2b@lab.test\r\nCSeq: 1 INVITE\r\n"
            b"User-Agent: ShadowPackets-TestUAS/1.0\r\nContent-Type: application/sdp\r\nContent-Length: 96\r\n"
            b"\r\nv=0\r\no=bob 1 1 IN IP4 10.10.0.20\r\ns=call\r\n"
            b"c=IN IP4 10.10.0.20\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n",
        ),
        ("c", b"ACK sip:bob@lab.test SIP/2.0\r\nCall-ID: 8f9e1c0a4d2b@lab.test\r\nCSeq: 1 ACK\r\n\r\n"),
        ("c", b"BYE sip:bob@lab.test SIP/2.0\r\nCall-ID: 8f9e1c0a4d2b@lab.test\r\nCSeq: 2 BYE\r\n\r\n"),
        ("s", b"SIP/2.0 200 OK\r\nCall-ID: 8f9e1c0a4d2b@lab.test\r\nCSeq: 2 BYE\r\n\r\n"),
    ]


def rtp_packets(
    *,
    src: str = SERVER,
    dst: str = CLIENT,
    sport: int = 5004,
    dport: int = 5004,
    ssrc: int = 0x1A2B3C4D,
    payload_types: tuple[int, ...] = (0, 0, 8, 0),
    sequences: tuple[int, ...] = (1000, 1001, 1004, 1005),
    base: float = BASE_EPOCH + 20,
) -> list:
    """RTP with a sequence gap (1001 -> 1004) so ``packets_lost`` is exercised."""
    packets = []
    for index, (pt, seq) in enumerate(zip(payload_types, sequences)):
        packet = (
            Ether()
            / IP(src=src, dst=dst)
            / UDP(sport=sport, dport=dport)
            / RTP(version=2, payload_type=pt, sequence=seq, timestamp=160 * index, sourcesync=ssrc)
            / Raw(bytes(160))
        )
        packets.append(packet)
    return _stamp(packets, base)


def rtcp_packets(
    *,
    src: str = SERVER,
    dst: str = CLIENT,
    sport: int = 5005,
    dport: int = 5005,
    ssrc: int = 0x1A2B3C4D,
    base: float = BASE_EPOCH + 21,
) -> list:
    """An RTCP sender report (200) and receiver report (201)."""

    def sender_report() -> bytes:
        body = struct.pack(">IIIII", ssrc, 0xE0C0_0000, 0, 4, 640)
        return bytes([0x80, 200]) + struct.pack(">H", (len(body) // 4) + 1) + body

    def receiver_report() -> bytes:
        body = struct.pack(">I", ssrc) + struct.pack(">IBBBBI", 0x1A2B3C4E, 0, 0, 0, 0, 3)
        return bytes([0x81, 201]) + struct.pack(">H", (len(body) // 4) + 1) + struct.pack(">I", ssrc) + body

    packets = []
    for payload, offset in ((sender_report(), 0.0), (receiver_report(), 0.5)):
        packets.append(
            Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)
        )
    return _stamp(packets, base)


def sip_offport_capture(
    dest: Path | None = None, *, dport: int = 6070, with_responses: bool = False
) -> Path:
    """SIP on a port §1.2 does not list.

    A status line is the server-role message rule 2 looks for, so the two variants cover
    both remaining rules: with only requests there is nothing for rule 2 and rule 3 decides
    (the sender of the first frame); with responses the status line decides.
    """
    exchanges = sip_exchanges()
    if not with_responses:
        exchanges = [(direction, payload) for direction, payload in exchanges if direction == "c"]
    packets = udp_exchange(exchanges, sport=6072, dport=dport, base=BASE_EPOCH + 45)
    name = "sip_offport_status.pcap" if with_responses else "sip_offport.pcap"
    return write(name, packets, dest)


def voip_capture(dest: Path | None = None) -> Path:
    """SIP signalling on 5060 plus the RTP/RTCP media its SDP announces."""
    packets: list = []
    packets += udp_exchange(sip_exchanges(), sport=5062, dport=5060, base=BASE_EPOCH + 20)
    packets += rtp_packets()
    packets += rtcp_packets()
    packets.sort(key=lambda packet: packet.time)
    return write("voip.pcap", packets, dest)


def rtp_without_sip_capture(dest: Path | None = None) -> Path:
    """RTP between two hosts no SIP session names, for media_without_signalling."""
    packets = rtp_packets(
        src="10.10.0.99", dst="10.10.0.50", sport=6004, dport=6004,
        ssrc=0x0BADF00D, base=BASE_EPOCH + 40,
    )
    return write("rtp_no_sip.pcap", packets, dest)


# --------------------------------------------------------------------------
# SMB
# --------------------------------------------------------------------------

SMB2_HEADER_SIZE = 64
SMB2_NEGOTIATE = 0
SMB2_SESSION_SETUP = 1
SMB2_TREE_CONNECT = 3
SMB2_CREATE = 5
SMB2_CLOSE = 6
SMB2_READ = 8


def nbss(payload: bytes) -> bytes:
    """NetBIOS session service framing: one type byte and a three-byte length."""
    return struct.pack(">I", len(payload)) + payload


def smb2_header(
    command: int,
    *,
    status: int = 0,
    response: bool = False,
    mid: int = 1,
    tid: int = 0,
    session: int = 0,
) -> bytes:
    return b"\xfeSMB" + struct.pack(
        "<HHIHHIIQIIQ16s",
        64,                            # structure size
        0,                             # credit charge
        status,
        command,
        1,                             # credit request
        1 if response else 0,          # flags
        0,                             # next command
        mid,
        0,                             # reserved
        tid,
        session,
        b"\x00" * 16,                  # signature
    )


def smb2_negotiate_request(dialects: tuple[int, ...] = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)) -> bytes:
    body = struct.pack(
        "<HHHHI", 36, len(dialects), 1, 0, 0x00000040  # request: encryption capable
    ) + b"\x11" * 16 + struct.pack("<IH", 0, 0)
    return smb2_header(SMB2_NEGOTIATE, mid=0) + body + b"".join(
        struct.pack("<H", dialect) for dialect in dialects
    )


def smb2_negotiate_response(dialect: int = 0x0300, *, sign_required: bool = False, encryption: bool = False) -> bytes:
    body = struct.pack(
        "<HHHH16sIIIIQ",
        65,
        1 if sign_required else 0,   # SecurityMode: signing required
        dialect,
        0,
        b"\x22" * 16,
        0x00000040 if encryption else 0,
        1 << 20,
        1 << 20,
        1 << 20,
        0,
    ) + struct.pack("<QQHH", 0, 0, 72, 0)
    return smb2_header(SMB2_NEGOTIATE, response=True, mid=0) + body


def ntlmssp_authenticate(domain: str = "LAB", user: str = "alice", host: str = "WS01") -> bytes:
    """An NTLMSSP AUTHENTICATE message with the buffers laid out after the header."""
    domain_b = domain.encode("utf-16le")
    user_b = user.encode("utf-16le")
    host_b = host.encode("utf-16le")
    header_len = 64

    def secbuf(offset: int, length: int = 0) -> bytes:
        return struct.pack("<HHI", length, length, offset)

    offset_domain = header_len
    offset_user = offset_domain + len(domain_b)
    offset_host = offset_user + len(user_b)
    message = b"NTLMSSP\x00" + struct.pack("<I", 3)
    message += secbuf(header_len, 0)                       # LM response
    message += secbuf(header_len, 0)                       # NT response
    message += secbuf(offset_domain, len(domain_b))
    message += secbuf(offset_user, len(user_b))
    message += secbuf(offset_host, len(host_b))
    message += secbuf(offset_host + len(host_b), 0)         # session key
    message += struct.pack("<I", 0x00008201)
    return message + domain_b + user_b + host_b


def smb2_session_setup_request(*, guest: bool = False) -> bytes:
    blob = ntlmssp_authenticate(user="guest" if guest else "alice")
    offset = SMB2_HEADER_SIZE + 24
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, offset, len(blob), 0)
    return smb2_header(SMB2_SESSION_SETUP, mid=1) + body + blob


def smb2_session_setup_response(*, guest: bool = False, session: int = 0x1000) -> bytes:
    # SessionFlags bit 0 is SESSION_FLAGS_IS_GUEST, bit 1 is SESSION_FLAGS_IS_NULL.
    flags = 1 if guest else 0
    return smb2_header(
        SMB2_SESSION_SETUP, response=True, mid=1, session=session
    ) + struct.pack("<HHHH", 9, flags, 72, 0)


def smb2_tree_connect_request(path: str, *, tid: int = 1, mid: int = 2) -> bytes:
    name = path.encode("utf-16le")
    offset = SMB2_HEADER_SIZE + 8
    body = struct.pack("<HHHH", 9, 0, offset, len(name))
    return smb2_header(SMB2_TREE_CONNECT, mid=mid, tid=tid, session=0x1000) + body + name


def smb2_tree_connect_response(*, tid: int = 1, mid: int = 2, share_type: int = 1) -> bytes:
    body = struct.pack("<HBBII", 16, share_type, 0, 0, 0)
    return smb2_header(
        SMB2_TREE_CONNECT, response=True, mid=mid, tid=tid, session=0x1000
    ) + body


def smb2_create_request(name: str, *, mid: int = 3) -> bytes:
    """CREATE (0x05) carrying the file name the contract records as ``filenames``."""
    encoded = name.encode("utf-16le")
    offset = SMB2_HEADER_SIZE + 56
    body = struct.pack(
        "<HBBIQQIIIIIHHII",
        57,                     # structure size
        0,                      # security flags
        0,                      # requested oplock level
        2,                      # impersonation level
        0, 0,                   # SMB create flags, reserved
        0x00120089,             # desired access
        0x00000080,             # file attributes (normal)
        0x00000007,             # share access
        1,                      # create disposition (file open)
        0x00000040,             # create options (non-directory file)
        offset,                 # name offset
        len(encoded),           # name length
        0, 0,                   # create contexts
    )
    return smb2_header(SMB2_CREATE, mid=mid, tid=1, session=0x1000) + body + encoded


def smb2_create_response(*, mid: int = 3) -> bytes:
    body = struct.pack(
        "<HBBIQQQQQQII16sII",
        89,                     # structure size
        0,                      # oplock level
        0,                      # flags
        1,                      # create action (file opened)
        0, 0, 0, 0, 0, 0,       # times and sizes
        0x00000080,             # file attributes
        0,                      # reserved
        b"\x33" * 16,           # file id
        0, 0,                   # create contexts
    )
    return smb2_header(SMB2_CREATE, response=True, mid=mid, tid=1, session=0x1000) + body


def smb2_read_request(*, mid: int = 4, length: int = 512) -> bytes:
    body = struct.pack("<HBBIQ16sIIIHH", 49, 0, 0, length, 0, b"\x33" * 16, 0, 0, 0, 0, 0)
    return smb2_header(SMB2_READ, mid=mid, tid=1, session=0x1000) + body


def smb2_read_response(*, mid: int = 4, data: bytes = b"", status: int = 0) -> bytes:
    offset = SMB2_HEADER_SIZE + 16
    body = struct.pack("<HBBIII", 17, offset, 0, len(data), 0, 0) + data
    return smb2_header(
        SMB2_READ, response=True, status=status, mid=mid, tid=1, session=0x1000
    ) + body


def smb2_close_request(*, mid: int = 5) -> bytes:
    body = struct.pack("<HHI16s", 24, 0, 0, b"\x33" * 16)
    return smb2_header(SMB2_CLOSE, mid=mid, tid=1, session=0x1000) + body


def smb2_close_response(*, mid: int = 5, status: int = 0) -> bytes:
    body = struct.pack("<HHIIII", 60, 0, 0, 0, 0, 0)
    return smb2_header(
        SMB2_CLOSE, response=True, status=status, mid=mid, tid=1, session=0x1000
    ) + body


def smb2_capture(dest: Path | None = None, *, guest: bool = False, dialect: int = 0x0300) -> Path:
    """A complete SMB2 session: negotiate, session setup, tree connect, create, read, close."""
    exchanges = [
        ("c", nbss(smb2_negotiate_request())),
        ("s", nbss(smb2_negotiate_response(dialect, sign_required=False, encryption=True))),
        ("c", nbss(smb2_session_setup_request(guest=guest))),
        ("s", nbss(smb2_session_setup_response(guest=guest))),
        ("c", nbss(smb2_tree_connect_request(r"\\fileserver\Shared"))),
        ("s", nbss(smb2_tree_connect_response())),
        ("c", nbss(smb2_create_request("report.docx"))),
        ("s", nbss(smb2_create_response())),
        ("c", nbss(smb2_read_request())),
        ("s", nbss(smb2_read_response(data=b"PK\x03\x04" * 32))),
        ("c", nbss(smb2_close_request())),
        ("s", nbss(smb2_close_response())),
        ("c", nbss(smb2_tree_connect_request(r"\\fileserver\IPC$", mid=6))),
        ("s", nbss(smb2_tree_connect_response(mid=6))),
        # A failing request, so ``statuses`` carries a real NT status code.
        ("c", nbss(smb2_read_request(mid=7))),
        ("s", nbss(smb2_read_response(mid=7, status=0xC0000034))),
    ]
    packets = tcp_stream(exchanges, sport=40251, dport=445, base=BASE_EPOCH + 60)
    return write("smb2_guest.pcap" if guest else "smb2.pcap", packets, dest)


# --- SMB1 ------------------------------------------------------------------

SMB1_NEGOTIATE = 0x72
SMB1_CLOSE = 0x04


def smb1_header(
    command: int, *, status: int = 0, response: bool = False, flags2: int = 0xC801, tid: int = 0
) -> bytes:
    return (
        b"\xffSMB"
        + bytes([command])
        + struct.pack("<I", status)
        + bytes([0x98 if response else 0x18])     # Flags
        + struct.pack("<H", flags2)               # Flags2
        + struct.pack("<H", 0)                    # PID high
        + b"\x00" * 8                             # signature
        + struct.pack("<H", 0)                    # reserved
        + struct.pack("<H", tid)
        + struct.pack("<H", 0x1234)               # PID low
        + struct.pack("<H", 0)                    # UID
        + struct.pack("<H", 1)                    # MID
    )


def smb1_negotiate_request(dialects: tuple[str, ...] = ("NT LM 0.12", "SMB 2.002")) -> bytes:
    buffer = b"".join(b"\x02" + dialect.encode() + b"\x00" for dialect in dialects)
    return smb1_header(SMB1_NEGOTIATE) + bytes([0]) + struct.pack("<H", len(buffer)) + buffer


def smb1_negotiate_response(dialect_index: int = 0, *, flags2: int = 0x0801) -> bytes:
    words = struct.pack(
        "<HBHHIIIIIIHb",
        dialect_index,   # DialectIndex 0 = "NT LM 0.12", i.e. SMB1
        3,               # SecurityMode: signing enabled and required
        50,              # MaxMpxCount
        1,               # MaxNumberVcs
        16644,           # MaxBufferSize
        65535,           # MaxRawSize
        0,               # SessionKey
        0x000000F4,      # Capabilities
        0, 0,            # SystemTime low/high
        0,               # ServerTimeZone
        8,               # ChallengeLength
    )
    return (
        smb1_header(SMB1_NEGOTIATE, response=True, flags2=flags2)
        + bytes([len(words) // 2])
        + words
        + struct.pack("<H", 8)
        + b"\x01\x02\x03\x04\x05\x06\x07\x08"
    )


def smb1_close_request(*, tid: int = 1) -> bytes:
    return smb1_header(SMB1_CLOSE, tid=tid) + bytes([3]) + struct.pack("<HH", 0x1234, 0) + struct.pack("<H", 0)


def smb1_close_response(*, tid: int = 1, status: int = 0) -> bytes:
    return (
        smb1_header(SMB1_CLOSE, response=True, status=status, tid=tid)
        + bytes([0])
        + struct.pack("<H", 0)
    )


def smb2_offport_capture(dest: Path | None = None, *, dport: int = 1445) -> Path:
    """SMB2 on a non-standard port: no registered port, so §1.2 rule 3 decides."""
    exchanges = [
        ("c", nbss(smb2_negotiate_request())),
        ("s", nbss(smb2_negotiate_response(0x0302, sign_required=True, encryption=False))),
    ]
    packets = tcp_stream(exchanges, sport=40253, dport=dport, base=BASE_EPOCH + 75)
    return write("smb2_offport.pcap", packets, dest)


def smb1_capture(dest: Path | None = None, *, sign_required: bool = False) -> Path:
    """An SMB1-only session: a negotiate pair and a close, with no SMB2 frame at all."""
    flags2 = 0x0801 if sign_required else 0x0001
    exchanges = [
        ("c", nbss(smb1_negotiate_request())),
        ("s", nbss(smb1_negotiate_response(flags2=flags2))),
        ("c", nbss(smb1_close_request())),
        ("s", nbss(smb1_close_response())),
    ]
    packets = tcp_stream(exchanges, sport=40252, dport=445, base=BASE_EPOCH + 90)
    return write("smb1.pcap", packets, dest)


# --------------------------------------------------------------------------
# every capture at once
# --------------------------------------------------------------------------

BUILDERS = {
    "email": email_capture,
    "smtp_submission": smtp_submission_capture,
    "smtp_midsession": smtp_midsession_capture,
    "smtp_twin": smtp_twin_capture,
    "smtp_many": smtp_many_commands_capture,
    "ssh": ssh_capture,
    "ssh_offport": ssh_offport_capture,
    "sip_offport": sip_offport_capture,
    "sip_offport_status": lambda dest=None: sip_offport_capture(
        dest, dport=6071, with_responses=True
    ),
    "ftp": ftp_capture,
    "ftp_midsession": ftp_midsession_capture,
    "voip": voip_capture,
    "rtp_no_sip": rtp_without_sip_capture,
    "smb2": smb2_capture,
    "smb2_offport": smb2_offport_capture,
    "smb2_guest": lambda dest=None: smb2_capture(dest, guest=True),
    "smb1": smb1_capture,
}


def build_all(dest: Path | None = None) -> dict[str, Path]:
    return {name: builder(dest) for name, builder in BUILDERS.items()}
