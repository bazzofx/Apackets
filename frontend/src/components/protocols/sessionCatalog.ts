import type { ScopeNoteItem } from './ProtocolDetail'
import type { FlagCatalog } from './ProtocolFlags'
import type { ProtocolFamily, ProtocolName } from '@/types'

/**
 * The catalogues the five protocol-session pages share (docs/PROTOCOLS.md).
 *
 * The five pages are one component with a different family, so everything that differs
 * between them lives here: which protocols a family covers, what to call each one, which
 * detail keys get a human label, the lead-flag catalogue, and the one sentence each page
 * uses to say what it can and cannot read. Nothing here decides anything about the data —
 * it is presentation for a shape the contract already fixes.
 */

/** The protocols each page asks the endpoint for. */
export const FAMILY_PROTOCOLS: Record<ProtocolFamily, ProtocolName[]> = {
  email: ['smtp', 'pop3', 'imap'],
  ssh: ['ssh'],
  ftp: ['ftp'],
  voip: ['sip', 'rtp', 'rtcp'],
  smb: ['smb'],
}

/** Display names, so a table cell never prints a raw identifier from the wire. */
export const PROTOCOL_LABELS: Record<ProtocolName, string> = {
  smtp: 'SMTP',
  pop3: 'POP3',
  imap: 'IMAP',
  ssh: 'SSH',
  ftp: 'FTP',
  sip: 'SIP',
  rtp: 'RTP',
  rtcp: 'RTCP',
  smb: 'SMB',
}

/**
 * Labels for the `detail` keys of contract §3.
 *
 * A key with no entry is still rendered — the renderer falls back to the key with its
 * underscores turned into spaces — so a key the backend adds cannot vanish from the page
 * just because this map has not learned it yet.
 */
export const DETAIL_LABELS: Record<string, string> = {
  commands: 'Commands',
  response_codes: 'Response codes',
  response_indicators: 'Response indicators',
  statuses: 'Statuses',
  messages: 'Handshake messages',
  helo: 'Client announced itself as',
  mail_from: 'Envelope senders',
  rcpt_to: 'Envelope recipients',
  auth_username: 'Authenticated as',
  auth_mechanisms: 'Auth mechanisms',
  password_present: 'Password crossed the wire',
  data_blocks: 'DATA transfers',
  username: 'User name',
  retrieved: 'Messages retrieved',
  deleted: 'Messages deleted',
  message_count: 'Messages reported',
  fetches: 'FETCH commands',
  folders: 'Mailboxes',
  client_banner: 'Client banner',
  server_banner: 'Server banner',
  kex_algorithms: 'Key exchange algorithms',
  server_host_key_algorithms: 'Host key algorithms',
  encryption_client_to_server: 'Ciphers, client to server',
  encryption_server_to_client: 'Ciphers, server to client',
  mac_client_to_server: 'MACs, client to server',
  paths: 'Directories entered',
  files_requested: 'Files asked for',
  data_streams: 'Data connections',
  methods: 'Methods',
  status_codes: 'Status codes',
  call_ids: 'Call-IDs',
  from_users: 'From',
  to_users: 'To',
  request_uris: 'Request URIs',
  user_agents: 'User agents',
  ssrc: 'Synchronisation source',
  payload_types: 'Payload types',
  packets_lost: 'Sequence gaps seen',
  rtcp_packet_types: 'RTCP packet types',
  dialects: 'Dialects',
  trees: 'Shares connected',
  filenames: 'File names requested',
  signing_required: 'Signing required',
  encryption_capable: 'Encryption advertised',
  server: 'Server name',
}

/** The lead-flag catalogue for these five sections (contract §4). */
export const SESSION_FLAG_CATALOG: FlagCatalog = {
  cleartext_credentials: {
    label: 'cleartext credentials',
    meaning:
      'A password crossed this session without transport encryption. Worth reviewing because it is readable by anything on the path — and it is also what plain legacy clients and badly configured mail, FTP or POP3 servers do, so it says the session was unencrypted, not that anyone abused it.',
  },
  cleartext_username: {
    label: 'cleartext user name',
    meaning:
      'A user name was sent in the clear. It identifies who was using the session; on its own it is normal for the protocols that do not encrypt, which is why it is a low flag rather than a finding.',
  },
  no_encryption_upgrade: {
    label: 'no encryption upgrade',
    meaning:
      'The session ran on a port that carries this protocol in the clear and expects an optional upgrade, and never negotiated TLS. That covers 25 and 587 for SMTP, 110 for POP3, 143 for IMAP and 21 for FTP. Common on internal and legacy infrastructure, and also what a downgrade attack looks like — the packets decide which.',
  },
  anonymous_login: {
    label: 'anonymous login',
    meaning:
      'An anonymous, guest or default-style identity was attempted or accepted. Anonymous FTP and guest SMB are legitimate in some estates and are a way into others; the share or directory it reached is the question that follows.',
  },
  legacy_dialect: {
    label: 'legacy dialect',
    meaning:
      'An SMB1 session was negotiated. SMB1 is obsolete and its signing is weak, which is why it is worth reviewing — plenty of older embedded devices and printers still offer nothing else.',
  },
  signing_not_required: {
    label: 'signing not required',
    meaning:
      'The negotiation did not require SMB signing, so this session’s traffic is not integrity-protected against a relay. It is the default on many servers, and only exploitable when combined with a relay opportunity.',
  },
  unusual_port: {
    label: 'unusual port',
    meaning:
      'The server side of this session was on none of the ports this protocol is expected on. A deliberate non-standard port is a normal hardening or evasion choice; the protocol’s own content is what makes the session that protocol at all.',
  },
  large_transfer: {
    label: 'large transfer',
    meaning:
      'The session moved more than the configured threshold. Backups, software deployment and media all do this, so the direction and the peer are what make it worth reading.',
  },
  many_commands: {
    label: 'many commands',
    meaning:
      'The session issued an unusually high number of commands. Bulk mailbox operations and file mirroring look the same as enumeration; the commands themselves distinguish them.',
  },
  long_session: {
    label: 'long session',
    meaning:
      'The session stayed open longer than the configured threshold. Keep-alives, sync clients and interactive shells all do this.',
  },
  media_without_signalling: {
    label: 'media without signalling',
    meaning:
      'RTP or RTCP was seen with no SIP session naming those addresses in this capture. The signalling may simply be outside the capture window or on another interface — which is a limit of the capture, not an observation about the traffic.',
  },
  auth_failures: {
    label: 'authentication failures',
    meaning:
      'Repeated rejected authentications on one session. Clients with stale saved passwords produce exactly this pattern, and so does password guessing.',
  },
}

/** Every flag key, in catalogue order, for the legend. */
export const SESSION_FLAG_KEYS: string[] = Object.keys(SESSION_FLAG_CATALOG)

/** The one-line summary a row shows of what the session actually said. */
export function sessionSummary(protocol: ProtocolName, detail: Record<string, unknown>): string {
  const list = (key: string): string[] => {
    const value = detail[key]
    return Array.isArray(value) ? value.map((item) => String(item)) : []
  }
  const text = (key: string): string => {
    const value = detail[key]
    return typeof value === 'string' ? value : ''
  }
  const commands = (key: string): string[] => {
    const value = detail[key]
    if (!Array.isArray(value)) return []
    return value
      .map((item) => {
        if (item === null || typeof item !== 'object') return ''
        const record = item as Record<string, unknown>
        const verb = String(record.verb ?? record.key ?? '')
        const arg = typeof record.arg === 'string' && record.arg !== '' ? ` ${record.arg}` : ''
        const count = typeof record.count === 'number' && record.count > 1 ? ` ×${String(record.count)}` : ''
        return `${verb}${arg}${count}`.trim()
      })
      .filter((item) => item !== '')
  }
  const countMap = (key: string): string => {
    const value = detail[key]
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return ''
    return Object.entries(value as Record<string, number>)
      .map(([name, count]) => `${name} ×${String(count)}`)
      .join(', ')
  }

  switch (protocol) {
    case 'smtp': {
      const from = list('mail_from')[0] ?? text('helo')
      const recipients = list('rcpt_to').length
      const parts = [from !== '' ? `from ${from}` : '', recipients > 0 ? `${String(recipients)} recipient(s)` : '']
      return parts.filter((part) => part !== '').join(', ') || commands('commands').slice(0, 6).join(', ')
    }
    case 'pop3':
    case 'imap': {
      const who = text('username') !== '' ? `as ${text('username')}` : ''
      const verbs = commands('commands').slice(0, 5).join(', ')
      return [who, verbs].filter((part) => part !== '').join(' · ')
    }
    case 'ssh':
      return (
        [text('client_banner'), text('server_banner')].filter((part) => part !== '').join(' → ') ||
        countMap('messages')
      )
    case 'ftp': {
      const files = list('files_requested')
      const verbs = commands('commands').slice(0, 5).join(', ')
      const file = files.length > 0 ? ` · ${String(files.length)} file(s): ${files.slice(0, 3).join(', ')}` : ''
      return `${verbs}${file}`
    }
    case 'sip':
      return [countMap('methods'), countMap('status_codes')].filter((part) => part !== '').join(' · ')
    case 'rtp':
    case 'rtcp':
      return [countMap('payload_types') || countMap('rtcp_packet_types'), text('ssrc') !== '' ? `ssrc ${text('ssrc')}` : '']
        .filter((part) => part !== '')
        .join(' · ')
    case 'smb': {
      const dialects = list('dialects')
      const trees = list('trees')
      const names = list('filenames')
      const parts = [
        dialects.length > 0 ? dialects.join('/') : '',
        trees.length > 0 ? `share ${trees.slice(0, 2).join(', ')}` : '',
        names.length > 0 ? `${String(names.length)} file name(s)` : '',
      ]
      return parts.filter((part) => part !== '').join(' · ') || countMap('commands')
    }
    default:
      return ''
  }
}

/** What each page says about itself, in the collapsible note above its table. */
export const FAMILY_SCOPE: Record<
  ProtocolFamily,
  { title: string; items: ScopeNoteItem[]; caveat: string }
> = {
  email: {
    title: 'How to read this section',
    items: [
      {
        can: true,
        text: 'One row per mail session: the endpoints, when it ran, the volume in each direction, and the commands, reply codes, envelope addresses and mailboxes the dissector produced.',
      },
      {
        can: true,
        text: 'Clear-text authentication: a session that sent AUTH, USER/PASS or LOGIN without TLS is flagged, with the user name and the mechanism recorded. Only the presence of a password is recorded, never its value.',
      },
      {
        can: false,
        text: 'Message contents. Bodies and attachments are not copied into this table — carved content is the Files and Objects page\'s job.',
      },
      {
        can: false,
        text: 'Sessions where the mail ran inside TLS on a non-standard port the dissector did not decode: the handshake is TLS, and shows up on the TLS page instead.',
      },
      {
        can: false,
        text: 'Anything from a capture indexed before this section existed: those analyses hold no session rows until they are re-read, which the button above the table does.',
      },
    ],
    caveat:
      'A session is a connection, not a person or a mailbox. The addresses are what the wire carried; nothing here proves who read the mail.',
  },
  ssh: {
    title: 'How to read this section',
    items: [
      {
        can: true,
        text: 'The identification banners both sides announced, the key-exchange, host-key, cipher and MAC algorithms they offered, and a histogram of handshake message types.',
      },
      {
        can: true,
        text: 'Which endpoint was the client and which the server, and the volume in each direction — enough to see an interactive session next to a bulk transfer.',
      },
      {
        can: false,
        text: 'Session content. SSH encrypts after the key exchange, so commands, file names and passwords are not in this capture in readable form and are not guessed at here.',
      },
      {
        can: false,
        text: 'Authentication outcomes for most sessions: the method and result are inside the encrypted channel, so a session that authenticated and one that failed can look identical.',
      },
      {
        can: false,
        text: 'Any claim about the client’s operator. A banner names software and often a version, not a person.',
      },
    ],
    caveat:
      'A banner is software’s own claim about itself. It can be changed by anything that felt like changing it.',
  },
  ftp: {
    title: 'How to read this section',
    items: [
      {
        can: true,
        text: 'The control channel in full: every command with its argument, every reply code, the directories entered and the file names asked for.',
      },
      {
        can: true,
        text: 'Clear-text credentials, which FTP sends by default: USER and PASS are recorded as an identity plus the presence of a password.',
      },
      {
        can: true,
        text: 'How many data connections the session opened, so a directory listing is distinguishable from a transfer.',
      },
      {
        can: false,
        text: 'File contents. Only names are recorded — the bytes are the Files and Objects page\'s job, and only where the application can carve them.',
      },
      {
        can: false,
        text: 'FTPS and SFTP. The first is FTP inside TLS, the second is a subsystem of SSH; neither shows a readable command channel here.',
      },
    ],
    caveat:
      'A file name is a string the client sent. Whether the transfer succeeded, and what the file held, are separate questions this table does not answer.',
  },
  voip: {
    title: 'How to read this section',
    items: [
      {
        can: true,
        text: 'SIP signalling: the methods and status codes, the parties in the From, To and request URI fields, the Call-IDs and the user agents.',
      },
      {
        can: true,
        text: 'The RTP and RTCP streams that carried media, with their payload type numbers, synchronisation source and packet counts.',
      },
      {
        can: false,
        text: 'Audio or video. The media itself is not decoded, transcribed or stored.',
      },
      {
        can: false,
        text: 'Codecs, unless the dissector itself printed one: a payload type number is a number this build does not translate into a codec name.',
      },
      {
        can: false,
        text: 'A call count as a claim about conversations. RTP is media seen; without SIP signalling in the same capture, this page says so rather than inventing a call.',
      },
    ],
    caveat:
      'Media and signalling are separate streams: an RTP row without a SIP row means the signalling was elsewhere, not that no call happened.',
  },
  smb: {
    title: 'How to read this section',
    items: [
      {
        can: true,
        text: 'The negotiation: the dialects offered, whether signing was required and whether encryption was advertised, plus the server name when it crossed the wire.',
      },
      {
        can: true,
        text: 'The shares connected, the file names requested, the command counts and every NT status — including the failures, which is often the interesting half.',
      },
      {
        can: false,
        text: 'File contents, and anything inside an encrypted SMB3 session: those sessions record endpoints, times, volume and the negotiation, and nothing else.',
      },
      {
        can: false,
        text: 'Authentication material. SMB hashes and tickets are not in the clear here and are not reconstructed.',
      },
      {
        can: false,
        text: 'Sessions the dissector did not decode, including SMB inside a tunnel or on a port it was not told to treat as SMB.',
      },
    ],
    caveat:
      'A share name and a file name are strings the client sent. Whether an open succeeded is answered by the NT status on the same row, not by the name.',
  },
}
