import { useMemo, type CSSProperties } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { ScanSearch } from 'lucide-react'
import pageBackground from '@/assets/hunt_bg.jpg'
import AnalysisGuard from '@/components/AnalysisGuard'
import EmptyState from '@/components/EmptyState'
import ErrorState from '@/components/ErrorState'
import LoadingState from '@/components/LoadingState'
import Page from '@/components/Page'
import { SectionNote } from '@/components/protocols/ProtocolDetail'
import EntitySearch, { KIND_HUE, KIND_LABEL, KindIcon } from '@/components/profile/EntitySearch'
import EntitySummary from '@/components/profile/EntitySummary'
import QuestionTile, { profileHueStyle } from '@/components/profile/QuestionTile'
import { useAnalysis } from '@/hooks/useAnalysis'
import { profileApi } from '@/services/api'
import { SECTIONS } from '@/theme/sections'
import { formatNumber } from '@/utils/format'
import type { EntityProfile, ProfileKind } from '@/types'

/**
 * Hunt — look up one address, domain name or URL and read everything this
 * capture recorded about it (docs/ENTITY_PROFILE.md).
 *
 * The page is a lookup, not a listing, so it is built unlike the rest of the app:
 * a centred head with the search box in it, then a grid of small widgets, one per
 * question, each with its own chart and its own hue. The questions are the same
 * card contract the Threat Map uses, which is why one set of renderers draws both.
 *
 * The selected entity lives in the URL (`?kind=ip&entity=…`), so a profile is
 * shareable, survives a reload, and can be linked to from anywhere in the app.
 * Nothing is fetched until an entity is chosen, and nothing here re-dissects a
 * capture: both requests are SQL over the analysis' indexed tables.
 */

/** One entry of the question index shown before anything is looked up. */
interface QuestionRef {
  id: string
  title: string
}

/**
 * The questions of §4, in contract order.
 *
 * This is the page's own copy of the contract's id list, and it exists for two
 * reasons: it is the index a reader sees before choosing an entity, and it is what
 * the page checks a response against, so a question the backend returns that this
 * build has never heard of is still drawn rather than dropped.
 */
const QUESTIONS: Record<ProfileKind, readonly QuestionRef[]> = {
  ip: [
    { id: 'volume_by_direction', title: 'Volume by direction' },
    { id: 'activity_over_time', title: 'Activity over time' },
    { id: 'connections', title: 'Conversations' },
    { id: 'peer_fanout', title: 'Peer fan-out' },
    { id: 'ports_offered', title: 'Ports offered' },
    { id: 'ports_contacted', title: 'Ports contacted' },
    { id: 'protocol_mix', title: 'Protocol mix' },
    { id: 'domains_resolved', title: 'Domains resolved' },
    { id: 'domains_contacted', title: 'Domains contacted' },
    { id: 'dns_health', title: 'DNS health' },
    { id: 'http_activity', title: 'HTTP activity' },
    { id: 'clear_text_credentials', title: 'Clear-text credentials' },
    { id: 'files', title: 'Files transferred' },
    { id: 'tls_fingerprints', title: 'TLS fingerprints' },
    { id: 'fingerprint_peers', title: 'Peers sharing a fingerprint' },
    { id: 'findings', title: 'Findings and signatures' },
  ],
  domain: [
    { id: 'clients', title: 'Clients that asked' },
    { id: 'answers', title: 'Resolved addresses' },
    { id: 'rcodes', title: 'Resolver answers' },
    { id: 'activity_over_time', title: 'Activity over time' },
    { id: 'tls_sessions', title: 'TLS handshakes naming it' },
    { id: 'http_transactions', title: 'HTTP requests addressed to it' },
    { id: 'files', title: 'Files fetched from it' },
    { id: 'findings', title: 'Findings and signatures' },
  ],
  url: [
    { id: 'clients', title: 'Clients that requested it' },
    { id: 'status_codes', title: 'Status codes' },
    { id: 'methods', title: 'Methods' },
    { id: 'activity_over_time', title: 'Activity over time' },
    { id: 'request_shape', title: 'Request shape' },
    { id: 'files', title: 'Files returned' },
    { id: 'findings', title: 'Findings and signatures' },
  ],
}

const KINDS: readonly ProfileKind[] = ['ip', 'domain', 'url']

/** The question index: what this page will ask, before anything has been chosen. */
function QuestionIndex({ kind }: { kind: ProfileKind }) {
  const refs = QUESTIONS[kind]
  const hue = KIND_HUE[kind]
  return (
    <section className="panel" data-profile-index={kind}>
      <div className="panel-header">
        <div className="min-w-0">
          <div className="panel-title">
            {formatNumber(refs.length)} questions about one {KIND_LABEL[kind] === 'IP' ? 'address' : KIND_LABEL[kind]}
          </div>
          <div
            className="panel-subtitle"
            title="Each question becomes a widget with its own chart once an entity is opened. The numbers are the contract's question ids, so this list and the response cannot drift apart."
          >
            one widget each, with its own chart
          </div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5 p-3">
        {refs.map((ref, index) => (
          <span
            key={ref.id}
            className="signal-question-chip"
            style={profileHueStyle(index)}
            title={ref.id}
            data-profile-index-item={ref.id}
          >
            <span className="mono text-2xs text-faint">{String(index + 1).padStart(2, '0')}</span>
            <span className="text-xs">{ref.title}</span>
          </span>
        ))}
        <span
          className="chip signal-kind"
          style={{ '--kind-hue': `var(${hue})` } as CSSProperties}
          title="Every widget is answered from this capture's indexed tables"
        >
          <KindIcon kind={kind} />
          {KIND_LABEL[kind]}
        </span>
      </div>
    </section>
  )
}

/** The three kinds this page can be pointed at, with their question counts. */
function KindIndex() {
  const [searchParams, setSearchParams] = useSearchParams()
  const kind = searchParams.get('kind')
  const selected: ProfileKind = kind === 'ip' || kind === 'domain' || kind === 'url' ? kind : 'ip'
  const set = (next: ProfileKind) => {
    const params = new URLSearchParams(searchParams)
    if (next === 'ip') params.delete('kind')
    else params.set('kind', next)
    setSearchParams(params, { replace: true })
  }
  return (
    <div className="flex flex-wrap items-center justify-center gap-1.5" data-profile-kind-tabs>
      {KINDS.map((each) => {
        const active = each === selected
        return (
          <button
            key={each}
            type="button"
            onClick={() => set(each)}
            aria-pressed={active}
            data-profile-kind={each}
            className="chip signal-kind"
            style={
              {
                '--kind-hue': `var(${KIND_HUE[each]})`,
                opacity: active ? 1 : 0.55,
              } as CSSProperties
            }
            title={`Show the questions asked about ${each === 'ip' ? 'an address' : `a ${KIND_LABEL[each]}`}`}
          >
            <KindIcon kind={each} />
            {KIND_LABEL[each]} · {formatNumber(QUESTIONS[each].length)}
          </button>
        )
      })}
    </div>
  )
}

/**
 * The profile itself: the entity's own facts, then one widget per question.
 *
 * Every returned question is drawn, in the order the backend returned it, with its
 * index taken from that order — so a question keeps its colour and its number on
 * every entity. `truncated` keys are surfaced rather than hidden, because "the first
 * fifty" and "all of them" are different claims.
 */
function InvestigateProfile({
  selected,
  onClear,
}: {
  selected: { kind: ProfileKind; entity: string }
  onClear: () => void
}) {
  const { analysisId } = useAnalysis()

  /* Deliberately not `keepPreviousData`: the previous entity's numbers must never
     stay on screen under the new entity's name, and a profile is a fixed set of
     aggregates that answers in well under a second (§8 of the contract document).
     The loading state names the entity being read instead. */
  const query = useQuery({
    queryKey: ['entity-profile', analysisId, selected.kind, selected.entity],
    queryFn: () => profileApi.get(analysisId as string, selected.kind, selected.entity),
    enabled: Boolean(analysisId),
  })

  const data: EntityProfile | undefined = query.data
  const questions = data?.questions ?? []
  const expected = useMemo(
    () => new Set(QUESTIONS[selected.kind].map((ref) => ref.id)),
    [selected.kind],
  )
  const missing = data === undefined ? [] : QUESTIONS[selected.kind].filter(
    (ref) => !questions.some((question) => question.id === ref.id),
  )
  const extra = questions.filter((question) => !expected.has(question.id))
  const answered = questions.filter((question) => question.availability === 'ok').length
  const capped = Object.entries(data?.truncated ?? {}).filter(([, cut]) => cut === true)

  if (query.isLoading) {
    return (
      <LoadingState
        label={`Reading everything this capture recorded about ${selected.entity}…`}
        rows={6}
      />
    )
  }

  if (query.error) {
    return (
      <ErrorState
        error={query.error}
        title="Could not load this entity’s profile"
        onRetry={() => void query.refetch()}
      />
    )
  }

  if (data === undefined) {
    return (
      <EmptyState
        icon={ScanSearch}
        title="The backend returned no profile payload"
        description="The request succeeded but carried no envelope, so there is nothing to draw. No widget is filled in from anything other than the response."
      />
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <EntitySummary profile={data} onClear={onClear} />

      {missing.length > 0 ? (
        <SectionNote tone="warn">
          {`The contract asks ${String(QUESTIONS[selected.kind].length)} questions about ${
            selected.kind === 'ip' ? 'an address' : `a ${KIND_LABEL[selected.kind]}`
          } and this response has no widget for ${missing.map((ref) => ref.id).join(', ')}. A question that was not answered is reported here rather than left out.`}
        </SectionNote>
      ) : null}

      {extra.length > 0 ? (
        <SectionNote tone="warn">
          {`This response carries ${String(extra.length)} question(s) this build of ShinboShark has no index entry for (${extra
            .map((question) => question.id)
            .join(', ')}). They are drawn below rather than dropped.`}
        </SectionNote>
      ) : null}

      <div className="flex flex-wrap items-center gap-2 px-1">
        <p className="text-xs text-muted">
          <span className="mono text-text">{formatNumber(answered)}</span> of{' '}
          <span className="mono text-text">{formatNumber(questions.length)}</span> answered
        </p>
        {capped.length > 0 ? (
          <span
            className="chip border-warn/40 bg-warn/10 text-warn"
            title={`These questions' charts were cut to their contract cap; their numbers count every row: ${capped
              .map(([key]) => key)
              .join(', ')}`}
          >
            {formatNumber(capped.length)} chart(s) capped
          </span>
        ) : null}
        <span className="ml-auto text-2xs text-faint" title="A greyed widget is a question this capture could not answer; hover any widget for what it may indicate, what it does not prove and why.">
          greyed = not answered · hover a widget for its reasoning
        </span>
      </div>

      <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4" data-profile-grid>
        {questions.map((question, index) => (
          <QuestionTile
            key={question.id}
            question={question}
            index={index}
            capped={data.truncated[question.id] === true}
          />
        ))}
      </div>

      <p
        className="px-1 pb-1 text-2xs text-faint"
        title="Every number is read from this analysis' indexed tables: nothing is estimated, sampled or filled in. A question this capture cannot answer says so instead of showing a zero, and a widget below its threshold still shows the numbers that stayed under it. Read a widget as a direction to look in, then check the rows behind it through the links it carries."
      >
        Measured from this capture’s index, never estimated.
      </p>
    </div>
  )
}

/** What the page shows before an entity has been chosen. */
function InvestigateStart() {
  const [searchParams] = useSearchParams()
  const kind = searchParams.get('kind')
  const selected: ProfileKind = kind === 'ip' || kind === 'domain' || kind === 'url' ? kind : 'ip'
  return (
    <div className="flex flex-col items-center gap-3">
      <KindIndex />
      <div className="w-full">
        <QuestionIndex kind={selected} />
      </div>
      <p
        className="max-w-3xl px-1 text-2xs text-faint"
        title="Type an address, a name or a URL into the search above and pick a suggestion, or press Enter to open exactly what you typed. Matching is over this capture's own tables, so a name that never appears here is never offered - and an entity this capture never recorded still opens, with every question stating why it cannot be answered."
      >
        Search an address, a name or a URL. Nothing is resolved online.
      </p>
    </div>
  )
}

/** Hunt — a lookup, then one coloured widget per question. */
export function InvestigatePage() {
  const { analysisId } = useAnalysis()
  const [searchParams, setSearchParams] = useSearchParams()

  const kindParam = searchParams.get('kind')
  const kind: ProfileKind | null =
    kindParam === 'ip' || kindParam === 'domain' || kindParam === 'url' ? kindParam : null
  const entityParam = searchParams.get('entity')
  const entity = entityParam !== null && entityParam.trim() !== '' ? entityParam : null
  const selected = kind !== null && entity !== null ? { kind, entity } : null

  /* The selection is the URL, so Back leaves a profile and returns to the search. */
  const pick = (nextKind: ProfileKind, nextEntity: string) => {
    const params = new URLSearchParams(searchParams)
    params.set('kind', nextKind)
    params.set('entity', nextEntity)
    setSearchParams(params)
  }

  const clear = () => {
    const params = new URLSearchParams(searchParams)
    params.delete('entity')
    setSearchParams(params)
  }

  return (
    <Page
      section={SECTIONS.investigate}
      headerImage={pageBackground}
      meta={
        analysisId !== null ? (
          <EntitySearch
            analysisId={analysisId}
            current={selected}
            onPick={pick}
            onClear={clear}
          />
        ) : null
      }
    >
      <AnalysisGuard emptyDescription="Upload a PCAP/PCAPNG capture or select an existing analysis in the top bar to look one address, name or URL up in it. Hunt reads only tables that already exist, so it needs a finished analysis.">
        {selected === null ? (
          <InvestigateStart />
        ) : (
          <InvestigateProfile selected={selected} onClear={clear} />
        )}
      </AnalysisGuard>
    </Page>
  )
}

export default InvestigatePage
