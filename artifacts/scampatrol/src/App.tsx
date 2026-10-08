import { useState, type FormEvent } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import {
  Activity, AlertOctagon, AlertTriangle, ArrowRight, BadgeCheck, Ban, BellRing,
  ChevronLeft, FileSearch, Fingerprint, Link2, LoaderCircle, MessageSquareText, Phone,
  Radar, Search, Shield, ShieldAlert, ShieldCheck, Signal, Target, TriangleAlert,
} from 'lucide-react';
import {
  getGetDashboardQueryKey, getGetIncidentQueryKey, getGetIncidentsQueryKey,
  getGetReputationQueryKey, useCreateScan, useGetDashboard, useGetIncident,
  useGetIncidents, useGetReputation, useReportIncident,
  type Dashboard, type ScanResult,
} from '@workspace/api-client-react';
import { Route, Switch, Link, useLocation, Router as WouterRouter } from 'wouter';
import NotFound from '@/pages/not-found';

const queryClient = new QueryClient();
type ScanKind = 'message' | 'url' | 'phone' | 'call';
type IncidentRecord = Dashboard['recentIncidents'][number];
type ScanResultRecord = ScanResult;
const kinds: { id: ScanKind; label: string; icon: typeof MessageSquareText }[] = [
  { id: 'message', label: 'Message', icon: MessageSquareText },
  { id: 'url', label: 'URL', icon: Link2 },
  { id: 'phone', label: 'Phone', icon: Phone },
  { id: 'call', label: 'Call', icon: BellRing },
];

function dateLabel(value?: string) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(date);
}
function shortDate(value?: string) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { weekday: 'short' }).format(date);
}
function riskTone(score: number) {
  if (score >= 70) return 'blocked';
  if (score >= 35) return 'caution';
  return 'safe';
}
function StatusBadge({ status }: { status: string }) {
  return <span className={`badge ${status}`} data-testid={`status-incident-${status}`}>{status}</span>;
}
function LoadingPanel({ rows = 3 }: { rows?: number }) {
  return <div className="panel loading-panel" aria-label="Loading data" data-testid="state-loading">{Array.from({ length: rows }, (_, index) => <div className="skeleton skeleton-line" key={index} style={{ width: `${90 - index * 13}%` }} />)}</div>;
}
function ErrorState({ retry, message = 'We could not load this information right now.' }: { retry: () => void; message?: string }) {
  return <div className="error-box" data-testid="state-error"><p className="error-title">A little interference</p><p className="error-copy">{message}</p><button className="button-secondary" onClick={retry} data-testid="button-retry">Try again</button></div>;
}
function EmptyState({ title, copy }: { title: string; copy: string }) {
  return <div className="empty-box" data-testid="state-empty"><p className="empty-title">{title}</p><p className="empty-copy">{copy}</p></div>;
}
function IncidentTable({ incidents }: { incidents: IncidentRecord[] }) {
  if (!incidents.length) return <EmptyState title="No incidents yet" copy="When ScamPatrol checks a target, its explanation will be kept here." />;
  return <div className="table-wrap"><table className="incident-table" data-testid="table-recent-incidents">
    <thead><tr><th>Target</th><th>Type</th><th>Risk</th><th>Outcome</th><th>Checked</th><th /></tr></thead>
    <tbody>{incidents.map((incident) => <tr key={incident.id} data-testid={`row-incident-${incident.id}`}>
      <td><Link className="target-link" href={`/incidents/${incident.id}`} data-testid={`link-incident-${incident.id}`}>{incident.target}</Link></td>
      <td style={{ textTransform: 'capitalize' }}>{incident.kind}</td>
      <td><span className="risk-cell">{incident.riskScore}<span className="risk-mini"><i style={{ width: `${incident.riskScore}%` }} /></span></span></td>
      <td><StatusBadge status={incident.status} /></td>
      <td>{dateLabel(incident.createdAt)}</td>
      <td><Link href={`/incidents/${incident.id}`} className="target-link" aria-label={`Open incident ${incident.id}`} data-testid={`link-open-incident-${incident.id}`}><ArrowRight size={14} /></Link></td>
    </tr>)}</tbody>
  </table></div>;
}
function Metric({ label, value, icon: Icon, note, testId }: { label: string; value: number; icon: typeof Activity; note: string; testId: string }) {
  return <div className="panel metric-card" data-testid={testId}>
    <div className="metric-top"><span>{label}</span><span className="metric-icon"><Icon size={15} /></span></div>
    <div className="metric-value" data-testid={`value-${testId}`}>{value}</div>
    <div className="metric-caption">{note}</div>
  </div>;
}
function Shell() {
  const [path] = useLocation();
  const isActive = (href: string) => href === '/' ? path === '/' : path.startsWith(href);
  const links = [
    { href: '/', label: 'Live dashboard', icon: Activity },
    { href: '/scan', label: 'Scan a target', icon: Radar },
    { href: '/incidents', label: 'Incident history', icon: FileSearch },
    { href: '/reputation', label: 'Reputation', icon: Fingerprint },
  ];
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand-lockup"><span className="brand-mark"><Shield size={20} strokeWidth={2.4} /></span><div><div className="brand-name">ScamPatrol</div><div className="brand-tagline">Detect. Explain. Protect.</div></div></div>
      <div className="nav-caption">Workspace</div>
      <nav className="nav-list" aria-label="Main navigation">{links.map(({ href, label, icon: Icon }) =>
        <Link href={href} key={href} className={`nav-item${isActive(href) ? ' active' : ''}`} data-testid={`link-nav-${href === '/' ? 'dashboard' : href.slice(1)}`}><Icon size={16} strokeWidth={1.8} /><span>{label}</span></Link>
      )}</nav>
      <div className="side-bottom">
        <div className="status-card"><div className="status-title"><span className="status-led" />Protection active</div><p className="status-copy">High-risk simulated calls are clearly marked for blocking.</p></div>
        <div className="sidebar-foot">REAL-TIME SAFETY CONSOLE · 01</div>
      </div>
    </aside>
    <main className="main-panel">
      <header className="topbar"><div><div className="top-kicker">ScamPatrol / Safety console</div><div className="top-title">Detect. Explain. Protect.</div></div><div className="top-live"><span className="live-dot" />Live monitoring</div></header>
      <Switch>
        <Route path="/" component={DashboardPage} />
        <Route path="/scan" component={ScanPage} />
        <Route path="/incidents/:id" component={IncidentDetailPage} />
        <Route path="/incidents" component={IncidentsPage} />
        <Route path="/reputation" component={ReputationPage} />
        <Route component={NotFound} />
      </Switch>
    </main>
  </div>;
}
function DashboardPage() {
  const dashboard = useGetDashboard();
  const data = dashboard.data;
  const recent = data?.recentIncidents ?? [];
  const activity = data?.weeklyActivity ?? [];
  const categories = data?.categoryBreakdown ?? [];
  const maxCount = Math.max(1, ...activity.map((item) => item.count));
  const maxCategory = Math.max(1, ...categories.map((item) => item.count));
  return <div className="page-wrap">
    <div className="page-heading"><div><div className="eyebrow">Overview / right now</div><h1 className="page-title">Your safety, at a glance.</h1><p className="page-subtitle">A clear read on the targets you've checked, with high-risk activity and blocked calls up front.</p></div><Link href="/scan" className="button-primary" data-testid="button-start-scan"><Radar size={15} />Check something</Link></div>
    {dashboard.isLoading ? <><div className="metric-grid">{[0,1,2,3].map((item) => <div className="panel loading-panel" key={item}><div className="skeleton skeleton-line" /><div className="skeleton" style={{ height: 32, width: '42%' }} /></div>)}</div><LoadingPanel rows={7} /></> : dashboard.isError ? <ErrorState retry={() => dashboard.refetch()} /> : <>
      <div className="metric-grid">
        <Metric label="Scans run" value={data?.totalScans ?? 0} icon={Activity} note="All-time checks" testId="metric-total-scans" />
        <Metric label="High risk" value={data?.highRiskScans ?? 0} icon={AlertOctagon} note="Targets needing care" testId="metric-high-risk" />
        <Metric label="Calls blocked" value={data?.blockedCalls ?? 0} icon={Ban} note="Protection made visible" testId="metric-blocked-calls" />
        <Metric label="Reported targets" value={data?.reportedTargets ?? 0} icon={Target} note="Community flagged" testId="metric-reported-targets" />
      </div>
      <div className="dash-grid">
        <section className="panel section-panel" aria-label="Weekly scan activity">
          <div className="section-head"><div><h2 className="section-title">Scan activity</h2><p className="section-note">A seven-day view of checks run</p></div><Signal size={17} color="#72917e" /></div>
          {activity.length ? <div className="activity-bars" data-testid="chart-weekly-activity">{activity.map((item, index) => <div className="activity-column" key={`${item.date}-${index}`} data-testid={`activity-day-${index}`}>
            <span className="activity-count">{item.count}</span><div className={`activity-bar${index === activity.length - 1 ? ' today' : ''}`} style={{ height: `${Math.max(4, (item.count / maxCount) * 111)}px` }} /><span className="activity-date">{shortDate(item.date)}</span>
          </div>)}</div> : <EmptyState title="No activity to chart" copy="Completed checks will appear here." />}
        </section>
        <section className="panel section-panel">
          <div className="section-head"><div><h2 className="section-title">Risk categories</h2><p className="section-note">Categories found across your checks</p></div><TriangleAlert size={17} color="#b77a52" /></div>
          {categories.length ? <div className="category-list" data-testid="list-category-breakdown">{categories.map((category, index) => <div className="category-row" key={`${category.category}-${index}`} data-testid={`category-${index}`}>
            <span className="category-name">{category.category}</span><span className="category-count">{category.count}</span><div className="category-track"><div className="category-fill" style={{ width: `${Math.max(4, category.count / maxCategory * 100)}%` }} /></div>
          </div>)}</div> : <EmptyState title="Nothing flagged yet" copy="Risk categories appear as targets are scanned." />}
        </section>
      </div>
      <section className="panel section-panel">
        <div className="table-head"><div><h2 className="section-title">Recent checks</h2><p className="section-note">Latest explanations from your scan history</p></div><Link href="/incidents" className="button-secondary" data-testid="link-all-incidents">All incidents <ArrowRight size={13} /></Link></div>
        <IncidentTable incidents={recent} />
      </section>
    </>}
  </div>;
}
function ScanPage() {
  const queryClient = useQueryClient();
  const createScan = useCreateScan();
  const [kind, setKind] = useState<ScanKind>('message');
  const [input, setInput] = useState('');
  const [callerName, setCallerName] = useState('');
  const [result, setResult] = useState<ScanResultRecord | null>(null);
  const [submitError, setSubmitError] = useState('');
  const placeholders: Record<ScanKind, string> = {
    message: 'Paste the suspicious text here…',
    url: 'https://example.com/account/verify',
    phone: '+1 (555) 014-0192',
    call: 'Enter the number that appeared on your screen…',
  };
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitError('');
    createScan.mutate({ data: { kind, input: input.trim(), ...(kind === 'call' && callerName.trim() ? { callerName: callerName.trim() } : {}) } }, {
      onSuccess: (scan) => {
        setResult(scan);
        void queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
        void queryClient.invalidateQueries({ queryKey: getGetIncidentsQueryKey() });
        void queryClient.invalidateQueries({ queryKey: getGetReputationQueryKey() });
      },
      onError: () => setSubmitError('The scan could not be completed. Check your connection and try again.'),
    });
  };
  return <div className="page-wrap">
    <div className="page-heading"><div><div className="eyebrow">Analysis workspace / new check</div><h1 className="page-title">Pause. Then check.</h1><p className="page-subtitle">Paste the message, address, or number you don't trust. ScamPatrol will explain what it finds before you act.</p></div></div>
    <div className="scan-layout">
      <form className="panel scan-form" onSubmit={submit} data-testid="form-scan">
        <div className="eyebrow">What are you checking?</div>
        <div className="kind-tabs" role="tablist" aria-label="Scan type">{kinds.map(({ id, label, icon: Icon }) => <button type="button" key={id} role="tab" aria-selected={kind === id} className={`kind-tab${kind === id ? ' selected' : ''}`} onClick={() => { setKind(id); setResult(null); setSubmitError(''); }} data-testid={`tab-scan-${id}`}><Icon size={16} />{label}</button>)}</div>
        {kind === 'call' && <div className="form-row"><label htmlFor="caller-name" className="field-label">Caller name <span style={{ color: '#929b95', fontWeight: 400 }}>optional</span></label><input id="caller-name" className="text-input" value={callerName} onChange={(event) => setCallerName(event.target.value)} maxLength={120} placeholder="Name shown on caller ID" data-testid="input-caller-name" /></div>}
        <div className="form-row"><label htmlFor="scan-input" className="field-label">{kind === 'message' ? 'Suspicious message' : kind === 'url' ? 'Web address' : kind === 'phone' ? 'Phone number' : 'Incoming number'}</label>
          {kind === 'message' ? <textarea id="scan-input" className="text-area" required minLength={2} maxLength={5000} value={input} onChange={(event) => setInput(event.target.value)} placeholder={placeholders[kind]} data-testid="input-scan-target" /> : <input id="scan-input" className="text-input" required minLength={2} maxLength={5000} value={input} onChange={(event) => setInput(event.target.value)} placeholder={placeholders[kind]} data-testid="input-scan-target" />}
          <div className="field-help">{kind === 'call' ? 'This is a simulated call check. A high-risk result will make the block recommendation explicit.' : 'Your scan is checked against known risk signals and reported-target reputation.'}</div>
        </div>
        {kind === 'call' && <div className="call-note"><ShieldAlert size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />Simulated call checks never place or answer a real call. A high-risk result is visibly marked as blocked.</div>}
        {submitError && <p role="alert" className="error-copy" data-testid="status-scan-error">{submitError}</p>}
        <button className="button-primary" style={{ width: '100%' }} disabled={createScan.isPending || input.trim().length < 2} type="submit" data-testid="button-submit-scan">{createScan.isPending ? <><LoaderCircle size={15} className="animate-spin" />Analyzing target…</> : <><Radar size={15} />Analyze safely</>}</button>
      </form>
      <section className="panel scan-result" aria-live="polite" data-testid="panel-scan-result">
        {createScan.isPending ? <><div className="eyebrow">Analysis in progress</div><div className="skeleton" style={{ height: 97, marginTop: 17 }} /><div className="skeleton skeleton-line" style={{ marginTop: 23 }} /><div className="skeleton skeleton-line" style={{ width: '78%' }} /><div className="skeleton skeleton-line" style={{ width: '68%' }} /></> :
        result ? <ScanExplanation result={result} /> : <div style={{ minHeight: 320, display: 'grid', alignContent: 'center', justifyItems: 'center', textAlign: 'center', padding: 20 }}>
          <span className="brand-mark" style={{ width: 49, height: 49, borderRadius: 15, marginBottom: 18 }}><ShieldCheck size={24} /></span><h2 className="section-title" style={{ fontSize: 19 }}>Your readout will appear here</h2><p className="page-subtitle" style={{ maxWidth: 320 }}>Every result includes a risk score, the signals behind it, and a clear next step.</p>
        </div>}
      </section>
    </div>
  </div>;
}
function ScanExplanation({ result }: { result: ScanResultRecord }) {
  const block = result.isBlocked || result.decision === 'block';
  return <div data-testid={`scan-result-${result.id}`}>
    <div className="section-head"><div><div className="eyebrow">Analysis complete</div><h2 className="section-title" style={{ marginTop: 7 }}>Risk explanation</h2></div><StatusBadge status={result.status} /></div>
    <div className="result-score"><div><div className="result-score-number" data-testid="value-risk-score">{result.riskScore}<span style={{ fontSize: 16, color: '#78837d' }}>/100</span></div><div className="result-score-label">{result.category} · risk score</div></div><div className="score-gauge" aria-label={`Risk score ${result.riskScore} of 100`} /></div>
    {block && <div className="call-note" style={{ borderLeft: '3px solid #a9433c', background: '#faeeea', color: '#823a34' }} data-testid="status-call-blocked"><Ban size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />{result.kind === 'call' ? 'High-risk call: blocking is recommended. Do not answer or call back.' : 'High-risk target: avoid engaging and follow the recommended protective action.'}</div>}
    <div className="recommendation"><strong>Recommended next step</strong><br />{result.recommendation}</div>
    <div className="section-head" style={{ marginBottom: 11 }}><div><h3 className="section-title" style={{ fontSize: 13 }}>Signals behind this score</h3><p className="section-note">{result.signals.length} signals contributed to this decision</p></div></div>
    {result.signals.length ? <div className="signal-list">{result.signals.map((signal, index) => <div className="signal-row" key={`${signal.code}-${index}`} data-testid={`signal-${signal.code}`}><div className="signal-points">+{signal.points}</div><div><div className="signal-title">{signal.title}</div><div className="signal-detail">{signal.detail}</div></div></div>)}</div> : <EmptyState title="No risk signals returned" copy="Follow the recommendation and use care with unexpected requests." />}
    <div style={{ marginTop: 17 }}><Link href={`/incidents/${result.id}`} className="button-secondary" data-testid="link-view-explanation">Full incident explanation <ArrowRight size={13} /></Link></div>
  </div>;
}
function IncidentsPage() {
  const [search, setSearch] = useState('');
  const [kind, setKind] = useState('');
  const incidents = useGetIncidents({ search: search || undefined, kind: (kind || undefined) as ScanKind | undefined, limit: 50 });
  const data = incidents.data;
  return <div className="page-wrap">
    <div className="page-heading"><div><div className="eyebrow">Incident history / saved checks</div><h1 className="page-title">What you've checked.</h1><p className="page-subtitle">Search past explanations and revisit the evidence behind every risk decision.</p></div></div>
    <div className="filter-bar">
      <div className="search-wrap"><Search size={15} /><input aria-label="Search incidents" className="text-input" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search targets or categories" data-testid="input-search-incidents" /></div>
      <select className="text-input filter-select" aria-label="Filter by scan type" value={kind} onChange={(event) => setKind(event.target.value)} data-testid="select-incident-kind"><option value="">All scan types</option>{kinds.map((option) => <option key={option.id} value={option.id}>{option.label}</option>)}</select>
    </div>
    {incidents.isLoading ? <LoadingPanel rows={8} /> : incidents.isError ? <ErrorState retry={() => incidents.refetch()} /> : <section className="panel section-panel">
      <div className="table-head"><div><h2 className="section-title">Saved incidents</h2><p className="section-note" data-testid="text-incident-total">{data?.total ?? 0} results · most recent first</p></div><FileSearch size={17} color="#72917e" /></div>
      {data?.items.length ? <IncidentTable incidents={data.items} /> : <EmptyState title={search || kind ? 'No matches found' : 'No checks saved yet'} copy={search || kind ? 'Try a different search or filter to find an incident.' : 'Run your first scan to start an incident history.'} />}
    </section>}
  </div>;
}
function IncidentDetailPage() {
  const [path] = useLocation();
  const id = path.split('/').filter(Boolean).at(-1) ?? '';
  const incident = useGetIncident(id, { query: { enabled: !!id, queryKey: getGetIncidentQueryKey(id) } });
  const [showReport, setShowReport] = useState(false);
  const [reason, setReason] = useState('');
  const [reportMessage, setReportMessage] = useState('');
  const queryClient = useQueryClient();
  const report = useReportIncident();
  const record = incident.data;
  const submitReport = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setReportMessage('');
    report.mutate({ id, ...(reason.trim() ? { data: { reason: reason.trim() } } : {}) }, {
      onSuccess: () => {
        setShowReport(false);
        setReason('');
        setReportMessage('Report received. This target’s reputation has been updated.');
        void queryClient.invalidateQueries({ queryKey: getGetIncidentQueryKey(id) });
        void queryClient.invalidateQueries({ queryKey: getGetIncidentsQueryKey() });
        void queryClient.invalidateQueries({ queryKey: getGetReputationQueryKey() });
        void queryClient.invalidateQueries({ queryKey: getGetDashboardQueryKey() });
      },
      onError: () => setReportMessage('Your report could not be sent. Please try again.'),
    });
  };
  return <div className="page-wrap">
    <div style={{ marginBottom: 24 }}><Link href="/incidents" className="button-secondary" data-testid="link-back-incidents"><ChevronLeft size={14} />Incident history</Link></div>
    {incident.isLoading ? <LoadingPanel rows={9} /> : incident.isError || !record ? <ErrorState retry={() => incident.refetch()} message="This incident could not be found or loaded." /> : <>
      <div className="page-heading"><div><div className="eyebrow">Incident explanation / {record.id}</div><h1 className="page-title">The detail behind the decision.</h1><p className="page-subtitle">Understand what was detected, why the score landed where it did, and what to do next.</p></div></div>
      <div className="detail-grid">
        <section className="panel detail-main" data-testid={`incident-detail-${record.id}`}>
          <div className="eyebrow">Target checked</div><div className="detail-target" data-testid="text-incident-target">{record.target}</div>
          <div className="detail-meta"><StatusBadge status={record.status} /><span className="badge safe" style={{ background: '#eef0e9', color: '#617068' }}>{record.kind}</span><span className="section-note" data-testid="text-incident-created">{dateLabel(record.createdAt)}</span></div>
          <div className="detail-score"><div><div className="eyebrow">Risk score</div><strong data-testid="value-detail-risk">{record.riskScore}<span style={{ fontSize: 17, color: '#8a948e' }}>/100</span></strong></div><span className={`badge ${riskTone(record.riskScore)}`}>{record.category}</span></div>
          <div className="score-track"><span style={{ width: `${record.riskScore}%` }} /></div>
          {record.isBlocked && <div className="call-note" style={{ borderLeft: '3px solid #a9433c', background: '#faeeea', color: '#823a34' }} data-testid="status-detail-blocked"><Ban size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />{record.kind === 'call' ? 'This simulated incoming call was marked high-risk and blocked.' : 'This target was marked high-risk. Follow the recommended protective action.'}</div>}
          <h2 className="section-title" style={{ marginBottom: 11 }}>What was checked</h2><div className="source-text" data-testid="text-original-input">{record.originalInput}</div>
          <div className="recommendation"><strong>Recommended action</strong><br />{record.recommendation}</div>
          <div className="section-head" style={{ marginBottom: 12 }}><div><h2 className="section-title">Why it scored this way</h2><p className="section-note">Signals included in the analysis</p></div></div>
          {record.signals.length ? <div className="signal-list">{record.signals.map((signal, index) => <div className="signal-row" key={`${signal.code}-${index}`} data-testid={`detail-signal-${signal.code}`}><div className="signal-points">+{signal.points}</div><div><div className="signal-title">{signal.title}</div><div className="signal-detail">{signal.detail}</div></div></div>)}</div> : <EmptyState title="No risk signals returned" copy="No specific signals were included with this analysis." />}
        </section>
        <aside className="panel detail-side">
          <div className="section-head"><div><div className="eyebrow">Your next move</div><h2 className="section-title" style={{ marginTop: 7 }}>{record.isBlocked || record.decision === 'block' ? 'Stay clear.' : 'Use your judgment.'}</h2></div><ShieldAlert size={18} color="#a65343" /></div>
          <p className="page-subtitle" style={{ marginTop: 0 }}>{record.recommendation}</p>
          <div style={{ borderTop: '1px solid #e7e9e1', marginTop: 19, paddingTop: 17 }}><div className="metric-top">Community reports</div><div className="metric-value" style={{ marginTop: 9 }} data-testid="value-report-count">{record.reportCount}</div><div className="metric-caption">Reports linked to this target</div></div>
          <div className="report-box">
            {record.status === 'reported' ? <div className="call-note" data-testid="status-already-reported"><BadgeCheck size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />This incident has already been reported.</div> : !showReport ? <button className="button-secondary" style={{ width: '100%' }} onClick={() => setShowReport(true)} data-testid="button-report-incident"><AlertTriangle size={14} />Report this target</button> :
              <form onSubmit={submitReport} data-testid="form-report-incident"><label htmlFor="report-reason" className="field-label">What should others know? <span style={{ color: '#929b95', fontWeight: 400 }}>optional</span></label><textarea id="report-reason" className="text-area" style={{ minHeight: 90 }} value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} placeholder="Add a little context for the community…" data-testid="input-report-reason" /><div className="field-help">Up to 500 characters. Your report updates this target's reputation.</div><div style={{ display: 'flex', gap: 8, marginTop: 12 }}><button className="button-danger" disabled={report.isPending} type="submit" data-testid="button-submit-report">{report.isPending ? 'Sending…' : 'Submit report'}</button><button type="button" className="button-secondary" onClick={() => setShowReport(false)} disabled={report.isPending} data-testid="button-cancel-report">Cancel</button></div></form>}
            {reportMessage && <p className="field-help" role="status" data-testid="status-report-message">{reportMessage}</p>}
          </div>
        </aside>
      </div>
    </>}
  </div>;
}
function ReputationPage() {
  const [search, setSearch] = useState('');
  const reputation = useGetReputation({ search: search || undefined, limit: 100 });
  const data = reputation.data ?? [];
  return <div className="page-wrap">
    <div className="page-heading"><div><div className="eyebrow">Reputation / reported targets</div><h1 className="page-title">Patterns worth knowing.</h1><p className="page-subtitle">Targets reported by the community, with report volume and reputation impact in one place.</p></div></div>
    <div className="filter-bar"><div className="search-wrap"><Search size={15} /><input aria-label="Search reported targets" className="text-input" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search a number, address, or target" data-testid="input-search-reputation" /></div></div>
    {reputation.isLoading ? <LoadingPanel rows={7} /> : reputation.isError ? <ErrorState retry={() => reputation.refetch()} /> : <section className="panel" data-testid="list-reputation">
      <div style={{ padding: '20px 18px 13px', borderBottom: '1px solid #eceee8' }}><h2 className="section-title">Community reputation</h2><p className="section-note" data-testid="text-reputation-total">{data.length} reported {data.length === 1 ? 'target' : 'targets'}</p></div>
      {!data.length ? <div style={{ padding: 18 }}><EmptyState title={search ? 'No targets found' : 'No reported targets yet'} copy={search ? 'Try another identifier or clear your search.' : 'Targets reported from incident explanations will appear here.'} /></div> : data.map((record, index) => <div className="rep-row" key={`${record.identifier}-${index}`} data-testid={`row-reputation-${index}`}>
        <div><div className="rep-id" data-testid={`text-reputation-identifier-${index}`}>{record.identifier}</div><div className="rep-kind">{record.kind}</div></div>
        <div><div className="rep-label">Reports</div><div className="rep-value">{record.reportCount}</div></div>
        <div><div className="rep-label">Risk boost</div><div className="rep-value">+{record.riskBoost}</div></div>
        <div className="rep-date"><div className="rep-label">Last reported</div><div className="rep-value">{dateLabel(record.lastReportedAt)}</div></div>
      </div>)}
    </section>}
  </div>;
}
function AppRouter() {
  return <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><Shell /></WouterRouter>;
}
function App() {
  return <QueryClientProvider client={queryClient}><AppRouter /></QueryClientProvider>;
}
export default App;
