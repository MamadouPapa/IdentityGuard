# Inline stylesheet: the report must stay a single self-contained file (no external assets).

$script:IGReportCss = @'
:root {
  --bg: #f4f6fa; --surface: #ffffff; --text: #1b2430; --muted: #5b6472; --line: #dde2ea;
  --accent: #1f3a5f; --critical: #b42318; --high: #c4320a; --medium: #a15c07; --low: #2f6fb0;
  --info: #5b6472; --pass: #217a4b;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, "Helvetica Neue", Arial, sans-serif; }
.page { max-width: 1180px; margin: 0 auto; padding: 32px 24px 48px; }
h1 { font-size: 26px; margin: 4px 0 8px; letter-spacing: -0.01em; }
h2 { font-size: 18px; margin: 32px 0 12px; }
h3 { font-size: 13px; margin: 16px 0 4px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
a { color: var(--accent); }
.report-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;
  padding-bottom: 20px; border-bottom: 3px solid var(--accent); }
.eyebrow { margin: 0; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; color: var(--accent); }
.meta { margin: 0; color: var(--muted); }
.demo-badge { flex: none; padding: 6px 12px; border-radius: 6px; background: #fff4e5; color: #8a4b00;
  border: 1px solid #f0c48a; font-weight: 700; font-size: 12px; letter-spacing: .04em; }
.summary { display: grid; grid-template-columns: 240px 1fr; gap: 16px; margin-top: 24px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px; }
.score { text-align: center; }
.score-value { font-size: 56px; font-weight: 700; line-height: 1; margin: 8px 0 4px; }
.score-grade { display: inline-block; margin-top: 6px; padding: 2px 12px; border-radius: 999px;
  background: var(--accent); color: #fff; font-weight: 700; }
.score-label { color: var(--muted); font-size: 12px; }
.counters { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.counter { border-left: 4px solid var(--info); }
.counter .value { font-size: 28px; font-weight: 700; }
.counter .label { color: var(--muted); font-size: 12px; }
.counter.sev-critical { border-left-color: var(--critical); } .counter.sev-high { border-left-color: var(--high); }
.counter.sev-medium { border-left-color: var(--medium); } .counter.sev-low { border-left-color: var(--low); }
.counter.st-pass { border-left-color: var(--pass); }
table { width: 100%; border-collapse: collapse; background: var(--surface); }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); background: #eef1f6; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.table-wrap { border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.badge { display: inline-block; min-width: 72px; text-align: center; padding: 2px 8px; border-radius: 4px;
  color: #fff; font-size: 12px; font-weight: 600; background: var(--info); }
.badge.sev-critical { background: var(--critical); } .badge.sev-high { background: var(--high); }
.badge.sev-medium { background: var(--medium); } .badge.sev-low { background: var(--low); }
.status { font-size: 12px; font-weight: 600; }
.st-pass { color: var(--pass); } .st-fail { color: var(--critical); } .st-notrun { color: var(--muted); }
details.finding { background: var(--surface); border: 1px solid var(--line); border-left: 5px solid var(--info);
  border-radius: 8px; margin-bottom: 10px; }
details.finding.sev-critical { border-left-color: var(--critical); } details.finding.sev-high { border-left-color: var(--high); }
details.finding.sev-medium { border-left-color: var(--medium); } details.finding.sev-low { border-left-color: var(--low); }
details.finding.st-pass { border-left-color: var(--pass); }
summary { display: flex; align-items: center; gap: 12px; padding: 12px 16px; cursor: pointer; list-style: none; }
summary::-webkit-details-marker { display: none; }
summary::before { content: "\25B8"; color: var(--muted); }
details[open] > summary::before { content: "\25BE"; }
.fid { font-family: Consolas, "SFMono-Regular", Menlo, monospace; font-size: 12px; color: var(--muted); }
.ftitle { flex: 1; font-weight: 600; }
.fcount { color: var(--muted); font-size: 12px; white-space: nowrap; }
.finding-body { padding: 0 16px 16px 40px; }
.finding-body p { margin: 4px 0; }
.note { background: #f1f4f9; border-radius: 6px; padding: 8px 10px; }
.empty { color: var(--muted); font-style: italic; }
.truncated { color: var(--muted); font-size: 12px; margin-top: 6px; }
.items td:first-child { font-family: Consolas, "SFMono-Regular", Menlo, monospace; font-size: 13px; word-break: break-all; }
footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; }
@media (max-width: 760px) { .summary { grid-template-columns: 1fr; } .report-header { flex-direction: column; } }
@media print { body { background: #fff; } .page { padding: 0; } details.finding { break-inside: avoid; } }
'@
