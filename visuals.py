"""Native notebook figures generated from pipeline results."""
from __future__ import annotations

import html
import textwrap
from pathlib import Path

import matplotlib.pyplot as plt
from IPython.display import HTML, display

plt.rcParams.update({
    'font.family': 'DejaVu Sans', 'font.size': 10.5,
    'axes.spines.top': False, 'axes.spines.right': False,
    'figure.facecolor': '#f7f5ef', 'axes.facecolor': '#f7f5ef',
})
ASSETS = Path(__file__).resolve().parent / 'assets'
INK, BLUE, TEAL, AMBER, MUTED = '#17242b', '#315a70', '#3f8077', '#bd7a2a', '#78838a'


def finish(fig, name):
    ASSETS.mkdir(exist_ok=True)
    fig.savefig(ASSETS / name, dpi=180, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.show()


def show_funnel(result):
    counts = result['pipeline']['stage_counts']
    labels = ['Inputs · both batches', 'OCSF · both batches', 'Events · selected batch', 'Investigation clusters', 'Candidate statements']
    values = [counts['raw_records'], counts['normalized_events'], counts['relevant_terminated_user_events'],
              counts['investigation_clusters'], len(result['reasoning']['candidates'])]
    fig, ax = plt.subplots(figsize=(11.5, 4.1))
    bars = ax.barh(labels[::-1], values[::-1], color=[AMBER, TEAL, BLUE, '#7696a5', '#aab9be'])
    ax.set_xscale('log'); ax.set_xlabel('Records / artifacts · logarithmic scale')
    ax.set_title('From source records to bounded investigation', loc='left', fontsize=17, weight='bold', color=INK, pad=14)
    for bar, value in zip(bars, values[::-1]):
        ax.text(value * 1.15, bar.get_y() + bar.get_height()/2, f'{value:,}', va='center', color=INK, weight='bold')
    ax.grid(axis='x', alpha=.18); fig.tight_layout(); finish(fig, 'pipeline-funnel.png')


def show_volume(result):
    raw = result['pipeline']['manifest']['raw_counts']
    labels = ['Okta System Log', 'Zscaler NSS', 'HR workers', 'Business services']
    values = [raw['okta'], raw['zscaler'], raw['hr'], raw['business_services']]
    fig, ax = plt.subplots(figsize=(11.5, 3.7))
    bars = ax.bar(labels, values, color=[BLUE, TEAL, MUTED, AMBER])
    ax.set_ylabel('Generated records'); ax.set_title('Vendor-shaped mock inputs at useful pipeline scale', loc='left', fontsize=17, weight='bold', color=INK, pad=14)
    ax.bar_label(bars, labels=[f'{v:,}' for v in values], padding=4, weight='bold'); ax.grid(axis='y', alpha=.16)
    fig.tight_layout(); finish(fig, 'source-volume.png')


def show_evidence(result, scenario_id=None):
    candidate_ids = {c['cluster_id'] for c in result['reasoning']['candidates']}
    bundles = [c for c in result['pipeline']['clusters'] if c['cluster_id'] in candidate_ids]
    if not bundles:
        display(HTML('<p>No candidate scenarios in this collection.</p>'))
        return
    bundle = next((x for x in bundles if x['scenario_id'] == scenario_id), bundles[0])
    fig, ax = plt.subplots(figsize=(12, 5.5)); ax.set_xlim(0, 12); ax.set_ylim(0, 6); ax.axis('off')
    ax.text(.2, 5.65, 'How the pipeline identifies a candidate risk scenario', fontsize=17, weight='bold', color=INK)
    ax.text(.2, 5.3, f"{bundle['scenario_id']} · solid lines are deterministic joins · dashed line is bounded interpretation", fontsize=9.5, color=MUTED)
    nodes = [
        (1.4, 4.15, 'HR context', f"Terminated\n{bundle['termination_time']}", '#dde5e7'),
        (1.4, 2.7, 'Okta · OCSF 3002', f"{bundle['authentication_events']} logon event", '#dde5e7'),
        (1.4, 1.25, 'Zscaler · OCSF 4002', f"{bundle['web_events']} allowed request", '#dde5e7'),
        (5.25, 2.7, 'Evidence bundle', f"Exact identity + service join\n{bundle['service_name']}", '#dce9e4'),
        (9.75, 2.7, 'Candidate statement', 'Plausible threat event\n+ potential consequence\n+ business objective', '#f0dfc8'),
    ]
    for x, y, title, body, color in nodes:
        ax.text(x, y, f'{title}\n{body}', ha='center', va='center', linespacing=1.35,
                bbox=dict(boxstyle='round,pad=.75', facecolor=color, edgecolor='none'))
    for y in (4.15, 2.7, 1.25):
        ax.annotate('', xy=(3.65, 2.7), xytext=(2.65, y), arrowprops=dict(arrowstyle='->', color=MUTED, lw=1.4))
    ax.annotate('', xy=(8.0, 2.7), xytext=(6.8, 2.7), arrowprops=dict(arrowstyle='->', color=AMBER, lw=1.6, linestyle='dashed'))
    ax.text(5.8, .35, f"Objective: {bundle['business_objective']}  ·  Target profile: {bundle['profile_outcome']}  ·  Human review required", ha='center', color=INK)
    fig.tight_layout(); finish(fig, 'evidence-to-statement.png')


def show_register(result):
    rows = []
    for candidate in result['reasoning']['candidates']:
        cells = [candidate['scenario_id'], candidate['statement'], candidate['objective'], ', '.join(candidate['evidence_ids']), 'Candidate']
        rows.append('<tr>' + ''.join(f'<td style="padding:10px 12px;border-bottom:1px solid #d7d7d2;vertical-align:top">{html.escape(str(v))}</td>' for v in cells) + '</tr>')
    header = ''.join(f'<th style="padding:8px 12px;text-align:left;border-bottom:2px solid #263942">{x}</th>' for x in ['Scenario', 'Risk statement', 'Business objective', 'Evidence', 'Status'])
    display(HTML(f'<h3>Candidate risk statements · identification only</h3><table style="border-collapse:collapse;width:100%;font-size:13px"><thead><tr>{header}</tr></thead><tbody>{"".join(rows)}</tbody></table>'))
    candidates = result['reasoning']['candidates']
    if not candidates:
        return
    fig, ax = plt.subplots(figsize=(12, 2.5 * len(candidates) + 1))
    ax.axis('off'); ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.text(0, .99, 'Candidate risk statements', fontsize=19, weight='bold', color=INK, va='top')
    ax.text(0, .94, 'Preserved model output · fictional evidence · human review required', fontsize=10, color=MUTED, va='top')
    height = .84 / len(candidates)
    for index, candidate in enumerate(candidates):
        y = .86 - index * height
        ax.text(0, y, candidate['service'], fontsize=12, weight='bold', color=INK, va='top')
        ax.text(0, y - .044, textwrap.fill(candidate['statement'], 110),
                fontsize=10.5, color=INK, va='top', linespacing=1.5)
        ax.text(0, y - height + .06,
                'Evidence: ' + ', '.join(candidate['evidence_ids']) + '   |   Objective: ' + candidate['objective'],
                fontsize=8.5, color=BLUE, va='top')
        ax.plot([0, 1], [y-height+.025, y-height+.025], color='#d7d7d2', lw=.8)
    fig.tight_layout(); finish(fig, 'candidate-risk-register.png')


def show_investigation_board(result):
    clusters = {c['cluster_id']: c for c in result['pipeline']['clusters']}
    outcomes = {d['cluster_id']: d['disposition'] for d in result['reasoning']['dispositions']}
    labels = ['Identity resolved', 'Successful auth', 'Allowed web', 'Disable observed']
    ids = sorted(clusters)
    fig, ax = plt.subplots(figsize=(12, 5.8))
    ax.set_xlim(-.8, 6.8); ax.set_ylim(-.8, len(ids)); ax.axis('off')
    ax.text(-.75, len(ids)-.05, 'Agent investigation board', fontsize=18, weight='bold', color=INK)
    ax.text(-.75, len(ids)-.42, 'One row per bounded cluster · evidence first, disposition last', fontsize=9.5, color=MUTED)
    for x, label in enumerate(labels, 1):
        ax.text(x, len(ids)-.75, label, ha='center', va='top', fontsize=9, color=MUTED)
    ax.text(5.6, len(ids)-.75, 'Disposition', ha='center', va='top', fontsize=9, color=MUTED)
    outcome_colors = {'candidate-submitted': AMBER, 'insufficient-evidence': MUTED, 'contradicted': TEAL, 'ambiguous': BLUE}
    for row, sid in enumerate(ids):
        y = len(ids)-1.55-row*.78
        c = clusters[sid]
        ax.text(-.75, y, c['person_id'], va='center', fontsize=10.5, weight='bold', color=INK)
        values = [c['identity_uids'] == [c['expected_identity_uid']], c['authentication_events'] > 0,
                  c['web_events'] > 0, c['disable_events'] > 0]
        for x, value in enumerate(values, 1):
            ax.scatter(x, y, s=185, color=TEAL if value else '#d9dedc', edgecolors='none')
            ax.text(x, y, '✓' if value else '—', ha='center', va='center', color='white' if value else MUTED, weight='bold')
        outcome = outcomes[sid]
        ax.text(5.6, y, outcome.replace('-', ' '), ha='center', va='center', fontsize=9.5, weight='bold',
                color='white', bbox=dict(boxstyle='round,pad=.45', facecolor=outcome_colors[outcome], edgecolor='none'))
    fig.tight_layout(); finish(fig, 'agent-investigation.png')


def show_history(results):
    people = ['P0001', 'P0002', 'P0003', 'P0004', 'P0005', 'P0006']
    colors = {'candidate-submitted': AMBER, 'insufficient-evidence': MUTED, 'contradicted': TEAL, 'ambiguous': BLUE}
    fig, ax = plt.subplots(figsize=(12, 5.2))
    for y, person in enumerate(people):
        ax.plot([1, 2], [y, y], color='#c7cac8', zorder=0)
        for batch, result in enumerate(results, 1):
            sid = next(c['cluster_id'] for c in result['pipeline']['clusters'] if c['person_id'] == person)
            state = next(x['disposition'] for x in result['reasoning']['dispositions'] if x['cluster_id'] == sid)
            ax.scatter(batch, y, s=150, color=colors[state], zorder=2)
            ax.text(batch + .06, y, state, va='center', fontsize=9,
                    bbox=dict(facecolor='#f7f5ef', edgecolor='none', pad=2))
    ax.set_yticks(range(len(people)), people); ax.set_xticks([1, 2], ['Collection batch 1', 'Collection batch 2'])
    ax.set_xlim(.75, 2.8); ax.set_ylim(-.5, len(people)-.5); ax.invert_yaxis()
    ax.set_title('Every collection adds an interpretation to the history', loc='left', fontsize=17, weight='bold', color=INK, pad=14)
    fig.tight_layout(); finish(fig, 'evidence-history.png')
