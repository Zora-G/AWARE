#!/usr/bin/env python3
import argparse
import csv
import statistics
import sys
from pathlib import Path

from pipeline import (AS_WORKERS, CLIENTS, COMMITTEES, COPIES, PAYLOADS, ROOT, TABLE4_PAYLOADS,
                      TARGETS, THRESHOLDS, TOKENS, USERS, G, K, M, jobs)

GLOBALEAKS = ROOT / 'experiments/globaleaks.csv'
URW = Path('/usr/share/fonts/opentype/urw-base35')
FONT = 'Nimbus Sans TT'
FIELDS = {'operation': 'op', 'n': 'n', 't': 't', 'm': 'm', 'payload_bytes': 'payload',
          'users': 'users', 'workers': 'workers', 'concurrency': 'clients'}

INK, MUTE, AXIS, GRID = '#30383D', '#536168', '#6B767C', '#E4E8EB'
SLATE, TEAL, REPORT = '#3D6A99', '#237A70', '#912D31'
SLATE_RAMP = ['#83A8D1', '#5C87B5', '#3C6998', '#204A74']
OCHRE_RAMP = ['#D89E53', '#BC822E', '#9C681A', '#774F12']
MARKERS, LINES = ['o', 's', '^', 'D'], ['-', '--', '-.', ':']
SIZE = (395.8225 / 72.27, 1.12)


class Results:
    def __init__(self, root, target):
        self.values = {}
        for role in ['client', 'server']:
            for job in jobs(role):
                if target in job['targets']:
                    self.read(root / role / f"{job['name']}.csv", role, job)

    def read(self, path, role, job):
        groups = {}
        with path.open() as f:
            for row in csv.DictReader(f):
                if any(row[k] != str(job[v]) for k, v in FIELDS.items()):
                    raise ValueError(f'{path}: parameters differ from the job')
                groups.setdefault((row['variant'], row['metric']), []).append(float(row['value']))
        for (variant, metric), values in groups.items():
            if len(values) != job['runs'] * job['rounds']:
                raise ValueError(f'{path}: {len(values)} runs of {metric}')
            self.values[role, job['name'], variant, metric] = values

    def get(self, role, job, metric='latency', variant='aware'):
        return self.values[role, job, variant, metric]

    def mean(self, *args, **kwargs):
        return statistics.fmean(self.get(*args, **kwargs))

    def median(self, *args, **kwargs):
        return statistics.median(self.get(*args, **kwargs))


def write(path, header, rows):
    with path.open('w', newline='') as f:
        csv.writer(f).writerows([header] + rows)
    csv.writer(sys.stdout).writerows([header] + rows)


def table2(r, out):
    spec = [('Setup', 'server', 'setup', 'Server', 'once', None),
            ('RegU', 'client', 'regu', 'Client', 'once/user', 'U->AS'),
            ('RegIss', 'server', 'regiss_m15', 'AS', 'per user/epoch', 'AS->U'),
            ('RegObt', 'client', 'regobt_m15', 'Client', 'per epoch', None),
            ('RepGen', 'client', 'holder', 'Client', 'per report', 'W->BB'),
            ('PostAccept', 'server', 'postaccept', 'BB', 'per report', None),
            ('RepDec', 'server', 'repdec', 'CM', 'per member', 'CM->BB'),
            ('RepCom', 'server', 'repcom', 'CM', 'per opening', None),
            ('CompleteOpen', 'server', 'completeopen', 'CMs+CM', 'per opening', 'CMs->BB')]
    rows = []
    for op, role, job, party, frequency, flow in spec:
        time, size = ('RepGen', 'Submission') if op == 'RepGen' else ('latency', 'communication')
        kib = f'{r.mean(role, job, size) / K:.2f}' if flow else '---'
        rows.append([op, party, frequency, f'{r.mean(role, job, time):.2f}', flow or '---', kib])
    write(out / 'table2.csv', ['Operation', 'Party', 'Frequency', 'Time (ms)', 'Flow', 'Size (KiB)'],
          rows)


def table3(r, out):
    spec = [('RepGen', 'client', 'holder', 'Client', 'ms'),
            ('PostAccept', 'server', 'holder', 'BB', 'ms'),
            ('Submission', 'client', 'holder', 'W->BB', 'bytes'),
            ('RepDec', 'server', 'opening', 'CM', 'ms'),
            ('RepCom', 'server', 'opening', 'CM', 'ms'),
            ('CompleteOpen', 'server', 'opening', 'CMs+CM', 'ms'),
            ('Contribution', 'server', 'opening', 'CM->BB', 'KiB')]
    rows = []
    for metric, role, job, party, unit in spec:
        values = [r.mean(role, job, metric, v) for v in ['baseline', 'aware', 'delta']]
        if unit == 'bytes':
            cells = [f'{v:.0f}' for v in values]
        elif unit == 'KiB':
            cells = [f'{v / K:.2f}' for v in values]
        else:
            cells = [f'{v:.2f}' for v in values]
        rows.append([metric, party, unit] + cells)
    write(out / 'table3.csv', ['Metric', 'Party', 'Unit', 'Baseline', 'AWARE', 'Overhead'], rows)


def table4(r, out):
    gl = {}
    with GLOBALEAKS.open() as f:
        for row in csv.DictReader(f):
            gl.setdefault((int(row['payload_bytes']), row['operation']), []).append(float(row['ms']))

    def ms(v):
        return f'{v:.0f}' if v >= 1000 else f'{v:.1f}'

    def ratio(v):
        return f'{v:.0f}' if v >= 10 else f'{v:.1f}' if v >= 1 else f'{v:.2f}'

    rows = []
    for p in TABLE4_PAYLOADS:
        prepare = r.median('server', f'repgen_{p}')
        member = r.median('server', f'repdecfull_{p}')
        combiner = r.median('server', f'repcomfull_{p}')
        gl_prepare = statistics.median(gl[p, 'GLSubmitCrypto'])
        gl_open = statistics.median(gl[p, 'GLRecipientOpen'])
        label = f'{p // G} GiB' if p >= G else f'{p // M} MiB' if p >= M else f'{p // K} KiB'
        rows.append([label, ms(prepare), ms(gl_prepare), ratio(prepare / gl_prepare), ms(member),
                     ms(combiner), ms(member + combiner), ms(gl_open),
                     ratio((member + combiner) / gl_open)])
    write(out / 'table4.csv',
          ['Payload', 'Preparation AWARE', 'Preparation GlobaLeaks', 'Preparation ratio', 'Member',
           'Combiner', 'Opening AWARE', 'Opening GlobaLeaks', 'Opening ratio'], rows)


def truetype(src, dst, style):
    from fontTools.pens.cu2quPen import Cu2QuPen
    from fontTools.pens.ttGlyphPen import TTGlyphPen
    from fontTools.ttLib import TTFont, newTable
    font = TTFont(src)
    order = font.getGlyphOrder()
    font['loca'] = newTable('loca')
    font['glyf'] = glyf = newTable('glyf')
    glyf.glyphOrder = order
    glyf.glyphs = {}
    glyphs = font.getGlyphSet()
    for name in order:
        pen = TTGlyphPen(glyphs)
        glyphs[name].draw(Cu2QuPen(pen, max_err=1.0, reverse_direction=True))
        glyf[name] = pen.glyph()
    font['head'].glyphDataFormat = 0
    font['maxp'] = maxp = newTable('maxp')
    maxp.tableVersion = 0x00010000
    for attr in ['maxTwilightPoints', 'maxStorage', 'maxFunctionDefs', 'maxInstructionDefs',
                 'maxStackElements', 'maxSizeOfInstructions', 'maxComponentElements']:
        setattr(maxp, attr, 0)
    maxp.maxZones = 1
    post = font['post']
    post.formatType, post.extraNames, post.mapping = 2.0, [], {}
    post.glyphOrder = order
    del font['CFF ']
    if 'VORG' in font:
        del font['VORG']
    font.sfntVersion = '\x00\x01\x00\x00'
    for rec in font['name'].names:
        if rec.nameID in (1, 16):
            rec.string = FONT
        elif rec.nameID == 4:
            rec.string = f'{FONT} {style}'
        elif rec.nameID == 6:
            rec.string = f'NimbusSansTT-{style.replace(" ", "")}'
    font.save(dst)


def style(out):
    import matplotlib as mpl
    from matplotlib import font_manager
    mpl.use('Agg')
    fonts = out / 'fonts'
    fonts.mkdir(exist_ok=True)
    for face, name in [('Regular', 'Regular'), ('Italic', 'Italic'), ('Bold', 'Bold'),
                       ('BoldItalic', 'Bold Italic')]:
        dst = fonts / f'NimbusSans-{face}.ttf'
        if not dst.exists():
            truetype(URW / f'NimbusSans-{face}.otf', dst, name)
        font_manager.fontManager.addfont(str(dst))
    mpl.rcParams.update({
        'font.family': 'sans-serif', 'font.sans-serif': [FONT],
        'mathtext.fontset': 'custom', 'mathtext.rm': FONT, 'mathtext.it': f'{FONT}:italic',
        'mathtext.bf': f'{FONT}:bold', 'mathtext.sf': FONT,
        'pdf.fonttype': 42, 'ps.fonttype': 42, 'svg.fonttype': 'none',
        'font.size': 7, 'axes.titlesize': 7.4, 'axes.labelsize': 7, 'xtick.labelsize': 6.4,
        'ytick.labelsize': 6.4, 'legend.fontsize': 6.3,
        'text.color': INK, 'axes.labelcolor': INK, 'axes.titlecolor': INK,
        'xtick.color': AXIS, 'ytick.color': AXIS, 'xtick.labelcolor': INK, 'ytick.labelcolor': INK,
        'axes.edgecolor': AXIS, 'axes.linewidth': 0.6, 'axes.spines.top': False,
        'axes.spines.right': False, 'axes.titlepad': 4, 'axes.labelpad': 2,
        'xtick.major.width': 0.6, 'ytick.major.width': 0.6, 'xtick.minor.width': 0.45,
        'ytick.minor.width': 0.45, 'xtick.major.size': 2.6, 'ytick.major.size': 2.6,
        'xtick.minor.size': 1.5, 'ytick.minor.size': 1.5, 'xtick.major.pad': 2,
        'ytick.major.pad': 2, 'lines.linewidth': 1.15, 'lines.markersize': 3.7,
        'lines.markeredgewidth': 0.6, 'lines.markeredgecolor': 'white',
        'legend.frameon': False, 'legend.handlelength': 2.0, 'legend.handletextpad': 0.45,
        'legend.labelspacing': 0.25, 'legend.borderaxespad': 0.2, 'legend.columnspacing': 0.9,
        'figure.facecolor': 'white', 'axes.facecolor': 'white', 'savefig.facecolor': 'white',
    })


def panel(ax, title, xlabel, ylabel, loc='center'):
    ax.set_title(title, loc=loc)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(axis='y', color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)


def figure():
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 3, figsize=SIZE, layout='constrained')
    fig.get_layout_engine().set(wspace=0.10, w_pad=0.02, h_pad=0.02)
    return fig, axes


def fig2(r, out):
    from matplotlib.ticker import NullLocator
    fig, (a, b, c) = figure()
    for op, label, role, color, marker, line in [('regiss', 'AS RegIss', 'server', SLATE, 'o', '-'),
                                                 ('regobt', 'User RegObt', 'client', TEAL, 's',
                                                  '--')]:
        a.plot(TOKENS, [r.mean(role, f'{op}_m{m}') for m in TOKENS], label=label, color=color,
               marker=marker, linestyle=line)
    a.set_ylim(0, max(max(x.get_ydata()) for x in a.get_lines()) * 1.5)
    a.legend(loc='upper left')
    panel(a, r'$\mathbf{(a)}$ Periodic issuance', r'Tokens per epoch $m$', 'Latency (ms)')
    a.yaxis.set_major_formatter('{x:.0f}')

    for op, label, color, marker, line in [('tgsenc', 'TGS.Enc', REPORT, 'o', '-'),
                                           ('repgen', 'RepGen', TEAL, 's', '--')]:
        y = []
        for p in PAYLOADS:
            if (op, p) == ('repgen', M):
                mean = r.mean('client', 'holder', 'RepGen')
            else:
                mean = r.mean('client', f'{op}_{p}')
            y.append(p / M / (mean / 1000))
        b.plot(PAYLOADS, y, label=label, color=color, marker=marker, linestyle=line)
    b.set_xscale('log', base=2)
    b.set_xticks([10 * K, M, G], ['10 KiB', '1 MiB', '1 GiB'])
    b.xaxis.set_minor_locator(NullLocator())
    b.set_ylim(0, None)
    b.legend(loc='upper left')
    panel(b, r'$\mathbf{(b)}$ Report-generation throughput', 'Report size', 'Throughput (MiB/s)')
    b.yaxis.set_major_formatter('{x:,.0f}')

    for n, color, marker, line in zip(COMMITTEES, OCHRE_RAMP, MARKERS, LINES):
        ts = [t for t in THRESHOLDS if t <= n]
        c.plot(ts, [r.mean('server', f'completeopen_n{n}_t{t}') for t in ts], label=f'$n={n}$',
               color=color, marker=marker, linestyle=line)
    c.set_xticks(THRESHOLDS)
    c.set_ylim(0, max(max(x.get_ydata()) for x in c.get_lines()) * 1.5)
    c.legend(ncol=2, loc='upper left', handlelength=1.8)
    panel(c, r'$\mathbf{(c)}$ Accountable-opening latency', r'Threshold $t$', 'Latency (ms)',
          loc='right')
    c.set_yticks([0, 100, 200, 300])
    c.yaxis.set_major_formatter('{x:.0f}')
    fig.savefig(out / 'fig2.pdf', dpi=600)


def fig3(r, out):
    from matplotlib.ticker import NullLocator
    fig, (a, b, c) = figure()
    for w, color, marker, line in zip(AS_WORKERS, SLATE_RAMP, MARKERS, LINES):
        a.plot(USERS, [r.mean('server', f'issuance_u{u}_w{w}') / 1000 for u in USERS], label=f'{w}',
               color=color, marker=marker, linestyle=line)
    a.set_xscale('log', base=10)
    a.set_yscale('log', base=10)
    a.set_xticks([10, 100, 1000, 10000], ['10', '100', '1k', '10k'])
    a.set_ylim(0.3, 1e5)
    a.set_yticks([1, 10, 100, 1000], ['1', '10', '100', '1,000'])
    a.legend(ncol=4, loc='upper left', title='AS workers', alignment='left', handlelength=1.5,
             columnspacing=0.6, handletextpad=0.3, title_fontsize=6.3)
    panel(a, r'$\mathbf{(a)}$ Periodic issuance', r'Users $N_U$', 'Epoch time (s)')

    b.plot(CLIENTS, [r.mean('server', f'bb_c{n}', 'throughput') for n in CLIENTS], marker='D',
           color=TEAL)
    b.set_xscale('log', base=2)
    b.set_xticks([1, 4, 16, 64, 256], ['1', '4', '16', '64', '256'])
    b.set_ylim(0, None)
    panel(b, r'$\mathbf{(b)}$ BB throughput', 'Concurrent clients', 'Accepted records/s')
    b.yaxis.set_major_formatter('{x:.0f}')

    for k in COPIES:
        if set(r.get('server', f'replay_k{k}', 'accepted')) != {1.0}:
            raise ValueError(f'replay race with {k} copies accepted other than one')
    c.plot(COPIES, [r.mean('server', f'replay_k{k}') for k in COPIES], marker='o', color=TEAL)
    c.set_xscale('log', base=2)
    c.set_xticks(COPIES, [str(k) for k in COPIES])
    c.xaxis.set_minor_locator(NullLocator())
    c.set_ylim(0, None)
    c.text(.04, .96, '1 accepted, $k-1$ rejected\nin all 100 runs per $k$', transform=c.transAxes,
           va='top', fontsize=6.3, color=MUTE, linespacing=1.25)
    panel(c, r'$\mathbf{(c)}$ Replay race', r'Copies of one token $k$', 'Decision time (ms)')
    c.set_yticks([0, 200, 400, 600])
    c.yaxis.set_major_formatter('{x:.0f}')
    fig.savefig(out / 'fig3.pdf', dpi=600)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('target', choices=TARGETS)
    p.add_argument('--results', type=Path, default=ROOT / 'results')
    args = p.parse_args()
    r = Results(args.results, args.target)
    if args.target.startswith('fig'):
        style(args.results)
    render = {'table2': table2, 'table3': table3, 'table4': table4, 'fig2': fig2, 'fig3': fig3}
    render[args.target](r, args.results)


if __name__ == '__main__':
    main()
