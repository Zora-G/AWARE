#!/usr/bin/env python3
"""Regenerate Fig. 2–3 and Tables II–IV from complete per-trial BN462 CSVs."""
import argparse,csv,json,math,os,shutil,statistics
from collections import defaultdict
from pathlib import Path
from run_pipeline import jobs,PAYLOADS,TOKENS,CLIENTS,K,M,G
COLORS=['#0072B2','#D55E00','#009E73','#6F3FA0']
DEFAULT_REPGEN_JOB='table3_holder_client'
MARKERS=['o','s','^','D'];LINES=['-','--','-.',':']
def write_csv(path,rows,fields=None):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields or list(rows[0]));w.writeheader();w.writerows(rows)
def load(root,roles,protocol_only=False):
    rows=[]
    for role in roles:
        for job in json.loads((root/role/'manifest.json').read_text()):
            if protocol_only and not set(job['targets']).intersection({'Fig3a','Fig3b','Fig3c','TableII','TableIII','TableIV'}):continue
            file=root/role/'raw'/(job['name']+'.csv');status=file.with_suffix('.status.json')
            if not status.exists() or not json.loads(status.read_text())['complete']:raise ValueError(f'incomplete paper job: {file}')
            trialrows=list(csv.DictReader(file.open()));groups=defaultdict(list)
            for r in trialrows:groups[(r['variant'],r['metric'],r['unit'])].append(r)
            for r in trialrows:
                expected={'operation':job['operation'],'n':job['n'],'t':job['t'],'m':job['m'],'payload_bytes':job['payload'],'users':job['users'],'workers':job['workers'],'concurrency':job['clients']}
                if any(r[key]!=str(value) for key,value in expected.items()):raise ValueError(f'parameter sweep mismatch: {file}, run {r["run"]}')
                if job['operation']=='ReplayRace' and r['metric']=='accepted' and float(r['value'])!=1:raise ValueError(f'replay acceptance: {file}, run {r["run"]}')
                if job['operation']=='BB' and r['metric']=='rejected' and float(r['value'])!=0:raise ValueError(f'independent submission rejection: {file}, run {r["run"]}')
            for (variant,metric,unit),group in groups.items():
                if sorted(int(r['run']) for r in group)!=list(range(1,job['runs']+1)):raise ValueError(f'trial count: {file} {metric}')
                values=[float(r['value']) for r in group]
                if not all(math.isfinite(v) for v in values):raise ValueError(f'nonfinite data: {file}')
                rows.append(dict(role=role,job=job['name'],operation=job['operation'],variant=variant,n=job['n'],t=job['t'],m=job['m'],payload_bytes=job['payload'],users=job['users'],workers=job['workers'],concurrency=job['clients'],metric=metric,unit=unit,mean=statistics.fmean(values),runs=job['runs']))
    return rows
class Results:
    def __init__(self,rows):self.rows=rows
    def get(self,job,metric='latency',variant='aware',role=None):
        r=[r for r in self.rows if r['job']==job and r['metric']==metric and r['variant']==variant and (role is None or r['role']==role)]
        if len(r)!=1:raise ValueError(f'expected unique observation: {job}/{metric}/{variant}')
        return r[0]
    def mean(self,*a,**kw):return self.get(*a,**kw)['mean']
def style():
    import matplotlib as mpl
    mpl.use('Agg');mpl.rcParams.update({'font.family':'serif','font.serif':['Times New Roman','Times','DejaVu Serif'],'mathtext.fontset':'stix','pdf.fonttype':42,'ps.fonttype':42,'svg.fonttype':'none','font.size':9,'axes.labelsize':9,'axes.titlesize':9.5,'xtick.labelsize':8.2,'ytick.labelsize':8.2,'legend.fontsize':7.8,'lines.linewidth':1.4,'lines.markersize':4.0,'axes.linewidth':.75,'axes.spines.top':False,'axes.spines.right':False,'figure.facecolor':'white','axes.facecolor':'white','savefig.facecolor':'white'})
def finish(ax):
    from matplotlib.ticker import FormatStrFormatter
    ax.grid(axis='y',alpha=.15,linewidth=.45);ax.tick_params(pad=2,length=3)
    if ax.get_yscale()=='linear':ax.yaxis.set_major_formatter(FormatStrFormatter('%.2f'))
def save(fig,root,stem,*aliases):
    for ext in ['pdf','png','svg']:
        path=root/f'{stem}.{ext}'
        fig.savefig(path,dpi=400)
        for alias in aliases:
            shutil.copy2(path,root/f'{alias}.{ext}')
def fig3b_data(r):
    rows=[]
    for op in ['TGSEnc','RepGen']:
        for p in PAYLOADS:
            job,metric=(DEFAULT_REPGEN_JOB,'RepGen') if (op,p)==('RepGen',M) else (f'fig3_{op}_{p}','latency')
            sample=r.get(job,metric)
            rows.append(dict(operation=op,payload_bytes=p,source_job=job,source_metric=metric,runs=sample['runs'],mean_ms=sample['mean'],throughput_mib_s=p/M/(sample['mean']/1000)))
    return rows
def fig3b(ax,r):
    data=fig3b_data(r)
    for op,label,color,marker,line in [('TGSEnc','TGS.Enc',COLORS[2],'o','-'),('RepGen','RepGen','#CC79A7','s','--')]:
        # Preserve the original estimator: payload / mean latency, not mean of reciprocals.
        y=[row['throughput_mib_s'] for row in data if row['operation']==op]
        ax.plot(PAYLOADS,y,label=label,color=color,marker=marker,linestyle=line)
    ax.set_xscale('log',base=2);ax.set_xticks([10*K,M,100*M,G,5*G],['10 KiB','1 MiB','100 MiB','1 GiB','5 GiB'],rotation=25,ha='right');ax.set(title='(b) Report-generation throughput',xlabel='Report payload',ylabel='Throughput (MiB/s)');ax.legend(frameon=False,loc='best');finish(ax)
def figures(r,root,client_only,protocol_only=False):
    import matplotlib.pyplot as plt
    write_csv(root/'fig3b_bn462_data.csv',fig3b_data(r))
    fig,ax=plt.subplots(figsize=(3.2,2.25),layout='constrained');fig3b(ax,r);save(fig,root,'fig3b_bn462');plt.close(fig)
    if client_only:return
    fig,axes=plt.subplots(1,3,figsize=(7.16,1.72),layout='constrained')
    fig.get_layout_engine().set(wspace=0.12)
    for op,label,role,i in [('RegIss','AS RegIss','server',0),('RegObt','Client RegObt','client',1)]:
        axes[0].plot(TOKENS,[r.mean(f'fig3_{op.lower()}_m{m}',role=role) for m in TOKENS],label=label,color=COLORS[i],marker=MARKERS[i],linestyle=LINES[i])
    axes[0].set(title='(a) Token preparation',xlabel='Tokens per epoch $m$',ylabel='Latency (ms)');axes[0].legend(frameon=False,loc='upper left');finish(axes[0]);fig3b(axes[1],r)
    for n,color,marker,line in zip([6,9,12,15],COLORS,MARKERS,LINES):
        thresholds=[t for t in [2,4,6,8,10] if t<=n];axes[2].plot(thresholds,[r.mean(f'fig3_open_n{n}_t{t}')/1000 for t in thresholds],label=f'$n={n}$',color=color,marker=marker,linestyle=line)
    axes[2].set(title='(c) Opening latency',xlabel='Threshold $t$',ylabel='Complete opening (s)');axes[2].set_xticks([2,4,6,8,10]);axes[2].legend(frameon=False,ncol=2,loc='best',columnspacing=.6,handlelength=1.3);finish(axes[2]);save(fig,root,'fig3_bn462','fig2_aware_bn462');plt.close(fig)
    if protocol_only:return
    fig,axes=plt.subplots(1,2,figsize=(3.5,1.34),layout='constrained');users=[10,100,500,1000,5000,10000]
    fig.get_layout_engine().set(wspace=0.16)
    for w,color,marker,line in zip([1,4,8,16],COLORS,MARKERS,LINES):axes[0].plot(users,[r.mean(f'fig4_issuance_u{u}_w{w}')/1000 for u in users],label=f'{w} worker'+('s' if w>1 else ''),color=color,marker=marker,linestyle=line)
    axes[0].set_xscale('log',base=10);axes[0].set_yscale('log',base=10);axes[0].set_xticks([10,100,1000,10000],['10','100','1k','10k']);axes[0].set(title='(a) AS issuance',xlabel='Users $N_U$',ylabel='Epoch time (s)');axes[0].legend(frameon=False,fontsize=6.2,ncol=1,handlelength=1.0,labelspacing=.05,borderaxespad=.25,loc='upper left');finish(axes[0])
    axes[1].plot(CLIENTS,[r.mean(f'fig4_bb_c{c}','throughput') for c in CLIENTS],marker='D',color=COLORS[3]);axes[1].set_xscale('log',base=2);axes[1].set_xticks([1,4,16,64,256],['1','4','16','64','256']);axes[1].set(title='(b) BB throughput',xlabel='Concurrent clients',ylabel='Reports/s');finish(axes[1]);save(fig,root,'fig4_bn462','fig3_aware_bn462');plt.close(fig)
def latex_table(path,headers,rows,alignment=None):
    def val(v):return f'{v:.2f}' if isinstance(v,float) else str(v).replace('_',r'\_')
    lines=[r'\begin{tabular}{'+(alignment or 'l'+'r'*(len(headers)-1))+'}',r'\toprule',' & '.join(headers)+r' \\',r'\midrule']
    lines+=[' & '.join(val(v) for v in row)+r' \\' for row in rows];lines += [r'\bottomrule',r'\end{tabular}'];path.write_text('\n'.join(lines)+'\n')
def tables(r,root,data_root):
    ops=[('Setup','table2_Setup','Server','once'),('RegU','table2_regu','Client','once/user'),('RegIss','fig3_regiss_m15','AS','per epoch'),('RegObt','fig3_regobt_m15','Client','per epoch'),('RepGen',DEFAULT_REPGEN_JOB,'Client','per report'),('PostAccept','table2_PostAccept','BB','per report'),('RepDec','table2_RepDec','CM','per member'),('RepCom','table2_RepCom','CM','per opening'),('CompleteOpen','table2_CompleteOpen','CMs+CM','per opening')]
    t2=[]
    phases=['Setup','Registration','Issuance','Token prep.','Reporting','Verification','Opening','Opening','Opening']
    directions={'RegU':r'$U\to AS$','RegIss':r'$AS\to U$','RepGen':r'$W\to BB$','RepDec':r'$CM\to BB$','CompleteOpen':r'$CMs\to BB$'}
    for op,job,role,freq in ops:
        value=r.get(job,'RepGen' if op=='RepGen' else 'latency')
        wire=r.mean('table3_holder_client','Submission','aware') if op=='RepGen' else r.mean(job,'communication') if op in ['RegU','RegIss','RepDec','CompleteOpen'] else ''
        t2.append(dict(phase=phases[len(t2)],operation=op,role=role,mean_ms=value['mean'],communication_bytes=int(wire) if wire!='' else '',runs=value['runs'],frequency=freq))
    write_csv(root/'table_II.csv',t2)
    latex_table(root/'table_II.tex',['Operation','Role','Comp. (ms)','Comm. (KiB)','Frequency'],[[x['operation'],x['role'],x['mean_ms'],f"{x['communication_bytes']/K:,.2f}" if x['communication_bytes']!='' else r'---',x['frequency']] for x in t2],alignment='lcrrl')
    t3=[]
    for group,job,metrics in [('Holder binding','table3_holder_client',['RepGen','Submission']),('Holder binding','table3_holder_server',['PostAccept']),('Accountable threshold opening','table3_opening',['RepDec','RepCom','CompleteOpen','Contribution'])]:
        for metric in metrics:
            base=r.get(job,metric,'baseline');aware=r.get(job,metric,'aware');delta=r.get(job,metric,'delta');t3.append(dict(extension=group,metric=metric,unit=base['unit'],baseline=base['mean'],aware=aware['mean'],delta=delta['mean'],paired_runs=base['runs']))
    order={'RepGen':0,'PostAccept':1,'Submission':2,'RepDec':3,'RepCom':4,'CompleteOpen':5,'Contribution':6}
    t3.sort(key=lambda x:order[x['metric']])
    write_csv(root/'table_III.csv',t3)
    lines=[r'\begin{tabular}{lrrr}',r'\toprule',r'Metric & Baseline & AWARE & $\Delta$ \\']
    previous=None
    for x in t3:
        if previous!=x['extension']:
            lines.extend([r'\midrule',r'\multicolumn{4}{l}{\textit{'+x['extension']+r'}} \\']);previous=x['extension']
        if x['metric']=='Submission':
            unit='MiB'
            numbers=[r'$<0.01$' if 0<x[k]/M<.01 else f"{x[k]/M:.2f}" for k in ['baseline','aware','delta']]
        else:
            unit='KiB' if x['unit']=='bytes' else x['unit']
            numbers=[f"{x[k]/K:,.2f}" if x['unit']=='bytes' else f"{x[k]:.2f}" for k in ['baseline','aware','delta']]
        lines.append(f"{x['metric']} ({unit}) & "+' & '.join(numbers)+r' \\')
    lines.extend([r'\bottomrule',r'\end{tabular}']);(root/'table_III.tex').write_text('\n'.join(lines)+'\n')
    t4=[]
    for p in [10*K,M,100*M,G,5*G]:
        gl=list(csv.DictReader((data_root/'comparison'/str(p)/'summary.csv').open()))
        for op,stage,glop in [('RepGen','Preparation','GLSubmitCrypto'),('RepDec','RepDec',None),('RepCom','RepCom','GLRecipientOpen')]:
            a=r.get(f'table4_{op}_{p}');g=next((x for x in gl if x['operation']==glop),None);t4.append(dict(payload_bytes=p,stage=stage,aware_ms=a['mean'],globaleaks_ms=float(g['mean_ms']) if g else '',aware_runs=a['runs'],globaleaks_runs=int(g['runs']) if g else ''))
    write_csv(root/'table_IV.csv',t4)
    labels={10*K:'10 KiB',M:'1 MiB',100*M:'100 MiB',G:'1 GiB',5*G:'5 GiB'}
    header=[r'\begin{tabular}{lrrrr}',r'\toprule',
        r'\multirow{2}{*}{\textbf{Payload}} & \multicolumn{2}{c}{\textbf{Report preparation} (s)} & \multicolumn{2}{c}{\textbf{Opening} (s)} \\',
        r'\cmidrule(lr){2-3}\cmidrule(l){4-5}',
        r' & \textbf{AWARE} & \textbf{GlobaLeaks} & \textbf{AWARE} & \textbf{GlobaLeaks} \\',r'\midrule']
    displayed=[]
    for payload,label in labels.items():
        prep,share,opening=[x for x in t4 if x['payload_bytes']==payload]
        values=[prep['aware_ms']/1000,prep['globaleaks_ms']/1000,(share['aware_ms']+opening['aware_ms'])/1000,opening['globaleaks_ms']/1000]
        header.append(label+' & '+' & '.join(r'$<0.01$' if v<0.01 else f'{v:.2f}' for v in values)+r' \\')
        displayed.append(dict(payload_bytes=payload,aware_preparation_s=values[0],globaleaks_preparation_s=values[1],aware_opening_sum_s=values[2],globaleaks_opening_s=values[3]))
    write_csv(root/'table_IV_display.csv',displayed)
    (root/'table_IV.tex').write_text('\n'.join(header+[r'\bottomrule',r'\end{tabular}'])+'\n')

def main():
    p=argparse.ArgumentParser();p.add_argument('--results',type=Path,required=True);p.add_argument('--figures',type=Path,required=True);p.add_argument('--client-only',action='store_true');p.add_argument('--protocol-only',action='store_true',help='Render complete Fig. 3 and Tables II–IV while the system sweep runs');args=p.parse_args();args.figures.mkdir(parents=True,exist_ok=True);os.environ.setdefault('MPLCONFIGDIR',str(args.figures/'.matplotlib'))
    rows=load(args.results,['client'] if args.client_only else ['client','server'],args.protocol_only);summary=args.results/'summary';summary.mkdir(exist_ok=True);write_csv(summary/('client_summary.csv' if args.client_only else 'protocol_summary.csv' if args.protocol_only else 'all_summary.csv'),rows)
    style();r=Results(rows);figures(r,args.figures,args.client_only,args.protocol_only)
    if not args.client_only:
        tables(r,summary,args.results)
        replay=[x for x in rows if x['operation']=='ReplayRace']
        if replay:
            write_csv(summary/'security_replay.csv',replay)
            raw=[]
            for job in jobs('server'):
                if job['operation']=='ReplayRace':raw.extend(csv.DictReader((args.results/'server/raw'/(job['name']+'.csv')).open()))
            write_csv(summary/'security_replay_raw.csv',raw)
        for row in replay:
            if row['metric']=='accepted' and row['mean']!=1:raise ValueError('replay acceptance condition')
    print('CLIENT_FIGURE_RENDERED' if args.client_only else 'PROTOCOL_RESULTS_RENDERED' if args.protocol_only else 'PAPER_RESULTS_RENDERED')
if __name__=='__main__':main()
