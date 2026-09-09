#!/usr/bin/env python3
"""Run the paper's complete parameter sweeps with genuine BN462 operations."""
import argparse,csv,json,os,platform,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
K=1024;M=K*K;G=K*M
DEFAULT_CONFIG=ROOT/'config/defaults.json'
DEFAULTS=json.loads(DEFAULT_CONFIG.read_text())['protocol']
PAYLOADS=[10*K,100*K,512*K,M,20*M,50*M,100*M,150*M,500*M,G,5*G]
TOKENS=[1,5,10,15,20,30]
CLIENTS=[1,2,4,8,16,32,64,128,256]
def jobs(role,fig3b_rounds=30,defaults=None):
    defaults=defaults or DEFAULTS
    out=[]
    def add(name,op,runs=None,warmups=None,n=None,t=None,m=None,payload=None,users=1,workers=None,clients=1,targets=()):
        runs=defaults['runs'] if runs is None else runs
        warmups=defaults['warmups'] if warmups is None else warmups
        n=defaults['n'] if n is None else n
        t=defaults['t'] if t is None else t
        m=defaults['m'] if m is None else m
        payload=defaults['payload_bytes'] if payload is None else payload
        workers=workers or (defaults['server_workers'] if role=='server' else defaults['client_workers'])
        job=dict(name=name,operation=op,runs=runs,warmups=warmups,n=n,t=t,m=m,payload=payload,users=users,workers=workers,clients=clients,targets=list(targets))
        if role=='client' and 'Fig3b' in targets:
            job.update(rounds=fig3b_rounds,runs_per_round=runs,runs=runs*fig3b_rounds,stream=True)
        out.append(job)
    if role=='client':
        for m in TOKENS:add(f'fig3_regobt_m{m}','RegObt',m=m,targets=['Fig3a','TableII'] if m==15 else ['Fig3a'])
        add('table2_regu','RegU',targets=['TableII'])
        for p in PAYLOADS:
            runs,warmups=(1,0) if p==5*G else (5,2) if p>=50*M else (30,10)
            for op in ['TGSEnc','RepGen']:add(f'fig3_{op}_{p}',op,runs,warmups,payload=p,targets=['Fig3b','TableII'] if p==M and op=='RepGen' else ['Fig3b'])
        add('table3_holder_client','HolderAblation',targets=['TableIII'])
    if role=='server':
        for m in TOKENS:add(f'fig3_regiss_m{m}','RegIss',m=m,targets=['Fig3a','TableII'] if m==15 else ['Fig3a'])
        for n in [6,9,12,15]:
            for t in [2,4,6,8,10]:
                if t<=n:add(f'fig3_open_n{n}_t{t}','CompleteOpen',n=n,t=t,targets=['Fig3c'])
        for op in ['Setup','PostAccept','RepDec','RepCom','CompleteOpen']:add(f'table2_{op}',op,targets=['TableII'])
        add('table3_holder_server','HolderAblation',targets=['TableIII'])
        add('table3_opening','OpeningAblation',targets=['TableIII'])
        for p in [10*K,M,100*M,G,5*G]:
            runs,warmups=(1,0) if p>=G else (30,10)
            for op in ['RepGen','RepDec','RepCom']:add(f'table4_{op}_{p}',op,runs,warmups,payload=p,targets=['TableIV'])
        for clients in [2,4,8,16,32,64]:add(f'replay_c{clients}','ReplayRace',100,10,clients=clients,targets=['SecurityReplay'])
        for workers in [1,4,8,16]:
            for users in [10,100,500,1000,5000,10000]:add(f'fig4_issuance_u{users}_w{workers}','EpochIssuance',10 if users<=1000 else 3,10,users=users,workers=workers,targets=['Fig4a'])
        for clients in CLIENTS:add(f'fig4_bb_c{clients}','BB',5,20,clients=clients,targets=['Fig4b'])
    return out

def argv(binary,j,runs=None):
    command=[str(binary),j['operation'],str(runs if runs is not None else j['runs'])]+[str(j[k]) for k in ['warmups','n','t','m','payload','users','workers','clients']]
    return command+['stream'] if j.get('stream') else command
def main():
    p=argparse.ArgumentParser();p.add_argument('--role',required=True,choices=['client','server']);p.add_argument('--output',type=Path,required=True);p.add_argument('--binary',type=Path,default=ROOT/'target/release/aware-bench');p.add_argument('--config',type=Path,default=DEFAULT_CONFIG);p.add_argument('--job',action='append');p.add_argument('--target',action='append',help='Run jobs tagged for a paper artifact, e.g. TableII, Fig3a, Fig3b, Fig3c, TableIII, TableIV, Fig4a, Fig4b.');p.add_argument('--manifest-only',action='store_true');p.add_argument('--cpus',help='taskset physical CPU list on the server');p.add_argument('--fig3b-rounds',type=int,default=30);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=True);(args.output/'raw').mkdir(exist_ok=True)
    defaults=json.loads(args.config.read_text())['protocol']
    manifest=jobs(args.role,args.fig3b_rounds,defaults)
    selected=[j for j in manifest if (args.job is None or j['name'] in args.job) and (args.target is None or set(j['targets']).intersection(args.target))]
    (args.output/'manifest.json').write_text(json.dumps(selected,indent=2)+'\n')
    metadata=dict(role=args.role,hostname=platform.node(),system=platform.platform(),machine=platform.machine(),cpu_count=os.cpu_count(),cpus=args.cpus,curve='MIRACL Core BN462',security_bits=defaults['lambda_bits'],symmetric='AES-256-GCM (OpenSSL)',iv_bytes=16,tag_bytes=16,started=time.strftime('%Y-%m-%dT%H:%M:%S%z'),binary=str(args.binary),config=str(args.config),submission_pool=os.environ.get('AWARE_SUBMISSION_POOL','65536'))
    for name,command in [('cpu',['sysctl','-n','machdep.cpu.brand_string'] if platform.system()=='Darwin' else ['lscpu']),('rustc',['rustc','--version'])]:
        metadata[name]=subprocess.run(command,text=True,capture_output=True).stdout.strip()
    (args.output/'environment.json').write_text(json.dumps(metadata,indent=2)+'\n')
    if args.manifest_only:return
    for number,j in enumerate(selected,1):
        path=args.output/'raw'/(j['name']+'.csv');status=path.with_suffix('.status.json')
        if status.exists() and json.loads(status.read_text()).get('complete'):
            print(f'[{number}/{len(selected)}] complete {j["name"]}',flush=True);continue
        start=time.time();rounds=j.get('rounds',1);round_runs=j.get('runs_per_round',j['runs'])
        if rounds==1:
            cmd=argv(args.binary,j)
            if args.cpus:cmd=['taskset','-c',args.cpus]+cmd
            print(f'[{number}/{len(selected)}] '+ ' '.join(cmd),flush=True)
            with path.open('w') as out,path.with_suffix('.stderr').open('w') as err:result=subprocess.run(cmd,stdout=out,stderr=err)
            if result.returncode:raise RuntimeError(f'{j["name"]} failed: {path.with_suffix(".stderr").read_text()}')
            with path.open() as source:all_rows=list(csv.DictReader(source))
        else:
            all_rows=[];fieldnames=None
            for round_number in range(1,rounds+1):
                round_path=args.output/'raw'/'rounds'/f'round_{round_number:02d}'/(j['name']+'.csv');round_path.parent.mkdir(parents=True,exist_ok=True)
                cmd=argv(args.binary,j,round_runs)
                if args.cpus:cmd=['taskset','-c',args.cpus]+cmd
                print(f'[{number}/{len(selected)}] round {round_number}/{rounds} '+ ' '.join(cmd),flush=True)
                with round_path.open('w') as out,round_path.with_suffix('.stderr').open('w') as err:result=subprocess.run(cmd,stdout=out,stderr=err)
                if result.returncode:raise RuntimeError(f'{j["name"]} round {round_number} failed: {round_path.with_suffix(".stderr").read_text()}')
                with round_path.open() as source:
                    reader=csv.DictReader(source);round_rows=list(reader);fieldnames=reader.fieldnames
                measured={int(r['run']) for r in round_rows}
                if measured!=set(range(1,round_runs+1)):raise RuntimeError(f'{j["name"]} round {round_number}: incomplete measured trial set')
                for row in round_rows:
                    row['run_in_round']=row['run'];row['round']=round_number;row['run']=str((round_number-1)*round_runs+int(row['run']))
                all_rows.extend(round_rows)
            with path.open('w',newline='') as out:
                writer=csv.DictWriter(out,fieldnames=fieldnames+['round','run_in_round']);writer.writeheader();writer.writerows(all_rows)
        measured={int(r['run']) for r in all_rows}
        if measured!=set(range(1,j['runs']+1)):raise RuntimeError(f'{j["name"]}: incomplete measured trial set')
        status.write_text(json.dumps(dict(complete=True,elapsed_seconds=time.time()-start,rows=len(all_rows),job=j),indent=2)+'\n')
    print('ROLE_PIPELINE_COMPLETE '+args.role,flush=True)
if __name__=='__main__':main()
