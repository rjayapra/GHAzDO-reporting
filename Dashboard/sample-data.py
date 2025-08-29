import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random, os

random.seed(42)
np.random.seed(42)

org = 'sample-org'
projects = ['Payments', 'CitizenServices', 'TransitOps']
repos = [
    ('Payments','payments-api'),
    ('Payments','billing-service'),
    ('Payments','invoicing-ui'),
    ('CitizenServices','licensing-portal'),
    ('CitizenServices','case-management'),
    ('CitizenServices','notification-worker'),
    ('TransitOps','route-optimizer'),
    ('TransitOps','vehicle-telemetry'),
    ('TransitOps','ticketing-web'),
    ('TransitOps','ops-tools'),
    ('Payments','data-models'),
    ('CitizenServices','identity-gateway'),
    ('CitizenServices','docs-site'),
    ('TransitOps','mobile-app'),
    ('Payments','terraform-infra')
]

# helper to create IDs
repo_ids = {name: f"{i:08x}-{i:04x}-{i:04x}-{i:04x}-{i:012x}" for i, (_,name) in enumerate(repos, start=1001)}

supported_langs_map = {
    'payments-api': 'csharp',
    'billing-service': 'java',
    'invoicing-ui': 'javascript',
    'licensing-portal': 'csharp',
    'case-management': 'python',
    'notification-worker': 'python',
    'route-optimizer': 'cpp',
    'vehicle-telemetry': 'go',
    'ticketing-web': 'javascript',
    'ops-tools': '',
    'data-models': '',
    'identity-gateway': 'csharp',
    'docs-site': '',
    'mobile-app': 'swift',
    'terraform-infra': ''
}

has_code_map = {
    'payments-api': True,
    'billing-service': True,
    'invoicing-ui': True,
    'licensing-portal': True,
    'case-management': True,
    'notification-worker': True,
    'route-optimizer': True,
    'vehicle-telemetry': True,
    'ticketing-web': True,
    'ops-tools': True,
    'data-models': False,  # no code
    'identity-gateway': True,
    'docs-site': False,     # docs only
    'mobile-app': True,
    'terraform-infra': True # infra code (unsupported for CodeQL in our simple map)
}

# which repos will have alerts
repos_with_alerts = {
    'payments-api': {'code':3,'dependency':5,'secret':1},
    'billing-service': {'code':2,'dependency':2,'secret':0},
    'invoicing-ui': {'code':1,'dependency':3,'secret':2},
    'licensing-portal': {'code':0,'dependency':4,'secret':0},
    'case-management': {'code':4,'dependency':1,'secret':1},
    'vehicle-telemetry': {'code':2,'dependency':0,'secret':0},
    'ticketing-web': {'code':0,'dependency':2,'secret':1},
    'identity-gateway': {'code':3,'dependency':2,'secret':0},
    'mobile-app': {'code':1,'dependency':1,'secret':0},
}

severities = ['critical','high','medium','low']

alerts_rows = []
with_rows = []
no_rows = []

now = datetime.utcnow()

for proj, repo in repos:
    rid = repo_ids[repo]
    def_branch = 'main'
    supported = supported_langs_map[repo]
    has_code = has_code_map[repo]

    # simulate analyzed branches if supported and code exists
    codeql_analyzed = []
    if has_code and supported:
        codeql_analyzed = ['main']
        if random.random() > 0.6:
            codeql_analyzed.append('release')

    if repo in repos_with_alerts:
        counts = repos_with_alerts[repo]
        total = sum(counts.values())

        sev_counts = {k:0 for k in severities}
        for t, c in counts.items():
            for i in range(c):
                sev = np.random.choice(severities, p=[0.15,0.35,0.35,0.15])
                sev_counts[sev]+=1
                aid = random.randint(100000,999999)
                title = {
                    'code':'CodeQL: Potential SQL injection',
                    'dependency':'Vulnerable dependency found',
                    'secret':'Secret detected in commit history'
                }[t]
                row = {
                    'Organization': org,
                    'Project': proj,
                    'Repository': repo,
                    'RepositoryId': rid,
                    'AlertId': aid,
                    'AlertType': t,
                    'Severity': sev,
                    'State': np.random.choice(['active','dismissed','fixed'], p=[0.7,0.1,0.2]),
                    'Title': title,
                    'RuleId': 'ghas-'+t,
                    'RuleName': title,
                    'RepoUrl': f'https://dev.azure.com/{org}/{proj}/_git/{repo}',
                    'FirstSeen': (now - timedelta(days=random.randint(5,90))).isoformat(),
                    'LastSeen': now.isoformat()
                }
                alerts_rows.append(row)
        with_rows.append({
            'Organization': org,
            'Project': proj,
            'Repository': repo,
            'RepositoryId': rid,
            'DefaultBranch': def_branch,
            'SupportedLangs': supported,
            'HasAnyCode': has_code,
            'CodeQLAnalyzedBranches': ','.join(codeql_analyzed),
            'Alerts_Total': total,
            'Alerts_Code': counts['code'],
            'Alerts_Dependency': counts['dependency'],
            'Alerts_Secret': counts['secret'],
            'Sev_Critical': sev_counts['critical'],
            'Sev_High': sev_counts['high'],
            'Sev_Medium': sev_counts['medium'],
            'Sev_Low': sev_counts['low']
        })
    else:
        # decide reason
        if not has_code:
            reason = 'NoCode'
        elif not supported:
            reason = 'UnsupportedLanguage'
        else:
            # supported and code, but no alerts -> scanned or not?
            reason = 'NoAlerts'
        no_rows.append({
            'Organization': org,
            'Project': proj,
            'Repository': repo,
            'RepositoryId': rid,
            'DefaultBranch': def_branch,
            'SupportedLangs': supported,
            'HasAnyCode': has_code,
            'CodeQLAnalyzedBranches': ','.join(codeql_analyzed),
            'Reason': reason
        })

alerts_df = pd.DataFrame(alerts_rows)
with_df   = pd.DataFrame(with_rows)
no_df     = pd.DataFrame(no_rows)

outdir = '/mnt/data/ghas-dash'
os.makedirs(outdir, exist_ok=True)
alerts_df.to_csv(os.path.join(outdir,'alerts.csv'), index=False)
with_df.to_csv(os.path.join(outdir,'repos_with_vulnerabilities.csv'), index=False)
no_df.to_csv(os.path.join(outdir,'repos_without_vulnerabilities.csv'), index=False)

outdir