## Power BI template (Power Query + DAX + Pages)

Open Power BI Desktop → Get Data → Folder → point at the folder with your 3 CSVs → transform with the queries below.

### Power Query (M)
(A) Alerts table

```

let
  Source    = Folder.Files("C:\path\to\ghas-dash"),
  Filter    = Table.SelectRows(Source, each Text.EndsWith([Name], "alerts.csv")),
  Csv       = Csv.Document(File.Contents(Filter{0}[Folder Path] & Filter{0}[Name]),[Delimiter=",", Columns=13, Encoding=65001, QuoteStyle=QuoteStyle.Csv]),
  Promoted  = Table.PromoteHeaders(Csv, [PromoteAllScalars=true]),
  Types     = Table.TransformColumnTypes(Promoted, {
      {"Organization", type text},{"Project", type text},{"Repository", type text},{"RepositoryId", type text},
      {"AlertId", Int64.Type},{"AlertType", type text},{"Severity", type text},{"State", type text},
      {"Title", type text},{"RuleId", type text},{"RuleName", type text},{"RepoUrl", type text},
      {"FirstSeen", type datetime},{"LastSeen", type datetime}
  })
in
  Types
```

(B) ReposWithVulnerabilities table

```
let
  Source    = Folder.Files("C:\path\to\ghas-dash"),
  Filter    = Table.SelectRows(Source, each Text.EndsWith([Name], "repos_with_vulnerabilities.csv")),
  Csv       = Csv.Document(File.Contents(Filter{0}[Folder Path] & Filter{0}[Name]),[Delimiter=",", Columns=16, Encoding=65001, QuoteStyle=QuoteStyle.Csv]),
  Promoted  = Table.PromoteHeaders(Csv, [PromoteAllScalars=true]),
  Types     = Table.TransformColumnTypes(Promoted, {
      {"Organization", type text},{"Project", type text},{"Repository", type text},{"RepositoryId", type text},
      {"DefaultBranch", type text},{"SupportedLangs", type text},{"HasAnyCode", type logical},
      {"CodeQLAnalyzedBranches", type text},{"Alerts_Total", Int64.Type},{"Alerts_Code", Int64.Type},
      {"Alerts_Dependency", Int64.Type},{"Alerts_Secret", Int64.Type},
      {"Sev_Critical", Int64.Type},{"Sev_High", Int64.Type},{"Sev_Medium", Int64.Type},{"Sev_Low", Int64.Type}
  })
in
```

(C) ReposWithoutVulnerabilities table
```
let
  Source    = Folder.Files("C:\path\to\ghas-dash"),
  Filter    = Table.SelectRows(Source, each Text.EndsWith([Name], "repos_without_vulnerabilities.csv")),
  Csv       = Csv.Document(File.Contents(Filter{0}[Folder Path] & Filter{0}[Name]),[Delimiter=",", Columns=9, Encoding=65001, QuoteStyle=QuoteStyle.Csv]),
  Promoted  = Table.PromoteHeaders(Csv, [PromoteAllScalars=true]),
  Types     = Table.TransformColumnTypes(Promoted, {
      {"Organization", type text},{"Project", type text},{"Repository", type text},{"RepositoryId", type text},
      {"DefaultBranch", type text},{"SupportedLangs", type text},{"HasAnyCode", type logical},
      {"CodeQLAnalyzedBranches", type text},{"Reason", type text}
  })
in
  Types
```

(D) Relationships
In the Model view, relate:

Alerts[RepositoryId] → ReposWithVulnerabilities[RepositoryId] (Many-to-one)
ReposWithoutVulnerabilities[RepositoryId] is a separate dimension-like table (no relationship needed unless you want a combined table).

### DAX Measures (on ReposWithVulnerabilities)

```
Total Alerts = SUM ( ReposWithVulnerabilities[Alerts_Total] )

Alerts (CodeQL) = SUM ( ReposWithVulnerabilities[Alerts_Code] )

Alerts (Dependency) = SUM ( ReposWithVulnerabilities[Alerts_Dependency] )

Alerts (Secret) = SUM ( ReposWithVulnerabilities[Alerts_Secret] )

Critical Alerts = SUM ( ReposWithVulnerabilities[Sev_Critical] )
High Alerts     = SUM ( ReposWithVulnerabilities[Sev_High] )
Medium Alerts   = SUM ( ReposWithVulnerabilities[Sev_Medium] )
Low Alerts      = SUM ( ReposWithVulnerabilities[Sev_Low] )
```

### Suggested Visuals / Pages
Page 1 – “Vulnerabilities Found”

KPI cards: Total Alerts, Critical Alerts, High Alerts, Medium Alerts, Low Alerts
Clustered bar chart: Repository (axis) vs Alerts (CodeQL), Alerts (Dependency), Alerts (Secret)
Matrix: Project → Repository rows; columns = Severity (use measures)
Slicer: Project, AlertType, Severity
(Optional) Table from Alerts with Title, RuleName, State, LastSeen for triage

Page 2 – “No Vulnerabilities (Why?)”

Donut: ReposWithoutVulnerabilities[Reason] (counts)
Table: Project, Repository, Reason, SupportedLangs, CodeQLAnalyzedBranches
Card: Count of repos by reason
Slicers: Project, Reason