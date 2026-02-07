# vc-ad-triage (read-only)

Read-only PowerShell 5.1 script that collects **basic AD information** from a **domain-joined machine** without RSAT.

## Run
```powershell
.\VC-Triage-AD.ps1
```

## Optional flags
- Include OU ACL/delegation snapshot (best-effort; permissions may limit results):
```powershell
.\VC-Triage-AD.ps1 -IncludeAcls -AclLimit 500
```

- Cap OU collection:
```powershell
.\VC-Triage-AD.ps1 -MaxOUs 5000
```

- Cap OU depth relative to the domain DN:
```powershell
.\VC-Triage-AD.ps1 -MaxDepth 6
```

## Output files
- triage.log
- domain_forest.json
- naming_contexts.json
- ou_list.csv
- ou_list.json
- ou_tree.txt
- ou_acl.csv (only if -IncludeAcls)

## Notes
- No changes are made to AD.
- ACL export can be large. Use -AclLimit or skip it.
