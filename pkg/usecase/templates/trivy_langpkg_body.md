# Summary

{{ .Vuln.Description }}

# Detail

- **ID**: {{ .Vuln.VulnerabilityID }}
- **Target**: {{ .Result.Target }} ({{ .Result.Type }})
- **Package Name**: {{ .Vuln.PkgName }}
- **Package Path**: {{ .Vuln.PkgPath }}
- **Installed Version**: {{ .Vuln.InstalledVersion }}
- **Fixed Version**: {{ or .Vuln.FixedVersion "N/A" }}
- **Severity**: {{ .Vuln.Severity }}
- **Detected Image**: {{ .Result.Target }}
- **CWEs**: {{ range .Vuln.CweIDs }}`{{ . }}` {{ end }}

# CVSS

| Vendor | Version | Vector |Score |
| --- | --- | --- | --- |
{{ range $vendor, $cvss := .Vuln.CVSS }}{{ if $cvss.V3Vector }}| {{ $vendor }} | V3 | `{{ $cvss.V3Vector }}` | {{ $cvss.V3Score }} |
{{ end }}{{ if $cvss.V2Vector }}| {{ $vendor }} | V2 | `{{ $cvss.V2Vector }}` | {{ $cvss.V2Score }} |
{{ end }}{{ end }}

# References

{{ range .Vuln.References }}
- {{ . }}{{ end }}
