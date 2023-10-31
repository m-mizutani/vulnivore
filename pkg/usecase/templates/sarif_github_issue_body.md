# Summary

{{ .Rule.FullDescription.Text }}

# Detail

[{{ .Rule.HelpURI }}]({{ .Rule.HelpURI }})

{{ .Rule.Help.Markdown }}

# Properties

- **Score**: {{ index .Rule.Properties "security-severity" }} / 10.0
- **Tags**: {{ range .Rule.Properties.tags }}{{ . }} {{ end }}

# Targets
{{ range .Result.Locations }}
- `{{ .Message.Text }}`{{ end }}
