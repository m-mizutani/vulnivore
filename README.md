# vulnivore
vulnivore is GitHub issue creator from SARIF data

![Overview](https://github.com/m-mizutani/vulnivore/assets/605953/1d76ac7a-b609-4f12-95ae-4e3930a956bb)

Vulnivore is a vulnerability management tool for GitHub private repository. It converts [SARIF](https://sarifweb.azurewebsites.net) format data and [Trivy](https://github.com/aquasecurity/trivy) scan result into GitHub issues. It is useful for those who want to manage vulnerabilities in private repositories without GitHub Advanced Security.

## Main features

- Customizable issue body template
- Prevent duplicated issues
- Customizable policy in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) for issue creation, label and assignee

## Quick start

> [!WARNING]
> This quick start guide is for trial. It is not recommended to use in production environment. If you want to use it in production environment, please read [Configuration your GitHub App](#configuration-your-github-app) section.

### 1. Install GitHub App

1. Open [GitHub App page](https://github.com/apps/vulnivore) and push "Configure" button
2. Choose organization or user account to install
3. Choose repositories to install and push "Install" button
4. Move to configuration page like URL https://github.com/settings/installations/XXXX and copy `XXXX` part as `INSTALLATION_ID`

### 2. Add GitHub Actions workflow

## Configuration your GitHub App



## License

Apache License 2.0
