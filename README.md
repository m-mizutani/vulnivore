# vulnivore
vulnivore is GitHub issue creator from SARIF data

![Overview](https://github.com/m-mizutani/vulnivore/assets/605953/1d76ac7a-b609-4f12-95ae-4e3930a956bb)

Vulnivore is a vulnerability management tool designed specifically for GitHub private repositories. It has the ability to convert security scan results into GitHub issues. Vulnivore supports [SARIF](https://sarifweb.azurewebsites.net) format and [Trivy](https://github.com/aquasecurity/trivy) json output format. This tool is particularly beneficial for those who wish to manage vulnerabilities within private repositories without the need for GitHub Advanced Security.

## Key Features

- Ability to customize the issue body template
- Prevents duplication of issues
- Offers a customizable policy in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) for the creation of issues, labels, and assignees

## Quick Start Guide

> [!WARNING]
> This quick start guide is intended for trial purposes only. It is not recommended for use in a production environment. For production use, please refer to the [Configuring your GitHub App](#configuring-your-github-app) section.

### 1. Installing the GitHub App

1. Navigate to the [GitHub App page](https://github.com/apps/vulnivore) and click on the "Configure" button.
2. Select the organization or user account you wish to install the app on.
3. Choose the repositories for installation and click on the "Install" button.
4. You'll be redirected to a configuration page with a URL similar to https://github.com/settings/installations/XXXX. Copy the `XXXX` part of the URL, which is your `INSTALLATION_ID`.

### 2. Adding the GitHub Actions Workflow

Add a `.github/workflows/vulnivore.yml` file to your repository. This step assumes your repository contains a `Dockerfile` to build an image.

```yaml
name: Build and Scan

on:
  push:
    branch:
      main

env:
  TAG_NAME: your-repo-name:${{ github.sha }}

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write # Need to authenticate for vulnivore
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: Set up Docker buildx
        uses: docker/setup-buildx-action@v2
      - name: Build Docker image
        run: docker build . -t ${{ env.TAG_NAME }}
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: "image"
          image-ref: ${{ env.TAG_NAME }}
          format: "json"
          output: "trivy-results.json"

      - name: Upload Trivy results to Vulnivore
        uses: m-mizutani/vulnivore-upload@main
        with:
          filepath: trivy-results.json
          url: https://vulnivore-j47o6xodla-an.a.run.app/webhook/github/action/trivy
          installation_id: "XXXX" # Put your INSTALLATION_ID
```

After a successful vulnerability detection, you can locate the identified issues within the 'Issues' section of your GitHub repository.

## Configuration your GitHub App

To be written

## License

Apache License 2.0
