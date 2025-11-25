# Shai-Hulud 2.0 Supply Chain Attack Scanner

A comprehensive security scanner to detect indicators of compromise from the **Shai-Hulud 2.0 npm supply chain attack** (November 2025).

## Background

On November 21-25, 2025, a massive supply chain attack compromised numerous npm packages, affecting over 25,000 GitHub repositories. The attack:

- Trojanized legitimate npm packages via compromised maintainer accounts
- Executed malicious code during `preinstall` phase
- Exfiltrated developer secrets (GitHub tokens, AWS/Azure/GCP credentials)
- Created backdoors via self-hosted GitHub runners
- Deployed malicious GitHub workflows for persistent access

**Reference:** [Wiz Blog - Shai-Hulud 2.0 Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)

## Features

This scanner checks for:

- ✅ **Malicious files** created by the worm (`setup_bun.js`, `cloud.json`, `truffleSecrets.json`, etc.)
- ✅ **Compromised npm packages** with specific malicious versions
- ✅ **Suspicious GitHub workflows** (`discussion.yaml` backdoor, `formatter_*.yml` secret exfiltration)
- ✅ **Suspicious self-hosted runners** (SHA1HULUD pattern)
- ✅ **Recently created repositories** during the attack window
- ✅ **Cloud credential files** that may have been exfiltrated
- ✅ **TruffleHog installation** (malware creates `truffleSecrets.json`)
- ✅ **npm configuration** security settings

## Requirements

- **bash** 4.0+
- **jq** - JSON parsing
- **npm** - Package checking
- **gh** (GitHub CLI) - Optional but recommended for GitHub checks

### Installation of Dependencies

**macOS:**
```bash
brew install jq gh
gh auth login
```

**Ubuntu/Debian:**
```bash
sudo apt-get install jq
# For GitHub CLI, see: https://cli.github.com/
```

## Usage

```bash
# Make executable
chmod +x shai-hulud-scanner.sh

# Scan current directory
./shai-hulud-scanner.sh

# Scan specific directory
./shai-hulud-scanner.sh ~/projects

# Scan all git repos
./shai-hulud-scanner.sh ~/git

# Show help
./shai-hulud-scanner.sh --help
```

## What It Checks

### 1. Malicious Files
The scanner looks for files created by the malware:
- `setup_bun.js` - Malicious payload
- `bun_environment.js` - Malicious payload
- `cloud.json` - Exfiltrated cloud credentials
- `contents.json` - Exfiltrated data
- `environment.json` - Exfiltrated environment variables
- `truffleSecrets.json` - Exfiltrated secrets
- `actionsSecrets.json` - Exfiltrated GitHub Actions secrets

### 2. Malicious GitHub Workflows
- `.github/workflows/discussion.yaml` - Backdoor that allows arbitrary code execution via GitHub discussions on self-hosted runners
- `.github/workflows/formatter_*.yml` - Secret exfiltration workflow that dumps `toJSON(secrets)`

### 3. Compromised npm Packages
Checks for specific malicious versions of packages including:
- `@postman/tunnel-agent` (27% prevalence)
- `posthog-node`, `posthog-js` (25% prevalence)
- `@asyncapi/*` packages (17-20% prevalence)
- `zapier-platform-*` packages
- `@ensdomains/*` packages
- And 100+ more packages with specific version matching

### 4. GitHub Security
- Self-hosted runners with suspicious names (SHA1HULUD pattern)
- Repositories created during the attack window (Nov 21+)
- Workflows containing secret dumping patterns
- Exfiltration artifacts in repositories

### 5. Cloud Credentials
Checks for credential files that may have been exfiltrated:
- `~/.aws/credentials`
- `~/.azure/`
- `~/.config/gcloud/application_default_credentials.json`

## Output

The scanner provides color-coded output:
- 🔴 **CRITICAL** - Definite indicators of compromise
- 🟡 **WARNING** - Potential issues requiring review
- 🟢 **OK** - Check passed
- 🔵 **INFO** - Informational messages

## Remediation Steps

If issues are found:

1. **Remove all node_modules:**
   ```bash
   find . -type d -name node_modules -exec rm -rf {} +
   ```

2. **Clear npm cache:**
   ```bash
   npm cache clean --force
   ```

3. **Rotate ALL credentials:**
   - GitHub tokens
   - npm tokens
   - AWS credentials
   - Azure credentials
   - GCP credentials

4. **Remove suspicious workflows:**
   - Delete `.github/workflows/discussion.yaml`
   - Delete `.github/workflows/formatter_*.yml`

5. **Check GitHub audit logs:**
   - Review for unauthorized access
   - Check for unexpected repository creation

6. **Reinstall dependencies:**
   ```bash
   npm install
   npm audit
   ```

## Prevention

- Enable npm ignore-scripts: `npm config set ignore-scripts true`
- Use lockfiles and pin dependency versions
- Regularly audit dependencies: `npm audit`
- Use security tools like Socket.dev, Snyk, or Dependabot
- Restrict CI/CD network access
- Use short-lived, scoped tokens
- Enable GitHub secret scanning and push protection

## Contributing

Issues and pull requests welcome at: https://github.com/MichaelAntonFischer/shai-hulud-2.0-scanner

## License

MIT License

## Credits

- Scanner created by Michael Anton Fischer (@MichaelAntonFischer)
- Attack research by [Wiz Research](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- Additional research by [Aikido Security](https://www.aikido.dev/)

