#!/bin/bash
#
# Shai-Hulud 2.0 Supply Chain Attack Scanner
# Based on: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
#
# This script scans for indicators of compromise from the Shai-Hulud 2.0
# npm supply chain attack (Nov 21-25, 2025).
#
# Usage: ./shai-hulud-scanner.sh [scan_directory]
#        If no directory specified, scans current directory
#
# Requirements:
#   - bash 4.0+
#   - jq (for JSON parsing)
#   - gh (GitHub CLI, optional but recommended)
#   - npm (for package checks)
#
# License: MIT
# Author: Michael Anton Fischer (@MichaelAntonFischer)
# Repository: https://github.com/MichaelAntonFischer/shai-hulud-2.0-scanner
#

set -euo pipefail

# Script version
VERSION="1.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Counters
ISSUES_FOUND=0
WARNINGS_FOUND=0

# Default scan directory (current directory if not specified)
SCAN_DIR="${1:-.}"

# Resolve to absolute path
SCAN_DIR="$(cd "$SCAN_DIR" 2>/dev/null && pwd)" || {
    echo -e "${RED}Error: Cannot access directory: $1${NC}"
    exit 1
}

# Log file in temp directory
LOG_FILE="${TMPDIR:-/tmp}/shai-hulud-scan-$(date +%Y%m%d-%H%M%S).log"

# Known affected packages with SPECIFIC MALICIOUS VERSIONS from Wiz blog
# Source: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
# Format: "package_name:malicious_versions" (comma-separated versions)
declare -A AFFECTED_PACKAGES_VERSIONS=(
    # High prevalence packages (13-27% of environments)
    ["@postman/tunnel-agent"]="0.6.4"
    ["posthog-node"]="4.3.1,4.3.2"
    ["posthog-js"]="1.194.0,1.194.1"
    ["@asyncapi/specs"]="6.8.1"
    ["@asyncapi/openapi-schema-parser"]="3.0.26"
    ["get-them-args"]="1.3.3,1.3.2"
    ["shell-exec"]="1.1.4,1.1.3"
    ["kill-port"]="2.0.2,2.0.1"
    
    # Zapier ecosystem
    ["zapier-platform-cli"]="18.0.4,18.0.3,18.0.2"
    ["zapier-platform-core"]="18.0.4,18.0.3,18.0.2"
    ["zapier-platform-schema"]="18.0.4,18.0.3,18.0.2"
    ["zapier-scripts"]="7.8.4,7.8.3"
    ["zapier-async-storage"]="1.0.3,1.0.2,1.0.1"
    
    # ENS/Ethereum ecosystem
    ["@ensdomains/ens-contracts"]="1.2.3,1.2.2,1.2.1"
    ["@ensdomains/ensjs"]="4.0.3,4.0.2"
    ["@ensdomains/thorin"]="0.6.52,0.6.51"
    ["@ensdomains/headless-web3-provider"]="1.0.9"
    ["@ensdomains/content-hash"]="3.1.1,3.1.2"
    ["@ensdomains/eth-ens-namehash"]="2.0.16"
    ["@ensdomains/ens-validation"]="0.1.1"
    ["@ensdomains/dnsprovejs"]="0.5.2,0.5.1"
    ["@ensdomains/buffer"]="0.1.2,0.1.1"
    ["@ensdomains/address-encoder"]="1.1.2,1.1.1"
    ["uniswap-router-sdk"]="1.6.2"
    ["uniswap-smart-order-router"]="3.16.26"
    ["uniswap-test-sdk-core"]="4.0.8"
    
    # AccordProject
    ["@accordproject/concerto-analysis"]="3.24.1"
    ["@accordproject/concerto-linter"]="3.24.1"
    ["@accordproject/concerto-linter-default-ruleset"]="3.24.1"
    ["@accordproject/concerto-metamodel"]="3.12.5"
    ["@accordproject/concerto-types"]="3.24.1"
    
    # AsyncAPI (extensive list)
    ["@asyncapi/avro-schema-parser"]="3.0.26"
    ["@asyncapi/converter"]="1.6.3,1.6.2"
    ["@asyncapi/diff"]="0.4.2"
    ["@asyncapi/dotnet-nats-template"]="0.14.1"
    ["@asyncapi/generator"]="2.5.1,2.5.2"
    ["@asyncapi/generator-react-sdk"]="1.1.3,1.1.2"
    ["@asyncapi/glee"]="0.0.1"
    ["@asyncapi/html-template"]="2.3.14,2.3.13"
    ["@asyncapi/java-spring-cloud-stream-template"]="0.15.1"
    ["@asyncapi/java-spring-template"]="1.6.1"
    ["@asyncapi/java-template"]="0.3.1"
    ["@asyncapi/markdown-template"]="1.7.1"
    ["@asyncapi/modelina"]="4.0.2,4.0.1"
    ["@asyncapi/nodejs-template"]="3.0.5,3.0.4"
    ["@asyncapi/nodejs-ws-template"]="0.10.13"
    ["@asyncapi/parser"]="3.4.1,3.4.2"
    ["@asyncapi/protobuf-schema-parser"]="3.3.1"
    ["@asyncapi/python-paho-template"]="0.2.15"
    ["@asyncapi/raml-dt-schema-parser"]="4.0.26"
    ["@asyncapi/react-component"]="2.0.1"
    ["@asyncapi/server-api"]="1.1.1"
    ["@asyncapi/studio"]="0.0.1"
    ["@asyncapi/ts-nats-template"]="0.0.1"
    
    # React Native packages
    ["react-native-modest-checkbox"]="3.3.1"
    ["react-native-modest-storage"]="2.1.1"
    ["react-native-phone-call"]="1.2.2,1.2.1"
    ["react-native-retriable-fetch"]="2.0.1,2.0.2"
    ["react-native-use-modal"]="1.0.3"
    ["react-native-view-finder"]="1.2.2,1.2.1"
    ["react-native-websocket"]="1.0.4,1.0.3"
    ["react-native-worklet-functions"]="3.3.3"
    
    # Svelte packages
    ["svelte-autocomplete-select"]="1.1.1"
    ["svelte-toasty"]="1.1.3,1.1.2"
    
    # Other affected packages
    ["02-echo"]="0.0.7"
    ["tcsp"]="2.0.2"
    ["tcsp-draw-test"]="1.0.5"
    ["tcsp-test-vd"]="2.4.4"
    ["solomon-api-stories"]="1.0.2"
    ["solomon-v3-stories"]="1.15.6"
    ["solomon-v3-ui-wrapper"]="1.6.1"
    ["rediff"]="1.0.5"
    ["rediff-viewer"]="0.0.7"
    ["rollup-plugin-httpfile"]="0.2.1"
    ["vite-plugin-httpfile"]="0.2.1"
    ["webpack-loader-httpfile"]="0.2.1"
    ["trigo-react-app"]="4.1.2"
    ["template-lib"]="1.1.4,1.1.3"
    ["template-micro-service"]="1.0.3,1.0.2"
    ["tenacious-fetch"]="2.3.3,2.3.2"
    ["typefence"]="1.2.2,1.2.3"
    ["typeorm-orbit"]="0.2.27"
    ["undefsafe-typed"]="1.0.4,1.0.3"
    ["token.js-fork"]="0.7.32"
    ["stoor"]="2.3.2"
    ["stat-fns"]="1.0.1"
    ["super-commit"]="1.0.1"
    ["sort-by-distance"]="2.0.1"
    ["set-nested-prop"]="2.0.1,2.0.2"
    ["samesame"]="1.0.3"
    ["redux-router-kit"]="1.2.2,1.2.4,1.2.3"
    ["react-qr-image"]="1.1.1"
    ["web-scraper-mcp"]="1.1.4"
    ["web-types-htmx"]="0.1.1"
    ["web-types-lit"]="0.1.1"
    ["wenk"]="1.0.9,1.0.10"
    ["uplandui"]="0.5.4"
    ["upload-to-play-store"]="1.0.2,1.0.1"
    ["url-encode-decode"]="1.0.2,1.0.1"
    ["use-unsaved-changes"]="1.0.9"
    ["valid-south-african-id"]="1.0.3"
    ["zuper-cli"]="1.0.1"
    ["zuper-sdk"]="1.0.57"
    ["zuper-stream"]="2.0.9"
    ["kill-port-process"]="3.2.2,3.2.1"
    ["fast-jwt"]="4.0.6,4.0.5"
    ["graphql-ws"]="5.16.2,5.16.1"
    ["primus-graphql"]="5.1.1"
    ["notistack-v4"]="3.0.2"
)

# Malicious files created by the worm
MALICIOUS_FILES=(
    "setup_bun.js"
    "bun_environment.js"
    "cloud.json"
    "contents.json"
    "environment.json"
    "truffleSecrets.json"
    "actionsSecrets.json"
)

# Malicious workflow patterns
MALICIOUS_WORKFLOW_PATTERNS=(
    "discussion.yaml"
    "formatter_"
)

print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
   _____ _           _       _    _       _           _   ___    ___  
  / ____| |         (_)     | |  | |     | |         | | |__ \  / _ \ 
 | (___ | |__   __ _ _ ______| |__| |_   _| |_   _  __| |    ) || | | |
  \___ \| '_ \ / _` | |______|  __  | | | | | | | |/ _` |   / / | | | |
  ____) | | | | (_| | |      | |  | | |_| | | |_| | (_| |  / /_ | |_| |
 |_____/|_| |_|\__,_|_|      |_|  |_|\__,_|_|\__,_|\__,_| |____(_)___/ 
                                                                       
EOF
    echo -e "${NC}"
    echo -e "${BOLD}Supply Chain Attack Scanner v${VERSION}${NC}"
    echo -e "Based on Wiz Research - November 2025"
    echo -e "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack"
    echo ""
}

print_section() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_error() {
    echo -e "${RED}[CRITICAL] $1${NC}"
    echo "[CRITICAL] $1" >> "$LOG_FILE"
    ((ISSUES_FOUND++)) || true
}

print_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] $1" >> "$LOG_FILE"
    ((WARNINGS_FOUND++)) || true
}

print_success() {
    echo -e "${GREEN}[OK] $1${NC}"
    echo "[OK] $1" >> "$LOG_FILE"
}

print_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    echo "[INFO] $1" >> "$LOG_FILE"
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Check dependencies
check_dependencies() {
    local missing=()
    
    if ! command_exists jq; then
        missing+=("jq")
    fi
    
    if ! command_exists npm; then
        missing+=("npm")
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Missing required dependencies: ${missing[*]}${NC}"
        echo "Please install them before running this script."
        echo ""
        echo "On macOS: brew install ${missing[*]}"
        echo "On Ubuntu/Debian: sudo apt-get install ${missing[*]}"
        exit 1
    fi
    
    if ! command_exists gh; then
        print_warning "GitHub CLI (gh) not installed - GitHub checks will be skipped"
        print_info "Install with: brew install gh (macOS) or see https://cli.github.com/"
    fi
}

# Check for trufflehog installation (suspicious if present without user knowledge)
check_trufflehog() {
    print_section "Checking for TruffleHog Installation"
    
    local found=false
    
    if command_exists trufflehog; then
        print_warning "trufflehog found in PATH: $(which trufflehog)"
        found=true
    fi
    
    if command_exists truffleHog; then
        print_warning "truffleHog found in PATH: $(which truffleHog)"
        found=true
    fi
    
    # Check npm global
    if npm list -g trufflehog 2>/dev/null | grep -q trufflehog; then
        print_warning "trufflehog found as npm global package"
        found=true
    fi
    
    # Check pip
    if command_exists pip3 && pip3 list 2>/dev/null | grep -qi trufflehog; then
        print_warning "trufflehog found as pip package"
        found=true
    fi
    
    # Check common binary locations
    local common_paths=(
        "/usr/local/bin/trufflehog"
        "/opt/homebrew/bin/trufflehog"
        "$HOME/.local/bin/trufflehog"
        "$HOME/go/bin/trufflehog"
    )
    
    for loc in "${common_paths[@]}"; do
        if [[ -f "$loc" ]]; then
            print_warning "trufflehog binary found at: $loc"
            found=true
        fi
    done
    
    if [[ "$found" == "false" ]]; then
        print_success "No trufflehog installation found"
    else
        print_info "Note: trufflehog is a legitimate security tool, but the Shai-Hulud malware"
        print_info "creates truffleSecrets.json files. Verify this is an intentional installation."
    fi
}

# Check for malicious files
check_malicious_files() {
    print_section "Scanning for Malicious Files Created by Shai-Hulud"
    
    local found_any=false
    
    for file in "${MALICIOUS_FILES[@]}"; do
        print_info "Searching for: $file"
        local results
        results=$(find "$SCAN_DIR" -name "$file" -type f 2>/dev/null || true)
        
        if [[ -n "$results" ]]; then
            found_any=true
            while IFS= read -r match; do
                print_error "MALICIOUS FILE FOUND: $match"
                echo "  File contents preview:"
                head -5 "$match" 2>/dev/null | sed 's/^/    /' || true
            done <<< "$results"
        fi
    done
    
    # Check for malicious workflows
    print_info "Searching for malicious GitHub workflows..."
    
    # discussion.yaml - the backdoor workflow
    local discussion_files
    discussion_files=$(find "$SCAN_DIR" -path "*/.github/workflows/discussion.yaml" -type f 2>/dev/null || true)
    if [[ -n "$discussion_files" ]]; then
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            # Check if it contains the malicious pattern
            if grep -q "self-hosted" "$match" 2>/dev/null && grep -q "github.event.discussion.body" "$match" 2>/dev/null; then
                found_any=true
                print_error "MALICIOUS WORKFLOW FOUND: $match"
                print_error "This workflow allows arbitrary code execution via GitHub discussions!"
            else
                print_warning "discussion.yaml found (may be legitimate, review manually): $match"
            fi
        done <<< "$discussion_files"
    fi
    
    # formatter_*.yml pattern - secret exfiltration workflow
    local formatter_files
    formatter_files=$(find "$SCAN_DIR" -path "*/.github/workflows/formatter_*.yml" -type f 2>/dev/null || true)
    if [[ -n "$formatter_files" ]]; then
        while IFS= read -r match; do
            [[ -z "$match" ]] && continue
            found_any=true
            if grep -q "toJSON(secrets)" "$match" 2>/dev/null; then
                print_error "MALICIOUS SECRET EXFILTRATION WORKFLOW FOUND: $match"
                print_error "This workflow exfiltrates GitHub secrets!"
            else
                print_warning "Suspicious formatter workflow found: $match"
            fi
        done <<< "$formatter_files"
    fi
    
    if [[ "$found_any" == "false" ]]; then
        print_success "No malicious files found"
    fi
}

# Check for affected npm packages with version matching
check_affected_packages() {
    print_section "Scanning for Affected npm Packages (Version-Specific)"
    
    local found_any=false
    
    # Find all package.json files (excluding node_modules, venvs, etc.)
    local package_files
    package_files=$(find "$SCAN_DIR" -name "package.json" \
        ! -path "*/node_modules/*" \
        ! -path "*/.venv/*" \
        ! -path "*/venv/*" \
        ! -path "*/site-packages/*" \
        ! -path "*/.next/*" \
        -type f 2>/dev/null || true)
    
    if [[ -z "$package_files" ]]; then
        print_info "No package.json files found in $SCAN_DIR"
        return
    fi
    
    local total_packages=${#AFFECTED_PACKAGES_VERSIONS[@]}
    print_info "Checking against $total_packages known affected packages with specific malicious versions..."
    
    while IFS= read -r pkg_file; do
        [[ -z "$pkg_file" ]] && continue
        
        local dir
        dir=$(dirname "$pkg_file")
        local lock_file="$dir/package-lock.json"
        
        for pkg_name in "${!AFFECTED_PACKAGES_VERSIONS[@]}"; do
            local malicious_versions="${AFFECTED_PACKAGES_VERSIONS[$pkg_name]}"
            
            # Check package-lock.json for exact versions (more reliable)
            if [[ -f "$lock_file" ]]; then
                # Extract version from package-lock.json
                local installed_version
                installed_version=$(jq -r --arg pkg "$pkg_name" \
                    '.packages["node_modules/" + $pkg].version // .dependencies[$pkg].version // empty' \
                    "$lock_file" 2>/dev/null || true)
                
                if [[ -n "$installed_version" ]]; then
                    # Check if installed version matches any malicious version
                    IFS=',' read -ra versions_array <<< "$malicious_versions"
                    for mal_ver in "${versions_array[@]}"; do
                        if [[ "$installed_version" == "$mal_ver" ]]; then
                            found_any=true
                            print_error "COMPROMISED PACKAGE FOUND: $pkg_name@$installed_version in $lock_file"
                            print_error "This exact version is known to be malicious!"
                        fi
                    done
                fi
            fi
            
            # Also check package.json for direct dependencies
            if grep -q "\"$pkg_name\"" "$pkg_file" 2>/dev/null; then
                local declared_version
                declared_version=$(jq -r --arg pkg "$pkg_name" \
                    '.dependencies[$pkg] // .devDependencies[$pkg] // empty' \
                    "$pkg_file" 2>/dev/null || true)
                
                if [[ -n "$declared_version" ]]; then
                    # Check if it could resolve to a malicious version
                    IFS=',' read -ra versions_array <<< "$malicious_versions"
                    for mal_ver in "${versions_array[@]}"; do
                        # Simple check - if declared version could match
                        if [[ "$declared_version" == "$mal_ver" ]] || \
                           [[ "$declared_version" == "^$mal_ver" ]] || \
                           [[ "$declared_version" == "~$mal_ver" ]]; then
                            found_any=true
                            print_warning "POTENTIALLY AFFECTED: $pkg_name ($declared_version) in $pkg_file"
                            print_warning "Malicious versions: $malicious_versions"
                        fi
                    done
                fi
            fi
        done
    done <<< "$package_files"
    
    if [[ "$found_any" == "false" ]]; then
        print_success "No affected packages found in dependencies"
    fi
}

# Check for suspicious npm configurations
check_npm_config() {
    print_section "Checking npm Configuration"
    
    # Check for ignore-scripts setting
    local ignore_scripts
    ignore_scripts=$(npm config get ignore-scripts 2>/dev/null || echo "false")
    if [[ "$ignore_scripts" == "false" ]]; then
        print_warning "npm ignore-scripts is disabled - lifecycle scripts will run during install"
        print_info "Consider enabling: npm config set ignore-scripts true"
    else
        print_success "npm ignore-scripts is enabled - good security practice"
    fi
    
    # Check npm cache location
    local cache_dir
    cache_dir=$(npm config get cache 2>/dev/null || echo "unknown")
    print_info "npm cache location: $cache_dir"
    
    # Check for any globally installed affected packages
    print_info "Checking npm global packages..."
    local global_list
    global_list=$(npm list -g --depth=0 2>/dev/null || true)
    
    local found_global=false
    for pkg_name in "${!AFFECTED_PACKAGES_VERSIONS[@]}"; do
        if echo "$global_list" | grep -q "$pkg_name@"; then
            local installed
            installed=$(echo "$global_list" | grep "$pkg_name@" | head -1)
            print_warning "Potentially affected package installed globally: $installed"
            found_global=true
        fi
    done
    
    if [[ "$found_global" == "false" ]]; then
        print_success "No affected packages found in global npm"
    fi
}

# Check cloud credentials for potential exposure
check_cloud_credentials() {
    print_section "Checking for Cloud Credential Files"
    
    print_info "The malware targets these credential locations for exfiltration:"
    
    local found_creds=false
    
    # AWS
    if [[ -f "$HOME/.aws/credentials" ]]; then
        print_warning "AWS credentials file exists: ~/.aws/credentials"
        found_creds=true
    fi
    
    # Azure
    if [[ -d "$HOME/.azure" ]]; then
        print_warning "Azure config directory exists: ~/.azure/"
        found_creds=true
    fi
    
    # GCP
    if [[ -f "$HOME/.config/gcloud/application_default_credentials.json" ]]; then
        print_warning "GCP credentials file exists"
        found_creds=true
    fi
    
    if [[ "$found_creds" == "true" ]]; then
        print_info "If you suspect compromise, rotate these credentials immediately!"
    else
        print_success "No cloud credential files found in standard locations"
    fi
    
    # Check for sensitive environment variables
    local sensitive_vars=("AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AZURE_CLIENT_SECRET" "GOOGLE_APPLICATION_CREDENTIALS" "GITHUB_TOKEN" "NPM_TOKEN" "GH_TOKEN")
    
    print_info "Checking for sensitive environment variables..."
    for var in "${sensitive_vars[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            print_warning "Environment variable $var is set"
        fi
    done
}

# GitHub organization/user detection and scanning
check_github() {
    print_section "GitHub Security Scan"
    
    if ! command_exists gh; then
        print_warning "GitHub CLI (gh) not installed - skipping GitHub checks"
        print_info "Install: brew install gh (macOS) or see https://cli.github.com/"
        return
    fi
    
    if ! gh auth status &>/dev/null 2>&1; then
        print_warning "GitHub CLI not authenticated - skipping GitHub checks"
        print_info "Authenticate with: gh auth login"
        return
    fi
    
    # Get authenticated user info
    local gh_user
    gh_user=$(gh api user --jq '.login' 2>/dev/null || echo "")
    
    if [[ -z "$gh_user" ]]; then
        print_warning "Could not determine GitHub user"
        return
    fi
    
    print_info "Authenticated as: $gh_user"
    
    # Try to detect organization from current git repo
    local detected_org=""
    if git rev-parse --git-dir &>/dev/null 2>&1; then
        detected_org=$(git remote get-url origin 2>/dev/null | sed -n 's/.*github.com[:/]\([^/]*\)\/.*/\1/p' || true)
    fi
    
    # Get list of organizations the user belongs to
    local orgs
    orgs=$(gh api user/orgs --jq '.[].login' 2>/dev/null || echo "")
    
    # Build list of accounts to scan (user + orgs)
    local accounts_to_scan=("$gh_user")
    if [[ -n "$orgs" ]]; then
        while IFS= read -r org; do
            [[ -n "$org" ]] && accounts_to_scan+=("$org")
        done <<< "$orgs"
    fi
    
    print_info "Will scan: ${accounts_to_scan[*]}"
    
    for account in "${accounts_to_scan[@]}"; do
        echo ""
        print_info "━━━ Scanning account: $account ━━━"
        
        # Check for self-hosted runners (potential SHA1HULUD backdoor)
        check_github_runners "$account"
        
        # Check for suspicious repositories
        check_github_repos "$account"
        
        # Check for suspicious workflows
        check_github_workflows "$account"
    done
}

# Check for suspicious GitHub self-hosted runners
check_github_runners() {
    local account="$1"
    
    print_info "Checking self-hosted runners for $account..."
    
    # Try org endpoint first, then user endpoint
    local runners
    runners=$(gh api "/orgs/$account/actions/runners" 2>/dev/null || \
              gh api "/users/$account/actions/runners" 2>/dev/null || \
              echo '{"total_count":0,"runners":[]}')
    
    local runner_count
    runner_count=$(echo "$runners" | jq '.total_count // 0' 2>/dev/null || echo "0")
    
    if [[ "$runner_count" -gt 0 ]]; then
        print_info "Found $runner_count self-hosted runner(s)"
        
        # Check for suspicious runner names (SHA1HULUD pattern)
        local suspicious
        suspicious=$(echo "$runners" | jq -r '.runners[]? | select(.name | test("sha1?hulud|hulud|shai"; "i")) | .name' 2>/dev/null || true)
        
        if [[ -n "$suspicious" ]]; then
            print_error "SUSPICIOUS RUNNER FOUND! Name matches Shai-Hulud pattern:"
            echo "$suspicious" | sed 's/^/    /'
            print_error "This runner may be a backdoor installed by the malware!"
        else
            print_success "No suspicious runner names found"
        fi
        
        # List all runners for manual review
        print_info "All runners (review for any unexpected entries):"
        echo "$runners" | jq -r '.runners[]? | "  - \(.name) (\(.status), \(.os))"' 2>/dev/null || true
    else
        print_info "No self-hosted runners found (or no access to view)"
    fi
}

# Check for suspicious GitHub repositories
check_github_repos() {
    local account="$1"
    
    print_info "Checking repositories for $account..."
    
    # Get repos
    local repos
    repos=$(gh repo list "$account" --json name,description,createdAt,isPrivate,pushedAt --limit 200 2>/dev/null || echo "[]")
    
    if [[ "$repos" == "[]" ]]; then
        print_info "No repositories found or no access"
        return
    fi
    
    # Check for repos with suspicious names/descriptions (hulud, exfil, etc.)
    local suspicious_repos
    suspicious_repos=$(echo "$repos" | jq -r '.[] | select((.name + " " + (.description // "")) | test("hulud|exfil|steal|secret.?dump"; "i")) | .name' 2>/dev/null || true)
    
    if [[ -n "$suspicious_repos" ]]; then
        print_error "SUSPICIOUS REPOSITORIES FOUND (match exfiltration patterns):"
        echo "$suspicious_repos" | sed 's/^/    /'
    fi
    
    # Check for repos created in the attack window (Nov 21-25, 2025)
    local attack_start="2025-11-21"
    local recent_repos
    recent_repos=$(echo "$repos" | jq -r --arg start "$attack_start" \
        '.[] | select(.createdAt >= $start) | "\(.name) (created: \(.createdAt | split("T")[0]))"' 2>/dev/null || true)
    
    if [[ -n "$recent_repos" ]]; then
        print_warning "Repositories created during attack window (Nov 21+):"
        echo "$recent_repos" | sed 's/^/    /'
        print_info "Review these to ensure they are legitimate"
    else
        print_success "No repositories created during the attack window"
    fi
}

# Check for suspicious GitHub workflows across repos
check_github_workflows() {
    local account="$1"
    
    print_info "Searching for suspicious workflows in $account repositories..."
    
    # Search for discussion.yaml workflows (the backdoor)
    local discussion_results
    discussion_results=$(gh search code "filename:discussion.yaml path:.github/workflows user:$account" --limit 10 2>/dev/null || \
                        gh search code "filename:discussion.yaml path:.github/workflows org:$account" --limit 10 2>/dev/null || true)
    
    if [[ -n "$discussion_results" ]]; then
        print_warning "Found discussion.yaml workflows (may be backdoors):"
        echo "$discussion_results" | head -10 | sed 's/^/    /'
    fi
    
    # Search for formatter_*.yml workflows (secret exfiltration)
    local formatter_results
    formatter_results=$(gh search code "filename:formatter_ path:.github/workflows user:$account" --limit 10 2>/dev/null || \
                       gh search code "filename:formatter_ path:.github/workflows org:$account" --limit 10 2>/dev/null || true)
    
    if [[ -n "$formatter_results" ]]; then
        print_warning "Found suspicious formatter workflows:"
        echo "$formatter_results" | head -10 | sed 's/^/    /'
    fi
    
    # Search for toJSON(secrets) pattern (secret dumping)
    local secrets_results
    secrets_results=$(gh search code "toJSON(secrets) path:.github/workflows user:$account" --limit 10 2>/dev/null || \
                     gh search code "toJSON(secrets) path:.github/workflows org:$account" --limit 10 2>/dev/null || true)
    
    if [[ -n "$secrets_results" ]]; then
        print_error "CRITICAL: Found workflows that dump secrets:"
        echo "$secrets_results" | head -10 | sed 's/^/    /'
    fi
    
    # Search for exfiltration artifacts in repos
    local artifact_results
    artifact_results=$(gh search code "truffleSecrets.json OR actionsSecrets.json OR cloud.json user:$account" --limit 10 2>/dev/null || \
                      gh search code "truffleSecrets.json OR actionsSecrets.json OR cloud.json org:$account" --limit 10 2>/dev/null || true)
    
    if [[ -n "$artifact_results" ]]; then
        print_error "CRITICAL: Found exfiltration artifacts in repositories:"
        echo "$artifact_results" | head -10 | sed 's/^/    /'
    fi
    
    if [[ -z "$discussion_results" ]] && [[ -z "$formatter_results" ]] && [[ -z "$secrets_results" ]] && [[ -z "$artifact_results" ]]; then
        print_success "No suspicious workflows or artifacts found"
    fi
}

# Generate remediation report
generate_report() {
    print_section "Scan Summary"
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}                         SCAN RESULTS                              ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\nScanned directory: $SCAN_DIR"
    echo -e "Scan completed at: $(date)"
    echo -e "Log file: $LOG_FILE"
    
    if [[ $ISSUES_FOUND -gt 0 ]]; then
        echo -e "\n${RED}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        printf "${RED}║  CRITICAL ISSUES FOUND: %-42s ║${NC}\n" "$ISSUES_FOUND"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        echo -e "\n${RED}${BOLD}IMMEDIATE ACTIONS REQUIRED:${NC}"
        echo "1. Remove all node_modules directories:"
        echo "   find . -type d -name node_modules -exec rm -rf {} +"
        echo ""
        echo "2. Clear npm cache:"
        echo "   npm cache clean --force"
        echo ""
        echo "3. ROTATE ALL CREDENTIALS IMMEDIATELY:"
        echo "   - GitHub tokens (Settings → Developer settings → Personal access tokens)"
        echo "   - npm tokens (npmjs.com → Access Tokens)"
        echo "   - AWS credentials (IAM Console)"
        echo "   - Azure credentials (Azure Portal)"
        echo "   - GCP credentials (GCP Console)"
        echo ""
        echo "4. Review and remove suspicious GitHub workflows:"
        echo "   - .github/workflows/discussion.yaml"
        echo "   - .github/workflows/formatter_*.yml"
        echo ""
        echo "5. Check GitHub audit logs for unauthorized access:"
        echo "   https://github.com/organizations/YOUR_ORG/settings/audit-log"
        echo ""
        echo "6. Remove any suspicious self-hosted runners"
        echo ""
        echo "7. Re-install dependencies after removing affected packages:"
        echo "   npm install"
    elif [[ $WARNINGS_FOUND -gt 0 ]]; then
        echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        printf "${YELLOW}║  WARNINGS FOUND: %-48s ║${NC}\n" "$WARNINGS_FOUND"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        echo -e "\n${YELLOW}RECOMMENDED ACTIONS:${NC}"
        echo "1. Review the warnings above carefully"
        echo "2. Consider rotating credentials as a precaution"
        echo "3. Enable npm ignore-scripts: npm config set ignore-scripts true"
        echo "4. Run npm audit in your projects"
    else
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  NO ISSUES FOUND - SYSTEM APPEARS CLEAN                          ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    fi
    
    echo -e "\n${CYAN}${BOLD}PREVENTION RECOMMENDATIONS:${NC}"
    echo "• Enable npm ignore-scripts: npm config set ignore-scripts true"
    echo "• Use lockfiles and pin dependency versions"
    echo "• Regularly audit dependencies: npm audit"
    echo "• Use security tools like Socket.dev, Snyk, or Dependabot"
    echo "• Restrict CI/CD network access to trusted domains only"
    echo "• Use short-lived, scoped tokens for automation"
    echo "• Review GitHub Actions workflows before merging PRs"
    echo "• Enable GitHub's secret scanning and push protection"
    
    echo -e "\n${CYAN}REFERENCE:${NC}"
    echo "https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack"
}

# Show help
show_help() {
    echo "Shai-Hulud 2.0 Supply Chain Attack Scanner v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS] [DIRECTORY]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --version  Show version"
    echo ""
    echo "Arguments:"
    echo "  DIRECTORY      Directory to scan (default: current directory)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Scan current directory"
    echo "  $0 ~/projects         # Scan specific directory"
    echo "  $0 /path/to/code      # Scan absolute path"
    echo ""
    echo "This script checks for:"
    echo "  - Malicious files created by Shai-Hulud (setup_bun.js, cloud.json, etc.)"
    echo "  - Compromised npm packages with known malicious versions"
    echo "  - Suspicious GitHub workflows (discussion.yaml, formatter_*.yml)"
    echo "  - Suspicious self-hosted GitHub runners (SHA1HULUD pattern)"
    echo "  - Recently created repositories during the attack window"
    echo "  - Cloud credential files that may have been exfiltrated"
    echo "  - TruffleHog installation (malware creates truffleSecrets.json)"
    echo ""
    echo "Requirements:"
    echo "  - jq (JSON parsing)"
    echo "  - npm (package checking)"
    echo "  - gh (GitHub CLI, optional but recommended)"
    echo ""
    echo "Report bugs to: https://github.com/MichaelAntonFischer/shai-hulud-2.0-scanner/issues"
}

# Main execution
main() {
    # Handle arguments
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            echo "Shai-Hulud Scanner v${VERSION}"
            exit 0
            ;;
    esac
    
    print_banner
    
    echo "Scan directory: $SCAN_DIR"
    echo "Log file: $LOG_FILE"
    echo ""
    
    # Check dependencies
    check_dependencies
    
    # Initialize log file
    {
        echo "Shai-Hulud 2.0 Scanner Log - $(date)"
        echo "Version: $VERSION"
        echo "Scan directory: $SCAN_DIR"
        echo "---"
    } > "$LOG_FILE"
    
    # Run all checks
    check_trufflehog
    check_malicious_files
    check_affected_packages
    check_npm_config
    check_cloud_credentials
    check_github
    
    # Generate final report
    generate_report
    
    echo ""
    echo -e "${BLUE}Full log saved to: $LOG_FILE${NC}"
    
    # Exit with appropriate code
    if [[ $ISSUES_FOUND -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main "$@"
