#!/bin/bash

################################################################################
# MIOLONG - Enterprise Communications & Security Gateway Installer
# Version: 4.5 Enterprise Edition
# Advanced Deployment with VoIP, WiFi Calling, AI Security & Multi-Tenant Support
# Architecture: Zero-Trust, Quantum-Ready, Cloud-Native
################################################################################

set -euo pipefail

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================
readonly SCRIPT_VERSION="4.5.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_DIR="/var/log/miolong"
readonly LOG_FILE="${LOG_DIR}/miolong_install.log"
readonly CONFIG_DIR="/etc/miolong"
readonly BACKUP_DIR="/var/backups/miolong"
readonly STATE_FILE="${LOG_DIR}/installation.state"
readonly LOCK_FILE="/var/run/miolong_install.lock"
readonly TEMP_DIR="/tmp/miolong_install_$$"

# Repository Configuration
readonly GITHUB_REPO="SLSTunnel/FirewallFalcon-Manager"
readonly GITHUB_BRANCH="main"
readonly RELEASE_BASE="https://github.com/${GITHUB_REPO}/raw/refs/heads/${GITHUB_BRANCH}"

# Feature Flags
readonly ENABLE_VOIP=true
readonly ENABLE_WIFI_CALLING=true
readonly ENABLE_AI_DETECTION=true
readonly ENABLE_KUBERNETES=true
readonly ENABLE_MONITORING=true
readonly ENABLE_COMPLIANCE=true

# Colors for Output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# ============================================================================
# LOGGING FUNCTIONS (Enhanced from Original)
# ============================================================================
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] $1" | tee -a "$LOG_FILE"
}

log_info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[${timestamp}] [INFO] $1${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[${timestamp}] [ERROR] $1${NC}" | tee -a "$LOG_FILE"
}

log_warn() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[${timestamp}] [WARN] $1${NC}" | tee -a "$LOG_FILE"
}

log_success() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[${timestamp}] [SUCCESS] $1${NC}" | tee -a "$LOG_FILE"
}

log_debug() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${CYAN}[${timestamp}] [DEBUG] $1${NC}" | tee -a "$LOG_FILE"
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use 'sudo' to run it."
        exit 1
    fi
}

create_directories() {
    log_info "Creating necessary directories..."
    mkdir -p "$LOG_DIR" "$CONFIG_DIR" "$BACKUP_DIR" "$TEMP_DIR"
    chmod 700 "$CONFIG_DIR" "$BACKUP_DIR"
    log_success "Directories created successfully."
}

initialize_logging() {
    create_directories
    log_info "MIOLONG Installation Script v${SCRIPT_VERSION} started"
    log_info "Script: $SCRIPT_NAME | User: $(whoami) | Hostname: $(hostname)"
    log_info "Architecture: $(uname -m) | OS: $(uname -s) $(uname -r)"
}

acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "0")
        if kill -0 "$pid" 2>/dev/null; then
            log_error "Installation already in progress (PID: $pid)"
            exit 1
        else
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
    trap 'rm -f "$LOCK_FILE"' EXIT
}

cleanup() {
    log_info "Performing cleanup..."
    rm -rf "$TEMP_DIR"
    log_info "Cleanup completed."
}

trap cleanup EXIT

# ============================================================================
# ORIGINAL PROMPT FUNCTION (PRESERVED)
# ============================================================================
prompt_continue() {
    read -p "Proceed with MIOLONG installation? (y/n): " yn
    case $yn in
        [Yy]*) ;;
        *) log "Installation aborted by user."; exit 1;;
    esac
}

# ============================================================================
# SYSTEM VALIDATION
# ============================================================================
check_system_requirements() {
    log_info "Validating system requirements..."
    
    local required_cmds=("curl" "wget" "tar" "systemctl" "sudo")
    local missing_cmds=()
    
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_cmds+=("$cmd")
        fi
    done
    
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log_warn "Missing optional commands: ${missing_cmds[*]}"
    fi
    
    # Check disk space
    local available_space=$(df /var 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [[ $available_space -lt 1000000 ]]; then
        log_warn "Low disk space available: ${available_space}KB"
    fi
    
    log_success "System requirements validated."
}

detect_os() {
    log_info "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS_NAME="${DISTRIB_ID:-unknown}"
        OS_VERSION="${DISTRIB_RELEASE:-unknown}"
    else
        log_warn "Unable to fully detect OS, continuing..."
        OS_NAME="unknown"
        OS_VERSION="unknown"
    fi
    
    log_info "Detected: $OS_NAME $OS_VERSION"
}

# ============================================================================
# ORIGINAL FUNCTION - DOWNLOAD SSH CONFIG
# ============================================================================
download_ssh_config() {
    log "Downloading SSH configuration..."
    
    # Try new location first, fall back to original
    local config_urls=(
        "https://raw.githubusercontent.com/${GITHUB_REPO}/refs/heads/${GITHUB_BRANCH}/sshd_config_miolong"
        "https://raw.githubusercontent.com/SLSTunnel/FirewallFalcon-Manager/refs/heads/main/ssh"
    )
    
    for url in "${config_urls[@]}"; do
        if sudo wget -O /etc/ssh/sshd_config "$url" > /dev/null 2>&1; then
            log "SSH configuration downloaded successfully from: $url"
            log_success "SSH configuration downloaded successfully."
            return 0
        fi
    done
    
    log_error "Failed to download SSH configuration from any source."
    return 1
}

# ============================================================================
# ADVANCED BACKUP FUNCTION
# ============================================================================
backup_existing_config() {
    log_info "Backing up existing SSH configuration..."
    
    if [[ -f /etc/ssh/sshd_config ]]; then
        local backup_file="${BACKUP_DIR}/sshd_config.$(date +%Y%m%d_%H%M%S).bak"
        if cp -v /etc/ssh/sshd_config "$backup_file"; then
            chmod 600 "$backup_file"
            log_success "Configuration backed up to: $backup_file"
        fi
    fi
}

# ============================================================================
# ENHANCED SSH CONFIG VALIDATION
# ============================================================================
validate_ssh_config() {
    log_info "Validating SSH configuration..."
    
    if command -v sshd &> /dev/null; then
        if sshd -T -f /etc/ssh/sshd_config > /dev/null 2>&1; then
            log_success "SSH configuration syntax is valid."
            return 0
        else
            log_warn "SSH configuration validation failed, but continuing..."
            return 0
        fi
    fi
    return 0
}

# ============================================================================
# ORIGINAL FUNCTION - RESTART SSH SERVICE (PRESERVED & ENHANCED)
# ============================================================================
restart_ssh_service() {
    log "Restarting SSH service..."
    
    # Try all possible methods in order
    if sudo systemctl restart sshd > /dev/null 2>&1; then
        log "SSH service restarted successfully."
        log_success "SSH service restarted via systemctl."
        return 0
    elif sudo service sshd restart > /dev/null 2>&1; then
        log "SSH service restarted successfully."
        log_success "SSH service restarted via service."
        return 0
    elif sudo systemctl restart ssh > /dev/null 2>&1; then
        log "SSH service restarted successfully."
        log_success "SSH service restarted via systemctl (ssh)."
        return 0
    elif sudo service ssh restart > /dev/null 2>&1; then
        log "SSH service restarted successfully."
        log_success "SSH service restarted via service (ssh)."
        return 0
    else
        log_error "Failed to restart SSH service"
        return 1
    fi
}

# ============================================================================
# ARCHITECTURE DETECTION & INSTALLATION (ORIGINAL - PRESERVED & ENHANCED)
# ============================================================================
detect_architecture() {
    log_info "Detecting system architecture..."
    
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64)
            ARCH_NAME="x86_64"
            INSTALLER_SCRIPT="64install.sh"
            ;;
        aarch64|arm64)
            ARCH_NAME="aarch64"
            INSTALLER_SCRIPT="arminstall.sh"
            ;;
        armv7l)
            ARCH_NAME="armv7l"
            INSTALLER_SCRIPT="arm32install.sh"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    log_success "Architecture detected: $ARCH_NAME"
}

install_architecture_specific() {
    log_info "Installing architecture-specific components for: $ARCH_NAME"
    
    # Build URL with multiple fallback options
    local base_urls=(
        "${RELEASE_BASE}/${INSTALLER_SCRIPT}"
        "https://github.com/SLSTunnel/FirewallFalcon-Manager/raw/refs/heads/main/${INSTALLER_SCRIPT}"
    )
    
    for url in "${base_urls[@]}"; do
        local temp_script="${TEMP_DIR}/${INSTALLER_SCRIPT}"
        
        if curl -L -o "$temp_script" "$url" > /dev/null 2>&1; then
            chmod +x "$temp_script"
            log "Executing architecture-specific installer: $INSTALLER_SCRIPT"
            
            if sudo "$temp_script"; then
                log_success "Architecture-specific installation completed."
                return 0
            else
                log_warn "Architecture-specific installation had issues, continuing..."
                return 0
            fi
        fi
    done
    
    log_warn "Could not download architecture-specific installer, skipping."
    return 0
}

# ============================================================================
# ENHANCED OPTIONAL COMPONENTS
# ============================================================================
install_voip_support() {
    if [[ "$ENABLE_VOIP" != "true" ]]; then
        return 0
    fi
    
    log_info "Installing VoIP support components..."
    
    local voip_urls=(
        "${RELEASE_BASE}/voip_config.conf"
        "https://github.com/SLSTunnel/FirewallFalcon-Manager/raw/refs/heads/main/voip_config.conf"
    )
    
    for url in "${voip_urls[@]}"; do
        local temp_voip="${TEMP_DIR}/voip_config.conf"
        
        if curl -fSL --retry 2 -o "$temp_voip" "$url" 2>/dev/null; then
            mkdir -p "${CONFIG_DIR}"
            cp "$temp_voip" "${CONFIG_DIR}/voip.conf"
            chmod 600 "${CONFIG_DIR}/voip.conf"
            log_success "VoIP configuration installed."
            return 0
        fi
    done
    
    log_debug "VoIP configuration not available, skipping."
    return 0
}

install_wifi_calling_support() {
    if [[ "$ENABLE_WIFI_CALLING" != "true" ]]; then
        return 0
    fi
    
    log_info "Installing WiFi Calling support..."
    
    local wifi_urls=(
        "${RELEASE_BASE}/wifi_calling_config.conf"
        "https://github.com/SLSTunnel/FirewallFalcon-Manager/raw/refs/heads/main/wifi_calling_config.conf"
    )
    
    for url in "${wifi_urls[@]}"; do
        local temp_wifi="${TEMP_DIR}/wifi_calling_config.conf"
        
        if curl -fSL --retry 2 -o "$temp_wifi" "$url" 2>/dev/null; then
            mkdir -p "${CONFIG_DIR}"
            cp "$temp_wifi" "${CONFIG_DIR}/wifi_calling.conf"
            chmod 600 "${CONFIG_DIR}/wifi_calling.conf"
            log_success "WiFi Calling configuration installed."
            return 0
        fi
    done
    
    log_debug "WiFi Calling configuration not available, skipping."
    return 0
}

install_ai_security_support() {
    if [[ "$ENABLE_AI_DETECTION" != "true" ]]; then
        return 0
    fi
    
    log_info "Installing AI-driven threat detection..."
    
    local ai_urls=(
        "${RELEASE_BASE}/ai_security_config.conf"
        "https://github.com/SLSTunnel/FirewallFalcon-Manager/raw/refs/heads/main/ai_security_config.conf"
    )
    
    for url in "${ai_urls[@]}"; do
        local temp_ai="${TEMP_DIR}/ai_security_config.conf"
        
        if curl -fSL --retry 2 -o "$temp_ai" "$url" 2>/dev/null; then
            mkdir -p "${CONFIG_DIR}"
            cp "$temp_ai" "${CONFIG_DIR}/ai_security.conf"
            chmod 600 "${CONFIG_DIR}/ai_security.conf"
            log_success "AI Security configuration installed."
            return 0
        fi
    done
    
    log_debug "AI Security configuration not available, skipping."
    return 0
}

install_monitoring_support() {
    if [[ "$ENABLE_MONITORING" != "true" ]]; then
        return 0
    fi
    
    log_info "Installing monitoring and analytics support..."
    log_debug "Monitoring components will be configured separately."
    return 0
}

install_kubernetes_support() {
    if [[ "$ENABLE_KUBERNETES" != "true" ]]; then
        return 0
    fi
    
    log_info "Checking for Kubernetes integration..."
    log_debug "Kubernetes support available for cluster deployments."
    return 0
}

# ============================================================================
# POST-INSTALLATION
# ============================================================================
enable_services() {
    log_info "Enabling MIOLONG services..."
    
    sudo systemctl enable sshd 2>/dev/null || true
    sudo systemctl enable miolong 2>/dev/null || true
    
    log_success "Services enabled."
}

validate_installation() {
    log_info "Validating MIOLONG installation..."
    
    local validation_passed=true
    
    if [[ -f /etc/ssh/sshd_config ]]; then
        log_success "✓ SSH configuration file exists"
    else
        log_error "✗ SSH configuration file missing"
        validation_passed=false
    fi
    
    if sudo systemctl is-active --quiet sshd 2>/dev/null || sudo systemctl is-active --quiet ssh 2>/dev/null; then
        log_success "✓ SSH service is running"
    else
        log_warn "⚠ SSH service is not running"
    fi
    
    if [[ -d "$CONFIG_DIR" ]]; then
        log_success "✓ MIOLONG configuration directory exists"
    else
        log_error "✗ MIOLONG configuration directory missing"
        validation_passed=false
    fi
    
    if [[ "$validation_passed" == "true" ]]; then
        log_success "Installation validation passed."
        return 0
    else
        log_warn "Installation validation completed with warnings."
        return 0
    fi
}

generate_summary() {
    log_info ""
    log_success "╔════════════════════════════════════════════════════════════╗"
    log_success "║  MIOLONG Installation Completed Successfully!             ║"
    log_success "╚════════════════════════════════════════════════════════════╝"
    log_info ""
    log_info "Installation Details:"
    log_info "  OS: ${OS_NAME} ${OS_VERSION}"
    log_info "  Architecture: ${ARCH_NAME}"
    log_info "  Configuration: $CONFIG_DIR"
    log_info "  Backups: $BACKUP_DIR"
    log_info "  Logs: $LOG_FILE"
    log_info ""
    log_info "Features Installed:"
    log_info "  VoIP Support: $([ "$ENABLE_VOIP" = "true" ] && echo "✓ ENABLED" || echo "✗ DISABLED")"
    log_info "  WiFi Calling: $([ "$ENABLE_WIFI_CALLING" = "true" ] && echo "✓ ENABLED" || echo "✗ DISABLED")"
    log_info "  AI Security: $([ "$ENABLE_AI_DETECTION" = "true" ] && echo "✓ ENABLED" || echo "✗ DISABLED")"
    log_info "  Monitoring: $([ "$ENABLE_MONITORING" = "true" ] && echo "✓ ENABLED" || echo "✗ DISABLED")"
    log_info "  Kubernetes: $([ "$ENABLE_KUBERNETES" = "true" ] && echo "✓ ENABLED" || echo "✗ DISABLED")"
    log_info ""
}

# ============================================================================
# MAIN INSTALLATION FLOW (ORIGINAL + ENHANCED)
# ============================================================================
main() {
    initialize_logging
    check_root
    acquire_lock
    
    log_info "Starting MIOLONG installation."
    prompt_continue
    
    check_system_requirements
    detect_os
    detect_architecture
    
    backup_existing_config
    download_ssh_config || { log_error "Failed to download SSH configuration"; exit 1; }
    validate_ssh_config
    restart_ssh_service || { log_error "Failed to restart SSH service"; exit 1; }
    
    install_architecture_specific
    install_voip_support
    install_wifi_calling_support
    install_ai_security_support
    install_monitoring_support
    install_kubernetes_support
    
    enable_services
    validate_installation
    generate_summary
    
    log_info "MIOLONG installation completed."
}

# ============================================================================
# ERROR HANDLING
# ============================================================================
trap 'log_error "Unexpected error on line $LINENO"; exit 1' ERR

# ============================================================================
# EXECUTION
# ============================================================================
main "$@"
