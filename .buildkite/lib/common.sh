#!/bin/bash
# Common utility functions for Buildkite automation scripts

# Global variables
YQ_VERSION=${YQ_VERSION:-4.45.4}

# install_yq installs yq if not already available
install_yq() {
    if ! command -v yq >/dev/null 2>&1; then
        echo "Installing yq version ${YQ_VERSION}..."
        local yq_binary="yq_linux_amd64"
        local temp_file="/tmp/yq"

        if wget -q "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/${yq_binary}" -O "$temp_file"; then
            chmod +x "$temp_file"
            mv "$temp_file" /usr/local/bin/yq
            echo "yq v${YQ_VERSION} installed"
        else
            echo "Failed to install yq" >&2
            return 1
        fi
    fi
}

# install_gh installs GitHub CLI if not already available
install_gh() {
    if ! command -v gh >/dev/null 2>&1; then
        echo "Installing GitHub CLI..."
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache github-cli
        else
            echo "Package manager not supported for GitHub CLI installation" >&2
            return 1
        fi
    fi
}

# install_dependencies installs all required tools
install_dependencies() {
    echo "Installing dependencies..."
    install_yq
    install_gh
    echo "Dependencies installed"
}

# setup_git_user configures git user settings for commits
setup_git_user() {
    local email="${1:-bender@theopenlane.io}"
    local name="${2:-theopenlane-bender}"

    git config --local user.email "$email"
    git config --local user.name "$name"

    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        git config --local url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
    fi
}

# create_temp_workspace creates a temporary directory with cleanup trap
create_temp_workspace() {
    local temp_dir=$(mktemp -d)
    trap "rm -rf \"$temp_dir\"" EXIT
    echo "$temp_dir"
}

# safe_push_branch pushes a branch to origin
safe_push_branch() {
    local branch="$1"
    local force="${2:-false}"

    local push_args="origin $branch"
    if [[ "$force" == "true" ]]; then
        push_args="-f $push_args"
    fi

    if git push $push_args; then
        echo "Branch $branch pushed successfully"
        return 0
    else
        echo "Failed to push branch $branch" >&2
        return 1
    fi
}
