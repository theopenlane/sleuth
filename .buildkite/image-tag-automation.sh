#!/bin/bash
set -euo pipefail

# Source shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

repo="${HELM_CHART_REPO}"
chart_dir="${HELM_CHART_PATH:-charts/sleuth}"

# Install dependencies
install_dependencies

echo "=== Image Tag Automation ==="
echo "Repository: $repo"
echo "Chart directory: $chart_dir"
echo "Release Tag: ${BUILDKITE_TAG}"
echo "Build: ${BUILDKITE_BUILD_NUMBER}"

# Verify this is a release build
if [[ -z "${BUILDKITE_TAG:-}" ]]; then
  echo "No release tag found - this automation only runs for tagged releases"
  exit 1
fi

work=$(create_temp_workspace)

# Clone the target repository
echo "Cloning repository..."
if ! git clone "$repo" "$work"; then
  echo "Failed to clone $repo" >&2
  exit 1
fi

cd "$work"

release_branch="sleuth-${BUILDKITE_TAG}"

echo "Creating release branch: $release_branch"
git checkout -b "$release_branch"

changes_made=false
change_summary=""

# Update the image tag in values.yaml
values_file="$chart_dir/values.yaml"
if [[ -f "$values_file" ]]; then
  current_tag=$(yq e '.sleuth.image.tag' "$values_file")
  new_tag="${BUILDKITE_TAG}"

  echo "Updating image tag: $current_tag -> $new_tag"

  yq e -i ".sleuth.image.tag = \"$new_tag\"" "$values_file"
  git add "$values_file"
  changes_made=true
  change_summary+="- Updated image tag from $current_tag to $new_tag"
else
  echo "Values file not found: $values_file"
  exit 1
fi

# Update chart version and appVersion
chart_file="$chart_dir/Chart.yaml"
if [[ -f "$chart_file" ]]; then
  current_version=$(grep '^version:' "$chart_file" | awk '{print $2}')

  if [[ "$new_tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"
    new_chart_version="$major.$minor.$patch"
  else
    IFS='.' read -r maj min pat <<< "$current_version"
    new_patch=$((pat+1))
    new_chart_version="$maj.$min.$new_patch"
  fi

  echo "Updating chart version: $current_version -> $new_chart_version"
  sed -i -E "s/^version:.*/version: $new_chart_version/" "$chart_file"

  current_app_version=$(grep '^appVersion:' "$chart_file" | awk '{print $2}' | tr -d '"' || echo "")
  new_app_version="${BUILDKITE_TAG}"

  if [[ "$current_app_version" != "$new_app_version" ]]; then
    echo "Updating app version: $current_app_version -> $new_app_version"

    if grep -q '^appVersion:' "$chart_file"; then
      sed -i -E "s/^appVersion:.*/appVersion: \"$new_app_version\"/" "$chart_file"
    else
      echo "appVersion: \"$new_app_version\"" >> "$chart_file"
    fi
  fi

  git add "$chart_file"
  changes_made=true
  change_summary+="\n- Updated chart version to $new_chart_version"
  change_summary+="\n- Updated app version to $new_app_version"
fi

# Check if we have any changes to commit
if [[ "$changes_made" == "false" ]]; then
  echo "No image tag changes needed (already up to date)"
  exit 0
fi

echo "Release changes detected, creating PR"

# Configure git
setup_git_user

git commit -m "chore: bump sleuth to ${BUILDKITE_TAG}

- Source Commit: ${BUILDKITE_COMMIT:0:8}
- Build Number: ${BUILDKITE_BUILD_NUMBER}"

# Push and create PR
echo "Pushing release branch..."
if safe_push_branch "$release_branch"; then
  pr_body="## Summary
- Automated chart update from sleuth release ${BUILDKITE_TAG}
$(printf '%b' "$change_summary")

## Build Information
- Build Number: ${BUILDKITE_BUILD_NUMBER}
- Source Commit: ${BUILDKITE_COMMIT:0:8}
- Source Branch: ${BUILDKITE_BRANCH:-main}"

  echo "Creating pull request..."
  if gh pr create \
    --repo "$repo" \
    --head "$release_branch" \
    --title "chore: bump sleuth to ${BUILDKITE_TAG}" \
    --body "$pr_body"; then
    pr_url=$(gh pr view "$release_branch" --repo "$repo" --json url --jq '.url' 2>/dev/null || echo "")
    echo "Pull request created successfully: $pr_url"
  else
    echo "Failed to create pull request"
    exit 1
  fi
else
  echo "Failed to push branch"
  exit 1
fi

echo "Image tag automation completed successfully"
