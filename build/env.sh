#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"

echo "$root" "$workspace"

appchaindir="$workspace/src/github.com/PlatONnetwork"
if [ ! -L "$appchaindir/AppChain-Go" ]; then
    mkdir -p "$appchaindir"
    cd "$appchaindir"
    ln -s ../../../../../. appchain
    cd "$root"
fi

echo "ln -s success."

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$appchaindir/AppChain-Go"
PWD="$appchaindir/AppChain-Go"

# Launch the arguments with the configured environment.
exec "$@"
