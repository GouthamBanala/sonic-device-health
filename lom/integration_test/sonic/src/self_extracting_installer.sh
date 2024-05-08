#!/bin/bash
echo ""
echo "Self Extracting Installer"
echo ""

# Function to check if Python is installed on the system
check_python() {
    if ! command -v python &> /dev/null; then
        echo "Error: Python is not installed on the system. Please install Python and try again."
        exit 1
    fi
}

# Check if the script is running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "This script requires elevated privileges. Please run it with 'sudo'."
    exit 1
fi

# Function to display script usage
display_usage() {
    echo "Usage: $0 [--dir EXTRACT_DIR] [--extract-only]"
    echo "Options:"
    echo "  --dir EXTRACT_DIR    Specify the directory to extract the archive (default is current directory)."
    echo "  --extract-only       Only extract the archive and do not run the tests."
    exit 0
}

# Parse arguments to get the extraction directory and the extract-only flag
EXTRACT_DIR=$(pwd)
EXTRACT_ONLY=false
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        -h|--help)
            display_usage
            ;;
        --dir)
            EXTRACT_DIR="$2"
            shift
            shift
            ;;
        --extract-only)
            EXTRACT_ONLY=true
            shift
            ;;
        *)
            # Ignore unknown options
            shift
            ;;
    esac
done

# Check if Python is installed on the system
check_python

# Remove the integration_test folder if it exists
if [ -d "$EXTRACT_DIR/integration_test" ]; then
    rm -rf "$EXTRACT_DIR/integration_test"
fi

ARCHIVE=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' $0)

tail -n+$ARCHIVE $0 | tar xzv -C "$EXTRACT_DIR"

# Print files extracted from the archive
echo "SUCCESS: Extracted archive to '$EXTRACT_DIR/integration_test'."
echo "Files extracted:"
ls -l "$EXTRACT_DIR/integration_test"

# change the permissions of the extracted directory to current user
chown -R $(logname):$(logname) "$EXTRACT_DIR/integration_test"

# Check if the user wants to run the tests or just extract
if [ "$EXTRACT_ONLY" = false ]; then
    # Run the tests
    echo "===================================================================================================="
    echo "Running tests started at $(date)"
    echo "===================================================================================================="
    pushd "$EXTRACT_DIR/integration_test/src"
    python ./run.py --all
    popd
fi

exit 0

__ARCHIVE_BELOW__
