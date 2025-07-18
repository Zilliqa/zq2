#!/bin/bash

# --- zurl Configuration ---
# Port range for random selection (5000-8000)
export ZURL_PORT_MIN="5000"
export ZURL_PORT_MAX="8000"
# --- End Configuration ---

# Global variables for cleanup
tunnel_pid=""
local_port=""
target_host=""
debug_mode=false

# Function to determine project ID based on instance name prefix
get_project_id() {
    local instance_name="$1"
    
    if [[ "$instance_name" =~ ^zq2-devnet ]]; then
        echo "prj-d-zq2-devnet-c83bkpsd"
    elif [[ "$instance_name" =~ ^zq2-testnet ]]; then
        echo "prj-d-zq2-testnet-g13pnaa8"
    elif [[ "$instance_name" =~ ^zq2-mainnet ]]; then
        echo "prj-p-zq2-mainnet-sn5n8wfl"
    else
        # Default to mainnet
        echo "prj-p-zq2-mainnet-sn5n8wfl"
    fi
}

# Function to look up zone for a given instance
lookup_instance_zone() {
    local project_id="$1"
    local instance_name="$2"
    
    # Query gcloud for the instance zone
    local zone_result=$(gcloud compute instances list \
        --format="value(zone)" \
        --project="${project_id}" \
        --filter="name=${instance_name}" 2>/dev/null)
    
    if [[ -z "$zone_result" ]]; then
        echo ""
        return 1
    fi
    
    # Count number of results
    local zone_count=$(echo "$zone_result" | wc -l)
    
    if [[ "$zone_count" -gt 1 ]]; then
        echo "Error: Multiple instances found with name '${instance_name}':" >&2
        echo "$zone_result" >&2
        echo "Please specify a unique instance name." >&2
        return 1
    fi
    
    # Extract zone from full path (e.g., "projects/project/zones/asia-southeast1-c" -> "asia-southeast1-c")
    local zone=$(echo "$zone_result" | sed 's|.*/||')
    echo "$zone"
    return 0
}

# Function to extract host and port from URL
extract_host_port() {
    local url="$1"
    local host=""
    local port=""
    
    # Remove protocol
    local without_protocol=$(echo "$url" | sed -E 's|^https?://||')
    
    # Extract host and port
    if [[ "$without_protocol" =~ ^([^/:]+):([0-9]+)(/.*)?$ ]]; then
        # URL with explicit port
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
    elif [[ "$without_protocol" =~ ^([^/:]+)(/.*)?$ ]]; then
        # URL without explicit port
        host="${BASH_REMATCH[1]}"
        if [[ "$url" =~ ^https:// ]]; then
            port="443"
        else
            port="80"
        fi
    fi
    
    echo "$host:$port"
}

# Function to kill processes using a specific port
kill_port_processes() {
    local port="$1"
    local pids=$(lsof -ti tcp:$port 2>/dev/null)
    
    if [[ -n "$pids" ]]; then
        kill -9 $pids 2>/dev/null
        sleep 1
    fi
}

# Function to check if port is available
is_port_available() {
    local port="$1"
    ! nc -z localhost "$port" 2>/dev/null
}

# Function to wait for port to be available
wait_for_port_available() {
    local port="$1"
    local max_wait=10
    local count=0
    
    while ! is_port_available "$port" && [[ $count -lt $max_wait ]]; do
        sleep 1
        ((count++))
    done
    
    if [[ $count -eq $max_wait ]]; then
        return 1
    fi
    
    return 0
}

# Function to find an available port in the specified range
find_available_port() {
    local min_port="${ZURL_PORT_MIN:-5000}"
    local max_port="${ZURL_PORT_MAX:-8000}"
    local max_attempts=20
    local attempts=0
    
    while [[ $attempts -lt $max_attempts ]]; do
        # Generate random port in range
        local port=$((RANDOM % (max_port - min_port + 1) + min_port))
        
        if is_port_available "$port"; then
            echo "$port"
            return 0
        fi
        
        ((attempts++))
    done
    
    # If we couldn't find a random port, try sequential search
    for ((port=min_port; port<=max_port; port++)); do
        if is_port_available "$port"; then
            echo "$port"
            return 0
        fi
    done
    
    # No available port found
    return 1
}

# Improved cleanup function
cleanup_tunnel() {
    if [[ "$debug_mode" == true ]]; then
        echo "Cleanup called: tunnel_pid=$tunnel_pid, local_port=$local_port, target_host=$target_host" >&2
    fi
    
    # Kill by process name pattern (more reliable for gcloud processes)
    if [[ -n "$target_host" ]]; then
        pkill -f "gcloud.*start-iap-tunnel.*${target_host}" 2>/dev/null
        sleep 1
    fi
    
    # Kill any gcloud processes related to IAP tunnel
    local gcloud_pids=$(pgrep -f "gcloud.*start-iap-tunnel" 2>/dev/null)
    if [[ -n "$gcloud_pids" ]]; then
        if [[ "$debug_mode" == true ]]; then
            echo "Killing gcloud processes: $gcloud_pids" >&2
        fi
        kill -TERM $gcloud_pids 2>/dev/null
        sleep 2
        # Force kill if still running
        kill -KILL $gcloud_pids 2>/dev/null
    fi
    
    if [[ -n "$tunnel_pid" ]]; then
        if [[ "$debug_mode" == true ]]; then
            echo "Killing tunnel process: $tunnel_pid" >&2
        fi
        # Kill the process group to ensure all child processes are killed
        kill -TERM "-$tunnel_pid" 2>/dev/null
        sleep 1
        
        # Force kill if still running
        if kill -0 "$tunnel_pid" 2>/dev/null; then
            kill -KILL "-$tunnel_pid" 2>/dev/null
        fi
        
        # Wait for the process to actually terminate
        wait "$tunnel_pid" 2>/dev/null
    fi
    
    # Clean up any remaining processes using the port
    if [[ -n "$local_port" ]]; then
        if [[ "$debug_mode" == true ]]; then
            echo "Cleaning up port $local_port" >&2
        fi
        kill_port_processes "$local_port"
        
        # Wait for port to be fully released
        wait_for_port_available "$local_port"
    fi
    
    # Reset global variables
    tunnel_pid=""
    local_port=""
    target_host=""
}

# zurl function - a curl replacement with automatic IAP tunnel management
zurl() {
    # Use global variables instead of local ones
    local target_port=""
    local target_zone=""
    local project_id=""
    
    # Find an available port
    local_port=$(find_available_port)
    if [[ $? -ne 0 ]]; then
        echo "Error: Could not find an available port in range ${ZURL_PORT_MIN:-5000}-${ZURL_PORT_MAX:-8000}." >&2
        return 1
    fi
    
    tunnel_pid=""
    target_host=""
    
    # Parse arguments for debug flag and build curl args
    local curl_args=()
    local curl_args_direct=()
    local target_found=false
    debug_mode=false
    
    for arg in "$@"; do
        if [[ "$arg" == "--debug" ]]; then
            debug_mode=true
            # Don't add --debug to curl_args since curl doesn't understand it
        elif [[ "$arg" =~ ^https?:// ]] && [[ "$target_found" == false ]]; then
            # Extract target from first URL found
            local host_port=$(extract_host_port "$arg")
            target_host=$(echo "$host_port" | cut -d: -f1)
            target_port=$(echo "$host_port" | cut -d: -f2)
            target_found=true
            
            # Replace URL with localhost equivalent for tunneled use
            local new_url=$(echo "$arg" | sed -E "s|^https?://[^/]+|http://localhost:${local_port}|")
            curl_args+=("$new_url")
            # Keep original URL for direct use
            curl_args_direct+=("$arg")
        elif [[ "$arg" =~ ^([^/:]+):([0-9]+)(/.*)?$ ]] && [[ "$target_found" == false ]]; then
            # Handle hostname:port format (without protocol)
            target_host="${BASH_REMATCH[1]}"
            target_port="${BASH_REMATCH[2]}"
            local path="${BASH_REMATCH[3]:-}"
            target_found=true
            
            # Create full URL with localhost for tunneled use
            local new_url="http://localhost:${local_port}${path}"
            curl_args+=("$new_url")
            # Keep original for direct use
            curl_args_direct+=("$arg")
        else
            curl_args+=("$arg")
            curl_args_direct+=("$arg")
        fi
    done
    
    # Check if required environment variables are set
    if [[ -z "$local_port" ]]; then
        echo "Error: zurl configuration failed to find available port." >&2
        return 1
    fi
    
    # Show separator at the beginning (only in debug mode)
    if [[ "$debug_mode" == true ]]; then
        echo "=====================================================================================" >&2
        echo "Using local port: $local_port" >&2
    fi
    
    # Check if we found a target
    if [[ "$target_found" == false ]]; then
        echo "Error: No URL found in arguments. Please provide a URL to tunnel to." >&2
        return 1
    fi
    
    # Determine project ID based on instance name
    project_id=$(get_project_id "$target_host")
    
    # Look up the zone for the target instance
    target_zone=$(lookup_instance_zone "$project_id" "$target_host")
    local lookup_result=$?
    
    if [[ $lookup_result -ne 0 ]]; then
        # Instance not found, execute curl directly without tunnel
        if [[ "$debug_mode" == true ]]; then
            echo "Instance '${target_host}' not found in project '${project_id}'" >&2
            echo "No tunnel needed - executing curl directly" >&2
            echo "=====================================================================================" >&2
        fi
        curl "${curl_args_direct[@]}"
        return $?
    fi
    
    if [[ "$debug_mode" == true ]]; then
        echo "Found instance '${target_host}' in zone '${target_zone}' in project '${project_id}'" >&2
    fi
    
    # Set up trap for cleanup
    trap cleanup_tunnel EXIT INT TERM
    
    # Start the IAP tunnel in the background
    if [[ "$debug_mode" == true ]]; then
        echo "Starting IAP tunnel from localhost:${local_port} to ${target_host}:${target_port} (zone: ${target_zone})..." >&2
    fi
    
    # Create a temporary file to capture gcloud output
    local gcloud_output=$(mktemp)
    
    # Disable job control to suppress "[1]+ Terminated" messages
    set +m
    
    # Start the tunnel - suppress job control messages completely
    {
        gcloud compute start-iap-tunnel \
            "${target_host}" "${target_port}" \
            --project="${project_id}" \
            --zone="${target_zone}" \
            --local-host-port="localhost:${local_port}" > "$gcloud_output" 2>&1 &
    } 2>/dev/null
    
    # Capture the Process ID (PID) of the backgrounded tunnel command
    tunnel_pid=$!
    
    if [[ "$debug_mode" == true ]]; then
        echo "Tunnel PID: $tunnel_pid" >&2
    fi
    
    # Give gcloud a moment to start
    sleep 2
    
    # Check if gcloud output contains actual errors (not just warnings or normal messages)
    if [[ -f "$gcloud_output" ]]; then
        if grep -q "ERROR:" "$gcloud_output" && ! grep -q "Testing if tunnel connection works" "$gcloud_output"; then
            echo "Error: Failed to start IAP tunnel. Details:" >&2
            cat "$gcloud_output" >&2
            echo "" >&2
            echo "Instance: ${target_host}" >&2
            echo "Zone: ${target_zone}" >&2
            echo "Project: ${project_id}" >&2
            rm -f "$gcloud_output"
            return 1
        fi
    fi
    
    # Clean up the temp file
    rm -f "$gcloud_output"
    
    # Poll the local port to see when the tunnel is ready
    local max_retries=20
    local retry_count=0
    
    # Loop until the port is open or we time out
    until nc -zvw1 localhost "${local_port}" &> /dev/null; do
        if [[ ${retry_count} -ge ${max_retries} ]]; then
            echo "Error: Timed out waiting for IAP tunnel to start on port ${local_port}." >&2
            cleanup_tunnel
            return 1
        fi
        retry_count=$((retry_count+1))
        sleep 0.5
    done
    
    if [[ "$debug_mode" == true ]]; then
        echo "Tunnel is ready" >&2
        # Add separator line before output
        echo "=====================================================================================" >&2
    fi
    
    # Run the curl command with the modified arguments
    curl "${curl_args[@]}"
    local curl_exit_code=$?
    
    # Add newline after curl output
    echo ""
    
    # Add separator line after curl output (only in debug mode)
    if [[ "$debug_mode" == true ]]; then
        echo "=====================================================================================" >&2
    fi
    
    # Explicitly cleanup before returning
    cleanup_tunnel
    
    # Return the same exit code as curl
    return $curl_exit_code
}

# If script is being sourced, export the function
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    export -f zurl
fi

# If script is being executed directly, run zurl with provided arguments
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    zurl "$@"
fi