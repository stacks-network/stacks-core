#!/bin/bash
set -o pipefail

#
# ** Recommendations
#   - Run this script in screen or tmux
#   - Use an existing chainstate on an XFS formatted disk (with reflink enabled, which is the default in recent OS versions)
#   - If on a disk formatted other than xfs (e.g. ext4), ensure there are multiple TB of free space - there **will** need to be multiple copies of the chainstate
#   - Depending on how many cpu cores you have available, a full run will take several hours. More cpus == faster execution time.
#     - On a system where 12 CPUS are allocated with an existing chainstate on an XFS parittion, full validation was ~14 hours. 

NETWORK="mainnet"                                 # network to validate
REPO_DIR="$HOME/stacks-core"                      # where to build the source
REMOTE_REPO="stacks-network/stacks-core"          # remote git repo to build stacks-inspect from
SCRATCH_DIR="${HOME}/scratch"                     # root folder for the validation slices
TIMESTAMP=$(date +%Y-%m-%d-%s)                    # use a simple date format year-month-day-epoch
LOG_DIR="${HOME}/block-validation_${TIMESTAMP}"   # location of logfiles for the validation
SLICE_DIR="${SCRATCH_DIR}/slice"                  # location of slice dirs
TMUX_SESSION="validation"                         # tmux session name to run the validation
TERM_OUT=false                                    # terminal friendly output
TESTING=false                                     # only run a validation on a few thousand blocks
BRANCH="develop"                                  # default branch to build stacks-inspect from
CORES=$(grep -c processor /proc/cpuinfo)          # retrieve total number of CORES on the system
RESERVED=8                                        # reserve this many CORES for other processes as default
LOCAL_CHAINSTATE=""                               # path to local chainstate to use instead of snapshot download
REFLINK=0                                         # is reflink enabled? (only relevant for XFS formatted disks)

# ANSI color codes for terminal output
COLRED=$'\033[31m'    # Red
COLGREEN=$'\033[32m'  # Green
COLYELLOW=$'\033[33m' # Yellow
COLCYAN=$'\033[36m'   # Cyan
COLBOLD=$'\033[1m'    # Bold Text
COLRESET=$'\033[0m'   # reset color/formatting

# Verify that cargo is installed in the expected path, not only $PATH
install_cargo() {
    command -v "$HOME/.cargo/bin/cargo" >/dev/null 2>&1 || {
        echo "Installing Rust via rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || {
            echo "${COLRED}Error${COLRESET} installing Rust"
            exit 1
        }
    }
    echo "Exporting $HOME/.cargo/env"
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    return 0
}

# Build release stacks-inspect binary from specified repo/branch
build_stacks_inspect() {
    if [ -d "${REPO_DIR}" ];then
        echo "Found ${COLYELLOW}${REPO_DIR}${COLRESET}. checking out ${COLGREEN}${BRANCH}${COLRESET} and resetting to ${COLBOLD}HEAD${COLRESET}"
        cd "${REPO_DIR}" && git fetch
        echo "Checking out ${BRANCH} and resetting to HEAD"
        # Git stash any local changes to prevent checking out $BRANCH
	git stash
        (git checkout "${BRANCH}" && git reset --hard HEAD) || {
            echo "${COLRED}Error${COLRESET} checking out ${BRANCH}"
            exit 1
        }
    else
        echo "Cloning stacks-core ${BRANCH}"
        (git clone "https://github.com/${REMOTE_REPO}" --branch "${BRANCH}" "${REPO_DIR}" && cd "${REPO_DIR}") || {
            echo "${COLRED}Error${COLRESET} cloning https://github.com/${REMOTE_REPO} into ${REPO_DIR}"
            exit 1
        }
    fi
    git pull
    # Build stacks-inspect to: ${REPO_DIR}/target/release/stacks-inspect
    echo "Building stacks-inspect binary"
    cd contrib/stacks-inspect && cargo build --bin=stacks-inspect --release || {
        echo "${COLRED}Error${COLRESET} building stacks-inspect binary"
        exit 1
    }
    echo "Done building. continuing"
}

# If LOCAL_CHAINSTATE is defined, check the disk for reflink
check_reflink() {
    if [[ -n "${LOCAL_CHAINSTATE}" ]]; then
        # Retrieve the disk only if LOCAL_CHAINSTATE is set
        local disk=$(df --type xfs --output=source $LOCAL_CHAINSTATE 2> /dev/null | tail -1)
        if [ "${disk}" == "" ]; then
            # Chainstate is not on an XFS formatted disk
            return 1
        fi
        # xfs_info needs to be run by sudo
        sudo xfs_info $disk | grep "reflink=1"  > /dev/null 2>&1 || {
            # Reflink is not enabled on the xfs disk
            return 1
        }
        # Reflink is enabled
        return 0
    else
        # LOCAL_CHAINSTATE is not set
        return 1
    fi
}

# Create the slice dirs from an chainstate archive (symlinking marf.sqlite.blobs), 1 dir per CPU
configure_validation_slices() {
    # LOCAL_CHAINSTATE is defined, check if the disk for the chainstate folder has reflink enabled
    if [[ -n "${LOCAL_CHAINSTATE}" ]]; then
        if check_reflink "${LOCAL_CHAINSTATE}"; then
            local REFLINK=1
            local LOCAL_CHAINSTATE_ROOT=$(dirname $LOCAL_CHAINSTATE)
            echo "${COLYELLOW}Reflink enabled disk found. Overriding scratch dir to: ${LOCAL_CHAINSTATE_ROOT}/scratch${COLRESET}"
            local SCRATCH_DIR="${LOCAL_CHAINSTATE_ROOT}/scratch"
            local SLICE_DIR="${SCRATCH_DIR}/slice"
            local cp_arg="--reflink=always"
    fi
    else
	# if LOCAL_CHAINSTATE is not defined, we may still use reflink if the scratch dir is mounted on a compatible disk
        if check_reflink "$(dirname $SCRATCH_DIR)"; then
	    echo "${COLYELLOW}Reflink enabled disk found for scratch dir  ${SCRATCH_DIR}${COLRESET}"
            local REFLINK=1
            local cp_arg="--reflink=always"
        fi
    fi

    if [ -d "${SCRATCH_DIR}" ]; then
        echo "Deleting existing scratch dir: ${COLYELLOW}${SCRATCH_DIR}${COLRESET}"
        rm -rf "${SCRATCH_DIR}" || {
            echo "${COLRED}Error${COLRESET} deleting dir ${SCRATCH_DIR}"
            exit 1
        }
    fi
    echo "Creating scratch and slice dirs"
    (mkdir -p "${SLICE_DIR}0" && cd "${SCRATCH_DIR}") || {
        echo "${COLRED}Error${COLRESET} creating dir ${SLICE_DIR}0"
        exit 1
    }
    if [[ -n "${LOCAL_CHAINSTATE}" ]]; then
        if [ ! -d "$LOCAL_CHAINSTATE" ]; then
            echo "Chainstate not found at ${LOCAL_CHAINSTATE}"
            exit 1
        fi
       echo "Copying local chainstate ${LOCAL_CHAINSTATE} ->  ${COLYELLOW}${SLICE_DIR}0${COLRESET}"
       cp -r ${cp_arg} "${LOCAL_CHAINSTATE}"/* "${SLICE_DIR}0"
    else
       echo "Downloading latest ${NETWORK} chainstate archive ${COLYELLOW}https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.zst${COLRESET}"
       ## curl had some random issues retrying the download when network issues arose. wget has resumed more consistently, so we'll use that for now, and leave the curl option commented
       # curl -L --proto '=https' --tlsv1.2 https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.zst -o ${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.zst || {
       wget -O  "${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.zst" "https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.zst"  || {
           echo "${COLRED}Error${COLRESET} downlaoding latest ${NETWORK} chainstate archive"
           exit 1
       }
       # Extract downloaded archive
       echo "Extracting downloaded archive: ${COLYELLOW}${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.zst${COLRESET}"
       tar --strip-components=1 --zstd -xvf  "${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.zst" -C "${SLICE_DIR}0" || {
           echo "${COLRED}Error${COLRESET} extracting ${NETWORK} chainstate archive"
           exit
       }
    fi
    # If reflink is not enabled for the filesystem, we'll need to copy and link the MARF database to save a little space for the chainstate copy
    if [[ ${REFLINK} -ne "1" ]]; then
        echo "Moving marf database: ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs -> ${COLYELLOW}${SCRATCH_DIR}/marf.sqlite.blobs${COLRESET}"
        mv "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs "${SCRATCH_DIR}"/ || {
            echo "${COLRED}Error${COLRESET} moving marg database"
            exit
        }
        echo "Symlinking marf database: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${COLYELLOW}${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs${COLRESET}"
        ln -s "${SCRATCH_DIR}"/marf.sqlite.blobs "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs || {
            echo "${COLRED}Error${COLRESET} creating symlink: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs"
            exit 1
        }
    fi

    # Create a copy of the linked db with <number of CORES><number of RESERVED CORES>
    #   - Decrement by 1 since we already have ${SLICE_DIR}0
    for ((i=1;i<=$(( CORES - RESERVED - 1));i++)); do
        echo "Copying ${SLICE_DIR}0 -> ${COLYELLOW}${SLICE_DIR}${i}${COLRESET}"
        cp -r ${cp_arg} "${SLICE_DIR}0" "${SLICE_DIR}${i}" || {
            echo "${COLRED}Error${COLRESET} copying ${SLICE_DIR}0 -> ${SLICE_DIR}${i}"
            exit 1
        }
    done
}

# Setup the tmux sessions and create the logdir for storing output
setup_logs() {
    # If there is an existing folder, rm it
    if [ -d "${LOG_DIR}" ]; then
        echo "Removing logdir ${LOG_DIR}"
        rm -rf "${LOG_DIR}"
    fi
    # Create LOG_DIR to store output files
    if  [ ! -d "${LOG_DIR}" ]; then
        echo "Creating logdir ${LOG_DIR}"
        mkdir -p "${LOG_DIR}"
        echo "${LOG_DIR}" > /tmp/block-validation.logdir
    fi
}

# Delete any existing tmux session and recreate
setup_tmux() {
    if [ ! -f "${SLICE_DIR}0/chainstate/vm/index.sqlite" ]; then
        echo "${COLRED}Error${COLRESET}: chainstate db not found (${SLICE_DIR}0/chainstate/vm/index.sqlite)"
        exit 1
    fi
    # If tmux session "$TMUX_SESSION" exists, kill it and start anew
    if eval "tmux list-windows -t ${TMUX_SESSION} &> /dev/null"; then
        echo "Killing existing tmux session: ${TMUX_SESSION}"
        eval "tmux kill-session -t ${TMUX_SESSION}  &> /dev/null"
    fi
    local slice_counter=0

    # Create tmux session named ${TMUX_SESSION} with a window named slice0
    tmux new-session -d -s ${TMUX_SESSION} -n slice${slice_counter} || {
        echo "${COLRED}Error${COLRESET} creating tmux session ${COLYELLOW}${TMUX_SESSION}${COLRESET}"
        exit 1
    }
    return 0
}

# Run the block validation
start_validation() {
    local mode=$1
    local total_blocks=0
    local starting_block=0
    local slice_counter=0
    local range_command=""
    local log_append=""
    local inspect_bin="${REPO_DIR}/target/release/stacks-inspect"
    local inspect_config="${REPO_DIR}/stackslib/conf/${NETWORK}-follower-conf.toml"
    local inspect_prefix="${inspect_bin} --config ${inspect_config} validate-block"

    case "$mode" in
        nakamoto)
            # Epoch 3.X
            echo "Mode: ${COLYELLOW}${mode}${COLRESET}"
            log_append="_${mode}"
            range_command="naka-index-range"
            # Use these values if `--testing` arg is provided (only validate 1_000 blocks)
            ${TESTING} && total_blocks=301883
            ${TESTING} && starting_block=300883
            ;;
        *)
            # Epoch 2.X
            echo "Mode: ${COLYELLOW}pre-nakamoto${COLRESET}"
            log_append=""
            range_command="index-range"
            # Use these values if `--testing` arg is provided (only validate 1_000 blocks) Note:  2.5 epoch is at 153106
            ${TESTING} && total_blocks=162200
            ${TESTING} && starting_block=161200
            # Testnet Epoch 3.0 starts at block 320. Hardcode to the first 300 blocks
            if [ "${NETWORK}" == "testnet" ]; then
                ${TESTING} && total_blocks=300
                ${TESTING} && starting_block=1
            fi
            ;;
    esac
    # Get the total number of blocks
    if [ "${total_blocks}" -eq 0 ]; then
        local count_output
        local count_cmd="${inspect_prefix} ${SLICE_DIR}0 ${range_command}"
        if ! count_output=$(${count_cmd} 2>/dev/null); then
            echo "${COLRED}Error${COLRESET} retrieving total number of blocks from chainstate"
            exit 1
        fi
        # Retrieve the total number of blocks from the stacks-inspect output as the last field
        total_blocks=$(printf '%s\n' "${count_output}" | awk -F " " '{print $NF}')
        echo "total_blocks: ${total_blocks}"
        if [ -z "${total_blocks}" ]; then
            echo "${COLRED}Error${COLRESET} parsing block count from stacks-inspect output"
            exit 1
        fi
    fi
    local block_diff=$((total_blocks - starting_block)) # How many blocks are being validated
    local slices=$((CORES - RESERVED))                  # How many validation slices to use
    local slice_blocks=$((block_diff / slices))         # How many blocks to validate per slice
    ${TESTING} && echo "${COLRED}Testing: ${TESTING}${COLRESET}"
    echo "Total blocks: ${COLYELLOW}${total_blocks}${COLRESET}"
    echo "Starting Block: ${COLYELLOW}$starting_block${COLRESET}"
    echo "Block diff: ${COLYELLOW}$block_diff${COLRESET}"
    echo "************************************************************************"
    echo "Total slices: ${COLYELLOW}${slices}${COLRESET}"
    echo "Blocks per slice: ${COLYELLOW}${slice_blocks}${COLRESET}"
    local end_block_count=$starting_block
    while [[ ${end_block_count} -lt ${total_blocks} ]]; do
        local start_block_count=$end_block_count
        end_block_count=$((end_block_count + slice_blocks))
        if [[ "${end_block_count}" -gt "${total_blocks}"  ]] ||  [[ "${slice_counter}" -eq $((slices - 1))  ]]; then
            end_block_count="${total_blocks}"
        fi
        if [ "${mode}" != "nakamoto" ]; then # don't create the tmux windows if we're validating nakamoto blocks (they should already exist). TODO: check if it does exist in case the function call order changes
            if [ "${slice_counter}" -gt 0 ];then
                tmux new-window -t "${TMUX_SESSION}" -d -n "slice${slice_counter}" || {
                    echo "${COLRED}Error${COLRESET} creating tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
                    exit 1
                }
            fi
        fi
        local slice_path="${SLICE_DIR}${slice_counter}"
        local log_file="${LOG_DIR}/slice${slice_counter}${log_append}.log"
        local log=" | tee -a ${log_file}"
        local cmd="${inspect_prefix} ${slice_path} ${range_command} ${start_block_count} ${end_block_count} 2>/dev/null"
        echo "  Creating tmux window: ${COLGREEN}${TMUX_SESSION}:slice${slice_counter}${COLRESET} :: Blocks: ${COLYELLOW}${start_block_count}-${end_block_count}${COLRESET} :: Logging to: ${log_file}"
        echo "Command: ${cmd}" > "${log_file}" ## log the command being run for the slice
        echo "Validating indexed blocks: ${start_block_count}-${end_block_count} (out of ${total_blocks})" >> "${log_file}"
        # Send `cmd` to the tmux window where the validation will run
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "${cmd}${log}" Enter || {
            echo "${COLRED}Error${COLRESET} sending stacks-inspect command to tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
            exit 1
        }
        # Log the return code as the last line in the logfile
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "echo \${PIPESTATUS[0]} >> ${log_file}" Enter  || {
            echo "${COLRED}Error${COLRESET} sending return status command to tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
            exit 1
        }
        slice_counter=$((slice_counter + 1))
    done
    check_progress
}

# Pretty print the status output (simple spinner while pids are active)
check_progress() {
    # Give the pids a few seconds to show up in process table before checking if they're running
    local sleep_duration=5
    local progress=1
    local sp="/-\|"
    local count
    while [ $sleep_duration -gt 0 ]; do
        ${TERM_OUT} && printf "Sleeping ...  \b [ %s%s%s ] \033[0K\r" "${COLYELLOW}" "${sleep_duration}" "${COLRESET}"
        sleep_duration=$((sleep_duration-1))
        sleep 1
    done
    echo "************************************************************************"
    echo "Checking Block Validation status"
    echo -e ' '
    while true; do
        count=$(pgrep  -c "stacks-inspect")
        if [ "${count}" -gt 0 ]; then
            ${TERM_OUT} && printf "Block validation processes are currently active [ %s%s%s%s ] ...  \b${sp:progress++%${#sp}:1}  \033[0K\r" "${COLYELLOW}" "${COLBOLD}" "${count}" "${COLRESET}"
        else
            ${TERM_OUT} && printf "\r\n"
            break
        fi
    done
    echo "************************************************************************"
}


# Store the results in an aggregated logfile and an html file
store_results() {
    # Text file to store results
    local results="${LOG_DIR}/results.log"
    local failed=0;
    local block_failure=0;
    local failure_count=0;
    local return_code=0;
    local failure_count=0
    local count_one=0
    echo "Results: ${COLYELLOW}${results}${COLRESET}"
    cd "${LOG_DIR}" || {
        echo "${COLRED}Error${COLRESET} Logdir ${COLYELLOW}${LOG_DIR}${COLRESET} doesn't exist"
        exit 1
    }
    # Retrieve the count of all lines with `Failed processing block`
    # Check the return codes to see if we had a panic
    for file in $(find . -name "slice*.log" -printf '%P\n' | sort); do
        echo "Checking file: ${COLYELLOW}$file${COLRESET}"
        return_code=$(tail -1 "${file}")
        case ${return_code} in
            0)
                # Block validation ran successfully
                echo "$file return code: $return_code" >> "${results}" # ok to continue if this write fails
                ;;
            1)
                # Block validation had some block failures
                block_failure=1
                ((count_one=count_one+1))
                echo "$file return code: $return_code" >> "${results}" # ok to continue if this write fails
                ;;
            *)
                # Return code likely indicates a panic
                ((failed=failed+1))
                echo "$file return code: $return_code" >> "${results}" # ok to continue if this write fails
                ;;
        esac
    done

    if [ "${failed}" != "0" ]; then
        failure_count=$failed
        echo "Panic: ${COLRED}$failure_count${COLRESET}"
    fi

    # Use the $failed var here in case there is a panic, then $failure_count may show zero, but the validation was not successful
    if [ ${block_failure} != "0" ];then
        ## retrieve the count of all lines with `Failed processing block`
        failure_count=$(grep -rc "Failed processing block" slice*.log | awk -F: '$NF >= 0 {x+=$NF; $NF=""} END{print x}')
        output=$(grep -r -h "Failed processing block" slice*.log)
        IFS=$'\n'
        if [ "${failure_count}" -gt 0 ]; then
            for line in ${output}; do
                echo "${line}" >> "${results}" || {
                    echo "${COLRED}Error${COLRESET} writing failure to: ${results}"
                }
            done
        else
            ## failures, but not block failures (binary panic for example)
            failure_count=$count_one
        fi
    fi
    echo "Failures: ${failure_count}"
    sed  -i "1i Failures: ${failure_count}" "${results}"
}

# Show usage and exit
usage() {
    echo
    echo "Usage:"
    echo "    ${COLBOLD}${0}${COLRESET}"
    echo "        ${COLYELLOW}--testing${COLRESET}: only check a small number of blocks"
    echo "        ${COLYELLOW}-t|--terminal${COLRESET}: more terminal friendly output"
    echo "        ${COLYELLOW}-n|--network${COLRESET}: run block validation against specific network (default: mainnet)"
    echo "        ${COLYELLOW}-s|--scratchdir${COLRESET}: folder to store copied chainstate data (default: ${HOME}/scratch)"
    echo "        ${COLYELLOW}-b|--branch${COLRESET}: branch of stacks-core to build stacks-inspect from (default: develop)"
    echo "        ${COLYELLOW}-c|--chainstate${COLRESET}: local chainstate copy to use instead of downloading a chainstaet snapshot"
    echo "        ${COLYELLOW}-l|--logdir${COLRESET}: use existing log directory"
    echo "        ${COLYELLOW}-r|--reserved${COLRESET}: how many cpu cores to reserve for system tasks"
    echo
    echo "    ex: ${COLCYAN}${0} -t -c /data/stacks/mainnet ${COLRESET}"
    echo
    exit 0
}


# Install missing dependencies
HAS_APT=1
HAS_SUDO=1
for cmd in apt-get sudo curl tmux git wget tar gzip grep cargo pgrep tput find xfsprogs; do
    # In Alpine, `find` might be linked to `busybox` and won't work
    if [ "${cmd}" == "find" ] && [ -L "${cmd}" ]; then
        rp=
        rp="$(readlink "$(command -v "${cmd}" || echo "NOTLINK")")"
        if [ "${rp}" == "/bin/busybox" ]; then
           echo "${COLRED}ERROR${COLRESET} Busybox 'find' is not supported. Please install 'findutils' or similar."
           exit 1
        fi
    fi

    command -v "${cmd}" >/dev/null 2>&1 || {
        case "${cmd}" in
            "apt-get")
                echo "${COLYELLOW}WARN${COLRESET} 'apt-get' not found; automatic package installation will fail"
                HAS_APT=0
                continue
                ;;
            "sudo")
                echo "${COLYELLOW}WARN${COLRESET} 'sudo' not found; automatic package installation will fail"
                HAS_SUDO=0
                continue
                ;;
            "cargo")
                install_cargo
                ;;
            "pgrep")
                package="procps"
                ;;
            *)
                package="${cmd}"
                ;;
        esac

        if [[ ${HAS_APT} = 0 ]] || [[ ${HAS_SUDO} = 0 ]]; then
           echo "${COLRED}Error${COLRESET} Missing command '${cmd}'"
           exit 1
        fi
        (sudo apt-get update && sudo apt-get install "${package}") || {
            echo "${COLRED}Error${COLRESET} installing $package"
            exit 1
        }
    }
done


# Parse cmd-line args
while [ ${#} -gt 0 ]; do
    case ${1} in
        --testing)
            # Only validate a small subset blocks
            TESTING=true
            ;;
        -s|--scratchdir)
            # Filesytem location to store the chainstate slice data used by stacks-inspect
            SCRATCH_DIR="${2}"
            SLICE_DIR="${SCRATCH_DIR}/slice"
            ;;
        -t|--terminal)
            # Update terminal with progress (it's just printf to show in real-time that the validations are running)
            TERM_OUT=true
            ;;
        -n|--network)
            # Required if not mainnet
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            NETWORK=${2}
            shift
            ;;
        -b|--branch)
            # Build from aspecific branch
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            BRANCH=${2}
            shift
            ;;
        -c|--chainstate)
            # uUse a local chainstate
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            LOCAL_CHAINSTATE="${2}"
            shift
            ;;
        -l|--logdir)
            # Use a specified logdir
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            LOG_DIR="${2}"
            shift
            ;;
        -r|--RESERVED)
            # Reserve this many cpus for the system (default is 10)
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                echo "ERROR: arg ($2) is not a number." >&2
                exit 1
            fi
            RESERVED=${2}
            shift
            ;;
        -h|--help|--usage)
            # show usage/options and exit
            usage
            ;;
    esac
    shift
done


# Clear display before starting
tput reset
echo "Validation Started: ${COLYELLOW}$(date)${COLRESET}"
build_stacks_inspect        # comment if using an existing chainstate/slice dir (ex: validation was performed already, and a second run is desired)
configure_validation_slices # comment if using an existing chainstate/slice dir (ex: validation was performed already, and a second run is desired)
setup_logs                  # configure logdir
setup_tmux                  # configure tmux sessions
start_validation            # validate pre-nakamoto blocks (2.x)
start_validation nakamoto   # validate nakamoto blocks
store_results               # store aggregated results of validation
echo "Validation finished: $(date)"
exit 0
