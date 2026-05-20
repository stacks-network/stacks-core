#!/bin/bash
set -Eeuo pipefail

#
# block-validation.sh — parallelizable block validation using stacks-inspect.
#
# Builds stacks-inspect from a configurable branch, prepares one chainstate copy
# per worker core (reflink when supported, otherwise a full copy), 
# runs validate-block across all workers in parallel via
# tmux windows, and aggregates per-slice results into a dedicate log file.
#
# See usage() for flags descriptions
#
# ** Default folder layout (when only -w/--workdir is set)
#   ${WORK_DIR}/stacks-core/                   built repo (checkout of develop by default)
#   ${WORK_DIR}/chain/                         chainstate used as the source of slices
#   ${WORK_DIR}/downloads/                     downloaded Hiro snapshot archive (expanded in-place to chain/ if missing)
#   ${WORK_DIR}/scratch/                       slice copies + .scratch_meta
#   ${WORK_DIR}/logs/<timestamp>/              per-run logs (slices + results)
#
# ** Caching (each step skips work when a prior artifact is reusable)
#   - stacks-core/     : reused if present (updated when branch tracking is enabled)
#   - downloads/       : Hiro snapshot archive reused if already on disk (no redownload)
#   - chain/           : reused if already extracted (no re-extract). 
#   - scratch/         : slices reused when .scratch_meta matches the current environment
#                        path + slice count + chainstate fingerprint. Otherwise wiped and rebuilt.
#   - logs/            : never wiped; each run gets a fresh timestamped subdir.
#
# ** Recommendations
#   - Run this script in screen or tmux
#   - Use an existing chainstate on a disk formatted using XFS, Btrfs, ZFS or APFS (for XFS, reflink support must be enabled at fs-creation time; this is the default in recent OS versions)
#   - If using a filesystem which doesn't support reflink (e.g. ext4), ensure that the SCRATCH_DIR volume has multiple TBs of free space - each allocated CPU will require its own chainstate copy.
#   - If using CHAIN_DIR on a reflink-enabled filesystem, note that the local chainstate must be located on the same logical volume as the SCRATCH_DIR.
#   - Depending on how many CPU cores you have available, a full run will take several hours. More CPUs = faster execution time.
#     - On a system with 12 CPUs allocated and using an existing chainstate on a reflink enabled partition, full validation took ~14 hours.

# ANSI color codes for terminal output
COLRED=$'\033[31m'    # Red
COLGREEN=$'\033[32m'  # Green
COLYELLOW=$'\033[33m' # Yellow
COLCYAN=$'\033[36m'   # Cyan
COLBOLD=$'\033[1m'    # Bold Text
COLRESET=$'\033[0m'   # reset color/formatting

# Initialize user-overridable defaults. Anything the
# user can set via a CLI flag has its default here.
set_default_config() {
    WORK_DIR="${HOME}"                         # root folder used for block validation and related artifacts
    CHAIN_DIR=""                               # path to local chainstate to use instead of snapshot download
    NETWORK="mainnet"                          # network to validate
    REPO_DIR=""                                # stacks-core checkout location; defaults to ${WORK_DIR}/stacks-core
    BRANCH="develop"                           # default branch to build stacks-inspect from
    TRACK_BRANCH=1                             # 1: BRANCH tracking enabled; 0: use REPO_DIR as-is if set by flag.
    CORES=""                                   # cores to use for validation; resolved in apply_input_config
    VALIDATE="full"                            # what to validate: scenario or block range
}

# Derive configurations and resolved values from the user-supplied config
apply_input_config() {
    # Input based configurations
    if [ -z "${SCRATCH_DIR:-}" ]; then
        SCRATCH_DIR="${WORK_DIR}/scratch"             # root folder for the validation slices
    fi 
    # LOG_ROOT is the persistent parent that collects every run; LOG_DIR is this
    # run's timestamped subdir inside it (created fresh, never deleted afterwards).
    if [ -z "${LOG_ROOT:-}" ]; then
        LOG_ROOT="${WORK_DIR}/logs"
    fi
    local timestamp=$(date +%Y-%m-%d-%s)              # year-month-day-epoch
    LOG_DIR="${LOG_ROOT}/${timestamp}"

    # Resolve CORES: number of validation workers to run in parallel.
    # Default: max(1, nproc/4) — leaves headroom for the system on large boxes.
    # User-supplied values are warned about when aggressive, and capped to nproc.
    local system_cores
    system_cores=$(nproc)
    if [ -z "${CORES}" ]; then
        CORES=$(( system_cores / 4 ))
        if [ "${CORES}" -lt 1 ]; then
            CORES=1
        fi
    elif [ "${CORES}" -gt "${system_cores}" ]; then
        echo "${COLYELLOW}Warning${COLRESET}: requested cores (${CORES}) exceeds detected cores (${system_cores}); capping to ${system_cores}"
        CORES="${system_cores}"
    elif [ "${CORES}" -eq "${system_cores}" ]; then
        echo "${COLYELLOW}Warning${COLRESET}: using all ${system_cores} available cores; system may be unresponsive during validation"
    fi
    if [ "${CORES}" -lt 1 ]; then
        echo "${COLRED}Error${COLRESET} cores (${CORES}) must be at least 1"
        exit 1
    fi

    if [ -z "${REPO_DIR}" ]; then
        REPO_DIR="${WORK_DIR}/stacks-core"            # default stacks-core checkout location
    fi

    # Internal configurations
    SLICE_DIR="${SCRATCH_DIR}/slice"                  # location of slice dirs
    REMOTE_REPO="stacks-network/stacks-core"          # remote git repo to build stacks-inspect from
    TMUX_SESSION="validation"                         # tmux session name to run the validation

    # Detect once whether stdout is attached to a terminal. Drives in-place
    # progress output and the initial tput reset.
    if [[ -t 1 ]]; then
        IS_TTY=true
    else
        IS_TTY=false
    fi
}

# Show usage and exit
usage() {
    echo
    echo "Usage:"
    echo "    ${COLBOLD}${0}${COLRESET}"
    echo "        ${COLYELLOW}-v|--validate <mode>${COLRESET}: what to validate (default: full)"
    echo "            modes: ${COLCYAN}test${COLRESET} (fixed test block ranges for pre-nakamoto and nakamoto)"
    echo "                   ${COLCYAN}pre-nakamoto${COLRESET} (full Epoch 2 blocks)"
    echo "                   ${COLCYAN}nakamoto${COLRESET} (full Epoch 3+ blocks)"
    echo "                   ${COLCYAN}full${COLRESET} (pre-nakamoto + nakamoto blocks)"
    echo "                   ${COLCYAN}<start>:<end>${COLRESET} (inclusive range in continuous block space; auto-splits at the epoch2/3 boundary)"
    echo "                   ${COLCYAN}<start>+<count>${COLRESET} (count blocks starting at start, equivalent to <start>:<start+count-1>)"
    echo "        ${COLYELLOW}-n|--network${COLRESET}: run block validation against specific network (default: mainnet)"
    echo "        ${COLYELLOW}-s|--scratchdir${COLRESET}: folder to store copied chainstate data (default: ${WORK_DIR}/scratch)"
    echo "        ${COLYELLOW}-b|--branch${COLRESET}: branch of stacks-core to build stacks-inspect from (default: develop)"
    echo "        ${COLYELLOW}-r|--repodir${COLRESET}: use an existing stacks-core checkout as-is. It must exist; branch flag is ignored (default: ${WORK_DIR}/stacks-core - with automatic checkout)"
    echo "        ${COLYELLOW}-c|--chaindir${COLRESET}: local chainstate copy to use instead of downloading a chainstate snapshot (default: download and extract to ${WORK_DIR}/chain)"
    echo "        ${COLYELLOW}-l|--logdir${COLRESET}: parent folder for run logs; a TIMESTAMP subdir is created per run (default: ${WORK_DIR}/logs)"
    echo "        ${COLYELLOW}-p|--proc${COLRESET}: how many cpu cores to use for validation cappet at nproc (default: max(1, nproc/4))"
    echo "        ${COLYELLOW}-w|--workdir${COLRESET}: root folder used for block validation and related artifacts (default: ${HOME})"
    echo
    echo "    ex: Full block validation with chainstate automatically downloaded"
    echo "        ${COLCYAN}${0} -w /data/workdir ${COLRESET}"
    echo
}

# Verify that cargo is installed in the expected path, not only $PATH
install_cargo() {
    command -v "${HOME}/.cargo/bin/cargo" >/dev/null 2>&1 || {
        echo "Installing Rust via rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || {
            echo "${COLRED}Error${COLRESET} installing Rust"
            exit 1
        }
    }
    echo "Exporting ${HOME}/.cargo/env"
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
    return 0
}

# Build release stacks-inspect binary.
# When TRACK_BRANCH=1 (default): clone if missing, otherwise track the branch
# When TRACK_BRANCH=0 (set by -r/--repodir): treat REPO_DIR as a pre-existing checkout
build_stacks_inspect() {
    if [ "${TRACK_BRANCH}" -eq 0 ]; then
        if [ ! -d "${REPO_DIR}" ]; then
            echo "${COLRED}Error${COLRESET} repo dir not found: ${REPO_DIR}"
            exit 1
        fi
        echo "Using existing checkout at ${COLYELLOW}${REPO_DIR}${COLRESET} as-is (branch tracking disabled)"
    elif [ -d "${REPO_DIR}" ]; then
        echo "Found ${COLYELLOW}${REPO_DIR}${COLRESET}. checking out ${COLGREEN}${BRANCH}${COLRESET} and resetting to ${COLBOLD}HEAD${COLRESET}"
        cd "${REPO_DIR}" && git fetch
        echo "Checking out ${BRANCH} and resetting to HEAD"
        # Git stash any local changes to prevent checking out $BRANCH
        git stash --include-untracked
        (git checkout "${BRANCH}" && git reset --hard HEAD) || {
            echo "${COLRED}Error${COLRESET} checking out ${BRANCH}"
            exit 1
        }
        git pull
    else
        echo "Cloning stacks-core ${BRANCH}"
        (git clone "https://github.com/${REMOTE_REPO}" --branch "${BRANCH}" "${REPO_DIR}" && cd "${REPO_DIR}") || {
            echo "${COLRED}Error${COLRESET} cloning https://github.com/${REMOTE_REPO} into ${REPO_DIR}"
            exit 1
        }
    fi
    # Build stacks-inspect to: ${REPO_DIR}/target/release/stacks-inspect
    echo "Building stacks-inspect binary"
    cd "${REPO_DIR}/contrib/stacks-inspect" && cargo build --bin=stacks-inspect --release || {
        echo "${COLRED}Error${COLRESET} building stacks-inspect binary"
        exit 1
    }
    echo "Done building. continuing"
}

# Resolve chain dir: use the user-provided path if set, otherwise reuse
# ${WORK_DIR}/chain if present, or download+extract the Hiro snapshot for ${NETWORK}.
configure_chainstate() {
    if [[ -n "${CHAIN_DIR}" ]]; then
        if [ ! -d "${CHAIN_DIR}" ]; then
            echo "${COLRED}Error${COLRESET} Chainstate not found: ${CHAIN_DIR}"
            exit 1
        fi
        echo "${COLYELLOW}Using local chainstate: ${CHAIN_DIR}"
    else
        CHAIN_DIR="${WORK_DIR}/chain"
        if [ -d "${CHAIN_DIR}" ]; then
            echo "Chainstate found. It will be reused: ${COLYELLOW}${CHAIN_DIR}${COLRESET}"
            return 0
        fi

        local download_dir="${WORK_DIR}/downloads"
        local archive_path="${download_dir}/${NETWORK}-stacks-blockchain-latest.tar.zst"
        
        if [ -f "${archive_path}" ]; then
            echo "Chainstate archive found will be reused: ${COLYELLOW}${archive_path}${COLRESET}"    
        else     
            mkdir -p "${download_dir}"
            echo "Downloading latest ${NETWORK} chainstate archive ${COLYELLOW}https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.zst${COLRESET}"
            local url="https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.zst"
            aria2c -x 16 -s 16 -k 1M --summary-interval=0 -d "${download_dir}" "${url}"  || {
            echo "${COLRED}Error${COLRESET} downloading latest ${NETWORK} chainstate archive"
            exit 1
            }
        fi

        # Extract downloaded archive
        mkdir -p "${CHAIN_DIR}"
        echo "Extracting downloaded archive: ${COLYELLOW}${archive_path}${COLRESET}"
        if [ ! -f "${archive_path}" ]; then
            echo "${COLRED}Error${COLRESET} ${archive_path} not found"
            exit 1
        fi
        tar --strip-components=1 --zstd -xvf "${archive_path}" -C "${CHAIN_DIR}" || {
            echo "${COLRED}Error${COLRESET} extracting ${NETWORK} chainstate archive"
            exit 1
        }
    fi
}

# Prepare ${CORES} chainstate slice copies under ${SCRATCH_DIR}. Reuses an
# existing scratch dir if its .scratch_meta matches the current chainstate fingerprint
# and slice count; otherwise wipes and rebuilds, using reflink when the filesystem
# supports it (falls back to a single full copy plus marf.sqlite.blobs symlinks).
configure_validation_slices() {
    local meta_file="${SCRATCH_DIR}/.scratch_meta"
    local expected_slices="${CORES}"

    # Fingerprint the source chainstate so we detect in-place updates (same path,
    # different content). mtime+size of the canonical index.sqlite is cheap and
    # changes whenever the chainstate advances.
    local chainstate_sentinel="${CHAIN_DIR}/chainstate/vm/index.sqlite"
    local chainstate_fp=""
    if [ -f "${chainstate_sentinel}" ]; then
        chainstate_fp=$(stat -c '%Y:%s' "${chainstate_sentinel}")
    fi

    # Reuse the existing scratch dir if the previous run used the same chainstate
    # (path AND fingerprint) and produced the same number of slices, and every
    # expected slice still has a valid chainstate db. 
    if [ -d "${SCRATCH_DIR}" ] && [ -f "${meta_file}" ]; then
        local prev_chainstate="" prev_slices="" prev_chainstate_fp=""
        while IFS='=' read -r key value; do
            case "${key}" in
                CHAIN_DIR) prev_chainstate="${value}" ;;
                SLICES)           prev_slices="${value}" ;;
                CHAINSTATE_FP)    prev_chainstate_fp="${value}" ;;
            esac
        done < "${meta_file}"
        if [ "${prev_chainstate}" == "${CHAIN_DIR}" ] \
            && [ "${prev_slices}" == "${expected_slices}" ] \
            && [ "${prev_chainstate_fp}" == "${chainstate_fp}" ] \
            && [ -n "${chainstate_fp}" ]; then
            local all_valid=1
            for ((i=0; i<expected_slices; i++)); do
                if [ ! -f "${SLICE_DIR}${i}/chainstate/vm/index.sqlite" ]; then
                    all_valid=0
                    break
                fi
            done
            if [ "${all_valid}" -eq 1 ]; then
                echo "Reusing existing scratch dir: ${COLYELLOW}${SCRATCH_DIR}${COLRESET} (${expected_slices} slices, chainstate: ${CHAIN_DIR})"
                return 0
            fi
            echo "${COLYELLOW}Scratch dir metadata matched but slices are incomplete${COLRESET}, rebuilding"
        else
            echo "Scratch dir was built with a different config or chainstate content changed, rebuilding"
        fi
    fi

    # If we got here, we need to build the slice dirs from the local chainstate. 
    # First clean up any existing scratch dir contents since we're not reusing it.
    if [ -d "${SCRATCH_DIR}" ]; then
        echo "Deleting existing scratch dir contents: ${COLYELLOW}${SCRATCH_DIR}${COLRESET}"
        find "${SCRATCH_DIR}" -mindepth 1 -depth -print0 | xargs -0 -P "${expected_slices}" -n 500 rm -rf || {
            echo "${COLRED}Error${COLRESET} deleting dir contents: ${SCRATCH_DIR}"
            exit 1
        }
    fi
    echo "Creating scratch and slice dirs"
    (mkdir -p "${SLICE_DIR}0" && cd "${SCRATCH_DIR}") || {
        echo "${COLRED}Error${COLRESET} creating dir ${SLICE_DIR}0"
        exit 1
    }

    # Check if reflink is enabled for the filesystem by copying a test file
    local reflink=0
    touch "${SCRATCH_DIR}/reflink_test"
    if cp --reflink=always "${SCRATCH_DIR}/reflink_test" "${SCRATCH_DIR}/reflink_test_copy" 2>/dev/null; then
        reflink=1
        echo "${COLGREEN}Reflink is supported${COLRESET}: chainstate slice copies will be fast and space-efficient"
    else
        echo "${COLYELLOW}Warning${COLRESET}: reflink is not enabled for this filesystem, chainstate copy will be slower"
    fi
    # Remove the test files, silently failing if the file(s) don't exist
    rm "${SCRATCH_DIR}/reflink_test" "${SCRATCH_DIR}/reflink_test_copy"  2>/dev/null
    
    # If reflink is not enabled for the filesystem, we'll need to copy and link the MARF database to save a little space for the chainstate copy
    if [[ ${reflink} -ne "1" ]]; then
        echo "Copying local chainstate ${CHAIN_DIR} ->  ${COLYELLOW}${SLICE_DIR}0${COLRESET}"
        cp -r "${CHAIN_DIR}"/* "${SLICE_DIR}0"

        echo "Moving marf database: ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs -> ${COLYELLOW}${SCRATCH_DIR}/marf.sqlite.blobs${COLRESET}"
        mv "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs "${SCRATCH_DIR}"/ || {
            echo "${COLRED}Error${COLRESET} moving marf database"
            exit 1
        }
        echo "Symlinking marf database: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${COLYELLOW}${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs${COLRESET}"
        ln -s "${SCRATCH_DIR}"/marf.sqlite.blobs "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs || {
            echo "${COLRED}Error${COLRESET} creating symlink: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs"
            exit 1
        }
    else 
        echo "Copying local chainstate ${CHAIN_DIR} ->  ${COLYELLOW}${SLICE_DIR}0${COLRESET}"
        cp -r --reflink=always "${CHAIN_DIR}"/* "${SLICE_DIR}0" 2>/dev/null
    fi 

    # Sanity check that the chainstate db exists in slice0 before copying
    if [ ! -f "${SLICE_DIR}0/chainstate/vm/index.sqlite" ]; then
        echo "${COLRED}Error${COLRESET}: chainstate db not found (${SLICE_DIR}0/chainstate/vm/index.sqlite)"
        exit 1
    fi

    # Create one slice copy per worker core.
    # note: decrement by 1 since we already have ${SLICE_DIR}0
    local cp_args=(-r)
    if [[ ${reflink} -eq 1 ]]; then
        cp_args+=(--reflink=always)
    fi
    for ((i=1;i<=$(( CORES - 1 ));i++)); do
        echo "Copying ${SLICE_DIR}0 -> ${COLYELLOW}${SLICE_DIR}${i}${COLRESET}"
        cp "${cp_args[@]}" "${SLICE_DIR}0" "${SLICE_DIR}${i}" || {
            echo "${COLRED}Error${COLRESET} copying ${SLICE_DIR}0 -> ${SLICE_DIR}${i}"
            exit 1
        }
    done

    # Record what we built so a future run can reuse this scratch dir as-is.
    {
        printf 'CHAIN_DIR=%s\n' "${CHAIN_DIR}"
        printf 'SLICES=%s\n' "${expected_slices}"
        printf 'CHAINSTATE_FP=%s\n' "${chainstate_fp}"
    } > "${meta_file}"
}

# Create this run's logdir under LOG_ROOT. LOG_ROOT is persistent; the per-run
# timestamped subdir is fresh each invocation.
setup_logs() {
    echo "Creating logdir ${LOG_DIR}"
    mkdir -p "${LOG_DIR}" || {
        echo "${COLRED}Error${COLRESET} creating logdir ${LOG_DIR}"
        exit 1
    }
    echo "${LOG_DIR}" > /tmp/block-validation.logdir
}

# Delete any existing tmux session and recreate. Pre-creates one window per worker
# core so validate_block_range can just send-keys into existing windows regardless
# of which scenario (or order of scenarios) is run.
setup_tmux() {
    if eval "tmux list-windows -t ${TMUX_SESSION} &> /dev/null"; then
        echo "Killing existing tmux session: ${TMUX_SESSION}"
        eval "tmux kill-session -t ${TMUX_SESSION}  &> /dev/null"
    fi
    tmux new-session -d -s "${TMUX_SESSION}" -n "slice0" || {
        echo "${COLRED}Error${COLRESET} creating tmux session ${COLYELLOW}${TMUX_SESSION}${COLRESET}"
        exit 1
    }
    local i
    for ((i=1; i<CORES; i++)); do
        tmux new-window -t "${TMUX_SESSION}" -d -n "slice${i}" || {
            echo "${COLRED}Error${COLRESET} creating tmux window ${COLYELLOW}slice${i}${COLRESET}"
            exit 1
        }
    done
    return 0
}

# Query stacks-inspect for the total number of blocks in the given epoch.
# Args: <mode>  (pre-nakamoto | nakamoto)
# Prints the total to stdout; errors go to stderr.
get_total_blocks() {
    local mode=$1
    local range_command
    case "$mode" in
        nakamoto)     range_command="naka-index-range" ;;
        pre-nakamoto) range_command="index-range" ;;
        *)
            echo "${COLRED}Error${COLRESET} get_total_blocks: invalid mode '${mode}'" >&2
            exit 1
            ;;
    esac
    local inspect_bin="${REPO_DIR}/target/release/stacks-inspect"
    local inspect_config="${REPO_DIR}/stackslib/conf/${NETWORK}-follower-conf.toml"
    local count_output
    if ! count_output=$("${inspect_bin}" --config "${inspect_config}" validate-block "${SLICE_DIR}0" "${range_command}" 2>/dev/null); then
        echo "${COLRED}Error${COLRESET} retrieving total ${mode} blocks from chainstate" >&2
        exit 1
    fi
    local total
    total=$(printf '%s\n' "${count_output}" | awk -F " " '{print $NF}')
    if [ -z "${total}" ]; then
        echo "${COLRED}Error${COLRESET} parsing block count for ${mode}" >&2
        exit 1
    fi
    printf '%s' "${total}"
}

# Validate an inclusive global block range within a single epoch. Converts to the
# half-open epoch-local indices stacks-inspect expects (start is inclusive, end is exclusive), 
# then dispatches one slice per worker core, and waits for the batch to finish.
# Args: <mode> <global_start> <global_end>   (start/end inclusive)
validate_block_range() {
    local mode=$1
    local global_start=$2   # inclusive
    local global_end=$3     # inclusive
    local range_command log_append
    case "$mode" in
        nakamoto)     range_command="naka-index-range"; log_append="_nakamoto" ;;
        pre-nakamoto) range_command="index-range";       log_append="" ;;
        *)
            echo "${COLRED}Error${COLRESET} validate_block_range: invalid mode '${mode}'"
            exit 1
            ;;
    esac
    # Convert the inclusive global block range to the half-open epoch-local index
    # range that stacks-inspect expects (start is inclusive, end is exclusive — see
    # contrib/stacks-inspect/src/lib.rs: SQL `LIMIT {start}, {end-start}`).
    # Pre-naka indices coincide with the global space (epoch starts at 0); nakamoto
    # indices are offset by the pre-naka total.
    # Bounds-check against the epoch total to fail fast on invalid input ranges.
    local starting_block total_blocks
    case "$mode" in
        nakamoto)
            local pre_total=$(get_total_blocks pre-nakamoto)
            local naka_total=$(get_total_blocks nakamoto)
            local epoch_min=${pre_total}
            local epoch_max=$((pre_total + naka_total - 1))
            if [ "${global_start}" -lt "${epoch_min}" ] || [ "${global_end}" -gt "${epoch_max}" ]; then
                echo "${COLRED}Error${COLRESET} nakamoto range ${global_start}-${global_end} is outside the available epoch (${epoch_min}-${epoch_max})"
                exit 1
            fi
            starting_block=$((global_start - pre_total))
            total_blocks=$((global_end - pre_total + 1))
            ;;
        pre-nakamoto)
            local pre_total=$(get_total_blocks pre-nakamoto)
            local epoch_max=$((pre_total - 1))
            if [ "${global_start}" -lt 0 ] || [ "${global_end}" -gt "${epoch_max}" ]; then
                echo "${COLRED}Error${COLRESET} pre-nakamoto range ${global_start}-${global_end} is outside the available epoch (0-${epoch_max})"
                exit 1
            fi
            starting_block=${global_start}
            total_blocks=$((global_end + 1))
            ;;
    esac
    # global = local + global_offset (0 for pre-naka, pre_total for naka)
    local global_offset=$((global_start - starting_block))

    local inspect_bin="${REPO_DIR}/target/release/stacks-inspect"
    local inspect_config="${REPO_DIR}/sample/conf/${NETWORK}-follower-conf.toml"
    local inspect_prefix="${inspect_bin} --config ${inspect_config} validate-block"

    local block_diff=$((global_end - global_start + 1))
    local slices="${CORES}"
    # If the range is smaller than the worker count, only spin up enough slices
    # to cover it (avoids slice_blocks=0 → infinite loop / zero-width SQL ranges).
    if [ "${slices}" -gt "${block_diff}" ]; then
        slices=$block_diff
    fi
    local slice_blocks=$((block_diff / slices))

    echo "************************************************************************"
    echo "Mode: ${COLYELLOW}${mode}${COLRESET}"
    echo "Block range: ${COLYELLOW}${global_start}-${global_end}${COLRESET} (${block_diff} blocks)"
    echo "Slices: ${COLYELLOW}${slices}${COLRESET} | Blocks/slice: ${COLYELLOW}${slice_blocks}${COLRESET}"
    echo "************************************************************************"
    local range_label="${mode} validation"
    local range_start=$(phase_start "${range_label}")

    local end_block_count=$starting_block
    local slice_counter=0
    while [[ ${end_block_count} -lt ${total_blocks} ]]; do
        local start_block_count=$end_block_count
        end_block_count=$((end_block_count + slice_blocks))
        if [[ "${end_block_count}" -gt "${total_blocks}" ]] || [[ "${slice_counter}" -eq $((slices - 1)) ]]; then
            end_block_count="${total_blocks}"
        fi
        # Local boundaries are half-open [start_block_count, end_block_count);
        # convert back to inclusive globals for display.
        local global_slice_start=$((start_block_count + global_offset))
        local global_slice_end=$((end_block_count + global_offset - 1))
        local slice_path="${SLICE_DIR}${slice_counter}"
        local log_file="${LOG_DIR}/slice${slice_counter}${log_append}.log"
        local log=" | tee -a ${log_file}"
        local cmd="${inspect_prefix} ${slice_path} ${range_command} ${start_block_count} ${end_block_count} 2>/dev/null"
        echo "  ${COLGREEN}${TMUX_SESSION}:slice${slice_counter}${COLRESET} :: Blocks: ${COLYELLOW}${global_slice_start}-${global_slice_end}${COLRESET} :: Logging to: ${log_file}"
        echo "Command: ${cmd}" > "${log_file}"
        echo "Validating blocks: ${global_slice_start}-${global_slice_end} (out of ${global_end})" >> "${log_file}"
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "${cmd}${log}" Enter || {
            echo "${COLRED}Error${COLRESET} sending stacks-inspect command to tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
            exit 1
        }
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "echo \${PIPESTATUS[0]} >> ${log_file}" Enter || {
            echo "${COLRED}Error${COLRESET} sending return status command to tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
            exit 1
        }
        slice_counter=$((slice_counter + 1))
    done
    check_progress
    phase_end "${range_label}" "${range_start}"
}

# Translate the user-facing VALIDATE scenario into inclusive global block ranges,
# then hand each range to validate_block_range. This function deals only in the
# continuous global block space; 
# Convention (mainnet example with pre_total=185630):
#   pre-naka : globals 0..185629    (inclusive, pre_total blocks)
#   naka     : globals 185630..N    (inclusive, naka_total blocks)
run_validation() {
    case "${VALIDATE}" in
        test)
            local pre_start pre_end
            if [ "${NETWORK}" == "testnet" ]; then
                pre_start=1
                pre_end=299
            else
                pre_start=161200
                pre_end=161299
            fi
            local naka_start=300883 naka_end=301882

            echo "${COLBOLD}Validating in test mode${COLRESET}"
            validate_block_range pre-nakamoto "${pre_start}" "${pre_end}"
            validate_block_range nakamoto "${naka_start}" "${naka_end}"
            ;;
        pre-nakamoto)
            local pre_total=$(get_total_blocks pre-nakamoto)
            validate_block_range pre-nakamoto 0 $((pre_total - 1))
            ;;
        nakamoto)
            local pre_total=$(get_total_blocks pre-nakamoto)
            local naka_total=$(get_total_blocks nakamoto)
            validate_block_range nakamoto "${pre_total}" $((pre_total + naka_total - 1))
            ;;
        full)
            local pre_total=$(get_total_blocks pre-nakamoto)
            local naka_total=$(get_total_blocks nakamoto)
            validate_block_range pre-nakamoto 0 $((pre_total - 1))
            validate_block_range nakamoto "${pre_total}" $((pre_total + naka_total - 1))
            ;;
        *)
            local start end
            if [[ "${VALIDATE}" =~ ^([0-9]+):([0-9]+)$ ]]; then
                # <start>:<end>  -- inclusive range
                start=${BASH_REMATCH[1]}
                end=${BASH_REMATCH[2]}
                if [ "${start}" -gt "${end}" ]; then
                    echo "${COLRED}Error${COLRESET} Invalid range: start (${start}) > end (${end})"
                    exit 1
                fi
            elif [[ "${VALIDATE}" =~ ^([0-9]+)[+]([0-9]+)$ ]]; then
                # <start>+<count>  -- N blocks starting at start (count must be > 0)
                start=${BASH_REMATCH[1]}
                local count=${BASH_REMATCH[2]}
                if [ "${count}" -lt 1 ]; then
                    echo "${COLRED}Error${COLRESET} Invalid count: must be at least 1 (got ${count})"
                    exit 1
                fi
                end=$((start + count - 1))
            else
                echo "${COLRED}Error${COLRESET} Invalid VALIDATE value: '${VALIDATE}'"
                exit 1
            fi
            
            local pre_total=$(get_total_blocks pre-nakamoto)
            if [ "${end}" -lt "${pre_total}" ]; then
                validate_block_range pre-nakamoto "${start}" "${end}"
            elif [ "${start}" -ge "${pre_total}" ]; then
                validate_block_range nakamoto "${start}" "${end}"
            else
                echo "${COLYELLOW}Range straddles epoch boundary at block ${pre_total}; splitting into two runs${COLRESET}"
                validate_block_range pre-nakamoto "${start}" $((pre_total - 1))
                validate_block_range nakamoto "${pre_total}" "${end}"
            fi
            ;;
    esac
}

# Pretty print the status output (simple spinner while pids are active)
check_progress() {
    # Give the pids a few seconds to show up in process table before checking if they're running
    local sleep_duration=5
    local progress=1
    local sp="/-\|"
    local count
    while [ $sleep_duration -gt 0 ]; do
        ${IS_TTY} && printf "Sleeping ...  \b [ %s%s%s ] \033[0K\r" "${COLYELLOW}" "${sleep_duration}" "${COLRESET}"
        sleep_duration=$((sleep_duration-1))
        sleep 1
    done
    echo "************************************************************************"
    echo "Checking Block Validation status"
    echo ' '
    while true; do
        count=$(pgrep -c "stacks-inspect" || true)
        if [ "${count}" -gt 0 ]; then
            ${IS_TTY} && printf "Block validation processes are currently active [ %s%s%s%s ] ...  \b${sp:progress++%${#sp}:1}  \033[0K\r" "${COLYELLOW}" "${COLBOLD}" "${count}" "${COLRESET}"
        else
            ${IS_TTY} && printf "\rAll block validation processes finished\033[0K\n"
            break
        fi
        sleep 1
    done
    echo "************************************************************************"
}

# Aggregate per-slice return codes and "Failed processing block" lines into
# ${LOG_DIR}/results.log, prefixed with a single "Failures: N" header.
store_results() {
    # Text file to store results
    local results="${LOG_DIR}/results.log"
    local failed=0;
    local block_failure=0;
    local failure_count=0;
    local return_code=0;
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
                count_one=$((count_one + 1))
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
        # grep exits 1 when no lines match; swallow it so pipefail+set -e
        # don't abort before the no-match fallback below runs.
        failure_count=$(grep -rc "Failed processing block" slice*.log | awk -F: '$NF >= 0 {x+=$NF; $NF=""} END{print x}' || true)
        output=$(grep -r -h "Failed processing block" slice*.log || true)
        local IFS=$'\n'
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

# Check and install missing dependencies
check_dependencies() {
    local has_apt=1
    local has_sudo=1
    local cmd rp package
    for cmd in apt-get sudo curl tmux git aria2 tar gzip grep cargo pgrep tput find; do
        # In Alpine, `find` might be linked to `busybox` and won't work
        if [ "${cmd}" == "find" ] && [ -L "${cmd}" ]; then
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
                    has_apt=0
                    continue
                    ;;
                "sudo")
                    echo "${COLYELLOW}WARN${COLRESET} 'sudo' not found; automatic package installation will fail"
                    has_sudo=0
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

            if [[ ${has_apt} = 0 ]] || [[ ${has_sudo} = 0 ]]; then
            echo "${COLRED}Error${COLRESET} Missing command '${cmd}'"
            exit 1
            fi
            (sudo apt-get update && sudo apt-get install -y "${package}") || {
                echo "${COLRED}Error${COLRESET} installing $package"
                exit 1
            }
        }
    done
}

# Require that a value was passed after the current flag; otherwise show usage and exit 1.
# Usage (from inside a parse_args case branch): require_value "${1}" "${2:-}"
require_value() {
    local flag=$1
    local value=$2
    if [ -z "${value}" ]; then
        echo "ERROR: Missing required value for ${flag}"
        usage
        exit 1
    fi
}

# Parse CLI flags into the config globals. See usage() for the supported flags.
parse_args() {
    while [ ${#} -gt 0 ]; do
        case ${1} in
            -v|--validate)
                # What to validate; see usage for accepted values
                require_value "${1}" "${2:-}"
                VALIDATE="${2}"
                case "${VALIDATE}" in
                    test|pre-nakamoto|nakamoto|full) ;;
                    *)
                        if ! [[ "${VALIDATE}" =~ ^[0-9]+[:+][0-9]+$ ]]; then
                            echo "ERROR: Invalid argument: ${1}"
                            usage
                            exit 1
                        fi
                        ;;
                esac
                shift
                ;;
            -s|--scratchdir)
                # Filesystem location to store the chainstate slice data used by stacks-inspect
                require_value "${1}" "${2:-}"
                SCRATCH_DIR="${2}"
                shift
                ;;
            -n|--network)
                # Required if not mainnet
                require_value "${1}" "${2:-}"
                NETWORK=${2}
                shift
                ;;
            -b|--branch)
                # Build from a specific branch
                require_value "${1}" "${2:-}"
                BRANCH=${2}
                shift
                ;;
            -r|--repodir)
                # Use an existing stacks-core checkout. Disables the branch-tracking
                # logic in build_stacks_inspect — the dir is used as-is, --branch is ignored.
                require_value "${1}" "${2:-}"
                REPO_DIR="${2}"
                TRACK_BRANCH=0
                shift
                ;;
            -c|--chaindir)
                # Use a local chainstate
                require_value "${1}" "${2:-}"
                CHAIN_DIR="${2}"
                shift
                ;;
            -l|--logdir)
                # Parent folder that collects every run's logs (timestamped subdir per run)
                require_value "${1}" "${2:-}"
                LOG_ROOT="${2}"
                shift
                ;;
            -p|--proc)
                # Cores to use for validation
                require_value "${1}" "${2:-}"
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    echo "ERROR: arg ($2) is not a number."
                    exit 1
                fi
                CORES=${2}
                shift
                ;;
            -w|--workdir)
                # Use a specified workdir
                require_value "${1}" "${2:-}"
                WORK_DIR="${2}"
                shift
                ;;
            -h|--help|--usage)
                # show usage/options and exit
                usage
                exit 0
                ;;
            *)
                echo "ERROR: Invalid argument: ${1}"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

# Print a "<label> started" timestamp line on stderr and return the start epoch on stdout.
# Usage: local foo_start=$(phase_start "Foo")
phase_start() {
    local label=$1
    echo "${label} started: ${COLYELLOW}$(date)${COLRESET}" >&2
    date +%s
}

# Print a "<label> finished" timestamp line with elapsed HH:MM:SS since start_epoch.
# Usage: phase_end "Foo" "${foo_start}"
phase_end() {
    local label=$1
    local start_epoch=$2
    local end_epoch=$(date +%s)
    local elapsed=$((end_epoch - start_epoch))
    local duration=$(printf '%02d:%02d:%02d' $((elapsed / 3600)) $(((elapsed % 3600) / 60)) $((elapsed % 60)))
    echo "${label} finished: ${COLYELLOW}$(date)${COLRESET} (duration: ${COLYELLOW}${duration}${COLRESET})"
}

# Entry point
main() {
    # Env preparation
    set_default_config
    parse_args "$@"
    apply_input_config
    check_dependencies
    ${IS_TTY} && tput reset

    # Validation preparation
    local prep_start=$(phase_start "Preparation")
    build_stacks_inspect
    configure_chainstate
    configure_validation_slices
    setup_logs
    setup_tmux
    phase_end "Preparation" "${prep_start}"

    # Validation execution
    local val_start=$(phase_start "Validation")
    run_validation
    store_results
    phase_end "Validation" "${val_start}"
}

main "$@"
