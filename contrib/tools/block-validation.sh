#!/bin/bash
set -Eeuo pipefail

#
# block-validation.sh — parallelizable block validation using stacks-inspect.
#
# Builds stacks-inspect from a configurable git revision (branch, tag, or commit
# SHA), prepares one chainstate copy
# per worker core (reflink when supported, otherwise a full copy), 
# runs validate-block across all workers in parallel via
# tmux windows, and aggregates per-slice results into a dedicated log file.
#
# See usage() for flags descriptions
#
# ** Default folder layout (when only --workdir is set)
#   ${WORK_DIR}/stacks-core/                   built repo (checkout of develop by default)
#   ${WORK_DIR}/chain/                         chainstate used as the source of slices
#   ${WORK_DIR}/downloads/                     downloaded Hiro snapshot archive (expanded in-place to chain/ if missing)
#   ${WORK_DIR}/scratch/                       slice copies + .scratch_meta
#   ${WORK_DIR}/logs/<timestamp>/              per-run logs: slice*.log + slice*.progress per slice, plus results.log
#
# ** Caching (each step skips work when a prior artifact is reusable)
#   - stacks-core/     : reused if present (updated when rev tracking is enabled)
#   - downloads/       : Hiro snapshot archive reused if already on disk (no redownload)
#   - chain/           : reused if already extracted (no re-extract). 
#   - scratch/         : slices reused when .scratch_meta matches the current environment
#                        path + slice count + chainstate fingerprint. Otherwise wiped and rebuilt.
#   - logs/            : never wiped; each run gets a fresh timestamped subdir.
#
# ** Recommendations
#   - Run this script in screen or tmux
#   - Use an existing chainstate on a disk formatted using XFS, Btrfs, ZFS or APFS (for XFS, reflink support must be enabled at fs-creation time; this is the default in recent OS versions)
#   - If using a filesystem which doesn't support reflink (e.g. ext4), ensure that the workdir volume has multiple TBs of free space - each allocated CPU will require its own chainstate copy.
#   - If using CHAIN_DIR on a reflink-enabled filesystem, note that the local chainstate must be located on the same logical volume as the workdir.
#   - Depending on how many CPU cores you have available, a full run will take several hours. More CPUs = faster execution time.
#     - On a system with 12 CPUs allocated and using an existing chainstate on a reflink enabled partition, full validation took ~18 hours (up to naka block 8.020.466).

# ANSI styling helpers. Skip codes when stdout isn't a TTY so logs stay plain.
# style <sgr-code> <text...> — wraps text in an SGR code.
_style() {
    local code=$1
    shift
    if ${IS_TTY}; then
        printf '\033[%sm%s\033[0m' "${code}" "$*"
    else
        printf '%s' "$*"
    fi
}
bold()        { _style "1"    "$*"; }
red()         { _style "31"   "$*"; }
green()       { _style "92"   "$*"; }
yellow()      { _style "33"   "$*"; }
blue()        { _style "94"   "$*"; }
cyan()        { _style "36"   "$*"; }
bold_yellow() { _style "1;33" "$*"; }
bold_green()  { _style "1;92" "$*"; }
highlight()   { cyan "$*"; }

# Logging helpers.
# All accept a printf-style format string + args (wrapper around `printf`).
# Output is written to stderr so stdout can remain for function results.
eprintln() { 
    local fmt=${1:-}
    shift || true
    printf "${fmt}\n" "$@" >&2
}

eprint() { 
    local fmt=${1:-}
    shift || true
    printf "${fmt}" "$@" >&2
}

_log() {
    local prefix=$1 fmt=$2
    shift 2
    local ts="$(date +%Y-%m-%dT%H:%M:%S%z)"
    printf "[%s][%s] ${fmt}\n" "${prefix}" "${ts}" "$@" >&2
}

info()  { _log "$(blue    'INFO')" "$@"; }
warn()  { _log "$(yellow  'WARN')" "$@"; }
error() { _log "$(red     'ERRO')" "$@"; }

# Known --repo label
declare -rA REPO_LABELS=(
    [stacks-core]="https://github.com/stacks-network/stacks-core.git"
    [stacks-core-p]="git@github.com:stx-labs/stacks-blockchain-p.git"
)

# Initialize user-overridable and env defaults. 
pre_input_config() {
    WORK_DIR="${HOME}/block-validation"        # root folder used for block validation and related artifacts
    CHAIN_DIR=""                               # path to local chainstate to use instead of snapshot download
    REPO="stacks-core"                         # --repo value: known label, git URL, or path to an existing checkout.
    REPO_REV="develop"                         # default git revision (branch, tag, or commit) to build stacks-inspect from
    CORES=""                                   # cores to use for validation; resolved in post_input_config
    NETWORK="mainnet"                          # network to validate
    RANGE="full"                               # block range to validate: scenario or numeric range

    if [[ -t 1 ]]; then
        IS_TTY=true
    else
        IS_TTY=false
    fi
}

# Derive configurations and resolved values from the user-supplied config
post_input_config() {
    # Input based configurations
    SCRATCH_DIR="${WORK_DIR}/scratch"                 # root folder for the validation slices
    local log_root="${WORK_DIR}/logs"                 
    local timestamp=$(date +%Y-%m-%d-%s)              # year-month-day-epoch
    LOG_DIR="${log_root}/${timestamp}"                # logs folder

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
        warn "requested cores (${CORES}) exceeds detected cores (${system_cores}); capping to ${system_cores}"
        CORES="${system_cores}"
    elif [ "${CORES}" -eq "${system_cores}" ]; then
        warn "using all ${system_cores} available cores; system may be unresponsive during validation"
    fi
    if [ "${CORES}" -lt 1 ]; then
        error "cores (${CORES}) must be at least 1"
        exit 1
    fi

    # Resolve --repo (label / git URL / local path) into REPO_URL, REPO_DIR, and TRACK_REV.
    resolve_repo "${REPO}"

    # Internal configurations
    SLICE_DIR="${SCRATCH_DIR}/slice"                  # location of slice dirs
    TMUX_SESSION="validation"                         # tmux session name to run the validation
}

# Resolve the --repo argument into REPO_URL, REPO_DIR, and TRACK_REV.
resolve_repo() {
    local arg=$1
    # Known label
    if [ -n "${REPO_LABELS[${arg}]:-}" ]; then
        REPO_URL="${REPO_LABELS[${arg}]}"
        REPO_DIR="${WORK_DIR}/${arg}"
        TRACK_REV=1
    # Git URL  
    elif [[ "${arg}" =~ ^(https?|git|ssh)://|^git@ ]]; then
        REPO_URL="${arg}"
        local base
        base=$(basename "${arg}")
        REPO_DIR="${WORK_DIR}/${base%.git}"
        TRACK_REV=1
    # Existing local directory
    elif [ -d "${arg}" ]; then
        REPO_URL=""
        REPO_DIR="${arg}"
        TRACK_REV=0
    else
        error "--repo '${arg}' is not a known label, a git URL, or an existing directory"
        exit 1
    fi
}

# Show usage and exit
usage() {
    cat <<EOF

Usage: $(bold "${0}") [options]

Options:
    $(yellow "--workdir <path>")
        Root folder for block-validation artifacts.
        Default: $(cyan "${WORK_DIR}")
    $(yellow "--chaindir <path>")
        Local chainstate copy; skips snapshot download.
        Default: $(cyan "${WORK_DIR}/chain")
    $(yellow "--repo <label>|<url>|<path>")
        stacks-core source. Accepts:
          $(cyan "<label>") - known shortcut. Choices: $(cyan "stacks-core"), $(cyan "stacks-core-p") (--rev is applied).
          $(cyan "<url>")   - a valid git URL (--rev is applied).
          $(cyan "<path>")  - existing local repository, used as-is (--rev is ignored).
        Default: $(cyan "stacks-core")
    $(yellow "--rev <branch>|<tag>|<sha>")
        git revision to build. 
        Branches are pulled to the latest; tags/commits land on detached HEAD.
        Default: $(cyan "develop")
    $(yellow "--proc <n>")
        CPU cores for validation, capped at nproc.
        Default: $(cyan "max(1, nproc/4)")
    $(yellow "--network <name>")
        Network to validate. Choices: $(cyan "mainnet"), $(cyan "testnet").
        Default: $(cyan "mainnet")
    $(yellow "--range <mode>")
        Block range to validate. Modes:
          $(cyan "test")            - fixed test ranges for pre-nakamoto and nakamoto
          $(cyan "pre-nakamoto")    - full Epoch 2 blocks
          $(cyan "nakamoto")        - full Epoch 3+ blocks
          $(cyan "full")            - pre-nakamoto + nakamoto blocks
          $(cyan "<start>:<end>")   - inclusive range; auto-splits at the epoch2/3 boundary
          $(cyan "<start>+<count>") - <count> blocks starting at <start>
        Default: $(cyan "full")

Example: full block validation, auto-downloading the chainstate using stacks-core public repo at develop
    $(bold "${0} --workdir /data/workdir")

EOF
}

# Verify that cargo is installed in the expected path, not only $PATH
install_cargo() {
    command -v "${HOME}/.cargo/bin/cargo" >/dev/null 2>&1 || {
        eprintln "Installing Rust via rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || {
            error "installing Rust"
            exit 1
        }
    }
    eprintln "Exporting ${HOME}/.cargo/env"
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
    return 0
}

# Resolve and check out ${REPO_REV} in the current directory. Accepts:
#   - a branch name: switches to it and fast-forwards from origin
#   - a tag        : detached HEAD at the tag (no pull)
#   - a commit SHA : detached HEAD at the commit (no pull); short or full
# Call after fetching, so remote-only branches/tags are resolvable.
checkout_rev() {
    if git show-ref --verify --quiet "refs/remotes/origin/${REPO_REV}"; then
        # Branch case: create/reset a local branch tracking origin/${REPO_REV}.
        # `checkout -B` is force-create + reset to the upstream tip in one step.
        eprintln "Checking out branch $(highlight "${REPO_REV}") (tracking origin/${REPO_REV})"
        git checkout -B "${REPO_REV}" "origin/${REPO_REV}" || {
            error "checking out branch ${REPO_REV}"
            exit 1
        }
    elif git rev-parse --verify --quiet "${REPO_REV}^{commit}" >/dev/null; then
        # Tag or commit SHA (short/full): detach HEAD at the resolved commit.
        eprintln "Checking out $(highlight "${REPO_REV}") (detached HEAD — tag or commit)"
        git checkout --detach "${REPO_REV}" || {
            error "checking out ${REPO_REV}"
            exit 1
        }
    else
        error "revision '${REPO_REV}' not found in ${REPO_DIR} (not a branch, tag, or known commit)"
        exit 1
    fi
}

# Build release stacks-inspect binary.
# When TRACK_REV=1 (default): clone if missing, otherwise check out ${REPO_REV}.
# When TRACK_REV=0 (set by --repo <path>): treat REPO_DIR as a pre-existing checkout.
build_stacks_inspect() {
    if [ "${TRACK_REV}" -eq 0 ]; then
        if [ ! -d "${REPO_DIR}" ]; then
            error "repo dir not found: ${REPO_DIR}"
            exit 1
        fi
        info "Using existing checkout at $(highlight "${REPO_DIR}") as-is (rev tracking disabled)"
    elif [ -d "${REPO_DIR}" ]; then
        info "Found $(highlight "${REPO_DIR}"). Updating to $(highlight "${REPO_REV}")"
        cd "${REPO_DIR}"
        # Stash local changes so checkout is clean; --tags pulls in new tags too.
        git stash --include-untracked
        git fetch --tags --prune origin || {
            error "fetching from origin"
            exit 1
        }
        checkout_rev
    else
        # Full clone (no --branch, since it rejects bare SHAs); resolve REPO_REV afterwards.
        info "Cloning $(highlight "${REPO_URL}") into $(highlight "${REPO_DIR}")"
        git clone "${REPO_URL}" "${REPO_DIR}" || {
            error "cloning ${REPO_URL} into ${REPO_DIR}"
            exit 1
        }
        cd "${REPO_DIR}"
        checkout_rev
    fi
    # Build stacks-inspect to: ${REPO_DIR}/target/release/stacks-inspect
    info "Building stacks-inspect binary"
    cd "${REPO_DIR}/contrib/stacks-inspect" && cargo build --bin=stacks-inspect --release || {
        error "building stacks-inspect binary"
        exit 1
    }
    info "Done building. continuing"
}

# Resolve chain dir: use the user-provided path if set, otherwise reuse
# ${WORK_DIR}/chain if present, or download+extract the Hiro snapshot for ${NETWORK}.
configure_chainstate() {
    if [[ -n "${CHAIN_DIR}" ]]; then
        if [ ! -d "${CHAIN_DIR}" ]; then
            error "Chainstate not found: ${CHAIN_DIR}"
            exit 1
        fi
        info "$(highlight "Using local chainstate: ${CHAIN_DIR}")"
    else
        CHAIN_DIR="${WORK_DIR}/chain"
        if [ -d "${CHAIN_DIR}" ]; then
            info "Chainstate found. It will be reused: $(highlight "${CHAIN_DIR}")"
            return 0
        fi

        local download_dir="${WORK_DIR}/downloads"
        local archive_path="${download_dir}/${NETWORK}-stacks-blockchain-latest.tar.zst"
        
        # Archive is "complete" only if the file exists AND aria2c's .aria2
        # sidecar is gone. Otherwise allow aria2c to try resuming a partial download.
        if [ -f "${archive_path}" ] && [ ! -f "${archive_path}.aria2" ]; then
            info "Chainstate archive found. It will be reused: $(highlight "${archive_path}")"
        else
            mkdir -p "${download_dir}"
            info "Downloading latest ${NETWORK} chainstate archive $(highlight "https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.zst")"
            local url="https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.zst"
            aria2c -x 16 -s 16 -k 1M --summary-interval=0 -d "${download_dir}" "${url}"  || {
                error "downloading latest ${NETWORK} chainstate archive"
                exit 1
            }
        fi

        # Extract downloaded archive
        mkdir -p "${CHAIN_DIR}"
        info "Extracting downloaded archive: $(highlight "${archive_path}")"
        if [ ! -f "${archive_path}" ]; then
            error "${archive_path} not found"
            exit 1
        fi
        tar --strip-components=1 --zstd -xvf "${archive_path}" -C "${CHAIN_DIR}" || {
            error "extracting ${NETWORK} chainstate archive"
            exit 1
        }
    fi
}

# Prepare ${CORES} chainstate slice copies under ${SCRATCH_DIR}. Reuses an
# existing scratch dir if its .scratch_meta matches the current chainstate fingerprint
# and slice count; otherwise wipes and rebuilds, using reflink when the filesystem
# supports it (falls back to a single full copy plus marf.sqlite.blobs symlinks).
#
# When reflink isn't available AND is_range_nakamoto_only is true, copies only
# the subset stacks-inspect needs for Epoch 3+ validation (burnchain/,
# chainstate/vm/, and chainstate/blocks/nakamoto.sqlite*) and skips the thousands
# of pre-nakamoto block subdirs. Gated on reflink because with reflink each
# per-slice copy is metadata-only and skipping those subdirs barely helps.
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
    else
        error "chainstate file not found: ${chainstate_sentinel}"
        exit 1
    fi

    # Probe reflink up-front so we can decide whether to apply the nakamoto-only
    # copy optimization (only worthwhile when reflink is unavailable). The probe
    # mirrors the real CHAIN_DIR -> SCRATCH_DIR copy: a self-copy within SCRATCH_DIR
    # wouldn't catch the case where CHAIN_DIR and SCRATCH_DIR are on different
    # logical volumes (reflink requires src/dest on the same filesystem).
    mkdir -p "${SCRATCH_DIR}"
    local reflink=0
    local reflink_probe_dst="${SCRATCH_DIR}/reflink_test"
    if cp --reflink=always "${chainstate_sentinel}" "${reflink_probe_dst}" 2>/dev/null; then
        reflink=1
        info "$(green "Reflink is supported"): chainstate slice copies will be fast and space-efficient"
    else
        warn "reflink not available, chainstate slice copies will be slower and take more space. Possible causes:"
        warn "  - chain dir ($(highlight "${CHAIN_DIR}")) and scatch dir ($(highlight "${SCRATCH_DIR}")) are on different logical volumes"
        warn "  - filesystem does not support reflink (only supported on XFS, Btrfs, ZFS, or APFS)"
    fi
    # Remove the test file, silently failing if it doesn't exist
    rm -f "${reflink_probe_dst}" 2>/dev/null

    local nakamoto_only=0
    if [[ ${reflink} -eq 0 ]] && is_range_nakamoto_only; then
        nakamoto_only=1
    fi

    # Reuse the existing scratch dir if the previous run used the same chainstate
    # (path AND fingerprint), same slice count, and same nakamoto_only flag (a
    # naka-only slice is missing the pre-naka blocks/* needed by a non-naka-only run),
    # and every expected slice still has a valid chainstate db.
    if [ -d "${SCRATCH_DIR}" ] && [ -f "${meta_file}" ]; then
        local prev_chainstate="" prev_slices="" prev_chainstate_fp="" prev_naka_only=""
        while IFS='=' read -r key value; do
            case "${key}" in
                CHAIN_DIR)        prev_chainstate="${value}" ;;
                SLICES)           prev_slices="${value}" ;;
                CHAINSTATE_FP)    prev_chainstate_fp="${value}" ;;
                NAKAMOTO_ONLY)    prev_naka_only="${value}" ;;
            esac
        done < "${meta_file}"
        if [ "${prev_chainstate}" == "${CHAIN_DIR}" ] \
            && [ "${prev_slices}" == "${expected_slices}" ] \
            && [ "${prev_chainstate_fp}" == "${chainstate_fp}" ] \
            && [ "${prev_naka_only}" == "${nakamoto_only}" ] \
            && [ -n "${chainstate_fp}" ]; then
            local all_valid=1
            for ((i=0; i<expected_slices; i++)); do
                if [ ! -f "${SLICE_DIR}${i}/chainstate/vm/index.sqlite" ]; then
                    all_valid=0
                    break
                fi
            done
            if [ "${all_valid}" -eq 1 ]; then
                info "Scratch dir found. It will be reused: $(highlight "${SCRATCH_DIR}") (${expected_slices} slices)"
                return 0
            fi
            warn "$(highlight "Scratch dir metadata matched but slices are incomplete"), rebuilding ..."
        else
            warn "Scratch dir was built with a different config or chainstate content changed, rebuilding ..."
        fi
    fi

    # If we got here, we need to build the slice dirs from the local chainstate.
    # First clean up any existing scratch dir contents since we're not reusing it.
    info "Deleting existing scratch dir contents: $(highlight "${SCRATCH_DIR}")"
    find "${SCRATCH_DIR}" -mindepth 1 -depth -print0 | xargs -0 -P "${expected_slices}" -n 500 rm -rf || {
        error "deleting dir contents: ${SCRATCH_DIR}"
        exit 1
    }
    info "Creating scratch and slice dirs"
    mkdir -p "${SLICE_DIR}0" || {
        error "creating dir ${SLICE_DIR}0"
        exit 1
    }

    # Build slice0 from CHAIN_DIR. Split by reflink availability:
    #   - reflink on : full reflink copy (per-slice copies are metadata-only and cheap)
    #   - reflink off: either selective naka-only copy (when nakamoto_only=1) or a
    #                  plain full copy, then move+symlink marf.sqlite.blobs so the
    #                  per-slice copies share that one big inode.
    if [[ ${reflink} -eq 1 ]]; then
        info "Copying ${CHAIN_DIR} -> $(highlight "${SLICE_DIR}0")"
        cp -r --reflink=always "${CHAIN_DIR}"/* "${SLICE_DIR}0" 2>/dev/null
    else
        if [[ ${nakamoto_only} -eq 1 ]]; then
            info "Copying nakamoto-only subset of ${CHAIN_DIR} -> $(highlight "${SLICE_DIR}0")"
            mkdir -p "${SLICE_DIR}0/chainstate/blocks"
            cp -r "${CHAIN_DIR}/burnchain"     "${SLICE_DIR}0/"           || { error "copying burnchain";    exit 1; }
            cp -r "${CHAIN_DIR}/chainstate/vm" "${SLICE_DIR}0/chainstate/" || { error "copying chainstate/vm"; exit 1; }
            # nakamoto.sqlite{,-wal,-shm} — glob covers all three; -shm is recreated by SQLite if missing.
            if ! compgen -G "${CHAIN_DIR}/chainstate/blocks/nakamoto.sqlite*" >/dev/null; then
                error "nakamoto.sqlite not found in ${CHAIN_DIR}/chainstate/blocks (chainstate too old for naka-only run?)"
                exit 1
            fi
            cp "${CHAIN_DIR}"/chainstate/blocks/nakamoto.sqlite* "${SLICE_DIR}0/chainstate/blocks/" || {
                error "copying nakamoto.sqlite"
                exit 1
            }
        else
            info "Copying ${CHAIN_DIR} -> $(highlight "${SLICE_DIR}0")"
            cp -r "${CHAIN_DIR}"/* "${SLICE_DIR}0"
        fi

        info "Moving marf database: ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs -> $(highlight "${SCRATCH_DIR}/marf.sqlite.blobs")"
        mv "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs "${SCRATCH_DIR}"/ || {
            error "moving marf database"
            exit 1
        }
        info "Symlinking marf database: ${SCRATCH_DIR}/marf.sqlite.blobs -> $(highlight "${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs")"
        ln -s "${SCRATCH_DIR}"/marf.sqlite.blobs "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs || {
            error "creating symlink: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs"
            exit 1
        }
    fi

    # Sanity check that the chainstate db exists in slice0 before copying
    if [ ! -f "${SLICE_DIR}0/chainstate/vm/index.sqlite" ]; then
        error "chainstate db not found (${SLICE_DIR}0/chainstate/vm/index.sqlite)"
        exit 1
    fi

    # Create one slice copy per worker core (decrement by 1 since slice0 exists).
    # With reflink, the per-slice copy is metadata-only; without, the bulk of the
    # data is the marf symlink so the actual copy is still small.
    local slice_cp_args=(-r)
    if [[ ${reflink} -eq 1 ]]; then
        slice_cp_args+=(--reflink=always)
    fi
    for ((i=1;i<=$(( CORES - 1 ));i++)); do
        info "Copying ${SLICE_DIR}0 -> $(highlight "${SLICE_DIR}${i}")"
        cp "${slice_cp_args[@]}" "${SLICE_DIR}0" "${SLICE_DIR}${i}" || {
            error "copying ${SLICE_DIR}0 -> ${SLICE_DIR}${i}"
            exit 1
        }
    done

    # Record what we built so a future run can reuse this scratch dir as-is.
    {
        printf 'CHAIN_DIR=%s\n' "${CHAIN_DIR}"
        printf 'SLICES=%s\n' "${expected_slices}"
        printf 'CHAINSTATE_FP=%s\n' "${chainstate_fp}"
        printf 'NAKAMOTO_ONLY=%s\n' "${nakamoto_only}"
    } > "${meta_file}"
}

# Create this run's log dir
setup_logs() {
    info "Creating logs dir ${LOG_DIR}"
    mkdir -p "${LOG_DIR}" || {
        error "creating logs dir ${LOG_DIR}"
        exit 1
    }
}

# EXIT trap handler: kill the tmux session so worker processes don't outlive the
# script (e.g. when the user confirms abort via confirm_abort, or set -e trips
# after windows are running). Logs are persisted to ${LOG_DIR}, so the live
# panes aren't needed for post-mortem.
cleanup_tmux() {
    tmux kill-session -t "${TMUX_SESSION}" &> /dev/null || true
}

# Delete any existing tmux session and recreate. Pre-creates one window per worker
# core so validate_block_range can just send-keys into existing windows regardless
# of which scenario (or order of scenarios) is run.
setup_tmux() {
    if eval "tmux list-windows -t ${TMUX_SESSION} &> /dev/null"; then
        info "Cleaning existing tmux session: ${TMUX_SESSION}"
        cleanup_tmux
    fi
    tmux new-session -d -s "${TMUX_SESSION}" -n "slice0" || {
        error "creating tmux session $(highlight "${TMUX_SESSION}")"
        exit 1
    }
    # Register cleanup as soon as the session exists, so a failure in the
    # window-creation loop below still tears the session down.
    trap cleanup_tmux EXIT
    local i
    for ((i=1; i<CORES; i++)); do
        tmux new-window -t "${TMUX_SESSION}" -d -n "slice${i}" || {
            error "creating tmux window $(highlight "slice${i}")"
            exit 1
        }
    done
    return 0
}

# Query stacks-inspect for the total number of blocks in the given epoch.
# Args: <mode>  (pre-nakamoto | nakamoto)
# Prints the total to stdout; errors go to stderr.
# Always reads from CHAIN_DIR (the canonical chainstate) so callers don't need
# slices to exist, and so the answer is consistent whether called during slice
# prep or while workers are running.
get_total_blocks() {
    local mode=$1
    local range_command
    case "$mode" in
        nakamoto)     range_command="naka-index-range" ;;
        pre-nakamoto) range_command="index-range" ;;
        *)
            error "get_total_blocks: invalid mode '${mode}'"
            exit 1
            ;;
    esac
    local inspect_bin="${REPO_DIR}/target/release/stacks-inspect"
    local inspect_config="${REPO_DIR}/sample/conf/${NETWORK}-follower-conf.toml"
    local count_output
    if ! count_output=$("${inspect_bin}" --config "${inspect_config}" validate-block "${CHAIN_DIR}" "${range_command}" 2>/dev/null); then
        error "retrieving total ${mode} blocks from chainstate"
        exit 1
    fi
    local total
    total=$(printf '%s\n' "${count_output}" | awk -F " " '{print $NF}')
    if [ -z "${total}" ]; then
        error "parsing block count for ${mode}"
        exit 1
    fi
    printf '%s' "${total}"
}

# Returns 0 (true) if the current RANGE only validates Epoch 3+ (nakamoto) blocks,
# 1 (false) otherwise. Used by configure_validation_slices to skip copying the
# thousands of pre-nakamoto chainstate/blocks/* subdirs into each slice when
# they won't be read.
is_range_nakamoto_only() {
    case "${RANGE}" in
        nakamoto)               return 0 ;;
        test|pre-nakamoto|full) return 1 ;;
        *)
            local start end
            if [[ "${RANGE}" =~ ^([0-9]+):([0-9]+)$ ]]; then
                start=${BASH_REMATCH[1]}
                end=${BASH_REMATCH[2]}
            elif [[ "${RANGE}" =~ ^([0-9]+)[+]([0-9]+)$ ]]; then
                start=${BASH_REMATCH[1]}
                end=$((start + BASH_REMATCH[2] - 1))
            else
                return 1
            fi
            local pre_total
            pre_total=$(get_total_blocks pre-nakamoto)
            # Range fully above the epoch2/3 boundary => nakamoto-only.
            # Straddling ranges still need pre-naka blocks (run_validation splits them).
            [ "${start}" -ge "${pre_total}" ] && [ "${end}" -ge "${pre_total}" ]
            ;;
    esac
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
        pre-nakamoto) range_command="index-range";      log_append="" ;;
        *)
            error "validate_block_range: invalid mode '${mode}'"
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
            local pre_total naka_total
            pre_total=$(get_total_blocks pre-nakamoto)
            naka_total=$(get_total_blocks nakamoto)
            local epoch_min=${pre_total}
            local epoch_max=$((pre_total + naka_total - 1))
            if [ "${global_start}" -lt "${epoch_min}" ] || [ "${global_end}" -gt "${epoch_max}" ]; then
                error "nakamoto range ${global_start}-${global_end} is outside the available epoch (${epoch_min}-${epoch_max})"
                exit 1
            fi
            starting_block=$((global_start - pre_total))
            total_blocks=$((global_end - pre_total + 1))
            ;;
        pre-nakamoto)
            local pre_total
            pre_total=$(get_total_blocks pre-nakamoto)
            local epoch_max=$((pre_total - 1))
            if [ "${global_start}" -lt 0 ] || [ "${global_end}" -gt "${epoch_max}" ]; then
                error "pre-nakamoto range ${global_start}-${global_end} is outside the available epoch (0-${epoch_max})"
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

    local block_diff=$((global_end - global_start + 1))
    local slices="${CORES}"
    # If the range is smaller than the worker count, only spin up enough slices
    # to cover it (avoids slice_blocks=0 → infinite loop / zero-width SQL ranges).
    if [ "${slices}" -gt "${block_diff}" ]; then
        slices=$block_diff
    fi
    local slice_blocks=$((block_diff / slices))
    
    local range_label="${mode} validation"
    local range_start=$(phase_start "${range_label}")
    eprintln "************************************************************************"
    eprintln "Mode: $(highlight "${mode}")"
    eprintln "Block range: $(highlight "${global_start}-${global_end}") (${block_diff} blocks)"
    eprintln "Slices: $(highlight "${slices}") | Blocks/slice: $(highlight "${slice_blocks}")"
    eprintln "************************************************************************"

    local end_block_count=$starting_block
    local slice_counter=0
    local slice_progress_files=()
    # Per-slice pipeline: inspect → [tee /dev/tty] → tr → read-loop → .progress + .log
    #
    # .progress is truncated+rewritten on each "Validating: NN%" update (read by
    # compute_progress_pct); .log is appended for non-progress lines only (Finished,
    # errors), keeping it small even on multi-hour runs. tr converts the in-place
    # \r progress separators to \n so the read loop can process them as records.
    #
    # Buffering matters because stacks-inspect's progress is ~25-byte writes
    # separated only by \r (no \n until completion), so without help, every stage
    # would hold data until inspect exits. stdbuf -o0 disables tee's stdout
    # buffering, stdbuf -oL keeps tr line-buffered. The filter is a bash read loop
    # rather than awk because mawk has its own input buffer above stdio that
    # stdbuf cannot reach — awk only saw data at EOF.
    #
    # The tee /dev/tty stage mirrors the live \r progress into the tmux pane; only
    # useful when someone might be watching (i.e. interactive run), so gate it on
    # IS_TTY to skip both tee and its stdbuf wrapper when non-interactive.
    local tee_stage=""
    if ${IS_TTY}; then
        tee_stage="stdbuf -o0 tee /dev/tty | "
    fi
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
        local progress_file="${LOG_DIR}/slice${slice_counter}${log_append}.progress"
        slice_progress_files+=("${progress_file}")
        # tmux send-keys re-parses this string as shell source in the target window,
        # so quote the paths so spaces / shell metacharacters survive re-parsing.
        local inspect_cmd="\"${inspect_bin}\" --config \"${inspect_config}\" validate-block \"${slice_path}\" ${range_command} ${start_block_count} ${end_block_count} 2>/dev/null"
        local cmd="${inspect_cmd} | ${tee_stage}stdbuf -oL tr '\\r' '\\n' | while IFS= read -r line; do if [[ \"\$line\" =~ ^Validating:[[:space:]]+[0-9]+% ]]; then printf '%s\\n' \"\$line\" > '${progress_file}'; elif [[ -n \"\$line\" ]]; then printf '%s\\n' \"\$line\" >> '${log_file}'; fi; done"
        eprintln "  $(highlight "${TMUX_SESSION}:slice${slice_counter}") :: Blocks: $(highlight "${global_slice_start}-${global_slice_end}") :: Logging to: ${log_file}"
        echo "Command: ${inspect_cmd}" > "${log_file}"
        echo "Validating blocks: ${global_slice_start}-${global_slice_end} (out of ${global_end})" >> "${log_file}"
        echo "Progress updates will be written to: ${progress_file}" >> "${log_file}"
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "${cmd}" Enter || {
            error "sending stacks-inspect command to tmux window $(highlight "slice${slice_counter}")"
            exit 1
        }
        # PIPESTATUS[0] is still stacks-inspect (first pipeline stage), so the
        # return-code capture continues to work unchanged.
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "echo \${PIPESTATUS[0]} >> ${log_file}" Enter || {
            error "sending return status command to tmux window $(highlight "slice${slice_counter}")"
            exit 1
        }
        slice_counter=$((slice_counter + 1))
    done
    check_progress "${slice_progress_files[@]}"
    phase_end "${range_label}" "${range_start}"
}

# Translate the user-facing RANGE scenario into inclusive global block ranges,
# then hand each range to validate_block_range. This function deals only in the
# continuous global block space;
# Convention (mainnet example with pre_total=185630):
#   pre-naka : globals 0..185629    (inclusive, pre_total blocks)
#   naka     : globals 185630..N    (inclusive, naka_total blocks)
run_validation() {
    case "${RANGE}" in
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

            info "$(bold_yellow "Validating in test mode")"
            validate_block_range pre-nakamoto "${pre_start}" "${pre_end}"
            validate_block_range nakamoto "${naka_start}" "${naka_end}"
            ;;
        pre-nakamoto)
            local pre_total
            pre_total=$(get_total_blocks pre-nakamoto)
            validate_block_range pre-nakamoto 0 $((pre_total - 1))
            ;;
        nakamoto)
            local pre_total naka_total
            pre_total=$(get_total_blocks pre-nakamoto)
            naka_total=$(get_total_blocks nakamoto)
            validate_block_range nakamoto "${pre_total}" $((pre_total + naka_total - 1))
            ;;
        full)
            local pre_total naka_total
            pre_total=$(get_total_blocks pre-nakamoto)
            naka_total=$(get_total_blocks nakamoto)
            validate_block_range pre-nakamoto 0 $((pre_total - 1))
            validate_block_range nakamoto "${pre_total}" $((pre_total + naka_total - 1))
            ;;
        *)
            local start end
            if [[ "${RANGE}" =~ ^([0-9]+):([0-9]+)$ ]]; then
                # <start>:<end>  -- inclusive range
                start=${BASH_REMATCH[1]}
                end=${BASH_REMATCH[2]}
                if [ "${start}" -gt "${end}" ]; then
                    error "Invalid range: start (${start}) > end (${end})"
                    exit 1
                fi
            elif [[ "${RANGE}" =~ ^([0-9]+)[+]([0-9]+)$ ]]; then
                # <start>+<count>  -- N blocks starting at start (count must be > 0)
                start=${BASH_REMATCH[1]}
                local count=${BASH_REMATCH[2]}
                if [ "${count}" -lt 1 ]; then
                    error "Invalid count: must be at least 1 (got ${count})"
                    exit 1
                fi
                end=$((start + count - 1))
            else
                error "Invalid --range value: '${RANGE}'"
                exit 1
            fi
            
            local pre_total
            pre_total=$(get_total_blocks pre-nakamoto)
            if [ "${end}" -lt "${pre_total}" ]; then
                validate_block_range pre-nakamoto "${start}" "${end}"
            elif [ "${start}" -ge "${pre_total}" ]; then
                validate_block_range nakamoto "${start}" "${end}"
            else
                warn "Range straddles epoch boundary at block ${pre_total}; splitting into two runs"
                validate_block_range pre-nakamoto "${start}" $((pre_total - 1))
                validate_block_range nakamoto "${pre_total}" "${end}"
            fi
            ;;
    esac
}

# Coarse overall progress for the current phase, computed from the last 1-2 slice
# progress files (the final slice may own a different-sized remainder, so a
# weighted average across all slices would skew optimistic). Each slice's progress
# file contains a single line — the latest "Validating: NN%" entry — kept current
# by the read-loop filter in validate_block_range.
# Args: <progress_file>...
# Prints "NN%" or "NA" on stdout.
compute_progress_pct() {
    local progress_files=("$@")
    local n=${#progress_files[@]}
    local tail_files=()
    if [ "${n}" -ge 2 ]; then
        tail_files=("${progress_files[n-2]}" "${progress_files[n-1]}")
    elif [ "${n}" -eq 1 ]; then
        tail_files=("${progress_files[0]}")
    fi
    local pct_sum=0 found=0
    local f line
    for f in "${tail_files[@]}"; do
        [ -f "${f}" ] || continue
        line=$(cat "${f}" 2>/dev/null || true)
        if [[ "${line}" =~ ([0-9]+)% ]]; then
            pct_sum=$((pct_sum + BASH_REMATCH[1]))
            found=$((found + 1))
        fi
    done
    if [ "${found}" -gt 0 ]; then
        printf '%d%%' $(( pct_sum / found ))
    else
        printf 'NA'
    fi
}

# Timing helpers.
# Usage:
#   local t=$(timer_start)
#   ...work...
#   local elapsed=$(timer_elapsed "${t}")
#   format_hms "${elapsed}"   # e.g. "00h20m30s"
timer_start() {
    date +%s
}
timer_elapsed() {
    local start_epoch=$1
    printf '%d' $(( $(date +%s) - start_epoch ))
}
# Format a seconds count as "HHhMMmSSs" (e.g. 1230 -> "00h20m30s").
format_hms() {
    local elapsed=$1
    printf '%02dh%02dm%02ds' $((elapsed / 3600)) $(((elapsed % 3600) / 60)) $((elapsed % 60))
}

# Pretty print the status output (simple spinner while pids are active)
# Args: <progress_file>...   slice .progress files for the current phase, used to estimate %.
check_progress() {
    local slice_progress=("$@")
    local progress=1
    local symbols="/-\|"
    local count pct spinner elapsed
    local timer=$(timer_start)
    # Give the pids a while to show up in the process table before checking if they're running
    while true; do
        count=$(pgrep -c "stacks-inspect" || true)
        if [ "${count}" -eq 0 ]; then
            ${IS_TTY} && eprint "Waiting for processes to be spawned ... \033[0K\r"
        else
            break
        fi
        sleep 1 || true   # tolerate SIGINT so confirm_abort "no" can resume
    done

    eprintln "************************************************************************"
    eprintln "Checking Block Validation status"
    eprintln ' '
    while true; do
        count=$(pgrep -c "stacks-inspect" || true)
        elapsed=$(timer_elapsed "${timer}")
        if [ "${count}" -gt 0 ]; then
            pct=$(compute_progress_pct "${slice_progress[@]}")
            spinner="${symbols:progress++%${#symbols}:1}"
            ${IS_TTY} && eprint "Processes: [ %s ] Progress: [ %s ] Elapsed: [ %s ] ...  \b%s  \033[0K\r" \
                            "$(bold_yellow "${count}")" "$(bold_yellow "${pct}")" "$(bold_yellow "$(format_hms "${elapsed}")")" "${spinner}"
        else
            ${IS_TTY} && eprint "\rValidation completed in %s\033[0K\n" \
                            "$(highlight "$(format_hms "${elapsed}")")"
            break
        fi
        sleep 1 || true   # tolerate SIGINT so confirm_abort "no" can resume
    done
    eprintln "************************************************************************"
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
    cd "${LOG_DIR}" || {
        error "Logdir $(highlight "${LOG_DIR}") doesn't exist"
        exit 1
    }
    # Retrieve the count of all lines with `Failed processing block`
    # Check the return codes to see if we had a panic
    for file in $(find . -name "slice*.log" -printf '%P\n' | sort); do
        info "Checking file: $(highlight "$file")"
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
        eprintln "Panic: $(red "$failure_count")"
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
                    error "writing failure to: ${results}"
                }
            done
        else
            ## failures, but not block failures (binary panic for example)
            failure_count=$count_one
        fi
    fi

    sed  -i "1i Failures: ${failure_count}" "${results}"
    info "Results: $(highlight "${results}")"

    if [ "${failure_count}" -eq 0 ]; then
        info "$(bold_green "Block Validation successful!")"
    else
        error "Block validation failures detected: ${failure_count}"
    fi
}

# Check and install missing dependencies
check_dependencies() {
    local has_apt=1
    local has_sudo=1
    local cmd rp package find_path
    local -a required=(
        apt-get sudo curl tmux git aria2c tar zstd grep cargo pgrep tput
        find xargs awk sed nproc stat stdbuf
    )
    for cmd in "${required[@]}"; do
        # In Alpine, `find` may be a symlink to busybox, whose `find` lacks flags we use.
        # Resolve the real `find` in $PATH first; `[ -L find ]` would only test a
        # symlink literally named `find` in the current directory.
        if [ "${cmd}" == "find" ]; then
            find_path="$(command -v find || true)"
            if [ -L "${find_path}" ]; then
                rp="$(readlink "${find_path}")"
                if [[ "${rp}" == *busybox* ]]; then
                    error "Busybox 'find' is not supported. Please install 'findutils' or similar."
                    exit 1
                fi
            fi
        fi

        command -v "${cmd}" >/dev/null 2>&1 || {
            case "${cmd}" in
                "apt-get")
                    warn "'apt-get' not found; automatic package installation will fail"
                    has_apt=0
                    continue
                    ;;
                "sudo")
                    warn "'sudo' not found; automatic package installation will fail"
                    has_sudo=0
                    continue
                    ;;
                "cargo")
                    install_cargo
                    ;;
                "pgrep")
                    package="procps"
                    ;;
                "aria2c")
                    package="aria2"
                    ;;
                "awk")
                    package="gawk"
                    ;;
                "find"|"xargs")
                    package="findutils"
                    ;;
                "nproc"|"stat"|"stdbuf")
                    package="coreutils"
                    ;;
                *)
                    package="${cmd}"
                    ;;
            esac

            if [[ ${has_apt} = 0 ]] || [[ ${has_sudo} = 0 ]]; then
                error "Missing command '${cmd}'"
                exit 1
            fi
            (sudo apt-get update && sudo apt-get install -y "${package}") || {
                error "installing $package"
                exit 1
            }
        }
    done
}

# Require that a value was passed after the current flag; otherwise show usage and exit 1.
# Usage (from inside a parse_input case branch): require_value "${1}" "${2:-}"
require_value() {
    local flag=$1
    local value=$2
    if [ -z "${value}" ]; then
        error "Missing required value for ${flag}"
        usage
        exit 1
    fi
}

# Parse CLI flags into the config globals. See usage() for the supported flags.
parse_input() {
    while [ ${#} -gt 0 ]; do
        case ${1} in
            --range)
                # Block range to validate; see usage for accepted values
                require_value "${1}" "${2:-}"
                RANGE="${2}"
                case "${RANGE}" in
                    test|pre-nakamoto|nakamoto|full) ;;
                    *)
                        if ! [[ "${RANGE}" =~ ^[0-9]+[:+][0-9]+$ ]]; then
                            error "Invalid argument: ${1}"
                            usage
                            exit 1
                        fi
                        ;;
                esac
                shift
                ;;
            --network)
                # Required if not mainnet
                require_value "${1}" "${2:-}"
                NETWORK=${2}
                shift
                ;;
            --rev)
                # Build from a specific git revision (branch, tag, or commit SHA)
                require_value "${1}" "${2:-}"
                REPO_REV=${2}
                shift
                ;;
            --repo)
                # stacks-core repo source: known label, git URL, or existing local path.
                require_value "${1}" "${2:-}"
                REPO="${2}"
                shift
                ;;
            --chaindir)
                # Use a local chainstate
                require_value "${1}" "${2:-}"
                CHAIN_DIR="${2}"
                shift
                ;;
            --proc)
                # Cores to use for validation
                require_value "${1}" "${2:-}"
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    error "arg ($2) is not a number."
                    exit 1
                fi
                CORES=${2}
                shift
                ;;
            --workdir)
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
                error "Invalid argument: ${1}"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

# SIGINT (Ctrl+C) handler: ask the user to confirm before actually quitting.
# Reads from /dev/tty so the prompt works when stdin is piped/redirected.
# Note: this is a best-effort safety net against accidental Ctrl+C. Because
# the script runs under `set -e`, answering "no" only reliably resumes
# execution if the interrupted command's failure is tolerated (see the
# `sleep 1 || true` guards in check_progress).
confirm_abort() {
    # Ignore further SIGINTs while prompting to avoid re-entering the handler
    trap '' INT
    printf '\n%s [y/N] ' "$(yellow 'Ctrl+C detected. Really abort?')" > /dev/tty
    local reply=""
    IFS= read -r reply < /dev/tty || true
    case "${reply}" in
        y|Y|yes|YES)
            eprintln "$(red "Aborting.")"
            exit 130
            ;;
        *)
            eprintln "$(green "Continuing.")"
            trap 'confirm_abort' INT
            ;;
    esac
}

# Print a "<label> started" timestamp line on stderr and return the start epoch on stdout.
# Usage: local foo_start=$(phase_start "Foo")
phase_start() {
    local label=$1
    info "$(highlight "${label}") started"
    timer_start
}

# Print a "<label> finished" timestamp line with elapsed HHhMMmSSs since start_epoch.
# Usage: phase_end "Foo" "${foo_start}"
phase_end() {
    local label=$1
    local start_epoch=$2
    local duration=$(format_hms "$(timer_elapsed "${start_epoch}")")
    info "$(highlight "${label}") finished (duration: $(highlight "${duration}"))"
}

# Entry point
main() {
    # Env preparation
    pre_input_config
    parse_input "$@"
    post_input_config
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
    # Note:
    # - Not all parts of the script support safe Ctrl+C interruption.
    # - Validation is the longest-running phase and therefore the primary focus for interruption handling.
    # - At present, only the validation progress display is safely interruptible.
    ${IS_TTY} && trap 'confirm_abort' INT
    local val_start=$(phase_start "Validation")
    run_validation
    store_results
    phase_end "Validation" "${val_start}"
}

# Run only when executed directly, not when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
