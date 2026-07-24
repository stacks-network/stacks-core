#!/bin/bash
set -Eeuo pipefail
shopt -s extglob   # enable extended globs (used by strip_ansi)

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
#   ${WORK_DIR}/logs/<timestamp>/              per-run logs: slice*.log + slice*.progress per slice, results.log, run.log (plain-text info/warn/error log), and status.json (machine-readable run status)
#   ${WORK_DIR}/logs/latest                    symlink to the current run's <timestamp> log dir (for external pollers)
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
# Console output is written to stderr so stdout can remain for function results.
#
# eprintln/eprint just print to the console. info/warn/error are the log functions:
# they print to the console AND, once setup_logs has set LOG_FILE, also append a
# plain (ANSI-stripped) copy of each line to the run log.
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

# Echo $1 with ANSI SGR / clear-line escapes removed (needs extglob).
strip_ansi() { printf '%s' "${1//$'\e'\[*([0-9;])[mK]/}"; }

_log() {
    local prefix=$1 fmt=$2
    shift 2
    local ts msg
    ts="$(date +%Y-%m-%dT%H:%M:%S%z)"
    printf -v msg "[%s][%s] ${fmt}" "${prefix}" "${ts}" "$@"
    printf '%s\n' "${msg}" >&2
    # Mirror to the run log (plain text) if LOG_FILE is set-up.
    # A log-file write failure must not abort the run.
    if [ -n "${LOG_FILE:-}" ]; then
        printf '%s\n' "$(strip_ansi "${msg}")" >> "${LOG_FILE}" || true
    fi
}

info()  { _log "$(blue    'INFO')" "$@"; }
warn()  { _log "$(yellow  'WARN')" "$@"; }
error() { _log "$(red     'ERRO')" "$@"; }

# Log an error and abort (exit 1).
# Also records the plain-text message in `LAST_ERROR`.
error_and_exit() {
    error "$@"
    printf -v LAST_ERROR "$@"
    LAST_ERROR="$(strip_ansi "${LAST_ERROR}")"
    exit 1
}

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
    PR=""                                      # optional pull request to validate: number (repo-relative) or full PR URL
    GH_TOKEN="${GH_TOKEN:-}"                    # optional token for authenticated PR fetches (env-provided value is preserved)
    CORES=""                                   # cores to use for validation; resolved in post_input_config
    NETWORK="mainnet"                          # network to validate
    RANGE="full"                               # block range to validate: scenario or numeric range
    LAST_ERROR=""                              # last error_and_exit message; surfaced by on_exit in status.json

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
    STATUS_FILE="${LOG_DIR}/status.json"              # machine-readable run status (see status_write)

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
        error_and_exit "cores (${CORES}) must be at least 1"
    fi

    # Resolve --repo (label / git URL / local path) into REPO_URL, REPO_DIR, and TRACK_REV.
    resolve_repo "${REPO}"

    # Resolve --pr (number or URL) into PR_NUMBER; a URL re-resolves REPO from itself.
    resolve_pr "${PR}"

    # Internal configurations
    SLICE_DIR="${SCRATCH_DIR}/slice"                  # location of slice dirs
    TMUX_SESSION="validation"                         # tmux session name to run the validation

    # status metadata (see status_write). They are filled in as they become known:
    #   - repo  : REPO_URL, or "LOCAL" when --repo is a local path (no URL)
    #   - ref   : the pr or rev requested
    #   - commit: the resolved HEAD (set after checkout in build_stacks_inspect)
    #   - range : left empty until the numeric block bounds are resolved
    #             (set per phase in validate_block_range)
    STATUS_REPO="${REPO_URL:-LOCAL}"
    if [ -n "${PR_NUMBER}" ]; then
        STATUS_REF="PR #${PR_NUMBER}"
    else
        STATUS_REF="${REPO_REV}"
    fi
    STATUS_COMMIT=""
    STATUS_RANGE=""
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
        # Derive REPO_DIR as <repo>, appending -<owner> for third-party forks, e.g.
        # https://github.com/hello-stacks/stacks-core.git -> stacks-core-hello-stacks
        # Owners stx-labs / stacks-network are treated as canonical and not appended.
        local path="${arg%.git}"        # strip trailing .git
        local repo="${path##*/}"        # last path component = repo name
        local rest="${path%/*}"         # drop the repo name
        local owner="${rest##*[/:]}"    # component after the last / or : = owner
        case "${owner}" in
            stx-labs|stacks-network) REPO_DIR="${WORK_DIR}/${repo}" ;;
            *)                       REPO_DIR="${WORK_DIR}/${repo}-${owner}" ;;
        esac
        TRACK_REV=1
    # Existing local directory
    elif [ -d "${arg}" ]; then
        REPO_URL=""
        REPO_DIR="${arg}"
        TRACK_REV=0
    else
        error_and_exit "--repo '${arg}' is not a known label, a git URL, or an existing directory"
    fi
}

# Resolve the --pr argument into PR_NUMBER. Accepts:
#   - a number   : PR relative to the already-resolved --repo
#   - a PR URL    : https://<host>/<owner>/<repo>/pull/<n> — derives the repo and
#                  re-resolves REPO_URL/REPO_DIR from it (so --repo becomes optional)
# Sets PR_NUMBER="" when --pr is not given. A PR fetch needs a remote, so --pr is
# rejected when --repo resolved to a local path (TRACK_REV=0).
resolve_pr() {
    local arg=$1
    # No pr given: nothing todo.
    if [ -z "${arg}" ]; then
        PR_NUMBER=""
        return 0
    fi

    if [[ "${arg}" =~ ^[0-9]+$ ]]; then
        # from the initial `resolve_repo` invocation, in `post_input_config`.
        if [ "${TRACK_REV}" -eq 0 ]; then
            error_and_exit "--pr <number> requires --repo not to be a local path"
        fi

        # Bare number: relative to the repo resolved from --repo.
        PR_NUMBER="${arg}"
    elif [[ "${arg}" =~ ^https?://([^/]+)/([^/]+)/([^/]+)/pull/([0-9]+) ]]; then
        # Full PR URL: derive host/owner/repo/number and re-resolve the repo.
        local host="${BASH_REMATCH[1]}"
        local owner="${BASH_REMATCH[2]}"
        local repo="${BASH_REMATCH[3]}"
        PR_NUMBER="${BASH_REMATCH[4]}"
        REPO="https://${host}/${owner}/${repo}.git"
        info "Derived repo from PR URL: $(highlight "${REPO}") (PR #${PR_NUMBER})"
        resolve_repo "${REPO}"
    else
        error_and_exit "--pr '${arg}' is not a number or a valid PR URL (https://<host>/<owner>/<repo>/pull/<n>)"
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
          $(cyan "<label>") - known shortcut. Choices: $(cyan "stacks-core"), $(cyan "stacks-core-p") ($(yellow "--rev") is applied).
          $(cyan "<url>")   - a valid git URL (--rev is applied).
          $(cyan "<path>")  - existing local repository, used as-is ($(yellow "--rev") is ignored).
        Default: $(cyan "stacks-core")
    $(yellow "--rev <branch>|<tag>|<sha>")
        git revision to build.
        Branches are pulled to the latest; tags/commits land on detached HEAD.
        Default: $(cyan "develop")
    $(yellow "--pr <number>|<url>")
        Validate a pull request. Fetches $(cyan "refs/pull/<n>/head").
          $(cyan "<number>") - PR number, relative to $(yellow "--repo") ($(yellow "--rev") is ignored).
          $(cyan "<url>")    - full PR URL, e.g. $(cyan "https://github.com/owner/repo/pull/123"); ($(yellow "--repo") and $(yellow "--rev") are ignored).
        Default: $(cyan "[NONE]")
    $(yellow "--ghtoken <token>")
        Token for authenticated git network operations (e.g. private repos). Sent as an HTTP auth
        header on the $(yellow "--pr") fetch only. Alternatively $(cyan "GH_TOKEN") env var can be used, 
        which keeps the token out of the process list.
        Default: $(cyan "\$GH_TOKEN")
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
            error_and_exit "installing Rust"
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
            error_and_exit "checking out branch ${REPO_REV}"
        }
    elif git rev-parse --verify --quiet "${REPO_REV}^{commit}" >/dev/null; then
        # Tag or commit SHA (short/full): detach HEAD at the resolved commit.
        eprintln "Checking out $(highlight "${REPO_REV}") (detached HEAD — tag or commit)"
        git checkout --detach "${REPO_REV}" || {
            error_and_exit "checking out ${REPO_REV}"
        }
    else
        error_and_exit "revision '${REPO_REV}' not found in ${REPO_DIR} (not a branch, tag, or known commit)"
    fi
}

# When GH_TOKEN is set and REPO_URL is an https URL, publish a host-scoped
# Authorization header via git's native env config (GIT_CONFIG_*). Every git
# network op that follows (clone, update-fetch, PR fetch) then authenticates,
# while scoping to REPO_URL's host keeps cargo's fetches to other hosts from
# ever seeing the token. The token never appears in a URL, in .git/config, in
# the process argv (ps), or in the logs. The exported vars live only in this
# script process and its children, so nothing leaks back to the caller.
setup_git_auth() {
    [ -n "${GH_TOKEN}" ] && [[ "${REPO_URL}" =~ ^https:// ]] || return 0
    local base="${REPO_URL#https://}"; base="https://${base%%/*}/"   # https://host/
    local b64
    b64=$(printf '%s' "x-access-token:${GH_TOKEN}" | base64 | tr -d '\n')
    export GIT_CONFIG_COUNT=1
    export GIT_CONFIG_KEY_0="http.${base}.extraheader"
    export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic ${b64}"
    info "Enabled token authentication for git operations on $(highlight "${base}")"
}

# Fetch a pull request's head commit into REPO_DIR and detach onto it.
# Fetches refs/pull/${PR_NUMBER}/head from REPO_URL — that ref lives in the base
# repo, so fork PRs work without cloning the fork or knowing its branch.
# Always re-fetches (a PR head moves as the contributor pushes). Authentication,
# if any, is inherited from the environment (see setup_git_auth).
fetch_pull_request() {
    local pull_ref="refs/pull/${PR_NUMBER}/head"
    if [ -d "${REPO_DIR}/.git" ]; then
        info "Fetching PR #$(highlight "${PR_NUMBER}") into existing $(highlight "${REPO_DIR}")"
        cd "${REPO_DIR}"
    else
        info "Initializing $(highlight "${REPO_DIR}") for PR #$(highlight "${PR_NUMBER}") fetch"
        mkdir -p "${REPO_DIR}"
        cd "${REPO_DIR}"
        git init -q || {
            error_and_exit "initializing git repo in ${REPO_DIR}"
        }
    fi
    info "Fetching $(highlight "${pull_ref}") from $(highlight "${REPO_URL}")"
    git fetch --depth 1 "${REPO_URL}" "${pull_ref}" || {
        error_and_exit "fetching ${pull_ref} from ${REPO_URL}"
    }
    git checkout -q --detach FETCH_HEAD || {
        error_and_exit "checking out FETCH_HEAD for PR #${PR_NUMBER}"
    }
}

# Build release stacks-inspect binary.
# When TRACK_REV=1 (default): clone if missing, otherwise check out ${REPO_REV}.
#   When --pr is set: fetch the PR head commit instead (overrides ${REPO_REV}).
# When TRACK_REV=0 (set by --repo <path>): treat REPO_DIR as a pre-existing checkout.
build_stacks_inspect() {
    status_write "${STATUS_STATE_ONGOING}" "Fetching stacks-inspect"
    
    if [ "${TRACK_REV}" -eq 0 ]; then # local path mode
        if [ ! -d "${REPO_DIR}" ]; then
            error_and_exit "repo dir not found: ${REPO_DIR}"
        fi
        info "Using existing checkout at $(highlight "${REPO_DIR}") as-is (rev tracking disabled)"
    else # git mode 
        # Publish token auth (if any) so every git network op below authenticates.
        setup_git_auth

        if [ -n "${PR_NUMBER}" ]; then
            # PR mode: fetch refs/pull/<n>/head (overrides --rev).
            fetch_pull_request
        elif [ -d "${REPO_DIR}" ]; then
            info "Found $(highlight "${REPO_DIR}"). Updating to $(highlight "${REPO_REV}")"
            cd "${REPO_DIR}"
            # Stash local changes so checkout is clean; --tags pulls in new tags too.
            git stash --include-untracked
            git fetch --tags --prune origin || {
                error_and_exit "fetching from origin"
            }
            checkout_rev
        else
            # Full clone (no --branch, since it rejects bare SHAs); resolve REPO_REV afterwards.
            info "Cloning $(highlight "${REPO_URL}") into $(highlight "${REPO_DIR}")"
            git clone "${REPO_URL}" "${REPO_DIR}" || {
                error_and_exit "cloning ${REPO_URL} into ${REPO_DIR}"
            }
            cd "${REPO_DIR}"
            checkout_rev
        fi

        # Record the resolved HEAD (used in status.json).
        STATUS_COMMIT="$(git -C "${REPO_DIR}" rev-parse HEAD)" || {
            error_and_exit "resolving HEAD commit in ${REPO_DIR}"
        }
    fi 
    
    # Build stacks-inspect to: ${REPO_DIR}/target/release/stacks-inspect
    status_write "${STATUS_STATE_ONGOING}" "Building stacks-inspect"
    info "Building stacks-inspect binary"
    cd "${REPO_DIR}/contrib/stacks-inspect" && cargo build --bin=stacks-inspect --release || {
        error_and_exit "building stacks-inspect binary"
    }
    info "Done building. continuing"
}

# Resolve chain dir: use the user-provided path if set, otherwise reuse
# ${WORK_DIR}/chain if present, or download+extract the Hiro snapshot for ${NETWORK}.
configure_chainstate() {
    status_write "${STATUS_STATE_ONGOING}" "Preparing chainstate"

    if [[ -n "${CHAIN_DIR}" ]]; then
        if [ ! -d "${CHAIN_DIR}" ]; then
            error_and_exit "Chainstate not found: ${CHAIN_DIR}"
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
                error_and_exit "downloading latest ${NETWORK} chainstate archive"
            }
        fi

        # Extract downloaded archive
        mkdir -p "${CHAIN_DIR}"
        info "Extracting downloaded archive: $(highlight "${archive_path}")"
        if [ ! -f "${archive_path}" ]; then
            error_and_exit "${archive_path} not found"
        fi
        tar --strip-components=1 --zstd -xvf "${archive_path}" -C "${CHAIN_DIR}" || {
            error_and_exit "extracting ${NETWORK} chainstate archive"
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
    status_write "${STATUS_STATE_ONGOING}" "Preparing chainstate slices"

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
        error_and_exit "chainstate file not found: ${chainstate_sentinel}"
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
    rm -f "${reflink_probe_dst}"

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
        error_and_exit "deleting dir contents: ${SCRATCH_DIR}"
    }
    info "Creating scratch and slice dirs"
    mkdir -p "${SLICE_DIR}0" || {
        error_and_exit "creating dir ${SLICE_DIR}0"
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
            cp -r "${CHAIN_DIR}/burnchain"     "${SLICE_DIR}0/"           || error_and_exit "copying burnchain"
            cp -r "${CHAIN_DIR}/chainstate/vm" "${SLICE_DIR}0/chainstate/" || error_and_exit "copying chainstate/vm"
            # nakamoto.sqlite{,-wal,-shm} — glob covers all three; -shm is recreated by SQLite if missing.
            if ! compgen -G "${CHAIN_DIR}/chainstate/blocks/nakamoto.sqlite*" >/dev/null; then
                error_and_exit "nakamoto.sqlite not found in ${CHAIN_DIR}/chainstate/blocks (chainstate too old for naka-only run?)"
            fi
            cp "${CHAIN_DIR}"/chainstate/blocks/nakamoto.sqlite* "${SLICE_DIR}0/chainstate/blocks/" || {
                error_and_exit "copying nakamoto.sqlite"
            }
        else
            info "Copying ${CHAIN_DIR} -> $(highlight "${SLICE_DIR}0")"
            cp -r "${CHAIN_DIR}"/* "${SLICE_DIR}0"
        fi

        info "Moving marf database: ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs -> $(highlight "${SCRATCH_DIR}/marf.sqlite.blobs")"
        mv "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs "${SCRATCH_DIR}"/ || {
            error_and_exit "moving marf database"
        }
        info "Symlinking marf database: ${SCRATCH_DIR}/marf.sqlite.blobs -> $(highlight "${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs")"
        ln -s "${SCRATCH_DIR}"/marf.sqlite.blobs "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs || {
            error_and_exit "creating symlink: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs"
        }
    fi

    # Sanity check that the chainstate db exists in slice0 before copying
    if [ ! -f "${SLICE_DIR}0/chainstate/vm/index.sqlite" ]; then
        error_and_exit "chainstate db not found (${SLICE_DIR}0/chainstate/vm/index.sqlite)"
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
            error_and_exit "copying ${SLICE_DIR}0 -> ${SLICE_DIR}${i}"
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

# Create this run's log dir and point the log helpers at run.log.
#
# Setting LOG_FILE switches info/warn/error into dual-write mode: each line is printed
# to the console (colored when IS_TTY) and a plain, ANSI-stripped copy is appended to
# run.log (see the logging helpers). eprintln/eprint stay console-only, so banners and
# the live progress spinner never reach the file, keeping run.log clean and greppable.
setup_logs() {
    mkdir -p "${LOG_DIR}" || {
        error_and_exit "creating logs dir ${LOG_DIR}"
    }
    LOG_FILE="${LOG_DIR}/run.log"
    info "Logging to $(highlight "${LOG_FILE}")"
    # Point logs/latest at this run so external pollers (e.g. the triage GitHub
    # App) can find status.json without knowing the timestamp; then publish the
    # initial status.
    ln -sfn "${LOG_DIR}" "$(dirname "${LOG_DIR}")/latest" || {
        error_and_exit "creating logs/latest symlink for ${LOG_DIR}"
    }
}

# ------------------------------------------------------------------------
# Run status file (status.json)
#
# The set of values the status "state" field can take. Defined as constants so
# call sites and any external consumer share one source of truth.
declare -r STATUS_STATE_ONGOING="ONGOING"   # validation is in progress (preparing/validating)
declare -r STATUS_STATE_SUCCESS="SUCCESS"   # validation completed with success
declare -r STATUS_STATE_FAILURE="FAILURE"   # validation completed with failures
declare -r STATUS_STATE_ERROR="ERROR"       # unexpected abort (see LAST_ERROR / run.log)
#
# A tiny machine-readable status document maintained alongside the logs so
# external tooling can poll a run to completion without parsing run.log. It is
# written atomically (tmp + mv) so a reader never sees a half-written file.
#
#   { "state": <s>, "message": <str>,
#     "repo": <url|LOCAL>, "commit": <sha>, "ref": <str>, "range": <str>,
#     "started_at": <iso8601 UTC>, "updated_at": <iso8601 UTC> }
#
#   state    ONGOING (preparing/validating) | SUCCESS | FAILURE (validation
#            failed; per-block detail in results.log) | ERROR (unexpected abort)
#   message  human-readable current activity
#   range    empty until the numeric block bounds are resolved
#
# status_write <state> <message>
# Builds the JSON with jq (guaranteed valid + correctly escaped) and swaps it in
# atomically. started_at is stamped once on the first write. Timestamps are UTC
# (Zulu, e.g. 2026-07-21T15:46:20Z). 
# The run metadata (repo/commit/ref/range) is read from the
# STATUS_* globals, which are populated as they become known.
status_write() {
    local state=$1 message=$2
    : "${STATUS_STARTED_AT:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
    local tmp="${STATUS_FILE}.tmp"
    jq -n \
        --arg     state      "${state}" \
        --arg     message    "${message}" \
        --arg     repo       "${STATUS_REPO:-}" \
        --arg     commit     "${STATUS_COMMIT:-}" \
        --arg     ref        "${STATUS_REF:-}" \
        --arg     range      "${STATUS_RANGE:-}" \
        --arg     started_at "${STATUS_STARTED_AT}" \
        --arg     updated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{state: $state, message: $message, repo: $repo, commit: $commit, ref: $ref, range: $range, started_at: $started_at, updated_at: $updated_at}' \
        > "${tmp}" || {
        error_and_exit "writing status file ${tmp}"
    }
    mv -f "${tmp}" "${STATUS_FILE}" || {
        error_and_exit "updating status file ${STATUS_FILE}"
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
        error_and_exit "creating tmux session $(highlight "${TMUX_SESSION}")"
    }

    local i
    for ((i=1; i<CORES; i++)); do
        tmux new-window -t "${TMUX_SESSION}" -d -n "slice${i}" || {
            error_and_exit "creating tmux window $(highlight "slice${i}")"
        }
    done
    return 0
}

# Query stacks-inspect for the total number of blocks in the given epoch and
# store it in the caller-named variable <out_var>.
# Args: <mode> (pre-nakamoto | nakamoto)  <out_var>
#
# The result is returned by assignment, not on stdout, so callers invoke it
# directly (not in $(...)). That keeps a failing error_and_exit in the caller's
# shell.
#
# Always reads from CHAIN_DIR (the canonical chainstate) so callers don't need
# slices to exist, and so the answer is consistent whether called during slice
# prep or while workers are running.
get_total_blocks() {
    local mode=$1 out_var=$2
    local range_command
    case "$mode" in
        nakamoto)     range_command="naka-index-range" ;;
        pre-nakamoto) range_command="index-range" ;;
        *)
            error_and_exit "get_total_blocks: invalid mode '${mode}'"
            ;;
    esac
    local inspect_bin="${REPO_DIR}/target/release/stacks-inspect"
    local inspect_config="${REPO_DIR}/sample/conf/${NETWORK}-follower-conf.toml"
    # Capture stderr to a file so the real stacks-inspect error
    # (e.g. a chainstate permission/DB error) is preserved for post-mortem.
    local count_output errfile="${LOG_DIR}/inspect-${mode}.err"
    if ! count_output=$("${inspect_bin}" --config "${inspect_config}" validate-block "${CHAIN_DIR}" "${range_command}" 2>"${errfile}"); then
        error_and_exit "retrieving total ${mode} blocks from chainstate (see ${errfile})"
    fi
    # Drop the error file if the command succeeded, so we don't leave stale files around.
    rm -f "${errfile}"

    local total
    total=$(printf '%s\n' "${count_output}" | awk -F " " '{print $NF}')
    if [ -z "${total}" ]; then
        error_and_exit "parsing block count for ${mode}"
    fi
    printf -v "${out_var}" '%s' "${total}"
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
            get_total_blocks pre-nakamoto pre_total
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
            error_and_exit "validate_block_range: invalid mode '${mode}'"
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
            get_total_blocks pre-nakamoto pre_total
            get_total_blocks nakamoto naka_total
            local epoch_min=${pre_total}
            local epoch_max=$((pre_total + naka_total - 1))
            if [ "${global_start}" -lt "${epoch_min}" ] || [ "${global_end}" -gt "${epoch_max}" ]; then
                error_and_exit "nakamoto range ${global_start}-${global_end} is outside the available epoch (${epoch_min}-${epoch_max})"
            fi
            starting_block=$((global_start - pre_total))
            total_blocks=$((global_end - pre_total + 1))
            ;;
        pre-nakamoto)
            local pre_total
            get_total_blocks pre-nakamoto pre_total
            local epoch_max=$((pre_total - 1))
            if [ "${global_start}" -lt 0 ] || [ "${global_end}" -gt "${epoch_max}" ]; then
                error_and_exit "pre-nakamoto range ${global_start}-${global_end} is outside the available epoch (0-${epoch_max})"
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
    info "************************************************************************"
    info "Mode: $(highlight "${mode}")"
    info "Block range: $(highlight "${global_start}-${global_end}") (${block_diff} blocks)"
    info "Slices: $(highlight "${slices}") | Blocks/slice: $(highlight "${slice_blocks}")"
    
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
        info "  $(highlight "${TMUX_SESSION}:slice${slice_counter}") :: Blocks: $(highlight "${global_slice_start}-${global_slice_end}") :: Logs: ${log_file}"
        echo "Command: ${inspect_cmd}" > "${log_file}"
        echo "Validating blocks: ${global_slice_start}-${global_slice_end} (out of ${global_end})" >> "${log_file}"
        echo "Progress updates will be written to: ${progress_file}" >> "${log_file}"
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "${cmd}" Enter || {
            error_and_exit "sending stacks-inspect command to tmux window $(highlight "slice${slice_counter}")"
        }
        # PIPESTATUS[0] is still stacks-inspect (first pipeline stage), so the
        # return-code capture continues to work unchanged.
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "echo \${PIPESTATUS[0]} >> ${log_file}" Enter || {
            error_and_exit "sending return status command to tmux window $(highlight "slice${slice_counter}")"
        }
        slice_counter=$((slice_counter + 1))
    done
    check_progress "${mode}" "${slice_progress_files[@]}"
    info "************************************************************************"
    phase_end "${range_label}" "${range_start}"
}

# Translate the user-facing RANGE scenario into inclusive global block ranges,
# then hand each range to validate_block_range. This function deals only in the
# continuous global block space;
# Convention (mainnet example with pre_total=185630):
#   pre-naka : globals 0..185629    (inclusive, pre_total blocks)
#   naka     : globals 185630..N    (inclusive, naka_total blocks)
run_validation() {
    status_write "${STATUS_STATE_ONGOING}" "Starting block validation"

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

            STATUS_RANGE="test"
            info "$(bold_yellow "Validating in test mode")"
            validate_block_range pre-nakamoto "${pre_start}" "${pre_end}"
            validate_block_range nakamoto "${naka_start}" "${naka_end}"
            ;;
        pre-nakamoto)
            local pre_total
            get_total_blocks pre-nakamoto pre_total
            STATUS_RANGE="0 - $((pre_total - 1))"
            validate_block_range pre-nakamoto 0 $((pre_total - 1))
            ;;
        nakamoto)
            local pre_total naka_total
            get_total_blocks pre-nakamoto pre_total
            get_total_blocks nakamoto naka_total
            STATUS_RANGE="${pre_total} - $((pre_total + naka_total - 1))"
            validate_block_range nakamoto "${pre_total}" $((pre_total + naka_total - 1))
            ;;
        full)
            local pre_total naka_total
            get_total_blocks pre-nakamoto pre_total
            get_total_blocks nakamoto naka_total
            STATUS_RANGE="0 - $((pre_total + naka_total - 1))"
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
                    error_and_exit "Invalid range: start (${start}) > end (${end})"
                fi
            elif [[ "${RANGE}" =~ ^([0-9]+)[+]([0-9]+)$ ]]; then
                # <start>+<count>  -- N blocks starting at start (count must be > 0)
                start=${BASH_REMATCH[1]}
                local count=${BASH_REMATCH[2]}
                if [ "${count}" -lt 1 ]; then
                    error_and_exit "Invalid count: must be at least 1 (got ${count})"
                fi
                end=$((start + count - 1))
            else
                error_and_exit "Invalid --range value: '${RANGE}'"
            fi
            
            STATUS_RANGE="${start} - ${end}"
            local pre_total
            get_total_blocks pre-nakamoto pre_total
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
    local phase_label=$1
    shift
    local slice_progress=("$@")
    local progress=1
    local symbols="/-\|"
    local count pct spinner elapsed
    local last_pct=""   # last % published to status.json (throttles rewrites)
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

    eprintln
    eprintln "Checking Block Validation status"
    eprintln
    while true; do
        count=$(pgrep -c "stacks-inspect" || true)
        elapsed=$(timer_elapsed "${timer}")
        if [ "${count}" -gt 0 ]; then
            pct=$(compute_progress_pct "${slice_progress[@]}")
            # Publish to status.json only when the pct changes, to avoid rewriting
            # the file every second.
            if [ "${pct}" != "${last_pct}" ]; then
                last_pct="${pct}"
                status_write "${STATUS_STATE_ONGOING}" "Validating ${phase_label} blocks ${pct}"
            fi
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
}

# Aggregate the run outcome into ${LOG_DIR}/:
#   - failed_blocks.txt : every "Block <hash>: Failed to validate …" entry from
#                         slices that ended with return code 1 (leading indent
#                         stripped) — a clean list, one line per failed block, so
#                         its line count is the failed-block count and it can be
#                         dropped straight into a PR comment.
#   - results.log       : a "Failed blocks: N (panicked slices: M)" summary header
#                         plus one "sliceN.log return code: X" line per slice.
# Sets the terminal status.json state: SUCCESS only when no block failed and no
# slice panicked; otherwise FAILURE (with the failed-block count).
store_results() {
    local results="${LOG_DIR}/results.log"
    local failed_blocks="${LOG_DIR}/failed_blocks.txt"
    local panicked=0        # slices that crashed (return code neither 0 nor 1)
    local return_code
    cd "${LOG_DIR}" || error_and_exit "Logdir $(highlight "${LOG_DIR}") doesn't exist"

    : > "${failed_blocks}"  # start clean; stays empty when nothing failed

    # One pass over the slice logs: record each slice's return code, and collect
    # the failed-block entries from slices that reported block failures (rc 1).
    for file in $(find . -name "slice*.log" -printf '%P\n' | sort); do
        info "Checking file: $(highlight "$file")"
        return_code=$(tail -1 "${file}")
        case ${return_code} in
            0)
                echo "${file} return code: ${return_code}" >> "${results}"
                ;;
            1)
                echo "${file} return code: ${return_code}" >> "${results}"
                # stacks-inspect lists each failure as an indented "  Block ..." line. 
                # Take just those, stripping the leading indent, and append to the global failed-blocks list.
                grep -E '^[[:space:]]*Block ' "${file}" | sed 's/^[[:space:]]*//' >> "${failed_blocks}" || true
                ;;
            *)
                panicked=$((panicked + 1))
                echo "${file} return code: ${return_code} (likely panic)" >> "${results}"
                ;;
        esac
    done

    local block_failures
    block_failures=$(wc -l < "${failed_blocks}" | tr -d '[:space:]')

    sed -i "1i Failed blocks: ${block_failures} (panicked slices: ${panicked})" "${results}"
    info "Results: $(highlight "${results}")"

    if [ "${block_failures}" -eq 0 ] && [ "${panicked}" -eq 0 ]; then
        # No failurers, so clean up the failed-blocks file to avoid leaving a stale artifact around.
        rm -f "${failed_blocks}"
        info "$(bold_green "Block Validation successful!")"
        status_write "${STATUS_STATE_SUCCESS}" "Block validation successful"
    else
        error "Block validation failed: ${block_failures} block(s), ${panicked} panicked slice(s) (see $(highlight "${failed_blocks}")"
        status_write "${STATUS_STATE_FAILURE}" "Block validation failed: ${block_failures} failed block(s), ${panicked} panicked slice(s)"
    fi
}

# Check and install missing dependencies
check_dependencies() {
    local has_apt=1
    local has_sudo=1
    local cmd rp package find_path
    local -a required=(
        apt-get sudo curl tmux git aria2c tar zstd grep cc cargo pgrep tput
        find xargs awk sed nproc stat stdbuf jq base64
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
                    error_and_exit "Busybox 'find' is not supported. Please install 'findutils' or similar."
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
                "cc")
                    # Rust uses the C compiler as its linker, and crates like
                    # `libc`/`proc-macro2` build native code; `build-essential`
                    # provides `cc` (via gcc), `make`, and the C headers.
                    package="build-essential"
                    ;;
                "cargo")
                    install_cargo
                    continue
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
                "nproc"|"stat"|"stdbuf"|"base64")
                    package="coreutils"
                    ;;
                *)
                    package="${cmd}"
                    ;;
            esac

            if [[ ${has_apt} = 0 ]] || [[ ${has_sudo} = 0 ]]; then
                error_and_exit "Missing command '${cmd}'"
            fi
            (sudo apt-get update && sudo apt-get install -y "${package}") || {
                error_and_exit "installing $package"
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
                        # <start>:<end>, <start>+<count>, or a bare <start>
                        if ! [[ "${RANGE}" =~ ^[0-9]+([:+][0-9]+)?$ ]]; then
                            error "Invalid value for: ${1}"
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
            --pr)
                # Validate a pull request: a number (repo-relative) or a full PR URL.
                require_value "${1}" "${2:-}"
                PR="${2}"
                shift
                ;;
            --ghtoken)
                # Token for authenticated git network ops. 
                require_value "${1}" "${2:-}"
                GH_TOKEN="${2}"
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
                    error_and_exit "arg ($2) is not a number."
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

# EXIT trap: runs on every exit — normal, an explicit `exit N`, or a `set -e`
# abort, so it reports *all* failure paths, not just unguarded ones.
on_exit() {
    local rc=$?
    cleanup_tmux
        
    if [ "${rc}" -ne 0 ]; then
        status_write "${STATUS_STATE_ERROR}" "${LAST_ERROR:-Run aborted (exit ${rc}); see run.log}"
    fi
}

# SIGTERM trap: a stop request from a non-interactive launcher 
on_terminate() {
    error_and_exit "Validation stopped by request (SIGTERM)"
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
    setup_logs
    trap on_exit EXIT
    # A stop request from a non-interactive launcher arrives as SIGTERM; exit
    # cleanly so on_exit tears down workers and records a terminal status.
    trap on_terminate TERM

    # Validation preparation
    local prep_start=$(phase_start "Preparation")
    build_stacks_inspect
    configure_chainstate
    configure_validation_slices
    setup_tmux
    phase_end "Preparation" "${prep_start}"

    # Validation execution
    # Note:
    # - Not all parts of the script support safe Ctrl+C interruption.
    # - Validation is the longest-running phase and therefore the primary focus for interruption handling.
    # - At present, only the validation progress display is safely interruptible.
    ${IS_TTY} && trap confirm_abort INT
    local val_start=$(phase_start "Validation")
    run_validation
    store_results
    phase_end "Validation" "${val_start}"
}

# Run only when executed directly, not when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
