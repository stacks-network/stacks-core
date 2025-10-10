#!/bin/bash
set -o pipefail


## Using 10 cpu cores, a full validation will take between 12-14 hours (assuming there are no other cpu/io bound processes running at the same time)
##
## ** Recommend to run this script in screen or tmux **
##
## We'll need ~217GB per slice, plus an extra ~4500GB for the chainstate archive and marf DB
## as of 09/2025:
##   for 10 slices, this is about 2.5TB

NETWORK="mainnet"                               ## network to validate
REPO_DIR="$HOME/stacks-core"                    ## where to build the source
REMOTE_REPO="stacks-network/stacks-core"        ## remote git repo to build stacks-inspect from
SCRATCH_DIR="$HOME/scratch"                     ## root folder for the validation slices
TIMESTAMP=$(date +%Y-%m-%d-%s)                  ## use a simple date format year-month-day-epoch
LOG_DIR="$HOME/block-validation_${TIMESTAMP}"   ## location of logfiles for the validation
SLICE_DIR="${SCRATCH_DIR}/slice"                ## location of slice dirs
TMUX_SESSION="validation"                       ## tmux session name to run the validation
TERM_OUT=false                                  ## terminal friendly output
TESTING=false                                   ## only run a validation on a few thousand blocks
BRANCH="develop"                                ## default branch to build stacks-inspect from
CORES=$(grep -c processor /proc/cpuinfo)        ## retrieve total number of CORES on the system
RESERVED=8                                      ## reserve this many CORES for other processes as default
LOCAL_CHAINSTATE=                               ## path to local chainstate to use instead of snapshot download

## ansi color codes for terminal output
COLRED=$'\033[31m'    ## Red
COLGREEN=$'\033[32m'  ## Green
COLYELLOW=$'\033[33m' ## Yellow
COLCYAN=$'\033[36m'   ## Cyan
COLBOLD=$'\033[1m'    ## Bold Text
COLRESET=$'\033[0m'   ## reset color/formatting

## verify that cargo is installed in the expected path, not only $PATH
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

## build stacks-inspect binary from specified repo/branch
build_stacks_inspect() {
    if [ -d "${REPO_DIR}" ];then
        echo "Found ${COLYELLOW}${REPO_DIR}${COLRESET}. checking out ${COLGREEN}${BRANCH}${COLRESET} and resetting to ${COLBOLD}HEAD${COLRESET}"
        cd "${REPO_DIR}" && git fetch
        echo "Checking out ${BRANCH} and resetting to HEAD"
        git stash ## stash any local changes to prevent checking out $BRANCH
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
    ## build stacks-inspect to: ${REPO_DIR}/target/release/stacks-inspect
    echo "Building stacks-inspect binary"
    cd contrib/stacks-inspect && cargo build --bin=stacks-inspect --release || {
        echo "${COLRED}Error${COLRESET} building stacks-inspect binary"
        exit 1
    }
    echo "Done building. continuing"
}

## create the slice dirs from an chainstate archive (symlinking marf.sqlite.blobs), 1 dir per CPU
configure_validation_slices() {
    if [ -d "$HOME/scratch" ]; then
        echo "Deleting existing scratch dir: ${COLYELLOW}$HOME/scratch${COLRESET}"
        rm -rf "${HOME}/scratch" || {
            echo "${COLRED}Error${COLRESET} deleting dir $HOME/scratch"
            exit 1
        }
    fi
    echo "Creating scratch and slice dirs"
    (mkdir -p "${SLICE_DIR}0" && cd "${SCRATCH_DIR}") || {
        echo "${COLRED}Error${COLRESET} creating dir ${SLICE_DIR}"
        exit 1
    }

    if [[ -n "${LOCAL_CHAINSTATE}" ]]; then
       echo "Copying local chainstate '${LOCAL_CHAINSTATE}'"
       cp -r "${LOCAL_CHAINSTATE}"/* "${SLICE_DIR}0"
    else
       echo "Downloading latest ${NETWORK} chainstate archive ${COLYELLOW}https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.gz${COLRESET}"
       ## curl had some random issues retrying the download when network issues arose. wget has resumed more consistently, so we'll use that binary
       # curl -L --proto '=https' --tlsv1.2 https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.gz -o ${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.gz || {
       wget -O  "${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.gz" "https://archive.hiro.so/${NETWORK}/stacks-blockchain/${NETWORK}-stacks-blockchain-latest.tar.gz"  || {
           echo "${COLRED}Error${COLRESET} downlaoding latest ${NETWORK} chainstate archive"
           exit 1
       }
       ## extract downloaded archive
       echo "Extracting downloaded archive: ${COLYELLOW}${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.gz${COLRESET}"
       tar --strip-components=1 -xzf "${SCRATCH_DIR}/${NETWORK}-stacks-blockchain-latest.tar.gz" -C "${SLICE_DIR}0" || {
           echo "${COLRED}Error${COLRESET} extracting ${NETWORK} chainstate archive"
           exit
       }
    fi
    echo "Moving marf database: ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs -> ${COLYELLOW}${SCRATCH_DIR}/marf.sqlite.blobs${COLRESET}"
    mv "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs "${SCRATCH_DIR}"/
    echo "Symlinking marf database: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${COLYELLOW}${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs${COLRESET}"
    ln -s "${SCRATCH_DIR}"/marf.sqlite.blobs "${SLICE_DIR}"0/chainstate/vm/clarity/marf.sqlite.blobs || {
        echo "${COLRED}Error${COLRESET} creating symlink: ${SCRATCH_DIR}/marf.sqlite.blobs -> ${SLICE_DIR}0/chainstate/vm/clarity/marf.sqlite.blobs"
        exit 1
    }

    ## create a copy of the linked db with <number of CORES><number of RESERVED CORES>
    ##   decrement by 1 since we already have ${SLICE_DIR}0
    for ((i=1;i<=$(( CORES - RESERVED - 1));i++)); do
        echo "Copying ${SLICE_DIR}0 -> ${COLYELLOW}${SLICE_DIR}${i}${COLRESET}"
        cp -R "${SLICE_DIR}0" "${SLICE_DIR}${i}" || {
            echo "${COLRED}Error${COLRESET} copying ${SLICE_DIR}0 -> ${SLICE_DIR}${i}"
            exit 1
        }
    done
}

## setup the tmux sessions and create the logdir for storing output
setup_validation() {
    ## if there is an existing folder, rm it
    if [ -d "${LOG_DIR}" ];then
        echo "Removing logdir ${LOG_DIR}"
        rm -rf "${LOG_DIR}"
    fi
    ## create LOG_DIR to store output files
    if  [ ! -d "${LOG_DIR}" ]; then
        echo "Creating logdir ${LOG_DIR}"
        mkdir -p "${LOG_DIR}"
    fi
    ## if tmux session "${TMUX_SESSION}" exists, kill it and start anew
    if eval "tmux list-windows -t ${TMUX_SESSION} &> /dev/null"; then
        echo "Killing existing tmux session: ${TMUX_SESSION}"
        eval "tmux kill-session -t ${TMUX_SESSION}  &> /dev/null"
    fi
    local slice_counter=0

    ## create tmux session named ${TMUX_SESSION} with a window named slice0
    tmux new-session -d -s ${TMUX_SESSION} -n slice${slice_counter} || {
        echo "${COLRED}Error${COLRESET} creating tmux session ${COLYELLOW}${TMUX_SESSION}${COLRESET}"
        exit 1
    }

    if [ ! -f "${SLICE_DIR}0/chainstate/vm/index.sqlite" ]; then
        echo "${COLRED}Error${COLRESET}: chainstate db not found (${SLICE_DIR}0/chainstate/vm/index.sqlite)"
        exit 1
    fi
    return 0
}

## run the block validation
start_validation() {
    local mode=$1
    local total_blocks=0
    local starting_block=0
    local inspect_command
    local slice_counter=0
    case "$mode" in
        nakamoto)
            ## nakamoto blocks
            echo "Mode: ${COLYELLOW}${mode}${COLRESET}"
            local log_append="_${mode}"
            inspect_command="validate-naka-block"
            ## get the total number of nakamoto blocks in db
            total_blocks=$(echo "select count(*) from nakamoto_block_headers" | sqlite3 "${SLICE_DIR}"0/chainstate/vm/index.sqlite)
            starting_block=0 # for the block counter, start at this block
            ## use these values if `--testing` arg is provided (only validate 1_000 blocks)
            ${TESTING} && total_blocks=301883
            ${TESTING} && starting_block=300883
            ;;
        *)
            ## pre-nakamoto blocks
            echo "Mode: ${COLYELLOW}pre-nakamoto${COLRESET}"
            local log_append=""
            inspect_command="validate-block"
            ## get the total number of blocks (with orphans) in db
            total_blocks=$(echo "select count(*) from staging_blocks where orphaned = 0" | sqlite3 "${SLICE_DIR}"0/chainstate/vm/index.sqlite)
            starting_block=0 # for the block counter, start at this block
            ## use these values if `--testing` arg is provided (only validate 1_000 blocks) Note:  2.5 epoch is at 153106
            ${TESTING} && total_blocks=153000
            ${TESTING} && starting_block=152000
            ;;
    esac
    local block_diff=$((total_blocks - starting_block)) ## how many blocks are being validated
    local slices=$((CORES - RESERVED))                  ## how many validation slices to use
    local slice_blocks=$((block_diff / slices))         ## how many blocks to validate per slice
    ${TESTING} && echo "${COLRED}Testing: ${TESTING}${COLRESET}"
    echo "Total blocks: ${COLYELLOW}${total_blocks}${COLRESET}"
    echo "Starting Block: ${COLYELLOW}$starting_block${COLRESET}"
    echo "Block diff: ${COLYELLOW}$block_diff${COLRESET}"
    echo "******************************************************"
    echo "Total slices: ${COLYELLOW}${slices}${COLRESET}"
    echo "Blocks per slice: ${COLYELLOW}${slice_blocks}${COLRESET}"
    local end_block_count=$starting_block
    while [[ ${end_block_count} -lt ${total_blocks} ]]; do
        local start_block_count=$end_block_count
        end_block_count=$((end_block_count + slice_blocks))
        if [[ "${end_block_count}" -gt "${total_blocks}"  ]] ||  [[ "${slice_counter}" -eq $((slices - 1))  ]]; then
            end_block_count="${total_blocks}"
        fi
        if [ "${mode}" != "nakamoto" ]; then ## don't create the tmux windows if we're validating nakamoto blocks (they should already exist). TODO: check if it does exist in case the function call order changes
            if [ "${slice_counter}" -gt 0 ];then
                tmux new-window -t "${TMUX_SESSION}" -d -n "slice${slice_counter}" || {
                    echo "${COLRED}Error${COLRESET} creating tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
                    exit 1
                }
            fi
        fi
        local log_file="${LOG_DIR}/slice${slice_counter}${log_append}.log"
        local log=" | tee -a ${log_file}"
        local cmd="${REPO_DIR}/target/release/stacks-inspect --config ${REPO_DIR}/stackslib/conf/${NETWORK}-follower-conf.toml ${inspect_command}  ${SLICE_DIR}${slice_counter} index-range $start_block_count $end_block_count 2>/dev/null"
        echo "  Creating tmux window: ${COLGREEN}${TMUX_SESSION}:slice${slice_counter}${COLRESET} :: Blocks: ${COLYELLOW}${start_block_count}-${end_block_count}${COLRESET} || Logging to: ${log_file}"
        echo "Command: ${cmd}" > "${log_file}" ## log the command being run for the slice
        echo "Validating indexed blocks: ${start_block_count}-${end_block_count} (out of ${total_blocks})" >> "${log_file}"
        ## send `cmd` to the tmux window where the validation will run
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "${cmd}${log}" Enter || {
            echo "${COLRED}Error${COLRESET} sending stacks-inspect command to tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
            exit 1
        }
        ## log the return code as the last line
        tmux send-keys -t "${TMUX_SESSION}:slice${slice_counter}" "echo \${PIPESTATUS[0]} >> ${log_file}" Enter  || {
            echo "${COLRED}Error${COLRESET} sending return status command to tmux window ${COLYELLOW}slice${slice_counter}${COLRESET}"
            exit 1
        }
        slice_counter=$((slice_counter + 1))
    done
    check_progress
}


## pretty print the status output (simple spinner while pids are active)
check_progress() {
    # give the pids a few seconds to show up in process table before checking if they're running
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


## store the results in an aggregated logfile and an html file
store_results() {
    ## text file to store results
    local results="${LOG_DIR}/results.log"
    ## html file to store results
    local results_html="${LOG_DIR}/results.html"
    local failed=0;
    local return_code=0;
    local failure_count
    echo "Results: ${COLYELLOW}${results}${COLRESET}"
    cd "${LOG_DIR}" || {
        echo "${COLRED}Error${COLRESET} Logdir ${COLYELLOW}${LOG_DIR}${COLRESET} doesn't exist"
        exit 1
    }
    ## retrieve the count of all lines with `Failed processing block`
    failure_count=$(grep -rc "Failed processing block" slice*.log | awk -F: '$NF >= 0 {x+=$NF; $NF=""} END{print x}')
    if [ "${failure_count}" -gt 0 ]; then
        echo "Failures: ${COLRED}${failure_count}${COLRESET}"
    else
        echo "Failures: ${COLGREEN}${failure_count}${COLRESET}"
    fi
    echo "Failures: ${failure_count}" > "${results}"
    ## check the return codes to see if we had a panic
    for file in $(find . -name "slice*.log" -printf '%P\n' | sort); do
    # for file in $(ls  slice*.log | sort); do
        echo "Checking file: ${COLYELLOW}$file${COLRESET}"
        return_code=$(tail -1 "${file}")
        case ${return_code} in
            0)
                # block validation ran successfully
                ;;
            1)
                # block validation had some block failures
                failed=1
                ;;
            *)
                # return code likely indicates a panic
                failed=1
                echo "$file return code: $return_code" >> "${results}" # ok to continue if this write fails
                ;;
        esac
    done

    ## Store the results as HTML:
    cat <<- _EOF_ > "${results_html}"
    <body>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Source+Code+Pro:ital,wght@0,200..900;1,200..900&display=swap');
            .container {
                border: 1px outset black;
                padding: 5px;
                border-radius: 5px;
                background-color: #eae9e8;
            }
            .fail {
                background-color: #ffffff;
                border: 1px outset black;
                border-radius: 5px;
                font-weight: 350;
            }
            .pass {
                background-color: #eae9e8;
            }
            .result {
                text-align: left;
                padding-left: 10px;
                padding-top: 10px;
                padding-bottom: 10px;
                margin: 5px;
            }
            body {
                font-family: "Source Code Pro", monospace;
                font-optical-sizing: auto;
                font-style: normal;
            }
        </style>
        <h2>$(date -u)</h2>
        <hr/>
        <h2>Failures: ${failure_count}</h2>
        <div class="container">
_EOF_

    ## use the $failed var here in case there is a panic, then $failure_count may show zero, but the validation was not successful
    if [ ${failed} == "1" ];then
        output=$(grep -r -h "Failed processing block" slice*.log)
        IFS=$'\n'
        for line in ${output}; do
            echo "        <div class=\"result fail\">${line}</div>" >> "${results_html}" || {
                echo "${COLRED}Error${COLRESET} writing failure to: ${results_html}"
            }
            echo "${line}" >> "${results}" || {
                echo "${COLRED}Error${COLRESET} writing failure to: ${results}"
            }
        done
    else
        echo "        <div class=\"result\">Test Passed</div>" >> "${results_html}"
    fi
    echo "    </div>" >> "${results_html}"
    echo "</body>" >> "${results_html}"
}


## show usage and exit
usage() {
    echo
    echo "Usage:"
    echo "    ${COLBOLD}${0}${COLRESET}"
    echo "        ${COLYELLOW}--testing${COLRESET}: only check a small number of blocks"
    echo "        ${COLYELLOW}-t|--terminal${COLRESET}: more terminal friendly output"
    echo "        ${COLYELLOW}-n|--network${COLRESET}: run block validation against specific network (default: mainnet)"
    echo "        ${COLYELLOW}-b|--branch${COLRESET}: branch of stacks-core to build stacks-inspect from (default: develop)"
    echo "        ${COLYELLOW}-c|--chainstate${COLRESET}: local chainstate copy to use instead of downloading a chainstaet snapshot"
    echo "        ${COLYELLOW}-l|--logdir${COLRESET}: use existing log directory"
    echo "        ${COLYELLOW}-r|--reserved${COLRESET}: how many cpu cores to reserve for system tasks"
    echo
    echo "    ex: ${COLCYAN}${0} -t -u ${COLRESET}"
    echo
    exit 0
}


## install missing dependencies
HAS_APT=1
HAS_SUDO=1
for cmd in apt-get sudo curl tmux git wget tar gzip grep cargo pgrep tput find; do
    # in Alpine, `find` might be linked to `busybox` and won't work
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


## parse cmd-line args
while [ ${#} -gt 0 ]; do
    case ${1} in
        --testing)
            # only validate 1_000 blocks
            TESTING=true
            ;;
        -t|--terminal)
            # update terminal with progress (it's just printf to show in real-time that the validations are running)
            TERM_OUT=true
            ;;
        -n|--network)
            # required if not mainnet
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            NETWORK=${2}
            shift
            ;;
        -b|--branch)
            # build from specific branch
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            BRANCH=${2}
            shift
            ;;
        -c|--chainstate)
            # use a local chainstate
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            LOCAL_CHAINSTATE="${2}"
            shift
            ;;
        -l|--logdir)
            # use a given logdir
            if [ "${2}" == "" ]; then
                echo "Missing required value for ${1}"
                exit 1
            fi
            LOG_DIR="${2}"
            shift
            ;;
        -r|--RESERVED)
            # reserve this many cpus for the system (default is 10)
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


## clear display before starting
tput reset
echo "Validation Started: ${COLYELLOW}$(date)${COLRESET}"
build_stacks_inspect        ## comment if using an existing chainstate/slice dir (ex: validation was performed already, and a second run is desired)
configure_validation_slices ## comment if using an existing chainstate/slice dir (ex: validation was performed already, and a second run is desired)
setup_validation            ## configure logdir and tmux sessions
start_validation            ## validate pre-nakamoto blocks (2.x)
start_validation nakamoto   ## validate nakamoto blocks
store_results               ## store aggregated results of validation
echo "Validation finished: $(date)"
