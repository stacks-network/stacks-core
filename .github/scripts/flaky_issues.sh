#!/usr/bin/env bash
#
# Keeps one GitHub issue per flaky test in step with the workflow's results.
#
# Two phases, both driven by observed-tests.jsonl from flaky_report.sh:
#
#   1. Tests that FAILED    -> file a new issue, or comment on the existing one
#   2. Tests that PASSED    -> close the issue once the test has been quiet for
#                              QUIET_AFTER qualifying workflow runs
#   2b. Tests never SEEN    -> close the issue once the test has gone unobserved
#                              for ORPHAN_AFTER runs (renamed, deleted, excluded)
#
# A run that failed more than MAX_FLAKY_FAILURES tests is treated as broken
# rather than flaky: none of the three phases runs, because the results are not
# trustworthy evidence about any individual test - see the guard in main().
#
# A test absent from one run is left alone: it may simply not have run (a
# narrowed `only-tests` matrix, an excluded test, or a job that never reported).
# One run's absence says nothing, but absence that persists says plenty, so an
# issue closes once its test has gone unobserved for ORPHAN_AFTER runs. That
# needs no judgement about *why* it vanished, which is the point: renamed,
# deleted and excluded are indistinguishable from the results alone.
#
# One issue per test, so the issue becomes that test's record: every workflow
# run in which it fails appends a comment. Evidence is written as text rather than
# only as a link, because Actions job logs are deleted after the retention period 
# while the issue is permanent.
#
# Required env vars:
#   GH_TOKEN            - token with issues:write on GITHUB_REPOSITORY
#   GITHUB_REPOSITORY   - owner/repo to file issues against
#   GITHUB_WORKFLOW     - this workflow's name, supplied by Actions. Used to
#                         count its own run history, so the count follows the
#                         workflow it is running in and cannot drift out of
#                         sync with a hardcoded name
#   QUIET_AFTER         - how many quiet runs before an issue is closed.
#                         0 closes as soon as the test passes
#   COUNT_MANUAL_RUNS   - "true" to also count manual runs towards QUIET_AFTER
#                         and ORPHAN_AFTER. Scheduled runs always count, and are
#                         the only sound measure: they are full-width, whereas a
#                         manual run can be narrowed by `only-tests` and so gives
#                         most tests no chance to fail. Counting manual runs is
#                         therefore a testing-only relaxation, to exercise the
#                         thresholds without waiting for the cron
#   ORPHAN_AFTER        - how many runs a test may go *unobserved* before its
#                         issue is closed as no longer watched. Must be greater
#                         than QUIET_AFTER - see close_quiet_issues()
#   MAX_FLAKY_FAILURES  - the most failures still attributable to flakiness.
#                         Above it the run is treated as broken and no issue is
#                         touched at all. This is also the bound on how
#                         many issues one run can write.
#   DRY_RUN_ISSUES      - "true" to print each issue write instead of making
#                         it. Scoped to issue and label writes only: the tests
#                         still run, every read still happens, and a broken
#                         harness still alerts. Nothing here makes the run cheap
#   FLAKY_LABEL         - the label every issue carries.
#   OBSERVED_TESTS_FILE - JSONL written by flaky_report.sh earlier in the same
#                         job.
#
# Exit behavior:
#   Exits 0 when triage completed, whether or not any test failed.
#
#   Exits 1 when triage was REFUSED: no results were observed, or the run failed
#   so many tests that it cannot be trusted. Both cases mean no issue was filed,
#   commented on or closed.
#
#   Exits non-zero if any GitHub write fails, at the point of failure. Triage is
#   then partially applied and no summary is written, so the job log is the only
#   record - deliberate, since a failed write is the harness breaking, not a test
#   failing, and the next run re-files anything it missed.

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/logging.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/require.sh"

main() {
    initialize

    local existing_issues
    local -A tests_stats=([observed]=0 [failed]=0)
    local -A issues_stats=(
        [created]=0 [updated]=0 [reopened]=0 [closed]=0 [orphaned]=0
    )
    local -a issues_actions=()

    # Precondition: this run must have observed something
    if [[ ! -s "${CFG_OBSERVED_TESTS_FILE}" ]]; then
        warn "No tests were observed in this run - nothing to do"
        report_summary_no_observations
        exit 1
    fi

    tests_stats[observed]=$(grep -c '' "${CFG_OBSERVED_TESTS_FILE}" || true)
    tests_stats[failed]=$(jq -s '[.[] | select(.status == "fail")] | length' "${CFG_OBSERVED_TESTS_FILE}")
    info "Observed $(hl "${tests_stats[observed]}") test(s), $(hl "${tests_stats[failed]}") failing, on $(hl "${CFG_REPO}")"

    # Mass-failure guard: is this a flaky run, or a broken one?
    if (( tests_stats[failed] > CFG_MAX_FLAKY_FAILURES )); then
        warn "$(hl "${tests_stats[failed]}") failures, more than $(hl "MAX_FLAKY_FAILURES")=$(hl "${CFG_MAX_FLAKY_FAILURES}")"
        warn "Treating this run as broken: nothing will be filed, commented on, or closed"
        report_summary_broken tests_stats
        exit 1
    fi

    # Manage Github issue lifecycle
    existing_issues="$(mktemp)"
    load_existing_issues "${existing_issues}"
    ## Phase 1: create, update, or reopen issues for tests that failed in this run
    file_failure_issues "${existing_issues}" issues_stats issues_actions
    ## Phase 2: close issues for tests that have gone quiet or orphaned
    close_quiet_issues "${existing_issues}" issues_stats issues_actions
    rm -f "${existing_issues}"

    report_summary_success tests_stats issues_stats issues_actions
}

## ── Helpers ─────────────────────────────────────────────────────────────────

# Initialize the script, checking preconditions and loading configuration. 
# Exits on failure.
initialize() {
    # Preconditions: tools
    require_cmds gh jq

    # Preconditions: inputs
    ## Github-provided
    require_vars \
        GH_TOKEN \
        GITHUB_REPOSITORY \
        GITHUB_WORKFLOW
    ## Custom-provided
    require_vars \
        OBSERVED_TESTS_FILE \
        FLAKY_LABEL \
        COUNT_MANUAL_RUNS \
        QUIET_AFTER \
        ORPHAN_AFTER \
        DRY_RUN_ISSUES \
        MAX_FLAKY_FAILURES

    # Configuration
    CFG_WORKFLOW_NAME="${GITHUB_WORKFLOW}"
    CFG_REPO="${GITHUB_REPOSITORY}"
    CFG_OBSERVED_TESTS_FILE="${OBSERVED_TESTS_FILE}"
    CFG_FLAKY_LABEL="${FLAKY_LABEL}"
    CFG_COUNT_MANUAL_RUNS="${COUNT_MANUAL_RUNS}"
    CFG_QUIET_AFTER="${QUIET_AFTER}"
    CFG_ORPHAN_AFTER="${ORPHAN_AFTER}"
    CFG_DRY_RUN_ISSUES="${DRY_RUN_ISSUES}"
    CFG_MAX_FLAKY_FAILURES="${MAX_FLAKY_FAILURES}"
    
    # Marker carrying the fully qualified test name within a Github issue
    CFG_ID_MARKER_PREFIX="test-id"

    # Starts every evidence comment, and is how the close phase dates the last
    # failure - the writer and the reader must stay in step.
    CFG_FAILURE_HEADING="### Failure - "

    # Applied only when creating the label; matches the upstream `flaky` label.
    CFG_FLAKY_LABEL_COLOR="58BCF1"

    # How many issues to load per state. Fetched as limit+1 so a full page is
    # distinguishable from a page that happens to hold exactly the limit.
    CFG_ISSUE_LIMIT=500

    # Long enough that captured output containing triple backticks cannot break out
    CFG_FENCE='`````'

    # Display only, so a missing GITHUB_* degrades the link, not the run.
    CFG_RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${CFG_REPO}/actions/runs/${GITHUB_RUN_ID:-}"
    CFG_TODAY="$(date -u +%Y-%m-%d)"

    # Validate the configuration
    if (( CFG_ORPHAN_AFTER <= CFG_QUIET_AFTER )); then
        error "$(hl "ORPHAN_AFTER") (${CFG_ORPHAN_AFTER}) must be greater than $(hl "QUIET_AFTER") (${CFG_QUIET_AFTER})"
        error "Otherwise one unreported test job could close the issue of a passing test."
        exit 1
    fi

    info "Config: quiet-after=$(hl "${CFG_QUIET_AFTER}") orphan-after=$(hl "${CFG_ORPHAN_AFTER}") max-flaky-failures=$(hl "${CFG_MAX_FLAKY_FAILURES}") count-manual-runs=$(hl "${CFG_COUNT_MANUAL_RUNS}") dry-run-issues=$(hl "${CFG_DRY_RUN_ISSUES}")"
    
    # Preconditions: Github issues must be enabled
    if [[ "$(gh api "repos/${CFG_REPO}" --jq '.has_issues')" != "true" ]]; then
        error "Issues are disabled on $(hl "${CFG_REPO}"), so no issue can be filed!"
        exit 1
    fi

    # Preconditions: Github label must exists
    ensure_flaky_label
}

# Create the label if the repo does not have it yet.
ensure_flaky_label() {
    local existing_labels

    # Not piped into grep -q: that exits on first match and can SIGPIPE gh,
    # which under pipefail reads as "label missing" and re-creates it.
    existing_labels=$(gh label list --repo "${CFG_REPO}" --limit 200 --json name --jq '.[].name')

    if grep -qxF "${CFG_FLAKY_LABEL}" <<< "${existing_labels}"; then
        info "Label already exists: $(hl "${CFG_FLAKY_LABEL}")"
    else
        info "Creating label: $(hl "${CFG_FLAKY_LABEL}")"
        gh_mutate label create "${CFG_FLAKY_LABEL}" --repo "${CFG_REPO}" \
            --color "${CFG_FLAKY_LABEL_COLOR}" \
            --description "Test that fails intermittently in CI"
    fi
}

# Write every issue we have already filed to the given file. `comments` and
# `createdAt` are needed because the close phase dates each issue's last
# failure from them.
#
# Open and closed are fetched separately, because truncating one is far worse
# than truncating the other. An issue missing from the list has no marker to
# match, so the next failure files a duplicate instead of updating it - and if
# the missing issue was OPEN, phase 2 can never close it either, leaving a pair
# that no run can reconcile. A missing CLOSED issue only means a recurrence
# after a long silence starts a fresh issue, which is reasonable on its own
# terms. So a full page of open issues stops the run, and a full page of closed
# ones is merely noted.
#
# Open is merged first: the marker lookup takes the first match, so where a
# duplicate pair already exists the open one is updated rather than the closed
# one reopened alongside it.
load_existing_issues() {
    local target="$1"
    local open_issues closed_issues fetched number full_comments
    local fields="number,state,body,comments,createdAt"

    open_issues="$(mktemp)"
    closed_issues="$(mktemp)"

    gh issue list --repo "${CFG_REPO}" --label "${CFG_FLAKY_LABEL}" --state open \
        --limit $(( CFG_ISSUE_LIMIT + 1 )) --json "${fields}" > "${open_issues}"

    # Refused rather than warned: triaging a truncated list of open issues files
    # duplicates, so every further run makes the pile worse. The report job fails,
    # which is what puts it in front of someone via the Slack alert.
    fetched=$(jq 'length' "${open_issues}")
    if (( fetched > CFG_ISSUE_LIMIT )); then
        error "More than $(hl "${CFG_ISSUE_LIMIT}") open $(hl "${CFG_FLAKY_LABEL}") issue(s)"
        error "The list would be truncated, and triaging a truncated list files duplicates"
        error "Close the stale ones, or raise $(hl "CFG_ISSUE_LIMIT")"
        rm -f "${open_issues}" "${closed_issues}"
        exit 1
    fi

    # Sorted by last touched, not by age: a closed issue nothing has touched in
    # months is the one that can be dropped safely, whereas one closed recently
    # is the likeliest to need reopening.
    gh issue list --repo "${CFG_REPO}" --label "${CFG_FLAKY_LABEL}" --state closed \
        --search "sort:updated-desc" \
        --limit $(( CFG_ISSUE_LIMIT + 1 )) --json "${fields}" > "${closed_issues}"

    if (( $(jq 'length' "${closed_issues}") > CFG_ISSUE_LIMIT )); then
        warn "More than $(hl "${CFG_ISSUE_LIMIT}") closed $(hl "${CFG_FLAKY_LABEL}") issue(s)"
        warn "The oldest are out of view, so a recurrence there files a new issue"
    fi

    jq -s 'add' "${open_issues}" "${closed_issues}" > "${target}"
    rm -f "${open_issues}" "${closed_issues}"

    # Special case: issues with 100+ comments.
    # `gh issue list` returns the OLDEST 100 comments per issue and says nothing
    # about it, so on a long-lived issue the recent failures fall out of view,
    # last_failure goes stale, and the close phase reads a still-failing test as
    # quiet. `gh issue view` pages internally and returns all of them, so any
    # issue sitting at the cap is re-fetched in full. One extra call each, and it
    # takes a hundred failing runs on one test to earn one.
    full_comments="$(mktemp)"
    while read -r number; do
        [[ -z "${number}" ]] && continue
        warn "Issue #${number} is at the comment list cap - re-fetching it in full"

        # Its own statement, so a failed fetch trips `set -e`. Inside a process
        # substitution it would not, and jq would quietly replace the comments
        # with nothing - ageing last_failure into a premature close.
        gh issue view "${number}" --repo "${CFG_REPO}" --json comments > "${full_comments}"
        jq --argjson number "${number}" --slurpfile full "${full_comments}" \
            'map(if .number == $number then .comments = $full[0].comments else . end)' \
            "${target}" > "${target}.full"
        mv "${target}.full" "${target}"
    done < <(jq -r '.[] | select((.comments | length) >= 100) | .number' "${target}")
    rm -f "${full_comments}"

    info "Found $(hl "$(jq 'length' "${target}")") existing $(hl "${CFG_FLAKY_LABEL}") issue(s)"
}

# Create, update, or reopen issues for tests that failed in this run
file_failure_issues() {
    local existing_issues="$1"
    local -n issues_stats_ref="$2"
    local -n issues_actions_ref="$3"
    local record name duration excerpt marker comment_file body_file
    local match number state url action

    while IFS= read -r record; do
        name=$(jq -r '.name' <<< "${record}")
        duration=$(jq -r '.duration' <<< "${record}")
        excerpt=$(jq -r '.excerpt' <<< "${record}")
        [[ -z "${name}" ]] && continue

        marker="<!-- ${CFG_ID_MARKER_PREFIX}: ${name} -->"

        # The evidence comment, identical whether the issue is new or existing
        comment_file="$(mktemp)"
        {
            echo "${CFG_FAILURE_HEADING}${CFG_TODAY}"
            echo
            echo "- **Run:** [${GITHUB_RUN_ID:-unknown}](${CFG_RUN_URL})"
            echo "- **Commit:** \`${GITHUB_SHA:-unknown}\` on \`${GITHUB_REF_NAME:-unknown}\`"
            echo "- **Duration:** ${duration}s"
            echo
            echo "${CFG_FENCE}text"
            printf '%s\n' "${excerpt}"
            echo "${CFG_FENCE}"
            echo
            echo "Full test output is in the run's job log, which is subject to GitHub retention policy."
        } > "${comment_file}"

        # Exact-match the marker against the bodies we already have. No match
        # leaves both fields empty. @tsv escapes any tab or newline *inside* a
        # value, so the row can never mis-split - which is why multi-line values
        # like the excerpt above travel as JSON instead.
        #
        # Assigned first, then read: `read <<< "$(jq ...)"` reports read's
        # status rather than jq's, so a jq failure would look like "no match"
        # and file a duplicate issue. As an assignment it aborts under set -e.
        match=$(jq -r --arg marker "${marker}" '
            map(select(.body != null and (.body | contains($marker))))
            | if length == 0 then "" else [.[0].number, .[0].state] | @tsv end
        ' "${existing_issues}")
        IFS=$'\t' read -r number state <<< "${match}"

        if [[ -z "${number}" ]]; then
            body_file="$(mktemp)"
            {
                echo "The following test looks flaky: \`${name}\`."
                echo
                echo "> Filed automatically by \`${CFG_WORKFLOW_NAME}\`."
                echo
                echo "${marker}"
            } > "${body_file}"

            info "Creating issue for $(hl "${name}")"
            url=$(gh_mutate issue create --repo "${CFG_REPO}" \
                --title "[Flaky Test] ${name}" \
                --label "${CFG_FLAKY_LABEL}" \
                --body-file "${body_file}")
            rm -f "${body_file}"

            if [[ -n "${url}" ]]; then
                number="${url##*/}"
            else # No url means DRY_RUN_ISSUES otherwise gh failure would have exited
                number="XYZ"
            fi

            action="created"

            gh_mutate issue comment "${number}" --repo "${CFG_REPO}" \
                    --body-file "${comment_file}"

            issues_stats_ref[created]=$(( issues_stats_ref[created] + 1 ))
            issues_actions_ref+=("$(issue_action_row "${name}" "${number}" "${action}")")
        else
            # Counters stay disjoint: a reopen counts as reopened, not also as
            # updated, so their sum matches the number of rows in the table.
            if [[ "${state}" == "CLOSED" ]]; then
                info "Reopening #${number} for $(hl "${name}")"
                gh_mutate issue reopen "${number}" --repo "${CFG_REPO}"
                issues_stats_ref[reopened]=$(( issues_stats_ref[reopened] + 1 ))
                action="reopened"
            else
                issues_stats_ref[updated]=$(( issues_stats_ref[updated] + 1 ))
                action="updated"
            fi

            info "Adding evidence to #${number} for $(hl "${name}")"
            gh_mutate issue comment "${number}" --repo "${CFG_REPO}" \
                --body-file "${comment_file}"

            issues_actions_ref+=("$(issue_action_row "${name}" "${number}" "${action}")")
        fi

        rm -f "${comment_file}"
    done < <(jq -c 'select(.status == "fail")' "${CFG_OBSERVED_TESTS_FILE}")
}

## Close issues whose test has gone quiet by passing, or vanished entirely.
#
# Two closes sharing one counter - qualifying runs since the test last failed:
#
#   pass   + quiet_count >= QUIET_AFTER   -> "went quiet"  (positive evidence)
#   absent + quiet_count >= ORPHAN_AFTER  -> "not watched" (negative evidence)
close_quiet_issues() {
    local existing_issues="$1"
    local -n issues_stats_ref="$2"
    local -n issues_actions_ref="$3"
    local quiet_runs quiet_runs_total number state test_id test_status last_failure quiet_count
    local manual_label
    local comment reason action
    local -A observed_status=()

    # Status of every test that ran, so "passed" is distinguishable from "did
    # not run" - otherwise a narrowed `only-tests` run would close everything.
    while IFS=$'\t' read -r test_id test_status; do
        observed_status["${test_id}"]="${test_status}"
    done < <(jq -r '[.name, .status] | @tsv' "${CFG_OBSERVED_TESTS_FILE}")

    # Runs that gave every test a chance to fail. One call for the whole phase.
    #
    # An allow-list, not a deny-list: only a run that finished ("success" or
    # "failure") has given every test a chance to execute.
    #
    # This is the workflow's conclusion, not the report job's, so a run that
    # finished but refused to triage - a mass failure, or no reports at all -
    # still counts here. Deliberately coarse: telling those apart needs a jobs
    # query per run or a marker persisted between runs, and a premature close is
    # self-correcting. The next observed failure reopens the issue with its
    # evidence attached, which is what the closing comment promises.
    #
    # Narrow server-side where we can, so the 200 applies to runs that could
    # qualify rather than to every run of this workflow. Without it, a burst of
    # manual dispatches pushes the scheduled runs out of the window and
    # quiet_count collapses toward zero, so nothing ever closes. Skipped when
    # manual runs count, because then both events qualify and --event takes a
    # single value; the jq below states the whole rule either way.
    local -a run_filter=()
    [[ "${CFG_COUNT_MANUAL_RUNS}" == "true" ]] || run_filter=(--event schedule)

    quiet_runs=$(gh run list --repo "${CFG_REPO}" --workflow "${CFG_WORKFLOW_NAME}" \
        "${run_filter[@]}" \
        --limit 200 --json event,createdAt,conclusion \
        | jq -c --arg manual "${CFG_COUNT_MANUAL_RUNS}" '
            [ .[]
              | select(.conclusion == "success" or .conclusion == "failure")
              | select(.event == "schedule"
                       or ($manual == "true" and .event == "workflow_dispatch"))
              | .createdAt ]')

    if [[ "${CFG_COUNT_MANUAL_RUNS}" == "true" ]]; then
        manual_label="counted"
    else
        manual_label="ignored"
    fi

    quiet_runs_total=$(jq 'length' <<< "${quiet_runs}")
    info "Counting quiet runs against $(hl "${quiet_runs_total}") run(s); manual runs $(hl "${manual_label}")"

    # Nothing can ever close at zero - most likely the cron has not run yet.
    if (( quiet_runs_total == 0 )); then
        warn "No qualifying run(s) found - nothing can close as quiet"
    fi

    # One row per issue this workflow filed, tab separated: number, state,
    # test_id, last_failure. Only issues carrying the id marker in their body
    # qualify, so anything hand-filed under the same label is left alone.
    # `last_failure` is the newest failure comment's date, falling back to the
    # issue's creation date: an issue exists because a test failed, so creation
    # is a lower bound on it, and the only record left if the evidence comment
    # never landed.
    while IFS=$'\t' read -r number state test_id last_failure; do
        [[ -z "${test_id}" ]] && continue

        # Only open issues can be closed
        [[ "${state}" != "OPEN" ]] && continue

        # Both branches need it. An issue with no date at all - neither a failure
        # comment nor a creation date - counts as infinitely quiet, since every
        # run sorts after "no failure".
        quiet_count=$(jq --arg last "${last_failure}" \
            '[.[] | select($last == "" or . > $last)] | length' <<< "${quiet_runs}")

        case "${observed_status[${test_id}]:-absent}" in
            fail)
                # Phase 1 just recorded a failure; nothing to close
                continue
                ;;
            pass)
                (( quiet_count >= CFG_QUIET_AFTER )) || continue
                reason="quiet"
                ;;
            absent)
                (( quiet_count >= CFG_ORPHAN_AFTER )) || continue
                reason="orphan"
                ;;
            *)
                # Only pass/fail are ever written: the format changed.
                warn "Unknown status $(hl "${observed_status[${test_id}]}") for $(hl "${test_id}") - skipping"
                continue
                ;;
        esac

        if [[ "${reason}" == "quiet" ]]; then
            comment="$(quiet_comment "${quiet_count}" "${last_failure}")"
            info "Closing #${number} for $(hl "${test_id}") after $(hl "${quiet_count}") quiet run(s)"
            issues_stats_ref[closed]=$(( issues_stats_ref[closed] + 1 ))
            action="closed — quiet for ${quiet_count} runs"
        else
            comment="$(orphan_comment "${quiet_count}" "${last_failure}")"
            info "Closing #${number} for $(hl "${test_id}") - unobserved for $(hl "${quiet_count}") run(s)"
            issues_stats_ref[orphaned]=$(( issues_stats_ref[orphaned] + 1 ))
            action="closed — unobserved for ${quiet_count} runs"
        fi

        issues_actions_ref+=("$(issue_action_row "${test_id}" "${number}" "${action}")")

        gh_mutate issue close "${number}" --repo "${CFG_REPO}" --comment "${comment}"
    done < <(jq -r --arg prefix "${CFG_ID_MARKER_PREFIX}" --arg heading "${CFG_FAILURE_HEADING}" '
        .[]
        | select(.body != null)
        | . as $issue
        | ($issue.body | capture("<!--\\s*" + $prefix + ":\\s*(?<id>\\S+)\\s*-->")?) as $m
        | select($m != null)
        | [ $issue.number,
            $issue.state,
            $m.id,
            ([$issue.comments[]? | select(.body | startswith($heading)) | .createdAt] | max)
              // $issue.createdAt // ""
          ]
        | @tsv
    ' "${existing_issues}")
}

# Quiet comment
quiet_comment() {
    local quiet_count="$1" last_failure="$2" comment

    comment="### Closed automatically - the test has gone quiet

The test passed in this run, and has not failed in the last ${quiet_count} run(s)."
    if [[ -n "${last_failure}" ]]; then
        comment="${comment}
Last recorded failure: ${last_failure%%T*}."
    fi

    printf '%s\n' "${comment}

**If the test fails again this issue reopens automatically** with the new failure attached."
}

# Orphaned comment: due to a tests being renamed, deleted or excluded.
orphan_comment() {
    local quiet_count="$1" last_failure="$2" comment

    comment="### Closed automatically - the test is no longer being watched

The test has not been observed in the last ${quiet_count} run(s). It may have been
renamed, deleted, or excluded from CI."
    if [[ -n "${last_failure}" ]]; then
        comment="${comment}
Last recorded failure: ${last_failure%%T*}."
    fi

    printf '%s\n' "${comment}

**If a test by this name fails again this issue reopens automatically** with the new failure attached."
}


# The no-observations summary: the run did not observe any tests.
report_summary_no_observations() {
    summary "## Flaky test issues"
    summary ""
    summary "**No test results were observed**, so no issue was filed, updated or closed."
    summary "This is not the same as a run in which no test failed - check the archive"
    summary "and test jobs."
}

# The broken-run refusal summary: the run failed too many tests to be trusted.
report_summary_broken() {
    local -n tests_stats_ref="$1"

    summary "## Flaky test issues"
    summary ""
    summary "### This run looks broken, not flaky"
    summary ""
    summary "${tests_stats_ref[failed]} of ${tests_stats_ref[observed]} observed tests failed, more than the"
    summary "\`MAX_FLAKY_FAILURES\` of ${CFG_MAX_FLAKY_FAILURES}. A failure count that high"
    summary "usually means the run itself broke rather than that tests are independently flaky."
    summary "No issue was filed, updated or closed."
}

# The normal summary: one line of totals, then a row per issue the run touched.
report_summary_success() {
    local -n tests_stats_ref="$1"
    local -n issues_stats_ref="$2"
    local -n issues_actions_ref="$3"
    local row_name row_issue row_action

    summary "## Flaky test issues"
    summary ""
    if [[ "${CFG_DRY_RUN_ISSUES}" == "true" ]]; then
        summary "\`DRY_RUN_ISSUES\` was set: no issue was created, updated or closed."
        summary ""
    fi
    summary "**${tests_stats_ref[failed]} failing of ${tests_stats_ref[observed]} observed** — ${issues_stats_ref[created]} created, \
${issues_stats_ref[updated]} updated, ${issues_stats_ref[reopened]} reopened, ${issues_stats_ref[closed]} closed quiet, ${issues_stats_ref[orphaned]} closed unwatched"
    summary ""

    # The five counters are disjoint, so they sum to the row count below.
    if (( ${#issues_actions_ref[@]} > 0 )); then
        summary "| Test | Issue | Action |"
        summary "| --- | --- | --- |"
        # Sorted by test name so one test can be found without reading every row
        while IFS=$'\t' read -r row_name row_issue row_action; do
            summary "| \`${row_name}\` | ${row_issue} | ${row_action} |"
        done < <(printf '%s\n' "${issues_actions_ref[@]}" | sort -t$'\t' -k1,1)
    else
        # An empty table reads as broken, so say it plainly
        summary "No issue needed creating, updating or closing."
    fi

    info "Done: $(hl "${issues_stats_ref[created]}") created, $(hl "${issues_stats_ref[updated]}") updated, $(hl "${issues_stats_ref[reopened]}") reopened, $(hl "${issues_stats_ref[closed]}") closed, $(hl "${issues_stats_ref[orphaned]}") orphaned"
}


# One row of the summary table: <test> <issue> <action>, tab separated.
issue_action_row() {
    local test_id="$1" number="$2" action="$3" issue=""

    if [[ "${number}" =~ ^[0-9]+$ ]]; then
        issue="[#${number}](https://github.com/${CFG_REPO}/issues/${number})"
    else
        issue="#${number}"
    fi

    printf '%s\t%s\t%s' "${test_id}" "${issue}" "${action}"
}

# Run a gh command that writes, or print it under DRY_RUN_ISSUES
gh_mutate() {
    if [[ "${CFG_DRY_RUN_ISSUES}" == "true" ]]; then
        info "DRY-RUN: gh $*"
    else
        gh "$@"
    fi
}

## ── Entry point ─────────────────────────────────────────────────────────────
# Guarded so a this file can be sourced and exercise the helpers above
# in isolation without running the whole thing.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
