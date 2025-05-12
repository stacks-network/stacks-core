;;
;; @contract voting for the aggregate public key
;;

;; maps dkg round and signer to proposed aggregate public key
(define-map votes {reward-cycle: uint, round: uint, signer: principal} {aggregate-public-key: (buff 33), signer-weight: uint})
;; maps dkg round and aggregate public key to weights of signers supporting this key so far
(define-map tally {reward-cycle: uint, round: uint, aggregate-public-key: (buff 33)} uint)
;; maps aggregate public keys to rewards cycles
(define-map used-aggregate-public-keys (buff 33) uint)

;; Error codes
;; 1 - 9 are reserved for use in the .signers contract, which can be returned
;; through this contract)
(define-constant ERR_SIGNER_INDEX_MISMATCH u10)
(define-constant ERR_INVALID_SIGNER_INDEX u11)
(define-constant ERR_OUT_OF_VOTING_WINDOW u12)
(define-constant ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY u13)
(define-constant ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY u14)
(define-constant ERR_DUPLICATE_VOTE u15)
(define-constant ERR_FAILED_TO_RETRIEVE_SIGNERS u16)
(define-constant ERR_INVALID_ROUND u17)

(define-constant pox-info
    (unwrap-panic (contract-call? .pox-4 get-pox-info)))

;; Threshold consensus, expressed as parts-per-hundred to allow for integer
;; division with higher precision (e.g. 70 for 70%).
(define-constant threshold-consensus u70)

;; Maps reward-cycle ids to last round
(define-map rounds uint uint)

;; Maps reward-cycle ids to aggregate public key.
(define-map aggregate-public-keys uint (buff 33))

;; Maps reward-cycle id to the total weight of signers. This map is used to
;; cache the total weight of signers for a given reward cycle, so it is not
;; necessary to recalculate it on every vote.
(define-map cycle-total-weight uint uint)

;; Maps voting data (count, current weight) per reward cycle & round
(define-map round-data {reward-cycle: uint, round: uint} {votes-count: uint, votes-weight: uint})

(define-read-only (burn-height-to-reward-cycle (height uint))
    (/ (- height (get first-burnchain-block-height pox-info)) (get reward-cycle-length pox-info)))

(define-read-only (reward-cycle-to-burn-height (reward-cycle uint))
    (+ (* reward-cycle (get reward-cycle-length pox-info)) (get first-burnchain-block-height pox-info)))

(define-read-only (current-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height))

(define-read-only (get-last-round (reward-cycle uint))
    (map-get? rounds reward-cycle))

(define-read-only (get-vote (reward-cycle uint) (round uint) (signer principal))
    (map-get? votes {reward-cycle: reward-cycle, round: round, signer: signer}))

(define-read-only (get-round-info (reward-cycle uint) (round uint))
    (map-get? round-data {reward-cycle: reward-cycle, round: round}))

(define-read-only (get-candidate-info (reward-cycle uint) (round uint) (candidate (buff 33)))
    {candidate-weight: (default-to u0 (map-get? tally {reward-cycle: reward-cycle, round: round, aggregate-public-key: candidate})),
    total-weight: (map-get? cycle-total-weight reward-cycle)})

(define-read-only (get-tally (reward-cycle uint) (round uint) (aggregate-public-key (buff 33)))
    (map-get? tally {reward-cycle: reward-cycle, round: round, aggregate-public-key: aggregate-public-key}))

(define-read-only (get-signer-weight (signer-index uint) (reward-cycle uint))
    (let ((details (unwrap! (try! (contract-call? .signers get-signer-by-index reward-cycle signer-index)) (err ERR_INVALID_SIGNER_INDEX))))
        (asserts! (is-eq (get signer details) tx-sender) (err ERR_SIGNER_INDEX_MISMATCH))
        (ok (get weight details))))

;; aggregate public key must be unique and can be used only in a single cycle
(define-read-only (is-novel-aggregate-public-key (key (buff 33)) (reward-cycle uint))
    (is-eq (default-to reward-cycle (map-get? used-aggregate-public-keys key)) reward-cycle))

(define-read-only (is-in-prepare-phase (height uint))
    (< (mod (+ (- height (get first-burnchain-block-height pox-info))
                (get prepare-cycle-length pox-info))
             (get reward-cycle-length pox-info)
            )
        (get prepare-cycle-length pox-info)))

;; get the aggregate public key for the given reward cycle (or none)
(define-read-only (get-approved-aggregate-key (reward-cycle uint))
    (map-get? aggregate-public-keys reward-cycle))

;; get the weight required for consensus threshold
(define-read-only (get-threshold-weight (reward-cycle uint))
    (let  ((total-weight (default-to u0 (map-get? cycle-total-weight reward-cycle))))
        (/ (+ (* total-weight threshold-consensus) u99) u100)))

(define-private (is-in-voting-window (height uint) (reward-cycle uint))
    (let ((last-cycle (unwrap-panic (contract-call? .signers get-last-set-cycle))))
        (and (is-eq last-cycle reward-cycle)
            (is-in-prepare-phase height))))

(define-private (sum-weights (signer { signer: principal, weight: uint }) (acc uint))
    (+ acc (get weight signer)))

(define-private (get-and-cache-total-weight (reward-cycle uint))
    (match (map-get? cycle-total-weight reward-cycle)
        total (ok total)
        (let ((signers (unwrap! (contract-call? .signers get-signers reward-cycle) (err ERR_FAILED_TO_RETRIEVE_SIGNERS)))
                (total (fold sum-weights signers u0)))
            (map-set cycle-total-weight reward-cycle total)
            (ok total))))

;; If the round is not set, or the new round is greater than the last round,
;; update the last round.
;; Returns:
;;  * `(ok true)` if this is the first round for the reward cycle
;;  * `(ok false)` if this is a new last round for the reward cycle
;;  * `(err ERR_INVALID_ROUND)` if the round is incremented by more than 1
(define-private (update-last-round (reward-cycle uint) (round uint))
    (ok (match (map-get? rounds reward-cycle)
        last-round (begin
            (asserts! (<= round (+ last-round u1)) (err ERR_INVALID_ROUND))
            (if (> round last-round) (map-set rounds reward-cycle round) false))
        (map-set rounds reward-cycle round))))

;; Signer vote for the aggregate public key of the next reward cycle
;;  Each signer votes for the aggregate public key for the next reward cycle.
;;  This vote must happen after the list of signers has been set by the node,
;;  which occurs in the first block of the prepare phase. The vote is concluded
;;  when the threshold of `threshold-consensus / 1000` is reached for a
;;  specific aggregate public key. The vote is weighted by the amount of
;;  reward slots that the signer controls in the next reward cycle. The vote
;;  may require multiple rounds to reach consensus, but once consensus is
;;  reached, later rounds will be ignored.
;;
;;  Arguments:
;;   * signer-index: the index of the calling signer in the signer set (from
;;     `get-signers` in the .signers contract)
;;   * key: the aggregate public key that this vote is in support of
;;   * round: the voting round for which this vote is intended
;;   * reward-cycle: the reward cycle for which this vote is intended
;;  Returns:
;;   * `(ok true)` if the vote was successful
;;   * `(err <code>)` if the vote was not successful (see errors above)
(define-public (vote-for-aggregate-public-key (signer-index uint) (key (buff 33)) (round uint) (reward-cycle uint))
    (let ((tally-key {reward-cycle: reward-cycle, round: round, aggregate-public-key: key})
            ;; vote by signer weight
            (signer-weight (try! (get-signer-weight signer-index reward-cycle)))
            (new-total (+ signer-weight (default-to u0 (map-get? tally tally-key))))
            (cached-weight (try! (get-and-cache-total-weight reward-cycle)))
            (threshold-weight (get-threshold-weight reward-cycle))
            (current-round (default-to {
                votes-count: u0, 
                votes-weight: u0} (map-get? round-data {reward-cycle: reward-cycle, round: round})))
                )
        ;; Check that the key has not yet been set for this reward cycle
        (asserts! (is-none (map-get? aggregate-public-keys reward-cycle)) (err ERR_OUT_OF_VOTING_WINDOW))
        ;; Check that the aggregate public key is the correct length
        (asserts! (is-eq (len key) u33) (err ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY))
        ;; Check that aggregate public key has not been used in a previous reward cycle
        (asserts! (is-novel-aggregate-public-key key reward-cycle) (err ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY))
        ;; Check that signer hasn't voted in this reward-cycle & round
        (asserts! (map-insert votes {reward-cycle: reward-cycle, round: round, signer: tx-sender} {aggregate-public-key: key, signer-weight: signer-weight}) (err ERR_DUPLICATE_VOTE))
        ;; Check that the round is incremented by at most 1
        (try! (update-last-round reward-cycle round))
        ;; Update the tally for this aggregate public key candidate
        (map-set tally tally-key new-total)
        ;; Update the current round data
        (map-set round-data {reward-cycle: reward-cycle, round: round} {
            votes-count: (+ (get votes-count current-round) u1),
            votes-weight: (+ (get votes-weight current-round) signer-weight)})
        ;; Update used aggregate public keys
        (map-set used-aggregate-public-keys key reward-cycle)
        (print {
            event: "voted",
            signer: tx-sender,
            reward-cycle: reward-cycle,
            round: round,
            key: key,
            new-total: new-total,
        })
        ;; If the new total weight is greater than or equal to the threshold consensus
        (if (>= new-total threshold-weight)
            ;; Save this approved aggregate public key for this reward cycle.
            ;; If there is not already a key for this cycle, the insert will
            ;; return true and an event will be created.
            (if (map-insert aggregate-public-keys reward-cycle key)
                (begin
                    ;; Create an event for the approved aggregate public key
                    (print {
                        event: "approved-aggregate-public-key",
                        reward-cycle: reward-cycle,
                        round: round,
                        key: key,
                    })
                    true)
                false
            )
            false
        )
        (ok true)))
