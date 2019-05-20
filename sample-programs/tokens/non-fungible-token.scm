;;  copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

;;  This file is part of Blockstack.

;;  Blockstack is free software. You may redistribute or modify
;;  it under the terms of the GNU General Public License as published by
;;  the Free Software Foundation, either version 3 of the License or
;;  (at your option) any later version.

;;  Blockstack is distributed in the hope that it will be useful,
;;  but WITHOUT ANY WARRANTY, including without the implied warranty of
;;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
;;  GNU General Public License for more details.

;;  You should have received a copy of the GNU General Public License
;;  along with Blockstack. If not, see <http://www.gnu.org/licenses/>.

;; Non Fungible Token, modeled after ERC-721

;; Storage
(define-map tokens-owner
  ((token-id int)) 
  ((owner principal)))
(define-map tokens-spender
  ((token-id int)) 
  ((spender principal)))
(define-map tokens-count
  ((owner principal))
  ((count int)))
(define-map accounts-operator
  ((operator principal) (account principal))
  ((is-approved bool)))

;; Internals

;; Gets the amount of tokens owned by the specified address.
(define (balance-of (account principal))
  (let ((balance
      (get count 
        (fetch-entry tokens-count (tuple (owner account))))))
    (if (eq? balance 'null) 0 balance)))

;; Gets the owner of the specified token ID.
(define (owner-of (token-id int)) 
  (get owner 
    (fetch-entry tokens-owner (tuple (token-id token-id)))))

;; Gets the approved address for a token ID, or zero if no address set (approved method in ERC721)
(define (is-spender-approved (spender principal) (token-id int))
  (let ((spender
      (get spender 
        (fetch-entry tokens-spender (tuple (token-id token-id))))))
    (if (eq? spender 'null) 'false 'true)))

;; Tells whether an operator is approved by a given owner (isApprovedForAll method in ERC721)
(define (is-operator-approved (account principal) (operator principal))
  (let ((is-approved
      (get is-approved 
        (fetch-entry accounts-operator (tuple (operator operator) (account account))))))
    (if (eq? is-approved 'null) 'false is-approved)))

;; Returns whether the given actor can transfer a given token ID.
;; To be optimized
(define (can-transfer (actor principal) (token-id int)) 
  (or 
    (eq? actor (owner-of token-id)) 
    (is-spender-approved actor token-id)
    (is-operator-approved (owner-of token-id) actor)))
 
;; Internal - Register token
(define (register-token! (new-owner principal) (token-id int))
  (let ((current-balance (balance-of new-owner)))
    (begin
      (set-entry! tokens-owner 
        (tuple (token-id token-id))
        (tuple (owner new-owner))) 
      (set-entry! tokens-count 
        (tuple (owner new-owner))
        (tuple (count (+ 1 current-balance)))) 
      'true)))

;; Internal - Release token
(define (release-token! (owner principal) (token-id int))
  (let ((current-balance (balance-of owner)))
    (begin
      (delete-entry! tokens-spender 
        (tuple (token-id token-id))) 
      (set-entry! tokens-count 
        (tuple (owner owner))
        (tuple (count (- current-balance 1)))) 
      'true)))

;; Public functions

;; Approves another address to transfer the given token ID (approve method in ERC721)
;; To be optimized
(define-public (set-spender-approval (spender principal) (token-id int))
  (if (eq? spender tx-sender)
    'false
    (if (or (eq? tx-sender (owner-of token-id)) 
            (is-operator-approved tx-sender (owner-of token-id)))
      (begin
        (set-entry! tokens-spender 
          (tuple (token-id token-id))
          (tuple (spender spender))) 
      'true)
      'false)))

;; Sets or unsets the approval of a given operator (setApprovalForAll method in ERC721)
(define-public (set-operator-approval (operator principal) (is-approved bool))
  (if (eq? operator tx-sender)
    'false
    (begin
      (set-entry! accounts-operator 
        (tuple (operator operator) (account tx-sender))
        (tuple (is-approved is-approved))) 
    'true)))

;; Transfers the ownership of a given token ID to another address.
(define-public (transfer-from (owner principal) (recipient principal) (token-id int))
  (if (can-transfer tx-sender token-id)
    (and
      (release-token! owner token-id)
      (register-token! recipient token-id))
    'false))

;; Transfers tokens to a specified principal.
(define-public (transfer (recipient principal) (token-id int))
  (transfer-from tx-sender recipient token-id))

;; Mint new tokens.
(define (mint! (owner principal) (token-id int))
  (register-token! owner token-id))

;; Initialize the contract
(begin
  (mint! 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7 10001)
  (mint! 'S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE 10002)
  (mint! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10003)
  'null)
