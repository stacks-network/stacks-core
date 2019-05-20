ALICE=SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7
BOB=S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE
CHARLIE=SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR
SPENDER=SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G
OPERATOR=ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ

echo "-> ALICE address: $ALICE"
echo "-> BOB address: $BOB"
echo "-> CHARLIE address: $CHARLIE"

# Check and initialize contract
blockstack-core local initialize test-erc721.sqlite3
blockstack-core local check sample-programs/erc721/erc721.scm test-erc721.sqlite3
blockstack-core local launch stx-erc721 sample-programs/erc721/erc721.scm test-erc721.sqlite3

# Assertions
echo "-> ALICE's balance = 1 token"
echo "(balance-of '$ALICE)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> BOB's balance = 1 token"
echo "(balance-of '$BOB)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> CHARLIE's balance = 1 token"
echo "(balance-of '$CHARLIE)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10001 is owned by $ALICE"
echo "(owner-of 10001)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10002 is owned by $BOB"
echo "(owner-of 10002)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10003 is owned by $CHARLIE"
echo "(owner-of 10003)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3

echo "-> BOB will send '10002' STX to ALICE"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 transfer $BOB \'$ALICE 10002
echo "-> CHARLIE will send '10003' STX to ALICE"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 transfer $CHARLIE \'$ALICE 10003

# Assertions
echo "-> ALICE's balance = 3 token"
echo "(balance-of '$ALICE)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> BOB's balance = 0 token"
echo "(balance-of '$BOB)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> CHARLIE's balance = 0 token"
echo "(balance-of '$CHARLIE)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10001 is owned by $ALICE"
echo "(owner-of 10001)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10002 is owned by $ALICE"
echo "(owner-of 10002)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10003 is owned by $ALICE"
echo "(owner-of 10003)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3

echo "-> BOB will send '10002' STX to ALICE - should fail"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 transfer $BOB \'$ALICE 10002

echo "-> ALICE will approve SPENDER as a spender for '10001'"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 set-spender-approval $ALICE \'$SPENDER 10002

echo "-> ALICE will approve OPERATOR as an operator"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 set-operator-approval $ALICE \'$OPERATOR \'true
echo "(can-transfer '$OPERATOR 10003)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3

echo "-> SPENDER will send '10002' from ALICE to BOB"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 transfer-from $SPENDER \'$ALICE \'$BOB 10002

echo "-> OPERATOR will send '10003' from ALICE to CHARLIE"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 transfer-from $OPERATOR \'$ALICE \'$CHARLIE 10003

# Assertions
echo "-> ALICE's balance = 1 token"
echo "(balance-of '$ALICE)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> BOB's balance = 1 token"
echo "(balance-of '$BOB)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> CHARLIE's balance = 1 token"
echo "(balance-of '$CHARLIE)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10001 is owned by $ALICE"
echo "(owner-of 10001)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10002 is owned by $BOB"
echo "(owner-of 10002)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3
echo "-> Token 10003 is owned by $CHARLIE"
echo "(owner-of 10003)" | blockstack-core local eval stx-erc721 test-erc721.sqlite3

# Ensure that SPENDER and OPERATOR lost their ability to transfer 10002 and 10003
echo "-> SPENDER will send '10002' from BOB to ALICE - should fail"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 transfer-from $SPENDER \'$BOB \'$ALICE 10002
echo "-> OPERATOR will send '10003' from CHARLIE to ALICE - should fail"
blockstack-core local execute test-erc721.sqlite3 stx-erc721 transfer-from $OPERATOR \'$CHARLIE \'$ALICE 10003

