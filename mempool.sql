--.eqp full
.eqp on
.echo on

DROP INDEX IF EXISTS index_by_fee_estimate_nonces;
DROP INDEX IF EXISTS index_by_fee_rate;
--DROP INDEX IF EXISTS fee_by_txid;

--CREATE INDEX fee_by_txid ON fee_estimates(txid) ;

--CREATE INDEX index_by_fee_estimate_nonces on mempool(origin_nonce,last_known_origin_nonce,sponsor_nonce,last_known_sponsor_nonce) where ((origin_nonce = last_known_origin_nonce AND sponsor_nonce = last_known_sponsor_nonce) OR (last_known_origin_nonce is NULL) OR (last_known_sponsor_nonce is NULL));

CREATE INDEX index_by_fee_estimate_nonces on mempool(txid,origin_nonce,sponsor_nonce);

CREATE INDEX index_by_fee_rate ON fee_estimates(fee_rate) WHERE fee_rate IS NOT NULL;

SELECT * FROM mempool 
LEFT JOIN fee_estimates as f 
ON mempool.txid = f.txid 
WHERE
--(
--(origin_nonce = last_known_origin_nonce AND sponsor_nonce = last_known_sponsor_nonce) 
--OR 
--(last_known_origin_nonce is NULL) OR (last_known_sponsor_nonce is NULL)
--)
origin_nonce IS NOT NULL AND sponsor_nonce IS NOT NULL
AND 
f.fee_rate IS NOT NULL 
ORDER BY f.fee_rate DESC 
LIMIT 1;

-- CREATE INDEX index_by_fee_estimate_nonces on mempool(origin_nonce,last_known_origin_nonce,sponsor_nonce,last_known_sponsor_nonce) where ((origin_nonce = last_known_origin_nonce AND sponsor_nonce = last_known_sponsor_nonce) OR (last_known_origin_nonce is NULL) OR (last_known_sponsor_nonce is NULL));
-- CREATE INDEX index_by_fee_rate ON fee_estimates(fee_rate) WHERE fee_rate IS NOT NULL;
