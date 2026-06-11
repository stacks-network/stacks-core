-- Merge principals (callers + contract issuers)
INSERT INTO principal (address)
SELECT DISTINCT caller_address
FROM _staged_stacks_tx
WHERE caller_address IS NOT NULL
UNION
SELECT DISTINCT contract_issuer_address
FROM _staged_stacks_tx
WHERE contract_issuer_address IS NOT NULL
ON CONFLICT (address) DO NOTHING;

-- Merge contracts (from contract issuer + contract name)
INSERT INTO contract (issuer_principal_id, name)
SELECT p.id, st.contract_name
FROM _staged_stacks_tx st
JOIN principal p
  ON st.contract_issuer_address = p.address
WHERE st.contract_issuer_address IS NOT NULL
  AND st.contract_name IS NOT NULL
ON CONFLICT (issuer_principal_id, name) DO NOTHING;

-- Merge contract functions (from contract + fn name)
INSERT INTO contract_fn (contract_id, name)
SELECT c.id, st.contract_fn_name
FROM _staged_stacks_tx st
JOIN principal p_issuer
  ON st.contract_issuer_address = p_issuer.address
JOIN contract c
  ON c.issuer_principal_id = p_issuer.id
 AND c.name = st.contract_name
WHERE st.contract_fn_name IS NOT NULL
ON CONFLICT (contract_id, name) DO NOTHING;

-- Merge Burn blocks
INSERT INTO burn_block (block_hash, height)
SELECT DISTINCT burn_block_hash, burn_block_height
FROM _staged_stacks_block
WHERE true
ON CONFLICT (block_hash) DO NOTHING;

-- Merge Stacks blocks (initial insert with NULL parent)
INSERT INTO stacks_block (index_hash, block_hash, height, burn_block_id, parent_stacks_block_id, txs_indexed)
SELECT sb.index_hash, sb.block_hash, sb.height, bb.id, NULL, FALSE
FROM _staged_stacks_block sb
JOIN burn_block bb ON sb.burn_block_hash = bb.block_hash
ON CONFLICT (index_hash) DO NOTHING;

-- Link Stacks block parents
UPDATE stacks_block
SET parent_stacks_block_id = parent.id
FROM _staged_stacks_block stage, stacks_block parent
WHERE stacks_block.index_hash = stage.index_hash
  AND parent.index_hash = stage.parent_index_hash;

-- Merge Transactions (resolves tx_type, caller_principal, contract_id, contract_fn_id, args json)
INSERT INTO stacks_tx (
    stacks_block_id,
    tx_hash,
    stacks_tx_type_id,
    caller_principal_id,
    contract_id,
    contract_fn_id,
    contract_call_args_json
)
SELECT
    b.id,
    st.tx_hash,
    st.stacks_tx_type_id,
    p_caller.id,
    c.id,
    cf.id,
    st.contract_call_args_json
FROM _staged_stacks_tx st
JOIN stacks_block b
  ON st.block_index_hash = b.index_hash
JOIN principal p_caller
  ON st.caller_address = p_caller.address
LEFT JOIN principal p_issuer
  ON st.contract_issuer_address = p_issuer.address
LEFT JOIN contract c
  ON c.issuer_principal_id = p_issuer.id
 AND c.name = st.contract_name
LEFT JOIN contract_fn cf
  ON cf.contract_id = c.id
 AND cf.name = st.contract_fn_name
ON CONFLICT (stacks_block_id, tx_hash) DO NOTHING;

-- Mark blocks as fully indexed only if the writer explicitly marked them complete
UPDATE stacks_block
SET txs_indexed = TRUE
WHERE index_hash IN (
  SELECT block_index_hash
  FROM _staged_indexed_stacks_block
);
