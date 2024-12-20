use clarity::vm::costs::ExecutionCost;

pub fn make_big_read_count_contract(limit: ExecutionCost, proportion: u64) -> String {
    let read_count = (limit.read_count * proportion) / 100;

    let read_lines = (0..read_count)
        .map(|_| format!("(var-get my-var)"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "
(define-data-var my-var uint u0)

(define-public (big-tx)
(begin
{}
(ok true)))
        ",
        read_lines
    )
}

#[cfg(test)]
mod tests {
    use stacks::core::BLOCK_LIMIT_MAINNET_21;

    use super::*;

    #[test]
    fn test_big_read_count_contract() {
        let limit = BLOCK_LIMIT_MAINNET_21;
        let proportion = 1;
        let code = make_big_read_count_contract(limit, proportion);
        println!("{}", code);
    }
}
