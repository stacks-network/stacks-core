;; the .costs contract

;; Helper Functions

;; Return a Cost Specification with just a runtime cost
(define-private (runtime (r uint))
    {
        runtime: r,
        write_length: u0,
        write_count: u0,
        read_count: u0,
        read_length: u0,
    })

;; Linear cost-assessment function
(define-private (linear (n uint) (a uint) (b uint))
    (+ (* a n) b))

;; LogN cost-assessment function
(define-private (logn (n uint) (a uint) (b uint))
    (+ (* a (log2 n)) b))

;; NLogN cost-assessment function
(define-private (nlogn (n uint) (a uint) (b uint))
    (+ (* a (* n (log2 n))) b))


;; Cost Functions
(define-read-only (cost_analysis_type_annotate (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_type_check (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_type_lookup (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_visit (n uint))
    (runtime u1000))

(define-read-only (cost_analysis_iterable_func (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_option_cons (n uint))
    (runtime u1000))

(define-read-only (cost_analysis_option_check (n uint))
    (runtime u1000))

(define-read-only (cost_analysis_bind_name (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_list_items_check (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_check_tuple_get (n uint))
    (runtime (logn n u1000 u1000)))

(define-read-only (cost_analysis_check_tuple_merge (n uint)) 
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_check_tuple_cons (n uint))
    (runtime (nlogn n u1000 u1000)))

(define-read-only (cost_analysis_tuple_items_check (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_check_let (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_lookup_function (n uint))
    (runtime u1000))

(define-read-only (cost_analysis_lookup_function_types (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_lookup_variable_const (n uint))
    (runtime u1000))

(define-read-only (cost_analysis_lookup_variable_depth (n uint))
    (runtime (nlogn n u1000 u1000)))

;; ast-parse is a very expensive linear operation, 
;;   primarily because it does the work of capturing
;;   most of the analysis phase's linear cost, but also
;;   because the most expensive part of the analysis phase 
;;   is the ast
(define-read-only (cost_ast_parse (n uint))
    (runtime (linear n u10000 u1000)))

(define-read-only (cost_ast_cycle_detection (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_analysis_storage (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_analysis_use_trait_entry (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_analysis_get_function_entry (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_analysis_fetch_contract_entry (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_lookup_variable_depth (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_lookup_variable_size (n uint))
    (runtime (linear n u1000 u0)))

(define-read-only (cost_lookup_function (n uint))
    (runtime u1000))

(define-read-only (cost_bind_name (n uint))
    (runtime u1000))

(define-read-only (cost_inner_type_check_cost (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_user_function_application (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_let (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_if (n uint))
    (runtime u1000))

(define-read-only (cost_asserts (n uint))
    (runtime u1000))

(define-read-only (cost_map (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_filter (n uint))
    (runtime u1000))

(define-read-only (cost_len (n uint))
    (runtime u1000))

(define-read-only (cost_element_at (n uint))
    (runtime u1000))

(define-read-only (cost_index_of (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_fold (n uint))
    (runtime u1000))

(define-read-only (cost_list_cons (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_type_parse_step (n uint))
    (runtime u1000))

(define-read-only (cost_data_hash_cost (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_tuple_get (n uint))
    (runtime (nlogn n u1000 u1000)))

(define-read-only (cost_tuple_merge (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_tuple_cons (n uint))
    (runtime (nlogn n u1000 u1000)))

(define-read-only (cost_add (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_sub (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_mul (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_div (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_geq (n uint))
    (runtime u1000))

(define-read-only (cost_leq (n uint))
    (runtime u1000))

(define-read-only (cost_le (n uint))
    (runtime u1000))

(define-read-only (cost_ge  (n uint))
    (runtime u1000))

(define-read-only (cost_int_cast (n uint))
    (runtime u1000))

(define-read-only (cost_mod (n uint))
    (runtime u1000))

(define-read-only (cost_pow (n uint))
    (runtime u1000))

(define-read-only (cost_sqrti (n uint))
    (runtime u1000))

(define-read-only (cost_log2 (n uint))
    (runtime u1000))

(define-read-only (cost_xor (n uint))
    (runtime u1000))

(define-read-only (cost_not (n uint))
    (runtime u1000))

(define-read-only (cost_eq (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_begin (n uint))
    (runtime u1000))

(define-read-only (cost_hash160 (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_sha256 (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_sha512 (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_sha512t256 (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_keccak256 (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_secp256k1recover (n uint))
    (runtime u1000))

(define-read-only (cost_secp256k1verify (n uint))
    (runtime u1000))

(define-read-only (cost_print (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_some_cons (n uint))
    (runtime u1000))

(define-read-only (cost_ok_cons (n uint))
    (runtime u1000))

(define-read-only (cost_err_cons (n uint))
    (runtime u1000))

(define-read-only (cost_default_to (n uint))
    (runtime u1000))

(define-read-only (cost_unwrap_ret (n uint))
    (runtime u1000))

(define-read-only (cost_unwrap_err_or_ret (n uint))
    (runtime u1000))

(define-read-only (cost_is_okay (n uint))
    (runtime u1000))

(define-read-only (cost_is_none (n uint))
    (runtime u1000))

(define-read-only (cost_is_err (n uint))
    (runtime u1000))

(define-read-only (cost_is_some (n uint))
    (runtime u1000))

(define-read-only (cost_unwrap (n uint))
    (runtime u1000))

(define-read-only (cost_unwrap_err (n uint))
    (runtime u1000))

(define-read-only (cost_try_ret (n uint))
    (runtime u1000))

(define-read-only (cost_match (n uint))
    (runtime u1000))

(define-read-only (cost_or (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_and (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_append (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_concat (n uint))
    (runtime (linear n u1000 u1000)))

(define-read-only (cost_as_max_len (n uint))
    (runtime u1000))

(define-read-only (cost_contract_call (n uint))
    (runtime u1000))

(define-read-only (cost_contract_of (n uint))
    (runtime u1000))

(define-read-only (cost_principal_of (n uint))
    (runtime u1000))

(define-read-only (cost_at_block (n uint))
    {
        runtime: u1000,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_load_contract (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u0,
        write_count: u0,
        ;; set to 3 because of the associated metadata loads
        read_count: u3,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_create_map (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })

(define-read-only (cost_create_var (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u2,
        read_count: u0,
        read_length: u0
    })

(define-read-only (cost_create_nft (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })

(define-read-only (cost_create_ft (n uint))
    {
        runtime: u1000,
        write_length: u1,
        write_count: u2,
        read_count: u0,
        read_length: u0
    })

(define-read-only (cost_fetch_entry (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_set_entry (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u0
    })

(define-read-only (cost_fetch_var (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_set_var (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u0
    })

(define-read-only (cost_contract_storage (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })

(define-read-only (cost_block_info (n uint))
    {
        runtime: u1000,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_stx_balance (n uint))
    {
        runtime: u1000,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_stx_transfer (n uint))
    {
        runtime: u1000,
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_ft_mint (n uint))
    {
        runtime: u1000,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })

(define-read-only (cost_ft_transfer (n uint))
    {
        runtime: u1000,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })

(define-read-only (cost_ft_balance (n uint))
    {
        runtime: u1000,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_nft_mint (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_nft_transfer (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_nft_owner (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_ft_get_supply (n uint))
    {
        runtime: u1000,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_ft_burn (n uint))
    {
        runtime: u1000,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })

(define-read-only (cost_nft_burn (n uint))
    {
        runtime: (linear n u1000 u1000),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (poison_microblock (n uint))
    {
        runtime: u1000,
        write_length: u1,
        write_count: u1,
        read_count: u1, 
        read_length: u1
    })
