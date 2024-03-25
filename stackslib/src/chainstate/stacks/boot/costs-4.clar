
;; the .costs-4 contract

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
    (runtime (linear n u1 u2)))

(define-read-only (cost_analysis_type_check (n uint))
    (runtime (linear n u39 u0)))

(define-read-only (cost_analysis_type_lookup (n uint))
    (runtime (linear n u1 u9)))

(define-read-only (cost_analysis_visit (n uint))
    (runtime u1))

(define-read-only (cost_analysis_iterable_func (n uint))
    (runtime (linear n u2 u10)))

(define-read-only (cost_analysis_option_cons (n uint))
    (runtime u2))

(define-read-only (cost_analysis_option_check (n uint))
    (runtime u2))

(define-read-only (cost_analysis_bind_name (n uint))
    (runtime (linear n u1 u25)))

(define-read-only (cost_analysis_list_items_check (n uint))
    (runtime (linear n u1 u7)))

(define-read-only (cost_analysis_check_tuple_get (n uint))
    (runtime (logn n u1 u1)))

(define-read-only (cost_analysis_check_tuple_merge (n uint))
    (runtime (nlogn n u19 u11)))

(define-read-only (cost_analysis_check_tuple_cons (n uint))
    (runtime (nlogn n u2 u85)))

(define-read-only (cost_analysis_tuple_items_check (n uint))
    (runtime (linear n u1 u44)))

(define-read-only (cost_analysis_check_let (n uint))
    (runtime (linear n u1 u6)))

(define-read-only (cost_analysis_lookup_function (n uint))
    (runtime u11))

(define-read-only (cost_analysis_lookup_function_types (n uint))
    (runtime (linear n u1 u15)))

(define-read-only (cost_analysis_lookup_variable_const (n uint))
    (runtime u12))

(define-read-only (cost_analysis_lookup_variable_depth (n uint))
    (runtime (nlogn n u1 u4)))

(define-read-only (cost_ast_parse (n uint))
    (runtime (linear n u14 u82)))

(define-read-only (cost_analysis_storage (n uint))
    {
        runtime: (linear n u2 u103),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_analysis_get_function_entry (n uint))
    {
        runtime: (linear n u46 u905),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_analysis_fetch_contract_entry (n uint))
    (runtime (linear n u1 u400)))

(define-read-only (cost_lookup_variable_depth (n uint))
    (runtime (linear n u1 u4)))

(define-read-only (cost_lookup_variable_size (n uint))
    (runtime (linear n u1 u12)))

(define-read-only (cost_lookup_function (n uint))
    (runtime u7))

(define-read-only (cost_bind_name (n uint))
    (runtime u171))

(define-read-only (cost_inner_type_check_cost (n uint))
    (runtime (linear n u1 u19)))

(define-read-only (cost_user_function_application (n uint))
    (runtime (linear n u18 u1)))

(define-read-only (cost_let (n uint))
    (runtime (linear n u50 u4)))

(define-read-only (cost_if (n uint))
    (runtime u96))

(define-read-only (cost_asserts (n uint))
    (runtime u80))

(define-read-only (cost_map (n uint))
    (runtime (linear n u1599 u837)))

(define-read-only (cost_filter (n uint))
    (runtime u348))

(define-read-only (cost_len (n uint))
    (runtime u547))

(define-read-only (cost_element_at (n uint))
    (runtime u389))

(define-read-only (cost_index_of (n uint))
    (runtime (linear n u1 u126)))

(define-read-only (cost_fold (n uint))
    (runtime u402))

(define-read-only (cost_list_cons (n uint))
    (runtime (linear n u25 u77)))

(define-read-only (cost_type_parse_step (n uint))
    (runtime u4))

(define-read-only (cost_tuple_get (n uint))
    (runtime (nlogn n u2 u209)))

(define-read-only (cost_tuple_merge (n uint))
    (runtime (linear n u2 u815)))

(define-read-only (cost_tuple_cons (n uint))
    (runtime (nlogn n u6 u1538)))

(define-read-only (cost_add (n uint))
    (runtime (linear n u13 u77)))

(define-read-only (cost_sub (n uint))
    (runtime (linear n u13 u77)))

(define-read-only (cost_mul (n uint))
    (runtime (linear n u15 u76)))

(define-read-only (cost_div (n uint))
    (runtime (linear n u15 u76)))

(define-read-only (cost_geq (n uint))
    (runtime (linear n u1 u86)))

(define-read-only (cost_leq (n uint))
    (runtime (linear n u1 u86)))

(define-read-only (cost_le (n uint))
    (runtime (linear n u1 u86)))

(define-read-only (cost_ge (n uint))
    (runtime (linear n u1 u86)))

(define-read-only (cost_int_cast (n uint))
    (runtime u89))

(define-read-only (cost_mod (n uint))
    (runtime u100))

(define-read-only (cost_pow (n uint))
    (runtime u102))

(define-read-only (cost_sqrti (n uint))
    (runtime u90))

(define-read-only (cost_log2 (n uint))
    (runtime u86))

(define-read-only (cost_xor (n uint))
    (runtime (linear n u13 u77)))

(define-read-only (cost_not (n uint))
    (runtime u89))

(define-read-only (cost_eq (n uint))
    (runtime (linear n u14 u80)))

(define-read-only (cost_begin (n uint))
    (runtime u101))

(define-read-only (cost_hash160 (n uint))
    (runtime (linear n u1 u190)))

(define-read-only (cost_sha256 (n uint))
    (runtime (linear n u1 u146)))

(define-read-only (cost_sha512 (n uint))
    (runtime (linear n u1 u151)))

(define-read-only (cost_sha512t256 (n uint))
    (runtime (linear n u1 u151)))

(define-read-only (cost_keccak256 (n uint))
    (runtime (linear n u1 u170)))

(define-read-only (cost_secp256k1recover (n uint))
    (runtime u7534))

(define-read-only (cost_secp256k1verify (n uint))
    (runtime u7268))

(define-read-only (cost_some_cons (n uint))
    (runtime u115))

(define-read-only (cost_ok_cons (n uint))
    (runtime u115))

(define-read-only (cost_err_cons (n uint))
    (runtime u115))

(define-read-only (cost_default_to (n uint))
    (runtime u160))

(define-read-only (cost_unwrap_ret (n uint))
    (runtime u197))

(define-read-only (cost_unwrap_err_or_ret (n uint))
    (runtime u198))

(define-read-only (cost_is_okay (n uint))
    (runtime u176))

(define-read-only (cost_is_none (n uint))
    (runtime u135))

(define-read-only (cost_is_err (n uint))
    (runtime u179))

(define-read-only (cost_is_some (n uint))
    (runtime u134))

(define-read-only (cost_unwrap (n uint))
    (runtime u164))

(define-read-only (cost_unwrap_err (n uint))
    (runtime u163))

(define-read-only (cost_try_ret (n uint))
    (runtime u169))

(define-read-only (cost_match (n uint))
    (runtime u176))

(define-read-only (cost_or (n uint))
    (runtime (linear n u6 u73)))

(define-read-only (cost_and (n uint))
    (runtime (linear n u6 u73)))

(define-read-only (cost_append (n uint))
    (runtime (linear n u27 u125)))

(define-read-only (cost_concat (n uint))
    (runtime (linear n u20 u283)))

(define-read-only (cost_as_max_len (n uint))
    (runtime u263))

(define-read-only (cost_contract_call (n uint))
    (runtime u82))

(define-read-only (cost_contract_of (n uint))
    (runtime u14798))

(define-read-only (cost_principal_of (n uint))
    (runtime u861))


(define-read-only (cost_at_block (n uint))
    {
        runtime: u966,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_load_contract (n uint))
    {
        runtime: (linear n u1 u7),
        write_length: u0,
        write_count: u0,
        ;; set to 3 because of the associated metadata loads
        read_count: u3,
        read_length: (linear n u1 u1)
    })


(define-read-only (cost_create_map (n uint))
    {
        runtime: (linear n u2 u1689),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_create_var (n uint))
    {
        runtime: (linear n u6 u2571),
        write_length: (linear n u1 u1),
        write_count: u2,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_create_nft (n uint))
    {
        runtime: (linear n u1 u1621),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_create_ft (n uint))
    {
        runtime: u1862,
        write_length: u1,
        write_count: u2,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_fetch_entry (n uint))
    {
        runtime: (linear n u1 u2636),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })


(define-read-only (cost_set_entry (n uint))
    {
        runtime: (linear n u5 u2050),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u0
    })


(define-read-only (cost_fetch_var (n uint))
    {
        runtime: (linear n u3 u59126),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })


(define-read-only (cost_set_var (n uint))
    {
        runtime: (linear n u5 u1017),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u0
    })


(define-read-only (cost_contract_storage (n uint))
    {
        runtime: (linear n u8 u5569),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_block_info (n uint))
    {
        runtime: u3202,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_stx_balance (n uint))
    {
        runtime: u4523,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_stx_transfer (n uint))
    {
        runtime: u6800,
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_ft_mint (n uint))
    {
        runtime: u939,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })


(define-read-only (cost_ft_transfer (n uint))
    {
        runtime: u376,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })


(define-read-only (cost_ft_balance (n uint))
    {
        runtime: u344,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_nft_mint (n uint))
    {
        runtime: (linear n u6 u1624),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_nft_transfer (n uint))
    {
        runtime: (linear n u6 u1593),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_nft_owner (n uint))
    {
        runtime: (linear n u7 u1634),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_ft_get_supply (n uint))
    {
        runtime: u295,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_ft_burn (n uint))
    {
        runtime: u376,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })


(define-read-only (cost_nft_burn (n uint))
    {
        runtime: (linear n u6 u1593),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (poison_microblock (n uint))
    {
        runtime: u15137,
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_buff_to_int_le (n uint))
    (runtime u92))

(define-read-only (cost_buff_to_uint_le (n uint))
    (runtime u92))

(define-read-only (cost_buff_to_int_be (n uint))
    (runtime u92))

(define-read-only (cost_buff_to_uint_be (n uint))
    (runtime u92))

(define-read-only (cost_is_standard (n uint))
    (runtime u77))

(define-read-only (cost_principal_destruct (n uint))
    (runtime u194))

(define-read-only (cost_principal_construct (n uint))
    (runtime u222))

(define-read-only (cost_string_to_int (n uint))
    (runtime u114))

(define-read-only (cost_string_to_uint (n uint))
    (runtime u114))

(define-read-only (cost_int_to_ascii (n uint))
    (runtime u95))

(define-read-only (cost_int_to_utf8 (n uint))
    (runtime u113))


(define-read-only (cost_burn_block_info (n uint))
    {
        runtime: u101332,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_stx_account (n uint))
    {
        runtime: u5780,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_slice (n uint))
    (runtime u493))

(define-read-only (cost_to_consensus_buff (n uint))
    (runtime (linear n u1 u174)))

(define-read-only (cost_from_consensus_buff (n uint))
    (runtime (nlogn n u2 u162)))


(define-read-only (cost_stx_transfer_memo (n uint))
    {
        runtime: u6841,
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_replace_at (n uint))
    (runtime (linear n u1 u144)))

(define-read-only (cost_as_contract (n uint))
    (runtime u84))

(define-read-only (cost_bitwise_and (n uint))
    (runtime (linear n u13 u76)))

(define-read-only (cost_bitwise_or (n uint))
    (runtime (linear n u13 u77)))

(define-read-only (cost_bitwise_not (n uint))
    (runtime u86))

(define-read-only (cost_bitwise_left_shift (n uint))
    (runtime u100))

(define-read-only (cost_bitwise_right_shift (n uint))
    (runtime u99))

