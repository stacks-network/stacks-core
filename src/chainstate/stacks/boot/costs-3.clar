
;; the .costs-3 contract

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
    (runtime (linear n u1 u9)))

(define-read-only (cost_analysis_type_check (n uint))
    (runtime (linear n u113 u1)))

(define-read-only (cost_analysis_type_lookup (n uint))
    (runtime (linear n u1 u4)))

(define-read-only (cost_analysis_visit (n uint))
    (runtime u1))

(define-read-only (cost_analysis_iterable_func (n uint))
    (runtime (linear n u2 u14)))

(define-read-only (cost_analysis_option_cons (n uint))
    (runtime u5))

(define-read-only (cost_analysis_option_check (n uint))
    (runtime u4))

(define-read-only (cost_analysis_bind_name (n uint))
    (runtime (linear n u1 u59)))

(define-read-only (cost_analysis_list_items_check (n uint))
    (runtime (linear n u2 u4)))

(define-read-only (cost_analysis_check_tuple_get (n uint))
    (runtime (logn n u1 u2)))

(define-read-only (cost_analysis_check_tuple_merge (n uint))
    (runtime (nlogn n u45 u49)))

(define-read-only (cost_analysis_check_tuple_cons (n uint))
    (runtime (nlogn n u3 u5)))

(define-read-only (cost_analysis_tuple_items_check (n uint))
    (runtime (linear n u1 u28)))

(define-read-only (cost_analysis_check_let (n uint))
    (runtime (linear n u1 u10)))

(define-read-only (cost_analysis_lookup_function (n uint))
    (runtime u18))

(define-read-only (cost_analysis_lookup_function_types (n uint))
    (runtime (linear n u1 u26)))

(define-read-only (cost_analysis_lookup_variable_const (n uint))
    (runtime u15))

(define-read-only (cost_analysis_lookup_variable_depth (n uint))
    (runtime (nlogn n u1 u12)))

(define-read-only (cost_ast_parse (n uint))
    (runtime (linear n u27 u81)))

(define-read-only (cost_ast_cycle_detection (n uint))
    (runtime (linear n u141 u72)))

(define-read-only (cost_analysis_storage (n uint))
    {
        runtime: (linear n u2 u94),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_analysis_use_trait_entry (n uint))
    {
        runtime: (linear n u9 u698),
        write_length: (linear n u1 u1),
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_analysis_fetch_contract_entry (n uint))
    {
        runtime: (linear n u1 u1516),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_analysis_get_function_entry (n uint))
    {
        runtime: (linear n u78 u1307),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })

(define-read-only (cost_lookup_variable_depth (n uint))
    (runtime (linear n u1 u1)))

(define-read-only (cost_lookup_variable_size (n uint))
    (runtime (linear n u2 u1)))

(define-read-only (cost_lookup_function (n uint))
    (runtime u16))

(define-read-only (cost_bind_name (n uint))
    (runtime u216))

(define-read-only (cost_inner_type_check_cost (n uint))
    (runtime (linear n u2 u5)))

(define-read-only (cost_user_function_application (n uint))
    (runtime (linear n u26 u5)))

(define-read-only (cost_let (n uint))
    (runtime (linear n u117 u178)))

(define-read-only (cost_if (n uint))
    (runtime u168))

(define-read-only (cost_asserts (n uint))
    (runtime u128))

(define-read-only (cost_map (n uint))
    (runtime (linear n u1198 u3067)))

(define-read-only (cost_filter (n uint))
    (runtime u407))

(define-read-only (cost_len (n uint))
    (runtime u429))

(define-read-only (cost_element_at (n uint))
    (runtime u498))

(define-read-only (cost_index_of (n uint))
    (runtime (linear n u1 u211)))

(define-read-only (cost_fold (n uint))
    (runtime u460))

(define-read-only (cost_list_cons (n uint))
    (runtime (linear n u14 u164)))

(define-read-only (cost_type_parse_step (n uint))
    (runtime u4))

(define-read-only (cost_tuple_get (n uint))
    (runtime (nlogn n u4 u1736)))

(define-read-only (cost_tuple_merge (n uint))
    (runtime (linear n u4 u408)))

(define-read-only (cost_tuple_cons (n uint))
    (runtime (nlogn n u10 u1876)))

(define-read-only (cost_add (n uint))
    (runtime (linear n u11 u125)))

(define-read-only (cost_sub (n uint))
    (runtime (linear n u11 u125)))

(define-read-only (cost_mul (n uint))
    (runtime (linear n u13 u125)))

(define-read-only (cost_div (n uint))
    (runtime (linear n u13 u125)))

(define-read-only (cost_geq (n uint))
    (runtime (linear n u7 u128)))

(define-read-only (cost_leq (n uint))
    (runtime (linear n u7 u128)))

(define-read-only (cost_le (n uint))
    (runtime (linear n u7 u128)))

(define-read-only (cost_ge (n uint))
    (runtime (linear n u7 u128)))

(define-read-only (cost_int_cast (n uint))
    (runtime u135))

(define-read-only (cost_mod (n uint))
    (runtime u141))

(define-read-only (cost_pow (n uint))
    (runtime u143))

(define-read-only (cost_sqrti (n uint))
    (runtime u142))

(define-read-only (cost_log2 (n uint))
    (runtime u133))

(define-read-only (cost_xor (n uint))
    (runtime (linear n u15 u129)))

(define-read-only (cost_not (n uint))
    (runtime u138))

(define-read-only (cost_eq (n uint))
    (runtime (linear n u7 u151)))

(define-read-only (cost_begin (n uint))
    (runtime u151))

(define-read-only (cost_hash160 (n uint))
    (runtime (linear n u1 u188)))

(define-read-only (cost_sha256 (n uint))
    (runtime (linear n u1 u100)))

(define-read-only (cost_sha512 (n uint))
    (runtime (linear n u1 u176)))

(define-read-only (cost_sha512t256 (n uint))
    (runtime (linear n u1 u56)))

(define-read-only (cost_keccak256 (n uint))
    (runtime (linear n u1 u127)))

(define-read-only (cost_secp256k1recover (n uint))
    (runtime u8655))

(define-read-only (cost_secp256k1verify (n uint))
    (runtime u8349))

(define-read-only (cost_print (n uint))
    (runtime (linear n u15 u1458)))

(define-read-only (cost_some_cons (n uint))
    (runtime u199))

(define-read-only (cost_ok_cons (n uint))
    (runtime u199))

(define-read-only (cost_err_cons (n uint))
    (runtime u199))

(define-read-only (cost_default_to (n uint))
    (runtime u268))

(define-read-only (cost_unwrap_ret (n uint))
    (runtime u274))

(define-read-only (cost_unwrap_err_or_ret (n uint))
    (runtime u302))

(define-read-only (cost_is_okay (n uint))
    (runtime u258))

(define-read-only (cost_is_none (n uint))
    (runtime u214))

(define-read-only (cost_is_err (n uint))
    (runtime u245))

(define-read-only (cost_is_some (n uint))
    (runtime u195))

(define-read-only (cost_unwrap (n uint))
    (runtime u252))

(define-read-only (cost_unwrap_err (n uint))
    (runtime u248))

(define-read-only (cost_try_ret (n uint))
    (runtime u240))

(define-read-only (cost_match (n uint))
    (runtime u264))

(define-read-only (cost_or (n uint))
    (runtime (linear n u3 u120)))

(define-read-only (cost_and (n uint))
    (runtime (linear n u3 u120)))

(define-read-only (cost_append (n uint))
    (runtime (linear n u73 u285)))

(define-read-only (cost_concat (n uint))
    (runtime (linear n u37 u220)))

(define-read-only (cost_as_max_len (n uint))
    (runtime u475))

(define-read-only (cost_contract_call (n uint))
    (runtime u134))

(define-read-only (cost_contract_of (n uint))
    (runtime u13400))

(define-read-only (cost_principal_of (n uint))
    (runtime u984))

(define-read-only (cost_at_block (n uint))
    {
        runtime: u1327,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_load_contract (n uint))
    {
        runtime: (linear n u1 u80),
        write_length: u0,
        write_count: u0,
        ;; set to 3 because of the associated metadata loads
        read_count: u3,
        read_length: (linear n u1 u1)
    })


(define-read-only (cost_create_map (n uint))
    {
        runtime: (linear n u1 u1564),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_create_var (n uint))
    {
        runtime: (linear n u7 u2025),
        write_length: (linear n u1 u1),
        write_count: u2,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_create_nft (n uint))
    {
        runtime: (linear n u1 u1570),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_create_ft (n uint))
    {
        runtime: u1831,
        write_length: u1,
        write_count: u2,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_fetch_entry (n uint))
    {
        runtime: (linear n u1 u1025),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })


(define-read-only (cost_set_entry (n uint))
    {
        runtime: (linear n u4 u1899),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u0
    })


(define-read-only (cost_fetch_var (n uint))
    {
        runtime: (linear n u1 u468),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: (linear n u1 u1)
    })


(define-read-only (cost_set_var (n uint))
    {
        runtime: (linear n u5 u655),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u1,
        read_length: u0
    })


(define-read-only (cost_contract_storage (n uint))
    {
        runtime: (linear n u11 u7165),
        write_length: (linear n u1 u1),
        write_count: u1,
        read_count: u0,
        read_length: u0
    })


(define-read-only (cost_block_info (n uint))
    {
        runtime: u6321,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_stx_balance (n uint))
    {
        runtime: u4294,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_stx_transfer (n uint))
    {
        runtime: u4640,
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_ft_mint (n uint))
    {
        runtime: u1479,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })


(define-read-only (cost_ft_transfer (n uint))
    {
        runtime: u549,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })


(define-read-only (cost_ft_balance (n uint))
    {
        runtime: u479,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_nft_mint (n uint))
    {
        runtime: (linear n u9 u575),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_nft_transfer (n uint))
    {
        runtime: (linear n u9 u572),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_nft_owner (n uint))
    {
        runtime: (linear n u9 u795),
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_ft_get_supply (n uint))
    {
        runtime: u420,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })


(define-read-only (cost_ft_burn (n uint))
    {
        runtime: u549,
        write_length: u1,
        write_count: u2,
        read_count: u2,
        read_length: u1
    })


(define-read-only (cost_nft_burn (n uint))
    {
        runtime: (linear n u9 u572),
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })


(define-read-only (poison_microblock (n uint))
    {
        runtime: u17485,
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_buff_to_int_le (n uint))
    (runtime u141))

(define-read-only (cost_buff_to_uint_le (n uint))
    (runtime u141))

(define-read-only (cost_buff_to_int_be (n uint))
    (runtime u141))

(define-read-only (cost_buff_to_uint_be (n uint))
    (runtime u141))

(define-read-only (cost_is_standard (n uint))
    (runtime u127))

(define-read-only (cost_principal_destruct (n uint))
    (runtime u314))

(define-read-only (cost_principal_construct (n uint))
    (runtime u398))

(define-read-only (cost_string_to_int (n uint))
    (runtime u168))

(define-read-only (cost_string_to_uint (n uint))
    (runtime u168))

(define-read-only (cost_int_to_ascii (n uint))
    (runtime u147))

(define-read-only (cost_int_to_utf8 (n uint))
    (runtime u181))


(define-read-only (cost_burn_block_info (n uint))
    {
        runtime: u96479,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_stx_account (n uint))
    {
        runtime: u4654,
        write_length: u0,
        write_count: u0,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_slice (n uint))
    (runtime u448))

(define-read-only (cost_to_consensus_buff (n uint))
    (runtime (linear n u1 u233)))

(define-read-only (cost_from_consensus_buff (n uint))
    (runtime (nlogn n u3 u185)))

(define-read-only (cost_stx_transfer_memo (n uint))
    {
        runtime: u4709,
        write_length: u1,
        write_count: u1,
        read_count: u1,
        read_length: u1
    })

(define-read-only (cost_replace_at (n uint))
    (runtime (linear n u1 u561)))

(define-read-only (cost_as_contract (n uint))
    (runtime u138))

(define-read-only (cost_bitwise_and (n uint))
    (runtime (linear n u15 u129)))

(define-read-only (cost_bitwise_or (n uint))
    (runtime (linear n u15 u129)))

(define-read-only (cost_bitwise_not (n uint))
    (runtime u147))

(define-read-only (cost_bitwise_left_shift (n uint))
    (runtime u167))

(define-read-only (cost_bitwise_right_shift (n uint))
    (runtime u167))
