//! Procedural macros for `stacks-profiler`. Exports the `#[profile]` attribute.
//!
//! Use via the re-export in the main `stacks-profiler` crate.

use darling::FromMeta;
use darling::ast::NestedMeta;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{ItemFn, Meta, parse_macro_input};

/// Behavior for unsampled calls when `sample_rate` is set.
#[derive(Debug, Default, Clone, Copy, FromMeta)]
enum UnsampledBehavior {
    /// Unsampled calls return `None` (default).
    #[default]
    #[darling(rename = "none")]
    None,
    /// Unsampled calls enter hierarchical suppression (nested spans become no-ops).
    #[darling(rename = "suppress")]
    Suppress,
    /// Unsampled calls preserve hierarchy + increment counts without timing.
    #[darling(rename = "count_only")]
    CountOnly,
}

/// Parsed arguments for `#[profile(...)]`.
#[derive(Debug, FromMeta)]
struct ProfileArgs<Name, SampleRate>
where
    Name: Into<Option<String>> + Default,
    SampleRate: Into<Option<usize>> + Default,
{
    #[darling(default)]
    name: Name,

    #[darling(default)]
    sample_rate: SampleRate,

    /// One of: "none" | "suppress" | "count_only".
    #[darling(default)]
    unsampled: UnsampledBehavior,
}

/// Emit runtime code that derives `context` and `auto_name` from
/// `type_name::<__StacksProfilerScope>()`.
fn build_context_extraction() -> TokenStream2 {
    quote! {
        let type_name = std::any::type_name::<__StacksProfilerScope>();
        // Strip the scope marker suffix to recover the enclosing function/module path.
        // `strip_suffix` avoids brittle fixed-length slicing.
        let full_path = type_name
            .strip_suffix("::__StacksProfilerScope")
            .unwrap_or(type_name);

        let (mut context, auto_name) = match full_path.rfind("::") {
            Some(idx) => (&full_path[..idx], &full_path[idx+2..]),
            None => ("", full_path),
        };

        if context.starts_with('<') {
            if let Some(idx) = context.find(" as ") {
                context = &context[1..idx];
            }
        }

        let last_colon = context.rfind("::").map(|i| i + 2).unwrap_or(0);
        if let Some(idx) = context[last_colon..].find('<') {
            context = &context[..last_colon + idx];
        }
    }
}

/// Emit the `OnceLock<SpanId>` init block. Uses `name` if provided, otherwise `auto_name`.
fn build_setup_block(name: Option<String>) -> TokenStream2 {
    let context_extraction = build_context_extraction();

    let span_id_init = match name {
        Some(custom_name) => quote! {
            stacks_profiler::Profiler::new_span_id(#custom_name).with_context(context)
        },
        None => quote! {
            stacks_profiler::Profiler::new_span_id(auto_name).with_context(context)
        },
    };

    quote! {
        {
            struct __StacksProfilerScope;

            static __PROFILER_SPAN_ID: std::sync::OnceLock<stacks_profiler::SpanId> =
                std::sync::OnceLock::new();
            __PROFILER_SPAN_ID.get_or_init(|| {
                #context_extraction
                #span_id_init
            })
        }
    }
}

/// Emit the `else` branch expression for unsampled calls.
fn unsampled_guard_expr(mode: UnsampledBehavior) -> TokenStream2 {
    match mode {
        UnsampledBehavior::None => quote! { None },
        UnsampledBehavior::Suppress => {
            quote! { Some(stacks_profiler::Profiler::begin_suppression()) }
        }
        UnsampledBehavior::CountOnly => {
            quote! { Some(stacks_profiler::Profiler::begin_span_count_only(__profiler_span_id, None)) }
        }
    }
}

/// Emit the guard-creation code. `None`/`Some(0|1)` → always timed; `Some(n)` → sampled 1/n.
fn build_guard_creation(sample_rate: Option<usize>, mode: UnsampledBehavior) -> TokenStream2 {
    let always_timed = quote! {
        let __profiler_guard =
            if stacks_profiler::Profiler::is_suppressed() {
                None
            } else {
                Some(stacks_profiler::Profiler::begin_span(__profiler_span_id, None))
            };
    };

    let Some(rate) = sample_rate else {
        return always_timed;
    };

    if rate <= 1 {
        return always_timed;
    }

    let unsampled = unsampled_guard_expr(mode);

    // The sampling check: bitmask for power-of-two rates, modulo otherwise.
    let should_sample = if rate.is_power_of_two() {
        let mask = rate - 1;
        quote! { (__n & #mask) == 0 }
    } else {
        quote! { (__n % #rate) == 0 }
    };

    quote! {
        let __profiler_guard =
            if stacks_profiler::Profiler::is_suppressed() {
                None
            } else {
                static __PROFILER_SAMPLE_COUNTER: std::sync::atomic::AtomicUsize =
                    std::sync::atomic::AtomicUsize::new(0);

                let __n =
                    __PROFILER_SAMPLE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let __should_sample = #should_sample;

                if __should_sample {
                    Some(stacks_profiler::Profiler::begin_span(__profiler_span_id, None))
                } else {
                    #unsampled
                }
            };
    }
}

/// Instrument a function with a profiling span. The span name defaults to the function name.
///
/// ```rust,ignore
/// #[profile]                          // span name: "parse_block"
/// fn parse_block() { /* ... */ }
///
/// #[profile(name = "net.rx")]         // custom span name
/// fn recv_packet() { /* ... */ }
///
/// #[profile(sample_rate = 100)]       // time ~1% of calls
/// fn hot_path() { /* ... */ }
///
/// #[profile(sample_rate = 100, unsampled = "suppress")]
/// fn request() { /* ... */ }          // suppress nested spans when unsampled
///
/// #[profile(sample_rate = 100, unsampled = "count_only")]
/// fn execute_tx() { /* ... */ }       // preserve hierarchy + counts when unsampled
/// ```
///
/// `sample_rate` and `unsampled` have the same semantics as `rate:` / `suppress` / `count_only`
/// on `span!`. Does not support tags — use `span!` directly if you need them.
///
/// `#[profile]` is not supported on `async fn`.
#[proc_macro_attribute]
pub fn profile(args: TokenStream, input: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(args with Punctuated::<Meta, Comma>::parse_terminated);
    let args_vec: Vec<NestedMeta> = attr_args.into_iter().map(NestedMeta::Meta).collect();

    let args = match ProfileArgs::from_list(&args_vec) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(e.write_errors()),
    };

    let input_fn = parse_macro_input!(input as ItemFn);
    if let Some(async_token) = &input_fn.sig.asyncness {
        return syn::Error::new_spanned(
            async_token,
            "#[profile] does not support async fn; use span!/measure! inside the function body",
        )
        .to_compile_error()
        .into();
    }

    let attrs = &input_fn.attrs;
    let vis = &input_fn.vis;
    let sig = &input_fn.sig;
    let block = &input_fn.block;

    let setup_block = build_setup_block(args.name);
    let guard_creation = build_guard_creation(args.sample_rate, args.unsampled);

    let output = quote! {
        #(#attrs)*
        #vis #sig {
            let __profiler_span_id = #setup_block;
            #guard_creation
            #block
        }
    };

    output.into()
}
