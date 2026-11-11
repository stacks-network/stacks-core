// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Pretty-printers for hook trace events and reconstructed call trees. Used largely for visually
//! inspecting test traces for correctness.

use super::{ArgKind, ArgSource, TraceCallKind, TraceCallTarget, TraceEvent, TraceResult, Value};

/// Prints both the linear event trace and reconstructed call tree for the current test.
pub fn print_trace(events: &[TraceEvent]) {
    let current_thread = std::thread::current();
    let test_name = current_thread
        .name()
        .and_then(|name| name.split("::").last())
        .unwrap_or("unknown test");
    println!();
    println!("=== {test_name} trace ===");
    for event in events {
        println!("{}", render_trace_event(event));
    }
    println!();
    println!("=== {test_name} call tree ===");
    print!("{}", render_clarity_call_tree(events));
}

/// Renders a single [`TraceEvent`] as one indented, human-readable line. Indentation follows the
/// call/argument nesting depth recorded on each event, producing a tree:
///
/// ```text
/// 𝑓(𝑥) "trace-test.entry" [public] (1 arg)
///   𝑎₁ "seed" = u0
///   𝑓(𝑥) "trace-test.foo" [private] (2 args)
///     𝑓(𝑎₁) "a"
///       𝑓(𝑥) "+" [builtin] (2 args)
///       ⏎ "+" ⇒ u42
///     𝑎₁ "a" = u42
///   ⏎ "trace-test.foo" ⇒ u84
/// ⏎ "trace-test.entry" ⇒ (ok u84)
/// ```
pub fn render_trace_event(event: &TraceEvent) -> String {
    match event {
        TraceEvent::BeginCall {
            depth,
            kind,
            target,
            arg_count,
            ..
        } => format!(
            "{}𝑓(𝑥) {} [{}] ({})",
            indent(*depth),
            render_target(target),
            render_kind(*kind),
            arg_count_label(*arg_count),
        ),
        TraceEvent::BeginArgumentEval {
            depth,
            arg_index,
            arg_name,
        } => format!(
            "{}𝑓(𝑎{}) \"{arg_name}\"",
            indent(*depth),
            subscript(arg_index + 1),
        ),
        TraceEvent::ArgumentValue {
            depth,
            arg_index,
            arg_name,
            value,
            ..
        } => format!(
            "{}𝑎{} \"{arg_name}\" = {value}",
            indent(*depth),
            subscript(arg_index + 1),
        ),
        TraceEvent::FinishCall {
            depth,
            target,
            result,
            ..
        } => format!(
            "{}⏎ {} ⇒ {}",
            indent(*depth),
            render_target(target),
            render_result(result),
        ),
    }
}

/// Returns the two-space-per-level indentation used by the linear trace renderer.
fn indent(depth: usize) -> String {
    "  ".repeat(depth)
}

/// Returns the human-readable label for a traced call kind.
fn render_kind(kind: TraceCallKind) -> &'static str {
    match kind {
        TraceCallKind::Builtin => "builtin",
        TraceCallKind::UserPublic => "public",
        TraceCallKind::UserPrivate => "private",
        TraceCallKind::UserReadOnly => "read-only",
    }
}

/// Renders a call target in the quoted form used by the linear trace.
fn render_target(target: &TraceCallTarget) -> String {
    match target {
        TraceCallTarget::Builtin(name) => format!("\"{name}\""),
        TraceCallTarget::UserDefined {
            contract_name,
            function_name,
        } => format!("\"{contract_name}.{function_name}\""),
    }
}

/// Renders a traced success value or error for diagnostic output.
fn render_result(result: &TraceResult) -> String {
    match result {
        TraceResult::Ok(value) => value.to_string(),
        TraceResult::Err(err) => format!("ERR {err}"),
    }
}

/// Formats an argument count with the appropriate singular or plural suffix.
fn arg_count_label(arg_count: usize) -> String {
    if arg_count == 1 {
        "1 arg".to_string()
    } else {
        format!("{arg_count} args")
    }
}

/// Renders `n` using Unicode subscript digits (e.g. `12` -> `₁₂`).
fn subscript(n: usize) -> String {
    n.to_string()
        .chars()
        .map(|digit| match digit {
            '0' => '₀',
            '1' => '₁',
            '2' => '₂',
            '3' => '₃',
            '4' => '₄',
            '5' => '₅',
            '6' => '₆',
            '7' => '₇',
            '8' => '₈',
            '9' => '₉',
            other => other,
        })
        .collect()
}

/// A call reconstructed from the flat [`TraceEvent`] stream: its resolved argument values, its
/// result, and the nested calls that produced those arguments.
struct CallNode {
    /// Category of callable represented by this node.
    kind: TraceCallKind,
    /// Builtin or user-defined call target.
    target: TraceCallTarget,
    /// `(arg_name, evaluated_value)` pairs, in evaluation order. Empty for special forms (`if`,
    /// `and`, ...) that evaluate their own arguments and report none.
    args: Vec<(String, Value)>,
    /// Per-argument source classification, captured when the call opened.
    arg_sources: Vec<ArgSource>,
    /// Result reported when the call finished, or `None` if it remains open.
    result: Option<TraceResult>,
    /// Calls nested below this call in execution order.
    children: Vec<CallNode>,
    /// The argument index of the *parent* that this call produces, if it was invoked while
    /// evaluating one of the parent's arguments (vs. inside the parent's body).
    producing_arg: Option<usize>,
    /// Cross-reference label (`𝑓ₙ`) assigned when this call produces a parent call-argument.
    label: Option<usize>,
}

/// Reconstructs the call forest from the linear event stream using begin/finish as push/pop.
/// Argument values attach to the call on top of the stack — which is always the consuming call,
/// since a callable's `did_evaluate_call_argument` fires only after the nested calls that produced
/// that argument have finished and been popped.
///
/// Each child records `producing_arg`: the count of the parent's arguments reported so far when the
/// child opened. If that index is within the parent's argument list, the child produced that
/// argument (left-to-right arg evaluation); otherwise it ran in the parent's body.
fn build_call_forest(events: &[TraceEvent]) -> Vec<CallNode> {
    let mut roots = Vec::new();
    let mut stack: Vec<CallNode> = Vec::new();
    for event in events {
        match event {
            TraceEvent::BeginCall {
                kind,
                target,
                arg_sources,
                ..
            } => {
                let producing_arg = stack.last().map(|parent| parent.args.len());
                stack.push(CallNode {
                    kind: *kind,
                    target: target.clone(),
                    args: Vec::new(),
                    arg_sources: arg_sources.clone(),
                    result: None,
                    children: Vec::new(),
                    producing_arg,
                    label: None,
                });
            }
            TraceEvent::ArgumentValue {
                arg_name, value, ..
            } => {
                if let Some(node) = stack.last_mut() {
                    node.args.push((arg_name.clone(), value.clone()));
                }
            }
            TraceEvent::FinishCall { result, .. } => {
                if let Some(mut node) = stack.pop() {
                    node.result = Some(result.clone());
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => roots.push(node),
                    }
                }
            }
            TraceEvent::BeginArgumentEval { .. } => {}
        }
    }
    roots
}

/// Assigns a fresh, globally-unique `𝑓ₙ` label (in reading order) to every call that produces one
/// of its parent's call-typed arguments.
fn assign_labels(node: &mut CallNode, next_label: &mut usize) {
    for child in &mut node.children {
        if child.producing_arg.is_some_and(|index| {
            node.arg_sources
                .get(index)
                .is_some_and(|source| source.kind == ArgKind::Call)
        }) {
            child.label = Some(*next_label);
            *next_label += 1;
        }
        assign_labels(child, next_label);
    }
}

/// Renders the call tree as executed Clarity-ish call notation. Arguments are annotated with their
/// origin: `𝑥(name)=value` for variable references, `𝑓ₙ=value` for values produced by a nested
/// call (cross-referenced to that child's trailing `(𝑓ₙ)` tag), and bare `value` for literals.
///
/// ```text
/// (trace-fold.accumulate item=u1 acc=u0) ⇒ u2
///     (+ 𝑥(acc)=u0 𝑓₁=u2) ⇒ u2
///         (* 𝑥(item)=u1 u2) ⇒ u2  (𝑓₁)
/// ```
pub fn render_clarity_call_tree(events: &[TraceEvent]) -> String {
    let mut roots = build_call_forest(events);
    let mut next_label = 1;
    for root in &mut roots {
        assign_labels(root, &mut next_label);
    }
    let mut out = String::new();
    for root in &roots {
        render_call_node(root, 0, &mut out);
    }
    out
}

/// Appends one call node and its descendants to the rendered call tree.
fn render_call_node(node: &CallNode, depth: usize, out: &mut String) {
    let result = node
        .result
        .as_ref()
        .map(render_result)
        .unwrap_or_else(|| "<unfinished>".to_string());
    let head = clarity_call_name(&node.target);
    let args = render_call_args(node);
    // s-expression head notation, per node: `(head args)`. Nested calls stay on their own indented
    // lines (we do NOT inline children into the parent expression, which is what would collapse the
    // whole trace onto one line).
    let call = if args.is_empty() {
        format!("({head})")
    } else {
        format!("({head} {args})")
    };
    // Trailing cross-reference tag: this call produces its parent's `𝑓ₙ` argument.
    let rendered_result = match node.label {
        Some(label) => format!("𝑓{}={result}", subscript(label)),
        None => result,
    };
    out.push_str(&format!(
        "{}{call} ⇒ {rendered_result}\n",
        "    ".repeat(depth)
    ));
    for child in &node.children {
        render_call_node(child, depth + 1, out);
    }
}

/// Renders a target as the unquoted Clarity call name used in the call tree.
fn clarity_call_name(target: &TraceCallTarget) -> String {
    match target {
        TraceCallTarget::Builtin(name) => name.clone(),
        TraceCallTarget::UserDefined {
            contract_name,
            function_name,
        } => format!("{contract_name}.{function_name}"),
    }
}

/// Looks up the `𝑓ₙ` label of the child call that produced argument `index`.
fn child_label_for_arg(node: &CallNode, index: usize) -> Option<usize> {
    node.children
        .iter()
        .find(|child| child.producing_arg == Some(index))
        .and_then(|child| child.label)
}

/// Renders a node's resolved arguments with source-origin annotations.
fn render_call_args(node: &CallNode) -> String {
    // Special forms report no evaluated arguments; fall back to raw source expressions.
    if node.args.is_empty() {
        return node
            .arg_sources
            .iter()
            .map(|source| source.text.clone())
            .collect::<Vec<_>>()
            .join(" ");
    }
    node.args
        .iter()
        .enumerate()
        .map(|(index, (arg_name, value))| {
            match node.arg_sources.get(index).map(|source| &source.kind) {
                Some(ArgKind::Variable(name)) => format!("𝑥({name})={value}"),
                Some(ArgKind::Call) => match child_label_for_arg(node, index) {
                    Some(label) => format!("𝑓{}={value}", subscript(label)),
                    None => value.to_string(),
                },
                Some(ArgKind::Literal) => value.to_string(),
                // Pre-evaluated args: keep the user-function parameter name where we have one;
                // builtins have only synthetic names, so render positionally.
                _ => match node.kind {
                    TraceCallKind::Builtin => value.to_string(),
                    _ => format!("{arg_name}={value}"),
                },
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
