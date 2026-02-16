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

//! Per-thread profiler state: node arena, active-span stack, and result materialisation.
//! All types are `pub(crate)`.

use std::time::Instant;

use crate::{Counter, ProfileStats, Record, SpanId, Tag};

/// Index into the per-thread node arena (`ThreadState::nodes`).
pub type NodeId = u32;

/// A single node in the per-thread profile arena.
///
/// Nodes are keyed by `(SpanId pointer, Tag)`.  Multiple entries of the same span under the same
/// parent **share** a node; timing is accumulated.
#[derive(Debug)]
pub struct Node {
    pub id: &'static SpanId,
    pub tag: Option<Tag>,

    pub wall_time_ns: u64,
    pub cpu_time_ns: u64,
    pub entered_count: usize,
    pub sampled_count: usize,

    pub children: Vec<NodeId>,
    pub last_child: Option<NodeId>,

    pub records: Vec<Record>,
    pub counters: Vec<Counter>,
}

impl Node {
    /// Returns `true` if this node matches the given `(SpanId, Tag)` key.
    #[inline(always)]
    pub fn key_eq(&self, id: &'static SpanId, tag: Option<Tag>) -> bool {
        // Fast path: callsite SpanIds are typically pointer-unique.
        std::ptr::eq(self.id, id) && self.tag == tag
    }
}

/// Discriminates timed vs count-only entries on the active stack.
#[derive(Debug)]
pub enum ActiveKind {
    Timed {
        start_wall: Instant,
        start_cpu_ns: u64,
    },
    CountOnly,
}

/// One frame on the per-thread active-span stack.
#[derive(Debug)]
pub struct ActiveFrame {
    pub node: NodeId,
    pub kind: ActiveKind,
}

/// Per-thread profiler state: a flat node arena plus an active-span stack.
#[derive(Debug)]
pub struct ThreadState {
    /// Active-span stack (LIFO).  The top frame is the current parent.
    pub stack: Vec<ActiveFrame>,
    /// Flat arena — nodes are addressed by [`NodeId`] (index).
    pub nodes: Vec<Node>,
    /// Top-level root node ids (spans entered with no parent).
    pub roots: Vec<NodeId>,
    /// Last-seen root, for fast consecutive-root deduplication.
    pub roots_last_child: Option<NodeId>,
}

impl ThreadState {
    /// Create an empty thread state with pre-allocated capacity.
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(64),
            nodes: Vec::with_capacity(256),
            roots: Vec::with_capacity(16),
            roots_last_child: None,
        }
    }

    /// Append a fresh zero-initialised node to the arena and return its id.
    #[inline(always)]
    pub fn alloc_node(&mut self, id: &'static SpanId, tag: Option<Tag>) -> NodeId {
        let idx = self.nodes.len();
        self.nodes.push(Node {
            id,
            tag,
            wall_time_ns: 0,
            cpu_time_ns: 0,
            entered_count: 0,
            sampled_count: 0,
            children: Vec::new(),
            last_child: None,
            records: Vec::with_capacity(4),
            counters: Vec::with_capacity(4),
        });
        idx as NodeId
    }

    /// Shared reference to a node by arena index.
    #[inline(always)]
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }

    /// Mutable reference to a node by arena index.
    #[inline(always)]
    pub fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.nodes[id as usize]
    }

    /// Look up or allocate a root-level node for the given `(SpanId, Tag)`.
    #[inline]
    pub fn find_or_create_root(&mut self, id: &'static SpanId, tag: Option<Tag>) -> NodeId {
        if let Some(last) = self.roots_last_child
            && self.node(last).key_eq(id, tag)
        {
            return last;
        }

        for &child in &self.roots {
            if self.node(child).key_eq(id, tag) {
                self.roots_last_child = Some(child);
                return child;
            }
        }

        let child = self.alloc_node(id, tag);
        self.roots.push(child);
        self.roots_last_child = Some(child);
        child
    }

    /// Look up or allocate a child node under `parent` for the given key.
    #[inline]
    pub fn find_or_create_child(
        &mut self,
        parent: NodeId,
        id: &'static SpanId,
        tag: Option<Tag>,
    ) -> NodeId {
        if let Some(last) = self.node(parent).last_child
            && self.node(last).key_eq(id, tag)
        {
            return last;
        }

        let children: &[NodeId] = &self.node(parent).children;
        for &child in children {
            if self.node(child).key_eq(id, tag) {
                self.node_mut(parent).last_child = Some(child);
                return child;
            }
        }

        let child = self.alloc_node(id, tag);
        let p = self.node_mut(parent);
        p.children.push(child);
        p.last_child = Some(child);
        child
    }

    /// The node id of the currently active (innermost) span, if any.
    #[inline(always)]
    pub fn current_parent(&self) -> Option<NodeId> {
        self.stack.last().map(|f| f.node)
    }

    /// Resolve (find-or-create) the node for a span, either as a root or as a child of the current
    /// parent.
    #[inline(always)]
    pub fn resolve_node(&mut self, id: &'static SpanId, tag: Option<Tag>) -> NodeId {
        match self.current_parent() {
            None => self.find_or_create_root(id, tag),
            Some(parent) => self.find_or_create_child(parent, id, tag),
        }
    }

    /// Convert the arena into a tree of [`ProfileStats`], consuming nodes in place.
    fn materialize_node(nodes: &mut Vec<Option<Node>>, node_id: NodeId) -> ProfileStats {
        let node = nodes[node_id as usize]
            .take()
            .expect("node already materialized or missing");

        let mut children = Vec::with_capacity(node.children.len());
        for &child_id in &node.children {
            children.push(Self::materialize_node(nodes, child_id));
        }

        ProfileStats {
            id: node.id,
            tag: node.tag,
            wall_time_ns: node.wall_time_ns,
            cpu_time_ns: node.cpu_time_ns,
            children,
            entered_count: node.entered_count,
            sampled_count: node.sampled_count,
            records: node.records,
            counters: node.counters,
        }
    }

    /// Drain the arena into a `Vec<ProfileStats>` tree and reset state.
    pub fn take_results_and_reset(&mut self) -> Vec<ProfileStats> {
        debug_assert!(
            self.stack.is_empty(),
            "take_results called while spans are still active"
        );

        let nodes = std::mem::take(&mut self.nodes);
        let roots = std::mem::take(&mut self.roots);

        let mut nodes_opt: Vec<Option<Node>> = nodes.into_iter().map(Some).collect();

        let mut out = Vec::with_capacity(roots.len());
        for root in roots {
            out.push(Self::materialize_node(&mut nodes_opt, root));
        }

        self.stack.clear();
        self.roots_last_child = None;

        out
    }

    /// Discard all accumulated nodes and reset the arena.
    pub fn clear(&mut self) {
        self.stack.clear();
        self.nodes.clear();
        self.roots.clear();
        self.roots_last_child = None;
    }
}
