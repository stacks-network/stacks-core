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

//! Version-neutral semantic node model for value-shape descriptors.

use crate::representations::ClarityName;
use crate::types::{CharType, SequenceData, Value};

/// Semantic reconstruction metadata derived from one or more active Clarity values.
///
/// A versioned [`ValueShape`](super::ValueShape) descriptor encodes this node tree on the wire;
/// `ActiveShape` itself owns neither encoded bytes nor a wire version.
///
/// Wire-version modules own the byte representation of this model. Keeping the model independent
/// lets record and shape grammars evolve separately without duplicating value traversal or merging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveShape {
    /// Signed integer scalar.
    Int,
    /// Unsigned integer scalar.
    UInt,
    /// Boolean scalar.
    Bool,
    /// Byte buffer sequence.
    Buffer,
    /// ASCII string sequence.
    Ascii,
    /// UTF-8 string sequence.
    Utf8,
    /// Standard, contract, or callable contract principal identity.
    Principal,
    /// Optional with only its active child shape, when present.
    Optional(Option<Box<ActiveShape>>),
    /// Response with one or both observed branch shapes.
    Response {
        /// Observed committed branch shape.
        ok: Option<Box<ActiveShape>>,
        /// Observed error branch shape.
        err: Option<Box<ActiveShape>>,
    },
    /// Canonically ordered tuple field names and active child shapes.
    Tuple(Vec<(ClarityName, ActiveShape)>),
    /// Empty list or non-empty list with one shared element shape.
    List(Option<Box<ActiveShape>>),
    /// Per-element shapes for a historical list whose active shapes cannot merge.
    ListElements(Vec<ActiveShape>),
}

impl ActiveShape {
    /// Derive reconstruction metadata solely from an active value.
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Int(_) => Self::Int,
            Value::UInt(_) => Self::UInt,
            Value::Bool(_) => Self::Bool,
            Value::Sequence(SequenceData::Buffer(_)) => Self::Buffer,
            Value::Sequence(SequenceData::String(CharType::ASCII(_))) => Self::Ascii,
            Value::Sequence(SequenceData::String(CharType::UTF8(_))) => Self::Utf8,
            Value::Principal(_) | Value::CallableContract(_) => Self::Principal,
            Value::Optional(optional) => {
                Self::Optional(optional.data.as_deref().map(Self::from_value).map(Box::new))
            }
            Value::Response(response) => {
                let child = Box::new(Self::from_value(&response.data));
                if response.committed {
                    Self::Response {
                        ok: Some(child),
                        err: None,
                    }
                } else {
                    Self::Response {
                        ok: None,
                        err: Some(child),
                    }
                }
            }
            Value::Tuple(tuple) => Self::Tuple(
                tuple
                    .data_map
                    .iter()
                    .map(|(name, value)| (name.clone(), Self::from_value(value)))
                    .collect(),
            ),
            Value::Sequence(SequenceData::List(list)) => {
                let Some((first, rest)) = list.data.split_first() else {
                    return Self::List(None);
                };
                let first_shape = Self::from_value(first);
                if rest
                    .iter()
                    .all(|element| first_shape.matches_value(element))
                {
                    return Self::List(Some(Box::new(first_shape)));
                }
                let elements = list.data.iter().map(Self::from_value).collect::<Vec<_>>();
                list_shape_from_elements(elements)
            }
        }
    }

    /// Return whether this shape can reconstruct one active value without widening.
    fn matches_value(&self, value: &Value) -> bool {
        match (self, value) {
            (Self::Int, Value::Int(_))
            | (Self::UInt, Value::UInt(_))
            | (Self::Bool, Value::Bool(_))
            | (Self::Buffer, Value::Sequence(SequenceData::Buffer(_)))
            | (Self::Ascii, Value::Sequence(SequenceData::String(CharType::ASCII(_))))
            | (Self::Utf8, Value::Sequence(SequenceData::String(CharType::UTF8(_))))
            | (Self::Principal, Value::Principal(_) | Value::CallableContract(_)) => true,
            (Self::Optional(_), Value::Optional(optional)) if optional.data.is_none() => true,
            (Self::Optional(Some(shape)), Value::Optional(optional)) => optional
                .data
                .as_deref()
                .is_some_and(|value| shape.matches_value(value)),
            (
                Self::Response {
                    ok: Some(shape), ..
                },
                Value::Response(response),
            ) if response.committed => shape.matches_value(&response.data),
            (
                Self::Response {
                    err: Some(shape), ..
                },
                Value::Response(response),
            ) if !response.committed => shape.matches_value(&response.data),
            (Self::Tuple(fields), Value::Tuple(tuple)) => {
                fields.len() == tuple.data_map.len()
                    && fields.iter().zip(&tuple.data_map).all(
                        |((expected_name, expected_shape), (name, value))| {
                            expected_name == name && expected_shape.matches_value(value)
                        },
                    )
            }
            (Self::List(None), Value::Sequence(SequenceData::List(list))) => list.data.is_empty(),
            (Self::List(Some(shape)), Value::Sequence(SequenceData::List(list))) => {
                list.data.iter().all(|value| shape.matches_value(value))
            }
            (Self::ListElements(shapes), Value::Sequence(SequenceData::List(list))) => {
                shapes.len() == list.data.len()
                    && shapes
                        .iter()
                        .zip(&list.data)
                        .all(|(shape, value)| shape.matches_value(value))
            }
            _ => false,
        }
    }

    /// Merge two active shapes when one canonical shared shape can reconstruct both.
    fn merge(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Int, Self::Int) => Some(Self::Int),
            (Self::UInt, Self::UInt) => Some(Self::UInt),
            (Self::Bool, Self::Bool) => Some(Self::Bool),
            (Self::Buffer, Self::Buffer) => Some(Self::Buffer),
            (Self::Ascii, Self::Ascii) => Some(Self::Ascii),
            (Self::Utf8, Self::Utf8) => Some(Self::Utf8),
            (Self::Principal, Self::Principal) => Some(Self::Principal),
            (Self::Optional(left), Self::Optional(right)) => {
                Some(Self::Optional(merge_optional_shape(left, right)?))
            }
            (
                Self::Response {
                    ok: left_ok,
                    err: left_err,
                },
                Self::Response {
                    ok: right_ok,
                    err: right_err,
                },
            ) => Some(Self::Response {
                ok: merge_optional_shape(left_ok, right_ok)?,
                err: merge_optional_shape(left_err, right_err)?,
            }),
            (Self::Tuple(left), Self::Tuple(right)) if left.len() == right.len() => {
                let mut merged = Vec::with_capacity(left.len());
                for ((left_name, left_shape), (right_name, right_shape)) in
                    left.into_iter().zip(right)
                {
                    if left_name != right_name {
                        return None;
                    }
                    merged.push((left_name, left_shape.merge(right_shape)?));
                }
                Some(Self::Tuple(merged))
            }
            (Self::List(left), Self::List(right)) => {
                Some(Self::List(merge_optional_shape(left, right)?))
            }
            (Self::List(Some(shared)), Self::ListElements(elements))
            | (Self::ListElements(elements), Self::List(Some(shared))) => {
                let merged = elements.into_iter().try_fold(*shared, ActiveShape::merge)?;
                Some(Self::List(Some(Box::new(merged))))
            }
            (Self::ListElements(left), Self::ListElements(right)) if left.len() == right.len() => {
                let elements = left
                    .into_iter()
                    .zip(right)
                    .map(|(left, right)| left.merge(right))
                    .collect::<Option<Vec<_>>>()?;
                Some(list_shape_from_elements(elements))
            }
            (Self::ListElements(left), Self::ListElements(right)) => {
                let elements = left.into_iter().chain(right).collect::<Vec<_>>();
                let merged = merge_list_elements(&elements)?;
                Some(Self::List(Some(Box::new(merged))))
            }
            _ => None,
        }
    }
}

/// Reduce every list element to one shared active shape.
pub fn merge_list_elements(elements: &[ActiveShape]) -> Option<ActiveShape> {
    let (first, rest) = elements.split_first()?;
    rest.iter()
        .cloned()
        .try_fold(first.clone(), ActiveShape::merge)
}

/// Merge optional child shapes while preserving an absent branch.
fn merge_optional_shape(
    left: Option<Box<ActiveShape>>,
    right: Option<Box<ActiveShape>>,
) -> Option<Option<Box<ActiveShape>>> {
    match (left, right) {
        (None, None) => Some(None),
        (Some(shape), None) | (None, Some(shape)) => Some(Some(shape)),
        (Some(left), Some(right)) => Some(Some(Box::new(left.merge(*right)?))),
    }
}

/// Select shared or per-element list metadata according to whether all shapes merge.
fn list_shape_from_elements(elements: Vec<ActiveShape>) -> ActiveShape {
    debug_assert!(!elements.is_empty());
    match merge_list_elements(&elements) {
        Some(merged) => ActiveShape::List(Some(Box::new(merged))),
        None => ActiveShape::ListElements(elements),
    }
}
