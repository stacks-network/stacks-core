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

//! Version 1 fixed-width layout classification.
//!
//! Only Booleans and recursively fixed tuples omit parent offset directories. Declared sequence
//! bounds and inactive response/optional branches never select physical framing.

use super::super::shape::ActiveShape;
use super::{PackedSchemaError, PackedValueError};
use crate::types::{ListData, TypeSignature, Value};

/// Physical framing selected for a list's element region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListLayout {
    /// Empty element region.
    Empty,
    /// Homogeneous unsigned integers sharing one minimal scalar width.
    UnsignedLane,
    /// Homogeneous signed integers sharing one minimal scalar width.
    SignedLane,
    /// Homogeneous Booleans packed one bit per element.
    BooleanLane,
    /// Directory-free concatenation of fixed-width element bodies.
    Fixed,
    /// Offset-directory framing for variable-width element bodies.
    Variable,
}

/// Classify list framing from active elements only.
///
/// Runtime lists are normally homogeneous. Migration from consensus bytes can also encounter
/// historical unsanitized lists whose elements have incompatible tuple shapes, so classification
/// must inspect every element instead of trusting the list's stored item type or first value.
pub fn list_layout(list: &ListData) -> ListLayout {
    if list.data.is_empty() {
        ListLayout::Empty
    } else if list
        .data
        .iter()
        .all(|value| matches!(value, Value::UInt(_)))
    {
        ListLayout::UnsignedLane
    } else if list.data.iter().all(|value| matches!(value, Value::Int(_))) {
        ListLayout::SignedLane
    } else if list
        .data
        .iter()
        .all(|value| matches!(value, Value::Bool(_)))
    {
        ListLayout::BooleanLane
    } else if list
        .data
        .iter()
        .all(|value| fixed_value_width(value).is_some())
    {
        ListLayout::Fixed
    } else {
        ListLayout::Variable
    }
}

/// Return the directory-free width selected by an active value, if any.
pub fn fixed_value_width(value: &Value) -> Option<usize> {
    match value {
        Value::Bool(_) => Some(1),
        Value::Tuple(tuple) => tuple.data_map.values().try_fold(0usize, |total, child| {
            total.checked_add(fixed_value_width(child)?)
        }),
        _ => None,
    }
}

/// Return the directory-free width selected by an active shape, if any.
pub fn fixed_shape_width(shape: &ActiveShape) -> Option<usize> {
    match shape {
        ActiveShape::Bool => Some(1),
        ActiveShape::Tuple(fields) => fields.iter().try_fold(0usize, |total, (_, child)| {
            total.checked_add(fixed_shape_width(child)?)
        }),
        _ => None,
    }
}

/// Return the directory-free width implied by a read schema, if any.
pub fn fixed_type_width(expected: &TypeSignature) -> Result<Option<usize>, PackedValueError> {
    match expected {
        TypeSignature::BoolType => Ok(Some(1)),
        TypeSignature::TupleType(tuple) => {
            let mut total = 0usize;
            for child in tuple.get_type_map().values() {
                let Some(width) = fixed_type_width(child)? else {
                    return Ok(None);
                };
                total = total
                    .checked_add(width)
                    .ok_or(PackedValueError::SizeOverflow)?;
            }
            Ok(Some(total))
        }
        TypeSignature::ListUnionType(_) => Err(PackedSchemaError::ListUnionType.into()),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::representations::ClarityName;
    use crate::types::TupleData;

    #[test]
    fn value_shape_and_type_fixed_width_classifiers_agree() {
        let nested = Value::Tuple(
            TupleData::from_data(vec![(
                ClarityName::from_literal("nested"),
                Value::Bool(false),
            )])
            .unwrap(),
        );
        let value = Value::Tuple(
            TupleData::from_data(vec![
                (ClarityName::from_literal("direct"), Value::Bool(true)),
                (ClarityName::from_literal("tuple"), nested),
            ])
            .unwrap(),
        );
        let shape = ActiveShape::from_value(&value);
        let value_type = TypeSignature::type_of(&value).unwrap();

        assert_eq!(fixed_value_width(&value), Some(2));
        assert_eq!(fixed_shape_width(&shape), Some(2));
        assert_eq!(fixed_type_width(&value_type).unwrap(), Some(2));

        assert_eq!(fixed_value_width(&Value::UInt(0)), None);
        assert_eq!(fixed_shape_width(&ActiveShape::UInt), None);
        assert_eq!(fixed_type_width(&TypeSignature::UIntType).unwrap(), None);

        let mixed = Value::Tuple(
            TupleData::from_data(vec![
                (ClarityName::from_literal("bool"), Value::Bool(true)),
                (ClarityName::from_literal("uint"), Value::UInt(0)),
            ])
            .unwrap(),
        );
        let mixed_shape = ActiveShape::from_value(&mixed);
        let mixed_type = TypeSignature::type_of(&mixed).unwrap();

        assert_eq!(fixed_value_width(&mixed), None);
        assert_eq!(fixed_shape_width(&mixed_shape), None);
        assert_eq!(fixed_type_width(&mixed_type).unwrap(), None);
    }

    #[test]
    fn empty_list_has_an_explicit_layout() {
        let Value::Sequence(crate::types::SequenceData::List(empty)) =
            Value::list_from(vec![]).unwrap()
        else {
            panic!("empty list constructor returned a non-list value");
        };
        assert_eq!(list_layout(&empty), ListLayout::Empty);
    }
}
