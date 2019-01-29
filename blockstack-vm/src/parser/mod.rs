use errors::Error;
use types::{TypeSignature,AtomTypeIdentifier};
use representations::SymbolicExpression;

#[derive(Debug)]
pub enum LexItem {
    LeftParen,
    RightParen,
    TypeSignifier(String),
    Atom(String)
}

fn finish_atom(current: &mut Option<String>) -> Option<LexItem> {
    let resp = match current {
        &mut None => {
            None
        },
        &mut Some(ref value) => {
            if value.starts_with('#') {
                Some(LexItem::TypeSignifier(value[1..].to_string()))
            } else {
                Some(LexItem::Atom(value.clone()))
            }
        },
    };

    *current = None;
    resp
}

pub fn lex(input: &str) -> Result<Vec<LexItem>, Error> {
    let mut result = Vec::new();
    let current = &mut None;
    for c in input.chars() {
        match c {
            '(' => {
                if let Some(value) = finish_atom(current) {
                    result.push(value);
                }
                result.push(LexItem::LeftParen)
            },
            ')' => {
                if let Some(value) = finish_atom(current) {
                    result.push(value);
                }
                result.push(LexItem::RightParen)
            },
            '#' => {
                if let Some(ref _value) = *current {
                    return Err(Error::ParseError("You may not use # in the middle of an atom.".to_string()))
                } else {
                    *current = Some(c.to_string())
                }
            },
            ' '|'\t'|'\n'|'\r' => {
                if let Some(value) = finish_atom(current) {
                    result.push(value);
                }
            },
            _ => {
                match *current {
                    None => {
                        *current = Some(c.to_string());
                    },
                    Some(ref mut value) => {
                        value.push(c);
                    }
                }
            }
        };
    }

    if let Some(value) = finish_atom(current) {
        result.push(value);
    }

    Ok(result)
}

fn get_atom_type(typename: &str) -> Result<AtomTypeIdentifier, Error> {
    match typename {
        "int" => Ok(AtomTypeIdentifier::IntType),
        "void" => Ok(AtomTypeIdentifier::VoidType),
        "bool" => Ok(AtomTypeIdentifier::BoolType),
        "buff" => Ok(AtomTypeIdentifier::BufferType),
        _ => Err(Error::ParseError(format!("Unknown type name: '{:?}'", typename)))
    }
}

fn get_list_type(prefix: &str, typename: &str, dimension: &str) -> Result<TypeSignature, Error> {
    if prefix != "list" {
        return Err(Error::ParseError(
            format!("Unknown type name: '{}-{}-{}'", prefix, typename, dimension)))
    }
    let atom_type = get_atom_type(typename)?;
    let dimension = match u8::from_str_radix(dimension, 10) {
        Ok(parsed) => Ok(parsed),
        Err(_e) => Err(Error::ParseError(
            format!("Failed to parse dimension of type: '{}-{}-{}'",
                    prefix, typename, dimension)))
    }?;
    Ok(TypeSignature::new(atom_type, dimension))
}

pub fn parse_lexed(input: &Vec<LexItem>) -> Result<Vec<SymbolicExpression>, Error> {
    let mut parse_stack = Vec::new();

    let mut output_list = Vec::new();

    let _result = input.iter().try_for_each(|item| {
        match *item {
            LexItem::LeftParen => {
                // start new list.
                let new_list = Vec::new();
                parse_stack.push(new_list);
                Ok(())
            },
            LexItem::TypeSignifier(ref value) => {
                // types should be formatted like one of:
                // typename
                // list-typename-dimensions
                let components: Vec<_> = value.split('-').collect();
                if components.len() < 1 {
                    return Err(Error::ParseError(format!("Failure to parse type identifier '{:?}'",
                                                         value)))
                }
                let type_identifier = match components.len() {
                    1 => {
                        let atom_type = get_atom_type(components[0])?;
                        Ok(TypeSignature::new(atom_type, 0))
                    },
                    3 => {
                        let type_identifier = get_list_type(components[0],
                                                            components[1],
                                                            components[2])?;
                        Ok(type_identifier)
                    },
                    _ => Err(Error::ParseError(
                        format!("Failure to parse type identifier '{:?}'", value)))
                }?;
                let symbol_out = SymbolicExpression::TypeIdentifier(type_identifier);
                match parse_stack.last_mut() {
                    None => output_list.push(symbol_out),
                    Some(ref mut list) => list.push(symbol_out)
                };
                Ok(())
            },
            LexItem::RightParen => {
                // end current list.
                if let Some(value) = parse_stack.pop() {
                    let expression = SymbolicExpression::List(value.into_boxed_slice());
                    match parse_stack.last_mut() {
                        None => {
                            // no open lists on stack, add current to result.
                            output_list.push(expression)
                        },
                        Some(ref mut list) => {
                            list.push(expression);
                        }
                    };
                    Ok(())
                } else {
                    Err(Error::ParseError("Tried to close list which isn't open.".to_string()))
                }
            },
            LexItem::Atom(ref value) => {
                match parse_stack.last_mut() {
                    None => output_list.push(SymbolicExpression::Atom(value.clone())),
                    Some(ref mut list) => list.push(SymbolicExpression::Atom(value.clone()))
                };
                Ok(())
            }
        }
    })?;

    // check unfinished stack:
    if parse_stack.len() > 0 {
        Err(Error::ParseError("List expressions (..) left opened.".to_string()))
    } else {
        Ok(output_list)
    }
}

pub fn parse(input: &str) -> Result<Vec<SymbolicExpression>, Error> {
    let lexed = lex(input)?;
    parse_lexed(&lexed)
}
