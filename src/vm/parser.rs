use errors::Error;
use representations::SymbolicExpression;

#[derive(Debug)]
pub enum LexItem {
    LeftParen,
    RightParen,
    NameParameter(String),
    Atom(String)
}

fn finish_atom(current: &mut Option<String>) -> Option<LexItem> {
    let resp = match current {
        &mut None => {
            None
        },
        &mut Some(ref value) => {
            if value.starts_with('#') {
                Some(LexItem::NameParameter(value[1..].to_string()))
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

pub fn parse_lexed(input: &Vec<LexItem>) -> Result<Vec<SymbolicExpression>, Error> {
    let mut parse_stack = Vec::new();

    let mut output_list = Vec::new();

    // TODO: we don't need to be cloning here, we can just seize item ownership from the
    //    input iterator by popping.
    let _result = input.iter().try_for_each(|item| {
        match *item {
            LexItem::LeftParen => {
                // start new list.
                let new_list = Vec::new();
                parse_stack.push(new_list);
                Ok(())
            },
            LexItem::NameParameter(ref value) => {
                let symbol_out = SymbolicExpression::NamedParameter(value.clone());
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
