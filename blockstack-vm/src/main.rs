pub struct SymbolicExpression {
    value: String,
    children: Option<Box<[SymbolicExpression]>>
}

pub struct Contract {
    content: Box<[SymbolicExpression]>
}

fn parse(value: &str) -> i32 {
    match i32::from_str_radix(value, 10) {
        Ok(parsed) => parsed,
        Err(_e) => panic!("Failed to parse!")
    }
}

fn nativeAdd(args: &[String]) -> String {
    let parsedArgs = args.iter().map(|x| parse(x));
    let result = parsedArgs.fold(0, |acc, x| acc + x);
    format!("{:?}", result).to_string()
}

fn lookupVariable(name: &str) -> String {
    // first off, are we talking about a constant?
    if name.starts_with(char::is_numeric) {
        name.to_string()
    } else {
        panic!("Not implemented");
    }
}

fn lookupFunction(name: &str)-> fn(&[String]) -> String {
    match name {
        "+" => nativeAdd,
        _ => panic!("Crash and burn")
    }
}

fn apply<F>(function: &F, args: &[SymbolicExpression]) -> String
    where F: Fn(&[String]) -> String {
    let evaluatedArgs: Vec<String> = args.iter().map(|x| eval(x)).collect();
    function(&evaluatedArgs)
}

fn eval(exp: &SymbolicExpression) -> String {
    match exp.children {
        None => lookupVariable(&exp.value),
        Some(ref children) => {
            let f = lookupFunction(&exp.value);
            apply(&f, &children)
        }
    }
}

fn main() {
    let content = [ SymbolicExpression { value: "+".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "1".to_string(),
                                                                              children: None },
                                                         SymbolicExpression { value: "1".to_string(),
                                                                              children: None } ])) } ];
//    let contract = Contract { content: Box::new(content) } ;
    println!("{:?}", eval(&content[0]));
}
