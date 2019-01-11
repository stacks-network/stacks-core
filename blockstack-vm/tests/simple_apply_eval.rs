extern crate blockstack_vm


#[test]
fn main() {
    let content = [ SymbolicExpression { value: "do_work".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "a".to_string(),
                                                                              children: None } ])) } ];
    let func_body = SymbolicExpression { value: "+".to_string(),
                                         children:
                                         Some(Box::new([ SymbolicExpression { value: "5".to_string(),
                                                                              children: None },
                                                         SymbolicExpression { value: "x".to_string(),
                                                                              children: None }])) };
    let func_args = vec!["x".to_string()];
    let user_function = Box::new(DefinedFunction { body: func_body,
                                                   arguments: func_args });

//    let contract = Contract { content: Box::new(content) } ;
    let mut context = Context {
        parent: Option::None,
        variables: HashMap::new(),
        functions: HashMap::new() };

    context.variables.insert("a".to_string(), ValueType::IntType(59));
    context.functions.insert("do_work".to_string(), user_function);

    println!("{:?}", eval(&content[0], &context));
}

