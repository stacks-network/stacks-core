use std::collections::{HashSet, HashMap};
use vm::representations::{SymbolicExpression};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};

use super::AnalysisDatabase;
pub use super::errors::{CheckResult, CheckError, CheckErrors};

#[cfg(test)]
mod tests;

struct Graph <'a> {
    top_level_expressions: Vec<&'a SymbolicExpression>,
    adjacency_list: Vec<Vec<usize>>
}

impl <'a>Graph <'a> {
    fn new() -> Graph <'a> {
        Graph {
            top_level_expressions: Vec::new(),
            adjacency_list: Vec::new()
        }
    }

    fn push_top_level_expression(&mut self, expr: &'a SymbolicExpression) -> CheckResult<()> {
        self.top_level_expressions.push(expr);
        let empty_list = vec![];
        self.adjacency_list.push(empty_list);
        Ok(())
    }

    fn add_directed_edge(&mut self, src_expr_index: usize, dst_expr_index: usize) -> CheckResult<()> {
        let list = self.adjacency_list.get_mut(src_expr_index).unwrap();
        list.push(dst_expr_index);
        Ok(())
    }
}

struct GraphWalker {
    seen: HashSet<usize>
}

impl GraphWalker  {

    fn get_desired_eval_order(graph: &Graph) -> CheckResult<Vec<usize>> {
        let mut walker =  GraphWalker {
            seen: HashSet::new()
        };
        let mut desired_state = Vec::<usize>::new();

        for expr_index in 0..graph.top_level_expressions.len() {
            let res = walker.ordered_dependencies_recursion(expr_index, graph, &mut desired_state);
            if res.is_err() {
                continue;
            }
        }

        Ok(desired_state)
    }

    fn ordered_dependencies_recursion(&mut self, tle_index: usize, graph: &Graph, branch: &mut Vec<usize>) -> CheckResult<usize> {
        if self.seen.contains(&tle_index) {
            return Err(CheckError::new(CheckErrors::NotImplemented))
        }
        self.seen.insert(tle_index);

        if let Some(list) = graph.adjacency_list.get(tle_index) {
            for neighbor in list.iter() {
                let res = self.ordered_dependencies_recursion(neighbor.clone(), graph, branch);
                if res.is_err() {
                    continue;
                }
            }
        }

        branch.push(tle_index);
        Ok(tle_index)
    }
}

pub struct TopLevelSymbolicExpression <'a> {
    exp: &'a SymbolicExpression,
    index: usize,
    atom_index: u64
}

pub struct TopLevelExpressionSorter <'a, 'b> {
    db: &'a AnalysisDatabase<'b>,
    graph: Graph<'b>,
    top_level_expressions: HashMap<String, TopLevelSymbolicExpression<'b>>,
}

impl <'a, 'b> TopLevelExpressionSorter <'a, 'b> {

    fn new(db: &'a AnalysisDatabase<'b>) -> TopLevelExpressionSorter<'a, 'b> {
        TopLevelExpressionSorter { 
            db, 
            top_level_expressions: HashMap::new(),
            graph: Graph::new()
        }
    }

    pub fn check_contract(contract: &mut [SymbolicExpression], analysis_db: &AnalysisDatabase) -> CheckResult<()> {
        let mut permuted_tle_indexes = vec![];
        {
            let mut checker = TopLevelExpressionSorter::new(analysis_db);
            
            let tle_map = TopLevelExpressionSorter::identify_top_level_expressions(contract);
            checker.top_level_expressions = tle_map;

            for index in 0..contract.len() {
                let expr = &contract[index];
                checker.graph.push_top_level_expression(expr)?;
                checker.register_dependencies(expr, index)?;
            }

            let indexes = GraphWalker::get_desired_eval_order(&checker.graph)?;
            permuted_tle_indexes = indexes.clone();
        }

        let mut permuted_contract = vec![];
        for index in permuted_tle_indexes.iter() {
            let expr = contract[*index].clone();
            permuted_contract.push(expr);
        }
        contract.swap_with_slice(permuted_contract.as_mut_slice());

        Ok(())
    }

    fn register_dependencies(&mut self, expr: &SymbolicExpression, tle_index: usize) -> CheckResult<bool> {
        match expr.expr {
            AtomValue(_) => {
                Ok(true)
            },
            Atom(ref name) => {
                if let Some(dep) = self.top_level_expressions.get(&name.clone()) {
                    if dep.atom_index != expr.id {
                        self.graph.add_directed_edge(tle_index, dep.index)?;
                    }
                }
                Ok(true)
            },
            List(ref exprs) => {
                for expr in exprs.into_iter() {
                    self.register_dependencies(expr, tle_index)?;
                }
                Ok(true)
            }
        }
    }

    fn identify_top_level_expressions(contract: &'a [SymbolicExpression]) -> HashMap<String, TopLevelSymbolicExpression> {
        let mut tle_map = HashMap::new(); 
        for index in 0..contract.len() {
            let exp = &contract[index];
            if let Some(expression) = exp.match_list() {
                if let Some((function_name, function_args)) = expression.split_first() {
                    if let Some(definition_type) = function_name.match_atom() {
                        match definition_type.as_str() {
                            "define-map" | "define-data-var" | "define" | "define-public" | "define-read-only" => {
                                if function_args.len() > 1 {
                                    if let Some(list) = function_args[0].match_list() {
                                        if let Some(tle_name) = list[0].match_atom() {
                                            let tle = TopLevelSymbolicExpression {exp, index, atom_index: list[0].id };
                                            tle_map.insert(tle_name.clone(), tle);
                                        }   
                                    } else {
                                        if let Some(tle_name) = function_args[0].match_atom() {
                                            let tle = TopLevelSymbolicExpression {exp, index, atom_index: function_args[0].id};
                                            tle_map.insert(tle_name.clone(), tle);
                                        }   
                                    }
                                }
                            }
                            _ => {}
                        }
                    } 
                } 
            }
        }
        tle_map
    }
}