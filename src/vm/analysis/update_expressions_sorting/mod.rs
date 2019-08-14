use std::collections::{HashSet, HashMap};
use std::iter::FromIterator;
use vm::representations::{SymbolicExpression};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::analysis::types::{ContractAnalysis, AnalysisPass};

use super::AnalysisDatabase;
use super::errors::{CheckResult, CheckError, CheckErrors};

#[cfg(test)]
mod tests;

pub struct UpdateExpressionsSorting {
    graph: Graph,
    top_level_expressions_map: HashMap<String, TopLevelExpressionIndex>   
}

impl AnalysisPass for UpdateExpressionsSorting {

    fn run_pass(contract_analysis: &mut ContractAnalysis, _analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let mut command = UpdateExpressionsSorting::new();
        command.run(contract_analysis)?;
        Ok(())
    }
}

impl <'a> UpdateExpressionsSorting {

    fn new() -> Self {
        Self { 
            top_level_expressions_map: HashMap::new(),
            graph: Graph::new()
        }
    }

    pub fn run(&mut self, contract_analysis: &'a mut ContractAnalysis) -> CheckResult<()> {

        let exprs = contract_analysis.expressions[..].to_vec();
        for (expr_index, expr) in exprs.iter().enumerate() {
            self.graph.add_node(expr_index)?;

            match self.find_expression_definition(expr) {
                Some((definition_name, atom_index, _)) => {
                    let tle = TopLevelExpressionIndex { expr_index, atom_index };
                    self.top_level_expressions_map.insert(definition_name, tle);
                },
                None => {}
            }
        }

        for (expr_index, expr) in exprs.iter().enumerate() {
            self.register_dependencies(&expr, expr_index)?;
        }

        let mut walker = GraphWalker::new();
        let sorted_indexes = walker.get_sorted_dependencies(&self.graph)?;
        
        if let Some(deps) = walker.get_cycling_dependencies(&self.graph, &sorted_indexes) {
            let deps_props: Vec<(String, u64, &SymbolicExpression)> = deps.iter().map(|i| {
                let exp = &contract_analysis.expressions[*i];
                self.find_expression_definition(&exp).unwrap()
            }).collect();
            let functions_names = deps_props.iter().map(|i| i.0.clone()).collect();
            let exprs = deps_props.iter().map(|i| i.2.clone()).collect();

            let mut error = CheckError::new(CheckErrors::CyclingDependencies(functions_names));
            error.set_expressions(exprs);
            return Err(error)
        }

        contract_analysis.top_level_expression_sorting = Some(sorted_indexes);
        Ok(())
    }

    fn register_dependencies(&mut self, expr: &SymbolicExpression, tle_index: usize) -> CheckResult<bool> {
        match expr.expr {
            AtomValue(_) => Ok(true),
            Atom(ref name) => {
                if let Some(dep) = self.top_level_expressions_map.get(&name.clone()) {
                    if dep.atom_index != expr.id {
                        self.graph.add_directed_edge(tle_index, dep.expr_index)?;
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

    fn find_expression_definition<'b>(&mut self, exp: &'b SymbolicExpression) -> Option<(String, u64, &'b SymbolicExpression)> {
        if let Some(expression) = exp.match_list() {
            if let Some((function_name, function_args)) = expression.split_first() {
                if let Some(definition_type) = function_name.match_atom() {
                    match definition_type.as_str() {
                        "define-map" | "define-data-var" | "define" | "define-public" | "define-read-only" => {
                            if function_args.len() > 1 {
                                let define_expr = match function_args[0].match_list() {
                                    Some(list) => &list[0],
                                    _ => &function_args[0]
                                };
                                if let Some(tle_name) = define_expr.match_atom() {
                                    return Some((tle_name.clone(), define_expr.id, define_expr));
                                }   
                            }
                        }
                        _ => {}
                    }
                } 
            } 
        }
        None
    }
}

pub struct TopLevelExpressionIndex {
    expr_index: usize,
    atom_index: u64
}

struct Graph {
    nodes: Vec<usize>,
    adjacency_list: Vec<Vec<usize>>
}

impl Graph {
    fn new() -> Self {
        Self { 
            nodes: Vec::new(), 
            adjacency_list: Vec::new() 
        }
    }

    fn add_node(&mut self, expr_index: usize) -> CheckResult<()> {
        self.nodes.push(expr_index);
        self.adjacency_list.push(vec![]);
        Ok(())
    }

    fn add_directed_edge(&mut self, src_expr_index: usize, dst_expr_index: usize) -> CheckResult<()> {
        let list = self.adjacency_list.get_mut(src_expr_index).unwrap();
        list.push(dst_expr_index);
        Ok(())
    }
    
    fn get_node_descendants(&self, expr_index: usize) -> Vec<usize> {
        self.adjacency_list[expr_index].clone()
    }

    fn has_node_descendants(&self, expr_index: usize) -> bool {
        self.adjacency_list[expr_index].len() > 0
    }
}

struct GraphWalker {
    seen: HashSet<usize>,
}

impl GraphWalker  {

    fn new() -> Self { Self { seen: HashSet::new() } }

    fn get_sorted_dependencies(&mut self, graph: &Graph) -> CheckResult<Vec<usize>> {
        let mut sorted_indexes = Vec::<usize>::new();
        for expr_index in 0..graph.nodes.len() {
            self.sort_dependencies_recursion(expr_index, graph, &mut sorted_indexes);
        }

        Ok(sorted_indexes)
    }

    fn sort_dependencies_recursion(&mut self, tle_index: usize, graph: &Graph, branch: &mut Vec<usize>) {
        if self.seen.contains(&tle_index) {
            return
        }

        self.seen.insert(tle_index);
        if let Some(list) = graph.adjacency_list.get(tle_index) {
            for neighbor in list.iter() {
                self.sort_dependencies_recursion(neighbor.clone(), graph, branch);
            }
        }
        branch.push(tle_index);
    }

    fn get_cycling_dependencies(&mut self, graph: &Graph, sorted_indexes: &Vec<usize>) -> Option<Vec<usize>> {
        let mut tainted: HashSet<usize> = HashSet::new();

        for node in sorted_indexes.iter() {
            let mut tainted_descendants_count = 0;
            let descendants = graph.get_node_descendants(*node);
            for descendant in descendants.iter() {
                if graph.has_node_descendants(*descendant) == false || tainted.contains(descendant) {
                    tainted.insert(*descendant);
                    tainted_descendants_count += 1;
                }
            }
            if tainted_descendants_count == descendants.len() {
                tainted.insert(*node);
            }
        }

        if tainted.len() == sorted_indexes.len() {
            return None
        }

        let nodes = HashSet::from_iter(sorted_indexes.iter().cloned());
        let deps = nodes.difference(&tainted).map(|i| *i).collect();        
        Some(deps) 
    }
}

