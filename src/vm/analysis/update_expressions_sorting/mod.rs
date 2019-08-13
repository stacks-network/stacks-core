use std::collections::{HashSet, HashMap, VecDeque};
use vm::representations::{SymbolicExpression};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::analysis::types::{ContractAnalysis, AnalysisPass};

use super::AnalysisDatabase;
use super::errors::{CheckResult, CheckError, CheckErrors};

#[cfg(test)]
mod tests;

pub struct TopLevelExpressionIndex {
    index: usize,
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

    fn push_top_level_expression(&mut self, expr_index: usize) -> CheckResult<()> {
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
        self.adjacency_list[expr_index].len() == 0
    }
}

struct GraphWalker {
    seen: HashSet<usize>,
}

impl GraphWalker  {

    fn new() -> Self { Self { seen: HashSet::new() } }

    fn get_sorted_dependencies(graph: &Graph) -> CheckResult<Vec<usize>> {
        let mut walker = GraphWalker::new();

        let mut sorted_indexes = Vec::<usize>::new();
        for expr_index in 0..graph.nodes.len() {
            walker.sort_dependencies_recursion(expr_index, graph, &mut sorted_indexes);
        }

        walker.detect_cycling_dependencies(&graph, &sorted_indexes)?;

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

    fn detect_cycling_dependencies(&mut self, graph: &Graph, sorted_indexes: &Vec<usize>) -> CheckResult<()> {
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

        println!("{:?} - {:?}", tainted, sorted_indexes);
        if tainted.len() == sorted_indexes.len() {
            return Ok(())
        }

        // let nodes = sorted_indexes.iter().cloned().collect();
        return Err(CheckError::new(CheckErrors::CyclingDependencies))
    }
}

pub struct UpdateExpressionsSorting <'a> {
    graph: Graph,
    top_level_expressions_map: HashMap<String, TopLevelExpressionIndex>,
    contract_analysis: &'a mut ContractAnalysis
}

impl <'a> AnalysisPass for UpdateExpressionsSorting <'a> {

    fn run_pass(contract_analysis: &mut ContractAnalysis, _analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let mut command = UpdateExpressionsSorting::new(contract_analysis);
        command.run()?;
        Ok(())
    }
}

impl <'a> UpdateExpressionsSorting <'a> {

    fn new(contract_analysis: &'a mut ContractAnalysis) -> Self {
        Self { 
            contract_analysis,
            top_level_expressions_map: HashMap::new(),
            graph: Graph::new()
        }
    }

    pub fn run(&mut self) -> CheckResult<()> {
        self.identify_top_level_expressions();

        let exprs = self.contract_analysis.expressions[..].to_vec();
        for (index, expr) in exprs.iter().enumerate() {
            self.graph.push_top_level_expression(index)?;
            self.register_dependencies(&expr, index)?;
        }

        let indexes = GraphWalker::get_sorted_dependencies(&self.graph)?;
        self.contract_analysis.top_level_expression_sorting = Some(indexes);

        Ok(())
    }

    fn register_dependencies(&mut self, expr: &SymbolicExpression, tle_index: usize) -> CheckResult<bool> {
        match expr.expr {
            AtomValue(_) => Ok(true),
            Atom(ref name) => {
                if let Some(dep) = self.top_level_expressions_map.get(&name.clone()) {
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

    fn identify_top_level_expressions(&mut self) {
        let mut tle_map = HashMap::new(); 
        let expressions = &self.contract_analysis.expressions;
        for (index, exp) in expressions.iter().enumerate() {
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
                                        let tle = TopLevelExpressionIndex { index, atom_index: define_expr.id };
                                        tle_map.insert(tle_name.clone(), tle);
                                    }   
                                }
                            }
                            _ => {

                            }
                        }
                    } 
                } 
            }
        }
        self.top_level_expressions_map = tle_map;
    }
}