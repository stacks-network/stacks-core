use std::collections::{HashSet, HashMap};
use vm::representations::{SymbolicExpression};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::analysis::types::{ContractAnalysis, AnalysisPass};

use super::AnalysisDatabase;
use super::errors::{CheckResult};

#[cfg(test)]
mod tests;

pub struct TopLevelExpressionIndex {
    index: usize,
    atom_index: u64
}

struct Graph {
    top_level_expressions: Vec<usize>,
    adjacency_list: Vec<Vec<usize>>
}

impl Graph {
    fn new() -> Self {
        Self { 
            top_level_expressions: Vec::new(), 
            adjacency_list: Vec::new() 
        }
    }

    fn push_top_level_expression(&mut self, expr_index: usize) -> CheckResult<()> {
        self.top_level_expressions.push(expr_index);
        self.adjacency_list.push(vec![]);
        Ok(())
    }

    fn add_directed_edge(&mut self, src_expr_index: usize, dst_expr_index: usize) -> CheckResult<()> {
        let list = self.adjacency_list.get_mut(src_expr_index).unwrap();
        list.push(dst_expr_index);
        Ok(())
    }
}

struct GraphWalker {
    seen: HashSet<usize>,
    tainted: HashSet<usize>,
}

impl GraphWalker  {

    fn get_required_eval_order(graph: &Graph) -> CheckResult<Vec<usize>> {
        let mut walker =  GraphWalker {
            seen: HashSet::new(),
            tainted: HashSet::new(),
        };
        let mut required_eval_order = Vec::<usize>::new();

        for expr_index in 0..graph.top_level_expressions.len() {
            walker.ordered_dependencies_recursion(expr_index, graph, &mut required_eval_order);
        }
        Ok(required_eval_order)
    }

    fn ordered_dependencies_recursion(&mut self, tle_index: usize, graph: &Graph, branch: &mut Vec<usize>) {
        if self.seen.contains(&tle_index) {
            return
        }

        self.seen.insert(tle_index);
        if let Some(list) = graph.adjacency_list.get(tle_index) {
            for neighbor in list.iter() {
                self.ordered_dependencies_recursion(neighbor.clone(), graph, branch);
            }
        }
        branch.push(tle_index);
    }
}

pub struct UpdateExpressionsSorting <'a> {
    graph: Graph,
    top_level_expressions_map: HashMap<String, TopLevelExpressionIndex>,
    top_level_expressions: Vec<TopLevelExpressionIndex>,
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
            top_level_expressions: Vec::new(),
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

        let indexes = GraphWalker::get_required_eval_order(&self.graph)?;
        self.contract_analysis.top_level_expression_sorting = Some(indexes.clone());

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