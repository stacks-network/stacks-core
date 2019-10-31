use std::collections::{HashSet, HashMap};
use std::iter::FromIterator;
use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue};
use vm::functions::NativeFunctions;
use vm::functions::define::DefineFunctions;
use vm::analysis::types::{ContractAnalysis, AnalysisPass};
use vm::analysis::errors::{CheckResult, CheckError, CheckErrors};
use super::AnalysisDatabase;

#[cfg(test)]
mod tests;

pub struct DefinitionSorter {
    graph: Graph,
    top_level_expressions_map: HashMap<ClarityName, TopLevelExpressionIndex>   
}

impl AnalysisPass for DefinitionSorter {

    fn run_pass(contract_analysis: &mut ContractAnalysis, _analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let mut command = DefinitionSorter::new();
        command.run(contract_analysis)?;
        Ok(())
    }
}

impl <'a> DefinitionSorter {

    fn new() -> Self {
        Self { 
            top_level_expressions_map: HashMap::new(),
            graph: Graph::new()
        }
    }

    pub fn run(&mut self, contract_analysis: &mut ContractAnalysis) -> CheckResult<()> {

        let exprs = contract_analysis.expressions[..].to_vec();
        for (expr_index, expr) in exprs.iter().enumerate() {
            self.graph.add_node(expr_index);

            match self.find_expression_definition(expr) {
                Some((definition_name, atom_index, _)) => {
                    let tle = TopLevelExpressionIndex { expr_index, atom_index };
                    self.top_level_expressions_map.insert(definition_name, tle);
                },
                None => {}
            }
        }

        for (expr_index, expr) in exprs.iter().enumerate() {
            self.probe_for_dependencies(&expr, expr_index)?;
        }

        let mut walker = GraphWalker::new();
        let sorted_indexes = walker.get_sorted_dependencies(&self.graph)?;
        
        if let Some(deps) = walker.get_cycling_dependencies(&self.graph, &sorted_indexes) {
            let deps_props: Vec<(_)> = deps.iter().map(|i| {
                let exp = &contract_analysis.expressions[*i];
                self.find_expression_definition(&exp).unwrap()
            }).collect();
            let functions_names = deps_props.iter().map(|i| i.0.to_string()).collect();
            let exprs = deps_props.iter().map(|i| i.2.clone()).collect();

            let mut error = CheckError::new(CheckErrors::CircularReference(functions_names));
            error.set_expressions(exprs);
            return Err(error)
        }

        contract_analysis.top_level_expression_sorting = Some(sorted_indexes);
        Ok(())
    }

    fn probe_for_dependencies(&mut self, expr: &SymbolicExpression, tle_index: usize) -> CheckResult<()> {
        match expr.expr {
            AtomValue(_)  | LiteralValue(_) => Ok(()),
            Atom(ref name) => {
                if let Some(dep) = self.top_level_expressions_map.get(name) {
                    if dep.atom_index != expr.id {
                        self.graph.add_directed_edge(tle_index, dep.expr_index);
                    }
                }
                Ok(())
            },
            List(ref exprs) => {
                // Avoid looking for dependencies in tuples 
                if let Some((function_name, function_args)) = exprs.split_first() {
                    if let Some(function_name) = function_name.match_atom() {
                        if let Some(define_function) = DefineFunctions::lookup_by_name(function_name) {
                            match define_function {
                                DefineFunctions::NonFungibleToken | DefineFunctions::FungibleToken |
                                DefineFunctions::PrivateFunction | DefineFunctions::Constant |
                                DefineFunctions::PublicFunction | DefineFunctions::PersistedVariable |
                                DefineFunctions::ReadOnlyFunction => {
                                    // Args: [(define-name-and-types), ...]: ignore 1st arg
                                    if function_args.len() > 1 {
                                        for expr in function_args[1..function_args.len()].into_iter() {
                                            self.probe_for_dependencies(expr, tle_index)?;
                                        }
                                    }
                                    return Ok(());
                                },
                                DefineFunctions::Map => {
                                    // Args: [name, tuple-key, tuple-value]: handle tuple-key and tuple-value as tuples
                                    if function_args.len() == 3 {
                                        self.probe_for_dependencies_in_tuple(&function_args[1], tle_index)?;
                                        self.probe_for_dependencies_in_tuple(&function_args[2], tle_index)?;
                                    }
                                    return Ok(());
                                }
                            }
                        } else if let Some(native_function) = NativeFunctions::lookup_by_name(function_name) {
                            match native_function {
                                NativeFunctions::FetchEntry | NativeFunctions::DeleteEntry => {
                                    // Args: [map-name, tuple-predicate]: handle tuple-predicate as tuple
                                    if function_args.len() == 2 {
                                        self.probe_for_dependencies(&function_args[0], tle_index)?;
                                        self.probe_for_dependencies_in_tuple(&function_args[1], tle_index)?;
                                    }
                                    return Ok(());
                                }, 
                                NativeFunctions::SetEntry | NativeFunctions::InsertEntry => {
                                    // Args: [map-name, tuple-keys, tuple-values]: handle tuple-keys and tuple-values as tuples
                                    if function_args.len() == 3 {
                                        self.probe_for_dependencies(&function_args[0], tle_index)?;
                                        self.probe_for_dependencies_in_tuple(&function_args[1], tle_index)?;
                                        self.probe_for_dependencies_in_tuple(&function_args[2], tle_index)?;
                                    }
                                    return Ok(());
                                }, 
                                NativeFunctions::FetchContractEntry => {
                                    // Args: [contract-name, map-name, tuple-predicate]: ignore contract-name, map-name, handle tuple-predicate as tuple
                                    if function_args.len() == 3 {
                                        self.probe_for_dependencies_in_tuple(&function_args[2], tle_index)?;
                                    }
                                    return Ok(());
                                }, 
                                NativeFunctions::Let => {
                                    // Args: [((name-1 value-1) (name-2 value-2)), ...]: handle 1st arg as a tuple
                                    if function_args.len() > 1 {
                                        self.probe_for_dependencies_in_tuple(&function_args[0], tle_index)?;
                                        for expr in function_args[1..function_args.len()].into_iter() {
                                            self.probe_for_dependencies(expr, tle_index)?;
                                        }
                                    }
                                    return Ok(());
                                }
                                NativeFunctions::TupleGet => {
                                    // Args: [key-name, expr]: ignore key-name
                                    if function_args.len() == 2 {
                                        self.probe_for_dependencies(&function_args[1], tle_index)?;
                                    }
                                    return Ok(());
                                }, 
                                NativeFunctions::TupleCons => {
                                    // Args: [(key-name A), (key-name-2 B), ...]: handle as a tuple
                                    self.probe_for_dependencies_in_tuple_list(function_args, tle_index)?;
                                    return Ok(());
                                },
                                _ => {}
                            }
                        }
                    }
                }
                for expr in exprs.into_iter() {
                    self.probe_for_dependencies(expr, tle_index)?;
                }
                Ok(())
            }
        }
    }

    fn probe_for_dependencies_in_tuple_list(&mut self, tuples: &[SymbolicExpression], tle_index: usize) -> CheckResult<()> {
        for index in 0..tuples.len() {
            self.probe_for_dependencies_in_tuple(&tuples[index], tle_index)?;
        } 
        Ok(())
    }

    fn probe_for_dependencies_in_tuple(&mut self, expr: &SymbolicExpression, tle_index: usize) -> CheckResult<()> {
        if let Some(tuple) = expr.match_list() {
            for pair in tuple.into_iter() {
                if let Some(pair) = pair.match_list() {
                    if pair.len() == 2 {
                        self.probe_for_dependencies(&pair[1], tle_index)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn find_expression_definition<'b>(&mut self, exp: &'b SymbolicExpression) -> Option<(ClarityName, u64, &'b SymbolicExpression)> {
        let (_define_type, args) = DefineFunctions::try_parse(exp)?;
        let defined_name = match args.get(0)?.match_list() {
            Some(list) => list.get(0)?,
            _ => &args[0]
        };
        let tle_name = defined_name.match_atom()?;
        Some((tle_name.clone(), defined_name.id, defined_name))
    }
}

pub struct TopLevelExpressionIndex {
    expr_index: usize,
    atom_index: u64
}

struct Graph {
    adjacency_list: Vec<Vec<usize>>
}

impl Graph {
    fn new() -> Self {
        Self { adjacency_list: Vec::new() }
    }

    fn add_node(&mut self, expr_index: usize) {
        self.adjacency_list.push(vec![]);
    }

    fn add_directed_edge(&mut self, src_expr_index: usize, dst_expr_index: usize) {
        let list = self.adjacency_list.get_mut(src_expr_index).unwrap();
        list.push(dst_expr_index);
    }
    
    fn get_node_descendants(&self, expr_index: usize) -> Vec<usize> {
        self.adjacency_list[expr_index].clone()
    }

    fn has_node_descendants(&self, expr_index: usize) -> bool {
        self.adjacency_list[expr_index].len() > 0
    }

    fn nodes_count(&self) -> usize { self.adjacency_list.len() }
}

struct GraphWalker {
    seen: HashSet<usize>,
}

impl GraphWalker {

    fn new() -> Self { Self { seen: HashSet::new() } }

    /// Depth-first search producing a post-order sort
    fn get_sorted_dependencies(&mut self, graph: &Graph) -> CheckResult<Vec<usize>> {
        let mut sorted_indexes = Vec::<usize>::new();
        for expr_index in 0..graph.nodes_count() {
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
                if !graph.has_node_descendants(*descendant) || tainted.contains(descendant) {
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

