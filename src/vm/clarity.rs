use vm::representations::SymbolicExpression;
use vm::types::{Value, AssetIdentifier, PrincipalData, QualifiedContractIdentifier, TypeSignature};
use vm::contexts::{OwnedEnvironment, AssetMap};
use vm::database::{MarfedKV, ClarityDatabase, SqliteConnection};
use vm::analysis::{AnalysisDatabase};
use vm::errors::{Error as InterpreterError};
use vm::ast::{ContractAST, errors::ParseError};
use vm::analysis::{ContractAnalysis, errors::CheckError};
use vm::ast;
use vm::analysis;

use chainstate::burn::BlockHeaderHash;

pub struct ClarityInstance {
    datastore: Option<MarfedKV<SqliteConnection>>,
}

pub struct ClarityBlockConnection<'a> {
    datastore: MarfedKV<SqliteConnection>,
    parent: &'a mut ClarityInstance
}

#[derive(Debug)]
pub enum Error {
    Analysis(CheckError),
    Parse(ParseError),
    Interpreter(InterpreterError),
}

impl From<CheckError> for Error {
    fn from(e: CheckError) -> Self {
        Error::Analysis(e)
    }
}

impl From<InterpreterError> for Error {
    fn from(e: InterpreterError) -> Self {
        Error::Interpreter(e)
    }
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Parse(e)
    }
}

impl ClarityInstance {
    pub fn new(datastore: MarfedKV<SqliteConnection>) -> ClarityInstance {
        ClarityInstance { datastore: Some(datastore) }
    }

    pub fn begin_block(&mut self, current: &BlockHeaderHash, next: &BlockHeaderHash) -> ClarityBlockConnection {
        let mut datastore = self.datastore.take()
            // this is a panicking failure, because there should be _no instance_ in which a ClarityBlockConnection
            //   doesn't restore it's parent's datastore
            .expect("FAIL: use of begin_block while prior block neither committed nor rolled back.");

        datastore.begin(current, next);

        ClarityBlockConnection {
            datastore: datastore,
            parent: self
        }
    }

    pub fn destroy(mut self) -> MarfedKV<SqliteConnection> {
        let mut datastore = self.datastore.take()
            .expect("FAIL: attempt to recover database connection from clarity instance which is still open");

        datastore
    }
}

impl <'a> ClarityBlockConnection <'a> {
    pub fn rollback_block(mut self) {
        self.datastore.rollback();

        self.parent.datastore.replace(self.datastore);
    }

    pub fn commit_block(mut self) {
        self.datastore.commit();

        self.parent.datastore.replace(self.datastore);
    }

    pub fn analyze_smart_contract(&mut self, identifier: &QualifiedContractIdentifier, contract_content: &str)
                                  -> Result<(ContractAST, ContractAnalysis), Error> {
        let mut db = AnalysisDatabase::new(Box::new(&mut self.datastore));

        let mut contract_ast = ast::build_ast(identifier, contract_content)?;
        let contract_analysis = analysis::run_analysis(identifier, &mut contract_ast.expressions,
                                                       &mut db, false)?;
        Ok((contract_ast, contract_analysis))
    }

    fn with_abort_callback<F, A, R>(&mut self, to_do: F, abort_call_back: A) -> Result<R, Error>
    where A: FnOnce(&AssetMap, &mut ClarityDatabase) -> bool,
          F: FnOnce(&mut OwnedEnvironment) -> Result<(R, AssetMap), Error> {
        let mut db = ClarityDatabase::new(Box::new(&mut self.datastore));
        // wrap the whole contract-call in a claritydb transaction,
        //   so we can abort on call_back's boolean retun
        db.begin();
        let mut vm_env = OwnedEnvironment::new(db);
        let result = to_do(&mut vm_env);
        let mut db = vm_env.destruct()
            .expect("Failed to recover database reference after executing transaction");

        match result {
            Ok((value, asset_map)) => {
                if abort_call_back(&asset_map, &mut db) {
                    db.roll_back();
                } else {
                    db.commit();
                }
                Ok(value)
            },
            Err(e) => {
                db.roll_back();
                Err(e)
            }
        }
    }
    

    /// An error here would indicate that something has gone terribly wrong in the processing of a contract insert.
    ///   the caller should likely abort the whole block or panic
    pub fn save_analysis(&mut self, identifier: &QualifiedContractIdentifier, contract_analysis: &ContractAnalysis) -> Result<(), CheckError> {
        let mut db = AnalysisDatabase::new(Box::new(&mut self.datastore));
        db.begin();
        let result = db.insert_contract(identifier, contract_analysis);
        if result.is_err() {
            db.roll_back();
        } else {
            db.commit();
        }
        result
    }

    pub fn run_contract_call <F> (&mut self, sender: &PrincipalData, contract: &QualifiedContractIdentifier, public_function: &str,
                                  args: &[Value], abort_call_back: F) -> Result<Value, Error>
    where F: FnOnce(&AssetMap, &mut ClarityDatabase) -> bool {
        let expr_args: Vec<_> = args.iter().map(|x| SymbolicExpression::atom_value(x.clone())).collect();

        self.with_abort_callback(
            |vm_env| { vm_env.execute_transaction(Value::Principal(sender.clone()), contract.clone(), public_function, &expr_args)
                       .map_err(Error::from) },
            abort_call_back)
    }

    pub fn initialize_smart_contract <F> (&mut self, identifier: &QualifiedContractIdentifier, contract_ast: &ContractAST, abort_call_back: F) -> Result<(), Error>
    where F: FnOnce(&AssetMap, &mut ClarityDatabase) -> bool {
        self.with_abort_callback(
            |vm_env| { vm_env.initialize_contract_from_ast(identifier.clone(), contract_ast)
                       .map_err(Error::from) },
            abort_call_back)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use vm::types::{Value, StandardPrincipalData};
    use vm::database::marf;
    use chainstate::stacks::index::storage::{TrieFileStorage};
    use vm::database::KeyValueStorage;
    use rusqlite::NO_PARAMS;

    #[test]
    pub fn simple_test() {
        let marf = marf::in_memory_marf();
        let mut clarity_instance = ClarityInstance::new(marf);

        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

        {
            let mut conn = clarity_instance.begin_block(&TrieFileStorage::block_sentinel(),
                                                        &BlockHeaderHash::from_bytes(&[0 as u8; 32]).unwrap());
            
            let contract = "(define-public (foo (x int)) (ok (+ x x)))";
            
            let (ct_ast, ct_analysis) = conn.analyze_smart_contract(&contract_identifier, &contract).unwrap();
            conn.initialize_smart_contract(
                &contract_identifier, &ct_ast, |_,_| false).unwrap();
            conn.save_analysis(&contract_identifier, &ct_analysis).unwrap();
            
            assert_eq!(
                conn.run_contract_call(&StandardPrincipalData::transient().into(), &contract_identifier, "foo", &[Value::Int(1)],
                                       |_, _| false).unwrap(),
                Value::okay(Value::Int(2)));
            
            conn.commit_block();
        }
        let mut marf = clarity_instance.destroy();
        assert!((&mut marf).has_entry(&ClarityDatabase::make_contract_key(&contract_identifier)));
    }

    #[test]
    pub fn test_block_roll_back() {
        let marf = marf::in_memory_marf();
        let mut clarity_instance = ClarityInstance::new(marf);
        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

        {
            let mut conn = clarity_instance.begin_block(&TrieFileStorage::block_sentinel(),
                                                        &BlockHeaderHash::from_bytes(&[0 as u8; 32]).unwrap());

            let contract = "(define-public (foo (x int)) (ok (+ x x)))";

            let (ct_ast, ct_analysis) = conn.analyze_smart_contract(&contract_identifier, &contract).unwrap();
            conn.initialize_smart_contract(
                &contract_identifier, &ct_ast, |_,_| false).unwrap();
            conn.save_analysis(&contract_identifier, &ct_analysis).unwrap();
            
            conn.rollback_block();
        }

        let mut marf = clarity_instance.destroy();
        // should not be in the marf.
        assert!(! (&mut marf).has_entry(&ClarityDatabase::make_contract_key(&contract_identifier)));
        let mut sql = marf.get_side_store();
        // sqlite should not have any entries
        assert_eq!(0,
                   sql.mut_conn()
                   .query_row::<u32,_,_>("SELECT COUNT(value) FROM data_table", NO_PARAMS, |row| row.get(0)).unwrap());
    }

    #[test]
    pub fn test_tx_roll_backs() {
        let marf = marf::in_memory_marf();
        let mut clarity_instance = ClarityInstance::new(marf);
        let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();
        let sender = StandardPrincipalData::transient().into();

        {
            let mut conn = clarity_instance.begin_block(&TrieFileStorage::block_sentinel(),
                                                        &BlockHeaderHash::from_bytes(&[0 as u8; 32]).unwrap());

            let contract = "
            (define-data-var bar int 0)
            (define-public (get-bar) (ok (var-get bar)))
            (define-public (set-bar (x int) (y int))
              (begin (var-set! bar (/ x y)) (ok (var-get bar))))";

            let (ct_ast, ct_analysis) = conn.analyze_smart_contract(&contract_identifier, &contract).unwrap();
            conn.initialize_smart_contract(
                &contract_identifier, &ct_ast, |_,_| false).unwrap();
            conn.save_analysis(&contract_identifier, &ct_analysis).unwrap();

            assert_eq!(
                conn.run_contract_call(&sender, &contract_identifier, "get-bar", &[],
                                       |_, _| false).unwrap(),
                Value::okay(Value::Int(0)));

            assert_eq!(
                conn.run_contract_call(&sender, &contract_identifier, "set-bar", &[Value::Int(1), Value::Int(1)],
                                       |_, _| false).unwrap(),
                Value::okay(Value::Int(1)));

            assert_eq!(
                conn.run_contract_call(&sender, &contract_identifier, "set-bar", &[Value::Int(10), Value::Int(1)],
                                       |_, _| true).unwrap(),
                Value::okay(Value::Int(10)));

            // prior transaction should have rolled back due to abort call back!
            assert_eq!(
                conn.run_contract_call(&sender, &contract_identifier, "get-bar", &[],
                                       |_, _| false).unwrap(),
                Value::okay(Value::Int(1)));

            assert!(
                format!("{:?}",
                        conn.run_contract_call(&sender, &contract_identifier, "set-bar", &[Value::Int(10), Value::Int(0)],
                                               |_, _| true).unwrap_err())
                    .contains("DivisionByZero"));

            // prior transaction should have rolled back due to runtime error
            assert_eq!(
                conn.run_contract_call(&StandardPrincipalData::transient().into(), &contract_identifier, "get-bar", &[],
                                       |_, _| false).unwrap(),
                Value::okay(Value::Int(1)));

            
            conn.commit_block();
        }
    }

}
