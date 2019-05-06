export interface BufferAtomicType {
  BufferType: number;
}

export interface TupleAtomicType {
  TupleType: {
    type_map: {
      [name: string]: TypeSignature;
    };
  };
}

export type AtomicType =
  | 'VoidType'
  | 'IntType'
  | 'BoolType'
  | 'PrincipalType'
  | BufferAtomicType
  | TupleAtomicType;

export interface TypeSignature {
  atomic_type: AtomicType;
  list_dimensions?: number;
}

export const FunctionArgTypes = 0;
export const FunctionReturnType = 1;

export interface FunctionTypeSignatureArray {
  [FunctionArgTypes]: TypeSignature[];
  [FunctionReturnType]: TypeSignature;
}

export interface FunctionTypeSignature {
  Fixed?: FunctionTypeSignatureArray;
  Variadic?: FunctionTypeSignatureArray;
}

export interface ContractTypes {
  private_function_types: {
    [name: string]: FunctionTypeSignature;
  };
  public_function_types: {
    [name: string]: FunctionTypeSignature;
  };
  variable_types: {
    [name: string]: TypeSignature;
  };
  map_types: {
    [name: string]: TypeSignature[];
  };
}
