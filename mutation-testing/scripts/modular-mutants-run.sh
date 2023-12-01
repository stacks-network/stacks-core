#!/bin/bash

packages=$(cargo tree --workspace --prefix depth | grep "^0" | cut -c2- | awk '{print $1}')
regex_list=()

while [ $# -gt 0 ]; do
  arg=$1

  if [[ $packages == *$arg* ]]; then
    package=$arg
    file=""
    shift
    arg=$1
  fi
  if [[ $arg == *.rs ]]; then
    file=$arg
    shift
    arg=$1
  fi

  functions=()
  while [ $# -gt 0 ] && [[ $1 != *.rs ]] && [[ $packages != *$1* ]]; do
    functions+=("$1")
    shift
  done

  IFS="|"
  functions_str="${functions[*]}"
  IFS=""

  regex="${package}/[^/]+/${file}.*?(?:${functions_str})[^-()]*(?:->|\(\))"
  regex_list+=("$regex")
done

command="cargo mutants -vV --no-shuffle"

for regex in "${regex_list[@]}"; do
  command+=" -F \"$regex\""
done

eval "$command"