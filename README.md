# NFD-Rust-Template
Compile template of translating NFD to Rust

## Need to be fixed

1. Instead of implementing Hash trait on HashMap/ HashSet in order to have a two layer mapping (`ID namespace` -> `mapping title` -> `mapping content`), I just use BtreeMap/BtreeSet to avoid implementing it.

## What Did I Learn

1. Rust Match is not that "intuitive", at least we shouldn't take it as a simple C "switch" semantic

    1. Rust match by default evalute the input, if match any subexpression arm, then the input will be MOVE to the pattern matched variable, this will usually lead to the "cannot move out of borrowed content" error
    
    2. If you don't want the value to be moved, then you have to specify the "ref" keyword to get the reference of input, since reference type variable already have the "copy" trait
