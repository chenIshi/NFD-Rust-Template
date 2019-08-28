# NFD-Rust-Template
Compile template of translating NFD to Rust

## Need to be fixed

1. Instead of implementing Hash trait on HashMap/ HashSet in order to have a two layer mapping (`ID namespace` -> `mapping title` -> `mapping content`), I just use BtreeMap/BtreeSet to avoid implementing it.
