## Coverage reports

It is possible to generate coverage reports for fuzzamoto scenarios by using the
`fuzzamoto-cli coverage` command. The build steps for doing this are slightly
different than if you were to run `fuzzamoto-cli init`:
- the bitcoind node must be compiled with llvm's [source-based code coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html).
- fuzzamoto's nyx feature should be disabled as coverage tooling does not use snapshots.
- AFL++ nyx support is unnecessary and does not need to be built.
- a corpus for the specific scenario is required

An example Dockerfile that runs a corpus against the compact blocks scenario to
generate a coverage report can be found in `Dockerfile.coverage`. A corpus for the
scenario under test must exist in `fuzzamoto/corpus/`.
