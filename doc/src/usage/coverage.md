# Coverage Reports

It is possible to generate coverage reports for fuzzamoto scenarios by using the
`fuzzamoto-cli coverage` command. The build steps for doing this are slightly
different than if you were to run `fuzzamoto-cli init`:
- the bitcoind node must be compiled with llvm's [source-based code coverage](https://clang.llvm.org/docs/SourceBasedCodeCoverage.html).
- fuzzamoto's nyx feature should be disabled as coverage tooling does not use snapshots.
- AFL++ nyx support is unnecessary and does not need to be built.
- a corpus for the specific scenario is required

The `Dockerfile.coverage` file can be used to run a corpus against a specific scenario.
Both a host directory and a corpus directory must be mounted.

Example:

```
docker build -t fuzzamoto .
docker run --privileged -it -v HOST_OUTPUT_DIR:/mnt/output -v HOST_CORPUS_DIR:/mnt/corpus fuzzamoto /fuzzamoto/target/release/scenario-compact-blocks
```
