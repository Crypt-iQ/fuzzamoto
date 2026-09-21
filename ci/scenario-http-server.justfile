corpus:
        rm -rf /tmp/in && mkdir /tmp/in && echo "AAA" > /tmp/in/A

run: corpus
        /AFLplusplus/afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server

test: corpus
        #!/bin/bash
        # Nested-virt runners boot the Nyx VM slowly, so poll fuzzer_stats rather than using a
        # fixed budget: pass as soon as corpus_count exceeds 5, fail after 180s.
        AFL_NO_UI=1 /AFLplusplus/afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server > /dev/null &
        pid=$!
        count=0
        for _ in $(seq 180); do
            count=$(grep "corpus_count" /tmp/out/default/fuzzer_stats 2>/dev/null | grep -o '[0-9]\+')
            count=${count:-0}
            if [ "$count" -gt 5 ]; then
                echo "Fuzzer is working (new corpus items: $count)"
                kill "$pid"
                exit 0
            fi
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        echo "Fuzzer does not generate enough testcases (new corpus items: $count)"
        cat /tmp/out/default/fuzzer_stats 2>/dev/null
        kill "$pid" 2>/dev/null
        exit 1

[working-directory: '/fuzzamoto']
clean:
        rm -rf /tmp/in && rm -rf /tmp/out && cargo clean