#!/bin/bash

rm -r target;
rm resources/scenario_ir
docker build -f Dockerfile.nyxlite -t fuzzamoto-nyxlite .
container_id=$(docker run --privileged -v $PWD:/fuzzamoto -dit fuzzamoto-nyxlite)
docker exec --workdir /fuzzamoto -e BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind $container_id cargo build --workspace --target=x86_64-unknown-linux-musl --release --features fuzz

# Are the following needed:
# * --sharedir
# * --crash-handler
# * --nyx-dir
docker exec --workdir /fuzzamoto $container_id ./target/release/fuzzamoto-cli init --sharedir /tmp/fuzzamoto_scenario-ir --crash-handler /fuzzamoto/doesntexist.so --bitcoind /bitcoin/build_fuzz/bin/bitcoind --scenario ./target/release/scenario-ir --nyx-dir ./target/release

docker exec --workdir /fuzzamoto $container_id mount -o remount,size=50% /dev/shm
docker exec --workdir /fuzzamoto $container_id mkdir /tmp/in
docker exec --workdir /fuzzamoto $container_id rm resources/scenario_ir
docker exec --workdir /fuzzamoto $container_id cp -L target/x86_64-unknown-linux-musl/release/scenario_ir resources/scenario_ir

# The below command(s) creates a firecracker config file
docker exec --workdir /fuzzamoto $container_id IMG_ID=$\(docker build -f Dockerfile.vm -q .\); CONTAINER_ID=$\(docker run -td $IMG_ID /bin/bash\); MOUNTDIR=mnt; FS=rootfs.ext4; sudo rm -rf $MOUNTDIR; sudo rm -rf $FS; mkdir $MOUNTDIR; qemu-img create -f raw $FS 800M; mkfs.ext4 $FS; sudo mount $FS $MOUNTDIR; sudo docker cp $CONTAINER_ID:/ $MOUNTDIR; sudo umount $MOUNTDIR; rm -rf $MOUNTDIR; docker stop $CONTAINER_ID; docker rm $CONTAINER_ID

# run:
# * Need to pass in the config file
# * RUST_LOG=info RUST_BACKTRACE=1 ./target/release/fuzzamoto-libafl --verbose --input /tmp/in --output /tmp/out --share /tmp/fuzzamoto_scenario-ir/ --cores 0-$1 --ignore-hangs --timeout 3000 2>&1 | tee fuzzamoto.log 
