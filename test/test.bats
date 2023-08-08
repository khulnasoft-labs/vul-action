#!/usr/bin/env bats
bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-file

@test "vul repo with securityCheck secret only" {
  # vul repo --format json --output repo.test --scanners=secret https://github.com/krol3/demo-vul/
  run ./entrypoint.sh '-b json' '-h repo.test' '-s secret' '-a repo' '-j https://github.com/krol3/demo-vul/'
  run diff repo.test ./test/data/repo.test
  echo "$output"
  assert_files_equal repo.test ./test/data/repo.test
}

@test "vul image" {
  # vul image --severity CRITICAL --output image.test knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh '-a image' '-i knqyf263/vuln-image:1.2.3' '-h image.test' '-g CRITICAL'
  run diff image.test ./test/data/image.test
  echo "$output"
  assert_files_equal image.test ./test/data/image.test
}

@test "vul config sarif report" {
  # vul config --format sarif --output  config-sarif.test .
  run ./entrypoint.sh '-a config' '-b sarif' '-h config-sarif.test' '-j .'
  run diff config-sarif.test ./test/data/config-sarif.test
  echo "$output"
  assert_files_equal config-sarif.test ./test/data/config-sarif.test
}

@test "vul config" {
  # vul config --format json --output config.test .
  run ./entrypoint.sh '-a config' '-b json' '-j .' '-h config.test'
  run diff config.test ./test/data/config.test
  echo "$output"
  assert_files_equal config.test ./test/data/config.test
}

@test "vul rootfs" {
  # vul rootfs --output rootfs.test .
  run ./entrypoint.sh '-a rootfs' '-j .' '-h rootfs.test'
  run diff rootfs.test ./test/data/rootfs.test
  echo "$output"
  assert_files_equal rootfs.test ./test/data/rootfs.test
}

@test "vul fs" {
  # vul fs --output fs.test .
  run ./entrypoint.sh '-a fs' '-j .' '-h fs.test'
  run diff fs.test ./test/data/fs.test
  echo "$output"
  assert_files_equal fs.test ./test/data/fs.test
}

@test "vul fs with securityChecks option" {
  # vul fs --format json --scanners=vuln,config --output fs-scheck.test .
  run ./entrypoint.sh '-a fs' '-b json' '-j .' '-s vuln,config,secret' '-h fs-scheck.test'
  run diff fs-scheck.test ./test/data/fs-scheck.test
  echo "$output"
  assert_files_equal fs-scheck.test ./test/data/fs-scheck.test
}


@test "vul image with vulIgnores option" {
  # cat ./test/data/.vulignore1 ./test/data/.vulignore2 > ./vulignores ; vul image --severity CRITICAL  --output image-vulignores.test --ignorefile ./vulignores knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh '-a image' '-i knqyf263/vuln-image:1.2.3' '-h image-vulignores.test' '-g CRITICAL' '-t ./test/data/.vulignore1,./test/data/.vulignore2'
  run diff image-vulignores.test ./test/data/image-vulignores.test
  echo "$output"
  assert_files_equal image-vulignores.test ./test/data/image-vulignores.test
}

@test "vul image with sbom output" {
  # vul image --format  github knqyf263/vuln-image:1.2.3
  run ./entrypoint.sh  "-a image" "-b github" "-i knqyf263/vuln-image:1.2.3"
  assert_output --partial '"package_url": "pkg:apk/ca-certificates@20171114-r0",' # TODO: Output contains time, need to mock
}

@test "vul image with vul.yaml config" {
  # vul --config=./test/data/vul.yaml image alpine:3.10
  run ./entrypoint.sh "-v ./test/data/vul.yaml" "-a image" "-i alpine:3.10"
  run diff yamlconfig.test ./test/data/yamlconfig.test
  echo "$output"
  assert_files_equal yamlconfig.test ./test/data/yamlconfig.test
}
