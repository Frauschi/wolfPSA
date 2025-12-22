## Testing (PSA Architecture Test Suite)


### Building and running the test

The script `./psa-crypto-tests.sh` provided does the following:

1. Clones the psa-arch-tests repository in this directory and/or runs `git clean`

2. Patches a bug in the psa-arch-tests repository:
  `patch -p1 < psa-arch-tests-ec_overflow.patch`

3. Copies the directory `tgt_dev_apis_wolfpsa` to `psa-arch-tests/api-tests/platform/targets/`

4. Runs cmake and builds the test suite
```
cmake -S psa-arch-tests/api-tests -B psa-arch-tests/api-tests/build-crypto \
  -DTARGET=tgt_dev_apis_wolfpsa -DSUITE=CRYPTO \
  -DPSA_INCLUDE_PATHS="/home/dan/src/psa-workspace/wolfPSA/wolfpsa" \
  -DTOOLCHAIN=HOST_GCC -DCPU_ARCH=armv8a \
  -DPSA_CRYPTO_LIB_FILENAME="/home/dan/src/psa-workspace/wolfPSA/libwolfpsa.a" \
  -DPSA_STORAGE_LIB_FILENAME=""

cmake --build psa-arch-tests/api-tests/build-crypto -j4
```

5. Runs the test suite, showing the current results

```
./psa-arch-tests/api-tests/build-crypto/psa-arch-tests-crypto
```


### Algorithms disabled / unsupported / deprecated

Unsupported algorithms are disabled in the target config at:
`psa-arch-tests/api-tests/platform/targets/tgt_dev_apis_wolfpsa/nspe/pal_crypto_config.h`.

