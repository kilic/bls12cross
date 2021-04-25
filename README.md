BLS12-381 ecc libaries cross tests in BLS signatures and EIP2537 contexts.

## BLS Signature

`blst`, `herumi/bls-eth-go-binary` and `kilic/bls12-381` are subjected to cross tests and benchmarks.

## EIP2537

Base libraries are `blst` and `kilic/bls12-381`. For `blst` library we used [the existing wrappers](https://github.com/sean-sn/blst_eip2537). Since this wrappers couldn't simply be used with go modules we needed to apply a workaround. Run build script:

```
./build_eip2537.sh
```