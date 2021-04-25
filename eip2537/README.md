Run Tests and Benchmarks with library flag `-lib blst` or `-lib kilic`

```
# test
go test -lib blst
# benchmark
go test -run none -bench . -lib blst
```