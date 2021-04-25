Run Tests and Benchmarks with library flag `-lib blst` or `-lib herumi` or `-lib kilic`

```
# test
go test -lib herumi -v
# benchmark
go test -run none -bench . -lib herumi -v
```