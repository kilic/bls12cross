module github.com/kilic/bls12cross/eip2537

go 1.16

require (
	github.com/consensys/gnark-crypto v0.4.0 // indirect
	github.com/herumi/bls-eth-go-binary v0.0.0-20210407105559-9588dcfc7de7
	github.com/kilic/bls12-381 v0.1.1-0.20210208205449-6045b0235e36
	github.com/sean-sn/blst_eip2537/go v0.0.0-20210112153044-bd46a10e26c1 // indirect
	golang.org/x/sys v0.0.0-20210326220804-49726bf1d181 // indirect

)

replace github.com/sean-sn/blst_eip2537/go => ../blst_eip2537/go
