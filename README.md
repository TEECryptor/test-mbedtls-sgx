# test-mbedtls-sgx
Use mbedtls_SGX in intel SGX Enclave

## Build mbedtls_SGX

- Switch to project folder 

```
git clone https://github.com/bl4ck5un/mbedtls-SGX && cd mbedtls-SGX
mkdir build && cd build
cmake ..
make -j && make install
```

## Copy mbedtls_SGX to /opt

```
sudo cp -r mbedtls_SGX-2.6.0 /opt/.
```

## Build test-mbedtls-sgx

- Hardware mode
```
cd test-mbedtls-sgx
mkdir build && cd build
cmake ..
make
```

- Simulation mode
```
cd test-mbedtls-sgx
mkdir build && cd build
cmake .. -DUSE_SIM_MODE=on
make
```

## Run
```
./App/test-mbedtls_SGX ./Enclave/enclave.signed.so
```