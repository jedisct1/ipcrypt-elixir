# IPCrypt Benchmarks

This directory contains benchmark scripts for the IPCrypt Elixir implementation.

## Available Benchmarks

### Quick Benchmark (`quick_bench.exs`)

A fast benchmark that compares the performance of all three IPCrypt variants:
- Deterministic (AES-128)
- Non-deterministic with KIASU-BC
- Non-deterministic with AES-XTS

Run with:
```bash
mix run bench/quick_bench.exs
```

### Comprehensive Benchmark (`ipcrypt_bench.exs`)

A detailed benchmark that includes:
- IPv4 and IPv6 encryption/decryption
- Throughput measurements (operations per second)
- Individual component benchmarks (KIASU-BC, AES-XTS)
- Memory usage analysis

Run with:
```bash
mix run bench/ipcrypt_bench.exs
```

## Performance Results

Based on the benchmarks, the relative performance of the three variants is:

1. **Deterministic (fastest)** - Best for scenarios where the same IP always produces the same output
2. **NDX with AES-XTS** - ~1.5x slower than deterministic, provides non-deterministic encryption with 16-byte tweaks
3. **ND with KIASU-BC** - ~70x slower than deterministic, provides non-deterministic encryption with 8-byte tweaks

## Interpreting Results

- **ips**: Iterations per second (higher is better)
- **average**: Average time per operation (lower is better)
- **deviation**: Standard deviation as a percentage (lower is more consistent)
- **median**: Middle value of all measurements
- **99th %**: 99% of operations complete within this time
