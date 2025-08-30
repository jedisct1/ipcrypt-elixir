# Quick benchmark for IPCrypt implementations
# Run with: mix run bench/quick_bench.exs

key16 = :crypto.strong_rand_bytes(16)
key32 = :crypto.strong_rand_bytes(32)
tweak8 = :crypto.strong_rand_bytes(8)
test_ip = "192.0.2.1"

IO.puts("\n=== IPCrypt Quick Benchmark ===\n")
IO.puts("Comparing encryption performance for IP: #{test_ip}\n")

Benchee.run(
  %{
    "deterministic" => fn -> IPCrypt.Deterministic.encrypt(test_ip, key16) end,
    "nd (KIASU-BC)" => fn -> IPCrypt.Nd.encrypt(test_ip, key16, tweak8) end,
    "ndx (AES-XTS)" => fn -> IPCrypt.Ndx.encrypt(test_ip, key32) end
  },
  time: 2,
  warmup: 1,
  memory_time: 1,
  formatters: [
    {Benchee.Formatters.Console, comparison: true}
  ]
)

# Benchmark encrypt/decrypt round trip
IO.puts("\n=== Round-trip Benchmark (Encrypt + Decrypt) ===\n")

Benchee.run(
  %{
    "deterministic round-trip" => fn ->
      encrypted = IPCrypt.Deterministic.encrypt(test_ip, key16)
      IPCrypt.Deterministic.decrypt(encrypted, key16)
    end,
    "nd round-trip" => fn ->
      encrypted = IPCrypt.Nd.encrypt(test_ip, key16, tweak8)
      IPCrypt.Nd.decrypt(encrypted, key16)
    end,
    "ndx round-trip" => fn ->
      encrypted = IPCrypt.Ndx.encrypt(test_ip, key32)
      IPCrypt.Ndx.decrypt(encrypted, key32)
    end
  },
  time: 2,
  warmup: 1,
  formatters: [
    {Benchee.Formatters.Console, comparison: true}
  ]
)