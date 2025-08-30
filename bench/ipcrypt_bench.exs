# Benchmark for IPCrypt Elixir implementation
# Run with: mix run bench/ipcrypt_bench.exs

# Setup test data
key16 = :crypto.strong_rand_bytes(16)
key32 = :crypto.strong_rand_bytes(32)
tweak8 = :crypto.strong_rand_bytes(8)

ipv4_addresses = [
  "192.0.2.1",
  "10.0.0.1",
  "172.16.0.1",
  "255.255.255.255",
  "0.0.0.0"
]

ipv6_addresses = [
  "2001:db8::1",
  "fe80::1",
  "::1",
  "2001:db8:85a3::8a2e:370:7334",
  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
]

# Pre-encrypt some data for decryption benchmarks
encrypted_deterministic_ipv4 = IPCrypt.Deterministic.encrypt("192.0.2.1", key16)
encrypted_deterministic_ipv6 = IPCrypt.Deterministic.encrypt("2001:db8::1", key16)
encrypted_nd = IPCrypt.Nd.encrypt("192.0.2.1", key16, tweak8)
encrypted_ndx = IPCrypt.Ndx.encrypt("192.0.2.1", key32)

IO.puts("\n=== IPCrypt Elixir Benchmark ===\n")

Benchee.run(
  %{
    # Deterministic encryption benchmarks
    "deterministic/encrypt/ipv4" => fn ->
      Enum.each(ipv4_addresses, &IPCrypt.Deterministic.encrypt(&1, key16))
    end,
    "deterministic/encrypt/ipv6" => fn ->
      Enum.each(ipv6_addresses, &IPCrypt.Deterministic.encrypt(&1, key16))
    end,
    "deterministic/decrypt/ipv4" => fn ->
      IPCrypt.Deterministic.decrypt(encrypted_deterministic_ipv4, key16)
    end,
    "deterministic/decrypt/ipv6" => fn ->
      IPCrypt.Deterministic.decrypt(encrypted_deterministic_ipv6, key16)
    end,

    # Non-deterministic (KIASU-BC) benchmarks
    "nd/encrypt/with_tweak" => fn ->
      Enum.each(ipv4_addresses, &IPCrypt.Nd.encrypt(&1, key16, tweak8))
    end,
    "nd/encrypt/random_tweak" => fn ->
      Enum.each(ipv4_addresses, &IPCrypt.Nd.encrypt(&1, key16))
    end,
    "nd/decrypt" => fn ->
      IPCrypt.Nd.decrypt(encrypted_nd, key16)
    end,

    # Non-deterministic (AES-XTS) benchmarks
    "ndx/encrypt" => fn ->
      Enum.each(ipv4_addresses, &IPCrypt.Ndx.encrypt(&1, key32))
    end,
    "ndx/decrypt" => fn ->
      IPCrypt.Ndx.decrypt(encrypted_ndx, key32)
    end,

    # Main module interface benchmarks
    "main/encrypt/deterministic" => fn ->
      IPCrypt.encrypt("192.0.2.1", key16, :deterministic)
    end,
    "main/encrypt/nd" => fn ->
      IPCrypt.encrypt("192.0.2.1", key16, :nd, tweak8)
    end,
    "main/encrypt/ndx" => fn ->
      IPCrypt.encrypt("192.0.2.1", key32, :ndx)
    end
  },
  time: 5,
  memory_time: 2,
  warmup: 2,
  formatters: [
    Benchee.Formatters.Console
  ]
)

IO.puts("\n=== Throughput Benchmark ===\n")

# Throughput benchmark - how many IPs can we encrypt per second
batch_size = 1000
ip_batch = List.duplicate("192.0.2.1", batch_size)

Benchee.run(
  %{
    "throughput/deterministic/#{batch_size}_ips" => fn ->
      Enum.each(ip_batch, &IPCrypt.Deterministic.encrypt(&1, key16))
    end,
    "throughput/nd/#{batch_size}_ips" => fn ->
      Enum.each(ip_batch, &IPCrypt.Nd.encrypt(&1, key16, tweak8))
    end,
    "throughput/ndx/#{batch_size}_ips" => fn ->
      Enum.each(ip_batch, &IPCrypt.Ndx.encrypt(&1, key32))
    end
  },
  time: 5,
  warmup: 2,
  formatters: [
    {Benchee.Formatters.Console, extended_statistics: true}
  ]
)

IO.puts("\n=== KIASU-BC Components Benchmark ===\n")

# Benchmark individual KIASU-BC components
plaintext = :crypto.strong_rand_bytes(16)

Benchee.run(
  %{
    "kiasu/encrypt" => fn ->
      IPCrypt.Kiasu.encrypt(key16, tweak8, plaintext)
    end,
    "kiasu/decrypt" => fn ->
      ciphertext = IPCrypt.Kiasu.encrypt(key16, tweak8, plaintext)
      IPCrypt.Kiasu.decrypt(key16, tweak8, ciphertext)
    end,
    "aes_xts/encrypt" => fn ->
      tweak16 = :crypto.strong_rand_bytes(16)
      IPCrypt.Ndx.aes_xts_encrypt(key32, tweak16, plaintext)
    end,
    "aes_xts/decrypt" => fn ->
      tweak16 = :crypto.strong_rand_bytes(16)
      ciphertext = IPCrypt.Ndx.aes_xts_encrypt(key32, tweak16, plaintext)
      IPCrypt.Ndx.aes_xts_decrypt(key32, tweak16, ciphertext)
    end
  },
  time: 3,
  warmup: 1,
  formatters: [
    Benchee.Formatters.Console
  ]
)