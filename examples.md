# IPCrypt Elixir Implementation Examples

This file demonstrates how to use the IPCrypt Elixir implementation.

## Installation

Add `ipcrypt` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ipcrypt, "~> 0.2.0"}
  ]
end
```

## Usage Examples

### Deterministic Encryption (ipcrypt-deterministic)

```elixir
# Encrypt an IP address
key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>  # 16 bytes
ip = "192.0.2.1"
encrypted_ip = IPCrypt.encrypt(ip, key, :deterministic)
# => Encrypted IP as string

# Decrypt an IP address
decrypted_ip = IPCrypt.decrypt(encrypted_ip, key, :deterministic)
# => "192.0.2.1"
```

### Prefix-Preserving Encryption (ipcrypt-pfx)

```elixir
# Encrypt an IP address
key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>  # 32 bytes
ip = "192.168.1.42"
encrypted_ip = IPCrypt.encrypt(ip, key, :pfx)
# => Encrypted IP as string (preserves network prefix relationships)

# Decrypt an IP address
decrypted_ip = IPCrypt.decrypt(encrypted_ip, key, :pfx)
# => "192.168.1.42"

# Demonstrate prefix preservation
ip1 = "192.168.1.42"
ip2 = "192.168.1.100"  # Same /24 network
encrypted_ip1 = IPCrypt.encrypt(ip1, key, :pfx)
encrypted_ip2 = IPCrypt.encrypt(ip2, key, :pfx)
# Both encrypted IPs will share the same network prefix
```

### Non-Deterministic Encryption with KIASU-BC (ipcrypt-nd)

```elixir
# Encrypt an IP address (random tweak will be generated)
key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>  # 16 bytes
ip = "192.0.2.1"
encrypted_data = IPCrypt.encrypt(ip, key, :nd)
# => 24-byte binary (8-byte tweak || 16-byte ciphertext)

# Encrypt with specific tweak
tweak = <<1, 2, 3, 4, 5, 6, 7, 8>>  # 8 bytes
encrypted_data = IPCrypt.encrypt(ip, key, :nd, tweak)

# Decrypt
decrypted_ip = IPCrypt.decrypt(encrypted_data, key, :nd)
# => "192.0.2.1"
```

### Non-Deterministic Encryption with AES-XTS (ipcrypt-ndx)

```elixir
# Encrypt an IP address (random tweak will be generated)
key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>  # 32 bytes
ip = "192.0.2.1"
encrypted_data = IPCrypt.encrypt(ip, key, :ndx)
# => 32-byte binary (16-byte tweak || 16-byte ciphertext)

# Decrypt
decrypted_ip = IPCrypt.decrypt(encrypted_data, key, :ndx)
# => "192.0.2.1"
```

## Testing

To run the tests:

```bash
mix test
```

The tests verify the implementation against the official test vectors from the IPCrypt specification.