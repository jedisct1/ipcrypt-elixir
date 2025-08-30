# IPCrypt Elixir Implementation

This is an Elixir implementation of the IPCrypt specification for IP address encryption and obfuscation.

## Features

- **ipcrypt-deterministic**: Deterministic encryption using AES-128
- **ipcrypt-nd**: Non-deterministic encryption using KIASU-BC with 8-byte tweaks
- **ipcrypt-ndx**: Non-deterministic encryption using AES-XTS with 16-byte tweaks

## Installation

Add `ipcrypt` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ipcrypt, "~> 0.1.0"}
  ]
end
```

## Usage

```elixir
# Deterministic encryption
key16 = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
ip = "192.0.2.1"
encrypted_ip = IPCrypt.Deterministic.encrypt(ip, key16)
decrypted_ip = IPCrypt.Deterministic.decrypt(encrypted_ip, key16)

# Non-deterministic encryption with KIASU-BC
encrypted_data_nd = IPCrypt.Nd.encrypt(ip, key16)
decrypted_ip_nd = IPCrypt.Nd.decrypt(encrypted_data_nd, key16)

# Non-deterministic encryption with AES-XTS
key32 = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>
encrypted_data_ndx = IPCrypt.Ndx.encrypt(ip, key32)
decrypted_ip_ndx = IPCrypt.Ndx.decrypt(encrypted_data_ndx, key32)
```

## Testing

To run the tests:

```bash
mix test
```

The tests verify the implementation against the official test vectors from the IPCrypt specification.

## License

This implementation is released under the MIT license.