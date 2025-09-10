#!/usr/bin/env elixir

# Example usage of IPCrypt

# Example 1: Deterministic encryption
IO.puts("=== Deterministic Encryption ===")
key16 = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
ip = "192.0.2.1"

encrypted_ip = IPCrypt.Deterministic.encrypt(ip, key16)
IO.puts("Original IP: #{ip}")
IO.puts("Encrypted IP: #{encrypted_ip}")

decrypted_ip = IPCrypt.Deterministic.decrypt(encrypted_ip, key16)
IO.puts("Decrypted IP: #{decrypted_ip}")
IO.puts("Match: #{ip == decrypted_ip}")
IO.puts("")

# Example 2: Prefix-preserving encryption
IO.puts("=== Prefix-Preserving Encryption ===")
key32 = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>
ip_pfx = "192.168.1.42"

encrypted_ip_pfx = IPCrypt.Pfx.encrypt(ip_pfx, key32)
IO.puts("Original IP: #{ip_pfx}")
IO.puts("Encrypted IP: #{encrypted_ip_pfx}")

decrypted_ip_pfx = IPCrypt.Pfx.decrypt(encrypted_ip_pfx, key32)
IO.puts("Decrypted IP: #{decrypted_ip_pfx}")
IO.puts("Match: #{ip_pfx == decrypted_ip_pfx}")

# Show prefix preservation with another IP from the same network
ip_pfx2 = "192.168.1.100"
encrypted_ip_pfx2 = IPCrypt.Pfx.encrypt(ip_pfx2, key32)
IO.puts("Another IP from same network: #{ip_pfx2}")
IO.puts("Encrypted: #{encrypted_ip_pfx2}")
IO.puts("Same network prefix preserved: #{String.slice(encrypted_ip_pfx, 0, 10) == String.slice(encrypted_ip_pfx2, 0, 10)}")
IO.puts("")

# Example 3: Non-deterministic encryption with KIASU-BC
IO.puts("=== Non-Deterministic Encryption (KIASU-BC) ===")
encrypted_data_nd = IPCrypt.Nd.encrypt(ip, key16)
IO.puts("Original IP: #{ip}")
IO.puts("Encrypted data size: #{byte_size(encrypted_data_nd)} bytes")

decrypted_ip_nd = IPCrypt.Nd.decrypt(encrypted_data_nd, key16)
IO.puts("Decrypted IP: #{decrypted_ip_nd}")
IO.puts("Match: #{ip == decrypted_ip_nd}")
IO.puts("")

# Example 4: Non-deterministic encryption with AES-XTS
IO.puts("=== Non-Deterministic Encryption (AES-XTS) ===")
key32 = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>
encrypted_data_ndx = IPCrypt.Ndx.encrypt(ip, key32)
IO.puts("Original IP: #{ip}")
IO.puts("Encrypted data size: #{byte_size(encrypted_data_ndx)} bytes")

decrypted_ip_ndx = IPCrypt.Ndx.decrypt(encrypted_data_ndx, key32)
IO.puts("Decrypted IP: #{decrypted_ip_ndx}")
IO.puts("Match: #{ip == decrypted_ip_ndx}")