defmodule IPCrypt.SimpleTest do
  def test_deterministic do
    key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
    ip = "192.0.2.1"
    encrypted = IPCrypt.encrypt(ip, key, :deterministic)
    decrypted = IPCrypt.decrypt(encrypted, key, :deterministic)
    IO.puts("Original: #{ip}")
    IO.puts("Encrypted: #{encrypted}")
    IO.puts("Decrypted: #{decrypted}")
    IO.puts("Match: #{ip == decrypted}")
  end

  def test_nd do
    key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
    ip = "192.0.2.1"
    encrypted = IPCrypt.encrypt(ip, key, :nd)
    decrypted = IPCrypt.decrypt(encrypted, key, :nd)
    IO.puts("Original: #{ip}")
    IO.puts("Encrypted size: #{byte_size(encrypted)}")
    IO.puts("Decrypted: #{decrypted}")
    IO.puts("Match: #{ip == decrypted}")
  end

  def test_ndx do
    key = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>
    ip = "192.0.2.1"
    encrypted = IPCrypt.encrypt(ip, key, :ndx)
    decrypted = IPCrypt.decrypt(encrypted, key, :ndx)
    IO.puts("Original: #{ip}")
    IO.puts("Encrypted size: #{byte_size(encrypted)}")
    IO.puts("Decrypted: #{decrypted}")
    IO.puts("Match: #{ip == decrypted}")
  end
end