defmodule IPCrypt.Ndx do
  @moduledoc """
  Implementation of ipcrypt-ndx using AES-XTS with a 16-byte tweak.
  """

  alias IPCrypt.Utils

  @doc """
  Encrypts an IP address using AES-XTS.

  ## Parameters
  - ip: IP address as a string or tuple
  - key: 32-byte encryption key (two AES-128 keys)

  ## Returns
  - 32-byte binary (16-byte tweak || 16-byte ciphertext)
  """
  def encrypt(ip, key) when byte_size(key) == 32 do
    # Generate random 16-byte tweak
    tweak = :crypto.strong_rand_bytes(16)

    # Convert IP to bytes and encrypt
    plaintext = Utils.ip_to_bytes(ip)
    ciphertext = aes_xts_encrypt(key, tweak, plaintext)

    # Return tweak || ciphertext
    tweak <> ciphertext
  end

  def encrypt(_ip, key) when byte_size(key) != 32 do
    {:error, "Key must be 32 bytes"}
  end

  @doc """
  Decrypts a binary output using AES-XTS.

  ## Parameters
  - binary_output: 32-byte binary (16-byte tweak || 16-byte ciphertext)
  - key: 32-byte encryption key (two AES-128 keys)

  ## Returns
  - Original IP address as a string
  """
  def decrypt(binary_output, key) when byte_size(key) == 32 and byte_size(binary_output) == 32 do
    # Split into tweak and ciphertext
    <<tweak::binary-size(16), ciphertext::binary-size(16)>> = binary_output

    # Decrypt and convert back to IP
    plaintext = aes_xts_decrypt(key, tweak, ciphertext)
    Utils.bytes_to_ip(plaintext)
  end

  def decrypt(_binary_output, key) when byte_size(key) != 32 do
    {:error, "Key must be 32 bytes"}
  end

  def decrypt(binary_output, _key) when byte_size(binary_output) != 32 do
    {:error, "Binary output must be 32 bytes"}
  end

  # Helper functions

  def aes_xts_encrypt(key, tweak, plaintext)
      when byte_size(key) == 32 and byte_size(tweak) == 16 and byte_size(plaintext) == 16 do
    # Split key into two 16-byte keys
    <<k1::binary-size(16), k2::binary-size(16)>> = key

    # Encrypt tweak with second key
    et = :crypto.crypto_one_time(:aes_128_ecb, k2, tweak, true)

    # XOR plaintext with encrypted tweak
    xored = xor_bytes(plaintext, et)

    # Encrypt with first key
    encrypted = :crypto.crypto_one_time(:aes_128_ecb, k1, xored, true)

    # XOR result with encrypted tweak
    xor_bytes(encrypted, et)
  end

  def aes_xts_decrypt(key, tweak, ciphertext)
      when byte_size(key) == 32 and byte_size(tweak) == 16 and byte_size(ciphertext) == 16 do
    # Split key into two 16-byte keys
    <<k1::binary-size(16), k2::binary-size(16)>> = key

    # Encrypt tweak with second key
    et = :crypto.crypto_one_time(:aes_128_ecb, k2, tweak, true)

    # XOR ciphertext with encrypted tweak
    xored = xor_bytes(ciphertext, et)

    # Decrypt with first key
    decrypted = :crypto.crypto_one_time(:aes_128_ecb, k1, xored, false)

    # XOR result with encrypted tweak
    xor_bytes(decrypted, et)
  end

  def xor_bytes(a, b) do
    a
    |> :binary.bin_to_list()
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.map(fn {x, y} -> Bitwise.bxor(x, y) end)
    |> :binary.list_to_bin()
  end
end
