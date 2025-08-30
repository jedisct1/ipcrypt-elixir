defmodule IPCrypt.Deterministic do
  @moduledoc """
  Implementation of ipcrypt-deterministic using AES-128.
  """

  alias IPCrypt.Utils

  @doc """
  Encrypts an IP address using AES-128 in deterministic mode.

  ## Parameters
  - ip: IP address as a string or tuple
  - key: 16-byte encryption key

  ## Returns
  - Encrypted IP address as a string
  """
  def encrypt(ip, key) when is_binary(key) and byte_size(key) == 16 do
    plaintext = Utils.ip_to_bytes(ip)
    ciphertext = :crypto.crypto_one_time(:aes_128_ecb, key, plaintext, true)
    Utils.bytes_to_ip(ciphertext)
  end

  def encrypt(_ip, key) when not is_binary(key) or byte_size(key) != 16 do
    {:error, "Key must be 16 bytes"}
  end

  @doc """
  Decrypts an IP address using AES-128 in deterministic mode.

  ## Parameters
  - encrypted_ip: Encrypted IP address as a string or tuple
  - key: 16-byte encryption key

  ## Returns
  - Original IP address as a string
  """
  def decrypt(encrypted_ip, key) when is_binary(key) and byte_size(key) == 16 do
    ciphertext = Utils.ip_to_bytes(encrypted_ip)
    plaintext = :crypto.crypto_one_time(:aes_128_ecb, key, ciphertext, false)
    Utils.bytes_to_ip(plaintext)
  end

  def decrypt(_encrypted_ip, key) when not is_binary(key) or byte_size(key) != 16 do
    {:error, "Key must be 16 bytes"}
  end
end