defmodule IPCrypt.Nd do
  @moduledoc """
  Implementation of ipcrypt-nd using KIASU-BC.
  """

  alias IPCrypt.Kiasu
  alias IPCrypt.Utils

  @doc """
  Encrypts an IP address using ipcrypt-nd.

  ## Parameters
  - ip_address: IP address as a string or tuple
  - key: 16-byte encryption key
  - tweak: Optional 8-byte tweak (if not provided, a random one will be generated)

  ## Returns
  - 24-byte binary (8-byte tweak || 16-byte ciphertext)
  """
  def encrypt(ip_address, key, tweak) when byte_size(key) == 16 and byte_size(tweak) == 8 do
    # Convert IP to bytes
    ip_bytes = Utils.ip_to_bytes(ip_address)

    # Encrypt using KIASU-BC
    ciphertext = Kiasu.encrypt(key, tweak, ip_bytes)

    # Return tweak || ciphertext
    tweak <> ciphertext
  end

  def encrypt(_ip_address, key, _tweak) when byte_size(key) != 16 do
    {:error, "Key must be 16 bytes"}
  end

  def encrypt(ip_address, key) when byte_size(key) == 16 do
    # Generate random 8-byte tweak
    tweak = :crypto.strong_rand_bytes(8)
    encrypt(ip_address, key, tweak)
  end

  @doc """
  Decrypts an IP address using ipcrypt-nd.

  ## Parameters
  - encrypted_data: 24-byte binary (8-byte tweak || 16-byte ciphertext)
  - key: 16-byte encryption key

  ## Returns
  - Original IP address as a string
  """
  def decrypt(encrypted_data, key)
      when byte_size(encrypted_data) == 24 and byte_size(key) == 16 do
    # Split into tweak and ciphertext
    <<tweak::binary-size(8), ciphertext::binary-size(16)>> = encrypted_data

    # Decrypt using KIASU-BC
    ip_bytes = Kiasu.decrypt(key, tweak, ciphertext)

    # Convert back to IP address
    Utils.bytes_to_ip(ip_bytes)
  end

  def decrypt(_encrypted_data, key) when byte_size(key) != 16 do
    {:error, "Key must be 16 bytes"}
  end

  def decrypt(encrypted_data, _key) when byte_size(encrypted_data) != 24 do
    {:error, "Encrypted data must be 24 bytes"}
  end
end
