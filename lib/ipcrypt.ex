defmodule IPCrypt do
  @moduledoc """
  Main module for IPCrypt - Methods for IP Address Encryption and Obfuscation.

  This module provides functions for encrypting and decrypting IP addresses
  using four different variants:

  1. `ipcrypt-deterministic` - Deterministic encryption using AES-128
  2. `ipcrypt-pfx` - Prefix-preserving encryption using dual AES-128
  3. `ipcrypt-nd` - Non-deterministic encryption using KIASU-BC with 8-byte tweak
  4. `ipcrypt-ndx` - Non-deterministic encryption using AES-XTS with 16-byte tweak
  """

  alias IPCrypt.Deterministic
  alias IPCrypt.Pfx
  alias IPCrypt.Nd
  alias IPCrypt.Ndx

  @doc """
  Encrypts an IP address using one of the IPCrypt methods.

  ## Parameters
  - ip: IP address as a string
  - key: Encryption key (16 bytes for deterministic and nd, 32 bytes for pfx and ndx)
  - method: Encryption method (:deterministic, :pfx, :nd, or :ndx)
  - tweak: Optional 8-byte tweak (only used for :nd method)

  ## Returns
  - Encrypted data (string for deterministic and pfx, binary for nd and ndx)
  """
  def encrypt(ip, key, method, tweak \\ nil)

  def encrypt(ip, key, :deterministic, _tweak) do
    Deterministic.encrypt(ip, key)
  end

  def encrypt(ip, key, :pfx, _tweak) do
    if byte_size(key) != 32 do
      {:error, "Key must be 32 bytes for ipcrypt-pfx"}
    else
      Pfx.encrypt(ip, key)
    end
  end

  def encrypt(ip, key, :nd, tweak) do
    if byte_size(key) != 16 do
      {:error, "Key must be 16 bytes for ipcrypt-nd"}
    else
      if is_nil(tweak) do
        Nd.encrypt(ip, key)
      else
        Nd.encrypt(ip, key, tweak)
      end
    end
  end

  def encrypt(ip, key, :ndx, _tweak) do
    if byte_size(key) != 32 do
      {:error, "Key must be 32 bytes for ipcrypt-ndx"}
    else
      Ndx.encrypt(ip, key)
    end
  end

  @doc """
  Decrypts IP address data using one of the IPCrypt methods.

  ## Parameters
  - data: Encrypted data (string for deterministic and pfx, binary for nd and ndx)
  - key: Encryption key (16 bytes for deterministic and nd, 32 bytes for pfx and ndx)
  - method: Encryption method (:deterministic, :pfx, :nd, or :ndx)

  ## Returns
  - Original IP address as a string
  """
  def decrypt(data, key, method)

  def decrypt(encrypted_ip, key, :deterministic) do
    if byte_size(key) != 16 do
      {:error, "Key must be 16 bytes for ipcrypt-deterministic"}
    else
      Deterministic.decrypt(encrypted_ip, key)
    end
  end

  def decrypt(encrypted_ip, key, :pfx) do
    if byte_size(key) != 32 do
      {:error, "Key must be 32 bytes for ipcrypt-pfx"}
    else
      Pfx.decrypt(encrypted_ip, key)
    end
  end

  def decrypt(encrypted_data, key, :nd) do
    if byte_size(key) != 16 do
      {:error, "Key must be 16 bytes for ipcrypt-nd"}
    else
      Nd.decrypt(encrypted_data, key)
    end
  end

  def decrypt(binary_output, key, :ndx) do
    if byte_size(key) != 32 do
      {:error, "Key must be 32 bytes for ipcrypt-ndx"}
    else
      Ndx.decrypt(binary_output, key)
    end
  end
end
