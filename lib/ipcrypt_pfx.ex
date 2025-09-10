defmodule IPCrypt.Pfx do
  @moduledoc """
  Implementation of ipcrypt-pfx using AES-128 for prefix-preserving encryption.
  """

  import Bitwise

  alias IPCrypt.Utils

  @doc """
  Encrypts an IP address using ipcrypt-pfx.

  ## Parameters
  - ip: IP address as a string or tuple
  - key: 32-byte encryption key (split into two 16-byte AES keys)

  ## Returns
  - Encrypted IP address as a string
  """
  def encrypt(ip, key) when byte_size(key) == 32 do
    # Check that K1 and K2 are different
    <<k1::binary-size(16), k2::binary-size(16)>> = key

    if k1 == k2 do
      {:error, "The two halves of the key must be different"}
    else
      do_encrypt(ip, key)
    end
  end

  def encrypt(_ip, key) when byte_size(key) != 32 do
    {:error, "Key must be 32 bytes"}
  end

  @doc """
  Decrypts an IP address using ipcrypt-pfx.

  ## Parameters
  - encrypted_ip: Encrypted IP address as a string or tuple
  - key: 32-byte encryption key (split into two 16-byte AES keys)

  ## Returns
  - Original IP address as a string
  """
  def decrypt(encrypted_ip, key) when byte_size(key) == 32 do
    # Check that K1 and K2 are different
    <<k1::binary-size(16), k2::binary-size(16)>> = key

    if k1 == k2 do
      {:error, "The two halves of the key must be different"}
    else
      do_decrypt(encrypted_ip, key)
    end
  end

  def decrypt(_encrypted_ip, key) when byte_size(key) != 32 do
    {:error, "Key must be 32 bytes"}
  end

  # Private implementation functions

  defp do_encrypt(ip, key) do
    # Split the key into two AES-128 keys
    <<k1::binary-size(16), k2::binary-size(16)>> = key

    # Convert IP to 16-byte representation
    bytes16 = Utils.ip_to_bytes(ip)

    # Initialize encrypted result with zeros
    encrypted = :binary.copy(<<0>>, 16)

    # Determine starting point
    {prefix_start, encrypted} =
      if ipv4_mapped?(bytes16) do
        {96, <<0::80, 255, 255, 0::32>>}
      else
        {0, encrypted}
      end

    # Initialize padded_prefix for the starting prefix length
    padded_prefix =
      if ipv4_mapped?(bytes16) do
        <<0, 0, 0, 1>> <> :binary.copy(<<0>>, 10) <> <<255, 255>>
      else
        :binary.copy(<<0>>, 15) <> <<1>>
      end

    # Process each bit position
    encrypted =
      prefix_start..127
      |> Enum.reduce({encrypted, padded_prefix}, fn prefix_len_bits, {enc_acc, pad_acc} ->
        # Compute pseudorandom function with dual AES encryption
        e1 = :crypto.crypto_one_time(:aes_128_ecb, k1, pad_acc, true)
        e2 = :crypto.crypto_one_time(:aes_128_ecb, k2, pad_acc, true)

        # XOR the two encryptions
        e = :crypto.exor(e1, e2)
        # We only need the least significant bit of the last byte
        cipher_bit = :binary.at(e, 15) &&& 1

        # Extract the current bit from the original IP
        current_bit_pos = 127 - prefix_len_bits

        # Get the bit from the original IP
        original_bit = get_bit(bytes16, current_bit_pos)

        # Set the bit in the encrypted result
        enc_acc = set_bit(enc_acc, current_bit_pos, bxor(cipher_bit, original_bit))

        # Prepare padded_prefix for next iteration
        # Shift left by 1 bit and insert the next bit from bytes16
        pad_acc = shift_left_one_bit(pad_acc)
        pad_acc = set_bit(pad_acc, 0, original_bit)

        {enc_acc, pad_acc}
      end)
      |> elem(0)

    Utils.bytes_to_ip(encrypted)
  end

  defp do_decrypt(encrypted_ip, key) do
    # Split the key into two AES-128 keys
    <<k1::binary-size(16), k2::binary-size(16)>> = key

    # Convert encrypted IP to 16-byte representation
    encrypted_bytes = Utils.ip_to_bytes(encrypted_ip)

    # Initialize decrypted result
    decrypted = :binary.copy(<<0>>, 16)

    # For decryption, we need to determine if this was originally IPv4-mapped
    {prefix_start, decrypted} =
      if ipv4_mapped?(encrypted_bytes) do
        {96, <<0::80, 255, 255, 0::32>>}
      else
        {0, decrypted}
      end

    # Initialize padded_prefix for the starting prefix length
    padded_prefix =
      if prefix_start == 0 do
        :binary.copy(<<0>>, 15) <> <<1>>
      else
        <<0, 0, 0, 1>> <> :binary.copy(<<0>>, 10) <> <<255, 255>>
      end

    # Process each bit position
    decrypted =
      prefix_start..127
      |> Enum.reduce({decrypted, padded_prefix}, fn prefix_len_bits, {dec_acc, pad_acc} ->
        # Compute pseudorandom function with dual AES encryption
        e1 = :crypto.crypto_one_time(:aes_128_ecb, k1, pad_acc, true)
        e2 = :crypto.crypto_one_time(:aes_128_ecb, k2, pad_acc, true)

        # XOR the two encryptions
        e = :crypto.exor(e1, e2)
        # We only need the least significant bit of the last byte
        cipher_bit = :binary.at(e, 15) &&& 1

        # Extract the current bit from the encrypted IP
        current_bit_pos = 127 - prefix_len_bits

        # Get the bit from the encrypted IP
        encrypted_bit = get_bit(encrypted_bytes, current_bit_pos)

        # Decrypt the bit
        original_bit = bxor(cipher_bit, encrypted_bit)

        # Set the bit in the decrypted result
        dec_acc = set_bit(dec_acc, current_bit_pos, original_bit)

        # Prepare padded_prefix for next iteration
        # Shift left by 1 bit and insert the next bit from decrypted
        pad_acc = shift_left_one_bit(pad_acc)
        pad_acc = set_bit(pad_acc, 0, original_bit)

        {dec_acc, pad_acc}
      end)
      |> elem(0)

    Utils.bytes_to_ip(decrypted)
  end

  # Helper functions

  defp ipv4_mapped?(bytes16) when byte_size(bytes16) == 16 do
    <<prefix::binary-size(12), _::binary-size(4)>> = bytes16
    prefix == <<0::80, 255, 255>>
  end

  defp ipv4_mapped?(_bytes16), do: false

  defp get_bit(data, position) when byte_size(data) == 16 do
    byte_index = 15 - div(position, 8)
    bit_index = rem(position, 8)
    byte_val = :binary.at(data, byte_index)
    byte_val >>> bit_index &&& 1
  end

  defp set_bit(data, position, value) when byte_size(data) == 16 do
    byte_index = 15 - div(position, 8)
    bit_index = rem(position, 8)
    byte_val = :binary.at(data, byte_index)

    # Update the byte with the new bit value
    new_byte_val = (byte_val &&& 255 - (1 <<< bit_index)) ||| (value &&& 1) <<< bit_index

    # Replace the byte in the binary
    <<prefix::binary-size(byte_index), _::binary-size(1), suffix::binary>> = data
    prefix <> <<new_byte_val>> <> suffix
  end

  defp shift_left_one_bit(data) when byte_size(data) == 16 do
    # Shift a 16-byte array one bit to the left
    # The most significant bit is lost, and a zero bit is shifted in from the right
    carry = 0

    # Process from least significant byte (byte 15) to most significant (byte 0)
    {result, _} =
      15..0//-1
      |> Enum.reduce({<<>>, carry}, fn i, {acc, carry} ->
        byte_val = :binary.at(data, i)
        # Current byte shifted left by 1, with carry from previous byte
        new_byte = (byte_val <<< 1 ||| carry) &&& 255
        # Extract the bit that will be carried to the next byte
        new_carry = byte_val >>> 7 &&& 1
        {<<new_byte>> <> acc, new_carry}
      end)

    result
  end
end
