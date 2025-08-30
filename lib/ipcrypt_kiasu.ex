defmodule IPCrypt.Kiasu do
  @moduledoc """
  Implementation of KIASU-BC tweakable block cipher for ipcrypt-nd.
  """

  import Bitwise

  # AES S-box
  @sbox [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16
  ]

  # AES inverse S-box
  @inv_sbox [
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D
  ]

  # AES round constants
  @rcon [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

  # Precomputed multiplication tables for AES operations
  @mul2 for x <- 0..255,
            do:
              Bitwise.bxor(
                :binary.decode_unsigned(<<x <<< 1>>),
                if((x &&& 0x80) != 0, do: 0x1B, else: 0)
              )
  @mul3 for x <- 0..255, do: Bitwise.bxor(Enum.at(@mul2, x), x)

  @doc """
  Encrypts using KIASU-BC construction.

  ## Parameters
  - key: 16-byte encryption key
  - tweak: 8-byte tweak
  - plaintext: 16-byte plaintext

  ## Returns
  - 16-byte ciphertext
  """
  def encrypt(key, tweak, plaintext)
      when byte_size(key) == 16 and byte_size(tweak) == 8 and byte_size(plaintext) == 16 do
    round_keys = expand_key(key)
    padded_tweak = pad_tweak(tweak)

    # Initial round
    state =
      plaintext
      |> xor_bytes(Enum.at(round_keys, 0))
      |> xor_bytes(padded_tweak)

    # Main rounds
    state =
      1..9
      |> Enum.reduce(state, fn round, acc ->
        acc
        |> sub_bytes()
        |> shift_rows()
        |> mix_columns()
        |> xor_bytes(Enum.at(round_keys, round))
        |> xor_bytes(padded_tweak)
      end)

    # Final round
    state
    |> sub_bytes()
    |> shift_rows()
    |> xor_bytes(Enum.at(round_keys, 10))
    |> xor_bytes(padded_tweak)
  end

  def encrypt(_key, _tweak, _plaintext) do
    {:error,
     "Invalid parameters: key must be 16 bytes, tweak must be 8 bytes, plaintext must be 16 bytes"}
  end

  @doc """
  Decrypts using KIASU-BC construction.

  ## Parameters
  - key: 16-byte encryption key
  - tweak: 8-byte tweak
  - ciphertext: 16-byte ciphertext

  ## Returns
  - 16-byte plaintext
  """
  def decrypt(key, tweak, ciphertext)
      when byte_size(key) == 16 and byte_size(tweak) == 8 and byte_size(ciphertext) == 16 do
    round_keys = expand_key(key)
    padded_tweak = pad_tweak(tweak)

    # Initial round (inverse final round)
    state =
      ciphertext
      |> xor_bytes(Enum.at(round_keys, 10))
      |> xor_bytes(padded_tweak)
      |> inv_shift_rows()
      |> inv_sub_bytes()

    # Main rounds (inverse)
    state =
      9..1//-1
      |> Enum.reduce(state, fn round, acc ->
        acc
        |> xor_bytes(Enum.at(round_keys, round))
        |> xor_bytes(padded_tweak)
        |> inv_mix_columns()
        |> inv_shift_rows()
        |> inv_sub_bytes()
      end)

    # Final round (inverse initial round)
    state
    |> xor_bytes(Enum.at(round_keys, 0))
    |> xor_bytes(padded_tweak)
  end

  def decrypt(_key, _tweak, _ciphertext) do
    {:error,
     "Invalid parameters: key must be 16 bytes, tweak must be 8 bytes, ciphertext must be 16 bytes"}
  end

  # Helper functions

  defp sub_bytes(state) do
    state
    |> :binary.bin_to_list()
    |> Enum.map(&Enum.at(@sbox, &1))
    |> :binary.list_to_bin()
  end

  defp inv_sub_bytes(state) do
    state
    |> :binary.bin_to_list()
    |> Enum.map(&Enum.at(@inv_sbox, &1))
    |> :binary.list_to_bin()
  end

  defp xor_bytes(a, b) do
    a
    |> :binary.bin_to_list()
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.map(fn {x, y} -> Bitwise.bxor(x, y) end)
    |> :binary.list_to_bin()
  end

  defp rot_word(word) do
    <<a, b, c, d>> = word
    <<b, c, d, a>>
  end

  defp expand_key(key) when byte_size(key) == 16 do
    round_keys = [key]

    0..9
    |> Enum.reduce(round_keys, fn i, acc ->
      prev_key = List.last(acc)
      <<_::binary-size(12), temp::binary-size(4)>> = prev_key
      temp = rot_word(temp) |> sub_bytes()
      <<first_byte, rest::binary-size(3)>> = temp
      temp = <<Bitwise.bxor(first_byte, Enum.at(@rcon, i)), rest::binary>>

      new_key = generate_new_key(prev_key, temp)

      acc ++ [new_key]
    end)
  end

  defp generate_new_key(prev_key, temp) do
    0..3
    |> Enum.reduce(<<>>, fn j, key_acc ->
      word = :binary.part(prev_key, {j * 4, 4})
      word = if j == 0, do: xor_bytes(word, temp), else: xor_with_prev_word(key_acc, word, j)
      key_acc <> word
    end)
  end

  defp xor_with_prev_word(key_acc, word, j) do
    <<prev_word::binary-size(4)>> = :binary.part(key_acc, {(j - 1) * 4, 4})
    xor_bytes(word, prev_word)
  end

  defp pad_tweak(tweak) when byte_size(tweak) == 8 do
    <<t0, t1, t2, t3, t4, t5, t6, t7>> = tweak

    <<t0, t1, 0, 0, t2, t3, 0, 0, t4, t5, 0, 0, t6, t7, 0, 0>>
  end

  defp shift_rows(state) do
    <<s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15>> = state

    <<s0, s5, s10, s15, s4, s9, s14, s3, s8, s13, s2, s7, s12, s1, s6, s11>>
  end

  defp inv_shift_rows(state) do
    <<s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15>> = state

    <<s0, s13, s10, s7, s4, s1, s14, s11, s8, s5, s2, s15, s12, s9, s6, s3>>
  end

  defp mix_columns(state) do
    state
    |> :binary.bin_to_list()
    |> Enum.chunk_every(4)
    |> Enum.map(fn [s0, s1, s2, s3] ->
      [
        Bitwise.bxor(
          Bitwise.bxor(Bitwise.bxor(Enum.at(@mul2, s0), Enum.at(@mul3, s1)), s2),
          s3
        ),
        Bitwise.bxor(
          Bitwise.bxor(Bitwise.bxor(s0, Enum.at(@mul2, s1)), Enum.at(@mul3, s2)),
          s3
        ),
        Bitwise.bxor(
          Bitwise.bxor(Bitwise.bxor(s0, s1), Enum.at(@mul2, s2)),
          Enum.at(@mul3, s3)
        ),
        Bitwise.bxor(
          Bitwise.bxor(Bitwise.bxor(Enum.at(@mul3, s0), s1), s2),
          Enum.at(@mul2, s3)
        )
      ]
    end)
    |> List.flatten()
    |> :binary.list_to_bin()
  end

  defp inv_mix_columns(state) do
    mul = &multiply_gf/2

    state
    |> :binary.bin_to_list()
    |> Enum.chunk_every(4)
    |> Enum.map(fn col ->
      [
        calculate_first_result(mul, col),
        calculate_second_result(mul, col),
        calculate_third_result(mul, col),
        calculate_fourth_result(mul, col)
      ]
    end)
    |> List.flatten()
    |> :binary.list_to_bin()
  end

  defp multiply_gf(a, b) do
    p = 0

    {result, _} =
      0..7
      |> Enum.reduce({p, {a, b}}, fn _, {p_acc, {a_acc, b_acc}} ->
        p_acc = if (b_acc &&& 1) != 0, do: Bitwise.bxor(p_acc, a_acc), else: p_acc
        hi_bit_set = (a_acc &&& 0x80) != 0
        a_acc = a_acc <<< 1
        a_acc = if hi_bit_set, do: Bitwise.bxor(a_acc, 0x1B), else: a_acc
        b_acc = b_acc >>> 1
        {p_acc, {a_acc &&& 0xFF, b_acc}}
      end)

    result &&& 0xFF
  end

  defp calculate_first_result(mul, col) do
    Bitwise.bxor(
      Bitwise.bxor(
        Bitwise.bxor(mul.(0x0E, Enum.at(col, 0)), mul.(0x0B, Enum.at(col, 1))),
        mul.(0x0D, Enum.at(col, 2))
      ),
      mul.(0x09, Enum.at(col, 3))
    )
  end

  defp calculate_second_result(mul, col) do
    Bitwise.bxor(
      Bitwise.bxor(
        Bitwise.bxor(mul.(0x09, Enum.at(col, 0)), mul.(0x0E, Enum.at(col, 1))),
        mul.(0x0B, Enum.at(col, 2))
      ),
      mul.(0x0D, Enum.at(col, 3))
    )
  end

  defp calculate_third_result(mul, col) do
    Bitwise.bxor(
      Bitwise.bxor(
        Bitwise.bxor(mul.(0x0D, Enum.at(col, 0)), mul.(0x09, Enum.at(col, 1))),
        mul.(0x0E, Enum.at(col, 2))
      ),
      mul.(0x0B, Enum.at(col, 3))
    )
  end

  defp calculate_fourth_result(mul, col) do
    Bitwise.bxor(
      Bitwise.bxor(
        Bitwise.bxor(mul.(0x0B, Enum.at(col, 0)), mul.(0x0D, Enum.at(col, 1))),
        mul.(0x09, Enum.at(col, 2))
      ),
      mul.(0x0E, Enum.at(col, 3))
    )
  end
end
