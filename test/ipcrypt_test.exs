defmodule IPCrypt.Test do
  use ExUnit.Case
  doctest IPCrypt

  alias IPCrypt.Deterministic
  alias IPCrypt.Kiasu
  alias IPCrypt.Nd
  alias IPCrypt.Ndx

  @test_vectors [
    # ipcrypt-deterministic test vectors
    %{
      variant: "ipcrypt-deterministic",
      key: "0123456789abcdeffedcba9876543210",
      ip: "0.0.0.0",
      encrypted_ip: "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb"
    },
    %{
      variant: "ipcrypt-deterministic",
      key: "1032547698badcfeefcdab8967452301",
      ip: "255.255.255.255",
      encrypted_ip: "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8"
    },
    %{
      variant: "ipcrypt-deterministic",
      key: "2b7e151628aed2a6abf7158809cf4f3c",
      ip: "192.0.2.1",
      encrypted_ip: "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777"
    },
    # ipcrypt-nd test vectors
    %{
      variant: "ipcrypt-nd",
      key: "0123456789abcdeffedcba9876543210",
      ip: "0.0.0.0",
      tweak: "08e0c289bff23b7c",
      output: "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16"
    },
    %{
      variant: "ipcrypt-nd",
      key: "1032547698badcfeefcdab8967452301",
      ip: "255.255.255.255",
      tweak: "08e0c289bff23b7c",
      output: "08e0c289bff23b7cf602ae8dcfeb47c1fbcb9597b8951b89"
    },
    %{
      variant: "ipcrypt-nd",
      key: "2b7e151628aed2a6abf7158809cf4f3c",
      ip: "192.0.2.1",
      tweak: "08e0c289bff23b7c",
      output: "08e0c289bff23b7cca25fe3b7f2ca5e50a0deb24ef0469f8"
    },
    # ipcrypt-ndx test vectors
    %{
      variant: "ipcrypt-ndx",
      key: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
      ip: "0.0.0.0",
      tweak: "21bd1834bc088cd2b4ecbe30b70898d7",
      output: "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5"
    },
    %{
      variant: "ipcrypt-ndx",
      key: "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210",
      ip: "255.255.255.255",
      tweak: "21bd1834bc088cd2b4ecbe30b70898d7",
      output: "21bd1834bc088cd2b4ecbe30b70898d776c7dbd1ae4802a2dd95ad4f88273535"
    },
    %{
      variant: "ipcrypt-ndx",
      key: "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b",
      ip: "192.0.2.1",
      tweak: "21bd1834bc088cd2b4ecbe30b70898d7",
      output: "21bd1834bc088cd2b4ecbe30b70898d7259e85ebaa000667d2437ac7e2208d71"
    }
  ]

  describe "ipcrypt-deterministic" do
    test "encrypts and decrypts IP addresses correctly" do
      deterministic_vectors = Enum.filter(@test_vectors, &(&1.variant == "ipcrypt-deterministic"))

      Enum.each(deterministic_vectors, fn vector ->
        key = Base.decode16!(String.upcase(vector.key))
        ip = vector.ip
        expected_encrypted_ip = vector.encrypted_ip

        # Test encryption
        encrypted_ip = Deterministic.encrypt(ip, key)
        assert encrypted_ip == expected_encrypted_ip

        # Test decryption
        decrypted_ip = Deterministic.decrypt(encrypted_ip, key)
        assert decrypted_ip == ip
      end)
    end
  end

  describe "ipcrypt-nd" do
    test "encrypts and decrypts IP addresses correctly" do
      nd_vectors = Enum.filter(@test_vectors, &(&1.variant == "ipcrypt-nd"))

      Enum.each(nd_vectors, fn vector ->
        key = Base.decode16!(String.upcase(vector.key))
        ip = vector.ip
        tweak = Base.decode16!(String.upcase(vector.tweak))
        expected_output = vector.output

        # Test encryption with specific tweak
        ip_bytes = IPCrypt.Utils.ip_to_bytes(ip)
        ciphertext = Kiasu.encrypt(key, tweak, ip_bytes)
        result = Base.encode16(tweak <> ciphertext) |> String.downcase()
        assert result == expected_output

        # Test full encryption/decryption
        encrypted_data = Nd.encrypt(ip, key, tweak)
        decrypted_ip = Nd.decrypt(encrypted_data, key)
        assert decrypted_ip == ip
      end)
    end
  end

  describe "ipcrypt-ndx" do
    test "encrypts and decrypts IP addresses correctly" do
      ndx_vectors = Enum.filter(@test_vectors, &(&1.variant == "ipcrypt-ndx"))

      Enum.each(ndx_vectors, fn vector ->
        key = Base.decode16!(String.upcase(vector.key))
        ip = vector.ip
        tweak = Base.decode16!(String.upcase(vector.tweak))
        expected_output = vector.output

        # Test encryption with specific tweak
        ip_bytes = IPCrypt.Utils.ip_to_bytes(ip)
        ciphertext = IPCrypt.Ndx.aes_xts_encrypt(key, tweak, ip_bytes)
        result = Base.encode16(tweak <> ciphertext) |> String.downcase()
        assert result == expected_output

        # Test full encryption/decryption
        # For this test, we need to use a fixed tweak to match the expected output
        # In practice, a random tweak would be generated
        <<actual_tweak::binary-size(16), _::binary>> =
          Base.decode16!(String.upcase(expected_output))

        encrypted_data = actual_tweak <> ciphertext
        decrypted_ip = Ndx.decrypt(encrypted_data, key)
        assert decrypted_ip == ip
      end)
    end
  end
end
