defmodule IPCrypt.Test do
  use ExUnit.Case
  doctest IPCrypt

  alias IPCrypt.Deterministic
  alias IPCrypt.Kiasu
  alias IPCrypt.Nd
  alias IPCrypt.Ndx
  alias IPCrypt.Pfx

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
    },
    # ipcrypt-pfx test vectors
    %{
      variant: "ipcrypt-pfx",
      key: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
      ip: "0.0.0.0",
      encrypted_ip: "151.82.155.134"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
      ip: "255.255.255.255",
      encrypted_ip: "94.185.169.89"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
      ip: "192.0.2.1",
      encrypted_ip: "100.115.72.131"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
      ip: "2001:db8::1",
      encrypted_ip: "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "10.0.0.47",
      encrypted_ip: "19.214.210.244"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "10.0.0.129",
      encrypted_ip: "19.214.210.80"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "10.0.0.234",
      encrypted_ip: "19.214.210.30"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "172.16.5.193",
      encrypted_ip: "210.78.229.136"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "172.16.97.42",
      encrypted_ip: "210.78.179.241"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "172.16.248.177",
      encrypted_ip: "210.78.121.215"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "2001:db8::a5c9:4e2f:bb91:5a7d",
      encrypted_ip: "7cec:702c:1243:f70:1956:125:b9bd:1aba"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "2001:db8::7234:d8f1:3c6e:9a52",
      encrypted_ip: "7cec:702c:1243:f70:a3ef:c8e:95c1:cd0d"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "2001:db8::f1e0:937b:26d4:8c1a",
      encrypted_ip: "7cec:702c:1243:f70:443c:c8e:6a62:b64d"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "2001:db8:3a5c:0:e7d1:4b9f:2c8a:f673",
      encrypted_ip: "7cec:702c:3503:bef:e616:96bd:be33:a9b9"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "2001:db8:9f27:0:b4e2:7a3d:5f91:c8e6",
      encrypted_ip: "7cec:702c:a504:b74e:194a:3d90:b047:2d1a"
    },
    %{
      variant: "ipcrypt-pfx",
      key: "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a",
      ip: "2001:db8:d8b4:0:193c:a5e7:8b2f:46d1",
      encrypted_ip: "7cec:702c:f840:aa67:1b8:e84f:ac9d:77fb"
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

  describe "ipcrypt-pfx" do
    test "encrypts and decrypts IP addresses correctly" do
      pfx_vectors = Enum.filter(@test_vectors, &(&1.variant == "ipcrypt-pfx"))

      Enum.each(pfx_vectors, fn vector ->
        key = Base.decode16!(String.upcase(vector.key))
        ip = vector.ip
        expected_encrypted_ip = vector.encrypted_ip

        # Test encryption
        encrypted_ip = Pfx.encrypt(ip, key)
        assert encrypted_ip == expected_encrypted_ip

        # Test decryption
        decrypted_ip = Pfx.decrypt(encrypted_ip, key)
        assert decrypted_ip == ip
      end)
    end
  end

  describe "main IPCrypt module" do
    test "encrypts and decrypts using pfx mode" do
      # Test a single pfx vector through the main module
      vector = %{
        variant: "ipcrypt-pfx",
        key: "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
        ip: "192.0.2.1",
        encrypted_ip: "100.115.72.131"
      }

      key = Base.decode16!(String.upcase(vector.key))
      ip = vector.ip
      expected_encrypted_ip = vector.encrypted_ip

      # Test encryption through main module
      encrypted_ip = IPCrypt.encrypt(ip, key, :pfx)
      assert encrypted_ip == expected_encrypted_ip

      # Test decryption through main module
      decrypted_ip = IPCrypt.decrypt(encrypted_ip, key, :pfx)
      assert decrypted_ip == ip
    end
  end
end
