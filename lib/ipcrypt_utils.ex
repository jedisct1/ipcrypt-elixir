defmodule IPCrypt.Utils do
  @moduledoc """
  Utility functions for IP address conversion and manipulation.
  """

  @doc """
  Converts an IP address to its 16-byte representation.

  ## Parameters
  - ip: IP address as a string or tuple

  ## Returns
  - 16-byte binary representation
  """
  def ip_to_bytes(ip) when is_binary(ip) do
    ip
    |> String.to_charlist()
    |> :inet.parse_address()
    |> case do
      {:ok, ip_tuple} -> ip_tuple_to_bytes(ip_tuple)
      {:error, _} -> ip_tuple_to_bytes(ip)
    end
  end

  def ip_to_bytes(ip) when is_tuple(ip) do
    ip_tuple_to_bytes(ip)
  end

  defp ip_tuple_to_bytes({a, b, c, d}) do
    # IPv4 address - convert to IPv4-mapped IPv6 format
    <<0::80, 255, 255, a, b, c, d>>
  end

  defp ip_tuple_to_bytes({a, b, c, d, e, f, g, h}) do
    # IPv6 address
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  @doc """
  Converts a 16-byte representation back to an IP address.

  ## Parameters
  - bytes16: 16-byte binary representation

  ## Returns
  - IP address as a string
  """
  def bytes_to_ip(bytes16) when byte_size(bytes16) == 16 do
    case bytes16 do
      <<0::80, 255, 255, a, b, c, d>> ->
        # IPv4-mapped IPv6 format - convert back to IPv4
        "#{a}.#{b}.#{c}.#{d}"

      <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> ->
        # IPv6 address
        format_ipv6({a, b, c, d, e, f, g, h})
    end
  end

  def bytes_to_ip(_bytes16) do
    {:error, "Input must be 16 bytes"}
  end

  defp format_ipv6(ip_tuple) do
    ip_tuple
    |> Tuple.to_list()
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.join(":")
    |> String.downcase()
  end
end