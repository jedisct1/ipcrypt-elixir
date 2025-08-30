defmodule IPCrypt.TestHelper do
  @moduledoc """
  Test helper functions for IPCrypt.
  """

  def hex_to_binary(hex_string) do
    Base.decode16!(String.upcase(hex_string))
  end

  def binary_to_hex(binary) do
    Base.encode16(binary) |> String.downcase()
  end
end