# Modbus TCP quick reference

## Basics
- TCP port 502; encapsulates Modbus PDU inside MBAP header (no CRC).
- MBAP: Transaction ID (2), Protocol ID (2, always 0), Length (2), Unit ID (1).

## Example (read holding registers)
- Request (hex bytes): `00 01 00 00 00 06 11 03 00 6B 00 03`
  - TID 0x0001, Unit ID 0x11, function 0x03, start 0x006B, qty 0x0003
- Response: `00 01 00 00 00 09 11 03 06 00 0A 01 02 00 00`

## Notes
- No timing gaps needed; relies on TCP stream.
- Use Unit ID to reach serial bridges; often matches RTU slave address.
- Mind endianness of registers per device documentation.
