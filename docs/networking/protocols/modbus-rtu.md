# Modbus RTU quick reference

## Basics
- Serial: typically RS-485 (2-wire) or RS-232, 9600/19200/38400 8N1 or 8E1.
- Framing: silent interval >= 3.5 char times between frames; CRC-16 (Modbus polynomial) at end (lo byte first, then hi byte).

## Example (read holding registers)
- Request (hex bytes): `01 03 00 6B 00 03 76 87`
  - Slave 0x01, function 0x03, start 0x006B, qty 0x0003, CRC 0x8776 (sent low-high as 0x76 0x87)
- Response (hex bytes): `01 03 06 00 0A 01 02 00 00 C5 CD`
  - 3 registers: 0x000A, 0x0102, 0x0000

## Write example (single register)
- Request: `01 06 00 6B 00 03 09 76`
- Response echoes request (if success).

## Checklist
- Match baud/parity/stop bits both ends.
- Use correct bias/termination on RS-485.
- Observe 3.5 char silence between frames; avoid inter-char gaps >1.5 char.
- CRC order: low byte then high byte.
