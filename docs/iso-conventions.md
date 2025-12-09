# ISO conventions for UK maritime/subsea documentation

Use these conventions for all documents stored in this repository.

## Date and time
- ISO 8601 format: dates as `YYYY-MM-DD`; times 24-hour with timezone.
- Default to UTC (`Z`). When local time is required, use offsets (`YYYY-MM-DDThh:mm:ss+hh:mm` or `YYYY-MM-DDThh:mm:ss-hh:mm`).

## Measurements and units
- SI units per ISO/IEC 80000; insert a space between value and unit (`10 m`, `2.5 kg`).
- Decimal separator is a dot; use thin/space grouping for thousands (`12 500`).

## Coordinates and positions
- Use WGS84 latitude/longitude in ISO 6709 decimal degrees: `+DD.DDDDD+DDD.DDDDD` (e.g., `+51.50750-000.12770`).
- If UTM is used, include zone, hemisphere, and datum (WGS84).

## Document identification and control
- Include document ID, title, author, version, and date on the cover/header.
- Maintain a revision history with reason for change (aligned with ISO 9001:2015 document control expectations).

## Safety colors, signs, and markings (UK maritime/subsea)
- Use ISO 24409 (shipboard safety signs) and ISO 3864/ISO 7010 color rules and pictograms.
- Red: prohibition symbols and fire-fighting equipment background; red/white striping to mark fire equipment zones.
- Yellow/amber: warning symbols; black/yellow striping at 45 degrees to mark physical hazards.
- Blue: mandatory action symbols (e.g., PPE required).
- Green: safe condition symbols (exits, muster, first aid).
- Keep pictograms to ISO 7010/IMO identifiers; pair icons with brief text describing hazard/action.

## Language and terminology
- Use UK English; expand abbreviations on first use.

## Currency
- If currency is mentioned, use ISO 4217 codes (e.g., `GBP`, `USD`).

## References
- ISO 8601 - Date and time format.
- ISO/IEC 80000 - Quantities and units (SI).
- ISO 6709 - Representation of geographic point location.
- ISO 24409 - Shipboard safety signs.
- ISO 3864 and ISO 7010 - Safety colors, shapes, and graphical symbols.
- ISO 4217 - Currency codes.
- ISO 9001:2015 - Documented information control expectations.
