# EUROCONTROL ASTERIX specification references

This document lists the official EUROCONTROL specification publications used as reference for **messages**, **structs**, **fields**, and **enumerations** in `examples/asterix_family.dsl`. PDFs can be downloaded from each publication page.

## Reference links (publication pages)

| Category | Description | Publication (PDF download) |
|----------|-------------|----------------------------|
| **CAT 001** | Monoradar Target Reports (standalone radar) | [CAT001 – ASTERIX Part 2a Category 001](https://eurocontrol.int/publication/cat001-eurocontrol-standard-document-radar-data-exchange-part-2a) |
| **CAT 002** | Monoradar Service Messages (North/Sector markers, etc.) | [CAT002 – Radar Data Exchange Part 2b](https://eurocontrol.int/publication/cat002-eurocontrol-standard-document-radar-data-exchange-part-2b) |
| **CAT 034** | Monoradar Service Messages (SSR, Mode S, primary radar) | [CAT034 – Surveillance Data Exchange Part 2b](https://eurocontrol.int/publication/cat034-eurocontrol-specification-surveillance-data-exchange-part-2b) |
| **CAT 048** | Monoradar Target Reports (PSR, SSR, MSSR, Mode S) | [CAT048 – ASTERIX Part 4 Category 48](https://eurocontrol.int/publication/cat048-eurocontrol-specification-surveillance-data-exchange-asterix-part-4-category-48) |
| **CAT 240** | Radar Video Transmission | [CAT240 – Surveillance Data Exchange ASTERIX](https://eurocontrol.int/publication/cat240-eurocontrol-specification-surveillance-data-exchange-asterix) |

## Direct PDF links (example editions)

PDFs are versioned; the publication pages above list current and past editions. Example direct PDF links:

- **CAT048** (Monoradar Target Reports, Part 4):  
  [eurocontrol-cat048-pt4-ed131.pdf](https://www.eurocontrol.int/sites/default/files/2022-12/eurocontrol-cat048-pt4-ed131.pdf)

## Mapping in this project

- **Messages** in the DSL (e.g. `Cat001Record`, `Cat048Record`) correspond to ASTERIX data blocks / record types for that category.
- **Structs** correspond to data items (e.g. I048/010 Data Source Identifier, I048/040 Measured Position in Polar Co-ordinates); field names and types follow the spec.
- **Fields** map to subfields or elements (e.g. SAC, SIC, RHO, THETA) with constraints and quantums as defined in the specification.
- **Enumerations** map to defined value sets in the spec (e.g. message type codes, TYP/SIM/RDP bit meanings).

For data item and field-level references, see the relevant category PDF (e.g. CAT048 Part 4 for I048/xxx items).
