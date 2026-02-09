// ASTERIX family (CAT 001, 002, 034, 048, 240) - protocol model
// Data block: category (1 byte) + length (2 bytes, length of record data)
// Record: FSPEC (variable-length, FX bit) + optional data items per UAP

transport {
  category: u8;
  length: u16;
}

// --- CAT 001 - Monoradar Target Reports (legacy) ---
message Cat001Record {
  fspec: fspec;
  i001_010: optional<DataSourceId>;
  i001_020: optional<TargetReportDescriptor>;
  i001_040: optional<MeasuredPositionPolar>;
}

// --- CAT 002 (placeholder) ---
message Cat002Record {
  fspec: fspec;
  i002_010: optional<DataSourceId>;
}

// --- CAT 034 - Monoradar Service Messages ---
message Cat034Record {
  fspec: fspec;
  i034_010: optional<DataSourceId>;
}

// --- CAT 048 - Monoradar Target Reports (current) ---
message Cat048Record {
  fspec: fspec;
  i048_010: optional<DataSourceId>;
  i048_020: optional<TargetReportDescriptor>;
  i048_040: optional<MeasuredPositionPolar>;
  i048_042: optional<CalculatedPositionCartesian>;
}

// --- CAT 240 - Radar Video Transmission ---
message Cat240Record {
  fspec: fspec;
  i240_010: optional<DataSourceId>;
}

// --- Common data item structs (used across categories) ---
// Ixxx/010 - Data Source Identifier (SAC + SIC)
struct DataSourceId {
  sac: u8;
  sic: u8;
}

// I048/020 - Target Report Descriptor (simplified)
struct TargetReportDescriptor {
  typ: bitfield(3);
  sim: bitfield(1);
  rdp: bitfield(1);
  spi: bitfield(1);
  rab: bitfield(1);
  spare: padding_bits(1);
}

// I048/040 - Measured Position Polar (RHO 16b, THETA 16b)
struct MeasuredPositionPolar {
  rho: u16;
  theta: u16;
}

// I048/042 - Calculated Position Cartesian (X 16b, Y 16b)
struct CalculatedPositionCartesian {
  x: i16;
  y: i16;
}
