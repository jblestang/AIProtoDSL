// ASTERIX family (CAT 001, 002, 034, 048, 240) - protocol model
// Data block: category (1 byte) + length (2 bytes, length of record data)
// Record: FSPEC (variable-length, FX bit) + optional data items per UAP
// Order: messages first (grammar), then structs.

transport {
  category: u8 [0..255];   // content not verifiable (full range)
  length: u16 [0..65535];   // content not verifiable (full range)
}

// Which messages can follow the transport and how to select message type from category.
// repeated: payload is a list of records (zero or more of the selected type per data block).
payload {
  messages: Cat001Record, Cat002Record, Cat034Record, Cat048Record, Cat240Record;
  selector: category -> 1: Cat001Record, 2: Cat002Record, 34: Cat034Record, 48: Cat048Record, 240: Cat240Record;
  repeated;
}

// ============== CAT 001 - Monoradar Target Reports (legacy) ==============
// UAP: 010, 020, 040, 070, 090, 130, 141, (FX) 050, 120, 131, 080, 100, 060, 030, (FX) 150, ...
message Cat001Record {
  fspec: fspec -> (0: i001_010, 1: i001_020, 2: i001_040, 3: i001_042, 4: i001_030, 5: i001_050, 6: i001_070, 7: i001_080, 8: i001_090, 9: i001_100, 10: i001_120, 11: i001_130, 12: i001_131, 13: i001_141, 14: i001_161, 15: i001_170, 16: i001_200, 17: i001_210);
  i001_010: optional<DataSourceId>;
  i001_020: optional<TargetReportDescriptor001>;
  i001_040: optional<MeasuredPositionPolar>;
  i001_042: optional<CalculatedPositionCartesian>;
  i001_030: optional<list<u8>>;
  i001_050: optional<Mode2Code>;
  i001_070: optional<Mode3ACode>;
  i001_080: optional<Mode3AConfidence>;
  i001_090: optional<FlightLevel>;
  i001_100: optional<ModeCCodeConfidence>;
  i001_120: optional<i8> [0..127];
  i001_130: optional<list<u8>>;
  i001_131: optional<i8> [-128..127];   // content not verifiable (full range)
  i001_141: optional<u16> [0..65535];  // content not verifiable (full range)
  i001_161: optional<u16> [0..4095];
  i001_170: optional<TrackStatus001>;
  i001_200: optional<TrackVelocityPolar>;
  i001_210: optional<list<u8>>;
}

// ============== CAT 002 (placeholder) ==============
message Cat002Record {
  fspec: fspec -> (0: i002_010);
  i002_010: optional<DataSourceId>;
}

// ============== CAT 034 - Monoradar Service Messages ==============
// UAP: 010, 000, 030, 020, 041, 050, 060, (FX) 070, 100, 110, 120, 090, ...
message Cat034Record {
  fspec: fspec -> (0: i034_010, 1: i034_000, 2: i034_020, 3: i034_030, 4: i034_041, 5: i034_050, 6: i034_060, 7: i034_070, 8: i034_090, 9: i034_100, 10: i034_110, 11: i034_120);
  i034_010: optional<DataSourceId>;
  i034_000: optional<u8> [0..255];      // content not verifiable (full range)
  i034_020: optional<u8> [0..255];     // content not verifiable (full range)
  i034_030: optional<TimeOfDay24>;
  i034_041: optional<u16> [0..65535];  // content not verifiable (full range)
  i034_050: optional<SystemConfig034>;
  i034_060: optional<SystemProcessingMode034>;
  i034_070: optional<list<MessageCountEntry>>;
  i034_090: optional<CollimationError>;
  i034_100: optional<PolarWindow>;
  i034_110: optional<u8> [0..255];     // content not verifiable (full range)
  i034_120: optional<Position3D>;
}

// ============== CAT 048 - Monoradar Target Reports (current) ==============
// UAP: 010, 020, 030, 040, 042, 050, 055, 060, 065, 070, 080, 090, 100, 110, 120, 130, 140, 161, 170, 200, 210, ...
message Cat048Record {
  fspec: fspec -> (0: i048_010, 1: i048_020, 2: i048_030, 3: i048_040, 4: i048_042, 5: i048_050, 6: i048_055, 7: i048_060, 8: i048_065, 9: i048_070, 10: i048_080, 11: i048_090, 12: i048_100, 13: i048_110, 14: i048_120, 15: i048_130, 16: i048_140, 17: i048_161, 18: i048_170, 19: i048_200, 20: i048_210);
  i048_010: optional<DataSourceId>;
  i048_020: optional<TargetReportDescriptor048>;
  i048_030: optional<list<u8>>;
  i048_040: optional<MeasuredPositionPolar>;
  i048_042: optional<CalculatedPositionCartesian>;
  i048_050: optional<Mode2Code>;
  i048_055: optional<Mode1Code>;
  i048_060: optional<Mode2Confidence>;
  i048_065: optional<Mode1Confidence>;
  i048_070: optional<Mode3ACode>;
  i048_080: optional<Mode3AConfidence>;
  i048_090: optional<FlightLevel>;
  i048_100: optional<ModeCCodeConfidence>;
  i048_110: optional<i16> [-32768..32767];  // content not verifiable (full range)
  i048_120: optional<DopplerSpeed>;
  i048_130: optional<RadarPlotCharacteristics>;
  i048_140: optional<TimeOfDay24>;
  i048_161: optional<TrackNumber>;
  i048_170: optional<TrackStatus048>;
  i048_200: optional<TrackVelocityPolar>;
  i048_210: optional<TrackQuality>;
}

// ============== CAT 240 - Radar Video Transmission ==============
message Cat240Record {
  fspec: fspec -> (0: i240_010);
  i240_010: optional<DataSourceId>;
}

// ============== Structs - Data items ==============

struct DataSourceId {
  sac: u8 [0..255];   // content not verifiable (full range)
  sic: u8 [0..255];   // content not verifiable (full range)
}

struct TargetReportDescriptor001 {
  typ: bitfield(1) [0..1];   // content not verifiable (full range)
  sim: bitfield(1) [0..1];   // content not verifiable (full range)
  ssrpsr: bitfield(2) [0..3];  // content not verifiable (full range)
  ant: bitfield(1) [0..1];   // content not verifiable (full range)
  spi: bitfield(1) [0..1];   // content not verifiable (full range)
  rab: bitfield(1) [0..1];   // content not verifiable (full range)
  spare: padding_bits(1);
}

struct TargetReportDescriptor048 {
  typ: bitfield(3) [0..7];   // content not verifiable (full range)
  sim: bitfield(1) [0..1];   // content not verifiable (full range)
  rdp: bitfield(1) [0..1];   // content not verifiable (full range)
  spi: bitfield(1) [0..1];   // content not verifiable (full range)
  rab: bitfield(1) [0..1];   // content not verifiable (full range)
  spare_fx: padding_bits(1);
}

struct TargetReportDescriptor048Ext {
  tst: bitfield(1) [0..1];   // content not verifiable (full range)
  err: bitfield(1) [0..1];   // content not verifiable (full range)
  xpp: bitfield(1) [0..1];   // content not verifiable (full range)
  me: bitfield(1) [0..1];   // content not verifiable (full range)
  mi: bitfield(1) [0..1];   // content not verifiable (full range)
  foefri: bitfield(2) [0..3];  // content not verifiable (full range)
  spare_fx2: padding_bits(1);
}

struct MeasuredPositionPolar {
  rho: u16 [0..65535];    // content not verifiable (full range)
  theta: u16 [0..65535];  // content not verifiable (full range)
}

struct CalculatedPositionCartesian {
  x: i16 [-32768..32767];  // content not verifiable (full range)
  y: i16 [-32768..32767];  // content not verifiable (full range)
}

struct Mode2Code {
  v: bitfield(1) [0..1];   // content not verifiable (full range)
  g: bitfield(1) [0..1];   // content not verifiable (full range)
  l: bitfield(1) [0..1];   // content not verifiable (full range)
  spare: padding_bits(1);
  mode2: u16(12) [0..4095];
}

struct Mode1Code {
  v: bitfield(1) [0..1];   // content not verifiable (full range)
  g: bitfield(1) [0..1];   // content not verifiable (full range)
  l: bitfield(1) [0..1];   // content not verifiable (full range)
  mode1: u8(5) [0..31];
}

struct Mode3ACode {
  v: bitfield(1) [0..1];   // content not verifiable (full range)
  g: bitfield(1) [0..1];   // content not verifiable (full range)
  l: bitfield(1) [0..1];   // content not verifiable (full range)
  spare: padding_bits(1);
  mode3a: u16(12) [0..4095];
}

struct Mode2Confidence {
  spare: padding_bits(4);
  qa4: bitfield(1) [0..1]; qa2: bitfield(1) [0..1]; qa1: bitfield(1) [0..1];
  qb4: bitfield(1) [0..1]; qb2: bitfield(1) [0..1]; qb1: bitfield(1) [0..1];
  qc4: bitfield(1) [0..1]; qc2: bitfield(1) [0..1]; qc1: bitfield(1) [0..1];
  qd4: bitfield(1) [0..1]; qd2: bitfield(1) [0..1]; qd1: bitfield(1) [0..1];
  // above bitfield(1) [0..1]: content not verifiable (full range)
}

struct Mode1Confidence {
  spare: padding_bits(3);
  qa4: bitfield(1) [0..1]; qa2: bitfield(1) [0..1]; qa1: bitfield(1) [0..1];
  qb2: bitfield(1) [0..1]; qb1: bitfield(1) [0..1];
  // above bitfield(1) [0..1]: content not verifiable (full range)
}

struct Mode3AConfidence {
  spare: padding_bits(4);
  qa4: bitfield(1) [0..1]; qa2: bitfield(1) [0..1]; qa1: bitfield(1) [0..1];
  qb4: bitfield(1) [0..1]; qb2: bitfield(1) [0..1]; qb1: bitfield(1) [0..1];
  qc4: bitfield(1) [0..1]; qc2: bitfield(1) [0..1]; qc1: bitfield(1) [0..1];
  qd4: bitfield(1) [0..1]; qd2: bitfield(1) [0..1]; qd1: bitfield(1) [0..1];
  // above bitfield(1) [0..1]: content not verifiable (full range)
}

struct FlightLevel {
  v: bitfield(1) [0..1];   // content not verifiable (full range)
  g: bitfield(1) [0..1];   // content not verifiable (full range)
  fl: u16(14) [0..16383];
}

struct ModeCCodeConfidence {
  v: bitfield(1) [0..1]; g: bitfield(1) [0..1];
  spare: padding_bits(2);
  modec: u16(12) [0..4095];
  spare2: padding_bits(4);
  qc1: bitfield(1) [0..1]; qa1: bitfield(1) [0..1]; qc2: bitfield(1) [0..1]; qa2: bitfield(1) [0..1];
  qc4: bitfield(1) [0..1]; qa4: bitfield(1) [0..1]; qb1: bitfield(1) [0..1]; qd1: bitfield(1) [0..1];
  qb2: bitfield(1) [0..1]; qd2: bitfield(1) [0..1]; qb4: bitfield(1) [0..1]; qd4: bitfield(1) [0..1];
  // above bitfield(1) [0..1]: content not verifiable (full range)
}

struct TimeOfDay24 {
  tod: u32(24) [0..16777215];
}

struct TrackNumber {
  spare: padding_bits(4);
  trn: u16(12) [0..4095];
}

struct TrackStatus001 {
  con: bitfield(1) [0..1]; rad: bitfield(1) [0..1]; man: bitfield(1) [0..1];
  dou: bitfield(1) [0..1]; rdpc: bitfield(1) [0..1];
  spare: padding_bits(1);
  gho: bitfield(1) [0..1];
  // above bitfield(1) [0..1]: content not verifiable (full range)
}

struct TrackStatus048 {
  cnf: bitfield(1) [0..1];   // content not verifiable (full range)
  rad: bitfield(2) [0..3];  // content not verifiable (full range)
  dou: bitfield(1) [0..1]; mah: bitfield(1) [0..1];  // content not verifiable (full range)
  cdm: bitfield(2) [0..3];  // content not verifiable (full range)
  spare_fx: padding_bits(1);
}

struct TrackStatus048Ext {
  tre: bitfield(1) [0..1]; gho: bitfield(1) [0..1]; sup: bitfield(1) [0..1]; tcc: bitfield(1) [0..1];
  spare: padding_bits(3);
  // above bitfield(1) [0..1]: content not verifiable (full range)
}

struct TrackVelocityPolar {
  gsp: u16 [0..65535];   // content not verifiable (full range)
  hdg: u16 [0..65535];   // content not verifiable (full range)
}

struct TrackQuality {
  sigx: u8 [0..255];   // content not verifiable (full range)
  sigy: u8 [0..255];   // content not verifiable (full range)
}

struct DopplerSpeed {
  d: bitfield(1) [0..1];   // content not verifiable (full range)
  spare: padding_bits(5);
  cal: i16(10) [-512..511];
}

struct RadarPlotCharacteristics {
  srl: u8 [0..255]; srr: u8 [0..255];   // content not verifiable (full range)
  sam: i8 [-128..127];   // content not verifiable (full range)
  prl: u8 [0..255];   // content not verifiable (full range)
  pam: i8 [-128..127]; rpd: i8 [-128..127]; apd: i8 [-128..127];   // content not verifiable (full range)
}

struct SystemConfig034 {
  nogo: bitfield(1) [0..1]; rdpc: bitfield(1) [0..1]; rdpr: bitfield(1) [0..1];
  ovlrdp: bitfield(1) [0..1]; ovlxmt: bitfield(1) [0..1]; msc: bitfield(1) [0..1]; tsv: bitfield(1) [0..1];
  spare: padding_bits(1);
  // above bitfield(1) [0..1]: content not verifiable (full range)
}

struct SystemProcessingMode034 {
  spare: padding_bits(1);
  redrdp: u8(3) [0..7];
  redxmt: u8(3) [0..7];
  spare2: padding_bits(1);
}

struct MessageCountEntry {
  typ: u8(5) [0..31];
  count: u16(11) [0..2047];
}

struct CollimationError {
  rng: i8 [-128..127];   // content not verifiable (full range)
  azm: i8 [-128..127];   // content not verifiable (full range)
}

struct PolarWindow {
  rhost: u16 [0..65535]; rhoend: u16 [0..65535];   // content not verifiable (full range)
  thetast: u16 [0..65535]; thetaend: u16 [0..65535];   // content not verifiable (full range)
}

struct Position3D {
  hgt: i16 [-32768..32767];   // content not verifiable (full range)
  lat: i32(24) [-8388608..8388607];
  lon: i32(24) [-8388608..8388607];
}
