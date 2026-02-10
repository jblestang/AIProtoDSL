// ASTERIX family (CAT 001, 002, 034, 048, 240) - protocol model
// Data block: category (1 byte) + length (2 bytes, length of record data)
// Record: FSPEC (variable-length, FX bit) + optional data items per UAP
// Order: messages first (grammar), then structs.

transport {
  category: u8 [0..255];   // content not verifiable (full range)
  length: u16 [0..65535];   // content not verifiable (full range)
}

// Which messages can follow the transport and how to select message type from category.
// list<...>: one or more records of the selected type per data block.
payload {
  messages: Cat001Record, Cat002Record, Cat034Record, Cat048Record, Cat240Record;
  selector: category -> 1: list<Cat001Record>, 2: list<Cat002Record>, 34: list<Cat034Record>, 48: list<Cat048Record>, 240: list<Cat240Record>;
}

// ==============================================================================
// ABSTRACT DATA MODEL (ASN.1-like) — describes WHAT the data is
// ==============================================================================

// --- Data item types ---

type DataSourceId {
  sac: integer [0..255];
  sic: integer [0..255];
}

type TargetReportDescriptor001 {
  typ: integer [0..1];
  sim: integer [0..1];
  ssrpsr: integer [0..3];
  ant: integer [0..1];
  spi: integer [0..1];
  rab: integer [0..1];
}

type TargetReportDescriptor048 {
  typ: integer [0..7];
  sim: integer [0..1];
  rdp: integer [0..1];
  spi: integer [0..1];
  rab: integer [0..1];
}

type MeasuredPositionPolar {
  rho: integer [0..65535];
  theta: integer [0..65535];
}

type CalculatedPositionCartesian {
  x: integer [-32768..32767];
  y: integer [-32768..32767];
}

type Mode2Code {
  v: integer [0..1];
  g: integer [0..1];
  l: integer [0..1];
  mode2: integer [0..4095];
}

type Mode1Code {
  v: integer [0..1];
  g: integer [0..1];
  l: integer [0..1];
  mode1: integer [0..31];
}

type Mode3ACode {
  v: integer [0..1];
  g: integer [0..1];
  l: integer [0..1];
  mode3a: integer [0..4095];
}

type Mode2Confidence {
  qa4: integer [0..1]; qa2: integer [0..1]; qa1: integer [0..1];
  qb4: integer [0..1]; qb2: integer [0..1]; qb1: integer [0..1];
  qc4: integer [0..1]; qc2: integer [0..1]; qc1: integer [0..1];
  qd4: integer [0..1]; qd2: integer [0..1]; qd1: integer [0..1];
}

type Mode1Confidence {
  qa4: integer [0..1]; qa2: integer [0..1]; qa1: integer [0..1];
  qb2: integer [0..1]; qb1: integer [0..1];
}

type Mode3AConfidence {
  qa4: integer [0..1]; qa2: integer [0..1]; qa1: integer [0..1];
  qb4: integer [0..1]; qb2: integer [0..1]; qb1: integer [0..1];
  qc4: integer [0..1]; qc2: integer [0..1]; qc1: integer [0..1];
  qd4: integer [0..1]; qd2: integer [0..1]; qd1: integer [0..1];
}

type FlightLevel {
  v: integer [0..1];
  g: integer [0..1];
  fl: integer [0..16383];
}

type ModeCCodeConfidence {
  v: integer [0..1]; g: integer [0..1];
  modec: integer [0..4095];
  qc1: integer [0..1]; qa1: integer [0..1]; qc2: integer [0..1]; qa2: integer [0..1];
  qc4: integer [0..1]; qa4: integer [0..1]; qb1: integer [0..1]; qd1: integer [0..1];
  qb2: integer [0..1]; qd2: integer [0..1]; qb4: integer [0..1]; qd4: integer [0..1];
}

type TimeOfDay24 {
  tod: integer [0..16777215];
}

type TrackNumber {
  trn: integer [0..4095];
}

type TrackStatus001 {
  con: integer [0..1]; rad: integer [0..1]; man: integer [0..1];
  dou: integer [0..1]; rdpc: integer [0..1];
  gho: integer [0..1];
}

type TrackStatus048 {
  cnf: integer [0..1];
  rad: integer [0..3];
  dou: integer [0..1]; mah: integer [0..1];
  cdm: integer [0..3];
}

type TrackVelocityPolar {
  gsp: integer [0..65535];
  hdg: integer [0..65535];
}

type TrackQuality {
  sigx: integer [0..255];
  sigy: integer [0..255];
}

type DopplerSpeed {
  d: integer [0..1];
  cal: integer [-512..511];
}

type RadarPlotCharacteristics {
  srl: integer [0..255]; srr: integer [0..255];
  sam: integer [-128..127];
  prl: integer [0..255];
  pam: integer [-128..127]; rpd: integer [-128..127]; apd: integer [-128..127];
}

type SystemConfig034 {
  nogo: integer [0..1]; rdpc: integer [0..1]; rdpr: integer [0..1];
  ovlrdp: integer [0..1]; ovlxmt: integer [0..1]; msc: integer [0..1]; tsv: integer [0..1];
}

type SystemProcessingMode034 {
  redrdp: integer [0..7];
  redxmt: integer [0..7];
}

type MessageCountEntry {
  typ: integer [0..31];
  count: integer [0..2047];
}

type CollimationError {
  rng: integer [-128..127];
  azm: integer [-128..127];
}

type PolarWindow {
  rhost: integer [0..65535]; rhoend: integer [0..65535];
  thetast: integer [0..65535]; thetaend: integer [0..65535];
}

type Position3D {
  hgt: integer [-32768..32767];
  lat: integer [-8388608..8388607];
  lon: integer [-8388608..8388607];
}

type PlotCountValue {
  typ: integer [0..31];
  count: integer [0..2047];
}

type DynamicWindow {
  rhost: integer [0..65535]; rhoend: integer [0..65535];
  thetast: integer [0..65535]; thetaend: integer [0..65535];
}

// --- Record types (PDUs) ---

type Cat001Record {
  i001_010: DataSourceId?;
  i001_020: TargetReportDescriptor001?;
  i001_040: MeasuredPositionPolar?;
  i001_042: CalculatedPositionCartesian?;
  i001_030: sequence of integer?;
  i001_050: Mode2Code?;
  i001_070: Mode3ACode?;
  i001_080: Mode3AConfidence?;
  i001_090: FlightLevel?;
  i001_100: ModeCCodeConfidence?;
  i001_120: integer? [0..127];
  i001_130: sequence of integer?;
  i001_131: integer? [-128..127];
  i001_141: integer? [0..65535];
  i001_161: integer? [0..4095];
  i001_170: TrackStatus001?;
  i001_200: TrackVelocityPolar?;
  i001_210: sequence of integer?;
}

type Cat002Record {
  i002_010: DataSourceId?;
  i002_000: integer? [1..8];
  i002_020: integer? [0..255];
  i002_030: TimeOfDay24?;
  i002_041: integer? [0..65535];
  i002_050: sequence of integer?;
  i002_060: sequence of integer?;
  i002_070: sequence of PlotCountValue?;
  i002_100: DynamicWindow?;
  i002_090: CollimationError?;
  i002_080: sequence of integer?;
}

type Cat034Record {
  i034_010: DataSourceId?;
  i034_000: integer? [0..255];
  i034_020: integer? [0..255];
  i034_030: TimeOfDay24?;
  i034_041: integer? [0..65535];
  i034_050: SystemConfig034?;
  i034_060: SystemProcessingMode034?;
  i034_070: sequence of MessageCountEntry?;
  i034_090: CollimationError?;
  i034_100: PolarWindow?;
  i034_110: integer? [0..255];
  i034_120: Position3D?;
}

type Cat048Record {
  i048_010: DataSourceId?;
  i048_020: TargetReportDescriptor048?;
  i048_030: sequence of integer?;
  i048_040: MeasuredPositionPolar?;
  i048_042: CalculatedPositionCartesian?;
  i048_050: Mode2Code?;
  i048_055: Mode1Code?;
  i048_060: Mode2Confidence?;
  i048_065: Mode1Confidence?;
  i048_070: Mode3ACode?;
  i048_080: Mode3AConfidence?;
  i048_090: FlightLevel?;
  i048_100: ModeCCodeConfidence?;
  i048_110: integer? [-32768..32767];
  i048_120: DopplerSpeed?;
  i048_130: RadarPlotCharacteristics?;
  i048_140: TimeOfDay24?;
  i048_161: TrackNumber?;
  i048_170: TrackStatus048?;
  i048_200: TrackVelocityPolar?;
  i048_210: TrackQuality?;
}

type Cat240Record {
  i240_010: DataSourceId?;
}

// ==============================================================================
// ENCODING (ECN-like) — describes HOW the data is serialized on the wire
// ==============================================================================

// ============== CAT 001 - Monoradar Target Reports (legacy) ==============
// UAP: 010, 020, 040, 070, 090, 130, 141, (FX) 050, 120, 131, 080, 100, 060, 030, (FX) 150, ...
message Cat001Record {
  fspec: fspec -> (
    0: i001_010, 1: i001_020, 2: i001_040, 3: i001_042, 4: i001_030, 5: i001_050, 6: i001_070, 7: FX,
    8: i001_080, 9: i001_090, 10: i001_100, 11: i001_120, 12: i001_130, 13: i001_131, 14: i001_141, 15: FX,
    16: i001_161, 17: i001_170, 18: i001_200, 19: i001_210
  );
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

// ============== CAT 002 - Monoradar Service Messages ==============
// UAP: 010, 000, 020, 030, 041, 050, 060, (FX) 070, 100, 090, 080, ...
message Cat002Record {
  fspec: fspec -> (
    0: i002_010, 1: i002_000, 2: i002_020, 3: i002_030, 4: i002_041, 5: i002_050, 6: i002_060, 7: FX,
    8: i002_070, 9: i002_100, 10: i002_090, 11: i002_080
  );
  i002_010: optional<DataSourceId>;
  i002_000: optional<u8> [1..8];                  // Message Type (1..8: North Marker, Sector Crossing, etc.)
  i002_020: optional<u8> [0..255];                // Sector Number (content not verifiable, full range)
  i002_030: optional<TimeOfDay24>;                // Time of Day
  i002_041: optional<u16> [0..65535];             // Antenna Rotation Period (content not verifiable)
  i002_050: optional<list<u8>>;                   // Station Configuration Status (variable length)
  i002_060: optional<list<u8>>;                   // Station Processing Mode (variable length)
  i002_070: optional<list<PlotCountValue>>;       // Plot Count Values
  i002_100: optional<DynamicWindow>;              // Dynamic Window - Type 1
  i002_090: optional<CollimationError>;           // Collimation Error
  i002_080: optional<list<u8>>;                   // Warning/Error Conditions (variable length)
}

// ============== CAT 034 - Monoradar Service Messages ==============
// UAP: 010, 000, 030, 020, 041, 050, 060, (FX) 070, 100, 110, 120, 090, ...
message Cat034Record {
  fspec: fspec -> (
    0: i034_010, 1: i034_000, 2: i034_020, 3: i034_030, 4: i034_041, 5: i034_050, 6: i034_060, 7: FX,
    8: i034_070, 9: i034_090, 10: i034_100, 11: i034_110, 12: i034_120
  );
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
  fspec: fspec -> (
    0: i048_010, 1: i048_020, 2: i048_030, 3: i048_040, 4: i048_042, 5: i048_050, 6: i048_055, 7: FX,
    8: i048_060, 9: i048_065, 10: i048_070, 11: i048_080, 12: i048_090, 13: i048_100, 14: i048_110, 15: FX,
    16: i048_120, 17: i048_130, 18: i048_140, 19: i048_161, 20: i048_170, 21: i048_200, 22: i048_210
  );
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
  fspec: fspec -> (0: i240_010);  // single item, no FX needed
  i240_010: optional<DataSourceId>;
}

// --- Encoding: struct-level wire format for data items ---

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

// Cat002: I002/070 Plot Count Values entry (3 bytes each)
struct PlotCountValue {
  typ: u8(5) [0..31];         // Counter type (SSR, PSR, etc.)
  count: u16(11) [0..2047];   // Plot count
}

// Cat002: I002/100 Dynamic Window - Type 1 (8 bytes)
struct DynamicWindow {
  rhost: u16 [0..65535];     // Rho start (content not verifiable)
  rhoend: u16 [0..65535];    // Rho end (content not verifiable)
  thetast: u16 [0..65535];   // Theta start (content not verifiable)
  thetaend: u16 [0..65535];  // Theta end (content not verifiable)
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
