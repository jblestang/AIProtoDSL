// ASTERIX family (CAT 001, 002, 034, 048, 240) — Messages, structs, fields and enumerations
// are defined per EUROCONTROL ASTERIX specifications. Reference (PDFs):
//   https://eurocontrol.int/publication/cat001-eurocontrol-standard-document-radar-data-exchange-part-2a
//   https://eurocontrol.int/publication/cat002-eurocontrol-standard-document-radar-data-exchange-part-2b
//   https://eurocontrol.int/publication/cat034-eurocontrol-specification-surveillance-data-exchange-part-2b
//   https://eurocontrol.int/publication/cat048-eurocontrol-specification-surveillance-data-exchange-asterix-part-4-category-48
//   https://eurocontrol.int/publication/cat240-eurocontrol-specification-surveillance-data-exchange-asterix
// See docs/asterix_eurocontrol_references.md for a table and direct PDF links.

transport {
	category: u8 [0..255];
	length: u16 [0..65535];
}



// Payload: record types per category selector (EUROCONTROL CAT 001/002/034/048/240).
payload {
	messages: Cat001Record, Cat002Record, Cat034Record, Cat048Record, Cat240Record;
	selector: category -> 1: list<Cat001Record>, 2: list<Cat002Record>, 34: list<Cat034Record>, 48: list<Cat048Record>, 240: list<Cat240Record>;
}







// Enumerations: value sets per EUROCONTROL spec (message type codes, etc.).
enum Cat034MessageType {
	NorthMarker = 1;
	SectorCrossing = 2;
	GeographicalFiltering = 3;
	JammingStrobe = 4;
	SolarStorm = 5;
}

enum Cat002MessageType {
	NorthMarker = 1;
	SectorCrossing = 2;
	SouthMarker = 3;
	ActivationOfBlindZoneFiltering = 8;
	StopOfBlindZoneFiltering = 9;
}



// Abstract types (logical model) and encoding structs below follow EUROCONTROL data items
// (e.g. I048/010 Data Source Identifier, I048/040 Measured Position). Fields map to spec subfields.
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
	rho: integer [0..65535] quantum "1/256 NM";
	theta: integer [0..65535] quantum "360/65536 °";
}

type CalculatedPositionCartesian {
	x: integer [-32768..32767] quantum "1/128 NM";
	y: integer [-32768..32767] quantum "1/128 NM";
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
	qa4: integer [0..1];
	qa2: integer [0..1];
	qa1: integer [0..1];
	qb4: integer [0..1];
	qb2: integer [0..1];
	qb1: integer [0..1];
	qc4: integer [0..1];
	qc2: integer [0..1];
	qc1: integer [0..1];
	qd4: integer [0..1];
	qd2: integer [0..1];
	qd1: integer [0..1];
}

type Mode1Confidence {
	qa4: integer [0..1];
	qa2: integer [0..1];
	qa1: integer [0..1];
	qb2: integer [0..1];
	qb1: integer [0..1];
}

type Mode3AConfidence {
	qa4: integer [0..1];
	qa2: integer [0..1];
	qa1: integer [0..1];
	qb4: integer [0..1];
	qb2: integer [0..1];
	qb1: integer [0..1];
	qc4: integer [0..1];
	qc2: integer [0..1];
	qc1: integer [0..1];
	qd4: integer [0..1];
	qd2: integer [0..1];
	qd1: integer [0..1];
}

type FlightLevel {
	v: integer [0..1];
	g: integer [0..1];
	fl: integer [0..16383];
}

type ModeCCodeConfidence {
	v: integer [0..1];
	g: integer [0..1];
	modec: integer [0..4095];
	qc1: integer [0..1];
	qa1: integer [0..1];
	qc2: integer [0..1];
	qa2: integer [0..1];
	qc4: integer [0..1];
	qa4: integer [0..1];
	qb1: integer [0..1];
	qd1: integer [0..1];
	qb2: integer [0..1];
	qd2: integer [0..1];
	qb4: integer [0..1];
	qd4: integer [0..1];
}

type TimeOfDay24 {
	tod: integer [0..16777215];
}

type TrackNumber {
	trn: integer [0..4095];
}

type TrackStatus001 {
	con: integer [0..1];
	rad: integer [0..1];
	man: integer [0..1];
	dou: integer [0..1];
	rdpc: integer [0..1];
	gho: integer [0..1];
}

type TrackStatus048 {
	cnf: integer [0..1];
	rad: integer [0..3];
	dou: integer [0..1];
	mah: integer [0..1];
	cdm: integer [0..3];
}

type TrackVelocityPolar {
	gsp: integer [0..65535] quantum "2^(-10) NM/s";
	hdg: integer [0..65535] quantum "360/65536 °";
}

type TrackQuality {
	sigx: integer [0..255];
	sigy: integer [0..255];
}


type AircraftAddress048 {
	addr: integer [0..16777215];
}
type CommunicationsAcas048 {
	com: integer [0..7];
	stat: integer [0..3];
	si: integer [0..1];
	mssc: integer [0..1];
	arc: integer [0..1];
	aic: integer [0..1];
	b1a: integer [0..1];
	b1b: integer [0..7];
}
type AircraftIdentification048 {
	chars: sequence of integer;
}
type BdsRegisterEntry {
	mbdata: sequence of integer;
	bds1: integer [0..15];
	bds2: integer [0..15];
}

type DopplerSpeed {
	d: integer [0..1];
	cal: integer [-512..511];
}


type RadarPlotCharacteristics {
	srl: integer? [0..255];
	srr: integer? [0..255];
	sam: integer? [-128..127];
	prl: integer? [0..255];
	pam: integer? [-128..127];
	rpd: integer? [-128..127];
	apd: integer? [-128..127];
}

type Com034 {
	nogo: integer [0..1];
	rdpc: integer [0..1];
	rdpr: integer [0..1];
	ovlrdp: integer [0..1];
	ovlxmt: integer [0..1];
	msc: integer [0..1];
	tsv: integer [0..1];
}

type SystemConfig034 {
	com: Com034?;
	psr: integer? [0..255];
	ssr: integer? [0..255];
	mds: integer? [0..255];
}

type RdpXmt034 {
	redrdp: integer [0..7];
	redxmt: integer [0..7];
}
type SystemProcessingMode034 {
	rdpxmt: RdpXmt034?;
}

type MessageCountEntry {
	typ: integer [0..31];
	count: integer [0..2047];
}

type CollimationError {
	rng: integer [-128..127] quantum "1/256 NM";
	azm: integer [-128..127] quantum "360/65536 °";
}

type PolarWindow {
	rhost: integer [0..65535] quantum "1/256 NM";
	rhoend: integer [0..65535] quantum "1/256 NM";
	thetast: integer [0..65535] quantum "360/65536 °";
	thetaend: integer [0..65535] quantum "360/65536 °";
}

type Position3D {
	hgt: integer [-32768..32767] quantum "1 ft";
	lat: integer [-8388608..8388607] quantum "180/2^23 °";
	lon: integer [-8388608..8388607] quantum "360/2^24 °";
}

type PlotCountValue {
	typ: integer [0..31];
	count: integer [0..2047] quantum "1";
}

type DynamicWindow {
	rhost: integer [0..65535] quantum "1/256 NM";
	rhoend: integer [0..65535] quantum "1/256 NM";
	thetast: integer [0..65535] quantum "360/65536 °";
	thetaend: integer [0..65535] quantum "360/65536 °";
}



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
	i002_000: Cat002MessageType?;
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
	i034_000: Cat034MessageType?;
	i034_030: TimeOfDay24?;
	i034_020: integer? [0..255];
	i034_041: integer? [0..65535];
	i034_050: SystemConfig034?;
	i034_060: SystemProcessingMode034?;
	i034_070: sequence of MessageCountEntry?;
	i034_100: PolarWindow?;
	i034_110: integer? [0..255];
	i034_120: Position3D?;
	i034_090: CollimationError?;
}

type Cat048Record {
	i048_010: DataSourceId?;
	i048_140: TimeOfDay24?;
	i048_020: TargetReportDescriptor048?;
	i048_040: MeasuredPositionPolar?;
	i048_070: Mode3ACode?;
	i048_090: FlightLevel?;
	i048_130: RadarPlotCharacteristics?;
	i048_220: AircraftAddress048?;
	i048_240: AircraftIdentification048?;
	i048_250: sequence of BdsRegisterEntry?;
	i048_161: TrackNumber?;
	i048_042: CalculatedPositionCartesian?;
	i048_200: TrackVelocityPolar?;
	i048_170: TrackStatus048?;
	i048_210: TrackQuality?;
	i048_030: sequence of integer?;
	i048_080: Mode3AConfidence?;
	i048_100: ModeCCodeConfidence?;
	i048_110: integer? [-32768..32767];
	i048_120: DopplerSpeed?;
	i048_230: CommunicationsAcas048?;
	i048_260: sequence of integer?;
	i048_055: Mode1Code?;
	i048_050: Mode2Code?;
	i048_065: Mode1Confidence?;
	i048_060: Mode2Confidence?;
	i048_sp: sequence of integer?;
	i048_re: sequence of integer?;
}

type Cat240Record {
	i240_010: DataSourceId?;
}







// Messages: one per ASTERIX record type; FSPEC and optional items per spec.
message Cat001Record {
	fspec: fspec(24, 8) -> (
	0: i001_010, 1: i001_020, 2: i001_040, 3: i001_042, 4: i001_030, 5: i001_050, 6: i001_070,
	7: i001_080, 8: i001_090, 9: i001_100, 10: i001_120, 11: i001_130, 12: i001_131, 13: i001_141,
	14: i001_161, 15: i001_170, 16: i001_200, 17: i001_210
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
	i001_131: optional<i8> [-128..127];
	i001_141: optional<u16> [0..65535];
	i001_161: optional<u16> [0..4095];
	i001_170: optional<TrackStatus001>;
	i001_200: optional<TrackVelocityPolar>;
	i001_210: optional<list<u8>>;
}



message Cat002Record {
	fspec: fspec(16, 8) -> (
	0: i002_010, 1: i002_000, 2: i002_020, 3: i002_030, 4: i002_041, 5: i002_050, 6: i002_060,
	7: i002_070, 8: i002_100, 9: i002_090, 10: i002_080
	);
	i002_010: optional<DataSourceId>;
	i002_000: optional<u8> [in(1, 2, 3, 8, 9)];
	i002_020: optional<u8> [0..255];
	i002_030: optional<TimeOfDay24>;
	i002_041: optional<u16> [0..65535];
	i002_050: optional<list<u8>>;
	i002_060: optional<list<u8>>;
	i002_070: optional<rep_list<PlotCountValue>>;
	i002_100: optional<DynamicWindow>;
	i002_090: optional<CollimationError>;
	i002_080: optional<list<u8>>;
}




message Cat034Record {
	fspec: fspec(16, 8) -> (
	0: i034_010, 1: i034_000, 2: i034_030, 3: i034_020, 4: i034_041, 5: i034_050, 6: i034_060,
	7: i034_070, 8: i034_100, 9: i034_110, 10: i034_120, 11: i034_090
	);
	i034_010: optional<DataSourceId>;
	i034_000: optional<u8> [in(1, 2, 3, 4, 5)];
	i034_030: optional<TimeOfDay24>;
	i034_020: optional<u8> [0..255];
	i034_041: optional<u16> [0..65535];
	i034_050: optional<SystemConfig034>;
	i034_060: optional<SystemProcessingMode034>;
	i034_070: optional<rep_list<MessageCountEntry>>;
	i034_100: optional<PolarWindow>;
	i034_110: optional<u8> [0..255];
	i034_120: optional<Position3D>;
	i034_090: optional<CollimationError>;
}



message Cat048Record {
	fspec: fspec(32, 8) -> (
	0: i048_010, 1: i048_140, 2: i048_020, 3: i048_040, 4: i048_070, 5: i048_090, 6: i048_130,
	7: i048_220, 8: i048_240, 9: i048_250, 10: i048_161, 11: i048_042, 12: i048_200, 13: i048_170,
	14: i048_210, 15: i048_030, 16: i048_080, 17: i048_100, 18: i048_110, 19: i048_120, 20: i048_230,
	21: i048_260, 22: i048_055, 23: i048_050, 24: i048_065, 25: i048_060, 26: i048_sp, 27: i048_re
	);
	i048_010: optional<DataSourceId>;
	i048_140: optional<TimeOfDay24>;
	i048_020: optional<TargetReportDescriptor048>;
	i048_040: optional<MeasuredPositionPolar>;
	i048_070: optional<Mode3ACode>;
	i048_090: optional<FlightLevel>;
	i048_130: optional<RadarPlotCharacteristics>;
	i048_220: optional<AircraftAddress048>;
	i048_240: optional<AircraftIdentification048>;
	i048_250: optional<rep_list<BdsRegisterEntry>>;
	i048_161: optional<TrackNumber>;
	i048_042: optional<CalculatedPositionCartesian>;
	i048_200: optional<TrackVelocityPolar>;
	i048_170: optional<TrackStatus048>;
	i048_210: optional<TrackQuality>;
	i048_030: optional<octets_fx>;
	i048_080: optional<Mode3AConfidence>;
	i048_100: optional<ModeCCodeConfidence>;
	i048_110: optional<i16> [-32768..32767];
	i048_120: optional<DopplerSpeed>;
	i048_230: optional<CommunicationsAcas048>;
	i048_260: optional<octets_fx>;
	i048_055: optional<Mode1Code>;
	i048_050: optional<Mode2Code>;
	i048_065: optional<Mode1Confidence>;
	i048_060: optional<Mode2Confidence>;
	i048_sp: optional<octets_fx>;
	i048_re: optional<octets_fx>;
}


message Cat240Record {
	fspec: fspec(8, 8) -> (0: i240_010);
	i240_010: optional<DataSourceId>;
}



// Structs: encoding of data items (e.g. I048/010, I048/040); field names and types per EUROCONTROL spec.
struct DataSourceId {
	sac: u8 [0..255];
	sic: u8 [0..255];
}

struct TargetReportDescriptor001 {
	typ: bitfield(1) [0..1];
	sim: bitfield(1) [0..1];
	ssrpsr: bitfield(2) [0..3];
	ant: bitfield(1) [0..1];
	spi: bitfield(1) [0..1];
	rab: bitfield(1) [0..1];
	spare: padding_bits(1);
}

struct TargetReportDescriptor048 {
	typ: bitfield(3) [0..7];
	sim: bitfield(1) [0..1];
	rdp: bitfield(1) [0..1];
	spi: bitfield(1) [0..1];
	rab: bitfield(1) [0..1];
	spare_fx: padding_bits(1);
}

struct TargetReportDescriptor048Ext {
	tst: bitfield(1) [0..1];
	err: bitfield(1) [0..1];
	xpp: bitfield(1) [0..1];
	me: bitfield(1) [0..1];
	mi: bitfield(1) [0..1];
	foefri: bitfield(2) [0..3];
	spare_fx2: padding_bits(1);
}

struct MeasuredPositionPolar {
	rho: u16 [0..65535] quantum "1/256 NM";
	theta: u16 [0..65535] quantum "360/65536 °";
}

struct CalculatedPositionCartesian {
	x: i16 [-32768..32767] quantum "1/128 NM";
	y: i16 [-32768..32767] quantum "1/128 NM";
}

struct Mode2Code {
	v: bitfield(1) [0..1];
	g: bitfield(1) [0..1];
	l: bitfield(1) [0..1];
	spare: padding_bits(1);
	mode2: u16(12) [0..4095];
}

struct Mode1Code {
	v: bitfield(1) [0..1];
	g: bitfield(1) [0..1];
	l: bitfield(1) [0..1];
	mode1: u8(5) [0..31];
}

struct Mode3ACode {
	v: bitfield(1) [0..1];
	g: bitfield(1) [0..1];
	l: bitfield(1) [0..1];
	spare: padding_bits(1);
	mode3a: u16(12) [0..4095];
}

struct Mode2Confidence {
	spare: padding_bits(4);
	qa4: bitfield(1) [0..1];
	qa2: bitfield(1) [0..1];
	qa1: bitfield(1) [0..1];
	qb4: bitfield(1) [0..1];
	qb2: bitfield(1) [0..1];
	qb1: bitfield(1) [0..1];
	qc4: bitfield(1) [0..1];
	qc2: bitfield(1) [0..1];
	qc1: bitfield(1) [0..1];
	qd4: bitfield(1) [0..1];
	qd2: bitfield(1) [0..1];
	qd1: bitfield(1) [0..1];

}

struct Mode1Confidence {
	spare: padding_bits(3);
	qa4: bitfield(1) [0..1];
	qa2: bitfield(1) [0..1];
	qa1: bitfield(1) [0..1];
	qb2: bitfield(1) [0..1];
	qb1: bitfield(1) [0..1];

}

struct Mode3AConfidence {
	spare: padding_bits(4);
	qa4: bitfield(1) [0..1];
	qa2: bitfield(1) [0..1];
	qa1: bitfield(1) [0..1];
	qb4: bitfield(1) [0..1];
	qb2: bitfield(1) [0..1];
	qb1: bitfield(1) [0..1];
	qc4: bitfield(1) [0..1];
	qc2: bitfield(1) [0..1];
	qc1: bitfield(1) [0..1];
	qd4: bitfield(1) [0..1];
	qd2: bitfield(1) [0..1];
	qd1: bitfield(1) [0..1];

}

struct FlightLevel {
	v: bitfield(1) [0..1];
	g: bitfield(1) [0..1];
	fl: u16(14) [0..16383] quantum "0.25 FL";
}

struct ModeCCodeConfidence {
	v: bitfield(1) [0..1];
	g: bitfield(1) [0..1];
	spare: padding_bits(2);
	modec: u16(12) [0..4095];
	spare2: padding_bits(4);
	qc1: bitfield(1) [0..1];
	qa1: bitfield(1) [0..1];
	qc2: bitfield(1) [0..1];
	qa2: bitfield(1) [0..1];
	qc4: bitfield(1) [0..1];
	qa4: bitfield(1) [0..1];
	qb1: bitfield(1) [0..1];
	qd1: bitfield(1) [0..1];
	qb2: bitfield(1) [0..1];
	qd2: bitfield(1) [0..1];
	qb4: bitfield(1) [0..1];
	qd4: bitfield(1) [0..1];

}

struct TimeOfDay24 {
	tod: u32(24) [0..16777215];
}

struct TrackNumber {
	spare: padding_bits(4);
	trn: u16(12) [0..4095];
}

struct TrackStatus001 {
	con: bitfield(1) [0..1];
	rad: bitfield(1) [0..1];
	man: bitfield(1) [0..1];
	dou: bitfield(1) [0..1];
	rdpc: bitfield(1) [0..1];
	spare: padding_bits(1);
	gho: bitfield(1) [0..1];
	spare2: padding_bits(1);

}

struct TrackStatus048 {
	cnf: bitfield(1) [0..1];
	rad: bitfield(2) [0..3];
	dou: bitfield(1) [0..1];
	mah: bitfield(1) [0..1];
	cdm: bitfield(2) [0..3];
	fspec: fspec(1, 0) -> (0: ext);
	ext: optional<TrackStatus048Ext>;
}

struct TrackStatus048Ext {
	tre: bitfield(1) [0..1];
	gho: bitfield(1) [0..1];
	sup: bitfield(1) [0..1];
	tcc: bitfield(1) [0..1];
	spare: padding_bits(3);
	spare2: padding_bits(1);

}

struct TrackVelocityPolar {
	gsp: u16 [0..65535] quantum "2^(-10) NM/s";
	hdg: u16 [0..65535] quantum "360/65536 °";
}

struct TrackQuality {
	sigx: u8 [0..255];
	sigy: u8 [0..255];
}


struct AircraftAddress048 {
	addr: u32(24) [0..16777215];
}

struct CommunicationsAcas048 {
	com: bitfield(3) [0..7];
	stat: bitfield(2) [0..3];
	si: bitfield(1) [0..1];
	mssc: bitfield(1) [0..1];
	spare: padding_bits(1);
	arc: bitfield(1) [0..1];
	aic: bitfield(1) [0..1];
	b1a: bitfield(1) [0..1];
	b1b: bitfield(3) [0..7];
	spare2: padding_bits(2);
}

struct AircraftIdentification048 {
	c: u8(6) [0..63];
	c2: u8(6) [0..63];
	c3: u8(6) [0..63];
	c4: u8(6) [0..63];
	c5: u8(6) [0..63];
	c6: u8(6) [0..63];
	c7: u8(6) [0..63];
	c8: u8(6) [0..63];
}

struct BdsRegisterEntry {
	mbdata: u8 [0..255];
	mbdata2: u8 [0..255];
	mbdata3: u8 [0..255];
	mbdata4: u8 [0..255];
	mbdata5: u8 [0..255];
	mbdata6: u8 [0..255];
	mbdata7: u8 [0..255];
	bds1: u8(4) [0..15];
	bds2: u8(4) [0..15];
}

struct DopplerSpeed {
	d: bitfield(1) [0..1];
	spare: padding_bits(5);
	cal: i16(10) [-512..511];
}


struct RadarPlotCharacteristics {
	fspec: fspec(8, 8) -> (0: srl, 1: srr, 2: sam, 3: prl, 4: pam, 5: rpd, 6: apd);
	srl: optional<u8> [0..255];
	srr: optional<u8> [0..255];
	sam: optional<i8> [-128..127];
	prl: optional<u8> [0..255];
	pam: optional<i8> [-128..127];
	rpd: optional<i8> [-128..127];
	apd: optional<i8> [-128..127];
}


struct Com034 {
	nogo: bitfield(1) [0..1];
	rdpc: bitfield(1) [0..1];
	rdpr: bitfield(1) [0..1];
	ovlrdp: bitfield(1) [0..1];
	ovlxmt: bitfield(1) [0..1];
	msc: bitfield(1) [0..1];
	tsv: bitfield(1) [0..1];
	spare: padding_bits(1);
}

struct SystemConfig034 {
	fspec: fspec(8, 8) -> (0: com, 1: psr, 2: ssr, 3: mds);
	com: optional<Com034>;
	psr: optional<u8> [0..255];
	ssr: optional<u8> [0..255];
	mds: optional<u8> [0..255];
}


struct RdpXmt034 {
	spare: padding_bits(1);
	redrdp: u8(3) [0..7];
	redxmt: u8(3) [0..7];
	spare2: padding_bits(1);
}
struct SystemProcessingMode034 {
	fspec: fspec(8, 8) -> (0: rdpxmt);
	rdpxmt: optional<RdpXmt034>;
}

struct MessageCountEntry {
	typ: bitfield(5) [0..31];
	count: u16(11) [0..2047];
}

struct CollimationError {
	rng: i8 [-128..127] quantum "1/256 NM";
	azm: i8 [-128..127] quantum "360/65536 °";
}


struct PlotCountValue {
	typ: bitfield(5) [0..31];
	count: u16(11) [0..2047] quantum "1";
}


struct DynamicWindow {
	rhost: u16 [0..65535] quantum "1/256 NM";
	rhoend: u16 [0..65535] quantum "1/256 NM";
	thetast: u16 [0..65535] quantum "360/65536 °";
	thetaend: u16 [0..65535] quantum "360/65536 °";
}

struct PolarWindow {
	rhost: u16 [0..65535] quantum "1/256 NM";
	rhoend: u16 [0..65535] quantum "1/256 NM";
	thetast: u16 [0..65535] quantum "360/65536 °";
	thetaend: u16 [0..65535] quantum "360/65536 °";
}

struct Position3D {
	hgt: i16 [-32768..32767] quantum "1 ft";
	lat: i32(24) [-8388608..8388607] quantum "180/2^23 °";
	lon: i32(24) [-8388608..8388607] quantum "360/2^24 °";
}
