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
	@doc "System Area Code (SAC); part of Data Source Identifier"
	sac: integer [0..255];
	@doc "System Identification Code (SIC); part of Data Source Identifier"
	sic: integer [0..255];
}

type TargetReportDescriptor001 {
	@doc "Report type (0=single, 1=multiple)"
	typ: integer [0..1];
	@doc "Simulated target"
	sim: integer [0..1];
	@doc "SSR/PSR mode (0–3)"
	ssrpsr: integer [0..3];
	@doc "Antenna (0=main, 1=auxiliary)"
	ant: integer [0..1];
	@doc "Special position identification"
	spi: integer [0..1];
	@doc "Range ambiguity"
	rab: integer [0..1];
}

type TargetReportDescriptor048 {
	@doc "Report type (0–7)"
	typ: integer [0..7];
	@doc "Simulated target"
	sim: integer [0..1];
	@doc "Radar data processing chain"
	rdp: integer [0..1];
	@doc "Special position identification"
	spi: integer [0..1];
	@doc "Range ambiguity"
	rab: integer [0..1];
}

type MeasuredPositionPolar {
	@doc "Slant range (rho) in 1/256 NM"
	rho: integer [0..65535] quantum "1/256 NM";
	@doc "Azimuth (theta) in 360/65536 degrees"
	theta: integer [0..65535] quantum "360/65536 °";
}

type CalculatedPositionCartesian {
	@doc "X coordinate in 1/128 NM (cartesian)"
	x: integer [-32768..32767] quantum "1/128 NM";
	@doc "Y coordinate in 1/128 NM (cartesian)"
	y: integer [-32768..32767] quantum "1/128 NM";
}

type Mode2Code {
	@doc "Valid (0=invalid, 1=valid)"
	v: integer [0..1];
	@doc "Garbled"
	g: integer [0..1];
	@doc "Lock (0=default, 1=lock)"
	l: integer [0..1];
	@doc "Mode 2 code (12 bits, 0–4095)"
	mode2: integer [0..4095];
}

type Mode1Code {
	@doc "Valid (0=invalid, 1=valid)"
	v: integer [0..1];
	@doc "Garbled"
	g: integer [0..1];
	@doc "Lock"
	l: integer [0..1];
	@doc "Mode 1 code (5 bits, 0–31)"
	mode1: integer [0..31];
}

type Mode3ACode {
	@doc "Valid (0=invalid, 1=valid)"
	v: integer [0..1];
	@doc "Garbled"
	g: integer [0..1];
	@doc "Lock"
	l: integer [0..1];
	@doc "Mode 3/A code (12 bits, 0–4095)"
	mode3a: integer [0..4095];
}

type Mode2Confidence {
	@doc "Confidence digit A (4)"
	qa4: integer [0..1];
	@doc "Confidence digit A (2)"
	qa2: integer [0..1];
	@doc "Confidence digit A (1)"
	qa1: integer [0..1];
	@doc "Confidence digit B (4)"
	qb4: integer [0..1];
	@doc "Confidence digit B (2)"
	qb2: integer [0..1];
	@doc "Confidence digit B (1)"
	qb1: integer [0..1];
	@doc "Confidence digit C (4)"
	qc4: integer [0..1];
	@doc "Confidence digit C (2)"
	qc2: integer [0..1];
	@doc "Confidence digit C (1)"
	qc1: integer [0..1];
	@doc "Confidence digit D (4)"
	qd4: integer [0..1];
	@doc "Confidence digit D (2)"
	qd2: integer [0..1];
	@doc "Confidence digit D (1)"
	qd1: integer [0..1];
}

type Mode1Confidence {
	@doc "Confidence digit A (4)"
	qa4: integer [0..1];
	@doc "Confidence digit A (2)"
	qa2: integer [0..1];
	@doc "Confidence digit A (1)"
	qa1: integer [0..1];
	@doc "Confidence digit B (2)"
	qb2: integer [0..1];
	@doc "Confidence digit B (1)"
	qb1: integer [0..1];
}

type Mode3AConfidence {
	@doc "Confidence digit A (4)"
	qa4: integer [0..1];
	@doc "Confidence digit A (2)"
	qa2: integer [0..1];
	@doc "Confidence digit A (1)"
	qa1: integer [0..1];
	@doc "Confidence digit B (4)"
	qb4: integer [0..1];
	@doc "Confidence digit B (2)"
	qb2: integer [0..1];
	@doc "Confidence digit B (1)"
	qb1: integer [0..1];
	@doc "Confidence digit C (4)"
	qc4: integer [0..1];
	@doc "Confidence digit C (2)"
	qc2: integer [0..1];
	@doc "Confidence digit C (1)"
	qc1: integer [0..1];
	@doc "Confidence digit D (4)"
	qd4: integer [0..1];
	@doc "Confidence digit D (2)"
	qd2: integer [0..1];
	@doc "Confidence digit D (1)"
	qd1: integer [0..1];
}

type FlightLevel {
	@doc "Valid / invalid"
	v: integer [0..1];
	@doc "Garbled"
	g: integer [0..1];
	@doc "Flight level value (1/4 FL)"
	fl: integer [0..16383];
}

type ModeCCodeConfidence {
	@doc "Valid (0=invalid, 1=valid)"
	v: integer [0..1];
	@doc "Garbled"
	g: integer [0..1];
	@doc "Mode C code (12 bits, altitude)"
	modec: integer [0..4095];
	@doc "Confidence digit C (1)"
	qc1: integer [0..1];
	@doc "Confidence digit A (1)"
	qa1: integer [0..1];
	@doc "Confidence digit C (2)"
	qc2: integer [0..1];
	@doc "Confidence digit A (2)"
	qa2: integer [0..1];
	@doc "Confidence digit C (4)"
	qc4: integer [0..1];
	@doc "Confidence digit A (4)"
	qa4: integer [0..1];
	@doc "Confidence digit B (1)"
	qb1: integer [0..1];
	@doc "Confidence digit D (1)"
	qd1: integer [0..1];
	@doc "Confidence digit B (2)"
	qb2: integer [0..1];
	@doc "Confidence digit D (2)"
	qd2: integer [0..1];
	@doc "Confidence digit B (4)"
	qb4: integer [0..1];
	@doc "Confidence digit D (4)"
	qd4: integer [0..1];
}

type TimeOfDay24 {
	@doc "Time of day in 1/128 seconds from midnight"
	tod: integer [0..16777215] quantum "1/128 s";
}

type TrackNumber {
	@doc "Track number (0–4095)"
	trn: integer [0..4095];
}

type TrackStatus001 {
	@doc "Confirmed track"
	con: integer [0..1];
	@doc "Radar plot update"
	rad: integer [0..1];
	@doc "Manoeuvre"
	man: integer [0..1];
	@doc "Doubtful track"
	dou: integer [0..1];
	@doc "RDP chain"
	rdpc: integer [0..1];
	@doc "Ghost track"
	gho: integer [0..1];
}

type TrackStatus048 {
	@doc "Confirmed track"
	cnf: integer [0..1];
	@doc "Radar plot update (0–3)"
	rad: integer [0..3];
	@doc "Doubtful track"
	dou: integer [0..1];
	@doc "Manoeuvre"
	mah: integer [0..1];
	@doc "Track formation (CDM)"
	cdm: integer [0..3];
}

type TrackVelocityPolar {
	@doc "Ground speed in 2^(-10) NM/s"
	gsp: integer [0..65535] quantum "2^(-10) NM/s";
	@doc "Heading in 360/65536 °"
	hdg: integer [0..65535] quantum "360/65536 °";
}

type TrackQuality {
	@doc "Standard deviation in X (sigma)"
	sigx: integer [0..255];
	@doc "Standard deviation in Y (sigma)"
	sigy: integer [0..255];
}


type AircraftAddress048 {
	@doc "24-bit aircraft address (ICAO)"
	addr: integer [0..16777215];
}
type CommunicationsAcas048 {
	@doc "Communications capability (COM, 3 bits)"
	com: integer [0..7];
	@doc "Status (STAT, 2 bits)"
	stat: integer [0..3];
	@doc "Surveillance integrity (SI)"
	si: integer [0..1];
	@doc "Mode S specific service capability (MSSC)"
	mssc: integer [0..1];
	@doc "Altitude reporting capability (ARC)"
	arc: integer [0..1];
	@doc "Aircraft identification capability (AIC)"
	aic: integer [0..1];
	@doc "B1A (1 bit)"
	b1a: integer [0..1];
	@doc "B1B (3 bits)"
	b1b: integer [0..7];
}
type AircraftIdentification048 {
	@doc "Aircraft identification (callsign) characters (6-bit each)"
	chars: sequence of integer;
}
type BdsRegisterEntry {
	@doc "Mode S BDS register data (56 bits / 7 octets)"
	mbdata: sequence of integer;
	@doc "BDS 1 (4 bits)"
	bds1: integer [0..15];
	@doc "BDS 2 (4 bits)"
	bds2: integer [0..15];
}

type DopplerSpeed {
	@doc "Doppler speed validity (0=invalid, 1=valid)"
	d: integer [0..1];
	@doc "Doppler speed (calibrated, signed)"
	cal: integer [-512..511];
}


type RadarPlotCharacteristics {
	@doc "Sum of the detected power in range (SRL)"
	srl: integer? [0..255];
	@doc "Sum of the detected power in range (SRR)"
	srr: integer? [0..255];
	@doc "Amplitude of the plot (SAM)"
	sam: integer? [-128..127];
	@doc "Plot amplitude in range (PRL)"
	prl: integer? [0..255];
	@doc "Plot amplitude of the plot (PAM)"
	pam: integer? [-128..127];
	@doc "Range deviation (RPD)"
	rpd: integer? [-128..127];
	@doc "Azimuth deviation (APD)"
	apd: integer? [-128..127];
}

type Com034 {
	@doc "No-go (COM status)"
	nogo: integer [0..1];
	@doc "RDP chain 1"
	rdpc: integer [0..1];
	@doc "RDP chain 2"
	rdpr: integer [0..1];
	@doc "Overload RDP"
	ovlrdp: integer [0..1];
	@doc "Overload XMT"
	ovlxmt: integer [0..1];
	@doc "Mono/stereo channel"
	msc: integer [0..1];
	@doc "Time slot validation"
	tsv: integer [0..1];
}

type Psr034 {
	@doc "PSR sensor status (1 octet, bit-coded per EUROCONTROL CAT034 I034/050)"
	status: integer [0..255];
}
type Ssr034 {
	@doc "SSR sensor status (1 octet, bit-coded per EUROCONTROL CAT034 I034/050)"
	status: integer [0..255];
}
type Mds034 {
	@doc "Antenna (0=main, 1=auxiliary)"
	ant: integer [0..1];
	@doc "Channel A/B (0–3)"
	chab: integer [0..3];
	@doc "Overload surveillance"
	ovlsur: integer [0..1];
	@doc "Mono/stereo channel"
	msc: integer [0..1];
	@doc "Split channel function"
	scf: integer [0..1];
	@doc "Diversity channel lockout failure"
	dlf: integer [0..1];
	@doc "Overload split channel function"
	ovlscf: integer [0..1];
	@doc "Overload diversity channel lockout"
	ovldlf: integer [0..1];
}
type SystemConfig034 {
	@doc "COM (communications) sensor status"
	com: Com034?;
	@doc "PSR (primary surveillance radar) sensor status"
	psr: Psr034?;
	@doc "SSR (secondary surveillance radar) sensor status"
	ssr: Ssr034?;
	@doc "MDS (Mode S) sensor status"
	mds: Mds034?;
}

type RdpXmt034 {
	@doc "Redundancy RDP channel (0–7)"
	redrdp: integer [0..7];
	@doc "Redundancy XMT channel (0–7)"
	redxmt: integer [0..7];
}
type SystemProcessingMode034 {
	@doc "RDP/XMT processing mode (redundancy)"
	rdpxmt: RdpXmt034?;
}

type MessageCountEntry {
	@doc "Message type code"
	typ: integer [0..31];
	@doc "Count"
	count: integer [0..2047];
}

type CollimationError {
	@doc "Range error (1/256 NM)"
	rng: integer [-128..127] quantum "1/256 NM";
	@doc "Azimuth error (360/65536 °)"
	azm: integer [-128..127] quantum "360/65536 °";
}

type PolarWindow {
	@doc "Range start (1/256 NM)"
	rhost: integer [0..65535] quantum "1/256 NM";
	@doc "Range end (1/256 NM)"
	rhoend: integer [0..65535] quantum "1/256 NM";
	@doc "Azimuth start (360/65536 °)"
	thetast: integer [0..65535] quantum "360/65536 °";
	@doc "Azimuth end (360/65536 °)"
	thetaend: integer [0..65535] quantum "360/65536 °";
}

type Position3D {
	@doc "Height in feet"
	hgt: integer [-32768..32767] quantum "1 ft";
	@doc "Latitude (180/2^23 °)"
	lat: integer [-8388608..8388607] quantum "180/2^23 °";
	@doc "Longitude (360/2^24 °)"
	lon: integer [-8388608..8388607] quantum "360/2^24 °";
}

type PlotCountValue {
	@doc "Plot/message type code (0–31)"
	typ: integer [0..31];
	@doc "Count value"
	count: integer [0..2047] quantum "1";
}

type DynamicWindow {
	@doc "Range start (1/256 NM)"
	rhost: integer [0..65535] quantum "1/256 NM";
	@doc "Range end (1/256 NM)"
	rhoend: integer [0..65535] quantum "1/256 NM";
	@doc "Azimuth start (360/65536 °)"
	thetast: integer [0..65535] quantum "360/65536 °";
	@doc "Azimuth end (360/65536 °)"
	thetaend: integer [0..65535] quantum "360/65536 °";
}



type Cat001Record {
	@doc "Data Source Identifier (SAC/SIC)"
	i001_010: DataSourceId?;
	@doc "Target report descriptor (TYP, SIM, SSR/PSR, etc.)"
	i001_020: TargetReportDescriptor001?;
	@doc "Measured position (polar)"
	i001_040: MeasuredPositionPolar?;
	@doc "Calculated position (cartesian)"
	i001_042: CalculatedPositionCartesian?;
	@doc "Reserved"
	i001_030: sequence of integer?;
	@doc "Mode 2 code"
	i001_050: Mode2Code?;
	@doc "Mode 3/A code"
	i001_070: Mode3ACode?;
	@doc "Mode 3/A confidence"
	i001_080: Mode3AConfidence?;
	@doc "Flight level (Mode C)"
	i001_090: FlightLevel?;
	@doc "Mode C code and confidence"
	i001_100: ModeCCodeConfidence?;
	@doc "Amplitude"
	i001_120: integer? [0..127];
	@doc "Reserved"
	i001_130: sequence of integer?;
	@doc "Reserved"
	i001_131: integer? [-128..127];
	@doc "Reserved"
	i001_141: integer? [0..65535];
	@doc "Reserved"
	i001_161: integer? [0..4095];
	@doc "Track status (CON, RAD, MAN, etc.)"
	i001_170: TrackStatus001?;
	@doc "Track velocity (ground speed, heading)"
	i001_200: TrackVelocityPolar?;
	@doc "Reserved"
	i001_210: sequence of integer?;
}

type Cat002Record {
	@doc "Data Source Identifier (SAC/SIC)"
	i002_010: DataSourceId?;
	@doc "Message type (North/South Marker, Sector Crossing, etc.)"
	i002_000: Cat002MessageType?;
	@doc "Message count or subtype"
	i002_020: integer? [0..255];
	@doc "Time of day"
	i002_030: TimeOfDay24?;
	@doc "Reserved"
	i002_041: integer? [0..65535];
	@doc "Reserved"
	i002_050: sequence of integer?;
	@doc "Reserved"
	i002_060: sequence of integer?;
	@doc "Plot count values per type"
	i002_070: sequence of PlotCountValue?;
	@doc "Dynamic window (sector filter)"
	i002_100: DynamicWindow?;
	@doc "Collimation error"
	i002_090: CollimationError?;
	@doc "Reserved"
	i002_080: sequence of integer?;
}

type Cat034Record {
	@doc "Data Source Identifier (SAC/SIC)"
	i034_010: DataSourceId?;
	@doc "Message type (North Marker, Sector Crossing, etc.)"
	i034_000: Cat034MessageType?;
	@doc "Time of day"
	i034_030: TimeOfDay24?;
	@doc "Sector number (azimuth in 360/256 °)"
	i034_020: integer? [0..255] quantum "360/256 °";
	@doc "Antenna rotation period in 1/128 s"
	i034_041: integer? [0..65535] quantum "1/128 s";
	@doc "System configuration (COM, PSR, SSR, MDS status)"
	i034_050: SystemConfig034?;
	@doc "System processing mode (RDP/XMT)"
	i034_060: SystemProcessingMode034?;
	@doc "Message count entries per type"
	i034_070: sequence of MessageCountEntry?;
	@doc "Polar window (sector filter)"
	i034_100: PolarWindow?;
	@doc "Reserved / spare"
	i034_110: integer? [0..255];
	@doc "Sensor position (3D)"
	i034_120: Position3D?;
	@doc "Collimation error (range/azimuth)"
	i034_090: CollimationError?;
}

type Cat048Record {
	@doc "Data Source Identifier (SAC/SIC)"
	i048_010: DataSourceId?;
	@doc "Time of day"
	i048_140: TimeOfDay24?;
	@doc "Target report descriptor (TYP, SIM, RDP, SPI, RAB)"
	i048_020: TargetReportDescriptor048?;
	@doc "Measured position (polar: range, azimuth)"
	i048_040: MeasuredPositionPolar?;
	@doc "Mode 3/A code"
	i048_070: Mode3ACode?;
	@doc "Flight level (Mode C)"
	i048_090: FlightLevel?;
	@doc "Radar plot characteristics (SRL, SRR, SAM, etc.)"
	i048_130: RadarPlotCharacteristics?;
	@doc "Aircraft address (24-bit)"
	i048_220: AircraftAddress048?;
	@doc "Aircraft identification (callsign)"
	i048_240: AircraftIdentification048?;
	@doc "BDS register entries (Mode S BDS data)"
	i048_250: sequence of BdsRegisterEntry?;
	@doc "Track number"
	i048_161: TrackNumber?;
	@doc "Calculated position (cartesian)"
	i048_042: CalculatedPositionCartesian?;
	@doc "Track velocity (ground speed, heading)"
	i048_200: TrackVelocityPolar?;
	@doc "Track status (CNF, RAD, DOU, MAH, CDM)"
	i048_170: TrackStatus048?;
	@doc "Track quality (SIGX, SIGY)"
	i048_210: TrackQuality?;
	@doc "Reserved expansion"
	i048_030: sequence of integer?;
	@doc "Mode 3/A confidence"
	i048_080: Mode3AConfidence?;
	@doc "Mode C code and confidence"
	i048_100: ModeCCodeConfidence?;
	@doc "Height (barometric altitude)"
	i048_110: integer? [-32768..32767];
	@doc "Doppler speed"
	i048_120: DopplerSpeed?;
	@doc "Communications/ACAS capability"
	i048_230: CommunicationsAcas048?;
	@doc "Reserved expansion"
	i048_260: sequence of integer?;
	@doc "Mode 1 code"
	i048_055: Mode1Code?;
	@doc "Mode 2 code"
	i048_050: Mode2Code?;
	@doc "Mode 1 confidence"
	i048_065: Mode1Confidence?;
	@doc "Mode 2 confidence"
	i048_060: Mode2Confidence?;
	@doc "Special purpose field"
	i048_sp: sequence of integer?;
	@doc "Reserved field"
	i048_re: sequence of integer?;
}

type Cat240Record {
	@doc "Data Source Identifier (SAC/SIC)"
	i240_010: DataSourceId?;
}







// Messages: one per ASTERIX record type; FSPEC and optional items per spec.
message Cat001Record {
	fspec: bitmap(24, 7) -> (
	0: i001_010, 1: i001_020, 2: i001_040, 3: i001_042, 4: i001_030, 5: i001_050, 6: i001_070,
	7: i001_080, 8: i001_090, 9: i001_100, 10: i001_120, 11: i001_130, 12: i001_131, 13: i001_141,
	14: i001_161, 15: i001_170, 16: i001_200, 17: i001_210
	);
	@doc "Data Source Identifier (SAC/SIC)"
	i001_010: optional<DataSourceId>;
	@doc "Target report descriptor (TYP, SIM, SSR/PSR, etc.)"
	i001_020: optional<TargetReportDescriptor001>;
	@doc "Measured position (polar)"
	i001_040: optional<MeasuredPositionPolar>;
	@doc "Calculated position (cartesian)"
	i001_042: optional<CalculatedPositionCartesian>;
	@doc "Reserved"
	i001_030: optional<list<u8>>;
	@doc "Mode 2 code"
	i001_050: optional<Mode2Code>;
	@doc "Mode 3/A code"
	i001_070: optional<Mode3ACode>;
	@doc "Mode 3/A confidence"
	i001_080: optional<Mode3AConfidence>;
	@doc "Flight level (Mode C)"
	i001_090: optional<FlightLevel>;
	@doc "Mode C code and confidence"
	i001_100: optional<ModeCCodeConfidence>;
	@doc "Amplitude"
	i001_120: optional<i8> [0..127];
	@doc "Reserved"
	i001_130: optional<list<u8>>;
	@doc "Reserved"
	i001_131: optional<i8> [-128..127];
	@doc "Reserved"
	i001_141: optional<u16> [0..65535];
	@doc "Reserved"
	i001_161: optional<u16> [0..4095];
	@doc "Track status (CON, RAD, MAN, etc.)"
	i001_170: optional<TrackStatus001>;
	@doc "Track velocity (ground speed, heading)"
	i001_200: optional<TrackVelocityPolar>;
	@doc "Reserved"
	i001_210: optional<list<u8>>;
}



message Cat002Record {
	fspec: bitmap(14, 7) -> (
	0: i002_010, 1: i002_000, 2: i002_020, 3: i002_030, 4: i002_041, 5: i002_050, 6: i002_060,
	7: i002_070, 8: i002_100, 9: i002_090, 10: i002_080
	);
	@doc "Data Source Identifier (SAC/SIC)"
	i002_010: optional<DataSourceId>;
	@doc "Message type (North/South Marker, Sector Crossing, etc.)"
	i002_000: optional<u8> [(1, 2, 3, 8, 9)];
	@doc "Message count or subtype"
	i002_020: optional<u8> [0..255];
	@doc "Time of day"
	i002_030: optional<TimeOfDay24>;
	@doc "Reserved"
	i002_041: optional<u16> [0..65535];
	@doc "Reserved"
	i002_050: optional<list<u8>>;
	@doc "Reserved"
	i002_060: optional<list<u8>>;
	@doc "Plot count values per type"
	i002_070: optional<rep_list<PlotCountValue>>;
	@doc "Dynamic window (sector filter)"
	i002_100: optional<DynamicWindow>;
	@doc "Collimation error"
	i002_090: optional<CollimationError>;
	@doc "Reserved"
	i002_080: optional<list<u8>>;
}




message Cat034Record {
	fspec: bitmap(14, 7) -> (
	0: i034_010, 1: i034_000, 2: i034_030, 3: i034_020, 4: i034_041, 5: i034_050, 6: i034_060,
	7: i034_070, 8: i034_100, 9: i034_110, 10: i034_120, 11: i034_090
	);
	@doc "Data Source Identifier (SAC/SIC)"
	i034_010: optional<DataSourceId>;
	@doc "Message type (North Marker, Sector Crossing, etc.)"
	i034_000: optional<Cat034MessageType>;
	@doc "Time of day"
	i034_030: optional<TimeOfDay24>;
	@doc "Sector number (azimuth in 360/256 °)"
	i034_020: optional<u8> [0..255] quantum "360/256 °";
	@doc "Antenna rotation period in 1/128 s"
	i034_041: optional<u16> [0..65535] quantum "1/128 s";
	@doc "System configuration (COM, PSR, SSR, MDS status)"
	i034_050: optional<SystemConfig034>;
	@doc "System processing mode (RDP/XMT)"
	i034_060: optional<SystemProcessingMode034>;
	@doc "Message count entries per type"
	i034_070: optional<rep_list<MessageCountEntry>>;
	@doc "Polar window (sector filter)"
	i034_100: optional<PolarWindow>;
	@doc "Reserved / spare"
	i034_110: optional<u8> [0..255];
	@doc "Sensor position (3D)"
	i034_120: optional<Position3D>;
	@doc "Collimation error (range/azimuth)"
	i034_090: optional<CollimationError>;
}



message Cat048Record {
	fspec: bitmap(28, 7) -> (
	0: i048_010, 1: i048_140, 2: i048_020, 3: i048_040, 4: i048_070, 5: i048_090, 6: i048_130,
	7: i048_220, 8: i048_240, 9: i048_250, 10: i048_161, 11: i048_042, 12: i048_200, 13: i048_170,
	14: i048_210, 15: i048_030, 16: i048_080, 17: i048_100, 18: i048_110, 19: i048_120, 20: i048_230,
	21: i048_260, 22: i048_055, 23: i048_050, 24: i048_065, 25: i048_060, 26: i048_sp, 27: i048_re
	);
	@doc "Data Source Identifier (SAC/SIC)"
	i048_010: optional<DataSourceId>;
	@doc "Time of day"
	i048_140: optional<TimeOfDay24>;
	@doc "Target report descriptor (TYP, SIM, RDP, SPI, RAB)"
	i048_020: optional<TargetReportDescriptor048>;
	@doc "Measured position (polar: range, azimuth)"
	i048_040: optional<MeasuredPositionPolar>;
	@doc "Mode 3/A code"
	i048_070: optional<Mode3ACode>;
	@doc "Flight level (Mode C)"
	i048_090: optional<FlightLevel>;
	@doc "Radar plot characteristics (SRL, SRR, SAM, etc.)"
	i048_130: optional<RadarPlotCharacteristics>;
	@doc "Aircraft address (24-bit)"
	i048_220: optional<AircraftAddress048>;
	@doc "Aircraft identification (callsign)"
	i048_240: optional<AircraftIdentification048>;
	@doc "BDS register entries (Mode S BDS data)"
	i048_250: optional<rep_list<BdsRegisterEntry>>;
	@doc "Track number"
	i048_161: optional<TrackNumber>;
	@doc "Calculated position (cartesian)"
	i048_042: optional<CalculatedPositionCartesian>;
	@doc "Track velocity (ground speed, heading)"
	i048_200: optional<TrackVelocityPolar>;
	@doc "Track status (CNF, RAD, DOU, MAH, CDM)"
	i048_170: optional<TrackStatus048>;
	@doc "Track quality (SIGX, SIGY)"
	i048_210: optional<TrackQuality>;
	@doc "Reserved expansion"
	i048_030: optional<octets_fx>;
	@doc "Mode 3/A confidence"
	i048_080: optional<Mode3AConfidence>;
	@doc "Mode C code and confidence"
	i048_100: optional<ModeCCodeConfidence>;
	@doc "Height (barometric altitude)"
	i048_110: optional<i16> [-32768..32767];
	@doc "Doppler speed"
	i048_120: optional<DopplerSpeed>;
	@doc "Communications/ACAS capability"
	i048_230: optional<CommunicationsAcas048>;
	@doc "Reserved expansion"
	i048_260: optional<octets_fx>;
	@doc "Mode 1 code"
	i048_055: optional<Mode1Code>;
	@doc "Mode 2 code"
	i048_050: optional<Mode2Code>;
	@doc "Mode 1 confidence"
	i048_065: optional<Mode1Confidence>;
	@doc "Mode 2 confidence"
	i048_060: optional<Mode2Confidence>;
	@doc "Special purpose field"
	i048_sp: optional<octets_fx>;
	@doc "Reserved field"
	i048_re: optional<octets_fx>;
}


message Cat240Record {
	fspec: bitmap(7, 7) -> (0: i240_010);
	@doc "Data Source Identifier (SAC/SIC)"
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
	spare: padding(1, bits);
}

struct TargetReportDescriptor048 {
	typ: bitfield(3) [0..7];
	sim: bitfield(1) [0..1];
	rdp: bitfield(1) [0..1];
	spi: bitfield(1) [0..1];
	rab: bitfield(1) [0..1];
	spare_fx: padding(1, bits);
}

struct TargetReportDescriptor048Ext {
	tst: bitfield(1) [0..1];
	err: bitfield(1) [0..1];
	xpp: bitfield(1) [0..1];
	me: bitfield(1) [0..1];
	mi: bitfield(1) [0..1];
	foefri: bitfield(2) [0..3];
	spare_fx2: padding(1, bits);
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
	spare: padding(1, bits);
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
	spare: padding(1, bits);
	mode3a: u16(12) [0..4095];
}

struct Mode2Confidence {
	spare: padding(4, bits);
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
	spare: padding(3, bits);
	qa4: bitfield(1) [0..1];
	qa2: bitfield(1) [0..1];
	qa1: bitfield(1) [0..1];
	qb2: bitfield(1) [0..1];
	qb1: bitfield(1) [0..1];

}

struct Mode3AConfidence {
	spare: padding(4, bits);
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
	spare: padding(2, bits);
	modec: u16(12) [0..4095];
	spare2: padding(4, bits);
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
	tod: u32(24) [0..16777215] quantum "1/128 s";
}

struct TrackNumber {
	spare: padding(4, bits);
	trn: u16(12) [0..4095];
}

struct TrackStatus001 {
	con: bitfield(1) [0..1];
	rad: bitfield(1) [0..1];
	man: bitfield(1) [0..1];
	dou: bitfield(1) [0..1];
	rdpc: bitfield(1) [0..1];
	spare: padding(1, bits);
	gho: bitfield(1) [0..1];
	spare2: padding(1, bits);

}

struct TrackStatus048 {
	cnf: bitfield(1) [0..1];
	rad: bitfield(2) [0..3];
	dou: bitfield(1) [0..1];
	mah: bitfield(1) [0..1];
	cdm: bitfield(2) [0..3];
	fspec: bitmap(1, 0) -> (0: ext);
	ext: optional<TrackStatus048Ext>;
}

struct TrackStatus048Ext {
	tre: bitfield(1) [0..1];
	gho: bitfield(1) [0..1];
	sup: bitfield(1) [0..1];
	tcc: bitfield(1) [0..1];
	spare: padding(3, bits);
	spare2: padding(1, bits);

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
	spare: padding(1, bits);
	arc: bitfield(1) [0..1];
	aic: bitfield(1) [0..1];
	b1a: bitfield(1) [0..1];
	b1b: bitfield(3) [0..7];
	spare2: padding(2, bits);
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
	spare: padding(5, bits);
	cal: i16(10) [-512..511];
}


struct RadarPlotCharacteristics {
	fspec: bitmap(7, 7) -> (0: srl, 1: srr, 2: sam, 3: prl, 4: pam, 5: rpd, 6: apd);
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
	spare: padding(1, bits);
}

struct Psr034 {
	// 1 octet: PSR sensor status bits (EUROCONTROL CAT034 I034/050)
	status: u8 [0..255];
}
struct Ssr034 {
	// 1 octet: SSR sensor status bits (EUROCONTROL CAT034 I034/050)
	status: u8 [0..255];
}
struct Mds034 {
	// Octet 1: ANT(1), CHAB(2), OVLSUR(1), MSC(1), SCF(1), DLF(1), OVLSCF(1)
	ant: bitfield(1) [0..1];
	chab: bitfield(2) [0..3];
	ovlsur: bitfield(1) [0..1];
	msc: bitfield(1) [0..1];
	scf: bitfield(1) [0..1];
	dlf: bitfield(1) [0..1];
	ovlscf: bitfield(1) [0..1];
	// Octet 2: OVLDLF(1), spare(7)
	ovldlf: bitfield(1) [0..1];
	spare: padding(7, bits);
}
struct SystemConfig034 {
	fspec: bitmap(7, 7) -> (0: com, 3: psr, 4: ssr, 5: mds);
	com: optional<Com034>;
	psr: optional<Psr034>;
	ssr: optional<Ssr034>;
	mds: optional<Mds034>;
}


struct RdpXmt034 {
	spare: padding(1, bits);
	redrdp: u8(3) [0..7];
	redxmt: u8(3) [0..7];
	spare2: padding(1, bits);
}
struct SystemProcessingMode034 {
	fspec: bitmap(7, 7) -> (0: rdpxmt);
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
