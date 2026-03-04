-- Auto-generated Wireshark Lua Dissector for asterix_family
local asterix_family_proto = Proto("asterix_family", "asterix_family Protocol")

-- ProtoFields
local f = {}
f.transport_category = ProtoField.bytes("asterix_family.transport.category", "category", base.HEX)
f.transport_length = ProtoField.bytes("asterix_family.transport.length", "length", base.HEX)
f.msg_Cat001Record = ProtoField.none("asterix_family.msg.Cat001Record", "Message Cat001Record")
f.msg_Cat001Record_fspec = ProtoField.bytes("asterix_family.msg.Cat001Record.fspec", "fspec", base.DEC)
f.msg_Cat001Record_i001_010 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_010", "i001_010", base.DEC)
f.msg_Cat001Record_i001_020 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_020", "i001_020", base.DEC)
f.msg_Cat001Record_i001_040 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_040", "i001_040", base.DEC)
f.msg_Cat001Record_i001_042 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_042", "i001_042", base.DEC)
f.msg_Cat001Record_i001_030 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_030", "i001_030", base.DEC)
f.msg_Cat001Record_i001_050 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_050", "i001_050", base.DEC)
f.msg_Cat001Record_i001_070 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_070", "i001_070", base.DEC)
f.msg_Cat001Record_i001_080 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_080", "i001_080", base.DEC)
f.msg_Cat001Record_i001_090 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_090", "i001_090", base.DEC)
f.msg_Cat001Record_i001_100 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_100", "i001_100", base.DEC)
f.msg_Cat001Record_i001_120 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_120", "i001_120", base.DEC)
f.msg_Cat001Record_i001_130 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_130", "i001_130", base.DEC)
f.msg_Cat001Record_i001_131 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_131", "i001_131", base.DEC)
f.msg_Cat001Record_i001_141 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_141", "i001_141", base.DEC)
f.msg_Cat001Record_i001_161 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_161", "i001_161", base.DEC)
f.msg_Cat001Record_i001_170 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_170", "i001_170", base.DEC)
f.msg_Cat001Record_i001_200 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_200", "i001_200", base.DEC)
f.msg_Cat001Record_i001_210 = ProtoField.bytes("asterix_family.msg.Cat001Record.i001_210", "i001_210", base.DEC)
f.msg_Cat002Record = ProtoField.none("asterix_family.msg.Cat002Record", "Message Cat002Record")
f.msg_Cat002Record_fspec = ProtoField.bytes("asterix_family.msg.Cat002Record.fspec", "fspec", base.DEC)
f.msg_Cat002Record_i002_010 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_010", "i002_010", base.DEC)
f.msg_Cat002Record_i002_000 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_000", "i002_000", base.DEC)
f.msg_Cat002Record_i002_020 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_020", "i002_020", base.DEC)
f.msg_Cat002Record_i002_030 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_030", "i002_030", base.DEC)
f.msg_Cat002Record_i002_041 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_041", "i002_041", base.DEC)
f.msg_Cat002Record_i002_050 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_050", "i002_050", base.DEC)
f.msg_Cat002Record_i002_060 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_060", "i002_060", base.DEC)
f.msg_Cat002Record_i002_070 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_070", "i002_070", base.DEC)
f.msg_Cat002Record_i002_100 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_100", "i002_100", base.DEC)
f.msg_Cat002Record_i002_090 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_090", "i002_090", base.DEC)
f.msg_Cat002Record_i002_080 = ProtoField.bytes("asterix_family.msg.Cat002Record.i002_080", "i002_080", base.DEC)
f.msg_Cat034Record = ProtoField.none("asterix_family.msg.Cat034Record", "Message Cat034Record")
f.msg_Cat034Record_fspec = ProtoField.bytes("asterix_family.msg.Cat034Record.fspec", "fspec", base.DEC)
f.msg_Cat034Record_i034_010 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_010", "i034_010", base.DEC)
f.msg_Cat034Record_i034_000 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_000", "i034_000", base.DEC)
f.msg_Cat034Record_i034_030 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_030", "i034_030", base.DEC)
f.msg_Cat034Record_i034_020 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_020", "i034_020", base.DEC)
f.msg_Cat034Record_i034_041 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_041", "i034_041", base.DEC)
f.msg_Cat034Record_i034_050 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_050", "i034_050", base.DEC)
f.msg_Cat034Record_i034_060 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_060", "i034_060", base.DEC)
f.msg_Cat034Record_i034_070 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_070", "i034_070", base.DEC)
f.msg_Cat034Record_i034_100 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_100", "i034_100", base.DEC)
f.msg_Cat034Record_i034_110 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_110", "i034_110", base.DEC)
f.msg_Cat034Record_i034_120 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_120", "i034_120", base.DEC)
f.msg_Cat034Record_i034_090 = ProtoField.bytes("asterix_family.msg.Cat034Record.i034_090", "i034_090", base.DEC)
f.msg_Cat048Record = ProtoField.none("asterix_family.msg.Cat048Record", "Message Cat048Record")
f.msg_Cat048Record_fspec = ProtoField.bytes("asterix_family.msg.Cat048Record.fspec", "fspec", base.DEC)
f.msg_Cat048Record_i048_010 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_010", "i048_010", base.DEC)
f.msg_Cat048Record_i048_140 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_140", "i048_140", base.DEC)
f.msg_Cat048Record_i048_020 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_020", "i048_020", base.DEC)
f.msg_Cat048Record_i048_040 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_040", "i048_040", base.DEC)
f.msg_Cat048Record_i048_070 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_070", "i048_070", base.DEC)
f.msg_Cat048Record_i048_090 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_090", "i048_090", base.DEC)
f.msg_Cat048Record_i048_130 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_130", "i048_130", base.DEC)
f.msg_Cat048Record_i048_220 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_220", "i048_220", base.DEC)
f.msg_Cat048Record_i048_240 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_240", "i048_240", base.DEC)
f.msg_Cat048Record_i048_250 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_250", "i048_250", base.DEC)
f.msg_Cat048Record_i048_161 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_161", "i048_161", base.DEC)
f.msg_Cat048Record_i048_042 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_042", "i048_042", base.DEC)
f.msg_Cat048Record_i048_200 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_200", "i048_200", base.DEC)
f.msg_Cat048Record_i048_170 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_170", "i048_170", base.DEC)
f.msg_Cat048Record_i048_210 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_210", "i048_210", base.DEC)
f.msg_Cat048Record_i048_030 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_030", "i048_030", base.DEC)
f.msg_Cat048Record_i048_080 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_080", "i048_080", base.DEC)
f.msg_Cat048Record_i048_100 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_100", "i048_100", base.DEC)
f.msg_Cat048Record_i048_110 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_110", "i048_110", base.DEC)
f.msg_Cat048Record_i048_120 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_120", "i048_120", base.DEC)
f.msg_Cat048Record_i048_230 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_230", "i048_230", base.DEC)
f.msg_Cat048Record_i048_260 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_260", "i048_260", base.DEC)
f.msg_Cat048Record_i048_055 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_055", "i048_055", base.DEC)
f.msg_Cat048Record_i048_050 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_050", "i048_050", base.DEC)
f.msg_Cat048Record_i048_065 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_065", "i048_065", base.DEC)
f.msg_Cat048Record_i048_060 = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_060", "i048_060", base.DEC)
f.msg_Cat048Record_i048_sp = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_sp", "i048_sp", base.DEC)
f.msg_Cat048Record_i048_re = ProtoField.bytes("asterix_family.msg.Cat048Record.i048_re", "i048_re", base.DEC)
f.msg_Cat240Record = ProtoField.none("asterix_family.msg.Cat240Record", "Message Cat240Record")
f.msg_Cat240Record_fspec = ProtoField.bytes("asterix_family.msg.Cat240Record.fspec", "fspec", base.DEC)
f.msg_Cat240Record_i240_010 = ProtoField.bytes("asterix_family.msg.Cat240Record.i240_010", "i240_010", base.DEC)
f.struct_DataSourceId = ProtoField.none("asterix_family.struct.DataSourceId", "Struct DataSourceId")
f.struct_DataSourceId_sac = ProtoField.uint8("asterix_family.struct.DataSourceId.sac", "sac", base.DEC)
f.struct_DataSourceId_sic = ProtoField.uint8("asterix_family.struct.DataSourceId.sic", "sic", base.DEC)
f.struct_TargetReportDescriptor001 = ProtoField.none("asterix_family.struct.TargetReportDescriptor001", "Struct TargetReportDescriptor001")
f.struct_TargetReportDescriptor001_typ = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor001.typ", "typ", base.DEC)
f.struct_TargetReportDescriptor001_sim = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor001.sim", "sim", base.DEC)
f.struct_TargetReportDescriptor001_ssrpsr = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor001.ssrpsr", "ssrpsr", base.DEC)
f.struct_TargetReportDescriptor001_ant = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor001.ant", "ant", base.DEC)
f.struct_TargetReportDescriptor001_spi = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor001.spi", "spi", base.DEC)
f.struct_TargetReportDescriptor001_rab = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor001.rab", "rab", base.DEC)
f.struct_TargetReportDescriptor001_spare = ProtoField.bytes("asterix_family.struct.TargetReportDescriptor001.spare", "spare", base.DEC)
f.struct_TargetReportDescriptor048 = ProtoField.none("asterix_family.struct.TargetReportDescriptor048", "Struct TargetReportDescriptor048")
f.struct_TargetReportDescriptor048_typ = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048.typ", "typ", base.DEC)
f.struct_TargetReportDescriptor048_sim = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048.sim", "sim", base.DEC)
f.struct_TargetReportDescriptor048_rdp = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048.rdp", "rdp", base.DEC)
f.struct_TargetReportDescriptor048_spi = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048.spi", "spi", base.DEC)
f.struct_TargetReportDescriptor048_rab = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048.rab", "rab", base.DEC)
f.struct_TargetReportDescriptor048_spare_fx = ProtoField.bytes("asterix_family.struct.TargetReportDescriptor048.spare_fx", "spare_fx", base.DEC)
f.struct_TargetReportDescriptor048Ext = ProtoField.none("asterix_family.struct.TargetReportDescriptor048Ext", "Struct TargetReportDescriptor048Ext")
f.struct_TargetReportDescriptor048Ext_tst = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048Ext.tst", "tst", base.DEC)
f.struct_TargetReportDescriptor048Ext_err = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048Ext.err", "err", base.DEC)
f.struct_TargetReportDescriptor048Ext_xpp = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048Ext.xpp", "xpp", base.DEC)
f.struct_TargetReportDescriptor048Ext_me = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048Ext.me", "me", base.DEC)
f.struct_TargetReportDescriptor048Ext_mi = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048Ext.mi", "mi", base.DEC)
f.struct_TargetReportDescriptor048Ext_foefri = ProtoField.uint32("asterix_family.struct.TargetReportDescriptor048Ext.foefri", "foefri", base.DEC)
f.struct_TargetReportDescriptor048Ext_spare_fx2 = ProtoField.bytes("asterix_family.struct.TargetReportDescriptor048Ext.spare_fx2", "spare_fx2", base.DEC)
f.struct_MeasuredPositionPolar = ProtoField.none("asterix_family.struct.MeasuredPositionPolar", "Struct MeasuredPositionPolar")
f.struct_MeasuredPositionPolar_rho = ProtoField.uint16("asterix_family.struct.MeasuredPositionPolar.rho", "rho", base.DEC)
f.struct_MeasuredPositionPolar_theta = ProtoField.uint16("asterix_family.struct.MeasuredPositionPolar.theta", "theta", base.DEC)
f.struct_CalculatedPositionCartesian = ProtoField.none("asterix_family.struct.CalculatedPositionCartesian", "Struct CalculatedPositionCartesian")
f.struct_CalculatedPositionCartesian_x = ProtoField.int16("asterix_family.struct.CalculatedPositionCartesian.x", "x", base.DEC)
f.struct_CalculatedPositionCartesian_y = ProtoField.int16("asterix_family.struct.CalculatedPositionCartesian.y", "y", base.DEC)
f.struct_Mode2Code = ProtoField.none("asterix_family.struct.Mode2Code", "Struct Mode2Code")
f.struct_Mode2Code_v = ProtoField.uint32("asterix_family.struct.Mode2Code.v", "v", base.DEC)
f.struct_Mode2Code_g = ProtoField.uint32("asterix_family.struct.Mode2Code.g", "g", base.DEC)
f.struct_Mode2Code_l = ProtoField.uint32("asterix_family.struct.Mode2Code.l", "l", base.DEC)
f.struct_Mode2Code_spare = ProtoField.bytes("asterix_family.struct.Mode2Code.spare", "spare", base.DEC)
f.struct_Mode2Code_mode2 = ProtoField.uint32("asterix_family.struct.Mode2Code.mode2", "mode2", base.DEC)
f.struct_Mode1Code = ProtoField.none("asterix_family.struct.Mode1Code", "Struct Mode1Code")
f.struct_Mode1Code_v = ProtoField.uint32("asterix_family.struct.Mode1Code.v", "v", base.DEC)
f.struct_Mode1Code_g = ProtoField.uint32("asterix_family.struct.Mode1Code.g", "g", base.DEC)
f.struct_Mode1Code_l = ProtoField.uint32("asterix_family.struct.Mode1Code.l", "l", base.DEC)
f.struct_Mode1Code_mode1 = ProtoField.uint32("asterix_family.struct.Mode1Code.mode1", "mode1", base.DEC)
f.struct_Mode3ACode = ProtoField.none("asterix_family.struct.Mode3ACode", "Struct Mode3ACode")
f.struct_Mode3ACode_v = ProtoField.uint32("asterix_family.struct.Mode3ACode.v", "v", base.DEC)
f.struct_Mode3ACode_g = ProtoField.uint32("asterix_family.struct.Mode3ACode.g", "g", base.DEC)
f.struct_Mode3ACode_l = ProtoField.uint32("asterix_family.struct.Mode3ACode.l", "l", base.DEC)
f.struct_Mode3ACode_spare = ProtoField.bytes("asterix_family.struct.Mode3ACode.spare", "spare", base.DEC)
f.struct_Mode3ACode_mode3a = ProtoField.uint32("asterix_family.struct.Mode3ACode.mode3a", "mode3a", base.DEC)
f.struct_Mode2Confidence = ProtoField.none("asterix_family.struct.Mode2Confidence", "Struct Mode2Confidence")
f.struct_Mode2Confidence_spare = ProtoField.bytes("asterix_family.struct.Mode2Confidence.spare", "spare", base.DEC)
f.struct_Mode2Confidence_qa4 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qa4", "qa4", base.DEC)
f.struct_Mode2Confidence_qa2 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qa2", "qa2", base.DEC)
f.struct_Mode2Confidence_qa1 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qa1", "qa1", base.DEC)
f.struct_Mode2Confidence_qb4 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qb4", "qb4", base.DEC)
f.struct_Mode2Confidence_qb2 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qb2", "qb2", base.DEC)
f.struct_Mode2Confidence_qb1 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qb1", "qb1", base.DEC)
f.struct_Mode2Confidence_qc4 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qc4", "qc4", base.DEC)
f.struct_Mode2Confidence_qc2 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qc2", "qc2", base.DEC)
f.struct_Mode2Confidence_qc1 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qc1", "qc1", base.DEC)
f.struct_Mode2Confidence_qd4 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qd4", "qd4", base.DEC)
f.struct_Mode2Confidence_qd2 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qd2", "qd2", base.DEC)
f.struct_Mode2Confidence_qd1 = ProtoField.uint32("asterix_family.struct.Mode2Confidence.qd1", "qd1", base.DEC)
f.struct_Mode1Confidence = ProtoField.none("asterix_family.struct.Mode1Confidence", "Struct Mode1Confidence")
f.struct_Mode1Confidence_spare = ProtoField.bytes("asterix_family.struct.Mode1Confidence.spare", "spare", base.DEC)
f.struct_Mode1Confidence_qa4 = ProtoField.uint32("asterix_family.struct.Mode1Confidence.qa4", "qa4", base.DEC)
f.struct_Mode1Confidence_qa2 = ProtoField.uint32("asterix_family.struct.Mode1Confidence.qa2", "qa2", base.DEC)
f.struct_Mode1Confidence_qa1 = ProtoField.uint32("asterix_family.struct.Mode1Confidence.qa1", "qa1", base.DEC)
f.struct_Mode1Confidence_qb2 = ProtoField.uint32("asterix_family.struct.Mode1Confidence.qb2", "qb2", base.DEC)
f.struct_Mode1Confidence_qb1 = ProtoField.uint32("asterix_family.struct.Mode1Confidence.qb1", "qb1", base.DEC)
f.struct_Mode3AConfidence = ProtoField.none("asterix_family.struct.Mode3AConfidence", "Struct Mode3AConfidence")
f.struct_Mode3AConfidence_spare = ProtoField.bytes("asterix_family.struct.Mode3AConfidence.spare", "spare", base.DEC)
f.struct_Mode3AConfidence_qa4 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qa4", "qa4", base.DEC)
f.struct_Mode3AConfidence_qa2 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qa2", "qa2", base.DEC)
f.struct_Mode3AConfidence_qa1 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qa1", "qa1", base.DEC)
f.struct_Mode3AConfidence_qb4 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qb4", "qb4", base.DEC)
f.struct_Mode3AConfidence_qb2 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qb2", "qb2", base.DEC)
f.struct_Mode3AConfidence_qb1 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qb1", "qb1", base.DEC)
f.struct_Mode3AConfidence_qc4 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qc4", "qc4", base.DEC)
f.struct_Mode3AConfidence_qc2 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qc2", "qc2", base.DEC)
f.struct_Mode3AConfidence_qc1 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qc1", "qc1", base.DEC)
f.struct_Mode3AConfidence_qd4 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qd4", "qd4", base.DEC)
f.struct_Mode3AConfidence_qd2 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qd2", "qd2", base.DEC)
f.struct_Mode3AConfidence_qd1 = ProtoField.uint32("asterix_family.struct.Mode3AConfidence.qd1", "qd1", base.DEC)
f.struct_FlightLevel = ProtoField.none("asterix_family.struct.FlightLevel", "Struct FlightLevel")
f.struct_FlightLevel_v = ProtoField.uint32("asterix_family.struct.FlightLevel.v", "v", base.DEC)
f.struct_FlightLevel_g = ProtoField.uint32("asterix_family.struct.FlightLevel.g", "g", base.DEC)
f.struct_FlightLevel_fl = ProtoField.uint32("asterix_family.struct.FlightLevel.fl", "fl", base.DEC)
f.struct_ModeCCodeConfidence = ProtoField.none("asterix_family.struct.ModeCCodeConfidence", "Struct ModeCCodeConfidence")
f.struct_ModeCCodeConfidence_v = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.v", "v", base.DEC)
f.struct_ModeCCodeConfidence_g = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.g", "g", base.DEC)
f.struct_ModeCCodeConfidence_spare = ProtoField.bytes("asterix_family.struct.ModeCCodeConfidence.spare", "spare", base.DEC)
f.struct_ModeCCodeConfidence_modec = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.modec", "modec", base.DEC)
f.struct_ModeCCodeConfidence_spare2 = ProtoField.bytes("asterix_family.struct.ModeCCodeConfidence.spare2", "spare2", base.DEC)
f.struct_ModeCCodeConfidence_qc1 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qc1", "qc1", base.DEC)
f.struct_ModeCCodeConfidence_qa1 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qa1", "qa1", base.DEC)
f.struct_ModeCCodeConfidence_qc2 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qc2", "qc2", base.DEC)
f.struct_ModeCCodeConfidence_qa2 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qa2", "qa2", base.DEC)
f.struct_ModeCCodeConfidence_qc4 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qc4", "qc4", base.DEC)
f.struct_ModeCCodeConfidence_qa4 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qa4", "qa4", base.DEC)
f.struct_ModeCCodeConfidence_qb1 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qb1", "qb1", base.DEC)
f.struct_ModeCCodeConfidence_qd1 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qd1", "qd1", base.DEC)
f.struct_ModeCCodeConfidence_qb2 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qb2", "qb2", base.DEC)
f.struct_ModeCCodeConfidence_qd2 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qd2", "qd2", base.DEC)
f.struct_ModeCCodeConfidence_qb4 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qb4", "qb4", base.DEC)
f.struct_ModeCCodeConfidence_qd4 = ProtoField.uint32("asterix_family.struct.ModeCCodeConfidence.qd4", "qd4", base.DEC)
f.struct_TimeOfDay24 = ProtoField.none("asterix_family.struct.TimeOfDay24", "Struct TimeOfDay24")
f.struct_TimeOfDay24_tod = ProtoField.uint32("asterix_family.struct.TimeOfDay24.tod", "tod", base.DEC)
f.struct_TrackNumber = ProtoField.none("asterix_family.struct.TrackNumber", "Struct TrackNumber")
f.struct_TrackNumber_spare = ProtoField.bytes("asterix_family.struct.TrackNumber.spare", "spare", base.DEC)
f.struct_TrackNumber_trn = ProtoField.uint32("asterix_family.struct.TrackNumber.trn", "trn", base.DEC)
f.struct_TrackStatus001 = ProtoField.none("asterix_family.struct.TrackStatus001", "Struct TrackStatus001")
f.struct_TrackStatus001_con = ProtoField.uint32("asterix_family.struct.TrackStatus001.con", "con", base.DEC)
f.struct_TrackStatus001_rad = ProtoField.uint32("asterix_family.struct.TrackStatus001.rad", "rad", base.DEC)
f.struct_TrackStatus001_man = ProtoField.uint32("asterix_family.struct.TrackStatus001.man", "man", base.DEC)
f.struct_TrackStatus001_dou = ProtoField.uint32("asterix_family.struct.TrackStatus001.dou", "dou", base.DEC)
f.struct_TrackStatus001_rdpc = ProtoField.uint32("asterix_family.struct.TrackStatus001.rdpc", "rdpc", base.DEC)
f.struct_TrackStatus001_spare = ProtoField.bytes("asterix_family.struct.TrackStatus001.spare", "spare", base.DEC)
f.struct_TrackStatus001_gho = ProtoField.uint32("asterix_family.struct.TrackStatus001.gho", "gho", base.DEC)
f.struct_TrackStatus001_spare2 = ProtoField.bytes("asterix_family.struct.TrackStatus001.spare2", "spare2", base.DEC)
f.struct_TrackStatus048 = ProtoField.none("asterix_family.struct.TrackStatus048", "Struct TrackStatus048")
f.struct_TrackStatus048_cnf = ProtoField.uint32("asterix_family.struct.TrackStatus048.cnf", "cnf", base.DEC)
f.struct_TrackStatus048_rad = ProtoField.uint32("asterix_family.struct.TrackStatus048.rad", "rad", base.DEC)
f.struct_TrackStatus048_dou = ProtoField.uint32("asterix_family.struct.TrackStatus048.dou", "dou", base.DEC)
f.struct_TrackStatus048_mah = ProtoField.uint32("asterix_family.struct.TrackStatus048.mah", "mah", base.DEC)
f.struct_TrackStatus048_cdm = ProtoField.uint32("asterix_family.struct.TrackStatus048.cdm", "cdm", base.DEC)
f.struct_TrackStatus048_fspec = ProtoField.bytes("asterix_family.struct.TrackStatus048.fspec", "fspec", base.DEC)
f.struct_TrackStatus048_ext = ProtoField.bytes("asterix_family.struct.TrackStatus048.ext", "ext", base.DEC)
f.struct_TrackStatus048Ext = ProtoField.none("asterix_family.struct.TrackStatus048Ext", "Struct TrackStatus048Ext")
f.struct_TrackStatus048Ext_tre = ProtoField.uint32("asterix_family.struct.TrackStatus048Ext.tre", "tre", base.DEC)
f.struct_TrackStatus048Ext_gho = ProtoField.uint32("asterix_family.struct.TrackStatus048Ext.gho", "gho", base.DEC)
f.struct_TrackStatus048Ext_sup = ProtoField.uint32("asterix_family.struct.TrackStatus048Ext.sup", "sup", base.DEC)
f.struct_TrackStatus048Ext_tcc = ProtoField.uint32("asterix_family.struct.TrackStatus048Ext.tcc", "tcc", base.DEC)
f.struct_TrackStatus048Ext_spare = ProtoField.bytes("asterix_family.struct.TrackStatus048Ext.spare", "spare", base.DEC)
f.struct_TrackStatus048Ext_spare2 = ProtoField.bytes("asterix_family.struct.TrackStatus048Ext.spare2", "spare2", base.DEC)
f.struct_TrackVelocityPolar = ProtoField.none("asterix_family.struct.TrackVelocityPolar", "Struct TrackVelocityPolar")
f.struct_TrackVelocityPolar_gsp = ProtoField.uint16("asterix_family.struct.TrackVelocityPolar.gsp", "gsp", base.DEC)
f.struct_TrackVelocityPolar_hdg = ProtoField.uint16("asterix_family.struct.TrackVelocityPolar.hdg", "hdg", base.DEC)
f.struct_TrackQuality = ProtoField.none("asterix_family.struct.TrackQuality", "Struct TrackQuality")
f.struct_TrackQuality_sigx = ProtoField.uint8("asterix_family.struct.TrackQuality.sigx", "sigx", base.DEC)
f.struct_TrackQuality_sigy = ProtoField.uint8("asterix_family.struct.TrackQuality.sigy", "sigy", base.DEC)
f.struct_AircraftAddress048 = ProtoField.none("asterix_family.struct.AircraftAddress048", "Struct AircraftAddress048")
f.struct_AircraftAddress048_addr = ProtoField.uint32("asterix_family.struct.AircraftAddress048.addr", "addr", base.DEC)
f.struct_CommunicationsAcas048 = ProtoField.none("asterix_family.struct.CommunicationsAcas048", "Struct CommunicationsAcas048")
f.struct_CommunicationsAcas048_com = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.com", "com", base.DEC)
f.struct_CommunicationsAcas048_stat = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.stat", "stat", base.DEC)
f.struct_CommunicationsAcas048_si = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.si", "si", base.DEC)
f.struct_CommunicationsAcas048_mssc = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.mssc", "mssc", base.DEC)
f.struct_CommunicationsAcas048_spare = ProtoField.bytes("asterix_family.struct.CommunicationsAcas048.spare", "spare", base.DEC)
f.struct_CommunicationsAcas048_arc = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.arc", "arc", base.DEC)
f.struct_CommunicationsAcas048_aic = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.aic", "aic", base.DEC)
f.struct_CommunicationsAcas048_b1a = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.b1a", "b1a", base.DEC)
f.struct_CommunicationsAcas048_b1b = ProtoField.uint32("asterix_family.struct.CommunicationsAcas048.b1b", "b1b", base.DEC)
f.struct_CommunicationsAcas048_spare2 = ProtoField.bytes("asterix_family.struct.CommunicationsAcas048.spare2", "spare2", base.DEC)
f.struct_AircraftIdentification048 = ProtoField.none("asterix_family.struct.AircraftIdentification048", "Struct AircraftIdentification048")
f.struct_AircraftIdentification048_c = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c", "c", base.DEC)
f.struct_AircraftIdentification048_c2 = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c2", "c2", base.DEC)
f.struct_AircraftIdentification048_c3 = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c3", "c3", base.DEC)
f.struct_AircraftIdentification048_c4 = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c4", "c4", base.DEC)
f.struct_AircraftIdentification048_c5 = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c5", "c5", base.DEC)
f.struct_AircraftIdentification048_c6 = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c6", "c6", base.DEC)
f.struct_AircraftIdentification048_c7 = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c7", "c7", base.DEC)
f.struct_AircraftIdentification048_c8 = ProtoField.uint32("asterix_family.struct.AircraftIdentification048.c8", "c8", base.DEC)
f.struct_BdsRegisterEntry = ProtoField.none("asterix_family.struct.BdsRegisterEntry", "Struct BdsRegisterEntry")
f.struct_BdsRegisterEntry_mbdata = ProtoField.uint8("asterix_family.struct.BdsRegisterEntry.mbdata", "mbdata", base.DEC)
f.struct_BdsRegisterEntry_mbdata2 = ProtoField.uint8("asterix_family.struct.BdsRegisterEntry.mbdata2", "mbdata2", base.DEC)
f.struct_BdsRegisterEntry_mbdata3 = ProtoField.uint8("asterix_family.struct.BdsRegisterEntry.mbdata3", "mbdata3", base.DEC)
f.struct_BdsRegisterEntry_mbdata4 = ProtoField.uint8("asterix_family.struct.BdsRegisterEntry.mbdata4", "mbdata4", base.DEC)
f.struct_BdsRegisterEntry_mbdata5 = ProtoField.uint8("asterix_family.struct.BdsRegisterEntry.mbdata5", "mbdata5", base.DEC)
f.struct_BdsRegisterEntry_mbdata6 = ProtoField.uint8("asterix_family.struct.BdsRegisterEntry.mbdata6", "mbdata6", base.DEC)
f.struct_BdsRegisterEntry_mbdata7 = ProtoField.uint8("asterix_family.struct.BdsRegisterEntry.mbdata7", "mbdata7", base.DEC)
f.struct_BdsRegisterEntry_bds1 = ProtoField.uint32("asterix_family.struct.BdsRegisterEntry.bds1", "bds1", base.DEC)
f.struct_BdsRegisterEntry_bds2 = ProtoField.uint32("asterix_family.struct.BdsRegisterEntry.bds2", "bds2", base.DEC)
f.struct_DopplerSpeed = ProtoField.none("asterix_family.struct.DopplerSpeed", "Struct DopplerSpeed")
f.struct_DopplerSpeed_d = ProtoField.uint32("asterix_family.struct.DopplerSpeed.d", "d", base.DEC)
f.struct_DopplerSpeed_spare = ProtoField.bytes("asterix_family.struct.DopplerSpeed.spare", "spare", base.DEC)
f.struct_DopplerSpeed_cal = ProtoField.uint32("asterix_family.struct.DopplerSpeed.cal", "cal", base.DEC)
f.struct_RadarPlotCharacteristics = ProtoField.none("asterix_family.struct.RadarPlotCharacteristics", "Struct RadarPlotCharacteristics")
f.struct_RadarPlotCharacteristics_fspec = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.fspec", "fspec", base.DEC)
f.struct_RadarPlotCharacteristics_srl = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.srl", "srl", base.DEC)
f.struct_RadarPlotCharacteristics_srr = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.srr", "srr", base.DEC)
f.struct_RadarPlotCharacteristics_sam = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.sam", "sam", base.DEC)
f.struct_RadarPlotCharacteristics_prl = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.prl", "prl", base.DEC)
f.struct_RadarPlotCharacteristics_pam = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.pam", "pam", base.DEC)
f.struct_RadarPlotCharacteristics_rpd = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.rpd", "rpd", base.DEC)
f.struct_RadarPlotCharacteristics_apd = ProtoField.bytes("asterix_family.struct.RadarPlotCharacteristics.apd", "apd", base.DEC)
f.struct_Com034 = ProtoField.none("asterix_family.struct.Com034", "Struct Com034")
f.struct_Com034_nogo = ProtoField.uint32("asterix_family.struct.Com034.nogo", "nogo", base.DEC)
f.struct_Com034_rdpc = ProtoField.uint32("asterix_family.struct.Com034.rdpc", "rdpc", base.DEC)
f.struct_Com034_rdpr = ProtoField.uint32("asterix_family.struct.Com034.rdpr", "rdpr", base.DEC)
f.struct_Com034_ovlrdp = ProtoField.uint32("asterix_family.struct.Com034.ovlrdp", "ovlrdp", base.DEC)
f.struct_Com034_ovlxmt = ProtoField.uint32("asterix_family.struct.Com034.ovlxmt", "ovlxmt", base.DEC)
f.struct_Com034_msc = ProtoField.uint32("asterix_family.struct.Com034.msc", "msc", base.DEC)
f.struct_Com034_tsv = ProtoField.uint32("asterix_family.struct.Com034.tsv", "tsv", base.DEC)
f.struct_Com034_spare = ProtoField.bytes("asterix_family.struct.Com034.spare", "spare", base.DEC)
f.struct_Psr034 = ProtoField.none("asterix_family.struct.Psr034", "Struct Psr034")
f.struct_Psr034_status = ProtoField.uint8("asterix_family.struct.Psr034.status", "status", base.DEC)
f.struct_Ssr034 = ProtoField.none("asterix_family.struct.Ssr034", "Struct Ssr034")
f.struct_Ssr034_status = ProtoField.uint8("asterix_family.struct.Ssr034.status", "status", base.DEC)
f.struct_Mds034 = ProtoField.none("asterix_family.struct.Mds034", "Struct Mds034")
f.struct_Mds034_ant = ProtoField.uint32("asterix_family.struct.Mds034.ant", "ant", base.DEC)
f.struct_Mds034_chab = ProtoField.uint32("asterix_family.struct.Mds034.chab", "chab", base.DEC)
f.struct_Mds034_ovlsur = ProtoField.uint32("asterix_family.struct.Mds034.ovlsur", "ovlsur", base.DEC)
f.struct_Mds034_msc = ProtoField.uint32("asterix_family.struct.Mds034.msc", "msc", base.DEC)
f.struct_Mds034_scf = ProtoField.uint32("asterix_family.struct.Mds034.scf", "scf", base.DEC)
f.struct_Mds034_dlf = ProtoField.uint32("asterix_family.struct.Mds034.dlf", "dlf", base.DEC)
f.struct_Mds034_ovlscf = ProtoField.uint32("asterix_family.struct.Mds034.ovlscf", "ovlscf", base.DEC)
f.struct_Mds034_ovldlf = ProtoField.uint32("asterix_family.struct.Mds034.ovldlf", "ovldlf", base.DEC)
f.struct_Mds034_spare = ProtoField.bytes("asterix_family.struct.Mds034.spare", "spare", base.DEC)
f.struct_SystemConfig034 = ProtoField.none("asterix_family.struct.SystemConfig034", "Struct SystemConfig034")
f.struct_SystemConfig034_fspec = ProtoField.bytes("asterix_family.struct.SystemConfig034.fspec", "fspec", base.DEC)
f.struct_SystemConfig034_com = ProtoField.bytes("asterix_family.struct.SystemConfig034.com", "com", base.DEC)
f.struct_SystemConfig034_psr = ProtoField.bytes("asterix_family.struct.SystemConfig034.psr", "psr", base.DEC)
f.struct_SystemConfig034_ssr = ProtoField.bytes("asterix_family.struct.SystemConfig034.ssr", "ssr", base.DEC)
f.struct_SystemConfig034_mds = ProtoField.bytes("asterix_family.struct.SystemConfig034.mds", "mds", base.DEC)
f.struct_RdpXmt034 = ProtoField.none("asterix_family.struct.RdpXmt034", "Struct RdpXmt034")
f.struct_RdpXmt034_spare = ProtoField.bytes("asterix_family.struct.RdpXmt034.spare", "spare", base.DEC)
f.struct_RdpXmt034_redrdp = ProtoField.uint32("asterix_family.struct.RdpXmt034.redrdp", "redrdp", base.DEC)
f.struct_RdpXmt034_redxmt = ProtoField.uint32("asterix_family.struct.RdpXmt034.redxmt", "redxmt", base.DEC)
f.struct_RdpXmt034_spare2 = ProtoField.bytes("asterix_family.struct.RdpXmt034.spare2", "spare2", base.DEC)
f.struct_SystemProcessingMode034 = ProtoField.none("asterix_family.struct.SystemProcessingMode034", "Struct SystemProcessingMode034")
f.struct_SystemProcessingMode034_fspec = ProtoField.bytes("asterix_family.struct.SystemProcessingMode034.fspec", "fspec", base.DEC)
f.struct_SystemProcessingMode034_rdpxmt = ProtoField.bytes("asterix_family.struct.SystemProcessingMode034.rdpxmt", "rdpxmt", base.DEC)
f.struct_MessageCountEntry = ProtoField.none("asterix_family.struct.MessageCountEntry", "Struct MessageCountEntry")
f.struct_MessageCountEntry_typ = ProtoField.uint32("asterix_family.struct.MessageCountEntry.typ", "typ", base.DEC)
f.struct_MessageCountEntry_count = ProtoField.uint32("asterix_family.struct.MessageCountEntry.count", "count", base.DEC)
f.struct_CollimationError = ProtoField.none("asterix_family.struct.CollimationError", "Struct CollimationError")
f.struct_CollimationError_rng = ProtoField.int8("asterix_family.struct.CollimationError.rng", "rng", base.DEC)
f.struct_CollimationError_azm = ProtoField.int8("asterix_family.struct.CollimationError.azm", "azm", base.DEC)
f.struct_PlotCountValue = ProtoField.none("asterix_family.struct.PlotCountValue", "Struct PlotCountValue")
f.struct_PlotCountValue_typ = ProtoField.uint32("asterix_family.struct.PlotCountValue.typ", "typ", base.DEC)
f.struct_PlotCountValue_count = ProtoField.uint32("asterix_family.struct.PlotCountValue.count", "count", base.DEC)
f.struct_DynamicWindow = ProtoField.none("asterix_family.struct.DynamicWindow", "Struct DynamicWindow")
f.struct_DynamicWindow_rhost = ProtoField.uint16("asterix_family.struct.DynamicWindow.rhost", "rhost", base.DEC)
f.struct_DynamicWindow_rhoend = ProtoField.uint16("asterix_family.struct.DynamicWindow.rhoend", "rhoend", base.DEC)
f.struct_DynamicWindow_thetast = ProtoField.uint16("asterix_family.struct.DynamicWindow.thetast", "thetast", base.DEC)
f.struct_DynamicWindow_thetaend = ProtoField.uint16("asterix_family.struct.DynamicWindow.thetaend", "thetaend", base.DEC)
f.struct_PolarWindow = ProtoField.none("asterix_family.struct.PolarWindow", "Struct PolarWindow")
f.struct_PolarWindow_rhost = ProtoField.uint16("asterix_family.struct.PolarWindow.rhost", "rhost", base.DEC)
f.struct_PolarWindow_rhoend = ProtoField.uint16("asterix_family.struct.PolarWindow.rhoend", "rhoend", base.DEC)
f.struct_PolarWindow_thetast = ProtoField.uint16("asterix_family.struct.PolarWindow.thetast", "thetast", base.DEC)
f.struct_PolarWindow_thetaend = ProtoField.uint16("asterix_family.struct.PolarWindow.thetaend", "thetaend", base.DEC)
f.struct_Position3D = ProtoField.none("asterix_family.struct.Position3D", "Struct Position3D")
f.struct_Position3D_hgt = ProtoField.int16("asterix_family.struct.Position3D.hgt", "hgt", base.DEC)
f.struct_Position3D_lat = ProtoField.uint32("asterix_family.struct.Position3D.lat", "lat", base.DEC)
f.struct_Position3D_lon = ProtoField.uint32("asterix_family.struct.Position3D.lon", "lon", base.DEC)

asterix_family_proto.fields = {
  f.transport_category,
  f.transport_length,
  f.msg_Cat001Record,
  f.msg_Cat001Record_fspec,
  f.msg_Cat001Record_i001_010,
  f.msg_Cat001Record_i001_020,
  f.msg_Cat001Record_i001_040,
  f.msg_Cat001Record_i001_042,
  f.msg_Cat001Record_i001_030,
  f.msg_Cat001Record_i001_050,
  f.msg_Cat001Record_i001_070,
  f.msg_Cat001Record_i001_080,
  f.msg_Cat001Record_i001_090,
  f.msg_Cat001Record_i001_100,
  f.msg_Cat001Record_i001_120,
  f.msg_Cat001Record_i001_130,
  f.msg_Cat001Record_i001_131,
  f.msg_Cat001Record_i001_141,
  f.msg_Cat001Record_i001_161,
  f.msg_Cat001Record_i001_170,
  f.msg_Cat001Record_i001_200,
  f.msg_Cat001Record_i001_210,
  f.msg_Cat002Record,
  f.msg_Cat002Record_fspec,
  f.msg_Cat002Record_i002_010,
  f.msg_Cat002Record_i002_000,
  f.msg_Cat002Record_i002_020,
  f.msg_Cat002Record_i002_030,
  f.msg_Cat002Record_i002_041,
  f.msg_Cat002Record_i002_050,
  f.msg_Cat002Record_i002_060,
  f.msg_Cat002Record_i002_070,
  f.msg_Cat002Record_i002_100,
  f.msg_Cat002Record_i002_090,
  f.msg_Cat002Record_i002_080,
  f.msg_Cat034Record,
  f.msg_Cat034Record_fspec,
  f.msg_Cat034Record_i034_010,
  f.msg_Cat034Record_i034_000,
  f.msg_Cat034Record_i034_030,
  f.msg_Cat034Record_i034_020,
  f.msg_Cat034Record_i034_041,
  f.msg_Cat034Record_i034_050,
  f.msg_Cat034Record_i034_060,
  f.msg_Cat034Record_i034_070,
  f.msg_Cat034Record_i034_100,
  f.msg_Cat034Record_i034_110,
  f.msg_Cat034Record_i034_120,
  f.msg_Cat034Record_i034_090,
  f.msg_Cat048Record,
  f.msg_Cat048Record_fspec,
  f.msg_Cat048Record_i048_010,
  f.msg_Cat048Record_i048_140,
  f.msg_Cat048Record_i048_020,
  f.msg_Cat048Record_i048_040,
  f.msg_Cat048Record_i048_070,
  f.msg_Cat048Record_i048_090,
  f.msg_Cat048Record_i048_130,
  f.msg_Cat048Record_i048_220,
  f.msg_Cat048Record_i048_240,
  f.msg_Cat048Record_i048_250,
  f.msg_Cat048Record_i048_161,
  f.msg_Cat048Record_i048_042,
  f.msg_Cat048Record_i048_200,
  f.msg_Cat048Record_i048_170,
  f.msg_Cat048Record_i048_210,
  f.msg_Cat048Record_i048_030,
  f.msg_Cat048Record_i048_080,
  f.msg_Cat048Record_i048_100,
  f.msg_Cat048Record_i048_110,
  f.msg_Cat048Record_i048_120,
  f.msg_Cat048Record_i048_230,
  f.msg_Cat048Record_i048_260,
  f.msg_Cat048Record_i048_055,
  f.msg_Cat048Record_i048_050,
  f.msg_Cat048Record_i048_065,
  f.msg_Cat048Record_i048_060,
  f.msg_Cat048Record_i048_sp,
  f.msg_Cat048Record_i048_re,
  f.msg_Cat240Record,
  f.msg_Cat240Record_fspec,
  f.msg_Cat240Record_i240_010,
  f.struct_DataSourceId,
  f.struct_DataSourceId_sac,
  f.struct_DataSourceId_sic,
  f.struct_TargetReportDescriptor001,
  f.struct_TargetReportDescriptor001_typ,
  f.struct_TargetReportDescriptor001_sim,
  f.struct_TargetReportDescriptor001_ssrpsr,
  f.struct_TargetReportDescriptor001_ant,
  f.struct_TargetReportDescriptor001_spi,
  f.struct_TargetReportDescriptor001_rab,
  f.struct_TargetReportDescriptor001_spare,
  f.struct_TargetReportDescriptor048,
  f.struct_TargetReportDescriptor048_typ,
  f.struct_TargetReportDescriptor048_sim,
  f.struct_TargetReportDescriptor048_rdp,
  f.struct_TargetReportDescriptor048_spi,
  f.struct_TargetReportDescriptor048_rab,
  f.struct_TargetReportDescriptor048_spare_fx,
  f.struct_TargetReportDescriptor048Ext,
  f.struct_TargetReportDescriptor048Ext_tst,
  f.struct_TargetReportDescriptor048Ext_err,
  f.struct_TargetReportDescriptor048Ext_xpp,
  f.struct_TargetReportDescriptor048Ext_me,
  f.struct_TargetReportDescriptor048Ext_mi,
  f.struct_TargetReportDescriptor048Ext_foefri,
  f.struct_TargetReportDescriptor048Ext_spare_fx2,
  f.struct_MeasuredPositionPolar,
  f.struct_MeasuredPositionPolar_rho,
  f.struct_MeasuredPositionPolar_theta,
  f.struct_CalculatedPositionCartesian,
  f.struct_CalculatedPositionCartesian_x,
  f.struct_CalculatedPositionCartesian_y,
  f.struct_Mode2Code,
  f.struct_Mode2Code_v,
  f.struct_Mode2Code_g,
  f.struct_Mode2Code_l,
  f.struct_Mode2Code_spare,
  f.struct_Mode2Code_mode2,
  f.struct_Mode1Code,
  f.struct_Mode1Code_v,
  f.struct_Mode1Code_g,
  f.struct_Mode1Code_l,
  f.struct_Mode1Code_mode1,
  f.struct_Mode3ACode,
  f.struct_Mode3ACode_v,
  f.struct_Mode3ACode_g,
  f.struct_Mode3ACode_l,
  f.struct_Mode3ACode_spare,
  f.struct_Mode3ACode_mode3a,
  f.struct_Mode2Confidence,
  f.struct_Mode2Confidence_spare,
  f.struct_Mode2Confidence_qa4,
  f.struct_Mode2Confidence_qa2,
  f.struct_Mode2Confidence_qa1,
  f.struct_Mode2Confidence_qb4,
  f.struct_Mode2Confidence_qb2,
  f.struct_Mode2Confidence_qb1,
  f.struct_Mode2Confidence_qc4,
  f.struct_Mode2Confidence_qc2,
  f.struct_Mode2Confidence_qc1,
  f.struct_Mode2Confidence_qd4,
  f.struct_Mode2Confidence_qd2,
  f.struct_Mode2Confidence_qd1,
  f.struct_Mode1Confidence,
  f.struct_Mode1Confidence_spare,
  f.struct_Mode1Confidence_qa4,
  f.struct_Mode1Confidence_qa2,
  f.struct_Mode1Confidence_qa1,
  f.struct_Mode1Confidence_qb2,
  f.struct_Mode1Confidence_qb1,
  f.struct_Mode3AConfidence,
  f.struct_Mode3AConfidence_spare,
  f.struct_Mode3AConfidence_qa4,
  f.struct_Mode3AConfidence_qa2,
  f.struct_Mode3AConfidence_qa1,
  f.struct_Mode3AConfidence_qb4,
  f.struct_Mode3AConfidence_qb2,
  f.struct_Mode3AConfidence_qb1,
  f.struct_Mode3AConfidence_qc4,
  f.struct_Mode3AConfidence_qc2,
  f.struct_Mode3AConfidence_qc1,
  f.struct_Mode3AConfidence_qd4,
  f.struct_Mode3AConfidence_qd2,
  f.struct_Mode3AConfidence_qd1,
  f.struct_FlightLevel,
  f.struct_FlightLevel_v,
  f.struct_FlightLevel_g,
  f.struct_FlightLevel_fl,
  f.struct_ModeCCodeConfidence,
  f.struct_ModeCCodeConfidence_v,
  f.struct_ModeCCodeConfidence_g,
  f.struct_ModeCCodeConfidence_spare,
  f.struct_ModeCCodeConfidence_modec,
  f.struct_ModeCCodeConfidence_spare2,
  f.struct_ModeCCodeConfidence_qc1,
  f.struct_ModeCCodeConfidence_qa1,
  f.struct_ModeCCodeConfidence_qc2,
  f.struct_ModeCCodeConfidence_qa2,
  f.struct_ModeCCodeConfidence_qc4,
  f.struct_ModeCCodeConfidence_qa4,
  f.struct_ModeCCodeConfidence_qb1,
  f.struct_ModeCCodeConfidence_qd1,
  f.struct_ModeCCodeConfidence_qb2,
  f.struct_ModeCCodeConfidence_qd2,
  f.struct_ModeCCodeConfidence_qb4,
  f.struct_ModeCCodeConfidence_qd4,
  f.struct_TimeOfDay24,
  f.struct_TimeOfDay24_tod,
  f.struct_TrackNumber,
  f.struct_TrackNumber_spare,
  f.struct_TrackNumber_trn,
  f.struct_TrackStatus001,
  f.struct_TrackStatus001_con,
  f.struct_TrackStatus001_rad,
  f.struct_TrackStatus001_man,
  f.struct_TrackStatus001_dou,
  f.struct_TrackStatus001_rdpc,
  f.struct_TrackStatus001_spare,
  f.struct_TrackStatus001_gho,
  f.struct_TrackStatus001_spare2,
  f.struct_TrackStatus048,
  f.struct_TrackStatus048_cnf,
  f.struct_TrackStatus048_rad,
  f.struct_TrackStatus048_dou,
  f.struct_TrackStatus048_mah,
  f.struct_TrackStatus048_cdm,
  f.struct_TrackStatus048_fspec,
  f.struct_TrackStatus048_ext,
  f.struct_TrackStatus048Ext,
  f.struct_TrackStatus048Ext_tre,
  f.struct_TrackStatus048Ext_gho,
  f.struct_TrackStatus048Ext_sup,
  f.struct_TrackStatus048Ext_tcc,
  f.struct_TrackStatus048Ext_spare,
  f.struct_TrackStatus048Ext_spare2,
  f.struct_TrackVelocityPolar,
  f.struct_TrackVelocityPolar_gsp,
  f.struct_TrackVelocityPolar_hdg,
  f.struct_TrackQuality,
  f.struct_TrackQuality_sigx,
  f.struct_TrackQuality_sigy,
  f.struct_AircraftAddress048,
  f.struct_AircraftAddress048_addr,
  f.struct_CommunicationsAcas048,
  f.struct_CommunicationsAcas048_com,
  f.struct_CommunicationsAcas048_stat,
  f.struct_CommunicationsAcas048_si,
  f.struct_CommunicationsAcas048_mssc,
  f.struct_CommunicationsAcas048_spare,
  f.struct_CommunicationsAcas048_arc,
  f.struct_CommunicationsAcas048_aic,
  f.struct_CommunicationsAcas048_b1a,
  f.struct_CommunicationsAcas048_b1b,
  f.struct_CommunicationsAcas048_spare2,
  f.struct_AircraftIdentification048,
  f.struct_AircraftIdentification048_c,
  f.struct_AircraftIdentification048_c2,
  f.struct_AircraftIdentification048_c3,
  f.struct_AircraftIdentification048_c4,
  f.struct_AircraftIdentification048_c5,
  f.struct_AircraftIdentification048_c6,
  f.struct_AircraftIdentification048_c7,
  f.struct_AircraftIdentification048_c8,
  f.struct_BdsRegisterEntry,
  f.struct_BdsRegisterEntry_mbdata,
  f.struct_BdsRegisterEntry_mbdata2,
  f.struct_BdsRegisterEntry_mbdata3,
  f.struct_BdsRegisterEntry_mbdata4,
  f.struct_BdsRegisterEntry_mbdata5,
  f.struct_BdsRegisterEntry_mbdata6,
  f.struct_BdsRegisterEntry_mbdata7,
  f.struct_BdsRegisterEntry_bds1,
  f.struct_BdsRegisterEntry_bds2,
  f.struct_DopplerSpeed,
  f.struct_DopplerSpeed_d,
  f.struct_DopplerSpeed_spare,
  f.struct_DopplerSpeed_cal,
  f.struct_RadarPlotCharacteristics,
  f.struct_RadarPlotCharacteristics_fspec,
  f.struct_RadarPlotCharacteristics_srl,
  f.struct_RadarPlotCharacteristics_srr,
  f.struct_RadarPlotCharacteristics_sam,
  f.struct_RadarPlotCharacteristics_prl,
  f.struct_RadarPlotCharacteristics_pam,
  f.struct_RadarPlotCharacteristics_rpd,
  f.struct_RadarPlotCharacteristics_apd,
  f.struct_Com034,
  f.struct_Com034_nogo,
  f.struct_Com034_rdpc,
  f.struct_Com034_rdpr,
  f.struct_Com034_ovlrdp,
  f.struct_Com034_ovlxmt,
  f.struct_Com034_msc,
  f.struct_Com034_tsv,
  f.struct_Com034_spare,
  f.struct_Psr034,
  f.struct_Psr034_status,
  f.struct_Ssr034,
  f.struct_Ssr034_status,
  f.struct_Mds034,
  f.struct_Mds034_ant,
  f.struct_Mds034_chab,
  f.struct_Mds034_ovlsur,
  f.struct_Mds034_msc,
  f.struct_Mds034_scf,
  f.struct_Mds034_dlf,
  f.struct_Mds034_ovlscf,
  f.struct_Mds034_ovldlf,
  f.struct_Mds034_spare,
  f.struct_SystemConfig034,
  f.struct_SystemConfig034_fspec,
  f.struct_SystemConfig034_com,
  f.struct_SystemConfig034_psr,
  f.struct_SystemConfig034_ssr,
  f.struct_SystemConfig034_mds,
  f.struct_RdpXmt034,
  f.struct_RdpXmt034_spare,
  f.struct_RdpXmt034_redrdp,
  f.struct_RdpXmt034_redxmt,
  f.struct_RdpXmt034_spare2,
  f.struct_SystemProcessingMode034,
  f.struct_SystemProcessingMode034_fspec,
  f.struct_SystemProcessingMode034_rdpxmt,
  f.struct_MessageCountEntry,
  f.struct_MessageCountEntry_typ,
  f.struct_MessageCountEntry_count,
  f.struct_CollimationError,
  f.struct_CollimationError_rng,
  f.struct_CollimationError_azm,
  f.struct_PlotCountValue,
  f.struct_PlotCountValue_typ,
  f.struct_PlotCountValue_count,
  f.struct_DynamicWindow,
  f.struct_DynamicWindow_rhost,
  f.struct_DynamicWindow_rhoend,
  f.struct_DynamicWindow_thetast,
  f.struct_DynamicWindow_thetaend,
  f.struct_PolarWindow,
  f.struct_PolarWindow_rhost,
  f.struct_PolarWindow_rhoend,
  f.struct_PolarWindow_thetast,
  f.struct_PolarWindow_thetaend,
  f.struct_Position3D,
  f.struct_Position3D_hgt,
  f.struct_Position3D_lat,
  f.struct_Position3D_lon,
}

-- Main Dissector
function asterix_family_proto.dissector(buffer, pinfo, tree)
  pinfo.cols.protocol = "asterix_family"
  local subtree = tree:add(asterix_family_proto, buffer(), "asterix_family Protocol Data")
  local offset = 0
  local len = buffer:len()

  -- TODO: Implemented actual decoding logic here, interpreting the AST
  -- Currently displaying an empty tree for the plugin skeleton structure
end

-- Register the dissector to a default UDP port (change as needed)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(12345, asterix_family_proto)
