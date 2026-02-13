# CAT034 failing message: our decoder vs Wireshark (frame 17)

Side-by-side view of one failing CAT034 block to see the real decoding error (under-consumption).

**Frame:** packet 17  
**Block:** CAT034, length 28 (3-byte transport + 25-byte body)  
**Our behaviour:** First record decoded as bytes [3–24] (21 bytes body), then we attempt a second record at [24–28] and get REMOVED (`field i034_000: IO: failed to fill whole buffer`).  
**Wireshark:** Single ASTERIX message, **length 25** → one record of **25 bytes** (body bytes 0–24 inclusive).

**Conclusion:** We under-consume by **4 bytes** on the first record. The bytes at body offsets 21–24 belong to the first record per Wireshark; we treat them as the start of a second record and fail.

---

## Raw block bytes

Block length 28. Our dump shows "offset 0 = first byte of record" (i.e. after 3-byte transport). So block bytes 3–27 = body 0–24 (25 bytes).

```
  offset   0: ef 10 19 0c 01 35 6e 49 02 79 84 44 4e 00 84 00
  offset  16: 00 03 0c 1e fb dd 0b aa a2
```

Body indices: 0–15 (line 1), 16–24 (line 2, 9 bytes). So body has 25 bytes. We consume 0..21 → **4 bytes not consumed**: body 21,22,23,24 = `dd 0b aa a2`. Those 4 bytes are still part of record 1 per Wireshark; we wrongly treat them as the start of a second record (at block index 24).

---

## Our decoder (decode_pcap --dump=- --frame=17)

```
=== packet 17  udp_offset 0  block cat 34  len 28 ===
  data (offset 0 = first byte of record, after 3-byte transport):
  offset   0: ef 10 19 0c 01 35 6e 49 02 79 84 44 4e 00 84 00
  offset  16: 00 03 0c 1e fb dd 0b aa a2
  record bytes [3-24]  DECODED Cat034Record
    fspec: hex(ef 10)
    i034_000: 1
    i034_010: struct {
        sac: 25
        sic: 12
      }
    i034_020: []
    i034_030: struct {
        tod: 3501641
      }
    i034_041: 633
    i034_050: struct {
        com: struct {
        msc: 0
        nogo: 0
        ovlrdp: 0
        ovlxmt: 0
        rdpc: 0
        rdpr: 1
        spare: <padding>
        tsv: 1
        }
        fspec: hex(84)
        mds: []
        psr: []
        ssr: []
      }
    i034_060: struct {
        fspec: hex(4e)
        rdpxmt: []
      }
    i034_070: []
    i034_090: []
    i034_100: []
    i034_110: []
    i034_120: struct {
        hgt: 132
        lat: 3
        lon: 794363
      }
  record bytes [24-28]  REMOVED: Validation: field i034_000: IO: failed to fill whole buffer
```

---

## Wireshark / tshark (frame 17, -O asterix)

```
Frame 17: Packet, 70 bytes on wire (560 bits), 70 bytes captured (560 bits)
Ethernet II, Src: Cisco_fe:5f:c2 (bc:16:65:fe:5f:c2), Dst: IPv4mcast_02:01:0c (01:00:5e:02:01:0c)
Internet Protocol Version 4, Src: 10.17.58.184, Dst: 232.2.1.12
User Datagram Protocol, Src Port: 21144, Dst Port: 22112
ASTERIX packet, Category 034
    Category: 34
    Length: 28
    Asterix message, #01, length: 25
        FSPEC
        010, Data Source Identifier
            SAC, System Area Code: 0x19 (25)
            SIC, System Identification Code: 0x0c (12)
        000, Message Type
            Message Type: North marker message (1)
        030, Time of Day
            Time of Day, [s]: 27356.5703125
        041, Antenna Rotation Speed
            Antenna Rotation Speed, [s]: 4.9453125
        050, System Configuration and Status
            FSPEC
            COM, Common Part
                0... .... = NOGO, Operational Release Status of the System: System is released for operational use (0)
                .1.. .... = RDPC, Radar Data Processor Chain Selection Status: RDPC-2 selected (1)
                ..0. .... = RDPR, Event to Signal a Reset/restart of the Selected Radar Data Processor Chain, I.e. Expect a New Assignment of Track Numbers: Default situation (0)
                ...0 .... = OVLRDP, Radar Data Processor Overload Indicator: Default, no overload (0)
                .... 0... = OVLXMT, Transmission Subsystem Overload Status: Default, no overload (0)
                .... .1.. = MSC, Monitoring System Connected Status: Monitoring system disconnected (1)
                .... ..0. = TSV, Time Source Validity: Valid (0)
            MDS, Specific Status Information for a Mode S Sensor
                0... .... = ANT, Selected Antenna: Antenna 1 (0)
                .10. .... = CHAB, Channel A/B Selection Status: Channel B only selected (2)
                ...0 .... = OVLSUR, Overload Condition: No overload (0)
                .... 1... = MSC, Monitoring System Connected Status:: Monitoring system disconnected (1)
                .... .1.. = SCF, Channel A/B Selection Status for Surveillance Co-ordination Function: Channel B in use (1)
                .... ..1. = DLF, Channel A/B Selection Status for Data Link Function: Channel B in use (1)
                .... ...0 = OVLSCF, Overload in Surveillance Co-ordination Function: No overload (0)
                0... .... = OVLDLF, Overload in Data Link Function: No overload (0)
        060, System Processing Mode
            FSPEC
            COM, Common Part
                .000 .... = REDRDP, Reduction Steps in Use for An Overload of the RDP: No reduction active (0)
                .... 000. = REDXMT, Reduction Steps in Use for An Overload of the Transmission Subsystem: No reduction active (0)
            MDS, Specific Processing Mode Information for a Mode S Sensor
                000. .... = REDRAD, Reduction Steps in Use as Result of An Overload Within the Mode S Subsystem: No reduction active (0)
                ...0 .... = CLU, Cluster State: Autonomous (0)
        120, 3D-Position Of Data Source
            HGT, Height of Data Source, [m]: 780
            LAT, Latitude, [°]: 43.57102632522583
            LON, Longitude, [°]: 16.4060640335083
```

---

## Summary

| Aspect | Our decoder | Wireshark |
|--------|-------------|-----------|
| Record 1 extent | [3–24) = 21 bytes body | length 25 → 25 bytes body |
| Record 2 | Attempted [24–28), REMOVED (i034_000 IO) | No second record |
| Under-consumption | 4 bytes (body 21–24 not consumed in record 1) | — |

The last field we decode is **I034/120 (Position3D)**. So the missing 4 bytes are likely either part of Position3D encoding (e.g. different sizing or an extension byte in the spec) or padding/extension after it. Next step: check EUROCONTROL CAT034 I034/120 and record termination rules.
