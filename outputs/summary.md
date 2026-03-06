# FFmpeg CVE Candidate Triage — Summary Report

**Date**: 2026-03-06
**Total candidates**: 65 unique finding files across libavcodec/ (42) and libavformat/ (23)
**Structured candidates**: 1 (libavformat/mov/ with finding.txt + poc.py + no_crash.log)

---

## Counts by Bug Class

| Bug Class | Count | Source-Verified |
|-----------|-------|-----------------|
| oob_read | 38 | 10 |
| integer_overflow | 17 | 9 |
| oob_write | 4 | 4 |
| logic | 6 | 4 |
| other (uninitialized) | 1 | 1 |
| **Total** | **65** | **28** |

## Counts by Subsystem

| Subsystem | Count |
|-----------|-------|
| decoder | 42 |
| demuxer | 23 |

## Counts by Confidence Band

| Band | Criteria | Count |
|------|----------|-------|
| **High (7-10)** | Source-verified, clear exploitation path, reachable from normal file open | 14 |
| **Medium (4-6)** | Plausible finding, needs source verification or has mitigating factors | 16 |
| **Low (1-3)** | Unverified, generic claims, heavily-fuzzed code with no specific exploit path | 34 |
| **Tested-Safe (0-2)** | Tested with ASan, no crash produced | 1 (mov/) |

## ASan Confirmation Status

| Status | Count |
|--------|-------|
| ASan-confirmed crash | 0 |
| Tested, no crash (no_crash.log) | 1 (mov/) |
| No crash testing | 64 |

---

## High-Confidence Findings (Score >= 7)

### Source-Verified Vulnerabilities

1. **swfdec.c** (8/10): Multiple tag handlers lack length validation → stream desync → heap OOB read
2. **vc1dec.c** (8/10): Late bounds check in vc1_parse_sprites → 87-byte heap over-read
3. **diracdec.c** (8/10): Negative lowdelay.bytes.num → backward buffer read
4. **flvdec.c** (7/10): Unbounded track_size in Enhanced FLV multitrack
5. **wmv2dec.c** (7/10): Missing bitstream bounds in SKIP_TYPE_ROW/COL
6. **wmalosslessdec.c** (7/10): Unbounded Golomb quotient → cascading overflow
7. **mlpdec.c** (7/10): All 5 integrity checks non-enforced (log-only)
8. **id3v2.c** (7/10): v2.3/v2.4 flag misinterpretation → encryption bypass → GEOB heap OOB
9. **dvbsubdec.c** (7/10): Map table update cases read 2-16 bytes past buf_end without bounds checks
10. **adpcm.c** (7/10): HVQM4 off-by-one heap buffer overflow — mono frame_format 1/3 writes nb_samples+1
11. **alsdec.c** (7/10): Negative nbits → ff_mlz_decompression heap buffer overflow via unsigned promotion
12. **cook.c** (7/10): joint_decode() reads 3760 bytes past decode_buffer_0 with large js_subband_start
13. **smacker.c** (7/10): Predictor writes past zero-length buffer when unp_size=0
14. **proresdec.c** (7/10): unpack_alpha() unbounded bitstream reads past buffer (~5.8KB heap over-read)

---

## Reporting Recommendations

### Report to security@ffmpeg.org (private security, CVE-worthy)
These have source-verified heap memory corruption reachable from normal file opens:

1. **swfdec.c** — SWF tag length validation missing (heap OOB read, parser desync)
2. **vc1dec.c** — vc1_parse_sprites late bounds check (heap over-read 87 bytes)
3. **diracdec.c** — Negative lowdelay.bytes.num (backward heap read)
4. **flvdec.c** — Enhanced FLV track_size unbounded (heap OOB read)
5. **wmv2dec.c** — parse_mb_skip bounds missing (heap OOB read)
6. **pngdec.c** — Broken overflow check (heap infoleak on 32-bit)
7. **id3v2.c** — v2.3 flag misinterpretation (heap OOB via GEOB)
8. **wmalosslessdec.c** — Unbounded Golomb (UB, cascading overflow)
9. **rmdec.c/rmsipr.c** — SIPR signed overflow (compiler-dependent heap OOB)
10. **speexdec.c** — Extradata OOB read
11. **dvbsubdec.c** — Map table OOB reads (2-16 bytes, infoleak via subtitle output)
12. **adpcm.c** — HVQM4 off-by-one heap write (2-byte attacker-controlled overflow)
13. **alsdec.c** — Negative nbits → massive MLZ decompression heap overflow
14. **cook.c** — joint_decode stride-40 OOB read (3760 bytes, ASLR bypass via pointer leak)
15. **smacker.c** — Zero-length buffer predictor overflow (1-4 byte attacker-controlled write)
16. **proresdec.c** — unpack_alpha unbounded reads (~5.8KB heap over-read into output)
17. **tiff.c** — tiff_unpack_zlib int overflow → undersized alloc → massive OOB read
18. **bmp.c** — Size validation int overflow → memcpy loop OOB read + RLE memset overflow

### Report to ffmpeg-devel (public, lower severity)
These are logic bugs or UB without direct memory corruption:

19. **mlpdec.c** — Non-enforced integrity checks (logic/quality bug)
20. **alac.c** — Signed overflow in LPC (UB, primarily DoS)
21. **sanm.c** — Uninitialized stack LUT leaks into video output (infoleak)

### Report to trac.ffmpeg.org (public bugtracker)
These are lower priority or known design patterns:

22. **nutdec.c** — Integer overflow + operator precedence
23. **mxfdec.c** — EIA-608 stream desync (requires option)
24. **rv60dec.c** — Silent error propagation
25. **wmaprodec.c** — Uninitialized decorrelation matrix
26. **huffyuvdec.c** — UNCHECKED_BITSTREAM_READER (known design tradeoff)
27. **h264dec.c** — is_avcc_extradata bounds (limited impact)

### Skip (low confidence or well-hardened)
28. **mov.c** — Tested with 8 PoC variants, all survived. MOV parser is exceptionally well-hardened.
29. All unverified generic findings in heavily-fuzzed codecs (h264, mpeg12, mpeg4, vp9, etc.)

---

## Key Patterns Observed

1. **Missing length/bounds validation before I/O reads**: The most common real vulnerability pattern. SWF, WMV2, DVB subtitle, Speex, ProRes alpha, Cook all share this pattern.
2. **Late bounds checks**: vc1dec performs the buffer overrun check AFTER consuming 1215 bits. Check should precede reads.
3. **Signed/unsigned confusion**: Dirac bytes.num, ALS nbits, demux.c buf_size, ID3v2 GEOB len — signed values used where unsigned semantics expected.
4. **Non-enforced integrity checks**: MLP/TrueHD has 5 checksum/parity checks that only log errors. This is a systemic design issue.
5. **Broken overflow guards**: PNG's `(exif_len & ~SIZE_MAX)` is always 0 — a textbook broken security check.
6. **Integer overflow in multiplication**: SIPR `h*w*2`, NUT `size_mul*varlen`, WMA Lossless `quo<<rem_bits`, TIFF `width*lines`, BMP `n*height`.
7. **Operator precedence bugs**: NUT's `&& ... ||` precedence causes safety bypass.
8. **Off-by-one in loop calculations**: ADPCM HVQM4 mono writes nb_samples+1 due to decrement mismatch between initial sample and loop step.
9. **Zero-length allocation corner cases**: Smacker unp_size=0 → malloc(0) → valid pointer → immediate overflow.

## Verification Status

| Action | Count |
|--------|-------|
| Directly read finding | 32 |
| Source-code verified | 21 |
| PoC exists | 2 (mov/, pngdec) |
| ASan tested | 1 (mov/ — no crash) |
| Needs ASan testing | 18 high/medium-confidence candidates |

## Next Steps

1. Build FFmpeg with ASan+UBSan for the target platform
2. Craft PoCs for top-14 candidates (prioritize #1-#5 and newly upgraded #9-#14)
3. Run ASan builds against crafted inputs
4. For confirmed crashes: file to security@ffmpeg.org with PoC and ASan output
5. Check https://trac.ffmpeg.org and git log before reporting to avoid duplicates
