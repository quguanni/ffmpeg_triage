# Top 10 FFmpeg CVE Candidates — Ranked by Exploitability & Confidence

## Ranking Criteria
1. Source-verified vulnerability (code confirmed in FFmpeg source)
2. Higher poc_trigger_likelihood
3. Higher impact (heap_corruption/rce > dos > infoleak)
4. Lower exploitability cost (moderate > difficult)
5. Weaker safety counterarguments

---

## #1: SWF Demuxer — Tag Length Validation Missing (Stream Desync → Heap OOB Read)

- **Path**: `libavformat/swfdec_c.txt`
- **FFmpeg file**: `libavformat/swfdec.c`
- **ASan confirmed**: No (no crash.log), but source-verified
- **Crash type**: heap-buffer-overflow (predicted)
- **Score**: 8/10

**Justification**: Multiple SWF tag handlers (TAG_VIDEOSTREAM, TAG_STREAMHEAD, TAG_DEFINESOUND, TAG_DEFINEBITSLOSSLESS, TAG_STREAMBLOCK) read bytes from the stream WITHOUT first validating that tag length (`len`) is sufficient. When a short tag is provided, reads spill past the tag boundary, and the `skip:` label clamps negative `len` to 0 without compensating. The for(;;) loop continues parsing from a desynchronized position, giving the attacker control over subsequent tag headers and lengths. Secondary bug: `buf[3]<<24` in DEFINEBITSLOSSLESS2 is both wrong index (should be `buf[4*i+3]`) and signed overflow UB.

**Minimal repro**:
1. `cp ./ffmpeg_CVE_candidate/libavformat/swfdec_c.txt ./scratch/`
2. Write SWF with TAG_VIDEOSTREAM len=4 (handler reads 10), followed by crafted TAG_JPEG2 bytes
3. `~/ffmpeg/ffmpeg -i /tmp/poc_swf.swf -f null - 2>&1 | grep -i 'sanitizer\|overflow'`

**Report to**: security@ffmpeg.org

---

## #2: VC-1 Decoder — Late Bounds Check in vc1_parse_sprites() (Heap Over-Read)

- **Path**: `libavcodec/vc1dec_c.txt`
- **FFmpeg file**: `libavcodec/vc1dec.c`
- **ASan confirmed**: No
- **Crash type**: heap-buffer-overflow (predicted, up to 87 bytes past padding)
- **Score**: 8/10

**Justification**: `vc1_parse_sprites()` reads up to 1215 bits (152 bytes) of sprite transform and effect data from the bitstream BEFORE performing the buffer overrun check at line 199. With AV_INPUT_BUFFER_PADDING_SIZE = 64 bytes, a 1-byte WMV3IMAGE packet causes an 87-byte heap over-read. The `goto image` path at line 998 directly enters sprite parsing, bypassing frame decode.

**Minimal repro**:
1. Craft WMV3IMAGE file with valid sequence header, 1-byte frame packet with bits triggering two_sprites=1
2. `~/ffmpeg/ffmpeg -i /tmp/poc_wmv3image.wmv -f null - 2>&1`
3. Check ASan output for heap-buffer-overflow in `get_bits_long` / `get_fp_val`

**Report to**: security@ffmpeg.org

---

## #3: Dirac Decoder — Negative lowdelay.bytes.num Causes Backward Buffer Read

- **Path**: `libavcodec/diracdec_c.txt`
- **FFmpeg file**: `libavcodec/diracdec.c`
- **ASan confirmed**: No
- **Crash type**: heap-buffer-overflow (predicted, backward read)
- **Score**: 8/10

**Justification**: `get_interleaved_ue_golomb()` returns unsigned int, but `lowdelay.bytes.num` is signed int (AVRational). Values > INT_MAX wrap negative. Only `bytes.den` is validated for <= 0; `bytes.num` is not checked. In `decode_lowdelay()`, negative `bytes` passes both safety checks (`bytes >= INT_MAX` and `bytes*8 > bufsize`), then `buf += bytes` moves the pointer BACKWARD before the buffer. Each of num_x * num_y slices reads heap memory preceding the input buffer.

**Minimal repro**:
1. Craft Dirac Low Delay bitstream with `lowdelay.bytes.num` = 0x80000000 (golomb-coded)
2. Set `lowdelay.bytes.den` = 1
3. `~/ffmpeg/ffmpeg -i /tmp/poc_dirac.raw -f null - 2>&1`

**Report to**: security@ffmpeg.org

---

## #4: FLV Demuxer — Unbounded track_size in Enhanced Multitrack Parsing

- **Path**: `libavformat/flvdec_c.txt`
- **FFmpeg file**: `libavformat/flvdec.c`
- **ASan confirmed**: No
- **Crash type**: heap-buffer-overflow (predicted)
- **Score**: 7/10

**Justification**: Enhanced FLV multitrack parsing reads `track_size` from `avio_rb24()` (up to 16MB) without validating against remaining tag `size`. The bounds check at line 1834 only verifies `size > 0 && track_size >= 0`, NOT `track_size <= size`. `av_get_packet()` then reads `track_size` bytes past the tag boundary. The for(;;) loop continues with deeply negative `size`, consuming subsequent tags as track data.

**Minimal repro**:
1. Craft FLV with Enhanced FLV multitrack header, small tag size (20), large track_size (0xFFFF)
2. `~/ffmpeg/ffmpeg -i /tmp/poc_flv.flv -f null - 2>&1`
3. Check for OOB in av_get_packet

**Report to**: security@ffmpeg.org

---

## #5: WMV2 Decoder — parse_mb_skip Missing Bitstream Bounds Checks

- **Path**: `libavcodec/wmv2dec_c.txt`
- **FFmpeg file**: `libavcodec/wmv2dec.c`
- **ASan confirmed**: No
- **Crash type**: heap-buffer-overflow (predicted)
- **Score**: 7/10

**Justification**: `SKIP_TYPE_ROW` and `SKIP_TYPE_COL` branches check only 1 bit availability before the outer loop, but the inner else-branches read `mb_width` or `mb_height` additional bits without bounds validation. For large frame dimensions (mb_width/height > 512), reads exceed the 64-byte padding region, accessing adjacent heap objects. Contrast with `SKIP_TYPE_MPEG` which correctly checks `mb_height * mb_width` bits upfront.

**Minimal repro**:
1. Craft WMV2 P-frame with SKIP_TYPE_ROW, large resolution, truncated bitstream
2. `~/ffmpeg/ffmpeg -i /tmp/poc_wmv2.wmv -f null - 2>&1`
3. Check ASan for OOB in parse_mb_skip

**Report to**: security@ffmpeg.org

---

## #6: PNG Decoder — Broken Overflow Check (exif_len & ~SIZE_MAX == always 0)

- **Path**: `libavcodec/pngdec_c.txt` + `libavcodec/pngdec_c_PoC.txt`
- **FFmpeg file**: `libavcodec/pngdec.c`
- **ASan confirmed**: No
- **Crash type**: heap-info-leak / allocation failure
- **Score**: 7/10 (6 on 64-bit, higher on 32-bit)

**Justification**: The overflow check `(exif_len & ~SIZE_MAX)` at line 561 is always 0 because `~SIZE_MAX = 0`. This makes the entire overflow guard a no-op. On 32-bit platforms, crafted `exif_len = 0x80000008` causes `2*exif_len` to wrap to 16, bypassing the bounds check. The resulting ~2GB allocation (if successful under overcommit) is filled with uninitialized heap data. PoC generator provided.

**Minimal repro**:
1. Extract Python from `pngdec_c_PoC.txt`, save to `./scratch/poc_png.py`
2. `python3 ./scratch/poc_png.py` → generates `poc_pngdec_overflow.png`
3. `~/ffmpeg/ffmpeg -i poc_pngdec_overflow.png -f null - 2>&1` (32-bit ASan build)

**Report to**: security@ffmpeg.org

---

## #7: ID3v2 Parser — v2.3/v2.4 Flag Misinterpretation (Encryption Bypass + GEOB Heap OOB)

- **Path**: `libavformat/id3v2_c.txt`
- **FFmpeg file**: `libavformat/id3v2.c`
- **ASan confirmed**: No
- **Crash type**: heap-buffer-overflow (predicted, via GEOB datasize)
- **Score**: 7/10

**Justification**: ID3v2 parser uses v2.4 flag constants (0x0004 for encryption) for v2.3 tags where encryption is 0x0040. Encrypted v2.3 frames bypass detection and are parsed as plaintext. In `read_geobtag`, `unsigned int len` assigned from negative `avio_read` wraps to ~3.75 billion, stored as `geob_data->datasize`, enabling massive heap over-read.

**Minimal repro**:
1. Craft MP3 with ID3v2.3 tag, encrypted GEOB frame (flag 0x0040)
2. `~/ffmpeg/ffmpeg -i /tmp/poc_id3v23.mp3 -f null - 2>&1`
3. Check ASan for OOB in GEOB metadata access

**Report to**: security@ffmpeg.org

---

## #8: WMA Lossless Decoder — Unbounded Golomb Quotient + Shift Overflow

- **Path**: `libavcodec/wmalosslessdec_c.txt`
- **FFmpeg file**: `libavcodec/wmalosslessdec.c`
- **ASan confirmed**: No
- **Crash type**: undefined behavior (signed overflow in revert_acfilter)
- **Score**: 7/10

**Justification**: `decode_channel_residues()` increments `quo` without bounds in a while loop, then at `quo >= 32` adds up to 2^32 more. The shift `(quo << rem_bits) + rem` overflows unsigned int. The ave_sum feedback loop amplifies overflow across iterations. Cascading through CDLMS, MCLMS, and AC filter stages, the signed int accumulation in `revert_acfilter` is undefined behavior per C standard.

**Minimal repro**:
1. Craft WMA Lossless stream with 32+ consecutive 1-bits in Golomb coding
2. Build with UBSan: `~/ffmpeg/ffmpeg -i /tmp/poc_wmalossless.wma -f null - 2>&1`
3. Check for signed-integer-overflow reports

**Report to**: security@ffmpeg.org

---

## #9: NUT Demuxer — Integer Overflow + Operator Precedence Bug

- **Path**: `libavformat/nutdec_c.txt`
- **FFmpeg file**: `libavformat/nutdec.c`
- **ASan confirmed**: No
- **Crash type**: dos / memory exhaustion
- **Score**: 6/10

**Justification**: Frame size computation `size += size_mul * ffio_read_varlen(bc)` truncates int64_t to int at line 1039. The safety check at lines 1064-1066 has an operator precedence bug: `!(NUT_PIPE) && size > max || pts_check` parses as `((!(NUT_PIPE) && size > max) || pts_check)`, meaning NUT_PIPE flag completely bypasses the size validation. Additionally, AV_PKT_DATA_PARAM_CHANGE side data allocation of 16 bytes with 4-12 bytes written leaks uninitialized heap memory.

**Minimal repro**:
1. Craft NUT file with NUT_PIPE flag, large varlen size, close PTS values
2. `~/ffmpeg/ffmpeg -i /tmp/poc_nut.nut -f null - 2>&1`
3. Check for memory exhaustion or OOB

**Report to**: security@ffmpeg.org

---

## #10: RM/SIPR Demuxer — Signed Integer Overflow in SIPR Reorder

- **Path**: `libavformat/rmdec_c.txt`
- **FFmpeg file**: `libavformat/rmsipr.c`, `libavformat/rmdec.c`
- **ASan confirmed**: No
- **Crash type**: heap-buffer-overflow (compiler-dependent)
- **Score**: 6/10

**Justification**: `ff_rm_reorder_sipr_data()` computes `bs = sub_packet_h * framesize * 2 / 96` using signed int multiplication. The validation at rmdec.c line 300 checks `h * w <= INT_MAX` (via uint64_t cast) but does NOT check `h * w * 2 <= INT_MAX`. When `h*w > INT_MAX/2`, the `*2` overflows — this is undefined behavior. Under aggressive optimization (-O2), the compiler may produce a large positive `bs`, causing `buf[bs*95/2]` to access far past the allocated buffer.

**Minimal repro**:
1. Craft RM file with SIPR codec, sub_packet_h=46340, audio_framesize=46340
2. Build with UBSan/ASan: `~/ffmpeg/ffmpeg -i /tmp/poc_sipr.rm -f null - 2>&1`
3. Check for signed-integer-overflow or heap-buffer-overflow

**Report to**: security@ffmpeg.org

---

## Honorable Mentions (11-20)

| Rank | Candidate | Bug Class | Score | Reason |
|------|-----------|-----------|-------|--------|
| 11 | DVB subtitle map table | oob_read | 7/10 | **UPGRADED**: 2-16 bytes read past buf_end, heap data leaks into subtitle bitmap output |
| 12 | ADPCM HVQM4 off-by-one | oob_write | 7/10 | **NEW**: Mono frame_format 1/3 writes nb_samples+1, 2-byte attacker-controlled heap overflow |
| 13 | ALS negative nbits | oob_write | 7/10 | **NEW**: Negative nbits → ff_mlz_decompression interprets as ~2^64, massive heap overflow |
| 14 | Cook joint_decode OOB | oob_read | 7/10 | **NEW**: js_subband_start >= 27 reads 3760 bytes past buffer, leaks struct pointers (ASLR bypass) |
| 15 | Smacker predictor overflow | oob_write | 7/10 | **NEW**: unp_size=0 → malloc(0) → 1-4 byte attacker-controlled heap write |
| 16 | ProRes alpha OOB | oob_read | 7/10 | **NEW**: unpack_alpha() unbounded reads ~5.8KB past buffer into output frame |
| 17 | Speex extradata OOB | oob_read | 6/10 | av_strnstr + fixed offset reads past buffer |
| 18 | Vorbis residue begin/end | oob_write | 6/10 | 24-bit values not validated against blocksize |
| 19 | TIFF zlib int overflow | integer_overflow | 6/10 | **NEW**: width*lines int overflow → undersized alloc → massive OOB read (LZMA path has correct fix) |
| 20 | BMP size validation overflow | integer_overflow | 6/10 | **NEW**: n*height int overflow wraps negative, bypasses size check → memcpy OOB |
| 21 | ALAC LPC signed overflow | integer_overflow | 6/10 | UB in accumulation, feedback loop |
| 22 | MLP/TrueHD non-enforced checksums | logic | 7/10 | All 5 integrity checks are log-only |
| 23 | demux.c probe_codec overflow | integer_overflow | 5/10 | Primarily 32-bit impact |
