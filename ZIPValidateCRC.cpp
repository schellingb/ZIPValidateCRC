//--------------------------------------------//
// ZIPValidateCRC                             //
// License: Public Domain (www.unlicense.org) //
//--------------------------------------------//

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <vector>

#if !defined(_MSC_VER) || _MSC_VER >= 1600
#include <stdint.h>
#else
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef signed short int16_t;
typedef unsigned int uint32_t;
typedef signed int int32_t;
typedef unsigned __int64 uint64_t;
#endif

// Use 64-bit fseek and ftell
#if defined(_MSC_VER) && _MSC_VER >= 1400 // VC2005 and up have a special 64-bit fseek
#define fseek_wrap(fp, offset, whence) _fseeki64(fp, (__int64)offset, whence)
#define ftell_wrap(fp) _ftelli64(fp)
#elif defined(HAVE_64BIT_OFFSETS) || (defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE - 0) >= 200112) || (defined(__POSIX_VISIBLE) && __POSIX_VISIBLE >= 200112) || (defined(_POSIX_VERSION) && _POSIX_VERSION >= 200112) || __USE_LARGEFILE || (defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64)
#define fseek_wrap(fp, offset, whence) fseeko(fp, (off_t)offset, whence)
#define ftell_wrap(fp) ftello(fp)
#else
#define fseek_wrap(fp, offset, whence) fseek(fp, (long)offset, whence)
#define ftell_wrap(fp) ftell(fp)
#endif

static uint32_t CRC32(const void* data, size_t data_size)
{
	// A compact CCITT crc16 and crc32 C implementation that balances processor cache usage against speed
	// By Karl Malbrain - http://www.geocities.ws/malbrain/
	static const uint32_t s_crc32[16] = { 0, 0x1db71064, 0x3b6e20c8, 0x26d930ac, 0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c, 0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c, 0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c };
	uint32_t crcu32 = (uint32_t)~(uint32_t)0;
	for (uint8_t b, *p = (uint8_t*)data;data_size--;) { b = *p++; crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b & 0xF)]; crcu32 = (crcu32 >> 4) ^ s_crc32[(crcu32 & 0xF) ^ (b >> 4)]; }
	return ~crcu32;
}

struct Zip_Archive
{
	FILE* zip;
	uint64_t ofs, size;

	Zip_Archive(FILE* _zip) : zip(_zip)
	{
		fseek_wrap(zip, 0, SEEK_END);
		ofs = size = (uint64_t)ftell_wrap(zip);
	}

	~Zip_Archive()
	{
		if (!zip) return;
		fclose(zip);
	}

	uint32_t Read(uint64_t seek_ofs, void *pBuf, uint32_t n)
	{
		if (seek_ofs >= size) n = 0;
		else if ((uint64_t)n > (size - seek_ofs)) n = (uint32_t)(size - seek_ofs);
		if (seek_ofs != ofs) { fseek_wrap(zip, seek_ofs, SEEK_SET); ofs = seek_ofs; }
		uint32_t got = (uint32_t)fread(pBuf, 1, n, zip);
		ofs += got;
		return got;
	}

	bool Unpack(uint64_t zf_data_ofs, uint32_t zf_comp_size, uint32_t zf_uncomp_size, uint8_t zf_bit_flags, uint8_t zf_method, std::vector<uint8_t>& mem_data);
	enum { METHOD_STORED = 0, METHOD_SHRUNK = 1, METHOD_IMPLODED = 6, METHOD_DEFLATED = 8 };
	static bool MethodSupported(uint32_t method) { return (method == METHOD_STORED || method == METHOD_DEFLATED || method == METHOD_SHRUNK || method == METHOD_IMPLODED); }
};

// Various ZIP archive enums. To completely avoid cross platform compiler alignment and platform endian issues, we don't use structs for any of this stuff
enum
{
	// ZIP archive identifiers and record sizes
	ZIP_END_OF_CENTRAL_DIR_HEADER_SIG = 0x06054b50, ZIP_CENTRAL_DIR_HEADER_SIG = 0x02014b50, ZIP_LOCAL_DIR_HEADER_SIG = 0x04034b50,
	ZIP_LOCAL_DIR_HEADER_SIZE = 30, ZIP_CENTRAL_DIR_HEADER_SIZE = 46, ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE = 22,
	ZIP64_END_OF_CENTRAL_DIR_HEADER_SIG = 0x06064b50, ZIP64_END_OF_CENTRAL_DIR_HEADER_SIZE = 56,
	ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIG = 0x07064b50, ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIZE = 20,
	// End of central directory offsets
	ZIP_ECDH_NUM_THIS_DISK_OFS = 4, ZIP_ECDH_NUM_DISK_CDIR_OFS = 6, ZIP_ECDH_CDIR_NUM_ENTRIES_ON_DISK_OFS = 8,
	ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS = 10, ZIP_ECDH_CDIR_SIZE_OFS = 12, ZIP_ECDH_CDIR_OFS_OFS = 16, ZIP_ECDH_COMMENT_SIZE_OFS = 20,
	ZIP64_ECDL_ECDH_OFS_OFS = 8, ZIP64_ECDH_CDIR_TOTAL_ENTRIES_OFS = 32, ZIP64_ECDH_CDIR_SIZE_OFS = 40, ZIP64_ECDH_CDIR_OFS_OFS = 48,
	// Central directory header record offsets
	ZIP_CDH_BIT_FLAG_OFS = 8, ZIP_CDH_METHOD_OFS = 10, ZIP_CDH_FILE_TIME_OFS = 12, ZIP_CDH_FILE_DATE_OFS = 14, ZIP_CDH_CRC32_OFS = 16,
	ZIP_CDH_COMPRESSED_SIZE_OFS = 20, ZIP_CDH_DECOMPRESSED_SIZE_OFS = 24, ZIP_CDH_FILENAME_LEN_OFS = 28, ZIP_CDH_EXTRA_LEN_OFS = 30,
	ZIP_CDH_COMMENT_LEN_OFS = 32, ZIP_CDH_EXTERNAL_ATTR_OFS = 38, ZIP_CDH_LOCAL_HEADER_OFS = 42,
	// Local directory header offsets
	ZIP_LDH_FILENAME_LEN_OFS = 26, ZIP_LDH_EXTRA_LEN_OFS = 28,
};

#define ZIP_MAX(a,b) (((a)>(b))?(a):(b))
#define ZIP_MIN(a,b) (((a)<(b))?(a):(b))
#define ZIP_READ_LE16(p) ((uint16_t)(((const uint8_t *)(p))[0]) | ((uint16_t)(((const uint8_t *)(p))[1]) << 8U))
#define ZIP_READ_LE32(p) ((uint32_t)(((const uint8_t *)(p))[0]) | ((uint32_t)(((const uint8_t *)(p))[1]) << 8U) | ((uint32_t)(((const uint8_t *)(p))[2]) << 16U) | ((uint32_t)(((const uint8_t *)(p))[3]) << 24U))
#define ZIP_READ_LE64(p) ((uint64_t)(((const uint8_t *)(p))[0]) | ((uint64_t)(((const uint8_t *)(p))[1]) << 8U) | ((uint64_t)(((const uint8_t *)(p))[2]) << 16U) | ((uint64_t)(((const uint8_t *)(p))[3]) << 24U) | ((uint64_t)(((const uint8_t *)(p))[4]) << 32U) | ((uint64_t)(((const uint8_t *)(p))[5]) << 40U) | ((uint64_t)(((const uint8_t *)(p))[6]) << 48U) | ((uint64_t)(((const uint8_t *)(p))[7]) << 56U))
#define ZIP_READ_BE32(p) ((uint32_t)((((const uint8_t *)(p))[0] << 24) | (((const uint8_t *)(p))[1] << 16) | (((const uint8_t *)(p))[2] << 8) | ((const uint8_t *)(p))[3]))
#define ZIP_READ_BE64(p) ((uint64_t)((((uint64_t)((const uint8_t *)(p))[0] << 56) | ((uint64_t)((const uint8_t *)(p))[1] << 48) | ((uint64_t)((const uint8_t *)(p))[2] << 40) | ((uint64_t)((const uint8_t *)(p))[3] << 32) | ((uint64_t)((const uint8_t *)(p))[4] << 24) | ((uint64_t)((const uint8_t *)(p))[5] << 16) | ((uint64_t)((const uint8_t *)(p))[6] << 8) | (uint64_t)((const uint8_t *)(p))[7])))

#ifdef NDEBUG
#define ZIP_ASSERT(cond)
#else
#define ZIP_ASSERT(cond) (void)((cond) ? ((int)0) : *(volatile int*)0 |= 0xbad|fprintf(stderr, "FAILED ASSERT (%s)\n", #cond))
#endif

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		fprintf(stderr, "Missing ZIP path(s)\n\nRun tool with:\n  %s <ZIP PATH> ...\n\n", (argc ? argv[0] : "ZIPValidateCRC"));
		return 1;
	}
	for (int test = 1; test != argc; test++)
	{
		FILE *fZIP = fopen(argv[test], "rb");
		if (!fZIP)
		{
			fprintf(stderr, "Unable to find input file %s\n", argv[test]);
			return 1;
		}
		fclose(fZIP);
	}

	for (int argi = 1; argi != argc; argi++)
	{
		const char *path = argv[argi];
		FILE *fZIP = fopen(path, "rb");
		if (!fZIP)
		{
			fprintf(stderr, "Unable to find input file %s\n", path);
			return 1;
		}

		printf("%sZIP: %s\n", (argi > 1 ? "\n" : ""), path);

		Zip_Archive archive(fZIP);

		// Basic sanity checks - reject files which are too small.
		if (archive.size < ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)
		{
			invalid_cd:
			printf("  Invalid ZIP central directory\n");
			continue;
		}

		// Find the end of central directory record by scanning the file from the end towards the beginning.
		uint8_t buf[4096];
		uint64_t ecdh_ofs = (archive.size < sizeof(buf) ? 0 : archive.size - sizeof(buf));
		for (;; ecdh_ofs = ZIP_MAX(ecdh_ofs - (sizeof(buf) - 3), 0))
		{
			int32_t i, n = (int32_t)ZIP_MIN(sizeof(buf), archive.size - ecdh_ofs);
			if (archive.Read(ecdh_ofs, buf, (uint32_t)n) != (uint32_t)n) return 1;
			for (i = n - 4; i >= 0; --i) { if (ZIP_READ_LE32(buf + i) == ZIP_END_OF_CENTRAL_DIR_HEADER_SIG) break; }
			if (i >= 0) { ecdh_ofs += i; break; }
			if (!ecdh_ofs || (archive.size - ecdh_ofs) >= (0xFFFF + ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)) goto invalid_cd;
		}

		// Read and verify the end of central directory record.
		if (archive.Read(ecdh_ofs, buf, ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE) != ZIP_END_OF_CENTRAL_DIR_HEADER_SIZE)
			goto invalid_cd;

		uint64_t total_files = ZIP_READ_LE16(buf + ZIP_ECDH_CDIR_TOTAL_ENTRIES_OFS);
		uint64_t cdir_size   = ZIP_READ_LE32(buf + ZIP_ECDH_CDIR_SIZE_OFS);
		uint64_t cdir_ofs    = ZIP_READ_LE32(buf + ZIP_ECDH_CDIR_OFS_OFS);

		// Handle Zip64
		if ((cdir_ofs == 0xFFFFFFFF || cdir_size == 0xFFFFFFFF || total_files == 0xFFFF)
			&& ecdh_ofs >= (ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIZE + ZIP64_END_OF_CENTRAL_DIR_HEADER_SIZE)
			&& archive.Read(ecdh_ofs - ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIZE, buf, ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIZE) == ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIZE
			&& ZIP_READ_LE32(buf) == ZIP64_END_OF_CENTRAL_DIR_LOCATOR_SIG)
		{
			uint64_t ecdh64_ofs = ZIP_READ_LE64(buf + ZIP64_ECDL_ECDH_OFS_OFS);
			if (ecdh64_ofs <= (archive.size - ZIP64_END_OF_CENTRAL_DIR_HEADER_SIZE)
				&& archive.Read(ecdh64_ofs, buf, ZIP64_END_OF_CENTRAL_DIR_HEADER_SIZE) == ZIP64_END_OF_CENTRAL_DIR_HEADER_SIZE
				&& ZIP_READ_LE32(buf) == ZIP64_END_OF_CENTRAL_DIR_HEADER_SIG)
			{
				total_files = ZIP_READ_LE64(buf + ZIP64_ECDH_CDIR_TOTAL_ENTRIES_OFS);
				cdir_size   = ZIP_READ_LE64(buf + ZIP64_ECDH_CDIR_SIZE_OFS);
				cdir_ofs    = ZIP_READ_LE64(buf + ZIP64_ECDH_CDIR_OFS_OFS);
			}
		}

		if (!total_files
			|| (cdir_size >= 0x10000000) // limit to 256MB content directory
			|| (cdir_size < total_files * ZIP_CENTRAL_DIR_HEADER_SIZE)
			|| ((cdir_ofs + cdir_size) > archive.size)
			) goto invalid_cd;

		void* m_central_dir = malloc((size_t)cdir_size);
		if (archive.Read(cdir_ofs, m_central_dir, (uint32_t)cdir_size) != cdir_size)
		{
			free(m_central_dir);
			goto invalid_cd;
		}
		const uint8_t *cdir_start = (const uint8_t*)m_central_dir, *cdir_end = cdir_start + cdir_size, *p = cdir_start;

		// Now create an index into the central directory file records, do some basic sanity checking on each record
		p = cdir_start;
		for (uint32_t i = 0, total_header_size; i < total_files && p >= cdir_start && p < cdir_end && ZIP_READ_LE32(p) == ZIP_CENTRAL_DIR_HEADER_SIG; i++, p += total_header_size)
		{
			uint32_t bit_flag         = ZIP_READ_LE16(p + ZIP_CDH_BIT_FLAG_OFS);
			uint32_t method           = ZIP_READ_LE16(p + ZIP_CDH_METHOD_OFS);
			uint16_t file_time        = ZIP_READ_LE16(p + ZIP_CDH_FILE_TIME_OFS);
			uint16_t file_date        = ZIP_READ_LE16(p + ZIP_CDH_FILE_DATE_OFS);
			uint32_t crc32            = ZIP_READ_LE32(p + ZIP_CDH_CRC32_OFS);
			uint64_t comp_size        = ZIP_READ_LE32(p + ZIP_CDH_COMPRESSED_SIZE_OFS);
			uint64_t decomp_size      = ZIP_READ_LE32(p + ZIP_CDH_DECOMPRESSED_SIZE_OFS);
			uint32_t filename_len     = ZIP_READ_LE16(p + ZIP_CDH_FILENAME_LEN_OFS);
			int32_t extra_len        = ZIP_READ_LE16(p + ZIP_CDH_EXTRA_LEN_OFS);
			int32_t external_attr    = ZIP_READ_LE32(p + ZIP_CDH_EXTERNAL_ATTR_OFS);
			uint64_t local_header_ofs = ZIP_READ_LE32(p + ZIP_CDH_LOCAL_HEADER_OFS);
			total_header_size = ZIP_CENTRAL_DIR_HEADER_SIZE + filename_len + extra_len + ZIP_READ_LE16(p + ZIP_CDH_COMMENT_LEN_OFS);

			if (p + total_header_size > cdir_end)
			{
				invalid_cdh:
				printf("  Encountered invalid file entry in central directory, ZIP is likely corrupt\n");
				continue;
			}

			// Handle Zip64
			if (decomp_size == 0xFFFFFFFF || comp_size == 0xFFFFFFFF || local_header_ofs == 0xFFFFFFFF)
			{
				for (const uint8_t *x = p + ZIP_CENTRAL_DIR_HEADER_SIZE + filename_len, *xEnd = x + extra_len; (x + (sizeof(uint16_t) * 2)) < xEnd;)
				{
					const uint8_t *field = x + (sizeof(uint16_t) * 2), *fieldEnd = field + ZIP_READ_LE16(x + 2);
					if (ZIP_READ_LE16(x) != 0x0001 || fieldEnd > xEnd) { x = fieldEnd; continue; } // Not Zip64 extended information extra field
					if (decomp_size == 0xFFFFFFFF)
					{
						if ((size_t)(fieldEnd - field) < sizeof(uint64_t)) goto invalid_cdh;
						decomp_size = ZIP_READ_LE64(field);
						field += sizeof(uint64_t);
					}
					if (comp_size == 0xFFFFFFFF)
					{
						if ((size_t)(fieldEnd - field) < sizeof(uint64_t)) goto invalid_cdh;
						comp_size = ZIP_READ_LE64(field);
						field += sizeof(uint64_t);
					}
					if (local_header_ofs == 0xFFFFFFFF)
					{
						if ((size_t)(fieldEnd - field) < sizeof(uint64_t)) goto invalid_cdh;
						local_header_ofs = ZIP_READ_LE64(field);
						field += sizeof(uint64_t);
					}
					break;
				}
			}

			// Get file name path
			char *name = (char*)(p + ZIP_CENTRAL_DIR_HEADER_SIZE);
			for (char *p = name, *name_end = name + filename_len; p != name_end; p++)
				if (*p == '\\')
					*p = '/'; // convert back-slashes to regular slashes

			// ZIP files optionally store entries for directories to keep a timestamp but such entries are just empty files otherwise
			bool is_dir = (name[filename_len - 1] == '/' || (external_attr & 0x10));

			printf("  - %60.*s - Date: %04d-%02d-%02d %02d:%02d:%02d - Size Compressed: %8u - Size Decompressed: %8u - Stored CRC: %08x",
				(int)filename_len, name,
				((file_date >> 9) + 1980), ((file_date >> 5) & 0xf), (file_date & 0x1f), (file_time >> 11), ((file_time >> 5) & 0x3f), ((file_time & 0x1f) * 2),
				(unsigned)comp_size, (unsigned)decomp_size, crc32);

			const bool invalid_comp_size = (((!method) && (decomp_size != comp_size)) || (decomp_size && !comp_size));
			const bool data_past_eof = ((local_header_ofs + ZIP_LOCAL_DIR_HEADER_SIZE + comp_size) > archive.size);
			const bool method_unsupported = !Zip_Archive::MethodSupported(method);
			const bool encryption_or_patch_file = ((bit_flag & (1 | 32)) != 0);

			if (invalid_comp_size || data_past_eof || method_unsupported || encryption_or_patch_file)
			{
				printf("\n");
				if (invalid_comp_size)        printf("    Encountered file with invalid compressed size, ZIP is likely corrupt\n");
				if (data_past_eof)            printf("    Encountered file with compressed data past end-of-file, ZIP is likely corrupt\n");
				if (method_unsupported)       printf("    Encountered file with unsupported method %u, cannot decompress\n", method);
				if (encryption_or_patch_file) printf("    Encountered file using encryption or patch file, cannot decompress\n");
			}
			else
			{
				std::vector<uint8_t> mem_data;
				archive.Unpack(local_header_ofs, (uint32_t)comp_size, (uint32_t)decomp_size, (uint8_t)bit_flag, (uint8_t)method, mem_data);
				const uint8_t* mem_ptr = (decomp_size ? &mem_data[0] : NULL);
				const uint32_t calculated_crc32 = CRC32(mem_ptr, (size_t)decomp_size);
				ZIP_ASSERT(mem_data.size() == decomp_size);
				printf(" - Calculated CRC: %08x%s%s\n", calculated_crc32, (crc32 == calculated_crc32 ? "" : " - MISMATCHED CRC!!!"), (is_dir ? " - DIRECTORY ENTRY" : ""));
			}
		}
		free(m_central_dir);
	}
	return 0;
}

struct miniz
{
	// BASED ON MINIZ
	// miniz.c v1.15 - public domain deflate
	// Rich Geldreich <richgel99@gmail.com>, last updated Oct. 13, 2013

	// Set MINIZ_HAS_64BIT_REGISTERS to 1 if operations on 64-bit integers are reasonably fast (and don't involve compiler generated calls to helper functions).
	#if defined(_M_X64) || defined(_WIN64) || defined(__MINGW64__) || defined(_LP64) || defined(__LP64__) || defined(__ia64__) || defined(__x86_64__)
	#define MINIZ_HAS_64BIT_REGISTERS 1
	#else
	#define MINIZ_HAS_64BIT_REGISTERS 0
	#endif

	enum
	{
		// Decompression flags used by tinfl_decompress().
		TINFL_FLAG_HAS_MORE_INPUT = 2,                // If set, there are more input bytes available beyond the end of the supplied input buffer. If clear, the input buffer contains all remaining input.
		TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF = 4, // If set, the output buffer is large enough to hold the entire decompressed stream. If clear, the output buffer is at least the size of the dictionary (typically 32KB).

		// Max size of read buffer.
		MZ_ZIP_MAX_IO_BUF_SIZE = 64*1024,

		// Max size of LZ dictionary (output buffer).
		TINFL_LZ_DICT_SIZE = 32*1024, // fixed for zip

		// Internal/private bits follow.
		TINFL_MAX_HUFF_TABLES = 3, TINFL_MAX_HUFF_SYMBOLS_0 = 288, TINFL_MAX_HUFF_SYMBOLS_1 = 32, TINFL_MAX_HUFF_SYMBOLS_2 = 19,
		TINFL_FAST_LOOKUP_BITS = 10, TINFL_FAST_LOOKUP_SIZE = 1 << TINFL_FAST_LOOKUP_BITS,

		// Number coroutine states consecutively
		TINFL_STATE_INDEX_BLOCK_BOUNDRY = 1,
		TINFL_STATE_3 , TINFL_STATE_5 , TINFL_STATE_6 , TINFL_STATE_7 , TINFL_STATE_51, TINFL_STATE_52,
		TINFL_STATE_9 , TINFL_STATE_38, TINFL_STATE_11, TINFL_STATE_14, TINFL_STATE_16, TINFL_STATE_18,
		TINFL_STATE_23, TINFL_STATE_24, TINFL_STATE_25, TINFL_STATE_26, TINFL_STATE_27, TINFL_STATE_53,
		TINFL_STATE_END
	};

	// Return status.
	enum tinfl_status
	{
		TINFL_STATUS_BAD_PARAM = -3,
		TINFL_STATUS_FAILED = -1,
		TINFL_STATUS_DONE = 0,
		TINFL_STATUS_NEEDS_MORE_INPUT = 1,
		TINFL_STATUS_HAS_MORE_OUTPUT = 2,
	};

	#if MINIZ_HAS_64BIT_REGISTERS
	typedef uint64_t tinfl_bit_buf_t;
	#else
	typedef uint32_t tinfl_bit_buf_t;
	#endif

	struct tinfl_huff_table
	{
		int16_t m_look_up[TINFL_FAST_LOOKUP_SIZE];
		int16_t m_tree[TINFL_MAX_HUFF_SYMBOLS_0 * 2];
		uint8_t m_code_size[TINFL_MAX_HUFF_SYMBOLS_0];
	};

	struct tinfl_decompressor
	{
		tinfl_huff_table m_tables[TINFL_MAX_HUFF_TABLES];
		uint32_t m_state, m_num_bits, m_final, m_type, m_dist, m_counter, m_num_extra, m_table_sizes[TINFL_MAX_HUFF_TABLES];
		tinfl_bit_buf_t m_bit_buf;
		size_t m_dist_from_out_buf_start;
		uint8_t m_raw_header[4], m_len_codes[TINFL_MAX_HUFF_SYMBOLS_0 + TINFL_MAX_HUFF_SYMBOLS_1 + 137];
	};

	// Initializes the decompressor to its initial state.
	static void tinfl_init(tinfl_decompressor *r) { r->m_state = 0; }

	// Main low-level decompressor coroutine function. This is the only function actually needed for decompression. All the other functions are just high-level helpers for improved usability.
	// This is a universal API, i.e. it can be used as a building block to build any desired higher level decompression API. In the limit case, it can be called once per every byte input or output.
	static tinfl_status tinfl_decompress(tinfl_decompressor *r, const uint8_t *pIn_buf_next, uint32_t *pIn_buf_size, uint8_t *pOut_buf_start, uint8_t *pOut_buf_next, uint32_t *pOut_buf_size, const uint32_t decomp_flags)
	{
		// An attempt to work around MSVC's spammy "warning C4127: conditional expression is constant" message.
		#ifdef _MSC_VER
		#define TINFL_MACRO_END while (0, 0)
		#else
		#define TINFL_MACRO_END while (0)
		#endif

		#define TINFL_MEMCPY(d, s, l) memcpy(d, s, l)
		#define TINFL_MEMSET(p, c, l) memset(p, c, l)
		#define TINFL_CLEAR(obj) memset(&(obj), 0, sizeof(obj))

		#define TINFL_CR_BEGIN switch(r->m_state) { case 0:
		#define TINFL_CR_RETURN(state_index, result) do { status = result; r->m_state = state_index; goto common_exit; case state_index:; } TINFL_MACRO_END
		#define TINFL_CR_RETURN_FOREVER(state_index, result) do { status = result; r->m_state = TINFL_STATE_END; goto common_exit; } TINFL_MACRO_END
		#define TINFL_CR_FINISH }

		// TODO: If the caller has indicated that there's no more input, and we attempt to read beyond the input buf, then something is wrong with the input because the inflator never
		// reads ahead more than it needs to. Currently TINFL_GET_BYTE() pads the end of the stream with 0's in this scenario.
		#define TINFL_GET_BYTE(state_index, c) do { \
			if (pIn_buf_cur >= pIn_buf_end) { \
				for ( ; ; ) { \
					if (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT) { \
						TINFL_CR_RETURN(state_index, TINFL_STATUS_NEEDS_MORE_INPUT); \
						if (pIn_buf_cur < pIn_buf_end) { \
							c = *pIn_buf_cur++; \
							break; \
						} \
					} else { \
						c = 0; \
						break; \
					} \
				} \
			} else c = *pIn_buf_cur++; } TINFL_MACRO_END

		#define TINFL_NEED_BITS(state_index, n) do { uint32_t c; TINFL_GET_BYTE(state_index, c); bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); num_bits += 8; } while (num_bits < (uint32_t)(n))
		#define TINFL_SKIP_BITS(state_index, n) do { if (num_bits < (uint32_t)(n)) { TINFL_NEED_BITS(state_index, n); } bit_buf >>= (n); num_bits -= (n); } TINFL_MACRO_END
		#define TINFL_GET_BITS(state_index, b, n) do { if (num_bits < (uint32_t)(n)) { TINFL_NEED_BITS(state_index, n); } b = bit_buf & ((1 << (n)) - 1); bit_buf >>= (n); num_bits -= (n); } TINFL_MACRO_END

		// TINFL_HUFF_BITBUF_FILL() is only used rarely, when the number of bytes remaining in the input buffer falls below 2.
		// It reads just enough bytes from the input stream that are needed to decode the next Huffman code (and absolutely no more). It works by trying to fully decode a
		// Huffman code by using whatever bits are currently present in the bit buffer. If this fails, it reads another byte, and tries again until it succeeds or until the
		// bit buffer contains >=15 bits (deflate's max. Huffman code size).
		#define TINFL_HUFF_BITBUF_FILL(state_index, pHuff) \
			do { \
				temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]; \
				if (temp >= 0) { \
					code_len = temp >> 9; \
					if ((code_len) && (num_bits >= code_len)) \
					break; \
				} else if (num_bits > TINFL_FAST_LOOKUP_BITS) { \
					 code_len = TINFL_FAST_LOOKUP_BITS; \
					 do { \
							temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)]; \
					 } while ((temp < 0) && (num_bits >= (code_len + 1))); if (temp >= 0) break; \
				} TINFL_GET_BYTE(state_index, c); bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); num_bits += 8; \
			} while (num_bits < 15);

		// TINFL_HUFF_DECODE() decodes the next Huffman coded symbol. It's more complex than you would initially expect because the zlib API expects the decompressor to never read
		// beyond the final byte of the deflate stream. (In other words, when this macro wants to read another byte from the input, it REALLY needs another byte in order to fully
		// decode the next Huffman code.) Handling this properly is particularly important on raw deflate (non-zlib) streams, which aren't followed by a byte aligned adler-32.
		// The slow path is only executed at the very end of the input buffer.
		#define TINFL_HUFF_DECODE(state_index, sym, pHuff) do { \
			int temp; uint32_t code_len, c; \
			if (num_bits < 15) { \
				if ((pIn_buf_end - pIn_buf_cur) < 2) { \
					 TINFL_HUFF_BITBUF_FILL(state_index, pHuff); \
				} else { \
					 bit_buf |= (((tinfl_bit_buf_t)pIn_buf_cur[0]) << num_bits) | (((tinfl_bit_buf_t)pIn_buf_cur[1]) << (num_bits + 8)); pIn_buf_cur += 2; num_bits += 16; \
				} \
			} \
			if ((temp = (pHuff)->m_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0) \
				code_len = temp >> 9, temp &= 511; \
			else { \
				code_len = TINFL_FAST_LOOKUP_BITS; do { temp = (pHuff)->m_tree[~temp + ((bit_buf >> code_len++) & 1)]; } while (temp < 0); \
			} sym = temp; bit_buf >>= code_len; num_bits -= code_len; } TINFL_MACRO_END

		static const int s_length_base[31] = { 3,4,5,6,7,8,9,10,11,13, 15,17,19,23,27,31,35,43,51,59, 67,83,99,115,131,163,195,227,258,0,0 };
		static const int s_length_extra[31]= { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0,0,0 };
		static const int s_dist_base[32] = { 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193, 257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577,0,0};
		static const int s_dist_extra[32] = { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
		static const uint8_t s_length_dezigzag[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
		static const int s_min_table_sizes[3] = { 257, 1, 4 };

		tinfl_status status = TINFL_STATUS_FAILED; uint32_t num_bits, dist, counter, num_extra; tinfl_bit_buf_t bit_buf;
		const uint8_t *pIn_buf_cur = pIn_buf_next, *const pIn_buf_end = pIn_buf_next + *pIn_buf_size, *const pIn_buf_end_m_4 = pIn_buf_end - 4;
		uint8_t *pOut_buf_cur = pOut_buf_next, *const pOut_buf_end = pOut_buf_next + *pOut_buf_size, *const pOut_buf_end_m_2 = pOut_buf_end - 2;
		size_t out_buf_size_mask = (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF) ? (size_t)-1 : ((pOut_buf_next - pOut_buf_start) + *pOut_buf_size) - 1, dist_from_out_buf_start;

		int16_t* r_tables_0_look_up = r->m_tables[0].m_look_up;

		// Ensure the output buffer's size is a power of 2, unless the output buffer is large enough to hold the entire output file (in which case it doesn't matter).
		if (((out_buf_size_mask + 1) & out_buf_size_mask) || (pOut_buf_next < pOut_buf_start)) { *pIn_buf_size = *pOut_buf_size = 0; return TINFL_STATUS_BAD_PARAM; }

		num_bits = r->m_num_bits; bit_buf = r->m_bit_buf; dist = r->m_dist; counter = r->m_counter; num_extra = r->m_num_extra; dist_from_out_buf_start = r->m_dist_from_out_buf_start;
		TINFL_CR_BEGIN

		bit_buf = num_bits = dist = counter = num_extra = 0;

		do
		{
			if (pIn_buf_cur - pIn_buf_next) { TINFL_CR_RETURN(TINFL_STATE_INDEX_BLOCK_BOUNDRY, TINFL_STATUS_HAS_MORE_OUTPUT); }
			TINFL_GET_BITS(TINFL_STATE_3, r->m_final, 3); r->m_type = r->m_final >> 1;
			if (r->m_type == 0)
			{
				TINFL_SKIP_BITS(TINFL_STATE_5, num_bits & 7);
				for (counter = 0; counter < 4; ++counter) { if (num_bits) TINFL_GET_BITS(TINFL_STATE_6, r->m_raw_header[counter], 8); else TINFL_GET_BYTE(TINFL_STATE_7, r->m_raw_header[counter]); }
				if ((counter = (r->m_raw_header[0] | (r->m_raw_header[1] << 8))) != (uint32_t)(0xFFFF ^ (r->m_raw_header[2] | (r->m_raw_header[3] << 8)))) { TINFL_CR_RETURN_FOREVER(39, TINFL_STATUS_FAILED); }
				while ((counter) && (num_bits))
				{
					TINFL_GET_BITS(TINFL_STATE_51, dist, 8);
					while (pOut_buf_cur >= pOut_buf_end) { TINFL_CR_RETURN(TINFL_STATE_52, TINFL_STATUS_HAS_MORE_OUTPUT); }
					*pOut_buf_cur++ = (uint8_t)dist;
					counter--;
				}
				while (counter)
				{
					size_t n; while (pOut_buf_cur >= pOut_buf_end) { TINFL_CR_RETURN(TINFL_STATE_9, TINFL_STATUS_HAS_MORE_OUTPUT); }
					while (pIn_buf_cur >= pIn_buf_end)
					{
						if (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT)
						{
							TINFL_CR_RETURN(TINFL_STATE_38, TINFL_STATUS_NEEDS_MORE_INPUT);
						}
						else
						{
							TINFL_CR_RETURN_FOREVER(40, TINFL_STATUS_FAILED);
						}
					}
					n = ZIP_MIN(ZIP_MIN((size_t)(pOut_buf_end - pOut_buf_cur), (size_t)(pIn_buf_end - pIn_buf_cur)), counter);
					TINFL_MEMCPY(pOut_buf_cur, pIn_buf_cur, n); pIn_buf_cur += n; pOut_buf_cur += n; counter -= (uint32_t)n;
				}
			}
			else if (r->m_type == 3)
			{
				TINFL_CR_RETURN_FOREVER(10, TINFL_STATUS_FAILED);
			}
			else
			{
				if (r->m_type == 1)
				{
					uint8_t *p = r->m_tables[0].m_code_size; uint32_t i;
					r->m_table_sizes[0] = 288; r->m_table_sizes[1] = 32; TINFL_MEMSET(r->m_tables[1].m_code_size, 5, 32);
					for (i = 0; i <= 143; ++i) { *p++ = 8; } for (; i <= 255; ++i) { *p++ = 9; } for (; i <= 279; ++i) { *p++ = 7; } for (; i <= 287; ++i) { *p++ = 8; }
				}
				else
				{
					for (counter = 0; counter < 3; counter++) { TINFL_GET_BITS(TINFL_STATE_11, r->m_table_sizes[counter], "\05\05\04"[counter]); r->m_table_sizes[counter] += s_min_table_sizes[counter]; }
					TINFL_CLEAR(r->m_tables[2].m_code_size); for (counter = 0; counter < r->m_table_sizes[2]; counter++) { uint32_t s; TINFL_GET_BITS(TINFL_STATE_14, s, 3); r->m_tables[2].m_code_size[s_length_dezigzag[counter]] = (uint8_t)s; }
					r->m_table_sizes[2] = 19;
				}
				for ( ; (int)r->m_type >= 0; r->m_type--)
				{
					int tree_next, tree_cur; tinfl_huff_table *pTable;
					uint32_t i, j, used_syms, total, sym_index, next_code[17], total_syms[16]; pTable = &r->m_tables[r->m_type]; TINFL_CLEAR(total_syms); TINFL_CLEAR(pTable->m_look_up); TINFL_CLEAR(pTable->m_tree);
					for (i = 0; i < r->m_table_sizes[r->m_type]; ++i) total_syms[pTable->m_code_size[i]]++;
					used_syms = 0, total = 0; next_code[0] = next_code[1] = 0;
					for (i = 1; i <= 15; ++i) { used_syms += total_syms[i]; next_code[i + 1] = (total = ((total + total_syms[i]) << 1)); }
					if ((65536 != total) && (used_syms > 1))
					{
						TINFL_CR_RETURN_FOREVER(35, TINFL_STATUS_FAILED);
					}
					for (tree_next = -1, sym_index = 0; sym_index < r->m_table_sizes[r->m_type]; ++sym_index)
					{
						uint32_t rev_code = 0, l, cur_code, code_size = pTable->m_code_size[sym_index]; if (!code_size) continue;
						cur_code = next_code[code_size]++; for (l = code_size; l > 0; l--, cur_code >>= 1) rev_code = (rev_code << 1) | (cur_code & 1);
						if (code_size <= TINFL_FAST_LOOKUP_BITS) { int16_t k = (int16_t)((code_size << 9) | sym_index); while (rev_code < TINFL_FAST_LOOKUP_SIZE) { pTable->m_look_up[rev_code] = k; rev_code += (1 << code_size); } continue; }
						if (0 == (tree_cur = pTable->m_look_up[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)])) { pTable->m_look_up[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)] = (int16_t)tree_next; tree_cur = tree_next; tree_next -= 2; }
						rev_code >>= (TINFL_FAST_LOOKUP_BITS - 1);
						for (j = code_size; j > (TINFL_FAST_LOOKUP_BITS + 1); j--)
						{
							tree_cur -= ((rev_code >>= 1) & 1);
							if (!pTable->m_tree[-tree_cur - 1]) { pTable->m_tree[-tree_cur - 1] = (int16_t)tree_next; tree_cur = tree_next; tree_next -= 2; } else tree_cur = pTable->m_tree[-tree_cur - 1];
						}
						tree_cur -= ((rev_code >>= 1) & 1); pTable->m_tree[-tree_cur - 1] = (int16_t)sym_index;
					}
					if (r->m_type == 2)
					{
						for (counter = 0; counter < (r->m_table_sizes[0] + r->m_table_sizes[1]); )
						{
							uint32_t s; TINFL_HUFF_DECODE(TINFL_STATE_16, dist, &r->m_tables[2]); if (dist < 16) { r->m_len_codes[counter++] = (uint8_t)dist; continue; }
							if ((dist == 16) && (!counter))
							{
								TINFL_CR_RETURN_FOREVER(17, TINFL_STATUS_FAILED);
							}
							num_extra = "\02\03\07"[dist - 16]; TINFL_GET_BITS(TINFL_STATE_18, s, num_extra); s += "\03\03\013"[dist - 16];
							TINFL_MEMSET(r->m_len_codes + counter, (dist == 16) ? r->m_len_codes[counter - 1] : 0, s); counter += s;
						}
						if ((r->m_table_sizes[0] + r->m_table_sizes[1]) != counter)
						{
							TINFL_CR_RETURN_FOREVER(21, TINFL_STATUS_FAILED);
						}
						TINFL_MEMCPY(r->m_tables[0].m_code_size, r->m_len_codes, r->m_table_sizes[0]); TINFL_MEMCPY(r->m_tables[1].m_code_size, r->m_len_codes + r->m_table_sizes[0], r->m_table_sizes[1]);
					}
				}
				for ( ; ; )
				{
					uint8_t *pSrc;
					for ( ; ; )
					{
						if (((pIn_buf_end_m_4 < pIn_buf_cur)) || ((pOut_buf_end_m_2 < pOut_buf_cur)))
						{
							TINFL_HUFF_DECODE(TINFL_STATE_23, counter, &r->m_tables[0]);
							if (counter >= 256)
								break;
							while (pOut_buf_cur >= pOut_buf_end) { TINFL_CR_RETURN(TINFL_STATE_24, TINFL_STATUS_HAS_MORE_OUTPUT); }
							*pOut_buf_cur++ = (uint8_t)counter;
						}
						else
						{
							int sym2; uint32_t code_len;
							#if MINIZ_HAS_64BIT_REGISTERS
							if (num_bits < 30) { bit_buf |= (((tinfl_bit_buf_t)ZIP_READ_LE32(pIn_buf_cur)) << num_bits); pIn_buf_cur += 4; num_bits += 32; }
							#else
							if (num_bits < 15) { bit_buf |= (((tinfl_bit_buf_t)ZIP_READ_LE16(pIn_buf_cur)) << num_bits); pIn_buf_cur += 2; num_bits += 16; }
							#endif

							sym2 = r_tables_0_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)];
							if (sym2 < 0)
							{
								code_len = TINFL_FAST_LOOKUP_BITS;
								do { sym2 = r->m_tables[0].m_tree[~sym2 + ((bit_buf >> code_len++) & 1)]; } while (sym2 < 0);
							}
							else
								code_len = sym2 >> 9;
							counter = sym2;
							bit_buf >>= code_len;
							num_bits -= code_len;
							if (counter & 256)
								break;

							#if !MINIZ_HAS_64BIT_REGISTERS
							if (num_bits < 15) { bit_buf |= (((tinfl_bit_buf_t)ZIP_READ_LE16(pIn_buf_cur)) << num_bits); pIn_buf_cur += 2; num_bits += 16; }
							#endif

							sym2 = r_tables_0_look_up[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)];
							if (sym2 >= 0)
								code_len = sym2 >> 9;
							else
							{
								code_len = TINFL_FAST_LOOKUP_BITS;
								do { sym2 = r->m_tables[0].m_tree[~sym2 + ((bit_buf >> code_len++) & 1)]; } while (sym2 < 0);
							}
							bit_buf >>= code_len;
							num_bits -= code_len;

							pOut_buf_cur[0] = (uint8_t)counter;
							if (sym2 & 256)
							{
								pOut_buf_cur++;
								counter = sym2;
								break;
							}
							pOut_buf_cur[1] = (uint8_t)sym2;
							pOut_buf_cur += 2;
						}
					}
					if ((counter &= 511) == 256) break;

					num_extra = s_length_extra[counter - 257]; counter = s_length_base[counter - 257];
					if (num_extra) { uint32_t extra_bits; TINFL_GET_BITS(TINFL_STATE_25, extra_bits, num_extra); counter += extra_bits; }

					TINFL_HUFF_DECODE(TINFL_STATE_26, dist, &r->m_tables[1]);
					num_extra = s_dist_extra[dist]; dist = s_dist_base[dist];
					if (num_extra) { uint32_t extra_bits; TINFL_GET_BITS(TINFL_STATE_27, extra_bits, num_extra); dist += extra_bits; }

					dist_from_out_buf_start = pOut_buf_cur - pOut_buf_start;
					if ((dist > dist_from_out_buf_start) && (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF))
					{
						TINFL_CR_RETURN_FOREVER(37, TINFL_STATUS_FAILED);
					}

					pSrc = pOut_buf_start + ((dist_from_out_buf_start - dist) & out_buf_size_mask);

					if ((ZIP_MAX(pOut_buf_cur, pSrc) + counter) <= pOut_buf_end)
					{
						do
						{
							pOut_buf_cur[0] = pSrc[0];
							pOut_buf_cur[1] = pSrc[1];
							pOut_buf_cur[2] = pSrc[2];
							pOut_buf_cur += 3; pSrc += 3;
						} while ((int)(counter -= 3) > 2);
						if ((int)counter > 0)
						{
							*(pOut_buf_cur++) = pSrc[0];
							if (counter == 2)
								*(pOut_buf_cur++) = pSrc[1];
						}
					}
					else
					{
						while (counter--)
						{
							while (pOut_buf_cur >= pOut_buf_end) { TINFL_CR_RETURN(TINFL_STATE_53, TINFL_STATUS_HAS_MORE_OUTPUT); }
							*pOut_buf_cur++ = pOut_buf_start[(dist_from_out_buf_start++ - dist) & out_buf_size_mask];
						}
					}
				}
			}
		} while (!(r->m_final & 1));
		TINFL_CR_RETURN_FOREVER(34, TINFL_STATUS_DONE);
		TINFL_CR_FINISH

		common_exit:
		r->m_num_bits = num_bits; r->m_bit_buf = bit_buf; r->m_dist = dist; r->m_counter = counter; r->m_num_extra = num_extra; r->m_dist_from_out_buf_start = dist_from_out_buf_start;
		*pIn_buf_size = (uint32_t)(pIn_buf_cur - pIn_buf_next); *pOut_buf_size = (uint32_t)(pOut_buf_cur - pOut_buf_next);
		return status;

		#undef TINFL_MACRO_END
		#undef TINFL_MEMCPY
		#undef TINFL_MEMSET
		#undef TINFL_CR_BEGIN
		#undef TINFL_CR_RETURN
		#undef TINFL_CR_RETURN_FOREVER
		#undef TINFL_CR_FINISH
		#undef TINFL_GET_BYTE
		#undef TINFL_NEED_BITS
		#undef TINFL_SKIP_BITS
		#undef TINFL_GET_BITS
		#undef TINFL_HUFF_BITBUF_FILL
		#undef TINFL_HUFF_DECODE
	}
};

struct oz_unshrink
{
	// BASED ON OZUNSHRINK
	// Ozunshrink / Old ZIP Unshrink (ozunshrink.h) (public domain)
	// By Jason Summers - https://github.com/jsummers/oldunzip

	enum
	{
		OZ_ERRCODE_OK                  = 0,
		OZ_ERRCODE_GENERIC_ERROR       = 1,
		OZ_ERRCODE_BAD_CDATA           = 2,
		OZ_ERRCODE_READ_FAILED         = 6,
		OZ_ERRCODE_WRITE_FAILED        = 7,
		OZ_ERRCODE_INSUFFICIENT_CDATA  = 8,
	};

	uint8_t *out_start, *out_cur, *out_end;
	uint8_t *in_start, *in_cur, *in_end;

	// The code table (implements a dictionary)
	enum { OZ_VALBUFSIZE = 7936, OZ_NUM_CODES = 8192 };
	uint8_t valbuf[OZ_VALBUFSIZE]; // Max possible chain length (8192 - 257 + 1 = 7936)
	struct { uint16_t parent; uint8_t value; uint8_t flags; } ct[OZ_NUM_CODES];

	static int Run(oz_unshrink *oz)
	{
		enum { OZ_INITIAL_CODE_SIZE = 9, OZ_MAX_CODE_SIZE = 13, OZ_INVALID_CODE = 256 };
		uint32_t oz_bitreader_buf = 0;
		uint8_t  oz_bitreader_nbits_in_buf = 0;
		uint8_t  oz_curr_code_size = OZ_INITIAL_CODE_SIZE;
		uint16_t oz_oldcode = 0;
		uint16_t oz_highest_code_ever_used = 0;
		uint16_t oz_free_code_search_start = 257;
		uint8_t  oz_last_value = 0;
		bool   oz_have_oldcode = false;
		bool   oz_was_clear = false;

		memset(oz->ct, 0, sizeof(oz->ct));
		for (uint16_t i = 0; i < 256; i++)
		{
			// For entries <=256, .parent is always set to OZ_INVALID_CODE.
			oz->ct[i].parent = OZ_INVALID_CODE;
			oz->ct[i].value = (uint8_t)i;
		}
		for (uint16_t j = 256; j < OZ_NUM_CODES; j++)
		{
			// For entries >256, .parent==OZ_INVALID_CODE means code is unused
			oz->ct[j].parent = OZ_INVALID_CODE;
		}

		for (;;)
		{
			while (oz_bitreader_nbits_in_buf < oz_curr_code_size)
			{
				if (oz->in_cur >= oz->in_end) return OZ_ERRCODE_INSUFFICIENT_CDATA;
				uint8_t b = *(oz->in_cur++);
				oz_bitreader_buf |= ((uint32_t)b) << oz_bitreader_nbits_in_buf;
				oz_bitreader_nbits_in_buf += 8;
			}

			uint16_t code = (uint16_t)(oz_bitreader_buf & ((1U << oz_curr_code_size) - 1U));
			oz_bitreader_buf >>= oz_curr_code_size;
			oz_bitreader_nbits_in_buf -= oz_curr_code_size;

			if (code == 256)
			{
				oz_was_clear = true;
				continue;
			}

			if (oz_was_clear)
			{
				oz_was_clear = false;

				if (code == 1 && (oz_curr_code_size < OZ_MAX_CODE_SIZE))
				{
					oz_curr_code_size++;
					continue;
				}
				if (code != 2) return OZ_ERRCODE_BAD_CDATA;

				// partial clear
				uint16_t i;
				for (i = 257; i <= oz_highest_code_ever_used; i++)
				{
					if (oz->ct[i].parent != OZ_INVALID_CODE)
					{
						oz->ct[oz->ct[i].parent].flags = 1; // Mark codes that have a child
					}
				}

				for (i = 257; i <= oz_highest_code_ever_used; i++)
				{
					if (oz->ct[i].flags == 0)
					{
						oz->ct[i].parent = OZ_INVALID_CODE; // Clear this code
						oz->ct[i].value = 0;
					}
					else
					{
						oz->ct[i].flags = 0; // Leave all flags at 0, for next time.
					}
				}

				oz_free_code_search_start = 257;
				continue;
			}

			// Process a single (nonspecial) LZW code that was read from the input stream.
			if (code >= OZ_NUM_CODES) return OZ_ERRCODE_GENERIC_ERROR;

			uint16_t emit_code;
			bool late_add, code_is_in_table = (code < 256 || oz->ct[code].parent != OZ_INVALID_CODE);
			if      (!oz_have_oldcode) { late_add = false; goto OZ_EMIT_CODE;         } //emit only
			else if (code_is_in_table) { late_add =  true; goto OZ_EMIT_CODE;         } //emit, then add
			else                       { late_add = false; goto OZ_ADD_TO_DICTIONARY; } //add, then emit

			// Add a code to the dictionary.
			OZ_ADD_TO_DICTIONARY:
			uint16_t newpos, valbuf_pos;
			for (newpos = oz_free_code_search_start; ; newpos++)
			{
				if (newpos >= OZ_NUM_CODES) return OZ_ERRCODE_BAD_CDATA;
				if (oz->ct[newpos].parent == OZ_INVALID_CODE) break;
			}
			oz->ct[newpos].parent = oz_oldcode;
			oz->ct[newpos].value = oz_last_value;
			oz_free_code_search_start = newpos + 1;
			if (newpos > oz_highest_code_ever_used)
			{
				oz_highest_code_ever_used = newpos;
			}
			if (late_add) goto OZ_FINISH_PROCESS_CODE;

			// Decode an LZW code to one or more values, and write the values. Updates oz_last_value.
			OZ_EMIT_CODE:
			for (emit_code = code, valbuf_pos = OZ_VALBUFSIZE;;) // = First entry that's used
			{
				if (emit_code >= OZ_NUM_CODES) return OZ_ERRCODE_GENERIC_ERROR;

				// Check if infinite loop (probably an internal error).
				if (valbuf_pos == 0) return OZ_ERRCODE_GENERIC_ERROR;

				// valbuf is a stack, essentially. We fill it in the reverse direction, to make it simpler to write the final byte sequence.
				valbuf_pos--;

				if (emit_code >= 257 && oz->ct[emit_code].parent == OZ_INVALID_CODE)
				{
					oz->valbuf[valbuf_pos] = oz_last_value;
					emit_code = oz_oldcode;
					continue;
				}

				oz->valbuf[valbuf_pos] = oz->ct[emit_code].value;

				if (emit_code < 257)
				{
					oz_last_value = oz->ct[emit_code].value;

					// Write out the collected values.
					size_t n = OZ_VALBUFSIZE - valbuf_pos;
					if (oz->out_cur + n > oz->out_end) return OZ_ERRCODE_WRITE_FAILED;
					memcpy(oz->out_cur, &oz->valbuf[valbuf_pos], n);
					oz->out_cur += n;
					if (oz->out_cur == oz->out_end) return OZ_ERRCODE_OK;

					break;
				}

				// Traverse the tree, back toward the root codes.
				emit_code = oz->ct[emit_code].parent;
			}
			if (late_add) goto OZ_ADD_TO_DICTIONARY;

			if (!oz_have_oldcode)
			{
				oz_have_oldcode = true;
				oz_last_value = (uint8_t)code;
			}

			OZ_FINISH_PROCESS_CODE:
			oz_oldcode = code;
		}
	}
};

struct unz_explode
{
	// BASED ON INFO-ZIP UNZIP
	// Info-ZIP UnZip v5.4 (explode.c and inflate.c)
	// Put in the public domain by Mark Adler

	enum
	{
		UNZ_ERRCODE_OK                  = 0,
		UNZ_ERRCODE_INCOMPLETE_SET      = 1,
		UNZ_ERRCODE_INVALID_TABLE_INPUT = 2,
		UNZ_ERRCODE_OUTOFMEMORY         = 3,
		UNZ_ERRCODE_INVALID_TREE_INPUT  = 4,
		UNZ_ERRCODE_INTERNAL_ERROR      = 5,
		UNZ_ERRCODE_OUTPUT_ERROR        = 6,
	};

	uint8_t *out_start, *out_cur, *out_end;
	uint8_t *in_start, *in_cur, *in_end;

	enum { WSIZE = 0x8000 }; // window size--must be a power of two
	uint8_t slide[WSIZE];

	static uint8_t GetByte(unz_explode* exploder)
	{
		return (exploder->in_cur < exploder->in_end ? *(exploder->in_cur++) : 0);
	}

	struct huft
	{
		// number of extra bits or operation, number of bits in this code or subcode
		uint8_t e, b;
		// literal, length base, or distance base || pointer to next level of table
		union { uint16_t n; huft *t; } v;
	};

	static void huft_free(huft *t)
	{
		for (huft *p = t, *q; p != (huft *)NULL; p = q)
		{
			q = (--p)->v.t;
			free(p);
		}
	}

	static int get_tree_build_huft(unz_explode* exploder, uint32_t *b, uint32_t n, uint32_t s, const uint16_t *d, const uint16_t *e, huft **t, int *m)
	{
		// Get the bit lengths for a code representation from the compressed stream.
		// If get_tree() returns 4, then there is an error in the data
		uint32_t bytes_remain;    // bytes remaining in list
		uint32_t lengths_entered; // lengths entered
		uint32_t ncodes;  // number of codes
		uint32_t bitlen; // bit length for those codes

		// get bit lengths
		bytes_remain = (uint32_t)GetByte(exploder) + 1; // length/count pairs to read
		lengths_entered = 0; // next code
		do
		{
			bitlen = ((ncodes = (uint32_t)GetByte(exploder)) & 0xf) + 1; //bits in code (1..16)
			ncodes = ((ncodes & 0xf0) >> 4) + 1; /* codes with those bits (1..16) */
			if (lengths_entered + ncodes > n) return UNZ_ERRCODE_INVALID_TREE_INPUT; // don't overflow bit_lengths
			do
			{
				b[lengths_entered++] = bitlen;
			} while (--ncodes);
		} while (--bytes_remain);
		if (lengths_entered != n) return UNZ_ERRCODE_INVALID_TREE_INPUT;

		// Mystery code, the original (huft_build function) wasn't much more readable IMHO (see inflate.c)
		// Given a list of code lengths and a maximum table size, make a set of tables to decode that set of codes.  Return zero on success, one if
		// the given code set is incomplete (the tables are still built in this case), two if the input is invalid (all zero length codes or an
		// oversubscribed set of lengths), and three if not enough memory.
		enum { BMAX = 16, N_MAX = 288 }; uint32_t a, c[BMAX + 1], f, i, j, *p, v[N_MAX], x[BMAX + 1], *xp, z; int g, h, k, l, w, y; huft *q, r, *u[BMAX];
		memset(c, 0, sizeof(c)); p = b; i = n; do { c[*p++]++; } while (--i); if (c[0] == n) { *t = (huft *)NULL; *m = 0; return UNZ_ERRCODE_OK; }
		l = *m; for (j = 1; j <= BMAX; j++) if (c[j]) break; k = j; if ((uint32_t)l < j) l = j; for (i = BMAX; i; i--) if (c[i]) break;
		g = i; if ((uint32_t)l > i) l = i; *m = l; for (y = 1 << j; j < i; j++, y <<= 1) if ((y -= c[j]) < 0) return UNZ_ERRCODE_INVALID_TABLE_INPUT;
		if ((y -= c[i]) < 0) { return UNZ_ERRCODE_INVALID_TABLE_INPUT; } c[i] += y; x[1] = j = 0; p = c + 1; xp = x + 2; while (--i) { *xp++ = (j += *p++); }
		p = b; i = 0; do { if ((j = *p++) != 0) v[x[j]++] = i; } while (++i < n); x[0] = i = 0; p = v; h = -1; w = -l;
		u[0] = (huft *)NULL; q = (huft *)NULL; z = 0; for (; k <= g; k++) { a = c[k]; while (a--) { while (k > w + l)
		{ h++; w += l; z = (z = g - w) > (uint32_t)l ? l : z; if ((f = 1 << (j = k - w)) > a + 1) { f -= a + 1; xp = c + k; while (++j < z)
		{ if ((f <<= 1) <= *++xp) break; f -= *xp; } } z = 1 << j; if ((q = (huft *)malloc((z + 1)*sizeof(huft))) == (huft *)NULL)
		{ if (h) huft_free(u[0]); return UNZ_ERRCODE_OUTOFMEMORY; } *t = q + 1; *(t = &(q->v.t)) = (huft *)NULL; u[h] = ++q; if (h)
		{ x[h] = i; r.b = (uint8_t)l; r.e = (uint8_t)(16 + j); r.v.t = q; j = i >> (w - l); u[h - 1][j] = r; } } r.b = (uint8_t)(k - w); if (p >= v + n) r.e = 99; else if (*p < s)
		{ r.e = (uint8_t)(*p < 256 ? 16 : 15); r.v.n = (uint16_t)*p++; } else
		{ r.e = (uint8_t)e[*p - s]; r.v.n = d[*p++ - s]; } f = 1 << (k - w); for (j = i >> w; j < z; j += f) q[j] = r; for (j = 1 << (k - 1);
		i & j; j >>= 1) { i ^= j; } i ^= j; while ((i & ((1 << w) - 1)) != x[h]) { h--; w -= l; } } }
		return (y == 0 || g == 1 ? UNZ_ERRCODE_OK : UNZ_ERRCODE_INCOMPLETE_SET);
	}

	static int flush(unz_explode* exploder, uint32_t w)
	{
		uint8_t *out_w = exploder->out_cur + w;
		int ret = (out_w > exploder->out_end ? 1 : 0);
		if (ret) out_w = exploder->out_end;
		memcpy(exploder->out_cur, exploder->slide, (out_w - exploder->out_cur));
		exploder->out_cur = out_w;
		return ret;
	}

	static int Run(unz_explode* exploder, uint16_t zip_bit_flag)
	{
		/* Tables for length and distance */
		static const uint16_t cplen2[]    = { 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65 };
		static const uint16_t cplen3[]    = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66 };
		static const uint16_t extra[]     = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8 };
		static const uint16_t cpdist4[]   = { 1, 65, 129, 193, 257, 321, 385, 449, 513, 577, 641, 705, 769, 833, 897, 961, 1025, 1089, 1153, 1217, 1281, 1345, 1409, 1473, 1537, 1601, 1665, 1729, 1793, 1857, 1921, 1985, 2049, 2113, 2177, 2241, 2305, 2369, 2433, 2497, 2561, 2625, 2689, 2753, 2817, 2881, 2945, 3009, 3073, 3137, 3201, 3265, 3329, 3393, 3457, 3521, 3585, 3649, 3713, 3777, 3841, 3905, 3969, 4033 };
		static const uint16_t cpdist8[]   = { 1, 129, 257, 385, 513, 641, 769, 897, 1025, 1153, 1281, 1409, 1537, 1665, 1793, 1921, 2049, 2177, 2305, 2433, 2561, 2689, 2817, 2945, 3073, 3201, 3329, 3457, 3585, 3713, 3841, 3969, 4097, 4225, 4353, 4481, 4609, 4737, 4865, 4993, 5121, 5249, 5377, 5505, 5633, 5761, 5889, 6017, 6145, 6273, 1, 6529, 6657, 6785, 6913, 7041, 7169, 7297, 7425, 7553, 7681, 7809, 7937, 8065 };
		static const uint16_t mask_bits[] = { 0x0000, 0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff, 0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff };

		huft *tb = NULL, *tl = NULL, *td = NULL; // literal code, length code, distance code tables
		uint32_t l[256]; // bit lengths for codes
		bool is8k  = ((zip_bit_flag & 2) == 2), islit = ((zip_bit_flag & 4) == 4);
		int bb = (islit ? 9 : 0), bl = 7, bd = ((exploder->in_end - exploder->in_start)  > 200000 ? 8 : 7); // bits for tb, tl, td
		uint32_t numbits = (is8k ? 7 : 6);

		int r;
		if (islit && (r = get_tree_build_huft(exploder, l, 256, 256, NULL, NULL, &tb, &bb)) != 0) goto done;
		if ((r = get_tree_build_huft(exploder, l, 64, 0, (islit ? cplen3 : cplen2), extra, &tl, &bl)) != 0) goto done;
		if ((r = get_tree_build_huft(exploder, l, 64, 0, (is8k ? cpdist8 : cpdist4), extra, &td, &bd)) != 0) goto done;

		// The implode algorithm uses a sliding 4K or 8K byte window on the uncompressed stream to find repeated byte strings.
		// This is implemented here as a circular buffer. The index is updated simply by incrementing and then and'ing with 0x0fff (4K-1) or 0x1fff (8K-1).
		// Here, the 32K buffer of inflate is used, and it works just as well to always have a 32K circular buffer, so the index is anded with 0x7fff.
		// This is done to allow the window to also be used as the output buffer.
		uint32_t s;          // bytes to decompress
		uint32_t e;          // table entry flag/number of extra bits
		uint32_t n, d;       // length and index for copy
		uint32_t w;          // current window position
		uint32_t mb, ml, md; // masks for bb (if lit), bl and bd bits
		uint32_t b;          // bit buffer
		uint32_t k;          // number of bits in bit buffer
		uint32_t u;          // true if unflushed
		huft *t;           // pointer to table entry

		#define UNZ_NEEDBITS(n) do {while(k<(n)){b|=((uint32_t)GetByte(exploder))<<k;k+=8;}} while(0)
		#define UNZ_DUMPBITS(n) do {b>>=(n);k-=(n);} while(0)

		// explode the coded data
		b = k = w = 0; // initialize bit buffer, window
		u = 1;         // buffer unflushed

		// precompute masks for speed
		mb = mask_bits[bb];
		ml = mask_bits[bl];
		md = mask_bits[bd];
		s = (uint32_t)(exploder->out_end - exploder->out_start);
		while (s > 0) // do until ucsize bytes uncompressed
		{
			UNZ_NEEDBITS(1);
			if (b & 1) // then literal
			{
				UNZ_DUMPBITS(1);
				s--;
				if (tb)
				{
					// LIT: Decompress the imploded data using coded literals and an 8K sliding window.
					UNZ_NEEDBITS((uint32_t)bb); // get coded literal
					if ((e = (t = tb + ((~(uint32_t)b) & mb))->e) > 16)
					{
						do
						{
							if (e == 99) { r = UNZ_ERRCODE_INTERNAL_ERROR; goto done; }
							UNZ_DUMPBITS(t->b);
							e -= 16;
							UNZ_NEEDBITS(e);
						} while ((e = (t = t->v.t + ((~(uint32_t)b) & mask_bits[e]))->e) > 16);
					}
					UNZ_DUMPBITS(t->b);
					exploder->slide[w++] = (uint8_t)t->v.n;
					if (w == WSIZE) { if (flush(exploder, w)) { r = UNZ_ERRCODE_OUTPUT_ERROR; goto done; } w = u = 0; }
				}
				else
				{
					// UNLIT: Decompress the imploded data using uncoded literals and an 8K sliding window.
					UNZ_NEEDBITS(8);
					exploder->slide[w++] = (uint8_t)b;
					if (w == WSIZE) { if (flush(exploder, w)) { r = UNZ_ERRCODE_OUTPUT_ERROR; goto done; } w = u = 0; }
					UNZ_DUMPBITS(8);
				}
			}
			else // else distance/length
			{
				UNZ_DUMPBITS(1);
				UNZ_NEEDBITS(numbits); // get distance low bits
				d = (uint32_t)b & ((1 << numbits) - 1);
				UNZ_DUMPBITS(numbits);
				UNZ_NEEDBITS((uint32_t)bd); // get coded distance high bits
				if ((e = (t = td + ((~(uint32_t)b) & md))->e) > 16)
				{
					do
					{
						if (e == 99) { r = UNZ_ERRCODE_INTERNAL_ERROR; goto done; }
						UNZ_DUMPBITS(t->b);
						e -= 16;
						UNZ_NEEDBITS(e);
					} while ((e = (t = t->v.t + ((~(uint32_t)b) & mask_bits[e]))->e) > 16);
				}
				UNZ_DUMPBITS(t->b);
				d = w - d - t->v.n; // construct offset
				UNZ_NEEDBITS((uint32_t)bl); // get coded length
				if ((e = (t = tl + ((~(uint32_t)b) & ml))->e) > 16)
				{
					do
					{
						if (e == 99) { r = UNZ_ERRCODE_INTERNAL_ERROR; goto done; }
						UNZ_DUMPBITS(t->b);
						e -= 16;
						UNZ_NEEDBITS(e);
					} while ((e = (t = t->v.t + ((~(uint32_t)b) & mask_bits[e]))->e) > 16);
				}
				UNZ_DUMPBITS(t->b);
				n = t->v.n;
				if (e) // get length extra bits
				{
					UNZ_NEEDBITS(8);
					n += (uint32_t)b & 0xff;
					UNZ_DUMPBITS(8);
				}

				// do the copy
				s -= n;
				do
				{
					n -= (e = (e = WSIZE - ((d &= WSIZE - 1) > w ? d : w)) > n ? n : e);
					if (u && w <= d)
					{
						memset(exploder->slide + w, 0, e);
						w += e;
						d += e;
					}
					else if (w - d >= e) // (this test assumes unsigned comparison)
					{
						memcpy(exploder->slide + w, exploder->slide + d, e);
						w += e;
						d += e;
					}
					else // do it slow to avoid memcpy() overlap
					{
						do {
							exploder->slide[w++] = exploder->slide[d++];
						} while (--e);
					}
					if (w == WSIZE)
					{
						if (flush(exploder, w)) { r = UNZ_ERRCODE_OUTPUT_ERROR; goto done; }
						w = u = 0;
					}
				} while (n);
			}
		}

		#undef UNZ_NEEDBITS
		#undef UNZ_DUMPBITS

		/* flush out slide */
		if (flush(exploder, w)) { r = UNZ_ERRCODE_OUTPUT_ERROR; goto done; }

		done:
		huft_free(td);
		huft_free(tl);
		huft_free(tb);
		return r;
	}
};

bool Zip_Archive::Unpack(uint64_t zf_data_ofs, uint32_t zf_comp_size, uint32_t zf_uncomp_size, uint8_t zf_bit_flags, uint8_t zf_method, std::vector<uint8_t>& mem_data)
{
	uint8_t local_header[ZIP_LOCAL_DIR_HEADER_SIZE];
	if (Read(zf_data_ofs, local_header, ZIP_LOCAL_DIR_HEADER_SIZE) != ZIP_LOCAL_DIR_HEADER_SIZE)
		return false;
	if (ZIP_READ_LE32(local_header) != ZIP_LOCAL_DIR_HEADER_SIG)
		return false;
	zf_data_ofs += ZIP_LOCAL_DIR_HEADER_SIZE + ZIP_READ_LE16(local_header + ZIP_LDH_FILENAME_LEN_OFS) + ZIP_READ_LE16(local_header + ZIP_LDH_EXTRA_LEN_OFS);
	if ((zf_data_ofs + zf_comp_size) > size)
		return false;

	mem_data.resize(zf_uncomp_size);
	if (!zf_uncomp_size) return true;
	else if (zf_method == METHOD_STORED)
	{
		Read(zf_data_ofs, &mem_data[0], zf_uncomp_size);
	}
	else if (zf_method == METHOD_DEFLATED)
	{
		miniz::tinfl_decompressor inflator;
		uint64_t pos = zf_data_ofs;
		uint32_t out_buf_ofs = 0, read_buf_avail = 0, read_buf_ofs = 0, comp_remaining = zf_comp_size;
		uint8_t read_buf[miniz::MZ_ZIP_MAX_IO_BUF_SIZE], *out_data = &mem_data[0];
		miniz::tinfl_init(&inflator);
		for (miniz::tinfl_status status = miniz::TINFL_STATUS_NEEDS_MORE_INPUT; status == miniz::TINFL_STATUS_NEEDS_MORE_INPUT || status == miniz::TINFL_STATUS_HAS_MORE_OUTPUT;)
		{
			if (!read_buf_avail)
			{
				read_buf_avail = (comp_remaining < miniz::MZ_ZIP_MAX_IO_BUF_SIZE ? comp_remaining : miniz::MZ_ZIP_MAX_IO_BUF_SIZE);
				if (Read(pos, read_buf, read_buf_avail) != read_buf_avail)
					break;
				pos += read_buf_avail;
				comp_remaining -= read_buf_avail;
				read_buf_ofs = 0;
			}
			uint32_t out_buf_size = zf_uncomp_size - out_buf_ofs;
			uint8_t *pWrite_buf_cur = out_data + out_buf_ofs;
			uint32_t in_buf_size = read_buf_avail;
			status = miniz::tinfl_decompress(&inflator, read_buf + read_buf_ofs, &in_buf_size, out_data, pWrite_buf_cur, &out_buf_size, miniz::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF | (comp_remaining ? miniz::TINFL_FLAG_HAS_MORE_INPUT : 0));
			read_buf_avail -= in_buf_size;
			read_buf_ofs += in_buf_size;
			out_buf_ofs += out_buf_size;
			ZIP_ASSERT(!out_buf_size || out_buf_ofs <= zf_uncomp_size);
			ZIP_ASSERT(status == miniz::TINFL_STATUS_NEEDS_MORE_INPUT || status == miniz::TINFL_STATUS_HAS_MORE_OUTPUT || status == miniz::TINFL_STATUS_DONE);
		}
	}
	else if (zf_method == METHOD_SHRUNK)
	{
		oz_unshrink *unshrink = (oz_unshrink*)malloc(sizeof(oz_unshrink) + zf_comp_size);
		uint8_t* in_buf = (uint8_t*)(unshrink + 1);
		if (Read(zf_data_ofs, in_buf, zf_comp_size) == zf_comp_size)
		{
			mem_data.resize(zf_uncomp_size);
			unshrink->in_start = unshrink->in_cur = in_buf;
			unshrink->in_end = in_buf + zf_comp_size;
			unshrink->out_start = unshrink->out_cur = &mem_data[0];
			unshrink->out_end = unshrink->out_start + zf_uncomp_size;
			#ifndef NDEBUG
			int res =
			#endif
			oz_unshrink::Run(unshrink);
			ZIP_ASSERT(res == 0);
		}
		free(unshrink);
	}
	else if (zf_method == METHOD_IMPLODED)
	{
		unz_explode *explode = (unz_explode*)malloc(sizeof(unz_explode) + zf_comp_size);
		uint8_t* in_buf = (uint8_t*)(explode + 1);
		if (Read(zf_data_ofs, in_buf, zf_comp_size) == zf_comp_size)
		{
			mem_data.resize(zf_uncomp_size);
			explode->in_start = explode->in_cur = in_buf;
			explode->in_end = in_buf + zf_comp_size;
			explode->out_start = explode->out_cur = &mem_data[0];
			explode->out_end = explode->out_start + zf_uncomp_size;
			#ifndef NDEBUG
			int res =
			#endif
			unz_explode::Run(explode, zf_bit_flags);
			ZIP_ASSERT(res == 0);
		}
		free(explode);
	}
	else { mem_data.clear(); return false; }
	return true;
}
