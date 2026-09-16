#include "dl_cache.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <vector>

namespace {

constexpr char kHybrisLdSoCacheEnvName[] = "HYBRIS_LD_SO_CACHE";
constexpr char kCacheMagicNew[] = "glibc-ld.so.cache";
constexpr char kCacheVersion[] = "1.1";

struct FileEntryNew {
  int32_t flags;       /* This is 1 for an ELF library.  */
  uint32_t key, value; /* String table indices.  */

  uint32_t osversion_unused; /* Required OS version (unused).  */
  uint64_t hwcap;            /* Hwcap entry.	 */
};

struct CacheFileNew {
  char magic[sizeof kCacheMagicNew - 1];
  char version[sizeof kCacheVersion - 1];
  uint32_t nlibs;       /* Number of entries.  */
  uint32_t len_strings; /* Size of string table. */

  /* flags & cache_file_new_flags_endian_mask is one of the values
     cache_file_new_flags_endian_unset, cache_file_new_flags_endian_invalid,
     cache_file_new_flags_endian_little, cache_file_new_flags_endian_big.

     The remaining bits are unused and should be generated as zero and
     ignored by readers.  */
  uint8_t flags;

  uint8_t padding_unsed[3]; /* Not used, for future extensions.  */

  /* File offset of the extension directory.  See struct
     cache_extension below.  Must be a multiple of four.  */
  uint32_t extension_offset;

  uint32_t unused[3];          /* Leave space for future extensions
                  and align to 8 byte boundary.  */
  struct FileEntryNew libs[0]; /* Entries describing libraries.  */
  /* After this the string table of size len_strings is found.	*/
};

int32_t OpenLdSoCache(int32_t flags) {
  std::vector<std::string> ld_so_caches{"/hybris/etc/ld.so.cache", "/etc/ld.so.cache"};
  if (!getauxval(AT_SECURE)) {
    // use LD_HYBRIS_LIBRARY_PATH
    if (auto hybris_ld_so_cache = getenv(kHybrisLdSoCacheEnvName); hybris_ld_so_cache) {
      ld_so_caches.clear();
      ld_so_caches.emplace_back(hybris_ld_so_cache);
    }
  }

  for (auto const& ld_so_cache : ld_so_caches) {
    if (auto fd = open(ld_so_cache.c_str(), flags); fd >= 0) {
      return fd;
    }
  }
  return -1;
}

}  // namespace

DlCache::DlCache() {
  endian_ =
      ((__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) ? FlagsEndianE::kLittle : FlagsEndianE::kBig);

#if defined(__aarch64__)
#define FLAG_ELF_LIBC6 0x0003
#define FLAG_AARCH64_LIB64 0x0a00
#define _DL_CACHE_DEFAULT_ID (FLAG_AARCH64_LIB64 | FLAG_ELF_LIBC6)
#elif defined(__x86_64__)
#define _DL_CACHE_DEFAULT_ID 0x303
#elif defined(__arm__)
#elif defined(__i386__)
#endif

#ifndef _DL_CACHE_DEFAULT_ID
#define _DL_CACHE_DEFAULT_ID 3
#endif
  flag_default_id_ = _DL_CACHE_DEFAULT_ID;

#undef _DL_CACHE_DEFAULT_ID

  Load();
}

DlCache::~DlCache() {
  if (cache_new_) {
    munmap(cache_new_, cache_size_);
  }
}

DlCache* DlCache::Instance() {
  static DlCache dl_cache;
  return &dl_cache;
}

bool DlCache::MatchesEndian(const CacheFileNew* cache) const {
  auto endian = static_cast<FlagsEndianE>(cache->flags & static_cast<int32_t>(FlagsEndianE::kBig));
  return cache->flags == 0 || (endian == endian_);
}

bool DlCache::CheckFlags(int32_t flags) const {
  return flags == flag_default_id_;
}

bool DlCache::Load() {
  /* Read the contents of the file.  */
  size_t cache_size = {};
  CacheFileNew* file{};

  if (int fd = OpenLdSoCache(O_RDONLY | O_CLOEXEC); fd >= 0) {
    struct stat64 st;
    if (fstat64(fd, &st) >= 0) {
      cache_size = st.st_size;
      /* No need to map the file if it is empty.  */
      if (cache_size != 0) {
        if (auto result = mmap(nullptr, cache_size, PROT_READ, MAP_PRIVATE, fd, 0);
            result != MAP_FAILED) {
          file = reinterpret_cast<CacheFileNew*>(result);
        } else {
          close(fd);
          return false;
        }
      }
    }
    close(fd);
  } else {
    return false;
  }

  bool integrity = (cache_size > sizeof(*file));
  integrity &= (((cache_size - sizeof(*file)) / sizeof(FileEntryNew)) >= file->nlibs);
  integrity &= (memcmp(file->magic, kCacheMagicNew, sizeof(file->magic)) == 0);
  integrity &= (memcmp(file->version, kCacheVersion, sizeof(file->version)) == 0);
  integrity &= MatchesEndian(file);
  if (!integrity) {
    munmap(file, cache_size);
    return false;
  }
  cache_size_ = cache_size;
  cache_new_ = file;
  return true;
}

int32_t DlCache::LibCmp(const char* p1, const char* p2) {
  while (*p1 != '\0') {
    if (*p1 >= '0' && *p1 <= '9') {
      if (*p2 >= '0' && *p2 <= '9') {
        /* Must compare this numerically.  */
        int val1;
        int val2;

        val1 = *p1++ - '0';
        val2 = *p2++ - '0';
        while (*p1 >= '0' && *p1 <= '9') val1 = val1 * 10 + *p1++ - '0';
        while (*p2 >= '0' && *p2 <= '9') val2 = val2 * 10 + *p2++ - '0';
        if (val1 != val2) return val1 - val2;
      } else
        return 1;
    } else if (*p2 >= '0' && *p2 <= '9')
      return -1;
    else if (*p1 != *p2)
      return *p1 - *p2;
    else {
      ++p1;
      ++p2;
    }
  }
  return *p1 - *p2;
}

const char* DlCache::Search(const char* name) const {
  int32_t left = 0;
  int32_t right = cache_new_->nlibs - 1;
  const char* best = nullptr;
  ;
  auto string_table = reinterpret_cast<const char*>(cache_new_);
  auto cache_entries = reinterpret_cast<const FileEntryNew*>(cache_new_ + 1);

  while (left <= right) {
    auto middle = (left + right) / 2;
    auto key = cache_entries[middle].key;
    /* Make sure string table indices are not bogus before using them.  */
    if (!VerifyPtr(key)) {
      return nullptr;
    }

    /* Actually compare the entry with the key.  */
    auto cmpres = LibCmp(name, string_table + key);
    if (cmpres == 0) {
      /* Found it.  LEFT now marks the last entry for which we
         know the name is correct.  */
      left = middle;

      /* There might be entries with this name before the one we
         found.  So we have to find the beginning.  */
      while (middle > 0) {
        auto key = cache_entries[middle - 1].key;
        /* Make sure string table indices are not bogus before
           using them.  */
        if (!VerifyPtr(key) || LibCmp(name, string_table + key) != 0) {
          break;
        }
        --middle;
      }

      do {
        auto lib = cache_entries + middle;
        if (middle > left &&
            (!VerifyPtr(lib->key) || (LibCmp(name, string_table + lib->key) != 0))) {
          break;
        }

        auto flags = lib->flags;
        if (CheckFlags(flags) && VerifyPtr(lib->value)) {
          if (best != nullptr) {
            break;
          }
          best = string_table + lib->value;
          if (flags == flag_default_id_) {
            break;
          }
        }
      } while (++middle <= right);
      break;
    }

    if (cmpres < 0)
      left = middle + 1;
    else
      right = middle - 1;
  }

  return best;
}
