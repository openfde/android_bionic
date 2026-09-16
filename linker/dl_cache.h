#pragma once

#include <cstdint>

namespace{
struct CacheFileNew;
}

class DlCache {
 public:
  static DlCache* Instance();

  const char* Search(const char* name) const;

 private:
  DlCache();
  ~DlCache();

  enum class FlagsEndianE : int32_t {
    kUnset = 0,
    kInvalid,
    kLittle,
    kBig,
  };

  bool Load();
  bool MatchesEndian(const CacheFileNew* cache) const;
  bool VerifyPtr(uint32_t ptr) const { return ptr < cache_size_; }
  bool CheckFlags(int32_t flags) const;

  static int32_t LibCmp(const char* p1, const char* p2);

  CacheFileNew* cache_new_ = {};
  size_t cache_size_ = {};
  FlagsEndianE endian_ = FlagsEndianE::kUnset;
  int32_t flag_default_id_ = {};
};
