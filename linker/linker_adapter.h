#pragma once

#include <link.h>

#include <string>
#include <vector>

#include "linker_namespaces.h"

struct android_namespace_t;
struct soinfo;

class LinkerAdapter {
 public:
  // call LoadAdapter after setup executable static tls
  bool LoadAdapter();

  // call FindSymbolByAdapter after lookup symbol successfully
  // si_found_in, sym are input/output argument
  ElfW(Addr) FindSymbolByAdapter(const char* name, soinfo** si_found_in,
                                 const ElfW(Sym) * *sym);

  static LinkerAdapter* Instance();

  bool IsAdaptee(const soinfo* si) const;

  void InitGnuAdaptee(soinfo* si);
  void DeinitGnuAdaptee(soinfo* si);
  const char* GnuLoadCacheLookup(android_namespace_t* ns, const char* name);

  android_namespace_t* GetGnuNamespace();

  bool IsEnabledHybris();
  bool IsGnuNamesSpace(soinfo* si);

 private:
  using FindSymbolAdapter = const void* (*)(const char*);

  bool InitAdapter(soinfo* si);

  LinkerAdapter() = default;

  soinfo* adapter_si_ = nullptr;
  soinfo* libc_si_ = nullptr;
  soinfo* glibc_adaptee_ = nullptr;
  soinfo* pthread_adaptee_ = nullptr;
  soinfo* dl_adaptee_ = nullptr;
  FindSymbolAdapter finder_ = nullptr;

  android_namespace_t gnu_namespace_;
  bool gnu_ns_inited_ = false;
  bool is_hybris_env = false;
};
