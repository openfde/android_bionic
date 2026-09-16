#include "linker_adapter.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "dl_cache.h"
#include "linker_debug.h"
#include "linker_globals.h"
#include "linker_main.h"
#include "linker_soinfo.h"
#include "linker_utils.h"
#include "private/CachedProperty.h"

static const char kHybrisLibPathEnvName[] = "HYBRIS_LD_LIBRARY_PATH";
static const char kHybrisRoLibraryPath[] = "ro.hybris.library_path";
static const char kEGLType[] = "ro.hardware.graphics.egl";

static const char kSymbolName[] = "find_symbol_adapter";
static const char kAdapterSoName[] = "libglibc-adapter.so";

static const char kLibcSoName[] = "libc.so";
static const char kPthreadSoName[] = "libpthread.so.0";
static const char kGlibcSoName[] = "libc.so.6";
static const char kDlSoName[] = "libdl.so.2";

namespace {

static const char* const kHybrisDefaultLdPaths[] = {
    "/usr/lib/aarch64-linux-gnu/",
    "/usr/lib/x86_64-linux-gnu/",
    "/usr/lib/",
    "/usr/lib64/"
    "/lib/aarch64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    "/lib/",
    "/lib64/",
    nullptr};

void ParsePath(const char* path, const char* delimiters,
               std::vector<std::string>* resolved_paths) {
  std::vector<std::string> paths;
  split_path(path, delimiters, &paths);
  resolve_paths(paths, resolved_paths);
}

std::vector<std::string> ParseHybrisLibraryPath(const char* path) {
  std::vector<std::string> ld_libary_paths;
  ParsePath(path, ":", &ld_libary_paths);
  return ld_libary_paths;
}

std::vector<std::string> InitDefaultPath() {
  auto default_ld_paths = kHybrisDefaultLdPaths;

  char real_path[PATH_MAX];
  std::set<std::string> default_paths;
  for (size_t i = 0; default_ld_paths[i] != nullptr; ++i) {
    if (realpath(default_ld_paths[i], real_path) != nullptr) {
      default_paths.emplace(real_path);
    }
  }

  std::vector<std::string> ld_default_paths;
  std::copy(default_paths.cbegin(), default_paths.cend(),
            std::back_inserter(ld_default_paths));
  return ld_default_paths;
}

}  // namespace

bool LinkerAdapter::LoadAdapter() {
  if (!is_hybris_env) {
    return false;
  }
  if (adapter_si_) {
    return true;
  }
  assert(si->get_primary_namespace() == GetGnuNamespace());
  auto name = kAdapterSoName;
  soinfo* si = nullptr;
  if (!find_libraries(&g_default_namespace, nullptr, &name, 1, &si, nullptr, 0,
                      RTLD_GLOBAL, nullptr, false, nullptr)) {
    std::vector<std::string> ld_libary_paths = g_default_namespace.get_default_library_paths();
    // fix load libglibc-adapter.so fail
    ld_libary_paths.emplace_back("/vendor/lib64");
    g_default_namespace.set_default_library_paths(std::move(ld_libary_paths));

    if (!find_libraries(&g_default_namespace, nullptr, &name, 1, &si, nullptr, 0,
                      RTLD_GLOBAL, nullptr, false, nullptr)) {
      DL_WARN("Cannot load gnu library : %s", linker_get_error_buffer());
      return false;
    }
  }
  return InitAdapter(si);
}

bool LinkerAdapter::IsAdaptee(const soinfo* si) const {
  return glibc_adaptee_ == si || pthread_adaptee_ == si || dl_adaptee_ == si;
}

ElfW(Addr) LinkerAdapter::FindSymbolByAdapter(const char* name,
                                              soinfo** si_found_in,
                                              const ElfW(Sym) * *sym) {
  if (!is_hybris_env) {
    return 0;
  }
  auto si = *si_found_in;
  if (!finder_ || !si) {
    // nothing to do
    return 0;
  }

  auto soname = si->get_soname();
  if (!soname) {
    return 0;
  }

  if (!IsAdaptee(si)) {
    return 0;
  }

  const void* addr = nullptr;
  if ((addr = finder_(name))) {
    *sym = nullptr;
    *si_found_in = adapter_si_;
    if (auto local_sym = libc_si_->find_symbol_by_address(addr)) {
      // symbol address in bionic libc.so.
      *si_found_in = libc_si_;
      *sym = local_sym;
    }
  }
  return reinterpret_cast<ElfW(Addr)>(addr);
}

bool LinkerAdapter::InitAdapter(soinfo* si) {
  if (si->get_soname() && strcmp(kAdapterSoName, si->get_soname()) == 0) {
    SymbolName symbol_name{kSymbolName};
    const ElfW(Sym)* local_sym = si->find_symbol_by_name(symbol_name, nullptr);
    if (local_sym) {
      ElfW(Addr) addr = si->resolve_symbol_address(local_sym);
      if (addr) {
        for (auto child : si->get_children()) {
          // get bionic libc.so library.
          if (child->get_soname() &&
              strcmp(kLibcSoName, child->get_soname()) == 0) {
            libc_si_ = child;
            finder_ = reinterpret_cast<FindSymbolAdapter>(addr);
            adapter_si_ = si;
            return true;
          }
        }
      }
    }
  }
  return false;
}

LinkerAdapter* LinkerAdapter::Instance() {
  static LinkerAdapter adapter{};
  return &adapter;
}

void LinkerAdapter::InitGnuAdaptee(soinfo* si) {
  if (!is_hybris_env) {
    return ;
  }
  if (!finder_ || !si || si->get_primary_namespace() != GetGnuNamespace()) {
    // nothing to do
    return;
  }

  auto soname = si->get_soname();
  if (!soname) {
    return;
  }

  if (!glibc_adaptee_ && strcmp(kGlibcSoName, soname) == 0) {
    glibc_adaptee_ = si;
  }

  if (!pthread_adaptee_ && strcmp(kPthreadSoName, soname) == 0) {
    pthread_adaptee_ = si;
  }

  if (!dl_adaptee_ && strcmp(kDlSoName, soname) == 0) {
    dl_adaptee_ = si;
  }
}

void LinkerAdapter::DeinitGnuAdaptee(soinfo* si) {
  if (!is_hybris_env) {
    return ;
  }
  if (dl_adaptee_ == si) {
    dl_adaptee_ = nullptr;
  } else if (pthread_adaptee_ == si) {
    pthread_adaptee_ = nullptr;
  } else if (glibc_adaptee_ == si) {
    glibc_adaptee_ = nullptr;
  }
}

const char* LinkerAdapter::GnuLoadCacheLookup(android_namespace_t* ns,
                                              const char* name) {
  if (!is_hybris_env) {
    CachedProperty egl_type_prop{kEGLType};
    if (auto type = egl_type_prop.Get(); type != nullptr) {
      if (strcmp(type, "proxy") == 0) {
        is_hybris_env = true;
      } else {
        is_hybris_env = false;
      }
    }
    if (!is_hybris_env)
      return nullptr;
  }
  if (ns != GetGnuNamespace()) {
    return nullptr;
  }

  auto best = DlCache::Instance()->Search(name);
  if (!best) {
    return nullptr;
  }

  size_t best_len = strlen(best) + 1;
  auto temp = reinterpret_cast<char*>(alloca(best_len));
  memcpy(temp, best, best_len);
  return strdup(temp);
}

android_namespace_t* LinkerAdapter::GetGnuNamespace() {
  if (!is_hybris_env) {
    return nullptr;
  }
  if (gnu_ns_inited_) {
    return &gnu_namespace_;
  }

  std::vector<std::string> hybris_library_paths;
  if (!getauxval(AT_SECURE)) {
    // use LD_HYBRIS_LIBRARY_PATH
    if (auto hybris_lib_path = getenv(kHybrisLibPathEnvName); hybris_lib_path) {
      hybris_library_paths = ParseHybrisLibraryPath(hybris_lib_path);
    }
  }

  {
    CachedProperty library_path_prop{kHybrisRoLibraryPath};
    if (auto path = library_path_prop.Get(); path != nullptr) {
      if (auto paths = ParseHybrisLibraryPath(path); !paths.empty()) {
        if (hybris_library_paths.empty()) {
          std::swap(paths, hybris_library_paths);
        } else {
          std::move(paths.begin(), paths.end(),
                    std::back_inserter(hybris_library_paths));
        }
      }
    }
  }

  if (!hybris_library_paths.empty()) {
    gnu_namespace_.set_ld_library_paths(std::move(hybris_library_paths));
  }

  // default library
  auto default_lib_paths = InitDefaultPath();
  gnu_namespace_.set_default_library_paths(default_lib_paths);

  gnu_ns_inited_ = true;
  return &gnu_namespace_;
}

bool LinkerAdapter::IsEnabledHybris() {
  return is_hybris_env;
}

bool LinkerAdapter::IsGnuNamesSpace(soinfo* si) {
  return (si->get_primary_namespace() == GetGnuNamespace());
}