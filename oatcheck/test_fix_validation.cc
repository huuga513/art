/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <set>
#include <tuple>
#include <memory>
#include <map>
#include <optional>
#include <sstream>

#include "base/hex_dump.h"
#include "cmdline.h"
#include "dex/class_accessor-inl.h"
#include "dex/class_accessor.h"
#include "dex/dex_file.h"
#include "disassembler.h"
#include "oat/oat_file.h"
#include "oat/oat_file-inl.h"
#include "oat/oat_quick_method_header.h"

namespace art {

// Helper function to validate OAT file and check disabled methods
class OatFileValidator {
 public:
  explicit OatFileValidator(const std::string& oat_file_path) : oat_file_path_(oat_file_path) {}

  // Validate the OAT file and collect all method code offsets
  bool Validate(std::string* error_msg) {
    oat_file_.reset(OatFile::Open(/* zip_fd */ -1,
                                  oat_file_path_,
                                  oat_file_path_,
                                  /* executable */ false,
                                  /* low_4gb */ false,
                                  error_msg));
    if (oat_file_ == nullptr) {
      return false;
    }

    // Collect all method info
    size_t dex_file_count = oat_file_->GetOatDexFiles().size();
    std::cout << "OAT file has " << dex_file_count << " DEX files\n";

    for (size_t i = 0; i < dex_file_count; ++i) {
      const OatDexFile* oat_dex_file = oat_file_->GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }

      std::string dex_error_msg;
      std::unique_ptr<const DexFile> dex_file = oat_dex_file->OpenDexFile(&dex_error_msg);
      if (dex_file == nullptr) {
        std::cout << "Warning: Failed to open DexFile: " << dex_error_msg << "\n";
        continue;
      }

      for (ClassAccessor accessor : dex_file->GetClasses()) {
        const uint16_t class_def_index = accessor.GetClassDefIndex();
        const OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
        uint32_t class_method_index = 0;

        for (const ClassAccessor::Method& method : accessor.GetMethods()) {
          const OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
          class_method_index++;

          // Get code_offset first - if it's 0, the method is disabled
          uint32_t code_offset = oat_method.GetCodeOffset();

          // Check if method has compiled code via method_header
          const OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
          if (method_header == nullptr || method_header->GetCodeSize() == 0) {
            continue;  // Method doesn't have compiled code
          }

          MethodInfo info;
          info.dex_file_idx = i;
          info.class_def_idx = class_def_index;
          info.method_idx = method.GetIndex();
          info.code_offset = code_offset;
          info.code_ptr = method_header->GetCode();
          info.code_size = method_header->GetCodeSize();
          info.is_compiled = true;

          methods_.push_back(info);
        }
      }
    }

    std::cout << "Total compiled methods: " << methods_.size() << "\n";
    return true;
  }

  struct MethodInfo {
    size_t dex_file_idx;
    uint16_t class_def_idx;
    uint32_t method_idx;
    uint32_t code_offset;
    // New fields for code comparison
    const uint8_t* code_ptr = nullptr;
    uint32_t code_size = 0;
    bool is_compiled = false;
  };

  // Get all methods with code_offset == 0
  std::vector<MethodInfo> GetDisabledMethods() const {
    std::vector<MethodInfo> disabled;
    for (const auto& method : methods_) {
      if (method.code_offset == 0) {
        disabled.push_back(method);
      }
    }
    return disabled;
  }

  const std::vector<MethodInfo>& GetMethods() const { return methods_; }

  OatFile* GetOatFile() const { return oat_file_.get(); }

 private:
  std::string oat_file_path_;
  std::unique_ptr<OatFile> oat_file_;
  std::vector<MethodInfo> methods_;
};

// Code difference structure
struct CodeDifference {
  size_t dex_file_idx;
  uint16_t class_def_idx;
  uint32_t method_idx;
  std::string method_name;
  std::string class_name;
  uint32_t diff_offset = 0;
  uint32_t fixed_byte = 0;
  uint32_t orig_byte = 0;
  uint32_t fixed_size = 0;
  uint32_t orig_size = 0;
  bool size_differs = false;
  enum class Status { kIdentical, kDifferent, kOnlyInFixed, kOnlyInOriginal };
  Status status = Status::kIdentical;
};

// Code comparison result class
class CodeComparisonResult {
 public:
  void AddDifference(const CodeDifference& diff) {
    differences_.push_back(diff);
    if (diff.status != CodeDifference::Status::kIdentical) {
      has_differences_ = true;
    }
  }

  bool HasDifferences() const { return has_differences_; }

  size_t CountIdentical() const {
    size_t count = 0;
    for (const auto& d : differences_) {
      if (d.status == CodeDifference::Status::kIdentical) {
        count++;
      }
    }
    return count;
  }

  size_t CountDifferent() const {
    size_t count = 0;
    for (const auto& d : differences_) {
      if (d.status == CodeDifference::Status::kDifferent) {
        count++;
      }
    }
    return count;
  }

  size_t CountOnlyInFixed() const {
    size_t count = 0;
    for (const auto& d : differences_) {
      if (d.status == CodeDifference::Status::kOnlyInFixed) {
        count++;
      }
    }
    return count;
  }

  size_t CountOnlyInOriginal() const {
    size_t count = 0;
    for (const auto& d : differences_) {
      if (d.status == CodeDifference::Status::kOnlyInOriginal) {
        count++;
      }
    }
    return count;
  }

  const std::vector<CodeDifference>& GetDifferences() const { return differences_; }

 private:
  std::vector<CodeDifference> differences_;
  bool has_differences_ = false;
};

// Helper functions for code comparison
static bool CollectMethodsWithCode(OatFile* oat_file,
                                   std::vector<OatFileValidator::MethodInfo>* methods,
                                   std::string* /*error_msg*/) {
  size_t dex_file_count = oat_file->GetOatDexFiles().size();

  for (size_t i = 0; i < dex_file_count; ++i) {
    const OatDexFile* oat_dex_file = oat_file->GetOatDexFiles()[i];
    if (oat_dex_file == nullptr) {
      continue;
    }

    std::string dex_error_msg;
    std::unique_ptr<const DexFile> dex_file = oat_dex_file->OpenDexFile(&dex_error_msg);
    if (dex_file == nullptr) {
      continue;
    }

    for (ClassAccessor accessor : dex_file->GetClasses()) {
      const uint16_t class_def_index = accessor.GetClassDefIndex();
      const OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
      uint32_t class_method_index = 0;

      for (const ClassAccessor::Method& method : accessor.GetMethods()) {
        const OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
        class_method_index++;

        uint32_t code_offset = oat_method.GetCodeOffset();
        const OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
        if (method_header == nullptr || method_header->GetCodeSize() == 0) {
          continue;
        }

        OatFileValidator::MethodInfo info;
        info.dex_file_idx = i;
        info.class_def_idx = class_def_index;
        info.method_idx = method.GetIndex();
        info.code_offset = code_offset;
        info.code_ptr = method_header->GetCode();
        info.code_size = method_header->GetCodeSize();
        info.is_compiled = true;

        methods->push_back(info);
      }
    }
  }
  return true;
}

static uint64_t ComputeMethodKey(const OatFileValidator::MethodInfo& m) {
  return (static_cast<uint64_t>(m.dex_file_idx) << 48) |
         (static_cast<uint64_t>(m.class_def_idx) << 32) |
         static_cast<uint64_t>(m.method_idx);
}

static std::optional<CodeDifference> CompareMethodCode(
    const OatFileValidator::MethodInfo& fixed_method,
    const OatFileValidator::MethodInfo& orig_method,
    const DexFile* fixed_dex_file,
    const DexFile* /*orig_dex_file*/) {

  CodeDifference diff;
  diff.dex_file_idx = fixed_method.dex_file_idx;
  diff.class_def_idx = fixed_method.class_def_idx;
  diff.method_idx = fixed_method.method_idx;

  if (fixed_dex_file != nullptr) {
    if (fixed_method.method_idx < fixed_dex_file->NumMethodIds()) {
      diff.method_name = fixed_dex_file->GetMethodName(fixed_dex_file->GetMethodId(fixed_method.method_idx));
    }
    if (fixed_method.class_def_idx < fixed_dex_file->NumClassDefs()) {
      const dex::ClassDef& class_def = fixed_dex_file->GetClassDef(fixed_method.class_def_idx);
      std::string_view descriptor = fixed_dex_file->GetTypeDescriptorView(class_def.class_idx_);
      diff.class_name = std::string(descriptor);
    }
  }

  diff.fixed_size = fixed_method.code_size;
  diff.orig_size = orig_method.code_size;

  if (fixed_method.code_size == orig_method.code_size &&
      fixed_method.code_ptr != nullptr && orig_method.code_ptr != nullptr &&
      memcmp(fixed_method.code_ptr, orig_method.code_ptr, fixed_method.code_size) == 0) {
    diff.status = CodeDifference::Status::kIdentical;
    return std::nullopt;
  }

  diff.status = CodeDifference::Status::kDifferent;

  if (fixed_method.code_size != orig_method.code_size) {
    diff.size_differs = true;
  }

  uint32_t min_size = std::min(fixed_method.code_size, orig_method.code_size);
  uint32_t offset = 0;
  if (fixed_method.code_ptr != nullptr && orig_method.code_ptr != nullptr) {
    while (offset < min_size) {
      if (fixed_method.code_ptr[offset] != orig_method.code_ptr[offset]) {
        break;
      }
      offset++;
    }
  }

  if (offset < min_size) {
    diff.diff_offset = offset;
    diff.fixed_byte = fixed_method.code_ptr[offset];
    diff.orig_byte = orig_method.code_ptr[offset];
  }

  return diff;
}

static CodeComparisonResult CompareOatFiles(
    OatFile* fixed_oat,
    OatFile* orig_oat,
    const std::string& /*fixed_path*/,
    const std::string& /*orig_path*/,
    std::string* error_msg) {

  CodeComparisonResult result;

  std::vector<OatFileValidator::MethodInfo> fixed_methods, orig_methods;

  if (!CollectMethodsWithCode(fixed_oat, &fixed_methods, error_msg)) {
    return result;
  }
  if (!CollectMethodsWithCode(orig_oat, &orig_methods, error_msg)) {
    return result;
  }

  std::map<uint64_t, const OatFileValidator::MethodInfo*> orig_method_map;
  for (const auto& m : orig_methods) {
    orig_method_map[ComputeMethodKey(m)] = &m;
  }

  for (const auto& fixed_method : fixed_methods) {
    uint64_t key = ComputeMethodKey(fixed_method);
    auto it = orig_method_map.find(key);

    if (it == orig_method_map.end()) {
      CodeDifference diff;
      diff.dex_file_idx = fixed_method.dex_file_idx;
      diff.class_def_idx = fixed_method.class_def_idx;
      diff.method_idx = fixed_method.method_idx;
      diff.status = CodeDifference::Status::kOnlyInFixed;
      result.AddDifference(diff);
    } else {
      const OatFileValidator::MethodInfo* orig_method = it->second;

      const OatDexFile* fixed_oat_dex = fixed_oat->GetOatDexFiles()[fixed_method.dex_file_idx];
      const OatDexFile* orig_oat_dex = orig_oat->GetOatDexFiles()[orig_method->dex_file_idx];

      std::unique_ptr<const DexFile> fixed_dex, orig_dex;
      if (fixed_oat_dex != nullptr) {
        std::string dex_err;
        fixed_dex = fixed_oat_dex->OpenDexFile(&dex_err);
      }
      if (orig_oat_dex != nullptr) {
        std::string dex_err;
        orig_dex = orig_oat_dex->OpenDexFile(&dex_err);
      }

      auto diff = CompareMethodCode(fixed_method, *orig_method, fixed_dex.get(), orig_dex.get());
      if (diff.has_value()) {
        result.AddDifference(*diff);
      } else {
        CodeDifference identical_diff;
        identical_diff.dex_file_idx = fixed_method.dex_file_idx;
        identical_diff.class_def_idx = fixed_method.class_def_idx;
        identical_diff.method_idx = fixed_method.method_idx;
        identical_diff.status = CodeDifference::Status::kIdentical;
        result.AddDifference(identical_diff);
      }
      orig_method_map.erase(it);
    }
  }

  for (const auto& [key, orig_method] : orig_method_map) {
    CodeDifference diff;
    diff.dex_file_idx = orig_method->dex_file_idx;
    diff.class_def_idx = orig_method->class_def_idx;
    diff.method_idx = orig_method->method_idx;
    diff.status = CodeDifference::Status::kOnlyInOriginal;
    result.AddDifference(diff);
  }

  return result;
}

}  // namespace art

struct TestFixValidationArgs : public art::CmdlineArgs {
 protected:
  using Base = art::CmdlineArgs;

 public:
  char const* fixed_oat_file_ = nullptr;
  char const* original_oat_file_ = nullptr;
  bool compare_code_ = false;
  uint32_t max_diffs_ = 100;
  bool show_hex_dumps_ = true;
  bool show_disasm_ = true;

  ParseStatus ParseCustom(const char* raw_option,
                          size_t raw_option_length,
                          std::string* error_msg) override {
    std::string_view option(raw_option, raw_option_length);

    if (option.starts_with("--fixed-oat=")) {
      fixed_oat_file_ = raw_option + strlen("--fixed-oat=");
    } else if (option.starts_with("--original-oat=")) {
      original_oat_file_ = raw_option + strlen("--original-oat=");
    } else if (option == "--compare-code") {
      compare_code_ = true;
    } else if (option.starts_with("--max-diffs=")) {
      max_diffs_ = std::atoi(raw_option + strlen("--max-diffs="));
    } else if (option == "--hex-dumps") {
      show_hex_dumps_ = true;
    } else if (option == "--no-hex-dumps") {
      show_hex_dumps_ = false;
    } else if (option == "--disasm") {
      show_disasm_ = true;
    } else if (option == "--no-disasm") {
      show_disasm_ = false;
    } else {
      return Base::ParseCustom(raw_option, raw_option_length, error_msg);
    }
    return kParseOk;
  }

  void PrintUsage() {
    std::cerr << "Usage: " << "test_prog" << " [options]\n";
    std::cerr << "  --fixed-oat=<file>       Path to the fixed OAT file\n";
    std::cerr << "  --original-oat=<file>   Path to the original OAT file for comparison\n";
    std::cerr << "  --compare-code          Compare machine code byte-by-byte\n";
    std::cerr << "  --max-diffs=N           Maximum differences to show (default 100)\n";
    std::cerr << "  --hex-dumps / --no-hex-dumps  Show/hide hex dumps (default show)\n";
    std::cerr << "  --disasm / --no-disasm  Show/hide ARM64 disassembly (default show)\n";
    Base::PrintUsage();
  }
};

struct TestFixValidationMain : public art::CmdlineMain<TestFixValidationArgs> {
  bool ExecuteWithoutRuntime() override {
    std::cerr << "This tool requires ART runtime.\n";
    return false;
  }

  bool ExecuteWithRuntime(ATTRIBUTE_UNUSED art::Runtime* runtime) override {
    if (args_->fixed_oat_file_ == nullptr) {
      std::cerr << "Usage: --fixed-oat <file> [--original-oat <file>]\n";
      return false;
    }

    std::string fixed_oat_path = args_->fixed_oat_file_;
    std::string original_oat_path = args_->original_oat_file_ != nullptr ? args_->original_oat_file_ : "";

    std::cout << "=== Validating Fixed OAT File ===\n";
    std::cout << "Fixed OAT: " << fixed_oat_path << "\n";

    // Validate the fixed OAT file using OatFile
    std::string error_msg;
    std::unique_ptr<art::OatFile> fixed_oat(art::OatFile::Open(
        /* zip_fd */ -1,
        fixed_oat_path,
        fixed_oat_path,
        /* executable */ false,
        /* low_4gb */ false,
        &error_msg));

    if (fixed_oat == nullptr) {
      std::cerr << "ERROR: Failed to open fixed OAT file: " << error_msg << "\n";
      return false;
    }

    std::cout << "Fixed OAT file is valid and can be loaded.\n";

    // Count methods with code_offset == 0
    size_t disabled_count = 0;
    size_t total_compiled_methods = 0;

    size_t dex_file_count = fixed_oat->GetOatDexFiles().size();
    for (size_t i = 0; i < dex_file_count; ++i) {
      const art::OatDexFile* oat_dex_file = fixed_oat->GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }

      std::string dex_error_msg;
      std::unique_ptr<const art::DexFile> dex_file = oat_dex_file->OpenDexFile(&dex_error_msg);
      if (dex_file == nullptr) {
        continue;
      }

      for (art::ClassAccessor accessor : dex_file->GetClasses()) {
        const uint16_t class_def_index = accessor.GetClassDefIndex();
        const art::OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
        uint32_t class_method_index = 0;

        for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
          const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
          class_method_index++;

          // Get code_offset first - if it's 0, the method is disabled
          uint32_t code_offset = oat_method.GetCodeOffset();

          // Check if method has compiled code via method_header
          const art::OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
          if (method_header == nullptr || method_header->GetCodeSize() == 0) {
            continue;  // Method doesn't have compiled code
          }

          total_compiled_methods++;

          if (code_offset == 0) {
            disabled_count++;
          }
        }
      }
    }

    std::cout << "\n=== Results ===\n";
    std::cout << "Total compiled methods: " << total_compiled_methods << "\n";
    std::cout << "Methods with code_offset == 0: " << disabled_count << "\n";

    // Code comparison mode
    if (args_->compare_code_) {
      if (original_oat_path.empty()) {
        std::cerr << "ERROR: --compare-code requires --original-oat <file>\n";
        return false;
      }

      std::cout << "\n=== Code Comparison Mode ===\n";
      std::cout << "Fixed OAT: " << fixed_oat_path << "\n";
      std::cout << "Original OAT: " << original_oat_path << "\n";

      std::unique_ptr<art::OatFile> original_oat(art::OatFile::Open(
          /* zip_fd */ -1,
          original_oat_path,
          original_oat_path,
          /* executable */ false,
          /* low_4gb */ false,
          &error_msg));

      if (original_oat == nullptr) {
        std::cerr << "ERROR: Failed to open original OAT file: " << error_msg << "\n";
        return false;
      }

      art::CodeComparisonResult result = art::CompareOatFiles(
          fixed_oat.get(),
          original_oat.get(),
          fixed_oat_path,
          original_oat_path,
          &error_msg);

      std::cout << "\n=== Comparison Summary ===\n";
      std::cout << "Identical methods: " << result.CountIdentical() << "\n";
      std::cout << "Different methods: " << result.CountDifferent() << "\n";
      std::cout << "Only in fixed: " << result.CountOnlyInFixed() << "\n";
      std::cout << "Only in original: " << result.CountOnlyInOriginal() << "\n";

      if (result.HasDifferences()) {
        std::cout << "\n=== Detailed Differences ===\n";
        size_t count = 0;
        for (const auto& diff : result.GetDifferences()) {
          if (count++ >= args_->max_diffs_) {
            std::cout << "... (stopped at " << args_->max_diffs_ << " differences)\n";
            break;
          }
          if (diff.status == art::CodeDifference::Status::kIdentical) {
            continue;
          }

          // For now, just print the method info without hex dump/disasm
          // (hex dump requires re-collecting method info which is complex)
          std::cout << "METHOD: " << diff.class_name << "->" << diff.method_name << "\n";
          std::cout << "  dex=" << diff.dex_file_idx
                    << " class_def=" << diff.class_def_idx
                    << " method=" << diff.method_idx << "\n";

          switch (diff.status) {
            case art::CodeDifference::Status::kDifferent:
              if (diff.size_differs) {
                std::cout << "  CODE SIZE DIFFERS: fixed=" << diff.fixed_size
                          << " orig=" << diff.orig_size << "\n";
              }
              if (diff.diff_offset > 0 || diff.fixed_byte != diff.orig_byte) {
                std::cout << "  FIRST DIFFERENCE at byte offset 0x" << std::hex << diff.diff_offset << ":\n";
                std::cout << "    Fixed: 0x" << std::hex << diff.fixed_byte << "\n";
                std::cout << "    Orig:  0x" << std::hex << diff.orig_byte << std::dec << "\n";
              }
              if (args_->show_hex_dumps_ || args_->show_disasm_) {
                std::cout << "  (Hex dump and disassembly require method info - showing basic diff only)\n";
              }
              break;
            case art::CodeDifference::Status::kOnlyInFixed:
              std::cout << "  METHOD ONLY IN FIXED FILE\n";
              break;
            case art::CodeDifference::Status::kOnlyInOriginal:
              std::cout << "  METHOD ONLY IN ORIGINAL FILE\n";
              break;
            case art::CodeDifference::Status::kIdentical:
              break;
          }
          std::cout << "\n";
        }
      }

      return !result.HasDifferences();
    }

    // If comparing with original, check that disabled methods changed from non-zero to zero
    if (!original_oat_path.empty()) {
      std::cout << "\n=== Comparing with Original OAT ===\n";
      std::cout << "Original OAT: " << original_oat_path << "\n";

      std::unique_ptr<art::OatFile> original_oat(art::OatFile::Open(
          /* zip_fd */ -1,
          original_oat_path,
          original_oat_path,
          /* executable */ false,
          /* low_4gb */ false,
          &error_msg));

      if (original_oat == nullptr) {
        std::cerr << "ERROR: Failed to open original OAT file: " << error_msg << "\n";
        return false;
      }

      size_t originally_disabled = 0;
      size_t newly_disabled = 0;

      for (size_t i = 0; i < dex_file_count; ++i) {
        const art::OatDexFile* oat_dex_file = fixed_oat->GetOatDexFiles()[i];
        const art::OatDexFile* orig_oat_dex_file = original_oat->GetOatDexFiles()[i];
        if (oat_dex_file == nullptr || orig_oat_dex_file == nullptr) {
          continue;
        }

        std::string dex_error_msg;
        std::unique_ptr<const art::DexFile> dex_file = oat_dex_file->OpenDexFile(&dex_error_msg);
        if (dex_file == nullptr) {
          continue;
        }

        for (art::ClassAccessor accessor : dex_file->GetClasses()) {
          const uint16_t class_def_index = accessor.GetClassDefIndex();
          const art::OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
          const art::OatFile::OatClass orig_oat_class = orig_oat_dex_file->GetOatClass(class_def_index);
          uint32_t class_method_index = 0;

          for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
            const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
            const art::OatFile::OatMethod orig_oat_method = orig_oat_class.GetOatMethod(class_method_index);
            class_method_index++;

            // Get code_offsets first
            uint32_t fixed_code_offset = oat_method.GetCodeOffset();
            uint32_t orig_code_offset = orig_oat_method.GetCodeOffset();

            // Check if method has compiled code via method_header
            const art::OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
            if (method_header == nullptr || method_header->GetCodeSize() == 0) {
              continue;
            }

            if (orig_code_offset == 0) {
              originally_disabled++;
            }

            if (orig_code_offset != 0 && fixed_code_offset == 0) {
              newly_disabled++;
              std::string method_name = dex_file->GetMethodName(method.GetIndex());
              std::cout << "  NEWLY DISABLED: " << method_name
                        << " (was " << orig_code_offset << ", now " << fixed_code_offset << ")\n";
            } else if (orig_code_offset != 0 && fixed_code_offset != 0 && orig_code_offset != fixed_code_offset) {
              std::cerr << "WARNING: code_offset changed unexpectedly from " << orig_code_offset
                        << " to " << fixed_code_offset << "\n";
            }
          }
        }
      }

      std::cout << "\nOriginally disabled (code_offset == 0): " << originally_disabled << "\n";
      std::cout << "Newly disabled by --fix: " << newly_disabled << "\n";

      if (newly_disabled == 0) {
        std::cout << "\nWARNING: No methods were newly disabled! The --fix may not be working correctly.\n";
        return false;
      }

      std::cout << "\nSUCCESS: --fix correctly disabled " << newly_disabled << " methods.\n";
    } else {
      if (disabled_count > 0) {
        std::cout << "\nSUCCESS: Found " << disabled_count << " methods with code_offset == 0\n";
      } else {
        std::cout << "\nWARNING: No methods have code_offset == 0\n";
        return false;
      }
    }

    return true;
  }
};

int main(int argc, char** argv) {
  android::base::SetLogger(android::base::StderrLogger);
  TestFixValidationMain main_runner;
  return main_runner.Main(argc, argv);
}