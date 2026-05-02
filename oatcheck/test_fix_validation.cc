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
#include <cstring>
#include <string>
#include <set>
#include <tuple>
#include <memory>
#include <map>
#include <optional>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

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

// Helper function to match method filter
static bool MethodMatchesFilter(const std::string& class_name,
                                const std::string& method_name,
                                const std::string& filter) {
  size_t arrow_pos = filter.find("->");
  if (arrow_pos == std::string::npos) {
    return false;
  }
  std::string filter_class = filter.substr(0, arrow_pos);
  std::string filter_method_sig = filter.substr(arrow_pos + 2);

  // Extract just the method name (before any '(' for signature)
  size_t sig_pos = filter_method_sig.find('(');
  std::string filter_method_name;
  if (sig_pos != std::string::npos) {
    filter_method_name = filter_method_sig.substr(0, sig_pos);
  } else {
    filter_method_name = filter_method_sig;
  }

  return class_name == filter_class && method_name == filter_method_name;
}

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
  // Code pointers for hex dump and disassembly
  const uint8_t* fixed_code_ptr = nullptr;
  const uint8_t* orig_code_ptr = nullptr;
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
  diff.fixed_code_ptr = fixed_method.code_ptr;
  diff.orig_code_ptr = orig_method.code_ptr;

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

  // ARM64 BL (Branch with Link) instruction mask.
  // BL encoding: bits[31]=1, bits[30:26]=00101, bits[25:0]=imm26
  // Mask: 0xFC000000, Match: 0x94000000
  static constexpr uint32_t kBlMask = 0xFC000000u;
  static constexpr uint32_t kBlOpcode = 0x94000000u;

  // Check if a 4-byte instruction at offset is a BL instruction.
  // ARM64 is little-endian, so we can directly cast to uint32_t*.
  auto IsBlInsn = [](const uint8_t* code, uint32_t offset) -> bool {
    if (offset + 4 > static_cast<uint32_t>(-1)) {
      return false;
    }
    uint32_t insn = *reinterpret_cast<const uint32_t*>(code + offset);
    return (insn & kBlMask) == kBlOpcode;
  };
  // ARM64 ADRP (Form PC-relative address to 4KB page) instruction mask.
  static constexpr uint32_t kAdrpMask = 0x9f000000u;
  static constexpr uint32_t kAdrpOpcode = 0x90000000u;

  // Check if a 4-byte instruction at offset is an ADRP instruction.
  // ARM64 is little-endian, so we can directly cast to uint32_t*.
  auto IsAdrpInsn = [](const uint8_t* code, uint32_t offset) -> bool {
    // Check for potential overflow if offset is near the limit of uint32_t
    if (offset + 4 > static_cast<uint32_t>(-1)) {
      return false;
    }
    uint32_t insn = *reinterpret_cast<const uint32_t*>(code + offset);
    return (insn & kAdrpMask) == kAdrpOpcode;
  };
  auto ShouldSkip = [=](const uint8_t* code, uint32_t offset) -> bool {
    if (IsBlInsn(code, offset)) return true;
    if (IsAdrpInsn(code, offset)) return true;
    return false;
  };

  diff.fixed_size = fixed_method.code_size;
  diff.orig_size = orig_method.code_size;

  // Compare code instruction-by-instruction (4 bytes per instruction for ARM64).
  // Skip BL and ADRP instructions as they use PC-relative offsets that may differ
  // between BCP versions due to different boot image layout and OAT linking.
  uint32_t fixed_idx = 0;
  uint32_t orig_idx = 0;
  bool has_difference = false;
  uint32_t diff_offset = 0;
  uint32_t diff_fixed_insn = 0;
  uint32_t diff_orig_insn = 0;

  while (fixed_idx < fixed_method.code_size && orig_idx < orig_method.code_size) {
    // ARM64 is little-endian, read 4-byte instruction directly
    uint32_t fixed_insn = *reinterpret_cast<const uint32_t*>(fixed_method.code_ptr + fixed_idx);
    uint32_t orig_insn = *reinterpret_cast<const uint32_t*>(orig_method.code_ptr + orig_idx);

    if (fixed_insn != orig_insn) {
      // Check if both are BL or ADRP instructions - skip if so.
      if (IsBlInsn(fixed_method.code_ptr, fixed_idx) &&
          IsBlInsn(orig_method.code_ptr, orig_idx)) {
        fixed_idx += 4;
        orig_idx += 4;
        continue;
      }
      // TODO: find out what makes adrp different
      if (IsAdrpInsn(fixed_method.code_ptr, fixed_idx) &&
          IsAdrpInsn(orig_method.code_ptr, orig_idx)) {
        fixed_idx += 4;
        orig_idx += 4;
        continue;
      }
      // Real difference found.
      has_difference = true;
      diff_offset = fixed_idx;
      diff_fixed_insn = fixed_insn;
      diff_orig_insn = orig_insn;
      break;
    }
    fixed_idx += 4;
    orig_idx += 4;
  }

  // Check if sizes differ (only relevant if no differences found yet).
  if (!has_difference && fixed_method.code_size != orig_method.code_size) {
    has_difference = true;
  }

  if (!has_difference) {
    diff.status = CodeDifference::Status::kIdentical;
    return std::nullopt;
  }

  diff.status = CodeDifference::Status::kDifferent;
  if (fixed_method.code_size != orig_method.code_size) {
    diff.size_differs = true;
  }
  diff.diff_offset = diff_offset;
  diff.fixed_byte = diff_fixed_insn;
  diff.orig_byte = diff_orig_insn;

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

// Helper function to run objdump on code bytes
static bool DisassembleWithObjdump(const uint8_t* code, uint32_t size, const std::string& label) {
  if (code == nullptr || size == 0) {
    std::cout << "  " << label << ": (no code)\n";
    return false;
  }

  // Write code to a temporary file
  char temp_path[] = "/tmp/art_code_XXXXXX";
  int fd = mkstemp(temp_path);
  if (fd < 0) {
    std::cerr << "  Failed to create temp file for objdump\n";
    return false;
  }

  FILE* f = fdopen(fd, "wb");
  if (f == nullptr) {
    close(fd);
    std::cerr << "  Failed to open temp file for objdump\n";
    return false;
  }

  fwrite(code, 1, size, f);
  fclose(f);

  // Run objdump
  std::string cmd = "aarch64-linux-gnu-objdump -b binary -m aarch64 -D " + std::string(temp_path) + " 2>/dev/null";
  FILE* objdump_fp = popen(cmd.c_str(), "r");
  if (objdump_fp == nullptr) {
    std::cerr << "  Failed to run objdump (aarch64-linux-gnu-objdump)\n";
    unlink(temp_path);
    return false;
  }

  std::cout << "  " << label << " disassembly:\n";
  char buf[256];
  while (fgets(buf, sizeof(buf), objdump_fp) != nullptr) {
    // Indent objdump output
    for (char* p = buf; *p; ++p) {
      if (*p == '\n') {
        std::cout << "    | ";
        break;
      }
    }
    std::cout << buf;
  }
  pclose(objdump_fp);
  unlink(temp_path);
  return true;
}

// Helper to print hex dump
static void PrintHexDump(const uint8_t* code, uint32_t size, const std::string& label, uint32_t max_bytes = 128) {
  if (code == nullptr || size == 0) {
    std::cout << "  " << label << ": (no code)\n";
    return;
  }

  uint32_t dump_size = std::min(size, max_bytes);
  std::cout << "  " << label << " hex (" << dump_size << " of " << size << " bytes):\n    ";
  for (uint32_t i = 0; i < dump_size; i++) {
    printf("%02x ", code[i]);
    if ((i + 1) % 16 == 0 && i < dump_size - 1) {
      std::cout << "\n    ";
    }
  }
  if (dump_size < size) {
    std::cout << "\n    ... (" << (size - dump_size) << " more bytes)";
  }
  std::cout << "\n";
}

// Helper to print DEX bytecode in human-readable form
static void PrintDexBytecode(const DexFile* dex_file,
                              uint16_t class_def_idx,
                              uint32_t method_idx) {
  if (dex_file == nullptr) {
    std::cout << "  DEX code: (no dex file)\n";
    return;
  }

  // Find the class
  if (class_def_idx >= dex_file->NumClassDefs()) {
    std::cout << "  DEX code: (class not found)\n";
    return;
  }

  const dex::ClassDef& class_def = dex_file->GetClassDef(class_def_idx);
  ClassAccessor accessor(*dex_file, class_def);

  // Find the method within this class
  for (ClassAccessor::Method method : accessor.GetMethods()) {
    if (method.GetIndex() == method_idx) {
      const dex::CodeItem* code_item = method.GetCodeItem();
      if (code_item == nullptr) {
        std::cout << "  DEX code: (native or abstract method)\n";
        return;
      }

      std::cout << "  DEX code:\n";
      CodeItemDataAccessor code_accessor(*dex_file, code_item);
      for (const DexInstructionPcPair& pair : code_accessor) {
        const uint32_t dex_pc = pair.DexPc();
        const Instruction* insn = &pair.Inst();
        std::string disasm = insn->DumpString(dex_file);
        printf("    %04x: %s\n", dex_pc * 2, disasm.c_str());
      }
      return;
    }
  }
  std::cout << "  DEX code: (method not found)\n";
}

}  // namespace art

struct TestFixValidationArgs : public art::CmdlineArgs {
 protected:
  using Base = art::CmdlineArgs;

 public:
  char const* fixed_oat_file_ = nullptr;
  char const* original_oat_file_ = nullptr;
  bool compare_code_ = false;
  uint32_t max_diffs_ = 10;
  bool show_hex_dumps_ = true;
  bool show_disasm_ = true;
  bool show_dex_instructions_ = true;
  char const* method_filter_ = nullptr;

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
    } else if (option == "--dex-instructions") {
      show_dex_instructions_ = true;
    } else if (option == "--no-dex-instructions") {
      show_dex_instructions_ = false;
    } else if (option.starts_with("--method=")) {
      method_filter_ = raw_option + strlen("--method=");
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
    std::cerr << "  --dex-instructions / --no-dex-instructions  Show/hide DEX instructions (default show)\n";
    std::cerr << "  --method=<sig>       Filter to method (e.g., Lcom/example/Class;->method(I)V)\n";
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

    // Method filter mode - print method info directly without comparison
    if (args_->method_filter_ != nullptr && original_oat_path.empty()) {
      std::cout << "\n=== Method Filter Output ===\n";
      bool found = false;
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
          const art::dex::ClassDef& class_def = dex_file->GetClassDef(class_def_index);
          std::string_view descriptor = dex_file->GetTypeDescriptorView(class_def.class_idx_);
          const std::string class_name = std::string(descriptor);
          const art::OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
          uint32_t class_method_index = 0;

          for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
            const std::string method_name = dex_file->GetMethodName(method.GetIndex());
            class_method_index++;

            if (!art::MethodMatchesFilter(class_name, method_name, args_->method_filter_)) {
              continue;
            }

            found = true;
            std::cout << "METHOD: " << class_name << "->" << method_name << "\n";
            std::cout << "  dex=" << i << " class_def=" << class_def_index << " method=" << method.GetIndex() << "\n";

            const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index - 1);
            const art::OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();

            if (method_header != nullptr && method_header->GetCodeSize() > 0) {
              const uint8_t* code = method_header->GetCode();
              uint32_t code_size = method_header->GetCodeSize();
              if (args_->show_hex_dumps_) {
                art::PrintHexDump(code, code_size, "Fixed", 64);
              }
              if (args_->show_disasm_) {
                art::DisassembleWithObjdump(code, code_size, "Fixed");
              }
            } else {
              std::cout << "  (no compiled code)\n";
            }
            if (args_->show_dex_instructions_) {
              art::PrintDexBytecode(dex_file.get(), class_def_index, method.GetIndex());
            }
            std::cout << "\n";
          }
        }
      }
      if (!found) {
        std::cout << "Method not found: " << args_->method_filter_ << "\n";
      }
      return true;
    }

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
          if (diff.status == art::CodeDifference::Status::kIdentical) {
            continue;
          }
          if (args_->method_filter_ != nullptr &&
              !art::MethodMatchesFilter(diff.class_name, diff.method_name, args_->method_filter_)) {
            continue;
          }
          if (count++ >= args_->max_diffs_) {
            std::cout << "... (stopped at " << args_->max_diffs_ << " differences)\n";
            break;
          }

          std::cout << "METHOD: " << diff.class_name << "->" << diff.method_name << "\n";
          std::cout << "  dex=" << diff.dex_file_idx
                    << " class_def=" << diff.class_def_idx
                    << " method=" << diff.method_idx << "\n";

          // Load DexFile for DEX bytecode printing
          std::unique_ptr<const art::DexFile> diff_dex_file;
          const art::OatDexFile* diff_oat_dex_file = fixed_oat->GetOatDexFiles()[diff.dex_file_idx];
          if (diff_oat_dex_file != nullptr) {
            std::string dex_err;
            diff_dex_file = diff_oat_dex_file->OpenDexFile(&dex_err);
          }

          switch (diff.status) {
            case art::CodeDifference::Status::kDifferent:
              if (diff.size_differs) {
                std::cout << "  CODE SIZE DIFFERS: fixed=" << diff.fixed_size
                          << " orig=" << diff.orig_size << "\n";
              }
              if (diff.diff_offset > 0 || diff.fixed_byte != diff.orig_byte) {
                printf("  FIRST DIFFERENCE at byte offset 0x%04x (instruction at offset %u):\n", diff.diff_offset, diff.diff_offset / 4);
                printf("    Fixed: 0x%08x\n", diff.fixed_byte);
                printf("    Orig:  0x%08x\n", diff.orig_byte);
              }
              if (args_->show_hex_dumps_) {
                art::PrintHexDump(diff.fixed_code_ptr, diff.fixed_size, "Fixed", 64);
                art::PrintHexDump(diff.orig_code_ptr, diff.orig_size, "Orig", 64);
              }
              if (args_->show_disasm_) {
                art::DisassembleWithObjdump(diff.fixed_code_ptr, diff.fixed_size, "Fixed");
                art::DisassembleWithObjdump(diff.orig_code_ptr, diff.orig_size, "Orig");
              }
              if (args_->show_dex_instructions_) {
                art::PrintDexBytecode(diff_dex_file.get(), diff.class_def_idx, diff.method_idx);
              }
              break;
            case art::CodeDifference::Status::kOnlyInFixed:
              std::cout << "  METHOD ONLY IN FIXED FILE\n";
              if (args_->show_hex_dumps_) {
                art::PrintHexDump(diff.fixed_code_ptr, diff.fixed_size, "Fixed", 64);
              }
              if (args_->show_disasm_) {
                art::DisassembleWithObjdump(diff.fixed_code_ptr, diff.fixed_size, "Fixed");
              }
              break;
            case art::CodeDifference::Status::kOnlyInOriginal:
              std::cout << "  METHOD ONLY IN ORIGINAL FILE\n";
              if (args_->show_hex_dumps_) {
                art::PrintHexDump(diff.orig_code_ptr, diff.orig_size, "Orig", 64);
              }
              if (args_->show_disasm_) {
                art::DisassembleWithObjdump(diff.orig_code_ptr, diff.orig_size, "Orig");
              }
              break;
            case art::CodeDifference::Status::kIdentical:
              break;
          }
          std::cout << "\n";
        }
      }

      return true;
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

/*Usage:
python3 oatcheck/test_fix_validation_host.py \
  --fixed-oat=/ssd2/wyz/app_oats/15.0.0_r5/com.tencent.mm/oat/base.odex \
  --original-oat=/ssd2/wyz/app_oats/15.0.0_r3/com.tencent.mm/oat/base.odex \
  --compare-code

python3 oatcheck/test_fix_validation_host.py --fixed-oat=/ssd2/wyz/app_oats/15.0.0_r5/com.qiyi.video/oat/base.odex\
  --method="Lcom/tencent/shadow/core/runtime/container/GeneratedPluginContainerAppCompatActivity;->onMenuOpened"
*/