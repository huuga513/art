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

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <set>
#include <tuple>
#include <memory>

#include "cmdline.h"
#include "dex/class_accessor-inl.h"
#include "dex/class_accessor.h"
#include "dex/dex_file.h"
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

}  // namespace art

struct TestFixValidationArgs : public art::CmdlineArgs {
 protected:
  using Base = art::CmdlineArgs;

 public:
  char const* fixed_oat_file_ = nullptr;
  char const* original_oat_file_ = nullptr;

  ParseStatus ParseCustom(const char* raw_option,
                          size_t raw_option_length,
                          std::string* error_msg) override {
    std::string_view option(raw_option, raw_option_length);

    if (option.starts_with("--fixed-oat=")) {
      fixed_oat_file_ = raw_option + strlen("--fixed-oat=");
    } else if (option.starts_with("--original-oat=")) {
      original_oat_file_ = raw_option + strlen("--original-oat=");
    } else {
      return Base::ParseCustom(raw_option, raw_option_length, error_msg);
    }
    return kParseOk;
  }

  void PrintUsage() {
    std::cerr << "Usage: " << "test_prog" << " [options]\n";
    std::cerr << "  --fixed-oat=<file>       Path to the fixed OAT file\n";
    std::cerr << "  --original-oat=<file>   Path to the original OAT file for comparison\n";
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