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
#include <string>
#include <string_view>
#include <vector>

#include "android-base/logging.h"
#include "android-base/macros.h"
#include "android-base/strings.h"
#include "cmdline.h"

#include "runtime.h"
#include "runtime-inl.h"

// For APK (ZIP) parsing
#include "ziparchive/zip_archive.h"
#include "ziparchive/zip_writer.h"

namespace art {

enum class OatCheckMode {
  kDefault,
  kVerbose,
};

struct OatCheckArgs : public CmdlineArgs {
 protected:
  using Base = CmdlineArgs;

  ParseStatus ParseCustom(const char* raw_option,
                          size_t raw_option_length,
                          std::string* error_msg) override {
    DCHECK_EQ(strlen(raw_option), raw_option_length);
    std::string_view option(raw_option, raw_option_length);

    if (option == "--help" || option == "-h") {
      help_ = true;
      return kParseOk;
    } else if (option == "--verbose" || option == "-v") {
      verbose_ = true;
    } else if (option.starts_with("--dex=")) {
      dex_files_.push_back(raw_option + strlen("--dex="));
    } else if (option.starts_with("--oat=")) {
      oat_file_ = raw_option + strlen("--oat=");
    } else if (option.starts_with("--system=")) {
      system_dir_ = raw_option + strlen("--system=");
    } else if (option.starts_with("--output=")) {
      output_file_ = raw_option + strlen("--output=");
    } else if (option.starts_with("--apk=")) {
      apk_file_ = raw_option + strlen("--apk=");
    }
    // TODO: Add more options.

    else {
      return Base::ParseCustom(raw_option, raw_option_length, error_msg);
    }

    return kParseOk;
  }

  ParseStatus ParseChecks(std::string* error_msg) override {
    ParseStatus parent_status = Base::ParseChecks(error_msg);
    if (parent_status != kParseOk) {
      return parent_status;
    }

    if (help_) {
      return kParseOk;
    }

    if (dex_files_.empty() && oat_file_ == nullptr && system_dir_ == nullptr && apk_file_ == nullptr) {
      *error_msg = "At least one of --dex, --oat, --system, or --apk must be specified.";
      return kParseError;
    }

    return kParseOk;
  }

  std::string GetUsage() const override {
    return R"(
Usage: oatcheck [options]

Check whether compiled methods in OAT files are still valid after a system upgrade.

Examples:
  oatcheck --apk=app.apk
  oatcheck --dex=classes.dex --oat=base.odex

Options:
  --apk=<file>        Path to APK file (will extract all classes*.dex)
  --dex=<file>        Path to DEX file (can be repeated)
  --oat=<file>        Path to OAT/ODEX file
  --system=<dir>      Root of system partition (e.g., /system)
  --output=<file>     Write result to file (default: stdout)
  --verbose, -v       Enable verbose logging
  --help, -h          Show this message
)";
  }

 public:
  bool help_ = false;
  bool verbose_ = false;
  std::vector<const char*> dex_files_;
  const char* oat_file_ = nullptr;
  const char* system_dir_ = nullptr;
  const char* output_file_ = nullptr;
  const char* apk_file_ = nullptr;

  OatCheckMode GetMode() const {
    if (verbose_) {
      return OatCheckMode::kVerbose;
    }
    return OatCheckMode::kDefault;
  }

  // Extract all classes*.dex from APK into `dex_files_`.
  bool ExtractDexFromApk(std::string* error_msg) {
    if (apk_file_ == nullptr) {
      return true;
    }

    ZipArchiveHandle handle;
    int32_t open_status = OpenArchive(apk_file_, &handle);
    if (open_status != 0) {
      *error_msg = "Failed to open APK: " + std::string(apk_file_) + " (" +
                   ErrorCodeString(open_status) + ")";
      CloseArchive(handle);
      return false;
    }

    std::vector<ZipEntry> entries;
    void* cookie;
    int status = StartIteration(handle, &cookie, "", "");
    if (status != 0) {
      *error_msg = "Failed to start ZIP iteration";
      CloseArchive(handle);
      return false;
    }

    ZipEntry entry;
    std::string name;
    while (Next(cookie, &entry, &name) == 0) {
      if (android::base::StartsWith(name, "classes") &&
          android::base::EndsWith(name, ".dex")) {
        // Store the full path as a temporary string? Not needed here.
        // We'll re-open the APK later when loading DEX.
        // Just record the name for now.
        extracted_dex_names_.push_back(name);
      }
    }
    EndIteration(cookie);
    CloseArchive(handle);

    if (extracted_dex_names_.empty()) {
      *error_msg = "No DEX files found in APK: " + std::string(apk_file_);
      return false;
    }

    if (verbose_) {
      LOG(INFO) << "Found " << extracted_dex_names_.size() << " DEX files in APK.";
    }

    return true;
  }

  // Return list of DEX entry names inside the APK (e.g., "classes.dex")
  const std::vector<std::string>& GetApkDexEntries() const {
    return extracted_dex_names_;
  }

 private:
  std::vector<std::string> extracted_dex_names_;
};

// Helper: Load DEX from APK entry (used in ExecuteWithRuntime)
// static std::unique_ptr<const DexFile> OpenDexFromApk(const char* apk_path,
                                                     // const std::string& entry_name,
                                                     // std::string* error_msg) {
  // std::vector<std::unique_ptr<const DexFile>> dex_files;
  // if (!DexFile::Open(apk_path, entry_name, /*verify_checksum*/ true, error_msg, &dex_files)) {
    // return nullptr;
  // }
  // if (dex_files.empty()) {
    // *error_msg = "No DEX loaded from " + entry_name;
    // return nullptr;
  // }
  // // Assume single DEX per entry (normal case)
  // return std::move(dex_files[0]);
// }

struct OatCheckMain : public CmdlineMain<OatCheckArgs> {
  bool ExecuteWithoutRuntime() override {
    LOG(FATAL) << "This tool requires ART runtime.";
    UNREACHABLE();
  }

  bool ExecuteWithRuntime(ATTRIBUTE_UNUSED Runtime* runtime) override {
    if (args_->verbose_) {
      LOG(INFO) << "Verbose mode enabled";
    }

    // Handle --apk: extract DEX entry names
    std::string error_msg;
    if (!args_->ExtractDexFromApk(&error_msg)) {
      LOG(ERROR) << error_msg;
      return false;
    }

    std::ostream* os = &std::cout;
    if (args_->output_file_ != nullptr) {
      LOG(WARNING) << "--output not implemented yet; using stdout";
    }

    *os << "Running OatCheck...\n";

    // Process explicit --dex files
    for (const char* dex : args_->dex_files_) {
      *os << "Processing DEX: " << dex << "\n";
      // TODO: Add real validation logic here.
    }

    // Process DEX files from APK
    // for (const std::string& entry : args_->GetApkDexEntries()) {
      // *os << "Processing DEX from APK (" << args_->apk_file_ << "): " << entry << "\n";

      // // Optional: Actually load the DEX file using ART
      // std::unique_ptr<const DexFile> dex = OpenDexFromApk(args_->apk_file_, entry, &error_msg);
      // if (dex == nullptr) {
        // LOG(WARNING) << "Failed to load " << entry << " from APK: " << error_msg;
        // continue;
      // }

      // // Example: Print number of classes
      // *os << "  -> Loaded " << dex->NumClassDefs() << " classes\n";
      // // TODO: Your validation logic goes here.
    // }

    if (args_->oat_file_)   *os << "OAT: " << args_->oat_file_ << "\n";
    if (args_->system_dir_) *os << "System: " << args_->system_dir_ << "\n";

    *os << "Done.\n";
    return true;
  }
};

}  // namespace art

int main(int argc, char** argv) {
  android::base::SetLogger(android::base::StderrLogger);
  art::OatCheckMain main_runner;
  return main_runner.Main(argc, argv);
}