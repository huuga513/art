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

#include "android-base/logging.h"
#include "android-base/macros.h"
#include "cmdline.h"

#include "runtime.h"
#include "runtime-inl.h"
namespace art {

// Execution mode of the tool.
enum class OatCheckMode {
  kDefault,
  kVerbose,
  // Additional modes can be added here as needed.
};

// Command-line argument parser for oatcheck.
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
      dex_file_ = raw_option + strlen("--dex=");
    } else if (option.starts_with("--oat=")) {
      oat_file_ = raw_option + strlen("--oat=");
    } else if (option.starts_with("--system=")) {
      system_dir_ = raw_option + strlen("--system=");
    } else if (option.starts_with("--output=")) {
      output_file_ = raw_option + strlen("--output=");
    }
    // TODO: Add more options here as needed.

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

    if (dex_file_ == nullptr && oat_file_ == nullptr && system_dir_ == nullptr) {
      *error_msg = "At least one of --dex, --oat, or --system must be specified.";
      return kParseError;
    }

    // TODO: Add additional validation logic here.

    return kParseOk;
  }

  std::string GetUsage() const override {
    return R"(
Usage: oatcheck [options]

Check whether compiled methods in OAT files are still valid after a system upgrade.

Examples:
  oatcheck --system=/system
  oatcheck --dex=classes.dex --oat=base.odex

Options:
  --dex=<file>        Path to DEX file (e.g., classes.dex)
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
  const char* dex_file_ = nullptr;
  const char* oat_file_ = nullptr;
  const char* system_dir_ = nullptr;
  const char* output_file_ = nullptr;

  OatCheckMode GetMode() const {
    if (verbose_) {
      return OatCheckMode::kVerbose;
    }
    return OatCheckMode::kDefault;
  }
};

// Main entry point that uses the ART runtime.
struct OatCheckMain : public CmdlineMain<OatCheckArgs> {
  bool ExecuteWithoutRuntime() override {
    LOG(FATAL) << "This tool requires ART runtime and should not be run without it.";
    UNREACHABLE();
  }

  bool ExecuteWithRuntime(ATTRIBUTE_UNUSED Runtime* runtime) override {
    if (args_->verbose_) {
      LOG(INFO) << "Verbose mode enabled";
    }

    std::ostream* os = &std::cout;
    if (args_->output_file_ != nullptr) {
      LOG(WARNING) << "--output is not implemented yet; using stdout";
    }

    *os << "Running OatCheck...\n";
    if (args_->dex_file_)   *os << "DEX: " << args_->dex_file_ << "\n";
    if (args_->oat_file_)   *os << "OAT: " << args_->oat_file_ << "\n";
    if (args_->system_dir_) *os << "System: " << args_->system_dir_ << "\n";

    *os << "Placeholder: Add your DEX/OAT validation logic here.\n";
    return true;
  }
};

}  // namespace art

int main(int argc, char** argv) {
  android::base::SetLogger(android::base::StderrLogger);
  art::OatCheckMain main_runner;
  return main_runner.Main(argc, argv);
}