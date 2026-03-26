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

// Test file for DexLoader functionality
// Usage: run via test_dex_loader_host.py

#include <iostream>
#include <memory>
#include <string>

#include "android-base/logging.h"
#include "android-base/thread_annotations.h"
#include "base/locks.h"
#include "class_linker.h"
#include "cmdline.h"
#include "dex_loader.h"
#include "mirror/class.h"
#include "obj_ptr.h"
#include "runtime.h"
#include "scoped_thread_state_change.h"
#include "scoped_thread_state_change-inl.h"
#include "thread.h"

namespace art {

struct TestDexLoaderArgs : public CmdlineArgs {
  const char* dex_path = nullptr;

 protected:
  ParseStatus ParseCustom(const char* raw_option,
                          size_t raw_option_length,
                          std::string* error_msg) override {
    std::string_view option(raw_option, raw_option_length);

    if (option.starts_with("--dex=")) {
      dex_path = raw_option + strlen("--dex=");
      return kParseOk;
    }

    return CmdlineArgs::ParseCustom(raw_option, raw_option_length, error_msg);
  }

  ParseStatus ParseChecks(std::string* error_msg) override {
    ParseStatus status = CmdlineArgs::ParseChecks(error_msg);
    if (status != kParseOk) {
      return status;
    }

    if (dex_path == nullptr) {
      *error_msg = "--dex must be specified";
      return kParseError;
    }

    return kParseOk;
  }

  std::string GetUsage() const override {
    return R"(
Usage: test_dex_loader [options]

Test DexLoader functionality.

Options:
  --dex=<file>    Path to DEX file (required)
)";
  }
};

class BootClassVisitor:public ClassVisitor{
  virtual bool operator()(ObjPtr<mirror::Class> klass) override {
    ScopedObjectAccess soa(Thread::Current());
    klass->DumpClass(std::cout, 0);
    return true;
  }
};
struct TestDexLoaderMain : public CmdlineMain<TestDexLoaderArgs> {
  bool ExecuteWithRuntime(Runtime* runtime) override {
    CHECK(runtime != nullptr);
    ClassLinker* class_linker = runtime->GetClassLinker();
    ScopedObjectAccess soa(Thread::Current());
    auto vistor = BootClassVisitor();
    class_linker->VisitClassesWithoutClassesLock(&vistor);
    //std::cout << "DexLoader Test\n";
    //std::cout << "==============\n";
    //std::cout << "DEX path: " << args_->dex_path << "\n";

    //DexLoader loader(runtime);

    //auto loaded_dex = loader.LoadDex(args_->dex_path, "test_dex");
    //if (loaded_dex == nullptr) {
      //std::cerr << "ERROR: Failed to load DEX\n";
      //return false;
    //}

    //std::cout << "DEX loaded successfully!\n";
    //std::cout << "  Name: " << loaded_dex->GetName() << "\n";
    //std::cout << "  DexFiles: " << loaded_dex->GetDexFiles().size() << "\n";

    //std::cout << "Loading all classes...\n";
    //bool success = loader.LoadAllClasses(loaded_dex.get());
    //if (!success) {
      //std::cerr << "WARNING: Some classes failed to load\n";
    //}

    //std::cout << "Classes loaded: " << loaded_dex->GetLoadedClasses().size() << "\n";

    //// Test FindClass - try to find a class
    //auto& classes = loaded_dex->GetLoadedClasses();
    //if (!classes.empty()) {
      //// Get descriptor of first class (need mutator lock)
      //ScopedObjectAccess soa(Thread::Current());
      //std::string descriptor_storage;
      //const char* first_descriptor = classes[0]->GetDescriptor(&descriptor_storage);
      //std::cout << "First class: " << first_descriptor << "\n";

      //// Try to find it via FindClass
      //auto found = loader.FindClass(loaded_dex.get(), first_descriptor);
      //if (found != nullptr) {
        //std::cout << "FindClass works! Found: " << first_descriptor << "\n";
      //} else {
        //std::cerr << "ERROR: FindClass failed for " << first_descriptor << "\n";
      //}
    //}

    //std::cout << "Test PASSED!\n";
    return true;
  }
};

}  // namespace art

int main(int argc, char** argv) {
  android::base::SetLogger(android::base::StderrLogger);
  art::TestDexLoaderMain main_runner;
  return main_runner.Main(argc, argv);
}