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

#include "dex_loader.h"

#include "android-base/logging.h"
#include "dex/dex_file_loader.h"
#include "dex/utf.h"
#include "interpreter/unstarted_runtime.h"
#include "jni.h"
#include "runtime.h"
#include "class_linker.h"
#include "handle_scope-inl.h"
#include "mirror/class_loader.h"
#include "scoped_thread_state_change-inl.h"
#include "thread.h"
#include "well_known_classes.h"

namespace art {

LoadedDex::LoadedDex(std::string name,
                       std::vector<std::unique_ptr<const DexFile>> dex_files,
                       Handle<mirror::ClassLoader> class_loader)
    : name_(std::move(name)),
      dex_files_(std::move(dex_files)),
      class_loader_(class_loader) {}

ObjPtr<mirror::Class> LoadedDex::FindClass(const char* descriptor) const {
  auto it = class_map_.find(descriptor);
  if (it != class_map_.end()) {
    return it->second;
  }
  return nullptr;
}

void LoadedDex::RegisterLoadedClass(ObjPtr<mirror::Class> klass)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  CHECK(klass != nullptr);
  std::string descriptor_storage;
  const char* descriptor = klass->GetDescriptor(&descriptor_storage);
  loaded_classes_.push_back(klass);
  class_map_[descriptor] = klass;
}

DexLoader::DexLoader(Runtime* runtime)
    : runtime_(runtime),
      class_linker_(runtime->GetClassLinker()) {
  DCHECK(runtime_ != nullptr);
  DCHECK(class_linker_ != nullptr);
}

std::unique_ptr<LoadedDex> DexLoader::LoadDex(const char* dex_path,
                                                  const std::string& name) {
  ScopedObjectAccess soa(Thread::Current());
  Thread* self = soa.Self();

  // Load DEX file(s) using DexFileLoader
  std::string error_msg;
  DexFileLoader loader(dex_path, /*location=*/dex_path);
  std::vector<std::unique_ptr<const DexFile>> dex_files;

  bool success = loader.Open(
      /*verify=*/true,
      /*verify_checksum=*/true,
      /*allow_no_dex_files=*/false,
      &error_msg,
      &dex_files);

  if (!success || dex_files.empty()) {
    LOG(ERROR) << "Failed to load DEX from " << dex_path << ": " << error_msg;
    return nullptr;
  }

  LOG(INFO) << "Loaded " << dex_files.size() << " DEX file(s) from " << dex_path;

  // Create a vector of raw pointers for CreateIsolatedClassLoader
  std::vector<const DexFile*> dex_file_ptrs;
  dex_file_ptrs.reserve(dex_files.size());
  for (const auto& dex_file : dex_files) {
    dex_file_ptrs.push_back(dex_file.get());
  }

  // Create isolated ClassLoader
  Handle<mirror::ClassLoader> class_loader = CreateIsolatedClassLoader(self, dex_file_ptrs);
  if (class_loader.Get() == nullptr) {
    LOG(ERROR) << "Failed to create isolated ClassLoader for " << dex_path;
    return nullptr;
  }

  return std::make_unique<LoadedDex>(name, std::move(dex_files), class_loader);
}

bool DexLoader::LoadAllClasses(LoadedDex* loaded_dex) {
  DCHECK(loaded_dex != nullptr);

  ScopedObjectAccess soa(Thread::Current());
  Thread* self = soa.Self();
  Handle<mirror::ClassLoader> class_loader = loaded_dex->GetClassLoader();

  bool all_succeeded = true;

  for (const auto& dex_file : loaded_dex->GetDexFiles()) {
    uint32_t num_class_defs = dex_file->NumClassDefs();
    for (uint32_t i = 0; i < num_class_defs; ++i) {
      const dex::ClassDef& class_def = dex_file->GetClassDef(i);
      const char* descriptor = dex_file->GetClassDescriptor(class_def);

      // Compute hash for the descriptor
      size_t hash = ComputeModifiedUtf8Hash(descriptor);

      // Define the class
      ObjPtr<mirror::Class> klass = class_linker_->DefineClass(
          self,
          descriptor,
          hash,
          class_loader,
          *dex_file,
          class_def);

      if (klass == nullptr) {
        if (self->IsExceptionPending()) {
          self->ClearException();
        }
        LOG(WARNING) << "Failed to define class: " << descriptor;
        all_succeeded = false;
        continue;
      }

      loaded_dex->RegisterLoadedClass(klass);
    }
  }

  LOG(INFO) << "Loaded " << loaded_dex->GetLoadedClasses().size() << " classes";
  return all_succeeded;
}

ObjPtr<mirror::Class> DexLoader::FindClass(LoadedDex* loaded_dex,
                                              const char* descriptor) {
  DCHECK(loaded_dex != nullptr);
  DCHECK(descriptor != nullptr);

  // First check if the class is already loaded in LoadedDex
  ObjPtr<mirror::Class> klass = loaded_dex->FindClass(descriptor);
  if (klass != nullptr) {
    return klass;
  }

  ScopedObjectAccess soa(Thread::Current());
  Thread* self = soa.Self();
  Handle<mirror::ClassLoader> class_loader = loaded_dex->GetClassLoader();

  // Try to find/load the class via ClassLinker
  klass = class_linker_->FindClass(self, descriptor, class_loader);

  if (klass != nullptr) {
    loaded_dex->RegisterLoadedClass(klass);
  } else if (self->IsExceptionPending()) {
    self->ClearException();
  }

  return klass;
}

Handle<mirror::ClassLoader> DexLoader::CreateIsolatedClassLoader(
    Thread* self,
    const std::vector<const DexFile*>& dex_files) {
  ScopedObjectAccess soa(self);
  StackHandleScope<1> hs(self);

  // Initialize WellKnownClasses before using them
  WellKnownClasses::Init(self->GetJniEnv());

  // Initialize UnstartedRuntime to support class initialization
  interpreter::UnstartedRuntime::Initialize();

  // Use ClassLinker::CreatePathClassLoader which properly initializes PathClassLoader
  // This returns a jobject (JNI global reference), we need to convert it to ObjPtr
  jobject class_loader_jobj = class_linker_->CreatePathClassLoader(self, dex_files);
  if (class_loader_jobj == nullptr) {
    LOG(ERROR) << "Failed to create PathClassLoader";
    return hs.NewHandle<mirror::ClassLoader>(nullptr);
  }

  // Convert jobject to ObjPtr<mirror::ClassLoader>
  ObjPtr<mirror::ClassLoader> class_loader =
      soa.Decode<mirror::ClassLoader>(class_loader_jobj);

  // Register dex files with the class loader
  for (const DexFile* dex_file : dex_files) {
    class_linker_->RegisterDexFile(*dex_file, class_loader);
  }

  return hs.NewHandle(class_loader);
}

}  // namespace art
