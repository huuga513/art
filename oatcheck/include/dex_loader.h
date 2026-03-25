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

#ifndef ART_OATCHECK_DEX_LOADER_H_
#define ART_OATCHECK_DEX_LOADER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dex/dex_file.h"
#include "handle.h"
#include "obj_ptr.h"

namespace art {

class ClassLinker;
class Runtime;
class Thread;

namespace mirror {
class Class;
class ClassLoader;
}  // namespace mirror

// Represents a loaded DEX file with its isolated ClassLoader and loaded classes.
// This class encapsulates the runtime state of a DEX file, enabling class-level
// isolation through a dedicated ClassLoader.
class LoadedDex {
 public:
  LoadedDex(std::string name,
            std::vector<std::unique_ptr<const DexFile>> dex_files,
            Handle<mirror::ClassLoader> class_loader);

  // Disable copy, enable move
  LoadedDex(const LoadedDex&) = delete;
  LoadedDex& operator=(const LoadedDex&) = delete;
  LoadedDex(LoadedDex&&) = default;
  LoadedDex& operator=(LoadedDex&&) = default;

  // Returns the identifier name for this loaded DEX.
  const std::string& GetName() const { return name_; }

  // Returns the DEX files contained in this loaded DEX.
  const std::vector<std::unique_ptr<const DexFile>>& GetDexFiles() const {
    return dex_files_;
  }

  // Returns the ClassLoader associated with this loaded DEX.
  // This ClassLoader provides isolation from other LoadedDex instances.
  Handle<mirror::ClassLoader> GetClassLoader() const { return class_loader_; }

  // Returns all classes that have been loaded via LoadAllClasses or FindClass.
  const std::vector<ObjPtr<mirror::Class>>& GetLoadedClasses() const {
    return loaded_classes_;
  }

  // Finds a class by its descriptor in this loaded DEX.
  // Returns nullptr if the class is not found or not loaded.
  ObjPtr<mirror::Class> FindClass(const char* descriptor) const;

  // Registers a loaded class. Called by DexLoader during class loading.
  void RegisterLoadedClass(ObjPtr<mirror::Class> klass);

 private:
  std::string name_;
  std::vector<std::unique_ptr<const DexFile>> dex_files_;
  Handle<mirror::ClassLoader> class_loader_;
  std::vector<ObjPtr<mirror::Class>> loaded_classes_;
  std::unordered_map<std::string, ObjPtr<mirror::Class>> class_map_;
};

// DexLoader provides functionality to load DEX files with isolated ClassLoaders.
// Each loaded DEX gets its own ClassLoader, enabling the same class descriptor
// to exist as different Class objects in different LoadedDex instances.
//
// This class is NOT thread-safe. External synchronization is required if used
// from multiple threads.
class DexLoader {
 public:
  // Creates a DexLoader that operates within the given Runtime.
  explicit DexLoader(Runtime* runtime);

  // Disable copy, enable move
  DexLoader(const DexLoader&) = delete;
  DexLoader& operator=(const DexLoader&) = delete;
  DexLoader(DexLoader&&) = default;
  DexLoader& operator=(DexLoader&&) = default;

  // Loads a DEX file from the given path with an isolated ClassLoader.
  //
  // The returned LoadedDex contains the parsed DexFile(s) and a newly created
  // ClassLoader, but NO classes have been loaded yet. Call LoadAllClasses()
  // to populate the Class objects.
  //
  // Parameters:
  //   dex_path - Path to the DEX file (or APK containing DEX)
  //   name - Identifier for this loaded DEX (used for debugging/logging)
  //
  // Returns:
  //   LoadedDex on success, nullptr on failure (error logged)
  std::unique_ptr<LoadedDex> LoadDex(const char* dex_path,
                                        const std::string& name);

  // Loads all classes defined in the given LoadedDex.
  //
  // This iterates through all class definitions in the LoadedDex's DexFile(s)
  // and calls ClassLinker::DefineClass() to create mirror::Class objects.
  // The loaded classes are stored in the LoadedDex and can be accessed via
  // GetLoadedClasses() or FindClass().
  //
  // Note: This operation may be time-consuming for DEX files with many classes.
  // Consider lazy loading (via FindClass) if not all classes are needed.
  //
  // Parameters:
  //   loaded_dex - The LoadedDex to load classes from
  //
  // Returns:
  //   true if all classes loaded successfully, false otherwise
  bool LoadAllClasses(LoadedDex* loaded_dex);

  // Finds a class by descriptor in the given LoadedDex.
  //
  // If the class has already been loaded (via LoadAllClasses or previous
  // FindClass call), it is returned from the LoadedDex's cache.
  // Otherwise, ClassLinker::FindClass() is called to load the class
  // on-demand.
  //
  // Parameters:
  //   loaded_dex - The LoadedDex to search in
  //   descriptor - Class descriptor (e.g., "Ljava/lang/String;")
  //
  // Returns:
  //   The Class object if found, nullptr otherwise
  ObjPtr<mirror::Class> FindClass(LoadedDex* loaded_dex,
                                   const char* descriptor);

 private:
  // Creates an isolated ClassLoader for the given DEX files.
  // This ClassLoader is not attached to any parent ClassLoader,
  // providing complete isolation.
  Handle<mirror::ClassLoader> CreateIsolatedClassLoader(
      Thread* self,
      const std::vector<const DexFile*>& dex_files);

  Runtime* runtime_;
  ClassLinker* class_linker_;
};

}  // namespace art

#endif  // ART_OATCHECK_DEX_LOADER_H_
