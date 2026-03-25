# DexLoader Component Design

## Overview

`DexLoader` is a low-level component for loading DEX files and managing class objects with **isolation support**. It is designed to enable use cases such as comparing classes from different DEX versions.

### Key Capabilities

1. **Load DEX files** - Parse and validate DEX format
2. **Create isolated ClassLoaders** - Each DEX gets its own ClassLoader
3. **Load class objects** - Define classes from DEX into runtime (mirror::Class)
4. **Provide class lookup** - Find loaded classes by descriptor

### What DexLoader Does NOT Do

- **No comparison logic** - Comparison is the responsibility of external components
- **No bytecode analysis** - Only class metadata (methods, fields, signatures)
- **No verification results** - Does not verify bytecode correctness

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DexLoader Component                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         LoadedDex (per DEX)                          │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │   │
│  │  │   DexFile(s)    │  │  ClassLoader    │  │  Loaded Classes   │  │   │
│  │  │  (parsed DEX)   │  │   (isolated)    │  │ (mirror::Class*)  │  │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────┘  │   │
│  │                                                                     │   │
│  │  Key insight: Each LoadedDex has its OWN ClassLoader, enabling    │   │
│  │  the same class descriptor to exist as DIFFERENT Class objects    │   │
│  │  in different LoadedDex instances.                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        DexLoader (factory)                           │   │
│  │                                                                      │   │
│  │  LoadDex(path) -> LoadedDex                                          │   │
│  │    1. Parse DEX file(s) -> DexFile                                  │   │
│  │    2. Create isolated ClassLoader                                     │   │
│  │    3. Return LoadedDex (DexFile + ClassLoader, no classes loaded)   │   │
│  │                                                                      │   │
│  │  LoadAllClasses(LoadedDex)                                           │   │
│  │    1. For each class in DexFile:                                      │   │
│  │       - Call ClassLinker::DefineClass()                               │   │
│  │       - Store resulting mirror::Class in LoadedDex                     │   │
│  │    2. All classes now defined in runtime                               │   │
│  │                                                                      │   │
│  │  FindClass(LoadedDex, descriptor) -> mirror::Class                     │   │
│  │    - Search in LoadedDex's loaded classes                             │   │
│  │    - Or call ClassLinker::FindClass with LoadedDex's ClassLoader      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### Why LoadedDex instead of just DexFile?

| Capability | DexFile | LoadedDex |
|------------|---------|-----------|
| Parse DEX structure | ✅ | ✅ (contains DexFile) |
| Store ClassLoader | ❌ | ✅ (essential for isolation) |
| Store loaded Class objects | ❌ | ✅ |
| Support `FindClass` lookup | ❌ | ✅ |
| Enable class-level isolation | ❌ | ✅ |

**Key insight**: `DexFile` is just a file parser. `LoadedDex` adds the **runtime context** needed to manage classes in memory with proper isolation.

### Why separate LoadDex and LoadAllClasses?

```
LoadDex() phase:
┌─────────────────────────────────────────────────────────┐
│  1. Open file → Parse DEX header                        │
│  2. Validate DEX format                                 │
│  3. Create DexFile object (in-memory DEX representation)  │
│  4. Create ClassLoader (empty, no classes loaded yet)    │
│                                                          │
│  At this point: DEX is in memory, but NO classes are     │
│  defined in the runtime. The ClassLoader is empty.     │
└─────────────────────────────────────────────────────────┘

LoadAllClasses() phase:
┌─────────────────────────────────────────────────────────┐
│  For each class definition in the DEX:                  │
│                                                          │
│  1. Allocate mirror::Class object (on GC Heap)           │
│  2. Parse class metadata (superclass, interfaces, etc.)  │
│  3. Define methods and fields                            │
│  4. Register Class in ClassLoader's ClassTable          │
│  5. Class is now findable via FindClass()                │
│                                                          │
│  At this point: All classes are defined in the runtime   │
│  with full Class objects that can be compared.           │
└─────────────────────────────────────────────────────────┘
```

**Analogy**:
- `LoadDex()` = Taking a book from the shelf and placing it on the table (book is closed)
- `LoadAllClasses()` = Opening the book and reading each page into memory

This separation is important because:
1. **Performance**: Some use cases only need to inspect DEX structure without loading classes
2. **Memory**: Loading classes allocates GC objects; deferring this gives control
3. **Flexibility**: Allows selective class loading if not all classes are needed

## Class Isolation for DEX Version Comparison

### The Problem

When comparing classes from two DEX file versions:

```cpp
// WRONG: Both DEX versions share the same ClassLoader
Handle<ClassLoader> shared_loader = ...;

// Load from old DEX
auto classA_old = class_linker->FindClass(self, "LClassA;", shared_loader);

// Load from new DEX - Returns the SAME Class object!
auto classA_new = class_linker->FindClass(self, "LClassA;", shared_loader);
// classA_new == classA_old (same pointer!)
```

The problem: `ClassLinker::FindClass()` first checks the ClassLoader's `ClassTable`. If a class with the descriptor is already loaded, it returns the existing Class object. This prevents comparing different DEX versions.

### The Solution: Isolated ClassLoaders

Use a separate `ClassLoader` for each DEX version:

```cpp
// CORRECT: Each DEX version has its own ClassLoader
Handle<ClassLoader> loader_old = CreateIsolatedClassLoader(dex_old);
Handle<ClassLoader> loader_new = CreateIsolatedClassLoader(dex_new);

// Load from old DEX
auto classA_old = class_linker->FindClass(self, "LClassA;", loader_old);

// Load from new DEX - Returns DIFFERENT Class object!
auto classA_new = class_linker->FindClass(self, "LClassA;", loader_new);
// classA_new != classA_old (different pointers!)
```

Now both Class objects can exist simultaneously and be compared.

## Implementation Example

```cpp
// External component: ClassComparator (NOT part of DexLoader)
class ClassComparator {
 public:
  struct Diff {
    std::string descriptor;
    std::vector<std::string> changes;
  };

  // Compare two Class objects from different DEX versions
  Diff Compare(ObjPtr<mirror::Class> old_class,
               ObjPtr<mirror::Class> new_class) {
    Diff result;
    result.descriptor = old_class->GetDescriptor();

    // Compare access flags
    if (old_class->GetAccessFlags() != new_class->GetAccessFlags()) {
      result.changes.push_back("Access flags changed");
    }

    // Compare superclass
    if (old_class->GetSuperClass() != new_class->GetSuperClass()) {
      result.changes.push_back("Superclass changed");
    }

    // Compare method counts
    size_t old_method_count = old_class->NumDirectMethods() +
                              old_class->NumVirtualMethods();
    size_t new_method_count = new_class->NumDirectMethods() +
                              new_class->NumVirtualMethods();
    if (old_method_count != new_method_count) {
      result.changes.push_back("Method count changed: " +
                               std::to_string(old_method_count) + " -> " +
                               std::to_string(new_method_count));
    }

    // Compare field counts
    size_t old_field_count = old_class->NumInstanceFields() +
                             old_class->NumStaticFields();
    size_t new_field_count = new_class->NumInstanceFields() +
                             new_class->NumStaticFields();
    if (old_field_count != new_field_count) {
      result.changes.push_back("Field count changed: " +
                               std::to_string(old_field_count) + " -> " +
                               std::to_string(new_field_count));
    }

    return result;
  }
};

// High-level workflow using DexLoader + ClassComparator
void CompareDexVersions(const char* old_dex_path, const char* new_dex_path) {
  // Step 1: Create DexLoader
  DexLoader loader(Runtime::Current());

  // Step 2: Load both DEX versions (with isolated ClassLoaders)
  auto old_dex = loader.LoadDex(old_dex_path, "old");
  auto new_dex = loader.LoadDex(new_dex_path, "new");

  // Step 3: Load all classes from both versions
  loader.LoadAllClasses(old_dex.get());
  loader.LoadAllClasses(new_dex.get());

  // Step 4: Use external comparator (NOT part of DexLoader)
  ClassComparator comparator;

  // Compare each class
  for (const auto& old_class : old_dex->GetLoadedClasses()) {
    const char* descriptor = old_class->GetDescriptor();

    // Find matching class in new version
    ObjPtr<mirror::Class> new_class = new_dex->FindClass(descriptor);

    if (new_class != nullptr) {
      auto diff = comparator.Compare(old_class, new_class);
      if (!diff.changes.empty()) {
        LOG(INFO) << "Class " << descriptor << " changed:";
        for (const auto& change : diff.changes) {
          LOG(INFO) << "  - " << change;
        }
      }
    } else {
      LOG(INFO) << "Class " << descriptor << " removed in new version";
    }
  }
}
```

## Key Files and Locations

| Component | File Path |
|-----------|-----------|
| DexFileLoader | `libdexfile/dex/dex_file_loader.h` |
| DexFile | `libdexfile/dex/dex_file.h` |
| ClassLinker | `runtime/class_linker.h` |
| ClassLinker::CreatePathClassLoader | `runtime/class_linker.cc:10911` |
| ClassLinker::CreateWellKnownClassLoader | `runtime/class_linker.cc:10779` |
| mirror::ClassLoader | `runtime/mirror/class_loader.h` |
| mirror::Class | `runtime/mirror/class.h` |
| Runtime | `runtime/runtime.h` |

## References

- See `oatcheck.cc` for existing DEX loading and class iteration examples
- See `runtime/class_linker.cc` for full ClassLinker implementation
- See `runtime/class_loader_context.cc` for ClassLoader creation
- See `runtime/mirror/class.h` for complete Class API
