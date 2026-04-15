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

#include <bitset>
#include <cstddef>
#include <map>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "android-base/logging.h"
#include "android-base/macros.h"
#include "android-base/stringprintf.h"
#include "android-base/strings.h"
#include "class_status.h"
#include "cmdline.h"
#include "dex/class_accessor-inl.h"
#include "dex/class_accessor.h"
#include "dex/dex_file.h"
#include "dex/dex_file_loader.h"
#include "dex/dex_file_structs.h"
#include "dex/dex_instruction-inl.h"
#include "dex/dex_instruction.h"
#include "dex/dex_instruction_iterator.h"
#include "dex/dex_instruction_utils.h"
#include "dex/signature.h"
#include "dex/signature-inl.h"
#include "graaflib/algorithm/topological_sorting/dfs_topological_sorting.h"
#include "graaflib/graph.h"
#include "graaflib/types.h"
#include "oat/oat_file.h"
#include "oat/oat_file-inl.h"
#include "oat/oat_quick_method_header.h"
#include "oat/stack_map.h"
#include "runtime-inl.h"
#include "runtime.h"
#include "scoped_thread_state_change.h"
#include "scoped_thread_state_change-inl.h"
namespace art {
enum class DependencyType {
  kStaticFieldLayout,
  kInstanceFieldLayout,
  kVirtualTableLayout,
  kDependencyTypeCount
};

// Interface method change: independent change tracking for invoke-interface
// Key: interface_descriptor, Value: set of "method_name:signature" that changed
using InterfaceMethodChanges = std::unordered_map<std::string, std::unordered_set<std::string>>;

struct DexSymId {
  uint32_t id;
  // |-- 8 bits: dex file index --|-- 8 bits: is method --|-- 16 bits: sym id --|
  // sym id is class def id
  void SetDexFileIndex(uint32_t dex_file_index) {
    id = (id & 0x00FFFFFF) | (dex_file_index << 24);
  }
  uint32_t GetDexFileIndex() const {
    return (id >> 24) & 0xFF;
  }
  bool IsMethod() const {
    return (id & 0x00FF0000) != 0;
  }
  void SetSymId(uint32_t sym_id) {
    id = (id & 0xFFFF0000) | (sym_id & 0x0000FFFF);
  }
  uint32_t GetSymId() const {
    return id & 0x0000FFFF;
  }
  DexSymId(uint32_t dex_file_index, bool is_method, uint32_t sym_id) : id(0) {
    SetDexFileIndex(dex_file_index);
    if (is_method) {
      id |= 0x00010000;
    }
    SetSymId(sym_id);
  }
  // Construct DexSymId from graaf vertex_id_t. Since vertex_id_t is directly
  // mapped to DexSymId.id, we can directly assign it.
  explicit DexSymId(graaf::vertex_id_t vertex_id) : id(static_cast<uint32_t>(vertex_id)) {}
};

class DependencyGraphNode {
 public:
  DependencyGraphNode(std::string descriptor, bool is_changed = false)
      : descriptor_(std::move(descriptor)), changes_(is_changed) {}

  const std::string& GetDescriptor() const { return descriptor_; }
  bool IsChanged() const { return changes_.any(); }

 private:
  std::string descriptor_;
  std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)> changes_;
  friend class DependencyGraphPropagator;
  friend class DependencyGraphBuilder;
  friend class BcpDependencyGraphPropagator;
};

// Caches all boot classpath class descriptors for fast lookup
static std::unordered_set<std::string> bcp_class_descriptors;

// Initializes the bcp_class_descriptors cache from ClassLinker::GetBootClassPath()
static void InitializeBootClassPathDescriptors() {
  if (!bcp_class_descriptors.empty()) {
    return;  // Already initialized
  }

  // Get all boot class path DexFiles
  const auto& bcp_dex_files = Runtime::Current()->GetClassLinker()->GetBootClassPath();

  // Collect all class descriptors from all boot class path DexFiles
  for (const DexFile* dex_file : bcp_dex_files) {
    uint32_t num_class_defs = dex_file->NumClassDefs();
    for (uint32_t i = 0; i < num_class_defs; ++i) {
      const dex::ClassDef& class_def = dex_file->GetClassDef(i);
      const char* class_descriptor = dex_file->GetClassDescriptor(class_def);
      bcp_class_descriptors.insert(class_descriptor);
    }
  }
}

// Returns true if the class descriptor represents a boot classpath class.
// Uses the cached boot classpath class descriptors.
bool IsBootClasspathClass(std::string_view class_descriptor) {
  // Initialize cache if not already done
  InitializeBootClassPathDescriptors();

  // Lookup in the cached boot classpath class descriptors
  return bcp_class_descriptors.find(std::string(class_descriptor)) != bcp_class_descriptors.end();
}

class DependencyGraphEdge {
 public:
  DependencyGraphEdge(std::bitset<3> deps) : deps_(std::move(deps)) {}

  const std::bitset<3>& GetDeps() const { return deps_; }
  void SetDeps(const std::bitset<3>& deps) { deps_ = deps; }

 private:
  std::bitset<3> deps_;
};
template <typename GraphNode, typename GraphEdge, graaf::graph_type GraphType>
class GraphBase {
public:
  GraphBase() = default;
  ~GraphBase() = default;
  GraphBase(GraphBase&&) = default;
  GraphBase& operator=(GraphBase&&) = default;
  GraphBase(const GraphBase&) = default;
  GraphBase& operator=(const GraphBase&) = default;

  template <typename... Args>
  requires std::is_constructible_v<GraphNode, Args&&...>
  graaf::vertex_id_t
  AddVertexIfAbsent(DexSymId dex_sym_id, Args&&... args) {
    graaf::vertex_id_t vertex_id = static_cast<graaf::vertex_id_t>(dex_sym_id.id);
    if (graph_.has_vertex(vertex_id))
      return vertex_id;
    GraphNode node(std::forward<Args>(args)...);
    graph_.add_vertex(node, vertex_id);
    return vertex_id;
  }

  std::string Summary() const {
    return android::base::StringPrintf(
        "vecs:%zu edges:%zu", graph_.vertex_count(), graph_.edge_count());
  }

  const auto& GetVertices() const {
    return graph_.get_vertices();
  }

  graaf::graph<GraphNode, GraphEdge, GraphType> graph_;
};
class DependencyGraph: public GraphBase<DependencyGraphNode, DependencyGraphEdge, graaf::graph_type::DIRECTED> {
 public:
  DependencyGraph() = default;
  ~DependencyGraph() = default;
  DependencyGraph(DependencyGraph&&) = default;
  DependencyGraph& operator=(DependencyGraph&&) = default;
  DependencyGraph(const DependencyGraph&) = default;
  DependencyGraph& operator=(const DependencyGraph&) = default;
  void UpdateEdge(const DexSymId from_dex_sym_id,
                  const DexSymId to_dex_sym_id,
                  std::bitset<3> deps) {
    graaf::vertex_id_t from_vertex_id = static_cast<graaf::vertex_id_t>(from_dex_sym_id.id);
    graaf::vertex_id_t to_vertex_id = static_cast<graaf::vertex_id_t>(to_dex_sym_id.id);
    if (graph_.has_edge(from_vertex_id, to_vertex_id)) {
      auto& edge = graph_.get_edge(from_vertex_id, to_vertex_id);
      edge.SetDeps(edge.GetDeps() | deps);
    } else {
      graph_.add_edge(from_vertex_id, to_vertex_id, DependencyGraphEdge(deps));
    }
  }
 private:
  friend class DependencyGraphBuilder;
  friend class DependencyGraphPropagator;
};

class BcpDependencyGraph : public DependencyGraph {
 public:
  BcpDependencyGraph() = default;
  ~BcpDependencyGraph() = default;

  // Set dex files reference for ClassAccessor construction
  void SetDexFiles(const std::vector<std::unique_ptr<const art::DexFile>>* dex_files) {
    dex_files_ = dex_files;
  }

  // Construct ClassAccessor from DexSymId
  // DexSymId encodes: dex_file_index in high bits, class_def_index in low bits
  art::ClassAccessor GetClassAccessor(const DexSymId& dex_sym_id) const {
    uint32_t dex_file_index = dex_sym_id.GetDexFileIndex();
    uint32_t class_def_index = dex_sym_id.GetSymId();

    const art::DexFile* dex = dex_files_->at(dex_file_index).get();
    return art::ClassAccessor(*dex, class_def_index);
  }

  // Check if DexSymId is valid (within bounds)
  // Returns false for external classes (dex_file_index = 0xFF)
  bool HasClassAccessor(const DexSymId& dex_sym_id) const {
    uint32_t dex_file_index = dex_sym_id.GetDexFileIndex();
    uint32_t class_def_index = dex_sym_id.GetSymId();

    // External class marker (0xFF) is not valid for ClassAccessor
    if (dex_file_index == 0xFF) {
      return false;
    }
    if (dex_file_index >= dex_files_->size()) {
      return false;
    }
    const art::DexFile* dex = dex_files_->at(dex_file_index).get();
    return class_def_index < dex->NumClassDefs();
  }

  // Check if DexSymId represents an external class (not in app dex files)
  bool IsExternalClass(const DexSymId& dex_sym_id) const {
    return dex_sym_id.GetDexFileIndex() == 0xFF;
  }

 private:
  const std::vector<std::unique_ptr<const art::DexFile>>* dex_files_ = nullptr;
  friend class BcpDependencyGraphBuilder;
};

// Base class for building dependency graphs from DEX files.
// Extracts common members and methods from BcpDependencyGraphBuilder and DependencyGraphBuilder.
class DependencyGraphBuilderBase {
 public:
  virtual ~DependencyGraphBuilderBase() = default;

  const std::vector<std::unique_ptr<const art::DexFile>>& GetDexFiles() const {
    return dex_files_;
  }

  // Main entry point for building the dependency graph.
  virtual bool BuildGraph(std::string* error_msg) = 0;

 protected:
  // Common member variables
  std::vector<std::unique_ptr<const art::DexFile>> dex_files_;

  // Descriptor -> DexSymId mapping for O(1) lookup
  // This maps class descriptors to their DexSymId (using class_def_index)
  std::unordered_map<std::string, DexSymId> descriptor_to_symid_;

  // Counter for assigning unique sym_ids to external classes
  uint32_t external_class_counter_ = 0;

  // Step 1: Build descriptor -> DexSymId mapping for all classes in the dex file.
  // Uses class_def_index (not type_idx) to correctly construct ClassAccessor/DexSymId.
  bool BuildDescriptorMapping(const art::DexFile* dex, size_t dex_file_idx, DependencyGraph* graph) {
    for (art::ClassAccessor accessor : dex->GetClasses()) {
      uint32_t class_def_index = accessor.GetClassDefIndex();
      const char* class_descriptor = accessor.GetDescriptor();
      DexSymId class_dex_sym_id(dex_file_idx, false, class_def_index);
      descriptor_to_symid_.emplace(class_descriptor, class_dex_sym_id);
      // Also add vertex for the class itself
      graph->AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);
    }
    return true;
  }

  // Get or create DexSymId for a descriptor.
  // If found in mapping, returns existing DexSymId.
  // If not found, creates external DexSymId (dex_file_index = 0xFF, unique sym_id) and stores it.
  DexSymId GetOrCreateDexSymId(const std::string& descriptor) {
    auto it = descriptor_to_symid_.find(descriptor);
    if (it != descriptor_to_symid_.end()) {
      return it->second;
    }
    // Not found - create external class marker (dex_file_index = 0xFF, unique sym_id)
    DexSymId external_symid(static_cast<uint32_t>(0xFF), false, external_class_counter_);
    descriptor_to_symid_.emplace(descriptor, external_symid);
    external_class_counter_++;
    return external_symid;
  }

  // Step 2: Build dependency edges using the descriptor mapping.
  // For superclass: if found in mapping, use the DexSymId; otherwise create external DexSymId.
  bool BuildDependencyEdges(const art::DexFile* dex, ATTRIBUTE_UNUSED size_t dex_file_idx, DependencyGraph* graph) {
    for (art::ClassAccessor accessor : dex->GetClasses()) {
      const dex::ClassDef& class_def = dex->GetClassDef(accessor.GetClassDefIndex());
      const char* class_descriptor = accessor.GetDescriptor();

      // Get DexSymId for current class
      auto it = descriptor_to_symid_.find(class_descriptor);
      if (it == descriptor_to_symid_.end()) {
        continue;  // Should not happen
      }
      DexSymId class_dex_sym_id = it->second;

      // Handle superclass
      if (class_def.superclass_idx_ != dex::TypeIndex::Invalid()) {
        const char* superclass_descriptor = dex->GetTypeDescriptor(class_def.superclass_idx_);
        DexSymId superclass_dex_sym_id = GetOrCreateDexSymId(superclass_descriptor);

        // Add vertex for superclass (if external, still need vertex for graph completeness)
        graph->AddVertexIfAbsent(superclass_dex_sym_id, superclass_descriptor, false);
        // Edge from superclass to subclass: subclass depends on superclass
        graph->UpdateEdge(superclass_dex_sym_id, class_dex_sym_id, std::bitset<3>(7));
      }
    }
    return true;
  }
};

class BcpDependencyGraphBuilder : public DependencyGraphBuilderBase {
 public:
  BcpDependencyGraphBuilder(const std::vector<const char*>& jar_file_paths, BcpDependencyGraph* bcp_graph)
      : jar_file_paths_(jar_file_paths), bcp_graph_(*bcp_graph) {}

  bool BuildGraph(std::string* error_msg) override {
    if (!ExtractDexFromJars(error_msg)) {
      return false;
    }

    // Set the dex files reference on BcpDependencyGraph
    bcp_graph_.SetDexFiles(&dex_files_);

    size_t i = 0;
    for (const auto& dex : dex_files_) {
      if (!AnalyzeDexClasses(dex.get(), i, error_msg)) {
        LOG(ERROR) << "Failed to analyze DEX classes: " << *error_msg;
        return false;
      }
      i++;
    }
    LOG(INFO) << "BcpDependencyGraph built: " << bcp_graph_.Summary();
    return true;
  }

 private:
  // Extract all classes*.dex from all JAR files into `dex_files_`.
  bool ExtractDexFromJars(std::string* error_msg) {
    for (const char* jar_file_path : jar_file_paths_) {
      if (jar_file_path == nullptr) {
        continue;
      }

      // Create DexFileLoader with JAR path as location
      art::DexFileLoader loader(jar_file_path, /*location=*/jar_file_path);

      // Open all DEX files in the JAR container
      std::vector<std::unique_ptr<const art::DexFile>> jar_dex_files;
      bool success = loader.Open(
          /*verify=*/true,
          /*verify_checksum=*/true,
          /*allow_no_dex_files=*/false,
          error_msg,
          &jar_dex_files);

      if (!success || jar_dex_files.empty()) {
        LOG(ERROR) << "Failed to load DEX from JAR " << jar_file_path << ": " << *error_msg;
        return false;
      }

      LOG(INFO) << "Loaded " << jar_dex_files.size() << " DEX file(s) from " << jar_file_path;

      // Move loaded dex files to the global list
      for (auto& dex : jar_dex_files) {
        dex_files_.push_back(std::move(dex));
      }
    }

    if (dex_files_.empty()) {
      *error_msg = "No DEX files loaded from any JAR files";
      return false;
    }

    return true;
  }

  // Combined method that calls base class methods for mapping and edges
  bool AnalyzeDexClasses(const art::DexFile* dex, size_t dex_file_idx, ATTRIBUTE_UNUSED std::string* error_msg) {
    // Step 1: Build descriptor -> DexSymId mapping
    if (!BuildDescriptorMapping(dex, dex_file_idx, &bcp_graph_)) {
      return false;
    }
    // Step 2: Build dependency edges
    if (!BuildDependencyEdges(dex, dex_file_idx, &bcp_graph_)) {
      return false;
    }
    return true;
  }

  std::vector<const char*> jar_file_paths_;
  BcpDependencyGraph& bcp_graph_;
};

class DependencyGraphBuilder : public DependencyGraphBuilderBase {
 public:
  DependencyGraphBuilder(const char* apk_file_path,
                          DependencyGraph* graph,
                          const InterfaceMethodChanges* interface_method_changes = nullptr)
      : interface_method_changes_(interface_method_changes), apk_file_path_(apk_file_path), graph_(*graph) {
    // TODO: There is no neccessity to analysis all methods in the APK, only compiled methods in
    // OAT.
  }

  bool BuildGraph(std::string* error_msg) override {
    if (!ExtractDexFromApk(error_msg)) {
      return false;
    }
    size_t i = 0;
    // Step 1: Build descriptor -> DexSymId mapping for all dex files
    for (const auto& dex : dex_files_) {
      if (!BuildDescriptorMapping(dex.get(), i, &graph_)) {
        LOG(ERROR) << "Failed to build descriptor mapping: " << *error_msg;
        return false;
      }
      i++;
    }
    // Step 2: Analyze classes and methods using the mapping
    i = 0;
    for (const auto& dex : dex_files_) {
      if (!AnalyzeDexMethods(dex.get(), i, error_msg)) {
        LOG(ERROR) << "Failed to analyze DEX methods: " << *error_msg;
        return false;
      }
      if (!BuildDependencyEdges(dex.get(), i, &graph_)) {
        LOG(ERROR) << "Failed to build dependency edges: " << *error_msg;
        return false;
      }
      i++;
    }
    LOG(INFO) << graph_.Summary();
    return true;
  }

 private:
  // Pointer to interface method changes from BCP diff
  const InterfaceMethodChanges* interface_method_changes_;
  const char* apk_file_path_;
  DependencyGraph& graph_;

  // Extract all classes*.dex from APK into `dex_files_`.
  bool ExtractDexFromApk(std::string* error_msg) {
    if (apk_file_path_ == nullptr) {
      return true;
    }

    // Create DexFileLoader with APK path as location
    art::DexFileLoader loader(apk_file_path_, /*location=*/apk_file_path_);

    // Open all DEX files in the container (APK is a ZIP container)
    bool success = loader.Open(
        /*verify=*/true,
        /*verify_checksum=*/true,
        /*allow_no_dex_files=*/false,
        error_msg,
        &dex_files_);

    if (!success || dex_files_.empty()) {
      LOG(ERROR) << "Failed to load DEX from APK: " << *error_msg;
      return false;
    }

    LOG(INFO) << "Loaded " << dex_files_.size() << " DEX file(s):\n";
    return true;
  }

  // Analyze method instructions and build method-level dependency edges.
  bool AnalyzeDexMethods(const art::DexFile* dex, size_t dex_file_idx, ATTRIBUTE_UNUSED std::string* error_msg) {
    // Build dependency edges based on method instructions.
    uint32_t count = 0;
    for (art::ClassAccessor accessor : dex->GetClasses()) {
      for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
        const art::CodeItemInstructionAccessor& code = method.GetInstructions();
        //std::string method_name(dex->PrettyMethod(method.GetIndex()));
        std::string method_name(android::base::StringPrintf("d%zum%u", dex_file_idx,count));
        DexSymId method_dex_sym_id(dex_file_idx, true, method.GetIndex());
        graph_.AddVertexIfAbsent(method_dex_sym_id, method_name, false);
        //if (count++ > 50000) // TODO: remove me
          //return true;
        for (auto it = code.begin(); it != code.end(); it++) {
          DexInstructionPcPair inst = *it;
          if (IsInstructionInvoke(inst->Opcode())) {
            DexInvokeType invoke_type = InvokeInstructionType(inst->Opcode());
            switch (invoke_type) {
              case kDexInvokeVirtual: {
                auto method_idx = inst->VRegB();
                const dex::MethodId& method_id = dex->GetMethodId(method_idx);
                const dex::TypeId& type_id = dex->GetTypeId(method_id.class_idx_);
                const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
                const char* class_descriptor = dex->GetStringData(name_id);
                DexSymId class_dex_sym_id(dex_file_idx, false, method_id.class_idx_.index_);
                graph_.AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);

                // Edge from class to method: method depends on class (for virtual table layout)
                graph_.UpdateEdge(
                    class_dex_sym_id,
                    method_dex_sym_id,
                    std::bitset<3>(1 << static_cast<size_t>(DependencyType::kVirtualTableLayout)));
                break;
              }
              case kDexInvokeSuper:
              case kDexInvokeDirect:
              case kDexInvokeStatic: {
                // For invoke-super, invoke-direct, and invoke-static, if the target is
                // from boot classpath, the call will always invalidate on system upgrade.
                auto method_idx = inst->VRegB();
                const dex::MethodId& method_id = dex->GetMethodId(method_idx);
                const dex::TypeId& type_id = dex->GetTypeId(method_id.class_idx_);
                const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
                const char* class_descriptor = dex->GetStringData(name_id);

                if (IsBootClasspathClass(class_descriptor)) {
                  // Mark the calling method as changed - all dependency bits set
                  graaf::vertex_id_t vertex_id = static_cast<graaf::vertex_id_t>(method_dex_sym_id.id);
                  auto& vertex = graph_.graph_.get_vertex(vertex_id);
                  vertex.changes_.set();
                }
                break;
              }
              case kDexInvokeInterface: {
                // Get interface type and method info
                auto method_idx = inst->VRegB();
                const dex::MethodId& method_id = dex->GetMethodId(method_idx);
                const dex::TypeId& type_id = dex->GetTypeId(method_id.class_idx_);
                const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
                const char* interface_descriptor = dex->GetStringData(name_id);

                // Check if this is a boot classpath interface
                if (!IsBootClasspathClass(interface_descriptor)) {
                  break;
                }

                // Get method name and signature
                const char* called_method_name = dex->GetMethodName(method_id);
                Signature method_sig = dex->GetMethodSignature(method_id);
                std::string method_key = std::string(called_method_name) + ":" + method_sig.ToString();

                // Check if interface method has changed
                if (interface_method_changes_ != nullptr) {
                  auto interface_it = interface_method_changes_->find(interface_descriptor);
                  if (interface_it != interface_method_changes_->end() &&
                      interface_it->second.find(method_key) != interface_it->second.end()) {
                  // Interface method changed - mark calling method as affected
                  graaf::vertex_id_t vertex_id = static_cast<graaf::vertex_id_t>(method_dex_sym_id.id);
                  auto& vertex = graph_.graph_.get_vertex(vertex_id);
                  vertex.changes_.set();
                }
              }
                break;
              }
              default:{
                LOG(WARNING) << "    Unknown invoke type at dex pc " << inst.DexPc()
                             << ": opcode=" << static_cast<int>(inst->Opcode()) << "\n";
                break;
              }
            }
          } else if (IsInstructionIGetOrIPut(inst->Opcode())) {
            auto field_idx = inst->VRegC();
            const dex::FieldId& field_id = dex->GetFieldId(field_idx);
            const dex::TypeId& type_id = dex->GetTypeId(field_id.class_idx_);
            const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
            const char* class_descriptor = dex->GetStringData(name_id);
            DexSymId class_dex_sym_id(dex_file_idx, false, field_id.class_idx_.index_);
            graph_.AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);

            // Edge from class to method: method depends on class (for instance field layout)
            graph_.UpdateEdge(
                class_dex_sym_id,
                method_dex_sym_id,
                std::bitset<3>(1 << static_cast<size_t>(DependencyType::kInstanceFieldLayout)));
          } else if (IsInstructionSGetOrSPut(inst->Opcode())) {
            auto field_idx = inst->VRegB();
            const dex::FieldId& field_id = dex->GetFieldId(field_idx);
            const dex::TypeId& type_id = dex->GetTypeId(field_id.class_idx_);
            const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
            const char* class_descriptor = dex->GetStringData(name_id);
            DexSymId class_dex_sym_id(dex_file_idx, false, field_id.class_idx_.index_);
            graph_.AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);

            // Edge from class to method: method depends on class (for static field layout)
            graph_.UpdateEdge(
                class_dex_sym_id,
                method_dex_sym_id,
                std::bitset<3>(1 << static_cast<size_t>(DependencyType::kStaticFieldLayout)));
          }
        }
      }
    }
    return true;
  }
};

class DependencyGraphPropagator {
 public:
  DependencyGraphPropagator(DependencyGraph* graph) : graph_(*graph) {}
  virtual ~DependencyGraphPropagator() = default;
  virtual void SetInitialChanges();  // TODO: Set initial changes based on changed BCP classes.
  void PropagateChanges() {
    // Propagate changes through the dependency graph.
    // Edge Y → X means X depends on Y, so if Y changes, X is also affected.
    // We propagate changes in topological order.
    auto& inner_graph = graph_.graph_;
    auto result = graaf::algorithm::dfs_topological_sort<DependencyGraphNode, DependencyGraphEdge>(
        graph_.graph_);
    if (!result.has_value()) {
      LOG(ERROR) << "Dependency graph has cycles!";
      return;
    }
    const std::vector<graaf::vertex_id_t>& topo = result.value();

    // Iterate in topological order
    for (auto it = topo.begin(); it != topo.end(); ++it) {
      graaf::vertex_id_t id = *it;
      auto& vertex = inner_graph.get_vertex(id);

      // For all successors (X where id → X, meaning X depends on id)
      // If id has changes, X also gets those changes
      auto successors = inner_graph.get_neighbors(id);
      for (graaf::vertex_id_t succ_id : successors) {
        auto& succ_vertex = inner_graph.get_vertex(succ_id);
        auto edge = inner_graph.get_edge(id, succ_id);
        succ_vertex.changes_ |= edge.GetDeps() & vertex.changes_;
      }
    }
  }

 private:
  DependencyGraph& graph_;
};

// BcpDependencyGraphPropagator compares new DexFiles against the BCP class descriptors
// to determine which classes have changed.
class BcpDependencyGraphPropagator : public DependencyGraphPropagator {
 public:
  BcpDependencyGraphPropagator(
      BcpDependencyGraph* bcp_graph,
      const std::vector<std::unique_ptr<const art::DexFile>>& updated_boot_dex_files)
      : DependencyGraphPropagator(bcp_graph),
        bcp_graph_(*bcp_graph),
        updated_boot_dex_files_(updated_boot_dex_files) {
    // Preprocess: build O(1) lookup map from descriptor to (DexFile*, class_def_idx)
    for (size_t i = 0; i < updated_boot_dex_files_.size(); ++i) {
      const art::DexFile* dex = updated_boot_dex_files_[i].get();
      for (uint32_t j = 0; j < dex->NumClassDefs(); ++j) {
        const dex::ClassDef& class_def = dex->GetClassDef(j);
        const char* class_descriptor = dex->GetClassDescriptor(class_def);
        // Use GetIndexForClassDef to get the correct class_def_index, as j may not
        // always be the class_def_index when iterating through class_defs in order.
        class_lookup_[class_descriptor] = {dex, dex->GetIndexForClassDef(class_def)};
      }
    }
  }


  // Getter for interface method changes (used by app dependency graph builder)
  const InterfaceMethodChanges& GetInterfaceMethodChanges() const { return interface_method_changes_; }
  void SetInitialChanges() override {
    size_t initial_changed_class_counter = 0;
    size_t interface_method_changes_counter = 0;
    // Iterate through all class nodes in BcpDependencyGraph
    for (const auto& [vertex_id, vertex] : bcp_graph_.GetVertices()) {
      // Create DexSymId from vertex_id
      DexSymId dex_sym_id(vertex_id);

      // Skip method nodes, only process class nodes
      if (dex_sym_id.IsMethod()) {
        continue;
      }

      const std::string& class_descriptor = vertex.GetDescriptor();

      // O(1) lookup using preprocessed map
      const art::DexFile* found_dex = nullptr;
      uint32_t found_class_def_idx = 0;
      if (!bcp_graph_.HasClassAccessor(dex_sym_id)) continue;
      if (FindClassInNewDexFiles(class_descriptor, &found_dex, &found_class_def_idx)) {
        // Compare the class between old (from bcp_graph) and new (from new_dex_files)
        // Create ClassAccessor for old class from bcp_graph
        art::ClassAccessor old_class_accessor = bcp_graph_.GetClassAccessor(dex_sym_id);
        // Create ClassAccessor for new class from updated_boot_dex_files
        art::ClassAccessor new_class_accessor(*found_dex, found_class_def_idx);

        // Check if it's an interface by examining access flags
        bool is_old_interface = (old_class_accessor.GetClassDef().access_flags_ & kAccInterface) != 0;
        bool is_new_interface = (new_class_accessor.GetClassDef().access_flags_ & kAccInterface) != 0;

        if (is_old_interface && is_new_interface) {
          // Both are interfaces: check for method changes
          auto changes = DetectInterfaceMethodChanges(old_class_accessor, new_class_accessor);
          if (!changes.empty()) {
            interface_method_changes_[class_descriptor] = std::move(changes);
            interface_method_changes_counter += interface_method_changes_[class_descriptor].size();
          }
        } else if (is_old_interface && !is_new_interface) {
          // Old interface is now not an interface - treat as deleted
          interface_method_changes_[class_descriptor];  // Empty set marks interface as deleted
        }

        // Regular class changes
        bool changes_found = CompareAndMarkChanges(dex_sym_id, old_class_accessor, new_class_accessor);
        if (changes_found) {
          initial_changed_class_counter += 1;
        }
      } else {
        // Class not found in new DexFiles - mark as changed
        // If it was an interface, mark all methods as changed
        if (bcp_graph_.HasClassAccessor(dex_sym_id)) {
          art::ClassAccessor old_class_accessor = bcp_graph_.GetClassAccessor(dex_sym_id);
          if ((old_class_accessor.GetClassDef().access_flags_ & kAccInterface) != 0) {
            // Interface deleted - all methods affected
            std::unordered_set<std::string> all_methods;
            for (const auto& method : old_class_accessor.GetMethods()) {
              const auto& method_id = old_class_accessor.GetDexFile().GetMethodId(method.GetIndex());
              const char* name = old_class_accessor.GetDexFile().GetMethodName(method_id);
              Signature sig = old_class_accessor.GetDexFile().GetMethodSignature(method_id);
              all_methods.insert(std::string(name) + ":" + sig.ToString());
            }
            interface_method_changes_[class_descriptor] = std::move(all_methods);
          }
        }
      }
    }
    LOG(INFO) << "Found " << initial_changed_class_counter << "(s) initial changed classes";
    LOG(INFO) << "Found " << interface_method_changes_counter << "(s) interface method changes";
  }

 private:
  // Detect interface method changes: returns set of "method_name:signature" that changed
  std::unordered_set<std::string> DetectInterfaceMethodChanges(
      const art::ClassAccessor& old_interface,
      const art::ClassAccessor& new_interface) {
    std::unordered_set<std::string> changed_methods;

    // Build map of old methods: method_name -> signature
    std::map<std::string, std::string> old_methods;
    for (const auto& method : old_interface.GetMethods()) {
      const auto& method_id = old_interface.GetDexFile().GetMethodId(method.GetIndex());
      const char* name = old_interface.GetDexFile().GetMethodName(method_id);
      Signature sig = old_interface.GetDexFile().GetMethodSignature(method_id);
      old_methods[std::string(name)] = sig.ToString();
    }

    // Compare with new methods
    for (const auto& method : new_interface.GetMethods()) {
      const auto& method_id = new_interface.GetDexFile().GetMethodId(method.GetIndex());
      const char* name = new_interface.GetDexFile().GetMethodName(method_id);
      Signature sig = new_interface.GetDexFile().GetMethodSignature(method_id);
      std::string method_key = std::string(name) + ":" + sig.ToString();

      auto it = old_methods.find(std::string(name));
      if (it == old_methods.end() || it->second != sig.ToString()) {
        // Method name or signature changed
        changed_methods.insert(method_key);
      }
    }

    return changed_methods;
  }

 public:

 private:
  // Find a class by descriptor using preprocessed lookup table (O(1))
  bool FindClassInNewDexFiles(const std::string& descriptor,
                              const art::DexFile** out_dex,
                              uint32_t* out_class_def_idx) const {
    auto it = class_lookup_.find(descriptor);
    if (it != class_lookup_.end()) {
      *out_dex = it->second.first;
      *out_class_def_idx = it->second.second;
      return true;
    }
    return false;
  }

  // Compare old and new class definitions using ClassAccessor and mark changes
  // Return true if any change found
  bool CompareAndMarkChanges(const DexSymId& old_dex_sym_id,
                             const art::ClassAccessor& old_class_accessor,
                             const art::ClassAccessor& new_class_accessor) {
    // Then set the appropriate bits in the changes_ bitset
    //
    // Static field layout changes if:
    //  a. number of static fields changed
    //  b. if number of static fields stay the same, then any of new static field doesnt match cooresponding old static field
    //
    // Instance field layout changes if:
    //  a. number of instance fields changed
    //  b. if number of instance fields stay the same, then any of new instance field doesnt match cooresponding old instance field
    //
    // VTable field layout changes if:
    //  a. number of virtual methods changed
    //  b. if number of virtual methods stay the same, then any of new virtual method doesnt match corresponding old instance field

    static int changed_class_count = 0;
    const int kMaxPrintedChanges = 10;

    DependencyGraphNode& vertex = bcp_graph_.graph_.get_vertex(static_cast<graaf::vertex_id_t>(old_dex_sym_id.id));

    // Helper to convert field to string representation
    auto field_to_string = [](const art::ClassAccessor& accessor,
                               const art::ClassAccessor::Field& field) -> std::string {
      const auto& field_id = accessor.GetDexFile().GetFieldId(field.GetIndex());
      const char* name = accessor.GetDexFile().GetFieldName(field_id);
      const char* type = accessor.GetDexFile().GetFieldTypeDescriptor(field_id);
      return std::string(name) + ":" + std::string(type);
    };

    // Helper to convert method to string representation
    auto method_to_string = [](const art::ClassAccessor& accessor,
                                const art::ClassAccessor::Method& method) -> std::string {
      const auto& method_id = accessor.GetDexFile().GetMethodId(method.GetIndex());
      const char* name = accessor.GetDexFile().GetMethodName(method_id);
      const Signature sig = accessor.GetDexFile().GetMethodSignature(method_id);
      return std::string(name) + sig.ToString();
    };

    // Collect all fields and methods as strings for debugging
    std::string old_static_fields_str, new_static_fields_str;
    std::string old_instance_fields_str, new_instance_fields_str;
    std::string old_virtual_methods_str, new_virtual_methods_str;

    // Static fields
    for (const auto& field : old_class_accessor.GetStaticFields()) {
      if (!old_static_fields_str.empty()) old_static_fields_str += "; ";
      old_static_fields_str += field_to_string(old_class_accessor, field);
    }
    for (const auto& field : new_class_accessor.GetStaticFields()) {
      if (!new_static_fields_str.empty()) new_static_fields_str += "; ";
      new_static_fields_str += field_to_string(new_class_accessor, field);
    }

    // Instance fields
    for (const auto& field : old_class_accessor.GetInstanceFields()) {
      if (!old_instance_fields_str.empty()) old_instance_fields_str += "; ";
      old_instance_fields_str += field_to_string(old_class_accessor, field);
    }
    for (const auto& field : new_class_accessor.GetInstanceFields()) {
      if (!new_instance_fields_str.empty()) new_instance_fields_str += "; ";
      new_instance_fields_str += field_to_string(new_class_accessor, field);
    }

    // Virtual methods
    for (const auto& method : old_class_accessor.GetVirtualMethods()) {
      if (!old_virtual_methods_str.empty()) old_virtual_methods_str += "; ";
      old_virtual_methods_str += method_to_string(old_class_accessor, method);
    }
    for (const auto& method : new_class_accessor.GetVirtualMethods()) {
      if (!new_virtual_methods_str.empty()) new_virtual_methods_str += "; ";
      new_virtual_methods_str += method_to_string(new_class_accessor, method);
    }

    // Compare static field layout
    bool static_fields_changed = false;
    uint32_t old_static_count = old_class_accessor.NumStaticFields();
    uint32_t new_static_count = new_class_accessor.NumStaticFields();
    if (old_static_count != new_static_count) {
      static_fields_changed = true;
    } else {
      auto old_static_fields = old_class_accessor.GetStaticFields();
      auto new_static_fields = new_class_accessor.GetStaticFields();
      auto old_it = old_static_fields.begin();
      auto new_it = new_static_fields.begin();
      for (; old_it != old_static_fields.end() && new_it != new_static_fields.end(); ++old_it, ++new_it) {
        const art::dex::FieldId& old_field_id = old_class_accessor.GetDexFile().GetFieldId(old_it->GetIndex());
        const art::dex::FieldId& new_field_id = new_class_accessor.GetDexFile().GetFieldId(new_it->GetIndex());
        const char* old_name = old_class_accessor.GetDexFile().GetFieldName(old_field_id);
        const char* new_name = new_class_accessor.GetDexFile().GetFieldName(new_field_id);
        const char* old_type = old_class_accessor.GetDexFile().GetFieldTypeDescriptor(old_field_id);
        const char* new_type = new_class_accessor.GetDexFile().GetFieldTypeDescriptor(new_field_id);
        if (strcmp(old_name, new_name) != 0 || strcmp(old_type, new_type) != 0) {
          static_fields_changed = true;
          break;
        }
      }
    }
    if (static_fields_changed) {
      vertex.changes_.set(static_cast<size_t>(DependencyType::kStaticFieldLayout));
    }

    // Compare instance field layout
    bool instance_fields_changed = false;
    uint32_t old_instance_count = old_class_accessor.NumInstanceFields();
    uint32_t new_instance_count = new_class_accessor.NumInstanceFields();
    if (old_instance_count != new_instance_count) {
      instance_fields_changed = true;
    } else {
      auto old_instance_fields = old_class_accessor.GetInstanceFields();
      auto new_instance_fields = new_class_accessor.GetInstanceFields();
      auto old_it = old_instance_fields.begin();
      auto new_it = new_instance_fields.begin();
      for (; old_it != old_instance_fields.end() && new_it != new_instance_fields.end(); ++old_it, ++new_it) {
        const art::dex::FieldId& old_field_id = old_class_accessor.GetDexFile().GetFieldId(old_it->GetIndex());
        const art::dex::FieldId& new_field_id = new_class_accessor.GetDexFile().GetFieldId(new_it->GetIndex());
        const char* old_name = old_class_accessor.GetDexFile().GetFieldName(old_field_id);
        const char* new_name = new_class_accessor.GetDexFile().GetFieldName(new_field_id);
        const char* old_type = old_class_accessor.GetDexFile().GetFieldTypeDescriptor(old_field_id);
        const char* new_type = new_class_accessor.GetDexFile().GetFieldTypeDescriptor(new_field_id);
        if (strcmp(old_name, new_name) != 0 || strcmp(old_type, new_type) != 0) {
          instance_fields_changed = true;
          break;
        }
      }
    }
    if (instance_fields_changed) {
      vertex.changes_.set(static_cast<size_t>(DependencyType::kInstanceFieldLayout));
    }

    // Compare virtual table layout
    bool vtable_changed = false;
    uint32_t old_virtual_count = old_class_accessor.NumVirtualMethods();
    uint32_t new_virtual_count = new_class_accessor.NumVirtualMethods();
    if (old_virtual_count != new_virtual_count) {
      vtable_changed = true;
    } else {
      auto old_virtual_methods = old_class_accessor.GetVirtualMethods();
      auto new_virtual_methods = new_class_accessor.GetVirtualMethods();
      auto old_it = old_virtual_methods.begin();
      auto new_it = new_virtual_methods.begin();
      for (; old_it != old_virtual_methods.end() && new_it != new_virtual_methods.end(); ++old_it, ++new_it) {
        const art::dex::MethodId& old_method_id = old_class_accessor.GetDexFile().GetMethodId(old_it->GetIndex());
        const art::dex::MethodId& new_method_id = new_class_accessor.GetDexFile().GetMethodId(new_it->GetIndex());
        const char* old_name = old_class_accessor.GetDexFile().GetMethodName(old_method_id);
        const char* new_name = new_class_accessor.GetDexFile().GetMethodName(new_method_id);
        const Signature old_signature = old_class_accessor.GetDexFile().GetMethodSignature(old_method_id);
        const Signature new_signature = new_class_accessor.GetDexFile().GetMethodSignature(new_method_id);
        if (strcmp(old_name, new_name) != 0 || old_signature != new_signature) {
          vtable_changed = true;
          break;
        }
      }
    }
    if (vtable_changed) {
      vertex.changes_.set(static_cast<size_t>(DependencyType::kVirtualTableLayout));
    }

    // Print debug info for first kMaxPrintedChanges changed classes
    if (static_fields_changed || instance_fields_changed || vtable_changed) {
      if (changed_class_count < kMaxPrintedChanges) {
        changed_class_count++;
        const std::string& class_descriptor = vertex.GetDescriptor();
        LOG(INFO) << "=== Class Change #" << changed_class_count << " ===";
        LOG(INFO) << "Class: " << class_descriptor;

        if (static_fields_changed) {
          LOG(INFO) << "  [STATIC FIELDS CHANGED]";
          LOG(INFO) << "    Old: " << old_static_fields_str;
          LOG(INFO) << "    New: " << new_static_fields_str;
        }

        if (instance_fields_changed) {
          LOG(INFO) << "  [INSTANCE FIELDS CHANGED]";
          LOG(INFO) << "    Old: " << old_instance_fields_str;
          LOG(INFO) << "    New: " << new_instance_fields_str;
        }

        if (vtable_changed) {
          LOG(INFO) << "  [VIRTUAL METHODS CHANGED]";
          LOG(INFO) << "    Old: " << old_virtual_methods_str;
          LOG(INFO) << "    New: " << new_virtual_methods_str;
        }
      }
    }
    return static_fields_changed || instance_fields_changed || vtable_changed;
  }

  BcpDependencyGraph& bcp_graph_;
  const std::vector<std::unique_ptr<const art::DexFile>>& updated_boot_dex_files_;

  // Preprocessed lookup: descriptor -> (DexFile*, class_def_idx)
  std::unordered_map<std::string, std::pair<const art::DexFile*, uint32_t>> class_lookup_;

  // Interface method changes: interface_descriptor -> set of changed method keys
  InterfaceMethodChanges interface_method_changes_;
};

class OatFileAnalyzer {
 public:
  OatFileAnalyzer(const char* oat_file_path) : oat_file_path_(oat_file_path) {}
  bool LoadOatFile(std::string* error_msg) {
    oat_file_.reset(OatFile::Open(/* zip_fd */ -1,
                                  oat_file_path_,
                                  oat_file_path_,
                                  /* executable */ false,
                                  /* low_4gb */ false,
                                  error_msg));
    if (oat_file_ == nullptr) {
      LOG(ERROR) << "Failed to open OAT file: " << *error_msg;
      return false;
    }
    return true;
  }
  const art::OatFile* GetOatFile() const {
    return oat_file_.get();
  }
  // Returns a list of human-readable method descriptors for all methods
  // in the OAT file that have compiled native code (i.e., non-null CompiledMethod).
  // Format example: "java.lang.Object.toString:()Ljava/lang/String;"
  bool GetCompiledMethodNames(/*out*/ std::vector<std::string>& method_names,
                              /*out*/ std::string* error_msg) const {
    if (!oat_file_) {
      *error_msg = "OAT file is not loaded.";
      return false;
    }
    // Iterate over all OatDexFile entries in the OAT file.
    size_t dex_file_count = oat_file_->GetOatDexFiles().size();
    for (size_t i = 0; i < dex_file_count; ++i) {
      const art::OatDexFile* oat_dex_file = oat_file_->GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }

      const art::DexFile* dex_file = dex_files_[i].get();
      // Skip DEX location check because DEX files extracted from APK may not match OAT file's recorded location
      for (ClassAccessor accessor : dex_file->GetClasses()) {
        const uint16_t class_def_index = accessor.GetClassDefIndex();
        const OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
        uint32_t class_method_index = 0;

        // inspired by DumpOatMethod
        for (const ClassAccessor::Method& method : accessor.GetMethods()) {
          const OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
          class_method_index++;
          const OatHeader& oat_header = oat_file_->GetOatHeader();
          const OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
          if (method_header == nullptr || method_header->GetCodeSize() == 0) {
            // No code.
            continue;
          }

          uint32_t dex_method_idx = method.GetIndex();
          std::string method_name = dex_file->GetMethodName(dex_file->GetMethodId(dex_method_idx));
          std::string pretty_method = dex_file->PrettyMethod(dex_method_idx, true);
          method_names.push_back(pretty_method);
        }
      }
    }
    return true;
  }

 private:
  const char* oat_file_path_;
  std::unique_ptr<art::OatFile> oat_file_;
  std::vector<std::unique_ptr<const art::DexFile>> dex_files_;
};
class InlineCallGraphNode {
 public:
  InlineCallGraphNode(const std::string& descriptor, bool is_effected) : descriptor_(descriptor), is_effected_(is_effected) {}

  const std::string& GetDescriptor() const { return descriptor_; }
  bool IsEffected() const { return is_effected_; }
  void SetEffected(bool is_effected) { is_effected_ = is_effected; }  
 private:
  std::string descriptor_;
  bool is_effected_;
};
class InlineCallGraphEdge {
 public:
  InlineCallGraphEdge() = default;
 private:
  // No additional data for now.
};
class InlineCallGraph: public GraphBase<InlineCallGraphNode, InlineCallGraphEdge, graaf::graph_type::DIRECTED> {
 public:
  friend class InlineCallGraphBuilder;
  friend class InlineDependencyExpander;
};

// InlineDependencyExpander propagates dependencies through the inline call graph.
// For each inline edge A → B (method A inlines method B), and for each
// dependency edge B → C in the dependency graph, this class creates a new graph
// that adds the edge A → C.
class InlineDependencyExpander {
 public:
  InlineDependencyExpander(const DependencyGraph* original_dep_graph, const InlineCallGraph* inline_graph)
      : original_dep_graph_(*original_dep_graph), inline_graph_(*inline_graph) {}

  // Expand dependencies using 1-hop propagation through inline call graph.
  // Creates a new graph with original edges plus expanded edges.
  // Returns the number of new edges added.
  size_t ExpandDependencies(DependencyGraph* expanded_graph) {
    // Step 1: Directly copy the original graph using copy constructor
    *expanded_graph = original_dep_graph_;
    size_t new_edges_added = 0;
    size_t skipped_a_not_in_dep_graph = 0;
    size_t skipped_b_not_in_dep_graph = 0;
    size_t b_has_no_neighbors = 0;

    // Build reverse adjacency map for fast predecessor lookup
    // reverse_adj_[v] = list of vertices that have edges to v (i.e., predecessors of v)
    std::unordered_map<graaf::vertex_id_t, std::vector<graaf::vertex_id_t>> reverse_adj;
    for (const auto& [from_id, from_node] : original_dep_graph_.GetVertices()) {
      auto neighbors = original_dep_graph_.graph_.get_neighbors(from_id);
      for (graaf::vertex_id_t to_id : neighbors) {
        reverse_adj[to_id].push_back(from_id);
      }
    }

    // Step 2: For each inline edge A → B (A inlines B)
    for (const auto& [vertex_a_id, vertex_a] : inline_graph_.GetVertices()) {
      // Get all successors B of A (A → B means A inlines B)
      const auto& successors = inline_graph_.graph_.get_neighbors(vertex_a_id);

      if (successors.empty()) {
        continue;
      }

      // Skip if vertex A doesn't exist in original dependency graph
      if (!original_dep_graph_.graph_.has_vertex(vertex_a_id)) {
        skipped_a_not_in_dep_graph++;
        continue;
      }

      // For each B that is inlined by A
      for (graaf::vertex_id_t vertex_b_id : successors) {
        // Skip if vertex B doesn't exist in original dependency graph
        if (!original_dep_graph_.graph_.has_vertex(vertex_b_id)) {
          skipped_b_not_in_dep_graph++;
          continue;
        }

        // Get all predecessors of B using reverse adjacency map (C → B)
        auto it = reverse_adj.find(vertex_b_id);
        if (it == reverse_adj.end() || it->second.empty()) {
          b_has_no_neighbors++;
          continue;
        }

        // For each predecessor C of B (C → B), add C → A to expanded graph
        // This makes A depend on everything that B depends on.
        for (graaf::vertex_id_t vertex_c_id : it->second) {
          // Get the dependency bits from original graph
          const auto& edge_c_b = original_dep_graph_.graph_.get_edge(vertex_c_id, vertex_b_id);
          std::bitset<3> deps = edge_c_b.GetDeps();

          // Create DexSymId from vertex IDs
          DexSymId from_dex_sym_id(vertex_c_id);
          DexSymId to_dex_sym_id(vertex_a_id);

          // Add or update the edge in expanded graph
          if (!expanded_graph->graph_.has_edge(vertex_c_id, vertex_a_id)) {
            expanded_graph->UpdateEdge(from_dex_sym_id, to_dex_sym_id, deps);
            new_edges_added++;
          } else {
            // Check if we need to merge dependency bits
            auto& existing_edge = expanded_graph->graph_.get_edge(vertex_c_id, vertex_a_id);
            std::bitset<3> new_deps = existing_edge.GetDeps() | deps;
            if (new_deps != existing_edge.GetDeps()) {
              expanded_graph->UpdateEdge(from_dex_sym_id, to_dex_sym_id, new_deps);
              new_edges_added++;
            }
          }
        }
      }
    }

    LOG(INFO) << "Inline dependency expansion: skipped A not in dep graph: " << skipped_a_not_in_dep_graph
              << ", skipped B not in dep graph: " << skipped_b_not_in_dep_graph
              << ", B has no neighbors: " << b_has_no_neighbors
              << ", new edges added: " << new_edges_added;
    return new_edges_added;
  }

  const DependencyGraph& original_dep_graph_;
  const InlineCallGraph& inline_graph_;
};
class InlineCallGraphBuilder {
 public:
  InlineCallGraphBuilder(InlineCallGraph* graph, const art::OatFile* oat_file, const std::vector<std::unique_ptr<const art::DexFile>>& dex_files) : graph_(*graph), oat_file_(*oat_file), dex_files_(dex_files) {}
  bool BuildGraph(ATTRIBUTE_UNUSED std::string* error_msg) {
    size_t dex_file_count = oat_file_.GetOatDexFiles().size();
    for (size_t i = 0; i < dex_file_count; ++i) {
      const art::OatDexFile* oat_dex_file = oat_file_.GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }

      const art::DexFile* dex_file = dex_files_[i].get();
      // Skip DEX location check because DEX files extracted from APK may not match OAT file's recorded location
      for (ClassAccessor accessor : dex_file->GetClasses()) {
        const uint16_t class_def_index = accessor.GetClassDefIndex();
        const OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
        uint32_t class_method_index = 0;

        for (const ClassAccessor::Method& method : accessor.GetMethods()) {
          const OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
          class_method_index++;
          const OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
          if (method_header == nullptr || method_header->GetCodeSize() == 0) {
            // No code.
            continue;
          }

          uint32_t dex_method_idx = method.GetIndex();
          std::string method_name = dex_file->GetMethodName(dex_file->GetMethodId(dex_method_idx));
          std::string pretty_method = dex_file->PrettyMethod(dex_method_idx, true);
          DexSymId dex_sym_id(i, true, dex_method_idx);
          graph_.AddVertexIfAbsent(dex_sym_id, pretty_method, false);
        }
      }
    }

    for (size_t i = 0; i < dex_file_count; ++i) {
      const art::OatDexFile* oat_dex_file = oat_file_.GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }

      const art::DexFile* dex_file = dex_files_[i].get();
      for (ClassAccessor accessor : dex_file->GetClasses()) {
        const uint16_t class_def_index = accessor.GetClassDefIndex();
        const OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
        uint32_t class_method_index = 0;

        for (const ClassAccessor::Method& method : accessor.GetMethods()) {
          const OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
          class_method_index++;
          const OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
          if (method_header == nullptr || method_header->GetCodeSize() == 0) {
            // No code.
            continue;
          }
          uint32_t dex_method_idx = method.GetIndex();
          std::string method_name = dex_file->GetMethodName(dex_file->GetMethodId(dex_method_idx));
          std::string pretty_method = dex_file->PrettyMethod(dex_method_idx, true);
          DexSymId caller_dex_sym_id(i, true, dex_method_idx);
          AnalyzeOatMethod(method_header, caller_dex_sym_id);
        }
      }
    }
    return true;
  }
  bool AnalyzeOatMethod(const OatQuickMethodHeader* caller_header, const DexSymId caller_dex_sym_id) {
    CodeInfo code_info(caller_header);
    for (const StackMap& stack_map : code_info.GetStackMaps()) {
      for (const InlineInfo& inline_info : code_info.GetInlineInfosOf(stack_map)) {
        MethodInfo method_info = code_info.GetMethodInfoOf(inline_info);

        // Prefer MethodInfo regardless of whether ArtMethod* is available or not
        if (method_info.HasDexFileIndex()) {
          graaf::vertex_id_t vertex_id_caller = static_cast<graaf::vertex_id_t>(caller_dex_sym_id.id);
          DexSymId callee_dex_sym_id(method_info.GetDexFileIndex(), true, method_info.GetMethodIndex());
          graaf::vertex_id_t vertex_id_callee = static_cast<graaf::vertex_id_t>(callee_dex_sym_id.id);

          // Try to get method name
          std::string method_name;
          if (inline_info.EncodesArtMethod()) {
            ArtMethod* callee = inline_info.GetArtMethod();
            ScopedObjectAccess soa(Thread::Current());
            method_name = callee->PrettyMethod();
          } else {
            // No ArtMethod*, use index as method name
            method_name = android::base::StringPrintf("d%uu%u", method_info.GetDexFileIndex(), method_info.GetMethodIndex());
          }

          graph_.AddVertexIfAbsent(callee_dex_sym_id, method_name, false);
          // If method A inlines method B, create edge A → B to indicate that A inlines B
          if (!graph_.graph_.has_edge(vertex_id_caller, vertex_id_callee)) {
            graph_.graph_.add_edge(vertex_id_caller, vertex_id_callee, InlineCallGraphEdge());
          }
        }
      }
    }
    return true;
  }
  private:
  InlineCallGraph& graph_;
  const art::OatFile& oat_file_;
  const std::vector<std::unique_ptr<const art::DexFile>>& dex_files_;
};
// BootClassPath from lynx device, matches list_bcp_classes.py
const std::vector<std::string> kBootClasspathJars = {
  "/apex/com.android.art/javalib/core-oj.jar",
  "/apex/com.android.art/javalib/core-libart.jar",
  "/apex/com.android.art/javalib/okhttp.jar",
  "/apex/com.android.art/javalib/bouncycastle.jar",
  "/apex/com.android.art/javalib/apache-xml.jar",
  "/system/framework/framework.jar",
  "/system/framework/framework-graphics.jar",
  "/system/framework/framework-location.jar",
  "/system/framework/ext.jar",
  "/system/framework/telephony-common.jar",
  "/system/framework/voip-common.jar",
  "/system/framework/ims-common.jar",
  "/apex/com.android.i18n/javalib/core-icu4j.jar",
  "/apex/com.android.adservices/javalib/framework-adservices.jar",
  "/apex/com.android.adservices/javalib/framework-sdksandbox.jar",
  "/apex/com.android.appsearch/javalib/framework-appsearch.jar",
  "/apex/com.android.btservices/javalib/framework-bluetooth.jar",
  "/apex/com.android.configinfrastructure/javalib/framework-configinfrastructure.jar",
  "/apex/com.android.conscrypt/javalib/conscrypt.jar",
  "/apex/com.android.crashrecovery/javalib/framework-crashrecovery.jar",
  "/apex/com.android.devicelock/javalib/framework-devicelock.jar",
  "/apex/com.android.healthfitness/javalib/framework-healthfitness.jar",
  "/apex/com.android.ipsec/javalib/android.net.ipsec.ike.jar",
  "/apex/com.android.media/javalib/updatable-media.jar",
  "/apex/com.android.mediaprovider/javalib/framework-mediaprovider.jar",
  "/apex/com.android.mediaprovider/javalib/framework-pdf.jar",
  "/apex/com.android.mediaprovider/javalib/framework-pdf-v.jar",
  "/apex/com.android.nfcservices/javalib/framework-nfc.jar",
  "/apex/com.android.ondevicepersonalization/javalib/framework-ondevicepersonalization.jar",
  "/apex/com.android.os.statsd/javalib/framework-statsd.jar",
  "/apex/com.android.permission/javalib/framework-permission.jar",
  "/apex/com.android.permission/javalib/framework-permission-s.jar",
  "/apex/com.android.profiling/javalib/framework-profiling.jar",
  "/apex/com.android.scheduling/javalib/framework-scheduling.jar",
  "/apex/com.android.sdkext/javalib/framework-sdkextensions.jar",
  "/apex/com.android.tethering/javalib/framework-connectivity.jar",
  "/apex/com.android.tethering/javalib/framework-connectivity-t.jar",
  "/apex/com.android.tethering/javalib/framework-tethering.jar",
  "/apex/com.android.uwb/javalib/framework-uwb.jar",
  "/apex/com.android.virt/javalib/framework-virtualization.jar",
  "/apex/com.android.wifi/javalib/framework-wifi.jar"
};

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
    } else if (option.starts_with("--output=")) {
      output_file_ = raw_option + strlen("--output=");
    } else if (option.starts_with("--apk=")) {
      apk_file_ = raw_option + strlen("--apk=");
    } else if (option.starts_with("--origin-bcp-prefix=")) {
      origin_bcp_prefix_ = raw_option + strlen("--origin-bcp-prefix=");
    } else if (option.starts_with("--updated-bcp-prefix=")) {
      updated_bcp_prefix_ = raw_option + strlen("--updated-bcp-prefix=");
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

    if (dex_files_.empty() && oat_file_ == nullptr && apk_file_ == nullptr && origin_bcp_prefix_ == nullptr) {
      *error_msg = "At least one of --dex, --oat, --apk, or --origin-bcp-prefix must be specified.";
      return kParseError;
    }

    // Check that if one BCP prefix is provided, the other is too
    if ((origin_bcp_prefix_ != nullptr && updated_bcp_prefix_ == nullptr) ||
        (origin_bcp_prefix_ == nullptr && updated_bcp_prefix_ != nullptr)) {
      *error_msg = "Both --origin-bcp-prefix and --updated-bcp-prefix must be specified together.";
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
  --apk=<file>                  Path to APK file (will extract all classes*.dex)
  --dex=<file>                  Path to DEX file (can be repeated)
  --oat=<file>                  Path to OAT/ODEX file
  --origin-bcp-prefix=<dir>     Prefix path for original BootClassPath jars (e.g., $ANDROID_PRODUCT_OUT)
  --updated-bcp-prefix=<dir>    Prefix path for updated BootClassPath jars
  --output=<file>               Write result to file (default: stdout)
  --verbose, -v                 Enable verbose logging
  --help, -h                    Show this message
)";
  }

 public:
  bool help_ = false;
  bool verbose_ = false;
  std::vector<const char*> dex_files_;
  const char* oat_file_ = nullptr;
  const char* output_file_ = nullptr;
  const char* apk_file_ = nullptr;
  const char* origin_bcp_prefix_ = nullptr;
  const char* updated_bcp_prefix_ = nullptr;

  OatCheckMode GetMode() const {
    if (verbose_) {
      return OatCheckMode::kVerbose;
    }
    return OatCheckMode::kDefault;
  }

  // Return list of DEX entry names inside the APK (e.g., "classes.dex")
  const std::vector<std::string>& GetApkDexEntries() const { return extracted_dex_names_; }

 private:
  std::vector<std::string> extracted_dex_names_;
};

std::unordered_set<std::string> changed_bcp_classes_descriptors;

struct OatCheckMain : public CmdlineMain<OatCheckArgs> {
  bool ExecuteWithoutRuntime() override {
    LOG(FATAL) << "This tool requires ART runtime.";
    UNREACHABLE();
  }

  bool ExecuteWithRuntime(ATTRIBUTE_UNUSED Runtime* runtime) override {
    if (args_->verbose_) {
      LOG(INFO) << "Verbose mode enabled";
    }

    std::string error_msg;
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

    if (args_->oat_file_)
      *os << "OAT: " << args_->oat_file_ << "\n";
    if (args_->origin_bcp_prefix_)
      *os << "Original BCP prefix: " << args_->origin_bcp_prefix_ << "\n";
    if (args_->updated_bcp_prefix_)
      *os << "Updated BCP prefix: " << args_->updated_bcp_prefix_ << "\n";

    // BCP change detection flow - run first to get interface method changes
    const InterfaceMethodChanges* interface_method_changes_ptr = nullptr;

    if (args_->origin_bcp_prefix_ != nullptr && args_->updated_bcp_prefix_ != nullptr) {
      LOG(INFO) << "Starting BCP change detection...";

      // Collect original BCP JAR paths
      std::vector<const char*> original_bcp_jars;
      std::vector<std::string> original_paths_storage; // To keep strings alive

      std::string origin_prefix = args_->origin_bcp_prefix_;
      // Ensure prefix ends with /
      if (!origin_prefix.empty() && origin_prefix.back() != '/') {
        origin_prefix += '/';
      }
      for (const auto& jar_relative_path : kBootClasspathJars) {
        // jar_relative_path starts with /, so we need to skip it when joining
        std::string full_path = origin_prefix + jar_relative_path.substr(1);
        original_paths_storage.push_back(full_path);
        original_bcp_jars.push_back(original_paths_storage.back().c_str());
      }

      // Build original BCP dependency graph
      BcpDependencyGraph original_bcp_graph;
      BcpDependencyGraphBuilder bcp_builder(original_bcp_jars, &original_bcp_graph);
      if (!bcp_builder.BuildGraph(&error_msg)) {
        LOG(ERROR) << "Failed to build original BCP dependency graph: " << error_msg;
        return false;
      }
      LOG(INFO) << "Original BCP graph built: " << original_bcp_graph.Summary();

      // Load updated BCP DEX files
      std::vector<std::unique_ptr<const art::DexFile>> updated_boot_dex_files;
      std::string updated_prefix = args_->updated_bcp_prefix_;
      // Ensure prefix ends with /
      if (!updated_prefix.empty() && updated_prefix.back() != '/') {
        updated_prefix += '/';
      }
      for (const auto& jar_relative_path : kBootClasspathJars) {
        // jar_relative_path starts with /, so we need to skip it when joining
        std::string jar_path = updated_prefix + jar_relative_path.substr(1);
        art::DexFileLoader loader(jar_path.c_str(), jar_path.c_str());
        std::vector<std::unique_ptr<const art::DexFile>> jar_dex_files;
        if (!loader.Open(/*verify=*/true, /*verify_checksum=*/true, /*allow_no_dex_files=*/true, &error_msg, &jar_dex_files)) {
          LOG(WARNING) << "Failed to load updated JAR " << jar_path << ": " << error_msg << ", skipping";
          continue;
        }
        for (auto& dex : jar_dex_files) {
          updated_boot_dex_files.push_back(std::move(dex));
        }
      }

      if (updated_boot_dex_files.empty()) {
        LOG(ERROR) << "No DEX files loaded from updated boot classes directory";
        return false;
      }
      LOG(INFO) << "Loaded " << updated_boot_dex_files.size() << " updated BCP DEX files";

      // Run change detection and propagation
      BcpDependencyGraphPropagator bcp_propagator(&original_bcp_graph, updated_boot_dex_files);
      LOG(INFO) << "Setting initial changes...";
      bcp_propagator.SetInitialChanges();
      LOG(INFO) << "Propagating changes";
      bcp_propagator.PropagateChanges();
      LOG(INFO) << "BCP change propagation complete";

      // Get interface method changes for app dependency graph
      interface_method_changes_ptr = &bcp_propagator.GetInterfaceMethodChanges();

      // Collect and report results
      size_t changed_classes = 0;
      size_t changed_methods = 0;
      for (const auto& [vertex_id, vertex] : original_bcp_graph.GetVertices()) {
        if (vertex.IsChanged()) {
          DexSymId sym_id(vertex_id);
          if (sym_id.IsMethod()) {
            changed_methods++;
          } else {
            changed_classes++;
          }
          if (args_->verbose_) {
            LOG(INFO) << "Changed: " << vertex.GetDescriptor();
          }
        }
      }

      *os << "\nBCP Change Detection Results:\n";
      *os << "  Changed classes: " << changed_classes << "\n";
      *os << "  Changed methods: " << changed_methods << "\n";
      *os << "  Total affected nodes: " << changed_classes + changed_methods << "\n";
    }

    // Build app dependency graph with interface method changes from BCP diff
    DependencyGraph graph;
    DependencyGraphBuilder graph_builder(args_->apk_file_, &graph, interface_method_changes_ptr);
    if (!graph_builder.BuildGraph(&error_msg)) {
      LOG(ERROR) << error_msg;
      return false;
    }

    // Build inline call graph if OAT file is provided
    InlineCallGraph inline_call_graph;
    if (args_->oat_file_) {
      LOG(INFO) << "Building inline call graph from OAT file...";
      OatFileAnalyzer oat_analyzer(args_->oat_file_);
      if (!oat_analyzer.LoadOatFile(&error_msg)) {
        LOG(ERROR) << "Failed to load OAT file: " << error_msg;
        return false;
      }
      InlineCallGraphBuilder inline_graph_builder(&inline_call_graph,
                                                 oat_analyzer.GetOatFile(),
                                                 graph_builder.GetDexFiles());
      if (!inline_graph_builder.BuildGraph(&error_msg)) {
        LOG(ERROR) << "Failed to build inline call graph: " << error_msg;
        return false;
      }
      LOG(INFO) << "Inline call graph built: "
                << inline_call_graph.graph_.vertex_count() << " vertices, "
                << inline_call_graph.graph_.edge_count() << " edges";

      // Expand dependencies through inline call graph
      LOG(INFO) << "Expanding dependencies through inline call graph...";
      InlineDependencyExpander expander(&graph, &inline_call_graph);
      DependencyGraph expanded_graph;
      size_t new_edges = expander.ExpandDependencies(&expanded_graph);
      graph = std::move(expanded_graph);
      LOG(INFO) << "Dependency graph after expansion: " << graph.Summary();
    }

    if (args_->output_file_ != nullptr) {
      LOG(WARNING) << "--output not implemented yet; using stdout";
    }

    std::cout << "Running OatCheck...\n";

    // Process explicit --dex files
    for (const char* dex : args_->dex_files_) {
      std::cout << "Processing DEX: " << dex << "\n";
      // TODO: Add real validation logic here.
    }

    if (args_->oat_file_)
      std::cout << "OAT: " << args_->oat_file_ << "\n";
    if (args_->origin_bcp_prefix_)
      std::cout << "Original BCP prefix: " << args_->origin_bcp_prefix_ << "\n";
    if (args_->updated_bcp_prefix_)
      std::cout << "Updated BCP prefix: " << args_->updated_bcp_prefix_ << "\n";

    // BCP change detection flow
    if (args_->origin_bcp_prefix_ != nullptr && args_->updated_bcp_prefix_ != nullptr) {
      LOG(INFO) << "Starting BCP change detection...";

      // Collect original BCP JAR paths
      std::vector<const char*> original_bcp_jars;
      std::vector<std::string> original_paths_storage; // To keep strings alive

      std::string origin_prefix = args_->origin_bcp_prefix_;
      // Ensure prefix ends with /
      if (!origin_prefix.empty() && origin_prefix.back() != '/') {
        origin_prefix += '/';
      }
      for (const auto& jar_relative_path : kBootClasspathJars) {
        // jar_relative_path starts with /, so we need to skip it when joining
        std::string full_path = origin_prefix + jar_relative_path.substr(1);
        original_paths_storage.push_back(full_path);
        original_bcp_jars.push_back(original_paths_storage.back().c_str());
      }

      // Build original BCP dependency graph
      BcpDependencyGraph original_bcp_graph;
      BcpDependencyGraphBuilder bcp_builder(original_bcp_jars, &original_bcp_graph);
      if (!bcp_builder.BuildGraph(&error_msg)) {
        LOG(ERROR) << "Failed to build original BCP dependency graph: " << error_msg;
        return false;
      }
      LOG(INFO) << "Original BCP graph built: " << original_bcp_graph.Summary();

      // Load updated BCP DEX files
      std::vector<std::unique_ptr<const art::DexFile>> updated_boot_dex_files;
      std::string updated_prefix = args_->updated_bcp_prefix_;
      // Ensure prefix ends with /
      if (!updated_prefix.empty() && updated_prefix.back() != '/') {
        updated_prefix += '/';
      }
      for (const auto& jar_relative_path : kBootClasspathJars) {
        // jar_relative_path starts with /, so we need to skip it when joining
        std::string jar_path = updated_prefix + jar_relative_path.substr(1);
        art::DexFileLoader loader(jar_path.c_str(), jar_path.c_str());
        std::vector<std::unique_ptr<const art::DexFile>> jar_dex_files;
        if (!loader.Open(/*verify=*/true, /*verify_checksum=*/true, /*allow_no_dex_files=*/true, &error_msg, &jar_dex_files)) {
          LOG(WARNING) << "Failed to load updated JAR " << jar_path << ": " << error_msg << ", skipping";
          continue;
        }
        for (auto& dex : jar_dex_files) {
          updated_boot_dex_files.push_back(std::move(dex));
        }
      }

      if (updated_boot_dex_files.empty()) {
        LOG(ERROR) << "No DEX files loaded from updated boot classes directory";
        return false;
      }
      LOG(INFO) << "Loaded " << updated_boot_dex_files.size() << " updated BCP DEX files";

      // Run change detection and propagation
      BcpDependencyGraphPropagator propagator(&original_bcp_graph, updated_boot_dex_files);
      LOG(INFO) << "Setting initial changes...";
      propagator.SetInitialChanges();
      LOG(INFO) << "Propagating changes";
      propagator.PropagateChanges();
      LOG(INFO) << "BCP change propagation complete";

      // Collect and report results
      size_t changed_classes = 0;
      size_t changed_methods = 0;
      for (const auto& [vertex_id, vertex] : original_bcp_graph.GetVertices()) {
        if (vertex.IsChanged()) {
          DexSymId sym_id(vertex_id);
          if (sym_id.IsMethod()) {
            changed_methods++;
          } else {
            changed_classes++;
          }
          if (args_->verbose_) {
            LOG(INFO) << "Changed: " << vertex.GetDescriptor();
          }
        }
      }

      *os << "\nBCP Change Detection Results:\n";
      *os << "  Changed classes: " << changed_classes << "\n";
      *os << "  Changed methods: " << changed_methods << "\n";
      *os << "  Total affected nodes: " << changed_classes + changed_methods << "\n";
    }

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