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
#include <set>
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

// Interface method change types for detailed diff
enum class MethodChangeType {
  kDeleted,   // existed in old but not in new
  kAdded,     // existed in new but not in old
  kModified   // existed in both but signature changed
};

struct MethodChangeDetail {
  MethodChangeType type;
  std::string method_name;
  std::string old_sig;  // empty if kAdded
  std::string new_sig;  // empty if kDeleted

  MethodChangeDetail(MethodChangeType t, const std::string& name, const std::string& old_s, const std::string& new_s)
      : type(t), method_name(name), old_sig(old_s), new_sig(new_s) {}
};

struct InterfaceMethodDiff {
  std::string interface_descriptor;
  std::vector<MethodChangeDetail> changes;
};

// Interface method change: independent change tracking for invoke-interface
// Key: interface_descriptor, Value: set of "method_name:signature" that changed
using InterfaceMethodChanges = std::unordered_map<std::string, std::unordered_set<std::string>>;

// Global counters for statistics (will be removed later)
static size_t g_interface_affected_methods = 0;
static size_t g_class_layout_affected_methods = 0;
static size_t g_printed_interface_diff_count = 0;

struct DexSymId {
  uint64_t id;
  // 64-bit layout (high to low):
  // | 1 bit is bcp dex| 23 bits unused | 8 bits dex_file_index | 16 bits class_def_id | 16 bits method_def_id |
  // Bit  63: is in bcp
  // Bits 62-40: unused (reserved)
  // Bits 39-32: dex file index (0-255), 0xFF indicates external class
  // Bits 31-16: class_def_id (0-65535), class definition index in DEX file
  // Bits 15-0: method_def_id (0-65535), method index in DEX file, 0xFFFF indicates this is a class (not a method)
  //
  // For class: method_def_id = 0xFFFF
  // For method: class_def_id = class_def_index of defining class, method_def_id = method index
  // For external class: dex_file_index = 0xFF
  void SetIsBcpDex(bool is_bcp_dex) {
    if (is_bcp_dex) {
        id |= (uint64_t(1) << 63);
    } else {
        id &= ~(uint64_t(1) << 63);
    }
  }
  bool IsBcpDex() const {
    bool highest_bit = (id >> 63) & 1;
    return highest_bit;
  }
  void SetDexFileIndex(uint32_t dex_file_index) {
    id = (id & 0xFFFFFF00FFFFFFFFULL) | (static_cast<uint64_t>(dex_file_index & 0xFF) << 32);
  }
  uint32_t GetDexFileIndex() const {
    return (id >> 32) & 0xFF;
  }
  void SetClassDefId(uint32_t class_def_id) {
    id = (id & 0xFFFFFFFF0000FFFFULL) | (static_cast<uint64_t>(class_def_id & 0xFFFF) << 16);
  }
  uint32_t GetClassDefId() const {
    return (id >> 16) & 0xFFFF;
  }
  void SetMethodDefId(uint32_t method_def_id) {
    id = (id & 0xFFFFFFFFFFFF0000ULL) | (method_def_id & 0xFFFF);
  }
  uint32_t GetMethodDefId() const {
    return id & 0xFFFF;
  }
  // Returns true if this is a class (method_def_id == 0xFFFF)
  bool IsClass() const {
    return (id & 0xFFFFULL) == 0xFFFF;
  }
  // Returns true if this represents an external class (dex_file_index == 0xFF)
  bool IsExternalClass() const {
    return GetDexFileIndex() == 0xFF;
  }
  // Constructor for class: method_def_id defaults to 0xFFFF
  DexSymId(uint32_t dex_file_index, uint32_t class_def_id) : id(0) {
    SetDexFileIndex(dex_file_index);
    SetClassDefId(class_def_id);
    SetMethodDefId(0xFFFF);
  }
  // Constructor for method: takes dex_file_index, class_def_id, and method_def_id
  DexSymId(uint32_t dex_file_index, uint32_t class_def_id, uint32_t method_def_id) : id(0) {
    SetDexFileIndex(dex_file_index);
    SetClassDefId(class_def_id);
    SetMethodDefId(method_def_id);
  }
  // Construct DexSymId from graaf vertex_id_t. Since vertex_id_t is directly
  // mapped to DexSymId.id, we can directly assign it.
  explicit DexSymId(graaf::vertex_id_t vertex_id) : id(static_cast<uint64_t>(vertex_id)) {}
  bool operator==(const DexSymId& other) const {return id==other.id;}
};

class DependencyGraphNode {
 public:
  DependencyGraphNode(std::string descriptor, bool is_changed = false)
      : descriptor_(std::move(descriptor)), changes_(is_changed) {}

  const std::string& GetDescriptor() const { return descriptor_; }
  bool IsChanged() const { return changes_.any(); }

  std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)> GetChanges() const {
    return changes_;
  }
  void SetChanges(
      const std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>& changes) {
    changes_ = changes;
  }
  void SetChange() { changes_.set(); }
  void SetChange(DependencyType type) {
    changes_.set(static_cast<size_t>(type));
  }
  void MergeChanges(
      const std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>& changes) {
    changes_ |= changes;
  }

 private:
  std::string descriptor_;
  std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)> changes_;
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
  DependencyGraph() {}
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

  // Dump all successor nodes of a given class descriptor
  // Edge direction: class -> method (method depends on class)
  // Successors are nodes that the given class points to (i.e., methods depending on this class)
  void DumpSuccessors(const std::string& class_descriptor) const {
    LOG(INFO) << "=== Successors of " << class_descriptor << " ===";
    size_t count = 0;
    for (const auto& [vertex_id, vertex] : graph_.get_vertices()) {
      if (vertex.GetDescriptor() == class_descriptor) {
        auto successors = graph_.get_neighbors(vertex_id);
        LOG(INFO) << "Found " << successors.size() << " successor(s)";
        for (graaf::vertex_id_t succ_id : successors) {
          const auto& succ_vertex = graph_.get_vertex(succ_id);
          LOG(INFO) << "  -> " << succ_vertex.GetDescriptor();
          count++;
          if (count >= 10000) {
            LOG(INFO) << "  (truncated at 10000)";
            break;
          }
        }
        break;
      }
    }
  }

  // Dump all ancestor nodes of a given descriptor (class or method)
  // Edge direction: class -> method (method depends on class)
  // Ancestors are nodes that the given node depends on (predecessors in the graph)
  // Uses reverse adjacency: find all successors in the reversed graph.
  void DumpAncestors(const std::string& target_descriptor) const {
    LOG(INFO) << "=== Ancestors of " << target_descriptor << " ===";

    // First, try exact match
    graaf::vertex_id_t target_id = 0;
    bool found = false;
    for (const auto& [vertex_id, vertex] : graph_.get_vertices()) {
      if (vertex.GetDescriptor() == target_descriptor) {
        target_id = vertex_id;
        found = true;
        break;
      }
    }

    // If not found exact, try prefix match and print all matches for debugging
    if (!found) {
      LOG(INFO) << "Exact match not found, checking prefix: " << target_descriptor;
      for (const auto& [vertex_id, vertex] : graph_.get_vertices()) {
        if (android::base::StartsWith(vertex.GetDescriptor(), target_descriptor)) {
          LOG(INFO) << "  Prefix match: " << vertex.GetDescriptor();
        }
      }
      LOG(INFO) << "Target node not found: " << target_descriptor;
      return;
    }

    // Build reverse adjacency map (predecessors of each node)
    std::unordered_map<graaf::vertex_id_t, std::vector<graaf::vertex_id_t>> reverse_adj;
    for (const auto& [from_id, from_node] : graph_.get_vertices()) {
      auto successors = graph_.get_neighbors(from_id);
      for (graaf::vertex_id_t to_id : successors) {
        reverse_adj[to_id].push_back(from_id);
      }
    }

    // BFS on reversed graph to find all ancestors
    std::unordered_set<graaf::vertex_id_t> visited;
    std::queue<graaf::vertex_id_t> to_visit;
    std::vector<graaf::vertex_id_t> ancestry_order;

    to_visit.push(target_id);
    visited.insert(target_id);

    while (!to_visit.empty()) {
      graaf::vertex_id_t current_id = to_visit.front();
      to_visit.pop();
      ancestry_order.push_back(current_id);

      // Get all predecessors (ancestors) using reverse adjacency
      auto it = reverse_adj.find(current_id);
      if (it != reverse_adj.end()) {
        for (graaf::vertex_id_t pred_id : it->second) {
          if (visited.find(pred_id) == visited.end()) {
            visited.insert(pred_id);
            to_visit.push(pred_id);
          }
        }
      }
    }

    LOG(INFO) << "Found " << (ancestry_order.size() - 1) << " ancestor(s) (excluding target)";

    // Print ancestors in reverse traversal order (closest first)
    size_t start_idx = 0;
    if (!ancestry_order.empty() && ancestry_order[0] == target_id) {
      start_idx = 1;
    }

    size_t count = 0;
    for (size_t i = ancestry_order.size(); i > start_idx; --i) {
      graaf::vertex_id_t ancestor_id = ancestry_order[i - 1];
      if (ancestor_id == target_id) {
        continue;
      }
      const auto& ancestor_vertex = graph_.get_vertex(ancestor_id);
      LOG(INFO) << "  <- " << ancestor_vertex.GetDescriptor();
      count++;
      if (count >= 10000) {
        LOG(INFO) << "  (truncated at 10000)";
        break;
      }
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

  const auto& GetDexFiles() const {
    return dex_files_;
  }

  // Construct ClassAccessor from DexSymId
  // DexSymId encodes: dex_file_index in high bits, class_def_index in low bits
  art::ClassAccessor GetClassAccessor(const DexSymId& dex_sym_id) const {
    uint32_t dex_file_index = dex_sym_id.GetDexFileIndex();
    uint32_t class_def_index = dex_sym_id.GetClassDefId();

    const art::DexFile* dex = dex_files_->at(dex_file_index).get();
    return art::ClassAccessor(*dex, class_def_index);
  }

  // Check if DexSymId is valid (within bounds)
  // Returns false for external classes (dex_file_index = 0xFF)
  bool HasClassAccessor(const DexSymId& dex_sym_id) const {
    uint32_t dex_file_index = dex_sym_id.GetDexFileIndex();
    uint32_t class_def_index = dex_sym_id.GetClassDefId();

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
      DexSymId class_dex_sym_id(dex_file_idx, class_def_index);
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
    DexSymId external_symid(0xFF, external_class_counter_);
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

// Intermediate base class for builders that analyze methods (as opposed to just class dependencies).
// Inherits from DependencyGraphBuilderBase and adds common method analysis logic.
class DependencyGraphBuilderWithMethods : public DependencyGraphBuilderBase {
 public:
  virtual ~DependencyGraphBuilderWithMethods() = default;

  // Override point 1: Extract DEX files (JAR vs APK)
  virtual bool ExtractDex(std::string* error_msg) = 0;

  // Override point 2: Whether to process a given method (for compiled method filtering)
  virtual bool ShouldProcessMethod(size_t dex_file_idx,
                                   uint16_t class_def_index,
                                   uint32_t method_index) = 0;

  // Common BuildGraph implementation
  bool BuildGraph(std::string* error_msg) override {
    if (!ExtractDex(error_msg)) {
      return false;
    }

    size_t i = 0;
    // Step 1: Build descriptor -> DexSymId mapping for all dex files
    for (const auto& dex : dex_files_) {
      if (!BuildDescriptorMapping(dex.get(), i, graph_)) {
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
      if (!BuildDependencyEdges(dex.get(), i, graph_)) {
        LOG(ERROR) << "Failed to build dependency edges: " << *error_msg;
        return false;
      }
      i++;
    }
    LOG(INFO) << graph_->Summary();
    return true;
  }

 protected:
  DependencyGraph* graph_ = nullptr;
  // Interface method changes from BCP diff: interface_descriptor -> set of changed method keys
  const InterfaceMethodChanges* interface_method_changes_ = nullptr;

 private:
  // Common AnalyzeDexMethods implementation
  bool AnalyzeDexMethods(const art::DexFile* dex, size_t dex_file_idx, ATTRIBUTE_UNUSED std::string* error_msg) {
    for (art::ClassAccessor accessor : dex->GetClasses()) {
      uint16_t class_def_index = accessor.GetClassDefIndex();
      for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
        // Check if method should be processed (filter by compiled status)
        if (!ShouldProcessMethod(dex_file_idx, class_def_index, method.GetIndex())) {
          continue;
        }

        const art::CodeItemInstructionAccessor& code = method.GetInstructions();
        std::string method_name(dex->PrettyMethod(method.GetIndex()));
        DexSymId method_dex_sym_id(dex_file_idx, class_def_index, method.GetIndex());
        graph_->AddVertexIfAbsent(method_dex_sym_id, method_name, false);

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
                DexSymId class_dex_sym_id = GetOrCreateDexSymId(class_descriptor);
                graph_->AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);
                graph_->UpdateEdge(
                    class_dex_sym_id,
                    method_dex_sym_id,
                    std::bitset<3>(1 << static_cast<size_t>(DependencyType::kVirtualTableLayout)));
                break;
              }
              case kDexInvokeSuper:
              case kDexInvokeDirect:
              case kDexInvokeStatic: {
                break;
              }
              case kDexInvokeInterface: {
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

                // Check if interface method changed and mark calling method as affected
                if (interface_method_changes_ != nullptr) {
                  auto interface_it = interface_method_changes_->find(interface_descriptor);
                  if (interface_it != interface_method_changes_->end() &&
                      interface_it->second.find(method_key) != interface_it->second.end()) {
                    graaf::vertex_id_t vertex_id = static_cast<graaf::vertex_id_t>(method_dex_sym_id.id);
                    auto& vertex = graph_->graph_.get_vertex(vertex_id);
                    if (!vertex.IsChanged()) g_interface_affected_methods++;
                    vertex.SetChange();
                  }
                }

                // Create edge for interface dependency
                DexSymId interface_dex_sym_id = GetOrCreateDexSymId(interface_descriptor);
                graph_->AddVertexIfAbsent(interface_dex_sym_id, interface_descriptor, false);
                graph_->UpdateEdge(
                    interface_dex_sym_id,
                    method_dex_sym_id,
                    std::bitset<3>(1 << static_cast<size_t>(DependencyType::kVirtualTableLayout)));
                break;
              }
              default: {
                LOG(WARNING) << "Unknown invoke type at dex pc " << inst.DexPc()
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
            DexSymId class_dex_sym_id = GetOrCreateDexSymId(class_descriptor);
            graph_->AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);
            graph_->UpdateEdge(
                class_dex_sym_id,
                method_dex_sym_id,
                std::bitset<3>(1 << static_cast<size_t>(DependencyType::kInstanceFieldLayout)));
          } else if (IsInstructionSGetOrSPut(inst->Opcode())) {
            auto field_idx = inst->VRegB();
            const dex::FieldId& field_id = dex->GetFieldId(field_idx);
            const dex::TypeId& type_id = dex->GetTypeId(field_id.class_idx_);
            const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
            const char* class_descriptor = dex->GetStringData(name_id);
            DexSymId class_dex_sym_id = GetOrCreateDexSymId(class_descriptor);
            graph_->AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);
            graph_->UpdateEdge(
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

// BCP method dependency graph builder - reuses DependencyGraphBuilder logic
// but processes ALL BCP methods (not filtered by compiled methods)
class BcpMethodDependencyGraphBuilder : public DependencyGraphBuilderWithMethods {
 public:
  BcpMethodDependencyGraphBuilder(const std::vector<const char*>& jar_file_paths,
                                 DependencyGraph* graph,
                                 const InterfaceMethodChanges* interface_method_changes = nullptr)
      : jar_file_paths_(jar_file_paths) {
    graph_ = graph;
    interface_method_changes_ = interface_method_changes;
  }

  bool ExtractDex(std::string* error_msg) override {
    for (const char* jar_file_path : jar_file_paths_) {
      if (jar_file_path == nullptr) {
        continue;
      }
      art::DexFileLoader loader(jar_file_path, /*location=*/jar_file_path);
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

  // Process ALL methods (no filtering)
  bool ShouldProcessMethod(ATTRIBUTE_UNUSED size_t dex_file_idx,
                           ATTRIBUTE_UNUSED uint16_t class_def_index,
                           ATTRIBUTE_UNUSED uint32_t method_index) override {
    return true;
  }

 private:
  std::vector<const char*> jar_file_paths_;
};

class DependencyGraphBuilder : public DependencyGraphBuilderWithMethods {
 public:
  using CompiledMethodSet = std::set<std::tuple<size_t, uint16_t, uint32_t>>;

  DependencyGraphBuilder(const char* apk_file_path,
                         DependencyGraph* graph,
                         const InterfaceMethodChanges* interface_method_changes = nullptr,
                         const CompiledMethodSet* compiled_methods = nullptr)
      : apk_file_path_(apk_file_path),
        compiled_methods_(compiled_methods) {
    graph_ = graph;
    interface_method_changes_ = interface_method_changes;
  }

  bool ExtractDex(std::string* error_msg) override {
    if (apk_file_path_ == nullptr) {
      return true;
    }
    art::DexFileLoader loader(apk_file_path_, /*location=*/apk_file_path_);
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
    LOG(INFO) << "Loaded " << dex_files_.size() << " DEX file(s)";
    return true;
  }

  bool ShouldProcessMethod(ATTRIBUTE_UNUSED size_t dex_file_idx,
                           ATTRIBUTE_UNUSED uint16_t class_def_index,
                           ATTRIBUTE_UNUSED uint32_t method_index) override {
    return true;
    //if (compiled_methods_ == nullptr || compiled_methods_->empty()) {
      //return true;
    //}
    //return compiled_methods_->find({dex_file_idx, class_def_index, method_index}) != compiled_methods_->end();
  }

 private:
  const char* apk_file_path_ = nullptr;
  ATTRIBUTE_UNUSED const CompiledMethodSet* compiled_methods_ = nullptr;
};

class DependencyGraphPropagator {
 public:
  DependencyGraphPropagator(DependencyGraph* graph) : graph_(*graph) {}
  virtual ~DependencyGraphPropagator() = default;
  virtual void SetInitialChanges();  // TODO: Set initial changes based on changed BCP classes.

  // Set initial changes on app dependency graph based on changed BCP classes.
  // Takes the changed class info from BCP diff and marks corresponding nodes in the graph.
  void SetInitialChangesFromBcp(
      const std::unordered_map<std::string, std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>>& changed_class_info) {
    size_t initial_changed_nodes = 0;

    // Iterate through all vertices in the graph
    for (const auto& [vertex_id, vertex] : graph_.GetVertices()) {
      DexSymId dex_sym_id(vertex_id);

      // Skip method nodes, only process class nodes
      if (!dex_sym_id.IsClass()) {
        continue;
      }

      const std::string& class_descriptor = vertex.GetDescriptor();

      // Check if this class is in the changed BCP classes
      auto it = changed_class_info.find(class_descriptor);
      if (it != changed_class_info.end()) {
        // Mark this node as changed with the appropriate dependency types
        auto& graph_vertex = graph_.graph_.get_vertex(vertex_id);
        // This should be a class node, not a method node
        CHECK(dex_sym_id.IsClass()) << "SetInitialChangesFromBcp should not modify method nodes: "
                                        << class_descriptor;
        graph_vertex.SetChanges(it->second);
        initial_changed_nodes++;
      }
    }

    LOG(INFO) << "Set initial changes for " << initial_changed_nodes << " nodes from BCP diff";
  }

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
        succ_vertex.MergeChanges(edge.GetDeps() & vertex.GetChanges());
      }
    }
  }

  // Set initial changes on app dependency graph based on affected BCP methods.
  // Marks app method nodes as changed if they correspond to affected BCP methods.
  void SetInitialChangesFromBcpMethods(
      const std::vector<DexSymId>& affected_bcp_methods) {
    size_t initial_changed_nodes = 0;

    for (const auto& [vertex_id, vertex] : graph_.GetVertices()) {
      DexSymId dex_sym_id(vertex_id);

      // Skip class nodes, only process method nodes
      if (dex_sym_id.IsClass()) {
        continue;
      }
      if (!dex_sym_id.IsBcpDex()) {
        continue;
      }
      bool found = false;
      for (auto t:affected_bcp_methods) {
        DexSymId k = t;
        k.SetIsBcpDex(true);
        if (k.GetDexFileIndex()==dex_sym_id.GetDexFileIndex() && k.GetMethodDefId() == dex_sym_id.GetMethodDefId()) {
          found = true;
          initial_changed_nodes++;
          break;
        }
      }

      if (found) {
        auto& graph_vertex = graph_.graph_.get_vertex(vertex_id);
        graph_vertex.SetChange();
        initial_changed_nodes++;
      }
    }

    LOG(INFO) << "Set initial changes for " << initial_changed_nodes << " BCP method nodes";
  }

 private:
  DependencyGraph& graph_;
};

// Empty base implementation - derived classes override SetInitialChanges
// This is only used for BcpDependencyGraphPropagator which has its own implementation
void DependencyGraphPropagator::SetInitialChanges() {
  // Base class does nothing - BCP change detection is handled by BcpDependencyGraphPropagator
}

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
  void ComputeStringIdChanges() {
    auto& origin_dexs = bcp_graph_.GetDexFiles();
    CHECK(origin_dexs->size() == updated_boot_dex_files_.size());
    size_t size = origin_dexs->size();
    for (size_t i = 0; i < size; ++i) {
      auto& origin_dex = (*origin_dexs)[i];
      auto& updated_dex = updated_boot_dex_files_[i];
      // for string ids in range(0,origin dex string id count)
      // if origin dex->get string(id) not eq updated dex string(id)
      // changed dex string add: dex id,string id
    }
    // return changed dex string
  }
  // IMPLEMENT ME:
  void MarkStringIdChanges() {
    // for all methods in 
  }



  // Getter for interface method changes (used by app dependency graph builder)
  // Move the ownership out since bcp_propagator will be destroyed after this
  InterfaceMethodChanges GetInterfaceMethodChanges() { return std::move(interface_method_changes_); }
  void SetInitialChanges() override {
    size_t initial_changed_class_counter = 0;
    size_t interface_method_changes_counter = 0;
    // Iterate through all class nodes in BcpDependencyGraph
    for (const auto& [vertex_id, vertex] : bcp_graph_.GetVertices()) {
      // Create DexSymId from vertex_id
      DexSymId dex_sym_id(vertex_id);

      // Skip method nodes, only process class nodes
      if (!dex_sym_id.IsClass()) {
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
          auto diff = DetectInterfaceMethodChanges(old_class_accessor, new_class_accessor);
          if (!diff.changes.empty()) {
            // Store detailed diff for printing
            interface_method_diffs_[class_descriptor] = diff;

            // Also convert to the simple set format for backward compatibility
            std::unordered_set<std::string> simple_changes;
            for (const auto& change : diff.changes) {
              if (change.type == MethodChangeType::kDeleted) {
                simple_changes.insert(change.method_name + ":" + change.old_sig);
              } else if (change.type == MethodChangeType::kAdded) {
                simple_changes.insert(change.method_name + ":" + change.new_sig);
              } else if (change.type == MethodChangeType::kModified) {
                simple_changes.insert(change.method_name + ":" + change.new_sig);
              }
            }
            interface_method_changes_[class_descriptor] = std::move(simple_changes);
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
          // Record the change info for app dependency graph
          auto& changed_vertex = bcp_graph_.graph_.get_vertex(static_cast<graaf::vertex_id_t>(dex_sym_id.id));
          changed_class_info_[class_descriptor] = changed_vertex.GetChanges();
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
          // Record that this class was deleted (all change types)
          changed_class_info_[class_descriptor].set();
        }
      }
    }
    // Print first 10 changed interfaces with detailed diff
    size_t printed_count = 0;
    for (const auto& [iface_desc, diff] : interface_method_diffs_) {
      if (printed_count >= 10) break;
      LOG(INFO) << "=== Interface Change #" << (printed_count + 1) << " ===";
      LOG(INFO) << "Interface: " << iface_desc;
      for (const auto& change : diff.changes) {
        if (change.type == MethodChangeType::kDeleted) {
          LOG(INFO) << "  - DELETED: " << change.method_name << change.old_sig;
        } else if (change.type == MethodChangeType::kAdded) {
          LOG(INFO) << "  + ADDED: " << change.method_name << change.new_sig;
        } else if (change.type == MethodChangeType::kModified) {
          LOG(INFO) << "  ~ MODIFIED: " << change.method_name << change.old_sig << " -> " << change.method_name << change.new_sig;
        }
      }
      printed_count++;
    }
    if (printed_count > 0) {
      LOG(INFO) << "Printed " << printed_count << " interface changes (first 10 of " << interface_method_diffs_.size() << " total)";
    }

    size_t printed_class_count = 0;
    for (const auto& [class_desc, changes] : changed_class_info_) {
      LOG(INFO) << "=== BCP Class Change #" << (printed_class_count + 1) << " ===";
      LOG(INFO) << "Class: " << class_desc;
      if (changes.test(static_cast<size_t>(DependencyType::kStaticFieldLayout))) {
        LOG(INFO) << "  [STATIC FIELD LAYOUT CHANGED]";
      }
      if (changes.test(static_cast<size_t>(DependencyType::kInstanceFieldLayout))) {
        LOG(INFO) << "  [INSTANCE FIELD LAYOUT CHANGED]";
      }
      if (changes.test(static_cast<size_t>(DependencyType::kVirtualTableLayout))) {
        LOG(INFO) << "  [VIRTUAL TABLE LAYOUT CHANGED]";
      }
      printed_class_count++;
    }
    if (!changed_class_info_.empty()) {
      LOG(INFO) << "Printed " << printed_class_count << " class changes (first 20 of " << changed_class_info_.size() << " total)";
    }

    LOG(INFO) << "Found " << initial_changed_class_counter << "(s) initial changed classes";
    LOG(INFO) << "Found " << interface_method_changes_counter << "(s) interface method changes";
  }

 private:
  // Detect interface method changes: returns detailed diff of method changes
  InterfaceMethodDiff DetectInterfaceMethodChanges(
      const art::ClassAccessor& old_interface,
      const art::ClassAccessor& new_interface) {
    InterfaceMethodDiff result;
    result.interface_descriptor = old_interface.GetDescriptor();

    // Build map of old methods: method_name -> signature
    // Use name:sig as key to handle Java method overloading correctly
    std::map<std::string, std::string> old_methods;
    for (const auto& method : old_interface.GetMethods()) {
      const auto& method_id = old_interface.GetDexFile().GetMethodId(method.GetIndex());
      const char* name = old_interface.GetDexFile().GetMethodName(method_id);
      Signature sig = old_interface.GetDexFile().GetMethodSignature(method_id);
      std::string method_key = std::string(name) + ":" + sig.ToString();
      old_methods[method_key] = sig.ToString();
    }

    // Build set of new method keys (name:sig) for quick lookup
    std::set<std::string> new_method_keys;
    std::map<std::string, std::string> new_methods;
    for (const auto& method : new_interface.GetMethods()) {
      const auto& method_id = new_interface.GetDexFile().GetMethodId(method.GetIndex());
      const char* name = new_interface.GetDexFile().GetMethodName(method_id);
      Signature sig = new_interface.GetDexFile().GetMethodSignature(method_id);
      std::string method_key = std::string(name) + ":" + sig.ToString();
      new_method_keys.insert(method_key);
      new_methods[method_key] = sig.ToString();
    }

    // Find deleted methods (in old but not in new)
    for (const auto& [method_key, sig] : old_methods) {
      if (new_method_keys.find(method_key) == new_method_keys.end()) {
        // Extract method name from method_key (name:sig format)
        size_t colon_pos = method_key.find(':');
        std::string method_name = method_key.substr(0, colon_pos);
        result.changes.push_back(MethodChangeDetail(MethodChangeType::kDeleted, method_name, sig, ""));
      }
    }

    // Find added and modified methods
    for (const auto& [method_key, sig] : new_methods) {
      auto it = old_methods.find(method_key);
      if (it == old_methods.end()) {
        // Added: in new but not in old
        size_t colon_pos = method_key.find(':');
        std::string method_name = method_key.substr(0, colon_pos);
        result.changes.push_back(MethodChangeDetail(MethodChangeType::kAdded, method_name, "", sig));
      } else if (it->second != sig) {
        // Modified: same name:sig key but different signature (shouldn't happen but handle it)
        size_t colon_pos = method_key.find(':');
        std::string method_name = method_key.substr(0, colon_pos);
        result.changes.push_back(MethodChangeDetail(MethodChangeType::kModified, method_name, it->second, sig));
      }
    }

    return result;
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
    const int kMaxPrintedChanges = 5;

    DependencyGraphNode& vertex = bcp_graph_.graph_.get_vertex(static_cast<graaf::vertex_id_t>(old_dex_sym_id.id));

    // Helper to convert field to string representation
    auto field_to_string = [](const art::ClassAccessor& accessor,
                               const art::ClassAccessor::Field& field) -> std::string {
      const auto& field_id = accessor.GetDexFile().GetFieldId(field.GetIndex());
      const char* name = accessor.GetDexFile().GetFieldName(field_id);
      const char* type = accessor.GetDexFile().GetFieldTypeDescriptor(field_id);
      return std::to_string(field.GetIndex()) + ":" + std::string(name) + ":" + std::string(type);
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
        if (/*old_it->GetIndex() != new_it->GetIndex() || */strcmp(old_name, new_name) != 0 || strcmp(old_type, new_type) != 0) {
          static_fields_changed = true;
          break;
        }
      }
    }
    if (static_fields_changed) {
      vertex.SetChange(DependencyType::kStaticFieldLayout);
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
        if (/*old_it->GetIndex() != new_it->GetIndex() ||*/strcmp(old_name, new_name) != 0 || strcmp(old_type, new_type) != 0) {
          instance_fields_changed = true;
          break;
        }
      }
    }
    if (instance_fields_changed) {
      vertex.SetChange(DependencyType::kInstanceFieldLayout);
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
        if (/*old_it->GetIndex() != new_it->GetIndex() ||*/strcmp(old_name, new_name) != 0 || old_signature != new_signature) {
          vtable_changed = true;
          break;
        }
      }
    }
    if (vtable_changed) {
      vertex.SetChange(DependencyType::kVirtualTableLayout);
    }

    // Print debug info for first kMaxPrintedChanges changed classes
    if (static_fields_changed || instance_fields_changed || vtable_changed) {
      if (changed_class_count < kMaxPrintedChanges || vertex.GetDescriptor() == "Landroid/view/View;") {
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

  // Detailed interface method diffs: interface_descriptor -> detailed diff (for printing)
  std::map<std::string, InterfaceMethodDiff> interface_method_diffs_;

  // Changed class info: class_descriptor -> bitset of change types
  // This is used to propagate changes to the app dependency graph
  std::unordered_map<std::string, std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>> changed_class_info_;

 public:
  // Collect all changed classes after propagation.
  // This includes both directly changed classes and indirectly affected classes
  // (through dependency graph propagation).
  void CollectChangedClassInfoAfterPropagation() {
    // After SetInitialChanges() and PropagateChanges() have been called,
    // collect ALL classes that have changes (not just directly changed ones).
    size_t collected_classes = 0;
    for (const auto& [vertex_id, vertex] : bcp_graph_.GetVertices()) {
      DexSymId dex_sym_id(vertex_id);
      // Skip method nodes, only process class nodes
      if (!dex_sym_id.IsClass()) {
        continue;
      }
      // Check if this class has any changes (directly or through propagation)
      if (vertex.IsChanged()) {
        const std::string& class_descriptor = vertex.GetDescriptor();
        auto& graph_vertex = bcp_graph_.graph_.get_vertex(vertex_id);
        changed_class_info_[class_descriptor] = graph_vertex.GetChanges();
        collected_classes++;
      }
    }
    LOG(INFO) << "Collected " << collected_classes << " changed classes after propagation";
  }

  // Getter for changed class info (used by app dependency graph propagator)
  const std::unordered_map<std::string, std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>>& GetChangedClassInfo() const {
    return changed_class_info_;
  }
};

// BCP method dependency graph propagator
// Propagates class changes to BCP methods and collects affected method descriptors
class BcpMethodDependencyGraphPropagator {
 public:
  BcpMethodDependencyGraphPropagator(
      DependencyGraph* bcp_method_graph,
      const std::unordered_map<std::string, std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>>& changed_class_info)
      : bcp_method_graph_(*bcp_method_graph), changed_class_info_(changed_class_info) {}

  // Set initial changes on BCP method graph based on changed BCP classes.
  // Marks class nodes as initially changed. PropagateChanges() will then
  // propagate these changes to method nodes through the dependency edges.
  void SetInitialChangesFromBcpClassChanges() {
    size_t initial_changed_classes = 0;

    // Iterate through all class vertices in BCP method graph and mark them as changed
    // if their descriptor is in changed_class_info
    for (const auto& [vertex_id, vertex] : bcp_method_graph_.GetVertices()) {
      DexSymId dex_sym_id(vertex_id);

      // Only process class nodes, skip method nodes
      if (!dex_sym_id.IsClass()) {
        continue;
      }

      const std::string& class_descriptor = vertex.GetDescriptor();
      auto it = changed_class_info_.find(class_descriptor);
      if (it != changed_class_info_.end()) {
        auto& graph_vertex = bcp_method_graph_.graph_.get_vertex(vertex_id);
        graph_vertex.SetChanges(it->second);
        initial_changed_classes++;
      }
    }

    LOG(INFO) << "Set initial changes for " << initial_changed_classes << " BCP class nodes from class changes";
  }

  // Propagate changes through the BCP method dependency graph
  void PropagateChanges() {
    auto& inner_graph = bcp_method_graph_.graph_;
    auto result = graaf::algorithm::dfs_topological_sort<DependencyGraphNode, DependencyGraphEdge>(
        bcp_method_graph_.graph_);
    if (!result.has_value()) {
      LOG(ERROR) << "BCP method dependency graph has cycles!";
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
        succ_vertex.MergeChanges(edge.GetDeps() & vertex.GetChanges());
      }
    }
  }

  // Collect all affected BCP method descriptors after propagation
  std::vector<DexSymId> CollectAffectedBcpMethods() {
    std::vector<DexSymId> affected_methods;
    size_t collected = 0;

    for (const auto& [vertex_id, vertex] : bcp_method_graph_.GetVertices()) {
      DexSymId dex_sym_id(vertex_id);

      // Skip class nodes
      if (dex_sym_id.IsClass()) {
        continue;
      }

      if (vertex.IsChanged()) {
        affected_methods.push_back(dex_sym_id);
        collected++;
      }
    }

    LOG(INFO) << "Collected " << collected << " affected BCP methods after propagation";
    for (auto x:affected_methods) LOG(INFO) << "BCP invalid method:" << bcp_method_graph_.graph_.get_vertex(x.id).GetDescriptor();
    return affected_methods;
  }

 private:
  DependencyGraph& bcp_method_graph_;
  const std::unordered_map<std::string, std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>>& changed_class_info_;
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

  // Returns the set of methods that have compiled code in the OAT file.
  // Key: (dex_file_idx, class_def_index, method_index)
  const std::set<std::tuple<size_t, uint16_t, uint32_t>>& GetCompiledMethods() const {
    return compiled_methods_;
  }

  // Precompute the set of methods that have OatMethod with compiled code
  // Loads DexFiles from OatFile and validates order matches expected_dex_files (if provided)
  bool PrecomputeCompiledMethods(const std::vector<std::unique_ptr<const art::DexFile>>* expected_dex_files = nullptr) {
    if (oat_file_ == nullptr) {
      return true;
    }

    // Load DexFiles from OAT
    std::vector<std::unique_ptr<const art::DexFile>> oat_dex_files;
    size_t oat_dex_file_count = oat_file_->GetOatDexFiles().size();
    for (size_t i = 0; i < oat_dex_file_count; ++i) {
      const art::OatDexFile* oat_dex_file = oat_file_->GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }
      std::string error_msg;
      std::unique_ptr<const art::DexFile> dex_file = oat_dex_file->OpenDexFile(&error_msg);
      if (dex_file == nullptr) {
        LOG(ERROR) << "Failed to open DexFile from OAT: " << error_msg;
        return false;
      }

      // Validate by SHA1 if expected_dex_files is provided
      if (expected_dex_files != nullptr && i < expected_dex_files->size()) {
        const art::DexFile* expected = expected_dex_files->at(i).get();
        if (dex_file->GetSha1() != expected->GetSha1()) {
          LOG(ERROR) << "DexFile SHA1 mismatch at index " << i
                     << ": OAT has " << dex_file->GetSha1().ToString()
                     << " but expected " << expected->GetSha1().ToString();
          return false;
        }
      }

      oat_dex_files.push_back(std::move(dex_file));
    }

    // Now iterate and find compiled methods
    for (size_t i = 0; i < oat_dex_files.size(); ++i) {
      const art::OatDexFile* oat_dex_file = oat_file_->GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }

      const art::DexFile* dex_file = oat_dex_files[i].get();
      for (ClassAccessor accessor : dex_file->GetClasses()) {
        const uint16_t class_def_index = accessor.GetClassDefIndex();
        const OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
        uint32_t class_method_index = 0;

        for (const ClassAccessor::Method& method : accessor.GetMethods()) {
          const OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
          class_method_index++;
          const OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
          if (method_header != nullptr && method_header->GetCodeSize() > 0) {
            // Method has compiled code - add to set
            compiled_methods_.insert({i, class_def_index, method.GetIndex()});
          }
        }
      }
    }
    LOG(INFO) << "Precomputed " << compiled_methods_.size() << " compiled methods from OAT file";
    return true;
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
  // Precomputed set of methods with compiled code: (dex_file_idx, class_def_index, method_index)
  std::set<std::tuple<size_t, uint16_t, uint32_t>> compiled_methods_;
};

// OatFilePatcher modifies OAT files to disable compiled methods by setting their code_offset to 0.
// This causes the methods to fall back to interpreter execution.
class OatFilePatcher {
 public:
  explicit OatFilePatcher(const std::string& oat_file_path);

  // Disable a method by setting its code_offset_ to 0
  // dex_file_idx: index of the DEX file in the OAT
  // class_def_idx: class definition index in the DEX file
  // method_idx: method index (within the class, NOT the method index in the DEX)
  bool DisableMethod(size_t dex_file_idx, uint16_t class_def_idx, uint32_t method_idx);

  // Save the modified OAT file to output_path
  bool SaveToFile(const std::string& output_path, std::string* error_msg);

  // Get the number of methods that were disabled
  size_t GetDisabledCount() const { return disabled_methods_.size(); }

  // Load OAT file info to get method offsets (must be called before DisableMethod)
  bool LoadOatFileInfo(std::string* error_msg);

 private:
  std::string oat_file_path_;
  std::unique_ptr<art::OatFile> oat_file_;
  // Store the file offsets of OatMethodOffsets for each (dex_file_idx, class_def_idx, method_idx)
  std::map<std::tuple<size_t, uint16_t, uint32_t>, uint32_t> method_offsets_;
  // Store the methods that need to be disabled
  std::set<std::tuple<size_t, uint16_t, uint32_t>> disabled_methods_;
};

OatFilePatcher::OatFilePatcher(const std::string& oat_file_path)
    : oat_file_path_(oat_file_path) {}

bool OatFilePatcher::LoadOatFileInfo(std::string* error_msg) {
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

  // Precompute the file offsets for all compiled methods
  size_t dex_file_count = oat_file_->GetOatDexFiles().size();
  for (size_t i = 0; i < dex_file_count; ++i) {
    const art::OatDexFile* oat_dex_file = oat_file_->GetOatDexFiles()[i];
    if (oat_dex_file == nullptr) {
      continue;
    }

    // Open DexFile from OatDexFile
    std::string dex_error_msg;
    std::unique_ptr<const art::DexFile> dex_file = oat_dex_file->OpenDexFile(&dex_error_msg);
    if (dex_file == nullptr) {
      LOG(WARNING) << "Failed to open DexFile: " << dex_error_msg;
      continue;
    }

    for (art::ClassAccessor accessor : dex_file->GetClasses()) {
      const uint16_t class_def_index = accessor.GetClassDefIndex();
      const art::OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
      uint32_t class_method_index = 0;

      for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
        const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index);
        class_method_index++;

        // Get the OatQuickMethodHeader to check if method has compiled code
        const art::OatQuickMethodHeader* method_header = oat_method.GetOatQuickMethodHeader();
        if (method_header == nullptr || method_header->GetCodeSize() == 0) {
          continue;  // Method doesn't have compiled code
        }

        // Get the file offset of OatMethodOffsets
        uint32_t offset = oat_class.GetOatMethodOffsetsOffset(class_method_index - 1);
        if (offset == 0) {
          continue;
        }

        // Store: (dex_file_idx, class_def_idx, method_idx) -> file_offset
        method_offsets_[{i, class_def_index, method.GetIndex()}] = offset;
      }
    }
  }

  LOG(INFO) << "Precomputed " << method_offsets_.size() << " method offsets from OAT file";
  return true;
}

bool OatFilePatcher::DisableMethod(size_t dex_file_idx, uint16_t class_def_idx, uint32_t method_idx) {
  auto it = method_offsets_.find({dex_file_idx, class_def_idx, method_idx});
  if (it == method_offsets_.end()) {
    // Method not found or doesn't have compiled code, nothing to disable
    return false;
  }

  // Mark this method to be disabled
  disabled_methods_.insert({dex_file_idx, class_def_idx, method_idx});
  return true;
}

bool OatFilePatcher::SaveToFile(const std::string& output_path, std::string* error_msg) {
  // Load OAT file info if not already loaded
  if (oat_file_ == nullptr) {
    if (!LoadOatFileInfo(error_msg)) {
      return false;
    }
  }

  // Open the original file for reading
  std::ifstream input(oat_file_path_, std::ios::binary);
  if (!input.is_open()) {
    *error_msg = "Failed to open input file: " + oat_file_path_;
    return false;
  }

  // Get file size
  input.seekg(0, std::ios::end);
  size_t file_size = input.tellg();
  input.seekg(0, std::ios::beg);

  // Read entire file into memory
  std::vector<char> file_data(file_size);
  input.read(file_data.data(), file_size);
  input.close();

  if (!input.good()) {
    *error_msg = "Failed to read input file: " + oat_file_path_;
    return false;
  }

  // Modify the code_offset_ for each disabled method
  // OatMethodOffsets.code_offset_ is a uint32_t at offset 0 within the structure
  for (const auto& key : disabled_methods_) {
    auto it = method_offsets_.find(key);
    if (it == method_offsets_.end()) {
      continue;
    }
    uint32_t method_offset = it->second;
    // Verify offset is within file bounds
    if (method_offset + sizeof(uint32_t) > file_size) {
      LOG(WARNING) << "Offset out of bounds: " << method_offset;
      continue;
    }
    // Set code_offset_ to 0
    uint32_t* code_offset_ptr = reinterpret_cast<uint32_t*>(file_data.data() + method_offset);
    *code_offset_ptr = 0;
    LOG(INFO) << "Disabled method at offset " << method_offset;
  }

  // Write the modified data to output file
  std::ofstream output(output_path, std::ios::binary);
  if (!output.is_open()) {
    *error_msg = "Failed to create output file: " + output_path;
    return false;
  }

  output.write(file_data.data(), file_size);
  output.close();

  if (!output.good()) {
    *error_msg = "Failed to write output file: " + output_path;
    return false;
  }

  LOG(INFO) << "Saved modified OAT file to: " << output_path;
  return true;
}

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
        // If vertex B doesn't exist in original dependency graph, create it in expanded_graph
        // B might be a BCP method that has changed - it will be marked during BCP method propagation
        if (!original_dep_graph_.graph_.has_vertex(vertex_b_id)) {
          DexSymId bcp_method_symid(vertex_b_id);
          const InlineCallGraphNode& vertex_b = inline_graph_.graph_.get_vertex(vertex_b_id);
          std::string method_name = vertex_b.GetDescriptor();
          expanded_graph->AddVertexIfAbsent(bcp_method_symid, method_name, false);  // is_changed=false
          expanded_graph->UpdateEdge(bcp_method_symid, DexSymId(vertex_a_id), std::bitset<3>(true));
          // B has no predecessors in original graph, so no C → B edges to propagate
          // Skip to next B but don't count as skipped since we created the vertex
          continue;
        }

        // Get all predecessors of B using reverse adjacency map (C → B means B depends on C)
        auto it = reverse_adj.find(vertex_b_id);
        if (it == reverse_adj.end() || it->second.empty()) {
          b_has_no_neighbors++;
          continue;
        }

        // For each predecessor C of B (C → B, B depends on C), add C → A to expanded graph
        // This propagates: if A inlines B and B depends on C, then A also depends on C.
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
              << ", B not in dep graph (created from inline): " << skipped_b_not_in_dep_graph
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
          DexSymId dex_sym_id(i, class_def_index, dex_method_idx);
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
          DexSymId caller_dex_sym_id(i, class_def_index, dex_method_idx);
          AnalyzeOatMethod(method_header, class_def_index, caller_dex_sym_id);
        }
      }
    }
    return true;
  }
  bool AnalyzeOatMethod(const OatQuickMethodHeader* caller_header, uint16_t caller_class_def_idx, const DexSymId caller_dex_sym_id) {
    CodeInfo code_info(caller_header);
    for (const StackMap& stack_map : code_info.GetStackMaps()) {
      for (const InlineInfo& inline_info : code_info.GetInlineInfosOf(stack_map)) {
        MethodInfo method_info = code_info.GetMethodInfoOf(inline_info);

        // Prefer MethodInfo regardless of whether ArtMethod* is available or not
        if (method_info.HasDexFileIndex()) {
          graaf::vertex_id_t vertex_id_caller = static_cast<graaf::vertex_id_t>(caller_dex_sym_id.id);
          DexSymId callee_dex_sym_id(method_info.GetDexFileIndex(), caller_class_def_idx, method_info.GetMethodIndex());

          // Try to get method name
          std::string method_name;
          if (inline_info.EncodesArtMethod()) {
            ArtMethod* callee = inline_info.GetArtMethod();
            ScopedObjectAccess soa(Thread::Current());
            method_name = callee->PrettyMethod();
          } else {
            // No ArtMethod*, use index as method name
            method_name = android::base::StringPrintf("d%uu%u", method_info.GetDexFileIndex(), method_info.GetMethodIndex());
            if (method_info.GetDexFileIndexKind() == MethodInfo::kKindBCP) {
              callee_dex_sym_id.SetIsBcpDex(true);
            }
          }
          graaf::vertex_id_t vertex_id_callee = static_cast<graaf::vertex_id_t>(callee_dex_sym_id.id);

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
    } else if (option == "--fix") {
      fix_ = true;
    } else if (option.starts_with("--dump-successors=")) {
      dump_successors_ = raw_option + strlen("--dump-successors=");
    } else if (option.starts_with("--dump-ancestors=")) {
      dump_ancestors_ = raw_option + strlen("--dump-ancestors=");
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

    // Check that --fix is used with --oat
    if (fix_ && oat_file_ == nullptr) {
      *error_msg = "--fix requires --oat to be specified.";
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
  --fix                         Disable invalidated methods and output fixed OAT file
  --dump-successors=<class>    Dump all successor nodes of the given class descriptor
  --dump-ancestors=<class>     Dump all ancestor nodes of the given class descriptor
  --help, -h                    Show this message
)";
  }

 public:
  bool help_ = false;
  bool verbose_ = false;
  bool fix_ = false;
  const char* dump_successors_ = nullptr;
  const char* dump_ancestors_ = nullptr;
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
    // Use a local variable instead of pointer to avoid dangling reference
    InterfaceMethodChanges interface_method_changes;

    // Changed class info for app dependency graph - populated when BCP diff is enabled
    std::unordered_map<std::string, std::bitset<static_cast<size_t>(DependencyType::kDependencyTypeCount)>> changed_class_info;

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

      // Run change detection and propagation
      BcpDependencyGraphPropagator bcp_propagator(&original_bcp_graph, updated_boot_dex_files);
      LOG(INFO) << "Setting initial changes...";
      bcp_propagator.SetInitialChanges();
      LOG(INFO) << "Propagating changes";
      bcp_propagator.PropagateChanges();
      LOG(INFO) << "BCP change propagation complete";

      // Collect all changed classes after propagation (including indirect changes)
      bcp_propagator.CollectChangedClassInfoAfterPropagation();

      // Get interface method changes for app dependency graph
      // Move ownership to avoid dangling pointer after bcp_propagator is destroyed
      interface_method_changes = bcp_propagator.GetInterfaceMethodChanges();

      // Get changed class info for app dependency graph propagation
      changed_class_info = bcp_propagator.GetChangedClassInfo();

      // Collect and report results
      size_t changed_classes = 0;
      size_t changed_methods = 0;
      for (const auto& [vertex_id, vertex] : original_bcp_graph.GetVertices()) {
        if (vertex.IsChanged()) {
          DexSymId sym_id(vertex_id);
          if (!sym_id.IsClass()) {
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

    // Load OAT file first if provided (needed for filtering compiled methods)
    std::unique_ptr<OatFileAnalyzer> oat_analyzer;
    const DependencyGraphBuilder::CompiledMethodSet* compiled_methods = nullptr;
    if (args_->oat_file_) {
      oat_analyzer.reset(new OatFileAnalyzer(args_->oat_file_));
      if (!oat_analyzer->LoadOatFile(&error_msg)) {
        LOG(ERROR) << "Failed to load OAT file: " << error_msg;
        return false;
      }
      // Precompute compiled methods after dex files are loaded in DependencyGraphBuilder
    }

    // Build app dependency graph with interface method changes from BCP diff
    DependencyGraph graph;
    DependencyGraphBuilder graph_builder(args_->apk_file_, &graph, &interface_method_changes,
                                          compiled_methods);
    if (!graph_builder.BuildGraph(&error_msg)) {
      LOG(ERROR) << error_msg;
      return false;
    }

    // Now precompute compiled methods using the dex files from graph_builder
    if (oat_analyzer != nullptr) {
      if (!oat_analyzer->PrecomputeCompiledMethods(&graph_builder.GetDexFiles())) {
        LOG(ERROR) << "Failed to precompute compiled methods";
        return false;
      }
      compiled_methods = &oat_analyzer->GetCompiledMethods();
      // Rebuild graph with compiled method filtering
      DependencyGraph graph2;
      DependencyGraphBuilder graph_builder2(args_->apk_file_, &graph2, &interface_method_changes,
                                             compiled_methods);
      if (!graph_builder2.BuildGraph(&error_msg)) {
        LOG(ERROR) << error_msg;
        return false;
      }
      graph = std::move(graph2);
    }

    // Build inline call graph if OAT file is provided
    InlineCallGraph inline_call_graph;
    if (args_->oat_file_) {
      LOG(INFO) << "Building inline call graph from OAT file...";
      OatFileAnalyzer oat_analyzer2(args_->oat_file_);
      if (!oat_analyzer2.LoadOatFile(&error_msg)) {
        LOG(ERROR) << "Failed to load OAT file: " << error_msg;
        return false;
      }
      InlineCallGraphBuilder inline_graph_builder(&inline_call_graph,
                                                 oat_analyzer2.GetOatFile(),
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

      // Dump successors if requested
      if (args_->dump_successors_ != nullptr) {
        graph.DumpSuccessors(args_->dump_successors_);
      }

      // Dump ancestors if requested
      if (args_->dump_ancestors_ != nullptr) {
        graph.DumpAncestors(args_->dump_ancestors_);
      }

      // Propagate changes through the expanded dependency graph to get AOT-invalidated methods
      if (args_->origin_bcp_prefix_ != nullptr && args_->updated_bcp_prefix_ != nullptr) {
        LOG(INFO) << "Setting initial changes from BCP diff on expanded dependency graph...";
        DependencyGraphPropagator propagator(&graph);
        propagator.SetInitialChangesFromBcp(changed_class_info);

        // Build BCP method dependency graph and propagate to get affected BCP methods
        LOG(INFO) << "Building BCP method dependency graph for method change analysis...";
        std::vector<const char*> original_bcp_jars;
        std::vector<std::string> original_paths_storage;
        std::string origin_prefix = args_->origin_bcp_prefix_;
        if (!origin_prefix.empty() && origin_prefix.back() != '/') {
          origin_prefix += '/';
        }
        for (const auto& jar_relative_path : kBootClasspathJars) {
          std::string full_path = origin_prefix + jar_relative_path.substr(1);
          original_paths_storage.push_back(full_path);
          original_bcp_jars.push_back(original_paths_storage.back().c_str());
        }

        // Use heap allocation to reduce stack usage
        std::unique_ptr<DependencyGraph> bcp_method_graph = std::make_unique<DependencyGraph>();
        BcpMethodDependencyGraphBuilder bcp_method_builder(original_bcp_jars, bcp_method_graph.get(), &interface_method_changes);
        if (!bcp_method_builder.BuildGraph(&error_msg)) {
          LOG(ERROR) << "Failed to build BCP method dependency graph: " << error_msg;
          return false;
        }

        BcpMethodDependencyGraphPropagator bcp_method_propagator(bcp_method_graph.get(), changed_class_info);
        bcp_method_propagator.SetInitialChangesFromBcpClassChanges();
        bcp_method_propagator.PropagateChanges();
        auto affected_bcp_methods = bcp_method_propagator.CollectAffectedBcpMethods();

        // Set initial changes from BCP methods on app graph
        LOG(INFO) << "Setting initial changes from affected BCP methods...";
        propagator.SetInitialChangesFromBcpMethods(affected_bcp_methods);

        LOG(INFO) << "Propagating changes through expanded dependency graph...";
        propagator.PropagateChanges();
        LOG(INFO) << "Change propagation complete";

        // Collect AOT-invalidated methods and affected classes
        size_t aot_invalidated_methods = 0;
        size_t aot_affected_classes = 0;
        std::vector<std::string> aot_invalidated_method_names;
        std::vector<std::pair<std::string, std::bitset<3>>> affected_class_details;
        for (const auto& [vertex_id, vertex] : graph.GetVertices()) {
          if (vertex.IsChanged()) {
            DexSymId sym_id(vertex_id);
            if (!sym_id.IsClass()) {
              aot_invalidated_methods++;
              const std::string& method_name = vertex.GetDescriptor();
              //if (compiled_methods->find({sym_id.GetDexFileIndex(), sym_id.GetClassDefId(), sym_id.GetMethodDefId()}) == compiled_methods->end()) continue;
              aot_invalidated_method_names.push_back(vertex.GetDescriptor());
            } else {
              aot_affected_classes++;
              affected_class_details.push_back({vertex.GetDescriptor(), vertex.GetChanges()});
            }
          }
        }

        size_t printed_class_count = 0;
        //for (const auto& [class_desc, changes] : affected_class_details) {
          //LOG(INFO) << "=== APP Affected Class #" << (printed_class_count + 1) << " ===";
          ////LOG(INFO) << "Class: " << class_desc;
          //printed_class_count++;
        //}
        if (!affected_class_details.empty()) {
          LOG(INFO) << "Printed " << printed_class_count << " affected APP classes (first 20 of " << affected_class_details.size() << " total)";
        }

        *os << "\n=== Compiled Method Count ===\n";
        *os << "Total compiled methods: " << compiled_methods->size() << "\n";

        *os << "\n=== AOT Invalidation Detection Results ===\n";
        *os << "Total AOT-affected classes: " << aot_affected_classes << "\n";
        *os << "Total AOT-invalidated methods: " << aot_invalidated_methods << "\n";
        // Statistics: interface vs class layout affected methods
        *os << "  (Interface method changes: " << g_interface_affected_methods << ")\n";
        *os << "  (Class layout changes: " << (aot_invalidated_methods - g_interface_affected_methods) << ")\n";

        // Print all invalidated method names
        *os << "\n=== AOT-Invalidated Methods ===\n";
        for (const auto& method_name : aot_invalidated_method_names) {
          *os << method_name << "\n";
        }

        // If --fix is enabled, disable the invalidated methods in the OAT file
        if (args_->fix_ && aot_invalidated_methods > 0 && args_->oat_file_ != nullptr) {
          LOG(INFO) << "Creating fixed OAT file...";

          std::string fix_error_msg;
          OatFilePatcher patcher(args_->oat_file_);

          // Load OAT file info to get method offsets
          if (!patcher.LoadOatFileInfo(&fix_error_msg)) {
            LOG(ERROR) << "Failed to load OAT file info: " << fix_error_msg;
          } else {
            // Disable each invalidated method
            for (const auto& [vertex_id, vertex] : graph.GetVertices()) {
              if (vertex.IsChanged()) {
                DexSymId sym_id(vertex_id);
                if (!sym_id.IsClass()) {
                  // This is a method, disable it
                  uint32_t dex_file_idx = sym_id.GetDexFileIndex();
                  uint16_t class_def_idx = sym_id.GetClassDefId();
                  uint32_t method_idx = sym_id.GetMethodDefId();
                  patcher.DisableMethod(dex_file_idx, class_def_idx, method_idx);
                }
              }
            }

            // Generate output file name: original.oat -> original.oatfixed
            // Note: Using .oatfixed instead of .oat.fixed so that GetVdexFilename
            // correctly derives the vdex filename as original.vdex instead of original.oat.vdex
            std::string output_path = std::string(args_->oat_file_) + "fixed";

            if (patcher.SaveToFile(output_path, &fix_error_msg)) {
              *os << "\n=== Fixed OAT File ===\n";
              *os << "Output: " << output_path << "\n";
              *os << "Disabled methods: " << patcher.GetDisabledCount() << "\n";
            } else {
              LOG(ERROR) << "Failed to save fixed OAT file: " << fix_error_msg;
            }
          }
        }
      }
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