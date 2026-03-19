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
#include <cstdint>
#include <cstdio>
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
struct DexSymId {
  uint32_t id;
  // |-- 8 bits: dex file index --|-- 8 bits: is method --|-- 16 bits: sym id --|
  void SetDexFileIndex(uint32_t dex_file_index) {
    id = (id & 0x00FFFFFF) | (dex_file_index << 24);
  }
  uint32_t GetDexFileIndex() {
    return (id >> 24) & 0xFF;
  }
  bool IsMethod() const {
    return (id & 0x00FF0000) != 0;
  }
  void SetSymId(uint32_t sym_id) {
    id = (id & 0xFFFF0000) | (sym_id & 0x0000FFFF);
  }
  DexSymId(uint32_t dex_file_index, bool is_method, uint32_t sym_id) : id(0) {
    SetDexFileIndex(dex_file_index);
    if (is_method) {
      id |= 0x00010000;
    }
    SetSymId(sym_id);
  }
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
};

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

class DependencyGraphBuilder {
 public:
  DependencyGraphBuilder(const char* apk_file_path, DependencyGraph* graph)
      : apk_file_path_(apk_file_path), graph_(*graph) {
    // TODO: There is no neccessity to analysis all methods in the APK, only compiled methods in
    // OAT.
  }
  const std::vector<std::unique_ptr<const art::DexFile>>& GetDexFiles() const {
    return dex_files_;
  }
  bool BuildGraph(std::string* error_msg) {
    if (!ExtractDexFromApk(error_msg)) {
      return false;
    }
    size_t i = 0;
    for (const auto& dex : dex_files_) {
      if (!AnalyzeDexMethods(dex.get(), i, error_msg)) {
        LOG(ERROR) << "Failed to analyze DEX methods: " << *error_msg;
        return false;
      }
      if (!AnalyzeDexClasses(dex.get(), i, error_msg)) {
        LOG(ERROR) << "Failed to analyze DEX classes: " << *error_msg;
        return false;
      }
      i++;
    }
    LOG(INFO) << graph_.Summary();
    return true;
  }

 private:
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
  bool AnalyzeDexClasses(const art::DexFile* dex,size_t dex_file_idx, ATTRIBUTE_UNUSED std::string* error_msg) {
    // Build dependency edges based on class hierarchy.
    for (art::ClassAccessor accessor : dex->GetClasses()) {
      // TODO: Handle interfaces
      const dex::ClassDef& class_def = dex->GetClassDef(accessor.GetClassDefIndex());
      const dex::TypeId& superclass_type_id = dex->GetTypeId(class_def.superclass_idx_);
      const char* superclass_descriptor = dex->GetTypeDescriptor(superclass_type_id);
      const char* class_descriptor = accessor.GetDescriptor();
      DexSymId superclass_dex_sym_id(dex_file_idx, false,
                                    class_def.superclass_idx_.index_);
      DexSymId class_dex_sym_id(dex_file_idx, false,
                                 accessor.GetClassIdx().index_);
      graph_.AddVertexIfAbsent(superclass_dex_sym_id, superclass_descriptor, false);
      graph_.AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);
      graph_.UpdateEdge(superclass_dex_sym_id, class_dex_sym_id, std::bitset<3>(7));
    }
    return true;
  }
  bool AnalyzeDexMethods(const art::DexFile* dex,size_t dex_file_idx, ATTRIBUTE_UNUSED std::string* error_msg) {
    // Build dependency edges based on method instructions.
    uint32_t count = 0;
    for (art::ClassAccessor accessor : dex->GetClasses()) {
      for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
        const art::CodeItemInstructionAccessor& code = method.GetInstructions();
        //std::string method_name(dex->PrettyMethod(method.GetIndex()));
        std::string method_name(android::base::StringPrintf("d%zum%u", dex_file_idx,count));
        DexSymId method_dex_sym_id(dex_file_idx, true, method.GetIndex());
        graph_.AddVertexIfAbsent(method_dex_sym_id, method_name, false);
        if (count++ > 50000) // TODO: remove me
          return true;
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

                graph_.UpdateEdge(
                    class_dex_sym_id,
                    method_dex_sym_id,
                    std::bitset<3>(1 << static_cast<size_t>(DependencyType::kVirtualTableLayout)));
                break;
              }
              case kDexInvokeSuper:
              case kDexInvokeDirect:
              case kDexInvokeStatic: {
                // TODO: If invoke target is from boot classpath, just set the method vertex as
                // changed.
                break;
              }
              case kDexInvokeInterface:
                break;
              default:
                LOG(WARNING) << "    Unknown invoke type at dex pc " << inst.DexPc()
                             << ": opcode=" << static_cast<int>(inst->Opcode()) << "\n";
                break;
            }
          } else if (IsInstructionIGetOrIPut(inst->Opcode())) {
            auto field_idx = inst->VRegC();
            const dex::FieldId& field_id = dex->GetFieldId(field_idx);
            const dex::TypeId& type_id = dex->GetTypeId(field_id.class_idx_);
            const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
            const char* class_descriptor = dex->GetStringData(name_id);
            DexSymId class_dex_sym_id(dex_file_idx, false, field_id.class_idx_.index_);
            graph_.AddVertexIfAbsent(class_dex_sym_id, class_descriptor, false);

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

  const char* apk_file_path_;
  std::vector<std::unique_ptr<const art::DexFile>> dex_files_;
  DependencyGraph& graph_;
};

class DependencyGraphPropagator {
 public:
  DependencyGraphPropagator(DependencyGraph* graph) : graph_(*graph) {}
  void SetInitialChanges();  // TODO: Set initial changes based on changed BCP classes.
  void PropagateChanges() {
    // Propagate changes from the initial changed classes through the dependency graph.
    auto& inner_graph = graph_.graph_;
    auto result = graaf::algorithm::dfs_topological_sort<DependencyGraphNode, DependencyGraphEdge>(
        graph_.graph_);
    if (!result.has_value()) {
      LOG(ERROR) << "Dependency graph has cycles!";
      return;
    }
    const std::vector<graaf::vertex_id_t>& topo = result.value();
    for (auto id : topo) {
      for (auto succId : inner_graph.get_neighbors(id)) {
        auto edge = inner_graph.get_edge(id, succId);
        auto& succ = inner_graph.get_vertex(succId);
        succ.changes_ |= edge.GetDeps() & inner_graph.get_vertex(id).changes_;
      }
    }
  }

 private:
  DependencyGraph& graph_;
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
      if (dex_file->GetLocation() != oat_dex_file->GetDexFileLocation()) {
        *error_msg = "DEX location mismatch between OAT and DEX files.";
        LOG(ERROR) << *error_msg;
        return false;
      }
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

    // Step 2: For each inline edge A → B (A inlines B)
    for (const auto& [vertex_a_id, vertex_a] : inline_graph_.GetVertices()) {
      // Get all successors B of A (A → B means A inlines B)
      const auto& successors = inline_graph_.graph_.get_neighbors(vertex_a_id);

      if (successors.empty()) {
        continue;
      }

      // Skip if vertex A doesn't exist in original dependency graph
      if (!original_dep_graph_.graph_.has_vertex(vertex_a_id)) {
        continue;
      }

      // For each B that is inlined by A
      for (graaf::vertex_id_t vertex_b_id : successors) {
        // Skip if vertex B doesn't exist in original dependency graph
        if (!original_dep_graph_.graph_.has_vertex(vertex_b_id)) {
          continue;
        }

        // Get all outgoing edges from B in original dependency graph (B → C)
        auto neighbors_b = original_dep_graph_.graph_.get_neighbors(vertex_b_id);

        if (neighbors_b.empty()) {
          continue;
        }

        // For each dependency edge B → C, add A → C to expanded graph
        for (graaf::vertex_id_t vertex_c_id : neighbors_b) {
          // Get the dependency bits from original graph
          const auto& edge_bc = original_dep_graph_.graph_.get_edge(vertex_b_id, vertex_c_id);
          std::bitset<3> deps = edge_bc.GetDeps();

          // Create DexSymId from vertex IDs
          DexSymId from_dex_sym_id = VertexIdToDexSymId(vertex_a_id);
          DexSymId to_dex_sym_id = VertexIdToDexSymId(vertex_c_id);

          // Add or update the edge in expanded graph
          if (!expanded_graph->graph_.has_edge(vertex_a_id, vertex_c_id)) {
            expanded_graph->UpdateEdge(from_dex_sym_id, to_dex_sym_id, deps);
            new_edges_added++;
          } else {
            // Check if we need to merge dependency bits
            auto& existing_edge = expanded_graph->graph_.get_edge(vertex_a_id, vertex_c_id);
            std::bitset<3> new_deps = existing_edge.GetDeps() | deps;
            if (new_deps != existing_edge.GetDeps()) {
              expanded_graph->UpdateEdge(from_dex_sym_id, to_dex_sym_id, new_deps);
              new_edges_added++;
            }
          }
        }
      }
    }

    LOG(INFO) << "Inline dependency expansion complete: added " << new_edges_added << " new edges";
    return new_edges_added;
  }

  // Get all predecessors of a vertex in a directed graph
  static std::vector<graaf::vertex_id_t> GetPredecessors(
      const graaf::graph<InlineCallGraphNode, InlineCallGraphEdge, graaf::graph_type::DIRECTED>& graph,
      graaf::vertex_id_t vertex_id) {
    std::vector<graaf::vertex_id_t> predecessors;

    // Iterate all vertices to find those pointing to vertex_id
    for (const auto& [other_id, _] : graph.get_vertices()) {
      if (other_id == vertex_id) {
        continue;
      }
      auto neighbors = graph.get_neighbors(other_id);
      if (std::find(neighbors.begin(), neighbors.end(), vertex_id) != neighbors.end()) {
        predecessors.push_back(other_id);
      }
    }

    return predecessors;
  }

  // Convert vertex ID to DexSymId. Vertex ID is directly the DexSymId.id value.
  static DexSymId VertexIdToDexSymId(graaf::vertex_id_t vertex_id) {
    // We're just creating a DexSymId object that has the given id. The other
    // parameters are ignored since we only use the id field in graph operations.
    DexSymId result(0, false, 0);
    // Set the raw id value directly
    result.id = static_cast<uint32_t>(vertex_id);
    return result;
  }

  const DependencyGraph& original_dep_graph_;
  const InlineCallGraph& inline_graph_;
};
class InlineCallGraphBuilder {
 public:
  InlineCallGraphBuilder(InlineCallGraph* graph, const art::OatFile* oat_file, const std::vector<std::unique_ptr<const art::DexFile>>& dex_files) : graph_(*graph), oat_file_(*oat_file), dex_files_(dex_files) {}
  bool BuildGraph(std::string* error_msg) {
    size_t dex_file_count = oat_file_.GetOatDexFiles().size();
    for (size_t i = 0; i < dex_file_count; ++i) {
      const art::OatDexFile* oat_dex_file = oat_file_.GetOatDexFiles()[i];
      if (oat_dex_file == nullptr) {
        continue;
      }

      const art::DexFile* dex_file = dex_files_[i].get();
      if (dex_file->GetLocation() != oat_dex_file->GetDexFileLocation()) {
        *error_msg = "DEX location mismatch between OAT and DEX files.";
        LOG(ERROR) << *error_msg;
        return false;
      }
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
      if (dex_file->GetLocation() != oat_dex_file->GetDexFileLocation()) {
        *error_msg = "DEX location mismatch between OAT and DEX files.";
        LOG(ERROR) << *error_msg;
        return false;
      }
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
        if (!inline_info.EncodesArtMethod()) {
          continue;
        }
        ArtMethod* callee = inline_info.GetArtMethod();
        size_t dex_file_index = code_info.GetMethodInfoOf(inline_info).GetDexFileIndex(); // TODO: what if callee in bcp? And is the index right?
        // TODO: If callee is from boot classpath, skip it for no problem.
        inline_info.GetMethodInfoIndex();
        ScopedObjectAccess soa(Thread::Current());
        
        graaf::vertex_id_t vertex_id_caller = static_cast<graaf::vertex_id_t>(caller_dex_sym_id.id);
        DexSymId callee_dex_sym_id(dex_file_index, true, callee->GetDexMethodIndex());
        graaf::vertex_id_t vertex_id_callee = static_cast<graaf::vertex_id_t>(callee_dex_sym_id.id);
        graph_.AddVertexIfAbsent(callee_dex_sym_id, callee->PrettyMethod(), false);
        // If method B is inlined into method A, create edge A → B to indicate that A inlines B
        graph_.graph_.add_edge(vertex_id_caller, vertex_id_callee, InlineCallGraphEdge());
      }
    }
    return true;
  }
  private:
  InlineCallGraph& graph_;
  const art::OatFile& oat_file_;
  const std::vector<std::unique_ptr<const art::DexFile>>& dex_files_;
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

    if (dex_files_.empty() && oat_file_ == nullptr && system_dir_ == nullptr &&
        apk_file_ == nullptr) {
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

    // Handle --apk: extract DEX entry names
    std::string error_msg;
    DependencyGraph graph;
    DependencyGraphBuilder graph_builder(args_->apk_file_, &graph);
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
    if (args_->system_dir_)
      *os << "System: " << args_->system_dir_ << "\n";

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