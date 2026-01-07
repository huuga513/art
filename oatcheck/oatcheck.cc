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
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "android-base/logging.h"
#include "android-base/macros.h"
#include "android-base/stringprintf.h"
#include "android-base/strings.h"
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
#include "graaflib/graph.h"
#include "graaflib/types.h"
#include "runtime-inl.h"
#include "runtime.h"
namespace art {

class DependencyGraphNode {
 public:
  DependencyGraphNode(std::string descriptor, bool is_changed = false)
      : descriptor_(std::move(descriptor)), is_changed_(is_changed) {}

  const std::string& GetDescriptor() const { return descriptor_; }
  bool IsChanged() const { return is_changed_; }

 private:
  std::string descriptor_;
  bool is_changed_ = false;
};

enum class DependencyType {
  kStaticFieldLayout,
  kInstanceFieldLayout,
  kVirtualTableLayout,
  kDependencyTypeCount
};

class DependencyGraphEdge {
 public:
  DependencyGraphEdge(std::bitset<3> deps) : deps_(std::move(deps)) {}

  const std::bitset<3>& GetDeps() const { return deps_; }
  void SetDeps(const std::bitset<3>& deps) { deps_ = deps; }

 private:
  std::bitset<3> deps_;
};

class DependencyGraph {
 public:
  DependencyGraph() = default;
  ~DependencyGraph() = default;
  template <typename... Args>
  std::enable_if_t<std::is_constructible_v<DependencyGraphNode, Args&&...>, graaf::vertex_id_t>
  GetOrAddVertexIfAbsent(Args&&... args) {
    DependencyGraphNode node(std::forward<Args>(args)...);
    auto it = descriptor_to_vertex_id_.find(node.GetDescriptor());
    if (it != descriptor_to_vertex_id_.end()) {
      return it->second;
    }
    graaf::vertex_id_t vertex_id = graph_.add_vertex(node);
    descriptor_to_vertex_id_[node.GetDescriptor()] = vertex_id;
    return vertex_id;
  }
  void UpdateEdge(const std::string from_descriptor,
                              const std::string to_descriptor,
                              std::bitset<3> deps) {
    graaf::vertex_id_t from_vertex_id = GetOrAddVertexIfAbsent(from_descriptor);
    graaf::vertex_id_t to_vertex_id = GetOrAddVertexIfAbsent(to_descriptor);

    if (graph_.has_edge(from_vertex_id, to_vertex_id)) {
      auto& edge = graph_.get_edge(from_vertex_id, to_vertex_id);
      edge.SetDeps(edge.GetDeps()|deps);
    } else {
      graph_.add_edge(from_vertex_id, to_vertex_id, DependencyGraphEdge(deps));
    }
  }
  
  std::string Summary() const {
    return android::base::StringPrintf("vecs:%zu edges:%zu", graph_.vertex_count(), graph_.edge_count());
  }

 private:
  graaf::graph<DependencyGraphNode, DependencyGraphEdge, graaf::graph_type::DIRECTED> graph_;
  std::unordered_map<std::string, graaf::vertex_id_t> descriptor_to_vertex_id_;
  friend class DependencyGraphBuilder;
};

class DependencyGraphBuilder {
 public:
  DependencyGraphBuilder(const char* apk_file_path, DependencyGraph* graph) : apk_file_path_(apk_file_path), graph_(*graph) {
    // TODO: There is no neccessity to analysis all methods in the APK, only compiled methods in OAT.
  }
  bool BuildGraph(std::string* error_msg) {
    if (!ExtractDexFromApk(error_msg)) {
      return false;
    }
    for (const auto& dex : dex_files_) {
      if(!AnalyzeDexMethods(dex.get(), error_msg)) {
        LOG(ERROR) << "Failed to analyze DEX methods: " << *error_msg;
        return false;
      }
      if (!AnalyzeDexClasses(dex.get(), error_msg)) {
        LOG(ERROR) << "Failed to analyze DEX classes: " << *error_msg;
        return false;
      }
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
  bool AnalyzeDexClasses(const art::DexFile* dex, ATTRIBUTE_UNUSED std::string* error_msg) {
      for (art::ClassAccessor accessor : dex->GetClasses()) {
        const dex::ClassDef& class_def = dex->GetClassDef(accessor.GetClassDefIndex());
        const dex::TypeId& superclass_type_id = dex->GetTypeId(class_def.superclass_idx_);
        const char* superclass_descriptor = dex->GetTypeDescriptor(superclass_type_id);
        const char* class_descriptor = accessor.GetDescriptor();
        graph_.UpdateEdge(superclass_descriptor, class_descriptor, std::bitset<3>(7));
      }
      return true;
  }
  bool AnalyzeDexMethods(const art::DexFile* dex, ATTRIBUTE_UNUSED std::string* error_msg) {
      uint32_t count = 0;
      for (art::ClassAccessor accessor : dex->GetClasses()) {
        for (const art::ClassAccessor::Method& method : accessor.GetMethods()) {
          const art::CodeItemInstructionAccessor& code = method.GetInstructions();
          std::string method_name(dex->PrettyMethod(method.GetIndex()));
          if (count++ > 10000) return true;
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

                  graph_.UpdateEdge(class_descriptor,
                                    method_name, 
                                    std::bitset<3>(1 << static_cast<size_t>(
                                        DependencyType::kVirtualTableLayout)));
                  break;
                }
                case kDexInvokeSuper:
                case kDexInvokeDirect:
                case kDexInvokeStatic: {
                  // TODO: If invoke target is from boot classpath, just set the method vertex as changed.
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

              graph_.UpdateEdge(class_descriptor,
                                method_name,
                                std::bitset<3>(1 << static_cast<size_t>(
                                    DependencyType::kInstanceFieldLayout)));
            } else if (IsInstructionSGetOrSPut(inst->Opcode())) {
              auto field_idx = inst->VRegB();
              const dex::FieldId& field_id = dex->GetFieldId(field_idx);
              const dex::TypeId& type_id = dex->GetTypeId(field_id.class_idx_);
              const dex::StringId& name_id = dex->GetStringId(type_id.descriptor_idx_);
              const char* class_descriptor = dex->GetStringData(name_id);

              graph_.UpdateEdge(class_descriptor,
                                method_name,
                                std::bitset<3>(1 << static_cast<size_t>(
                                    DependencyType::kStaticFieldLayout)));
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
void preprocess_changed_app_classes(art::DexFile* dex) {
  for (uint32_t i = 0; i < dex->NumTypeIds(); ++i) {
    const art::dex::TypeId& type_id = dex->GetTypeId(dex::TypeIndex(i));
    const char* descriptor = dex->GetStringData(type_id.descriptor_idx_);
    changed_bcp_classes_descriptors.insert(std::string(descriptor));
  }
}
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