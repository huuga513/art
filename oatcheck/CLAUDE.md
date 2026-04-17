# Oatcheck Coding Guidelines

## Comments

All comments in the oatcheck project **must be written in English**. This includes:
- Source code comments (//, /* */)
- Header comments
- Documentation comments (/** */)
- TODO comments
- Git commit messages
- Documentation files (README.md, etc.)

## Rationale

English is the universal language of software development and ensures:
1. Consistency across the codebase
2. Accessibility to international contributors
3. Compatibility with existing Android Open Source Project (AOSP) conventions
4. Clear communication for the maintainers and future developers

## Examples

Good (English):
```cpp
// Compute the shortest path using Dijkstra's algorithm
template <typename Graph>
std::vector<vertex_id_t> dijkstra_shortest_path(const Graph& graph, vertex_id_t start) {
  // Implementation here
}
```

Bad (Chinese):
```cpp
// 使用 Dijkstra 算法计算最短路径
template <typename Graph>
std::vector<vertex_id_t> dijkstra_shortest_path(const Graph& graph, vertex_id_t start) {
  // 实现代码
}
```

## Exceptions

Only documentation files specifically targeting non-English audiences may use other languages, but those should be clearly marked and separated from the main codebase documentation.

## Enforcement

Please ensure all contributions follow this guideline. Code reviews will check for compliance with this rule.

## Git Repository Location

The oatcheck project is part of the ART (Android Runtime) repository, located at:

```
/ssd2/wyz/AOSP/art/
```

## Building oatcheck

To compile oatcheck, use:
```bash
cd /ssd2/wyz/AOSP && source ./setenv-lynx.sh && m oatcheck
```

## Testing oatcheck

To test oatcheck, just pick an app in /ssd2/wyz/app_oats. Each directory represents an app, base.apk is the app apk, and odex files are located in oat subdir

Use oatcheck/oatcheck_host.py to run oatcheck:
```bash
oatcheck/oatcheck_host.py [args of oatcheck]
```

For example:

a. test oatcheck with app
```
# in dir art/...
python3 oatcheck/oatcheck_host.py --apk=/ssd2/wyz/app_oats/com.tencent.mm/base.apk --oat=/ssd2/wyz/app_oats/com.tencent.mm/oat/base.odex  --origin-bcp-prefix=/ssd2/wyz/bcp_classes/15r3 --updated-bcp-prefix=/ssd2/wyz/bcp_classes/15r5
```
## Dont remove include statements of include xxx-inl.h
If mcp tells u some of xxx-inl.h never been used, dont care. It is a false positive.