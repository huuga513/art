# BCP差分结果到依赖传播组件的传递方案

## BCP差分的信息输出类型

1. **Class变化**：static field layout, instance field layout, vtable layout
2. **Interface变化**：接口名-方法名-方法签名的变化

## 核心思路

BCP差分完成后，遍历BCP图中有变化的节点。对于每个变化的类A，检查应用依赖图中是否存在A节点。若存在，则将同样的变化标记到应用图中的A节点。

## 实现步骤

### 1. BCP差分生成变化表

`BcpDependencyGraphPropagator` 在 `SetInitialChanges` + `PropagateChanges` 完成后，导出变化信息：
- 变化的类名 -> 变化类型bitset (class变化)
- 变化的接口 -> {方法名-签名对} (interface变化)
- 删除的接口 -> 标记

### 2. 将变化应用到应用依赖图

遍历变化表，对每个变化的类A：

```cpp
// 伪代码
if (应用图中有节点A) {
  应用图中的节点A.changes_ = BCP图中A的变化;
}
```

对于interface变化，类似处理（标记哪些方法签名有变化）。

### 3. Main函数流程

```
1. 构建应用依赖图
2. 构建BCP依赖图 -> BCP差分 -> 生成变化表
3. 将变化应用到应用依赖图对应的节点
4. 内联扩展
5. 拓扑排序传播
6. 输出失效方法
```

## 关键点

- 变化信息通过节点descriptor匹配（而非图合并）
- 应用图中BCP节点在构建时已存在（通过DEX指令分析生成）
- interface变化需要单独处理（因为不通过layout bitset传播）