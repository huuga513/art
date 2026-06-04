import matplotlib.pyplot as plt
import numpy as np

species = ("r2-r3", "r3-r5", "r2-r5")
time_counts = {
    "Build bcp graph": np.array([0.3943, 0.3967, 0.3939]),
    "Detect initial changes": np.array([0.7641, 0.7837, 0.7962]),
    "Propagate changes": np.array([1.9763, 1.9691, 1.984]),
}
width = 0.5
plt.rcParams['font.family']=['SimHei']
colors = plt.get_cmap('tab20c')(range(5))

fig, ax = plt.subplots()
bottom = np.zeros(3)

for color, (label, time_count) in zip(colors, time_counts.items()):
    p = ax.bar(species, time_count, width, label=label, bottom=bottom, color=color)
    bottom += time_count

ax.set_ylabel("Time(s)")
ax.set_ylim(0, 4.0)
ax.set_title("系统框架库分析耗时")
ax.legend(loc="upper right")

plt.tight_layout()
plt.savefig("system_framework_analysis.pdf")
plt.show()

def ploy_black_white():
    import matplotlib.pyplot as plt
    import numpy as np
    import matplotlib.patches as mpatches

    species = ("r2-r3", "r3-r5", "r2-r5")
    time_counts = {
        "Build bcp graph": np.array([0.3943, 0.3967, 0.3939]),
        "Detect initial changes": np.array([0.7641, 0.7837, 0.7962]),
        "Propagate changes": np.array([1.9763, 1.9691, 1.984]),
    }
    width = 0.5
    plt.rcParams['font.family'] = ['SimHei']
    colors = plt.get_cmap('tab20c')(range(3))  # 获取3个不同的基础颜色

    # 分别定义每种类型的填充样式
    # 样式1: 实心填充 (solid)
    # 样式2: 斜线填充 (hatch='/')，线条用颜色，空隙为背景色
    # 样式3: 点填充 (hatch='.')，点用颜色，空隙为背景色
    hatch_styles = ['', '///', '...']  # 空字符串表示实心填充

    fig, ax = plt.subplots()
    bottom = np.zeros(3)

    bars = []
    for idx, (label, time_count) in enumerate(time_counts.items()):
        # 绘制时指定hatch和颜色
        # edgecolor设置为与填充色相同，使线条与填充色一致（斜线和点会显示该颜色）
        color = colors[idx]
        p = ax.bar(species, time_count, width, label=label, bottom=bottom,
                color=color, edgecolor='white', hatch=hatch_styles[idx])
        bottom += time_count
        bars.append(p)

    ax.set_ylabel("Time(s)")
    ax.set_ylim(0, 4.0)
    ax.set_title("系统框架库分析耗时")
    ax.legend(loc="upper right")

    plt.tight_layout()
    plt.savefig("system_framework_analysis_filled.pdf")
    plt.show()