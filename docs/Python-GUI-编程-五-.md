# Python GUI 编程（五）

> 原文：[`zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa`](https://zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用 Canvas 小部件可视化数据

在数据库中记录了数月的实验数据后，现在是开始可视化和解释数据的过程。你的同事分析师们询问程序本身是否可以创建图形数据可视化，而不是将数据导出到电子表格中创建图表和图形。为了实现这一功能，你需要了解 Tkinter 的`Canvas`小部件。

在本章中，你将学习以下主题：

+   使用 Canvas 小部件进行绘图和动画

+   使用 Canvas 构建简单的折线图

+   使用 Matplotlib 集成更高级的图表和图表

# 使用 Tkinter 的 Canvas 进行绘图和动画

`Canvas`小部件无疑是 Tkinter 中最强大的小部件。它可以用于构建从自定义小部件和视图到完整用户界面的任何内容。顾名思义，`Canvas`是一个可以绘制图形和图像的空白区域。

可以像创建其他小部件一样创建`Canvas`对象：

```py
root = tk.Tk()
canvas = tk.Canvas(root, width=1024, height=768)
canvas.pack()
```

`Canvas`接受通常的小部件配置参数，以及用于设置其大小的`width`和`height`。创建后，我们可以使用其许多`create_()`方法开始向`canvas`添加项目。

例如，我们可以使用以下代码添加一个矩形：

```py
canvas.create_rectangle(100, 100, 200, 200, fill='orange')
```

前四个参数是左上角和右下角的坐标，以像素为单位，从画布的左上角开始。每个`create_()`方法都是以定义形状的坐标开始的。`fill`选项指定了对象内部的颜色。

坐标也可以指定为元组对，如下所示：

```py
canvas.create_rectangle((600, 100), (700, 200), fill='#FF8800')
```

尽管这是更多的字符，但它显着提高了可读性。还要注意，就像 Tkinter 中的其他颜色一样，我们可以使用名称或十六进制代码。

我们还可以创建椭圆，如下所示：

```py
canvas.create_oval((350, 250), (450, 350), fill='blue')
```

椭圆和矩形一样，需要其**边界框**的左上角和右下角的坐标。边界框是包含项目的最小矩形，因此在这个椭圆的情况下，你可以想象一个圆在一个角坐标为`(350, 250)`和`(450, 350)`的正方形内。

我们可以使用`create_line()`创建线，如下所示：

```py
canvas.create_line((100, 400), (400, 500),
    (700, 400), (100, 400), width=5, fill='red')
```

行可以由任意数量的点组成，Tkinter 将连接这些点。我们已经指定了线的宽度以及颜色（使用`fill`参数）。额外的参数可以控制角和端点的形状，线两端箭头的存在和样式，线条是否虚线，以及线条是直线还是曲线。

类似地，我们可以创建多边形，如下所示：

```py
canvas.create_polygon((400, 150), (350,  300), (450, 300),
    fill='blue', smooth=True)
```

这与创建线条类似，只是 Tkinter 将最后一个点连接回第一个点，并填充内部。将`smooth`设置为`True`会使用贝塞尔曲线使角变圆。

除了简单的形状之外，我们还可以按照以下方式在`canvas`对象上放置文本或图像：

```py
canvas.create_text((400, 600), text='Smile!',
    fill='cyan', font='TkDefaultFont 64')
smiley = tk.PhotoImage(file='smile.gif')
image_item = canvas.create_image((400, 300), image=smiley)
```

任何`create_()`方法的返回值都是一个字符串，它在`Canvas`对象的上下文中唯一标识该项。我们可以使用该标识字符串在创建后对该项进行操作。

例如，我们可以这样绑定事件：

```py
canvas.tag_bind(image_item, '<Button-1>', lambda e: canvas.delete(image_item))
```

在这里，我们使用`tag_bind`方法将鼠标左键单击我们的图像对象绑定到画布的`delete()`方法，该方法（给定一个项目标识符）会删除该项目。

# 为 Canvas 对象添加动画

Tkinter 的`Canvas`小部件没有内置的动画框架，但我们仍然可以通过将其`move()`方法与对事件队列的理解相结合来创建简单的动画。

为了演示这一点，我们将创建一个虫子赛跑模拟器，其中两只虫子（用彩色圆圈表示）将杂乱地向屏幕的另一侧的终点线赛跑。就像真正的虫子一样，它们不会意识到自己在比赛，会随机移动，赢家是哪只虫子碰巧先到达终点线。

首先，打开一个新的 Python 文件，并从以下基本样板开始：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
```

```py
        super().__init__()

App().mainloop()
```

# 创建我们的对象

让我们创建用于游戏的对象：

1.  在`App.__init__()`中，我们将简单地创建我们的`canvas`对象，并使用`pack()`添加它：

```py
self.canvas = tk.Canvas(self, background='black')
self.canvas.pack(fill='both', expand=1)
```

1.  接下来，我们将创建一个`setup()`方法如下：

```py
   def setup(self):
       self.canvas.left = 0
       self.canvas.top = 0
       self.canvas.right = self.canvas.winfo_width()
       self.canvas.bottom = self.canvas.winfo_height()
       self.canvas.center_x = self.canvas.right // 2
       self.canvas.center_y = self.canvas.bottom // 2

       self.finish_line = self.canvas.create_rectangle(
           (self.canvas.right - 50, 0),
           (self.canvas.right, self.canvas.bottom),
           fill='yellow', stipple='gray50')
```

在上述代码片段中，`setup()`首先通过计算`canvas`对象上的一些相对位置，并将它们保存为实例属性，这将简化在`canvas`对象上放置对象。终点线是窗口右边的一个矩形，使用`stipple`参数指定一个位图，该位图将覆盖实色以赋予其一些纹理；在这种情况下，`gray50`是一个内置的位图，交替黑色和透明像素。

1.  在`__init__()`的末尾添加一个对`setup()`的调用如下：

```py
self.after(200, self.setup)
```

因为`setup()`依赖于`canvas`对象的`width`和`height`值，我们需要确保在操作系统的窗口管理器绘制和调整窗口大小之前不调用它。最简单的方法是将调用延迟几百毫秒。

1.  接下来，我们需要创建我们的玩家。让我们创建一个类来表示他们如下：

```py
class Racer:

    def __init__(self, canvas, color):
        self.canvas = canvas
        self.name = "{} player".format(color.title())
        size = 50
        self.id = canvas.create_oval(
            (canvas.left, canvas.center_y),
            (canvas.left + size, canvas.center_y + size),
            fill=color)
```

`Racer`类将使用对`canvas`的引用和一个`color`字符串创建，并从中派生其颜色和名称。我们将最初在屏幕的中间左侧绘制赛车，并使其大小为`50`像素。最后，我们将其项目 ID 字符串的引用保存在`self.id`中。

1.  现在，在`App.setup()`中，我们将通过执行以下代码创建两个赛车：

```py
               self.racers = [
                   Racer(self.canvas, 'red'),
                   Racer(self.canvas, 'green')]
```

1.  到目前为止，我们游戏中的所有对象都已设置好。运行程序，你应该能看到右侧的黄色点线终点线和左侧的绿色圆圈（红色圆圈将被隐藏在绿色下面）。

# 动画赛车

为了使我们的赛车动画化，我们将使用`Canvas.move()`方法。`move()`接受一个项目 ID，一定数量的`x`像素和一定数量的`y`像素，并将项目移动该数量。通过使用`random.randint()`和一些简单的逻辑，我们可以生成一系列移动，将每个赛车发送到一条蜿蜒的路径朝着终点线。

一个简单的实现可能如下所示：

```py
def move_racer(self):
    x = randint(0, 100)
    y = randint(-50, 50)
    t = randint(500, 2000)
    self.canvas.after(t, self.canvas.move, self.id, x, y)
    if self.canvas.bbox(self.id)[0] < self.canvas.right:
        self.canvas.after(t, self.move_racer)
```

然而，这并不是我们真正想要的；问题在于`move()`是瞬间发生的，导致错误跳跃到屏幕的另一侧；我们希望我们的移动在一段时间内平稳进行。

为了实现这一点，我们将采取以下方法：

1.  计算一系列线性移动，每个移动都有一个随机的增量`x`，增量`y`和`时间`，可以到达终点线

1.  将每个移动分解为由时间分成的一定间隔的步骤

1.  将每个移动的每一步添加到队列中

1.  在我们的常规间隔中，从队列中提取下一步并传递给`move()`

让我们首先定义我们的帧间隔并创建我们的动画队列：

```py
from queue import Queue
...
class Racer:
    FRAME_RES = 50

    def __init__(...):
        ...
        self.animation_queue = Queue()
```

`FRAME_RES`（帧分辨率的缩写）定义了每个`Canvas.move()`调用之间的毫秒数。`50`毫秒给我们 20 帧每秒，应该足够平滑移动。

现在创建一个方法来绘制到终点线的路径：

```py
    def plot_course(self):
        start_x = self.canvas.left
        start_y = self.canvas.center_y
        total_dx, total_dy = (0, 0)

        while start_x + total_dx < self.canvas.right:
            dx = randint(0, 100)
            dy = randint(-50, 50)
            target_y = start_y + total_dy + dy
            if not (self.canvas.top < target_y < self.canvas.bottom):
                dy = -dy
            time = randint(500, 2000)
            self.queue_move(dx, dy, time)
            total_dx += dx
            total_dy += dy
```

这个方法通过生成随机的`x`和`y`移动，从`canvas`的左中心绘制一条到右侧的路径，直到总`x`大于`canvas`对象的宽度。`x`的变化总是正的，使我们的错误向着终点线移动，但`y`的变化可以是正的也可以是负的。为了保持我们的错误在屏幕上，我们通过否定任何会使玩家超出画布顶部或底部边界的`y`变化来限制总的`y`移动。

除了`dx`和`dy`，我们还生成了移动所需的随机`time`数量，介于半秒和两秒之间，并将生成的值发送到`queue_move()`方法。

`queue_move()`命令将需要将大移动分解为描述在一个`FRAME_RES`间隔中应该发生多少移动的单个帧。为此，我们需要一个**partition 函数**：一个数学函数，将整数`n`分解为大致相等的整数`k`。例如，如果我们想将-10 分成四部分，我们的函数应返回一个类似于[-3, -3, -2, -2]的列表。

将`partition()`创建为`Racer`的静态方法：

```py
    @staticmethod
    def partition(n, k):
        """Return a list of k integers that sum to n"""
        if n == 0:
            return [0] * k
```

我们从简单的情况开始：当`n`为`0`时，返回一个由`k`个零组成的列表。

代码的其余部分如下所示：

```py
        base_step = int(n / k)
        parts = [base_step] * k
        for i in range(n % k):
                parts[i] += n / abs(n)
        return parts
```

首先，我们创建一个长度为`k`的列表，由`base_step`组成，即`n`除以`k`的整数部分。我们在这里使用`int()`的转换而不是地板除法，因为它在负数时表现更合适。接下来，我们需要尽可能均匀地在列表中分配余数。为了实现这一点，我们在部分列表的前`n % k`项中添加`1`或`-1`（取决于余数的符号）。

使用我们的例子`n = -10`和`k = 4`，按照这里的数学：

+   -10 / 4 = -2.5，截断为-2。

+   所以我们有一个列表：[-2, -2, -2, -2]。

+   -10 % 4 = 2，所以我们在列表的前两个项目中添加-1（即-10 / 10）。

+   我们得到了一个答案：[-3, -3, -2, -2]。完美！

现在我们可以编写`queue_move()`：

```py
    def queue_move(self, dx, dy, time):
        num_steps = time // self.FRAME_RES
        steps = zip(
            self.partition(dx, num_steps),
            self.partition(dy, num_steps))

        for step in steps:
            self.animation_queue.put(step)
```

我们首先通过使用地板除法将时间除以`FRAME_RES`来确定此移动中的步数。我们通过将`dx`和`dy`分别传递给我们的`partition()`方法来创建`x`移动列表和`y`移动列表。这两个列表与`zip`结合形成一个`(dx, dy)`对的单个列表，然后添加到动画队列中。

为了使动画真正发生，我们将编写一个`animate()`方法：

```py
    def animate(self):
        if not self.animation_queue.empty():
            nextmove = self.animation_queue.get()
            self.canvas.move(self.id, *nextmove)
        self.canvas.after(self.FRAME_RES, self.animate)
```

`animate()`方法检查队列是否有移动。如果有，将调用`canvas.move()`，并传递赛车的 ID 和需要进行的移动。最后，`animate()`方法被安排在`FRAME_RES`毫秒后再次运行。

动画赛车的最后一步是在`__init__()`的末尾调用`self.plot_course()`和`self.animate()`。如果现在运行游戏，你的两个点应该从左到右在屏幕上漫游。但目前还没有人获胜！

# 检测和处理获胜条件

为了检测获胜条件，我们将定期检查赛车是否与终点线项目重叠。当其中一个重叠时，我们将宣布它为获胜者，并提供再玩一次的选项。

物品之间的碰撞检测在 Tkinter 的 Canvas 小部件中有些尴尬。我们必须将一组边界框坐标传递给`find_overlapping()`，它会返回与边界框重叠的项目标识的元组。

让我们为我们的`Racer`类创建一个`overlapping()`方法：

```py
    def overlapping(self):
        bbox = self.canvas.bbox(self.id)
        overlappers = self.canvas.find_overlapping(*bbox)
        return [x for x in overlappers if x!=self.id]
```

这个方法使用画布的`bbox()`方法检索`Racer`项目的边界框。然后使用`find_overlapping()`获取与此边界框重叠的项目的元组。接下来，我们将过滤此元组，以删除`Racer`项目的 ID，有效地返回与`Racer`类重叠的项目列表。

回到我们的`App()`方法，我们将创建一个`check_for_winner()`方法：

```py
    def check_for_winner(self):
        for racer in self.racers:
            if self.finish_line in racer.overlapping():
                self.declare_winner(racer)
                return
        self.after(Racer.FRAME_RES, self.check_for_winner)
```

这个方法迭代我们的赛车列表，并检查赛车的`overlapping()`方法返回的列表中是否有`finish_line` ID。如果有，`racer`就到达了终点线，并将被宣布为获胜者。

如果没有宣布获胜者，我们将在`Racer.FRAME_RES`毫秒后再次安排检查运行。

我们在`declare_winner()`方法中处理获胜条件：

```py
    def declare_winner(self, racer):
        wintext = self.canvas.create_text(
            (self.canvas.center_x, self.canvas.center_y),
            text='{} wins!\nClick to play again.'.format(racer.name),
            fill='white',
            font='TkDefaultFont 32',
            activefill='violet')
        self.canvas.tag_bind(wintext, '<Button-1>', self.reset)
```

在这个方法中，我们刚刚创建了一个`text`项目，在`canvas`的中心声明`racer.name`为获胜者。`activefill`参数使颜色在鼠标悬停在其上时变为紫色，向用户指示此文本是可点击的。

当点击该文本时，它调用`reset()`方法：

```py
    def reset(self, *args):
        for item in self.canvas.find_all():
            self.canvas.delete(item)
        self.setup()
```

`reset()`方法需要清除画布，因此它使用`find_all()`方法检索所有项目标识符的列表，然后对每个项目调用`delete()`。最后，我们调用`setup()`来重置游戏。

如您在下面的截图中所见，游戏现在已经完成：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/5199652b-2987-472d-b74e-4d00c79ddc46.png)

虽然不是很简单，但 Tkinter 中的动画可以通过一些仔细的规划和一点数学来提供流畅和令人满意的结果。

不过，够玩游戏了；让我们回到实验室，看看如何使用 Tkinter 的`Canvas`小部件来可视化数据。

# 在画布上创建简单的图表

我们想要生成的第一个图形是一个简单的折线图，显示我们植物随时间的生长情况。每个实验室的气候条件各不相同，我们想要看到这些条件如何影响所有植物的生长，因此图表将显示每个实验室的一条线，显示实验期间实验室中所有地块的中位高度测量的平均值。

我们将首先创建一个模型方法来返回原始数据，然后创建一个基于`Canvas`的折线图视图，最后创建一个应用程序回调来获取数据并将其发送到图表视图。

# 创建模型方法

假设我们有一个 SQL 查询，通过从`plot_checks`表中的最旧日期中减去其日期来确定地块检查的天数，然后在给定实验室和给定日期上拉取`lab_id`和所有植物的`median_height`的平均值。

我们将在一个名为`get_growth_by_lab()`的新`SQLModel`方法中运行此查询：

```py
    def get_growth_by_lab(self):
        query = (
            'SELECT date - (SELECT min(date) FROM plot_checks) AS day, '
            'lab_id, avg(median_height) AS avg_height FROM plot_checks '
            'GROUP BY date, lab_id ORDER BY day, lab_id;')
        return self.query(query)
```

我们将得到一个数据表，看起来像这样：

| **Day** | **Lab ID** | **Average height** |
| --- | --- | --- |
| 0 | A | 7.4198750000000000 |
| 0 | B | 7.3320000000000000 |
| 0 | C | 7.5377500000000000 |
| 0 | D | 8.4633750000000000 |
| 0 | E | 7.8530000000000000 |
| 1 | A | 6.7266250000000000 |
| 1 | B | 6.8503750000000000 |  |

我们将使用这些数据来构建我们的图表。

# 创建图形视图

转到`views.py`，在那里我们将创建`LineChartView`类：

```py
class LineChartView(tk.Canvas):

    margin = 20

    def __init__(self, parent, chart_width, chart_height,
                 x_axis, y_axis, x_max, y_max):
        self.max_x = max_x
        self.max_y = max_y
        self.chart_width = chart_width
        self.chart_height = chart_height
```

`LineChartView`是`Canvas`的子类，因此我们将能够直接在其上绘制项目。我们将接受父小部件、图表部分的高度和宽度、`x`和`y`轴的标签作为参数，并显示`x`和`y`的最大值。我们将保存图表的尺寸和最大值以供以后使用，并将边距宽度设置为 20 像素的类属性。

让我们开始设置这个`Canvas`：

```py
        view_width = chart_width + 2 * self.margin
        view_height = chart_height + 2 * self.margin
        super().__init__(
            parent, width=view_width,
            height=view_height, background='lightgrey')
```

通过将边距添加到两侧来计算视图的`width`和`height`值，然后使用它们调用超类`__init__()`，同时将背景设置为`lightgrey`。我们还将保存图表的`width`和`height`作为实例属性。

接下来，让我们绘制轴：

```py
        self.origin = (self.margin, view_height - self.margin)
        self.create_line(
            self.origin, (self.margin, self.margin), width=2)
        self.create_line(
            self.origin,
            (view_width - self.margin,
             view_height - self.margin))
```

我们的图表原点将距离左下角`self.margin`像素，并且我们将绘制`x`和`y`轴，作为简单的黑色线条从原点向左和向上延伸到图表的边缘。

接下来，我们将标记轴：

```py
        self.create_text(
            (view_width // 2, view_height - self.margin),
            text=x_axis, anchor='n')
        # angle requires tkinter 8.6 -- macOS users take note!
        self.create_text(
            (self.margin, view_height // 2),
            text=y_axis, angle=90, anchor='s')
```

在这里，我们创建了设置为`x`和`y`轴标签的`text`项目。这里使用了一些新的参数：`anchor`设置文本边界框的哪一侧与提供的坐标相连，`angle`将文本对象旋转给定的角度。请注意，`angle`是 Tkinter 8.6 的一个特性，因此对于 macOS 用户可能会有问题。另外，请注意，我们将旋转的文本的`anchor`设置为 south；即使它被旋转，基本方向仍然指的是未旋转的边，因此 south 始终是文本的底部，就像正常打印的那样。

最后，我们需要创建一个包含实际图表的第二个`Canvas`：

```py
        self.chart = tk.Canvas(
            self, width=chart_width, height=chart_height,
            background='white')
        self.create_window(
            self.origin, window=self.chart, anchor='sw')
```

虽然我们可以使用`pack()`或`grid()`等几何管理器在`canvas`上放置小部件，但`create_window()`方法将小部件作为`Canvas`项目放置在`Canvas`上，使用坐标。我们将图表的左下角锚定到我们图表的原点。

随着这些部分的就位，我们现在将创建一个在图表上绘制数据的方法：

```py
    def plot_line(self, data, color):
        x_scale = self.chart_width / self.max_x
        y_scale = self.chart_height / self.max_y

        coords = [(round(x * x_scale),
            self.chart_height - round(y * y_scale))
            for x, y in data]

        self.chart.create_line(*coords, width=2, fill=color)
```

在`plot_line()`中，我们首先必须将原始数据转换为可以绘制的坐标。我们需要缩放我们的`数据`点，使它们的范围从图表对象的高度和宽度为`0`。我们的方法通过将图表尺寸除以`x`和`y`的最大值来计算`x`和`y`的比例（即每个单位`x`或`y`有多少像素）。然后我们可以通过使用列表推导将每个数据点乘以比例值来转换我们的数据。

此外，数据通常是以左下角为原点绘制的，但坐标是从左上角开始测量的，因此我们需要翻转`y`坐标；这也是我们的列表推导中所做的，通过从图表高度中减去新的`y`值来完成。现在可以将这些坐标传递给`create_line()`，并与合理的`宽度`和调用者传入的`颜色`参数一起传递。

我们需要的最后一件事是一个**图例**，告诉用户图表上的每种颜色代表什么。没有图例，这个图表将毫无意义。

让我们创建一个`draw_legend()`方法：

```py
    def draw_legend(self, mapping):
        y = self.margin
        x = round(self.margin * 1.5) + self.chart_width
        for label, color in mapping.items():
              self.create_text((x, y), text=label, fill=color, 
              anchor='w')
              y += 20
```

我们的方法接受一个将标签映射到颜色的字典，这将由应用程序提供。对于每一个，我们只需绘制一个包含`标签`文本和相关`填充`颜色的文本项。由于我们知道我们的标签会很短（只有一个字符），我们可以只把它放在边缘。

# 更新应用程序

在`Application`类中，创建一个新方法来显示我们的图表：

```py
    def show_growth_chart(self):
        data = self.data_model.get_growth_by_lab()
        max_x = max([x['day'] for x in data])
        max_y = max([x['avg_height'] for x in data])
```

首要任务是从我们的`get_growth_by_lab()`方法中获取数据，并计算`x`和`y`轴的最大值。我们通过使用列表推导将值提取到列表中，并在其上调用内置的`max()`函数来完成这一点。

接下来，我们将构建一个小部件来容纳我们的`LineChartView`对象：

```py
        popup = tk.Toplevel()
        chart = v.LineChartView(popup, 600, 300, 'day',
                                'centimeters', max_x, max_y)
        chart.pack(fill='both', expand=1)
```

在这种情况下，我们使用`Toplevel`小部件，它在我们的主应用程序窗口之外创建一个新窗口。然后我们创建了`LineChartView`，它是`600`乘`300`像素，带有*x*轴和*y*轴标签，并将其添加到`Toplevel`中使用`pack()`。

接下来，我们将为每个实验室分配颜色并绘制`图例`：

```py
        legend = {'A': 'green', 'B': 'blue', 'C': 'cyan',
                  'D': 'yellow', 'E': 'purple'}
        chart.draw_legend(legend)
```

最后要做的是绘制实际的线：

```py
        for lab, color in legend.items():
            dataxy = [(x['day'], x['avg_height'])
                for x in data
                if x['lab_id'] == lab]
            chart.plot_line(dataxy, color)
```

请记住，我们的数据包含所有实验室的值，因此我们正在`图例`中迭代实验室，并使用列表推导来提取该实验室的数据。然后我们的`plot_line()`方法完成其余工作。

完成此方法后，将其添加到`callbacks`字典中，并为每个平台的工具菜单添加一个菜单项。

当您调用您的函数时，您应该看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/db64ecf3-2169-4ea1-ac5c-954a960ba237.png)没有一些示例数据，图表看起来不会很好。除非您只是喜欢进行数据输入，否则在`sql`目录中有一个加载示例数据的脚本。

# 使用 Matplotlib 和 Tkinter 创建高级图表

我们的折线图很漂亮，但要使其完全功能，仍需要相当多的工作：它缺少比例、网格线和其他功能，这些功能将使它成为一个完全有用的图表。

我们可以花很多时间使它更完整，但在我们的 Tkinter 应用程序中获得更令人满意的图表和图形的更快方法是**Matplotlib**。

Matplotlib 是一个第三方库，用于生成各种类型的专业质量、交互式图表。这是一个庞大的库，有许多附加组件，我们不会涵盖其实际用法的大部分内容，但我们应该看一下如何将 Matplotlib 集成到 Tkinter 应用程序中。为此，我们将创建一个气泡图，显示每个地块的产量与`湿度`和`温度`的关系。

您应该能够使用`pip install --user matplotlib`命令使用`pip`安装`matplotlib`。有关安装的完整说明，请参阅[`matplotlib.org/users/installing.html.`](https://matplotlib.org/users/installing.html)

# 数据模型方法

在我们制作图表之前，我们需要一个`SQLModel`方法来提取数据：

```py
    def get_yield_by_plot(self):
        query = (
            'SELECT lab_id, plot, seed_sample, MAX(fruit) AS yield, '
            'AVG(humidity) AS avg_humidity, '
            'AVG(temperature) AS avg_temperature '
            'FROM plot_checks WHERE NOT equipment_fault '
            'GROUP BY lab_id, plot, seed_sample')
        return self.query(query)
```

此图表的目的是找到每个种子样本的`温度`和`湿度`的最佳点。因此，我们需要每个`plot`的一行，其中包括最大的`fruit`测量值，`plot`列处的平均湿度和温度，以及`seed_sample`。由于我们不想要任何错误的数据，我们将过滤掉具有`Equipment` `Fault`的行。

# 创建气泡图表视图

要将 MatplotLib 集成到 Tkinter 应用程序中，我们需要进行几次导入。

第一个是`matplotlib`本身：

```py
import matplotlib
matplotlib.use('TkAgg')
```

在“导入”部分运行代码可能看起来很奇怪，甚至您的编辑器可能会对此进行投诉。但在我们从`matplotlib`导入任何其他内容之前，我们需要告诉它应该使用哪个后端。在这种情况下，我们想要使用`TkAgg`后端，这是专为集成到 Tkinter 中而设计的。

现在我们可以从`matplotlib`中再引入一些内容：

```py
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import (
    FigureCanvasTkAgg, NavigationToolbar2TkAgg)
```

`Figure`类表示`matplotlib`图表可以绘制的基本绘图区域。`FigureCanvasTkAgg`类是`Figure`和 Tkinter`Canvas`之间的接口，`NavigationToolbar2TkAgg`允许我们在图表上放置一个预制的`Figure`工具栏。

为了看看这些如何配合，让我们在`views.py`中启动我们的`YieldChartView`类：

```py
class YieldChartView(tk.Frame):
    def __init__(self, parent, x_axis, y_axis, title):
        super().__init__(parent)
        self.figure = Figure(figsize=(6, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
```

在调用`super().__init__()`创建`Frame`对象之后，我们创建一个`Figure`对象来保存我们的图表。`Figure`对象不是以像素为单位的大小，而是以**英寸**和**每英寸点数**（**dpi**）设置为单位（在这种情况下，得到的是一个 600x400 像素的`Figure`）。接下来，我们创建一个`FigureCanvasTkAgg`对象，将我们的`Figure`对象与 Tkinter`Canvas`连接起来。`FigureCanvasTkAgg`对象本身不是`Canvas`对象或子类，但它有一个`Canvas`对象，我们可以将其放置在我们的应用程序中。

接下来，我们将工具栏和`pack()`添加到我们的`FigureCanvasTkAgg`对象中：

```py
        self.toolbar = NavigationToolbar2TkAgg(self.canvas, self)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
```

我们的工具栏被传递给了我们的`FigureCanvasTkAgg`对象和根窗口（在这种情况下是`self`），将其附加到我们的图表和它的画布上。要将`FigureCanvasTkAgg`对象放在我们的`Frame`对象上，我们需要调用`get_tk_widget()`来检索其 Tkinter`Canvas`小部件，然后我们可以使用`pack()`和`grid()`按需要对其进行打包或网格化。

下一步是设置轴：

```py
        self.axes = self.figure.add_subplot(1, 1, 1)
        self.axes.set_xlabel(x_axis)
        self.axes.set_ylabel(y_axis)
        self.axes.set_title(title)
```

在 Matplotlib 中，`axes`对象表示可以在其上绘制数据的单个`x`和`y`轴集，使用`add_subplot()`方法创建。传递给`add_subplot()`的三个整数建立了这是一个子图中一行中的第一个`axes`集。我们的图表可能包含多个以表格形式排列的子图，但我们只需要一个。创建后，我们设置`axes`对象上的标签。

要创建气泡图表，我们将使用 Matplotlib 的**散点图**功能，但使用每个点的大小来指示水果产量。我们还将对点进行颜色编码以指示种子样本。

让我们实现一个绘制散点图的方法：

```py
    def draw_scatter(self, data, color, label):
        x, y, s = zip(*data)
        s = [(x ** 2)//2 for x in s]
        scatter = self.axes.scatter(
            x, y, s, c=color, label=label, alpha=0.5)
```

传入的数据应该包含每条记录的三列，并且我们将这些分解为包含`x`、`y`和`size`值的三个单独的列表。接下来，我们将放大大小值之间的差异，使它们更加明显，方法是将每个值平方然后除以一半。这并不是绝对必要的，但在差异相对较小时，它有助于使图表更易读。

最后，我们通过调用`scatter()`将数据绘制到`axes`对象上，同时传递`color`和`label`值给点，并使用`alpha`参数使它们半透明。

`zip(*data)`是一个 Python 习语，用于将 n 长度元组的列表分解为值的 n 个列表，本质上是`zip(x, y, s)`的反向操作。

为了为我们的`axes`对象绘制图例，我们需要两样东西：我们的`scatter`对象的列表和它们的标签列表。为了获得这些，我们将不得不在`__init__()`中创建一些空列表，并在每次调用`draw_scatter()`时进行追加。

在`__init__()`中，添加一些空列表：

```py
        self.scatters = []
        self.scatter_labels = []
```

现在，在`draw_scatter()`的末尾，追加列表并更新`legend()`方法：

```py
        self.scatters.append(scatter)
        self.scatter_labels.append(label)
        self.axes.legend(self.scatters, self.scatter_labels)
```

我们可以反复调用`legend()`，它会简单地销毁并重新绘制图例。

# 应用程序方法

回到`Application`，让我们创建一个显示产量数据的方法。

首先创建一个`Toplevel`方法并添加我们的图表视图：

```py
        popup = tk.Toplevel()
        chart = v.YieldChartView(popup,
            'Average plot humidity', 'Average Plot temperature',
            'Yield as a product of humidity and temperature')
        chart.pack(fill='both', expand=True)
```

现在让我们为我们的散点图设置数据：

```py
        data = self.data_model.get_yield_by_plot()
        seed_colors = {'AXM477': 'red', 'AXM478': 'yellow',
            'AXM479': 'green', 'AXM480': 'blue'}
```

我们从数据模型中检索了产量`data`，并创建了一个将保存我们想要为每个种子样本使用的颜色的字典。

现在我们只需要遍历种子样本并绘制散点图：

```py
        for seed, color in seed_colors.items():
            seed_data = [
                (x['avg_humidity'], x['avg_temperature'], x['yield'])
                for x in data if x['seed_sample'] == seed]
            chart.draw_dots(seed_data, color, seed)
```

再次，我们使用列表推导式格式化和过滤我们的数据，为`x`提供平均湿度，为`y`提供平均温度，为`s`提供产量。

将该方法添加到`callbacks`字典中，并在生长图选项下方创建一个菜单项。

您的气泡图应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/335e2505-6f35-4708-aaa0-5a5e1948112e.png)

请利用导航工具栏玩一下这个图表，注意你可以缩放和平移，调整图表的大小，并保存图像。这些都是 Matplotlib 自动提供的强大工具。

# 总结

在本章中，您了解了 Tkinter 的图形能力。您学会了如何在 Tkinter 的`Canvas`小部件上绘制和动画图形，以及如何利用这些能力来可视化数据。您还学会了如何将 Matplotlib 图形集成到您的应用程序中，并通过将 SQL 查询连接到我们的图表视图，在我们的应用程序中实现了两个图表。


# 第十三章：使用 Qt 组件创建用户界面

在本章中，我们将学习使用以下小部件：

+   显示欢迎消息

+   使用单选按钮小部件

+   分组单选按钮

+   以复选框形式显示选项

+   显示两组复选框

# 介绍

我们将学习使用 Qt 工具包创建 GUI 应用程序。Qt 工具包，简称 Qt，是由 Trolltech 开发的跨平台应用程序和 UI 框架，用于开发 GUI 应用程序。它可以在多个平台上运行，包括 Windows、macOS X、Linux 和其他 UNIX 平台。它也被称为小部件工具包，因为它提供了按钮、标签、文本框、推按钮和列表框等小部件，这些小部件是设计 GUI 所必需的。它包括一组跨平台的类、集成工具和跨平台 IDE。为了创建实时应用程序，我们将使用 Python 绑定的 Qt 工具包，称为 PyQt5。

# PyQt

PyQt 是一个用于跨平台应用程序框架的 Python 绑定集合，结合了 Qt 和 Python 的所有优势。使用 PyQt，您可以在 Python 代码中包含 Qt 库，从而能够用 Python 编写 GUI 应用程序。换句话说，PyQt 允许您通过 Python 代码访问 Qt 提供的所有功能。由于 PyQt 依赖于 Qt 库来运行，因此在安装 PyQt 时，所需版本的 Qt 也会自动安装在您的计算机上。

GUI 应用程序可能包括一个带有多个对话框的主窗口，或者只包括一个对话框。一个小型 GUI 应用程序通常至少包括一个对话框。对话框应用程序包含按钮。它不包含菜单栏、工具栏、状态栏或中央小部件，而主窗口应用程序通常包括所有这些。

对话框有以下两种类型：

+   **模态**：这种对话框会阻止用户与应用程序的其他部分进行交互。对话框是用户可以与之交互的应用程序的唯一部分。在对话框关闭之前，无法访问应用程序的其他部分。

+   **非模态**：这种对话框与模态对话框相反。当非模态对话框处于活动状态时，用户可以自由地与对话框和应用程序的其他部分进行交互。

# 创建 GUI 应用程序的方式

有以下两种方式编写 GUI 应用程序：

+   使用简单文本编辑器从头开始

+   使用 Qt Designer，一个可视化设计工具，可以快速使用拖放功能创建用户界面

您将使用 Qt Designer 在 PyQt 中开发 GUI 应用程序，因为这是一种快速简便的设计用户界面的方法，无需编写一行代码。因此，双击桌面上的图标启动 Qt Designer。

打开时，Qt Designer 会要求您为新应用程序选择模板，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4c0a403e-cd4c-427f-93aa-fcfdc443eefd.png)

Qt Designer 提供了适用于不同类型应用程序的多个模板。您可以选择其中任何一个模板，然后单击“创建”按钮。

Qt Designer 为新应用程序提供以下预定义模板：

+   带有底部按钮的对话框：此模板在右下角创建一个带有确定和取消按钮的表单。

+   带有右侧按钮的对话框：此模板在右上角创建一个带有确定和取消按钮的表单。

+   没有按钮的对话框：此模板创建一个空表单，您可以在其中放置小部件。对话框的超类是`QDialog`。

+   主窗口：此模板提供一个带有菜单栏和工具栏的主应用程序窗口，如果不需要可以删除。

+   小部件：此模板创建一个表单，其超类是`QWidget`而不是`QDialog`。

每个 GUI 应用程序都有一个顶级小部件，其余的小部件称为其子级。顶级小部件可以是`QDialog`、`QWidget`或`QMainWindow`，具体取决于您需要的模板。如果要基于对话框模板创建应用程序，则顶级小部件或您继承的第一个类将是`QDialog`。类似地，要基于主窗口模板创建应用程序，顶级小部件将是`QMainWindow`，要基于窗口小部件模板创建应用程序，您需要继承`QWidget`类。如前所述，用于用户界面的其余小部件称为这些类的子小部件。

Qt Designer 在顶部显示菜单栏和工具栏。它在左侧显示一个包含各种小部件的窗口小部件框，用于开发应用程序，分组显示。您只需从表单中拖放您想要的小部件即可。您可以在布局中排列小部件，设置它们的外观，提供初始属性，并将它们的信号连接到插槽。

# 显示欢迎消息

在这个示例中，用户将被提示输入他/她的名字，然后点击一个按钮。点击按钮后，将出现一个欢迎消息，“你好”，后面跟着用户输入的名字。对于这个示例，我们需要使用三个小部件，标签、行编辑和按钮。让我们逐个了解这些小部件。

# 理解标签小部件

标签小部件是`QLabel`类的一个实例，用于显示消息和图像。因为标签小部件只是显示计算结果，不接受任何输入，所以它们只是用于在屏幕上提供信息。

# 方法

以下是`QLabel`类提供的方法：

+   `setText()`: 该方法将文本分配给标签小部件

+   `setPixmap()`: 该方法将`pixmap`，`QPixmap`类的一个实例，分配给标签小部件

+   `setNum()`: 该方法将整数或双精度值分配给标签小部件

+   `clear()`: 该方法清除标签小部件中的文本

`QLabel`的默认文本是 TextLabel。也就是说，当您通过拖放标签小部件将`QLabel`类添加到表单时，它将显示 TextLabel。除了使用`setText()`，您还可以通过在属性编辑器窗口中设置其文本属性来为选定的`QLabel`对象分配文本。

# 理解行编辑小部件

行编辑小部件通常用于输入单行数据。行编辑小部件是`QLineEdit`类的一个实例，您不仅可以输入，还可以编辑数据。除了输入数据，您还可以在行编辑小部件中撤消、重做、剪切和粘贴数据。

# 方法

以下是`QLineEdit`类提供的方法：

+   `setEchoMode()`: 它设置行编辑小部件的回显模式。也就是说，它确定如何显示行编辑小部件的内容。可用选项如下：

+   `Normal`: 这是默认模式，它以输入的方式显示字符

+   `NoEcho`: 它关闭了行编辑的回显，也就是说，它不显示任何内容

+   `Password`: 该选项用于密码字段，不会显示文本；而是用户输入的文本将显示为星号

+   `PasswordEchoOnEdit`: 在编辑密码字段时显示实际文本，否则将显示文本的星号

+   `maxLength()`: 该方法用于指定可以在行编辑小部件中输入的文本的最大长度。

+   `setText()`: 该方法用于为行编辑小部件分配文本。

+   `text()`: 该方法访问在行编辑小部件中输入的文本。

+   `clear()`: 该方法清除或删除行编辑小部件的全部内容。

+   `setReadOnly()`:当将布尔值 true 传递给此方法时，它将使 LineEdit 小部件变为只读，即不可编辑。用户无法对通过 LineEdit 小部件显示的内容进行任何更改，但只能复制。

+   `isReadOnly()`:如果 LineEdit 小部件处于只读模式，则此方法返回布尔值 true，否则返回 false。

+   `setEnabled()`:默认情况下，LineEdit 小部件是启用的，即用户可以对其进行更改。但是，如果将布尔值 false 传递给此方法，它将禁用 LineEdit 小部件，因此用户无法编辑其内容，但只能通过`setText()`方法分配文本。

+   `setFocus()`:此方法将光标定位在指定的 LineEdit 小部件上。

# 了解 PushButton 小部件

要在应用程序中显示一个按钮，您需要创建一个`QPushButton`类的实例。在为按钮分配文本时，您可以通过在文本中的任何字符前加上一个和字符来创建快捷键。例如，如果分配给按钮的文本是`Click Me`，则字符`C`将被下划线标记，表示它是一个快捷键，用户可以通过按*Alt* + *C*来选择按钮。按钮在激活时发出 clicked()信号。除了文本，图标也可以显示在按钮中。在按钮中显示文本和图标的方法如下：

+   `setText()`:此方法用于为按钮分配文本

+   `setIcon()`:此方法用于为按钮分配图标

# 如何做...

让我们基于没有按钮的对话框模板创建一个新应用程序。如前所述，此应用程序将提示用户输入姓名，并在输入姓名后单击按钮后，应用程序将显示一个 hello 消息以及输入的姓名。以下是创建此应用程序的步骤：

1.  具有默认文本的另一个 Label 应该具有`labelResponse`的 objectName 属性

1.  从显示小部件类别中拖动一个 Label 小部件，并将其放在表单上。不要更改此 Label 小部件的文本属性，并将其文本属性保留为其默认值 TextLabel。这是因为此 Label 小部件的文本属性将通过代码设置，即将用于向用户显示 hello 消息。

1.  从输入小部件类别中拖动一个 LineEdit，并将其放在表单上。将其 objectName 属性设置为`lineEditName`。

1.  从按钮类别中拖动一个 PushButton 小部件，并将其放在表单上。将其 text 属性设置为`Click`。您可以通过以下三种方式之一更改 PushButton 小部件的 text 属性：通过双击 PushButton 小部件并覆盖默认文本，通过右键单击 PushButton 小部件并从弹出的上下文菜单中选择更改文本...选项，或者通过从属性编辑器窗口中选择文本属性并覆盖默认文本。

1.  将 PushButton 小部件的 objectName 属性设置为`ButtonClickMe`。

1.  将应用程序保存为`demoLineEdit.ui`。现在，表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d296bf34-b970-46a3-af33-77336aebb427.png)

您使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，其中包括所有表单的信息：其小部件、布局等。`.ui`文件是一个 XML 文件，您需要将其转换为 Python 代码。这样，您可以在视觉界面和代码中实现的行为之间保持清晰的分离。

1.  要使用`.ui`文件，您首先需要将其转换为 Python 脚本。您将用于将`.ui`文件转换为 Python 脚本的命令实用程序是`pyuic5`。在 Windows 中，`pyuic5`实用程序与 PyQt 捆绑在一起。要进行转换，您需要打开命令提示符窗口并导航到保存文件的文件夹，并发出以下命令：

```py
C:\Pythonbook\PyQt5>pyuic5 demoLineEdit.ui -o demoLineEdit.py
```

假设我们将表单保存在此位置：`C:\Pythonbook\PyQt5>`。上述命令显示了`demoLineEdit.ui`文件转换为 Python 脚本`demoLineEdit.py`的过程。

此方法生成的 Python 代码不应手动修改，因为任何更改都将在下次运行`pyuic5`命令时被覆盖。

生成的 Python 脚本文件`demoLineEdit.py`的代码可以在本书的源代码包中找到。

1.  将`demoLineEdit.py`文件中的代码视为头文件，并将其导入到将调用其用户界面设计的文件中。

头文件是指那些被导入到当前文件中的文件。导入这些文件的命令通常写在脚本的顶部，因此被称为头文件。

1.  让我们创建另一个名为`callLineEdit.py`的 Python 文件，并将`demoLineEdit.py`的代码导入其中，如下所示：

```py
import sys from PyQt5.QtWidgets import QDialog, QApplication
from demoLineEdit import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.ButtonClickMe.clicked.connect(self.dispmessage)
        self.show()
    def dispmessage(self):
        self.ui.labelResponse.setText("Hello "
        +self.ui.lineEditName.text())
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

`demoLineEdit.py`文件非常容易理解。创建了一个名为顶级对象的类，前面加上`Ui_`。由于我们应用程序中使用的顶级对象是`Dialog`，因此创建了`Ui_Dialog`类，并存储了我们小部件的界面元素。该类有两个方法，`setupUi()`和`retranslateUi()`。`setupUi()`方法设置小部件；它创建了您在 Qt Designer 中定义用户界面时使用的小部件。该方法逐个创建小部件，并设置它们的属性。`setupUi()`方法接受一个参数，即创建用户界面（子小部件）的顶级小部件。在我们的应用程序中，它是`QDialog`的一个实例。`retranslateUi()`方法翻译界面。

让我们逐条理解`callLineEdit.py`的作用：

1.  它导入了必要的模块。`QWidget`是 PyQt5 中所有用户界面对象的基类。

1.  它创建了一个继承自基类`QDialog`的新`MyForm`类。

1.  它为`QDialog`提供了默认构造函数。默认构造函数没有父级，没有父级的小部件称为窗口。

1.  PyQt5 中的事件处理使用信号和槽。信号是一个事件，槽是在发生信号时执行的方法。例如，当您单击一个按钮时，会发生一个`clicked()`事件，也称为信号。`connect()`方法将信号与槽连接起来。在这种情况下，槽是一个方法：`dispmessage()`。也就是说，当用户单击按钮时，将调用`dispmessage()`方法。`clicked()`在这里是一个事件，事件处理循环等待事件发生，然后将其分派以执行某些任务。事件处理循环会继续工作，直到调用`exit()`方法或主窗口被销毁为止。

1.  它通过`QApplication()`方法创建了一个名为`app`的应用程序对象。每个 PyQt5 应用程序都必须创建`sys.argv`应用程序对象，其中包含从命令行传递的参数列表，并在创建应用程序对象时传递给方法。`sys.argv`参数有助于传递和控制脚本的启动属性。

1.  使用`MyForm`类的一个实例被创建，名为`w`。

1.  `show()`方法将在屏幕上显示小部件。

1.  `dispmessage()`方法执行按钮的事件处理。它显示 Hello 文本，以及在行编辑小部件中输入的名称。

1.  `sys.exit()`方法确保干净退出，释放内存资源。

`exec_()`方法有一个下划线，因为`exec`是 Python 关键字。

在执行上述程序时，您将获得一个带有行编辑和按钮小部件的窗口，如下截图所示。当选择按钮时，将执行`dispmessage()`方法，显示 Hello 消息以及输入在行编辑小部件中的用户名：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/1aa5d22d-74f6-4f2d-9664-791751d4bedb.png)

# 使用单选按钮小部件

这个示例通过单选按钮显示特定的航班类型，当用户选择单选按钮时，将显示与该航班相关的价格。我们需要首先了解单选按钮的工作原理。

# 了解单选按钮

当您希望用户只能从可用选项中选择一个选项时，单选按钮小部件非常受欢迎。这些选项被称为互斥选项。当用户选择一个选项时，先前选择的选项将自动取消选择。单选按钮小部件是`QRadioButton`类的实例。每个单选按钮都有一个关联的文本标签。单选按钮可以处于选定（已选中）或未选定（未选中）状态。如果您想要两个或更多组单选按钮，其中每组允许单选按钮的互斥选择，请将它们放入不同的按钮组（`QButtonGroup`的实例）中。`QRadioButton`提供的方法如下所示。

# 方法

`QRadioButton`类提供以下方法：

+   `isChecked()`: 如果按钮处于选定状态，则此方法返回布尔值 true。

+   `setIcon()`: 此方法显示带有单选按钮的图标。

+   `setText()`: 此方法为单选按钮分配文本。如果您想为单选按钮指定快捷键，请在文本中使用和号（`&`）前置所选字符。快捷字符将被下划线标记。

+   `setChecked()`: 要使任何单选按钮默认选定，将布尔值 true 传递给此方法。

# 信号描述

`QRadioButton`发射的信号如下：

+   toggled(): 当按钮从选中状态变为未选中状态，或者反之时，将发射此信号

+   点击（）：当按钮被激活（即按下并释放）或者按下其快捷键时，将发射此信号

+   stateChanged(): 当单选按钮从选中状态变为未选中状态，或者反之时，将发射此信号

为了理解单选按钮的概念，让我们创建一个应用程序，询问用户选择航班类型，并通过单选按钮以`头等舱`，`商务舱`和`经济舱`的形式显示三个选项。通过单选按钮选择一个选项后，将显示该航班的价格。

# 如何做...

让我们基于没有按钮的对话框模板创建一个新的应用程序。这个应用程序将显示不同的航班类型以及它们各自的价格。当用户选择一个航班类型时，它的价格将显示在屏幕上：

1.  将两个标签小部件和三个单选按钮小部件拖放到表单上。

1.  将第一个标签小部件的文本属性设置为`选择航班类型`，并删除第二个标签小部件的文本属性。第二个标签小部件的文本属性将通过代码设置；它将用于显示所选航班类型的价格。

1.  将三个单选按钮小部件的文本属性设置为`头等舱 $150`，`商务舱 $125`和`经济舱 $100`。

1.  将第二个标签小部件的 objectName 属性设置为`labelFare`。三个单选按钮的默认对象名称分别为`radioButton`，`radioButton_2`和`radioButton_3`。将这三个单选按钮的 objectName 属性更改为`radioButtonFirstClass`，`radioButtonBusinessClass`和`radioButtonEconomyClass`。

1.  将应用程序保存为`demoRadioButton1.ui`。

看一下以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/545e660b-5490-4767-8101-c8f7ab6dea60.png)

`demoRadioButton1.ui`应用程序是一个 XML 文件，需要通过`pyuic5`命令实用程序转换为 Python 代码。本书的源代码包中可以看到生成的 Python 代码`demoRadioButton1.py`。

1.  将`demoRadioButton1.py`文件作为头文件导入到您即将创建的 Python 脚本中，以调用用户界面设计。

1.  在 Python 脚本中，编写代码根据用户选择的单选按钮显示飞行类型。将源文件命名为`callRadioButton1.py`；其代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoRadioButton1 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.radioButtonFirstClass.toggled.connect(self.
        dispFare)
        self.ui.radioButtonBusinessClass.toggled.connect(self.
        dispFare)
        self.ui.radioButtonEconomyClass.toggled.connect(self.
        dispFare)
        self.show()
    def dispFare(self):
        fare=0
        if self.ui.radioButtonFirstClass.isChecked()==True:
            fare=150
        if self.ui.radioButtonBusinessClass.isChecked()==True:
            fare=125
        if self.ui.radioButtonEconomyClass.isChecked()==True:
            fare=100
        self.ui.labelFare.setText("Air Fare is "+str(fare))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理

单选按钮的 toggled()事件连接到`dispFare()`函数，该函数将显示所选航班类型的价格。在`dispFare()`函数中，您检查单选按钮的状态。因此，如果选择了`radioButtonFirstClass`，则将值`150`分配给票价变量。同样，如果选择了`radioButtonBusinessClass`，则将值`125`分配给`fare`变量。同样，当选择`radioButtonEconomyClass`时，将值`100`分配给`fare`变量。最后，通过`labelFare`显示`fare`变量中的值。

在执行上一个程序时，您会得到一个对话框，其中显示了三种飞行类型，并提示用户选择要用于旅行的飞行类型。选择飞行类型后，所选飞行类型的价格将显示出来，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/1f097ec8-af6f-4177-8496-d35da2a29cc3.png)

# 分组单选按钮

在这个应用程序中，我们将学习创建两组单选按钮。用户可以从任一组中选择单选按钮，相应地结果或文本将出现在屏幕上。

# 准备工作

我们将显示一个对话框，其中显示不同尺码的衬衫和不同的付款方式。选择衬衫尺码和付款方式后，所选的衬衫尺码和付款方式将显示在屏幕上。我们将创建两组单选按钮，一组是衬衫尺码，另一组是付款方式。衬衫尺码组显示四个单选按钮，显示四种不同尺码的衬衫，例如 M、L、XL 和 XXL，其中 M 代表中号，L 代表大号，依此类推。付款方式组显示三个单选按钮，分别是借记/信用卡、网上银行和货到付款。用户可以从任一组中选择任何单选按钮。当用户选择任何衬衫尺码或付款方式时，所选的衬衫尺码和付款方式将显示出来。

# 如何做到...

让我们逐步重新创建前面的应用程序：

1.  基于无按钮对话框模板创建一个新应用程序。

1.  拖放三个 Label 小部件和七个 Radio Button 小部件。在这七个单选按钮中，我们将四个单选按钮排列在一个垂直布局中，将另外三个单选按钮排列在第二个垂直布局中。这两个布局将有助于将这些单选按钮分组。单选按钮是互斥的，只允许从布局或组中选择一个单选按钮。

1.  将前两个 Label 小部件的文本属性分别设置为`选择您的衬衫尺码`和`选择您的付款方式`。

1.  删除第三个 Label 小部件的文本属性，因为我们将通过代码显示所选的衬衫尺码和付款方式。

1.  在属性编辑器窗口中，增加所有小部件的字体大小，以增加它们在应用程序中的可见性。

1.  将前四个单选按钮的文本属性设置为`M`、`L`、`XL`和`XXL`。将这四个单选按钮排列成一个垂直布局。

1.  将接下来的三个单选按钮的文本属性设置为`借记/信用卡`、`网上银行`和`货到付款`。将这三个单选按钮排列成第二个垂直布局。请记住，这些垂直布局有助于将这些单选按钮分组。

1.  将前四个单选按钮的对象名称更改为`radioButtonMedium`、`radioButtonLarge`、`radioButtonXL`和`radioButtonXXL`。

1.  将第一个`VBoxLayout`布局的 objectName 属性设置为`verticalLayout`。`VBoxLayout`布局将用于垂直对齐单选按钮。

1.  将下一个三个单选按钮的对象名称更改为`radioButtonDebitCard`，`radioButtonNetBanking`和`radioButtonCashOnDelivery`。

1.  将第二个`QVBoxLayout`对象的 objectName 属性设置为`verticalLayout_2`。

1.  将第三个标签小部件的`objectName`属性设置为`labelSelected`。通过此标签小部件，将显示所选的衬衫尺寸和付款方式。

1.  将应用程序保存为`demoRadioButton2.ui`。

1.  现在，表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/8c185e1e-852e-46ca-bb90-d767f275c3ab.png)

然后，`.ui`（XML）文件通过`pyuic5`命令实用程序转换为 Python 代码。您可以在本书的源代码包中找到 Python 代码`demoRadioButton2.py`。

1.  将`demoRadioButton2.py`文件作为头文件导入我们的程序，以调用用户界面设计并编写代码，通过标签小部件显示所选的衬衫尺寸和付款方式，当用户选择或取消选择任何单选按钮时。

1.  让我们将程序命名为`callRadioButton2.pyw`；其代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoRadioButton2 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.radioButtonMedium.toggled.connect(self.
        dispSelected)
        self.ui.radioButtonLarge.toggled.connect(self.
        dispSelected)
        self.ui.radioButtonXL.toggled.connect(self.dispSelected)
        self.ui.radioButtonXXL.toggled.connect(self.
        dispSelected)
        self.ui.radioButtonDebitCard.toggled.connect(self.
        dispSelected)
        self.ui.radioButtonNetBanking.toggled.connect(self.
        dispSelected)
        self.ui.radioButtonCashOnDelivery.toggled.connect(self.
        dispSelected)
        self.show()
    def dispSelected(self):
        selected1="";
        selected2=""
        if self.ui.radioButtonMedium.isChecked()==True:
            selected1="Medium"
        if self.ui.radioButtonLarge.isChecked()==True:
            selected1="Large"
        if self.ui.radioButtonXL.isChecked()==True:
            selected1="Extra Large"
        if self.ui.radioButtonXXL.isChecked()==True:
            selected1="Extra Extra Large"
        if self.ui.radioButtonDebitCard.isChecked()==True:
            selected2="Debit/Credit Card"
        if self.ui.radioButtonNetBanking.isChecked()==True:
            selected2="NetBanking"
        if self.ui.radioButtonCashOnDelivery.isChecked()==True:
            selected2="Cash On Delivery"
        self.ui.labelSelected.setText("Chosen shirt size is 
        "+selected1+" and payment method as " + selected2)
if __name__=="__main__":
    app = QApplication(sys.argv)
```

```py
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

所有单选按钮的`toggled()`事件都连接到`dispSelected()`函数，该函数将显示所选的衬衫尺寸和付款方式。在`dispSelected()`函数中，您检查单选按钮的状态，以确定它们是选中还是未选中。根据第一个垂直布局中选择的单选按钮，`selected1`变量的值将设置为`中号`、`大号`、`特大号`或`特特大号`。类似地，从第二个垂直布局中，根据所选的单选按钮，`selected2`变量的值将初始化为`借记卡/信用卡`、`网上银行`或`货到付款`。最后，通过`labelSelected`小部件显示分配给`selected1`变量和`selected`变量的衬衫尺寸和付款方式。运行应用程序时，会弹出对话框，提示您选择衬衫尺寸和付款方式。选择衬衫尺寸和付款方式后，所选的衬衫尺寸和付款方式将通过标签小部件显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/fbe0eafa-412a-4a05-8700-c88f95f491ee.png)

# 以复选框形式显示选项

在创建应用程序时，您可能会遇到需要为用户提供多个选项以供选择的情况。也就是说，您希望用户从一组选项中选择一个或多个选项。在这种情况下，您需要使用复选框。让我们更多地了解复选框。

# 准备就绪

而单选按钮只允许在组中选择一个选项，复选框允许您选择多个选项。也就是说，选择复选框不会影响应用程序中的其他复选框。复选框显示为文本标签，是`QCheckBox`类的一个实例。复选框可以处于三种状态之一：选中（已选中）、未选中（未选中）或三态（未更改）。三态是一种无变化状态；用户既没有选中也没有取消选中复选框。

# 方法应用

以下是`QCheckBox`类提供的方法：

+   `isChecked()`: 如果复选框被选中，此方法返回布尔值 true，否则返回 false。

+   `setTristate()`: 如果您不希望用户更改复选框的状态，请将布尔值 true 传递给此方法。用户将无法选中或取消选中复选框。

+   `setIcon()`: 此方法用于显示复选框的图标。

+   `setText()`: 此方法将文本分配给复选框。要为复选框指定快捷键，请在文本中的首选字符前加上一个和字符。快捷字符将显示为下划线。

+   `setChecked()`: 为了使复选框默认显示为选中状态，请将布尔值 true 传递给此方法。

# 信号描述

`QCheckBox`发出的信号如下：

+   clicked(): 当复选框被激活（即按下并释放）或按下其快捷键时，将发出此信号

+   stateChanged(): 每当复选框从选中到未选中或反之亦然时，将发出此信号

理解复选框小部件，让我们假设您经营一家餐厅，销售多种食物，比如比萨。比萨可以搭配不同的配料，比如额外的奶酪，额外的橄榄等，每种配料的价格也会显示出来。用户可以选择普通比萨并加上一个或多个配料。您希望的是，当选择了配料时，比萨的总价，包括所选的配料，会显示出来。

# 操作步骤...

本教程的重点是理解当复选框的状态从选中到未选中或反之时如何触发操作。以下是创建这样一个应用程序的逐步过程：

1.  首先，基于无按钮的对话框模板创建一个新应用程序。

1.  将三个标签小部件和三个复选框小部件拖放到表单上。

1.  将前两个标签小部件的文本属性设置为`Regular Pizza $10`和`Select your extra toppings`。

1.  在属性编辑器窗口中，增加所有三个标签和复选框的字体大小，以增加它们在应用程序中的可见性。

1.  将三个复选框的文本属性设置为`Extra Cheese $1`，`Extra Olives $1`和`Extra Sausages $2`。三个复选框的默认对象名称分别为`checkBox`，`checkBox_2`和`checkBox_3`。

1.  分别更改为`checkBoxCheese`，`checkBoxOlives`和`checkBoxSausages`。

1.  将标签小部件的 objectName 属性设置为`labelAmount`。

1.  将应用程序保存为`demoCheckBox1.ui`。现在，表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a49fb108-5909-488f-98fb-addd10717ebf.png)

然后，通过`pyuic5`命令实用程序将`.ui`（XML）文件转换为 Python 代码。在本书的源代码包中可以看到生成的`demoCheckBox1.py`文件中的 Python 代码。

1.  将`demoCheckBox1.py`文件作为头文件导入我们的程序，以调用用户界面设计并编写代码，通过标签小部件计算普通比萨的总成本以及所选的配料，当用户选择或取消选择任何复选框时。

1.  让我们将程序命名为`callCheckBox1.pyw`；其代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton
from demoCheckBox1 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.checkBoxCheese.stateChanged.connect(self.
        dispAmount)
        self.ui.checkBoxOlives.stateChanged.connect(self.
        dispAmount)
        self.ui.checkBoxSausages.stateChanged.connect(self.
        dispAmount)
        self.show()
    def dispAmount(self):
        amount=10
        if self.ui.checkBoxCheese.isChecked()==True:
            amount=amount+1
        if self.ui.checkBoxOlives.isChecked()==True:
            amount=amount+1
        if self.ui.checkBoxSausages.isChecked()==True:
            amount=amount+2
        self.ui.labelAmount.setText("Total amount for pizza is 
        "+str(amount))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

将复选框的 stateChanged()事件连接到`dispAmount`函数，该函数将计算所选配料的比萨的成本。在`dispAmount`函数中，您检查复选框的状态，以找出它们是选中还是未选中。被选中的复选框的配料成本被添加并存储在`amount`变量中。最后，存储在`amount`变量中的金额加法通过`labelAmount`显示出来。运行应用程序时，会弹出对话框提示您选择要添加到普通比萨中的配料。选择任何配料后，普通比萨的金额以及所选的配料将显示在屏幕上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4ed74906-5046-4431-99fb-2da485c83932.png)每当任何复选框的状态改变时，`dispAmount`函数将被调用。因此，只要勾选或取消任何复选框，总金额将通过标签小部件显示出来。

# 显示两组复选框

在这个应用程序中，我们将学习如何制作两组复选框。用户可以从任一组中选择任意数量的复选框，相应的结果将显示出来。

# 准备工作

我们将尝试显示一家餐厅的菜单，那里供应不同类型的冰淇淋和饮料。我们将创建两组复选框，一组是冰淇淋，另一组是饮料。冰淇淋组显示四个复选框，显示四种不同类型的冰淇淋，薄荷巧克力片、曲奇面团等，以及它们的价格。饮料组显示三个复选框，咖啡、苏打水等，以及它们的价格。用户可以从任一组中选择任意数量的复选框。当用户选择任何冰淇淋或饮料时，所选冰淇淋和饮料的总价格将显示出来。

# 操作步骤...

以下是创建应用程序的步骤，解释了如何将复选框排列成不同的组，并在任何组的任何复选框的状态发生变化时采取相应的操作：

1.  基于没有按钮的对话框模板创建一个新的应用程序。

1.  将四个标签小部件、七个复选框小部件和两个分组框小部件拖放到表单上。

1.  将前三个标签小部件的文本属性分别设置为`菜单`，`选择您的冰淇淋`和`选择您的饮料`。

1.  删除第四个标签小部件的文本属性，因为我们将通过代码显示所选冰淇淋和饮料的总金额。

1.  通过属性编辑器，增加所有小部件的字体大小，以增加它们在应用程序中的可见性。

1.  将前四个复选框的文本属性设置为`Mint Choclate Chips $4`，`Cookie Dough $2`，`Choclate Almond $3`和`Rocky Road $5`。将这四个复选框放入第一个分组框中。

1.  将接下来三个复选框的文本属性设置为`Coffee $2`，`Soda $3`和`Tea $1`。将这三个复选框放入第二个分组框中。

1.  将前四个复选框的对象名称更改为`checkBoxChoclateChips`，`checkBoxCookieDough`，`checkBoxChoclateAlmond`和`checkBoxRockyRoad`。

1.  将第一个分组框的`objectName`属性设置为`groupBoxIceCreams`。

1.  将接下来三个复选框的`objectName`属性更改为`checkBoxCoffee`，`checkBoxSoda`和`checkBoxTea`。

1.  将第二个分组框的`objectName`属性设置为`groupBoxDrinks`。

1.  将第四个标签小部件的`objectName`属性设置为`labelAmount`。

1.  将应用程序保存为`demoCheckBox2.ui`。通过这个标签小部件，所选冰淇淋和饮料的总金额将显示出来，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/0c376114-b3d1-4706-8f83-f503e597ac9f.png)

然后，通过`pyuic5`命令实用程序将`.ui`（XML）文件转换为 Python 代码。您可以在本书的源代码包中找到生成的 Python 代码`demoCheckbox2.py`文件。

1.  在我们的程序中将`demoCheckBox2.py`文件作为头文件导入，以调用用户界面设计，并编写代码来通过标签小部件计算冰淇淋和饮料的总成本，当用户选择或取消选择任何复选框时。

1.  让我们将程序命名为`callCheckBox2.pyw`；其代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton
from demoCheckBox2 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.checkBoxChoclateAlmond.stateChanged.connect
        (self.dispAmount)
        self.ui.checkBoxChoclateChips.stateChanged.connect(self.
        dispAmount)
        self.ui.checkBoxCookieDough.stateChanged.connect(self.
        dispAmount)
        self.ui.checkBoxRockyRoad.stateChanged.connect(self.
        dispAmount)
        self.ui.checkBoxCoffee.stateChanged.connect(self.
        dispAmount)
        self.ui.checkBoxSoda.stateChanged.connect(self.
        dispAmount)
        self.ui.checkBoxTea.stateChanged.connect(self.
        dispAmount)
        self.show()
    def dispAmount(self):
        amount=0
        if self.ui.checkBoxChoclateAlmond.isChecked()==True:
            amount=amount+3
        if self.ui.checkBoxChoclateChips.isChecked()==True:
            amount=amount+4
        if self.ui.checkBoxCookieDough.isChecked()==True:
            amount=amount+2
        if self.ui.checkBoxRockyRoad.isChecked()==True:
            amount=amount+5
        if self.ui.checkBoxCoffee.isChecked()==True:
            amount=amount+2
        if self.ui.checkBoxSoda.isChecked()==True:
            amount=amount+3
        if self.ui.checkBoxTea.isChecked()==True:
            amount=amount+1
        self.ui.labelAmount.setText("Total amount is 
        $"+str(amount))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

所有复选框的`stateChanged()`事件都连接到`dispAmount`函数，该函数将计算所选冰淇淋和饮料的成本。在`dispAmount`函数中，您检查复选框的状态，以找出它们是选中还是未选中。选中复选框的冰淇淋和饮料的成本被添加并存储在`amount`变量中。最后，通过`labelAmount`小部件显示存储在`amount`变量中的金额的总和。运行应用程序时，会弹出对话框提示您选择要订购的冰淇淋或饮料。选择冰淇淋或饮料后，所选项目的总金额将显示出来，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/9e489150-d6f2-4a81-bb85-67494f09c7fd.png)


# 第十四章：事件处理-信号和插槽

在本章中，我们将学习以下主题：

+   使用信号/插槽编辑器

+   从一个*Line Edit*小部件复制并粘贴文本到另一个*Line Edit*小部件

+   转换数据类型并制作一个小型计算器

+   使用旋转框小部件

+   使用滚动条和滑块

+   使用列表小部件

+   从一个列表小部件中选择多个列表项，并在另一个列表中显示它们

+   将项目添加到列表小部件中

+   在列表小部件中执行操作

+   使用组合框小部件

+   使用字体组合框小部件

+   使用进度条小部件

# 介绍

事件处理是每个应用程序中的重要机制。应用程序不仅应该识别事件，还必须采取相应的行动来服务事件。在任何事件上采取的行动决定了应用程序的进程。每种编程语言都有不同的处理或监听事件的技术。让我们看看 Python 如何处理其事件。

# 使用信号/插槽编辑器

在 PyQt 中，事件处理机制也被称为**信号**和**插槽**。事件可以是在小部件上单击或双击的形式，或按下*Enter*键，或从单选按钮、复选框等中选择选项。每个小部件在应用事件时都会发出一个信号，该信号需要连接到一个方法，也称为插槽。插槽是指包含您希望在发生信号时执行的代码的方法。大多数小部件都有预定义的插槽；您不必编写代码来将预定义的信号连接到预定义的插槽。

您甚至可以通过导航到工具栏中的编辑|编辑信号/插槽工具来编辑信号/插槽。

# 如何做...

要编辑放置在表单上的不同小部件的信号和插槽，您需要执行以下步骤切换到信号和插槽编辑模式：

1.  您可以按*F4*键，导航到编辑|编辑信号/插槽选项，或从工具栏中选择编辑信号/插槽图标。该模式以箭头的形式显示所有信号和插槽连接，指示小部件与其相应插槽的连接。

您还可以在此模式下创建小部件之间的新信号和插槽连接，并删除现有信号。

1.  要在表单中的两个小部件之间建立信号和插槽连接，请通过在小部件上单击鼠标，将鼠标拖向要连接的另一个小部件，然后释放鼠标按钮来选择小部件。

1.  在拖动鼠标时取消连接，只需按下*Esc*键。

1.  在释放鼠标到达目标小部件时，将出现“连接对话框”，提示您从源小部件中选择信号和从目标小部件中选择插槽。

1.  选择相应的信号和插槽后，选择“确定”以建立信号和插槽连接。

以下屏幕截图显示了将*Push Button*拖动到*Line Edit*小部件上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/44ba5e6d-dc82-49fc-a7b8-db7d21c9ff08.png)

1.  在*Line Edit*小部件上释放鼠标按钮后，您将获得预定义信号和插槽的列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6236b767-2cf0-4da3-bc9b-f585ceb40395.png)您还可以在“配置连接”对话框中选择取消以取消信号和插槽连接。

1.  连接后，所选信号和插槽将显示为箭头中的标签，连接两个小部件。

1.  要修改信号和插槽连接，请双击连接路径或其标签之一，以显示“配置连接”对话框。

1.  从“配置连接”对话框中，您可以根据需要编辑信号或插槽。

1.  要删除信号和插槽连接，请在表单上选择其箭头，然后按*删除*键。

信号和插槽连接也可以在任何小部件和表单之间建立。为此，您可以执行以下步骤：

1.  选择小部件，拖动鼠标，并释放鼠标按钮到表单上。连接的终点会变成电气接地符号，表示已经在表单上建立了连接。

1.  要退出信号和插槽编辑模式，导航到 Edit | Edit Widgets 或按下*F3*键。

# 从一个 Line Edit 小部件复制文本并粘贴到另一个

这个教程将让您了解一个小部件上执行的事件如何调用相关小部件上的预定义动作。因为我们希望在点击推按钮时从一个 Line Edit 小部件复制内容，所以我们需要在推按钮的 pressed()事件发生时调用`selectAll()`方法。此外，我们需要在推按钮的 released()事件发生时调用`copy()`方法。要在点击另一个推按钮时将剪贴板中的内容粘贴到另一个 Line Edit 小部件中，我们需要在另一个推按钮的 clicked()事件发生时调用`paste()`方法。

# 准备就绪

让我们创建一个包含两个 Line Edit 和两个 Push Button 小部件的应用程序。点击第一个推按钮时，第一个 Line Edit 小部件中的文本将被复制，点击第二个推按钮时，从第一个 Line Edit 小部件中复制的文本将被粘贴到第二个 Line Edit 小部件中。

让我们根据无按钮对话框模板创建一个新应用程序，执行以下步骤：

1.  通过从小部件框中将 Line Edit 和 Push Button 小部件拖放到表单上，开始添加`QLineEdit`和`QPushButton`。

在编辑时预览表单，选择 Form、Preview，或使用*Ctrl* + *R*。

1.  要在用户在表单上选择推按钮时复制 Line Edit 小部件的文本，您需要将推按钮的信号连接到 Line Edit 的插槽。让我们学习如何做到这一点。

# 如何操作...

最初，表单处于小部件编辑模式，要应用信号和插槽连接，您需要首先切换到信号和插槽编辑模式：

1.  从工具栏中选择编辑信号/插槽图标，切换到信号和插槽编辑模式。

1.  在表单上，选择推按钮，拖动鼠标到 Line Edit 小部件上，然后释放鼠标按钮。配置连接对话框将弹出，允许您在 Push Button 和 Line Edit 小部件之间建立信号和插槽连接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a35a1ce3-4efe-436f-9082-068d9263932a.png)

1.  从 pushButton (QPushButton)选项卡中选择 pressed()事件或信号，从 lineEdit (QLineEdit)选项卡中选择 selectAll()插槽。

Push Button 小部件与 Line Edit 的连接信号将以箭头的形式显示，表示两个小部件之间的信号和插槽连接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/76b97b24-9475-4591-a360-15a724c1cc19.png)

1.  将 Push Button 小部件的文本属性设置为`Copy`，表示它将复制 Line Edit 小部件中输入的文本。

1.  接下来，我们将重复点击推按钮并将其拖动到 Line Edit 小部件上，以连接 push 按钮的 released()信号与 Line Edit 小部件的 copy()插槽。在表单上，您将看到另一个箭头，表示两个小部件之间建立的第二个信号和插槽连接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/3a3fca9d-bd78-4f3a-9756-17182366be2c.png)

1.  为了粘贴复制的内容，将一个推按钮和一个 Line Edit 小部件拖放到表单上。

1.  将 Push Button 小部件的文本属性设置为`Paste`。

1.  点击推按钮，按住鼠标按钮拖动，然后释放到 Line Edit 小部件上。

1.  从配置连接对话框中，选择 pushButton (QPushButton)列中的 clicked()事件和 lineEdit (QLineEdit)列中的 paste()插槽。

1.  将表单保存为`demoSignal1.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4d966c42-f1e8-4711-8c50-3ac51135e31c.png)

表单将保存在扩展名为`.ui`的文件中。`demoSignal1.ui`文件将包含表单的所有信息，包括其小部件、布局等。`.ui`文件是一个 XML 文件，需要使用`pyuic5`实用程序将其转换为 Python 代码。生成的 Python 代码文件`demoSignal1.py`可以在本书的源代码包中找到。在`demoSignal1.py`文件中，您会发现它从`QtCore`和`QtGui`两个模块中导入了所有内容，因为您将需要它们来开发 GUI 应用程序：

+   `QtCore`：`QtCore`模块构成了所有基于 Qt 的应用程序的基础。它包含了最基本的类，如`QCoreApplication`、`QObject`等。这些类执行重要的任务，如事件处理、实现信号和槽机制、I/O 操作、处理字符串等。该模块包括多个类，包括`QFile`、`QDir`、`QIODevice`、`QTimer`、`QString`、`QDate`和`QTime`。

+   `QtGui`：顾名思义，`QtGUI`模块包含了开发跨平台 GUI 应用程序所需的类。该模块包含了 GUI 类，如`QCheckBox`、`QComboBox`、`QDateTimeEdit`、`QLineEdit`、`QPushButton`、`QPainter`、`QPaintDevice`、`QApplication`、`QTextEdit`和`QTextDocument`。

1.  将`demoSignalSlot1.py`文件视为头文件，并将其导入到您将调用其用户界面设计的文件中。

1.  创建另一个名为`calldemoSignal1.pyw`的 Python 文件，并将`demoSignal1.py`代码导入其中：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoSignalSlot1 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.show()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

`sys`模块被导入，因为它提供了对存储在`sys.argv`列表中的命令行参数的访问。这是因为每个 PyQt GUI 应用程序必须有一个`QApplication`对象，以提供对应用程序目录、屏幕大小等信息的访问，因此您创建了一个`QApplication`对象。为了使 PyQt 能够使用和应用命令行参数（如果有的话），您在创建`QApplication`对象时传递命令行参数。您创建了`MyForm`的一个实例，并调用其`show()`方法，该方法向`QApplication`对象的事件队列中添加了一个新事件。这个新事件用于显示`MyForm`类中指定的所有小部件。调用`app.exec_`方法来启动`QApplication`对象的事件循环。一旦事件循环开始，`MyForm`类中使用的顶级小部件以及其子小部件将被显示。所有系统生成的事件以及用户交互事件都将被添加到事件队列中。应用程序的事件循环不断检查是否发生了事件。发生事件时，事件循环会处理它并调用相关的槽或方法。在关闭应用程序的顶级小部件时，PyQt 会删除该小部件，并对应用程序进行清理终止。

在 PyQt 中，任何小部件都可以用作顶级窗口。`super().__init__()`方法从`MyForm`类中调用基类构造函数，即从`MyForm`类中调用`QDialog`类的构造函数，以指示通过该类显示`QDialog`是一个顶级窗口。

通过调用 Python 代码中创建的类的`setupUI()`方法来实例化用户界面设计（`Ui_Dialog`）。我们创建了`Ui_Dialog`类的一个实例，该类是在 Python 代码中创建的，并调用了它的`setupUi()`方法。对话框小部件将被创建为所有用户界面小部件的父级，并显示在屏幕上。请记住，`QDialog`、`QMainWindow`以及 PyQt 的所有小部件都是从`QWidget`派生的。

运行应用程序时，您将获得两对行编辑和按钮小部件。在一个行编辑小部件中输入文本，当您单击复制按钮时，文本将被复制。

现在，单击粘贴按钮后，复制的文本将粘贴在第二个行编辑小部件中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4555d238-8d6a-4315-bcb7-6f4b37d2e1b4.png)

# 转换数据类型并创建一个小型计算器

接受单行数据最常用的小部件是行编辑小部件，行编辑小部件的默认数据类型是字符串。为了对两个整数值进行任何计算，需要将行编辑小部件中输入的字符串数据转换为整数数据类型，然后将计算结果（将是数值数据类型）转换回字符串类型，然后通过标签小部件显示。这个示例正是这样做的。

# 如何做...

为了了解用户如何接受数据以及如何进行类型转换，让我们创建一个基于对话框无按钮模板的应用程序，执行以下步骤：

1.  通过拖放三个标签、两个行编辑和四个按钮小部件到表单上，向表单添加三个`QLabel`、两个`QLineEdit`和一个`QPushButton`小部件。

1.  将两个标签小部件的文本属性设置为`输入第一个数字`和`输入第二个数字`。

1.  将三个标签的 objectName 属性设置为`labelFirstNumber`，`labelSecondNumber`和`labelResult`。

1.  将两个行编辑小部件的 objectName 属性设置为`lineEditFirstNumber`和`lineEditSecondNumber`。

1.  将四个按钮小部件的 objectName 属性分别设置为`pushButtonPlus`，`pushButtonSubtract`，`pushButtonMultiply`和`pushButtonDivide`。

1.  将按钮的文本属性分别设置为`+`，`-`，`x`和`/`。

1.  删除第三个标签的默认文本属性，因为 Python 脚本将设置该值，并在添加两个数字值时显示它。 

1.  不要忘记在设计师中拖动标签小部件，以确保它足够长，可以显示通过 Python 脚本分配给它的文本。

1.  将 UI 文件保存为`demoCalculator.ui`。

1.  您还可以通过在属性编辑器窗口中的 geometry 下设置宽度属性来增加标签小部件的宽度：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/78cf810c-5dc9-488b-8c9b-99978a6d18d5.png)

`.ui`文件以 XML 格式，需要转换为 Python 代码。生成的 Python 代码`demoCalculator.py`可以在本书的源代码包中看到。

1.  创建一个名为`callCalculator.pyw`的 Python 脚本，导入 Python 代码`demoCalculator.py`来调用用户界面设计，并获取输入的行编辑小部件中的值，并显示它们的加法。Python 脚本`callCalculator.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoCalculator import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonPlus.clicked.connect(self.addtwonum)
        self.ui.pushButtonSubtract.clicked.connect
        (self.subtracttwonum)
        self.ui.pushButtonMultiply.clicked.connect
        (self.multiplytwonum)
        self.ui.pushButtonDivide.clicked.connect(self.dividetwonum)
        self.show()
    def addtwonum(self):
        if len(self.ui.lineEditFirstNumber.text())!=0:
                a=int(self.ui.lineEditFirstNumber.text())
        else:
                a=0
        if len(self.ui.lineEditSecondNumber.text())!=0:
                b=int(self.ui.lineEditSecondNumber.text())
        else:
                b=0
                sum=a+b
        self.ui.labelResult.setText("Addition: " +str(sum))
    def subtracttwonum(self):
        if len(self.ui.lineEditFirstNumber.text())!=0:
                a=int(self.ui.lineEditFirstNumber.text())
        else:
                a=0
        if len(self.ui.lineEditSecondNumber.text())!=0:
                b=int(self.ui.lineEditSecondNumber.text())
        else:
                b=0
                diff=a-b
        self.ui.labelResult.setText("Substraction: " +str(diff))
    def multiplytwonum(self):
        if len(self.ui.lineEditFirstNumber.text())!=0:
                a=int(self.ui.lineEditFirstNumber.text())
        else:
                a=0
        if len(self.ui.lineEditSecondNumber.text())!=0:
                b=int(self.ui.lineEditSecondNumber.text())
        else:
                b=0
                mult=a*b
        self.ui.labelResult.setText("Multiplication: " +str(mult))
    def dividetwonum(self):
        if len(self.ui.lineEditFirstNumber.text())!=0:
                a=int(self.ui.lineEditFirstNumber.text())
        else:
                a=0
        if len(self.ui.lineEditSecondNumber.text())!=0:
                b=int(self.ui.lineEditSecondNumber.text())
        else:
                b=0
                division=a/b
        self.ui.labelResult.setText("Division: "+str(round
        (division,2)))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

此代码中使用了以下四个函数：

+   `len()`: 这个函数返回字符串中的字符数

+   `str()`: 这个函数将传递的参数转换为字符串数据类型

+   `int()`: 这个函数将传递的参数转换为整数数据类型

+   `round()`: 这个函数将传递的数字四舍五入到指定的小数位

`pushButtonPlus`的`clicked()`事件连接到`addtwonum()`方法，以显示在两个行编辑小部件中输入的数字的总和。在`addtwonum()`方法中，首先验证`lineEditFirstNumber`和`lineEditSecondNumber`，以确保用户是否将任一行编辑留空，如果是，则该行编辑的值为零。

检索两个行编辑小部件中输入的值，通过`int()`转换为整数，并赋值给两个变量`a`和`b`。计算`a`和`b`变量中的值的总和，并存储在`sum`变量中。通过`str`方法将变量`sum`中的结果转换为字符串格式，并通过`labelResult`显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/c49fe2fa-a965-4712-9a07-2b38c64867e5.png)

类似地，`pushButtonSubtract`的`clicked()`事件连接到`subtracttwonum()`方法，以显示两个行编辑小部件中输入的数字的减法。再次，在验证两个行编辑小部件之后，检索并将其输入的值转换为整数。对这两个数字进行减法运算，并将结果分配给`diff`变量。

最后，通过`str()`方法将`diff`变量中的结果转换为字符串格式，并通过`labelResult`显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/45370293-94db-4db0-975b-215463fc4a0b.png)

类似地，`pushButtonMultiply`和`pushButtonDivide`的`clicked()`事件分别连接到`multiplytwonum()`和`dividetwonum()`方法。这些方法将两个行编辑小部件中输入的值相乘和相除，并通过`labelResult`小部件显示它们。

乘法的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ed7ceb86-a691-4815-b23a-b6fa3495afbf.png)

除法的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/984be4f4-3428-475e-9a52-702b4dfd181d.png)

# 使用旋转框小部件

旋转框小部件用于显示整数值、浮点值和文本。它对用户施加了约束：用户不能输入任意数据，但只能从旋转框显示的可用选项中进行选择。旋转框小部件默认显示初始值，可以通过选择上/下按钮或在键盘上按上/下箭头键来增加或减少该值。您可以通过单击或手动输入来选择要显示的值。

# 准备就绪

旋转框小部件可以使用两个类`QSpinBox`和`QDoubleSpinBox`创建，其中`QSpinBox`仅显示整数值，而`QDoubleSpinBox`类显示浮点值。`QSpinBox`提供的方法如下所示：

+   `value()`: 此方法返回从旋转框中选择的当前整数值。

+   `text()`: 此方法返回旋转框显示的文本。

+   `setPrefix()`: 此方法分配要添加到旋转框返回值之前的前缀文本。

+   `setSuffix()`: 此方法分配要附加到旋转框返回值的后缀文本。

+   `cleanText()`: 此方法返回旋转框的值，不带后缀、前缀或前导或尾随空格。

+   `setValue()`: 此方法分配值给旋转框。

+   `setSingleStep()`: 此方法设置旋转框的步长。步长是旋转框的增量/减量值，即旋转框的值将通过选择上/下按钮或使用`setValue()`方法增加或减少的值。

+   `setMinimum()`: 此方法设置旋转框的最小值。

+   `setMaximum()`: 此方法设置旋转框的最大值。

+   `setWrapping()`: 此方法将布尔值 true 传递给此方法，以启用旋转框中的包装。包装意味着当按下上按钮显示最大值时，旋转框返回到第一个值（最小值）。

`QSpinBox`类发出的信号如下：

+   valueChanged(): 当通过选择上/下按钮或使用`setValue()`方法更改旋转框的值时，将发出此信号。

+   `editingFinished()`: 当焦点离开旋转框时发出此信号

用于处理旋转框中浮点值的类是`QDoubleSpinBox`。所有前述方法也受`QDoubleSpinBox`类的支持。它默认显示值，保留两位小数。要更改精度，请使用`round()`，它会显示值，保留指定数量的小数位；该值将四舍五入到指定数量的小数位。

旋转框的默认最小值、最大值、单步值和值属性分别为 0、99、1 和 0；双精度旋转框的默认值为 0.000000、99.990000、1.000000 和 0.000000。

让我们创建一个应用程序，该应用程序将要求用户输入书的价格，然后输入客户购买的书的数量，并显示书的总金额。此外，该应用程序将提示您输入 1 公斤糖的价格，然后输入用户购买的糖的数量。在输入糖的数量时，应用程序将显示糖的总量。书籍和糖的数量将分别通过微调框和双精度微调框输入。

# 如何做...

要了解如何通过微调框接受整数和浮点值并在进一步计算中使用，让我们基于无按钮模板创建一个新的应用程序，并按照以下步骤操作：

1.  让我们开始拖放三个标签，一个微调框，一个双精度微调框和四个行编辑小部件。

1.  两个标签小部件的文本属性设置为`Book Price value`和`Sugar Price`，第三个标签小部件的 objectName 属性设置为`labelTotalAmount`。

1.  将四个行编辑小部件的 objectName 属性设置为`lineEditBookPrice`，`lineEditBookAmount`，`lineEditSugarPrice`和`lineEditSugarAmount`。

1.  将 Spin Box 小部件的 objectName 属性设置为`spinBoxBookQty`，将 Double Spin Box 小部件的 objectName 属性设置为`doubleSpinBoxSugarWeight`。

1.  删除第三个标签小部件 TextLabe 的默认文本属性，因为您将在程序中设置其文本以显示总金额。

1.  删除第三个标签小部件的文本属性后，它将变得不可见。

1.  禁用两个行编辑小部件`lineEditBookAmount`和`lineEditSugarAmount`，通过取消选中它们的属性编辑器窗口中的启用属性，因为您希望它们显示不可编辑的值。

1.  使用名称`demoSpinner.ui`保存应用程序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/4af31882-d0d5-42af-8146-943ccd17fa15.png)

1.  使用`pyuic5`命令实用程序，`.ui`（XML）文件将转换为 Python 代码。生成的 Python 代码文件`demoSpinner.py`可以在本书的源代码中看到。

1.  创建一个名为`calldemoSpinner.pyw`的 Python 脚本文件，导入代码`demoSpinner.py`，使您能够调用显示通过微调框选择的数字并计算总书籍金额和总糖量的用户界面设计。`calldemoSpinner.pyw`文件将显示如下：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoSpinBox import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.spinBoxBookQty.editingFinished.connect(self.
        result1)
        self.ui.doubleSpinBoxSugarWeight.editingFinished.connect
        (self.result2)
        self.show()
    def result1(self):
        if len(self.ui.lineEditBookPrice.text())!=0:
                bookPrice=int(self.ui.lineEditBookPrice.text())
        else:
                bookPrice=0
                totalBookAmount=self.ui.spinBoxBookQty.value() * 
                bookPrice
                self.ui.lineEditBookAmount.setText(str
                (totalBookAmount))
    def result2(self):
        if len(self.ui.lineEditSugarPrice.text())!=0:
                sugarPrice=float(self.ui.lineEditSugarPrice.
                text())
        else:
                sugarPrice=0
                totalSugarAmount=self.ui.
                doubleSpinBoxSugarWeight.value() * sugarPrice
                self.ui.lineEditSugarAmount.setText(str(round
                (totalSugarAmount,2)))
                totalBookAmount=int(self.ui.lineEditBookAmount.
                text())
                totalAmount=totalBookAmount+totalSugarAmount
                self.ui.labelTotalAmount.setText(str(round
                (totalAmount,2)))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在此代码中，您可以看到两个微调框的`editingFinished`信号附加到`result1`和`result2`函数。这意味着当焦点离开任何微调框时，将调用相应的方法。当用户使用鼠标移动到其他微调框或按 Tab 键时，焦点将离开小部件：

+   在`result1`方法中，您从 Spin Box 小部件中检索购买的书的数量的整数值，并将其乘以在`lineEditBookPrice`小部件中输入的书的价格，以计算总书费。然后通过`lineEditBookAmount`小部件显示总书费。

+   类似地，在`result2`方法中，您从双精度微调框中检索购买的糖的重量的浮点值，并将其乘以在`lineEditSugarPrice`小部件中输入的每公斤糖的价格，以计算总糖成本，然后通过`lineEditSugarAmount`小部件显示。书的成本和糖的成本的总和最终通过`labelTotalAmount`小部件显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/ef46d187-e1cd-41f5-bcdc-05f1af89982d.png)

# 使用滚动条和滑块

滚动条在查看无法出现在有限可见区域的大型文档或图像时非常有用。滚动条水平或垂直出现，指示您在文档或图像中的当前位置以及不可见区域的大小。使用这些滚动条提供的滑块手柄，您可以访问文档或图像的隐藏部分。

滑块是选择两个值之间的整数值的一种方式。也就是说，滑块可以表示一系列最小和最大值，并且用户可以通过将滑块手柄移动到滑块中所需位置来选择此范围内的值。

# 准备就绪

滚动条用于查看大于视图区域的文档或图像。要显示水平或垂直滚动条，您可以使用`HorizontalScrollBar`和`VerticalScrollBar`小部件，它们是`QScrollBar`类的实例。这些滚动条有一个滑块手柄，可以移动以查看不可见的区域。滑块手柄的位置指示文档或图像内的位置。滚动条具有以下控件：

+   **滑块手柄**: 此控件用于快速移动到文档或图像的任何部分。

+   **滚动箭头**: 这些是滚动条两侧的箭头，用于查看当前不可见的文档或图像的所需区域。使用这些滚动箭头时，滑块手柄的位置移动以显示文档或图像内的当前位置。

+   **页面控制**: 页面控制是滑块手柄拖动的滚动条的背景。单击背景时，滑块手柄向单击位置移动一个页面。滑块手柄移动的量可以通过 pageStep 属性指定。页面步进是用户按下*Page Up*和*Page Down*键时滑块移动的量。您可以使用`setPageStep()`方法设置 pageStep 属性的量。

用于设置和检索滚动条的值的特定方法是`value()`方法，这里进行了描述。

`value()`方法获取滑块手柄的值，即其距离滚动条起始位置的距离值。当滑块手柄在垂直滚动条的顶部边缘或水平滚动条的左边缘时，您会得到滚动条的最小值；当滑块手柄在垂直滚动条的底部边缘或水平滚动条的右边缘时，您会得到滚动条的最大值。您也可以通过键盘将滑块手柄移动到其最小和最大值，分别按下*Home*和*End*键。让我们来看看以下方法：

+   `setValue()`: 此方法将值分配给滚动条，并根据分配的值设置滑块手柄在滚动条中的位置

+   `minimum()`: 此方法返回滚动条的最小值

+   `maximum()`: 此方法返回滚动条的最大值

+   `setMinimum()`: 此方法将最小值分配给滚动条

+   `setMaximum()`: 此方法将最大值分配给滚动条

+   `setSingleStep()`: 此方法设置单步值

+   `setPageStep()`: 此方法设置页面步进值

`QScrollBar`仅提供整数值。

通过`QScrollBar`类发出的信号如下所示：

+   valueChanged(): 当滚动条的值发生变化时发出此信号，即当其滑块手柄移动时

+   sliderPressed(): 当用户开始拖动滑块手柄时发出此信号

+   sliderMoved(): 当用户拖动滑块手柄时发出此信号

+   sliderReleased(): 当用户释放滑块手柄时发出此信号

+   actionTriggered(): 当用户交互改变滚动条时发出此信号

滑块通常用于表示某个整数值。与滚动条不同，滚动条大多用于显示大型文档或图像，滑块是交互式的，是输入或表示整数值的更简单的方式。也就是说，通过移动和定位其手柄沿水平或垂直槽，可以使水平或垂直滑块表示某个整数值。为了显示水平和垂直滑块，使用了`HorizontalSlider`和`VerticalSlider`小部件，它们是`QSlider`类的实例。与我们在滚动条中看到的方法类似，滑块在移动滑块手柄时也会生成信号，例如`valueChanged()`，`sliderPressed()`，`sliderMoved()`，`sliderReleased()`等等。

滚动条和滑块中的滑块手柄表示在最小和最大范围内的值。要更改默认的最小和最大值，可以通过为 minimum、maximum、singleStep 和 pageStep 属性分配值来更改它们的值。

滑块的最小值、最大值、singleStep、pageStep 和 value 属性的默认值分别为 0、99、1、10 和 0。

让我们创建一个应用程序，其中包括水平和垂直滚动条，以及水平和垂直滑块。水平滚动条和滑块将分别表示血糖水平和血压。也就是说，移动水平滚动条时，患者的血糖水平将通过行编辑小部件显示。同样，移动水平滑块时，将表示血压，并通过行编辑小部件显示。

垂直滚动条和滑块将分别表示心率和胆固醇水平。移动垂直滚动条时，心率将通过行编辑小部件显示，移动垂直滑块时，胆固醇水平将通过行编辑小部件显示。

# 操作步骤...

为了理解水平和垂直滚动条的工作原理，以及水平和垂直滑块的工作原理，了解滚动条和滑块在值更改时如何生成信号，以及如何将相应的槽或方法与它们关联，执行以下步骤：

1.  让我们创建一个新的对话框应用程序，没有按钮模板，并将水平和垂直滚动条和滑块拖放到表单上。

1.  将四个标签小部件和一个行编辑小部件放置到显示滚动条和滑块手柄值的位置。

1.  将四个标签小部件的 text 属性分别设置为`血糖水平`，`血压`，`脉搏率`和`胆固醇`。

1.  将水平滚动条的 objectName 属性设置为`horizontalScrollBarSugarLevel`，垂直滚动条的 objectName 属性设置为`verticalScrollBarPulseRate`，水平滑块的 objectName 属性设置为`horizontalSliderBloodPressure`，垂直滑块的 objectName 属性设置为`verticalSliderCholestrolLevel`。

1.  将行编辑小部件的 objectName 属性设置为`lineEditResult`。

1.  将应用程序保存为名称为`demoSliders.ui`的文件。表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e9694361-d6d4-4f0d-a343-05e70ae1ea91.png)

`pyuic5`命令实用程序将把`.ui`（XML）文件转换为 Python 代码。生成的 Python 文件`demoScrollBar.py`可以在本书的源代码包中找到。

1.  创建一个名为`callScrollBar.pyw`的 Python 脚本文件，导入代码`demoScrollBar.py`，以调用用户界面设计并同步滚动条和滑块手柄的移动。该脚本还将通过标签小部件显示滚动条和滑块手柄的值。Python 脚本`callScrollBar.pyw`将显示如下：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoScrollBar import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.horizontalScrollBarSugarLevel.valueChanged.connect
        (self.scrollhorizontal)
        self.ui.verticalScrollBarPulseRate.valueChanged.connect
        (self.scrollvertical)
        self.ui.horizontalSliderBloodPressure.valueChanged.connect
        (self.sliderhorizontal)
        self.ui.verticalSliderCholestrolLevel.valueChanged.connect
        (self.slidervertical)
        self.show()
    def scrollhorizontal(self,value):
        self.ui.lineEditResult.setText("Sugar Level : "+str(value))
    def scrollvertical(self, value):
        self.ui.lineEditResult.setText("Pulse Rate : "+str(value))
    def sliderhorizontal(self, value):
        self.ui.lineEditResult.setText("Blood Pressure :  
        "+str(value))
    def slidervertical(self, value):
        self.ui.lineEditResult.setText("Cholestrol Level : 
        "+str(value))
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在此代码中，您正在将每个窗口部件的`valueChanged()`信号与相应的函数连接起来，以便如果窗口部件的滚动条或滑块移动，将调用相应的函数来执行所需的任务。例如，当水平滚动条的滑块移动时，将调用`scrollhorizontal`函数。`scrollhorizontal`函数通过 Label 窗口部件显示滚动条表示的值，即血糖水平。

同样，当垂直滚动条或滑块的滑块移动时，将调用`scrollvertical`函数，并且垂直滚动条的滑块的值，即心率，将通过 Label 窗口部件显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/267f54e8-3456-4f03-aca5-19072ac1f550.png)

同样，当水平和垂直滑块移动时，血压和胆固醇水平会相应地显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/69d859b6-7ea2-4da1-8bc1-b9458ee448fc.png)

# 使用 List 窗口部件

要以更简单和可扩展的格式显示多个值，可以使用 List 窗口部件，它是`QListWidget`类的实例。List 窗口部件显示多个项目，不仅可以查看，还可以编辑和删除。您可以逐个添加或删除列表项目，也可以使用其内部模型集合地设置列表项目。

# 准备工作

列表中的项目是`QListWidgetItem`类的实例。`QListWidget`提供的方法如下所示：

+   `insertItem()`: 此方法将提供的文本插入到 List 窗口部件的指定位置。

+   `insertItems()`: 此方法从提供的列表中的指定位置开始插入多个项目。

+   `count()`: 此方法返回列表中项目数量的计数。

+   `takeItem()`: 此方法从列表窗口中指定的行中移除并返回项目。

+   `currentItem()`: 此方法返回列表中的当前项目。

+   `setCurrentItem()`: 此方法用指定的项目替换列表中的当前项目。

+   `addItem()`: 此方法将具有指定文本的项目附加到 List 窗口部件的末尾。

+   `addItems()`: 此方法将提供的列表中的项目附加到 List 窗口部件的末尾。

+   `clear()`: 此方法从 List 窗口部件中移除所有项目。

+   `currentRow()`: 此方法返回当前选定列表项的行号。如果未选择列表项，则返回值为`-1`。

+   `setCurrentRow()`: 此方法选择 List 窗口部件中的指定行。

+   `item()`: 此方法返回指定行处的列表项。

`QListWidget`类发出的信号如下所示：

+   currentRowChanged(): 当当前列表项的行更改时发出此信号

+   currentTextChanged(): 当当前列表项中的文本更改时发出此信号

+   currentItemChanged(): 当当前列表项的焦点更改时发出此信号

# 如何做...

因此，让我们创建一个应用程序，通过 List 窗口部件显示特定的诊断测试，并且当用户从 List 窗口部件中选择任何测试时，所选测试将通过 Label 窗口部件显示。以下是创建应用程序的逐步过程：

1.  创建一个没有按钮模板的对话框的新应用程序，并将两个 Label 窗口部件和一个 List 窗口部件拖放到表单上。

1.  将第一个 Label 窗口部件的文本属性设置为“选择诊断测试”。

1.  将 List 窗口部件的 objectName 属性设置为`listWidgetDiagnosis`。

1.  将 Label 窗口部件的 objectName 属性设置为`labelTest`。

1.  删除`labelTest`窗口部件的默认文本属性，因为我们将通过代码通过此窗口部件显示所选的诊断测试。

1.  要通过 List 窗口部件显示诊断测试，请右键单击它，并从打开的上下文菜单中选择“编辑项目”选项。

1.  逐个添加诊断测试，然后在输入每个测试后单击底部的+按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f88c1e1d-2934-4bd7-a0ba-37acd3757fca.png)

1.  使用名称`demoListWidget1.ui`保存应用程序。表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/46334250-f059-4b61-a0d8-413c80e98db3.png)

`pyuic5`命令实用程序将把`.ui`（XML）文件转换为 Python 代码。生成的 Python 代码`demoListWidget1.py`可以在本书的源代码包中看到。

1.  创建一个名为`callListWidget1.pyw`的 Python 脚本文件，导入代码`demoListWidget1.py`，以调用用户界面设计和从列表窗口中显示所选的诊断测试的代码。Python 脚本`callListWidget1.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoListWidget1 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.listWidgetDiagnosis.itemClicked.connect(self.
        dispSelectedTest)
        self.show()
    def dispSelectedTest(self):
        self.ui.labelTest.setText("You have selected 
        "+self.ui.listWidgetDiagnosis.currentItem().text())
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以看到列表窗口的`itemClicked`事件连接到`dispSelectedTest()`方法。也就是说，单击列表窗口中的任何列表项时，将调用`dispSelectedTest()`方法，该方法使用列表窗口的`currentItem`方法通过名为`labelTest`的标签显示列表窗口的所选项目。

运行应用程序时，您将看到列表窗口显示一些诊断测试；从列表窗口中选择一个测试，该测试将通过 Label 窗口显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/989c3543-3303-45f5-ae47-1f09e11d3090.png)

# 从一个列表窗口中选择多个列表项，并在另一个列表窗口中显示它们

在前面的应用程序中，您只从列表窗口中选择了单个诊断测试。如果我想要从列表窗口中进行多重选择怎么办？在进行多重选择的情况下，您需要另一个列表窗口来存储所选的诊断测试，而不是使用行编辑窗口。

# 如何做...

让我们创建一个应用程序，通过列表窗口显示特定的诊断测试，当用户从列表窗口中选择任何测试时，所选测试将显示在另一个列表窗口中：

1.  因此，创建一个没有按钮模板的对话框的新应用程序，并将两个 Label 窗口小部件和两个列表窗口拖放到表单上。

1.  将第一个 Label 窗口小部件的文本属性设置为`诊断测试`，另一个设置为`已选择的测试为`。

1.  将第一个列表窗口的 objectName 属性设置为`listWidgetDiagnosis`，第二个列表窗口的设置为`listWidgetSelectedTests`。

1.  要通过列表窗口显示诊断测试，请右键单击它，从打开的上下文菜单中选择“编辑项目”选项。

1.  逐个添加诊断测试，然后在输入每个测试后单击底部的+按钮。

1.  要从列表窗口启用多重选择，请选择`listWidgetDiagnosis`窗口小部件，并从属性编辑器窗口中将 selectionMode 属性从`SingleSelection`更改为`MultiSelection`。

1.  使用名称`demoListWidget2.ui`保存应用程序。表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/62a52de1-daaf-4e26-a240-17cd71be81d7.png)

通过使用`pyuic5`实用程序，XML 文件`demoListWidget2.ui`将被转换为 Python 代码，即`demoListWidget2.py`文件。可以在本书的源代码包中看到从`demoListWidget2.py`文件生成的 Python 代码。

1.  创建一个名为`callListWidget2.pyw`的 Python 脚本文件，导入代码`demoListWidget2.py`，以调用用户界面设计和显示从列表窗口中选择的多个诊断测试的代码。Python 脚本`callListWidget2.pyw`将显示如下：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoListWidget2 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.listWidgetDiagnosis.itemSelectionChanged.connect
        (self.dispSelectedTest)
        self.show()
    def dispSelectedTest(self):
        self.ui.listWidgetSelectedTests.clear()
        items = self.ui.listWidgetDiagnosis.selectedItems()
        for i in list(items):
            self.ui.listWidgetSelectedTests.addItem(i.text())
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

您可以看到，第一个列表小部件的`itemSelectionChanged`事件连接到`dispSelectedTest()`方法。也就是说，在从第一个列表小部件中选择或取消选择任何列表项目时，将调用`dispSelectedTest()`方法。`dispSelectedTest()`方法调用列表小部件上的`selectedItems()`方法以获取所有选定项目的列表。然后，使用`for`循环，通过在第二个列表小部件上调用`addItem()`方法，将所有选定的项目添加到第二个列表小部件中。

运行应用程序时，您将看到列表小部件显示一些诊断测试；从第一个列表小部件中选择任意数量的测试，所有选定的测试将通过第二个列表小部件项目显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/e8efd76e-aedb-4ecc-ac45-fd7f615126a9.png)

# 向列表小部件添加项目

虽然您可以通过属性编辑器手动向列表小部件添加项目，但有时需要通过代码动态向列表小部件添加项目。让我们创建一个应用程序，解释向列表小部件添加项目的过程。

在此应用程序中，您将使用标签、行编辑、按钮和列表小部件。列表小部件项目最初将为空，并要求用户将所需的食物项目输入到行编辑中，并选择“添加到列表”按钮。然后将输入的食物项目添加到列表小部件项目中。所有后续的食物项目将添加到上一个条目下方。

# 如何做...

执行以下步骤以了解如何向列表小部件项目添加项目：

1.  我们将从基于无按钮对话框模板创建一个新应用程序开始，并将标签、行编辑、按钮和列表小部件拖放到表单中。

1.  将标签和按钮小部件的文本属性分别设置为“您最喜欢的食物项目”和“添加到列表”。

1.  将行编辑小部件的 objectName 属性设置为`lineEditFoodItem`，按钮的 objectName 设置为`pushButtonAdd`，列表小部件的 objectName 设置为`listWidgetSelectedItems`。

1.  将应用程序保存为`demoListWidget3.ui`。表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f7f06759-0127-48e4-93fd-83b746974b69.png)

在执行`pyuic5`实用程序时，XML 文件`demoListWidget3.ui`将被转换为 Python 代码`demoListWidget3.py`。生成的 Python 文件`demoListWidget3.py`的代码可以在本书的源代码包中找到。

1.  创建一个名为`callListWidget3.pyw`的 Python 脚本文件，导入 Python 代码`demoListWidget3.py`以调用用户界面设计，并将用户在行编辑中输入的食物项目添加到列表小部件中。`callListWidget3.pyw`文件中的 Python 代码将如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoListWidget3 import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonAdd.clicked.connect(self.addlist)
        self.show()
    def addlist(self):
        self.ui.listWidgetSelectedItems.addItem(self.ui.
        lineEditFoodItem.text())
        self.ui.lineEditFoodItem.setText('')
        self.ui.lineEditFoodItem.setFocus()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

将按钮小部件的 clicked()事件连接到`addlist`函数。因此，在在行编辑小部件中输入要添加到列表小部件中的文本后，当用户选择“添加到列表”按钮时，将调用`addlist`函数。`addlist`函数检索在行编辑中输入的文本，并将其添加到列表小部件中。然后，清除行编辑小部件中的文本，并将焦点设置在它上面，使用户能够输入不同的文本。

在下面的截图中，您可以看到用户在行编辑小部件中输入的文本在用户选择“添加到列表”按钮时添加到列表小部件中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/29ad3de8-401c-4098-a53c-c40863d88069.png)

# 在列表小部件中执行操作

在这个示例中，您将学习如何在 List Widget 中执行不同的操作。List Widget 基本上用于显示一组相似的项目，使用户能够选择所需的项目。因此，您需要向 List Widget 添加项目。此外，您可能需要编辑 List Widget 中的任何项目。有时，您可能需要从 List Widget 中删除项目。您可能还希望对 List Widget 执行的另一个操作是删除其中的所有项目，清除整个 List Widget 项目。在学习如何向 List Widget 添加、编辑和删除项目之前，让我们先了解列表项的概念。

# 准备工作

List Widget 包含多个列表项。这些列表项是`QListWidgetItem`类的实例。可以使用`insertItem()`或`addItem()`方法将列表项插入 List Widget 中。列表项可以是文本或图标形式，并且可以被选中或取消选中。`QListWidgetItem`提供的方法如下。

# `QListWidgetItem`类提供的方法

让我们来看看`QListWidgetItem`类提供的以下方法：

+   `setText()`: 这个方法将指定的文本分配给列表项

+   `setIcon()`: 这个方法将指定的图标分配给列表项

+   `checkState()`: 这个方法根据列表项是选中还是未选中状态返回布尔值

+   `setHidden()`: 这个方法将布尔值 true 传递给这个方法以隐藏列表项

+   `isHidden()`: 如果列表项被隐藏，这个方法返回 true

我们已经学会了向 List Widget 添加项目。如果您想编辑 List Widget 中的现有项目，或者您想从 List Widget 中删除项目，或者您想从 List Widget 中删除所有项目呢？

让我们通过创建一个应用程序来学习在列表小部件上执行不同的操作。这个应用程序将显示 Line Edit，List Widget 和一对 Push Button 小部件。您可以通过在 Line Edit 中输入文本，然后单击“Add”按钮来向 List Widget 添加项目。同样，您可以通过单击 List Widget 中的项目，然后单击“Edit”按钮来编辑 List Widget 中的任何项目。不仅如此，您甚至可以通过单击“Delete”按钮来删除 List Widget 中的任何项目。如果您想清除整个 List Widget，只需单击“Delete All”按钮。

# 如何做....

执行以下步骤以了解如何在列表小部件上应用不同的操作；如何向列表小部件添加、编辑和删除项目；以及如何清除整个列表小部件：

1.  打开 Qt Designer，基于无按钮模板创建一个新应用程序，并将一个标签、一个 Line Edit、四个 Push Button 和 List Widget 小部件拖放到表单上。

1.  将标签小部件的文本属性设置为`Enter an item`。

1.  将四个 Push Button 小部件的文本属性设置为`Add`，`Edit`，`Delete`和`Delete All`。

1.  将四个 Push Button 小部件的 objectName 属性设置为`psuhButtonAdd`，`pushButtonEdit`，`pushButtonDelete`和`pushButtonDeleteAll`。

1.  将应用程序保存为`demoListWidgetOp.ui`。

表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/a15bca18-c4e6-4674-8be7-c898809bc6dc.png)

需要使用`pyuic5`命令实用程序将 XML 文件`demoListWidgetOp.ui`转换为 Python 脚本。本书的源代码包中可以看到生成的 Python 文件`demoListWidgetOp.py`。

1.  创建一个名为`callListWidgetOp.pyw`的 Python 脚本文件，导入 Python 代码`demoListWidgetOp.py`，使您能够调用用户界面设计并在 List Widget 中添加、删除和编辑列表项。Python 脚本`callListWidgetOp.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication, QInputDialog, QListWidgetItem
from demoListWidgetOp import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.listWidget.addItem('Ice Cream')
        self.ui.listWidget.addItem('Soda')
        self.ui.listWidget.addItem('Coffee')
        self.ui.listWidget.addItem('Chocolate')
        self.ui.pushButtonAdd.clicked.connect(self.addlist)
        self.ui.pushButtonEdit.clicked.connect(self.editlist)
        self.ui.pushButtonDelete.clicked.connect(self.delitem)
        self.ui.pushButtonDeleteAll.clicked.connect
        (self.delallitems)
        self.show()
    def addlist(self):
        self.ui.listWidget.addItem(self.ui.lineEdit.text())
        self.ui.lineEdit.setText('')
        self.ui.lineEdit.setFocus()
    def editlist(self):
        row=self.ui.listWidget.currentRow()
        newtext, ok=QInputDialog.getText(self, "Enter new text", 
        "Enter new text")
        if ok and (len(newtext) !=0):
                self.ui.listWidget.takeItem(self.ui.listWidget.
                currentRow())
                self.ui.listWidget.insertItem(row,
                QListWidgetItem(newtext))
    def delitem(self):
        self.ui.listWidget.takeItem(self.ui.listWidget.
        currentRow())
    def delallitems(self):
        self.ui.listWidget.clear()
if __name__=="__main__":
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 它是如何工作的...

`pushButtonAdd`的 clicked()事件连接到`addlist`函数。同样，`pushButtonEdit`，`pushButtonDelete`和`pushButtonDeleteAll`对象的 clicked()事件分别连接到`editlist`，`delitem`和`delallitems`函数。也就是说，单击任何按钮时，将调用相应的函数。`addlist`函数调用`addItem`函数来添加在 Line Edit 部件中输入的文本。`editlist`函数使用 List Widget 上的`currentRow`方法来找出要编辑的列表项目。

调用`QInputDialog`类的`getText`方法来提示用户输入新文本或编辑文本。在对话框中单击 OK 按钮后，当前列表项目将被对话框中输入的文本替换。`delitem`函数调用 List Widget 上的`takeItem`方法来删除当前行，即所选的列表项目。`delallitems`函数调用 List Widget 上的`clear`方法来清除或删除 List Widget 中的所有列表项目。

运行应用程序后，您将在 Line Edit 部件下方找到一个空的 List Widget、Line Edit 和 Add 按钮。在 Line Edit 部件中添加任何文本，然后单击添加按钮将该项目添加到 List Widget 中。在 List Widget 中添加了四个项目后，可能会显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f3ab5ae8-fe93-46e6-bc4d-4edfb5f2f9bb.png)

让我们向 List Widget 中再添加一个项目 Pizza。在 Line Edit 部件中输入`Pizza`，然后单击添加按钮。Pizza 项目将被添加到 List Widget 中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/dac59a1d-1586-4ae6-96c2-86f6cbe5c05b.png)

假设我们要编辑 List Widget 中的 Pizza 项目，点击 List Widget 中的 Pizza 项目，然后点击编辑按钮。单击编辑按钮后，将弹出一个对话框，提示您输入一个新项目来替换 Pizza 项目。让我们在对话框中输入`Cold Drink`，然后单击 OK 按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/eb1432ea-258f-4eb5-b620-2b28fc01782f.png)

在下面的截图中，您可以看到列表部件中的 Pizza 项目被文本 Cold Drink 替换：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d19c2923-1402-4399-8c88-3b3883a1cce3.png)

要从列表部件中删除任何项目，只需点击列表部件中的项目，然后点击删除按钮。让我们点击列表部件中的 Coffee 项目，然后点击删除按钮；如下截图所示，Coffee 项目将从列表部件中删除：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/877ff850-e8c9-48eb-896c-27e14a12e9d7.png)

单击删除所有按钮后，整个 List Widget 项目将变为空，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/bbf1152c-f749-4aad-82c3-184593fc8a81.png)

# 使用组合框部件

组合框用于从用户那里获取输入，并应用约束；也就是说，用户将以弹出列表的形式看到某些选项，他/她只能从可用选项中选择。与 List Widget 相比，组合框占用更少的空间。`QComboBox`类用于显示组合框。您不仅可以通过组合框显示文本，还可以显示`pixmaps`。以下是`QComboBox`类提供的方法：

| **方法** | **用途** |
| --- | --- |
| `setItemText()` | 设置或更改组合框中项目的文本。 |
| `removeItem()` | 从组合框中删除特定项目。 |
| `clear()` | 从组合框中删除所有项目。 |
| `currentText()` | 返回当前项目的文本，即当前选择的项目。 |
| `setCurrentIndex()` | 设置组合框的当前索引，即将组合框中的所需项目设置为当前选择的项目。 |
| `count()` | 返回组合框中项目的计数。 |
| `setMaxCount()` | 设置允许在组合框中的最大项目数。 |
| `setEditable()` | 使组合框可编辑，即用户可以编辑组合框中的项目。 |
| `addItem()` | 将指定内容附加到组合框中。 |
| `addItems()` | 将提供的每个字符串附加到组合框中。 |
| `itemText()` | 返回组合框中指定索引位置的文本。 |
| `currentIndex()` | 返回组合框中当前选择项目的索引位置。如果组合框为空或组合框中当前未选择任何项目，则该方法将返回`-1`作为索引。 |

以下是由`QComboBox`生成的信号：

| **信号** | **描述** |
| --- | --- |
| currentIndexChanged() | 当组合框的索引更改时发出，即用户在组合框中选择了一些新项目。 |
| activated() | 当用户更改索引时发出。 |
| highlighted() | 当用户在组合框中突出显示项目时发出。 |
| editTextChanged() | 当可编辑组合框的文本更改时发出。 |

为了实际了解组合框的工作原理，让我们创建一个示例。这个示例将通过一个组合框显示特定的银行账户类型，并提示用户选择他/她想要开设的银行账户类型。通过组合框选择的银行账户类型将通过`Label`小部件显示在屏幕上。

# 如何做…

以下是创建一个应用程序的步骤，该应用程序利用组合框显示某些选项，并解释了如何显示来自组合框的所选选项：

1.  创建一个没有按钮的对话框的新应用程序模板，从小部件框中拖动两个 Label 小部件和一个 Combo Box 小部件，并将它们放到表单中。

1.  将第一个 Label 小部件的文本属性设置为`选择您的账户类型`。

1.  删除第二个 Label 小部件的默认文本属性，因为其文本将通过代码设置。

1.  将组合框小部件的 objectName 属性设置为`comboBoxAccountType`。

1.  第二个 Label 小部件将用于显示用户选择的银行账户类型，因此将第二个 Label 小部件的 objectName 属性设置为`labelAccountType`。

1.  由于我们希望组合框小部件显示特定的银行账户类型，因此右键单击组合框小部件，并从打开的上下文菜单中选择编辑项目选项。

1.  逐个向组合框小部件添加一些银行账户类型。

1.  将应用程序保存为`demoComboBox.ui`。

1.  单击对话框底部显示的+按钮，将银行账户类型添加到组合框小部件中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f949873b-a195-402c-b874-ed1b68424b5f.png)

1.  在添加所需的银行账户类型后，单击“确定”按钮退出对话框。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/d8e57706-8767-492e-9c85-d22cfaf04fbb.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。可以使用`pyuic5`实用程序从 XML 文件生成 Python 代码。生成的文件`demoComboBox.py`可以在本书的源代码包中看到。

1.  将`demoComboBox.py`文件视为头文件，并将其导入到将调用其用户界面设计的文件中，这样您就可以访问组合框。

1.  创建另一个名为`callComboBox.pyw`的 Python 文件，并将`demoComboBox.py`的代码导入其中。Python 脚本`callComboBox.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoComboBox import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.comboBoxAccountType.currentIndexChanged.connect
        (self.dispAccountType)
        self.show()

    def dispAccountType(self):
        self.ui.labelAccountType.setText("You have selected 
        "+self.ui.comboBoxAccountType.itemText(self.ui.
        comboBoxAccountType.currentIndex())) 

if __name__=="__main__":   
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理…

在`demoComboBox.py`文件中，创建了一个名为顶级对象的类，其名称为`Ui_ prepended`。也就是说，对于顶级对象`Dialog`，创建了`Ui_Dialog`类，并存储了我们小部件的接口元素。该类包括两种方法，`setupUi`和`retranslateUi`。

`setupUi`方法创建了在 Qt Designer 中定义用户界面时使用的小部件。此方法还设置了小部件的属性。`setupUi`方法接受一个参数，即应用程序的顶层小部件，即`QDialog`的一个实例。`retranslateUi`方法用于翻译界面。

在`callComboBox.pyw`文件中，每当用户从组合框中选择任何项目时，`currentIndexChanged`信号将被发射，并且`currentIndexChanged`信号连接到`dispAccountType`方法，因此每当从组合框中选择任何项目时，`dispAccountType`方法将被调用。

在`dispAccountType`方法中，通过调用`QComboBox`类的`currentIndex`方法来访问当前选定的索引号，并将获取的索引位置传递给`QComboBox`类的`itemText`方法，以获取当前选定的组合框项目的文本。然后通过标签小部件显示当前选定的组合框项目。

运行应用程序时，您将看到一个下拉框显示四种银行账户类型：储蓄账户、活期账户、定期存款账户和定期存款账户，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/1bb48fee-e2aa-42b9-8837-da3970018460.png)

从组合框中选择一个银行账户类型后，所选的银行账户类型将通过标签小部件显示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/7f09f615-47ce-4645-ae6d-308a5ee1430d.png)

# 使用字体组合框小部件

字体组合框小部件，顾名思义，显示一个可选择的字体样式列表。如果需要，所选的字体样式可以应用到所需的内容中。

# 准备工作

为了实际理解字体组合框小部件的工作原理，让我们创建一个示例。这个示例将显示一个字体组合框小部件和一个文本编辑小部件。用户可以在文本编辑小部件中输入所需的内容。在文本编辑小部件中输入文本后，当用户从字体组合框小部件中选择任何字体样式时，所选字体将被应用到文本编辑小部件中输入的内容。

# 如何做…

以下是显示活动字体组合框小部件并将所选字体应用于文本编辑小部件中的文本的步骤：

1.  创建一个没有按钮的对话框模板的新应用程序，并从小部件框中拖动两个标签小部件、一个字体组合框小部件和一个文本编辑小部件，并将它们放到表单上。

1.  将第一个标签小部件的文本属性设置为`选择所需的字体`，将第二个标签小部件的文本属性设置为`输入一些文本`。

1.  将应用程序保存为`demoFontComboBox.ui`。表单现在将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6422b45f-9351-46f8-a76a-87798511ab90.png)

使用 Qt Designer 创建的用户界面存储在一个`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。转换为 Python 代码后，生成的文件`demoFontComboBox.py`将在本书的源代码包中可见。上述代码将被用作头文件，并被导入到需要 GUI 的文件中，也就是说，设计的用户界面可以通过简单地导入上述代码在任何 Python 脚本中访问。

1.  创建另一个名为`callFontFontComboBox.pyw`的 Python 文件，并将`demoFontComboBox.py`代码导入其中。

Python 脚本`callFontComboBox.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoFontComboBox import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        myFont=QtGui.QFont(self.ui.fontComboBox.itemText(self.ui.
        fontComboBox.currentIndex()),15)
        self.ui.textEdit.setFont(myFont)
        self.ui.fontComboBox.currentFontChanged.connect
        (self.changeFont)
        self.show()
    def changeFont(self):
        myFont=QtGui.QFont(self.ui.fontComboBox.itemText(self.ui.
        fontComboBox.currentIndex()),15)
        self.ui.textEdit.setFont(myFont)
if __name__=="__main__":   
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理...

在`callFontComboBox.pyw`文件中，每当用户从字体组合框小部件中选择任何字体样式时，将发射`currentFontChanged`信号，并且该信号连接到`changeFont`方法，因此每当从字体组合框小部件中选择任何字体样式时，将调用`changeFont()`方法。

在`changeFont()`方法中，通过调用两个方法来访问所选的字体样式。首先调用的是`QFontComboBox`类的`currentIndex()`方法，该方法获取所选字体样式的索引号。然后调用的是`itemText()`方法，并将当前所选字体样式的索引位置传递给该方法，以访问所选的字体样式。然后将所选的字体样式应用于文本编辑小部件中的内容。

运行应用程序时，您将看到一个字体组合框小部件，显示系统中可用的字体样式，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/f886b743-3310-4daa-9245-852c3926c46a.png)

在文本编辑小部件中输入一些文本，并从字体组合框中选择所需的字体。所选的字体样式将应用于文本编辑小部件中的文本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/058646f2-31d3-4a67-adf1-60a195d177fd.png)

# 使用进度条小部件

进度条小部件在表示任何任务的进度时非常有用。无论是从服务器下载文件，还是在计算机上进行病毒扫描，或者其他一些关键任务，进度条小部件都有助于通知用户任务完成的百分比和待处理的百分比。随着任务的完成，进度条小部件不断更新，指示任务的进展。

# 准备工作

为了理解如何更新进度条以显示任何任务的进度，让我们创建一个示例。这个示例将显示一个进度条小部件，指示下载文件所需的总时间。当用户点击推送按钮开始下载文件时，进度条小部件将从 0%逐渐更新到 100%；也就是说，随着文件的下载，进度条将更新。当文件完全下载时，进度条小部件将显示 100%。

# 如何做…

最初，进度条小部件为 0%，为了使其增加，我们需要使用循环。随着进度条小部件表示的任务向完成的进展，循环将增加其值。循环值的每次增加都会增加进度条小部件的一些进度。以下是逐步过程，展示了如何更新进度条：

1.  从没有按钮的对话框模板创建一个新应用程序，并从小部件框中拖动一个标签小部件、一个进度条小部件和一个推送按钮小部件，然后将它们放到表单上。

1.  将标签小部件的文本属性设置为`下载文件`，将推送按钮小部件的文本属性设置为`开始下载`。

1.  将推送按钮小部件的 objectName 属性设置为`pushButtonStart`。

1.  将应用程序保存为`demoProgressBar.ui`。现在表单将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b1652ac9-b923-490a-b769-fb30070ac1f3.png)

使用 Qt Designer 创建的用户界面存储在`.ui`文件中，这是一个 XML 文件，需要转换为 Python 代码。生成的 Python 代码`demoProgressBar.py`可以在本书的源代码包中找到。上述代码将用作头文件，并导入到需要 GUI 的文件中；也就是说，代码中设计的用户界面可以通过简单导入上述代码在任何 Python 脚本中访问。

1.  创建另一个名为`callProgressBar.pyw`的 Python 文件，并将`demoProgressBar.py`代码导入其中。Python 脚本`callProgressBar.pyw`中的代码如下所示：

```py
import sys
from PyQt5.QtWidgets import QDialog, QApplication
from demoProgressBar import *
class MyForm(QDialog):
    def __init__(self):
        super().__init__()
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.pushButtonStart.clicked.connect(self.updateBar)
        self.show()

    def updateBar(self):
        x = 0
        while x < 100:
            x += 0.0001
            self.ui.progressBar.setValue(x)

if __name__=="__main__":   
    app = QApplication(sys.argv)
    w = MyForm()
    w.show()
    sys.exit(app.exec_())
```

# 工作原理…

在`callProgressBar.pyw`文件中，因为我们希望在按下按钮时进度条显示其进度，所以将进度条的 clicked()事件连接到`updateBar()`方法，因此当按下按钮时，将调用`updateBar()`方法。在`updateBar()`方法中，使用了一个`while`循环，从`0`到`100`循环。一个变量`x`被初始化为值`0`。在 while 循环的每次迭代中，变量`x`的值增加了`0.0001`。在更新进度条时，将`x`变量的值应用于进度条。也就是说，每次 while 循环的迭代中，变量`x`的值都会增加，并且变量`x`的值会用于更新进度条。因此，进度条将从 0%开始逐渐增加，直到达到 100%。

在运行应用程序时，最初，您会发现进度条小部件为 0%，底部有一个带有标题“开始下载”的按钮（请参见以下屏幕截图）。单击“开始下载”按钮，您会看到进度条开始逐渐显示进度。进度条会持续增加，直到达到 100%，表示文件已完全下载：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/07e662a1-24bf-46c4-97b3-be0ce58f4577.png)
