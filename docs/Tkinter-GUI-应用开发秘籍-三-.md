# Tkinter GUI 应用开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/398a043f4e87ae54140cbfe923282feb`](https://zh.annas-archive.org/md5/398a043f4e87ae54140cbfe923282feb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：画布和图形

在本章中，我们将涵盖以下配方：

+   了解坐标系统

+   绘制线条和箭头

+   在画布上写字

+   向画布添加形状

+   通过它们的位置查找项目

+   移动画布项目

+   检测项目之间的碰撞

+   从画布中删除项目

+   将事件绑定到画布项目

+   将画布渲染成 PostScript 文件

# 介绍

在第一章中，我们涵盖了标准 Tkinter 小部件的几个配方。但是，我们跳过了**Canvas**小部件，因为它提供了丰富的图形功能，并且值得单独的章节来深入了解其常见用例。

画布是一个矩形区域，您不仅可以在其中显示文本和几何形状，如线条、矩形或椭圆，还可以嵌套其他 Tkinter 小部件。这些对象称为**画布项目**，每个项目都有一个唯一的标识符，允许我们在它们最初显示在画布上之前对它们进行操作。

我们将使用`Canvas`类的方法进行交互示例，这将帮助我们识别可能转换为我们想要构建的应用程序的常见模式。

# 了解坐标系统

要在画布上绘制图形项目，我们需要使用**坐标系统**指定它们的位置。由于画布是二维空间，点将通过它们在水平和垂直轴上的坐标来表示——通常分别标记为*x*和*y*。

通过一个简单的应用程序，我们可以很容易地说明如何定位这些点与坐标系统原点的关系，该原点位于画布区域的左上角。

# 如何做...

以下程序包含一个空画布和一个标签，显示光标在画布上的位置；您可以移动光标以查看其所处的位置，清晰地反映了鼠标指针移动的方向，x 和 y 坐标是如何增加或减少的：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Basic canvas")

        self.canvas = tk.Canvas(self, bg="white")
        self.label = tk.Label(self)
        self.canvas.bind("<Motion>", self.mouse_motion)

        self.canvas.pack()
        self.label.pack()

    def mouse_motion(self, event):
        x, y = event.x, event.y
        text = "Mouse position: ({}, {})".format(x, y)
        self.label.config(text=text)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

`Canvas`实例像其他 Tkinter 小部件一样创建，即首先通过将父容器和额外的配置选项作为关键字参数传递：

```py
    def __init__(self):
        # ...
        self.canvas = tk.Canvas(self, bg="white")
        self.label = tk.Label(self)
        self.canvas.bind("<Motion>", self.mouse_motion)
```

下一个屏幕截图显示了由每个轴的垂直投影组成的点：

+   x 坐标对应于水平轴上的距离，当您将光标从左向右移动时，其值会增加

+   y 坐标是垂直轴上的距离，当您将光标从上向下移动时，其值会增加

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/43cd19e1-fd63-49cd-8d6f-dbca306cb2c4.png)

正如您可能已经注意到的在前面的屏幕截图中，这些坐标直接映射到传递给处理程序的`event`实例的`x`和`y`属性：

```py
    def mouse_motion(self, event):
        x, y = event.x, event.y
 text = "Mouse position: ({}, {})".format(x, y)
        self.label.config(text=text)
```

这是因为这些属性是相对于事件绑定到的小部件计算的，在这种情况下是`<Motion>`序列。

# 还有更多...

画布表面还可以显示具有其坐标中的负值的项目。根据项目的大小，它们可能部分显示在画布的顶部或左边界上。

类似地，如果项目放置在任一坐标大于画布大小的点上，它可能部分落在底部或右边界之外。

# 绘制线条和箭头

您可以使用画布执行的最基本的操作之一是从一个点到另一个点绘制线段。虽然可以使用其他方法直接绘制多边形，但`Canvas`类的`create_line`方法具有足够的选项来理解显示项目的基础知识。

# 准备工作

在这个示例中，我们将构建一个应用程序，允许我们通过单击画布来绘制线条。每条线都将通过首先单击确定线条起点的点，然后第二次设置线条终点来显示。

我们还可以指定一些外观选项，如颜色和宽度：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/917ecb33-f662-47ac-9ef6-7cb7d79595a2.png)

# 如何做...

我们的`App`类将负责创建一个空画布并处理鼠标点击事件。

线选项的信息将从`LineForm`类中检索。将此组件分离到不同的类中的方法有助于我们抽象其实现细节，并专注于如何使用`Canvas`小部件。

为了简洁起见，我们在以下片段中省略了`LineForm`类的实现：

```py
import tkinter as tk

class LineForm(tk.LabelFrame):
    # ...

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Basic canvas")

        self.line_start = None
        self.form = LineForm(self)
        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.bind("<Button-1>", self.draw)

        self.form.pack(side=tk.LEFT, padx=10, pady=10)
        self.canvas.pack(side=tk.LEFT)

    def draw(self, event):
        x, y = event.x, event.y
        if not self.line_start:
            self.line_start = (x, y)
        else:
            x_origin, y_origin = self.line_start
            self.line_start = None
            line = (x_origin, y_origin, x, y)
            arrow = self.form.get_arrow()
            color = self.form.get_color()
            width = self.form.get_width()
            self.canvas.create_line(*line, arrow=arrow,
                                    fill=color, width=width)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

您可以在`chapter7_02.py`文件中找到完整的代码示例。

# 它是如何工作的...

由于我们想要处理画布上的鼠标点击，我们将`draw()`方法绑定到这种类型的事件。我们还将定义`line_start`字段

跟踪每条新线的起点：

```py
    def __init__(self):
        # ...

        self.line_start = None
        self.form = LineForm(self)
        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.bind("<Button-1>", self.draw)
```

`draw()`方法包含我们应用程序的主要逻辑。每条新线的第一次点击用于确定原点，并且不执行任何绘图操作。这些坐标是从传递给处理程序的`event`对象中检索的：

```py
    def draw(self, event):
 x, y = event.x, event.y
 if not self.line_start:
 self.line_start = (x, y)
        else:
            # ...
```

如果`line_start`已经有一个值，我们将检索原点，并将其与当前事件的坐标一起传递以绘制线条：

```py
    def draw(self, event):
        x, y = event.x, event.y
        if not self.line_start:
            # ...
        else:
            x_origin, y_origin = self.line_start
 self.line_start = None
 line = (x_origin, y_origin, x, y)
 self.canvas.create_line(*line)
 text = "Line drawn from ({}, {}) to ({}, {})".format(*line)
```

`canvas.create_line()`方法需要四个参数，前两个是线条起点的水平和垂直坐标，最后两个是与线条终点对应的坐标。

# 在画布上写文本

如果我们想在画布上写一些文本，我们不需要使用额外的小部件，比如 Label。`Canvas`类包括`create_text`方法来显示一个可以像任何其他类型的画布项一样操作的字符串。

还可以使用与我们可以指定的相同的格式选项来为常规 Tkinter 小部件的文本添加样式，例如颜色、字体系列和大小。

# 准备就绪

在这个例子中，我们将连接一个 Entry 小部件与文本画布项的内容。虽然输入将具有标准外观，但画布上的文本将具有自定义样式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/7fcc52e1-d1b6-43fe-a9ef-042f22b3b08f.png)

# 如何做...

文本项将首先使用`canvas.create_text()`方法显示，还有一些额外的选项来使用 Consolas 字体和蓝色。

文本项的动态行为将使用`StringVar`实现。通过跟踪这个 Tkinter 变量，我们可以修改项目的内容：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Canvas text items")
        self.geometry("300x100")

        self.var = tk.StringVar()
        self.entry = tk.Entry(self, textvariable=self.var)
        self.canvas = tk.Canvas(self, bg="white")

        self.entry.pack(pady=5)
        self.canvas.pack()
        self.update()

        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        options = { "font": "courier", "fill": "blue",
                    "activefill": "red" }
        self.text_id = self.canvas.create_text((w/2, h/2), **options)
        self.var.trace("w", self.write_text)

    def write_text(self, *args):
        self.canvas.itemconfig(self.text_id, text=self.var.get())

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

您可以通过在输入框中键入任意文本并注意它如何自动更新画布上的文本来尝试此程序。

# 它是如何工作的...

首先，我们使用其`StringVar`变量和 Canvas 小部件初始化`Entry`实例：

```py
        self.var = tk.StringVar()
        self.entry = tk.Entry(self, textvariable=self.var)
        self.canvas = tk.Canvas(self, bg="white")
```

然后，我们通过调用 Pack 几何管理器的方法来放置小部件。请注意调用根窗口上的`update()`的重要性，因为我们希望强制 Tkinter 处理所有未决的更改，在这种情况下在`__init__`方法继续执行之前渲染小部件：

```py
        self.entry.pack(pady=5)
        self.canvas.pack()
        self.update()
```

我们这样做是因为下一步将是计算画布的尺寸，直到几何管理器显示小部件，它才会有其宽度和高度的真实值。

之后，我们可以安全地检索画布的尺寸。由于我们想要将文本项与画布的中心对齐，我们将宽度和高度的值除以二。

这些坐标确定了项目的位置，并与样式选项一起传递给`create_text()`方法。`text`关键字参数在这里是一个常用选项，但我们将省略它，因为当`StringVar`更改其值时，它将被动态设置：

```py
        w, h = self.canvas.winfo_width(), self.canvas.winfo_height()
        options = { "font": "courier", "fill": "blue",
                    "activefill": "red" }
        self.text_id = self.canvas.create_text((w/2, h/2), **options)
        self.var.trace("w", self.write_text)
```

`create_text()`返回的标识符存储在`text_id`字段中。它将在`write_text()`方法中用于引用该项，该方法由`var`实例的写操作的跟踪机制调用。

要更新`write_text()`处理程序中的`text`选项，我们使用`canvas.itemconfig()`方法调用项目标识符作为第一个参数，然后是配置选项。

在我们的情况下，我们使用了我们在初始化`App`实例时存储的`text_id`字段和通过其`get()`方法获取的`StringVar`的内容：

```py
    def write_text(self, *args):
        self.canvas.itemconfig(self.text_id, text=self.var.get())
```

我们定义了`write_text()`方法，以便它可以接收可变数量的参数，即使我们不需要它们，因为 Tkinter 变量的`trace()`方法将它们传递给回调函数。

# 还有更多...

`canvas.create_text()` 方法有许多其他选项，可以自定义创建的画布项目。

# 通过其左上角放置文本

`anchor`选项允许我们控制相对于作为其`canvas.create_text()`的第一个参数传递的位置放置项目的位置。默认情况下，此选项值为`tk.CENTER`，这意味着文本小部件居中于这些坐标上。

如果要将文本放在画布的左上角，可以通过传递`(0, 0)`位置并将`anchor`选项设置为`tk.NW`来这样做，将原点对齐到文本放置在其中的矩形区域的西北角：

```py
        # ...
        options = { "font": "courier", "fill": "blue",
                    "activefill": "red", "anchor": tk.NW }
        self.text_id = self.canvas.create_text((0, 0), **options)
```

上述代码片段将给我们以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/51d7f33e-6edb-4b2d-b763-04ebf4508af2.png)

# 设置换行

默认情况下，文本项目的内容将显示在单行中。`width`选项允许我们定义最大行宽，用于换行超过该宽度的行：

```py
        # ...
        options = { "font": "courier", "fill": "blue",
                    "activefill": "red", "width": 70 }
        self.text_id = self.canvas.create_text((w/2, h/2), **options)
```

现在，当我们在输入框中写入`Hello, world!`时，超过行宽的文本部分将显示在新行中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/689721c7-6307-4dac-b556-28b3dbb199ec.png)

# 向画布添加形状

在本示例中，我们将介绍三种标准画布项目：矩形、椭圆和弧。它们都显示在一个边界框内，因此只需要两个点来设置它们的位置：框的左上角和右下角。

# 准备工作

以下应用程序允许用户通过三个按钮选择其类型在画布上自由绘制一些项目-每个按钮选择相应的形状。

项目的位置是通过首先在画布上单击来设置项目将包含在其中的框的左上角，然后再单击来设置此框的左下角并使用一些预定义选项绘制项目来确定的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/dff4558b-fd6c-4ff5-b8c6-76e02e2dee61.png)

# 操作步骤...

我们的应用程序存储当前选择的项目类型，可以使用放置在画布下方框架上的三个按钮之一选择。

使用主鼠标按钮单击画布会触发处理程序，该处理程序存储新项目的第一个角的位置，然后再次单击，它会读取所选形状的值以有条件地绘制相应的项目：

```py
import tkinter as tk
from functools import partial

class App(tk.Tk):
    shapes = ("rectangle", "oval", "arc")
    def __init__(self):
        super().__init__()
        self.title("Drawing standard items")

        self.start = None
        self.shape = None
        self.canvas = tk.Canvas(self, bg="white")
        frame = tk.Frame(self)
        for shape in self.shapes:
            btn = tk.Button(frame, text=shape.capitalize())
            btn.config(command=partial(self.set_selection, btn, shape))
            btn.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        self.canvas.bind("<Button-1>", self.draw_item)
        self.canvas.pack()
        frame.pack(fill=tk.BOTH)

    def set_selection(self, widget, shape):
        for w in widget.master.winfo_children():
            w.config(relief=tk.RAISED)
        widget.config(relief=tk.SUNKEN)
        self.shape = shape

    def draw_item(self, event):
        x, y = event.x, event.y
        if not self.start:
            self.start = (x, y)
        else:
            x_origin, y_origin = self.start
            self.start = None
            bbox = (x_origin, y_origin, x, y)
            if self.shape == "rectangle":
                self.canvas.create_rectangle(*bbox, fill="blue",
                                             activefill="yellow")
            elif self.shape == "oval":
                self.canvas.create_oval(*bbox, fill="red",
                                        activefill="yellow")
            elif self.shape == "arc":
                self.canvas.create_arc(*bbox, fill="green",
                                       activefill="yellow")

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理...

为了通过单击画布动态选择要绘制的项目类型，我们将通过迭代`shapes`元组为每个形状创建一个按钮。

我们使用`functools`模块中的`partial`函数来定义每个回调命令。由于这样，我们可以将`Button`实例和循环的当前形状作为每个按钮的回调的参数冻结：

```py
        for shape in self.shapes:
            btn = tk.Button(frame, text=shape.capitalize())
            btn.config(command=partial(self.set_selection, btn, shape))
            btn.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
```

`set_selection()`回调标记了单击的按钮，并将选择存储在`shape`字段中，使用`SUNKEN` relief。

其他小部件兄弟姐妹通过导航到父级（在当前小部件的`master`字段中可用）并使用`winfo_children()`方法检索所有子小部件来配置标准的`relief`（`RAISED`）：

```py
    def set_selection(self, widget, shape):
        for w in widget.master.winfo_children():
            w.config(relief=tk.RAISED)
        widget.config(relief=tk.SUNKEN)
        self.shape = shape
```

`draw_item()`处理程序将每对事件的第一次单击的坐标存储起来，以便在再次单击画布时绘制项目-就像我们在*绘制线条和箭头*示例中所做的那样。

根据`shape`字段的值，调用以下方法之一来显示相应的项目类型：

+   `canvas.create_rectangle(x0, y0, x1, y1, **options)`: 绘制一个矩形，其左上角位于**(x0, y0)**，右下角位于**(x1, y1)**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/9bc92787-61f1-4eed-9c2c-1f7b422cb606.png)

+   `canvas.create_oval(x0, y0, x1, y1, **options)`: 绘制一个椭圆，适合从**(x0, y0)**到**(x1, y1)**的矩形中：*

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/f9490d06-adc3-4f5e-872c-0fb600265970.png)

+   `canvas.create_arc(x0, y0, x1, y1, **options)`: 绘制一个四分之一的椭圆，该椭圆适合从**(x0, y0)**到**(x1, y1)**的矩形中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/3abfc301-8ed6-4ed3-bacf-e0a8df5746e9.png)

# 另请参阅

+   *绘制线条和箭头*食谱

# 按其位置查找项目

`Canvas`类包括检索接近画布坐标的项目标识符的方法。

这非常有用，因为它可以避免我们存储对画布项目的每个引用，然后计算它们的当前位置以检测哪些项目在特定区域内或最接近特定点。

# 做好准备

以下应用程序创建了一个带有四个矩形的画布，并更改了最接近鼠标指针的矩形的颜色：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/72906402-5615-46ca-8bfb-b05a0f3b46b0.png)

# 如何做...

为了找到最接近指针的项目，我们将鼠标事件坐标传递给`canvas.find_closest()`方法，该方法检索最接近给定位置的项目的标识符。

一旦画布中至少有一个项目，我们可以安全地假定该方法将始终返回有效的项目标识符：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Finding canvas items")

        self.current = None
        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.bind("<Motion>", self.mouse_motion)
        self.canvas.pack()

        self.update()
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        positions = [(60, 60), (w-60, 60), (60, h-60), (w-60, h-60)]
        for x, y in positions:
            self.canvas.create_rectangle(x-10, y-10, x+10, y+10,
                                         fill="blue")

    def mouse_motion(self, event):
        self.canvas.itemconfig(self.current, fill="blue")
        self.current = self.canvas.find_closest(event.x, event.y)
        self.canvas.itemconfig(self.current, fill="yellow")

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

在应用程序初始化期间，我们创建画布并定义`current`字段以存储对当前突出显示项目的引用。我们还使用`mouse_motion()`方法处理画布上的`"<Motion>"`事件：

```py
        self.current = None
        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.bind("<Motion>", self.mouse_motion)
        self.canvas.pack()
```

然后，我们创建四个具有特定排列的项目，以便我们可以轻松地可视化最接近鼠标指针的项目：

```py
        self.update()
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        positions = [(60, 60), (w-60, 60), (60, h-60), (w-60, h-60)]
        for x, y in positions:
            self.canvas.create_rectangle(x-10, y-10, x+10, y+10,
                                         fill="blue")
```

`mouse_motion()`处理程序将当前项目的颜色设置回`blue`，并保存新项目的项目标识符，该项目更接近事件坐标。最后，设置此项目的`fill`颜色为`yellow`：

```py
    def mouse_motion(self, event):
        self.canvas.itemconfig(self.current, fill="blue")
        self.current = self.canvas.find_closest(event.x, event.y)
        self.canvas.itemconfig(self.current, fill="yellow")
```

当首次调用`mouse_motion()`时，`current`字段仍为`None`时不会出现错误，因为它也是`itemconfig()`的有效输入参数；它只是不会在画布上执行任何操作。

# 移动画布项目

一旦放置，画布项目就可以移动到特定的偏移量，而无需指定绝对坐标。

移动画布项目时，通常需要计算其当前位置，例如确定它们是否放置在具体的画布区域内，并限制它们的移动，使其始终保持在该区域内。

# 如何做...

我们的示例将包括一个简单的带有矩形项目的画布，可以使用箭头键在水平和垂直方向上移动。

为了防止此项目移出屏幕，我们将限制其在画布尺寸内的移动：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Moving canvas items")

        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.pack()
        self.update()
        self.width = self.canvas.winfo_width()
        self.height = self.canvas.winfo_height()

        self.item = self.canvas.create_rectangle(30, 30, 60, 60,
                                                 fill="blue")
        self.pressed_keys = {}
        self.bind("<KeyPress>", self.key_press)
        self.bind("<KeyRelease>", self.key_release)
        self.process_movements()

    def key_press(self, event):
        self.pressed_keys[event.keysym] = True

    def key_release(self, event):
        self.pressed_keys.pop(event.keysym, None)

    def process_movements(self):
        off_x, off_y = 0, 0
        speed = 3
        if 'Right' in self.pressed_keys:
            off_x += speed
        if 'Left' in self.pressed_keys:
            off_x -= speed
        if 'Down' in self.pressed_keys:
            off_y += speed
        if 'Up' in self.pressed_keys:
            off_y -= speed

        x0, y0, x1, y1 = self.canvas.coords(self.item)
        pos_x = x0 + (x1 - x0) / 2 + off_x
        pos_y = y0 + (y1 - y0) / 2 + off_y
        if 0 <= pos_x <= self.width and 0 <= pos_y <= self.height:
            self.canvas.move(self.item, off_x, off_y)

        self.after(10, self.process_movements)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

为了处理箭头键盘事件，我们将`"<KeyPress>"`和`"<KeyRelease>"`序列绑定到应用程序实例。当前按下的键符号存储在`pressed_keys`字典中：

```py
    def __init__(self):
        # ...
        self.pressed_keys = {}
        self.bind("<KeyPress>", self.key_press)
        self.bind("<KeyRelease>", self.key_release)

    def key_press(self, event):
        self.pressed_keys[event.keysym] = True

    def key_release(self, event):
        self.pressed_keys.pop(event.keysym, None)
```

这种方法比分别绑定`"<Up>"`、`"<Down>"`、`"<Right>"`和`"<Left>"`键更可取，因为这样会在 Tkinter 处理输入键盘事件时仅调用每个处理程序，导致项目从一个位置“跳转”到下一个位置，而不是在水平和垂直轴上平滑移动。

`App`实例初始化的最后一句是调用`process_movements()`，它开始处理画布项目的移动。

该方法计算项目应该在每个轴上偏移的量。根据`pressed_keys`字典的内容，`speed`值将添加或减去坐标的每个分量：

```py
    def process_movements(self):
        off_x, off_y = 0, 0
        speed = 3
        if 'Right' in self.pressed_keys:
            off_x += speed
        if 'Left' in self.pressed_keys:
            off_x -= speed
        if 'Down' in self.pressed_keys:
            off_y += speed
        if 'Up' in self.pressed_keys:
            off_y -= speed
```

之后，通过调用`canvas.coords()`并解压形成边界框的一对点来检索当前项目位置到四个变量。

通过将左上角的`x`和`y`分量加上其宽度和高度的一半来计算项目的中心。这个结果，再加上每个轴上的偏移量，对应于项目移动后的最终位置：

```py
        x0, y0, x1, y1 = self.canvas.coords(self.item)
        pos_x = x0 + (x1 - x0) / 2 + off_x
        pos_y = y0 + (y1 - y0) / 2 + off_y
```

然后，我们检查最终项目位置是否在画布区域内。为此，我们利用 Python 对链接比较运算符的支持：

```py
        if 0 <= pos_x <= self.width and 0 <= pos_y <= self.height:
            self.canvas.move(self.item, off_x, off_y)
```

最后，该方法通过调用`self.after(10, self.process_movements)`以 10 毫秒的延迟安排自身。因此，我们实现了在 Tkinter 的主循环中具有“自定义主循环”的效果。

# 还有更多...

您可能会想知道为什么我们没有调用`after_idle()`而是调用`after()`来安排`process_movements()`方法。

这似乎是一个有效的方法，因为除了重新绘制我们的画布和处理键盘输入之外，没有其他事件需要处理，因此在`process_movements()`之间如果没有待处理的 GUI 事件，就不需要添加延迟。

但是，使用`after_idle`会导致项目移动的速度取决于计算机的速度。这意味着快速系统将在相同的时间间隔内多次调用`process_movements()`，而较慢的系统将在项目速度上有所不同。

通过引入最小固定延迟，我们给具有不同功能的机器一个机会，以便以类似的方式行事。

# 另请参阅

+   检测项目之间的碰撞食谱

# 检测项目之间的碰撞

作为前面食谱的延续，我们可以检测矩形项目是否与另一个项目重叠。实际上，假设我们正在使用包含在矩形框中的形状，可以使用`Canvas`类的`find_overlapping()`方法来实现这一点。

# 准备工作

该应用程序通过向画布添加四个绿色矩形并突出显示通过使用箭头键移动的蓝色矩形触摸的矩形，扩展了前一个应用程序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/ce47f2c4-c609-4fa0-aea3-71bf7cb0b81e.png)

# 如何做...

由于此脚本与前一个脚本有许多相似之处，我们标记了创建四个矩形并调用`canvas.find_overlapping()`方法的代码部分：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Detecting collisions between items")

        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.pack()
        self.update()
 self.width = w = self.canvas.winfo_width()
 self.height = h = self.canvas.winfo_height()

 pos = (w/2 - 15, h/2 - 15, w/2 + 15, h/2 + 15)
 self.item = self.canvas.create_rectangle(*pos, fill="blue") 
 positions = [(60, 60), (w-60, 60), (60, h-60), (w-60, h-60)]
 for x, y in positions:
 self.canvas.create_rectangle(x-10, y-10, x+10, y+10,
 fill="green")

        self.pressed_keys = {}
        self.bind("<KeyPress>", self.key_press)
        self.bind("<KeyRelease>", self.key_release)
        self.process_movements()

    def key_press(self, event):
        self.pressed_keys[event.keysym] = True

    def key_release(self, event):
        self.pressed_keys.pop(event.keysym, None)

    def process_movements(self):
 all_items = self.canvas.find_all()
 for item in filter(lambda i: i is not self.item, all_items):
 self.canvas.itemconfig(item, fill="green")

 x0, y0, x1, y1 = self.canvas.coords(self.item)
 items = self.canvas.find_overlapping(x0, y0, x1, y1)
 for item in filter(lambda i: i is not self.item, items):
 self.canvas.itemconfig(item, fill="yellow")

        off_x, off_y = 0, 0
        speed = 3
        if 'Right' in self.pressed_keys:
            off_x += speed
        if 'Left' in self.pressed_keys:
            off_x -= speed
        if 'Down' in self.pressed_keys:
            off_y += speed
        if 'Up' in self.pressed_keys:
            off_y -= speed

        pos_x = x0 + (x1 - x0) / 2 + off_x
        pos_y = y0 + (y1 - y0) / 2 + off_y
        if 0 <= pos_x <= self.width and 0 <= pos_y <= self.height:
            self.canvas.move(self.item, off_x, off_y)

        self.after(10, self.process_movements)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理...

`__init__`方法的修改类似于*按位置查找项目*食谱中的修改，因此如果有任何疑问，您可以查看它并直接跳转到`process_movements()`方法中的更改。

在计算任何重叠之前，除了用户可以控制的项目之外，所有画布项目的填充颜色都更改为绿色。这些项目的标识符由`canvas.find_all()`方法检索：

```py
    def process_movements(self):
 all_items = self.canvas.find_all()
 for item in filter(lambda i: i != self.item, all_items):
 self.canvas.itemconfig(item, fill="green")
```

现在项目颜色已重置，我们调用`canvas.find_overlapping()`以获取当前与移动项目发生碰撞的所有项目。同样，用户控制的项目在循环中被排除，重叠项目的颜色（如果有）被更改为黄色：

```py
    def process_movements(self):
        # ...

 x0, y0, x1, y1 = self.canvas.coords(self.item)
 items = self.canvas.find_overlapping(x0, y0, x1, y1)
 for item in filter(lambda i: i != self.item, items):
 self.canvas.itemconfig(item, fill="yellow")
```

该方法继续执行，通过计算偏移量移动蓝色矩形，并再次安排`process_movements()`自身。

# 还有更多...

如果要检测移动项目完全与另一个项目重叠，而不是部分重叠，可以将对`canvas.find_overlapping()`的调用替换为使用相同参数的`canvas.find_enclosed()`。

# 从画布中删除项目

除了在画布上添加和修改项目，还可以通过`Canvas`类的`delete()`方法删除它们。虽然这种方法的使用非常简单，但在下一个示例中我们将看到一些有用的模式。

请记住，在画布上显示的项目越多，Tkinter 重新绘制小部件所需的时间就越长。因此，如果这可能会导致性能问题，最好删除不必要的项目。

# 准备工作

对于此示例，我们将构建一个应用程序，在画布上随机显示几个圆。单击圆后，每个圆都会自行删除，窗口包含一个按钮来清除所有项目和另一个按钮来重新开始：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/f5f70f4c-b05c-4a20-a132-8128d59fc1b4.png)

# 如何做...

为了在画布上不规则地放置项目，我们将使用`random`模块的`randint`函数生成坐标。项目颜色也将通过调用`choice`并使用预定义的颜色列表来随机选择。

一旦生成，项目可以通过单击触发`on_click`处理程序或按下`Clear items`按钮来删除，后者执行`clear_all`回调。这些方法内部使用适当的参数调用`canvas.delete()`：

```py
import random
import tkinter as tk

class App(tk.Tk):
    colors = ("red", "yellow", "green", "blue", "orange")

    def __init__(self):
        super().__init__()
        self.title("Removing canvas items")

        self.canvas = tk.Canvas(self, bg="white")
        frame = tk.Frame(self)
        generate_btn = tk.Button(frame, text="Generate items",
                                 command=self.generate_items)
        clear_btn = tk.Button(frame, text="Clear items",
                              command=self.clear_items)

        self.canvas.pack()
        frame.pack(fill=tk.BOTH)
        generate_btn.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        clear_btn.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        self.update()
        self.width = self.canvas.winfo_width()
        self.height = self.canvas.winfo_height()

        self.canvas.bind("<Button-1>", self.on_click)
        self.generate_items()

    def on_click(self, event):
        item = self.canvas.find_withtag(tk.CURRENT)
        self.canvas.delete(item)

    def generate_items(self):
        self.clear_items()
        for _ in range(10):
            x = random.randint(0, self.width)
            y = random.randint(0, self.height)
            color = random.choice(self.colors)
            self.canvas.create_oval(x, y, x + 20, y + 20, fill=color)

    def clear_items(self):
        self.canvas.delete(tk.ALL)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

`canvas.delete()`方法接受一个参数，可以是项目标识符或标记，并删除匹配的项目，因为相同的标记可以多次使用。

在`on_click()`处理程序中，我们可以看到如何通过其标识符删除项目的示例：

```py
    def on_click(self, event):
        item = self.canvas.find_withtag(tk.CURRENT)
        self.canvas.delete(item)
```

请注意，如果我们单击空点，`canvas.find_withtag(tk.CURRENT)`将返回`None`，但当传递给`canvas.delete()`时不会引发任何错误。这是因为`None`参数不会匹配任何项目标识符或标记，因此，即使它不执行任何操作，它也是有效的值。

在`clear_items()`回调中，我们可以找到另一个删除项目的示例。在这里，我们使用`ALL`标记而不是传递项目标识符来匹配所有项目并将其从画布中删除：

```py
    def clear_items(self):
        self.canvas.delete(tk.ALL)
```

您可能已经注意到，`ALL`标记可以直接使用，无需添加到每个画布项目。

# 将事件绑定到画布项目

到目前为止，我们已经看到了如何将事件绑定到小部件；但是，也可以为画布项目这样做。这有助于我们编写更具体和更简单的事件处理程序，而不是在`Canvas`实例上绑定我们想要处理的所有事件类型，然后根据受影响的项目确定要应用的操作。

# 准备工作

以下应用程序显示了如何在画布项目上实现拖放功能。这是一个常见的功能，用于说明这种方法如何简化我们的程序。

# 如何做...

我们将创建两个可以使用鼠标拖放的项目——一个矩形和一个椭圆。不同的形状帮助我们注意到单击事件如何正确应用于相应的项目，即使项目重叠放置：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Drag and drop")

        self.dnd_item = None
        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.pack()

        self.canvas.create_rectangle(30, 30, 60, 60, fill="green",
                                     tags="draggable")
        self.canvas.create_oval(120, 120, 150, 150, fill="red",
                                tags="draggable")
        self.canvas.tag_bind("draggable", "<ButtonPress-1>",
                             self.button_press)
        self.canvas.tag_bind("draggable", "<Button1-Motion>",
                             self.button_motion)

    def button_press(self, event):
        item = self.canvas.find_withtag(tk.CURRENT)
        self.dnd_item = (item, event.x, event.y)

    def button_motion(self, event):
        x, y = event.x, event.y
        item, x0, y0 = self.dnd_item
        self.canvas.move(item, x - x0, y - y0)
        self.dnd_item = (item, x, y)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

要将事件绑定到项目，我们使用`Canvas`类的`tag_bind()`方法。这将事件绑定添加到与项目指定符匹配的所有项目上，在我们的示例中是`"draggable"`标记。

即使方法被命名为`tag_bind()`; 传递项目标识符而不是标记也是有效的：

```py
        self.canvas.tag_bind("draggable", "<ButtonPress-1>",
                             self.button_press)
        self.canvas.tag_bind("draggable", "<Button1-Motion>",
                             self.button_motion)
```

请记住，这仅影响现有的带标签项目，因此，如果我们稍后使用`"draggable"`标记添加新项目，它们将不具有这些绑定附加。

`button_press()`方法是在单击项目时调用的处理程序。通常，检索单击的项目的常见模式是调用`canvas.find_withtag(tk.CURRENT)`。

此项目标识符和`click`事件的`x`和`y`坐标存储在`dnd_item`字段中。稍后将使用这些值来与鼠标运动同步移动项目：

```py
    def button_press(self, event):
        item = self.canvas.find_withtag(tk.CURRENT)
        self.dnd_item = (item, event.x, event.y)
```

`button_motion()`方法在按住主按钮时处理鼠标运动事件。

为了设置项目应该移动的距离，我们计算当前事件位置与先前存储的坐标之间的差异。这些值传递给`canvas.move()`方法，并再次保存在`dnd_item`字段中：

```py
    def button_motion(self, event):
        x, y = event.x, event.y
        item, x0, y0 = self.dnd_item
        self.canvas.move(item, x - x0, y - y0)
        self.dnd_item = (item, x, y)
```

还有一些变体的拖放功能，还实现了`<ButtonRelease-1>`序列的处理程序，该处理程序取消当前拖动的项目。

然而，这并非必要，因为一旦发生这种类型的事件，直到再次单击项目，`<Button1-Motion>`绑定将不会触发。这也使我们免于在`button_motion()`处理程序的开头检查`dnd_item`是否不是`None`。

# 还有更多...

可以通过添加一些基本验证来改进此示例，例如验证用户不能将项目放在画布可见区域之外。

要实现这一点，您可以使用我们在以前的配方中介绍的模式来计算画布的宽度和高度，并通过链接比较运算符来验证项目的最终位置是否在有效范围内。您可以使用以下代码段中显示的结构作为模板：

```py
final_x, final_y = pos_x + off_x, pos_y + off_y
if 0 <= final_x <= canvas_width and 0 <= final_y <= canvas_height:
     canvas.move(item, off_x, off_y)
```

# 另请参阅

+   *移动画布项目*配方

# 将画布渲染成 PostScript 文件

`Canvas`类通过其`postscript()`方法本地支持使用 PostScript 语言保存其内容。这会存储画布项目的图形表示，如线条、矩形、多边形、椭圆和弧，但不会对嵌入式小部件和图像进行存储。

我们将修改一个之前的配方，动态生成这种简单项目的功能，以添加将画布的表示保存到 PostScript 文件的功能。

# 如何做...

我们将从*绘制线条和箭头*配方中获取代码示例，以添加一个按钮，将画布内容打印到 PostScript 文件中：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Basic canvas")

        self.line_start = None
        self.form = LineForm(self)
        self.render_btn = tk.Button(self, text="Render canvas",
                                    command=self.render_canvas)
        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.bind("<Button-1>", self.draw)

        self.form.grid(row=0, column=0, padx=10, pady=10)
        self.render_btn.grid(row=1, column=0)
        self.canvas.grid(row=0, column=1, rowspan=2)

    def draw(self, event):
        # ...

    def render_canvas(self):
        self.canvas.postscript(file="output.ps", colormode="color")
```

# 工作原理...

原始脚本的主要添加是带有`render_canvas()`回调的`Render canvas`按钮。

它在`canvas`实例上调用`postscript()`方法，并使用`file`和`colormode`参数。这些选项指定了写入 PostScript 和输出颜色信息的目标文件的路径，可以是`"color"`表示全彩输出，`"gray"`表示转换为灰度等效，`"mono"`表示将所有颜色转换为黑色或白色：

```py
    def render_canvas(self):
        self.canvas.postscript(file="output.ps", colormode="color")
```

您可以在 Tk/Tcl 文档的`postscript()`方法中检查所有可以传递的有效选项，网址为[`www.tcl.tk/man/tcl8.6/TkCmd/canvas.htm#M61`](https://www.tcl.tk/man/tcl8.6/TkCmd/canvas.htm#M61)。请记住，PostScript 是一种主要用于打印的语言，因此大多数选项都是指页面设置。

# 还有更多...

由于 PostScript 文件不像其他文件格式那样流行，您可能希望将生成的文件从 PostScript 转换为更熟悉的格式，如 PDF。

为了做到这一点，您需要一个第三方软件，比如**Ghostscript**，它是根据 GNU 的**Affero 通用公共许可证**（**AGPL**）分发的。 Ghostscript 的解释器和渲染器实用程序可以从您的程序中调用，自动将 PostScript 结果转换为 PDF。

从[`www.ghostscript.com/download/gsdnld.html`](https://www.ghostscript.com/download/gsdnld.html)下载并安装软件的最新版本，并将安装的`bin`和`lib`文件夹添加到操作系统路径中。

然后，修改您的 Tkinter 应用程序，调用`ps2pdf`程序作为子进程，并在执行完毕时删除`output.ps`文件，如下所示：

```py
import os
import subprocess
import tkinter as tk

class App(tk.Tk):
    # ...

    def render_canvas(self):
        output_filename = "output.ps"
        self.canvas.postscript(file=output_filename, colormode="color")
 process = subprocess.run(["ps2pdf", output_filename, "output.pdf"],
 shell=True)
 os.remove(output_filename)
```


# 第八章：主题小部件

在本章中，我们将涵盖以下内容：

+   替换基本的小部件类

+   使用 Combobox 创建可编辑的下拉菜单

+   使用 Treeview 小部件

+   在 Treeview 中填充嵌套项目

+   使用 Notebook 显示可切换的窗格

+   应用 Ttk 样式

+   创建日期选择器小部件

# 介绍

Tk 主题小部件是 Tk 小部件的一个单独集合，具有本机外观和感觉，并且它们的样式可以使用特定的 API 进行高度定制。

这些类在`tkinter.ttk`模块中定义。除了定义新的小部件，如 Treeview 和 Notebook，这个模块还重新定义了经典 Tk 小部件的实现，如 Button、Label 和 Frame。

在本章中，我们将不仅涵盖如何将应用程序 Tk 小部件更改为主题小部件，还将涵盖如何对其进行样式设置和使用新的小部件类。

主题 Tk 小部件集是在 Tk 8.5 中引入的，这不应该是一个问题，因为 Python 3.6 安装程序可以让您包含 Tcl/Tk 解释器的 8.6 版本。

但是，您可以通过在命令行中运行`python -m tkinter`来验证任何平台，这将启动以下程序，输出 Tcl/Tk 版本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/5e1aac09-b958-416e-aaaa-3a752a2ff65f.png)

# 替换基本的小部件类

作为使用主题 Tkinter 类的第一种方法，我们将看看如何从这个不同的模块中使用相同的小部件（按钮、标签、输入框等），在我们的应用程序中保持相同的行为。

尽管这不会充分发挥其样式能力，但我们可以轻松欣赏到带来主题小部件本机外观和感觉的视觉变化。

# 准备工作

在下面的屏幕截图中，您可以注意到带有主题小部件的 GUI 和使用标准 Tkinter 小部件的相同窗口之间的差异：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/64a181c4-fef7-4ef4-ab23-4d4a70afe4ed.png)

我们将构建第一个窗口中显示的应用程序，但我们还将学习如何轻松地在两种样式之间切换。

请注意，这高度依赖于平台。在这种情况下，主题变化对应于 Windows 10 上主题小部件的外观。

# 操作步骤

要开始使用主题小部件，您只需要导入`tkinter.ttk`模块，并像往常一样在您的 Tkinter 应用程序中使用那里定义的小部件：

```py
import tkinter as tk
import tkinter.ttk as ttk

class App(tk.Tk):
    greetings = ("Hello", "Ciao", "Hola")

    def __init__(self):
        super().__init__()
        self.title("Tk themed widgets")

        var = tk.StringVar()
        var.set(self.greetings[0])
        label_frame = ttk.LabelFrame(self, text="Choose a greeting")
        for greeting in self.greetings:
            radio = ttk.Radiobutton(label_frame, text=greeting,
                                    variable=var, value=greeting)
            radio.pack()

        frame = ttk.Frame(self)
        label = ttk.Label(frame, text="Enter your name")
        entry = ttk.Entry(frame)

        command = lambda: print("{}, {}!".format(var.get(), 
                                         entry.get()))
        button = ttk.Button(frame, text="Greet", command=command)

        label.grid(row=0, column=0, padx=5, pady=5)
        entry.grid(row=0, column=1, padx=5, pady=5)
        button.grid(row=1, column=0, columnspan=2, pady=5)

        label_frame.pack(side=tk.LEFT, padx=10, pady=10)
        frame.pack(side=tk.LEFT, padx=10, pady=10)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

如果您想要使用常规的 Tkinter 小部件运行相同的程序，请将所有`ttk.`出现替换为`tk.`。

# 它是如何工作的...

开始使用主题小部件的常见方法是使用`import ... as`语法导入`tkinter.ttk`模块。因此，我们可以轻松地用`tk`名称标识标准小部件，用`ttk`名称标识主题小部件：

```py
import tkinter as tk
import tkinter.ttk as ttk
```

正如您可能已经注意到的，在前面的代码中，将`tkinter`模块中的小部件替换为`tkinter.ttk`中的等效小部件就像更改别名一样简单：

```py
import tkinter as tk
import tkinter.ttk as ttk

# ...
entry_1 = tk.Entry(root)
entry_2 = ttk.Entry(root)
```

在我们的示例中，我们为`ttk.Frame`、`ttk.Label`、`ttk.Entry`、`ttk.LabelFrame`和`ttk.Radiobutton`小部件这样做。这些类接受的基本选项几乎与它们的标准 Tkinter 等效类相同；事实上，它们实际上是它们的子类。

然而，这个翻译很简单，因为我们没有移植任何样式选项，比如`foreground`或`background`。在主题小部件中，这些关键字通过`ttk.Style`类分别使用，我们将在另一个食谱中介绍。

# 另请参阅

+   *应用 Ttk 样式*食谱

# 使用 Combobox 创建可编辑的下拉菜单

下拉列表是一种简洁的方式，通过垂直显示数值列表来选择数值，只有在需要时才显示。这也是让用户输入列表中不存在的另一个选项的常见方式。

这个功能结合在`ttk.Combobox`类中，它采用您平台下拉菜单的本机外观和感觉。

# 准备工作

我们的下一个应用程序将包括一个简单的下拉输入框，带有一对按钮来确认选择或清除其内容。

如果选择了预定义的值之一或单击了提交按钮，则当前 Combobox 值将以以下方式打印在标准输出中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/90f6db52-c463-4a4c-bde6-1aeaf09dff48.png)

# 如何做到...

我们的应用程序在初始化期间创建了一个`ttk.Combobox`实例，传递了一个预定义的数值序列，可以在下拉列表中进行选择：

```py
import tkinter as tk
import tkinter.ttk as ttk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ttk Combobox")
        colors = ("Purple", "Yellow", "Red", "Blue")

        self.label = ttk.Label(self, text="Please select a color")
        self.combo = ttk.Combobox(self, values=colors)
        btn_submit = ttk.Button(self, text="Submit",
                                command=self.display_color)
        btn_clear = ttk.Button(self, text="Clear",
                                command=self.clear_color)

        self.combo.bind("<<ComboboxSelected>>", self.display_color)

        self.label.pack(pady=10)
        self.combo.pack(side=tk.LEFT, padx=10, pady=5)
        btn_submit.pack(side=tk.TOP, padx=10, pady=5)
        btn_clear.pack(padx=10, pady=5)

    def display_color(self, *args):
        color = self.combo.get()
        print("Your selection is", color)

    def clear_color(self):
        self.combo.set("")

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

与往常一样，通过将`Tk`实例作为其构造函数的第一个参数传递给我们的应用程序，我们将`ttk.Combobox`小部件添加到应用程序中。`values`选项指定了在单击下拉箭头时显示的可选择选项列表。

我们绑定了`"<<ComboboxSelected>>"`虚拟事件，当从值列表中选择一个选项时生成该事件：

```py
        self.label = ttk.Label(self, text="Please select a color")
        self.combo = ttk.Combobox(self, values=colors)
        btn_submit = ttk.Button(self, text="Submit",
                                command=self.display_color)
        btn_clear = ttk.Button(self, text="Clear",
                                command=self.clear_color)

        self.combo.bind("<<ComboboxSelected>>", self.display_color)
```

当单击`提交`按钮时，也会调用相同的方法，因此它会接收用户输入的值。

我们定义`display_color()`使用`*`语法接受可选参数列表。这是因为当通过事件绑定调用它时，会传递一个事件给它，但当从按钮回调中调用它时，不会接收任何参数。

在这个方法中，我们通过其`get()`方法检索当前 Combobox 值，并将其打印在标准输出中：

```py
    def display_color(self, *args):
        color = self.combo.get()
        print("Your selection is", color)
```

最后，`clear_color()`通过调用其`set()`方法并传递空字符串来清除 Combobox 的内容：

```py
    def clear_color(self):
        self.combo.set("")
```

通过这些方法，我们已经探讨了如何与 Combobox 实例的当前选择进行交互。

# 还有更多...

`ttk.Combobox`类扩展了`ttk.Entry`，后者又扩展了`tkinter`模块中的`Entry`类。

这意味着如果需要，我们也可以使用我们已经介绍的`Entry`类的方法：

```py
    combobox.insert(0, "Add this at the beginning: ")
```

前面的代码比`combobox.set("Add this at the beginning: " + combobox.get())`更简单。

# 使用 Treeview 小部件

在这个示例中，我们将介绍`ttk.Treeview`类，这是一个多功能的小部件，可以让我们以表格和分层结构显示信息。

添加到`ttk.Treeview`类的每个项目都分成一个或多个列，其中第一列可能包含文本和图标，并用于指示项目是否可以展开并显示更多嵌套项目。其余的列包含我们想要为每一行显示的值。

`ttk.Treeview`类的第一行由标题组成，通过其名称标识每一列，并可以选择性地隐藏。

# 准备好了

使用`ttk.Treeview`，我们将对存储在 CSV 文件中的联系人列表的信息进行制表，类似于我们在第五章中所做的*面向对象编程和 MVC*：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/5d623144-43ad-44ef-b852-aa63a1428d0b.png)

# 如何做到...

我们将创建一个`ttk.Treeview`小部件，其中包含三列，分别用于每个联系人的字段：一个用于姓，另一个用于名，最后一个用于电子邮件地址。

联系人是使用`csv`模块从 CSV 文件中加载的，然后我们为`"<<TreeviewSelect>>"`虚拟元素添加了绑定，当选择一个或多个项目时生成该元素：

```py
import csv
import tkinter as tk
import tkinter.ttk as ttk

class App(tk.Tk):
    def __init__(self, path):
        super().__init__()
        self.title("Ttk Treeview")

        columns = ("#1", "#2", "#3")
        self.tree = ttk.Treeview(self, show="headings", columns=columns)
        self.tree.heading("#1", text="Last name")
        self.tree.heading("#2", text="First name")
        self.tree.heading("#3", text="Email")
        ysb = ttk.Scrollbar(self, orient=tk.VERTICAL, 
                            command=self.tree.yview)
        self.tree.configure(yscroll=ysb.set)

        with open("contacts.csv", newline="") as f:
            for contact in csv.reader(f):
                self.tree.insert("", tk.END, values=contact)
        self.tree.bind("<<TreeviewSelect>>", self.print_selection)

        self.tree.grid(row=0, column=0)
        ysb.grid(row=0, column=1, sticky=tk.N + tk.S)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def print_selection(self, event):
        for selection in self.tree.selection():
            item = self.tree.item(selection)
            last_name, first_name, email = item["values"][0:3]
            text = "Selection: {}, {} <{}>"
            print(text.format(last_name, first_name, email))

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

如果您运行此程序，每次选择一个联系人，其详细信息都将以标准输出的方式打印出来，以说明如何检索所选行的数据。

# 它是如何工作的...

要创建一个具有多列的`ttk.Treeview`，我们需要使用`columns`选项指定每个列的标识符。然后，我们可以通过调用`heading()`方法来配置标题文本。

我们使用标识符`#1`、`#2`和`#3`，因为第一列始终使用`#0`标识符生成，其中包含可展开的图标和文本。

我们还将`"headings"`值传递给`show`选项，以指示我们要隐藏`#0`列，因为不会有嵌套项目。

`show`选项的有效值如下：

+   `"tree"`：显示列`#0`

+   `"headings"`：显示标题行

+   `"tree headings"`：显示列`#0`和标题行—这是默认值

+   `""`：不显示列`#0`或标题行

之后，我们将垂直滚动条附加到我们的`ttk.Treeview`小部件：

```py
        columns = ("#1", "#2", "#3")
        self.tree = ttk.Treeview(self, show="headings", columns=columns)
        self.tree.heading("#1", text="Last name")
        self.tree.heading("#2", text="First name")
        self.tree.heading("#3", text="Email")
        ysb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=ysb.set)
```

要将联系人加载到表中，我们使用`csv`模块的`reader()`函数处理文件，并在每次迭代中读取的行添加到`ttk.Treeview`中。

这是通过调用`insert()`方法来完成的，该方法接收父节点和放置项目的位置。

由于所有联系人都显示为顶级项目，因此我们将空字符串作为第一个参数传递，并将`END`常量传递以指示每个新项目插入到最后位置。

您可以选择为`insert()`方法提供一些关键字参数。在这里，我们指定了`values`选项，该选项接受在 Treeview 的每一列中显示的值序列：

```py
        with open("contacts.csv", newline="") as f:
            for contact in csv.reader(f):
                self.tree.insert("", tk.END, values=contact)
        self.tree.bind("<<TreeviewSelect>>", self.print_selection)
```

`<<TreeviewSelect>>`事件是用户从表中选择一个或多个项目时生成的虚拟事件。在`print_selection()`处理程序中，我们通过调用`selection()`方法检索当前选择，对于每个结果，我们将执行以下步骤：

1.  使用`item()`方法，我们可以获取所选项目的选项和值的字典

1.  我们从`item`字典中检索前三个值，这些值对应于联系人的姓氏、名字和电子邮件

1.  值被格式化并打印到标准输出：

```py
    def print_selection(self, event):
        for selection in self.tree.selection():
            item = self.tree.item(selection)
            last_name, first_name, email = item["values"][0:3]
            text = "Selection: {}, {} <{}>"
            print(text.format(last_name, first_name, email))
```

# 还有更多...

到目前为止，我们已经涵盖了`ttk.Treeview`类的一些基本方面，因为我们将其用作常规表。但是，还可以通过更高级的功能扩展我们现有的应用程序。

# 在 Treeview 项目中使用标签

`ttk.Treeview`项目可用标签，因此可以为`contacts`表的特定行绑定事件序列。

假设我们希望在双击时打开一个新窗口以给联系人写电子邮件；但是，这仅适用于填写了电子邮件字段的记录。

我们可以通过在插入项目时有条件地向其添加标签，然后在小部件实例上使用`"<Double-Button-1>"`序列调用`tag_bind()`来轻松实现这一点——这里我们只是通过其名称引用`send_email_to_contact()`处理程序函数的实现：

```py
    columns = ("Last name", "First name", "Email")
    tree = ttk.Treeview(self, show="headings", columns=columns)

    for contact in csv.reader(f):
        email = contact[2]
 tags = ("dbl-click",) if email else ()
 self.tree.insert("", tk.END, values=contact, tags=tags)

 tree.tag_bind("dbl-click", "<Double-Button-1>", send_email_to_contact)
```

与将事件绑定到`Canvas`项目时发生的情况类似，始终记住在调用`tag_bind()`之前将带有标签的项目添加到`ttk.Treeview`中，因为绑定仅添加到现有的匹配项目。

# 另请参阅

+   *在 Treeview 中填充嵌套项目*食谱

# 在 Treeview 中填充嵌套项目

虽然`ttk.Treeview`可以用作常规表，但它也可能包含分层结构。这显示为树，其中的项目可以展开以查看层次结构的更多节点。

这对于显示递归调用的结果和多层嵌套项目非常有用。在此食谱中，我们将研究适合这种结构的常见场景。

# 准备就绪

为了说明如何在`ttk.Treeview`小部件中递归添加项目，我们将创建一个基本的文件系统浏览器。可展开的节点将表示文件夹，一旦打开，它们将显示它们包含的文件和文件夹：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/9bd56ff2-7170-4c16-821d-af9d1f31e0ca.png)

# 如何做...

树将最初由`populate_node()`方法填充，该方法列出当前目录中的条目。如果条目是目录，则还会添加一个空子项以显示它作为可展开节点。

打开表示目录的节点时，它会通过再次调用`populate_node()`来延迟加载目录的内容。这次，不是将项目添加为顶级节点，而是将它们嵌套在打开的节点内部：

```py
import os
import tkinter as tk
import tkinter.ttk as ttk

class App(tk.Tk):
    def __init__(self, path):
        super().__init__()
        self.title("Ttk Treeview")

        abspath = os.path.abspath(path)
        self.nodes = {}
        self.tree = ttk.Treeview(self)
        self.tree.heading("#0", text=abspath, anchor=tk.W)
        ysb = ttk.Scrollbar(self, orient=tk.VERTICAL,
                            command=self.tree.yview)
        xsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL,
                            command=self.tree.xview)
        self.tree.configure(yscroll=ysb.set, xscroll=xsb.set)

        self.tree.grid(row=0, column=0, sticky=tk.N + tk.S + tk.E +     tk.W)
        ysb.grid(row=0, column=1, sticky=tk.N + tk.S)
        xsb.grid(row=1, column=0, sticky=tk.E + tk.W)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewOpen>>", self.open_node)
        self.populate_node("", abspath)

    def populate_node(self, parent, abspath):
        for entry in os.listdir(abspath):
            entry_path = os.path.join(abspath, entry)
            node = self.tree.insert(parent, tk.END, text=entry, open=False)
            if os.path.isdir(entry_path):
                self.nodes[node] = entry_path
                self.tree.insert(node, tk.END)

    def open_node(self, event):
        item = self.tree.focus()
        abspath = self.nodes.pop(item, False)
        if abspath:
            children = self.tree.get_children(item)
            self.tree.delete(children)
            self.populate_node(item, abspath)

if __name__ == "__main__":
    app = App(path=".")
    app.mainloop()
```

当运行上述示例时，它将显示脚本所在目录的文件系统层次结构，但您可以通过`App`构造函数的`path`参数明确设置所需的目录。

# 工作原理

在这个例子中，我们将使用`os`模块，它是 Python 标准库的一部分，提供了执行操作系统调用的便携方式。

`os`模块的第一个用途是将树的初始路径转换为绝对路径，以及初始化`nodes`字典，它将存储可展开项和它们表示的目录路径之间的对应关系：

```py
import os
import tkinter as tk
import tkinter.ttk as ttk

class App(tk.Tk):
    def __init__(self, path):
        # ...
 abspath = os.path.abspath(path)
 self.nodes = {}
```

例如，`os.path.abspath(".")`将返回你从脚本运行的路径的绝对版本。我们更喜欢这种方法而不是使用相对路径，因为这样可以避免在应用程序中处理路径时出现混淆。

现在，我们使用垂直和水平滚动条初始化`ttk.Treeview`实例。图标标题的`text`将是我们之前计算的绝对路径：

```py
        self.tree = ttk.Treeview(self)
        self.tree.heading("#0", text=abspath, anchor=tk.W)
        ysb = ttk.Scrollbar(self, orient=tk.VERTICAL,
                            command=self.tree.yview)
        xsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL,
                            command=self.tree.xview)
        self.tree.configure(yscroll=ysb.set, xscroll=xsb.set)
```

然后，我们使用 Grid 布局管理器放置小部件，并使`ttk.Treeview`实例在水平和垂直方向上自动调整大小。

之后，我们绑定了`"<<TreeviewOpen>>"`虚拟事件，当展开项时生成，调用`open_node()`处理程序并调用`populate_node()`加载指定目录的条目：

```py
        self.tree.bind("<<TreeviewOpen>>", self.open_node)
        self.populate_node("", abspath)
```

请注意，第一次调用此方法时，父目录为空字符串，这意味着它们没有任何父项，并显示为顶级项。

在`populate_node()`方法中，我们通过调用`os.listdir()`列出目录条目的名称。对于每个条目名称，我们执行以下操作：

+   计算条目的绝对路径。在类 UNIX 系统上，这是通过用斜杠连接字符串来实现的，但 Windows 使用反斜杠。由于`os.path.join()`方法，我们可以安全地连接路径，而不必担心平台相关的细节。

+   我们将`entry`字符串插入到指定的`parent`节点的最后一个子项中。我们总是将节点初始设置为关闭，因为我们希望仅在需要时延迟加载嵌套项。

+   如果条目的绝对路径是一个目录，我们在`nodes`属性中添加节点和路径之间的对应关系，并插入一个空的子项，允许该项展开：

```py
    def populate_node(self, parent, abspath):
        for entry in os.listdir(abspath):
            entry_path = os.path.join(abspath, entry)
            node = self.tree.insert(parent, tk.END, text=entry, open=False)
            if os.path.isdir(entry_path):
                self.nodes[node] = entry_path
                self.tree.insert(node, tk.END)
```

当单击可展开项时，`open_node()`处理程序通过调用`ttk.Treeview`实例的`focus()`方法检索所选项。

此项标识符用于获取先前添加到`nodes`属性的绝对路径。为了避免在字典中节点不存在时引发`KeyError`，我们使用了它的`pop()`方法，它将第二个参数作为默认值返回——在我们的例子中是`False`。

如果节点存在，我们清除可展开节点的“虚假”项。调用`self.tree.get_children(item)`返回`item`的子项的标识符，然后通过调用`self.tree.delete(children)`来删除它们。

一旦清除了该项，我们通过使用`item`作为父项调用`populate_node()`来添加“真实”的子项：

```py
    def open_node(self, event):
        item = self.tree.focus()
        abspath = self.nodes.pop(item, False)
        if abspath:
            children = self.tree.get_children(item)
            self.tree.delete(children)
            self.populate_node(item, abspath)
```

# 显示带有 Notebook 的选项卡窗格

`ttk.Notebook`类是`ttk`模块中引入的另一种新的小部件类型。它允许您在同一窗口区域中添加许多应用程序视图，让您通过单击与每个视图关联的选项卡来选择应该显示的视图。

选项卡面板是重用 GUI 相同部分的好方法，如果多个区域的内容不需要同时显示。

# 准备工作

以下应用程序显示了一些按类别分隔的待办事项列表，列表显示为只读数据，以简化示例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/de95909e-d3ee-4c23-9283-94af0b2928d9.png)

# 操作步骤

我们使用固定大小实例化`ttk.Notebook`，然后循环遍历具有一些预定义数据的字典，这些数据将用于创建选项卡并向每个区域添加一些标签：

```py
import tkinter as tk
import tkinter.ttk as ttk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ttk Notebook")

        todos = {
            "Home": ["Do the laundry", "Go grocery shopping"],
            "Work": ["Install Python", "Learn Tkinter", "Reply emails"],
            "Vacations": ["Relax!"]
        }

        self.notebook = ttk.Notebook(self, width=250, height=100)
        self.label = ttk.Label(self)
        for key, value in todos.items():
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=key, underline=0,
                              sticky=tk.NE + tk.SW)
            for text in value:
                ttk.Label(frame, text=text).pack(anchor=tk.W)

        self.notebook.pack()
        self.label.pack(anchor=tk.W)
        self.notebook.enable_traversal()
        self.notebook.bind("<<NotebookTabChanged>>", self.select_tab)

    def select_tab(self, event):
        tab_id = self.notebook.select()
        tab_name = self.notebook.tab(tab_id, "text")
        text = "Your current selection is: {}".format(tab_name)
        self.label.config(text=text)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

每次单击选项卡时，窗口底部的标签都会更新其内容，显示当前选项卡的名称。

# 它是如何工作的...

我们的`ttk.Notebook`小部件具有特定的宽度和高度，以及外部填充。

`todos`字典中的每个键都用作选项卡的名称，并且值列表被添加为标签到`ttk.Frame`，它代表窗口区域：

```py
 self.notebook = ttk.Notebook(self, width=250, height=100, padding=10)
        for key, value in todos.items():
            frame = ttk.Frame(self.notebook)
 self.notebook.add(frame, text=key,
                              underline=0, sticky=tk.NE+tk.SW)
            for text in value:
                ttk.Label(frame, text=text).pack(anchor=tk.W)
```

之后，我们在`ttk.Notebook`小部件上调用`enable_traversal()`。这允许用户使用*Ctrl* + *Shift* + *Tab*和*Ctrl* + *Tab*在选项卡面板之间来回切换选项卡。

它还可以通过按下*Alt*和下划线字符来切换到特定的选项卡，即*Alt* + *H*代表`Home`选项卡，*Alt* + *W*代表`Work`选项卡，*Alt* + *V*代表`Vacation`选项卡。

当选项卡选择更改时，生成`"<<NotebookTabChanged>>"`虚拟事件，并将其绑定到`select_tab()`方法。请注意，当 Tkinter 添加一个选项卡到`ttk.Notebook`时，此事件会自动触发：

```py
        self.notebook.pack()
        self.label.pack(anchor=tk.W)
 self.notebook.enable_traversal()
 self.notebook.bind("<<NotebookTabChanged>>", self.select_tab)
```

当我们打包项目时，不需要放置`ttk.Notebook`子窗口，因为`ttk.Notebook`调用几何管理器内部完成了这一点：

```py
    def select_tab(self, event):
        tab_id = self.notebook.select()
        tab_name = self.notebook.tab(tab_id, "text")
        self.label.config(text=f"Your current selection is: {tab_name}")
```

# 还有更多...

如果您想要检索`ttk.Notebook`当前显示的子窗口，您不需要使用任何额外的数据结构来将选项卡索引与小部件窗口进行映射。

Tkinter 的`nametowidget()`方法可从所有小部件类中使用，因此您可以轻松获取与小部件名称对应的小部件对象：

```py
    def select_tab(self, event):
        tab_id = self.notebook.select()
        frame = self.nametowidget(tab_id)
        # Do something with the frame
```

# 应用 Ttk 样式

正如我们在本章的第一个配方中提到的，主题小部件具有特定的 API 来自定义它们的外观。我们不能直接设置选项，例如前景色或内部填充，因为这些值是通过`ttk.Style`类设置的。

在这个配方中，我们将介绍如何修改第一个配方中的小部件以添加一些样式选项。

# 如何做...

为了添加一些默认设置，我们只需要一个`ttk.Style`对象，它提供以下方法：

+   `configure(style, opts)`: 更改小部件`style`的外观`opts`。在这里，我们设置诸如前景色、填充和浮雕等选项。

+   `map(style, query)`: 更改小部件`style`的动态外观。参数`query`是一个关键字参数，其中每个键都是样式选项，值是`(state, value)`形式的元组列表，表示选项的值由其当前状态确定。

例如，我们已经标记了以下两种情况的示例：

```py
import tkinter as tk
import tkinter.ttk as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Tk themed widgets")

        style = ttk.Style(self)
 style.configure("TLabel", padding=10)
 style.map("TButton",
 foreground=[("pressed", "grey"), ("active", "white")],
 background=[("pressed", "white"), ("active", "grey")]
 ) # ...
```

现在，每个`ttk.Label`显示为`10`的填充，`ttk.Button`具有动态样式：当状态为`pressed`时，灰色前景和白色背景，当状态为`active`时，白色前景和灰色背景。

# 它是如何工作的...

为我们的应用程序构建`ttk.Style`非常简单——我们只需要使用我们的父小部件作为它的第一个参数创建一个实例。

然后，我们可以为我们的主题小部件设置默认样式选项，使用大写的`T`加上小部件名称：`TButton`代表`ttk.Button`，`TLabel`代表`ttk.Label`，依此类推。然而，也有一些例外，因此建议您在 Python 解释器上调用小部件实例的`winfo_class()`方法来检查类名。

我们还可以添加前缀来标识我们不想默认使用的样式，但明确地将其设置为某些特定的小部件：

```py
        style.configure("My.TLabel", padding=10)
        # ...
        label = ttk.Label(master, text="Some text", style="My.TLabel")
```

# 创建日期选择器小部件

如果我们想让用户在我们的应用程序中输入日期，我们可以添加一个文本输入，强制他们编写一个带有有效日期格式的字符串。另一种解决方案是添加几个数字输入，用于日期、月份和年份，但这也需要一些验证。

与其他 GUI 框架不同，Tkinter 不包括一个专门用于此目的的类；然而，我们可以选择应用我们对主题小部件的知识来构建一个日历小部件。

# 准备就绪

在这个配方中，我们将逐步解释使用 Ttk 小部件和功能制作日期选择器小部件的实现：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/2af6aa0e-0480-4c96-b406-d51e96c7d0f1.png)

这是 [`svn.python.org/projects/sandbox/trunk/ttk-gsoc/samples/ttkcalendar.py`](http://svn.python.org/projects/sandbox/trunk/ttk-gsoc/samples/ttkcalendar.py) 的重构版本，不需要任何外部包。

# 操作步骤...

除了 `tkinter` 模块，我们还需要标准库中的 `calendar` 和 `datetime` 模块。它们将帮助我们对小部件中保存的数据进行建模和交互。

小部件标题显示了一对箭头，根据 Ttk 样式选项来前后移动当前月份。小部件的主体由一个 `ttk.Treeview` 表格组成，其中包含一个 `Canvas` 实例来突出显示所选日期单元格：

```py
import calendar
import datetime
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.font as tkfont
from itertools import zip_longest

class TtkCalendar(ttk.Frame):
    def __init__(self, master=None, **kw):
        now = datetime.datetime.now()
        fwday = kw.pop('firstweekday', calendar.MONDAY)
        year = kw.pop('year', now.year)
        month = kw.pop('month', now.month)
        sel_bg = kw.pop('selectbackground', '#ecffc4')
        sel_fg = kw.pop('selectforeground', '#05640e')

        super().__init__(master, **kw)

        self.selected = None
        self.date = datetime.date(year, month, 1)
        self.cal = calendar.TextCalendar(fwday)
        self.font = tkfont.Font(self)
        self.header = self.create_header()
        self.table = self.create_table()
        self.canvas = self.create_canvas(sel_bg, sel_fg)
        self.build_calendar()

    def create_header(self):
        left_arrow = {'children': [('Button.leftarrow', None)]}
        right_arrow = {'children': [('Button.rightarrow', None)]}
        style = ttk.Style(self)
        style.layout('L.TButton', [('Button.focus', left_arrow)])
        style.layout('R.TButton', [('Button.focus', right_arrow)])

        hframe = ttk.Frame(self)
        btn_left = ttk.Button(hframe, style='L.TButton',
                              command=lambda: self.move_month(-1))
        btn_right = ttk.Button(hframe, style='R.TButton',
                               command=lambda: self.move_month(1))
        label = ttk.Label(hframe, width=15, anchor='center')

        hframe.pack(pady=5, anchor=tk.CENTER)
        btn_left.grid(row=0, column=0)
        label.grid(row=0, column=1, padx=12)
        btn_right.grid(row=0, column=2)
        return label

    def move_month(self, offset):
        self.canvas.place_forget()
        month = self.date.month - 1 + offset
        year = self.date.year + month // 12
        month = month % 12 + 1
        self.date = datetime.date(year, month, 1)
        self.build_calendar()

    def create_table(self):
        cols = self.cal.formatweekheader(3).split()
        table = ttk.Treeview(self, show='', selectmode='none',
                             height=7, columns=cols)
        table.bind('<Map>', self.minsize)
        table.pack(expand=1, fill=tk.BOTH)
        table.tag_configure('header', background='grey90')
        table.insert('', tk.END, values=cols, tag='header')
        for _ in range(6):
            table.insert('', tk.END)

        width = max(map(self.font.measure, cols))
        for col in cols:
            table.column(col, width=width, minwidth=width, anchor=tk.E)
        return table

    def minsize(self, e):
        width, height = self.master.geometry().split('x')
        height = height[:height.index('+')]
        self.master.minsize(width, height)

    def create_canvas(self, bg, fg):
        canvas = tk.Canvas(self.table, background=bg,
                           borderwidth=0, highlightthickness=0)
        canvas.text = canvas.create_text(0, 0, fill=fg, anchor=tk.W)
        handler = lambda _: canvas.place_forget()
        canvas.bind('<ButtonPress-1>', handler)
        self.table.bind('<Configure>', handler)
        self.table.bind('<ButtonPress-1>', self.pressed)
        return canvas

    def build_calendar(self):
        year, month = self.date.year, self.date.month
        month_name = self.cal.formatmonthname(year, month, 0)
        month_weeks = self.cal.monthdayscalendar(year, month)

        self.header.config(text=month_name.title())
        items = self.table.get_children()[1:]
        for week, item in zip_longest(month_weeks, items):
            week = week if week else [] 
            fmt_week = ['%02d' % day if day else '' for day in week]
            self.table.item(item, values=fmt_week)

    def pressed(self, event):
        x, y, widget = event.x, event.y, event.widget
        item = widget.identify_row(y)
        column = widget.identify_column(x)
        items = self.table.get_children()[1:]

        if not column or not item in items:
            # clicked te header or outside the columns
            return

        index = int(column[1]) - 1
        values = widget.item(item)['values']
        text = values[index] if len(values) else None
        bbox = widget.bbox(item, column)
        if bbox and text:
            self.selected = '%02d' % text
            self.show_selection(bbox)

    def show_selection(self, bbox):
        canvas, text = self.canvas, self.selected
        x, y, width, height = bbox
        textw = self.font.measure(text)
        canvas.configure(width=width, height=height)
        canvas.coords(canvas.text, width - textw, height / 2 - 1)
        canvas.itemconfigure(canvas.text, text=text)
        canvas.place(x=x, y=y)

    @property
    def selection(self):
        if self.selected:
            year, month = self.date.year, self.date.month
            return datetime.date(year, month, int(self.selected))

def main():
    root = tk.Tk()
    root.title('Tkinter Calendar')
    ttkcal = TtkCalendar(firstweekday=calendar.SUNDAY)
    ttkcal.pack(expand=True, fill=tk.BOTH)
    root.mainloop()

if __name__ == '__main__':
    main()
```

# 工作原理...

我们的 `TtkCalendar` 类可以通过传递一些选项作为关键字参数来进行自定义。它们在初始化时被检索出来，并在没有提供的情况下使用一些默认值；例如，如果当前日期用于日历的初始年份和月份：

```py
    def __init__(self, master=None, **kw):
        now = datetime.datetime.now()
        fwday = kw.pop('firstweekday', calendar.MONDAY)
        year = kw.pop('year', now.year)
        month = kw.pop('month', now.month)
        sel_bg = kw.pop('selectbackground', '#ecffc4')
        sel_fg = kw.pop('selectforeground', '#05640e')

        super().__init__(master, **kw)
```

然后，我们定义一些属性来存储日期信息：

+   `selected`：保存所选日期的值

+   `date`：表示在日历上显示的当前月份的日期

+   `calendar`：具有周和月份名称信息的公历日历

小部件的可视部分在 `create_header()` 和 `create_table()` 方法中内部实例化，稍后我们将对其进行介绍。

我们还使用了一个 `tkfont.Font` 实例来帮助我们测量字体大小。

一旦这些属性被初始化，通过调用 `build_calendar()` 方法来安排日历的可视部分：

```py
        self.selected = None
        self.date = datetime.date(year, month, 1)
        self.cal = calendar.TextCalendar(fwday)
        self.font = tkfont.Font(self)
        self.header = self.create_header()
        self.table = self.create_table()
        self.canvas = self.create_canvas(sel_bg, sel_fg)
        self.build_calendar()
```

`create_header()` 方法使用 `ttk.Style` 来显示箭头以前后移动月份。它返回显示当前月份名称的标签：

```py
    def create_header(self):
        left_arrow = {'children': [('Button.leftarrow', None)]}
        right_arrow = {'children': [('Button.rightarrow', None)]}
        style = ttk.Style(self)
        style.layout('L.TButton', [('Button.focus', left_arrow)])
        style.layout('R.TButton', [('Button.focus', right_arrow)])

        hframe = ttk.Frame(self)
        lbtn = ttk.Button(hframe, style='L.TButton',
                          command=lambda: self.move_month(-1))
        rbtn = ttk.Button(hframe, style='R.TButton',
                          command=lambda: self.move_month(1))
        label = ttk.Label(hframe, width=15, anchor='center')

        # ...
        return label
```

`move_month()` 回调隐藏了用画布字段突出显示的当前选择，并将指定的 `offset` 添加到当前月份以设置 `date` 属性为上一个或下一个月份。然后，日历再次重绘，显示新月份的日期：

```py
    def move_month(self, offset):
        self.canvas.place_forget()
        month = self.date.month - 1 + offset
        year = self.date.year + month // 12
        month = month % 12 + 1
        self.date = datetime.date(year, month, 1)
        self.build_calendar()
```

日历主体是在 `create_table()` 中使用 `ttk.Treeview` 小部件创建的，它在一行中显示当前月份的每周：

```py
    def create_table(self):
        cols = self.cal.formatweekheader(3).split()
        table = ttk.Treeview(self, show='', selectmode='none',
                             height=7, columns=cols)
        table.bind('<Map>', self.minsize)
        table.pack(expand=1, fill=tk.BOTH)
        table.tag_configure('header', background='grey90')
        table.insert('', tk.END, values=cols, tag='header')
        for _ in range(6):
            table.insert('', tk.END)

        width = max(map(self.font.measure, cols))
        for col in cols:
            table.column(col, width=width, minwidth=width, anchor=tk.E)
        return table
```

在 `create_canvas()` 方法中实例化了突出显示选择的画布。由于它根据所选项的尺寸调整其大小，因此如果窗口被调整大小，它也会隐藏自己：

```py
    def create_canvas(self, bg, fg):
        canvas = tk.Canvas(self.table, background=bg,
                           borderwidth=0, highlightthickness=0)
        canvas.text = canvas.create_text(0, 0, fill=fg, anchor=tk.W)
        handler = lambda _: canvas.place_forget()
        canvas.bind('<ButtonPress-1>', handler)
        self.table.bind('<Configure>', handler)
        self.table.bind('<ButtonPress-1>', self.pressed)
        return canvas
```

通过迭代 `ttk.Treeview` 表格的周和项目位置来构建日历。使用 `itertools` 模块中的 `zip_longest()` 函数，我们遍历包含大多数项目的集合，并将缺少的日期留空字符串：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/92fb9a31-6eb8-431c-8244-13316aa52fde.png)

这种行为对每个月的第一周和最后一周很重要，因为这通常是我们找到这些空白位置的地方：

```py
    def build_calendar(self):
        year, month = self.date.year, self.date.month
        month_name = self.cal.formatmonthname(year, month, 0)
        month_weeks = self.cal.monthdayscalendar(year, month)

        self.header.config(text=month_name.title())
        items = self.table.get_children()[1:]
        for week, item in zip_longest(month_weeks, items):
            week = week if week else [] 
            fmt_week = ['%02d' % day if day else '' for day in week]
            self.table.item(item, values=fmt_week)
```

当您单击表项时，`pressed()` 事件处理程序如果该项存在则设置选择，并重新显示画布以突出显示选择：

```py
    def pressed(self, event):
        x, y, widget = event.x, event.y, event.widget
        item = widget.identify_row(y)
        column = widget.identify_column(x)
        items = self.table.get_children()[1:]

        if not column or not item in items:
            # clicked te header or outside the columns
            return

        index = int(column[1]) - 1
        values = widget.item(item)['values']
        text = values[index] if len(values) else None
        bbox = widget.bbox(item, column)
        if bbox and text:
            self.selected = '%02d' % text
            self.show_selection(bbox)
```

`show_selection()` 方法将画布放置在包含选择的边界框上，测量文本大小以使其适合其上方：

```py
    def show_selection(self, bbox):
        canvas, text = self.canvas, self.selected
        x, y, width, height = bbox
        textw = self.font.measure(text)
        canvas.configure(width=width, height=height)
        canvas.coords(canvas.text, width - textw, height / 2 - 1)
        canvas.itemconfigure(canvas.text, text=text)
        canvas.place(x=x, y=y)
```

最后，`selection` 属性使得可以将所选日期作为 `datetime.date` 对象获取。在我们的示例中没有直接使用它，但它是与 `TtkCalendar` 类一起使用的 API 的一部分：

```py
    @property
    def selection(self):
        if self.selected:
            year, month = self.date.year, self.date.month
            return datetime.date(year, month, int(self.selected))
```

# 另请参阅

+   *使用 Treeview 小部件* 配方

+   *应用 Ttk 样式* 配方
