# Python GUI 编程（三）

> 原文：[`zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa`](https://zh.annas-archive.org/md5/9d5f7126bd532a80dd6a9dce44175aaa)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用样式和主题改进外观

虽然程序可以完全使用黑色、白色和灰色的纯文本进行功能性操作，但是对颜色、字体和图像的微妙使用可以增强视觉吸引力和可用性，即使是最实用的应用程序也是如此。您的数据输入应用程序也不例外。您的老板和用户已经向您提出了几个问题，似乎需要使用 Tkinter 的样式功能。您的老板已经告诉您，总部要求所有内部软件突出显示公司标志，而数据输入人员已经提到了应用程序的可读性和整体外观的各种问题。

在本章中，我们将学习一些 Tkinter 的功能，这些功能将帮助我们解决这些问题：

+   我们将学习如何向我们的 Tkinter GUI 添加图像

+   我们将学习如何调整 Tkinter 小部件的字体和颜色，直接和使用标签

+   我们将学习如何使用样式和主题调整 Ttk 小部件的外观

# 在 Tkinter 中使用图像

我们将处理的第一个要求是添加公司标志。由于公司政策的结果，您的应用程序应该嵌入公司标志，并且如果可能的话，您已被要求使您的应用程序符合要求。

要将此图像添加到我们的应用程序中，您需要了解 Tkinter 的`PhotoImage`类。

# Tkinter PhotoImage

包括`Label`和`Button`在内的几个 Tkinter 小部件可以接受`image`参数，从而允许它们显示图像。在这些情况下，我们不能简单地将图像文件的路径放入其中；相反，我们必须创建一个`PhotoImage`对象。

创建`PhotoImage`对象相当简单：

```py
myimage = tk.PhotoImage(file='my_image.png')
```

通常使用关键字参数`file`调用`PhotoImage`，该参数指向文件路径。或者，您可以使用`data`参数指向包含图像数据的`bytes`对象。

`PhotoImage`可以在接受`image`参数的任何地方使用，例如`Label`：

```py
mylabel = tk.Label(root, image=myimage)
```

必须注意的是，您的应用程序必须保留对`PhotoImage`对象的引用，该引用将在图像显示期间保持在范围内；否则，图像将不会显示。

考虑以下示例：

```py
import tkinter as tk
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        smile = tk.PhotoImage(file='smile.gif')
        tk.Label(self, image=smile).pack()
App().mainloop()
```

如果您运行此示例，您会注意到没有显示任何图像。这是因为`smile`变量在`__init__()`退出时立即被销毁；由于没有对`PhotoImage`对象的引用，图像消失了，即使我们已经将其打包到布局中。要解决此问题，您需要将`image`对象存储在实例变量中，例如`self.smile`，这样在方法返回后它将继续存在。

Tkinter 中的图像支持仅限于 GIF、PGM、PPM 和（从版本 8.6 开始）PNG 文件。要使用其他文件格式，如 JPEG 或 BMP，您需要使用图像处理库（如 Pillow）将它们转换为 Tkinter 可以理解的格式。

在撰写本文时，macOS 的 Python 3 附带 Tkinter 8.5。要在 macOS 上使用 PNG，您需要升级到 Tkinter 8.6 或更高版本，或者使用 Pillow。有关 Tcl/Tk 和 macOS 的更多信息，请参见[`www.python.org/download/mac/tcltk/`](https://www.python.org/download/mac/tcltk/)。Pillow 不在 Python 标准库中。要安装它，请按照[`python-pillow.org`](http://python-pillow.org)上的说明操作。

# 添加公司标志

凭借我们对`PhotoImage`的了解，将公司标志添加到我们的程序应该很简单；但是，我们必须解决如何确定图像文件的路径的问题。路径可以是绝对路径，也可以是相对于工作目录的路径，但我们不知道另一个系统上的路径是什么。幸运的是，有一种方法可以找出来。

在`abq_data_entry`目录下，创建一个名为`images`的新目录，在其中放置一个适当大小的 PNG 文件，我们可以在我们的应用程序中使用（图像具有 8x5 的宽高比，所以在这种情况下，我们使用`32x20`）。要获取图像的绝对路径，我们将依赖 Python 中一个名为`__file__`的内置变量。在任何 Python 脚本中，`__file__`变量将包含当前脚本文件的绝对路径，我们可以使用它来定位我们的图像文件。

例如，从我们的`application.py`文件中，我们可以使用这段代码找到我们的图像：

```py
from os import path
image_path = path.join(path.dirname(__file__),
                       'images/abq_logo_32x20.png')
```

在这个例子中，我们首先通过调用`path.dirname(__file__)`找到包含`application.py`文件的目录。这给了我们`abq_data_entry`的绝对路径，从中我们知道图像的相对路径。我们可以连接这两个路径，并获得图像的绝对路径，无论程序安装在文件系统的何处。

这种方法可以正常工作，但考虑到我们可能希望从应用程序的各种模块中访问图像，并且不得不在多个文件中导入`path`并重复这个逻辑，这不是最佳的。一个更干净的方法是将我们的`images`文件夹视为 Python 包，并在其中创建指向图像路径的常量。

首先，在`images`文件夹内创建一个`__init__.py`文件，并添加以下代码：

```py
from os import path

IMAGE_DIRECTORY = path.dirname(__file__)

ABQ_LOGO_32 = path.join(IMAGE_DIRECTORY, 'abq_logo-32x20.png')
ABQ_LOGO_64 = path.join(IMAGE_DIRECTORY, 'abq_logo-64x40.png')
```

现在，我们的`application.py`模块可以简单地这样做：

```py
from .images import ABQ_LOGO_32
```

`Application.__init__()`然后可以使用`ABQ_LOGO_32`中的路径创建一个`PhotoImage`对象：

```py
        self.logo = tk.PhotoImage(file=ABQ_LOGO_32)
        tk.Label(self, image=self.logo).grid(row=0)
```

创建`PhotoImage`对象后，我们使用`Label`显示它。如果你运行应用程序，你应该会看到标志出现在顶部。

# 设置我们的窗口图标

我们还可以将标志添加为我们的窗口图标，这比保留默认的 Tkinter 标志更有意义。这样，标志将显示在窗口装饰和操作系统的任务栏中。

作为 Tk 的子类，我们的`Application`对象有一个名为`iconbitmap`的方法，应该可以根据图标文件的路径设置图标。不幸的是，这个方法对于给定的文件类型非常挑剔，并且在各个平台上工作效果不佳。我们可以使用`PhotoImage`和特殊的 Tk `call()`方法来解决这个问题。

`call`方法允许我们直接调用 Tcl/Tk 命令，并且可以用于访问 Tkinter 包装不好或根本不包装的 Tk 功能。

代码如下：

```py
        self.taskbar_icon = tk.PhotoImage(file=ABQ_LOGO_64)
        self.call('wm', 'iconphoto', self._w, self.taskbar_icon)
```

第一行创建了另一个`PhotoImage`对象，引用了一个更大的标志的版本。接下来，我们执行`self.call()`，传入 Tcl/Tk 命令的各个标记。在这种情况下，我们调用`wm iconphoto`命令。`self._w`返回我们的`Application`对象的 Tcl/Tk 名称；最后，我们传入我们创建的`PhotoImage`对象。

希望你不需要经常使用`call`，但如果你需要，你可以在这里找到有关 Tcl/Tk 命令的文档：[`www.tcl.tk/doc/`](https://www.tcl.tk/doc/) 。

运行你的应用程序，注意图标已经改变了。

# 样式化 Tkinter 小部件

Tkinter 基本上有两种样式系统：旧的 Tkinter 小部件系统和更新的 Ttk 系统。由于我们仍然需要使用 Tkinter 和 Ttk 小部件，我们将不得不查看这两个系统。让我们首先看一下旧的 Tkinter 系统，并对我们应用程序中的 Tkinter 小部件应用一些样式。

# 小部件颜色属性

基本的 Tkinter 小部件允许你更改两种颜色：**前景**，主要是文本和边框，和**背景**，指其余的小部件。这些可以使用`foreground`和`background`参数，或它们的别名`fg`和`bg`来设置。

这个例子展示了在`Label`上使用颜色：

```py
l = tk.Label(text='Hot Dog!', fg='yellow', bg='red')
```

颜色的值可以是颜色名称字符串或 CSS 样式的 RGB 十六进制字符串。

例如，这段代码产生了相同的效果：

```py
l2 = tk.Label(text='Also Hot Dog!',
              foreground='#FFFF00',
              background='#FF0000')
```

Tkinter 识别了 700 多种命名颜色，大致对应于 Linux 和 Unix 上使用的 X11 显示服务器或 Web 设计师使用的 CSS 命名颜色。有关完整列表，请参见[`www.tcl.tk/man/tcl8.6/TkCmd/colors.htm`](https://www.tcl.tk/man/tcl8.6/TkCmd/colors.htm)。

# 在我们的表单上使用小部件属性

数据输入人员收到的一个请求是增加数据输入表单上各个部分之间的视觉分隔。我们的`LabelFrame`小部件是简单的 Tkinter 小部件（不是 Ttk），因此我们可以通过给各个部分设置有色的背景来相对简单地实现这一点。

经过一番思考和讨论，您决定按以下方式对各个部分进行颜色编码：

+   记录信息将使用`khaki`，表明用于纸质记录的经典马尼拉文件夹

+   环境信息将使用`lightblue`，象征着水和空气

+   植物信息将具有`lightgreen`背景，象征着植物

+   `Notes`已经足够与众不同，因此它将保持不变

打开`views.py`并编辑`DataRecordForm.__init__()`中的`LabelFrame`调用：

```py
        recordinfo = tk.LabelFrame(
            self, text="Record Information",
            bg="khaki", padx=10, pady=10)
...
        environmentinfo = tk.LabelFrame(
            self, text="Environment Data",
            bg='lightblue', padx=10, pady=10)
...
        plantinfo = tk.LabelFrame(
            self, text="Plant Data",
            bg="lightgreen", padx=10, pady=10)
```

请注意，我们在这里添加了一些填充，以使小部件周围的颜色更加明显，并在表单中创建更多的分隔。

我们应该在`Notes`小部件周围添加类似的填充：

```py
   self.inputs['Notes'].grid(sticky="w", row=4, column=0,
                             padx=10, pady=10)
```

在这种情况下，我们在`grid`调用中添加了填充，以便整个`LabelInput`被移动。

至少在 Debian Linux 上，结果看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/6133ca48-cf64-43e2-bcb9-19fa095453eb.png)

尽管还不是一个视觉杰作，但我们在表单各个部分之间有了一些分隔和颜色编码。

# 使用标签

前景和背景对于按钮等简单小部件已经足够了，但是像`Text`小部件或 Ttk `Treeview`这样的更复杂的 Tkinter 小部件依赖于一种**标签**系统。在 Tkinter 中，标签是可以应用颜色和字体设置的小部件内容的命名区域。为了看看这是如何工作的，让我们构建一个粗糙但漂亮的 Python shell。

我们将首先创建一个`Text`小部件：

```py
import tkinter as tk
text = tk.Text(width=50, height=20, bg='black', fg='lightgreen')
text.pack()
```

在这里，我们使用`fg`和`bg`参数设置了一个程序员喜欢的黑底绿字的主题。但是，我们不仅仅要绿色的文本，让我们为我们的提示和解释器输出配置不同的颜色。

为此，我们将定义一些标签：

```py
text.tag_configure('prompt', foreground='magenta')
text.tag_configure('output', foreground='yellow')
```

`tag_configure`方法允许我们在`Text`小部件上创建和配置标签。我们为我们的 shell 提示创建了一个名为`'prompt'`的标签，另一个名为`'output'`的标签。

要使用给定标签插入文本，我们需要执行以下操作：

```py
text.insert('end', '>>> ', ('prompt',))
```

正如您可能记得的那样，`Text.insert`方法将索引和字符串作为其前两个参数。请注意第三个参数：这是我们想要标记插入的文本的标签的元组。这个值必须是一个元组，即使您只使用一个标签。

如果您将`text.mainloop()`添加到代码的末尾并运行它，您会看到我们有一个黑色的文本输入窗口，带有品红色的提示，但如果您输入文本，它将显示为绿色。到目前为止一切顺利；现在，让我们让它执行一些 Python。

在`mainloop()`调用之前创建一个函数：

```py
def on_return(*args):
    cmd = text.get('prompt.last', 'end').strip()
```

当从`Text`小部件中检索文本时，我们需要为我们想要检索的文本提供起始和结束索引。请注意，我们在索引中使用了我们的标签名称。`prompt.last`告诉 Tkinter 从标记为`prompt`的区域的结束之后开始获取文本。

接下来，让我们执行`cmd`：

```py
     if cmd:
        try:
            output = str(eval(cmd))
        except Exception as e:
            output = str(e)
```

如果我们的`cmd`实际上包含任何内容，我们将尝试使用`eval`执行它，然后将响应值的字符串存储为`output`。如果它抛出异常，我们将获得我们的异常作为字符串，并将其设置为`output`。

然后，我们只需显示我们的`output`：

```py
   text.insert('end', '\n' + output, ('output',))
```

我们插入我们的`output`文本，前面加上一个换行符，并标记为`output`。

我们将通过给用户返回一个`prompt`来完成该函数：

```py
    text.insert('end', '\n>>> ', ('prompt',))
    return 'break'
```

我们还在这里返回字符串`break`，告诉 Tkinter 忽略触发回调的原始事件。因为我们将从`Return`/`Enter`按键触发这个操作，所以我们希望在完成后忽略该按键。如果不这样做，按键将在我们的函数返回后执行，用户将在提示下的下一行。

最后，我们需要将我们的函数绑定到`Return`键：

```py
text.bind('<Return>', on_return)
```

请注意，`Enter`/`Return`键的事件始终是`<Return>`，即使在非苹果硬件上（该按键更常被标记为`Enter`）也是如此。

你的应用程序应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/db7df434-b620-4c9e-b45c-b34a34475830.png)

虽然这个 shell 不会很快取代 IDLE，但它看起来确实很好看，你觉得呢？

# 使用标签样式化我们的记录列表

虽然`Treeview`是一个 Ttk 小部件，但它使用标签来控制单独行的样式。我们可以利用这一点来回答数据输入人员提出的另一个要求：他们希望记录列表突出显示在当前会话期间更新和插入的记录。

首先，我们需要做的是让我们的`Application`对象在会话期间跟踪哪些行已被更新或插入。

在`Application.__init__()`中，我们将创建以下实例变量：

```py
        self.inserted_rows.clear()
        self.updated_rows.clear()
```

当记录保存时，我们需要更新这些列表中的一个或另一个与其行号。我们将在`Application.on_save()`中完成这个操作，在记录保存后但在重新填充记录列表之前。

首先，我们将检查更新的记录：

```py
       if rownum is not None:
           self.updated_rows.append(rownum)
```

更新有`rownum`，没有`None`值，所以如果是这种情况，我们将把它追加到列表中。如果记录不断更新，我们的列表中会有重复，但在我们操作的规模上，这实际上并不重要。

现在，我们需要处理插入：

```py
       else:
           rownum = len(self.data_model.get_all_records()) - 1
           self.inserted_rows.append(rownum)
```

插入的记录会更麻烦一些，因为我们没有一个行号可以记录。不过，我们知道插入总是添加到文件的末尾，所以它应该比文件中的行数少一个。

我们的插入和更新记录将保留到程序会话结束（用户退出程序）时，但在用户选择新文件的情况下，我们需要手动删除它们。

我们可以通过在`on_file_select()`中清除列表来处理这个问题：

```py
       if filename:
            ...
            self.inserted_rows = []
            self.updated_rows = []
```

现在，我们的控制器知道插入和更新的记录。不过，我们的记录列表并不知道；我们需要解决这个问题。

在`Application.__init__()`中找到`RecordList`调用，并将这些变量添加到其参数中：

```py
       self.recordlist = v.RecordList(
            self, self.callbacks,
            self.inserted_rows,
            self.updated_rows)
```

现在，我们需要回到`views.py`，告诉`RecordList`如何处理这些信息。

我们将首先更新其参数列表并将列表保存到实例变量中：

```py
    def __init__(self, parent, callbacks,
                 inserted, updated,
                 *args, **kwargs):
        self.inserted = inserted
        self.updated = updated
```

接下来，我们需要配置适当颜色的标签。我们的数据输入人员认为`lightgreen`是插入记录的合理颜色，`lightblue`是更新记录的颜色。

在`__init__()`中添加以下代码，放在`self.treeview`配置之后：

```py
      self.treeview.tag_configure('inserted', background='lightgreen')
      self.treeview.tag_configure('updated', background='lightblue')
```

就像我们之前对`Text`小部件所做的那样，我们调用`tag_configure`来将背景颜色设置与我们的标签名称连接起来。请注意，这里不仅限于一个配置设置；我们可以在同一个调用中添加`foreground`、`font`或其他配置设置。

要将标签添加到我们的`TreeView`行中，我们需要更新`populate`方法。

在`for`循环中，在插入行之前，我们将添加这段代码：

```py
           if self.inserted and rownum in self.inserted:
                tag = 'inserted'
            elif self.updated and rownum in self.updated:
                tag = 'updated'
            else:
                tag = ''
```

如果`inserted`列表存在且我们的`rownum`在其中，我们希望`tag`等于`'inserted'`；如果`updated`列表存在且我们的`rownum`在其中，我们希望它等于`'updated'`。否则，我们将其留空。

现在，我们的`treeview.insert`调用只需要用这个`tag`值来修改：

```py
            self.treeview.insert('', 'end', iid=str(rownum),
                                 text=str(rownum), values=values,
                                 tag=tag)
```

运行应用程序并尝试插入和更新一些记录。

你应该得到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/b8fb6912-02db-4fc5-a202-10d600d31c28.png)

# Tkinter 字体

在 Tkinter 中，有三种指定小部件字体的方法。

最简单的方法就是使用字符串格式：

```py
tk.Label(text="Direct font format", 
         font="Times 20 italic bold")
```

字符串采用`Font-family` `size` `styles`的格式，其中`styles`可以是任何有效的文本样式关键字的组合。

这些单词包括：

+   `bold` 用于粗体文本，或 `normal` 用于正常字重

+   `italic` 用于斜体文本，或 `roman` 用于常规倾斜

+   `underline` 用于下划线文本

+   `overstrike` 用于删除线文本

除了字体系列之外，其他都是可选的，尽管如果要指定任何样式关键字，您需要指定一个`size`。样式关键字的顺序无关紧要，但是重量和斜体关键字是互斥的（也就是说，您不能同时拥有`bold` `normal`或`italic roman`）。

字符串方法的一个缺点是它无法处理名称中带有空格的字体。

要处理这些，您可以使用字体的元组格式：

```py
tk.Label(
    text="Tuple font format",
    font=('Droid sans', 15, 'overstrike'))
```

这种格式与字符串格式完全相同，只是不同的组件被写成元组中的项目。`size`组件可以是整数或包含数字的字符串，这取决于值来自何处。

这种方法适用于在启动时设置少量字体更改的情况，但是对于需要动态操作字体设置的情况，Tkinter 具有一种称为**命名字体**的功能。这种方法使用一个可以分配给小部件然后动态更改的`Font`类。

要使用`Font`，必须从`tkinter.font`模块中导入它：

```py
from tkinter.font import Font
```

现在，我们可以创建一个自定义的`Font`对象并将其分配给小部件：

```py
labelfont = Font(family='Courier', size=30,
                 weight='bold', slant='roman',
                 underline=False, overstrike=False)
tk.Label(text='Using the Font class', font=labelfont).pack()
```

正如您所看到的，`Font`构造函数参数与字符串和元组字体规范中使用的关键字相关。

一旦分配了这个字体，我们就可以在运行时动态地改变它的各个方面：

```py
def toggle_overstrike():
    labelfont['overstrike'] = not labelfont['overstrike']

tk.Button(text='Toggle Overstrike', command=toggle_overstrike).pack()
```

在这个例子中，我们提供了一个`Button`，它将切换`overstrike`属性的开和关。

Tk 已经配置了几个命名字体；我们可以使用`tkinter.font`模块的`nametofont`函数从中创建 Python `Font`对象。

这个表格显示了 Tkinter 中包含的一些命名字体：

| **字体名称** | **默认为** | **用于** |
| --- | --- | --- |
| `TkCaptionFont` | 系统标题字体 | 窗口和对话框标题栏 |
| `TkDefaultFont` | 系统默认字体 | 未另行指定的项目 |
| `TkFixedFont` | 系统等宽字体 | 无 |
| `TkHeadingFont` | 系统标题字体 | 列表和表格中的列标题 |
| `TkIconFont` | 系统图标字体 | 图标标题 |
| `TkMenuFont` | 系统菜单字体 | 菜单标签 |
| `TkSmallCaptionFont` | 系统标题 | 子窗口，工具对话框 |
| `TkTextFont` | 系统输入字体 | 输入小部件：Entry，Spinbox 等 |
| `TkTooltipFont` | 系统工具提示字体 | 工具提示 |

如果您想知道 Tkinter 在您的操作系统上使用的字体，可以使用`tkinter.font.names()`函数检索它们的列表。

要改变应用程序的整体外观，我们可以覆盖这些命名字体，更改将应用于所有未另行设置字体的小部件。

例如：

```py
import tkinter as tk
from tkinter.font import nametofont

default_font = nametofont('TkDefaultFont')
default_font.config(family='Helvetica', size=32)

tk.Label(text='Feeling Groovy').pack()
```

在这个例子中，我们使用`nametofont`函数检索`TkDefaultFont`的对象，Tkinter 应用程序的默认命名字体类。检索后，我们可以设置它的字体`family`和`size`，为使用`TkDefaultFont`的所有小部件更改这些值。

`Label`然后显示这个调整的结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/12b670be-7fa5-4774-acb0-5cae16efab46.png)

# 给用户提供字体选项

我们的一些数据输入用户抱怨应用程序的字体有点太小，不容易阅读，但其他人不喜欢您增加它，因为这样会使应用程序对屏幕来说太大。为了满足所有用户，我们可以添加一个配置选项，允许他们设置首选字体大小。

我们需要首先向我们的设置模型添加一个`'font size'`选项。

打开`models.py`并将`SettingsModel.variables`字典追加如下：

```py
    variables = {
        ...
        'font size': {'type': 'int', 'value': 9}
```

接下来，我们将在选项菜单中添加一组单选按钮，以便用户可以设置值。

打开`views.py`，让我们在将选项菜单添加到主菜单之前开始创建一个菜单：

```py
        font_size_menu = tk.Menu(self, tearoff=False)
        for size in range(6, 17, 1):
            font_size_menu.add_radiobutton(
                label=size, value=size,
                variable=settings['font size'])
        options_menu.add_cascade(label='Font size', 
                                 menu=font_size_menu)
```

这应该看起来很熟悉，因为我们在学习 Tkinter `Menu`小部件时创建了一个几乎相同的字体大小菜单。我们允许字体大小从`6`到`16`，这应该为我们的用户提供足够的范围。

在`Application`类中，让我们创建一个方法，将应用程序的字体设置应用到我们的应用程序字体中：

```py
    def set_font(self, *args):
```

我们包括`*args`，因为`set_font`将作为`trace`回调调用，所以我们需要捕获发送的任何参数，尽管我们不会使用它们。

接下来，我们将获取当前的`'font size'`值：

```py
   font_size = self.settings['font size'].get()
```

我们需要更改几个命名字体，不仅仅是`TkDefaultFont`。对于我们的应用程序，`TkDefaultFont`、`TkTextFont`和`TkMenuFont`应该足够了。

我们只需循环遍历这些，检索类并在每个类上设置大小：

```py
        font_names = ('TkDefaultFont', 'TkMenuFont', 'TkTextFont')
        for font_name in font_names:
            tk_font = nametofont(font_name)
            tk_font.config(size=font_size)
```

我们需要做的最后一件事是确保调用此回调。

在`Application.__init__()`中的`load_settings()`调用之后，添加以下内容：

```py
        self.set_font()
        self.settings['font size'].trace('w', self.set_font)
```

我们调用`set_font()`一次以激活任何保存的`字体大小`设置，然后设置一个`trace`，以便在更改值时运行它。

运行应用程序并尝试使用字体菜单。它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/8fb2114c-d0ab-4d97-96b0-4523e44ddb24.png)

# Ttk 小部件的样式

Ttk 小部件在功能上代表了对标准 Tkinter 小部件的重大改进。这种灵活性使得 Ttk 小部件能够在各个平台上模仿本机 UI 控件，但代价是：Ttk 样式令人困惑，文档不完善，有时不一致。

要了解 Ttk 样式，让我们从最基本的元素到最复杂的元素开始使用一些词汇：

+   Ttk 从**元素**开始。元素是小部件的一部分，例如边框、箭头或可以输入文本的字段。

+   元素使用**布局**组成一个完整的小部件（例如`Combobox`或`Treeview`）。

+   **样式**是定义颜色和字体设置的属性集合：

+   每个样式都有一个名称，通常是 T，加上小部件的名称，例如`TButton`或`TEntry`。也有一些例外。

+   布局中的每个元素都引用一个或多个样式属性来定义其外观。

+   小部件有许多**状态**，这些状态是可以打开或关闭的标志：

+   样式可以通过**映射**进行配置，将属性值连接到状态或状态的组合

+   一组样式称为**主题**。Tkinter 在不同平台上提供了不同的主题。：

+   一个主题可能不仅定义不同的样式，还定义不同的布局。例如，默认 macOS 主题上的`ttk.Button`可能包含不同的元素集，与在 Windows 中使用默认主题的`ttk.Button`相比，应用样式设置的方式也不同。

如果你现在感到困惑，没关系。让我们深入了解`ttk.Combobox`的解剖，以更好地了解这些概念。

# 探索 Ttk 小部件

为了更好地了解 Ttk 小部件是如何构建的，请在 IDLE 中打开一个 shell 并导入`tkinter`、`ttk`和`pprint`：

```py
>>> import tkinter as tk
>>> from tkinter import ttk
>>> from pprint import pprint
```

现在，创建一个根窗口、`Combobox`和`Style`对象：

```py
>>> root = tk.Tk()
>>> cb = ttk.Combobox(root)
>>> cb.pack()
>>> style = ttk.Style()
```

`Style`对象可能命名有点不准确；它并不指向单个样式，而是给了我们一个处理当前主题的样式、布局和映射的句柄。

为了检查我们的`Combobox`，我们首先使用`winfo_class()`方法获取它的`stylename`：

```py
>>> cb_stylename = cb.winfo_class()
>>> print(cb_stylename)
TCombobox
```

然后，我们可以使用`Style.layout()`方法检查`Combobox`的布局：

```py
>>> cb_layout = style.layout(cb_stylename)
>>> pprint(cb_layout)
[('Combobox.field',
  {'children':  [('Combobox.downarrow', 
                {'side': 'right', 'sticky': 'ns'}),
                ('Combobox.padding',
                {'children': [('Combobox.textarea', 
                {'sticky': 'nswe'})],
                'expand': '1',
                'sticky': 'nswe'})],
                'sticky': 'nswe'})]
```

通过将样式名称（在本例中为`TCombobox`）传递给`style.layout()`方法，我们得到一个布局规范，显示用于构建此小部件的元素的层次结构。

在这种情况下，元素是`"Combobox.field"`、`"Combobox.downarrow"`、`"Combobox.padding"`和`"Combobox.textarea"`。正如您所看到的，每个元素都有与`pack()`中传递的定位属性类似的关联定位属性。

`layout`方法也可以用于通过传入新的布局规范来替换样式的布局。不幸的是，这需要替换整个布局规范，您不能只是在原地调整或替换单个元素。

要查看样式如何连接到元素，我们可以使用`style.element_options()`方法。该方法接受一个元素名称，并返回一个可以用于更改它的选项列表。

例如：

```py
>>> pprint(style.element_options('Combobox.downarrow'))
('background', 'relief', 'borderwidth', 'arrowcolor', 'arrowsize')
```

这告诉我们`Combobox`的`downarrow`元素使用这些样式属性来确定其外观。要更改这些属性，我们将需要使用`style.configure()`方法。

让我们将箭头的颜色更改为`red`：

```py
>>> style.configure('TCombobox', arrowcolor='red')
```

您应该看到`arrowcolor`已更改为`red`。这就是我们需要了解的配置小部件进行静态更改的全部内容，但是动态更改呢？

要进行动态更改，我们需要了解小部件的状态。

我们可以使用`state`方法检查或更改我们的`Combobox`的状态：

```py
>>> print(cb.state())
()
>>> cb.state(['active', 'invalid'])
('!active', '!invalid')
>>> print(cb.state())
('active', 'invalid')
```

`Combobox.state()`没有参数时将返回一个包含当前设置的状态标志的元组；当与参数一起使用时（参数必须是字符串序列），它将设置相应的状态标志。

要关闭状态标志，需要在标志名称前加上`!`：

```py
>>> cb.state(['!invalid'])
('invalid',)
>>> print(cb.state())
('active',)
```

当您调用`state()`并带有参数来更改值时，返回值是一个元组，其中包含一组状态，如果应用，则会撤消您刚刚设置的状态更改。这在您想要临时设置小部件的状态，然后将其返回到先前（未知）状态的情况下可能会有用。

您不能只是使用任何字符串来调用`state()`；它们必须是以下之一：

+   `active`

+   `disabled`

+   `focus`

+   `pressed`

+   `selected`

+   `background`

+   `readonly`

+   `alternate`

+   `invalid`

每个小部件如何使用这些状态取决于小部件；并非每个`state()`默认情况下都配置为具有效果。

小部件状态通过映射与小部件样式进行交互。我们使用`style.map()`方法来检查或设置每个样式的映射。

看一下`TCombobox`的默认映射：

```py
>>> pprint(style.map(cb_stylename))
{'arrowcolor': [('disabled', '#a3a3a3')],
 'fieldbackground': [('readonly', '#d9d9d9'), 
                     ('disabled', '#d9d9d9')]}
```

正如您所看到的，`TCombobox`默认情况下具有`arrowcolor`和`fieldbackground`属性的样式映射。每个样式映射都是一个元组列表，每个元组都是一个或多个状态标志，后跟一个设置的值。当所有状态标志与小部件的当前状态匹配时，该值生效。

默认映射在设置`disabled`标志时将箭头颜色更改为浅灰色，并在设置`disabled`或`readonly`标志时将字段背景更改为不同的浅灰色。

我们可以使用相同的方法设置自己的样式映射：

```py
>>> style.map('TCombobox', arrowcolor=[('!invalid',  'blue'), ('invalid', 'focus', 'red')])
{}
>>> pprint(style.map('TCombobox'))
{'arrowcolor': [('!invalid', 'blue'), ('invalid', 'focus', 'red')],
 'fieldbackground': [('readonly', '#d9d9d9'), ('disabled', '#d9d9d9')]}
```

在这里，我们已经配置了`arrowcolor`属性，当`invalid`标志未设置时，它为`blue`，当`invalid`和`focus`标志都设置时，它为`red`。请注意，虽然我们对`map`的调用完全覆盖了`arrowcolor`样式映射，但`fieldbackground`映射未受影响。这意味着您可以单独替换样式映射，但不能简单地追加到给定属性的现有映射中。

到目前为止，我们一直在操作`TCombobox`样式，这是所有`Combobox`小部件的默认样式。我们所做的任何更改都会影响应用程序中的每个`Combobox`。我们还可以通过在现有样式名称前加上名称和点来创建从现有样式派生的自定义样式。

例如：

```py
>>> style.configure('Blue.TCombobox', fieldbackground='blue')
>>> cb.configure(style='Blue.TCombobox')
```

`Blue.TCombobox`继承了`TCombobox`的所有属性（包括我们之前配置的`blue` `downarrow`），但可以添加或覆盖自己的设置，而不会影响`TCombobox`。这使您可以为某些小部件创建自定义样式，而不会影响相同类型的其他小部件。

我们可以通过更改主题来一次性改变所有 Ttk 小部件的外观。请记住，主题是一组样式，因此通过更改主题，我们将替换所有内置样式和布局。

不同的主题在不同的平台上发行；要查看您平台上可用的主题，使用`theme_names()`方法：

```py
>>> style.theme_names()
('clam', 'alt', 'default', 'classic')
```

（这些是 Debian Linux 上可用的主题；您的可能不同。）

要查询当前主题，或设置新主题，使用`theme_use()`方法：

```py
>>> style.theme_use()
'default'
>>> style.theme_use('alt')
```

注意当您更改主题时，之前的样式已经消失。但是，如果您切换回默认主题，您会发现您的更改已被保留。

# 为我们的表单标签设置样式

我们可以利用我们对样式的知识来解决的第一件事是我们的表单小部件。由于`LabelInput`小部件保留其默认的沉闷颜色，我们的表单的着色相当丑陋和不完整。我们需要为每个小部件设置样式，以匹配其`LabelInput`的颜色。

在`views.py`文件中，在`DataRecordForm.__init__()`方法的开头添加此内容：

```py
   style = ttk.Style()
```

我们正在创建我们的`Style`对象，以便我们可以开始使用我们的 Ttk 样式。我们需要哪些样式？

+   我们需要为每个部分的 Ttk`Label`小部件设置样式，因为我们需要为`RecordInfo`、`EnvironmentInfo`和`Plant Info`中的小部件设置不同的颜色。

+   我们需要为我们的 Ttk`Checkbutton`设置样式，因为它使用自己内置的标签而不是单独的标签小部件。由于现在只有一个，我们只需要一个样式。

让我们创建这些样式：

```py
        style.configure('RecordInfo.TLabel', background='khaki')
        style.configure(
            'EnvironmentInfo.TLabel',
             background='lightblue')
        style.configure(
            'EnvironmentInfo.TCheckbutton',
            background='lightblue')
        style.configure('PlantInfo.TLabel', background='lightgreen')
```

如您所见，我们正在基于`TLabel`创建自定义样式，但这是为每个单独的部分添加前缀。对于每种样式，我们只需适当设置`background`颜色。

现在是将此样式添加到每个小部件的繁琐任务：

```py
       self.inputs['Date'] = w.LabelInput(
            recordinfo, "Date",
            field_spec=fields['Date'],
            label_args={'style': 'RecordInfo.TLabel'})
```

在每个`LabelInput`调用中，您需要添加一个`label_args`参数，将`style`设置为相应部分的`TLabel`样式。为所有小部件执行此操作。

对于`Checkbutton`，您需要以不同的方式进行操作：

```py
       self.inputs['Equipment Fault'] = w.LabelInput(
            environmentinfo, "Equipment Fault",
            field_spec=fields['Equipment Fault'],
            label_args={'style': 'EnvironmentInfo.TLabel'},
            input_args={'style': 'EnvironmentInfo.TCheckbutton'})
```

在这里，我们设置了`input_args`，因为该样式适用于`Checkbutton`而不是标签（保留`label_args`；我们一会儿会用到）。

如果你此时运行程序，你会看到明显的改进，但还不够完美；错误标签仍然是旧的默认颜色。

要解决这个问题，我们只需要编辑我们的`LabelInput`小部件，以便错误标签也使用`label_args`。

在`widgets.py`中，修复`LabelInput.__init__()`中的`self.error_label`赋值：

```py
        self.error_label = ttk.Label(self, textvariable=self.error,
                                     **label_args)
```

现在，您的应用程序应该具有一致的颜色，并且看起来更加吸引人：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/eabe2216-6517-4675-b812-375b762689ae.png)

# 在错误时为输入小部件设置样式

我们的数据输入人员抱怨说，我们字段中的错误样式并不是非常显眼。目前，我们只是将`foreground`颜色设置为`红色`。

这有几个问题：

+   对于空字段，实际上没有什么可以涂成`红色`

+   我们的色盲用户很难区分`红色`和普通文本颜色

我们将利用我们的样式知识来改进错误样式，并使无效字段更加显眼。

不过，在这之前，您可能需要修复一个小部件的小问题。

# 使我们的 Spinbox 成为 Ttk 小部件

如果您使用的是 Python 3.6 或更早版本，则`Spinbox`小部件仅在`tkinter`中可用，而不在`ttk`中。我们需要修复这个问题，以便我们的错误样式可以保持一致。

在撰写本书时，作者已经提交了一个补丁到 Python 3.7 中，以包括 Ttk`Spinbox`。如果您使用的是 Python 3.7 或更高版本，您可以直接使用`ttk::spinbox`并跳过此部分。

由于`Spinbox`已经在 Tcl/Tk Ttk 库中，为其创建一个 Python 类非常容易。

在`widgets.py`的顶部附近添加此代码：

```py
class TtkSpinbox(ttk.Entry):

    def __init__(self, parent=None, **kwargs):
        super().__init__(parent, 'ttk::spinbox', **kwargs)
```

这就是为这个应用程序创建 Ttk `Spinbox`所需的全部内容。我们只是对`ttk.Entry`进行子类化，但在`__init__`语句中更改了使用的 Ttk 小部件。如果我们需要`Entry`缺少的任何`Spinbox`方法，我们需要提供这些方法；对于这个应用程序，我们不需要其他任何东西。

现在，我们只需要更新我们的`ValidatedSpinbox`类，使其继承`TtkSpinbox`而不是`tk.Spinbox`：

```py
class ValidatedSpinbox(ValidatedMixin, TtkSpinbox):
```

# 更新 ValidatedMixin

现在我们正在使用所有的 Ttk 小部件，我们可以通过一些动态样式来更新我们的`ValidatedMixin`类。

我们将从`__init__()`方法开始，创建一个`Style`对象：

```py
   style = ttk.Style()
```

由于这是一个混合类，我们不知道我们正在混合的小部件的原始样式名称，因此我们将不得不获取它。

记住我们可以用`winfo_class()`来实现这一点：

```py
       widget_class = self.winfo_class()
       validated_style = 'ValidatedInput.' + widget_class
```

在获取小部件类之后，我们通过在其前面添加`ValidatedInput`来创建一个派生样式。为了在错误和非错误外观之间切换我们的输入外观，我们将创建一个样式映射，根据`invalid`状态标志的状态进行切换。

您可以通过调用`style.map()`来实现这一点：

```py
       style.map(
            validated_style,
            foreground=[('invalid', 'white'), ('!invalid', 'black')],
            fieldbackground=[('invalid', 'darkred'), ('!invalid', 'white')]
       )
```

我们仍然使用红色，因为它是一个已建立的“错误颜色”，但这次我们将字段从浅色背景变为深色背景。这应该帮助我们的色盲用户区分错误，即使它们是红色的。

最后，我们需要更新对`self.config`的调用，以包括将小部件的样式设置为我们的新验证样式：

```py
       self.config(
            style=validated_style,
            validate='all',
            ...
```

Ttk 小部件会自动设置它们的`invalid`标志作为内置验证系统的一部分。目前，我们有一个名为`_toggle_error()`的方法，每当验证开始或失败时都会调用它，并设置错误状态。我们可以完全删除该方法，以及所有对它的引用。

如果现在尝试应用程序，您会看到带有错误的字段现在会变成深红色，并带有白色文本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog/img/aa35c553-7642-47b8-b442-8d30c3a69249.png)

# 设置主题

一般来说，任何给定平台上的默认 Ttk 主题可能是最好的选择，但外观是主观的，有时我们可能觉得 Tkinter 做错了。有一种方法可以调整主题可能有助于消除一些粗糙的边缘，并使一些用户更舒适地看待应用程序的外观。

正如我们已经看到的，查询可用主题并设置新主题是相当简单的。让我们创建一个配置选项来更改我们应用程序的主题。

# 构建主题选择器

主题不是用户经常需要更改的东西，正如我们所见，更改主题可能会撤消我们对小部件的样式更改。鉴于此，我们将通过设计我们的主题更改器的方式来确保需要重新启动程序才能实际更改。

我们将首先在我们的`SettingsModel`中添加一个主题选项：

```py
    variables = {
        ...
        'theme': {'type': 'str', 'value': 'default'}
    }
```

每个平台都有一个`theme`别名为`default`，因此这是一个安全和合理的默认值。

接下来，我们的`Application.__init__()`方法将需要检查这个值，并相应地设置`theme`。

在调用`load_settings()`之后添加此代码：

```py
        style = ttk.Style()
        theme = self.settings.get('theme').get()
        if theme in style.theme_names():
            style.theme_use(theme)
```

我们创建一个`Style`对象，查询主题名称的设置，然后（假设保存的`theme`在可用主题中）相应地设置`theme`。

现在剩下的就是创建 UI。

在`views.py`文件中，我们将为`options_menu`创建一个新的子菜单：

```py
        style = ttk.Style()
        themes_menu = tk.Menu(self, tearoff=False)
        for theme in style.theme_names():
            themes_menu.add_radiobutton(
                label=theme, value=theme,
                variable=settings['theme']
            )
        options_menu.add_cascade(label='Theme', menu=themes_menu)
```

在这里，我们只是循环遍历可用的主题，并为每个主题添加一个`Radiobutton`，将其绑定到我们的`settings['theme']`变量。

对于用户来说，可能不明显更改主题需要重新启动，因此让我们确保让他们知道。

我们将为变量添加一个`trace`：

```py
        settings['theme'].trace('w', self.on_theme_change)
```

`on_theme_change`方法将显示一个警告对话框，通知用户需要重新启动才能实现更改。

将其添加到`MainMenu`类的末尾：

```py
    def on_theme_change(self, *args):
        """Popup a message about theme changes"""
        message = "Change requires restart"
        detail = (
            "Theme changes do not take effect"
            " until application restart")
            messagebox.showwarning(
            title='Warning',
            message=message,
            detail=detail)
```

现在，您可以运行应用程序并尝试更改`theme`。哪个主题在您的平台上看起来最好？

你可能会发现，平台上的一些主题会破坏表单中的小部件样式。请记住，主题不仅仅改变默认颜色和字体，它们还改变小部件元素本身的布局和内容。有时，由于属性名称的更改，样式设置在不同主题之间无法传递。

# 总结

在本章中，我们为了美观和可用性改进彻底改变了应用程序的外观和感觉。您学会了如何处理 Tkinter 小部件的颜色和字体设置，以及 Ttk 样式的复杂世界。


# 第九章：使用 unittest 创建自动化测试

随着应用程序的规模和复杂性迅速扩大，您开始对进行更改感到紧张。如果你弄坏了什么？你怎么知道？您需要一种可靠的方法来确保您的程序在代码更改时正常工作。

幸运的是，我们有一种方法：自动化测试。在本章中，您将涵盖以下主题：

+   学习自动化测试的基础知识

+   学习测试 Tkinter 应用程序的具体策略

+   将这些知识应用于我们的数据输入应用程序

# 自动化测试基础

到目前为止，测试我们的应用程序一直是一个启动它，运行它通过一些基本程序，并验证它是否按我们预期的那样工作的过程。这种方法在一个非常小的脚本上可以接受，但随着应用程序的增长，验证应用程序行为变得越来越耗时和容易出错。使用自动化测试，我们可以在几秒钟内始终验证我们的应用逻辑。

自动化测试有几种形式，但最常见的两种是**单元测试**和**集成测试**。单元测试与隔离的代码片段一起工作，允许我们快速验证特定部分的行为。集成测试验证多个代码单元的交互。我们将编写这两种测试来验证我们应用程序的行为。

# 一个简单的单元测试

在其最基本的层面上，单元测试只是一个短小的程序，它在不同条件下运行代码单元，并将其输出与预期结果进行比较。

考虑以下计算类：

```py
import random

class MyCalc:

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def add(self):
        return self.a + self.b

    def mod_divide(self):
        if self.b == 0:
            raise ValueError("Cannot divide by zero")
        return (int(self.a / self.b), self.a % self.b)

    def rand_between(self):
        return ((random.random() * abs(self.a - self.b)) + 
        min(self.a, self.b))
```

该类使用两个数字进行初始化，然后可以对它们执行各种算术方法。

让我们创建一个简单的对该函数的测试：

```py
from mycalc import MyCalc

mc1 = MyCalc(1, 100)
mc2 = MyCalc(10, 4)

try:
    assert mc1.add() == 101, "Test of add() failed."
    assert mc2.mod_divide() == (2, 2), "Test of mod_divide() failed."
except AssertionError as e:
    print("Test failed: ", e)
else:
    print("Tests succeeded!")
```

我们的测试代码创建了一个`MyCalc`对象，然后使用`assert`语句来检查`add()`和`mod_divide()`的输出是否符合预期值。Python 中的`assert`关键字是一个特殊语句，如果其后的语句评估为`False`，则会引发`AssertionError`异常。逗号后的消息字符串是将传递给`AssertionError`异常的错误字符串。

代码`assert statement, "message"`本质上等同于这个：

```py
if not statement:
    raise AssertionError("message")
```

目前，如果运行`MyCalc`的测试脚本，所有测试都会通过。让我们尝试更改`add()`方法如下以使其失败：

```py
    def add(self):
        return self.a - self.b
```

现在，运行测试会出现以下错误：

```py
Test failed:  Test of add() failed.
```

这些测试的价值是什么？假设有人决定对我们的`mod_divide()`方法进行重构：

```py
    def mod_divide(self):
        ...
        return (self.a // self.b, self.a % self.b)
```

由于这些测试通过了，我们可以相当肯定这个算法是正确的，即使我们不理解这段代码。如果重构出现问题，我们的测试应该能够很快地显示出来。

测试纯数学函数相当简单；不幸的是，测试真实应用代码给我们带来了一些需要更复杂方法的挑战。

考虑这些问题：

+   代码单元通常依赖于必须在测试之前设置并在测试之后清除的现有状态。

+   代码可能具有改变代码单元外部对象的副作用。

+   代码可能会与慢速、不可靠或不可预测的资源进行交互。

+   真实应用包含许多需要测试的函数和类，理想情况下，我们希望一次性提醒所有问题。我们目前编写的测试会在第一个失败的断言上停止，因此我们只会一次性提醒一个问题。

为了解决这些问题和其他问题，程序员依赖于**测试框架**，以使编写和执行自动化测试尽可能简单和可靠。

# unittest 模块

`unittest`模块是 Python 标准库的自动化测试框架。它为我们提供了一些强大的工具，使得测试我们的代码相当容易。

`unittest`基于许多测试框架中发现的这些标准单元测试概念：

+   **测试**：一个**测试**是一个单独的方法，要么完成，要么引发异常。测试通常专注于代码的一个单元，比如一个函数、方法或过程。一个测试可以通过，意味着测试成功；失败，意味着代码未通过测试；或者错误，意味着测试本身遇到了问题。

+   **测试用例**：一个测试用例是一组应该一起运行的测试，包含类似的设置和拆卸要求，通常对应一个类或模块。测试用例可以有夹具，这些夹具需要在每个测试之前设置并在每个测试之后拆卸，以提供一个干净、可预测的环境，让测试可以运行。

+   **测试套件**：一个测试套件是一组覆盖应用程序或模块所有代码的测试用例。

+   **模拟**：模拟是一个代表外部资源（比如文件或数据库）的对象。在测试期间，模拟会被覆盖到这些资源上。

为了深入探讨这些概念，让我们使用`unittest`来测试我们的`MyCalc`类。

# 编写测试用例

让我们在`test_mycalc.py`中为`MyCalc`类创建一个测试用例，如下所示：

```py
from mycalc import MyCalc
import unittest

class TestMyCalc(unittest.TestCase):
    def test_add(self):
        mc = MyCalc(1, 10)
        assert mc.add() == 11

if __name__ == '__main__':
    unittest.main()
```

你的测试模块和测试方法的名称都应该以`test_`为前缀。这样做可以让`unittest`运行程序自动找到测试模块，并区分测试方法和测试用例类中的其他方法。

你可能已经猜到，`TestCase`类代表一个测试用例。为了创建我们的`MyCalc`测试用例，我们继承`TestCase`并开始添加`test_`方法来测试我们类的各个方面。我们的`test_add()`方法创建一个`MyCalc`对象，然后对`add()`的输出进行断言。为了运行测试用例，我们在文件末尾添加一个对`unittest.main()`的调用。

如果你在命令行上运行你的测试文件，你应该会得到以下输出：

```py
.
----------------------------------------------------------------------
Ran 1 test in 0.000s

OK
```

第一行上的单个点代表我们的测试（`test_add()`）。对于每个测试方法，`unittest.main()`会输出一个点表示通过，`F`表示失败，或`E`表示错误。最后，我们会得到一个总结。

为了看看测试失败时会发生什么，让我们改变我们的测试使其不正确：

```py
    def test_add(self):
        mc = mycalc.MyCalc(1, 10)
        assert mc.add() == 12
```

现在当你运行测试模块时，你应该会看到以下失败：

```py
F
======================================================================
FAIL: test_add (__main__.TestMyCalc)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "test_mycalc.py", line 8, in test_add
    assert mc.add() == 12
AssertionError
----------------------------------------------------------------------
Ran 1 test in 0.000s

FAILED (failures=1)
```

注意顶部的单个`F`，代表我们的测试失败了。所有测试运行完毕后，我们会得到任何失败测试的完整回溯，这样我们就可以轻松定位失败的代码并进行修正。不过，这个回溯输出并不是非常理想；我们可以看到`mc.add()`不等于`12`，但我们不知道它等于什么。我们可以在我们的`assert`调用中添加一个注释字符串，但`unittest`提供了一个更好的方法。

# TestCase 断言方法

`TestCase`对象有许多断言方法，可以提供一种更清晰、更健壮的方式来运行我们代码的各种测试输出。

例如，有`TestCase.assertEqual()`方法来测试相等性，我们可以这样使用：

```py
    def test_add(self):
        mc = mycalc.MyCalc(1, 10)
        self.assertEqual(mc.add(), 12)
```

当我们用这段代码运行我们的测试时，你会看到回溯得到了改进：

```py
Traceback (most recent call last):
  File "test_mycalc.py", line 11, in test_add
    self.assertEqual(mc.add(), 12)
AssertionError: 11 != 12
```

现在，我们可以看到`mc.add()`创建的值，这对于调试来说更有帮助。`TestCase`包含了 20 多个断言方法，可以简化对各种条件的测试，比如类继承、引发异常和序列成员资格。

一些常用的方法列在下表中：

| **方法** | **测试** |
| --- | --- |
| `assertEqual(a, b)` | `a == b` |
| `assertTrue(a)` | `a`是`True` |
| `assertFalse(a)` | `a`是`False` |
| `assertIn(item, sequence)` | `item`在`sequence`中 |
| `assertRaises(exception, callable, args)` | `callable`用`args`调用引发`exception` |
| `assertGreater(a, b)` | `a`大于`b` |
| `assertLess(a, b)` | `a`小于`b` |

你也可以轻松地向你的测试用例中添加自定义的断言方法；只需要创建一个在某些条件下引发`AssertionError`异常的方法。

让我们使用一个断言方法来测试`mod_divide()`在`b`为`0`时是否引发`ValueError`：

```py
    def test_mod_divide(self):
        mycalc = mycalc.MyCalc(1, 0)
        self.assertRaises(ValueError, mycalc.mod_divide)
```

`assertRaises`在调用时，如果函数引发给定的断言，则通过。如果我们需要将任何参数传递到被测试的函数中，它们可以作为额外的参数指定给`assertRaises()`。

`assertRaises()`也可以像这样用作上下文管理器：

```py
        mycalc = MyCalc(1, 0)
        with self.assertRaises(ValueError):
            mycalc.mod_divide()
```

这段代码实现了完全相同的功能，但更清晰、更灵活。

# 固定装置

我们的`TestCase`对象可以具有一个`setUp()`方法，自动创建我们的测试需要的任何资源，而不必在每个测试中执行创建`MyCalc`对象的繁琐任务。

例如，看一下以下代码：

```py
    def setUp(self):
        self.mycalc1_0 = mycalc.MyCalc(1, 0)
        self.mycalc36_12 = mycalc.MyCalc(36, 12)
```

现在，每个测试用例都可以使用这些对象来运行其测试。`setUp()`方法将在每个测试之前重新运行，因此这些对象将始终在测试方法之间重置。如果我们有需要在每个测试后清理的项目，我们可以定义一个`tearDown()`方法，在每个测试后运行（在这种情况下，这是不必要的）。

例如，我们的`test_add()`方法可以更简单：

```py
    def test_add(self):
        self.assertEqual(self.mycalc1_0.add(), 1)
        self.assertEqual(self.mycalc36_12.add(), 48)
```

除了实例方法`setUp()`和`tearDown()`之外，`TestCase`还有用于设置和拆卸的类方法，即`setUpClass()`和`tearDownClass()`。这些可以用于较慢的操作，可以在测试用例创建和销毁时运行，而不需要在每个测试方法之间刷新。

# 使用 Mock 和 patch

`rand_between()`方法生成`a`和`b`之间的随机数。因为我们不可能预测它的输出，所以我们无法提供一个固定值来测试它。我们如何测试这个方法？

一个天真的方法如下：

```py
    def test_rand_between(self):
        rv = self.mycalc1_0.rand_between()
        self.assertLessEqual(rv, 1)
        self.assertGreaterEqual(rv, 0)
```

如果我们的代码正确，这个测试通过，但如果代码错误，它不一定会失败；事实上，如果代码错误，它可能会以不可预测的方式通过或失败。例如，如果`MyCalc(1, 10).rand_between()`错误地返回 2 到 11 之间的值，那么每次运行测试的机会只有 10%。

我们可以安全地假设标准库函数`random()`工作正常，因此我们的单元测试应该真正测试我们的方法是否正确处理`random()`提供给它的数字。如果我们可以暂时用返回固定值的函数替换`random()`，那么测试后续计算的正确性就会变得简单。

`unittest.mock`模块为我们提供了`Mock`类，用于此目的。`Mock`对象可用于可预测地模拟另一个类、方法或库的行为。我们可以给我们的`Mock`对象返回值、副作用、属性、方法和其他需要模拟另一个对象行为的特性，然后在运行测试之前将其放在该对象的位置。

让我们使用`Mock`创建一个虚假的`random()`函数，如下所示：

```py
from unittest.mock import Mock

#... inside TestMyCalc
    def test_rand_between(self):
        fakerandom = Mock(return_value=.5)
```

`Mock`对象的`return_value`参数允许我们在被调用为函数时硬编码一个值。在这里，`fakerandom`将始终返回`0.5`。

现在我们可以将`fakerandom`放在`random()`的位置：

```py
        orig_random = mycalc.random.random
        mycalc.random.random = fakerandom
        rv = self.mycalc1_0.rand_between()
        self.assertEqual(rv, 0.5)
        mycalc.random.random = orig_random
```

在替换之前，我们首先保存对`mycalc.random.random`的引用。请注意，我们只替换`mycalc.py`中使用的`random`版本，以便不影响其他任何地方的`random`。在修补库时尽可能具体是最佳实践，以避免意外的副作用。

有了`fakerandom`，我们调用我们的方法并测试输出。因为`fakerandom`将始终返回`0.5`，所以我们知道当`a`为`1`，`b`为`0`时，答案应该是（0.5 × 1 + 0）或`0.5`。任何其他值都会表明我们的算法存在错误。最后，我们将`random`恢复为原始函数，以便其他测试不会意外使用模拟。

每次都必须存储或恢复原始库是一个麻烦，所以`unittest.mock`提供了一个更清晰的方法，使用`patch`。`patch`命令可以作为上下文管理器或装饰器使用，无论哪种方法都可以将`Mock`对象补丁到我们的代码中，使其更加清晰。

使用我们的模拟`random()`，使用`patch`作为上下文管理器看起来像这样：

```py
from unittest.mock import patch

    #... inside TestMyCalc
    def test_rand_between(self):
       with patch('mycalc.random.random') as fakerandom:
            fakerandom.return_value = 0.5
            rv = self.mycalc1_0.rand_between()
            self.assertEqual(rv, 0.5)
```

`patch()`命令接受一个导入路径字符串，并为我们提供一个已经补丁的`Mock`对象。我们可以在`Mock`对象上设置方法和属性，并在块中运行我们的实际测试，当块结束时，补丁的库将被恢复。

使用`patch()`作为装饰器是类似的：

```py
    @patch('mycalc.random.random')
    def test_rand_between2(self, fakerandom):
        fakerandom.return_value = 0.5
        rv = self.mycalc1_0.rand_between()
        self.assertEqual(rv, 0.5)
```

在这种情况下，由`patch`创建的模拟对象作为参数传递给我们的测试方法，并将在装饰函数的持续时间内保持补丁状态。

# 运行多个单元测试

虽然我们可以在最后包含一个调用`unittest.main()`来运行单元测试，但这种方法不太适用。随着应用程序的增长，我们将编写许多测试文件，我们希望以组或全部运行。

幸运的是，`unittest`可以通过一个命令发现并运行项目中的所有测试：

```py
python -m unittest
```

只要你遵循了推荐的命名方案，将测试模块以`test_`为前缀，运行这个命令在项目的根目录中应该可以运行所有的测试。

# 测试 Tkinter 代码

测试 Tkinter 代码会带来一些特殊的挑战。首先，Tkinter 处理许多回调和方法是**异步**的，这意味着我们不能指望某些代码的结果立即显现。此外，测试 GUI 行为通常依赖于诸如窗口管理或视觉提示之类的外部因素，而我们的测试无法检测到。

我们将学习一些工具和策略，帮助你为 Tkinter 代码编写测试。

# 管理异步代码

每当与 Tkinter UI 交互时，无论是点击按钮、在字段中输入，还是提升窗口，例如，响应都不会立即执行。相反，这些操作被放在一个待办事项列表中，称为**事件队列**，稍后处理，而您的代码执行则继续。虽然这些操作对用户来说似乎是瞬间发生的，但测试代码不能指望请求的操作在下一行代码执行之前完成。

为了解决这个问题，我们可以使用这些特殊的小部件方法来管理事件队列：

+   `wait_visibility()`: 这个方法会导致程序等待，直到小部件完全绘制在屏幕上，然后再执行下一行代码。

+   `update_idletasks()`: 这个方法强制 Tkinter 处理小部件上当前未完成的任何空闲任务。空闲任务是低优先级的任务，如绘图和渲染。

+   `update()`: 这个方法强制 Tkinter 处理小部件上未完成的所有事件，包括调用回调、重绘和几何管理。它包括`update_idletasks()`的所有功能以及更多。

# 模拟用户操作

在自动化 GUI 测试时，我们可能希望知道当用户点击某个小部件或键入某个按键时会发生什么。当这些操作在 GUI 中发生时，Tkinter 会为小部件生成一个`Event`对象并将其传递给事件队列。我们可以在代码中做同样的事情，使用小部件的`event_generate()`方法。

# 指定事件序列

要使用`event_generate()`创建一个事件，我们需要传入一个事件序列字符串，格式为`<EventModifier-EventType-EventDetail>`。

事件类型指定了我们发送的事件类型，比如按键、鼠标点击、窗口事件等。

Tkinter 大约有 30 种事件类型，但通常只需要处理以下几种：

| **事件类型** | **描述** |
| --- | --- |
| `ButtonPress` | 也是`Button`，表示鼠标按钮点击 |
| `ButtonRelease` | 表示释放鼠标按钮 |
| `KeyPress` | 也是`Key`，表示按下键盘按键 |
| `KeyRelease` | 表示释放键盘键 |
| `FocusIn` | 表示将焦点放在小部件上 |
| `FocusOut` | 表示退出小部件 |
| `Enter` | 表示鼠标光标进入小部件 |
| `Leave` | 表示鼠标光标移出小部件 |
| `Configure` | 当小部件的配置发生变化时调用，可以是`.config()`调用或用户操作（例如调整大小） |

**事件修饰符**是可以改变事件类型的可选词语；例如，`Control`，`Alt`和`Shift`可以用来指示其中一个修改键被按下；`Double`或`Triple`可以用来指示所描述按钮的双击或三击。如果需要，可以将多个修饰符串在一起。

**事件详情**，仅适用于键盘或鼠标事件，描述了按下哪个键或按钮。例如，`<Button-1>`指的是鼠标左键，而`<Button-3>`指的是右键。对于字母和数字键，可以使用字面上的字母或数字；然而，大多数符号是用单词（`minus`，`colon`，`semicolon`等）来描述，以避免语法冲突。

对于按钮按下和键盘按下，事件类型在技术上是可选的；然而，出于清晰起见，最好将其保留。例如，`<1>`是一个有效的事件，但它是指鼠标左键还是按下`1`键？您可能会惊讶地发现它是鼠标按钮。

以下表格显示了一些有效事件序列的示例：

| **序列** | **意义** |
| --- | --- |
| `<Double-Button-3>` | 双击鼠标右键 |
| `<Alt-KeyPress-exclam>` | 按住`Alt`并输入感叹号 |
| `<Control-Alt-Key-m>` | 按住`Control`和`Alt`并按下`m`键 |
| `<KeyRelease-minus>` | 释放按下的减号键 |

除了序列，我们还可以向`event_generate()`传递其他参数，这些参数描述事件的各个方面。其中许多是多余的，但在某些情况下，我们需要提供额外的信息，以使事件具有任何意义；例如，鼠标按钮事件需要包括指定单击坐标的`x`和`y`参数。

# 管理焦点和抓取

焦点指的是当前接收键盘输入的小部件或窗口。小部件还可以抓取焦点，防止鼠标移动或超出其范围的按键。

Tkinter 为我们提供了这些小部件方法来管理焦点和抓取，其中一些对于运行测试非常有用：

| **方法** | **描述** |
| --- | --- |
| `focus_set()` | 在其窗口下次获得焦点时，将焦点设置到小部件 |
| `focus_force()` | 立即将焦点设置到小部件和其所在的窗口 |
| `grab_set()` | 小部件抓取应用程序的所有事件 |
| `grab_set_global()` | 小部件抓取所有屏幕事件 |
| `grab_release()` | 小部件放弃抓取 |

在测试环境中，我们可以使用这些方法来确保我们生成的键盘和鼠标事件发送到正确的小部件或窗口。

# 获取小部件信息

Tkinter 小部件有一组`winfo_`方法，可以让我们访问有关小部件的信息。虽然这组方法还有很多不足之处，但它确实提供了一些方法，我们可以在测试中使用这些方法来提供有关给定小部件状态的反馈。

以下是一些我们会发现有用的`winfo_`方法：

| **方法** | **描述** |
| --- | --- |
| `winfo_height()`，`winfo_width()` | 获取小部件的高度和宽度 |
| `winfo_children()` | 获取子小部件列表 |
| `winfo_geometry()` | 获取小部件的大小和位置 |
| `winfo_ismapped()` | 确定小部件是否已映射，意味着它已被添加到布局中，例如使用`pack()`或`grid()` |
| `winfo_viewable()` | 确定小部件是否可见，意味着它和所有父级都已被映射 |
| `winfo_x()`，`winfo_y()` | 获取小部件左上角的`x`或`y`坐标 |

# 为我们的应用编写测试

让我们利用`unittest`的知识，为我们的应用程序编写一些测试。要开始，我们需要为我们的应用程序创建一个测试模块。在`abq_data_entry`包内创建一个名为`test`的目录，并在其中创建习惯的空`__init__.py`文件。我们将在这个目录内创建所有的测试模块。

# 测试我们的模型

我们的`CSVModel`代码相当自包含，除了需要读写文件。由于文件操作是测试中需要模拟的常见事物之一，`mock`模块提供了`mock_open`，这是一个准备好替换 Python 的`open`方法的`Mock`子类。当调用时，`mock_open`对象返回一个`mock`文件句柄对象，支持`read()`、`write()`和`readlines()`方法。

让我们开始创建我们的测试用例类，位于`test/test_models.py`中：

```py
from .. import models
from unittest import TestCase
from unittest import mock

class TestCSVModel(TestCase):
    def setUp(self):
        self.file1_open = mock.mock_open(
            read_data=(
                "Date,Time,Technician,Lab,Plot,Seed sample,Humidity,Light,"
                "Temperature,Equipment Fault,Plants,Blossoms,Fruit,"
                "Min Height,Max Height,Median Height,Notes\r\n"
                "2018-06-01,8:00,J Simms,A,2,AX478,
                 24.47,1.01,21.44,False,14,"
                "27,1,2.35,9.2,5.09,\r\n"
                "2018-06-01,8:00,J Simms,A,3,AX479,
                24.15,1,20.82,False,18,49,"
                "6,2.47,14.2,11.83,\r\n"))
        self.file2_open = mock.mock_open(read_data='')
        self.model1 = models.CSVModel('file1')
        self.model2 = models.CSVModel('file2')
```

`mock_open`和`read_data`参数允许我们指定一个字符串，当文件句柄被读取时将返回该字符串。我们创建了两个`mock_open`对象，一个包含 CSV 标题和两行数据，另一个什么都没有。

我们还创建了两个`CSVModel`对象，一个文件名为`file1`，另一个文件名为`file2`。值得一提的是，我们的模型和`mock_open`对象之间实际上没有任何连接。选择`mock_open`对象，而不是文件名，将决定返回什么数据。

# 在`get_all_records()`中测试文件读取

看看我们如何使用这些，让我们从`get_all_records()`方法的测试开始：

```py
    @mock.patch('abq_data_entry.models.os.path.exists')
    def test_get_all_records(self, mock_exists):
        mock_exists.return_value = True
```

由于我们的文件名实际上并不存在，我们使用`patch`的装饰器版本来将`os.path.exists`补丁为一个总是返回`True`的模拟函数。如果我们想测试文件不存在的情况，我们可以稍后更改`return_value`的值。

为了运行`get_all_records()`方法，我们将使用`patch()`的上下文管理器形式如下：

```py
        with mock.patch('abq_data_entry.models.open', self.file1_open):
            records = self.model1.get_all_records()
```

`models.py`文件中任何在上下文管理器块内启动的`open()`调用都将被我们的`mock_open`对象替换，并且返回的文件句柄将包含我们指定的`read_data`。然而，在我们继续之前，`mock_open`存在一个不幸的缺陷，我们需要解决。虽然它实现了大多数文件方法，但它没有实现`csv`库需要从文件处理程序中读取数据的迭代器方法。

对我们的`models.py`代码进行轻微修改将解决这个问题：

```py
    def get_all_records(self):
        ...
        with open(self.filename, 'r', encoding='utf-8') as fh:
            csvreader = csv.DictReader(list(fh.readlines()))
```

我们需要调用`readlines()`并将其转换为`list`，而不是简单地将`fh`传递给`DictReader`。这不会以任何方式影响程序，但它将允许`mock_open()`正常工作。

对于调整代码以适应测试没有任何问题；在许多情况下，代码甚至会因此变得更好！然而，如果您进行了不直观的更改，比如前面的更改，请确保在代码中添加注释以解释原因。否则，有人很可能会在将来的某个时候将其删除。

现在我们可以开始对返回的记录进行断言：

```py
        self.assertEqual(len(records), 2)
        self.assertIsInstance(records, list)
        self.assertIsInstance(records[0], dict)
```

在这里，我们正在检查`records`是否包含两行（因为我们的读取数据包含两个`csv`记录），它是一个`list`对象，并且它的第一个成员是一个`dict`对象（或`dict`的子类）。

接下来，让我们确保所有字段都通过了，并且我们的布尔转换起作用：

```py
        fields = (
           'Date', 'Time', 'Technician', 'Lab', 'Plot',
           'Seed sample', 'Humidity', 'Light', 
           'Temperature', 'Equipment Fault', 'Plants',
           'Blossoms', 'Fruit', 'Min Height', 'Max Height', 
           'Median Height', 'Notes')
        for field in fields:
            self.assertIn(field, records[0].keys())
        self.assertFalse(records[0]['Equipment Fault'])
```

通过迭代所有字段名称的元组，我们可以检查记录输出中是否存在所有字段。不要害怕在测试中使用循环来快速检查大量内容。

`Mock`对象不仅可以代替另一个类或函数；它还有自己的断言方法，可以告诉我们它是否被调用，调用了多少次，以及使用了什么参数。

例如，我们可以检查我们的`mock_open`对象，确保它被调用时带有预期的参数：

```py
        self.file1_open.assert_called_with('file1', 'r', encoding='utf-8')
```

`assert_called_with()`接受一组参数，并检查对`mock`对象的最后一次调用是否使用了这些参数。我们期望`file1_open`被调用时使用文件名`file1`，模式为`r`，编码为`utf-8`。通过确认模拟函数是否使用了正确的参数进行了调用，并假设真实函数的正确性（在本例中是内置的`open()`函数），我们可以避免测试实际结果。

# 测试`save_record()`中的文件保存

为了演示如何使用`mock_open`测试文件写入，让我们测试`save_record()`：

```py
    @patch('abq_data_entry.models.os.path.exists')
    def test_save_record(self, mock_exists):
```

为了测试从`dict`到`csv`字符串的转换，我们需要两种格式的样本记录：

```py
        record = {
            "Date": '2018-07-01', "Time": '12:00', 
            "Technician": 'Test Tech', "Lab": 'E', 
             "Plot": '7', "Seed sample": 'test',
            "Humidity": '10', "Light": '99', 
            "Temperature": '20', "Equipment Fault": False,
            "Plants": '10', "Blossoms": '200', "Fruit": '250', 
            "Min Height": '40', "Max Height": '50',
            "Median Height": '55', "Notes": 'Test Note\r\nTest Note\r\n'}
        record_as_csv = (
            '2018-07-01,12:00,Test Tech,E,17,test,10,99,20,False,'
            '10,200,250,40,50,55,"Test Note\r\nTest Note\r\n"\r\n')
```

你可能会被诱惑使用代码生成记录或其预期输出，但在测试中最好坚持使用文字；这样做可以使测试的期望明确，并避免测试中的逻辑错误。

对于我们的第一个场景，让我们通过使用`file2_open`和`model2`来模拟向一个空但已存在的文件写入：

```py
        mock_exists.return_value = True
        with patch('abq_data_entry.models.open', self.file2_open):
            self.model2.save_record(record, None)
```

将我们的`mock_exists.return_value`设置为`True`，告诉我们的方法文件已经存在，然后用第二个`mock_open`对象覆盖`open()`，并调用`save_record()`方法。由于我们传入的记录没有行号（表示记录插入），这应该导致我们的代码尝试以追加模式打开`file2`并在 CSV 格式的记录中写入。

`assert_called_with()`将测试这一假设，如下所示：

```py
            self.file2_open.assert_called_with('file2', 'a', 
                encoding='utf-8')
```

`file2_open`可以告诉我们它是否使用了预期的参数进行了调用，但我们如何访问它的文件处理程序，以便我们可以看到写入了什么？

事实证明，我们可以直接调用我们的`mock_open`对象并检索`mock`文件处理程序对象：

```py
            file2_handle = self.file2_open()
            file2_handle.write.assert_called_with(record_as_csv)
```

一旦我们有了`mock`文件处理程序（它本身是一个`Mock`），我们可以对其运行测试方法，以找出它是否按预期被调用。在这种情况下，文件处理程序的`write`方法应该被调用，并传入 CSV 格式的记录字符串。

让我们进行一组类似的测试，传入一个行号来模拟记录更新：

```py
        with patch('abq_data_entry.models.open', self.file1_open):
            self.model1.save_record(record, 1)
            self.file1_open.assert_called_with('file1', 'w', 
            encoding='utf-8')
```

检查我们的更新是否正确完成存在一个问题：`assert_called_with()`只检查对模拟函数的最后一次调用。当我们更新 CSV 文件时，整个 CSV 文件都会被更新，每行一个`write()`调用。我们不能只检查最后一次调用是否正确；我们需要确保所有行的`write()`调用都是正确的。为了实现这一点，`Mock`为我们提供了`assert_has_calls()`，我们可以向其传递一个`Call`对象的列表，以与对象的调用历史进行比较。

我们使用`mock.call()`函数创建`Call`对象，如下所示：

```py
            file1_handle = self.file1_open()
            file1_handle.write.assert_has_calls([
                mock.call('Date,Time,Technician,Lab,Plot,Seed sample,'
                     'Humidity,Light,Temperature,Equipment Fault,'
                     'Plants,Blossoms,Fruit,Min Height,Max Height,'
                     'Median Height,Notes\r\n'),
                mock.call('2018-06-01,8:00,J Simms,A,2,AX478,24.47,1.01,'
                    '21.44,False, '14,27,1,2.35,9.2,5.09,\r\n'),
                mock.call('2018-07-01,12:00,Test Tech,E,17,test,10,99,20,'
                    'False,10,200,250,'40,50,55,' 
                    '"Test Note\r\nTest Note\r\n"\r\n')
            ])
```

`call()`的参数表示传递给函数调用的参数。我们向`assert_has_calls()`传递的`Call`对象列表表示应该按顺序进行的每次对`write()`的调用。关键字参数`in_order`也可以设置为`False`，在这种情况下，顺序不需要匹配。在这种情况下，顺序很重要，因为错误的顺序会导致损坏的 CSV 文件。

# 更多测试

测试`CSVModel`类和`SettingsModel`类方法的其余部分应该基本上与这两个方法相同。示例代码中包含了一些额外的测试，但看看你是否也能想出一些自己的测试。

# 测试我们的应用程序

我们已经将我们的应用程序实现为一个`Tk`对象，它不仅充当主窗口，还充当控制器，将在应用程序的其他地方定义的模型和视图进行拼接。正如你可能期望的那样，`patch()`将在我们的测试代码中大量出现，因为我们模拟了所有其他组件，以隔离`Application`。让我们看看这是如何完成的：

1.  在一个名为`test_application.py`的新文件中，导入`unittest`和`application`。现在开始一个测试用例，如下所示：

```py
class TestApplication(TestCase):
    records = [
        {'Blossoms': '21', 'Date': '2018-06-01',
         'Equipment Fault': 'False', 'Fruit': '3, 
         'Humidity': '24.09', 'Lab': 'A', 'Light': '1.03', 
         'Max Height': '8.7', 'Median Height': '2.73', 
         'Min Height': '1.67','Notes': '\n\n', 'Plants': '9', 
         'Plot': '1', 'Seed sample': 'AX477',
         'Technician': 'J Simms', 'Temperature': '22.01', 
         'Time': '8:00'},
        {'Blossoms': '27', 'Date': '2018-06-01', 
         'Equipment Fault': 'False', 'Fruit': '1', 
         'Humidity': '24.47', 'Lab': 'A', 'Light': '1.01',
         'Max Height': '9.2', 'Median Height': '5.09', 
         'Min Height': '2.35', 'Notes': '', 'Plants': '14', 
         'Plot': '2', 'Seed sample': 'AX478', 
         'Technician': 'J Simms', 'Temperature': '21.44', 
         'Time': '8:00'}]
    settings = {
        'autofill date': {'type': 'bool', 'value': True},
        'autofill sheet data': {'type': 'bool', 'value': True},
        'font size': {'type': 'int', 'value': 9},
        'theme': {'type': 'str', 'value': 'default'}}
```

我们的`TestApplication`类将使用模拟数据和设置模型的替代品，因此我们创建了一些类属性来存储`Application`期望从这些模型中检索的数据样本。`setUp()`方法将使用模拟数据替换所有外部类，配置模拟模型以返回我们的样本数据，然后创建一个`Application`实例，供我们的测试使用。

1.  让我们首先使用`patch()`作为上下文管理器来替换所有外部资源，如下所示：

```py
  def setUp(self):
      with \
          patch('abq_data_entry.application.m.CSVModel')\
              as csvmodel,\
          patch('abq_data_entry.application.m.SettingsModel') \
              as settingsmodel,\
          patch('abq_data_entry.application.v.DataRecordForm'), \            
          patch('abq_data_entry.application.v.RecordList'),\    
          patch('abq_data_entry.application.get_main_menu_for_os')\
        :
```

在这里，我们创建了一个`with`块，使用了五个`patch()`上下文管理器，每个库都有一个。请注意，我们只为模型模拟创建别名，因为我们希望对它们进行一些额外的配置。视图模拟不需要做太多事情，只需要被导入或调用，而且我们可以将它们作为`Application`对象的属性访问。

自 Python 3.2 以来，您可以通过使用逗号分隔每个上下文管理器调用来创建具有多个上下文管理器的块。不幸的是，您不能将它们放在括号中，因此我们使用了相对丑陋的转义换行方法，将这个巨大的调用分成多行。

1.  在块内，我们需要配置我们的模型模拟以返回适当的数据，如下所示：

```py
            settingsmodel().variables = self.settings
            csvmodel().get_all_records.return_value = self.records
```

请注意，我们正在实例化我们的`settingsmodel`和`csvmodel`对象，并配置返回值上的方法，而不是在模拟对象本身上配置。请记住，我们的模拟对象替换的是*类*，而不是*对象*，而是包含`Application`对象将要调用的方法的对象。因此，我们需要调用它们来访问`Application`将用作数据或设置模型的实际`Mock`对象。

与其代表的实际类不同，作为函数调用的`Mock`对象每次被调用时都会返回相同的对象。因此，我们不必保存通过调用模拟类创建的对象的引用；我们只需重复调用模拟类以访问该对象。但是，请注意，`Mock`类每次都会返回一个唯一的`Mock`对象。

1.  这样我们的模拟就处理好了，让我们创建一个`Application`对象：

```py
            self.app = application.Application()
```

1.  因为`Application`是`Tk`的子类，所以我们最好在每次使用后安全地处理它；即使我们重新分配了它的变量名，它仍将继续存在并在我们的测试中造成问题。为了解决这个问题，创建一个`tearDown()`方法：

```py
    def tearDown(self):
        self.app.update()
        self.app.destroy()
```

请注意对`app.update()`的调用。如果我们在销毁`app`之前不调用它，可能会有任务在事件队列中尝试在它消失后访问它。这不会破坏我们的代码，但会在我们的测试输出中产生错误消息。

1.  现在我们的固定装置已经处理好了，让我们写一个测试：

```py
    def test_show_recordlist(self):
        self.app.show_recordlist()
        self.app.update()
        self.app.recordlist.tkraise.assert_called()
```

`Application.show_recordlist()`包含一行代码，只是调用`recordlist.tkraise()`。因为我们将`recordlist`设置为模拟对象，`tkraise`也是模拟对象，我们可以检查它是否被调用。`assert_called()`只是检查方法是否被调用，而不检查参数，在这种情况下是合适的，因为`tkraise()`不需要参数。

1.  我们可以使用类似的技术来检查`populate_recordlist()`，如下所示：

```py
    def test_populate_recordlist(self):
        self.app.populate_recordlist()
        self.app.data_model.get_all_records.assert_called()
        self.app.recordlist.populate.assert_called_with(self.records)
```

1.  在某些情况下，`get_all_records()`可能会引发异常，在这种情况下，我们应该显示一个错误消息框。但是，由于我们模拟了我们的数据模型，我们如何让它引发异常呢？解决方案是使用模拟的`side_effect`属性，如下所示：

```py
        self.app.data_model.get_all_records.side_effect = 
        Exception('Test message')
```

`side_effect`可用于模拟可调用的更复杂功能。它可以设置为一个函数，这样当调用时，模拟将运行该函数并返回结果；它可以设置为一个可迭代对象，这样当调用时，模拟将返回可迭代对象中的下一个项目；或者，就像在这种情况下一样，它可以设置为一个异常，当调用模拟时将引发该异常。

1.  在使用之前，我们需要按照以下方式修补`messagebox`：

```py
        with patch('abq_data_entry.application.messagebox'):
            self.app.populate_recordlist()
            application.messagebox.showerror.assert_called_with(
                title='Error', message='Problem reading file',
                detail='Test message')
```

1.  这次当我们调用`populate_recordlist()`时，它会抛出一个异常，促使该方法调用`messagebox.showerror()`。由于我们已经模拟了`showerror()`，我们可以断言它是否以预期的参数被调用。

显然，测试我们的`Application`对象最困难的部分是补丁所有模拟的组件，并确保它们的行为足够像真实的东西，以满足`Application`。一旦我们做到了这一点，编写实际的测试就相当简单了。

# 测试我们的小部件

到目前为止，我们在`patch`、`Mock`和默认的`TestCase`方面做得很好，但是测试我们的小部件模块将带来一些新的挑战。首先，我们的小部件将需要一个`Tk`实例作为它们的根窗口。我们可以在每个案例的`setUp()`方法中创建这个实例，但这将大大减慢测试的速度，并且并不是真正必要的；我们的测试不会修改根窗口，因此一个根窗口对于每个测试案例就足够了。我们可以利用`setUpClass()`方法，在类实例化时只创建一个 Tk 的单个实例。其次，我们有大量的小部件需要测试，这意味着我们有大量的测试案例需要相同的样板`Tk()`设置和拆卸。

为了解决这个问题，让我们从一个自定义的`TestCase`类开始我们的`test_widgets.py`模块，如下所示：

```py
class TkTestCase(TestCase):
    """A test case designed for Tkinter widgets and views"""
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.wait_visibility()

    @classmethod
    def tearDownClass(cls):
        cls.root.update()
        cls.root.destroy()
```

`setUpClass()`方法创建`Tk()`对象并调用`wait_visibility()`，只是为了确保我们的窗口在我们的测试开始使用它之前是可见的。就像我们在`Application`测试中所做的那样，我们还提供了一个补充的拆卸方法，更新`Tk`实例并销毁它。

# 单元测试 ValidatedSpinbox 小部件

`ValidatedSpinbox`是我们为应用程序创建的较复杂的小部件之一，因此它是编写测试的好地方。

子类化`TkTestCase`类以创建`ValidatedSpinbox`的测试案例，如下所示：

```py
class TestValidatedSpinbox(TkTestCase):

    def setUp(self):
        self.value = tk.DoubleVar()
        self.vsb = widgets.ValidatedSpinbox(
            self.root,
            textvariable=self.value,
            from_=-10, to=10, increment=1)
        self.vsb.pack()
        self.vsb.wait_visibility()

    def tearDown(self):
        self.vsb.destroy()
```

我们的设置方法创建一个变量来存储小部件的值，然后使用一些基本设置创建`ValidatedSpinbox`小部件的实例：最小值为-10，最大值为 10，增量为 1。创建后，我们将其打包并等待它变得可见。对于我们的拆卸方法，我们只是销毁小部件。

在测试我们的小部件时，我们可以采取几种方法。第一种方法是面向单元测试的方法，我们专注于实际的方法代码，简单地模拟任何外部功能。

让我们尝试使用`_key_validate()`方法如下：

```py
    def test__key_validate(self):
        # test valid input
        for x in range(10):
            x = str(x)
            p_valid = self.vsb._key_validate(x, 'end', '', '', x, '1')
            n_valid = self.vsb._key_validate(
                x, 'end', '-', '-' + x, '1')
            self.assertTrue(p_valid)
            self.assertTrue(n_valid)
```

我们只是从 0 到 9 进行迭代，并测试数字的正负值对`_key_validate()`的输出，这些值都应该返回`True`。`_key_validate()`方法需要很多位置参数，大部分是多余的；可能会很好地有一个包装方法，使其更容易调用，因为我们的测试案例可能会多次调用它。

让我们将该方法称为`key_validate()`并将其添加到我们的`TestValidatedSpinbox`类中，如下所示：

```py
    def key_validate(self, new, current=''):
        # args are inserted char, insertion index, current value,
        # proposed value, and action code (where '1' is 'insert')
        return self.vsb._key_validate(new, 'end', current,
        current + new, '1')
```

这将使将来对该方法的调用更短，更不容易出错。

现在让我们使用它来测试一些无效的输入，如下所示：

```py
        # test letters
        valid = self.key_validate('a')
        self.assertFalse(valid)

        # test non-increment number
        valid = self.key_validate('1', '0.')
        self.assertFalse(valid)

        # test too high number
        valid = self.key_validate('0', '10')
        self.assertFalse(valid)
```

在第一个示例中，我们输入`a`；在第二个示例中，当框中已经有`0.`时，我们输入`1`，结果为`0.1`；在第三个示例中，当框中已经有`10`时，我们输入`0`，结果为`100`。所有这些情况都应该使验证方法失败。

# 集成测试 ValidatedSpinbox 小部件

在前面的测试中，我们实际上并没有向小部件输入任何数据；我们只是直接调用键验证方法并评估其输出。这是很好的单元测试，但作为对这段代码的测试来说并不够令人满意。由于我们的自定义小部件非常依赖于 Tkinter 的验证 API，我们希望测试我们是否正确地实现了这个 API。毕竟，代码的这一方面比我们的验证方法中的实际逻辑更具挑战性。

我们可以通过创建一些集成测试来实现这一点，这些测试模拟了实际用户操作，然后检查这些操作的结果。为了做到这一点，我们首先需要创建一些支持方法。

首先在`TkTestCase`类中添加一个新方法，如下所示：

```py
    def type_in_widget(self, widget, string):
        widget.focus_force()
        for char in string:
            char = self.keysyms.get(char, char)
```

这个类将接受一个小部件和一个字符串，并尝试模拟用户将字符串输入到小部件中。我们首先做的是强制焦点到小部件；我们需要使用`focus_force()`，因为我们的测试 Tk 窗口在运行测试时不太可能处于焦点状态。

一旦我们获得焦点，我们将遍历字符串中的字符，并将原始字符转换为事件序列的适当键符号。请记住，一些字符，特别是符号，必须表示为字符串，比如`minus`或`colon`。

为了使这个方法起作用，我们需要一个名为`dict`的类属性，用于在字符和它们的键符号之间进行转换，如下所示：

```py
    keysyms = {'-': 'minus', ' ': 'space', ':': 'colon', ...}
```

更多的键符号可以在[`www.tcl.tk/man/tcl8.4/TkCmd/keysyms.htm`](http://www.tcl.tk/man/tcl8.4/TkCmd/keysyms.htm)找到，但现在这些就够了。

一旦我们的字符被转换为适当的键符号，我们就可以创建我们的事件序列并生成我们的按键事件。在`type_in_widget()`方法中，我们可以创建并调用一个按键事件序列，如下所示：

```py
            self.root.update()
            widget.event_generate('<KeyPress-{}>'.format(char))
            self.root.update()
```

请注意，在生成按键事件之前和之后都调用了`self.root.update()`。这确保小部件已准备好输入，并且生成的输入在生成后注册。顺便说一句，`update_idletasks()`在这里行不通；试一试，你会发现测试会失败。

我们可以创建一个类似的方法来模拟鼠标点击按钮，如下所示：

```py
    def click_on_widget(self, widget, x, y, button=1):
        widget.focus_force()
        self.root.update()
        widget.event_generate("<ButtonPress-{}>".format(button), 
        x=x, y=y)
        self.root.update()
```

就像我们使用按键方法一样，我们首先强制焦点，更新应用程序，生成我们的事件，然后再次更新。然而，在这个方法中，我们还需要指定鼠标点击的`x`和`y`坐标。这些坐标是相对于小部件左上角的坐标。我们也可以指定按钮编号，但我们将默认为左按钮（`1`）。

有了这些方法，回到`TestValidatedSpinbox`并编写一个新的测试：

```py
    def test__key_validate_integration(self):
        self.vsb.delete(0, 'end')
        self.type_in_widget(self.vsb, '10')
        self.assertEqual(self.vsb.get(), '10')
```

这个方法首先通过清除小部件，然后用`type_in_widget()`模拟一些有效的输入，并检查小部件是否接受了输入。请注意，在这些集成测试中，我们需要每次清除小部件，因为我们正在模拟实际小部件中的按键，并触发所有这些操作的副作用。

接下来，让我们通过执行以下代码来测试一些无效的输入：

```py
        self.vsb.delete(0, 'end')
        self.type_in_widget(self.vsb, 'abcdef')
        self.assertEqual(self.vsb.get(), '')

        self.vsb.delete(0, 'end')
        self.type_in_widget(self.vsb, '200')
        self.assertEqual(self.vsb.get(), '2')
```

我们可以使用鼠标点击方法来测试`Spinbox`箭头按钮的功能。为了简化这个过程，让我们在测试用例类中创建一个辅助方法来点击我们想要的箭头。将这个方法添加到`TestValidatedSpinbox`中：

```py
    def click_arrow(self, arrow='inc', times=1):
        x = self.vsb.winfo_width() - 5
        y = 5 if arrow == 'inc' else 15
        for _ in range(times):
            self.click_on_widget(self.vsb, x=x, y=y)
```

我们可以通过点击距离小部件右侧`5`像素，顶部`5`像素来定位增量箭头。减量箭头可以在距右侧`5`像素，顶部`15`像素的位置找到。当然，这可能需要根据主题或屏幕设置进行一些调整。现在，我们可以轻松地测试我们的箭头键功能，如下所示：

```py
    def test_arrows(self):
        self.value.set(0)
        self.click_arrow(times=1)
        self.assertEqual(self.vsb.get(), '1')

        self.click_arrow(times=5)
        self.assertEqual(self.vsb.get(), '6')

        self.click_arrow(arrow='dec', times=1)
        self.assertEqual(self.vsb.get(), '5')
```

通过设置小部件的值，然后点击适当的箭头指定次数，我们可以测试箭头是否根据我们的小部件类的规则完成了它们的工作。

# 测试我们的混合类

我们还没有解决的一个额外挑战是测试我们的混合类。与我们的其他小部件类不同，我们的混合类实际上不能独立存在：它依赖于与之组合的`ttk`小部件中找到的方法和属性。

测试这个类的一种方法是将它与一个`Mock`对象混合，该对象模拟了任何继承方法。这种方法是有优点的，但一个更简单（虽然不太理想）的方法是用最简单的`ttk`小部件的子类来继承它，并测试生成的子类。

这种方法看起来是这样的：

```py
class TestValidatedMixin(TkTestCase):

    def setUp(self):
        class TestClass(widgets.ValidatedMixin, ttk.Entry):
            pass
        self.vw1 = TestClass(self.root)
```

在这里，我们只是使用`ttk.Entry`创建了一个基本的子类，并没有进行其他修改。然后，我们创建了该类的一个实例。

让我们按照以下方式测试我们的`_validate()`方法：

```py
    def test__validate(self):
        args = {'proposed': 'abc', 'current': 'ab', 'char': 'c', 
        'event': 'key', 'index': '2', 'action': '1'}
        self.assertTrue(self.vw1._validate(**args))
```

因为我们向`_validate()`发送了一个键事件，它将请求路由到`_key_validate()`，后者默认情况下只返回`True`。我们需要验证当`_key_validate()`返回`False`时，`_validate()`是否执行了所需的操作。

我们将使用`Mock`来实现这一点：

```py
        fake_key_val = Mock(return_value=False)
        self.vw1._key_validate = fake_key_val
        self.assertFalse(self.vw1._validate(**args))
        fake_key_val.assert_called_with(**args)
```

我们测试`False`被返回，并且`_key_validate`被调用时使用了正确的参数。

通过更新`args`中的`event`值，我们可以检查`focusout`事件是否也起作用：

```py
        args['event'] = 'focusout'
        self.assertTrue(self.vw1._validate(**args))
        fake_focusout_val = Mock(return_value=False)
        self.vw1._focusout_validate = fake_focusout_val
        self.assertFalse(self.vw1._validate(**args))
        fake_focusout_val.assert_called_with(event='focusout')
```

我们采取了相同的方法，只是模拟了`_focusout_validate()`以使其返回`False`。

正如您所看到的，一旦我们创建了我们的测试类，测试`ValidatedMixin`就像测试任何其他小部件类一样。在包含的源代码中还有其他测试方法的示例；这些应该足以让您开始创建一个完整的测试套件。

# 总结

在本章中，我们学习了自动化测试以及 Python 的`unittest`库提供的功能。我们针对应用程序的部分编写了单元测试和集成测试，您学会了解决各种测试挑战的方法。

在下一章中，我们将升级我们的后端以使用关系数据库。您还将学习关系数据库、SQL 和数据库规范化。您将学习如何与 PostgreSQL 数据库服务器和 Python 的`psycopg2` PostgreSQL 接口库一起工作。
