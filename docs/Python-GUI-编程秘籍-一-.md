# Python GUI 编程秘籍（一）

> 原文：[`zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245`](https://zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在这本书中，我们将探索使用 Python 编程语言的图形用户界面（GUI）的美丽世界。

在这个过程中，我们将讨论网络、队列、OpenGL 图形库以及许多其他技术。

这是一本编程食谱。每一章都是独立的，解释了某个特定的编程解决方案。

我们将从非常简单的开始，然而在整本书中，我们将构建一个用 Python 3 编写的工作程序。

我们还将在整本书中应用一些设计模式和最佳实践。

本书假设读者具有一些使用 Python 编程语言的基本经验，但这并不是真正需要使用本书的前提条件。

如果您是任何编程语言的经验丰富的程序员，您将有一个愉快的时光，将您的技能扩展到使用 Python 编程 GUI！

你准备好了吗？

让我们开始我们的旅程吧...

# 本书涵盖的内容

第一章，“创建 GUI 表单并添加小部件”，解释了在 Python 中开发我们的第一个 GUI 的步骤。我们将从构建运行的 GUI 应用程序所需的最少代码开始。然后，每个示例都向 GUI 表单添加不同的小部件。

第二章，“布局管理”，探讨了如何安排小部件来创建我们的 Python GUI。网格布局管理器是内置在 tkinter 中的最重要的布局工具之一，我们将使用它。

第三章，“外观和感觉定制”，展示了如何创建一个良好的“外观和感觉”GUI 的几个示例。在实际层面上，我们将为我们在其中一个示例中创建的**帮助** | **关于**菜单项添加功能。

第四章，“数据和类”，讨论了保存我们的 GUI 显示的数据。我们将开始使用面向对象编程（OOP）来扩展 Python 的内置功能。

第五章，“Matplotlib 图表”，解释了如何创建美丽的图表来直观地表示数据。根据数据源的格式，我们可以在同一图表中绘制一个或多个数据列。

第六章，“线程和网络”，解释了如何使用线程、队列和网络连接扩展 Python GUI 的功能。这将向我们展示，我们的 GUI 并不局限于 PC 的本地范围。

第七章，“通过我们的 GUI 在 MySQL 数据库中存储数据”，向我们展示了如何连接到 MySQL 数据库服务器。本章的第一个示例将展示如何安装免费的 MySQL Server Community Edition，接下来的示例中，我们将创建数据库、表，然后将数据加载到这些表中，以及修改这些数据。我们还将从 MySQL 服务器中读取数据到我们的 GUI 中。

第八章，“国际化和测试”，展示了如何通过在不同语言中显示标签、按钮、选项卡和其他小部件上的文本来国际化我们的 GUI。我们将从简单开始，然后探讨如何在设计层面准备我们的 GUI 进行国际化。我们还将探讨使用 Python 内置的单元测试框架自动测试我们的 GUI 的几种方法。

第九章，“使用 wxPython 库扩展我们的 GUI”，介绍了另一个 Python GUI 工具包，它目前不随 Python 一起发布。它被称为 wxPython，我们将使用为 Python 3 设计的 Phoenix 版本的 wxPython。

第十章，*使用 PyOpenGL 和 PyGLet 创建令人惊叹的 3D GUI*，展示了如何通过赋予 GUI 真正的三维能力来改变我们的 GUI。我们将使用两个 Python 第三方包。PyOpenGL 是 OpenGL 标准的 Python 绑定，这是一个内置于所有主要操作系统中的图形库。这使得生成的小部件具有本地的外观和感觉。PyGLet 是我们将在本章中探索的一个这样的绑定。

第十一章，*最佳实践*，探讨了可以帮助我们以高效的方式构建 GUI 并使其易于维护和扩展的不同最佳实践。最佳实践适用于任何良好的代码，我们的 GUI 也不例外，设计和实施良好的软件实践。

# 你需要为这本书做些什么

本书所需的所有软件都可以在线获得，而且是免费的。这从 Python 3 本身开始，然后扩展到 Python 的附加模块。为了下载所需的任何软件，你需要一个可用的互联网连接。

# 这本书是为谁准备的

这本书是为希望创建图形用户界面（GUI）的程序员准备的。通过使用 Python 编程语言，我们可以创造出美丽、功能强大的 GUI，你可能会对我们能够实现什么感到惊讶。Python 是一种非常出色、直观的编程语言，而且非常容易学习。

我想邀请你现在就开始这段旅程。这将是非常有趣的！

# 约定

在这本书中，你会发现一些区分不同信息种类的文本样式。以下是一些这些样式的例子，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名和用户输入显示如下：“使用 Python，我们可以使用`class`关键字而不是`def`关键字创建我们自己的类。”

代码块设置如下：

```py
import tkinter as tk     # 1
win = tk.Tk()            # 2
win.title("Python GUI")  # 3
win.mainloop()           # 4
```

任何命令行输入或输出都以以下方式编写：

```py
**pip install numpy-1.9.2+mkl-cp34-none-win_amd64.whl**

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，菜单或对话框中的单词会以这样的方式出现在文本中：“接下来，我们将为菜单项添加功能，例如，单击**退出**菜单项时关闭主窗口，并显示**帮助**|**关于**对话框。”

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会出现在这样的地方。


# 第一章：创建 GUI 表单并添加小部件

在本章中，我们开始使用 Python 3 创建令人惊叹的 GUI：

+   创建我们的第一个 Python GUI

+   防止 GUI 大小调整

+   将标签添加到 GUI 表单

+   创建按钮并更改其文本属性

+   文本框小部件

+   将焦点设置为小部件并禁用小部件

+   组合框小部件

+   创建具有不同初始状态的复选按钮

+   使用单选按钮小部件

+   使用滚动文本小部件

+   在循环中添加多个小部件

# 介绍

在本章中，我们将在 Python 中开发我们的第一个 GUI。我们从构建运行的 GUI 应用程序所需的最少代码开始。然后，每个示例都向 GUI 表单添加不同的小部件。

在前两个示例中，我们展示了仅包含几行代码的完整代码。在接下来的示例中，我们只展示要添加到前面示例中的代码。

在本章结束时，我们将创建一个工作的 GUI 应用程序，其中包括各种状态的标签、按钮、文本框、组合框和复选按钮，以及可以更改 GUI 背景颜色的单选按钮。

# 创建我们的第一个 Python GUI

Python 是一种非常强大的编程语言。它附带了内置的 tkinter 模块。只需几行代码（确切地说是四行），我们就可以构建我们的第一个 Python GUI。

## 准备工作

要遵循此示例，需要一个可用的 Python 开发环境。Python 附带的 IDLE GUI 足以开始。IDLE 是使用 tkinter 构建的！

### 注意

本书中的所有示例都是在 Windows 7 64 位操作系统上使用 Python 3.4 开发的。它们尚未在任何其他配置上进行测试。由于 Python 是一种跨平台语言，预计每个示例的代码都可以在任何地方运行。

如果您使用的是 Mac，它确实内置了 Python，但可能缺少一些模块，例如我们将在本书中使用的 tkinter。

我们正在使用 Python 3，Python 的创建者有意选择不与 Python 2 向后兼容。

如果您使用的是 Mac 或 Python 2，您可能需要从[www.python.org](http://www.python.org)安装 Python 3，以便成功运行本书中的示例。

## 如何做...

以下是创建结果 GUI 所需的四行 Python 代码：

```py
import tkinter as tk     # 1
win = tk.Tk()            # 2
win.title("Python GUI")  # 3
win.mainloop()           # 4
```

执行此代码并欣赏结果：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_01.jpg)

## 工作原理...

在第 1 行中，我们导入内置的`tkinter`模块，并将其别名为`tk`以简化我们的 Python 代码。在第 2 行中，我们通过调用其构造函数（括号附加到`Tk`将类转换为实例）创建`Tk`类的实例。我们使用别名`tk`，这样我们就不必使用更长的单词`tkinter`。我们将类实例分配给名为`win`（窗口的缩写）的变量。由于 Python 是一种动态类型的语言，我们在分配给它之前不必声明此变量，并且我们不必给它指定特定的类型。*Python 从此语句的分配中推断出类型*。Python 是一种强类型的语言，因此每个变量始终都有一个类型。我们只是不必像其他语言那样事先指定其类型。这使得 Python 成为一种非常强大和高效的编程语言。

### 注意

关于类和类型的一点说明：

在 Python 中，每个变量始终都有一个类型。我们不能创建一个没有分配类型的变量。然而，在 Python 中，我们不必事先声明类型，就像在 C 编程语言中一样。

Python 足够聪明，可以推断类型。在撰写本文时，C#也具有这种能力。

使用 Python，我们可以使用`class`关键字而不是`def`关键字来创建自己的类。

为了将类分配给变量，我们首先必须创建我们类的一个实例。我们创建实例并将此实例分配给我们的变量。

```py
class AClass(object):
    print('Hello from AClass')

classInstance = AClass()
```

现在变量`classInstance`的类型是`AClass`。

如果这听起来令人困惑，不要担心。我们将在接下来的章节中介绍面向对象编程。

在第 3 行，我们使用类的实例变量(`win`)通过`title`属性给我们的窗口设置了一个标题。在第 4 行，通过在类实例`win`上调用`mainloop`方法来启动窗口的事件循环。在我们的代码中到目前为止，我们创建了一个实例并设置了一个属性*但是 GUI 直到我们启动主事件循环之前都不会显示*。

### 注意

事件循环是使我们的 GUI 工作的机制。我们可以把它看作是一个无限循环，我们的 GUI 在其中等待事件发送给它。按钮点击在我们的 GUI 中创建一个事件，或者我们的 GUI 被调整大小也会创建一个事件。

我们可以提前编写所有的 GUI 代码，直到我们调用这个无限循环(`win.mainloop()`在上面显示的代码中)用户的屏幕上什么都不会显示。

当用户点击红色的**X**按钮或者我们编程结束 GUI 的小部件时，事件循环就会结束。当事件循环结束时，我们的 GUI 也会结束。

## 还有更多...

这个示例使用了最少量的 Python 代码来创建我们的第一个 GUI 程序。然而，在本书中，我们会在合适的时候使用 OOP。

# 阻止 GUI 的大小可调整

## 准备工作

这个示例扩展了之前的示例。因此，有必要自己输入第 1 个示例的代码到你自己的项目中，或者从[`www.packtpub.com/support`](https://www.packtpub.com/support)下载代码。

## 如何做...

我们正在阻止 GUI 的大小可调整。

```py
import tkinter as tk        # 1 imports

win = tk.Tk()               # 2 Create instance
win.title("Python GUI")     # 3 Add a title       

win.resizable(0, 0)         # 4 Disable resizing the GUI

win.mainloop()              # 5 Start GUI
```

运行这段代码会创建这个 GUI：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_02.jpg)

## 它是如何工作的...

第 4 行阻止 Python GUI 的大小可调整。

运行这段代码将会得到一个类似于我们在第 1 个示例中创建的 GUI。然而，用户不能再调整它的大小。同时，注意窗口工具栏中的最大化按钮是灰色的。

为什么这很重要？因为一旦我们向我们的表单添加小部件，调整大小可能会使我们的 GUI 看起来不如我们希望的那样好。我们将在下一个示例中向我们的 GUI 添加小部件。

`Resizable()`是`Tk()`类的一个方法，通过传入`(0, 0)`，我们阻止了 GUI 的大小可调整。如果我们传入其他值，我们就会硬编码 GUI 的 x 和 y 的启动大小，*但这不会使它不可调整大小*。

我们还在我们的代码中添加了注释，为本书中包含的示例做准备。

### 注意

在 Visual Studio .NET 等可视化编程 IDE 中，C#程序员通常不会考虑阻止用户调整他们用这种语言开发的 GUI。这会导致 GUI 质量较差。添加这一行 Python 代码可以让我们的用户欣赏我们的 GUI。

# 向 GUI 表单添加标签

## 准备工作

我们正在扩展第一个示例。我们将保持 GUI 可调整大小，所以不要使用第二个示例中的代码(或者将第 4 行的`win.resizable`注释掉)。

## 如何做...

为了向我们的 GUI 添加一个`Label`小部件，我们从`tkinter`中导入了`ttk`模块。请注意这两个导入语句。

```py
# imports                  # 1
import tkinter as tk       # 2
from tkinter import ttk    # 3
```

在示例 1 和 2 底部的`win.mainloop()`上面添加以下代码。

```py
# Adding a Label           # 4
ttk.Label(win, text="A Label").grid(column=0, row=0) # 5
```

运行这段代码会向我们的 GUI 添加一个标签：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_03.jpg)

## 它是如何工作的...

在上面的代码的第 3 行，我们从`tkinter`中导入了一个单独的模块。`ttk`模块有一些高级的小部件，可以让我们的 GUI 看起来很棒。在某种意义上，`ttk`是`tkinter`中的一个扩展。

我们仍然需要导入`tkinter`本身，但是我们必须指定我们现在也想要从`tkinter`中使用`ttk`。

### 注意

`ttk`代表"themed tk"。它改善了我们的 GUI 外观和感觉。

上面的第 5 行在调用`mainloop`之前向 GUI 添加了标签(这里没有显示以保持空间。请参见示例 1 或 2)。

我们将我们的窗口实例传递给`ttk.Label`构造函数，并设置文本属性。这将成为我们的`Label`将显示的文本。

我们还使用了*网格布局管理器*，我们将在第二章中更深入地探讨*布局管理*。

请注意我们的 GUI 突然变得比以前的食谱小得多。

它变得如此之小的原因是我们在表单中添加了一个小部件。没有小部件，`tkinter`使用默认大小。添加小部件会导致优化，通常意味着尽可能少地使用空间来显示小部件。

如果我们使标签的文本更长，GUI 将自动扩展。我们将在第二章中的后续食谱中介绍这种自动表单大小调整，*布局管理*。

## 还有更多...

尝试调整和最大化带有标签的 GUI，看看会发生什么。

# 创建按钮并更改它们的文本属性

## 准备就绪

这个食谱扩展了上一个食谱。您可以从 Packt Publishing 网站下载整个代码。

## 如何做...

我们正在添加一个按钮，当点击时执行一个动作。在这个食谱中，我们将更新上一个食谱中添加的标签，以及更新按钮的文本属性。

```py
# Modify adding a Label                                      # 1
aLabel = ttk.Label(win, text="A Label")                      # 2
aLabel.grid(column=0, row=0)                                 # 3

# Button Click Event Callback Function                       # 4
def clickMe():                                               # 5
    action.configure(text="** I have been Clicked! **")
    aLabel.configure(foreground='red')

# Adding a Button                                            # 6
action = ttk.Button(win, text="Click Me!", command=clickMe)  # 7
action.grid(column=1, row=0)                                 # 8
```

点击按钮之前：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_04.jpg)

点击按钮后，标签的颜色已经改变，按钮的文本也改变了。动作！

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_05.jpg)

## 它是如何工作的...

在第 2 行，我们现在将标签分配给一个变量，在第 3 行，我们使用这个变量来定位表单中的标签。我们将需要这个变量来在`clickMe()`函数中更改它的属性。默认情况下，这是一个模块级变量，因此只要我们在调用它的函数上方声明变量，我们就可以在函数内部访问它。

第 5 行是一旦按钮被点击就被调用的事件处理程序。

在第 7 行，我们创建按钮并将命令绑定到`clickMe()`函数。

### 注意

GUI 是事件驱动的。点击按钮会创建一个事件。我们使用`ttk.Button`小部件的命令属性绑定事件发生时回调函数中的操作。请注意我们没有使用括号；只有名称`clickMe`。

我们还将标签的文本更改为包含`red`，就像印刷版中一样，否则可能不太明显。当您运行代码时，您会看到颜色确实改变了。

第 3 行和第 8 行都使用了网格布局管理器，这将在下一章中讨论。这样可以对齐标签和按钮。

## 还有更多...

我们将继续向我们的 GUI 中添加更多的小部件，并在本书的其他章节中利用许多内置属性。

# 文本框小部件

在`tkinter`中，典型的文本框小部件称为`Entry`。在这个食谱中，我们将向我们的 GUI 添加这样一个`Entry`。我们将通过描述`Entry`为用户做了什么来使我们的标签更有用。

## 准备就绪

这个食谱是基于*创建按钮并更改它们的文本属性*食谱的。

## 如何做...

```py
# Modified Button Click Function   # 1
def clickMe():                     # 2
    action.configure(text='Hello ' + name.get())

# Position Button in second row, second column (zero-based)
action.grid(column=1, row=1)

# Changing our Label               # 3
ttk.Label(win, text="Enter a name:").grid(column=0, row=0) # 4

# Adding a Textbox Entry widget    # 5
name = tk.StringVar()              # 6
nameEntered = ttk.Entry(win, width=12, textvariable=name) # 7
nameEntered.grid(column=0, row=1)  # 8
```

现在我们的 GUI 看起来是这样的：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_06.jpg)

输入一些文本并点击按钮后，GUI 发生了以下变化：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_07.jpg)

## 它是如何工作的...

在第 2 行，我们获取`Entry`小部件的值。我们还没有使用面向对象编程，那么我们怎么能访问甚至还没有声明的变量的值呢？

在 Python 过程式编码中，如果不使用面向对象编程类，我们必须在尝试使用该名称的语句上方物理放置一个名称。那么为什么这样会起作用呢（它确实起作用）？

答案是按钮单击事件是一个回调函数，当用户单击按钮时，此函数中引用的变量是已知且存在的。

生活很美好。

第 4 行给我们的标签一个更有意义的名称，因为现在它描述了它下面的文本框。我们将按钮移动到标签旁边，以视觉上将两者关联起来。我们仍然使用网格布局管理器，将在第二章中详细解释，*布局管理*。

第 6 行创建了一个变量`name`。这个变量绑定到`Entry`，在我们的“clickMe（）”函数中，我们可以通过在这个变量上调用“get（）”来检索`Entry`框的值。这非常有效。

现在我们看到，虽然按钮显示了我们输入的整个文本（以及更多），但文本框`Entry`小部件没有扩展。原因是我们在第 7 行中将其硬编码为宽度为 12。

### 注意

Python 是一种动态类型的语言，并且从赋值中推断类型。这意味着如果我们将一个字符串赋给变量“name”，那么该变量将是字符串类型，如果我们将一个整数赋给“name”，那么该变量的类型将是整数。

使用 tkinter，我们必须将变量`name`声明为类型“tk.StringVar（）”才能成功使用它。原因是 Tkinter 不是 Python。我们可以从 Python 中使用它，但它不是相同的语言。

# 将焦点设置为小部件并禁用小部件

尽管我们的图形用户界面正在不断改进，但在 GUI 出现时让光标立即出现在`Entry`小部件中会更方便和有用。在这里，我们学习如何做到这一点。

## 准备工作

这个示例扩展了以前的示例。

## 如何做...

Python 真的很棒。当 GUI 出现时，我们只需调用先前创建的`tkinter`小部件实例上的“focus（）”方法，就可以将焦点设置为特定控件。在我们当前的 GUI 示例中，我们将`ttk.Entry`类实例分配给了一个名为`nameEntered`的变量。现在我们可以给它焦点。

将以下代码放在启动主窗口事件循环的模块底部之上，就像以前的示例一样。如果出现错误，请确保将变量调用放在声明它们的代码下面。我们目前还没有使用面向对象编程，所以这仍然是必要的。以后，将不再需要这样做。

```py
nameEntered.focus()            # Place cursor into name Entry
```

在 Mac 上，您可能必须先将焦点设置为 GUI 窗口，然后才能将焦点设置为该窗口中的`Entry`小部件。

添加这一行 Python 代码将光标放入我们的文本`Entry`框中，使文本`Entry`框获得焦点。一旦 GUI 出现，我们就可以在不必先单击它的情况下在这个文本框中输入。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_08.jpg)

### 注意

请注意，光标现在默认驻留在文本`Entry`框内。

我们也可以禁用小部件。为此，我们在小部件上设置一个属性。通过添加这一行 Python 代码，我们可以使按钮变为禁用状态：

```py
action.configure(state='disabled')    # Disable the Button Widget
```

添加上述一行 Python 代码后，单击按钮不再产生任何动作！

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_09.jpg)

## 它是如何工作的...

这段代码是不言自明的。我们将焦点设置为一个控件并禁用另一个小部件。在编程语言中良好的命名有助于消除冗长的解释。在本书的后面，将有一些关于如何在工作中编程或在家练习编程技能时进行高级提示。

## 还有更多...

是的。这只是第一章。还有更多内容。

# 组合框小部件

在这个示例中，我们将通过添加下拉组合框来改进我们的 GUI，这些下拉组合框可以具有初始默认值。虽然我们可以限制用户只能选择某些选项，但与此同时，我们也可以允许用户输入他们希望的任何内容。

## 准备工作

这个示例扩展了以前的示例。

## 如何做...

我们正在使用网格布局管理器在`Entry`小部件和`Button`之间插入另一列。以下是 Python 代码。

```py
ttk.Label(win, text="Choose a number:").grid(column=1, row=0)  # 1
number = tk.StringVar()                         # 2
numberChosen = ttk.Combobox(win, width=12, textvariable=number) #3
numberChosen['values'] = (1, 2, 4, 42, 100)     # 4
numberChosen.grid(column=1, row=1)              # 5
numberChosen.current(0)                         # 6
```

将此代码添加到以前的示例中后，将创建以下 GUI。请注意，在前面的代码的第 4 行中，我们将默认值的元组分配给组合框。然后这些值出现在下拉框中。如果需要，我们也可以在应用程序运行时更改它们（通过输入不同的值）。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_10.jpg)

## 它是如何工作的...

第 1 行添加了第二个标签以匹配新创建的组合框（在第 3 行创建）。第 2 行将框的值分配给特殊`tkinter`类型的变量（`StringVar`），就像我们在之前的示例中所做的那样。

第 5 行将两个新控件（标签和组合框）与我们之前的 GUI 布局对齐，第 6 行在 GUI 首次可见时分配要显示的默认值。这是`numberChosen['values']`元组的第一个值，字符串`"1"`。我们在第 4 行没有在整数元组周围放置引号，但它们被转换为字符串，因为在第 2 行，我们声明值为`tk.StringVar`类型。

屏幕截图显示用户所做的选择（**42**）。这个值被分配给`number`变量。

## 还有更多...

如果我们希望限制用户只能选择我们编程到`Combobox`中的值，我们可以通过将*state 属性*传递给构造函数来实现。修改前面代码中的第 3 行：

```py
numberChosen = ttk.Combobox(win, width=12, textvariable=number, state='readonly')
```

现在用户不能再在`Combobox`中输入值。我们可以通过在我们的按钮单击事件回调函数中添加以下代码行来显示用户选择的值：

```py
# Modified Button Click Callback Function
def clickMe():
    action.configure(text='Hello ' + name.get()+ ' ' + numberChosen.get())
```

选择一个数字，输入一个名称，然后单击按钮，我们得到以下 GUI 结果，现在还显示了所选的数字：

![还有更多...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_11.jpg)

# 创建具有不同初始状态的复选按钮

在这个示例中，我们将添加三个`Checkbutton`小部件，每个小部件都有不同的初始状态。

## 准备就绪

这个示例扩展了之前的示例。

## 如何做...

我们创建了三个`Checkbutton`小部件，它们的状态不同。第一个是禁用的，并且其中有一个复选标记。用户无法移除此复选标记，因为小部件被禁用。

第二个`Checkbutton`是启用的，并且默认情况下没有复选标记，但用户可以单击它以添加复选标记。

第三个`Checkbutton`既启用又默认选中。用户可以随意取消选中和重新选中小部件。

```py
# Creating three checkbuttons    # 1
chVarDis = tk.IntVar()           # 2
check1 = tk.Checkbutton(win, text="Disabled", variable=chVarDis, state='disabled')                     # 3
check1.select()                  # 4
check1.grid(column=0, row=4, sticky=tk.W) # 5

chVarUn = tk.IntVar()            # 6
check2 = tk.Checkbutton(win, text="UnChecked", variable=chVarUn)
check2.deselect()                # 8
check2.grid(column=1, row=4, sticky=tk.W) # 9                  

chVarEn = tk.IntVar()            # 10
check3 = tk.Checkbutton(win, text="Enabled", variable=chVarEn)
check3.select()                  # 12
check3.grid(column=2, row=4, sticky=tk.W) # 13
```

运行新代码将得到以下 GUI：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_12.jpg)

## 它是如何工作的...

在第 2、6 和 10 行，我们创建了三个`IntVar`类型的变量。在接下来的一行中，对于这些变量中的每一个，我们创建一个`Checkbutton`，传入这些变量。它们将保存`Checkbutton`的状态（未选中或选中）。默认情况下，它们是 0（未选中）或 1（选中），因此变量的类型是`tkinter`整数。

我们将这些`Checkbutton`小部件放在我们的主窗口中，因此传递给构造函数的第一个参数是小部件的父级；在我们的情况下是`win`。我们通过其`text`属性为每个`Checkbutton`提供不同的标签。

将网格的 sticky 属性设置为`tk.W`意味着小部件将对齐到网格的西侧。这与 Java 语法非常相似，意味着它将对齐到左侧。当我们调整 GUI 的大小时，小部件将保持在左侧，并不会向 GUI 的中心移动。

第 4 和 12 行通过调用这两个`Checkbutton`类实例的`select()`方法向`Checkbutton`小部件中放入复选标记。

我们继续使用网格布局管理器来排列我们的小部件，这将在第二章*布局管理*中详细解释。

# 使用单选按钮小部件

在这个示例中，我们将创建三个`tkinter Radiobutton`小部件。我们还将添加一些代码，根据选择的`Radiobutton`来更改主窗体的颜色。

## 准备就绪

这个示例扩展了之前的示例。

## 如何做...

我们将以下代码添加到之前的示例中：

```py
# Radiobutton Globals   # 1
COLOR1 = "Blue"         # 2
COLOR2 = "Gold"         # 3
COLOR3 = "Red"          # 4

# Radiobutton Callback  # 5
def radCall():          # 6
   radSel=radVar.get()
   if   radSel == 1: win.configure(background=COLOR1)
   elif radSel == 2: win.configure(background=COLOR2)
   elif radSel == 3: win.configure(background=COLOR3)

# create three Radiobuttons   # 7
radVar = tk.IntVar()          # 8
rad1 = tk.Radiobutton(win, text=COLOR1, variable=radVar, value=1,               command=radCall)              # 9
rad1.grid(column=0, row=5, sticky=tk.W)  # 10

rad2 = tk.Radiobutton(win, text=COLOR2, variable=radVar, value=2, command=radCall)                             # 11
rad2.grid(column=1, row=5, sticky=tk.W)  # 12

rad3 = tk.Radiobutton(win, text=COLOR3, variable=radVar, value=3, command=radCall)                             # 13
rad3.grid(column=2, row=5, sticky=tk.W)  # 14
```

运行此代码并选择名为**Gold**的`Radiobutton`将创建以下窗口：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_13.jpg)

## 它是如何工作的...

在 2-4 行中，我们创建了一些模块级全局变量，我们将在每个单选按钮的创建以及在创建改变主窗体背景颜色的回调函数（使用实例变量`win`）中使用这些变量。

我们使用全局变量使代码更容易更改。通过将颜色的名称分配给一个变量，并在多个地方使用这个变量，我们可以轻松地尝试不同的颜色。我们只需要更改一行代码，而不是全局搜索和替换硬编码的字符串（容易出错），其他所有东西都会工作。这被称为**DRY 原则**，代表**不要重复自己**。这是我们将在本书的后续食谱中使用的面向对象编程概念。

### 注意

我们分配给变量（`COLOR1`，`COLOR2...`）的颜色名称是`tkinter`关键字（从技术上讲，它们是*符号名称*）。如果我们使用不是`tkinter`颜色关键字的名称，那么代码将无法工作。

第 6 行是*回调函数*，根据用户的选择改变我们主窗体（`win`）的背景。

在第 8 行，我们创建了一个`tk.IntVar`变量。重要的是，我们只创建了一个变量供所有三个单选按钮使用。从上面的截图中可以看出，无论我们选择哪个`Radiobutton`，所有其他的都会自动为我们取消选择。

第 9 到 14 行创建了三个单选按钮，将它们分配给主窗体，并传入要在回调函数中使用的变量，以创建改变主窗口背景的操作。

### 注意

虽然这是第一个改变小部件颜色的食谱，但老实说，它看起来有点丑。本书中的大部分后续食谱都会解释如何使我们的 GUI 看起来真正令人惊叹。

## 还有更多...

这里是一小部分可用的符号颜色名称，您可以在官方 tcl 手册页面上查找：

[`www.tcl.tk/man/tcl8.5/TkCmd/colors.htm`](http://www.tcl.tk/man/tcl8.5/TkCmd/colors.htm)

| 名称 | 红 | 绿 | 蓝 |
| --- | --- | --- | --- |
| alice blue | 240 | 248 | 255 |
| AliceBlue | 240 | 248 | 255 |
| Blue | 0 | 0 | 255 |
| 金色 | 255 | 215 | 0 |
| 红色 | 255 | 0 | 0 |

一些名称创建相同的颜色，因此`alice blue`创建的颜色与`AliceBlue`相同。在这个食谱中，我们使用了符号名称`Blue`，`Gold`和`Red`。

# 使用滚动文本小部件

`ScrolledText`小部件比简单的`Entry`小部件大得多，跨越多行。它们就像记事本一样的小部件，自动换行，并在文本大于`ScrolledText`小部件的高度时自动启用垂直滚动条。

## 准备工作

这个食谱扩展了之前的食谱。您可以从 Packt Publishing 网站下载本书每一章的代码。

## 如何做...

通过添加以下代码行，我们创建了一个`ScrolledText`小部件：

```py
# Add this import to the top of the Python Module    # 1
from tkinter import scrolledtext      # 2

# Using a scrolled Text control       # 3
scrolW  = 30                          # 4
scrolH  =  3                          # 5
scr = scrolledtext.ScrolledText(win, width=scrolW, height=scrolH, wrap=tk.WORD)                         # 6
scr.grid(column=0, columnspan=3)      # 7
```

我们实际上可以在我们的小部件中输入文字，如果我们输入足够多的单词，行将自动换行！

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_14.jpg)

一旦我们输入的单词超过了小部件可以显示的高度，垂直滚动条就会启用。所有这些都是开箱即用的，我们不需要编写任何额外的代码来实现这一点。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_01_15.jpg)

## 它是如何工作的...

在第 2 行，我们导入包含`ScrolledText`小部件类的模块。将其添加到模块顶部，就在其他两个`import`语句的下面。

第 4 和 5 行定义了我们即将创建的`ScrolledText`小部件的宽度和高度。这些是硬编码的值，我们将它们传递给第 6 行中`ScrolledText`小部件的构造函数。

这些值是通过实验找到的*魔术数字*，可以很好地工作。您可以尝试将`srcolW`从 30 更改为 50，并观察效果！

在第 6 行，我们通过传入`wrap=tk.WORD`在小部件上设置了一个属性。

通过将`wrap`属性设置为`tk.WORD`，我们告诉`ScrolledText`小部件按单词换行，这样我们就不会在单词中间换行。默认选项是`tk.CHAR`，它会在单词中间换行。

第二个屏幕截图显示，垂直滚动条向下移动，因为我们正在阅读一个较长的文本，它不能完全适应我们创建的`SrolledText`控件的 x，y 维度。

将网格小部件的`columnspan`属性设置为`3`，使`SrolledText`小部件跨越所有三列。如果我们不设置这个属性，我们的`SrolledText`小部件将只驻留在第一列，这不是我们想要的。

# 在循环中添加多个小部件

到目前为止，我们已经通过基本上复制和粘贴相同的代码，然后修改变化（例如，列号）来创建了几个相同类型的小部件（例如`Radiobutton`）。在这个示例中，我们开始重构我们的代码，使其不那么冗余。

## 准备工作

我们正在重构上一个示例代码的一些部分，所以你需要将那个代码应用到这个示例中。

## 如何做到...

```py
# First, we change our Radiobutton global variables into a list.
colors = ["Blue", "Gold", "Red"]              # 1

# create three Radiobuttons using one variable
radVar = tk.IntVar()

Next we are selecting a non-existing index value for radVar.
radVar.set(99)                                # 2

Now we are creating all three Radiobutton widgets within one loop.

for col in range(3):                          # 3
    curRad = 'rad' + str(col)  
    curRad = tk.Radiobutton(win, text=colors[col], variable=radVar,     value=col, command=radCall)
    curRad.grid(column=col, row=5, sticky=tk.W)

We have also changed the callback function to be zero-based, using the list instead of module-level global variables. 

# Radiobutton callback function                # 4
def radCall():
   radSel=radVar.get()
   if   radSel == 0: win.configure(background=colors[0])
   elif radSel == 1: win.configure(background=colors[1])
   elif radSel == 2: win.configure(background=colors[2])
```

运行此代码将创建与以前相同的窗口，但我们的代码更清晰，更易于维护。这将有助于我们在下一个示例中扩展我们的 GUI。

## 它是如何工作的...

在第 1 行，我们将全局变量转换为列表。

在第 2 行，我们为名为`radVar`的`tk.IntVar`变量设置了默认值。这很重要，因为在上一个示例中，我们将`Radiobutton`小部件的值设置为 1，但在我们的新循环中，使用 Python 的基于零的索引更方便。如果我们没有将默认值设置为超出`Radiobutton`小部件范围的值，当 GUI 出现时，将选择一个单选按钮。虽然这本身可能并不那么糟糕，*它不会触发回调*，我们最终会选择一个不起作用的单选按钮（即更改主窗体的颜色）。

在第 3 行，我们用循环替换了之前硬编码创建`Radiobutton`小部件的三个部分，这样做是一样的。它只是更简洁（代码行数更少）和更易于维护。例如，如果我们想创建 100 个而不仅仅是 3 个`Radiobutton`小部件，我们只需要改变 Python 的 range 运算符中的数字。我们不必输入或复制粘贴 97 个重复代码段，只需一个数字。

第 4 行显示了修改后的回调，实际上它位于前面的行之上。我们将其放在下面是为了强调这个示例的更重要的部分。

## 还有更多...

这个示例结束了本书的第一章。接下来章节中的所有示例都将在我们迄今为止构建的 GUI 基础上进行扩展，大大增强它。


# 第二章：布局管理

在本章中，我们将使用 Python 3 来布局我们的 GUI：

+   在标签框架小部件内排列几个标签

+   使用填充在小部件周围添加空间

+   小部件如何动态扩展 GUI

+   通过在框架内嵌套框架来对齐 GUI 小部件

+   创建菜单栏

+   创建选项卡小部件

+   使用网格布局管理器

# 介绍

在这一章中，我们将探讨如何在小部件内部排列小部件，以创建我们的 Python GUI。学习 GUI 布局设计的基础知识将使我们能够创建外观出色的 GUI。有一些技术将帮助我们实现这种布局设计。

网格布局管理器是内置在 tkinter 中的最重要的布局工具之一，我们将使用它。

我们可以很容易地使用 tk 来创建菜单栏，选项卡控件（又名 Notebooks）以及许多其他小部件。

tk 中默认缺少的一个小部件是状态栏。

在本章中，我们将不费力地手工制作这个小部件，但这是可以做到的。

# 在标签框架小部件内排列几个标签

`LabelFrame`小部件允许我们以有组织的方式设计我们的 GUI。我们仍然使用网格布局管理器作为我们的主要布局设计工具，但通过使用`LabelFrame`小部件，我们可以更好地控制 GUI 设计。

## 准备工作

我们开始向我们的 GUI 添加越来越多的小部件，并且我们将在接下来的示例中使 GUI 完全功能。在这里，我们开始使用`LabelFrame`小部件。我们将重用上一章最后一个示例中的 GUI。

## 如何做...

在 Python 模块的底部朝向主事件循环上方添加以下代码：

```py
# Create a container to hold labels
labelsFrame = ttk.LabelFrame(win, text=' Labels in a Frame ') # 1
labelsFrame.grid(column=0, row=7)

# Place labels into the container element # 2
ttk.Label(labelsFrame, text="Label1").grid(column=0, row=0)
ttk.Label(labelsFrame, text="Label2").grid(column=1, row=0)
ttk.Label(labelsFrame, text="Label3").grid(column=2, row=0)

# Place cursor into name Entry
nameEntered.focus()
```

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_01.jpg)

### 注意

通过更改我们的代码，我们可以轻松地垂直对齐标签，如下所示。请注意，我们唯一需要更改的是列和行编号。

```py
# Place labels into the container element – vertically # 3
ttk.Label(labelsFrame, text="Label1").grid(column=0, row=0)
ttk.Label(labelsFrame, text="Label2").grid(column=0, row=1)
ttk.Label(labelsFrame, text="Label3").grid(column=0, row=2)
```

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_01_1.jpg)

## 它是如何工作的...

注释＃1：在这里，我们将创建我们的第一个 ttk LabelFrame 小部件并为框架命名。父容器是`win`，即我们的主窗口。

在注释＃2 之后的三行代码创建标签名称并将它们放置在 LabelFrame 中。我们使用重要的网格布局工具来排列 LabelFrame 内的标签。此布局管理器的列和行属性赋予我们控制 GUI 布局的能力。

### 注意

我们标签的父级是 LabelFrame，而不是主窗口的`win`实例变量。我们可以在这里看到布局层次的开始。

突出显示的注释＃3 显示了通过列和行属性轻松更改布局的方法。请注意，我们如何将列更改为 0，并且如何通过按顺序编号行值来垂直叠加我们的标签。

### 注意

ttk 的名称代表“主题 tk”。tk-themed 小部件集是在 Tk 8.5 中引入的。

## 还有更多...

在本章的后面的一个示例中，我们将嵌套 LabelFrame(s)在 LabelFrame(s)中，以控制我们的 GUI 布局。

# 使用填充在小部件周围添加空间

我们的 GUI 正在很好地创建。接下来，我们将通过在它们周围添加一点空间来改善我们小部件的视觉效果，以便它们可以呼吸...

## 准备工作

尽管 tkinter 可能曾经以创建丑陋的 GUI 而闻名，但自 8.5 版本以来（随 Python 3.4.x 一起发布），这种情况发生了显著变化。您只需要知道如何使用可用的工具和技术。这就是我们接下来要做的。

## 如何做...

首先展示了围绕小部件添加间距的程序化方法，然后我们将使用循环以更好的方式实现相同的效果。

我们的 LabelFrame 看起来有点紧凑，因为它与主窗口向底部融合在一起。让我们现在来修复这个问题。

通过添加`padx`和`pady`修改以下代码行：

```py
labelsFrame.grid(column=0, row=7, padx=20, pady=40)
```

现在我们的 LabelFrame 有了一些空间：

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_02.jpg)

## 它是如何工作的...

在 tkinter 中，通过使用名为`padx`和`pady`的内置属性来水平和垂直地添加空间。这些属性可以用于在许多小部件周围添加空间，分别改善水平和垂直对齐。我们在 LabelFrame 的左右两侧硬编码了 20 像素的空间，并在框架的顶部和底部添加了 40 像素。现在我们的 LabelFrame 比以前更加突出。

### 注意

上面的屏幕截图只显示了相关的更改。

我们可以使用循环在 LabelFrame 内包含的标签周围添加空间：

```py
for child in labelsFrame.winfo_children(): 
    child.grid_configure(padx=8, pady=4)
```

现在 LabelFrame 小部件内的标签周围也有一些空间：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_02_1.jpg)

`grid_configure()`函数使我们能够在主循环显示 UI 元素之前修改它们。因此，我们可以在首次创建小部件时，而不是硬编码数值，可以在文件末尾的布局中工作，然后在创建 GUI 之前进行间距调整。这是一个不错的技巧。

`winfo_children()`函数返回属于`labelsFrame`变量的所有子项的列表。这使我们能够循环遍历它们并为每个标签分配填充。

### 注意

要注意的一件事是标签右侧的间距实际上并不明显。这是因为 LabelFrame 的标题比标签的名称长。我们可以通过使标签的名称更长来进行实验。

```py
ttk.Label(labelsFrame, text="Label1 -- sooooo much loooonger...").grid(column=0, row=0)
```

现在我们的 GUI 看起来像下面这样。请注意，现在在长标签旁边的右侧添加了一些空间。最后一个点没有触及 LabelFrame，如果没有添加的空间，它就会触及。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_02_2.jpg)

我们还可以删除 LabelFrame 的名称，以查看`padx`对定位我们的标签的影响。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_02_3.jpg)

# 小部件如何动态扩展 GUI

您可能已经注意到在之前的屏幕截图中，并通过运行代码，小部件具有扩展自身以视觉显示其文本所需的能力。

### 注意

Java 引入了动态 GUI 布局管理的概念。相比之下，像 VS.NET 这样的可视化开发 IDE 以可视化方式布局 GUI，并且基本上是在硬编码 UI 元素的 x 和 y 坐标。

使用`tkinter`，这种动态能力既带来了优势，也带来了一点挑战，因为有时我们的 GUI 会在我们不希望它太动态时动态扩展！好吧，我们是动态的 Python 程序员，所以我们可以想出如何最好地利用这种奇妙的行为！

## 准备工作

在上一篇食谱的开头，我们添加了一个标签框小部件。这将一些控件移动到第 0 列的中心。我们可能不希望这种修改影响我们的 GUI 布局。接下来，我们将探讨一些修复这个问题的方法。

## 如何做...

让我们首先注意一下 GUI 布局中正在发生的微妙细节，以更好地理解它。

我们正在使用网格布局管理器小部件，并且它以从零开始的网格布局排列我们的小部件。

| 第 0 行；第 0 列 | 第 0 行；第 1 列 | 第 0 行；第 2 列 |
| --- | --- | --- |
| 第 1 行；第 0 列 | 第 1 行；第 1 列 | 第 1 行；第 2 列 |

使用网格布局管理器时，任何给定列的宽度由该列中最长的名称或小部件确定。这会影响所有行。

通过添加 LabelFrame 小部件并给它一个比某些硬编码大小小部件（如左上角的标签和下面的文本输入）更长的标题，我们动态地将这些小部件移动到第 0 列的中心，并在这些小部件的左右两侧添加空间。

顺便说一句，因为我们为 Checkbutton 和 ScrolledText 小部件使用了 sticky 属性，它们仍然附着在框架的左侧。

让我们更详细地查看本章第一个示例的屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_02_4.jpg)

我们添加了以下代码来创建 LabelFrame，然后将标签放入此框架中：

```py
# Create a container to hold labels
labelsFrame = ttk.LabelFrame(win, text=' Labels in a Frame ')
labelsFrame.grid(column=0, row=7)
```

由于 LabelFrame 的 text 属性（显示为 LabelFrame 的标题）比我们的**Enter a name:**标签和下面的文本框条目都长，这两个小部件会动态地居中于列 0 的新宽度。

列 0 中的 Checkbutton 和 Radiobutton 小部件没有居中，因为我们在创建这些小部件时使用了`sticky=tk.W`属性。

对于 ScrolledText 小部件，我们使用了`sticky=tk.WE`，这将小部件绑定到框架的西（即左）和东（即右）两侧。

让我们从 ScrolledText 小部件中删除 sticky 属性，并观察这个改变的影响。

```py
scr = scrolledtext.ScrolledText(win, width=scrolW, height=scrolH, wrap=tk.WORD)
#### scr.grid(column=0, sticky='WE', columnspan=3)
scr.grid(column=0, columnspan=3)
```

现在我们的 GUI 在 ScrolledText 小部件的左侧和右侧都有新的空间。因为我们使用了`columnspan=3`属性，我们的 ScrolledText 小部件仍然跨越了所有三列。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_02_5.jpg)

如果我们移除`columnspan=3`，我们会得到以下 GUI，这不是我们想要的。现在我们的 ScrolledText 只占据列 0，并且由于其大小，它拉伸了布局。

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_02_6.jpg)

将我们的布局恢复到添加 LabelFrame 之前的方法之一是调整网格列位置。将列值从 0 更改为 1。

```py
labelsFrame.grid(column=1, row=7, padx=20, pady=40)
```

现在我们的 GUI 看起来像这样：

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_03.jpg)

## 它是如何工作的...

因为我们仍在使用单独的小部件，所以我们的布局可能会混乱。通过将 LabelFrame 的列值从 0 移动到 1，我们能够将控件放回到它们原来的位置，也是我们喜欢它们的位置。至少最左边的标签、文本、复选框、滚动文本和单选按钮小部件现在位于我们打算的位置。第二个标签和文本`Entry`位于列 1，它们自己对齐到了**Labels in a Frame**小部件的长度中心，所以我们基本上将我们的对齐挑战移到了右边一列。这不太明显，因为**Choose a number:**标签的大小几乎与**Labels in a Frame**标题的大小相同，因此列宽已经接近 LabelFrame 生成的新宽度。

## 还有更多...

在下一个教程中，我们将嵌入框架以避免我们在本教程中刚刚经历的小部件意外错位。

# 通过嵌入框架来对齐 GUI 小部件

如果我们在框架中嵌入框架，我们将更好地控制 GUI 布局。这就是我们将在本教程中做的事情。

## 准备工作

Python 及其 GUI 模块的动态行为可能会对我们真正想要的 GUI 外观造成一些挑战。在这里，我们将嵌入框架以获得对布局的更多控制。这将在不同 UI 元素之间建立更强的层次结构，使视觉外观更容易实现。

我们将继续使用我们在上一个教程中创建的 GUI。

## 如何做...

在这里，我们将创建一个顶级框架，其中将包含其他框架和小部件。这将帮助我们将 GUI 布局调整到我们想要的样子。

为了做到这一点，我们将不得不将我们当前的控件嵌入到一个中央 ttk.LabelFrame 中。这个 ttk.LabelFrame 是主父窗口的子窗口，所有控件都是这个 ttk.LabelFrame 的子控件。

在我们的教程中到目前为止，我们已经直接将所有小部件分配给了我们的主 GUI 框架。现在我们将只将我们的 LabelFrame 分配给我们的主窗口，之后，我们将使这个 LabelFrame 成为所有小部件的父容器。

这在我们的 GUI 布局中创建了以下层次结构：

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_30.jpg)

在这个图表中，**win**是指我们的主 GUI tkinter 窗口框架的变量；**monty**是指我们的 LabelFrame 的变量，并且是主窗口框架（**win**）的子窗口；**aLabel**和所有其他小部件现在都放置在 LabelFrame 容器（**monty**）中。

在我们的 Python 模块顶部添加以下代码（参见注释＃1）：

```py
# Create instance
win = tk.Tk()

# Add a title       
win.title("Python GUI")    

# We are creating a container frame to hold all other widgets # 1
monty = ttk.LabelFrame(win, text=' Monty Python ')
monty.grid(column=0, row=0)
```

接下来，我们将修改所有以下控件，使用`monty`作为父控件，替换`win`。以下是如何做到这一点的示例：

```py
# Modify adding a Label
aLabel = ttk.Label(monty, text="A Label")
```

![如何做到...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_04.jpg)

请注意，现在所有的小部件都包含在**Monty Python** LabelFrame 中，它用几乎看不见的细线将它们全部包围起来。接下来，我们可以重置**Labels in a Frame**小部件到左侧，而不会弄乱我们的 GUI 布局：

![如何做到...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_04_1.jpg)

哎呀-也许不是。虽然我们在另一个框架中的框架很好地对齐到了左侧，但它又把我们的顶部小部件推到了中间（默认）。

为了将它们对齐到左侧，我们必须使用`sticky`属性来强制我们的 GUI 布局。通过将其分配为"W"（西），我们可以控制小部件左对齐。

```py
# Changing our Label
ttk.Label(monty, text="Enter a name:").grid(column=0, row=0, sticky='W')
```

![如何做到...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_04_2.jpg)

## 它是如何工作的...

请注意我们对齐了标签，但没有对下面的文本框进行对齐。我们必须使用`sticky`属性来左对齐我们想要左对齐的所有控件。我们可以在一个循环中做到这一点，使用`winfo_children()`和`grid_configure(sticky='W')`属性，就像我们在本章的第 2 个配方中做的那样。

`winfo_children()`函数返回属于父控件的所有子控件的列表。这使我们能够循环遍历所有小部件并更改它们的属性。

### 注意

使用 tkinter 来强制左、右、上、下的命名与 Java 非常相似：west、east、north 和 south，缩写为："W"等等。我们还可以使用以下语法：tk.W 而不是"W"。

在以前的配方中，我们将"W"和"E"组合在一起，使我们的 ScrolledText 小部件使用"WE"附加到其容器的左侧和右侧。我们可以添加更多的组合："NSE"将使我们的小部件拉伸到顶部、底部和右侧。如果我们的表单中只有一个小部件，例如一个按钮，我们可以使用所有选项使其填满整个框架："NSWE"。我们还可以使用元组语法：`sticky=(tk.N, tk.S, tk.W, tk.E)`。

让我们把非常长的标签改回来，并将条目对齐到第 0 列的左侧。

```py
ttk.Label(monty, text="Enter a name:").grid(column=0, row=0, sticky='W')

name = tk.StringVar()
nameEntered = ttk.Entry(monty, width=12, textvariable=name)
nameEntered.grid(column=0, row=1, sticky=tk.W)
```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_04_3.jpg)

### 注意

为了分离我们的**Labels in a Frame** LabelFrame 对我们的 GUI 布局的影响，我们不能将这个 LabelFrame 放入与其他小部件相同的 LabelFrame 中。相反，我们直接将它分配给主 GUI 表单（`win`）。

我们将在以后的章节中做到这一点。

# 创建菜单栏

在这个配方中，我们将向我们的主窗口添加一个菜单栏，向菜单栏添加菜单，然后向菜单添加菜单项。

## 准备工作

我们将首先学习如何添加菜单栏、几个菜单和一些菜单项的技巧，以展示如何做到这一点的原则。单击菜单项将不会产生任何效果。接下来，我们将为菜单项添加功能，例如，单击**Exit**菜单项时关闭主窗口，并显示**Help** | **About**对话框。

我们将继续扩展我们在当前和上一章中创建的 GUI。

## 如何做到...

首先，我们必须从`tkinter`中导入`Menu`类。在 Python 模块的顶部添加以下代码，即导入语句所在的地方： 

```py
from tkinter import Menu
```

接下来，我们将创建菜单栏。在模块的底部添加以下代码，就在我们创建主事件循环的地方上面：

```py
menuBar = Menu(win)                      # 1
win.config(menu=menuBar)
```

现在我们在菜单栏中添加一个菜单，并将一个菜单项分配给菜单。

```py
fileMenu = Menu(menuBar)                 # 2
fileMenu.add_command(label="New")
menuBar.add_cascade(label="File", menu=fileMenu)
```

运行此代码将添加一个菜单栏，其中有一个菜单，其中有一个菜单项。

![如何做到...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_05.jpg)

接下来，我们在我们添加到菜单栏的第一个菜单中添加第二个菜单项。

```py
fileMenu.add_command(label="New")
fileMenu.add_command(label="Exit")        # 3
menuBar.add_cascade(label="File", menu=fileMenu)
```

![如何做到...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_05_1.jpg)

我们可以通过在现有的 MenuItems 之间添加以下代码（＃4）来添加一个分隔线。

```py
fileMenu.add_command(label="New")
fileMenu.add_separator()               # 4
fileMenu.add_command(label="Exit")
```

![如何做到...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_05_2.jpg)

通过将`tearoff`属性传递给菜单的构造函数，我们可以删除默认情况下出现在菜单中第一个 MenuItem 上方的第一条虚线。

```py
# Add menu items
fileMenu = Menu(menuBar, tearoff=0)      # 5
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_05_3.jpg)

我们将添加第二个菜单，它将水平放置在第一个菜单的右侧。我们将给它一个菜单项，我们将其命名为`关于`，为了使其工作，我们必须将这第二个菜单添加到菜单栏。

**文件**和**帮助** | **关于**是非常常见的 Windows GUI 布局，我们都很熟悉，我们可以使用 Python 和 tkinter 创建相同的菜单。

菜单的创建顺序和命名可能一开始有点令人困惑，但一旦我们习惯了 tkinter 要求我们如何编码，这实际上变得有趣起来。

```py
helpMenu = Menu(menuBar, tearoff=0)            # 6
helpMenu.add_command(label="About")
menuBar.add_cascade(label="Help", menu=helpMenu)
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_05_4.jpg)

此时，我们的 GUI 有一个菜单栏和两个包含一些菜单项的菜单。单击它们并没有太多作用，直到我们添加一些命令。这就是我们接下来要做的。在创建菜单栏之前添加以下代码：

```py
def _quit():         # 7
    win.quit()
    win.destroy()
    exit()
```

接下来，我们将**文件** | **退出**菜单项绑定到这个函数，方法是在菜单项中添加以下命令：

```py
fileMenu.add_command(label="Exit", command=_quit)    # 8
```

现在，当我们点击`退出`菜单项时，我们的应用程序确实会退出。

## 它是如何工作的...

在注释＃1 中，我们调用了菜单的`tkinter`构造函数，并将菜单分配给我们的主 GUI 窗口。我们在实例变量中保存了一个名为`menuBar`的引用，并在下一行代码中，我们使用这个实例来配置我们的 GUI，以使用`menuBar`作为我们的菜单。

注释＃2 显示了我们首先添加一个菜单项，然后创建一个菜单。这似乎有点不直观，但这就是 tkinter 的工作原理。`add_cascade()`方法将菜单项垂直布局在一起。

注释＃3 显示了如何向菜单添加第二个菜单项。

在注释＃4 中，我们在两个菜单项之间添加了一个分隔线。这通常用于将相关的菜单项分组并将它们与不太相关的项目分开（因此得名）。

注释＃5 禁用了虚线以使我们的菜单看起来更好。

### 注意

在不禁用此默认功能的情况下，用户可以从主窗口“撕下”菜单。我发现这种功能价值不大。随意双击虚线（在禁用此功能之前）进行尝试。

如果您使用的是 Mac，这个功能可能没有启用，所以您根本不用担心。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_05_5.jpg)

注释＃6 向您展示了如何向菜单栏添加第二个菜单。我们可以继续使用这种技术添加菜单。

注释＃7 创建了一个函数来干净地退出我们的 GUI 应用程序。这是结束主事件循环的推荐 Pythonic 方式。

在＃8 中，我们将在＃7 中创建的函数绑定到菜单项，使用`tkinter`命令属性。每当我们想要我们的菜单项实际执行某些操作时，我们必须将它们中的每一个绑定到一个函数。

### 注意

我们使用了推荐的 Python 命名约定，通过在退出函数之前加上一个下划线，以表示这是一个私有函数，不应该由我们代码的客户端调用。

## 还有更多...

在下一章中，我们将添加**帮助** | **关于**功能，介绍消息框等等。

# 创建选项卡小部件

在这个配方中，我们将创建选项卡小部件，以进一步组织我们在 tkinter 中编写的扩展 GUI。

## 准备工作

为了改进我们的 Python GUI，我们将从头开始，使用最少量的代码。在接下来的配方中，我们将从以前的配方中添加小部件，并将它们放入这个新的选项卡布局中。

## 如何做...

创建一个新的 Python 模块，并将以下代码放入该模块：

```py
import tkinter as tk                    # imports
from tkinter import ttk
win = tk.Tk()                           # Create instance      
win.title("Python GUI")                 # Add a title 
tabControl = ttk.Notebook(win)          # Create Tab Control
tab1 = ttk.Frame(tabControl)            # Create a tab 
tabControl.add(tab1, text='Tab 1')      # Add the tab
tabControl.pack(expand=1, fill="both")  # Pack to make visible
win.mainloop()                          # Start GUI
```

这创建了以下 GUI：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06.jpg)

尽管目前还不是非常令人印象深刻，但这个小部件为我们的 GUI 设计工具包增加了另一个非常强大的工具。它在上面的极简示例中有自己的限制（例如，我们无法重新定位 GUI，也不显示整个 GUI 标题）。

在以前的示例中，我们使用网格布局管理器来创建更简单的 GUI，我们可以使用更简单的布局管理器之一，“pack”是其中之一。

在上述代码中，我们将 tabControl ttk.Notebook“pack”到主 GUI 表单中，扩展选项卡控件以填充所有边缘。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06_0.jpg)

我们可以向我们的控件添加第二个选项卡并在它们之间切换。

```py
tab2 = ttk.Frame(tabControl)            # Add a second tab
tabControl.add(tab2, text='Tab 2')      # Make second tab visible
win.mainloop()                          # Start GUI
```

现在我们有两个标签。单击**Tab 2**以使其获得焦点。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06_1.jpg)

我们真的很想看到我们的窗口标题。因此，为了做到这一点，我们必须向我们的选项卡中添加一个小部件。该小部件必须足够宽，以动态扩展我们的 GUI 以显示我们的窗口标题。我们正在将 Ole Monty 和他的孩子们重新添加。

```py
monty = ttk.LabelFrame(tab1, text=' Monty Python ')
monty.grid(column=0, row=0, padx=8, pady=4)
ttk.Label(monty, text="Enter a name:").grid(column=0, row=0, sticky='W')
```

现在我们在**Tab1**中有我们的**Monty Python**。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06_2.jpg)

我们可以继续将到目前为止创建的所有小部件放入我们新创建的选项卡控件中。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06_3.jpg)

现在所有的小部件都驻留在**Tab1**中。让我们将一些移动到**Tab2**。首先，我们创建第二个 LabelFrame，作为我们将移动到**Tab2**的小部件的容器：

```py
monty2 = ttk.LabelFrame(tab2, text=' The Snake ')
monty2.grid(column=0, row=0, padx=8, pady=4)
```

接下来，我们通过指定新的父容器`monty2`，将复选框和单选按钮移动到**Tab2**。以下是一个示例，我们将其应用于所有移动到**Tab2**的控件：

```py
chVarDis = tk.IntVar()
check1 = tk.Checkbutton(monty2, text="Disabled", variable=chVarDis, state='disabled')
```

当我们运行代码时，我们的 GUI 现在看起来不同了。**Tab1**的小部件比以前少了，当它包含我们以前创建的所有小部件时。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06_4.jpg)

现在我们可以单击**Tab 2**并查看我们移动的小部件。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06_5.jpg)

单击移动的 Radiobutton(s)不再产生任何效果，因此我们将更改它们的操作以重命名文本属性，这是 LabelFrame 小部件的标题，以显示 Radiobuttons 的名称。当我们单击**Gold** Radiobutton 时，我们不再将框架的背景设置为金色，而是在这里替换 LabelFrame 文本标题。Python“ The Snake”现在变成“Gold”。

```py
# Radiobutton callback function
def radCall():
    radSel=radVar.get()
    if   radSel == 0: monty2.configure(text='Blue')
    elif radSel == 1: monty2.configure(text='Gold')
    elif radSel == 2: monty2.configure(text='Red')
```

现在，选择任何 RadioButton 小部件都会导致更改 LabelFrame 的名称。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_06_6.jpg)

## 它是如何工作的...

创建第二个选项卡后，我们将一些最初驻留在**Tab1**中的小部件移动到**Tab2**。添加选项卡是组织我们不断增加的 GUI 的另一种绝佳方式。这是处理 GUI 设计中复杂性的一种非常好的方式。我们可以将小部件分组放置在它们自然属于的组中，并通过使用选项卡使我们的用户摆脱混乱。

### 注意

在`tkinter`中，通过`Notebook`小部件创建选项卡是通过`Notebook`小部件完成的，这是允许我们添加选项卡控件的工具。 tkinter 笔记本小部件，就像许多其他小部件一样，具有我们可以使用和配置的附加属性。探索我们可以使用的 tkinter 小部件的其他功能的绝佳起点是官方网站：[`docs.python.org/3.1/library/tkinter.ttk.html#notebook`](https://docs.python.org/3.1/library/tkinter.ttk.html#notebook)

# 使用网格布局管理器

网格布局管理器是我们可以使用的最有用的布局工具之一。我们已经在许多示例中使用了它，因为它非常强大。

## 准备工作...

在这个示例中，我们将回顾一些网格布局管理器的技术。我们已经使用过它们，在这里我们将进一步探讨它们。

## 如何做...

在本章中，我们已经创建了行和列，这实际上是 GUI 设计的数据库方法（MS Excel 也是如此）。我们硬编码了前四行，但然后忘记了给下一行一个我们希望它驻留的位置的规范。

Tkinter 在我们不知不觉中为我们填充了这个。

以下是我们在代码中所做的：

```py
check3.grid(column=2, row=4, sticky=tk.W, columnspan=3)
scr.grid(column=0, sticky='WE', columnspan=3)              # 1
curRad.grid(column=col, row=6, sticky=tk.W, columnspan=3)
labelsFrame.grid(column=0, row=7)
```

Tkinter 自动添加了我们没有指定任何特定行的缺失行（在注释＃1 中强调）。我们可能没有意识到这一点。

我们将复选框布置在第 4 行，然后“忘记”为我们的 ScrolledText 小部件指定行，我们通过 scr 变量引用它，然后我们添加了要布置在第 6 行的 Radiobutton 小部件。

这很好用，因为 tkinter 自动递增了我们的 ScrolledText 小部件的行位置，以使用下一个最高的行号，即第 5 行。

查看我们的代码，没有意识到我们“忘记”将我们的 ScrolledText 小部件明确定位到第 5 行，我们可能会认为那里什么都没有。

因此，我们可以尝试以下操作。

如果我们将变量`curRad`设置为使用第 5 行，我们可能会得到一个不愉快的惊喜：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_02_07.jpg)

## 它是如何工作的...

注意我们的 RadioButton(s)行突然出现在我们的 ScrolledText 小部件的中间！这绝对不是我们想要的 GUI 样式！

### 注意

如果我们忘记显式指定行号，默认情况下，`tkinter`将使用下一个可用的行。

我们还使用了`columnspan`属性来确保我们的小部件不会被限制在一列。以下是我们如何确保我们的 ScrolledText 小部件跨越 GUI 的所有列：

```py
# Using a scrolled Text control    
scrolW = 30; scrolH = 3
scr = ScrolledText(monty, width=scrolW, height=scrolH, wrap=tk.WORD)
scr.grid(column=0, sticky='WE', columnspan=3)
```


# 第三章：外观定制

在本章中，我们将使用 Python 3 自定义我们的 GUI：

+   创建消息框-信息、警告和错误

+   如何创建独立的消息框

+   如何创建 tkinter 窗体的标题

+   更改主根窗口的图标

+   使用旋转框控件

+   小部件的浮雕、凹陷和凸起外观

+   使用 Python 创建工具提示

+   如何使用画布小部件

# 介绍

在本章中，我们将通过更改一些属性来自定义 GUI 中的一些小部件。我们还介绍了一些 tkinter 提供给我们的新小部件。

*使用 Python 创建工具提示*示例将创建一个 ToolTip 面向对象的类，它将成为我们到目前为止一直在使用的单个 Python 模块的一部分。

# 创建消息框-信息、警告和错误

消息框是一个弹出窗口，向用户提供反馈。它可以是信息性的，暗示潜在问题，甚至是灾难性的错误。

使用 Python 创建消息框非常容易。

## 准备工作

我们将为上一个示例中创建的“帮助”|“关于”菜单项添加功能。在大多数应用程序中，单击“帮助”|“关于”菜单时向用户提供的典型反馈是信息性的。我们从这个信息开始，然后变化设计模式以显示警告和错误。

## 如何做...

将以下代码添加到导入语句所在的模块顶部：

```py
from tkinter import messagebox as mBox
```

接下来，我们将创建一个回调函数来显示一个消息框。我们必须将回调的代码放在我们将回调附加到菜单项的代码上面，因为这仍然是过程性的而不是面向对象的代码。

将此代码添加到创建帮助菜单的行的上方：

```py
# Display a Message Box
# Callback function
def _msgBox():
    mBox.showinfo('Python Message Info Box', 'A Python GUI created using tkinter:\nThe year is 2015.')   

# Add another Menu to the Menu Bar and an item
helpMenu = Menu(menuBar, tearoff=0)
helpMenu.add_command(label="About", command=_msgBox)
```

现在单击“帮助”|“关于”会导致以下弹出窗口出现：

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_01.jpg)

让我们将这段代码转换为警告消息框弹出窗口。注释掉上一行并添加以下代码：

```py
# Display a Message Box
def _msgBox():
#    mBox.showinfo('Python Message Info Box', 'A Python GUI 
#      created using tkinter:\nThe year is 2015.')
    mBox.showwarning('Python Message Warning Box', 'A Python GUI created using tkinter:\nWarning: There might be a bug in this code.')
```

运行上面的代码现在会导致以下略微修改的消息框出现：

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_02.jpg)

显示错误消息框很简单，通常警告用户存在严重问题。如上所述，注释掉并添加此代码，如我们在这里所做的：

```py
# Display a Message Box
def _msgBox():
#    mBox.showinfo('Python Message Info Box', 'A Python GUI 
#      created using tkinter:\nThe year is 2015.')
#    mBox.showwarning('Python Message Warning Box', 'A Python GUI 
#      created using tkinter:\nWarning: There might be a bug in 
#      this code.')
    mBox.showerror('Python Message Error Box', 'A Python GUI created using tkinter:\nError: Houston ~ we DO have a serious PROBLEM!')
```

![操作步骤...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_03.jpg)

## 工作原理...

我们添加了另一个回调函数，并将其附加为处理单击事件的委托。现在，当我们单击“帮助”|“关于”菜单时，会发生一个动作。我们正在创建和显示最常见的弹出式消息框对话框。它们是模态的，因此用户在点击“确定”按钮之前无法使用 GUI。

在第一个示例中，我们显示了一个信息框，可以看到其左侧的图标。接下来，我们创建警告和错误消息框，它们会自动更改与弹出窗口关联的图标。我们只需指定要显示哪个 mBox。

有不同的消息框显示多个“确定”按钮，我们可以根据用户的选择来编程我们的响应。

以下是一个简单的例子，说明了这种技术：

```py
# Display a Message Box
def _msgBox():
    answer = mBox.askyesno("Python Message Dual Choice Box", "Are you sure you really wish to do this?")
    print(answer)
```

运行此 GUI 代码会导致弹出一个用户响应可以用来分支的窗口，通过将其保存在`answer`变量中来驱动此事件驱动的 GUI 循环的答案。

![工作原理...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_04.jpg)

在 Eclipse 中使用控制台输出显示，单击“是”按钮会导致将布尔值`True`分配给`answer`变量。

![工作原理...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_05.jpg)

例如，我们可以使用以下代码：

```py
If answer == True:
    <do something>
```

# 如何创建独立的消息框

在这个示例中，我们将创建我们的 tkinter 消息框作为独立的顶层 GUI 窗口。

我们首先注意到，这样做会多出一个窗口，因此我们将探索隐藏此窗口的方法。

在上一个示例中，我们通过我们主 GUI 表单中的“帮助”|“关于”菜单调用了 tkinter 消息框。

那么为什么我们希望创建一个独立的消息框呢？

一个原因是我们可能会自定义我们的消息框，并在我们的 GUI 中重用它们。我们可以将它们从我们的主 GUI 代码中分离出来，而不是在我们设计的每个 Python GUI 中复制和粘贴相同的代码。这可以创建一个小的可重用组件，然后我们可以将其导入到不同的 Python GUI 中。

## 准备工作

我们已经在上一个食谱中创建了消息框的标题。我们不会重用上一个食谱中的代码，而是会用很少的 Python 代码构建一个新的 GUI。

## 如何做...

我们可以像这样创建一个简单的消息框：

```py
from tkinter import messagebox as mBox
mBox.showinfo('A Python GUI created using tkinter:\nThe year is 2015')
```

这将导致这两个窗口：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_06.jpg)

这看起来不像我们想象的那样。现在我们有两个窗口，一个是不需要的，第二个是其文本显示为标题。

哎呀。

现在让我们来修复这个问题。我们可以通过添加一个单引号或双引号，后跟一个逗号来更改 Python 代码。

```py
mBox.showinfo('', 'A Python GUI created using tkinter:\nThe year is 2015')
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_07.jpg)

第一个参数是标题，第二个是弹出消息框中显示的文本。通过添加一对空的单引号或双引号，后跟一个逗号，我们可以将我们的文本从标题移到弹出消息框中。

我们仍然需要一个标题，而且我们肯定想摆脱这个不必要的第二个窗口。

### 注意

在像 C#这样的语言中，会出现第二个窗口的相同现象。基本上是一个 DOS 风格的调试窗口。许多程序员似乎不介意有这个额外的窗口漂浮。从 GUI 编程的角度来看，我个人觉得这很不雅。我们将在下一步中删除它。

第二个窗口是由 Windows 事件循环引起的。我们可以通过抑制它来摆脱它。

添加以下代码：

```py
from tkinter import messagebox as mBox
from tkinter import Tk
root = Tk()
root.withdraw()
mBox.showinfo('', 'A Python GUI created using tkinter:\nThe year is 2015')
```

现在我们只有一个窗口。`withdraw()`函数移除了我们不希望漂浮的调试窗口。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_08.jpg)

为了添加标题，我们只需将一些字符串放入我们的空第一个参数中。

例如：

```py
from tkinter import messagebox as mBox
from tkinter import Tk
root = Tk()
root.withdraw()
mBox.showinfo('This is a Title', 'A Python GUI created using tkinter:\nThe year is 2015')
```

现在我们的对话框有了标题：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_09.jpg)

## 它是如何工作的...

我们将更多参数传递给消息框的 tkinter 构造函数，以添加窗体的标题并在消息框中显示文本，而不是将其显示为标题。这是由于我们传递的参数的位置。如果我们省略空引号或双引号，那么消息框小部件将把第一个参数的位置作为标题，而不是要在消息框中显示的文本。通过传递一个空引号后跟一个逗号，我们改变了消息框显示我们传递给函数的文本的位置。

我们通过在我们的主根窗口上调用`withdraw()`方法来抑制 tkinter 消息框小部件自动创建的第二个弹出窗口。

# 如何创建 tkinter 窗体的标题

更改 tkinter 主根窗口的标题的原则与前一个食谱中讨论的原则相同。我们只需将一个字符串作为小部件的构造函数的第一个参数传递进去。

## 准备工作

与弹出对话框窗口不同，我们创建主根窗口并给它一个标题。

在这个食谱中显示的 GUI 是上一章的代码。它不是在本章中基于上一个食谱构建的。

## 如何做...

以下代码创建了主窗口并为其添加了标题。我们已经在以前的食谱中做过这个。在这里，我们只关注 GUI 的这个方面。

```py
import tkinter as tk
win = tk.Tk()               # Create instance
win.title("Python GUI")     # Add a title
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_10.jpg)

## 它是如何工作的...

通过使用内置的 tkinter `title` 属性，为主根窗口添加标题。在创建`Tk()`实例后，我们可以使用所有内置的 tkinter 属性来自定义我们的 GUI。

# 更改主根窗口的图标

自定义 GUI 的一种方法是给它一个与 tkinter 默认图标不同的图标。下面是我们如何做到这一点。

## 准备工作

我们正在改进上一个配方的 GUI。我们将使用一个随 Python 一起提供的图标，但您可以使用任何您认为有用的图标。确保您在代码中有图标所在的完整路径，否则可能会出错。

### 注意

虽然可能会有点混淆，上一章的这个配方指的是哪个配方，最好的方法就是只下载本书的代码，然后逐步执行代码以理解它。

## 如何做...

将以下代码放在主事件循环的上方某处。示例使用了我安装 Python 3.4 的路径。您可能需要调整它以匹配您的安装目录。

请注意 GUI 左上角的“feather”默认图标已更改。

```py
# Change the main windows icon
win.iconbitmap(r'C:\Python34\DLLs\pyc.ico')
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_11.jpg)

## 它是如何工作的...

这是另一个与 Python 3.x 一起提供的 tkinter 的属性。 `iconbitmap`是我们使用的属性，通过传递图标的绝对（硬编码）路径来改变主根窗口的图标。这将覆盖 tkinter 的默认图标，用我们选择的图标替换它。

### 注意

在上面的代码中，使用绝对路径的字符串中的“r”来转义反斜杠，因此我们可以使用“raw”字符串，而不是写`C:\\`，这让我们可以写更自然的单个反斜杠`C:\`。这是 Python 为我们创建的一个巧妙的技巧。

# 使用旋转框控件

在这个示例中，我们将使用`Spinbox`小部件，并且还将绑定键盘上的*Enter*键到我们的小部件之一。

## 准备工作

我们正在使用我们的分页 GUI，并将在`ScrolledText`控件上方添加一个`Spinbox`小部件。这只需要我们将`ScrolledText`行值增加一，并在`Entry`小部件上面的行中插入我们的新`Spinbox`控件。

## 如何做...

首先，我们添加了`Spinbox`控件。将以下代码放在`ScrolledText`小部件上方：

```py
# Adding a Spinbox widget
spin = Spinbox(monty, from_=0, to=10)
spin.grid(column=0, row=2)
```

这将修改我们的 GUI，如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_12.jpg)

接下来，我们将减小`Spinbox`小部件的大小。

```py
spin = Spinbox(monty, from_=0, to=10, width=5)
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_13.jpg)

接下来，我们添加另一个属性来进一步自定义我们的小部件，`bd`是`borderwidth`属性的简写表示。

```py
spin = Spinbox(monty, from_=0, to=10, width=5 , bd=8)
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_14.jpg)

在这里，我们通过创建回调并将其链接到控件来为小部件添加功能。

这将把 Spinbox 的选择打印到`ScrolledText`中，也打印到标准输出。名为`scr`的变量是我们对`ScrolledText`小部件的引用。

```py
# Spinbox callback 
def _spin():
    value = spin.get()
    print(value)
    scr.insert(tk.INSERT, value + '\n')

spin = Spinbox(monty, from_=0, to=10, width=5, bd=8, command=_spin)
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_15.jpg)

除了使用范围，我们还可以指定一组值。

```py
# Adding a Spinbox widget using a set of values
spin = Spinbox(monty, values=(1, 2, 4, 42, 100), width=5, bd=8, command=_spin) 
spin.grid(column=0, row=2)
```

这将创建以下 GUI 输出：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_16.jpg)

## 它是如何工作的...

请注意，在第一个屏幕截图中，我们的新`Spinbox`控件默认为宽度 20，推出了此列中所有控件的列宽。这不是我们想要的。我们给小部件一个从 0 到 10 的范围，并且默认显示`to=10`值，这是最高值。如果我们尝试将`from_/to`范围从 10 到 0 反转，tkinter 不会喜欢。请自行尝试。

在第二个屏幕截图中，我们减小了`Spinbox`控件的宽度，这使其与列的中心对齐。

在第三个屏幕截图中，我们添加了 Spinbox 的`borderwidth`属性，这自动使整个`Spinbox`看起来不再是平的，而是三维的。

在第四个屏幕截图中，我们添加了一个回调函数，以显示在`ScrolledText`小部件中选择的数字，并将其打印到标准输出流中。我们添加了“\n”以打印在新行上。请注意默认值不会被打印。只有当我们单击控件时，回调函数才会被调用。通过单击默认为 10 的向上箭头，我们可以打印值“10”。

最后，我们将限制可用的值为硬编码集。这也可以从数据源（例如文本或 XML 文件）中读取。

# 小部件的 Relief、sunken 和 raised 外观

我们可以通过一个属性来控制`Spinbox`小部件的外观，使它们看起来是凸起的、凹陷的，或者是凸起的格式。

## 准备工作

我们将添加一个`Spinbox`控件来演示`Spinbox`控件的`relief`属性的可用外观。

## 如何做...

首先，让我们增加`borderwidth`以区分我们的第二个`Spinbox`和第一个`Spinbox`。

```py
# Adding a second Spinbox widget 
spin = Spinbox(monty, values=(0, 50, 100), width=5, bd=20, command=_spin) 
spin.grid(column=1, row=2)
```

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_17.jpg)

我们上面的两个 Spinbox 小部件具有相同的`relief`样式。唯一的区别是，我们右边的新小部件的边框宽度要大得多。

在我们的代码中，我们没有指定使用哪个`relief`属性，所以`relief`默认为`tk.SUNKEN`。

以下是可以设置的可用`relief`属性选项：

| tk.SUNKEN | tk.RAISED | tk.FLAT | tk.GROOVE | tk.RIDGE |
| --- | --- | --- | --- | --- |

通过将不同的可用选项分配给`relief`属性，我们可以为这个小部件创建不同的外观。

将`tk.RIDGE`的`relief`属性分配给它，并将边框宽度减小到与我们的第一个`Spinbox`小部件相同的值，结果如下 GUI 所示：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_18.jpg)

## 它是如何工作的...

首先，我们创建了一个第二个`Spinbox`，对齐到第二列（索引==1）。它默认为`SUNKEN`，所以它看起来类似于我们的第一个`Spinbox`。我们通过增加第二个控件（右边的控件）的边框宽度来区分这两个小部件。

接下来，我们隐式地设置了`Spinbox`小部件的`relief`属性。我们使边框宽度与我们的第一个`Spinbox`相同，因为通过给它一个不同的`relief`，不需要改变任何其他属性，差异就变得可见了。

# 使用 Python 创建工具提示

这个示例将向我们展示如何创建工具提示。当用户将鼠标悬停在小部件上时，将以工具提示的形式提供额外的信息。

我们将把这些额外的信息编码到我们的 GUI 中。

## 准备工作

我们正在为我们的 GUI 添加更多有用的功能。令人惊讶的是，向我们的控件添加工具提示应该很简单，但实际上并不像我们希望的那样简单。

为了实现这种期望的功能，我们将把我们的工具提示代码放入自己的面向对象编程类中。

## 如何做...

在导入语句的下面添加这个类：

```py
class ToolTip(object):
    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        "Display text in tooltip window"
        self.text = text
        if self.tipwindow or not self.text:
            return
        x, y, _cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 27
        y = y + cy + self.widget.winfo_rooty() +27
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))

        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
   background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                      font=("tahoma", "8", "normal"))

        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

#===========================================================
def createToolTip( widget, text):
    toolTip = ToolTip(widget)
    def enter(event):
        toolTip.showtip(text)
    def leave(event):
        toolTip.hidetip()
    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)
```

在**面向对象编程**（**OOP**）方法中，我们在 Python 模块中创建一个新的类。Python 允许我们将多个类放入同一个 Python 模块中，并且还可以在同一个模块中“混合和匹配”类和常规函数。

上面的代码正在做这个。

`ToolTip`类是一个 Python 类，为了使用它，我们必须实例化它。

如果你不熟悉面向对象的编程，“实例化一个对象以创建类的实例”可能听起来相当无聊。

这个原则非常简单，非常类似于通过`def`语句创建一个 Python 函数，然后在代码中稍后调用这个函数。

以非常相似的方式，我们首先创建一个类的蓝图，并通过在类的名称后面添加括号将其分配给一个变量：

```py
class AClass():
    pass
instanceOfAClass = AClass()
print(instanceOfAClass)
```

上面的代码打印出一个内存地址，并且显示我们的变量现在引用了这个类实例。

面向对象编程的很酷的一点是，我们可以创建同一个类的许多实例。

在我们之前的代码中，我们声明了一个 Python 类，并明确地让它继承自所有 Python 类的基础对象。我们也可以将其省略，就像我们在`AClass`代码示例中所做的那样，因为它是所有 Python 类的默认值。

在`ToolTip`类中发生的所有必要的工具提示创建代码之后，我们接下来转到非面向对象的 Python 编程，通过在其下方创建一个函数。

我们定义了函数`createToolTip()`，它期望我们的 GUI 小部件之一作为参数传递进来，这样当我们将鼠标悬停在这个控件上时，我们就可以显示一个工具提示。

`createToolTip()`函数实际上为我们为每个调用它的小部件创建了`ToolTip`类的一个新实例。

我们可以为我们的 Spinbox 小部件添加一个工具提示，就像这样：

```py
# Add a Tooltip
createToolTip(spin, 'This is a Spin control.')
```

以及我们所有其他 GUI 小部件的方式完全相同。我们只需传入我们希望显示一些额外信息的工具提示的小部件的父级。对于我们的 ScrolledText 小部件，我们使变量`scr`指向它，所以这就是我们传递给我们的 ToolTip 创建函数构造函数的内容。

```py
# Using a scrolled Text control    
scrolW  = 30; scrolH  =  3
scr = scrolledtext.ScrolledText(monty, width=scrolW, height=scrolH, wrap=tk.WORD)
scr.grid(column=0, row=3, sticky='WE', columnspan=3)

# Add a Tooltip to the ScrolledText widget
createToolTip(scr, 'This is a ScrolledText widget.')
```

## 它是如何工作的...

这是本书中面向对象编程的开始。这可能看起来有点高级，但不用担心，我们会解释一切，它确实有效！

嗯，实际上运行这段代码并没有起作用，也没有任何区别。

在创建微调器之后，添加以下代码：

```py
# Add a Tooltip
createToolTip(spin, 'This is a Spin control.')
```

现在，当我们将鼠标悬停在微调小部件上时，我们会得到一个工具提示，为用户提供额外的信息。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_19.jpg)

我们调用创建工具提示的函数，然后将对小部件的引用和我们希望在悬停鼠标在小部件上时显示的文本传递进去。

本书中的其余示例将在合适的情况下使用面向对象编程。在这里，我们展示了可能的最简单的面向对象编程示例。作为默认，我们创建的每个 Python 类都继承自`object`基类。作为一个真正的务实的编程语言，Python 简化了类的创建过程。

我们可以写成这样：

```py
class ToolTip(object):
    pass
```

我们也可以通过省略默认的基类来简化它：

```py
class ToolTip():
    pass
```

在同样的模式中，我们可以继承和扩展任何 tkinter 类。

# 如何使用画布小部件

这个示例展示了如何通过使用 tkinter 画布小部件为我们的 GUI 添加戏剧性的颜色效果。

## 准备工作

通过为其添加更多的颜色，我们将改进我们先前的代码和 GUI 的外观。

## 如何做...

首先，我们将在我们的 GUI 中创建第三个选项卡，以便隔离我们的新代码。

以下是创建新的第三个选项卡的代码：

```py
# Tab Control introduced here --------------------------------
tabControl = ttk.Notebook(win)          # Create Tab Control

tab1 = ttk.Frame(tabControl)            # Create a tab 
tabControl.add(tab1, text='Tab 1')      # Add the tab

tab2 = ttk.Frame(tabControl)            # Add a second tab
tabControl.add(tab2, text='Tab 2')      # Make second tab visible

tab3 = ttk.Frame(tabControl)            # Add a third tab
tabControl.add(tab3, text='Tab 3')      # Make second tab visible

tabControl.pack(expand=1, fill="both")  # Pack to make visible
# ~ Tab Control introduced here -------------------------------
```

接下来，我们使用 tkinter 的另一个内置小部件，即画布。很多人喜欢这个小部件，因为它具有强大的功能。

```py
# Tab Control 3 -------------------------------
tab3 = tk.Frame(tab3, bg='blue')
tab3.pack()
for orangeColor in range(2):
    canvas = tk.Canvas(tab3, width=150, height=80, highlightthickness=0, bg='orange')
    canvas.grid(row=orangeColor, column=orangeColor)
```

## 它是如何工作的...

以下屏幕截图显示了通过运行上述代码并单击新的**Tab 3**创建的结果。当你运行代码时，它真的是橙色和蓝色的。在这本无色的书中，这可能不太明显，但这些颜色是真实的；你可以相信我。

您可以通过在线搜索来查看绘图和绘制功能。我不会在这本书中深入探讨这个小部件（但它确实很酷）。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_03_20.jpg)


# 第四章：数据和类

在本章中，我们将使用 Python 3 来使用数据和 OOP 类：

+   如何使用 StringVar()

+   如何从小部件获取数据

+   使用模块级全局变量

+   如何在类中编码可以改进 GUI

+   编写回调函数

+   创建可重用的 GUI 组件

# 介绍

在本章中，我们将把 GUI 数据保存到 tkinter 变量中。

我们还将开始使用**面向对象编程**（**OOP**）来扩展现有的 tkinter 类，以扩展 tkinter 的内置功能。这将使我们创建可重用的 OOP 组件。

# 如何使用 StringVar()

在 tkinter 中有一些内置的编程类型，它们与我们习惯用 Python 编程的类型略有不同。StringVar()就是这些 tkinter 类型之一。

这个示例将向您展示如何使用 StringVar()类型。

## 准备工作

我们正在学习如何将 tkinter GUI 中的数据保存到变量中，以便我们可以使用这些数据。我们可以设置和获取它们的值，与 Java 的 getter/setter 方法非常相似。

这里是 tkinter 中可用的一些编码类型：

| `strVar = StringVar()` | # 保存一个字符串；默认值是一个空字符串"" |
| --- | --- |
| `intVar = IntVar()` | # 保存一个整数；默认值是 0 |
| `dbVar = DoubleVar()` | # 保存一个浮点数；默认值是 0.0 |
| `blVar = BooleanVar()` | # 保存一个布尔值，对于 false 返回 0，对于 true 返回 1 |

### 注意

不同的语言称带有小数点的数字为浮点数或双精度数。Tkinter 将 Python 中称为浮点数据类型的内容称为 DoubleVar。根据精度级别，浮点数和双精度数据可能不同。在这里，我们将 tkinter 的 DoubleVar 翻译成 Python 中的 Python 浮点类型。

## 如何做...

我们正在创建一个新的 Python 模块，下面的截图显示了代码和生成的输出：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_01.jpg)

首先，我们导入 tkinter 模块并将其别名为`tk`。

接下来，我们使用这个别名通过在`Tk`后面加括号来创建`Tk`类的一个实例，这样就调用了类的构造函数。这与调用函数的机制相同，只是这里我们创建了一个类的实例。

通常我们使用分配给变量`win`的实例来在代码中稍后启动主事件循环。但是在这里，我们不显示 GUI，而是演示如何使用 tkinter 的 StringVar 类型。

### 注意

我们仍然必须创建`Tk()`的一个实例。如果我们注释掉这一行，我们将从 tkinter 得到一个错误，因此这个调用是必要的。

然后我们创建一个 tkinter StringVar 类型的实例，并将其分配给我们的 Python`strData`变量。

之后，我们使用我们的变量调用 StringVar 的`set()`方法，并在设置为一个值后，然后获取该值并将其保存在一个名为`varData`的新变量中，然后打印出它的值。

在 Eclipse PyDev 控制台中，可以看到输出打印到控制台的底部，这是**Hello StringVar**。

接下来，我们将打印 tkinter 的 IntVar、DoubleVar 和 BooleanVar 类型的默认值。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_02.jpg)

## 它是如何工作的...

如前面的截图所示，默认值并没有像我们预期的那样被打印出来。

在线文献提到了默认值，但在调用它们的`get`方法之前，我们不会看到这些值。否则，我们只会得到一个自动递增的变量名（例如在前面的截图中可以看到的 PY_VAR3）。

将 tkinter 类型分配给 Python 变量并不会改变结果。我们仍然没有得到默认值。

在这里，我们专注于最简单的代码（创建 PY_VAR0）：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_03.jpg)

该值是 PY_VAR0，而不是预期的 0，直到我们调用`get`方法。现在我们可以看到默认值。我们没有调用`set`，所以一旦我们在每种类型上调用`get`方法，就会看到自动分配给每种 tkinter 类型的默认值。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_04.jpg)

注意`IntVar`实例的默认值为 0 被打印到控制台，我们将其保存在`intData`变量中。我们还可以在屏幕截图的顶部看到 Eclipse PyDev 调试器窗口中的值。

# 如何从小部件中获取数据

当用户输入数据时，我们希望在我们的代码中对其进行处理。这个配方展示了如何在变量中捕获数据。在上一个配方中，我们创建了几个 tkinter 类变量。它们是独立的。现在我们正在将它们连接到我们的 GUI，使用我们从 GUI 中获取的数据并将其存储在 Python 变量中。

## 准备工作

我们将继续使用我们在上一章中构建的 Python GUI。

## 如何做...

我们正在将来自我们的 GUI 的值分配给一个 Python 变量。

在我们的模块底部，就在主事件循环之上，添加以下代码：

```py
strData = spin.get()
print("Spinbox value: " + strData)

# Place cursor into name Entry
nameEntered.focus()      
#======================
# Start GUI
#======================
win.mainloop()
```

运行代码会给我们以下结果：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_05.jpg)

我们正在检索`Spinbox`控件的当前值。

### 注意

我们将我们的代码放在 GUI 主事件循环之上，因此打印发生在 GUI 变得可见之前。如果我们想要在显示 GUI 并改变`Spinbox`控件的值之后打印出当前值，我们将不得不将代码放在回调函数中。

我们使用以下代码创建了我们的 Spinbox 小部件，将可用值硬编码到其中：

```py
# Adding a Spinbox widget using a set of values
spin = Spinbox(monty, values=(1, 2, 4, 42, 100), width=5, bd=8, command=_spin) 
spin.grid(column=0, row=2)
```

我们还可以将数据的硬编码从`Spinbox`类实例的创建中移出，并稍后设置它。

```py
# Adding a Spinbox widget assigning values after creation
spin = Spinbox(monty, width=5, bd=8, command=_spin) 
spin['values'] = (1, 2, 4, 42, 100)
spin.grid(column=0, row=2)
```

无论我们如何创建小部件并将数据插入其中，因为我们可以通过在小部件实例上使用`get()`方法来访问这些数据，所以我们可以访问这些数据。

## 它是如何工作的...

为了从使用 tkinter 编写的 GUI 中获取值，我们使用 tkinter 的`get()`方法来获取我们希望获取值的小部件的实例。

在上面的例子中，我们使用了 Spinbox 控件，但对于所有具有`get()`方法的小部件，原理是相同的。

一旦我们获得了数据，我们就处于一个纯粹的 Python 世界，而 tkinter 确实帮助我们构建了我们的 GUI。现在我们知道如何从我们的 GUI 中获取数据，我们可以使用这些数据。

# 使用模块级全局变量

封装是任何编程语言中的一个主要优势，它使我们能够使用 OOP 进行编程。Python 既是 OOP 又是过程化的。我们可以创建局部化到它们所在模块的全局变量。它们只对这个模块全局，这是一种封装的形式。为什么我们想要这样做？因为随着我们向我们的 GUI 添加越来越多的功能，我们希望避免命名冲突，这可能导致我们代码中的错误。

### 注意

我们不希望命名冲突在我们的代码中创建错误！命名空间是避免这些错误的一种方法，在 Python 中，我们可以通过使用 Python 模块（这些是非官方的命名空间）来实现这一点。

## 准备工作

我们可以在任何模块的顶部和函数之外声明模块级全局变量。

然后我们必须使用`global` Python 关键字来引用它们。如果我们在函数中忘记使用`global`，我们将意外创建新的局部变量。这将是一个错误，而且是我们真的不想做的事情。

### 注意

Python 是一种动态的、强类型的语言。我们只会在运行时注意到这样的错误（忘记使用全局关键字来限定变量的范围）。

## 如何做...

将第 15 行中显示的代码添加到我们在上一章和上一章中使用的 GUI 中，这将创建一个模块级的全局变量。我们使用了 C 风格的全大写约定，这并不真正“Pythonic”，但我认为这确实强调了我们在这个配方中要解决的原则。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_06.jpg)

运行代码会导致全局变量的打印。注意**42**被打印到 Eclipse 控制台。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_07.jpg)

## 它是如何工作的...

我们在我们的模块顶部定义一个全局变量，稍后，在我们的模块底部，我们打印出它的值。

那起作用。

在我们的模块底部添加这个函数：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_08.jpg)

在上面，我们正在使用模块级全局变量。很容易出错，因为`global`被遮蔽，如下面的屏幕截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_09.jpg)

请注意，即使我们使用相同的变量名，`42`也变成了`777`。

### 注意

Python 中没有编译器警告我们在本地函数中覆盖全局变量。这可能导致在运行时调试时出现困难。

使用全局限定符（第 234 行）打印出我们最初分配的值（42），如下面的屏幕截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_10.jpg)

但是，要小心。当我们取消本地全局时，我们打印出本地的值，而不是全局的值：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_11.jpg)

尽管我们使用了`global`限定符，但本地变量似乎会覆盖它。我们从 Eclipse PyDev 插件中得到了一个警告，即我们的`GLOBAL_CONST = 777`没有被使用，但运行代码仍然打印出 777，而不是预期的 42。

这可能不是我们期望的行为。使用`global`限定符，我们可能期望指向先前创建的全局变量。

相反，似乎 Python 在本地函数中创建了一个新的全局变量，并覆盖了我们之前创建的全局变量。

全局变量在编写小型应用程序时非常有用。它们可以帮助在同一 Python 模块中的方法和函数之间共享数据，并且有时 OOP 的开销是不合理的。

随着我们的程序变得越来越复杂，使用全局变量所获得的好处很快就会减少。

### 注意

最好避免使用全局变量，并通过在不同范围中使用相同的名称而意外地遮蔽变量。我们可以使用面向对象编程来代替使用全局变量。

我们在过程化代码中玩了全局变量，并学会了如何导致难以调试的错误。在下一章中，我们将转向面向对象编程，这可以消除这些类型的错误。

# 如何在类中编码可以改进 GUI

到目前为止，我们一直在以过程化的方式编码。这是来自 Python 的一种快速脚本化方法。一旦我们的代码变得越来越大，我们就需要进步到面向对象编程。

为什么？

因为，除了许多其他好处之外，面向对象编程允许我们通过使用方法来移动代码。一旦我们使用类，我们就不再需要在调用代码的代码上方物理放置代码。这使我们在组织代码方面具有很大的灵活性。

我们可以将相关代码写在其他代码旁边，不再担心代码不会运行，因为代码不在调用它的代码上方。

我们可以通过编写引用未在该模块中创建的方法的模块来将其推向一些相当花哨的极端。它们依赖于运行时状态在代码运行时创建了这些方法。

### 注意

如果我们调用的方法在那时还没有被创建，我们会得到一个运行时错误。

## 准备就绪

我们只需将整个过程化代码简单地转换为面向对象编程。我们只需将其转换为一个类，缩进所有现有代码，并在所有变量之前添加`self`。

这非常容易。

虽然起初可能感觉有点烦人，必须在所有东西之前加上`self`关键字，使我们的代码更冗长（嘿，我们浪费了这么多纸...）；但最终，这将是值得的。

## 如何做...

一开始，一切都乱了，但我们很快就会解决这个明显的混乱。

请注意，在 Eclipse 中，PyDev 编辑器通过在代码编辑器的右侧部分将其标记为红色来提示编码问题。

也许我们毕竟不应该使用面向对象编程，但这就是我们所做的，而且理由非常充分。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_12.jpg)

我们只需使用`self`关键字在所有变量之前添加，并通过使用`self`将函数绑定到类中，这样官方和技术上将函数转换为方法。

### 注意

函数和方法之间有区别。Python 非常清楚地表明了这一点。方法绑定到一个类，而函数则没有。我们甚至可以在同一个 Python 模块中混合使用这两种方法。

让我们用`self`作为前缀来消除红色，这样我们就可以再次运行我们的代码。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_13.jpg)

一旦我们对所有在红色中突出显示的错误做了这些，我们就可以再次运行我们的 Python 代码。

`clickMe`函数现在绑定到类上，正式成为一个方法。

不幸的是，以过程式方式开始，然后将其转换为面向对象的方式并不像我上面说的那么简单。代码变得一团糟。这是以面向对象的方式开始编程的一个很好的理由。

### 注意

Python 擅长以简单的方式做事。简单的代码通常变得更加复杂（因为一开始很容易）。一旦变得过于复杂，将我们的过程式代码重构为真正的面向对象的代码变得越来越困难。

我们正在将我们的过程式代码转换为面向对象的代码。看看我们陷入的所有麻烦，仅仅将 200 多行的 Python 代码转换为面向对象的代码可能表明，我们可能最好从一开始就开始使用面向对象的方式编码。

实际上，我们确实破坏了一些之前工作正常的功能。现在无法使用 Tab 2 和点击单选按钮了。我们必须进行更多的重构。

过程式代码之所以容易，是因为它只是从上到下的编码。现在我们把我们的代码放入一个类中，我们必须把所有的回调函数移到方法中。这样做是可以的，但确实需要一些工作来转换我们的原始代码。

我们的过程式代码看起来像这样：

```py
# Button Click Function
def clickMe():
    action.configure(text='Hello ' + name.get())

# Changing our Label
ttk.Label(monty, text="Enter a name:").grid(column=0, row=0, sticky='W')

# Adding a Textbox Entry widget
name = tk.StringVar()
nameEntered = ttk.Entry(monty, width=12, textvariable=name)
nameEntered.grid(column=0, row=1, sticky='W')

# Adding a Button
action = ttk.Button(monty, text="Click Me!", command=clickMe)
action.grid(column=2, row=1)

The new OOP code looks like this:
class OOP():
    def __init__(self): 
        # Create instance
        self.win = tk.Tk()   

        # Add a title       
        self.win.title("Python GUI")      
        self.createWidgets()

    # Button callback
    def clickMe(self):
        self.action.configure(text='Hello ' + self.name.get())

    # … more callback methods 

    def createWidgets(self):    
        # Tab Control introduced here -----------------------
        tabControl = ttk.Notebook(self.win)     # Create Tab Control

        tab1 = ttk.Frame(tabControl)            # Create a tab 
        tabControl.add(tab1, text='Tab 1')      # Add the tab

        tab2 = ttk.Frame(tabControl)            # Create second tab
        tabControl.add(tab2, text='Tab 2')      # Add second tab 

        tabControl.pack(expand=1, fill="both")  # Pack make visible
#======================
# Start GUI
#======================
oop = OOP()
oop.win.mainloop()
```

我们将回调方法移到模块顶部，放在新的面向对象类内部。我们将所有的部件创建代码放入一个相当长的方法中，在类的初始化器中调用它。

从技术上讲，在低级代码的深处，Python 确实有一个构造函数，但 Python 让我们摆脱了对此的任何担忧。这已经为我们处理了。

相反，除了一个“真正的”构造函数之外，Python 还为我们提供了一个初始化器。

我们强烈建议使用这个初始化器。我们可以用它来向我们的类传递参数，初始化我们希望在类实例内部使用的变量。

### 注意

在 Python 中，同一个 Python 模块中可以存在多个类。

与 Java 不同，它有一个非常严格的命名约定（没有这个约定它就无法工作），Python 要灵活得多。

### 注意

我们可以在同一个 Python 模块中创建多个类。与 Java 不同，我们不依赖于必须与每个类名匹配的文件名。

Python 真的很棒！

一旦我们的 Python GUI 变得庞大，我们将把一些类拆分成它们自己的模块，但与 Java 不同，我们不必这样做。在这本书和项目中，我们将保持一些类在同一个模块中，同时，我们将把一些其他类拆分成它们自己的模块，将它们导入到可以被认为是一个 main()函数的地方（这不是 C，但我们可以像 C 一样思考，因为 Python 非常灵活）。

到目前为止，我们所做的是将`ToolTip`类添加到我们的 Python 模块中，并将我们的过程式 Python 代码重构为面向对象的 Python 代码。

在这里，在这个示例中，我们可以看到一个 Python 模块中可以存在多个类。

确实很酷！

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_14.jpg)

`ToolTip`类和`OOP`类都驻留在同一个 Python 模块中。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_15.jpg)

## 它是如何工作的...

在这个示例中，我们将我们的过程式代码推进到面向对象编程（OOP）代码。

Python 使我们能够以实用的过程式风格编写代码，就像 C 编程语言一样。

与此同时，我们有选择以面向对象的方式编码，就像 Java、C#和 C++一样。

# 编写回调函数

起初，回调函数可能看起来有点令人生畏。您调用函数，传递一些参数，现在函数告诉您它真的很忙，会回电话给您！

你会想：“这个函数会*永远*回调我吗？”“我需要*等*多久？”

在 Python 中，即使回调函数也很容易，是的，它们通常会回调你。

它们只需要先完成它们分配的任务（嘿，是你编码它们的第一次...）。

让我们更多地了解一下当我们将回调编码到我们的 GUI 中时会发生什么。

我们的 GUI 是事件驱动的。在创建并显示在屏幕上之后，它通常会等待事件发生。它基本上在等待事件被发送到它。我们可以通过点击其动作按钮之一来向我们的 GUI 发送事件。

这创建了一个事件，并且在某种意义上，我们通过发送消息“调用”了我们的 GUI。

现在，我们发送消息到我们的 GUI 后应该发生什么？

点击按钮后发生的事情取决于我们是否创建了事件处理程序并将其与此按钮关联。如果我们没有创建事件处理程序，点击按钮将没有任何效果。

事件处理程序是一个回调函数（或方法，如果我们使用类）。

回调方法也是被动的，就像我们的 GUI 一样，等待被调用。

一旦我们的 GUI 被点击按钮，它将调用回调函数。

回调通常会进行一些处理，完成后将结果返回给我们的 GUI。

### 注意

在某种意义上，我们可以看到我们的回调函数在回调我们的 GUI。

## 准备就绪

Python 解释器会运行项目中的所有代码一次，找到任何语法错误并指出它们。如果语法不正确，您无法运行 Python 代码。这包括缩进（如果不导致语法错误，错误的缩进通常会导致错误）。

在下一轮解析中，解释器解释我们的代码并运行它。

在运行时，可以生成许多 GUI 事件，通常是回调函数为 GUI 小部件添加功能。

## 如何做...

这是 Spinbox 小部件的回调：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_16.jpg)

## 它是如何工作的...

我们在`OOP`类中创建了一个回调方法，当我们从 Spinbox 小部件中选择一个值时，它会被调用，因为我们通过`command`参数（`command=self._spin`）将该方法绑定到小部件。我们使用下划线前缀来暗示这个方法应该像一个私有的 Java 方法一样受到尊重。

Python 故意避免了私有、公共、友好等语言限制。

在 Python 中，我们使用命名约定。预期用双下划线包围关键字的前后缀应该限制在 Python 语言中，我们不应该在我们自己的 Python 代码中使用它们。

但是，我们可以使用下划线前缀来提供一个提示，表明这个名称应该被视为私有助手。

与此同时，如果我们希望使用本来是 Python 内置名称的名称，我们可以在后面加上一个下划线。例如，如果我们希望缩短列表的长度，我们可以这样做：

```py
len_ = len(aList)
```

通常，下划线很难阅读，容易忽视，因此在实践中这可能不是最好的主意。

# 创建可重用的 GUI 组件

我们正在使用 Python 创建可重用的 GUI 组件。

在这个示例中，我们将简化操作，将我们的`ToolTip`类移动到其自己的模块中。接下来，我们将导入并在 GUI 的几个小部件上使用它来显示工具提示。

## 准备就绪

我们正在构建我们之前的代码。

## 如何做...

我们将首先将我们的`ToolTip`类拆分为一个单独的 Python 模块。我们将稍微增强它，以便传入控件小部件和我们希望在悬停鼠标在控件上时显示的工具提示文本。

我们创建了一个新的 Python 模块，并将`ToolTip`类代码放入其中，然后将此模块导入我们的主要模块。

然后，我们通过创建几个工具提示来重用导入的`ToolTip`类，当鼠标悬停在几个 GUI 小部件上时可以看到它们。

将我们通用的`ToolTip`类代码重构到自己的模块中有助于我们重用这些代码。我们使用 DRY 原则，将我们的通用代码放在一个地方，这样当我们修改代码时，导入它的所有模块将自动获得我们模块的最新版本，而不是复制/粘贴/修改。

### 注意

DRY 代表不要重复自己，我们将在以后的章节中再次讨论它。

我们可以通过将选项卡 3 的图像转换为可重用组件来做类似的事情。

为了保持本示例的代码简单，我们删除了选项卡 3，但您可以尝试使用上一章的代码进行实验。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_17.jpg)

```py

# Add a Tooltip to the Spinbox
tt.createToolTip(self.spin, 'This is a Spin control.')

# Add Tooltips to more widgets
tt.createToolTip(nameEntered, 'This is an Entry control.')
tt.createToolTip(self.action, 'This is a Button control.')
tt.createToolTip(self.scr, 'This is a ScrolledText control.')
```

这也适用于第二个选项卡。

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_18.jpg)

新的代码结构现在看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_19.jpg)

导入语句如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_20.jpg)

而在单独的模块中分解（重构）的代码如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-gui-prog-cb/img/B04829_04_21.jpg)

## 工作原理...

在前面的屏幕截图中，我们可以看到显示了几条工具提示消息。主窗口的工具提示可能有点烦人，所以最好不要为主窗口显示工具提示，因为我们真的希望突出显示各个小部件的功能。主窗体有一个解释其目的的标题；不需要工具提示。
