# Tkinter GUI 应用开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/398a043f4e87ae54140cbfe923282feb`](https://zh.annas-archive.org/md5/398a043f4e87ae54140cbfe923282feb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

作为一种更多用途的编程语言之一，Python 以其“电池包含”哲学而闻名，其中包括其标准库中丰富的模块集；Tkinter 是用于构建桌面应用程序的库。Tkinter 是建立在 Tk GUI 工具包之上的，是快速 GUI 开发的常见选择，复杂的应用程序可以从该库的全部功能中受益。本书涵盖了 Tkinter 和 Python GUI 开发的所有问题和解决方案。

*Tkinter GUI 应用程序开发食谱*首先概述了 Tkinter 类，同时提供了有关基本主题的示例，例如布局模式和事件处理。接下来，本书介绍了如何开发常见的 GUI 模式，例如输入和保存数据，通过菜单和对话框导航，以及在后台执行长时间操作。然后，您可以使您的应用程序有效地利用网络资源，并在画布上执行图形操作以及相关任务，例如检测项目之间的碰撞。最后，本书介绍了使用主题小部件，这是 Tk 小部件的扩展，具有更本地的外观和感觉。

通过本书，您将深入了解 Tkinter 类，并知道如何使用它们构建高效和丰富的 GUI 应用程序。

# 这本书是为谁准备的

这本书的目标读者是熟悉 Python 语言基础知识（语法、数据结构和面向对象编程）的开发人员，希望学习 GUI 开发常见挑战的有效解决方案，并希望发现 Tkinter 可以提供的有趣功能，以构建复杂的应用程序。

您不需要有 Tkinter 或其他 GUI 开发库的先前经验，因为本书的第一部分将通过介绍性用例教授库的基础知识。

# 本书涵盖的内容

第一章，*开始使用 Tkinter*，介绍了 Tkinter 程序的结构，并向您展示如何执行最常见的任务，例如创建小部件和处理用户事件。

第二章，*窗口布局*，演示了如何使用几何管理器放置小部件并改进大型应用程序的布局。

第三章，*自定义小部件*，深入探讨了 Tkinter 小部件的配置和外观自定义。

第四章，*对话框和菜单*，教会您如何通过菜单和对话框改进 Tkinter 应用程序的导航。

第五章，*面向对象编程和 MVC*，教会您如何在 Tkinter 应用程序中有效应用设计模式。

第六章，*异步编程*，涵盖了执行长时间操作而不冻结应用程序的几个方法——这是 GUI 开发中经常出现的问题。

第七章，*画布和图形*，探索了画布小部件以及您可以添加到画布的项目类型以及如何操作它们。

第八章，*主题小部件*，教会您如何使用 Tk 主题小部件集扩展 Tkinter 应用程序。

# 充分利用本书

要开始并运行，用户需要安装以下技术：

+   Python 3.x

+   任何操作系统

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的软件解压或提取文件夹。

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Tkinter-GUI-Application-Development-Cookbook`](https://github.com/PacktPublishing/Tkinter-GUI-Application-Development-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/TkinterGUIApplicationDevelopmentCookbook_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/TkinterGUIApplicationDevelopmentCookbook_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子："`delete()`方法接受两个参数，指示应删除的字符范围。"

代码块设置如下：

```py
from tkinter import * 

root = Tk() 
btn = Button(root, text="Click me!") 
btn.config(command=lambda: print("Hello, Tkinter!"))
btn.pack(padx=120, pady=30)
root.title("My Tkinter app")
root.mainloop()
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```py
def show_caption(self, event):
    caption = tk.Label(self, ...)
    caption.place(in_=event.widget, x=event.x, y=event.y)
    # ...
```

**粗体**：表示一个新术语，一个重要单词，或者您在屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这是一个例子："第一个将被标记为选择文件。"

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：开始使用 Tkinter

在本章中，我们将涵盖以下内容：

+   构建 Tkinter 应用程序

+   使用按钮

+   创建文本输入

+   跟踪文本更改

+   验证文本输入

+   选择数值

+   使用单选按钮创建选择

+   使用复选框实现开关

+   显示项目列表

+   处理鼠标和键盘事件

+   设置主窗口的图标、标题和大小

# 介绍

由于其清晰的语法和广泛的库和工具生态系统，Python 已经成为一种流行的通用编程语言。从 Web 开发到自然语言处理（NLP），您可以轻松找到一个符合您应用领域需求的开源库，最后，您总是可以使用 Python 标准库中包含的任何模块。

标准库遵循“电池包含”哲学，这意味着它包含了大量的实用程序：正则表达式、数学函数、网络等。该库的标准图形用户界面（GUI）包是 Tkinter，它是 Tcl/Tk 的一个薄的面向对象的层。

从 Python 3 开始，`Tkinter`模块被重命名为`tkinter`（小写的 t）。它也影响到`tkinter.ttk`和`tkinter.tix`扩展。我们将在本书的最后一章深入探讨`tkinter.ttk`模块，因为`tkinter.tix`模块已经正式弃用。

在本章中，我们将探索`tkinter`模块的一些基本类的几种模式以及所有小部件子类共有的一些方法。

# 构建 Tkinter 应用程序

使用 Tkinter 制作应用程序的主要优势之一是，使用几行脚本非常容易设置基本 GUI。随着程序变得更加复杂，逻辑上分离每个部分变得更加困难，因此有组织的结构将帮助我们保持代码整洁。

# 准备工作

我们将以以下程序为例：

```py
from tkinter import * 

root = Tk() 
btn = Button(root, text="Click me!") 
btn.config(command=lambda: print("Hello, Tkinter!"))
btn.pack(padx=120, pady=30)
root.title("My Tkinter app")
root.mainloop()
```

它创建一个带有按钮的主窗口，每次点击按钮时都会在控制台中打印`Hello, Tkinter!`。按钮在水平轴上以 120px 的填充和垂直轴上以 30px 的填充放置。最后一条语句启动主循环，处理用户事件并更新 GUI，直到主窗口被销毁：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/0b2f562d-e318-40c4-9a0c-2190012897ce.png)

您可以执行该程序并验证它是否按预期工作。但是，所有我们的变量都是在全局命名空间中定义的，添加的小部件越多，理清它们的使用部分就变得越困难。

在生产代码中，强烈不建议使用通配符导入（`from ... import *`），因为它们会污染全局命名空间——我们只是在这里使用它们来说明一个常见的反模式，这在在线示例中经常见到。

这些可维护性问题可以通过基本的面向对象编程技术来解决，在所有类型的 Python 程序中都被认为是良好的实践。

# 如何做...

为了改进我们简单程序的模块化，我们将定义一个包装我们全局变量的类：

```py
import tkinter as tk 

class App(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        self.btn = tk.Button(self, text="Click me!", 
                             command=self.say_hello) 
        self.btn.pack(padx=120, pady=30) 

    def say_hello(self): 
        print("Hello, Tkinter!") 

if __name__ == "__main__": 
    app = App() 
    app.title("My Tkinter app") 
    app.mainloop()
```

现在，每个变量都被封装在特定的范围内，包括`command`函数，它被移动为一个单独的方法。

# 工作原理...

首先，我们用`import ... as`语法替换了通配符导入，以便更好地控制我们的全局命名空间。

然后，我们将我们的`App`类定义为`Tk`子类，现在通过`tk`命名空间引用。为了正确初始化基类，我们将使用内置的`super()`函数调用`Tk`类的`__init__`方法。这对应以下行：

```py
class App(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        # ... 
```

现在，我们有了对`App`实例的引用，使用`self`变量，所以我们将把所有的按钮小部件作为我们类的属性添加。

虽然对于这样一个简单的程序来说可能看起来有点过度，但这种重构将帮助我们理清每个部分，按钮实例化与单击时执行的回调分开，应用程序引导被移动到`if __name__ == "__main__"`块中，这是可执行 Python 脚本中的常见做法。

我们将遵循这个约定通过所有的代码示例，所以您可以将这个模板作为任何更大应用程序的起点。

# 还有更多...

在我们的示例中，我们对`Tk`类进行了子类化，但通常也会对其他小部件类进行子类化。我们这样做是为了重现在重构代码之前的相同语句。

然而，在更大的程序中，比如有多个窗口的程序中，可能更方便地对`Frame`或`Toplevel`进行子类化。这是因为 Tkinter 应用程序应该只有一个`Tk`实例，如果在创建`Tk`实例之前实例化小部件，系统会自动创建一个`Tk`实例。

请记住，这个决定不会影响我们的`App`类的结构，因为所有的小部件类都有一个`mainloop`方法，它在内部启动`Tk`主循环。

# 使用按钮

按钮小部件表示 GUI 应用程序中可点击的项目。它们通常使用文本或指示单击时将执行的操作的图像。Tkinter 允许您使用`Button`小部件类的一些标准选项轻松配置此功能。

# 如何做...

以下包含一个带有图像的按钮，单击后会被禁用，并带有不同类型可用的 relief 的按钮列表：

```py
import tkinter as tk 

RELIEFS = [tk.SUNKEN, tk.RAISED, tk.GROOVE, tk.RIDGE, tk.FLAT] 

class ButtonsApp(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        self.img = tk.PhotoImage(file="python.gif") 
        self.btn = tk.Button(self, text="Button with image", 
                             image=self.img, compound=tk.LEFT, 
                             command=self.disable_btn) 
        self.btns = [self.create_btn(r) for r in RELIEFS]         
        self.btn.pack() 
        for btn in self.btns: 
            btn.pack(padx=10, pady=10, side=tk.LEFT) 

    def create_btn(self, relief): 
        return tk.Button(self, text=relief, relief=relief) 

    def disable_btn(self): 
        self.btn.config(state=tk.DISABLED) 

if __name__ == "__main__": 
    app = ButtonsApp() 
    app.mainloop()
```

这个程序的目的是显示在创建按钮小部件时可以使用的几个配置选项。

在执行上述代码后，您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/972eaa5e-75fd-46c8-88be-f6fc9b648bb5.png)

# 它是如何工作的...

`Button`实例化的最基本方法是使用`text`选项设置按钮标签和引用在按钮被点击时要调用的函数的`command`选项。

在我们的示例中，我们还通过`image`选项添加了`PhotoImage`，它优先于*text*字符串。`compound`选项用于在同一个按钮中组合图像和文本，确定图像放置的位置。它接受以下常量作为有效值：`CENTER`、`BOTTOM`、`LEFT`、`RIGHT`和`TOP`。

第二行按钮是用列表推导式创建的，使用了`RELIEF`值的列表。每个按钮的标签对应于常量的名称，因此您可以注意到每个按钮外观上的差异。

# 还有更多...

我们使用了一个属性来保留对我们的`PhotoImage`实例的引用，即使我们在`__init__`方法之外没有使用它。原因是图像在垃圾收集时会被清除，如果我们将其声明为局部变量并且方法存在，则会发生这种情况。

为了避免这种情况，始终记住在窗口仍然存在时保留对每个`PhotoImage`对象的引用。

# 创建文本输入框

Entry 小部件表示以单行显示的文本输入。它与`Label`和`Button`类一样，是 Tkinter 类中最常用的类之一。

# 如何做...

这个示例演示了如何创建一个登录表单，其中有两个输入框实例用于`username`和`password`字段。`password`的每个字符都显示为星号，以避免以明文显示它：

```py
import tkinter as tk 

class LoginApp(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        self.username = tk.Entry(self) 
        self.password = tk.Entry(self, show="*") 
        self.login_btn = tk.Button(self, text="Log in", 
                                   command=self.print_login) 
        self.clear_btn = tk.Button(self, text="Clear", 
                                   command=self.clear_form)         
        self.username.pack() 
        self.password.pack() 
        self.login_btn.pack(fill=tk.BOTH) 
        self.clear_btn.pack(fill=tk.BOTH) 

    def print_login(self): 
        print("Username: {}".format(self.username.get())) 
        print("Password: {}".format(self.password.get())) 

    def clear_form(self): 
        self.username.delete(0, tk.END) 
        self.password.delete(0, tk.END) 
        self.username.focus_set() 

if __name__ == "__main__": 
    app = LoginApp() 
    app.mainloop()
```

`Log in`按钮在控制台中打印值，而`Clear`按钮删除两个输入框的内容，并将焦点返回到`username`的输入框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/21860bf1-fad4-4dc9-9f33-8b60bc599fbe.png)

# 它是如何工作的...

使用父窗口或框架作为第一个参数实例化 Entry 小部件，并使用一组可选关键字参数来配置其他选项。我们没有为对应`username`字段的条目指定任何选项。为了保持密码的机密性，我们使用字符串`"*"`指定`show`参数，它将显示每个键入的字符为星号。

使用`get()`方法，我们将检索当前文本作为字符串。这在`print_login`方法中用于在标准输出中显示条目的内容。

`delete()`方法接受两个参数，指示应删除的字符范围。请记住，索引从位置 0 开始，并且不包括范围末尾的字符。如果只传递一个参数，它将删除该位置的字符。

在`clear_form()`方法中，我们从索引 0 删除到常量`END`，这意味着整个内容被删除。最后，我们将焦点设置为`username`条目。

# 还有更多...

可以使用`insert()`方法以编程方式修改 Entry 小部件的内容，该方法接受两个参数：

+   `index`：要插入文本的位置；请注意，条目位置是从 0 开始的

+   `string`：要插入的文本

使用`delete()`和`insert()`的组合可以实现重置条目内容为默认值的常见模式：

```py
entry.delete(0, tk.END) 
entry.insert(0, "default value") 
```

另一种模式是在文本光标的当前位置追加文本。在这里，您可以使用`INSERT`常量，而不必计算数值索引：

```py
entry.insert(tk.INSERT, "cursor here")
```

与`Button`类一样，`Entry`类还接受`relief`和`state`选项来修改其边框样式和状态。请注意，在状态为`"disabled"`或`"readonly"`时，对`delete()`和`insert()`的调用将被忽略。

# 另请参阅

+   *跟踪文本更改*配方

+   *验证文本输入*配方

# 跟踪文本更改

`Tk`变量允许您的应用程序在输入更改其值时得到通知。`Tkinter`中有四个变量类：`BooleanVar`、`DoubleVar`、`IntVar`和`StringVar`。每个类都包装了相应 Python 类型的值，该值应与附加到变量的输入小部件的类型匹配。

如果您希望根据某些输入小部件的当前状态自动更新应用程序的某些部分，则此功能特别有用。

# 如何做...

在以下示例中，我们将使用`textvariable`选项将`StringVar`实例与我们的条目关联；此变量跟踪写操作，并使用`show_message()`方法作为回调：

```py
import tkinter as tk 

class App(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        self.var = tk.StringVar() 
        self.var.trace("w", self.show_message) 
        self.entry = tk.Entry(self, textvariable=self.var) 
        self.btn = tk.Button(self, text="Clear", 
                             command=lambda: self.var.set("")) 
        self.label = tk.Label(self) 
        self.entry.pack() 
        self.btn.pack() 
        self.label.pack() 

    def show_message(self, *args): 
        value = self.var.get() 
        text = "Hello, {}!".format(value) if value else "" 
        self.label.config(text=text) 

if __name__ == "__main__": 
    app = App() 
    app.mainloop() 
```

当您在 Entry 小部件中输入内容时，标签将使用由`Tk`变量值组成的消息更新其文本。例如，如果您输入单词`Phara`，标签将显示`Hello, Phara!`。如果输入为空，标签将不显示任何文本。为了向您展示如何以编程方式修改变量的内容，我们添加了一个按钮，当您单击它时清除条目：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/93325b8b-dbe1-4415-a4a2-855233a38797.png)

# 它是如何工作的...

我们的应用程序构造函数的前几行实例化了`StringVar`并将回调附加到写入模式。有效的模式值如下：

+   `"w"`：在写入变量时调用

+   `"r"`：在读取变量时调用

+   `"u"`（对于*unset*）：在删除变量时调用

当调用时，回调函数接收三个参数：内部变量名称，空字符串（在其他类型的`Tk`变量中使用），以及触发操作的模式。通过使用`*args`声明方法，我们使这些参数变为可选，因为我们在回调中没有使用这些值。

`Tk`包装器的`get()`方法返回变量的当前值，`set()`方法更新其值。它们还通知相应的观察者，因此通过 GUI 修改输入内容或单击“清除”按钮都将触发对`show_message()`方法的调用。

# 还有更多...

对于`Entry`小部件，Tk 变量是可选的，但对于其他小部件类（例如`Checkbutton`和`Radiobutton`类）来说，它们是必要的，以便正确工作。

# 另请参阅

+   *使用单选按钮创建选择*食谱

+   *使用复选框实现开关*食谱

# 验证文本输入

通常，文本输入代表遵循某些验证规则的字段，例如具有最大长度或匹配特定格式。一些应用程序允许在这些字段中键入任何类型的内容，并在提交整个表单时触发验证。

在某些情况下，我们希望阻止用户将无效内容输入文本字段。我们将看看如何使用 Entry 小部件的验证选项来实现此行为。

# 如何做...

以下应用程序显示了如何使用正则表达式验证输入：

```py
import re 
import tkinter as tk 

class App(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        self.pattern = re.compile("^\w{0,10}$") 
        self.label = tk.Label(self, text="Enter your username") 
        vcmd = (self.register(self.validate_username), "%i", "%P") 
        self.entry = tk.Entry(self, validate="key", 
                              validatecommand=vcmd, 
                              invalidcommand=self.print_error) 
        self.label.pack() 
        self.entry.pack(anchor=tk.W, padx=10, pady=10) 

    def validate_username(self, index, username): 
        print("Modification at index " + index) 
        return self.pattern.match(username) is not None 

    def print_error(self): 
        print("Invalid username character") 

if __name__ == "__main__": 
    app = App() 
    app.mainloop() 
```

如果您运行此脚本并在 Entry 小部件中键入非字母数字字符，则它将保持相同的内容并打印错误消息。当您尝试键入超过 10 个有效字符时，也会发生这种情况，因为正则表达式还限制了内容的长度。

# 工作原理...

将`validate`选项设置为``"key"``，我们将激活在任何内容修改时触发的输入验证。默认情况下，该值为``"none"``，这意味着没有验证。

其他可能的值是``"focusin"``和``"focusout"``，分别在小部件获得或失去焦点时进行验证，或者简单地使用``"focus"``在两种情况下进行验证。或者，我们可以使用``"all"``值在所有情况下进行验证。

`validatecommand`函数在每次触发验证时调用，如果新内容有效，则应返回`true`，否则返回`false`。

由于我们需要更多信息来确定内容是否有效，我们使用`Widget`类的`register`方法创建了一个围绕 Python 函数的 Tcl 包装器。然后，您可以为将传递给 Python 函数的每个参数添加百分比替换。最后，我们将这些值分组为 Python 元组。这对应于我们示例中的以下行：

```py
vcmd = (self.register(self.validate_username), "%i", "%P") 
```

一般来说，您可以使用以下任何一个替换：

+   `％d`：操作类型；插入为 1，删除为 0，否则为-1

+   `％i`：正在插入或删除的字符串的索引

+   `％P`：如果允许修改，则输入的值

+   `％s`：修改前的输入值

+   `％S`：正在插入或删除的字符串内容

+   `％v`：当前设置的验证类型

+   `％V`：触发操作的验证类型

+   `％W`：Entry 小部件的名称

`invalidcommand`选项接受一个在`validatecommand`返回`false`时调用的函数。这个选项也可以应用相同的百分比替换，但在我们的示例中，我们直接传递了我们类的`print_error()`方法。

# 还有更多...

Tcl/Tk 文档建议不要混合`validatecommand`和`textvariable`选项，因为将无效值设置为`Tk`变量将关闭验证。如果`validatecommand`函数不返回布尔值，也会发生同样的情况。

如果您不熟悉`re`模块，可以在官方 Python 文档的[`docs.python.org/3.6/howto/regex.html`](https://docs.python.org/3.6/howto/regex.html)中查看有关正则表达式的详细介绍。

# 另请参阅

+   *创建文本输入*食谱

# 选择数值

以前的食谱介绍了如何处理文本输入；我们可能希望强制某些输入只包含数字值。这是`Spinbox`和`Scale`类的用例——这两个小部件允许用户从范围或有效选项列表中选择数值，但它们在显示和配置方式上有几个不同之处。

# 如何做...

此程序具有用于从`0`到`5`选择整数值的`Spinbox`和`Scale`：

```py
import tkinter as tk 

class App(tk.Tk):
    def __init__(self): 
        super().__init__() 
        self.spinbox = tk.Spinbox(self, from_=0, to=5) 
        self.scale = tk.Scale(self, from_=0, to=5, 
                              orient=tk.HORIZONTAL) 
        self.btn = tk.Button(self, text="Print values", 
                             command=self.print_values) 
        self.spinbox.pack() 
        self.scale.pack() 
        self.btn.pack() 

    def print_values(self): 
        print("Spinbox: {}".format(self.spinbox.get())) 
        print("Scale: {}".format(self.scale.get())) 

if __name__ == "__main__": 
    app = App()
    app.mainloop()
```

在上面的代码中，出于调试目的，我们添加了一个按钮，当您单击它时，它会打印每个小部件的值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/61eb247c-f98a-4874-a756-96f2985bb7f6.png)

# 它是如何工作的...

这两个类都接受`from_`和`to`选项，以指示有效值的范围——由于`from`选项最初是在 Tcl/Tk 中定义的，但它在 Python 中是一个保留关键字，因此需要添加下划线。

`Scale`类的一个方便功能是`resolution`选项，它设置了舍入的精度。例如，分辨率为 0.2 将允许用户选择值 0.0、0.2、0.4 等。此选项的默认值为 1，因此小部件将所有值舍入到最接近的整数。

与往常一样，可以使用`get()`方法检索每个小部件的值。一个重要的区别是，`Spinbox`将数字作为字符串返回，而`Scale`返回一个整数值，如果舍入接受小数值，则返回一个浮点值。

# 还有更多...

`Spinbox`类具有与 Entry 小部件类似的配置，例如`textvariable`和`validate`选项。您可以将所有这些模式应用于旋转框，主要区别在于它限制为数值。

# 另请参阅

+   *跟踪文本更改*食谱

# 使用单选按钮创建选择

使用 Radiobutton 小部件，您可以让用户在多个选项中进行选择。这种模式适用于相对较少的互斥选择。

# 如何做...

您可以使用 Tkinter 变量连接多个`Radiobutton`实例，以便当您单击未选择的选项时，它将取消选择先前选择的任何其他选项。

在下面的程序中，我们为`Red`，`Green`和`Blue`选项创建了三个单选按钮。每次单击单选按钮时，它都会打印相应颜色的小写名称：

```py
import tkinter as tk

COLORS = [("Red", "red"), ("Green", "green"), ("Blue", "blue")]

class ChoiceApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.var = tk.StringVar()
        self.var.set("red")
        self.buttons = [self.create_radio(c) for c in COLORS]
        for button in self.buttons:
            button.pack(anchor=tk.W, padx=10, pady=5)

    def create_radio(self, option):
        text, value = option
        return tk.Radiobutton(self, text=text, value=value, 
                              command=self.print_option, 
                              variable=self.var)

    def print_option(self):
        print(self.var.get())

if __name__ == "__main__": 
    app = ChoiceApp()
    app.mainloop()
```

如果您运行此脚本，它将显示已选择红色单选按钮的应用程序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/69c23add-531e-4e7c-ab29-ee12aa28deff.png)

# 它是如何工作的...

为了避免重复`Radiobutton`初始化的代码，我们定义了一个实用方法，该方法从列表推导中调用。我们解压了`COLORS`列表的每个元组的值，然后将这些局部变量作为选项传递给`Radiobutton`。请记住，尽可能尝试不要重复自己。

由于`StringVar`在所有`Radiobutton`实例之间共享，它们会自动连接，并且我们强制用户只能选择一个选项。

# 还有更多...

我们在程序中设置了默认值为`"red"`；但是，如果我们省略此行，且`StringVar`的值与任何单选按钮的值都不匹配会发生什么？它将匹配`tristatevalue`选项的默认值，即空字符串。这会导致小部件显示在特殊的“三态”或不确定模式下。虽然可以使用`config()`方法修改此选项，但最好的做法是设置一个明智的默认值，以便变量以有效状态初始化。

# 使用复选框实现开关

通常使用复选框和选项列表实现两个选择之间的选择，其中每个选择与其余选择无关。正如我们将在下一个示例中看到的，这些概念可以使用 Checkbutton 小部件来实现。

# 如何做...

以下应用程序显示了如何创建 Checkbutton，它必须连接到`IntVar`变量才能检查按钮状态：

```py
import tkinter as tk

class SwitchApp(tk.Tk):
    def __init__(self):
        super().__init__() 
        self.var = tk.IntVar() 
        self.cb = tk.Checkbutton(self, text="Active?",  
                                 variable=self.var, 
                                 command=self.print_value) 
        self.cb.pack() 

    def print_value(self): 
        print(self.var.get()) 

if __name__ == "__main__": 
    app = SwitchApp() 
    app.mainloop() 
```

在上面的代码中，我们只是在每次单击小部件时打印小部件的值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/a667f326-09f7-49c0-bd84-aa4b43f73390.png)

# 它是如何工作的...

与 Button 小部件一样，Checkbutton 也接受`command`和`text`选项。

使用`onvalue`和`offvalue`选项，我们可以指定按钮打开和关闭时使用的值。我们使用整数变量，因为默认情况下这些值分别为**1**和**0**；但是，您也可以将它们设置为任何其他整数值。

# 还有更多...

对于 Checkbuttons，也可以使用其他变量类型：

```py
var = tk.StringVar() 
var.set("OFF") 
checkbutton_active = tk.Checkbutton(master, text="Active?", variable=self.var, 
                                    onvalue="ON", offvalue="OFF", 
                                    command=update_value)
```

唯一的限制是要将`onvalue`和`offvalue`与 Tkinter 变量的类型匹配；在这种情况下，由于`"ON"`和`"OFF"`是字符串，因此变量应该是`StringVar`。否则，当尝试设置不同类型的相应值时，Tcl 解释器将引发错误。

# 另请参阅

+   *跟踪文本更改*的方法

+   *使用单选按钮创建选择*的方法

# 显示项目列表

Listbox 小部件包含用户可以使用鼠标或键盘选择的文本项。这种选择可以是单个的或多个的，这取决于小部件的配置。

# 如何做...

以下程序创建了一个星期几的列表选择。有一个按钮来打印实际选择，以及一个按钮列表来更改选择模式：

```py
import tkinter as tk 

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", 
        "Friday", "Saturday", "Sunday"] 
MODES = [tk.SINGLE, tk.BROWSE, tk.MULTIPLE, tk.EXTENDED] 

class ListApp(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        self.list = tk.Listbox(self)  
        self.list.insert(0, *DAYS) 
        self.print_btn = tk.Button(self, text="Print selection", 
                                   command=self.print_selection) 
        self.btns = [self.create_btn(m) for m in MODES] 

        self.list.pack() 
        self.print_btn.pack(fill=tk.BOTH) 
        for btn in self.btns: 
            btn.pack(side=tk.LEFT) 

    def create_btn(self, mode): 
        cmd = lambda: self.list.config(selectmode=mode) 
        return tk.Button(self, command=cmd, 
                         text=mode.capitalize()) 

    def print_selection(self): 
        selection = self.list.curselection() 
        print([self.list.get(i) for i in selection]) 

if __name__ == "__main__": 
    app = ListApp() 
    app.mainloop() 
```

您可以尝试更改选择模式并打印所选项目：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/f8530d3e-efbd-4789-b518-48e43e5de8b5.png)

# 它是如何工作的...

我们创建一个空的 Listbox 对象，并使用`insert()`方法添加所有文本项。0 索引表示应在列表的开头添加项目。在下面的代码片段中，我们解包了`DAYS`列表，但是可以使用`END`常量将单独的项目附加到末尾：

```py
self.list.insert(tk.END, "New item") 
```

使用`curselection()`方法检索当前选择。它返回所选项目的索引，以便将它们转换为相应的文本项目，我们为每个索引调用了`get()`方法。最后，为了调试目的，列表将被打印在标准输出中。

在我们的示例中，`selectmode`选项可以通过编程方式进行更改，以探索不同的行为，如下所示：

+   `SINGLE`：单选

+   `BROWSE`：可以使用上下键移动的单选

+   `MULTIPLE`：多选

+   `EXTENDED`：使用*Shift*和*Ctrl*键选择范围的多选

# 还有更多...

如果文本项的数量足够大，可能需要添加垂直滚动条。您可以使用`yscrollcommand`选项轻松连接它。在我们的示例中，我们可以将两个小部件都包装在一个框架中，以保持相同的布局。记得在打包滚动条时指定`fill`选项，以便在*y*轴上填充可用空间。

```py
def __init__(self):
    self.frame = tk.Frame(self) 
    self.scroll = tk.Scrollbar(self.frame, orient=tk.VERTICAL) 
    self.list = tk.Listbox(self.frame, yscrollcommand=self.scroll.set) 
    self.scroll.config(command=self.list.yview) 
    # ... 
    self.frame.pack() 
    self.list.pack(side=tk.LEFT) 
    self.scroll.pack(side=tk.LEFT, fill=tk.Y) 
```

同样，对于水平轴，还有一个`xscrollcommand`选项。

# 另请参阅

+   *使用单选按钮创建选择*的方法

# 处理鼠标和键盘事件

能够对事件做出反应是 GUI 应用程序开发中最基本但最重要的主题之一，因为它决定了用户如何与程序进行交互。

按键盘上的键和用鼠标点击项目是一些常见的事件类型，在一些 Tkinter 类中会自动处理。例如，这种行为已经在`Button`小部件类的`command`选项上实现，它调用指定的回调函数。

有些事件可以在没有用户交互的情况下触发，例如从一个小部件到另一个小部件的程序性输入焦点更改。

# 如何做...

您可以使用`bind`方法将事件绑定到小部件。以下示例将一些鼠标事件绑定到`Frame`实例：

```py
import tkinter as tk 

class App(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        frame = tk.Frame(self, bg="green", 
                         height=100, width=100) 
        frame.bind("<Button-1>", self.print_event) 
        frame.bind("<Double-Button-1>", self.print_event) 
        frame.bind("<ButtonRelease-1>", self.print_event) 
        frame.bind("<B1-Motion>", self.print_event) 
        frame.bind("<Enter>", self.print_event) 
        frame.bind("<Leave>", self.print_event) 
        frame.pack(padx=50, pady=50) 

    def print_event(self, event): 
        position = "(x={}, y={})".format(event.x, event.y) 
        print(event.type, "event", position) 

if __name__ == "__main__": 
    app = App() 
    app.mainloop() 
```

所有事件都由我们的类的`print_event()`方法处理，该方法在控制台中打印事件类型和鼠标位置。您可以通过单击鼠标上的绿色框架并在开始打印事件消息时将其移动来尝试它。

以下示例包含一个带有一对绑定的 Entry 小部件；一个用于在输入框获得焦点时触发的事件，另一个用于所有按键事件：

```py
import tkinter as tk 

class App(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        entry = tk.Entry(self) 
        entry.bind("<FocusIn>", self.print_type)  
        entry.bind("<Key>", self.print_key) 
        entry.pack(padx=20, pady=20) 

    def print_type(self, event): 
        print(event.type) 

    def print_key(self, event): 
        args = event.keysym, event.keycode, event.char 
        print("Symbol: {}, Code: {}, Char: {}".format(*args)) 

if __name__ == "__main__": 
    app = App() 
    app.mainloop() 
```

该程序将输出的第一条消息是当您将焦点设置在 Entry 小部件上时的`FocusIn`事件。如果您尝试一下，您会发现它还会显示与不可打印字符不对应的键的事件，比如箭头键或回车键。

# 它是如何工作的...

`bind`方法在`widget`类中定义，并接受三个参数，一个事件`sequence`，一个`callback`函数和一个可选的`add`字符串：

```py
widget.bind(sequence, callback, add='') 
```

`sequence`字符串使用`<modifier-type-detail>`的语法。

首先，修饰符是可选的，允许您指定事件的一般类型的其他组合：

+   `Shift`: 当用户按下*Shift*键时

+   `Alt`: 当用户按下*Alt*键时

+   `控制`: 当用户按下*Ctrl*键时

+   `Lock`: 当用户按下*Shift*锁定时

+   `Double`: 当事件快速连续发生两次时

+   `Triple`: 当事件快速连续发生三次时

事件类型确定事件的一般类型：

+   `ButtonPress`或`Button`: 鼠标按钮按下时生成的事件

+   `ButtonRelease`: 鼠标按钮释放时生成的事件

+   `Enter`: 当鼠标移动到小部件上时生成的事件

+   `Leave`: 当鼠标指针离开小部件时生成的事件

+   `FocusIn`: 当小部件获得输入焦点时生成的事件

+   `FocusOut`: 当小部件失去输入焦点时生成的事件

+   `KeyPress`或`Key`: 按下键时生成的事件

+   `KeyRelease`: 松开键时生成的事件

+   `Motion`: 鼠标移动时生成的事件

详细信息也是可选的，用于指示鼠标按钮或键：

+   对于鼠标事件，1 是左按钮，2 是中间按钮，3 是右按钮。

+   对于键盘事件，它是键字符。特殊键使用键符号；一些常见的示例是回车、*Tab*、*Esc*、上、下、右、左、*Backspace*和功能键（从*F1*到*F12*）。

`callback`函数接受一个事件参数。对于鼠标事件，它具有以下属性：

+   `x`和`y`: 当前鼠标位置（以像素为单位）

+   `x_root`和`y_root`: 与`x`和`y`相同，但相对于屏幕左上角

+   `num`: 鼠标按钮编号

对于键盘事件，它包含这些属性：

+   `char`: 按下的字符代码作为字符串

+   `keysym`: 按下的键符号

+   `keycode`: 按下的键码

在这两种情况下，事件都有`widget`属性，引用生成事件的实例，以及`type`，指定事件类型。

我们强烈建议您为`callback`函数定义方法，因为您还将拥有对类实例的引用，因此您可以轻松访问每个`widget`属性。

最后，`add`参数可以是`''`，以替换`callback`函数（如果有先前的绑定），或者是`'+'`，以添加回调并保留旧的回调。

# 还有更多...

除了这里描述的事件类型之外，还有其他类型，在某些情况下可能会有用，比如当小部件被销毁时生成的`<Destroy>`事件，或者当小部件的大小或位置发生变化时发送的`<Configure>`事件。

您可以查看 Tcl/Tk 文档，了解事件类型的完整列表[`www.tcl.tk/man/tcl/TkCmd/bind.htm#M7`](https://www.tcl.tk/man/tcl/TkCmd/bind.htm#M7)。

# 另请参阅

+   *构建 Tkinter 应用程序*的配方

# 设置主窗口的图标、标题和大小

`Tk`实例与普通小部件不同，它的配置方式也不同，因此我们将探讨一些基本方法，允许我们自定义它的显示方式。

# 如何做到...

这段代码创建了一个带有自定义标题和图标的主窗口。它的宽度为 400 像素，高度为 200 像素，与屏幕左上角的每个轴向的间隔为 10 像素：

```py
import tkinter as tk 

class App(tk.Tk): 
    def __init__(self): 
        super().__init__() 
        self.title("My Tkinter app") 
        self.iconbitmap("python.ico") 
        self.geometry("400x200+10+10") 

if __name__ == "__main__": 
    app = App() 
    app.mainloop()
```

该程序假定您在脚本所在的目录中有一个名为`python.ico`的有效 ICO 文件。

# 它是如何工作的...

`Tk`类的`title()`和`iconbitmap()`方法非常自描述——第一个设置窗口标题，而第二个接受与窗口关联的图标的路径。

`geometry()`方法使用遵循以下模式的字符串配置窗口的大小：

*{width}x{height}+{offset_x}+{offset_y}*

如果您向应用程序添加更多的辅助窗口，这些方法也适用于`Toplevel`类。

# 还有更多...

如果您想使应用程序全屏，将对`geometry()`方法的调用替换为`self.state("zoomed")`。


# 第二章：窗口布局

在本章中，我们将介绍以下食谱：

+   使用框架对小部件进行分组

+   使用 Pack 几何管理器

+   使用 Grid 几何管理器

+   使用 Place 几何管理器

+   使用 FrameLabel 小部件对输入进行分组

+   动态布置小部件

+   创建水平和垂直滚动条

# 介绍

小部件确定用户可以在 GUI 应用程序中执行的操作；但是，我们应该注意它们的放置和我们与该安排建立的关系。有效的布局帮助用户识别每个图形元素的含义和优先级，以便他们可以快速理解如何与我们的程序交互。

布局还确定了用户期望在整个应用程序中一致找到的视觉外观，例如始终将确认按钮放在屏幕右下角。尽管这些信息对我们作为开发人员来说可能是显而易见的，但如果我们不按照自然顺序引导他们通过应用程序，最终用户可能会感到不知所措。

本章将深入探讨 Tkinter 提供的不同机制，用于布置和分组小部件以及控制其他属性，例如它们的大小或间距。

# 使用框架对小部件进行分组

框架表示窗口的矩形区域，通常用于复杂布局以包含其他小部件。由于它们有自己的填充、边框和背景，您可以注意到小部件组在逻辑上是相关的。

框架的另一个常见模式是封装应用程序功能的一部分，以便您可以创建一个抽象，隐藏子部件的实现细节。

我们将看到一个示例，涵盖了从`Frame`类继承并公开包含小部件上的某些信息的组件的两种情况。

# 准备就绪

我们将构建一个应用程序，其中包含两个列表，第一个列表中有一系列项目，第二个列表最初为空。两个列表都是可滚动的，并且您可以使用两个中央按钮在它们之间移动项目：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/4c30ba49-f25a-48ca-85ed-5533ffb88ce7.png)

# 如何做…

我们将定义一个`Frame`子类来表示可滚动列表，然后创建该类的两个实例。两个按钮也将直接添加到主窗口：

```py
import tkinter as tk

class ListFrame(tk.Frame):
    def __init__(self, master, items=[]):
        super().__init__(master)
        self.list = tk.Listbox(self)
        self.scroll = tk.Scrollbar(self, orient=tk.VERTICAL,
                                   command=self.list.yview)
        self.list.config(yscrollcommand=self.scroll.set)
        self.list.insert(0, *items)
        self.list.pack(side=tk.LEFT)
        self.scroll.pack(side=tk.LEFT, fill=tk.Y)

    def pop_selection(self):
        index = self.list.curselection()
        if index:
            value = self.list.get(index)
            self.list.delete(index)
            return value

    def insert_item(self, item):
        self.list.insert(tk.END, item)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        months = ["January", "February", "March", "April",
                  "May", "June", "July", "August", "September",
                  "October", "November", "December"]
        self.frame_a = ListFrame(self, months)
        self.frame_b = ListFrame(self)
        self.btn_right = tk.Button(self, text=">",
                                   command=self.move_right)
        self.btn_left = tk.Button(self, text="<",
                                  command=self.move_left)

        self.frame_a.pack(side=tk.LEFT, padx=10, pady=10)
        self.frame_b.pack(side=tk.RIGHT, padx=10, pady=10)
        self.btn_right.pack(expand=True, ipadx=5)
        self.btn_left.pack(expand=True, ipadx=5)

    def move_right(self):
        self.move(self.frame_a, self.frame_b)

    def move_left(self):
        self.move(self.frame_b, self.frame_a)

    def move(self, frame_from, frame_to):
        value = frame_from.pop_selection()
        if value:
            frame_to.insert_item(value)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理…

我们的`ListFrame`类只有两种方法与内部列表进行交互：`pop_selection()`和`insert_item()`。第一个返回并删除当前选择的项目，如果没有选择项目，则返回 None，而第二个在列表末尾插入新项目。

这些方法用于父类中将项目从一个列表转移到另一个列表：

```py
def move(self, frame_from, frame_to):
    value = frame_from.pop_selection()
    if value:
        frame_to.insert_item(value)
```

我们还利用父框架容器正确地打包它们，以适当的填充：

```py
# ...
self.frame_a.pack(side=tk.LEFT, padx=10, pady=10) self.frame_b.pack(side=tk.RIGHT, padx=10, pady=10)
```

由于这些框架，我们对几何管理器的调用在全局布局中更加隔离和有组织。

# 还有更多...

这种方法的另一个好处是，它允许我们在每个容器小部件中使用不同的几何管理器，例如在框架内使用`grid()`来布置小部件，在主窗口中使用`pack()`来布置框架。

但是，请记住，在 Tkinter 中不允许在同一个容器中混合使用这些几何管理器，否则会使您的应用程序崩溃。

# 另请参阅

+   *使用 Pack 几何管理器*食谱

# 使用 Pack 几何管理器

在之前的食谱中，我们已经看到创建小部件并不会自动在屏幕上显示它。我们调用了每个小部件上的`pack()`方法来实现这一点，这意味着我们使用了 Pack 几何管理器。

这是 Tkinter 中三种可用的几何管理器之一，非常适合简单的布局，例如当您想要将所有小部件放在彼此上方或并排时。

# 准备就绪

假设我们想在应用程序中实现以下布局：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/fce828e9-1f75-4590-a50e-bb8adbc1d8eb.png)

它由三行组成，最后一行有三个小部件并排放置。在这种情况下，Pack 布局管理器可以轻松地按预期添加小部件，而无需额外的框架。

# 操作步骤

我们将使用五个具有不同文本和背景颜色的`Label`小部件来帮助我们识别每个矩形区域：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        label_a = tk.Label(self, text="Label A", bg="yellow")
        label_b = tk.Label(self, text="Label B", bg="orange")
        label_c = tk.Label(self, text="Label C", bg="red")
        label_d = tk.Label(self, text="Label D", bg="green")
        label_e = tk.Label(self, text="Label E", bg="blue")

        opts = { 'ipadx': 10, 'ipady': 10, 'fill': tk.BOTH }
        label_a.pack(side=tk.TOP, **opts)
        label_b.pack(side=tk.TOP, **opts)
        label_c.pack(side=tk.LEFT, **opts)
        label_d.pack(side=tk.LEFT, **opts)
        label_e.pack(side=tk.LEFT, **opts)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

我们还向`opts`字典中添加了一些选项，以便清楚地确定每个区域的大小：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/1a0e72a4-090a-4af8-af83-c8574e730056.png)

# 工作原理

为了更好地理解 Pack 布局管理器，我们将逐步解释它如何将小部件添加到父容器中。在这里，我们特别关注`side`选项的值，它指示小部件相对于下一个将被打包的小部件的位置。

首先，我们将两个标签打包到屏幕顶部。虽然`tk.TOP`常量是`side`选项的默认值，但我们明确设置它以清楚地区分它与我们使用`tk.LEFT`值的调用。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/77b7063f-2c0b-4a2b-ab75-c1704861201d.jpg)

然后，我们使用`side`选项设置为`tk.LEFT`来打包下面的三个标签，这会使它们并排放置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/0f54aec2-5957-4da5-9e32-d63acc06903f.jpg)

指定`label_e`上的 side 实际上并不重要，只要它是我们添加到容器中的最后一个小部件即可。

请记住，这就是在使用 Pack 布局管理器时顺序如此重要的原因。为了防止复杂布局中出现意外结果，通常将小部件与框架分组，这样当您将所有小部件打包到一个框架中时，就不会干扰其他小部件的排列。

在这些情况下，我们强烈建议您使用网格布局管理器，因为它允许您直接调用几何管理器设置每个小部件的位置，并且避免了额外框架的需要。

# 还有更多...

除了`tk.TOP`和`tk.LEFT`，您还可以将`tk.BOTTOM`和`tk.RIGHT`常量传递给`side`选项。它们执行相反的堆叠，正如它们的名称所暗示的那样；但是，这可能是反直觉的，因为我们遵循的自然顺序是从上到下，从左到右。

例如，如果我们在最后三个小部件中用`tk.RIGHT`替换`tk.LEFT`的值，它们从左到右的顺序将是`label_e`，`label_d`和`label_c`。

# 参见

+   *使用网格布局管理器*食谱

+   *使用 Place 布局管理器*食谱

# 使用网格布局管理器

网格布局管理器被认为是三种布局管理器中最通用的。它直接重新组合了通常用于用户界面设计的*网格*概念，即一个二维表格，分为行和列，其中每个单元格代表小部件的可用空间。

# 准备工作

我们将演示如何使用网格布局管理器来实现以下布局：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/2f7823b8-c9f3-4408-8b62-eccfb7ab446d.png)

这可以表示为一个 3 x 3 的表格，其中第二列和第三列的小部件跨越两行，底部行的小部件跨越三列。

# 操作步骤

与前面的食谱一样，我们将使用五个具有不同背景的标签来说明单元格的分布：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        label_a = tk.Label(self, text="Label A", bg="yellow")
        label_b = tk.Label(self, text="Label B", bg="orange")
        label_c = tk.Label(self, text="Label C", bg="red")
        label_d = tk.Label(self, text="Label D", bg="green")
        label_e = tk.Label(self, text="Label E", bg="blue")

        opts = { 'ipadx': 10, 'ipady': 10 , 'sticky': 'nswe' }
        label_a.grid(row=0, column=0, **opts)
        label_b.grid(row=1, column=0, **opts)
        label_c.grid(row=0, column=1, rowspan=2, **opts)
        label_d.grid(row=0, column=2, rowspan=2, **opts)
        label_e.grid(row=2, column=0, columnspan=3, **opts)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

我们还传递了一个选项字典，以添加一些内部填充并将小部件扩展到单元格中的所有可用空间。

# 工作原理

`label_a`和`label_b`的放置几乎是不言自明的：它们分别占据第一列的第一行和第二行，记住网格位置是从零开始计数的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/956d78d6-3cda-41e4-949e-45489d30fdda.png)

为了扩展`label_c`和`label_d`跨越多个单元格，我们将把`rowspan`选项设置为`2`，这样它们将跨越两个单元格，从`row`和`column`选项指示的位置开始。最后，我们将使用`columnspan`选项将`label_e`放置到`3`。

需要强调的是，与 Pack 几何管理器相比，可以更改对每个小部件的`grid()`调用的顺序，而不修改最终布局。

# 还有更多...

`sticky`选项表示小部件应粘附的边界，用基本方向表示：北、南、西和东。这些值由 Tkinter 常量`tk.N`、`tk.S`、`tk.W`和`tk.E`表示，以及组合版本`tk.NW`、`tk.NE`、`tk.SW`和`tk.SE`。

例如，`sticky=tk.N`将小部件对齐到单元格的顶部边界（北），而`sticky=tk.SE`将小部件放置在单元格的右下角（东南）。

由于这些常量代表它们对应的小写字母，我们用`"nswe"`字符串简写了`tk.N + tk.S + tk.W + tk.E`表达式。这意味着小部件应该在水平和垂直方向上都扩展，类似于 Pack 几何管理器的`fill=tk.BOTH`选项。

如果`sticky`选项没有传递值，则小部件将在单元格内居中。

# 另请参阅

+   *使用 Pack 几何管理器*配方

+   *使用 Place 几何管理器*配方

# 使用 Place 几何管理器

Place 几何管理器允许您以绝对或相对于另一个小部件的位置和大小。

在三种几何管理器中，它是最不常用的一种。另一方面，它可以适应一些复杂的情况，例如您想自由定位一个小部件或重叠一个先前放置的小部件。

# 准备工作

为了演示如何使用 Place 几何管理器，我们将通过混合绝对位置和相对位置和大小来复制以下布局：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/78190289-c61d-422c-8422-84a24b8a0d78.png)

# 如何做...

我们将显示的标签具有不同的背景，并按从左到右和从上到下的顺序定义：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        label_a = tk.Label(self, text="Label A", bg="yellow")
        label_b = tk.Label(self, text="Label B", bg="orange")
        label_c = tk.Label(self, text="Label C", bg="red")
        label_d = tk.Label(self, text="Label D", bg="green")
        label_e = tk.Label(self, text="Label E", bg="blue")

        label_a.place(relwidth=0.25, relheight=0.25)
        label_b.place(x=100, anchor=tk.N,
                      width=100, height=50)
        label_c.place(relx=0.5, rely=0.5, anchor=tk.CENTER,
                      relwidth=0.5, relheight=0.5)
        label_d.place(in_=label_c, anchor=tk.N + tk.W,
                      x=2, y=2, relx=0.5, rely=0.5,
                      relwidth=0.5, relheight=0.5)
        label_e.place(x=200, y=200, anchor=tk.S + tk.E,
                      relwidth=0.25, relheight=0.25)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

如果运行前面的程序，您可以看到`label_c`和`label_d`在屏幕中心的重叠，这是我们使用其他几何管理器没有实现的。

# 它是如何工作的...

第一个标签的`relwidth`和`relheight`选项设置为`0.25`，这意味着它的宽度和高度是其父容器的 25%。默认情况下，小部件放置在`x=0`和`y=0`位置，并对齐到西北，即屏幕的左上角。

第二个标签放置在绝对位置`x=100`，并使用`anchor`选项设置为`tk.N`（北）常量与顶部边界对齐。在这里，我们还使用`width`和`height`指定了绝对大小。

第三个标签使用相对定位在窗口中心，并将`anchor`设置为`tk.CENTER`。请记住，`relx`和`relwidth`的值为`0.5`表示父容器宽度的一半，`rely`和`relheight`的值为`0.5`表示父容器高度的一半。

第四个标签通过将其作为`in_`参数放置在`label_c`上（请注意，Tkinter 在其后缀中添加了下划线，因为`in`是一个保留关键字）。使用`in_`时，您可能会注意到对齐不是几何上精确的。在我们的示例中，我们必须在每个方向上添加 2 个像素的偏移量，以完全重叠`label_c`的右下角。

最后，第五个标签使用绝对定位和相对大小。正如您可能已经注意到的那样，这些尺寸可以很容易地切换，因为我们假设父容器为 200 x 200 像素；但是，如果调整主窗口的大小，只有相对权重才能按预期工作。您可以通过调整窗口大小来测试此行为。

# 还有更多...

Place 几何管理器的另一个重要优势是它可以与 Pack 或 Grid 一起使用。

例如，假设您希望在右键单击小部件时动态显示标题。您可以使用 Label 小部件表示此标题，并将其放置在单击小部件的相对位置：

```py
def show_caption(self, event):
    caption = tk.Label(self, ...)
    caption.place(in_=event.widget, x=event.x, y=event.y)
    # ...
```

作为一般建议，我们建议您在 Tkinter 应用程序中尽可能多地使用其他几何管理器，并且仅在需要自定义定位的专门情况下使用此几何管理器。

# 另请参阅

+   使用 Pack 几何管理器的食谱

+   使用网格几何管理器的食谱

# 使用 LabelFrame 小部件对输入进行分组

`LabelFrame`类可用于对多个输入小部件进行分组，指示它们表示的逻辑实体的标签。它通常用于表单，与`Frame`小部件非常相似。

# 准备就绪

我们将构建一个带有一对`LabelFrame`实例的表单，每个实例都有其相应的子输入小部件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/e9759bcf-5dd1-41ce-9de4-bdb6de6a32e9.png)

# 如何做…

由于此示例的目的是显示最终布局，我们将添加一些小部件，而不将它们的引用保留为属性：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        group_1 = tk.LabelFrame(self, padx=15, pady=10,
                               text="Personal Information")
        group_1.pack(padx=10, pady=5)

        tk.Label(group_1, text="First name").grid(row=0)
        tk.Label(group_1, text="Last name").grid(row=1)
        tk.Entry(group_1).grid(row=0, column=1, sticky=tk.W)
        tk.Entry(group_1).grid(row=1, column=1, sticky=tk.W)

        group_2 = tk.LabelFrame(self, padx=15, pady=10,
                               text="Address")
        group_2.pack(padx=10, pady=5)

        tk.Label(group_2, text="Street").grid(row=0)
        tk.Label(group_2, text="City").grid(row=1)
        tk.Label(group_2, text="ZIP Code").grid(row=2)
        tk.Entry(group_2).grid(row=0, column=1, sticky=tk.W)
        tk.Entry(group_2).grid(row=1, column=1, sticky=tk.W)
        tk.Entry(group_2, width=8).grid(row=2, column=1,
                                        sticky=tk.W)

        self.btn_submit = tk.Button(self, text="Submit")
        self.btn_submit.pack(padx=10, pady=10, side=tk.RIGHT)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理…

`LabelFrame`小部件采用`labelwidget`选项来设置用作标签的小部件。如果不存在，它将显示作为`text`选项传递的字符串。例如，可以用以下语句替换`tk.LabelFrame(master, text="Info")`的实例：

```py
label = tk.Label(master, text="Info", ...)
frame = tk.LabelFrame(master, labelwidget=label)
# ...
frame.pack()
```

这将允许您进行任何类型的自定义，例如添加图像。请注意，我们没有为标签使用任何几何管理器，因为当您放置框架时，它会被管理。

# 动态布局小部件

网格几何管理器在简单和高级布局中都很容易使用，也是与小部件列表结合使用的强大机制。

我们将看看如何通过列表推导和`zip`和`enumerate`内置函数，可以减少行数并仅用几行调用几何管理器方法。

# 准备就绪

我们将构建一个应用程序，其中包含四个`Entry`小部件，每个小部件都有相应的标签，指示输入的含义。我们还将添加一个按钮来打印所有条目的值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/a4586bd3-a7cf-4f0d-9ce6-a538e7114f37.png)

我们将使用小部件列表而不是创建和分配每个小部件到单独的属性。由于我们将在这些列表上进行迭代时跟踪索引，因此我们可以轻松地使用适当的`column`选项调用`grid()`方法。

# 如何做…

我们将使用`zip`函数聚合标签和输入列表。按钮将单独创建和显示，因为它与其余小部件没有共享任何选项：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        fields = ["First name", "Last name", "Phone", "Email"]
        labels = [tk.Label(self, text=f) for f in fields]
        entries = [tk.Entry(self) for _ in fields]
        self.widgets = list(zip(labels, entries))
        self.submit = tk.Button(self, text="Print info",
                                command=self.print_info)

        for i, (label, entry) in enumerate(self.widgets):
            label.grid(row=i, column=0, padx=10, sticky=tk.W)
            entry.grid(row=i, column=1, padx=10, pady=5)
        self.submit.grid(row=len(fields), column=1, sticky=tk.E,
                         padx=10, pady=10)

    def print_info(self):
        for label, entry in self.widgets:
            print("{} = {}".format(label.cget("text"), "=", entry.get()))

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

您可以在每个输入上输入不同的文本，并单击“打印信息”按钮以验证每个元组包含相应的标签和输入。

# 工作原理…

每个列表推导式都会迭代字段列表的字符串。标签使用每个项目作为显示的文本，输入只需要父容器的引用——下划线是一个常见的习惯用法，表示变量值被忽略。

从 Python 3 开始，`zip`返回一个迭代器而不是列表，因此我们使用列表函数消耗聚合。结果，`widgets`属性包含一个可以安全多次迭代的元组列表：

```py
fields = ["First name", "Last name", "Phone", "Email"]
labels = [tk.Label(self, text=f) for f in fields]
entries = [tk.Entry(self) for _ in fields]
self.widgets = list(zip(labels, entries))
```

现在，我们必须在每个小部件元组上调用几何管理器。使用`enumerate`函数，我们可以跟踪每次迭代的索引并将其作为*行*号传递：

```py
for i, (label, entry) in enumerate(self.widgets):
    label.grid(row=i, column=0, padx=10, sticky=tk.W)
    entry.grid(row=i, column=1, padx=10, pady=5)
```

请注意，我们使用了`for i, (label, entry) in ...`语法，因为我们必须解压使用`enumerate`生成的元组，然后解压`widgets`属性的每个元组。

在`print_info()`回调中，我们迭代小部件以打印每个标签文本及其相应的输入值。要检索标签的`text`，我们使用了`cget()`方法，它允许您通过名称获取小部件选项的值。

# 创建水平和垂直滚动条

在 Tkinter 中，几何管理器会占用所有必要的空间，以适应其父容器中的所有小部件。但是，如果容器具有固定大小或超出屏幕大小，将会有一部分区域对用户不可见。

在 Tkinter 中，滚动条小部件不会自动添加，因此您必须像其他类型的小部件一样创建和布置它们。另一个考虑因素是，只有少数小部件类具有配置选项，使其能够连接到滚动条。

为了解决这个问题，您将学习如何利用**Canvas**小部件的灵活性使任何容器可滚动。

# 准备就绪

为了演示`Canvas`和`Scrollbar`类的组合，创建一个可调整大小和可滚动的框架，我们将构建一个通过加载图像动态更改大小的应用程序。

当单击“加载图像”按钮时，它会将自身移除，并将一个大于可滚动区域的图像加载到`Canvas`中-例如，我们使用了一个预定义的图像，但您可以修改此程序以使用文件对话框选择任何其他 GIF 图像：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/5ed14b60-2769-43a6-9204-75d6a42f8198.png)

这将启用水平和垂直滚动条，如果主窗口被调整大小，它们会自动调整自己：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/1c73a705-07ce-497d-a353-1cc76c01b56e.png)

# 操作步骤…

当我们将在单独的章节中深入了解 Canvas 小部件的功能时，本应用程序将介绍其标准滚动界面和`create_window()`方法。请注意，此脚本需要将文件`python.gif`放置在相同的目录中：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.scroll_x = tk.Scrollbar(self, orient=tk.HORIZONTAL)
        self.scroll_y = tk.Scrollbar(self, orient=tk.VERTICAL)
        self.canvas = tk.Canvas(self, width=300, height=100,
                                xscrollcommand=self.scroll_x.set,
                                yscrollcommand=self.scroll_y.set)
        self.scroll_x.config(command=self.canvas.xview)
        self.scroll_y.config(command=self.canvas.yview)

        self.frame = tk.Frame(self.canvas)
        self.btn = tk.Button(self.frame, text="Load image",
                             command=self.load_image)
        self.btn.pack()

        self.canvas.create_window((0, 0), window=self.frame,  
                                          anchor=tk.NW)

        self.canvas.grid(row=0, column=0, sticky="nswe")
        self.scroll_x.grid(row=1, column=0, sticky="we")
        self.scroll_y.grid(row=0, column=1, sticky="ns")

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.bind("<Configure>", self.resize)
        self.update_idletasks()
        self.minsize(self.winfo_width(), self.winfo_height())

    def resize(self, event):
        region = self.canvas.bbox(tk.ALL)
        self.canvas.configure(scrollregion=region)

    def load_image(self):
        self.btn.destroy()
        self.image = tk.PhotoImage(file="python.gif")
        tk.Label(self.frame, image=self.image).pack()

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理…

我们应用程序的第一行创建了滚动条，并使用`xscrollcommand`和`yscrollcommand`选项将它们连接到`Canvas`对象，这些选项分别使用`scroll_x`和`scroll_y`的`set()`方法的引用-这是负责移动滚动条滑块的方法。

还需要在定义`Canvas`后配置每个滚动条的`command`选项：

```py
self.scroll_x = tk.Scrollbar(self, orient=tk.HORIZONTAL)
self.scroll_y = tk.Scrollbar(self, orient=tk.VERTICAL)
self.canvas = tk.Canvas(self, width=300, height=100,
                        xscrollcommand=self.scroll_x.set,
                        yscrollcommand=self.scroll_y.set)
self.scroll_x.config(command=self.canvas.xview)
self.scroll_y.config(command=self.canvas.yview)
```

也可以先创建`Canvas`，然后在实例化滚动条时配置其选项。

下一步是使用`create_window()`方法将框架添加到我们可滚动的`Canvas`中。它接受的第一个参数是使用`window`选项传递的小部件的位置。由于`Canvas`小部件的*x*和*y*轴从左上角开始，我们将框架放置在`(0, 0)`位置，并使用`anchor=tk.NW`将其对齐到该角落（西北）：

```py
self.frame = tk.Frame(self.canvas)
# ...
self.canvas.create_window((0, 0), window=self.frame, anchor=tk.NW)
```

然后，我们将使用`rowconfigure()`和`columnconfigure()`方法使第一行和列可调整大小。`weight`选项指示相对权重以分配额外的空间，但在我们的情况下，没有更多的行或列需要调整大小。

绑定到`<Configure>`事件将帮助我们在主窗口调整大小时正确重新配置`canvas`。处理这种类型的事件遵循我们在上一章中看到的相同原则，以处理鼠标和键盘事件：

```py
self.rowconfigure(0, weight=1)
self.columnconfigure(0, weight=1)
self.bind("<Configure>", self.resize)
```

最后，我们将使用`winfo_width()`和`winfo_height()`方法设置主窗口的最小大小，这些方法可以检索当前的宽度和高度。

为了获得容器的真实大小，我们必须通过调用`update_idletasks()`强制几何管理器首先绘制所有子小部件。这个方法在所有小部件类中都可用，并强制 Tkinter 处理所有待处理的空闲事件，如重绘和几何重新计算：

```py
self.update_idletasks()
self.minsize(self.winfo_width(), self.winfo_height())
```

`resize`方法处理窗口调整大小事件，并更新`scrollregion`选项，该选项定义了可以滚动的`canvas`区域。为了轻松地重新计算它，您可以使用`bbox()`方法和`ALL`常量。这将返回整个 Canvas 小部件的边界框：

```py
def resize(self, event):
    region = self.canvas.bbox(tk.ALL)
    self.canvas.configure(scrollregion=region)
```

当我们启动应用程序时，Tkinter 将自动触发多个`<Configure>`事件，因此无需在`__init__`方法的末尾调用`self.resize()`。

# 还有更多...

只有少数小部件类支持标准滚动选项：`Listbox`、`Text`和`Canvas`允许`xscrollcommand`和`yscrollcommand`，而输入小部件只允许`xscrollcommand`。我们已经看到如何将此模式应用于`canvas`，因为它可以用作通用解决方案，但您可以遵循类似的结构使这些小部件中的任何一个可滚动和可调整大小。

还有一点要指出的是，我们没有调用任何几何管理器来绘制框架，因为`create_window()`方法会为我们完成这项工作。为了更好地组织我们的应用程序类，我们可以将属于框架及其内部小部件的所有功能移动到专用的`Frame`子类中。

# 另请参阅

+   处理鼠标和键盘事件的方法

+   使用框架对小部件进行分组的方法


# 第三章：自定义小部件

在本章中，我们将涵盖以下示例：

+   使用颜色

+   设置小部件字体

+   使用选项数据库

+   更改光标图标

+   介绍文本小部件

+   向文本小部件添加标签

# 介绍

默认情况下，Tkinter 小部件将显示本机外观和感觉。虽然这种标准外观可能足够快速原型设计，但我们可能希望自定义一些小部件属性，如字体、颜色和背景。

这种自定义不仅影响小部件本身，还影响其内部项目。我们将深入研究文本小部件，它与画布小部件一样是最多功能的 Tkinter 类之一。文本小部件表示具有格式化内容的多行文本区域，具有几种方法，使得可以格式化字符或行并添加特定事件绑定。

# 使用颜色

在以前的示例中，我们使用颜色名称（如白色、蓝色或黄色）来设置小部件的颜色。这些值作为字符串传递给`foreground`和`background`选项，这些选项修改了小部件的文本和背景颜色。

颜色名称内部映射到**RGB**值（一种通过红、绿和蓝强度的组合来表示颜色的加法模型），这种转换基于一个因平台而异的表。因此，如果要在不同平台上一致显示相同的颜色，可以将 RGB 值传递给小部件选项。

# 准备就绪

以下应用程序显示了如何动态更改显示固定文本的标签的`foreground`和`background`选项： 

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/2988a6bc-c48d-49b5-843b-b37f4a7f858a.png)

颜色以 RGB 格式指定，并由用户使用本机颜色选择对话框选择。以下屏幕截图显示了 Windows 10 上的此对话框的外观：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/7be30749-7137-4489-9b0a-ed89b07827d5.png)

# 如何做...

像往常一样，我们将使用标准按钮触发小部件配置——每个选项一个按钮。与以前的示例的主要区别是，可以直接使用`tkinter.colorchooser`模块的`askcolor`对话框直接选择值：

```py
from functools import partial

import tkinter as tk
from tkinter.colorchooser import askcolor

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Colors demo")
        text = "The quick brown fox jumps over the lazy dog"
        self.label = tk.Label(self, text=text)
        self.fg_btn = tk.Button(self, text="Set foreground color",
                                command=partial(self.set_color, "fg")) 
        self.bg_btn = tk.Button(self, text="Set background color",
                                command=partial(self.set_color, "bg"))

        self.label.pack(padx=20, pady=20)
        self.fg_btn.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.bg_btn.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def set_color(self, option):
        color = askcolor()[1]
        print("Chosen color:", color)
        self.label.config(**{option: color})

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

如果要查看所选颜色的 RGB 值，在对话框确认时会在控制台上打印出来，如果关闭而没有选择颜色，则不会显示任何值。

# 它是如何工作的...

正如您可能已经注意到的，两个按钮都使用了部分函数作为回调。这是`functools`模块中的一个实用程序，它创建一个新的可调用对象，其行为类似于原始函数，但带有一些固定的参数。例如，考虑以下语句：

```py
tk.Button(self, command=partial(self.set_color, "fg"), ...)
```

前面的语句执行与以下语句相同的操作：

```py
tk.Button(self, command=lambda: self.set_color("fg"), ...)
```

我们这样做是为了同时重用我们的`set_color()`方法和引入`functools`模块。这些技术在更复杂的场景中非常有用，特别是当您想要组合多个函数并且非常清楚地知道一些参数已经预定义时。

要记住的一个小细节是，我们用`fg`和`bg`分别缩写了`foreground`和`background`。在这个语句中，这些字符串使用`**`进行解包，用于配置小部件：

```py
def set_color(self, option):
    color = askcolor()[1]
    print("Chosen color:", color)
    self.label.config(**{option: color}) # same as (fg=color)
                      or (bg=color)
```

`askcolor`返回一个包含两个项目的元组，表示所选颜色——第一个是表示 RGB 值的整数元组，第二个是十六进制代码作为字符串。由于第一个表示不能直接传递给小部件选项，我们使用了十六进制格式。

# 还有更多...

如果要将颜色名称转换为 RGB 格式，可以在先前创建的小部件上使用`winfo_rgb()`方法。由于它返回一个整数元组，表示 16 位 RGB 值的整数从 0 到 65535，您可以通过向右移动 8 位将其转换为更常见的*#RRGGBB*十六进制表示：

```py
rgb = widget.winfo_rgb("lightblue")
red, green, blue = [x>>8 for x in rgb]
print("#{:02x}{:02x}{:02x}".format(red, green, blue))
```

在前面的代码中，我们使用`{:02x}`将每个整数格式化为两个十六进制数字。

# 设置小部件字体

在 Tkinter 中，可以自定义用于向用户显示文本的小部件的字体，例如按钮、标签和输入框。默认情况下，字体是特定于系统的，但可以使用`font`选项进行更改。

# 准备工作

以下应用程序允许用户动态更改具有静态文本的标签的字体系列和大小。尝试不同的值以查看字体配置的结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/cd7bce85-0d22-479b-9990-315236013a54.png)

# 如何做...

我们将有两个小部件来修改字体配置：一个下拉选项，其中包含字体系列名称，以及一个输入字体大小的微调框：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Fonts demo")
        text = "The quick brown fox jumps over the lazy dog"
        self.label = tk.Label(self, text=text)

        self.family = tk.StringVar()
        self.family.trace("w", self.set_font)
        families = ("Times", "Courier", "Helvetica")
        self.option = tk.OptionMenu(self, self.family, *families)

        self.size = tk.StringVar()
        self.size.trace("w", self.set_font)
        self.spinbox = tk.Spinbox(self, from_=8, to=18,
                                  textvariable=self.size)

        self.family.set(families[0])
        self.size.set("10")
        self.label.pack(padx=20, pady=20)
        self.option.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.spinbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def set_font(self, *args):
        family = self.family.get()
        size = self.size.get()
        self.label.config(font=(family, size))

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

请注意，我们已为与每个输入连接的 Tkinter 变量设置了一些默认值。

# 它是如何工作的...

`FAMILIES`元组包含`Tk`保证在所有平台上支持的三种字体系列：`Times`（Times New Roman）、`Courier`和`Helvetica`。它们可以通过与`self.family`变量连接的`OptionMenu`小部件进行切换。

类似的方法用于使用`Spinbox`设置字体大小。这两个变量触发了更改`font`标签的方法：

```py
def set_font(self, *args):
    family = self.family.get()
    size = self.size.get()
    self.label.config(font=(family, size))
```

传递给`font`选项的元组还可以定义以下一个或多个字体样式：粗体、罗马体、斜体、下划线和删除线：

```py
widget1.config(font=("Times", "20", "bold"))
widget2.config(font=("Helvetica", "16", "italic underline"))
```

您可以使用`tkinter.font`模块的`families()`方法检索可用字体系列的完整列表。由于您需要首先实例化`root`窗口，因此可以使用以下脚本：

```py
import tkinter as tk
from tkinter import font

root = tk.Tk()
print(font.families())
```

如果您使用的字体系列未包含在可用系列列表中，Tkinter 不会抛出任何错误，而是会尝试匹配类似的字体。

# 还有更多...

`tkinter.font`模块包括一个`Font`类，可以在多个小部件上重复使用。修改`font`实例的主要优势是它会影响与`font`选项共享它的所有小部件。

使用`Font`类的工作方式与使用字体描述符非常相似。例如，此代码段创建一个 18 像素的`Courier`粗体字体：

```py
from tkinter import font
courier_18 = font.Font(family="Courier", size=18, weight=font.BOLD)
```

要检索或更改选项值，您可以像往常一样使用`cget`和`configure`方法：

```py
family = courier_18.cget("family")
courier_18.configure(underline=1)
```

# 另请参阅

+   *使用选项数据库*配方

# 使用选项数据库

Tkinter 定义了一个称为*选项数据库*的概念，这是一种用于自定义应用程序外观的机制，而无需为每个小部件指定它。它允许您将一些小部件选项与单个小部件配置分离开来，根据小部件层次结构提供标准化的默认值。

# 准备工作

在此配方中，我们将构建一个具有不同样式的多个小部件的应用程序，这些样式将在选项数据库中定义：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/ed5977dc-0974-4b65-8e65-d56373bfdbf7.png)

# 如何做...

在我们的示例中，我们将通过`option_add()`方法向数据库添加一些选项，该方法可以从所有小部件类访问：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Options demo")
        self.option_add("*font", "helvetica 10")
        self.option_add("*header.font", "helvetica 18 bold")
        self.option_add("*subtitle.font", "helvetica 14 italic")
        self.option_add("*Button.foreground", "blue")
        self.option_add("*Button.background", "white")
        self.option_add("*Button.activeBackground", "gray")
        self.option_add("*Button.activeForeground", "black")

        self.create_label(name="header", text="This is the header")
        self.create_label(name="subtitle", text="This is the subtitle")
        self.create_label(text="This is a paragraph")
        self.create_label(text="This is another paragraph")
        self.create_button(text="See more")

    def create_label(self, **options):
        tk.Label(self, **options).pack(padx=20, pady=5, anchor=tk.W)

    def create_button(self, **options):
        tk.Button(self, **options).pack(padx=5, pady=5, anchor=tk.E)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

因此，Tkinter 将使用选项数据库中定义的默认值，而不是与其他选项一起配置字体、前景和背景。

# 它是如何工作的...

让我们从解释对`option_add`的每个调用开始。第一次调用添加了一个选项，将`font`属性设置为所有小部件——通配符代表任何应用程序名称：

```py
self.option_add("*font", "helvetica 10")
```

下一个调用将匹配限制为具有`header`名称的元素——规则越具体，优先级越高。稍后在使用`name="header"`实例化标签时指定此名称：

```py
self.option_add("*header.font", "helvetica 18 bold")
```

对于`self.option_add("*subtitle.font", "helvetica 14 italic")`，也是一样的，所以每个选项都匹配到不同命名的小部件实例。

下一个选项使用`Button`类名而不是实例名。这样，您可以引用给定类的所有小部件以提供一些公共默认值：

```py
self.option_add("*Button.foreground", "blue")
self.option_add("*Button.background", "white")
self.option_add("*Button.activeBackground", "gray")
self.option_add("*Button.activeForeground", "black")
```

正如我们之前提到的，选项数据库使用小部件层次结构来确定适用于每个实例的选项，因此，如果我们有嵌套的容器，它们也可以用于限制优先级选项。

这些配置选项不适用于现有小部件，只适用于修改选项数据库后创建的小部件。因此，我们始终建议在应用程序开头调用`option_add()`。

这些是一些示例，每个示例比前一个更具体：

+   `*Frame*background`：匹配框架内所有小部件的背景

+   `*Frame.background`：匹配所有框架的背景

+   `*Frame.myButton.background`：匹配名为`myButton`的小部件的背景

+   `*myFrame.myButton.background`：匹配容器名为`myFrame`内名为`myButton`的小部件的背景

# 还有更多...

不仅可以通过编程方式添加选项，还可以使用以下格式在单独的文本文件中定义它们：

```py
*font: helvetica 10
*header.font: helvetica 18 bold
*subtitle.font: helvetica 14 italic
*Button.foreground: blue
*Button.background: white
*Button.activeBackground: gray
*Button.activeForeground: black
```

这个文件应该使用`option_readfile()`方法加载到应用程序中，并替换所有对`option_add()`的调用。在我们的示例中，假设文件名为`my_options_file`，并且它放在与我们的脚本相同的目录中：

```py
def __init__(self):
        super().__init__()
        self.title("Options demo")
        self.option_readfile("my_options_file")
        # ...
```

如果文件不存在或其格式无效，Tkinter 将引发`TclError`。

# 另请参阅

+   使用颜色

+   设置小部件字体

# 更改光标图标

Tkinter 允许您在悬停在小部件上时自定义光标图标。这种行为有时是默认启用的，比如显示 I 型光标的 Entry 小部件。

# 准备工作

以下应用程序显示了如何在执行长时间操作时显示繁忙光标，以及在帮助菜单中通常使用的带有问号的光标：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/c660453b-6895-4f3e-a6ed-87a59c90693d.png)

# 如何做...

鼠标指针图标可以使用`cursor`选项更改。在我们的示例中，我们使用`watch`值来显示本机繁忙光标，`question_arrow`来显示带有问号的常规箭头：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cursors demo")
        self.resizable(0, 0)
        self.label = tk.Label(self, text="Click the button to start")
        self.btn_launch = tk.Button(self, text="Start!",
                                    command=self.perform_action)
        self.btn_help = tk.Button(self, text="Help",
                                  cursor="question_arrow")

        btn_opts = {"side": tk.LEFT, "expand":True, "fill": tk.X,
                    "ipadx": 30, "padx": 20, "pady": 5}
        self.label.pack(pady=10)
        self.btn_launch.pack(**btn_opts)
        self.btn_help.pack(**btn_opts)

    def perform_action(self):
        self.config(cursor="watch")
        self.btn_launch.config(state=tk.DISABLED)
        self.btn_help.config(state=tk.DISABLED)
        self.label.config(text="Working...")
        self.after(3000, self.end_action)

    def end_action(self):
        self.config(cursor="arrow")
        self.btn_launch.config(state=tk.NORMAL)
        self.btn_help.config(state=tk.NORMAL)
        self.label.config(text="Done!")

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

您可以在官方 Tcl/Tk 文档的[`www.tcl.tk/man/tcl/TkCmd/cursors.htm`](https://www.tcl.tk/man/tcl/TkCmd/cursors.htm)中查看有效`cursor`值和特定于系统的完整列表。

# 它是如何工作的...

如果一个小部件没有指定`cursor`选项，它将采用父容器中定义的值。因此，我们可以通过在`root`窗口级别设置它来轻松地将其应用于所有小部件。这是通过在`perform_action()`方法中调用`set_watch_cursor()`来完成的：

```py
def perform_action(self):
    self.config(cursor="watch")
    # ...
```

这里的例外是`Help`按钮，它明确将光标设置为`question_arrow`。此选项也可以在实例化小部件时直接设置：

```py
self.btn_help = tk.Button(self, text="Help",
                          cursor="question_arrow")
```

# 还有更多...

请注意，如果在调用预定方法之前单击`Start!`按钮并将鼠标放在`Help`按钮上，光标将显示为`help`而不是`watch`。这是因为如果小部件的`cursor`选项已设置，它将优先于父容器中定义的`cursor`。

为了避免这种情况，我们可以保存当前的`cursor`值并将其更改为`watch`，然后稍后恢复它。执行此操作的函数可以通过迭代`winfo_children()`列表在子小部件中递归调用：

```py
def perform_action(self):
    self.set_watch_cursor(self)
    # ...

def end_action(self):
 self.restore_cursor(self)
    # ...

def set_watch_cursor(self, widget):
    widget._old_cursor = widget.cget("cursor")
    widget.config(cursor="watch")
    for w in widget.winfo_children():
        self.set_watch_cursor(w)

def restore_cursor(self, widget):
    widget.config(cursor=widget._old_cursor)
    for w in widget.winfo_children():
        self.restore_cursor(w)
```

在前面的代码中，我们为每个小部件添加了`_old_cursor`属性，因此如果您遵循类似的方法，请记住在`set_watch_cursor()`之前不能调用`restore_cursor()`。

# 介绍 Text 小部件

Text 小部件提供了与其他小部件类相比更高级的功能。它显示可编辑文本的多行，可以按行和列进行索引。此外，您可以使用标签引用文本范围，这些标签可以定义自定义外观和行为。

# 准备工作

以下应用程序展示了 `Text` 小部件的基本用法，您可以动态插入和删除文本，并检索所选内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/a753a28a-5bb3-434a-8efd-712c2e758a2e.png)

# 如何做...

除了 `Text` 小部件，我们的应用程序还包含三个按钮，这些按钮调用方法来清除整个文本内容，在当前光标位置插入`"Hello, world"`字符串，并打印用鼠标或键盘进行的当前选择：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Text demo")
        self.resizable(0, 0)
        self.text = tk.Text(self, width=50, height=10)
        self.btn_clear = tk.Button(self, text="Clear text",
                                   command=self.clear_text)
        self.btn_insert = tk.Button(self, text="Insert text",
                                    command=self.insert_text)
        self.btn_print = tk.Button(self, text="Print selection",
                                   command=self.print_selection)
        self.text.pack()
        self.btn_clear.pack(side=tk.LEFT, expand=True, pady=10)
        self.btn_insert.pack(side=tk.LEFT, expand=True, pady=10)
        self.btn_print.pack(side=tk.LEFT, expand=True, pady=10)

    def clear_text(self):
        self.text.delete("1.0", tk.END)

    def insert_text(self):
        self.text.insert(tk.INSERT, "Hello, world")

    def print_selection(self):
        selection = self.text.tag_ranges(tk.SEL)
        if selection:
            content = self.text.get(*selection)
            print(content)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

我们的 `Text` 小部件最初是空的，宽度为 50 个字符，高度为 10 行。除了允许用户输入任何类型的文本，我们还将深入研究每个按钮使用的方法，以更好地了解如何与这个小部件交互。

`delete(start, end)` 方法从 `start` 索引到 `end` 索引删除内容。如果省略第二个参数，它只删除 `start` 位置的字符。

在我们的示例中，我们通过从 `1.0` 索引（第一行的第 0 列）调用此方法到 `tk.END` 索引（指向最后一个字符）来删除所有文本：

```py
def clear_text(self):
    self.text.delete("1.0", tk.END)
```

`insert(index, text)` 方法在`index`位置插入给定的文本。在这里，我们使用`INSERT`索引调用它，该索引对应于插入光标的位置：

```py
def insert_text(self):
    self.text.insert(tk.INSERT, "Hello, world")
```

`tag_ranges(tag)` 方法返回一个元组，其中包含给定 `tag` 的所有范围的第一个和最后一个索引。我们使用特殊的 `tk.SEL` 标签来引用当前选择。如果没有选择，这个调用会返回一个空元组。这与 `get(start, end)` 方法结合使用，该方法返回给定范围内的文本：

```py
def print_selection(self):
    selection = self.text.tag_ranges(tk.SEL)
    if selection:
        content = self.text.get(*selection)
        print(content)
```

由于 `SEL` 标签只对应一个范围，我们可以安全地解包它来调用 `get` 方法。

# 向 Text 小部件添加标记

在本示例中，您将学习如何配置 `Text` 小部件中标记的字符范围的行为。

所有的概念都与适用于常规小部件的概念相同，比如事件序列或配置选项，这些概念在之前的示例中已经涵盖过了。主要的区别是，我们需要使用文本索引来识别标记的内容，而不是使用对象引用。

# 准备工作

为了说明如何使用文本标记，我们将创建一个模拟插入超链接的 `Text` 小部件。点击时，此链接将使用默认浏览器打开所选的 URL。

例如，如果用户输入以下内容，`python.org` 文本可以被标记为超链接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/8a673cd4-d0d1-438b-b1d9-44ae42a5aa4e.png)

# 如何做...

对于此应用程序，我们将定义一个名为`"link"`的标记，它表示可点击的超链接。此标记将被添加到当前选择中，鼠标点击将触发打开浏览器中的链接的事件：

```py
import tkinter as tk
import webbrowser

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Text tags demo")
        self.text = tk.Text(self, width=50, height=10)
        self.btn_link = tk.Button(self, text="Add hyperlink",
                                  command=self.add_hyperlink)

        self.text.tag_config("link", foreground="blue", underline=1)
        self.text.tag_bind("link", "<Button-1>", self.open_link)
        self.text.tag_bind("link", "<Enter>",
                           lambda _: self.text.config(cursor="hand2"))
        self.text.tag_bind("link", "<Leave>",
                           lambda e: self.text.config(cursor=""))

        self.text.pack()
        self.btn_link.pack(expand=True)

    def add_hyperlink(self):
        selection = self.text.tag_ranges(tk.SEL)
        if selection:
            self.text.tag_add("link", *selection)

    def open_link(self, event):
        position = "@{},{} + 1c".format(event.x, event.y)
        index = self.text.index(position)
        prevrange = self.text.tag_prevrange("link", index)
        url = self.text.get(*prevrange)
        webbrowser.open(url)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

首先，我们将通过配置颜色和下划线样式来初始化标记。我们添加事件绑定来使用浏览器打开点击的文本，并在鼠标悬停在标记文本上时改变光标外观：

```py
def __init__(self):
    # ...
    self.text.tag_config("link", foreground="blue", underline=1)
    self.text.tag_bind("link", "<Button-1>", self.open_link)
    self.text.tag_bind("link", "<Enter>",
                       lambda e: self.text.config(cursor="hand2"))
    self.text.tag_bind("link", "<Leave>",
                       lambda e: self.text.config(cursor=""))
```

在 `open_link` 方法中，我们使用 `Text` 类的 `index` 方法将点击的位置转换为相应的行和列：

```py
position = "@{},{} + 1c".format(event.x, event.y)
index = self.text.index(position)
prevrange = self.text.tag_prevrange("link", index)
```

请注意，与点击的索引对应的位置是`"@x,y"`，但我们将其移动到下一个字符。我们这样做是因为 `tag_prevrange` 返回给定索引的前一个范围，因此如果我们点击第一个字符，它将不返回当前范围。

最后，我们将从范围中检索文本，并使用 `webbrowser` 模块的 `open` 函数在默认浏览器中打开它：

```py
url = self.text.get(*prevrange)
webbrowser.open(url)
```

# 还有更多...

由于 `webbrowser.open` 函数不检查 URL 是否有效，可以通过包含基本的超链接验证来改进此应用程序。例如，您可以使用 `urlparse` 函数来验证 URL 是否具有网络位置：

```py
from urllib.parse import urlparse def validate_hyperlink(self, url):
    return urlparse(url).netloc
```

尽管这个解决方案并不打算处理一些特殊情况，但它可能作为丢弃大多数无效 URL 的第一步。

一般来说，您可以使用标签来创建复杂的基于文本的程序，比如带有语法高亮的 IDE。事实上，IDLE——默认的 Python 实现中捆绑的——就是基于 Tkinter 的。

# 另请参阅

+   *更改光标图标*食谱

+   *介绍文本小部件*食谱
