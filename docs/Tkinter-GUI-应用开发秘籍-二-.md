# Tkinter GUI 应用开发秘籍（二）

> 原文：[`zh.annas-archive.org/md5/398a043f4e87ae54140cbfe923282feb`](https://zh.annas-archive.org/md5/398a043f4e87ae54140cbfe923282feb)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：对话框和菜单

在本章中，我们将涵盖以下配方：

+   显示警报对话框

+   要求用户确认

+   选择文件和目录

+   将数据保存到文件中

+   创建菜单栏

+   在菜单中使用变量

+   显示上下文菜单

+   打开次要窗口

+   在窗口之间传递变量

+   处理窗口删除

# 介绍

几乎每个非平凡的 GUI 应用程序都由多个视图组成。在浏览器中，这是通过从一个 HTML 页面导航到另一个页面实现的，在桌面应用程序中，它由用户可以与之交互的多个窗口和对话框表示。

到目前为止，我们只学习了如何创建一个与 Tcl 解释器关联的根窗口。但是，Tkinter 允许我们在同一个应用程序下创建多个顶级窗口，并且还包括具有内置对话框的特定模块。

另一种构造应用程序导航的方法是使用菜单，通常在桌面应用程序的标题栏下显示。在 Tkinter 中，这些菜单由一个小部件类表示；我们将在稍后深入研究其方法以及如何将其与我们应用程序的其余部分集成。

# 显示警报对话框

对话框的一个常见用例是通知用户应用程序中发生的事件，例如记录已保存，或者无法打开文件。现在我们将看一下 Tkinter 中包含的一些基本函数来显示信息对话框。

# 准备就绪

我们的程序将有三个按钮，每个按钮都显示一个不同的对话框，具有静态标题和消息。这种类型的对话框框只有一个确认和关闭对话框的按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/6bf8de6b-3907-4221-9ea0-3fc4a4fabd9a.png)

当您运行上面的示例时，请注意每个对话框都会播放由您的平台定义的相应声音，并且按钮标签会被翻译成您的语言：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/55c3bc6c-eb7e-4198-8f1a-4ee12827f024.png)

# 如何做...

在前面的*准备就绪*部分提到的三个对话框是使用`tkinter.messagebox`模块中的`showinfo`、`showwarning`和`showerror`函数打开的：

```py
import tkinter as tk
import tkinter.messagebox as mb

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        btn_info = tk.Button(self, text="Show Info",
                             command=self.show_info)
        btn_warn = tk.Button(self, text="Show Warning",
                             command=self.show_warning)
        btn_error = tk.Button(self, text="Show Error",
                              command=self.show_error)

        opts = {'padx': 40, 'pady': 5, 'expand': True, 'fill': tk.BOTH}
        btn_info.pack(**opts)
        btn_warn.pack(**opts)
        btn_error.pack(**opts)

    def show_info(self):
        msg = "Your user preferences have been saved"
        mb.showinfo("Information", msg)

    def show_warning(self):
        msg = "Temporary files have not been correctly removed"
        mb.showwarning("Warning", msg)

    def show_error(self):
        msg = "The application has encountered an unknown error"
        mb.showerror("Error", msg)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

首先，我们使用较短的别名`mb`导入了`tkinter.messagebox`模块。这个模块在 Python 2 中被命名为`tkMessageBox`，因此这种语法也有助于我们将兼容性问题隔离在一个语句中。

每个对话框通常根据通知给用户的信息类型而使用：

+   `showinfo`：操作成功完成

+   `showwarning`：操作已完成，但某些内容未按预期行为

+   `showerror`：由于错误操作失败

这三个函数接收两个字符串作为输入参数：第一个显示在标题栏上，第二个对应对话框显示的消息。

对话框消息也可以通过添加换行字符`\n`跨多行生成。

# 要求用户确认

Tkinter 中包括的其他类型的对话框是用于要求用户确认的对话框，例如当我们要保存文件并且要覆盖同名文件时显示的对话框。

这些对话框与前面的对话框不同，因为函数返回的值将取决于用户点击的确认按钮。这样，我们可以与程序交互，指示是否继续或取消操作。

# 准备就绪

在这个配方中，我们将涵盖`tkinter.messagebox`模块中定义的其余对话框函数。每个按钮上都标有单击时打开的对话框类型：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/fdcf033f-5f95-4a30-80e5-775993a13713.png)

由于这些对话框之间存在一些差异，您可以尝试它们，以查看哪一个可能更适合您每种情况的需求：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/58981fea-4262-4b93-b599-d6baf00fe9f4.png)

# 如何做...

与我们在前面的示例中所做的一样，我们将使用`import ... as`语法导入`tkinter.messagebox`并调用每个函数与`title`和`message`： 

```py
import tkinter as tk
import tkinter.messagebox as mb

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.create_button(mb.askyesno, "Ask Yes/No",
                           "Returns True or False")
        self.create_button(mb.askquestion, "Ask a question",
                           "Returns 'yes' or 'no'")
        self.create_button(mb.askokcancel, "Ask Ok/Cancel",
                           "Returns True or False")
        self.create_button(mb.askretrycancel, "Ask Retry/Cancel",
                           "Returns True or False")
        self.create_button(mb.askyesnocancel, "Ask Yes/No/Cancel",
                           "Returns True, False or None")

    def create_button(self, dialog, title, message):
        command = lambda: print(dialog(title, message))
        btn = tk.Button(self, text=title, command=command)
        btn.pack(padx=40, pady=5, expand=True, fill=tk.BOTH)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

为了避免重复编写按钮实例化和回调方法的代码，我们定义了一个`create_button`方法，以便根据需要多次重用它以添加所有带有其对话框的按钮。命令只是简单地打印作为参数传递的`dialog`函数的结果，以便我们可以看到根据点击的按钮返回的值来回答对话框。

# 选择文件和目录

文件对话框允许用户从文件系统中选择一个或多个文件。在 Tkinter 中，这些函数声明在`tkinter.filedialog`模块中，该模块还包括用于选择目录的对话框。它还允许您自定义新对话框的行为，例如通过其扩展名过滤文件或选择对话框显示的初始目录。

# 准备工作

我们的应用程序将包含两个按钮。第一个将被标记为选择文件，并且它将显示一个对话框以选择文件。默认情况下，它只会显示具有`.txt`扩展名的文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/7f9c5028-420b-4ff0-b74b-840a8521687a.png)

第二个按钮将是选择目录，并且它将打开一个类似的对话框以选择目录：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/04091bd1-b45c-4a74-8168-0cc0eca082a4.png)

两个按钮都将打印所选文件或目录的完整路径，并且如果对话框被取消，将不执行任何操作。

# 如何做...

我们应用程序的第一个按钮将触发对`askopenfilename`函数的调用，而第二个按钮将调用`askdirectory`函数：

```py
import tkinter as tk
import tkinter.filedialog as fd

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        btn_file = tk.Button(self, text="Choose file",
                             command=self.choose_file)
        btn_dir = tk.Button(self, text="Choose directory",
                             command=self.choose_directory)
        btn_file.pack(padx=60, pady=10)
        btn_dir.pack(padx=60, pady=10)

    def choose_file(self):
        filetypes = (("Plain text files", "*.txt"),
                     ("Images", "*.jpg *.gif *.png"),
                     ("All files", "*"))
        filename = fd.askopenfilename(title="Open file", 
                   initialdir="/", filetypes=filetypes)
        if filename:
            print(filename)

    def choose_directory(self):
        directory = fd.askdirectory(title="Open directory", 
                                    initialdir="/")
        if directory:
            print(directory)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

由于这些对话框可能会被关闭，我们添加了条件语句来检查对话框函数在将其打印到控制台之前是否返回了非空字符串。我们需要在任何必须对此路径执行操作的应用程序中进行此验证，例如读取或复制文件，或更改权限。

# 它是如何工作的...

我们使用`askopenfilename`函数创建第一个对话框，该函数返回一个表示所选文件的完整路径的字符串。它接受以下可选参数：

+   `title`：对话框标题栏中显示的标题。

+   `initialdir`：初始目录。

+   `filetypes`：两个字符串元组的序列。第一个是以人类可读格式指示文件类型的标签，而第二个是用于匹配文件名的模式。

+   `multiple`：布尔值，指示用户是否可以选择多个文件。

+   `defaultextension`：如果未明确给出文件名，则添加到文件名的扩展名。

在我们的示例中，我们将初始目录设置为根文件夹和自定义标题。在我们的文件类型元组中，我们有以下三个有效选择：使用`.txt`扩展名保存的文本文件；带有`.jpg`、`.gif`和`.png`扩展名的图像；以及通配符(`"*"`)以匹配所有文件。

请注意，这些模式不一定与文件中包含的数据的格式匹配，因为可以使用不同的扩展名重命名文件：

```py
filetypes = (("Plain text files", "*.txt"),
             ("Images", "*.jpg *.gif *.png"),
             ("All files", "*"))
filename = fd.askopenfilename(title="Open file", initialdir="/",
                              filetypes=filetypes)
```

`askdirectory`函数还接受`title`和`initialdir`参数，以及一个`mustexist`布尔选项，指示用户是否必须选择现有目录：

```py
directory = fd.askdirectory(title="Open directory", initialdir="/")
```

# 还有更多...

`tkinter.filedialog`模块包括这些函数的一些变体，允许您直接检索文件对象。

例如，`askopenfile`返回与所选文件对应的文件对象，而不必使用`askopenfilename`返回的路径调用`open`。我们仍然必须检查对话框在调用文件方法之前是否已被关闭：

```py
import tkinter.filedialog as fd

filetypes = (("Plain text files", "*.txt"),)
my_file = fd.askopenfile(title="Open file", filetypes=filetypes)
if my_file:
    print(my_file.readlines())
    my_file.close()
```

# 将数据保存到文件中

除了选择现有文件和目录外，还可以使用 Tkinter 对话框创建新文件。它们可用于保存应用程序生成的数据，让用户选择新文件的名称和位置。

# 准备工作

我们将使用保存文件对话框将文本窗口小部件的内容写入纯文本文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/1d7858dc-1a91-4591-8f72-08ee9d0c6f1d.png)

# 如何做...

要打开保存文件的对话框，我们从`tkinter.filedialog`模块调用`asksaveasfile`函数。它内部使用`'w'`模式创建文件对象进行写入，或者如果对话框被关闭，则返回`None`：

```py
import tkinter as tk
import tkinter.filedialog as fd

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.text = tk.Text(self, height=10, width=50)
        self.btn_save = tk.Button(self, text="Save",
                                  command=self.save_file)

        self.text.pack()
        self.btn_save.pack(pady=10, ipadx=5)

    def save_file(self):
        contents = self.text.get(1.0, tk.END)
        new_file = fd.asksaveasfile(title="Save file",
                                    defaultextension=".txt",
                                    filetypes=(("Text files", 
                                                "*.txt"),))
        if new_file:
            new_file.write(contents)
            new_file.close()

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理...

`asksaveasfile`函数接受与`askopenfile`函数相同的可选参数，但还允许您使用`defaultextension`选项默认添加文件扩展名。

为了防止用户意外覆盖先前的文件，此对话框会在您尝试保存与现有文件同名的新文件时自动警告您。

有了文件对象，我们可以写入 Text 小部件的内容-始终记得关闭文件以释放对象占用的资源：

```py
contents = self.text.get(1.0, tk.END)
new_file.write(contents)
new_file.close()
```

# 还有更多...

在前面的食谱中，我们看到有一个等价于`askopenfilename`的函数，它返回一个文件对象而不是一个字符串，名为`askopenfile`。

要保存文件，还有一个`asksaveasfilename`函数，它返回所选文件的路径。如果要在打开文件进行写入之前修改路径或执行任何验证，可以使用此函数。

# 另请参阅

+   *选择文件和目录*食谱

# 创建菜单栏

复杂的 GUI 通常使用菜单栏来组织应用程序中可用的操作和导航。这种模式也用于将紧密相关的操作分组，例如大多数文本编辑器中包含的“文件”菜单。

Tkinter 本地支持这些菜单，显示为目标桌面环境的外观和感觉。因此，您不必使用框架或标签模拟它们，因为这样会丢失 Tkinter 中已经构建的跨平台功能。

# 准备工作

我们将首先向根窗口添加一个菜单栏，并嵌套下拉菜单。在 Windows 10 上，显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/42b9c97d-a199-40bb-8c16-7be46d4ec632.png)

# 如何做...

Tkinter 有一个`Menu`小部件类，可用于许多种类型的菜单，包括顶部菜单栏。与任何其他小部件类一样，菜单是用父容器作为第一个参数和一些可选的配置选项来实例化的：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=0)

        file_menu.add_command(label="New file")
        file_menu.add_command(label="Open")
        file_menu.add_separator()
        file_menu.add_command(label="Save")
        file_menu.add_command(label="Save as...")

        menu.add_cascade(label="File", menu=file_menu)
        menu.add_command(label="About")
        menu.add_command(label="Quit", command=self.destroy)
        self.config(menu=menu)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

如果运行上述脚本，您会看到“文件”条目显示次级菜单，并且可以通过单击“退出”菜单按钮关闭应用程序。

# 工作原理...

首先，我们实例化每个菜单，指定父容器。`tearoff`选项默认设置为`1`，表示菜单可以通过单击其顶部边框的虚线分离。这种行为不适用于顶部菜单栏，但如果我们想要停用此功能，就必须将此选项设置为`0`：

```py
    def __init__(self):
        super().__init__()
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=0)
```

菜单条目按照它们添加的顺序排列，使用`add_command`、`add_separator`和`add_cascade`方法：

```py
menu.add_cascade(label="File", menu=file_menu)
menu.add_command(label="About")
menu.add_command(label="Quit", command=self.destroy)
```

通常，`add_command`与`command`选项一起调用，当单击条目时会调用回调。与 Button 小部件的`command`选项一样，回调函数不会传递任何参数。

为了举例说明，我们只在“退出”选项中添加了这个选项，以销毁`Tk`实例并关闭应用程序。

最后，我们通过调用`self.config(menu=menu)`将菜单附加到顶层窗口。请注意，每个顶层窗口只能配置一个菜单栏。

# 在菜单中使用变量

除了调用命令和嵌套子菜单外，还可以将 Tkinter 变量连接到菜单条目。

# 准备工作

我们将向“选项”子菜单添加一个复选框条目和三个单选按钮条目，之间用分隔符分隔。将有两个基础的 Tkinter 变量来存储所选值，因此我们可以轻松地从应用程序的其他方法中检索它们：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/d882404a-5f1c-428e-b30d-784413ff31e6.png)

# 如何做...

这些类型的条目是使用`Menu`小部件类的`add_checkbutton`和`add_radiobutton`方法添加的。与常规单选按钮一样，所有条目都连接到相同的 Tkinter 变量，但每个条目设置不同的值：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.checked = tk.BooleanVar()
        self.checked.trace("w", self.mark_checked)
        self.radio = tk.StringVar()
        self.radio.set("1")
        self.radio.trace("w", self.mark_radio)

        menu = tk.Menu(self)
        submenu = tk.Menu(menu, tearoff=0)

        submenu.add_checkbutton(label="Checkbutton", onvalue=True,
                                offvalue=False, variable=self.checked)
        submenu.add_separator()
        submenu.add_radiobutton(label="Radio 1", value="1",
                                variable=self.radio)
        submenu.add_radiobutton(label="Radio 2", value="2",
                                variable=self.radio)
        submenu.add_radiobutton(label="Radio 3", value="3",
                                variable=self.radio)

        menu.add_cascade(label="Options", menu=submenu)
        menu.add_command(label="Quit", command=self.destroy)
        self.config(menu=menu)

    def mark_checked(self, *args):
        print(self.checked.get())

    def mark_radio(self, *args):
        print(self.radio.get())

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

此外，我们正在跟踪变量更改，以便在运行此应用程序时可以在控制台上看到打印的值。

# 工作原理...

要将布尔变量连接到`Checkbutton`条目，我们首先定义`BooleanVar`，然后使用`variable`选项调用`add_checkbutton`创建条目。

请记住，`onvalue`和`offvalue`选项应与 Tkinter 变量的类型匹配，就像我们在常规 RadioButton 和 CheckButton 小部件中所做的那样：

```py
self.checked = tk.BooleanVar()
self.checked.trace("w", self.mark_checked)
# ...
submenu.add_checkbutton(label="Checkbutton", onvalue=True,
                        offvalue=False, variable=self.checked)
```

`Radiobutton`条目是使用`add_radiobutton`方法以类似的方式创建的，当单击单选按钮时，只需设置一个`value`选项即可将其设置为 Tkinter 变量。由于`StringVar`最初保存空字符串值，因此我们将其设置为第一个单选按钮值，以便它显示为已选中：

```py
self.radio = tk.StringVar()
self.radio.set("1")
self.radio.trace("w", self.mark_radio)
# ...        
submenu.add_radiobutton(label="Radio 1", value="1",
                        variable=self.radio)
submenu.add_radiobutton(label="Radio 2", value="2",
                        variable=self.radio)
submenu.add_radiobutton(label="Radio 3", value="3",
                        variable=self.radio)
```

两个变量都使用`mark_checked`和`mark_radio`方法跟踪更改，这些方法只是将变量值打印到控制台。

# 显示上下文菜单

Tkinter 菜单不一定要位于菜单栏上，而实际上可以自由放置在任何坐标。这些类型的菜单称为上下文菜单，通常在用户右键单击项目时显示。

上下文菜单广泛用于 GUI 应用程序；例如，文件浏览器显示它们以提供有关所选文件的可用操作，因此用户知道如何与它们交互是直观的。

# 准备工作

我们将为文本小部件构建一个上下文菜单，以显示文本编辑器的一些常见操作，例如剪切、复制、粘贴和删除：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/c344d057-cdb3-4c33-9a5c-1cc2ecf55991.png)

# 如何做...

不是使用顶级容器作为顶部菜单栏来配置菜单实例，而是可以使用其`post`方法将其明确放置。

菜单条目中的所有命令都调用一个使用文本实例来检索当前选择或插入位置的方法：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Cut", command=self.cut_text)
        self.menu.add_command(label="Copy", command=self.copy_text)
        self.menu.add_command(label="Paste", command=self.paste_text)
        self.menu.add_command(label="Delete", command=self.delete_text)

        self.text = tk.Text(self, height=10, width=50)
        self.text.bind("<Button-3>", self.show_popup)
        self.text.pack()

    def show_popup(self, event):
        self.menu.post(event.x_root, event.y_root)

    def cut_text(self):
        self.copy_text()
        self.delete_text()

    def copy_text(self):
        selection = self.text.tag_ranges(tk.SEL)
        if selection:
            self.clipboard_clear()
            self.clipboard_append(self.text.get(*selection))

    def paste_text(self):
        self.text.insert(tk.INSERT, self.clipboard_get())

    def delete_text(self):
        selection = self.text.tag_ranges(tk.SEL)
        if selection:
            self.text.delete(*selection)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理...

我们将右键单击事件绑定到文本实例的`show_popup`处理程序，该处理程序将菜单显示在右键单击位置的左上角。每次触发此事件时，都会再次显示相同的菜单实例：

```py
def show_popup(self, event):
    self.menu.post(event.x_root, event.y_root)
```

对所有小部件类可用的以下方法与剪贴板交互：

+   清除剪贴板中的数据

+   `clipboard_append(string)`: 将字符串附加到剪贴板

+   `clipboard_get()`: 从剪贴板返回数据

*复制*操作的回调方法获取当前选择并将其添加到剪贴板：

```py
    def copy_text(self):
        selection = self.text.tag_ranges(tk.SEL)
        if selection:
            self.clipboard_clear()
 self.clipboard_append(self.text.get(*selection))
```

*粘贴*操作将剪贴板内容插入到由`INSERT`索引定义的插入光标位置。我们必须将此包装在`try...except`块中，因为调用`clipboard_get`会在剪贴板为空时引发`TclError`：

```py
    def paste_text(self):
        try:
 self.text.insert(tk.INSERT, self.clipboard_get())
        except tk.TclError:
            pass
```

*删除*操作不与剪贴板交互，但会删除当前选择的内容：

```py
    def delete_text(self):
        selection = self.text.tag_ranges(tk.SEL)
        if selection:
            self.text.delete(*selection)
```

由于剪切操作是复制和删除的组合，我们重用这些方法来组成其回调函数。

# 还有更多...

`postcommand`选项允许您使用`post`方法每次显示菜单时重新配置菜单。为了说明如何使用此选项，如果文本小部件中没有当前选择，则我们将禁用剪切、复制和删除条目，并且如果剪贴板中没有内容，则禁用粘贴条目。

与我们的其他回调函数一样，我们传递了对我们类的方法的引用以添加此配置选项：

```py
def __init__(self):
    super().__init__()
    self.menu = tk.Menu(self, tearoff=0, 
    postcommand=self.enable_selection)
```

然后，我们检查`SEL`范围是否存在，以确定条目的状态应为`ACTIVE`或`DISABLED`。将此值传递给`entryconfig`方法，该方法以要配置的条目的索引作为其第一个参数，并以要更新的选项列表作为其第二个参数-请记住菜单条目是`0`索引的：

```py
def enable_selection(self):
    state_selection = tk.ACTIVE if self.text.tag_ranges(tk.SEL) 
                      else tk.DISABLED
    state_clipboard = tk.ACTIVE
    try:
        self.clipboard_get()
    except tk.TclError:
        state_clipboard = tk.DISABLED

    self.menu.entryconfig(0, state=state_selection) # Cut
    self.menu.entryconfig(1, state=state_selection) # Copy
    self.menu.entryconfig(2, state=state_clipboard) # Paste
    self.menu.entryconfig(3, state=state_selection) # Delete
```

例如，如果没有选择或剪贴板上没有内容，所有条目都应该变灰。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/f731180c-8a40-4ad9-a552-df57e3a48a4b.png)

使用`entryconfig`，还可以配置许多其他选项，如标签、字体和背景。请参阅[`www.tcl.tk/man/tcl8.6/TkCmd/menu.htm#M48`](https://www.tcl.tk/man/tcl8.6/TkCmd/menu.htm#M48)以获取可用条目选项的完整参考。

# 打开一个次要窗口

根`Tk`实例代表我们 GUI 的主窗口——当它被销毁时，应用程序退出，事件主循环结束。

然而，在我们的应用程序中创建额外的顶层窗口的另一个 Tkinter 类是`Toplevel`。您可以使用这个类来显示任何类型的窗口，从自定义对话框到向导表单。

# 准备就绪

我们将首先创建一个简单的窗口，当主窗口的按钮被点击时打开。它将包含一个关闭它并将焦点返回到主窗口的按钮：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/f4f3b50d-7dd0-487d-8db4-022b57435aac.png)

# 如何做...

`Toplevel`小部件类创建一个新的顶层窗口，它像`Tk`实例一样作为父容器。与`Tk`类不同，您可以实例化任意数量的顶层窗口：

```py
import tkinter as tk

class Window(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.label = tk.Label(self, text="This is another window")
        self.button = tk.Button(self, text="Close", 
                                command=self.destroy)

        self.label.pack(padx=20, pady=20)
        self.button.pack(pady=5, ipadx=2, ipady=2)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.btn = tk.Button(self, text="Open new window",
                             command=self.open_window)
        self.btn.pack(padx=50, pady=20)

    def open_window(self):
        window = Window(self)
        window.grab_set()

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

我们定义一个`Toplevel`子类来表示我们的自定义窗口，它与父窗口的关系在它的`__init__`方法中定义。小部件被添加到这个窗口，因为我们遵循与子类化`Tk`相同的约定：

```py
class Window(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
```

通过简单地创建一个新实例来打开窗口，但是为了使其接收所有事件，我们必须调用它的`grab_set`方法。这可以防止用户与主窗口交互，直到该窗口关闭为止。

```py
def open_window(self):
    window = Window(self)
 window.grab_set()
```

# 处理窗口删除

在某些情况下，您可能希望在用户关闭顶层窗口之前执行某个操作，例如，以防止丢失未保存的工作。Tkinter 允许您拦截这种类型的事件以有条件地销毁窗口。

# 准备就绪

我们将重用前面一篇文章中的`App`类，并修改`Window`类以显示一个对话框来确认关闭窗口：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/4c58c76f-dc88-4947-ba95-45a14f8417e0.png)

# 如何做...

在 Tkinter 中，我们可以通过为`WM_DELETE_WINDOW`协议注册处理程序函数来检测窗口即将关闭的情况。这可以通过在大多数桌面环境的标题栏上点击 X 按钮来触发：

```py
import tkinter as tk
import tkinter.messagebox as mb

class Window(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.protocol("WM_DELETE_WINDOW", self.confirm_delete)

        self.label = tk.Label(self, text="This is another window")
        self.button = tk.Button(self, text="Close", 
                                command=self.destroy)

        self.label.pack(padx=20, pady=20)
        self.button.pack(pady=5, ipadx=2, ipady=2)

    def confirm_delete(self):
        message = "Are you sure you want to close this window?"
        if mb.askyesno(message=message, parent=self):
            self.destroy()
```

我们的处理程序方法显示一个对话框来确认窗口删除。在更复杂的程序中，这种逻辑通常会通过额外的验证来扩展。

# 它是如何工作的...

`bind()`方法用于为小部件事件注册处理程序，`protocol`方法用于为窗口管理器协议注册处理程序。

当顶层窗口即将关闭时，`WM_DELETE_WINDOW`处理程序被调用，默认情况下，`Tk`会销毁接收到它的窗口。由于我们通过注册`confirm_delete`处理程序来覆盖此行为，如果对话框得到确认，它需要显式销毁窗口。

另一个有用的协议是`WM_TAKE_FOCUS`，当窗口获得焦点时会调用它。

# 还有更多...

请记住，为了在显示对话框时保持第二个窗口的焦点，我们必须将对顶层实例的引用，`parent`选项，传递给对话框函数：

```py
if mb.askyesno(message=message, parent=self):
    self.destroy()
```

否则，对话框将以根窗口为其父窗口，并且您会看到它弹出到第二个窗口上。这些怪癖可能会让您的用户感到困惑，因此正确设置每个顶层实例或对话框的父窗口是一个好的做法。

# 在窗口之间传递变量

在程序执行期间，两个不同的窗口可能需要共享信息。虽然这些数据可以保存到磁盘并从使用它的窗口读取，但在某些情况下，更直接地在内存中处理它并将这些信息作为变量传递可能更简单。

# 准备工作

主窗口将包含三个单选按钮，用于选择我们要创建的用户类型，并且次要窗口将打开表单以填写用户数据：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/4a23ce5f-f29c-4fea-ac85-e96904c0d994.png)

# 操作步骤...

为了保存用户数据，我们使用`namedtuple`创建了一个字段，代表每个用户实例。`collections`模块中的这个函数接收类型名称和字段名称序列，并返回一个元组子类，用于创建具有给定字段的轻量级对象：

```py
import tkinter as tk
from collections import namedtuple

User = namedtuple("User", ["username", "password", "user_type"])

class UserForm(tk.Toplevel):
    def __init__(self, parent, user_type):
        super().__init__(parent)
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.user_type = user_type

        label = tk.Label(self, text="Create a new " + 
                         user_type.lower())
        entry_name = tk.Entry(self, textvariable=self.username)
        entry_pass = tk.Entry(self, textvariable=self.password, 
                              show="*")
        btn = tk.Button(self, text="Submit", command=self.destroy)

        label.grid(row=0, columnspan=2)
        tk.Label(self, text="Username:").grid(row=1, column=0)
        tk.Label(self, text="Password:").grid(row=2, column=0)
        entry_name.grid(row=1, column=1)
        entry_pass.grid(row=2, column=1)
        btn.grid(row=3, columnspan=2)

    def open(self):
        self.grab_set()
        self.wait_window()
        username = self.username.get()
        password = self.password.get()
        return User(username, password, self.user_type)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        user_types = ("Administrator", "Supervisor", "Regular user")
        self.user_type = tk.StringVar()
        self.user_type.set(user_types[0])

        label = tk.Label(self, text="Please, select the type of user")
        radios = [tk.Radiobutton(self, text=t, value=t, \
                  variable=self.user_type) for t in user_types]
        btn = tk.Button(self, text="Create user", 
                        command=self.open_window)

        label.pack(padx=10, pady=10)
        for radio in radios:
            radio.pack(padx=10, anchor=tk.W)
        btn.pack(pady=10)

    def open_window(self):
        window = UserForm(self, self.user_type.get())
        user = window.open()
        print(user)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

当执行流返回到主窗口时，用户数据将被打印到控制台。

# 工作原理...

这个示例的大部分代码已经在其他示例中涵盖，主要区别在于`UserForm`类的`open()`方法中，我们将调用`grab_set()`移到了那里。然而，`wait_window()`方法实际上是停止执行并防止我们在表单被修改之前返回数据的方法：

```py
    def open(self):
 self.grab_set()
 self.wait_window()
        username = self.username.get()
        password = self.password.get()
        return User(username, password, self.user_type)
```

需要强调的是，`wait_window()`进入一个本地事件循环，当窗口被销毁时结束。虽然可以传递我们想要等待移除的部件，但我们可以省略它以隐式地引用调用此方法的实例。

当`UserForm`实例被销毁时，`open()`方法的执行将继续，并返回`User`对象，现在可以在`App`类中使用：

```py
    def open_window(self):
        window = UserForm(self, self.user_type.get())
        user = window.open()
        print(user)
```


# 第五章：面向对象编程和 MVC

在本章中，我们将涵盖以下示例：

+   使用类来构造我们的数据

+   组合小部件以显示信息

+   从 CSV 文件中读取记录

+   将数据持久化到 SQLite 数据库中

+   使用 MVC 模式进行重构

# 介绍

到目前为止，我们所有的应用程序都将数据保存在内存中作为本地变量或属性。但是，我们也希望能够持久化信息，以便在程序关闭时不会丢失。

在本章中，我们将讨论如何使用**面向对象编程**（**OOP**）原则和应用**模型-视图-控制器**（**MVC**）模式来表示和显示这些数据。简而言之，这种模式提出了三个组件，我们可以将我们的 GUI 分为这三个组件：一个**模型**保存应用程序数据，一个**视图**显示这些数据，一个**控制器**处理用户事件并连接视图和模型。

这些概念与我们如何操作和持久化信息有关，并帮助我们改进程序的组织。大多数这些示例不特定于 Tkinter，您可以将相同的原则应用于其他 GUI 库。

# 使用类来构造我们的数据

我们将以联系人列表应用程序为例，说明如何使用 Python 类来建模我们的数据。即使用户界面可能提供许多不同的功能，我们仍需要定义哪些属性代表我们的领域模型——在我们的情况下，每个个人联系人。

# 准备工作

每个联系人将包含以下信息：

+   名字和姓氏，不能为空

+   电子邮件地址，例如`john.doe@acme.com`

+   电话号码，格式为*(123) 4567890*

有了这个抽象，我们可以开始编写我们的`Contact`类的代码。

# 如何做...

首先，我们定义了一对实用函数，我们将重复使用它们来验证必填字段或必须遵循特定格式的字段：

```py
def required(value, message):
    if not value:
        raise ValueError(message)
    return value

def matches(value, regex, message):
    if value and not regex.match(value):
        raise ValueError(message)
    return value
```

然后，我们定义我们的`Contact`类及其`__init__`方法。我们在这里设置所有参数对应的字段。我们还将编译的正则表达式存储为类属性，因为我们将在每个实例中使用它们来执行字段验证：

```py
import re

class Contact(object):
    email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
    phone_regex = re.compile(r"\([0-9]{3}\)\s[0-9]{7}")

    def __init__(self, last_name, first_name, email, phone):
        self.last_name = last_name
        self.first_name = first_name
        self.email = email
        self.phone = phone
```

然而，这个定义还不足以强制执行每个字段的验证。为此，我们使用`@property`装饰器，它允许我们包装对内部属性的访问：

```py
    @property
    def last_name(self):
        return self._last_name

    @last_name.setter
    def last_name(self, value):
        self._last_name = required(value, "Last name is required")
```

相同的技术也适用于`first_name`，因为它也是必需的。`email`和`phone`属性采用类似的方法，使用`matches`函数和相应的正则表达式：

```py
    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        self._email = matches(value, self.email_regex,
                              "Invalid email format")
```

此脚本应保存为`chapter5_01.py`，因为我们将在以后的示例中使用这个名称导入它。

# 它是如何工作的...

正如我们之前提到的，`property`描述符是一种在访问对象的属性时触发函数调用的机制。

在我们的示例中，它们使用下划线包装对内部属性的访问，如下所示：

```py
contact.first_name = "John" # Stores "John" in contact._first_name
print(contact.first_name)   # Reads "John" from contact._first_name
contact.last_name = ""      # ValueError raised by the required function
```

`property`描述符通常与`@decorated`语法一起使用——请记住始终使用相同的名称来装饰函数：

```py
    @property
    def last_name(self):
        # ...

    @last_name.setter
    def last_name(self, value):
        # ...
```

# 还有更多...

您可能会发现我们的`Contact`类的完整实现非常冗长和重复。对于每个属性，我们都需要在`__init__`方法中分配它，并编写其对应的 getter 和 setter 方法。

幸运的是，我们有几种替代方案来减少这种样板代码的数量。标准库中的`namedtuple`函数允许我们创建具有命名字段的轻量级元组子类：

```py
from collections import namedtuple

Contact = namedtuple("Contact", ["last_name", "first_name",
                                 "email", "phone"])
```

但是，我们仍然需要添加一个解决方法来实现字段的验证。为了解决这个常见问题，我们可以使用 Python 包索引中提供的`attrs`包。

像往常一样，您可以使用以下命令行和`pip`安装它：

```py
$ pip install attrs
```

安装后，您可以用`attr.ib`描述符替换所有属性。它还允许您指定一个`validator`回调，该回调接受类实例、要修改的属性和要设置的值。

通过一些小的修改，我们可以重写我们的`Contact`类，将代码行数减少一半：

```py
import re
import attr

def required(message):
    def func(self, attr, val):
        if not val: raise ValueError(message)
    return func

def match(pattern, message):
    regex = re.compile(pattern)
    def func(self, attr, val):
        if val and not regex.match(val):
            raise ValueError(message)
    return func

@attr.s
class Contact(object):
    last_name = attr.ib(validator=required("Last name is required"))
    first_name = attr.ib(validator=required("First name is required"))
    email = attr.ib(validator=match(r"[^@]+@[^@]+\.[^@]+",
                                    "Invalid email format"))
    phone = attr.ib(validator=match(r"\([0-9]{3}\)\s[0-9]{7}",
                                    "Invalid phone format"))
```

在项目中添加外部依赖时，注意不仅要考虑生产力的好处，还要注意其他重要方面，如文档、支持和许可证。

您可以在其网站[`www.attrs.org/en/stable/`](http://www.attrs.org/en/stable/)上找到有关`attrs`包的更多信息。

# 组合小部件以显示信息

如果所有的代码都包含在一个类中，构建大型应用程序将会很困难。通过将 GUI 代码拆分为特定的类，我们可以模块化程序的结构，并创建具有明确定义目的的小部件。

# 准备工作

除了导入 Tkinter 包，我们还将从前面的配方中导入`Contact`类：

```py
import tkinter as tk
import tkinter.messagebox as mb

from chapter5_01 import Contact
```

验证`chapter5_01.py`文件是否在相同的目录中；否则，这个`import-from`语句将引发`ImportError`。

# 操作步骤...

我们将创建一个可滚动的列表，显示所有联系人。为了将列表中的每个项目表示为一个字符串，我们将显示联系人的姓和名：

```py
class ContactList(tk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master)
        self.lb = tk.Listbox(self, **kwargs)
        scroll = tk.Scrollbar(self, command=self.lb.yview)

        self.lb.config(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

    def insert(self, contact, index=tk.END):
        text = "{}, {}".format(contact.last_name, contact.first_name)
        self.lb.insert(index, text)

    def delete(self, index):
        self.lb.delete(index, index)

    def update(self, contact, index):
        self.delete(index)
        self.insert(contact, index)

    def bind_doble_click(self, callback):
        handler = lambda _: callback(self.lb.curselection()[0])
        self.lb.bind("<Double-Button-1>", handler)
```

为了显示并允许我们编辑联系人的详细信息，我们还将创建一个特定的表单。我们将以`LabelFrame`小部件作为基类，为每个字段添加一个`Label`和一个`Entry`：

```py
class ContactForm(tk.LabelFrame):
    fields = ("Last name", "First name", "Email", "Phone")

    def __init__(self, master, **kwargs):
        super().__init__(master, text="Contact",
                         padx=10, pady=10, **kwargs)
        self.frame = tk.Frame(self)
        self.entries = list(map(self.create_field, 
        enumerate(self.fields)))
        self.frame.pack()

    def create_field(self, field):
        position, text = field
        label = tk.Label(self.frame, text=text)
        entry = tk.Entry(self.frame, width=25)
        label.grid(row=position, column=0, pady=5)
        entry.grid(row=position, column=1, pady=5)
        return entry

    def load_details(self, contact):
        values = (contact.last_name, contact.first_name,
                  contact.email, contact.phone)
        for entry, value in zip(self.entries, values):
            entry.delete(0, tk.END)
            entry.insert(0, value)

    def get_details(self):
        values = [e.get() for e in self.entries]
        try:
            return Contact(*values)
        except ValueError as e:
            mb.showerror("Validation error", str(e), parent=self)

    def clear(self):
        for entry in self.entries:
            entry.delete(0, tk.END)
```

# 工作原理...

`ContactList`类的一个重要细节是，它公开了将回调附加到双击事件的可能性。它还将点击的索引作为参数传递给这个函数。我们这样做是因为我们希望隐藏底层`Listbox`的实现细节：

```py
    def bind_doble_click(self, callback):
        handler = lambda _: callback(self.lb.curselection()[0])
        self.lb.bind("<Double-Button-1>", handler)
```

`ContactForm`还提供了一个抽象，用于从输入的值实例化一个新的联系人：

```py
    def get_details(self):
        values = [e.get() for e in self.entries]
        try:
            return Contact(*values)
        except ValueError as e:
            mb.showerror("Validation error", str(e), parent=self)
```

由于我们在`Contact`类中包含了字段验证，实例化一个新的联系人可能会引发`ValueError`，如果一个条目包含无效值。为了通知用户，我们会显示一个带有错误消息的错误对话框。

# 从 CSV 文件中读取记录

作为将只读数据加载到我们的应用程序的第一种方法，我们将使用**逗号分隔值**（**CSV**）文件。这种格式将数据制表在纯文本文件中，其中每个文件对应于记录的字段，用逗号分隔，如下所示：

```py
Gauford,Albertine,agauford0@acme.com,(614) 7171720
Greger,Bryce,bgreger1@acme.com,(616) 3543513
Wetherald,Rickey,rwetherald2@acme.com,(379) 3652495
```

这种解决方案对于简单的场景很容易实现，特别是如果文本字段不包含换行符。我们将使用标准库中的`csv`模块，一旦记录加载到我们的应用程序中，我们将填充在前面的配方中开发的小部件。

# 准备工作

我们将组装在前面的配方中创建的自定义小部件。一旦从 CSV 文件加载记录，我们的应用程序将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/4c1f3853-759d-44a7-8bd8-7b1302be4fae.png)

# 操作步骤...

除了导入`Contact`类，我们还将导入`ContactForm`和`ContactList`小部件：

```py
import csv
import tkinter as tk

from chapter5_01 import Contact
from chapter5_02 import ContactForm, ContactList

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CSV Contact list")
        self.list = ContactList(self, height=12)
        self.form = ContactForm(self)
        self.contacts = self.load_contacts()

        for contact in self.contacts:
            self.list.insert(contact)
        self.list.pack(side=tk.LEFT, padx=10, pady=10)
        self.form.pack(side=tk.LEFT, padx=10, pady=10)
        self.list.bind_doble_click(self.show_contact)

    def load_contacts(self):
        with open("contacts.csv", encoding="utf-8", newline="") as f:
            return [Contact(*r) for r in csv.reader(f)]

    def show_contact(self, index):
        contact = self.contacts[index]
        self.form.load_details(contact)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理...

`load_contacts`函数负责读取 CSV 文件，并将所有记录转换为`Contact`实例的列表。

`csv.reader`读取的每一行都作为一个字符串元组返回，通过使用逗号分隔符拆分相应的行创建。由于这个元组使用与`Contact`类的`__init__`方法中定义的参数相同的顺序，我们可以简单地使用`*`运算符解包它。这段代码可以用列表推导式总结为一行，如下所示：

```py
def load_contacts(self):
    with open("contacts.csv", encoding="utf-8", newline="") as f:
        return [Contact(*r) for r in csv.reader(f)]
```

在`with`块中返回列表没有问题，因为上下文管理器在方法执行完成时会自动关闭文件。

# 将数据持久化到 SQLite 数据库

由于我们希望能够通过我们的应用程序持久保存数据的更改，我们必须实现一个既用于读取又用于写入操作的解决方案。

我们可以在每次修改后将所有记录写入我们从中读取的同一纯文本文件，但是当单独更新一些记录时，这可能是一种低效的解决方案。

由于所有信息都将存储在本地，我们可以使用 SQLite 数据库来持久保存我们的应用程序数据。`sqlite3`模块是标准库的一部分，因此您无需任何额外的依赖项即可开始使用它。

这个示例并不打算成为 SQLite 的全面指南，而是一个实际的介绍，将其集成到您的 Tkinter 应用程序中。

# 准备工作

在我们的应用程序中使用数据库之前，我们需要创建并填充它一些初始数据。我们所有的联系人都存储在 CSV 文件中，因此我们将使用迁移脚本读取所有记录并将它们插入数据库。

首先，我们创建到`contacts.db`文件的连接，我们的数据将存储在其中。然后，我们使用`last_name`、`first_name`、`email`和`phone`文本字段创建`contacts`表。

由于`csv.reader`返回一个元组的可迭代对象，其字段遵循我们在`CREATE TABLE`语句中定义的相同顺序，我们可以直接将其传递给`executemany`方法。它将为每个元组执行`INSERT`语句，用实际值替换问号：

```py
import csv
import sqlite3

def main():
    with open("contacts.csv", encoding="utf-8", newline="") as f, \
         sqlite3.connect("contacts.db") as conn:
        conn.execute("""CREATE TABLE contacts (
                          last_name text,
                          first_name text,
                          email text,
                          phone text
                        )""")
        conn.executemany("INSERT INTO contacts VALUES (?,?,?,?)",
                         csv.reader(f))

if __name__ == "__main__":
    main()
```

`with`语句会自动提交事务，并在执行结束时关闭文件和 SQLite 连接。

# 如何做...

要将新联系人添加到我们的数据库，我们将定义一个`Toplevel`子类，它重用`ContactForm`来实例化一个新联系人：

```py
class NewContact(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.contact = None
        self.form = ContactForm(self)
        self.btn_add = tk.Button(self, text="Confirm",
                                 command=self.confirm)
        self.form.pack(padx=10, pady=10)
        self.btn_add.pack(pady=10)

    def confirm(self):
        self.contact = self.form.get_details()
        if self.contact:
            self.destroy()

    def show(self):
        self.grab_set()
        self.wait_window()
        return self.contact
```

以下顶级窗口将显示在主窗口之上，并在对话框确认或关闭后返回焦点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/a86cb45d-2ed0-4f5f-ae76-d9a6e4db65d9.png)

我们还将扩展我们的`ContactForm`类，增加两个额外的按钮——一个用于更新联系人信息，另一个用于删除所选联系人：

```py
class UpdateContactForm(ContactForm):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.btn_save = tk.Button(self, text="Save")
        self.btn_delete = tk.Button(self, text="Delete")

        self.btn_save.pack(side=tk.RIGHT, ipadx=5, padx=5, pady=5)
        self.btn_delete.pack(side=tk.RIGHT, ipadx=5, padx=5, pady=5)

    def bind_save(self, callback):
        self.btn_save.config(command=callback)

    def bind_delete(self, callback):
        self.btn_delete.config(command=callback)
```

`bind_save`和`bind_delete`方法允许我们将回调附加到相应按钮的`command`上。

要整合所有这些更改，我们将向我们的`App`类添加以下代码：

```py
class App(tk.Tk):
    def __init__(self, conn):
        super().__init__()
        self.title("SQLite Contacts list")
        self.conn = conn
 self.selection = None
        self.list = ContactList(self, height=15)
        self.form = UpdateContactForm(self)
        self.btn_new = tk.Button(self, text="Add new contact",
 command=self.add_contact)
        self.contacts = self.load_contacts()

        for contact in self.contacts:
            self.list.insert(contact)
        self.list.pack(side=tk.LEFT, padx=10, pady=10)
        self.form.pack(padx=10, pady=10)
        self.btn_new.pack(side=tk.BOTTOM, pady=5)

        self.list.bind_doble_click(self.show_contact)
        self.form.bind_save(self.update_contact)
 self.form.bind_delete(self.delete_contact)
```

我们还需要修改`load_contacts`方法以从查询结果创建联系人：

```py
    def load_contacts(self):
        contacts = []
        sql = """SELECT rowid, last_name, first_name, email, phone
                 FROM contacts"""
        for row in self.conn.execute(sql):
            contact = Contact(*row[1:])
            contact.rowid = row[0]
            contacts.append(contact)
        return contacts

    def show_contact(self, index):
        self.selection = index
        contact = self.contacts[index]
        self.form.load_details(contact)
```

要将联系人添加到列表中，我们将实例化一个`NewContact`对话框，并调用其`show`方法以获取新联系人的详细信息。如果这些值有效，我们将按照与我们的`INSERT`语句中指定的相同顺序将它们存储在一个元组中：

```py
    def to_values(self, c):
        return (c.last_name, c.first_name, c.email, c.phone)

    def add_contact(self):
        new_contact = NewContact(self)
        contact = new_contact.show()
        if not contact:
            return
        values = self.to_values(contact)
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute("INSERT INTO contacts VALUES (?,?,?,?)", 
            values)
            contact.rowid = cursor.lastrowid
        self.contacts.append(contact)
        self.list.insert(contact)
```

选择联系人后，我们可以通过检索当前表单值来更新其详细信息。如果它们有效，我们执行`UPDATE`语句以设置具有指定`rowid`的记录的列。

由于此语句的字段与`INSERT`语句的顺序相同，我们重用`to_values`方法从联系人实例创建一个元组——唯一的区别是我们必须附加`rowid`的替换参数：

```py
    def update_contact(self):
        if self.selection is None:
            return
        rowid = self.contacts[self.selection].rowid
        contact = self.form.get_details()
        if contact:
            values = self.to_values(contact)
            with self.conn:
                sql = """UPDATE contacts SET
                         last_name = ?,
                         first_name = ?,
                         email = ?,
                         phone = ?
                     WHERE rowid = ?"""
                self.conn.execute(sql, values + (rowid,))
            contact.rowid = rowid
            self.contacts[self.selection] = contact
            self.list.update(contact, self.selection)
```

要删除所选联系人，我们获取其`rowid`以替换我们的`DELETE`语句。一旦事务提交，联系人将从 GUI 中清除表单并从列表中删除。`selection`属性也设置为`None`，以避免对无效选择执行操作：

```py
    def delete_contact(self):
        if self.selection is None:
            return
        rowid = self.contacts[self.selection].rowid
        with self.conn:
            self.conn.execute("DELETE FROM contacts WHERE rowid = ?",
                              (rowid,))
        self.form.clear()
        self.list.delete(self.selection)
        self.selection = None
```

最后，我们将包装代码以初始化我们的应用程序在一个`main`函数中：

```py
def main():
    with sqlite3.connect("contacts.db") as conn:
        app = App(conn)
        app.mainloop()

if __name__ == "__main__":
    main()
```

有了所有这些更改，我们完整的应用程序将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/54018c9c-4b84-4521-b888-b9ca33f899e4.png)

# 工作原理...

这种类型的应用程序被称为**CRUD**首字母缩写，代表**创建、读取、更新和删除**，并且很容易映射到 SQL 语句`INSERT`、`SELECT`、`UPDATE`和`DELETE`。我们现在将看一下如何使用`sqlite3.Connection`类来实现每个操作。

`INSERT`语句向表中添加新记录，指定列名和相应的值。如果省略列名，将使用列顺序。

当你在 SQLite 中创建一个表时，默认情况下会添加一个名为`rowid`的列，并自动分配一个唯一值来标识每一行。由于我们通常需要它进行后续操作，我们使用`Cursor`类中可用的`lastrowid`属性来检索它：

```py
sql = "INSERT INTO my_table (col1, col2, col3) VALUES (?, ?, ?)"
with connection:
    cursor = connection.cursor()
    cursor.execute(sql, (value1, value2, value3))
    rowid = cursor.lastrowid
```

`SELECT`语句从表的记录中检索一个或多个列的值。可选地，我们可以添加一个`WHERE`子句来过滤要检索的记录。这对于有效地实现搜索和分页非常有用，但在我们的示例应用程序中，我们将忽略这个功能：

```py
sql = "SELECT rowid, col1, col2, col3 FROM my_table"
for row in connection.execute(sql):
    # do something with row
```

`UPDATE`语句修改表中记录的一个或多个列的值。通常，我们添加一个`WHERE`子句，只更新符合给定条件的行 - 在这里，如果我们想要更新特定记录，我们可以使用`rowid`：

```py
sql = "UPDATE my_table SET col1 = ?, col2 = ?, col3 = ? 
WHERE rowid = ?"
with connection:
    connection.execute(sql, (value1, value2, value3, rowid))
```

最后，`DELETE`语句从表中删除一个或多个记录。在这些语句中添加`WHERE`子句更加重要，因为如果我们省略它，该语句将删除表中的所有行：

```py
sql = "DELETE FROM my_table WHERE rowid = ?"
with connection:
    connection.execute(sql, (rowid,))
```

# 另请参阅

+   *组合小部件以显示信息*食谱

# 使用 MVC 模式进行重构

现在我们已经开发了应用程序的完整功能，我们可以发现当前设计中存在一些问题。例如，`App`类有多个职责，从实例化 Tkinter 小部件到执行 SQL 语句。

尽管编写从头到尾执行操作的方法似乎很容易和直接，但这种方法会导致更难以维护的代码库。我们可以通过预期可能的架构更改来检测这种缺陷，例如用通过 HTTP 访问的 REST 后端替换我们的关系数据库。

# 准备工作

让我们首先定义 MVC 模式以及它如何映射到我们在上一篇文章中构建的应用程序的不同部分。

这种模式将我们的应用程序分为三个组件，每个组件封装一个单一的责任，形成 MVC 三合一：

+   **模型**表示领域数据，并包含与之交互的业务规则。在我们的示例中，它是`Contact`类和特定于 SQLite 的代码。

+   **视图**是模型数据的图形表示。在我们的情况下，它由组成 GUI 的 Tkinter 小部件组成。

+   **控制器**通过接收用户输入并更新模型数据来连接视图和模型。这对应于我们的回调和事件处理程序以及所需的属性。

我们将重构我们的应用程序以实现这种关注点的分离。您会注意到组件之间的交互需要额外的代码，但它们也帮助我们定义它们的边界。

# 如何做...

首先，我们将所有与数据库交互的代码片段提取到一个单独的类中。这将允许我们隐藏持久层的实现细节，只暴露四个必要的方法，`get_contacts`，`add_contact`，`update_contact`和`delete_contact`：

```py
class ContactsRepository(object):
    def __init__(self, conn):
        self.conn = conn

    def to_values(self, c):
        return c.last_name, c.first_name, c.email, c.phone

    def get_contacts(self):
        sql = """SELECT rowid, last_name, first_name, email, phone
                 FROM contacts"""
        for row in self.conn.execute(sql):
            contact = Contact(*row[1:])
            contact.rowid = row[0]
            yield contact

    def add_contact(self, contact):
        sql = "INSERT INTO contacts VALUES (?, ?, ?, ?)"
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute(sql, self.to_values(contact))
            contact.rowid = cursor.lastrowid
        return contact

    def update_contact(self, contact):
        rowid = contact.rowid
        sql = """UPDATE contacts
                 SET last_name = ?, first_name = ?, email = ?, 
                 phone = ?
                 WHERE rowid = ?"""
        with self.conn:
            self.conn.execute(sql, self.to_values(contact) + (rowid,))
        return contact

    def delete_contact(self, contact):
        sql = "DELETE FROM contacts WHERE rowid = ?"
        with self.conn:
            self.conn.execute(sql, (contact.rowid,))
```

这个，连同`Contact`类，将组成我们的模型。

现在，我们的视图将只包含足够的代码来显示 GUI 和让控制器更新它的方法。我们还将将类重命名为`ContactsView`，以更好地表达其目的。

```py
class ContactsView(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SQLite Contacts list")
        self.list = ContactList(self, height=15)
        self.form = UpdateContactForm(self)
        self.btn_new = tk.Button(self, text="Add new contact")

        self.list.pack(side=tk.LEFT, padx=10, pady=10)
        self.form.pack(padx=10, pady=10)
        self.btn_new.pack(side=tk.BOTTOM, pady=5)

    def set_ctrl(self, ctrl):
        self.btn_new.config(command=ctrl.create_contact)
        self.list.bind_doble_click(ctrl.select_contact)
        self.form.bind_save(ctrl.update_contact)
        self.form.bind_delete(ctrl.delete_contact)

    def add_contact(self, contact):
        self.list.insert(contact)

    def update_contact(self, contact, index):
        self.list.update(contact, index)

    def remove_contact(self, index):
        self.form.clear()
        self.list.delete(index)

    def get_details(self):
        return self.form.get_details()

    def load_details(self, contact):
        self.form.load_details(contact)
```

请注意，用户输入由控制器处理，因此我们添加了一个`set_ctrl`方法来将其连接到 Tkinter 回调。

我们的`ContactsController`类现在将包含我们初始的`App`类中缺失的所有代码，也就是界面和持久性之间的交互，具有`selection`和`contacts`属性：

```py
class ContactsController(object):
    def __init__(self, repo, view):
        self.repo = repo
        self.view = view
        self.selection = None
        self.contacts = list(repo.get_contacts())

    def create_contact(self):
        new_contact = NewContact(self.view).show()
        if new_contact:
            contact = self.repo.add_contact(new_contact)
            self.contacts.append(contact)
            self.view.add_contact(contact)

    def select_contact(self, index):
        self.selection = index
        contact = self.contacts[index]
        self.view.load_details(contact)

    def update_contact(self):
        if not self.selection:
            return
        rowid = self.contacts[self.selection].rowid
        update_contact = self.view.get_details()
        update_contact.rowid = rowid

        contact = self.repo.update_contact(update_contact)
        self.contacts[self.selection] = contact
        self.view.update_contact(contact, self.selection)

    def delete_contact(self):
        if not self.selection:
            return
        contact = self.contacts[self.selection]
        self.repo.delete_contact(contact)
        self.view.remove_contact(self.selection)

    def start(self):
        for c in self.contacts:
            self.view.add_contact(c)
        self.view.mainloop()
```

我们将创建一个`__main__.py`脚本，不仅允许我们引导我们的应用程序，还可以从压缩文件或包含目录名称启动它：

```py
# Suppose that __main__.py is in the directory chapter5_05
$ python chapter5_05
# Or if we compress the directory contents
$ python chapter5_05.zip
```

# 工作原理...

原始的 MVC 实现是在 Smalltalk 编程语言中引入的，并且由以下图表表示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/994bfa05-b8eb-48a8-9870-dc89e1d1df40.jpg)

在前面的图表中，我们可以看到视图将用户事件传递给控制器，控制器再更新模型。为了将这些更改传播到视图，模型实现了**观察者模式**。这意味着订阅模型的视图在更新发生时会收到通知，因此它们可以查询模型状态并更改显示的数据。

还有一种设计的变体，视图和模型之间没有通信。相反，控制器在更新模型后，通过更改视图来进行视图的更改。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/162786bf-3623-4440-bebb-4fd75fd9d71b.jpg)

这种方法被称为**被动模型**，它是现代 MVC 实现中最常见的方法，特别是对于 Web 框架来说。我们在示例中使用了这种变体，因为它简化了我们的`ContactsRepository`，并且不需要对我们的`ContactsController`类进行重大修改。

# 还有更多...

您可能已经注意到，更新和删除操作是通过`rowid`字段实现的，例如，在`ContactsController`类的`update_contact`方法中：

```py
    def update_contact(self):
        if not self.selection:
            return
        rowid = self.contacts[self.selection].rowid
        update_contact = self.view.get_details()
        update_contact.rowid = rowid
```

由于这是我们 SQLite 数据库的实现细节，这应该对我们的其他组件隐藏起来。

一个解决方案是向`Contact`类添加另一个字段，例如`id`或`contact_id`，注意`id`也是 Python 的内置函数，一些编辑器可能会错误地将其标记出来。

然后，我们可以假设这个字段是我们领域数据的一部分，作为一个唯一标识符，并将它的生成实现细节留给模型。


# 第六章：异步编程

在本章中，我们将介绍以下食谱：

+   调度操作

+   在线程上运行方法

+   执行 HTTP 请求

+   将线程与进度条连接起来

+   取消已调度的操作

+   处理空闲任务

+   生成单独的进程

# 介绍

与任何其他编程语言一样，Python 允许您将进程执行分成多个可以在时间上独立执行的单元，称为**线程**。当启动 Python 程序时，它会在**主线程**中开始执行。

Tkinter 的主循环必须从主线程开始，负责处理所有 GUI 的事件和更新。默认情况下，我们的应用程序代码，如回调和事件处理程序，也将在此线程中执行。

然而，如果我们在这个线程中启动一个长时间运行的操作，主线程的执行将会被阻塞，因此 GUI 将会冻结，并且不会响应用户事件。

在本章中，我们将介绍几种方法来实现应用程序的响应性，同时在后台执行单独的操作，并了解如何与它们交互。

# 调度操作

在 Tkinter 中防止阻塞主线程的基本技术是调度一个在超时后被调用的操作。

在本食谱中，我们将介绍如何使用`after()`方法在 Tkinter 中实现这一点，该方法可以从所有 Tkinter 小部件类中调用。

# 准备就绪

以下代码展示了一个回调如何阻塞主循环的简单示例。

该应用程序由一个按钮组成，当单击时会被禁用，等待 5 秒，然后再次启用。一个简单的实现如下：

```py
import time
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.button = tk.Button(self, command=self.start_action,
                                text="Wait 5 seconds")
        self.button.pack(padx=20, pady=20)

    def start_action(self):
        self.button.config(state=tk.DISABLED)
        time.sleep(5)
        self.button.config(state=tk.NORMAL)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

如果运行上述程序，您会注意到**等待 5 秒**按钮根本没有被禁用，但点击它会使 GUI 冻结 5 秒。我们可以直接注意到按钮样式的变化，看起来是活动的而不是禁用的；此外，标题栏在 5 秒时间到之前将不会响应鼠标点击：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/c38a83be-7aae-4da8-9461-e4c44b592c65.png)

如果我们包含了其他小部件，比如输入框和滚动条，这也会受到影响。

现在，我们将看看如何通过调度操作而不是挂起线程执行来实现所需的功能。

# 如何做...

`after()`方法允许您注册一个回调函数，在 Tkinter 的主循环中延迟指定的毫秒数后调用。您可以将这些注册的警报视为应该在系统空闲时立即处理的事件。

因此，我们将使用`self.after(5000, callback)`替换对`time.sleep(5)`的调用。我们使用`self`实例，因为`after()`方法也可以在根`Tk`实例中使用，并且从子小部件中调用它不会有任何区别：

```py
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.button = tk.Button(self, command=self.start_action,
                                text="Wait 5 seconds")
        self.button.pack(padx=50, pady=20)

    def start_action(self):
        self.button.config(state=tk.DISABLED)
        self.after(5000, lambda: self.button.config(state=tk.NORMAL))

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

使用上述方法，应用程序在调度操作被调用之前是响应的。按钮的外观将变为禁用状态，我们也可以像往常一样与标题栏交互：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/064d3045-79e4-43cc-ae25-e13f2ab909e7.png)

# 工作原理...

从前面部分提到的示例中，您可能会认为`after()`方法会在给定的毫秒数经过后准确执行回调。

然而，它只是请求 Tkinter 注册一个警报，保证不会在指定的时间之前执行；因此，如果主线程忙碌，实际执行时间是没有上限的。

我们还应该记住，在调度操作之后，方法的执行立即继续。以下示例说明了这种行为：

```py
print("First")
self.after(1000, lambda: print("Third"))
print("Second")
```

上述代码段将分别在 1 秒后打印`"First"`，`"Second"`和`"Third"`。在此期间，主线程将保持 GUI 响应，并且用户可以像往常一样与应用程序交互。

通常，我们希望防止同一后台操作的运行超过一次，因此最好禁用触发执行的小部件。

不要忘记，任何预定的函数都将在主线程上执行，因此仅仅使用`after()`是不足以防止 GUI 冻结的；还重要的是避免执行长时间运行的方法作为回调。

在下一个示例中，我们将看看如何利用单独的线程执行这些阻塞操作。

# 还有更多...

`after()`方法返回一个预定警报的标识符，可以将其传递给`after_cancel()`方法以取消回调的执行。

在另一个示例中，我们将看到如何使用这种方法实现停止预定回调的功能。

# 另请参阅

+   *取消预定操作*示例

# 在线程上运行方法

由于主线程应该负责更新 GUI 和处理事件，因此其余的后台操作必须在单独的线程中执行。

Python 的标准库包括`threading`模块，用于使用高级接口创建和控制多个线程，这将允许我们使用简单的类和方法。

值得一提的是，CPython——参考 Python 实现——受**GIL**（**全局解释器锁**）的固有限制，这是一种防止多个线程同时执行 Python 字节码的机制，因此它们无法在单独的核心上运行，无法充分利用多处理器系统。如果尝试使用`threading`模块来提高应用程序的性能，应该记住这一点。

# 如何做...

以下示例将`time.sleep()`的线程暂停与通过`after()`调度的操作结合起来：

```py
import time
import threading
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.button = tk.Button(self, command=self.start_action,
                                text="Wait 5 seconds")
        self.button.pack(padx=50, pady=20)

    def start_action(self):
        self.button.config(state=tk.DISABLED)
        thread = threading.Thread(target=self.run_action)
        print(threading.main_thread().name)
        print(thread.name)
        thread.start()
        self.check_thread(thread)

    def check_thread(self, thread):
        if thread.is_alive():
            self.after(100, lambda: self.check_thread(thread))
        else:
            self.button.config(state=tk.NORMAL)

    def run_action(self):
        print("Starting long running action...")
        time.sleep(5)
        print("Long running action finished!")

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

要创建一个新的`Thread`对象，可以使用带有`target`关键字参数的构造函数，在调用其`start()`方法时将在单独的线程上调用它。

在前面的部分中，我们在当前应用程序实例上使用了对`run_action`方法的引用：

```py
    thread = threading.Thread(target=self.run_action)
    thread.start()
```

然后，我们使用`after()`定期轮询线程状态，直到线程完成为止：

```py
    def check_thread(self, thread):
        if thread.is_alive():
            self.after(100, lambda: self.check_thread(thread))
        else:
            self.button.config(state=tk.NORMAL)
```

在前面的代码片段中，我们设置了`100`毫秒的延迟，因为没有必要以更频繁的频率进行轮询。当然，这个数字可能会根据线程操作的性质而变化。

这个时间线可以用以下序列图表示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/fea2c979-482b-44a4-a0b5-c4ed260cd966.jpg)

**Thread-1**上的矩形表示它忙于执行**time.sleep(5)**的时间。与此同时，**MainThread**只定期检查状态，没有操作长到足以导致 GUI 冻结。

# 还有更多...

在这个示例中，我们简要介绍了`Thread`类，但同样重要的是指出一些关于在 Python 程序中实例化和使用线程的细节。

# 线程方法 - start、run 和 join

在我们的示例中，我们调用了`start()`，因为我们希望在单独的线程中执行该方法并继续执行当前线程。

另一方面，如果我们调用了`join()`方法，主线程将被阻塞，直到新线程终止。因此，即使我们使用多个线程，它也会导致我们想要避免的相同的“冻结”行为。

最后，`run()`方法是线程实际执行其可调用目标操作的地方。当我们扩展`Thread`类时，我们将覆盖它，就像下一个示例中一样。

作为一个经验法则，始终记住从主线程调用`start()`以避免阻塞它。

# 参数化目标方法

在使用`Thread`类的构造函数时，可以通过`args`参数指定目标方法的参数：

```py
    def start_action(self):
        self.button.config(state=tk.DISABLED)
        thread = threading.Thread(target=self.run_action, args=(5,))
        thread.start()
        self.check_thread(thread)

    def run_action(self, timeout):
        # ...
```

请注意，由于我们正在使用当前实例引用目标方法，因此`self`参数会自动传递。在新线程需要访问来自调用方实例的信息的情况下，这可能很方便。

# 执行 HTTP 请求

通过 HTTP 与远程服务器通信是异步编程的常见用例。客户端执行请求，该请求使用 TCP/IP 协议在网络上传输；然后，服务器处理信息并将响应发送回客户端。

执行此操作所需的时间可能会从几毫秒到几秒不等，但在大多数情况下，可以安全地假设用户可能会注意到这种延迟。

# 做好准备

互联网上有很多第三方网络服务可以免费访问以进行原型设计。但是，我们不希望依赖外部服务，因为其 API 可能会更改，甚至可能会下线。

对于这个示例，我们将实现我们自己的 HTTP 服务器，该服务器将生成一个随机的 JSON 响应，该响应将打印在我们单独的 GUI 应用程序中：

```py
import time
import json
import random
from http.server import HTTPServer, BaseHTTPRequestHandler

class RandomRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Simulate latency
        time.sleep(3)

        # Write response headers
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        # Write response body
        body = json.dumps({'random': random.random()})
        self.wfile.write(bytes(body, "utf8"))

def main():
    """Starts the HTTP server on port 8080"""
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, RandomRequestHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    main()
```

要启动此服务器，请运行`server.py`脚本，并保持进程运行以接受本地端口`8080`上的传入 HTTP 请求。

# 如何做...

我们的客户端应用程序包括一个简单的标签，用于向用户显示信息，以及一个按钮，用于向我们的本地服务器执行新的 HTTP 请求：

```py
import json
import threading
import urllib.request
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HTTP request example")
        self.label = tk.Label(self,
                              text="Click 'Start' to get a random 
                              value")
        self.button = tk.Button(self, text="Start",
                                command=self.start_action)
        self.label.pack(padx=60, pady=10)
        self.button.pack(pady=10)

    def start_action(self):
        self.button.config(state=tk.DISABLED)
        thread = AsyncAction()
        thread.start()
        self.check_thread(thread)

    def check_thread(self, thread):
        if thread.is_alive():
            self.after(100, lambda: self.check_thread(thread))
        else:
            text = "Random value: {}".format(thread.result)
            self.label.config(text=text)
            self.button.config(state=tk.NORMAL)

class AsyncAction(threading.Thread):
    def run(self):
        self.result = None
        url = "http://localhost:8080"
        with urllib.request.urlopen(url) as f:
            obj = json.loads(f.read().decode("utf-8"))
            self.result = obj["random"]

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

当请求完成时，标签显示服务器中生成的随机值，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/1dafeaf9-7935-446d-a1fb-b04232acb21b.png)

通常情况下，当异步操作正在运行时，按钮会被禁用，以避免在处理前一个请求之前执行新的请求。

# 工作原理...

在这个示例中，我们扩展了`Thread`类，以使用更面向对象的方法实现必须在单独线程中运行的逻辑。这是通过覆盖其`run()`方法来完成的，该方法将负责执行对本地服务器的 HTTP 请求：

```py
class AsyncAction(threading.Thread):
    def run(self):
        # ...
```

有很多 HTTP 客户端库，但在这里，我们将简单地使用标准库中的`urllib.request`模块。该模块包含`urlopen()`函数，可以接受 URL 字符串并返回一个 HTTP 响应，可以作为上下文管理器使用，即可以使用`with`语句安全地读取和关闭。

服务器返回一个 JSON 文档，如下所示（您可以通过在浏览器中打开`http://localhost:8080`URL 来检查）：

```py
{"random": 0.0915826359180778}
```

为了将字符串解码为对象，我们将响应内容传递给`json`模块的`loads()`函数。由于这样，我们可以像使用字典一样访问随机值，并将其存储在`result`属性中，该属性初始化为`None`，以防止主线程在发生错误时读取未设置的字段：

```py
def run(self):
    self.result = None
    url = "http://localhost:8080"
    with urllib.request.urlopen(url) as f:
        obj = json.loads(f.read().decode("utf-8"))
        self.result = obj["random"]
```

然后，GUI 定期轮询线程状态，就像我们在前面的示例中看到的那样：

```py
    def check_thread(self, thread):
        if thread.is_alive():
            self.after(100, lambda: self.check_thread(thread))
        else:
            text = "Random value: {}".format(thread.result)
            self.label.config(text=text)
            self.button.config(state=tk.NORMAL)
```

这里，主要的区别在于一旦线程不再活动，我们可以检索`result`属性的值，因为它在执行结束之前已经设置。

# 另请参阅

+   *在线程上运行方法*示例

# 将线程与进度条连接起来

进度条是后台任务状态的有用指示器，显示相对于进度的逐步填充部分。它们经常用于长时间运行的操作，因此通常将它们与执行这些任务的线程连接起来，以向最终用户提供视觉反馈。

# 做好准备

我们的示例应用程序将包括一个水平进度条，一旦用户点击“开始”按钮，它将增加固定数量的进度：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/39ccaa8f-15d9-4d73-bfc0-e0be22d147d2.png)

# 如何做...

为了模拟后台任务的执行，进度条的增量将由一个不同的线程生成，该线程将在每个步骤之间暂停 1 秒。

通信将使用同步队列进行，这允许我们以线程安全的方式交换信息：

```py
import time
import queue
import threading
import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox as mb

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Progressbar example")
        self.queue = queue.Queue()
        self.progressbar = ttk.Progressbar(self, length=300,
                                           orient=tk.HORIZONTAL)
        self.button = tk.Button(self, text="Start",
                                command=self.start_action)

        self.progressbar.pack(padx=10, pady=10)
        self.button.pack(padx=10, pady=10)

    def start_action(self):
        self.button.config(state=tk.DISABLED)
        thread = AsyncAction(self.queue, 20)
        thread.start()
        self.poll_thread(thread)

    def poll_thread(self, thread):
        self.check_queue()
        if thread.is_alive():
            self.after(100, lambda: self.poll_thread(thread))
        else:
            self.button.config(state=tk.NORMAL)
            mb.showinfo("Done!", "Async action completed")

    def check_queue(self):
        while self.queue.qsize():
            try:
                step = self.queue.get(0)
                self.progressbar.step(step * 100)
            except queue.Empty:
                pass

class AsyncAction(threading.Thread):
    def __init__(self, queue, steps):
        super().__init__()
        self.queue = queue
        self.steps = steps

    def run(self):
        for _ in range(self.steps):
            time.sleep(1)
            self.queue.put(1 / self.steps)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

`Progressbar`是`tkinter.ttk`模块中包含的一个主题小部件。我们将在第八章中深入探讨这个模块，探索它定义的新小部件，但到目前为止，我们只需要将`Progressbar`作为常规小部件使用。

我们还需要导入`queue`模块，该模块定义了同步集合，如`Queue`。在多线程环境中，同步性是一个重要的主题，因为如果在完全相同的时间访问共享资源，可能会出现意外的结果，我们将这些不太可能但可能发生的情况定义为**竞争条件**。

通过这些添加，我们的`App`类包含了这些新的语句：

```py
# ...
import queue
import tkinter.ttk as ttk

class App(tk.Tk):
    def __init__(self):
        # ...
        self.queue = queue.Queue()
 self.progressbar = ttk.Progressbar(self, length=300,
 orient=tk.HORIZONTAL)
```

与以前的示例一样，`start_action()`方法启动一个线程，传递队列和将模拟长时间运行任务的步数：

```py
    def start_action(self):
        self.button.config(state=tk.DISABLED)
        thread = AsyncAction(self.queue, 20)
        thread.start()
        self.poll_thread(thread)
```

我们的`AsyncAction`子类定义了一个自定义构造函数来接收这些参数，这些参数将在`run()`方法中使用：

```py
class AsyncAction(threading.Thread):
    def __init__(self, queue, steps):
        super().__init__()
        self.queue = queue
        self.steps = steps

    def run(self):
        for _ in range(self.steps):
            time.sleep(1)
            self.queue.put(1 / self.steps)
```

循环暂停线程的执行 1 秒，并根据`steps`属性中指示的次数将增量添加到队列中。

从应用程序实例中读取队列，从`check_queue()`中检查队列中添加的项目：

```py
    def check_queue(self):
        while self.queue.qsize():
            try:
                step = self.queue.get(0)
                self.progressbar.step(step * 100)
            except queue.Empty:
                pass
```

从`poll_thread()`定期调用以下方法，该方法轮询线程状态并使用`after()`再次调度自己，直到线程完成执行：

```py
    def poll_thread(self, thread):
        self.check_queue()
        if thread.is_alive():
            self.after(100, lambda: self.poll_thread(thread))
        else:
            self.button.config(state=tk.NORMAL)
            mb.showinfo("Done!", "Async action completed")
```

# 另请参阅

+   *在线程上运行方法*食谱

# 取消预定的操作

Tkinter 的调度机制不仅提供了延迟回调执行的方法，还提供了取消它们的方法，如果它们尚未执行。考虑一个可能需要太长时间才能完成的操作，因此我们希望让用户通过按下按钮或关闭应用程序来停止它。

# 准备工作

我们将从第一个食谱中获取示例，并添加一个 Stop 按钮，以允许我们取消预定的操作。

这个按钮只有在操作被预定时才会启用，这意味着一旦单击左按钮，用户可以等待 5 秒，或者单击 Stop 按钮立即再次启用它：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/d3b3fcb2-7afe-4875-83aa-f97e554a4787.png)

# 如何做到这一点...

`after_cancel()`方法通过获取先前调用`after()`返回的标识符来取消预定操作的执行。在这个例子中，这个值存储在`scheduled_id`属性中：

```py
import time
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.button = tk.Button(self, command=self.start_action,
                                text="Wait 5 seconds")
        self.cancel = tk.Button(self, command=self.cancel_action,
                                text="Stop", state=tk.DISABLED)
        self.button.pack(padx=30, pady=20, side=tk.LEFT)
        self.cancel.pack(padx=30, pady=20, side=tk.LEFT)

    def start_action(self):
        self.button.config(state=tk.DISABLED)
        self.cancel.config(state=tk.NORMAL)
        self.scheduled_id = self.after(5000, self.init_buttons)

    def init_buttons(self):
        self.button.config(state=tk.NORMAL)
        self.cancel.config(state=tk.DISABLED)

    def cancel_action(self):
        print("Canceling scheduled", self.scheduled_id)
        self.after_cancel(self.scheduled_id)
        self.init_buttons()

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 它是如何工作的...

要取消回调，我们首先需要`after()`返回的警报标识符。我们将把这个标识符存储在`scheduled_id`属性中，因为我们将在一个单独的方法中需要它：

```py
    def start_action(self):
        self.button.config(state=tk.DISABLED)
        self.cancel.config(state=tk.NORMAL)
        self.scheduled_id = self.after(5000, self.init_buttons)
```

然后，该字段被传递给`Stop`按钮的回调函数中的`after_cancel()`：

```py
    def cancel_action(self):
        print("Canceling scheduled", self.scheduled_id)
        self.after_cancel(self.scheduled_id)
        self.init_buttons()
```

在我们的情况下，一旦单击`Start`按钮，将其禁用是很重要的，因为如果`start_action()`被调用两次，`scheduled_id`将被覆盖，而`Stop`按钮只能取消最后一个预定的操作。

顺便说一句，如果我们使用已经执行过的警报标识符调用`after_cancel()`，它将没有效果。

# 还有更多...

在本节中，我们介绍了如何取消预定的警报，但是如果此回调正在轮询后台线程的状态，您可能会想知道如何停止线程。

不幸的是，没有官方的 API 可以优雅地停止`Thread`实例。如果您已经定义了一个自定义子类，您可能需要在其`run()`方法中定期检查的标志。

```py
class MyAsyncAction(threading.Thread):
    def __init__(self):
        super().__init__()
        self.do_stop = False

    def run(self):
        # Start execution...
        if not self.do_stop:
            # Continue execution...
```

然后，当调用`after_cancel()`时，这个标志可以通过设置`thread.do_stop = True`来外部修改，也可以停止线程。

显然，这种方法将严重依赖于`run()`方法内部执行的操作，例如，如果它由一个循环组成，那么您可以在每次迭代之间执行此检查。

从 Python 3.4 开始，您可以使用`asyncio`模块，其中包括管理异步操作的类和函数，包括取消。尽管这个模块超出了本书的范围，但如果您面对更复杂的情况，我们建议您探索一下。

# 处理空闲任务

有些情况下，某个操作会导致程序执行时出现短暂的暂停。它甚至可能不到一秒就完成，但对于用户来说仍然是可察觉的，因为它在 GUI 中引入了短暂的暂停。

在这个配方中，我们将讨论如何处理这些情况，而无需在单独的线程中处理整个任务。

# 准备工作

我们将从*Scheduling actions*配方中取一个例子，但超时时间为 1 秒，而不是 5 秒。

# 如何做...

当我们将按钮的状态更改为`DISABLED`时，回调函数继续执行，因此按钮的状态实际上直到系统处于空闲状态时才会更改，这意味着它必须等待`time.sleep()`完成。

但是，我们可以强制 Tkinter 在特定时刻更新所有挂起的 GUI 更新，如下面的脚本所示：

```py
import time
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.button = tk.Button(self, command=self.start_action,
                                text="Wait 1 second")
        self.button.pack(padx=30, pady=20)

    def start_action(self):
        self.button.config(state=tk.DISABLED)
        self.update_idletasks()
        time.sleep(1)
        self.button.config(state=tk.NORMAL)

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理...

在前面部分提到的代码片段中，关键是调用`self.update_idletasks()`。由于这一点，按钮状态的更改在调用`time.sleep()`之前由 Tkinter 处理。因此，在回调被暂停的一秒钟内，按钮具有期望的外观，而不是 Tkinter 在调用回调之前设置的`ACTIVE`状态。

我们使用`time.sleep()`来说明一个语句执行时间长，但足够短，可以考虑将其移到新线程中的情况——在现实世界的场景中，这将是一个更复杂的计算操作。

# 生成单独的进程

在某些情况下，仅使用线程可能无法实现应用程序所需的功能。例如，您可能希望调用用不同语言编写的单独程序。

在这种情况下，我们还需要使用`subprocess`模块从 Python 进程中调用目标程序。

# 准备工作

以下示例执行对指定 DNS 或 IP 地址的 ping 操作：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/tk-gui-app-dev-cb/img/2d22640c-8c92-43f6-8cec-59f2f6dcb862.png)

# 如何做...

像往常一样，我们定义一个自定义的`AsyncAction`方法，但在这种情况下，我们使用 Entry 小部件中设置的值调用`subprocess.run()`。

这个函数启动一个单独的子进程，与线程不同，它使用单独的内存空间。这意味着为了获得`ping`命令的结果，我们必须将打印到标准输出的结果进行管道传输，并在我们的 Python 程序中读取它：

```py
import threading
import subprocess
import tkinter as tk

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.entry = tk.Entry(self)
        self.button = tk.Button(self, text="Ping!",
                                command=self.do_ping)
        self.output = tk.Text(self, width=80, height=15)

        self.entry.grid(row=0, column=0, padx=5, pady=5)
        self.button.grid(row=0, column=1, padx=5, pady=5)
        self.output.grid(row=1, column=0, columnspan=2,
                         padx=5, pady=5)

    def do_ping(self):
        self.button.config(state=tk.DISABLED)
        thread = AsyncAction(self.entry.get())
        thread.start()
        self.poll_thread(thread)

    def poll_thread(self, thread):
        if thread.is_alive():
            self.after(100, lambda: self.poll_thread(thread))
        else:
            self.button.config(state=tk.NORMAL)
            self.output.delete(1.0, tk.END)
            self.output.insert(tk.END, thread.result)

class AsyncAction(threading.Thread):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip

    def run(self):
        self.result = subprocess.run(["ping", self.ip], shell=True,
                                     stdout=subprocess.PIPE).stdout

if __name__ == "__main__":
    app = App()
    app.mainloop()
```

# 工作原理...

`run()`函数执行数组参数中指定的子进程。默认情况下，结果只包含进程的返回代码，因此我们还传递了`stdout`选项和`PIPE`常量，以指示应将标准输出流进行管道传输。

我们使用关键字参数`shell`设置为`True`来调用这个函数，以避免为`ping`子进程打开新的控制台：

```py
    def run(self):
        self.result = subprocess.run(["ping", self.ip], shell=True,
                                     stdout=subprocess.PIPE).stdout
```

最后，当主线程验证该操作已完成时，将输出打印到 Text 小部件：

```py
    def poll_thread(self, thread):
        if thread.is_alive():
            self.after(100, lambda: self.poll_thread(thread))
        else:
            self.button.config(state=tk.NORMAL)
 self.output.delete(1.0, tk.END)
 self.output.insert(tk.END, thread.result)
```
