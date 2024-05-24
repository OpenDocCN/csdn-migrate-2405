# 精通 Python GUI 编程（二）

> 原文：[`zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408`](https://zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 QMainWindow 构建应用程序

基本的 Qt 小部件可以在构建简单表单时带我们走很远，但完整的应用程序包括诸如菜单、工具栏、对话框等功能，这些功能可能很繁琐和棘手，从头开始构建。幸运的是，PyQt 为这些标准组件提供了现成的类，使构建应用程序相对轻松。

在本章中，我们将探讨以下主题：

+   `QMainWindow`类

+   标准对话框

+   使用`QSettings`保存设置

# 技术要求

本章将需要与第一章的设置相同。您可能还希望参考我们在 GitHub 存储库中找到的代码，网址为[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter04`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter04)。

查看以下视频以查看代码的实际操作：[`bit.ly/2M5OGnq`](http://bit.ly/2M5OGnq)

# QMainWindow 类

到目前为止，我们一直在使用`QWidget`作为顶级窗口的基类。这对于简单的表单效果很好，但它缺少许多我们可能期望从应用程序的主窗口中得到的功能，比如菜单栏或工具栏。Qt 提供了`QMainWindow`类来满足这种需求。

从第一章的应用程序模板中复制一份，并进行一个小但至关重要的更改：

```py
class MainWindow(qtw.QMainWindow):
```

我们不再继承自`QWidget`，而是继承自`QMainWindow`。正如您将看到的，这将改变我们编写 GUI 的方式，但也会为我们的主窗口添加许多很好的功能。

为了探索这些新功能，让我们构建一个简单的纯文本编辑器。以下屏幕截图显示了我们完成的编辑器的外观，以及显示`QMainWindow`类的主要组件的标签：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/67b30b0a-e7d2-42cf-8b9d-3d2f92ee0828.png)

保存您更新的模板，将其复制到一个名为`text_editor.py`的新文件中，并在您的代码编辑器中打开新文件。让我们开始吧！

# 设置中央小部件

`QMainWindow`分为几个部分，其中最重要的是**中央小部件**。这是一个代表界面主要业务部分的单个小部件。

我们通过将任何小部件的引用传递给`QMainWindow.setCentralWidget（）`方法来设置这一点，就像这样：

```py
        self.textedit = qtw.QTextEdit()
        self.setCentralWidget(self.textedit)
```

只能有一个中央小部件，因此在更复杂的应用程序（例如数据输入应用程序）中，它更可能是一个`QWidget`对象，您在其中安排了一个更复杂的 GUI；对于我们的简单文本编辑器，一个单独的`QTextEdit`小部件就足够了。请注意，我们没有在`QMainWindow`上设置布局；这样做会破坏组件的预设排列。 

# 添加状态栏

**状态栏**是应用程序窗口底部的一条条纹，用于显示短文本消息和信息小部件。在 Qt 中，状态栏是一个`QStatusBar`对象，我们可以将其分配给主窗口的`statusBar`属性。

我们可以像这样创建一个：

```py
        status_bar = qtw.QStatusBar()
        self.setStatusBar(status_bar)
        status_bar.showMessage('Welcome to text_editor.py')
```

然而，没有必要费这么大的劲；如果没有状态栏，`QMainWindow`对象的`statusBar（）`方法会自动创建一个新的状态栏，如果有状态栏，则返回现有的状态栏。

因此，我们可以将所有的代码简化为这样：

```py
        self.statusBar().showMessage('Welcome to text_editor.py')
```

`showMessage（）`方法确切地做了它所说的，显示状态栏中给定的字符串。这是状态栏最常见的用法；但是，`QStatusBar`对象也可以包含其他小部件。

例如，我们可以添加一个小部件来跟踪我们的字符计数：

```py
        charcount_label = qtw.QLabel("chars: 0")
        self.textedit.textChanged.connect(
            lambda: charcount_label.setText(
                "chars: " +
                str(len(self.textedit.toPlainText()))
                )
            )
        self.statusBar().addPermanentWidget(charcount_label)
```

每当我们的文本更改时，这个`QLabel`就会更新输入的字符数。

请注意，我们直接将其添加到状态栏，而不引用布局对象；`QStatusBar`具有自己的方法来添加或插入小部件，有两种模式：**常规**和**永久**。在常规模式下，如果状态栏发送了一个长消息来显示，小部件可能会被覆盖。在永久模式下，它们将保持可见。在这种情况下，我们使用`addPermanentWidget()`方法以永久模式添加`charcount_label`，这样它就不会被长文本消息覆盖。

在常规模式下添加小部件的方法是`addWidget()`和`insertWidget()`；对于永久模式，请使用`addPermanentWidget()`和`insertPermanentWidget()`。

# 创建应用程序菜单

**应用程序菜单**对于大多数应用程序来说是一个关键功能，它提供了对应用程序所有功能的访问，以分层组织的下拉菜单形式。

我们可以使用`QMainWindow.menuBar()`方法轻松创建一个。

```py
        menubar = self.menuBar()
```

`menuBar()`方法返回一个`QMenuBar`对象，与`statusBar()`一样，如果存在窗口的现有菜单，此方法将返回该菜单，如果不存在，则会创建一个新的菜单。

默认情况下，菜单是空白的，但是我们可以使用菜单栏的`addMenu()`方法添加子菜单，如下所示：

```py
        file_menu = menubar.addMenu('File')
        edit_menu = menubar.addMenu('Edit')
        help_menu = menubar.addMenu('Help')
```

`addMenu()`返回一个`QMenu`对象，表示下拉子菜单。传递给该方法的字符串将用于标记主菜单栏中的菜单。

某些平台，如 macOS，不会显示空的子菜单。有关在 macOS 中构建菜单的更多信息，请参阅*macOS 上的菜单*部分。

要向这些菜单填充项目，我们需要创建一些**操作**。操作只是`QAction`类的对象，表示我们的程序可以执行的操作。要有用，`QAction`对象至少需要一个名称和一个回调；它们还可以为操作定义键盘快捷键和图标。

创建操作的一种方法是调用`QMenu`对象的`addAction()`方法，如下所示：

```py
        open_action = file_menu.addAction('Open')
        save_action = file_menu.addAction('Save')
```

我们创建了两个名为`Open`和`Save`的操作。它们实际上什么都没做，因为我们还没有分配回调方法，但是如果运行应用程序脚本，您会看到文件菜单确实列出了两个项目，`Open`和`Save`。

创建实际执行操作的项目，我们可以传入第二个参数，其中包含一个 Python 可调用对象或 Qt 槽：

```py
        quit_action = file_menu.addAction('Quit', self.destroy)
        edit_menu.addAction('Undo', self.textedit.undo)
```

对于需要更多控制的情况，可以显式创建`QAction`对象并将其添加到菜单中，如下所示：

```py
        redo_action = qtw.QAction('Redo', self)
        redo_action.triggered.connect(self.textedit.redo)
        edit_menu.addAction(redo_action)
```

`QAction`对象具有`triggered`信号，必须将其连接到可调用对象或槽，以使操作产生任何效果。当我们使用`addAction()`方法创建操作时，这将自动处理，但在显式创建`QAction`对象时，必须手动执行。

虽然在技术上不是必需的，但在显式创建`QAction`对象时传入父窗口小部件非常重要。如果未这样做，即使将其添加到菜单中，该项目也不会显示。

# macOS 上的菜单

`QMenuBar`默认包装操作系统的本机菜单系统。在 macOS 上，本机菜单系统有一些需要注意的特殊之处：

+   macOS 使用**全局菜单**，这意味着菜单栏不是应用程序窗口的一部分，而是附加到桌面顶部的栏上。默认情况下，您的主窗口的菜单栏将用作全局菜单。如果您有一个具有多个主窗口的应用程序，并且希望它们都使用相同的菜单栏，请不要使用`QMainWindow.menuBar()`来创建菜单栏。而是显式创建一个`QMenuBar`对象，并使用`setMenuBar()`方法将其分配给您使用的主窗口对象。

+   macOS 还有许多默认的子菜单和菜单项。要访问这些项目，只需在添加子菜单时使用相同的方法。有关添加子菜单的更多详细信息，请参阅*进一步阅读*部分中有关 macOS 菜单的更多详细信息。

+   如前所述，macOS 不会在全局菜单上显示空子菜单。

如果您发现这些问题对您的应用程序太具有问题，您可以始终指示 Qt 不使用本机菜单系统，就像这样：

```py
        self.menuBar().setNativeMenuBar(False)
```

这将在应用程序窗口中放置菜单栏，并消除特定于平台的问题。但是，请注意，这种方法会破坏 macOS 软件的典型工作流程，用户可能会感到不适。

有关 macOS 上的 Qt 菜单的更多信息，请访问[`doc.qt.io/qt-5/macos-issues.html#menu-bar`](https://doc.qt.io/qt-5/macos-issues.html#menu-bar)。

# 添加工具栏

**工具栏**是一排长按钮，通常用于编辑命令或类似操作。与主菜单不同，工具栏不是分层的，按钮通常只用图标标记。

`QMainWindow`允许我们使用`addToolBar()`方法向应用程序添加多个工具栏，就像这样：

```py
        toolbar = self.addToolBar('File')
```

`addToolBar()`方法创建并返回一个`QToolBar`对象。传递给该方法的字符串成为工具栏的标题。

我们可以像向`QMenu`对象添加`QAction`对象一样添加到`QToolBar`对象中：

```py
        toolbar.addAction(open_action)
        toolbar.addAction("Save")
```

与菜单一样，我们可以添加`QAction`对象，也可以只添加构建操作所需的信息（标题、回调等）。

运行应用程序；它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/f019127f-1cea-4671-84cd-3379db227da6.png)

请注意，工具栏的标题不会显示在工具栏上。但是，如果右键单击工具栏区域，您将看到一个弹出菜单，其中包含所有工具栏标题，带有复选框，允许您显示或隐藏应用程序的任何工具栏。

默认情况下，工具栏可以从应用程序中拆下并悬浮，或者停靠到应用程序的四个边缘中的任何一个。可以通过将`movable`和`floatable`属性设置为`False`来禁用此功能：

```py
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
```

您还可以通过将其`allowedAreas`属性设置为来自`QtCore.Qt.QToolBarAreas`枚举的标志组合，限制窗口的哪些边可以停靠该工具栏。

例如，让我们将工具栏限制为仅限于顶部和底部区域：

```py
        toolbar.setAllowedAreas(
            qtc.Qt.TopToolBarArea |
            qtc.Qt.BottomToolBarArea
        )
```

我们的工具栏当前具有带文本标签的按钮，但通常工具栏会有带图标标签的按钮。为了演示它的工作原理，我们需要一些图标。

我们可以从内置样式中提取一些图标，就像这样：

```py
        open_icon = self.style().standardIcon(qtw.QStyle.SP_DirOpenIcon)
        save_icon = self.style().standardIcon(qtw.QStyle.SP_DriveHDIcon)
```

现在不要担心这段代码的工作原理；有关样式和图标的完整讨论将在第六章 *Qt 应用程序的样式* 中进行。现在只需了解`open_icon`和`save_icon`是`QIcon`对象，这是 Qt 处理图标的方式。

这些可以附加到我们的`QAction`对象，然后可以将它们附加到工具栏，就像这样：

```py
        open_action.setIcon(open_icon)
        toolbar.addAction(open_action)
```

如您所见，这看起来好多了：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/7b1be327-2b73-4735-a461-fc53946a9f16.png)

注意，当您运行此代码时，菜单中的文件 | 打开选项现在也有图标。因为两者都使用`open_action`对象，我们对该操作对象所做的任何更改都将传递到对象的所有使用中。

图标对象可以作为第一个参数传递给工具栏的`addAction`方法，就像这样：

```py
        toolbar.addAction(
            save_icon,
            'Save',
            lambda: self.statusBar().showMessage('File Saved!')
        )
```

这将在工具栏中添加一个带有图标和一个相当无用的回调的保存操作。请注意，这一次，菜单中的文件 | 保存操作没有图标；尽管我们使用了相同的标签文本，在两个地方分别调用`addAction()`会导致两个不同且不相关的`QAction`对象。

最后，就像菜单一样，我们可以显式创建`QAction`对象，并将它们添加到工具栏中，就像这样：

```py
        help_action = qtw.QAction(
            self.style().standardIcon(qtw.QStyle.SP_DialogHelpButton),
            'Help',
            self,  # important to pass the parent!
            triggered=lambda: self.statusBar().showMessage(
                'Sorry, no help yet!'
                )
        )
        toolbar.addAction(help_action)
```

要在多个操作容器（工具栏、菜单等）之间同步操作，可以显式创建`QAction`对象，或者保存从`addAction()`返回的引用，以确保在每种情况下都添加相同的操作对象。

我们可以向应用程序添加任意数量的工具栏，并将它们附加到应用程序的任何一侧。要指定一侧，我们必须使用`addToolBar()`的另一种形式，就像这样：

```py
        toolbar2 = qtw.QToolBar('Edit')
        toolbar2.addAction('Copy', self.textedit.copy)
        toolbar2.addAction('Cut', self.textedit.cut)
        toolbar2.addAction('Paste', self.textedit.paste)
        self.addToolBar(qtc.Qt.RightToolBarArea, toolbar2)
```

要使用这种形式的`addToolBar()`，我们必须首先创建工具栏，然后将其与`QtCore.Qt.ToolBarArea`常量一起传递。

# 添加停靠窗口

**停靠窗口**类似于工具栏，但它们位于工具栏区域和中央窗口之间，并且能够包含任何类型的小部件。

添加一个停靠窗口就像显式创建一个工具栏一样：

```py
        dock = qtw.QDockWidget("Replace")
        self.addDockWidget(qtc.Qt.LeftDockWidgetArea, dock)
```

与工具栏一样，默认情况下，停靠窗口可以关闭，浮动或移动到应用程序的另一侧。要更改停靠窗口是否可以关闭，浮动或移动，我们必须将其`features`属性设置为`QDockWidget.DockWidgetFeatures`标志值的组合。

例如，让我们使用户无法关闭我们的停靠窗口，通过添加以下代码：

```py
        dock.setFeatures(
            qtw.QDockWidget.DockWidgetMovable |
            qtw.QDockWidget.DockWidgetFloatable
        )
```

我们已将`features`设置为`DockWidgetMovable`和`DockWidgetFloatable`。由于这里缺少`DockWidgetClosable`，用户将无法关闭小部件。

停靠窗口设计为容纳使用`setWidget()`方法设置的单个小部件。与我们主应用程序的`centralWidget`一样，我们通常会将其设置为包含某种表单或其他 GUI 的`QWidget`。

让我们构建一个表单放在停靠窗口中，如下所示：

```py
        replace_widget = qtw.QWidget()
        replace_widget.setLayout(qtw.QVBoxLayout())
        dock.setWidget(replace_widget)

        self.search_text_inp = qtw.QLineEdit(placeholderText='search')
        self.replace_text_inp = qtw.QLineEdit(placeholderText='replace')
        search_and_replace_btn = qtw.QPushButton(
            "Search and Replace",
            clicked=self.search_and_replace
            )
        replace_widget.layout().addWidget(self.search_text_inp)
        replace_widget.layout().addWidget(self.replace_text_inp)
        replace_widget.layout().addWidget(search_and_replace_btn)
        replace_widget.layout().addStretch()
```

`addStretch()`方法可以在布局上调用，以添加一个扩展的`QWidget`，将其他小部件推在一起。

这是一个相当简单的表单，包含两个`QLineEdit`小部件和一个按钮。当点击按钮时，它调用主窗口的`search_and_replace()`方法。让我们快速编写代码：

```py
    def search_and_replace(self):
        s_text = self.search_text_inp.text()
        r_text = self.replace_text_inp.text()

        if s_text:
            self.textedit.setText(
                self.textedit.toPlainText().replace(s_text, r_text)
                )
```

这种方法只是检索两行编辑的内容；然后，如果第一个中有内容，它将在文本编辑的内容中用第二个文本替换所有实例。

此时运行程序，您应该在应用程序的左侧看到我们的停靠窗口，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/755c0898-64be-465f-8532-8db0e1916875.png)

请注意停靠窗口右上角的图标。这允许用户将小部件分离并浮动到应用程序窗口之外。

# 其他`QMainWindow`功能

尽管我们已经涵盖了它的主要组件，但`QMainWindow`提供了许多其他功能和配置选项，您可以在其文档中探索这些选项[`doc.qt.io/qt-5/qmainwindow.html`](https://doc.qt.io/qt-5/qmainwindow.html)。我们可能会在未来的章节中涉及其中一些，因为我们将从现在开始广泛使用`QMainWindow`。

# 标准对话框

**对话框**在应用程序中通常是必需的，无论是询问问题，呈现表单还是仅向用户提供一些信息。Qt 提供了各种各样的现成对话框，用于常见情况，以及定义自定义对话框的能力。在本节中，我们将看一些常用的对话框类，并尝试设计自己的对话框。

# QMessageBox

`QMessageBox`是一个简单的对话框，主要用于显示短消息或询问是或否的问题。使用`QMessageBox`的最简单方法是利用其方便的静态方法，这些方法可以创建并显示一个对话框，而不需要太多麻烦。

六个静态方法如下：

| 功能 | 类型 | 对话框 |
| --- | --- | --- |
| `about()` | 非模态 | 显示应用程序的**关于**对话框，并提供给定的文本。 |
| `aboutQt()` | 非模态 | 显示 Qt 的**关于**对话框。 |
| `critical()` | 模态 | 显示带有提供的文本的关键错误消息。 |
| `information()` | 模态 | 显示带有提供的文本的信息消息。 |
| `warning()` | 模态 | 显示带有提供的文本的警告消息。 |
| `question()` | 模态 | 向用户提问。 |

这些对话框之间的主要区别在于默认图标，默认按钮和对话框的模态性。

对话框可以是**模态**的，也可以是**非模态**的。模态对话框阻止用户与程序的任何其他部分进行交互，并在显示时阻止程序执行，并且在完成时可以返回一个值。非模态对话框不会阻止执行，但它们也不会返回值。在模态`QMessageBox`的情况下，返回值是表示按下的按钮的`enum`常量。

让我们使用`about()`方法向我们的应用程序添加一个**关于**消息。首先，我们将创建一个回调来显示对话框：

```py
    def showAboutDialog(self):
        qtw.QMessageBox.about(
            self,
            "About text_editor.py",
```

```py
            "This is a text editor written in PyQt5."
        )
```

**关于**对话框是非模态的，因此它实际上只是一种被动显示信息的方式。参数依次是对话框的父窗口小部件，对话框的窗口标题文本和对话框的主要文本。

回到构造函数，让我们添加一个菜单操作来调用这个方法：

```py
        help_menu.addAction('About', self.showAboutDialog)
```

模态对话框可用于从用户那里检索响应。例如，我们可以警告用户我们的编辑器尚未完成，并查看他们是否真的打算使用它，如下所示：

```py
        response = qtw.QMessageBox.question(
            self,
            'My Text Editor',
            'This is beta software, do you want to continue?'
        )
        if response == qtw.QMessageBox.No:
            self.close()
            sys.exit()
```

所有模态对话框都返回与用户按下的按钮相对应的 Qt 常量；默认情况下，`question()`创建一个带有`QMessageBox.Yes`和`QMessageBox.No`按钮值的对话框，因此我们可以测试响应并做出相应的反应。还可以通过传入第四个参数来覆盖呈现的按钮，该参数包含使用管道运算符组合的多个按钮。

例如，我们可以将`No`更改为`Abort`，如下所示：

```py
        response = qtw.QMessageBox.question(
            self,
            'My Text Editor',
            'This is beta software, do you want to continue?',
            qtw.QMessageBox.Yes | qtw.QMessageBox.Abort
        )
        if response == qtw.QMessageBox.Abort:
            self.close()
            sys.exit()
```

如果静态的`QMessageBox`方法不提供足够的灵活性，还可以显式创建`QMessageBox`对象，如下所示：

```py
        splash_screen = qtw.QMessageBox()
        splash_screen.setWindowTitle('My Text Editor')
        splash_screen.setText('BETA SOFTWARE WARNING!')
        splash_screen.setInformativeText(
            'This is very, very beta, '
            'are you really sure you want to use it?'
        )
        splash_screen.setDetailedText(
            'This editor was written for pedagogical '
            'purposes, and probably is not fit for real work.'
        )
        splash_screen.setWindowModality(qtc.Qt.WindowModal)
        splash_screen.addButton(qtw.QMessageBox.Yes)
        splash_screen.addButton(qtw.QMessageBox.Abort)
        response = splash_screen.exec()
        if response == qtw.QMessageBox.Abort:
            self.close()
            sys.exit()
```

正如您所看到的，我们可以在消息框上设置相当多的属性；这些在这里描述：

| 属性 | 描述 |
| --- | --- |
| `windowTitle` | 对话框任务栏和标题栏中打印的标题。 |
| `text` | 对话框中显示的文本。 |
| `informativeText` | 在`text`字符串下显示的较长的解释性文本，通常以较小或较轻的字体显示。 |
| `detailedText` | 将隐藏在“显示详细信息”按钮后面并显示在滚动文本框中的文本。用于调试或日志输出。 |
| `windowModality` | 用于设置消息框是模态还是非模态。需要一个`QtCore.Qt.WindowModality`常量。 |

我们还可以使用`addButton()`方法向对话框添加任意数量的按钮，然后通过调用其`exec()`方法显示对话框。如果我们配置对话框为模态，此方法将返回与单击的按钮匹配的常量。

# QFileDialog

应用程序通常需要打开或保存文件，用户需要一种简单的方法来浏览和选择这些文件。 Qt 为我们提供了`QFileDialog`类来满足这种需求。

与`QMessageBox`一样，`QFileDialog`类包含几个静态方法，显示适当的模态对话框并返回用户选择的值。

此表显示了静态方法及其预期用途：

| 方法 | 返回 | 描述 |
| --- | --- | --- |
| `getExistingDirectory` | String | 选择现有目录路径。 |
| `getExistingDirectoryUrl` | `QUrl` | 选择现有目录 URL。 |
| `getOpenFileName` | String | 选择要打开的现有文件名路径。 |
| `getOpenFileNames` | List | 选择多个现有文件名路径以打开。 |
| `getOpenFileUrl` | `QUrl` | 选择现有文件名 URL。 |
| `getSaveFileName` | String | 选择要保存到的新文件名路径或现有文件名路径。 |
| `getSaveFileUrl` | `QUrl` | 选择新的或现有的 URL。 |

在支持的平台上，这些方法的 URL 版本允许选择远程文件和目录。

要了解文件对话框的工作原理，让我们在应用程序中创建打开文件的能力：

```py
    def openFile(self):
        filename, _ = qtw.QFileDialog.getOpenFileName()
        if filename:
            try:
                with open(filename, 'r') as fh:
                    self.textedit.setText(fh.read())
            except Exception as e:
                qtw.QMessageBox.critical(f"Could not load file: {e}")
```

`getOpenFileName()`返回一个包含所选文件名和所选文件类型过滤器的元组。如果用户取消对话框，将返回一个空字符串作为文件名，并且我们的方法将退出。如果我们收到一个文件名，我们尝试打开文件并将`textedit`小部件的内容写入其中。

由于我们不使用方法返回的第二个值，我们将其分配给`_`（下划线）变量。这是命名不打算使用的变量的标准 Python 约定。

`getOpenFileName()`有许多用于配置对话框的参数，所有这些参数都是可选的。按顺序，它们如下：

1.  父窗口小部件

1.  标题，用于窗口标题

1.  起始目录，作为路径字符串

1.  文件类型过滤器下拉菜单可用的过滤器

1.  默认选择的过滤器

1.  选项标志

例如，让我们配置我们的文件对话框：

```py
        filename, _ = qtw.QFileDialog.getOpenFileName(
            self,
            "Select a text file to open…",
            qtc.QDir.homePath(),
            'Text Files (*.txt) ;;Python Files (*.py) ;;All Files (*)',
            'Python Files (*.py)',
            qtw.QFileDialog.DontUseNativeDialog |
            qtw.QFileDialog.DontResolveSymlinks
        )
```

`QDir.homePath()`是一个返回用户主目录的静态方法。

请注意，过滤器被指定为单个字符串；每个过滤器都是一个描述加上括号内的通配符字符串，并且过滤器之间用双分号分隔。这将导致一个看起来像这样的过滤器下拉菜单：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/cf80d69c-0bbc-402c-8a6b-ec719c7d9afe.png)

最后，我们可以使用管道运算符组合一系列选项标志。在这种情况下，我们告诉 Qt 不要使用本机 OS 文件对话框，也不要解析符号链接（这两者都是默认情况下）。有关选项标志的完整列表，请参阅`QFileDialog`文档[`doc.qt.io/qt-5/qfiledialog.html#Option-enum`](https://doc.qt.io/qt-5/qfiledialog.html#Option-enum)。

保存文件对话框的工作方式基本相同，但提供了更适合保存文件的界面。我们可以实现我们的`saveFile()`方法如下：

```py
    def saveFile(self):
        filename, _ = qtw.QFileDialog.getSaveFileName(
            self,
            "Select the file to save to…",
            qtc.QDir.homePath(),
            'Text Files (*.txt) ;;Python Files (*.py) ;;All Files (*)'
        )
        if filename:
            try:
                with open(filename, 'w') as fh:
                    fh.write(self.textedit.toPlainText())
            except Exception as e:
                qtw.QMessageBox.critical(f"Could not save file: {e}")
```

其他`QFileDialog`便利方法的工作方式相同。与`QMessageBox`一样，也可以显式创建一个`QFileDialog`对象，手动配置其属性，然后使用其`exec()`方法显示它。然而，这很少是必要的，因为内置方法对大多数文件选择情况都是足够的。

在继续之前，不要忘记在`MainWindow`构造函数中添加调用这些方法的操作：

```py
        open_action.triggered.connect(self.openFile)
        save_action.triggered.connect(self.saveFile)
```

# QFontDialog

Qt 提供了许多其他方便的选择对话框，类似于`QFileDialog`；其中一个对话框是`QFontDialog`，允许用户选择和配置文本字体的各个方面。

与其他对话框类一样，最简单的方法是调用静态方法显示对话框并返回用户的选择，这种情况下是`getFont()`方法。

让我们在`MainWindow`类中添加一个回调方法来设置编辑器字体：

```py
    def set_font(self):
        current = self.textedit.currentFont()
        font, accepted = qtw.QFontDialog.getFont(current, self)
        if accepted:
            self.textedit.setCurrentFont(font)
```

`getFont`以当前字体作为参数，这使得它将所选字体设置为当前字体（如果您忽略这一点，对话框将默认为列出的第一个字体）。

它返回一个包含所选字体和一个布尔值的元组，指示用户是否点击了确定。字体作为`QFont`对象返回，该对象封装了字体系列、样式、大小、效果和字体的书写系统。我们的方法可以将此对象传回到`QTextEdit`对象的`setCurrentFont()`槽中，以设置其字体。

与`QFileDialog`一样，如果操作系统有原生字体对话框，Qt 会尝试使用它；否则，它将使用自己的小部件。您可以通过将`DontUseNativeDialog`选项传递给`options`关键字参数来强制使用对话框的 Qt 版本，就像我们在这里做的那样：

```py
        font, accepted = qtw.QFontDialog.getFont(
            current,
            self,
            options=(
                qtw.QFontDialog.DontUseNativeDialog |
                qtw.QFontDialog.MonospacedFonts
            )
        )
```

我们还在这里传入了一个选项，以限制对话框为等宽字体。有关可用选项的更多信息，请参阅`QFontDialog`的 Qt 文档[`doc.qt.io/qt-5/qfontdialog.html#FontDialogOption-enum`](https://doc.qt.io/qt-5/qfontdialog.html#FontDialogOption-enum)。

# 其他对话框

Qt 包含其他对话框类，用于选择颜色、请求输入值等。所有这些类似于文件和字体对话框，它们都是`QDialog`类的子类。我们可以自己子类化`QDialog`来创建自定义对话框。

例如，假设我们想要一个对话框来输入我们的设置。我们可以像这样开始构建它：

```py
class SettingsDialog(qtw.QDialog):
    """Dialog for setting the settings"""

    def __init__(self, settings, parent=None):
        super().__init__(parent, modal=True)
        self.setLayout(qtw.QFormLayout())
        self.settings = settings
        self.layout().addRow(
            qtw.QLabel('<h1>Application Settings</h1>'),
        )
        self.show_warnings_cb = qtw.QCheckBox(
            checked=settings.get('show_warnings')
        )
        self.layout().addRow("Show Warnings", self.show_warnings_cb)

        self.accept_btn = qtw.QPushButton('Ok', clicked=self.accept)
        self.cancel_btn = qtw.QPushButton('Cancel', clicked=self.reject)
        self.layout().addRow(self.accept_btn, self.cancel_btn)
```

这段代码与我们在过去章节中使用`QWidget`创建的弹出框并没有太大的区别。然而，通过使用`QDialog`，我们可以免费获得一些东西，特别是这些：

+   我们获得了`accept`和`reject`插槽，可以将适当的按钮连接到这些插槽。默认情况下，这些会导致窗口关闭并分别发出`accepted`或`rejected`信号。

+   我们还可以使用`exec()`方法，该方法返回一个布尔值，指示对话框是被接受还是被拒绝。

+   我们可以通过向`super()`构造函数传递适当的值来轻松设置对话框为模态或非模态。

`QDialog`为我们提供了很多灵活性，可以让我们如何利用用户输入的数据。例如，我们可以使用信号来发射数据，或者重写`exec()`来返回数据。

在这种情况下，由于我们传入了一个可变的`dict`对象，我们将重写`accept()`来修改那个`dict`对象：

```py
    def accept(self):
        self.settings['show_warnings'] = self.show_warnings_cb.isChecked()
        super().accept()
```

回到`MainWindow`类，让我们创建一个属性和方法来使用新的对话框：

```py
class MainWindow(qtw.QMainWindow):

    settings = {'show_warnings': True}

    def show_settings(self):
        settings_dialog = SettingsDialog(self.settings, self)
        settings_dialog.exec()
```

使用`QDialog`类就像创建对话框类的实例并调用`exec()`一样简单。在这种情况下，由于我们直接编辑我们的`settings` dict，所以我们不需要担心连接`accepted`信号或使用`exec()`的输出。

# 使用 QSettings 保存设置

任何合理大小的应用程序都可能积累需要在会话之间存储的设置。保存这些设置通常涉及大量繁琐的文件操作和数据序列化工作，当我们希望跨平台良好地工作时，这种工作变得更加复杂。Qt 的`QtCore.QSettings`类解救了我们。

`QSettings`类是一个简单的键值数据存储，会以平台适当的方式自动持久化。例如，在 Windows 上，设置存储在注册表数据库中，而在 Linux 上，它们被放置在`~/.config`下的纯文本配置文件中。

让我们用`QSettings`对象替换我们在文本编辑器中创建的设置`dict`对象。

要创建一个`QSettings`对象，我们需要传入公司名称和应用程序名称，就像这样：

```py
class MainWindow(qtw.QMainWindow):

    settings = qtc.QSettings('Alan D Moore', 'text editor')
```

这些字符串将确定存储设置的注册表键或文件路径。例如，在 Linux 上，此设置文件将保存在`~/.config/Alan D Moore/text editor.conf`。在 Windows 上，它将存储在注册表中的`HKEY_CURRENT_USER\Alan D Moore\text editor\`。

我们可以使用对象的`value()`方法查询任何设置的值；例如，我们可以根据`show_warnings`设置使我们的启动警告对话框成为有条件的：

```py
        if self.settings.value('show_warnings', False, type=bool):
            # Warning dialog code follows...
```

`value()`的参数是键字符串、如果未找到键则是默认值，以及`type`关键字参数，告诉`QSettings`如何解释保存的值。`type`参数至关重要；并非所有平台都能以明确的方式充分表示所有数据类型。例如，如果未指定数据类型，则布尔值将作为字符串`true`和`false`返回，这两者在 Python 中都是`True`。

设置键的值使用`setValue()`方法，就像在`SettingsDialog.accept()`方法中所示的那样：

```py
        self.settings.setValue(
            'show_warnings',
            self.show_warnings_cb.isChecked()
        )
```

请注意，我们不必做任何事情将这些值存储到磁盘上；它们会被 Qt 事件循环定期自动同步到磁盘上。它们也会在创建`QSettings`对象的时候自动从磁盘上读取。简单地用`QSettings`对象替换我们原来的`settings` dict 就足以让我们获得持久的设置，而无需编写一行文件 I/O 代码！

# QSettings 的限制

尽管它们很强大，`QSettings`对象不能存储任何东西。设置对象中的所有值都存储为`QVariant`对象，因此只有可以转换为`QVariant`的对象才能存储。这包括了一个长列表的类型，包括几乎任何 Python 内置类型和`QtCore`中的大多数数据类。甚至函数引用也可以被存储（尽管不是函数定义）。

不幸的是，如果你尝试存储一个无法正确存储的对象，`QSettings.setValue()`既不会抛出异常也不会返回错误。它会在控制台打印警告并存储一些可能不会有用的东西，例如：

```py
app = qtw.QApplication([])
s = qtc.QSettings('test')
s.setValue('app', app)
# Prints: QVariant::save: unable to save type 'QObject*' (type id: 39).
```

一般来说，如果你正在存储清晰表示数据的对象，你不应该遇到问题。

`QSettings`对象的另一个主要限制是它无法自动识别一些存储对象的数据类型，就像我们在布尔值中看到的那样。因此，在处理任何不是字符串值的东西时，传递`type`参数是至关重要的。

# 总结

在本章中，你学习了有助于构建完整应用程序的 PyQt 类。你学习了`QMainWindow`类，它的菜单、状态栏、工具栏和停靠窗口。你还学习了从`QDialog`派生的标准对话框和消息框，以及如何使用`QSettings`存储应用程序设置。

在下一章中，我们将学习 Qt 中的模型-视图类，这将帮助我们分离关注点并创建更健壮的应用程序设计。

# 问题

尝试这些问题来测试你从本章中学到的知识：

1.  你想要使用`QMainWindow`与第三章中的`calendar_app.py`脚本，*使用信号和槽处理事件*。你会如何进行转换？

1.  你正在开发一个应用程序，并将子菜单名称添加到菜单栏，但没有填充任何子菜单项。你的同事说在他们测试时，他们的桌面上没有出现任何菜单名称。你的代码看起来是正确的；这里可能出了什么问题？

1.  你正在开发一个代码编辑器，并希望为与调试器交互创建一个侧边栏面板。哪个`QMainWindow`特性对这个任务最合适？

1.  以下代码不正确；无论点击什么都会继续进行。为什么它不起作用，你该如何修复它？

```py
    answer = qtw.QMessageBox.question(
        None, 'Continue?', 'Run this program?')
    if not answer:
        sys.exit()
```

1.  你正在通过子类化`QDialog`来构建一个自定义对话框。你需要将输入到对话框中的信息传回主窗口对象。以下哪种方法将不起作用？

+   1.  传入一个可变对象，并使用对话框的`accept()`方法来更改其值。

1.  重写对象的`accept()`方法，并让它返回输入值的字典。

1.  重写对话框的`accepted`信号，使其传递输入值的字典。将此信号连接到主窗口类中的回调函数。

1.  你正在 Linux 上编写一个名为**SuperPhoto**的照片编辑器。你已经编写了代码并保存了用户设置，但在`~/.config/`中找不到`SuperPhoto.conf`。查看代码并确定出了什么问题：

```py
    settings = qtc.QSettings()
    settings.setValue('config_file', 'SuperPhoto.conf')
    settings.setValue('default_color', QColor('black'))
    settings.sync()
```

1.  你正在从设置对话框保存偏好设置，但由于某种原因，保存的设置回来的时候非常奇怪。这里有什么问题？

```py
    settings = qtc.QSettings('My Company', 'SuperPhoto')
    settings.setValue('Default Name', dialog.default_name_edit.text)
    settings.setValue('Use GPS', dialog.gps_checkbox.isChecked)
    settings.setValue('Default Color', dialog.color_picker.color)
```

# 进一步阅读

有关更多信息，请参考以下内容：

+   Qt 的`QMainWindow`文档可以在[`doc.qt.io/qt-5/qmainwindow.html`](https://doc.qt.io/qt-5/qmainwindow.html)找到。

+   使用`QMainWindow`的示例可以在[`github.com/pyqt/examples/tree/master/mainwindows`](https://github.com/pyqt/examples/tree/master/mainwindows)找到。

+   苹果的 macOS 人机界面指南包括如何构建应用程序菜单的指导。这些可以在[`developer.apple.com/design/human-interface-guidelines/macos/menus/menu-anatomy/`](https://developer.apple.com/design/human-interface-guidelines/macos/menus/menu-anatomy/)找到。

+   微软提供了有关为 Windows 应用程序设计菜单的指南，网址为[`docs.microsoft.com/en-us/windows/desktop/uxguide/cmd-menus`](https://docs.microsoft.com/en-us/windows/desktop/uxguide/cmd-menus)。

+   PyQt 提供了一些关于对话框使用的示例，网址为[`github.com/pyqt/examples/tree/master/dialogs`](https://github.com/pyqt/examples/tree/master/dialogs)。

+   `QMainWindow`也可以用于创建**多文档界面**（**MDIs**）。有关如何构建 MDI 应用程序的更多信息，请参见[`www.pythonstudio.us/pyqt-programming/multiple-document-interface-mdi.html`](https://www.pythonstudio.us/pyqt-programming/multiple-document-interface-mdi.html)，以及[`doc.qt.io/qt-5/qtwidgets-mainwindows-mdi-example.html`](https://doc.qt.io/qt-5/qtwidgets-mainwindows-mdi-example.html)上的示例代码。


# 第五章：使用模型-视图类创建数据接口

绝大多数应用软件都是用来查看和操作组织好的数据。即使在不是显式*数据库应用程序*的应用程序中，通常也需要以较小的规模与数据集进行交互，比如用选项填充组合框或显示一系列设置。如果没有某种组织范式，GUI 和一组数据之间的交互很快就会变成一团乱麻的代码噩梦。**模型-视图**模式就是这样一种范式。

在本章中，我们将学习如何使用 Qt 的模型-视图小部件以及如何在应用程序中优雅地处理数据。我们将涵盖以下主题：

+   理解模型-视图设计

+   PyQt 中的模型和视图

+   构建一个**逗号分隔值**（**CSV**）编辑器

# 技术要求

本章具有与前几章相同的技术要求。您可能还希望从[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter05`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter05)获取示例代码。

您还需要一个或两个 CSV 文件来使用我们的 CSV 编辑器。这些可以在任何电子表格程序中制作，并且应该以列标题作为第一行创建。

查看以下视频，看看代码是如何运行的：[`bit.ly/2M66bnv`](http://bit.ly/2M66bnv)

# 理解模型-视图设计

模型-视图是一种实现**关注点分离**的软件应用设计范式。它基于古老的**模型-视图-控制器**（**MVC**）模式，但不同之处在于控制器和视图被合并成一个组件。

在模型-视图设计中，**模型**是保存应用程序数据并包含检索、存储和操作数据逻辑的组件。**视图**组件向用户呈现数据，并提供输入和操作数据的界面。通过将应用程序的这些组件分离，我们将它们的相互依赖性降到最低，使它们更容易重用或重构。

让我们通过一个简单的例子来说明这个过程。从第四章的应用程序模板开始，*使用 QMainWindow 构建应用程序*，让我们构建一个简单的文本文件编辑器：

```py
    # This code goes in MainWindow.__init__()
    form = qtw.QWidget()
    self.setCentralWidget(form)
    form.setLayout(qtw.QVBoxLayout())
    self.filename = qtw.QLineEdit()
    self.filecontent = qtw.QTextEdit()
    self.savebutton = qtw.QPushButton(
      'Save',
      clicked=self.save
    )

    form.layout().addWidget(self.filename)
    form.layout().addWidget(self.filecontent)
    form.layout().addWidget(self.savebutton)
```

这是一个简单的表单，包括一个用于文件名的行编辑，一个用于内容的文本编辑和一个调用`save()`方法的保存按钮。

让我们创建以下`save()`方法：

```py
  def save(self):
    filename = self.filename.text()
    error = ''
    if not filename:
      error = 'Filename empty'
    elif path.exists(filename):
      error = f'Will not overwrite {filename}'
    else:
      try:
        with open(filename, 'w') as fh:
          fh.write(self.filecontent.toPlainText())
      except Exception as e:
        error = f'Cannot write file: {e}'
    if error:
      qtw.QMessageBox.critical(None, 'Error', error)
```

这种方法检查是否在行编辑中输入了文件名，确保文件名不存在（这样你就不会在测试这段代码时覆盖重要文件！），然后尝试保存它。如果出现任何错误，该方法将显示一个`QMessageBox`实例来报告错误。

这个应用程序可以工作，但缺乏清晰的模型和视图分离。将文件写入磁盘的同一个方法也显示错误框并调用输入小部件方法。如果我们要扩展这个应用程序到任何程度，`save()`方法很快就会变成一个混合了数据处理逻辑和呈现逻辑的迷宫。

让我们用单独的`Model`和`View`类重写这个应用程序。

从应用程序模板的干净副本开始，让我们创建我们的`Model`类：

```py
class Model(qtc.QObject):

  error = qtc.pyqtSignal(str)

  def save(self, filename, content):
    print("save_called")
    error = ''
    if not filename:
      error = 'Filename empty'
    elif path.exists(filename):
      error = f'Will not overwrite {filename}'
    else:
      try:
        with open(filename, 'w') as fh:
          fh.write(content)
      except Exception as e:
        error = f'Cannot write file: {e}'
    if error:
      self.error.emit(error)
```

我们通过子类化`QObject`来构建我们的模型。模型不应参与显示 GUI，因此不需要基于`QWidget`类。然而，由于模型将使用信号和槽进行通信，我们使用`QObject`作为基类。模型实现了我们在前面示例中的`save()`方法，但有两个变化：

+   首先，它期望用户数据作为参数传入，不知道这些数据来自哪些小部件

+   其次，当遇到错误时，它仅仅发出一个 Qt 信号，而不采取任何特定于 GUI 的操作

接下来，让我们创建我们的`View`类：

```py
class View(qtw.QWidget):

  submitted = qtc.pyqtSignal(str, str)

  def __init__(self):
    super().__init__()
    self.setLayout(qtw.QVBoxLayout())
    self.filename = qtw.QLineEdit()
    self.filecontent = qtw.QTextEdit()
    self.savebutton = qtw.QPushButton(
      'Save',
      clicked=self.submit
    )
    self.layout().addWidget(self.filename)
    self.layout().addWidget(self.filecontent)
    self.layout().addWidget(self.savebutton)

  def submit(self):
    filename = self.filename.text()
    filecontent = self.filecontent.toPlainText()
    self.submitted.emit(filename, filecontent)

  def show_error(self, error):
    qtw.QMessageBox.critical(None, 'Error', error)
```

这个类包含与之前相同的字段和字段布局定义。然而，这一次，我们的保存按钮不再调用`save()`，而是连接到一个`submit()`回调，该回调收集表单数据并使用信号发射它。我们还添加了一个`show_error()`方法来显示错误。

在我们的`MainWindow.__init__()`方法中，我们将模型和视图结合在一起：

```py
    self.view = View()
    self.setCentralWidget(self.view)

    self.model = Model()

    self.view.submitted.connect(self.model.save)
    self.model.error.connect(self.view.show_error)
```

在这里，我们创建`View`类的一个实例和`Model`类，并连接它们的信号和插槽。

在这一点上，我们的代码的模型视图版本的工作方式与我们的原始版本完全相同，但涉及更多的代码。你可能会问，这有什么意义？如果这个应用程序注定永远不会超出它现在的状态，那可能没有意义。然而，应用程序往往会在功能上扩展，并且通常其他应用程序需要重用相同的代码。考虑以下情况：

+   你想提供另一种编辑形式，也许是基于控制台的，或者具有更多的编辑功能

+   你想提供将内容保存到数据库而不是文本文件的选项

+   你正在创建另一个也将文本内容保存到文件的应用程序

在这些情况下，使用模型视图模式意味着我们不必从头开始。例如，在第一种情况下，我们不需要重写任何保存文件的代码；我们只需要创建用户界面代码，发射相同的`submitted`信号。随着你的代码扩展和你的应用程序变得更加复杂，这种关注点的分离将帮助你保持秩序。

# PyQt 中的模型和视图

模型视图模式不仅在设计大型应用程序时有用，而且在包含数据的小部件上也同样有用。从第四章中复制应用程序模板，*使用 QMainWindow 构建应用程序*，让我们看一个模型视图在小部件级别上是如何工作的简单示例。

在`MainWindow`类中，创建一个项目列表，并将它们添加到`QListWidget`和`QComboBox`对象中：

```py
    data = [
      'Hamburger', 'Cheeseburger',
      'Chicken Nuggets', 'Hot Dog', 'Fish Sandwich'
    ]
    # The list widget
    listwidget = qtw.QListWidget()
    listwidget.addItems(data)
    # The combobox
    combobox = qtw.QComboBox()
    combobox.addItems(data)
    self.layout().addWidget(listwidget)
    self.layout().addWidget(combobox)
```

因为这两个小部件都是用相同的列表初始化的，所以它们都包含相同的项目。现在，让我们使列表小部件的项目可编辑：

```py
    for i in range(listwidget.count()):
      item = listwidget.item(i)
      item.setFlags(item.flags() | qtc.Qt.ItemIsEditable)
```

通过迭代列表小部件中的项目，并在每个项目上设置`Qt.ItemIsEditable`标志，小部件变得可编辑，我们可以改变项目的文本。运行应用程序，尝试编辑列表小部件中的项目。即使你改变了列表小部件中的项目，组合框中的项目仍然保持不变。每个小部件都有自己的内部列表模型，它存储了最初传入的项目的副本。在一个列表的副本中改变项目对另一个副本没有影响。

我们如何保持这两个列表同步？我们可以连接一些信号和插槽，或者添加类方法来做到这一点，但 Qt 提供了更好的方法。

`QListWidget`实际上是另外两个 Qt 类的组合：`QListView`和`QStringListModel`。正如名称所示，这些都是模型视图类。我们可以直接使用这些类来构建我们自己的带有离散模型和视图的列表小部件：

```py
    model = qtc.QStringListModel(data)
    listview = qtw.QListView()
    listview.setModel(model)
```

我们简单地创建我们的模型类，用我们的字符串列表初始化它，然后创建视图类。最后，我们使用视图的`setModel()`方法连接两者。

`QComboBox`没有类似的模型视图类，但它仍然在内部是一个模型视图小部件，并且具有使用外部模型的能力。

因此，我们可以使用`setModel()`将我们的`QStringListModel`传递给它：

```py
    model_combobox = qtw.QComboBox()
    model_combobox.setModel(model)
```

将这些小部件添加到布局中，然后再次运行程序。这一次，你会发现对`QListView`的编辑立即在组合框中可用，因为你所做的更改被写入了`QStringModel`对象，这两个小部件都会查询项目数据。

`QTableWidget`和`QTreeWidget`也有类似的视图类：`QTableView`和`QTreeView`。然而，没有现成的模型类可以与这些视图一起使用。相反，我们必须通过分别继承`QAbstractTableModel`和`QAbstractTreeModel`来创建自己的自定义模型类。

在下一节中，我们将通过构建自己的 CSV 编辑器来介绍如何创建和使用自定义模型类。

# 构建 CSV 编辑器

逗号分隔值（CSV）是一种存储表格数据的纯文本格式。任何电子表格程序都可以导出为 CSV，或者您可以在文本编辑器中手动创建。我们的程序将被设计成可以打开任意的 CSV 文件并在`QTableView`中显示数据。通常在 CSV 的第一行用于保存列标题，因此我们的应用程序将假定这一点并使该行不可变。

# 创建表格模型

在开发数据驱动的模型-视图应用程序时，模型通常是最好的起点，因为这里是最复杂的代码。一旦我们把这个后端放在适当的位置，实现前端就相当简单了。

在这种情况下，我们需要设计一个可以读取和写入 CSV 数据的模型。从第四章的应用程序模板中复制应用程序模板，*使用* *QMainWindow*，并在顶部添加 Python `csv`库的导入。

现在，让我们通过继承`QAbstractTableModel`来开始构建我们的模型：

```py
class CsvTableModel(qtc.QAbstractTableModel):
  """The model for a CSV table."""

  def __init__(self, csv_file):
    super().__init__()
    self.filename = csv_file
    with open(self.filename) as fh:
      csvreader = csv.reader(fh)
      self._headers = next(csvreader)
      self._data = list(csvreader)
```

我们的模型将以 CSV 文件的名称作为参数，并立即打开文件并将其读入内存（对于大文件来说不是一个很好的策略，但这只是一个示例程序）。我们将假定第一行是标题行，并在将其余行放入模型的`_data`属性之前使用`next()`函数检索它。

# 实现读取功能

为了创建我们的模型的实例以在视图中显示数据，我们需要实现三种方法：

+   `rowCount()`，必须返回表中的总行数

+   `columnCount()`，必须返回表中的总列数

+   `data()`用于从模型请求数据

在这种情况下，`rowCount()`和`columnCount()`都很容易：

```py
  def rowCount(self, parent):
    return len(self._data)

  def columnCount(self, parent):
    return len(self._headers)
```

行数只是`_data`属性的长度，列数可以通过获取`_headers`属性的长度来获得。这两个函数都需要一个`parent`参数，但在这种情况下，它没有被使用，因为它是指父节点，只有在分层数据中才适用。

最后一个必需的方法是`data()`，需要更多解释；`data()`看起来像这样：

```py
  def data(self, index, role):
    if role == qtc.Qt.DisplayRole:
      return self._data[index.row()][index.column()]
```

`data()`的目的是根据`index`和`role`参数返回表格中单个单元格的数据。现在，`index`是`QModelIndex`类的一个实例，它描述了列表、表格或树结构中单个节点的位置。每个`QModelIndex`包含以下属性：

+   `row`号

+   `column`号

+   `parent`模型索引

在我们这种表格模型的情况下，我们对`row`和`column`属性感兴趣，它们指示我们想要的数据单元的表行和列。如果我们处理分层数据，我们还需要`parent`属性，它将是父节点的索引。如果这是一个列表，我们只关心`row`。

`role`是`QtCore.Qt.ItemDataRole`枚举中的一个常量。当视图从模型请求数据时，它传递一个`role`值，以便模型可以返回适合请求上下文的数据或元数据。例如，如果视图使用`EditRole`角色进行请求，模型应返回适合编辑的数据。如果视图使用`DecorationRole`角色进行请求，模型应返回适合单元格的图标。

如果没有特定角色的数据需要返回，`data()`应该返回空。

在这种情况下，我们只对`DisplayRole`角色感兴趣。要实际返回数据，我们需要获取索引的行和列，然后使用它来从我们的 CSV 数据中提取适当的行和列。

在这一点上，我们有一个最小功能的只读 CSV 模型，但我们可以添加更多内容。

# 添加标题和排序

能够返回数据只是模型功能的一部分。模型还需要能够提供其他信息，例如列标题的名称或排序数据的适当方法。

要在我们的模型中实现标题数据，我们需要创建一个`headerData()`方法：

```py
  def headerData(self, section, orientation, role):

    if (
      orientation == qtc.Qt.Horizontal and
      role == qtc.Qt.DisplayRole
    ):
      return self._headers[section]
    else:
      return super().headerData(section, orientation, role)
```

`headerData()`根据三个信息——**section**、**orientation**和**role**返回单个标题的数据。

标题可以是垂直的或水平的，由方向参数确定，该参数指定为`QtCore.Qt.Horizontal`或`QtCore.Qt.Vertical`常量。

该部分是一个整数，指示列号（对于水平标题）或行号（对于垂直标题）。

如`data()`方法中的角色参数一样，指示需要返回数据的上下文。

在我们的情况下，我们只对`DisplayRole`角色显示水平标题。与`data()`方法不同，父类方法具有一些默认逻辑和返回值，因此在任何其他情况下，我们希望返回`super().headerData()`的结果。

如果我们想要对数据进行排序，我们需要实现一个`sort()`方法，它看起来像这样：

```py
  def sort(self, column, order):
    self.layoutAboutToBeChanged.emit() # needs to be emitted before a sort
    self._data.sort(key=lambda x: x[column])
    if order == qtc.Qt.DescendingOrder:
      self._data.reverse()
    self.layoutChanged.emit() # needs to be emitted after a sort
```

`sort()`接受一个`column`号和`order`，它可以是`QtCore.Qt.DescendingOrder`或`QtCore.Qt.AscendingOrder`，该方法的目的是相应地对数据进行排序。在这种情况下，我们使用 Python 的`list.sort()`方法来就地对数据进行排序，使用`column`参数来确定每行的哪一列将被返回进行排序。如果请求降序排序，我们将使用`reverse()`来相应地改变排序顺序。

`sort()`还必须发出两个信号：

+   在内部进行任何排序之前，必须发出`layoutAboutToBeChanged`信号。

+   在排序完成后，必须发出`layoutChanged`信号。

这两个信号被视图用来适当地重绘自己，因此重要的是要记得发出它们。

# 实现写入功能

我们的模型目前是只读的，但因为我们正在实现 CSV 编辑器，我们需要实现写入数据。首先，我们需要重写一些方法以启用对现有数据行的编辑：`flags()`和`setData()`。

`flags()`接受一个`QModelIndex`值，并为给定索引处的项目返回一组`QtCore.Qt.ItemFlag`常量。这些标志用于指示项目是否可以被选择、拖放、检查，或者——对我们来说最有趣的是——编辑。

我们的方法如下：

```py
  def flags(self, index):
    return super().flags(index) | qtc.Qt.ItemIsEditable
```

在这里，我们将`ItemIsEditable`标志添加到父类`flags()`方法返回的标志列表中，指示该项目是可编辑的。如果我们想要实现逻辑，在某些条件下只使某些单元格可编辑，我们可以在这个方法中实现。

例如，如果我们有一个存储在`self.readonly_indexes`中的只读索引列表，我们可以编写以下方法：

```py
  def flags(self, index):
    if index not in self.readonly_indexes:
      return super().flags(index) | qtc.Qt.ItemIsEditable
    else:
      return super().flags(index)
```

然而，对于我们的应用程序，我们希望每个单元格都是可编辑的。

现在模型中的所有项目都标记为可编辑，我们需要告诉我们的模型如何实际编辑它们。这在`setData()`方法中定义：

```py
  def setData(self, index, value, role):
    if index.isValid() and role == qtc.Qt.EditRole:
      self._data[index.row()][index.column()] = value
      self.dataChanged.emit(index, index, [role])
      return True
    else:
      return False
```

`setData()`方法接受要设置的项目的索引、要设置的值和项目角色。此方法必须承担设置数据的任务，然后返回一个布尔值，指示数据是否成功更改。只有在索引有效且角色为`EditRole`时，我们才希望这样做。

如果数据发生变化，`setData()`也必须发出`dataChanged`信号。每当项目或一组项目与任何角色相关的更新时，都会发出此信号，因此携带了三个信息：被更改的最左上角的索引，被更改的最右下角的索引，以及每个索引的角色列表。在我们的情况下，我们只改变一个单元格，所以我们可以传递我们的索引作为单元格范围的两端，以及一个包含单个角色的列表。

`data()`方法还有一个小改变，虽然不是必需的，但会让用户更容易操作。回去编辑该方法如下：

```py
  def data(self, index, role):
    if role in (qtc.Qt.DisplayRole, qtc.Qt.EditRole):
      return self._data[index.row()][index.column()]
```

当选择表格单元格进行编辑时，将使用`EditRole`角色调用`data()`。在这个改变之前，当使用该角色调用`data()`时，`data()`会返回`None`，结果，单元格中的数据将在选择单元格时消失。通过返回`EditRole`的数据，用户将可以访问现有数据进行编辑。

我们现在已经实现了对现有单元格的编辑，但为了使我们的模型完全可编辑，我们需要实现插入和删除行。我们可以通过重写另外两个方法来实现这一点：`insertRows()`和`removeRows()`。

`insertRows()`方法如下：

```py
  def insertRows(self, position, rows, parent):
    self.beginInsertRows(
      parent or qtc.QModelIndex(),
      position,
      position + rows - 1
    )
    for i in range(rows):
      default_row = [''] * len(self._headers)
      self._data.insert(position, default_row)
    self.endInsertRows()
```

该方法接受插入开始的*位置*，要插入的*行数*以及父节点索引（与分层数据一起使用）。

在该方法内部，我们必须在调用`beginInsertRows()`和`endInsertRows()`之间放置我们的逻辑。`beginInsertRows()`方法准备了底层对象进行修改，并需要三个参数：

+   父节点的`ModelIndex`对象，对于表格数据来说是一个空的`QModelIndex`

+   行插入将开始的位置

+   行插入将结束的位置

我们可以根据传入方法的起始位置和行数来计算所有这些。一旦我们处理了这个问题，我们就可以生成一些行（以空字符串列表的形式，长度与我们的标题列表相同），并将它们插入到`self._data`中的适当索引位置。

在插入行后，我们调用`endInsertRows()`，它不带任何参数。

`removeRows()`方法非常相似：

```py
  def removeRows(self, position, rows, parent):
    self.beginRemoveRows(
      parent or qtc.QModelIndex(),
      position,
      position + rows - 1
    )
    for i in range(rows):
      del(self._data[position])
    self.endRemoveRows()
```

再次，我们需要在编辑数据之前调用`beginRemoveRows()`，在编辑后调用`endRemoveRows()`，就像我们对插入一样。如果我们想允许编辑列结构，我们可以重写`insertColumns()`和`removeColumns()`方法，它们的工作方式与行方法基本相同。现在，我们只会坚持行编辑。

到目前为止，我们的模型是完全可编辑的，但我们将添加一个方法，以便将数据刷新到磁盘，如下所示：

```py
  def save_data(self):
    with open(self.filename, 'w', encoding='utf-8') as fh:
      writer = csv.writer(fh)
      writer.writerow(self._headers)
      writer.writerows(self._data)
```

这个方法只是打开我们的文件，并使用 Python 的`csv`库写入标题和所有数据行。

# 在视图中使用模型

现在我们的模型已经准备好使用了，让我们充实应用程序的其余部分，以演示如何使用它。

首先，我们需要创建一个`QTableView`小部件，并将其添加到我们的`MainWindow`中：

```py
    # in MainWindow.__init__()
    self.tableview = qtw.QTableView()
    self.tableview.setSortingEnabled(True)
    self.setCentralWidget(self.tableview)
```

如您所见，我们不需要做太多工作来使`QTableView`小部件与模型一起工作。因为我们在模型中实现了`sort()`，我们将启用排序，但除此之外，它不需要太多配置。

当然，要查看任何数据，我们需要将模型分配给视图；为了创建一个模型，我们需要一个文件。让我们创建一个回调来获取一个：

```py
  def select_file(self):
    filename, _ = qtw.QFileDialog.getOpenFileName(
      self,
      'Select a CSV file to open…',
      qtc.QDir.homePath(),
      'CSV Files (*.csv) ;; All Files (*)'
    )
    if filename:
      self.model = CsvTableModel(filename)
      self.tableview.setModel(self.model)
```

我们的方法使用`QFileDialog`类来询问用户要打开的 CSV 文件。如果选择了一个文件，它将使用 CSV 文件来创建我们模型类的一个实例。然后使用`setModel()`访问方法将模型类分配给视图。

回到`MainWindow.__init__()`，让我们为应用程序创建一个主菜单，并添加一个“打开”操作：

```py
    menu = self.menuBar()
    file_menu = menu.addMenu('File')
    file_menu.addAction('Open', self.select_file)
```

如果您现在运行脚本，您应该能够通过转到“文件|打开”并选择有效的 CSV 文件来打开文件。您应该能够查看甚至编辑数据，并且如果单击标题单元格，数据应该按列排序。

接下来，让我们添加用户界面组件，以便保存我们的文件。首先，创建一个调用`MainWindow`方法`save_file()`的菜单项：

```py
    file_menu.addAction('Save', self.save_file)
```

现在，让我们创建我们的`save_file()`方法来实际保存文件：

```py
  def save_file(self):
    if self.model:
      self.model.save_data()
```

要保存文件，我们实际上只需要调用模型的`save_data()`方法。但是，我们不能直接将菜单项连接到该方法，因为在实际加载文件之前模型不存在。这个包装方法允许我们创建一个没有模型的菜单选项。

我们想要连接的最后一个功能是能够插入和删除行。在电子表格中，能够在所选行的上方或下方插入行通常是有用的。因此，让我们在`MainWindow`中创建回调来实现这一点：

```py
  def insert_above(self):
    selected = self.tableview.selectedIndexes()
    row = selected[0].row() if selected else 0
    self.model.insertRows(row, 1, None)

  def insert_below(self):
    selected = self.tableview.selectedIndexes()
    row = selected[-1].row() if selected else self.model.rowCount(None)
    self.model.insertRows(row + 1, 1, None)
```

在这两种方法中，我们通过调用表视图的`selectedIndexes()`方法来获取所选单元格的列表。这些列表从左上角的单元格到右下角的单元格排序。因此，对于插入上方，我们检索列表中第一个索引的行（如果列表为空，则为 0）。对于插入下方，我们检索列表中最后一个索引的行（如果列表为空，则为表中的最后一个索引）。最后，在这两种方法中，我们使用模型的`insertRows()`方法将一行插入到适当的位置。

删除行类似，如下所示：

```py
  def remove_rows(self):
    selected = self.tableview.selectedIndexes()
    if selected:
      self.model.removeRows(selected[0].row(), len(selected), None)
```

这次我们只在有活动选择时才采取行动，并使用模型的`removeRows()`方法来删除第一个选定的行。

为了使这些回调对用户可用，让我们在`MainWindow`中添加一个“编辑”菜单：

```py
    edit_menu = menu.addMenu('Edit')
    edit_menu.addAction('Insert Above', self.insert_above)
    edit_menu.addAction('Insert Below', self.insert_below)
    edit_menu.addAction('Remove Row(s)', self.remove_rows)
```

此时，请尝试加载 CSV 文件。您应该能够在表中插入和删除行，编辑字段并保存结果。恭喜，您已经创建了一个 CSV 编辑器！

# 总结

在本章中，您学习了模型视图编程。您学习了如何在常规小部件中使用模型，以及如何在 Qt 中使用特殊的模型视图类。您创建了一个自定义表模型，并通过利用模型视图类的功能快速构建了一个 CSV 编辑器。

我们将学习更高级的模型视图概念，包括委托和数据映射在第九章中，*使用 QtSQL 探索 SQL*。

在下一章中，您将学习如何为您的 PyQt 应用程序设置样式。我们将使用图像、动态图标、花哨的字体和颜色来装扮我们的单调表单，并学习控制 Qt GUI 整体外观和感觉的多种方法。

# 问题

尝试这些问题来测试您从本章中学到的知识：

1.  假设我们有一个设计良好的模型视图应用程序，以下代码是模型还是视图的一部分？

```py
  def save_as(self):
    filename, _ = qtw.QFileDialog(self)
    self.data.save_file(filename)
```

1.  您能否至少说出模型不应该做的两件事和视图不应该做的两件事？

1.  `QAbstractTableModel`和`QAbstractTreeModel`都在名称中有*Abstract*。在这种情况下，*Abstract*在这里是什么意思？在 C++中，它的意思是否与 Python 中的意思不同？

1.  哪种模型类型——列表、表格或树——最适合以下数据集：

+   用户最近的文件

+   Windows 注册表

+   Linux `syslog`记录

+   博客文章

+   个人称谓（例如，先生，夫人或博士）

+   分布式版本控制历史

1.  为什么以下代码失败了？

```py
  class DataModel(QAbstractTreeModel):
    def rowCount(self, node):
      if node > 2:
        return 1
      else:
        return len(self._data[node])
```

1.  当插入列时，您的表模型工作不正常。您的`insertColumns()`方法有什么问题？

```py
    def insertColumns(self, col, count, parent):
      for row in self._data:
        for i in range(count):
          row.insert(col, '')
```

1.  当悬停时，您希望您的视图显示项目数据作为工具提示。您将如何实现这一点？

# 进一步阅读

您可能希望查看以下资源：

+   有关模型视图编程的 Qt 文档在[`doc.qt.io/qt-5/model-view-programming.html`](https://doc.qt.io/qt-5/model-view-programming.html)

+   马丁·福勒在[`martinfowler.com/eaaDev/uiArchs.html`](https://martinfowler.com/eaaDev/uiArchs.html)上介绍了**模型-视图-控制器**（**MVC**）及相关模式的概述。


# 第六章：样式化 Qt 应用程序

很容易欣赏到 Qt 默认提供的清晰、本地外观。但对于不那么商业化的应用程序，普通的灰色小部件和标准字体并不总是设置正确的语气。即使是最沉闷的实用程序或数据输入应用程序偶尔也会受益于添加图标或谨慎调整字体以增强可用性。幸运的是，Qt 的灵活性使我们能够自己控制应用程序的外观和感觉。

在本章中，我们将涵盖以下主题：

+   使用字体、图像和图标

+   配置颜色、样式表和样式

+   创建动画

# 技术要求

在本章中，您将需要第一章中列出的所有要求，*PyQt 入门*，以及第四章中的 Qt 应用程序模板，*使用 QMainWindow 构建应用程序*。

此外，您可能需要 PNG、JPEG 或 GIF 图像文件来使用；您可以使用示例代码中包含的这些文件：[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter06`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter06)。

查看以下视频，了解代码的运行情况：[`bit.ly/2M5OJj6`](http://bit.ly/2M5OJj6)

# 使用字体、图像和图标

我们将通过自定义应用程序的字体、显示一些静态图像和包含动态图标来开始样式化我们的 Qt 应用程序。但在此之前，我们需要创建一个**图形用户界面**（**GUI**），以便我们可以使用。我们将创建一个游戏大厅对话框，该对话框将用于登录到一个名为**Fight Fighter**的虚构多人游戏。

要做到这一点，打开应用程序模板的新副本，并将以下 GUI 代码添加到`MainWindow.__init__()`中：

```py
        self.setWindowTitle('Fight Fighter Game Lobby')
        cx_form = qtw.QWidget()
        self.setCentralWidget(cx_form)
        cx_form.setLayout(qtw.QFormLayout())
        heading = qtw.QLabel("Fight Fighter!")
        cx_form.layout().addRow(heading)

        inputs = {
            'Server': qtw.QLineEdit(),
            'Name': qtw.QLineEdit(),
            'Password': qtw.QLineEdit(
                echoMode=qtw.QLineEdit.Password),
            'Team': qtw.QComboBox(),
            'Ready': qtw.QCheckBox('Check when ready')
        }
        teams = ('Crimson Sharks', 'Shadow Hawks',
                  'Night Terrors', 'Blue Crew')
        inputs['Team'].addItems(teams)
        for label, widget in inputs.items():
            cx_form.layout().addRow(label, widget)
        self.submit = qtw.QPushButton(
            'Connect',
            clicked=lambda: qtw.QMessageBox.information(
                None, 'Connecting', 'Prepare for Battle!'))
        self.reset = qtw.QPushButton('Cancel', clicked=self.close)
        cx_form.layout().addRow(self.submit, self.reset)
```

这是相当标准的 Qt GUI 代码，您现在应该对此很熟悉；我们通过将输入放入`dict`对象中并在循环中将它们添加到布局中，节省了一些代码行，但除此之外，它相对直接。根据您的操作系统和主题设置，对话框框可能看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/ce8de21f-49a5-46c4-aab8-3f45ba3b8c26.png)

正如您所看到的，这是一个不错的表单，但有点单调。因此，让我们探讨一下是否可以改进样式。

# 设置字体

我们要解决的第一件事是字体。每个`QWidget`类都有一个`font`属性，我们可以在构造函数中设置，也可以使用`setFont()`访问器来设置。`font`的值必须是一个`QtGui.QFont`对象。

以下是您可以创建和使用`QFont`对象的方法：

```py
        heading_font = qtg.QFont('Impact', 32, qtg.QFont.Bold)
        heading_font.setStretch(qtg.QFont.ExtraExpanded)
        heading.setFont(heading_font)
```

`QFont`对象包含描述文本将如何绘制到屏幕上的所有属性。构造函数可以接受以下任何参数：

+   一个表示字体系列的字符串

+   一个浮点数或整数，表示点大小

+   一个`QtGui.QFont.FontWeight`常量，指示权重

+   一个布尔值，指示字体是否应该是斜体

字体的其余方面，如`stretch`属性，可以使用关键字参数或访问器方法进行配置。我们还可以创建一个没有参数的`QFont`对象，并按照以下方式进行程序化配置：

```py
        label_font = qtg.QFont()
        label_font.setFamily('Impact')
        label_font.setPointSize(14)
        label_font.setWeight(qtg.QFont.DemiBold)
        label_font.setStyle(qtg.QFont.StyleItalic)

        for inp in inputs.values():
            cx_form.layout().labelForField(inp).setFont(label_font)
```

在小部件上设置字体不仅会影响该小部件，还会影响所有子小部件。因此，我们可以通过在`cx_form`上设置字体而不是在单个小部件上设置字体来为整个表单配置字体。

# 处理缺失的字体

现在，如果所有平台和**操作系统**（**OSes**）都提供了无限数量的同名字体，那么您需要了解的就是`QFont`。不幸的是，情况并非如此。大多数系统只提供了少数内置字体，并且这些字体中只有少数是跨平台的，甚至是平台的不同版本通用的。因此，Qt 有一个处理缺失字体的回退机制。

例如，假设我们要求 Qt 使用一个不存在的字体系列，如下所示：

```py
        button_font = qtg.QFont(
            'Totally Nonexistant Font Family XYZ', 15.233)
```

Qt 不会在此调用时抛出错误，甚至不会注册警告。相反，在未找到请求的字体系列后，它将回退到其`defaultFamily`属性，该属性利用了操作系统或桌面环境中设置的默认字体。

`QFont`对象实际上不会告诉我们发生了什么；如果查询它以获取信息，它只会告诉您已配置了什么：

```py
        print(f'Font is {button_font.family()}')
        # Prints: "Font is Totally Nonexistent Font Family XYZ"
```

要发现实际使用的字体设置，我们需要将我们的`QFont`对象传递给`QFontInfo`对象：

```py
        actual_font = qtg.QFontInfo(button_font).family()
        print(f'Actual font used is {actual_font}')
```

如果运行脚本，您会看到，很可能实际上使用的是默认的屏幕字体：

```py
$ python game_lobby.py
Font is Totally Nonexistent Font Family XYZ
Actual font used is Bitstream Vera Sans
```

虽然这确保了用户不会在窗口中没有任何文本，但如果我们能让 Qt 更好地了解应该使用什么样的字体，那就更好了。

我们可以通过设置字体的`styleHint`和`styleStrategy`属性来实现这一点，如下所示：

```py
        button_font.setStyleHint(qtg.QFont.Fantasy)
        button_font.setStyleStrategy(
            qtg.QFont.PreferAntialias |
            qtg.QFont.PreferQuality
        )
```

`styleHint`建议 Qt 回退到的一般类别，在本例中是`Fantasy`类别。这里的其他选项包括`SansSerif`、`Serif`、`TypeWriter`、`Decorative`、`Monospace`和`Cursive`。这些选项对应的内容取决于操作系统和桌面环境的配置。

`styleStrategy`属性告诉 Qt 与所选字体的能力相关的更多技术偏好，比如抗锯齿、OpenGL 兼容性，以及大小是精确匹配还是四舍五入到最接近的非缩放大小。策略选项的完整列表可以在[`doc.qt.io/qt-5/qfont.html#StyleStrategy-enum`](https://doc.qt.io/qt-5/qfont.html#StyleStrategy-enum)找到。

设置这些属性后，再次检查字体，看看是否有什么变化：

```py
        actual_font = qtg.QFontInfo(button_font)
        print(f'Actual font used is {actual_font.family()}'
              f' {actual_font.pointSize()}')
        self.submit.setFont(button_font)
        self.cancel.setFont(button_font)
```

根据系统的配置，您应该看到与之前不同的结果：

```py
$ python game_lobby.py
Actual font used is Impact 15
```

在这个系统上，`Fantasy`被解释为`Impact`，而`PreferQuality`策略标志强制最初奇怪的 15.233 点大小成为一个漂亮的`15`。

此时，根据系统上可用的字体，您的应用程序应该如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/0ac336f7-5ade-4387-a6c5-48a27c8fd1b1.png)

字体也可以与应用程序捆绑在一起；请参阅本章中的*使用 Qt 资源文件*部分。

# 添加图像

Qt 提供了许多与应用程序中使用图像相关的类，但是，对于在 GUI 中简单显示图片，最合适的是`QPixmap`。`QPixmap`是一个经过优化的显示图像类，可以加载许多常见的图像格式，包括 PNG、BMP、GIF 和 JPEG。

要创建一个，我们只需要将`QPixmap`传递给图像文件的路径：

```py
        logo = qtg.QPixmap('logo.png')
```

一旦加载，`QPixmap`对象可以显示在`QLabel`或`QButton`对象中，如下所示：

```py
        heading.setPixmap(logo)
```

请注意，标签只能显示字符串或像素图，但不能同时显示两者。

为了优化显示，`QPixmap`对象只提供了最小的编辑功能；但是，我们可以进行简单的转换，比如缩放：

```py
        if logo.width() > 400:
            logo = logo.scaledToWidth(
                400, qtc.Qt.SmoothTransformation)
```

在这个例子中，我们使用了像素图的`scaledToWidth()`方法，使用平滑的转换算法将标志的宽度限制为`400`像素。

`QPixmap`对象如此有限的原因是它们实际上存储在显示服务器的内存中。`QImage`类似，但是它将数据存储在应用程序内存中，因此可以进行更广泛的编辑。我们将在第十二章中更多地探讨这个类，创建*使用 QPainter 进行 2D 图形*。

`QPixmap`还提供了一个方便的功能，可以生成简单的彩色矩形，如下所示：

```py
        go_pixmap = qtg.QPixmap(qtc.QSize(32, 32))
        stop_pixmap = qtg.QPixmap(qtc.QSize(32, 32))
        go_pixmap.fill(qtg.QColor('green'))
        stop_pixmap.fill(qtg.QColor('red'))
```

通过在构造函数中指定大小并使用`fill()`方法，我们可以创建一个简单的彩色矩形像素图。这对于显示颜色样本或用作快速的图像替身非常有用。

# 使用图标

现在考虑工具栏或程序菜单中的图标。当菜单项被禁用时，您期望图标以某种方式变灰。同样，如果用户使用鼠标指针悬停在按钮或项目上，您可能期望它被突出显示。为了封装这种状态相关的图像显示，Qt 提供了`QIcon`类。`QIcon`对象包含一组与小部件状态相映射的像素图。

以下是如何创建一个`QIcon`对象：

```py
        connect_icon = qtg.QIcon()
        connect_icon.addPixmap(go_pixmap, qtg.QIcon.Active)
        connect_icon.addPixmap(stop_pixmap, qtg.QIcon.Disabled)
```

创建图标对象后，我们使用它的`addPixmap()`方法将一个`QPixmap`对象分配给小部件状态。这些状态包括`Normal`、`Active`、`Disabled`和`Selected`。

当禁用时，`connect_icon`图标现在将是一个红色的正方形，或者当启用时将是一个绿色的正方形。让我们将其添加到我们的提交按钮，并添加一些逻辑来切换按钮的状态：

```py
        self.submit.setIcon(connect_icon)
        self.submit.setDisabled(True)
        inputs['Server'].textChanged.connect(
            lambda x: self.submit.setDisabled(x == '')
        )
```

如果您在此时运行脚本，您会看到红色的正方形出现在提交按钮上，直到“服务器”字段包含数据为止，此时它会自动切换为绿色。请注意，我们不必告诉图标对象本身切换状态；一旦分配给小部件，它就会跟踪小部件状态的任何更改。

图标可以与`QPushButton`、`QToolButton`和`QAction`对象一起使用；`QComboBox`、`QListView`、`QTableView`和`QTreeView`项目；以及大多数其他您可能合理期望有图标的地方。

# 使用 Qt 资源文件

在程序中使用图像文件的一个重要问题是确保程序可以在运行时找到它们。传递给`QPixmap`构造函数或`QIcon`构造函数的路径被解释为绝对路径（即，如果它们以驱动器号或路径分隔符开头），或者相对于当前工作目录（您无法控制）。例如，尝试从代码目录之外的某个地方运行您的脚本：

```py
$ cd ..
$ python ch05/game_lobby.py
```

您会发现您的图像都丢失了！当`QPixmap`找不到文件时不会抱怨，它只是不显示任何东西。如果没有图像的绝对路径，您只能在脚本从相对路径相关的确切目录运行时找到它们。

不幸的是，指定绝对路径意味着您的程序只能从文件系统上的一个位置工作，这对于您计划将其分发到多个平台是一个重大问题。

PyQt 为我们提供了一个解决这个问题的解决方案，即**PyQt 资源文件**，我们可以使用**PyQt 资源编译器**工具创建。基本过程如下：

1.  编写一个 XML 格式的**Qt 资源集合**文件（.qrc），其中包含我们要包括的所有文件的路径

1.  运行`pyrcc5`工具将这些文件序列化并压缩到包含在 Python 模块中的数据中

1.  将生成的 Python 模块导入我们的应用程序脚本

1.  现在我们可以使用特殊的语法引用我们的资源

让我们逐步走过这个过程——假设我们有一些队徽，以 PNG 文件的形式，我们想要包含在我们的程序中。我们的第一步是创建`resources.qrc`文件，它看起来像下面的代码块：

```py
<RCC>
  <qresource prefix="teams">
    <file>crimson_sharks.png</file>
    <file>shadow_hawks.png</file>
    <file>night_terrors.png</file>
    <file alias="blue_crew.png">blue_crew2.png</file>
  </qresource>
</RCC>
```

我们已经将这个文件放在与脚本中列出的图像文件相同的目录中。请注意，我们添加了一个`prefix`值为`teams`。前缀允许您将资源组织成类别。另外，请注意，最后一个文件有一个指定的别名。在我们的程序中，我们可以使用这个别名而不是文件的实际名称来访问这个资源。

现在，在命令行中，我们将运行`pyrcc5`，如下所示：

```py
$ pyrcc5 -o resources.py resources.qrc
```

这里的语法是`pyrcc5 -o outputFile.py inputFile.qrc`。这个命令应该生成一个包含您的资源数据的 Python 文件。如果您花一点时间打开文件并检查它，您会发现它主要只是一个分配给`qt_resource_data`变量的大型`bytes`对象。

回到我们的主要脚本中，我们只需要像导入任何其他 Python 文件一样导入这个文件：

```py
import resources
```

文件不一定要叫做`resources.py`；实际上，任何名称都可以。你只需要导入它，文件中的代码将确保资源对 Qt 可用。

现在资源文件已导入，我们可以使用资源语法指定像素图路径：

```py
        inputs['Team'].setItemIcon(
            0, qtg.QIcon(':/teams/crimson_sharks.png'))
        inputs['Team'].setItemIcon(
            1, qtg.QIcon(':/teams/shadow_hawks.png'))
        inputs['Team'].setItemIcon(
            2, qtg.QIcon(':/teams/night_terrors.png'))
        inputs['Team'].setItemIcon(
            3, qtg.QIcon(':/teams/blue_crew.png'))
```

基本上，语法是`:/prefix/file_name_or_alias.extension`。

因为我们的数据存储在一个 Python 文件中，我们可以将它放在一个 Python 库中，它将使用 Python 的标准导入解析规则来定位文件。

# Qt 资源文件和字体

资源文件不仅限于图像；实际上，它们可以用于包含几乎任何类型的二进制文件，包括字体文件。例如，假设我们想要在程序中包含我们喜欢的字体，以确保它在所有平台上看起来正确。

与图像一样，我们首先在`.qrc`文件中包含字体文件：

```py
<RCC>
  <qresource prefix="teams">
    <file>crimson_sharks.png</file>
    <file>shadow_hawks.png</file>
    <file>night_terrors.png</file>
    <file>blue_crew.png</file>
  </qresource>
  <qresource prefix="fonts">
    <file>LiberationSans-Regular.ttf</file>
  </qresource>
</RCC>
```

在这里，我们添加了一个前缀`fonts`并包含了对`LiberationSans-Regular.ttf`文件的引用。运行`pyrcc5`对这个文件进行处理后，字体被捆绑到我们的`resources.py`文件中。

要在代码中使用这个字体，我们首先要将它添加到字体数据库中，如下所示：

```py
        libsans_id = qtg.QFontDatabase.addApplicationFont(
            ':/fonts/LiberationSans-Regular.ttf')
```

`QFontDatabase.addApplicationFont()`将传递的字体文件插入应用程序的字体数据库并返回一个 ID 号。然后我们可以使用该 ID 号来确定字体的系列字符串；这可以传递给`QFont`，如下所示：

```py
        family = qtg.QFontDatabase.applicationFontFamilies(libsans_id)[0]
        libsans = qtg.QFont(family)
        inputs['Team'].setFont(libsans)
```

在分发应用程序之前，请确保检查字体的许可证！请记住，并非所有字体都可以自由分发。

我们的表单现在看起来更像游戏了；运行应用程序，它应该看起来类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/93a4b1be-2c07-49b2-9a87-7d2b740a59fc.png)

# 配置颜色、样式表和样式

字体和图标改善了我们表单的外观，但现在是时候摆脱那些机构灰色调，用一些颜色来替换它们。在本节中，我们将看一下 Qt 为自定义应用程序颜色提供的三种不同方法：操纵**调色板**、使用**样式表**和覆盖**应用程序样式**。

# 使用调色板自定义颜色

由`QPalette`类表示的调色板是一组映射到颜色角色和颜色组的颜色和画笔的集合。

让我们解开这个声明：

+   在这里，**color**是一个文字颜色值，由`QColor`对象表示

+   **画笔**将特定颜色与样式（如图案、渐变或纹理）结合在一起，由`QBrush`类表示

+   **颜色角色**表示小部件使用颜色的方式，例如前景、背景或边框

+   **颜色组**指的是小部件的交互状态；它可以是`Normal`、`Active`、`Disabled`或`Inactive`

当小部件在屏幕上绘制时，Qt 的绘图系统会查阅调色板，以确定用于渲染小部件的每个部分的颜色和画笔。要自定义这一点，我们可以创建自己的调色板并将其分配给一个小部件。

首先，我们需要获取一个`QPalette`对象，如下所示：

```py
        app = qtw.QApplication.instance()
        palette = app.palette()
```

虽然我们可以直接创建一个`QPalette`对象，但 Qt 文档建议我们在运行的`QApplication`实例上调用`palette()`来检索当前配置样式的调色板的副本。

您可以通过调用`QApplication.instance()`来随时检索`QApplication`对象的副本。

现在我们有了调色板，让我们开始覆盖一些规则：

```py
        palette.setColor(
            qtg.QPalette.Button,
            qtg.QColor('#333')
        )
        palette.setColor(
            qtg.QPalette.ButtonText,
            qtg.QColor('#3F3')
        )
```

`QtGui.QPalette.Button`和`QtGui.QPalette.ButtonText`是颜色角色常量，正如你可能猜到的那样，它们分别代表所有 Qt 按钮类的背景和前景颜色。我们正在用新颜色覆盖它们。

要覆盖特定按钮状态的颜色，我们需要将颜色组常量作为第一个参数传递：

```py
        palette.setColor(
            qtg.QPalette.Disabled,
            qtg.QPalette.ButtonText,
            qtg.QColor('#F88')
        )
        palette.setColor(
            qtg.QPalette.Disabled,
            qtg.QPalette.Button,
            qtg.QColor('#888')
        )
```

在这种情况下，我们正在更改按钮处于`Disabled`状态时使用的颜色。

要应用这个新的调色板，我们必须将它分配给一个小部件，如下所示：

```py
        self.submit.setPalette(palette)
        self.cancel.setPalette(palette)
```

`setPalette()`将提供的调色板分配给小部件和所有子小部件。因此，我们可以创建一个单独的调色板，并将其分配给我们的`QMainWindow`类，以将其应用于所有对象，而不是分配给单个小部件。

# 使用 QBrush 对象

如果我们想要比纯色更花哨的东西，那么我们可以使用`QBrush`对象。画笔可以填充颜色、图案、渐变或纹理（即基于图像的图案）。

例如，让我们创建一个绘制白色点划填充的画笔：

```py
        dotted_brush = qtg.QBrush(
            qtg.QColor('white'), qtc.Qt.Dense2Pattern)
```

`Dense2Pattern`是 15 种可用图案之一。（你可以参考[`doc.qt.io/qt-5/qt.html#BrushStyle-enum`](https://doc.qt.io/qt-5/qt.html#BrushStyle-enum)获取完整列表。）其中大多数是不同程度的点划、交叉点划或交替线条图案。

图案有它们的用途，但基于渐变的画笔可能更适合现代风格。然而，创建一个可能会更复杂，如下面的代码所示：

```py
        gradient = qtg.QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0, qtg.QColor('navy'))
        gradient.setColorAt(0.5, qtg.QColor('darkred'))
        gradient.setColorAt(1, qtg.QColor('orange'))
        gradient_brush = qtg.QBrush(gradient)
```

要在画笔中使用渐变，我们首先必须创建一个渐变对象。在这里，我们创建了一个`QLinearGradient`对象，它实现了基本的线性渐变。参数是渐变的起始和结束坐标，我们指定为主窗口的左上角（0, 0）和右下角（宽度，高度）。

Qt 还提供了`QRadialGradient`和`QConicalGradient`类，用于提供额外的渐变选项。

创建对象后，我们使用`setColorAt()`指定颜色停止。第一个参数是 0 到 1 之间的浮点值，指定起始和结束之间的百分比，第二个参数是渐变应该在该点的`QColor`对象。

创建渐变后，我们将其传递给`QBrush`构造函数，以创建一个使用我们的渐变进行绘制的画笔。

我们现在可以使用`setBrush()`方法将我们的画笔应用于调色板，如下所示：

```py
        window_palette = app.palette()
        window_palette.setBrush(
            qtg.QPalette.Window,
            gradient_brush
        )
        window_palette.setBrush(
            qtg.QPalette.Active,
            qtg.QPalette.WindowText,
            dotted_brush
        )
        self.setPalette(window_palette)
```

就像`QPalette.setColor()`一样，我们可以分配我们的画笔，无论是否指定了特定的颜色组。在这种情况下，我们的渐变画笔将用于绘制主窗口，而我们的点画画笔只有在小部件处于活动状态时才会使用（即当前活动窗口）。

# 使用 Qt 样式表（QSS）自定义外观

对于已经使用过 Web 技术的开发人员来说，使用调色板、画笔和颜色对象来设计应用程序可能会显得啰嗦和不直观。幸运的是，Qt 为您提供了一种称为 QSS 的替代方案，它与 Web 开发中使用的**层叠样式表**（**CSS**）非常相似。这是一种简单的方法，可以对我们的小部件进行一些简单的更改。

您可以按照以下方式使用 QSS：

```py
        stylesheet = """
        QMainWindow {
            background-color: black;
        }
        QWidget {
            background-color: transparent;
            color: #3F3;
        }
        QLineEdit, QComboBox, QCheckBox {
            font-size: 16pt;
        }"""
        self.setStyleSheet(stylesheet)
```

在这里，样式表只是一个包含样式指令的字符串，我们可以将其分配给小部件的`styleSheet`属性。

这个语法对于任何使用过 CSS 的人来说应该很熟悉，如下所示：

```py
WidgetClass {
    property-name: value;
    property-name2: value2;
}
```

如果此时运行程序，你会发现（取决于你的系统主题），它可能看起来像以下的截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/5aa10114-bea6-4980-b9a0-6d011e653a36.png)

在这里，界面大部分变成了黑色，除了文本和图像。特别是我们的按钮和复选框与背景几乎无法区分。那么，为什么会发生这种情况呢？

当您向小部件类添加 QSS 样式时，样式更改会传递到所有其子类。由于我们对`QWidget`进行了样式设置，所有其他`QWidget`派生类（如`QCheckbox`和`QPushButton`）都继承了这种样式。

让我们通过覆盖这些子类的样式来修复这个问题，如下所示：

```py
        stylesheet += """
        QPushButton {
            background-color: #333;
        }
        QCheckBox::indicator:unchecked {
            border: 1px solid silver;
            background-color: darkred;
        }
        QCheckBox::indicator:checked {
            border: 1px solid silver;
            background-color: #3F3;
        }
        """
        self.setStyleSheet(stylesheet)
```

就像 CSS 一样，将样式应用于更具体的类会覆盖更一般的情况。例如，我们的`QPushButton`背景颜色会覆盖`QWidget`背景颜色。

请注意在`QCheckBox`中使用冒号 - QSS 中的双冒号允许我们引用小部件的子元素。在这种情况下，这是`QCheckBox`类的指示器部分（而不是其标签部分）。我们还可以使用单个冒号来引用小部件状态，就像在这种情况下，我们根据复选框是否选中或未选中来设置不同的样式。

如果您只想将更改限制为特定类，而不是其任何子类，只需在名称后添加一个句点（`。`），如下所示：

```py
        stylesheet += """
        .QWidget {
           background: url(tile.png);
        }
        """
```

前面的示例还演示了如何在 QSS 中使用图像。就像在 CSS 中一样，我们可以提供一个包装在`url()`函数中的文件路径。

如果您已经使用`pyrcc5`序列化了图像，QSS 还接受资源路径。

如果要将样式应用于特定小部件而不是整个小部件类，有两种方法可以实现。

第一种方法是依赖于`objectName`属性，如下所示：

```py
        self.submit.setObjectName('SubmitButton')
        stylesheet += """
        #SubmitButton:disabled {
            background-color: #888;
            color: darkred;
        }
        """
```

在我们的样式表中，对象名称前必须加上一个

`#`符号用于将其标识为对象名称，而不是类。

在单个小部件上设置样式的另一种方法是调用 t

使用小部件的`setStyleSheet()`方法和一些样式表指令，如下所示：

```py
        for inp in ('Server', 'Name', 'Password'):
            inp_widget = inputs[inp]
            inp_widget.setStyleSheet('background-color: black')
```

如果我们要直接将样式应用于我们正在调用的小部件，我们不需要指定类名或对象名；我们可以简单地传递属性和值。

经过所有这些更改，我们的应用程序现在看起来更像是一个游戏 GUI：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/ec30b7cf-f46b-4f79-955c-9af210c2281f.png)

# QSS 的缺点

正如您所看到的，QSS 是一种非常强大的样式方法，对于任何曾经从事 Web 开发的开发人员来说都是可访问的；但是，它确实有一些缺点。

QSS 是对调色板和样式对象的抽象，必须转换为实际系统。这使它们在大型应用程序中变得更慢，这也意味着没有默认样式表可以检索和编辑 - 每次都是从头开始。

正如我们已经看到的，当应用于高级小部件时，QSS 可能会产生不可预测的结果，因为它通过类层次结构继承。

最后，请记住，QSS 是 CSS 2.0 的一个较小子集，带有一些添加或更改 - 它不是 CSS。因此，过渡、动画、flexbox 容器、相对单位和其他现代 CSS 好东西完全不存在。因此，尽管 Web 开发人员可能会发现其基本语法很熟悉，但有限的选项集可能会令人沮丧，其不同的行为也会令人困惑。

# 使用 QStyle 自定义外观

调色板和样式表可以帮助我们大大定制 Qt 应用程序的外观，对于大多数情况来说，这就是您所需要的。要真正深入了解 Qt 应用程序外观的核心，我们需要了解样式系统。

每个运行的 Qt 应用程序实例都有一个样式，负责告诉图形系统如何绘制每个小部件或 GUI 组件。样式是动态和可插拔的，因此不同的 OS 平台具有不同的样式，用户可以安装自己的 Qt 样式以在 Qt 应用程序中使用。这就是 Qt 应用程序能够在不同的操作系统上具有本机外观的原因。

在第一章中，*使用 PyQt 入门*，我们学到`QApplication`在创建时应传递`sys.argv`的副本，以便它可以处理一些特定于 Qt 的参数。其中一个参数是`-style`，它允许用户为其 Qt 应用程序设置自定义样式。

例如，让我们使用`Windows`样式运行第三章中的日历应用程序，*使用信号和槽处理事件*：

```py
$ python3 calendar_app.py -style Windows
```

现在尝试使用`Fusion`样式，如下所示：

```py
$ python3 calendar_app.py -style Fusion
```

请注意外观上的差异，特别是输入控件。

样式中的大小写很重要；**windows**不是有效的样式，而**Windows**是！

常见 OS 平台上可用的样式如下表所示：

| OS | 样式 |
| --- | --- |
| Windows 10 | `windowsvista`，`Windows`和`Fusion` |
| macOS | `macintosh`，`Windows`和`Fusion` |
| Ubuntu 18.04 | `Windows`和`Fusion` |

在许多 Linux 发行版中，可以从软件包存储库中获取其他 Qt 样式。可以通过调用`QtWidgets.QStyleFactory.keys()`来获取当前安装的样式列表。

样式也可以在应用程序内部设置。为了检索样式类，我们需要使用`QStyleFactory`类，如下所示：

```py
if __name__ == '__main__':
    app = qtw.QApplication(sys.argv)
    windows_style = qtw.QStyleFactory.create('Windows')
    app.setStyle(windows_style)
```

`QStyleFactory.create()`将尝试查找具有给定名称的已安装样式，并返回一个`QCommonStyle`对象；如果未找到请求的样式，则它将返回`None`。然后可以使用样式对象来设置我们的`QApplication`对象的`style`属性。（`None`的值将导致其使用默认值。）

如果您计划在应用程序中设置样式，最好在绘制任何小部件之前尽早进行，以避免视觉故障。

# 自定义 Qt 样式

构建 Qt 样式是一个复杂的过程，需要深入了解 Qt 的小部件和绘图系统，很少有开发人员需要创建一个。但是，我们可能希望覆盖运行样式的某些方面，以完成一些无法通过调色板或样式表的操作来实现的事情。我们可以通过对`QtWidgets.QProxyStyle`进行子类化来实现这一点。

代理样式是我们可以使用来覆盖实际运行样式的方法的覆盖层。这样，用户选择的实际样式是什么并不重要，我们的代理样式的方法（在实现时）将被使用。

例如，让我们创建一个代理样式，强制所有屏幕文本都是大写的，如下所示：

```py
class StyleOverrides(qtw.QProxyStyle):

    def drawItemText(
        self, painter, rect,
        flags, palette, enabled,
        text, textRole
    ):
        """Force uppercase in all text"""
        text = text.upper()
        super().drawItemText(
            painter, rect, flags,
            palette, enabled, text,
            textRole
        )
```

`drawItemText()`是在必须将文本绘制到屏幕时在样式上调用的方法。它接收许多参数，但我们最关心的是要绘制的`text`参数。我们只是要拦截此文本，并在将所有参数传回`super().drawTextItem()`之前将其转换为大写。

然后可以将此代理样式应用于我们的`QApplication`对象，方式与任何其他样式相同：

```py
if __name__ == '__main__':
    app = qtw.QApplication(sys.argv)
    proxy_style= StyleOverrides()
    app.setStyle(proxy_style)
```

如果此时运行程序，您会看到所有文本现在都是大写。任务完成！

# 绘制小部件

现在让我们尝试一些更有野心的事情。让我们将所有的`QLineEdit`输入框更改为绿色的圆角矩形轮廓。那么，我们如何在代理样式中做到这一点呢？

第一步是弄清楚我们要修改的小部件的元素是什么。这些可以在`QStyle`类的枚举常量中找到，它们分为三个主要类别：

+   `PrimitiveElement`，其中包括基本的非交互式 GUI 元素，如框架或背景

+   `ControlElement`，其中包括按钮或选项卡等交互元素

+   `ComplexControl`，其中包括复杂的交互元素，如组合框和滑块

这些类别中的每个项目都由`QStyle`的不同方法绘制；在这种情况下，我们想要修改的是`PE_FrameLineEdit`元素，这是一个原始元素（由`PE_`前缀表示）。这种类型的元素由`QStyle.drawPrimitive()`绘制，因此我们需要在代理样式中覆盖该方法。

将此方法添加到`StyleOverrides`中，如下所示：

```py
    def drawPrimitive(
        self, element, option, painter, widget
    ):
        """Outline QLineEdits in Green"""
```

要控制元素的绘制，我们需要向其`painter`对象发出命令，如下所示：

```py
        self.green_pen = qtg.QPen(qtg.QColor('green'))
        self.green_pen.setWidth(4)
        if element == qtw.QStyle.PE_FrameLineEdit:
            painter.setPen(self.green_pen)
            painter.drawRoundedRect(widget.rect(), 10, 10)
        else:
            super().drawPrimitive(element, option, painter, widget)
```

绘图对象和绘图将在第十二章中完全介绍，*使用 QPainter 创建 2D 图形*，但是，现在要理解的是，如果`element`参数匹配`QStyle.PE_FrameLineEdit`，则前面的代码将绘制一个绿色的圆角矩形。否则，它将将参数传递给超类的`drawPrimitive()`方法。

请注意，在绘制矩形后，我们不调用超类方法。如果我们这样做了，那么超类将在我们的绿色矩形上方绘制其样式定义的小部件元素。

正如你在这个例子中看到的，使用`QProxyStyle`比使用调色板或样式表要复杂得多，但它确实让我们几乎无限地控制我们的小部件的外观。

无论你使用 QSS 还是样式和调色板来重新设计应用程序都没有关系；然而，强烈建议你坚持使用其中一种。否则，你的样式修改可能会相互冲突，并在不同平台和桌面设置上产生不可预测的结果。

# 创建动画

没有什么比动画的巧妙使用更能为 GUI 增添精致的边缘。在颜色、大小或位置的变化之间平滑地淡入淡出的动态 GUI 元素可以为任何界面增添现代感。

Qt 的动画框架允许我们使用`QPropertyAnimation`类在我们的小部件上创建简单的动画。在本节中，我们将探讨如何使用这个类来为我们的游戏大厅增添一些动画效果。

因为 Qt 样式表会覆盖另一个基于小部件和调色板的样式，所以你需要注释掉所有这些动画的样式表代码才能正常工作。

# 基本属性动画

`QPropertyAnimation`对象用于动画小部件的单个 Qt 属性。该类会自动在两个数值属性值之间创建插值步骤序列，并在一段时间内应用这些变化。

例如，让我们动画我们的标志，让它从左向右滚动。你可以通过添加一个属性动画对象来开始，如下所示：

```py
        self.heading_animation = qtc.QPropertyAnimation(
            heading, b'maximumSize')
```

`QPropertyAnimation`需要两个参数：一个要被动画化的小部件（或其他类型的`QObject`类），以及一个指示要被动画化的属性的`bytes`对象（请注意，这是一个`bytes`对象，而不是一个字符串）。

接下来，我们需要配置我们的动画对象如下：

```py
        self.heading_animation.setStartValue(qtc.QSize(10, logo.height()))
        self.heading_animation.setEndValue(qtc.QSize(400, logo.height()))
        self.heading_animation.setDuration(2000)
```

至少，我们需要为属性设置一个`startValue`值和一个`endValue`值。当然，这些值必须是属性所需的数据类型。我们还可以设置毫秒为单位的`duration`（默认值为 250）。

配置好后，我们只需要告诉动画开始，如下所示：

```py
        self.heading_animation.start()
```

有一些要求限制了`QPropertyAnimation`对象的功能：

+   要动画的对象必须是`QObject`的子类。这包括所有小部件，但不包括一些 Qt 类，如`QPalette`。

+   要动画的属性必须是 Qt 属性（不仅仅是 Python 成员变量）。

+   属性必须具有读写访问器方法，只需要一个值。例如，`QWidget.size`可以被动画化，但`QWidget.width`不能，因为没有`setWidth()`方法。

+   属性值必顺为以下类型之一：`int`、`float`、`QLine`、`QLineF`、`QPoint`、`QPointF`、`QSize`、`QSizeF`、`QRect`、`QRectF`或`QColor`。

不幸的是，对于大多数小部件，这些限制排除了我们可能想要动画的许多方面，特别是颜色。幸运的是，我们可以解决这个问题。

# 动画颜色

正如你在本章前面学到的，小部件颜色不是小部件的属性，而是调色板的属性。调色板不能被动画化，因为`QPalette`不是`QObject`的子类，而且`setColor()`需要的不仅仅是一个单一的值。

颜色是我们想要动画的东西，为了实现这一点，我们需要对小部件进行子类化，并将其颜色设置为 Qt 属性。

让我们用一个按钮来做到这一点；在脚本的顶部开始一个新的类，如下所示：

```py
class ColorButton(qtw.QPushButton):

    def _color(self):
        return self.palette().color(qtg.QPalette.ButtonText)

    def _setColor(self, qcolor):
        palette = self.palette()
        palette.setColor(qtg.QPalette.ButtonText, qcolor)
        self.setPalette(palette)
```

在这里，我们有一个`QPushButton`子类，其中包含用于调色板`ButtonText`颜色的访问器方法。但是，请注意这些是 Python 方法；为了对此属性进行动画处理，我们需要`color`成为一个实际的 Qt 属性。为了纠正这一点，我们将使用`QtCore.pyqtProperty()`函数来包装我们的访问器方法，并在底层 Qt 对象上创建一个属性。

您可以按照以下方式操作：

```py
    color = qtc.pyqtProperty(qtg.QColor, _color, _setColor)
```

我们使用的属性名称将是 Qt 属性的名称。传递的第一个参数是属性所需的数据类型，接下来的两个参数是 getter 和 setter 方法。

`pyqtProperty()`也可以用作装饰器，如下所示：

```py
    @qtc.pyqtProperty(qtg.QColor)
    def backgroundColor(self):
        return self.palette().color(qtg.QPalette.Button)

    @backgroundColor.setter
    def backgroundColor(self, qcolor):
        palette = self.palette()
        palette.setColor(qtg.QPalette.Button, qcolor)
        self.setPalette(palette)
```

请注意，在这种方法中，两个方法必须使用我们打算创建的属性名称相同的名称。

现在我们的属性已经就位，我们需要用`ColorButton`对象替换我们的常规`QPushButton`对象：

```py
        # Replace these definitions
        # at the top of the MainWindow constructor
        self.submit = ColorButton(
            'Connect',
            clicked=lambda: qtw.QMessageBox.information(
                None,
                'Connecting',
                'Prepare for Battle!'))
        self.cancel = ColorButton(
            'Cancel',
            clicked=self.close)
```

经过这些更改，我们可以如下地对颜色值进行动画处理：

```py
        self.text_color_animation = qtc.QPropertyAnimation(
            self.submit, b'color')
        self.text_color_animation.setStartValue(qtg.QColor('#FFF'))
        self.text_color_animation.setEndValue(qtg.QColor('#888'))
        self.text_color_animation.setLoopCount(-1)
        self.text_color_animation.setEasingCurve(
            qtc.QEasingCurve.InOutQuad)
        self.text_color_animation.setDuration(2000)
        self.text_color_animation.start()
```

这个方法非常有效。我们还在这里添加了一些额外的配置设置：

+   `setLoopCount()`将设置动画重新启动的次数。值为`-1`将使其永远循环。

+   `setEasingCurve()`改变了值插值的曲线。我们选择了`InOutQuad`，它减缓了动画开始和结束的速率。

现在，当您运行脚本时，请注意颜色从白色渐变到灰色，然后立即循环回白色。如果我们希望动画从一个值移动到另一个值，然后再平稳地返回，我们可以使用`setKeyValue()`方法在动画的中间放置一个值：

```py
        self.bg_color_animation = qtc.QPropertyAnimation(
            self.submit, b'backgroundColor')
        self.bg_color_animation.setStartValue(qtg.QColor('#000'))
        self.bg_color_animation.setKeyValueAt(0.5, qtg.QColor('darkred'))
        self.bg_color_animation.setEndValue(qtg.QColor('#000'))
        self.bg_color_animation.setLoopCount(-1)
        self.bg_color_animation.setDuration(1500)
```

在这种情况下，我们的起始值和结束值是相同的，并且我们在动画的中间添加了一个值为 0.5（动画进行到一半时）设置为第二个颜色。这个动画将从黑色渐变到深红色，然后再返回。您可以添加任意多个关键值并创建相当复杂的动画。

# 使用动画组

随着我们向 GUI 添加越来越多的动画，我们可能会发现有必要将它们组合在一起，以便我们可以将动画作为一个组来控制。这可以使用动画组类`QParallelAnimationGroup`和`QSequentialAnimationGroup`来实现。

这两个类都允许我们向组中添加多个动画，并作为一个组开始、停止、暂停和恢复动画。

例如，让我们将按钮动画分组如下：

```py
        self.button_animations = qtc.QParallelAnimationGroup()
        self.button_animations.addAnimation(self.text_color_animation)
        self.button_animations.addAnimation(self.bg_color_animation)
```

`QParallelAnimationGroup`在调用其`start()`方法时会同时播放所有动画。相反，`QSequentialAnimationGroup`将按添加的顺序依次播放其动画，如下面的代码块所示：

```py
        self.all_animations = qtc.QSequentialAnimationGroup()
        self.all_animations.addAnimation(self.heading_animation)
        self.all_animations.addAnimation(self.button_animations)
        self.all_animations.start()
```

通过像我们在这里所做的那样将动画组添加到其他动画组中，我们可以将复杂的动画安排成一个对象，可以一起启动、停止、暂停和恢复。

注释掉所有其他动画的`start()`调用并启动脚本。请注意，按钮动画仅在标题动画完成后开始。

我们将在*第十二章* *使用 QPainter 进行 2D 图形*中探索更多`QPropertyAnimation`的用法。

# 总结

在本章中，我们学习了如何自定义 PyQt 应用程序的外观和感觉。我们还学习了如何操纵屏幕字体并添加图像。此外，我们还学习了如何以对路径更改具有弹性的方式打包图像和字体资源。我们还探讨了如何使用调色板和样式表改变应用程序的颜色和外观，以及如何覆盖样式方法来实现几乎无限的样式更改。最后，我们探索了使用 Qt 的动画框架进行小部件动画，并学习了如何向我们的类添加自定义 Qt 属性，以便我们可以对其进行动画处理。

在下一章中，我们将使用`QtMultimedia`库探索多媒体应用程序的世界。您将学习如何使用摄像头拍照和录制视频，如何显示视频内容，以及如何录制和播放音频。

# 问题

尝试这些问题来测试您从本章学到的知识：

1.  您正在准备分发您的文本编辑器应用程序，并希望确保用户无论使用什么平台，都会默认获得等宽字体。您可以使用哪两种方法来实现这一点？

1.  尽可能地，尝试使用`QFont`模仿以下文本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/07c03999-3b51-4ee3-8a01-aaaf1e4cf5c3.png)

1.  您能解释一下`QImage`，`QPixmap`和`QIcon`之间的区别吗？

1.  您已为应用程序定义了以下`.qrc`文件，运行了`pyrcc5`，并在脚本中导入了资源库。您会如何将此图像加载到`QPixmap`中？

```py
   <RCC>
      <qresource prefix="foodItems">
        <file alias="pancakes.png">pc_img.45234.png</file>
      </qresource>
   </RCC>
```

1.  使用`QPalette`，如何使用`tile.png`图像在`QWidget`对象的背景上铺砌？

1.  您试图使用 QSS 使删除按钮变成粉色，但没有成功。您的代码有什么问题？

```py
   deleteButton = qtw.QPushButton('Delete')
   form.layout().addWidget(deleteButton)
   form.setStyleSheet(
      form.styleSheet() + 'deleteButton{ background-color: #8F8; }'
   )
```

1.  哪个样式表字符串将把您的`QLineEdit`小部件的背景颜色变成黑色？

```py
   stylesheet1 = "QWidget {background-color: black;}"
   stylesheet2 = ".QWidget {background-color: black;}"
```

1.  构建一个简单的应用程序，其中包含一个下拉框，允许您将 Qt 样式更改为系统上安装的任何样式。包括一些其他小部件，以便您可以看到它们在不同样式下的外观。

1.  您对学习如何为 PyQt 应用程序设置样式感到非常高兴，并希望创建一个`QProxyStyle`类，该类将强制 GUI 中的所有像素图像为`smile.gif`。您会如何做？提示：您需要研究`QStyle`的一些其他绘图方法，而不是本章讨论的方法。

1.  以下动画不起作用；找出它为什么不起作用：

```py
    class MyWidget(qtw.QWidget):
        def __init__(self):
            super().__init__()
            animation = qtc.QPropertyAnimation(
                self, b'windowOpacity')
            animation.setStartValue(0)
            animation.setEndValue(1)
            animation.setDuration(10000)
            animation.start()
```

# 进一步阅读

有关更多信息，请参考以下内容：

+   有关字体如何解析的更详细描述可以在[`doc.qt.io/qt-5/qfont.html#details`](https://doc.qt.io/qt-5/qfont.html#details)的`QFont`文档中找到

+   这个 C++中的 Qt 样式示例([`doc.qt.io/qt-5/qtwidgets-widgets-styles-example.html`](https://doc.qt.io/qt-5/qtwidgets-widgets-styles-example.html))演示了如何创建一个全面的 Qt 代理样式

+   Qt 的动画框架概述在[`doc.qt.io/qt-5/animation-overview.html`](https://doc.qt.io/qt-5/animation-overview.html)提供了如何使用属性动画以及它们的限制的额外细节
