# 精通 Python GUI 编程（四）

> 原文：[`zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408`](https://zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：揭开高级 Qt 实现

在这最后一节中，您将深入了解 PyQt 提供的更高级功能。您将处理多线程、2D 和 3D 图形、丰富文本文档、打印、数据绘图和网页浏览。您将学习如何在树莓派上使用 PyQt，以及如何在桌面系统上构建和部署代码。通过本节结束时，您将拥有构建美丽 GUI 所需的所有工具和技术。

本节包括以下章节：

+   第十章，*使用 QTimer 和 QThread 进行多线程*

+   第十一章，*使用 QTextDocument 创建丰富的文本*

+   第十二章，*使用 QPainter 创建 2D 图形*

+   第十三章，*使用 QtOpenGL 创建 3D 图形*

+   第十四章，*使用 QtCharts 嵌入数据图*

+   第十五章，*PyQt 树莓派*

+   第十六章，*使用 QtWebEngine 进行网页浏览*

+   第十七章，*为软件分发做准备*


# 第十章：使用 QTimer 和 QThread 进行多线程处理

尽管计算机硬件的功能不断增强，程序仍然经常需要执行需要几秒甚至几分钟才能完成的任务。虽然这种延迟可能是由于程序员无法控制的因素造成的，但它仍然会影响应用程序的性能，使其在后台任务运行时变得无响应。在本章中，我们将学习一些工具，可以帮助我们通过推迟重型操作或将其移出线程来保持应用程序的响应性。我们还将学习如何使用多线程应用程序设计来加快多核系统上的这些操作。

本章分为以下主题：

+   使用`QTimer`进行延迟操作

+   使用`QThread`进行多线程处理

+   使用`QThreadPool`和`QRunner`实现高并发

# 技术要求

本章只需要您在整本书中一直在使用的基本 Python 和 PyQt5 设置。您还可以参考[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter10`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter10)上的示例代码。

查看以下视频以查看代码的运行情况：[`bit.ly/2M6iSPl`](http://bit.ly/2M6iSPl)

# 使用 QTimer 进行延迟操作

在程序中能够延迟操作在各种情况下都是有用的。例如，假设我们想要一个无模式的**弹出**对话框，在定义的秒数后自动关闭，而不是等待用户点击按钮。

我们将从子类化`QDialog`开始：

```py
class AutoCloseDialog(qtw.QDialog):

    def __init__(self, parent, title, message, timeout):
        super().__init__(parent)
        self.setModal(False)
        self.setWindowTitle(title)
        self.setLayout(qtw.QVBoxLayout())
        self.layout().addWidget(qtw.QLabel(message))
        self.timeout = timeout
```

保存了一个`timeout`值后，我们现在想要重写对话框的`show()`方法，以便在指定的秒数后关闭它。

一个天真的方法可能是：

```py
    def show(self):
        super().show()
        from time import sleep
        sleep(self.timeout)
        self.hide()
```

Python 的`time.sleep()`函数将暂停程序执行我们传入的秒数。乍一看，它似乎应该做我们想要的事情，即显示窗口，暂停`timeout`秒，然后隐藏窗口。

因此，让我们在我们的`MainWindow.__init__()`方法中添加一些代码来测试它：

```py
        self.dialog = AutoCloseDialog(
            self,
            "Self-destructing message",
            "This message will self-destruct in 10 seconds",
            10
        )
        self.dialog.show()
```

如果运行程序，您会发现事情并不如预期。由于这个对话框是无模式的，它应该出现在我们的主窗口旁边，而不会阻塞任何东西。此外，由于我们在调用`sleep()`之前调用了`show()`，它应该在暂停之前显示自己。相反，您很可能得到一个空白和冻结的对话框窗口，它在其存在的整个期间都会暂停整个程序。那么，这里发生了什么？

从第一章 *PyQt 入门*中记得，Qt 程序有一个**事件循环**，当我们调用`QApplication.exec()`时启动。当我们调用`show()`这样的方法时，它涉及许多幕后操作，如绘制小部件和与窗口管理器通信，这些任务不会立即执行。相反，它们被放置在任务队列中。事件循环逐个处理任务队列中的工作，直到它为空。这个过程是**异步**的，因此调用`QWidget.show()`方法不会等待窗口显示后再返回；它只是将显示小部件的任务放在事件队列中并返回。

我们对`time.sleep()`方法的调用在程序中创建了一个立即阻塞的延迟，直到函数退出为止，这将停止所有其他处理。这包括停止 Qt 事件循环，这意味着所有仍在队列中的绘图操作都不会发生。事实上，直到`sleep()`完成，没有事件会被处理。这就是为什么小部件没有完全绘制，程序在`sleep()`执行时为什么没有继续的原因。

为了正确工作，我们需要将`hide()`调用放在事件循环中，这样我们对`AutoCloseDialog.show()`的调用可以立即返回，并让事件循环处理隐藏对话框，就像它处理显示对话框一样。但我们不想立即这样做，我们希望在事件队列上延迟执行一段时间。这就是`QtCore.QTimer`类可以为我们做的事情。

# 单发定时器

`QTimer`是一个简单的`QObject`子类，可以在一定时间后发出`timeout`信号。

使用`QTimer`延迟单个操作的最简单方法是使用`QTimer.singleShot()`静态方法，如下所示：

```py
    def show(self):
        super().show()
        qtc.QTimer.singleShot(self.timeout * 1000, self.hide)
```

`singleShot()`接受两个参数：毫秒为单位的间隔和回调函数。在这种情况下，我们在一定数量的`self.timeout`秒后调用`self.hide()`方法（我们将乘以 1,000 将其转换为毫秒）。

再次运行此脚本，您现在应该看到您的对话框表现如预期。

# 重复定时器

在应用程序中，有时我们需要在指定的间隔重复执行某个操作，比如自动保存文档，轮询网络套接字，或者不断地催促用户在应用商店给应用程序评 5 星（好吧，也许不是这个）。

`QTimer`也可以处理这个问题，您可以从以下代码块中看到：

```py
        interval_seconds = 10
        self.timer = qtc.QTimer()
        self.timer.setInterval(interval_seconds * 1000)
        self.interval_dialog = AutoCloseDialog(
            self, "It's time again",
            f"It has been {interval_seconds} seconds "
            "since this dialog was last shown.", 2000)
        self.timer.timeout.connect(self.interval_dialog.show)
        self.timer.start()
```

在这个例子中，我们明确创建了一个`QTimer`对象，而不是使用静态的`singleShot()`方法。然后，我们使用`setInterval()`方法配置了以毫秒为单位的超时间隔。当间隔过去时，定时器对象将发出`timeout`信号。默认情况下，`QTimer`对象将在达到指定间隔的末尾时重复发出`timeout`信号。您也可以使用`setSingleShot()`方法将其转换为单发，尽管一般来说，使用我们在*单发定时器*部分演示的静态方法更容易。

创建`QTimer`对象并配置间隔后，我们只需将其`timeout`信号连接到另一个`AutoCloseDialog`对象的`show()`方法，然后通过调用`start()`方法启动定时器。

我们也可以停止定时器，然后重新启动：

```py
        toolbar = self.addToolBar('Tools')
        toolbar.addAction('Stop Bugging Me', self.timer.stop)
        toolbar.addAction('Start Bugging Me', self.timer.start)
```

`QTimer.stop()`方法停止定时器，`start()`方法将重新开始。值得注意的是这里没有`pause()`方法；`stop()`方法将清除任何当前的进度，`start()`方法将从配置的间隔重新开始。

# 从定时器获取信息

`QTimer`有一些方法，我们可以用来提取有关定时器状态的信息。例如，让我们通过以下代码让用户了解事情的进展：

```py
        self.timer2 = qtc.QTimer()
        self.timer2.setInterval(1000)
        self.timer2.timeout.connect(self.update_status)
        self.timer2.start()
```

我们设置了另一个定时器，它将每秒调用`self.update_status()`。`update_status()`然后查询信息的第一次如下：

```py
    def update_status(self):
        if self.timer.isActive():
            time_left = (self.timer.remainingTime() // 1000) + 1
            self.statusBar().showMessage(
                f"Next dialog will be shown in {time_left} seconds.")
        else:
            self.statusBar().showMessage('Dialogs are off.')
```

`QTimer.isActive()`方法告诉我们定时器当前是否正在运行，而`remainingTime()`告诉我们距离下一个`timeout`信号还有多少毫秒。

现在运行这个程序，您应该看到关于下一个对话框的状态更新。

# 定时器的限制

虽然定时器允许我们将操作推迟到事件队列，并可以帮助防止程序中的尴尬暂停，但重要的是要理解连接到`timeout`信号的函数仍然在主执行线程中执行，并且因此会阻塞主执行线程。

例如，假设我们有一个长时间阻塞的方法，如下所示：

```py
    def long_blocking_callback(self):
        from time import sleep
        self.statusBar().showMessage('Beginning a long blocking function.')
        sleep(30)
        self.statusBar().showMessage('Ending a long blocking function.')
```

您可能认为从单发定时器调用此方法将阻止其锁定应用程序。让我们通过将此代码添加到`MainView.__init__()`来测试这个理论：

```py
        qtc.QTimer.singleShot(1, self.long_blocking_callback)
```

使用`1`毫秒延迟调用`singleShot()`是安排一个几乎立即发生的事件的简单方法。那么，它有效吗？

好吧，实际上并不是这样；如果你运行程序，你会发现它会锁定 30 秒。尽管我们推迟了操作，但它仍然是一个长时间的阻塞操作，会在运行时冻结程序。也许我们可以调整延迟值，以确保它被推迟到更合适的时刻（比如在应用程序绘制完毕后或者在启动画面显示后），但迟早，应用程序将不得不冻结并在任务运行时变得无响应。

然而，对于这样的问题有一个解决方案；在下一节*使用 QThread 进行多线程处理*中，我们将看看如何将这样的繁重阻塞任务推送到另一个线程，以便我们的程序可以继续运行而不会冻结。

# 使用 QThread 进行多线程处理

等待有时是不可避免的。无论是查询网络、访问文件系统还是运行复杂的计算，有时程序只是需要时间来完成一个过程。然而，在等待的时候，我们的 GUI 没有理由完全变得无响应。具有多个 CPU 核心和线程技术的现代系统允许我们运行并发进程，我们没有理由不利用这一点来制作响应式的 GUI。尽管 Python 有自己的线程库，但 Qt 为我们提供了`QThread`对象，可以轻松构建多线程应用程序。它还有一个额外的优势，就是集成到 Qt 中，并且与信号和槽兼容。

在本节中，我们将构建一个相对缓慢的文件搜索工具，然后使用`QThread`来确保 GUI 保持响应。

# SlowSearcher 文件搜索引擎

为了有效地讨论线程，我们首先需要一个可以在单独线程上运行的缓慢过程。打开一个新的 Qt 应用程序模板副本，并将其命名为`file_searcher.py`。

让我们开始实现一个文件搜索引擎：

```py
class SlowSearcher(qtc.QObject):

    match_found = qtc.pyqtSignal(str)
    directory_changed = qtc.pyqtSignal(str)
    finished = qtc.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.term = None
```

我们将其称为`SlowSearcher`，因为它将是故意非优化的。它首先定义了一些信号，如下所示：

+   当文件名与搜索项匹配时，将发出`match_found`信号，并包含匹配的文件名

+   每当我们开始在一个新目录中搜索时，将发出`directory_changed`信号

+   当整个文件系统树已经被搜索时，将发出`finished`信号

最后，我们重写`__init__()`只是为了定义一个名为`self.term`的实例变量。

接下来，我们将为`term`创建一个 setter 方法：

```py
    def set_term(self, term):
        self.term = term
```

如果你想知道为什么我们要费力实现一个如此简单的 setter 方法，而不是直接设置变量，这个原因很快就会显而易见，当我们讨论`QThread`的一些限制时，这个原因将很快显现出来。

现在，我们将创建搜索方法，如下所示：

```py
    def do_search(self):
        root = qtc.QDir.rootPath()
        self._search(self.term, root)
        self.finished.emit()
```

这个方法将是我们调用来启动搜索过程的槽。它首先将根目录定位为一个`QDir`对象，然后调用`_search()`方法。一旦`_search()`返回，它就会发出`finished`信号。

实际的`_search()`方法如下：

```py
    def _search(self, term, path):
        self.directory_changed.emit(path)
        directory = qtc.QDir(path)
        directory.setFilter(directory.filter() |
            qtc.QDir.NoDotAndDotDot | qtc.QDir.NoSymLinks)
        for entry in directory.entryInfoList():
            if term in entry.filePath():
                print(entry.filePath())
                self.match_found.emit(entry.filePath())
            if entry.isDir():
                self._search(term, entry.filePath())
```

`_search()`是一个递归搜索方法。它首先发出`directory_changed`信号，表示我们正在一个新目录中搜索，然后为当前路径创建一个`QDir`对象。接下来，它设置`filter`属性，以便在查询`entryInfoList()`方法时，不包括符号链接或`.`和`..`快捷方式（这是为了避免搜索中的无限循环）。最后，我们遍历`entryInfoList()`检索到的目录内容，并为每个匹配的项目发出`match_found`信号。对于每个找到的目录，我们在其上运行`_search()`方法。

这样，我们的方法将递归遍历文件系统中的所有目录，寻找与我们的搜索词匹配的内容。这不是最优化的方法，这是故意这样做的。根据您的硬件、平台和驱动器上的文件数量，这个搜索可能需要几秒钟到几分钟的时间才能完成，因此它非常适合查看线程如何帮助必须执行缓慢进程的应用程序。

在多线程术语中，执行实际工作的类被称为`Worker`类。`SlowSearcher`是`Worker`类的一个示例。

# 一个非线程化的搜索器

为了实现一个搜索应用程序，让我们添加一个用于输入搜索词和显示搜索结果的 GUI 表单。

让我们称它为`SearchForm`，如下所示：

```py
class SearchForm(qtw.QWidget):

    textChanged = qtc.pyqtSignal(str)
    returnPressed = qtc.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setLayout(qtw.QVBoxLayout())
        self.search_term_inp = qtw.QLineEdit(
            placeholderText='Search Term',
            textChanged=self.textChanged,
            returnPressed=self.returnPressed)
        self.layout().addWidget(self.search_term_inp)
        self.results = qtw.QListWidget()
        self.layout().addWidget(self.results)
        self.returnPressed.connect(self.results.clear)
```

这个 GUI 只包含一个用于输入搜索词的`QLineEdit`小部件和一个用于显示结果的`QListWidget`小部件。我们将`QLineEdit`小部件的`returnPressed`和`textChanged`信号转发到`SearchForm`对象上的同名信号，以便我们可以更容易地在我们的`MainView`方法中连接它们。我们还将`returnPressed`连接到列表小部件的`clear`槽，以便开始新搜索时清除结果区域。

`SearchForm()`方法还需要一个方法来添加新项目：

```py
    def addResult(self, result):
        self.results.addItem(result)
```

这只是一个方便的方法，这样一来，主应用程序就不必直接操作表单中的小部件。

在我们的`MainWindow.__init__()`方法中，我们可以创建一个搜索器和表单对象，并将它们连接起来，如下所示：

```py
        form = SearchForm()
        self.setCentralWidget(form)
        self.ss = SlowSearcher()
        form.textChanged.connect(self.ss.set_term)
        form.returnPressed.connect(self.ss.do_search)
        self.ss.match_found.connect(form.addResult)
```

创建`SlowSearcher`和`SearchForm`对象并将表单设置为中央部件后，我们将适当的信号连接在一起，如下所示：

+   表单的`textChanged`信号，发出输入的字符串，连接到搜索器的`set_term()`设置方法。

+   表单的`returnPressed`信号连接到搜索器的`do_search()`方法以触发搜索。

+   搜索器的`match_found`信号，携带找到的路径名，连接到表单的`addResult()`方法。

最后，让我们添加两个`MainWindow`方法，以便让用户了解搜索的状态：

```py
    def on_finished(self):
        qtw.QMessageBox.information(self, 'Complete', 'Search complete')

    def on_directory_changed(self, path):
        self.statusBar().showMessage(f'Searching in: {path}')
```

第一个将显示一个指示搜索已完成的状态，而第二个将显示一个指示搜索器正在搜索的当前路径的状态。

回到`__init__()`，这些将连接到搜索器，如下所示：

```py
        self.ss.finished.connect(self.on_finished)
        self.ss.directory_changed.connect(self.on_directory_changed)
```

# 测试我们的非线程化搜索应用程序

我们对这个脚本的期望是，当我们在系统中搜索目录时，我们将在结果区域得到稳定的搜索结果打印输出，同时状态栏中的当前目录也会不断更新。

然而，如果您运行它，您会发现实际发生的并不是这样。相反，一旦搜索开始，GUI 就会冻结。状态栏中什么都没有显示，列表小部件中也没有条目出现，尽管匹配项已经打印到控制台上。只有当搜索最终完成时，结果才会出现，状态才会更新。

为了解决这个问题，我们需要引入线程。

那么，为什么程序会实时打印到控制台，但不会实时更新我们的 GUI 呢？这是因为`print()`是同步的——它在调用时立即执行，并且直到文本被写入控制台后才返回。然而，我们的 GUI 方法是异步的——它们被排队在 Qt 事件队列中，并且直到主事件循环执行`SlowSearcher.search()`方法后才会执行。

# 添加线程

**线程**是独立的代码执行上下文。默认情况下，我们所有的代码都在一个线程中运行，因此我们将其称为**单线程**应用程序。使用`QtCore.QThread`类，我们可以创建新的线程并将代码的部分移动到这些线程中，使其成为**多线程**应用程序。

您可以使用`QThread`对象，如下所示：

```py
        self.searcher_thread = qtc.QThread()
        self.ss.moveToThread(self.searcher_thread)
        self.ss.finished.connect(self.searcher_thread.quit)
        self.searcher_thread.start()
```

我们首先创建一个`QThread`对象，然后使用`SlowSearcher.moveToThread()`方法将我们的`SlowSearcher`对象移动到新线程中。`moveToThread()`是`QObject`的一个方法，由任何子类`QObject`的类继承。

接下来，我们将搜索器的`finished`信号连接到线程的`quit`槽；这将导致线程在搜索完成时停止执行。由于搜索线程不是我们主要的执行线程的一部分，它必须有一种方法来自行退出，否则在搜索结束后它将继续运行。

最后，我们需要调用搜索线程的`start()`方法来开始执行代码，并允许我们的主线程与`SlowSearcher`对象交互。

这段代码需要在创建`SlowSearcher`对象之后插入，但在连接到它的任何信号或槽之前（我们将在*线程提示和注意事项*部分讨论原因）。

由于我们在每次搜索后都要退出线程，所以需要在每次开始新搜索时重新启动线程。我们可以通过以下连接来实现这一点：

```py
        form.returnPressed.connect(self.searcher_thread.start)
```

这就是使用线程所需的一切。再次运行脚本，你会看到随着搜索的进行，GUI 会更新。

让我们总结一下这个过程，如下所示：

1.  创建`Worker`类的实例

1.  创建一个`QThread`对象

1.  使用`Worker`类的`moveToThread()`方法将其移动到新线程

1.  连接任何其他信号和槽

1.  调用线程的`start()`方法

# 另一种方法

虽然`moveToThread()`方法是使用`QThread`的推荐方法，但还有另一种方法可以完全正常地工作，并且在某种程度上简化了我们的代码。这种方法是通过对`QThread`进行子类化并重写`run()`方法来创建我们的`Worker`类，使用我们的工作代码。

例如，创建`SlowSearcher`的副本，并进行如下修改：

```py
class SlowSearcherThread(qtc.QThread):
    # rename "do_search()" to "run()":

    def run (self):
        root = qtc.QDir.rootPath()
        self._search(self.term, root)
        self.finished.emit()

    # The rest of the class is the same
```

在这里，我们只改变了三件事：

+   我们已将类重命名为`SlowSearcherThread`。

+   我们已将父类更改为`QThread`。

+   我们已经将`do_search()`重命名为`run()`。

我们的`MainWindow.__init__()`方法现在会简单得多：

```py
        form = SearchForm()
        self.setCentralWidget(form)
        self.ss = SlowSearcherThread()
        form.textChanged.connect(self.ss.set_term)
        form.returnPressed.connect(self.ss.start)
        self.ss.match_found.connect(form.addResult)
        self.ss.finished.connect(self.on_finished)
        self.ss.directory_changed.connect(self.on_directory_changed)
```

现在，我们只需要将`returnPressed`连接到`SlowSearcher.start()`。`start()`方法创建了新线程，并在新线程中执行对象的`run()`方法。这意味着，通过重写该方法，我们可以有效地将该代码放在一个新线程中。

始终记得实现`run()`，但调用`start()`。不要搞混了，否则你的多线程就无法工作！

虽然这种方法有一些有效的用例，但它可能会在对象数据的线程所有权上产生微妙的问题。即使`QThread`对象为辅助线程提供了控制接口，但对象本身仍然存在于主线程中。当我们在`worker`对象上调用`moveToThread()`时，我们可以确保`worker`对象完全移动到新线程中。然而，当`worker`对象是`QThread`的子类时，`QThread`的部分必须保留在主线程中，即使执行的代码被移动到新线程中。这可能会导致微妙的错误，因为很难搞清楚`worker`对象的哪些部分在哪个线程中。

最终，除非你有清晰的理由来对`QThread5`进行子类化，否则应该使用`moveToThread()`。

# 线程的提示和注意事项

之前的示例可能让多线程编程看起来很简单，但那是因为代码经过精心设计，避免了在处理线程时可能出现的一些问题。实际上，在单线程应用程序上进行多线程改造可能会更加困难。

一个常见的问题是`worker`对象在主线程中被卡住，导致我们失去了多线程的好处。这可能以几种方式发生。

例如，在我们原始的线程脚本（使用`moveToThread()`的脚本）中，我们必须在连接任何信号之前将工作线程移动到线程中。如果您尝试在信号连接之后移动线程代码，您会发现 GUI 会锁定，就好像您没有使用线程一样。

发生这种情况的原因是我们的工作线程方法是 Python 方法，并且连接到它们会在 Python 中创建一个连接，这个连接必须在主线程中持续存在。解决这个问题的一种方法是使用`pyqtSlot()`装饰器将工作线程的方法转换为真正的 Qt 槽，如下所示：

```py
    @qtc.pyqtSlot(str)
    def set_term(self, term):
        self.term = term

    @qtc.pyqtSlot()
    def do_search(self):
        root = qtc.QDir.rootPath()
        self._search(self.term, root)
        self.finished.emit()
```

一旦您这样做了，顺序就不重要了，因为连接将完全存在于 Qt 对象之间，而不是 Python 对象之间。

您还可以通过在主线程中直接调用`worker`对象的一个方法来捕获`worker`对象：

```py
        # in MainView__init__():
        self.ss.set_term('foo')
        self.ss.do_search()
```

将上述行放在`__init__()`中将导致 GUI 保持隐藏，直到对`foo`进行的文件系统搜索完成。有时，这个问题可能会很微妙；例如，以下`lambda`回调表明我们只是将信号直接连接到槽：

```py
        form.returnPressed.connect(lambda: self.ss.do_search())
```

然而，这种连接会破坏线程，因为`lambda`函数本身是主线程的一部分，因此对`search()`的调用将在主线程中执行。

不幸的是，这个限制也意味着您不能将`MainWindow`方法用作调用工作方法的槽；例如，我们不能在`MainWindow`中运行以下代码：

```py
    def on_return_pressed(self):
        self.searcher_thread.start()
        self.ss.do_search()
```

将其作为`returnPressed`的回调，而不是将信号连接到`worker`对象的方法，会导致线程失败和 GUI 锁定。

简而言之，最好将与`worker`对象的交互限制为纯 Qt 信号和槽连接，没有中间函数。

# 使用 QThreadPool 和 QRunner 进行高并发

`QThreads`非常适合将单个长时间的进程放入后台，特别是当我们希望使用信号和槽与该进程进行通信时。然而，有时我们需要做的是使用尽可能多的线程并行运行多个计算密集型操作。这可以通过`QThread`来实现，但更好的选择是在`QThreadPool`和`QRunner`中找到。

`QRunner`代表我们希望工作线程执行的单个可运行任务。与`QThread`不同，它不是从`QObject`派生的，也不能使用信号和槽。然而，它非常高效，并且在需要多个线程时使用起来更简单。

`QThreadPool`对象的工作是管理`QRunner`对象的队列，当计算资源可用时，启动新线程来执行对象。

为了演示如何使用这个，让我们构建一个文件哈希实用程序。

# 文件哈希 GUI

我们的文件哈希工具将接受一个源目录、一个目标文件和要使用的线程数。它将使用线程数来计算目录中每个文件的 MD5 哈希值，然后在执行此操作时将信息写入目标文件。

诸如 MD5 之类的**哈希函数**用于从任意数据计算出唯一的固定长度的二进制值。哈希经常用于确定文件的真实性，因为对文件的任何更改都会导致不同的哈希值。

从第四章中制作一个干净的 Qt 模板的副本，*使用 QMainWindow 构建应用程序*，将其命名为`hasher.py`。

然后，我们将从我们的 GUI 表单类开始，如下所示：

```py
class HashForm(qtw.QWidget):

    submitted = qtc.pyqtSignal(str, str, int)

    def __init__(self):
        super().__init__()
        self.setLayout(qtw.QFormLayout())
        self.source_path = qtw.QPushButton(
            'Click to select…', clicked=self.on_source_click)
        self.layout().addRow('Source Path', self.source_path)
        self.destination_file = qtw.QPushButton(
            'Click to select…', clicked=self.on_dest_click)
        self.layout().addRow('Destination File', self.destination_file)
        self.threads = qtw.QSpinBox(minimum=1, maximum=7, value=2)
        self.layout().addRow('Threads', self.threads)
        submit = qtw.QPushButton('Go', clicked=self.on_submit)
        self.layout().addRow(submit)
```

这种形式与我们在前几章设计的形式非常相似，有一个`submitted`信号来发布数据，`QPushButton`对象来存储选定的文件，一个旋转框来选择线程的数量，以及另一个按钮来提交表单。

文件按钮的回调将如下所示：

```py
    def on_source_click(self):
        dirname = qtw.QFileDialog.getExistingDirectory()
        if dirname:
            self.source_path.setText(dirname)

    def on_dest_click(self):
        filename, _ = qtw.QFileDialog.getSaveFileName()
        if filename:
            self.destination_file.setText(filename)
```

在这里，我们使用`QFileDialog`静态函数（你在第五章中学到的，*使用模型视图类创建数据接口*）来检索要检查的目录名称和我们将用来保存输出的文件名。

最后，我们的`on_submit()`回调如下：

```py
    def on_submit(self):
        self.submitted.emit(
            self.source_path.text(),
            self.destination_file.text(),
            self.threads.value()
        )
```

这个回调只是简单地从我们的小部件中收集数据，并使用`submitted`信号发布它。

在`MainWindow.__init__()`中，创建一个表单并将其设置为中央小部件：

```py
        form = HashForm()
        self.setCentralWidget(form)
```

这样我们的 GUI 就完成了，现在让我们来构建后端。

# 哈希运行器

`HashRunner`类将表示我们要执行的实际任务的单个实例。对于我们需要处理的每个文件，我们将创建一个唯一的`HashRunner`实例，因此它的构造函数将需要接收输入文件名和输出文件名作为参数。它的任务将是计算输入文件的 MD5 哈希，并将其与输入文件名一起追加到输出文件中。

我们将通过子类化`QRunnable`来启动它：

```py
class HashRunner(qtc.QRunnable):

    file_lock = qtc.QMutex()
```

我们首先创建一个`QMutex`对象。在多线程术语中，**互斥锁**是一个在线程之间共享的可以被锁定或解锁的对象。

你可以将互斥锁看作是单用户洗手间的门的方式；假设 Bob 试图进入洗手间并锁上门。如果 Alice 已经在洗手间里，那么门不会打开，Bob 将不得不耐心地等待，直到 Alice 解锁门并离开洗手间。然后，Bob 才能进入并锁上门。

同样，当一个线程尝试锁定另一个线程已经锁定的互斥锁时，它必须等到第一个线程完成并解锁互斥锁，然后才能获取锁。

在`HashRunner`中，我们将使用我们的`file_lock`互斥锁来确保两个线程不会同时尝试写入输出文件。请注意，该对象是在类定义中创建的，因此它将被`HashRunner`的所有实例共享。

现在，让我们创建`__init__()`方法：

```py
    def __init__(self, infile, outfile):
        super().__init__()
        self.infile = infile
        self.outfile = outfile
        self.hasher = qtc.QCryptographicHash(
            qtc.QCryptographicHash.Md5)
        self.setAutoDelete(True)
```

该对象将接收输入文件和输出文件的路径，并将它们存储为实例变量。它还创建了一个`QtCore.QCryptographicHash`的实例。这个对象能够计算数据的各种加密哈希，比如 MD5、SHA-256 或 Keccak-512。这个类支持的哈希的完整列表可以在[`doc.qt.io/qt-5/qcryptographichash.html`](https://doc.qt.io/qt-5/qcryptographichash.html)找到。

最后，我们将类的`autoDelete`属性设置为`True`。`QRunnable`的这个属性将导致对象在`run()`方法返回时被删除，节省我们的内存和资源。

运行器执行的实际工作在`run()`方法中定义：

```py
    def run(self):
        print(f'hashing {self.infile}')
        self.hasher.reset()
        with open(self.infile, 'rb') as fh:
            self.hasher.addData(fh.read())
        hash_string = bytes(self.hasher.result().toHex()).decode('UTF-8')
```

我们的函数首先通过打印一条消息到控制台并重置`QCryptographicHash`对象来开始，清除其中可能存在的任何数据。

然后，我们使用`addData()`方法将文件的二进制内容读入哈希对象中。可以使用`result()`方法从哈希对象中计算和检索哈希值作为`QByteArray`对象。然后，我们使用`toHex()`方法将字节数组转换为十六进制字符串，然后通过`bytes`对象将其转换为 Python Unicode 字符串。

现在，我们只需要将这个哈希字符串写入输出文件。这就是我们的互斥锁对象发挥作用的地方。

传统上，使用互斥锁的方式如下：

```py
        try:
            self.file_lock.lock()
            with open(self.outfile, 'a', encoding='utf-8') as out:
                out.write(f'{self.infile}\t{hash_string}\n')
        finally:
            self.file_lock.unlock()
```

我们在`try`块内调用互斥锁的`lock()`方法，然后执行我们的文件操作。在`finally`块内，我们调用`unlock`方法。之所以在`try`和`finally`块内执行这些操作，是为了确保即使`file`方法出现问题，互斥锁也一定会被释放。

然而，在 Python 中，每当我们有像这样具有初始化和清理代码的操作时，最好使用**上下文管理器**对象与`with`关键字结合使用。PyQt 为我们提供了这样的对象：`QMutexLocker`。

我们可以像下面这样使用这个对象：

```py
        with qtc.QMutexLocker(self.file_lock):
            with open(self.outfile, 'a', encoding='utf-8') as out:
                out.write(f'{self.infile}\t{hash_string}\n')
```

这种方法更加清晰。通过使用互斥上下文管理器，我们确保`with`块内的任何操作只由一个线程执行，其他线程将等待直到对象完成。

# 创建线程池

这个应用程序的最后一部分将是一个`HashManager`对象。这个对象的工作是接收表单输出，找到要进行哈希处理的文件，然后为每个文件启动一个`HashRunner`对象。

它将开始像这样：

```py
class HashManager(qtc.QObject):

    finished = qtc.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.pool = qtc.QThreadPool.globalInstance()
```

我们基于`QObject`类，这样我们就可以定义一个`finished`信号。当所有的运行者完成他们的任务时，这个信号将被发射。

在构造函数中，我们创建了`QThreadPool`对象。但是，我们使用`globalInstance()`静态方法来访问每个 Qt 应用程序中已经存在的全局线程池对象，而不是创建一个新对象。你不必这样做，但对于大多数应用程序来说已经足够了，并且消除了涉及多个线程池的一些复杂性。

这个类的真正工作将在一个我们将称之为`do_hashing`的方法中发生：

```py
    @qtc.pyqtSlot(str, str, int)
    def do_hashing(self, source, destination, threads):
        self.pool.setMaxThreadCount(threads)
        qdir = qtc.QDir(source)
        for filename in qdir.entryList(qtc.QDir.Files):
            filepath = qdir.absoluteFilePath(filename)
            runner = HashRunner(filepath, destination)
            self.pool.start(runner)
```

这个方法被设计为直接连接到`HashForm.submitted`信号，所以我们将它作为一个槽与匹配的信号。它首先通过将线程池的最大线程数（由`maxThreadCount`属性定义）设置为函数调用中接收到的数字。一旦设置了这个值，我们可以在线程池中排队任意数量的`QRunnable`对象，但只有`maxThreadCount`个线程会同时启动。

接下来，我们将使用`QDir`对象的`entryList()`方法来遍历目录中的文件，并为每个文件创建一个`HashRunner`对象。然后将运行对象传递给线程池的`start()`方法，将其添加到池的工作队列中。

在这一点上，我们所有的运行者都在单独的执行线程中运行，但是当它们完成时，我们想发射一个信号。不幸的是，`QThreadPool`中没有内置的信号告诉我们这一点，但`waitForDone()`方法将继续阻塞，直到所有线程都完成。

因此，将以下代码添加到`do_hashing()`中：

```py
        self.pool.waitForDone()
        self.finished.emit()
```

回到`MainWindow.__init__()`，让我们创建我们的管理器对象并添加我们的连接：

```py
        self.manager = HashManager()
        self.manager_thread = qtc.QThread()
        self.manager.moveToThread(self.manager_thread)
        self.manager_thread.start()
        form.submitted.connect(self.manager.do_hashing)
```

创建了我们的`HashManager`之后，我们使用`moveToThread()`将其移动到一个单独的线程中。这是因为我们的`do_hashing()`方法将阻塞，直到所有的运行者都完成，而我们不希望 GUI 在等待时冻结。如果我们省略了`do_hashing()`的最后两行，这是不必要的（但我们也永远不会知道何时完成）。

为了获得发生的反馈，让我们添加两个更多的连接：

```py
        form.submitted.connect(
            lambda x, y, z: self.statusBar().showMessage(
                f'Processing files in {x} into {y} with {z} threads.'))
        self.manager.finished.connect(
            lambda: self.statusBar().showMessage('Finished'))
```

第一个连接将在表单提交时设置状态，指示即将开始的工作的详细信息；第二个连接将在工作完成时通知我们。

# 测试脚本

继续启动这个脚本，让我们看看它是如何工作的。将源目录指向一个充满大文件的文件夹，比如 DVD 镜像、存档文件或视频文件。将线程的旋钮保持在默认设置，并点击`Go`。

从控制台输出中可以看到，文件正在一次处理两个。一旦一个完成，另一个就开始，直到所有文件都被处理完。

再试一次，但这次将线程数增加到四或五。注意到更多的文件正在同时处理。当您调整这个值时，您可能也会注意到有一个收益递减的点，特别是当您接近 CPU 核心数时。这是关于并行化的一个重要教训——有时候，过多会导致性能下降。

# 线程和 Python GIL

在 Python 中，没有讨论多线程是完整的，而不涉及全局解释器锁（GIL）。GIL 是官方 Python 实现（CPython）中内存管理系统的一部分。本质上，它就像我们在`HashRunner`类中使用的互斥锁一样——就像`HashRunner`类必须在写入输出之前获取`file_lock`互斥锁一样，Python 应用程序中的任何线程在执行任何 Python 代码之前必须获取 GIL。换句话说，一次只有一个线程可以执行 Python 代码。

乍一看，这可能会使 Python 中的多线程看起来是徒劳的；毕竟，如果只有一个线程可以一次执行 Python 代码，那么创建多个线程有什么意义呢？

答案涉及 GIL 要求的两个例外情况：

+   长时间运行的代码可以是 CPU 绑定或 I/O 绑定。CPU 绑定意味着大部分处理时间都用于运行繁重的 CPU 操作，比如加密哈希。I/O 绑定操作是指大部分时间都花在等待输入/输出调用上，比如将大文件写入磁盘或从网络套接字读取数据。当线程进行 I/O 调用并开始等待响应时，它会释放 GIL。因此，如果我们的工作代码大部分是 I/O 绑定的，我们可以从多线程中受益，因为在等待 I/O 操作完成时，其他代码可以运行。

+   如果 CPU 绑定的代码在 Python 之外运行，则会释放 GIL。换句话说，如果我们使用 C 或 C++函数或对象执行 CPU 绑定操作，那么 GIL 会被释放，只有在下一个 Python 操作运行时才重新获取。

这就是为什么我们的`HashRunner`起作用的原因；它的两个最重的操作如下：

+   从磁盘读取大文件（这是一个 I/O 绑定操作）

+   对文件内容进行哈希处理（这是在`QCryptographicHash`对象内部处理的——这是一个在 Python 之外运行的 C++对象）

如果我们要在纯 Python 中实现一个哈希算法，那么我们很可能会发现我们的多线程代码实际上比单线程实现还要慢。

最终，多线程并不是 Python 中加速代码的魔法子弹；必须仔细规划，以避免与 GIL 和我们在“线程提示和注意事项”部分讨论的陷阱有关的问题。然而，经过适当的关怀，它可以帮助我们创建快速响应的程序。

# 总结

在本章中，您学会了如何在运行缓慢的代码时保持应用程序的响应性。您学会了如何使用`QTimer`将操作推迟到以后的时间，无论是作为一次性操作还是重复操作。您学会了如何使用`QThread`将代码推送到另一个线程，既可以使用`moveToThread()`也可以通过子类化`QThread`。最后，您学会了如何使用`QThreadPool`和`QRunnable`来构建高度并发的数据处理应用程序。

在第十一章中，“使用 QTextDocument 创建丰富的文本”，我们将看看如何在 PyQt 中处理丰富的文本。您将学会如何使用类似 HTML 的标记定义丰富的文本，以及如何使用`QDocument`API 检查和操作文档。您还将学会如何利用 Qt 的打印支持将文档带入现实世界。

# 问题

尝试回答这些问题，以测试你从本章学到的知识：

1.  创建代码以每 10 秒调用`self.every_ten_seconds()`方法。

1.  以下代码错误地使用了`QTimer`。你能修复它吗？

```py
   timer = qtc.QTimer()
   timer.setSingleShot(True)
   timer.setInterval(1000)
   timer.start()
   while timer.remainingTime():
       sleep(.01)
   run_delayed_command()
```

1.  您已经创建了以下单词计数的`Worker`类，并希望将其移动到另一个线程以防止大型文档减慢 GUI。但它没有起作用——你需要改变这个类的什么？

```py
   class Worker(qtc.QObject):

    counted = qtc.pyqtSignal(int)

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent

    def count_words(self):
        content = self.parent.textedit.toPlainText()
        self.counted.emit(len(content.split()))
```

1.  以下代码是阻塞的，而不是在单独的线程中运行。为什么会这样？

```py
   class Worker(qtc.QThread):

       def set_data(data):
           self.data = data

       def run(self):n
           start_complex_calculations(self.data)

    class MainWindow(qtw.QMainWindow):

        def __init__(self):
            super().__init__()
            form = qtw.QWidget()
            self.setCentralWidget(form)
            form.setLayout(qtw.QFormLayout())

            worker = Worker()
            line_edit = qtw.QLineEdit(textChanged=worker.set_data)
            button = qtw.QPushButton('Run', clicked=worker.run)
            form.layout().addRow('Data:', line_edit)
            form.layout().addRow(button)
            self.show()
```

1.  这个`Worker`类会正确运行吗？如果不会，为什么？

```py
   class Worker(qtc.QRunnable):

       finished = qtc.pyqtSignal()

       def run(self):
           calculate_navigation_vectors(30)
           self.finished.emit()
```

1.  以下代码是设计用于处理科学设备输出的大型数据文件的`QRunnable`类的`run()`方法。这些文件包含数百万行以空格分隔的长数字。这段代码可能会受到 Python GIL 的影响吗？您能否减少 GIL 的干扰？

```py
       def run(self):
           with open(self.file, 'r') as fh:
               for row in fh:
                   numbers = [float(x) for x in row.split()]
                   if numbers:
                       mean = sum(numbers) / len(numbers)
                       numbers.append(mean)
                   self.queue.put(numbers)
```

1.  以下是您正在编写的多线程 TCP 服务器应用程序中`QRunnable`类的`run()`方法。所有线程共享通过`self.datastream`访问的服务器套接字实例。然而，这段代码不是线程安全的。您需要做什么来修复它？

```py
       def run(self):
           message = get_http_response_string()
           message_len = len(message)
           self.datastream.writeUInt32(message_len)
           self.datastream.writeQString(message)
```

# 进一步阅读

欲了解更多信息，请参考以下内容：

+   信号量类似于互斥锁，但允许获取任意数量的锁，而不仅仅是单个锁。您可以在[`doc.qt.io/qt-5/qsemaphore.html`](https://doc.qt.io/qt-5/qsemaphore.html)了解更多关于 Qt 实现的`QSemaphore`类的信息。

+   David Beazley 在 PyCon 2010 的演讲提供了更深入的了解 Python GIL 的运作，可在[`www.youtube.com/watch?v=Obt-vMVdM8s`](https://www.youtube.com/watch?v=Obt-vMVdM8s)上观看。


# 第十一章：使用 QTextDocument 创建富文本

无论是在文字处理器中起草商业备忘录、写博客文章还是生成报告，世界上大部分的计算都涉及文档的创建。这些应用程序大多需要能够生成不仅仅是普通的字母数字字符串，还需要生成富文本。富文本（与纯文本相对）意味着包括字体、颜色、列表、表格和图像等样式和格式特性的文本。

在本章中，我们将学习 PyQt 如何允许我们通过以下主题处理富文本：

+   使用标记创建富文本

+   使用`QTextDocument`操纵富文本

+   打印富文本

# 技术要求

对于本章，您将需要自第一章以来一直在使用的基本 Python 和 Qt 设置。您可能希望参考可以在[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter11`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter11)找到的示例代码。

查看以下视频以查看代码的实际效果：[`bit.ly/2M5P4Cq`](http://bit.ly/2M5P4Cq)

# 使用标记创建富文本

每个支持富文本的应用程序都必须有一些格式来表示内存中的文本，并在将其保存到文件时。有些格式使用自定义二进制代码，例如旧版本 Microsoft Word 使用的`.doc`和`.rtf`文件。在其他情况下，使用纯文本**标记语言**。在标记语言中，称为**标签**的特殊字符串指示富文本特性的放置。Qt 采用标记方法，并使用**超文本标记语言**（**HTML**）第 4 版的子集表示富文本。

Qt 中的富文本标记由`QTextDocument`对象呈现，因此它只能用于使用`QTextDocument`存储其内容的小部件。这包括`QLabel`、`QTextEdit`和`QTextBrowser`小部件。在本节中，我们将创建一个演示脚本，以探索这种标记语言的语法和功能。

鉴于 Web 开发的普及和普遍性，您可能已经对 HTML 有所了解；如果您不了解，下一节将作为一个快速介绍。

# HTML 基础

HTML 文档由文本内容和标签组成，以指示非纯文本特性。标签只是用尖括号括起来的单词，如下所示：

```py
<sometag>This is some content</sometag>
```

注意前面示例中的`</sometag>`代码。这被称为**闭合标签**，它与开放标签类似，但标签名称前面有一个斜杠（`/`）。通常只有用于包围（或有能力包围）文本内容的标签才使用闭合标签。

考虑以下示例：

```py
Text can be <b>bold<b> <br>
Text can be <em>emphasized</em> <br>
Text can be <u>underlined</u> <hr>
```

`b`、`em`和`u`标签需要闭合标签，因为它们包围内容的一部分并指示外观的变化。`br`和`hr`标签（*换行*和*水平线*，分别）只是指示包含在文档中的非文本项，因此它们没有闭合标签。

如果您想看看这些示例中的任何一个是什么样子，您可以将它们复制到一个文本文件中，然后在您的 Web 浏览器中打开它们。还可以查看示例代码中的`html_examples.html`文件。

有时，通过嵌套标签创建复杂结构，例如以下列表：

```py
<ol>
  <li> Item one</li>
  <li> Item two</li>
  <li> Item three</li>
</ol>
```

在这里，`ol`标签开始一个有序列表（使用顺序数字或字母的列表，而不是项目符号字符）。列表中的每个项目由`li`（列表项）标签表示。请注意，当嵌套标签使用闭合标签时，标签必须按正确顺序关闭，如下所示：

```py
<b><i>This is right</i></b>
<b><i>This is wrong!</b></i>
```

前面的错误示例不起作用，因为内部标签（`<i>`）在外部标签（`<b>`）之后关闭。

HTML 标签可以有属性，这些属性是用于配置标签的键值对，如下例所示：

```py
<img src="my_image.png" width="100px" height="20px">
```

前面的标签是一个用于显示图像的`img`（图像）标签。 其属性是`src`（指示图像文件路径），`width`（指示显示图像的宽度）和`height`（指示显示的高度）。

HTML 属性是以空格分隔的，所以不要在它们之间放逗号。 值可以用单引号或双引号引用，或者如果它们不包含空格或其他令人困惑的字符（例如闭合尖括号）则不引用； 但通常最好用双引号引用它们。 在 Qt HTML 中，大小通常以`px`（像素）或`％`（百分比）指定，尽管在现代 Web HTML 中，通常使用其他单位。

# 样式表语法

现代 HTML 使用**层叠样式表**（**CSS**）进行样式设置。 在第六章中，*为 Qt 应用程序设置样式*，我们讨论了 QSS 时学习了 CSS。 回顾一下，CSS 允许您对标签的外观进行声明，如下所示：

```py
b {
    color: red;
    font-size: 16pt;
}
```

前面的 CSS 指令将使粗体标签内的所有内容（在`<b>`和`</b>`之间）以红色 16 点字体显示。

某些标签也可以有修饰符，例如：

```py
a:hovered {
   color: green;
   font-size: 16pt;
}
```

前面的 CSS 适用于`<a>`（锚点）标签内容，但仅当鼠标指针悬停在锚点上时。 这样的修饰符也称为**伪类**。

# 语义标签与装饰标签

一些 HTML 标签描述了内容应该如何显示。 我们称这些为**装饰**标签。 例如，`<i>`标签表示文本应以斜体字打印。 但请注意，斜体字在现代印刷中有许多用途-强调一个词，表示已出版作品的标题，或表示短语来自外语。 为了区分这些用途，HTML 还有*语义*标签。 例如，`<em>`表示强调，并且在大多数情况下会导致斜体文本。 但与`<i>`标签不同，它还指示文本应该以何种方式斜体。 HTML 的旧版本通常侧重于装饰标签，而较新版本则越来越注重语义标签。

Qt 的富文本 HTML 支持一些语义标签，但它们只是等效的装饰标签。

现代 HTML 和 CSS 在网页上使用的内容远不止我们在这里描述的，但我们所涵盖的内容足以理解 Qt 小部件使用的有限子集。 如果您想了解更多，请查看本章末尾的*进一步阅读*部分中的资源。

# 结构和标题标签

为了尝试丰富的文本标记，我们将为我们的下一个大型游戏*Fight Fighter 2*编写广告，并在 QTextBrowser 中查看它。 首先，从第四章中获取应用程序模板，*使用 QMainWindow 构建应用程序*，并将其命名为`qt_richtext_demo.py`。

在`MainWindow.__init__（）`中，像这样添加一个`QTextBrowser`对象作为主窗口小部件：

```py
        main = qtw.QTextBrowser()
        self.setCentralWidget(main)
        with open('fight_fighter2.html', 'r') as fh:
            main.insertHtml(fh.read())
```

`QTextBrowser`基于`QTextEdit`，但是只读并预先配置为导航超文本链接。 创建文本浏览器后，我们打开`fight_fighter2.html`文件，并使用`insertHtml（）`方法将其内容插入浏览器。 现在，我们可以编辑`fight_fighter2.html`并查看它在 PyQt 中的呈现方式。

在编辑器中打开`fight_fighter2.html`并从以下代码开始：

```py
<qt>
  <body>
    <h1>Fight Fighter 2</h1>
    <hr>
```

HTML 文档是按层次结构构建的，最外层的标签通常是`<html>`。 但是，当将 HTML 传递给基于`QTextDocument`的小部件时，我们还可以使用`<qt>`作为最外层的标签，这是一个好主意，因为它提醒我们正在编写 Qt 支持的 HTML 子集，而不是实际的 HTML。

在其中，我们有一个`<body>`标签。 这个标签也是可选的，但它将使未来的样式更容易。

接下来，我们在`<h1>`标签内有一个标题。这里的*H*代表标题，标签`<h1>`到`<h6>`表示从最外层到最内层的部分标题。这个标签将以更大更粗的字体呈现，表明它是部分的标题。

在标题之后，我们有一个`<hr>`标签来添加水平线。默认情况下，`<hr>`会产生一个单像素厚的黑线，但可以使用样式表进行自定义。

让我们添加以下常规文本内容：

```py
    <p>Everything you love about fight-fighter, but better!</p>
```

`<p>`标签，或段落标签，表示一块文本。在段落标签中不严格需要包含文本内容，但要理解 HTML 默认不会保留换行。如果你想要通过换行来分隔不同的段落，你需要将它们放在段落标签中。（你也可以插入`<br>`标签，但是段落标签被认为是更语义化的更干净的方法。）

接下来，添加第一个子标题，如下所示：

```py
    <h2>About</h2>
```

在`<h1>`下的任何子部分应该是`<h2>`；在`<h2>`内的任何子部分应该是`<h3>`，依此类推。标题标签是语义标签的例子，表示文档层次结构的级别。

永远不要根据它们产生的外观来选择标题级别——例如，不要在`<h1>`下使用`<h4>`，只是因为你想要更小的标题文本。使用它们语义化，并使用样式来调整外观（参见*字体、颜色、图片和样式*部分了解更多信息）。

# 排版标签

Qt 富文本支持许多标签来改变文本的基本外观，如下所示：

```py
  <p>Fight fighter 2 is the <i>amazing</i> sequel to <u>Fight Fighter</u>, an <s>intense</s> ultra-intense multiplayer action game from <b>FightSoft Software, LLC</b>.</p>
```

在这个例子中，我们使用了以下标签：

| 标签 | 结果 |
| --- | --- |
| `<i>` | *斜体* |
| `<b>` | **粗体** |
| `<u>` | 下划线 |
| `<s>` | 删除线 |

这些是装饰性标签，它们每个都会改变标签内文本的外观。除了这些标签，还支持一些用于文本大小和位置的较少使用的标签，包括以下内容：

```py
    <p>Fight Fighter 2's new Ultra-Action<sup>TM</sup> technology delivers low-latency combat like never before.   Best of all, at only $1.99<sub>USD</sub>, you <big>Huge Action</big> for a <small>tiny</small> price.</p>
```

在前面的例子中，我们可以看到`<sup>`和`<sub>`标签，分别提供上标和下标文本，以及`<big>`和`<small>`标签，分别提供稍微更大或更小的字体。

# 超链接

超链接也可以使用`<a>`（锚点）标签添加到 Qt 富文本中，如下所示：

```py
    <p>Download it today from
    <a href='http://www.example.com'>Example.com</a>!</p>
```

超链接的确切行为取决于显示超链接的部件和部件的设置。

`QTextBrowser`默认会尝试在部件内导航到超链接；但请记住，这些链接只有在它们是资源 URL 或本地文件路径时才会起作用。`QTextBrowser`缺乏网络堆栈，不能用于浏览互联网。

然而，它可以配置为在外部浏览器中打开 URL；在 Python 脚本中，添加以下代码到`MainWindow.__init__()`：

```py
      main.setOpenExternalLinks(True)
```

这利用`QDesktopServices.openUrl()`来在桌面的默认浏览器中打开锚点的`href`值。每当你想要在文档中支持外部超链接时，你应该配置这个设置。

外部超链接也可以在`QLabel`部件上进行配置，但不能在`QTextEdit`部件内进行配置。

文档也可以使用超链接来在文档内部导航，如下所示：

```py
    <p><a href='#Features'>Read about the features</a></p>

    <br><br><br><br><br><br>

    <a name='Features'></a>
    <h2>Features</h2>
    <p>Fight Fighter 2 is so amazing in so many ways:</p>
```

在这里，我们添加了一个指向`#Features`（带有井号）的锚点，然后是一些换行来模拟更多的内容。当用户点击链接时，它将滚动浏览器部件到具有`name`属性（而不是`href`）为`Features`的锚点标签（不带井号）。

这个功能对于提供可导航的目录表格非常有用。

# 列表和表格

列表和表格非常有用，可以以用户能够快速解析的方式呈现有序信息。

列表的一个例子如下：

```py
    <ul type=square>
      <li>More players at once!  Have up to 72 players.</li>
      <li>More teams!  Play with up to 16 teams!</li>
      <li>Easier installation!  Simply:<ol>
        <li>Copy the executable to your system.</li>
        <li>Run it!</li>
      </ol></li>
      <li>Sound and music! &gt;16 Million colors on some systems!</li>
    </ul>
```

Qt 富文本中的列表可以是有序或无序的。在上面的例子中，我们有一个无序列表（`<ul>`）。可选的`type`属性允许您指定应使用什么样的项目符号。在这种情况下，我们选择了`square`；无序列表的其他选项包括`circle`和`disc`。

使用`<li>`（列表项）标签指定列表中的每个项目。我们还可以在列表项内部嵌套一个列表，以创建一个子列表。在这种情况下，我们添加了一个有序列表，它将使用顺序号来指示新项目。有序列表还接受`type`属性；有效值为`a`（小写字母）、`A`（大写字母）或`1`（顺序号）。

在最后一个项目中的`&gt;`是 HTML 实体的一个例子。这些是特殊代码，用于显示 HTML 特殊字符，如尖括号，或非 ASCII 字符，如版权符号。实体以一个和号开始，以一个冒号结束，并包含一个指示要显示的字符的字符串。在这种情况下，`gt`代表*greater than*。可以在[`dev.w3.org/html5/html-author/charref`](https://dev.w3.org/html5/html-author/charref)找到官方实体列表，尽管并非所有实体都受`QTextDocument`支持。

创建 HTML 表格稍微复杂，因为它需要多层嵌套。表标签的层次结构如下：

+   表格本身由`<table>`标签定义

+   表的标题部分由`<thead>`标签定义

+   表的每一行（标题或数据）由`<tr>`（表行）标签定义

+   在每一行中，表格单元格由`<th>`（表头）标签或`<td>`（表数据）标签定义

让我们用以下代码开始一个表格：

```py
    <table border=2>
      <thead>
        <tr bgcolor='grey'>
        <th>System</th><th>Graphics</th><th>Sound</th></tr>
      </thead>
```

在上面的例子中，我们从开头的`<table>`标签开始。`border`属性指定了表格边框的宽度（以像素为单位）；在这种情况下，我们希望有一个两像素的边框。请记住，这个边框围绕每个单元格，不会合并（也就是说，不会与相邻单元格的边框合并），因此实际上，每个单元格之间将有一个四像素的边框。表格边框可以有不同的样式；默认情况下使用*ridge*样式，因此这个边框将被着色，看起来略微立体。

在`<thead>`部分，有一行表格，填满了表头单元格。通过设置行的`bgcolor`属性，我们可以将所有表头单元格的背景颜色更改为灰色。

现在，让我们用以下代码添加一些数据行：

```py
      <tr><td>Windows</td><td>DirectX 3D</td><td>24 bit PCM</td></tr>
      <tr><td>FreeDOS</td><td>256 color</td><td>8 bit Adlib PCM</td></tr>
      <tr><td>Commodore 64</td><td>256 color</td><td>SID audio</td></tr>
      <tr><td>TRS80</td>
        <td rowspan=2>Monochrome</td>
        <td rowspan=2>Beeps</td>
      </tr>
      <tr><td>Timex Sinclair</td></tr>
      <tr>
        <td>BBC Micro</td>
        <td colspan=2 bgcolor='red'>No support</td>
      </tr>
    </table>
```

在上面的例子中，行包含了用于实际表格数据的`<td>`单元格。请注意，我们可以在单个单元格上使用`rowspan`和`colspan`属性，使它们占用额外的行和列，并且`bgcolor`属性也可以应用于单个单元格。

可以将数据行包装在`<tbody>`标签中，以使其与`<thead>`部分区分开，但这实际上在 Qt 富文本 HTML 中没有任何有用的影响。

# 字体、颜色、图像和样式

可以使用`<font>`标签设置富文本字体，如下所示：

```py
    <h2>Special!</h2>

    <p>
      <font face='Impact' size=32 color='green'>Buy Now!</font>
      and receive <tt>20%</tt> off the regular price plus a
      <font face=Impact size=16 color='red'>Free sticker!</font>
    </p>
```

`<font>`对于那些学习了更现代 HTML 的人可能会感到陌生，因为它在 HTML 5 中已被弃用。但正如您所看到的，它可以用来设置标签中的文本的`face`、`size`和`color`属性。

`<tt>`（打字机类型）标签是使用等宽字体的简写，对于呈现内联代码、键盘快捷键和终端输出非常有用。

如果您更喜欢使用更现代的 CSS 样式字体配置，可以通过在块级标签（如`<div>`）上设置`style`属性来实现：

```py
    <div style='font-size: 16pt; font-weight: bold; color: navy;
                background-color: orange; padding: 20px;
                text-align: center;'>
                Don't miss this exciting offer!
    </div>
```

在`style`属性中，您可以设置任何支持的 CSS 值，以应用于该块。

# 文档范围的样式

Qt 富文本文档*不*支持 HTML `<style>`标签或`<link>`标签来设置文档范围的样式表。相反，您可以使用`QTextDocument`对象的`setDefaultStyleSheet()`方法来设置一个 CSS 样式表，该样式表将应用于所有查看的文档。

回到`MainWindow.__init__()`，添加以下内容：

```py
        main.document().setDefaultStyleSheet(
            'body {color: #333; font-size: 14px;} '
            'h2 {background: #CCF; color: #443;} '
            'h1 {background: #001133; color: white;} '
        )
```

但是，请注意，这必须在 HTML 插入小部件之前添加。`defaultStyleSheet`方法仅适用于新插入的 HTML。

还要注意，外观的某些方面不是文档的属性，而是小部件的属性。特别是，文档的背景颜色不能通过修改`body`的样式来设置。

相反，设置小部件的样式表，如下所示：

```py
        main.setStyleSheet('background-color: #EEF;')
```

请记住，小部件的样式表使用 QSS，而文档的样式表使用 CSS。区别是微小的，但在某些情况下可能会起作用。

# 图片

可以使用`<img>`标签插入图像，如下所示：

```py
    <div>
      <img src=logo.png width=400 height=100 />
    </div>
```

`src`属性应该是 Qt 支持的图像文件的文件或资源路径（有关图像格式支持的更多信息，请参见第六章，*Qt 应用程序的样式*）。`width`和`height`属性可用于强制指定特定大小。

# Qt 富文本和 Web HTML 之间的区别

如果您有网页设计或开发经验，您无疑已经注意到 Qt 的富文本标记与现代网页浏览器中使用的 HTML 之间的几个区别。在创建富文本时，重要的是要记住这些区别，所以让我们来看一下主要的区别。

首先，Qt 富文本基于 HTML 4 和 CSS 2.1；正如您所见，它包括一些已弃用的标签，如`<font>`，并排除了许多更现代的标签，如`<section>`或`<figure>`。

此外，Qt 富文本基于这些规范的一个子集，因此它不支持许多标签。例如，没有输入或表单相关的标签，如`<select>`或`<textarea>`。

`QTextDocument`在语法错误和大小写方面也比大多数网页浏览器渲染器更严格。例如，当设置默认样式表时，标签名称的大小写需要与文档中使用的大小写匹配，否则样式将不会应用。此外，未使用块级标签（如`<p>`、`<div>`等）包围内容可能会导致不可预测的结果。

简而言之，最好不要将 Qt 富文本标记视为真正的 HTML，而是将其视为一种类似但独立的标记语言。如果您对特定标记或样式指令是否受支持有任何疑问，请参阅[`doc.qt.io/qt-5/richtext-html-subset.html`](https://doc.qt.io/qt-5/richtext-html-subset.html)上的支持参考。

# 使用 QTextDocument 操作富文本

除了允许我们在标记中指定富文本外，Qt 还为我们提供了一个 API 来编程创建和操作富文本。这个 API 称为**Qt Scribe Framework**，它是围绕`QTextDocument`和`QTextCursor`类构建的。

演示如何使用`QTextDocument`和`QTextCursor`类创建文档，我们将构建一个简单的发票生成器应用程序。我们的应用程序将从小部件表单中获取数据，并使用它来编程生成富文本文档。

# 创建发票应用程序 GUI

获取我们的 PyQt 应用程序模板的最新副本，并将其命名为`invoice_maker.py`。我们将通过创建 GUI 元素开始我们的应用程序，然后开发实际构建文档的方法。

从一个数据输入表单类开始您的脚本，如下所示：

```py
class InvoiceForm(qtw.QWidget):

    submitted = qtc.pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.setLayout(qtw.QFormLayout())
        self.inputs = dict()
        self.inputs['Customer Name'] = qtw.QLineEdit()
        self.inputs['Customer Address'] = qtw.QPlainTextEdit()
        self.inputs['Invoice Date'] = qtw.QDateEdit(
            date=qtc.QDate.currentDate(), calendarPopup=True)
        self.inputs['Days until Due'] = qtw.QSpinBox(
            minimum=0, maximum=60, value=30)
        for label, widget in self.inputs.items():
            self.layout().addRow(label, widget)
```

与我们创建的大多数表单一样，这个类基于`QWidget`，并通过定义一个`submitted`信号来携带表单值的字典来开始。在这里，我们还向`QFormLayout`添加了各种输入，以输入基本的发票数据，如客户名称、客户地址和发票日期。

接下来，我们将添加`QTableWidget`以输入发票的行项目，如下所示：

```py
        self.line_items = qtw.QTableWidget(
            rowCount=10, columnCount=3)
        self.line_items.setHorizontalHeaderLabels(
            ['Job', 'Rate', 'Hours'])
        self.line_items.horizontalHeader().setSectionResizeMode(
            qtw.QHeaderView.Stretch)
        self.layout().addRow(self.line_items)
        for row in range(self.line_items.rowCount()):
            for col in range(self.line_items.columnCount()):
                if col > 0:
                    w = qtw.QSpinBox(minimum=0)
                    self.line_items.setCellWidget(row, col, w)
```

该表格小部件的每一行都包含任务的描述、工作的费率和工作的小时数。因为最后两列中的值是数字，所以我们使用表格小部件的`setCellWidget()`方法来用`QSpinBox`小部件替换这些单元格中的默认`QLineEdit`小部件。

最后，我们将使用以下代码添加一个`submit`按钮：

```py
        submit = qtw.QPushButton('Create Invoice', clicked=self.on_submit)
        self.layout().addRow(submit)
```

`submit`按钮调用一个`on_submit()`方法，开始如下：

```py
   def on_submit(self):
        data = {
            'c_name': self.inputs['Customer Name'].text(),
            'c_addr': self.inputs['Customer Address'].toPlainText(),
            'i_date': self.inputs['Invoice Date'].date().toString(),
            'i_due': self.inputs['Invoice Date'].date().addDays(
                self.inputs['Days until Due'].value()).toString(),
            'i_terms': '{} days'.format(
                self.inputs['Days until Due'].value())
        }
```

该方法只是简单地提取输入表单中输入的值，进行一些计算，并使用`submitted`信号发射生成的数据`dict`。在这里，我们首先通过使用每个小部件的适当方法将表单的每个输入小部件的值放入 Python 字典中。

接下来，我们需要检索行项目的数据，如下所示：

```py
       data['line_items'] = list()
        for row in range(self.line_items.rowCount()):
            if not self.line_items.item(row, 0):
                continue
            job = self.line_items.item(row, 0).text()
            rate = self.line_items.cellWidget(row, 1).value()
            hours = self.line_items.cellWidget(row, 2).value()
            total = rate * hours
            row_data = [job, rate, hours, total]
            if any(row_data):
                data['line_items'].append(row_data)
```

对于表格小部件中具有描述的每一行，我们将检索所有数据，通过将费率和工时相乘来计算总成本，并将所有数据附加到我们的`data`字典中的列表中。

最后，我们将计算一个总成本，并使用以下代码将其附加到：

```py
        data['total_due'] = sum(x[3] for x in data['line_items'])
        self.submitted.emit(data)
```

在每一行的成本总和之后，我们将其添加到数据字典中，并使用数据发射我们的`submitted`信号。

这就是我们的`form`类，所以让我们在`MainWindow`中设置主应用程序布局。在`MainWindow.__init__()`中，添加以下代码：

```py
        main = qtw.QWidget()
        main.setLayout(qtw.QHBoxLayout())
        self.setCentralWidget(main)

        form = InvoiceForm()
        main.layout().addWidget(form)

        self.preview = InvoiceView()
        main.layout().addWidget(self.preview)

        form.submitted.connect(self.preview.build_invoice)
```

主小部件被赋予一个水平布局，以包含格式化发票的表单和视图小部件。然后，我们将表单的`submitted`信号连接到视图对象上将创建的`build_invoice()`方法。

这是应用程序的主要 GUI 和逻辑；现在我们只需要创建我们的`InvoiceView`类。

# 构建 InvoiceView

`InvoiceView`类是所有繁重工作发生的地方；我们将其基于只读的`QTextEdit`小部件，并且它将包含一个`build_invoice()`方法，当使用数据字典调用时，将使用 Qt Scribe 框架构建格式化的发票文档。

让我们从构造函数开始，如下例所示：

```py
class InvoiceView(qtw.QTextEdit):

    dpi = 72
    doc_width = 8.5 * dpi
    doc_height = 11 * dpi

    def __init__(self):
        super().__init__(readOnly=True)
        self.setFixedSize(qtc.QSize(self.doc_width, self.doc_height))
```

首先，我们为文档的宽度和高度定义了类变量。我们选择这些值是为了给我们一个标准的美国信件大小文档的纵横比，适合于普通计算机显示器的合理尺寸。在构造函数中，我们使用计算出的值来设置小部件的固定大小。这是我们在构造函数中需要做的所有事情，所以现在是时候开始真正的工作了——构建一个文档。

让我们从`build_invoice()`开始，如下所示：

```py
    def build_invoice(self, data):
        document = qtg.QTextDocument()
        self.setDocument(document)
        document.setPageSize(qtc.QSizeF(self.doc_width, self.doc_height))
```

正如您在前面的示例中所看到的，该方法首先创建一个新的`QTextDocument`对象，并将其分配给视图的`document`属性。然后，使用在类定义中计算的文档尺寸设置`pageSize`属性。请注意，我们基于 QTextEdit 的视图已经有一个我们可以检索的`document`对象，但我们正在创建一个新的对象，以便该方法每次调用时都会以空文档开始。

使用`QTextDocument`编辑文档可能会感觉有点不同于我们创建 GUI 表单的方式，通常我们会创建对象，然后配置并将它们放置在布局中。

相反，`QTextDocument`的工作流更像是一个文字处理器：

+   有一个`cursor`始终指向文档中的某个位置

+   有一个活动文本样式、段落样式或另一个块级样式，其设置将应用于输入的任何内容

+   要添加内容，用户首先要定位光标，配置样式，最后创建内容

因此，显然，第一步是获取光标的引用；使用以下代码来实现：

```py
        cursor = qtg.QTextCursor(document)
```

`QTextCursor`对象是我们用来插入内容的工具，并且它有许多方法可以将不同类型的元素插入文档中。

例如，在这一点上，我们可以开始插入文本内容，如下所示：

```py
        cursor.insertText("Invoice, woohoo!")
```

然而，在我们开始向文档中写入内容之前，我们应该构建一个基本的文档框架来进行工作。为了做到这一点，我们需要了解`QTextDocument`对象的结构。

# QTextDocument 结构

就像 HTML 文档一样，`QTextDocument`对象是一个分层结构。它由**框架**、**块**和**片段**组成，定义如下：

+   框架由`QTextFrame`对象表示，是文档的矩形区域，可以包含任何类型的内容，包括其他框架。在我们的层次结构顶部是**根框架**，它包含了文档的所有内容。

+   一个块，由`QTextBlock`对象表示，是由换行符包围的文本区域，例如段落或列表项。

+   片段，由`QTextFragment`对象表示，是块内的连续文本区域，共享相同的文本格式。例如，如果您有一个句子中包含一个粗体字，那么代表三个文本片段：粗体字之前的句子，粗体字，和粗体字之后的句子。

+   其他项目，如表格、列表和图像，都是从这些前面的类中派生出来的。

我们将通过在根框架下插入一组子框架来组织我们的文档，以便我们可以轻松地导航到我们想要处理的文档部分。我们的文档将有以下四个框架：

+   **标志框架**将包含公司标志和联系信息

+   **客户地址框架**将保存客户姓名和地址

+   **条款框架**将保存发票条款和条件的列表

+   **行项目框架**将保存行项目和总计的表格

让我们创建一些文本框架来概述我们文档的结构。我们将首先保存对根框架的引用，以便在创建子框架后可以轻松返回到它，如下所示：

```py
        root = document.rootFrame()
```

既然我们有了这个，我们可以通过调用以下命令在任何时候为根框架的末尾检索光标位置：

```py
        cursor.setPosition(root.lastPosition())
```

光标的`setPosition()`方法将我们的光标放在任何给定位置，根框架的`lastPosition()`方法检索根框架末尾的位置。

现在，让我们定义第一个子框架，如下所示：

```py
        logo_frame_fmt = qtg.QTextFrameFormat()
        logo_frame_fmt.setBorder(2)
        logo_frame_fmt.setPadding(10)
        logo_frame = cursor.insertFrame(logo_frame_fmt)
```

框架必须使用定义其格式的`QTextFrameFormat`对象创建，因此在我们写框架之前，我们必须定义我们的格式。不幸的是，框架格式的属性不能使用关键字参数设置，因此我们必须使用 setter 方法进行配置。在这个例子中，我们设置了框架周围的两像素边框，以及十像素的填充。

一旦格式对象被创建，我们调用光标的`insertFrame()`方法来使用我们配置的格式创建一个新框架。

`insertFrame()`返回创建的`QTextFrame`对象，并且将我们文档的光标定位在新框架内。由于我们还没有准备好向这个框架添加内容，并且我们不想在其中创建下一个框架，所以我们需要使用以下代码返回到根框架之前创建下一个框架：

```py
        cursor.setPosition(root.lastPosition())
        cust_addr_frame_fmt = qtg.QTextFrameFormat()
        cust_addr_frame_fmt.setWidth(self.doc_width * .3)
        cust_addr_frame_fmt.setPosition(qtg.QTextFrameFormat.FloatRight)
        cust_addr_frame = cursor.insertFrame(cust_addr_frame_fmt)
```

在上面的例子中，我们使用框架格式来将此框架的宽度设置为文档宽度的三分之一，并使其浮动到右侧。*浮动*文档框架意味着它将被推到文档的一侧，其他内容将围绕它流动。

现在，我们将添加术语框架，如下所示：

```py
        cursor.setPosition(root.lastPosition())
        terms_frame_fmt = qtg.QTextFrameFormat()
        terms_frame_fmt.setWidth(self.doc_width * .5)
        terms_frame_fmt.setPosition(qtg.QTextFrameFormat.FloatLeft)
        terms_frame = cursor.insertFrame(terms_frame_fmt)
```

这一次，我们将使框架的宽度为文档宽度的一半，并将其浮动到左侧。

理论上，这两个框架应该相邻。实际上，由于`QTextDocument`类渲染中的一个怪癖，第二个框架的顶部将在第一个框架的顶部下面一行。这对我们的演示来说没问题，但如果您需要实际的列，请改用表格。

最后，让我们添加一个框架来保存我们的行项目表格，如下所示：

```py
        cursor.setPosition(root.lastPosition())
        line_items_frame_fmt = qtg.QTextFrameFormat()
        line_items_frame_fmt.setMargin(25)
        line_items_frame = cursor.insertFrame(line_items_frame_fmt)
```

再次，我们将光标移回到根框架并插入一个新框架。这次，格式将在框架上添加 25 像素的边距。

请注意，如果我们不想对`QTextFrameFormat`对象进行任何特殊配置，我们就不必这样做，但是*必须*为每个框架创建一个对象，并且*必须*在创建新框架之前对它们进行任何配置。请注意，如果您有许多具有相同配置的框架，也可以重用框架格式。

# 字符格式

就像框架必须使用框架格式创建一样，文本内容必须使用**字符格式**创建，该格式定义了文本的字体和对齐等属性。在我们开始向框架添加内容之前，我们应该定义一些常见的字符格式，以便在文档的不同部分使用。

这是使用`QTextCharFormat`类完成的，如下所示：

```py
        std_format = qtg.QTextCharFormat()

        logo_format = qtg.QTextCharFormat()
        logo_format.setFont(
            qtg.QFont('Impact', 24, qtg.QFont.DemiBold))
        logo_format.setUnderlineStyle(
            qtg.QTextCharFormat.SingleUnderline)
        logo_format.setVerticalAlignment(
            qtg.QTextCharFormat.AlignMiddle)

        label_format = qtg.QTextCharFormat()
        label_format.setFont(qtg.QFont('Sans', 12, qtg.QFont.Bold))
```

在前面的示例中，我们创建了以下三种格式：

+   `std_format`，将用于常规文本。我们不会改变默认设置。

+   `logo_format`，将用于我们的公司标志。我们正在自定义其字体并添加下划线，以及设置其垂直对齐。

+   `label_format`，将用于标签；它们将使用 12 号字体并加粗。

请注意，`QTextCharFormat`允许您直接使用 setter 方法进行许多字体配置，或者甚至可以配置一个`QFont`对象分配给格式。我们将在文档的其余部分添加文本内容时使用这三种格式。

# 添加基本内容

现在，让我们使用以下命令向我们的`logo_frame`添加一些基本内容：

```py
        cursor.setPosition(logo_frame.firstPosition())
```

就像我们调用根框架的`lastPosition`方法来获取其末尾的位置一样，我们可以调用标志框架的`firstPosition()`方法来获取框架开头的位置。一旦在那里，我们可以插入内容，比如标志图像，如下所示：

```py
        cursor.insertImage('nc_logo.png')
```

图片可以像这样插入——通过将图像的路径作为字符串传递。然而，这种方法在配置方面提供的内容很少，所以让我们尝试一种稍微复杂的方法：

```py
        logo_image_fmt = qtg.QTextImageFormat()
        logo_image_fmt.setName('nc_logo.png')
        logo_image_fmt.setHeight(48)
        cursor.insertImage(logo_image_fmt, qtg.QTextFrameFormat.FloatLeft)
```

通过使用`QTextImageFormat`对象，我们可以首先配置图像的各个方面，如其高度和宽度，然后将其添加到枚举常量指定其定位策略。在这种情况下，`FloatLeft`将导致图像与框架的左侧对齐，并且随后的文本将围绕它。

现在，让我们在块中写入以下文本：

```py
        cursor.insertText('   ')
        cursor.insertText('Ninja Coders, LLC', logo_format)
        cursor.insertBlock()
        cursor.insertText('123 N Wizard St, Yonkers, NY 10701', std_format)
```

使用我们的`logo_format`，我们已经编写了一个包含公司名称的文本片段，然后插入了一个新块，这样我们就可以在另一行上添加包含地址的另一个片段。请注意，传递字符格式是可选的；如果我们不这样做，片段将以当前活动格式插入，就像在文字处理器中一样。

处理完我们的标志后，现在让我们来处理客户地址块，如下所示：

```py
        cursor.setPosition(cust_addr_frame.lastPosition())
```

文本块可以像框架和字符一样具有格式。让我们使用以下代码创建一个文本块格式，用于我们的客户地址：

```py
        address_format = qtg.QTextBlockFormat()
        address_format.setAlignment(qtc.Qt.AlignRight)
        address_format.setRightMargin(25)
        address_format.setLineHeight(
            150, qtg.QTextBlockFormat.ProportionalHeight)
```

文本块格式允许您更改文本段落中更改的设置：边距、行高、缩进和对齐。在这里，我们将文本对齐设置为右对齐，右边距为 25 像素，行高为 1.5 行。在`QTextDocument`中有多种指定高度的方法，`setLineHeight()`的第二个参数决定了传入值的解释方式。在这种情况下，我们使用`ProportionalHeight`模式，它将传入的值解释为行高的百分比。

我们可以将我们的块格式对象传递给任何`insertBlock`调用，如下所示：

```py
        cursor.insertBlock(address_format)
        cursor.insertText('Customer:', label_format)
        cursor.insertBlock(address_format)
        cursor.insertText(data['c_name'], std_format)
        cursor.insertBlock(address_format)
        cursor.insertText(data['c_addr'])
```

每次插入一个块，就像开始一个新段落一样。我们的多行地址字符串将被插入为一个段落，但请注意，它仍将被间隔为 1.5 行。

# 插入列表

我们的发票条款将以无序项目列表的形式呈现。有序和无序列表可以使用光标的`insertList()`方法插入到`QTextDocument`中，如下所示：

```py
        cursor.setPosition(terms_frame.lastPosition())
        cursor.insertText('Terms:', label_format)
        cursor.insertList(qtg.QTextListFormat.ListDisc)
```

`insertList()`的参数可以是`QTextListFormat`对象，也可以是`QTextListFormat.Style`枚举中的常量。在这种情况下，我们使用了后者，指定我们希望使用圆盘样式的项目列表。

列表格式的其他选项包括`ListCircle`和`ListSquare`用于无序列表，以及`ListDecimal`、`ListLowerAlpha`、`ListUpperAlpha`、`ListUpperRoman`和`ListLowerRoman`用于有序列表。

现在，我们将定义要插入到我们的列表中的一些项目，如下所示：

```py
        term_items = (
            f'<b>Invoice dated:</b> {data["i_date"]}',
            f'<b>Invoice terms:</b> {data["i_terms"]}',
            f'<b>Invoice due:</b> {data["i_due"]}',
        )
```

请注意，在上面的示例中，我们使用的是标记，而不是原始字符串。在使用`QTextCursor`创建文档时，仍然可以使用标记；但是，您需要通过调用`insertHtml()`而不是`insertText()`来告诉光标它正在插入 HTML 而不是纯文本，如下例所示：

```py
        for i, item in enumerate(term_items):
            if i > 0:
                cursor.insertBlock()
            cursor.insertHtml(item)
```

在调用`insertList()`之后，我们的光标位于第一个列表项内，因此现在我们需要调用`insertBlock()`来到达后续项目（对于第一个项目，我们不需要这样做，因为我们已经处于项目符号中，因此需要进行`if i > 0`检查）。

与`insertText()`不同，`insertHtml()`不接受字符格式对象。您必须依靠您的标记来确定格式。

# 插入表格

我们要在发票中插入的最后一件事是包含我们的行项目的表格。`QTextTable`是`QTextFrame`的子类，就像框架一样，我们需要在创建表格本身之前为其创建格式对象。

我们需要的类是`QTextTableFormat`类：

```py
        table_format = qtg.QTextTableFormat()
        table_format.setHeaderRowCount(1)
        table_format.setWidth(
            qtg.QTextLength(qtg.QTextLength.PercentageLength, 100))
```

在这里，我们配置了`headerRowCount`属性，该属性表示第一行是标题行，并且应在每页顶部重复。这相当于在标记中将第一行放在`<thead>`标记中。

我们还设置了宽度，但是我们没有使用像素值，而是使用了`QTextLength`对象。这个类的命名有些令人困惑，因为它不是特指文本的长度，而是指您可能在`QTextDocument`中需要的任何通用长度。`QTextLength`对象可以是百分比、固定或可变类型；在这种情况下，我们指定了值为`100`或 100%的`PercentageLength`。

现在，让我们使用以下代码插入我们的表格：

```py
        headings = ('Job', 'Rate', 'Hours', 'Cost')
        num_rows = len(data['line_items']) + 1
        num_cols = len(headings)

        cursor.setPosition(line_items_frame.lastPosition())
        table = cursor.insertTable(num_rows, num_cols, table_format)
```

在将表格插入`QTextDocument`时，我们不仅需要定义格式，还需要指定行数和列数。为此，我们创建了标题的元组，然后通过计算行项目列表的长度（为标题行添加 1），以及标题元组的长度来计算行数和列数。

然后，我们需要将光标定位在行项目框中并插入我们的表格。就像其他插入方法一样，`insertTable()`将我们的光标定位在插入的项目内部，即第一行的第一列。

现在，我们可以使用以下代码插入我们的标题行：

```py
        for heading in headings:
            cursor.insertText(heading, label_format)
            cursor.movePosition(qtg.QTextCursor.NextCell)
```

到目前为止，我们一直通过将确切位置传递给`setPosition()`来定位光标。`QTextCursor`对象还具有`movePosition()`方法，该方法可以接受`QTextCursor.MoveOperation`枚举中的常量。该枚举定义了表示约两打不同光标移动的常量，例如`StartOfLine`、`PreviousBlock`和`NextWord`。在这种情况下，`NextCell`移动将我们带到表格中的下一个单元格。

我们可以使用相同的方法来插入我们的数据，如下所示：

```py
        for row in data['line_items']:
            for col, value in enumerate(row):
                text = f'${value}' if col in (1, 3) else f'{value}'
                cursor.insertText(text, std_format)
                cursor.movePosition(qtg.QTextCursor.NextCell)
```

在这种情况下，我们正在迭代数据列表中每一行的每一列，并使用`insertText()`将数据添加到单元格中。如果列号为`1`或`3`，即货币值，我们需要在显示中添加货币符号。

我们还需要添加一行来保存发票的总计。要在表格中添加额外的行，我们可以使用以下`QTextTable.appendRows()`方法：

```py
        table.appendRows(1)
```

为了将光标定位到新行中的特定单元格中，我们可以使用表对象的`cellAt()`方法来检索一个`QTableCell`对象，然后使用该对象的`lastCursorPosition()`方法，该方法返回一个位于单元格末尾的新光标，如下所示：

```py
        cursor = table.cellAt(num_rows, 0).lastCursorPosition()
        cursor.insertText('Total', label_format)
        cursor = table.cellAt(num_rows, 3).lastCursorPosition()
        cursor.insertText(f"${data['total_due']}", label_format)
```

这是我们需要写入发票文档的最后一部分内容，所以让我们继续测试一下。

# 完成和测试

现在，如果您运行您的应用程序，填写字段，然后点击创建发票，您应该会看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/79fad3bf-5ad0-4208-a822-82277ebe1785.png)

看起来不错！当然，如果我们无法打印或导出发票，那么这张发票对我们就没有什么用处。因此，在下一节中，我们将看看如何处理文档的打印。

# 打印富文本

没有什么能像被要求实现打印机支持那样让程序员心生恐惧。将原始的数字位转化为纸上的墨迹在现实生活中是混乱的，在软件世界中也可能一样混乱。幸运的是，Qt 提供了`QtPrintSupport`模块，这是一个跨平台的打印系统，可以轻松地将`QTextDocument`转换为硬拷贝格式，无论我们使用的是哪个操作系统。

# 更新发票应用程序以支持打印

在我们将文档的尺寸硬编码为 8.5×11 时，美国以外的读者几乎肯定会感到沮丧，但不要担心——我们将进行一些更改，以便根据用户选择的文档尺寸来设置尺寸。

在`InvoiceView`类中，创建以下新方法`set_page_size()`，以设置页面大小：

```py
    def set_page_size(self, qrect):
        self.doc_width = qrect.width()
        self.doc_height = qrect.height()
        self.setFixedSize(qtc.QSize(self.doc_width, self.doc_height))
        self.document().setPageSize(
            qtc.QSizeF(self.doc_width, self.doc_height))
```

该方法将接收一个`QRect`对象，从中提取宽度和高度值以更新文档的设置、小部件的固定大小和文档的页面大小。

在`MainWindow.__init__()`中，添加一个工具栏来控制打印，并设置以下操作：

```py
        print_tb = self.addToolBar('Printing')
        print_tb.addAction('Configure Printer', self.printer_config)
        print_tb.addAction('Print Preview', self.print_preview)
        print_tb.addAction('Print dialog', self.print_dialog)
        print_tb.addAction('Export PDF', self.export_pdf)
```

当我们设置每个打印过程的各个方面时，我们将实现这些回调。

# 配置打印机

打印始于一个`QtPrintSupport.QPrinter`对象，它代表内存中的打印文档。在 PyQt 中打印的基本工作流程如下：

1.  创建一个`QPrinter`对象

1.  使用其方法或打印机配置对话框配置`QPrinter`对象

1.  将`QTextDocument`打印到`QPrinter`对象

1.  将`QPrinter`对象传递给操作系统的打印对话框，用户可以使用物理打印机进行打印

在`MainWindow.__init__()`中，让我们创建我们的`QPrinter`对象，如下所示：

```py
        self.printer = qtps.QPrinter()
        self.printer.setOrientation(qtps.QPrinter.Portrait)
        self.printer.setPageSize(qtg.QPageSize(qtg.QPageSize.Letter))
```

打印机创建后，我们可以配置许多属性；在这里，我们只是设置了方向和页面大小（再次设置为美国信纸默认值，但可以随意更改为您喜欢的纸张大小）。

您可以通过`QPrinter`方法配置打印机设置对话框中的任何内容，但理想情况下，我们宁愿让用户做出这些决定。因此，让我们实现以下`printer_config()`方法：

```py
    def printer_config(self):
        dialog = qtps.QPageSetupDialog(self.printer, self)
        dialog.exec()
```

`QPageSetupDialog`对象是一个`QDialog`子类，显示了`QPrinter`对象可用的所有选项。我们将我们的`QPrinter`对象传递给它，这将导致对话框中所做的任何更改应用于该打印机对象。在 Windows 和 macOS 上，Qt 将默认使用操作系统提供的打印对话框；在其他平台上，将使用一个特定于 Qt 的对话框。

现在用户可以配置纸张大小，我们需要允许`InvoiceView`在每次更改后重置页面大小。因此，让我们在`MainWindow`中添加以下方法：

```py
    def _update_preview_size(self):
        self.preview.set_page_size(
            self.printer.pageRect(qtps.QPrinter.Point))
```

`QPrinter.pageRect()`方法提取了一个`QRect`对象，定义了配置的页面大小。由于我们的`InvoiceView.set_page_size()`方法接受一个`QRect`，我们只需要将这个对象传递给它。

请注意，我们已经将一个常量传递给`pageRect()`，表示我们希望以**点**为单位获取大小。点是英寸的 1/72，因此我们的小部件大小将是物理页面尺寸的 72 倍英寸。如果您想要自己计算以缩放小部件大小，您可以请求以各种单位（包括毫米、Picas、英寸等）获取页面矩形。

不幸的是，`QPrinter`对象不是`QObject`的后代，因此我们无法使用信号来确定其参数何时更改。

现在，在`printer_config()`的末尾添加对`self._update_preview_size()`的调用，这样每当用户配置页面时都会被调用。您会发现，如果您在打印机配置对话框中更改纸张的大小，您的预览小部件将相应地调整大小。

# 打印一页

在我们实际打印文档之前，我们必须首先将`QTextDocument`打印到`QPrinter`对象中。这是通过将打印机对象传递给文档的`print()`方法来完成的。

我们将创建以下方法来为我们执行这些操作：

```py
    def _print_document(self):
        self.preview.document().print(self.printer)
```

请注意，这实际上并不会导致您的打印设备开始在页面上放墨水-它只是将文档加载到`QPrinter`对象中。

要实际将其打印到纸张上，需要打印对话框；因此，在`MainView`中添加以下方法：

```py
    def print_dialog(self):
        self._print_document()
        dialog = qtps.QPrintDialog(self.printer, self)
        dialog.exec()
        self._update_preview_size()
```

在这个方法中，我们首先调用我们的内部方法将文档加载到`QPrinter`对象中，然后将对象传递给`QPrintDialog`对象，通过调用其`exec()`方法来执行。这将显示打印对话框，用户可以使用它将文档发送到物理打印机。

如果您不需要打印对话框来阻止程序执行，您可以调用其`open()`方法。在前面的示例中，我们正在阻止，以便在对话框关闭后执行操作。

对话框关闭后，我们调用`_update_preview_size()`来获取新的纸张大小并更新我们的小部件和文档。理论上，我们可以将对话框的`accepted`信号连接到该方法，但实际上，可能会出现一些竞争条件导致失败。

# 打印预览

没有人喜欢浪费纸张打印不正确的东西，所以我们应该添加一个`print_preview`函数。`QPrintPreviewDialog`就是为此目的而存在的，并且与其他打印对话框非常相似，如下所示：

```py
    def print_preview(self):
        dialog = qtps.QPrintPreviewDialog(self.printer, self)
        dialog.paintRequested.connect(self._print_document)
        dialog.exec()
        self._update_preview_size()
```

再次，我们只需要将打印机对象传递给对话框的构造函数并调用`exec()`。我们还需要将对话框的`paintRequested`信号连接到一个插槽，该插槽将更新`QPrinter`中的文档，以便对话框可以确保预览是最新的。在这里，我们将其连接到我们的`_print_document()`方法，该方法正是所需的。

# 导出为 PDF

在这个无纸化的数字时代，PDF 文件已经取代了许多用途的硬拷贝，因此，添加一个简单的导出到 PDF 功能总是一件好事。`QPrinter`可以轻松为我们做到这一点。

在`MainView`中添加以下`export_pdf()`方法：

```py
    def export_pdf(self):
        filename, _ = qtw.QFileDialog.getSaveFileName(
            self, "Save to PDF", qtc.QDir.homePath(), "PDF Files (*.pdf)")
        if filename:
            self.printer.setOutputFileName(filename)
            self.printer.setOutputFormat(qtps.QPrinter.PdfFormat)
            self._print_document()
```

在这里，我们将首先要求用户提供文件名。如果他们提供了文件名，我们将使用该文件名配置我们的`QPrinter`对象，将输出格式设置为`PdfFormat`，然后打印文档。在写入文件时，`QTextDocument.print()`将负责写入数据并为我们保存文件，因此我们在这里不需要做其他事情。

这涵盖了发票程序的所有打印需求！花些时间测试这个功能，看看它如何与您的打印机配合使用。

# 总结

在本章中，您掌握了在 PyQt5 中处理富文本文档的方法。您学会了如何使用 Qt 的 HTML 子集在`QLabel`、`QTextEdit`和`QTextBrowser`小部件中添加富文本格式。您通过使用`QTextCursor`接口编程方式构建了`QTextDocument`。最后，您学会了如何使用 Qt 的打印支持模块将`QTextDocument`对象带入现实世界。

在第十二章中，*使用 QPainter 创建 2D 图形*，你将学习一些二维图形的高级概念。你将学会如何使用`QPainter`对象来创建图形，构建自定义小部件，并创建动画。

# 问题

尝试使用这些问题来测试你对本章的了解：

1.  以下 HTML 显示的不如你希望的那样。找出尽可能多的错误：

```py
<table>
<thead background=#EFE><th>Job</th><th>Status</th></thead>
<tr><td>Backup</td>
<font text-color='green'>Success!</font></td></tr>
<tr><td>Cleanup<td><font text-style='bold'>Fail!</font></td></tr>
</table>
```

1.  以下 Qt HTML 代码有什么问题？

```py
<p>There is nothing <i>wrong</i> with your television <b>set</p></b>
<table><row><data>french fries</data>
<data>$1.99</data></row></table>
<font family='Tahoma' color='#235499'>Can you feel the <strikethrough>love</strikethrough>code tonight?</font>
<label>Username</label><input type='text' name='username'></input>
<img source='://mypix.png'>My picture</img>
```

1.  这段代码应该实现一个目录。为什么它不能正确工作？

```py
   <ul>
     <li><a href='Section1'>Section 1</a></li>
     <li><a href='Section2'>Section 2</a></li>
   </ul>
   <div id=Section1>
     <p>This is section 1</p>
   </div>
   <div id=Section2>
     <p>This is section 2</p>
   </div>
```

1.  使用`QTextCursor`，在文档的右侧添加一个侧边栏。解释一下你会如何做到这一点。

1.  你正在尝试使用`QTextCursor`创建一个文档。它应该有一个顶部和底部的框架；在顶部框架中应该有一个标题，在底部框架中应该有一个无序列表。请纠正以下代码，使其实现这一点：

```py
   document = qtg.QTextDocument()
   cursor = qtg.QTextCursor(document)
   top_frame = cursor.insertFrame(qtg.QTextFrameFormat())
   bottom_frame = cursor.insertFrame(qtg.QTextFrameFormat())

   cursor.insertText('This is the title')
   cursor.movePosition(qtg.QTextCursor.NextBlock)
   cursor.insertList(qtg.QTextListFormat())
   for item in ('thing 1', 'thing 2', 'thing 3'):
       cursor.insertText(item)
```

1.  你正在创建自己的`QPrinter`子类以在页面大小更改时添加一个信号。以下代码会起作用吗？

```py
   class MyPrinter(qtps.QPrinter):

       page_size_changed = qtc.pyqtSignal(qtg.QPageSize)

       def setPageSize(self, size):
           super().setPageSize(size)
           self.page_size_changed.emit(size)
```

1.  `QtPrintSupport`包含一个名为`QPrinterInfo`的类。使用这个类，在你的系统上打印出所有打印机的名称、制造商、型号和默认页面大小的列表。

# 进一步阅读

有关更多信息，请参考以下链接：

+   Qt 对 Scribe 框架的概述可以在[`doc.qt.io/qt-5/richtext.html`](https://doc.qt.io/qt-5/richtext.html)找到

+   可以使用`QAbstractTextDocumentLayout`和`QTextLine`类来定义高级文档布局；关于如何使用这些类的信息可以在[`doc.qt.io/qt-5/richtext-layouts.html`](https://doc.qt.io/qt-5/richtext-layouts.html)找到

+   Qt 的打印系统概述可以在[`doc.qt.io/qt-5/qtprintsupport-index.html`](https://doc.qt.io/qt-5/qtprintsupport-index.html)找到


# 第十二章：使用`QPainter`创建 2D 图形

我们已经看到 Qt 提供了大量的小部件，具有广泛的样式和自定义功能。然而，有时我们需要直接控制屏幕上的绘制内容；例如，我们可能想要编辑图像，创建一个独特的小部件，或者构建一个交互式动画。在所有这些任务的核心是 Qt 中一个谦卑而勤奋的对象，称为`QPainter`。

在本章中，我们将在三个部分中探索 Qt 的**二维**（**2D**）图形功能：

+   使用`QPainter`进行图像编辑

+   使用`QPainter`创建自定义小部件

+   使用`QGraphicsScene`动画 2D 图形

# 技术要求

本章需要基本的 Python 和 PyQt5 设置，这是您在整本书中一直在使用的。您可能还希望从[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter12`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter12)下载示例代码。

您还需要`psutil`库，可以使用以下命令从 PyPI 安装：

```py
$ pip install --user psutil
```

最后，有一些图像在手边会很有帮助，您可以用它们作为示例数据。

查看以下视频以查看代码的运行情况：[`bit.ly/2M5xzlL`](http://bit.ly/2M5xzlL)

# 使用`QPainter`进行图像编辑

在 Qt 中，可以使用`QPainter`对象在`QImage`对象上绘制图像。在第六章中，*Qt 应用程序的样式*，您了解了`QPixmap`对象，它是一个表示图形图像的显示优化对象。`QImage`对象是一个类似的对象，它针对编辑而不是显示进行了优化。为了演示如何使用`QPainter`在`QImage`对象上绘制图像，我们将构建一个经典的表情包生成器应用程序。

# 生成表情包的图形用户界面

从第四章中创建 Qt 应用程序模板的副本，*使用 QMainWindow 构建应用程序*，并将其命名为`meme_gen.py`。我们将首先构建用于表情包生成器的 GUI 表单。

# 编辑表单

在创建实际表单之前，我们将通过创建一些自定义按钮类稍微简化我们的代码：一个用于设置颜色的`ColorButton`类，一个用于设置字体的`FontButton`类，以及一个用于选择图像的`ImageFileButton`类。

`ColorButton`类的开始如下：

```py
class ColorButton(qtw.QPushButton):

   changed = qtc.pyqtSignal()

    def __init__(self, default_color, changed=None):
        super().__init__()
        self.set_color(qtg.QColor(default_color))
        self.clicked.connect(self.on_click)
        if changed:
            self.changed.connect(changed)
```

这个按钮继承自`QPushButton`，但做了一些改动。我们定义了一个`changed`信号来跟踪按钮值的变化，并添加了一个关键字选项，以便可以像内置信号一样使用关键字连接这个信号。

我们还添加了指定默认颜色的功能，该颜色将传递给`set_color`方法：

```py
    def set_color(self, color):
        self._color = color
        pixmap = qtg.QPixmap(32, 32)
        pixmap.fill(self._color)
        self.setIcon(qtg.QIcon(pixmap))
```

这种方法将传递的颜色值存储在实例变量中，然后生成给定颜色的`pixmap`对象，用作按钮图标（我们在第六章中看到了这种技术，*Qt 应用程序的样式*）。

按钮的`clicked`信号连接到`on_click()`方法：

```py
    def on_click(self):
        color = qtw.QColorDialog.getColor(self._color)
        if color:
            self.set_color(color)
            self.changed.emit()
```

这种方法打开`QColorDialog`，允许用户选择颜色，并且如果选择了颜色，则设置其颜色并发出`changed`信号。

`FontButton`类将与前一个类几乎相同：

```py
class FontButton(qtw.QPushButton):

    changed = qtc.pyqtSignal()

    def __init__(self, default_family, default_size, changed=None):
        super().__init__()
        self.set_font(qtg.QFont(default_family, default_size))
        self.clicked.connect(self.on_click)
        if changed:
            self.changed.connect(changed)

    def set_font(self, font):
        self._font = font
        self.setFont(font)
        self.setText(f'{font.family()} {font.pointSize()}')
```

与颜色按钮类似，它定义了一个可以通过关键字连接的`changed`信号。它采用默认的字体和大小，用于生成存储在按钮的`_font`属性中的默认`QFont`对象，使用`set_font()`方法。

`set_font()`方法还会更改按钮的字体和文本为所选的字体和大小。

最后，`on_click()`方法处理按钮点击：

```py
    def on_click(self):
        font, accepted = qtw.QFontDialog.getFont(self._font)
        if accepted:
            self.set_font(font)
            self.changed.emit()
```

与颜色按钮类似，我们显示一个`QFontDialog`对话框，并且如果用户选择了字体，则相应地设置按钮的字体。

最后，`ImageFileButton`类将与前两个类非常相似：

```py
class ImageFileButton(qtw.QPushButton):

    changed = qtc.pyqtSignal()

    def __init__(self, changed=None):
        super().__init__("Click to select…")
        self._filename = None
        self.clicked.connect(self.on_click)
        if changed:
            self.changed.connect(changed)

    def on_click(self):
        filename, _ = qtw.QFileDialog.getOpenFileName(
            None, "Select an image to use",
            qtc.QDir.homePath(), "Images (*.png *.xpm *.jpg)")
        if filename:
            self._filename = filename
            self.setText(qtc.QFileInfo(filename).fileName())
            self.changed.emit()
```

唯一的区别是对话框现在是一个`getOpenFileName`对话框，允许用户选择 PNG、XPM 或 JPEG 文件。

`QImage`实际上可以处理各种各样的图像文件。您可以在[`doc.qt.io/qt-5/qimage.html#reading-and-writing-image-files`](https://doc.qt.io/qt-5/qimage.html#reading-and-writing-image-files)找到这些信息，或者调用`QImageReader.supportedImageFormats()`。出于简洁起见，我们在这里缩短了列表。

现在这些类已经创建，让我们为编辑表情包属性构建一个表单：

```py
class MemeEditForm(qtw.QWidget):

    changed = qtc.pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.setLayout(qtw.QFormLayout())
```

这个表单将与我们在之前章节中创建的表单非常相似，但是，与其在表单提交时使用`submitted`信号不同，`changed`信号将在任何表单项更改时触发。这将允许我们实时显示任何更改，而不需要按按钮。

我们的第一个控件将是设置源图像的文件名：

```py
        self.image_source = ImageFileButton(changed=self.on_change)
        self.layout().addRow('Image file', self.image_source)
```

我们将把每个小部件的`changed`信号（或类似的信号）链接到一个名为`on_change()`的方法上，该方法将收集表单中的数据并发射`MemeEditForm`的`changed`信号。

不过，首先让我们添加字段来控制文本本身：

```py
        self.top_text = qtw.QPlainTextEdit(textChanged=self.on_change)
        self.bottom_text = qtw.QPlainTextEdit(textChanged=self.on_change)
        self.layout().addRow("Top Text", self.top_text)
        self.layout().addRow("Bottom Text", self.bottom_text)
        self.text_color = ColorButton('white', changed=self.on_change)
        self.layout().addRow("Text Color", self.text_color)
        self.text_font = FontButton('Impact', 32, changed=self.on_change)
        self.layout().addRow("Text Font", self.text_font)
```

我们的表情包将在图像的顶部和底部分别绘制文本，并且我们使用了`ColorButton`和`FontButton`类来创建文本颜色和字体的输入。再次，我们将每个小部件的适当`changed`信号连接到一个`on_changed()`实例方法。

让我们通过添加控件来绘制文本的背景框来完成表单 GUI：

```py
        self.text_bg_color = ColorButton('black', changed=self.on_change)
        self.layout().addRow('Text Background', self.text_bg_color)
        self.top_bg_height = qtw.QSpinBox(
            minimum=0, maximum=32,
            valueChanged=self.on_change, suffix=' line(s)')
        self.layout().addRow('Top BG height', self.top_bg_height)
        self.bottom_bg_height = qtw.QSpinBox(
            minimum=0, maximum=32,
            valueChanged=self.on_change, suffix=' line(s)')
        self.layout().addRow('Bottom BG height', self.bottom_bg_height)
        self.bg_padding = qtw.QSpinBox(
            minimum=0, maximum=100, value=10,
            valueChanged=self.on_change, suffix=' px')
        self.layout().addRow('BG Padding', self.bg_padding)
```

这些字段允许用户在图像太丰富而无法阅读时在文本后面添加不透明的背景。控件允许您更改顶部和底部背景的行数、框的颜色和填充。

这样就处理了表单布局，现在我们来处理`on_change()`方法：

```py
    def get_data(self):
        return {
            'image_source': self.image_source._filename,
            'top_text': self.top_text.toPlainText(),
            'bottom_text': self.bottom_text.toPlainText(),
            'text_color': self.text_color._color,
            'text_font': self.text_font._font,
            'bg_color': self.text_bg_color._color,
            'top_bg_height': self.top_bg_height.value(),
            'bottom_bg_height': self.bottom_bg_height.value(),
            'bg_padding': self.bg_padding.value()
        }

    def on_change(self):
        self.changed.emit(self.get_data())
```

首先，我们定义了一个`get_data()`方法，该方法从表单的小部件中组装一个值的`dict`对象并返回它们。如果我们需要显式地从表单中提取数据，而不是依赖信号，这将非常有用。`on_change()`方法检索这个`dict`对象并用`changed`信号发射它。

# 主 GUI

创建了表单小部件后，现在让我们组装我们的主 GUI。

让我们从`MainView.__init__()`开始：

```py
        self.setWindowTitle('Qt Meme Generator')
        self.max_size = qtc.QSize(800, 600)
        self.image = qtg.QImage(
            self.max_size, qtg.QImage.Format_ARGB32)
        self.image.fill(qtg.QColor('black'))
```

我们将从设置窗口标题开始，然后定义生成的表情包图像的最大尺寸。我们将使用这个尺寸来创建我们的`QImage`对象。由于在程序启动时我们没有图像文件，所以我们将生成一个最大尺寸的黑色占位图像，使用`fill()`方法来实现，就像我们用像素图一样。然而，当创建一个空白的`QImage`对象时，我们需要指定一个图像格式来用于生成的图像。在这种情况下，我们使用 ARGB32 格式，可以用于制作具有透明度的全彩图像。

在创建主 GUI 布局时，我们将使用这个图像：

```py
        mainwidget = qtw.QWidget()
        self.setCentralWidget(mainwidget)
        mainwidget.setLayout(qtw.QHBoxLayout())
        self.image_display = qtw.QLabel(pixmap=qtg.QPixmap(self.image))
        mainwidget.layout().addWidget(self.image_display)
        self.form = MemeTextForm()
        mainwidget.layout().addWidget(self.form)
        self.form.changed.connect(self.build_image)
```

这个 GUI 是一个简单的两面板布局，左边是一个`QLabel`对象，用于显示我们的表情包图像，右边是用于编辑的`MemeTextForm()`方法。我们将表单的`changed`信号连接到一个名为`build_image()`的`MainWindow`方法，其中包含我们的主要绘图逻辑。请注意，我们不能直接在`QLabel`对象中显示`QImage`对象；我们必须先将其转换为`QPixmap`对象。

# 使用 QImage 进行绘制

既然我们的 GUI 已经准备好了，现在是时候创建`MainView.build_image()`了。这个方法将包含所有的图像处理和绘制方法。

我们将从添加以下代码开始：

```py
    def build_image(self, data):
        if not data.get('image_source'):
            self.image.fill(qtg.QColor('black'))
        else:
            self.image.load(data.get('image_source'))
            if not (self.max_size - self.image.size()).isValid():
                # isValid returns false if either dimension is negative
                self.image = self.image.scaled(
                    self.max_size, qtc.Qt.KeepAspectRatio)
```

我们的第一个任务是设置我们的表情包的基本图像。如果在表单数据中没有 `image_source` 值，那么我们将用黑色填充我们的 `QImage` 对象，为我们的绘图提供一个空白画布。如果我们有图像来源，那么我们可以通过将其文件路径传递给 `QImage.load()` 来加载所选图像。如果我们加载的图像大于最大尺寸，我们将希望将其缩小，使其小于最大宽度和高度，同时保持相同的纵横比。

检查图像在任一维度上是否太大的一种快速方法是从最大尺寸中减去它的尺寸。如果宽度或高度大于最大值，则其中一个维度将为负，这使得减法表达式产生的 `QSize` 对象无效。

`QImage.scaled()` 方法将返回一个新的 `QImage` 对象，该对象已经按照提供的 `QSize` 对象进行了缩放。通过指定 `KeepAspectRatio`，我们的宽度和高度将分别进行缩放，以使结果大小与原始大小具有相同的纵横比。

现在我们有了我们的图像，我们可以开始在上面绘画。

# `QPainter` 对象

最后，让我们来认识一下 `QPainter` 类！`QPainter` 可以被认为是屏幕内部的一个小机器人，我们可以为它提供一个画笔和一个笔，然后发出绘图命令。

让我们创建我们的绘画“机器人”：

```py
        painter = qtg.QPainter(self.image)
```

绘图者的构造函数接收一个它将绘制的对象的引用。要绘制的对象必须是 `QPaintDevice` 的子类；在这种情况下，我们传递了一个 `QImage` 对象，它是这样一个类。传递的对象将成为绘图者的画布，在这个画布上，当我们发出绘图命令时，绘图者将进行绘制。

为了了解基本绘画是如何工作的，让我们从顶部和底部的背景块开始。我们首先要弄清楚我们需要绘制的矩形的边界：

```py
        font_px = qtg.QFontInfo(data['text_font']).pixelSize()
        top_px = (data['top_bg_height'] * font_px) + data['bg_padding']
        top_block_rect = qtc.QRect(
            0, 0, self.image.width(), top_px)
        bottom_px = (
            self.image.height() - data['bg_padding']
            - (data['bottom_bg_height'] * font_px))
        bottom_block_rect = qtc.QRect(
            0, bottom_px, self.image.width(), self.image.height())
```

`QPainter` 使用的坐标从绘画表面的左上角开始。因此，坐标 `(0, 0)` 是屏幕的左上角，而 `(width, height)` 将是屏幕的右下角。

为了计算我们顶部矩形的高度，我们将所需行数乘以我们选择的字体的像素高度（我们从 `QFontInfo` 中获取），最后加上填充量。我们最终得到一个从原点(`(0, 0)`)开始并在框的图像的完整宽度和高度处结束的矩形。这些坐标用于创建一个表示框区域的 `QRect` 对象。

对于底部的框，我们需要从图像的底部计算；这意味着我们必须首先计算矩形的高度，然后从框的高度中*减去*它。然后，我们构造一个从左侧开始并延伸到右下角的矩形。

`QRect` 坐标必须始终从左上到右下定义。

现在我们有了我们的矩形，让我们来绘制它们：

```py
        painter.setBrush(qtg.QBrush(data['bg_color']))
        painter.drawRect(top_block_rect)
        painter.drawRect(bottom_block_rect)
```

`QPainter` 有许多用于创建线条、圆圈、多边形和其他形状的绘图函数。在这种情况下，我们使用 `drawRect()`，它用于绘制矩形。为了定义这个矩形的填充，我们将绘图者的 `brush` 属性设置为一个 `QBrush` 对象，该对象设置为我们选择的背景颜色。绘图者的 `brush` 值决定了它将用什么颜色和图案来填充任何形状。

除了 `drawRect()`，`QPainter` 还包含一些其他绘图方法，如下所示：

| 方法 | 用于绘制 |
| --- | --- |
| `drawEllipse()` | 圆和椭圆 |
| `drawLine()` | 直线 |
| `drawRoundedRect()` | 带有圆角的矩形 |
| `drawPolygon()` | 任何类型的多边形 |
| `drawPixmap()` | `QPixmap` 对象 |
| `drawText()` | 文本 |

为了将我们的表情包文本放在图像上，我们需要使用 `drawText()`：

```py
        painter.setPen(data['text_color'])
        painter.setFont(data['text_font'])
        flags = qtc.Qt.AlignHCenter | qtc.Qt.TextWordWrap
        painter.drawText(
            self.image.rect(), flags | qtc.Qt.AlignTop, data['top_text'])
        painter.drawText(
            self.image.rect(), flags | qtc.Qt.AlignBottom,
            data['bottom_text'])
```

在绘制文本之前，我们需要给画家一个`QPen`对象来定义文本颜色，并给一个`QFont`对象来定义所使用的字体。画家的`QPen`确定了画家绘制的文本、形状轮廓、线条和点的颜色。

为了控制文本在图像上的绘制位置，我们可以使用`drawText()`的第一个参数，它是一个`QRect`对象，用于定义文本的边界框。然而，由于我们不知道我们要处理多少行文本，我们将使用整个图像作为边界框，并使用垂直对齐来确定文本是在顶部还是底部写入。

使用`QtCore.Qt.TextFlag`和`QtCore.Qt.AlignmentFlag`枚举的标志值来配置对齐和自动换行等行为。在这种情况下，我们为顶部和底部文本指定了居中对齐和自动换行，然后在`drawText()`调用中添加了垂直对齐选项。

`drawText()`的最后一个参数是实际的文本，我们从我们的`dict`数据中提取出来。

现在我们已经绘制了文本，我们需要做的最后一件事是在图像显示标签中设置图像：

```py
        self.image_display.setPixmap(qtg.QPixmap(self.image))
```

在这一点上，你应该能够启动程序并创建一个图像。试试看吧！

# 保存我们的图像

创建一个时髦的迷因图像后，我们的用户可能想要保存它，以便他们可以将其上传到他们最喜欢的社交媒体网站。为了实现这一点，让我们回到`MainWindow.__init_()`并创建一个工具栏：

```py
        toolbar = self.addToolBar('File')
        toolbar.addAction("Save Image", self.save_image)
```

当然，你也可以使用菜单选项或其他小部件来做到这一点。无论如何，我们需要定义由此操作调用的`save_image()`方法：

```py
    def save_image(self):
        save_file, _ = qtw.QFileDialog.getSaveFileName(
            None, "Save your image",
            qtc.QDir.homePath(), "PNG Images (*.png)")
        if save_file:
            self.image.save(save_file, "PNG")
```

要将`QImage`文件保存到磁盘，我们需要使用文件路径字符串和第二个字符串定义图像格式调用其`save()`方法。在这种情况下，我们将使用`QFileDialog.getSaveFileName()`来检索保存位置，并以`PNG`格式保存。

如果你运行你的迷因生成器，你应该会发现它看起来像下面的截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/ce619532-1f47-4b59-bcbf-e28f4e9401a2.png)

作为额外的练习，尝试想出一些其他你想在迷因上绘制的东西，并将这个功能添加到代码中。

# 使用 QPainter 创建自定义小部件

`QPainter`不仅仅是一个专门用于在图像上绘制的工具；它实际上是为 Qt 中所有小部件绘制所有图形的工作马。换句话说，你在 PyQt 应用程序中看到的每个小部件的每个像素都是由`QPainter`对象绘制的。我们可以控制`QPainter`来创建一个纯自定义的小部件。

为了探索这个想法，让我们创建一个 CPU 监视器应用程序。获取 Qt 应用程序模板的最新副本，将其命名为`cpu_graph.py`，然后我们将开始。

# 构建一个 GraphWidget

我们的 CPU 监视器将使用区域图显示实时 CPU 活动。图表将通过颜色渐变进行增强，高值将以不同颜色显示，低值将以不同颜色显示。图表一次只显示配置数量的值，随着从右侧添加新值，旧值将滚动到小部件的左侧。

为了实现这一点，我们需要构建一个自定义小部件。我们将其命名为`GraphWidget`，并开始如下：

```py
class GraphWidget(qtw.QWidget):
    """A widget to display a running graph of information"""

    crit_color = qtg.QColor(255, 0, 0)  # red
    warn_color = qtg.QColor(255, 255, 0)  # yellow
    good_color = qtg.QColor(0, 255, 0)  # green

    def __init__(
        self, *args, data_width=20,
        minimum=0, maximum=100,
        warn_val=50, crit_val=75, scale=10,
        **kwargs
    ):
        super().__init__(*args, **kwargs)
```

自定义小部件从一些类属性开始，用于定义*good*、*warning*和*critical*值的颜色。如果你愿意，可以随意更改这些值。

我们的构造函数接受一些关键字参数，如下所示：

+   `data_width`：这指的是一次将显示多少个值

+   `minimum`和`maximum`：要显示的最小和最大值

+   `warn_val`和`crit_val`：这些是颜色变化的阈值值

+   `Scale`：这指的是每个数据点将使用多少像素

我们的下一步是将所有这些值保存为实例属性：

```py
        self.minimum = minimum
        self.maximum = maximum
        self.warn_val = warn_val
        self.scale = scale
        self.crit_val = crit_val
```

为了存储我们的值，我们需要类似 Python `list`的东西，但受限于固定数量的项目。Python 的`collections`模块为此提供了完美的对象：`deque`类。

让我们在代码块的顶部导入这个类：

```py
from collections import deque
```

`deque`类可以接受一个`maxlen`参数，这将限制其长度。当新项目附加到`deque`类时，将其推到其`maxlen`值之外，旧项目将从列表的开头删除，以使其保持在限制之下。这对于我们的图表非常完美，因为我们只想在图表中同时显示固定数量的数据点。

我们将创建我们的`deque`类如下：

```py
        self.values = deque([self.minimum] * data_width, maxlen=data_width)
        self.setFixedWidth(data_width * scale)
```

`deque`可以接受一个`list`作为参数，该参数将用于初始化其数据。在这种情况下，我们使用一个包含最小值的`data_width`项的`list`进行初始化，并将`deque`类的`maxlen`值设置为`data_width`。

您可以通过将包含 1 个项目的列表乘以*N*在 Python 中快速创建*N*个项目的列表，就像我们在这里所做的那样；例如，`[2] * 4`将创建一个列表`[2, 2, 2, 2]`。

我们通过将小部件的固定宽度设置为`data_width * scale`来完成`__init__()`方法，这代表了我们想要显示的总像素数。

接下来，我们需要一个方法来向我们的`deque`类添加一个新值，我们将其称为`add_value()`：

```py
    def add_value(self, value):
        value = max(value, self.minimum)
        value = min(value, self.maximum)
        self.values.append(value)
        self.update()
```

该方法首先通过将我们的值限制在最小值和最大值之间，然后将其附加到`deque`对象上。这还有一个额外的效果，即将`deque`对象的开头弹出第一项，使其保持在`data_width`值。

最后，我们调用`update()`，这是一个`QWidget`方法，告诉小部件重新绘制自己。我们将在下一步处理这个绘图过程。

# 绘制小部件

`QWidget`类，就像`QImage`一样，是`QPaintDevice`的子类；因此，我们可以使用`QPainter`对象直接在小部件上绘制。当小部件收到重新绘制自己的请求时（类似于我们发出`update()`的方式），它调用其`paintEvent()`方法。我们可以用我们自己的绘图命令覆盖这个方法，为我们的小部件定义一个自定义外观。

让我们按照以下方式开始该方法：

```py
    def paintEvent(self, paint_event):
        painter = qtg.QPainter(self)
```

`paintEvent()`将被调用一个参数，一个`QPaintEvent`对象。这个对象包含有关请求重绘的事件的信息 - 最重要的是，需要重绘的区域和矩形。对于复杂的小部件，我们可以使用这些信息来仅重绘请求的部分。对于我们简单的小部件，我们将忽略这些信息，只重绘整个小部件。

我们定义了一个指向小部件本身的画家对象，因此我们向画家发出的任何命令都将在我们的小部件上绘制。让我们首先创建一个背景：

```py
        brush = qtg.QBrush(qtg.QColor(48, 48, 48))
        painter.setBrush(brush)
        painter.drawRect(0, 0, self.width(), self.height())
```

就像我们在我们的模因生成器中所做的那样，我们正在定义一个画刷，将其给我们的画家，并画一个矩形。

请注意，我们在这里使用了`drawRect()`的另一种形式，它直接取坐标而不是`QRect`对象。`QPainter`对象的许多绘图函数都有取稍微不同类型参数的替代版本，以增加灵活性。

接下来，让我们画一些虚线，显示警告和临界的阈值在哪里。为此，我们需要将原始数据值转换为小部件上的*y*坐标。由于这将经常发生，让我们创建一个方便的方法来将值转换为*y*坐标：

```py
    def val_to_y(self, value):
        data_range = self.maximum - self.minimum
        value_fraction = value / data_range
        y_offset = round(value_fraction * self.height())
        y = self.height() - y_offset
        return y
```

要将值转换为*y*坐标，我们首先需要确定值代表数据范围的什么比例。然后，我们将该分数乘以小部件的高度，以确定它应该离小部件底部多少像素。然后，因为像素坐标从顶部开始计数*向下*，我们必须从小部件的高度中减去我们的偏移量，以确定*y*坐标。

回到`paintEvent()`，让我们使用这个方法来画一个警告阈值线：

```py
        pen = qtg.QPen()
        pen.setDashPattern([1, 0])
        warn_y = self.val_to_y(self.warn_val)
        pen.setColor(self.warn_color)
        painter.setPen(pen)
        painter.drawLine(0, warn_y, self.width(), warn_y)
```

由于我们正在绘制一条线，我们需要设置绘图者的`pen`属性。`QPen.setDashPattern()`方法允许我们通过向其传递`1`和`0`值的列表来为线定义虚线模式，表示绘制或未绘制的像素。在这种情况下，我们的模式将在绘制像素和空像素之间交替。

创建了笔之后，我们使用我们的新转换方法将`warn_val`值转换为*y*坐标，并将笔的颜色设置为`warn_color`。我们将配置好的笔交给我们的绘图者，并指示它在我们计算出的*y*坐标处横跨小部件的宽度绘制一条线。

同样的方法可以用来绘制我们的临界阈值线：

```py
        crit_y = self.val_to_y(self.crit_val)
        pen.setColor(self.crit_color)
        painter.setPen(pen)
        painter.drawLine(0, crit_y, self.width(), crit_y)
```

我们可以重用我们的`QPen`对象，但请记住，每当我们对笔或刷子进行更改时，我们都必须重新分配给绘图者。绘图者传递了笔或刷子的副本，因此我们对对象进行的更改*在*分配给绘图者之后不会隐式传递给使用的笔或刷子。

在第六章中，*Qt 应用程序的样式*，您学习了如何创建一个渐变对象并将其应用于`QBrush`对象。在这个应用程序中，我们希望使用渐变来绘制我们的数据值，使得高值在顶部为红色，中等值为黄色，低值为绿色。

让我们定义一个`QLinearGradient`渐变对象如下：

```py
        gradient = qtg.QLinearGradient(
            qtc.QPointF(0, self.height()), qtc.QPointF(0, 0))
```

这个渐变将从小部件的底部（`self.height()`）到顶部（`0`）进行。这一点很重要要记住，因为在定义颜色停止时，`0`位置表示渐变的开始（即小部件的底部），`1`位置将表示渐变的结束（即顶部）。

我们将设置我们的颜色停止如下：

```py
        gradient.setColorAt(0, self.good_color)
        gradient.setColorAt(
            self.warn_val/(self.maximum - self.minimum),
            self.warn_color)
        gradient.setColorAt(
            self.crit_val/(self.maximum - self.minimum),
            self.crit_color)
```

类似于我们计算*y*坐标的方式，在这里，我们通过将警告和临界值除以最小值和最大值之间的差来确定数据范围表示的警告和临界值的分数。这个分数是`setColorAt()`需要的第一个参数。

现在我们有了一个渐变，让我们为绘制数据设置我们的绘图者：

```py
        brush = qtg.QBrush(gradient)
        painter.setBrush(brush)
        painter.setPen(qtc.Qt.NoPen)
```

为了使我们的面积图看起来平滑和连贯，我们不希望图表部分有任何轮廓。为了阻止`QPainter`勾勒形状，我们将我们的笔设置为一个特殊的常数：`QtCore.Qt.NoPen`。

为了创建我们的面积图，每个数据点将由一个四边形表示，其中右上角将是当前数据点，左上角将是上一个数据点。宽度将等于我们在构造函数中设置的`scale`属性。

由于我们将需要每个数据点的*上一个*值，我们需要从一点开始进行一些簿记：

```py
        self.start_value = getattr(self, 'start_value', self.minimum)
        last_value = self.start_value
        self.start_value = self.values[0]
```

我们需要做的第一件事是确定一个起始值。由于我们需要在当前值*之前*有一个值，我们的第一项需要一个开始绘制的地方。我们将创建一个名为`start_value`的实例变量，它在`paintEvent`调用之间保持不变，并存储初始值。然后，我们将其赋值给`last_value`，这是一个本地变量，将用于记住循环的每次迭代的上一个值。最后，我们将起始值更新为`deque`对象的第一个值，以便*下一次*调用`paintEvent`。

现在，让我们开始循环遍历数据并计算每个点的`x`和`y`值：

```py
        for indx, value in enumerate(self.values):
            x = (indx + 1) * self.scale
            last_x = indx * self.scale
            y = self.val_to_y(value)
            last_y = self.val_to_y(last_value)
```

多边形的两个*x*坐标将是（1）值的索引乘以比例，和（2）比例乘以值的索引加一。对于*y*值，我们将当前值和上一个值传递给我们的转换方法。这四个值将使我们能够绘制一个四边形，表示从一个数据点到下一个数据点的变化。

要绘制该形状，我们将使用一个称为`QPainterPath`的对象。在数字图形中，**路径**是由单独的线段或形状组合在一起构建的对象。`QPainterPath`对象允许我们通过在代码中逐个绘制每一边来创建一个独特的形状。

接下来，让我们使用我们计算出的`x`和`y`数据开始绘制我们的路径对象：

```py
            path = qtg.QPainterPath()
            path.moveTo(x, self.height())
            path.lineTo(last_x, self.height())
            path.lineTo(last_x, last_y)
            path.lineTo(x, y)
```

要绘制路径，我们首先创建一个`QPainterPath`对象。然后我们使用它的`moveTo()`方法设置绘制的起始点。然后我们使用`lineTo()`方法连接路径的四个角，以在点之间绘制一条直线。最后一个连接我们的结束点和起始点是自动完成的。

请注意，此时我们实际上并没有在屏幕上绘制；我们只是在定义一个对象，我们的绘图器可以使用其当前的画笔和笔将其绘制到屏幕上。

让我们绘制这个对象：

```py
            painter.drawPath(path)
            last_value = value
```

我们通过绘制路径和更新最后一个值到当前值来完成了这个方法。当然，这条由直线组成的路径相当乏味——我们本可以只使用绘图器的`drawPolygon()`方法。使用`QPainterPath`对象的真正威力在于利用它的非线性绘制方法。

例如，如果我们希望我们的图表是平滑和圆润的，而不是锯齿状的，那么我们可以使用**立方贝塞尔曲线**来绘制最后一条线（即形状的顶部），而不是直线：

```py
            #path.lineTo(x, y)
            c_x = round(self.scale * .5) + last_x
            c1 = (c_x, last_y)
            c2 = (c_x, y)
            path.cubicTo(*c1, *c2, x, y)
```

贝塞尔曲线使用两个控制点来定义其曲线。每个控制点都会将线段拉向它自己——第一个控制点拉动线段的前半部分，第二个控制点拉动线段的后半部分：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/004dbd50-bd0b-40cc-8967-020135f4a640.png)

我们将第一个控制点设置为最后的 y 值，将第二个控制点设置为当前的 y 值——这两个值都是开始和结束 x 值的中间值。这给我们在上升斜坡上一个 S 形曲线，在下降斜坡上一个反 S 形曲线，从而产生更柔和的峰值和谷值。

在应用程序中设置`GraphWidget`对象后，您可以尝试在曲线和线命令之间切换以查看差异。

# 使用 GraphWidget

我们的图形小部件已经完成，所以让我们转到`MainWindow`并使用它。

首先创建您的小部件并将其设置为中央小部件：

```py
        self.graph = GraphWidget(self)
        self.setCentralWidget(self.graph)
```

接下来，让我们创建一个方法，该方法将读取当前的 CPU 使用情况并将其发送到`GraphWidget`。为此，我们需要从`psutil`库导入`cpu_percent`函数：

```py
from psutil import cpu_percent
```

现在我们可以编写我们的图形更新方法如下：

```py
    def update_graph(self):
        cpu_usage = cpu_percent()
        self.graph.add_value(cpu_usage)
```

`cpu_percent()`函数返回一个从 0 到 100 的整数，反映了计算机当前的 CPU 利用率。这非常适合直接发送到我们的`GraphWidget`，其默认范围是 0 到 100。

现在我们只需要定期调用这个方法来更新图形；在`MainWindow.__init__()`中，添加以下代码：

```py
        self.timer = qtc.QTimer()
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.update_graph)
        self.timer.start()
```

这只是一个`QTimer`对象，您在第十章中学到的，*使用 QTimer 和 QThread 进行多线程处理*，设置为每秒调用一次`update_graph()`。

如果现在运行应用程序，您应该会得到类似于这样的结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/9f215c0b-8fcb-4e0d-acbf-b344e4bf5605.png)

注意我们的贝塞尔曲线所创建的平滑峰值。如果切换回直线代码，您将看到这些峰值变得更加尖锐。

如果您的 CPU 太强大，无法提供有趣的活动图，请尝试对`update_graph()`进行以下更改以更好地测试小部件：

```py
    def update_graph(self):
        import random
        cpu_usage = random.randint(1, 100)
        self.graph.add_value(cpu_usage)
```

这将只输出介于`1`和`100`之间的随机值，并且应该产生一些相当混乱的结果。

看到这个 CPU 图表实时动画可能会让您对 Qt 的动画能力产生疑问。在下一节中，我们将学习如何使用`QPainter`和 Qt 图形视图框架一起创建 Qt 中的 2D 动画。

# 使用 QGraphicsScene 进行 2D 图形动画

在简单的小部件和图像编辑中，对`QPaintDevice`对象进行绘制效果很好，但在我们想要绘制大量的 2D 对象，并可能实时地对它们进行动画处理的情况下，我们需要一个更强大的对象。Qt 提供了 Graphics View Framework，这是一个基于项目的模型视图框架，用于组合复杂的 2D 图形和动画。

为了探索这个框架的运作方式，我们将创建一个名为**Tankity Tank Tank Tank**的游戏。

# 第一步

这个坦克游戏将是一个两人对战游戏，模拟了你可能在经典的 1980 年代游戏系统上找到的简单动作游戏。一个玩家将在屏幕顶部，一个在底部，两辆坦克将不断从左到右移动，每个玩家都试图用一颗子弹射击对方。

要开始，将您的 Qt 应用程序模板复制到一个名为`tankity_tank_tank_tank.py`的新文件中。从文件顶部的`import`语句之后开始，我们将添加一些常量：

```py
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
BORDER_HEIGHT = 100
```

这些常量将在整个游戏代码中用于计算大小和位置。实际上，我们将立即在`MainWindow.__init__()`中使用其中的两个：

```py
        self.resize(qtc.QSize(SCREEN_WIDTH, SCREEN_HEIGHT))
        self.scene = Scene()
        view = qtw.QGraphicsView(self.scene)
        self.setCentralWidget(view)
```

这是我们将要添加到`MainWindow`中的所有代码。在将窗口调整大小为我们的宽度和高度常量之后，我们将创建两个对象，如下：

+   第一个是`Scene`对象。这是一个我们将要创建的自定义类，是从`QGraphicsScene`派生的。`QGraphicsScene`是这个模型视图框架中的模型，表示包含各种图形项目的 2D 场景。

+   第二个是`QGraphicsView`对象，它是框架的视图组件。这个小部件的工作只是渲染场景并将其显示给用户。

我们的`Scene`对象将包含游戏的大部分代码，所以我们将下一步构建那部分。

# 创建一个场景

`Scene`类将是我们游戏的主要舞台，并将管理游戏中涉及的各种对象，如坦克、子弹和墙壁。它还将显示分数并跟踪其他游戏逻辑。

让我们这样开始：

```py
class Scene(qtw.QGraphicsScene):

    def __init__(self):
        super().__init__()
        self.setBackgroundBrush(qtg.QBrush(qtg.QColor('black')))
        self.setSceneRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT)
```

我们在这里做的第一件事是通过设置`backgroundBrush`属性将我们的场景涂成黑色。这个属性自然地需要一个`QBrush`对象，它将用来填充场景的背景。我们还设置了`sceneRect`属性，它描述了场景的大小，设置为我们的宽度和高度常量的`QRect`对象。

要开始在场景上放置对象，我们可以使用它的许多 add 方法之一：

```py
        wall_brush = qtg.QBrush(qtg.QColor('blue'), qtc.Qt.Dense5Pattern)
        floor = self.addRect(
            qtc.QRectF(0, SCREEN_HEIGHT - BORDER_HEIGHT,
                       SCREEN_WIDTH, BORDER_HEIGHT),
            brush=wall_brush)
        ceiling = self.addRect(
            qtc.QRectF(0, 0, SCREEN_WIDTH, BORDER_HEIGHT),
            brush=wall_brush)
```

在这里，我们使用`addRect()`在场景上绘制了两个矩形——一个在底部作为地板，一个在顶部作为天花板。就像`QPainter`类一样，`QGraphicsScene`有方法来添加椭圆、像素图、线、多边形、文本和其他这样的项目。然而，与绘图程序不同，`QGraphicsScene`方法不仅仅是将像素绘制到屏幕上；相反，它们创建了`QGraphicsItem`类（或其子类）的项目。我们随后可以查询或操作所创建的项目。

例如，我们可以添加一些文本项目来显示我们的分数，如下所示：

```py
        self.top_score = 0
        self.bottom_score = 0
        score_font = qtg.QFont('Sans', 32)
        self.top_score_display = self.addText(
            str(self.top_score), score_font)
        self.top_score_display.setPos(10, 10)
        self.bottom_score_display = self.addText(
            str(self.bottom_score), score_font)
        self.bottom_score_display.setPos(
            SCREEN_WIDTH - 60, SCREEN_HEIGHT - 60)
```

在这里，在创建文本项目之后，我们正在操作它们的属性，并使用`setPos()`方法设置每个文本项目的位置。

我们还可以更新项目中的文本；例如，让我们创建方法来更新我们的分数：

```py
    def top_score_increment(self):
        self.top_score += 1
        self.top_score_display.setPlainText(str(self.top_score))

    def bottom_score_increment(self):
        self.bottom_score += 1
        self.bottom_score_display.setPlainText(str(self.bottom_score))
```

如果你把`QPainter`比作在纸上绘画，那么把`QGraphicsItems`添加到`QGraphicsScene`类就相当于在毛毯图上放置毛毡形状。项目*在*场景上，但它们不是场景的一部分，因此它们可以被改变或移除。

# 创建坦克

我们的游戏将有两辆坦克，一辆在屏幕顶部，一辆在底部。这些将在`Scene`对象上绘制，并进行动画处理，以便玩家可以左右移动它们。在第六章中，*Qt 应用程序的样式*，您学到了可以使用`QPropertyAnimation`进行动画处理，但是*只有*被动画处理的属性属于`QObject`的后代。`QGraphicsItem`不是`QObject`的后代，但`QGraphicsObject`对象将两者结合起来，为我们提供了一个可以进行动画处理的图形项。

因此，我们需要将我们的`Tank`类构建为`QGraphicsObject`的子类：

```py
class Tank(qtw.QGraphicsObject):

    BOTTOM, TOP = 0, 1
    TANK_BM = b'\x18\x18\xFF\xFF\xFF\xFF\xFF\x66'
```

这个类首先定义了两个常量，`TOP`和`BOTTOM`。这将用于表示我们是在屏幕顶部还是底部创建坦克。

`TANK_BM`是一个包含坦克图形的 8×8 位图数据的`bytes`对象。我们很快就会看到这是如何工作的。

首先，让我们开始构造函数：

```py
    def __init__(self, color, y_pos, side=TOP):
        super().__init__()
        self.side = side
```

我们的坦克将被赋予颜色、*y*坐标和`side`值，该值将是`TOP`或`BOTTOM`。我们将使用这些信息来定位和定向坦克。

接下来，让我们使用我们的`bytes`字符串为我们的坦克创建一个位图：

```py
        self.bitmap = qtg.QBitmap.fromData(
            qtc.QSize(8, 8), self.TANK_BM)
```

`QBitmap`对象是`QPixmap`的单色图像的特殊情况。通过将大小和`bytes`对象传递给`fromData()`静态方法，我们可以生成一个简单的位图对象，而无需单独的图像文件。

为了理解这是如何工作的，请考虑`TANK_BM`字符串。因为我们将其解释为 8×8 图形，所以该字符串中的每个字节（8 位）对应于图形的一行。

如果您将每一行转换为二进制数字并将它们按每行一个字节的方式排列，它将如下所示：

```py
00011000
00011000
11111111
11111111
11111111
11111111
11111111
01100110
```

由 1 创建的形状实质上是该位图将采用的形状。当然，8x8 的图形将非常小，所以我们应该将其放大。此外，这辆坦克显然是指向上的，所以如果我们是顶部的坦克，我们需要将其翻转过来。

我们可以使用`QTransform`对象来完成这两件事：

```py
        transform = qtg.QTransform()
        transform.scale(4, 4)  # scale to 32x32
        if self.side == self.TOP:  # We're pointing down
            transform.rotate(180)
        self.bitmap = self.bitmap.transformed(transform)
```

`QTransform`对象表示要在`QPixmap`或`QBitmap`上执行的一组变换。创建变换对象后，我们可以设置要应用的各种变换，首先是缩放操作，然后是添加`rotate`变换（如果坦克在顶部）。`QTransform`对象可以传递给位图的`transformed()`方法，该方法返回一个应用了变换的新`QBitmap`对象。

该位图是单色的，默认情况下是黑色。要以其他颜色绘制，我们将需要一个设置为所需颜色的`QPen`（而不是刷子！）对象。让我们使用我们的`color`参数按如下方式创建它：

```py
        self.pen = qtg.QPen(qtg.QColor(color))
```

`QGraphicsObject`对象的实际外观是通过重写`paint()`方法确定的。让我们按照以下方式创建它：

```py
    def paint(self, painter, option, widget):
        painter.setPen(self.pen)
        painter.drawPixmap(0, 0, self.bitmap)
```

`paint()`的第一个参数是`QPainter`对象，Qt 已经创建并分配给绘制对象。我们只需要对该绘图程序应用命令，它将根据我们的要求绘制图像。我们将首先将`pen`属性设置为我们创建的笔，然后使用绘图程序的`drawPixmap()`方法来绘制我们的位图。

请注意，我们传递给`drawPixmap()`的坐标不是`QGraphicsScene`类的坐标，而是`QGraphicsObject`对象本身的边界矩形内的坐标。因此，我们需要确保我们的对象返回一个适当的边界矩形，以便我们的图像被正确绘制。

为了做到这一点，我们需要重写`boundingRect()`方法：

```py
    def boundingRect(self):
        return qtc.QRectF(0, 0, self.bitmap.width(),
                          self.bitmap.height())
```

在这种情况下，我们希望我们的`boundingRect()`方法返回一个与位图大小相同的矩形。

回到`Tank.__init__()`，让我们定位我们的坦克：

```py
        if self.side == self.BOTTOM:
            y_pos -= self.bitmap.height()
        self.setPos(0, y_pos)
```

`QGraphicsObject.setPos()`方法允许您使用像素坐标将对象放置在其分配的`QGraphicsScene`上的任何位置。由于像素坐标始终从对象的左上角计数，如果对象在屏幕底部，我们需要调整对象的*y*坐标，使其自身高度升高，以便坦克的*底部*距离屏幕顶部`y_pos`像素。

对象的位置始终表示其左上角的位置。

现在我们想要让我们的坦克动起来；每个坦克将在*x*轴上来回移动，在触碰屏幕边缘时会反弹。

让我们创建一个`QPropertyAnimation`方法来实现这一点：

```py
        self.animation = qtc.QPropertyAnimation(self, b'x')
        self.animation.setStartValue(0)
        self.animation.setEndValue(SCREEN_WIDTH - self.bitmap.width())
        self.animation.setDuration(2000)
```

`QGraphicsObject`对象具有定义其在场景上的*x*和*y*坐标的`x`和`y`属性，因此将对象进行动画处理就像是将我们的属性动画指向这些属性。我们将从`0`开始动画`x`，并以屏幕的宽度结束；但是，为了防止我们的坦克离开边缘，我们需要从该值中减去位图的宽度。最后，我们设置两秒的持续时间。

属性动画可以向前或向后运行。因此，要启用左右移动，我们只需要切换动画运行的方向。让我们创建一些方法来做到这一点：

```py
    def toggle_direction(self):
        if self.animation.direction() == qtc.QPropertyAnimation.Forward:
            self.left()
        else:
            self.right()

    def right(self):
        self.animation.setDirection(qtc.QPropertyAnimation.Forward)
        self.animation.start()

    def left(self):
        self.animation.setDirection(qtc.QPropertyAnimation.Backward)
        self.animation.start()
```

改变方向只需要设置动画对象的`direction`属性为`Forward`或`Backward`，然后调用`start()`来应用它。

回到`__init__()`，让我们使用`toggle_direction()`方法来创建*反弹*：

```py
        self.animation.finished.connect(self.toggle_direction)
```

为了使游戏更有趣，我们还应该让我们的坦克从屏幕的两端开始：

```py
        if self.side == self.TOP:
            self.toggle_direction()
        self.animation.start()
```

设置动画后，通过调用`start()`来启动它。这处理了坦克的动画；现在是时候装载我们的武器了。

# 创建子弹

在这个游戏中，每个坦克一次只能在屏幕上有一个子弹。这简化了我们的游戏代码，但也使游戏保持相对具有挑战性。

为了实现这些子弹，我们将创建另一个名为`Bullet`的`QGraphicsObject`对象，它被动画化沿着*y*轴移动。

让我们开始我们的`Bullet`类如下：

```py
class Bullet(qtw.QGraphicsObject):

    hit = qtc.pyqtSignal()

    def __init__(self, y_pos, up=True):
        super().__init__()
        self.up = up
        self.y_pos = y_pos
```

子弹类首先通过定义`hit`信号来表示它击中了敌方坦克。构造函数接受一个`y_pos`参数来定义子弹的起始点，并且一个布尔值来指示子弹是向上还是向下移动。这些参数被保存为实例变量。

接下来，让我们按照以下方式定义子弹的外观：

```py
    def boundingRect(self):
        return qtc.QRectF(0, 0, 10, 10)

    def paint(self, painter, options, widget):
        painter.setBrush(qtg.QBrush(qtg.QColor('yellow')))
        painter.drawRect(0, 0, 10, 10)
```

我们的子弹将简单地是一个 10×10 的黄色正方形，使用绘图器的`drawRect()`方法创建。这对于复古游戏来说是合适的，但是为了好玩，让我们把它变得更有趣。为此，我们可以将称为`QGraphicsEffect`的类应用于`QGraphicsObject`。`QGraphicsEffect`类可以实时地对对象应用视觉效果。我们通过创建`QGraphicEffect`类的子类实例并将其分配给子弹的`graphicsEffect`属性来实现这一点，如下所示：

```py
        blur = qtw.QGraphicsBlurEffect()
        blur.setBlurRadius(10)
        blur.setBlurHints(
            qtw.QGraphicsBlurEffect.AnimationHint)
 self.setGraphicsEffect(blur)
```

添加到`Bullet.__init__()`的这段代码创建了一个模糊效果并将其应用到我们的`QGraphicsObject`类。请注意，这是应用在对象级别上的，而不是在绘画级别上，因此它适用于我们绘制的任何像素。我们已将模糊半径调整为 10 像素，并添加了`AnimationHint`对象，告诉我们正在应用于动画对象的效果，并激活某些性能优化。

说到动画，让我们按照以下方式创建子弹的动画：

```py
        self.animation = qtc.QPropertyAnimation(self, b'y')
        self.animation.setStartValue(y_pos)
        end = 0 if up else SCREEN_HEIGHT
        self.animation.setEndValue(end)
        self.animation.setDuration(1000)
```

动画被配置为使子弹从当前的`y_pos`参数到屏幕的顶部或底部花费一秒的时间，具体取决于子弹是向上还是向下射击。不过我们还没有开始动画，因为我们不希望子弹在射击前就开始移动。

射击将在`shoot()`方法中发生，如下所示：

```py
    def shoot(self, x_pos):
        self.animation.stop()
        self.setPos(x_pos, self.y_pos)
        self.animation.start()
```

当玩家射出子弹时，我们首先停止任何可能发生的动画。由于一次只允许一颗子弹，快速射击只会导致子弹重新开始（虽然这并不是非常现实，但这样做可以使游戏更具挑战性）。

然后，将子弹重新定位到*x*坐标并传递到`shoot()`方法和坦克的*y*坐标。最后，启动动画。这个想法是，当玩家射击时，我们将传入坦克当前的*x*坐标，子弹将从那个位置直线飞出。

让我们回到我们的`Tank`类，并添加一个`Bullet`对象。在`Tank.__init__()`中，添加以下代码：

```py
        bullet_y = (
            y_pos - self.bitmap.height()
            if self.side == self.BOTTOM
            else y_pos + self.bitmap.height()
        )
        self.bullet = Bullet(bullet_y, self.side == self.BOTTOM)
```

为了避免我们的子弹击中自己的坦克，我们希望子弹从底部坦克的正上方或顶部坦克的正下方开始，这是我们在第一条语句中计算出来的。由于我们的坦克不会上下移动，这个位置是一个常数，我们可以将它传递给子弹的构造函数。

为了让坦克射出子弹，我们将在`Tank`类中创建一个名为`shoot()`的方法：

```py
    def shoot(self):
        if not self.bullet.scene():
            self.scene().addItem(self.bullet)
        self.bullet.shoot(self.x())
```

我们需要做的第一件事是将子弹添加到场景中（如果尚未添加或已被移除）。我们可以通过检查子弹的`scene`属性来确定这一点，如果对象不在场景中，则返回`None`。

然后，通过传入坦克的*x*坐标来调用子弹的`shoot()`方法。

# 碰撞检测

如果子弹击中目标后什么都不发生，那么子弹就没有什么用。为了在子弹击中坦克时发生一些事情，我们需要实现**碰撞检测**。我们将在`Bullet`类中实现这一点，要求它在移动时检查是否击中了任何东西。

首先在`Bullet`中创建一个名为`check_colllision()`的方法：

```py
    def check_collision(self):
        colliding_items = self.collidingItems()
        if colliding_items:
            self.scene().removeItem(self)
            for item in colliding_items:
                if type(item).__name__ == 'Tank':
                    self.hit.emit()
```

`QGraphicsObject.collidingItems()`返回一个列表，其中包含任何与此项的边界矩形重叠的`QGraphicsItem`对象。这不仅包括我们的`Tank`对象，还包括我们在`Scene`类中创建的`floor`和`ceiling`项，甚至是另一个坦克的`Bullet`对象。如果我们的子弹触碰到这些物品中的任何一个，我们需要将其从场景中移除；为此，我们调用`self.scene().removeItem(self)`来消除子弹。

然后，我们需要检查我们碰撞的物品中是否有`Tank`对象。我们只需检查被击中的对象的类型和名称即可。如果我们击中了坦克，我们就会发出`hit`信号。（我们可以安全地假设它是另一个坦克，因为我们的子弹移动的方式）

每次`Bullet`对象移动时都需要调用这个方法，因为每次移动都可能导致碰撞。幸运的是，`QGraphicsObject`方法有一个`yChanged`信号，每当它的*y*坐标发生变化时就会发出。

因此，在`Bullet.__init__()`方法中，我们可以添加一个连接，如下所示：

```py
        self.yChanged.connect(self.check_collision)
```

我们的坦克和子弹对象现在已经准备就绪，所以让我们回到`Scene`对象来完成我们的游戏。

# 结束游戏

回到`Scene.__init__()`，让我们创建我们的两辆坦克：

```py
        self.bottom_tank = Tank(
            'red', floor.rect().top(), Tank.BOTTOM)
        self.addItem(self.bottom_tank)

        self.top_tank = Tank(
            'green', ceiling.rect().bottom(), Tank.TOP)
        self.addItem(self.top_tank)
```

底部坦克位于地板上方，顶部坦克位于天花板下方。现在我们可以将它们的子弹的`hit`信号连接到适当的分数增加方法：

```py
        self.top_tank.bullet.hit.connect(self.top_score_increment)
        self.bottom_tank.bullet.hit.connect(self.bottom_score_increment)
```

到目前为止，我们的游戏几乎已经完成了：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/492381be-ba26-4e11-91b5-de1470a9ef5a.png)

当然，还有一个非常重要的方面还缺失了——控制！

我们的坦克将由键盘控制；我们将为底部玩家分配箭头键进行移动和回车键进行射击，而顶部玩家将使用*A*和*D*进行移动，空格键进行射击。

为了处理按键，我们需要重写`Scene`对象的`keyPressEvent()`方法：

```py
    def keyPressEvent(self, event):
        keymap = {
            qtc.Qt.Key_Right: self.bottom_tank.right,
            qtc.Qt.Key_Left: self.bottom_tank.left,
            qtc.Qt.Key_Return: self.bottom_tank.shoot,
            qtc.Qt.Key_A: self.top_tank.left,
            qtc.Qt.Key_D: self.top_tank.right,
            qtc.Qt.Key_Space: self.top_tank.shoot
        }
        callback = keymap.get(event.key())
        if callback:
            callback()
```

`keyPressEvent()`在`Scene`对象聚焦时每当用户按下键盘时被调用。它是唯一的参数，是一个`QKeyEvent`对象，其`key()`方法返回`QtCore.Qt.Key`枚举中的常量，告诉我们按下了什么键。在这个方法中，我们创建了一个`dict`对象，将某些键常量映射到我们的坦克对象的方法。每当我们接收到一个按键，我们尝试获取一个回调方法，如果成功，我们调用这个方法。

游戏现在已经准备好玩了！找个朋友（最好是你不介意和他共享键盘的人）并开始玩吧。

# 总结

在本章中，您学习了如何在 PyQt 中使用 2D 图形。我们学习了如何使用`QPainter`对象编辑图像并创建自定义小部件。然后，您学习了如何使用`QGraphicsScene`方法与`QGraphicsObject`类结合使用，创建可以使用自动逻辑或用户输入控制的动画场景。

在下一章中，我们将为我们的图形添加一个额外的维度，探索在 PyQt 中使用 OpenGL 3D 图形。您将学习一些 OpenGL 编程的基础知识，以及如何将其集成到 PyQt 应用程序中。

# 问题

尝试这些问题来测试你从本章学到的知识：

1.  在这个方法中添加代码，以在图片底部用蓝色写下你的名字：

```py
       def create_headshot(self, image_file, name):
           image = qtg.QImage()
           image.load(image_file)
           # your code here

           # end of your code
           return image
```

1.  给定一个名为`painter`的`QPainter`对象，写一行代码在绘图设备的左上角绘制一个 80×80 像素的八边形。您可以参考[`doc.qt.io/qt-5/qpainter.html#drawPolygon`](https://doc.qt.io/qt-5/qpainter.html#drawPolygon)中的文档进行指导。

1.  您正在创建一个自定义小部件，但不知道为什么文本显示为黑色。以下是您的`paintEvent()`方法；看看你能否找出问题：

```py
   def paintEvent(self, event):
       black_brush = qtg.QBrush(qtg.QColor('black'))
       white_brush = qtg.QBrush(qtg.QColor('white'))
       painter = qtg.QPainter()
       painter.setBrush(black_brush)
       painter.drawRect(0, 0, self.width(), self.height())
       painter.setBrush(white_brush)
       painter.drawText(0, 0, 'Test Text')
```

1.  深炸迷因是一种使用极端压缩、饱和度和其他处理来使迷因图像故意看起来低质量的迷因风格。在你的迷因生成器中添加一个功能，可以选择使迷因深炸。你可以尝试的一些事情包括减少颜色位深度和调整图像中颜色的色调和饱和度。

1.  您想要动画一个圆在屏幕上水平移动。更改以下代码以动画圆：

```py
   scene = QGraphicsScene()
   scene.setSceneRect(0, 0, 800, 600)
   circle = scene.addEllipse(0, 0, 10, 10)
   animation = QPropertyAnimation(circle, b'x')
   animation.setStartValue(0)
   animation.setEndValue(600)
   animation.setDuration(5000)
   animation.start()
```

1.  以下代码尝试使用渐变刷设置`QPainter`对象。找出其中的问题所在：

```py
   gradient = qtg.QLinearGradient(
       qtc.QPointF(0, 100), qtc.QPointF(0, 0))
   gradient.setColorAt(20, qtg.QColor('red'))
   gradient.setColorAt(40, qtg.QColor('orange'))
   gradient.setColorAt(60, qtg.QColor('green'))
   painter = QPainter()
   painter.setGradient(gradient)
```

1.  看看你是否可以实现一些对我们创建的游戏的改进：

+   +   脉动子弹

+   坦克被击中时爆炸

+   声音（参见第七章，*使用 QtMultimedia 处理音频-视觉*，以获取指导）

+   背景动画

+   多个子弹

# 进一步阅读

有关更多信息，请参阅以下内容：

+   有关`QPainter`和 Qt 绘图系统的深入讨论可以在[`doc.qt.io/qt-5/paintsystem.html`](https://doc.qt.io/qt-5/paintsystem.html)找到

+   Qt 图形视图框架的概述可以在[`doc.qt.io/qt-5/graphicsview.html`](https://doc.qt.io/qt-5/graphicsview.html)找到

+   动画框架的概述可以在[`doc.qt.io/qt-5/animation-overview.html`](https://doc.qt.io/qt-5/animation-overview.html)找到
