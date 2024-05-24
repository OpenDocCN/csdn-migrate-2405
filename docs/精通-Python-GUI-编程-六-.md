# 精通 Python GUI 编程（六）

> 原文：[`zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408`](https://zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：使用 QtWebEngine 进行 Web 浏览

在第八章中，*使用 QtNetwork 进行网络操作*，您学习了如何使用套接字和 HTTP 与网络系统进行交互。然而，现代网络远不止于网络协议；它是建立在 HTML、JavaScript 和 CSS 组合之上的编程平台，有效地使用它需要一个完整的 Web 浏览器。幸运的是，Qt 为我们提供了`QtWebEngineWidgets`库，为我们的应用程序提供了一个完整的 Web 浏览器小部件。

在本章中，我们将学习如何在以下部分中使用 Qt 访问 Web：

+   使用`QWebEngineView`构建基本浏览器

+   高级`QtWebEngine`用法

# 技术要求

除了本书中使用的基本 PyQt5 设置之外，您还需要确保已从 PyPI 安装了`PyQtWebEngine`软件包。您可以使用以下命令执行此操作：

```py
$ pip install --user PyQtWebEngine
```

您可能还想要本章的示例代码，可以从[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter16`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter16)获取。

查看以下视频，了解代码的运行情况：[`bit.ly/2M5xFtD`](http://bit.ly/2M5xFtD)

# 使用`QWebEngineView`构建基本浏览器

从`QtWebEngineWidgets`中使用的主要类是`QWebEngineView`类；这个类在`QWidget`对象中提供了一个几乎完整的基于 Chromium 的浏览器。Chromium 是支持许多 Google Chrome、最新版本的 Microsoft Edge 和许多其他浏览器的开源项目。

Qt 还有一个基于**Webkit**渲染引擎的已弃用的`QtWebKit`模块，用于 Safari、Opera 和一些旧版浏览器。`QtWebKit`和`QtWebEngineWidgets`之间的 API 和渲染行为存在一些显着差异，后者更适合新项目。

在本节中，我们将看到使用`QtWebEngineWidgets`构建一个简单的 Web 浏览器，将 Web 内容包含在 Qt 应用程序中是多么容易。

# 使用 QWebEngineView 小部件

我们需要从第四章中复制我们的 Qt 应用程序模板，*使用 QMainWindow 构建应用程序*，并将其命名为`simple_browser.py`；我们将开发一个带有选项卡和历史记录显示的基本浏览器。

我们首先导入`QtWebEngineWidgets`库，如下所示：

```py
from PyQt5 import QtWebEngineWidgets as qtwe
```

请注意，还有一个`QtWebEngine`模块，但它是用于与**Qt 建模语言**（**QML**）声明性框架一起使用的，而不是本书涵盖的 Qt 小部件框架。`QtWebEngineWidgets`包含基于小部件的浏览器。

在我们的`MainWindow`类构造函数中，我们将通过定义导航工具栏来启动 GUI：

```py
        navigation = self.addToolBar('Navigation')
        style = self.style()
        self.back = navigation.addAction('Back')
        self.back.setIcon(style.standardIcon(style.SP_ArrowBack))
        self.forward = navigation.addAction('Forward')
        self.forward.setIcon(style.standardIcon(style.SP_ArrowForward))
        self.reload = navigation.addAction('Reload')
        self.reload.setIcon(style.standardIcon(style.SP_BrowserReload))
        self.stop = navigation.addAction('Stop')
        self.stop.setIcon(style.standardIcon(style.SP_BrowserStop))
        self.urlbar = qtw.QLineEdit()
        navigation.addWidget(self.urlbar)
        self.go = navigation.addAction('Go')
        self.go.setIcon(style.standardIcon(style.SP_DialogOkButton))
```

在这里，我们为标准浏览器操作定义了工具栏按钮，以及用于 URL 栏的`QLineEdit`对象。我们还从默认样式中提取了这些操作的图标，就像我们在第四章的*添加工具栏*部分中所做的那样，*使用 QMainWindow 构建应用程序*。

现在我们将创建一个`QWebEngineView`对象：

```py
        webview = qtwe.QWebEngineView()
        self.setCentralWidget(webview)
```

`QWebEngineView`对象是一个（大多数情况下，正如您将看到的那样）功能齐全且交互式的 Web 小部件，能够检索和呈现 HTML、CSS、JavaScript、图像和其他标准 Web 内容。

要在视图中加载 URL，我们将`QUrl`传递给其`load()`方法：

```py
        webview.load(qtc.QUrl('http://www.alandmoore.com'))
```

这将提示 Web 视图下载并呈现页面，就像普通的 Web 浏览器一样。

当然，尽管该网站很好，我们希望能够浏览其他网站，因此我们将添加以下连接：

```py
        self.go.triggered.connect(lambda: webview.load(
            qtc.QUrl(self.urlbar.text())))
```

在这里，我们将我们的`go`操作连接到一个`lambda`函数，该函数检索 URL 栏的文本，将其包装在`QUrl`对象中，并将其发送到 Web 视图。如果此时运行脚本，您应该能够在栏中输入 URL，点击 Go，然后像任何其他浏览器一样浏览 Web。

`QWebView`具有所有常见浏览器导航操作的插槽，我们可以将其连接到我们的导航栏：

```py
        self.back.triggered.connect(webview.back)
        self.forward.triggered.connect(webview.forward)
        self.reload.triggered.connect(webview.reload)
        self.stop.triggered.connect(webview.stop)
```

通过连接这些信号，我们的脚本已经在成为一个完全功能的网络浏览体验的路上。但是，我们目前仅限于单个浏览器窗口；我们想要选项卡，因此让我们在以下部分实现它。

# 允许多个窗口和选项卡

在`MainWindow.__init__()`中，删除或注释掉刚刚添加的 Web 视图代码（返回到创建`QWebEngineView`对象）。我们将将该功能移动到一个方法中，以便我们可以在选项卡界面中创建多个 Web 视图。我们将按照以下方式进行：

1.  首先，我们将用`QTabWidget`对象替换我们的`QWebEngineView`对象作为我们的中央小部件：

```py
        self.tabs = qtw.QTabWidget(
            tabsClosable=True, movable=True)
        self.tabs.tabCloseRequested.connect(self.tabs.removeTab)
        self.new = qtw.QPushButton('New')
        self.tabs.setCornerWidget(self.new)
        self.setCentralWidget(self.tabs)
```

此选项卡小部件将具有可移动和可关闭的选项卡，并在左上角有一个新按钮用于添加新选项卡。

1.  要添加一个带有 Web 视图的新选项卡，我们将创建一个`add_tab()`方法：

```py
    def add_tab(self, *args):
        webview = qtwe.QWebEngineView()
        tab_index = self.tabs.addTab(webview, 'New Tab')
```

该方法首先创建一个 Web 视图小部件，并将其添加到选项卡小部件的新选项卡中。

1.  现在我们有了我们的 Web 视图对象，我们需要连接一些信号：

```py
        webview.urlChanged.connect(
            lambda x: self.tabs.setTabText(tab_index, x.toString()))
        webview.urlChanged.connect(
            lambda x: self.urlbar.setText(x.toString()))
```

`QWebEngineView`对象的`urlChanged`信号在将新 URL 加载到视图中时发出，并将新 URL 作为`QUrl`对象发送。我们将此信号连接到一个`lambda`函数，该函数将选项卡标题文本设置为 URL，以及另一个函数，该函数设置 URL 栏的内容。这将使 URL 栏与用户在网页中使用超链接导航时与浏览器保持同步，而不是直接使用 URL 栏。

1.  然后，我们可以使用其`setHtml()`方法向我们的 Web 视图对象添加默认内容：

```py
        webview.setHtml(
            '<h1>Blank Tab</h1><p>It is a blank tab!</p>',
            qtc.QUrl('about:blank'))
```

这将使浏览器窗口的内容成为我们提供给它的任何 HTML 字符串。如果我们还传递一个`QUrl`对象，它将被用作当前 URL（例如发布到`urlChanged`信号）。

1.  为了启用导航，我们需要将我们的工具栏操作连接到浏览器小部件。由于我们的浏览器有一个全局工具栏，我们不能直接将这些连接到 Web 视图小部件。我们需要将它们连接到将信号传递到当前活动 Web 视图的插槽的方法。首先创建回调方法如下：

```py
    def on_back(self):
        self.tabs.currentWidget().back()

    def on_forward(self):
        self.tabs.currentWidget().forward()

    def on_reload(self):
        self.tabs.currentWidget().reload()

    def on_stop(self):
        self.tabs.currentWidget().stop()

    def on_go(self):
        self.tabs.currentWidget().load(
            qtc.QUrl(self.urlbar.text()))
```

这些方法本质上与单窗格浏览器使用的方法相同，但有一个关键变化——它们使用选项卡窗口小部件的`currentWidget()`方法来检索当前可见选项卡的`QWebEngineView`对象，然后在该 Web 视图上调用导航方法。

1.  在`__init__()`中连接以下方法：

```py
        self.back.triggered.connect(self.on_back)
        self.forward.triggered.connect(self.on_forward)
        self.reload.triggered.connect(self.on_reload)
        self.stop.triggered.connect(self.on_stop)
        self.go.triggered.connect(self.on_go)
        self.urlbar.returnPressed.connect(self.on_go)
        self.new.clicked.connect(self.add_tab)
```

为了方便和键盘友好性，我们还将 URL 栏的`returnPressed`信号连接到`on_go()`方法。我们还将我们的新按钮连接到`add_tab()`方法。

现在尝试浏览器，您应该能够添加多个选项卡并在每个选项卡中独立浏览。

# 为弹出窗口添加选项卡

目前，我们的脚本存在问题，即如果您*Ctrl* +单击超链接，或打开配置为打开新窗口的链接，将不会发生任何事情。默认情况下，`QWebEngineView`无法打开新标签页或窗口。为了启用此功能，我们必须使用一个函数覆盖其`createWindow()`方法，该函数创建并返回一个新的`QWebEngineView`对象。

我们可以通过更新我们的`add_tab()`方法来轻松实现这一点：

```py
        webview.createWindow = self.add_tab
        return webview
```

我们不会对`QWebEngineView`进行子类化以覆盖该方法，而是将我们的`MainWindow.add_tab()`方法分配给其`createWindow()`方法。然后，我们只需要确保在方法结束时返回创建的 Web 视图对象。

请注意，我们不需要在`createWindow()`方法中加载 URL；我们只需要适当地创建视图并将其添加到 GUI 中。Qt 将负责在我们返回的 Web 视图对象中执行浏览所需的操作。

现在，当您尝试浏览器时，您应该发现*Ctrl * +单击会打开一个带有请求链接的新选项卡。

# 高级 QtWebEngine 用法

虽然我们已经实现了一个基本的、可用的浏览器，但它还有很多不足之处。在本节中，我们将通过修复用户体验中的一些痛点和实现有用的工具，如历史和文本搜索，来探索`QtWebEngineWidgets`的一些更高级的功能。

# 共享配置文件

虽然我们可以在浏览器中查看多个选项卡，但它们在与经过身份验证的网站一起工作时存在一个小问题。访问任何您拥有登录帐户的网站；登录，然后*Ctrl *+单击站点内的链接以在新选项卡中打开它。您会发现您在新选项卡中没有经过身份验证。对于使用多个窗口或选项卡来实现其用户界面的网站来说，这可能是一个真正的问题。我们希望身份验证和其他会话数据是整个浏览器范围的，所以让我们来解决这个问题。

会话信息存储在一个由`QWebEngineProfile`对象表示的**配置文件**中。这个对象是为每个`QWebEngineWidget`对象自动生成的，但我们可以用自己的对象来覆盖它。

首先在`MainWindow.__init__()`中创建一个：

```py
        self.profile = qtwe.QWebEngineProfile()
```

当我们在`add_tab()`中创建新的 web 视图时，我们需要将这个配置文件对象与每个新的 web 视图关联起来。然而，配置文件实际上并不是 web 视图的属性；它们是 web 页面对象的属性。页面由`QWebEnginePage`对象表示，可以被视为 web 视图的*模型*。每个 web 视图都会生成自己的`page`对象，它充当了浏览引擎的接口。

为了覆盖 web 视图的配置文件，我们需要创建一个`page`对象，覆盖它的配置文件，然后用我们的新页面覆盖 web 视图的页面，就像这样：

```py
        page = qtwe.QWebEnginePage(self.profile)
        webview.setPage(page)
```

配置文件*必须*作为参数传递给`QWebEnginePage`构造函数，因为没有访问函数可以在之后设置它。一旦我们有了一个使用我们的配置文件的新的`QWebEnginePage`对象，我们就可以调用`QWebEngineView.setPage()`将其分配给我们的 web 视图。

现在当您测试浏览器时，您的身份验证状态应该在所有选项卡中保持不变。

# 查看历史记录

每个`QWebEngineView`对象都管理着自己的浏览历史，我们可以访问它来允许用户查看和导航已访问的 URL。

为了构建这个功能，让我们创建一个界面，显示当前选项卡的历史记录，并允许用户点击历史记录项进行导航：

1.  首先在`MainView.__init__()`中创建一个历史记录的停靠窗口小部件：

```py
        history_dock = qtw.QDockWidget('History')
        self.addDockWidget(qtc.Qt.RightDockWidgetArea, history_dock)
        self.history_list = qtw.QListWidget()
        history_dock.setWidget(self.history_list)
```

历史记录停靠窗口只包含一个`QListWidget`对象，它将显示当前选定选项卡的历史记录。

1.  由于我们需要在用户切换选项卡时刷新这个列表，将选项卡小部件的`currentChanged`信号连接到一个可以执行此操作的回调函数：

```py
        self.tabs.currentChanged.connect(self.update_history)
```

1.  `update_history()`方法如下：

```py
    def update_history(self, *args):
        self.history_list.clear()
        webview = self.tabs.currentWidget()
        if webview:
            history = webview.history()
            for history_item in reversed(history.items()):
                list_item = qtw.QListWidgetItem()
                list_item.setData(
                    qtc.Qt.DisplayRole, history_item.url())
                self.history_list.addItem(list_item)
```

首先，我们清除列表小部件并检索当前活动选项卡的 web 视图。如果 web 视图存在（如果所有选项卡都关闭了，它可能不存在），我们使用`history()`方法检索 web 视图的历史记录。

这个历史记录是一个`QWebEngineHistory`对象；这个对象是 web 页面对象的属性，用来跟踪浏览历史。当在 web 视图上调用`back()`和`forward()`槽时，会查询这个对象，找到正确的 URL 进行加载。历史对象的`items()`方法返回一个`QWebEngineHistoryItem`对象的列表，详细描述了 web 视图对象的整个浏览历史。

我们的`update_history`方法遍历这个列表，并为历史中的每个项目添加一个新的`QListWidgetItem`对象。请注意，我们使用列表小部件项的`setData()`方法，而不是`setText()`，因为它允许我们直接存储`QUrl`对象，而不必将其转换为字符串（`QListWidget`将自动将 URL 转换为字符串进行显示，使用 URL 的`toString()`方法）。

1.  除了在切换选项卡时调用此方法之外，我们还需要在 web 视图导航到新页面时调用它，以便在用户浏览时保持历史记录的最新状态。为了实现这一点，在`add_tab()`方法中为每个新生成的 web 视图添加一个连接：

```py
        webview.urlChanged.connect(self.update_history)
```

1.  为了完成我们的历史功能，我们希望能够双击历史中的项目并在当前打开的标签中导航到其 URL。我们将首先创建一个`MainWindow`方法来进行导航：

```py
    def navigate_history(self, item):
        qurl = item.data(qtc.Qt.DisplayRole)
        if self.tabs.currentWidget():
            self.tabs.currentWidget().load(qurl)
```

我们将使用`QListWidget`中的`itemDoubleClicked`信号来触发此方法，该方法将`QListItemWidget`对象传递给其回调。我们只需通过调用其`data()`访问器方法从列表项中检索 URL，然后将 URL 传递给当前可见的 web 视图。

1.  现在，回到`__init__()`，我们将连接信号到回调如下：

```py
        self.history_list.itemDoubleClicked.connect(
            self.navigate_history)
```

这完成了我们的历史功能；启动浏览器，您会发现可以使用停靠中的历史列表查看和导航。

# Web 设置

`QtWebEngine`浏览器，就像它所基于的 Chromium 浏览器一样，提供了一个非常可定制的网络体验；我们可以编辑许多设置来实现各种安全、功能或外观的更改。

为此，我们需要访问以下默认的`settings`对象：

```py
        settings = qtwe.QWebEngineSettings.defaultSettings()
```

`defaultSettings()`静态方法返回的`QWebEngineSettings`对象是一个全局对象，由程序中所有的 web 视图引用。我们不必（也不能）在更改后将其显式分配给 web 视图。一旦我们检索到它，我们可以以各种方式配置它，我们的设置将被所有我们创建的 web 视图所尊重。

例如，让我们稍微改变字体：

```py
        # The web needs more drama:
        settings.setFontFamily(
            qtwe.QWebEngineSettings.SansSerifFont, 'Impact')
```

在这种情况下，我们将所有无衬线字体的默认字体系列设置为`Impact`。除了设置字体系列，我们还可以设置默认的`fontSize`对象和`defaultTextEncoding`对象。

`settings`对象还具有许多属性，这些属性是布尔开关，我们可以切换；例如：

```py
        settings.setAttribute(
            qtwe.QWebEngineSettings.PluginsEnabled, True)
```

在这个例子中，我们启用了 Pepper API 插件的使用，例如 Chrome 的 Flash 实现。我们可以切换 29 个属性，以下是其中的一些示例：

| 属性 | 默认 | 描述 |
| --- | --- | --- |
| `JavascriptEnabled` | `True` | 允许运行 JavaScript 代码。 |
| `JavascriptCanOpenWindows` | `True` | 允许 JavaScript 打开新的弹出窗口。 |
| 全屏支持已启用 | 假 | 允许浏览器全屏显示。 |
| `AllowRunningInsecureContent` | `False` | 允许在 HTTPS 页面上运行 HTTP 内容。 |
| `PlaybackRequiresUserGesture` | `False` | 在用户与页面交互之前不要播放媒体。 |

要更改单个 web 视图的设置，请使用`page().settings()`访问其`QWebEnginSettings`对象。

# 构建文本搜索功能

到目前为止，我们已经在我们的 web 视图小部件中加载和显示了内容，但实际内容并没有做太多事情。我们通过`QtWebEngine`获得的强大功能之一是能够通过将我们自己的 JavaScript 代码注入到这些页面中来操纵网页的内容。为了看看这是如何工作的，我们将使用以下说明来开发一个文本搜索功能，该功能将突出显示搜索词的所有实例：

1.  我们将首先在`MainWindow.__init__()`中添加 GUI 组件：

```py
        find_dock = qtw.QDockWidget('Search')
        self.addDockWidget(qtc.Qt.BottomDockWidgetArea, find_dock)
        self.find_text = qtw.QLineEdit()
        find_dock.setWidget(self.find_text)
        self.find_text.textChanged.connect(self.text_search)
```

搜索小部件只是一个嵌入在停靠窗口中的`QLineEdit`对象。我们已经将`textChanged`信号连接到一个回调函数，该函数将执行搜索。

1.  为了实现搜索功能，我们需要编写一些 JavaScript 代码，以便为我们定位和突出显示搜索词的所有实例。我们可以将此代码添加为字符串，但为了清晰起见，让我们将其写在一个单独的文件中；打开一个名为`finder.js`的文件，并添加以下代码：

```py
function highlight_selection(){
    let tag = document.createElement('found');
    tag.style.backgroundColor = 'lightgreen';
    window.getSelection().getRangeAt(0).surroundContents(tag);}

function highlight_term(term){
    let found_tags = document.getElementsByTagName("found");
    while (found_tags.length > 0){
        found_tags[0].outerHTML = found_tags[0].innerHTML;}
    while (window.find(term)){highlight_selection();}
    while (window.find(term, false, true)){highlight_selection();}}
```

这本书不是一本 JavaScript 文本，所以我们不会深入讨论这段代码的工作原理，只是总结一下正在发生的事情：

+   1.  `highlight_term()`函数接受一个字符串作为搜索词。它首先清理任何 HTML`<found>`标签；这不是一个真正的标签——这是我们为了这个功能而发明的，这样它就不会与任何真正的标签冲突。

1.  然后该函数通过文档向前和向后搜索搜索词的实例。

1.  当它找到一个时，它会用背景颜色设置为浅绿色的`<found>`标签包裹它。

1.  回到`MainWindow.__init__()`，我们将读取这个文件并将其保存为一个实例变量：

```py
        with open('finder.js', 'r') as fh:
            self.finder_js = fh.read()
```

1.  现在，让我们在`MainWindow`下实现我们的搜索回调方法：

```py
    def text_search(self, term):
        term = term.replace('"', '')
        page = self.tabs.currentWidget().page()
        page.runJavaScript(self.finder_js)
        js = f'highlight_term("{term}");'
        page.runJavaScript(js)
```

在我们当前的网页视图中运行 JavaScript 代码，我们需要获取它的`QWebEnginePage`对象的引用。然后我们可以调用页面的`runJavaScript()`方法。这个方法简单地接受一个包含 JavaScript 代码的字符串，并在网页上执行它。

1.  在这种情况下，我们首先运行我们的`finder.js`文件的内容来设置函数，然后我们调用`highlight_term()`函数并插入搜索词。作为一个快速而粗糙的安全措施，我们还从搜索词中剥离了所有双引号；因此，它不能用于注入任意的 JavaScript。如果你现在运行应用程序，你应该能够在页面上搜索字符串，就像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/3e7dac13-b284-4ea5-ae91-54413221f4f9.png)

这个方法效果还不错，但是每次更新搜索词时重新定义这些函数并不是很有效，是吗？如果我们只定义这些函数一次，然后在我们导航到的任何页面上都可以访问它们，那就太好了。

1.  这可以使用`QWebEnginePage`对象的`scripts`属性来完成。这个属性存储了一个`QWebEngineScript`对象的集合，其中包含了每次加载新页面时要运行的 JavaScript 片段。通过将我们的脚本添加到这个集合中，我们可以确保我们的函数定义仅在每次页面加载时运行，而不是每次我们尝试搜索时都运行。为了使这个工作，我们将从`MainWindow.__init__()`开始，定义一个`QWebEngineScript`对象：

```py
        self.finder_script = qtwe.QWebEngineScript()
        self.finder_script.setSourceCode(self.finder_js)
```

1.  集合中的每个脚本都在 256 个**worlds**中的一个中运行，这些 worlds 是隔离的 JavaScript 上下文。为了在后续调用中访问我们的函数，我们需要确保我们的`script`对象通过设置它的`worldId`属性在主 world 中执行：

```py
        self.finder_script.setWorldId(qtwe.QWebEngineScript.MainWorld)
```

`QWebEngineScript.MainWorld`是一个常量，指向主 JavaScript 执行上下文。如果我们没有设置这个，我们的脚本会运行，但函数会在它们自己的 world 中运行，并且在网页上下文中不可用于搜索。

1.  现在我们有了我们的`script`对象，我们需要将它添加到网页对象中。这应该在`MainWindow.add_tab()`中完成，当我们创建我们的`page`对象时：

```py
        page.scripts().insert(self.finder_script)
```

1.  最后，我们可以缩短`text_search()`方法：

```py
    def text_search(self, term):
        page = self.tabs.currentWidget().page()
        js = f'highlight_term("{term}");'
        page.runJavaScript(js)
```

除了运行脚本，我们还可以从脚本中检索数据并将其发送到我们的 Python 代码中的回调方法。

例如，我们可以对我们的 JavaScript 进行以下更改，以从我们的函数中返回匹配项的数量：

```py
function highlight_term(term){
    //cleanup
    let found_tags = document.getElementsByTagName("found");
    while (found_tags.length > 0){
        found_tags[0].outerHTML = found_tags[0].innerHTML;}
    let matches = 0
    //search forward and backward
    while (window.find(term)){
        highlight_selection();
        matches++;
    }
    while (window.find(term, false, true)){
        highlight_selection();
        matches++;
    }
    return matches;
}
```

这个值*不*是从`runJavaScript()`返回的，因为 JavaScript 代码是异步执行的。

要访问返回值，我们需要将一个 Python 可调用的引用作为`runJavaScript()`的第二个参数传递；Qt 将调用该方法，并传递被调用代码的返回值：

```py
    def text_search(self, term):
        term = term.replace('"', '')
        page = self.tabs.currentWidget().page()
        js = f'highlight_term("{term}");'
        page.runJavaScript(js, self.match_count)
```

在这里，我们将 JavaScript 调用的输出传递给一个名为`match_count()`的方法，它看起来像下面的代码片段：

```py
    def match_count(self, count):
        if count:
            self.statusBar().showMessage(f'{count} matches ')
        else:
            self.statusBar().clearMessage()
```

在这种情况下，如果找到任何匹配项，我们将显示一个状态栏消息。再次尝试浏览器，你会看到消息应该成功传达。

# 总结

在本章中，我们探讨了`QtWebEngineWidgets`为我们提供的可能性。您实现了一个简单的浏览器，然后学习了如何利用浏览历史、配置文件共享、多个选项卡和常见设置等功能。您还学会了如何向网页注入任意 JavaScript 并检索这些调用的结果。

在下一章中，您将学习如何准备您的代码以进行共享、分发和部署。我们将讨论如何正确地构建项目目录结构，如何使用官方工具分发 Python 代码，以及如何使用 PyInstaller 为各种平台创建独立的可执行文件。

# 问题

尝试这些问题来测试您从本章中学到的知识：

1.  以下代码给出了一个属性错误；出了什么问题？

```py
   from PyQt5 import QtWebEngine as qtwe
   w = qtwe.QWebEngineView()
```

1.  以下代码应该将`UrlBar`类与`QWebEngineView`连接起来，以便在按下*return*/*Enter*键时加载输入的 URL。但是它不起作用；出了什么问题？

```py
   class UrlBar(qtw.QLineEdit):

       url_request = qtc.pyqtSignal(str)

       def __init__(self):
           super().__init__()
           self.returnPressed.connect(self.request)

       def request(self):
           self.url_request.emit(self.text())

   mywebview = qtwe.QWebEngineView()
   myurlbar = UrlBar()
   myurlbar.url_request(mywebview.load)
```

1.  以下代码的结果是什么？

```py
   class WebView(qtwe.QWebEngineView):

       def createWindow(self, _):

           return self
```

1.  查看[`doc.qt.io/qt-5/qwebengineview.html`](https://doc.qt.io/qt-5/qwebengineview.html)中的`QWebEngineView`文档。您将如何在浏览器中实现缩放功能？

1.  正如其名称所示，`QWebEngineView`代表了模型-视图架构中的视图部分。在这个设计中，哪个类代表了模型？

1.  给定一个名为`webview`的`QWebEngineView`对象，编写代码来确定`webview`上是否启用了 JavaScript。

1.  您在我们的浏览器示例中看到`runJavaScript()`可以将整数值传递给回调函数。编写一个简单的演示脚本来测试可以返回哪些其他类型的 JavaScript 对象，以及它们在 Python 代码中的表现方式。

# 进一步阅读

有关更多信息，请参考以下内容：

+   **QuteBrowser**是一个使用`QtWebEngineWidgets`用 Python 编写的开源网络浏览器。您可以在[`github.com/qutebrowser/qutebrowser`](https://github.com/qutebrowser/qutebrowser)找到其源代码。

+   **ADMBrowser**是一个基于`QtWebEngineWidgets`的浏览器，由本书的作者创建，并可用于信息亭系统。您可以在[`github.com/alandmoore/admbrowser`](https://github.com/alandmoore/admbrowser)找到它。

+   `QtWebChannel`是一个功能，允许您的 PyQt 应用程序与 Web 内容之间进行更强大的通信。您可以在[`doc.qt.io/qt-5/qtwebchannel-index.html`](https://doc.qt.io/qt-5/qtwebchannel-index.html)开始探索这一高级功能。


# 第十七章：准备软件进行分发

到目前为止，在这本书中，我们主要关注的是编写一个可工作的代码。我们的项目都是单个脚本，最多有几个支持数据文件。然而，完成一个项目并不仅仅是编写代码；我们还需要我们的项目能够轻松分发，这样我们就可以与其他人分享（或出售）它们。

在本章中，我们将探讨为分享和分发准备我们的代码的方法。

我们将涵盖以下主题：

+   项目结构

+   使用`setuptools`进行分发

+   使用 PyInstaller 编译

# 技术要求

在本章中，您将需要我们在整本书中使用的基本 Python 和 PyQt 设置。您还需要使用以下命令从 PyPI 获取`setuptools`、`wheel`和`pyinstaller`库：

```py
$ pip install --user setuptools wheel pyinstaller
```

Windows 用户将需要从[`www.7-zip.org/`](https://www.7-zip.org/)安装 7-Zip 程序，以便他们可以使用`tar.gz`文件，所有平台的用户都应该从[`upx.github.io/`](https://upx.github.io/)安装 UPX 实用程序。

最后，您将希望从存储库中获取示例代码[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter17`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter17)。

查看以下视频，看看代码是如何运行的：[`bit.ly/2M5xH4J`](http://bit.ly/2M5xH4J)

# 项目结构

到目前为止，在这本书中，我们一直将每个示例项目中的所有 Python 代码放入单个文件中。然而，现实世界的 Python 项目受益于更好的组织。虽然没有关于如何构建 Python 项目的官方标准，但我们可以应用一些约定和一般概念来构建我们的项目结构，这不仅可以保持组织，还可以鼓励其他人贡献我们的代码。

为了看到这是如何工作的，我们将在 PyQt 中创建一个简单的井字棋游戏，然后花费本章的其余部分来准备分发。

# 井字棋

我们的井字棋游戏由三个类组成：

+   管理游戏逻辑的引擎类

+   提供游戏状态视图和进行游戏的方法的棋盘类

+   将其他两个类合并到 GUI 中的主窗口类

打开第四章中的应用程序模板的新副本，*使用 QMainWindow 构建应用程序*，并将其命名为`ttt-qt.py`。现在让我们创建这些类。

# 引擎类

我们的游戏引擎对象的主要责任是跟踪游戏并检查是否有赢家或游戏是否为平局。玩家将简单地由`'X'`和`'O'`字符串表示，棋盘将被建模为九个项目的列表，这些项目将是玩家或`None`。

它开始如下：

```py
class TicTacToeEngine(qtc.QObject):

    winning_sets = [
        {0, 1, 2}, {3, 4, 5}, {6, 7, 8},
        {0, 3, 6}, {1, 4, 7}, {2, 5, 8},
        {0, 4, 8}, {2, 4, 6}
    ]
    players = ('X', 'O')

    game_won = qtc.pyqtSignal(str)
    game_draw = qtc.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.board = [None] * 9
        self.current_player = self.players[0]
```

`winning_sets`列表包含`set`对象，其中包含构成胜利的每个棋盘索引的组合。我们将使用该列表来检查玩家是否获胜。我们还定义了信号，当游戏获胜或平局时发出（即，所有方块都填满了，没有人获胜）。构造函数填充了棋盘列表，并将当前玩家设置为`X`。

我们将需要一个方法来在每轮之后更新当前玩家，看起来是这样的：

```py
    def next_player(self):
        self.current_player = self.players[
            not self.players.index(self.current_player)]
```

接下来，我们将添加一个标记方块的方法：

```py
    def mark_square(self, square):
        if any([
                not isinstance(square, int),
                not (0 <= square < len(self.board)),
                self.board[square] is not None
        ]):
            return False
        self.board[square] = self.current_player
        self.next_player()
        return True
```

此方法首先检查给定方块是否应该被标记的任何原因，如果有原因则返回`False`；否则，我们标记方块，切换到下一个玩家，并返回`True`。

这个类中的最后一个方法将检查棋盘的状态，看看是否有赢家或平局：

```py
    def check_board(self):
        for player in self.players:
            plays = {
                index for index, value in enumerate(self.board)
                if value == player
            }
            for win in self.winning_sets:
                if not win - plays:  # player has a winning combo
                    self.game_won.emit(player)
                    return
        if None not in self.board:
            self.game_draw.emit()
```

该方法使用一些集合操作来检查每个玩家当前标记的方块是否与获胜组合列表匹配。如果找到任何匹配项，将发出`game_won`信号并返回。如果还没有人赢，我们还要检查是否有任何未标记的方块；如果没有，游戏就是平局。如果这两种情况都不成立，我们什么也不做。

# 棋盘类

对于棋盘 GUI，我们将使用一个`QGraphicsScene`对象，就像我们在第十二章中为坦克游戏所做的那样，*使用 QPainter 创建 2D 图形*。

我们将从一些类变量开始：

```py
class TTTBoard(qtw.QGraphicsScene):

    square_rects = (
        qtc.QRectF(5, 5, 190, 190),
        qtc.QRectF(205, 5, 190, 190),
        qtc.QRectF(405, 5, 190, 190),
        qtc.QRectF(5, 205, 190, 190),
        qtc.QRectF(205, 205, 190, 190),
        qtc.QRectF(405, 205, 190, 190),
        qtc.QRectF(5, 405, 190, 190),
        qtc.QRectF(205, 405, 190, 190),
        qtc.QRectF(405, 405, 190, 190)
    )

    square_clicked = qtc.pyqtSignal(int)
```

`square_rects`元组为棋盘上的九个方块定义了一个`QRectF`对象，并且每当点击一个方块时会发出一个`square_clicked`信号；随附的整数将指示点击了哪个方块（0-8）。

以下是`=__init__()`方法：

```py
    def __init__(self):
        super().__init__()
        self.setSceneRect(0, 0, 600, 600)
        self.setBackgroundBrush(qtg.QBrush(qtc.Qt.cyan))
        for square in self.square_rects:
            self.addRect(square, brush=qtg.QBrush(qtc.Qt.white))
        self.mark_pngs = {
            'X': qtg.QPixmap('X.png'),
            'O': qtg.QPixmap('O.png')
        }
        self.marks = []
```

该方法设置了场景大小并绘制了青色背景，然后在`square_rects`中绘制了每个方块。然后，我们加载了用于标记方块的`'X'`和`'O'`图像的`QPixmap`对象，并创建了一个空列表来跟踪我们标记的`QGraphicsSceneItem`对象。

接下来，我们将添加一个方法来绘制棋盘的当前状态：

```py
    def set_board(self, marks):
        for i, square in enumerate(marks):
            if square in self.mark_pngs:
                mark = self.addPixmap(self.mark_pngs[square])
                mark.setPos(self.square_rects[i].topLeft())
                self.marks.append(mark)
```

该方法将接受我们棋盘上的标记列表，并在每个方块中绘制适当的像素项，跟踪创建的`QGraphicsSceneItems`对象。

现在我们需要一个方法来清空棋盘：

```py
    def clear_board(self):
        for mark in self.marks:
            self.removeItem(mark)
```

该方法只是遍历保存的像素项并将它们全部删除。

我们需要做的最后一件事是处理鼠标点击：

```py
    def mousePressEvent(self, mouse_event):
        position = mouse_event.buttonDownScenePos(qtc.Qt.LeftButton)
        for square, qrect in enumerate(self.square_rects):
            if qrect.contains(position):
                self.square_clicked.emit(square)
                break
```

`mousePressEvent()`方法由`QGraphicsScene`在用户进行鼠标点击时调用。它包括一个`QMouseEvent`对象，其中包含有关事件的详细信息，包括鼠标点击的位置。我们可以检查此点击是否在我们的`square_rects`对象中的任何一个内部，如果是，我们将发出`square_clicked`信号并退出该方法。

# 主窗口类

在`MainWindow.__init__()`中，我们将首先创建一个棋盘和一个`QGraphicsView`对象来显示它：

```py
        self.board = TTTBoard()
        self.board_view = qtw.QGraphicsView()
        self.board_view.setScene(self.board)
        self.setCentralWidget(self.board_view)
```

现在我们需要创建一个游戏引擎的实例并连接它的信号。为了让我们能够一遍又一遍地开始游戏，我们将为此创建一个单独的方法：

```py
    def start_game(self):
        self.board.clear_board()
        self.game = TicTacToeEngine()
        self.game.game_won.connect(self.game_won)
        self.game.game_draw.connect(self.game_draw)
```

该方法清空了棋盘，然后创建了游戏引擎对象的一个实例，将引擎的信号连接到`MainWindow`方法以处理两种游戏结束的情况。

回到`__init__()`，我们将调用这个方法来自动设置第一局游戏：

```py
        self.start_game()
```

接下来，我们需要启用玩家输入。我们需要一个方法，该方法将尝试在引擎中标记方块，然后在标记成功时检查棋盘是否获胜或平局：

```py
    def try_mark(self, square):
        if self.game.mark_square(square):
            self.board.set_board(self.game.board)
            self.game.check_board()
```

该方法可以连接到棋盘的`square_clicked`信号；在`__init__()`中，添加以下代码：

```py
        self.board.square_clicked.connect(self.try_mark)
```

最后，我们需要处理两种游戏结束的情况：

```py
    def game_won(self, player):
        """Display the winner and start a new game"""
        qtw.QMessageBox.information(
            None, 'Game Won', f'Player {player} Won!')
        self.start_game()

    def game_draw(self):
        """Display the lack of a winner and start a new game"""
        qtw.QMessageBox.information(
            None, 'Game Over', 'Game Over.  Nobody Won...')
        self.start_game()
```

在这两种情况下，我们只会在`QMessageBox`中显示适当的消息，然后重新开始游戏。

这完成了我们的游戏。花点时间运行游戏，并确保您了解它在正常工作时的响应（也许找个朋友和您一起玩几局；如果您的朋友很年轻或者不太聪明，这会有所帮助）。

现在我们有了一个可用的游戏，是时候准备将其分发了。我们首先要做的是以一种使我们更容易维护和扩展的方式构建我们的项目，以及让其他 Python 程序员合作。

# 模块式结构

作为程序员，我们倾向于将应用程序和库视为两个非常不同的东西，但实际上，结构良好的应用程序与库并没有太大的不同。库只是一组现成的类和函数。我们的应用程序主要也只是类定义；它只是碰巧在最后有几行代码，使其能够作为应用程序运行。当我们以这种方式看待事物时，将我们的应用程序结构化为 Python 库模块是很有道理的。为了做到这一点，我们将把我们的单个 Python 文件转换为一个包含多个文件的目录，每个文件包含一个单独的代码单元。

第一步是考虑我们项目的名称；现在，那个名称是`ttt-qt.py`。当你开始着手一个项目时，想出一个快速简短的名称是很常见的，但这不一定是你要坚持的名称。在这种情况下，我们的名称相当神秘，由于连字符而不能作为 Python 模块名称。相反，让我们称之为`qtictactoe`，这是一个更明确的名称，避免了连字符。

首先，创建一个名为`QTicTacToe`的新目录；这将是我们的**项目根目录**。项目根目录是所有项目文件都将放置在其中的目录。

在该目录下，我们将创建一个名为`qtictactoe`的第二个目录；这将是我们的**模块目录**，其中将包含大部分我们的源代码。

# 模块的结构

为了开始我们的模块，我们将首先添加我们三个类的代码。我们将把每个类放在一个单独的文件中；这并不是严格必要的，但这将帮助我们保持代码解耦，并使得更容易找到我们想要编辑的类。

因此，在`qtictactoe`下，创建三个文件：

+   `engine.py`将保存我们的游戏引擎类。复制`TicTacToeEngine`的定义以及它所使用的必要的`PyQt5`导入语句。在这种情况下，你只需要`QtCore`。

+   `board.py`将保存`TTTBoard`类。也复制那段代码以及完整的`PyQt5`导入语句。

+   最后，`mainwindow.py`将保存`MainWindow`类。复制该类的代码以及`PyQt5`导入。

`mainwindow.py`还需要从其他文件中获取`TicTacToeEngine`和`TTTBoard`类的访问权限。为了提供这种访问权限，我们需要使用**相对导入**。相对导入是一种从同一模块中导入子模块的方法。

在`mainwindow.py`的顶部添加这行：

```py
from .engine import TicTacToeEngine
from .board import TTTBoard
```

在导入中的点表示这是一个相对导入，并且特指当前容器模块（在本例中是`qtictactoe`）。通过使用这样的相对导入，我们可以确保我们从自己的项目中导入这些模块，而不是从用户系统上的其他 Python 库中导入。

我们需要添加到我们模块的下一个代码是使其实际运行的代码。这通常是我们放在`if __name__ == '__main__'`块下的代码。

在模块中，我们将把它放在一个名为`__main__.py`的文件中：

```py
import sys
from PyQt5.QtWidgets import QApplication
from .mainwindow import MainWindow

def main():
    app = QApplication(sys.argv)
    mainwindow = MainWindow()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
```

`__main__.py`文件在 Python 模块中有着特殊的用途。每当我们使用`-m`开关运行我们的模块时，它就会被执行，就像这样：

```py
$ python3 -m qtictactoe
```

实质上，`__main__.py`是 Python 脚本中`if __name__ == '__main__':`块的模块等价物。

请注意，我们已经将我们的三行主要代码放在一个名为`main()`的函数中。当我们讨论`setuptools`的使用时，这样做的原因将变得明显。

我们需要在模块内创建的最后一个文件是一个名为`__init__.py`的空文件。Python 模块的`__init__.py`文件类似于 Python 类的`__init__()`方法。每当导入模块时，它都会被执行，并且其命名空间中的任何内容都被视为模块的根命名空间。但在这种情况下，我们将它留空。这可能看起来毫无意义，但如果没有这个文件，我们将要使用的许多工具将不会将这个 Python 文件夹识别为一个实际的模块。

此时，您的目录结构应该是这样的：

```py
QTicTacToe/
├── qtictactoe
    ├── board.py
    ├── engine.py
    ├── __init__.py
    ├── __main__.py
    └── mainwindow.py
```

现在，我们可以使用`python3 -m qtictactoe`来执行我们的程序，但对大多数用户来说，这并不是非常直观。让我们通过创建一个明显的文件来帮助一下执行应用程序。

在项目根目录下（模块外部），创建一个名为`run.py`的文件：

```py
from qtictactoe.__main__ import main
main()
```

这个文件的唯一目的是从我们的模块中加载`main()`函数并执行它。现在，您可以执行`python run.py`，您会发现它可以正常启动。但是，有一个问题——当您点击一个方块时，什么也不会发生。那是因为我们的图像文件丢失了。我们需要处理这些问题。

# 非 Python 文件

在 PyQt 程序中，处理诸如我们的`X`和`O`图像之类的文件的最佳方法是使用`pyrcc5`工具生成一个资源文件，然后像任何其他 Python 文件一样将其添加到您的模块中（我们在第六章中学习了这个）。然而，在这种情况下，我们将保留我们的图像作为 PNG 文件，以便我们可以探索处理非 Python 文件的选项。

关于这些文件应该放在项目目录的何处，目前还没有达成一致的意见，但是由于这些图像是`TTTBoard`类的一个必需组件，将它们放在我们的模块内是有意义的。为了组织起见，将它们放在一个名为`images`的目录中。

现在，您的目录结构应该是这样的：

```py
QTicTacToe/
├── qtictactoe
│   ├── board.py
│   ├── engine.py
│   ├── images
│   │   ├── O.png
│   │   └── X.png
│   ├── __init__.py
│   ├── __main__.py
│   └── mainwindow.py
└── run.py
```

我们编写`TTTBoard`的方式是，您可以看到每个图像都是使用相对文件路径加载的。在 Python 中，相对路径始终相对于当前工作目录，也就是用户启动脚本的目录。不幸的是，这是一个相当脆弱的设计，因为我们无法控制这个目录。我们也不能硬编码绝对文件路径，因为我们不知道我们的应用程序可能存储在用户系统的何处（请参阅我们在第六章中对这个问题的讨论，*Styling Qt Applications*，*Using Qt Resource files*部分）。

在 PyQt 应用程序中解决这个问题的理想方式是使用 Qt 资源文件；然而，我们将尝试一种不同的方法，只是为了说明在这种情况下如何解决这个问题。

为了解决这个问题，我们需要修改`TTTBoard`加载图像的方式，使其相对于我们模块的位置，而不是用户的当前工作目录。这将需要我们使用 Python 标准库中的`os.path`模块，因此在`board.py`的顶部添加这个：

```py
from os import path
```

现在，在`__init__()`中，我们将修改加载图像的行：

```py
        directory = path.dirname(__file__)
        self.mark_pngs = {
            'X': qtg.QPixmap(path.join(directory, 'images', 'X.png')),
            'O': qtg.QPixmap(path.join(directory, 'images', 'O.png'))
        }
```

`__file__`变量是一个内置变量，它始终包含当前文件（在本例中是`board.py`）的绝对路径。使用`path.dirname`，我们可以找到包含此文件的目录。然后，我们可以使用`path.join`来组装一个路径，以便在同一目录下的名为`images`的文件夹中查找文件。

如果您现在运行程序，您应该会发现它完美地运行，就像以前一样。不过，我们还没有完成。

# 文档和元数据

工作和组织良好的代码是我们项目的一个很好的开始；但是，如果您希望其他人使用或贡献到您的项目，您需要解决一些他们可能会遇到的问题。例如，他们需要知道如何安装程序，它的先决条件是什么，或者使用或分发的法律条款是什么。

为了回答这些问题，我们将包括一系列标准文件和目录：`LICENSE`文件，`README`文件，`docs`目录和`requirements.txt`文件。

# 许可文件

当您分享代码时，非常重要的是明确说明其他人可以或不可以对该代码做什么。在大多数国家，创建作品的人自动成为该作品的版权持有人；这意味着您对您的作品的复制行为行使控制。如果您希望其他人为您创建的作品做出贡献或使用它们，您需要授予他们一个**许可证**。

管理您项目的许可证通常以项目根目录中的一个名为`LICENSE`的纯文本文件提供。在我们的示例代码中，我们已经包含了这样一个文件，其中包含了**MIT 许可证**的副本。MIT 许可证是一种宽松的开源许可证，基本上允许任何人对代码做任何事情，只要他们保留我们的版权声明。它还声明我们对因某人使用我们的代码而发生的任何可怕事件不负责。

这个文件有时被称为`COPYING`，也可能有一个名为`txt`的文件扩展名。

您当然可以在许可证中加入任何条件；但是，对于 PyQt 应用程序，您需要确保您的许可证与 PyQt 的**通用公共许可证**（**GPL**）GNU 和 Qt 的**较宽松的通用公共许可证**（**LGPL**）GNU 的条款兼容。如果您打算发布商业或限制性许可的 PyQt 软件，请记住来自第一章，*PyQt 入门*，您需要从 Qt 公司和 Riverbank Computing 购买商业许可证。

对于开源项目，Python 社区强烈建议您坚持使用 MIT、BSD、GPL 或 LGPL 等知名许可证。可以在开放源代码倡议组织的网站[`opensource.org/licenses`](https://opensource.org/licenses)上找到已知的开源许可证列表。您还可以参考[`choosealicense.com`](https://choosealicense.com)，这是一个提供有关选择最符合您意图的许可证的指导的网站。

# README 文件

`README`文件是软件分发中最古老的传统之一。追溯到 20 世纪 70 年代中期，这个纯文本文件通常旨在在用户安装或运行软件之前向程序的用户传达最基本的一组指令和信息。

虽然没有关于`README`文件应包含什么的标准，但用户希望找到某些内容；其中一些包括以下内容：

+   软件的名称和主页

+   软件的作者（带有联系信息）

+   软件的简短描述

+   基本使用说明，包括任何命令行开关或参数

+   报告错误或为项目做出贡献的说明

+   已知错误的列表

+   诸如特定平台问题或说明之类的注释

无论您在文件中包含什么，您都应该力求简洁和有组织。为了方便一些组织，许多现代软件项目在编写`README`文件时使用标记语言；这使我们可以使用诸如标题、项目列表甚至表格等元素。

在 Python 项目中，首选的标记语言是**重新结构化文本**（**RST**）。这种语言是`docutils`项目的一部分，为 Python 提供文档实用程序。

当我们创建`qtictactoe`的`README.rst`文件时，我们将简要介绍 RST。从一个标题开始：

```py
============
 QTicTacToe
============
```

顶部行周围的等号表示它是一个标题；在这种情况下，我们只是使用了我们项目的名称。

接下来，我们将为项目的基本信息创建几个部分；我们通过简单地用符号划线下一行文本来指示部分标题，就像这样：

```py
Authors
=======
By Alan D Moore -  https://www.alandmoore.com

About
=====

This is the classic game of **tic-tac-toe**, also known as noughts and crosses.  Battle your opponent in a desperate race to get three in a line.
```

用于下划线部分标题的符号必须是以下之一：

```py
= - ` : ' " ~ ^ _ * + # < >
```

我们使用它们的顺序并不重要，因为 RST 解释器会假定第一个使用的符号作为表示顶级标题的下划线，下一个类型的符号是第二级标题，依此类推。在这种情况下，我们首先使用等号，所以无论我们在整个文档中使用它，它都会指示一个一级标题。

注意单词`tac-tac-toe`周围的双星号，这表示粗体文本。RST 还可以表示下划线、斜体和类似的排版样式。

例如，我们可以使用反引号来指示等宽代码文本：

```py
Usage
=====

Simply run `python qtictactoe.py` from within the project folder.

- Players take turns clicking the mouse on the playing field to mark squares.
- When one player gets 3 in a row, they win.
- If the board is filled with nobody getting in a row, the game is a draw.
```

这个例子还展示了一个项目列表：每行前面都加了一个破折号和空格。我们也可以使用`+`或`*`符号，并通过缩进创建子项目。

让我们用一些关于贡献的信息和一些注释来完成我们的`README.rst`文件：

```py
Contributing
============

Submit bugs and patches to the
`public git repository <http://git.example.com/qtictactoe>`_.

Notes
=====

    A strange game.  The only winning move is not to play.

    *—Joshua the AI, WarGames*
```

`Contributing`部分显示如何创建超链接：将超链接文本放在反引号内，URL 放在尖括号内，并在关闭反引号后添加下划线。`Notes`部分演示了块引用，只需将该行缩进四个空格即可。

虽然我们的文件作为文本是完全可读的，但是许多流行的代码共享网站会将 RST 和其他标记语言转换为 HTML。例如，在 GitHub 上，这个文件将在浏览器中显示如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/74f798bd-47d8-4941-8a14-63b614ce31d7.png)

这个简单的`README.rst`文件对于我们的小应用已经足够了；随着应用的增长，它将需要进一步扩展以记录添加的功能、贡献者、社区政策等。这就是为什么我们更喜欢使用 RST 这样的纯文本格式，也是为什么我们将其作为项目仓库的一部分；它应该随着代码一起更新。

RST 语法的快速参考可以在[docutils.sourceforge.net/docs/user/rst/quickref.html](http://docutils.sourceforge.net/docs/user/rst/quickref.html)找到。

# 文档目录

虽然这个`README`文件对于`QTicTacToe`已经足够了，但是一个更复杂的程序或库可能需要更健壮的文档。放置这样的文档的标准位置是在`docs`目录中。这个目录应该直接位于我们的项目根目录下，并且可以包含任何类型的额外文档，包括以下内容：

+   示例配置文件

+   用户手册

+   API 文档

+   数据库图表

由于我们的程序不需要这些东西，所以我们不需要在这个项目中添加`docs`目录。

# `requirements.txt`文件

Python 程序通常需要标准库之外的包才能运行，用户需要知道安装什么才能让你的项目运行。你可以（而且可能应该）将这些信息放在`README`文件中，但你也应该将它放在`requirements.txt`中。

`requirements.txt`的格式是每行一个库，如下所示：

```py
PyQt5
PyQt5-sip
```

这个文件中的库名称应该与 PyPI 中使用的名称相匹配，因为这个文件可以被`pip`用来安装项目所需的所有库，如下所示：

```py
$ pip  install --user -r requirements.txt
```

我们实际上不需要指定`PyQt5-sip`，因为它是`PyQt5`的依赖项，会自动安装。我们在这里添加它是为了展示如何指定多个库。

如果需要特定版本的库，也可以使用版本说明符进行说明：

```py
PyQt5 >= 5.12
PyQt5-sip == 4.19.4
```

在这种情况下，我们指定了`PyQt5`版本`5.12`或更高，并且只有`PyQt5-sip`的`4.19.4`版本。

关于`requirements.txt`文件的更多信息可以在[`pip.readthedocs.io/en/1.1/requirements.html`](https://pip.readthedocs.io/en/1.1/requirements.html)找到。

# 其他文件

这些是项目文档和元数据的基本要素，但在某些情况下，你可能会发现一些额外的文件有用：

+   `TODO.txt`：需要处理的错误或缺失功能的简要列表

+   `CHANGELOG.txt`：主要项目变更和发布历史的日志

+   `tests`：包含模块单元测试的目录

+   `scripts`：包含对你的模块有用但不是其一部分的 Python 或 shell 脚本的目录

+   `Makefile`：一些项目受益于脚本化的构建过程，对此，像`make`这样的实用工具可能会有所帮助；其他选择包括 CMake、SCons 或 Waf

不过，此时你的项目已经准备好上传到你喜欢的源代码共享站点。在下一节中，我们将看看如何为 PyPI 做好准备。

# 使用 setuptools 进行分发

在本书的许多部分，你已经使用`pip`安装了 Python 包。你可能知道`pip`会从 PyPI 下载这些包，并将它们安装到你的系统、Python 虚拟环境或用户环境中。你可能不知道的是，用于创建和安装这些包的工具称为`setuptools`，如果我们想要为 PyPI 或个人使用制作自己的包，它就可以随时为我们提供。

尽管`setuptools`是官方推荐的用于创建 Python 包的工具，但它并不是标准库的一部分。但是，如果你在安装过程中选择包括`pip`，它通常会包含在大多数操作系统的默认发行版中。如果由于某种原因你没有安装`setuptools`，请参阅[`setuptools.readthedocs.io/en/latest/`](https://setuptools.readthedocs.io/en/latest/)上的文档，了解如何在你的平台上安装它。

使用`setuptools`的主要任务是编写一个`setup.py`脚本。在本节中，我们将学习如何编写和使用我们的`setup.py`脚本来生成可分发的包。

# 编写 setuptools 配置

`setup.py`的主要目的是使用关键字参数调用`setuptools.setup()`函数，这将定义我们项目的元数据以及我们的项目应该如何打包和安装。

因此，我们将首先导入该函数：

```py
from setuptools import setup

setup(
    # Arguments here
)
```

`setup.py`中的剩余代码将作为`setup()`的关键字参数。让我们来看看这些参数的不同类别。

# 基本元数据参数

最简单的参数涉及项目的基本元数据：

```py
    name='QTicTacToe',
    version='1.0',
    author='Alan D Moore',
    author_email='alandmoore@example.com',
    description='The classic game of noughts and crosses',
    url="http://qtictactoe.example.com",
    license='MIT',
```

在这里，我们已经描述了包名称、版本、简短描述、项目 URL 和许可证，以及作者的姓名和电子邮件。这些信息将被写入包元数据，并被 PyPI 等网站使用，以构建项目的个人资料页面。

例如，看一下 PyQt5 的 PyPI 页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/816fd19d-7d1a-4e06-88c6-53ff5541c532.png)

在页面的左侧，你会看到一个指向项目主页的链接，作者（带有超链接的电子邮件地址）和许可证。在顶部，你会看到项目名称和版本，以及项目的简短描述。所有这些数据都可以从项目的`setup.py`脚本中提取出来。

如果你计划向 PyPI 提交一个包，请参阅[`www.python.org/dev/peps/pep-0440/`](https://www.python.org/dev/peps/pep-0440/)上的 PEP 440，了解你的版本号应该如何指定。

你在这个页面的主体中看到的长文本来自`long_description`参数。我们可以直接将一个长字符串放入这个参数，但既然我们已经有了一个很好的`README.rst`文件，为什么不在这里使用呢？由于`setup.py`是一个 Python 脚本，我们可以直接读取文件的内容，就像这样：

```py
    long_description=open('README.rst', 'r').read(),
```

在这里使用 RST 的一个优点是，PyPI（以及许多其他代码共享站点）将自动将你的标记渲染成格式良好的 HTML。

如果我们希望使我们的项目更容易搜索，我们可以包含一串空格分隔的关键字：

```py
    keywords='game multiplayer example pyqt5',
```

在这种情况下，搜索 PyPI 中的“multiplayer pyqt5”的人应该能找到我们的项目。

最后，你可以包含一个与项目相关的 URL 字典：

```py
    project_urls={
        'Author Website': 'https://www.alandmoore.com',
        'Publisher Website': 'https://packtpub.com',
        'Source Code': 'https://git.example.com/qtictactoe'
    },
```

格式为`{'label': 'URL'}`；你可能会在这里包括项目的 bug 跟踪器、文档站点、Wiki 页面或源代码库，特别是如果其中任何一个与主页 URL 不同的话。

# 包和依赖关系

除了建立基本元数据外，`setup()`还需要有关需要包含的实际代码或需要在系统上存在的环境的信息，以便执行此包。

这里我们需要处理的第一个关键字是`packages`，它定义了我们项目中需要包含的模块：

```py
    packages=['qtictactoe', 'qtictactoe.images'],
```

请注意，我们需要明确包括`qtictactoe`模块和`qtictactoe.images`模块；即使`images`目录位于`qtictactoe`下，也不会自动包含它。

如果我们有很多子模块，并且不想明确列出它们，`setuptools`也提供了自动解决方案：

```py
from setuptools import setup, find_package

setup(
    #...
    packages=find_packages(),
)
```

如果要使用`find_packages`，请确保每个子模块都有一个`__init__.py`文件，以便`setuputils`可以将其识别为模块。在这种情况下，您需要在`images`文件夹中添加一个`__init__.py`文件，否则它将被忽略。

这两种方法都有优点和缺点；手动方法更费力，但`find_packages`有时可能在某些情况下无法识别库。

我们还需要指定此项目运行所需的外部库，例如`PyQt5`。可以使用`install_requires`关键字来完成：

```py
    install_requires=['PyQt5'],
```

这个关键字接受一个包名列表，这些包必须被安装才能安装程序。当使用`pip`安装程序时，它将使用此列表自动安装所有依赖包。您应该在此列表中包括任何不属于标准库的内容。

就像`requirements.txt`文件一样，我们甚至可以明确指定每个依赖项所需的版本号：

```py
    install_requires=['PyQt5 >= 5.12'],
```

在这种情况下，`pip`将确保安装大于或等于 5.12 的 PyQt5 版本。如果未指定版本，`pip`将安装 PyPI 提供的最新版本。

在某些情况下，我们可能还需要指定特定版本的 Python；例如，我们的项目使用 f-strings，这是 Python 3.6 或更高版本才有的功能。我们可以使用`python_requires`关键字来指定：

```py
    python_requires='>=3.6',
```

我们还可以为可选功能指定依赖项；例如，如果我们为`qtictactoe`添加了一个可选的网络游戏功能，需要`requests`库，我们可以这样指定：

```py
    extras_require={
        "NetworkPlay": ["requests"]
    }
```

`extras_require`关键字接受一个特性名称（可以是任何您想要的内容）到包名称列表的映射。这些模块在安装您的包时不会自动安装，但其他模块可以依赖于这些子特性。例如，另一个模块可以指定对我们项目的`NetworkPlay`额外关键字的依赖，如下所示：

```py
    install_requires=['QTicTacToe[NetworkPlay]'],
```

这将触发一系列依赖关系，导致安装`requests`库。

# 非 Python 文件

默认情况下，`setuptools`将打包在我们项目中找到的 Python 文件，其他文件类型将被忽略。然而，在几乎任何项目中，都会有一些非 Python 文件需要包含在我们的分发包中。这些文件通常分为两类：一类是 Python 模块的一部分，比如我们的 PNG 文件，另一类是不是，比如`README`文件。

要包含*不*是 Python 包的文件，我们需要创建一个名为`MANIFEST.in`的文件。此文件包含项目根目录下文件路径的`include`指令。例如，如果我们想要包含我们的文档文件，我们的文件应该如下所示：

```py
include README.rst
include LICENSE
include requirements.txt
include docs/*
```

格式很简单：单词`include`后跟文件名、路径或匹配一组文件的模式。所有路径都是相对于项目根目录的。

要包含 Python 包的文件，我们有两种选择。

一种方法是将它们包含在`MANIFEST.in`文件中，然后在`setup.py`中将`include_package_data`设置为`True`：

```py
    include_package_data=True,
```

包含非 Python 文件的另一种方法是在`setup.py`中使用`package_data`关键字参数：

```py
    package_data={
        'qtictactoe.images': ['*.png'],
        '': ['*.txt', '*.rst']
    },
```

这个参数接受一个`dict`对象，其中每个条目都是一个模块路径和一个匹配包含的文件的模式列表。在这种情况下，我们希望包括在`qtictactoe.images`模块中找到的所有 PNG 文件，以及包中任何位置的 TXT 或 RST 文件。请记住，这个参数只适用于*模块目录中*的文件（即`qtictactoe`下的文件）。如果我们想要包括诸如`README.rst`或`run.py`之类的文件，那些应该放在`MANIFEST.in`文件中。

您可以使用任一方法来包含文件，但您不能在同一个项目中同时使用*两种*方法；如果启用了`include_package_data`，则将忽略`package_data`指令。

# 可执行文件

我们倾向于将 PyPI 视为安装 Python 库的工具；事实上，它也很适合安装应用程序，并且许多 Python 应用程序都可以从中获取。即使你正在创建一个库，你的库很可能会随附可执行的实用程序，比如 PyQt5 附带的`pyrcc5`和`pyuic5`实用程序。

为了满足这些需求，`setuputils` 为我们提供了一种指定特定函数或方法作为控制台脚本的方法；当安装包时，它将创建一个简单的可执行文件，在从命令行执行时将调用该函数或方法。

这是使用`entry_points`关键字指定的：

```py
    entry_points={
        'console_scripts': [
            'qtictactoe = qtictactoe.__main__:main'
        ]
    }
```

`entry_points`字典还有其他用途，但我们最关心的是`'console_scripts'`键。这个键指向一个字符串列表，指定我们想要设置为命令行脚本的函数。这些字符串的格式如下：

```py
'command_name = module.submodule:function'
```

您可以添加尽可能多的控制台脚本；它们只需要指向包中可以直接运行的函数或方法。请注意，您*必须*在这里指定一个实际的可调用对象；您不能只是指向一个要运行的 Python 文件。这就是为什么我们将所有执行代码放在`__main__.py`中的`main()`函数下的原因。

`setuptools`包含许多其他指令，用于处理不太常见的情况；有关完整列表，请参阅[`setuptools.readthedocs.io/en/latest/setuptools.html`](https://setuptools.readthedocs.io/en/latest/setuptools.html)。

# 源码分发

现在`setup.py`已经准备就绪，我们可以使用它来实际创建我们的软件包分发。软件包分发有两种基本类型：`源码`和`构建`。在本节中，我们将讨论如何使用**源码分发**。

源码分发是我们构建项目所需的所有源代码和额外文件的捆绑包。它包括`setup.py`文件，并且对于以跨平台方式分发您的项目非常有用。

# 创建源码分发

要构建源码分发，打开项目根目录中的命令提示符，并输入以下命令：

```py
$ python3 setup.py sdist
```

这将创建一些目录和许多文件：

+   `ProjectName.egg-info`目录（在我们的情况下是`QTicTacToe.egg-info`目录）将包含从我们的`setup.py`参数生成的几个元数据文件。

+   `dist`目录将包含包含我们分发的`tar.gz`存档文件。我们的文件名为`QTicTacToe-1.0.tar.gz`。

花几分钟时间来探索`QTicTacToe.egg-info`的内容；您会看到我们在`setup()`中指定的所有信息以某种形式存在。这个目录也包含在源码分发中。

此外，花点时间打开`tar.gz`文件，看看它包含了什么；你会看到我们在`MANIFEST.in`中指定的所有文件，以及`qtictactoe`模块和来自`QTicTacToe.egg-info`的所有文件。基本上，这是我们项目目录的完整副本。

Linux 和 macOS 原生支持`tar.gz`存档；在 Windows 上，您可以使用免费的 7-Zip 实用程序。有关 7-Zip 的信息，请参阅*技术要求*部分。

# 安装源码分发

源分发可以使用`pip`进行安装；为了在一个干净的环境中看到这是如何工作的，我们将在 Python 的**虚拟环境**中安装我们的库。虚拟环境是创建一个隔离的 Python 堆栈的一种方式，您可以在其中独立于系统 Python 安装添加或删除库。

在控制台窗口中，创建一个新目录，然后将其设置为虚拟环境：

```py
$ mkdir test_env
$ virtualenv -p python3 test_env
```

`virtualenv`命令将必要的文件复制到给定目录，以便可以运行 Python，以及一些激活和停用环境的脚本。

要开始使用您的新环境，请运行此命令：

```py
# On Linux and Mac
$ source test_env/bin/activate
# On Windows
$ test_env\Scripts\activate
```

根据您的平台，您的命令行提示可能会更改以指示您处于虚拟环境中。现在当您运行`python`或 Python 相关工具，如`pip`时，它们将在虚拟环境中执行所有操作，而不是在您的系统 Python 中执行。

让我们安装我们的源分发包：

```py
$ pip install QTicTacToe/dist/QTicTacToe-1.0.tar.gz
```

此命令将导致`pip`提取我们的源分发并在项目根目录内执行`python setup.py install`。`install`指令将下载任何依赖项，构建一个入口点可执行文件，并将代码复制到存储 Python 库的目录中（在我们的虚拟环境的情况下，那将是`test_env/lib/python3.7/site-packages/`）。请注意，`PyQt5`的一个新副本被下载；您的虚拟环境中除了 Python 和标准库之外没有安装任何依赖项，因此我们在`install_requires`中列出的任何依赖项都必须重新安装。

在`pip`完成后，您应该能够运行`qtictactoe`命令并成功启动应用程序。该命令存储在`test_env/bin`中，以防您的操作系统不会自动将虚拟环境目录附加到您的`PATH`。

要从虚拟环境中删除包，可以运行以下命令：

```py
$ pip uninstall QTicTacToe
```

这应该清理源代码和所有生成的文件。

# 构建分发

源分发对开发人员至关重要，但它们通常包含许多对最终用户不必要的元素，例如单元测试或示例代码。除此之外，如果项目包含编译代码（例如用 C 编写的 Python 扩展），那么该代码在目标上使用之前将需要编译。为了解决这个问题，`setuptools`提供了各种**构建分发**类型。构建分发提供了一组准备好的文件，只需要将其复制到适当的目录中即可使用。

在本节中，我们将讨论如何使用构建分发。

# 构建分发的类型

创建构建分发的第一步是确定我们想要的构建分发类型。`setuptools`库提供了一些不同的构建分发类型，我们可以安装其他库以添加更多选项。

内置类型如下：

+   **二进制分发**：这是一个`tar.gz`文件，就像源分发一样，但与源分发不同，它包含预编译的代码（例如`qtictactoe`可执行文件），并省略了某些类型的文件（例如测试）。构建分发的内容需要被提取和复制到适当的位置才能运行。

+   **Windows 安装程序**：这与二进制分发类似，只是它是一个在 Windows 上启动安装向导的可执行文件。向导仅用于将文件复制到适当的位置以供执行或库使用。

+   **RPM 软件包管理器**（**RPM**）**安装程序**：再次，这与二进制分发类似，只是它将代码打包在一个 RPM 文件中。RPM 文件被用于几个 Linux 发行版的软件包管理工具（如 Red Hat、CentOS、Suse、Fedora 等）。

虽然您可能会发现这些分发类型在某些情况下很有用，但它们在 2019 年都有点过时；今天分发 Python 的标准方式是使用**wheel 分发**。这些是您在 PyPI 上找到的二进制分发包。

让我们来看看如何创建和安装 wheel 包。

# 创建 wheel 分发

要创建一个 wheel 分发，您首先需要确保从 PyPI 安装了`wheel`库（请参阅*技术要求*部分）。之后，`setuptools`将有一个额外的`bdist_wheel`选项。

您可以使用以下方法创建您的`wheel`文件：

```py
$ python3 setup.py bdist_wheel
```

就像以前一样，这个命令将创建`QTicTacToe.egg-info`目录，并用包含您项目元数据的文件填充它。它还创建一个`build`目录，在那里编译文件被分阶段地压缩成`wheel`文件。

在`dist`下，我们会找到我们完成的`wheel`文件。在我们的情况下，它被称为`QTicTacToe-1.0-py3-none-any.whl`。文件名的格式如下：

+   项目名称（`QTicTacToe`）。

+   版本（1.0）。

+   支持的 Python 版本，无论是 2、3 还是`universal`（`py3`）。

+   `ABI`标签，它表示我们的项目依赖的 Python 二进制接口的特定版本（`none`）。如果我们已经编译了代码，这将被使用。

+   平台（操作系统和 CPU 架构）。我们的是`any`，因为我们没有包含任何特定平台的二进制文件。

二进制分发有三种类型：

+   **通用**类型只有 Python，并且与 Python 2 或 3 兼容

+   **纯 Python**类型只有 Python，但与 Python 2 或 Python 3 兼容

+   **平台**类型包括只在特定平台上运行的已编译代码

正如分发名称所反映的那样，我们的包是纯 Python 类型，因为它不包含已编译的代码，只支持 Python 3。PyQt5 是一个平台包类型的例子，因为它包含为特定平台编译的 Qt 库。

回想一下第十五章，*树莓派上的 PyQt*，我们无法在树莓派上从 PyPI 安装 PyQt，因为 Linux ARM 平台上没有`wheel`文件。由于 PyQt5 是一个平台包类型，它只能安装在已生成此`wheel`文件的平台上。

# 安装构建的分发

与源分发一样，我们可以使用`pip`安装我们的 wheel 文件：

```py
$ pip install qtictactoe/dist/QTicTacToe-1.0-py3-none-any.whl
```

如果您在一个新的虚拟环境中尝试这个，您应该会发现，PyQt5 再次从 PyPI 下载并安装，并且您之后可以使用`qtictactoe`命令。对于像`QTicTacToe`这样的程序，对最终用户来说并没有太大的区别，但对于一个包含需要编译的二进制文件的库（如 PyQt5）来说，这使得设置变得相当不那么麻烦。

当然，即使`wheel`文件也需要目标系统安装了 Python 和`pip`，并且可以访问互联网和 PyPI。这对许多用户或计算环境来说仍然是一个很大的要求。在下一节中，我们将探讨一个工具，它将允许我们从我们的 Python 项目创建一个独立的可执行文件，而无需任何先决条件。

# 使用 PyInstaller 编译

成功编写他们的第一个应用程序后，许多 Python 程序员最常见的问题是*如何将这段代码制作成可执行文件？*不幸的是，对于这个问题并没有一个单一的官方答案。多年来，许多项目已经启动来解决这个任务（例如 Py2Exe、cx_Freeze、Nuitka 和 PyInstaller 等），它们在支持程度、使用简单性和结果一致性方面各有不同。在这些特性方面，目前最好的选择是**PyInstaller**。

# PyInstaller 概述

Python 是一种解释语言；与 C 或 C++编译成机器代码不同，您的 Python 代码（或称为**字节码**的优化版本）每次运行时都会被 Python 解释器读取和执行。这使得 Python 具有一些使其非常易于使用的特性，但也使得它难以编译成机器代码以提供传统的独立可执行文件。

PyInstaller 通过将您的脚本与 Python 解释器以及运行所需的任何库或二进制文件打包在一起来解决这个问题。这些东西被捆绑在一起，形成一个目录或一个单一文件，以提供一个可分发的应用程序，可以复制到任何系统并执行，即使该系统没有 Python。

要查看这是如何工作的，请确保您已经从 PyPI 安装了 PyInstaller（请参阅*技术要求*部分），然后让我们为`QTicTacToe`创建一个可执行文件。

请注意，PyInstaller 创建的应用程序包是特定于平台的，只能在与编译平台兼容的操作系统和 CPU 架构上运行。例如，如果您在 64 位 Linux 上构建 PyInstaller 可执行文件，则它将无法在 32 位 Linux 或 64 位 Windows 上运行。

# 基本的命令行用法

理论上，使用 PyInstaller 就像打开命令提示符并输入这个命令一样简单：

```py
$ pyinstaller my_python_script.py
```

实际上，让我们尝试一下，使用第四章中的`qt_template.py`文件，*使用 QMainWindow 构建应用程序*；将其复制到一个空目录，并在该目录中运行`pyinstaller qt_template.py`。

您将在控制台上获得大量输出，并发现生成了几个目录和文件：

+   `build`和`__pycache__`目录主要包含在构建过程中生成的中间文件。这些文件在调试过程中可能有所帮助，但它们不是最终产品的一部分。

+   `dist`目录包含我们的可分发输出。

+   `qt_template.spec`文件保存了 PyInstaller 生成的配置数据。

默认情况下，PyInstaller 会生成一个包含可执行文件以及运行所需的所有库和数据文件的目录。如果要运行可执行文件，整个目录必须复制到另一台计算机上。

进入这个目录，寻找一个名为`qt_template`的可执行文件。如果运行它，您应该会看到一个空白的`QMainWindow`对象弹出。

如果您更喜欢只有一个文件，PyInstaller 可以将这个目录压缩成一个单独的可执行文件，当运行时，它会将自身提取到临时位置并运行主可执行文件。

这可以通过`--onefile`参数来实现；删除`dist`和`build`的内容，然后运行这个命令：

```py
$ pyinstaller --onefile qt_template.py
```

现在，在`dist`下，您只会找到一个单一的`qt_template`可执行文件。再次运行它，您将看到我们的空白`QMainWindow`。请记住，虽然这种方法更整洁，但它会增加启动时间（因为应用程序需要被提取），并且如果您的应用程序打开本地文件，可能会产生一些复杂性，我们将在下面看到。

如果对代码、环境或构建规范进行了重大更改，最好删除`build`和`dist`目录，可能还有`.spec`文件。

在我们尝试打包`QTicTacToe`之前，让我们深入了解一下`.spec`文件。

# .spec 文件

`.spec`文件是一个 Python 语法的`config`文件，包含了关于我们构建的所有元数据。您可以将其视为 PyInstaller 对`setup.py`文件的回答。然而，与`setup.py`不同，`.spec`文件是自动生成的。这是在我们运行`pyinstaller`时发生的，使用了从我们的脚本和通过命令行开关传递的数据的组合。我们也可以只生成`.spec`文件（而不开始构建）使用`pyi-makespec`命令。

生成后，可以编辑`.spec`文件，然后将其传递回`pyinstaller`，以重新构建分发，而无需每次都指定命令行开关：

```py
$ pyinstaller qt_template.spec
```

要查看我们可能在这个文件中编辑的内容，再次运行`pyi-makespec qt_template.py`，然后在编辑器中打开`qt_template.spec`。在文件内部，您将发现正在创建四种对象：`Analysis`、`PYZ`、`EXE`和`COLLECT`。

`Analysis`构造函数接收有关我们的脚本、数据文件和库的信息。它使用这些信息来分析项目的依赖关系，并生成五个指向应包含在分发中的文件的路径表。这五个表是：

+   `scripts`：作为入口点的 Python 文件，将被转换为可执行文件

+   `pure`：脚本所需的纯 Python 模块

+   `binaries`：脚本所需的二进制库

+   `datas`：非 Python 数据文件，如文本文件或图像

+   `zipfiles`：任何压缩的 Python`.egg`文件

在我们的文件中，`Analysis`部分看起来像这样：

```py
a = Analysis(['qt_template.py'],
             pathex=['/home/alanm/temp/qt_template'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
```

您会看到 Python 脚本的名称、路径和许多空关键字参数。这些参数大多对应于输出表，并用于手动补充分析结果，以弥补 PyInstaller 未能检测到的内容，包括以下内容：

+   `binaries` 对应于`binaries`表。

+   `datas` 对应于`datas`表。

+   `hiddenimports` 对应于`pure`表。

+   `excludes` 允许我们排除可能已自动包含但实际上并不需要的模块。

+   `hookspath` 和 `runtime_hooks` 允许您手动指定 PyInstaller **hooks**；hooks 允许您覆盖分析的某些方面。它们通常用于处理棘手的依赖关系。

接下来创建的对象是`PYZ`对象：

```py
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
```

`PYZ` 对象表示在分析阶段检测到的所有纯 Python 脚本的压缩存档。我们项目中的所有纯 Python 脚本将被编译为字节码（.pyc）文件并打包到这个存档中。

注意`Analysis`和`PYZ`中都有`cipher`参数；这个参数可以使用 AES256 加密进一步混淆我们的 Python 字节码。虽然它不能完全阻止代码的解密和反编译，但如果您计划商业分发，它可以成为好奇心的有用威慑。要使用此选项，请在创建文件时使用`--key`参数指定一个加密字符串，如下所示：

```py
$ pyi-makespec --key=n0H4CK1ngPLZ qt_template.py
```

在`PYZ`部分之后，生成了一个`EXE()`对象：

```py
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='qt_template',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True )
```

`EXE` 对象表示可执行文件。这里的位置参数表示我们要捆绑到可执行文件中的所有文件表。目前，这只是压缩的 Python 库和主要脚本；如果我们指定了`--onefile`选项，其他表（`binaries`、`zipfiles`和`datas`）也会包含在这里。

`EXE`的关键字参数允许我们控制可执行文件的各个方面：

+   `name` 是可执行文件的文件名

+   `debug` 切换可执行文件的调试输出

+   `upx` 切换是否使用**UPX**压缩可执行文件

+   `console` 切换在 Windows 和 macOS 中以控制台或 GUI 模式运行程序；在 Linux 中，它没有效果

UPX 是一个可用于多个平台的免费可执行文件打包工具，网址为[`upx.github.io/`](https://upx.github.io/)。如果您已安装它，启用此参数可以使您的可执行文件更小。

该过程的最后阶段是生成一个`COLLECT`对象：

```py
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='qt_template')
```

这个对象将所有必要的文件收集到最终的分发目录中。它只在单目录模式下运行，其位置参数包括要包含在目录中的组件。我们还可以覆盖文件夹的其他一些方面，比如是否在二进制文件上使用 UPX 以及输出目录的名称。

现在我们对 PyInstaller 的工作原理有了更多的了解，让我们来打包 QTicTacToe。

# 为 PyInstaller 准备 QTicTacToe

PyInstaller 在处理单个脚本时非常简单，但是在处理我们的模块式项目安排时该如何工作呢？我们不能将 PyInstaller 指向我们的模块，因为它会返回一个错误；它需要指向一个作为入口点的 Python 脚本，比如我们的`run.py`文件。

这似乎有效：

```py
$ pyinstaller run.py
```

然而，生成的分发和可执行文件现在被称为`run`，这并不太好。您可能会想要将`run.py`更改为`qtictactoe.py`；事实上，一些关于 Python 打包的教程建议这种安排（即，将`run`脚本与主模块具有相同的名称）。

然而，如果您尝试这样做，您可能会发现出现以下错误：

```py
Traceback (most recent call last):
  File "qtictactoe/__init__.py", line 3, in <module>
    from .mainwindow import MainWindow
ModuleNotFoundError: No module named '__main__.mainwindow'; '__main__' is not a package
[3516] Failed to execute script qtictactoe
```

因为 Python 模块可以是`.py`文件或目录，PyInstaller 无法确定哪一个构成了`qtictactoe`模块，因此两者具有相同的名称将失败。

正确的方法是在创建我们的`.spec`文件或运行`pyinstaller`时使用`--name`开关：

```py
$ pyinstaller --name qtictactoe run.py
# or, to just create the spec file:
# pyi-makespec --name qtictactoe run.py
```

这将创建`qtictactoe.spec`并将`EXE`和`COLLECT`的`name`参数设置为`qtictactoe`，如下所示：

```py
exe = EXE(pyz,
          #...
          name='qtictactoe',
          #...
coll = COLLECT(exe,
               #...
               name='qtictactoe')
```

当然，这也可以通过手动编辑`.spec`文件来完成。

# 处理非 Python 文件

我们的程序运行了，但我们又回到了`'X'`和`'O'`图像不显示的旧问题。这里有两个问题：首先，我们的 PNG 文件没有包含在分发中，其次，即使它们包含在分发中，程序也无法找到它们。

要解决第一个问题，我们必须告诉 PyInstaller 在构建的`Analysis`阶段将我们的文件包含在`datas`表中。我们可以在命令行中这样做：

```py
# On Linux and macOS:
$ pyinstaller --name qtictactoe --add-data qtictactoe/images:images run.py
# On Windows:
$ pyinstaller --name qtictactoe --add-data qtictactoe\images;images run.py
```

`--add-data`参数接受一个源路径和一个目标路径，两者之间用冒号（在 macOS 和 Linux 上）或分号（在 Windows 上）分隔。源路径是相对于我们正在运行`pyinstaller`的项目根目录（在本例中为`QTicTacToe`）的，目标路径是相对于分发根文件夹的。

如果我们不想使用长而复杂的命令行，我们还可以更新`qtictactoe.spec`文件的`Analysis`部分：

```py
a = Analysis(['run.py'],
             #...
             datas=[('qtictactoe/images', 'images')],
```

在这里，源路径和目标路径只是`datas`列表中的一个元组。源值也可以是一个模式，例如`qtictactoe/images/*.png`。如果您使用这些更改运行`pyinstaller qtictactoe.spec`，您应该会在`dist/qtictactoe`中找到一个`images`目录，其中包含我们的 PNG 文件。

这解决了图像的第一个问题，但我们仍然需要解决第二个问题。在*使用 setuptools 进行分发*部分，我们通过使用`__file__`内置变量解决了定位 PNG 文件的问题。但是，当您从 PyInstaller 可执行文件运行时，`__file__`的值*不是*可执行文件的路径；它实际上是一个临时目录的路径，可执行文件在其中解压缩字节码。此目录的位置也会根据我们是处于单文件模式还是单目录模式而改变。为了解决这个问题，我们需要更新我们的代码以检测程序是否已制作成可执行文件，并且如果是，则使用不同的方法来定位文件。

当我们运行 PyInstaller 可执行文件时，PyInstaller 会向`sys`模块添加两个属性来帮助我们：

+   `sys.frozen`属性，其值为`True`

+   `sys._MEIPASS`属性，存储可执行目录的路径

因此，我们可以将我们的代码在`board.py`中更新为以下内容：

```py
        if getattr(sys, 'frozen', False):
            directory = sys._MEIPASS
        else:  # Not frozen
            directory = path.dirname(__file__)
        self.mark_pngs = {
            'X': qtg.QPixmap(path.join(directory, 'images', 'X.png')),
            'O': qtg.QPixmap(path.join(directory, 'images', 'O.png'))
        }
```

现在，在从冻结的 PyInstaller 环境中执行时，我们的代码将能够正确地定位文件。重新运行`pyinstaller qtictactoe.spec`，您应该会发现`X`和`O`图形正确显示。万岁！

如前所述，在 PyQt5 应用程序中更好的解决方案是使用第六章中讨论的 Qt 资源文件，*Styling Qt Applications*。对于非 PyQt 程序，`setuptools`库有一个名为`pkg_resources`的工具可能会有所帮助。

# 进一步调试

如果您的构建继续出现问题，有几种方法可以获取更多关于正在进行的情况的信息。

首先，确保您的代码作为 Python 脚本正确运行。如果在任何模块文件中存在语法错误或其他代码问题，分发将在没有它们的情况下构建。这些遗漏既不会中止构建，也不会在命令行输出中提到。

确认后，检查构建目录以获取 PyInstaller 正在执行的详细信息。在`build/projectname/`下，您应该看到一些文件，可以帮助您进行调试，包括这些：

+   `warn-projectname.txt`：这个文件包含`Analysis`过程输出的警告。其中一些是无意义的（通常只是无法在您的平台上找到特定于平台的库），但如果库有错误或无法找到，这些问题将在这里记录。

+   `.toc`文件：这些文件包含构建过程各阶段创建的目录表；例如，`Analysis-00.toc`显示了`Analysis()`中找到的目录。您可以检查这些文件，看看项目的依赖项是否被错误地识别或从错误的位置提取。

+   `base_library.zip`：此存档应包含您的应用程序使用的所有纯 Python 模块的 Python 字节码文件。您可以检查这个文件，看看是否有任何遗漏。

如果您需要更详细的输出，可以使用`--log-level`开关来增加输出的详细程度到`warn-projectname.txt`。设置为`DEBUG`将提供更多细节：

```py
$ pyinstaller --log-level DEBUG my_project.py
```

更多调试提示可以在[`pyinstaller.readthedocs.io/en/latest/when-things-go-wrong.html`](https://pyinstaller.readthedocs.io/en/latest/when-things-go-wrong.html)找到。

# 总结

在本章中，您学会了如何与他人分享您的项目。您学会了使您的项目目录具有最佳布局，以便您可以与其他 Python 编码人员和 Python 工具进行协作。您学会了如何使用`setuptools`为诸如 PyPI 之类的站点制作可分发的 Python 软件包。最后，您学会了如何使用 PyInstaller 将您的代码转换为可执行文件。

恭喜！您已经完成了这本书。到目前为止，您应该对使用 Python 和 PyQt5 从头开始开发引人入胜的 GUI 应用程序的能力感到自信。从基本的输入表单到高级的网络、数据库和多媒体应用程序，您现在有了创建和分发惊人程序的工具。即使我们涵盖了所有的主题，PyQt 中仍有更多的发现。继续学习，创造伟大的事物！

# 问题

尝试回答这些问题，以测试您从本章中学到的知识：

1.  您已经在一个名为`Scan & Print Tool-box.py`的文件中编写了一个 PyQt 应用程序。您想将其转换为模块化组织形式；您应该做出什么改变？

1.  您的 PyQt5 数据库应用程序有一组包含应用程序使用的查询的`.sql`文件。当您的应用程序是与`.sql`文件在同一目录中的单个脚本时，它可以正常工作，但是现在您已将其转换为模块化组织形式后，无法找到查询。您应该怎么做？

1.  在将新应用程序上传到代码共享站点之前，您正在编写一个详细的`README.rst`文件来记录您的新应用程序。分别应使用哪些字符来下划线标记您的一级、二级和三级标题？

1.  您正在为您的项目创建一个`setup.py`脚本，以便您可以将其上传到 PyPI。您想要包括项目的常见问题解答页面的 URL。您该如何实现这一点？

1.  您在`setup.py`文件中指定了`include_package_data=True`，但由于某种原因，`docs`文件夹没有包含在您的分发包中。出了什么问题？

1.  您运行了`pyinstaller fight_fighter3.py`来将您的新游戏打包为可执行文件。然而出了些问题；您在哪里可以找到构建过程的日志？

1.  尽管名称如此，PyInstaller 实际上不能生成安装程序或包来安装您的应用程序。请为您选择的平台研究一些选项。

# 进一步阅读

有关更多信息，请参阅以下内容：

+   有关`ReStructuredText`标记的教程可以在[`docutils.sourceforge.net/docs/user/rst/quickstart.html`](http://docutils.sourceforge.net/docs/user/rst/quickstart.html)找到。

+   关于设计、构建、文档化和打包 Python GUI 应用程序的更多信息可以在作者的第一本书《Python GUI 编程与 Tkinter》中找到，该书可在 Packt Publications 上获得。

+   如果您有兴趣将软件包发布到 PyPI，请参阅[`blog.jetbrains.com/pycharm/2017/05/how-to-publish-your-package-on-pypi/`](https://blog.jetbrains.com/pycharm/2017/05/how-to-publish-your-package-on-pypi/)了解发布过程的教程。

+   解决在非 PyQt 代码中包含图像的问题的更好方法是`setuptools`提供的`pkg_resources`工具。您可以在[`setuptools.readthedocs.io/en/latest/pkg_resources.html`](https://setuptools.readthedocs.io/en/latest/pkg_resources.html)上了解更多信息。

+   PyInstaller 的高级用法在 PyInstaller 手册中有详细说明，可在[`pyinstaller.readthedocs.io/en/stable/`](https://pyinstaller.readthedocs.io/en/stable/)找到。


# 第十八章：问题的答案

# 第一章

1.  **Qt 是用 C++编写的，这种语言与 Python 非常不同。这两种语言之间有哪些主要区别？在我们使用 Python 中的 Qt 时，这些区别可能会如何体现？**

C++语言的差异以多种方式影响 PyQt，例如：

+   +   它的静态类型和类型安全的函数意味着在某些情况下，PyQt 对可以调用的函数和可以传递的变量相当严格。

+   C++中缺乏内置数据类型意味着 Qt 提供了丰富的数据类型选择，其中许多我们必须在 Python 中使用，因为类型安全。

+   在 C++中常见但在 Python 中很少见的`enum`类型在 Qt 中普遍存在。

1.  GUI 由小部件组成。在计算机上打开一些 GUI 应用程序，尝试识别尽可能多的小部件。

一些例子可能包括以下内容：

+   +   按钮

+   复选框

+   单选按钮

+   标签

+   文本编辑

+   滑块

+   图像区域

+   组合框

1.  **假设以下程序崩溃。找出原因，并修复它以显示一个窗口：**

```py
 from PyQt5.QtWidgets import *
 app = QWidget()
 app.show()
 QApplication().exec()
```

代码应该如下所示：

```py
   from PyQt5.QtWidgets import *

   app = QApplication([])
   window = QWidget()
   window.show()
   app.exe()
```

记住在任何`QWidget`对象之前必须存在一个`QApplication()`对象，并且它必须用列表作为参数创建。

1.  **`QWidget`类有一个名为`statusTip`的属性。以下哪些最有可能是该属性的访问方法的名称：**

1.  1.  `getStatusTip()`和`setStatusTip()`

1.  `statusTip()`和`setStatusTip()`

1.  `get_statusTip()`和`change_statusTip()`

答案**b**是正确的。在大多数情况下，`property`的访问器是`property()`和`setProperty()`。

1.  `QDate`是用于包装日历日期的类。你期望在三个主要的 Qt 模块中的哪一个找到它？

`QDate`在`QtCore`中。`QtCore`保存了与 GUI 不一定相关的数据类型类。

1.  `QFont`是定义屏幕字体的类。你期望在三个主要的 Qt 模块中的哪一个找到它？

`QFont`在`QtGui`中。字体与 GUI 相关，但不是小部件或布局，所以你期望它在`QtGui`中。

1.  **你能使用 Qt Designer 重新创建`hello_world.py`吗？确保设置`windowTitle`。**

基于`QWidget`创建一个新项目。然后选择主窗口小部件，并在属性窗格中设置`windowTitle`。

# 第二章

1.  **你如何创建一个全屏的`QWidget`，没有窗口框架，并使用沙漏光标？**

代码看起来像这样：

```py
   widget = QWidget(cursor=qtc.Qt.WaitCursor)
   widget.setWindowState(qtc.Qt.WindowFullScreen)
   widget.setWindowFlags(qtc.Qt.FramelessWindowHint)
```

1.  假设你被要求为计算机库存数据库设计一个数据输入表单。为以下字段选择最佳的小部件：

+   +   **计算机制造**：公司购买的八个品牌之一

+   **处理器速度**：CPU 速度（GHz）

+   **内存量**：RAM 的数量，以 MB 为单位

+   **主机名**：计算机的主机名

+   **视频制造**：视频硬件是 Nvidia、AMD 还是 Intel

+   **OEM 许可**：计算机是否使用 OEM 许可

这个表格列出了一些可能的答案：

| 字段 | 小部件 | 解释 |
| --- | --- | --- |
| 计算机制造 | `QComboBox` | 用于在许多值列表中进行选择，组合框是理想的选择 |
| 处理器速度 | `QDoubleSpinBox` | 十进制值的最佳选择 |
| 内存量 | `QSpinBox` | 整数值的最佳选择 |
| 主机名 | `QLineEdit` | 主机名只是一个单行文本字符串 |
| 视频制造 | `QComboBox`，`QRadioButton` | 组合框可以工作，但只有三个选择，单选按钮也是一个选项 |
| OEM 许可 | `QCheckBox` | `QCheckBox`是布尔值的一个很好的选择 |

1.  **数据输入表单包括一个需要`XX-999-9999X`格式的`库存编号`字段，其中`X`是从`A`到`Z`的大写字母，不包括`O`和`I`，`9`是从`0`到`9`的数字。你能创建一个验证器类来验证这个输入吗？**

查看示例代码中的`inventory_validator.py`。

1.  查看以下计算器表单：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/1ecc9365-5e6d-40b1-9764-b07adf8f0aff.png)

**可能使用了哪些布局来创建它？**

很可能是一个带有嵌套`QGridLayout`布局的`QVBoxLayout`，用于按钮区域，或者是一个使用列跨度的单个`QGridLayout`布局的前两行。

1.  **参考前面的计算器表单，当表单被调整大小时，你如何使按钮网格占据任何额外的空间？**

在每个小部件上设置`sizePolicy`属性为`QtWidgets.QSizePolicy.Expanding`，垂直和水平都是。

1.  **计算器表单中最顶部的小部件是一个`QLCDNumber`小部件。你能找到关于这个小部件的 Qt 文档吗？它有哪些独特的属性？什么时候会用到它？**

`QLCDNumber`的文档在[`doc.qt.io/qt-5/qlcdnumber.html`](https://doc.qt.io/qt-5/qlcdnumber.html)。它的独特属性是`digitCount`、`intValue`、`mode`、`segmentStyle`、`smallDecimalPoint`和`value`。它适用于显示任何类型的数字，包括八进制、十六进制和二进制。

1.  **从你的模板代码开始，在代码中构建计算器表单。**

在示例代码中查看`calculator_form.py`。

1.  **在 Qt Designer 中构建计算器表单。**

在示例代码中查看`calculator_form.ui`。

# 第三章

1.  **查看下表，并确定哪些连接实际上可以被建立，哪些会导致错误。你可能需要在文档中查找这些信号和槽的签名：**

| # | 信号 | 槽 |
| --- | --- | --- |
| 1 | `QPushButton.clicked` | `QLineEdit.clear` |
| 2 | `QComboBox.currentIndexChanged` | `QListWidget.scrollToItem` |
| 3 | `QLineEdit.returnPressed` | `QCalendarWidget.setGridVisible` |
| 4 | `QLineEdit.textChanged` | `QTextEdit.scrollToAnchor` |

答案如下：

1.  1.  可以，因为`clicked`的布尔参数可以被`clear`忽略

1.  不行，因为`currentIndexChanged`发送的是`int`，但`scrollToItem`期望一个项目和一个滚动提示

1.  不行，因为`returnPressed`不发送任何参数，而`setGridVisible`期望一个参数

1.  可以，因为`textChanged`发送一个字符串，而`scrollToAnchor`接受它

1.  **在信号对象上，`emit()`方法直到信号被绑定（即连接到槽）之前都不存在。重新编写我们第一个`calendar_app.py`文件中的`CategoryWindow.onSubmit()`方法，以防`submitted`未被绑定的可能性。**

我们需要捕获`AttributeError`，像这样：

```py
        def onSubmit(self):
            if self.category_entry.text():
                try:
                    self.submitted.emit(self.category_entry.text())
                except AttributeError:
                    pass
            self.close()
```

1.  **你在 Qt 文档中找到一个对象，它的槽需要`QString`作为参数。你能连接你自定义的信号，发送一个 Python `str`对象吗？**

可以，因为 PyQt 会自动在`QString`和 Python `str`对象之间转换。

1.  **你在 Qt 文档中找到一个对象，它的槽需要`QVariant`作为参数。你可以发送哪些内置的 Python 类型到这个槽？**

任何一个都可以发送。`QVariant`是一个通用对象容器，可以容纳任何其他类型的对象。

1.  **你正在尝试创建一个对话框窗口，它需要时间，并在用户完成编辑数值时发出信号。你试图使用自动槽连接，但你的代码没有做任何事情。确定以下代码缺少什么：**

```py
    class TimeForm(qtw.QWidget):

        submitted = qtc.pyqtSignal(qtc.QTime)

        def __init__(self):
        super().__init__()
        self.setLayout(qtw.QHBoxLayout())
        self.time_inp = qtw.QTimeEdit(self)
        self.layout().addWidget(self.time_inp)

        def on_time_inp_editingFinished(self):
        self.submitted.emit(self.time_inp.time())
        self.destroy()
```

首先，你忘记调用`connectSlotsByName()`。另外，你没有设置`self.time_inp`的对象名称。你的代码应该像这样：

```py
    class TimeForm(qtw.QWidget):

        submitted = qtc.pyqtSignal(qtc.QTime)

        def __init__(self):
            super().__init__()
            self.setLayout(qtw.QHBoxLayout())
            self.time_inp = qtw.QTimeEdit(
                self, objectName='time_inp')
            self.layout().addWidget(self.time_inp)
            qtc.QMetaObject.connectSlotsByName(self)

        def on_time_inp_editingFinished(self):
            self.submitted.emit(self.time_inp.time())
            self.destroy()
```

1.  **你在 Qt Designer 中为一个计算器应用程序创建了一个`.ui`文件，并尝试在代码中让它工作，但是没有成功。你做错了什么？查看以下源代码：**

```py
    from calculator_form import Ui_Calculator

    class Calculator(qtw.QWidget):
        def __init__(self):
            self.ui = Ui_Calculator(self)
            self.ui.setupGUI(self.ui)
            self.show()
```

这里有四个问题：

+   +   首先，你忘记调用`super().__init__()`

+   其次，你将`self`传递给`Ui_Calculator`，它不需要任何参数

+   第三，你调用了`self.ui.setupGUI()`；应该是`self.ui.setupUi()`

+   最后，你将`self.ui`传递给`setupUi()`；你应该传递一个对包含小部件的引用，即`self`

1.  **你正在尝试创建一个新的按钮类，当点击按钮时会发出一个整数值；不幸的是，当你点击按钮时什么也不会发生。查看以下代码并尝试让它工作：**

```py
    class IntegerValueButton(qtw.QPushButton):

        clicked = qtc.pyqtSignal(int)

        def __init__(self, value, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.value = value
            self.clicked.connect(
                lambda: self.clicked.emit(self.value))
```

答案是将`__init__()`的最后一行更改为以下内容：

```py
 super().clicked.connect(
             lambda: self.clicked.emit(self.value))
```

因为我们用自己的信号覆盖了内置的`clicked`属性，`self.clicked`不再指向按钮被点击时发出的信号。我们必须调用`super().clicked`来获得对父类`clicked`信号的引用。

# 第四章

1.  **你想要使用`calendar_app.py`脚本中的`QMainWindow`，来自第三章，*使用信号和槽处理事件*。你会如何进行转换？**

最简单的方法是以下：

+   +   将`MainWindow`重命名为类似`CalendarForm`的东西

+   基于`QMainWindow`创建一个新的`MainWindow`类

+   在`MainWindow`内创建一个`CalendarForm`的实例，并将其设置为中央小部件

1.  **你正在开发一个应用程序，并已将子菜单名称添加到菜单栏，但尚未填充任何子菜单。你的同事说在他测试时他的桌面上没有出现任何菜单名称。你的代码看起来是正确的；这里可能出了什么问题？**

你的同事正在使用一个默认不显示空菜单文件夹的平台（如 macOS）。

1.  **你正在开发一个代码编辑器，并希望创建一个侧边栏面板与调试器进行交互。哪个`QMainWindow`特性对这个任务最合适？**

`QDockWidget`是最合适的，因为它允许你将任何类型的小部件构建到可停靠窗口中。工具栏不是一个好选择，因为它主要设计用于按钮。

1.  **以下代码无法正常工作；无论点击什么都会继续。为什么它不起作用，你如何修复它？**

```py
    answer = qtw.QMessageBox.question(
        None, 'Continue?', 'Run this program?')
    if not answer:
        sys.exit()
```

`QMessageBox.question()`不返回布尔值；它返回与点击的按钮类型匹配的常量。匹配`No`按钮的常量的实际整数值是`65536`，在 Python 中评估为`True`。代码应该如下所示：

```py
    answer = qtw.QMessageBox.question(
        None, 'Continue?', 'Run this program?')
    if answer == qtw.QMessageBox.No:
        sys.exit()
```

1.  **你正在通过子类化`QDialog`来构建一个自定义对话框。你需要将对话框中输入的信息传递回主窗口对象。以下哪种方法不起作用？**

+   1.  **传入一个可变对象，并使用对话框的`accept()`方法来改变它的值。**

1.  **覆盖对象的`accept()`方法，并使其返回输入值的`dict`。**

+   1.  **覆盖对话框的`accepted`信号，使其传递输入值的`dict`。将此信号连接到主窗口类中的回调。**

答案**a**和**c**都可以。答案**b**不行，因为`accept`的返回值在调用`exec()`时对话框没有返回。`exec()`只返回一个布尔值，指示对话框是被接受还是被拒绝。

1.  **你正在 Linux 上开发一个名为 SuperPhoto 的照片编辑器。你已经编写了代码并保存了用户设置，但是在`~/.config/`中找不到`SuperPhoto.conf`。查看代码并确定出了什么问题：**

```py
    settings = qtc.QSettings()
    settings.setValue('config_file', 'SuperPhoto.conf')
    settings.setValue('default_color', QColor('black'))
    settings.sync()
```

`QSettings`使用的配置文件（或在 Windows 上的注册表键）由传递给构造函数的公司名称和应用程序名称确定。代码应该如下所示：

```py
 settings = qtc.QSettings('My Company', 'SuperPhoto')
 settings.setValue('default_color', QColor('black'))
```

另外，注意`sync()`不需要显式调用。它会被 Qt 事件循环自动调用。

1.  **你正在从设置对话框保存偏好设置，但出于某种原因，保存的设置返回的结果非常奇怪。这里有什么问题？看看以下代码：**

```py
    settings = qtc.QSettings('My Company', 'SuperPhoto')
    settings.setValue('Default Name', dialog.default_name_edit.text)
    settings.setValue('Use GPS', dialog.gps_checkbox.isChecked)
    settings.setValue('Default Color', dialog.color_picker.color)
```

问题在于你实际上没有调用小部件的访问函数。因此，`settings`存储了访问函数的引用。在下一次程序启动时，这些引用是无意义的，因为新的对象被创建在新的内存位置。请注意，如果你保存函数引用，`settings`不会抱怨。

# 第五章

1.  **假设我们有一个设计良好的模型-视图应用程序，以下代码是模型还是视图的一部分？**

```py
  def save_as(self):
    filename, _ = qtw.QFileDialog(self)
    self.data.save_file(filename)
```

这是视图代码，因为它创建了一个 GUI 元素（文件对话框），并似乎回调到可能是一个模型的东西（`self.data`）。

1.  **您能否至少列举两件模型绝对不应该做的事情，以及视图绝对不应该做的两件事情？**

模型绝对不应该做的事情的例子包括创建或直接更改 GUI 元素，为演示格式化数据，或关闭应用程序。视图绝对不应该做的事情的例子包括将数据保存到磁盘，对存储的数据执行转换（如排序或算术），或从模型以外的任何地方读取数据。

1.  `QAbstractTableModel`和`QAbstractTreeModel`都在名称中带有`abstract`。在这种情况下，`abstract`是什么意思？在 C++中，它的含义与 Python 中的含义不同吗？

在任何编程语言中，抽象类是指不打算实例化为对象的类；它们只应该被子类化，并覆盖所需的方法。在 Python 中，这是暗示的，但不是强制的；在 C++中，标记为`abstract`的类将无法实例化。

1.  **以下哪种模型类型——列表、表格或树——最适合以下数据集？**

+   1.  **用户的最近文件**

1.  **Windows 注册表**

1.  **Linux `syslog`记录**

1.  **博客文章**

1.  **个人称谓（例如，先生，夫人或博士）**

1.  **分布式版本控制历史**

虽然有争议，但最有可能的答案如下：

1.  1.  列表

1.  树

1.  表

1.  表

1.  列表

1.  树

1.  **为什么以下代码失败了？**

```py
  class DataModel(QAbstractTreeModel):
    def rowCount(self, node):
      if node > 2:
        return 1
      else:
        return len(self._data[node])
```

`rowCount()`的参数是指向父节点的`QModelIndex`对象。它不能与整数进行比较（`if node > 2`）。

1.  **当插入列时，您的表模型工作不正常。您的`insertColumns()`方法有什么问题？**

```py
    def insertColumns(self, col, count, parent):
      for row in self._data:
        for i in range(count):
          row.insert(col, '')
```

在修改数据之前，您忽略了调用`self.beginInsertColumns()`，并在完成后调用`self.endInsertColumns()`。

1.  **当鼠标悬停时，您希望您的视图显示项目数据作为工具提示。您将如何实现这一点？**

您需要在模型的`data()`方法中处理`QtCore.Qt.TooltipRole`。代码示例如下：

```py
        def data(self, index, role):
            if role in (
                qtc.Qt.DisplayRole,
                qtc.Qt.EditRole,
                qtc.Qt.ToolTipRole
            ):
                return self._data[index.row()][index.column()]
```

# 第六章

1.  **您正在准备分发您的文本编辑器应用程序，并希望确保用户无论使用什么平台，都会默认获得等宽字体。您可以使用哪两种方法来实现这一点？**

第一种方法是将默认字体的`styleHint`设置为`QtGui.QFont.Monospace`。第二种方法是找到一个适当许可的等宽字体，将其捆绑到 Qt 资源文件中，并将字体设置为您捆绑的字体。

1.  **尽可能地，尝试使用`QFont`模仿以下文本：**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/7bcc4ce2-2313-4c4a-81c0-6897c8e32149.png)

代码如下：

```py
   font = qtg.QFont('Times', 32, qtg.QFont.Bold)
   font.setUnderline(True)
   font.setOverline(True)
   font.setCapitalization(qtg.QFont.SmallCaps)
```

1.  **您能解释`QImage`，`QPixmap`和`QIcon`之间的区别吗？**

`QPixmap`和`QImage`都代表单个图像，但`QPixmap`经过优化用于显示，而`QImage`经过优化用于内存中的图像处理。`QIcon`不是单个图像，而是一组可以绑定到小部件或操作状态的图像。

1.  您已经为您的应用程序定义了以下`.qrc`文件，运行了`pyrcc5`，并在脚本中导入了资源库。如何将这个图像加载到`QPixmap`中？

```py
   <RCC>
      <qresource prefix="foodItems">
        <file alias="pancakes.png">pc_img.45234.png</file>
      </qresource>
   </RCC>
```

代码应该如下所示：

```py
   pancakes_pxm = qtg.QPixmap(":/foodItems/pancakes.png")
```

1.  **使用`QPalette`，如何使用`tile.png`图像铺设`QWidget`对象的背景？**

代码应该如下所示：

```py
   widget = qtw.QWidget()
   palette = widget.palette()
   tile_brush = qtg.QBrush(
       qtg.QColor('black'),
       qtg.QPixmap('tile.png')
   )
   palette.setBrush(qtg.QPalette.Window, tile_brush)
   widget.setPalette(palette)
```

1.  **您试图使用 QSS 使删除按钮变成粉色，但没有成功。您的代码有什么问题？**

```py
   deleteButton = qtw.QPushButton('Delete')
   form.layout().addWidget(deleteButton)
   form.setStyleSheet(
      form.styleSheet() + 'deleteButton{ background-color: #8F8; }'
   )
```

您的代码有两个问题。首先，您的`deleteButton`没有分配`objectName`。QSS 对您的 Python 变量名称一无所知；它只知道 Qt 对象名称。其次，您的样式表没有使用`#`符号前缀对象名称。更正后的代码应该如下所示：

```py
   deleteButton = qtw.QPushButton('Delete')
   deleteButton.setObjectName('deleteButton')
   form.layout().addWidget(deleteButton)
   form.setStyleSheet(
      form.styleSheet() + 
      '#deleteButton{ background-color: #8F8; }'
   )
```

1.  **哪种样式表字符串将把您的`QLineEdit`小部件的背景颜色变成黑色？**

```py
   stylesheet1 = "QWidget {background-color: black;}"
   stylesheet2 = ".QWidget {background-color: black;}"
```

`stylesheet1`将把任何`QWidget`子类的背景变成黑色，包括`QLineEdit`。`stylesheet2`只会把实际`QWidget`对象的背景变成黑色；子类将保持不受影响。

1.  **使用下拉框构建一个简单的应用程序，允许您将 Qt 样式更改为系统上安装的任何样式。包括一些其他小部件，以便您可以看到它们在不同样式下的外观。**

在本章的示例代码中查看`question_8_answer.py`。

1.  **您对学习如何为 PyQt 应用程序设置样式感到非常高兴，并希望创建一个`QProxyStyle`类，该类将强制 GUI 中的所有像素图像为`smile.gif`。您会如何做？提示：您需要研究一些`QStyle`的绘图方法，而不是本章讨论的方法。**

该类如下所示：

```py
   class SmileyStyley(qtw.QProxyStyle):

       def drawItemPixmap(
           self, painter, rectangle, alignment, pixmap):
           smile = qtg.QPixmap('smile.gif')
           super().drawItemPixmap(
               painter, rectangle, alignment, smile)
```

1.  **以下动画不起作用；找出为什么不起作用：**

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

简短的答案是`animation`应该是`self.animation`。动画没有父对象，当它们被添加到布局时，它们不会像小部件一样被**重新父化**。因此，当构造函数退出时，`animation`就会超出范围并被销毁。故事的寓意是，保存您的动画作为实例变量。

# 第七章

1.  **使用`QSoundEffect`，您为呼叫中心编写了一个实用程序，允许他们回顾录制的电话呼叫。他们正在转移到一个新的电话系统，该系统将电话呼叫存储为 MP3 文件。您需要对您的实用程序进行任何更改吗？**

是的。您需要使用`QMediaPlayer`而不是`QSoundEffect`，或者编写一个解码 MP3 到 WAV 的层，因为`QSoundEffect`无法播放压缩音频。

1.  `cool_songs`是一个 Python 列表，其中包含您最喜欢的歌曲的路径字符串。要以随机顺序播放这些歌曲，您需要做什么？

您需要将路径转换为`QUrl`对象，将它们添加到`QMediaPlaylist`，将`playbackMode`设置为`Random`，然后将其传递给`QMediaPlayer`。代码如下：

```py
   playlist = qtmm.QMediaPlaylist()
   for song in cool_songs:
       url = qtc.QUrl.fromLocalFile(song)
       content = qtmm.QMediaContent(url)
       playlist.addMedia(content)
   playlist.setPlaybackMode(qtmm.QMediaPlaylist.Random)
   player = qtmm.QMediaPlayer()
   player.setPlaylist(playlist)
   player.play()
```

1.  **您已在系统上安装了`audio/mpeg`编解码器，但以下代码不起作用。找出其中的问题：**

```py
   recorder = qtmm.QAudioRecorder()
   recorder.setCodec('audio/mpeg')
   recorder.record()
```

`QAudioRecorder`没有`setCodec`方法。录制中使用的编解码器设置在`QAudioEncoderSettings`对象上设置。代码应该如下所示：

```py
   recorder = qtmm.QAudioRecorder()
   settings = qtmm.QAudioEncoderSettings()
   settings.setCodec('audio/mpeg')
   recorder.setEncodingSettings(settings)
   recorder.record()
```

1.  在几个不同的 Windows、macOS 和 Linux 系统上运行`audio_test.py`和`video_test.py`。输出有什么不同？有哪些项目在所有系统上都受支持？

答案将取决于您选择的系统。

1.  `QCamera`类的属性包括几个控制对象，允许您管理相机的不同方面。其中之一是`QCameraFocus`。在 Qt 文档中查看`QCameraFocus`，并编写一个简单的脚本，显示取景器并让您调整数字变焦。

在包含的代码示例中查看`question_5_example_code.py`。

1.  **您已经注意到录制到您的船长日志视频日志中的音频相当响亮。您想添加一个控件来调整它；您会如何做？**

`QMediaRecorder`有一个`volume()`插槽，就像`QAudioRecorder`一样。您需要创建一个`QSlider`（或任何其他控件小部件），并将其`valueChanged`或`sliderMoved`信号连接到录制器的`volume()`插槽。

1.  **在`captains_log.py`中实现一个停靠窗口小部件，允许您控制尽可能多的音频和视频录制方面。您可以包括焦点、缩放、曝光、白平衡、帧速率、分辨率、音频音量、音频质量等内容。**

这里就靠你自己了！

# 第八章

1.  **您正在设计一个应用程序，该应用程序将向本地网络发出状态消息，您将使用管理员工具进行监控。哪种类型的套接字对象是一个不错的选择？**

在这里最好使用`QUdpSocket`，因为它允许广播数据包，并且状态数据包不需要 TCP 的开销。

1.  您的 GUI 类有一个名为`self.socket`的`QTcpSocket`对象。您已经将其`readyRead`信号连接到以下方法，但它没有起作用。发生了什么，您该如何修复它？

```py
       def on_ready_read(self):
           while self.socket.hasPendingDatagrams():
               self.process_data(self.socket.readDatagram())
```

`QTcpSocket`没有`hasPendingDatagrams()`或`readDatagram()`方法。TCP 套接字使用数据流而不是数据包。这个方法需要重写以使用`QDataStream`对象提取数据。

1.  使用`QTcpServer`实现一个简单的服务，监听端口`8080`并打印接收到的任何请求。让它用您选择的字节字符串回复客户端。

在示例代码中查看`question_3_tcp_server.py`。通过运行脚本并将 Web 浏览器指向[`localhost:8080`](http://localhost:8080)来进行测试。

1.  您正在为应用程序创建一个下载函数，以便检索一个大型数据文件以导入到您的应用程序中。代码不起作用。阅读代码并决定您做错了什么：

```py
       def download(self, url):
        self.manager = qtn.QNetworkAccessManager(
            finished=self.on_finished)
        self.request = qtn.QNetworkRequest(qtc.QUrl(url))
        reply = self.manager.get(self.request)
        with open('datafile.dat', 'wb') as fh:
            fh.write(reply.readAll())
```

您试图同步使用`QNetworkAccessManager.get()`，但它是设计用于异步使用的。您需要连接一个回调到网络访问管理器的`finished`信号，而不是从`get()`中检索回复对象，它携带完成的回复。

1.  修改您的`poster.py`脚本，以便将键值数据发送为 JSON，而不是 HTTP 表单数据。

在示例代码中查看`question_5_json_poster.py`文件。

# 第九章

1.  编写一个 SQL `CREATE`语句，用于构建一个表来保存电视节目表。确保它具有日期、时间、频道和节目名称的字段。还要确保它具有主键和约束，以防止无意义的数据（例如在同一频道上同时播放两个节目，或者一个节目没有时间或日期）。

一个示例可能如下所示：

```py
   CREATE TABLE tv_schedule AS (
       id INTEGER PRIMARY KEY,
       channel TEXT NOT NULL,
       date DATE NOT NULL,
       time TIME NOT NULL,
       program TEXT NOT NULL,
       UNIQUE(channel, date, time)
   )
```

1.  以下 SQL 查询返回语法错误；您能修复它吗？

```py
DELETE * FROM my_table IF category_id == 12;
```

这里有几个问题：

+   +   `DELETE`不接受字段列表，因此必须删除`*`。

+   `IF`是错误的关键字。它应该使用`WHERE`。

+   `==`不是 SQL 运算符。与 Python 不同，SQL 使用单个`=`进行赋值和比较操作。

生成的 SQL 应该如下所示：

```py
   DELETE FROM my_table WHERE category_id = 12;
```

1.  以下 SQL 查询不正确；您能修复它吗？

```py
INSERT INTO flavors(name) VALUES ('hazelnut', 'vanilla', 'caramel', 'onion');
```

`VALUES`子句中的每组括号表示一行。由于我们只插入一列，每行应该只有一个值。因此，我们的语句应该如下所示：

```py
   INSERT INTO flavors(name) VALUES ('hazelnut'), ('vanilla'), ('caramel'), ('onion');
```

1.  `QSqlDatabase`的文档可以在[`doc.qt.io/qt-5/qsqldatabase.html`](https://doc.qt.io/qt-5/qsqldatabase.html)找到。详细了解如何使用多个数据库连接，例如对同一数据库进行只读和读写连接。您将如何创建两个连接并对每个连接进行特定的查询？

关键是多次使用唯一连接名称调用`addDatabase()`；一个示例如下：

```py
   db1 = qts.QSqlDatabase.addDatabase('QSQLITE', 'XYZ read-only')
   db1.setUserName('readonlyuser')
   # etc...
   db1.open()
   db2 = qts.QSqlDatabase.addDatabase('QSQLITE', 'XYZ read-write')
   db2.setUserName('readwriteuser')
   # etc...
   db2.open()

   # Keep the database reference for querying:
   query = qts.QSqlQuery('SELECT * FROM my_table', db1)

   # Or retrieve it using its name:
   db = qts.QSqlDatabase.database('XYZ read-write')
   db.exec('INSERT INTO my_table VALUES (1, 2, 3)')
```

1.  使用`QSqlQuery`，编写代码将`dict`对象中的数据安全地插入`coffees`表中：

```py
data = {'brand': 'generic', 'name': 'cheap coffee', 'roast': 
    'light'}
# Your code here:
```

为了安全起见，我们将使用`QSqlQuery`的`prepare()`方法：

```py
   data = {'brand': 'generic', 'name': 'cheap coffee', 'roast': 
       'Light'}
   query = QSqlQuery()
   query.prepare(
       'INSERT INTO coffees(coffee_brand, coffee_name, roast_id) '
       'VALUES (:brand, :name,
       '(SELECT id FROM roasts WHERE description == :roast))'
   )
   query.bindValue(':brand', data['brand'])
   query.bindValue(':name', data['name'])
   query.bindValue(':roast', data['roast'])
   query.exec()
```

1.  您已经创建了一个`QSqlTableModel`对象，并将其附加到`QTableView`。您知道表中有数据，但在视图中没有显示。查看代码并决定问题出在哪里：

```py
flavor_model = qts.QSqlTableModel()
flavor_model.setTable('flavors')
flavor_table = qtw.QTableView()
flavor_table.setModel(flavor_model)
mainform.layout().addWidget(flavor_table)
```

您没有在模型上调用`select()`。在这样做之前，它将是空的。

1.  以下是附加到`QLineEdit`的`textChanged`信号的回调。解释为什么这不是一个好主意：

```py
def do_search(self, text):
    self.sql_table_model.setFilter(f'description={text}')
    self.sql_table_model.select()
```

问题在于您正在接受任意用户输入并将其传递给表模型的`filter()`字符串。这个字符串被直接附加到表模型的内部 SQL 查询中，从而使您的数据库容易受到 SQL 注入。为了使其安全，您需要采取措施来清理`text`或切换 SQL 表模型以使用`prepare()`来创建一个准备好的语句。

1.  您决定在您的咖啡列表的烘焙组合框中使用颜色而不是名称。为了实现这一点，您需要做出哪些改变？

您需要更改`roast_id`上设置的`QSqlRelation`所使用的显示字段为`color`。然后，您需要为`coffee_list`创建一个自定义委托，用于创建颜色图标（参见第六章，*Qt 应用程序的样式*）并在组合框中使用它们而不是文本标签。

# 第十章

1.  创建代码以每十秒调用`self.every_ten_seconds()`方法。

假设我们在一个类的`__init__()`方法中，它看起来像这样：

```py
           self.timer = qtc.QTimer()
           self.timer.setInterval(10000)
           self.timer.timeout.connect(self.every_ten_seconds)
```

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

`QTimer`与`while`循环同步使用。这会创建阻塞代码。可以异步完成相同的操作，如下所示：

```py
   qtc.QTimer.singleShot(1000, run_delayed_command)
```

1.  您创建了以下计算单词数的工作类，并希望将其移动到另一个线程以防止大型文档减慢 GUI。但是，它没有工作；您需要对这个类做出哪些改变？

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

该类依赖于通过共同的父级访问小部件，因为`Worker`类必须由包含小部件的 GUI 类作为父级。您需要更改此类，使以下内容适用：

+   +   它没有父小部件。

+   它以其他方式访问内容，比如通过一个槽。

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

按钮回调指向`Worker.run()`。它应该指向`QThread`对象的`start()`方法。

1.  这个工作类会正确运行吗？如果不会，为什么？

```py
   class Worker(qtc.QRunnable):

       finished = qtc.pyqtSignal()

       def run(self):
           calculate_navigation_vectors(30)
           self.finished.emit()
```

不，`QRunnable`对象不能发出信号，因为它们不是从`QObject`继承的，也没有事件循环。在这种情况下，最好使用`QThread`。

1.  以下代码是一个`QRunnable`类的`run()`方法，用于处理来自科学设备的大型数据文件输出。文件由数百万行空格分隔的数字组成。这段代码可能会被 Python GIL 减慢吗？您能使 GIL 干扰的可能性更小吗？

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

读取文件是一个 I/O 绑定的操作，不需要获取 GIL。但是，进行数学计算和类型转换是一个 CPU 绑定的任务，需要获取 GIL。这可以通过在非 Python 数学库（如 NumPy）中进行计算来减轻。

1.  以下是你正在编写的多线程 TCP 服务器应用程序中`QRunnable`中的`run()`方法。所有线程共享通过`self.datastream`访问的服务器套接字实例。但是，这段代码不是线程安全的。你需要做什么来修复它？

```py
       def run(self):
           message = get_http_response_string()
           message_len = len(message)
           self.datastream.writeUInt32(message_len)
           self.datastream.writeQString(message)
```

由于您不希望两个线程同时写入数据流，您将希望使用`QMutex`来确保只有一个线程可以访问。在定义了一个名为`qmutex`的共享互斥对象之后，代码将如下所示：

```py
       def run(self):
           message = get_http_response_string()
           message_len = len(message)
           with qtc.QMutexLocker(self.qmutex):
               self.datastream.writeUInt32(message_len)
               self.datastream.writeQString(message)
```

# 第十一章

1.  以下 HTML 显示不像您想要的那样。找出尽可能多的错误：

```py
<table>
<thead background=#EFE><th>Job</th><th>Status</th></thead>
<tr><td>Backup</td><font text-color='green'>Success!</font></td></tr>
<tr><td>Cleanup<td><font text-style='bold'>Fail!</font></td></tr>
</table>
```

这里有几个错误：

+   +   `<thead>`部分缺少围绕单元格的`<tr>`标签。

+   在下一行中，第二个单元格缺少开放的`<td>`标签。

+   另外，没有`text-color`属性。它只是`color`。

+   在下一行中，第一个单元格缺少闭合的`</td>`标签。

+   还有没有`text-style`属性。文本应该只是用`<b>`标签包装起来。

1.  以下 Qt HTML 片段有什么问题？

```py
<p>There is nothing <i>wrong</i> with your television <b>set</p></b>
<table><row><data>french fries</data>
<data>$1.99</data></row></table>
<font family='Tahoma' color='#235499'>Can you feel the <strikethrough>love</strikethrough>code tonight?</font>
<label>Username</label><input type='text' name='username'></input>
<img source='://mypix.png'>My picture</img>
```

问题如下：

1.  1.  最后两个闭合标签被切换了。嵌套标签必须在外部标签之前关闭。

1.  没有`<row>`或`<data>`这样的标签。正确的标签应该分别是`<tr>`和`<td>`。

1.  有两个问题——`<font>`没有`family`属性，应该是`face`；另外，没有`<strikethrough>`标签，应该是`<s>`。

1.  Qt 不支持`<label>`或`<input>`标签。此外，`<input>`不使用闭合标签。

1.  `<img>`没有`source`属性；它应该是`src`。它也没有使用闭合标签，也不能包含文本内容。

1.  **这段代码应该实现一个目录。为什么它不能正常工作？**

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

这不是文档锚点的工作方式。正确的代码如下：

```py
   <ul>
     <li><a href='#Section1'>Section 1</a></li>
     <li><a href='#Section2'>Section 2</a></li>
   </ul>
   <a name='Section1'></a>
   <div id=Section1>
     <p>This is section 1</p>
   </div>
   <a name='Section2'></a>
   <div id=Section2>
     <p>This is section 2</p>
   </div>
```

请注意`href`前面的井号(`#`)，表示这是一个内部锚点，以及上面的`<a>`标签，其中包含一个包含部分名称的`name`属性（不包括井号！）。

1.  **使用`QTextCursor`，您需要在文档的右侧添加一个侧边栏。解释一下您将如何做到这一点。**

这样做的步骤如下：

+   1.  创建一个`QTextFrameFormat`对象

1.  将框架格式的`position`属性配置为右浮动

1.  将文本光标定位在根框中

1.  在光标上调用`insertFrame()`，并将框架对象作为第一个参数

1.  使用光标插入方法插入侧边栏内容

1.  **您正在尝试使用`QTextCursor`创建一个文档。它应该有一个顶部和底部框架；在顶部框架中，应该有一个标题，在底部框架中，应该有一个无序列表。请更正此代码，使其实现这一点：**

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

这段代码的主要问题在于它未能正确移动光标，因此内容没有被创建在正确的位置。以下是更正后的代码：

```py
   document = qtg.QTextDocument()
   cursor = qtg.QTextCursor(document)
   top_frame = cursor.insertFrame(qtg.QTextFrameFormat())
   cursor.setPosition(document.rootFrame().lastPosition())
   bottom_frame = cursor.insertFrame(qtg.QTextFrameFormat())

   cursor.setPosition(top_frame.lastPosition())
   cursor.insertText('This is the title')
   # This won't get us to the next frame:
   #cursor.movePosition(qtg.QTextCursor.NextBlock)
   cursor.setPosition(bottom_frame.lastPosition())
   cursor.insertList(qtg.QTextListFormat())
   for i, item in enumerate(('thing 1', 'thing 2', 'thing 3')):
       # don't forget to add a block for each item after the first:
       if i > 0:
           cursor.insertBlock()
       cursor.insertText(item)
```

1.  **您正在创建自己的`QPrinter`子类以在页面大小更改时添加信号。以下代码会起作用吗？**

```py
   class MyPrinter(qtps.QPrinter):

       page_size_changed = qtc.pyqtSignal(qtg.QPageSize)

       def setPageSize(self, size):
           super().setPageSize(size)
           self.page_size_changed.emit(size)
```

不幸的是，不会。因为`QPrinter`不是从`QObject`派生的，所以它不能有信号。您将会收到这样的错误：

```py
   TypeError: MyPrinter cannot be converted to PyQt5.QtCore.QObject in this context
```

1.  **`QtPrintSupport`包含一个名为`QPrinterInfo`的类。使用这个类，在您的系统上打印出所有打印机的名称、制造商和型号以及默认页面大小的列表。**

代码如下：

```py
   for printer in qtps.QPrinterInfo.availablePrinters():
       print(
           printer.printerName(),
           printer.makeAndModel(),
           printer.defaultPageSize())
```

# 第十二章

1.  **在这个方法中添加代码，以在图片底部用蓝色写下您的名字：**

```py
       def create_headshot(self, image_file, name):
           image = qtg.QImage()
           image.load(image_file)
           # your code here

           # end of your code
           return image
```

您的代码将需要创建`QPainter`和`QPen`，然后写入图像：

```py
       def create_headshot(self, image_file, name):
           image = qtg.QImage()
           image.load(image_file)

           # your code here
           painter = qtg.QPainter(image)
           pen = qtg.QPen(qtg.QColor('blue'))
           painter.setPen(pen)
           painter.drawText(image.rect(), qtc.Qt.AlignBottom, name)

           # end of your code
           return image
```

1.  **给定一个名为`painter`的`QPainter`对象，写一行代码在绘图设备的左上角绘制一个 80×80 像素的八边形。参考[`doc.qt.io/qt-5/qpainter.html#drawPolygon`](https://doc.qt.io/qt-5/qpainter.html#drawPolygon)中的文档。**

有几种方法可以创建和绘制多边形，但最简单的方法是将一系列`QPoint`对象传递给`drawPolygon()`：

```py
   painter.drawPolygon(
       qtc.QPoint(0, 20), qtc.QPoint(20, 0),
       qtc.QPoint(60, 0), qtc.QPoint(80, 20),
       qtc.QPoint(80, 60), qtc.QPoint(60, 80),
       qtc.QPoint(20, 80), qtc.QPoint(0, 60)
   )
```

当然，您也可以使用`QPainterPath`对象。

1.  **您正在创建一个自定义小部件，但不知道为什么文本显示为黑色。以下是您的`paintEvent()`方法；看看您能否找出问题所在：**

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

问题在于您设置了`brush`，但文本是用`pen`绘制的。默认的笔是黑色。要解决这个问题，创建一个设置为白色的`pen`，并在绘制文本之前将其传递给`painter.setPen()`。

1.  **油炸模因是一种使用极端压缩、饱和度和其他处理方式的模因风格，使模因图像看起来故意低质量。向您的模因生成器添加一个功能，可选择使模因油炸。您可以尝试的一些方法包括减少颜色位深度和调整图像中颜色的色调和饱和度。**

在这里要有创意，但是可以参考附带源代码中的`question_4_example_code.py`文件。

1.  **您想要对一个圆进行水平移动的动画。在以下代码中，您需要改变什么才能使圆形动起来？**

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

您的`circle`对象不能像现在这样进行动画处理，因为它是一个`QGraphicsItem`。要使用`QPropertyAnimation`对对象的属性进行动画处理，它必须是`QObject`的后代。您需要将您的圆构建为`QGraphicsObject`的子类；然后，您可以对其进行动画处理。

1.  **以下代码有什么问题，它试图使用渐变刷设置`QPainter`？**

```py
   gradient = qtg.QLinearGradient(
       qtc.QPointF(0, 100), qtc.QPointF(0, 0))
   gradient.setColorAt(20, qtg.QColor('red'))
   gradient.setColorAt(40, qtg.QColor('orange'))
   gradient.setColorAt(60, qtg.QColor('green'))
   painter = QPainter()
   painter.setGradient(gradient)
```

这里有两个问题：

1.  1.  `setColorAt`的第一个参数不是像素位置，而是一个表示为浮点数的百分比，介于`0`和`1`之间。

1.  没有`QPainter.setGradient()`方法。渐变必须传递到`QPainter`构造函数中。

1.  看看你是否可以实现以下游戏改进：

+   +   脉动子弹

+   击中坦克时爆炸

+   声音（参见第七章，*使用 QtMultimedia 处理音频-视觉*，在这里寻求帮助）

+   背景动画

+   多个子弹

你自己来吧。玩得开心！

# 第十三章

1.  OpenGL 渲染管线的哪些步骤是可用户定义的？为了渲染任何东西，必须定义哪些步骤？你可能需要参考[`www.khronos.org/opengl/wiki/Rendering_Pipeline_Overview`](https://www.khronos.org/opengl/wiki/Rendering_Pipeline_Overview)上的文档。

顶点处理和片段着色器步骤是可用户定义的。至少，你必须创建一个顶点着色器和一个片段着色器。可选步骤包括几何着色器和镶嵌步骤，这些步骤是顶点处理的一部分。

1.  你正在为一个 OpenGL 2.1 程序编写着色器。以下看起来正确吗？

```py
   #version 2.1

   attribute highp vec4 vertex;

   void main (void)
   {
   gl_Position = vertex;
   }
```

你的版本字符串是错误的。它应该是`#version 120`，因为它指定了 GLSL 的版本，而不是 OpenGL 的版本。版本也被指定为一个没有句号的三位数。

1.  以下是顶点着色器还是片段着色器？你如何判断？

```py
   attribute highp vec4 value1;
   varying highp vec3 x[4];
   void main(void)
   {
     x[0] = vec3(sin(value1[0] * .4));
     x[1] = vec3(cos(value1[1]));
     gl_Position = value1;
     x[2] = vec3(10 * x[0])
   }
```

这是一个顶点着色器；有一些线索：

+   +   它有一个属性变量，它分配给`gl_Position`。

+   它有一个可变变量，它正在分配值。

1.  给定以下顶点着色器，你需要写什么代码来为这两个变量分配简单的值？

```py
   attribute highp vec4 coordinates;
   uniform highp mat4 matrix1;

   void main(void){
     gl_Position = matrix1 * coordinates;
   }
```

假设你的`QOpenGLShaderProgram`对象保存为`self.program`，需要以下代码：

```py
   c_handle = self.program.attributeLocation('coordinates')
   m_handle = self.program.uniformLocation('matrix1')
   self.program.setAttributeValue(c_handle, coordinate_value)
   self.program.setUniformValue(m_handle, matrix)
```

1.  你启用面剔除以节省一些处理能力，但发现你的绘图中的几何体没有渲染。可能出了什么问题？

顶点被以错误的顺序绘制。记住，逆时针绘制一个基元会导致远处的面被剔除；顺时针绘制会导致近处的面被剔除。

1.  以下代码对我们的 OpenGL 图像做了什么？

```py
   matrix = qtg.QMatrix4x4()
   matrix.perspective(60, 4/3, 2, 10)
   matrix.translate(1, -1, -4)
   matrix.rotate(45, 1, 0, 0)
```

单独来看，什么也没有。这段代码只是创建一个 4x4 矩阵，并对其进行一些变换操作。然而，如果我们将其传递到一个应用其值到顶点的着色器中，它将创建一个透视投影，将我们的对象移动到空间中，并旋转图像。实际的`matrix`对象只不过是一组数字的矩阵。

1.  尝试演示，并看看你是否可以添加以下功能中的任何一个：

+   +   一个更有趣的形状（金字塔、立方体等）

+   移动对象的更多控件

+   阴影和光效果

+   在对象中动画形状的变化

你自己来吧！

# 第十四章

1.  考虑以下数据集的描述。你会为每个建议哪种图表样式？

+   1.  按日期的 Web 服务器点击次数

1.  每个销售人员每月的销售数据

1.  去年各公司部门支持票的百分比

1.  豆类植物的产量与植物的高度的图表，几百个植物

答案是主观的，但作者建议以下内容：

1.  1.  线图或样条线图，因为它可以说明交通趋势

1.  条形图或堆叠图，因为这样可以让你比较销售人员的销售情况

1.  饼图，因为它代表一组百分比加起来等于 100

1.  散点图，因为你想展示大量数据的一般趋势

1.  以下代码中哪个图表组件尚未配置，结果会是什么？

```py
   data_list = [
       qtc.QPoint(2, 3),
       qtc.QPoint(4, 5),
       qtc.QPoint(6, 7)]
   chart = qtch.QChart()
   series = qtch.QLineSeries()
   series.append(data_list)
   view = qtch.QChartView()
   view.setChart(chart)
   view.show()
```

轴尚未配置。此图表可以显示，但轴上将没有参考标记，并且可能无法直观地进行缩放。

1.  以下代码有什么问题？

```py
   mainwindow = qtw.QMainWindow()
   chart = qtch.QChart()
   series = qtch.QPieSeries()
   series.append('Half', 50)
   series.append('Other Half', 50)
   mainwindow.setCentralWidget(chart)
   mainwindow.show()
```

`QChart`不是一个小部件，不能添加到布局或设置为中央小部件。它必须附加到`QChartView`。

1.  **你想创建一个比较 Bob 和 Alice 季度销售额的柱状图。需要添加什么代码？（注意这里不需要轴。）**

```py
   bob_sales = [2500, 1300, 800]
   alice_sales = [1700, 1850, 2010]

   chart = qtch.QChart()
   series = qtch.QBarSeries()
   chart.addSeries(series)

   # add code here

   # end code
   view = qtch.QChartView()
   view.setChart(chart)
   view.show()
```

我们需要为 Bob 和 Alice 创建柱状图，并将它们附加到系列中：

```py
   bob_set = qtch.QBarSet('Bob')
   alice_set = qtch.QBarSet('Alice')
   bob_set.append(bob_sales)
   alice_set.append(alice_sales)
   series.append(bob_set)
   series.append(alice_set)
```

1.  **给定一个名为`chart`的`QChart`对象，编写代码使图表具有黑色背景和蓝色数据图。**

为此，设置`backgroundBrush`和`theme`属性：

```py
   chart.setBackgroundBrush(
       qtg.QBrush(qtc.Qt.black))
   chart.setTheme(qtch.QChart.ChartThemeBlueIcy)
```

1.  **使用你在上一个图表中使用的技术来为系统监视器脚本中的另外两个图表设置样式。尝试不同的画刷和笔，看看是否可以找到其他需要设置的属性。**

你现在是自己一个人了！

1.  **`QPolarChart`是`QChart`的一个子类，允许你构建极坐标图。查阅 Qt 文档中关于极坐标图的使用，并看看你是否可以创建一个适当数据集的极坐标图。**

你现在是自己一个人了！

1.  **`psutil.cpu_percent()`接受一个可选参数`percpu`，它将创建一个显示每个 CPU 核心使用信息的值列表。更新你的应用程序以使用这个选项，并分别在一个图表上显示每个 CPU 核心的活动。**

你现在还是自己一个人；不过别担心，你可以做到的！

# 第十五章

1.  **你刚刚购买了一个预装了 Raspbian 的树莓派来运行你的 PyQt5 应用程序。当你尝试运行你的应用程序时，你会遇到一个错误，试图导入`QtNetworkAuth`，而你的应用程序依赖于它。可能的问题是什么？**

可能你的 Raspbian 安装版本是 9。版本 9 具有 Qt 5.7，其中没有`QtNetworkAuth`模块。你需要升级到更新的 Raspbian 版本。

1.  **你为一个传统扫描仪设备编写了一个 PyQt 前端。你的代码通过一个名为`scanutil.exe`的专有驱动程序实用程序与扫描仪通信。它目前在 Windows 10 PC 上运行，但你的雇主希望通过将其移植到树莓派来节省成本。这是一个好主意吗？**

不幸的是，不是这样。如果你的应用程序依赖于专有的 Windows x86 二进制文件，那么该程序将无法在树莓派上运行。要切换到树莓派，你需要一个为 ARM 平台编译的二进制文件，可以在树莓派支持的操作系统之一上运行（此外，该操作系统需要能够运行 Python 和 Qt）。

1.  **你已经获得了一个新的传感器，并想要用树莓派试验它。它有三个连接，标有 Vcc、GND 和 Data。你将如何将其连接到树莓派？你还需要更多的信息吗？**

你真的需要更多的信息，但这里有足够的信息让你开始：

+   +   **Vcc**是输入电压的缩写。你将不得不将其连接到树莓派上的 5V 或 3V3 引脚。你需要查阅制造商的文档，以确定哪种连接方式可行。

+   **GND**意味着地线，你可以将其连接到树莓派上的任何地线引脚。

+   **Data**可能是你想要连接到可编程 GPIO 引脚之一的连接。很可能你需要某种库来使其工作，所以你应该向制造商咨询。

1.  **你试图点亮连接到树莓派左侧第四个 GPIO 引脚的 LED。这段代码有什么问题？**

```py
   GPIO.setmode(GPIO.BCM)
   GPIO.setup(8, GPIO.OUT)
   GPIO.output(8, 1)
```

GPIO 引脚模式设置为`BCM`，这意味着你使用的引脚号错误。将模式设置为`BOARD`，或者使用正确的 BCM 引脚号（`14`）。

1.  **你试图调暗连接到 GPIO 引脚`12`的 LED。这段代码有效吗？**

```py
   GPIO.setmode(GPIO.BOARD)
   GPIO.setup(12, GPIO.OUT)
   GPIO.output(12, 0.5)
```

这段代码不起作用，因为引脚只能是开或关。要模拟半电压，你需要使用脉冲宽度调制，就像下面的例子中所示：

```py
   GPIO.setmode(GPIO.BOARD)
   GPIO.setup(12, GPIO.OUT)
   pwm = GPIO.PWM(12, 60)
   pwm.start(0)
   pwm.ChangeDutyCycle(50)
```

1.  **你有一个带有数据引脚的运动传感器，当检测到运动时会变为`HIGH`。它连接到引脚`8`。以下是你的驱动代码：**

```py
   class MotionSensor(qtc.QObject):

       detection = qtc.pyqtSignal()

       def __init__(self):
           super().__init__()
           GPIO.setmode(GPIO.BOARD)
           GPIO.setup(8, GPIO.IN)
           self.state = GPIO.input(8)

       def check(self):
           state = GPIO.input(8)
           if state and state != self.state:
               detection.emit()
           self.state = state
```

**你的主窗口类创建了一个`MotionSensor`对象，并将其`detection`信号连接到一个回调方法。然而，没有检测到任何东西。缺少了什么？**

您没有调用`MotionSensor.check()`。您应该通过添加一个调用`check()`的`QTimer`对象来实现轮询。

1.  **以创造性的方式结合本章中的两个电路；例如，您可以创建一个根据湿度和温度改变颜色的灯。**

这里就靠你自己了！

# 第十六章

1.  **以下代码给出了一个属性错误；怎么了？**

```py
   from PyQt5 import QtWebEngine as qtwe
   w = qtwe.QWebEngineView()
```

您想要导入`QtWebEngineWidgets`，而不是`QtWebEngine`。后者用于与 Qt 的 QML 前端一起使用。

1.  **以下代码应该将`UrlBar`类与`QWebEngineView`连接起来，以便在按下*返回*/*Enter*键时加载输入的 URL。但是它不起作用；怎么了？**

```py
   class UrlBar(qtw.QLineEdit):

       url_request = qtc.pyqtSignal(str)

       def __init__(self):
           super().__init__()
           self.returnPressed.connect(self.request)

       def request(self):
           self.url_request.emit(self.text())

   mywebview = qtwe.QWebEngineView()
   myurlbar = UrlBar()
   myurlbar.url_request(mywebview.load)
```

`QWebEngineView.load()`需要一个`QUrl`对象，而不是一个字符串。`url_request`信号将栏的文本作为字符串直接发送到`load()`。它应该首先将其包装在`QUrl`对象中。

1.  **以下代码的结果是什么？**

```py
   class WebView(qtwe.QWebEngineView):

    def createWindow(self, _):

        return self
```

每当浏览器操作请求创建新的选项卡或窗口时，都会调用`QWebEngineView.createWindow()`，并且预计返回一个`QWebEngineView`对象，该对象将用于新窗口或选项卡。通过返回`self`，这个子类强制任何尝试创建新窗口的链接或调用只是在同一个窗口中导航。

1.  **查看[`doc.qt.io/qt-5/qwebengineview.html`](https://doc.qt.io/qt-5/qwebengineview.html)上的`QWebEngineView`文档。您将如何在浏览器中实现缩放功能？**

首先，您需要在`MainWindow`上实现回调函数，以设置当前 Web 视图的`zoomFactor`属性：

```py
   def zoom_in(self):
        webview = self.tabs.currentWidget()
        webview.setZoomFactor(webview.zoomFactor() * 1.1)

    def zoom_out(self):
        webview = self.tabs.currentWidget()
        webview.setZoomFactor(webview.zoomFactor() * .9)
```

然后，在`MainWindow.__init__()`中，您只需要创建控件来调用这些方法：

```py
   navigation.addAction('Zoom In', self.zoom_in)
   navigation.addAction('Zoom Out', self.zoom_out)
```

1.  **顾名思义，`QWebEngineView`表示模型-视图架构中的视图部分。在这个设计中，哪个类代表模型？**

`QWebEnginePage`似乎是这里最清晰的候选者，因为它存储和控制 Web 内容的呈现。

1.  **给定名为`webview`的`QWebEngineView`，编写代码来确定`webview`上是否启用了 JavaScript。**

代码必须查询视图的`QWebEngineSettings`对象，就像这样：

```py
   webview.settings().testAttribute(
       qtwe.QWebEngineSettings.JavascriptEnabled)
```

1.  **您在我们的浏览器示例中看到`runJavaScript()`可以将整数值传递给回调函数。编写一个简单的演示脚本来测试可以返回哪些其他类型的 JavaScript 对象，以及它们在 Python 代码中的显示方式。**

在示例代码中查看`chapter_7_return_value_test.py`。

# 第十七章

1.  **您已经在名为`Scan & Print Tool-box.py`的文件中编写了一个 PyQt 应用程序。您想将其转换为模块样式的组织；您应该做出什么改变？**

脚本的名称应该更改，因为空格、和符号和破折号不是 Python 模块名称中使用的有效字符。例如，您可以将模块名称更改为`scan_and_print_toolbox`。

1.  **您的 PyQt5 数据库应用程序有一组包含应用程序使用的查询的`.sql`文件。当您的应用程序是与`.sql`文件在同一个目录中的单个脚本时，它可以工作，但是现在您已经将其转换为模块样式的组织，就无法找到查询。你应该怎么办？**

最好的做法是将您的`.sql`文件放入 Qt 资源文件中，并将其作为 Python 模块的一部分。如果无法使用 Qt 资源文件，您将需要使用`path`模块和内置的`file`变量将相对路径转换为绝对路径

1.  **在将新应用程序上传到代码共享站点之前，您正在编写一个详细的`README.rst`文件来记录您的新应用程序。分别应该使用哪些字符来标记您的一级、二级和三级标题？**

实际上并不重要，只要使用可接受字符列表中的字符即可：

```py
   = - ` : ' " ~ ^ _ * + # < >
```

RST 解释器应该考虑遇到的第一个标题字符表示一级；第二个表示二级；第三个表示三级。

1.  您正在为您的项目创建一个`setup.py`脚本，以便您可以将其上传到 PyPI。您想要包括项目的 FAQ 页面的 URL。您该如何实现这一点？

您需要向`project_urls`字典中添加一个`key: value`对，就像这样：

```py
   setup(
       project_urls={
           'Project FAQ': 'https://example.com/faq',
       }
   )
```

1.  您在`setup.py`文件中指定了`include_package_data=True`，但由于某种原因，`docs`文件夹没有包含在您的分发包中。出了什么问题？

`include_package_data`只影响包（模块）内的数据文件。如果您想要包括模块外的文件，您需要使用`MANIFEST.in`文件。

1.  您运行了`pyinstaller fight_fighter3.py`来将您的新游戏打包为可执行文件。不过出了些问题；您可以在哪里找到构建过程的日志？

首先，您需要查看`build/fight_fighter3/warn-fight_fighter3.txt`。您可能需要通过使用`--log-level DEBUG`参数调用 PyInstaller 来增加调试输出。

1.  尽管名字是这样，但 PyInstaller 实际上不能生成安装程序或包来安装您的应用程序。研究一些适合您平台的选项。

您需要自己解决这个问题，尽管一个流行的选项是**Nullsoft Scriptable Install System**（**NSIS**）。
