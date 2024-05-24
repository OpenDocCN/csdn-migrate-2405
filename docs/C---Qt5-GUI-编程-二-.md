# C++ Qt5 GUI 编程（二）

> 原文：[`annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed`](https://annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：集成网络内容

在上一章中，我们学习了如何在 Qt 中使用项目视图和对话框。在这一章中，我们将学习如何将网络内容集成到我们的 Qt 应用程序中。

从 90 年代末和 21 世纪初的互联网时代开始，我们的世界变得越来越被互联网连接。自然地，运行在我们计算机上的应用程序也朝着这个方向发展。如今，我们大多数——如果不是全部——的软件在某种程度上都与互联网连接，通常是为了检索有用的信息并将其显示给用户。最简单的方法是将网络浏览器显示（也称为网络视图）嵌入到应用程序的用户界面中。这样，用户不仅可以查看信息，而且可以以美观的方式进行查看。

通过使用网络视图，开发人员可以利用其渲染能力，并使用**HTML**（超文本标记语言）和**CSS**（层叠样式表）的强大组合来装饰他们的内容。在这一章中，我们将探索 Qt 的 web 引擎模块，并创建我们自己的网络浏览器。

在这一章中，我们将涵盖以下主题：

+   创建你自己的网络浏览器

+   会话、cookie 和缓存

+   集成 JavaScript 和 C++

话不多说，让我们看看如何在 Qt 中创建我们自己的网络浏览器！

# 创建你自己的网络浏览器

从前，Qt 使用一个名为**WebKit**的不同模块在其用户界面上渲染网络内容。然而，自 5.5 版本以来，WebKit 模块已完全被弃用，并被一个名为**WebEngine**的新模块所取代。

新的 WebEngine 模块是基于谷歌构建的**Chromium**框架，它只能在 Windows 平台上的**Visual C++**编译器上运行。因此，如果你在运行 Windows，确保你已经在你的计算机上安装了**Microsoft Visual Studio**以及与你的计算机上安装的 Visual Studio 版本匹配的 Qt 的**MSVC**组件。除此之外，这个特定章节还需要 Qt WebEngine 组件。如果你在 Qt 的安装过程中跳过了这些组件，你只需要再次运行相同的安装程序并在那里安装它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/02f1ed42-5efc-43a4-b0d7-40c1610c382e.png)

# 添加网络视图小部件

一旦你准备好了，让我们开始吧！首先，打开 Qt Creator 并创建一个新的 Qt Widgets 应用程序项目。之后，打开项目（`.pro`）文件并添加以下文本以启用模块：

```cpp
QT += core gui webengine webenginewidgets 
```

如果你没有安装 MSVC 组件（在 Windows 上）或 Qt WebEngine 组件，如果你尝试构建项目，此时将会出现错误消息。如果是这种情况，请再次运行 Qt 安装程序。

接下来，打开`mainwindow.h`并添加以下头文件：

```cpp
#ifndef MAINWINDOW_H 
#define MAINWINDOW_H 

#include <QMainWindow> 
#include <QWebEngineView> 
```

之后，打开`mainwindow.h`并添加以下代码：

```cpp
private: 
   Ui::MainWindow *ui; 
 QWebEngineView* webview; 
```

然后，添加以下代码：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   webview = new QWebEngineView(ui->centralWidget); 
   webview->load(QUrl("http://www.kloena.com")); 
} 
```

现在构建并运行程序，你应该看到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d9118fa0-3227-49b7-a2bb-714e581d8784.png)

就是这么简单。你现在已经成功地在你的应用程序上放置了一个网络视图！

我们使用 C++代码创建网络视图的原因是，Qt Creator 使用的默认 Qt Designer 在小部件框中没有网络视图。前面的代码简单地创建了`QWebEngineView`对象，设置了它的父对象（在这种情况下是中央小部件），并在显示网络视图小部件之前设置了网页的 URL。如果你想使用 Qt Designer 在你的 UI 上放置一个 web 引擎视图，你必须运行独立的 Qt Designer，它位于你的 Qt 安装目录中。例如，如果你在 Windows 上运行，它位于`C:QtQt5.10.25.10.2msvc2017_64bin`。请注意，它位于支持 web 引擎的编译器名称的目录中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/0ff18712-2f53-4ce9-a66c-939f467147e6.png)

# 为网络浏览器创建用户界面

接下来，我们将把它变成一个合适的网络浏览器。首先，我们需要添加一些布局小部件，以便稍后可以放置其他小部件。将垂直布局(1)拖放到 centralWidget 上，并从对象列表中选择 centralWidget。然后，点击位于顶部的 Lay Out Vertically 按钮(2)：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/bf92deaf-aeb4-44b2-9ae7-84a690721694.png)

完成后，选择新添加的垂直布局，右键单击，选择 Morph into | QFrame。我们这样做的原因是，我们希望将 web 视图小部件放在这个 QFrame 对象下，而不是中心小部件下。我们必须将布局小部件转换为 QFrame(或任何继承自 QWidget 的)对象，以便它可以*采用*web 视图作为其子对象。最后，将 QFrame 对象重命名为`webviewFrame`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4c9ede35-a9f9-4f09-9158-12a6773bb646.png)

完成后，让我们将水平布局小部件拖放到 QFrame 对象上方。现在我们可以看到水平布局小部件和 QFrame 对象的大小是相同的，我们不希望这样。接下来，选择 QFrame 对象，并将其垂直策略设置为 Expanding：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/41a44341-e29f-4869-be90-c8c26479e052.png)

然后，您会看到顶部布局小部件现在非常窄。让我们暂时将其高度设置为`20`，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/804fd92d-c9dd-4e0c-8085-4f938384d1a4.png)

完成后，将三个按钮拖放到水平布局中，现在我们可以将其顶部边距设置回`0`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/073c8c36-2d6a-4ab1-9c34-a62fdefd8695.png)

将按钮的标签分别设置为`Back`、`Forward`和`Refresh`。您也可以使用图标而不是文本显示在这些按钮上。如果您希望这样做，只需将文本属性设置为空，并从图标属性中选择一个图标。为了简单起见，我们将在本教程中只在按钮上显示文本。

接下来，在三个按钮的右侧放置一个行编辑小部件，然后再添加另一个带有`Go`标签的按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7c621b7f-d77a-4bab-8c9f-a4f45f2ca11c.png)

完成后，右键单击每个按钮，然后选择转到插槽。窗口将弹出，选择 clicked()，然后按 OK。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ba8acc39-41ae-4c97-9b68-464ec3008baa.png)

这些按钮的信号函数将看起来像这样：

```cpp
void MainWindow::on_backButton_clicked() 
{ 
   webview->back(); 
} 

void MainWindow::on_forwardButton_clicked() 
{ 
   webview->forward(); 
} 

void MainWindow::on_refreshButton_clicked() 
{ 
   webview->reload(); 
} 

void MainWindow::on_goButton_clicked() 
{ 
   loadPage(); 
} 
```

基本上，`QWebEngineView`类已经为我们提供了`back()`、`forward()`和`reload()`等函数，所以我们只需在按下相应按钮时调用这些函数。然而，`loadPage()`函数是我们将编写的自定义函数。

```cpp
void MainWindow::loadPage() 
{ 
   QString url = ui->addressInput->text(); 
   if (!url.startsWith("http://") && !url.startsWith("https://")) 
   { 
         url = "http://" + url; 
   } 
   ui->addressInput->setText(url); 
   webview->load(QUrl(url)); 
} 
```

记得在`mainwindow.h`中添加`loadPage()`的声明。

我们不应该只调用`load()`函数，我认为我们应该做更多的事情。通常，用户在输入网页 URL 时不会包括`http://`(或`https://`)方案，但当我们将 URL 传递给 web 视图时，这是必需的。为了解决这个问题，我们会自动检查方案的存在。如果没有找到任何方案，我们将手动将`http://`方案添加到 URL 中。还要记得在开始时调用它来替换`load()`函数：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

 webview = new QWebEngineView(ui->webviewFrame); 
   loadPage(); 
} 
```

接下来，右键单击文本输入，然后选择转到插槽。然后，选择 returnPressed()，点击 OK 按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a722c4f2-e653-4d97-bb37-5547c61835d4.png)

用户在完成输入网页 URL 后，按键盘上的*Return*键时，将调用此插槽函数。从逻辑上讲，用户希望页面开始加载，而不必每次输入 URL 后都要按 Go 按钮。代码非常简单，我们只需调用前面步骤中创建的`loadPage()`函数：

```cpp
void MainWindow::on_addressInput_returnPressed() 
{ 
   loadPage(); 
} 
```

现在我们已经完成了大量的代码，让我们构建并运行我们的项目，看看结果如何：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e0729566-832f-4121-9b6c-d68ddf187c50.png)

显示的结果看起来并不是很好。由于某种原因，新的 Web 视图似乎在扩展大小策略上也无法正确缩放，至少在编写本书时使用的 Qt 版本 5.10 上是如此。这个问题可能会在将来的版本中得到修复，但让我们找到解决这个问题的方法。我所做的是重写主窗口中继承的函数`paintEvent()`。在`mainwindow.h`中，只需添加函数声明，就像这样：

```cpp
public: 
   explicit MainWindow(QWidget *parent = 0); 
   ~MainWindow(); 
 void paintEvent(QPaintEvent *event); 
```

然后，在`mainwindow.cpp`中编写其定义，就像这样：

```cpp
void MainWindow::paintEvent(QPaintEvent *event) 
{ 
   QMainWindow::paintEvent(event); 
   webview->resize(ui->webviewFrame->size()); 
} 
```

当主窗口需要重新渲染其部件时（例如当窗口被调整大小时），Qt 会自动调用`paintEvent()`函数。由于这个函数在应用程序初始化时和窗口调整大小时都会被调用，我们将使用这个函数手动调整 Web 视图的大小以适应其父部件。

再次构建和运行程序，你应该能够让 Web 视图很好地适应，无论你如何调整主窗口的大小。此外，我还删除了菜单栏、工具栏和状态栏，以使整个界面看起来更整洁，因为我们在这个应用程序中没有使用这些功能：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/244f4c48-0ee6-4dab-9873-101bfac0d247.png)

接下来，我们需要一个进度条来显示用户当前页面加载的进度。为此，首先我们需要在 Web 视图下方放置一个进度条部件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d092b79b-87d6-4b15-b1a9-f91c1cfb5e94.png)

然后，在`mainwindow.h`中添加这两个槽函数：

```cpp
private slots: 
   void on_backButton_clicked(); 
   void on_forwardButton_clicked(); 
   void on_refreshButton_clicked(); 
   void on_goButton_clicked(); 
   void on_addressInput_returnPressed(); 
   void webviewLoading(int progress); 
   void webviewLoaded(); 
```

它们在`mainwindow.cpp`中的函数定义如下：

```cpp
void MainWindow::webviewLoading(int progress) 
{ 
   ui->progressBar->setValue(progress); 
} 

void MainWindow::webviewLoaded() 
{ 
   ui->addressInput->setText(webview->url().toString()); 
} 
```

第一个函数`webviewLoading()`简单地从 Web 视图中获取进度级别（以百分比值的形式）并直接提供给进度条部件。

第二个函数`webviewLoaded()`将用 Web 视图加载的网页的实际 URL 替换地址输入框上的 URL 文本。如果没有这个函数，地址输入框在你按下返回按钮或前进按钮后将不会显示正确的 URL。完成后，让我们再次编译和运行项目。结果看起来很棒：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/39428977-f800-4408-bbd9-451b45561382.png)

你可能会问我，如果我不是使用 Qt 制作 Web 浏览器，这有什么实际用途？将 Web 视图嵌入到应用程序中还有许多其他用途，例如，通过精美装饰的 HTML 页面向用户展示产品的最新新闻和更新，这是游戏市场上大多数在线游戏使用的常见方法。例如，流媒体客户端也使用 Web 视图来向玩家展示最新的游戏和折扣。

这些通常被称为混合应用程序，它们将 Web 内容与本地 x 结合在一起，因此你可以利用来自 Web 的动态内容以及具有高性能和一致外观和感觉优势的本地运行的代码。

除此之外，你还可以使用它来以 HTML 格式显示可打印的报告。你可以通过调用`webview->page()->print()`或`webview->page()->printToPdf()`轻松地将报告发送到打印机，或将其保存为 PDF 文件。

要了解更多关于从 Web 视图打印的信息，请查看以下链接：[`doc.Qt.io/Qt-5/qwebenginepage.html#print.`](http://doc.Qt.io/Qt-5/qwebenginepage.html#print)

你可能还想使用 HTML 创建程序的整个用户界面，并将所有 HTML、CSS 和图像文件嵌入到 Qt 的资源包中，并从 Web 视图本地运行。可能性是无限的，唯一的限制是你的想象力！

要了解更多关于 Qt WebEngine 的信息，请查看这里的文档：[`doc.Qt.io/Qt-5/qtwebengine-overview.html.`](https://doc.Qt.io/Qt-5/qtwebengine-overview.html)

# 管理浏览器历史记录

Qt 的 Web 引擎将用户访问过的所有链接存储在一个数组结构中以供以后使用。Web 视图部件使用这个结构通过调用`back()`和`forward()`在历史记录中来回移动。

如果需要手动访问此浏览历史记录，请在`mainwindow.h`中添加以下头文件：

```cpp
#include <QWebEnginePage> 
```

然后，使用以下代码以获取以`QWebEngineHistory`对象形式的浏览历史记录：

```cpp
QWebEngineHistory* history = QWebEnginePage::history(); 
```

您可以从`history->items()`获取访问链接的完整列表，或者使用`back()`或`forward()`等函数在历史记录之间导航。要清除浏览历史记录，请调用`history->clear()`。或者，您也可以这样做：

```cpp
QWebEngineProfile::defaultProfile()->clearAllVisitedLinks();
```

要了解更多关于`QWebEngineHistory`类的信息，请访问以下链接：[`doc.Qt.io/Qt-5/qwebenginehistory.html.`](http://doc.Qt.io/Qt-5/qwebenginehistory.html)

# 会话、cookie 和缓存

与任何其他网络浏览器一样，`WebEngine`模块还支持用于存储临时数据和持久数据的机制，用于会话和缓存。会话和缓存非常重要，因为它们允许网站记住您的上次访问并将您与数据关联，例如购物车。会话、cookie 和缓存的定义如下所示：

+   **会话**：通常，会话是包含用户信息和唯一标识符的服务器端文件，从客户端发送以将它们映射到特定用户。然而，在 Qt 中，会话只是指没有任何过期日期的 cookie，因此当程序关闭时它将消失。

+   **Cookie**：Cookie 是包含用户信息或任何您想要保存的其他信息的客户端文件。与会话不同，cookie 具有过期日期，这意味着它们将保持有效，并且可以在到达过期日期之前检索，即使程序已关闭并重新打开。

+   **缓存**：缓存是一种用于加快页面加载速度的方法，通过在首次加载时将页面及其资源保存到本地磁盘。如果用户在下次访问时再次加载同一页面，Web 浏览器将重用缓存的资源，而不是等待下载完成，这可以显著加快页面加载时间。

# 管理会话和 cookie

默认情况下，`WebEngine`不保存任何 cookie，并将所有用户信息视为临时会话，这意味着当您关闭程序时，您在网页上的登录会话将自动失效。

要在 Qt 的`WebEngine`模块上启用 cookie，首先在`mainwindow.h`中添加以下头文件：

```cpp
#include <QWebEngineProfile> 
```

然后，只需调用以下函数以强制使用持久性 cookie：

```cpp
QWebEngineProfile::defaultProfile()->setPersistentCookiesPolicy(QWebEngineProfile::ForcePersistentCookies);
```

调用上述函数后，您的登录会话将在关闭程序后继续存在。要恢复为非持久性 cookie，我们只需调用：

```cpp
QWebEngineProfile::defaultProfile()->setPersistentCookiesPolicy(QWebEngineProfile::NoPersistentCookies); 
```

除此之外，您还可以更改 Qt 程序存储 cookie 的目录。要做到这一点，请将以下代码添加到您的源文件中：

```cpp
QWebEngineProfile::defaultProfile()->setPersistentStoragePath("your folder");  
```

如果出于某种原因，您想手动删除所有 cookie，请使用以下代码：

```cpp
QWebEngineProfile::defaultProfile()->cookieStore()->deleteAllCookies(); 
```

# 管理缓存

接下来，让我们谈谈缓存。在 Web 引擎模块中，有两种类型的缓存，即内存缓存和磁盘缓存。内存缓存使用计算机的内存来存储缓存，一旦关闭程序就会消失。另一方面，磁盘缓存将所有文件保存在硬盘中，因此它们将在关闭计算机后仍然存在。

默认情况下，Web 引擎模块将所有缓存保存到磁盘，如果需要将它们更改为内存缓存，请调用以下函数：

```cpp
QWebEngineProfile::defaultProfile()->setHttpCacheType(QWebEngineProfile::MemoryHttpCache); 
```

或者，您也可以通过调用完全禁用缓存：

```cpp
QWebEngineProfile::defaultProfile()->setHttpCacheType(QWebEngineProfile::NoCache); 
```

要更改程序保存缓存文件的文件夹，请调用`setCachePath()`函数：

```cpp
QWebEngineProfile::defaultProfile()->setCachePath("your folder"); 
```

最后，要删除所有缓存文件，请调用`clearHttpCache()`：

```cpp
QWebEngineProfile::defaultProfile()->clearHttpCache(); 
```

还有许多其他函数可用于更改与 cookie 和缓存相关的设置。

您可以在以下链接中了解更多信息：[`doc.Qt.io/Qt-5/qwebengineprofile.html`](https://doc.Qt.io/Qt-5/qwebengineprofile.html)

# 集成 JavaScript 和 C++

使用 Qt 的 Web 引擎模块的一个强大功能是它可以从 C++调用 JavaScript 函数，以及从 JavaScript 调用 C++函数。这使它不仅仅是一个 Web 浏览器。您可以使用它来访问 Web 浏览器标准不支持的功能，例如文件管理和硬件集成。这些功能在 W3C 标准中是不可能的；因此，无法在原生 JavaScript 中实现。但是，您可以使用 C++和 Qt 来实现这些功能，然后简单地从 JavaScript 中调用 C++函数。让我们看看如何在 Qt 中实现这一点。

# 从 C++调用 JavaScript 函数

之后，将以下代码添加到我们刚创建的 HTML 文件中：

```cpp
<!DOCTYPE html><html> 
   <head> 
      <title>Page Title</title> 
   </head> 
   <body> 
      <p>Hello World!</p> 
   </body> 
</html> 
```

这些是基本的 HTML 标记，除了显示一行文字`Hello World!`之外，什么也不显示。您可以尝试使用 Web 浏览器加载它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/84001c1c-aabc-4ff1-80bf-b05771ab51cf.png)

之后，让我们返回到我们的 Qt 项目中，然后转到文件|新建文件或项目，并创建一个 Qt 资源文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1d9d3c88-e775-4c5e-bd46-ab54e7a7ab81.png)

然后，打开我们刚创建的 Qt 资源文件，并在 HTML 文件中添加`/html`前缀，然后将 HTML 文件添加到资源文件中，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8c17bb18-d44b-4989-a04d-0e8b7ea3b91e.png)

在资源文件仍然打开的情况下，右键单击`text.html`，然后选择复制资源路径到剪贴板。然后，立即更改您的 Web 视图的 URL：

```cpp
webview->load(QUrl("qrc:///html/test.html")); 
```

您可以使用刚从资源文件中复制的链接，但请确保在链接前面添加 URL 方案`qrc://`。现在构建并运行您的项目，您应该能够立即看到结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3908ba70-8603-4631-bfef-3994e2929583.png)

接下来，我们需要在 JavaScript 中设置一个函数，稍后将由 C++调用。我们将创建一个简单的函数，当调用时弹出一个简单的消息框并将`Hello World!`文本更改为其他内容：

```cpp
<!DOCTYPE html> 
<html> 
   <head> 
         <title>Page Title</title> 
         <script> 
               function hello() 
               { 
                  document.getElementById("myText").innerHTML =       
                  "Something happened!"; 
                  alert("Good day sir, how are you?"); 
               } 
         </script> 
   </head> 
   <body> 
         <p id="myText">Hello World!</p> 
   </body> 
</html> 
```

请注意，我已经为`Hello World!`文本添加了一个 ID，以便我们能够找到它并更改其文本。完成后，让我们再次转到我们的 Qt 项目。

让我们继续向程序 UI 添加一个按钮，当按钮被按下时，我们希望我们的 Qt 程序调用我们刚刚在 JavaScript 中创建的`hello()`函数。在 Qt 中做到这一点实际上非常容易；您只需从`QWebEnginePage`类中调用`runJavaScript()`函数，就像这样：

```cpp
void MainWindow::on_pushButton_clicked() 
{ 
   webview->page()->runJavaScript("hello();"); 
} 
```

结果非常惊人，您可以从以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e860b594-575b-49c9-81dc-922f1dbb9067.png)

您可以做的远不止更改文本或调用消息框。例如，您可以在 HTML 画布中启动或停止动画，显示或隐藏 HTML 元素，触发 Ajax 事件以从 PHP 脚本中检索信息，等等...无限的可能性！

# 从 JavaScript 调用 C++函数

接下来，让我们看看如何从 JavaScript 中调用 C++函数。为了演示，我将在 Web 视图上方放置一个文本标签，并使用 JavaScript 函数更改其文本：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a962a250-b7c4-4945-93ad-ddc7ae12a78b.png)

通常，JavaScript 只能在 HTML 环境中工作，因此只能更改 HTML 元素，而不能更改 Web 视图之外的内容。但是，Qt 允许我们通过使用 Web 通道模块来做到这一点。因此，让我们打开我们的项目（`.pro`）文件并将 Web 通道模块添加到项目中：

```cpp
QT += core gui webengine webenginewidgets webchannel 
```

之后，打开`mainwindow.h`并添加`QWebChannel`头文件：

```cpp
#include <QMainWindow> 
#include <QWebEngineView> 
#include <QWebChannel> 
```

同时，我们还声明一个名为`doSomething()`的函数，并在其前面加上`Q_INVOKABLE`宏：

```cpp
Q_INVOKABLE void doSomething(); 
```

`Q_INVOKABLE`宏告诉 Qt 将函数暴露给 JavaScript 引擎，因此该函数可以从 JavaScript（以及 QML，因为 QML 也基于 JavaScript）中调用。

然后在`mainwindow.cpp`中，我们首先需要创建一个`QWebChannel`对象，并将我们的主窗口注册为 JavaScript 对象。只要从`QObject`类派生，就可以将任何 Qt 对象注册为 JavaScript 对象。

由于我们将从 JavaScript 中调用`doSomething（）`函数，因此我们必须将主窗口注册到 JavaScript 引擎。之后，我们还需要将刚刚创建的`QWebChannel`对象设置为我们的 web 视图的 web 通道。代码如下所示：

```cpp
QWebChannel* channel = new QWebChannel(this); 
channel->registerObject("mainwindow", this); 
webview->page()->setWebChannel(channel); 
```

完成后，让我们定义`doSomething（）`函数。我们只是做一些简单的事情——改变我们的 Qt GUI 上的文本标签，就这样：

```cpp
void MainWindow::doSomething() 
{ 
   ui->label->setText("This text has been changed by javascript!"); 
} 
```

我们已经完成了 C++代码，让我们打开 HTML 文件。我们需要做一些事情才能使其工作。首先，我们需要包含默认嵌入在 Qt 程序中的`qwebchannel.js`脚本，这样您就不必在 Qt 目录中搜索该文件。在`head`标签之间添加以下代码：

```cpp
<script type="text/javascript" src="img/qwebchannel.js"></script> 
```

然后，在 JavaScript 中，当文档成功被 web 视图加载时，我们创建一个`QWebChannel`对象，并将`mainwindow`变量链接到之前在 C++中注册的实际主窗口对象。这一步必须在网页加载后才能完成（通过`window.onload`回调）；否则，可能会出现创建 web 通道的问题：

```cpp
var mainwindow; 
window.onload = function() 
{ 
   new QWebChannel(Qt.webChannelTransport,function(channel) 
   { 
         mainwindow = channel.objects.mainwindow; 
   }); 
} 
```

之后，我们创建一个调用`doSomething（）`函数的 JavaScript 函数：

```cpp
function myFunction() 
{ 
   mainwindow.doSomething(); 
} 
```

最后，在 HTML 主体中添加一个按钮，并确保在按下按钮时调用`myFunction（）`：

```cpp
<body> 
   <p id="myText">Hello World!</p> 
   <button onclick="myFunction()">Do Something</button> 
</body> 
```

现在构建并运行程序，您应该能够获得以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/eebf2409-5486-476d-b772-06ec44cbed98.png)

除了更改 Qt 小部件的属性之外，您可以使用此方法做很多有用的事情。例如，将文件保存到本地硬盘，从条形码扫描仪获取扫描数据等。本地和 Web 技术之间不再有障碍。但是，请格外注意此技术可能带来的安全影响。正如古话所说：

“伟大的力量带来伟大的责任。”

# 摘要

在本章中，我们已经学会了如何创建自己的网络浏览器，并使其与本地代码交互。Qt 为我们提供了 Web 通道技术，使 Qt 成为软件开发的一个非常强大的平台。

它充分利用了 Qt 的强大功能和 Web 技术的美感，这意味着在开发时你可以有更多的选择，而不仅仅局限于 Qt 的方法。我非常兴奋，迫不及待地想看看你能用这个技术实现什么！

加入我们的下一章，学习如何创建一个类似 Google Maps 的地图查看器，使用 Qt！


# 第七章：地图查看器

用户位置和地图显示是如今变得更加常见的两个功能，已经被用于各种类型的应用程序。它们通常用于后端分析和前端显示目的。

地图查看器可用于导航、附近的兴趣点查找、基于位置的服务（如叫出租车）等等。你可以使用 Qt 来实现大部分功能，但如果你要做更复杂的东西，就需要一个先进的数据库系统。

在上一章中，我们学习了如何将 Web 浏览器嵌入到应用程序中。在本章中，我们将尝试一些更有趣的东西，涵盖以下主题：

+   创建地图显示

+   标记和形状显示

+   获取用户位置

+   地理路由请求

让我们继续创建我们自己的地图查看器！

# 地图显示

Qt 位置模块为开发者提供了地理编码和导航信息的访问权限。它还可以允许用户进行地点搜索，需要从服务器或用户设备中检索数据。

目前，Qt 的地图视图不支持 C++，只支持 QML。这意味着我们只能使用 QML 脚本来改变与可视化相关的任何内容——显示地图，添加标记等等；另一方面，我们可以使用模块提供的 C++类来从数据库或服务提供商获取信息，然后通过 QML 将其显示给用户。

简单来说，**QML**（**Qt 建模语言**）是用于 Qt Quick 应用程序的用户界面标记语言。由于 QML 由 JavaScript 框架驱动，其编码语法几乎与 JavaScript 相似。如果你需要深入学习 QML 和 Qt Quick，请继续阅读第十四章，*Qt Quick 和 QML*，因为这是一个专门的章节。

有许多教程教你如何使用 Qt Quick 和 QML 语言创建一个完整的地图查看器，但并没有很多教你如何将 C++与 QML 结合使用。让我们开始吧！

# 设置 Qt 位置模块

1.  首先，创建一个新的 Qt Widgets 应用程序项目。

1.  之后，打开项目文件（`.pro`）并将以下模块添加到你的 Qt 项目中：

```cpp
QT += core gui location qml quickwidgets 
```

除了`location`模块，我们还添加了`qml`和`quickwidgets`模块，这些模块是下一节地图显示小部件所需的。这就是我们在项目中启用`Qt Location`模块所需要做的。接下来，我们将继续向项目中添加地图显示小部件。

# 创建地图显示

准备好后，让我们打开`mainwindow.ui`，并移除 menuBar、toolBar 和 statusBar，因为在这个项目中我们不需要这些东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/c0b7b1d8-e5fe-4bcc-a390-a313956cddb6.png)

然后，从小部件框中拖动一个 QQuickWidget 到 UI 画布上。然后，点击画布顶部的水平布局按钮，为其添加布局属性：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/28d2e932-e3fa-4392-a2b3-0426a394ff24.png)

然后，将中央小部件的所有边距属性设置为 0：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3a817668-af69-4e72-9b67-377db36a1240.png)

接下来，我们需要创建一个名为`mapview.qml`的新文件，方法是转到文件 | 新建文件或项目... 然后选择 Qt 类别并选择 QML 文件（Qt Quick 2）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6a51fac1-dd56-4e67-bf24-8ac694b71266.png)

一旦 QML 文件创建完成，打开它并添加以下代码以包含`location`和`positioning`模块，以便稍后可以使用其功能：

```cpp
import QtQuick 2.0 
import QtLocation 5.3 
import QtPositioning 5.0 
```

之后，我们创建一个`Plugin`对象并命名为**osm**（**Open Street Map**），然后创建一个 Map 对象并将插件应用到其`plugin`属性上。我们还将起始坐标设置为（`40.7264175，-73.99735`），这是纽约的某个地方。除此之外，默认的`缩放级别`设置为`14`，足以让我们有一个良好的城市视图：

```cpp
Item 
{ 
    Plugin 
    { 
        id: mapPlugin 
        name: "osm" 
    } 

    Map 
    { 
        id: map 
        anchors.fill: parent 
        plugin: mapPlugin 
        center: QtPositioning.coordinate(40.7264175,-73.99735) 
        zoomLevel: 14 
    } 
} 
```

在我们能够在应用程序上显示地图之前，我们必须先创建一个资源文件并将 QML 文件添加到其中。这可以通过转到文件 | 创建新文件或项目...来完成。然后，选择 Qt 类别并选择 Qt 资源文件。

资源文件创建完成后，添加一个名为`qml`的前缀，并将 QML 文件添加到前缀中，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ccdd7e2f-cb58-4ebd-b4f3-dc5320be49f4.png)

现在我们可以打开`mainwindow.ui`并将 QQuickWidget 的`source`属性设置为`qrc:/qml/mapview.qml`。您还可以点击源属性后面的按钮，直接从资源中选择 QML 文件。

完成后，让我们编译并运行项目，看看我们得到了什么！您也可以尝试使用鼠标在地图上平移和放大缩小：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7151aaa3-59be-4e8a-8dee-883c039e2c05.png)

即使我们可以通过使用 web 视图小部件来实现相同的结果，但这将使我们编写大量的 JavaScript 代码来显示地图。通过使用 Qt Quick，我们只需要编写几行简单的 QML 代码就可以了。

# 标记和形状显示

在前面的部分中，我们成功创建了地图显示，但这只是这个项目的开始。我们需要能够以标记或形状的形式显示自定义数据，以便用户能够理解这些数据。

# 在地图上显示位置标记

如果我告诉你我的最喜欢的餐厅位于（`40.7802655, -74.108644`），你可能无法理解。然而，如果这些坐标以位置标记的形式显示在地图视图上，你会立刻知道它在哪里。让我们看看如何向地图视图添加位置标记！

首先，我们需要一个标记图像，应该看起来像这样，或者更好的是，设计你自己的标记：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/04d42016-db00-4884-a2c8-0c8edfb9052d.png)

之后，我们需要将这个图像注册到我们项目的资源文件中。用 Qt Creator 打开`resource.qrc`，创建一个名为`images`的新前缀。然后，将标记图像添加到新创建的前缀中。确保图像具有透明背景，以便在地图上显示良好。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/935d7d97-990d-4453-a247-1a9a05867f34.png)

接下来，打开`mapview.qml`并用以下代码替换原来的代码：

```cpp
Item 
{ 
    id: window 

    Plugin 
    { 
        id: mapPlugin 
        name: "osm" 
    } 

    Image 
    { 
        id: icon 
        source: "qrc:///images/map-marker-icon.png" 
        sourceSize.width: 50 
        sourceSize.height: 50 
    } 

    MapQuickItem 
    { 
        id: marker 
        anchorPoint.x: marker.width / 4 
        anchorPoint.y: marker.height 
        coordinate: QtPositioning.coordinate(40.7274175,-73.99835) 

        sourceItem: icon 
    } 

    Map 
    { 
        id: map 
        anchors.fill: parent 
        plugin: mapPlugin 
        center: QtPositioning.coordinate(40.7264175,-73.99735) 
        zoomLevel: 14 

        Component.onCompleted: 
        { 
            map.addMapItem(marker) 
        } 
    } 
} 
```

在上面的代码中，我们首先添加了一个图像对象，它将用作标记的图像。由于原始图像非常庞大，我们必须通过将`sourceSize`属性设置为`50x50`来调整其大小。我们还必须将标记图像的锚点设置为图像的`中心底部`，因为那是标记的尖端所在的位置。

之后，我们创建一个`MapQuickItem`对象，它将作为标记本身。将标记图像设置为`MapQuickItem`对象的`sourceItem`，然后通过调用`map.addMapItem()`将标记添加到地图上。这个函数必须在地图创建并准备好显示之后调用，这意味着我们只能在`Component.onCompleted`事件触发后调用它。

现在我们完成了代码，让我们编译并查看结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6977a437-56a1-4f90-bcc9-55b5005d9fda.png)

尽管现在看起来一切都很好，但我们不想在 QML 中硬编码标记。想象一下向地图添加数百个标记，手动使用不同的代码添加每个标记是不可能的。

为了创建一个允许我们动态创建位置标记的函数，我们需要先将标记的 QML 代码从`mapview.qml`中分离出来，放到一个新的 QML 文件中。让我们创建一个名为`marker.qml`的新 QML 文件，并将其添加到资源文件中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2dd8239b-895d-482c-985e-cde898426da4.png)

接下来，从`mapview.qml`中删除`MapQuickItem`和`Image`对象，并将其移动到`marker.qml`中：

```cpp
import QtQuick 2.0 
import QtLocation 5.3 

MapQuickItem 
{ 
    id: marker 
    anchorPoint.x: marker.width / 4 
    anchorPoint.y: marker.height 
    sourceItem: Image 
    { 
        id: icon 
        source: "qrc:///images/map-marker-icon.png" 
        sourceSize.width: 50 
        sourceSize.height: 50 
    } 
} 
```

从上述代码中，您可以看到我已经将`Image`对象与`MapQuickItem`对象合并。坐标属性也已被删除，因为我们只会在将标记放在地图上时设置它。

现在，再次打开`mapview.qml`，并将此函数添加到`Item`对象中：

```cpp
Item 
{ 
    id: window 

    Plugin 
    { 
        id: mapPlugin 
        name: "osm" 
    } 

    function addMarker(latitude, longitude) 
    { 
        var component = Qt.createComponent("qrc:///qml/marker.qml") 
        var item = component.createObject(window, { coordinate: 
        QtPositioning.coordinate(latitude, longitude) }) 
        map.addMapItem(item) 
    } 
```

从上述代码中，我们首先通过加载`marker.qml`文件创建了一个组件。然后，我们通过调用`createObject()`从组件创建了一个对象/项。在`createObject()`函数中，我们将窗口对象设置为其父对象，并将其位置设置为`addMarker()`函数提供的坐标。最后，我们将项目添加到地图中以进行渲染。

每当我们想要创建一个新的位置标记时，我们只需调用这个`addMarker()`函数。为了演示这一点，让我们通过三次调用`addMarker()`来创建三个不同的标记：

```cpp
Map 
{ 
    id: map 
    anchors.fill: parent 
    plugin: mapPlugin 
    center: QtPositioning.coordinate(40.7264175,-73.99735) 
    zoomLevel: 14 

    Component.onCompleted: 
    { 
        addMarker(40.7274175,-73.99835) 
        addMarker(40.7276432,-73.98602) 
        addMarker(40.7272175,-73.98935) 
    } 
} 
```

再次构建和运行项目，您应该能够看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/581d34bc-8dfb-46c4-80e3-fbea4706da85.png)

我们甚至可以进一步为每个标记添加文本标签。要做到这一点，首先打开`marker.qml`，然后添加另一个名为`QtQuick.Controls`的模块：

```cpp
import QtQuick 2.0 
import QtQuick.Controls 2.0 
import QtLocation 5.3 
```

之后，向`MapQuickItem`对象添加一个自定义属性称为`labelText`：

```cpp
MapQuickItem 
{ 
    id: marker 
    anchorPoint.x: marker.width / 4 
    anchorPoint.y: marker.height 
    property string labelText 
```

一旦完成，将其`sourceItem`属性更改为：

```cpp
sourceItem: Item 
{ 
        Image 
        { 
            id: icon 
            source: "qrc:///images/map-marker-icon.png" 
            sourceSize.width: 50 
            sourceSize.height: 50 
        } 

        Rectangle 
        { 
            id: tag 
            anchors.centerIn: label 
            width: label.width + 4 
            height: label.height + 2 
            color: "black" 
        } 

        Label 
        { 
            id: label 
            anchors.centerIn: parent 
            anchors.horizontalCenterOffset: 20 
            anchors.verticalCenterOffset: -12 
            font.pixelSize: 16 
            text: labelText 
            color: "white" 
        } 
} 
```

从上述代码中，我们创建了一个`Item`对象来将多个对象组合在一起。然后，我们创建了一个`Rectangle`对象作为标签背景，以及一个文本的`Label`对象。`Label`对象的`text`属性将链接到`MapQuickItem`对象的`labelText`属性。我们可以为`addMarker()`函数添加另一个输入，用于设置`labelText`属性，如下所示：

```cpp
function addMarker(name, latitude, longitude) 
{ 
        var component = Qt.createComponent("qrc:///qml/marker.qml") 
        var item = component.createObject(window, { coordinate: QtPositioning.coordinate(latitude, longitude), labelText: name }) 
        map.addMapItem(item) 
} 
```

因此，当我们创建标记时，我们可以像这样调用`addMarker()`函数：

```cpp
Component.onCompleted: 
{ 
   addMarker("Restaurant", 40.7274175,-73.99835) 
   addMarker("My Home", 40.7276432,-73.98602) 
   addMarker("School", 40.7272175,-73.98935) 
} 
```

再次构建和运行项目，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8b2f536b-7199-4fd7-bd36-b15745c7e285.png)

相当棒，不是吗？但是，我们还没有完成。由于我们很可能使用 C++通过 Qt 的 SQL 模块从数据库获取数据，我们需要找到一种方法从 C++调用 QML 函数。

为了实现这一点，让我们在`mapview.qml`中注释掉三个`addMarker()`函数，并打开`mainwindow.h`和以下头文件：

```cpp
#include <QQuickItem> 
#include <QQuickView> 
```

之后，打开`mainwindow.cpp`并调用`QMetaObject::invokeMethod()`函数，如下所示：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

 QObject* target = qobject_cast<QObject*>(ui->quickWidget->rootObject()); 
   QString functionName = "addMarker"; 

   QMetaObject::invokeMethod(target, functionName, Qt::AutoConnection, Q_ARG(QVariant, "Testing"), Q_ARG(QVariant, 40.7274175), Q_ARG(QVariant, -73.99835)); 
} 
```

上述代码可能看起来复杂，但如果我们分解并分析每个参数，实际上非常简单。上述函数的第一个参数是我们要从中调用函数的对象，在这种情况下，它是地图视图小部件中的根对象（`mapview.qml`中的`Item`对象）。接下来，我们要告诉要调用的函数名称是什么，它是`addMarker()`函数。之后，第三个参数是信号和槽系统使用的连接类型来调用此方法。对于这一点，我们将让它保持默认设置，即`Qt::AutoConnection`。其余的是`addMarker()`函数所需的参数。我们使用`Q_ARG`宏来指示数据的类型和值。

最后，再次构建和运行应用程序。您将看到一个带有标签的标记已经添加到地图上，但这次是从我们的 C++代码而不是 QML 中调用的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3372e8f3-0227-467a-ba57-3a7033d395e1.png)

# 在地图上显示形状

除了在地图上添加标记，我们还可以在地图上绘制不同类型的形状，以指示感兴趣的区域或作为地理围栏，当目标进入或离开形状覆盖的区域时发出警告。地理围栏是在地图上定义感兴趣区域或虚拟地理边界的多边形形状，用于基于位置的服务。通常，地理围栏用于在设备进入和/或离开地理围栏时触发警报。使用地理围栏的一个很好的例子是当你需要购物提醒时，你可以在超市周围画一个地理围栏，并附上购物清单。当你（和你的手机）进入地理围栏区域时，你将收到一条提醒你要买什么的手机通知。那不是很棒吗？

有关地理围栏的更多信息，请访问：`https://en.wikipedia.org/wiki/Geo-fence`

在本章中，我们不会创建一个功能性的地理围栏，因为这是一个相当高级的话题，通常作为服务器端服务运行，用于检查和触发警报。我们只会使用 Qt 来绘制形状并在屏幕上显示它。

为了在地图视图小部件上绘制形状，我们将为每种类型的形状创建一些新的 QML 文件，并将它们添加到程序的资源中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7ea97aa7-6e6d-4218-8515-adc2ad7578b5.png)

对于每个新创建的 QML 文件，我们将类似于位置标记的操作。对于`circle.qml`，它看起来像这样：

```cpp
import QtQuick 2.0 
import QtLocation 5.3 

MapCircle 
{ 
    property int borderWidth 
    border.width: borderWidth 
} 
```

我们只在这个文件中声明`borderWidth`，因为当调用`createCircle()`函数时，我们可以直接设置其他属性。对于`rectangle.qml`也是一样的：

```cpp
import QtQuick 2.0 
import QtLocation 5.3 

MapRectangle 
{ 
    property int borderWidth 
    border.width: borderWidth 
} 
```

对于`polygon.qml`，重复类似的步骤：

```cpp
import QtQuick 2.0 
import QtLocation 5.3 

MapPolygon 
{ 
    property int borderWidth 
    border.width: borderWidth 
} 
```

如果你愿意，你可以设置其他属性，但为了演示，我们只改变了一些属性，比如颜色、形状和边框宽度。完成后，让我们打开`mapview.qml`并定义一些函数来添加形状：

```cpp
Item 
{ 
    id: window 

    Plugin 
    { 
        id: mapPlugin 
        name: "osm" 
    } 

    function addCircle(latitude, longitude, radius, color, borderWidth) 
    { 
       var component = Qt.createComponent("qrc:///qml/circle.qml") 
       var item = component.createObject(window, { center: 
       QtPositioning.coordinate(latitude, longitude), radius: radius, 
       color: color, borderWidth: borderWidth }) 
       map.addMapItem(item) 
    } 

    function addRectangle(startLat, startLong, endLat, endLong, color, 
    borderWidth) 
    { 
        var component = Qt.createComponent("qrc:///qml/rectangle.qml") 
        var item = component.createObject(window, { topLeft: 
       QtPositioning.coordinate(startLat, startLong), bottomRight: 
       QtPositioning.coordinate(endLat, endLong), color: color, 
       borderWidth: borderWidth }) 
        map.addMapItem(item) 
    } 

    function addPolygon(path, color, borderWidth) 
    { 
        var component = Qt.createComponent("qrc:///qml/polygon.qml") 
        var item = component.createObject(window, { path: path, color: 
        color, borderWidth: borderWidth }) 
        map.addMapItem(item) 
    } 
```

这些函数与`addMarker()`函数非常相似，只是它接受稍有不同的参数，稍后传递给`createObject()`函数。之后，让我们尝试使用前面的函数创建形状：

```cpp
addCircle(40.7274175,-73.99835, 250, "green", 3); 
addRectangle(40.7274175,-73.99835, 40.7376432, -73.98602, "red", 2) 
var path = [{ latitude: 40.7324281, longitude: -73.97602 }, 
            { latitude: 40.7396432, longitude: -73.98666 }, 
            { latitude: 40.7273266, longitude: -73.99835 }, 
            { latitude: 40.7264281, longitude: -73.98602 }]; 
addPolygon(path, "blue", 3); 
```

以下是使用我们刚刚定义的函数创建的形状。我分别调用了每个函数来演示其结果，因此有三个不同的窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/c6a0e1b2-e88a-4a65-b6a0-c5c4ea11274d.png)

# 获取用户位置

Qt 为我们提供了一组函数来获取用户的位置信息，但只有在用户的设备支持地理定位时才能工作。这应该适用于所有现代智能手机，也可能适用于一些现代计算机。 

要使用`Qt Location`模块获取用户位置，首先让我们打开`mainwindow.h`并添加以下头文件：

```cpp
#include <QDebug> 
#include <QGeoPositionInfo> 
#include <QGeoPositionInfoSource> 
```

在同一个文件中声明以下的`slot`函数：

```cpp
private slots: 
   void positionUpdated(const QGeoPositionInfo &info); 
```

就在那之后，打开`mainwindow.cpp`并将以下代码添加到你希望开始获取用户位置的地方。出于演示目的，我只是在`MainWindow`构造函数中调用它：

```cpp
QGeoPositionInfoSource *source = QGeoPositionInfoSource::createDefaultSource(this); 
if (source) 
{ 
   connect(source, &QGeoPositionInfoSource::positionUpdated, 
         this, &MainWindow::positionUpdated); 
   source->startUpdates(); 
} 
```

然后，实现我们之前声明的`positionUpdated()`函数，就像这样：

```cpp
void MainWindow::positionUpdated(const QGeoPositionInfo &info) 
{ 
   qDebug() << "Position updated:" << info; 
} 
```

如果现在构建并运行应用程序，根据你用于运行测试的设备，你可能会或者不会获得任何位置信息。如果你收到这样的调试消息：

```cpp
serialnmea: No serial ports found
Failed to create Geoclue client interface. Geoclue error: org.freedesktop.DBus.Error.Disconnected
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d9095bd8-9aa1-4369-998f-0cc65b69698d.png)

然后你可能需要找一些其他设备进行测试。否则，你可能会得到类似于这样的结果：

```cpp
Position updated: QGeoPositionInfo(QDateTime(2018-02-22 19:13:05.000 EST Qt::TimeSpec(LocalTime)), QGeoCoordinate(45.3333, -75.9))
```

我在这里给你留下一个作业，你可以尝试使用我们迄今为止创建的函数来完成。由于你现在可以获取你的位置坐标，尝试通过在地图显示上添加一个标记来进一步增强你的应用程序。这应该很有趣！

# 地理路由请求

还有一个重要的功能叫做**地理路由请求**，它是一组函数，帮助你绘制从 A 点到 B 点的路线（通常是最短路线）。这个功能需要一个服务提供商；在这种情况下，我们将使用**Open Street Map**（**OSM**），因为它是完全免费的。

请注意，OSM 是一个在线协作项目，这意味着如果你所在地区没有人向 OSM 服务器贡献路线数据，那么你将无法获得准确的结果。作为可选项，你也可以使用付费服务，如 Mapbox 或 ESRI。

让我们看看如何在 Qt 中实现地理路由请求！首先，将以下头文件包含到我们的`mainwindow.h`文件中：

```cpp
#include <QGeoServiceProvider>
#include <QGeoRoutingManager>
#include <QGeoRouteRequest>
#include <QGeoRouteReply>
```

之后，向`MainWindow`类添加两个槽函数，分别是`routeCalculated()`和`routeError()`：

```cpp
private slots:
    void positionUpdated(const QGeoPositionInfo &info);
    void routeCalculated(QGeoRouteReply *reply);
    void routeError(QGeoRouteReply *reply, QGeoRouteReply::Error error, const QString &errorString);
```

完成后，打开`mainwindow.cpp`并在`MainWindow`构造方法中创建一个服务提供商对象。我们将使用 OSM 服务，因此在初始化`QGeoServiceProvider`类时，我们将放置缩写`"osm"`：

```cpp
QGeoServiceProvider* serviceProvider = new QGeoServiceProvider("osm");
```

接着，我们将从刚刚创建的服务提供商对象中获取路由管理器的指针：

```cpp
QGeoRoutingManager* routingManager = serviceProvider->routingManager();
```

然后，将路由管理器的`finished()`信号和`error()`信号与我们刚刚定义的`slot`函数连接起来：

```cpp
connect(routingManager, &QGeoRoutingManager::finished, this, &MainWindow::routeCalculated);
connect(routingManager, &QGeoRoutingManager::error, this, &MainWindow::routeError);
```

当成功请求后，这些槽函数将在服务提供商回复时被触发，或者当请求失败并返回错误消息时被触发。`routeCalculated()`槽函数看起来像这样：

```cpp
void MainWindow::routeCalculated(QGeoRouteReply *reply)
{
    qDebug() << "Route Calculated";
    if (reply->routes().size() != 0)
    {
        // There could be more than 1 path
        // But we only get the first route
        QGeoRoute route = reply->routes().at(0);
        qDebug() << route.path();
    }
    reply->deleteLater();
}
```

正如你所看到的，`QGeoRouteReply`指针包含了服务提供商在成功请求后发送的路线信息。有时它会有多条路线，所以在这个例子中，我们只获取第一条路线并通过 Qt 的应用程序输出窗口显示出来。或者，你也可以使用这些坐标来绘制路径或沿着路线动画移动你的标记。

至于`routeError()`槽函数，我们将只输出服务提供商发送的错误字符串：

```cpp
void MainWindow::routeError(QGeoRouteReply *reply, QGeoRouteReply::Error error, const QString &errorString)
{
    qDebug() << "Route Error" << errorString;
    reply->deleteLater();
}
```

完成后，让我们在`MainWindow`构造方法中发起一个地理路由请求并将其发送给服务提供商：

```cpp
QGeoRouteRequest request(QGeoCoordinate(40.675895,-73.9562151), QGeoCoordinate(40.6833154,-73.987715));
routingManager->calculateRoute(request);
```

现在构建并运行项目，你应该能看到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/849cb2c6-e347-4f25-b95e-743695a488fc.png)

这里有另一个具有挑战性的任务——尝试将所有这些坐标放入一个数组中，并创建一个`addLine()`函数，该函数接受数组并绘制一系列直线，代表地理路由服务描述的路线。

自从 GPS 导航系统发明以来，地理路由一直是最重要的功能之一。希望在完成本教程后，你能够创造出一些有用的东西！

# 摘要

在本章中，我们学习了如何创建类似于谷歌地图的自己的地图视图。我们学习了如何创建地图显示，将标记和形状放在地图上，最后找到用户的位置。请注意，你也可以使用 Web 视图并调用谷歌的 JavaScript 地图 API 来创建类似的地图显示。然而，使用 QML 更简单，轻量级（我们不必加载整个 Web 引擎模块来使用地图），在移动设备和触摸屏上运行得非常好，并且也可以轻松移植到其他地图服务上。希望你能利用这些知识创造出真正令人印象深刻和有用的东西。

在下一章中，我们将探讨如何使用图形项显示信息。让我们继续吧！


# 第八章：Graphics View

在上一章中，我们学习了通过在地图上显示坐标数据来为用户提供视觉呈现的重要性。在本章中，我们将进一步探索使用 Qt 的`Graphics View`框架来表示图形数据的可能性。

在本章中，我们将涵盖以下主题：

+   Graphics View 框架

+   可移动的图形项

+   创建一个组织图表

在本章结束时，你将能够使用 C++和 Qt 的 API 创建一个组织图表显示。让我们开始吧！

# Graphics View 框架

`Graphics View`框架是 Qt 中的小部件模块的一部分，因此它已经默认支持，除非你运行的是 Qt 控制台应用程序，它不需要小部件模块。

在 Qt 中，`Graphics View`视图的工作方式基本上就像一个白板，你可以使用 C/C++代码在上面画任何东西，比如绘制形状、线条、文本，甚至图像。对于初学者来说，这一章可能有点难以理解，但肯定会是一个有趣的项目。让我们开始吧！

# 设置一个新项目

首先，创建一个新的 Qt Widgets 应用程序项目。之后，打开`mainwindow.ui`，将`Graphics View`小部件拖放到主窗口上，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/01a52e3d-f0ef-4e70-b7dd-c390e5edc2b1.png)

然后，通过点击画布顶部的垂直布局按钮为图形视图创建一个布局。之后，打开`mainwindow.h`并添加以下头文件和变量：

```cpp
#include <QGraphicsScene> 
#include <QGraphicsRectItem> 
#include <QGraphicsEllipseItem> 
#include <QGraphicsTextItem> 
#include <QBrush> 
#include <QPen> 

private:
  Ui::MainWindow *ui;
  QGraphicsScene* scene;
```

之后，打开`mainwindow.cpp`。一旦打开，添加以下代码：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   scene = new QGraphicsScene(this); 
   ui->graphicsView->setScene(scene); 

   QBrush greenBrush(Qt::green); 
   QBrush blueBrush(Qt::blue); 
   QPen pen(Qt::black); 
   pen.setWidth(2); 

   QGraphicsRectItem* rectangle = scene->addRect(80, 0, 80, 80, pen, greenBrush); 
   QGraphicsEllipseItem* ellipse = scene->addEllipse(0, -80, 200, 60, pen, blueBrush); 
   QGraphicsTextItem* text = scene->addText("Hello World!", QFont("Times", 25)); 
} 
```

现在构建并运行程序，你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8b6246e1-dedd-4df3-b865-75e323337c8a.png)

代码有点长，所以让我向你解释一下它的作用以及它如何将图形绘制到屏幕上。

正如我之前所说，`Graphics View`小部件就像一个画布或白板，允许你在上面画任何你想要的东西。然而，我们还需要一个叫做 Graphics Scene 的东西，它本质上是一个场景图，它在显示在`Graphics View`上之前以父子层次结构存储所有图形组件。场景图层次结构就像在之前的截图中出现的图像，每个对象都可以有一个链接在一起的父对象或子对象：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/25c1c1d4-4bba-4b7d-9fe3-ec7e109bfcbb.png)

在上面的代码中，我们首先创建了一个`QGraphicsScene`对象，并将其设置为我们的`Graphics View`小部件的 Graphics Scene：

```cpp
scene = new QGraphicsScene(this); 
ui->graphicsView->setScene(scene); 
```

然而，在这个例子中，我们不必将图形项链接在一起，所以我们只需独立创建它们，就像这样：

```cpp
QBrush greenBrush(Qt::green); 
...
QGraphicsTextItem* text = scene->addText("Hello World!", QFont("Times", 25)); 
```

`QPen`和`QBrush`类用于定义这些图形项的渲染样式。`QBrush`通常用于定义项目的背景颜色和图案，而`QPen`通常影响项目的轮廓。

Qt 提供了许多类型的图形项，用于最常见的形状，包括：

+   `QGraphicsEllipseItem` – 椭圆项

+   `QGraphicsLineItem` – 线条项

+   `QGraphicsPathItem` – 任意路径项

+   `QGraphicsPixmapItem` – 图像项

+   `QGraphicsPolygonItem` – 多边形项

+   `QGraphicsRectItem` – 矩形项

+   `QGraphicsSimpleTextItem` – 简单文本标签项

+   `QGraphicsTextItem` – 高级格式化文本项

更多信息，请访问此链接：[`doc.qt.io/archives/qt-5.8/qgraphicsitem.html#details.`](http://doc.qt.io/archives/qt-5.8/qgraphicsitem.html#details)

# 可移动的图形项

在上一个例子中，我们成功地将一些简单的形状和文本绘制到了`Graphics View`小部件上。然而，这些图形项是不可交互的，因此不适合我们的目的。我们想要的是一个交互式的组织图表，用户可以使用鼠标移动项目。在 Qt 下，使这些项目可移动实际上非常容易；让我们看看我们如何通过继续我们之前的项目来做到这一点。

首先，确保不要更改我们的图形视图小部件的默认交互属性，即启用（复选框已选中）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/01e7d066-00f9-4c4e-ae4b-9352ecf34437.png)

在那之后，在之前的`Hello World`示例中创建的每个图形项下面添加以下代码：

```cpp
QGraphicsRectItem* rectangle = scene->addRect(80, 0, 80, 80, pen, greenBrush); 
rectangle->setFlag(QGraphicsItem::ItemIsMovable); 
rectangle->setFlag(QGraphicsItem::ItemIsSelectable); 

QGraphicsEllipseItem* ellipse = scene->addEllipse(0, -80, 200, 60, pen, blueBrush); 
ellipse->setFlag(QGraphicsItem::ItemIsMovable); 
ellipse->setFlag(QGraphicsItem::ItemIsSelectable); 

QGraphicsTextItem* text = scene->addText("Hello World!", QFont("Times", 25)); 
text->setFlag(QGraphicsItem::ItemIsMovable); 
text->setFlag(QGraphicsItem::ItemIsSelectable); 
```

再次构建和运行程序，这次您应该能够在图形视图中选择和移动项目。请注意，`ItemIsMovable`和`ItemIsSelectable`都会给您不同的行为——前者标志将使项目可以通过鼠标移动，而后者使项目可选择，通常在选择时使用虚线轮廓进行视觉指示。每个标志都独立工作，不会影响其他标志。

我们可以通过使用 Qt 中的信号和槽机制来测试`ItemIsSelectable`标志的效果。让我们回到我们的代码并添加以下行：

```cpp
ui->setupUi(this); 
scene = new QGraphicsScene(this); 
ui->graphicsView->setScene(scene); 
connect(scene, &QGraphicsScene::selectionChanged, this, &MainWindow::selectionChanged); 
```

`selectionChanged()`信号将在您在图形视图小部件上选择项目时触发，然后`MainWindow`类下的`selectionChanged()`槽函数将被调用（我们需要编写）。让我们打开`mainwindow.h`并添加另一个头文件以显示调试消息：

```cpp
#include <QDebug> 
```

然后，我们声明槽函数，就像这样：

```cpp
private: 
   Ui::MainWindow *ui; 

public slots: 
 void selectionChanged(); 
```

之后打开`mainwindow.cpp`并定义槽函数，就像这样：

```cpp
void MainWindow::selectionChanged() 
{ 
   qDebug() << "Item selected"; 
} 
```

现在尝试再次运行程序；您应该看到一行调试消息，每当单击图形项时会出现“项目选择”。这真的很简单，不是吗？

至于`ItemIsMovable`标志，我们将无法使用信号和槽方法进行测试。这是因为所有从`QGraphicsItem`类继承的类都不是从`QObject`类继承的，因此信号和槽机制不适用于这些类。这是 Qt 开发人员有意为之，以使其轻量级，从而提高性能，特别是在屏幕上渲染数千个项目时。

尽管信号和槽对于这个选项不是一个选择，我们仍然可以使用事件系统，这需要对`itemChange()`虚函数进行重写，我将在下一节中演示。

# 创建组织图表

让我们继续学习如何使用 Graphics View 创建组织图表。组织图表是一种显示组织结构和员工职位关系层次结构的图表。通过使用图形表示来理解公司的结构是很容易的；因此最好使用 Graphics View 而不是表格。

这一次，我们需要为图形项创建自己的类，以便我们可以利用 Qt 的事件系统，并且更好地控制它的分组和显示方式。

首先，通过转到文件 | 新建文件或项目来创建一个 C/C++类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a86a053b-8bab-4827-b081-a2858e1b1d66.png)

接下来，在点击下一步和完成按钮之前，将我们的类命名为`profileBox`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e257c658-4e37-45d9-a89a-e0ef788161b7.png)

之后，打开`mainwindow.h`并添加这些头文件：

```cpp
#include <QWidget> 
#include <QDebug> 
#include <QBrush> 
#include <QPen> 
#include <QFont> 
#include <QGraphicsScene> 
#include <QGraphicsItemGroup> 
#include <QGraphicsItem> 
#include <QGraphicsRectItem> 
#include <QGraphicsTextItem> 
#include <QGraphicsPixmapItem> 
```

然后，打开`profilebox.h`并使我们的`profileBox`类继承`QGraphicsItemGroup`：

```cpp
class profileBox : public QGraphicsItemGroup 
{ 
public: 
   explicit profileBox(QGraphicsItem* parent = nullptr); 
```

在那之后，打开`profilebox.cpp`并在类的构造函数中设置`QBrush`、`QPen`和`QFont`，这将在稍后用于渲染：

```cpp
profileBox::profileBox(QGraphicsItem *parent) : QGraphicsItemGroup(parent) 
{ 
   QBrush brush(Qt::white); 
   QPen pen(Qt::black); 
   QFont font; 
   font.setFamily("Arial"); 
   font.setPointSize(12); 
} 
```

之后，在构造函数中，创建一个`QGraphicsRectItem`、`QGraphicsTextItem`和一个`QGraphicsPixmapItem`：

```cpp
QGraphicsRectItem* rectangle = new QGraphicsRectItem(); 
rectangle->setRect(0, 0, 90, 100); 
rectangle->setBrush(brush); 
rectangle->setPen(pen); 

nameTag = new QGraphicsTextItem(); 
nameTag->setPlainText(""); 
nameTag->setFont(font); 

QGraphicsPixmapItem* picture = new QGraphicsPixmapItem(); 
QPixmap pixmap(":/images/person-icon-blue.png"); 
picture->setPixmap(pixmap); 
picture->setPos(15, 30); 
```

然后，将这些项目添加到组中，这是当前类，因为这个类是从`QGraphicsItemGroup`类继承的：

```cpp
this->addToGroup(rectangle); 
this->addToGroup(nameTag); 
this->addToGroup(picture); 
```

最后，为当前类设置三个标志，即`ItemIsMovable`、`ItemIsSelectable`和`ItemSendsScenePositionChanges`：

```cpp
this->setFlag(QGraphicsItem::ItemIsMovable); 
this->setFlag(QGraphicsItem::ItemIsSelectable); 
this->setFlag(QGraphicsItem::ItemSendsScenePositionChanges); 
```

这些标志非常重要，因为它们默认情况下都是禁用的，出于性能原因。我们在上一节中已经涵盖了`ItemIsMovable`和`ItemIsSelectable`，而`ItemSendsPositionChanges`是一些新的东西。此标志使图形项在用户移动时通知图形场景，因此得名。

接下来，创建另一个名为`init()`的函数，用于设置员工个人资料。为简单起见，我们只设置了员工姓名，但是如果您愿意，还可以进行更多操作，例如根据职级设置不同的背景颜色，或更改其个人资料图片：

```cpp
void profileBox::init(QString name, MainWindow *window, QGraphicsScene* scene) 
{ 
   nameTag->setPlainText(name); 
   mainWindow = window; 
   scene->addItem(this); 
} 
```

请注意，我们还在这里设置了主窗口和图形场景指针，以便以后使用。在将其呈现在屏幕上之前，我们必须将`QGraphicsItem`添加到场景中。在这种情况下，我们将所有图形项分组到`QGraphicsItemGroup`中，因此我们只需要将组添加到场景中，而不是单个项。

请注意，您必须在`profilebox.h`中的`#include "mainwindow.h"`之后进行`MainWindow`类的前向声明，以避免递归头文件包含错误。同时，我们还在`profilebox.h`中放置了`MainWindow`和`QGraphicsTextItem`指针，以便以后调用它们：

```cpp
#include "mainwindow.h" 

class MainWindow; 

class profileBox : public QGraphicsItemGroup 
{ 
public: 
   explicit profileBox(QGraphicsItem* parent = nullptr); 
   void init(QString name, MainWindow* window, QGraphicsScene* scene); 

private: 
   MainWindow* mainWindow; 
   QGraphicsTextItem* nameTag; 

```

您还会注意到，我在`QGraphicsPixmapItem`中使用了一个图标作为装饰图标：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9787b7b9-c914-42cd-a823-622a852bea88.png)

此图标是存储在资源文件中的 PNG 图像。您可以从我们在 GitHub 页面上的示例项目文件中获取此图像：[`github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5`](http://github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5)

为您的项目创建一个资源文件。转到文件|新建文件或项目，然后在 Qt 类别下选择 Qt 资源文件选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b48d892f-781d-4781-a7d1-2548d6d5dca4.png)

创建空的资源文件后，通过添加|添加前缀添加一个新前缀。我们将只称此前缀为`images`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8a5addd2-28d8-4bb3-b595-9acd7b2a0531.png)

然后，选择新创建的`images`前缀，单击添加|添加文件。将图标图像添加到资源文件并保存。您现在已成功将图像添加到项目中。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/1803de41-0a6d-4761-bf75-a9da8ff984bf.png)

如果您的前缀名称或文件名与本书中的前缀名称或文件名不同，您可以右键单击资源文件中的图像，然后选择复制资源路径到剪贴板，并用您的路径替换代码中的路径。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/27bfcbda-33d3-4330-8ed7-33cd8082e990.png)

之后，打开`mainwindow.h`并添加：

```cpp
#include "profilebox.h"
```

然后，打开`mainwindow.cpp`并添加以下代码以手动创建个人资料框：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   scene = new QGraphicsScene(this); 
   ui->graphicsView->setScene(scene); 

   connect(scene, &QGraphicsScene::selectionChanged, this, &MainWindow::selectionChanged); 

   profileBox* box = new profileBox(); 
   box->init("John Doe", this, scene); 
} 
```

现在构建和运行项目，您应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/af8e4e65-97ea-4571-a6f0-b00a43980191.png)

看起来整洁；但我们还远未完成。还有一些事情要做——我们必须允许用户通过用户界面添加或删除个人资料框，而不是使用代码。同时，我们还需要添加连接不同个人资料框的线条，以展示不同员工之间的关系以及他们在公司内的职位。

让我们从简单的部分开始。再次打开`mainwindow.ui`，并在图形视图小部件底部添加一个推送按钮，并将其命名为`addButton`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/03f5b860-526e-425f-b3d7-d24c86c84ebd.png)

然后，右键单击推送按钮，选择转到插槽...之后，选择单击选项，然后单击确定。将自动为您创建一个新的插槽函数，名为`on_addButton_clicked()`。添加以下代码以允许用户在单击添加按钮时创建个人资料框：

```cpp
void MainWindow::on_addButton_clicked() 
{ 
   bool ok; 
   QString name = QInputDialog::getText(this, tr("Employee Name"), 
   tr("Please insert employee's full name here:"), QLineEdit::Normal,  
   "John Doe", &ok); 
   if (ok && !name.isEmpty()) 
   { 
         profileBox* box = new profileBox(); 
         box->init(name, this, scene); 
   } 
} 
```

现在，用户不再需要使用代码创建每个个人资料框，他们可以通过单击添加按钮轻松创建任意数量的个人资料框。还将出现一个消息框，让用户在创建个人资料框之前输入员工姓名：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/7f6b3cf5-f348-49a5-a43e-71172aab6166.png)

接下来，我们将创建另一个名为`profileLine`的类。这次，我们将使这个类继承`QGraphicsLineItem`。`profileline.h`基本上看起来像这样：

```cpp
#include <QWidget> 
#include <QGraphicsItem> 
#include <QPen> 

class profileLine : public QGraphicsLineItem 
{ 
public: 
   profileLine(QGraphicsItem* parent = nullptr); 
   void initLine(QGraphicsItem* start, QGraphicsItem* end); 
   void updateLine(); 

   QGraphicsItem* startBox; 
   QGraphicsItem* endBox; 

private: 
}; 
```

与`profileBox`类类似，我们还为`profileLine`类创建了一个`init`函数，称为`initLine()`函数。此函数接受两个`QGraphicsItem`对象作为渲染行的起点和终点。此外，我们还创建了一个`updateLine()`函数，以便在配置框移动时重新绘制行。

接下来，打开`profileline.cpp`并将以下代码添加到构造函数中：

```cpp
profileLine::profileLine(QGraphicsItem *parent) : QGraphicsLineItem(parent) 
{ 
   QPen pen(Qt::black); 
   pen.setWidth(2); 
   this->setPen(pen); 

   this->setZValue(-999); 
} 
```

我们使用`QPen`将线的颜色设置为黑色，宽度设置为`2`。之后，我们还将线的`Zvalue`设置为`-999`，这样它将始终保持在配置框的后面。

之后，将以下代码添加到我们的`initLine()`函数中，使其看起来像这样：

```cpp
void profileLine::initLine(QGraphicsItem* start, QGraphicsItem* end) 
{ 
   startBox = start; 
   endBox = end; 

   updateLine(); 
} 
```

它的作用基本上是设置框的起点和终点位置。之后，调用`updateLine()`函数来渲染行。

最后，`updateLine()`函数看起来像这样：

```cpp
void profileLine::updateLine() 
{ 
   if (startBox != NULL && endBox != NULL) 
   { 
         this->setLine(startBox->pos().x() + startBox->boundingRect().width() / 2, startBox->pos().y() + startBox->boundingRect().height() / 2, endBox->pos().x() + endBox->boundingRect().width() / 2, endBox->pos().y() + endBox->boundingRect().height() / 2); 
   } 
} 
```

前面的代码看起来有点复杂，但如果我这样说，它就真的很简单：

```cpp
this->setLine(x1, y1, x2, y2); 
```

值`x1`和`y1`基本上是第一个配置框的中心位置，而`x2`和`y2`是第二个配置框的中心位置。由于从调用`pos()`获取的位置值从左上角开始，我们必须获取配置框的边界大小并除以二以获取其中心位置。然后，将该值添加到左上角位置以将其偏移至中心。

完成后，让我们再次打开`mainwindow.cpp`并将以下代码添加到`on_addButton_clicked()`函数中：

```cpp
void MainWindow::on_addButton_clicked() 
{ 
   bool ok; 
   QString name = QInputDialog::getText(this, tr("Employee Name"), tr("Please insert employee's full name here:"), QLineEdit::Normal, "John Doe", &ok); 
   if (ok && !name.isEmpty()) 
   { 
         profileBox* box = new profileBox(); 
         box->init(name, this, scene); 

         if (scene->selectedItems().size() > 0) 
         { 
               profileLine* line = new profileLine(); 
               line->initLine(box, scene->selectedItems().at(0)); 
               scene->addItem(line); 

               lines.push_back(line); 
         } 
   } 
} 
```

在前面的代码中，我们检查用户是否选择了任何配置框。如果没有，我们就不必创建任何线。否则，创建一个新的`profileLine`对象，并将新创建的配置框和当前选择的配置框设置为`startBox`和`endBox`属性。

之后，将该`profileLine`对象添加到我们的图形场景中，以便它出现在屏幕上。最后，将此`profileLine`对象存储到`QList`数组中，以便我们以后使用。在`mainwindow.h`中，数组声明如下所示：

```cpp
private: 
   Ui::MainWindow *ui; 
   QGraphicsScene* scene; 
   QList<profileLine*> lines; 
```

现在构建和运行项目。当您点击“添加”按钮创建第二个配置框时，您应该能够看到线出现，并在选择第一个框时保持选中。但是，您可能会注意到一个问题，即当您将配置框移出原始位置时，线根本不会更新自己！：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/115bd268-e78e-49b4-95d5-f58d962cd051.png)

这是我们将行放入`QList`数组的主要原因，这样我们就可以在用户移动配置框时更新这些行。

为此，首先，我们需要重写`profileBox`类中的虚函数`itemChanged()`。让我们打开`profilebox.h`并添加以下代码行：

```cpp
class profileBox : public QGraphicsItemGroup 
{ 
public: 
   explicit profileBox(QGraphicsItem* parent = nullptr); 
   void init(QString name, MainWindow* window, QGraphicsScene* scene); 
   QVariant itemChange(GraphicsItemChange change, const QVariant 
   &value) override; 
```

然后，打开`profilebox.cpp`并添加`itemChanged()`的代码：

```cpp
QVariant profileBox::itemChange(GraphicsItemChange change, const QVariant &value) 
{ 
   if (change == QGraphicsItem::ItemPositionChange) 
   { 
         qDebug() << "Item moved"; 

         mainWindow->updateLines(); 
   } 

   return QGraphicsItem::itemChange(change, value); 
} 
```

`itemChanged()`函数是`QGraphicsItem`类中的虚函数，当图形项发生变化时，Qt 的事件系统将自动调用它，无论是位置变化、可见性变化、父级变化、选择变化等等。

因此，我们所需要做的就是重写该函数并向函数中添加我们自己的自定义行为。在前面的示例代码中，我们所做的就是在我们的主窗口类中调用`updateLines()`函数。

接下来，打开`mainwindow.cpp`并定义`updateLines()`函数。正如函数名所示，您要在此函数中做的是循环遍历存储在行数组中的所有配置行对象，并更新每一个，如下所示：

```cpp
void MainWindow::updateLines() 
{ 
   if (lines.size() > 0) 
   { 
         for (int i = 0; i < lines.size(); i++) 
         { 
               lines.at(i)->updateLine(); 
         } 
   } 
} 
```

完成后，再次构建和运行项目。这次，您应该能够创建一个组织图表，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/72762a59-c68a-4e39-8bb7-097924dd8425.png)

这只是一个更简单的版本，向您展示了如何利用 Qt 强大的图形视图系统来显示一组数据的图形表示，这些数据可以被普通人轻松理解。

在完成之前还有一件事-我们还没有讲解如何删除配置档框。实际上很简单，让我们打开`mainwindow.h`并添加`keyReleaseEvent()`函数，看起来像这样：

```cpp
public: 
   explicit MainWindow(QWidget *parent = 0); 
   ~MainWindow(); 

   void updateLines(); 
   void keyReleaseEvent(QKeyEvent* event); 
```

这个虚函数在键盘按钮被按下和释放时也会被 Qt 的事件系统自动调用。函数的内容在`mainwindow.cpp`中看起来像这样：

```cpp
void MainWindow::keyReleaseEvent(QKeyEvent* event) 
{ 
   qDebug() << "Key pressed: " + event->text(); 

   if (event->key() == Qt::Key_Delete) 
   { 
         if (scene->selectedItems().size() > 0) 
         { 
               QGraphicsItem* item = scene->selectedItems().at(0); 
               scene->removeItem(item); 

               for (int i = lines.size() - 1; i >= 0; i--) 
               { 
                     profileLine* line = lines.at(i); 

                     if (line->startBox == item || line->endBox == 
                     item) 
                     { 
                           lines.removeAt(i); 
                           scene->removeItem(line); 
                           delete line; 
                     } 
               } 
               delete item; 
         } 
   } 
} 
```

在这个函数中，我们首先要检测用户按下的键盘按钮。如果按钮是`Qt::Key_Delete (删除按钮)`，那么我们将检查用户是否选择了任何配置档框，通过检查`scene->selectedItems().size()`是否为空来判断。如果用户确实选择了一个配置档框，那么就从图形场景中移除该项。之后，循环遍历线数组，并检查是否有任何配置线连接到已删除的配置档框。从场景中移除连接到配置档框的任何线，然后我们就完成了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6fb5678c-13c1-4f9e-a849-3abd267b209c.png)

这个截图显示了从组织结构图中删除`Jane Smith`配置档框的结果。请注意，连接配置框的线已经被正确移除。就是这样，本章到此结束；希望您觉得这很有趣，也许会继续创造比这更好的东西！

# 总结

在本章中，我们学习了如何使用 Qt 创建一个应用程序，允许用户轻松创建和编辑组织结构图。我们学习了诸如`QGraphicsScene`、`QGrapicsItem`、`QGraphicsTextItem`、`QGraphicsPixmapItem`等类，这些类帮助我们在短时间内创建一个交互式组织结构图。在接下来的章节中，我们将学习如何使用网络摄像头捕捉图像！


# 第九章：摄像头模块

在通过许多难度逐渐增加的章节后，让我们尝试一些更简单和更有趣的东西！我们将学习如何通过 Qt 的多媒体模块访问我们的摄像头并使用它拍照。

在本章中，我们将涵盖以下主题：

+   Qt 多媒体模块

+   连接到摄像头

+   将摄像头图像捕获到文件

+   将摄像头视频录制到文件

您可以使用这个功能创建视频会议应用程序、安全摄像头系统等。让我们开始吧！

# Qt 多媒体模块

Qt 中的多媒体模块处理平台的多媒体功能，如媒体播放和摄像头和收音机设备的使用。这个模块涵盖了很多主题，但是在本章中我们只会专注于摄像头。

# 设置一个新项目

首先，创建一个新的 Qt Widgets 应用程序项目。

首先，我们需要打开项目文件（.pro）并添加两个关键字——`multimedia`和`multimediawidgets`：

```cpp
QT += core gui multimedia multimediawidgets 
```

通过在项目文件中检测这些关键字，Qt 在编译时将包含多媒体模块和所有与多媒体相关的部件到您的项目中。多媒体模块包括四个主要组件，列举如下：

+   音频

+   视频

+   摄像头

+   收音机

每个组件都包括一系列提供相应功能的类。通过使用这个模块，您不再需要自己实现低级别的平台特定代码。让 Qt 来为您完成这项工作。真的很简单。

在添加了多媒体模块后，让我们打开`mainwindow.ui`并将一个水平布局拖放到主窗口上，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/59be5c52-c020-4ae8-8db0-3485497ad386.png)

然后，在我们刚刚添加的水平布局中添加一个标签、下拉框（命名为`deviceSelection`）和一个按钮。之后，在下拉框和按钮之间添加一个水平间隔。完成后，选择中央窗口部件并点击工作区上方的垂直布局按钮。

然后，在上一个水平布局的底部添加另一个水平布局，右键单击它并选择转换为 | QFrame。然后，将其 sizePolicy（水平策略和垂直策略）设置为扩展。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/afc05a4b-5788-4b1d-ac84-33e5cd81fd92.png)

到目前为止，您的程序用户界面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e31cada6-b831-4f34-bad4-3c3096644d80.png)

我们将布局转换为框架的原因是为了将 sizePolicy（水平策略和垂直策略）设置为扩展。但是，如果我们只是从部件框中添加一个框架部件（本质上是 QFrame），我们就无法得到所需的用于稍后附加取景器的布局组件。

接下来，再次右键单击 QFrame 并选择更改样式表。将弹出一个窗口来设置该部件的样式表。添加以下样式表代码以使背景变为黑色：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/64d7d9eb-31d7-463e-b806-0c13f4de32b4.png)

这一步是可选的；我们将其背景设置为黑色，只是为了指示取景器的位置。完成后，让我们在 QFrame 上方再添加一个水平布局，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/bb45ce27-fc97-4962-a84f-f3e7f3cac303.png)

然后，在水平布局中添加两个按钮和一个水平间隔以使它们右对齐：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cd4977c9-a179-4245-a431-8f3ef6622ba3.png)

到此为止；我们已经完成了使用多媒体模块设置项目，并为下一节精心布置了用户界面。

# 连接到摄像头

最激动人心的部分来了。我们将学习如何使用 Qt 的多媒体模块访问我们的摄像头。首先，打开`mainwindow.h`并添加以下头文件：

```cpp
#include <QMainWindow> 
#include <QDebug> 
#include <QCameraInfo> 
#include <QCamera> 
#include <QCameraViewfinder> 
#include <QCameraImageCapture> 
#include <QMediaRecorder> 
#include <QUrl> 
```

接下来，添加以下变量，如下所示：

```cpp
private: 
   Ui::MainWindow *ui; 
   QCamera* camera; 
   QCameraViewfinder* viewfinder; 
   bool connected; 
```

然后，打开`mainwindow.cpp`并将以下代码添加到类构造函数中以初始化`QCamera`对象。然后，我们使用`QCameraInfo`类检索连接摄像头的列表，并将该信息填充到组合框小部件中：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 

   connected = false; 
   camera = new QCamera(); 

   qDebug() << "Number of cameras found:" << QCameraInfo::availableCameras().count(); 

   QList<QCameraInfo> cameras = QCameraInfo::availableCameras(); 
   foreach (const QCameraInfo &cameraInfo, cameras) 
   { 
         qDebug() << "Camera info:" << cameraInfo.deviceName() << 
         cameraInfo.description() << cameraInfo.position(); 

         ui->deviceSelection->addItem(cameraInfo.description()); 
   } 
} 
```

现在构建并运行项目。之后，检查调试输出以查看计算机上检测到的摄像头。检测到的摄像头也应显示在下拉框中。如果您在支持摄像头的笔记本电脑上运行，您应该能够看到它在列表中。如果您在没有内置摄像头的系统上运行，则调试输出可能不会显示任何内容，下拉框也将保持为空。如果是这种情况，请尝试插入一个廉价的 USB 摄像头并重新运行程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/653beee6-57b1-4705-8987-5387abe142b4.png)

之后，打开`mainwindow.ui`，右键单击连接按钮，然后选择转到槽.... 选择`clicked()`选项，然后单击确定。Qt Creator 将自动为您创建一个`slot`函数；将以下代码添加到函数中：

```cpp
void MainWindow::on_connectButton_clicked() 
{ 
   if (!connected) 
   { 
         connectCamera(); 
   } 
   else 
   { 
         camera->stop(); 
         viewfinder->deleteLater(); 
         ui->connectButton->setText("Connect"); 
         connected = false; 
   } 
} 
```

当单击连接按钮时，我们首先检查`camera`是否已连接，方法是检查`connect`变量。如果尚未连接，我们运行`connectCamera()`函数，我们将在下一步中定义。如果摄像头已连接，我们停止摄像头，删除`viewfinder`并将连接按钮的文本设置为`Connect`。最后，将`connected`变量设置为`false`。请注意，这里我们使用`deleteLater()`而不是`delete()`，这是删除内存指针的推荐方法。如果在没有运行事件循环的线程中调用`deleteLater()`，则对象将在线程完成时被销毁。

接下来，我们将在`MainWindow`类中添加一个名为`connectCamera()`的新函数。该函数如下所示：

```cpp
void MainWindow::connectCamera() 
{ 
   QList<QCameraInfo> cameras = QCameraInfo::availableCameras(); 
   foreach (const QCameraInfo &cameraInfo, cameras) 
   { 
         qDebug() << cameraInfo.description() << ui->deviceSelection-
         >currentText(); 

         if (cameraInfo.description() == ui->deviceSelection- 
         >currentText()) 
         { 
               camera = new QCamera(cameraInfo); 
               viewfinder = new QCameraViewfinder(this); 
               camera->setViewfinder(viewfinder); 
               ui->webcamLayout->addWidget(viewfinder); 

               connected = true; 
               ui->connectButton->setText("Disconnect"); 

               camera->start(); 

               return; 
         } 
   } 
} 
```

在`connectCamera()`函数中，我们重复了构造中的操作，并获取当前连接摄像头的列表。然后，我们循环遍历列表，并将摄像头的名称（存储在`description`变量中）与组合框小部件上当前选择的设备名称进行比较。

如果有匹配的名称，这意味着用户打算连接到该特定摄像头，因此我们将通过初始化`QCamera`对象和新的`QCameraViewFinder`对象来连接到该摄像头。然后，我们将`viewfinder`链接到`camera`，并将`viewfinder`添加到具有黑色背景的布局中。然后，我们将`connected`变量设置为`true`，并将连接按钮的文本设置为`Disconnect`。最后，调用`start()`函数来启动摄像头运行。

现在构建并运行项目。选择要连接的摄像头，然后单击连接按钮。您应该能够连接到摄像头并在程序中看到自己：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/c6d70bb6-30f2-426f-815c-a92e80f674e0.png)

如果您的摄像头无法连接，请执行以下步骤以显示操作系统返回的任何错误。首先，打开`mainwindow.h`并添加以下`slot`函数：

```cpp
private slots: 
   void cameraError(QCamera::Error error); 
```

之后，打开`mainwindow.cpp`并将以下代码添加到`connectCamera()`函数中，将`error()`信号连接到`cameraError()`槽函数：

```cpp
void MainWindow::connectCamera() 
{ 
   QList<QCameraInfo> cameras = QCameraInfo::availableCameras(); 
   foreach (const QCameraInfo &cameraInfo, cameras) 
   { 
         qDebug() << cameraInfo.description() << ui->deviceSelection-
         >currentText(); 

         if (cameraInfo.description() == ui->deviceSelection-
         >currentText()) 
         { 
               camera = new QCamera(cameraInfo); 
               viewfinder = new QCameraViewfinder(this); 
               camera->setViewfinder(viewfinder); 
               ui->webcamLayout->addWidget(viewfinder); 

               connect(camera, SIGNAL(error(QCamera::Error)), this, 
               SLOT(cameraError(QCamera::Error))); 

               connected = true; 
               ui->connectButton->setText("Disconnect"); 

               camera->start(); 

               return; 
         } 
   } 
} 
```

`cameraError()`槽函数如下所示：

```cpp
void MainWindow::cameraError(QCamera::Error error) 
{ 
   qDebug() << "Camera error:" << error; 

   connected = false; 
   camera->stop(); 
   ui->connectButton->setText("Connect"); 
} 
```

在上述代码中，我们显示错误消息，并确保摄像头已完全停止，以防万一。通过查看错误消息，您应该能够更轻松地调试问题。

# 将摄像头图像捕获到文件

在上一节中，我们已经学习了如何使用 Qt 的多媒体模块连接到摄像头。现在，我们将尝试从摄像头中捕获静态图像并将其保存为 JPEG 文件。使用 Qt 实际上非常简单。

首先，打开`mainwindow.h`并添加以下变量：

```cpp
private: 
   Ui::MainWindow *ui; 
   QCamera* camera; 
   QCameraViewfinder* viewfinder; QCameraImageCapture* imageCapture; bool connected; 
```

然后，在`mainwindow.ui`中右键单击 Capture 按钮，选择转到槽...。然后，选择`clicked()`并按 OK。现在，在`mainwindow.cpp`中为您创建了一个新的`slot`函数。添加以下代码以从摄像头捕获图像：

```cpp
void MainWindow::on_captureButton_clicked() 
{ 
   if (connected) 
   { 
         imageCapture = new QCameraImageCapture(camera); 
         camera->setCaptureMode(QCamera::CaptureStillImage); 
         camera->searchAndLock(); 
         imageCapture->capture(qApp->applicationDirPath()); 
         camera->unlock(); 
   } 
} 
```

在前面的代码中，我们基本上创建了一个新的`QCameraImageCapture`对象，并将其媒体对象设置为活动摄像头。然后，将其捕获模式设置为静态图像。在要求`QCameraImageCapture`对象捕获图像之前，我们必须锁定摄像头，以便在捕获图像过程中设置保持不变。成功捕获图像后，您可以通过调用`camera->unlock()`来解锁它。

我们使用了`qApp->applicationDirPath()`来获取应用程序目录，以便图像将保存在可执行文件旁边。您可以将其更改为任何您想要的目录。您还可以将所需的文件名放在目录路径后面；否则，它将使用默认文件名格式按顺序保存图像，从`IMG_00000001.jpg`开始，依此类推。

# 将摄像头视频录制到文件

在学习了如何从我们的摄像头捕获静态图像之后，让我们继续学习如何录制视频。首先，打开`mainwindow.h`并添加以下变量：

```cpp
private: 
   Ui::MainWindow *ui; 
   QCamera* camera; 
   QCameraViewfinder* viewfinder; 
   QCameraImageCapture* imageCapture; 
   QMediaRecorder* recorder; 

   bool connected; 
   bool recording; 
```

接下来，再次打开`mainwindow.ui`，右键单击 Record 按钮。从菜单中选择转到槽...，然后选择`clicked()`选项，然后单击 OK 按钮。将为您创建一个`slot`函数；然后继续将以下代码添加到`slot`函数中：

```cpp
void MainWindow::on_recordButton_clicked() 
{ 
   if (connected) 
   { 
         if (!recording) 
         { 
               recorder = new QMediaRecorder(camera); 
               camera->setCaptureMode(QCamera::CaptureVideo); 
               recorder->setOutputLocation(QUrl(qApp-
               >applicationDirPath())); 
               recorder->record(); 
               recording = true; 
         } 
         else 
         { 
               recorder->stop(); 
               recording = false; 
         } 
   } 
} 
```

这次，我们使用`QMediaRecorder`来录制视频。在调用`recorder->record()`之前，我们还必须将摄像头的捕获模式设置为`QCamera::CaptureVideo`。

要检查媒体录制器在录制阶段产生的错误消息，您可以将媒体录制器的`error()`信号连接到`slot`函数，如下所示：

```cpp
void MainWindow::on_recordButton_clicked() 
{ 
   if (connected) 
   { 
         if (!recording) 
         { 
               recorder = new QMediaRecorder(camera); 
               connect(recorder, SIGNAL(error(QMediaRecorder::Error)), 
               this, SLOT(recordError(QMediaRecorder::Error))); 
               camera->setCaptureMode(QCamera::CaptureVideo); 
               recorder->setOutputLocation(QUrl(qApp-
               >applicationDirPath())); 
               recorder->record(); 
               recording = true; 
         } 
         else 
         { 
               recorder->stop(); 
               recording = false; 
         } 
   } 
} 
```

然后，只需在`slot`函数中显示错误消息：

```cpp
void MainWindow::recordError(QMediaRecorder::Error error) 
{ 
   qDebug() << errorString(); 
} 
```

请注意，在撰写本章时，`QMediaRecorder`类仅支持 macOS、Linux、移动平台和 Windows XP 上的视频录制。目前在 Windows 8 和 Windows 10 上不起作用，但将在即将推出的版本之一中移植过去。主要原因是 Qt 在 Windows 平台上使用 Microsoft 的`DirectShow` API 来录制视频，但自那时起已经从 Windows 操作系统中停用。希望在您阅读本书时，这个功能已经完全在 Qt 中为 Windows 8 和 10 实现。

如果没有，您可以使用使用`OpenCV` API 进行视频录制的第三方插件，例如**Qt 媒体编码库**（**QtMEL**）API，作为临时解决方案。请注意，QtMEL 中使用的代码与我们在本章中展示的代码完全不同。

有关 QtMEL 的更多信息，请查看以下链接：

[`kibsoft.ru`](http://kibsoft.ru)。

# 摘要

在本章中，我们学习了如何使用 Qt 连接到我们的摄像头。我们还学习了如何从摄像头捕获图像或录制视频。在下一章中，我们将学习有关网络模块，并尝试使用 Qt 制作即时通讯工具！
