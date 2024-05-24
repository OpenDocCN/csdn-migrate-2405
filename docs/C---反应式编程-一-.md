# C++ 反应式编程（一）

> 原文：[`annas-archive.org/md5/e4e6a4bd655b0a85e570c3c31e1be9a2`](https://annas-archive.org/md5/e4e6a4bd655b0a85e570c3c31e1be9a2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书将帮助您学习如何使用 C++实现响应式编程范式，以构建异步和并发应用程序。响应式编程模型在编程模型（OOP/FP）、事件驱动 GUI 编程、语言级并发、无锁编程、设计模式和事件流编程方面需要大量的先决条件。前六章详细介绍了这些主题。在剩下的章节中，我们基于工业级 RxCpp 库进行讨论。涵盖的主题包括 RxCpp 编程模型的介绍，RxCpp 编程模型的五个关键元素，使用 Qt 进行 GUI 编程，编写自定义操作符，Rx 设计模式，响应式微服务和高级异常/操作符。通过本书，您将能够自信地将 Rx 构造嵌入到您的程序中，以使用 C++编写更好的并发和并行应用程序。

# 这本书是为谁准备的

如果您是一名对使用响应式编程构建异步和并发应用程序感兴趣的 C++开发人员，您会发现这本书非常有用。本书不假设读者具有响应式编程的任何先前知识。我们在第二章，*现代 C++及其关键习惯的介绍*，第三章，*C++语言级并发和并行性*，以及第四章，*C++中的异步和无锁编程*中涵盖了编写响应式程序所需的现代 C++构造。任何对经典 C++有合理熟悉度的 C++程序员都可以轻松地阅读本书。

# 这本书涵盖了什么

第一章，*响应式编程模型-概述和历史*，介绍了 GUI 工具包（如 Windows API，XLib API，Qt 和 MFC）实现的各种事件处理技术。本章还在编写跨平台控制台应用程序和使用 MFC 库编写 GUI 应用程序的背景下，介绍了 Rx 编程模型的一些关键数据结构。

第二章，*现代 C++及其关键习惯的介绍*，涵盖了编写响应式程序所需的现代 C++构造。本章重点介绍了新的 C++特性，类型推断，可变模板，右值引用，移动语义，lambda 函数，基本函数式编程，可管道化操作符，迭代器和观察者的实现。

第三章，*C++语言级并发和并行性*，讨论了 C++标准提供的线程库。您将学习如何启动和管理线程。我们将讨论线程库的不同方面。本章为现代 C++引入的并发支持奠定了良好的基础。

第四章，*C++中的异步和无锁编程*，讨论了标准库提供的用于实现基于任务的并行性的设施。它还讨论了现代 C++语言提供的新的多线程感知内存模型。

第五章，*可观察对象简介*，讨论了 GoF 观察者模式并解释了它的缺点。您将学习如何使用我们设计的技术，将实现 GoF 组合/访问者模式的程序转换为可观察流，这是在建模表达树的背景下进行的。

第六章，*使用 C++进行事件流编程简介*，专注于事件流编程的主题。我们还将介绍 Streamulus 库，该库提供了一种**领域特定嵌入式语言**（**DSEL**）方法来操作事件流。

第七章，《数据流计算和 RxCpp 库简介》，从数据流计算范式的概念概述开始，迅速转向编写一些基本的基于 RxCpp 的程序。您将了解 RxCpp 库支持的一组操作符。

第八章，《RxCpp - 关键元素》，让您了解 Rx 编程的各个部分如何在 Rx 编程模型的整体和 RxCpp 库的特定上下文中相互配合。详细涵盖的主题包括 Observables、Observer、Operators、Subscribers、Schedulers（Rx 编程模型的五个关键元素）。

第九章，《使用 Qt/C++进行响应式 GUI 编程》，涉及使用 Qt 框架进行响应式 GUI 编程的主题。您将了解 Qt 框架中的概念，如 Qt 对象层次结构、元对象系统、信号和槽。最后，您将使用 RxCpp 库编写一个应用程序，以响应式方式处理鼠标事件并对其进行过滤。

第十章，《在 RxCpp 中创建自定义操作符》，涵盖了如何在 RxCpp 中创建自定义响应式操作符的高级主题，如果现有的操作符集不适用于特定目的。我们将介绍如何利用 Lift Meta Operator 并向 RxCpp 库添加操作符。此主题还将帮助您通过组合现有操作符来创建复合操作符。

第十一章，《C++ Rx 编程的设计模式和习语》，深入探讨了设计模式和习语的奇妙世界。从 GOF 设计模式开始，我们将转向响应式编程模式。我们将涵盖 Composite/Visitor/Iterator（来自 GOF 目录）、Active Object、Cell、Resource Loan 和 Event Bus Pattern。

第十二章，《使用 C++编写响应式微服务》，介绍了如何使用 Rx 编程模型来编写使用 C++的响应式微服务。它向您介绍了 Microsoft C++ REST SDK 及其编程模型。您将学习如何利用 RxCpp 库以响应式方式编写聚合服务并访问基于 HTTP 的服务。

第十三章，《高级流和错误处理》，讨论了 RxCpp 中的错误处理，以及处理 RxCpp 库中的流的一些高级构造和操作符。我们将讨论在出现错误时如何继续流，如何等待流的生产者纠正错误并继续序列，以及如何执行适用于成功和错误路径的常见操作。

# 要充分利用本书

为了跟进本书中的主题，您需要了解 C++编程。本书涵盖了所有其他主题。当然，您需要搜索网络或阅读其他材料，以对一些主题有专家级的理解（这对任何主题都是真实的）。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或在[www.packtpub.com](http://www.packtpub.com/support)注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上：[`github.com/PacktPublishing/CPP-Reactive-Programming`](https://github.com/PacktPublishing/CPP-Reactive-Programming)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的书籍和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/CPPReactiveProgramming_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/CPPReactiveProgramming_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“前面的代码片段通过名为`WNDCLASS`（或现代系统中的`WNDCLASSEX`）的结构进行初始化，为窗口提供必要的模板。”

代码块设置如下：

```cpp
/* close connection to server */
XCloseDisplay(display);

return 0;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
/* close connection to server */
XCloseDisplay(display);

return 0;
}
```

任何命令行输入或输出都以以下方式编写：

```cpp
$ mkdir css
$ cd css
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“在窗口术语中，它被称为**消息**循环。”

警告或重要说明会出现在这样。

提示和技巧会出现在这样。


# 第一章：反应式编程模型-概述和历史

X Windows 系统、Microsoft Windows 和 IBM OS/2 Presentation Manager 使得 GUI 编程在 PC 平台上变得流行。这是从字符模式用户界面和批处理式编程模型到他们之前存在的重大转变。对事件的响应成为全球软件开发人员的主要关注点，平台供应商转而创建了基于低级 C 的 API，依赖于函数指针和回调来使程序员能够处理事件。编程模型大多基于合作式多线程模型，并随着更好的微处理器的出现，大多数平台开始支持抢占式多线程。处理事件（和其他异步任务）变得更加复杂，以传统方式响应事件变得不太可扩展。尽管出现了出色的基于 C++的 GUI 工具包，事件处理大多是使用消息 ID、函数指针分发和其他低级技术来完成的。甚至一家知名的编译器供应商尝试添加 C++语言的语言扩展来实现更好的 Windows 编程。处理事件、异步性和相关问题需要重新审视问题。幸运的是，现代 C++标准支持函数式编程、语言级并发（带有内存模型）和更好的内存管理技术，使程序员能够处理异步数据流（将事件视为流）的编程模型称为反应式编程。为了让事情更清晰，本章将概述以下主题：

+   事件驱动编程模型及其在各种平台上的实现。

+   什么是反应式编程？

+   反应式编程的不同模型。

+   一些简单的程序以更好地理解概念。

+   我们书的理念。

# 事件驱动编程模型

事件驱动编程是一种编程模型，其中流程控制由事件决定。事件的例子包括鼠标点击、按键、手势、传感器数据、来自其他程序的消息等等。事件驱动应用程序具有在几乎实时基础上检测事件并通过调用适当的事件处理过程来响应或反应的机制。由于早期的事件处理程序大多使用 C/C++编写，它们采用低级技术，如回调（使用函数指针）来编写这些事件处理程序。后来的系统，如 Visual Basic、Delphi 和其他快速应用程序开发工具确实增加了对事件驱动编程的本地支持。为了更清楚地阐明问题，我们将介绍各种平台的事件处理机制。这将帮助读者理解反应式编程模型解决的问题（从 GUI 编程的角度）。

反应式编程将数据视为流和窗口系统中的事件可以被视为流以便以统一的方式进行处理。反应式编程模型支持从不同来源收集事件作为流，过滤流，转换流，对流执行操作等。编程模型处理异步性，调度细节作为框架的一部分。本章主要基于反应式编程模型的关键数据结构以及我们如何实现基本的反应式程序。在工业强度的反应式程序中，编写的代码将是异步的，而本章的示例是同步的。在讨论乱序执行和调度之前，我们在接下来的章节中提供必要的背景信息和语言构造。这些实现是为了阐明问题，并可以作为学习示例。

# X Windows 上的事件驱动编程

X Windows 编程模型是一个跨平台 API，在 POSIX 系统上得到了广泛支持，甚至已经移植到了 Microsoft Windows。事实上，X 是一个网络窗口协议，需要一个窗口管理器来管理窗口堆栈。屏幕内容由 X 服务器管理，客户端库将内容拉取并在本地机器上显示。在桌面环境中，服务器在同一台机器上本地运行。以下程序将帮助读者了解 XLib 编程模型的要点以及平台上如何处理事件：

```cpp
#include <X11/Xlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    Display *display;
    Window window;
    XEvent event;
    char *msg = "Hello, World!";
    int s;
```

前面的代码片段包括了程序员应该包含的正确的头文件，以获取 XLib C 库提供的函数原型。在从头开始编写 XLib 程序时，程序员应该了解一些数据结构。如今，人们使用诸如 Qt、WxWidgets、Gtk+、Fox toolkit 等库来编写商业质量的 X 程序。

```cpp
    /* open connection with the server */
    display = XOpenDisplay(NULL);
    if (display == NULL){
        fprintf(stderr, "Cannot open display\n");
        exit(1);
    }
    s = DefaultScreen(display);
    /* create window */
    window = XCreateSimpleWindow(display,
             RootWindow(display, s), 10, 10, 200, 200, 1,
             BlackPixel(display, s), WhitePixel(display, s));

    /* select kind of events we are interested in */
    XSelectInput(display, window, ExposureMask | KeyPressMask);

    /* map (show) the window */
    XMapWindow(display, window);
```

前面的代码片段初始化了服务器并根据特定规格创建了一个窗口。传统上，大多数 X Windows 程序在管理级窗口下运行。我们通过在显示窗口之前调用`XSelectInput` API 来选择我们感兴趣的消息：

```cpp
    /* event loop */
    for (;;)
    {
        XNextEvent(display, &event);

        /* draw or redraw the window */
        if (event.type == Expose)
        {
            XFillRectangle(display, window,
                DefaultGC(display, s), 20, 20, 10, 10);
            XDrawString(display, window,
                DefaultGC(display, s), 50, 50, msg, strlen(msg));
        }
        /* exit on key press */
        if (event.type == KeyPress)
        break;
    }
```

然后，程序进入一个无限循环，同时轮询任何事件，并使用适当的 Xlib API 在窗口上绘制字符串。在窗口术语中，这被称为**消息**循环。事件的检索将通过`XNextEvent` API 调用来完成：

```cpp
    /* close connection to server */
    XCloseDisplay(display);

    return 0;
    }
```

一旦我们退出无限消息循环，与服务器的连接将被关闭。

# 微软 Windows 上的事件驱动编程

微软公司创建了一个 GUI 编程模型，可以被认为是世界上最成功的窗口系统。Windows 软件的第三版（1990 年）取得了巨大成功，随后微软推出了 Windows NT 和 Windows 95/98/ME 系列。让我们来看看微软 Windows 的事件驱动编程模型（请参阅微软文档，详细了解这个编程模型的工作原理）。以下程序将帮助我们了解使用 C/C++编写 Windows 编程所涉及的要点：

```cpp
#include <windows.h>
//----- Prtotype for the Event Handler Function
LRESULT CALLBACK WndProc(HWND hWnd, UINT message,
                         WPARAM wParam, LPARAM lParam);
//--------------- Entry point for a Idiomatic Windows API function
int WINAPI WinMain(HINSTANCE hInstance,
              HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{

MSG msg = {0};
WNDCLASS wc = {0};
wc.lpfnWndProc = WndProc;
wc.hInstance = hInstance;
wc.hbrBackground = (HBRUSH)(COLOR_BACKGROUND);
wc.lpszClassName = "minwindowsapp";
if( !RegisterClass(&wc) )
  return 1;
```

前面的代码片段初始化了一个名为`WNDCLASS`（或现代系统上的`WNDCLASSEX`）的结构，并提供了一个窗口的必要模板。结构中最重要的字段是`lpfnWndProc`，它是响应此窗口实例中事件的函数的地址：

```cpp
if( !CreateWindow(wc.lpszClassName,
                  "Minimal Windows Application",
                  WS_OVERLAPPEDWINDOW|WS_VISIBLE,
                  0,0,640,480,0,0,hInstance,NULL))
    return 2;
```

我们将调用`CreateWindow`（或现代系统上的`CreateWindowEx`）API 调用，根据`WNDCLASS.lpszClassname`参数中提供的类名创建一个窗口：

```cpp
    while( GetMessage( &msg, NULL, 0, 0 ) > 0 )
        DispatchMessage( &msg );
    return 0;
}
```

前面的代码片段进入了一个无限循环，消息将从消息队列中检索，直到我们收到一个`WM_QUIT`消息。`WM_QUIT`消息将使我们退出无限循环。有时在调用`DispatchMessage` API 之前会对消息进行翻译。`DispatchMessage`调用窗口回调过程（`lpfnWndProc`）：

```cpp
LRESULT CALLBACK WndProc(HWND hWnd, UINT message,
                         WPARAM wParam, LPARAM lParam) {
switch(message){
  case WM_CLOSE:
    PostQuitMessage(0);break;
  default:
    return DefWindowProc(hWnd, message, wParam, lParam);
}
return 0;
}
```

前面的代码片段是一个最简化的`callback`函数。您可以查阅微软文档，了解 Windows API 编程以及这些程序中如何处理事件

# Qt 下的事件驱动编程

Qt 框架是一个工业级、跨平台和多平台的 GUI 工具包，可在 Windows、GNU Linux、macOS X 和其他 Mac 系统上运行。该工具包已经编译到嵌入式系统和移动设备中。C++编程模型利用了称为**元对象编译器**（**MOC**）的东西，它将浏览指令的源代码（源代码中嵌入的一堆宏和语言扩展）并生成适当的附加源代码以生成事件处理程序。因此，在 C++编译器获取源代码之前，必须运行 MOC pass 以通过删除那些特定于 Qt 系统的额外语言构造生成合法的 ANSI C++。请参阅 Qt 文档以了解更多信息。以下简单的 Qt 程序将演示 Qt 编程及其事件处理系统的关键方面：

```cpp
#include <qapplication.h>
#include <qdialog.h>
#include <qmessagebox.h>
#include <qobject.h>
#include <qpushbutton.h>

class MyApp : public QDialog {
  Q_OBJECT
public:
    MyApp(QObject* /*parent*/ = 0):
    button(this)
    {
      button.setText("Hello world!"); button.resize(100, 30);

      // When the button is clicked, run button_clicked
      connect(&button,
              &QPushButton::clicked, this, &MyApp::button_clicked);
    }
```

宏`Q_OBJECT`是指示 MOC 生成`事件分发`表的指令。当我们将事件源连接到事件接收器时，将向`事件分发`表中添加一个条目。生成的代码将与 C++代码一起编译以生成可执行文件：

```cpp
public slots:
    void button_clicked() {
      QMessageBox box;
      box.setWindowTitle("Howdy");
      box.setText("You clicked the button");
      box.show();
      box.exec();
    }

protected:
  QPushButton button;
};
```

语言扩展*public slots*将被 MOC 剥离（在完成源代码生成的工作后）以与 ANSI C/C++编译器兼容的形式：

```cpp
int main(int argc, char** argv) {
  QApplication app(argc, argv);
  MyApp myapp;
  myapp.show();
  return app.exec();
}
```

前面的代码片段初始化了 Qt 应用程序对象并显示了主窗口。在实际应用中，Qt 是 C++语言最重要的应用程序开发框架，它还与 Python 编程语言有很好的绑定。

# MFC 下的事件驱动编程

Microsoft Foundation 类库仍然是编写基于 Microsoft Windows 的桌面程序的流行库。如果我们将**ActiveX 模板库**（**ATL**）与之混合使用，它确实对 Web 编程提供了一些支持。作为一个 C++库，MFC 使用一种称为消息映射的机制来处理事件。每个 MFC 程序都有一些给定的宏作为样本事件处理表：

```cpp
BEGIN_MESSAGE_MAP(CClockFrame,CFrameWnd)
    ON_WM_CREATE()
    ON_WM_PAINT()
    ON_WM_TIMER()
END_MESSAGE_MAP()
```

前面的消息映射将响应`OnCreate`、`OnPaint`和`Ontimer`标准 Windows API 消息。深入了解这些消息映射，它们实际上就是数组，我们将使用`消息 ID`作为索引来分派事件。仔细检查后，它与标准的 Windows API 消息模型并没有太大的不同。

这里没有给出代码清单，因为我们全局上使用了 MFC 来实现响应式编程模型的一个关键接口的 GUI。该实现基于 MFC 库，读者可以通过注释清单来理解 MFC 中的非平凡事件处理。

# 其他基于事件驱动的编程模型

诸如 COM+和 CORBA 之类的分布式对象处理框架确实有自己的事件处理框架。COM+事件模型基于连接点的概念（由`IConnectionPointContainer`/`IConnectionPoint`接口建模），而 CORBA 确实有自己的事件服务模型。CORBA 标准提供了基于拉取和推送的事件通知。COM+和 CORBA 超出了本书的范围，读者应该查阅各自的文档。

# 经典事件处理模型的限制

进行事件处理的整个目的是为了正确地看待事物。这些平台中的事件响应逻辑大多与编写代码的平台耦合在一起。随着多核编程的出现，编写低级多线程代码变得困难，而使用 C++编程语言可以使用声明式任务模型。但是，事件源大多在 C++标准之外！C++语言没有标准的 GUI 编程库，也没有访问外部设备的接口标准等。有什么办法？幸运的是，外部数据和事件可以聚合成流（或序列），并且通过使用 Lambda 函数等函数式编程构造可以被高效地处理。额外的好处是，如果我们对变量和流的可变性以及并发性方面进行一些限制，那么并发性和并行性就内置到流处理模型中了。

# 响应式编程模型

简而言之，响应式编程就是使用异步数据流进行编程。通过对流应用各种操作，我们可以实现不同的计算目标。响应式程序的主要任务是将数据转换为流，而不管数据的来源是什么。在编写现代图形用户界面应用程序时，我们处理鼠标移动和点击事件。目前，大多数系统都会得到回调，并在事件发生时处理这些事件。大部分时间，处理程序在调用与事件调用相关的动作方法之前会进行一系列的过滤操作。在这种特定的上下文中，响应式编程帮助我们将鼠标移动和点击事件聚合到一个集合中，并在通知处理程序逻辑之前对它们进行过滤。这样，应用程序/处理程序逻辑就不会被不必要地执行。

流处理模型是众所周知的，并且非常容易由应用程序开发人员编码。几乎任何东西都可以转换成流。这些候选对象包括消息、日志、属性、Twitter 动态、博客文章、RSS 动态等。函数式编程技术非常擅长处理流。像现代 C++这样对面向对象/函数式编程提供了出色支持的语言，是编写响应式程序的自然选择。响应式编程的基本思想是，有一些数据类型代表随时间变化的值。在这种编程范式中，这些数据类型（或者说数据序列）被表示为可观察序列。涉及这些变化（依赖时间）的值的计算本身也会随时间变化，并且需要异步地接收通知（在依赖数据发生变化时）。

# 函数式响应式编程

几乎所有现代编程语言都支持函数式编程构造。函数式编程构造，如转换、应用、过滤、折叠等，非常适合处理流。使用函数式编程构造来编程异步数据流通常被称为函数式响应式编程（在实际目的上）。这里给出的定义是一个操作性的定义。请参考 Conal Elliott 和 Paul Hudak 在 Haskell 社区所做的工作，以了解严格的定义。将响应式编程与函数式编程混合在一起在开发人员中越来越受欢迎。Rx.Net、RxJava、RxJs、RxCpp 等库的出现证明了这一点。

尽管响应式编程是本书的核心主题，但在本章中，我们将坚持面向对象的方法。这是因为我们需要引入一些标准接口（在 C++中使用虚函数模拟）来进行响应式编程。之后，在学习 C++支持的 FP 构造之后，读者可以将 OOP 构造进行一些心智模型映射到 FP 构造。在本章中，我们还将远离并发内容，专注于软件接口。第二章，*现代 C++及其关键习语之旅*，第三章，*C++中的语言级并发和并行性*，以及第四章，*C++中的异步和无锁编程*，将为理解使用 FP 构造进行响应式编程提供必要的背景。

# 响应式程序的关键接口

为了帮助您理解响应式程序内部实际发生的事情，我们将编写一些玩具程序，以便将事情放在适当的背景下。从软件设计的角度来看，如果将并发/并行性放在一边，专注于软件接口，响应式程序应该具有：

+   实现`IObservable<T>`的事件源

+   实现`IObserver<T>`的事件接收器

+   一个向事件源添加订阅者的机制

+   当数据出现在源头时，订阅者将收到通知

在本章中，我们使用了经典的 C++构造编写了代码。这是因为我们还没有介绍现代 C++构造。我们还使用了原始指针，这在编写现代 C++代码时可以大多避免。本章中的代码是一般遵循 ReactiveX 文档编写的。在 C++中，我们不像在 Java 或 C#中那样使用基于继承的技术。

为了开始，让我们定义 Observer、Observable 和`CustomException`类：

```cpp
#pragma once 
//Common2.h 

struct CustomException /*:*public std::exception */ {
   const char * what() const throw () { 
         return "C++ Exception"; 
   } 
}; 
```

`CustomException`类只是一个占位符，以使接口完整。由于我们决定在本章中只使用经典的 C++，我们不会偏离`std::exception`类：

```cpp
template<class T> class IEnumerator {
public:
      virtual bool HasMore() = 0;
      virtual T next() = 0;
      //--------- Omitted Virtual destructor for brevity
};
template <class T> class IEnumerable{
public:
      virtual IEnumerator<T> *GetEnumerator() = 0;
      //---------- Omitted Virtual destructor for brevity
};
```

`Enumerable`接口由数据源使用，我们可以枚举数据，并且客户端将使用`IEnuerator<T>`进行迭代。

定义迭代器接口（`IEnuerable<T>`/`IEnumerator<T>`）的目的是让读者理解它们与`Observer<T>`/`Observable<T>`模式非常密切相关。我们将定义`Observer<T>`/`Observable<T>`如下：

```cpp
template<class T> class IObserver
{
public:
      virtual void OnCompleted() = 0;
      virtual void OnError(CustomException *exception) = 0;
      virtual void OnNext(T value) = 0;
};
template<typename T>
class IObservable
{
public:
      virtual bool Subscribe(IObserver<T>& observer) = 0;
};
```

`IObserver<T>`是数据接收器将用于从数据源接收通知的接口。数据源将实现`IObservable<T>`接口。

我们已经定义了`IObserver<T>`接口，并且它有三种方法。它们是`OnNext`（当项目通知给观察者时），`OnCompleted`（当没有更多数据时），和`OnError`（当遇到异常时）。`Observable<T>`由事件源实现，事件接收器可以插入实现`IObserver<T>`以接收通知的对象。

# 拉取与推送式响应式编程

响应式程序可以被分类为**基于推送**和**基于拉取**。基于拉取的系统等待需求，将数据流推送给请求者（或我们的订阅者）。这是经典情况，其中数据源被主动轮询以获取更多信息。这使用了迭代器模式，而`IEnumerable <T>`/`IEnumerator <T>`接口专门设计用于这种同步性质的场景（应用程序在拉取数据时可能会阻塞）。另一方面，基于推送的系统聚合事件并通过信号网络推送以实现计算。在这种情况下，与基于拉取的系统不同，数据和相关更新是从源头（在这种情况下是 Observable 序列）传递给订阅者。这种异步性质是通过不阻塞订阅者，而是使其对变化做出反应来实现的。正如您所看到的，采用这种推送模式在丰富的 UI 环境中更有益，因为您不希望在等待某些事件时阻塞主 UI 线程。这变得理想，从而使响应式程序具有响应性。

# IEnumerable/IObservable 对偶性

如果您仔细观察，这两种模式之间只有微妙的差异。`IEnumerable<T>`可以被认为是基于拉取的等价于基于推送的`IObservable<T>`。实际上，它们是对偶的。当两个实体交换信息时，一个实体的拉取对应于另一个实体推送信息。这种对偶性在下图中有所说明：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/a4538551-7bd5-4fcc-8a04-e2b682f92a84.png)

让我们通过查看这个示例代码，一个数字序列生成器，来理解这种对偶性：

我们努力使用经典的 C++构造来编写本章的程序，因为还有关于现代 C++语言特性、语言级并发、无锁编程以及实现现代 C++中的响应式构造的相关主题。

```cpp
#include <iostream>
#include <vector>
#include <iterator>
#include <memory>
#include "../Common2.h"
using namespace std;

class ConcreteEnumberable : public IEnumerable<int>
{
      int *numberlist,_count;
public:
      ConcreteEnumberable(int numbers[], int count):
            numberlist(numbers),_count(count){}
      ~ConcreteEnumberable() {}

      class Enumerator : public IEnumerator<int>
      {
      int *inumbers, icount, index;
      public:
      Enumerator(int *numbers,
            int count):inumbers(numbers),icount(count),index(0) {}
      bool HasMore() { return index < icount; }
      //---------- ideally speaking, the next function should throw
      //---------- an exception...instead it just returns -1 when the 
      //---------- bound has reached
      int next() { return (index < icount) ?
                   inumbers[index++] : -1; }
      ~Enumerator() {}
      };
      IEnumerator<int> *GetEnumerator()
            { return new Enumerator(numberlist, _count); }
};
```

前面的类以整数数组作为参数，并且我们可以枚举元素，因为我们已经实现了`IEnumerable<T>`接口。`Enumeration`逻辑由嵌套类实现，该嵌套类实现了`IEnumerator<T>`接口：

```cpp
int main()
{
      int x[] = { 1,2,3,4,5 };
      //-------- Has used Raw pointers on purpose here as we have
      //------- not introduced unique_ptr,shared_ptr,weak_ptr yet
      //-------- using auto_ptr will be confusting...otherwise
      //-------- need to use boost library here... ( an overkill)
      ConcreteEnumberable *t = new ConcreteEnumberable(x, 5);
      IEnumerator<int> * numbers = t->GetEnumerator();
      while (numbers->HasMore())
            cout << numbers->next() << endl;
      delete numbers;delete t;
      return 0;
}
```

主程序实例化了`ConcreteEnuerable`类的一个实现，并遍历每个元素。

我们将编写一个偶数序列生成器，以演示这些数据类型如何在将基于拉取的程序转换为推送程序时一起工作。鲁棒性方面给予了较低的优先级，以保持清单的简洁性：

```cpp
#include "stdafx.h"
#include <iostream>
#include <vector>
#include <iterator>
#include <memory>
#include "../Common2.h"
using namespace std;

class EvenNumberObservable : IObservable<int>{
      int *_numbers,_count;
public:
      EvenNumberObservable(int numbers[],
            int count):_numbers(numbers),_count(count){}
      bool Subscribe(IObserver<int>& observer){
            for (int i = 0; i < _count; ++i)
                  if (_numbers[i] % 2 == 0)
                        observer.OnNext(_numbers[i]);
            observer.OnCompleted();
            return true;
      }
};
```

前面的程序接受一个整数数组，过滤掉奇数，并在遇到偶数时通知`Observer<T>`。在这种情况下，数据源将数据推送给`observer`。`Observer<T>`的实现如下所示：

```cpp
class SimpleObserver : public IObserver<int>{
public:
      void OnNext(int value) { cout << value << endl; }
      void OnCompleted() { cout << _T("hello completed") << endl; }
      void OnError( CustomException * ex) {}
};
```

`SimpleObserver`类实现了`IObserver<T>`接口，并具有接收通知并对其做出反应的能力：

```cpp
int main()
{
      int x[] = { 1,2,3,4,5 };
      EvenNumberObservable *t = new EvenNumberObservable(x, 5);
      IObserver<int>> *xy = new SimpleObserver();
      t->Subscribe(*xy);
      delete xy; delete t;
      return 0;
}
```

从前面的例子中，您可以看到如何自然地订阅自然数的 Observable 序列中的偶数。当检测到偶数时，系统将自动向观察者（订阅者）“推送”（发布）值。代码为关键接口提供了明确的实现，以便人们可以理解或推测在幕后到底发生了什么。

# 将事件转换为 IObservable<T>

我们现在已经理解了如何将基于`IEnumerable<T>`的拉取程序转换为基于`IObservable<T>`/`IObserver<T>`的推送程序。在现实生活中，事件源并不像我们之前给出的数字流示例中那么简单。让我们看看如何将`MouseMove`事件转换为一个小型 MFC 程序中的流：

我们选择了 MFC 来实现这个特定的实现，因为我们有一章专门讲解基于 Qt 的响应式编程。在那一章中，我们将以成语异步推送流的方式实现响应式程序。在这个 MFC 程序中，我们只是进行了一个过滤操作，以查看鼠标是否在一个边界矩形内移动，如果是，则通知`observer`。我们在这里使用同步分发。这个示例也是同步的：

```cpp
#include "stdafx.h"
#include <afxwin.h>
#include <afxext.h>
#include <math.h>
#include <vector>
#include "../Common2.h"

using namespace std;
class CMouseFrame :public CFrameWnd,IObservable<CPoint>
{
private:
      RECT _rect;
      POINT _curr_pos;
      vector<IObserver<CPoint> *> _event_src;
public:
      CMouseFrame(){
            HBRUSH brush =
                  (HBRUSH)::CreateSolidBrush(RGB(175, 238, 238));
            CString mywindow = AfxRegisterWndClass(
                  CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS,
                  0, brush, 0);
            Create(mywindow, _T("MFC Clock By Praseed Pai"));
      }
```

代码的前面部分定义了一个`Frame`类，它从`MFC`库的`CFrameWnd`类派生，并实现了`IObservable<T>`接口，以强制程序员实现`Subscribe`方法。一个`IObserver<T>`的向量将存储`observers`或`Subscribers`的列表。在本例中，我们只有一个`observer`。代码中没有对`observer`的数量进行限制：

```cpp
      virtual bool Subscribe(IObserver<CPoint>& observer) {
            _event_src.push_back(&observer);
            return true;
      }
```

`Subscribe`方法只是将`observer`的引用存储到一个向量中并返回`true`：当鼠标移动时，我们从`MFC`库中获得通知，如果它在一个矩形区域内，`observer`将会被通知（通知代码如下）：

```cpp
      bool FireEvent(const CPoint& pt) {
            vector<IObserver<CPoint> *>::iterator it =
                  _event_src.begin();
            while (it != _event_src.end()){
                  IObserver<CPoint> *observer = *it;
                  observer->OnNext(pt);
                  //---------- In a Real world Rx programs there is a 
                  //--------- sequence stipulated to call methods...
                  //--------- OnCompleted will be called only when 
                  //--------- all the data is processed...this code
                  //--------- is written to demonstrate the call schema
                  observer->OnCompleted();
                  it++;
            }
            return true;
      }
```

`FireEvent`方法遍历`observer`并调用`observer`的`OnNext`方法。它还调用每个 Observer 的`OnCompleted`方法：Rx 调度机制在调用`observer`方法时遇到一些规则。如果调用了`OnComplete`方法，同一个`observer`将不再调用`OnNext`。同样，如果调用了`OnError`，将不会再向`observer`分发消息。如果我们需要遵循 Rx 模型规定的约定，代码将变得复杂。这里给出的代码目的是以一种概要的方式展示 Rx 编程模型的工作原理。

```cpp
      int OnCreate(LPCREATESTRUCT l){
            return CFrameWnd::OnCreate(l);
      }
      void SetCurrentPoint(CPoint pt) {
            this->_curr_pos = pt;
            Invalidate(0);
      }
```

`SetCurrentPoint`方法由`observer`调用以设置文本绘制的当前点。调用`Invalidate`方法触发`WM_PAINT`消息，`MFC`子系统将其路由到`OnPaint`（因为它在`Message`映射中被连接）：

```cpp
      void OnPaint()
      {
            CPaintDC d(this);
            CBrush b(RGB(100, 149, 237));
            int x1 = -200, y1 = -220, x2 = 210, y2 = 200;
            Transform(&x1, &y1); Transform(&x2, &y2);
            CRect rect(x1, y1, x2, y2);
            d.FillRect(&rect, &b);
            CPen p2(PS_SOLID, 2, RGB(153, 0, 0));
            d.SelectObject(&p2);

            char *str = "Hello Reactive C++";
            CFont f;
            f.CreatePointFont(240, _T("Times New Roman"));
            d.SelectObject(&f);
            d.SetTextColor(RGB(204, 0, 0));
            d.SetBkMode(TRANSPARENT);
            CRgn crgn;
            crgn.CreateRectRgn(rect.left,rect.top,
            rect.right ,rect.bottom);
            d.SelectClipRgn(&crgn);
            d.TextOut(_curr_pos.x, _curr_pos.y,
            CString(str), strlen(str));
      }
```

当调用`Invalidate`时，`OnPaint`方法由`MFC`框架调用。该方法在屏幕上绘制`literal`字符串`Hello Reactive C++`：

```cpp
      void Transform(int *px, int *py) {
            ::GetClientRect(m_hWnd, &_rect);
            int width = (_rect.right - _rect.left) / 2,
            height = (_rect.bottom - _rect.top) / 2;
           *px = *px + width; *py = height - *py;
      }
```

`Transform`方法计算`Frame`的客户区域的边界，并将`Cartesian`坐标转换为设备坐标。这种计算可以通过世界坐标变换更好地完成：

```cpp
      void OnMouseMove(UINT nFlags, CPoint point)
      {
            int x1 = -200,y1= -220, x2 = 210,y2 = 200;
            Transform(&x1, &y1);Transform(&x2, &y2);
            CRect rect(x1, y1, x2, y2);
            POINT pts;
            pts.x = point.x; pts.y = point.y;
            rect.NormalizeRect();
            //--- In a real program, the points will be aggregated
            //---- into a list (stream)
            if (rect.PtInRect(point)) {
                  //--- Ideally speaking this notification has to go
                  //--- through a non blocking call
                  FireEvent(point);
            }
      }
```

`OnMouseMove`方法检查鼠标位置是否在屏幕内的一个矩形区域内，并向`observer`发出通知：

```cpp
      DECLARE_MESSAGE_MAP();
};

BEGIN_MESSAGE_MAP(CMouseFrame, CFrameWnd)
      ON_WM_CREATE()
      ON_WM_PAINT()
      ON_WM_MOUSEMOVE()
END_MESSAGE_MAP()
class WindowHandler : public IObserver<CPoint>
{
private:
      CMouseFrame *window;
public:
      WindowHandler(CMouseFrame *win) : window(win) { }
      virtual ~WindowHandler() { window = 0; }
      virtual void OnCompleted() {}
      virtual void OnError(CustomException *exception) {}
      virtual void OnNext(CPoint value) {
            if (window) window->SetCurrentPoint(value);
      }
};
```

前面的`WindowHandler`类实现了`IObserver<T>`接口，并处理了由`CMouseFrame`通知的事件，后者实现了`IObservable<CPoint>`接口。在这个示例中，我们通过调用`SetCurrentPoint`方法来设置当前点，以便在鼠标位置绘制字符串：

```cpp
class CMouseApp :public CWinApp
{
      WindowHandler *reactive_handler;
public:
      int InitInstance(){
            CMouseFrame *p = new CMouseFrame();
            p->ShowWindow(1);
            reactive_handler = new WindowHandler(p);
            //--- Wire the observer to the Event Source
            //--- which implements IObservable<T>
            p->Subscribe(*reactive_handler);
            m_pMainWnd = p;
            return 1;
      }
      virtual ~CMouseApp() {
            if (reactive_handler) {
                  delete reactive_handler;
                  reactive_handler = 0;
           }
      }
};

CMouseApp a;
```

# 我们的书的哲学

本章的目的是向读者介绍响应式编程模式的关键接口，它们是`IObservable<T>`和`IObserver<T>`。实际上，它们是`IEnumerable<T>`和`IEnumerator<T>`接口的对偶。我们学习了如何在经典 C++中对这些接口进行建模（大部分），并对它们进行了玩具实现。最后，我们实现了一个捕获鼠标移动并通知一系列观察者的 GUI 程序。这些玩具实现是为了让我们初步了解响应式编程模式的思想和理想。我们的实现可以被视为基于面向对象的响应式编程的实现。

要精通 C++响应式编程，程序员必须熟悉以下主题：

+   现代 C++提供的高级语言构造

+   现代 C++提供的函数式编程构造

+   异步编程（RxCpp 为您处理！）模型

+   事件流处理

+   对 RxCpp 等工业级库的了解

+   RxCpp 在 GUI 和 Web 编程中的应用

+   高级响应式编程构造

+   处理错误和异常

本章主要讨论了关键的习语以及为什么我们需要一个强大的模型来处理异步数据。接下来的三章将涵盖现代 C++的语言特性，使用 C++标准构造处理并发/并行性，以及无锁编程（由内存模型保证实现）。前面的主题将为用户提供坚实的基础，以便掌握函数式响应式编程。

在[第五章]《可观察对象简介》中，我们将再次回到可观察对象的主题，并以函数式的方式实现接口，重申一些概念。在[第六章]《使用 C++进行事件流编程简介》中，我们将借助两个工业级库，使用**领域特定嵌入式语言**（DSEL）方法处理高级事件流处理主题。

到目前为止，用户将有机会接触工业级 RxCpp 库及其细微之处，以编写专业质量的现代 C++程序。在第七章《数据流计算和 RxCpp 库简介》和第八章《RxCpp - 关键要素》中，我们将介绍这个出色的库。接下来的章节将涵盖使用 Qt 库进行响应式 GUI 编程以及 RxCpp 中的高级操作符。

最后三章涵盖了响应式设计模式、C++中的微服务以及错误/异常处理的高级主题。在本书结束时，从经典 C++开始的读者将不仅在编写响应式程序方面取得了很大进展，而且在 C++语言本身方面也有了很大进步。由于主题的性质，我们将涵盖 C++ 17 的大部分特性（在撰写时）。

# 总结

在本章中，我们了解了 Rx 编程模型的一些关键数据结构。我们实现了它们的玩具版本，以熟悉支撑它们的概念细微差别。我们从 Windows API、XLib API、MFC 和 Qt 处理 GUI 事件开始。我们还简要介绍了在 COM+/CORBA 中如何处理事件。然后，我们快速概述了响应式编程。在介绍了一些接口后，我们从头开始实现了它们。最后，为了完整起见，我们在 MFC 上实现了这些接口的 GUI 版本。我们还处理了本书的一些关键哲学方面。

在下一章中，我们将快速浏览现代 C++（C++版本 11/14/17）的关键特性，重点介绍移动语义、Lambda、类型推断、基于范围的循环、可管道的操作符、智能指针等。这对于编写响应式编程的基本代码至关重要。


# 第二章：现代 C++及其关键习语之旅

经典的 C++编程语言在 1998 年被标准化，随后在 2003 年进行了一次小的修订（主要是更正）。为了支持高级抽象，开发人员依赖于 Boost ([`www.boost.org`](http://www.boost.org))库和其他公共领域库。由于下一波标准化的到来，语言（从 C++ 11 开始）得到了增强，现在开发人员可以在不依赖外部库的情况下编码大多数其他语言支持的抽象。甚至线程和文件系统接口，原本属于库的范畴，现在已成为标准语言的一部分。现代 C++（代表 C++版本 11/14/17）包含了对语言和其库的出色增强，使得 C++成为编写工业级生产软件的事实选择。本章涵盖的功能是程序员必须了解的最小功能集，以便使用响应式编程构造，特别是 RxCpp。本章的主要目标是介绍语言的最重要的增强功能，使得实现响应式编程构造更加容易，而不需要使用神秘的语言技术。本章将涵盖以下主题：

+   C++编程语言设计的关键问题

+   一些用于编写更好代码的 C++增强功能

+   通过右值引用和移动语义实现更好的内存管理

+   使用增强的智能指针实现更好的对象生命周期管理

+   使用 Lambda 函数和表达式进行行为参数化

+   函数包装器（`std::function`类型）

+   其他功能

+   编写迭代器和观察者（将所有内容整合在一起）

# C++编程语言的关键问题

就开发人员而言，C++编程语言设计者关注的三个关键问题是（现在仍然是）：

+   零成本抽象 - 高级抽象不会带来性能惩罚

+   表现力 - 用户定义类型（UDT）或类应该与内置类型一样具有表现力

+   可替代性 - UDT 可以在期望内置类型的任何地方替代（如通用数据结构和算法）

我们将简要讨论这些内容。

# 零成本抽象

C++编程语言一直帮助开发人员编写利用微处理器的代码（生成的代码运行在微处理器上），并在需要时提高抽象级别。在提高抽象级别的同时，语言的设计者们一直试图最小化（几乎消除）性能开销。这被称为零成本抽象或零开销成本抽象。你所付出的唯一显著代价是间接调用的成本（通过函数指针）来分派虚拟函数。尽管向语言添加了大量功能，设计者们仍然保持了语言从一开始就暗示的“零成本抽象”保证。

# 表现力

C++帮助开发人员编写用户定义类型或类，可以像编程语言的内置类型一样具有表现力。这使得可以编写任意精度算术类（在某些语言中被称为`BigInteger`/`BigFloat`），其中包含了双精度或浮点数的所有特性。为了说明，我们定义了一个`SmartFloat`类，它包装了 IEEE 双精度浮点数，并重载了大多数双精度数据类型可用的运算符。以下代码片段显示，可以编写模仿内置类型（如 int、float 或 double）语义的类型：

```cpp
//---- SmartFloat.cpp
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
class SmartFloat {
     double _value; // underlying store
   public:
      SmartFloat(double value) : _value(value) {}
      SmartFloat() : _value(0) {}
      SmartFloat( const SmartFloat& other ) { _value = other._value; }
      SmartFloat& operator = ( const SmartFloat& other ) {
          if ( this != &other ) { _value = other._value;}
          return *this;
      }
      SmartFloat& operator = (double value )
       { _value = value; return *this;}
      ~SmartFloat(){ }
```

`SmartFloat`类包装了一个 double 值，并定义了一些构造函数和赋值运算符来正确初始化实例。在下面的代码片段中，我们将定义一些操作符来增加值。前缀和后缀变体的操作符都已定义：

```cpp
      SmartFloat& operator ++ () { _value++; return *this; }
      SmartFloat operator ++ (int) { // postfix operator
             SmartFloat nu(*this); ++_value; return nu;
      }
      SmartFloat& operator -- () { _value--; return *this; }
      SmartFloat operator -- (int) {
           SmartFloat nu(*this); --_value; return nu;
      }
```

前面的代码片段实现了增量运算符（前缀和后缀），仅用于演示目的。在真实的类中，我们将检查浮点溢出和下溢，以使代码更加健壮。包装类型的整个目的是编写健壮的代码！

```cpp
     SmartFloat& operator += ( double x ) { _value += x; return *this;}
     SmartFloat& operator -= ( double x ) { _value -= x;return *this; }
     SmartFloat& operator *= ( double x ) { _value *= x; return *this;}
     SmartFloat& operator /= ( double x ) { _value /= x; return *this;}
```

前面的代码片段实现了 C++风格的赋值运算符，再次为了简洁起见，我们没有检查是否存在任何浮点溢出或下溢。我们也没有处理异常，以保持清单的简洁。

```cpp
      bool operator > ( const SmartFloat& other )
        { return _value > other._value; }
      bool operator < ( const SmartFloat& other )
       {return _value < other._value;}
      bool operator == ( const SmartFloat& other )
        { return _value == other._value;}
      bool operator != ( const SmartFloat& other )
        { return _value != other._value;}
      bool operator >= ( const SmartFloat& other )
        { return _value >= other._value;}
      bool operator <= ( const SmartFloat& other )
        { return _value <= other._value;}
```

前面的代码实现了关系运算符，并且大部分与双精度浮点数相关的语义都已经实现如下：

```cpp
      operator int () { return _value; }
      operator double () { return _value;}
};
```

为了完整起见，我们已经实现了到`int`和`double`的转换运算符。我们将编写两个函数来聚合存储在数组中的值。第一个函数期望一个`double`数组作为参数，第二个函数期望一个`SmartFloat`数组作为参数。两个例程中的代码是相同的，只是类型不同。两者将产生相同的结果：

```cpp
double Accumulate( double a[] , int count ){
    double value = 0;
    for( int i=0; i<count; ++i) { value += a[i]; }
    return value;
}
double Accumulate( SmartFloat a[] , int count ){
    SmartFloat value = 0;
    for( int i=0; i<count; ++i) { value += a[i]; }
    return value;
}
int main() {
    // using C++ 1z's initializer list
    double x[] = { 10.0,20.0,30,40 };
    SmartFloat y[] = { 10,20.0,30,40 };
    double res = Accumulate(x,4); // will call the double version
    cout << res << endl;
    res = Accumulate(y,4); // will call the SmartFloat version
    cout << res << endl;
}
```

C++语言帮助我们编写富有表现力的类型，增强基本类型的语义。语言的表现力还帮助我们使用语言支持的多种技术编写良好的值类型和引用类型。通过支持运算符重载、转换运算符、放置 new 和其他相关技术，与其同时代的其他语言相比，该语言已将类设计提升到了一个更高的水平。但是，能力与责任并存，有时语言会给你足够的自由让你自食其果。

# 可替代性

在前面的例子中，我们看到了如何使用用户定义的类型来表达对内置类型进行的所有操作。C++的另一个目标是以一种通用的方式编写代码，其中我们可以替换一个模拟内置类型（如`float`、`double`、`int`等）语义的用户定义类：

```cpp
//------------- from SmartValue.cpp
template <class T>
T Accumulate( T a[] , int count ) {
    T value = 0;
    for( int i=0; i<count; ++i) { value += a[i]; }
    return value;
}
int main(){
    //----- Templated version of SmartFloat
    SmartValue<double> y[] = { 10,20.0,30,40 };
    double res = Accumulate(y,4);
    cout << res << endl;
}
```

C++编程语言支持不同的编程范式，前面概述的三个原则只是其中的一些。该语言支持可以帮助创建健壮类型（特定领域）以编写更好代码的构造。这三个原则确实为我们带来了一个强大而快速的编程语言。现代 C++确实添加了许多新的抽象，以使程序员的生活更加轻松。但是，为了实现这些目标，之前概述的三个设计原则并没有以任何方式被牺牲。这在一定程度上是可能的，因为语言由于模板机制的无意中图灵完备性而具有元编程支持。使用您喜欢的搜索引擎阅读有关**模板元编程**（**TMP**）和图灵完备性的内容。 

# C++增强以编写更好的代码

在过去的十年里，编程语言的世界发生了很大变化，这些变化应该反映在 C++编程语言的新版本中。现代 C++中的大部分创新涉及处理高级抽象，并引入函数式编程构造以支持语言级并发。大多数现代语言都有垃圾收集器，运行时管理这些复杂性。C++编程语言没有自动垃圾收集作为语言标准的一部分。C++编程语言以其隐式的零成本抽象保证（你不用为你不使用的东西付费）和最大的运行时性能，必须依靠大量的编译时技巧和元编程技术来实现 C#、Java 或 Scala 等语言支持的抽象级别。其中一些在以下部分中概述，你可以自行深入研究这些主题。网站[`en.cppreference.com`](http://en.cppreference.com)是提高你对 C++编程语言知识的一个好网站。

# 类型推断和推理

现代 C++语言编译器在程序员指定的表达式和语句中推断类型方面做得非常出色。大多数现代编程语言都支持类型推断，现代 C++也是如此。这是从 Haskell 和 ML 等函数式编程语言借鉴来的习惯用法。类型推断已经在 C#和 Scala 编程语言中可用。我们将编写一个小程序来启动我们的类型推断：

```cpp
//----- AutoFirst.cpp
#include <iostream>
#include <vector>
using namespace std;
int main(){
    vector<string> vt = {"first", "second", "third", "fourth"};
    //--- Explicitly specify the Type ( makes it verbose)
    for (vector<string>::iterator it = vt.begin();
        it != vt.end(); ++it)
    cout << *it << " ";
    //--- Let the compiler infer the type for us
    for (auto it2 = vt.begin(); it2 != vt.end(); ++it2)
        cout << *it2 << " ";
    return 0;
}
```

`auto`关键字指定变量的类型将根据初始化和表达式中指定的函数的返回值由编译器推导出来。在这个特定的例子中，我们并没有获得太多。随着我们的声明变得更加复杂，最好让编译器进行类型推断。我们的代码清单将使用 auto 来简化整本书的代码。现在，让我们编写一个简单的程序来更清楚地阐明这个想法：

```cpp
//----- AutoSecond.cpp
#include <iostream>
#include <vector>
#include <initializer_list>
using namespace std;
int main() {
    vector<double> vtdbl = {0, 3.14, 2.718, 10.00};
    auto vt_dbl2 = vtdbl; // type will be deduced
    auto size = vt_dbl2.size(); // size_t
    auto &rvec = vtdbl; // specify a auto reference
    cout << size << endl;
    // Iterate - Compiler infers the type
    for ( auto it = vtdbl.begin(); it != vtdbl.end(); ++it)
        cout << *it << " ";
    // 'it2' evaluates to iterator to vector of double
    for (auto it2 = vt_dbl2.begin(); it2 != vt_dbl2.end(); ++it2)
        cout << *it2 << " ";
    // This will change the first element of vtdbl vector
    rvec[0] = 100;
    // Now Iterate to reflect the type
    for ( auto it3 = vtdbl.begin(); it3 != vtdbl.end(); ++it3)
        cout << *it3 << " ";
    return 0;
}
```

前面的代码演示了在编写现代 C++代码时使用类型推断。C++编程语言还有一个新关键字，用于查询给定参数的表达式的类型。关键字的一般形式是`decltype(<expr>)`。以下程序有助于演示这个特定关键字的用法：

```cpp
//---- Decltype.cpp
#include <iostream>
using namespace std;
int foo() { return 10; }
char bar() { return 'g'; }
auto fancy() -> decltype(1.0f) { return 1;} //return type is float
int main() {
    // Data type of x is same as return type of foo()
    // and type of y is same as return type of bar()
    decltype(foo()) x;
    decltype(bar()) y;
    //--- in g++, Should print i => int
    cout << typeid(x).name() << endl;
    //--- in g++, Should print c => char 
    cout << typeid(y).name() << endl;
    struct A { double x; };
    const A* a = new A();
    decltype(a->x) z; // type is double
    decltype((a->x)) t= z; // type is const double&
    //--- in g++, Should print  d => double
    cout << typeid(z).name() << endl;
    cout << typeid(t).name() << endl;
    //--- in g++, Should print  f => float
    cout << typeid(decltype(fancy())).name() << endl;
    return 0;
}
```

`decltype`是一个编译时构造，它有助于指定变量的类型（编译器将进行艰苦的工作来找出它），并且还可以帮助我们强制变量的类型（参见前面的`fancy()`函数）。

# 变量的统一初始化

经典 C++对变量的初始化有一些特定的 ad-hoc 语法。现代 C++支持统一初始化（我们已经在类型推断部分看到了示例）。语言为开发人员提供了辅助类，以支持他们自定义类型的统一初始化：

```cpp
//----------------Initialization.cpp
#include <iostream>
#include <vector>
#include <initializer_list>
using namespace std;
template <class T>
struct Vector_Wrapper {
    std::vector<T> vctr;
    Vector_Wrapper(std::initializer_list<T> l) : vctr(l) {}
    void Append(std::initializer_list<T> l)
    { vctr.insert(vctr.end(), l.begin(), l.end());}
};
int main() {
    Vector_Wrapper<int> vcw = {1, 2, 3, 4, 5}; // list-initialization
    vcw.Append({6, 7, 8}); // list-initialization in function call
    for (auto n : vcw.vctr) { std::cout << n << ' '; }
    std::cout << '\n';
}
```

前面的清单显示了如何使程序员创建的自定义类启用初始化列表。

# 可变模板

在 C++ 11 及以上版本中，标准语言支持可变模板。可变模板是一个接受可变数量的模板参数的模板类或模板函数。在经典 C++中，模板实例化发生在固定数量的参数中。可变模板在类级别和函数级别都得到支持。在本节中，我们将处理可变函数，因为它们在编写函数式程序、编译时编程（元编程）和可管道函数中被广泛使用：

```cpp
//Variadic.cpp
#include <iostream>
#include <iterator>
#include <vector>
#include <algorithm>
using namespace std;
//--- add given below is a base case for ending compile time
//--- recursion
int add() { return 0; } // end condition
//---- Declare a Variadic function Template
//---- ... is called parameter pack. The compiler
//--- synthesize a function based on the number of arguments
//------ given by the programmer.
//----- decltype(auto) => Compiler will do Type Inference
template<class T0, class ... Ts>
decltype(auto) add(T0 first, Ts ... rest) {
    return first + add(rest ...);
}
int main() { int n = add(0,2,3,4); cout << n << endl; }
```

在上面的代码中，编译器根据传递的参数数量合成一个函数。编译器理解`add`是一个可变参数函数，并通过在编译时递归展开参数来生成代码。编译时递归将在编译器处理完所有参数时停止。基本情况版本是一个提示编译器停止递归的方法。下一个程序展示了可变模板和完美转发如何用于编写接受任意数量参数的函数：

```cpp
//Variadic2.cpp
#include <iostream>
#include <iterator>
#include <vector>
#include <algorithm>
using namespace std;
//--------- Print values to the console for basic types
//-------- These are base case versions
void EmitConsole(int value) { cout << "Integer: " << value << endl; }
void EmitConsole(double value) { cout << "Double: " << value << endl; }
void EmitConsole(const string& value){cout << "String: "<<value<< endl; }
```

`EmitConsole` 的三个变体将参数打印到控制台。我们有打印`int`、`double`和`string`的函数。利用这些函数作为基本情况，我们将编写一个使用通用引用和完美转发的函数，以编写接受任意值的函数：

```cpp
template<typename T>
void EmitValues(T&& arg) { EmitConsole(std::forward<T>(arg)); }

template<typename T1, typename... Tn>
void EmitValues(T1&& arg1, Tn&&... args){
    EmitConsole(std::forward<T1>(arg1));
    EmitValues(std::forward<Tn>(args)...);
}

int main() { EmitValues(0,2.0,"Hello World",4); }
```

# 右值引用

如果你长时间在 C++中编程，你可能知道 C++引用可以帮助你给变量取别名，并且可以对引用进行赋值以反映变量别名的变化。C++支持的引用类型称为左值引用（因为它们是引用可以出现在赋值的左侧的变量的引用）。以下代码片段展示了左值引用的用法：

```cpp
//---- Lvalue.cpp
#include <iostream>
using namespace std;
int main() {
  int i=0;
  cout << i << endl; //prints 0
  int& ri = i;
  ri = 20;
  cout << i << endl; // prints 20
}
```

`int&` 是左值引用的一个实例。在现代 C++中，有右值引用的概念。右值被定义为任何不是左值的东西，可以出现在赋值的右侧。在经典的 C++中，没有右值引用的概念。现代 C++引入了它：

```cpp
///---- Rvaluref.cpp
#include <iostream>using namespace std;
int main() {
    int&& j = 42;int x = 3,y=5; int&& z = x + y; cout << z << endl;
    z = 10; cout << z << endl;j=20;cout << j << endl;
}
```

右值引用由两个`&&`表示。以下程序将清楚地演示了在调用函数时使用右值引用：

```cpp
//------- RvaluerefCall.cpp
#include <iostream>
using namespace std;
void TestFunction( int & a ) {cout << a << endl;}
void TestFunction( int && a ){
    cout << "rvalue references" << endl;
    cout << a << endl;
}
int main() {
int&& j = 42;
int x = 3,y=5;
int&& z = x + y;
    TestFunction(x + y ); // Should call rvalue reference function
    TestFunction(j); // Calls Lvalue Refreence function
}
```

右值引用的真正威力在于内存管理方面。C++编程语言具有复制构造函数和赋值运算符的概念。它们大多数情况下是复制源对象的内容。借助右值引用，可以通过交换指针来避免昂贵的复制，因为右值引用是临时的或中间表达式。下一节将演示这一点。

# 移动语义

C++编程语言隐式地为我们设计的每个类提供了一个复制构造函数、赋值运算符和一个析构函数（有时是虚拟的）。这是为了在克隆对象或对现有对象进行赋值时进行资源管理。有时复制对象是非常昂贵的，通过指针的所有权转移有助于编写快速的代码。现代 C++提供了移动构造函数和移动赋值运算符的功能，以帮助开发人员避免复制大对象，在创建新对象或对新对象进行赋值时。右值引用可以作为一个提示，告诉编译器在涉及临时对象时，构造函数的移动版本或赋值的移动版本更适合于上下文：

```cpp
//----- FloatBuffer.cpp
#include <iostream>
#include <vector>
using namespace std;
class FloatBuffer {
    double *bfr; int count;
public:
    FloatBuffer():bfr(nullptr),count(0){}
    FloatBuffer(int pcount):bfr(new double[pcount]),count(pcount){}
        // Copy constructor.
    FloatBuffer(const FloatBuffer& other) : count(other.count)
        , bfr(new double[other.count])
    { std::copy(other.bfr, other.bfr + count, bfr); }
    // Copy assignment operator - source code is obvious
    FloatBuffer& operator=(const FloatBuffer& other) {
        if (this != &other) {
          if ( bfr != nullptr) 
            delete[] bfr; // free memory of the current object
            count = other.count;
            bfr = new double[count]; //re-allocate
            std::copy(other.bfr, other.bfr + count, bfr);
        }
        return *this;
    }
    // Move constructor to enable move semantics
    // The Modern STL containers supports move sementcis
    FloatBuffer(FloatBuffer&& other) : bfr(nullptr) , count(0) {
    cout << "in move constructor" << endl;
    // since it is a move constructor, we are not copying elements from
    // the source object. We just assign the pointers to steal memory
    bfr = other.bfr;
    count = other.count;
    // Now that we have grabbed our memory, we just assign null to
    // source pointer
    other.bfr = nullptr;
    other.count = 0;
    }
// Move assignment operator.
FloatBuffer& operator=(FloatBuffer&& other) {
    if (this != &other)
    {
        // Free the existing resource.
        delete[] bfr;
       // Copy the data pointer and its length from the
       // source object.
       bfr = other.bfr;
       count = other.count;
       // We have stolen the memory, now set the pinter to null
       other.bfr = nullptr;
       other.count = 0;
    }
    return *this;
}

};
int main() {
    // Create a vector object and add a few elements to it.
    // Since STL supports move semantics move methods will be called.
    // in this particular case (Modern Compilers are smart)
    vector<FloatBuffer> v;
    v.push_back(FloatBuffer(25));
    v.push_back(FloatBuffer(75));
}
```

`std::move` 函数可用于指示（在传递参数时）候选对象是可移动的，编译器将调用适当的方法（移动赋值或移动构造函数）来优化与内存管理相关的成本。基本上，`std::move` 是对右值引用的`static_cast`。

# 智能指针

管理对象生命周期一直是 C++编程语言的一个问题。如果开发人员不小心，程序可能会泄漏内存并降低性能。智能指针是围绕原始指针的包装类，其中重载了解引用(*)和引用(->)等操作符。智能指针可以进行对象生命周期管理，充当有限形式的垃圾回收，释放内存等。现代 C++语言具有：

+   `unique_ptr<T>`

+   `shared_ptr<T>`

+   `weak_ptr<T>`

`unique_ptr<T>`是一个具有独占所有权的原始指针的包装器。以下代码片段将演示`<unique_ptr>`的使用：

```cpp
//---- Unique_Ptr.cpp
#include <iostream>
#include <deque>#include <memory>
using namespace std;
int main( int argc , char **argv ) {
    // Define a Smart Pointer for STL deque container...
    unique_ptr< deque<int> > dq(new deque<int>() );
    //------ populate values , leverages -> operator
    dq->push_front(10); dq->push_front(20);
    dq->push_back(23); dq->push_front(16);
    dq->push_back(41);
    auto dqiter = dq->begin();
    while ( dqiter != dq->end())
    { cout << *dqiter << "\n"; dqiter++; }
    //------ SmartPointer will free reference
    //------ and it's dtor will be called here
    return 0;
}
```

`std::shared_ptr`是一个智能指针，它使用引用计数来跟踪对对象实例的引用。当指向它的最后一个`shared_ptr`被销毁或重置时，底层对象将被销毁：

```cpp
//----- Shared_Ptr.cpp
#include <iostream>
#include <memory>
#include <stdio.h>
using namespace std;
////////////////////////////////////////
// Even If you pass shared_ptr<T> instance
// by value, the update is visible to callee
// as shared_ptr<T>'s copy constructor reference
// counts to the orgininal instance
//

void foo_byvalue(std::shared_ptr<int> i) { (*i)++;}

///////////////////////////////////////
// passed by reference,we have not
// created a copy.
//
void foo_byreference(std::shared_ptr<int>& i) { (*i)++; }
int main(int argc, char **argv )
{
    auto sp = std::make_shared<int>(10);
    foo_byvalue(sp);
    foo_byreference(sp);
    //--------- The output should be 12
    std::cout << *sp << std::endl;
}
```

`std:weak_ptr`是一个原始指针的容器。它是作为`shared_ptr`的副本创建的。`weak_ptr`的存在或销毁对`shared_ptr`或其其他副本没有影响。在所有`shared_ptr`的副本被销毁后，所有`weak_ptr`的副本都变为空。以下程序演示了使用`weak_ptr`来检测失效指针的机制：

```cpp
//------- Weak_Ptr.cpp
#include <iostream>
#include <deque>
#include <memory>

using namespace std;
int main( int argc , char **argv )
{
    std::shared_ptr<int> ptr_1(new int(500));
    std::weak_ptr<int> wptr_1 = ptr_1;
    {
        std::shared_ptr<int> ptr_2 = wptr_1.lock();
        if(ptr_2)
        {
            cout << *ptr_2 << endl; // this will be exeucted
        }
    //---- ptr_2 will go out of the scope
    }

    ptr_1.reset(); //Memory is deleted.

    std::shared_ptr<int> ptr_3= wptr_1.lock();
    //-------- Always else part will be executed
    //-------- as ptr_3 is nullptr now 
    if(ptr_3)
        cout << *ptr_3 << endl;
    else
        cout << "Defunct Pointer" << endl;
    return 0;
}
```

经典 C++有一个名为`auto_ptr`的智能指针类型，已从语言标准中删除。需要使用`unique_ptr`代替。

# Lambda 函数

C++语言的一个主要增强是 Lambda 函数和 Lambda 表达式。它们是程序员可以在调用站点定义的匿名函数，用于执行一些逻辑。这简化了逻辑，代码的可读性也以显着的方式增加。

与其定义 Lambda 函数是什么，不如编写一段代码来帮助我们计算`vector<int>`中正数的数量。在这种情况下，我们需要过滤掉负值并计算剩下的值。我们将使用 STL `count_if`来编写代码：

```cpp
//LambdaFirst.cpp
#include <iostream>
#include <iterator>
#include <vector>
#include <algorithm>
using namespace std;
int main() {
    auto num_vect =
        vector<int>{ 10, 23, -33, 15, -7, 60, 80};
    //---- Define a Lambda Function to Filter out negatives
    auto filter = [](int const value) {return value > 0; };
    auto cnt= count_if(
        begin(num_vect), end(num_vect),filter);
    cout << cnt << endl;
}
```

在上面的代码片段中，变量 filter 被赋予了一个匿名函数，并且我们在`count_if STL`函数中使用了 filter。现在，让我们编写一个简单的 Lambda 函数，在函数调用时指定。我们将使用 STL accumulate 来聚合向量中的值：

```cpp
//-------------- LambdaSecond.cpp
#include <iostream>
#include <iterator>
#include <vector>
#include <algorithm>
#include <numeric>
using namespace std;
int main() {
    auto num_vect =
        vector<int>{ 10, 23, -33, 15, -7, 60, 80};
    //-- Define a BinaryOperation Lambda at the call site
    auto accum = std::accumulate(
        std::begin(num_vect), std::end(num_vect), 0,
        [](auto const s, auto const n) {return s + n;});
    cout << accum << endl;
}
```

# 函数对象和 Lambda

在经典的 C++中，使用 STL 时，我们广泛使用函数对象或函数符号，通过重载函数运算符来编写转换过滤器和对 STL 容器执行减少操作：

```cpp
//----- LambdaThird.cpp
#include <iostream>
#include <numeric>
using namespace std;
//////////////////////////
// Functors to add and multiply two numbers
template <typename T>
struct addition{
    T operator () (const T& init, const T& a ) { return init + a; }
};
template <typename T>
struct multiply {
    T operator () (const T& init, const T& a ) { return init * a; }
};
int main()
{
    double v1[3] = {1.0, 2.0, 4.0}, sum;
    sum = accumulate(v1, v1 + 3, 0.0, addition<double>());
    cout << "sum = " << sum << endl;
    sum = accumulate(v1,v1+3,0.0, [] (const double& a ,const double& b   ) {
        return a +b;
    });
    cout << "sum = " << sum << endl;
    double mul_pi = accumulate(v1, v1 + 3, 1.0, multiply<double>());
    cout << "mul_pi = " << mul_pi << endl;
    mul_pi= accumulate(v1,v1+3,1, [] (const double& a , const double& b ){
        return a *b;
    });
    cout << "mul_pi = " << mul_pi << endl;
}
```

以下程序清楚地演示了通过编写一个玩具排序程序来使用 Lambda。我们将展示如何使用函数对象和 Lambda 来编写等效的代码。该代码以一种通用的方式编写，但假设数字是预期的（`double`，`float`，`integer`或用户定义的等效类型）：

```cpp
/////////////////
//-------- LambdaFourth.cpp
#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;
//--- Generic functions for Comparison and Swap
template <typename T>
bool Cmp( T& a , T&b ) {return ( a > b ) ? true: false;}
template <typename T>
void Swap( T& a , T&b ) { T c = a;a = b;b = c;}
```

`Cmp`和`Swap`是通用函数，将用于比较相邻元素和交换元素，同时执行排序操作：

```cpp
template <typename T>
void BubbleSortFunctor( T *arr , int length ) {
    for( int i=0; i< length-1; ++i )
        for(int j=i+1; j< length; ++j )
            if ( Cmp( arr[i] , arr[j] ) )
                Swap(arr[i],arr[j] );
}
```

有了 Cmp 和 Swap，编写冒泡排序就变得简单了。我们需要有一个嵌套循环，在其中我们将比较两个元素，如果 Cmp 返回 true，我们将调用 Swap 来交换值：

```cpp
template <typename T>
void BubbleSortLambda( T *arr , int length ) {
    auto CmpLambda = [] (const auto& a , const auto& b )
    { return ( a > b ) ? true: false; };
    auto SwapLambda = [] ( auto& a , auto& b )
    { auto c = a;a = b;b = c;};
    for( int i=0; i< length-1; ++i )
        for(int j=i+1; j< length; ++j )
            if ( CmpLambda( arr[i] , arr[j] ) )
                SwapLambda (arr[i],arr[j] );
}
```

在上面的例程中，我们将比较和交换函数定义为 Lambda。Lambda 函数是一种在调用站点内指定代码或表达式的机制，通常称为匿名函数。定义可以使用 C++语言指定的语法，并且可以赋值给变量，作为参数传递，或者从函数返回。在上面的函数中，变量`CmpLambda`和`SwapLambda`是 Lambda 语法中指定的匿名函数的示例。Lambda 函数的主体与之前的函数版本没有太大的不同。要了解有关 Lambda 函数和表达式的更多信息，可以参考[`en.cppreference.com/w/cpp/language/lambda`](http://en.cppreference.com/w/cpp/language/lambda)页面。

```cpp
template <typename T>
void Print( const T& container){
    for(auto i = container.begin() ; i != container.end(); ++i )
        cout << *i << "\n" ;
}
```

`Print`例程只是循环遍历容器中的元素，并将内容打印到控制台：

```cpp
int main( int argc , char **argv ){
    double ar[4] = {20,10,15,-41};
    BubbleSortFunctor(ar,4);
    vector<double> a(ar,ar+4);
    Print(a);
    cout << "=========================================" << endl;
    ar[0] = 20;ar[1] = 10;ar[2] = 15;ar[3] = -41;
    BubbleSortLambda(ar,4);
    vector<double> a1(ar,ar+4);
    Print(a1);
    cout << "=========================================" << endl;
}
```

# 组合、柯里化和部分函数应用

Lambdas 的一个优点是你可以将两个函数组合在一起，创建函数的组合，就像你在数学中所做的那样（在数学和函数式编程的上下文中阅读有关函数组合的内容，使用喜欢的搜索引擎）。以下程序演示了这个想法。这是一个玩具实现，撰写通用实现超出了本章的范围：

```cpp
//------------ Compose.cpp
//----- g++ -std=c++1z Compose.cpp
#include <iostream>
using namespace std;
//---------- base case compile time recursion
//---------- stops here
template <typename F, typename G>
auto Compose(F&& f, G&& g)
{ return = { return f(g(x)); };}
//----- Performs compile time recursion based
//----- on number of parameters
template <typename F, typename... R>
auto Compose(F&& f, R&&... r){
    return = { return f(Compose(r...)(x)); };
}
```

`Compose`是一个可变模板函数，编译器通过递归扩展`Compose`参数生成代码，直到处理完所有参数。在前面的代码中，我们使用`[=]`指示编译器应该按值捕获 Lambda 体中引用的所有变量。您可以在函数式编程的上下文中学习更多关于闭包和变量捕获的内容。C++语言允许通过值（以及使用`[&]`）或通过显式指定要捕获的变量（如`[&var]`）来灵活地`Capture`变量。

函数式编程范式基于由美国数学家阿隆佐·邱奇发明的一种数学形式主义，称为 Lambda 演算。Lambda 演算仅支持一元函数，柯里化是一种将多参数函数分解为一系列一次接受一个参数的函数评估的技术。

使用 Lambdas 和以特定方式编写函数，我们可以在 C++中模拟柯里化：

```cpp
auto CurriedAdd3(int x) {
    return x { //capture x
        return x, y{ return x + y + z; };
    };
};
```

部分函数应用涉及将具有多个参数的函数转换为固定数量的参数。如果固定数量的参数少于函数的 arity（参数计数），则将返回一个新函数，该函数期望其余的参数。当接收到所有参数时，将调用该函数。我们可以将部分应用视为某种形式的记忆化，其中参数被缓存，直到我们接收到所有参数以调用它们。

在以下代码片段中，我们使用了模板参数包和可变模板。模板参数包是一个接受零个或多个模板参数（非类型、类型或模板）的模板参数。函数参数包是一个接受零个或多个函数参数的函数参数。至少有一个参数包的模板称为可变模板。对参数包和可变模板的良好理解对于理解`sizeof...`构造是必要的。

```cpp
template <typename... Ts>
auto PartialFunctionAdd3(Ts... xs) {
    //---- http://en.cppreference.com/w/cpp/language/parameter_pack
    //---- http://en.cppreference.com/w/cpp/language/sizeof...
    static_assert(sizeof...(xs) <= 3);
    if constexpr (sizeof...(xs) == 3){
        // Base case: evaluate and return the sum.
        return (0 + ... + xs);
    }
    else{
        // Recursive case: bind `xs...` and return another
        return xs...{
            return PartialFunctionAdd3(xs..., ys...);
        };
    }
}
int main() {
    // ------------- Compose two functions together
    //----https://en.wikipedia.org/wiki/Function_composition
    auto val = Compose(
        [](int const a) {return std::to_string(a); },
        [](int const a) {return a * a; })(4); // val = "16"
    cout << val << std::endl; //should print 16
    // ----------------- Invoke the Curried function
    auto p = CurriedAdd3(4)(5)(6);
    cout << p << endl;
    //-------------- Compose a set of function together
    auto func = Compose(
        [](int const n) {return std::to_string(n); },
        [](int const n) {return n * n; },
        [](int const n) {return n + n; },
        [](int const n) {return std::abs(n); });
    cout << func(5) << endl;
    //----------- Invoke Partial Functions giving different arguments
    PartialFunctionAdd3(1, 2, 3);
    PartialFunctionAdd3(1, 2)(3);
    PartialFunctionAdd3(1)(2)(3);
}
```

# 函数包装器

函数包装器是可以包装任何函数、函数对象或 Lambdas 成可复制对象的类。包装器的类型取决于类的函数原型。来自`<functional>`头文件的`std::function(<prototype>)`表示一个函数包装器：

```cpp
//---------------- FuncWrapper.cpp Requires C++ 17 (-std=c++1z )
#include <functional>
#include <iostream>
using namespace std;
//-------------- Simple Function call
void PrintNumber(int val){ cout << val << endl; }
// ------------------ A class which overloads function operator
struct PrintNumber {
    void operator()(int i) const { std::cout << i << '\n';}
};
//------------ To demonstrate the usage of method call
struct FooClass {
    int number;
    FooClass(int pnum) : number(pnum){}
    void PrintNumber(int val) const { std::cout << number + val<< endl; }
};
int main() {
    // ----------------- Ordinary Function Wrapped
    std::function<void(int)> 
    displaynum = PrintNumber;
    displaynum(0xF000);
    std::invoke(displaynum,0xFF00); //call through std::invoke
    //-------------- Lambda Functions Wrapped
    std::function<void()> lambdaprint = []() { PrintNumber(786); };
        lambdaprint();
        std::invoke(lambdaprint);
        // Wrapping member functions of a class
        std::function<void(const FooClass&, int)>
        class display = &FooClass::PrintNumber;
        // creating an instance
        const FooClass fooinstance(100);
        class display (fooinstance,100);
}
```

在接下来的章节中，我们将广泛使用`std::function`，因为它有助于将函数调用作为数据进行处理。

# 使用管道运算符将函数组合在一起

Unix 操作系统的命令行 shell 允许将一个函数的标准输出管道到另一个函数，形成一个过滤器链。后来，这个特性成为大多数操作系统提供的每个命令行 shell 的一部分。在编写函数式风格的代码时，当我们通过函数组合来组合方法时，由于深层嵌套，代码变得难以阅读。现在，使用现代 C++，我们可以重载管道（`|`）运算符，以允许将多个函数链接在一起，就像我们在 Unix shell 或 Windows PowerShell 控制台中执行命令一样。这就是为什么有人重新将 LISP 语言称为许多令人恼火和愚蠢的括号。RxCpp 库广泛使用`|`运算符来组合函数。以下代码帮助我们了解如何创建可管道化的函数。我们将看一下这个原则上如何实现。这里给出的代码仅用于解释目的：

```cpp
//---- PipeFunc2.cpp
//-------- g++ -std=c++1z PipeFunc2.cpp
#include <iostream>
using namespace std;

struct AddOne {
    template<class T>
    auto operator()(T x) const { return x + 1; }
};
struct SumFunction {
    template<class T>
    auto operator()(T x,T y) const { return x + y;} // Binary Operator
};
```

前面的代码创建了一组 Callable 类，并将其用作函数组合链的一部分。现在，我们需要创建一种机制，将任意函数转换为闭包：

```cpp
//-------------- Create a Pipable Closure Function (Unary)
//-------------- Uses Variadic Templates Paramter pack
template<class F>
struct PipableClosure : F{
    template<class... Xs>
    PipableClosure(Xs&&... xs) : // Xs is a universal reference
    F(std::forward<Xs>(xs)...) // perfect forwarding
    {}
};
//---------- A helper function which converts a Function to a Closure
template<class F>
auto MakePipeClosure(F f)
{ return PipableClosure<F>(std::move(f)); }
// ------------ Declare a Closure for Binary
//------------- Functions
//
template<class F>
struct PipableClosureBinary {
    template<class... Ts>
    auto operator()(Ts... xs) const {
        return MakePipeClosure(= -> decltype(auto)
        { return F()(x, xs...);}); }
};
//------- Declare a pipe operator
//------- uses perfect forwarding to invoke the function
template<class T, class F> //---- Declare a pipe operator
decltype(auto) operator|(T&& x, const PipableClosure<F>& pfn)
{ return pfn(std::forward<T>(x)); }

int main() {
    //-------- Declare a Unary Function Closure
    const PipableClosure<AddOne> fnclosure = {};
    int value = 1 | fnclosure| fnclosure;
    std::cout << value << std::endl;
    //--------- Decalre a Binary function closure
    const PipableClosureBinary<SumFunction> sumfunction = {};
    int value1 = 1 | sumfunction(2) | sumfunction(5) | fnclosure;
    std::cout << value1 << std::endl;
}
```

现在，我们可以创建一个带有一元函数作为参数的`PipableClosure`实例，并将一系列调用链接（或组合）到闭包中。前面的代码片段应该在控制台上打印出三。我们还创建了一个`PipableBinaryClosure`实例，以串联一元和二元函数。

# 杂项功能

到目前为止，我们已经介绍了从 C++ 11 标准开始的语言中最重要的语义变化。本章的目的是突出一些可能有助于编写现代 C++程序的关键变化。C++ 17 标准在语言中添加了一些新内容。我们将突出语言的一些其他特性来结束这个讨论。

# 折叠表达式

C++ 17 标准增加了对折叠表达式的支持，以简化可变函数的生成。编译器进行模式匹配，并通过推断程序员的意图生成代码。以下代码片段演示了这个想法：

```cpp
//---------------- Folds.cpp
//--------------- Requires C++ 17 (-std=c++1z )
//--------------- http://en.cppreference.com/w/cpp/language/fold
#include <functional>
#include <iostream>

using namespace std;
template <typename... Ts>
auto AddFoldLeftUn(Ts... args) { return (... + args); }
template <typename... Ts>
auto AddFoldLeftBin(int n,Ts... args){ return (n + ... + args);}
template <typename... Ts>
auto AddFoldRightUn(Ts... args) { return (args + ...); }
template <typename... Ts>
auto AddFoldRightBin(int n,Ts... args) { return (args + ... + n); }
template <typename T,typename... Ts>
auto AddFoldRightBinPoly(T n,Ts... args) { return (args + ... + n); }
template <typename T,typename... Ts>
auto AddFoldLeftBinPoly(T n,Ts... args) { return (n + ... + args); }

int main() {
    auto a = AddFoldLeftUn(1,2,3,4);
    cout << a << endl;
    cout << AddFoldRightBin(a,4,5,6) << endl;
    //---------- Folds from Right
    //---------- should produce "Hello  World C++"
    auto b = AddFoldRightBinPoly("C++ "s,"Hello "s,"World "s );
    cout << b << endl;
    //---------- Folds (Reduce) from Left
    //---------- should produce "Hello World C++"
    auto c = AddFoldLeftBinPoly("Hello "s,"World "s,"C++ "s );
    cout << c << endl;
}
```

控制台上的预期输出如下

```cpp
10
 25
 Hello World C++
 Hello World C++
```

# 变体类型

变体的极客定义将是“类型安全的联合”。在定义变体时，我们可以将一系列类型作为模板参数。在任何给定时间，对象将仅保存模板参数列表中的一种数据类型。如果我们尝试访问不包含当前值的索引，将抛出`std::bad_variant_access`异常。以下代码不处理此异常：

```cpp
//------------ Variant.cpp
//------------- g++ -std=c++1z Variant.cpp
#include <variant>
#include <string>
#include <cassert>
#include <iostream>
using namespace std;

int main(){
    std::variant<int, float,string> v, w;
    v = 12.0f; // v contains now contains float
    cout << std::get<1>(v) << endl;
    w = 20; // assign to int
    cout << std::get<0>(w) << endl;
    w = "hello"s; //assign to string
    cout << std::get<2>(w) << endl;
}
```

# 其他重要主题

现代 C++支持诸如语言级并发、内存保证和异步执行等功能，这些功能将在接下来的两章中介绍。该语言支持可选数据类型和`std::any`类型。其中最重要的功能之一是大多数 STL 算法的并行版本。

# 基于范围的 for 循环和可观察对象

在本节中，我们将实现自己编写的自定义类型上的基于范围的 for 循环，以帮助您了解如何将本章中提到的所有内容组合起来编写支持现代习语的程序。我们将实现一个返回在范围内的一系列数字的类，并将实现基于范围的 for 循环的值的迭代的基础设施支持。首先，我们将利用基于范围的 for 循环编写“Iterable/Iterator”（又名“Enumerable/Enumerable”）版本。经过一些调整，实现将转变为 Observable/Observer（响应式编程的关键接口）模式：此处 Observable/Observer 模式的实现仅用于阐明目的，不应被视为这些模式的工业级实现。

以下的`iterable`类是一个嵌套类：

```cpp
// Iterobservable.cpp
// we can use Range Based For loop as given below (see the main below)
// for (auto l : EnumerableRange<5, 25>()) { std::cout << l << ' '; }
// std::cout << endl;
#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>
#include <functional>
using namespace std;

template<long START, long END>
class EnumerableRange {
public:

    class iterable : public std::iterator<
        std::input_iterator_tag, // category
        long, // value_type
        long, // difference_type
        const long*, // pointer type
        long> // reference type
        {
            long current_num = START;
            public:
                reference operator*() const { return current_num; }
                explicit iterable(long val = 0) : current_num(val) {}
                iterable& operator++() {
                    current_num = ( END >= START) ? current_num + 1 :
                        current_num - 1;
                return *this;
            }
            iterable operator++(int) {
                iterable retval = *this; ++(*this); return retval;
            }
            bool operator==(iterable other) const
                { return current_num == other.current_num; }
            bool operator!=(iterable other) const
                { return !(*this == other); }
    };
```

前面的代码实现了一个内部类，该类派生自`std::iterator`，以满足类型通过基于范围的 for 循环进行枚举的要求。现在我们将编写两个公共方法（`begin()`和`end()`），以便类的使用者可以使用基于范围的 for 循环：

```cpp
iterable begin() { return iterable(START); }
    iterable end() { return iterable(END >= START ? END + 1 :
        END - 1); }
};
```

现在，我们可以编写代码来使用前面的类：

```cpp
for (long l : EnumerableRange<5, 25>())
    { std::cout << l << ' '; }
```

在上一章中，我们定义了`IEnumerable<T>`接口。这个想法是遵循 Reactive eXtensions 的文档。可迭代类与上一章中的`IEnumerable<T>`实现非常相似。正如在上一章中概述的那样，如果我们稍微调整代码，前面的类可以变为推送型。让我们编写一个包含三个方法的`OBSERVER`类。我们将使用标准库提供的函数包装器来定义这些方法：

```cpp
struct OBSERVER {
    std::function<void(const long&)> ondata;
    std::function<void()> oncompleted;
    std::function<void(const std::exception &)> onexception;
};
```

这里给出的`ObservableRange`类包含一个存储订阅者列表的`vector<T>`。当生成新数字时，事件将通知所有订阅者。如果我们从异步方法中分派通知调用，消费者将与范围流的生产者解耦。我们还没有为以下类实现`IObserver/IObserver<T>`接口，但我们可以通过订阅方法订阅通知：

```cpp
template<long START, long END>
class ObservableRange {
    private:
        //---------- Container to store observers
        std::vector<
            std::pair<const OBSERVER&,int>> _observers;
        int _id = 0;
```

我们将以`std::pair`的形式将订阅者列表存储在`std::vector`中。`std::pair`中的第一个值是对`OBSERVER`的引用，`std::pair`中的第二个值是唯一标识订阅者的整数。消费者应该使用订阅方法返回的 ID 来取消订阅：

```cpp
//---- The following implementation of iterable does
//---- not allow to take address of the pointed value  &(*it)
//---- Eg- &(*iterable.begin()) will be ill-formed
//---- Code is just for demonstrate Obervable/Observer
class iterable : public std::iterator<
    std::input_iterator_tag, // category
    long, // value_type
    long, // difference_type
    const long*, // pointer type
    long> // reference type
    {
        long current_num = START;
    public:
        reference operator*() const { return current_num; }
        explicit iterable(long val = 0) : current_num(val) {}
        iterable& operator++() {
            current_num = ( END >= START) ? current_num + 1 :
                current_num - 1;
            return *this;
        }
        iterable operator++(int) {
            iterable retval = *this; ++(*this); return retval;
        }
        bool operator==(iterable other) const
            { return current_num == other.current_num; }
        bool operator!=(iterable other) const
            { return !(*this == other); }
        };
    iterable begin() { return iterable(START); }
    iterable end() { return iterable(END >= START ? END + 1 : END - 1); }
// generate values between the range
// This is a private method and will be invoked from the generate
// ideally speaking, we should invoke this method with std::asnyc
void generate_async()
{
    auto& subscribers = _observers;
    for( auto l : *this )
        for (const auto& obs : subscribers) {
            const OBSERVER& ob = obs.first;
            ob.ondata(l);
    }
}

//----- The public interface of the call include generate which triggers
//----- the generation of the sequence, subscribe/unsubscribe pair
public:
    //-------- the public interface to trigger generation
    //-------- of thevalues. The generate_async can be executed
    //--------- via std::async to return to the caller
    void generate() { generate_async(); }
    //---------- subscribe method. The clients which
    //----------- expects notification can register here
    int subscribe(const OBSERVER& call) {
        // https://en.cppreference.com/w/cpp/container/vector/emplace_back
        _observers.emplace_back(call, ++_id);
        return _id;
    }
    //------------ has just stubbed unsubscribe to keep
    //------------- the listing small
    void unsubscribe(const int subscription) {}

};

int main() {
    //------ Call the Range based enumerable
    for (long l : EnumerableRange<5, 25>())
        { std::cout << l << ' '; }
    std::cout << endl;
    // instantiate an instance of ObservableRange
    auto j = ObservableRange<10,20>();
    OBSERVER test_handler;
    test_handler.ondata = [=
    {cout << r << endl; };
    //---- subscribe to the notifiactions
    int cnt = j.subscribe(test_handler);
    j.generate(); //trigget events to generate notifications
    return 0;
}
```

# 摘要

在本章中，我们了解了 C++程序员在编写响应式程序或其他类型的程序时应该熟悉的编程语言特性。我们谈到了类型推断、可变模板、右值引用和移动语义、Lambda 函数、基本的函数式编程、可管道化的操作符以及迭代器和观察者的实现。在下一章中，我们将学习 C++编程语言提供的并发编程支持。


# 第三章：C++中的语言级并发和并行

自 C++ 11 语言标准发布以来，C++一直对并发编程提供了出色的支持。在那之前，线程是由特定于平台的库处理的事务。微软公司有自己的线程库，其他平台（GNU Linux/macOS X）支持 POSIX 线程模型。作为语言的一部分的线程机制帮助 C++程序员编写可在多个平台上运行的可移植代码。

最初的 C++标准于 1998 年发布，语言设计委员会坚信线程、文件系统、GUI 库等最好留给特定平台的库。Herb Sutter 在《Dr. Dobbs Journal》上发表了一篇有影响力的文章，题为《免费午餐结束了》，他在文章中提倡利用多核处理器中的多个核心的编程技术。在编写并行代码时，函数式编程模型非常适合这项任务。线程、Lambda 函数和表达式、移动语义和内存保证等特性帮助人们轻松地编写并发或并行代码。本章旨在使开发人员能够利用线程库及其最佳实践。

在本章中，我们将涵盖以下主题：

+   什么是并发？

+   使用多个线程的特征 Hello World 程序

+   如何管理线程的生命周期和资源

+   在线程之间共享数据

+   如何编写线程安全的数据结构

# 什么是并发？

在基本层面上，并发代表着多个活动同时发生。我们可以将并发与我们的许多现实生活情况联系起来，比如我们一边吃爆米花一边看电影，或者同时用两只手进行不同的功能，等等。那么，在计算机中，并发是什么呢？

几十年前，计算机系统已经能够进行任务切换，多任务操作系统也存在了很长时间。为什么计算领域突然对并发产生了新的兴趣？微处理器制造商通过将更多的硅片塞入处理器来增加计算能力。在这个过程的某个阶段，由于达到了基本的物理极限，他们无法再将更多的东西塞入相同的区域。那个时代的 CPU 一次只能执行一条执行路径，并通过切换任务（指令流）来运行多条指令路径。在 CPU 级别上，只有一个指令流在执行，由于事情发生得非常快（与人类感知相比），用户感觉动作是同时发生的。

大约在 2005 年，英特尔宣布了他们的新多核处理器（支持硬件级别的多条执行路径），这是一个改变游戏规则的事件。多核处理器不再是通过在任务之间切换来执行每个任务的处理器，而是作为一个解决方案来实际并行执行它们。但这给程序员带来了另一个挑战，即编写他们的代码以利用硬件级别的并发性。此外，实际硬件并发行为与任务切换所创建的幻觉之间存在差异的问题也出现了。直到多核处理器出现之前，芯片制造商一直在竞相增加他们的计算能力，期望在 21 世纪初达到 10 GHz。正如 Herb Sutter 在《免费午餐结束了》中所说的：“如果软件要利用这种增加的计算能力，它必须设计成能够同时运行多个任务”。Herb 警告程序员，那些忽视并发性的人在编写程序时也必须考虑这一点。

现代 C++标准库提供了一套机制来支持并发和并行。首先，`std::thread`以及同步对象（如`std::mutex`、`std::lock_guards`、`std::unique_lock`、`std::condition_variables`等）使程序员能够使用标准 C++编写并发的多线程代码。其次，为了使用基于任务的并行（如.NET 和 Java），C++引入了`std::future`和`std::promise`类，它们配对工作以分离函数调用和等待结果。

最后，为了避免管理线程的额外开销，C++引入了一个名为`std::async`的类，它将在接下来的章节中详细介绍，讨论重点将是编写无锁并发程序（至少在可能的情况下最小化锁定）。

并发是指两个或更多个线程或执行路径可以在重叠的时间段内启动、运行和完成（以某种交错的执行方式）。并行意味着两个任务可以同时运行（就像在多核 CPU 上看到的那样）。并发是关于响应时间，而并行主要是利用可用资源。

# 并发的 Hello World（使用 std::thread）

现在，让我们开始使用`std::thread`库编写我们的第一个程序。我们期望您有 C++ 11 或更高版本来编译我们将在本章讨论的程序。在深入讨论多线程的 Hello World 之前，让我们以一个简单的经典的 Hello World 示例作为参考：

```cpp
//---- Thanks to Dennis Ritchie and Brian Kernighan, this is a norm for all languages
#include <iostream> 
int main() 
{ 
   std::cout << "Hello World\n"; 
} 
```

这个程序简单地将 Hello World 写入标准输出流（主要是控制台）。现在，让我们看另一个例子，它做同样的事情，但是使用一个后台线程（通常称为工作线程）：

```cpp
#include <iostream> 
#include <thread> 
#include <string> 
//---- The following function will be invoked by the thread library 
void thread_proc(std::string msg) 
{ 
   std::cout << "ThreadProc msg:" << msg; 
}  
int main() 
{ 
   // creates a new thread and execute thread_proc on it. 
   std::thread t(thread_proc, "Hello World\n");  
   // Waiting for the thread_proc to complete its execution 
   // before exiting from the program 
   t.join(); 
} 
```

与传统代码的第一个区别是包含了`<thread>`标准头文件。所有的多线程支持函数和类都声明在这个新头文件中。但是为了实现同步和共享数据保护，支持类是在其他头文件中可用的。如果您熟悉 Windows 或 POSIX 系统中的平台级线程，所有线程都需要一个初始函数。标准库也遵循相同的概念。在这个例子中，`thread_proc`函数是在主函数中声明的线程的初始函数。初始函数（通过函数指针）在`std::thread`对象`t`的构造函数中指定，并且构造开始执行线程。

最显著的区别是现在应用程序从一个新线程（后台线程）向标准输出流写入消息，这导致在此应用程序中有两个线程或执行路径。一旦新线程启动，主线程就会继续执行。如果主线程不等待新启动的线程完成，`main()`函数将结束，这样应用程序就会结束——甚至在新线程有机会完成执行之前。这就是在主线程完成之前调用`join()`的原因，以等待新线程`t`的结束。

# 管理线程

在运行时，执行从用户入口点`main()`开始（在启动代码执行之后），并且将在已创建的默认线程中执行。因此，每个程序都至少有一个执行线程。在程序执行期间，可以通过标准库或特定于平台的库创建任意数量的线程。如果 CPU 核心可用于执行它们，这些线程可以并行运行。如果线程数多于 CPU 核心数，即使存在并行性，我们也无法同时运行所有线程。因此，线程切换也在这里发生。程序可以从主线程启动任意数量的线程，并且这些线程在初始线程上同时运行。正如我们所看到的，程序线程的初始函数是`main()`，并且当主线程从其执行返回时程序结束。这将终止所有并行线程。因此，主线程需要等待直到所有子线程完成执行。因此，让我们看看线程的启动和加入是如何发生的。

# 线程启动

在前面的示例中，我们看到初始化函数作为参数传递给`std::thread`构造函数，并且线程被启动。此函数在自己的线程上运行。线程启动发生在线程对象的构造期间，但初始化函数也可以有其他替代方案。函数对象是线程类的另一个可能参数。C++标准库确保`std::thread`与任何可调用类型一起工作。

现代 C++标准支持通过以下方式初始化线程：

+   函数指针（如前一节中）

+   实现调用运算符的对象

+   Lambda

任何可调用实体都可以用于初始化线程。这使得`std::thread`能够接受具有重载函数调用运算符的类对象：

```cpp
class parallel_job 
{ 
public: 
void operator() () 
{ 
    some_implementation(); 
} 
};  
parallel_job job; 
std::thread t(job); 
```

在这里，新创建的线程将对象复制到其存储中，因此必须确保复制行为。在这里，我们还可以使用`std::move`来避免与复制相关的问题：

```cpp
std::thread t(std::move(job)); 
```

如果传递临时对象（rvalue）而不是函数对象，则语法如下：

```cpp
std::thread t(parallel_job()); 
```

编译器可以将此代码解释为接受函数指针并返回`std::thread`对象的函数声明。但是，我们可以通过使用新的统一初始化语法来避免这种情况，如下所示：

```cpp
std::thread t{ parallel_job() };
```

在以下代码片段中给出的额外一组括号也可以避免将`std::thread`对象声明解释为函数声明：

```cpp
std::thread t((parallel_job()));
```

启动线程的另一个有趣的方法是通过将 C++ Lambda 作为参数传递给`std::thread`构造函数。Lambda 可以捕获局部变量，从而避免不必要地使用任何参数。当涉及编写匿名函数时，Lambda 非常有用，但这并不意味着它们应该随处使用。

Lambda 函数可以与线程声明一起使用，如下所示：

```cpp
std::thread t([]{ 
    some_implementation(); 
}); 
```

# 线程加入

在 Hello World 示例中，您可能已经注意到在`main()`结束之前使用了`t.join()`。在函数离开之前，对关联线程实例的`join()`调用确保启动的函数将等待直到后台线程完成执行。如果没有 join，线程将在线程开始之前终止，直到当前上下文完成（它们的子线程也将被终止）。

`join()`是一个直接的函数，可以等待线程完成，也可以不等待。为了更好地控制线程，我们还有其他机制，比如互斥锁、条件变量和期物，它们将在本章和下一章的后面部分进行讨论。调用`join()`会清理与线程相关联的存储，因此确保对象不再与启动的线程相关联。这意味着`join()`函数只能每个线程调用一次；在调用`join()`后，调用`joinable()`将始终返回 false。前面的使用函数对象的示例可以修改如下以理解`join()`：

```cpp
class parallel_job 
{ 
   int& _iterations; 

public: 
    parallel_job(int& input): _iterations(input) 
    {} 

    void operator() () 
    { 
        for (int i = 0; i < _iterations; ++i) 
        { 
            some_implementation(i); 
        } 
    } 
}; 
void func() 
{ 
    int local_Val = 10000; 
    parallel_job job(local_Val); 
    std::thread t(job); 

    if(t.joinable()) 
        t.join(); 
} 
```

在这种情况下，在`func()`函数结束时，验证线程对象以确认线程是否仍在执行。在放置 join 调用之前，我们调用`joinable()`来查看其返回值。

为了防止在`func()`上等待，标准引入了一种机制，即使父函数完成执行，也可以继续执行。这可以通过另一个标准函数`detach()`来实现：

```cpp
if(t.joinable()) 
         t.detach(); 
```

在分离线程之前，我们需要考虑几件事情；当`func()`退出时，线程`t`可能仍在运行。根据前面示例中给出的实现，线程使用了在`func()`中创建的局部变量的引用，这不是一个好主意，因为在大多数架构上，旧的堆栈变量随时可能被覆盖。在编写代码时，必须始终解决这些情况。处理这种情况的最常见方法是使线程自包含，并将数据复制到线程中，而不是共享它。

# 将参数传递给线程

因此，我们已经找出了如何启动和等待线程。现在，让我们看看如何将参数传递给线程初始化函数。让我们看一个计算阶乘的示例：

```cpp
class Factorial 
{ 
private: 
    long long myFact; 

public: 
    Factorial() : myFact(1) 
    { 
    } 

    void operator() (int number) 
    { 
        myFact = 1; 
        for (int i = 1; i <= number; ++i) 
        { 
            myFact *= i; 
        } 
        std::cout << "Factorial of " << number << " is " << myFact; 
    } 
}; 

int main() 
{ 
    Factorial fact; 

    std::thread t1(fact, 10); 

    t1.join(); 
} 

```

从这个例子中，可以清楚地看出，通过向`std::thread()`声明中传递额外的参数，可以实现将参数传递给线程函数或线程可调用对象。我们必须记住一件事；*传递的参数被复制到线程的内部存储以供进一步执行*。对于线程的执行来说，拥有自己的参数副本是很重要的，因为我们已经看到了与局部变量作用域结束相关的问题。要进一步讨论将参数传递给线程，让我们回到本章的第一个 Hello World 示例：

```cpp
void thread_proc(std::string msg); 

std::thread t(thread_proc, "Hello World\n"); 
```

在这种情况下，`thread_proc()`函数以`std::string`作为参数，但我们将`const char*`作为参数传递给线程函数。只有在线程的情况下，参数才会被传递、转换并复制到线程的内部存储中。在这里，`const char*`将被转换为`std::string`。必须在选择线程提供的参数类型时考虑到这一点。让我们看看如果将指针作为参数提供给线程会发生什么：

```cpp
void thread_proc(std::string msg); 
void func() 
{ 
   char buf[512]; 
   const char* hello = "Hello World\n"; 
   std::strcpy(buf, hello); 

   std::thread t(thread_proc, buf); 
   t.detach(); 
} 
```

在前面的代码中，提供给线程的参数是指向局部变量`buf`的指针。`func()`函数在线程上发生`buf`转换为`std::string`之前可能会退出。这可能导致未定义的行为。可以通过在声明中将`buf`变量转换为`std::string`来解决这个问题，如下所示：

```cpp
std::thread t(thread_proc, std::string(buf)); 
```

现在，让我们看看当您希望在线程中更新引用时的情况。在典型情况下，线程会复制传递给线程的值，以确保安全执行，但标准库还提供了一种通过引用传递参数给线程的方法。在许多实际系统中，您可能已经看到在线程内部更新共享数据结构。以下示例展示了如何在线程中实现按引用传递：

```cpp
void update_data(shared_data& data);

void another_func() 
{ 
   shared_data data; 
   std::thread t(update_data, std::ref(data)); 
   t.join(); 
   do_something_else(data); 
} 
```

在前面的代码中，使用`std::ref`将传递给`std::thread`构造函数的参数包装起来，确保线程内部使用的变量是实际参数的引用。您可能已经注意到，线程初始化函数的函数原型接受了对`shared_data`对象的引用，但为什么在线程调用中仍然需要`std::ref()`包装呢？考虑以下线程调用的代码：

```cpp
std::thread t(update_data, data);
```

在这种情况下，`update_data()`函数期望`shared_data`参数被视为实际参数的引用。但当用作线程初始化函数时，参数会在内部被简单地复制。当调用`update_data()`时，它将传递给参数的内部副本的引用，而不是实际参数的引用。

# 使用 Lambda

现在，让我们看一下 Lambda 表达式在多线程中的用处。在以下代码中，我们将创建五个线程，并将它们放入一个向量容器中。每个线程将使用 Lambda 函数作为初始化函数。在以下代码中初始化的线程通过值捕获循环索引：

```cpp
int main() 
{ 
    std::vector<std::thread> threads; 

    for (int i = 0; i < 5; ++i) 
    { 
        threads.push_back(std::thread( [i]() { 
            std::cout << "Thread #" << i << std::endl; 
        })); 
    } 

    std::cout << "nMain function"; 

    std::for_each(threads.begin(), threads.end(), [](std::thread &t) { 
        t.join(); 
    }); 
} 
```

向量容器线程存储了在循环内创建的五个线程。一旦执行结束，它们将在`main()`函数的末尾被连接。前面代码的输出可能如下所示：

```cpp
Thread # Thread # Thread # Thread # Thread #
Main function
0
4
1
3
2
```

程序的输出可能在每次运行时都不同。这个程序是一个很好的例子，展示了并发编程中的不确定性。在接下来的部分中，我们将讨论`std::thread`对象的移动属性。

# 所有权管理

从本章迄今讨论的示例中，您可能已经注意到启动线程的函数必须使用`join()`函数等待线程完成执行，否则它将以程序失去对线程的控制为代价调用`detach()`。在现代 C++中，许多标准类型是可移动的，但不能被复制；`std::thread`就是其中之一。这意味着线程执行的所有权可以在`std::thread`实例之间通过移动语义移动。

有许多情况下，我们希望将所有权移交给另一个线程，例如，如果我们希望线程在创建线程的函数上后台运行而不等待它。这可以通过将线程所有权传递给调用函数来实现，而不是在创建的函数中等待它完成。在另一种情况下，将所有权传递给另一个函数，该函数将等待线程完成其执行。这两种情况都可以通过将一个线程实例的所有权传递给另一个线程实例来实现。

为了进一步解释，让我们定义两个函数来用作线程函数：

```cpp
void function1() 
{ 
    std::cout << "function1()n"; 
} 

void function2() 
{ 
    std::cout << "function2()n"; 
} 
```

让我们来看一下从先前声明的函数中生成线程的主要函数：

```cpp
int main() 
{ 
    std::thread t1(function1); 

    // Ownership of t1 is transferred to t2 
    std::thread t2 = std::move(t1);
```

在前面的代码中，`main()`的第一行启动了一个新的线程`t1`。然后，使用`std::move()`函数将所有权转移到`t2`，该函数调用了与`t2`关联的`std::thread`的移动构造函数。现在，t1 实例没有关联的线程执行。初始化函数`function1()`现在与`t2`关联：

```cpp
    t1 = std::thread(function2); 
```

然后，使用 rvalue 启动了一个新的线程，这将调用与`t1`关联的`std::thread`的移动赋值运算符。由于我们使用了 rvalue，因此不需要显式调用`std::move()`：

```cpp
    // thread instance Created without any associated thread execution 
    std::thread t3; 

    // Ownership of t2 is transferred to t3 
    t3 = std::move(t2); 
```

`t3`是在没有任何线程执行的情况下实例化的，这意味着它正在调用默认构造函数。然后，通过显式调用`std::move()`函数，通过移动赋值运算符将当前与`t2`关联的所有权转移到`t3`：

```cpp
    // No need to join t1, no longer has any associated thread of execution 
    if (t1.joinable())  t1.join(); 
    if (t3.joinable())  t3.join(); 

    return 0; 
} 
```

最后，与关联执行线程的`std::thread`实例在程序退出之前被连接。在这里，`t1`和`t3`是与关联执行线程的实例。

现在，让我们假设在前面示例中的线程`join()`之前存在以下代码：

```cpp
t1 = std::move(t3); 
```

在这里，实例`t1`已经与正在运行的函数(`function2`)相关联。当`std::move()`试图将`function1`的所有权转移回`t1`时，将调用`std::terminate()`来终止程序。这保证了`std::thread`析构函数的一致性。

`std::thread`中的移动支持有助于将线程的所有权从函数中转移出来。以下示例演示了这样的情况：

```cpp
void func() 
{ 
    std::cout << "func()n"; 
} 

std::thread thread_creator() 
{ 
    return std::thread(func); 
} 

void thread_wait_func() 
{ 
    std::thread t = thread_creator(); 

    t.join(); 
} 
```

在这里，`thread_creator()`函数返回与`func()`函数相关联的`std::thread`。`thread_wait_func()`函数调用`thread_creator()`，然后返回线程对象，这是一个 rvalue，分配给了一个`std::thread`对象。这将线程的所有权转移到`std::thread`对象`t`中，对象`t`正在等待转移函数中线程执行的完成。

# 在线程之间共享数据

我们已经看到了如何启动线程和管理它们的不同方法。现在，让我们讨论如何在线程之间共享数据。并发的一个关键特性是它能够在活动的线程之间共享数据。首先，让我们看看线程访问共同（共享）数据所带来的问题。

如果在线程之间共享的数据是不可变的（只读），那么就不会有问题，因为一个线程读取的数据不受其他线程是否读取相同数据的影响。当线程开始修改共享数据时，问题就开始出现了。

例如，如果线程正在访问一个共同的数据结构，如果正在进行更新，与数据结构相关的不变量将被破坏。在这种情况下，数据结构中存储了元素的数量，通常需要修改多个值。考虑自平衡树或双向链表的删除操作。如果不采取任何特殊措施来确保否则，如果一个线程正在读取数据结构，而另一个正在删除一个节点，很可能会导致读取线程看到具有部分删除节点的数据结构，因此不变量被破坏。这可能最终会永久损坏数据结构，并可能导致程序崩溃。

不变量是一组在程序执行或对象生命周期中始终为真的断言。在代码中放置适当的断言来查看不变量是否被违反将产生健壮的代码。这是一种很好的记录软件的方式，也是防止回归错误的良好机制。关于这一点可以在以下维基百科文章中阅读更多：[`en.wikipedia.org/wiki/Invariant_(computer_science)`](https://en.wikipedia.org/wiki/Invariant_(computer_science))。

这经常导致一种称为*竞争条件*的情况，这是并发程序中最常见的错误原因。在多线程中，竞争条件意味着线程竞争执行各自的操作。在这里，结果取决于两个或更多线程中操作的执行相对顺序。通常，竞争条件一词指的是问题性的竞争条件；正常的竞争条件不会导致任何错误。问题性的竞争条件通常发生在完成操作需要修改两个或更多位数据的情况下，例如在树数据结构或双向链表中删除节点。因为修改必须访问不同的数据片段，当另一个线程尝试访问数据结构时，这些数据必须在单独的指令中进行修改。这发生在先前修改的一半已经完成时。

竞争条件通常很难找到，也很难复制，因为它们发生在非常短的执行窗口内。对于使用并发的软件，实现的主要复杂性来自于避免问题性的竞争条件。

有许多方法可以处理问题性的竞争条件。常见且最简单的选择是使用*同步原语*，这是基于锁的保护机制。它通过使用一些锁定机制来包装数据结构，以防止其他线程在其执行期间访问。我们将在本章中详细讨论可用的同步原语及其用途。

另一个选择是修改数据结构及其不变量的设计，以确保修改可以保证代码的顺序一致性，即使跨多个线程。这是一种编写程序的困难方式，通常被称为*无锁编程*。无锁编程和 C++内存模型将在第四章中进行介绍，《C++中的异步和无锁编程》。

然后，还有其他机制，比如将对数据结构的更新视为事务，就像对数据库的更新是在事务中完成的一样。目前，这个主题不在本书的范围内，因此不会涉及。

现在，让我们考虑 C++标准中用于保护共享数据的最基本机制，即*互斥锁*。

# 互斥锁

互斥锁是用于并发控制的机制，用于防止竞争条件。互斥锁的功能是防止执行线程在另一个并发线程进入其自己的临界区时进入其*临界区*。它是一个可锁定的对象，设计用于在代码的临界区需要独占访问时发出信号，从而限制其他并发线程在执行和内存访问方面具有相同的保护。C++ 11 标准引入了`std::mutex`类到标准库中，以实现跨并发线程的数据保护。

`std::mutex`类包括`lock()`和`unlock()`函数，用于在代码中创建临界区。在使用成员函数创建临界区时要记住的一件事是，永远不要跳过与锁定函数相关联的解锁函数，以标记代码中的临界区。

现在，让我们讨论与线程一起使用 Lambda 时所使用的相同代码。在那里，我们观察到程序的输出由于与共享资源`std::cout`和`std::ostream`操作符的竞争条件而混乱。现在，该代码正在使用`std::mutex`进行重写，以打印线程索引：

```cpp
#include <iostream> 
#include <thread> 
#include <mutex> 
#include <vector>  
std::mutex m; 
int main() 
{ 
    std::vector<std::thread> threads; 

    for (int i = 1; i < 10; ++i) 
    { 
        threads.push_back(std::thread( [i]() { 
            m.lock(); 
            std::cout << "Thread #" << i << std::endl; 
            m.unlock();
        })); 
    }      
    std::for_each(threads.begin(), threads.end(), [](std::thread &t) { 
        t.join(); 
    }); 
} 
```

前面代码的输出可能如下所示：

```cpp
Thread #1 
Thread #2 
Thread #3 
Thread #4 
Thread #5 
Thread #6 
Thread #7 
Thread #8 
Thread #9 
```

在前面的代码中，互斥锁用于保护共享资源，即`std::cout`和级联的`std::ostream`操作符。与旧示例不同，现在代码中添加了互斥锁，避免了混乱的输出，但输出将以随机顺序出现。在`std::mutex`类中使用`lock()`和`unlock()`函数可以保证输出不会混乱。然而，直接调用成员函数的做法并不推荐，因为你需要在函数的每个代码路径上调用解锁，包括异常情况。相反，C++标准引入了一个新的模板类`std::lock_guard`，它为互斥锁实现了**资源获取即初始化**（**RAII**）习惯用法。它在构造函数中锁定提供的互斥锁，并在析构函数中解锁。这个模板类的实现在`<mutex>`标准头文件库中可用。前面的示例可以使用`std::lock_guard`进行重写，如下所示：

```cpp
std::mutex m; 
int main() 
{ 
    std::vector<std::thread> threads;  
    for (int i = 1; i < 10; ++i) 
    { 
        threads.push_back(std::thread( [i]() { 
            std::lock_guard<std::mutex> local_lock(m); 
            std::cout << "Thread #" << i << std::endl; 
        })); 
    }      
    std::for_each(threads.begin(), threads.end(), [](std::thread &t) { 
        t.join(); 
    }); 
}
```

在前面的代码中，保护临界区的互斥锁位于全局范围，而`std::lock_guard`对象在每次线程执行时都是局部的 Lambda。这样，一旦对象被构造，互斥锁就会获得锁。当 Lambda 执行结束时，调用析构函数解锁互斥锁。

RAII 是 C++的一种习惯用法，其中诸如数据库/文件句柄、套接字句柄、互斥锁、堆上动态分配的内存等实体的生命周期都与持有它的对象的生命周期绑定。你可以在以下维基百科页面上阅读更多关于 RAII 的内容：[`en.wikipedia.org/wiki/Resource_acquisition_is_initialization`](https://en.wikipedia.org/wiki/Resource_acquisition_is_initialization)。

# 避免死锁

在处理互斥锁时，可能出现的最大问题就是死锁。要理解死锁是什么，想象一下 iPod。为了实现 iPod 的目的，它需要 iPod 和耳机。如果两个兄弟共享一个 iPod，有时候两个人都想同时听音乐。想象一个人拿到了 iPod，另一个拿到了耳机，他们都不愿意分享自己拥有的物品。现在他们陷入僵局，除非其中一个人试图友好一点，让另一个人听音乐。

在这里，兄弟们在争夺 iPod 和耳机，但回到我们的情况，线程在争夺互斥锁上的锁。在这里，每个线程都有一个互斥锁，并且正在等待另一个线程。没有互斥锁可以继续进行，因为每个线程都在等待另一个线程释放其互斥锁。这种情况被称为**死锁**。

避免死锁有时候相当简单，因为不同的互斥锁用于不同的目的，但也有一些情况处理起来并不那么明显。我能给你的最好建议是，为了避免死锁，始终以相同的顺序锁定多个互斥锁。这样，你就永远不会遇到死锁情况。

考虑一个具有两个线程的程序的例子；每个线程都打算单独打印奇数和偶数。由于两个线程的意图不同，程序使用两个互斥锁来控制每个线程。两个线程之间的共享资源是`std::cout`。让我们看一个具有死锁情况的以下程序：

```cpp
// Global mutexes 
std::mutex evenMutex; 
std::mutex oddMutex;  
// Function to print even numbers 
void printEven(int max) 
{ 
    for (int i = 0; i <= max; i +=2) 
    { 
        oddMutex.lock(); 
        std::cout << i << ","; 
        evenMutex.lock(); 
        oddMutex.unlock(); 
        evenMutex.unlock(); 
    } 
} 
```

`printEven()`函数被定义为将所有小于`max`值的正偶数打印到标准控制台中。同样，让我们定义一个`printOdd()`函数，以打印小于`max`的所有正奇数，如下所示：

```cpp
// Function to print odd numbers 
void printOdd(int max) 
{ 
    for (int i = 1; i <= max; i +=2) 
    { 
        evenMutex.lock(); 
        std::cout << i << ","; 
        oddMutex.lock(); 
        evenMutex.unlock(); 
        oddMutex.unlock(); 

    } 
} 
```

现在，让我们编写`main`函数，生成两个独立的线程，使用先前定义的函数作为每个操作的线程函数来打印奇数和偶数：

```cpp
int main() 
{ 
    auto max = 100; 

    std::thread t1(printEven, max); 
    std::thread t2(printOdd, max); 

    if (t1.joinable()) 
        t1.join(); 
    if (t2.joinable()) 
        t2.join(); 
} 
```

在这个例子中，`std::cout`受到两个互斥锁`printEven`和`printOdd`的保护，它们以不同的顺序进行锁定。使用这段代码，我们总是陷入死锁，因为每个线程明显都在等待另一个线程锁定的互斥锁。运行这段代码将导致程序挂起。如前所述，可以通过以相同的顺序锁定它们来避免死锁，如下所示：

```cpp
void printEven(int max) 
{ 
    for (int i = 0; i <= max; i +=2) 
    { 
        evenMutex.lock(); 
        std::cout << i << ","; 
        oddMutex.lock(); 
        evenMutex.unlock(); 
        oddMutex.unlock(); 
    } 
}  
void printOdd(int max) 
{ 
    for (int i = 1; i <= max; i +=2) 
    { 
        evenMutex.lock(); 
        std::cout << i << ","; 
        oddMutex.lock(); 
        evenMutex.unlock(); 
        oddMutex.unlock(); 

    } 
} 
```

但是这段代码显然不够干净。你已经知道使用 RAII 习惯用法的互斥锁可以使代码更清晰、更安全，但为了确保锁定的顺序，C++标准库引入了一个新函数`std::lock`——一个可以一次锁定两个或更多互斥锁而不会出现死锁风险的函数。以下示例展示了如何在先前的奇偶程序中使用这个函数：

```cpp
void printEven(int max) 
{ 
    for (int i = 0; i <= max; i +=2) 
    { 
        std::lock(evenMutex, oddMutex); 
        std::lock_guard<std::mutex> lk_even(evenMutex, std::adopt_lock); 
        std::lock_guard<std::mutex> lk_odd(oddMutex, std::adopt_lock); 
        std::cout << i << ","; 
    } 
}  
void printOdd(int max) 
{ 
    for (int i = 1; i <= max; i +=2) 
    { 
        std::lock(evenMutex, oddMutex); 
        std::lock_guard<std::mutex> lk_even(evenMutex, std::adopt_lock); 
        std::lock_guard<std::mutex> lk_odd(oddMutex, std::adopt_lock); 

        std::cout << i << ","; 

    } 
} 
```

在这种情况下，一旦线程执行进入循环，对`std::lock`的调用会锁定两个互斥锁。为每个互斥锁构造了两个`std::lock_guard`实例。除了互斥锁实例之外，还提供了`std::adopt_lock`参数给`std::lock_guard`，以指示互斥锁已经被锁定，它们应该只是接管现有锁的所有权，而不是尝试在构造函数中锁定互斥锁。这保证了安全的解锁，即使在异常情况下也是如此。

然而，`std::lock`可以帮助您避免死锁，因为程序要求同时锁定两个或多个互斥锁时，它并不会帮助您解决问题。死锁是多线程程序中可能发生的最困难的问题之一。它最终依赖于程序员的纪律，不要陷入任何死锁情况。

# 使用 std::unique_lock 进行锁定

与`std::lock_guard`相比，`std::unique_lock`在操作上提供了更多的灵活性。`std::unique_lock`实例并不总是拥有与之关联的互斥锁。首先，您可以将`std::adopt_lock`作为第二个参数传递给构造函数，以管理与`std::lock_guard`类似的互斥锁上的锁。其次，通过将`std::defer_lock`作为第二个参数传递给构造函数，在构造期间互斥锁可以保持未锁定状态。因此，稍后在代码中，可以通过在同一`std::unique_lock`对象上调用`lock()`来获取锁。但是，`std::unique_lock`提供的灵活性是有代价的；它在存储额外信息方面比`lock_guard`慢一些，并且需要更新。因此，建议除非确实需要`std::unique_lock`提供的灵活性，否则使用`lock_guard`。

关于`std::unique_lock`的另一个有趣特性是其所有权转移的能力。由于`std::unique_lock`必须拥有其关联的互斥锁，这导致互斥锁的所有权转移。与`std::thread`类似，`std::unique_lock`类也是一种只能移动的类型。C++标准库中提供的所有移动语义语言细微差别和右值引用处理都适用于`std::unique_lock`。

与`std::mutex`类似，具有`lock()`和`unlock()`等成员函数的可用性增加了它在代码中的灵活性，相对于`std::lock_guard`。在`std::unique_lock`实例被销毁之前释放锁的能力意味着，如果明显不再需要锁，可以在代码的任何地方选择性地释放它。不必要地持有锁会严重降低应用程序的性能，因为等待锁的线程会被阻止执行比必要时间更长的时间。因此，`std::unique_lock`是 C++标准库引入的非常方便的功能，支持 RAII 习惯用法，并且可以有效地最小化适用代码的关键部分的大小：

```cpp
void retrieve_and_process_data(data_params param) 
{ 
   std::unique_lock<std::mutex> local_lock(global_mutex, std::defer_lock); 
   prepare_data(param); 

   local_lock.lock(); 
   data_class data = get_data_to_process(); 
   local_lock.unlock(); 

   result_class result = process_data(data); 

   local_lock.lock(); 
   strore_result(result); 
} 
```

在前面的代码中，您可以看到通过利用`std::unique_lock`的灵活性实现的细粒度锁定。当函数开始执行时，使用`global_mutex`构造了一个处于未锁定状态的`std::unique_lock`对象。立即准备了不需要独占访问的参数，它可以自由执行。在检索准备好的数据之前，`local_lock`使用`std::unique_lock`中的 lock 成员函数标记了关键部分的开始。一旦数据检索完成，锁将被释放，标志着关键部分的结束。在此之后，调用`process_data()`函数，再次不需要独占访问，可以自由执行。最后，在执行`store_result()`函数之前，锁定互斥锁以保护更新处理结果的写操作。在退出函数时，当`std::unique_lock`的局部实例被销毁时，锁将被释放。

# 条件变量

我们已经知道互斥锁可以用于共享公共资源并在线程之间同步操作。但是，如果不小心使用互斥锁进行同步，会变得有点复杂并容易发生死锁。在本节中，我们将讨论如何使用条件变量等待事件，以及如何以更简单的方式在同步中使用它们。

当涉及使用互斥锁进行同步时，如果等待的线程已经获得了对互斥锁的锁定，那么任何其他线程都无法锁定它。此外，通过定期检查由互斥锁保护的状态标志来等待一个线程完成执行是一种浪费 CPU 资源。这是因为这些资源可以被系统中的其他线程有效利用，而不必等待更长的时间。

为了解决这些问题，C++标准库提供了两种条件变量的实现：`std::condition_variable`和`std::condition_variable_any`。两者都声明在`<condition_variable>`库头文件中，两种实现都需要与互斥锁一起工作以同步线程。`std::condition_variable`的实现仅限于与`std::mutex`一起工作。另一方面，`std::condition_variable_any`可以与满足类似互斥锁标准的任何东西一起工作，因此带有`_any`后缀。由于其通用行为，`std::condition_variable_any`最终会消耗更多内存并降低性能。除非有真正的、定制的需求，否则不建议使用它。

以下程序是我们在讨论互斥锁时讨论过的奇偶线程的实现，现在正在使用条件变量进行重新实现。

```cpp
std::mutex numMutex; 
std::condition_variable syncCond; 
auto bEvenReady = false; 
auto bOddReady  = false; 
void printEven(int max) 
{ 
    for (int i = 0; i <= max; i +=2) 
    { 
        std::unique_lock<std::mutex> lk(numMutex); 
        syncCond.wait(lk, []{return bEvenReady;}); 

        std::cout << i << ","; 

        bEvenReady = false; 
        bOddReady  = true; 
        syncCond.notify_one(); 
    } 
}
```

程序从全局声明一个互斥锁、一个条件变量和两个布尔标志开始，以便在两个线程之间进行同步。`printEven`函数在一个工作线程中执行，并且只打印从 0 开始的偶数。在这里，当它进入循环时，互斥锁受到`std::unique_lock`的保护，而不是`std::lock_guard`；我们马上就会看到原因。然后线程调用`std::condition_variable`中的`wait()`函数，传递锁对象和一个 Lambda 谓词函数，表达了正在等待的条件。这可以用任何返回 bool 的可调用对象替换。在这个函数中，谓词函数返回`bEvenReady`标志，以便在它变为 true 时函数继续执行。如果谓词返回 false，`wait()`函数将解锁互斥锁并等待另一个线程通知它，因此`std::unique_lock`对象在这里非常方便，提供了锁定和解锁的灵活性。

一旦`std::cout`打印循环索引，`bEvenReady`标志就会被设置为 false，`bOddReady`标志则会被设置为 true。然后，与`syncCond`相关联的`notify_one()`函数的调用会向等待的奇数线程发出信号，要求其将奇数写入标准输出流：

```cpp
void printOdd(int max) 
{ 
    for (int i = 1; i <= max; i +=2) 
    { 
        std::unique_lock<std::mutex> lk(numMutex); 
        syncCond.wait(lk, []{return bOddReady;}); 

        std::cout << i << ","; 

        bEvenReady = true; 
        bOddReady  = false; 
        syncCond.notify_one(); 
    } 
} 
```

`printOdd`函数在另一个工作线程中执行，并且只打印从`1`开始的奇数。与`printEven`函数不同，循环迭代并打印由全局声明的条件变量和互斥锁保护的索引。在`std::condition_variable`的`wait()`函数中使用的谓词返回`bOddReady`，`bEvenReady`标志被设置为`true`，`bOddReady`标志被设置为`false`。随后，调用与`syncCond`相关联的`notify_one()`函数会向等待的偶数线程发出信号，要求其将偶数写入标准输出流。这种奇偶数交替打印将持续到最大值：

```cpp
int main() 
{ 
    auto max = 10; 
    bEvenReady = true; 

    std::thread t1(printEven, max); 
    std::thread t2(printOdd, max); 

    if (t1.joinable()) 
        t1.join(); 
    if (t2.joinable()) 
        t2.join(); 

} 
```

主函数启动两个后台线程，`t1`与`printEven`函数相关联，`t2`与`printOdd`函数相关联。输出在确认偶数奇数性之前开始，通过将`bEvenReady`标志设置为 true。

# 线程安全的堆栈数据结构

到目前为止，我们已经讨论了如何启动和管理线程，以及如何在并发线程之间同步操作。但是，当涉及到实际系统时，数据以数据结构的形式表示，必须根据情况选择适当的数据结构，以确保程序的性能。在本节中，我们将讨论如何使用条件变量和互斥量设计并发栈。以下程序是 `std::stack` 的包装器，声明在库头文件 `<stack>` 下，并且栈包装器将提供不同的 pop 和 push 功能的重载（这样做是为了保持清单的简洁，并且还演示了如何将顺序数据结构调整为在并发上下文中工作）：

```cpp
template <typename T> 
class Stack 
{ 
private: 
    std::stack<T> myData; 
    mutable std::mutex myMutex; 
    std::condition_variable myCond; 

public: 
    Stack() = default; 
    ~Stack() = default; 
    Stack& operator=(const Stack&) = delete; 

    Stack(const Stack& that) 
    { 
        std::lock_guard<std::mutex> lock(that.myMutex); 
        myData = that.myData; 
    }
```

`Stack` 类包含模板类 `std::stack` 的对象，以及 `std::mutex` 和 `std::condition_variable` 的成员变量。类的构造函数和析构函数标记为默认，让编译器为其生成默认实现，并且复制赋值运算符标记为删除，以防止在编译时调用此类的赋值运算符。定义了复制构造函数，它通过调用自己的复制赋值运算符来复制 `std::stack` 成员对象 `myData`，该操作受到右侧对象的互斥量保护：

```cpp
      void push(T new_value) 
      { 
          std::lock_guard<std::mutex> local_lock(myMutex); 
          myData.push(new_value); 
          myCond.notify_one(); 
      } 
```

成员函数 `push()` 包装了 `std::stack` 容器的 `push` 函数。可以看到，互斥量成员变量 `myMutex` 被 `std::lock_guard` 对象锁定，以保护接下来的 `push` 操作。随后，使用成员 `std::condition_variable` 对象调用 `notify_one()` 函数，以通过相同的条件变量引发事件来通知等待的线程。在以下代码清单中，您将看到 `pop` 操作的两个重载，它们等待在此条件变量上得到信号：

```cpp
    bool try_pop(T& return_value) 
    { 
        std::lock_guard<std::mutex> local_lock(myMutex); 
        if (myData.empty()) return false; 
        return_value = myData.top(); 
        myData.pop(); 
        return true; 
    }
```

`try_pop()` 函数以模板参数作为引用。由于实现从不等待栈至少填充一个元素，因此使用 `std::lock_guard` 对象来保护线程。如果栈为空，函数返回 `false`，否则返回 `true`。在这里，输出通过调用 `std::stack` 的 `top()` 函数分配给输入引用参数，该函数返回栈中的顶部元素，然后调用 `pop()` 函数来清除栈中的顶部元素。所有 `pop` 函数的重载都调用 `top()` 函数，然后调用 `std::stack` 的 `pop()` 函数：

```cpp
    std::shared_ptr<T> try_pop() 
    { 
        std::lock_guard<std::mutex> local_lock(myMutex); 
        if (myData.empty()) return std::shared_ptr<T>(); 

        std::shared_ptr<T> return_value(std::make_shared<T>(myData.top())); 
        myData.pop(); 

        return return_value;
    } 
```

这是 `try_pop()` 函数的另一个重载，它返回模板类型的 `std::shared_ptr`（智能指针）的实例。正如您已经看到的，`try_pop` 函数有多个重载，并且从不等待栈至少填充一个元素；因此，此实现使用 `std::lock_guard`。如果内部栈为空，函数返回 `std::shared_ptr` 的实例，并且不包含栈的任何元素。否则，返回包含栈顶元素的 `std::shared_ptr` 实例：

```cpp
    void wait_n_pop(T& return_value) 
    { 
        std::unique_lock<std::mutex> local_lock(myMutex); 
        myCond.wait(local_lock, [this]{ return !myData.empty(); }); 
        return_value = myData.top(); 
        myData.pop(); 
    }      
    std::shared_ptr<T> wait_n_pop() 
    { 
        std::unique_lock<std::mutex> local_lock(myMutex); 
        myCond.wait(local_lock, [this]{ return !myData.empty(); }); 
        std::shared_ptr<T> return_value(std::make_shared<T>(myData.top())); 
        return return_value; 
    }   
}; 
```

到目前为止，`pop`函数的重载不会等待堆栈至少填充一个元素，如果它是空的。为了实现这一点，添加了`pop`函数的另外两个重载，它们使用与`std::condition_variable`相关的等待函数。第一个实现将模板值作为输出参数返回，第二个实现返回一个`std::shared_ptr`实例。这两个函数都使用`std::unique_lock`来控制互斥锁，以便提供`std::condition_variable`的`wait()`函数。在`wait`函数中，`predicate`函数正在检查堆栈是否为空。如果堆栈为空，那么`wait()`函数会解锁互斥锁，并继续等待，直到从`push()`函数接收到通知。一旦调用了 push，predicate 将返回 true，`wait_n_pop`继续执行。函数重载接受模板引用，并将顶部元素分配给输入参数，后一个实现返回一个包含顶部元素的`std::shared_ptr`实例。

# 总结

在本章中，我们讨论了 C++标准库中可用的线程库。我们看到了如何启动和管理线程，并讨论了线程库的不同方面，比如如何将参数传递给线程，线程对象的所有权管理，线程之间数据的共享等等。C++标准线程库可以执行大多数可调用对象作为线程！我们看到了所有可用的可调用对象与线程的关联的重要性，比如`std::function`，Lambda 和函数对象。我们讨论了 C++标准库中可用的同步原语，从简单的`std::mutex`开始，使用 RAII 习惯用法来保护互斥锁免受未处理的退出情况的影响，以避免显式解锁，并使用诸如`std::lock_guard`和`std::unique_lock`之类的类。我们还讨论了条件变量(`std::condition_variable`)在线程同步的上下文中。本章为现代 C++引入的并发支持奠定了良好的基础，为本书进入功能习惯打下了基础。

在接下来的章节中，我们将涵盖 C++中更多的并发库特性，比如基于任务的并行性和无锁编程。
