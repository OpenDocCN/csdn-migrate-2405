# C++ 专家编程：成为熟练的程序员（六）

> 原文：[`annas-archive.org/md5/f9404739e16292672f830e964de1c2e4`](https://annas-archive.org/md5/f9404739e16292672f830e964de1c2e4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：使用 Qt 进行图形用户界面

C++并不直接提供**图形用户界面**（**GUI**）编程。首先，我们应该了解 GUI 与特定的**操作系统**（**OS**）密切相关。您可以使用 Windows API 在 Windows 中编写 GUI 应用程序，或者使用 Linux 特定的 API 在 Linux 中编写 GUI 应用程序，依此类推。每个操作系统都有自己特定的窗口和 GUI 组件形式。

我们在第一章中提到了不同平台及其差异。在讨论 GUI 编程时，平台之间的差异更加令人望而生畏。跨平台开发已经成为 GUI 开发人员生活中的一大痛苦。他们不得不专注于特定的操作系统。为其他平台实现相同的应用程序几乎需要同样多的工作。这是一个不合理的巨大时间和资源浪费。诸如*Java*之类的语言提供了在虚拟环境中运行应用程序的智能模型。这使得开发人员可以专注于一种语言和一个项目，因为环境负责在不同的平台上运行应用程序。这种方法的一个主要缺点是强制用户安装虚拟机，以及与特定平台应用程序相比较慢的执行时间。

为了解决这些问题，Qt 框架被创建了。在本章中，我们将了解 Qt 框架如何支持跨平台 GUI 应用程序开发。为此，您需要熟悉 Qt 及其关键特性。这将使您能够使用您喜爱的编程语言——C++来开发 GUI 应用程序。我们将首先了解 Qt 的 GUI 开发方法，然后我们将涵盖其概念和特性，如信号和槽，以及模型/视图编程。

在本章中，我们将涵盖以下主题：

+   跨平台 GUI 编程的基础

+   Qt 核心组件

+   使用 Qt 小部件

+   使用 Qt Network 设计网络应用程序

# 技术要求

您需要安装最新的 Qt 框架才能运行本章的示例。我们建议使用 Qt Creator 作为项目的 IDE。要下载 Qt 及相应的工具，请访问[qt.io](https://www.qt.io/)网站，并选择框架的开源版本。本章的代码可以在以下网址找到：[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)。

# 了解跨平台 GUI 编程

每个操作系统都有自己的 API。它与 GUI 特别相关。当公司计划设计、实现和发布桌面应用程序时，他们应该决定专注于哪个平台。一个团队的开发人员在一个平台上工作，几乎需要花同样多的时间为另一个平台编写相同的应用程序。这最大的原因是操作系统提供的不同方法和 API。API 的复杂性也可能在按时实现应用程序方面起到重要作用。例如，官方文档中的以下片段显示了如何使用 C++在 Windows 中创建按钮：

```cpp
HWND hwndButton = CreateWindow(
  L"BUTTON", // Predefined class; Unicode assumed      
  L"OK", // Button text      
  WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, // Styles      
  10, // x position      
  10, // y position      
  100, // Button width     
  100, // Button height     
  m_hwnd, // Parent window     
  NULL, // No menu.     
  (HINSTANCE)GetWindowLong(m_hwnd, GWL_HINSTANCE),     
  NULL); // Pointer not needed.
```

解决 Windows GUI 编程需要你使用`HWND`、`HINSTACNCE`和许多其他奇怪命名和令人困惑的组件。

.NET Framework 对 Windows GUI 编程进行了重大改进。如果您想支持除 Windows 之外的操作系统，使用.NET Framework 之前要三思。

然而，为了支持多个操作系统，您仍然需要深入了解 API 来实现相同的应用程序，以满足所有操作系统的用户。以下代码显示了在 Linux 中使用*Gtk+* GUI 工具包创建按钮的示例：

```cpp
GtkWidget* button = gtk_button_new_with_label("Linux button");
```

与 Windows API 相比，它似乎更容易理解。但是，您应该深入了解`GtkWidgets`和其他带有*Gtk*前缀的组件，以了解更多关于它们的信息。

正如我们已经提到的，诸如 Java 和.NET Core 之类的跨平台语言使用虚拟机在不同平台上运行代码。Qt 框架支持使用基于平台的编译方法进行跨平台 GUI 编程。让我们就 C++语言讨论这两种方法。

# 使用 C++作为 Java

诸如 Java 或 C#之类的语言有不同的编译模型。本书的第一章介绍了 C++的编译模型。首先，我们认为 C++是一种完全可编译的语言，而 Java 保持了混合模型。它将源代码编译成称为**字节码**的中间表示，然后虚拟机通过将其翻译成特定平台的机器代码来运行它。

以下图表描述了 C++和 Java 编译模型之间的差异：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/c0552bd5-d588-48b5-b7ec-9491231fbe30.png)

**Java 虚拟机**（JVM）充当中间层。它对每个平台有一个独特的实现。用户需要在运行 Java 程序之前安装特定实现的虚拟机。安装过程只发生一次。另一方面，C++程序被翻译成机器代码，而不需要像 JVM 这样的中间层环境。这是 C++应用程序通常更快的原因之一。当我们在某个平台上编译 C++程序时，编译器会输出一个由特定于该平台的格式的指令组成的可执行文件。当我们将应用程序移动到另一个平台时，它就无法运行。

其他平台无法识别它的格式，也无法识别它的指令（尽管它们可能在某种程度上相似）。Java 方法通过提供一些字节码来工作，这些字节码对于所有虚拟机的实现都是相同的。但是虚拟机确切地知道他们应该为作为输入提供的字节码生成哪些指令。如果安装了虚拟机，相同的字节码可以在许多计算机上运行。以下图表演示了 Java 应用程序编译模型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/4395de50-bc9b-4255-a882-8203041b2429.png)

如您所见，源代码被编译成可以在每个操作系统上运行的字节码。然而，每个操作系统必须提供其自己的虚拟机实现。这意味着如果我们为该操作系统安装了专门为该操作系统实现的 JVM，我们就可以在任何操作系统上运行 Java 应用程序。

尽管 C++是一种跨平台语言，也就是说我们不需要修改代码就可以在其他平台上编译它，但是这种语言并不直接支持 GUI 编程。为了编写 GUI 应用程序，正如我们之前提到的，我们需要直接从代码中访问操作系统 API。这使得 C++ GUI 应用程序依赖于平台，因为你需要修改代码基础才能在其他平台上编译它。以下图表显示了 GUI 是如何破坏语言的跨平台性的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2cba1673-03ed-49cd-89b0-123652d0f46b.png)

尽管应用程序的逻辑、名称和任务可能相同，但现在它有三种不同的实现，有三种不同的可执行文件。要将应用程序交付给最终用户，我们需要发现他们的操作系统并交付正确的可执行文件。您可能在从网上下载应用程序时遇到了类似的情况。它们基于操作系统提供下载应用程序。这就是 Qt 发挥作用的地方。让我们看看它是如何做到的。

# Qt 的跨平台模型

Qt 是一个用于创建 GUI 应用程序的流行的小部件工具包。它还允许我们创建在各种系统上运行的跨平台应用程序。Qt 包括以下模块：

+   **Qt 核心**：核心类

+   **Qt GUI**：GUI 组件的基本类

+   **Qt 小部件**：用于扩展 Qt GUI 的 C++小部件的类

+   **Qt 多媒体**：音频、视频、广播和摄像功能的类

+   **Qt 多媒体小部件**：实现多媒体功能的类

+   **Qt 网络**：网络编程的类（我们将在本章中使用它们）

+   **Qt 建模语言**（**QML**）：用于构建具有自定义用户界面的声明性框架

+   **Qt SQL**：使用 SQL 进行数据库集成的类

+   **Qt Quick 模块系列**：一个与 QML 相关的模块列表，本书不会讨论

+   **Qt 测试**：用于单元测试 Qt 应用程序的类

我们在程序中使用的每个模块都通过具有`.pro`扩展名的项目文件连接到编译器。该文件描述了`qmake`构建应用程序所需的一切。*qmake*是一个旨在简化构建过程的工具。我们在项目的`.pro`文件中描述项目组件（源文件、Qt 模块、库等）。例如，一个使用 Qt 小部件和 Qt 网络，由`main.cpp`和`test.cpp`文件组成的项目将在`.pro`文件中具有以下内容：

```cpp
QT += widgets
QT += network
SOURCES += test.cpp
SOURCES += main.cpp
```

我们也可以在`.pro`文件中指定特定于平台的源文件，如下所示：

```cpp
QT += widgets
QT += network
SOURCES += test.cpp
SOURCES += main.cpp
win32 {
 SOURCES += windows_specific.cpp
}
unix {
 SOURCES += linux_world.cpp
}
```

当我们在 Windows 环境中构建应用程序时，`windows_specific.cpp`文件将参与构建过程。相反，当在 Unix 环境中构建时，将包括`linux_world.cpp`文件，而`windows_specific.cpp`文件将被忽略。通过这样，我们已经了解了 Qt 应用程序的编译模型。

Qt 强大的跨平台编程能力的整个重点在于元编译源代码；也就是说，在代码传递给 C++编译器之前，Qt 编译器通过引入或替换特定于平台的组件来清理它。例如，当我们使用按钮组件（`QPushButton`）时，如果在 Windows 环境中编译，它将被替换为特定于 Windows 的按钮组件。这就是为什么`.pro`文件也可以包含项目的特定于平台的修改。以下图表描述了这个编译过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/ea855027-5cfa-4dbb-861e-3c3c908077f2.png)

元编译器通常被称为**元对象编译器**（**MOC**）。这种方法的美妙之处在于产生的输出代表了我们可以直接运行的相同机器代码，而无需虚拟机。我们可以立即发布可执行文件。这种方法的缺点是，我们再次为不同的平台有不同的可执行文件。然而，我们只编写一个应用程序 - 无需使用不同的语言，深入研究特定于操作系统的 API，或学习特定于操作系统的 GUI 组件类名称。正如 Qt 所说，*一次编写，到处编译*。现在，让我们继续构建一个简单的 GUI 应用程序。

# 编写一个简单的应用程序

我们不会在本书中讨论我们之前提到的所有模块，因为这需要一本全新的书。您可以在本章末尾列出的书籍中的*进一步阅读*部分中查阅更多信息。`main`函数如下所示：

```cpp
#include <QtWidgets>

int main(int argc, char** argv)
{
  QApplication app(argc, argv);

  QPushButton btn("Click me!");
  btn.show();

  return app.exec();
}
```

让我们来看看我们在代码中使用的各种组件。第一个是`QtWidgets`头文件。它包含了我们可以用来为应用程序构建细粒度 GUI 的小部件组件。接下来是`QPushButton`类，它代表一个可点击按钮的包装器。我们故意在这里引入它作为一个包装器，这样我们可以在本章后面讨论 Qt 程序的编译过程时解释它。这是运行上述代码的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/10a68757-4e71-4c70-a722-b05add3fda63.png)

正如您所看到的，我们只声明了`QPushButton`类，但它出现为一个具有标准 OS 的关闭和最小化按钮的窗口（在本例中是 macOS）。这是因为`QPushButton`间接继承自`QWidget`，它是一个带有框架的小部件；也就是说，一个窗口。按钮几乎占据了窗口的所有空间。我们可以调整窗口的大小，看看按钮如何随之调整大小。我们将在本章后面更详细地讨论小部件。 

当我们运行`app.exec()`时，GUI 构建完成。注意`app`对象的类型。它是一个`QApplication`对象。这是 Qt 应用程序的起点。当我们调用`exec()`函数时，我们启动了 Qt 的事件循环。我们对程序执行的感知应该有所改变，以理解 GUI 应用程序的生命周期。重新定义程序构建和执行的感知在第七章之后对你来说应该不足为奇，*函数式编程*。这次并不那么困难。这里需要知道的主要事情是，GUI 应用程序在主程序之外还有一个额外的实体在运行。这个实体被称为**事件循环**。

回想一下我们在第十一章中讨论过的事件循环，*使用设计模式设计策略游戏*。游戏代表了用户密集交互的可视组件的程序。同样适用于具有按钮、标签和其他图形组件的常规 GUI 应用程序。

用户与应用程序交互，每个用户操作都被解释为一个事件。然后将每个事件推送到队列中。事件循环逐个处理这些事件。处理事件意味着调用与事件相关联的特殊处理程序函数。例如，每当单击按钮时，将调用`keyPressedEvent()`函数。它是一个虚函数，因此在设计自定义按钮时可以重写它，如下面的代码所示：

```cpp
class MyAwesomeButton : public QPushButton
{
  Q_OBJECT
public:
 void keyPressedEvent(QKeyEvent* e) override
 {
 // anything that we need to do when the button is pressed
 }
};
```

事件的唯一参数是指向`QKeyEvent`的指针，它是`QEvent`的子类型。`QEvent`是 Qt 中所有事件类的基类。注意在类的开头块之后放置的奇怪的`Q_OBJECT`。这是一个 Qt 特定的宏，如果你想让它们被 Qt 的 MOC 发现，应该将它放在自定义类的第一行。

在下一节中，我们将介绍特定于 Qt 对象的信号和槽的机制。为了使我们的自定义对象支持该机制，我们在类定义中放置`Q_OBJECT`宏。

现在，让我们构建比简单按钮更大的东西。以下示例创建了一个标题为“精通 C ++”的窗口：

```cpp
#include <QtWidgets>

int main(int argc, char** argv)
{
  QApplication app(argc, argv);
 QWidget window;
 window.resize(120, 100);
 window.setWindowTitle("Mastering C++");
 window.show();

  return app.exec();
}
```

通过执行上述程序，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/9d9f3077-f55d-4e9d-969c-943ce57ae816.png)

标题被截断了；我们只能看到“Mast...”部分的“Mastering C ++”。现在，如果我们手动调整大小，或者更改源代码，使第二个参数的`resize()`函数具有更大的值，我们会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/e176177a-de4c-4ab2-8043-e63400a3a368.png)

`window`对象是`QWidget`类型。`QWidget`是所有用户界面对象的中心类。每当您想要创建自定义小部件或扩展现有小部件时，您都会直接或间接地继承自`QWidget`。它有很多函数适用于每种用例。您可以使用`move()`函数在屏幕上移动它，可以通过调用`showFullScreen()`使窗口全屏，等等。在上面的代码中，我们调用了`resize()`函数，它接受宽度和高度来调整小部件的大小。还要注意`setWindowTitle()`函数，它正如其名-将传递的字符串参数设置为窗口的标题。在代码中使用字符串值时，最好使用`QApplication::translate()`函数。这样做可以使程序本地化变得更容易，因为当语言设置更改时，Qt 会自动用正确的翻译替换文本。`QObject::tr()`提供了几乎相同的功能。

`QObject`是所有 Qt 类型的基类。在诸如 Java 或 C＃之类的语言中，每个对象都直接或间接地继承自一个通用类型，通常命名为`Object`。C ++没有包含一个公共基类。另一方面，Qt 引入了`QObject`，它具有所有对象应支持的基本功能。

现在我们已经了解了 Qt 应用程序开发的基础知识，让我们深入了解框架并发现其关键特性。

# 发现 Qt

Qt 随着时间的推移不断发展，在撰写本书时，其版本为 5.14。它的第一个公共预发布版本是在 1995 年宣布的。已经过去了二十多年，现在 Qt 在几乎所有平台上都有许多强大的功能，包括 Android 和 iOS 等移动系统。除了少数例外，我们可以自信地为所有平台使用 C++和 Qt 编写功能齐全的 GUI 应用程序。这是一个重大的变革，因为公司可以雇佣专门从事一种技术的小团队，而不是为每个特定平台都有几个团队。

如果你是 Qt 的新手，强烈建议你尽可能熟悉它（在本章的末尾有书籍参考）。除了 GUI 框架提供的常规组件外，Qt 还引入了一些在框架中新的或精心实现的概念。其中一个概念是使用信号和槽进行对象之间的通信。

# 掌握信号和槽

Qt 引入了信号和槽的概念作为对象之间灵活的通信机制。信号和槽的概念及其实现机制是将 Qt 与其他 GUI 框架区分开的特性之一。在之前的章节中，我们讨论了观察者模式。这个模式的主要思想是有一个对象通知其他对象（订阅者）一个事件。信号和槽的机制类似于观察者模式的实现。这是一种对象通知另一个对象其变化的方式。Qt 提供了一个通用接口，可以用来通过将一个对象的信号与另一个对象的槽绑定来连接对象。信号和槽都是对象的常规成员函数。信号是在对象的指定动作上调用的函数。槽是作为订阅者的另一个函数。它由信号函数调用。

正如我们之前提到的，Qt 向我们介绍了所有对象的基本类型`QObject`。支持信号和槽的基本功能在`QObject`中实现。你在代码中声明的任何对象，`QWidget`、`QPushButton`等都继承自`QObject`，因此它们都支持信号和槽。QObject 为我们提供了两个用于管理对象通信的函数。这些对象是`connect()`和`disconnect()`：

```cpp
bool connect(const QObject* sender, const char* signal, 
  const QObject* receiver, const char* method, 
  Qt::ConnectionType type = Qt::AutoConnect);

bool disconnect(const QObject* sender, const char* signal, 
  const QObject* receiver, const char* method);
```

正如你所看到的，`connect()`函数将`receiver`和`sender`对象作为参数。它还接受信号和槽的名称。`signal`与发送者相关联，而`slot`是接收者提供的。以下图表显示了这一点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2583b4a4-6b3d-4aa9-b879-885fcb19b63b.png)

当编写 Qt 应用程序时，操作信号和槽将变得自然，迟早你会认为每个其他框架都支持信号和槽，因为它们很方便。还要注意，在`connect()`和`disconnect()`函数中，信号和槽被处理为字符串。在连接对象时指定信号和槽，我们使用另外两个宏，分别是`SIGNAL()`和`SLOT()`。从现在开始不会再介绍更多的宏 - 我们保证。

这是我们如何连接两个对象的方式。假设我们想要改变标签（`QLabel`的一个实例）的文本，使其在按钮被点击时接收一个信号。为了实现这一点，我们将`QPushButton`的`clicked()`信号连接到`QLabel`的槽，如下所示：

```cpp
QPushButton btn("Click me!");
QLabel lbl;
lbl.setText("No signal received");
QObject::connect(&btn, SIGNAL(clicked()), &lbl, SLOT(setText(const QString&)));
```

前面的代码可能看起来有点冗长，但你会习惯的。把它看作是信号和槽的便利机制的代价。然而，前面的例子不会给我们所需的结果；也就是说，它不会将标签的文本设置为接收到信号。我们应该以某种方式将该字符串传递给标签的槽。`clicked()`信号不会为我们做到这一点。实现这一点的一种方法是通过扩展`QLabel`，使其实现一个自定义槽，将文本设置为`received a signal`。下面是我们可以这样做的方法：

```cpp
class MyLabel : public QLabel
{
Q_OBJECT
public slots:
  void setCustomText() { 
    this->setText("received a signal");
  }
};
```

要声明一个槽，我们像在前面的代码中所做的那样指定部分。信号的声明方式几乎相同：通过指定一个带有`signals：`的部分。唯一的区别是信号不能是私有或受保护的。我们只是按原样声明它们：

```cpp
class Example
{
Q_OBJECT:
public:
  // member functions
public slots:
  // public slots
private slots:
  // private slots
signals: // no public, private, or protected
  // signals without any definition, only the prototype
};
```

现在，我们只需要更新前面的代码，以更改标签的信号（以及标签对象的类型）：

```cpp
QPushButton btn("Click me!");
MyLabel lbl;
lbl.setText("No signal received");
QOBject::connect(&btn, SIGNAL(clicked()), &lbl, SLOT(setCustomText()));
```

我们说槽将在信号被发射时被调用。您还可以在对象内部声明和发射信号。与 GUI 事件循环无关的信号和槽的一个重要细节。

当信号被发射时，连接的槽立即执行。但是，我们可以通过将`Qt::ConnectionType`之一作为`connect()`函数的第五个参数来指定连接的类型。它包括以下值：

+   `AutoConnection`

+   `DirectConnection`

+   `QueuedConnection`

+   `BlockingQueuedConnection`

+   `UniqueConnection`

在`DirectConnection`中，当信号被发射时，槽立即被调用。另一方面，当使用`QueuedConnection`时，当执行返回到接收对象线程的事件循环时，槽被调用。`BlockingQueuedConnection`类似于`QueuedConnection`，只是信号线程被阻塞，直到槽返回一个值。`AutoConnection`可以是`DirectConnection`或`QueuedConnection`。当信号被发射时，类型被确定。如果接收者和发射者在同一线程中，使用`DirectConnection`；否则，连接使用`QueuedConnection`。最后，`UniqueConnection`与前面描述的任何连接类型一起使用。它与其中一个使用按位或组合。它的唯一目的是使`connect()`函数在信号和线程之间的连接已经建立时失败。

信号和槽构成了 Qt 在 GUI 编程中出色的机制。我们介绍的下一个机制在框架中很受欢迎，与我们在应用程序中操作数据的方式有关。

# 理解模型/视图编程

模型/视图编程根植于**模型视图控制器**（MVC）设计模式。该模式的主要思想是将问题分解为三个松散耦合的组件，如下所示：

+   模型负责存储和操作数据

+   视图负责渲染和可视化数据

+   控制器负责额外的业务逻辑，并从模型向视图提供数据

通过其演变，我们现在有了一种简化和更便利的编程方法，称为**模型/视图编程**。它类似于 MVC 模式，只是通过使视图和模型更关注手头的功能来省略了控制器。我们可以说视图和控制器在模型/视图架构中合并在一起。看一下以下架构图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/f039425a-e465-49bd-81db-34ca31d2918f.png)

模型代表数据，与其来源通信，并为架构中的其他组件提供方便的接口。模型的实现及其与其他组件的通信基于手头数据的类型。

视图通过获取所谓的模型索引来引用数据项。视图可以从模型检索和提供数据。关键是，数据项可以使用视图进行编辑，委托起到了与模型通信以保持数据同步的作用。

介绍的每个组件——模型、视图和委托——都由提供共同接口的抽象类定义。在某些情况下，类还提供了功能的默认实现。要编写专门的组件，我们从抽象类继承。当然，模型、视图和委托使用我们在上一节中介绍的信号和槽进行通信。

当模型遇到数据变化时，它会通知视图。另一方面，渲染数据项的用户交互由视图发出的信号通知。最后，委托发出的信号通知模型和视图有关数据编辑状态的信息。

模型基于`QAbstractItemModel`类，该类定义了视图和委托使用的接口。Qt 提供了一组现有的模型类，我们可以在不进行修改的情况下使用；但是，如果需要创建新模型，应该从`QAbstractItemModel`继承您的类。例如，`QStringListModel`、`QStandardItemModel`和`QFileSystemModel`类已经准备好处理数据项。`QStringListModel`用于存储字符串项列表（表示为`QString`对象）。此外，还有方便的模型类用于处理 SQL 数据库。`QSqlQueryModel`、`QSqlTableModel`和`QSqlRelationalTableModel`允许我们在模型/视图约定的上下文中访问关系数据库。

视图和委托也有相应的抽象类，即`QAbstractItemView`和`QAbstractItemDelegate`。Qt 提供了现有的视图，可以立即使用，例如`QListView`、`QTableView`和`QTreeView`。这些是大多数应用程序处理的基本视图类型。`QListView`显示项目列表，`QTableView`以表格形式显示数据，`QTreeView`以分层列表形式显示数据。如果要使用这些视图类，Qt 建议从`QAbstractListModel`或`QAbstractTableModel`继承自定义模型，而不是对`QAbstractItemModel`进行子类化。

`QListView`、`QTreeView`和`QTableView`被认为是核心和低级别的类。还有更方便的类，为新手 Qt 程序员提供更好的可用性——`QListWidget`、`QTreeWidget`和`QTableWidget`。我们将在本章的下一节中看到使用小部件的示例。在那之前，让我们看一个`QListWidget`的简单示例：

```cpp
#include <QListWidget>

int main(int argc, char** argv)
{
  QApplication app(argc, argv);
  QListWidget* listWgt{new QListWidget};
  return app.exec();
}
```

向列表窗口小部件添加项目的一种方法是通过创建它们，我们可以通过将列表窗口小部件设置为其所有者来实现。在下面的代码中，我们声明了三个`QListWidgetItem`对象，每个对象都包含一个名称，并与我们之前声明的列表窗口小部件相关联：

```cpp
new QListWidgetItem("Amat", listWgt);
new QListWidgetItem("Samvel", listWgt);
new QListWidgetItem("Leia", listWgt);
```

或者，我们可以声明一个项目，然后将其插入到列表窗口小部件中：

```cpp
QListWidgetItem* newName{new QListWidgetItem};
newName->setText("Sveta");
listWgt->insertItem(0, newName);
```

`insertItem()`成员函数的第一个参数是要将项目插入的`row`的数量。我们将`Sveta`项目放在列表的第一个位置。

现在我们已经涉及了行的概念，我们应该回到模型和它们的索引。模型将数据封装为数据项的集合。模型中的每个项都有一个由`QModelIndex`类指定的唯一索引。这意味着模型中的每个项都可以通过关联的模型索引访问。要获取模型索引，我们需要使用`index()`函数。以下图表描述了一个以表格结构组织其数据的模型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/394f992b-dd5a-4d0b-a1cf-ad364cf58851.png)

视图使用这种约定来访问模型中的数据项。但是，请注意，视图在呈现数据给用户方面并没有限制。视图的实现方式取决于如何以对用户方便的方式呈现和展示数据。以下图表显示了数据在模型中的组织方式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/8cadf899-4035-46fc-9457-dc68738f5099.png)

这是我们如何使用模型索引访问第 1 行第 2 列的特定数据项：

```cpp
QModelIndex itemAtRow1Col2 = model->index(1, 2);
```

最后，让我们声明一个视图并为其设置一个模型，以查看模型/视图编程的实际效果：

```cpp
QStringList lst;
lst << "item 1" << "item 2" << "item 3";

QStringListModel model;
model.setStringList(lst);

QListView lview;
lview.setModel(model);
```

一旦我们熟悉了 Qt 提供的各种小部件，我们将在下一节继续这个示例。

# 使用 Qt 小部件

小部件是可视化 GUI 组件。如果一个小部件没有父级，它将被视为一个窗口，也就是**顶级小部件**。在本章的前面，我们创建了 Qt 中最简单的窗口，如下所示：

```cpp
#include <QtWidgets>

int main(int argc, char** argv)
{
  QApplication app(argc, argv);
 QWidget window;
 window.resize(120, 100);
 window.setWindowTitle("Mastering C++");
 window.show();

  return app.exec();
}
```

正如您所看到的，`window`对象没有父级。问题是，`QWidget`的构造函数接受另一个`QWidget`作为当前对象的父级。因此，当我们声明一个按钮并希望它成为`window`对象的子级时，我们可以这样做：

```cpp
#include <QtWidgets>

int main(int argc, char** argv)
{
  QApplication app(argc, argv);
QWidget window;
  window.resize(120, 100);
  window.setWindowTitle("Mastering C++");
  window.show();

 QPushButton* btn = new QPushButton("Click me!", &window);

  return app.exec();
}
```

观察`QPushButton`构造函数的第二个参数。我们将`window`对象的引用作为其父级传递。当父对象被销毁时，其子对象将自动被销毁。Qt 支持许多其他小部件；让我们看看其中一些。

# 常见的 Qt 小部件

在上一节中，我们介绍了`QPushButton`类，并指出它间接继承了`QWidget`类。要创建一个窗口，我们使用了`QWidget`类。事实证明，QWidget 代表了向屏幕渲染的能力，它是所有小部件都继承的基本类。它具有许多属性和函数，例如`enabled`，一个布尔属性，如果小部件启用则为 true。要访问它，我们使用`isEnabled()`和`setEnabled()`函数。要控制小部件的大小，我们使用它的`height`和`width`，分别表示小部件的高度和宽度。要获取它们的值，我们分别调用`height()`和`width()`。要设置新的高度和宽度，我们应该使用`resize()`函数，它接受两个参数 - 宽度和高度。您还可以使用`setMinimumWidth()`、`setMinimumHeight()`、`setMaximumWidth()`和`setMaximumHeight()`函数来控制小部件的最小和最大大小。当您在布局中设置小部件时，这可能会很有用（请参阅下一节）。除了属性和函数，我们主要对 QWidget 的公共槽感兴趣，它们如下：

+   `close()`: 关闭小部件。

+   `hide()`: 等同于`setVisible(false)`，此函数隐藏小部件。

+   `lower()`和`raise()`: 将小部件移动到父小部件的堆栈中（到底部或顶部）。每个小部件都可以有一个父小部件。没有父小部件的小部件将成为独立窗口。我们可以使用`setWindowTitle()`和`setWindowIcon()`函数为此窗口设置标题和图标。

+   `style`: 该属性保存小部件的样式。要修改它，我们使用`setStyleSheet()`函数，通过传递描述小部件样式的字符串。另一种方法是调用`setStyle()`函数，并传递封装了与样式相关属性的`QStyle`类型的对象。

Qt 小部件几乎具备所有必要的属性，可以直接使用。很少遇到需要构建自定义小部件的情况。然而，一些团队为他们的软件创建了整套自定义小部件。如果您计划为程序创建自定义外观和感觉，那是可以的。例如，您可以整合扁平风格的小部件，这意味着您需要修改框架提供的默认小部件的样式。自定义小部件应该继承自`QWidget`（或其任何后代），如下所示：

```cpp
class MyWidget : public QWidget
{}; 
```

如果您希望小部件公开信号和插槽，您需要在类声明的开头使用`Q_OBJECT`宏。更新后的`MyWidget`类的定义如下：

```cpp
class MyWidget : public QWidget
{
Q_OBJECT
public:
  // public section

signals: 
  // list of signals

public slots:
  // list of public slots
};
```

正如您可能已经猜到的那样，信号没有访问修饰符，而插槽可以分为公共、私有和受保护部分。正如我们之前提到的，Qt 提供了足够的小部件。为了了解这些小部件，Qt 提供了一组将小部件组合在一起的示例。如果您已安装了 Qt Creator（用于开发 Qt 应用程序的 IDE），您应该能够通过单击一次来查看示例。在 Qt Creator 中的样子如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/477bcb65-d63d-444f-b137-11aa76371cd2.png)

配置和运行地址簿示例将给我们提供以下界面：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/d0e7b66e-749a-4d36-9520-e04b702e354a.png)

单击“添加”按钮将打开一个对话框，以便我们可以向地址簿添加新条目，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/5bd497c5-53ec-4f80-8c12-1b1143f90e84.png)

添加了几个条目后，主窗口将以表格形式显示条目，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/91bc9193-20c4-4f05-8660-b43300552cd6.png)

前面的屏幕截图显示了在一个应用程序中组合在一起的各种小部件。以下是我们在 GUI 应用程序开发中经常使用的一些常见小部件：

+   `QCheckBox`：表示带有文本标签的复选框。

+   `QDateEdit`：表示可以用来输入日期的小部件。如果还要输入时间，也可以使用`QDateTimeEdit`。

+   `QLabel`：文本显示。也用于显示图像。

+   `QLineEdit`：单行编辑框。

+   `QProgressBar`：渲染垂直或水平进度条。

+   `QTabWidget`：标签式小部件的堆栈。这是许多组织小部件中的一个。其他组织者包括`QButtonGroup`、`QGroupBox`和`QStackedWidget`。

前面的列表并非最终版本，但它给出了 Qt 的基本功能的基本概念。我们在这里使用的地址簿示例使用了许多这些小部件。`QTabWidget`表示一个组织小部件。它将几个小部件组合在一起。另一种组织小部件的方法是使用布局。在下一节中，我们将介绍如何将小部件组织在一起。

# 使用布局组合小部件

Qt 为我们提供了一个灵活和简单的平台，我们可以在其中使用布局机制来安排小部件。这有助于确保小部件内部的空间被高效地使用，并提供友好的用户体验。

让我们来看看布局管理类的基本用法。使用布局管理类的优势在于，当容器小部件更改大小时，它们会自动调整小部件的大小和位置。Qt 的布局类的另一个优势是，它们允许我们通过编写代码来安排小部件，而不是使用 UI 组合器。虽然 Qt Creator 提供了一种通过手工组合小部件的好方法（在屏幕上拖放小部件），但大多数程序员在实际编写安排小部件外观和感觉的代码时会感到更舒适。假设您也喜欢后一种方法，我们将介绍以下布局类：

+   `QHBoxLayout`

+   `QVBoxLayout`

+   `QGridLayout`

+   `QFormLayout`

所有这些类都继承自`QLayout`，这是几何管理的基类。`QLayout`是一个抽象基类，继承自`QObject`。它不继承自`QWidget`，因为它与渲染无关；相反，它负责组织应该在屏幕上呈现的小部件。您可能不需要实现自己的布局管理器，但如果需要，您应该从`QLayout`继承您的类，并为以下函数提供实现：

+   `addItem()`

+   `sizeHint()`

+   `setGeometry()`

+   `itemAt()`

+   `takeAt()`

+   `minimumSize()`

这里列出的类已经足够组成几乎任何复杂的小部件。更重要的是，我们可以将一个布局放入另一个布局中，从而更灵活地组织小部件。使用`QHBoxLayout`，我们可以从左到右水平地组织小部件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/41c40a4b-c3e7-48f1-b380-1e50488376d7.png)

要实现上述组织，我们需要使用以下代码：

```cpp
QWidget *window = new QWidget;
QPushButton *btn1 = new QPushButton("Leia");
QPushButton *btn2 = new QPushButton("Patrick");
QPushButton *btn3 = new QPushButton("Samo");
QPushButton *btn4 = new QPushButton("Amat");

QHBoxLayout *layout = new QHBoxLayout;
layout->addWidget(btn1);
layout->addWidget(btn2);
layout->addWidget(btn3);
layout->addWidget(btn4);

window->setLayout(layout);
window->show();
```

看一下我们在小部件上调用`setLayout()`函数的那一行。每个小部件都可以分配一个布局。布局本身没有太多作用，除非有一个容器，所以我们需要将其设置为一个作为组织小部件（在我们的情况下是按钮）容器的小部件。`QHBoxLayout`继承自`QBoxLayout`，它有另一个我们之前列出的后代——`QVBoxLayout`。它类似于`QHBoxLayout`，但是垂直地组织小部件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/a74e6782-1f0b-4911-a676-6caff1a6e7cf.png)

在上述代码中，我们唯一需要做的是将`QHBoxLayout`替换为`QVBoxLayout`，如下所示：

```cpp
QVBoxLayout* layout = new QVBoxLayout;
```

`GridLayout`允许我们将小部件组织成网格，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/76ec7f99-4a11-45e6-938a-9693af4e5f5f.png)

以下是相应的代码块：

```cpp
QGridLayout *layout = new QGridLayout;
layout->addWidget(btn1, 0, 0);
layout->addWidget(btn2, 0, 1);
layout->addWidget(btn3, 1, 0);
layout->addWidget(btn4, 1, 1);
```

最后，类似于`QGridLayout`，`QFormLayout`在设计输入表单时更有帮助，因为它以两列描述的方式布置小部件。

正如我们之前提到的，我们可以将一个布局组合到另一个布局中。为此，我们需要使用`addItem()`函数，如下所示：

```cpp
QVBoxLayout *vertical = new QVBoxLayout;
vertical->addWidget(btn1);
vertical->addWidget(btn2);

QHBoxLayout *horizontal = new QHBoxLayout;
horizontal->addWidget(btn3);
horizontal->addWidget(btn4);

vertical->addItem(horizontal);

```

布局管理器足够灵活，可以构建复杂的用户界面。

# 总结

如果您是 Qt 的新手，本章将作为对框架的一般介绍。我们涉及了 GUI 应用程序开发的基础知识，并比较了 Java 方法和 Qt 方法。使用 Qt 的最大优点之一是它支持跨平台开发。虽然 Java 也可以做到，但 Qt 通过生成与平台原生的可执行文件而更进一步。这使得使用 Qt 编写的应用程序比集成虚拟机的替代方案快得多。

我们还讨论了 Qt 的信号和槽作为对象间通信的灵活机制。通过使用这个机制，您可以在 GUI 应用程序中设计复杂的通信机制。虽然本章中我们只看了一些简单的例子，但您可以自由地尝试各种使用信号和槽的方式。我们还熟悉了常见的 Qt 小部件和布局管理机制。现在您已经有了基本的理解，可以设计甚至最复杂的 GUI 布局。这意味着您可以通过应用本章介绍的技术和小部件来实现复杂的 Qt 应用程序。在下一章中，我们将讨论一个当今流行的话题——人工智能和机器学习。

# 问题

1.  为什么 Qt 不需要虚拟机？

1.  `QApplication::exec()`函数的作用是什么？

1.  如何更改顶层小部件的标题？

1.  给定`m`模型，如何访问第 2 行第 3 列的项目？

1.  给定`wgt`小部件，如何将其宽度更改为 400，高度更改为 450？

1.  从`QLayout`继承以创建自己的布局管理器类时，应该实现哪些函数？

1.  如何将信号连接到槽？

# 进一步阅读

+   *Qt5 C++ GUI Programming Cookbook* by Lee Zhi Eng: [`www.packtpub.com/application-development/qt5-c-gui-programming-cookbook-second-edition`](https://www.packtpub.com/application-development/qt5-c-gui-programming-cookbook-second-edition)

+   *Mastering Qt5* by Guillaume Lazar, Robin Penea: [`www.packtpub.com/web-development/mastering-qt-5-second-edition`](https://www.packtpub.com/web-development/mastering-qt-5-second-edition)


# 第三部分：C++在人工智能世界中

本节是人工智能和机器学习最新进展的概述。我们将使用 C++来处理机器学习任务，并设计基于对话框的搜索引擎。

本节包括以下章节：

+   第十五章， 在机器学习任务中使用 C++

+   第十六章，实现基于对话框的搜索引擎


# 第十五章：在机器学习任务中使用 C++

人工智能（AI）和机器学习（ML）最近变得越来越受欢迎。从简单的食品送货网站到复杂的工业机器人，AI 已被宣称为支持软件和硬件的主要特性之一。虽然大多数时候这些术语被用来使产品看起来更严肃，但一些公司正在密集地研究并将 AI 纳入其系统中。

在我们继续之前，请考虑到这一章是从 C++程序员的角度对机器学习进行温和介绍。对于更全面的文献，请参考本章末尾的书籍列表。在本章中，我们将介绍人工智能和机器学习的概念。虽然最好有数学背景，但在本章中我们几乎不使用任何数学。如果你打算扩展你的技能并深入机器学习，你必须先考虑学习数学。

除了介绍概念，本章还提供了机器学习任务的示例。我们将实施它们，并给你一个如何研究和解决更复杂任务的基本思路。

我们将在本章中涵盖以下主题：

+   人工智能和机器学习的介绍

+   机器学习的类别和应用

+   为计算设计一个 C++类

+   神经网络结构和实现

+   回归分析和聚类

# 技术要求

在本章中，使用 g++编译器和`-std=c++2a`选项来编译示例。你可以在[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)找到本章中使用的源文件。

# 人工智能的介绍

人工智能的最简单定义是机器表现得像人类一样。这是机器所展示的智能。接下来讨论智能的定义。我们如何为机器定义智能，以及在什么程度上我们应该大声宣布我们正在处理一个智能机器？

如果你不熟悉用不同的测试来验证机器智能的方法，其中一种流行的方法是图灵测试。其思想是让一个询问者向两个人提问，其中一个是机器，另一个是人类。如果询问者无法清楚区分这两者，那么这台机器就应该被认为是智能的。

图灵测试是以艾伦·图灵命名的。这项测试是在他 1950 年的论文《计算机器和智能》中提出的。他建议使用模拟游戏来确定机器是否像人类一样思考。

被询问的人在墙后，以便询问者看不见他们。然后询问者向两个参与者提出几个问题。以下图表演示了询问者如何与人类和机器进行交流，但无法亲自看到他们：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/34dd7f9a-7753-4539-9a3a-526fa0f79ee3.png)

当你开始深入研究人工智能领域时，智能的定义变得越来越模糊。可以以任何形式向机器提问：文字、音频、视觉等等。有许多东西可能永远不会出现在机器中，比如他们的表情。有时人们通过对方的表情来理解彼此的情绪。你无法确定机器是否会理解，甚至能够模仿他们脸上的情绪。没有人教我们在生气时看起来生气。没有人教我们有情感。它们就在那里。很难说有一天，类似的事情是否会被机器实现。

谈到人工智能时，我们大多数时候认为它是关于一个与人类类似的说话和行为的机器人。但当你试图将其作为程序员进行分解时，你会遇到许多子领域，每个子领域都需要花费大量时间来理解。许多领域有许多正在进行的任务或处于早期研究阶段。以下是一些你可能有兴趣在职业生涯中专注的人工智能子领域：

+   **计算机视觉**：设计用于视觉对象识别和通过分析它们的视觉表示来理解对象的算法。人类很容易在人群中发现熟悉的面孔，但为机器实现类似的功能可能需要很长时间才能达到与人类相同的准确性。

+   **自然语言处理**（**NLP**）：机器对文本进行语言分析。它在各个领域都有应用，比如机器翻译。想象一下，计算机完全理解人类书面文本，这样我们就可以告诉它该做什么，而不是花几个月学习编程语言。

+   **知识推理**：这似乎是机器表现智能的明显目标。知识推理涉及让机器根据它们所拥有的信息进行推理并提供解决方案；例如，通过检查医疗状况来提供诊断。

+   **机器学习**：机器用于执行任务的算法和统计模型的研究领域。机器学习算法不依赖于直接指令，而是依赖于模式和推理。也就是说，机器学习允许机器自行完成工作，无需人类参与。

让我们分别讨论前面的子领域，然后集中讨论机器学习。

# 计算机视觉

计算机视觉是一个广泛的研究领域，有许多正在进行的研究项目。它涉及几乎与视觉数据处理相关的一切。它在各个领域都有广泛的应用；例如，人脸识别软件处理来自城市各处摄像头的数据，以查找和确定犯罪嫌疑人，或者光学字符识别软件从包含文本的图像中生成文本。结合一些**增强现实**（**AR**）技术，软件能够将图像中的文本翻译成用户熟悉的语言。

这一领域的研究正在日益取得进展。结合人工智能系统，计算机视觉是使机器感知世界的领域。对我们来说是简单的任务，但在计算机视觉方面实现起来是具有挑战性的。例如，当我们在图像中看到一个物体时，我们很容易看出它的尺寸。例如，以下图像代表了一辆自行车的前视图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/1e417264-3431-4087-a127-a74603e541bf.png)

即使我们不提到它是一辆自行车，人类也不难确定它。对我们来说，图像底部中央的黑色粗线是自行车的前轮是显而易见的。很难告诉计算机理解它是一个车轮。计算机所看到的只是一堆像素，其中一些颜色相同：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/1f146977-eca9-4201-8f08-c4874284568e.png)

除了理解自行车的车轮，它还应该推断这辆自行车必须有另一辆在图像中看不见的车轮。而且，我们可能对自行车的大致尺寸有一个猜测，而对于计算机来说，从图像中确定它是一个全面的任务。也就是说，我们视角中的简单事物可能在计算机视觉中成为一个真正的挑战。

我们建议在计算机视觉任务中使用 OpenCV 库。这是一个用 C 和 C++编写的跨平台库。OpenCV 代表了一组旨在实时计算机视觉的功能，包括但不限于人脸识别、手势识别、动作理解、运动跟踪和其他功能。

计算机视觉中的典型任务包括对象识别、识别和检测。对象识别是理解对象是前一图像中的车辆。识别是识别对象的个别实例，例如前一图像中自行车的车轮。对象检测任务可能包括在自行车图像中找到损坏的区域。所有这些任务结合机器学习算法可能构成一个全面的软件，它能够以接近人类方式理解周围环境。

# NLP

另一个有趣的研究领域是自然语言处理。自然语言处理致力于使计算机理解人类语言。更一般化的方法是自动语音识别和自然语言理解；这是虚拟助手的关键特性。今天，和手机交谈并要求它在网络上搜索某些内容已经不再是魔术。整个过程都由语音和文本分析中的复杂算法驱动。以下图表显示了发生在对话代理背后的高层视图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2afbe1d3-4236-437b-8728-a7a864c33172.png)

许多语言处理任务与网络相关。搜索引擎处理用户输入以在网络上数百万文档中搜索是自然语言处理的顶级应用之一。在下一章中，我们将深入探讨搜索引擎的设计和实现。搜索引擎设计的主要关注点之一是处理文本数据。搜索引擎不能只存储所有网站并对用户的查询返回第一个匹配项。自然语言处理中有许多复杂的任务。假设我们正在设计一个程序，该程序接收文本文档并应输出文档中的句子。识别句子的开始和结束是其中的一个复杂任务。以下句子是一个简单的例子：

```cpp
I love studying C++. It's hard, but interesting. 
```

程序将输出两个句子：

```cpp
I love studying C++.
It's hard, but interesting.
```

在编码任务方面，我们只需搜索句子末尾的 .（句号）字符，并确保第一个单词以大写字母开头。如果其中一句话的形式如下，程序会如何行为？

```cpp
I love studying C++!
```

由于句子末尾有感叹号，我们应该重新审视我们的程序，添加另一个规则来识别句子的结束。如果一句话是这样结束的呢？

```cpp
It's hard, but interesting...
```

逐一引入更多规则和定义，以实现一个完全功能的句子提取器。在解决自然语言处理任务时，利用机器学习将我们引向更智能的方向。

另一个与语言相关的任务是机器翻译，它可以自动将一种语言的文档翻译成另一种语言。此外，需要注意的是，构建一个全面的自然语言处理系统将有益于其他研究领域，比如知识推理。

# 知识推理

知识推理是使计算机以类似于人类的方式思考和推理。想象一下和机器进行对话，开始如下：

```cpp
[Human] Hello
[Machine] Hello
```

我们可以编程让机器回答特定问题或理解用户输入的复杂文本，但要让机器基于以前的经验进行推理就要困难得多。例如，以下推理是研究的目标之一：

```cpp
[Human] I was walking yesterday and it was raining.
[Machine] Nice.
[Human] I should dress warmer next time.
[Machine] OK.
[Human] I think I have a temperature.
[Machine] Did you caught a cold yesterday?
[Human] I guess so.
```

虽然似乎很容易发现感冒和雨之间的联系，但让程序推断这一点需要付出很大的努力。它必须将雨与感冒联系起来，并将有温度与感冒联系起来。它还应该记住先前的输入，以便在智能地保持对话中使用它。

前面提到的所有研究领域对于程序员来说都是令人兴奋的深入领域。最后，机器学习通常是设计算法和模型的基础，用于每个特定应用领域。

# 机器学习

机器学习使我们达到了一个全新的水平，让机器执行任务的方式与人类一样，甚至可能更好。与我们之前介绍的领域相比，机器学习的目标是构建能够在没有具体指令的情况下执行任务的系统。在发明人工智能机器的过程中，我们应该更加关注人类智慧。当一个孩子出生时，并不表现出智能行为，而是开始慢慢熟悉周围的世界。没有记录表明一个月大的婴儿解决微分方程或创作音乐。就像孩子学习和发现世界一样，机器学习关注的是构建直接执行任务的基础模型，而不是直接执行任务，而是学会如何执行任务。这是设置系统执行预定义指令和让系统自行解决问题之间的根本区别。

当一个孩子开始行走、拿东西、说话和提问时，他们正在逐步获取关于世界的知识。他或她拿起一本书，尝试它的味道，不久之后就不再把书当作食物来咀嚼。几年过去了，孩子现在打开书的页面，寻找其中的图像和构成文本的小图形。再过几年，孩子开始阅读它们。多年过去了，大脑变得越来越复杂，它的神经元之间建立了越来越多的连接。孩子变成了一个聪明的人类。

想象一下一个系统，其中有一些神奇的算法和模型。在输入了大量数据之后，它将能够越来越理解，就像孩子通过处理视觉数据（通过他们的眼睛观察）、气味或味道的输入数据来了解世界一样。后来，通过提出问题的方式，孩子开始理解单词，并将这些单词与现实世界中的对象，甚至是无形的概念联系起来。机器学习系统几乎以相同的方式行事。它们处理输入数据并产生一些输出，符合我们期望的结果。下图说明了这个想法：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/e1574aeb-59e5-4890-a1cb-0c31e04315f3.png)

现在让我们深入了解机器学习。和往常一样，理解新事物的最好方法是先尝试实现它。

# 理解机器学习

机器学习是一个庞大的研究领域，正在快速扩展。要理解机器学习，我们首先应该了解学习的本质。思考和推理是使我们——人类——特殊的关键概念。机器学习的核心是使系统学习并利用知识来执行任务。你可能还记得学习编程的第一步。我们相信那并不容易。你必须学习新概念，构建抽象，并让你的大脑理解程序执行的底层原理。之后，你需要使用那些在入门指南中描述的关键字、指令、条件语句、函数、类等小构件来构建复杂系统。

然而，机器学习程序与我们通常创建的程序不同。看一下下面的代码：

```cpp
int calculate()
{
  int a{14};
  int b{27};
  int c{a + b};
  return c;
}
```

简单的前述程序按照我们的指示执行。它包含了几个简单的指令，导致变量`c`表示`a`和`b`的和。我们可以修改函数以接受用户输入，如下所示：

```cpp
int calculate(int a, int b)
{
  int c{a + b};
  return c;
}
```

前述函数永远不会获得任何智能。无论我们调用`calculate()`函数多少次都无所谓。无论我们提供什么数字作为输入都无所谓。该函数代表了一系列指令。我们甚至可以说是一系列硬编码的指令。也就是说，该函数永远不会修改自己的指令以根据输入的不同行为。然而，我们可以引入一些逻辑；比如说，我们让它在收到负数时每次返回 0：

```cpp
int calculate(int a, int b)
{
  if (a < 0 && b < 0) {
    return 0;
  }
  int c{a + b};
  return c;
}
```

条件语句引入了函数基于其输入所做决定的最简单形式。我们可以添加更多的条件语句，使函数增长并具有复杂的实现。然而，无论添加多少条件语句，它都不会变得更聪明，因为它不是代码自己想出来的。这就是我们在处理程序时所面临的限制。它们不会思考；它们会按照我们编程的方式行事。我们决定它们必须如何行事。它们总是服从。嗯，只要我们没有引入错误。

现在，想象一下 ML 算法在行动。假设`calculate()`函数中有一些魔法，以便它根据输入返回一个值。假设它具有以下形式：

```cpp
int calculate(int a, int b)
{
  // some magic
  // return value 
}
```

现在，假设我们正在调用`calculate()`并将`2`和`4`作为参数传递，希望它将计算它们的总和并返回`6`。此外，想象一下，我们可以以某种方式告诉它结果是否符合我们的预期。过了一会儿，函数以一种方式行事，以便它了解如何使用这些输入值并返回它们的总和。我们正在构建的以下类代表了我们对理解 ML 的第一步。

# 设计一个学习的算法

以下类代表一个计算机。它包括四种算术运算，并期望我们提供如何计算输入值的示例：

```cpp
struct Example
{
  int input1;
  int input 2;
  int output;
};

class CalculationMachine
{
public:
  using Examples = std::vector<Example>;
  // pass calculation examples through the setExamples()
 void setExamples(const Examples& examples);

  // the main function of interest
  // returns the result of the calculation
 int calculate(int a, int b);

private:
  // this function pointer will point to 
  // one of the arithmetic functions below
 int (*fptr_)(int, int) = nullptr;

private:
  // set of arithmetic functions
  static int sum(int, int);
  static int subtract(int, int);
  static int multiply(int, int);
  static int divide(int, int);
};
```

在使用`calculate()`函数之前，我们应该为`setExamples()`函数提供一个示例列表。以下是我们提供给`CalculationMachine`的示例的示例：

```cpp
3 4 7
2 2 4
5 5 10
4 5 9
```

每行中的前两个数字代表输入参数；第三个数字是操作的结果。`setExamples()`函数是`CalculationMachine`学习如何使用正确的算术函数。我们可以从前面的例子中猜出正在发生的事情，同样`CalculationMachine`试图找到最适合其操作的方法。它通过示例并定义在调用`calculate()`时应该使用哪个函数。实现方式类似于以下内容：

```cpp
void CalculationMachine::setExamples(const Examples& examples)
{
  int sum_count{0};
  int sub_count{0};
  int mul_count{0};
  int div_count{0};
  for (const auto& example : Examples) {
 if (CalculationMachine.sum(example.input1, example.input2) == example.output) {
 ++sum_count;
 }
 if (CalculationMachine.subtract(example.input1, example.input2) == example.output) {
 ++sub_count;
 }
    // the same for multiply() and divide()
  }

  // the function that has the maximum number of correct output results
  // becomes the main function for called by calculate()
  // fptr_ is assigned the winner arithmetic function
}
```

从前面的例子中可以看出，该函数调用所有算术函数并将它们的返回值与示例输出进行比较。每次结果正确时，它会增加特定函数的正确答案计数。最后，具有最多正确答案的函数被分配给`fptr_`，该函数由`calculate()`函数使用如下：

```cpp
int CalculationMachine::calculate(int a, int b)
{
  // fptr_ points to the sum() function
 return fptr_(a, b);
}
```

我们设计了一个简单的学习算法。`setExamples()`函数可以被重命名为`setDataSet()`或`trainWithExamples()`或类似的名称。`CalculationMachine`的例子的重点在于我们定义了一个模型和算法来处理它，并且我们可以称之为 ML。它从数据中学习。或者，更好的是，它从经验中学习。我们提供给`CalculationMachine`的示例向量中的每个记录都可以被视为一种经验。我们说计算的性能随着经验的增加而提高。也就是说，我们提供的示例越多，它在选择正确的函数执行任务时就越有信心。而任务就是根据两个输入参数计算值。学习过程本身不是任务。学习是导致执行任务的原因。任务通常被描述为系统应该如何处理一个示例，其中一个示例是一组特征。尽管在 ML 术语中，一个示例被表示为一个向量（数学），其中每个条目都是另一个特征，但向量数据结构的选择只是一个巧合。作为系统训练的基本原则之一，ML 算法可以被分类为监督或无监督。让我们检查它们的区别，然后建立 ML 系统的各种应用。

# ML 的分类

以下图表说明了 ML 的分类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/57c4aa6a-343d-43e9-8060-f24d62dee7b3.png)

ML 算法的分类取决于它们在学习过程中的经验类型。我们通常称示例的集合为*数据集*。有些书籍也使用术语*数据点*。数据集基本上是代表对目标系统有用的任何数据的集合。它可能包括一段时间内的天气测量，某家公司或多家公司的股票价格列表，或任何其他数据集。虽然数据集可能是未经处理的或所谓的原始数据，但也有数据集包含每个经验的附加信息。在`CalculationMachine`的示例中，我们使用了一个原始数据集，尽管我们已经编程系统识别前两个值是操作的操作数，第三个值是其结果。如前所述，我们将 ML 算法分类为监督和无监督。

监督学习算法从带标签的数据集中学习；也就是说，每条记录都包含描述数据的附加信息。`CalulcationMachine`是监督学习算法的一个例子。监督学习也被称为**带教练训练**。教练使用数据集来教授系统。 

监督学习算法将能够在从提供的经验中学习后标记新的未知数据。下图最好描述了它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/3c11cb39-8e0b-48ed-af2b-e498f0345c35.png)

监督学习算法的一个应用示例是电子邮件应用中的垃圾邮件过滤器。用户将电子邮件标记为垃圾邮件或非垃圾邮件，然后系统试图在新收到的电子邮件中找到模式以检测潜在的垃圾邮件。

`CalculationMachine`的示例是监督学习的另一个案例。我们用以下数据集来喂它：

```cpp
3 4 7
2 2 4
5 5 10
4 5 9
```

我们编程`CalculationMachine`以读取前两个数字作为输入参数，第三个数字作为应用于输入的函数产生的输出。这样，我们提供了关于系统应该得到什么结果的必要信息。

无监督学习算法更加复杂——它们处理包含大量特征的数据集，然后试图找到特征的有用属性。无监督学习算法大多是独立定义数据集中的内容。就智能而言，无监督学习方法更符合智能生物的描述，而不是监督学习算法。相比之下，监督学习算法试图预测哪些输入值映射到输出值，而无监督算法执行多个操作来发现数据集中的模式。根据前面图表中的关联，下图描述了一个无监督学习算法：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/3957f1b0-47f6-4f5f-9fd7-d789c436e981.png)

无监督学习算法的应用示例包括推荐系统。我们将在下一章中讨论一个例子，设计一个网络搜索引擎。推荐系统分析用户活动以推荐类似的数据，例如电影推荐。

从前面的插图中可以看出，还有*强化学习*。这是一类从错误中学习的算法。学习系统和其经验之间存在反馈循环，因此强化学习算法与环境进行交互。它可能在开始时犯很多错误，经过处理反馈后，纠正自身以改进算法。学习过程成为任务执行的一部分。想象一下，`CalculationMachine`只接收输入数字而不是计算结果。对于每个经验，它将通过应用算术运算之一产生结果，然后接收反馈。假设它减去数字，然后根据反馈修改自身以计算总和。

# ML 的应用

了解机器学习的分类有助于更好地将其应用于各种任务。有许多任务可以通过机器学习来解决。我们已经提到*分类*是机器学习算法解决的任务之一。基本上，分类是过滤和排序输入以指定输入所属的类别的过程。用机器学习解决分类通常意味着它产生一个将输入映射到特定输出的函数。输出类别的概率分布也是一种分类任务。分类任务的最佳示例之一是对象识别。输入是一组像素值（换句话说，是一幅图像），输出是标识图像中物体的值。想象一下一个能够识别不同种类的工具并在命令下将它们交给工人的机器人；也就是说，一个在车库里工作的机械师有一个能够识别螺丝刀并在命令下将其带来的助手机器人。

更具挑战性的是具有缺失输入的分类。在前面的例子中，这类似于要求机器人带来螺丝钉的东西。当一些输入缺失时，学习算法必须使用多个函数来实现成功的结果。例如，助手机器人可能首先带来钳子，然后找到螺丝刀作为正确的解决方案。

与分类类似的是*回归*，在这种情况下，系统被要求根据提供的一些输入来预测一个数值。不同之处在于输出的格式。回归任务的一个例子是预测股票未来价格。这些以及其他机器学习的应用使其迅速成为一个研究领域。学习算法不仅仅是一系列条件语句，尽管一开始可能感觉是这样。它们是基于更全面的构造，模仿人脑神经元及其连接而建模的。这将我们带到下一节，即**人工神经网络**（**ANNs**）的研究。

# 神经网络

神经网络被设计用于识别模式。它们是模仿人脑的；更具体地说，我们谈论的是大脑神经元及其人工对应物——人工神经元。人类大脑中的神经元在下图中有所说明：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2ae9ed94-046b-41d3-b973-d49240e60d96.png)

神经元通过*突触*与其他神经元进行通信。神经元的基本功能是处理部分数据并根据该数据产生信号。在编程术语中，神经元接受一组输入并产生输出。

这就是为什么下面的图表清楚地说明了为什么人工神经元类似于人脑神经元结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/c5ab77e8-d399-4ea8-8266-87af81434f8b.png)

ANN 是自然神经网络的一个简化模型。它代表了一组相互连接的节点，每个节点代表一个神经元模型。每个节点连接可以传输类似于生物大脑神经元中突触的信号。神经网络是一组帮助进行聚类和分类的算法。正如您从前面的图表中看到的，神经网络由三层组成：

+   输入层

+   隐藏层

+   输出层

输入层和输出层不言自明；初始输入是外部数据，例如图像、音频或文本文件。输出是任务的完成，例如对文本内容的分类或图像中识别的对象。隐藏层是使网络产生合理结果的关键。输入到输出的转换经过隐藏层，隐藏层进行了必要的分析、处理和修改以产生输出。

考虑前面的图表；它显示一个神经元可以有多个输入和输出连接。通常，每个连接都有一个权重，指定连接的重要性。前面图表中的分层告诉我们，每一层的神经元都连接到紧邻的前一层和后一层的神经元。您应该注意，输入和输出层之间可能有几个隐藏层。虽然输入和输出层的主要目的是读取外部数据并返回计算（或推断）的输出，但隐藏层的目的是通过学习来适应。学习还涉及调整连接和权重，以提高输出的准确性。这就是机器学习发挥作用的地方。因此，如果我们创建一个复杂的神经网络，其中包含几个隐藏层，准备学习和改进，我们就得到了一个人工智能系统。例如，让我们先来研究聚类问题，然后再进行回归分析。

# 聚类

聚类涉及将一组对象分组以将它们分布在相似对象的组中。也称为**聚类分析**，它是一组旨在将相似对象分组在一起的技术和算法。最简单的说明是将一组有颜色的对象分成不同的组，每组由相同颜色的对象组成，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/3ef57b1e-05f2-4d19-a942-b7d6b85c8d95.png)

虽然我们在本章讨论 AI 任务，但我们建议您首先尝试用到目前为止所掌握的知识库来解决问题。也就是说，让我们想一想如何通过相似性对对象进行分类。首先，我们应该对对象的外观有一个基本的概念。在前面的例子中，一个对象的表示可能是这样的：`形状`，`颜色`，尺寸（2D 对象的`宽度`和`高度`），等等。不深入探讨，基本对象表示可能是这样的：

```cpp
struct Object
{
  int color;
  int shape;
  int width;
  int height;
};
```

让我们考虑颜色和形状的值在一定范围内的事实。我们可以使用枚举来提高可读性。聚类分析涉及分析对象以某种方式对其进行分类。首先想到的是有一个接受对象列表的函数。让我们试着定义一个：

```cpp
using objects_list = std::vector<Object>;
using categorized_table = std::unordered_map<int, objects_list>;
categorized_table clusterize(const objects_list& objects)
{
  // categorization logic 
}
```

想一想实现细节。我们需要定义聚类点。它可能是颜色，也可能是形状的类型。具有挑战性的是，它可能是未知的。也就是说，为了以防万一，我们对每个属性的对象进行分类如下：

```cpp
categorized_table clusterize(const objects_list& objects)
{
  categorized_table result;
  for (const auto& obj : objects) {
    result[obj.color].push_back(obj);
    result[obj.shape].push_back(obj);
  }
  return result;
}
```

具有相似颜色或形状的对象被分组在一个哈希表中。虽然前面的代码相当简单，但它包含了按某种相似性标准对对象进行分组的基本思想。在前面的例子中，我们更可能将其描述为硬聚类。一个对象要么属于一个簇，要么不属于。相反，软聚类（也称为模糊聚类）描述了对象对某个簇的归属程度。

例如，形状属性的对象相似性可以由应用于对象的函数的结果来定义。也就是说，如果对象 A 的形状是正方形，对象 B 的形状是菱形，那么函数定义了对象 A 和对象 B 是否具有相似的形状。这意味着我们应该更新前面例子中的逻辑，以便根据几个值来比较对象并定义它们的形状为一组。通过进一步发展这个想法，我们迟早会到达不同的聚类策略和算法，比如 K 均值聚类。

# 回归分析

回归分析涉及找出一个值对另一个值的偏差。理解回归分析的最简单方法是通过数学函数的图表。您可能还记得函数 f(x) = y 的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/378390fd-c0b2-4a73-86ea-cc2108a8afa0.png)

对于每个`x`的值，函数都会得出一个固定的`y`值。回归分析与前面的图表有些相似，因为它涉及查找变量之间的关系。更具体地说，它估计因变量和几个自变量之间的关系。因变量也被称为**结果**，而自变量也被称为**特征**。特征的数量可能是一个。

最常见的回归分析形式是线性回归。它看起来与前面的图表相似。以下是一个例子，表示测试程序所花费的时间与发布版本中发现的错误数量之间的关系：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/85954804-fb7b-4621-8295-dd72845621b6.png)

有两种类型的回归：负回归是前面图表中显示的一种，因为自变量的值减少而因变量增加。相反，正回归具有自变量增加的值。

机器学习中的回归分析被用作一种预测的方式。你可能会开发一个程序，根据自变量的数值来预测结果。正如你到目前为止已经猜到的那样，机器学习是一个涵盖广泛主题的大领域。尽管程序员倾向于尽可能少地使用数学，但在机器学习中却是不可能的。你仍然需要掌握一些数学知识，以充分利用机器学习。回归分析在很大程度上依赖于数学统计。

# C++和机器学习

现在已经不再是秘密，机器学习更多地涉及数学而不是编程。计算机科学的根源在数学中，在早期，计算机科学家首先是数学家。你可能熟悉一些杰出的科学家，包括艾伦·图灵、约翰·冯·诺伊曼、克劳德·香农、诺伯特·维纳、尼古劳斯·维尔特、唐纳德·克努斯等。他们都是数学家，对技术有着特殊的热爱。在其发展过程中，计算机编程成为了一个更加友好的领域，对新手更加友好。在过去的二三十年里，计算机程序员不再被迫在开发有用的程序之前学习数学。编程语言演变成了越来越高级的工具，几乎每个人都可以编写代码。

有很多框架可以让程序员的工作更轻松。现在只需要几周的时间就可以掌握一些框架或高级编程语言，并创建一个新的程序。然而，程序往往会重复自己。现在构建一些东西并不那么困难，因为有很多模式和最佳实践可以帮助我们。数学的作用已经被推到了后台，越来越多的人成为程序员，甚至根本不需要使用数学。这实际上并不是一个问题；这更像是技术发展的自然流动。最终，技术的目标是让人类生活更加舒适。工程师也是如此。然而，在 20 世纪 60 年代，NASA 的工程师使用计算机进行计算，但那时的计算机并非我们今天所知的计算机。那些都是真正的人类，拥有一种特殊的专业称为“计算机”，尽管成为计算机意味着在数学上非常出色，比其他人更快地解决方程。

现在我们是计算机科学的新时代的一部分，数学再次回归。机器学习工程师现在使用数学的方式，就像数学家在 20 世纪 70 年代或 80 年代使用编程语言一样。现在仅仅知道一种编程语言或一个框架已经不够了，要设计一个新的算法或将机器学习应用到你的应用程序中，你还应该至少在一些数学子领域表现出色，比如线性代数、统计学和概率论。

几乎相同的逻辑也适用于 C++。现代语言提供了广泛的功能，而 C++开发人员仍在努力设计具有手动内存管理的无缺陷程序。如果您对 ML 领域进行一些快速研究，您会发现大多数库或示例都在使用 Python。起初，这可能被视为在 ML 任务中使用的默认语言。然而，ML 工程师开始触及一个新的进化阈值——性能。这个阈值并不新鲜；许多工具仍在需要性能的部分使用 C++。游戏开发、操作系统、关键任务系统以及许多其他基本领域都在使用 C++（和 C）作为*事实*标准。现在是 C++征服新领域的时候了。我们对读者的最好建议是学习 ML 和 C++，因为将 C++纳入其中对于 ML 工程师来说慢慢变得至关重要，以获得最佳性能。

# 总结

我们介绍了 ML 及其类别和应用。这是一个快速增长的研究领域，在构建智能系统方面有着众多应用。我们将 ML 分类为监督、无监督和强化学习算法。每个类别都在解决分类、聚类、回归和机器翻译等任务中有应用。

我们实现了一个简单的学习算法，它根据提供的经验定义了一个计算函数。我们称之为我们用来训练系统的数据集。使用数据集（称为**经验**）进行训练是 ML 系统中的关键属性之一。

最后，我们介绍并讨论了应用于识别模式的人工神经网络。ML 和神经网络在解决任务时息息相关。本章为您提供了领域的必要介绍以及几个任务的示例，以便您花一些时间深入了解该主题。这将帮助您对 AI 和 ML 有一个大致的了解，因为在实际应用开发中，对工程师来说这变得越来越必要。在下一章中，我们将学习如何实现基于对话的搜索引擎。

# 问题

1.  什么是 ML？

1.  监督学习和无监督学习算法之间有什么区别？

1.  给出一些 ML 应用的例子。

1.  你会如何修改`CalculationMachine`类以在用不同的经验集训练后改变其行为？

1.  神经网络的目的是什么？

# 进一步阅读

+   *人工智能和机器学习基础*，网址为[`www.packtpub.com/big-data-and-business-intelligence/artificial-intelligence-and-machine-learning-fundamentals`](https://www.packtpub.com/big-data-and-business-intelligence/artificial-intelligence-and-machine-learning-fundamentals)

+   *机器学习基础*，网址为[`www.packtpub.com/big-data-and-business-intelligence/machine-learning-fundamentals`](https://www.packtpub.com/big-data-and-business-intelligence/machine-learning-fundamentals)

+   *算法交易的实践机器学习*，网址为[`www.packtpub.com/big-data-and-business-intelligence/hands-machine-learning-algorithmic-trading`](https://www.packtpub.com/big-data-and-business-intelligence/hands-machine-learning-algorithmic-trading)


# 第十六章：实现基于对话框的搜索引擎

在这本书中，我们已经走了这么远！我们已经学习了 C++应用程序开发的基础知识，并讨论了构建和设计面向全球的应用程序。我们还深入研究了数据结构和算法，这是高效编程的核心。现在是时候利用所有这些技能来设计复杂的软件，比如搜索引擎了。

随着互联网的普及，搜索引擎已成为最受欢迎的产品。大多数用户从搜索引擎开始他们的网络之旅。各种网络搜索服务，如 Google、Baidu、Yandex 等，每天接收大量的流量，处理数万亿的请求。搜索引擎在不到一秒的时间内处理每个请求。尽管它们维护了成千上万的服务器来处理负载，但它们高效处理的核心是数据结构和算法、数据架构策略和缓存。

设计高效搜索系统的问题不仅出现在网络搜索引擎中。本地数据库、**客户关系管理**（**CRM**）系统、会计软件等都需要强大的搜索功能。在本章中，我们将了解搜索引擎的基础知识，并讨论用于构建快速搜索引擎的算法和数据结构。您将了解网络搜索引擎的一般工作原理，并了解需要高处理能力的项目中使用的新数据结构。您还将建立信心，去构建自己的搜索引擎，与现有的搜索引擎竞争。

在本章中，我们将涵盖以下主题：

+   理解搜索引擎的结构

+   理解和设计用于在搜索引擎中将关键词映射到文档的倒排索引

+   为搜索平台的用户设计和构建推荐引擎

+   使用知识图谱设计基于对话框的搜索引擎

# 技术要求

本章中使用`g++`编译器和`-std=c++2a`选项来编译示例。您可以在[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)找到本章中使用的源文件。

# 理解搜索引擎的结构

想象一下世界上数十亿的网页。在搜索引擎界面中输入一个单词或短语，不到一秒钟就会返回一个长长的结果列表。搜索引擎如此快速地处理如此多的网页，这是奇迹般的。它是如何如此快速地找到正确的文档的呢？为了回答这个问题，我们将做程序员可以做的最明智的事情，设计我们自己的引擎。

以下图表显示了搜索引擎背后的基本思想：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/e863777e-e6a1-428a-9543-34793e6ebfc4.png)

**用户**使用搜索引擎的**用户界面**输入单词。**搜索引擎**扫描所有文档，对其进行过滤，按相关性对其进行排序，并尽快向用户做出响应。我们主要关注的是网络搜索引擎的实现。寻找某物需要在数十亿的文档中进行搜索。

让我们试着想出一种方法来从数十亿的文档中找到短语“Hello, world!”（为了简洁起见，我们将网页称为文档）。扫描每个文档以查找该短语将需要大量的时间。如果我们认为每个文档至少有 500 个单词，搜索特定单词或单词组合将需要很长时间。更实际的方法是事先扫描所有文档。这个扫描过程包括在文档中建立每个单词出现的索引，并将信息存储在数据库中，这也被称为**文档索引**。当用户输入一个短语时，搜索引擎将在其数据库中查找这些单词，并返回满足查询的文档链接。

在搜索文档之前，引擎验证用户输入并不会有害。用户在短语中出现拼写错误并不罕见。除了拼写错误，如果引擎自动完成单词和短语，用户体验会更好。例如，当用户输入“hello”时，引擎可能建议搜索短语“Hello, world!”。一些搜索引擎跟踪用户，存储有关其最近搜索、请求设备的详细信息等信息。例如，如果用户搜索“如何重新启动计算机”，如果搜索引擎知道用户的操作系统，结果会更好。如果是 Linux 发行版，搜索引擎将对搜索结果进行排序，使描述如何重新启动基于 Linux 的计算机的文档首先出现。

我们还应该注意定期出现在网络上的新文档。后台作业可能会持续分析网络以查找新内容。我们称这个作业为**爬虫**，因为它爬行网络并索引文档。爬虫下载文档以解析其内容并构建索引。已经索引的文档可能会得到更新，或者更糟的是被删除。因此，另一个后台作业应定期更新现有文档。您可能会遇到爬行网络以解析文档的任务术语**蜘蛛**。

下面更新的图表更详细地说明了搜索引擎的结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/80b2e7a9-acbb-4672-a83c-d3bce75bde7c.png)

搜索具有广泛的应用。想象一下最简单的搜索形式——在数组中查找一个单词：

```cpp
using words = std::vector<std::string>;
words list = get_list_of_words(); // suppose the function is implemented

auto find_in_words(const std::string& term)
{
  return std::find(list.begin(), list.end(), term);
}
```

尽管前面的例子适用于最简单的搜索引擎，但真正的问题是设计一个可扩展的搜索引擎。您不希望通过搜索字符串数组来处理用户请求。相反，您应该努力实现一个能够搜索数百万个文档的可扩展搜索引擎。这需要大量的思考和设计，因为一切都很重要，从正确选择的数据结构到高效的数据处理算法。现在让我们更详细地讨论搜索引擎的组件。我们将整合从之前章节学到的所有技能来设计一个好的搜索引擎。

# 提供方便的用户界面

在构建提供令人惊叹的用户体验的细粒度用户界面上投入时间和资源至关重要。关键在于简单。界面越简单，使用起来就越好。我们将以市场主导地位的 Google 为例。它在页面中央有一个简单的输入字段。用户在字段中输入请求，引擎会建议一些短语：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/51e853fb-bc2e-4002-b368-fbd3e49d7057.png)

我们不认为用户是懒惰的人，但提供建议列表是有帮助的，因为有时用户不知道他们正在寻找的确切术语。让我们集中精力在建议列表的结构和实施上。毕竟，我们对解决问题感兴趣，而不是设计漂亮的用户界面。我们不会在本章讨论用户界面设计；更好的是集中在搜索引擎的后端。然而，在继续之前，有一件事情我们应该考虑。我们正在实现的搜索引擎是基于对话的。用户查询引擎并可以从几个答案中选择以缩小结果列表。例如，假设用户查询“一台电脑”，搜索引擎会问“台式机还是笔记本？”。这会大大减少搜索结果并为用户提供更好的结果。我们将使用决策树来实现这一点。但在此之前，让我们了解搜索引擎的复杂性。

首先，存在**输入标记化**的问题。这涉及文档解析和搜索短语分析。您可能构建了一个很好的查询解析器，但由于用户在查询中犯了一个错误，它就会出现问题。让我们来看看处理模糊查询的一些方法。

# 处理查询中的拼写错误

用户在输入时犯错并非罕见。虽然这似乎是一件简单的事情，但对于搜索引擎设计者来说可能会是一个真正的问题。如果用户输入了 helo worl 而不是 hello world，那么在数百万份文档中进行搜索可能会产生意外的错误结果。你可能熟悉搜索引擎提供的自动建议。例如，当我们输入错误时，谷歌搜索界面是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/3885d527-3de0-4b25-946d-c20714d9eb89.png)

注意屏幕截图底部的两行。其中一行显示了 hello world 的搜索结果，这表明搜索引擎假定用户输入的查询存在拼写错误，并主动显示了正确查询的结果。然而，仍然有可能用户确实想要搜索他们输入的确切单词。因此，用户体验提供了下一行，即搜索 helo worl 的结果。

因此，在构建搜索引擎时，我们需要解决几个问题，首先是用户请求。首先，我们需要为用户提供一个方便的界面来输入他们的文本。界面还应该与用户进行交互，以提供更好的结果。这包括根据部分输入的单词提供建议，就像之前讨论的那样。使搜索引擎与用户进行交互是用户界面的另一个改进，我们将在本章中讨论。

接下来是检查拼写错误或不完整单词，这并不是一件容易的事。保留字典中所有单词的列表并比较用户输入的单词可能需要一段时间。为了解决这个问题，必须使用特定的数据结构和算法。例如，在检查用户查询中的拼写错误时，找到单词之间的**Levenshtein 距离**可能会有所帮助。Levenshtein 距离是一个单词需要添加、删除或替换的字符数，使其等于另一个单词。例如，*world*和*worl*之间的 Levenshtein 距离是 1，因为从*world*中删除字母*d*或在*worl*中添加*d*可以使这些单词相等。*coding*和*sitting*之间的距离是 4，因为以下四次编辑将一个单词变成另一个单词：

1.  coding -> cod**t**ing（在中间插入**t**）

1.  co**d**ting -> co**t**ting（将**t**替换为**d**）

1.  c**o**tting -> c**i**tting（将**o**替换为**i**）

1.  **c**itting -> **s**itting（将**c**替换为**s**）

现在，想象一下，如果我们要将每个用户输入与成千上万个单词进行比较以找到最接近的单词，处理将需要多长时间。另一种方法是使用一个大的**trie**（数据结构）来预先发现可能的拼写错误。Trie 是一个有序搜索树，其中键是字符串。看一下下面表示 trie 的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/296999a5-2bd6-4b40-bc87-9fdf30532cc2.png)

每条路径代表一个有效的单词。例如，a 节点指向 n 和 r 节点。注意 n 后面的#。它告诉我们，直到这个节点的路径代表一个单词，an。然而，它继续指向 d，然后是另一个#，意味着直到这个节点的路径代表另一个单词，and。对于 trie 的其余部分也适用相同的逻辑。例如，想象一下*world*的 trie 部分：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/d174ec96-3f73-441a-8f25-6ebd22d5038a.png)

当引擎遇到*worl*时，它会通过前面的 trie。w 没问题，o 也没问题，直到单词的倒数第二个字符 l 之前的所有字符都没问题。在前面的图表中，l 后面没有终端节点，只有 d。这意味着我们可以确定没有*worl*这样的单词；所以它可能是*world*。为了提供良好的建议和检查拼写错误，我们应该有用户语言的完整词典。当你计划支持多种语言时，情况会变得更加困难。然而，尽管收集和存储词典可以说是一项简单的任务，更困难的任务是收集所有网页文档并相应地存储以进行快速搜索。搜索引擎收集和解析网站以构建搜索引擎数据库的工具、程序或模块（如前所述）称为爬虫。在更深入地研究我们将如何存储这些网页之前，让我们快速看一下爬虫的功能。

# 爬取网站

每次用户输入查询时搜索数百万个文档是不现实的。想象一下，当用户在系统的 UI 上点击搜索按钮后，搜索引擎解析网站以搜索用户查询。这将永远无法完成。搜索引擎从网站发送的每个请求都需要一些时间。即使时间少于一毫秒（0.001 秒），在用户等待查询完成的同时分析和解析所有网站将需要很长时间。假设访问和搜索一个网站大约需要 0.5 毫秒（即使如此，这也是不合理的快）。这意味着搜索 100 万个网站将需要大约 8 分钟。现在想象一下你打开谷歌搜索并进行查询，你会等待 8 分钟吗？

正确的方法是将所有信息高效地存储在数据库中，以便搜索引擎快速访问。爬虫下载网页并将它们存储为临时文档，直到解析和索引完成。复杂的爬虫可能还会解析文档，以便更方便地存储。重要的一点是，下载网页不是一次性的行为。网页的内容可能会更新。此外，在此期间可能会出现新页面。因此，搜索引擎必须保持其数据库的最新状态。为了实现这一点，它安排爬虫定期下载页面。智能的爬虫可能会在将内容传递给索引器之前比较内容的差异。

通常，爬虫作为多线程应用程序运行。开发人员应该尽可能快地进行爬取，因为保持数十亿个文档的最新状态并不是一件容易的事。正如我们已经提到的，搜索引擎不直接搜索文档。它在所谓的索引文件中进行搜索。虽然爬取是一个有趣的编码任务，但在本章中我们将主要集中在索引上。下一节介绍搜索引擎中的索引功能。

# 索引文档

搜索引擎的关键功能是索引。以下图表显示了爬虫下载的文档如何被处理以构建索引文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/17ba8dc9-5ed9-428a-8b09-0db88bbcb4d4.png)

在前面的图表中，索引显示为**倒排索引**。正如你所看到的，用户查询被引导到倒排索引。虽然在本章中我们在**索引**和**倒排索引**这两个术语之间交替使用，但**倒排索引**是更准确的名称。首先，让我们看看搜索引擎的索引是什么。索引文档的整个目的是提供快速的搜索功能。其思想很简单：每次爬虫下载文档时，搜索引擎会处理其内容，将其分成指向该文档的单词。这个过程称为**标记化**。假设我们从维基百科下载了一个包含以下文本的文档（为了简洁起见，我们只列出了段落的一部分作为示例）：

```cpp
In 1979, Bjarne Stroustrup, a Danish computer scientist, began work on "C with Classes", the predecessor to C++. The motivation for creating a new language originated from Stroustrup's experience in programming for his PhD thesis. Stroustrup found that Simula had features that were very helpful for large software development...
```

搜索引擎将前面的文档分成单独的单词，如下所示（出于简洁起见，这里只显示了前几个单词）：

```cpp
In
1979
Bjarne
Stroustrup
a
Danish
computer
scientist
began
work
...
```

将文档分成单词后，引擎为文档中的每个单词分配一个**标识符**（**ID**）。假设前面文档的 ID 是 1，下表显示了单词指向（出现在）ID 为 1 的文档： 

| In | 1 |
| --- | --- |
| 1979 | 1 |
| Bjarne | 1 |
| Stroustrup | 1 |
| a | 1 |
| Danish | 1 |
| computer | 1 |
| scientist | 1 |
| ... |  |

可能有几个文档包含相同的单词，因此前表实际上可能看起来更像以下表：

| In | 1, 4, 14, 22 |
| --- | --- |
| 1979 | 1, 99, 455 |
| Bjarne | 1, 202, 1314 |
| Stroustrup | 1, 1314 |
| a | 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ... |
| Danish | 1, 99, 102, 103 |
| 计算机 | 1, 4, 5, 6, 24, 38, ... |
| scientist | 1, 38, 101, 3958, ... |

下表表示了倒排索引。它将单词与爬虫下载的文档的 ID 进行了映射。现在，当用户通过键入*computer*查询引擎时，结果是基于从索引中检索到的 ID 生成的，即在前面的示例中是 1, 4, 5, 6, 24, 38, ...。索引还有助于找到更复杂查询的结果。例如，*计算机科学家*匹配以下文档：

| computer | **1**, 4, 5, 6, 24, **38**, ... |
| --- | --- |
| scientist | **1**, **38**, 101, 3958, ... |

为了回应用户并提供包含两个术语的文档，我们应该找到引用文档的交集（参见前表中的粗体数字），例如，1 和 38。

请注意，用户查询在与索引匹配之前也会被标记化。标记化通常涉及单词规范化。如果没有规范化，*计算机科学家*查询将不会返回任何结果（请注意查询中的大写字母）。让我们更多地了解一下这个。

# 标记化文档

你可能还记得第一章中的标记化概念，*构建 C++应用程序*，我们讨论了编译器如何通过将源文件标记化为更小的、不可分割的单元（称为标记）来解析源文件。搜索引擎以类似的方式解析和标记化文档。

我们不会详细讨论这个，但你应该考虑文档是以一种方式处理的，这意味着标记（在搜索引擎上下文中具有意义的不可分割的术语）是规范化的。例如，我们正在查看的所有单词都是小写的。因此，索引表应该如下所示：

| in | 1, 4, 14, 22 |
| --- | --- |
| 1979 | 1, 99, 455 |
| bjarne | 1, 202, 1314 |
| stroustrup | 1, 1314 |
| a | 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ... |
| danish | 1, 99, 102, 103 |
| computer | 1, 4, 5, 6, 24, 38, ... |
| scientist | 1, 38, 101, 3958, ... |

作为 C++程序员，看到 bjarne 或 stroustrup 变成小写可能会让您感到不舒服。然而，由于我们正在将用户输入与倒排索引键进行匹配，我们应该考虑用户输入可能不具有我们期望的形式。因此，我们需要对用户输入应用相同的规则，以使其与倒排索引的形式匹配。

接下来，注意 a。毫不夸张地说，这是每个文档中都出现的一个词。其他类似的例子是*the*，*an*，*in*等词。我们称它们为**停用词**；它们在实际处理之前被过滤掉。通常，搜索引擎会忽略它们，因此倒排索引更新为以下形式：

| 1979 | 1, 99, 455 |
| --- | --- |
| bjarne | 1, 202, 1314 |
| stroustrup | 1, 1314 |
| danish | 1, 99, 102, 103 |
| computer | 1, 4, 5, 6, 24, 38, ... |
| scientist | 1, 38, 101, 3958, ... |

您应该注意，规范化不仅仅是将单词变成小写。它还涉及将单词转换为它们的正常形式。

将单词规范化为其根形式（或其词干）也称为**词干提取**。

看一下我们在本节开头使用的文档中的以下句子：

```cpp
The motivation for creating a new language originated from Stroustrup's experience in programming for his PhD thesis.
```

creating，originated 和 Stroustrup's 已经被规范化，因此倒排索引将具有以下形式：

| motivation | 1 |
| --- | --- |
| **create** | 1 |
| new | 1 |
| language | 1 |
| **originate** | 1 |
| **stroustrup** | 1 |
| experience | 1 |
| programming | 1 |
| phd | 1 |
| thesis | 1 |

还要注意，我们已经忽略了停用词，并且在前面的表中没有包括*the*。

标记化是索引创建的第一步。除此之外，我们可以以任何使搜索更好的方式处理输入，如下一节所示。

# 对结果进行排序

相关性是搜索引擎最重要的特性之一。仅仅返回与用户输入匹配的文档是不够的。我们应该以一种方式对它们进行排名，以便最相关的文档首先出现。

一种策略是记录文档中每个单词的出现次数。例如，描述计算机的文档可能包含单词*computer*的多次出现，如果用户搜索*a computer*，结果将显示包含最多*computer*出现次数的文档。以下是一个示例索引表：

| computer | 1{18}, 4{13}, 899{3} |
| --- | --- |
| map | 4{9}, 1342{4}, 1343{2} |
| world | 12{1} |

花括号中的值定义了文档中每个单词的出现次数。

当向用户呈现搜索结果时，我们可以考虑许多因素。一些搜索引擎会存储与用户相关的信息，以便返回个性化的结果。甚至用户用于访问搜索引擎的程序（通常是网络浏览器）也可能改变搜索平台的结果。例如，Linux 操作系统上搜索*重新安装操作系统*的用户会得到包含*重新安装 Ubuntu*的结果，因为浏览器提供了操作系统类型和版本信息。然而，考虑到隐私问题，有些搜索引擎完全消除了个性化用户数据的使用。

文档的另一个属性是更新日期。新鲜内容始终具有更高的优先级。因此，当向用户返回文档列表时，我们可能还会按其内容更新的顺序重新排列它们。对文档的相关排名的担忧将我们带到下一节，我们将在那里讨论推荐引擎。

# 构建推荐引擎

我们在上一章介绍了**人工智能**（**AI**）和**机器学习**（**ML**）。推荐引擎可以被视为一个 AI 驱动的解决方案，或者一个简单的条件语句集合。构建一个接收用户数据并返回最满足该输入的选项的系统是一个复杂的任务。将 ML 纳入这样的任务中可能听起来相当合理。

然而，你应该考虑到推荐引擎可能包括一系列规则，这些规则在输出给最终用户之前对数据进行处理。推荐引擎可以在预期和意想不到的地方运行。例如，在亚马逊浏览产品时，推荐引擎会根据我们当前查看的产品向我们推荐产品。电影数据库会根据我们之前观看或评分的电影向我们推荐新电影。对许多人来说，这可能看起来出乎意料，但推荐引擎也在搜索引擎背后运行。

你可能熟悉一些电子商务平台推荐产品的方式。大多数情况下，建议窗格的标题类似于“购买此产品的顾客还购买了...”。回想一下我们在上一章介绍的聚类分析。现在，如果我们试图了解这些建议是如何工作的，我们可能会发现一些聚类算法。

让我们简单地看一下并设想一些推荐机制。比如，一个书店网站。约翰买了一本名为“掌握 Qt5”的书，那么我们可以把这个信息放在表格中：

| | 掌握 Qt5 |
| --- | --- |
| 约翰 | 是 |

接下来，约翰决定购买一本 C++书籍，*掌握 C++编程*。莱娅购买了一本名为*设计模式*的书。卡尔购买了三本书，名为*学习 Python*、*掌握机器学习*和*Python 机器学习*。表格被更新，现在看起来是这样的：

| | 掌握 Qt5 | 掌握 C++编程 | 设计模式 | 学习 Python | 掌握机器学习 | Python 机器学习 |
| --- | --- | --- | --- | --- | --- | --- |
| 约翰 | 是 | 是 | 否 | 否 | 否 | 否 |
| 莱娅 | 否 | 否 | 是 | 否 | 否 | 否 |
| 卡尔 | 否 | 否 | 否 | 是 | 是 | 是 |

现在，让我们想象哈鲁特访问网站并购买了之前列出的两本书，*学习 Python*和*Python 机器学习*。向他推荐书籍*掌握 Qt5*是否合理？我们认为不合理。但我们知道他购买了哪些书，我们也知道另一个用户卡尔购买了三本书，其中两本与哈鲁特购买的书相同。因此，向哈鲁特推荐*掌握机器学习*可能是合理的，告诉他购买这两本书的其他顾客也购买了这本书。这是推荐引擎从高层次的工作原理的一个简单例子。 

# 使用知识图谱

现在，让我们回到我们的搜索引擎。用户正在搜索一位著名的计算机科学家——比如，唐纳德·克努斯。他们在搜索框中输入这个名字，然后从整个网络中得到排序后的最佳结果。再次看看谷歌搜索。为了充分利用用户界面，谷歌向我们展示了一些关于搜索主题的简要信息。在这种情况下，它在网页右侧显示了这位伟大科学家的几张图片和一些关于他的信息。这个部分看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/703e4005-d07b-4044-8fdd-c249be7de3e0.png)

这种方式，搜索引擎试图满足用户的基本需求，让他们能够更快地找到信息，甚至无需访问任何网站。在这种情况下，我们最感兴趣的是放置在前面信息框下面的建议框。它的标题是“人们还搜索”，看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/97e5ef3e-1898-47e4-8368-92a7fcba26c5.png)

这些是基于搜索 Donald Knuth 后搜索 Alan Turing 的用户活动的推荐。这促使推荐引擎提出建议，即如果有人新搜索 Donald Knuth，他们可能也对 Alan Turing 感兴趣。

我们可以通过谷歌称之为**知识图谱**的东西来组织类似的建议机制。这是一个由节点组成的图，每个节点代表一些可搜索的主题、人物、电影或其他任何东西。图数据结构是一组节点和连接这些节点的边，就像以下图表中的那样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/45cb1241-4a3d-44db-9fde-8bb9a30d3c84.png)

在知识图谱中，每个节点代表一个单一实体。所谓实体，我们指的是城市、人、宠物、书籍，或者几乎你能想象到的任何其他东西。现在，图中的边代表实体之间的连接。每个节点可以通过多个节点连接到另一个节点。例如，看看这两个节点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/ca796132-cf5f-4ed1-b8f0-f703724ac5f5.png)

这两个节点只包含文本。我们可能猜测 Donald Knuth 是一个名字，而《计算机程序设计艺术》是某种艺术。建立知识图谱的本质是我们可以将每个节点与代表其类型的另一个节点相关联。以下图表扩展了之前的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/5e6932f4-bec8-455f-8dd5-f15a92aa7946.png)

看看我们添加的两个新节点。其中一个代表一个**人**，而另一个代表一本**书**。更令人兴奋的是，我们将 Donald Knuth 节点与**人**节点连接，并标记为 is a 关系。同样，我们将**《计算机程序设计艺术》**节点连接到书籍节点，因此我们可以说《计算机程序设计艺术》是一本书。现在让我们将 Donald Knuth 与他写的书连接起来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/e68dfd54-f84d-4ee7-89ef-5c187ee45498.png)

所以，现在我们有了一个完整的关系，因为我们知道 Donald Knuth 是一位作者《计算机程序设计艺术》的人，而这本书又代表一本书。

让我们再添加几个代表人的节点。以下图表显示了我们如何添加了 Alan Turing 和 Peter Weyland 节点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/d433010e-be15-41f9-9669-d36aefa0590e.png)

所以，Alan Turing 和 Peter Weyland 都是人。现在，如果这是搜索引擎知识库的一部分，那么它给了我们对用户搜索意图的很好洞察。当我们点击 Donald Knuth 的结果时，我们知道这是关于一个人的。如果需要，我们可以建议用户查看我们在知识图谱中积累的其他人。是否合理建议搜索 Donald Knuth 的用户也查看 Alan Turing 和 Peter Weyland 的页面？这里就有棘手的部分：尽管两者都是人，它们之间并没有强烈的联系。因此，我们需要一些额外的东西来定义两个不同人之间连接的相关性。看看图表的以下添加：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/9d8c7081-485a-487e-9692-9f9e43c47eb0.png)

现在清楚了，Donald Knuth 和 Alan Turing 共享相同的活动，被表示为“计算机科学”节点，代表了一门研究领域，而 Peter Weyland 原来是一个虚构的角色。所以，Peter Weyland 和 Donald Knuth 相关的唯一一件事就是他们都是人。看一下我们放在从人节点到计算机科学节点的边上的数字。假设我们将关系评分从 0 到 100，后者表示关系最强。所以，我们为 Alan Turing 和 Donald Knuth 都放了 99。我们本应该省略从 Peter Weyland 到计算机科学的边，而不是放 0，但我们故意这样做来显示对比。这些数字是权重。我们给边添加权重以强调连接因素；也就是说，Alan Turing 和 Donald Knuth 共享相同的事物，并且彼此之间关系密切。如果我们将 Steve Jobs 作为知识图中的一个新人物，图将会是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/39e8ff27-3843-4762-b607-d5af7f171c25.png)

看一下边的权重。Steve Jobs 与计算机科学有一定关系，但他更多地与“商人”和“影响者”节点相关。同样，我们现在可以看到 Peter Weyland 与 Steve Jobs 的关系比与 Donald Knuth 的关系更密切。现在，对于推荐引擎来说，建议搜索 Donald Knuth 的用户也应该看看 Alan Turing 更具信息量，因为他们都是人，并且与计算机科学的关系权重相等或接近相等。这是一个很好的例子，展示了如何在搜索引擎中整合这样的图。我们接下来要做的是向您介绍使用类似知识图来构建一个更智能的框架，以提供相关的搜索结果。我们称之为基于对话的搜索。

# 实现基于对话的搜索引擎

最后，让我们来设计搜索引擎的一部分，这部分将为我们提供精细的用户界面。正如我们在本章开头提到的，基于对话的搜索引擎涉及构建一个用户界面，询问用户与其查询相关的问题。这种方法在我们有模糊的结果的情况下最为适用。例如，搜索 Donald 的用户可能心里想的是以下之一：

+   *唐纳德·克努斯*，伟大的计算机科学家

+   *唐纳德·达克*，卡通人物

+   *唐纳德·邓恩*，杰瑞德·邓恩的真名，虚构的角色

+   *唐纳德·特朗普*，商人和第 45 任美国总统

前面的列表只是对 Donald 搜索词的潜在结果的一个小例子。那么，缺乏基于对话的方法的搜索引擎会怎么做呢？它们会为用户输入的最佳匹配提供相关结果列表。例如，在撰写本书时，搜索 Donald 会得到一个与 Donald Trump 相关的网站列表，尽管我当时心里想的是 Donald Knuth。在这里，我们可以看到最佳匹配和用户最佳匹配之间的微妙差别。

搜索引擎收集大量数据用于个性化搜索结果。如果用户从事网站开发领域的工作，他们的大部分搜索请求都会与该特定领域有关。这对于提供用户更好的搜索结果非常有帮助。例如，一个搜索历史记录中大部分请求都与网站开发相关的用户，在搜索 zepelin 时将会得到更好、更专注的结果。理想的搜索引擎将提供链接到 Zeplin 应用程序用于构建 Web UI 的网站，而对于其他用户，引擎将提供有关摇滚乐队 Led Zeppelin 的信息的结果。

设计基于对话框的搜索引擎是提供用户更好界面的下一步。如果我们已经有了强大的知识库，构建起来就足够简单了。我们将使用前一节中描述的知识图概念。假设当用户输入搜索词时，我们从知识图中获取所有匹配的主题，并为用户提供潜在命中列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2fcc30b2-7cd7-4d82-bd2b-7d3d5b733845.png)

因此，用户现在更容易选择一个主题，并节省回忆完整名称的时间。来自知识图的信息可以（对于一些搜索引擎而言）在用户输入查询时合并到自动建议中。此外，我们将着手处理搜索引擎的主要组件。显然，本章无法涵盖实现的每个方面，但我们将讨论的基本组件足以让您开始设计和实现自己的搜索引擎。

我们不会去烦恼搜索引擎的用户界面部分。我们最关心的是后端。当谈论应用程序的后端时，通常指的是用户看不到的部分。更具体地说，让我们看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/1ef212ea-f319-4913-a62e-db2027a3059c.png)

正如您所看到的，大部分引擎位于后端。虽然用户界面可能感觉简单，但它是整个搜索系统的重要部分。这是用户开始他们旅程的地方，界面设计得越好，用户在搜索时的不适感就越少。我们将集中在后端；以下是我们将讨论的几个主要模块：

+   **查询解析器**：分析用户查询，规范化单词，并收集查询中每个术语的信息，以便稍后传递给查询处理器。

+   **查询处理器**：使用索引和辅助数据库检索与查询相关的数据，并构建响应。

+   **对话生成器**：为用户在搜索时提供更多选择。对话生成器是一个辅助模块。发出请求的用户可以省略对话，也可以使用它来进一步缩小搜索结果。

我们跳过了一些在搜索引擎中常见的组件（如爬虫），而是集中在与基于对话框的搜索引擎密切相关的组件上。现在让我们从查询解析器开始。

# 实现查询解析器

查询解析器做的就是其名字所暗示的：*解析*查询。作为查询解析器的基本任务，我们应该通过空格来分隔单词。例如，用户查询*zeplin best album*被分成以下术语：`zeplin`，`best`和`album`。以下类表示基本的查询解析器：

```cpp
// The Query and Token will be defined in the next snippet
class QueryParser
{
public:
  static Query parse(const std::string& query_string) {
 auto tokens = QueryParser::tokenize(query_string);
    // construct the Query object and return
    // see next snippet for details
 }

private:
  static std::vector<Token> tokenize(const std::string& raw_query) {
    // return tokenized query string
  }
};
```

看一下前面的`parse()`函数。这是类中唯一的公共函数。我们将添加更多的私有函数，这些函数从`parse()`函数中调用，以完全解析查询并将结果作为`Query`对象返回。`Query`表示一个简单的结构，包含有关查询的信息，如下所示：

```cpp
struct Query
{
  std::string raw_query;
  std::string normalized_query;
  std::vector<Token> tokens;
  std::string dialog_id; // we will use this in Dialog Generator
};
```

`raw_query`是用户输入的查询的文本表示，而`normalized_query`是规范化后的相同查询。例如，如果用户输入*good books, a programmer should read*，`raw_query`就是这个确切的文本，而`normalized_query`是*good books programmer should read*。在下面的片段中，我们不使用`normalized_query`，但在完成实现时您将需要它。我们还将标记存储在`Token`向量中，其中`Token`是一个结构，如下所示：

```cpp
struct Token
{
  using Word = std::string;
  using Weight = int;
  Word value;
  std::unordered_map<Word, Weight> related;
};
```

`related`属性表示与标记**语义相关**的单词列表。如果两个单词在概念上表达相似的含义，我们称它们为**语义相关**。例如，单词*best*和*good*，或者*album*和*collection*可以被认为是语义相关的。您可能已经猜到了哈希表值中权重的目的。我们使用它来存储相似性的`Weight`。

**权重**的范围是在利用搜索引擎的过程中应该进行配置的内容。假设我们选择的范围是从 0 到 99。单词*best*和*good*的相似性权重可以表示为接近 90 的数字，而单词*album*和*collection*的相似性权重可能在 40 到 70 之间偏离。选择这些数字是棘手的，它们应该在引擎的开发和利用过程中进行调整。

最后，`Query`结构的`dialog_id`表示如果用户选择了生成器建议的路径，则生成的对话的 ID。我们很快就会谈到这一点。现在让我们继续完成`parse()`函数。

看一下`QueryParser`类的以下补充内容：

```cpp
class QueryParser
{
public:
  static Query parse(const std::string& query_string, 
                     const std::string& dialog_id = "")
  {
    Query qr;
    qr.raw_query = query_string;
    qr.dialog_id = dialog_id;
    qr.tokens = QueryParser::tokenize(query_string);
    QueryParser::retrieve_word_relations(qr.tokens);
    return qr;
  }

private:
  static std::vector<Token> tokenize(const std::string& raw_string) {
    // 1\. split raw_string by space
    // 2\. construct for each word a Token
    // 3\. return the list of tokens 
  }

  static void retrieve_word_relations(std::vector<Token>& tokens) {
    // for each token, request the Knowledge Base
    // to retrieve relations and update tokens list
  }
};
```

尽管前面的代码片段中的两个私有函数（`tokenize`和`retrieve_word_relations`）没有实现，但基本思想是对搜索查询进行规范化和收集信息。在继续实现查询处理器之前，请查看前面的代码。

# 实现查询处理器

查询处理器执行搜索引擎的主要工作，即从搜索索引中检索结果，并根据搜索查询响应相关的文档列表。在本节中，我们还将涵盖对话生成。

正如您在前一节中看到的，查询解析器构造了一个包含标记和`dialog_id`的`Query`对象。我们将在查询处理器中使用这两者。

由于可扩展性问题，建议为对话生成器单独设计一个组件。出于教育目的，我们将保持实现简洁，但您可以重新设计基于对话的搜索引擎，并完成与爬虫和其他辅助模块的实现。

`Query`对象中的标记用于向搜索索引发出请求，以检索与每个单词相关联的文档集。以下是相应的`QueryProcessor`类的外观：

```cpp
struct Document {
  // consider this
};

class QueryProcessor
{
public:
  using Documents = std::vector<Document>;
  static Documents process_query(const Query& query) {
 if (!query.dialog_id.empty()) {
 // request the knowledge graph for new terms
 }
 // retrieve documents from the index
 // sort and return documents
 }
};
```

将前面的代码片段视为实现的介绍。我们希望表达`QueryProcessor`类的基本思想。它具有`process_query()`函数，根据查询参数中的标记从索引中检索文档。这里的关键作用由搜索索引发挥。我们定义其构造方式和存储文档的方式对于进行快速查询至关重要。同时，作为附加参数提供的对话 ID 允许`process_query()`函数请求知识库（或知识图）以检索与查询相关的更多相关标记。

还要考虑到`QueryProcessor`还负责生成对话（即定义一组路径，为用户提供查询的可能场景）。生成的对话将发送给用户，当用户进行另一个查询时，使用的对话将通过我们已经看到的对话 ID 与该查询相关联。

尽管前面的实现大多是介绍性的（因为实际代码的规模太大，无法放入本章），但它是您进一步设计和实现引擎的良好基础。

# 总结

从头开始构建搜索引擎是一项需要经验丰富的程序员来完成的任务。本书涉及了许多主题，并在本章中通过设计搜索引擎将大部分主题结合起来。

我们已经了解到，网络搜索引擎是由爬虫、索引器和用户界面等多个组件组成的复杂系统。爬虫负责定期检查网络，下载网页供搜索引擎索引。索引会产生一个名为倒排索引的大型数据结构。倒排索引，或者简称索引，是一种将单词与它们出现的文档进行映射的数据结构。

接下来，我们定义了推荐引擎是什么，并尝试为我们的搜索引擎设计一个简单的推荐引擎。推荐引擎与本章讨论的基于对话的搜索引擎功能相连。基于对话的搜索引擎旨在向用户提供有针对性的问题，以更好地了解用户实际想要搜索的内容。

通过从 C++的角度讨论计算机科学的各种主题，我们完成了本书的阅读。我们从 C++程序的细节开始，然后简要介绍了使用数据结构和算法进行高效问题解决。了解一种编程语言并不足以在编程中取得成功。您需要解决需要数据结构、算法、多线程等技能的编码问题。此外，解决不同的编程范式可能会极大地增强您对计算机科学的认识，并使您以全新的方式看待问题解决。在本书中，我们涉及了几种编程范式，比如函数式编程。

最后，正如您现在所知，软件开发不仅仅局限于编码。架构和设计项目是成功应用开发的关键步骤之一。第十章，*设计面向全球的应用程序*，到第十六章，*实现基于对话的搜索*，大部分与设计现实世界应用程序的方法和策略有关。让本书成为您从 C++开发者的角度进入编程世界的入门指南。通过开发更复杂的应用程序来发展您的技能，并与同事和刚刚开始职业生涯的人分享您的知识。学习新知识的最佳方式之一就是教授它。

# 问题

1.  爬虫在搜索引擎中的作用是什么？

1.  为什么我们称搜索索引为倒排索引？

1.  令牌化单词在索引之前的主要规则是什么？

1.  推荐引擎的作用是什么？

1.  知识图是什么？

# 进一步阅读

有关更多信息，请参考以下书籍：

*信息检索导论*，*Christopher Manning 等*，[`www.amazon.com/Introduction-Information-Retrieval-Christopher-Manning/dp/0521865719/`](https://www.amazon.com/Introduction-Information-Retrieval-Christopher-Manning/dp/0521865719/)


# 第十七章：评估

# 第一章

1.  从源代码生成可执行文件的过程称为编译。编译 C++程序是一系列复杂的任务，最终产生机器代码。通常，C++编译器解析和分析源代码，生成中间代码，对其进行优化，最后生成一个名为对象文件的机器代码文件。另一方面，解释器不会产生机器代码。相反，它逐行执行源代码中的指令。

1.  首先是预处理，然后编译器通过解析代码、执行语法和语义分析来编译代码，然后生成中间代码。在优化生成的中间代码之后，编译器生成最终的对象文件（包含机器代码），然后可以与其他对象文件链接。

1.  预处理器旨在处理源文件，使其准备好进行编译。预处理器使用预处理指令，如`#define`和`#include`。指令不代表程序语句，而是预处理器的命令，告诉它如何处理源文件的文本。编译器无法识别这些指令，因此每当您在代码中使用预处理指令时，预处理器会在实际编译代码之前相应地解析它们。 

1.  编译器为每个编译单元输出一个对象文件。链接器的任务是将这些对象文件合并成一个单一的对象文件。

1.  库可以链接到可执行文件中，可以是静态库也可以是动态库。当将它们作为静态库链接时，它们将成为最终可执行文件的一部分。动态链接库也应该被操作系统加载到内存中，以便为您的程序提供调用其函数的能力。

# 第二章

1.  通常，`main()`函数有两个参数，`argc`和`argv`，其中`argc`是程序的输入参数数量，`argv`包含这些输入参数。很少见的是，您可能会看到一个广泛支持但未标准化的第三个参数，最常见的名称是`envp`。`envp`的类型是 char 指针数组，它保存系统的环境变量。

1.  `constexpr`说明符声明函数的值可以在编译时求值。相同的定义也适用于变量。名称由`const`和表达式组成。

1.  递归导致为函数调用分配额外的空间。与迭代解决方案相比，为函数分配空间和调用的成本很高。

1.  栈保存具有自动存储期的对象；也就是说，程序员不需要关心内存中这些对象的构造和销毁。通常，栈用于函数参数和局部变量。另一方面，堆允许在程序执行期间分配新的内存。然而，正确的内存空间释放现在是程序员的责任。

1.  指针的大小不取决于指针的类型，因为指针是表示内存中地址的值。地址的大小取决于系统。通常是 32 位或 64 位。因此，我们说指针的大小是 4 或 8 字节。

1.  数组在项目位置方面具有独特的结构。它们在内存中是连续放置的；第二个项目紧跟在第一个项目后面，第三个项目紧跟在第二个项目后面，依此类推。考虑到这一特性，以及数组由相同类型的元素组成的事实，访问任何位置的项目都需要恒定的时间。

1.  如果我们在`case`语句中忘记了`break`关键字，执行将会转移到下一个`case`语句，而不检查其条件。

1.  例如，`operations['+'] = [](int a, int b) { return a + b; }`

# 第三章

1.  身份、状态和行为。

1.  在移动对象而不是复制时，我们省略了创建临时变量。

1.  在 C++中，结构体和类之间没有任何区别，除了默认访问修饰符。结构体的默认访问修饰符是 public，而类的默认访问修饰符是 private。

1.  在聚合的情况下，包含其他类的实例或实例的类可以在没有聚合的情况下实例化。而组合则表示强的包含关系。

1.  私有继承将继承的成员隐藏在派生类的客户端代码中。保护继承也是如此，但允许链中的派生类访问这些成员。

1.  通常，引入虚函数会导致向类添加指向虚函数表的附加数据成员。通常，这会增加类对象的 4 或 8 个字节的空间（根据指针的大小）。

1.  单例设计模式允许构造类的单个实例。这在许多项目中非常有用，其中我们需要确保类的实例数量限制为一个。例如，如果实现为单例的数据库连接类效果最佳。

# 第四章

1.  宏是强大的工具，如果以正确的方式使用。然而，以下方面限制了宏的使用。(1) 你无法调试宏；(2) 宏扩展可能导致奇怪的副作用；(3) 宏没有命名空间，因此如果你的宏与其他地方使用的名称冲突，你会在不想要的地方得到宏替换，这通常会导致奇怪的错误消息；和(4) 宏可能影响你不知道的事情。有关更多详细信息，请访问[`stackoverflow.com/questions/14041453`](https://stackoverflow.com/questions/14041453)。

1.  类/函数模板是一种用于生成模板类/函数的模板。它只是一个模板，而不是一个类/函数，因此编译器不会为其生成任何对象代码。模板类/函数是类/函数模板的一个实例。由于它是一个类/函数，编译器会生成相应的对象代码。

1.  当我们定义一个类/函数模板时，在`template`关键字后面有一个<>符号，其中必须给出一个或多个类型参数。<>中的类型参数被称为模板参数列表。当我们实例化一个类/函数模板时，所有模板参数必须用相应的模板参数替换，这被称为模板参数列表。

隐式实例化是按需发生的。然而，当提供库文件（.lib）时，你不知道用户将来会使用什么类型的参数列表，因此，你需要显式实例化所有潜在的类型。

1.  *多态*意味着某物以不同的形式存在。具体来说，在编程语言中，多态意味着一些函数、操作或对象在不同的上下文中有几种不同的行为。在 C++中，有两种多态性：动态多态和静态多态。动态多态允许用户在运行时确定要执行的实际函数方法，而静态多态意味着在编译时知道要调用的实际函数（或者一般来说，要运行的实际代码）。

函数重载意味着使用相同的名称但不同的参数集（不同的签名）定义函数。

函数重写是子类重写父类中定义的虚方法的能力。

1.  类型特征是一种用于收集有关类型信息的技术。借助它，我们可以做出更明智的决策

在通用编程中开发高质量优化的算法。类型特征可以通过部分或完全模板特化来实现。

1.  我们可以在`g()`中编写一个错误语句，并构建代码。如果实例化了未使用的函数，则编译器将报告错误，否则将成功构建。您可以在以下文件中找到示例代码，`ch4_5_class_template_implicit_inst_v2.h`和`ch4_5_class_template_implicit_inst_B_v2.cpp`，位于[`github.com/PacktPublishing/Mastering-Cpp-Programming./tree/master/Chapter-4.`](https://github.com/PacktPublishing/Expert-CPP/tree/master/Chapter-4)

1.  请参考[`github.com/PacktPublishing/Mastering-Cpp-Programming./tree/master/Chapter-4`](https://github.com/PacktPublishing/Mastering-Cpp-Programming./tree/master/Chapter-4)中的`ch4_q7.cpp`。

1.  这是一个实验练习；不需要答案。

# 第五章

1.  计算机内存可以描述为一个概念 - **动态 RAM**（**DRAM**），或者是计算机包含的所有内存单元的组合，从寄存器和缓存内存开始，到硬盘结束。从程序员的角度来看，DRAM 是最感兴趣的，因为它保存了计算机中运行的程序的指令和数据。

1.  虚拟内存是一种有效管理计算机物理内存的方法。通常，操作系统会整合虚拟内存来处理程序的内存访问，并有效地为特定程序分配内存块。

1.  在 C++中，我们使用`new`和`delete`运算符来分配和释放内存空间。

1.  `delete`用于释放为单个对象分配的空间，而`delete[]`用于动态数组，并在堆上释放数组的所有元素。

1.  垃圾收集器是一种工具或一组工具和机制，用于在堆上提供自动资源释放。对于垃圾收集器，需要一个支持环境，比如虚拟机。C++直接编译成可以在没有支持环境的情况下运行的机器代码。

# 第六章

1.  在向向量中插入新元素时，它被放置在向量的已分配的空闲槽中。如果向量的大小和容量相等，则意味着向量没有空闲槽可供新元素使用。在这些（罕见）情况下，向量会自动调整大小，这涉及分配新的内存空间，并将现有元素复制到新的更大空间。

1.  在链表的前面插入元素时，我们只创建新元素并更新列表指针，以有效地将新元素放入列表中。在向向量的前面插入新元素时，需要将所有向量元素向右移动，以释放一个槽位给该元素。

1.  请参考 GitHub 中的章节源代码。

1.  它看起来像一个链表。

1.  选择排序搜索最大（或最小）元素，并用该最大（或最小）元素替换当前元素。插入排序将集合分为两部分，并遍历未排序部分，并将其每个元素放入已排序部分的适当槽中。

1.  请参考 GitHub 中的章节源代码。

# 第七章

1.  C++中的 ranges 库允许处理元素的范围，并使用视图适配器对其进行操作，这样更有效，因为它们不会将整个集合作为适配器结果存储。

1.  如果函数不修改状态，并且对于相同的输入产生相同的结果，则该函数是纯的。

1.  纯虚函数是没有实现的函数的特征。纯虚函数用于描述派生类的接口函数。函数式编程中的纯函数是那些不修改状态的函数。

1.  折叠（或缩减）是将一组值组合在一起以生成减少数量的结果的过程。

1.  尾递归允许编译器通过省略为每个递归调用分配新内存空间来优化递归调用。

# 第八章

1.  如果两个操作的开始和结束时间在任何时刻交错，则它们会同时运行。

1.  并行意味着任务同时运行，而并发不强制任务同时运行。

1.  进程是程序的映像。它是程序指令和数据加载到计算机内存中的组合。

1.  线程是进程范围内可以由操作系统调度程序调度的代码部分，而进程是正在运行的程序的映像。

1.  请参考章节中的任何示例。

1.  通过使用双重检查锁定。

1.  请参考 GitHub 上该章节的源代码。

1.  C++20 引入了协程作为经典异步函数的补充。协程将代码的后台执行提升到了下一个级别。它们允许在必要时暂停和恢复函数。`co_await`是一个构造，告诉代码等待异步执行的代码。这意味着函数可以在那一点被暂停，并在结果准备好时恢复执行。

# 第九章

1.  双重检查锁定是使单例模式在多线程环境中无缺陷地工作的一种方法。

1.  这是一种确保在复制其他堆栈的基础数据时，其底层数据不会被修改的方法。

1.  原子操作是不可分割的操作，原子类型利用底层机制来确保指令的独立和原子执行。

1.  `load()`和`store()`利用低级机制来确保写入和读取操作是原子的。

1.  除了`load()`和`store()`之外，还有诸如`exchange()`、`wait()`和`notify_one()`等操作。

# 第十章

1.  TDD 代表测试驱动开发，其目的是在项目的实际实现之前编写测试。这有助于更清晰地定义项目需求，并在代码中避免大部分错误。

1.  交互图表现了对象之间通信的确切过程。这使开发人员能够高层次地查看任何给定时刻的实际程序执行。

1.  在聚合的情况下，包含其他类的实例或实例的类可以在没有聚合的情况下实例化。另一方面，组合表达了强包含关系。

1.  简而言之，里氏替换原则确保接受某种类型 T 对象作为参数的任何函数也将接受类型 K 对象，如果 K 扩展了 T。

1.  开闭原则规定类应该对扩展开放，对修改关闭。在所述示例中，`Animal`对扩展开放，因此从`Animal`继承`monkey`类并不违反该原则。

1.  请参考 GitHub 上该章节的源代码。

# 第十一章

1.  覆盖私有虚函数允许通过保持其公共接口不变来修改类的行为。

1.  这是一种行为设计模式，其中对象封装了一个动作和执行该动作所需的所有信息。

1.  尽可能与其他对象共享数据。当我们有许多具有相似结构的对象时，跨对象共享重复数据可以最小化内存使用。

1.  观察者通知订阅对象有关事件，而中介者则扮演着相互通信对象之间连接的角色。

1.  将游戏循环设计为无限循环是合理的，因为从理论上讲，游戏可能永远不会结束，只有在玩家命令结束时才会结束。

# 第十二章

1.  物理层、数据链路层、网络层、传输层、会话层、表示层和应用层。

1.  端口号提供了一种区分在同一环境中运行的多个网络应用程序的方法。

1.  套接字是提供程序员发送和接收网络数据的抽象。

1.  首先，我们需要创建并绑定带有 IP 地址的套接字。接下来，我们应该监听传入的连接，如果有一个连接，我们应该接受连接以进一步处理数据通信。

1.  TCP 是一种可靠的协议。它处理端点之间的稳固连接，并通过重新发送接收方未收到的数据包来处理数据包丢失。另一方面，UDP 不可靠。几乎所有处理方面都由程序员来处理。UDP 的优势在于它的速度，因为它省略了握手、检查和数据包丢失处理。

1.  宏定义会导致代码中的逻辑错误，很难发现。最好始终使用`const`表达式而不是宏。

1.  客户端应用程序必须具有唯一的标识符，以及用于授权和/或验证它们的令牌（或密码）。

# 第十三章

1.  这是一个实验室练习；不需要答案。

1.  以下输出来自 NVIDIA Jetson Nano 上的 Ubuntu 18.04：

```cpp
swu@swu-desktop:~/ch13$ g++ -c -Wall -Weffc++ -Wextra ch13_rca_compound.cpp
 ch13_rca_compound.cpp: In function ‘int main()’:
 ch13_rca_compound.cpp:11:17: warning: operation on ‘x’ may be undefined [-Wsequence-point]
 std::cout << f(++x, x) << std::endl; //bad,f(4,4) or f(4,3)?
 ^~~

```

```cpp
swu@swu-desktop:~/ch13$ g++ -c -Wall -Weffc++ -Wextra ch13_rca_mix_sign_unsigned.cpp
nothing is detected 
```

```cpp
swu@swu-desktop:~/ch13$ g++ -c -Wall -Weffc++ -Wextra ch13_rca_order_of_evaluation.cpp
 ch13_rca_order_of_evaluation.cpp: In constructor ‘A::A(int)’:
 ch13_rca_order_of_evaluation.cpp:14:14: warning: ‘A::v3’ will be initialized after [-Wreorder]
 int v1, v2, v3;
 ^~
 ch13_rca_order_of_evaluation.cpp:14:6: warning: ‘int A::v1’ [-Wreorder]
 int v1, v2, v3;
 ^~
 ch13_rca_order_of_evaluation.cpp:7:2: warning: when initialized here [-Wreorder]
 A(int x) : v2(v1), v3(v2), v1(x) {
 ^
 ch13_rca_order_of_evaluation.cpp: In constructor ‘B::B(float)’:
 ch13_rca_order_of_evaluation.cpp:32:6: warning: ‘B::v2’ will be initialized after [-Wreorder]
 int v2;
 ^~
 ch13_rca_order_of_evaluation.cpp:31:6: warning: ‘int B::v1’ [-Wreorder]
 int v1; //good, here the declaration order is clear
 ^~
 ch13_rca_order_of_evaluation.cpp:25:2: warning: when initialized here [-Wreorder]
 B(float x) : v2(x), v1(v2) {};
 ^
 swu@swu-desktop:~/ch13$ g++ -c -Wall -Weffc++ -Wextra ch13_rca_uninit_variable.cpp
 ch13_rca_uninit_variable.cpp: In function ‘int main()’:
 ch13_rca_uninit_variable.cpp:7:2: warning: ‘x’ is used uninitialized in this function [-Wuninitialized]
 if (x) {
 ^~
```

1.  因为静态分析工具从其模型中预测错误，动态分析工具通过程序的执行来检测错误。

1.  请参考样本代码，`ch13_tdd_v3.h`，`ch13_tdd_v3.cpp`和`ch13_tdd_Boost_UTF3.cpp`，

[`github.com/PacktPublishing/Mastering-Cpp-Programming./tree/master/Chapter-13`](https://github.com/PacktPublishing/Mastering-Cpp-Programming./tree/master/Chapter-13)。

# 第十四章

1.  Qt 的编译模型允许省略虚拟机。它使用**元对象编译器**（**MOC**）将其转换为 C++，然后编译为特定平台的机器代码。

1.  `QApplication::exec()`是应用程序的起点。它启动 Qt 的事件循环。

1.  通过调用`setWindowTitle()`。

1.  `m->index (2, 3)`。

1.  `wgt->resize (400, 450)`。

1.  当从`QLayout`继承时，应为`addItem()`、`sizeHint()`、`setGeometry()`、`itemAt()`、`takeAt()`和`minimumSize()`函数提供实现。

1.  通过使用`connect()`函数，该函数以源对象和目标对象以及信号和插槽的名称作为参数。

# 第十五章

1.  **ML**代表**机器学习**，是计算机系统用于执行特定任务的算法和统计模型的研究领域，而不使用显式指令，而是依赖模式和推理。

1.  监督学习算法（也称为带教练的训练）从带标签的数据集中学习；也就是说，每个记录都包含描述数据的附加信息。无监督学习算法更加复杂——它们处理包含大量特征的数据集，然后试图找到特征的有用属性。

1.  机器学习应用包括机器翻译、自然语言处理、计算机视觉和电子邮件垃圾邮件检测。

1.  其中一种方法是为每个结果添加权重，如果减法操作的权重超过其他操作，它将成为主导操作。

1.  神经网络的目的是识别模式。

# 第十六章

1.  网络爬虫下载网页并存储其内容，以便搜索引擎对其进行索引。

1.  我们称之为倒排索引，因为它将单词映射回它们在文档中的位置。

1.  在索引之前，标记化会规范化单词。

1.  推荐引擎验证并推荐适合特定请求的最佳结果。

1.  知识图是一个图，其中节点是主题（知识），边是主题之间的连接。
