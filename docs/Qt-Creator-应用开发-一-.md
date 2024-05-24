# Qt Creator 应用开发（一）

> 原文：[`annas-archive.org/md5/27c7d87c779f8446e54a74757f855137`](https://annas-archive.org/md5/27c7d87c779f8446e54a74757f855137)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

无论您是刚开始学习编程，还是已经确定 Qt 是您项目的 GUI 工具包，Qt Creator 都是一个很好的集成开发环境（IDE）的选择！在本书中，我们努力帮助您充分利用 Qt Creator，向您展示使用 Qt Creator 的几乎每个方面，从配置到编译和调试应用程序，以及众多的技巧和窍门。在这个过程中，您不仅会获得 Qt Creator 作为 IDE 的宝贵经验，还会获得 Qt 和 Qt Quick 的宝贵经验。阅读完本书后，您将能够：

+   使用 Qt Creator 编辑、编译、调试和运行 C++应用程序，为使用 Qt 和标准模板库（STL）构建最先进的控制台和 GUI 应用程序打开了一条道路

+   使用 Qt Creator 编辑、编译、调试和运行 Qt Quick 应用程序，让您可以访问最先进的声明式 GUI 创作环境之一

+   使用 Qt Designer 设计 GUI 应用程序，构建传统的基于小部件或 Qt Quick 应用程序

+   分析 Qt 应用程序的内存和运行时性能，并进行改进和缺陷修复

+   提供应用程序的本地化版本，以便您可以在世界各地以不同语言部署它

+   使用 Qt Quick 和 Qt Widgets 为诸如 Google Android 等平台编写移动应用程序

# 本书涵盖了什么内容

本书分为七章，您应该按顺序阅读，特别是如果您对 Qt Creator 和 Qt 编程不熟悉的话。这些章节包括：

第一章，“使用 Qt Creator 入门”，解释了如何下载和安装 Qt Creator，以及编辑简单的应用程序来测试您的安装。

第二章，“使用 Qt Creator 构建应用程序”，解释了如何使用 Qt Creator 编译，运行和调试应用程序。您将学习 Qt Creator 如何与 GNU 调试器和 Microsoft 控制台调试器集成，以提供断点、内存检查和其他调试帮助。

第三章，“使用 Qt Designer 设计您的应用程序”，解释了如何使用 Qt Creator 中的拖放 GUI 设计工具来构建 Qt 基于小部件和 Qt Quick 应用程序。

第四章，“使用 Qt Linguist 本地化您的应用程序”，解释了如何管理不同区域设置的资源字符串，让您可以在不同区域设置中使用不同语言构建应用程序。

第五章，“使用 Qt Creator 进行性能优化”，解释了如何使用 Qt Creator 来检查 Qt Quick 应用程序的运行时性能，以及如何使用 Valgrind 进行应用程序的内存分析，Valgrind 是一个开源的诊断工具。

第六章，“使用 Qt Creator 开发移动应用程序”，介绍了移动软件开发的激动人心的领域，并展示了如何利用本书中关于 Qt 和 Qt Creator 的知识来为诸如 Google Android 等平台编写应用程序。

第七章，“Qt 技巧和技巧”，涵盖了使用 Qt 和 Qt Creator 的技巧，这将帮助您高效地使用 Qt 框架和 Qt Creator IDE。

# 本书需要什么

Qt 和 Qt Creator 是跨平台工具。无论您使用的是 Windows 机器、运行 Mac OS X 的 Macintosh，还是运行 Linux 的工作站，您可能已经拥有所需的一切。您应该有足够的磁盘空间（大约 10GB 就足够了）来安装整个 Qt Creator IDE 和 Qt 库，与任何软件开发环境一样，您拥有的 RAM 越多越好（尽管我曾在运行 Ubuntu 的上网本上运行 Qt Creator，只有 1GB 的 RAM 也能正常运行！）。

您应该对计算机编程有基本的了解，并且应该准备用 C++编写代码。如果您对使用 Qt Quick 进行编程感兴趣，那么对 JavaScript 的基本了解会有所帮助，但您可以在学习过程中轻松掌握。

# 这本书适合谁

我写这本书是为了那些对 Qt 和 Qt Creator 没有或很少经验的人，他们可能是第一次在大学课程、开源项目中使用它，或者只是想尝试一下这个平台和 IDE。

我特别鼓励您阅读这本书，如果您是一名在大学 C++编程课程中使用 Qt Creator 的学生！您应该专注于前两章，以及您课程所需的其余部分。

# 约定

在这本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“对于名称，输入`HelloWorldConsole`，并选择对您有意义的路径（或接受默认设置）。”

代码块设置如下：

```cpp
#include <QCoreApplication>
#include <iostream>
using namespace std;
int main(int argc, char *argv[])
{
  QCoreApplication a(argc, argv);
  cout << "Hello world!";
  return a.exec();
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```cpp
import QtQuick 2.0
Rectangle {
  width: 360
  height: 360
  Text {
    text: qsTr("Hello World")
    anchors.centerIn: parent
  }
  MouseArea {
    anchors.fill: parent
    onClicked: {
      Qt.quit();
    }
  }
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中：“在**此处输入**的位置，右键单击并选择**删除菜单栏**。”

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这样的方式出现。

# 第一章：使用 Qt Creator 入门

Qt Creator 是集成的软件开发环境，支持传统的 C++应用程序开发，以及使用 Qt 项目的库进行开发（统称为“Qt”，发音为“cute”）。在本章中，我们将看到开始使用 Qt Creator 所需的一切：

+   在哪里下载 Linux、Mac OS X 或 Windows 的 Qt Creator

+   如何确保您的基本配置正在运行

+   快速查看简单的 Qt GUI 应用程序，以及 Qt Quick 应用程序

# 下载 Qt Creator

Qt Creator 背后的跨平台工具包 Qt 有着悠久而辉煌的历史。目前，作为 Digia 的一个项目，它在[qt-project.org](http://qt-project.org)上有自己的 URL，并提供商业和非商业许可证。

要免费开始使用非商业版本，请访问[`bit.ly/13G4Jfr`](http://bit.ly/13G4Jfr)查看类似以下截图的内容：

![下载 Qt Creator](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_01_01.jpg)

下载 Qt Creator

### 提示

用 Qt 进行应用程序开发的最受欢迎的平台之一是 Linux。在许多 Linux 变体中，特别是 Ubuntu，您可以使用软件包管理器获取 Qt Creator。在我的 Ubuntu 系统上，只需执行`sudo apt-get install qtcreator`命令即可获得 Qt Creator。您将获得与您的 Linux 版本匹配的 Qt 版本，尽管它可能不是 Digia 发布的最新版本。

我们还可以下载 Qt 的一部分，比如只有运行时库，或者从源代码构建 Qt Creator。这通常需要您已经安装了编译器和基本的开发工具，并且对`qmake`和 Qt 的构建配置管理系统有基本的了解。

有些下载包括您开发所需的 C++编译器和链接器；有些则不包括。例如，在 Windows 上有一个包括 MinGW 工具链的变体，因此您拥有构建应用程序所需的一切。但是，您也可以下载使用 Microsoft Visual Studio 编译器的 Windows 版 Qt Creator，因此，如果您更喜欢使用 Visual Studio 进行编译并将 Qt Creator 作为您的 IDE，这也是一个选择。在 Mac OS X 上，您需要先安装 Xcode 和命令行开发工具；您可以从 Mac OS X 应用商店下载 Xcode，然后使用 Xcode 下载命令行开发工具。

下载安装程序后，以通常的方式运行它。它将为您的平台启动一个安装向导，通常安装大约需要三到四分钟。您需要有足够的磁盘空间。Qt Creator 并不占用太多磁盘空间，但软件开发通常会占用很多空间；至少为工具和库预留 500 兆字节，为源代码、中间目标文件、调试符号以及编译的应用程序在主驱动器上预留几个千兆字节的空间。 （如果您在虚拟机上运行 Qt Creator，特别需要计划这一点；确保虚拟机镜像的虚拟硬盘有足够的磁盘空间。）您还应确保您的开发机有足够的 RAM；越多越好。Qt Creator 在 2GB 的 RAM 中运行得很好，但 Qt Creator 使用的编译器和链接器如果有更多的可用 RAM，将运行得更快。

# 熟悉 Qt Creator

以下截图显示了您第一次启动 Qt Creator 时看到的内容。让我们仔细看看屏幕的每个部分：

![熟悉 Qt Creator](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_01_02.jpg)

Qt Creator 的首页

主窗口当前显示了**IDE 概述**、**用户界面**、**构建和运行示例应用程序**和**开始开发**的图标，这是您的工作区。在正常情况下，这将是您看到应用程序源代码的地方。左侧是一系列图标，让您选择进入应用程序的各种视图。它们是：

+   **欢迎**视图显示了关于 Qt Creator 的基本信息

+   **编辑**视图允许您编辑构成应用程序的文件

+   **设计**视图允许您使用 Qt Designer 为应用程序设计用户界面

+   **调试**视图允许您在应用程序运行时调试，包括查看内存和变量、设置断点和逐步执行应用程序等操作

+   **项目**视图允许您调整项目的构建和链接设置

+   **分析**视图允许您分析应用程序的运行时性能

+   **帮助**视图提供了关于 Qt Creator 和 Qt Framework 的文档

在上一张截图中**帮助**视图按钮下方，您可以看到活动项目；当我拍摄这张截图时，我已经创建了我们的第一个应用程序。现在让我们来做吧。

# 你的第一个应用程序-你好世界

在 Qt Creator 中，从**文件**菜单中选择**新建文件或项目...**。Qt Creator 将呈现给您**新建**项目向导，让您选择要创建的项目类型，给它命名等等。要创建我们的第一个应用程序：

1.  如果您还没有选择，选择**新建文件或项目...**

1.  Qt Creator 会向您呈现一个对话框，其中有许多项目选择。选择**应用程序**，然后选择**Qt 控制台应用程序**，然后点击**选择...**

1.  Qt Creator 会要求您为项目文件存储的目录输入名称和路径。对于名称，输入`HelloWorldConsole`，选择一个对您来说有意义的路径（或接受默认值）。然后，点击**下一步**。

1.  Qt Creator 可以支持针对构建应用程序的各种工具包和库。选择默认安装的桌面 Qt 工具包，保持**发布**和**调试**选项都被选中。然后，点击**下一步**。

1.  在下一步中，Qt Creator 会提示您关于项目的版本控制。Qt Creator 可以使用您安装的版本控制客户端来执行项目的更改跟踪。现在，跳过这一步，将**添加到版本控制**设置为**无**，然后点击**完成**。

Qt Creator 创建您的项目并切换到**编辑**视图。在文件`main.cpp`的源代码编辑器中，输入以下代码：

```cpp
#include <QCoreApplication>
#include <iostream>

using namespace std;

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    cout << "Hello world!";

    return a.exec();
}
```

`QCoreApplication`任务处理应用程序的系统启动，并且每个 Qt 控制台应用程序都需要创建一个并调用其`exec`方法，作为`main`方法的一部分。它设置了 Qt 的事件处理程序，并提供了一堆移植助手，用于确定诸如应用程序目录、库路径和其他细节的事情。

对于控制台应用程序，这就是您所需要的：您可以自由地混合和匹配 Qt 类与 C++标准库和**标准模板库**（尽管一旦掌握了 Qt 的基础类，许多 STL 构造会感觉有些限制）。

接下来，让我们编译和运行应用程序。您可以使用以下任一选项：

+   按下*F5*在调试器中构建和运行您的应用程序

+   从**调试**菜单中选择**开始调试...**

+   单击左侧**帮助**视图按钮下方的绿色**运行**箭头以运行应用程序

+   单击带有错误标志的绿色**运行**箭头以调试应用程序

### 提示

如果您只想构建应用程序，可以单击**运行**和**调试**图标下方的锤子图标。

当您选择这些选项之一时，Qt Creator 会调用编译器和链接器来构建您的应用程序。如果您选择了调试选项，Qt Creator 会切换到**调试**视图（我将在下一章中详细讨论），因为它启动您的应用程序。

应用程序启动后，您将在控制台视图中看到`Hello world!`消息。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

## 使用 Qt GUI 库的 Hello World

Qt 的一个优势是其丰富的 GUI 元素集合，您可以使用它们来创建窗口应用程序。制作 GUI 应用程序在原则上与制作控制台应用程序类似；只需选择**Qt Gui 应用程序**而不是**Qt 控制台应用程序**，当您选择**新文件或项目…**时，从向导的**新**对话框中选择**Qt Gui 应用程序**。现在试试看：

1.  首先，通过选择**文件**菜单中的**关闭所有项目和编辑器**关闭当前文件和项目。

1.  接下来，再次选择**新文件或项目…**，并从向导的第一步中选择**Qt Gui 应用程序**。

1.  再次通过向导，命名您的项目为`HelloWorldGui`。

1.  **新**项目向导将提示您输入实现主窗口的类的名称。保持给定的默认值：将子类保留为`QMainWindow`，名称保留为`MainWindow`。

Qt Creator 在`mainform.h`和`mainform.cpp`文件中创建类的默认子类，提供平台的基本窗口处理，并创建一个将包含应用程序窗口小部件的表单。如果此时运行应用程序，您将看到一个空窗口。而是双击 Qt Creator 第二窗格中的**Forms**文件夹，然后双击文件`mainwindow.ui`。Qt Creator 切换到**设计**视图，您将看到类似于以下屏幕截图的内容：

![使用 Qt GUI 库的 Hello World](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_01_03.jpg)

Qt Creator 的设计视图

左侧是您可以选择以组织小部件的布局列表，例如间隔器、视图、容器、按钮和其他小部件。中间是您的应用程序主窗口布局的视图，右侧是包含主窗口中对象层次结构和单击主窗口中任何项目的属性的窗格。

虽然我在第三章中更多地探索 Qt Designer，*使用 Qt Designer 设计您的应用程序*，您可以尝试使用它来构建一个简单的 UI：

1.  在**Type Here**处右键单击并选择**删除菜单栏**。

1.  拖动标签（在左侧窗格中的**显示小部件**下）并将其放在中央窗格中的窗口预览上。

1.  双击出现的标签，然后键入`Hello world!`。

1.  抓住标签的一个角落并调整大小，以便显示整个文本。您也可以在窗口中移动它。

1.  请注意，当您单击标签时，右下角的属性字段会更新，显示新标签的属性。

1.  在左侧窗格中的**按钮**下拖动按钮，并将其放在中央窗格中的窗口预览上。

1.  双击按钮并将其文本更改为`Exit`。

1.  选择新按钮后，在属性浏览器中将**objectName**字段更改为`exitButton`。

1.  右键单击按钮并选择**转到槽…**。一个窗口将显示一个槽的列表（目前，您可以将槽视为在动作上触发的内容）。

1.  从出现的列表中选择**clicked()**。

1.  Qt Creator 返回到`mainindow.cpp`文件的**编辑**视图。将其更改为：

```cpp
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QApplication>
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    QApplication::exit();
}
```

在运行应用程序之前，让我们确保我们了解`MainWindow`类的实现。`MainWindow`类的构造函数加载了主窗口用户界面的描述，并使用 Qt Creator 生成的`Ui::MainWindow`类进行设置。析构函数删除了代码布局的实现，`on_pushButton_clicked`方法通过调用`QApplication`类实现的静态方法`exit`简单地终止了应用程序。

最后，我们必须将`on_pushButton_clicked`方法的声明添加到`MainWindow.h`中。在左侧的浏览器中双击该文件，并确保它读取为：

```cpp
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
```

你需要添加的关键行是：

```cpp
private slots:
    void on_pushButton_clicked();
```

我们将在下一章更多地了解信号和槽；现在，知道当你点击按钮时，你正在声明一个私有函数来触发。

运行应用程序。它应该打开一个带有文本**Hello World**的单个窗口；点击窗口中的**退出**按钮（或右上角的关闭框）应该关闭应用程序。此时，如果你想了解更多关于 Qt GUI 小部件应用程序的知识，可以尝试将其他 GUI 项目拖到窗口中，或者切换到**帮助**视图并从帮助项目列表中选择**Qt Gui**来探索 Qt GUI 应用程序的帮助。

# 使用 Qt Quick 的 Hello World

Qt Quick 是 Qt 的较新的声明性用户界面框架，使用它可以非常容易地创建具有动画过渡和流畅用户界面的流畅应用程序。使用 Qt Quick，你可以使用 QML 来描述用户界面，这是一种类似于 JavaScript 的语言，让你声明用户界面元素及其关系；Qt Quick 运行时会在应用程序的实现中大部分繁重的工作。

到目前为止，你可以猜到如何创建一个 Qt Quick 项目：从**文件**菜单中选择**新建文件或项目...**，然后点击**Qt Quick 2 应用程序（内置类型）**，并按照向导进行操作。

向导不会询问任何额外的问题，如果你只是按照向导进行操作，最终会得到一个简单的应用程序，实际上在自己的窗口中显示了`Hello World`。以下是它提供的代码：

```cpp
import QtQuick 2.0

Rectangle {
    width: 360
    height: 360
    Text {
        text: qsTr("Hello World")
        anchors.centerIn: parent
    }
    MouseArea {
        anchors.fill: parent
        onClicked: {
            Qt.quit();
        }
    }
}
```

如果你了解 JavaScript，这个语法可能看起来有点熟悉，但仍然有所不同。第一行是一个导入语句；它告诉 QML 运行时应该有哪些类可用。至少，你所有的 Qt Quick 应用程序都必须导入 QtQuick 版本 2.0，就像这个例子一样。

接下来是 QML 本身。它声明了一个 360×360 像素的父矩形，确定了应用程序窗口的大小。矩形内有两个对象：**Text**和**MouseArea**。**Text**对象只是一个带有文本`Hello World`的标签，放置在矩形的中心。请注意，文本属性的值实际上是一个函数调用的结果，调用了函数`qsTr`，这是 Qt 内置的本地化函数，它查看应用程序资源以返回`Hello World`的本地化版本（如果已提供）。

**MouseArea**对象接受用户输入，并根据输入执行函数；它的大小适应父对象（`anchors.fill`设置为`parent`），并在点击时响应执行分配给`onClicked`属性的函数。这个`onClicked`函数只是通过调用 Qt 类的`quit`函数来退出应用程序。

此时，你可以以通常的方式运行应用程序，你会看到一个窗口，其中心是文本**Hello World**。

虽然原理类似，但 Qt Quick 设计师与 Qt GUI 设计师非常不同；看一下下面的截图：

![使用 Qt Quick 的 Hello World](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_01_04.jpg)

Qt Quick 设计师

有一些明显的相似之处。两个设计师都显示了可以添加到视图中的事物列表，以及视图中对象的层次结构和单个对象的属性。然而，Qt Quick 小部件比 Qt GUI 小部件要少得多，而且 Qt Quick 中的小部件与本地平台的外观和感觉几乎没有匹配。按设计，Qt GUI 用于构建与本地平台匹配的传统应用程序，而 Qt Quick 用于创建具有自己外观和感觉的与设备无关的应用程序。例如，您可能会使用 Qt GUI 编写企业数据收集应用程序，而使用 Qt Quick 创建媒体中心应用程序。

然而，在这两种情况下，使用设计师是相同的。让我们在主视图中添加另一个**MouseArea**，并让它做一些事情：

1.  在 Qt Creator 的文件列表中选择`main.qml`，然后单击**设计**以查看**设计**视图。

1.  在**库**窗格上，选择项目并向下滚动，直到看到**矩形**。将矩形拖到中心窗格并将其放置在`Hello World`标签的上方某处。您可能需要调整矩形的大小，以便标签仍然可见。

1.  在窗格中选择矩形，在**颜色**下，输入矩形的颜色。

1.  现在从**库**窗格中拖出一个**MouseArea**对象，并将其放在新的矩形上。

1.  选择**MouseArea**后，选择**布局**，并将鼠标悬停在布局上，直到看到**填充到父级**。然后单击它。

1.  返回**编辑**视图并修改`main.qml`，使其看起来像下面这样：

```cpp
import QtQuick 2.0

Rectangle {
    width: 360
    height: 360
    Text {
 id: text
        text: qsTr("Hello World")
        anchors.centerIn: parent
    }
    MouseArea {
        anchors.fill: parent
        onClicked: {
            Qt.quit();
        }

        Rectangle {
            id: rectangle1
            x: 80
            y: 7
            width: 200
            height: 124
            color: "#777777"

            MouseArea {
                id: mousearea1
                anchors.fill: parent
 onClicked: text.text = qsTr("Hi there!")
            }
        }
    }
}
```

您应该看到大部分更改是由**设计**视图进行的；它在原始**MouseArea**对象内添加了一个矩形，以及另一个**MouseArea**。您应该需要添加一行，将`text`元素的 ID 设置为 text，并将`onClicked`处理程序添加到您在**设计**视图中拖出的新**MouseArea**对象。`id`属性允许其他 QML 通过名称访问文本字段（在本例中，它的名称只是 text），而`onClicked`处理程序将文本项的`text`属性的内容更改为文本`Hi there!`。

这里值得观察一下`qsTr`：您不必向应用程序资源添加任何文本即可使基本本地化工作。这与大多数其他平台不同，其他平台的本地化是通过为具有未本地化字符串的默认值提供本地文件中的键值来实现的。

运行应用程序。您将看到矩形在文本**Hello World**上方，单击矩形会将文本更改为**Hi there!**。

# 概要

获取 Qt Creator 很容易；它只是一个网页下载，或者在大多数 Linux 平台上，它是通过本机软件包管理器的可选安装（尽管软件包管理器提供的版本可能比您从 Qt 项目网站获得的版本稍微旧一些）。

Qt Creator 为您在项目中组织源代码；当您首次启动它时，您可以创建一个默认项目，或者创建一个新项目来包含应用程序的源代码和资源。Qt Creator 中包含了编译和调试应用程序所需的所有选项。此外，它支持用于开发 Qt GUI 和 Qt Quick 应用程序的设计工具。

在下一章中，我们将深入了解如何配置 Qt Creator 以编译和编辑您的代码，包括如何向项目添加源文件，配置编译器和链接器选项，添加第三方库的依赖项等。


# 第二章：使用 Qt Creator 构建应用程序

你要做的第一件事是弄清楚如何向 Qt Creator 添加源文件并构建（或调试）你的项目。本章就是关于这个的-我们将讨论如何向项目添加文件，如何创建库以及如何使用调试器和控制台记录器。在本章结束时，你将能够驾驭 Qt Creator 来开发你的控制台应用程序。

# 入门-我们的示例库

本章的示例代码有两个部分：定义公共函数的库和调用该函数的控制台应用程序。库是拆分应用程序的好方法，虽然这个例子很简单，但也让我向你展示如何创建一个库并将其包含在你的应用程序中。

我要稍微拉伸一下你的想象力：假设你负责设置一个数学函数库。在这个例子中，我们只会编写一个函数，`factorial`。你应该记得从入门编程中的`factorial`函数；它用*a!*表示，并定义为：

+   0！是 0

+   1！是 1

+   *n!*是*n × (n-1)!*

这是一个递归定义，我们可以这样编码：

```cpp
unsigned long factorial(unsigned int n)
{
    switch(n) 
    {
        case 0: return 0;
        case 1: return 1;
        default: return n * factorial(n-1);
    }
}
```

### 提示

一个避免函数调用成本的替代定义是：

```cpp
unsigned long factorial(unsigned int n)
{
    unsigned long result = 1;
    for(unsigned int i = n; i > 1; i--)
    {
        result *= i;
    }
}
```

为什么我选择了递归定义？有三个原因：我认为这更清晰，函数调用的性能开销在这个例子中并不重要，并且本书的许多读者可能会将这本书作为入门计算机科学课程的一部分，递归是教授和应该加强的。

让我们开始创建实现我们的`factorial`函数的库。要做到这一点：

1.  在 Qt Creator 中，从**文件**菜单中选择**新建文件或项目…**。

1.  在对话框的左侧窗格中选择**库**，并从中央窗格中选择**C++库**。

1.  Qt Creator 可以创建动态库（在 Windows 中称为 DLL）、静态库或可以在应用程序之间共享的插件。我们将创建一个静态库，所以在下一个屏幕上选择**静态链接库**，并将其命名为`MathFunctions`。选择一个合理的项目路径。

1.  在向导的下一步中，保持 Qt 版本、**调试**和**发布**项目选中。

1.  Qt Creator 构建的库可以依赖于 Qt 库本身。让我们允许这个库依赖于 QtCore，Qt 的核心数据结构；在**选择所需模块**窗口中，保持**QtCore**选中，然后点击**下一步**。

1.  在下一个窗口中，你将命名 Qt Creator 将添加到你的项目中的骨架文件。点击**下一步**。

1.  在**项目管理**窗口中，选择版本控制选择**<无>**（我们不会为这个项目使用版本控制），然后点击**完成**。

1.  编辑`mathfunctions.h`以包括我们的`factorial`函数的静态方法声明：

```cpp
#ifndef MATHFUNCTIONS_H
#define MATHFUNCTIONS_H

class MathFunctions
{
public:
    MathFunctions();

    static unsigned long int factorial(unsigned int n);
};

#endif // MATHFUNCTIONS_H 
```

1.  打开`mathfunctions.cpp`。有两种方法可以做到这一点，一种是在**项目**窗格中双击它，另一种是右键单击`factorial`函数，然后选择**切换头/源**。编写你的`factorial`函数；`mathfunctions.cpp`应该是这样的：

```cpp
#include "mathfunctions.h"

MathFunctions::MathFunctions()
{
}

unsigned long
MathFunctions::factorial(unsigned int n)
{
    switch(n)
    {
        case 0: return 0;
        case 1: return 1;
        default: return n * factorial(n-1);
    }
}
```

1.  点击左侧的**项目**按钮，并更改**发布**和**调试**构建的输出路径，通过编辑**常规**下的**构建目录**行，首先是**发布**，然后是**调试**构建配置。为了做到这一点，从**构建目录**路径中删除`release`和`debug`部分。这样，当你构建你的库时，Qt Creator 会将你的库的发布和调试版本放在一个单独的文件夹中，而不是分别命名为`release`和`debug`的文件夹。

在编写代码时，请注意 Qt Creator 在各个阶段会提示您从头文件中推断出的内容，并提供自动建议（称为**自动建议**）。例如，一旦您键入`MathFunc`，它会提供自动完成类名或 C 预处理器保护；您可以使用鼠标选择其中一个，或者只需按*Enter*获取类名。同样，键入双冒号告诉 Qt Creator 您正在尝试输入`MathFunctions`类，并提示您`MathFunctions`类成员；您可以使用箭头选择`factorial`并按*Enter*，它会自动输入。最后，键入开括号提示 Qt Creator 您正在定义一个函数，并提示您在头文件中定义的该函数的参数。当您输入代码时，您会经常看到这种自动完成；这也是学习 Qt 的好方法，因为您可以键入类名或部分函数名，Qt Creator 会在途中提示您有用的提示。

在继续之前，请确保您已经在发布和调试配置中构建了您的库。这样做的最简单方法是单击左下角的构建选择器，然后选择**发布**或**调试**，然后单击锤子图标进行构建。

# 学习景观——构建菜单和.pro 文件

在上一章中，您学会了如何通过点击 Qt Creator 主窗口角落的锤子按钮或启动调试器来构建应用程序。要构建您的库或任何应用程序，您可以使用锤子图标或**构建**菜单中的各种选项。明显的选择是**构建所有**或**重新构建所有**；选择**构建所有**只重新编译 Qt Creator 识别为需要重新构建的文件；**重新构建所有**清理项目的所有对象文件，并从头开始重新构建整个项目。在大多数情况下，选择**构建所有**就足够了，这也是您想要做的，因为它更快。有时，当 Qt 的`make`系统无法协调所有依赖关系时（或者您已经对依赖关系进行了更改），您确实需要重新构建整个项目。现在选择**构建所有**，并等待它构建，同时我们讨论其他选项。

**构建**菜单允许您构建单个文件——如果您只想检查正在编写的代码的语法并确保没有错误，或者整个项目。它还允许您在调试器之外运行项目，在某些情况下可能需要这样做，比如进行演示。您还可以通过选择**清除所有**来清理项目（删除所有对象文件和其他自动生成的产品）。**发布**选项适用于一些附加工具包，这些工具包允许您将编译的应用程序和库发布到应用商店和存储库；您可以在任何 Qt Creator 插件的文档中找到有关此内容的更多详细信息，例如用于 Maemo 开发的 SDK（诺基亚旧版 Linux 变体，用于手持设备）。

每个 Qt Creator 项目背后都有一个`.pro`文件；这个文件的作用与`make`文件相同，并且实际上是由一个名为`qmake`的 Qt 工具命令处理的。（Make 文件是由`make`命令处理的文件，指示应以何种顺序编译文件以生成可执行文件。）这些文件是声明性的，您在其中声明了构成应用程序的文件之间的关系，`qmake`会从中找出如何构建您的应用程序。在大多数情况下，您可能需要对`.pro`文件进行很少或没有更改，但了解它们的工作原理也无妨。双击`MathFunctions.pro`，您会发现：

```cpp
#-------------------------------------------------
#
# Project created by QtCreator 2013-07-23T19:50:46
#
#-------------------------------------------------

QT       -= gui

TARGET = MathFunctions
TEMPLATE = lib
CONFIG += staticlib

SOURCES += mathfunctions.cpp

HEADERS += mathfunctions.h
unix:!symbian {
    maemo5 {
        target.path = /opt/usr/lib
    } else {
        target.path = /usr/lib
    }
    INSTALLS += target
}
```

`.pro`文件的基本语法是变量赋值；Qt Creator 为我们生成的这个文件分配了以下变量：

+   `QT`变量指示您的项目将链接的 Qt 模块。默认情况下，所有项目都包括 QtCore 和 QtGui；还有大量其他可用的模块，其中包括关键功能，如 WebKit 网络浏览引擎（`QtWebkit`）和多媒体库（`Phonon`）。我们在这里的任务是指出我们使用默认的 Qt 模块，但不链接`QtGui`。

+   `TARGET`变量是编译库或可执行文件的名称。

+   `TEMPLATE`变量指示`qmake`应该使用哪种模板来生成二进制文件；在我们的情况下，我们说它应该使用模板来创建一个`lib`文件-一个库。

+   `CONFIG`变量将额外的配置传递给`qmake`的模板；在这里，我们说我们想要一个静态链接的库。

+   `SOURCES`和`HEADERS`变量包含构成项目的源文件和头文件的列表。

+   `INSTALLS`变量指示应该安装生成的构建产品的位置。在这里，它设置在一个范围内。范围允许您在`qmake`中指定条件选项；范围的条件是一个变量或表达式，可以是`true`或`false`，如果变量为`true`，则执行后面的代码。文件末尾的范围表示：“如果我们正在构建`unix`变体，并且变体不是`symbian`，则将`target.path`变量设置为`/opt/usr/lib`，如果`unix`变体是`maemo`，否则将其设置为`/usr/lib`，对于其他`unix`变体，并且在任何情况下，将`INSTALLS`变量设置为`target`”。

这些是您几乎可以在任何`.pro`文件中找到的基本变量；有关您可以使用的`qmake`范围的详细讨论，可以参见[`bit.ly/163tAIh`](http://bit.ly/163tAIh)。您可能还想了解的两个附加变量是`DEFINES`和`LIBS`；`DEFINES`允许您指定在整个构建过程中应设置的预处理器定义，而`LIBS`指示 Qt Creator 链接项目的附加库。

请注意变量的管理方式：使用`=`进行赋值，使用`+=`向列表中添加项目，使用`-=`从列表中删除项目。

# 链接到我们的示例库

现在，让我们制作一个依赖于我们的库的应用程序。我们的应用程序将调用库中的`factorial`函数，静态链接到库以访问`factorial`函数。为了实现这一点，您需要：

1.  从**文件**菜单中选择**关闭所有项目和编辑器**。

1.  从**文件**菜单中选择**新文件或项目…**，并使用向导创建一个名为`MathFunctionsTest`的新 Qt 控制台应用程序。

1.  右键单击**MathFunctionsTest**，然后选择**添加库**。然后可以选择构建树中的库，构建树之外的库，或者系统上的外部库，如 Unix 数学库、`ffmpeg`或其他您创建的库。选择**外部库**，然后单击**下一步**。

1.  通过单击**浏览**旁边标有**库文件**的行来浏览上一节中构建的库文件。它将在项目文件夹中的名为`build-MathFunctions-Desktop_Qt_5_0_2_MSVC2012_64bit`的文件夹中。在`release`或`debug`文件夹中选择`MathFunctions`库，无论选择哪个都可以。

1.  通过单击**浏览**旁边的**包含路径**来浏览库的包含文件；这是您放置库头文件的目录。

1.  选择静态链接；如果您链接的是动态链接库，当然您会选择**动态**。

1.  将其他值保持为默认值，然后单击**下一步**，然后单击**完成**。

Qt Creator 将使用您的.pro 文件进行魔术操作，添加一个包含您的库构建输出的`LIBS`变量，并包含您的库头文件的包含路径。

现在我们可以调用我们的`factorial`函数。编辑`main.cpp`以读取：

```cpp
#include <QCoreApplication>
#include "MathFunctions.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    qDebug("6! is %d", MathFunctions::factorial(6));

    return a.exec();
}
```

这段代码首先包含了我们的库头文件。请注意，如果你在添加了`#include`声明后编译应用程序，你将为`MathFunctions`库的每个元素获得自动建议帮助。这段代码使用`qDebug`而不是 C 标准库来执行控制台输出。

### 提示

`qDebug()`函数实际上也有一个流智能的实现。我本可以将`qDebug`行写成

```cpp
qDebug() << "6! is" << MathFunctions::factorial(6);
```

代码将生成相同的输出。

现在，在调试模式下构建和运行应用程序；你应该看到一个带有文本`6! is 720`的控制台窗口。尝试在发布模式下构建和运行库；等等，为什么`qDebug`的调试输出还在那里？

`qDebug`实际上不是一个调试日志，它是一个用于调试信息的输出流，不受构建级别限制。如果你想在发布构建中关闭它的输出，你需要编辑`.pro`文件。双击你的`.pro`文件，并添加以下行：

```cpp
CONFIG(release, debug|release): DEFINES += QT_NO_DEBUG_OUTPUT
```

这是另一个范围：它表示如果你的构建配置是发布，将`QT_NO_DEBUG_OUTPUT`预处理器定义添加到项目的预处理器定义列表中。

现在，如果你重新构建（不只是选择构建，而是选择重新构建，因为你希望整个系统进行一次干净的构建）并在发布模式下运行，你将看不到任何输出。

### 提示

Qt 实际上定义了四个输出流，一个用于调试消息，一个用于真正的警告。使用`qDebug`进行常规日志记录，使用`qWarning`输出优先级更高的消息。还有`qCritical`和`qFatal`用于指示关键失败或导致应用程序终止的更高优先级日志消息。你也可以以相同的方式在发布构建中关闭警告；只需将以下内容添加到你的`.pro`文件中：

```cpp
CONFIG(release, debug|release): DEFINES += QT_NO_WARNING_OUTPUT
```

如果你想向项目添加文件怎么办？你可以通过手动编辑`.pro`文件来做，如果你是一个熟练的打字员，这可能更快，但也容易出错，如果搞砸了会导致奇怪的构建问题，或者右键单击你的项目，然后选择**添加新建…**或**添加现有文件…**。**添加新建…**选项打开一个简短的向导，提供了这样的选择：

+   C++头文件和源文件

+   我们将在下一章讨论的 Qt Designer 表单

+   我们将在下一章讨论的 Qt 资源文件

+   Qt Quick 标记（QML）文件

+   JavaScript 文件（可以包含实现 Qt Quick 应用程序逻辑的代码）

+   用于完整 OpenGL 或 OpenGL/ES 中片段或顶点的 OpenGL 着色器

+   文本文件（比如项目的`Readme`文件）或一个用作临时剪贴板项目存放处的草稿文件，直到你完成编辑会话

在我们继续讨论调试的重要主题之前，让我们再看一个应用程序的`.pro`文件：

```cpp
#-------------------------------------------------
#
# Project created by QtCreator 2013-07-23T20:43:19
#
#-------------------------------------------------

QT       += core

QT       -= gui

CONFIG(release, debug|release): DEFINES += QT_NO_DEBUG_OUTPUT

TARGET = MathFunctionsTest
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

SOURCES += main.cpp

win32:CONFIG(release, debug|release): LIBS += -L$$PWD/../build-MathFunctions-Desktop_Qt_5_0_2_MSVC2012_64bit/release/ -lMathFunctions
else:win32:CONFIG(debug, debug|release): LIBS += -L$$PWD/../build-MathFunctions-Desktop_Qt_5_0_2_MSVC2012_64bit/debug/ -lMathFunctions
else:unix: LIBS += -L$$PWD/../build-MathFunctions-Desktop_Qt_5_0_2_MSVC2012_64bit/ -lMathFunctions

INCLUDEPATH += $$PWD/../MathFunctions
DEPENDPATH += $$PWD/../MathFunctions

win32:CONFIG(release, debug|release): PRE_TARGETDEPS += $$PWD/../build-MathFunctions-Desktop_Qt_5_0_2_MSVC2012_64bit/release/MathFunctions.lib
else:win32:CONFIG(debug, debug|release): PRE_TARGETDEPS += $$PWD/../build-MathFunctions-Desktop_Qt_5_0_2_MSVC2012_64bit/debug/MathFunctions.lib
else:unix: PRE_TARGETDEPS += $$PWD/../build-MathFunctions-Desktop_Qt_5_0_2_MSVC2012_64bit-Debug/libMathFunctions.a
```

哦！这相当密集。让我们看看我们能不能解开它。它首先告诉构建系统我们使用 QtCore，但不使用 QtGui。接下来的指令是在发布构建中禁用`qDebug`消息，这不会默认发生。`TARGET`、`CONFIG`和`TEMPLATE`选项一起表示我们正在构建一个名为`MathFunctionsTest`的控制台应用程序。下一行指示我们有一个源文件`main.cpp`。

下一组范围指示了我们库的路径，并处理了我们的库在 Windows 上的`release`和`debug`目录不同的情况——这与 Unix 系统不同，在 Unix 系统中库只有一个`build`变体。之后是`INCLUDEPATH`和`DEPENDPATH`变量，指示`MathFunctions`目录中有库头文件，并且应用程序依赖于这些头文件。因此，如果头文件的时间戳发生变化，二进制文件应该重新构建。最后一个范围指定了对输出库本身的相同依赖；如果库发生变化，应用程序可执行文件必须重新构建。这一点尤为重要，因为这样我们可以运行多个 Qt Creator 的副本，分别编辑我们的库和应用程序文件，在它们发生变化后构建我们需要的部分。当我们这样做时，所有的依赖关系都会被解决，库和应用程序的正确部分会自动构建。

# 迷失和重新找到——调试

Qt Creator 拥有一流的 GUI，可以连接到 GNU 调试器 GDB，或者如果你使用 Microsoft 工具，还可以连接到 Microsoft 的命令行调试器 CDB。

如果你在 Mac OS 或 Linux 上安装了 Qt Creator，或者在 Windows 上安装了 MinGW 版本的 Qt Creator，你已经拥有了开始调试应用程序所需的一切。如果你已经安装了 Microsoft Visual Studio 并安装了使用 Microsoft 编译器的 Qt Creator 版本，你还需要安装 Microsoft 命令行调试器以使用 Qt Creator 的调试功能。以下是安装命令行调试器的方法：

1.  下载 Windows 的调试工具，如果你使用 32 位版本的编译器和 Qt Creator，请访问[`bit.ly/1dWoqi0`](http://bit.ly/1dWoqi0)，如果你使用 64 位版本的编译器和 Qt Creator，请访问[`bit.ly/12kEtGt`](http://bit.ly/12kEtGt)。

1.  通过转到**工具**菜单下的**选项**，选择左侧的**调试器**项目，选择**CDB**选项卡，然后点击**符号路径**行旁边的**编辑**来配置调试符号服务器。

### 提示

通常情况下，Qt Creator 可以直接使用调试器，除非你使用的是 Microsoft 的工具链。但是，如果你遇到问题，请参考 Qt 文档中有关设置调试器的部分，网址是[`bit.ly/19jgycQ`](http://bit.ly/19jgycQ)。

下面的截图显示了调试器在我们的测试项目中的运行情况，停在一个断点上：

![迷失和重新找到——调试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_02_01.jpg)

Qt Creator 的调试视图运行中

让我们仔细看一下截图以便定位：

+   左侧是 Qt Creator 中选择视图的通常按钮行

+   按钮旁边是项目文件的视图和打开文档的列表

+   在主编辑窗格中，每个源代码行都有一个可点击的指示器，让你设置和清除断点。

+   在编辑器窗格下面的窗格中显示了调用堆栈，指示程序如何到达执行停止的行

+   右上角是变量检查器，你可以在当前堆栈帧中看到变量的值，以及任何全局变量。

+   在变量检查器下面是一个待处理断点的列表，这样你就可以在不需要在代码中搜索的情况下打开和关闭断点。

为了生成上面的截图，我点击了第 7 行的左侧，设置了一个断点，然后在构建选择器中确保我指定了一个调试构建，然后点击了左侧的**调试**按钮。Qt Creator 以调试模式构建了应用程序，启动了应用程序，并让它运行到第 7 行的断点处。

## 设置断点和逐行调试程序

断点，如果您以前没有遇到过这个概念，就是这样——执行中断的点，您可以检查程序的状态。一旦在断点处停止，您可以进入函数，或者跳过一行，逐行执行程序，以查看其行为。在**调试**视图中，单击行号左侧可以设置或清除断点。在断点处停止时，编辑窗格边缘的黄色箭头指示处理器即将执行的代码行。

在断点处停止时，调用堆栈窗格上方会出现几个按钮，让您控制程序流程。它们是：

+   绿色继续按钮，继续执行由箭头指示的行。您也可以通过按下*F5*功能键来继续。

+   红色停止按钮，完全停止调试。

+   跳过按钮，执行当前行并在再次停止之前前进到下一行。您可以通过按下*F10*来跳过一行。

+   进入按钮，输入下一个要调用的函数并再次停止。您可以通过按下*F11*来进入函数。

+   跳出按钮，在当前调用上下文中运行函数的其余部分，然后再次停止。您可以通过按下*F11*来跳出当前函数。

+   逐条指令按钮（看起来像一个小屏幕），可以在源代码行和汇编代码行之间切换调试器。

+   还有一个线程菜单，因此您可以看到哪个线程正在运行或停止。

如果（在上一张屏幕截图中）从第**7**行跳过第**8**行（按下*F10*），然后按下*F11*，我们将进入我们的`factorial`函数，就像您在下一张屏幕截图中看到的那样。我已经裁剪了屏幕截图，所以您只能看到调试器中已更改的相关窗格，并且稍微调整了窗口大小，以便您可以看到整个调用堆栈。

![设置断点并逐步执行程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_02_02.jpg)

调试器即将进入函数

此时，如果我们再次步进一行（*F10*），我们将看到右侧列中**n**的值发生变化，并且箭头将前进指向第**9**行（再次，如屏幕截图中编号的那样）。从这里，我们可以以几种方式调试我的函数：

+   通过查看右侧窗格中的变量来检查变量的内容。如果它在当前调用帧的上方的堆栈帧中，我们可以更改调用帧并查看不同调用帧中的变量。

+   我们可以通过单击其值并输入新值来修改变量。

+   使用一些调试器，我们可以将箭头移动到调用函数中的不同行，以跳过一个或多个代码行，或者倒带执行以重新运行代码段。

这个最后的功能——不幸的是，它与 CDB 不兼容——特别强大，因为我们可以逐步执行程序，观察错误，修改变量以解决错误的过程，并继续测试我们的代码，而无需重新编译代码和重新运行可执行文件。或者，我们可以通过替换相关变量的新状态并从当前调用帧的新位置继续，跳过我们知道需要花费很长时间运行的一部分代码。

还有许多其他事情可以做，从调试应用程序的方式到在应用程序运行时查看应用程序状态的各种方式。在主**调试**菜单上，我们可以：

+   通过从**调试**菜单中选择**分离**来从运行中的进程中分离调试器（如果调试器减慢了速度，而我们知道我们的代码的一部分不需要调试，这很方便）。

+   通过从**调试**菜单中选择**中断**来中断程序执行，停止执行并检查当前状态（如果我们的应用程序似乎陷入了一个我们没有预料到的长循环并且似乎挂起，这很有用）。

+   在停止时，我们可以通过选择**运行到行**或按下*Ctrl* + *F10*来运行光标所在的行。

+   停止时，我们可以通过选择**跳转到行**来跳转到光标所在的行。

## 断点的精细控制

如果您在断点窗格中右键单击，可以添加、编辑或删除断点。点击**添加断点…**或**编辑断点…**会弹出断点编辑器，这是一个令人生畏的对话框，鉴于它只是一个简单的断点。以下截图显示了断点编辑器：

![断点的精细控制](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_02_03.jpg)

断点编辑器窗口

从编辑器中，您可以微调断点设置：

+   断点的类型。大多数断点是按文件名和行号进行的——代码的特定行——但您还有其他几种选择，包括：

+   按名称的函数入口点

+   当内存地址被执行到

+   当抛出或捕获 C++异常时

+   当发生 JavaScript 异常时

+   当您的主函数开始时

+   当一个新进程被分叉时

+   当系统调用发生时

+   当在固定位置访问数据，或者在运行时涉及指针变量的表达式指示的地址时

+   断点的位置（例如源行号和文件名，或函数），取决于您在上一个列表中的选择。

+   无论断点是否启用。

+   断点是否是一次性的，也就是说，触发一次后将被禁用。

+   断点的条件，例如涉及程序变量值的表达式，忽略断点的次数以及断点适用于哪些线程。

## 检查变量和内存

变量窗格显示当前堆栈帧中所有变量的值。结构显示其成员的值，因此您也可以遍历复杂的数据结构。从变量窗格中，您还可以将变量名称和值复制到剪贴板，或者只复制变量值。

从变量窗格中，有一个非常有用的功能称为**表达式求值器**，它允许您构建关于代码中变量的代数表达式并查看结果。例如，如果我停在`factorial`函数的开头，就像您在*调试器即将进入函数*截图中看到的那样，**n**设置为`6`，我可以右键单击变量窗格，选择**插入新表达式求值器**，然后在出现的对话框中输入一个公式`n*(n-1)`，然后窗格中会出现一个新行，显示表达式和值**30**。虽然这是一个相当牵强的例子，但我也可以查看指针值和指针解引用。

当变量发生变化时，我还可以有条件地中断执行；这称为条件断点或数据断点。例如，让我们在主函数中放一个循环，并在执行循环时中断。要做到这一点，首先更改`main`如下：

```cpp
#include <QCoreApplication>
#include <QDebug>
#include "MathFunctions.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    int values[] = { 6, 7, 8 };

    for(int i = 0; i < sizeof(values)/sizeof(int); i++)
    {
        qDebug() << values[i]
                 << "! = "
                 << MathFunctions::factorial(values[i]);
    }

    return a.exec();
}
```

这将遍历整数数组值中存储的值，并打印每个值的计算阶乘。重新开始调试，然后让我们在`i`上添加一个数据断点。要做到这一点：

1.  在`main`的第一行上设置一个断点，该行初始化`QCoreApplication`。

1.  在左窗格中右键单击`i`，然后从**添加数据断点**子菜单中选择**在对象地址处添加数据断点**。

1.  按下*F5*或**继续**按钮继续。

当`i`设置为`0`时，执行将在第**11**行停止，即`for`循环的开始。每次我按下*F5*继续，应用程序都会运行，直到`i`的值因`for`循环末尾的`i++`语句而发生变化。

您还可以通过单击变量检查器窗格中数组名称旁边的展开箭头来检查和更改数组的单个值。

除了查看和更改变量值，您还可以查看和更改单个内存位置。例如，如果您需要查看内存中的特定位置，例如调试二进制格式的解码器或编码器，您可能需要这样做。从变量窗格中，您有几个选择：

+   您可以右键单击给定变量并在该变量地址处打开内存窗口

+   您可以右键单击给定变量并在变量指向的值处打开内存窗口（换句话说，解引用指向内存位置的指针）

+   您可以右键单击变量窗格，并在当前堆栈帧的开头打开内存浏览器

+   您可以右键单击变量窗格，并在内存中的任意位置打开内存浏览器

以下屏幕截图显示了内存查看器显示包含数组值的内存：

![检查变量和内存](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_02_04.jpg)

内存查看器窗口

窗口显示左侧的内存地址，每行十六个字节的内存值（先是十六进制，然后是 ASCII），并且突出显示你选择打开窗口的实际变量。您可以选择一系列值，然后右键单击执行以下操作：

+   以 ASCII 或十六进制形式复制值

+   在您选择的内存位置上设置数据断点

+   将执行转移到您单击的地址（如果您正在查看数据，这可能不是您想要做的）

## 检查调用堆栈

**调用堆栈**是应用程序执行在某一时间点的函数调用层次结构。虽然实际流程各不相同，但通常在您的代码中，它始于`main`，尽管调用`main`的内容因平台而异。调用堆栈的一个明显用途是在按下**中断**按钮时提供上下文；如果您的程序在某个地方的循环中只是在思考问题，点击**中断**并查看调用堆栈可以给您一些线索。

还记得我如何定义`factorial`函数吗？如果您在`factorial`中设置断点，调用它，并在查看调用堆栈之前继续通过断点几次，您将看到类似以下屏幕截图的内容：

![检查调用堆栈](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_02_05.jpg)

递归函数的调用堆栈在中间计算时

从左到右，调用堆栈窗口的字段是堆栈级别（从堆栈顶部向下编号），正在调用的函数，定义函数的文件，以及当前正在执行的函数的行号。因此，这个堆栈帧表示我们在`mathfunctions.cpp`的`MathFunctions::factorial`的第**9**行，由`MathFunctions::factorial`的第**13**行调用，依此类推，直到在我们的`main`函数中结束，并在此之前是操作系统用来设置应用程序进程的系统启动代码。

如果您右键单击调用堆栈窗格的一行，您可以：

+   重新加载堆栈，以防显示出现损坏。

+   将调用堆栈的内容复制到剪贴板；这对于错误报告非常有用。如果您的应用程序在调试器中抛出异常或崩溃，您可以复制调用堆栈并将其发送给负责该部分代码的开发人员（或者留作纪念品）。

+   在调用堆栈中函数调用所指示的代码行的指令地址处打开内存编辑器。

+   在调用堆栈中函数调用所指示的代码行的指令地址处打开反汇编器。

+   反汇编内存区域或当前函数。

+   在调试时在调用堆栈窗口中显示程序计数器地址。

# 项目窗格和构建项目

您已经看到了`.pro`文件如何影响项目的编译，但它的作用远不止于此。如果您在 Qt Creator 左侧点击**项目**按钮，您将看到项目选项，包括**构建和运行**选项，**编辑器**选项，**代码样式**选项和**依赖项**，每个选项都有自己的面板。

在大多数情况下，您不需要调整这些设置。但是，您可能需要调整**构建和运行**设置，特别是如果您要针对多个平台进行目标设置，例如使用交叉编译器在 Windows 和 Linux 上，或者在 Digia 完成对这些平台的支持后，在 Android 和 iOS 上。 （我稍后会在本书的后面更多地介绍这一激动人心的 Qt 发展。）

您应该知道的最后一件事是构建和运行工具包选择器。Qt 是当今最好的跨平台工具包之一，您很容易发现自己在支持多个平台的系统上工作，例如 Linux 和 Android，或者 Qt 的多个版本。为了支持这一点，Qt 有一个构建工具包的概念，它只是支持特定平台的头文件、库和相关内容。您可以安装多个构建工具包，并通过选择**打开构建**和**运行工具包选择器…**来选择您要编译的构建工具包。默认情况下，如果您按照上一章中的步骤安装了 Qt Creator，您将安装一个构建工具包；从 Digia 网站上，您可以选择其他工具包。在后面的章节中，我们将为 Android 上的 Qt 构建一个示例应用程序。为此，您需要下载并安装 Qt on Android 构建工具包，然后告诉 Qt Creator 有关新工具包。添加工具包很容易，您只需要在 Qt Creator 中安装工具包，然后按照以下步骤操作：

1.  点击左侧的**项目**。

1.  单击出现的面板左上角的**管理工具包…**。**构建和运行**选项窗口将出现。

1.  Qt 可能会自动检测到您的新工具包，或者您可能需要通过单击**添加**来添加它。单击**添加**后，您需要指定目标平台（例如 Android 设备）、要使用的编译器等。

对于构建设置，有发布和调试构建的配置选项。在**构建设置**编辑器中，您可以控制构建产品是否放置在它们自己的目录中（默认情况下，所谓的影子构建，其中您的构建输出与源代码混合），构建的`qmake`配置（实际上看到 Qt Creator 将如何调用`qmake`），Qt Creator 如何清理您的项目，以及您需要为构建设置的任何环境变量。

运行设置让您控制应用程序是在本地运行还是部署到远程主机（不一定始终支持，但通常适用于诸如 Android 之类的平台），您想要传递给应用程序的任何命令行参数，以及性能分析工具的设置，我将在第四章中更多地谈到*使用 Qt Linguist 本地化您的应用程序*。

在**编辑器**面板中，您可以为此项目设置特定的编辑器选项。这些选项会覆盖全局 Qt Creator 默认设置，您可以通过选择**工具**菜单中的**选项**并选择**文本编辑器**选项来设置这些选项。这些选项包括诸如在格式化代码时是否使用制表符或空格（我强烈建议您使用空格；它与任何编辑器兼容）、每个制表位的空格数、是否自动缩进、源文件应该如何编码等细节。

**代码风格**面板是 Qt Creator 全局设置的另一个覆盖（这次是 C++和 Qt Quick 面板，可以从**选项**菜单中的**选项**对话框中找到）。在这里，您可以选择默认样式，或编辑样式。

### 提示

我强烈建议您选择与您正在编辑的现有源代码相匹配的样式；如果您是从空白页面开始的，Qt 默认样式非常易读，也是我最喜欢的。

**依赖项**面板允许您设置构建顺序，如果您的项目文件包含多个子项目，以便以正确的顺序构建事物。例如，我们可以选择同时打开我们的库项目和测试项目；如果我们这样做，我们将在依赖项中看到`MathFunctions`库，并且我们可以选择在构建测试应用程序之前构建该项目。

# 回顾-运行和调试您的应用程序

在 Qt Creator 中，您将花费大量时间编辑、编译和调试代码，因此，记住以下基础知识是明智的：

+   箭头键在不使用调试器的情况下运行您的应用程序；要调试您的应用程序，请选择带有错误图标的箭头键。

+   您可以通过单击左侧的**编辑**或**调试**视图选择在编辑器视图和调试视图之间切换您的应用程序；如果调试您的应用程序，Qt Creator 将自动进入调试视图。

+   断点比仅仅在代码行停止更有用！使用数据断点来帮助确定只有在某些时候发生的奇怪错误，或者快速跳过大循环的前几个项目。

+   变量窗格让您不仅可以查看变量的内容；您还可以添加由多个变量和算术组成的表达式，或查看任意内存位置。

+   想要在调试会话期间解决错误？您可以在变量窗格中更改变量的值并继续运行，随着程序的进行改变程序状态。

# 总结

Qt Creator 集成开发环境包含编辑器和工具，用于启动编译器、链接器和调试器以构建和调试您的应用程序。使用它，您可以启动和停止应用程序，在应用程序停止时设置断点，或检查应用程序的变量或逻辑流程。

虽然 Qt Creator 为您管理大部分项目，但有时您必须亲自动手处理`.pro`文件。您可以使用作用域来处理条件编译（例如在为特定平台构建时，或者文件是否应包含在发布或调试模式中）。`.pro`文件由作用域、变量及其值组成；通过设置`.pro`文件提供给`qmake`的变量，`qmake`了解项目中的依赖关系，并神奇地创建一个 Make 文件来构建您的应用程序。

在下一章中，我们将从制作项目构建的机制转向 Qt Creator 的 UI 设计师，并为您简要介绍 Qt Widgets 和 Qt Quick 的世界。


# 第三章：使用 Qt Designer 设计您的应用程序

Qt 可能最为人所知的是一个跨平台用户界面工具包，直到最近几年，Qt Creator 才真正发展成为一个完整的软件开发环境。然而，即使在早期版本中，Qt 也具有了一个优秀的用于使用 Qt Designer 构建用户界面的工具，现在已经成为 Qt Creator 的一部分。最近，构建 Qt 的开发人员添加了 Qt Quick 作为用户界面开发的第二个选项。Qt Quick 扩展了 Qt 库和 Qt Creator 的 Qt Designer 功能，用于构建触摸屏和机顶盒的流畅界面，并促进了 Qt Quick 和**Qt 元对象语言**（**QML**）的声明性特性。

在本章中，我们将学习如何使用 Qt Designer 创建用户界面，Qt Designer 是 Qt Creator 中的用户界面构建器。我们首先介绍了理解 Qt 框架的关键概念：**信号**和**槽**。接下来，我们重新使用 Qt Designer 创建应用程序表单，这是在使用 Qt Widgets 时用户界面的基础。我们还介绍了如何添加资源并在应用程序中访问它们，这是用户界面设计的重要方面。然后，我们回到代码中，构建了你在第一章 *使用 Qt Creator 入门*中学到的 QML 基础知识。在本章结束时，你将能够决定你的应用程序应该使用 Qt GUI 还是 Qt Quick，并且能够借助 Qt Creator 附带的文档构建你的应用程序。

# 代码插曲 - 信号和槽

在软件系统中，通常需要耦合不同的对象。理想情况下，这种耦合应该是松散的，即不依赖于系统的编译时配置。当考虑用户界面时，这一点尤为明显；例如，按钮按下可能会调整文本窗口的内容，或者导致某些东西出现或消失。许多系统使用事件来实现这一目的；提供数据的组件将数据封装在事件中，事件循环（或者最近更常见的事件监听器）捕获事件并执行某些操作。

Qt 提供了更好的方法：信号和槽。就像事件一样，发送组件生成一个信号—在 Qt 术语中，对象发出一个信号—接收对象可以在槽中接收这个信号以进行处理。Qt 对象可以发出多个信号，信号可以携带参数；此外，多个 Qt 对象可以连接到相同的信号上的槽，这样可以轻松地安排一对多的通知。同样重要的是，如果没有对象对信号感兴趣，它可以被安全地忽略，没有连接到信号的槽。任何继承自`QObject`的对象，Qt 的对象基类，都可以发出信号或提供用于连接到信号的槽。在底层，Qt 为声明信号和槽提供了对 C++语法的扩展。

一个简单的例子将有助于澄清这一点。在 Qt 文档中找到的经典例子是一个很好的例子，我们将在这里再次使用它，并进行一些扩展。想象一下你需要一个计数器，即一个包含整数的容器。在 C++中，你可能会这样写：

```cpp
class Counter
{
public:
  Counter() { m_value = 0; }
  int value() const { return m_value; }
  void setValue(int value);

private:
  int m_value;
 };
```

`Counter`类有一个私有成员`m_value`，存储它的值。客户端可以调用`value`来获取计数器的值，或者通过调用`setValue`来设置它的值为新值。

在 Qt 中，使用信号和槽，我们这样写这个类：

```cpp
#include <QObject>

class Counter : public QObject
{
  Q_OBJECT

public:
  Counter() { m_value = 0; }

  int value() const { return m_value; }

   public slots:
  void setValue(int value);
  void increment();
  void decrement();

signals:
  void valueChanged(int newValue);

private:
  int m_value;
};
```

这个`Counter`类继承自`QObject`，这是所有 Qt 对象的基类。所有`QObject`子类必须在其定义的第一个元素中包含声明`Q_OBJECT`；这个宏会扩展为 Qt 代码，实现了特定于子类的粘合剂，这是 Qt 对象和信号槽机制所必需的。构造函数保持不变，将我们的私有成员初始化为零。同样，访问器方法`value`保持不变，返回计数器的当前值。

对象的槽必须是公共的，并且使用 Qt 对 C++的扩展公共槽进行声明。这段代码定义了三个槽：一个`setValue`槽，它接受计数器的新值，以及`increment`和`decrement`槽，它们增加和减少计数器的值。槽可以接受参数，但不返回参数；信号和槽之间的通信是单向的，由信号发起并以连接到信号的槽终止。

计数器提供了一个单一的信号。与槽一样，信号也是使用 Qt 对 C++的扩展`signals`声明的。在上面的示例中，一个`Counter`对象发出带有单个参数的信号`valueChanged`，这个参数是计数器的新值。信号是一个函数签名，而不是一个方法；Qt 对 C++的扩展使用信号和槽的类型签名来确保信号-槽连接之间的类型安全，这是信号和槽相对于其他解耦的消息传递方案的一个关键优势。

作为开发人员，我们有责任使用适当的应用逻辑在我们的类中实现每个槽。`Counter`类的槽看起来像这样：

```cpp
void Counter::setValue(int newValue)
{
  if (newValue != m_value) {
      m_value = newValue;
      emit valueChanged(newValue);
  }
}

void Counter::increment()
{
  setValue(value() + 1);
}

void Counter::decrement()
{
  setValue(value() – 1);
}
```

我们使用`setValue`槽的实现作为一个方法，这就是所有槽在本质上都是什么。`setValue`槽接受一个新值，并将新值赋给`Counter`类的私有成员变量，如果它们不相同的话。然后，信号发出`valueChanged`信号，使用 Qt 扩展`emit`，这会触发对连接到信号的槽的调用。

### 提示

这是处理对象属性的信号的常见模式：测试要设置的属性是否与新值相等，只有在值不相等时才分配和发出信号。

如果我们有一个按钮，比如`QPushButton`，我们可以将它的 clicked 信号连接到`increment`或`decrement`槽，这样点击按钮就会增加或减少计数器。我会使用`QObject::connect`方法来做到这一点，就像这样：

```cpp
QPushButton* button = new QPushButton(tr("Increment"), this);
Counter* counter = new Counter(this);
QObject::connect(button, SIGNAL(clicked(void)),
                 Counter, SLOT(increment(void));
```

我们首先创建`QPushButton`和`Counter`对象。`QPushButton`构造函数接受一个字符串，按钮的标签，我们将其表示为字符串`Increment`或其本地化对应物。

为什么我们要将 this 传递给每个构造函数？Qt 在 QObjects 和它们的后代之间提供了父子内存管理，简化了在使用对象时的清理工作。当您释放一个对象时，Qt 也会释放父对象的任何子对象，因此您不必这样做。父子关系在构造时设置；我在构造函数中发出信号，当调用此代码的对象被释放时，按钮和计数器也可能被释放。（当然，调用方法也必须是`QObject`的子类才能起作用。）

接下来，我调用`QObject::connect`，首先传递源对象和要连接的信号，然后传递接收对象和应该发送信号的槽。信号和槽的类型必须匹配，并且信号和槽必须分别包装在`SIGNAL`和`SLOT`宏中。

信号也可以连接到信号，当这种情况发生时，信号被链接在一起，并触发连接到下游信号的任何槽。例如，我可以这样写：

```cpp
Counter a, b;
QObject::connect(&a, SIGNAL(valueChanged(int)),
                 &b, SLOT(setValue(int)));
```

这将计数器`b`与计数器`a`连接起来，这样对计数器`a`值的任何更改也会改变计数器`b`的值。

信号和槽在 Qt 中被广泛使用，用于用户界面元素以及处理异步操作，比如网络套接字上的数据存在和 HTTP 事务结果。在底层，信号和槽非常高效，归结为函数调度操作，因此您不应该犹豫在自己的设计中使用这种抽象。Qt 提供了一个特殊的构建工具，元对象编译器，它编译了信号和槽所需的 C++扩展，并生成了实现机制所需的额外代码。

# 在 Qt Designer 中创建表单

让我们使用 Qt Designer 和两个表单创建一个简单的计算器应用程序：一个表单用于获取算术运算的参数，另一个对话框表单用于呈现结果。我将在本章中进行两次演示，首先向您展示如何使用 Qt GUI 进行此操作，然后再使用 Qt Quick。这个例子是刻意构造的，但将向您展示如何在两种环境中创建多个用户界面表单，并让您练习处理信号和插槽。

## 创建主表单

在第一章中，*使用 Qt Creator 入门*，您学习了 Qt GUI Designer 的基本元素，包括可以使用的小部件调色板，中央编辑窗格，对象树和属性视图。以下屏幕截图再次显示了 Qt Designer：

![创建主表单](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_03_01.jpg)

Qt Creator 的 Qt GUI 应用程序设计器

从左到右，您看到的屏幕部分依次是：

+   视图选择器，目前指示 Qt Designer 视图处于活动状态

+   您可以在表单上布局的可能小部件的调色板

+   表单编辑器，在连接编辑器上方，可让您在小部件之间连接信号和插槽

+   对象树，指示已在表单上布置的所有对象，并通过使用嵌套列表显示它们的父子关系

+   在对象树下方是属性编辑器，您可以在表单编辑器上选择的任何项目的编译时属性

让我们从创建一个新的 Qt GUI 项目开始（从**新文件或项目...**对话框中选择**Qt Gui Application**），将项目命名为`QtGuiCalculator`，然后按照以下步骤操作：

1.  在项目的**Forms**文件夹中，双击`mainwindow.ui`文件。设计器将打开。

1.  从调色板中拖出**垂直布局**。

1.  右键单击布局，选择**布局**，然后选择**调整大小**。布局将缩小到一个点。

1.  拖动两个**行编辑**小部件并将它们放在对象查看器中的垂直布局上（最右边的窗格）。您将看到垂直布局会扩展以接受每个行编辑器。您现在应该有类似以下屏幕截图的东西：![创建主表单](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_03_07.jpg)

第一个两个文本字段后的布局

1.  拖动**水平布局**并将其放在对象查看器中的垂直布局上。

1.  在您刚刚添加的水平布局上拖放四个**Push Button**小部件。

1.  调整包含窗口的大小，以便整个布局显示在窗口中。

1.  使用右下角的属性浏览器将按钮重命名为`plusButton`，`minusButton`，`timesButton`和`divideButton`。在这样做时，向下滚动到**text**属性（在**QAbstractButton**下）并为每个按钮赋予类似`+`，`-`，`*`和`/`的逻辑标签。

1.  选择顶部输入行并将其命名为`argument1Input`。

1.  选择底部输入行并将其命名为`argument2Input`。

下一个屏幕截图显示了到目前为止在 Qt Designer 表单编辑器窗格中应该看到的内容。您还可以通过打破布局并使用鼠标定位按钮来手动排列按钮，但这通常会使您的布局对窗口调整大小的鲁棒性降低，并且通常不是一个好主意：

![创建主表单](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_03_02.jpg)

我们的计算器用户界面

到目前为止，这很简单。我们使用了垂直布局和水平布局来布置各种控件；这充分利用了 Qt 对小部件布局和大小的动态约束。所有小部件都有最小和最大尺寸，布局使用这些尺寸来确定小部件实际占用的大小。一些小部件是弹性的；也就是说，它们会拉伸以填充其内容。在指定小部件的实际大小时，您可以指定它在 x 和 y 轴上的以下值之一：

+   小部件的最小尺寸

+   小部件的最大尺寸

+   在其最小和最大之间的固定大小

+   一个扩展大小，扩展以适应小部件内容的大小

Qt 提供了四种布局，您可以像我们刚刚做的那样混合和匹配。您已经遇到了垂直和水平布局；还有一个网格布局，它可以让您在*m*×*n*网格中组织事物，还有一个表单布局，它可以以类似于本机平台枚举表单字段的方式组织小部件。

现在，我们的布局有点拥挤。让我们添加一些间隔符，以更好地填充窗口中的空间，并添加一个关于框的按钮：

1.  拖动**垂直间隔符**，并将其放置在输入行之间，然后在包含按钮行的水平布局和输入行之间再添加一个垂直间隔符。

1.  将一个**工具按钮**小部件拖到垂直布局中，并在底部行和按钮之间添加一个间隔符。

1.  将最后一个按钮命名为`aboutButton`，并给它文本`关于`。稍后我们将添加一个图标。

如果按下**运行**按钮，下面的屏幕截图显示了我们在设计师中构建的应用程序：

![创建主窗体](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_03_03.jpg)

我们应用程序的主窗口

现在，让我们制作我们的结果对话框。右键单击项目，选择**添加新内容…**，然后：

1.  在出现的对话框中，选择左侧的**Qt**，然后在中间选择**Qt 设计师表单**。点击**选择**。

1.  为您的对话框选择对话框样式；选择**底部带按钮的对话框**，然后点击**下一步**。

1.  将文件命名为`resultdialog.ui`，然后点击**下一步**。

1.  点击**完成**。

1.  在出现的对话框中，拖出**表单布局**。右键单击它，选择**布局**和**调整大小**。

1.  将一个**标签**小部件添加到表单布局中。将其文本更改为`结果`。

1.  拖出另一个标签，并将其命名为`结果`。

现在可能是您尝试布局和间隔符，并以您希望的任何方式样式化对话框的好时机。

## 使用应用程序资源

现在，让我们为**关于**按钮向应用程序添加一个图标。您可以绘制一个，或者去 The *Noun Project*（[`bit.ly/16n9bOk`](http://bit.ly/16n9bOk)）等网站寻找合适的图标。图标可以是 PNG、JPEG 或其他格式；一个不错的选择是 SVG，因为 SVG 图像是基于矢量的，可以正确缩放到不同的大小。将资源文件放在您的项目目录中，然后：

1.  在 Qt Creator 中选择**编辑**视图。

1.  右键单击解决方案，然后点击**添加新内容…**；然后，选择**Qt**和**Qt 资源文件**。

1.  将文件命名为`资源`。

1.  将其添加到当前项目中。

1.  如果`resources.qrc`尚未在编辑器中打开，请在解决方案窗格中双击它。资源文件编辑器将出现。

1.  点击**添加**，选择**添加前缀**，并添加前缀`/`。

1.  再次点击**添加**，选择**添加文件**，然后选择您的图标。

图标是通过 Qt 资源编译器加载到应用程序的只读段中的。您可以通过在资源的路径和名称前加上冒号来在任何地方访问它们，就像访问文件一样。例如，我们可以将一个文本文件放在我们的应用程序资源中，然后像这样打开文件进行读取：

```cpp
QFile file(":/data/myfile.txt");
file.open(QIODevice::ReadOnly | QIODevice::Text);

while (!file.atEnd()) {
  QByteArray line = file.readLine();
  process_line(line);
}
```

应用程序资源适用于文本和小媒体文件，如图标或图像。但是，您应该避免将它们用于像电影和大型声音这样的较大项目，因为它们会不必要地膨胀应用程序二进制文件的大小。对于这些目的，最好将媒体文件与应用程序打包在一起，并直接从磁盘加载它们。

在下一节中，当我们向应用程序添加关于框时，我们将使用您添加的资源。

# 在您的应用程序中实例化表单、消息框和对话框

Qt Designer 为您在设计器中创建的每个表单生成基于 XML 的布局文件（以 `.ui` 结尾）。在编译时，Qt Creator 将布局编译为一个头文件，用于构建用户界面布局的组件。Qt 应用程序通常使用的模式是构建一个私有布局类，该类由主窗口或对话框的构造函数实例化，然后实例化用户界面。以下是主窗口的工作原理：

```cpp
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
  class MainWindow;
}

class ResultDialog;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H

// In mainwindow.cpp:
#include "mainwindow.h"

// mainwindow.cpp
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
{
    ui->setupUi(this);
}
```

`Ui::MainWindow` 类是由 Qt Designer 自动构建的；通过在 `mainwindow.cpp` 中包含它的声明，我们创建了一个实例并将该实例分配给 `ui` 字段。一旦初始化，我们调用它的 `setupUi` 函数，该函数创建了您在 Qt Designer 中勾画出的整个用户界面。

我们在 Qt Designer 中布置的控件可以作为字段名访问。例如，我们可以修改 `mainwindow.cpp`，通过在 `mainwindow.h` 中添加一个槽来处理单击 **About** 按钮时的情况，并在槽的实现中添加代码来调用关于框。要做到这一点，请按照以下步骤进行：

1.  在 `mainwindow.h` 中添加一个 `public slots` 声明，以及一个名为 `aboutClicked` 的槽。现在应该是这样的：

```cpp
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void aboutClicked();

private:
    Ui::MainWindow *ui;
};
```

1.  将 `aboutClicked` 槽的实现添加到 `mainwindow.cpp`。此代码在堆栈上构造了一个 `QMessageBox` 对象，并将其图标设置为您之前添加的图标，对话框的文本设置为 `"Lorem ipsum"`，消息框的标题设置为 `"About"`。`QMessageBox` 调用的 `exec` 方法打开消息框并阻塞应用程序流，直到您关闭消息框。它应该是这样的：

```cpp
void MainWindow::aboutClicked()
{
    QMessageBox messageBox;
    messageBox.setIconPixmap(QPixmap(":/icon.png"));
    messageBox.setText("Lorem ipsum.");
    messageBox.setWindowTitle("About");
    messageBox.exec();
}
```

1.  在 `mainwindow.cpp` 的顶部，为 `QMessageBox` 类添加一个 `include` 语句：

```cpp
#include <QMessageBox>
```

1.  在 `MainWindow` 构造函数中，将关于按钮的信号连接到刚刚创建的槽。您的构造函数现在应该是这样的：

```cpp
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    results(0)
{
    ui->setupUi(this);
    QObject::connect(ui->aboutButton, SIGNAL(clicked()),
                     this, SLOT(aboutClicked()));
}
```

如果我们构建应用程序，现在我们有一个完全功能的关于框，包括您选择的应用程序图标。`connect` 调用就像我们之前看到的信号槽连接一样；它将 `aboutButton` 的 `clicked` 信号连接到主窗口 UI 中的 `aboutClicked` 槽。

在继续之前，我们先来谈谈命名信号和槽：信号通常以动词的过去时命名，表示刚刚发生的事件的语义，它试图发出信号。槽应该以某种方式匹配这些语义，最好包括有关如何处理信号的更多细节。因此，Qt 逻辑上将按钮的 `clicked` 信号命名，我通过给槽命名为 `aboutClicked` 来扩展这一点。当然，您可以根据自己的喜好命名信号和槽，但这是一个很好的实践方法。

在我们连接其他按钮并实现计算器逻辑之前，我们需要为我们的 `results` 对话框设置类。我们将遵循 `MainWindow` 类的模式，创建一个包含编译时生成的构建结果对话框 UI 的对象实例的私有 `ui` 成员。您可以通过右键单击项目并选择 **Qt Designer Form Class** 来使用 **New File** 向导创建 `ResultDialog` 类，并将其命名为 `ResultDialog`。该类本身应该继承自 `QDialog`。头文件应该如下所示：

```cpp
#ifndef RESULTDIALOG_H
#define RESULTDIALOG_H

#include <QDialog>

namespace Ui {
    class Dialog;
}

class ResultDialog : public QDialog
{
    Q_OBJECT
public:
    explicit ResultDialog(QWidget *parent = 0);
    ~ResultDialog();
private:
    Ui::Dialog *ui;

};

#endif // RESULTDIALOG_H
```

我们需要做的第一件事是在 `Ui` 命名空间中前向声明由 Qt Designer 创建的 `Dialog` 类；然后，我们需要将该类的实例的指针声明为私有成员变量；我们将这个指针命名为 `ui`，就像对 `MainWindow` 类所做的那样。

您可以猜到我们的 `ResultDialog` 实现是什么样的：

```cpp
#include "resultdialog.h"
#include "ui_resultdialog.h"

ResultDialog::ResultDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);

}

ResultDialog::~ResultDialog()
{
    delete ui;
}
```

在构造时，它创建了我们的 `Ui:Dialog` 类的一个实例，然后调用其 `setupUi` 方法，在运行时创建用户界面的实例。

# 连接 Qt GUI 应用程序逻辑

计算器的应用逻辑很简单：我们在`ResultDialog`实现中添加了一个属性设置器，它让我们设置对话框的`result`字段，然后在`MainWindow`中连接一些算术、信号和槽，以进行实际计算并显示对话框。

首先，更改`ResultDialog`：

```cpp
void ResultDialog::setResult(float r)
{
    ui->result->setText(QString::number(r));
}
```

这种方法接受一个浮点数，显示在对话框中，并使用 Qt 的默认格式将结果格式化为字符串。Qt 是完全国际化的；如果在使用英语的区域中进行此操作，它将使用小数点，而如果在区域设置为使用逗号作为小数分隔符的地区中进行此操作，它将使用逗号。`number`方法是一个方便的方法，它有多个重载，接受双精度和浮点数，以及整数，并带有参数来指示返回字符串的精度和指数。

现在，修改后的`MainWindow`类。首先，修改后的类声明：

```cpp
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPair>

namespace Ui {
    class MainWindow;
}

class ResultDialog;

class MainWindow : public QMainWindow
{
    Q_OBJECT

    typedef QPair<float, float> Arguments;

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    Arguments arguments();

signals:
    void computed(float f);

public slots:
    void aboutClicked();
    void plusClicked();
    void minusClicked();
    void timesClicked();
    void divideClicked();

    void showResult(float r);
private:
    Ui::MainWindow *ui;
    ResultDialog* results;
};

#endif // MAINWINDOW_H
```

除了基类`QMainWindow`之外，我现在还包括`QPair`，这是一个简单的 Qt 模板，让我们可以传递一对值。我们将使用`QPair`模板，类型定义为`Arguments`，来传递算术操作的一对参数。

我添加了一个信号`computed`，这个类在执行算术操作时触发任何时间。我还为每个算术按钮点击添加了槽：`plusClicked`、`minusClicked`、`timesClicked`和`dividedClicked`。最后，我添加了一个`showResult`信号，当发生计算时显示结果。

`MainWindow`的构造函数现在需要为所有按钮、信号和槽进行一堆信号-槽连接：

```cpp
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    results(0)
{
    ui->setupUi(this);
    QObject::connect(ui->aboutButton, SIGNAL(clicked()),
                     this, SLOT(aboutClicked()));
    QObject::connect(this, SIGNAL(computed(float)),
                     this, SLOT(showResult(float)));
    QObject::connect(ui->plusButton, SIGNAL(clicked()),
                     this, SLOT(plusClicked()));
    QObject::connect(ui->minusButton, SIGNAL(clicked()),
                     this, SLOT(minusClicked()));
    QObject::connect(ui->timesButton, SIGNAL(clicked()),
                     this, SLOT(timesClicked()));
    QObject::connect(ui->divdeButton, SIGNAL(clicked()),
                     this, SLOT(divideClicked()));
}
```

将关于按钮连接到显示关于对话框的槽之后，我接下来将`MainWindow`的计算信号连接到其`showResult`槽。请注意，此信号/槽携带一个参数，要显示的值。剩下的四个连接将每个操作按钮与执行特定算术操作的代码连接起来。

`showResult`槽如果我们还没有一个，就创建一个新的`ResultDialog`对象，将其结果设置为传入的值，并调用对话框：

```cpp
void MainWindow::showResult(float r)
{
    if (!results)
    {
        results = new ResultDialog();
    }
    results->setResult(r);
    results->exec();
}
```

`arguments`方法是一个辅助方法，每个算术函数都使用它，它从每个输入行中获取值，将它们从字符串转换为浮点数，并进行一些错误检查，以确保条目是有效的浮点数。

```cpp
MainWindow::Arguments MainWindow::arguments()
{
    bool ok1, ok2;
    float a1 = ui->argument1Input->text().toFloat(&ok1);
    float a2 = ui->argument2Input->text().toFloat(&ok2);
    if (!ok1 || !ok2)
    {
        QMessageBox messageBox;
        messageBox.setIconPixmap(QPixmap(":/icon.png"));
        messageBox.setText("One of your entries is not a validnumber.");
        messageBox.setWindowTitle("Error");
        messageBox.exec();
    }
    return Arguments(a1, a2);
}
```

`QString`方法`toFloat`就是这样做的：它将一个字符串转换为浮点数，返回该数字，并且如果转换成功，则将传入的布尔值设置为`true`，否则设置为`false`。代码对两个参数输入行都这样做，然后检查生成的布尔值，并在任一参数格式错误时报告错误，然后将参数的 QPair 返回给调用者。

剩下的代码实际上执行算术运算，在操作完成时发出计算已完成的信号。例如，考虑`plusClicked`槽：

```cpp
void MainWindow::plusClicked()
{
    Arguments a = arguments();
    emit computed(a.first + a.second);
}
```

使用`arguments`函数从输入行获取参数，计算总和，然后发出带有总和值的计算信号。因为我们将计算信号连接到`showResults`槽，这将触发对`showResults`的调用，如果需要，它将创建`ResultDialog`对象，并显示带有计算结果的对话框。`minusClicked`、`timesClicked`和`divideClicked`方法都是类似的。

## 学习更多关于 Qt GUI 小部件

有关使用 Qt GUI 小部件集进行编程的整本书：这是一个非常丰富的小部件集，包括构建普通 Macintosh、Windows 或 Linux 应用程序所需的几乎所有内容，并且具有 UI 控件对大多数计算机用户来说都很熟悉的优势。要进一步探索，请参阅[`bit.ly/17stfw3`](http://bit.ly/17stfw3)上的 Qt 文档。

# 代码插曲-Qt Quick 和 QML 语法

你在最低级别的大部分编程都是命令式的：你描述算法应该如何工作（“取这个值并平方”，“搜索这个字符串的第一个出现并替换它”，“以这种方式格式化这个数据”等）。在 Qt Quick 中，你的编程主要是声明式的：你不是说“如何”，而是说“什么”。例如，在 C++中使用 Qt，我们可能会写出这样的代码来绘制一个矩形：

```cpp
QRect r(0, 0, 16, 16);
QPainter p;
p.setBrush(QBrush(Qt::blue));
p.drawRect(r);
```

这段代码创建了一个 16 x 16 像素的矩形，分配了一个进行绘制的`QPainter`对象，告诉绘图者它的画笔应该是蓝色的，然后告诉绘图者绘制矩形。在 QML 中，我只需写下矩形：

```cpp
import QtQuick 2.0
Rectangle {
    width: 16
    height: 16
    color: "blue"
}
```

区别是显而易见的：我只是说有一个蓝色的 16 x 16 像素的矩形。由 Qt Quick 运行时决定如何绘制矩形。

Qt Quick 的基础语言是 QML。它在很大程度上基于 JavaScript，事实上，大多数你可以用 JavaScript 编写的东西也可以用 QML 表达。表达式语法基本上没有改变：赋值、算术等都是一样的，名称-值系统在功能上也是一样的，尽管对象框可能会在类型声明之前（就像我刚刚向你展示的`Rectangle`示例一样）。

### 注意

“在 JavaScript 中有效的在 QML 中也有效”规则的一个关键例外是缺乏文档对象模型（DOM）和像文档根这样的全局变量，因为没有根上下文或 DOM，其他东西都挂在上面。如果你要将 Web 应用程序移植到 QML，请准备好重构应用程序架构的这些部分。

QML 中的对象必须以树的方式进行父子关系；每个 QML 文件必须包含一个封装对象，然后可以有具有子对象的子对象。但是，在文件的顶部必须有一个单一的层次结构根。通常，这个根是一个矩形，它绘制一个基本矩形，其子对象被呈现在上面，或者是一个项目，它是一个更复杂的用户界面元素的容器，实际上并不绘制任何东西。每个项目可能有一个名称，存储在其`id`属性中。

大多数可见的 QML 项目都可以有状态；也就是说，当特定状态处于活动状态时，一组属性将应用。这使你可以声明按钮的静止和按下状态之间的差异；按下按钮只是在状态之间切换，按钮的颜色、阴影等都可以随之改变，而不需要更改每个单独的属性。

在 QML 中一个关键概念是**绑定**：如果两个 QML 对象属性共享相同的值，改变一个会改变另一个。绑定将值与关于值的通知耦合在一起，类似于 C++中引用的工作方式，或者其他语言中的按引用传递的方式，但在 QML 中，这发生在被引用的变量名的级别上。这在编写诸如动画之类的东西时非常方便，因为你可以使用一个对象的值作为另一个对象的值，当底层值在一个地方发生变化时，两个对象都会更新。

QML 文件可以相互依赖，或者包含 JavaScript 文件以进行业务逻辑。你已经在每个 QML 文件的顶部看到了一个例子：`import`指令指示运行时包含指定的文件和版本，所以当我写`import QtQuick 2.0`时，运行时会找到 QtQuick 模块版本 2.0 的声明，并在解析文件时包含其符号。这就是你可以封装功能的方式。项目中的 QML 文件默认包含，同时你也可以包含 JavaScript 文件并将其分配给特定的 JavaScript 变量。例如，我们可以有一个名为`calculatorLogic.js`的 JavaScript 文件，它实现了我的计算器的所有功能，在 QML 中写入：

```cpp
import QtQuick 2.0
import "calculatorLogic.js" as CalculatorLogic
Item {
  // someplace in code
  CalculatorLogic.add(argument1, argument2);
}
```

初始导入加载 JavaScript 并将其值分配给 QML 对象`CalculatorLogic`；然后我可以像处理其他 QML 对象一样调度方法和访问该对象的属性。

Qt Quick 声明了许多基本数据类型；这些与您在编写 C++代码时在 Qt 中找到的数据类型非常相似，尽管语法可能有所不同。您将遇到的一些最重要的类型包括：

+   具有`x`和`y`属性的点

+   具有`x`、`y`、`宽度`和`高度`属性的矩形

+   具有`宽度`和`高度`属性的大小

+   颜色，这是 HTML RGB 表示法中的带引号的字符串或 Qt 颜色词典中的命名颜色（您可以想到的大多数颜色在 QML 中都有名称）

+   一个 2D、3D 或 4D 向量

+   包括布尔值、字符串、整数和浮点数在内的基本类型

还有许多用于用户界面构建的可见类型；在本章中，只有少数类型可以提及。有关所有 QML 类型的详细列表以及有关这些类型的文档，请参见[`bit.ly/17stfw3`](http://bit.ly/17stfw3)。

# 在 Qt Designer 中创建 Qt Quick 应用程序

在第一章中，*使用 Qt Creator 入门*，您已经对 Qt Designer 进行了基本了解，用于 Qt Quick 应用程序。在我们重新在 QML 中创建计算器应用程序之前，让我们再看一遍。下一张截图显示了 Qt Designer 用于 Qt Quick 窗口：

![在 Qt Designer 中创建 Qt Quick 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_03_04.jpg)

Qt Designer 用于 Qt Quick

再次从左边开始，我们有以下组件：

+   视图选择器，显示 Qt Designer 视图处于活动状态

+   正在编辑的文件的对象层次结构，显示了该文件中可见项目之间的父子关系

+   在对象层次结构下方是可以拖动到 QML 编辑器窗格上的项目的调色板

+   对象状态的摘要

+   在状态摘要下方是 QML 文件的对象编辑器

+   最后，有一个属性编辑器，可以调整当前选定的 QML 项目的属性

### 提示

坦率地说，我觉得写 QML 比使用设计师更容易。语法需要一点时间来适应，但设计师擅长的是通过手写的 QML 预览你所写的 QML，并对其布局进行微小调整。

说到布局，在我们详细查看示例代码之前，值得注意的是 QML 具有丰富的动态布局系统。可见项目具有`anchor`属性，您可以将项目的边缘锚定在其邻居或父视图的边缘上。您在第一章中简要看到了这一点，我们将`MouseArea`设置为与其父级一样大。我们还将使用它来控制计算器参数输入行和操作按钮的布局。

现在通过从**文件**菜单中选择**新文件或项目…**开始制作我们的示例代码，并通过向导创建一个 Qt Quick 2.0 应用程序。将应用程序命名为`QtQuickCalculator`。

## 创建可重用按钮

我们的计算器为每个操作都有一个按钮。虽然我们可以将每个按钮制作成单独的矩形和`MouseArea`，但更容易的方法是制作一个封装按钮行为的单个 QML 按钮，包括按下时外观的变化、按钮标签的放置等。

通过右键单击项目并选择**添加新内容…**，然后从 Qt 项目中选择**QML 文件（Qt Quick 2）**来创建一个新的 QML 文件。该按钮是一个包含第二个矩形、按钮的`Text`标签和处理按钮点击的`MouseArea`区域的矩形。将文件命名为`Button.qml`，并编辑它，使其内容如下：

```cpp
import QtQuick 2.0

Rectangle {
    id: button
    width: 64
    height: 64

    property alias operation: buttonText.text
    signal clicked

    color: "green"

    Rectangle {
        id: shade
        anchors.fill: button;
        color: "black"; opacity: 0
    }

    Text {
        id: buttonText
        anchors.centerIn: parent;
        color: "white"
        font.pointSize: 16
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        onClicked: {
            button.clicked();
        }
    }

    states: State {
        name: "pressed"; when: mouseArea.pressed == true
        PropertyChanges { target: shade; opacity: .4 }
    }
}
```

从文件代码的顶部开始：

+   在此文件的范围内，按钮的 ID 只是`button`。

+   宽度和高度都是 64 像素。

+   按钮有一个由其客户端配置的属性，即`operation`属性。该属性实际上是一个别名，这意味着它自动设置`buttonText.text`属性的值，而不是作为一个单独的字段。

+   按钮发出一个信号，即`clicked`信号。

+   按钮的颜色是绿色。

+   有一个填充按钮的矩形，颜色为黑色，但不透明度为零，意味着在正常使用中它是不可见的，是透明的。当按下按钮时，我调整这个矩形的不透明度，使按钮在被按下时变暗。

+   按钮的`text`标签大小为`16`点，颜色为白色，并居中在按钮本身。

+   接受按钮点击的`MouseArea`区域与按钮大小相同，并发出`clicked`信号。

+   按钮有两个状态：默认状态和第二个状态 pressed，当`mouseArea.pressed`属性为`true`时（因为您正在按下鼠标区域中的鼠标按钮）发生。当状态为 pressed 时，我请求一个单一的`PropertyChange`事件，稍微改变矩形的不透明度，给按钮投上一层阴影，使其变暗。

实际上，您可以在进入 Qt Designer 时看到按钮的两个状态（请参见以下屏幕截图）。状态只是一个名称，一个指示状态何时处于活动状态的`when`子句，以及一组`PropertyChanges`，指示状态处于活动状态时应更改哪些属性。所有可见的 QML 项都有一个`state`属性，它只是当前活动状态的名称。

![创建可重用按钮](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_03_05.jpg)

按钮的状态

请注意，QML 使用类似于 C++中的 Qt 的信号和槽，但没有`emit`关键字。相反，您可以直接使用`signal`关键字和信号的名称来声明信号，然后像调用函数一样调用信号。对于每个 QML 项的信号，槽的名称为`on`后跟信号名称；例如，`onClicked`，`onPressed`等。因此，当我们使用按钮时，我们为`clicked`信号编写一个`onClicked`处理程序。

## 计算器的主视图

返回编辑器，直接编辑`main.qml`。我们将在代码中直接声明我们的输入行、结果行和四个操作按钮；如果您愿意，您也可以在设计师中做类似的操作，然后编辑代码以匹配以下内容：

```cpp
import QtQuick 2.0

Rectangle {
    width: 360
    height: 200
    color: "grey"

    TextInput {
        id: argument1
        anchors.left: parent.left
        width: 160
        anchors.top: parent.top
        anchors.topMargin: 10
        anchors.leftMargin: 10
        anchors.rightMargin: 10
        text: "2"
        font.pointSize: 18
    }

    TextInput {
        id: argument2
        anchors.right: parent.right
        width: 160
        anchors.top: parent.top
        anchors.topMargin: 10
        anchors.leftMargin: 10
        anchors.rightMargin: 10
        text: "2"
        font.pointSize: 18
    }

    Text {
        id: result
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: argument2.bottom
        anchors.topMargin: 10
        anchors.leftMargin: 10
        anchors.rightMargin: 10
        text: "4"
        font.pointSize: 24
    }

    Row {
        id: buttonRow
        anchors.bottom: parent.bottom
        anchors.horizontalCenter: parent
        anchors.bottomMargin: 20
        spacing: 20
        Button {
            id: plusButton
            operation: "+"
            onClicked: result.text =
              parseFloat(argument1.text) + parseFloat(argument2.text)
        }

        Button {
            id: minusButton
            operation: "-"
            onClicked: result.text =
              parseFloat(argument1.text) - parseFloat(argument2.text)
        }

        Button {
            id: timesButton
            operation: "*"
            onClicked: result.text =
              parseFloat(argument1.text) * parseFloat(argument2.text)
        }

        Button {
            id: divideButton
            operation: "/"
            onClicked: result.text =
              parseFloat(argument1.text) / parseFloat(argument2.text)
        }
    }
}
```

视图有两个`TextInput`行，一个只读的`text`结果行，然后是`operation`按钮，包裹在`Row`项中，以给它们一个水平布局。计算器的基本视图是`grey`，位于 360×200 像素的窗口中。控件的位置如下：

+   第一个输入行锚定在父窗口的左上角，各有 10 像素的边距。它也是 160 像素长，是 18 点`TextInput`字段的默认高度。

+   第二个输入行锚定在父级的右侧，顶部和右侧各有 10 像素的边距。它也是 160 像素长，是 18 点`TextInput`字段的默认高度。

+   结果输入行的顶部锚定在输入行的底部，并且锚定在父矩形的左侧。两侧也各有 10 像素的边距。

+   按钮在一个`Row`项中间隔 20 像素，该项锚定在父级的底部。

这些锚点可以让视图在调整应用程序窗口大小时重新流动；输入行横跨窗口的宽度，底部的按钮栏随着窗口的放大而向下移动。

每个按钮都有一个`click`槽，用于获取每个输入行的浮点解释并执行适当的算术操作。它们都是我在上一节中向您展示的 QML 类`Button`的实例。请注意，在`onClicked`处理程序中使用了 JavaScript 函数`parseFloat`：正如我之前提到的，QML 中的 JavaScript 运行时支持这些函数，因此我们可以直接调用 JavaScript 函数。

以下屏幕截图显示了完成的计算器应用程序。请注意，运行应用程序时，如果您将鼠标悬停在按钮上并按下，您会看到阴影变暗（这在屏幕截图中没有显示）。这反映了我在上一节中向您展示的按钮的两种状态：

![计算器的主视图](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_03_06.jpg)

完成的 Qt Quick 计算器应用程序

## 学习更多关于 Qt Quick 和 QML

Qt Quick 旨在创建流畅的应用程序，不需要太多深层次的小部件复杂性。媒体中心、照片查看器、电话拨号器、网页浏览器等不需要与主机平台外观和感觉匹配（或者在主机平台完全使用 Qt Quick 编写）的应用程序是 Qt Quick 范例的好例子。有关 Qt Quick 的更多信息以及展示平台广度和功能的大量示例，请参阅[`bit.ly/16ULQ4V`](http://bit.ly/16ULQ4V)。

# 总结

Qt 提供了不止一个 GUI 工具包：Qt GUI 采用传统的基于小部件的 GUI 开发方法，而 Qt Quick 提供了一种声明性方法，更适合于媒体盒子、一些手机应用程序、汽车仪表板和其他嵌入式环境的跨平台用户界面。对于这两种方法，Qt 都提供了 Qt Designer，一个拖放环境，让您在构建应用程序时构建、配置和预览用户界面。

Qt 的核心是信号和槽的概念，是 Qt 对于处理当今 GUI 应用程序所需的延迟绑定的回调和事件的解决方案。Qt 对象可以发出信号，这些信号是类型安全的函数声明，其他对象可以连接到这些信号，触发方法调用当信号被发出时。

在下一章中，您将暂停学习 Qt Creator 和图形用户界面开发，专注于应用程序开发的一个关键方面：本地化。我将向您展示如何使用 Qt Linguist 和 Qt 的本地化功能来本地化您的应用程序。


# 第四章：使用 Qt Linguist 本地化您的应用程序

本地化是当今软件开发中重要但常被忽视的部分。大多数应用程序的作者，无论这些应用程序是商业应用程序还是开源应用程序，都希望为其应用程序吸引大量用户。越来越多地意味着在多个语言和多个区域设置中支持多种语言；通常需要在一个区域设置中支持多种语言（想想加拿大同时存在法语和英语）。

Qt 长期以来一直有一个框架，用于使应用程序易于本地化。借助这些工具，您可以避免在应用程序中硬编码字符串，并使用名为 Qt Linguist 的 GUI 来帮助管理翻译，从而减轻 Qt 在整个应用程序开发周期中的本地化负担。在本章中，我们将研究 Qt 的本地化策略，讨论 Qt 提供的三种工具（**lupdate**、**lrelease**和**Qt Linguist**）以及如何使用它们，以及在编写应用程序时如何利用 Qt 的本地化框架。

# 理解本地化任务

本地化您的应用程序有几个阶段，通常在整个项目中重叠。这些阶段包括：

1.  在编写应用程序时，您以特定方式放置字符串以本地化您的应用程序，以便 Qt 可以识别需要本地化的字符串。

1.  定期提取应用程序中的所有字符串并交给翻译人员进行翻译。

1.  翻译人员为您的应用程序提供字符串的翻译。

1.  您使用翻译后的字符串编译翻译文件，以支持每种语言。

Qt 提供了四种工具来促进这些阶段：

+   C++和 QML 的`tr`和`qsTr`函数让您识别应用程序中需要本地化的字符串

+   `lupdate`命令会生成需要在您的应用程序中本地化的字符串列表

+   翻译人员使用 Qt Linguist 为您的应用程序提供字符串的翻译

+   `lrelease`命令会将 Qt Creator 中的翻译字符串打包成应用程序可使用的格式

以下图显示了这些阶段是如何相互作用的：

![理解本地化任务](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_04_01.jpg)

lupdate/Linguist/lrelease 循环

软件开发是迭代的，本地化也不例外。小型项目可能更喜欢只进行一次或两次本地化，等到应用程序几乎完成后再提交应用程序字符串进行本地化。较大的应用程序或拥有专门的翻译人员团队的较大公司可能更喜欢更迭代的方法，在应用程序开发过程中多次进行本地化循环。Qt 支持这两种模式。

# 标记字符串以进行本地化

在第一章*使用 Qt Creator 入门*中，我告诉您始终要使用`tr`和`qsTr`函数标记您的字符串以进行本地化：C++使用`tr`，QML 字符串使用`qsTr`。这样做对您有两个关键优势。首先，它使 Qt 能够找到每个需要本地化的字符串。其次，如果您在应用程序中安装了 Qt 翻译器对象并提供了翻译文件，那么您使用这些函数包装的字符串将自动替换为其本地化等效字符串。

让我们更详细地研究`tr`的使用。在其声明中包含`Q_OBJECT`宏的所有 Qt 对象都包括`tr`函数。您已经看到它带有一个参数，如下面的代码行所示：

```cpp
button = new QPushButton(tr("&Quit"), this);
```

字符串中的前导`&`不是给`tr`函数用的，而是给键盘加速器用的；您可以用`&`前缀一个字母，它就会得到默认的系统（Windows 为*Alt*，Apple 为*command*，Linux 为*Control*）。如果在应用程序的当前翻译表中没有字符串的翻译版本，`tr`函数将使用您传递的字符串作为用户界面中的字符串，或者如果当前翻译表中存在该字符串，则使用当前翻译表中的字符串。

`tr`函数可以接受第二个参数，一个消歧义上下文，`tr`用于可能需要不同翻译的相同字符串。它还可以处理带有复数的字符串，如下面的代码行所示：

```cpp
tr("%n item(s) replaced", "", count);
```

根据计数和区域设置的值，返回不同的字符串。因此，本地化的英文翻译可能返回"0 items replaced"，"1 item replaced"，"2 items replaced"等，而法语翻译可能返回"0 item remplacé"，"1 item remplacé"，"2 items remplacés"等。

QML 中的`qsTr`函数工作原理类似，但它没有`tr`方法对于消除歧义或处理复数的灵活性。

# 使用 Qt Linguist 本地化您的应用程序

一旦您使用`tr`或`qsTr`标记了您的字符串，您需要为 Qt Linguist 生成这些字符串的表格以进行本地化。您可以使用`lupdate`命令来实现这一点，该命令会获取您的`.pro`文件并遍历您的源代码以查找需要本地化的字符串，并为 Qt Linguist 创建一个 XML 文件，其中包含您需要翻译的字符串。您需要为每种想要支持的语言执行此操作。在执行此操作时，最好以系统化的方式命名生成的文件；一种方法是使用项目文件的名称，后跟 ISO-639-2 语言代码。

需要举一个具体的例子。本章有一个`QtLinguistExample`；我可以使用如下命令运行`lupdate`来创建一个我将翻译成世界语（ISO-639-2 语言代码 EPO）的字符串列表：

```cpp
% lupdate -pro .\QtLinguistExample.pro –ts .\QtLinguistExample-epo.ts
```

其中`–pro`文件指示包含要扫描以进行翻译的源文件列表的`.pro`文件，`–ts`参数指示要写入的翻译文件的名称。

### 提示

当然，您需要在路径中添加`lupdate`。您如何设置路径将取决于您是在 Windows、Mac OS X 还是 Linux 上工作，以及您在哪里安装了 Qt。有些 Qt 的安装可能会自动更新您的路径，而其他可能不会。例如，在我的 Windows 机器上，我发现`lupdate`在`C:\qt\5.1.0\msvc2012_64\bin\lupdate.exe`。

`.ts`文件是一个带有标签的 XML 文件，用于指示需要翻译的字符串、它们在应用程序源代码中的上下文等。Qt Linguist 也会将翻译保存到 QM 文件中，但不用担心，`lupdate`足够智能，如果您在提供一些翻译后再次运行它，它不会覆盖现有的翻译。

Qt Linguist 是一个 GUI 应用程序；当您启动它时，您将看到一个与下一个截图非常相似的屏幕：

![使用 Qt Linguist 本地化您的应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_04_02.jpg)

Qt Linguist 应用程序编辑一个 QM 文件

首先，您需要打开一个通过导航到**文件** | **打开**生成的`.ts`文件，并选择一个翻译文件。然后会提示您选择目标语言，然后会显示它找到的字符串列表。您或者您的翻译人员只需要逐个查看每个字符串，并输入相应的翻译语言的字符串。在这样做的同时，您可以在最右侧的窗格中看到字符串在源代码中的上下文；捕获该字符串的源代码行会被突出显示。

Qt Linguist 可以让您跟踪您已经翻译和仍需要翻译的字符串。每个字符串左侧的图标可以是：

+   一个黑色的问号表示一个字符串尚未被翻译

+   一个黄色的问号表示该字符串未通过 Qt Linguist 的所有验证测试，但您忽略了这些失败

+   感叹号表示您提供的字符串未通过 Qt Linguist 的验证测试

+   黄色复选框表示您已提供翻译，但 Qt Creator 可能发现了问题

+   绿色复选框表示该字符串已被翻译并准备就绪

Qt Linguist 提供了一些简单的验证测试，例如确保带有`printf`等参数的字符串在每个翻译中具有相同数量的参数。

Qt Linguist 还支持短语书；您可以下载一个已经本地化为您目标语言的常见字符串的短语书。

在任何时候，您都可以通过运行`lrelease`为您的应用程序生成一个翻译文件以供包含。例如，要为我的世界语字符串创建一个翻译文件，我将使用以下方式使用`lrelease`：

```cpp
% lrelease .\QtLinguistExample-epo.ts .\QtLinguistExample-epo.qm
```

这将获取传入的`.ts`文件，并生成一个带有字符串的`.qm`文件。`.qm`文件是高度压缩的二进制文件，由 Qt 直接在渲染应用程序的过程中使用。

# 在应用程序中包含本地化字符串

为了向应用程序的`tr`和`qsTr`函数提供翻译的字符串，您的应用程序需要包含一个`QTranslator`对象来读取`.ts`文件，并用其翻译后的字符串替换`tr`和`qsTr`提供的字符串。我们在您的主入口点函数中执行此操作，如下面的代码块所示：

```cpp
QApplication a(argc, argv);
QTranslator translator;
bool result = translator.load("QtLinguistExample-epo.qm");
a.installTranslator(&translator);

    // Other window setup stuff goes here

return a.exec();
```

此代码分配了一个`QTranslator`对象，并在将其安装到`QApplication`之前将指定的翻译文件加载到翻译器中。在这个例子中，我们将语言硬编码为世界语。

请注意，如果您希望支持系统选择的区域设置，我们可能会选择以这种方式执行：

```cpp
QString locale = QLocale::system().name();
QTranslator translator;
translator.load(QString("QtLinguistExample-") + locale);
```

这确定系统区域设置，并尝试加载系统当前区域设置的本地化字符串文件。

为了使这个工作，应用程序的`.qm`文件需要被应用程序找到。它们应该在输出目录中；在开发过程中执行此操作的一种方法是在 Qt Creator 的**项目**窗格中的**构建设置**下关闭阴影构建。当您构建应用程序的安装程序时——这是本书范围之外的特定于平台的任务——您需要将您的`.qm`文件与应用程序二进制文件一起包含。

# 本地化特殊内容——使用`QLocale`本地化货币和日期

您可能需要做的一件常见事情是本地化货币和日期。Qt 使这变得容易，尽管在您仔细考虑之前解决方案并不明显。

首先，您应该了解`QString`的`arg`方法。它将转义的数字替换为其参数的格式化版本；如果我们写：

```cpp
QString s = new QString("%1 %2").arg("a").arg("b");
```

然后`s`包含字符串`a b`。其次，您应该了解`QLocale`的`toString`方法，它以特定于区域设置的方式格式化其参数。

因此，我们可以写：

```cpp
QString currencyValue = QString("%1 %2")
    .arg(tr("$")).arg(QLocale::toString(value, 'g', 2)
```

这使用`tr`来本地化货币符号，并使用`QLocale`类的静态方法`toString`将值转换为带有特定区域设置的十进制分隔符的字符串（在美国和加拿大为句点，在欧洲为逗号）。

日期格式化类似：`QLocale`的`toString`方法有适用于`QDateTime`、`QDate`和`QTime`参数的重载，因此您可以简单地写：

```cpp
QDateTime whenDateTime = QDateTime::currentDateTime();
QString when = QLocale::toString(whenDate);
```

这将获取当前日期和时间并将其存储在`whenDateTime`中，然后使用区域设置的默认格式将其转换为字符串。`toString`方法可以接受第二个参数，用于确定输出格式。它可以是以下之一：

+   `QLocale::LongFormat`，它使用月份和日期名称的长版本

+   `QLocale::ShortFormat`，它使用日期和月份名称的短版本

+   `QLocale::NarrowFormat`，它为日期和时间提供最窄的格式

# 总结

使用 Qt 本地化应用程序很容易，可以使用 Qt Linguist 和 Qt 中的本地化框架。但是，要使用该框架，您必须在源代码中使用`tr`或`qsTr`标记要本地化的字符串。一旦这样做，您就可以使用 Qt 的`lupdate`命令创建要翻译的字符串的源文件，并为每个字符串提供翻译。提供了翻译后，您可以使用`lrelease`编译它们，然后通过在应用程序的`main`函数中安装`QTranslator`对象并加载`lrelease`生成的翻译表来将它们包含在应用程序中。

在下一章中，我们将看到 Qt Creator 支持的软件开发的另一个重要方面，即使用 QML Profiler 和 Valgrind 进行性能分析。


# 第五章：使用 Qt Creator 进行性能优化

我们并不是每天都使用性能分析工具，但当我们需要时，我们很高兴它们存在。商业工具，如与 Microsoft Visual Studio 一起提供的工具或 IBM 的 Rational Rose Purify 等独立工具，可能会花费大量资金，幸运的是，Qt Creator 大部分所需的功能都内置了，或者支持使用开源工具来帮助您分析应用程序的运行时和内存性能。

在本章中，我们将看到如何使用 QML 性能分析器对 QML 应用程序进行运行时分析，并学习如何阅读其生成的报告。然后，我们将关注使用 Qt Creator 进行内存性能分析，使用 Valgrind 在 Linux 平台上查找内存泄漏和堆损坏的免费选项。

# QML 性能分析器

Qt Quick 应用程序应该快速，具有流畅的用户界面。在许多情况下，使用 QML 可以轻松实现这一点；QML 和 Qt Quick 运行时的贡献者们在创建一个在各种情况下表现良好的环境方面付出了大量努力。然而，有时，尽最大努力，您可能会发现无法使应用程序的性能达到您想要的水平。有些错误是显而易见的，比如：

+   在状态更改或触发绘图操作的操作之间执行大量计算密集型任务

+   过于复杂的视图层次结构，一次显示数千个元素

+   在非常有限的硬件上运行（通常与前两个问题结合使用）

Knuth 曾经说过，“过早优化是万恶之源”，他绝对是对的。但是，也许会有一段时间，您需要测量应用程序的性能，Qt Creator 包含了一个专门用于此目的的性能分析器。使用它，您可以看到应用程序在每个 QML 方法中花费了多少时间，以及测量应用程序的关键方面，这些方面可能超出您的控制，比如创建应用程序的视图层次结构需要多长时间。

让我们仔细看看。

## QtSlowButton-需要性能调优的 Qt Quick 应用程序

让我们分析`QtSlowButton`的性能，这是我在本章为您准备的性能不佳的示例程序。 `QtSlowButton`有两个 QML 组件：一个基于第三章中的计算器按钮的按钮，*使用 Qt Designer 设计您的应用程序*，以及一个带有可按的按钮的视图。这是按钮的实现：

```cpp
import QtQuick 2.0

Rectangle {
    id: button

    width: 128
    height: 64

    property alias label: buttonText.text
    property int delay: 0

    color: "green"

    Rectangle {
        id: shade
        anchors.fill: button;
        color: "black"; opacity: 0
    }

    Text {
        id: buttonText
        anchors.centerIn: parent;
        color: "white"
        font.pointSize: 16
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        onClicked: {
            for(var i = 0; i < button.delay; i++);
        }
    }

    states: [
        State {
            name: "pressed"; when: mouseArea.pressed == true
            PropertyChanges { target: shade; opacity: .4 }
        }
    ]
}
```

每个按钮在按下时都简单地运行一个`for`循环；其`delay`属性控制循环运行的次数。此外，每个按钮都有一个标签，按钮会在可点击区域的中心绘制该标签。

主用户界面由三个按钮组成，位于“列区域”，标有“快速”、“中等”和“慢速”，延迟逐渐增加：

```cpp
import QtQuick 2.0

Rectangle {
    width: 180
    height: 360

    Column
    {
        spacing: 20
        Button
        {
            delay: 10000;
            label: "fast";
        }
        Button
        {
            delay: 100000;
            label: "medium";
        }
        Button
        {
            delay: 300000;
            label: "slow";
        }
    }
}
```

您可以加载本书附带的源项目，也可以创建一个新的 Qt Quick 项目，并使用此代码创建一个按钮和主视图。

分析应用程序的性能：

1.  构建应用程序。

1.  从**分析**菜单中选择**QML Profiler**。应用程序将启动，Qt Creator 将切换到**分析**视图。

1.  在应用程序本身中，单击每个应用程序按钮几次。单击每个按钮后，您将需要等待。

1.  退出应用程序。

### 提示

QML Profiler 使用 TCP/IP 在默认端口 3768 上运行的应用程序和分析器之间建立连接。您可能需要调整主机防火墙设置以确保正确运行。在 Windows 上，请务必允许**Windows 防火墙**对话框中的连接。

下一张截图显示了运行应用程序后的**分析**视图。QML Profiler 有三个标签，默认显示第一个：

+   第一个标签是时间轴，指示应用程序中的事情发生在什么时候，以及它们花费了多长时间

+   第二个标签列出了 QML 应用程序处理的事件，以及每个事件花费了多少时间

+   第三个标签列出了程序在运行时遇到的 JavaScript 函数，以及应用程序总共花费多长时间来运行每个函数

在下一张截图中，我点击了**处理信号**行以展开应用程序处理的信号。你可以看到它处理了一个名为`onClicked`的信号，共三次，并且每次花费的时间都显示在图表上。显然，如果应用程序正在执行可以优化的操作，那么在这里就有性能改进的机会：

![QtSlowButton – 需要性能调优的 Qt Quick 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_05_01.jpg)

时间轴视图，显示了在我的 onClicked 方法中花费的时间

下一张截图显示了这些信息的不同视图，表明在数值精度的限制下，应用程序在按钮的`onClicked`处理程序中花费了所有测量时间：显然，这是性能上的“热点”。有趣的是，这里测量了我 JavaScript 的每一个事件，包括按下按钮时将不透明滤镜放在按钮前面的`$when`子句。从**JavaScript**视图中查看可以帮助你在广义上了解应用程序中发生的事情：

![QtSlowButton – 需要性能调优的 Qt Quick 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_05_02.jpg)

在 QtSlowButton 中运行不同 JavaScript 部分所花费的总时间

下一张截图可能是性能极客最感兴趣的，因为它显示了 QML 在运行应用程序时处理的每一个事件所花费的时间。同样，我们看到`onClicked`处理程序占用了大部分处理器资源，但还显示了其他一些事情，比如为视图创建矩形和按钮状态的变量绑定。通常，我们会使用**JavaScript**视图来了解应用程序中的问题所在，而使用**Events**视图来专注于特定问题：

![QtSlowButton – 需要性能调优的 Qt Quick 应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/app-dev-qt-crt/img/2319OS_05_03.jpg)

QML Profiler 的 Events 视图，显示了 QtSlowButton 中的每一个事件

# 使用 Valgrind 查找内存泄漏

正如我们在第三章中讨论的那样，*使用 Qt Designer 设计您的应用程序*，在管理应用程序中的`QObject`类的内存时，您应该养成使用 Qt 的父子关系的习惯，以避免内存泄漏。在我编写 Qt 应用程序的时候，唯一遇到内存泄漏的情况是当我没有这样做的时候。此外，对于不基于`QObject`的指针，也应该使用`QSharedPointer`等类。

然而，有时候您可能会引入一个自己找不到的内存泄漏。在这种情况下，像 Valgrind 这样的工具可能会拯救你；它会跟踪应用程序中的每个内存分配和释放操作，在程序终止时提醒您，如果它没有释放所有分配的内存。

不幸的是，Valgrind 是一个仅适用于 Linux 的工具。如果您编写纯 Qt 代码，即使在 Windows 或 Mac OS X 上开发，这对您来说也不是一个严重的问题，因为您可以将应用程序移植到 Linux 并在那里运行 Valgrind。为此，您需要使用诸如 VMware Fusion、VMware Player、Microsoft HyperV 或 Parallels 之类的应用程序来设置运行 Linux 的虚拟机（我喜欢使用 Ubuntu），安装 Qt Creator，并在那里运行您的代码。（不幸的是，如果您的应用程序中有特定于 Windows 的代码或库，这不是一个选择。）

### 提示

如果您为 Windows 构建应用程序，商业泄漏检测器如 Rational Purify 可能是一个选择。

在继续之前，您应该确保您的 Qt Creator 在 Linux 发行版下运行，并从[`bit.ly/14QwiQZ`](http://bit.ly/14QwiQZ)安装 Valgrind，或者使用您的软件包管理器。例如，在 Ubuntu 上，我可以使用以下命令安装 Valgrind：

```cpp
sudo apt-get install valgrind

```

当您使用 Valgrind 时，实际上是在 Valgrind 内运行您的应用程序；而不是启动您的应用程序，您启动 Valgrind，然后启动您的应用程序。

## QtLeakyButton-一个需要内存帮助的 Qt C++应用程序

`QtLeakyButton`应用程序只做一件事：它呈现一个按钮，当点击时，会分配 512KB 的 RAM。以下是代码（您可以运行本书附带的示例，或者创建一个带有单个按钮和标签的 Qt GUI 应用程序，并将此代码用于您的`MainWindow`类）：

```cpp
// mainwindow.h
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void leakPressed();

private:
    Ui::MainWindow *ui;
    int m_count;
};

#endif // MAINWINDOW_H

// mainwindow.cpp

#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    m_count(0)
{
    ui->setupUi(this);
    connect(ui->leakButton, SIGNAL(clicked()),
            this, SLOT(leakPressed()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::leakPressed()
{
    void *p = new char[512 * 1024];
    m_count++;
    ui->leakCount->setText(QString::number(m_count));
}
```

`MainWindow`类有一个整数计数器和一个用于实例化表单的`ui`插槽。`MainWindow`构造函数实例化此表单，然后将`leakButton`的`clicked`信号连接到`MainWnidow::leakPressed`。`leakPressed`方法只是分配内存并增加计数器，更新计数器以显示您按下按钮的次数。

要使用 Valgrind，我们需要为您的应用程序添加一个新的运行目标。为此，请执行以下操作：

1.  在左侧点击**项目**，然后点击**运行**。

1.  点击**添加**。

1.  对于**名称**，输入`valgrind`。

1.  对于**可执行文件**，添加 Valgrind 的路径（通常为`/usr/bin/valgrind`）。

1.  对于参数，输入以下内容：

```cpp
-q --tool=memcheck --leak-check=full --leak-resolution=low ./<your-app-target-name>

```

1.  对于**工作目录**，输入`$BUILDDIR`。

现在我们可以为您的应用程序选择 Valgrind 运行目标。我们需要使用调试构建，因为 Valgrind 需要我们应用程序中的调试符号来生成有意义的报告。要使用 Valgrind，启动应用程序并点击按钮几次。Valgrind 进程会持续输出信息，但大部分输出是在我们退出应用程序后才出现的。

Valgrind 会产生大量输出，需要一些时间来整理。我们正在寻找泄漏摘要，其中指示了明确丢失和间接丢失的字节数。明确丢失的块是您分配但未释放的内存；间接丢失的内存是因为它被另一个指针引用而泄漏，而引用指针未被释放。输出将看起来像：

```cpp
X bytes in 1 blocks are definitely lost in loss record n of m
 at 0x........: function_name (filename:line number)

```

在这里，`X`表示泄漏的字节数，并且泄漏块的地址显示在第二行上。记录号表示应用程序内存分配器使用的内部记录号，可能对您没有太大帮助。

我们应该真正关注我们的应用程序中的内存泄漏，因为 Qt 可能会有自己的内存泄漏。Valgrind 支持抑制文件，指示应忽略哪些泄漏；如果您可以找到并下载一个适用于您构建的 Qt 版本的抑制文件，您可以通过修改参数行来包含对抑制文件的引用：

```cpp
-q --tool=memcheck --leak-check=full --leak-resolution=low --suppressions=suppresion.txt ./[your-app-target-name]

```

在您的应用程序中查找内存泄漏是一部分艺术和一部分科学。这是一个很好的练习，在应用程序开发过程中定期进行，以确保您可能引入的泄漏在您最熟悉运行的新代码时能够快速发现。

# 摘要

Qt Creator 提供了 QML 分析器，让您可以对 Qt 应用程序进行运行时分析。您可以看到应用程序运行的时间图表，以及深入了解应用程序如何花费时间进行绘制、绑定变量和执行 JavaScript。

Qt Creator 还与 Linux 上的 Valgrind 很好地集成，让您可以查找应用程序中的内存泄漏。在 Linux 上使用 Valgrind，您可以看到已分配但未释放的内存块，更重要的是，它们有多大以及在代码中的分配位置，让您可以提前确定为什么它们没有被释放。

在下一章中，我们将从 Qt Creator 的特定部分转向其最激动人心的一般方面之一：使用 Qt Creator 编译和测试 Google Android 等移动平台的应用程序的能力。
