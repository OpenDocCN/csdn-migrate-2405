# C++ Qt5 GUI 编程（四）

> 原文：[`annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed`](https://annas-archive.org/md5/63069ff6b9b588d5c75e8d5b8dbfb5ed)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：Qt Quick 和 QML

在这一章中，我们将学习与本书其他章节非常不同的内容。Qt 包括两种不同的应用开发方法。第一种方法是 Qt Widgets 和 C++，这是我们在之前所有章节中都涵盖过的内容。第二种方法是使用 Qt Quick 控件和 QML 脚本语言，这将在本章中介绍。

在本章中，我们将涵盖以下主题：

+   介绍 Qt Quick 和 QML

+   Qt Quick 控件和控制

+   Qt Quick 设计师

+   Qt Quick 布局

+   基本的 QML 脚本

准备好了吗？让我们开始吧！

# 介绍 Qt Quick 和 QML

在接下来的部分，我们将学习 Qt Quick 和 QML 是什么，以及如何利用它们来开发 Qt 应用程序，而无需编写 C++代码。

# 介绍 Qt Quick

**Qt Quick**是 Qt 中的一个模块，为开发面向触摸和视觉的应用程序提供了一整套用户界面引擎和语言基础设施。开发人员选择 Qt Quick 后，将使用 Qt Quick 对象和控件，而不是通常的 Qt Widgets 进行用户界面设计。

此外，开发人员将使用类似于**JavaScript**的 QML 语言编写代码，而不是使用 C++代码。但是，您可以使用 Qt 提供的 C++ API 来扩展 QML 应用程序，通过相互调用每种语言的函数（在 QML 中调用 C++函数，反之亦然）。

开发人员可以通过在创建项目时选择正确的选项来选择他们喜欢的开发应用程序的方法。开发人员可以选择 Qt Quick 应用程序而不是通常的 Qt Widgets 应用程序选项，这将告诉 Qt Creator 为您的项目创建不同的起始文件和设置，从而增强 Qt Quick 模块：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/43e54681-0742-4983-9a4e-70c933538d25.png)

当您创建 Qt Quick 应用程序项目时，Qt Creator 将要求您选择项目的最低要求 Qt 版本：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3077a542-a06f-4c6a-96d6-2b84826ebc78.png)

选择了 Qt 版本后，Qt Quick 设计师将确定要启用哪些功能，并在 QML 类型窗口上显示哪些小部件。我们将在后面的部分中更多地讨论这些内容。

# 介绍 QML

**QML**（**Qt 建模语言**）是一种用于设计触摸友好用户界面的用户界面标记语言，类似于 CSS 在 HTML 上的工作方式。与 C++或 JavaScript 不同，它们都是命令式语言，QML 是一种声明式语言。在声明式编程中，您只需在脚本中表达逻辑，而不描述其控制流。它只是告诉计算机要做什么，而不是如何做。然而，命令式编程需要语句来指定操作。

当您打开新创建的 Qt Quick 项目时，您将在项目中看到`main.qml`和`MainForm.ui.qml`，而不是通常的`mainwindow.h`和`mainwindow.cpp`文件。您可以在以下截图中的项目目录中看到这一点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/fc36ad7d-787e-4a09-bde7-f95ab7c362df.png)

这是因为整个项目主要将在 QML 上运行，而不是在 C++上。您将看到的唯一 C++文件是`main.cpp`，它在应用程序启动时只是加载`main.qml`文件。`main.cpp`中执行此操作的代码如下所示：

```cpp
int main(int argc, char *argv[]) 
{ 
   QGuiApplication app(argc, argv); 

   QQmlApplicationEngine engine; 
   engine.load(QUrl(QStringLiteral("qrc:/main.qml"))); 
   if (engine.rootObjects().isEmpty()) 
         return -1; 

   return app.exec(); 
} 
```

您应该已经意识到有两种类型的 QML 文件，一种是扩展名为`.qml`，另一种是扩展名为`.ui.qml`。尽管它们都使用相同的语法等，但它们在项目中的作用是非常不同的。

首先，`.ui.qml`文件（在开头多了一个`.ui`）用作基于 Qt Quick 的用户界面设计的声明文件。您可以使用 Qt Quick Designer 可视化编辑器编辑`.ui.qml`文件，并轻松设计应用程序的 GUI。您也可以向文件添加自己的代码，但对文件中可以包含的代码有一些限制，特别是与逻辑代码相关的限制。当运行 Qt Quick 应用程序时，Qt Quick 引擎将阅读`.ui.qml`文件中存储的所有信息，并相应地构建用户界面，这与 Qt Widgets 应用程序中使用的`.ui`文件非常相似。

然后，我们有另一个只有`.qml`扩展名的文件。这个文件仅用于构建 Qt Quick 应用程序中的逻辑和功能，就像 Qt Widget 应用程序中使用的`.h`和`.cpp`文件一样。这两种不同的格式将应用程序的视觉定义与其逻辑块分开。这使开发人员能够将相同的逻辑代码应用于不同的用户界面模板。您不能使用 Qt Quick Designer 打开`.qml`文件，因为它不用于 GUI 声明。`.qml`文件是由开发人员手动编写的，对他们使用的 QML 语言特性没有限制。

让我们首先打开`MainForm.ui.qml`，看看这两个 QML 文件的区别。默认情况下，Qt Creator 将打开用户界面设计师（Qt Quick Designer）；然而，让我们通过按左侧面板上的编辑按钮切换到代码编辑模式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d2c87dda-ef9d-45f7-89c1-0bc053484c75.png)

然后，您将能够看到形成您在设计模式中看到的用户界面的 QML 脚本。让我们分析这段代码，看看 QML 与 C++相比是如何工作的。在`MainForm.ui.qml`中，您首先看到的是这行代码：

```cpp
import QtQuick 2.6 
```

这非常简单明了；我们需要导入带有适当版本号的`Qt Quick`模块。不同的 Qt Quick 版本可能具有不同的功能，并支持不同的部件控件。有时，甚至语法可能略有不同。请确保为您的项目选择正确的版本，并确保它支持您需要的功能。如果不知道要使用哪个版本，请考虑使用最新版本。

接下来，我们将看到在两个大括号之间声明的不同 GUI 对象（我们称之为 QML 类型）。我们首先看到的是`Rectangle`类型：

```cpp
    Rectangle { 
       property alias mouseArea: mouseArea 
       property alias textEdit: textEdit 

       width: 360 
       height: 360 
       ... 
```

在这种情况下，`Rectangle`类型是窗口背景，类似于 Qt Widget 应用程序项目中使用的中央窗口部件。让我们看看`Rectangle`下面的其他 QML 类型：

```cpp
    MouseArea { 
        id: mouseArea 
        anchors.fill: parent 
    } 

    TextEdit { 
        id: textEdit 
        text: qsTr("Enter some text...") 
        verticalAlignment: Text.AlignVCenter 
        anchors.top: parent.top 
        anchors.horizontalCenter: parent.horizontalCenter 
        anchors.topMargin: 20 
        Rectangle { 
            anchors.fill: parent 
            anchors.margins: -10 
            color: "transparent" 
            border.width: 1 
        } 
    } 
```

`MousArea`类型，顾名思义，是一个检测鼠标点击和触摸事件的无形形状。您基本上可以通过在其上放置`MouseArea`将任何东西变成按钮。之后，我们还有一个`TextEdit`类型，其行为与 Qt Widget 应用程序中的`Line Edit`部件完全相同。

您可能已经注意到，在`Rectangle`声明中有两个带有`alias`关键字的属性。这两个属性公开了`MouseArea`和`TextEdit`类型，并允许其他 QML 脚本与它们交互，接下来我们将学习如何做到这一点。

现在，打开`main.qml`并查看其代码：

```cpp
import QtQuick 2.6 
import QtQuick.Window 2.2 

Window { 
    visible: true 
    width: 640 
    height: 480 
    title: qsTr("Hello World") 

    MainForm { 
        anchors.fill: parent 
        mouseArea.onClicked: { 
            console.log(qsTr('Clicked on background. Text: "' + 
            textEdit.text + '"')) 
        } 
    } 
} 
```

在上面的代码中，有一个`Window`类型，只能通过导入`QtQuick.Window`模块才能使用。设置了`Window`类型的属性后，声明了`MainForm`类型。这个`MainForm`类型实际上就是我们之前在`MainForm.ui.qml`中看到的整个用户界面。由于`MouseArea`和`TextEdit`类型已在`MainForm.ui.qml`中公开，我们现在可以在`main.qml`中访问并使用它们。

QML 还使用 Qt 提供的信号和槽机制，但写法略有不同，因为我们不再编写 C++代码。例如，我们可以在上面的代码中看到`onClicked`的使用，这是一个内置信号，相当于 Qt Widgets 应用程序中的`clicked()`。由于`.qml`文件是我们定义应用程序逻辑的地方，我们可以定义`onClicked`被调用时发生的事情。另一方面，我们不能在`.ui.qml`中做同样的事情，因为它只允许与视觉相关的代码。如果你尝试在`.ui.qml`文件中编写逻辑相关的代码，Qt Creator 会发出警告。

就像 Qt Widgets 应用程序一样，您也可以像以前一样构建和运行项目。默认示例应用程序看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/cfbfa37c-2ba3-4e65-b456-4735c5c90efa.png)

您可能会意识到构建过程非常快。这是因为 QML 代码默认不会被编译成二进制代码。QML 是一种解释性语言，就像 JavaScript 一样，因此不需要编译就可以执行。在构建过程中，所有 QML 文件将被打包到应用程序的资源系统中。然后，在应用程序启动时，Qt Quick 引擎将加载和解释 QML 文件。

但是，您仍然可以选择使用包含在 Qt 中的`Qt Quick Compiler`程序将您的 QML 脚本编译成二进制代码，以使代码执行速度略快于通常情况。这是一个可选步骤，除非您要在资源非常有限的嵌入式系统上运行应用程序，否则不需要。

现在我们已经了解了**Qt Quick**和**QML**语言是什么，让我们来看看 Qt 提供的所有不同的 QML 类型。

# Qt Quick 小部件和控件

在 Qt Quick 的领域中，小部件和控件被称为`QML 类型`。默认情况下，**Qt Quick Designer**为我们提供了一组基本的 QML 类型。您还可以导入随不同模块提供的其他 QML 类型。此外，如果没有现有的类型符合您的需求，甚至可以创建自定义的 QML 类型。

让我们来看看 Qt Quick Designer 默认提供的 QML 类型。首先，这是基本类别下的 QML 类型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/87221c3c-f5cb-4409-a1aa-2e1b86f76030.png)

让我们看看不同的选项：

+   **Border Image**：Border Image 是一个设计用来创建可维持其角形状和边框的可伸缩矩形形状的 QML 类型。

+   **Flickable**：Flickable 是一个包含所有子类型的 QML 类型，并在其裁剪区域内显示它们。Flickable 还被`ListView`和`GridView`类型扩展和用于滚动长内容。它也可以通过触摸屏轻扫手势移动。

+   **Focus Scope**：Focus Scope 是一个低级别的 QML 类型，用于促进其他 QML 类型的构建，这些类型在被按下或释放时可以获得键盘焦点。我们通常不直接使用这种 QML 类型，而是使用直接从它继承的其他类型，如`GroupBox`、`ScrollView`、`StatusBar`等。

+   **Image**：`Image`类型基本上是不言自明的。它可以加载本地或网络上的图像。

+   **Item**：`Item`类型是 Qt Quick 中所有可视项的最基本的 QML 类型。Qt Quick 中的所有可视项都继承自这个`Item`类型。

+   **MouseArea**：我们已经在默认的 Qt Quick 应用程序项目中看到了`MouseArea`类型的示例用法。它在预定义区域内检测鼠标点击和触摸事件，并在检测到时调用 clicked 信号。

+   **Rectangle**：`Rectangle` QML 类型与`Item`类型非常相似，只是它有一个可以填充纯色或渐变的背景。您还可以选择使用自己的颜色和厚度添加边框。

+   **文本**：`Text` QML 类型也很容易理解。它只是在窗口上显示一行文本。您可以使用它来显示特定字体系列和字体大小的纯文本和富文本。

+   **文本编辑**：文本编辑 QML 类型相当于 Qt Widgets 应用程序中的`文本编辑`小部件。当焦点在它上面时，允许用户输入文本。它可以显示纯文本和格式化文本，这与`文本输入`类型非常不同。

+   **文本输入**：文本输入 QML 类型相当于 Qt Widgets 应用程序中的行编辑小部件，因为它只能显示单行可编辑的纯文本，这与`文本编辑`类型不同。您还可以通过验证器或输入掩码对其应用输入约束。通过将`echoMode`设置为`Password`或`PasswordEchoOnEdit`，它也可以用于密码输入字段。

我们在这里讨论的 QML 类型是 Qt Quick Designer 默认提供的最基本的类型。这些也是用于构建其他更复杂的 QML 类型的基本构建块。Qt Quick 还提供了许多额外的模块，我们可以将其导入到我们的项目中，例如，如果我们在`MainForm.ui.qml`文件中添加以下行：

```cpp
import QtQuick.Controls 2.2
```

当您切换到设计模式时，Qt Quick Designer 将在您的 Qt Quick Designer 上显示一堆额外的 QML 类型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/64d47d41-00c4-45c9-9bbe-80aff6dc8bd3.png)

我们不会逐一介绍所有这些 QML 类型，因为它们太多了。如果您有兴趣了解更多关于这些 QML 类型的信息，请访问以下链接：[`doc.qt.io/qt-5.10/qtquick-controls-qmlmodule.html`](https://doc.qt.io/qt-5.10/qtquick-controls-qmlmodule.html)

# Qt Quick Designer

接下来，我们将看一下 Qt Quick Designer 对 Qt Quick 应用程序项目的布局。当您打开一个`.ui.qml`文件时，Qt Quick Designer，即包含在 Qt Creator 工具集中的设计工具，将自动为您启动。

自从本书第一章以来一直跟随所有示例项目的读者可能会意识到，Qt Quick Designer 看起来与我们一直在使用的设计工具有些不同。这是因为 Qt Quick 项目与 Qt Widgets 项目非常不同，因此设计工具自然也应该有所不同以适应其需求。

让我们看看 Qt Quick 项目中的 Qt Quick Designer 是什么样子的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/a20022be-e9e5-4630-baa7-4c0b82b689c5.png)

1.  库：库窗口显示当前项目可用的所有 QML 类型。您可以单击并将其拖动到画布窗口中以将其添加到您的 UI 中。您还可以创建自己的自定义 QML 类型并在此处显示。

1.  资源：资源窗口以列表形式显示所有资源，然后可以在 UI 设计中使用。

1.  导入：导入窗口允许您将不同的 Qt Quick 模块导入到当前项目中。

1.  导航器：导航器窗口以树形结构显示当前 QML 文件中的项目。它类似于 Qt Widgets 应用程序项目中的对象操作器窗口。

1.  连接：连接窗口由几个不同的选项卡组成：连接、绑定、属性和后端。这些选项卡允许您在不切换到编辑模式的情况下向您的 QML 文件添加连接（信号和槽）、绑定和属性。

1.  状态窗格：状态窗格显示 QML 项目中的不同状态，通常描述 UI 配置，例如 UI 控件、它们的属性和行为以及可用操作。

1.  画布：画布是您设计应用程序 UI 的工作区。

1.  属性窗格：与我们在 Qt Widgets 应用程序项目中使用的属性编辑器类似，QML 设计师中的属性窗格显示所选项目的属性。在更改这里的值后，您可以立即在 UI 中看到结果。

# Qt Quick 布局

与 Qt Widget 应用程序一样，Qt Quick 应用程序中也存在布局系统。唯一的区别是在 Qt Quick 中称为定位器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ee431b85-661f-47d1-9709-8f4d7a64297b.png)

最显著的相似之处是列和行定位器。这两者与 Qt Widgets 应用程序中的垂直布局和水平布局完全相同。除此之外，网格定位器也与网格布局相同。

在 Qt Quick 中唯一额外的是 Flow 定位器。Flow 定位器中包含的项目会像页面上的单词一样排列，项目沿一个轴排成一行，然后沿另一个轴放置项目行。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/931898a3-240c-472c-91f7-58409ec5cbc9.png)

# 基本的 QML 脚本

在接下来的部分中，我们将学习如何使用 Qt Quick Designer 和 QML 创建我们的第一个 Qt Quick 应用程序！

# 设置项目

话不多说，让我们动手使用 QML 创建一个 Qt Quick 应用程序吧！在这个示例项目中，我们将使用 Qt Quick Designer 和一个 QML 脚本创建一个虚拟登录界面。首先，让我们打开 Qt Creator，并通过转到文件|新建文件或项目...来创建一个新项目。

在那之后，选择 Qt Quick 应用程序并按“选择”....之后，一直按“下一步”直到项目创建完成。我们将在这个示例项目中使用所有默认设置，包括最小所需的 Qt 版本：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/f61ed1c4-6c26-438d-a9d0-adfe3d663049.png)

项目创建完成后，我们需要向项目中添加一些图像文件，以便稍后使用它们：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/984d0ff3-798c-46fe-9d4c-5b9745e3590c.png)

您可以在我们的 GitHub 页面上获取源文件（包括这些图像）：[`github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5`](http://github.com/PacktPublishing/Hands-On-GUI-Programming-with-C-QT5)

我们可以通过右键单击项目窗格中的`qml.qrc`文件并选择在编辑器中打开来将这些图像添加到我们的项目中。添加一个名为`images`的新前缀，并将所有图像文件添加到该前缀中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/44cb6357-0d0f-4a8c-83c4-c8182c2cafbb.png)

在那之后，打开`MainForm.ui.qml`，并删除 QML 文件中的所有内容。我们通过向画布添加一个 Item 类型，将其大小设置为 400 x 400，并将其命名为`loginForm`来重新开始。之后，在其下方添加一个`Image`类型，并将其命名为`background`。然后将背景图像应用到`Image`类型上，画布现在看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/885c2157-4e28-477d-8ccd-ebc2c3e669ec.png)

然后，在`Image`类型（背景）下添加一个`Rectangle`类型，并在属性窗格中打开布局选项卡。启用垂直和水平锚定选项。之后，将`width`设置为`402`，`height`设置为`210`，将`vertical anchor margin`设置为`50`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4b63ff3b-64b7-4cf3-919d-de2c5407db44.png)

接着，我们将矩形的颜色设置为`#fcf9f4`，边框颜色设置为`#efedeb`，然后将边框值设置为`1`。到目前为止，用户界面看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/2046715a-edfc-44b7-bd96-490ea0da78b6.png)

接下来，在矩形下添加一个 Image QML 类型，并将其锚定设置为顶部锚定和水平锚定。然后将其顶部锚定边距设置为`-110`，并将 logo 图像应用到其`image source`属性上。您可以通过单击位于画布顶部的小按钮来打开和关闭 QML 类型的边界矩形和条纹，这样在画布上充满内容时更容易查看结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/fd8bc259-88d1-458d-bcae-9d0aa18e09ab.png)

然后，我们在`loginRect`矩形下的画布中添加了三个`Rectangle`类型，并将它们命名为`emailRect`、`passwordRect`和`loginButton`。矩形的锚定设置如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b5ff6a01-25f6-4081-92bb-6e0607e3bf95.png)

然后，将`emailRect`和`passwordRect`的`border`值设置为`1`，`color`设置为`#ffffff`，`bordercolor`设置为`#efedeb`。至于`loginButton`，我们将`border`设置为`0`，`radius`设置为`2`，`color`设置为`#27ae61`。登录屏幕现在看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d5578076-0799-402b-a013-554a56330e25.png)

看起来不错。接下来，我们将在`emailRect`和`passwordRect`中添加`TextInput`、`Image`、`MouseArea`和`Text` QML 类型。由于这里有许多 QML 类型，我将列出需要设置的属性：

+   TextInput：

+   选择颜色设置为`#4f0080`

+   启用左锚点、右锚点和垂直锚点

+   左锚点边距`20`，右锚点边距`40`，垂直边距`3`

+   为密码输入设置 echoMode 为 Password

+   Image：

+   启用右锚点和垂直锚点

+   右锚点边距设置为`10`

+   将图像源设置为电子邮件图标或密码图标

+   将图像填充模式设置为 PreserveAspectFit

+   MouseArea：

+   启用填充父项

+   Text：

+   将文本属性分别设置为`E-Mail`和`Password`

+   文本颜色设置为`#cbbdbd`

+   将文本对齐设置为左对齐和顶部对齐

+   启用左锚点、右锚点和垂直锚点

+   左锚点边距`20`，右锚点边距`40`，垂直边距`-1`

完成后，还要为`loginButton`添加`MouseArea`和`Text`。为`MouseArea`启用`fill parent item`，为`Text` QML 类型启用`vertical`和`horizontal anchors`。然后，将其`text`属性设置为`LOGIN`。

您不必完全按照我的步骤进行，它们只是指导您实现与上面截图类似的结果的指南。但是，最好您应用自己的设计并创建独特的东西！

哦！经过上面漫长的过程，我们的登录屏幕现在应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/b17e64f5-faef-47a9-abd5-88669f766d47.png)

在转到`main.qml`之前，我们还需要做一件事，那就是公开我们登录屏幕中的一些 QML 类型，以便我们可以将其链接到我们的`main.qml`文件进行逻辑编程。实际上，我们可以直接在设计工具上做到这一点。您只需点击对象名称旁边的小矩形图标，并确保图标上的三条线穿过矩形框，就像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/882dcceb-99d9-4358-9e59-a444ab53d9d3.png)

我们需要公开/导出的 QML 类型是`emailInput`（TextInput）、`emailTouch`（MouseArea）、`emailDisplay`（Text）、`passwordInput`（TextInput）、`passwordTouch`（MouseArea）、`passwordDisplay`（Text）和`loginMouseArea`（MouseArea）。完成所有这些后，让我们打开`main.qml`。

首先，我们的`main.qml`应该看起来像这样，它只会打开一个空窗口：

```cpp
import QtQuick 2.6 
import QtQuick.Window 2.2 

Window { 
    id: window 
    visible: true 
    width: 800 
    height: 600 
    title: qsTr("My App") 
} 
```

之后，添加`MainForm`对象，并将其锚点设置为`anchors.fill: parent`。然后，当点击（或触摸，如果在触摸设备上运行）`loginButton`时，在控制台窗口上打印一行文本`Login pressed`：

```cpp
Window { 
    id: window 
    visible: true 
    width: 800 
    height: 600 
    title: qsTr("My App") 

    MainForm 
    { 
        anchors.fill: parent 

        loginMouseArea.onClicked: 
        { 
            console.log("Login pressed"); 
        } 
    } 
} 
```

之后，我们将编写`MouseArea`在电子邮件输入上被点击/触摸时的行为。由于我们手动创建自己的文本字段，而不是使用`QtQuick.Controls`模块提供的`TextField` QML 类型，我们必须手动隐藏和显示`E-Mail`和`Password`文本显示，并在用户点击/触摸`MouseArea`时更改输入焦点。

我选择不使用`TextField`类型的原因是，我几乎无法自定义`TextField`的视觉呈现，那么为什么不创建自己的呢？手动为电子邮件输入设置焦点的代码如下：

```cpp
emailTouch.onClicked: 
{ 
    emailDisplay.visible = false;      // Hide emailDisplay 
    emailInput.forceActiveFocus();     // Focus emailInput 
    Qt.inputMethod.show();       // Activate virtual keyboard 
} 

emailInput.onFocusChanged: 
{ 
    if (emailInput.focus == false && emailInput.text == "") 
    { 
        emailDisplay.visible = true;   // Show emailDisplay if 
        emailInput is empty when loses focus 
    } 
} 
```

之后，对密码字段执行相同操作：

```cpp
passwordTouch.onClicked: 
{ 
    passwordDisplay.visible = false;   // Hide passwordDisplay 
    passwordInput.forceActiveFocus();  // Focus passwordInput 
    Qt.inputMethod.show();       // Activate virtual keyboard 
} 

passwordInput.onFocusChanged: 
{ 
    if (passwordInput.focus == false && passwordInput.text == "") 
    { 
        passwordDisplay.visible = true;      // Show passwordDisplay if  
        passwordInput is empty when loses focus 
    } 
} 
```

就是这样，我们完成了！现在您可以编译和运行程序。您应该会得到类似这样的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/e4f5430c-1afb-4481-842b-fa0dcb61ffea.png)

如果您没有看到图片，并且收到错误消息说 Qt 无法打开图片，请返回到您的`MainForm.ui.qml`，并在源属性的前面添加前缀`image/`。这是因为 Qt Quick Designer 加载图片时没有前缀，而您的最终程序需要前缀。添加了前缀后，您可能会意识到在 Qt Quick Designer 中不再看到图片显示，但在最终程序中将正常工作。

我不确定这是一个错误还是他们有意这样做的。希望 Qt 的开发人员可以解决这个问题，这样我们就不必再做额外的步骤了。就是这样，希望您已经理解了 Qt Widgets 应用程序和 Qt Quick 应用程序之间的相似之处和不同之处。现在您可以从这两者中选择最适合您项目需求的选项了！

# 总结

在本章中，我们学习了 Qt Quick 是什么，以及如何使用 QML 语言创建程序。在接下来的章节中，我们将学习如何将我们的 Qt 项目轻松导出到不同的平台。让我们开始吧！


# 第十五章：跨平台开发

自从第一次发布以来，Qt 就以其跨平台能力而闻名。这也是创始人在决定创建这个框架时的主要目标之一，早在它被**诺基亚**和后来的**Qt 公司**接管之前。

在本章中，我们将涵盖以下主题：

+   编译器

+   构建设置

+   部署到 PC 平台

+   部署到移动平台

让我们开始吧。

# 了解编译器

在本章中，我们将学习从 Qt 项目生成可执行文件的过程。这个过程就是我们所谓的**编译**或**构建**。用于此目的的工具称为**编译器**。在接下来的部分中，我们将学习编译器是什么，以及如何使用它为我们的 Qt 项目生成可执行文件。

# 什么是编译器？

当我们开发一个应用程序时，无论是使用 Qt 还是其他任何软件开发工具包，我们经常需要将项目编译成可执行文件，但实际上在我们编译项目时到底发生了什么呢？

**编译器**是一种软件，它将用高级编程语言编写的计算机代码或计算机指令转换为计算机可以读取和执行的机器代码或较低级别形式。这种低级机器代码在操作系统和计算机处理器上都有很大的不同，但你不必担心，因为编译器会为你转换它。

这意味着你只需要担心用人类可读的编程语言编写逻辑代码，让编译器为你完成工作。理论上，通过使用不同的编译器，你应该能够将代码编译成可在不同操作系统和硬件上运行的可执行程序。我在这里使用“理论上”这个词是因为实际上要比使用不同的编译器更困难，你可能还需要实现支持目标平台的库。然而，Qt 已经为你处理了所有这些，所以你不必做额外的工作。

在当前版本中，Qt 支持以下编译器：

+   **GNU 编译器集合（GCC）**：GCC 是用于 Linux 和 macOS 的编译器

+   **MinGW（Windows 的最小 GNU）**：MinGW 是 GCC 和 GNU Binutils（二进制工具）的本地软件端口，用于在 Windows 上开发应用程序

+   **Microsoft Visual C++（MSVC）**：Qt 支持 MSVC 2013、2015 和 2017 用于构建 Windows 应用程序

+   **XCode**：XCode 是开发者为 macOS 和 iOS 开发应用程序时使用的主要编译器

+   **Linux ICC（英特尔 C++编译器）**：Linux ICC 是英特尔为 Linux 应用程序开发开发的一组 C 和 C++编译器

+   **Clang**：Clang 是 LLVM 编译器的 C、C++、Objective C 和 Objective C++前端，适用于 Windows、Linux 和 macOS

+   **Nim**：Nim 是适用于 Windows、Linux 和 macOS 的 Nim 编译器

+   **QCC**：QCC 是用于在 QNX 操作系统上编译 C++应用程序的接口

# 使用 Make 进行构建自动化

在软件开发中，**Make**是一种构建自动化工具，它通过读取名为**Makefiles**的配置文件自动从源代码构建可执行程序和库，这些配置文件指定如何生成目标平台。简而言之，Make 程序生成构建配置文件，并使用它们告诉编译器在生成最终可执行程序之前要做什么。

Qt 支持两种类型的 Make 程序：

+   **qmake**：它是 Qt 团队开发的本地 Make 程序。它在 Qt Creator 上效果最好，我强烈建议在所有 Qt 项目中使用它。

+   **CMake**：另一方面，尽管这是一个非常强大的构建系统，但它并不像 qmake 那样专门为 Qt 项目做所有事情，比如：

+   运行**元对象编译器**（**MOC**）

+   告诉编译器在哪里查找 Qt 头文件

+   告诉链接器在哪里查找 Qt 库

在 CMake 上手动执行上述步骤，以便成功编译 Qt 项目。只有在以下情况下才应使用 CMake：

+   您正在处理一个非 Qt 项目，但希望使用 Qt Creator 编写代码

+   您正在处理一个需要复杂配置的大型项目，而 qmake 无法处理

+   您真的很喜欢使用 CMake，并且您确切地知道自己在做什么

在选择适合项目的正确工具时，Qt 真的非常灵活。它不仅限于自己的构建系统和编译器。它给开发人员自由选择最适合其项目的工具。

# 构建设置

在项目编译或构建之前，编译器需要在继续之前了解一些细节。这些细节被称为**构建设置**，是编译过程中非常重要的一个方面。在接下来的部分中，我们将学习构建设置是什么，以及如何以准确的方式配置它们。

# Qt 项目（.pro）文件

我相信您已经了解**Qt 项目文件**，因为我们在整本书中已经提到了无数次。`.pro`文件实际上是*qmake*用来构建应用程序、库或插件的项目文件。它包含了所有信息，例如链接到头文件和源文件，项目所需的库，不同平台/环境的自定义构建过程等。一个简单的项目文件可能如下所示：

```cpp
QT += core gui widgets 

TARGET = MyApp 
TEMPLATE = app 

SOURCES +=  
        main.cpp  
        mainwindow.cpp 

HEADERS +=  
        mainwindow.h 

FORMS +=  
        mainwindow.ui 

RESOURCES +=  
    resource.qrc 
```

它只是告诉 qmake 应该在项目中包含哪些 Qt 模块，可执行程序的名称是什么，应用程序的类型是什么，最后是需要包含在项目中的头文件、源文件、表单声明文件和资源文件的链接。所有这些信息对于 qmake 生成配置文件并成功构建应用程序至关重要。对于更复杂的项目，您可能希望为不同的操作系统不同地配置项目。在 Qt 项目文件中也可以轻松实现这一点。

要了解如何为不同的操作系统配置项目，请参阅以下链接：[`doc.qt.io/qt-5/qmake-language.html#scopes-and-conditions.`](http://doc.qt.io/qt-5/qmake-language.html#scopes-and-conditions)

# 评论

您可以在项目文件中添加自己的注释，以提醒自己添加特定配置行的目的，这样您在一段时间不接触后就不会忘记为什么添加了一行。注释以井号（`#`）开头，之后您可以写任何内容，因为构建系统将简单地忽略整行文本。例如：

```cpp
# The following define makes your compiler emit warnings if you use 
# any feature of Qt which has been marked as deprecated (the exact warnings 
# depend on your compiler). Please consult the documentation of the 
# deprecated API in order to know how to port your code away from it. 
DEFINES += QT_DEPRECATED_WARNINGS 
```

您还可以添加虚线或使用空格使您的评论脱颖而出：

```cpp
#------------------------------------------------- 
# 
# Project created by QtCreator 2018-02-18T01:59:44 
# 
#------------------------------------------------- 
```

# 模块、配置和定义

您可以向项目添加不同的 Qt 模块、配置选项和定义。让我们看看我们如何实现这些。要添加额外的模块，只需在`QT +=`后面添加`module`关键字，如下所示：

```cpp
QT += core gui sql printsupport charts multimedia 
```

或者您还可以在前面添加条件来确定何时向项目添加特定模块：

```cpp
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets 
```

您还可以向项目添加配置设置。例如，我们希望明确要求编译器在编译我们的项目时遵循 C++规范的 2011 版本（称为 C++11），并使其成为多线程应用程序：

```cpp
CONFIG += qt c++11 thread
```

您必须使用`+=`，而不是`=`，否则 qmake 将无法使用 Qt 的配置来确定项目所需的设置。或者，您也可以使用`-=`来从项目中删除模块、配置和定义。

至于向编译器添加定义（或变量），我们使用`DEFINES`关键字，如下所示：

```cpp
DEFINES += QT_DEPRECATED_WARNINGS 
```

在编译项目之前，qmake 将此变量的值作为编译器 C 预处理宏（`-D`选项）添加到项目中。前面的定义告诉 Qt 编译器，如果您使用了已标记为弃用的 Qt 功能，则会发出警告。

# 特定于平台的设置

您可以为不同的平台设置不同的配置或设置，因为并非每个设置都适用于所有用例。例如，如果我们想为不同的操作系统包含不同的头文件路径，可以执行以下操作：

```cpp
win32:INCLUDEPATH += "C:/mylibs/extra headers" 
unix:INCLUDEPATH += "/home/user/extra headers" 
```

或者，您还可以将设置放在花括号中，这类似于编程语言中的`if`语句：

```cpp
win32 { 
    SOURCES += extra_code.cpp 
} 
```

您可以通过访问以下链接查看项目文件中可以使用的所有设置：[`doc.qt.io/qt-5/qmake-variable-reference.html.`](http://doc.qt.io/qt-5/qmake-variable-reference.html)

# 部署到 PC 平台

让我们继续学习如何在 Windows、Linux 和 macOS 等平台上部署我们的应用程序。

# Windows

在本节中，我们将学习如何将我们的应用程序部署到不同的操作系统。尽管 Qt 默认支持所有主要平台，但可能需要设置一些配置，以便使您的应用程序能够轻松部署到所有平台。

我们将要介绍的第一个操作系统是最常见的**Microsoft Windows**。

从 Qt 5.6 开始，Qt 不再支持**Windows XP**。

在您尝试部署的 Windows 版本上可能有某些插件无法正常工作，因此在决定处理项目之前，请查看文档。但可以肯定的是，大多数功能在 Qt 上都可以直接使用。

默认情况下，当您将 Qt 安装到 Windows PC 时，**MinGW** 32 位编译器会一起安装。不幸的是，除非您从源代码编译 Qt，否则默认情况下不支持 64 位。如果您需要构建 64 位应用程序，可以考虑在**Microsoft Visual Studio**旁边安装 MSVC 版本的 Qt。可以从以下链接免费获取 Microsoft Visual Studio：[`www.visualstudio.com/vs`](https://www.visualstudio.com/vs)。

您可以通过转到 Tools | Options，然后转到 Build & Run 类别并选择 Kits 选项卡，在 Qt Creator 中设置编译器设置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/4061d513-9767-4724-9382-a1c09d727cc1.png)

如您所见，有多个运行在不同编译器上的工具包，您可以进行配置。默认情况下，Qt 已经配备了五个工具包——一个用于 Android，一个用于 MinGW，三个用于 MSVC（版本 2013、2015 和 2017）。Qt 将自动检测这些编译器的存在，并相应地为您配置这些设置。

如果您尚未安装**Visual Studio**或**Android SDK**，则在工具包选项前会出现带有感叹号的红色图标。安装所需的编译器后，请尝试重新启动 Qt Creator。它现在将检测到新安装的编译器。您应该可以毫无问题地为 Windows 平台编译 Qt 将为您处理其余部分。我们将在另一节中更多地讨论 Android 平台。

编译应用程序后，打开安装 Qt 的文件夹。将相关的 DLL 文件复制到应用程序文件夹中，并在分发给用户之前将其打包在一起。没有这些 DLL 文件，用户可能无法运行 Qt 应用程序。

有关更多信息，请访问以下链接：[`doc.qt.io/qt-5/windows-deployment.html.`](http://doc.qt.io/qt-5/windows-deployment.html)

要为应用程序设置自定义图标，必须将以下代码添加到项目（`.pro`）文件中：

```cpp
win32:RC_ICONS = myappico.ico 
```

前面的代码仅适用于 Windows 平台，因此我们必须在其前面添加`win32`关键字。

# Linux

**Linux**（或 GNU/Linux）通常被认为是主导云/服务器市场的主要操作系统。由于 Linux 不是单一操作系统（Linux 以不完全兼容的不同 Linux 发行版的形式由不同供应商提供），就像 Windows 或 macOS 一样，开发人员很难构建他们的应用程序并期望它们在不同的 Linux 发行版（**distros**）上无缝运行。但是，如果您在 Qt 上开发 Linux 应用程序，只要目标系统上存在 Qt 库，它就有很高的机会在大多数发行版上运行，如果不是所有主要发行版。

在 Linux 上的默认套件选择比 Windows 简单得多。由于 64 位应用程序已经成为大多数 Linux 发行版的主流和标准已经有一段时间了，我们在安装 Qt 时只需要包括**GCC** 64 位编译器。还有一个 Android 选项，但我们稍后会详细讨论：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/39cbb752-788b-4f19-be8e-80a6fe79aecb.png)

如果您是第一次在 Qt Creator 上编译 Linux 应用程序，我相当肯定您会收到以下错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/8cb011d6-5884-41c7-9359-949a3da431c1.png)

这是因为您尚未安装构建 Linux 应用程序所需的相关工具，例如 Make、GCC 和其他程序。

不同的 Linux 发行版安装程序的方法略有不同，但我不会在这里解释每一个。在我的情况下，我使用的是 Ubuntu 发行版，所以我首先打开终端并键入以下命令来安装包含 Make 和 GCC 的`build-essential`软件包：

```cpp
sudo apt-get install build-essential 
```

前面的命令仅适用于继承自**Debian**和**Ubuntu**的发行版，可能不适用于其他发行版，如**Fedora**、**Gentoo**、**Slackware**等。您应该搜索您的 Linux 发行版使用的适当命令来安装这些软件包，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/ca215015-a2a1-4372-bc16-b295382402fb.png)

一旦安装了适当的软件包，请重新启动 Qt Creator 并转到工具|选项。然后，转到“构建和运行”类别，打开“套件”选项卡。现在，您应该能够为您的桌面套件选择 C 和 C ++选项的编译器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d8efa23d-958b-49c4-a0af-9d9ab6ef91b5.png)

但是，当您再次尝试编译时，可能会遇到另一个错误，即找不到-lGL：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3fa99b4a-7ff3-4fbb-a194-4fadbb2b8cc1.png)

这是因为 Qt 试图寻找`OpenGL`库，但在您的系统上找不到它们。通过使用以下命令安装`Mesa 开发`库软件包，可以轻松解决这个问题：

```cpp
sudo apt-get install libgl1-mesa-dev 
```

同样，前面的命令仅适用于 Debian 和 Ubuntu 变体。如果您没有运行 Debian 或 Ubuntu 分支之一，请寻找适合您的 Linux 发行版的命令：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/469afd43-8058-490f-87dd-f89d97955bd7.png)

安装了软件包后，您应该能够编译和运行 Qt 应用程序而无任何问题：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/f90b95a8-a587-4cfd-8c60-c291a40177ae.png)

至于使用其他不太流行的编译器，如**Linux ICC**、**Nim**或**QCC**，您必须通过单击位于 Kits 界面右侧的“添加”按钮来手动设置，然后输入所有适当的设置以使其正常工作。大多数人不使用这些编译器，所以我们暂时跳过它们。

在分发 Linux 应用程序时，比 Windows 或 macOS 要复杂得多。这是因为 Linux 不是单一操作系统，而是一堆具有自己依赖项和配置的不同发行版，这使得分发程序非常困难。

最安全的方法是静态编译程序，这有其优缺点。您的程序将变得非常庞大，这使得对于互联网连接速度较慢的用户来说，更新软件将成为一个巨大的负担。除此之外，如果您不是在进行开源项目并且没有 Qt 商业许可证，Qt 许可证也禁止您进行静态构建。要了解有关 Qt 许可选项的更多信息，请访问以下链接：[`www1.qt.io/licensing-comparison`](https://www1.qt.io/licensing-comparison)

另一种方法是要求用户在运行应用程序之前安装正确版本的 Qt，但这将在用户端产生大量问题，因为并非每个用户都非常精通技术，并且有耐心去避免依赖地狱。

因此，最好的方法是将 Qt 库与应用程序一起分发，就像我们在 Windows 平台上所做的那样。该库可能在某些 Linux 发行版上无法工作（很少见，但有一点可能性），但可以通过为不同的发行版创建不同的安装程序来轻松克服这个问题，现在每个人都很满意。

然而，出于安全原因，Linux 应用程序通常不会默认在其本地目录中查找其依赖项。您必须在您的 qmake 项目（.pro）文件中使用可执行文件的`rpath`设置中的`$ORIGIN`关键字：

```cpp
unix:!mac{ 
QMAKE_LFLAGS += -Wl,--rpath=$$ORIGIN 
QMAKE_RPATH= 
} 
```

设置`QMAKE_RPATH`会清除 Qt 库的默认`rpath`设置。这允许将 Qt 库与应用程序捆绑在一起。如果要将`rpath`包括在 Qt 库的路径中，就不要设置`QMAKE_RPATH`。

之后，只需将 Qt 安装文件夹中的所有库文件复制到应用程序的文件夹中，并从文件名中删除其次版本号。例如，将`libQtCore.so.5.8.1`重命名为`libQtCore.so.5`，现在应该能够被您的 Linux 应用程序检测到。

至于应用程序图标，默认情况下无法为 Linux 应用程序应用任何图标，因为不受支持。尽管某些桌面环境（如 KDE 和 GNOME）支持应用程序图标，但必须手动安装和配置图标，这对用户来说并不是很方便。它甚至可能在某些用户的 PC 上无法工作，因为每个发行版的工作方式都有些不同。为应用程序设置图标的最佳方法是在安装过程中创建桌面快捷方式（符号链接）并将图标应用于快捷方式。

# macOS

在我看来，**macOS**是软件世界中最集中的操作系统。它不仅设计为仅在 Macintosh 机器上运行，您还需要从 Apple 应用商店下载或购买软件。

毫无疑问，这对一些关心选择自由的人造成了不安，但另一方面，这也意味着开发人员在构建和分发应用程序时遇到的问题更少。

除此之外，macOS 应用程序的行为与 ZIP 存档非常相似，每个应用程序都有自己的目录，其中包含适当的库。因此，用户无需预先在其操作系统上安装 Qt 库，一切都可以直接使用。

至于 Kit Selection，Qt for macOS 支持 Android、clang 64 位、iOS 和 iOS 模拟器的工具包：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/735061cd-1346-48d1-bc11-915a94b1f452.png)

从 Qt 5.10 及更高版本开始，Qt 不再支持 macOS 的 32 位构建。此外，Qt 不支持 PowerPC 上的 OS X；由于 Qt 在内部使用 Cocoa，因此也不可能构建 Carbon，请注意这一点。

在编译您的 macOS 应用程序之前，请先从 App Store 安装 Xcode。Xcode 是 macOS 的集成开发环境，包含了由苹果开发的一套用于开发 macOS 和 iOS 软件的软件开发工具。一旦安装了 Xcode，Qt Creator 将检测到其存在，并自动为您设置编译器设置，这非常棒：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/5998a25c-8025-4cab-a703-0ebc982da29c.png)

编译项目后，生成的可执行程序是一个单个的应用程序包，可以轻松地分发给用户。由于所有库文件都打包在应用程序包中，因此它应该可以在用户的 PC 上直接运行。

为 Mac 设置应用程序图标是一项非常简单的任务。只需将以下代码添加到您的项目（`.pro`）文件中，我们就可以开始了：

```cpp
ICON = myapp.icns 
```

请注意，图标格式为`.icns`，而不是我们通常用于 Windows 的`.ico`。

# 在移动平台上部署

除了 Windows、Linux 和 macOS 等平台外，移动平台同样重要。许多开发人员希望将他们的应用程序部署到移动平台。让我们看看如何做到这一点。我们将涵盖两个主要平台，即 iOS 和 Android。

# iOS

在 iOS 上部署 Qt 应用程序非常简单。就像我们之前为 macOS 所做的那样，您需要首先在开发 PC 上安装 Xcode：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3be1b23b-4409-4291-8b3a-50b98101ecde.png)

然后，重新启动 Qt Creator。它现在应该能够检测到 Xcode 的存在，并且会自动为您设置编译器设置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/3a8e54b9-b260-4f38-8b25-33541d29e9a0.png)

之后，只需将 iPhone 连接并点击运行按钮！

在 Qt 上构建 iOS 应用程序确实很容易。然而，分发它们并不容易。这是因为 iOS 就像一个有围墙的花园一样，是一个非常封闭的生态系统。您不仅需要在 Apple 注册为应用程序开发人员，还需要在能够将其分发给用户之前对 iOS 应用程序进行代码签名。如果您想为 iOS 构建应用程序，您无法避开这些步骤。

您可以通过访问以下链接了解更多信息：[`developer.apple.com/app-store/submissions.`](https://developer.apple.com/app-store/submissions)

# Android

尽管 Android 是基于 Linux 的操作系统，但与您在 PC 上运行的 Linux 平台相比，它非常不同。要在 Qt 上构建 Android 应用程序，无论您是在 Windows、Linux 还是 macOS 上运行，都必须先将**Android SDK**、**Android NDK**和**Apache ANT**安装到开发 PC 上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/c84e6e83-7ac5-46fc-b538-4f7013df7fa0.png)

这三个软件包在构建 Qt 上的 Android 应用程序时至关重要。一旦它们都安装好了，重新启动 Qt Creator，它应该已经检测到它们的存在，并且构建设置现在应该已经自动设置好了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/670eda7a-b1cb-49ef-80f4-e32d4bf20ced.png)

最后，您可以通过使用 Qt Creator 打开`AndroidManifect.xml`文件来配置您的 Android 应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d5039d76-b634-4e6b-9116-3b4ef38c82c0.png)

您可以在这里设置一切，如包名称、版本代码、SDK 版本、应用程序图标、权限等。

与 iOS 相比，Android 是一个开放的系统，因此在将应用程序分发给用户之前，您无需做任何事情。但是，如果您希望在 Google Play 商店上分发您的应用程序，可以选择注册为 Google Play 开发人员。

# 总结

在本章中，我们已经学习了如何为不同平台（如 Windows、Linux、macOS、Android 和 iOS）编译和分发我们的 Qt 应用程序。在下一章中，我们将学习不同的调试方法，这可以节省开发时间。让我们来看看吧！


# 第十六章：测试和调试

在阅读与编程相关的教程或文章时，我们经常看到*调试*这个词。但是您知道调试是什么意思吗？在编程术语中，*bug*表示计算机程序中的错误或缺陷，导致软件无法正常运行，通常会导致不正确的输出甚至崩溃。

在本章中，我们将涵盖以下主题，并学习如何调试我们的 Qt 项目：

+   调试技术

+   Qt 支持的调试器

+   单元测试

让我们开始吧。

# 调试技术

在开发过程中经常会出现技术问题。为了解决这些问题，我们需要在将应用程序发布给用户之前找出所有这些问题并解决它们，以免影响公司/团队的声誉。用于查找技术问题的方法称为调试。在本节中，我们将介绍专业人士常用的常见调试技术，以确保他们的程序可靠且质量高。

# 识别问题

在调试程序时，无论编程语言或平台如何，最重要的是知道代码的哪一部分导致了问题。您可以通过几种方式来识别问题代码：

+   询问用户出现错误的位置；例如，按下了哪个按钮，导致崩溃的步骤是什么，等等。

+   注释掉代码的一部分，然后重新构建和运行程序，以检查问题是否仍然存在。如果问题仍然存在，继续注释更多的代码，直到找到问题所在的代码行。

+   使用内置调试器通过设置数据断点来检查目标函数中的变量更改。您可以轻松地发现您的变量是否已更改为意外值，或者对象指针是否已变为未定义指针。

+   确保您为用户安装程序中包含的所有库与项目中使用的库具有匹配的版本号。

# 使用 QDebug 打印变量

您还可以使用`QDebug`类将变量的值打印到应用程序输出窗口。`QDebug`与标准库中的`std::cout`非常相似，但使用`QDebug`的优势在于，由于它是 Qt 的一部分，它支持 Qt 类，而且能够在不需要任何转换的情况下输出其值。

要启用`QDebug`，我们必须首先包含其头文件：

```cpp
#include <QDebug> 
```

之后，我们可以调用`qDebug()`将变量打印到应用程序输出窗口：

```cpp
int amount = 100; 
qDebug() << "You have obtained" << amount << "apples!"; 
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/085d30a2-eaa0-43d5-8887-4df07ebf0ed9.png)

通过使用`QDebug`，我们将能够检查我们的函数是否正常运行。在检查完问题后，您可以注释掉包含`qDebug()`的特定代码行。

# 设置断点

设置断点是调试程序的另一种好方法。当您在 Qt Creator 中右键单击脚本的行号时，将会弹出一个包含三个选项的菜单，您可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/6ee7547c-f999-4056-b55d-41a1ea786a99.png)

第一个选项称为在行处设置断点...，允许您在脚本的特定行上设置断点。一旦创建了断点，该行号旁边将出现一个红色圆点图标：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/59956e75-08f7-4699-8bd7-2d45b6d49ee0.png)

第二个选项称为在行处设置消息跟踪点...，当程序到达特定代码行时打印消息。一旦创建了断点，该行号旁边将出现一个眼睛图标：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/488f3bb1-e9de-42ac-8600-e4b592256270.png)

第三个选项是切换书签，允许您为自己设置书签。让我们创建一个名为`test()`的函数来尝试断点：

```cpp
void MainWindow::test() 
{ 
   int amount = 100; 
   amount -= 10; 
   qDebug() << "You have obtained" << amount << "apples!"; 
} 
```

之后，我们在`MainWindow`构造函数中调用`test()`函数：

```cpp
MainWindow::MainWindow(QWidget *parent) : 
   QMainWindow(parent), 
   ui(new Ui::MainWindow) 
{ 
   ui->setupUi(this); 
   test(); 
} 
```

然后，按下位于 Qt Creator 窗口左下角的开始调试按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/dc999d58-3ca2-4a24-91b9-0474314d3908.png)

您可能会收到类似于这样的错误消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d8c0529c-a614-491e-ac8f-0089a0b6a7c5.png)

在这种情况下，请确保您的项目工具包已连接到调试器。如果仍然出现此错误，请关闭 Qt Creator，转到您的项目文件夹并删除`.pro.user`文件。然后，用 Qt Creator 打开您的项目。Qt Creator 将重新配置您的项目，并且调试模式现在应该可以工作了。

让我们给我们的代码添加两个断点并运行它。一旦我们的程序启动，我们将看到一个黄色箭头出现在第一个红点的顶部：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/d5b0fc54-92ce-48ef-a6e6-7ce0af651b97.png)

这意味着调试器已经停在了第一个断点处。现在，位于 Qt Creator 右侧的本地和表达式窗口将显示变量及其值和类型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/401c5d9f-2626-4871-ac40-f7bba1272cab.png)

在上图中，您可以看到值仍然为 100，因为此时减法操作尚未运行。接下来，我们需要做的是单击位于 Qt Creator 底部的堆栈窗口顶部的“步入”按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/fb1565d7-beb1-4642-ae50-737e7795057c.png)

之后，调试器将移动到下一个断点，这里我们可以看到值已经减少到了 90，正如预期的那样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/fca1e49a-7ed7-4b7b-b17e-56aed8a01921.png)

您可以使用这种方法轻松检查您的应用程序。要删除断点，只需再次单击红点图标。

请注意，您必须在调试模式下运行此操作。这是因为在调试模式下编译时，将额外的调试符号嵌入到您的应用程序或库中，使您的调试器能够访问来自二进制源代码的信息，例如标识符、变量和例程的名称。这也是为什么在调试模式下编译的应用程序或库的文件大小会更大的原因。

# Qt 支持的调试器

Qt 支持不同类型的调试器。根据您的项目运行的平台和编译器，使用的调试器也会有所不同。以下是 Qt 通常支持的调试器列表：

+   **Windows (MinGW):** GDB (GNU 调试器)

+   **Windows (MSVC):** CDB (Windows 调试工具)

+   **macOS**: LLDB (LLVM 调试器), FSF GDB (实验性)

+   **Linux**: GDB, LLDB (实验性)

+   **Unix** (FreeBSD, OpenBSD, 等): GDB

+   **Android**: GDB

+   **iOS**: LLDB

# PC 的调试

对于**GDB (GNU 调试器)**，如果您在 Windows 上使用 MinGW 编译器，则无需进行任何手动设置，因为它通常与您的 Qt 安装一起提供。如果您运行其他操作系统，如 Linux，则可能需要在将其与 Qt Creator 链接之前手动安装它。Qt Creator 会自动检测 GDB 的存在并将其与您的项目链接起来。如果没有，您可以轻松地在 Qt 目录中找到 GDB 可执行文件并自行链接。

另一方面，需要在 Windows 机器上手动安装**CDB (Windows 调试工具)**。请注意，Qt 不支持 Visual Studio 的内置调试器。因此，您需要通过在安装 Windows SDK 时选择一个名为“调试工具”的可选组件来单独安装 CDB 调试器。Qt Creator 通常会识别 CDB 的存在，并将其放在调试器选项页面下的调试器列表中。您可以转到“工具”|“选项”|“构建和运行”|“调试器”查找设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/9b474cf0-8099-4386-860c-4ef15f5e5e40.png)

# 针对 Android 设备的调试

针对 Android 设备的调试比 PC 稍微复杂一些。您必须安装所有必要的 Android 开发包，如 JDK（6 或更高版本）、Android SDK 和 Android NDK。然后，您还需要在 Windows 平台上安装 Android 调试桥（ADB）驱动程序，以启用 USB 调试，因为 Windows 上的默认 USB 驱动程序不允许调试。

# macOS 和 iOS 的调试

至于 macOS 和 iOS，使用的调试器是**LLDB（LLVM 调试器）**，它默认随 Xcode 一起提供。Qt Creator 也会自动识别其存在并将其与您的项目链接起来。

每个调试器都与另一个略有不同，并且在 Qt Creator 上可能表现不同。如果您熟悉这些工具并知道自己在做什么，还可以在其各自的 IDE（Visual Studio、XCode 等）上运行非 GDB 调试器。

如果您需要向项目添加其他调试器，可以转到“工具”|“选项”|“构建和运行”|“工具包”，然后单击“克隆”以复制现有工具包。然后，在“调试器”选项卡下，单击“添加”按钮以添加新的调试器选择：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-gui-prog-qt5/img/471d3646-ff16-4764-a526-92ea5bf8f6b4.png)

在“名称”字段中，输入调试器的描述性名称，以便您可以轻松记住其目的。然后，在“路径”字段中指定调试器二进制文件的路径，以便 Qt Creator 知道在启动调试过程时要运行哪个可执行文件。除此之外，“类型”和“版本”字段由 Qt Creator 用于识别调试器的类型和版本。此外，Qt Creator 还在“ABIs”字段中显示将在嵌入式设备上使用的 ABI 版本。

要了解如何在 Qt 中设置不同调试器的详细信息，请访问以下链接：

[`doc.qt.io/qtcreator/creator-debugger-engines.html.`](http://doc.qt.io/qtcreator/creator-debugger-engines.html)

# 单元测试

单元测试是一个自动化的过程，用于测试应用程序中的单个模块、类或方法。单元测试可以在开发周期的早期发现问题。这包括程序员实现中的错误和单元规范中的缺陷或缺失部分。

# Qt 中的单元测试

Qt 带有一个内置的单元测试模块，我们可以通过在项目文件（.pro）中添加`testlib`关键字来使用它：

```cpp
QT += core gui testlib 
```

之后，将以下标题添加到我们的源代码中：

```cpp
#include <QtTest/QtTest> 
```

然后，我们可以开始测试我们的代码。我们必须将测试函数声明为私有槽。除此之外，该类还必须继承自`QOBject`类。例如，我创建了两个文本函数，分别称为`testString()`和`testGui()`，如下所示：

```cpp
private slots: 
   void testString(); 
   void testGui(); 
```

函数定义看起来像这样：

```cpp
void MainWindow::testString() 
{ 
   QString text = "Testing"; 
   QVERIFY(text.toUpper() == "TESTING"); 
} 

void MainWindow::testGui() 
{ 
   QTest::keyClicks(ui->lineEdit, "testing gui"); 
   QCOMPARE(ui->lineEdit->text(), QString("testing gui")); 
} 
```

我们使用`QTest`类提供的一些宏，如`QVERIFY`、`QCOMPARE`等，来评估作为其参数传递的表达式。如果表达式求值为`true`，则测试函数的执行将继续。否则，将向测试日志附加描述失败的消息，并且测试函数停止执行。

我们还使用了`QTest::keyClicks()`来模拟鼠标在我们的应用程序中的点击。在前面的示例中，我们模拟了在主窗口小部件上的行编辑小部件上的点击。然后，我们输入一行文本到行编辑中，并使用`QCOMPARE`宏来测试文本是否已正确插入到行编辑小部件中。如果出现任何问题，Qt 将在应用程序输出窗口中显示问题。

之后，注释掉我们的`main()`函数，而是使用`QTEST_MAIN()`函数来开始测试我们的`MainWindow`类：

```cpp
/*int main(int argc, char *argv[]) 
{ 
   QApplication a(argc, argv); 
   MainWindow w; 
   w.show(); 

   return a.exec(); 
}*/ 
QTEST_MAIN(MainWindow) 
```

如果我们现在构建和运行我们的项目，我们应该会得到类似以下的结果：

```cpp
********* Start testing of MainWindow ********* 
Config: Using QtTest library 5.9.1, Qt 5.9.1 (i386-little_endian-ilp32 shared (dynamic) debug build; by GCC 5.3.0) 
PASS   : MainWindow::initTestCase() 
PASS   : MainWindow::_q_showIfNotHidden() 
PASS   : MainWindow::testString() 
PASS   : MainWindow::testGui() 
PASS   : MainWindow::cleanupTestCase() 
Totals: 5 passed, 0 failed, 0 skipped, 0 blacklisted, 880ms 
********* Finished testing of MainWindow ********* 
```

还有许多宏可以用来测试应用程序。

有关更多信息，请访问以下链接：

[`doc.qt.io/qt-5/qtest.html#macros`](http://doc.qt.io/qt-5/qtest.html#macros)

# 总结

在这一章中，我们学习了如何使用多种调试技术来识别 Qt 项目中的技术问题。除此之外，我们还了解了 Qt 在不同操作系统上支持的不同调试器。最后，我们还学会了如何通过单元测试自动化一些调试步骤。

就是这样！我们已经到达了本书的结尾。希望你在学习如何使用 Qt 从头开始构建自己的应用程序时找到了这本书的用处。你可以在 GitHub 上找到所有的源代码。祝你一切顺利！
