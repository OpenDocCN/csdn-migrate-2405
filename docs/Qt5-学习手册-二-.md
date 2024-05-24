# Qt5 学习手册（二）

> 原文：[`annas-archive.org/md5/9fdbc9f976587acda3d186af05c73879`](https://annas-archive.org/md5/9fdbc9f976587acda3d186af05c73879)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：样式

在开发过程中，通常最好先考虑功能，然后再考虑形式，但 UI 是我们的用户与之交互的应用程序的一部分，也是成功解决方案的关键因素。在本章中，我们将介绍类似 CSS 的样式资源，并在上一章介绍的响应式设计原则的基础上进行构建。

我们将创建自定义的 QML 组件和模块，以最大程度地重用代码。我们将集成 Font Awesome 到我们的解决方案中，为我们提供一套可扩展的图标，并帮助我们的 UI 呈现出现代的图形外观。我们将整理导航栏，引入命令的概念，并构建一个动态的、上下文敏感的命令栏的框架。

在本章中，我们将涵盖以下主题：

+   自定义样式资源

+   字体真棒

+   自定义组件

+   导航栏样式

+   命令

# 样式资源

首先，让我们创建一个新的资源文件，以包含我们需要的非 QML 视觉元素。在`cm-ui`项目中，添加新... > Qt > Qt 资源文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/98aae715-a183-4b20-a955-8370098aad56.png)

将文件命名为`assets.qrc`，并将其放置在`cm/cm-ui`中。您的新文件将自动在资源编辑器中打开，我发现这个编辑器并不是特别有用，所以关闭它。您将看到`assets.qrc`文件已添加到`cm-ui`项目的资源部分。右键单击它，然后选择添加新... > Qt > QML 文件。将文件命名为`Style.qml`，并将其保存到`cm/cm-ui/assets`。

在纯文本编辑器中编辑`assets.qrc`文件，方式与我们为视图所做的方式相同：

```cpp
<RCC>
    <qresource prefix="/assets">
        <file alias="Style.qml">assets/Style.qml</file>
    </qresource>
</RCC>
```

现在，编辑`Style.qml`，我们将添加一个用于视图背景颜色的单个样式属性：

```cpp
pragma Singleton
import QtQuick 2.9

Item {
    readonly property color colourBackground: "#f4c842"
}
```

在 C++术语中，我们正在创建一个具有名为`colourBackground`的 const 颜色类型的公共成员变量的单例类，并初始化为（非常）浅灰色的十六进制 RGB 代码的值。

现在，我们需要进行一点手动的调整。我们需要在与`Style.qml`（`cm/cm-ui/assets`）相同的文件夹中创建一个名为`qmldir`的模块定义文件（没有文件扩展名）。对于这种类型的文件，没有内置模板，因此我们需要自己创建它。在旧版本的 Windows 中，文件资源管理器总是坚持要求文件扩展名，因此这总是一个痛苦的练习。需要使用控制台命令强制重命名文件。Windows 10 将愉快地创建没有扩展名的文件。在 Unix 世界中，没有扩展名的文件更常见。

创建`qmldir`文件后，编辑`assets.qrc`，并在`/assets`前缀内的`Style.qml`旁边插入一个新条目：

```cpp
<file alias="qmldir">assets/qmldir</file>
```

双击新添加的`qmldir`文件，并输入以下行：

```cpp
module assets
singleton Style 1.0 Style.qml
```

我们已经在**导入 QtQuick 2.9**时看到了模块。这使得 QtQuick 模块的 2.9 版本可以在我们的视图中使用。在我们的`qmldir`文件中，我们正在定义一个名为`assets`的新模块，并告诉 Qt 该模块的 1.0 版本中有一个**Style**对象，其实现在我们的`Style.qml`文件中。

创建并连接了我们的新样式模块后，现在让我们开始使用这种现代的米白色。从我们看到的第一个子视图`SplashView`开始，并添加以下内容以访问我们的新模块：

```cpp
import assets 1.0
```

您会注意到我们被呈现出愤怒的红色下划线，表明一切并不顺利。将鼠标指针悬停在该行上，工具提示会告诉我们，我们需要将导入路径添加到我们的新`qmldir`定义文件中。

有几种方法可以做到这一点。第一种选择是转到“项目”模式，选择当前“工具包”的构建设置，然后选择调试模式。在“构建环境”部分的底部，单击“详细信息”。在这里，您可以看到当前工具包和配置的所有环境变量的列表。添加一个名为 QML2_IMPORT_PATH 的新变量，并将其值设置为`cm-ui`文件夹：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/15b22f72-580d-476a-bc12-0b56ead7901c.png)

这将`cm-ui`项目的工作目录(`/projects/qt/cm/cm-ui`)添加到 QML 导入路径。请注意，我们的模块名必须反映到`qmldir`文件相对于此导入路径的相对路径。

这种方法的问题在于，这个环境变量与`cm.pro.user`文件绑定。如果您与其他开发人员共享项目，他们将拥有自己的`cm.pro.user`文件，并且他们必须记住也要添加这个变量。此外，它与绝对路径绑定，如果您将项目代码复制到另一台机器上，它可能不在那个位置。

第二种，也是首选的选项是在实例化**QQmlApplicationEngine**之后立即在`main.cpp`中添加以下行：

```cpp
engine.addImportPath("qrc:/");
```

那么为什么是`qrc:/`而不是我们`qmldir`文件的绝对路径？您会记得我们在`cm-ui.pro`中的`RESOURCES`变量中添加了我们的`views.qrc`资源包。这样做的作用是将`views.qrc`中的所有文件编译到应用程序二进制文件中，形成一种虚拟文件系统，其中前缀充当虚拟文件夹。这个虚拟文件系统的根目录被引用为`qrc:/`，通过在导入路径中使用这个，我们实质上是在要求 Qt 在我们的所有捆绑资源文件中查找任何模块。转到`cm-ui.pro`，确保我们的新`assets.qrc`也已添加到`RESOURCES`中：

```cpp
RESOURCES += views.qrc \
    assets.qrc
```

这可能有点令人困惑，所以重申一下，我们已经添加了以下文件夹来搜索新的模块，可以使用 QML2_IMPORT_PATH 环境变量在本地物理文件系统上搜索我们的`cm-ui`项目文件夹，或者使用`addImportPath()`方法在运行时搜索我们虚拟资源文件系统的根目录。

在这两种情况下，定义我们的新模块的`qmldir`文件位于一个名为`assets`的文件夹中，即在物理文件系统中的`<Qt Projects>/cm/cm-ui/assets`或虚拟文件系统中的`qrc:/assets`。

这给我们模块名`assets`。如果我们的文件夹结构更深，比如 stuff/badgers/assets，那么我们的模块需要被称为`stuff.badgers.assets`，因为这是相对于我们定义的导入路径的路径。同样，如果我们想为现有视图添加另一个模块，我们将在`cm-ui/views`中创建一个`qmldir`文件，并称模块为`views`。

如果您发现 Qt Creator 仍然有点困惑，红线仍然存在，请确保`cm-ui.pro`包含`QML_IMPORT_PATH += $$PWD`行。

有了这一切，我们现在可以使用我们的新模块。包括模块意味着我们现在可以访问我们的单例`Style`对象并从中读取属性。替换我们的`SplashView`的`color`属性：

```cpp
Rectangle {
    ...    
    color: Style.colourBackground
    ...
}
```

重复此操作，为除`MasterView`之外的所有视图设置背景颜色。记得在每个视图中也包含`include ui.assets 1.0`。

当您构建和运行应用程序时，您可能会想知道为什么我们要经历所有这些麻烦，而视图看起来与以前完全相同。好吧，假设我们刚刚与营销部的人开了个会，他们告诉我们，橙黄色不再适合品牌，我们需要将所有视图更改为干净的米白色。以前，我们必须进入每个视图，并将颜色从`#f4c842`更改为`#efefef`。现在，只有七个，所以这没什么大不了的，但是想象一下，如果我们不得不为 50 个复杂的视图中的所有组件更改所有颜色，那将是一个非常痛苦的过程。

然而，转到`Style.qml`并将`colourBackground`属性从`#f4c842`更改为`#efefef`。构建和运行应用程序，沐浴在我们重新品牌的应用程序的荣耀中！通过尽早设置我们的共享样式组件，我们可以在进行的过程中添加属性，然后稍后重新设计我们的应用程序变得更容易。我们可以在这里添加所有类型的属性，不仅仅是颜色，所以随着我们进一步开发，我们将添加大小、字体和其他东西。

# Font Awesome

有了我们的样式框架，让我们来看看我们的导航栏是什么样子的，然后想想我们想要实现什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/5ff42490-1ab9-4573-88bc-ac1e8e9af10c.png)

我们想要在导航栏上显示的按钮是仪表板视图（主页视图）、新客户视图和查找客户视图，以及顶部的切换按钮，用于展开和折叠栏。

常见的 UI 设计模式是使用图标表示简单的命令。有多种方式可以获取有关命令的更多信息；例如，当您悬停在按钮上时，可以在工具提示中或屏幕底部的状态栏中显示信息。我们的方法是拥有一个可折叠的栏。栏的默认状态将是折叠的，并显示代表每个命令的图标。在展开状态下，栏将显示图标和命令的文本描述。用户可以使用额外的按钮切换状态。这是一种在移动应用程序开发中特别普遍的模式，因为您希望默认情况下尽可能少地占用屏幕空间。

有几种选项可以显示按钮的图标。较旧的桌面应用程序很可能会使用某种图像文件。这样可以完全控制图标的外观，但也带来了一些缺点。图像文件往往比较大，并且是固定大小的。如果需要以不同的大小绘制它们，它们可能会看起来很糟糕，特别是如果它们被放大或者纵横比发生变化。

**可缩放矢量图形**（**SVG**）文件要小得多，并且缩放效果非常好。它们更难创建，在艺术上可能有一些限制，但对于图标的用途非常有用。然而，根据经验，它们在 Qt/QML 中可能会很棘手。

第三种选项可以让您获得 SVG 的小文件大小和可伸缩性优势，但更容易使用的是符号字体文件。这是 Web 开发中非常常见的解决方案，也是我们将采取的方法。

有许多符号字体可用，但也许最受欢迎的是**Font Awesome**。它提供了各种精彩的符号，并且有一个非常有帮助的网站；请查看：[`fontawesome.io/`](http://fontawesome.io/)。

检查您选择使用的字体的任何许可证，特别是如果您要商业使用它们。

下载工具包并打开存档文件。我们感兴趣的文件是`fonts`/`fontawesome-webfont.ttf`。将此文件复制到我们项目文件夹中的`cm/cm-ui/assets`中。

在我们的`cm-ui`项目中，编辑`assets.qrc`并将字体添加到我们的资源中：

```cpp
<file alias="fontawesome.ttf">assets/fontawesome-webfont.ttf</file>
```

请记住，我们的别名不一定要与原始文件名相同，我们已经有机会将其缩短一点。

接下来，编辑`Style.qml`，我们将把字体与我们的自定义样式连接起来，以便轻松使用。我们首先需要加载字体并使其可用，我们使用`FontLoader`组件来实现这一点。在根**Item**元素内添加以下内容：

```cpp
FontLoader {
    id: fontAwesomeLoader
    source: "qrc:/assets/fontawesome.ttf"
}    
```

在`source`属性中，我们使用了我们在`assets.qrc`文件中定义的`/assets`前缀（或虚拟文件夹），以及`fontawesome.ttf`的别名。现在，我们已经加载了字体，但是就目前而言，我们无法从`Style.qml`之外引用它。这是因为只有根组件级别的属性可以在文件之外访问。子组件被视为私有的。我们绕过这个问题的方法是为我们想要公开的元素创建一个`property alias`：

```cpp
Item {
    property alias fontAwesome: fontAwesomeLoader.name

    readonly property color colourBackground: "#efefef"

    FontLoader {
        id: fontAwesomeLoader
        source: "qrc:/assets/fontawesome.ttf"
    }    
}
```

这将创建一个名为`fontAwesome`的公共可用属性，当调用时，它会简单地将调用者重定向到内部`fontAwesomeLoader`元素的`name`属性。

完成连接后，让我们找到我们想要使用的图标。回到 Font Awesome 网站，转到图标页面。在这里，您可以看到所有可用的图标。单击其中一个将显示有关它的更多信息，我们可以从中获取需要显示它的关键信息，即 Unicode 字符。我将为我们的菜单选择以下图标，但请随意选择任何您想要的图标：

| **命令** | **图标** | **Unicode 字符** |
| --- | --- | --- |
| Toggle Menu | bars | f0c9 |
| Dashboard | home | f015 |
| New Client | user-plus | f234 |
| Find Client | search | f002 |

现在，让我们用每个图标的`Text`组件替换`MasterView`上的`Button`组件：

```cpp
Column {
    Text {
        font {
            family: Style.fontAwesome
            pixelSize: 42
        }
        color: "#ffffff"
        text: "\uf0c9"
    }
    Text {
        font {
            family: Style.fontAwesome
            pixelSize: 42
        }
        color: "#ffffff"
        text: "\uf015"
    }
    Text {
        font {
            family: Style.fontAwesome
            pixelSize: 42
        }
        color: "#ffffff"
        text: "\uf234"
    }
    Text {
        font {
            family: Style.fontAwesome
            pixelSize: 42
        }
        color: "#ffffff"
        text: "\uf002"
    }
}
```

如果您还没有添加**assets 1.0**导入，则还需要添加它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/0f8f95a5-e2a7-4511-986b-f772c7d125d3.png)

接下来，我们将为客户命令添加描述性文本。将每个`Text`组件包装在`Row`中，并添加一个描述的`Text`组件，如下所示：

```cpp
Row {
    Text {
        font {
            family: Style.fontAwesome
            pixelSize: 42
        }
        color: "#ffffff"
        text: "\uf234"
    }
    Text {
        color: "#ffffff"
        text: "New Client"
    }
}
```

`Row`组件将水平布置其子元素——首先是图标，然后是描述性文本。对其他命令重复此操作。为其他按钮添加 Dashboard 和 Find Client 的描述，对于切换命令只需添加空字符串：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/877075bc-0bc9-4813-8ba1-dd98326e65dd.png)

在我们进一步进行更改之前，我们将停下来，进行一些重构，并开始引入组件。

# 组件

我们刚刚编写的 QML 已经足够功能，但已经变得难以维护。我们的`MasterView`变得有点长，难以阅读。例如，当我们要更改命令按钮的外观时，例如对齐图标和文本，我们将不得不在四个地方进行更改。如果我们想要添加第五个按钮，我们必须复制、粘贴和编辑大量的 QML。这就是可重用组件发挥作用的地方。

组件与我们已经创建的视图完全相同——只是 QML 的片段。区别纯粹是语义上的。在本书中，视图代表布局内容的屏幕，而组件是内容。

创建新组件的最简单方法是当您已经编写了要形成组件基础的 QML 时。右键单击我们为命令添加的任何`Row`元素，并选择**重构 > 将组件移动到单独的文件中**。

将新组件命名为`NavigationButton`并将其保存到一个新文件夹`cm/cm-ui/components`中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/4b37e410-961d-4855-b235-5b6102bea245.png)

`Row`元素将移动到我们的新文件中，在`MasterView`中，您将得到一个空的`NavigationButton`组件：

```cpp
NavigationButton {
}
```

不幸的是，它带有一个大大的红色波浪线，我们的应用程序将不再运行。虽然重构步骤已经为我们创建了一个新的`NavigationButton.qml`文件，但它实际上并没有包含在我们的项目中，所以 Qt 不知道它在哪里。不过，解决起来很容易，我们只需要像我们对视图和资产所做的那样设置我们的资源包：

1.  创建一个名为`components.qrc`的新的`Qt Resource File`，放在`cm/cm-ui`文件夹中

1.  在`cm/cm-ui/components`中创建一个空的`qmldir`文件，就像我们为我们的资产所做的那样

1.  编辑`components.qrc`以在`/components`前缀下包含我们的两个新文件：

```cpp
<RCC>
    <qresource prefix="/components">
        <file alias="qmldir">components/qmldir</file>
        <file   
 alias="NavigationButton.qml">components/NavigationButton.qml</file>
    </qresource>
</RCC>
```

1.  编辑`qmldir`以设置我们的模块并将我们的`NavigationButton`组件添加到其中：

```cpp
module components
NavigationButton 1.0 NavigationButton.qml
```

1.  确保`components.qrc`已添加到`cm-ui.pro`中的`RESOURCES`变量中

1.  在`MasterView`中，包含我们的新组件模块，以便访问我们的新组件：

```cpp
import components 1.0
```

有时，要使我们的模块得到完全识别并消除红色波浪线，可能只能通过重新启动 Qt Creator 来实现，因为这样可以强制重新加载所有的 QML 模块。

现在我们有一个可重用的组件，隐藏了实现细节，减少了代码重复，并且更容易添加新的命令和维护旧的命令。然而，在我们可以为其他命令利用它之前，还有一些改变需要做。

目前，我们的`NavigationButton`有硬编码的图标和描述文本值，无论何时我们使用组件，它们都将是相同的。我们需要公开文本属性，以便我们可以为我们的每个命令设置不同的值。正如我们所看到的，我们可以使用属性别名来实现这一点，但我们需要为此添加唯一的标识符到我们的`Text`元素中。让我们将默认值设置为一些通用的内容，并且还要实现本书早期的建议，将`Item`组件作为根元素：

```cpp
import QtQuick 2.9
import assets 1.0

Item {
    property alias iconCharacter: textIcon.text
    property alias description: textDescription.text

    Row {
        Text {
            id: textIcon
            font {
                family: Style.fontAwesome
                pixelSize: 42
            }
            color: "#ffffff"
            text: "\uf11a"
        }
        Text {
            id: textDescription
            color: "#ffffff"
            text: "SET ME!!"
        }
    }
}
```

现在我们的组件可以通过属性进行配置，我们可以替换`MasterView`中的命令：

```cpp
Column {
    NavigationButton {
        iconCharacter: "\uf0c9"
        description: ""
    }
    NavigationButton {
        iconCharacter: "\uf015"
        description: "Dashboard"
    }
    NavigationButton {
        iconCharacter: "\uf234"
        description: "New Client"
    }
    NavigationButton {
        iconCharacter: "\uf002"
        description: "Find Client"
    }
}
```

这比我们之前拥有的所有重复的 QML 要简洁和易于管理得多。现在，如果你运行应用程序，你会看到虽然我们已经向前迈出了一小步，但我们也后退了一步：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/2cc949e0-1300-4208-b473-ab860a09c420.png)

正如你所看到的，我们所有的组件都是叠加在一起的。这个问题的根本原因是我们之前提到的关于大小的问题。我们有一个带有根`Item`元素的可视组件，并且我们没有明确定义它的大小。我们忽视的另一件事是我们的自定义样式。让我们接下来修复这些问题。

# 样式化导航栏

从简单的部分开始，让我们首先将`NavigationButton`中的硬编码颜色和图标像素大小移到`Style.qml`中：

```cpp
readonly property color colourNavigationBarBackground: "#000000"
readonly property color colourNavigationBarFont: "#ffffff"
readonly property int pixelSizeNavigationBarIcon: 42
```

我们现在需要考虑我们想要调整按钮元素的大小。我们有一个图标，我们希望它是正方形的，所以宽度和高度将是相同的。接下来，我们有一个文本描述，它的高度将与图标相同，但宽度会更宽：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/1a0d5ede-e554-4bff-8009-5485a5757630.png)

整个组件的宽度是图标的宽度加上描述的宽度。整个组件的高度与图标和描述的高度相同；然而，这样做可以让我们更灵活地将高度设置为两者中较大的一个。这样，如果我们决定将一个项目变大，我们知道组件将足够大以容纳它们。让我们选择图标的起始尺寸为 80 x 80，描述的尺寸为 80 x 240，并定义这些属性：

```cpp
readonly property real widthNavigationButtonIcon: 80
readonly property real heightNavigationButtonIcon: widthNavigationButtonIcon
readonly property real widthNavigationButtonDescription: 240
readonly property real heightNavigationButtonDescription: heightNavigationButtonIcon
readonly property real widthNavigationButton: widthNavigationButtonIcon + widthNavigationButtonDescription
readonly property real heightNavigationButton: Math.max(heightNavigationButtonIcon, heightNavigationButtonDescription)
```

这里有几件事情需要注意。属性可以直接绑定到其他属性，这样可以减少重复的数量，使整个设置更加动态。我们知道我们希望我们的图标是正方形的，所以通过将高度绑定为与宽度相同，如果我们想要改变图标的总大小，我们只需要更新宽度，高度将自动更新。QML 还与 JavaScript 引擎有很强的集成，所以我们可以使用`Math.max()`函数来帮助我们找出哪个高度更大。

我们希望导航按钮提供一些视觉提示，当用户将鼠标悬停在按钮上时，指示它是一个交互元素。为了做到这一点，我们需要每个按钮都有自己的背景矩形。

在`NavigationButton`中，将`Row`元素包装在一个新的`Rectangle`中，并将尺寸插入到我们的组件中：

```cpp
Item {
    property alias iconCharacter: textIcon.text
    property alias description: textDescription.text

    width: Style.widthNavigationButton
    height: Style.heightNavigationButton

    Rectangle {
        id: background
        anchors.fill: parent
        color: Style.colourNavigationBarBackground

        Row {
            Text {
                id: textIcon
                width: Style.widthNavigationButtonIcon
                height: Style.heightNavigationButtonIcon
                font {
                    family: Style.fontAwesome
                    pixelSize: Style.pixelSizeNavigationBarIcon
                }
                color: Style.colourNavigationBarFont
                text: "\uf11a"
            }
            Text {
                id: textDescription
                width: Style.widthNavigationButtonDescription
                height: Style.heightNavigationButtonDescription
                color: Style.colourNavigationBarFont
                text: "SET ME!!"
            }
        }
    }
}
```

再次运行，你会看到略微的改进：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/4ea8081d-d28b-40e7-9335-9a31e0c02f7c.png)

我们的导航栏被硬编码为 100 像素宽，导致部分描述被切断。我们需要改变这一点，并且还要实现切换展开/折叠的功能。我们已经计算出了我们需要的尺寸，所以让我们通过向`Style.qml`添加一些新属性来做好准备：

```cpp
readonly property real widthNavigationBarCollapsed: widthNavigationButtonIcon
readonly property real heightNavigationBarExpanded: widthNavigationButton
```

折叠状态将刚好宽到足够容纳图标，而展开状态将包含整个按钮，包括描述。

接下来，让我们将我们的导航栏封装在一个新的组件中。在这种情况下，不会有任何重用的好处，因为只会有一个，但这有助于保持我们的 QML 组织有序，并使`MasterView`更简洁和易于阅读。

你可以右键单击`MasterView`中的`Rectangle`组件，并将我们的导航栏重构为一个新的 QML 文件，就像我们为我们的`NavigationButton`所做的那样。然而，让我们手动操作，这样你就可以熟悉这两种方法。右键单击`components.qrc`，然后选择添加新内容... > Qt > QML 文件。将`NavigationBar.qml`添加到`cm/cm-ui/components`中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/0c4e1ac6-4818-49d8-8118-07d9ecf603b6.png)

编辑`components.qrc`，将我们的新`NavigationBar`移动到`/components`前缀部分，并使用别名：

```cpp
<file alias="NavigationBar.qml">components/NavigationBar.qml</file>
```

将组件添加到我们的组件模块中，编辑`qmldir`：

```cpp
NavigationBar 1.0 NavigationBar.qml
```

从`MasterView`中剪切`Rectangle`及其子元素，并将其粘贴到`NavigationBar.qml`中的根`Item`元素内。如果已经初始化为较旧的版本，请将`QtQuick`模块导入更新为版本 2.9。添加一个导入我们资产模块的导入，以获得对我们 Style 对象的访问。将`Rectangle`的`anchors`和`width`属性移到根`Item`，并设置`Rectangle`以填充其父元素：

```cpp
import QtQuick 2.9
import assets 1.0

Item {
    anchors {
        top: parent.top
        bottom: parent.bottom
        left: parent.left
    }
    width: 100

    Rectangle {
        anchors.fill: parent
        color: "#000000"

        Column {
            NavigationButton {
                iconCharacter: "\uf0c9"
                description: ""
            }
            NavigationButton {
                iconCharacter: "\uf015"
                description: "Dashboard"
            }
            NavigationButton {
                iconCharacter: "\uf234"
                description: "New Client"
            }
            NavigationButton {
                iconCharacter: "\uf002"
                description: "Find Client"
            }
        }
    }
}
```

回到`MasterView`，现在可以在原来的`Rectangle`位置添加新的`NavigationBar`组件：

```cpp
NavigationBar {
    id: navigationBar
}
```

虽然你会再次看到可怕的红色波浪线，但你实际上可以运行应用程序并验证重构没有出现任何问题。

我们新的`NavigationBar`组件的定位是好的，但`width`要复杂一些——我们怎么知道它应该是`Style.widthNavigationBarCollapsed`还是`Style.heightNavigationBarExpanded`？我们将通过一个公开访问的布尔属性来控制这一点，该属性指示栏是否已折叠。然后我们可以使用这个属性的值来决定我们想要使用哪个宽度，使用条件`?`操作符语法。最初将属性设置为 true，这样栏将默认以折叠状态呈现：

```cpp
property bool isCollapsed: true
```

有了这个，替换 100 的硬编码`width`如下：

```cpp
width: isCollapsed ? Style.widthNavigationBarCollapsed : Style.heightNavigationBarExpanded
```

接下来，更新`Rectangle`的`color`属性为`Style.colourNavigationBarBackground`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/d9041acb-28ab-4c99-99bb-b7c7b247be84.png)

现在我们已经接近了，但我们一路上错过的一个关键点是，现在点击按钮实际上什么都不做了。让我们下一步修复这个问题。

# 点击

在本书的早期，我们看过一个叫做`MouseArea`的组件。这很快被我们使用的`Button`组件所取代，它为我们提供了点击功能。然而，现在我们正在开发自己的按钮形式，我们需要自己实现点击功能。与`Button`组件类似，我们的`NavigationButton`在被点击时实际上不应该做任何事情，除了通知其父组件事件已发生。组件应尽可能地通用和无知于上下文，以便您可以在多个地方使用它们。我们需要做的是添加一个`MouseArea`组件，并通过自定义信号简单地传递`onClicked`事件。

在`NavigationButton`中，我们首先添加我们希望在组件被点击时发出的信号。在属性之后添加这个：

```cpp
signal navigationButtonClicked()
```

尽量给信号起相当具体的名称，即使有点长。如果你简单地把一切都叫做`clicked()`，那么事情可能会变得有点混乱，有时你可能会发现自己引用了一个不同于你打算的信号。

接下来，我们将添加另一个属性来支持我们将要实现的鼠标悬停效果。这将是一个`color`类型，并且我们将默认它为常规背景颜色：

```cpp
property color hoverColour: Style.colourNavigationBarBackground
```

我们将与`Rectangle`的`states`属性一起使用这个颜色：

```cpp
states: [
    State {
        name: "hover"
        PropertyChanges {
            target: background
            color: hoverColour
        }
    }
]
```

将数组中的每个状态视为一个命名配置。默认配置没有名称（""），由我们已经在`Rectangle`元素中设置的属性组成。 “悬停”状态应用于`PropertyChanges`元素中指定的属性的更改，也就是说，它将把 ID 为`background`的元素的`color`属性更改为`hoverColour`的值。

接下来，在`Rectangle`内但在`Row`下方，添加我们的`MouseArea`：

```cpp
MouseArea {
    anchors.fill: parent
    cursorShape: Qt.PointingHandCursor
    hoverEnabled: true
    onEntered: background.state = "hover"
    onExited: background.state = ""
    onClicked: navigationButtonClicked()
}
```

我们使用`anchors`属性来填充整个按钮背景区域，包括图标和描述。接下来，我们将通过将鼠标光标更改为指向手指，当它进入按钮区域时启用悬停`hoverEnabled`标志来使事情变得有趣一些。启用后，当光标进入和退出区域时会发出**entered**和**exited**信号，我们可以使用相应的插槽通过在刚刚实现的悬停状态和默认（""）之间切换来改变我们的背景`Rectangle`的外观。最后，我们通过`MouseArea`的`clicked()`信号响应`onClicked()`插槽并简单地发出我们自己的信号。

现在我们可以对`NavigationBar`组件中的`navigationButtonClicked()`信号做出反应，并在此过程中添加一些悬停颜色。首先实现切换按钮：

```cpp
NavigationButton {
    iconCharacter: "\uf0c9"
    description: ""
    hoverColour: "#993333"
    onNavigationButtonClicked: isCollapsed = !isCollapsed
}
```

我们实现了`<MyCapitalisedSignalName>`约定来为我们的信号创建一个插槽，当它触发时，我们只需在`true`和`false`之间切换`isCollapsed`的值。

现在可以运行应用程序。单击切换按钮以展开和折叠导航栏：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/180bd707-01e0-487d-a7c1-3e63e5c47372.png)

请注意，由于我们使用了`anchors`，子视图会动态调整大小以适应导航栏。当您悬停在按钮上时，还会看到指向手指光标和一道闪烁的颜色，这有助于用户理解它是一个交互式元素并可视化边界。

对于剩余的导航按钮，我们希望在点击事件发生时发出`NavigationCoordinator`上的`goDashboardView()`，`goCreateClientView()`和`goFindClientView()`信号。

将`onNavigationButtonClicked`插槽添加到其他按钮，并通过`masterController`对象深入到我们想要调用的信号。也可以添加一些自己喜欢的花哨颜色：

```cpp
NavigationButton {
    iconCharacter: "\uf015"
    description: "Dashboard"
    hoverColour: "#dc8a00"
    onNavigationButtonClicked: masterController.ui_navigationController.goDashboardView();
}
NavigationButton {
    iconCharacter: "\uf234"
    description: "New Client"
    hoverColour: "#dccd00"
    onNavigationButtonClicked: masterController.ui_navigationController.goCreateClientView();
}
NavigationButton {
    iconCharacter: "\uf002"
    description: "Find Client"
    hoverColour: "#8aef63"
    onNavigationButtonClicked: masterController.ui_navigationController.goFindClientView();
}
```

现在可以单击按钮导航到不同的子视图。

为了完成导航栏的最后一些微调，我们需要更好地对齐按钮的内容并调整一些大小。

描述文本应该垂直对齐到图标的中心而不是顶部，我们的图标应该居中而不是紧贴窗口边缘。第一个问题很容易解决，因为我们已经在大小上保持了一致并且明确。只需将以下属性添加到`NavigationButton`中的两个`Text`组件中：

```cpp
verticalAlignment: Text.AlignVCenter
```

两个`Text`元素的大小被调整为占据整个按钮的高度，因此我们只需要在该空间内垂直对齐文本。

修复图标的对齐方式与之前一样，但这次是在水平轴上。在图标的`Text`组件中添加以下内容：

```cpp
horizontalAlignment: Text.AlignHCenter
```

至于大小，我们的描述文本有点小，文本后面有很多空白。向我们的`Style`对象添加一个新属性：

```cpp
readonly property int pixelSizeNavigationBarText: 22
```

在描述`Text`元素中使用新属性：

```cpp
font.pixelSize: Style.pixelSizeNavigationBarText
```

接下来，将`Style`中的`widthNavigationButtonDescription`属性减小到 160。

运行应用程序，我们几乎到达目标了。大小和对齐现在好多了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/d011ffc4-fc00-4900-9347-f7f6ae385647.png)

但是，您可能没有注意到的一件事是，当栏被折叠并且只显示图标时，`MouseArea`仍然是包括描述的整个按钮的宽度。尝试将鼠标移动到描述的位置，您会看到指向手光标出现。您甚至可以单击组件，然后进行过渡。我们需要做的是，而不是`NavigationButton`中的根`Item`元素是一个固定宽度（`Style.widthNavigationButton`），我们需要使其动态，并将其设置为`parent.width`。为了使其工作，我们需要沿着 QML 层次结构向上走，并确保其父级也有宽度。其父级是`NavigationBar`中的`Column`元素。将`Column`的`width`属性设置为`parent.width`。

有了这些改变，导航栏现在的行为符合预期。

# 命令

我们待办事项清单上的下一件事是实现一个上下文敏感的命令栏。虽然我们的导航栏是一个恒定的存在，无论用户在做什么，都有相同的按钮，但是命令栏会出现和消失，并且会根据上下文包含不同的按钮。例如，如果用户正在添加或编辑客户，我们将需要一个保存按钮来提交对数据库的任何更改。然而，如果我们正在搜索客户，那么保存就没有意义，而查找按钮更相关。虽然创建命令栏的技术与导航栏大致相似，但所需的额外灵活性提出了更大的挑战。

为了帮助我们克服这些障碍，我们将实现命令。这种方法的额外好处是，我们可以将逻辑从 UI 层移出，并移到业务逻辑层。我喜欢 UI 尽可能愚蠢和通用。这样可以使您的应用程序更加灵活，而且 C++代码中的错误比 QML 中的错误更容易识别和解决。

命令对象将封装一个图标，描述性文本，一个用于确定按钮是否启用的函数，最后，一个在相关按钮被按下时将被发射的`executed()`信号。然后我们的命令栏中的每个按钮将绑定到一个命令对象上。

我们的每个子视图可能都有一个命令列表和一个关联的命令栏。对于具有这些功能的视图，我们将通过命令控制器向 UI 呈现命令列表。

在`cm-lib`项目中创建两个新的`C++`类，两者都应该继承自 QObject：

+   **在新文件夹`cm-lib/source/framework`中的命令**

+   **现有文件夹`cm-lib/source/controllers`中的命令控制器**

`command.h`：

```cpp
#ifndef COMMAND_H
#define COMMAND_H

#include <functional>

#include <QObject>
#include <QScopedPointer>
#include <QString>

#include <cm-lib_global.h>

namespace cm {
namespace framework {

class CMLIBSHARED_EXPORT Command : public QObject
{
    Q_OBJECT
    Q_PROPERTY( QString ui_iconCharacter READ iconCharacter CONSTANT )
    Q_PROPERTY( QString ui_description READ description CONSTANT )
    Q_PROPERTY( bool ui_canExecute READ canExecute NOTIFY canExecuteChanged )

public:
    explicit Command(QObject* parent = nullptr,
                     const QString& iconCharacter = "",
                     const QString& description = "",
                     std::function<bool()> canExecute = [](){ return 
                                                           true; });
    ~Command();

    const QString& iconCharacter() const;
    const QString& description() const;
    bool canExecute() const;

signals:
    void canExecuteChanged();
    void executed();

private:
    class Implementation;
    QScopedPointer<Implementation> implementation;
};

}}

#endif
```

`command.cpp`：

```cpp
#include "command.h"

namespace cm {
namespace framework {

class Command::Implementation
{
public:
    Implementation(const QString& _iconCharacter, const QString& 
     _description, std::function<bool()> _canExecute)
        : iconCharacter(_iconCharacter)
        , description(_description)
        , canExecute(_canExecute)
    {
    }

    QString iconCharacter;
    QString description;
    std::function<bool()> canExecute;
};

Command::Command(QObject* parent, const QString& iconCharacter, const QString& description, std::function<bool()> canExecute)
    : QObject(parent)
{
    implementation.reset(new Implementation(iconCharacter, description, canExecute));
}

Command::~Command()
{
}

const QString& Command::iconCharacter() const
{
    return implementation->iconCharacter;
}

const QString& Command::description() const
{
    return implementation->description;
}

bool Command::canExecute() const
{
    return implementation->canExecute();
}

}
}
```

现在，QObject，命名空间和 dll 导出代码应该是熟悉的。我们将要在 UI 按钮上显示的图标字符和描述值表示为字符串。我们将成员变量隐藏在私有实现中，并为它们提供`访问器`方法。我们可以将`canExecute`成员表示为一个简单的`bool`成员，调用代码可以根据需要将其设置为`true`或`false`；然而，一个更加优雅的解决方案是传入一个方法，让它在运行时为我们计算值。默认情况下，我们将其设置为返回`true`的 lambda，这意味着按钮将被启用。我们提供了一个`canExecuteChanged()`信号来配合使用，我们可以在需要 UI 重新评估按钮是否启用时触发它。最后一个元素是`executed()`信号，当相应的按钮被按下时将被 UI 触发。

`command-controller.h`：

```cpp
#ifndef COMMANDCONTROLLER_H
#define COMMANDCONTROLLER_H

#include <QObject>
#include <QtQml/QQmlListProperty>
#include <cm-lib_global.h>
#include <framework/command.h>

namespace cm {
namespace controllers {

class CMLIBSHARED_EXPORT CommandController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QQmlListProperty<cm::framework::Command> 
     ui_createClientViewContextCommands READ  
     ui_createClientViewContextCommands CONSTANT)

public:
    explicit CommandController(QObject* _parent = nullptr);
    ~CommandController();

    QQmlListProperty<framework::Command> 
    ui_createClientViewContextCommands();

public slots:
    void onCreateClientSaveExecuted();

private:
    class Implementation;
    QScopedPointer<Implementation> implementation;
};

}}

#endif
```

`command-controller.cpp`：

```cpp
#include "command-controller.h"

#include <QList>
#include <QDebug>

using namespace cm::framework;

namespace cm {
namespace controllers {

class CommandController::Implementation
{
public:
    Implementation(CommandController* _commandController)
        : commandController(_commandController)
    {
        Command* createClientSaveCommand = new Command( 
          commandController, QChar( 0xf0c7 ), "Save" );
        QObject::connect( createClientSaveCommand, &Command::executed,   
   commandController, &CommandController::onCreateClientSaveExecuted );
        createClientViewContextCommands.append( createClientSaveCommand );
    }

    CommandController* commandController{nullptr};

    QList<Command*> createClientViewContextCommands{};
};

CommandController::CommandController(QObject* parent)
    : QObject(parent)
{
    implementation.reset(new Implementation(this));
}

CommandController::~CommandController()
{
}

QQmlListProperty<Command> CommandController::ui_createClientViewContextCommands()
{
    return QQmlListProperty<Command>(this, implementation->createClientViewContextCommands);
}

void CommandController::onCreateClientSaveExecuted()
{
    qDebug() << "You executed the Save command!";
}

}}
```

在这里，我们引入了一个新类型——`QQmlListProperty`。它本质上是一个包装器，使 QML 能够与自定义对象列表进行交互。请记住，我们需要在`Q_PROPERTY`语句中完全限定模板化类型。实际保存数据的私有成员是一个 QList，并且我们已经实现了一个将 QList 取出并将其转换为相同模板化类型的`QQmlListProperty`的`访问器`方法。

根据`QQmlListProperty`的文档，这种对象构造方法不应该在生产代码中使用，但我们将使用它来保持简单。

我们为`CreateClientView`创建了一个单一的命令列表。稍后我们将为其他视图添加命令列表。同样，现在我们会保持简单；我们只创建一个用于保存新创建客户的命令。在创建命令时，我们将其父级设置为命令协调器，这样我们就不必担心内存管理。我们为其分配了一个软盘图标（unicode f0c7）和`Save`标签。我们暂时将`canExecute`函数保持为默认值，这样它将始终处于启用状态。接下来，我们将`command`的`executed()`信号连接到`CommandController`的`onCreateClientSaveExecuted()`槽。连接完成后，我们将命令添加到列表中。

我们的意图是向用户呈现一个绑定到`Command`对象的命令按钮。当用户按下按钮时，我们将从 UI 触发`executed()`信号。我们设置的连接将导致命令控制器上的槽被调用，然后我们将执行我们的业务逻辑。现在，当按钮被按下时，我们将简单地在控制台上打印一行。

接下来，在`main.cpp`中注册我们的两种新类型（记住`#includes`）：

```cpp
qmlRegisterType<cm::controllers::CommandController>("CM", 1, 0, "CommandController");
qmlRegisterType<cm::framework::Command>("CM", 1, 0, "Command");
```

最后，我们需要将`CommandCoordinator`属性添加到`MasterController`中：

```cpp
Q_PROPERTY( cm::controllers::CommandController* ui_commandController READ commandController CONSTANT )
```

然后，我们添加一个`accessor`方法：

```cpp
CommandController* commandController();
```

最后，在`master-controller.cpp`中，实例化私有实现中的对象，并以与我们为`NavigationController`做的方式完全相同的方式实现`accessor`方法。

现在，我们已经为我们的`CreateClientView`准备好了一个（非常简短的！）命令列表。

# 命令栏

让我们首先为我们的命令组件的样式添加一些属性：

```cpp
readonly property color colourCommandBarBackground: "#cecece"
readonly property color colourCommandBarFont: "#131313"
readonly property color colourCommandBarFontDisabled: "#636363"
readonly property real heightCommandBar: heightCommandButton
readonly property int pixelSizeCommandBarIcon: 32
readonly property int pixelSizeCommandBarText: 12

readonly property real widthCommandButton: 80
readonly property real heightCommandButton: widthCommandButton
```

接下来，在我们的 UI 项目中创建两个新的 QML 组件：在`cm-ui/components`中创建`CommandBar.qml`和`CommandButton.qml`。更新`components.qrc`并将新组件移动到带有别名的`/components`前缀中。编辑`qmldir`并追加新组件：

```cpp
CommandBar 1.0 CommandBar.qml
CommandButton 1.0 CommandButton.qml
```

对于我们的按钮设计，我们希望在图标下方布置描述。图标应该略微位于中心位置之上。组件应该是正方形的，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/1bf95587-1026-463f-91b3-cfb511bdf1c2.png)

`CommandButton.qml`：

```cpp
import QtQuick 2.9
import CM 1.0
import assets 1.0

Item {
    property Command command
    width: Style.widthCommandButton
    height: Style.heightCommandButton

    Rectangle {
        id: background
        anchors.fill: parent
        color: Style.colourCommandBarBackground

        Text {
            id: textIcon
            anchors {
                centerIn: parent
                verticalCenterOffset: -10
            }
            font {
                family: Style.fontAwesome
                pixelSize: Style.pixelSizeCommandBarIcon
            }
            color: command.ui_canExecute ? Style.colourCommandBarFont : 
                                          colourCommandBarFontDisabled
            text: command.ui_iconCharacter
            horizontalAlignment: Text.AlignHCenter
        }

        Text {
            id: textDescription
            anchors {
                top: textIcon.bottom
                bottom: parent.bottom
                left: parent.left
                right: parent.right
            }
            font.pixelSize: Style.pixelSizeNavigationBarText
            color: command.ui_canExecute ? Style.colourCommandBarFont : 
                                          colourCommandBarFontDisabled
            text: command.ui_description
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            hoverEnabled: true
            onEntered: background.state = "hover"
            onExited: background.state = ""
            onClicked: if(command.ui_canExecute) {
                           command.executed();
                       }
        }

        states: [
            State {
                name: "hover"
                PropertyChanges {
                    target: background
                    color: Qt.darker(Style.colourCommandBarBackground)
                }
            }
        ]
    }
}
```

这与我们的`NavigationButton`组件非常相似。我们传入一个`Command`对象，从中我们将获取图标字符和描述以显示在**Text**元素中，以及在按钮被按下时发出的信号，只要命令可以执行。

我们使用了一种替代**Row/Column**布局的方法，并使用锚点来定位我们的图标和描述。我们将图标居中放置在父`Rectangle`中，然后应用垂直偏移将其向上移动，以便为描述留出空间。我们将描述的顶部锚定到图标的底部。

我们不是在按钮被按下时传播信号，而是首先验证命令是否可以执行，然后发出`Command`对象的`executed()`信号。我们还使用这个标志有选择地为我们的文本元素着色，如果命令被禁用，我们使用较浅的灰色字体。

我们使用`MouseArea`实现了一些更多的悬停功能，但我们不是暴露一个属性来传递悬停颜色，而是使用内置的`Qt.darker()`方法将默认颜色变暗几个色调。如果命令可以执行，我们也只在`MouseArea`的`onEntered()`槽中应用状态更改。

`CommandBar.qml`：

```cpp
import QtQuick 2.9
import assets 1.0

Item {
    property alias commandList: commandRepeater.model

    anchors {
        left: parent.left
        bottom: parent.bottom
        right: parent.right
    }
    height: Style.heightCommandBar

    Rectangle {
        anchors.fill: parent
        color: Style.colourCommandBarBackground

        Row {
            anchors {
                top: parent.top
                bottom: parent.bottom
                right: parent.right
            }

            Repeater {
                id: commandRepeater
                delegate: CommandButton {
                    command: modelData
                }
            }
        }
    }
}
```

这基本上与`NavigationBar`相同，但是使用动态命令列表而不是硬编码的 QML 按钮。我们引入了另一个新组件——`Repeater`。通过`model`属性提供的对象列表，`Repeater`将为列表中的每个项目实例化在`delegate`属性中定义的 QML 组件。列表中的对象可通过内置的`modelData`变量获得。使用这种机制，我们可以为给定列表中的每个命令自动生成一个`CommandButton`元素。我们使用另一个属性别名，以便调用者可以设置命令列表。

让我们在`CreateClientView`中使用它。首先，`import components 1.0`，然后在根`Item`内以及`Rectangle`之后添加以下内容：

```cpp
CommandBar {
    commandList: masterController.ui_commandController.ui_createClientViewContextCommands
}
```

我们通过属性层次结构深入到创建客户端视图的命令列表，并将该列表传递给负责处理其余部分的命令栏。如果`CommandBar`有红色波浪线，不要担心，Qt Creator 只是需要跟上我们的快速步伐。

运行应用程序并导航到创建客户端视图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/093cca1f-f222-4039-a734-70488a159adc.png)

单击按钮，您将看到消息输出到控制台。添加新命令就像将新的`Command`对象附加到`CommandController`内的 QList 一样简单——不需要 UI 更改！命令栏将自动为列表中找到的每个命令创建一个新按钮。还要注意，此命令栏仅出现在`CreateClientView`上，因此它是上下文敏感的。我们可以通过简单地向`CommandController`添加额外的列表和属性来轻松地将命令栏添加到其他视图中，就像我们稍后将要做的那样。

# 总结

在本章中，我们对导航栏进行了急需的改进。我们添加了我们的前几个组件，并利用了我们的新自定义样式对象，Font Awesome 为我们提供了一些可爱的可伸缩图形。我们还引入了命令，并且已经准备好能够向我们的视图添加上下文敏感的命令按钮。

在第五章 *数据*中，我们将深入研究业务逻辑层，并完善我们的第一个数据模型。


# 第五章：数据

在本章中，我们将实现处理任何业务应用程序中最关键部分的类——数据。我们将引入自我感知的数据实体，它们可以自动序列化到**JavaScript 对象表示**（**JSON**）中，这是一种在 Web 通信中经常使用的流行序列化格式。我们将为应用程序创建核心模型，并通过自定义控件将它们连接到我们的 UI 以进行读取和写入。我们将涵盖以下主题：

+   JSON

+   数据装饰器

+   抽象数据实体

+   数据实体的集合

+   具体数据模型

+   UI 控件和数据绑定

# JSON

如果您以前从未接触过 JSON，让我们快速进行一次简短的课程。这是一种简单而轻量的表达对象层次结构及其属性的方式。在发送 HTTP 请求时，这是一个非常受欢迎的选择。它类似于 XML 的意图，但要简洁得多。

JSON 对象封装在大括号`{}`中，属性以 key: value 的格式表示。字符串用双引号`""`括起来。我们可以将单个客户对象表示如下：

```cpp
{
    "reference": "CLIENT0001",
    "name": "Dale Cooper"
}
```

请注意，空格和制表符等控制字符会被忽略——缩进的属性只是为了使事情更易读。

在通过网络传输 JSON 时，通常最好去除其中的多余字符（例如在 HTTP 请求中），以减少有效负载的大小；每个字节都很重要！

属性值可以是以下类型之一：`String`，`Number`，`JSON 对象`，`JSON 数组`，以及字面值`true`，`false`和`null`。

我们可以将供应地址和账单地址添加到我们的客户作为子 JSON 对象，为每个对象提供一个唯一的键。虽然键可以是任何格式，只要它们是唯一的，但通常使用驼峰命名法，例如`myAwesomeJsonKey`。我们可以用 null 表示一个空地址对象：

```cpp
{
    "reference": "CLIENT0001",
    "name": "Dale Cooper",
    "supplyAddress": {
         "number": 7,
        "name": "White Lodge",
        "street": "Lost Highway",
        "city": "Twin Peaks",
        "postcode": "WS119"
    },
    "billingAddress": null
}
```

对象的集合（数组）用方括号`[]`括起来，用逗号分隔。我们可以通过简单地留空方括号来表示没有预约：

```cpp
{
    "reference": "CLIENT0001",
    "name": "Dale Cooper",
    "supplyAddress": {
        "number": 7,
        "name": "White Lodge",
        "street": "Lost Highway",
        "city": "Twin Peaks",
        "postcode": "WS119"
    },
    "billingAddress": null,
    "contacts": [
        {
            "type": 1,
            "address": "+12345678"
        },
        {
            "type": 2,
            "address": "dale.cooper@fbi.com"
        }
    ],
    "appointments": []
}
```

# 对象层次结构

大多数现实世界的应用程序以分层或关系方式表示数据，将数据合理化为离散对象。通常有一个中心的“根”对象，它作为父对象包含了几个其他子对象，可以是单个对象或集合。每个离散对象都有自己的一组数据项，可以是任意数量的类型。我们要涵盖的关键原则如下所列：

+   一系列数据类型（`string`，`integer`，`datetime`）和枚举值

+   对象层次结构

+   多个相同类型的单个子实体

+   实体的集合

在平衡这些目标与简单性的基础上，我们将致力于实现以下数据图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/ffa84470-9d21-4f42-93b5-1691a7bdabe0.png)

每个模型的目的在下表中描述：

| **模型** | **描述** |
| --- | --- |
| **客户** | 这是我们对象层次结构的根，代表了我们公司与个人或团体的关系，例如客户或患者。 |
| **联系人** | 我们可以用来联系客户的地址集合。可能的联系方式包括电话、电子邮件和传真。每个客户可以有一个或多个联系人。 |
| **预约** | 与客户安排的预约集合，例如现场访问或咨询。每个客户可以有零个或多个预约。 |
| **供应地址** | 与客户关系密切的地址，例如我们公司供应能源的地点或患者的家庭地址。每个客户必须有一个供应地址。 |
| **账单地址** | 用于开具发票的可选地址，例如公司的总部。每个客户可以有零个或一个账单地址。 |

另一种完全有效的方法是将地址聚合到一个集合中，就像我们在联系人中所做的那样，但我想演示如何在多个属性中使用相同类型的对象（地址）。

高级设计就位后，我们现在可以编写我们的类。但是，在开始处理数据实体之前，让我们先看一下数据项。

# 数据装饰器

我们的客户端模型的`name`属性的一个简单实现是将其添加为`QString`；然而，这种方法有一些缺点。每当我们在 UI 中显示此属性时，我们可能希望在文本框旁边显示一个信息性标签，以便用户知道它是用来做什么的，比如说“姓名”或类似的内容。每当我们想要验证用户输入的姓名时，我们必须在代码中的其他地方进行管理。最后，如果我们想要将值序列化到 JSON 中或从 JSON 中反序列化，再次需要有一些其他组件来为我们完成。 

为了解决所有这些问题，我们将引入`DataDecorator`的概念，它将提升给定的基本数据类型，并为我们提供标签、验证功能和 JSON 序列化。我们的模型将维护一个`DataDecorators`集合，允许它们通过简单地遍历数据项并执行相关操作来验证和将自己序列化为 JSON。

在我们的`cm-lib`项目中，在一个新文件夹`cm-lib/source/data`中创建以下类：

| **类** | **目的** |
| --- | --- |
| `DataDecorator` | 我们数据项的基类 |
| `StringDecorator` | 用于字符串属性的派生类 |
| `IntDecorator` | 用于整数属性的派生类 |
| `DateTimeDecorator` | 用于日期/时间属性的派生类 |
| `EnumeratorDecorator` | 用于枚举属性的派生类 |

我们的`DataDecorator`基类将包含所有数据项共享的特性。

`data-decorator.h`：

```cpp
#ifndef DATADECORATOR_H
#define DATADECORATOR_H

#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QScopedPointer>

#include <cm-lib_global.h>

namespace cm {
namespace data {

class Entity;

class CMLIBSHARED_EXPORT DataDecorator : public QObject
{
    Q_OBJECT
    Q_PROPERTY( QString ui_label READ label CONSTANT )

public:
    DataDecorator(Entity* parent = nullptr, const QString& key = 
                  "SomeItemKey", const QString& label = "");
                                 virtual ~DataDecorator();

    const QString& key() const;
    const QString& label() const;
    Entity* parentEntity();

    virtual QJsonValue jsonValue() const = 0;
    virtual void update(const QJsonObject& jsonObject) = 0;

private:
    class Implementation;
    QScopedPointer<Implementation> implementation;
};

}}

#endif
```

我们从 QObject 继承，添加我们的`dllexport`宏，并像往常一样将整个内容放入命名空间中。此外，因为这是一个抽象基类，我们确保已实现了虚拟析构函数。

我们知道，因为我们从 QObject 继承，我们希望在构造函数中接收一个父指针。我们还知道所有数据项都将是**Entity**的子项（我们将很快编写并在此处进行前向声明），它本身将从 QObject 派生。我们可以利用这两个事实，将我们的`DataDecorator`直接作为 Entity 的子项。

我们用一对字符串构造装饰器。我们所有的数据装饰器必须有一个键，该键在序列化到 JSON 和从 JSON 中使用时将被使用，并且它们还将共享一个`label`属性，UI 可以用来在数据控件旁边显示描述性文本。我们将这些成员隐藏在私有实现中，并为它们实现一些访问器方法。

最后，我们开始实现 JSON 序列化，声明虚拟方法来表示值为`QJsonValue`，并从提供的`QJsonObject`更新值。由于基类中未知值，而是在派生类中实现，因此这两种方法都是纯虚拟函数。

`data-decorator.cpp`：

```cpp
#include "data-decorator.h"

namespace cm {
namespace data {

class DataDecorator::Implementation
{
public:
    Implementation(Entity* _parent, const QString& _key, const QString& 
                                                         _label)
        : parentEntity(_parent)
        , key(_key)
        , label(_label)
    {
    }
    Entity* parentEntity{nullptr};
    QString key;
    QString label;
};

DataDecorator::DataDecorator(Entity* parent, const QString& key, const QString& label)
    : QObject((QObject*)parent)
{
    implementation.reset(new Implementation(parent, key, label));
}

DataDecorator::~DataDecorator()
{
}

const QString& DataDecorator::key() const
{
    return implementation->key;
}

const QString& DataDecorator::label() const
{
    return implementation->label;
}

Entity* DataDecorator::parentEntity()
{
    return implementation->parentEntity;
}

}}
```

实现非常简单，基本上只是管理一些数据成员。

接下来，我们将实现用于处理字符串的派生装饰器类。

`string-decorator.h`：

```cpp
#ifndef STRINGDECORATOR_H
#define STRINGDECORATOR_H

#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QScopedPointer>
#include <QString>

#include <cm-lib_global.h>
#include <data/data-decorator.h>

namespace cm {
namespace data {

class CMLIBSHARED_EXPORT StringDecorator : public DataDecorator
{
    Q_OBJECT

    Q_PROPERTY( QString ui_value READ value WRITE setValue NOTIFY 
               valueChanged )
public:
    StringDecorator(Entity* parentEntity = nullptr, const QString& key = "SomeItemKey", const QString& label = "", const QString& value = "");
    ~StringDecorator();

    StringDecorator& setValue(const QString& value);
    const QString& value() const;

    QJsonValue jsonValue() const override;
    void update(const QJsonObject& jsonObject) override;

signals:
    void valueChanged();

private:
    class Implementation;
    QScopedPointer<Implementation> implementation;
};

}}

#endif
```

这里没有太多其他事情发生 - 我们只是添加了一个强类型的`QString`值属性来保存我们的值。我们还重写了虚拟的与 JSON 相关的方法。

从继承自 QObject 的类派生时，如果派生类实现了自己的信号或槽，您需要在派生类以及基类中添加`Q_OBJECT`宏。

`string-decorator.cpp`：

```cpp
#include "string-decorator.h"

#include <QVariant>

namespace cm {
namespace data {

class StringDecorator::Implementation
{
public:
    Implementation(StringDecorator* _stringDecorator, const QString& 
                                                      _value)
        : stringDecorator(_stringDecorator)
        , value(_value)
    {
    }

    StringDecorator* stringDecorator{nullptr};
    QString value;
};

StringDecorator::StringDecorator(Entity* parentEntity, const QString& key, const QString& label, const QString& value)
    : DataDecorator(parentEntity, key, label)
{
    implementation.reset(new Implementation(this, value));
}

StringDecorator::~StringDecorator()
{
}

const QString& StringDecorator::value() const
{
    return implementation->value;
}

StringDecorator& StringDecorator::setValue(const QString& value)
{
    if(value != implementation->value) {
        // ...Validation here if required...
        implementation->value = value;
        emit valueChanged();
    }
    return *this;
}

QJsonValue StringDecorator::jsonValue() const
{
    return QJsonValue::fromVariant(QVariant(implementation->value));
}

void StringDecorator::update(const QJsonObject& _jsonObject)
{
    if (_jsonObject.contains(key())) {
        setValue(_jsonObject.value(key()).toString());
    } else {
        setValue("");
    }
}
}}
```

这里没有什么特别复杂的。通过使用`READ`和`WRITE`属性语法，而不是更简单的`MEMBER`关键字，我们现在有了一种拦截 UI 设置值的方法，并且我们可以决定是否要将更改应用到成员变量。修改器可以像你需要的那样复杂，但我们现在所做的一切只是设置值并发出信号告诉 UI 它已经被更改。我们将操作包装在一个相等检查中，所以如果新值与旧值相同，我们就不会采取任何行动。

在这里，修改器返回对自身（*this）的引用，这很有帮助，因为它使方法链接成为可能，例如，`myName.setValue(“Nick”).setSomeNumber(1234).setSomeOtherProperty(true)`。然而，这对于属性绑定并不是必要的，所以如果你喜欢的话，可以使用更常见的`void`返回类型。

我们使用两步转换过程，将我们的`QString`值转换为`QVariant`，然后再将其转换为我们目标的`QJsonValue`类型。`QJsonValue`将被插入到父实体 JSON 对象中，使用`DataDecorator`基类的`key`。当我们编写**Entity**相关的类时，我们将更详细地介绍这一点。

另一种方法是简单地将各种数据项的值表示为`DataDecorator`基类中的`QVariant`成员，而不需要为`QString`、`int`等编写单独的类。这种方法的问题在于，最终你将不得不编写大量的恶心代码，比如“如果你有一个包含字符串的`QVariant`，那么运行这段代码，如果它包含一个`int`，那么运行这段代码...”。我更喜欢写额外的类来换取已知类型和更清晰、更简单的代码。当我们进行数据验证时，这将变得特别有帮助。验证字符串与验证数字完全不同，而验证日期又与二者不同。

`IntDecorator`和`DateTimeDecorator`与`StringDecorator`几乎相同，只是用`QString`值替换为 int 或`QDateTime`。然而，我们可以为`DateTimeDecorator`补充一些额外的属性来帮助我们。添加以下属性和每个属性对应的访问器方法：

```cpp
Q_PROPERTY( QString ui_iso8601String READ toIso8601String NOTIFY valueChanged )
Q_PROPERTY( QString ui_prettyDateString READ toPrettyDateString NOTIFY valueChanged )
Q_PROPERTY( QString ui_prettyTimeString READ toPrettyTimeString NOTIFY valueChanged )
Q_PROPERTY( QString ui_prettyString READ toPrettyString NOTIFY valueChanged )
```

这些属性的目的是使 UI 能够轻松地访问日期/时间值，作为预先格式化为几种不同样式的`QString`。让我们逐个运行每个访问器的实现。

Qt 内置支持 ISO8601 格式的日期，这是在系统之间传输日期时间值时非常常见的格式，例如在 HTTP 请求中。这是一种灵活的格式，支持几种不同的表示，但通常遵循格式 yyyy-MM-ddTHH:mm:ss.zt，其中 T 是一个字符串文字，z 是毫秒，t 是时区信息：

```cpp
QString DateTimeDecorator::toIso8601String() const
{
    if (implementation->value.isNull()) {
        return "";
    } else {
        return implementation->value.toString(Qt::ISODate);
    }
}
```

接下来，我们提供一种方法来以长的人类可读格式显示完整的日期时间，例如，Sat 22 Jul 2017 @ 12:07:45：

```cpp
QString DateTimeDecorator::toPrettyString() const
{
    if (implementation->value.isNull()) {
        return "Not set";
    } else {
        return implementation->value.toString( "ddd d MMM yyyy @ HH:mm:ss" );
    }
}
```

最后两种方法分别显示日期或时间组件，例如，22 Jul 2017 或 12:07 pm：

```cpp
QString DateTimeDecorator::toPrettyDateString() const
{
    if (implementation->value.isNull()) {
        return "Not set";
    } else {
        return implementation->value.toString( "d MMM yyyy" );
    }
}

QString DateTimeDecorator::toPrettyTimeString() const
{
    if (implementation->value.isNull()) {
        return "Not set";
    } else {
        return implementation->value.toString( "hh:mm ap" );
    }
}
```

我们的最终类型，`EnumeratorDecorator`，与`IntDecorator`基本相同，但它还接受一个映射器。这个容器帮助我们将存储的整数值映射为字符串表示。如果我们考虑要实现的`Contact.type`枚举器，枚举值将是 0、1、2 等；然而，当涉及到 UI 时，这个数字对用户来说没有任何意义。我们真的需要呈现`Email`、`Telephone`或其他字符串表示，而映射允许我们做到这一点。

`enumerator-decorator.h`：

```cpp
#ifndef ENUMERATORDECORATOR_H
#define ENUMERATORDECORATOR_H

#include <map>

#include <QJsonObject>
#include <QJsonValue>
#include <QObject>
#include <QScopedPointer>

#include <cm-lib_global.h>
#include <data/data-decorator.h>

namespace cm {
namespace data {

class CMLIBSHARED_EXPORT EnumeratorDecorator : public DataDecorator
{
    Q_OBJECT
    Q_PROPERTY( int ui_value READ value WRITE setValue NOTIFY 
                                              valueChanged )
    Q_PROPERTY( QString ui_valueDescription READ valueDescription 
                                             NOTIFY valueChanged )

public:
    EnumeratorDecorator(Entity* parentEntity = nullptr, const QString& 
    key = "SomeItemKey", const QString& label = "", int value = 0,  
    const std::map<int, QString>& descriptionMapper = std::map<int, 
     QString>());
    ~EnumeratorDecorator();

    EnumeratorDecorator& setValue(int value);
    int value() const;
    QString valueDescription() const;

    QJsonValue jsonValue() const override;
    void update(const QJsonObject& jsonObject) override;

signals:
    void valueChanged();

private:
    class Implementation;
    QScopedPointer<Implementation> implementation;
};

}}

#endif
```

我们将映射存储为私有实现类中的另一个成员变量，然后使用它来提供枚举值的字符串表示：

```cpp
QString EnumeratorDecorator::valueDescription() const
{
    if (implementation->descriptionMapper.find(implementation->value) 
                       != implementation->descriptionMapper.end()) {
        return implementation->descriptionMapper.at(implementation-
                                                    >value);
    } else {
        return {};
    }
}
```

现在我们已经介绍了我们实体所需的数据类型，让我们继续讨论实体本身。

# 实体

由于我们希望在我们的数据模型之间共享许多功能，我们将实现一个**Entity**基类。我们需要能够表示父/子关系，以便客户可以拥有供应和账单地址。我们还需要支持实体的集合，用于我们的联系人和约会。最后，每个实体层次结构必须能够将自身序列化为 JSON 对象，并从 JSON 对象中反序列化。

在`cm-lib/source/data`中创建一个名为 Entity 的新类。

`entity.h`：

```cpp
#ifndef ENTITY_H
#define ENTITY_H

#include <map>

#include <QObject>
#include <QScopedPointer>

#include <cm-lib_global.h>
#include <data/data-decorator.h>

namespace cm {
namespace data {

class CMLIBSHARED_EXPORT Entity : public QObject
{
    Q_OBJECT

public:
    Entity(QObject* parent = nullptr, const QString& key = 
                                                  "SomeEntityKey");
    Entity(QObject* parent, const QString& key, const QJsonObject& 
     jsonObject);
    virtual ~Entity();

public:
    const QString& key() const;
    void update(const QJsonObject& jsonObject);
    QJsonObject toJson() const;

signals:
    void childEntitiesChanged();
    void dataDecoratorsChanged();

protected:
    Entity* addChild(Entity* entity, const QString& key);
    DataDecorator* addDataItem(DataDecorator* dataDecorator);

protected:
    class Implementation;
    QScopedPointer<Implementation> implementation;
};

}}

#endif
```

`entity.cpp`：

```cpp
#include "entity.h"

namespace cm {
namespace data {

class Entity::Implementation
{
public:
    Implementation(Entity* _entity, const QString& _key)
        : entity(_entity)
        , key(_key)
    {
    }
    Entity* entity{nullptr};
    QString key;
    std::map<QString, Entity*> childEntities;
    std::map<QString, DataDecorator*> dataDecorators;
};

Entity::Entity(QObject* parent, const QString& key)
    : QObject(parent)
{
    implementation.reset(new Implementation(this, key));
}

Entity::Entity(QObject* parent, const QString& key, const QJsonObject& 
               jsonObject) : Entity(parent, key)
{
    update(jsonObject);
}

Entity::~Entity()
{
}

const QString& Entity::key() const
{
    return implementation->key;
}

Entity* Entity::addChild(Entity* entity, const QString& key)
{
    if(implementation->childEntities.find(key) == 
        std::end(implementation->childEntities)) {
        implementation->childEntities[key] = entity;
        emit childEntitiesChanged();
    }
    return entity;
}

DataDecorator* Entity::addDataItem(DataDecorator* dataDecorator)
{
    if(implementation->dataDecorators.find(dataDecorator->key()) == 
       std::end(implementation->dataDecorators)) {
        implementation->dataDecorators[dataDecorator->key()] = 
        dataDecorator;
        emit dataDecoratorsChanged();
    }
    return dataDecorator;
}

void Entity::update(const QJsonObject& jsonObject)
{
    // Update data decorators
    for (std::pair<QString, DataDecorator*> dataDecoratorPair : 
         implementation->dataDecorators) {
        dataDecoratorPair.second->update(jsonObject);
    }
    // Update child entities
    for (std::pair<QString, Entity*> childEntityPair : implementation-
    >childEntities) {childEntityPair.second>update(jsonObject.value(childEntityPair.first).toObject());
    }
}

QJsonObject Entity::toJson() const
{
    QJsonObject returnValue;
    // Add data decorators
    for (std::pair<QString, DataDecorator*> dataDecoratorPair : 
                         implementation->dataDecorators) {
        returnValue.insert( dataDecoratorPair.first, 
        dataDecoratorPair.second->jsonValue() );
    }
    // Add child entities
    for (std::pair<QString, Entity*> childEntityPair : implementation->childEntities) {
        returnValue.insert( childEntityPair.first, childEntityPair.second->toJson() );
    }
    return returnValue;
}

}}
```

与我们的`DataDecorator`基类非常相似，我们为所有实体分配一个唯一的键，这将用于 JSON 序列化。我们还添加了一个重载的构造函数，我们可以通过它传递一个`QJsonObject`，以便我们可以从 JSON 实例化一个实体。另外，我们还声明了一对方法来将现有实例序列化为 JSON 并从 JSON 中反序列化。

我们的实体将维护一些集合——表示模型属性的数据装饰器的地图，以及表示单个子项的实体的地图。我们将每个项的键映射到实例。

我们公开了一些受保护的方法，派生类将使用这些方法来添加其数据项和子项；例如，我们的客户模型将添加一个名称数据项以及`supplyAddress`和`billingAddress`子项。为了补充这些方法，我们还添加了信号，告诉任何感兴趣的观察者集合已经发生了变化。

在这两种情况下，我们在添加之前检查地图上是否已经存在该键。然后我们返回提供的指针，以便消费者可以将其用于进一步操作。当我们开始实现数据模型时，您将看到这一点的价值。

我们使用填充的地图来进行 JSON 序列化方法。我们已经在我们的`DataDecorator`基类上声明了一个`update()`方法，因此我们只需迭代所有数据项，并依次将 JSON 对象传递给每个数据项。每个派生的装饰器类都有自己的实现来处理解析。类似地，我们对每个子实体递归调用`Entity::update()`。

将序列化为 JSON 对象遵循相同的模式。每个数据项都可以将其值转换为`QJsonValue`对象，因此我们依次获取每个值，并将其附加到根 JSON 对象中，使用每个项的键。我们对每个子项递归调用`Entity::toJson()`，这样就可以级联到层次结构树下。

在我们完成**Entity**之前，我们需要声明一组类来表示实体集合。

# 实体集合

要实现实体集合，我们需要利用一些更高级的 C++技术，并且我们将暂时中断我们迄今为止的惯例，实现在单个头文件中的多个类。

在`cm-lib/source/data`中创建`entity-collection.h`，并在其中像平常一样添加我们的命名空间并前向声明 Entity：

```cpp
#ifndef ENTITYCOLLECTION_H
#define ENTITYCOLLECTION_H

namespace cm {
namespace data {
    class Entity;
}}

#endif
```

接下来，我们将依次讨论必要的类，每个类都必须按顺序添加到命名空间中。

我们首先定义根类，它除了继承自`QObject`并给我们访问它带来的所有好处外，什么也不做，比如对象所有权和信号。这是必需的，因为直接从`QObject`派生的类不能被模板化：

```cpp
class CMLIBSHARED_EXPORT EntityCollectionObject : public QObject
{
    Q_OBJECT

public:
    EntityCollectionObject(QObject* _parent = nullptr) : QObject(_parent) {}
    virtual ~EntityCollectionObject() {}

signals:
    void collectionChanged();
};
```

你需要添加`QObject`和我们的 DLL 导出宏的包含。接下来，我们需要一个类型不可知的接口，用于与我们的实体一起使用，就像我们已经实现的`DataDecorator`和实体映射一样。然而，在这里情况会有些复杂，因为我们不会为每个集合派生一个新类，所以我们需要一种获取类型化数据的方法。我们有两个要求。首先，UI 需要一个派生类型的`QList`（例如**Client**），这样它就可以访问特定于客户的所有属性并显示所有数据。其次，我们的**Entity**类需要一个基本类型的向量（**Entity***），这样它就可以迭代它的集合而不用关心它正在处理的确切类型。我们实现这一点的方法是声明两个模板方法，但推迟到以后再定义它们。`derivedEntities()`将在消费者想要一个派生类型的集合时使用，而`baseEntities()`将在消费者只想要访问基本接口时使用。

```cpp
class EntityCollectionBase : public EntityCollectionObject
{
public:
    EntityCollectionBase(QObject* parent = nullptr, const QString& key 
                                         = "SomeCollectionKey")
        : EntityCollectionObject(parent)
        , key(key)
    {}

    virtual ~EntityCollectionBase()
    {}

    QString getKey() const
    {
        return key;
    }

    virtual void clear() = 0;
    virtual void update(const QJsonArray& json) = 0;
    virtual std::vector<Entity*> baseEntities() = 0;

    template <class T>
    QList<T*>& derivedEntities();

    template <class T>
    T* addEntity(T* entity);

private:
    QString key;
};
```

接下来，我们声明一个完整的模板类，其中我们存储我们的派生类型的集合并实现我们所有的方法，除了我们刚刚讨论的两个模板方法：

```cpp
template <typename T>
class EntityCollection : public EntityCollectionBase
{
public:
    EntityCollection(QObject* parent = nullptr, const QString& key = 
             "SomeCollectionKey")
        : EntityCollectionBase(parent, key)
    {}

    ~EntityCollection()
    {}

    void clear() override
    {
        for(auto entity : collection) {
            entity->deleteLater();
        }
        collection.clear();
    }

    void update(const QJsonArray& jsonArray) override
    {
        clear();
        for(const QJsonValue& jsonValue : jsonArray) {
            addEntity(new T(this, jsonValue.toObject()));
        }
    }

    std::vector<Entity*> baseEntities() override
    {
        std::vector<Entity*> returnValue;
        for(T* entity : collection) {
            returnValue.push_back(entity);
        }
        return returnValue;
    }

    QList<T*>& derivedEntities()
    {
        return collection;
    }

    T* addEntity(T* entity)
    {
        if(!collection.contains(entity)) {
            collection.append(entity);
            EntityCollectionObject::collectionChanged();
        }
        return entity;
    }

private:
    QList<T*> collection;       
};
```

你需要`#include <QJsonValue>`和`<QJsonArray>`来获取这些类。

`clear()`方法只是清空集合并整理内存；`update()`在概念上与我们在 Entity 中实现的 JSON 方法相同，只是我们处理的是一组实体，所以我们使用 JSON 数组而不是对象。`addEntity()`将派生类的实例添加到集合中，`derivedEntities()`返回集合；`baseEntities()`做了更多的工作，根据请求创建一个新的向量，并用集合中的所有项目填充它。它只是隐式地转换指针，所以我们不用担心昂贵的对象实例化。

最后，我们为我们的魔术模板方法提供实现：

```cpp
template <class T>
QList<T*>& EntityCollectionBase::derivedEntities()
{
    return dynamic_cast<const EntityCollection<T>&>(*this).derivedEntities();
}

template <class T>
T* EntityCollectionBase::addEntity(T* entity)
{
    return dynamic_cast<const EntityCollection<T>&>(*this).addEntity(entity);
}
```

通过推迟实现这些方法，我们现在已经完全声明了我们的模板化`EntityCollection`类。现在我们可以将任何对模板方法的调用“路由”到模板类中的实现。这是一种让你头脑转弯的棘手技术，但当我们开始在我们的现实世界模型中实现这些集合时，它将有望更加合理。

现在我们的实体集合已经准备就绪，我们可以返回到我们的 Entity 类并将它们加入其中。

在头文件中，`#include <data/entity-collection.h>`，添加信号：

```cpp
void childCollectionsChanged(const QString& collectionKey);
```

还有，添加受保护的方法：

```cpp
EntityCollectionBase* addChildCollection(EntityCollectionBase* entityCollection);
```

在实现文件中，添加私有成员：

```cpp
std::map<QString, EntityCollectionBase*> childCollections;
```

然后，添加这个方法：

```cpp
EntityCollectionBase* Entity::addChildCollection(EntityCollectionBase* entityCollection)
{
    if(implementation->childCollections.find(entityCollection- 
     >getKey()) == std::end(implementation->childCollections)) {
        implementation->childCollections[entityCollection->getKey()] =  
                                        entityCollection;
        emit childCollectionsChanged(entityCollection->getKey());
    }
    return entityCollection;
}
```

这与其他映射的工作方式完全相同，将键与基类的指针关联起来。

接下来，将集合添加到`update()`方法中：

```cpp
void Entity::update(const QJsonObject& jsonObject)
{
    // Update data decorators
    for (std::pair<QString, DataDecorator*> dataDecoratorPair :   
         implementation->dataDecorators) {
        dataDecoratorPair.second->update(jsonObject);
    }

    // Update child entities
    for (std::pair<QString, Entity*> childEntityPair : implementation- 
       >childEntities) { childEntityPair.second- 
       >update(jsonObject.value(childEntityPair.first).toObject());
    }

    // Update child collections
    for (std::pair<QString, EntityCollectionBase*> childCollectionPair 
         : implementation->childCollections) {
            childCollectionPair.second-
        >update(jsonObject.value(childCollectionPair.first).toArray());
    }
}
```

最后，将集合添加到`toJson()`方法中：

```cpp
QJsonObject Entity::toJson() const
{
    QJsonObject returnValue;

    // Add data decorators
    for (std::pair<QString, DataDecorator*> dataDecoratorPair : 
        implementation->dataDecorators) {
        returnValue.insert( dataDecoratorPair.first, 
        dataDecoratorPair.second->jsonValue() );
    }

    // Add child entities
    for (std::pair<QString, Entity*> childEntityPair : implementation-
        >childEntities) {
        returnValue.insert( childEntityPair.first, 
       childEntityPair.second->toJson() );
    }

    // Add child collections
    for (std::pair<QString, EntityCollectionBase*> childCollectionPair 
        : implementation->childCollections) {
        QJsonArray entityArray;
            for (Entity* entity : childCollectionPair.second-
           >baseEntities()) {
            entityArray.append( entity->toJson() );
        }
        returnValue.insert( childCollectionPair.first, entityArray );
    }

    return returnValue;
}
```

你需要`#include <QJsonArray>`来获取最后一段代码。

我们使用`baseEntities()`方法来给我们一个`Entity*`的集合。然后我们将每个实体的 JSON 对象附加到一个 JSON 数组中，当完成时，将该数组添加到我们的根 JSON 对象中，带有集合的键。

过去几节内容非常长且复杂，可能看起来需要大量工作才能实现一些数据模型。然而，这是你只需要编写一次的所有代码，并且它可以为你提供大量的功能，让你在创建每个实体时都能免费使用，所以从长远来看是值得投资的。我们将继续看如何在我们的数据模型中实现这些类。

# 数据模型

现在我们已经有了基础设施，可以定义数据对象（实体和实体集合）和各种类型的属性（数据装饰器），我们可以继续构建我们在本章前面所列出的对象层次结构。我们已经有了一个由 Qt Creator 创建的默认**Client**类，所以在`cm-lib/source/models`中补充以下新类：

| **类** | **目的** |
| --- | --- |
| `Address` | 代表供应或结算地址 |
| `Appointment` | 代表与客户的约会 |
| `Contact` | 代表与客户联系的方法 |

我们将从最简单的模型开始——地址。

`address.h`：

```cpp
#ifndef ADDRESS_H
#define ADDRESS_H

#include <QObject>

#include <cm-lib_global.h>
#include <data/string-decorator.h>
#include <data/entity.h>

namespace cm {
namespace models {

class CMLIBSHARED_EXPORT Address : public data::Entity
{
    Q_OBJECT
    Q_PROPERTY(cm::data::StringDecorator* ui_building MEMBER building 
                                                      CONSTANT)
    Q_PROPERTY(cm::data::StringDecorator* ui_street MEMBER street  
                                                    CONSTANT)
    Q_PROPERTY(cm::data::StringDecorator* ui_city MEMBER city CONSTANT)
    Q_PROPERTY(cm::data::StringDecorator* ui_postcode MEMBER postcode 
                                                      CONSTANT)
    Q_PROPERTY(QString ui_fullAddress READ fullAddress CONSTANT)

public:
    explicit Address(QObject* parent = nullptr);
    Address(QObject* parent, const QJsonObject& json);

    data::StringDecorator* building{nullptr};
    data::StringDecorator* street{nullptr};
    data::StringDecorator* city{nullptr};
    data::StringDecorator* postcode{nullptr};

    QString fullAddress() const;
};

}}

#endif
```

我们定义了我们在本章开头设计的属性，但是我们使用我们的新`StringDecorators`，而不是使用常规的`QString`对象。为了保护数据的完整性，我们应该真正使用`READ`关键字，并通过访问器方法返回`StringDecorator* const`，但为了简单起见，我们将使用`MEMBER`。我们还提供了一个重载的构造函数，我们可以用它来从`QJsonObject`构造地址。最后，我们添加了一个辅助的`fullAddress()`方法和属性，将地址元素连接成一个单一的字符串，以在 UI 中使用。

`address.cpp`：

```cpp
#include "address.h"

using namespace cm::data;

namespace cm {
namespace models {

Address::Address(QObject* parent)
        : Entity(parent, "address")
{
    building = static_cast<StringDecorator*>(addDataItem(new StringDecorator(this, "building", "Building")));
    street = static_cast<StringDecorator*>(addDataItem(new StringDecorator(this, "street", "Street")));
    city = static_cast<StringDecorator*>(addDataItem(new StringDecorator(this, "city", "City")));
    postcode = static_cast<StringDecorator*>(addDataItem(new StringDecorator(this, "postcode", "Post Code")));
}

Address::Address(QObject* parent, const QJsonObject& json)
        : Address(parent)
{
    update(json);
}

QString Address::fullAddress() const
{
    return building->value() + " " + street->value() + "\n" + city->value() + "\n" + postcode->value();
}

}}
```

这是我们所有辛苦工作开始汇聚的地方。我们需要对我们的每个属性做两件事。首先，我们需要一个指向派生类型（`StringDecorator`）的指针，这样我们就可以向 UI 呈现并编辑值。其次，我们需要让基本的 Entity 类知道基本类型（`DataDecorator`），以便它可以迭代数据项并为我们执行 JSON 序列化工作。我们可以使用`addDataItem()`方法在一行语句中实现这两个目标：

```cpp
building = static_cast<StringDecorator*>(addDataItem(new StringDecorator(this, "building", "Building")));
```

分解一下，我们使用`building`键和`Building` UI 标签创建一个新的`StringDecorator*`。这立即传递给`addDataItem()`，它将其添加到**Entity**中的`dataDecorators`集合中，并将数据项作为`DataDecorator*`返回。然后我们可以将其强制转换回`StringDecorator*`，然后将其存储在`building`成员变量中。

这里的另一个实现部分是获取 JSON 对象，通过调用默认构造函数正常构造地址，然后使用`update()`方法更新模型。

`Appointment`和`Contact`模型遵循相同的模式，只是具有不同的属性和每种数据类型的适当变体的`DataDecorator`。`Contact`的变化更显著的是在其对`contactType`属性使用`EnumeratorDecorator`。为了支持这一点，我们首先在头文件中定义一个枚举器，其中包含我们想要的所有可能值：

```cpp
enum eContactType {
    Unknown = 0,
    Telephone,
    Email,
    Fax
};

```

请注意，我们将`Unknown`的默认值表示为`0`。这很重要，因为它允许我们容纳初始未设置的值。接下来，我们定义一个映射器容器，允许我们将枚举类型中的每个类型映射到一个描述性字符串：

```cpp
std::map<int, QString> Contact::contactTypeMapper = std::map<int, QString> {
    { Contact::eContactType::Unknown, "" }
    , { Contact::eContactType::Telephone, "Telephone" }
    , { Contact::eContactType::Email, "Email" }
    , { Contact::eContactType::Fax, "Fax" }
};
```

在创建新的`EnumeratorDecorator`时，我们提供默认值（对于`eContactType::Unknown`为 0）以及映射器：

```cpp
contactType = static_cast<EnumeratorDecorator*>(addDataItem(new EnumeratorDecorator(this, "contactType", "Contact Type", 0, contactTypeMapper)));
```

我们的客户模型稍微复杂一些，因为它不仅有数据项，还有子实体和集合。但是，我们创建和公开这些内容的方式与我们已经看到的非常相似。

`client.h`：

```cpp
#ifndef CLIENT_H
#define CLIENT_H

#include <QObject>
#include <QtQml/QQmlListProperty>

#include <cm-lib_global.h>
#include <data/string-decorator.h>
#include <data/entity.h>
#include <data/entity-collection.h>
#include <models/address.h>
#include <models/appointment.h>
#include <models/contact.h>

namespace cm {
namespace models {

class CMLIBSHARED_EXPORT Client : public data::Entity
{
    Q_OBJECT
    Q_PROPERTY( cm::data::StringDecorator* ui_reference MEMBER 
                                           reference CONSTANT )
    Q_PROPERTY( cm::data::StringDecorator* ui_name MEMBER name CONSTANT )
    Q_PROPERTY( cm::models::Address* ui_supplyAddress MEMBER 
                                     supplyAddress CONSTANT )
    Q_PROPERTY( cm::models::Address* ui_billingAddress MEMBER 
                                     billingAddress CONSTANT )
    Q_PROPERTY( QQmlListProperty<Appointment> ui_appointments READ 
                        ui_appointments NOTIFY appointmentsChanged )
    Q_PROPERTY( QQmlListProperty<Contact> ui_contacts READ ui_contacts 
                                          NOTIFY contactsChanged )

public:    
    explicit Client(QObject* parent = nullptr);
    Client(QObject* parent, const QJsonObject& json);

    data::StringDecorator* reference{nullptr};
    data::StringDecorator* name{nullptr};
    Address* supplyAddress{nullptr};
    Address* billingAddress{nullptr};
    data::EntityCollection<Appointment>* appointments{nullptr};
    data::EntityCollection<Contact>* contacts{nullptr};

    QQmlListProperty<cm::models::Appointment> ui_appointments();
    QQmlListProperty<cm::models::Contact> ui_contacts();

signals:
    void appointmentsChanged();
    void contactsChanged();
};

}}

#endif
```

我们将子实体公开为指向派生类型的指针，将集合公开为指向模板化的`EntityCollection`的指针。

`client.cpp`：

```cpp
#include "client.h"

using namespace cm::data;

namespace cm {
namespace models {

Client::Client(QObject* parent)
    : Entity(parent, "client")
{
    reference = static_cast<StringDecorator*>(addDataItem(new 
                StringDecorator(this, "reference", "Client Ref")));
    name = static_cast<StringDecorator*>(addDataItem(new 
                StringDecorator(this, "name", "Name")));
    supplyAddress = static_cast<Address*>(addChild(new Address(this), 
                                          "supplyAddress"));
    billingAddress = static_cast<Address*>(addChild(new Address(this), 
                                          "billingAddress"));
    appointments = static_cast<EntityCollection<Appointment>*>
    (addChildCollection(new EntityCollection<Appointment>(this, 
                                            "appointments")));
    contacts = static_cast<EntityCollection<Contact>*>(addChildCollection(new EntityCollection<Contact>(this, "contacts")));
}

Client::Client(QObject* parent, const QJsonObject& json)
    : Client(parent)
{
    update(json);
}

QQmlListProperty<Appointment> Client::ui_appointments()
{
    return QQmlListProperty<Appointment>(this, appointments->derivedEntities());
}

QQmlListProperty<Contact> Client::ui_contacts()
{
    return QQmlListProperty<Contact>(this, contacts->derivedEntities());
}

}}
```

添加子实体遵循与数据项相同的模式，但使用`addChild()`方法。请注意，我们添加了多个相同地址类型的子实体，但确保它们具有不同的`key`值，以避免重复和无效的 JSON。实体集合使用`addChildCollection()`添加，除了使用模板化之外，它们遵循相同的方法。

虽然创建实体和数据项需要大量工作，但创建模型实际上非常简单，现在它们都具有我们原本没有的功能。

在 UI 中使用我们新的模型之前，我们需要在`cm-ui`的`main.cpp`中注册类型，包括表示数据项的数据装饰器。记得先添加相关的`#include`语句：

```cpp
qmlRegisterType<cm::data::DateTimeDecorator>("CM", 1, 0, "DateTimeDecorator");
qmlRegisterType<cm::data::EnumeratorDecorator>("CM", 1, 0, "EnumeratorDecorator");
qmlRegisterType<cm::data::IntDecorator>("CM", 1, 0, "IntDecorator");
qmlRegisterType<cm::data::StringDecorator>("CM", 1, 0, "StringDecorator");

qmlRegisterType<cm::models::Address>("CM", 1, 0, "Address");
qmlRegisterType<cm::models::Appointment>("CM", 1, 0, "Appointment");
qmlRegisterType<cm::models::Client>("CM", 1, 0, "Client");
qmlRegisterType<cm::models::Contact>("CM", 1, 0, "Contact");
```

完成后，我们将在`MasterController`中创建一个客户端的实例，用于填充新客户端的数据。这完全遵循了我们用于添加其他控制器的相同模式。

首先，在`MasterController`的私有实现中添加成员变量：

```cpp
Client* newClient{nullptr};
```

然后，在`Implementation`构造函数中初始化它：

```cpp
newClient = new Client(masterController);
```

第三，添加访问器方法：

```cpp
Client* MasterController::newClient()
{
    return implementation->newClient;
}
```

最后，添加`Q_PROPERTY`：

```cpp
Q_PROPERTY( cm::models::Client* ui_newClient READ newClient CONSTANT )
```

现在，我们有一个空的客户端实例可供 UI 使用，特别是`CreateClientView`，我们将在下一步中编辑它。首先添加一个新客户端实例的快捷属性：

```cpp
property Client newClient: masterController.ui_newClient
```

请记住，所有属性都应在根 Item 级别定义，并且您需要`import CM 1.0`才能访问已注册的类型。这只是让我们能够使用`newClient`作为访问实例的简写，而不必每次都输入`masterController.ui_newClient`。

到目前为止，一切都已经准备就绪，您应该能够运行应用程序并导航到新的客户端视图，而没有任何问题。视图目前还没有使用新的客户端实例，但它已经准备好进行操作。现在，让我们看看如何与它进行交互。

# 自定义文本框

我们将从客户端的`name`数据项开始。当我们在 UI 中使用另一个`QString`属性时，我们使用基本文本组件显示它。这个组件是只读的，所以为了查看和编辑我们的属性，我们需要寻找其他东西。在基本的`QtQuick`模块中有几个选项：`TextInput`和`TextEdit`。`TextInput`用于单行可编辑的纯文本，而`TextEdit`处理多行文本块，并支持富文本。`TextInput`非常适合我们的**name**。

导入`QtQuick.Controls`模块可以使其他基于文本的组件如`Label`、`TextField`和`TextArea`可用。Label 继承并扩展 Text，`TextField`继承并扩展`TextInput`，`TextArea`继承并扩展`TextEdit`。在这个阶段，基本控件已经足够了，但请注意这些替代品的存在。如果您发现自己尝试使用基本控件做一些它似乎不支持的事情，那么导入`QtQuick.Controls`并查看它更强大的同类。它很可能具有您正在寻找的功能。

让我们在所学知识的基础上构建一个新的可重用组件。和往常一样，我们将首先准备我们需要的样式属性：

```cpp
readonly property real sizeScreenMargin: 20
```

```cpp
readonly property color colourDataControlsBackground: "#ffffff"
readonly property color colourDataControlsFont: "#131313" 
readonly property int pixelSizeDataControls: 18 
readonly property real widthDataControls: 400 
readonly property real heightDataControls: 40
```

接下来，在`cm/cm-ui/components`中创建`StringEditorSingleLine.qml`。这可能不是最美观的名称，但至少它是描述性的！

通常有助于在自定义 QML 视图和组件中使用前缀，以帮助区分它们与内置的 Qt 组件，并避免命名冲突。如果我们在这个项目中使用这种方法，我们可以将这个组件称为`CMTextBox`或者其他同样简短简单的名称。使用任何适合您的方法和约定，这不会产生功能上的差异。

编辑`components.qrc`和`qmldir`，就像我们之前做的那样，以便在我们的组件模块中使用新组件。

我们尝试实现这个组件的目标如下：

+   能够传递任何数据模型和视图中的`StringDecorator`属性并查看/编辑值

+   查看`StringDecorator`的`ui_label`属性中定义的控件的描述性标签

+   查看/编辑`StringDecorator`的`ui_value`属性在`TextBox`中

+   如果窗口足够宽，则标签和文本框将水平布局

+   如果窗口不够宽，则标签和文本框将垂直布局

考虑到这些目标，实现`StringEditorSingleLine`如下：

```cpp
import QtQuick 2.9
import CM 1.0
import assets 1.0

Item {
    property StringDecorator stringDecorator

    height: width > textLabel.width + textValue.width ? 
    Style.heightDataControls : Style.heightDataControls * 2

    Flow {
        anchors.fill: parent

        Rectangle {
            width: Style.widthDataControls
            height: Style.heightDataControls
            color: Style.colourBackground
            Text {
                id: textLabel
                anchors {
                    fill: parent
                    margins: Style.heightDataControls / 4
                }
                text: stringDecorator.ui_label
                color: Style.colourDataControlsFont
                font.pixelSize: Style.pixelSizeDataControls
                verticalAlignment: Qt.AlignVCenter
            }
        }

        Rectangle {
            id: background
            width: Style.widthDataControls
            height: Style.heightDataControls
            color: Style.colourDataControlsBackground
            border {
                width: 1
                color: Style.colourDataControlsFont
            }
            TextInput {
                id: textValue
                anchors {
                    fill: parent
                    margins: Style.heightDataControls / 4
                }
                text: stringDecorator.ui_value
                color: Style.colourDataControlsFont
                font.pixelSize: Style.pixelSizeDataControls
                verticalAlignment: Qt.AlignVCenter
            }
        }

        Binding {
            target: stringDecorator
            property: "ui_value"
            value: textValue.text
        }
    }
}
```

我们从公共`StringDecorator`属性开始（因为它在根 Item 元素中），我们可以从组件外部设置它。

我们引入了一种新的元素——Flow——来为我们布置标签和文本框。与始终沿着单个方向（如行或列）布置内容不同，Flow 项将将其子元素并排布置，直到可用空间用尽，然后像页面上的单词一样将它们包裹起来。我们通过将其锚定到根 Item 来告诉它有多少可用空间可以使用。

接下来是我们描述性标签在文本控件中和可编辑值在`TextInput`控件中。我们将两个控件嵌入明确大小的矩形中。这些矩形帮助我们对齐元素，并为我们提供绘制背景和边框的机会。

`Binding`组件在两个不同对象的属性之间建立了依赖关系；在我们的情况下，是名为`textValue`的`TextInput`控件和名为`stringDecorator`的`StringDecorator`实例。`target`属性定义了我们要更新的对象，`property`是我们要设置的`Q_PROPERTY`，`value`是我们要设置的值。这是一个关键元素，使我们实现了真正的双向绑定。没有这个，我们将能够从`StringDecorator`中查看值，但我们在 UI 中进行的任何更改都不会更新该值。

回到`CreateClientView`，用我们的新组件替换旧的文本元素，并传入`ui_name`属性：

```cpp
StringEditorSingleLine {
    stringDecorator: newClient.ui_name
}
```

现在构建并运行应用程序，导航到创建客户端视图，并尝试编辑名称：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-qt5/img/91a79322-c123-4af2-8e42-736e540130a3.png)

如果您切换到查找客户端视图，然后再切换回来，您会看到该值被保留，证明更新成功地设置在字符串装饰器中。

我们新绑定的视图目前还没有太多数据，但在接下来的章节中，我们将为这个视图添加更多内容，因此让我们添加一些最后的修饰来做好准备。

首先，我们只需要向视图添加另外三四个属性，我们将会用完空间，因为我们为窗口设置的默认大小非常小，所以在`MasterView`中将窗口大小调整到适合您显示器的舒适大小。我会给自己一些待遇，选择全高清的 1920 x 1080。

即使有更大的窗口可供使用，我们仍然需要准备可能溢出的情况，因此我们将将我们的内容添加到另一个名为`ScrollView`的新元素中。顾名思义，它的工作方式类似于流，并根据其可用的空间来管理其内容。如果内容超出可用空间，它将为用户呈现滚动条。它还是一个非常适合手指操作的控件，在触摸屏上，用户可以直接拖动内容，而不必费力地操作微小的滚动条。

尽管我们目前只有一个属性，但当我们添加更多属性时，我们需要对它们进行布局，因此我们将添加一列。

最后，控件粘附在视图的边界上，因此我们将在视图周围添加一点间隙和一些列间距。

修改后的视图应如下所示：

```cpp
import QtQuick 2.9
import QtQuick.Controls 2.2
import CM 1.0
import assets 1.0
import components 1.0

Item {
    property Client newClient: masterController.ui_newClient

    Rectangle {
        anchors.fill: parent
        color: Style.colourBackground
    }

    ScrollView {
        id: scrollView
        anchors {
            left: parent.left
            right: parent.right
            top: parent.top
            bottom: commandBar. top
            margins: Style.sizeScreenMargin
        }
        clip: true
        Column {
            spacing: Style.sizeScreenMargin
            width: scrollView.width
            StringEditorSingleLine {
                stringDecorator: newClient.ui_name
                anchors {
                    left: parent.left
                    right: parent.right
                }
            }
        }
    }

    CommandBar {
        id: commandBar
        commandList: masterController.ui_commandController.ui_createClientViewContextCommands
    }
}
```

构建并运行，您应该会看到漂亮整洁的屏幕边距。您还应该能够将窗口从宽变窄，并看到字符串编辑器自动调整其布局。

# 总结

这是一个相当庞大的章节，但我们已经涵盖了任何业务应用程序中可能最重要的元素，那就是数据。我们实现了一个能够将自身序列化到 JSON 并开始构建数据绑定控件的自我意识实体框架。我们已经设计并创建了我们的数据模型，现在正在进入回家的阶段。在第六章中，*单元测试*，我们将关注到迄今为止被忽视的单元测试项目，并检查我们的实体是否按预期行为。
