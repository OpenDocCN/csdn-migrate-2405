# Qt5 C++ GUI 编程秘籍（一）

> 原文：[`annas-archive.org/md5/9BC2D959B55E8629DCD159B600A4BD90`](https://annas-archive.org/md5/9BC2D959B55E8629DCD159B600A4BD90)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

计算机软件市场的持续增长导致了一个竞争激烈和具有挑战性的时代。你的软件不仅需要功能强大且易于使用，还必须对用户具有吸引力和专业性。为了在市场上获得竞争优势，产品的外观和感觉至关重要，并且应该在生产阶段早期予以关注。在本书中，我们将教你如何使用 Qt5 开发平台创建功能强大、吸引人且用户友好的软件。

# 本书涵盖了什么

第一章 *外观和感觉定制*，展示了如何使用 Qt Designer 和 Qt Quick Designer 设计程序的用户界面。

第二章 *状态和动画*，解释了如何通过使用状态机框架和动画框架来为用户界面小部件添加动画效果。

第三章 *QPainter 和 2D 图形*，介绍了如何使用 Qt 的内置类在屏幕上绘制矢量形状和位图图像。

第四章 *OpenGL 实现*，演示了如何通过在 Qt 项目中集成 OpenGL 来渲染程序中的 3D 图形。

第五章 *使用 Qt5 构建触摸屏应用程序*，解释了如何创建适用于触摸屏设备的程序。

第六章 *简化 XML 解析*，展示了如何处理 XML 格式的数据，并与 Google 地理编码 API 一起使用，以创建一个简单的地址查找器。

第七章 *转换库*，介绍了如何使用 Qt 的内置类以及第三方程序在不同变量类型、图像格式和视频格式之间进行转换。

第八章 *访问数据库*，解释了如何使用 Qt 将程序连接到 SQL 数据库。

第九章 *使用 Qt Web 引擎开发 Web 应用程序*，介绍了如何使用 Qt 提供的 Web 渲染引擎，并开发利用 Web 技术的程序。

# 本书需要什么

以下是本书的先决条件：

1.  Qt5（适用于所有章节）

1.  FFmpeg（用于第七章 *转换库*）

1.  XAMPP（用于第八章 *访问数据库*）

# 本书适合谁

本书旨在为那些想使用 Qt5 开发软件的人提供帮助。如果你想提高软件应用的视觉质量和内容呈现，这本书将最适合你。

# 部分

在本书中，你会经常看到几个标题（准备工作，如何做，它是如何工作的，还有更多，另请参阅）。

为了清晰地说明如何完成一个配方，我们使用以下这些部分：

## 准备工作

本节告诉你在配方中可以期待什么，并描述了为配方设置任何软件或任何预备设置所需的步骤。

## 如何做...

本节包含了遵循配方所需的步骤。

## 它是如何工作的...

本节通常包括对上一节内容的详细解释。

## 还有更多...

本节包含有关配方的附加信息，以使读者更加了解配方。

## 另请参阅

本节为配方提供了其他有用信息的链接。 

# 约定

在本书中，你会发现一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："在`mylabel.cpp`源文件中，定义一个名为`SetMyObject()`的函数来保存对象指针。"

代码块设置如下：

```cpp
QSpinBox::down-button
{
  image: url(:/images/spindown.png);
  subcontrol-origin: padding;
  subcontrol-position: right bottom;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
QSpinBox::down-button
{
 image: url(:/images/spindown.png);
  subcontrol-origin: padding;
  subcontrol-position: right bottom;
}
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中："转到**Library**窗口中的**Imports**标签，并向您的项目添加一个名为**QtQuick.Controls**的 Qt Quick 模块。"

### 注意

警告或重要提示会显示在这样的框中。

### 提示

提示和技巧会显示为这样。

# 第一章：外观和感觉定制

在本章中，我们将涵盖以下内容：

+   在 Qt Designer 中使用样式表

+   基本样式表定制

+   使用样式表创建登录界面

+   在样式表中使用资源

+   自定义属性和子控件

+   QML 中的样式

+   将 QML 对象指针暴露给 C++

# 介绍

Qt 允许我们通过大多数人熟悉的方法轻松设计程序的用户界面。Qt 不仅为我们提供了一个强大的用户界面工具包 Qt Designer，使我们能够在不写一行代码的情况下设计用户界面，而且还允许高级用户通过一种简单的脚本语言 Qt 样式表来自定义他们的用户界面组件。

# 在 Qt Designer 中使用样式表

在这个例子中，我们将学习如何通过使用样式表和资源来改变程序的外观和感觉，使其看起来更专业。Qt 允许你使用一种名为 Qt 样式表的样式表语言来装饰你的**图形用户界面**（**GUI**），这与网页设计师使用的**层叠样式表**（**CSS**）非常相似，用于装饰他们的网站。

## 如何做…

1.  我们需要做的第一件事是打开 Qt Creator 并创建一个新项目。如果这是你第一次使用 Qt Creator，你可以点击上面写着**New Project**和一个**+**号的大按钮，或者简单地转到**File** | **New File or New Project**。

1.  然后，在**项目**窗口下选择**Application**，并选择**Qt Widgets Application**。

1.  之后，点击底部的**Choose**按钮。然后会弹出一个窗口，要求你输入项目名称和位置。

1.  完成后，点击**Next**几次，然后点击**Finish**按钮创建项目。现在我们将坚持使用所有默认设置。项目创建完成后，你会看到窗口左侧有一个名为**Mode Selector**的面板，上面有很多大图标；我们稍后将在*How it works...*部分详细讨论这一点。

1.  然后，你还会看到所有源文件都列在位于**Mode Selector**面板旁边的**Side Bar**面板上。这是你可以选择要编辑的文件的地方，在这种情况下是`mainwindow.ui`，因为我们即将开始设计程序的 UI！

1.  双击 `mainwindow.ui`，你会看到一个完全不同的界面突然出现。Qt Creator 实际上帮助你从脚本编辑器切换到 UI 编辑器（Qt Designer），因为它检测到你要打开的文件具有`.ui`扩展名。

1.  你还会注意到**Mode Selector**面板上高亮显示的按钮已经从**Edit**按钮变成了**Design**按钮。你可以通过点击**Mode Selector**面板上半部分的按钮之一，切换回脚本编辑器或切换到其他工具。

1.  让我们回到 Qt Designer，看看`mainwindow.ui`文件。这基本上是我们程序的主窗口（如文件名所示），默认情况下是空的，没有任何小部件。你可以尝试通过点击**Mode Selector**面板底部的**Run**按钮（绿色箭头按钮）来编译和运行程序，一旦编译完成，你会看到一个空窗口弹出来：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_01.jpg)

1.  现在，让我们通过单击小部件框中的`Push Button`项目（在**按钮**类别下）并将其拖动到表单编辑器中的主窗口，向我们的程序 UI 添加一个按钮。然后，保持按钮选定状态，现在您将在窗口右侧的属性编辑器中看到此按钮的所有属性。向下滚动到中间左右某处，查找名为**styleSheet**的属性。这是您向小部件应用样式的地方，这些样式可能会根据您设置样式表的方式递归地继承到其子代或孙代。或者，您还可以右键单击表单编辑器中的任何小部件，并从弹出菜单中选择**更改样式表**。

1.  您可以单击**styleSheet**属性的输入字段，直接编写样式表代码，或单击输入字段旁边的**...**按钮，打开**编辑样式表**窗口，该窗口具有更大的空间，用于编写更长的样式表代码。在窗口顶部，您可以找到几个按钮，例如**添加资源**、**添加渐变**、**添加颜色**和**添加字体**，这些按钮可以帮助您启动编码，如果您记不住属性的名称。

让我们尝试使用**编辑样式表**窗口进行一些简单的样式设置。

1.  单击**添加颜色**并选择颜色。

1.  从颜色选择器窗口中选择一个随机颜色，比如纯红色。然后单击**确定**。

1.  现在，您将看到一行代码已添加到**编辑样式表**窗口上的文本字段中，例如：

`color: rgb(255, 0, 0);`

1.  单击**确定**按钮，现在您将看到按钮上的文本已更改为红色。

## 它是如何工作的...

在开始学习如何设计自己的 UI 之前，让我们花点时间熟悉 Qt Designer 的界面：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_02.jpg)

1.  **菜单栏：**菜单栏包含特定于应用程序的菜单，可轻松访问诸如创建新项目、保存文件、撤消、重做、复制、粘贴等基本功能。它还允许您访问随 Qt Creator 一起提供的开发工具，例如编译器、调试器、分析器等。

1.  **小部件框：**这是您可以找到 Qt Designer 提供的所有不同类型的小部件的地方。您可以通过单击小部件框中的一个小部件并将其拖动到表单编辑器中，向程序 UI 添加一个小部件。

1.  **模式选择器：**模式选择器是一个侧面面板，其中放置了用于轻松访问不同工具的快捷按钮。您可以通过单击模式选择器面板上的**编辑**或**设计**按钮快速在脚本编辑器和表单编辑器之间切换，这对于多任务处理非常有用。您还可以以相同的速度和方式轻松导航到调试器和分析器工具。

1.  **构建快捷键：**构建快捷键位于模式选择器面板的底部。您可以通过按快捷按钮轻松构建、运行和调试项目。

1.  **表单编辑器：**表单编辑器是您编辑程序 UI 的地方。您可以从小部件框中选择一个小部件，并将其拖动到表单编辑器中，从而向程序添加不同的小部件。

1.  **表单工具栏：**从这里，您可以快速选择要编辑的不同表单，单击位于小部件框上方的下拉框，并选择要在 Qt Designer 中打开的文件。在下拉框旁边是用于在表单编辑器的不同模式之间切换的按钮，还有用于更改 UI 布局的按钮。

1.  **对象检视器：**对象检视器列出了当前`.ui`文件中的所有小部件。所有小部件按照它们在层次结构中的父子关系进行排列。您可以从对象检视器中选择一个小部件，以在属性编辑器中显示其属性。

1.  **属性编辑器：**属性编辑器将显示您从对象检视器窗口或表单编辑器窗口中选择的小部件的所有属性。

1.  **操作编辑器和信号与槽编辑器：** 此窗口包含两个编辑器，**操作编辑器**和**信号与槽编辑器**，可以从窗口下方的选项卡中访问。操作编辑器是您创建可以添加到程序 UI 的菜单栏或工具栏中的操作的地方。

1.  **输出窗格：** 输出窗格由几个不同的窗口组成，显示与脚本编译和调试相关的信息和输出消息。您可以通过按带有数字的按钮（例如**1**-**Issues**，**2**-**Search Results**，**3**-**Application Output**等）来在不同的输出窗格之间切换。

## 还有更多...

在前一节中，我们讨论了如何通过 C++编码将样式表应用到 Qt 小部件。虽然这种方法非常有效，但大多数时候负责设计程序 UI 的人不是程序员，而是专门设计用户友好 UI 的 UI 设计师。在这种情况下，最好让 UI 设计师使用不同的工具设计程序的布局和样式表，而不要在代码中乱搞。

Qt 提供了一个名为 Qt Creator 的多合一编辑器。Qt Creator 包括几种不同的工具，如脚本编辑器、编译器、调试器、分析器和 UI 编辑器。UI 编辑器，也称为 Qt Designer，是设计师设计其程序 UI 而无需编写任何代码的完美工具。这是因为 Qt Designer 采用了所见即所得的方法，通过提供最终结果的准确视觉表示，意味着您在 Qt Designer 中设计的任何内容在编译和运行程序时都会完全相同。

Qt 样式表和 CSS 之间的相似之处如下：

+   **CSS**：`h1 { color: red; background-color: white;}`

+   **Qt 样式表**：`QLineEdit { color: red; background-color: white;}`

+   如您所见，它们都包含选择器和声明块。每个声明包含一个属性和一个值，由冒号分隔。

+   在 Qt 中，可以通过在 C++代码中调用`QObject::setStyleSheet()`函数将样式表应用于单个小部件，例如：

```cpp
myPushButton->setStyleSheet("color : blue");
```

+   上述代码将将变量名为`myPushButton`的按钮的文本颜色更改为`蓝色`。您也可以通过在 Qt Designer 的样式表属性字段中编写声明来实现相同的结果。我们将在下一节中更多地讨论 Qt Designer。

+   Qt 样式表还支持 CSS2 标准中定义的所有不同类型的选择器，包括通用选择器、类型选择器、类选择器、ID 选择器等，这使我们能够将样式应用于非常具体的单个或一组小部件。例如，如果我们想要更改具有对象名称`usernameEdit`的特定行编辑小部件的背景颜色，我们可以使用 ID 选择器来引用它：

```cpp
QLineEdit#usernameEdit { background-color: blue }
```

### 注意

要了解 CSS2 中所有选择器的详细信息（这些选择器也被 Qt 样式表支持），请参考此文档：[`www.w3.org/TR/REC-CSS2/selector.html`](http://www.w3.org/TR/REC-CSS2/selector.html)。

# 基本样式表定制

在前面的示例中，您学会了如何在 Qt Designer 中将样式表应用于小部件。让我们疯狂一下，进一步推动事情，创建一些其他类型的小部件，并将它们的样式属性更改为一些奇怪的东西以便学习。但是这一次，我们不会逐个将样式应用于每个小部件，而是学会将样式表应用于主窗口，并让它在整个层次结构中继承到所有其他小部件，以便更容易地管理和维护样式表。

## 如何做...

1.  首先，让我们通过选择它并单击`styleSheet`属性旁边的小箭头按钮来从按钮中删除样式表。这个按钮将将属性恢复到默认值，在这种情况下是空的样式表。

1.  然后，通过将它们一个接一个地从小部件框拖动到表单编辑器中，向 UI 添加几个小部件。我添加了一个行编辑、组合框、水平滑块、单选按钮和复选框。

1.  为了简单起见，通过从对象检查器中选择它们，右键单击并选择**删除**，从您的 UI 中删除菜单栏、主工具栏和状态栏。现在您的 UI 应该看起来类似于这样：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_03.jpg)

1.  从表单编辑器或对象检查器中选择主窗口，然后右键单击并选择**更改样式表**以打开**编辑样式表**。

插入以下样式表：

```cpp
border: 2px solid gray;
border-radius: 10px;
padding: 0 8px;
background: yellow;
```

1.  现在您将看到一个完全奇异的 UI，所有内容都被涂成黄色，带有厚厚的边框。这是因为前面的样式表没有选择器，这意味着样式将应用于主窗口的所有子小部件，一直到层次结构的底部。为了改变这一点，让我们尝试一些不同的东西：

```cpp
QPushButton
{
  border: 2px solid gray;
  border-radius: 10px;
  padding: 0 8px;
  background: yellow;
}
```

1.  这一次，只有按钮将获得前面代码中描述的样式，所有其他小部件将返回到默认样式。您可以尝试向您的 UI 添加几个按钮，它们将看起来都一样：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_04.jpg)

1.  这是因为我们明确告诉选择器将样式应用于所有具有名为`QPushButton`的类的小部件。我们还可以通过在样式表中提及其名称来仅将样式应用于其中一个按钮，如下所示：

```cpp
QPushButton#pushButton_3
{
  border: 2px solid gray;
  border-radius: 10px;
  padding: 0 8px;
  background: yellow;
}
```

1.  一旦您理解了这种方法，我们可以将以下代码添加到样式表中：

```cpp
QPushButton
{
 color: red;
 border: 0px;
 padding: 0 8px;
 background: white;
}

QPushButton#pushButton_2
{
 border: 1px solid red;
 border-radius: 10px;
}

QPushButton#pushButton_3
{
  border: 2px solid gray;
  border-radius: 10px;
  padding: 0 8px;
  background: yellow;
}
```

1.  它的作用基本上是更改所有按钮的样式，以及更改名为`pushButton_2`的特定按钮的一些属性。我们保留`pushButton_3`的样式表。现在按钮将看起来像这样：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_05.jpg)

1.  第一组样式表将把所有`QPushButton`类型的小部件更改为白色的矩形按钮，没有边框，红色文本。然后第二组样式表仅更改名为`pushButton_2`的特定`QPushButton`小部件的边框。请注意，`pushButton_2`的背景颜色和文本颜色仍然分别为白色和红色，因为我们没有在第二组样式表中覆盖它们，因此它将返回到第一组样式表中描述的样式，因为它适用于所有`QPushButton`小部件。请注意，第三个按钮的文本也变为了红色，因为我们没有在第三组样式表中描述颜色属性。

1.  之后，使用通用选择器创建另一组样式，如下所示：

```cpp
*
{
  background: qradialgradient(cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4, radius: 1.35, stop: 0 #fff, stop: 1 #888);
  color: rgb(255, 255, 255);
  border: 1px solid #ffffff;
}
```

1.  通用选择器将影响所有小部件，而不考虑它们的类型。因此，前面的样式表将为所有小部件的背景应用漂亮的渐变颜色，并将它们的文本设置为白色，并给它们一个白色的一像素实线轮廓。我们可以使用`rgb`函数（`rgb(255, 255, 255)`）或十六进制代码（`#ffffff`）来描述颜色值，而不是写颜色的名称（即白色）。

1.  就像以前一样，前面的样式表不会影响按钮，因为我们已经为它们提供了自己的样式，这将覆盖通用选择器中描述的一般样式。请记住，在 Qt 中，更具体的样式最终将在对小部件产生影响的多个样式中使用。这是现在 UI 的外观：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_06.jpg)

## 它是如何工作的...

如果您曾经参与使用 HTML 和 CSS 进行 Web 开发，Qt 的样式表的工作方式与 CSS 完全相同。样式表提供了描述小部件呈现方式的定义 - 小部件组中每个元素的颜色是什么，边框应该有多厚等等。

如果你将小部件的名称指定给样式表，它将更改具有你提供的名称的特定推按钮小部件的样式。其他小部件都不会受到影响，仍将保持默认样式。

要更改小部件的名称，从表单编辑器或对象检查器中选择小部件，并在属性窗口中更改名为`objectName`的属性。如果之前使用了 ID 选择器来更改小部件的样式，更改其对象名称将破坏样式表并丢失样式。要解决这个问题，只需在样式表中也更改对象名称。

# 使用样式表创建登录界面

接下来，我们将学习如何将我们在之前示例中学到的所有知识结合起来，为一个想象中的操作系统创建一个虚假的图形登录界面。样式表并不是你需要掌握的唯一东西，以设计良好的 UI。你还需要学会如何使用 Qt Designer 中的布局系统整齐地排列小部件。

## 操作步骤…

1.  我们需要做的第一件事是在开始任何操作之前设计图形登录界面的布局。规划对于制作良好的软件非常重要。以下是我制作的一个示例布局设计，以展示我想象中的登录界面将会是什么样子。只要能清晰地传达信息，像这样的简单线条图就足够了：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_07.jpg)

1.  现在我们知道了登录界面应该是什么样子，让我们再次回到 Qt Designer。

1.  我们将首先放置顶部面板上的小部件，然后放置标志和登录表单。

1.  选择主窗口，并将其宽度和高度从 400 和 300 分别更改为 800 和 600，因为我们将需要更大的空间来放置所有的小部件。

1.  点击并从小部件框中的**显示小部件**类别下拖动一个标签到表单编辑器中。

1.  将标签的`objectName`属性更改为`currentDateTime`，并将其`Text`属性更改为当前日期和时间，仅用于显示目的，例如`星期一，2015 年 10 月 25 日 下午 3:14`。

1.  点击并从**按钮**类别下拖动一个推按钮到表单编辑器中。重复此过程一次，因为顶部面板上有两个按钮。将这两个按钮分别重命名为`restartButton`和`shutdownButton`。

1.  接下来，选择主窗口并单击表单工具栏上的小图标按钮，当鼠标悬停在上面时，它会显示**垂直布局**。现在你会看到小部件被自动排列在主窗口上，但还不是我们想要的。

1.  点击并从**布局**类别下拖动一个水平布局小部件到主窗口中。

1.  点击并将两个按钮和文本标签拖放到水平布局中。现在你会看到这三个小部件被水平排列，但在垂直方向上它们位于屏幕中间。水平排列几乎是正确的，但垂直位置完全不对。

1.  点击并从**间隔器**类别下拖动一个垂直间隔器，并将其放置在我们之前创建的水平布局下方（红色矩形轮廓下方）。现在你会看到所有的小部件都被间隔器推到了顶部。

1.  现在，在文本标签和两个按钮之间放置一个水平间隔器，使它们保持分开。这将使文本标签始终保持在左侧，按钮对齐到右侧。

1.  将两个按钮的`水平策略`和`垂直策略`属性都设置为`固定`，并将`minimumSize`属性设置为`55x55`。然后，将按钮的`text`属性设置为空，因为我们将使用图标而不是文本。我们将在下一节学习如何在按钮小部件中放置图标。

1.  现在你的 UI 应该看起来类似于这样：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_08.jpg)

接下来，我们将通过以下步骤添加标志：

1.  在顶部面板和垂直间隔器之间添加一个水平布局，作为标志的容器。

1.  添加水平布局后，您会发现布局的高度太瘦，无法添加任何小部件。这是因为布局是空的，并且被下方的垂直间隔推到零高度。为解决这个问题，我们可以将其垂直边距（`layoutTopMargin`或`layoutBottomMargin`）临时设置得更大，直到向布局添加小部件为止。

1.  接下来，在您刚刚创建的水平布局中添加一个标签，并将其重命名为`logo`。我们将在下一节中学习如何将图像插入标签以将其用作徽标。目前，只需清空`text`属性，并将其`Horizontal Policy`和`Vertical Policy`属性都设置为`Fixed`。然后，将`minimumSize`属性设置为`150x150`。

1.  如果尚未这样做，请将布局的垂直边距设置回零。

1.  现在徽标看起来是不可见的，因此我们将添加一个临时样式表使其可见，直到在下一节中为其添加图像。样式表非常简单：

```cpp
border: 1px solid;
```

1.  现在您的 UI 应该看起来类似于这样：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_09.jpg)

现在让我们按照以下步骤创建登录表单：

1.  在徽标的布局和垂直间隔之间添加一个水平布局。就像之前一样，将`layoutTopMargin`属性设置为更大的数字（例如 100），以便更轻松地向其中添加小部件。

1.  之后，在您刚刚创建的水平布局中添加一个垂直布局。该布局将用作登录表单的容器。将其`layoutTopMargin`设置为比水平布局低的数字（例如 20），以便我们可以在其中放置小部件。

1.  接下来，右键单击您刚刚创建的垂直布局，然后选择**Morph into -> QWidget**。垂直布局现在被转换为一个空小部件。这一步是必不可少的，因为我们将调整登录表单的容器的宽度和高度。布局小部件不包含宽度和高度的任何属性，而只包含边距，因为布局将向其周围的空白空间扩展，这是有道理的，考虑到它没有任何大小属性。将布局转换为`QWidget`对象后，它将自动继承小部件类的所有属性，因此我们现在可以调整其大小以满足我们的需求。

1.  将刚刚从布局转换的`QWidget`对象重命名为`loginForm`，并将其`Horizontal Policy`和`Vertical Policy`属性都设置为`Fixed`。然后，将`minimumSize`设置为`350x200`。

1.  由于我们已经将`loginForm`小部件放入了水平布局中，现在可以将其`layoutTopMargin`属性设置回零。

1.  将与徽标相同的样式表添加到`loginForm`小部件中，以使其暂时可见，但这次我们需要在前面添加一个 ID 选择器，以便仅将样式应用于`loginForm`，而不是其子小部件：

```cpp
#loginForm { border: 1px solid; }
```

1.  现在您的 UI 应该看起来类似于这样：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_10.jpg)

我们还没有完成登录表单。现在我们已经为登录表单创建了容器，是时候向表单中添加更多小部件了：

1.  将两个水平布局放入登录表单容器中。我们需要两个布局，一个用于用户名字段，另一个用于密码字段。

1.  在您刚刚添加的每个布局中添加一个标签和一个行编辑。将上方标签的`text`属性更改为“用户名：”，下方标签更改为“密码：”。然后，分别将两个行编辑重命名为`username`和`password`。

1.  在密码布局下方添加一个按钮，并将其`text`属性更改为“登录”。然后，将其重命名为`loginButton`。

1.  您可以在密码布局和登录按钮之间添加一个垂直间隔以稍微拉开它们之间的距离。放置垂直间隔后，将其`sizeType`属性更改为`Fixed`，并将`Height`更改为`5`。

1.  现在，选择`loginForm`容器，并将其所有边距设置为 35。这是为了通过在所有边缘添加一些空间来使登录表单看起来更好。

1.  您还可以将`username`、`password`和`loginButton`小部件的`Height`属性设置为 25，以使它们看起来不那么拥挤。

1.  现在您的用户界面应该看起来像这样：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_11.jpg)

我们还没有完成！正如您所看到的，由于它们下方的垂直间隔器，登录表单和标志都紧贴主窗口顶部。标志和登录表单应该放在主窗口的中心，而不是顶部。要解决这个问题，请按照以下步骤操作：

1.  在顶部面板和标志布局之间添加另一个垂直间隔器。这样它将抵消底部的间隔器，从而平衡对齐。

1.  如果您认为标志与登录表单太过紧密，还可以在标志布局和登录表单布局之间添加一个垂直间隔器。将其`sizeType`属性设置为`Fixed`，将`Height`属性设置为`10`。

1.  右键单击顶部面板的布局，然后选择**Morph into -> QWidget**。然后，将其重命名为`topPanel`。布局必须转换为`QWidget`的原因是，我们无法对布局应用样式表，因为它除了边距之外没有任何属性。

1.  目前，您可以看到主窗口的边缘周围有一点边距 - 我们不希望出现这种情况。要删除边距，请从对象检查器窗口中选择`centralWidget`对象，该对象位于`MainWindow`面板的正下方，并将所有边距值设置为零。

1.  此时，您可以通过单击**Run**按钮（带有绿色箭头图标）来运行项目，以查看您的程序现在的外观。如果一切顺利，您应该看到类似于这样的东西：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_12.jpg)

1.  布局完成后，是时候为用户界面添加一些花哨的样式表了！由于所有重要的小部件都被赋予了对象名称，因此我们可以更容易地从主窗口为其应用样式表，因为我们只会将样式表写到主窗口，然后让它们在层次树中继承下来。

1.  从对象检查器窗口中右键单击**MainWindow**，然后选择**Change Stylesheet**。

1.  将以下代码添加到样式表中：

```cpp
#centralWidget { background: rgba(32, 80, 96, 100); }
```

1.  现在您会看到主窗口的背景颜色发生了变化。我们将在下一节中学习如何使用图像作为背景，因此颜色只是临时的。

1.  在 Qt 中，如果要对主窗口本身应用样式，必须将其应用到其中央小部件，而不是主窗口本身，因为窗口只是一个容器。

1.  然后，我们将为顶部面板添加一个漂亮的渐变颜色：

```cpp
#topPanel { background-color: qlineargradient(spread:reflect, x1:0.5, y1:0, x2:0, y2:0, stop:0 rgba(91, 204, 233, 100), stop:1 rgba(32, 80, 96, 100)); }
```

1.  之后，我们将为登录表单应用黑色，并使其看起来半透明。之后，我们还将通过设置`border-radius`属性使登录表单容器的角略微圆润：

```cpp
#loginForm
{
  background: rgba(0, 0, 0, 80);
  border-radius: 8px;
}
```

1.  在我们完成对特定小部件应用样式之后，我们将对一般类型的小部件应用样式：

```cpp
QLabel { color: white; }
QLineEdit { border-radius: 3px; }
```

1.  上述样式表将把所有标签的文本更改为白色，这包括小部件上的文本，因为在内部，Qt 使用相同类型的标签来标记带有文本的小部件。此外，我们使线编辑小部件的角稍微圆润。

1.  接下来，我们将为用户界面上的所有推按钮应用样式表：

```cpp
QPushButton
{
  color: white;
  background-color: #27a9e3;
  border-width: 0px;
  border-radius: 3px;
}
```

1.  上述样式表将把所有按钮的文本更改为白色，然后将其背景颜色设置为蓝色，并且还使其角稍微圆润。

1.  为了更进一步推动事情，我们将使用关键字`hover`来在鼠标悬停时更改推按钮的颜色。

```cpp
QPushButton:hover { background-color: #66c011; }
```

1.  上述样式表将在鼠标悬停时将推按钮的背景颜色更改为绿色。我们将在下一节中详细讨论这个问题。

1.  您可以进一步调整小部件的大小和边距，使它们看起来更好。记得通过删除我们之前直接应用到登录表单的样式表来删除登录表单的边框线。

1.  现在您的登录屏幕应该看起来像这样：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_13.jpg)

## 它是如何工作的…

这个示例更多地关注 Qt 的布局系统。Qt 布局系统提供了一种简单而强大的方式，自动安排小部件在一个小部件内，以确保它们充分利用可用的空间。

在前面的示例中使用的间隔项有助于推动布局中包含的小部件向外推动，以创建间距。要将小部件定位到布局的中间，请将两个间隔项放到布局中，一个放在小部件的左侧，另一个放在小部件的右侧。然后，这两个间隔器将把小部件推到布局的中间。

# 在样式表中使用资源

Qt 为我们提供了一个平台无关的资源系统，允许我们将任何类型的文件存储在程序的可执行文件中以供以后使用。我们可以在可执行文件中存储任何类型的文件，如图像、音频、视频、HTML、XML、文本文件、二进制文件等。如果您的应用程序始终需要一定的文件集（图标、翻译文件等），并且您不希望丢失这些文件，这将非常有用。为了实现这一点，我们必须告诉 Qt 我们想要将哪些文件添加到其资源系统中的`.qrc`文件，并且 Qt 将在构建过程中处理其余部分。

## 如何做

要向项目添加新的`.qrc`文件，请转到**文件** | **新建文件或项目**。然后，在**文件和类别**类别下选择**Qt**，然后选择**Qt 资源文件**。之后，给它取一个名字（即`resources`），然后单击**下一步**，接着单击**完成**。`.qrc`文件将被创建并由 Qt Creator 自动打开。

您不必直接在 XML 格式中编辑`.qrc`文件，因为 Qt Creator 为您提供了用户界面来管理资源。要向项目添加图像和图标，首先需要确保图像和图标被放置在项目的目录中。

在 Qt Creator 中打开`.qrc`文件后，单击**添加**按钮，然后单击**添加前缀**按钮。前缀用于对资源进行分类，以便在项目中有大量资源时更好地进行管理：

1.  重命名您刚创建的前缀为`/icons`。

1.  然后，通过单击**添加**，然后单击**添加前缀**来创建另一个前缀。

1.  重命名新的前缀为`/images`。

1.  之后，选择`/icon`前缀，然后单击**添加**，接着单击**添加文件**。

1.  将出现文件选择窗口；使用它来选择所有图标文件。您可以通过在键盘上按住*Ctrl*键并单击文件来选择多个文件。完成后，单击**打开**。

1.  然后，选择`/images`前缀，然后单击**添加**按钮，接着单击**添加文件**按钮。文件选择窗口将再次弹出，这次我们将选择背景图像。

1.  重复上述步骤，但这次我们将把徽标图像添加到`/images`前缀。

完成后不要忘记按*Ctrl* + *S*保存。您的`.qrc`文件现在应该是这样的：

![如何做](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_14.jpg)

1.  之后，打开我们的`mainwindow.ui`文件；我们现在将使用刚刚添加到项目中的资源。首先，我们将选择位于顶部面板上的重新启动按钮。然后，向下滚动属性编辑器，直到看到`icon`属性。单击带有下拉箭头图标的小按钮，然后从其菜单中单击**选择资源**。

1.  然后将弹出**选择资源**窗口。在左侧面板上单击`icons`前缀，然后在右侧面板上选择重新启动图标。之后，按**确定**。

1.  现在您会看到一个小图标出现在按钮上。图标看起来非常小，因为默认图标尺寸设置为`16x16`。将`iconSize`属性更改为`50x50`，您会看到图标现在变大了。

对于关闭按钮，重复上述步骤，只是这次我们将选择关闭图标。

1.  完成后，两个按钮现在应该看起来像这样：![如何做](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_15.jpg)

1.  接下来，我们将使用添加到资源文件中的图像作为我们的标志。首先，选择标志小部件，并删除我们先前添加的样式表，以渲染其轮廓。

1.  向下滚动属性编辑器，直到看到`pixmap`属性。

1.  单击`pixmap`属性后面的小下拉按钮，并从菜单中选择**选择资源**。之后，选择标志图像并单击**确定**。现在，您会看到标志的大小不再遵循您先前设置的尺寸，而是遵循图像的实际尺寸。我们无法更改其尺寸，因为这就是`pixmap`的工作原理。

1.  如果您想对标志的尺寸有更多控制，可以从`pixmap`属性中删除图像，并改用样式表。您可以使用以下代码将图像应用到图标容器：

```cpp
border-image: url(:/images/logo.png);
```

1.  要获取图像的路径，请右键单击文件列表窗口上的图像名称，然后选择**复制路径**。路径将保存到您的操作系统剪贴板中，现在您可以将其粘贴到前面的样式表中。使用这种方法将确保图像完全适合您应用样式的小部件的尺寸。您的标志现在应该看起来像这样：![如何做](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_16.jpg)

1.  最后，我们将使用样式表将壁纸图像应用到背景上。由于背景尺寸会根据窗口大小而改变，所以在这种情况下我们不能使用`pixmap`。相反，我们将使用样式表中的`border-image`属性来实现这一点。右键单击主窗口，选择**更改样式表**以打开**编辑样式表**窗口。我们将在中央小部件的样式表下添加一行新的样式表：

```cpp
#centralWidget
{
  background: rgba(32, 80, 96, 100);
 border-image: url(:/images/login_bg.png);
}
```

1.  这真的很简单和容易！您的登录界面现在应该看起来像这样：![如何做](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_17.jpg)

## 它的工作原理…

Qt 中的资源系统将二进制文件（如图像、翻译文件等）存储在编译后的可执行文件中。它读取项目中的资源集合文件（`.qrc`）来定位需要存储在可执行文件中的文件，并将它们包含到构建过程中。`.qrc`文件看起来像这样：

```cpp
<!DOCTYPE RCC><RCC version="1.0">
  <qresource>
    <file>images/copy.png</file>
    <file>images/cut.png</file>
    <file>images/new.png</file>
    <file>images/open.png</file>
    <file>images/paste.png</file>
    <file>images/save.png</file>
  </qresource>
</RCC>
```

它使用 XML 格式存储资源文件的路径，这些路径是相对于包含它的目录的。请注意，列出的资源文件必须位于与`.qrc`文件相同的目录中，或者其子目录之一。

# 自定义属性和子控件

Qt 的样式表系统使我们能够轻松创建令人惊叹和专业的 UI。在这个例子中，我们将学习如何为我们的小部件设置自定义属性，并使用它们在不同样式之间切换。

## 如何做…

1.  让我们尝试一下上述段落中描述的情景，创建一个新的 Qt 项目。我已经为此准备了 UI。UI 在左侧包含三个按钮，在右侧有一个包含三个页面的选项卡小部件，如下截图所示：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_18.jpg)

1.  三个按钮是蓝色的，因为我已将以下样式表添加到主窗口（而不是单独的按钮）：

```cpp
QPushButton
{
  color: white;
  background-color: #27a9e3;
  border-width: 0px;
  border-radius: 3px;
}
```

1.  接下来，我将通过向主窗口添加以下样式表来向您解释 Qt 中的伪状态，您可能已经熟悉：

```cpp
QPushButton:hover
{
  color: white;
  background-color: #66c011;
  border-width: 0px;
  border-radius: 3px;
}
```

1.  我们在上一个教程中使用了前面的样式表，使按钮在鼠标悬停时更改颜色。这是由 Qt 样式表的伪状态实现的，在这种情况下，是单词`hover`与`QPushButton`类之间用冒号分隔。每个小部件都有一组通用伪状态，例如`active`、`disabled`、`enabled`等，还有一组适用于其小部件类型的伪状态。例如，`QPushButton`可用`open`和`flat`等状态，但`QLineEdit`不行。让我们添加`pressed`伪状态以在用户单击时将按钮的颜色更改为黄色：

```cpp
QPushButton:pressed
{
  color: white;
  background-color: yellow;
  border-width: 0px;
  border-radius: 3px;
}
```

1.  伪状态允许用户根据适用于它的条件加载不同的样式表。Qt 通过在 Qt 样式表中实现动态属性进一步推动了这一概念。这使我们能够在满足自定义条件时更改小部件的样式表。我们可以利用此功能根据 Qt 中的自定义属性设置来更改按钮的样式表。

首先，我们将向我们的主窗口添加此样式表：

```cpp
QPushButton[pagematches=true]
{
  color: white;
  background-color: red;
  border-width: 0px;
  border-radius: 3px;
}
```

1.  它的基本作用是，如果名为`pagematches`的属性返回`true`，则将推按钮的背景颜色更改为红色。显然，`QPushButton`类中不存在此属性。但是，我们可以通过使用`QObject::setProperty()`将其添加到我们的按钮中：

+   在您的`MainWindow.cpp`源代码中，在`ui->setupUi(this)`之后添加以下代码：

```cpp
ui->button1->setProperty("pagematches", true);
```

+   前面的代码将向第一个按钮添加一个名为`pagematches`的自定义属性，并将其值设置为`true`。这将使第一个按钮默认变为红色。

+   然后，在选项卡小部件上右键单击，选择**转到槽**。然后会弹出一个窗口；从列表中选择**currentChanged(int)**选项，然后单击**确定**。Qt 将为您生成一个`slot`函数，看起来像这样：

```cpp
private slots:
void on_tabWidget_currentChanged(int index);
```

+   每当我们更改选项卡小部件的页面时，将调用`slot`函数。然后，我们可以通过将代码添加到`slot`函数中来决定我们希望它执行的操作。要做到这一点，请打开`mainwindow.cpp`，您将在那里看到函数的声明。让我们向函数添加一些代码：

```cpp
void MainWindow::on_tabWidget_currentChanged(int index)
{
  // Set all buttons to false
  ui->button1->setProperty("pagematches", false);
  ui->button2->setProperty("pagematches", false);
  ui->button3->setProperty("pagematches", false);

  // Set one of the buttons to true
  if (index == 0)
    ui->button1->setProperty("pagematches", true);
  else if (index == 1)
    ui->button2->setProperty("pagematches", true);
  else
    ui->button3->setProperty("pagematches", true);

  // Update buttons style
  ui->button1->style()->polish(ui->button1);
  ui->button2->style()->polish(ui->button2);
  ui->button3->style()->polish(ui->button3);
}
```

1.  前面的代码基本上是这样的：当选项卡小部件切换到当前页面时，它将所有三个按钮的`pagematches`属性设置为`false`。在我们决定哪个按钮应该变为红色之前，请确保重置所有内容。

1.  然后，检查事件信号提供的`index`变量，它将告诉您当前页面的索引号。根据索引号将一个按钮的`pagematches`属性设置为`true`。

1.  最后，通过调用`polish()`来刷新所有三个按钮的样式。

然后，构建并运行项目。现在，每当您将选项卡小部件切换到不同页面时，您应该会看到三个按钮的颜色变为红色。此外，当鼠标悬停时，按钮将变为绿色，当您单击它们时，它们的颜色将变为黄色：

![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_19.jpg)

## 它是如何工作的…

Qt 为用户提供了向任何类型的小部件添加自定义属性的自由。如果您想在满足特殊条件时更改特定小部件，而 Qt 默认情况下不提供这样的上下文，那么自定义属性非常有用。这使用户能够扩展 Qt 的可用性，并使其成为定制解决方案的灵活工具。

例如，如果我们在主窗口上有一排按钮，并且我们需要其中一个根据选项卡小部件当前显示的页面而更改其颜色，则按钮不会知道它们何时应更改其颜色，因为 Qt 本身没有针对这种情况的内置上下文。为了解决这个问题，Qt 为我们提供了一种方法来向小部件添加自己的属性，即使用一个名为`QObject::setProperty()`的通用函数。要读取自定义属性，我们可以使用另一个名为`QObject::property()`的函数。

接下来，我们将讨论 Qt 样式表中的子控件。通过观察子控件这个术语，实际上是相当不言自明的。通常，一个小部件不仅仅是一个单一的对象，而是由多个对象或控件组合而成，以形成一个更复杂的小部件，这些对象被称为子控件。

例如，一个微调框小部件包含一个输入字段、一个向下按钮、一个向上按钮、一个向上箭头和一个向下箭头，与其他一些小部件相比相当复杂。在这种情况下，Qt 允许我们通过样式表更灵活地改变每个子控件，如果我们想的话。我们可以通过在小部件类名后面指定子控件的名称，用双冒号分隔来实现。例如，如果我想改变微调框中向下按钮的图像，我可以这样写我的样式表：

```cpp
QSpinBox::down-button
{
  image: url(:/images/spindown.png);
  subcontrol-origin: padding;
  subcontrol-position: right bottom;
}
```

这将只将图像应用于我的微调框的向下按钮，而不是小部件的任何其他部分。

通过结合自定义属性、伪状态和子控件，Qt 为我们提供了一种非常灵活的方法来自定义我们的用户界面。

### 注意

访问以下链接了解更多关于 Qt 中伪状态和子控件的信息：

[`doc.qt.io/qt-4.8/stylesheet-reference.html`](http://doc.qt.io/qt-4.8/stylesheet-reference.html)

# 在 QML 中进行样式设置

**Qt Meta Language**或**Qt Modeling Language**（**QML**）是 Qt 使用的一种类似于 Javascript 的用户界面标记语言，用于设计用户界面。Qt 为您提供了 Qt Quick 组件（由 QML 技术提供支持的小部件），可以轻松设计触摸友好的 UI，无需 C++编程。我们将通过按照以下部分给出的步骤来学习如何使用 QML 和 Qt Quick 组件来设计我们程序的 UI。

## 如何做…

1.  通过转到**文件**|**新建文件或项目**来创建一个新项目。在**项目**类别下选择**应用程序**，然后选择**Qt Quick 应用程序**。

1.  点击**选择**按钮，这将带您到下一个窗口。输入项目名称，然后再次点击**下一步**按钮。

1.  现在将出现另一个窗口，询问您选择所需的最低 Qt 版本。选择计算机上安装的最新版本，然后点击**下一步**。

1.  之后，再次点击**下一步**，然后点击**完成**。Qt Creator 现在将为您创建一个新项目。

1.  项目创建后，您会发现与 C++ Qt 项目相比有一些不同。您会在项目资源中看到两个`.qml`文件，分别是`main.qml`和`MainForm.ui.qml`。这两个文件是使用 QML 标记语言的 UI 描述文件。如果您双击`main.qml`文件，Qt Creator 将打开脚本编辑器，您会看到类似于这样的内容：

```cpp
import QtQuick 2.5
import QtQuick.Window 2.2

Window {
  visible: true
  MainForm {
    anchors.fill: parent
    mouseArea.onClicked: {
      Qt.quit();
    }
  }
}
```

1.  这个文件基本上告诉 Qt 创建一个窗口，并插入一个名为`MainForm`的 UI 集，实际上是来自另一个名为`MainForm.ui.qml`的`.qml`文件。它还告诉 Qt，当用户点击**mouseArea**小部件时，整个程序应该被终止。

1.  现在，尝试双击打开`MainForm.ui.qml`文件。这次，Qt Designer（UI 编辑器）将被打开，您会看到一个与我们之前做的 C++项目完全不同的 UI 编辑器。这个编辑器也被称为 Qt Quick Designer，专门用于编辑基于 QML 的 UI。

1.  如果你在项目中打开`main.cpp`文件，你会看到这行代码：

```cpp
QQmlApplicationEngine engine;
engine.load(QUrl(QStringLiteral("qrc:/main.qml")));
```

1.  前面的代码基本上告诉 Qt 的 QML 引擎在程序启动时加载`main.qml`文件。如果你想加载其他`.qml`文件而不是`main.qml`，你知道在哪里找代码了。

1.  当`main.qml`被 QML 引擎加载时，它还将`MainForm.ui.qml`导入到 UI 中，因为`MainForm`在`main.qml`文件中被调用。Qt 将通过搜索其`.qml`文件来检查`MainForm`是否是有效的 UI，这是基于命名约定的。基本上，这个概念类似于我们在上一节中做的 C++项目，其中`main.qml`文件就像`main.cpp`文件，`MainForm.ui.qml`就像`MainWindow`类。您还可以创建其他 UI 模板并在`main.qml`中使用它们。希望这种比较能让您更容易理解 QML 的工作原理。

1.  现在让我们打开`MainForm.ui.qml`。您应该在导航窗口上看到列出了三个项目：**Rectangle**、**mouseArea**和**Text**。当 QML 引擎解释这些项目时，它会在画布上产生以下结果：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_21.jpg)

1.  **Rectangle**项目基本上是窗口的基本布局，无法删除。它类似于我们在上一节中使用的`centralWidget`。**mouseArea**项目是一个无形项目，当鼠标点击它或手指触摸它（适用于移动平台）时会触发它。鼠标区域也用于按钮组件，我们一会儿会用到。**Text**组件是不言自明的：它是一个在应用程序上显示文本块的标签。

1.  在**导航**窗口上，我们可以通过单击类似于眼睛图标的项目旁边的图标来隐藏或显示项目。当项目被隐藏时，它将不会显示在画布上，也不会显示在编译后的应用程序中。就像 C++ Qt 项目中的小部件一样，Qt Quick 组件是根据父子关系的层次结构排列的。所有子项目将放置在具有缩进位置的父项目下方。在我们的情况下，您可以看到**mouseArea**和**Text**项目都相对于**Rectangle**项目略微向右放置，因为它们都是**Rectangle**项目的子项目。我们可以通过从导航窗口使用单击和拖动的方法重新排列父子关系以及它们在层次结构中的位置。您可以尝试单击**Text**项目并将其拖动到**mouseArea**上方。然后，您将看到**Text**项目改变了位置，现在位于**mouseArea**下方，并且缩进更宽：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_22.jpg)

1.  我们还可以通过使用位于导航窗口顶部的箭头按钮来重新排列它们，如前面的屏幕截图所示。发生在父项上的任何事情也会影响到其所有子项，例如移动父项、隐藏和显示父项等。

### 提示

您可以通过按住鼠标中键（或鼠标滚轮）并移动鼠标来在画布视图中移动。您还可以在按住键盘上的*Ctrl*键的同时滚动鼠标来放大和缩小。默认情况下，滚动鼠标会上下移动画布视图。但是，如果您的鼠标光标位于画布的水平滚动条上方，滚动鼠标将使视图向左和向右移动。

1.  接下来，删除**mouseArea**和**Text**项目，因为我们将学习如何使用 QML 和 Qt Quick 从头开始创建用户界面。

1.  完成后，让我们将**Rectangle**项目的大小设置为`800x600`，因为我们将需要更大的空间来放置小部件。

1.  打开`main.qml`并删除以下代码：

```cpp
mouseArea.onClicked: {
  Qt.quit();
}
```

这是因为**mouseArea**项目不再存在，当编译时会导致错误。

1.  之后，从`MainForm.ui.qml`中删除以下代码：

```cpp
property alias mouseArea: mousearea
```

1.  由于**mouseArea**项目不再存在，因此出于相同的原因，此内容已被删除。

1.  然后，将我们在之前的 C++项目中使用的图像复制到 QML 项目的文件夹中，因为我们要使用 QML 重新创建相同的登录界面！

1.  将图像添加到资源文件中，以便我们可以在 UI 中使用它们。

1.  完成后，再次打开 Qt Quick Designer，并切换到资源窗口。直接点击并拖动背景图像到画布上。然后，切换到属性窗格上的**布局**选项卡，并点击红色圆圈标记的填充锚点按钮。这将使背景图像始终固定在窗口大小上：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_23.jpg)

1.  接下来，从库窗口中点击并拖动一个**矩形**组件到画布上。我们将使用这个作为程序的顶部面板。

1.  对于顶部面板，启用顶部锚点、左锚点和右锚点，使其固定在窗口顶部并跟随其宽度。确保所有边距都设置为零。

1.  然后，转到顶部面板的`Color`属性，并选择**Gradient**模式。将第一种颜色设置为`#805bcce9`，第二种颜色设置为`#80000000`。这将创建一个半透明的面板，带有蓝色的渐变。

1.  之后，将一个文本小部件添加到画布上，并将其设置为顶部面板的子级。将其文本属性设置为当前日期和时间（例如，星期一，2015 年 10 月 26 日下午 3:14），以供显示目的。然后，将文本颜色设置为白色。

1.  切换到**布局**选项卡，启用顶部锚点和左锚点，以便文本小部件始终固定在屏幕的左上角。

1.  接下来，在屏幕上添加一个鼠标区域，并将其大小设置为`50x50`。然后，通过将其拖动到导航窗口中的顶部面板上，使其成为顶部面板的子级。

1.  将鼠标区域的颜色设置为蓝色（`#27a9e3`），并将其半径设置为`2`，使其角落略微圆润。然后，启用顶部锚点和右锚点，使其固定在窗口的右上角。将顶部锚点的边距设置为`8`，右锚点的边距设置为`10`，以留出一些空间。

1.  之后，打开资源窗口，并将关闭图标拖动到画布上。然后，将其设置为我们刚刚创建的鼠标区域项的子级。然后，启用填充锚点，使其适应鼠标区域的大小。

1.  哦，这是很多步骤！现在你的项目应该在**导航**窗口上排列如下：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_24.jpg)

1.  当主窗口改变大小时，父子关系和布局锚点都非常重要，以保持小部件在正确的位置。

1.  此时，你的顶部面板应该看起来像这样：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_25.jpg)

1.  接下来，我们将开始处理登录表单。首先，通过从**库**窗口中拖动矩形到画布上，添加一个新的矩形。将矩形的大小调整为`360x200`，并将其半径设置为`15`。

1.  然后，将其颜色设置为`#80000000`，这将使其变为黑色，透明度为`50%`。

1.  之后，启用垂直中心锚点和水平中心锚点，使其始终与窗口中心对齐。然后，将垂直中心锚点的边距设置为`100`，使其稍微向下移动到底部，为标志留出空间。以下截图展示了锚点的设置：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_26.jpg)

1.  将文本小部件添加到画布上。将它们设置为登录表单（矩形小部件）的子级，并将它们的文本属性分别设置为`用户名：`和`密码：`。然后，将它们的文本颜色设置为白色，并相应地定位它们。这次我们不需要设置边距，因为它们将跟随矩形的位置。

1.  然后，在画布上添加两个文本输入小部件，并将它们放置在我们刚刚创建的文本小部件旁边。确保文本输入也是登录表单的子级。由于文本输入不包含任何背景颜色属性，我们需要在画布上添加两个矩形作为它们的背景。

1.  在画布上添加两个矩形，并将它们分别设置为我们刚刚创建的文本输入的子级。然后，将半径属性设置为`5`，使它们具有一些圆角。之后，在两个矩形上启用填充锚点，以便它们将跟随文本输入小部件的大小。

1.  之后，我们将在密码字段下方创建登录按钮。首先，在画布上添加一个鼠标区域，并将其设置为登录表单的子级。然后，将其调整为所需的尺寸并移动到指定位置。

1.  由于鼠标区域也不包含任何背景颜色属性，我们需要添加一个矩形小部件，并将其设置为鼠标区域的子级。将矩形的颜色设置为蓝色（`#27a9e3`），并启用填充锚点，使其与鼠标区域完美匹配。

1.  接下来，在画布上添加一个文本小部件，并将其设置为登录按钮的子级。将其文本颜色设置为白色，并将其文本属性设置为`登录`。最后，启用水平居中锚点和垂直居中锚点，使其与按钮居中对齐。

1.  现在，您将获得一个看起来与我们在 C++项目中制作的登录表单非常相似的登录表单：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_27.jpg)

1.  完成登录表单后，是时候添加标志了。实际上非常简单。首先，打开资源窗口，然后将标志图像拖放到画布中。

1.  将其设置为登录表单的子级，并将其大小设置为`512x200`。

1.  将其定位在登录表单上方，然后完成！

1.  这是编译后整个 UI 的样子。我们已经成功地用 QML 和 Qt Quick 重新创建了 C++项目中的登录界面！如何做...

## 它是如何工作的...

Qt Quick 编辑器在将小部件放置在应用程序中的方法上与表单编辑器有很大不同。用户可以自行决定哪种方法最适合他/她。

以下截图显示了 Qt Quick Designer 的外观：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_01_20.jpg)

现在我们将看一下编辑器 UI 的各个元素：

1.  **导航器**：**导航器**窗口以树形结构显示当前 QML 文件中的项目。它类似于我们在上一节中使用的其他 Qt Designer 中的对象操作器窗口。

1.  **库**：**库**窗口显示所有可用的 QML 组件或 Qt Quick 控件。您可以单击并将其拖放到画布窗口中以添加到您的 UI 中。您还可以创建自定义的 QML 组件并在此处显示。

1.  **资源**：**资源**窗口以列表形式显示所有资源，然后可以在 UI 设计中使用。

1.  **导入**：**导入**窗口允许您将不同的 QML 模块导入到当前的 QML 文件中，例如蓝牙模块、webkit 模块、定位模块等，以为您的 QML 项目添加额外的功能。

1.  **状态窗格**：状态窗格显示 QML 项目中的不同状态，通常描述 UI 配置，例如 UI 控件、其属性和行为以及可用的操作。

1.  **属性窗格**：与我们在上一节中使用的属性编辑器类似，QML Designer 中的属性窗格显示所选项目的属性。您也可以在代码编辑器中更改项目的属性。

1.  **画布**：画布是您创建 QML 组件和设计应用程序的工作区。

# 将 QML 对象指针暴露给 C++

有时，我们希望通过 C++脚本修改 QML 对象的属性，例如更改标签的文本、隐藏/显示小部件、更改其大小等。Qt 的 QML 引擎允许您将 QML 对象注册为 C++类型，从而自动公开其所有属性。

## 如何做...

我们想在 QML 中创建一个标签，并偶尔更改其文本。为了将标签对象暴露给 C++，我们可以执行以下步骤。首先，创建一个名为`MyLabel`的 C++类，它继承自`QObject`类：

```cpp
mylabel.h:
class MyLabel : public QObject
{
  Q_OBJECT
  public:
    // Object pointer
    QObject* myObject;

    explicit MyLabel(QObject *parent = 0);

  // Must call Q_INVOKABLE so that this function can be used in QML
  Q_INVOKABLE void SetMyObject(QObject* obj);
}
```

在`mylabel.cpp`源文件中，定义一个名为`SetMyObject()`的函数来保存对象指针。稍后将在 QML 中调用此函数：

```cpp
mylabel.cpp:
void MyLabel::SetMyObject(QObject* obj)
{
  // Set the object pointer
  myObject = obj;
}
```

之后，在`main.cpp`中，包括`MyLabel`头文件，并使用`qmlRegisterType()`函数将其注册到 QML 引擎中：

```cpp
#include "mylabel.h"
int main(int argc, char *argv[])
{
  // Register your class to QML
  qmlRegisterType<MyClass>("MyLabelLib", 1, 0, "MyLabel");
}
```

请注意，在`qmlRegisterType()`中需要声明四个参数。除了声明您的类名（`MyLabel`）之外，还需要声明您的库名称（`MyLabelLib`）和其版本（`1.0`），这将用于以后将您的类导入到 QML 中。

现在 QML 引擎已经完全了解我们的自定义标签类，我们可以将其映射到 QML 中的标签对象，并通过在我们的 QML 文件中调用`import MyLabelLib 1.0`来导入我们之前定义的类库。请注意，库名称及其版本号必须与您在`main.cpp`中声明的相匹配，否则将会抛出错误。

在 QML 中声明`MyLabel`并将其 ID 设置为`mylabels`后，立即调用`mylabel.SetMyObject(myLabel)`将其指针暴露给 C/C++，在标签初始化后：

```cpp
import MyLabelLib 1.0

ApplicationWindow
{
  id: mainWindow
  width: 480
  height: 640

  MyLabel
  {
    id: mylabel
  }

  Label
  {
    id: helloWorldLabel
    text: qsTr("Hello World!")
    Component.onCompleted:
    {
      mylabel.SetMyObject(hellowWorldLabel);
    }
  }
}
```

请注意，您需要等待标签完全初始化后，才能将其指针暴露给 C/C++，否则可能会导致程序崩溃。为了确保它完全初始化，调用`SetMyObject()`在`Component.onCompleted`中，而不是其他任何地方。

现在 QML 标签已经暴露给 C/C++，我们可以通过调用`setProperty()`函数来更改其任何属性。例如，我们可以将其可见性设置为`true`，并将其文本更改为`再见世界！`：

```cpp
// QVariant automatically detects your data type
myObject->setProperty("visible", QVariant(true));
myObject->setProperty("text", QVariant("Bye bye world!"));
```

除了更改属性，我们还可以通过调用`QMetaObject::invokeMethod()`来调用其函数：

```cpp
QVariant returnedValue;
QVariant message = "Hello world!";

QMetaObject::invokeMethod(myObject, "myQMLFunction",
Q_RETURN_ARG(QVariant, returnedValue),
Q_ARG(QVariant, message));

qDebug() << "QML function returned:" << returnedValue.toString();
```

或者简单地，如果我们不希望从中返回任何值，我们可以只使用两个参数调用`invokedMethod()`函数：

```cpp
QMetaObject::invokeMethod(myObject, "myQMLFunction");
```

## 它是如何工作的...

QML 旨在通过 C++代码轻松扩展。Qt QML 模块中的类使得可以从 C++加载和操作 QML 对象，而 QML 引擎与 Qt 的元对象系统的集成性质使得可以直接从 QML 调用 C++功能。要将一些 C++数据或功能提供给 QML，必须从 QObject 派生类中提供。

QML 对象类型可以从 C++中实例化和检查，以便访问它们的属性，调用它们的方法，并接收它们的信号通知。这是可能的，因为所有 QML 对象类型都是使用 QObject 派生类实现的，使得 QML 引擎能够通过 Qt 元对象系统动态加载和内省对象。


# 第二章：状态和动画

在本章中，我们将涵盖以下内容：

+   Qt 中的属性动画

+   使用缓动曲线控制属性动画

+   创建动画组

+   创建嵌套动画组

+   Qt 中的状态机

+   QML 中的状态、转换和动画

+   使用动画器动画小部件属性

+   精灵动画

# 介绍

Qt 提供了一种简单的方法来为继承`QObject`类的小部件或其他对象进行动画处理，通过其强大的动画框架。动画可以单独使用，也可以与状态机框架一起使用，该框架允许根据小部件的当前活动状态播放不同的动画。Qt 的动画框架还支持分组动画，允许您同时移动多个图形项，或者按顺序移动它们。

# Qt 中的属性动画

在这个例子中，我们将学习如何使用 Qt 的属性动画类来为我们的**图形用户界面**（**GUI**）元素添加动画效果，这是其强大的动画框架的一部分，它允许我们以最小的努力创建流畅的动画效果。

## 如何做到…

1.  首先，让我们创建一个新的 Qt 小部件应用程序项目。之后，用 Qt Designer 打开`mainwindow.ui`并在主窗口上放置一个按钮，如下所示：![如何做到…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_02_01.jpg)

1.  接下来，打开`mainwindow.cpp`并在源代码开头添加以下行代码：

```cpp
#include <QPropertyAnimation>
```

1.  之后，打开`mainwindow.cpp`并在构造函数中添加以下代码：

```cpp
QPropertyAnimation *animation = new QPropertyAnimation(ui->pushButton, "geometry");
animation->setDuration(10000);
animation->setStartValue(ui->pushButton->geometry());
animation->setEndValue(QRect(200, 200, 100, 50));
animation->start();
```

## 它是如何工作的...

通过 Qt 提供的属性动画类`QPropertyAnimation`类是通过 Qt 提供的一种常见方法来为 GUI 元素添加动画效果。这个类是动画框架的一部分，它利用 Qt 的定时器系统在给定的持续时间内更改 GUI 元素的属性。

我们在这里要做的是将按钮从一个位置动画到另一个位置，同时也随着动画过程放大按钮的大小。

通过在步骤 2 中在源代码中包含`QPropertyAnimation`头文件，我们将能够访问 Qt 提供的`QPropertyAnimation`类并利用其功能。

步骤 3 中的代码基本上创建了一个新的属性动画，并将其应用于我们刚刚在 Qt Designer 中创建的按钮。我们明确要求属性动画类更改按钮的`geometry`属性，并将其持续时间设置为 3,000 毫秒（3 秒）。

然后，动画的起始值设置为按钮的初始几何形状，因为显然我们希望它从我们最初在 Qt Designer 中放置按钮的位置开始。然后，结束值设置为我们希望它变成的值；在这种情况下，我们将按钮移动到 x:`200`，y:`200`的新位置，同时沿途改变其大小为宽度:`100`，高度:`50`。

之后，调用`animation->start()`来启动动画。

编译并运行项目，现在您应该看到按钮开始在主窗口上缓慢移动，同时逐渐扩大大小，直到达到目的地。您可以通过修改前面代码中的值来更改动画持续时间和目标位置和比例。使用 Qt 的属性动画系统来为 GUI 元素添加动画效果真的是如此简单！

## 还有更多...

Qt 为我们提供了几种不同的子系统来为我们的 GUI 创建动画，包括定时器、时间轴、动画框架、状态机框架和图形视图框架：

+   **定时器**：Qt 为我们提供了重复和单次定时器。当达到超时值时，将通过 Qt 的信号和槽机制触发事件回调函数。您可以利用定时器在给定的时间间隔内更改 GUI 元素的属性（颜色、位置、比例等），以创建动画效果。

+   **时间轴**：时间轴定期调用插槽以对 GUI 元素进行动画处理。它与重复定时器非常相似，但是当触发插槽时，时间轴会向插槽提供一个值来指示当前帧索引，以便您可以根据给定的值执行不同的操作（例如偏移到精灵表的不同位置）。

+   **动画框架**：动画框架通过允许对 GUI 元素的属性进行动画处理，使动画变得简单。动画是通过使用缓动曲线来控制的。缓动曲线描述了控制动画速度的函数，从而产生不同的加速和减速模式。Qt 支持的缓动曲线类型包括：线性、二次、三次、四次、正弦、指数、圆形和弹性。

+   **状态机框架**：Qt 为我们提供了用于创建和执行状态图的类，允许每个 GUI 元素在触发信号时从一个状态移动到另一个状态。状态机框架中的状态图是分层的，这意味着每个状态也可以嵌套在其他状态内部。

+   **图形视图框架**：图形视图框架是一个强大的图形引擎，用于可视化和与大量自定义的 2D 图形项进行交互。如果您是一名经验丰富的程序员，您可以使用图形视图框架手动绘制 GUI，并对其进行动画处理。

通过利用这里提到的所有强大功能，我们能够轻松创建直观现代的 GUI。在本章中，我们将探讨使用 Qt 对 GUI 元素进行动画处理的实际方法。

# 使用缓动曲线控制属性动画

在这个示例中，我们将学习如何通过利用缓动曲线使我们的动画更加有趣。我们仍然会使用先前的源代码，该源代码使用属性动画来对推按钮进行动画处理。

## 如何做...

1.  在调用`start()`函数之前，定义一个缓动曲线并将其添加到属性动画中：

```cpp
QPropertyAnimation *animation = new QPropertyAnimation(ui->pushButton, "geometry");
animation->setDuration(3000);
animation->setStartValue(ui->pushButton->geometry());
animation->setEndValue(QRect(200, 200, 100, 50));
QEasingCurve curve;
curve.setType(QEasingCurve::OutBounce);
animation->setEasingCurve(curve);
animation->start();
```

1.  调用`setLoopCount()`函数来设置要重复多少次循环：

```cpp
QPropertyAnimation *animation = new QPropertyAnimation(ui->pushButton, "geometry");
animation->setDuration(3000);
animation->setStartValue(ui->pushButton->geometry());
animation->setEndValue(QRect(200, 200, 100, 50));
QEasingCurve curve;
Curve.setType(EasingCurve::OutBounce);
animation->setEasingCurve(curve);
animation->setLoopCount(2);
animation->start();
```

1.  在应用缓动曲线到动画之前，调用`setAmplitude()`、`setOvershoot()`和`setPeriod()`：

```cpp
QEasingCurve curve;
curve.setType(QEasingCurve::OutBounce);
curve.setAmplitude(1.00);
curve.setOvershoot(1.70);
curve.setPeriod(0.30);
animation->setEasingCurve(curve);
animation->start();
```

## 它是如何工作的...

为了让缓动曲线控制动画，您只需要在调用`start()`函数之前定义一个缓动曲线并将其添加到属性动画中。您还可以尝试几种其他类型的缓动曲线，看看哪一种最适合您。以下是一个示例：

```cpp
animation->setEasingCurve(QEasingCurve::OutBounce);
```

如果您希望动画在播放完成后循环播放，可以调用`setLoopCount()`函数来设置要重复多少次循环，或者将值设置为`-1`以进行无限循环：

```cpp
animation->setLoopCount(-1);
```

在将缓动曲线应用到属性动画之前，您可以设置几个参数来完善缓动曲线。这些参数包括振幅、超调和周期：

+   **振幅**：振幅越高，动画的弹跳或弹簧效果就越强。

+   **超调**：由于阻尼效应，某些曲线函数将产生超调（超过其最终值）曲线。通过调整超调值，我们能够增加或减少这种效果。

+   **周期**：设置较小的周期值将使曲线具有较高的频率。较大的周期将使其具有较低的频率。

然而，这些参数并不适用于所有曲线类型。请参考 Qt 文档，了解哪个参数适用于哪种曲线类型。

## 还有更多...

虽然属性动画运行良好，但有时看到 GUI 元素以恒定速度进行动画处理会感到有些无聊。我们可以通过添加缓动曲线来控制运动使动画看起来更有趣。在 Qt 中有许多类型的缓动曲线可供使用，以下是其中一些：

![还有更多...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_02_02.jpg)

正如您从上图中看到的，每个缓动曲线产生不同的缓入和缓出效果。

### 注意

有关 Qt 中可用的缓动曲线的完整列表，请参阅 Qt 文档[`doc.qt.io/qt-5/qeasingcurve.html#Type-enum`](http://doc.qt.io/qt-5/qeasingcurve.html#Type-enum)。

# 创建动画组

在这个例子中，我们将学习如何使用动画组来管理组中包含的动画的状态。

## 操作方法...

1.  我们将使用之前的例子，但这次，我们将在主窗口中添加两个更多的按钮，如下所示：![操作方法...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_02_03.jpg)

1.  接下来，在主窗口的构造函数中为每个按钮定义动画：

```cpp
QPropertyAnimation *animation1 = new QPropertyAnimation(ui->pushButton, "geometry");
animation1->setDuration(3000);
animation1->setStartValue(ui->pushButton->geometry());
animation1->setEndValue(QRect(50, 200, 100, 50));

QPropertyAnimation *animation2 = new QPropertyAnimation(ui->pushButton_2, "geometry");
animation2->setDuration(3000);
animation2->setStartValue(ui->pushButton_2->geometry());
animation2->setEndValue(QRect(150, 200, 100, 50));

QPropertyAnimation *animation3 = new QPropertyAnimation(ui->pushButton_3, "geometry");
animation3->setDuration(3000);
animation3->setStartValue(ui->pushButton_3->geometry());
animation3->setEndValue(QRect(250, 200, 100, 50));
```

1.  之后，创建一个缓动曲线并将相同的曲线应用于所有三个动画：

```cpp
QEasingCurve curve;
curve.setType(QEasingCurve::OutBounce);
curve.setAmplitude(1.00);
curve.setOvershoot(1.70);
curve.setPeriod(0.30);

animation1->setEasingCurve(curve);
animation2->setEasingCurve(curve);
animation3->setEasingCurve(curve);
```

1.  一旦您将缓动曲线应用于所有三个动画，我们将创建一个动画组并将所有三个动画添加到组中：

```cpp
QParallelAnimationGroup *group = new QParallelAnimationGroup;group->addAnimation(animation1);
group->addAnimation(animation2);
group->addAnimation(animation3);
```

1.  从刚刚创建的动画组中调用`start()`函数：

```cpp
group->start();
```

## 工作原理...

由于我们现在使用动画组，我们不再从单独的动画中调用`start()`函数，而是从刚刚创建的动画组中调用`start()`函数。

如果现在编译并运行示例，您将看到所有三个按钮同时播放。这是因为我们使用了并行动画组。您可以将其替换为顺序动画组并再次运行示例：

```cpp
QSequentialAnimationGroup *group = new QSequentialAnimationGroup;
```

这次，一次只有一个按钮会播放其动画，而其他按钮将耐心等待他们的轮到。

优先级是根据首先添加到动画组中的动画来设置的。您可以通过简单地重新排列添加到组中的动画的顺序来更改动画顺序。例如，如果我们希望按钮 3 首先开始动画，然后是按钮 2，然后是按钮 1，代码将如下所示：

```cpp
group->addAnimation(animation3);
group->addAnimation(animation2);
group->addAnimation(animation1);
```

由于属性动画和动画组都是从`QAbstractAnimator`类继承的，这意味着您也可以将一个动画组添加到另一个动画组中，以形成一个更复杂的嵌套动画组。

## 还有更多...

Qt 允许我们创建多个动画并将它们分组成一个动画组。一个组通常负责管理其动画的状态（即，它决定何时开始、停止、恢复和暂停它们）。目前，Qt 提供了两种动画组类，`QParallelAnimationGroup`和`QSequentialAnimationGroup`：

+   `QParallelAnimationGroup`：顾名思义，并行动画组同时运行其组中的所有动画。当最持久的动画完成运行时，组被视为已完成。

+   `QSequentialAnimationGroup`：顺序动画组按顺序运行其动画，这意味着一次只运行一个动画，并且只有当前动画完成后才会播放下一个动画。

# 创建嵌套动画组

使用嵌套动画组的一个很好的例子是当您有几个并行动画组并且希望按顺序播放这些组时。

## 操作方法...

1.  我们将使用之前的示例中的 UI，并在主窗口中添加几个更多的按钮，如下所示：![操作方法...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_02_04.jpg)

1.  首先，为所有按钮创建动画，然后创建一个缓动曲线并将其应用于所有动画：

```cpp
QPropertyAnimation *animation1 = new QPropertyAnimation(ui->pushButton, "geometry");
animation1->setDuration(3000);
animation1->setStartValue(ui->pushButton->geometry());
animation1->setEndValue(QRect(50, 50, 100, 50));

QPropertyAnimation *animation2 = new QPropertyAnimation(ui->pushButton_2, "geometry");
animation2->setDuration(3000);
animation2->setStartValue(ui->pushButton_2->geometry());
animation2->setEndValue(QRect(150, 50, 100, 50));

QPropertyAnimation *animation3 = new QPropertyAnimation(ui->pushButton_3, "geometry");
animation3->setDuration(3000);
animation3->setStartValue(ui->pushButton_3->geometry());
animation3->setEndValue(QRect(250, 50, 100, 50));

QPropertyAnimation *animation4 = new QPropertyAnimation(ui->pushButton_4, "geometry");
animation4->setDuration(3000);
animation4->setStartValue(ui->pushButton_4->geometry());
animation4->setEndValue(QRect(50, 200, 100, 50));

QPropertyAnimation *animation5 = new QPropertyAnimation(ui->pushButton_5, "geometry");
animation5->setDuration(3000);
animation5->setStartValue(ui->pushButton_5->geometry());
animation5->setEndValue(QRect(150, 200, 100, 50));

QPropertyAnimation *animation6 = new QPropertyAnimation(ui->pushButton_6, "geometry");
animation6->setDuration(3000);
animation6->setStartValue(ui->pushButton_6->geometry());
animation6->setEndValue(QRect(250, 200, 100, 50));

QEasingCurve curve;
curve.setType(QEasingCurve::OutBounce);
curve.setAmplitude(1.00);
curve.setOvershoot(1.70);
curve.setPeriod(0.30);

animation1->setEasingCurve(curve);
animation2->setEasingCurve(curve);
animation3->setEasingCurve(curve);
animation4->setEasingCurve(curve);
animation5->setEasingCurve(curve);
animation6->setEasingCurve(curve);
```

1.  创建两个动画组，一个用于上列按钮，另一个用于下列按钮：

```cpp
QParallelAnimationGroup *group1 = new QParallelAnimationGroup;
group1->addAnimation(animation1);
group1->addAnimation(animation2);
group1->addAnimation(animation3);

QParallelAnimationGroup *group2 = new QParallelAnimationGroup;
group2->addAnimation(animation4);
group2->addAnimation(animation5);
group2->addAnimation(animation6);
```

1.  我们将创建另一个动画组，用于存储我们之前创建的两个动画组：

```cpp
QSequentialAnimationGroup *groupAll = new QSequentialAnimationGroup;
groupAll->addAnimation(group1);
groupAll->addAnimation(group2);
groupAll->start();
```

## 工作原理...

我们在这里要做的是先播放上列按钮的动画，然后是下列按钮的动画。

由于两个动画组都是并行动画组，当调用`start()`函数时，属于各自组的按钮将同时进行动画。

这一次，然而，这个组是一个顺序动画组，这意味着一次只有一个并行动画组会被播放，当第一个完成时，另一个会接着播放。

动画组是一个非常方便的系统，它允许我们用简单的编码创建非常复杂的 GUI 动画。Qt 会为我们处理困难的部分，所以我们不必自己处理。

# Qt 中的状态机

状态机可以用于许多目的，但在本章中，我们只会涵盖与动画相关的主题。

## 如何做...

1.  首先，我们将为我们的示例程序设置一个新的用户界面，它看起来像这样：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_02_06.jpg)

1.  接下来，我们将在源代码中包含一些头文件：

```cpp
#include <QStateMachine>
#include <QPropertyAnimation>
#include <QEventTransition>
```

1.  在我们的主窗口构造函数中，添加以下代码来创建一个新的状态机和两个状态，我们稍后会使用它们：

```cpp
QStateMachine *machine = new QStateMachine(this);
QState *s1 = new QState();
QState *s2 = new QState();
```

1.  然后，我们将定义在每个状态中应该做什么，这种情况下将是更改标签的文本，以及按钮的位置和大小：

```cpp
QState *s1 = new QState();
s1->assignProperty(ui->stateLabel, "text", "Current state: 1");
s1->assignProperty(ui->pushButton, "geometry", QRect(50, 200, 100, 50));

QState *s2 = new QState();
s2->assignProperty(ui->stateLabel, "text", "Current state: 2");
s2->assignProperty(ui->pushButton, "geometry", QRect(200, 50, 140, 100));

```

1.  完成后，让我们通过向源代码添加事件转换类来继续：

```cpp
QEventTransition *t1 = new QEventTransition(ui->changeState, QEvent::MouseButtonPress);
t1->setTargetState(s2);
s1->addTransition(t1);

QEventTransition *t2 = new QEventTransition(ui->changeState, QEvent::MouseButtonPress);
T2->setTargetState(s1);
s2->addTransition(t2);
```

1.  接下来，将我们刚刚创建的所有状态添加到状态机中，并将状态 1 定义为初始状态。然后，调用`machine->start()`来启动状态机运行：

```cpp
machine->addState(s1);
machine->addState(s2);

machine->setInitialState(s1);
machine->start();
```

1.  如果你现在运行示例程序，你会注意到一切都运行正常，除了按钮没有经历平滑的过渡，它只是立即跳到我们之前设置的位置和大小。这是因为我们没有使用属性动画来创建平滑的过渡。

1.  返回到事件转换步骤，添加以下代码行：

```cpp
QEventTransition *t1 = new QEventTransition(ui->changeState, QEvent::MouseButtonPress);
t1->setTargetState(s2);
t1->addAnimation(new QPropertyAnimation(ui->pushButton, "geometry"));
s1->addTransition(t1);

QEventTransition *t2 = new QEventTransition(ui->changeState, QEvent::MouseButtonPress);
t2->setTargetState(s1);
t2->addAnimation(new QPropertyAnimation(ui->pushButton, "geometry"));
s2->addTransition(t2);
```

1.  你也可以为动画添加一个缓动曲线，使其看起来更有趣：

```cpp
QPropertyAnimation *animation = new QPropertyAnimation(ui->pushButton, "geometry");
animation->setEasingCurve(QEasingCurve::OutBounce);
QEventTransition *t1 = new QEventTransition(ui->changeState, QEvent::MouseButtonPress);
t1->setTargetState(s2);
t1->addAnimation(animation);
s1->addTransition(t1);

QEventTransition *t2 = new QEventTransition(ui->changeState, QEvent::MouseButtonPress);
t2->setTargetState(s1);
t2->addAnimation(animation);
s2->addTransition(t2);
```

## 它是如何工作的...

主窗口布局上有两个按钮和一个标签。左上角的按钮在按下时将触发状态更改，而右上角的标签将更改其文本以显示我们当前处于哪个状态，并且下面的按钮将根据当前状态进行动画。

`QEventTransition`类定义了触发一个状态到另一个状态的转换。

在我们的例子中，当点击`ui->changeState`按钮（左上角的按钮）时，我们希望状态从状态 1 变为状态 2。之后，当再次按下相同的按钮时，我们还希望从状态 2 变回状态 1。这可以通过创建另一个事件转换类并将目标状态设置回状态 1 来实现。然后，将这些转换添加到它们各自的状态中。

我们告诉 Qt 使用属性动画类来平滑地插值属性到目标值，而不是直接将属性直接分配给小部件。就是这么简单！

不需要设置起始值和结束值，因为我们已经调用了`assignProperty()`函数，它已经自动分配了结束值。

## 还有更多...

Qt 中的状态机框架提供了用于创建和执行状态图的类。Qt 的事件系统用于驱动状态机，状态之间的转换可以通过使用信号来触发，然后在另一端的槽将被信号调用来执行一个动作，比如播放一个动画。

一旦你理解了状态机的基础知识，你也可以用它们来做其他事情。状态机框架中的状态图是分层的。就像前一节中的动画组一样，状态也可以嵌套在其他状态中：

![还有更多...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_02_05.jpg)

# QML 中的状态、转换和动画

如果你更喜欢使用 QML 而不是 C++，Qt 还提供了类似的功能在 Qt Quick 中，允许你用最少的代码轻松地为 GUI 元素添加动画。在这个例子中，我们将学习如何用 QML 实现这一点。

## 如何做...

1.  首先，我们将创建一个新的**Qt Quick Application**项目，并设置我们的用户界面如下：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_02_07.jpg)

1.  这是我的`main.qml`文件的样子：

```cpp
import QtQuick 2.3
import QtQuick.Window 2.2

Window {
  visible: true
  width: 480;
  height: 320;

  Rectangle {
    id: background;
    anchors.fill: parent;
    color: "blue";
  }

  Text {
    text: qsTr("Hello World");
    anchors.centerIn: parent;
    color: "white";
    font.pointSize: 15;
  }
}
```

1.  将颜色动画添加到`Rectangle`对象中：

```cpp
Rectangle {
  id: background;
  anchors.fill: parent;
  color: "blue";
  SequentialAnimation on color
  {
    ColorAnimation { to: "yellow"; duration: 1000 }
    ColorAnimation { to: "red"; duration: 1000 }
    ColorAnimation { to: "blue"; duration: 1000 }
    loops: Animation.Infinite;
  }
}
```

1.  然后，将数字动画添加到文本对象中：

```cpp
Text {
  text: qsTr("Hello World");
  anchors.centerIn: parent;
  color: "white";
  font.pointSize: 15;
  SequentialAnimation on opacity {
 NumberAnimation { to: 0.0; duration: 200}
 NumberAnimation { to: 1.0; duration: 200}
 loops: Animation.Infinite;
 }
}
```

1.  接下来，为其添加另一个数字动画：

```cpp
Text {
  text: qsTr("Hello World");
  anchors.centerIn: parent;
  color: "white";
  font.pointSize: 15;
  SequentialAnimation on opacity {
    NumberAnimation { to: 0.0; duration: 200}
    NumberAnimation { to: 1.0; duration: 200}
    loops: Animation.Infinite;
  }
 NumberAnimation on rotation {
 from: 0;
 to: 360;
 duration: 2000;
 loops: Animation.Infinite;
 }
}
```

1.  定义两种状态，一种称为`PRESSED`状态，另一种称为`RELEASED`状态。然后，将默认状态设置为`RELEASED`：

```cpp
Rectangle {
  id: background;
  anchors.fill: parent;

 state: "RELEASED";
 states: [
 State {
 name: "PRESSED"
 PropertyChanges { target: background; color: "blue"}
 },
 State {
 name: "RELEASED"
 PropertyChanges { target: background; color: "red"}
 }
 ]
}
```

1.  之后，在`Rectangle`对象内创建一个鼠标区域，以便我们可以单击它：

```cpp
MouseArea {
  anchors.fill: parent;
  onPressed: background.state = "PRESSED";
  onReleased: background.state = "RELEASED";
}
```

1.  给`Rectangle`对象添加一些过渡效果：

```cpp
transitions: [
  Transition {
    from: "PRESSED"
    to: "RELEASED"
    ColorAnimation { target: background; duration: 200}
  },
  Transition {
    from: "RELEASED"
    to: "PRESSED"
    ColorAnimation { target: background; duration: 200}
  }
]
```

## 它是如何工作的...

主窗口由一个蓝色矩形和静态文本组成，上面写着`Hello World`。

我们希望背景颜色在循环中从蓝色变为黄色，然后变为红色，最后再变回蓝色。这可以通过在 QML 中使用颜色动画类型轻松实现。

在步骤 3 中，我们基本上是在`Rectangle`对象内创建了一个顺序动画组，然后在组内创建了三个不同的颜色动画，这些动画将每 1000 毫秒（1 秒）改变对象的颜色。我们还将动画设置为无限循环。

在步骤 4 中，我们希望使用数字动画来动画化静态文本的 alpha 值。我们在`Text`对象内创建了另一个顺序动画组，并创建了两个数字动画，以将 alpha 值从 0 动画到 1，然后再返回。然后，我们将动画设置为无限循环。

然后在第 5 步中，我们通过向其添加另一个数字动画来旋转`Hello World`文本。

在第 6 步中，我们希望在单击时使`Rectangle`对象从一种颜色变为另一种颜色。当鼠标释放时，`Rectangle`对象将恢复到其初始颜色。为了实现这一点，首先我们需要定义两种状态，一种称为`PRESSED`状态，另一种称为`RELEASED`状态。然后，我们将默认状态设置为`RELEASED`。

现在，当您编译并运行示例时，背景在按下时会立即变为蓝色，当释放鼠标时会变回红色。这很好用，我们可以通过给颜色切换时添加一些过渡效果来进一步增强它。这可以通过向`Rectangle`对象添加过渡效果轻松实现。

## 还有更多…

在 QML 中，有八种不同类型的属性动画可供使用：

+   **锚点动画**：动画化锚点值的变化

+   **颜色动画**：动画化颜色值的变化

+   **数字动画**：动画化 qreal 类型值的变化

+   **父动画**：动画化父级值的变化

+   **路径动画**：沿路径动画化项目

+   **属性动画**：动画化属性值的变化

+   **旋转动画**：动画化旋转值的变化

+   **Vector3d 动画**：动画化 QVector3d 值的变化

就像 C++版本一样，这些动画也可以在动画组中组合在一起，以便按顺序或并行播放动画。您还可以使用缓动曲线来控制动画，并使用状态机确定何时播放这些动画，就像我们在上一节中所做的那样。

# 使用动画器动画化小部件属性

在本教程中，我们将学习如何使用 QML 提供的动画器功能来动画化 GUI 小部件的属性。

## 如何做…

1.  创建一个矩形对象，并为其添加一个比例动画器：

```cpp
Rectangle {
  id: myBox;
  width: 50;
  height: 50;
  anchors.horizontalCenter: parent.horizontalCenter;
  anchors.verticalCenter: parent.verticalCenter;
  color: "blue";

  ScaleAnimator {
    target: myBox;
    from: 5;
    to: 1;
    duration: 2000;
    running: true;
  }
}
```

1.  添加一个旋转动画器，并将运行值设置为并行动画组中，但不是任何单独的动画器中。

```cpp
ParallelAnimation {
  ScaleAnimator {
    target: myBox;
    from: 5;
    to: 1;
    duration: 2000;
  }
  RotationAnimator {
    target: myBox;
    from: 0;
    to: 360;
    duration: 1000;
  }
  running: true;
}
```

1.  为比例动画器添加一个缓动曲线：

```cpp
ScaleAnimator {
  target: myBox;
  from: 5;
  to: 1;
  duration: 2000;
  easing.type: Easing.InOutElastic;
 easing.amplitude: 2.0;
 asing.period: 1.5;
  running: true;
}
```

## 它是如何工作的...

动画器类型可以像任何其他动画类型一样使用。我们希望在 2000 毫秒（2 秒）内将矩形从大小`5`缩放到大小`1`。

我们创建了一个蓝色的`Rectangle`对象，并为其添加了一个比例动画器。我们将初始值设置为`5`，最终值设置为`1`。然后，我们将动画持续时间设置为`2000`，并将运行值设置为`true`，这样程序启动时就会播放它。

就像动画类型一样，动画器也可以放入组中（即并行动画组或顺序动画组）。动画组也将被 QtQuick 视为动画器，并在可能的情况下在场景图的渲染线程上运行。

在第 2 步中，我们想将两个不同的动画器分组到一个并行动画组中，以便它们同时运行。

我们将保留之前创建的缩放动画器，并向`Rectangle`对象添加另一个旋转动画器。这次，在并行动画组中设置运行值，而不是在任何单独的动画器中设置。

就像 C++版本一样，QML 也支持缓动曲线，它们可以轻松应用于任何动画或动画器类型。

QML 中有一种叫做动画器的东西，它与普通动画类型类似但又不同。动画器类型是一种特殊类型的动画，它直接在 Qt Quick 的场景图上运行，而不是像常规动画类型那样在 QML 对象和它们的属性上运行。

QML 属性的值将在动画完成后更新。然而，在动画运行时，属性不会被更新。使用动画器类型的好处是性能稍微更好，因为它不在 UI 线程上运行，而是直接在场景图的渲染线程上运行。

# 精灵动画

在这个例子中，我们将学习如何在 QML 中创建精灵动画。

## 如何做…

1.  首先，我们需要将精灵表添加到 Qt 的资源系统中，以便在程序中使用。打开`qml.qrc`，点击**添加** | **添加文件**按钮。选择精灵表图像并按下*Ctrl* + *S*保存资源文件。

1.  之后，在`main.qml`中创建一个新的空窗口：

```cpp
import QtQuick 2.3
import QtQuick.Window 2.2

Window {
  visible: true
  width: 420
  height: 380
  Rectangle {
    anchors.fill: parent
    color: "white"
  }
}
```

1.  完成后，我们将在 QML 中开始创建一个`AnimatedSprite`对象：

```cpp
import QtQuick 2.3
import QtQuick.Window 2.2

Window {
  visible: true;
  width: 420;
  height: 380;
  Rectangle {
    anchors.fill: parent;
    color: "white";
  }

 AnimatedSprite {
 id: sprite;
 width: 128;
 height: 128;
 anchors.centerIn: parent;
 source: "qrc:///horse_1.png";
 frameCount: 11;
 frameWidth: 128;
 frameHeight: 128;
 frameRate: 25;
 loops: Animation.Infinite;
 running: true;
 }
}
```

1.  在窗口中添加一个鼠标区域并检查`onClicked`事件：

```cpp
MouseArea {
  anchors.fill: parent;
  onClicked: {
    if (sprite.paused)
      sprite.resume();
    else
      sprite.pause();
  }
}
```

1.  如果现在编译和运行示例程序，你会看到一个小马在窗口中间奔跑。多有趣啊！如何做…

1.  接下来，我们想尝试做一些酷炫的事情。我们将让马在窗口中奔跑，并在播放奔跑动画的同时无限循环！

首先，我们需要从 QML 中删除`anchors.centerIn:` parent，并用`x`和`y`值替换它：

```cpp
AnimatedSprite {
  id: sprite;
  width: 128;
  height: 128;
  x: -128;
  y: parent.height / 2;
  source: "qrc:///horse_1.png";
  frameCount: 11;
  frameWidth: 128;
  frameHeight: 128;
  frameRate: 25;
  loops: Animation.Infinite;
  running: true;
}
```

1.  之后，向精灵对象添加一个数字动画，并设置其属性如下：

```cpp
NumberAnimation {
  target: sprite;
  property: "x";
  from: -128;
  to: 512;
  duration: 3000;
  loops: Animation.Infinite;
  running: true;
}
```

1.  现在编译和运行示例程序，你会看到小马疯狂地在窗口中奔跑！

## 工作原理…

在这个示例中，我们将动画精灵对象放在窗口中间，并将其图像源设置为刚刚添加到项目资源中的精灵表。

然后，我们数了一下属于奔跑动画的精灵表中有多少帧，这里是 11 帧。我们还告诉 Qt 每一帧动画的尺寸，这里是 128 x 128。之后，我们将帧速率设置为`25`以获得合理的速度，然后将其设置为无限循环。然后我们将奔跑值设置为`true`，这样动画在程序开始运行时将默认播放。

然后在第 4 步，我们希望能够通过点击窗口来暂停动画并恢复它。当点击鼠标区域时，我们只需检查精灵当前是否暂停。如果精灵动画已经暂停，那么恢复动画；否则，暂停动画。

在第 6 步，我们用`x`和`y`值替换了`anchors.centerIn`，这样动画精灵对象就不会锚定在窗口中心，这样就可以移动了。

然后，我们在动画精灵中创建了一个数字动画，以动画化其`x`属性。我们将起始值设置为窗口左侧的某个位置，将结束值设置为窗口右侧的某个位置。之后，我们将持续时间设置为 3,000 毫秒（3 秒），并使其无限循环。

最后，我们还将运行值设置为`true`，这样当程序开始运行时，它将默认播放动画。

## 还有更多...

精灵动画被广泛应用，尤其在游戏开发中。精灵用于角色动画、粒子动画，甚至 GUI 动画。精灵表包含许多图像组合成一个，然后可以被切割并逐一显示在屏幕上。从精灵表中不同图像（或精灵）之间的过渡创造了动画的错觉，我们通常称之为精灵动画。在 QML 中，可以很容易地使用`AnimatedSprite`类型实现精灵动画。

### 注意

在这个示例程序中，我使用了由 bluecarrot16 在 CC-BY 3.0 / GPL 3.0 / GPL 2.0 / OGA-BY 3.0 许可下创建的免费开源图像。该图像可以在[`opengameart.org/content/lpc-horse`](http://opengameart.org/content/lpc-horse)上合法获取。


# 第三章：QPainter 和 2D 图形

在本章中，我们将涵盖以下内容：

+   在屏幕上绘制基本形状

+   将形状导出为 SVG 文件

+   坐标变换

+   在屏幕上显示图像

+   将图像效果应用于图形

+   创建基本绘画程序

+   QML 中的 2D 画布

# 简介

在本章中，我们将学习如何使用 Qt 在屏幕上渲染 2D 图形。在内部，Qt 使用一个低级别的类称为`QPainter`来在主窗口上渲染其小部件。Qt 允许我们访问和使用`QPainter`类来绘制矢量图形、文本、2D 图像，甚至 3D 图形。您可以利用`QPainter`类来创建自定义小部件，或者创建依赖于计算机图形渲染的程序，如视频游戏、照片编辑器、3D 建模工具等。

# 在屏幕上绘制基本形状

在本节中，我们将学习如何使用`QPainter`类在主窗口上绘制简单的矢量形状（线条、矩形、圆形等）并显示文本。我们还将学习如何使用`QPen`类更改矢量形状的绘制样式。

## 如何做...

首先，让我们创建一个新的**Qt Widgets 应用程序**项目：

1.  打开`mainwindow.ui`并删除菜单栏、主工具栏和状态栏，以便获得一个干净的空白主窗口。右键单击栏小部件，从弹出菜单中选择**删除菜单栏**：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_01.jpg)

1.  然后，打开`mainwindow.h`并添加以下代码以包含`QPainter`头文件：

```cpp
#include <QMainWindow>
#include <QPainter>

```

1.  然后，在类析构函数下面声明`paintEvent()`事件处理程序：

```cpp
public:
explicit MainWindow(QWidget *parent = 0);
~MainWindow();
virtual void paintEvent(QPaintEvent *event);

```

1.  接下来，打开`mainwindow.cpp`并定义`paintEvent()`事件处理程序：

```cpp
void MainWindow::paintEvent(QPaintEvent *event)
{
}
```

1.  之后，我们将使用`paintEvent()`事件处理程序内的`QPainter`类向屏幕添加文本。我们在屏幕上的位置`(20, 30)`绘制文本之前设置文本字体设置：

```cpp
QPainter textPainter(this);
textPainter.setFont(QFont("Times", 14, QFont::Bold));
textPainter.drawText(QPoint(20, 30), "Testing");
```

1.  然后，我们将绘制一条从`(50, 60)`开始到`(100, 100)`结束的直线：

```cpp
QPainter linePainter(this);
linePainter.drawLine(QPoint(50, 60), QPoint(100, 100));
```

1.  我们还可以通过使用`QPainter`类调用`drawRect()`函数轻松绘制一个矩形形状。不过这次，在绘制之前我们还会为形状应用一个背景图案：

```cpp
QPainter rectPainter(this);
rectPainter.setBrush(Qt::BDiagPattern);
rectPainter.drawRect(QRect(40, 120, 80, 30));
```

1.  接下来，声明一个`QPen`类，将其颜色设置为`red`，将其绘制样式设置为`Qt::DashDotLine`。然后，将`QPen`类应用于`QPainter`并在`(80, 200)`处绘制一个水平半径为`50`，垂直半径为`20`的椭圆形：

```cpp
QPen ellipsePen;
ellipsePen.setColor(Qt::red);
ellipsePen.setStyle(Qt::DashDotLine);

QPainter ellipsePainter(this);
ellipsePainter.setPen(ellipsePen);
ellipsePainter.drawEllipse(QPoint(80, 200), 50, 20);
```

1.  我们还可以使用`QPainterPath`类来定义形状，然后将其传递给`QPainter`类进行渲染：

```cpp
QPainterPath rectPath;
rectPath.addRect(QRect(150, 20, 100, 50));

QPainter pathPainter(this);
pathPainter.setPen(QPen(Qt::red, 1, Qt::DashDotLine, Qt::FlatCap, Qt::MiterJoin));
pathPainter.setBrush(Qt::yellow);
pathPainter.drawPath(rectPath);
```

1.  您还可以使用`QPainterPath`绘制任何其他形状，比如椭圆：

```cpp
QPainterPath ellipsePath;
ellipsePath.addEllipse(QPoint(200, 120), 50, 20);

QPainter ellipsePathPainter(this);
ellipsePathPainter.setPen(QPen(QColor(79, 106, 25), 5, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
ellipsePathPainter.setBrush(QColor(122, 163, 39));
ellipsePathPainter.drawPath(ellipsePath);
```

1.  `QPainter`也可以用来将图像文件绘制到屏幕上。在下面的示例中，我们加载一个名为`tux.png`的图像文件，并在屏幕上的位置`(100, 150)`绘制它：

```cpp
QImage image;
image.load("tux.png");

QPainter imagePainter(this);
imagePainter.drawImage(QPoint(100, 150), image);
```

1.  最终结果应该看起来像这样：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_02.jpg)

## 工作原理...

如果您想使用`QPainter`在屏幕上绘制一些东西，基本上您只需要告诉它应该绘制什么类型的图形（文本、矢量形状、图像、多边形等），以及其位置和大小。

QPen 确定了图形的轮廓样式，如颜色、线宽、线型（实线、虚线、点线等）、端点样式、连接样式等。

另一方面，`QBrush`设置了图形的背景样式，如背景颜色、图案（纯色、渐变、密集刷、交叉对角线等）和像素图。

在调用绘制函数（`drawLine()`、`drawRect()`、`drawEllipse()`等）之前应设置图形的选项。

如果你的图形不显示在屏幕上，并且在 Qt Creator 的应用程序输出窗口中看到警告，比如`QPainter::setPen: Painter not active`和`QPainter::setBrush: Painter not active`，这意味着`QPainter`类当前不活动，你的程序不会触发它的绘制事件。要解决这个问题，将主窗口设置为`QPainter`类的父类。通常，如果你在`mainwindow.cpp`文件中编写代码，初始化`QPainter`时只需要在括号中放入`this`。例如：

```cpp
QPainter linePainter(this);
```

`QImage`可以从计算机目录和程序资源中加载图像。

## 还有更多…

把`QPainter`想象成一个带着笔和空画布的机器人。你只需要告诉机器人应该画什么类型的形状以及它在画布上的位置，然后机器人会根据你的描述完成工作。为了让你的生活更轻松，`QPainter`类还提供了许多函数，比如`drawArc()`、`drawEllipse()`、`drawLine()`、`drawRect()`、`drawPie()`等，让你可以轻松地渲染预定义的形状。

在 Qt 中，所有的窗口部件类（包括主窗口）都有一个名为`QWidget::paintEvent()`的事件处理程序。每当操作系统认为主窗口应该重新绘制其窗口部件时，这个事件处理程序就会被触发。许多事情可能导致这个决定，比如主窗口被缩放，窗口部件改变其状态（即，按钮被按下），或者在代码中手动调用`repaint()`或`update()`等函数。不同的操作系统在决定是否触发相同条件下的更新事件时可能会有不同的行为。如果你正在制作一个需要连续和一致的图形更新的程序，可以使用定时器手动调用`repaint()`或`update()`。

# 将形状导出为 SVG 文件

**可伸缩矢量图形**（**SVG**）是一种基于 XML 的语言，用于描述二维矢量图形。Qt 提供了保存矢量形状到 SVG 文件的类。这个功能可以用来创建一个简单的矢量图形编辑器，类似于 Adobe Illustrator 和 Inkscape。

在下一个示例中，我们将继续使用前一个示例中的相同项目文件。

## 如何做…

让我们学习如何创建一个简单的程序，在屏幕上显示 SVG 图形：

1.  首先，通过右键单击层次结构窗口上的主窗口部件，并从弹出菜单中选择**创建菜单栏**选项来创建一个菜单栏。之后，在菜单栏中添加一个**文件**选项，然后在其下方添加一个**另存为 SVG**操作：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_03.jpg)

1.  之后，在 Qt Creator 窗口底部的**Action Editor**窗口中会看到一个名为`actionSave_as_SVG`的项目。右键单击该项目，从弹出菜单中选择**转到槽…**。现在会出现一个窗口，其中列出了特定操作可用的槽。选择名为`triggered()`的默认信号，然后点击**OK**按钮：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_04.jpg)

1.  点击**OK**按钮后，Qt Creator 将切换到脚本编辑器。你会发现一个名为`on_actionSave_as_SVG_triggered()`的槽已经自动添加到你的主窗口类中。在你的`mainwindow.h`的底部，你会看到类似这样的内容：

```cpp
void MainWindow::on_actionSave_as_SVG_triggered()
{
}
```

当你从菜单栏点击**另存为 SVG**选项时，将调用上述函数。我们将在这个函数中编写代码，将所有矢量图形保存到一个 SVG 文件中。

1.  为了做到这一点，我们首先需要在源文件顶部包含一个名为`QSvgGenerator`的类头文件。这个头文件非常重要，因为它用于生成 SVG 文件。然后，我们还需要包含另一个名为`QFileDialog`的类头文件，它将用于打开保存对话框：

```cpp
#include <QtSvg/QSvgGenerator>
#include <QFileDialog>
```

1.  我们还需要在项目文件中添加 SVG 模块，如下所示：

```cpp
QT += core gui svg
```

1.  然后，在`mainwindow.h`中创建一个名为`paintAll()`的新函数，如下所示：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

  virtual void paintEvent(QPaintEvent *event);
  void paintAll(QSvgGenerator *generator = 0);
```

1.  之后，在`mainwindow.cpp`中，将所有代码从`paintEvent()`移动到`paintAll()`函数中。然后，用单一统一的`QPainter`替换所有单独的`QPainter`对象来绘制所有图形。还要在绘制任何内容之前调用`begin()`函数，并在完成绘制后调用`end()`函数。代码应该如下所示：

```cpp
void MainWindow::paintAll(QSvgGenerator *generator)
{
  QPainter painter;

  if (engine)
    painter.begin(engine);
  else
    painter.begin(this);

  painter.setFont(QFont("Times", 14, QFont::Bold));
  painter.drawText(QPoint(20, 30), "Testing");

  painter.drawLine(QPoint(50, 60), QPoint(100, 100));

  painter.setBrush(Qt::BDiagPattern);
  painter.drawRect(QRect(40, 120, 80, 30));

  QPen ellipsePen;
  ellipsePen.setColor(Qt::red);
  ellipsePen.setStyle(Qt::DashDotLine);

  painter.setPen(ellipsePen);
  painter.drawEllipse(QPoint(80, 200), 50, 20);

  QPainterPath rectPath;
  rectPath.addRect(QRect(150, 20, 100, 50));

  painter.setPen(QPen(Qt::red, 1, Qt::DashDotLine, Qt::FlatCap, Qt::MiterJoin));
  painter.setBrush(Qt::yellow);
  painter.drawPath(rectPath);

  QPainterPath ellipsePath;
  ellipsePath.addEllipse(QPoint(200, 120), 50, 20);

  painter.setPen(QPen(QColor(79, 106, 25), 5, Qt::SolidLine, Qt::FlatCap, Qt::MiterJoin));
  painter.setBrush(QColor(122, 163, 39));
  painter.drawPath(ellipsePath);

  QImage image;
  image.load("tux.png");

  painter.drawImage(QPoint(100, 150), image);

  painter.end();
}
```

1.  由于我们已将所有代码从`paintEvent()`移动到`paintAll()`，因此现在我们应该在`paintEvent()`中调用`paintAll()`函数，如下所示：

```cpp
void MainWindow::paintEvent(QPaintEvent *event)
{
 paintAll();
}
```

1.  然后，我们将编写将图形导出到 SVG 文件的代码。代码将写在名为`on_actionSave_as_SVG_triggered()`的槽函数中，该函数由 Qt 生成。我们首先调用保存文件对话框，并从用户那里获取所需文件名的目录路径：

```cpp
void MainWindow::on_actionSave_as_SVG_triggered()
{
  QString filePath = QFileDialog::getSaveFileName(this, "Save SVG", "", "SVG files (*.svg)");

  if (filePath == "")
    return;
}
```

1.  之后，创建一个`QSvgGenerator`对象，并通过将`QSvgGenerator`对象传递给`paintAll()`函数将图形保存到 SVG 文件中：

```cpp
void MainWindow::on_actionSave_as_SVG_triggered()
{
  QString filePath = QFileDialog::getSaveFileName(this, "Save SVG", "", "SVG files (*.svg)");

  if (filePath == "")
    return;

 QSvgGenerator generator;
 generator.setFileName(filePath);
 generator.setSize(QSize(this->width(), this->height()));
 generator.setViewBox(QRect(0, 0, this->width(), this->height()));
 generator.setTitle("SVG Example");
 generator.setDescription("This SVG file is generated by Qt.");

 paintAll(&generator);
}
```

1.  现在编译并运行程序，您应该能够通过转到**文件** | **另存为 SVG**来导出图形：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_05.jpg)

## 工作原理...

默认情况下，`QPainter`将使用其父对象的绘图引擎来绘制分配给它的图形。如果您没有为`QPainter`分配任何父对象，可以手动为其分配绘图引擎，这就是我们在这个例子中所做的。

我们将代码放入`paintAll()`的原因是因为我们希望将相同的代码用于两个不同的目的：用于在窗口上显示图形和将图形导出到 SVG 文件。请注意`paintAll()`函数中`generator`变量的默认值设置为`0`，这意味着除非指定，否则不需要`QSvgGenerator`对象来运行该函数。稍后，在`paintAll()`函数中，我们检查`generator`对象是否存在。如果存在，就像这样将其用作绘图引擎：

```cpp
if (engine)
 painter.begin(engine);
else
  painter.begin(this);
```

否则，将主窗口传递给`begin()`函数（因为我们正在`mainwindow.cpp`中编写代码，所以可以直接使用`this`来引用主窗口的指针），这样它将使用主窗口本身的绘图引擎，这意味着图形将绘制在主窗口的表面上。

在这个例子中，需要使用单个`QPainter`对象将图形保存到 SVG 文件中。如果使用多个`QPainter`对象，生成的 SVG 文件将包含多个 XML 头定义，因此任何图形编辑软件都会将文件视为无效。

`QFileDialog::getSaveFileName()`将为用户打开本机保存文件对话框，以选择保存目录并设置所需的文件名。一旦用户完成，完整路径将作为字符串返回，我们将能够将该信息传递给`QSvgGenerator`对象以导出图形。

请注意，在上一张截图中，SVG 文件中的企鹅已被裁剪。这是因为 SVG 的画布大小设置为跟随主窗口的大小。为了帮助可怜的企鹅找回身体，导出 SVG 文件之前将窗口放大。

## 还有更多...

**可缩放矢量图形**（**SVG**）以 XML 格式定义图形。由于它是矢量图形，所以 SVG 图形在缩放或调整大小时不会失去任何质量。

SVG 允许三种类型的图形对象：矢量图形、光栅图形和文本。包括 PNG 和 JPEG 光栅图像在内的图形对象可以分组、样式化、变换和合成到先前渲染的对象中。

您可以在[`www.w3.org/TR/SVG`](https://www.w3.org/TR/SVG)上查看 SVG 图形的完整规范。

# 坐标变换

在这个例子中，我们将学习如何使用坐标变换和定时器来创建实时时钟显示。

## 如何做...

要创建我们的第一个图形时钟显示，请按照以下步骤进行：

1.  首先，创建一个新的**Qt Widgets Application**项目。然后，打开`mainwindow.ui`并移除菜单栏、工具栏和状态栏。

1.  在此之后，打开`mainwindow.h`并包含以下头文件：

```cpp
#include <QTime>
#include <QTimer>
#include <QPainter>
```

1.  然后，声明`paintEvent()`函数，如下所示：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

virtual void paintEvent(QPaintEvent *event);

```

1.  在`mainwindow.cpp`中，创建三个数组来存储时针、分针和秒针的形状，其中每个数组包含三组坐标：

```cpp
void MainWindow::paintEvent(QPaintEvent *event)
{
 static const QPoint hourHand[3] =
 {
 QPoint(4, 4),
 QPoint(-4, 4),
 QPoint(0, -40)
 };

 static const QPoint minuteHand[3] =
 {
 QPoint(4, 4),
 QPoint(-4, 4),
 QPoint(0, -70)
 };

 static const QPoint secondHand[3] =
 {
 QPoint(2, 2),
 QPoint(-2, 2),
 QPoint(0, -90)
 };
}
```

1.  在此之后，将以下代码添加到数组下面，以创建绘图器并将其移动到主窗口的中心。此外，我们调整绘图器的大小，使其在主窗口中很好地适应，即使窗口被调整大小：

```cpp
int side = qMin(width(), height());

QPainter painter(this);
painter.setRenderHint(QPainter::Antialiasing);
painter.translate(width() / 2, height() / 2);
painter.scale(side / 250.0, side / 250.0);
```

1.  完成后，我们将通过使用`for`循环开始绘制刻度。每个刻度旋转增加 6 度，所以 60 个刻度将完成一个完整的圆。此外，每 5 分钟的刻度看起来会稍微长一些：

```cpp
for (int i = 0; i < 60; ++i)
{
  if ((i % 5) != 0)
    painter.drawLine(92, 0, 96, 0);
  else
    painter.drawLine(86, 0, 96, 0);
  painter.rotate(6.0);
}
```

1.  然后，我们继续绘制时钟的指针。每个指针的旋转根据当前时间和其相应的单位计算超过 360 度：

```cpp
QTime time = QTime::currentTime();

// Draw hour hand
painter.save();
painter.rotate((time.hour() * 360) / 12);
painter.setPen(Qt::NoPen);
painter.setBrush(Qt::black);
painter.drawConvexPolygon(hourHand, 3);
painter.restore();

// Draw minute hand
painter.save();
painter.rotate((time.minute() * 360) / 60);
painter.setPen(Qt::NoPen);
painter.setBrush(Qt::black);
painter.drawConvexPolygon(minuteHand, 3);
painter.restore();

// Draw second hand
painter.save();
painter.rotate((time.second() * 360) / 60);
painter.setPen(Qt::NoPen);
painter.setBrush(Qt::black);
painter.drawConvexPolygon(secondHand, 3);
painter.restore();
```

1.  最后，创建一个定时器，每秒刷新一次图形，使程序像一个真正的时钟一样工作！

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  QTimer* timer = new QTimer(this);
  timer->start(1000);
  connect(timer, SIGNAL(timeout()), this, SLOT(update()));
}
```

1.  现在编译并运行程序，你应该会看到类似这样的东西：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_07.jpg)

## 它是如何工作的...

每个数组都包含三个`QPoint`数据，形成一个细长的三角形。然后将这些数组传递给绘图器，并使用`drawConvexPolygon()`函数呈现为凸多边形。

在绘制每个时钟指针之前，我们使用`painter.save()`保存`QPainter`对象的状态，然后使用坐标转换继续绘制指针。完成绘制后，我们通过调用`painter.restore()`将绘图器恢复到先前的状态。这个函数将撤消`painter.restore()`之前的所有转换，以便下一个时钟指针不会继承上一个时钟指针的转换。如果不使用`painter.save()`和`painter.restore()`，我们将不得不在绘制下一个指针之前手动改变位置、旋转和比例。

不使用`painter.save()`和`painter.restore()`的一个很好的例子是绘制刻度。由于每个刻度的旋转是从前一个刻度增加 6 度，我们根本不需要保存绘图器的状态。我们只需在循环中调用`painter.rotate(6.0)`，每个刻度将继承前一个刻度的旋转。我们还使用模运算符(`%`)来检查刻度所代表的单位是否可以被 5 整除。如果可以，我们就会稍微拉长它。

如果不使用定时器不断调用`update()`槽，时钟将无法正常工作。这是因为当父窗口的状态没有改变时，Qt 不会调用`paintEvent()`。因此，我们需要手动告诉 Qt 我们需要通过每秒调用`update()`来刷新图形。

我们使用`painter.setRenderHint(QPainter::Antialiasing)`函数在渲染时启用抗锯齿。没有抗锯齿，图形看起来会非常锯齿和像素化：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_08.jpg)

## 还有更多...

`QPainter`类使用坐标系统来确定在屏幕上呈现图形之前的位置和大小。这些信息可以被改变，使图形出现在不同的位置、旋转和大小。这个改变图形坐标信息的过程就是我们所谓的坐标转换。有几种类型的转换，其中包括平移、旋转、缩放和剪切：

![还有更多...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_06.jpg)

Qt 使用一个坐标系统，其原点位于左上角，意味着 x 值向右增加，y 值向下增加。这个坐标系统可能与物理设备使用的坐标系统不同，比如计算机屏幕。Qt 通过使用`QPaintDevice`类自动处理这个问题，将 Qt 的逻辑坐标映射到物理坐标。

`QPainter`提供了四种变换操作来执行不同类型的变换：

+   `QPainter::translate()`: 通过给定的单位偏移图形的位置

+   `QPainter::rotate()`: 以顺时针方向围绕原点旋转图形

+   `QPainter::scale()`: 通过给定的因子偏移图形的大小

+   `QPainter::shear()`: 扭曲图形的坐标系围绕原点

# 在屏幕上显示图像

Qt 不仅允许我们在屏幕上绘制形状和图像，还允许我们将多个图像叠加在一起，并使用不同类型的算法结合所有图层的像素信息，以创建非常有趣的结果。在这个例子中，我们将学习如何将图像叠加在一起，并对它们应用不同的组合效果。

## 如何做…

让我们创建一个简单的演示，通过以下步骤展示不同图像组合效果的效果：

1.  首先，设置一个新的**Qt Widgets Application**项目，并移除菜单栏、工具栏和状态栏。

1.  接下来，将 QPainter 类头文件添加到`mainwindow.h`中：

```cpp
#include <QPainter>
```

1.  之后，声明`paintEvent()`虚函数如下：

```cpp
virtual void paintEvent(QPaintEvent* event);
```

1.  在`mainwindow.cpp`中，我们将首先使用`QImage`类加载几个图像文件：

```cpp
void MainWindow::paintEvent(QPaintEvent* event)
{
 QImage image;
 image.load("checker.png");

 QImage image2;
 image2.load("tux.png");

 QImage image3;
 image3.load("butterfly.png");
}
```

1.  然后，创建一个`QPainter`对象，并使用它来绘制两对图像，其中一张图像叠加在另一张图像上：

```cpp
QPainter painter(this);
painter.drawImage(QPoint(10, 10), image);
painter.drawImage(QPoint(10, 10), image2);
painter.drawImage(QPoint(300, 10), image);
painter.drawImage(QPoint(300, 40), image3);
```

1.  现在编译并运行程序，你应该会看到类似这样的东西：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_10.jpg)

1.  接下来，我们将在屏幕上绘制每个图像之前设置组合模式：

```cpp
QPainter painter(this);

painter.setCompositionMode(QPainter::CompositionMode_Difference);
painter.drawImage(QPoint(10, 10), image);
painter.setCompositionMode(QPainter::CompositionMode_Multiply);
painter.drawImage(QPoint(10, 10), image2);

painter.setCompositionMode(QPainter::CompositionMode_Xor);
painter.drawImage(QPoint(300, 10), image);
painter.setCompositionMode(QPainter::CompositionMode_SoftLight);
painter.drawImage(QPoint(300, 40), image3);
```

1.  再次编译并运行程序，你现在会看到类似这样的东西：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_11.jpg)

## 它是如何工作的…

在使用 Qt 绘制图像时，调用`drawImage()`函数的顺序将决定首先渲染哪个图像，以及后渲染哪个图像。这将影响图像的深度顺序，并产生不同的结果。

在之前的例子中，我们调用了`drawImage()`四次，在屏幕上绘制了四个不同的图像。第一次`drawImage()`渲染了`checker.png`，第二次`drawImage()`渲染了`tux.png`（企鹅）。后渲染的图像将始终出现在其他图像的前面，这就是为什么企鹅显示在棋盘前面。右侧的蝴蝶和棋盘也是如此。尽管蝴蝶被渲染在棋盘前面，你仍然能看到棋盘，这是因为蝴蝶图像不是完全不透明的。

现在让我们反转渲染顺序，看看会发生什么。我们将尝试首先渲染企鹅，然后是棋盘。右侧的另一对图像也是如此：蝴蝶首先被渲染，然后是棋盘：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_12.jpg)

要对图像应用组合效果，我们必须在绘制图像之前设置绘图者的组合模式，通过调用`painter.setCompositionMode()`函数来选择所需的组合模式。

在之前的例子中，我们将`QPainter::CompositionMode_Difference`应用到左侧的棋盘上，这使其颜色反转。接下来，我们将`QPainter::CompositionMode_Overlay`应用到企鹅上，使其与棋盘混合，我们能够看到两个图像叠加在一起。

在右侧，我们将`QPainter::CompositionMode_Xor`应用于棋盘，如果源和目的地之间存在差异，则显示颜色；否则，它将呈现为黑色。由于它正在与白色背景比较差异，棋盘的不透明部分变为完全黑色。我们还将`QPainter::CompositionMode_SoftLight`应用于蝴蝶图像。这会将像素与背景混合，降低对比度。

如果您想在进行下一个渲染之前禁用刚刚设置的合成模式，请将其设置回默认模式，即`QPainter::CompositionMode_SourceOver`。

## 还有更多…

例如，我们可以将多个图像叠加在一起，并使用 Qt 的图像合成功能将它们合并在一起，并根据我们使用的合成模式计算屏幕上的结果像素。这在图像编辑软件（如 Photoshop 和 GIMP）中经常用于合成图像图层。

Qt 中有 30 多种合成模式可用。一些最常用的模式包括：

+   **清除**：目的地中的像素被设置为完全透明，与源无关。

+   **源**：输出是源像素。这种模式是`CompositionMode_Destination`的反向。

+   **目的地**：输出是目的地像素。这意味着混合没有效果。这种模式是`CompositionMode_Source`的反向。

+   **源上**：通常称为 alpha 混合。源的 alpha 值用于将像素混合在目的地的顶部。这是`QPainter`使用的默认模式。

+   **目的地超过**：目的地的 alpha 值用于在源像素的顶部混合。这种模式是`CompositionMode_SourceOver`的反向。

+   **源入**：输出是源，其中 alpha 值减少了目标的 alpha 值。

+   **目的地内**：输出是目的地，其中 alpha 值减少了源的 alpha 值。这种模式是`CompositionMode_SourceIn`的反向。

+   **源出**：输出是源，其中 alpha 值减少了目标的倒数。

+   **目的地外**：输出是目的地，其中 alpha 值减少了源的倒数。这种模式是`CompositionMode_SourceOut`的反向。

+   **源顶部**：源像素在目标的顶部混合，源像素的 alpha 值减少了目标像素的 alpha 值。

+   **目的地顶部**：目的地像素在源的顶部混合，源像素的 alpha 值减少了目的地像素的 alpha 值。这种模式是`CompositionMode_SourceAtop`的反向。

+   **异或**：这是**异或**的缩写，是一种主要用于图像分析的高级混合模式。源的 alpha 值减少了目的地 alpha 值的倒数，与目的地合并，目的地的 alpha 值减少了源 alpha 值的倒数。

以下图像显示了使用不同合成模式叠加两个图像的结果：

![更多内容…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_09.jpg)

# 应用图像效果到图形

Qt 提供了一种简单的方法，可以在使用`QPainter`类绘制的任何图形上添加图像效果。在这个例子中，我们将学习如何应用不同的图像效果，如阴影、模糊、着色和不透明度效果，以在屏幕上显示图形之前应用到图形上。

## 如何做…

让我们学习如何通过以下步骤将图像效果应用于文本和图形：

1.  创建一个新的**Qt 小部件应用程序**，并删除菜单栏、工具栏和状态栏。

1.  通过转到**文件** | **新文件或项目**创建一个新的资源文件，并添加项目所需的所有图像：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_13.jpg)

1.  接下来，打开`mainwindow.ui`并向窗口添加四个标签。其中两个标签将是文本，另外两个将加载我们刚刚添加到资源文件中的图像：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_14.jpg)

1.  您可能已经注意到字体大小比默认大小要大得多。例如，可以通过向标签小部件添加样式表来实现：

```cpp
font: 26pt "MS Shell Dlg 2";
```

1.  之后，打开`mainwindow.cpp`并在源代码顶部包含以下头文件：

```cpp
#include <QGraphicsBlurEffect>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsColorizeEffect>
#include <QGraphicsOpacityEffect>
```

1.  然后，在`MainWindow`类的构造函数中，添加以下代码以创建一个投影效果，并将其应用于其中一个标签：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);

 QGraphicsDropShadowEffect* shadow = new QGraphicsDropShadowEffect();
 shadow->setXOffset(4);
 shadow->setYOffset(4);
 ui->label->setGraphicsEffect(shadow);
}
```

1.  接下来，我们将创建一个着色效果，并将其应用于其中一幅图像，这里是蝴蝶。我们还将效果颜色设置为红色：

```cpp
QGraphicsColorizeEffect* colorize = new QGraphicsColorizeEffect();
colorize->setColor(QColor(255, 0, 0));
ui->butterfly->setGraphicsEffect(colorize);
```

1.  完成后，创建一个模糊效果，并将其半径设置为`12`。然后，将图形效果应用于另一个标签：

```cpp
QGraphicsBlurEffect* blur = new QGraphicsBlurEffect();
blur->setBlurRadius(12);
ui->label2->setGraphicsEffect(blur);
```

1.  最后，创建一个 alpha 效果，并将其应用于企鹅图像。我们将不透明度值设置为`0.2`，即 20%的不透明度：

```cpp
QGraphicsOpacityEffect* alpha = new QGraphicsOpacityEffect();
alpha->setOpacity(0.2);
ui->penguin->setGraphicsEffect(alpha);
```

1.  现在编译并运行程序，您应该能够看到类似于这样的东西：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_15.jpg)

## 它是如何工作的…

每种图形效果都是其自己的类，继承自`QGraphicsEffect`父类。您可以通过创建一个新类，该类继承自`QGraphicsEffect`并重新实现其中的一些函数来创建自定义效果。

每种效果都有其专门为其创建的一组变量。例如，您可以设置着色效果的颜色，但在模糊效果中没有这样的变量。这是因为每种效果与其他效果大不相同，这也是为什么它需要成为自己的类，而不是使用相同的类来处理所有不同的效果。

一次只能向小部件添加一个图形效果。如果添加多个效果，只有最后一个效果将应用于小部件，因为它替换了前一个效果。除此之外，要注意，如果创建了一个图形效果，比如投影效果，您不能将其分配给两个不同的小部件，因为它只会分配给您应用它的最后一个小部件。如果需要将相同类型的效果应用于几个不同的小部件，创建几个相同类型的图形效果，并将每个效果应用于各自的小部件。

## 还有更多…

目前 Qt 支持模糊、投影、着色和不透明度效果。这些效果可以通过调用以下类来使用：`QGraphicsBlurEffect`、`QGraphicsDropShadowEffect`、`QGraphicsColorizeEffect`和`QGraphicsOpacityEffect`。所有这些类都是从`QGraphicsEffect`类继承的。您还可以通过创建`QGrapicsEffect`的子类（或任何其他现有效果）并重新实现`draw()`函数来创建自定义图像效果。

图形效果仅改变源的边界矩形。如果要增加边界矩形的边距，可以重新实现虚拟的`boundingRectFor()`函数，并在此矩形更改时调用`updateBoundingRect()`来通知框架。

# 创建一个基本的绘画程序

由于我们已经学习了关于`QPainter`类以及如何使用它在屏幕上显示图形，我想现在是时候做一些有趣的事情，这样我们就可以将我们的知识付诸实践了。

在这个示例中，我们将学习如何制作一个基本的绘画程序，允许我们在画布上用不同的画笔大小和颜色绘制线条。我们还将学习如何使用`QImage`类和鼠标事件来构建绘画程序。

## 如何做…

让我们通过以下步骤开始我们有趣的项目：

1.  同样，我们首先创建一个新的**Qt Widgets Application**项目，并移除工具栏和状态栏。这次我们将保留菜单栏。

1.  之后，设置菜单栏如下：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_16.jpg)

1.  我们将暂时保留菜单栏，然后继续进行`mainwindow.h`。首先，包括以下头文件，因为它对项目是必需的：

```cpp
#include <QPainter>
#include <QMouseEvent>
#include <QFileDialog>
```

1.  接下来，声明我们将在此项目中使用的变量，如下所示：

```cpp
private:
Ui::MainWindow *ui;

QImage image;
bool drawing;
QPoint lastPoint;
int brushSize;
QColor brushColor;

```

1.  然后，声明事件回调函数，这些函数是从`QWidget`类继承的。这些函数将由 Qt 在相应事件发生时触发。我们将重写这些函数，并告诉 Qt 在这些事件被调用时该做什么：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

 virtual void mousePressEvent(QMouseEvent *event);
 virtual void mouseMoveEvent(QMouseEvent *event);
 virtual void mouseReleaseEvent(QMouseEvent *event);
 virtual void paintEvent(QPaintEvent *event);
 virtual void resizeEvent(QResizeEvent *event);

```

1.  之后，转到`mainwindow.cpp`并在类构造函数中添加以下代码以设置一些变量：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);

 image = QImage(this->size(), QImage::Format_RGB32);
 image.fill(Qt::white);

 drawing = false;
 brushColor = Qt::black;
 brushSize = 2;
}
```

1.  接下来，我们将构造`mousePressEvent()`事件并告诉 Qt 当左鼠标按钮被按下时该做什么：

```cpp
void MainWindow::mousePressEvent(QMouseEvent *event)
{
  if (event->button() == Qt::LeftButton)
  {
    drawing = true;
    lastPoint = event->pos();
  }
}
```

1.  然后，我们将构造`mouseMoveEvent()`事件并告诉 Qt 当鼠标移动时该做什么。在这种情况下，如果左鼠标按钮被按住，我们希望在画布上绘制线条：

```cpp
void MainWindow::mouseMoveEvent(QMouseEvent *event)
{
  if ((event->buttons() & Qt::LeftButton) && drawing)
  {
    QPainter painter(&image);
    painter.setPen(QPen(brushColor, brushSize, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawLine(lastPoint, event->pos());

    lastPoint = event->pos();
    this->update();
  }
}
```

1.  之后，我们还将构造`mouseReleaseEvent()`事件，当鼠标按钮释放时将被触发：

```cpp
void MainWindow::mouseReleaseEvent(QMouseEvent *event)
{
  if (event->button() == Qt::LeftButton)
  {
    drawing = false;
  }
}
```

1.  完成后，我们将继续进行`paintEvent()`事件，与我们在之前章节中看到的其他示例相比，这个事件非常简单：

```cpp
void MainWindow::paintEvent(QPaintEvent *event)
{
  QPainter canvasPainter(this);
  canvasPainter.drawImage(this->rect(), image, image.rect());
}
```

1.  记住我们有一个无所事事的菜单栏吗？让我们右键单击 GUI 编辑器下面的每个操作，并在弹出菜单中选择**转到槽...**。我们要告诉 Qt 当菜单栏上的每个选项被选择时该做什么：![如何做到这一点...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_17.jpg)

1.  然后，选择名为`triggered()`的默认槽，并按下**确定**按钮。Qt 将自动生成一个新的槽函数，分别在你的`mainwindow.h`和`mainwindow.cpp`中。完成所有操作后，你应该在`mainwindow.h`中看到类似这样的东西：

```cpp
private slots:
  void on_actionSave_triggered();
  void on_actionClear_triggered();
  void on_action2px_triggered();
  void on_action5px_triggered();
  void on_action10px_triggered();
  void on_actionBlack_triggered();
  void on_actionWhite_triggered();
  void on_actionRed_triggered();
  void on_actionGreen_triggered();
  void on_actionBlue_triggered();
```

1.  接下来，我们将告诉 Qt 在每个这些槽被触发时该做什么：

```cpp
void MainWindow::on_actionSave_triggered()
{
  QString filePath = QFileDialog::getSaveFileName(this, "Save Image", "", "PNG (*.png);;JPEG (*.jpg *.jpeg);;All files (*.*)");

  if (filePath == "")
    return;

  image.save(filePath);
}
void MainWindow::on_actionClear_triggered()
{
  image.fill(Qt::white);
  this->update();
}
void MainWindow::on_action2px_triggered()
{
  brushSize = 2;
}
void MainWindow::on_action5px_triggered()
{
  brushSize = 5;
}
void MainWindow::on_action10px_triggered()
{
  brushSize = 10;
}
void MainWindow::on_actionBlack_triggered()
{
  brushColor = Qt::black;
}

void MainWindow::on_actionWhite_triggered()
{
  brushColor = Qt::white;
}
void MainWindow::on_actionRed_triggered()
{
  brushColor = Qt::red;
}
void MainWindow::on_actionGreen_triggered()
{
  brushColor = Qt::green;
}
void MainWindow::on_actionBlue_triggered()
{
  brushColor = Qt::blue;
}
```

1.  如果我们现在编译并运行程序，我们将得到一个简单但可用的绘图程序：![如何做到这一点...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_18.jpg)

## 它是如何工作的...

在这个例子中，当程序启动时，我们创建了一个`QImage`小部件。这个小部件充当画布，当窗口被调整大小时，它将跟随窗口的大小。

为了在画布上绘制东西，我们需要使用 Qt 提供的鼠标事件。这些事件将告诉我们光标的位置，我们将能够利用这些信息来改变画布上的像素。

我们使用一个名为`drawing`的布尔变量来让程序知道当鼠标按钮被按下时是否应该开始绘制。在这种情况下，当左鼠标按钮被按下时，变量`drawing`将被设置为`true`。当左鼠标按钮被按下时，我们还将当前光标位置保存到`lastPoint`变量中，这样 Qt 就会知道从哪里开始绘制。

当鼠标移动时，Qt 将触发`mouseMoveEvent()`事件。这是我们需要检查`drawing`变量是否设置为`true`的地方。如果是，那么`QPainter`可以根据我们提供的画笔设置开始在`QImage`小部件上绘制线条。

画笔设置包括画笔颜色和画笔大小。这些设置被保存为变量，并可以通过从菜单栏中选择不同的设置来更改。

请记住，在用户在画布上绘制时调用`update()`函数。否则，尽管我们已经改变了画布的像素信息，画布仍将保持空白。当我们从菜单栏中选择**文件** | **清除**时，我们还必须调用`update()`函数来重置我们的画布。

在这个例子中，我们使用`QImage::save()`来保存图像文件，这非常简单和直接。我们使用文件对话框让用户决定在哪里保存图像及其所需的文件名。然后，我们将信息传递给`QImage`，它将自行完成剩下的工作。如果我们没有向`QImage::save()`函数指定文件格式，`QImage`将尝试通过查看所需文件名的扩展名来确定它。

# QML 中的 2D 画布

在本章的所有先前示例中，我们已经讨论了使用 Qt 的 C++ API 渲染 2D 图形的方法和技术。然而，我们还没有学习如何使用强大的 QML 脚本来实现类似的结果。

## 如何做…

在这个项目中，我们将做一些完全不同的事情：

1.  像往常一样，我们应该首先创建一个新项目，方法是转到**文件** | **新建文件或项目**，然后选择**Qt Quick Application**作为项目模板。

1.  创建新项目后，从项目窗格中的`Resource`文件夹中右键单击打开`qml.qrc`。然后，从项目资源中删除`MainForm.ui.qml`，因为我们不需要它：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_19.jpg)

1.  接下来，打开`qml.rc`项目窗格下列出的`main.qml`。之后，删除引用`MainForm`的整个部分。现在剩下的只有`main.qml`中的`Window`对象。之后，为窗口设置一个 ID，并将其宽度和高度调整为更高的值，如下所示：

```cpp
import QtQuick 2.5
import QtQuick.Window 2.2

Window
{
  id: myWindow
  visible: true
  width: 540
  height: 380
}
```

1.  然后，在`myWindow`下添加一个`Canvas`对象，并将其命名为`myCanvas`。之后，将其宽度和高度设置为与`myWindow`相同：

```cpp
Window
{
  id: myWindow
  visible: true
  width: 540
  height: 380

 Canvas
 {
 id: myCanvas
 width: myWindow.width
 height: myWindow.height
 }
}
```

1.  接下来，我们定义`onPaint`事件触发时会发生什么；在这种情况下，我们将在窗口上绘制一个十字架：

```cpp
Canvas
{
  id: myCanvas
  width: myWindow.width
  height: myWindow.height

  onPaint:
 {
 var context = getContext('2d')
 context.fillStyle = 'white'
 context.fillRect(0, 0, width, height)
 context.lineWidth = 2
 context.strokeStyle = 'black'

 // Draw cross
 context.beginPath()
 context.moveTo(50, 50)
 context.lineTo(100, 100)
 context.closePath()
 context.stroke()

 context.beginPath()
 context.moveTo(100, 50)
 context.lineTo(50, 100)
 context.closePath()
 context.stroke()
 }
}
```

1.  之后，添加以下代码以在十字架旁边绘制一个勾号：

```cpp
// Draw tick
context.beginPath()
context.moveTo(150, 90)
context.lineTo(158, 100)
context.closePath()
context.stroke()

context.beginPath()
context.moveTo(180, 100)
context.lineTo(210, 50)
context.closePath()
context.stroke()
```

1.  然后，通过添加以下代码来绘制一个三角形形状：

```cpp
// Draw triangle
context.lineWidth = 4
context.strokeStyle = "red"
context.fillStyle = "salmon"

context.beginPath()
context.moveTo(50,150)
context.lineTo(150,150)
context.lineTo(50,250)
context.closePath()
context.fill()
context.stroke()
```

1.  之后，使用以下代码绘制一个半圆和一个完整的圆：

```cpp
// Draw circle
context.lineWidth = 4
context.strokeStyle = "blue"
context.fillStyle = "steelblue"

var pi = 3.141592653589793

context.beginPath()
context.arc(220, 200, 60, 0, pi, true)
context.closePath()
context.fill()
context.stroke()

context.beginPath()
context.arc(220, 280, 60, 0, 2 * pi, true)
context.closePath()
context.fill()
context.stroke()
```

1.  最后，我们从文件中绘制一个 2D 图像：

```cpp
// Draw image
context.drawImage("tux.png", 280, 10, 256, 297)
```

1.  然而，仅仅使用上述代码将无法成功在屏幕上渲染图像，因为您还必须预先加载图像文件。在`Canvas`对象内添加以下代码，以便在程序启动时要求 QML 加载图像文件，然后在图像加载时调用`requestPaint()`信号，以便触发`onPaint()`事件槽：

```cpp
Component.onCompleted:
{
 loadImage("tux.png")
}

onImageLoaded:requestPaint();
onPaint:
{
  // The code we added previously
}
```

1.  现在构建并运行程序，您应该会得到以下结果：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_03_20.jpg)
