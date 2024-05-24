# C++ UE4 脚本编程秘籍（一）

> 原文：[`zh.annas-archive.org/md5/244B225FA5E3FFE01C9887B1851E5B64`](https://zh.annas-archive.org/md5/244B225FA5E3FFE01C9887B1851E5B64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

虚幻引擎 4（UE4）是由游戏开发者制作的一套完整的游戏开发工具。本书提供 80 多个实用的配方，展示了在使用 UE4 开发游戏时如何利用 C++脚本的技术。我们将从在虚幻编辑器内添加和编辑 C++类开始。然后，我们将深入研究虚幻的主要优势之一 - 设计师可以定制程序员开发的角色和组件。这将帮助您了解何时以及如何使用 C++作为脚本工具的好处。本书将提供一系列以任务为导向的配方，为您提供有关使用 C++脚本游戏和使用 C++操纵游戏和开发环境的可行信息。在本书的最后，您将有能力成为使用 C++作为脚本语言的顶尖开发人员。

# 本书涵盖的内容

第一章，“UE4 开发工具”，概述了开始使用 UE4 游戏开发和用于创建游戏代码的基本工具的基本配方。

第二章，“创建类”，着重介绍如何创建与 UE4 蓝图编辑器良好集成的 C++类和结构。这些类将是称为 UCLASSES 的常规 C++类的毕业版本。

第三章，“内存管理和智能指针”，带领读者使用三种类型的指针，并提到了关于自动垃圾收集的一些常见陷阱。本章还向读者展示如何使用 Visual Studio 或 XCode 来解释崩溃或确认功能是否实现正确。

第四章，“角色和组件”，涉及创建自定义角色和组件，以及它们各自的作用以及它们如何协同工作。

第五章，“处理事件和委托”，描述了委托、事件和事件处理程序，并指导您通过创建它们自己的实现。

第六章，“输入和碰撞”，展示了如何将用户输入连接到 C++函数，以及如何从 UE4 中处理碰撞。它还将提供默认处理游戏事件，如用户输入和碰撞，允许设计师在必要时使用蓝图进行覆盖。

第七章，“类和接口之间的通信”，向您展示如何编写自己的 UInterfaces，并演示如何利用它们在 C++中最小化类耦合并帮助保持代码清晰。

第八章，“集成 C++和虚幻编辑器”，向您展示如何通过从头开始创建自定义蓝图和动画节点来自定义编辑器。我们还将实现自定义编辑器窗口和自定义详细面板，以检查用户创建的类型。

第九章，“用户界面 - UI 和 UMG”，演示了向玩家显示反馈是游戏设计中最重要的元素之一，这通常会涉及某种 HUD，或者至少是游戏中的菜单。

第十章，“控制 NPC 的人工智能”，涵盖了使用一点人工智能（AI）来控制 NPC 角色的食谱。

第十一章，“自定义材料和着色器”，讨论了在 UE4 编辑器中创建自定义材料和音频图节点。

第十二章，“使用 UE4 API”，解释了应用程序编程接口（API）是您作为程序员可以指示引擎（以及 PC）要做什么的方式。每个模块都有一个 API。要使用 API，有一个非常重要的链接步骤，您必须在`ProjectName.Build.cs`文件中列出您将在构建中使用的所有 API。

# 您需要为本书做什么

创建游戏是一项复杂的任务，需要资产和代码的结合。为了创建资产和代码，我们将需要一些非常先进的工具，包括美术工具，声音工具，级别编辑工具和代码编辑工具。资产包括任何视觉艺术品（2D 精灵，3D 模型），音频（音乐和音效）和游戏关卡。为此，我们将设置一个 C++编码环境来构建我们的 UE4 应用程序。我们将下载 Visual Studio 2015，安装它，并为 UE4 C++编码进行设置。（在编辑 UE4 游戏的 C++代码时，Visual Studio 是一个必不可少的代码编辑包。）

# 本书适合谁

本书适用于了解游戏设计和 C++基础知识，并希望将本机代码纳入 Unreal 制作的游戏中的游戏开发人员。他们将是希望扩展引擎或实现允许设计师在构建关卡时具有控制和灵活性的系统和角色的程序员。

# 部分

在本书中，您会经常看到几个标题（准备工作，如何做，工作原理，还有更多，另请参阅）。

为了清晰地说明如何完成食谱，我们使用以下部分：

## 准备工作

本节告诉您在食谱中可以期待什么，并描述了如何设置任何软件或食谱所需的任何初步设置。

## 如何做...

本节包含了遵循食谱所需的步骤。

## 工作原理...

本节通常包括对上一节中发生的事情的详细解释。

## 还有更多...

本节包含有关食谱的其他信息，以使读者对食谱更加了解。

## 另请参阅

本节提供了有关食谱的其他有用信息的有用链接。

# 约定

在本书中，您会发现一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄显示如下：“传递给`UPROPERTY()`宏的参数指定了关于变量的一些重要信息。”

代码块设置如下：

```cpp
#include<stdio.h>

int main()
{
  puts("Welcome to Visual Studio 2015 Community Edition!");
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
int intVar = 5;
float floatVar = 3.7f;
FString fstringVar = "an fstring variable";
UE_LOG(LogTemp, Warning, TEXT("Text, %d %f %s"), intVar, floatVar, *fstringVar );

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“在选择要添加到 Visual Studio 的工具后，单击**下一步**按钮。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧看起来像这样。


# 第一章：UE4 开发工具

在本章中，我们将概述 UE4 游戏开发的基本方法，并介绍我们用于创建使您的游戏的代码的基本工具。这将包括以下方法：

+   安装 Visual Studio

+   在 Visual Studio 中创建和构建您的第一个 C++项目

+   在 Visual Studio 中更改代码字体和颜色

+   扩展 - 在 Visual Studio 中更改颜色主题

+   在 Visual Studio 中格式化您的代码（自动完成设置）

+   Visual Studio 中的快捷键

+   在 Visual Studio 中扩展鼠标使用

+   UE4 - 安装

+   UE4 - 第一个项目

+   UE4 - 创建您的第一个级别

+   UE4 - 使用`UE_LOG`进行日志记录

+   UE4 - 从`FStrings`和其他变量创建`FString`

+   GitHub 上的项目管理 - 获取您的源代码控制

+   在 GitHub 上的项目管理 - 使用问题跟踪器

+   在 VisualStudio.com 上的项目管理 - 管理项目中的任务

+   在 VisualStudio.com 上的项目管理 - 构建用户故事和任务

# 介绍

创建游戏是一个复杂的任务，需要结合**资产**和**代码**。为了创建资产和代码，我们需要一些非常先进的工具，包括*艺术工具*、*声音工具*、*级别编辑工具*和*代码编辑工具*。在本章中，我们将讨论寻找适合资产创建和编码的工具。资产包括任何视觉艺术品（2D 精灵、3D 模型）、音频（音乐和音效）和游戏级别。代码是指（通常是 C++）指示计算机如何将这些资产组合在一起以创建游戏世界和级别，并如何使该游戏世界“运行”的文本。每项任务都有数十种非常好的工具；我们将探索其中的一些，并提出一些建议。特别是游戏编辑工具是庞大的程序，需要强大的 CPU 和大量内存，以及非常好的 GPU 以获得良好的性能。

保护您的资产和工作也是必要的实践。我们将探讨和描述源代码控制，这是您如何在远程服务器上备份工作的方式。还包括*Unreal Engine 4 编程*的介绍，以及探索基本的日志记录功能和库的使用。还需要进行重要的规划来完成任务，因此我们将使用任务计划软件包来完成。

# 安装 Visual Studio

在编辑 UE4 游戏的 C++代码时，Visual Studio 是一个必不可少的代码编辑包。

## 准备工作

我们将建立一个 C++编码环境来构建我们的 UE4 应用程序。我们将下载 Visual Studio 2015，安装它，并为 UE4 C++编码进行设置。

## 如何做... 

1.  首先访问[`www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx`](https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx)。单击**下载 Community 2015**。这将下载大约 200 KB 的加载程序/安装程序。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00002.jpeg)

### 提示

您可以在[`www.visualstudio.com/en-us/products/compare-visual-studio-2015-products-vs.aspx`](https://www.visualstudio.com/en-us/products/compare-visual-studio-2015-products-vs.aspx)上比较 Visual Studio 的版本。本书中的 UE4 开发目的，Visual Studio 的社区版是完全足够的。

1.  启动安装程序，并选择要添加到您的 PC 的 Visual Studio 2015 组件。请记住，您选择的功能越多，安装的大小就越大。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00003.jpeg)

上述屏幕截图显示了推荐的最小安装，所有都已选中**Visual C++ 2015 的公共工具**，**Git for Windows**和**Visual Studio 的 GitHub 扩展**。我们将在本章的后面部分使用**Git for Windows**功能。

1.  在您选择要添加到 Visual Studio 的工具后，单击**下一步**按钮。安装程序将下载所需的组件，并继续设置。安装时间取决于您的选项选择和连接速度，大约需要 20-40 分钟。

1.  下载并安装 Visual Studio 2015 后，启动它。您将看到一个**登录**对话框。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00004.jpeg)

您可以使用您的 Microsoft 帐户（用于登录 Windows 10 的帐户）**登录**，或者**注册**一个新帐户。登录或注册后，您将能够登录到 Visual Studio 本身。在登录到 Visual Studio 时，您可以选择（仅一次）Visualstudio.com 上托管的源代码库的唯一 URL。

## 工作原理...

Visual Studio 是一个优秀的编辑器，您将在其中编写代码时度过美好的时光。在下一个教程中，我们将讨论如何创建和编译您自己的代码。

# 在 Visual Studio 中创建和构建您的第一个 C++项目

为了从 Visual Studio 编译和运行代码，必须在项目内完成。

## 准备工作

在本教程中，我们将介绍如何从 Visual Studio 创建一个实际的可执行运行程序。我们将通过在 Visual Studio 中创建一个项目来实现这一点，以托管、组织和编译代码。

## 操作步骤...

在 Visual Studio 中，每组代码都包含在一个称为**项目**的东西中。项目是一组可构建的代码和资产，可以生成可执行文件（`.exe`可运行）或库（`.lib`或`.dll`）。一组项目可以被收集到一起形成一个称为**解决方案**的东西。让我们首先为控制台应用程序构建一个 Visual Studio 解决方案和项目，然后构建一个 UE4 示例项目和解决方案。

1.  打开 Visual Studio，转到**文件** | **新建** | **项目...**

1.  您将看到以下对话框：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00005.jpeg)

在左侧的窗格中选择**Win32**。在右侧的窗格中，点击**Win32 控制台应用程序**。在下方的框中命名您的项目，然后点击**确定**。

1.  在下一个对话框中，我们指定控制台应用程序的属性。阅读第一个对话框，然后简单地点击**下一步**。然后，在**应用程序设置**对话框中，选择**控制台应用程序**选项，然后在**附加选项**下选择**空项目**。您可以不选择**安全开发生命周期（SDL）检查**。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00006.jpeg)

1.  应用程序向导完成后，您将创建您的第一个项目。将创建一个解决方案和一个项目。要查看这些内容，您需要**解决方案资源管理器**。为了确保**解决方案资源管理器**正在显示，转到**视图** | **解决方案资源管理器**（或按下*Ctrl* + *Alt* + *L*）。**解决方案资源管理器**通常显示在主编辑器窗口的左侧或右侧，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00007.jpeg)

**解决方案资源管理器**还显示了项目的所有文件。使用**解决方案资源管理器**，我们还将在编辑器中添加一个代码文件。右键单击您的项目`FirstProject`，然后选择**添加** | **新建项...**

![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00008.jpeg)

1.  在下一个对话框中，只需选择**C++文件 (.cpp)**，并给文件任何您喜欢的名称。我称我的为`Main.cpp`。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00009.jpeg)

1.  一旦您添加了文件，它将出现在**解决方案资源管理器**中，位于您的`FirstProject`的源文件过滤器下。随着项目的增长，将会添加更多的文件到您的项目中。您可以使用以下文本编译和运行您的第一个 C++程序：

```cpp
#include<stdio.h>

int main()
{
  puts("Welcome to Visual Studio 2015 Community Edition!");
}
```

1.  按下*Ctrl* + *Shift* + *B*来构建项目，然后按下*Ctrl* + *F5*来运行项目。

1.  您的可执行文件将被创建，您将看到一个小黑窗口显示程序运行的结果：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00010.jpeg)

## 工作原理...

构建可执行文件涉及将您的 C++代码从文本语言转换为二进制文件。运行该文件将运行您的游戏程序，这只是发生在`main()`函数之间的代码文本，即在`{`和`}`之间。

## 更多内容...

构建配置是我们应该在这里讨论的构建**样式**。至少有两个重要的构建配置需要了解：**调试**和**发布**。所选的构建配置位于编辑器顶部，在默认位置的工具栏下方。

![更多内容...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00011.jpeg)

根据您选择的配置，将使用不同的编译器选项。**调试**配置通常在构建中包含大量的调试信息，并关闭优化以加快编译速度。**发布**构建通常经过优化（无论是为了大小还是速度），需要更长时间来构建，并且生成的可执行文件更小或更快。使用调试器进行逐步调试在**调试**模式下通常比**发布**模式更好。

# 在 Visual Studio 中更改代码字体和颜色

在 Visual Studio 中自定义字体和颜色不仅非常灵活，而且如果您的显示器分辨率非常高或非常低，您还会发现它非常必要。

## 准备工作

Visual Studio 是一个高度可定制的代码编辑工具。您可能会发现默认字体对于您的屏幕来说太小了。您可能想要更改代码的字体大小和颜色。或者您可能想要完全自定义关键字和文本背景颜色。**字体和颜色**对话框，我们将在本节中向您展示如何使用，允许您完全自定义代码编辑器字体和颜色的每个方面。

![准备工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00012.jpeg)

## 如何做...

1.  从 Visual Studio 中，转到**工具** | **选项...**![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00013.jpeg)

1.  从出现的对话框中选择**环境** | **字体和颜色**。它将看起来像下面的截图:![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00014.jpeg)

1.  尝试调整**文本编辑器/纯文本**的字体和字体大小。在对话框上点击**确定**，然后在代码文本编辑器中查看结果。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00015.jpeg)

**文本编辑器/纯文本**描述了常规代码编辑器中所有代码文本使用的字体和大小。如果更改字体的大小，那么在编码窗口中输入的任何文本的大小都会改变（包括 C、C++、C#等所有语言）。

![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00016.jpeg)

每个项目的颜色（前景和背景）都可以完全自定义。尝试对**文本编辑器/关键字**设置（影响所有语言），或者对 C++特定项目进行设置，比如**文本编辑器/C++函数**。点击**确定**，您将看到项目的更改颜色在代码编辑器中得到反映。

您可能还想配置**输出窗口**的字体大小 - 选择**显示设置** => **输出窗口**，如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00017.jpeg)

**输出窗口**是编辑器底部显示构建结果和编译器错误的小窗口。

### 提示

无法保存（导出）或导入（导入）对**字体和颜色**对话框的更改。但是您可以使用一个叫做*Visual Studio Theme Editor Extension*的东西，了解更多请参考*扩展 - 在 Visual Studio 中更改颜色主题*来导出和导入自定义颜色主题。

因此，您可能希望避免从此对话框更改字体颜色。但是，您必须使用此对话框来更改字体和字体大小，无论在任何设置中（在撰写本文时）。

## 它是如何工作的...

**字体和颜色**对话框只是简单地改变了文本编辑器中代码的外观，以及输出窗口等其他窗口的外观。这对于使您的编码环境更加舒适非常有用。

## 更多内容...

一旦你自定义了你的设置，你会发现你可能想要保存你定制的**字体和颜色**设置供他人使用，或者放到另一台计算机上的另一个 Visual Studio 安装中。不幸的是，默认情况下，你无法保存你定制的**字体和颜色**设置。你需要一个叫做 Visual Studio Theme Editor 的扩展来做到这一点。我们将在下一个步骤中探讨这个问题。

## 另请参阅

+   *扩展 - 在 Visual Studio 中更改颜色主题*部分描述了如何导入和导出颜色主题

# 扩展 - 在 Visual Studio 中更改颜色主题

默认情况下，你无法保存在**字体和颜色**对话框中所做的字体颜色和背景设置的更改。为了解决这个问题，Visual Studio 2015 有一个叫做**主题**的功能。如果你转到**工具** | **选项** | **环境** | **常规**，你可以将主题更改为三种预安装的主题之一（**浅色**，**蓝色**和**深色**）。

![扩展 - 在 Visual Studio 中更改颜色主题](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00018.jpeg)

不同的主题会完全改变 Visual Studio 的外观-从标题栏的颜色到文本编辑器窗口的背景颜色。

你也可以完全自定义 Visual Studio 的主题，但你需要一个扩展来实现。扩展是可以安装到 Visual Studio 中以修改其行为的小程序。

默认情况下，你的定制颜色设置无法在没有扩展的情况下保存或重新加载到另一个 Visual Studio 安装中。有了扩展，你还可以保存自己的颜色主题以供他人使用。你还可以将另一个人或你自己制作的颜色设置加载到全新的 Visual Studio 副本中。

## 操作步骤...

1.  转到**工具** | **扩展和更新...**

1.  从出现的对话框中，在左侧面板中选择**在线**。在右侧的搜索框中开始输入`Theme Editor`。**Visual Studio 2015 Color Theme Editor**对话框将会出现在你的搜索结果中。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00019.jpeg)

1.  点击条目右上角的小**下载**按钮。按照安装对话框提示进行操作，允许插件安装。安装完成后，Visual Studio 将提示你重新启动。

### 提示

或者，访问[`visualstudiogallery.msdn.microsoft.com/6f4b51b6-5c6b-4a81-9cb5-f2daa560430b`](https://visualstudiogallery.msdn.microsoft.com/6f4b51b6-5c6b-4a81-9cb5-f2daa560430b)并通过双击浏览器中的`.vsix`来下载/安装扩展。

1.  点击**立即重启**以确保插件已加载。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00020.jpeg)

1.  重新启动后，转到**工具** | **自定义颜色** 打开**颜色主题**编辑页面。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00021.jpeg)

1.  从出现的**颜色主题**对话框中，点击你想要用作基础或起始主题的右上角小调色板形状图标（我在这里点击了**浅色**主题的调色板，如你在下面的截图中所见）。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00022.jpeg)

1.  在**颜色主题**窗口的下部将出现一个**自定义主题**部分的主题副本。点击**编辑主题**来修改主题。当你编辑主题时，你可以改变从字体文本颜色到 C++关键字颜色的一切。

1.  你感兴趣的主要区域是 C++文本编辑器部分。为了访问所有 C++文本编辑器选项，请确保在 Theme Editor 窗口顶部选择**显示所有元素**选项，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00023.jpeg)

### 注意

确保在 Theme Editor 窗口中选择**显示所有元素**选项，以显示特定于 C++的文本编辑器设置。否则，你只能进行 Chrome/GUI 类型的修改。

1.  请注意，您感兴趣的大多数设置将在**文本编辑器** | **C/C++**下，但有些设置不会有**C++**子标题。例如，编辑器窗口内的主/纯文本的设置（适用于所有语言）在**文本编辑器** | **纯文本**（没有**C++**子标题）下。

1.  从**工具** | **选项** | **环境** | **常规**中选择要使用的主题。您创建的任何新主题都将自动显示在下拉菜单中。

## 工作原理...

一旦加载插件，它会很好地集成到 Visual Studio 中。导出和上传您的主题以与他人共享也非常容易。

将主题添加到 Visual Studio 中，将其安装为**工具** | **扩展和更新...**中的扩展，要删除主题，只需**卸载**其扩展。

![工作原理...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00024.jpeg)

# 在 Visual Studio 中格式化您的代码（自动完成设置）

使用 Visual Studio 编写代码格式非常愉快。在本教程中，我们将讨论如何控制 Visual Studio 排列代码文本的方式。

## 准备工作

代码必须格式正确。如果代码一直保持一致的格式，您和您的合作程序员将能更好地理解、掌握并保持代码无错。这就是为什么 Visual Studio 在编辑器内包含许多自动格式化工具的原因。

## 如何做...

1.  转到**工具** | **选项** | **文本编辑器** | **C/C++**。此对话框显示一个窗口，允许您切换**自动括号完成**。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00025.jpeg)

**自动括号完成**是一种功能，当您键入`{`时，会自动为您键入相应的`}`。如果您不喜欢文本编辑器意外地插入字符，这个功能可能会让您不爽。

通常希望打开**自动列出成员**，因为这会显示一个漂亮的对话框，其中列出了您开始键入时的数据成员的完整名称。这样可以轻松记住变量名称，因此您不必记住它们：

![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00026.jpeg)

### 提示

如果您在代码编辑器中随时按*Ctrl* + Spacebar，将弹出自动列表。

1.  更多的自动完成行为选项位于**文本编辑器** | **C/C++** | **格式**下：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00027.jpeg)

**自动格式化部分**：突出显示文本的部分，然后选择**编辑** | **高级** | **格式化选择**（*Ctrl* + *K, Ctrl* + *F*）。

## 工作原理...

默认的自动完成和自动格式化行为可能会让您不爽。您需要与团队讨论如何格式化代码（空格或制表符缩进、缩进大小等），然后相应地配置您的 Visual Studio 设置。

# Visual Studio 中的快捷键

编码时，快捷键确实可以节省您的时间。随时了解快捷键总是很好的。

## 准备工作

有许多快捷键可以让您的编码和项目导航更快速、更高效。在本教程中，我们将介绍如何使用一些常见的快捷键，以真正提高您的编码速度。

## 如何做...

以下是一些非常有用的键盘快捷键供您尝试：

1.  单击代码的一页，然后单击其他地方，至少相隔 10 行代码。现在按下*Ctrl* + *-* [向后导航]。通过按*Ctrl* + *-*和*Ctrl* + *Shift* + *-*分别可以导航到源代码的不同页面（您上次所在的位置和您现在所在的位置）。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00028.jpeg)

### 提示

使用*Ctrl* + *-*在文本编辑器中跳转。光标将跳回到上次所在的位置，即使上次所在的位置距离代码超过 10 行，即使上次所在的位置在另一个文件中。

比如，例如，你正在一个地方编辑代码，然后你想回到你刚刚去过的地方（或者回到你来自的代码部分）。只需按下*Ctrl* + *-*，就会将你传送回到你上次所在的代码位置。要向前传送到你按下*Ctrl* + *-*之前所在的位置，按下*Ctrl* + *Shift* + *-*。要向后传送，前一个位置应该超过 10 行，或者在不同的文件中。这对应于工具栏中的前进和后退菜单按钮：

![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00029.jpeg)

### 提示

工具栏中的后退和前进导航按钮，分别对应*Ctrl* + *-*和*Ctrl* + *Shift* + *-*的快捷键。

1.  按下*Ctrl* + *W*可以高亮显示一个单词。

1.  按住*Ctrl* + *Shift* + 右箭头（或左箭头）（不是*Shift* + 右箭头）来移动到光标的右侧和左侧，选择整个单词。

1.  按下*Ctrl* + *C*复制文本，*Ctrl* + *X*剪切文本，*Ctrl* + *V*粘贴文本。

1.  **剪贴板环**: 剪贴板环是对 Visual Studio 维护的最后一次复制操作堆栈的一种引用。通过按下*Ctrl* + *C*，你将正在复制的文本推送到一个有效的堆栈中。在不同的文本上再次按下*Ctrl* + *C*，将该文本推送到**剪贴板堆栈**中。例如，在下图中，我们先是在单词**cyclic**上按下了*Ctrl* + *C*，然后在单词**paste**上按下了*Ctrl* + *C*。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00030.jpeg)

如你所知，按下*Ctrl* + *V*会粘贴堆栈中的顶部项目。按下*Ctrl* + *Shift* + *V*会访问在该会话中曾经复制的所有项目的非常长的历史记录，也就是堆栈顶部项目下面的项目。在你用尽项目列表后，列表会回到堆栈顶部的项目。这是一个奇怪的功能，但你可能偶尔会发现它有用。

1.  *Ctrl* + *M*，*Ctrl* + *M*折叠代码部分。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00031.jpeg)

## 操作原理...

键盘快捷键可以通过减少编码会话中必须执行的鼠标操作次数来加快代码编辑器中的工作速度。

# 在 Visual Studio 中扩展鼠标使用

鼠标是一个非常方便的选择文本的工具。在这一部分，我们将介绍如何以一种高级的方式使用鼠标快速编辑代码文本。

## 操作步骤...

1.  按住*Ctrl*键单击以选择整个单词。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00032.jpeg)

1.  按住*Alt*键选择文本框（*Alt* + 左键单击 + 拖动）。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00033.jpeg)

然后你可以剪切、复制或覆盖方框形的文本区域。

## 操作原理...

单纯的鼠标点击可能很繁琐，但通过*Ctrl* + *Alt*的帮助，它变得非常酷。尝试*Alt* + 左键单击 + 拖动来选择一行文本，然后进行输入。你输入的字符将在行中重复出现。

# UE4 – 安装

安装和配置 UE4 需要遵循一系列步骤。在这个教程中，我们将详细介绍引擎的正确安装和设置。

## 准备工作

UE4 需要相当多的 GB 空间，所以你应该在目标驱动器上至少有 20GB 左右的空间来进行安装。

## 操作步骤...

1.  访问 unrealengine.com 并下载它。如果需要，注册一个账户。

1.  通过双击`EpicGamesLauncherInstaller-x.x.x-xxx.msi`安装程序来运行 Epic Games Launcher 程序的安装程序。在默认位置安装它。

1.  安装 Epic Games Launcher 程序后，通过双击桌面上的图标或开始菜单中的图标打开它。

1.  浏览起始页面，四处看看。最终，你需要安装一个引擎。点击**UE4**选项卡顶部左侧的大橙色**安装引擎**按钮，如下图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00034.jpeg)

1.  弹出对话框将显示可以安装的组件。选择您想要安装的组件。建议首先安装前三个组件（**核心组件**，**入门内容**和**模板和功能包**）。如果不打算使用，可以不安装**用于调试的编辑符号**组件。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00035.jpeg)

1.  引擎安装完成后，**安装引擎**按钮将变为**启动引擎**按钮。

## 它是如何工作的...

Epic Games Launcher 是您需要启动引擎本身的程序。它在**库**选项卡中保存了所有您的项目和库的副本。

## 还有更多...

尝试在**库** | **保险库**部分下载一些免费的库包。为此，请单击左侧的**库**项目，并向下滚动，直到看到**保险库**，位于**我的项目**下方。

# UE4 - 第一个项目

在 UE4 中设置项目需要多个步骤。重要的是要正确选择选项，以便您可以获得自己喜欢的设置，因此在构建第一个项目时，请仔细遵循这个配方。

在 UE4 中创建的每个项目至少占用 1GB 左右的空间，因此您应该决定是否要将创建的项目放在同一目标驱动器上，还是放在外部或单独的硬盘驱动器上。

## 如何操作...

1.  从 Epic Games Launcher 中，单击**启动虚幻引擎 4.11.2**按钮。一旦您进入引擎，将出现创建新项目或加载现有项目的选项。

1.  选择**新项目**选项卡。

1.  决定您是否将使用 C++来编写项目，还是仅使用蓝图。

1.  如果仅使用蓝图，从**蓝图**选项卡中选择要使用的模板。

1.  如果除了蓝图之外还要使用 C++来构建项目，请从**C++**选项卡中选择项目模板来构建项目。

1.  如果不确定要基于哪个模板编写代码，BASIC Code 是任何 C++项目的绝佳起点（或者对于仅蓝图的项目，选择 Blank）。

1.  查看模板列表下方出现的三个图标。这里有三个配置选项：

1.  您可以选择目标桌面或移动应用程序。

1.  您可以选择修改质量设置（带有魔法植物的图片）。但您可能不需要修改这些。质量设置在**引擎** | **引擎可扩展性设置**下是可重新配置的。

1.  最后一个选项是是否将**入门内容**包含在项目中。您可能可以在项目中使用**入门内容**包。它包含一些出色的材料和纹理。

### 提示

如果不喜欢**入门内容**包，请尝试 UE4 市场中的包。那里有一些出色的免费内容，包括**GameTextures Material Pack**。

1.  选择要保存项目的驱动器和文件夹。请记住，每个项目大约占用 1GB 的空间，您需要目标驱动器上至少有这么多的空间。

1.  给您的项目命名。最好将其命名为与您计划创建的内容相关的独特名称。

1.  点击**创建**。UE4 编辑器和 Visual Studio 2015 窗口都应该弹出，使您能够编辑您的项目。

### 提示

将来，请记住，您可以通过以下两种方法之一打开 Visual Studio 2015 Solution：

+   通过您的本地文件浏览器。导航到项目存储的根目录，并双击`ProjectName.sln`文件。

+   从 UE4 中，单击**文件** | **打开 Visual Studio**。

# UE4 - 创建您的第一个级别

在 UE4 中创建级别非常容易，并且通过一个很好的 UI 得到了很好的促进。在这个配方中，我们将概述基本的编辑器使用，并描述一旦您启动了第一个项目后如何构建您的第一个级别。

## 准备工作

完成上一个配方，*UE4 - 第一个项目*。一旦您构建了一个项目，我们就可以继续创建一个级别。

## 如何操作...

1.  在开始新项目时设置的默认关卡将包含一些默认几何图形和风景。但是，您不需要从这些入门内容开始。如果您不想从中构建，可以删除它，或者创建一个新关卡。

1.  要创建一个新关卡，请单击**文件** | **新建关卡…**，然后选择创建一个带有背景天空（**默认**）或不带背景天空（**空关卡**）的关卡。

### 提示

如果选择创建一个不带背景天空的关卡，请记住您必须向其添加**灯光**，以有效地查看您添加到其中的几何图形。

1.  如果在项目创建时加载了**入门内容**（或其他内容），那么您可以使用**内容浏览器**将内容拉入您的关卡。只需从**内容浏览器**将您的内容实例拖放到关卡中，保存并启动它们。

1.  使用**模式**面板（**窗口** | **模式**）向您的关卡添加一些几何图形。确保单击灯泡和立方体的图片以访问可放置的几何图形。您还可以通过单击**模式**选项卡上左侧的**灯光**子选项卡来添加灯光。![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00036.jpeg)

### 注意

**模式**面板包含两个有用的项目，用于构建关卡：一些示例几何图形（立方体和球等）以及一个充满灯光的面板。尝试这些并进行实验，开始布置您的关卡。

# UE4 - 使用 UE_LOG 记录

记录对于输出内部游戏数据非常重要。使用日志工具可以让您将信息打印到 UE4 编辑器中一个方便的**输出日志**窗口中。

## 准备工作

在编码时，有时我们可能希望将一些调试信息发送到 UE 日志窗口。使用`UE_LOG`宏是可能的。日志消息是一种非常重要和方便的方式，可以在开发程序时跟踪信息。

## 如何做…

1.  在您的代码中，输入一行代码，使用以下形式：

```cpp
UE_LOG(LogTemp, Warning, TEXT("Some warning message") );

```

1.  在 UE4 编辑器中打开**输出日志**，以便在程序运行时在该窗口中看到打印的日志消息。![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00037.jpeg)

## 它是如何工作的…

`UE_LOG`宏接受至少三个参数：

+   日志类别（我们在这里使用`LogTemp`来表示临时日志中的日志消息）

+   日志级别（我们在这里使用警告来表示以黄色警告文本打印的日志消息）

+   用于日志消息文本的实际文本的字符串

不要忘记在日志消息文本周围使用`TEXT()`宏！它会将封闭的文本提升为 Unicode（它会在前面加上 L），当编译器设置为使用 Unicode 时。

`UE_LOG`也接受可变数量的参数，就像 C 编程语言中的`printf()`一样。

```cpp
int intVar = 5;
float floatVar = 3.7f;
FString fstringVar = "an fstring variable";
UE_LOG(LogTemp, Warning, TEXT("Text, %d %f %s"), intVar, floatVar, *fstringVar );

```

在使用`UE_LOG`时，`FString`变量前面会有一个星号`*`，用于**取消引用**`FString`到常规的 C 样式`TCHAR`指针。

### 提示

`TCHAR`通常被定义为一个变量类型，如果编译中使用了 Unicode，则`TCHAR`解析为`wchar_t`。如果关闭了 Unicode（编译器开关`_UNICODE`未定义），那么`TCHAR`解析为简单的 char。

在不再需要来自源的日志消息时，不要忘记清除它们！

# UE4 - 从 FStrings 和其他变量创建 FString

在 UE4 编码时，通常希望从变量构造一个字符串。使用`FString::Printf`或`FString::Format`函数非常容易。

## 准备工作

为此，您应该有一个现有的项目，可以在其中输入一些 UE4 C++代码。通过**打印**可以将变量放入字符串中。将变量打印到字符串中可能有些反直觉，但您不能简单地将变量连接在一起，希望它们会自动转换为字符串，就像 JavaScript 等某些语言中那样。

## 如何做…

1.  使用`FString::Printf()`：

1.  考虑您想要打印到字符串中的变量。

1.  打开并查看`printf`格式说明符的参考页面，例如[`en.cppreference.com/w/cpp/io/c/fprintf`](http://en.cppreference.com/w/cpp/io/c/fprintf)。

1.  尝试以下代码：

```cpp
FString name = "Tim";
int32 mana = 450;
FString string = FString::Printf( TEXT( "Name = %s Mana = %d" ), *name, mana );
```

注意前面的代码块如何精确地使用格式说明符，就像传统的`printf`函数一样。在前面的示例中，我们使用`%s`将一个字符串放入格式化的字符串中，使用`%d`将一个整数放入格式化的字符串中。不同类型的变量存在不同的格式说明符，你应该在 cppreference.com 等网站上查找它们。

1.  使用`FString::Format()`。以以下形式编写代码：

```cpp
FString name = "Tim";
int32 mana = 450;
TArray< FStringFormatArg > args;
args.Add( FStringFormatArg( name ) );
args.Add( FStringFormatArg( mana ) );
FString string = FString::Format( TEXT( "Name = {0} Mana = {1}" ), args );
UE_LOG( LogTemp, Warning, TEXT( "Your string: %s" ), *string );
```

使用`FString::Format()`，而不是使用正确的格式说明符，我们使用简单的整数和`FStringFormatArg`的`TArray`。`FstringFormatArg`帮助`FString::Format()`推断要放入字符串的变量类型。

# GitHub 上的项目管理-获取你的源代码控制

在开发项目时非常重要的一件事是在工作时生成时间线历史。为此，你需要定期备份你的源代码。Git 是一个很好的工具，可以做到这一点。Git 允许你将更改（提交）存储到远程服务器上的在线存储库中，以便你的代码的开发历史被记录并保存在远程服务器上。如果你的本地副本出现了损坏，你总是可以从在线备份中恢复。你的代码库开发的时间线历史被称为**源代码控制**。

## 准备工作

有一些免费的在线源备份服务。一些免费的存储数据的替代方案包括：

+   **Visualstudio.com**：有限/私人分享你的存储库

+   **github.com**：无限公开分享你的存储库

Visualstudio.com 非常适合免费为你的项目提供一些隐私，而 GitHub 非常适合免费与大量用户分享你的项目。Visualstudio.com 还提供一些非常好的工作板和规划功能，我们稍后会在本文中使用（GitHub 也提供竞争对手问题跟踪器，我们稍后也会讨论）。

你选择的网站主要取决于你计划如何分享你的代码。在本文中，我们将使用 GitHub 进行源代码存储，因为我们需要与大量用户（包括你！）分享我们的代码。

## 如何做...

1.  在[`github.com`](https://github.com)注册一个 GitHub 账户。使用**Team Explorer**菜单（**View** | **Team Explorer**）登录到你的 GitHub 账户。

1.  一旦打开**Team Explorer**，你可以使用**Team Explorer**窗口中出现的按钮登录到你的 GitHub 账户。

1.  在你登录后，你应该获得**Clone**和**Create**存储库的能力。这些选项将出现在**Team Explorer**中 GitHub 菜单的正下方。

1.  从这里，我们想要创建我们的第一个存储库。点击**Create**按钮，在弹出的窗口中命名你的存储库。

### 提示

在创建项目时，要小心从`.gitignore`选项菜单中选择**VisualStudio**选项。这将导致 Git 忽略你不想包含在存储库中的 Visual Studio 特定文件，例如构建和发布目录。

1.  现在你有了一个存储库！存储库在 GitHub 上初始化。我们只需要把一些代码放进去。

1.  打开 Epic Games Launcher，并创建一个要放入存储库的项目。

1.  在 Visual Studio 2015 中打开 C++项目，右键单击解决方案。从出现的上下文菜单中选择**Add Solution to Source Control**。出现的对话框会询问你是否要使用**Git**还是**TFVC**。

### 提示

如果你使用**Git**进行源代码控制，那么你可以托管在 github.com 或 Visualstudio.com 上。

1.  在将 Git 源代码控制添加到项目后，再次查看**Team Explorer**。从那个窗口，你应该输入一个简短的消息，然后点击**Commit**按钮。

## 它是如何工作的...

Git 存储库对于备份代码和项目文件的副本在项目发展过程中非常重要。Git 中有许多命令可用于浏览项目历史记录（尝试 Git GUI 工具），查看自上次提交以来的更改（`git diff`），或在 Git 历史记录中向后和向前移动（`git checkout commit-hash-id`）。

# GitHub 上的项目管理-使用问题跟踪器

跟踪您项目的进展、功能和错误非常重要。GitHub 问题跟踪器将使您能够做到这一点。

## 准备工作

跟踪您项目计划的功能和运行问题非常重要。GitHub 的问题跟踪器可用于创建您想要添加到项目中的功能列表，以及您需要在将来某个时候修复的错误。

## 如何做...

1.  要向您的问题跟踪器添加问题，首先选择您想要编辑的存储库，方法是转到 GitHub 的首页并选择

+   `您输入错误或功能描述的框支持**Markdown**`**。Markdown 是一种简化的类似 HTML 的标记语言，让您可以轻松快速地编写类似 HTML 的语法。以下是一些 markdown 语法的示例：

```cpp
# headings
## sub-headings
### sub-sub-headings
_italics_, __bold__, ___bold-italics___
[hyperlinks](http://towebsites.com/)

code (indented by 4 spaces), preceded by a blank line

* bulleted
* lists
  - sub bullets
    - sub sub bullets

>quotations
```

### 提示

如果您想了解更多关于 Markdown 语法的信息，请查看[`daringfireball.net/projects/markdown/syntax`](https://daringfireball.net/projects/markdown/syntax)。** * **您还可以将问题标记为错误、增强（功能）或其他任何您喜欢的标签。通过**问题** | **标签**链接可以自定义标签：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00041.jpeg)*** **从那里，您可以编辑、更改标签的颜色，或删除您的标签。我删除了所有的默认标签，并用`feature`替换了**增强**一词，如下两个屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00042.jpeg)![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00043.jpeg)*** **一旦您完全自定义了您的标签，您的 GitHub **问题跟踪器**就会更容易导航。通过使用适当的标签对问题进行优先处理。** **## 它是如何工作的...

GitHub 的问题跟踪器是跟踪项目中的错误和功能的绝佳方式。使用它不仅可以组织您的工作流程，还可以保持项目上所做工作的出色历史记录。

## 另请参阅

+   你还应该查看 Wiki 功能，它允许你记录你的源代码

# 在 VisualStudio.com 上的项目管理-管理项目中的任务

通常使用规划工具进行项目的高级管理。GitHub 的**问题跟踪器**可能满足您的需求，但如果您想要更多，Microsoft 的 Visual Studio Team Services 提供了**Scrum**和**Kanban**风格编程任务（功能，错误等）的规划工具。

使用此工具是组织任务的绝佳方式，以确保按时完成任务，并适应工业标准的工作流程。在安装过程中注册 Visual Studio 的社区版时，您的帐户将包括免费使用这些工具。

## 如何做...

在本节中，我们将描述如何使用 Visualstudio.com 上的**Workboard**功能来规划一些简单的任务。

1.  要创建自己的项目 Workboard，请转到 Visualstudio.com 上的您的帐户。登录，然后选择**概述**选项卡。在**最近的项目和团队标题**下，选择**新建**链接。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00044.jpeg)

1.  向您的项目添加**项目名称**和**描述**。在命名您的项目之后（我命名为`Workboards`），单击**创建项目**。您将等待一两秒钟以完成项目创建，然后在下一个对话框中单击**导航到项目**按钮。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00045.jpeg)

1.  下一个显示的屏幕允许您导航到**Workboards**区域。单击**管理工作**。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00046.jpeg)

1.  **管理工作**屏幕是项目中要做的事情的看板式（即：优先级）任务队列。您可以点击**新项目**按钮来添加新项目到您的待办事项列表中。![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00047.jpeg)

### 提示

一旦您将某些东西添加到您的待办事项列表中，它就被称为是您的待办事项的一部分。在看板中，您总是落后！如果您是经理，您永远不希望待办事项为空。

## 工作原理…

您看板的待办事项中的每个项目都被称为**用户故事**。用户故事是敏捷软件开发术语，每个用户故事都应该描述特定最终用户的需求。例如，在前面的用户故事中，需求是有可视图形，用户故事描述了必须创建图形（精灵）来满足这个用户需求。

用户故事通常有一个特定的格式：

### 注意

作为<某人>，我想要<这样做>，这样我就可以<获得好处>。

例如：

### 注意

作为<游戏玩家>，我想要<重新组织物品>，这样我就可以<将热键设置为我想要的槽位>。

在工作板上，您将有许多用户故事。我之前放置了一些用户故事，所以我们可以与它们一起玩。

一旦您的看板上充满了用户故事，它们都将位于新的垂直列中。当您开始或者在特定用户故事上取得进展时，您可以将其从**新**水平拖动到**活跃**，最后到**已解决**和**已关闭**，当用户故事完成时。

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00048.jpeg)

# 在 VisualStudio.com 上进行项目管理 - 构建用户故事和任务

从 Scrum 的角度来看，用户故事是需要完成的任务的分组。一组用户故事可以被收集到一个**特性**中，一组特性可以被聚集到一个称为**史诗**的东西中。VisualStudio.com 非常好地组织了用户故事的创建，以便轻松构建和规划完成任何特定任务（用户故事）。在这个教程中，我们将描述如何组装和整理用户故事。

## 准备工作

在 VisualStudio.com 的项目管理套件中输入的每个项目都应该是某人希望出现在软件中的特性。用户故事的创建是一种有趣、简单和令人兴奋的方式，可以将一堆任务分组并分配给您的程序员作为要完成的工作。立即登录到您的 VisualStudio.com 帐户，编辑其中一个项目，并开始使用此功能。

## 如何做…

1.  从 VisualStudio.com 的**团队服务**首页，导航到您想要输入一些新工作的项目。如果您点击**最近的项目和团队**下的**浏览**，您可以找到所有的项目。![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00049.jpeg)

1.  选择您想要使用的项目并点击**导航**。

1.  Visualstudio.com 中的任务发生在三种超级任务类别之一中：

+   用户故事

+   特性

+   史诗

### 提示

用户故事，特性和史诗只是工作的组织单位。史诗包含许多特性。特性包含许多用户故事，用户故事包含许多任务。

默认情况下，**史诗**不会显示。您可以通过转到设置（屏幕右侧的齿轮图标）来显示**史诗**。然后导航到**常规** | **待办事项**。在**仅查看您的团队管理的待办事项**部分下，选择显示所有三种待办事项：**史诗**，**特性**和**故事**。

1.  在您可以将第一个任务（用户故事）输入到**待办事项**之前，现在有四个导航步骤要执行：

1.  从顶部的菜单栏中选择**工作**。

1.  然后，在**工作**页面上出现的子菜单中，选择**待办事项**。

1.  在出现的侧边栏中，点击**故事**。

1.  从右侧面板中选择**看板**。![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00050.jpeg)

### 提示

Backlog 是我们尚未完成的用户故事和任务集。你可能会想，“全新的任务真的会被输入到 Backlog 中吗？”没错！你已经落后了！Scrum 术语的含义似乎暗示着“工作过剩”。

1.  从右侧面板中，点击**新项目**，并填写你的新**用户故事**项目的文本。

1.  点击**用户故事**卡的文本，并填写**受让人**、它所属的**迭代**、**描述**、**标签**以及你想探索的**详情**选项卡的任何其他字段。

1.  接下来，我们将整个**用户故事**分解为一系列可实现的任务。将鼠标悬停在新的**用户故事**项目上，直到出现省略号（三个点…）。点击省略号，然后选择**+添加任务**。

1.  列出完成**用户故事**的细节，以一系列任务的形式。

1.  将每个任务分配给：

+   一个受让人

+   一个迭代

### 提示

简单来说，迭代实际上只是一个时间段。在每个迭代结束时，你应该有一个可交付的、可测试的软件完成品。迭代是一个时间段，指的是产生你惊人软件的另一个版本（用于测试和可能的发布）。

1.  随着项目开发功能完成和错误修复，继续向项目添加任务。

## 它是如何工作的…

史诗包含许多特性。特性包含许多用户故事，用户故事包含许多任务和测试。

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00051.jpeg)

所有这些项目都可以分配给一个用户（一个实际的人），以及一个迭代（时间段），用于分配责任和安排任务。一旦分配了这些，任务应该出现在**查询**选项卡中。

### 提示

在本书的前言中提到了下载代码包的详细步骤。请查看一下。

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Unreal-Engine-4-Scripting-with-CPlusPlus-Cookbook`](https://github.com/PacktPublishing/Unreal-Engine-4-Scripting-with-CPlusPlus-Cookbook)。我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！


# 第二章：创建类

本章重点介绍如何创建与 UE4 蓝图编辑器良好集成的 C++类和结构。这些类是常规 C++类的毕业版本，称为`UCLASS`。

### 提示

`UCLASS`只是一个带有大量 UE4 宏装饰的 C++类。这些宏生成额外的 C++头文件代码，使其能够与 UE4 编辑器本身集成。

使用`UCLASS`是一个很好的实践。如果配置正确，`UCLASS`宏可能会使你的`UCLASS`可蓝图化。使你的`UCLASS`可蓝图化的优势在于，它可以使你的自定义 C++对象具有蓝图可视编辑属性（`UPROPERTY`），并带有方便的 UI 小部件，如文本字段、滑块和模型选择框。你还可以在蓝图图表中调用函数（`UFUNCTION`）。这两者都显示在以下截图中：

![创建类](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00052.jpeg)

在左边，两个装饰为`UPROPERTY`的类成员（一个`UTexture`引用和一个`FColor`）显示在 C++类的蓝图中进行编辑。在右边，一个标记为`BlueprintCallable`的 C++函数`GetName`显示为可以从蓝图图表中调用的`UFUNCTION`。

### 注意

`UCLASS`宏生成的代码将位于`ClassName.generated.h`文件中，这将是你的`UCLASS`头文件`ClassName.h`中所需的最后一个`#include`。

以下是本章将涵盖的主题：

+   制作`UCLASS`-派生自`UObject`

+   创建可编辑的`UPROPERTY`

+   从蓝图中访问`UPROPERTY`

+   指定`UCLASS`作为`UPROPERTY`的类型

+   从你的自定义`UCLASS`创建蓝图

+   实例化`UObject`派生类（`ConstructObject <>`和`NewObject <>`）

+   销毁`UObject`派生类

+   创建`USTRUCT`

+   创建`UENUM()`

+   创建`UFUNCTION`

### 提示

你会注意到，即使我们在这个类中创建的示例对象是可蓝图化的，它们也不会被放置在关卡中。这是因为为了放置在关卡中，你的 C++类必须派生自`Actor`基类，或者在其下。有关更多详细信息，请参见第四章，*演员和组件*。

# 介绍

一旦你了解了模式，UE4 代码通常非常容易编写和管理。我们编写的代码用于从另一个`UCLASS`派生，或者创建`UPROPERTY`或`UFUNCTION`非常一致。本章提供了围绕基本`UCLASS`派生、属性和引用声明、构造、销毁和一般功能的常见 UE4 编码任务的示例。

# 制作`UCLASS`-派生自 UObject

使用 C++编码时，你可以拥有自己的代码，编译并运行为本机 C++代码，适当调用`new`和`delete`来创建和销毁你的自定义对象。只要你的`new`和`delete`调用适当配对，以便在你的 C++代码中没有泄漏，本机 C++代码在你的 UE4 项目中是完全可接受的。

然而，你也可以声明自定义的 C++类，它们的行为类似于 UE4 类，通过将你的自定义 C++对象声明为`UCLASS`。`UCLASS`使用 UE4 的智能指针和内存管理例程进行分配和释放，根据智能指针规则进行加载和读取，可以从蓝图中访问。

### 提示

请注意，当您使用`UCLASS`宏时，您的`UCLASS`对象的创建和销毁必须完全由 UE4 管理：您必须使用`ConstructObject`来创建对象的实例（而不是 C++本机关键字`new`），并调用`UObject::ConditionalBeginDestroy()`来销毁对象（而不是 C++本机关键字`delete`）。如何创建和销毁您的`UObject`派生类在本章后面的*实例化 UObject 派生类（ConstructObject <>和 NewObject <>）*和*销毁 UObject 派生类*部分中有详细说明。

## 准备工作

在本配方中，我们将概述如何编写一个使用`UCLASS`宏的 C++类，以启用托管内存分配和释放，并允许从 UE4 编辑器和蓝图中访问。您需要一个 UE4 项目，可以在其中添加新代码以使用此配方。

## 如何做...

要创建自己的`UObject`派生类，请按照以下步骤进行：

1.  从正在运行的项目中，在 UE4 编辑器中选择**文件** | **添加 C++类**。

1.  在**添加 C++类**对话框中，转到窗口的右上方，选中**显示所有类**复选框：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00053.jpeg)

1.  通过选择从`Object`父类派生来创建`UCLASS`。`UObject`是 UE4 层次结构的根。您必须选中此对话框右上角的**显示所有类**复选框，才能在列表视图中看到`Object`类。

1.  选择`Object`（层次结构顶部）作为要继承的父类，然后单击**下一步**。

### 提示

请注意，虽然对话框中将写入`Object`，但在您的 C++代码中，您将从实际上以大写`U`开头的`UObject`派生的 C++类。这是 UE4 的命名约定：

从`UObject`（不在`Actor`分支上）派生的`UCLASS`必须以`U`开头命名。

从`Actor`派生的`UCLASS`必须以`A`开头命名（第四章，“演员和组件”）。

不派生自`UCLASS`的 C++类（不具有命名约定），但可以以`F`开头命名（例如`FAssetData`）。

直接派生自`UObject`的派生类将无法放置在级别中，即使它们包含`UStaticMeshes`等可视表示元素。如果要将对象放置在 UE4 级别中，您至少必须从`Actor`类或其下的继承层次结构中派生。请参阅第四章，“演员和组件”了解如何从`Actor`类派生可放置在级别中的对象。

本章的示例代码将无法放置在级别中，但您可以在 UE4 编辑器中基于本章中编写的 C++类创建和使用蓝图。

1.  为您的新的`Object`派生类命名，以适合您正在创建的对象类型。我称我的为`UserProfile`。在 UE4 生成的 C++文件中，这将显示为`UUserObject`，以确保遵循 UE4 的约定（C++ `UCLASS`前面加上`U`）。

1.  转到 Visual Studio，并确保您的类文件具有以下形式：

```cpp
#pragma once

#include "Object.h" // For deriving from UObject
#include "UserProfile.generated.h" // Generated code

// UCLASS macro options sets this C++ class to be 
// Blueprintable within the UE4 Editor
UCLASS( Blueprintable )
class CHAPTER2_API UUserProfile : public UObject
{
  GENERATED_BODY()
};
```

1.  编译并运行您的项目。现在，您可以在 Visual Studio 和 UE4 编辑器中使用自定义的`UCLASS`对象。有关您可以使用它做什么的更多详细信息，请参阅以下配方。

## 工作原理…

UE4 为你的自定义`UCLASS`生成和管理大量的代码。这些代码是由 UE4 宏（如`UPROPERTY`、`UFUNCTION`和`UCLASS`宏本身）的使用而生成的。生成的代码被放入`UserProfile.generated.h`中。你必须为了编译成功，将`UCLASSNAME.generated.h`文件与`UCLASSNAME.h`文件一起`#include`进来。如果不包含`UCLASSNAME.generated.h`文件，编译将失败。`UCLASSNAME.generated.h`文件必须作为`UCLASSNAME.h`中`#include`列表中的最后一个`#include`包含进来：

| 正确 | 错误 |
| --- | --- |

|

```cpp
#pragma once

#include "Object.h"
#include "Texture.h"
// CORRECT: .generated.h last file
#include "UserProfile.generated.h"
```

|

```cpp
#pragma once

#include "Object.h"
#include "UserProfile.generated.h" 
// WRONG: NO INCLUDES AFTER
// .GENERATED.H FILE
#include "Texture.h"
```

|

当`UCLASSNAME.generated.h`文件不是最后一个包含在包含列表中时，会出现错误：

```cpp
>> #include found after .generated.h file - the .generated.h file should always be the last #include in a header
```

## 还有更多...

这里有一堆关键字，我们想在这里讨论，它们修改了`UCLASS`的行为方式。`UCLASS`可以标记如下：

+   `Blueprintable`：这意味着你希望能够在 UE4 编辑器内的**Class Viewer**中构建一个蓝图（右键单击时，**创建蓝图类...**变为可用）。如果没有`Blueprintable`关键字，即使你可以在**Class Viewer**中找到它并右键单击，**创建蓝图类...**选项也不会对你的`UCLASS`可用：![还有更多...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00054.jpeg)

+   只有当你在`UCLASS`宏定义中指定了`Blueprintable`时，**创建蓝图类...**选项才可用。如果不指定`Blueprintable`，那么生成的`UCLASS`将不可用于蓝图。

+   `BlueprintType`：使用这个关键字意味着`UCLASS`可以作为另一个蓝图中的变量使用。你可以在任何蓝图的**EventGraph**的左侧面板的**Variables**组中创建蓝图变量。如果指定了`NotBlueprintType`，那么你不能将这个蓝图变量类型用作蓝图图表中的变量。在**Class Viewer**中右键单击`UCLASS`名称将不会显示**创建蓝图类...**：![还有更多...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00055.jpeg)

任何指定了`BlueprintType`的`UCLASS`都可以添加为蓝图类图表的变量列表。

你可能不确定是否将你的 C++类声明为`UCLASS`。这真的取决于你。如果你喜欢智能指针，你可能会发现`UCLASS`不仅可以使代码更安全，还可以使整个代码库更连贯和更一致。

## 另请参阅

+   要向蓝图图表添加可编程的`UPROPERTY`，请参阅下面的*创建可编辑的 UPROPERTY*部分。有关使用适当的智能指针引用`UCLASS`实例的详细信息，请参阅第三章，*内存管理和智能指针*。

# 创建可编辑的 UPROPERTY

你声明的每个`UCLASS`可以在其中声明任意数量的`UPROPERTY`。每个`UPROPERTY`可以是一个可视可编辑的字段，或者是`UCLASS`的蓝图可访问的数据成员。

我们可以为每个`UPROPERTY`添加一些限定符，这些限定符会改变它在 UE4 编辑器中的行为，比如`EditAnywhere`（可以更改`UPROPERTY`的屏幕）和`BlueprintReadWrite`（指定蓝图可以随时读写变量，而 C++代码也被允许这样做）。

## 准备工作

要使用这个方法，你应该有一个可以添加 C++代码的 C++项目。此外，你还应该完成前面的方法，*制作一个 UCLASS - 派生自 UObject*。

## 如何做...

1.  在你的`UCLASS`声明中添加成员如下：

```cpp
UCLASS( Blueprintable )
class CHAPTER2_API UUserProfile : public UObject
{
  GENERATED_BODY()
  public:
  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Stats)
  float Armor;
  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Stats)
  float HpMax;
};
```

1.  创建你的`UObject`类派生的蓝图，并通过从对象浏览器中双击打开 UE4 编辑器中的蓝图。

1.  现在你可以在蓝图中为这些新的`UPROPERTY`字段的默认值指定值：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00056.jpeg)

1.  通过将蓝图类的几个实例拖放到您的级别中，并编辑放置的对象上的值（双击它们）来指定每个实例的值。

## 它是如何工作的...

传递给`UPROPERTY()`宏的参数指定了关于变量的一些重要信息。在前面的示例中，我们指定了以下内容：

+   `EditAnywhere`：这意味着`UPROPERTY()`宏可以直接从蓝图中编辑，或者在游戏级别中放置的每个`UClass`对象的每个实例上进行编辑。与以下进行对比：

+   `EditDefaultsOnly`：蓝图的值是可编辑的，但不能在每个实例上进行编辑

+   `EditInstanceOnly`：这将允许在`UClass`对象的游戏级实例中编辑`UPROPERTY()`宏，而不是在基蓝图本身上进行编辑

+   `BlueprintReadWrite`：这表示属性可以从蓝图图中读取和写入。带有`BlueprintReadWrite`的`UPROPERTY()`必须是公共成员，否则编译将失败。与以下进行对比：

+   `BlueprintReadOnly`：属性必须从 C++中设置，不能从蓝图中更改

+   `类别`：您应该始终为您的`UPROPERTY()`指定一个`类别`。`类别`确定了`UPROPERTY()`将出现在属性编辑器中的哪个子菜单下。在`类别=Stats`下指定的所有`UPROPERTY()`将出现在蓝图编辑器中的相同`Stats`区域中。

## 另请参阅

+   完整的`UPROPERTY`列表位于[`docs.unrealengine.com/latest/INT/Programming/UnrealArchitecture/Reference/Properties/Specifiers/index.html`](https://docs.unrealengine.com/latest/INT/Programming/UnrealArchitecture/Reference/Properties/Specifiers/index.html)。浏览一下。

# 从蓝图中访问 UPROPERTY

从蓝图中访问`UPROPERTY`非常简单。成员必须作为`UPROPERTY`公开在您的蓝图图中要访问的成员变量上。您必须在宏声明中限定`UPROPERTY`，指定它是`BlueprintReadOnly`还是`BlueprintReadWrite`，以指定您是否希望变量从蓝图中只读取（仅）或甚至可以从蓝图中写入。

您还可以使用特殊值`BlueprintDefaultsOnly`来指示您只希望默认值（在游戏开始之前）可以从蓝图编辑器中进行编辑。`BlueprintDefaultsOnly`表示数据成员不能在运行时从蓝图中编辑。

## 如何做到...

1.  创建一些`UObject`派生类，指定`Blueprintable`和`BlueprintType`，例如以下内容：

```cpp
UCLASS( Blueprintable, BlueprintType )
class CHAPTER2_API UUserProfile : public UObject
{
  GENERATED_BODY()
  public:
  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Stats)
  FString Name;
};
```

在`UCLASS`宏中的`BlueprintType`声明是使用`UCLASS`作为蓝图图中的类型所必需的。

1.  在 UE4 编辑器中，从 C++类派生一个蓝图类，如*从自定义 UCLASS 创建蓝图*中所示。

1.  通过将实例从**内容浏览器**拖放到主游戏世界区域中，在 UE4 编辑器中创建您的蓝图派生类的实例。它应该出现为游戏世界中的一个圆形白色球，除非您已为其指定了模型网格。

1.  在允许函数调用的蓝图图中（例如**级别蓝图**，通过**蓝图** | **打开级别蓝图**访问），尝试打印您的 Warrior 实例的**Name**属性，如下截图所示：![如何做到...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00057.jpeg)

### 提示

导航蓝图图很容易。右键单击并拖动以平移蓝图图；*Alt* +右键单击+拖动以缩放。

## 它是如何工作的...

`UPROPERTY`会自动为 UE4 类编写`Get`/`Set`方法。但是，它们不能在`UCLASS`中声明为`private`变量。如果它们没有声明为`public`或`protected`成员，您将收到形式为的编译器错误：

```cpp
>> BlueprintReadWrite should not be used on private members
```

# 指定 UCLASS 作为 UPROPERTY 的类型

因此，您已经构建了一些用于在 UE4 中使用的自定义`UCLASS`。但是如何实例化它们呢？UE4 中的对象是引用计数和内存管理的，因此您不应该直接使用 C++关键字`new`来分配它们。相反，您将不得不使用一个名为`ConstructObject`的函数来实例化您的`UObject`派生类。`ConstructObject`不仅需要您创建对象的 C++类，还需要一个 C++类的蓝图类派生（`UClass*`引用）。`UClass*`引用只是指向蓝图的指针。

我们如何在 C++代码中实例化特定蓝图的实例？C++代码不应该知道具体的`UCLASS`名称，因为这些名称是在 UE4 编辑器中创建和编辑的，您只能在编译后访问。我们需要以某种方式将蓝图类名称传递给 C++代码以实例化。

我们通过让 UE4 程序员从 UE4 编辑器中列出的所有可用蓝图（从特定 C++类派生）的简单下拉菜单中选择 C++代码要使用的`UClass`来实现这一点。为此，我们只需提供一个可编辑的`UPROPERTY`，其中包含一个`TSubclassOf<C++ClassName>`类型的变量。或者，您可以使用`FStringClassReference`来实现相同的目标。

这使得在 C++代码中选择`UCLASS`就像选择要使用的纹理一样。`UCLASS`应该被视为 C++代码的资源，它们的名称不应该硬编码到代码库中。

## 准备工作

在您的 UE4 代码中，您经常需要引用项目中的不同`UCLASS`。例如，假设您需要知道玩家对象的`UCLASS`，以便在代码中使用`SpawnObject`。从 C++代码中指定`UCLASS`非常麻烦，因为 C++代码根本不应该知道在蓝图编辑器中创建的派生`UCLASS`的具体实例。就像我们不希望将特定资产名称嵌入 C++代码中一样，我们也不希望将派生的蓝图类名称硬编码到 C++代码中。

因此，我们在 UE4 编辑器中使用 C++变量（例如`UClassOfPlayer`），并从蓝图对话框中进行选择。您可以使用`TSubclassOf`成员或`FStringClassReference`成员来实现，如下面的屏幕截图所示：

![准备工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00058.jpeg)

## 如何做…

1.  导航到您想要向其添加`UCLASS`引用成员的 C++类。例如，装饰一个类派生的`UCLASS`玩家相当容易。

1.  在`UCLASS`内部，使用以下形式的代码声明`UPROPERTY`，允许选择从层次结构中派生的`UObject`的`UClass`（蓝图类）：

```cpp
UCLASS()
class CHAPTER2_API UUserProfile : public UObject
{
  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Unit)
  TSubclassOf<UObject> UClassOfPlayer; // Displays any UClasses
  // deriving from UObject in a dropdown menu in Blueprints

  // Displays string names of UCLASSes that derive from
  // the GameMode C++ base class
  UPROPERTY( EditAnywhere, meta=(MetaClass="GameMode"), Category = Unit )
  FStringClassReference UClassGameMode;
};
```

1.  将 C++类制作成蓝图，然后打开该蓝图。单击`UClassOfPlayer`菜单旁边的下拉菜单。

1.  从列出的`UClass`的下拉菜单中选择适当的`UClassOfPlayer`成员。

## 它是如何工作的…

### TSubclassOf

`TSubclassOf< >`成员将允许您在 UE4 编辑器内编辑具有`TSubclassOf< >`成员的任何蓝图时，使用下拉菜单指定`UClass`名称。

### FStringClassReference

`MetaClass`标签是指您期望`UClassName`派生自哪个基本 C++类。这将限制下拉菜单的内容仅显示从该 C++类派生的蓝图。如果您希望显示项目中的所有蓝图，可以省略`MetaClass`标签。

# 从您的自定义 UCLASS 创建蓝图

制作蓝图只是从您的 C++对象派生蓝图类的过程。从您的 UE4 对象创建蓝图派生类允许您在编辑器中可视化编辑自定义`UPROPERTY`。这避免了将任何资源硬编码到您的 C++代码中。此外，为了使您的 C++类能够放置在关卡中，必须首先制作成蓝图。但是，只有在蓝图下面的 C++类是`Actor`类派生类时才可能。

### 注意

有一种方法可以使用`FStringAssetReferences`和`StaticLoadObject`来加载资源（例如纹理）。然而，通常不鼓励通过将路径字符串硬编码到您的 C++代码中来加载资源。在`UPROPERTY()`中提供可编辑的值，并从正确的具体类型的资产引用中加载是一个更好的做法。

## 准备工作

要按照此步骤进行操作，您需要有一个构建好的`UCLASS`，您希望从中派生一个蓝图类（请参阅本章前面的*制作 UCLASS-从 UObject 派生*部分）。您还必须在`UCLASS`宏中将您的`UCLASS`标记为`Blueprintable`，以便在引擎内部进行蓝图制作。

### 提示

任何在`UCLASS`宏声明中具有`Blueprintable`元关键字的`UObject`派生类都可以制作成蓝图。

## 如何操作…

1.  要将您的`UserProfile`类制作成蓝图，首先确保`UCLASS`在`UCLASS`宏中具有`Blueprintable`标记。应如下所示：

```cpp
UCLASS( Blueprintable )
class CHAPTER2_API UUserProfile : public UObject
```

1.  编译并运行您的代码。

1.  在**类查看器**中找到`UserProfile` C++类（**窗口** | **开发人员工具** | **类查看器**）。由于先前创建的`UCLASS`不是从`Actor`派生的，因此要找到您的自定义`UCLASS`，您必须在**类查看器**中关闭**筛选器** | **仅显示角色**（默认已选中）：![如何操作…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00059.jpeg)

关闭**仅显示角色**复选标记，以显示**类查看器**中的所有类。如果不这样做，那么您的自定义 C++类可能不会显示！

### 提示

请记住，您可以使用**类查看器**中的小搜索框轻松找到`UserProfile`类，只需开始输入即可：

![如何操作…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00060.jpeg)

1.  在**类查看器**中找到您的`UserProfile`类，右键单击它，并通过选择**创建蓝图…**从中创建一个蓝图。

1.  给您的蓝图命名。有些人喜欢在蓝图类名之前加上`BP_`。您可以选择遵循这个惯例，也可以不遵循，只要确保保持一致即可。

1.  双击**内容浏览器**中出现的新蓝图，看一看。您将能够为创建的每个`UserProfile`蓝图实例编辑**名称**和**电子邮件**字段。

## 它是如何工作的…

在 UE4 编辑器中，您创建的任何具有`Blueprintable`标记的 C++类都可以在蓝图中使用。蓝图允许您在 UE4 的可视 GUI 界面中自定义 C++类的属性。

# 实例化`UObject`派生类（ConstructObject <>和 NewObject <>）

在 C++中创建类实例通常使用关键字`new`。但是，UE4 实际上在内部创建其类的实例，并要求您调用特殊的工厂函数来生成任何要实例化的`UCLASS`的副本。您创建的是 UE4 蓝图类的实例，而不仅仅是 C++类。当您创建`UObject`派生类时，您将需要使用特殊的 UE4 引擎函数来实例化它们。

工厂方法允许 UE4 在对象上进行一些内存管理，控制对象在删除时的行为。该方法允许 UE4 跟踪对象的所有引用，以便在对象销毁时轻松取消所有对对象的引用。这确保了程序中不存在指向无效内存的悬空指针。

## 准备工作

实例化不是`AActor`类派生类的`UObject`派生类不使用`UWorld::SpawnActor< >`。相反，我们必须使用名为`ConstructObject< >`或`NewObject< >`的特殊全局函数。请注意，您不应该使用裸的 C++关键字`new`来分配您的 UE4 `UObject`类派生的新实例。

您至少需要两个信息来正确实例化您的`UCLASS`实例：

+   一个指向您想要实例化的类类型（蓝图类）的 C++类型的`UClass`引用。

+   蓝图类派生的原始 C++基类

## 如何做...

1.  在全局可访问的对象（如您的`GameMode`对象）中，添加一个`TSubclassOf< YourC++ClassName > UPROPERTY()`来指定并提供`UCLASS`名称给您的 C++代码。例如，我们在我们的`GameMode`对象中添加以下两行：

```cpp
UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = UClassNames )
TSubclassOf<UUserProfile> UPBlueprintClassName;
```

1.  进入 UE4 编辑器，并从下拉菜单中选择您的`UClass`名称，以便您可以看到它的作用。保存并退出编辑器。

1.  在您的 C++代码中，找到您想要实例化`UCLASS`实例的部分。

1.  使用以下公式使用`ConstructObject< >`实例化对象：

```cpp
ObjectType* object = ConstructObject< ObjectType >( UClassReference );
```

例如，使用我们在上一个示例中指定的`UserProfile`对象，我们将得到如下代码：

```cpp
// Get the GameMode object, which has a reference to 
// the UClass name that we should instantiate:
AChapter2GameMode *gm = Cast<AChapter2GameMode>( GetWorld()->GetAuthGameMode() );
if( gm )
{
  UUserProfile* object = ConstructObject<UUserProfile>( gm->UPBlueprintClassName );
}
```

### 提示

如果您愿意，您也可以使用`NewObject`函数如下：

```cpp
UProfile* object = NewObject<UProfile>( GetTransientPackage(), uclassReference );
```

## 它是如何工作的...

使用`ConstructObject`或`NewObject`实例化`UObject`类很简单。`NewObject`和`ConstructObject`几乎做同样的事情：实例化一个蓝图类类型的对象，并返回正确类型的 C++指针。

不幸的是，`NewObject`有一个讨厌的第一个参数，它要求您在每次调用时传递`GetTransientPackage()`。`ConstructObject`在每次调用时不需要此参数。此外，`ConstructObject`为您提供了更多的构造选项。

在构造您的 UE4 `UObject`派生类时不要使用关键字`new`！它将无法得到正确的内存管理。

## 还有更多...

`NewObject`和`ConstructObject`是面向对象编程世界所谓的工厂。您要求工厂为您制造对象-您不会自己构造它。使用工厂模式使引擎能够轻松跟踪对象的创建过程。

# 销毁 UObject 派生类

在 UE4 中删除任何`UObject`派生类都很简单。当您准备删除您的`UObject`派生类时，我们只需在其上调用一个函数（`ConditionalBeginDestroy()`）来开始拆卸。我们不使用本机 C++ `delete`命令来删除`UObject`派生类。我们将在下面的示例中展示这一点。

## 准备工作

您需要在任何未使用的`UObject`派生类上调用`ConditionalBeginDestroy()`，以便将其从内存中删除。不要调用`delete`来回收系统内存中的`UObject`派生类。您必须使用内部引擎提供的内存管理函数。下面将展示如何做到这一点。

## 如何做...

1.  在您的对象实例上调用`objectInstance->ConditionalBeginDestroy()`。

1.  在您的客户端代码中将所有对`objectInstance`的引用设置为 null，并且在对其调用`ConditionalBeginDestroy()`之后不再使用`objectInstance`。 

## 它是如何工作的...

`ConditionalBeginDestroy()`函数通过删除所有内部引擎链接来开始销毁过程。这标记了引擎认为的对象销毁。然后，对象稍后通过销毁其内部属性，随后实际销毁对象来销毁。

在对象上调用了`ConditionalBeginDestroy()`之后，您（客户端）的代码必须考虑对象已被销毁，并且不能再使用它。

实际的内存恢复发生在`ConditionalBeginDestroy()`在对象上调用后的一段时间。有一个垃圾收集例程，它在固定时间间隔内完成清除游戏程序不再引用的对象的内存。垃圾收集器调用之间的时间间隔列在`C:\Program Files (x86)\Epic Games\4.11\Engine\Config \BaseEngine.ini`中，默认为每 60 秒进行一次收集：

```cpp
gc.TimeBetweenPurgingPendingKillObjects=60
```

### 提示

如果在多次`ConditionalBeginDestroy()`调用后内存似乎不足，您可以通过调用`GetWorld()->ForceGarbageCollection(true)`来触发内存清理，以强制进行内部内存清理。

通常，除非您急需清除内存，否则无需担心垃圾收集或间隔。不要过于频繁地调用垃圾收集例程，因为这可能会导致游戏不必要的延迟。

# 创建一个 USTRUCT

您可能希望在 UE4 中构造一个蓝图可编辑的属性，其中包含多个成员。我们将在本章中创建的`FColoredTexture`结构将允许您将纹理和其颜色组合在同一结构中，以便在任何其他`UObject`衍生的`Blueprintable`类中进行包含和指定：

![创建一个 USTRUCT](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00061.jpeg)

`FColoredTexture`结构确实在蓝图中具有上述图中显示的外观。

这是为了良好的组织和方便您的其他`UCLASS``UPROPERTIES()`。您可能希望在游戏中使用关键字`struct`构造一个 C++结构。

## 准备工作

`UObject`是所有 UE4 类对象的基类，而`FStruct`只是任何普通的 C++风格结构。所有使用引擎内的自动内存管理功能的对象必须从此类派生。

### 提示

如果您还记得 C++语言，C++类和 C++结构之间唯一的区别是 C++类具有默认的`private`成员，而结构默认为`public`成员。在 C#等语言中，情况并非如此。在 C#中，结构是值类型，而类是引用类型。

## 如何做...

我们将在 C++代码中创建一个名为`FColoredTexture`的结构，其中包含一个纹理和一个调制颜色：

1.  在项目文件夹中创建一个名为`ColoredTexture.h`的文件（而不是`FColoredTexture`）。

1.  `ColoredTexture.h`包含以下代码：

```cpp
#pragma once

#include "Chapter2.h"
#include "ColoredTexture.generated.h"

USTRUCT()
struct CHAPTER2_API FColoredTexture
{
  GENERATED_USTRUCT_BODY()
  public:
  UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = HUD )
  UTexture* Texture;
  UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = HUD )
  FLinearColor Color;
};
```

1.  在一些可蓝图化的`UCLASS()`中，使用`ColoredTexture.h`作为`UPROPERTY()`，使用如下的`UPROPERTY()`声明：

```cpp
UPROPERTY( EditAnywhere, BlueprintReadWrite, Category = HUD )
FColoredTexture* Texture;
```

## 它是如何工作的...

为`FColoredTexture`指定的`UPROPERTY()`将显示为可编辑字段，当作为`UPROPERTY()`字段包含在另一个类中时，如步骤 3 所示。

## 还有更多...

将结构标记为`USTRUCT()`而不仅仅是普通的 C++结构的主要原因是与 UE4 引擎功能进行接口。您可以使用纯 C++代码（而不创建`USTRUCT()`对象）快速创建小型结构，而不要求引擎直接使用它们。

# 创建一个 UENUM()

C++的`enum`在典型的 C++代码中非常有用。UE4 有一种称为`UENUM()`的自定义枚举类型，它允许您创建一个将显示在正在编辑的蓝图内的下拉菜单中的`enum`。

## 如何做...

1.  转到将使用您指定的`UENUM()`的头文件，或创建一个名为`EnumName.h`的文件。

1.  使用以下形式的代码：

```cpp
UENUM()
enum Status
{
  Stopped     UMETA(DisplayName = "Stopped"),
  Moving      UMETA(DisplayName = "Moving"),
  Attacking   UMETA(DisplayName = "Attacking"),
};
```

1.  在`UCLASS()`中使用您的`UENUM()`如下：

```cpp
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Status)
TEnumAsByte<Status> status;

```

## 它是如何工作的...

`UENUM()`在代码编辑器中显示为蓝图编辑器中的下拉菜单，您只能从中选择几个值。

# 创建一个 UFUNCTION

`UFUNCTION()`很有用，因为它们是可以从您的 C++客户端代码以及蓝图图表中调用的 C++函数。任何 C++函数都可以标记为`UFUNCTION()`。

## 如何做...

1.  构建一个`UClass`，其中包含您想要暴露给蓝图的成员函数。用`UFUNCTION( BlueprintCallable, Category=SomeCategory)`装饰该成员函数，以使其可以从蓝图中调用。例如，以下是再次提到的“战士”类：

```cpp
// Warrior.h
class WRYV_API AWarrior : public AActor
{
  GENERATED_BODY()
  public:
  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Properties)
  FString Name;
  UFUNCTION(BlueprintCallable, Category = Properties)
  FString ToString();
};

// Warrior.cpp
FString UProfile::ToString()
{
  return FString::Printf( "An instance of UProfile: %s", *Name );
}
```

1.  通过将实例拖放到游戏世界上来创建您的“战士”类的实例。

1.  从蓝图中，点击您的“战士”实例，调用`ToString()`函数。然后，在蓝图图表中，输入`ToString()`。它应该看起来像下面的截图：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00062.jpeg)

### 提示

为了在实例上调用函数，在蓝图图表中开始输入自动完成菜单时，实例必须在**世界大纲**中被选中，如下面的截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00063.jpeg)

## 工作原理…

`UFUNCTION()`实际上是 C++函数，但具有额外的元数据，使它们可以被蓝图访问。


# 第三章：内存管理和智能指针

在本章中，我们将涵盖以下主题：

+   未管理内存-使用`malloc()`/`free()`

+   未管理内存-使用`new`/`delete`

+   管理内存-使用`NewObject< >`和`ConstructObject< >`

+   管理内存-释放内存

+   管理内存-智能指针（`TSharedPtr`，`TWeakPtr`，`TAutoPtr`）来跟踪对象

+   使用`TScopedPointer`来跟踪对象

+   虚幻引擎的垃圾收集系统和`UPROPERTY()`

+   强制垃圾收集

+   断点和逐步执行代码

+   查找错误并使用调用堆栈

+   使用分析器识别热点

# 介绍

内存管理始终是计算机程序中最重要的事情之一，以确保代码的稳定性和良好的无错误运行。悬空指针（指向已从内存中删除的内容的指针）是一个很难跟踪的错误示例。

![介绍](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00064.jpeg)

在任何计算机程序中，内存管理都非常重要。UE4 的`UObject`引用计数系统是 Actor 和`UObject`衍生类的默认内存管理方式。这是在 UE4 程序中管理内存的默认方式。

如果您编写自己的自定义 C++类，这些类不是从`UObject`派生的，您可能会发现`TSharedPtr`/`TWeakPtr`引用计数类很有用。这些类为 0 引用对象提供引用计数和自动删除。

本章提供了 UE4 内存管理的示例。

# 未管理内存-使用 malloc()/free()

在 C（和 C++）中为计算机程序分配内存的基本方法是使用`malloc()`。`malloc()`为程序的使用指定了计算机系统的内存块。一旦程序使用了一段内存，其他程序就无法使用或访问该段内存。尝试访问未分配给程序的内存段将生成“分段错误”，并在大多数系统上表示非法操作。

## 如何做...

让我们看一个示例代码，它分配了一个指针变量`i`，然后使用`malloc()`为其分配内存。我们在`int`后面的`int*`指针后面分配了一个整数。分配后，我们使用解引用运算符`*`在`int`内存中存储一个值：

```cpp
// CREATING AND ALLOCATING MEMORY FOR AN INT VARIABLE i
int* i; // Declare a pointer variable i
i = ( int* )malloc( sizeof( int ) ); // Allocates system memory
*i = 0; // Assign the value 0 into variable i
printf( "i contains %d", *i ); // Use the variable i, ensuring to 
// use dereferencing operator * during use
// RELEASING MEMORY OCCUPIED BY i TO THE SYSTEM
free( i ); // When we're done using i, we free the memory 
// allocated for it back to the system.
i = 0;// Set the pointer's reference to address 0
```

## 它是如何工作的...

前面的代码执行了后面图中所示的操作：

1.  第一行创建了一个`int*`指针变量`i`，它起初是一个悬空指针，指向一个内存段，这个内存段可能对程序来说是无效的。

1.  在第二个图中，我们使用`malloc()`调用来初始化变量`i`，使其指向一个大小恰好为`int`变量的内存段，这对于程序来说是有效的。

1.  然后，我们使用命令`*i = 0;`初始化该内存段的内容为值`0`。![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00065.jpeg)

### 提示

注意指针变量的赋值（`i =`）与赋值到指针变量引用的内存地址中的内容（`*i =`）之间的区别。

当变量`i`中的内存需要释放回系统时，我们使用`free()`释放调用，如下图所示。然后将`i`分配为指向内存地址`0`（由**电气接地**符号引用![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00066.jpeg)）。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00067.jpeg)

我们将变量`i`设置为指向`NULL`引用的原因是为了明确表明变量`i`不引用有效的内存段。

# 未管理内存-使用 new/delete

`new`运算符几乎与`malloc`调用相同，只是它在分配内存后立即调用对象的构造函数。使用`new`分配的对象应该使用`delete`运算符（而不是`free()`）进行释放。

## 准备工作

在 C++中，使用`malloc()`被最佳实践替换为使用`new`运算符。`malloc()`和`new`运算符功能的主要区别在于，`new`在内存分配后会调用对象类型的构造函数。

| `malloc` | `new` |
| --- | --- |
| 为使用分配一块连续空间。 | 为使用分配一块连续空间。调用构造函数作为`new`运算符的参数使用的对象类型。 |

## 如何做...

在下面的代码中，我们声明了一个简单的`Object`类，然后使用`new`运算符构造了一个实例：

```cpp
class Object
{
  Object()
  {
    puts( "Object constructed" );
  }
  ~Object()
  {
    puts( "Object destructed" );
  }
};
Object* object= new Object(); // Invokes ctor
delete object; // Invokes dtor
object = 0; // resets object to a null pointer
```

## 它是如何工作的...

`new`运算符的工作方式与`malloc()`一样，都是分配空间。如果与`new`运算符一起使用的类型是对象类型，则构造函数会自动使用关键字`new`调用，而使用`malloc()`则永远不会调用构造函数。

## 还有更多...

应该避免使用关键字`new`（或`malloc`）进行裸堆分配。引擎内部首选使用托管内存，以便跟踪和清理所有内存使用。如果分配了`UObject`派生类，绝对需要使用`NewObject< >`或`ConstructObject< >`（在后续的示例中有详细介绍）。

# 托管内存-使用 NewObject< >和 ConstructObject< >

托管内存是指由 C++中的`new`、`delete`、`malloc`和`free`调用之上的某个编程子系统分配和释放的内存。通常创建这些子系统是为了程序员在分配内存后不会忘记释放内存。未释放的、占用但未使用的内存块称为内存泄漏。例如：

```cpp
for( int i = 0; i < 100; i++ )
int** leak = new int[500]; // generates memory leaks galore!
```

在上面的例子中，分配的内存没有被任何变量引用！因此，您既不能在`for`循环之后使用分配的内存，也不能释放它。如果您的程序分配了所有可用的系统内存，那么会发生的是您的系统将完全耗尽内存，您的操作系统将标记您的程序并关闭它，因为它使用了太多内存。

内存管理可以防止忘记释放内存。在内存管理程序中，通常由动态分配的对象记住引用该对象的指针数量。当引用该对象的指针数量为零时，它要么立即被自动删除，要么在下一次运行**垃圾回收器**时被标记为删除。

在 UE4 中，使用托管内存是自动的。必须使用`NewObject< >()`或`SpawnActor< >()`来分配引擎内部使用的对象。释放对象是通过删除对对象的引用，然后偶尔调用垃圾清理例程（在本章后面列出）来完成的。

## 准备工作

当您需要构造任何不是`Actor`类的`UObject`派生类时，您应该始终使用`NewObject< >`。只有当对象是`Actor`或其派生类时，才应该使用`SpawnActor< >`。

## 如何做...

假设我们要构造一个类型为`UAction`的对象，它本身是从`UObject`派生的。例如，以下类：

```cpp
UCLASS(BlueprintType, Blueprintable, meta=(ShortTooltip="Base class for any Action type") )
Class WRYV_API UAction : public UObject
{
  GENERATED_UCLASS_BODY()
  public:
  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category=Properties)
  FString Text;
  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category=Properties)
  FKey ShortcutKey;
};
```

要构造`UAction`类的实例，我们可以这样做：

```cpp
UAction* action = NewObject<UAction>( GetTransientPackage(),
UAction::StaticClass() /* RF_* flags */ );
```

## 它是如何工作的...

在这里，`UAction::StaticClass()`可以获取`UAction`对象的基本`UClass*`。`NewObject< >`的第一个参数是`GetTransientPackage()`，它只是为游戏检索瞬态包。在 UE4 中，包（`UPackage`）只是一个数据集合。在这里，我们使用**瞬态包**来存储我们的堆分配数据。您还可以使用蓝图中的`UPROPERTY() TSubclassOf<AActor>`来选择`UClass`实例。

第三个参数（可选）是一组参数的组合，指示内存管理系统如何处理`UObject`。

## 还有更多...

还有一个与`NewObject<>`非常相似的函数叫做`ConstructObject<>`。`ConstructObject<>`在构造时提供了更多的参数，如果您需要指定这些参数，您可能会发现它很有用。否则，`NewObject`也可以正常工作。

## 另请参阅

+   您可能还想查看`RF_*`标志的文档，网址为[`docs.unrealengine.com/latest/INT/Programming/UnrealArchitecture/Objects/Creation/index.html#objectflags`](https://docs.unrealengine.com/latest/INT/Programming/UnrealArchitecture/Objects/Creation/index.html#objectflags)

# 托管内存-释放内存

当没有对`UObject`实例的引用时，`UObject`是引用计数和垃圾回收的。使用`ConstructObject<>`或`NewObject<>`在`UObject`类派生类上分配的内存也可以通过调用`UObject::ConditionalBeginDestroy()`成员函数手动释放（在引用计数降至 0 之前）。

## 准备工作

只有在您确定不再需要`UObject`或`UObject`类派生实例时才会这样做。使用`ConditionalBeginDestroy()`函数释放内存。

## 如何做…

以下代码演示了`UObject 类`的释放：

```cpp
UObject *o = NewObject< UObject >( ... );
o->ConditionalBeginDestroy();
```

## 它是如何工作的…

命令`ConditionalBeginDestroy()`开始了释放过程，调用了`BeginDestroy()`和`FinishDestroy()`可重写函数。

## 还有更多…

注意不要在其他对象的指针仍在内存中引用的对象上调用`UObject::ConditionalBeginDestroy()`。

# 托管内存-智能指针（TSharedPtr、TWeakPtr、TAutoPtr）跟踪对象

当人们担心会忘记为他们创建的标准 C++对象调用`delete`时，他们经常使用智能指针来防止内存泄漏。`TSharedPtr`是一个非常有用的 C++类，它将使任何自定义 C++对象引用计数——除了`UObject`派生类，它们已经是引用计数的。还提供了一个名为`TWeakPtr`的替代类，用于指向引用计数对象，具有无法阻止删除的奇怪属性（因此称为“弱”）。

![托管内存-智能指针（TSharedPtr、TWeakPtr、TAutoPtr）跟踪对象](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00068.jpeg)

### 提示

`UObject`及其派生类（使用`NewObject`或`ConstructObject`创建的任何内容）不能使用`TSharedPtr`！

## 准备工作

如果您不想在不使用`UObject`派生类的 C++代码中使用原始指针并手动跟踪删除，那么该代码是使用智能指针（如`TSharedPtr`、`TSharedRef`等）的良好选择。当您使用动态分配的对象（使用关键字`new`创建）时，您可以将其包装在一个引用计数指针中，以便自动发生释放。不同类型的智能指针确定智能指针的行为和删除调用时间。它们如下：

+   `TSharedPtr`：线程安全（如果您将`ESPMode::ThreadSafe`作为模板的第二个参数）的引用计数指针类型，表示一个共享对象。当没有对它的更多引用时，共享对象将被释放。

+   `TAutoPtr`：非线程安全的共享指针。

## 如何做…

我们可以使用一个简短的代码段来演示先前提到的四种智能指针的使用。在所有这些代码中，起始指针可以是原始指针，也可以是另一个智能指针的副本。您只需将 C++原始指针包装在`TSharedPtr`、`TSharedRef`、`TWeakPtr`或`TAutoPtr`的任何构造函数调用中。

例如：

```cpp
// C++ Class NOT deriving from UObject
class MyClass { };
TSharedPtr<MyClass>sharedPtr( new MyClass() );
```

## 它是如何工作的…

弱指针和共享指针之间存在一些差异。弱指针在引用计数降至 0 时无法保持对象在内存中。

使用弱指针（而不是原始指针）的优势在于，当弱指针下面的对象被手动删除（使用`ConditionalBeginDestroy()`），弱指针的引用将变为`NULL`引用。这使你可以通过检查形式为的语句来检查指针下面的资源是否仍然正确分配：

```cpp
if( ptr.IsValid() ) // Check to see if the pointer is valid
{
}
```

## 还有更多…

共享指针是线程安全的。这意味着底层对象可以在单独的线程上安全地进行操作。请记住，你不能在`UObject`或`UObject`派生类上使用`TSharedRef`，只能在自定义的 C++类上使用`TSharedPtr`、`TSharedRef`、`TWeakPtr`类，或者在你的`FStructures`上使用任何`TSharedPtr`、`TSharedRef`、`TWeakPtr`类来封装原始指针。你必须使用`TWeakObjectPointer`或`UPROPERTY()`作为指向对象的智能指针的起点。

如果不需要`TSharedPtr`的线程安全保证，可以使用`TAutoPtr`。当对该对象的引用数量降至 0 时，`TAutoPtr`将自动删除该对象。

# 使用 TScopedPointer 跟踪对象

作用域指针是在声明它的块结束时自动删除的指针。请记住，作用域只是变量“存活”的代码段。作用域将持续到第一个出现的闭括号`}`。

例如，在以下代码块中，我们有两个作用域。外部作用域声明一个整数变量`x`（在整个外部块中有效），而内部作用域声明一个整数变量`y`（在声明它的行之后的内部块中有效）：

```cpp
{
  int x;
  {
    int y;
  } // scope of y ends
} // scope of x ends
```

## 准备工作

当重要的引用计数对象（可能会超出范围）需要在使用期间保留时，作用域指针非常有用。

## 如何做…

要声明一个作用域指针，我们只需使用以下语法：

```cpp
TScopedPointer<AWarrior> warrior(this );
```

这声明了一个指向在尖括号内声明的类型对象的作用域指针：`<AWarrior>`。

## 它是如何工作的…

`TScopedPointer`变量类型会自动为指向的变量添加引用计数。这可以防止在作用域指针的生命周期内至少释放底层对象。

# Unreal 的垃圾回收系统和 UPROPERTY()

当你有一个对象（比如`TArray< >`）作为`UCLASS()`的`UPROPERTY()`成员时，你需要将该成员声明为`UPROPERTY()`（即使你不会在蓝图中编辑它），否则`TArray`将无法正确分配内存。

## 如何做…

假设我们有以下的`UCLASS()`宏：

```cpp
UCLASS()
class MYPROJECT_API AWarrior : public AActor
{
  //TArray< FSoundEffect > Greets; // Incorrect
  UPROPERTY() TArray< FSoundEffect > Greets; // Correct
};
```

你必须将`TArray`成员列为`UPROPERTY()`，以便它能够正确地进行引用计数。如果不这样做，你将在代码中遇到意外的内存错误类型 bug。

## 它是如何工作的…

`UPROPERTY()`声明告诉 UE4，`TArray`必须得到适当的内存管理。没有`UPROPERTY()`声明，你的`TArray`将无法正常工作。

# 强制进行垃圾回收

当内存填满时，你想要释放一些内存时，可以强制进行垃圾回收。你很少需要这样做，但在有一个非常大的纹理（或一组纹理）需要清除的情况下，你可以这样做。

## 准备工作

只需在所有想要从内存中释放的`UObject`上调用`ConditionalBeginDestroy()`，或将它们的引用计数设置为 0。

## 如何做…

通过调用以下方式执行垃圾回收：

```cpp
GetWorld()->ForceGarbageCollection( true );
```

# 断点和逐步执行代码

断点是用来暂停 C++程序，暂时停止代码运行，并有机会分析和检查程序操作的方式。你可以查看变量，逐步执行代码，并更改变量值。

## 准备工作

在 Visual Studio 中设置断点很容易。你只需在想要暂停操作的代码行上按下*F9*，或者单击代码行左侧的灰色边距。当操作到达指定行时，代码将暂停。

## 如何做…

1.  按下*F9*，在您希望执行暂停的行上添加断点。这将在代码中添加一个断点，如下面的屏幕截图所示，用红点表示。单击红点可切换它。![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00069.jpeg)

1.  将**生成配置**设置为标题中带有**调试**的任何配置（**DebugGame**编辑器或者如果您将在没有编辑器的情况下启动，则简单地选择**DebugGame**）。

1.  通过按下*F5*（不按住*Ctrl*），或选择**调试** | **开始调试**菜单选项来启动您的代码。

1.  当代码到达红点时，代码的执行将暂停。

1.  暂停的视图将带您进入**调试模式**的代码编辑器。在此模式下，窗口可能会重新排列，**解决方案资源管理器**可能会移动到右侧，并且新窗口会出现在底部，包括**本地变量**、**监视 1**和**调用堆栈**。如果这些窗口没有出现，请在**调试** | **窗口**子菜单下找到它们。

1.  在**本地变量**窗口（**调试** | **窗口** | **本地变量**）下检查您的变量。

1.  按下*F10*跨过一行代码。

1.  按下*F11*以进入一行代码。

## 工作原理…

调试器是强大的工具，允许您在代码运行时查看关于代码的一切，包括变量状态。

在代码行上方跨过一行（*F10*）会执行整行代码，然后立即在下一行再次暂停程序。如果代码行是一个函数调用，那么函数将在不暂停在函数调用的第一行的情况下执行。例如：

```cpp
void f()
{
  // F11 pauses here
  UE_LOG( LogTemp, Warning, TEXT( "Log message" ) );
}
int main()
{
  f(); // Breakpoint here: F10 runs and skips to next line
}
```

进入一行代码（*F11*）将在接下来要运行的代码的下一行暂停执行。

# 查找错误并使用调用堆栈

当您的代码中有错误时，Visual Studio 会停止并允许您检查代码。Visual Studio 停止的位置不一定总是错误的确切位置，但可能会接近。它至少会在不能正确执行的代码行处。

## 准备就绪

在这个示例中，我们将描述**调用堆栈**，以及如何追踪您认为错误可能来自的位置。尝试向您的代码中添加一个错误，或者在您想要暂停进行检查的有趣位置添加一个断点。

## 如何做…

1.  通过按下*F5*或选择**调试** | **开始调试**菜单选项，运行代码直到出现错误的地方。例如，添加以下代码行：

```cpp
UObject *o = 0; // Initialize to an illegal null pointer
o->GetName(); // Try and get the name of the object (has bug)
```

1.  代码将在第二行（`o->GetName()`）暂停。

1.  当代码暂停时，转到**调用堆栈**窗口（**调试** | **窗口** | **调用堆栈**）。

## 工作原理…

**调用堆栈**是已执行的函数调用列表。发生错误时，发生错误的行将列在**调用堆栈**的顶部。

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00070.jpeg)

# 使用性能分析器识别热点

C++性能分析器非常有用，可以找到需要大量处理时间的代码部分。使用性能分析器可以帮助您找到在优化期间需要关注的代码部分。如果您怀疑某个代码区域运行缓慢，那么如果在性能分析器中没有突出显示，您实际上可以确认它不会运行缓慢。

## 如何做…

1.  转到**调试** | **启动诊断工具（无调试）…**![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00071.jpeg)

1.  在前面的屏幕截图中显示的对话框中，选择您希望显示的分析类型。您可以选择分析**CPU 使用情况**、**GPU 使用情况**、**内存使用情况**，或者通过**性能向导**逐步选择您想要看到的内容。

1.  单击对话框底部的**开始**按钮。

1.  在短时间内（不到一两分钟）停止代码以停止采样。

### 提示

不要收集太多样本，否则性能分析器将需要很长时间才能启动。

1.  检查出现在`.diagsession`文件中的结果。一定要浏览所有可用的选项卡。可用的选项卡将根据执行的分析类型而变化。

## 工作原理…

C++性能分析器对运行的代码进行采样和分析，并向您呈现一系列关于代码执行情况的图表和数据。


# 第四章：Actor 和组件

在本章中，我们将涵盖以下示例：

+   在 C++中创建自定义`Actor`

+   使用`SpawnActor`实例化`Actor`

+   使用`Destroy`和定时器销毁`Actor`

+   使用`SetLifeSpan`在延迟后销毁`Actor`

+   通过组合实现`Actor`功能

+   使用`FObjectFinder`将资产加载到组件中

+   通过继承实现`Actor`功能

+   附加组件以创建层次结构

+   创建自定义`Actor`组件

+   创建自定义`Scene`组件

+   创建自定义`Primitive`组件

+   为 RPG 创建`InventoryComponent`

+   创建`OrbitingMovement`组件

+   创建生成单位的建筑物

# 介绍

Actor 是在游戏世界中具有一定存在的类。Actor 通过合并组件获得其专门功能。本章涉及创建自定义 Actor 和组件，它们的作用以及它们如何一起工作。

# 在 C++中创建自定义 Actor

在 Unreal 默认安装的一些不同类型的 Actor 中，您可能会发现自己在项目开发过程中需要创建自定义的 Actor。这可能发生在您需要向现有类添加功能时，将组件组合成默认子类中不存在的组合，或者向类添加额外的成员变量时。接下来的两个示例演示了如何使用组合或继承来自定义 Actor。

## 准备工作

确保您已经按照第一章中的示例安装了 Visual Studio 和 Unreal 4，*UE4 开发工具*。您还需要有一个现有项目，或者使用 Unreal 提供的向导创建一个新项目。

## 如何做...

1.  在 Unreal Editor 中打开您的项目，然后单击**Content Browser**中的**Add New**按钮：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00072.jpeg)

1.  选择**New C++ Class...**![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00073.jpeg)

1.  在打开的对话框中，从列表中选择**Actor**：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00074.jpeg)

1.  给您的 Actor 一个名称，比如`MyFirstActor`，然后单击**OK**启动 Visual Studio。

### 提示

按照惯例，`Actor`子类的类名以`A`开头。在使用此类创建向导时，请确保不要为您的类添加`A`前缀，因为引擎会自动为您添加前缀。

![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00075.jpeg)

1.  当 Visual Studio 加载时，您应该看到与以下列表非常相似的内容：

```cpp
MyFirstActor.h
#pragma once

#include "GameFramework/Actor.h"
#include "MyFirstActor.generated.h"

UCLASS()
class UE4COOKBOOK_API AMyFirstActor : public AActor
{
  GENERATED_BODY()
  public:
  AMyFirstActor(); 
};
MyFirstActor.cpp
#include "UE4Cookbook.h"
#include "MyFirstActor.h"
AMyFirstActor::AMyFirstActor()
{
  PrimaryActorTick.bCanEverTick = true;
}
```

## 它是如何工作的...

随着时间的推移，您将熟悉标准代码，因此您将能够在不使用 Unreal 向导的情况下直接从 Visual Studio 创建新类。

+   `#pragma once`: 这个预处理器语句，或者`pragma`，是 Unreal 预期的实现包含保护的方法——防止多次引用`include`文件导致错误。

+   `#include "GameFramework/Actor.h"`: 我们将创建一个`Actor`子类，因此自然需要包含我们从中继承的类的`header`文件。

+   `#include "MyFirstActor.generated.h"`: 所有 actor 类都需要包含它们的`generated.h`文件。这个文件是根据它在您的文件中检测到的宏自动由**Unreal Header Tool** (**UHT**)创建的。

+   `UCLASS()`: `UCLASS`是这样一个宏，它允许我们指示一个类将暴露给 Unreal 的反射系统。反射允许我们在运行时检查和迭代对象属性，以及管理对我们对象的引用以进行垃圾回收。

+   `class UE4COOKBOOK_API AMyFirstActor : public AActor`：这是我们类的实际声明。`UE4COOKBOOK_API`宏是由 UHT 创建的，通过确保项目模块的类在 DLL 中正确导出，可以帮助我们的项目在 Windows 上正确编译。你还会注意到`MyFirstActor`和`Actor`都有前缀`A`——这是虚幻要求的从`Actor`继承的本地类的命名约定。

+   `GENERATED_BODY()`: `GENERATED_BODY`是另一个 UHT 宏，已经扩展到包括底层 UE 类型系统所需的自动生成函数。

+   `PrimaryActorTick.bCanEverTick = true;`：在构造函数实现中，这一行启用了这个`Actor`的 tick。所有的 Actor 都有一个名为`Tick`的函数，这个布尔变量意味着`Actor`将每帧调用一次该函数，使得`Actor`能够在每帧执行必要的操作。作为性能优化，默认情况下是禁用的。

# 使用 SpawnActor 实例化一个 Actor

对于这个配方，你需要准备一个`Actor`子类来实例化。你可以使用内置类，比如`StaticMeshActor`，但最好练习使用上一个配方中创建的自定义`Actor`。

## 如何操作...

1.  创建一个新的 C++类，就像在上一个配方中一样。这次，选择`GameMode`作为基类，给它起一个名字，比如`UE4CookbookGameMode`。

1.  在你的新`GameMode`类中声明一个函数重写：

```cpp
virtual void BeginPlay() override;
```

1.  在`.cpp`文件中实现`BeginPlay`：

```cpp
void AUE4CookbookGameMode::BeginPlay()
{
  Super::BeginPlay();
  GEngine->AddOnScreenDebugMessage(-1, -1, FColor::Red, TEXT("Actor Spawning"));

  FTransform SpawnLocation;
  GetWorld()->SpawnActor<AMyFirstActor>( AMyFirstActor::StaticClass(), &SpawnLocation);
}
```

1.  编译你的代码，可以通过 Visual Studio 或者在虚幻编辑器中点击**编译**按钮来进行。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00076.jpeg)

1.  通过点击**设置**工具栏图标，然后从下拉菜单中选择**World Settings**，打开当前级别的**World Settings**面板。在**GameMode Override**部分，将游戏模式更改为你刚刚创建的`GameMode`子类，如下两个截图所示:![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00077.jpeg)![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00078.jpeg)

1.  启动关卡，并通过查看**World Outliner**面板来验证`GameMode`是否在世界中生成了你的`Actor`的副本。你可以通过查看屏幕上显示的**Actor Spawning**文本来验证`BeginPlay`函数是否正在运行。如果没有生成，请确保世界原点没有障碍物阻止`Actor`生成。你可以通过在**World Outliner**面板顶部的搜索栏中输入来搜索世界中的对象列表，以过滤显示的实体。![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00079.jpeg)

## 工作原理...

1.  `GameMode`是一种特殊类型的 Actor，它是虚幻游戏框架的一部分。地图的`GameMode`在游戏启动时由引擎自动实例化。

1.  通过将一些代码放入自定义`GameMode`的`BeginPlay`方法中，我们可以在游戏开始时自动运行它。

1.  在`BeginPlay`中，我们创建一个`FTransform`，用于`SpawnActor`函数。默认情况下，`FTransform`被构造为零旋转，并且位置在原点。

1.  然后，我们使用`GetWorld`获取当前级别的`UWorld`实例，然后调用它的`SpawnActor`函数。我们传入之前创建的`FTransform`，以指定对象应该在其位置即原点处创建。

# 使用 Destroy 和定时器销毁一个 Actor

这个配方将重用上一个配方中的`GameMode`，所以你应该先完成它。

## 如何操作...

1.  对`GameMode`声明进行以下更改：

```cpp
UPROPERTY()
AMyFirstActor* SpawnedActor;
UFUNCTION()
void DestroyActorFunction();
```

1.  在实现文件的包含中添加`#include "MyFirstActor.h"`。

1.  将`SpawnActor`的结果分配给新的`SpawnedActor`变量：

```cpp
SpawnedActor = GetWorld()->SpawnActor<AMyFirstActor> (AMyFirstActor::StaticClass(), SpawnLocation);
```

1.  在`BeginPlay`函数的末尾添加以下内容：

```cpp
FTimerHandle Timer;
GetWorldTimerManager().SetTimer(Timer, this, &AUE4CookbookGameMode::DestroyActorFunction, 10);
```

1.  最后，实现`DestroyActorFunction`：

```cpp
void AUE4CookbookGameMode::DestroyActorFunction()
{
  if (SpawnedActor != nullptr)
  {
    SpawnedActor->Destroy();
  }
}
```

1.  加载你在上一个配方中创建的具有自定义类游戏模式的关卡。

1.  播放你的关卡，并使用 Outliner 验证你的`SpawnedActor`在 10 秒后被删除。

## 它的工作原理...

+   我们声明一个`UPROPERTY`来存储我们生成的`Actor`实例，并创建一个自定义函数来调用，以便我们可以在计时器上调用`Destroy()`：

```cpp
UPROPERTY()
AMyFirstActor* SpawnedActor;
UFUNCTION()
void DestroyActorFunction();
```

+   在`BeginPlay`中，我们将生成的`Actor`分配给我们的新`UPROPERTY`：

```cpp
SpawnedActor = GetWorld()->SpawnActor<AMyFirstActor> (AMyFirstActor::StaticClass(), SpawnLocation);
```

+   然后我们声明一个`TimerHandle`对象，并将其传递给`GetWorldTimerManager::SetTimer`。`SetTimer`在 10 秒后调用`DestroyActorFunction`指向的对象。`SetTimer`返回一个对象，一个句柄，允许我们在必要时取消计时器。`SetTimer`函数将`TimerHandle`对象作为引用参数传入，因此我们提前声明它，以便正确地将其传递给函数：

```cpp
FTimerHandle Timer;
GetWorldTimerManager().SetTimer(Timer, this, &AUE4CookbookGameMode::DestroyActorFunction, 10);
```

+   `DestroyActorFunction`检查我们是否有一个有效的生成`Actor`的引用：

```cpp
void AUE4CookbookGameMode::DestroyActorFunction()
{
  if (SpawnedActor != nullptr)
}
```

+   如果这样做，它会调用实例上的`Destroy`，因此它将被销毁，并最终被垃圾回收：

```cpp
SpawnedActor->Destroy();
```

# 使用 SetLifeSpan 延迟销毁 Actor

让我们看看如何销毁一个`Actor`。

## 如何做...

1.  使用向导创建一个新的 C++类。选择`Actor`作为你的基类。

1.  在`Actor`的实现中，将以下代码添加到`BeginPlay`函数中：

```cpp
SetLifeSpan(10);
```

1.  将你的自定义`Actor`的一个副本拖到编辑器中的视口中。

1.  播放你的关卡，并查看 Outliner，以验证你的`Actor`实例在 10 秒后消失，自行销毁。

## 它的工作原理...

1.  我们将代码插入到`BeginPlay`函数中，以便在游戏启动时执行。

1.  `SetLifeSpan(10);`：`SetLifeSpan`函数允许我们指定持续时间（以秒为单位），之后`Actor`调用自己的`Destroy()`方法。

# 通过组合实现 Actor 功能

没有组件的自定义 Actor 没有位置，也不能附加到其他 Actor。没有根组件，Actor 没有基本变换，因此它没有位置。因此，大多数 Actor 至少需要一个组件才能有用。

我们可以通过组合创建自定义 Actor-向我们的`Actor`添加多个组件，其中每个组件提供所需的一些功能。

## 准备工作

这个示例将使用*在 C++中创建自定义 Actor*中创建的`Actor`类。

## 如何做...

1.  通过在`public`部分进行以下更改，在你的自定义类中添加一个新成员：

```cpp
UPROPERTY()
UStaticMeshComponent* Mesh;
```

1.  在 cpp 文件的构造函数中添加以下行：

```cpp
Mesh = CreateDefaultSubobject<UStaticMeshComponent>("BaseMeshComponent");
```

1.  验证你的代码看起来像以下片段，并通过编辑器中的**Compile**按钮编译它，或者在 Visual Studio 中构建项目：

```cpp
UCLASS()
class UE4COOKBOOK_API AMyFirstActor : public AActor
{
  GENERATED_BODY()
  public:
  AMyFirstActor();

  UPROPERTY() 
  UStaticMeshComponent* Mesh;
};

#include "UE4Cookbook.h"
#include "MyFirstActor.h"
AMyFirstActor::AMyFirstActor()
{
  PrimaryActorTick.bCanEverTick = true;

  Mesh = CreateDefaultSubobject<UStaticMeshComponent>("BaseMeshComponent");
}
```

1.  编译此代码后，将类的一个实例从**Content Browser**拖到游戏环境中，您将能够验证它现在具有变换和其他属性，例如来自我们添加的`StaticMeshComponent`的 Static Mesh。

## 它的工作原理...

1.  我们在类声明中添加的`UPROPERTY 宏`是一个指针，用于保存我们作为`Actor`子对象的组件。

```cpp
UPROPERTY()
UStaticMeshComponent* Mesh;
```

1.  使用`UPROPERTY()`宏确保指针中声明的对象被视为引用，并且不会被垃圾回收（即删除），从而使指针悬空。

1.  我们使用了一个 Static Mesh 组件，但任何`Actor`组件子类都可以工作。请注意，星号与变量类型连接在一起，符合 Epic 的样式指南。

1.  在构造函数中，我们使用`template`函数将指针初始化为已知的有效值，`template<class TReturnType> TReturnType* CreateDefaultSubobject(FName SubobjectName, bool bTransient = false)`。

1.  这个函数负责调用引擎代码来适当初始化组件，并返回一个指向新构造对象的指针，以便我们可以给我们的组件指针一个默认值。这很重要，显然，以确保指针始终具有有效值，最大程度地减少对未初始化内存的引用风险。

1.  该函数是基于要创建的对象类型进行模板化的，但还接受两个参数——第一个是子对象的名称，理想情况下应该是可读的，第二个是对象是否应该是瞬态的（即不保存在父对象中）。

## 另请参阅

+   以下食谱向您展示如何在静态网格组件中引用网格资产，以便可以在不需要用户在编辑器中指定网格的情况下显示它

# 使用 FObjectFinder 将资产加载到组件中

在上一个食谱中，我们创建了一个静态网格组件，但我们没有尝试加载一个网格来显示组件。虽然在编辑器中可以做到这一点，但有时在 C++中指定默认值会更有帮助。

## 准备工作

按照上一个食谱，这样您就有了一个准备好的自定义`Actor`子类，其中包含一个静态网格组件。

在您的**内容浏览器**中，单击**查看选项**按钮，然后选择**显示引擎内容**：

![准备工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00080.jpeg)

浏览到**引擎内容**，然后到**基本形状**，看看我们将在这个食谱中使用的**立方体**。

![准备工作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00081.jpeg)

## 如何做...

1.  将以下代码添加到您的类的构造函数中：

```cpp
auto MeshAsset = ConstructorHelpers::FObjectFinder<UStaticMesh>(TEXT("StaticMesh'/Engine/BasicShapes/Cube.Cube'"));
if (MeshAsset.Object != nullptr)
{
  Mesh->SetStaticMesh(MeshAsset.Object);
}
```

1.  编译，并在编辑器中验证您的类的实例现在具有网格作为其视觉表示。

## 工作原理...

+   我们创建了`FObjectFinder`类的一个实例，将要加载的资产类型作为模板参数传递进去。

+   `FObjectFinder`是一个类模板，帮助我们加载资产。当我们构造它时，我们传入一个包含我们要加载的资产路径的字符串。

+   字符串的格式为`"{ObjectType}'/Path/To/Asset.Asset'"`。请注意字符串中使用了单引号。

+   为了获取已经存在于编辑器中的资产的字符串，您可以在**内容浏览器**中右键单击资产，然后选择**复制引用**。这会给您一个字符串，这样您就可以将其粘贴到您的代码中。![工作原理...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00082.jpeg)

+   我们使用了 C++11 中的`auto`关键字，以避免在声明中输入整个对象类型；编译器会为我们推断出类型。如果没有`auto`，我们将不得不使用以下代码：

```cpp
ConstructorHelpers::FObjectFinder<UStaticMesh> MeshAsset = ConstructorHelpers::FObjectFinder<UStaticMesh>(TEXT("StaticMesh'/Engine/BasicShapes/Cube.Cube'"));
```

+   `FObjectFinder`类有一个名为`Object`的属性，它要么有指向所需资产的指针，要么是`NULL`，如果找不到资产。

+   这意味着我们可以将其与`nullptr`进行比较，如果它不是空的，就使用`SetStaticMesh`将其分配给`Mesh`。

# 通过继承实现 Actor 功能

继承是实现自定义`Actor`的第二种方法。这通常是为了创建一个新的子类，它添加成员变量、函数或组件到现有的`Actor`类中。在这个食谱中，我们将向自定义的`GameState`子类添加一个变量。

## 如何做...

1.  在虚幻编辑器中，单击**内容浏览器**中的**添加新内容**，然后单击**新建 C++类...**，然后选择**GameState**作为基类，然后给您的新类起一个名字。

1.  将以下代码添加到新类头文件中：

```cpp
AMyGameState(); 

UFUNCTION()
void SetScore(int32 NewScore);

UFUNCTION()
int32 GetScore();
private:
UPROPERTY()
int32 CurrentScore;
```

1.  将以下代码添加到 cpp 文件中：

```cpp
AMyGameState::AMyGameState()
{
  CurrentScore = 0;
}

int32 AMyGameState::GetScore()
{
  return CurrentScore;
}

void AMyGameState::SetScore(int32 NewScore)
{
  CurrentScore = NewScore;
}
```

1.  确认您的代码看起来像以下清单，并使用虚幻编辑器中的**编译**按钮进行编译：

```cpp
MyGameState.h
#pragma once

#include "GameFramework/GameState.h"
#include "MyGameState.generated.h"

/**
*
*/
UCLASS()
class UE4COOKBOOK_API AMyGameState : public AGameState
{
  GENERATED_BODY()
  public:
  AMyGameState();

  UPROPERTY()
  int32 CurrentScore;

  UFUNCTION()
  int32 GetScore();

  UFUNCTION()
  void SetScore(uint32 NewScore);
};
MyGameState.cpp
#include "UE4Cookbook.h"
#include "MyGameState.h"

AMyGameState::AMyGameState()
{
  CurrentScore = 0;
}

int32 AMyGameState::GetScore()
{
  return CurrentScore;
}

void AMyGameState::SetScore(uint32 NewScore)
{
  CurrentScore = NewScore;
}
```

## 工作原理...

1.  首先，我们添加了默认构造函数的声明：

```cpp
AMyGameState();
```

1.  这使我们能够在对象初始化时将我们的新成员变量设置为安全的默认值`0`：

```cpp
AMyGameState::AMyGameState()
{
  CurrentScore = 0;
}
```

1.  在声明新变量时，我们使用`int32`类型，以确保在虚幻引擎支持的各种编译器之间具有可移植性。这个变量将负责在游戏运行时存储当前游戏分数。与往常一样，我们将使用`UPROPERTY`标记我们的变量，以便它能够得到适当的垃圾回收。这个变量被标记为`private`，所以改变值的唯一方式是通过我们的函数：

```cpp
UPROPERTY()
int32 CurrentScore;
```

1.  `GetScore`函数将检索当前分数，并将其返回给调用者。它被实现为一个简单的访问器，只是返回基础成员变量。

1.  第二个函数`SetScore`设置成员变量的值，允许外部对象请求更改分数。将此请求作为函数确保`GameState`可以审核此类请求，并且仅在有效时才允许它们，以防止作弊。此类检查的具体内容超出了本配方的范围，但`SetScore`函数是进行此类检查的适当位置。

1.  我们的分数函数使用`UFUNCTION`宏声明有多种原因。首先，`UFUNCTION`可以通过一些额外的代码被蓝图调用或重写。其次，`UFUNCTION`可以标记为`exec`—这意味着它们可以在游戏会话期间由玩家或开发人员作为控制台命令运行，这样可以进行调试。

## 另请参阅

+   第八章, *集成 C++和虚幻编辑器,* 有一个名为*创建新控制台命令*的配方，您可以参考有关`exec`和控制台命令功能的更多信息

# 将组件附加到创建层次结构

在从组件创建自定义 Actor 时，考虑“附加”的概念非常重要。将组件附加在一起会创建一个关系，其中应用于父组件的变换也会影响附加到它的组件。

## 如何做...

1.  使用编辑器基于`Actor`创建一个新类，并将其命名为`HierarchyActor`。

1.  将以下属性添加到您的新类中：

```cpp
UPROPERTY()
USceneComponent* Root;
UPROPERTY()
USceneComponent* ChildSceneComponent;
UPROPERTY()
UStaticMeshComponent* BoxOne;
UPROPERTY()
UStaticMeshComponent* BoxTwo;
```

1.  将以下代码添加到类构造函数中：

```cpp
Root = CreateDefaultSubobject<USceneComponent>("Root");
ChildSceneComponent = CreateDefaultSubobject<USceneComponent>("ChildSceneComponent");
BoxOne = CreateDefaultSubobject<UStaticMeshComponent>("BoxOne");
BoxTwo = CreateDefaultSubobject<UStaticMeshComponent>("BoxTwo");

auto MeshAsset = ConstructorHelpers::FObjectFinder<UStaticMesh>(TEXT("StaticMesh'/Engine/BasicShapes/Cube.Cube'"));
if (MeshAsset.Object != nullptr)
{
  BoxOne->SetStaticMesh(MeshAsset.Object);
  BoxTwo->SetStaticMesh(MeshAsset.Object);
}
RootComponent = Root;
BoxOne->AttachTo(Root);
BoxTwo->AttachTo(ChildSceneComponent);
ChildSceneComponent->AttachTo(Root);
ChildSceneComponent->SetRelativeTransform(FTransform(FRotator(0, 0, 0), FVector(250, 0, 0), FVector(0.1f)));
```

1.  验证您的代码是否如下所示：

```cpp
HierarchyActor.h
#pragma once

#include "GameFramework/Actor.h"
#include "HierarchyActor.generated.h"

UCLASS()
class UE4COOKBOOK_API AHierarchyActor : public AActor
{
  GENERATED_BODY()
  public:
  AHierarchyActor();
  virtual void BeginPlay() override;
  virtual void Tick( float DeltaSeconds ) override;
  UPROPERTY()
  USceneComponent* Root;
  UPROPERTY()
  USceneComponent* ChildSceneComponent;
  UPROPERTY()
  UStaticMeshComponent* BoxOne;
  UPROPERTY()
  UStaticMeshComponent* BoxTwo;
};
HierarchyActor.cpp

#include "UE4Cookbook.h"
#include "HierarchyActor.h"

AHierarchyActor::AHierarchyActor()
{
  PrimaryActorTick.bCanEverTick = true;
  Root = CreateDefaultSubobject<USceneComponent>("Root");
  ChildSceneComponent = CreateDefaultSubobject<USceneComponent>("ChildSceneComponent");
  BoxOne = CreateDefaultSubobject<UStaticMeshComponent>("BoxOne");
  BoxTwo = CreateDefaultSubobject<UStaticMeshComponent>("BoxTwo");
  auto MeshAsset = ConstructorHelpers::FObjectFinder<UStaticMesh>(TEXT("StaticMesh'/Engine/BasicShapes/Cube.Cube'"));
  if (MeshAsset.Object != nullptr)
  {
    BoxOne->SetStaticMesh(MeshAsset.Object);
    BoxOne->SetCollisionProfileName(UCollisionProfile::Pawn_ProfileName);
    BoxTwo->SetStaticMesh(MeshAsset.Object);
    BoxTwo->SetCollisionProfileName(UCollisionProfile::Pawn_ProfileName);	
  }
  RootComponent = Root;
  BoxOne->AttachTo(Root);
  BoxTwo->AttachTo(ChildSceneComponent);
  ChildSceneComponent->AttachTo(Root);
  ChildSceneComponent->SetRelativeTransform(FTransform(FRotator(0, 0, 0), FVector(250, 0, 0), FVector(0.1f)));
}
void AHierarchyActor::BeginPlay()
{
  Super::BeginPlay();
}
void AHierarchyActor::Tick( float DeltaTime )
{
  Super::Tick( DeltaTime );
}
```

1.  编译并启动编辑器。将 HierarchyActor 的副本拖入场景中。！如何做...

1.  验证`Actor`在层次结构中是否有组件，并且第二个框的大小较小。！如何做...

## 它是如何工作的...

1.  像往常一样，我们为我们的 Actor 创建一些带有`UPROPERTY`标记的组件。我们创建了两个场景组件和两个静态网格组件。

1.  在构造函数中，我们像往常一样为每个组件创建默认子对象。

1.  然后，我们加载静态网格，如果加载成功，将其分配给两个静态网格组件，以便它们具有视觉表示。

1.  然后，我们通过附加组件在我们的`Actor`中构建了一个层次结构。

1.  我们将第一个场景组件设置为`Actor`根。此组件将确定应用于层次结构中所有其他组件的变换。

1.  然后，我们将第一个框附加到我们的新根组件，并将第二个场景组件作为第一个组件的父级。

1.  我们将第二个框附加到我们的子场景组件，以演示更改该场景组件上的变换如何影响其子组件，但不影响对象中的其他组件。

1.  最后，我们设置场景组件的相对变换，使其从原点移动一定距离，并且是比例的十分之一。

1.  这意味着在编辑器中，您可以看到`BoxTwo`组件继承了其父组件`ChildSceneComponent`的平移和缩放。

# 创建自定义 Actor 组件

Actor 组件是实现应该在 Actor 之间共享的常见功能的简单方法。Actor 组件不会被渲染，但仍然可以执行操作，比如订阅事件或与包含它们的 Actor 的其他组件进行通信。

## 如何做...

1.  使用编辑器向导创建一个名为`RandomMovementComponent`的`ActorComponent`。将以下类说明符添加到`UCLASS`宏中：

```cpp
UCLASS( ClassGroup=(Custom), meta=(BlueprintSpawnableComponent) )
```

1.  在类头文件中添加以下`UPROPERTY`：

```cpp
UPROPERTY()
float MovementRadius;
```

1.  将以下内容添加到构造函数的实现中：

```cpp
MovementRadius = 0;
```

1.  最后，将以下内容添加到`TickComponent()`的实现中：

```cpp
AActor* Parent = GetOwner();
if (Parent)
{
  Parent->SetActorLocation(
  Parent->GetActorLocation() +
  FVector(
  FMath::FRandRange(-1, 1)* MovementRadius,
  FMath::FRandRange(-1, 1)* MovementRadius,
  FMath::FRandRange(-1, 1)* MovementRadius));
}
```

1.  验证您的代码是否如下所示：

```cpp
#pragma once
#include "Components/ActorComponent.h"
#include "RandomMovementComponent.generated.h"
UCLASS( ClassGroup=(Custom), meta=(BlueprintSpawnableComponent) )
class UE4COOKBOOK_API URandomMovementComponent : public UActorComponent
{
  GENERATED_BODY()
  public:
  URandomMovementComponent();
  virtual void BeginPlay() override;
  virtual void TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction ) override;
  UPROPERTY()
  float MovementRadius;
};

#include "UE4Cookbook.h"
#include "RandomMovementComponent.h"
URandomMovementComponent::URandomMovementComponent()
{
  bWantsBeginPlay = true;
  PrimaryComponentTick.bCanEverTick = true;
  MovementRadius = 5;
}

void URandomMovementComponent::BeginPlay()
{
  Super::BeginPlay();
}

void URandomMovementComponent::TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction )
{
  Super::TickComponent( DeltaTime, TickType, ThisTickFunction );
  AActor* Parent = GetOwner();
  if (Parent)
  {
    Parent->SetActorLocation(
    Parent->GetActorLocation() +
    FVector(
    FMath::FRandRange(-1, 1)* MovementRadius,
    FMath::FRandRange(-1, 1)* MovementRadius,
    FMath::FRandRange(-1, 1)* MovementRadius));
  }
}
```

1.  编译您的项目。在编辑器中，创建一个空的`Actor`，并将**Random Movement**组件添加到其中。要做到这一点，从**放置**选项卡中将**空 Actor**拖到级别中，然后在**详细信息**面板中单击**添加组件**，并选择**Random Movement**。再次执行相同的操作以添加**Cube**组件，以便您有东西来可视化 actor 的位置。![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00085.jpeg)![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00086.jpeg)

1.  播放你的关卡，并观察 actor 在每次调用`TickComponent`函数时随机移动的位置改变。

## 它是如何工作的...

1.  首先，在组件声明中使用的`UCLASS`宏中添加一些说明符。将`BlueprintSpawnableComponent`添加到类的元值中意味着可以在编辑器中将组件的实例添加到蓝图类中。`ClassGroup`说明符允许我们指示组件在类列表中属于哪个类别：

```cpp
UCLASS( ClassGroup=(Custom), meta=(BlueprintSpawnableComponent) )
```

1.  将`MovementRadius`作为新组件的属性添加，允许我们指定组件在单个帧中允许漫游的距离：

```cpp
UPROPERTY()
float MovementRadius;
```

1.  在构造函数中，我们将此属性初始化为安全的默认值：

```cpp
MovementRadius =5;
```

1.  `TickComponent`是引擎每帧调用的函数，就像`Tick`对于 Actors 一样。在其实现中，我们检索组件所有者的当前位置，即包含我们组件的`Actor`，并在世界空间中生成一个偏移量：

```cpp
AActor* Parent = GetOwner();
if (Parent)
{
  Parent->SetActorLocation(
  Parent->GetActorLocation() +
  FVector(
  FMath::FRandRange(-1, 1)* MovementRadius,
  FMath::FRandRange(-1, 1)* MovementRadius,
  FMath::FRandRange(-1, 1)* MovementRadius)
  );
}
```

1.  我们将随机偏移添加到当前位置以确定新位置，并将拥有的 actor 移动到该位置。这会导致 actor 的位置在每一帧随机改变并且跳动。

# 创建自定义 Scene Component

`Scene`组件是`Actor`组件的子类，具有变换，即相对位置、旋转和缩放。就像`Actor`组件一样，`Scene`组件本身不会被渲染，但可以使用它们的变换进行各种操作，比如在`Actor`的固定偏移处生成其他对象。

## 如何做...

1.  创建一个名为`ActorSpawnerComponent`的自定义`SceneComponent`。对头文件进行以下更改：

```cpp
UFUNCTION()
void Spawn();
UPROPERTY()
TSubclassOf<AActor> ActorToSpawn;
```

1.  将以下函数实现添加到 cpp 文件中：

```cpp
void UActorSpawnerComponent::Spawn()
{
  UWorld* TheWorld = GetWorld();
  if (TheWorld != nullptr)
  {
    FTransform ComponentTransform(this->GetComponentTransform());
    TheWorld->SpawnActor(ActorToSpawn,&ComponentTransform);
  }
}
```

1.  根据此片段验证您的代码：

```cpp
ActorSpawnerComponent.h
#pragma once

#include "Components/SceneComponent.h"
#include "ActorSpawnerComponent.generated.h"

UCLASS( ClassGroup=(Custom), meta=(BlueprintSpawnableComponent) )
class UE4COOKBOOK_API UActorSpawnerComponent : public USceneComponent
{
  GENERATED_BODY()

  public:
  UActorSpawnerComponent();

  virtual void BeginPlay() override;

  virtual void TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction ) override;

  UFUNCTION(BlueprintCallable, Category=Cookbook)
  void Spawn();

  UPROPERTY(EditAnywhere)
  TSubclassOf<AActor> ActorToSpawn;

};
ActorSpawnerComponent.cpp
#include "UE4Cookbook.h"
#include "ActorSpawnerComponent.h"

UActorSpawnerComponent::UActorSpawnerComponent()
{
  bWantsBeginPlay = true;
  PrimaryComponentTick.bCanEverTick = true;
}

void UActorSpawnerComponent::BeginPlay()
{
  Super::BeginPlay();
}

void UActorSpawnerComponent::TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction )
{
  Super::TickComponent( DeltaTime, TickType, ThisTickFunction );
}

void UActorSpawnerComponent::Spawn()
{
  UWorld* TheWorld = GetWorld();
  if (TheWorld != nullptr)
  {
    FTransform ComponentTransform(this->GetComponentTransform());
    TheWorld->SpawnActor(ActorToSpawn,&ComponentTransform);
  }
}
```

1.  编译并打开您的项目。将一个空的`Actor`拖到场景中，并将`ActorSpawnerComponent`添加到其中。在`详细信息`面板中选择您的新组件，并为`ActorToSpawn`分配一个值。现在，每当在组件的实例上调用`Spawn()`时，它将实例化`ActorToSpawn`中指定的`Actor`类的副本。

## 它是如何工作的...

1.  我们创建`Spawn UFUNCTION`和一个名为`ActorToSpawn`的变量。`ActorToSpawn`的`UPROPERTY`类型是`TSubclassOf<>`，这是一个模板类型，允许我们将指针限制为基类或其子类。这也意味着在编辑器中，我们将获得一个经过预过滤的类列表可供选择，防止我们意外分配无效值。![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00087.jpeg)

1.  在`Spawn`函数的实现中，我们可以访问我们的世界，并检查其有效性。

1.  `SpawnActor`需要一个`FTransform*`来指定生成新 Actor 的位置，因此我们创建一个新的堆栈变量来包含当前组件变换的副本。

1.  如果`TheWorld`有效，我们请求它生成一个`ActorToSpawn`指定的子类的实例，传入我们刚刚创建的`FTransform`的地址，其中现在包含了新`Actor`所需的位置。

## 另请参阅

+   第八章，“集成 C++和虚幻编辑器”，包含了对如何使蓝图可访问的更详细的调查。

# 创建自定义基本组件

`Primitive`组件是最复杂的`Actor`组件类型，因为它们不仅有一个变换，而且还在屏幕上呈现。

## 操作步骤...

1.  基于`MeshComponent`创建一个自定义的 C++类。当 Visual Studio 加载时，将以下内容添加到你的类头文件中：

```cpp
UCLASS(ClassGroup=Experimental, meta = (BlueprintSpawnableComponent))
public:
virtual FPrimitiveSceneProxy* CreateSceneProxy() override;
TArray<int32> Indices;
TArray<FVector> Vertices;
UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Materials)
UMaterial* TheMaterial;
```

1.  我们需要在 cpp 文件中为我们重写的`CreateSceneProxy`函数创建一个实现：

```cpp
FPrimitiveSceneProxy* UMyMeshComponent::CreateSceneProxy()
{
  FPrimitiveSceneProxy* Proxy = NULL;
  Proxy = new FMySceneProxy(this);
  return Proxy;
}
```

1.  这个函数返回一个`FMySceneProxy`的实例，我们需要实现它。通过在`CreateSceneProxy`函数上方添加以下代码来实现：

```cpp
class FMySceneProxy : public FPrimitiveSceneProxy
{
  public:
  FMySceneProxy(UMyMeshComponent* Component)
  :FPrimitiveSceneProxy(Component),
  Indices(Component->Indices),
  TheMaterial(Component->TheMaterial)
  {
    VertexBuffer = FMyVertexBuffer();
    IndexBuffer = FMyIndexBuffer();
    for (FVector Vertex : Component->Vertices)
    {
      Vertices.Add(FDynamicMeshVertex(Vertex));
    }
  };
  UPROPERTY()
  UMaterial* TheMaterial;
  virtual FPrimitiveViewRelevance GetViewRelevance(const FSceneView* View)  const override
  {
    FPrimitiveViewRelevance Result;
    Result.bDynamicRelevance = true;
    Result.bDrawRelevance = true;
    Result.bNormalTranslucencyRelevance = true;
    return Result;
  }
  virtual void GetDynamicMeshElements(const TArray<const FSceneView*>& Views, const FSceneViewFamily& ViewFamily, uint32 VisibilityMap, FMeshElementCollector& Collector) const override
  {
    for (int32 ViewIndex = 0; ViewIndex < Views.Num(); ViewIndex++)
    {
      FDynamicMeshBuilder MeshBuilder;
      if (Vertices.Num() == 0)
      {
        return;
      }
      MeshBuilder.AddVertices(Vertices);
      MeshBuilder.AddTriangles(Indices);
      MeshBuilder.GetMesh(FMatrix::Identity, new FColoredMaterialRenderProxy(TheMaterial->GetRenderProxy(false), FLinearColor::Gray), GetDepthPriorityGroup(Views[ViewIndex]), true, true, ViewIndex, Collector);
    }
  }
  uint32 FMySceneProxy::GetMemoryFootprint(void) const override
  {
    return sizeof(*this);
  }
  virtual ~FMySceneProxy() {};
  private:
  TArray<FDynamicMeshVertex> Vertices;
  TArray<int32> Indices;
  FMyVertexBuffer VertexBuffer;
  FMyIndexBuffer IndexBuffer;
};
```

1.  我们的场景代理需要一个顶点缓冲区和一个索引缓冲区。以下子类应该放在场景代理的实现之上：

```cpp
class FMyVertexBuffer : public FVertexBuffer
{
  public:
  TArray<FVector> Vertices;
  virtual void InitRHI() override
  {
    FRHIResourceCreateInfo CreateInfo;
    VertexBufferRHI = RHICreateVertexBuffer(Vertices.Num() * sizeof(FVector), BUF_Static, CreateInfo);
    void* VertexBufferData = RHILockVertexBuffer(VertexBufferRHI, 0, Vertices.Num() * sizeof(FVector), RLM_WriteOnly);
    FMemory::Memcpy(VertexBufferData, Vertices.GetData(), Vertices.Num() * sizeof(FVector));
    RHIUnlockVertexBuffer(VertexBufferRHI);
  }
};
class FMyIndexBuffer : public FIndexBuffer
{
  public:
  TArray<int32> Indices;
  virtual void InitRHI() override
  {
    FRHIResourceCreateInfo CreateInfo;
    IndexBufferRHI = RHICreateIndexBuffer(sizeof(int32), Indices.Num() * sizeof(int32), BUF_Static, CreateInfo);
    void* Buffer = RHILockIndexBuffer(IndexBufferRHI, 0, Indices.Num() * sizeof(int32), RLM_WriteOnly);
    FMemory::Memcpy(Buffer, Indices.GetData(), Indices.Num() * sizeof(int32));
    RHIUnlockIndexBuffer(IndexBufferRHI);
  }
};
```

1.  添加以下构造函数实现：

```cpp
UMyMeshComponent::UMyMeshComponent()
{
  static ConstructorHelpers::FObjectFinder<UMaterial> Material(TEXT("Material'/Engine/BasicShapes/BasicShapeMaterial'"));
  if (Material.Object != NULL)
  {
    TheMaterial = (UMaterial*)Material.Object;
  }
  Vertices.Add(FVector(10, 0, 0));
  Vertices.Add(FVector(0, 10, 0));
  Vertices.Add(FVector(0, 0, 10));
  Indices.Add(0);
  Indices.Add(1);
  Indices.Add(2);
}
```

1.  验证你的代码是否如下所示：

```cpp
#pragma once

#include "Components/MeshComponent.h"
#include "MyMeshComponent.generated.h"

UCLASS(ClassGroup = Experimental, meta = (BlueprintSpawnableComponent))
class UE4COOKBOOK_API UMyMeshComponent : public UMeshComponent
{
  GENERATED_BODY()
  public:
  virtual FPrimitiveSceneProxy* CreateSceneProxy() override;
  TArray<int32> Indices;
  TArray<FVector> Vertices;

  UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = Materials)
  UMaterial* TheMaterial;
  UMyMeshComponent();
};

#include "UE4Cookbook.h"
#include "MyMeshComponent.h"
#include <VertexFactory.h>
#include "DynamicMeshBuilder.h"

class FMyVertexBuffer : public FVertexBuffer
{
  public:
  TArray<FVector> Vertices;

  virtual void InitRHI() override
  {
    FRHIResourceCreateInfo CreateInfo;
    VertexBufferRHI = RHICreateVertexBuffer(Vertices.Num() * sizeof(FVector), BUF_Static, CreateInfo);

    void* VertexBufferData = RHILockVertexBuffer(VertexBufferRHI, 0, Vertices.Num() * sizeof(FVector), RLM_WriteOnly);
    FMemory::Memcpy(VertexBufferData, Vertices.GetData(), Vertices.Num() * sizeof(FVector));
    RHIUnlockVertexBuffer(VertexBufferRHI);
  }
};

class FMyIndexBuffer : public FIndexBuffer
{
  public:
  TArray<int32> Indices;

  virtual void InitRHI() override
  {
    FRHIResourceCreateInfo CreateInfo;
    IndexBufferRHI = RHICreateIndexBuffer(sizeof(int32), Indices.Num() * sizeof(int32), BUF_Static, CreateInfo);

    void* Buffer = RHILockIndexBuffer(IndexBufferRHI, 0, Indices.Num() * sizeof(int32), RLM_WriteOnly);
    FMemory::Memcpy(Buffer, Indices.GetData(), Indices.Num() * sizeof(int32));
    RHIUnlockIndexBuffer(IndexBufferRHI);
  }
};
class FMySceneProxy : public FPrimitiveSceneProxy
{
  public:
  FMySceneProxy(UMyMeshComponent* Component)
  :FPrimitiveSceneProxy(Component),
  Indices(Component->Indices),
  TheMaterial(Component->TheMaterial)
  {
    VertexBuffer = FMyVertexBuffer();
    IndexBuffer = FMyIndexBuffer();

    for (FVector Vertex : Component->Vertices)
    {
      Vertices.Add(FDynamicMeshVertex(Component->GetComponentLocation() + Vertex));
    }
  };

UPROPERTY()
  UMaterial* TheMaterial;

  virtual FPrimitiveViewRelevance GetViewRelevance(const FSceneView* View)  const override
  {
    FPrimitiveViewRelevance Result;
    Result.bDynamicRelevance = true;
    Result.bDrawRelevance = true;
    Result.bNormalTranslucencyRelevance = true;
    return Result;
  }

  virtual void GetDynamicMeshElements(const TArray<const FSceneView*>& Views, const FSceneViewFamily& ViewFamily, uint32 VisibilityMap, FMeshElementCollector& Collector) const override
  {
    for (int32 ViewIndex = 0; ViewIndex < Views.Num(); ViewIndex++)
    {
      FDynamicMeshBuilder MeshBuilder;
      if (Vertices.Num() == 0)
      {
        return;
      }
      MeshBuilder.AddVertices(Vertices);
      MeshBuilder.AddTriangles(Indices);

      MeshBuilder.GetMesh(FMatrix::Identity, new FColoredMaterialRenderProxy(TheMaterial->GetRenderProxy(false), FLinearColor::Gray), GetDepthPriorityGroup(Views[ViewIndex]), true, true, ViewIndex, Collector);

    }
  }

  void FMySceneProxy::OnActorPositionChanged() override
  {
    VertexBuffer.ReleaseResource();
    IndexBuffer.ReleaseResource();
  }

  uint32 FMySceneProxy::GetMemoryFootprint(void) const override
  {
    return sizeof(*this);
  }
  virtual ~FMySceneProxy() {};
  private:
  TArray<FDynamicMeshVertex> Vertices;
  TArray<int32> Indices;
  FMyVertexBuffer VertexBuffer;
  FMyIndexBuffer IndexBuffer;
};

FPrimitiveSceneProxy* UMyMeshComponent::CreateSceneProxy()
{
  FPrimitiveSceneProxy* Proxy = NULL;
  Proxy = new FMySceneProxy(this);
  return Proxy;
}

UMyMeshComponent::UMyMeshComponent()
{
  static ConstructorHelpers::FObjectFinder<UMaterial> Material(TEXT("Material'/Engine/BasicShapes/BasicShapeMaterial'"));

  if (Material.Object != NULL)
  {
    TheMaterial = (UMaterial*)Material.Object;
  }
  Vertices.Add(FVector(10, 0, 0));
  Vertices.Add(FVector(0, 10, 0));
  Vertices.Add(FVector(0, 0, 10));
  Indices.Add(0);
  Indices.Add(1);
  Indices.Add(2);
}
```

1.  在编辑器中创建一个空的`Actor`，并将新的网格组件添加到其中，以查看你的三角形是否被渲染。尝试通过更改添加到顶点的值来进行实验。添加并查看在重新编译后几何图形如何改变。![操作步骤](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00088.jpeg)

## 它是如何工作的...

1.  为了渲染一个`Actor`，描述它的数据需要被传递给渲染线程。

1.  最简单的方法是使用场景代理-在渲染线程上创建的代理对象，旨在为数据传输提供线程安全性。

1.  `PrimitiveComponent`类定义了一个`CreateSceneProxy`函数，返回`FPrimitiveSceneProxy*`。这个函数允许像我们这样的自定义组件返回一个基于`FPrimitiveSceneProxy`的对象，利用多态性。

1.  我们定义了`SceneProxy`对象的构造函数，以便每个创建的`SceneProxy`都知道与其关联的组件实例。

1.  然后这些数据被缓存在场景代理中，并使用`GetDynamicMeshElements`传递给渲染器。

1.  我们创建了一个`IndexBuffer`和一个`VertexBuffer`。我们创建的每个缓冲区类都是辅助类，帮助场景代理为这两个缓冲区分配特定于平台的内存。它们在`InitRHI`（也称为初始化渲染硬件接口）函数中这样做，在这个函数中，它们使用 RHI API 的函数来创建一个顶点缓冲区，锁定它，复制所需的数据，然后解锁它。

1.  在组件的构造函数中，我们使用`ObjectFinder`模板查找内置在引擎中的材质资源，以便我们的网格有一个材质。

1.  然后我们向我们的缓冲区添加一些顶点和索引，以便在渲染器请求场景代理时可以绘制网格。

# 为 RPG 创建一个 InventoryComponent

一个`InventoryComponent`使其包含的`Actor`能够在其库存中存储`InventoryActors`，并将它们放回游戏世界中。

## 准备工作

在继续本教程之前，请确保你已经按照第六章，“输入和碰撞”，中的*轴映射-键盘、鼠标和游戏手柄方向输入用于 FPS 角色*教程中的步骤进行操作，因为它向你展示了如何创建一个简单的角色。

此外，本章中的*使用 SpawnActor 实例化 Actor*教程向你展示了如何创建一个自定义的`GameMode`。

## 操作步骤...

1.  使用引擎创建一个`ActorComponent`子类，名为`InventoryComponent`，然后将以下代码添加到其中：

```cpp
UPROPERTY()
TArray<AInventoryActor*> CurrentInventory;
UFUNCTION()
int32 AddToInventory(AInventoryActor* ActorToAdd);

UFUNCTION()
void RemoveFromInventory(AInventoryActor* ActorToRemove);
```

1.  将以下函数实现添加到源文件中：

```cpp
int32 UInventoryComponent::AddToInventory(AInventoryActor* ActorToAdd)
{
  return CurrentInventory.Add(ActorToAdd);
}

void UInventoryComponent::RemoveFromInventory(AInventoryActor* ActorToRemove)
{
  CurrentInventory.Remove(ActorToRemove);
}
```

1.  接下来，创建一个名为`InventoryActor`的新`StaticMeshActor`子类。将以下内容添加到其声明中：

```cpp
virtual void PickUp();
virtual void PutDown(FTransform TargetLocation);
```

1.  在实现文件中实现新函数：

```cpp
void AInventoryActor::PickUp()
{
  SetActorTickEnabled(false);
  SetActorHiddenInGame(true);
  SetActorEnableCollision(false);
}

void AInventoryActor::PutDown(FTransform TargetLocation)
{
  SetActorTickEnabled(true);
  SetActorHiddenInGame(false);
  SetActorEnableCollision(true);
  SetActorLocation(TargetLocation.GetLocation());
}
```

1.  还要更改构造函数如下：

```cpp
AInventoryActor::AInventoryActor()
:Super()
{
  PrimaryActorTick.bCanEverTick = true;
  auto MeshAsset = ConstructorHelpers::FObjectFinder<UStaticMesh>(TEXT("StaticMesh'/Engine/BasicShapes/Cube.Cube'"));
  if (MeshAsset.Object != nullptr)
  {
    GetStaticMeshComponent()->SetStaticMesh(MeshAsset.Object);
    GetStaticMeshComponent()->SetCollisionProfileName(UCollisionProfile::Pawn_ProfileName);
  }
  GetStaticMeshComponent()->SetMobility(EComponentMobility::Movable);
  SetActorEnableCollision(true);
}
```

1.  我们需要向角色添加`InventoryComponent`，以便我们有一个可以存储物品的库存。使用编辑器创建一个新的`SimpleCharacter`子类，并将以下内容添加到其声明中：

```cpp
UPROPERTY()
UInventoryComponent* MyInventory;

UFUNCTION()
virtual void SetupPlayerInputComponent(class UInputComponent* InputComponent) override;

UFUNCTION()
void DropItem();
UFUNCTION()
void TakeItem(AInventoryActor* InventoryItem);

UFUNCTION()
virtual void NotifyHit(class UPrimitiveComponent* MyComp, AActor* Other, class UPrimitiveComponent* OtherComp, bool bSelfMoved, FVector HitLocation, FVector HitNormal, FVector NormalImpulse, const FHitResult& Hit) override;
```

1.  将此行添加到角色的构造函数实现中：

```cpp
MyInventory = CreateDefaultSubobject<UInventoryComponent>("MyInventory");
```

1.  将此代码添加到重写的`SetupPlayerInputComponent`中：

```cpp
void AInventoryCharacter::SetupPlayerInputComponent(class UInputComponent* InputComponent)
{
  Super::SetupPlayerInputComponent(InputComponent);
  InputComponent->BindAction("DropItem", EInputEvent::IE_Pressed, this, &AInventoryCharacter::DropItem);
}
```

1.  最后，添加以下函数实现：

```cpp
void AInventoryCharacter::DropItem()
{
  if (MyInventory->CurrentInventory.Num() == 0)
  {
    return;
  }

  AInventoryActor* Item = MyInventory->CurrentInventory.Last();
  MyInventory->RemoveFromInventory(Item);
  FVector ItemOrigin;
  FVector ItemBounds;
  Item->GetActorBounds(false, ItemOrigin, ItemBounds);
  FTransform PutDownLocation = GetTransform() + FTransform(RootComponent->GetForwardVector() * ItemBounds.GetMax());
  Item->PutDown(PutDownLocation);
}

void AInventoryCharacter::NotifyHit(class UPrimitiveComponent* MyComp, AActor* Other, class UPrimitiveComponent* OtherComp, bool bSelfMoved, FVector HitLocation, FVector HitNormal, FVector NormalImpulse, const FHitResult& Hit)
{
  AInventoryActor* InventoryItem = Cast<AInventoryActor>(Other);
  if (InventoryItem != nullptr)
  {
    TakeItem(InventoryItem);
  }
}

void AInventoryCharacter::TakeItem(AInventoryActor* InventoryItem)
{
  InventoryItem->PickUp();
  MyInventory->AddToInventory(InventoryItem);
}
```

1.  编译您的代码并在编辑器中进行测试。创建一个新级别，并将几个`InventoryActor`实例拖到场景中。

1.  如果需要提醒如何重写当前游戏模式，请参考*使用 SpawnActor 实例化 Actor*配方。将以下行添加到该配方中的游戏模式构造函数中，然后将您的级别的`GameMode`设置为您在该配方中创建的游戏模式：

```cpp
DefaultPawnClass = AInventoryCharacter::StaticClass();
```

1.  在编译和启动项目之前，请对照此处的清单验证您的代码。

```cpp
#pragma once

#include "GameFramework/Character.h"
#include "InventoryComponent.h"
#include "InventoryCharacter.generated.h"

UCLASS()
class UE4COOKBOOK_API AInventoryCharacter : public ACharacter
{
  GENERATED_BODY()

  public:
  AInventoryCharacter();
  virtual void BeginPlay() override;
  virtual void Tick( float DeltaSeconds ) override;
  virtual void SetupPlayerInputComponent(class UInputComponent* InputComponent) override;

  UPROPERTY()
  UInventoryComponent* MyInventory;
  UPROPERTY()
  UCameraComponent* MainCamera;
  UFUNCTION()
  void TakeItem(AInventoryActor* InventoryItem);
  UFUNCTION()
  void DropItem();
  void MoveForward(float AxisValue);
  void MoveRight(float AxisValue);
  void PitchCamera(float AxisValue);
  void YawCamera(float AxisValue);

  UFUNCTION()
  virtual void NotifyHit(class UPrimitiveComponent* MyComp, AActor* Other, class UPrimitiveComponent* OtherComp, bool bSelfMoved, FVector HitLocation, FVector HitNormal, FVector NormalImpulse, const FHitResult& Hit) override;
  private:
  FVector MovementInput;
  FVector CameraInput;
};

#include "UE4Cookbook.h"
#include "InventoryCharacter.h"

AInventoryCharacter::AInventoryCharacter()
:Super()
{
  PrimaryActorTick.bCanEverTick = true;
  MyInventory = CreateDefaultSubobject<UInventoryComponent>("MyInventory");
  MainCamera = CreateDefaultSubobject<UCameraComponent>("MainCamera");
  MainCamera->bUsePawnControlRotation = 0;
}

void AInventoryCharacter::BeginPlay()
{
  Super::BeginPlay();
  MainCamera->AttachTo(RootComponent);
}

void AInventoryCharacter::Tick( float DeltaTime )
{
  Super::Tick( DeltaTime );
  if (!MovementInput.IsZero())
  {
    MovementInput *= 100;
    FVector InputVector = FVector(0,0,0);
    InputVector += GetActorForwardVector()* MovementInput.X * DeltaTime;
    InputVector += GetActorRightVector()* MovementInput.Y * DeltaTime;
    GetCharacterMovement()->AddInputVector(InputVector);
    GEngine->AddOnScreenDebugMessage(-1, 1, FColor::Red, FString::Printf(TEXT("x- %f, y - %f, z - %f"),InputVector.X, InputVector.Y, InputVector.Z));
  }

  if (!CameraInput.IsNearlyZero())
  {
    FRotator NewRotation = GetActorRotation();
    NewRotation.Pitch += CameraInput.Y;
    NewRotation.Yaw += CameraInput.X;
    APlayerController* MyPlayerController =Cast<APlayerController>(GetController());
    if (MyPlayerController != nullptr)
    {
      MyPlayerController->AddYawInput(CameraInput.X);
      MyPlayerController->AddPitchInput(CameraInput.Y);
    }
    SetActorRotation(NewRotation);
  }
}
void AInventoryCharacter::SetupPlayerInputComponent(class UInputComponent* InputComponent)
{
  Super::SetupPlayerInputComponent(InputComponent);
  InputComponent->BindAxis("MoveForward", this, &AInventoryCharacter::MoveForward);
  InputComponent->BindAxis("MoveRight", this, &AInventoryCharacter::MoveRight);
  InputComponent->BindAxis("CameraPitch", this, &AInventoryCharacter::PitchCamera);
  InputComponent->BindAxis("CameraYaw", this, &AInventoryCharacter::YawCamera);
  InputComponent->BindAction("DropItem", EInputEvent::IE_Pressed, this, &AInventoryCharacter::DropItem);
}
void AInventoryCharacter::DropItem()
{
  if (MyInventory->CurrentInventory.Num() == 0)
  {
    return;
  }
  AInventoryActor* Item = MyInventory->CurrentInventory.Last();
  MyInventory->RemoveFromInventory(Item);
  FVector ItemOrigin;
  FVector ItemBounds;
  Item->GetActorBounds(false, ItemOrigin, ItemBounds);
  FTransform PutDownLocation = GetTransform() + FTransform(RootComponent->GetForwardVector() * ItemBounds.GetMax());
  Item->PutDown(PutDownLocation);
}

void AInventoryCharacter::MoveForward(float AxisValue)
{
  MovementInput.X = FMath::Clamp<float>(AxisValue, -1.0f, 1.0f);
}

void AInventoryCharacter::MoveRight(float AxisValue)
{
  MovementInput.Y = FMath::Clamp<float>(AxisValue, -1.0f, 1.0f);
}

void AInventoryCharacter::PitchCamera(float AxisValue)
{
  CameraInput.Y = AxisValue;
}
void AInventoryCharacter::YawCamera(float AxisValue)
{
  CameraInput.X = AxisValue;
}
void AInventoryCharacter::NotifyHit(class UPrimitiveComponent* MyComp, AActor* Other, class UPrimitiveComponent* OtherComp, bool bSelfMoved, FVector HitLocation, FVector HitNormal, FVector NormalImpulse, const FHitResult& Hit)
{
  AInventoryActor* InventoryItem = Cast<AInventoryActor>(Other);
  if (InventoryItem != nullptr)
  {
    TakeItem(InventoryItem);
  }
}
void AInventoryCharacter::TakeItem(AInventoryActor* InventoryItem)
{
  InventoryItem->PickUp();
  MyInventory->AddToInventory(InventoryItem);
}

#pragma once

#include "Components/ActorComponent.h"
#include "InventoryActor.h"
#include "InventoryComponent.generated.h"

UCLASS( ClassGroup=(Custom), meta=(BlueprintSpawnableComponent))
class UE4COOKBOOK_API UInventoryComponent : public UActorComponent
{
  GENERATED_BODY()

  public:
  UInventoryComponent();
  virtual void TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction ) override;

  UPROPERTY()
  TArray<AInventoryActor*> CurrentInventory;
  UFUNCTION()
  int32 AddToInventory(AInventoryActor* ActorToAdd);

  UFUNCTION()
  void RemoveFromInventory(AInventoryActor* ActorToRemove);
};
#include "UE4Cookbook.h"
#include "InventoryComponent.h"

UInventoryComponent::UInventoryComponent()
{
  bWantsBeginPlay = true;
  PrimaryComponentTick.bCanEverTick = true;
}
void UInventoryComponent::TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction )
{
  Super::TickComponent( DeltaTime, TickType, ThisTickFunction );
}

int32 UInventoryComponent::AddToInventory(AInventoryActor* ActorToAdd)
{
  return CurrentInventory.Add(ActorToAdd);
}

void UInventoryComponent::RemoveFromInventory(AInventoryActor* ActorToRemove)
{
  CurrentInventory.Remove(ActorToRemove);
}

#pragma once

#include "GameFramework/GameMode.h"
#include "UE4CookbookGameMode.generated.h"

UCLASS()
class UE4COOKBOOK_API AUE4CookbookGameMode : public AGameMode
{
  GENERATED_BODY()

  public:
  AUE4CookbookGameMode();
  };

#include "UE4Cookbook.h"
#include "MyGameState.h"
#include "InventoryCharacter.h"
#include "UE4CookbookGameMode.h"

AUE4CookbookGameMode::AUE4CookbookGameMode()
{
  DefaultPawnClass = AInventoryCharacter::StaticClass();
  GameStateClass = AMyGameState::StaticClass();
}
```

1.  最后，我们需要在编辑器中的绑定中添加我们的`InputAction`。为此，通过选择**Edit** | **Project Settings...**来打开**Project Settings...**窗口：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00089.jpeg)

然后，在左侧选择**Input**。选择**Action Mappings**旁边的加号符号，并在出现的文本框中键入`DropItem`。在其下是您可以绑定到此操作的所有潜在按键的列表。选择标记为`E`的按键。您的设置现在应如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00090.jpeg)

1.  然后我们可以点击播放，走到我们的库存角色旁边，它将被拾起。按*E*键将角色放置在新位置！通过多个库存角色测试，看它们是否都被正确收集和放置。

## 工作原理...

1.  我们的新组件包含一个存储指针的角色数组，以及声明添加或移除项目到数组的函数。这些函数是围绕`TArray`的添加/移除功能的简单包装器，但允许我们选择性地执行诸如在继续存储项目之前检查数组是否在指定大小限制内等操作。

1.  `InventoryActor`是一个基类，可用于玩家拿走的所有物品。

1.  在`PickUp`函数中，我们需要在拾起时禁用角色。为此，我们必须执行以下操作：

+   禁用角色打勾

+   隐藏角色

+   禁用碰撞

1.  我们使用`SetActorTickEnabled`、`SetActorHiddenInGame`和`SetActorEnableCollision`函数来实现这一点。

1.  `PutDown`函数是相反的。我们启用角色打勾，取消隐藏角色，然后重新打开其碰撞，并将角色传送到所需位置。

1.  我们还在新角色中添加了`InventoryComponent`以及一个用于获取物品的函数。

1.  在我们角色的构造函数中，我们为我们的`InventoryComponent`创建了一个默认子对象。

1.  我们还添加了一个`NotifyHit`覆盖，以便在角色撞到其他角色时得到通知。

1.  在此函数中，我们将其他角色转换为`InventoryActor`。如果转换成功，那么我们知道我们的`Actor`是一个`InventoryActor`，因此我们可以调用`TakeItem`函数来拿起它。

1.  在`TakeItem`函数中，我们通知库存物品角色我们要拿起它，然后将其添加到我们的库存中。

1.  `InventoryCharacter`中的最后一个功能是`DropItem`函数。此函数检查我们的库存中是否有任何物品。如果有任何物品，我们将其从库存中移除，然后使用物品边界计算我们的玩家角色前方的安全距离，以便放下物品。

1.  然后，我们通知物品我们正在将其放置在所需位置的世界中。

## 另请参阅

+   第五章, *处理事件和委托*，详细解释了事件和输入处理在引擎中如何一起工作，以及本教程中提到的`SimpleCharacter`类的用法。

+   第六章, *输入和碰撞*，还有关于绑定输入动作和轴的教程

# 创建一个 OrbitingMovement 组件

这个组件类似于`RotatingMovementComponent`，它旨在使附加到它的组件以特定方式移动。在这种情况下，它将以固定距离围绕固定点移动任何附加的组件。

例如，这可以用于**动作 RPG**中围绕角色旋转的护盾。

## 操作步骤...

1.  创建一个新的`SceneComponent`子类，并将以下属性添加到类声明中：

```cpp
UPROPERTY()
bool RotateToFaceOutwards;
UPROPERTY()
float RotationSpeed;
UPROPERTY()
float OrbitDistance;
float CurrentValue;
```

1.  将以下内容添加到构造函数中：

```cpp
RotationSpeed = 5;
OrbitDistance = 100;
CurrentValue = 0;
RotateToFaceOutwards = true;
```

1.  将以下代码添加到`TickComponent`函数中：

```cpp
float CurrentValueInRadians = FMath::DegreesToRadians<float>(CurrentValue);
SetRelativeLocation(FVector(OrbitDistance * FMath::Cos(CurrentValueInRadians), OrbitDistance * FMath::Sin(CurrentValueInRadians), RelativeLocation.Z));
if (RotateToFaceOutwards)
{
  FVector LookDir = (RelativeLocation).GetSafeNormal();
  FRotator LookAtRot = LookDir.Rotation();
  SetRelativeRotation(LookAtRot);
}
CurrentValue = FMath::Fmod(CurrentValue + (RotationSpeed* DeltaTime) ,360);
```

1.  根据以下清单验证你的工作：

```cpp
#pragma once
#include "Components/SceneComponent.h"
#include "OrbitingMovementComponent.generated.h"

UCLASS( ClassGroup=(Custom), meta=(BlueprintSpawnableComponent) )
class UE4COOKBOOK_API UOrbitingMovementComponent : public USceneComponent
{
  GENERATED_BODY()
  public:
  // Sets default values for this component's properties
  UOrbitingMovementComponent();

  // Called when the game starts
  virtual void BeginPlay() override;
  // Called every frame
  virtual void TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction ) override;

  UPROPERTY()
  bool RotateToFaceOutwards;
  UPROPERTY()
  float RotationSpeed;
  UPROPERTY()
  float OrbitDistance;
  float CurrentValue;
};
#include "UE4Cookbook.h"
#include "OrbitingMovementComponent.h"
// Sets default values for this component's properties
UOrbitingMovementComponent::UOrbitingMovementComponent()
{
  // Set this component to be initialized when the game starts, and to be ticked every frame. You can turn these features
  // off to improve performance if you don't need them.
  bWantsBeginPlay = true;
  PrimaryComponentTick.bCanEverTick = true;
  RotationSpeed = 5;
  OrbitDistance = 100;
  CurrentValue = 0;
  RotateToFaceOutwards = true;
  //...
}

// Called when the game starts
void UOrbitingMovementComponent::BeginPlay()
{
  Super::BeginPlay();
  //...
}
// Called every frame
void UOrbitingMovementComponent::TickComponent( float DeltaTime, ELevelTick TickType, FActorComponentTickFunction* ThisTickFunction )
{
  Super::TickComponent( DeltaTime, TickType, ThisTickFunction );
  float CurrentValueInRadians = FMath::DegreesToRadians<float>(CurrentValue);
  SetRelativeLocation(
  FVector(OrbitDistance * FMath::Cos(CurrentValueInRadians),
  OrbitDistance * FMath::Sin(CurrentValueInRadians),
  RelativeLocation.Z));
  if (RotateToFaceOutwards)
  {
    FVector LookDir = (RelativeLocation).GetSafeNormal();
    FRotator LookAtRot = LookDir.Rotation();
    SetRelativeRotation(LookAtRot);
  }
  CurrentValue = FMath::Fmod(CurrentValue + (RotationSpeed* DeltaTime) ,360);
  //...
}
```

1.  你可以通过创建一个简单的`Actor`蓝图来测试这个组件。

1.  将一个`OrbitingMovement`组件添加到你的`Actor`中，然后使用`Cube`组件添加一些网格。通过将它们拖放到**Components**面板中的`OrbitingMovement`组件上，将它们作为子组件。最终的层次结构应该如下所示：![How to do it...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/ue4-scp-cpp-cb/img/00091.jpeg)

1.  如果你对这个过程不确定，可以参考*创建自定义 Actor 组件*教程。

1.  点击播放，看看网格是否围绕`Actor`中心以圆周运动。

## 工作原理...

1.  添加到组件的属性是我们用来自定义组件的圆周运动的基本参数。

1.  `RotateToFaceOutwards`指定组件是否在每次更新时朝向远离旋转中心。`RotationSpeed`是组件每秒旋转的度数。

1.  `OrbitDistance`表示旋转的组件必须从原点移动的距离。`CurrentValue`是当前的旋转位置（以度为单位）。

1.  在我们的构造函数中，我们为我们的新组件建立了一些合理的默认值。

1.  在`TickComponent`函数中，我们计算我们组件的位置和旋转。

1.  下一步的公式要求我们的角度用弧度而不是度来表示。弧度用 *π* 来描述角度。我们首先使用`DegreesToRadians`函数将我们当前的度数值转换为弧度。

1.  `SetRelativeLocation`函数使用了圆周运动的一般方程，即 *Pos(θ) = cos(θ in radians), sin(θ in radians)*。我们保留每个对象的 Z 轴位置。

1.  下一步是将对象旋转回原点（或者直接远离原点）。只有当`RotateToFaceOutwards`为`true`时才会计算这一步，它涉及到获取组件相对于其父级的相对偏移，并创建一个基于从父级指向当前相对偏移的向量的旋转器。然后我们将相对旋转设置为结果旋转器。

1.  最后，我们增加当前的度数值，使其每秒移动`RotationSpeed`单位，将结果值夹在 0 和 360 之间，以允许旋转循环。

# 创建一个生成单位的建筑

对于这个教程，我们将创建一个在特定位置定时生成单位的建筑。

## 操作步骤...

1.  在编辑器中创建一个新的`Actor`子类，然后将以下实现添加到类中：

```cpp
UPROPERTY()
UStaticMeshComponent* BuildingMesh;
UPROPERTY()
UParticleSystemComponent* SpawnPoint;

UPROPERTY()
UClass* UnitToSpawn;

UPROPERTY()
float SpawnInterval;

UFUNCTION()
void SpawnUnit();

UFUNCTION()
void EndPlay(const EEndPlayReason::Type EndPlayReason) override;

UPROPERTY()
FTimerHandle SpawnTimerHandle;
```

1.  将以下内容添加到构造函数中：

```cpp
BuildingMesh = CreateDefaultSubobject<UStaticMeshComponent>("BuildingMesh");
SpawnPoint = CreateDefaultSubobject<UParticleSystemComponent>("SpawnPoint");
SpawnInterval = 10;
auto MeshAsset = ConstructorHelpers::FObjectFinder<UStaticMesh>(TEXT("StaticMesh'/Engine/BasicShapes/Cube.Cube'"));
if (MeshAsset.Object != nullptr)
{
  BuildingMesh->SetStaticMesh(MeshAsset.Object);
  BuildingMesh->SetCollisionProfileName(UCollisionProfile::Pawn_ProfileName);

}
auto ParticleSystem =
ConstructorHelpers::FObjectFinder<UParticleSystem>(TEXT("ParticleSystem'/Engine/Tutorial/SubEditors/TutorialAssets/TutorialParticleSystem.TutorialParticleSystem'"));
if (ParticleSystem.Object != nullptr)
{
  SpawnPoint->SetTemplate(ParticleSystem.Object);
}
SpawnPoint->SetRelativeScale3D(FVector(0.5, 0.5, 0.5));
UnitToSpawn = ABarracksUnit::StaticClass();
```

1.  将以下内容添加到`BeginPlay`函数中：

```cpp
RootComponent = BuildingMesh;
SpawnPoint->AttachTo(RootComponent);
SpawnPoint->SetRelativeLocation(FVector(150, 0, 0));
GetWorld()->GetTimerManager().SetTimer(SpawnTimerHandle, this, &ABarracks::SpawnUnit, SpawnInterval, true);
```

1.  为`SpawnUnit`函数创建实现：

```cpp
void ABarracks::SpawnUnit()
{
  FVector SpawnLocation = SpawnPoint->GetComponentLocation();
  GetWorld()->SpawnActor(UnitToSpawn, &SpawnLocation);
}
```

1.  实现重写的`EndPlay`函数：

```cpp
void ABarracks::EndPlay(const EEndPlayReason::Type EndPlayReason)
{
  Super::EndPlay(EndPlayReason);
  GetWorld()->GetTimerManager().ClearTimer(SpawnTimerHandle);
}
```

1.  接下来，创建一个新的角色子类，并添加一个属性：

```cpp
UPROPERTY()
UParticleSystemComponent* VisualRepresentation;
```

1.  在构造函数中初始化组件：

```cpp
VisualRepresentation = CreateDefaultSubobject<UParticleSystemComponent>("SpawnPoint");
auto ParticleSystem =ConstructorHelpers::FObjectFinder<UParticleSystem>(TEXT("ParticleSystem'/Engine/Tutorial/SubEditors/TutorialAssets/TutorialParticleSystem.TutorialParticleSystem'"));
if (ParticleSystem.Object != nullptr)
{
  SpawnPoint->SetTemplate(ParticleSystem.Object);
}
SpawnPoint->SetRelativeScale3D(FVector(0.5, 0.5, 0.5));
SpawnCollisionHandlingMethod = ESpawnActorCollisionHandlingMethod::AlwaysSpawn;
```

1.  将可视化表示附加到根组件：

```cpp
void ABarracksUnit::BeginPlay()
{
  Super::BeginPlay();
  SpawnPoint->AttachTo(RootComponent);
}
```

1.  最后，将以下内容添加到 `Tick` 函数中以使生成的角色移动：

```cpp
SetActorLocation(GetActorLocation() + FVector(10, 0, 0));
```

1.  根据以下片段进行验证，然后编译您的项目。将兵营角色的副本放入级别中。然后您可以观察它以固定间隔生成角色：

```cpp
#pragma once
#include "GameFramework/Actor.h"
#include "Barracks.generated.h"
UCLASS()
class UE4COOKBOOK_API ABarracks : public AActor
{
  GENERATED_BODY()
  public:
  ABarracks();
  virtual void BeginPlay() override;
  virtual void Tick( float DeltaSeconds ) override;

  UPROPERTY()
  UStaticMeshComponent* BuildingMesh;
  UPROPERTY()
  UParticleSystemComponent* SpawnPoint;

  UPROPERTY()
  UClass* UnitToSpawn;

  UPROPERTY()
  float SpawnInterval;

  UFUNCTION()
  void SpawnUnit();
  UFUNCTION()
  void EndPlay(const EEndPlayReason::Type EndPlayReason) override;

  UPROPERTY()
  FTimerHandle SpawnTimerHandle;
};

#include "UE4Cookbook.h"
#include "BarracksUnit.h"
#include "Barracks.h"

// Sets default values
ABarracks::ABarracks()
{
  // Set this actor to call Tick() every frame. You can turn this off to improve performance if you don't need it.
  PrimaryActorTick.bCanEverTick = true;
  BuildingMesh = CreateDefaultSubobject<UStaticMeshComponent>("BuildingMesh");
  SpawnPoint = CreateDefaultSubobject<UParticleSystemComponent>("SpawnPoint");
  SpawnInterval = 10;
  auto MeshAsset = ConstructorHelpers::FObjectFinder<UStaticMesh>(TEXT("StaticMesh'/Engine/BasicShapes/Cube.Cube'"));
  if (MeshAsset.Object != nullptr)
  {
    BuildingMesh->SetStaticMesh(MeshAsset.Object);
    BuildingMesh->SetCollisionProfileName(UCollisionProfile::Pawn_ProfileName);

  }
  auto ParticleSystem = ConstructorHelpers::FObjectFinder<UParticleSystem>(TEXT("ParticleSystem'/Engine/Tutorial/SubEditors/TutorialAssets/TutorialParticleSystem.TutorialParticleSystem'"));
  if (ParticleSystem.Object != nullptr)
  {
    SpawnPoint->SetTemplate(ParticleSystem.Object);
  }
  SpawnPoint->SetRelativeScale3D(FVector(0.5, 0.5, 0.5));
  UnitToSpawn = ABarracksUnit::StaticClass();
}
void ABarracks::BeginPlay()
{
  Super::BeginPlay();
  RootComponent = BuildingMesh;
  SpawnPoint->AttachTo(RootComponent);
  SpawnPoint->SetRelativeLocation(FVector(150, 0, 0));
  GetWorld()->GetTimerManager().SetTimer(SpawnTimerHandle, this, &ABarracks::SpawnUnit, SpawnInterval, true);
}

void ABarracks::Tick( float DeltaTime )
{
  Super::Tick( DeltaTime );
}
void ABarracks::SpawnUnit()
{
  FVector SpawnLocation = SpawnPoint->GetComponentLocation();
  GetWorld()->SpawnActor(UnitToSpawn, &SpawnLocation);
}

void ABarracks::EndPlay(const EEndPlayReason::Type EndPlayReason)
{
  Super::EndPlay(EndPlayReason);
  GetWorld()->GetTimerManager().ClearTimer(SpawnTimerHandle);
}

#pragma once

#include "GameFramework/Character.h"
#include "BarracksUnit.generated.h"

UCLASS()
class UE4COOKBOOK_API ABarracksUnit : public ACharacter
{
  GENERATED_BODY()

  public:
  ABarracksUnit();

  virtual void BeginPlay() override;
  virtual void Tick( float DeltaSeconds ) override;

  virtual void SetupPlayerInputComponent(class UInputComponent* InputComponent) override;

  UPROPERTY()
  UParticleSystemComponent* SpawnPoint;
};

#include "UE4Cookbook.h"
#include "BarracksUnit.h"

ABarracksUnit::ABarracksUnit()
{
  PrimaryActorTick.bCanEverTick = true;
  SpawnPoint = CreateDefaultSubobject<UParticleSystemComponent>("SpawnPoint");
  auto ParticleSystem =ConstructorHelpers::FObjectFinder<UParticleSystem>(TEXT("ParticleSystem'/Engine/Tutorial/SubEditors/TutorialAssets/TutorialParticleSystem.TutorialParticleSystem'"));
  if (ParticleSystem.Object != nullptr)
  {
    SpawnPoint->SetTemplate(ParticleSystem.Object);
  }
  SpawnPoint->SetRelativeScale3D(FVector(0.5, 0.5, 0.5));
  SpawnCollisionHandlingMethod = ESpawnActorCollisionHandlingMethod::AlwaysSpawn;
}
void ABarracksUnit::BeginPlay()
{
  Super::BeginPlay();
  SpawnPoint->AttachTo(RootComponent);
}

void ABarracksUnit::Tick( float DeltaTime )
{
  Super::Tick( DeltaTime );
  SetActorLocation(GetActorLocation() + FVector(10, 0, 0));
}
void ABarracksUnit::SetupPlayerInputComponent(class UInputComponent* InputComponent)
{
  Super::SetupPlayerInputComponent(InputComponent);
}
```

## 它是如何工作的...

1.  首先，我们创建兵营角色。我们添加一个粒子系统组件来指示新单位将生成的位置，以及一个静态网格用于建筑的可视表示。

1.  在构造函数中，我们初始化组件，然后使用 `FObjectFinder` 设置它们的值。我们还使用 `StaticClass` 函数设置要生成的类，以从类类型中检索 `UClass*` 实例。

1.  在兵营的 `BeginPlay` 函数中，我们创建一个定时器，以固定间隔调用我们的 `SpawnUnit` 函数。我们将定时器句柄存储在类的成员变量中，这样当我们的实例被销毁时，我们可以停止定时器；否则，当定时器再次触发时，我们将遇到对象指针被取消引用的崩溃。

1.  `SpawnUnit` 函数获取了 `SpawnPoint` 对象的世界空间位置，然后请求世界在该位置生成一个我们单位类的实例。

1.  `BarracksUnit` 在其 `Tick()` 函数中有代码，每帧向前移动 10 个单位，以便每个生成的单位都会移动以为下一个单位腾出空间。

1.  `EndPlay` 函数重写调用父类函数的实现，如果父类中有要取消的定时器或要执行的去初始化操作，这一点很重要。然后使用存储在 `BeginPlay` 中的定时器句柄来取消定时器。
