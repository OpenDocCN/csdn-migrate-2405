# 通过使用 Unreal4 构建游戏学习 C++（一）

> 原文：[`annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27`](https://annas-archive.org/md5/1c4190d0f9858df324374dcae7b4dd27)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

因此，您想要使用 Unreal Engine 4（UE4）编写自己的游戏。您有很多理由这样做：UE4 功能强大——UE4 提供了一些最先进、美丽和逼真的光照和物理效果，这些效果是 AAA 工作室使用的类型。

UE4 是设备无关的：为 UE4 编写的代码将在 Windows 台式机、Mac 台式机、所有主要游戏主机（如果您是官方开发人员）、Android 设备和 iOS 设备上运行（在撰写本书时——将来可能支持更多设备！）。因此，您可以使用 UE4 一次编写游戏的主要部分，然后在不经过任何麻烦的情况下部署到 iOS 和 Android 市场。当然，会有一些小问题：iOS 和 Android 应用内购买和通知将需要单独编程，还可能存在其他差异。

# 本书适合对象

本书适合任何想学习游戏编程的人。我们将逐步创建一个简单的游戏，因此您将对整个过程有一个很好的了解。

本书也适合任何想学习 C++，特别是 C++17 的人。我们将介绍 C++的基础知识以及如何在其中编程，并介绍最新 C++版本中的一些新功能。

最后，本书适合任何想学习 UE4 的人。我们将使用它来创建我们的游戏。我们将主要关注 C++方面，但也会涉及一些基本的蓝图开发。

# 本书涵盖内容

第一章，“使用 C++17 入门”，介绍了如何在 Visual Studio Community 2017 或 Xcode 中创建您的第一个 C++项目。我们将创建我们的第一个简单的 C++程序。

第二章，“变量和内存”，涵盖了不同类型的变量，C++中存储数据的基本方法，以及指针、命名空间和控制台应用程序中的基本输入和输出。

第三章，“If、Else 和 Switch”，涵盖了 C++中的基本逻辑语句，允许您根据变量中的值在代码中做出选择。

第四章，“循环”，介绍了如何运行一段代码一定次数，或者直到条件为真。它还涵盖了逻辑运算符，并且我们将看到 UE4 中的第一个代码示例。

第五章，“函数和宏”，介绍了如何设置可以从代码的其他部分调用的代码部分。我们还将介绍如何传递值或获取返回值，并涉及与变量相关的一些更高级的主题。

第六章，“对象、类和继承”，介绍了 C++中的对象，它们是将数据成员和成员函数绑定在一起形成的代码片段，称为类或结构。我们将学习封装以及如何更轻松、更高效地编程对象，使其保持自己的内部状态。

第七章，“动态内存分配”，讨论了动态内存分配以及如何为对象组在内存中创建空间。本章介绍了 C 和 C++风格的数组和向量。在大多数 UE4 代码中，您将使用 UE4 编辑器内置的集合类。

第八章，“角色和棋子”，介绍了如何创建角色并在屏幕上显示它，使用轴绑定控制角色，并创建并显示可以向 HUD 发布消息的 NPC。

第九章，“模板和常用容器”，介绍了如何在 C++中使用模板，并讨论了在 UE4 和 C++标准模板库中可用的基于模板的数据结构。

第十章，库存系统和拾取物品，我们将为玩家编写和设计一个背包来存放物品。当用户按下*I*键时，我们将显示玩家携带的物品。我们将学习如何为玩家设置多个拾取物品。

第十一章，怪物，介绍了如何添加一个景观。玩家将沿着为他们雕刻出的路径行走，然后他们将遇到一支军队。您将学习如何在屏幕上实例化怪物，让它们追逐玩家并攻击他们。

第十二章，使用高级人工智能构建更智能的怪物，介绍了人工智能的基础知识。我们将学习如何使用 NavMesh、行为树和其他人工智能技术，使你的怪物看起来更聪明。

第十三章，魔法书，介绍了如何在游戏中创建防御法术，以及用于可视化显示法术的粒子系统。

第十四章，使用 UMG 和音频改进 UI 反馈，介绍了如何使用新的 UMG UI 系统向用户显示游戏信息。我们将使用 UMG 更新您的库存窗口，使其更简单、更美观，并提供创建自己 UI 的技巧。还介绍了如何添加基本音频以增强游戏体验。

第十五章，虚拟现实及更多，概述了 UE4 在 VR、AR、过程式编程、附加组件和不同平台上的能力。

# 要充分利用本书

在本书中，我们不假设您具有任何编程背景，因此如果您是完全初学者，也没关系！但是最好了解一些关于计算机的知识，以及一些基本的游戏概念。当然，如果您想编写游戏，那么您很可能至少玩过几款游戏！

我们将运行 Unreal Engine 4 和 Visual Studio 2017（或者如果您使用 Mac，则是 Xcode），因此您可能希望确保您的计算机是最新的、性能较强的计算机（如果您想进行 VR，则确保您的计算机已准备好 VR）。

另外，请做好准备！UE4 使用 C++，您可以很快学会基础知识（我们将在这里学到），但要真正掌握这门语言可能需要很长时间。如果您正在寻找一个快速简单的方式来创建游戏，还有其他工具可供选择，但如果您真的想学习能够带来编程游戏职业技能，这是一个很好的起点！

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packt.com/support](http://www.packt.com/support)注册并直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“SUPPORT”选项卡。

1.  单击“Code Downloads & Errata”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压软件解压文件夹：

+   Windows 系统使用 WinRAR/7-Zip

+   Mac 系统使用 Zipeg/iZip/UnRarX

+   Linux 系统使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learning-Cpp-by-Building-Games-with-Unreal-Engine-4-Second-Edition`](https://github.com/PacktPublishing/Learning-Cpp-by-Building-Games-with-Unreal-Engine-4-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781788476249_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781788476249_ColorImages.pdf)。

# 本书使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子："我们看到的第一件事是一个`#include`语句。我们要求 C++复制并粘贴另一个 C++源文件的内容，名为`<iostream>`。"

代码块设置如下：

```cpp
#include <iostream>
using namespace std;  
int main() 
{ 
  cout << "Hello, world" << endl; 
  cout << "I am now a C++ programmer." << endl; 
  return 0;
} 
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```cpp
string name; 
int goldPieces; 
float hp; 
```

**粗体**：表示一个新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中出现。这是一个例子："打开 Epic Games Launcher 应用程序。选择启动 Unreal Engine 4.20.X。"

警告或重要说明看起来像这样。

提示和技巧看起来像这样。

# 第一章：开始使用 C++17

学术界经常在理论上描述编程概念，但喜欢把实现留给别人，最好是来自行业的人。在这本书中，我们将涵盖所有内容：我们将描述 C++概念的理论，并实现我们自己的游戏。如果您是第一次编程，您有很多东西要学习！

我首先建议您做练习。仅仅通过阅读是学不会编程的。您必须在练习中应用理论，才能吸收并将来能够使用它。

我们将从编写非常简单的 C++程序开始。我知道您现在想要开始玩您完成的游戏。但是，您必须从头开始才能达到目标（如果您真的想要，可以跳到第十三章*，* *咒语书*，或打开一些示例来感受我们的方向）。

在本章中，我们将涵盖以下主题：

+   设置一个新项目（在 Visual Studio 或 Xcode 中）

+   您的第一个 C++项目

+   如何处理错误

+   什么是构建和编译？

# 设置我们的项目

我们的第一个 C++程序将在 UE4 之外编写。首先，我将为 Xcode 和 Visual Studio 2017 提供步骤，但在本章之后，我将尝试只讨论 C++代码，而不涉及您是使用 Microsoft Windows 还是 macOS。

# 在 Windows 上使用 Microsoft Visual Studio

在本节中，我们将安装一个允许您编辑 Windows 代码的**集成开发环境**（**IDE**），即微软的 Visual Studio。如果您使用的是 Mac，请跳到下一节。

# 下载和安装 Visual Studio

首先，下载并安装 Microsoft Visual Studio Community 2017。

Visual Studio 的 Community 版本是微软在其网站上提供的免费版本。前往[`www.visualstudio.com/downloads/`](http://www.visualstudio.com/en-us/products/visual-studio-express-vs.aspx)进行下载，然后开始安装过程。

您可以在这里找到完整的安装说明：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio?view=vs-2017`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio?view=vs-2017)。当您到达“工作负载”部分时，您将需要选择“使用 C++进行桌面开发”。

安装了 Visual Studio Community 2017 后，打开它。软件的图标如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/265876f5-f04d-466c-95f3-f8a59af9665b.png)

# 在 Visual Studio 中开始一个新项目

按照以下步骤进行，直到您能够实际输入代码：

1.  从“文件”菜单中，选择“新建 | 项目...”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/669cecd1-75e3-4245-8948-c4b972d1887e.png)

1.  您将会得到以下对话框：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c3b51d0a-eedc-44d2-95c5-322e25267b91.png)

请注意底部有一个带有“解决方案名称”文本的小框。一般来说，Visual Studio 解决方案可能包含许多项目。但是，本书只使用单个项目，但有时您可能会发现将许多项目集成到同一个解决方案中很有用。

1.  现在有五件事情要处理，如下所示：

1.  从左侧面板选择“在线 | 模板 | Visual C++”

1.  从右侧面板选择“控制台应用程序（通用）项目模板”

1.  命名您的应用（我使用了`MyFirstApp`）

1.  选择一个文件夹保存您的代码

1.  点击“确定”按钮

1.  如果您以前从未使用过此模板，它将打开 VSIX 安装程序并显示此对话框：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0b03f1e7-944b-4a00-ba2f-f5116cbb77dc.png)

1.  点击“修改”。它将安装并关闭 Visual Studio。如果您看到此对话框，您可能需要点击“结束任务”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/e023a532-033d-4c40-bd80-49bb437d461c.png)

1.  然后，它将为您安装项目模板。这将需要很长时间，但您只需要做一次。完成后，点击“关闭”并重新启动 Visual Studio。

1.  您需要从文件|新建|项目...重新开始之前的步骤。这次，在已安装的项目下，Visual C++将显示出来：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/54cb942c-bc59-40da-85f6-81f31104ea0a.png)

1.  选择空项目，您可以将名称从 Project1 更改为您想要的任何名称，在我的案例中是 MyFirstApp。

现在，您已经进入了 Visual Studio 2017 环境。这是您将进行所有工作和编码的地方。

然而，我们需要一个文件来写入我们的代码。因此，我们将通过在“解决方案资源管理器”中右键单击项目名称并选择添加|**新项目**来向我们的项目添加一个 C++代码文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/92b4196f-85b6-4a5f-baa0-5786a1603754.png)

按照以下截图所示，添加您的新的 C++（`.cpp`）源代码文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/526bf3b2-f0ca-4ac1-a65f-66e8ab1f2fe3.png)

`Source.cpp`现在已经打开并准备好让您添加代码。跳转到*创建您的第一个 C++程序*部分并开始。

# 在 Mac 上使用 Xcode

在这一部分，我们将讨论如何在 Mac 上安装 Xcode。如果您使用 Windows，请跳转到下一节。

# 下载和安装 Xcode

Xcode 可以在 Apple 应用商店上的所有 Mac 电脑上免费获取。

如果可能的话，您应该获取最新版本。截至目前为止，它是 Xcode 10，但至少需要 macOS Sierra 或（最好是）High Sierra。如果您的 Mac 较旧并且运行较旧的操作系统，您可以免费下载操作系统更新，只要您使用的机器足够新来支持它。

只需在 Apple 应用商店上搜索 Xcode，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/bd16b214-46c1-44d2-9d00-c308094aa746.png)

只需点击获取按钮，等待下载和安装。

# 在 Xcode 中开始一个新项目

1.  安装完 Xcode 后，打开它。然后，要么选择在打开的启动画面上创建一个新的 Xcode 项目，要么从屏幕顶部的系统菜单栏中导航到文件|新建|项目...，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/b711f1db-82e5-4bad-9263-468d15c9d89d.png)

1.  在新项目对话框中，在屏幕顶部的 macOS 下的应用程序部分中，选择命令行工具。然后，点击下一步：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6719fad2-0b15-4df3-9733-92d228725f81.png)

1.  在下一个对话框中，命名您的项目。确保填写所有字段，否则 Xcode 将不允许您继续。确保项目的类型设置为 C++，然后点击下一步按钮，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/96c9388b-1d41-450e-a571-77acbf282617.png)

1.  接下来的弹出窗口将要求您选择一个位置以保存您的项目。在硬盘上选择一个位置并将其保存在那里。Xcode 默认情况下为您创建每个项目的 Git 存储库。您可以取消选中创建 git 存储库，因为我们在本章中不涉及 Git，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/99a90ba0-9ea9-4dd6-a96b-d250c142808d.png)

Git 是一个**版本控制系统**。这基本上意味着 Git 会定期（每次*提交*到存储库时）获取并保留项目中所有代码的快照。其他流行的**源代码控制管理**（**SCM**）工具包括 Mercurial、Perforce 和 Subversion。当多人在同一个项目上合作时，SCM 工具具有自动合并和复制其他人对存储库的更改到您的本地代码库的能力。

好了！您已经准备好了。在 Xcode 的左侧面板中点击`main.cpp`文件。如果文件没有出现，请确保首先选择左侧面板顶部的文件夹图标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/2d168111-aab2-4b3b-a1c9-61328c4b675f.png)

# 创建您的第一个 C++程序

我们现在要编写一些 C++源代码。我们称之为源代码有一个非常重要的原因：它是构建二进制可执行代码的源头。相同的 C++源代码可以在 Mac、Windows 和移动平台等不同平台上构建，并且理论上在每个相应的平台上执行相同操作的可执行代码应该是一样的。

在不太久远的过去，在引入 C 和 C++之前，程序员为他们单独针对的每台特定机器编写代码。他们用一种称为汇编语言的语言编写代码。但现在，有了 C 和 C++，程序员只需编写一次代码，就可以通过使用不同的编译器构建相同的源代码，将其部署到许多不同的机器上。

实际上，Visual Studio 的 C++版本和 Xcode 的 C++版本之间存在一些差异，但这些差异主要出现在处理高级 C++概念（如模板）时。在处理多个平台时，UE4 非常有帮助。

Epic Games 付出了大量的工作，以使相同的代码在 Windows 和 Mac 上以及许多其他平台（如移动平台和游戏机）上运行。

现实世界的提示

使代码在所有机器上以相同的方式运行非常重要，特别是对于联网游戏或允许诸如可共享的重放之类的游戏。这可以通过标准来实现。例如，IEEE 浮点标准用于在所有 C++编译器上实现十进制数学。这意味着诸如 200 * 3.14159 之类的计算结果应该在所有机器上相同。没有标准，不同的编译器可能（例如）以不同的方式四舍五入数字，而在有许多计算且代码需要精确时，这可能会导致不可接受的差异。

在 Microsoft Visual Studio 或 Xcode 中编写以下代码：

```cpp
#include <iostream>
using namespace std;  
int main() 
{ 
  cout << "Hello, world" << endl; 
  cout << "I am now a C++ programmer." << endl; 
  return 0;
} 
```

为了解释发生了什么，这里是相同的代码，但添加了注释（在`//`之后的任何内容都将被编译器忽略，但可以帮助解释发生了什么）。

```cpp
#include <iostream>  // Import the input-output library 
using namespace std; // allows us to write cout 
                     // instead of std::cout 
int main() 
{ 
  cout << "Hello, world" << endl; 
  cout << "I am now a C++ programmer." << endl; 
  return 0;      // "return" to the operating sys 
} 
```

按*Ctrl* + *F5*（或使用 Debug | Start Without Debugging 菜单）在 Visual Studio 中运行上述代码，或按*Command* + *R*（Product | Run）在 Xcode 中运行。在 Visual Studio 中第一次按*Ctrl* + *F5*时，您会看到此对话框：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/fa80783c-d71f-4fb8-8804-cf43911cff55.png)

如果您不想每次运行程序时都看到这个对话框，请选择是并且不再显示此对话框。

以下是在 Windows 上应该看到的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0c3809e7-173f-4e56-b212-7e3688928c01.png)

这是在 Mac 上的情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/1442d579-e93d-420a-80a0-be030bfef8ad.png)

如果您在 Windows 上，您可能会注意到当您运行它时窗口会自动关闭，因此您无法看到结果。有各种方法可以解决这个问题，包括更改设置以暂停并让您按键继续。您可以在这里获取更多信息：[`stackoverflow.com/questions/454681/how-to-keep-the-console-window-open-in-visual-c/1152873#1152873`](https://stackoverflow.com/questions/454681/how-to-keep-the-console-window-open-in-visual-c/1152873#1152873)

您可能首先想到的是“哎呀！一大堆胡言乱语！”

实际上，您很少看到井号（#）符号的使用（除非您使用 Twitter）和花括号对`{``}`在正常的英文文本中。但是，在 C++代码中，这些奇怪的符号随处可见。您只需习惯它们。

因此，让我们解释一下这个程序，从第一行开始。

这是程序的第一行：

```cpp
#include <iostream>  // Import the input-output library 
```

这行有两个重要的要点需要注意：

1.  我们看到的第一件事是一个`#include`语句。我们要求 C++将另一个 C++源文件的内容，称为`<iostream>`，直接复制粘贴到我们的代码文件中。`<iostream>`是一个标准的 C++库，处理所有让我们将文本打印到屏幕上的代码。

1.  我们注意到的第二件事是一个`//`注释。如前所述，C++会忽略双斜杠（`//`）之后的任何文本，直到该行结束。注释非常有用，可以添加纯文本解释一些代码的功能。你可能还会在源代码中看到`/* */`多行 C 风格的注释。用斜杠星`/*`和星斜杠`*/`将任何文本（甚至跨多行）包围在 C 或 C++中，指示编译器删除该代码。

这是下一行代码：

```cpp
using namespace std; // allows us to write cout 
                     // instead of std::cout 
```

这一行旁边的注释解释了`using`语句的作用：它只是让你使用一个简写（例如，`cout`）而不是完全限定的名称（在这种情况下将是`std::cout`）来执行我们的许多 C++代码命令。有些人不喜欢`using namespace std;`语句；他们更喜欢每次使用`cout`时写`std::cout`的长格式。你可以就这样的事情进行长时间的争论。在本节文本中，我们更喜欢`using namespace std;`语句带来的简洁性。

另外，请注意本节第二行的注释与上一行的注释对齐。这是很好的编程实践，因为它在视觉上显示它是上一个注释的延续。

这是下一行：

```cpp
int main() 
```

这是应用程序的起点。你可以把`main`想象成比赛的起跑线。`int main()`语句是你的 C++程序知道从哪里开始的方式。

如果你没有一个`int main()`程序标记，或者`main`拼写错误，那么你的程序就不会工作，因为程序不知道从哪里开始。

下一行是一个你不经常看到的字符：

```cpp
{ 
```

这个`{`字符不是一个侧面的胡须。它被称为花括号，表示程序的起点。

接下来的两行将文本打印到屏幕上：

```cpp
cout << "Hello, world" << endl; 
cout << "I am now a C++ programmer." << endl; 
```

`cout`语句代表控制台输出。双引号之间的文本将以与引号之间的内容完全相同的方式输出到控制台。你可以在双引号之间写任何你想写的东西，除了双引号，它仍然是有效的代码。另外，请注意`endl`告诉`cout`添加一个换行（回车）字符，这对于格式化非常有用。

要在双引号之间输入双引号，你需要在你想要放在字符串中的双引号字符前面加上一个反斜杠（\），如下所示：

```cpp
cout << "John shouted into the cave \"Hello!\" The cave echoed."  
```

`\"`符号是转义序列的一个例子。还有其他转义序列可以使用；你会发现最常见的转义序列是`\n`，它用于将文本输出跳转到下一行。

程序的最后一行是`return`语句：

```cpp
return 0; 
```

这行代码表示 C++程序正在退出。你可以把`return`语句看作是返回到操作系统。

最后，你的程序的结束由闭合的花括号表示，这是一个相反的侧面胡须：

```cpp
} 
```

# 分号

分号（;）在 C++编程中很重要。请注意在前面的代码示例中，大多数代码行都以分号结束。如果你不在每行末尾加上分号，你的代码将无法编译，如果发生这种情况，你的雇主将不会很高兴（当然，一旦你做了一段时间，你会在他们发现之前找到并修复这些问题）。

# 处理错误

如果你在输入代码时犯了一个错误，那么你将会有一个语法错误。面对语法错误，C++会大声尖叫，你的程序甚至不会编译；而且，它也不会运行。

让我们试着在之前的 C++代码中插入一些错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3fca0dff-5690-4455-8896-87da9e078a6e.png)

警告！这段代码清单包含错误。找到并修复所有错误是一个很好的练习！

作为练习，试着找到并修复这个程序中的所有错误。

请注意，如果你对 C++非常陌生，这可能是一个很难的练习。然而，这将向你展示在编写 C++代码时需要多么小心。

修复编译错误可能是一件麻烦的事情。然而，如果你将这个程序的文本输入到你的代码编辑器中并尝试编译它，它将导致编译器向你报告所有的错误。逐个修复错误，然后尝试重新编译（从列表中的第一个开始，因为它可能导致后面的一些错误）。一个新的错误将弹出，或者程序将正常工作，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/5e745745-442b-422b-8382-56d4f5f364e3.png)

当你尝试编译代码时，你的编译器会显示代码中的错误（尽管如果你使用 Visual Studio，它会询问你是否要先运行之前成功的构建）。

我展示这个示例程序的原因是鼓励以下工作流程，只要你是 C++的新手：

1.  始终从一个可工作的 C++代码示例开始。你可以从*创建* *你的第一个 C++程序*部分分叉出一堆新的 C++程序。

1.  在小步骤中进行代码修改。当你是新手时，每写一行新代码后进行编译。不要一两个小时编码，然后一次性编译所有新代码。

1.  你可能需要几个月的时间才能写出第一次就能正常运行的代码。不要灰心。学习编码是有趣的。

# C++中的警告

编译器会标记它认为可能是错误的东西。这些是另一类编译器通知，称为警告。警告是你代码中的问题，你不必修复它们才能运行你的代码，但编译器建议修复。警告通常是代码不够完美的指示，修复代码中的警告通常被认为是良好的做法。

然而，并非所有的警告都会在你的代码中引起问题。一些程序员喜欢禁用他们认为不是问题的警告（例如，警告 4018 警告有符号/无符号不匹配，你很可能以后会看到）。

# 什么是构建和编译？

你可能听说过一个计算机进程术语叫做编译。编译是将你的 C++程序转换为可以在 CPU 上运行的代码的过程。构建你的源代码意味着与编译相同的事情。

看，你的源代码`code.cpp`文件实际上不会在计算机上运行。它必须首先进行编译才能运行。

这就是使用 Microsoft Visual Studio Community 或 Xcode 的全部意义。Visual Studio 和 Xcode 都是编译器。你可以在任何文本编辑程序中编写 C++源代码，甚至在记事本中。但是你需要一个编译器在你的机器上运行它。

每个操作系统通常都有一个或多个可以在该平台上运行的 C++编译器。在 Windows 上，你有 Visual Studio 和 Intel C++ Studio 编译器。在 Mac 上，有 Xcode，在 Windows、Mac 和 Linux 上都有**GNU 编译器集合**（**GCC**）。

我们编写的相同的 C++代码（源代码）可以使用不同的编译器在不同的操作系统上编译，并且理论上它们应该产生相同的结果。在不同平台上编译相同的代码的能力称为可移植性。一般来说，可移植性是一件好事。

# 示例输出

这是你的第一个 C++程序的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/65ae7f80-3457-4436-acbc-94b35c03c77f.png)

以下屏幕截图是它的输出，你的第一个胜利：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/921550c8-8ed5-4817-a15b-fbe91ac1bd6e.png)

还有一类编程语言叫做脚本语言。这些包括诸如 PHP、Python 和`ActionScript`的语言。脚本语言不需要编译；对于 JavaScript、PHP 和 ActionScript，没有编译步骤。相反，它们在程序运行时从源代码中进行解释。脚本语言的好处是它们通常是平台无关的，因为解释器被设计得非常仔细以实现平台无关性。

# 练习 - ASCII 艺术

游戏程序员喜欢 ASCII 艺术。你可以只用字符绘制一幅图片。这里有一个 ASCII 艺术迷宫的例子：

```cpp
cout << "****************" << endl; 
cout << "*............*.*" << endl; 
cout << "*.*.*******..*.*" << endl; 
cout << "*.*.*..........*" << endl; 
cout << "*.*.*.**********" << endl; 
cout << "***.***........*" << endl; 
```

用 C++代码构建自己的迷宫，或者用字符绘制一幅图片。

# 总结

总之，我们学会了如何在集成开发环境（IDE，Visual Studio 或 Xcode）中用 C++编程语言编写我们的第一个程序。这是一个简单的程序，但是你应该把编译和运行你的第一个程序视为你的第一次胜利。在接下来的章节中，我们将组合更复杂的程序，并开始在我们的游戏中使用虚幻引擎。


# 第二章：变量和内存

为了编写你的 C++游戏程序，你需要让你的计算机记住很多东西，比如玩家在世界的位置，他们有多少生命值，还剩下多少弹药，世界中物品的位置，它们提供的增益效果，以及组成玩家屏幕名字的字母。

你的计算机实际上有一种叫做**内存**或 RAM 的电子素描板。从物理上讲，计算机内存是由硅制成的，看起来与下面的照片相似：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/50811780-25ce-481b-a8d4-3f90d20df7fc.png)

这块 RAM 看起来像停车场吗？因为这就是我们要使用的隐喻。

RAM 是随机存取存储器的缩写。它被称为随机存取，因为你可以随时访问它的任何部分。如果你还有一些 CD 在身边，它们就是非随机存取的例子。CD 是按顺序读取和播放的。我还记得很久以前在 CD 上切换曲目需要很长时间！然而，跳跃和访问 RAM 的不同单元并不需要太多时间。RAM 是一种快速存储器访问的类型，称为闪存存储器。

RAM 被称为易失性闪存存储器，因为当计算机关闭时，RAM 的内容被清除，除非它们首先保存到硬盘上，否则 RAM 的旧内容将丢失。

对于永久存储，你必须把你的数据保存到硬盘上。有两种主要类型的硬盘：

+   基于盘片的**硬盘驱动器**（**HDDs**）

+   **固态硬盘**（**SSD**）

SSD 比基于盘片的 HDD 更现代，因为它们使用 RAM 的快速访问（闪存）存储原理。然而，与 RAM 不同，SSD 上的数据在计算机关闭后仍然存在。如果你能得到一个 SSD，我强烈建议你使用它！基于盘片的驱动器已经过时了。

当程序运行时，访问存储在 RAM 中的数据比从 HDD 或 SSD 中访问要快得多，所以我们需要一种方法来在 RAM 上保留空间并从中读取和写入。幸运的是，C++使这变得容易。

# 变量

在计算机内存中保存的位置，我们可以读取或写入，称为**变量**。

变量是一个值可以变化的组件。在计算机程序中，你可以把变量看作是一个容器，可以在其中存储一些数据。在 C++中，这些数据容器（变量）有类型和名称，你可以用来引用它们。你必须使用正确类型的数据容器来保存你的程序中的数据。

如果你想保存一个整数，比如 1、0 或 20，你将使用`int`类型的容器。你可以使用 float 类型的容器来携带浮点（小数）值，比如 38.87，你可以使用字符串变量来携带字母字符串（把它想象成一串珍珠，其中每个字母都是一颗珍珠）。

你可以把你在 RAM 中保留的位置看作是在停车场预留一个停车位：一旦我们声明了我们的变量并为它获得了一个位置，操作系统就不会把那块 RAM 的其他部分分配给其他程序（甚至是在同一台机器上运行的其他程序）。你的变量旁边的 RAM 可能未被使用，也可能被其他程序使用。

操作系统的存在是为了防止程序相互干扰，同时访问计算机硬件的相同位。一般来说，文明的计算机程序不应该读取或写入其他程序的内存。然而，一些类型的作弊程序（例如，地图黑客）会秘密访问你程序的内存。像 PunkBuster 这样的程序被引入来防止在线游戏中的作弊。

# 声明变量——触摸硅

使用 C++在计算机内存中保留一个位置很容易。我们想要用一个好的、描述性的名字来命名我们将在其中存储数据的内存块。

例如，假设我们知道玩家的**生命值**（**hp**）将是一个整数（整数）数字，例如 1、2、3 或 100。为了让硅片在内存中存储玩家的`hp`，我们将声明以下代码行：

```cpp
int hp;     // declare variable to store the player's hp 
```

这行代码保留了一小块 RAM 来存储称为`hp`的整数（`int`是整数的缩写）。以下是我们用来存储玩家`hp`的 RAM 块的示例。这在内存中为我们保留了一个停车位（在所有其他停车位中），我们可以通过其标签（`hp`）引用内存中的这个空间：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/43575241-0eb0-41bd-b8e3-0e5d9ce0182b.png)

在内存中的所有其他空间中，我们有一个地方来存储我们的 hp 数据。

当您命名变量时，有一些规则。变量名称不能以数字开头，编译器不允许使用某些“保留字”（通常是因为它们被 C++本身使用）。随着您学习更多的 C++，您将学到这些，或者您可以在网上寻找保留字列表。

请注意，变量空间在此图中标记为`int`，如果它是双精度或其他类型的变量空间。C++不仅通过名称记住您在内存中为程序保留的空间，还通过变量的类型记住它。

请注意，我们还没有把任何东西放在 hp 的盒子里！我们稍后会这样做——现在，`hp`变量的值尚未设置，因此它将具有上一个占用者（也许是另一个程序留下的值）留在那个停车位上的值。告诉 C++变量的类型很重要！稍后，我们将声明一个变量来存储十进制值，例如 3.75。

# 读取和写入内存中保留的位置

将值写入内存很容易！一旦有了`hp`变量，您只需使用`=`符号写入它：

```cpp
hp = 500; 
```

哇！玩家有 500 hp。

读取变量同样简单。要打印变量的值，只需输入以下内容：

```cpp
cout << hp << endl; 
```

这将打印存储在`hp`变量中的值。`cout`对象足够聪明，可以弄清楚它是什么类型的变量，并打印内容。如果您更改`hp`的值，然后再次使用`cout`，将打印最新的值，如下所示：

```cpp
hp = 1200; 
cout << hp << endl; // now shows 1200 
```

# 数字和数学

标题说明了一切；在本节中，我们将深入探讨 C++中数字和数学的重要性。

# 数字就是一切

开始计算机编程时，你需要习惯的一件事是，令人惊讶的是，许多东西可以仅以数字形式存储在计算机内存中。玩家的生命值？正如我们在前一节中所看到的，生命值可以只是一个整数。如果玩家受伤，我们减少这个数字。如果玩家获得健康，我们增加这个数字。

颜色也可以存储为数字！如果您使用标准的图像编辑程序，可能会有滑块指示颜色使用了多少红色、绿色和蓝色，例如 Pixelmator 的颜色滑块，如果您使用过的话。Photoshop 没有滑块，但会显示数字，并允许您直接编辑以更改颜色。然后，颜色由三个数字表示。以下截图中显示的紫色是（R:`127`，G:`34`，B:`203`）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/31daffe0-b152-444a-a39a-c7b14167ab65.png)

正如您所看到的，Photoshop 允许您使用其他数字来表示颜色，例如 HSB（色调、饱和度、亮度），这是表示颜色的另一种方式，或者 CMYK（青色、品红色、黄色、黑色），用于印刷，因为专业印刷机使用这些颜色油墨进行印刷。对于在计算机显示器上查看，您通常会坚持使用 RGB 颜色表示，因为这是显示器使用的颜色。

世界几何呢？这些也只是数字；我们所要做的就是存储一组 3D 空间点（*x*、*y*和*z*坐标），然后存储另一组解释这些点如何连接以形成三角形的点。在下面的屏幕截图中，我们可以看到 3D 空间点是如何用来表示世界几何的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ed292664-eb2e-4e40-94eb-3b3187163583.png)

颜色和 3D 空间点的数字组合将让您在游戏世界中绘制大型且彩色的景观。

前面示例的技巧在于我们如何解释存储的数字，以便使它们意味着我们想要的意思。

# 有关变量的更多信息

您可以将变量看作宠物携带者。猫笼可以用来携带猫，但不能携带狗。同样，您应该使用浮点类型的变量来携带小数值。如果您将小数值存储在`int`变量中，它将不适合：

```cpp
int x = 38.87f; 
cout << x << endl; // prints 38, not 38.87 
```

这里真正发生的是 C++对`38.87`进行了自动类型转换，将其转换为整数以适应`int`的容器。它舍弃了小数部分，将`38.87`转换为整数值`38`。

因此，例如，我们可以修改代码以包括使用三种类型的变量，如下面的代码所示：

```cpp
#include <iostream> 
#include <string>  // need this to use string variables! 
using namespace std; 
int main() 
{ 
  string name; 
  int goldPieces; 
  float hp; 
  name = "William"; // That's my name 
  goldPieces = 322; // start with this much gold  
  hp = 75.5f;       // hit points are decimal valued 
  cout << "Character " << name << " has "  
           << hp << " hp and "  
           << goldPieces << " gold."; 
} 
```

在前三行中，我们声明了三个盒子来存储我们的数据部分，如下所示：

```cpp
string name; int goldPieces; float hp; 
```

这三行在内存中保留了三个位置（就像停车位）。接下来的三行将变量填充为我们想要的值，如下所示：

```cpp
name = "William"; 
goldPieces = 322; 
hp = 75.5f; 
```

在计算机内存中，这将看起来像以下图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/91199601-5d19-43f5-98e6-a7dea05d3d5d.png)

您可以随时更改变量的内容。您可以使用`=`赋值运算符来写入变量，如下所示：

```cpp
goldPieces = 522;// = is called the "assignment operator" 
```

您还可以随时读取变量的内容。代码的下三行就是这样做的，如下所示：

```cpp
cout << "Character " << name << " has "  
     << hp << " hp and "  
     << goldPieces << " gold."; 
```

看一下以下行：

```cpp
cout << "I have " << hp << " hp." << endl; 
```

在这一行中，单词`hp`有两种用法。一种是在双引号之间，而另一种则不是。双引号之间的单词总是精确输出为您键入的样子。当不使用双引号（例如`<< hp <<`）时，将执行变量查找。如果变量不存在，那么您将收到编译器错误（未声明的标识符）。

内存中有一个为名称分配的空间，一个为玩家拥有的`goldPieces`分配的空间，以及一个为玩家的 hp 分配的空间。

当您运行程序时，您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/aa24ff21-3d49-4d67-9c0c-ddd78d56a222.png)

一般来说，您应该始终尝试将正确类型的数据存储在正确类型的变量中。如果您存储了错误类型的数据，您的代码可能会表现异常。例如，意外地将浮点数存储到`int`变量中将使您丢失小数点，并且将字符的值存储在`int`中将给出 ASCII 值，但不再将其视为字母。有时，甚至没有任何类型的自动类型转换，因此它将不知道如何处理该值。

# C++中的数学运算

C++中的数学运算很容易；`+`（加）、`-`（减）、`*`（乘）、`/`（除）都是常见的 C++操作，将遵循正确的**括号**、**指数**、**除法**、**乘法**、**加法**和**减法**（**BEDMAS**）顺序。例如，我们可以按照以下代码中所示的方式进行：

```cpp
int answer = 277 + 5 * 4 / 2 + 20; 
```

当然，如果你想要绝对确定顺序，使用括号总是一个好主意。你可能还不熟悉的另一个运算符是%（取模）。取模（例如，10 % 3）找到`x`（10）除以`y`（3）时的余数。请参考以下表格中的示例：

| 运算符（名称） | 示例 | 答案 |
| --- | --- | --- |
| + (plus) | 7 + 3 | 10 |
| - (minus) | 8 - 5 | 3 |
| * (times) | 5*6 | 30 |
| / (division) | 12/6 | 2 |
| % (modulus) | 10 % 3 | 1（因为 10/3 是 3，余数=1）。 |

然而，我们通常不希望以这种方式进行数学运算。相反，我们通常希望按一定计算的数量更改变量的值。这是一个更难理解的概念。假设玩家遇到一个小恶魔并受到 15 点伤害。

以下代码将用于减少玩家的`hp` `15`（信不信由你）：

```cpp
hp = hp - 15;                  // probably confusing :) 
```

你可能会问为什么。因为在右侧，我们正在计算 hp 的新值（`hp-15`）。找到 hp 的新值（比以前少 15），然后将新值写入`hp`变量。

将`hp`视为墙上特定位置的绘画。`-15`告诉您在绘画上画上胡须，但保持在原地。新的、留着胡须的绘画现在是`hp`。

陷阱

未初始化的变量具有在内存中保存的位模式。声明变量不会清除内存。

因此，假设我们使用以下行代码：

```cpp
int hp;   
hp = hp - 15;   
```

第二行代码将 hp 从其先前的值减少 15。如果我们从未设置`hp = 100`或其他值，那么它的先前值是多少？它可能是 0，但并非总是如此。

最常见的错误之一是在未初始化变量的情况下继续使用变量。

以下是进行此操作的简写语法：

```cpp
hp -= 15; 
```

除了`-=`，您还可以使用`+=`将一定数量添加到变量，`*=`将变量乘以一定数量，`/=`将变量除以一定数量。

如果您使用`int`并希望将其增加（或减少）1，可以缩短语法。您不需要编写以下内容：

```cpp
hp = hp + 1;
hp = hp - 1;
```

您也可以执行以下任何操作：

```cpp
hp++;
++hp;
hp--;
--hp;
```

将其放在变量之前会在使用变量之前递增或递减变量（如果您在较大的语句中使用它）。将其放在后面会在使用变量后更新变量。

# 练习

执行以下操作后写下`x`的值，然后与您的编译器进行检查：

| 练习 | 解决方案 |
| --- | --- |
| `int x = 4; x += 4;` | `8` |
| `int x = 9; x-=2;` | `7` |
| `int x = 900; x/=2;` | `450` |
| `int x = 50; x*=2;` | `100` |
| `int x = 1; x += 1;` | `2` |
| `int x = 2; x -= 200;` | `-198` |
| `int x = 5; x*=5;` | `25` |

# 广义变量语法

在前一节中，您了解到您在 C++中保存的每个数据都有一个类型。所有变量都是以相同的方式创建的；在 C++中，变量声明的形式如下：

```cpp
variableType variableName; 
```

`variableType`对象告诉您我们将在变量中存储什么类型的数据。`variableName`对象是我们将用来读取或写入该内存块的符号。

# 基本类型

我们之前谈到计算机内部的所有数据最终都将是一个数字。您的计算机代码负责正确解释该数字。

据说 C++只定义了一些基本数据类型，如下表所示：

| `Char` | 单个字母，例如*a*，*b*或*+*。它以 ASCII 存储为-127 到 127 的数字值，ASCII 是一种为每个字符分配特定数字值的标准。 |
| --- | --- |
| `Short` | 从`-32,767`到`+32,768`的整数。 |
| `Int` | 从`-2,147,483,647`到`+2,147,483,648`的整数。 |
| `Long` | 从`-2,147,483,647`到`+2,147,483,648`的整数。 |
| `Float` | 从约`-1x10³⁸`到`1x10³⁸`的任何小数值。 |
| `Double` | 从约`-1x10³⁰⁸`到`1x10³⁰⁸`的任何小数值。 |
| `Bool` | 真或假。 |

在前面的表中提到的每种变量类型都有无符号版本（当然，Bool 除外，这实际上没有什么意义）。无符号变量可以包含自然数，包括 0（x >= 0）。例如，无符号`short`的值可能在`0`和`65535`之间。如果需要，您还可以使用`long long`或`long long int`获得更大的整数。

变量的大小有时在不同的编译器中可能会有所不同，或者取决于您是为 32 位还是 64 位操作系统进行编译。如果您将来发现自己在处理不同的东西，请记住这一点。

在这种情况下，我们关注的是 Visual Studio 或 Xcode 和（很可能）64 位。

如果你对浮点数和双精度之间的区别感兴趣，请随时在互联网上查找。我只会解释用于游戏的最重要的 C++概念。如果你对这个文本未涵盖的内容感到好奇，请随时查找。

# 高级变量主题

C++的更新版本添加了一些与变量相关的新功能，还有一些尚未提及的功能。以下是一些你应该记住的事情。

# 自动检测类型

从 C++ 11 开始，有一种新的变量*类型*，可以用于你可能不确定期望得到的类型的情况。这种新类型叫做`auto`。它的意思是它将检测你首先分配给它的任何值的类型，然后使用它。比如你输入以下内容：

```cpp
auto x = 1.5;
auto y = true;
```

如果你这样做，`x`将自动成为一个浮点数，`y`将成为一个布尔值。一般来说，如果你知道变量的实际类型（大多数情况下你会知道），最好避免使用它。然而，你应该能够在看到它时识别它，并且在最终需要它的情况下了解它。

# 枚举

枚举类型已经存在很长时间了，但是从 C++ 11 开始，你可以更好地控制它们。枚举的想法有时是你想要在游戏中跟踪不同类型的东西，你只是想要一种简单的方法来给每个值，告诉你它是什么，以及你以后可以检查它。枚举看起来像下面这样：

```cpp
enum weapon {
    sword = 0;
    knife,
    axe,
    mace,
    numberOfWeaponTypes,
    defaultWeapon = mace
}; // Note the semicolon at the end
```

这将创建每种武器类型，并通过为每种武器类型加 1 来分配每种武器类型一个唯一的值，因此刀将等于 1，斧头将等于 2，依此类推。请注意，你不需要将第一个设置为 0（它会自动设置），但如果你想从不同的数字开始，你可以这样做（不仅仅是第一个可以设置为特定的值）。你还可以将任何`enum`成员分配给另一个不同的成员，它将具有相同的值（在这个例子中，`defaultWeapon`具有与`mace`相同的值：3）。在枚举列表中的任何地方分配特定值时，列表中之后添加的任何类型将从该值开始递增 1。

枚举类型一直包含一个 int 值，但是从 C++ 11 开始，你可以指定一个变量类型。例如，你可能想做类似以下的事情：

```cpp
enum isAlive : bool {
    alive = true,
    dead = false
}
```

虽然你可以用 0 和 1 来做到这一点，但在某些情况下，你可能会发现这更方便。

# 常量变量

有时你会有一个值，你不希望在游戏过程中改变。你不希望像生命值、最大生命值、达到特定级别所需的经验值或移动速度这样的东西改变（除非你的角色确实达到了那个级别，在这种情况下，你可能会切换到另一个常量值）。

在某些情况下，`enum`可以解决这个问题，但对于单个值，更容易创建一个新变量并声明它为`const`。这里有一个例子：

```cpp
const int kNumLives = 5;
```

在变量类型前面放置`const`告诉程序永远不要允许该值被更改，如果你尝试，它会给你一个错误。在变量名前面放置`k`是`const`变量的常见命名约定。许多公司会坚持要求你遵循这个标准。

# 构建更复杂的类型

事实证明，这些简单的数据类型本身可以用来构建任意复杂的程序。*怎么做？* 你会问。仅仅使用浮点数和整数来构建 3D 游戏难吗？

从`float`和`int`构建游戏并不是真的很困难，但更复杂的数据类型会有所帮助。如果我们使用松散的浮点数来表示玩家的位置，编程将会很乏味和混乱。

# 对象类型 - 结构

C++为你提供了将变量组合在一起的结构，这将使你的生活变得更加轻松。以以下代码块为例：

```cpp
#include <iostream> 
using namespace std; 
struct Vector        // BEGIN Vector OBJECT DEFINITION 
{ 
  float x, y, z;     // x, y and z positions all floats 
};                   // END Vector OBJECT DEFINITION. 
// The computer now knows what a Vector is 
// So we can create one. 
int main() 
{ 
  Vector v; // Create a Vector instance called v 
  v.x=20, v.y=30, v.z=40; // assign some values 
  cout << "A 3-space vector at " << v.x << ", " << v.y << ", " <<  
   v.z << endl; 
} 
```

在内存中的显示方式非常直观；**Vector**只是一个具有三个浮点数的内存块，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f0a7f2fa-edae-43ba-8254-665d7b7eec5a.png)

不要将前面的屏幕截图中的`struct Vector`与**标准模板库**（**STL**）的`std::vector`混淆-我们稍后会介绍这一点。前面的`Vector`对象用于表示三维向量，而 STL 的`std::vector`类型表示一组值。

关于前面的代码清单，这里有一些复习注意事项。

首先，甚至在我们使用`Vector`对象类型之前，我们必须定义它。C++没有内置的数学向量类型（它只支持标量数字，他们认为这已经足够了！）。因此，C++允许您构建自己的对象构造以使您的生活更轻松。我们首先有以下定义：

```cpp
struct Vector        // BEGIN Vector STRUCT DEFINITION 
{ 
  float x, y, z;     // x, y, and z positions all floats 
};                   // END Vector STRUCT DEFINITION. 
```

这告诉计算机`Vector`是什么（它是三个浮点数，所有这些都被声明为坐在内存中的相邻位置）。在前面的图中显示了`Vector`在内存中的样子。

接下来，我们使用我们的`Vector`对象定义来创建一个名为`v`的 Vector 实例：

```cpp
Vector v; // Create a Vector instance called v 
```

一旦您有了`Vector`的实例，您就可以使用我们称之为**点语法**来访问其中的变量。您可以使用`v.x`在 Vector `v`上访问变量`x`。`struct` Vector 定义实际上并不创建 Vector 对象，它只是定义了对象类型。您不能做`Vector.x = 1`。您在谈论哪个对象实例？C++编译器会问。您需要首先创建一个 Vector 实例，例如 Vector `v`。这将创建一个 Vector 的实例并将其命名为`v`。然后，您可以对`v`实例进行赋值，例如`v.x = 0`。

然后，我们使用这个实例来写入`v`中的值：

```cpp
v.x=20, v.y=30, v.z=40; // assign some values 
```

我们在前面的代码中使用逗号来初始化同一行上的一堆变量。这在 C++中是可以的。虽然您可以将每个变量放在自己的一行上，但在这里显示的方法也是可以的。

这使得`v`看起来像前面的图像。然后，我们将它们打印出来：

```cpp
cout << "A 3-space vector at " << v.x << ", " << v.y << ", " <<  
   v.z << endl;
```

在这里的两行代码中，我们通过简单地使用点（`.`）访问对象内的各个数据成员；`v.x`指的是对象`v`内的`x`成员。每个 Vector 对象内部将恰好有三个浮点数：一个称为`x`，一个称为`y`，一个称为`z`。

# 练习-玩家

为`Player`对象定义一个 C++数据结构。然后，创建您的`Player`结构的一个实例，并为每个数据成员填充值。

# 解决方案

让我们声明我们的`Player`对象。我们希望将与玩家有关的所有内容都放入`Player`对象中。我们这样做是为了使代码整洁。您在 Unreal Engine 中阅读的代码将在各个地方使用这样的对象，因此请注意：

```cpp
struct Player 
{ 
  string name; 
  int hp; 
  Vector position; 
}; // Don't forget this semicolon at the end! 
int main() 
{ 
  // create an object of type Player, 
  Player me; // instance named 'me' 
  me.name = "William"; 
  me.hp = 100; 
  me.position.x = me.position.y = me.position.z=0; 
} 
```

行`me.position.x = me.position.y = me.position.z=0;`意味着`me.position.z`设置为`0`，然后将该值传递给`me.position.y`设置为 0，然后传递并设置`me.position.x`为`0`。

`struct Player`定义告诉计算机如何在内存中布置`Player`对象。

我希望您注意到了结构声明末尾的必需分号。结构对象声明需要在末尾加上分号，但函数不需要（我们稍后会讨论函数）。这只是一个必须记住的 C++规则。

在`Player`对象内部，我们声明了一个字符串用于玩家的名称，一个浮点数用于他们的 hp，以及一个`Vector`对象用于他们完整的`x`，`y`和`z`位置。

当我说对象时，我的意思是 C++结构（稍后我们将介绍术语*类*）。

等等！我们把一个 Vector 对象放在一个 Player 对象里！是的，你可以这样做。只要确保 Vector 在同一个文件中定义。

在定义了`Player`对象内部的内容之后，我们实际上创建了一个名为`me`的`Player`对象实例，并为其分配了一些值。

# 指针

一个特别棘手的概念是指针的概念。指针并不难理解，但可能需要一段时间才能牢固掌握。指针基本上包含一个对象存储的内存地址，因此它们在内存中“指向”对象。

假设我们在内存中声明了一个`Player`类型的变量：

```cpp
Player me; 
me.name = "William"; 
me.hp = 100; 
```

我们现在声明一个指向`Player`的指针：

```cpp
Player* ptrMe;               // Declaring a pointer to 
                             // a Player object
```

`*`改变了变量类型的含义。`*`是使`ptrMe`成为`Player`对象的指针而不是常规`Player`对象的原因。

我们现在想要将`ptrMe`链接到`me`：

```cpp
ptrMe = &me;                  // LINKAGE 
```

这种链接步骤非常重要。如果在使用指针之前不将指针链接到对象，将会出现内存访问违规错误——尝试访问未设置的内存，因此可能包含随机数据甚至其他程序的一部分！

`ptrMe`指针现在指向与`me`相同的对象。更改`ptrMe`指向的对象中的变量的值将在`me`中更改，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/39c61393-1da4-452f-a007-f0252648101b.png)

# 指针能做什么？

当我们建立指针变量和它所指向的东西之间的链接时，我们可以通过指针操纵它所指向的变量。

指针的一个用途是在代码中的多个不同位置引用同一个对象。如果您经常尝试访问它，您可能希望在本地存储一个指向它的指针，以便更容易访问。`Player`对象是一个很好的指向候选对象，因为您的代码中的许多地方可能会不断地访问它。

您可以创建任意数量的指针指向同一个对象，但您需要跟踪它们所有（除非您使用智能指针，我们稍后会介绍）。被指向的对象不一定知道自己被指向，但可以通过指针对对象进行更改。

例如，假设玩家受到了攻击。他们的 hp 减少将是结果，并且这种减少将使用指针来完成，如下面的代码所示：

```cpp
ptrMe->hp -= 33;      // reduced the player's hp by 33 
ptrMe->name = "John";// changed his name to John 
```

使用指针时，您需要使用`->`而不是`.`来访问指向的对象中的变量。

现在`Player`对象的外观如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/aa4316de-1a4a-43bc-a029-729cf5c3125e.png)

因此，我们通过改变`ptrMe->name`来改变`me.name`。因为`ptrMe`指向`me`，所以通过`ptrMe`的更改会直接影响`me`。

# 地址运算符（&）

请注意在前面的代码示例中使用了`&`符号。`&`运算符获取变量存储的内存地址。变量的内存地址是计算机内存空间中保留存储变量值的位置。C++能够获取程序内任何对象的内存地址。变量的地址是唯一的，也有点随机。

假设我们打印一个整数变量`x`的地址，如下所示：

```cpp
int x = 22; 
cout << &x << endl; // print the address of x 
```

在程序的第一次运行中，我的计算机打印如下：

```cpp
0023F744 
```

这个数字（`&x`的值）只是存储`x`的内存单元。这意味着在程序的这次启动中，`x`变量位于内存单元编号`0023F744`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6bdb0610-ff05-47f6-a361-5b6026e67f61.png)

您可能会想为什么前面的数字包含一个`F`。地址是十六进制（基数 16），因此在 9 之后数字位用完了，但实际上 1 中无法容纳两个数字，因此将值设置为 10-15 分别为 A-F。因此 A = 10，B = 11，在这种情况下 F = 15。

现在，创建并将指针变量分配给`x`的地址：

```cpp
int *px; 
px = &x; 
```

我们在这里做的是将`x`的内存地址存储在`px`变量中。因此，我们用另一个不同的变量`px`来指向`x`变量。这可能看起来类似于以下图示中所示的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/6e560752-06c4-46e1-b673-7e7486f96405.png)

在这里，`px`变量中包含了`x`变量的地址。换句话说，`px`变量是对另一个变量的引用。对`px`进行解引用意味着访问`px`引用的变量。解引用使用`*`符号进行：

```cpp
cout << *px << endl; 
```

# 使用 nullptr

`nullptr`变量是一个值为`0`的指针变量。一般来说，大多数程序员喜欢在创建新指针变量时将指针初始化为`nullptr`（`0`）。一般来说，计算机程序无法访问内存地址`0`（它是保留的），因此如果尝试引用空指针，程序将崩溃。

*Pointer Fun with Binky*是一个关于指针的有趣视频。请查看[`www.youtube.com/watch?v=i49_SNt4yfk`](http://www.youtube.com/watch?v=i49_SNt4yfk)。

# 智能指针

指针可能很难管理。一旦我们在本书的后面开始创建和删除新对象，我们可能不知道所有指向特定对象的指针在哪里。删除仍在使用的另一个指针指向的对象可能太容易（导致崩溃），或者停止指向对象的唯一指针并使其漂浮在内存中而没有任何引用（这称为内存泄漏，并会减慢计算机的速度）。

智能指针跟踪特定对象存在多少引用，并将随着代码中的变化自动增加或减少这个数字。这使得更容易控制发生的事情，在实际编程中，尽可能使用普通指针更可取。

人们过去必须编写自己的智能指针，但自从 C++ 11 以来就不再需要了。现在有一个`shared_ptr`模板可用（我们稍后会讨论模板和 STL）。这将自动跟踪指向对象的指针，并在没有其他引用它时自动删除该对象，防止内存泄漏。这就是为什么最好使用智能指针而不是指针，因为普通指针可能最终指向已在代码的其他地方被删除的对象。

# 输入和输出

在编程中，您不断需要向用户传递信息，或者从用户那里获取信息。对于我们将要开始的简单情况（以及后来查找错误的许多情况），您需要输入和输出标准文本和数字。C++使这变得很容易。

# cin 和 cout 对象

我们已经在之前的例子中看到了`cout`的工作原理。`cin`对象是 C++传统上从用户输入程序中获取输入的方式。`cin`对象易于使用，因为它查看将值放入的变量类型，并使用该类型来确定放入其中的类型。例如，假设我们想要询问用户的年龄并将其存储在`int`变量中。我们可以这样做：

```cpp
cout << "What is your age?" << endl; 
int age; 
cin >> age; 
```

运行此代码时，它将打印`What is your age?`并等待您的回答。输入一个回答并按*Enter*进行输入。您可能想尝试输入除`int`变量之外的其他内容，以查看会发生什么！

# printf()函数

尽管到目前为止我们已经使用`cout`打印变量，但您还应该了解另一个常用函数，用于打印到控制台。这个函数称为`printf`函数，最初来自 C。`printf`函数包含在`<iostream>`库中，因此您无需`#include`任何额外的内容即可使用它。游戏行业的一些人更喜欢`printf`而不是`cout`，因此让我们介绍一下。

让我们继续讲解`printf()`的工作原理，如下面的代码所示：

```cpp
#include <iostream> 
#include <string> 
using namespace std; 
int main() 
{ 
  char character = 'A'; 
  int integer = 1; 
  printf( "integer %d, character %c\n", integer, character ); 
} 
```

下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，用于您购买的所有 Packt 图书。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

我们从一个格式字符串开始。格式字符串就像一个画框，变量将被插入到格式字符串中`%`的位置。然后，整个东西被倾倒到控制台上。在前面的例子中，整数变量将被插入到格式字符串中第一个`%`（`%d`）的位置，字符将被插入到格式字符串中第二个`%`（`%c`）的位置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/0f75934f-d8a3-4f1f-92c3-8e724477863f.png)

您必须使用正确的格式代码才能使输出正确格式化；请看下表：

| 数据类型 | 格式代码 |
| --- | --- |
| `Int` | `%d` |
| `Char` | `%c` |
| `String` | `%s` |

要打印 C++字符串，您必须使用`string.c_str()`函数：

```cpp
string s = "Hello"; printf( "string %s\n", s.c_str() ); 
```

`s.c_str()`函数访问字符串的 C 指针，这是`printf`所需要的。

如果您使用错误的格式代码，输出将不会正确显示，或者程序可能会崩溃。

您可能还会发现需要使用这种类型的格式来设置字符串的情况，所以了解这一点是很好的。但是，如果您更喜欢避免记住这些不同的格式代码，只需使用`cout`。它会为您找出类型。只要确保您使用您最终工作的公司所偏好的标准。在大多数编程事情中，这通常是一个好主意。

# 练习

询问用户姓名和年龄，并使用`cin`将它们输入。然后，使用`printf()`在控制台上为他们发出问候（而不是`cout`）。

# 解决方案

程序将如下所示：

```cpp
#include <iostream> 
#include <string> 
using namespace std; 
int main() 
{ 
  cout << "Name?" << endl; 
  string name; 
  cin >> name; 
  cout << "Age?" << endl;  
  int age; 
  cin >> age; 
  //Change to printf:
  cout << "Hello " << name << " I see you have attained " << age  
   << " years. Congratulations." << endl; 
} 
```

字符串实际上是一种对象类型。在内部，它只是一堆字符！

# 命名空间

到目前为止，我们已经在`std`的情况下看到了命名空间，并且大多数情况下通过在文件顶部放置以下内容来避免这个问题：

```cpp
using namespace std;
```

但是，您应该知道这对未来意味着什么。

命名空间是将相关代码分组在一起的方式，它允许您在不同的命名空间中使用相同的变量名称而不会出现任何命名冲突（当然，除非您在顶部为两者都使用了`using namespace`，这就是为什么许多人更喜欢不使用它的原因）。

您可以像这样在 C++文件中创建自己的命名空间：

```cpp
namespace physics {
    float gravity = 9.80665;
    //Add the rest of your your physics related code here...
}
```

一旦您创建了命名空间，您就可以像这样访问该代码：

```cpp
float g = physics::gravity;
```

或者，您可以在顶部放入一个使用语句（只要确保该名称没有用于其他用途）。但是，一般来说，您不希望在更复杂的程序中使用这个，因为命名空间允许您在不同的命名空间中重用相同的变量名称，因此如果您将其与一个包含当前命名空间中具有相同名称的变量的命名空间一起使用，并尝试访问它，编译器将不知道您指的是哪一个，这将导致冲突。

# 总结

在本章中，我们讨论了变量和内存。我们谈到了关于变量的数学运算，以及它们在 C++中是多么简单。

我们还讨论了如何使用这些更简单的数据类型（如浮点数、整数和字符）的组合来构建任意复杂的数据类型。这样的构造被称为对象。在下一章中，我们将开始讨论我们可以用这些对象做什么！


# 第三章：If，Else 和 Switch

在上一章中，我们讨论了内存的重要性以及如何将数据存储在计算机内部。我们谈到了如何使用变量为程序保留内存，并且我们可以在变量中包含不同类型的信息。

在本章中，我们将讨论如何控制程序的流程以及如何通过控制流语句分支代码。在这里，我们将讨论不同类型的控制流，如下所示：

+   `If`语句

+   如何使用`==`运算符检查事物是否相等

+   `else`语句

+   如何测试不等式（即，如何使用`>`,`>=`,`<`,`<=`和`!=`运算符检查一个数字是否大于或小于另一个数字）

+   使用逻辑运算符（如非（`!`），和（`&&`），或（`||`））

+   分支超过两种方式：

+   `else if`语句

+   `switch`语句

+   我们的第一个虚幻引擎示例项目

# 分支

我们在第二章中编写的计算机代码只有一个方向：向下。有时，我们可能希望能够跳过代码的某些部分。我们可能希望代码能够分支到多个方向。从图表上看，我们可以这样表示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/c1178346-f65b-44e1-84a2-c7030d6be946.png)

换句话说，我们希望在特定条件下有选择地不运行某些代码行。上面的图表称为流程图。根据这个流程图，只有当我们饿了，我们才会准备三明治，吃完后就去休息。如果我们不饿，那么就不需要做三明治，我们会直接休息。

在本书中，我们有时会使用流程图，但在 UE4 中，您甚至可以使用流程图来编写游戏（使用称为蓝图的东西）。

这本书是关于 C++代码的，因此在本书中，我们将始终将我们的流程图转换为实际的 C++代码。

# 控制程序的流程

最终，我们希望代码在特定条件下以一种方式分支。更改下一行执行的代码的代码命令称为控制流语句。最基本的控制流语句是`if`语句。为了能够编写`if`语句，我们首先需要一种检查变量值的方法。

因此，首先让我们介绍`==`符号，用于检查变量的值。

# ==运算符

为了在 C++中检查两个事物是否相等，我们需要使用两个等号（`==`）而不是一个，如下所示：

```cpp
int x = 5; // as you know, we use one equals sign  
int y = 4; // for assignment.. 
// but we need to use two equals signs  
// to check if variables are equal to each other 
cout << "Is x equal to y? C++ says: " << (x == y) << endl; 
```

如果运行上述代码，您会注意到输出如下：

```cpp
Is x equal to y? C++ says: 0  
```

在 C++中，`1`表示`true`，`0`表示`false`。如果您希望在`1`和`0`之外显示`true`或`false`，可以在`cout`代码行中使用`boolalpha`流操纵器，如下所示：

```cpp
cout << "Is x equal to y? C++ says: " << boolalpha <<  
        (x == y) << endl; 
```

`==`运算符是一种比较运算符。C++使用`==`来检查相等性的原因是，我们已经使用了`=`符号作为赋值运算符！（请参阅第二章中的*关于变量的更多信息*部分）。如果使用单个`=`符号，C++将假定我们要用`y`覆盖`x`，而不是比较它们。

# 编写 if 语句

现在我们掌握了双等号，让我们编写流程图。上述流程图的代码如下：

```cpp
bool isHungry = true;  // can set this to false if not 
                       // hungry! 
if( isHungry == true ) // only go inside { when isHungry is true 
{ 
  cout << "Preparing snack.." << endl; 
  cout << "Eating .. " << endl; 
} 
cout << "Sitting on the couch.." << endl; 
```

这是我们第一次使用`bool`变量！`bool`变量可以保存值`true`或值`false`。

首先，我们从一个名为`isHungry`的`bool`变量开始，然后将其设置为`true`。

然后，我们使用`if`语句，如下所示：

```cpp
if( isHungry == true )
```

`if`语句就像是守卫下面的代码块（记住，代码块是在`{`和`}`中的一组代码）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/31a956f9-de7e-4848-b059-20dade64db0d.png)

只有当`isHungry==true`时，您才能阅读`{`和`}`之间的代码。

只有当`isHungry==true`时，您才能访问大括号内的代码。否则，您将被拒绝访问并被迫跳过整个代码块。

基本上，任何可以作为布尔值进行评估的东西都可以放在`if（boolean）`中。因此，我们可以通过简单地编写以下代码行来实现相同的效果：

`if（isHungry）//只有在 isHungry 为 true 时才会到这里`这可以用作以下内容的替代：

`if（isHungry==true）`

人们可能使用`if（isHungry）`形式的原因是为了避免出错的可能性。意外写成`if（isHungry = true）`会使`isHungry`在每次命中`if`语句时都设置为 true！为了避免这种可能性，我们可以只写`if（isHungry）`。或者，一些（明智的）人使用所谓的 Yoda 条件来检查`if`语句：`if（true == isHungry）`。我们以这种方式编写`if`语句的原因是，如果我们意外地写成`if（true = isHungry）`，这将生成编译器错误，捕捉错误。

尝试运行此代码段以查看我的意思：

```cpp
int x = 4, y = 5; 
cout << "Is x equal to y? C++ says: " << (x = y) << endl; //bad! 
// above line overwrote value in x with what was in y, 
// since the above line contains the assignment x = y 
// we should have used (x == y) instead. 
cout << "x = " << x << ", y = " << y << endl; 
```

以下行显示了前面代码的输出：

```cpp
Is x equal to y? C++ says: 5 
x = 5, y = 5 
```

具有`(x = y)`的代码行会覆盖`x`的先前值（为 4）并用`y`的值（为 5）进行赋值。尽管我们试图检查`x`是否等于`y`，但在先前的语句中发生的是`x`被赋予了`y`的值。

# 编写 else 语句

`else`语句用于在`if`部分的代码未运行时执行我们的代码。

例如，假设我们还有其他事情要做，以防我们不饿，如下面的代码片段所示：

```cpp
bool isHungry = true; 
if( isHungry )      // notice == true is implied! 
{ 
  cout << "Preparing snack.." << endl; 
  cout << "Eating .. " << endl; 
} 
else                // we go here if isHungry is FALSE 
{ 
  cout << "I'm not hungry" << endl; 
} 
cout << "Sitting on the couch.." << endl; 
```

有几件重要的事情您需要记住关于`else`关键字，如下所示：

+   `else`语句必须紧随`if`语句之后。在`if`块结束和相应的`else`块之间不能有任何额外的代码行。

+   程序永远不会同时执行`if`和相应的`else`块。它总是一个或另一个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/3676e502-fcb4-404c-b163-9fc5bb354f97.png)

如果 `isHungry` 不等于 true，则`else`语句是您将要执行的方式。

您可以将`if`/`else`语句视为将人们引导到左侧或右侧的守卫。每个人都会朝着食物走（当`isHungry==true`时），或者他们会远离食物（当`isHungry==false`时）。

# 使用其他比较运算符（>，>=，<，<=和!=）进行不等式测试

C++中可以很容易地进行其他逻辑比较。 `>` 和 `<` 符号的意思与数学中一样。它们分别表示大于（`>`）和小于（`<`）。`>=` 在数学中与 `≥` 符号具有相同的含义。`<=` 是 C++中 `≤` 的代码。由于键盘上没有 `≤` 符号，我们必须在 C++中使用两个字符来编写它。`!=` 是 C++中表示“不等于”的方式。因此，例如，假设我们有以下代码行：

```cpp
int x = 9; 
int y = 7; 
```

我们可以询问计算机是否 `x > y` 或 `x < y`，如下所示：

```cpp
cout << "Is x greater than y? " << (x > y) << endl; 
cout << "Is x greater than OR EQUAL to y? " << (x >= y) << endl; 
cout << "Is x less than y? " << (x < y) << endl; 
cout << "Is x less than OR EQUAL to y? " << (x <= y) << endl; 
cout << "Is x not equal to y? " << (x != y) << endl; 
```

我们需要在比较`x`和`y`时加上括号，因为有一个称为运算符优先级的东西。如果没有括号，C++将在`<<`和`<`运算符之间感到困惑。这很奇怪，您稍后会更好地理解这一点，但您需要 C++在输出结果（<<）之前评估`(x < y)`比较。有一个很好的可供参考的表格，网址为[`en.cppreference.com/w/cpp/language/operator_precedence`](http://en.cppreference.com/w/cpp/language/operator_precedence)。

# 使用逻辑运算符

逻辑运算符允许您进行更复杂的检查，而不仅仅是检查简单的相等或不相等。例如，要获得进入特殊房间的条件需要玩家同时拥有红色和绿色钥匙卡。我们想要检查两个条件是否同时成立。为了进行这种复杂的逻辑语句检查，我们需要学习三个额外的构造：非(`!`)、和(`&&`)和或(`||`)运算符。

# 非(!)运算符

`!`运算符很方便，可以颠倒`boolean`变量的值。以以下代码为例：

```cpp
bool wearingSocks = true; 
if( !wearingSocks ) // same as if( false == wearingSocks ) 
{
         cout << "Get some socks on!" << endl;
 } 
else 
{ 
        cout << "You already have socks" << endl; 
} 
```

这里的`if`语句检查您是否穿袜子。然后，您会收到一个命令来穿上一些袜子。`!`运算符将`boolean`变量中的值取反。

我们使用一个称为真值表的东西来显示在`boolean`变量上使用`!`运算符的所有可能结果，如下所示：

| `wearingSocks` | `!wearingSocks` |
| --- | --- |
| `true` | `false` |
| `false` | `true` |

因此，当`wearingSocks`的值为`true`时，`!wearingSocks`的值为`false`，反之亦然。

# 练习

1.  当`wearingSocks`的值为`true`时，您认为`!!wearingSocks`的值将是多少？

1.  在运行以下代码后，`isVisible`的值是多少？

```cpp
bool hidden = true; 
bool isVisible = !hidden; 
```

# 解决方案

1.  如果`wearingSocks`是`true`，那么`!wearingSocks`就是`false`。因此，`!!wearingSocks`再次变为`true`。这就像在说“我不饿”。双重否定，所以这句话意味着我实际上是饿了。

1.  第二个问题的答案是`false`。`hidden`的值是`true`，所以`!hidden`是`false`。然后`false`的值被保存到`isVisible`变量中。但`hidden`本身的值仍然是`true`。

`!`运算符有时在口语中被称为感叹号。前面的双重感叹号操作(`!!`)是双重否定和双重逻辑反转。如果您对`bool`变量进行双重否定，那么变量不会有任何变化。

当然，您可以在`int`上使用这些，如果`int`设置为零，`! int`将是`true`，如果大于零，`! int`将是`false`。因此，如果您对该`int`变量进行双重否定，且`int`值大于零，则它将简化为`true`。如果`int`值已经是 0，则它将简化为`false`。

# 和(&&)运算符

假设我们只想在两个条件都为`true`时运行代码的一部分。例如，只有在我们穿袜子和衣服时才算穿好衣服。您可以使用以下代码来检查：

```cpp
bool wearingSocks = true; 
bool wearingClothes = false; 
if( wearingSocks && wearingClothes )// && requires BOTH to be true 
{ 
        cout << "You are dressed!" << endl; 
} 
else 
{ 
        cout << "You are not dressed yet" << endl; 
} 
```

# 或(||)运算符

有时我们希望在变量中的任一个为`true`时运行代码的一部分。

例如，假设玩家在关卡中找到特殊星星或完成关卡所需的时间少于 60 秒时，可以获得特定的奖励。在这种情况下，您可以使用以下代码：

```cpp
bool foundStar = false; 
float levelCompleteTime = 25.f; 
float maxTimeForBonus = 60.f; 
// || requires EITHER to be true to get in the { below 
if( foundStar || (levelCompleteTime < maxTimeForBonus) ) 
{ 
        cout << "Bonus awarded!" << endl; 
} 
else 
{ 
        cout << "No bonus." << endl; 
} 
```

您可能会注意到我在`levelCompleteTime < maxTimeForBonus`周围添加了括号。尽管优先级规则可能让您在没有它们的情况下添加更长的语句，但我发现如果有任何疑问，最好还是添加它们。小心总比后悔好（对于稍后查看的其他人来说可能更清晰）。

# 练习

到目前为止，您应该已经注意到提高编程能力的最佳方法是通过实践。您必须经常练习编程才能显著提高。

创建两个整数变量，称为`x`和`y`，并从用户那里读取它们。编写一个`if`/`else`语句对，打印出值较大的变量的名称。

# 解决方案

上一个练习的解决方案如下所示：

```cpp
int x, y; 
cout << "Enter two numbers (integers), separated by a space " << endl; 
cin >> x >> y; 
if( x < y )  
{ 
  cout << "x is less than y" << endl; 
} 
else 
{ 
  cout << "x is greater than y" << endl; 
} 
```

当`cin`期望一个数字时不要输入字母。如果发生这种情况，`cin`可能会失败，并给您的变量一个错误的值。

# 以两种以上的方式分支代码

在以前的章节中，我们只能使代码在两种方式中的一种分支。在伪代码中，我们有以下代码：

```cpp
if( some condition is true ) 
{ 
  execute this; 
} 
else // otherwise 
{ 
  execute that; 
} 
```

伪代码是*假代码*。编写伪代码是一种很好的头脑风暴和计划代码的方法，特别是如果你还不太习惯 C++的话。

这段代码有点像是在一个象征性的岔路口，只有两个方向可选。

有时，我们可能希望代码分支不仅仅有两个方向。我们可能希望代码以三种方式或更多方式分支。例如，假设代码的走向取决于玩家当前持有的物品。玩家可以持有三种不同的物品：硬币、钥匙或沙元。C++允许这样做！事实上，在 C++中，你可以按照任意你希望的方向进行分支。

# `else if`语句

`else if`语句是一种编写超过两个可能分支方向的方法。在下面的代码示例中，代码将根据玩家持有的`Coin`、`Key`或`Sanddollar`对象的不同方式进行运行：

```cpp
#include <iostream> 
using namespace std; 
int main() 
{ 
  enum Item  // This is how enums come in handy!
  { 
    Coin, Key, Sanddollar // variables of type Item can have  
    // any one of these 3 values 
  };
  Item itemInHand = Key;  // Try changing this value to Coin,  
                          // Sanddollar 
  if( itemInHand == Key ) 
  { 
    cout << "The key has a lionshead on the handle." << endl; 
    cout << "You got into a secret room using the Key!" << endl; 
  } 
  else if( itemInHand == Coin ) 
  { 
    cout << "The coin is a rusted brassy color. It has a picture  
     of a lady with a skirt." << endl; 
    cout << "Using this coin you could buy a few things" << endl; 
  } 
  else if( itemInHand == Sanddollar ) 
  { 
    cout << "The sanddollar has a little star on it." << endl; 
    cout << "You might be able to trade it for something." <<  
     endl; 
  } 
  return 0;  
} 
```

请注意，前面的代码只会按三种不同的方式之一进行！在`if`、`else`和`else if`系列检查中，我们只会进入一个代码块。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/ee886ad0-ece1-421b-a109-35e91255f97f.png)

# 练习

使用 C++程序回答代码后面的问题。一定要尝试这些练习，以便熟练掌握这些相等运算符：

```cpp
#include <iostream> 
using namespace std; 
int main() 
{ 
  int x; 
  int y; 
  cout << "Enter an integer value for x:" << endl; 
  cin >> x; // This will read in a value from the console 
  // The read in value will be stored in the integer  
  // variable x, so the typed value better be an integer! 
  cout << "Enter an integer value for y:" << endl; 
  cin >> y; 
  cout << "x = " << x << ", y = " << y << endl; 
  // *** Write new lines of code here 
} 
```

在标有(`// *** Write new...`)的位置写一些新的代码行：

1.  检查`x`和`y`是否相等。如果它们相等，打印`x and y are equal`。否则，打印`x and y are not equal`。

1.  一个关于不等式的练习：检查`x`是否大于`y`。如果是，打印`x is greater than y`。否则，打印`y is greater than x`。

# 解决方案

要评估相等性，请插入以下代码：

```cpp
if( x == y ) 
{ 
  cout << "x and y are equal" << endl; 
} 
else 
{ 
  cout << "x and y are not equal" << endl; 
} 
```

要检查哪个值更大，请插入以下代码：

```cpp
if( x > y ) 
{ 
  cout << "x is greater than y" << endl; 
} 
else if( x < y ) 
{ 
  cout << "y is greater than x" << endl; 
} 
else // in this case neither x > y nor y > x 
{ 
  cout << "x and y are equal" << endl; 
} 
```

# `switch`语句

`switch`语句允许你的代码以多种方式分支。`switch`语句将查看变量的值，并根据其值，代码将走向不同的方向。

我们还会在这里看到`enum`构造：

```cpp
#include <iostream> 
using namespace std; 
enum Food  // enums are very useful with switch! 
{ 
  // a variable of type Food can have any of these values 
  Fish, 
  Bread, 
  Apple, 
  Orange 
}; 
int main() 
{ 
  Food food = Bread; // Change the food here 
  switch( food ) 
  { 
    case Fish: 
      cout << "Here fishy fishy fishy" << endl; 
      break; 
    case Bread: 
      cout << "Chomp! Delicious bread!" << endl; 
      break; 
    case Apple: 
      cout << "Mm fruits are good for you" << endl; 
      break; 
    case Orange: 
      cout << "Orange you glad I didn't say banana" << endl; 
      break; 
    default:  // This is where you go in case none 
              // of the cases above caught 
      cout << "Invalid food" << endl; 
      break; 
  } 
  return 0; 
} 
```

`switch`就像硬币分类器。当你把 25 美分硬币放入硬币分类器时，它会自动进入 25 美分硬币堆。同样，`switch`语句将允许代码跳转到适当的部分。硬币分类的示例显示在下图中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/d32684e2-0719-4159-af5b-c8cf73d1773d.png)

`switch`语句内的代码将继续运行（逐行），直到遇到`break;`语句。`break`语句会跳出`switch`语句。如果省略`break;`语句，它将继续运行下一个 case 语句内的代码，并且直到遇到`break;`或者`switch`结束才会停止。如果你想尝试，可以尝试去掉所有的`break;`语句，看看会发生什么！看一下下面的图表，了解`switch`的工作原理：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/313c6aed-604d-4a6d-a39f-ab1684cd5561.png)

1.  首先检查`Food`变量。它有什么值？在这种情况下，它里面有`Fish`。

1.  `switch`命令跳转到正确的 case 标签。（如果没有匹配的 case 标签，`switch`将被跳过）。

1.  `cout`语句被执行，控制台上出现`Here fishy fishy fishy`。

1.  检查变量并打印用户响应后，`break`语句被执行。这使我们停止运行`switch`中的代码行，并退出`switch`。接下来要运行的代码行就是如果`switch`根本不存在的话，否则将是程序中的下一行代码（在`switch`语句的结束大括号之后）。是`return 0`退出程序。

# `switch`语句与`if`语句

开关类似于之前的`if` / `else if` / `else`链。但是，开关可以比`if` / `else if` / `else if` / `else`链更快地生成代码。直观地说，开关只会跳转到适当的代码部分以执行。`if` / `else if` / `else`链可能涉及更复杂的比较（包括逻辑比较），这可能需要更多的 CPU 时间。您将使用`if`语句的主要原因是，如果您要检查的内容比仅比较特定值集合中的内容更复杂。

`enum`的一个实例实际上是一个`int`。要验证这一点，请打印以下代码：

`cout << "Fish=" << Fish <<

" Bread=" << Bread <<

" Apple=" << Apple <<`

` "Orange=" << Orange << endl;`

您将看到`enum`的整数值-只是让您知道。

有时，程序员希望在相同的开关`case`标签下分组多个值。假设我们有一个如下所示的`enum`对象：

```cpp
enum Vegetables { Potato, Cabbage, Broccoli, Zucchini }; 
```

程序员希望将所有绿色物品分组在一起，因此他们编写了一个如下所示的`switch`语句：

```cpp
Vegetable veg = Zucchini;

switch( veg ) 
{ 
case Zucchini:             // zucchini falls through because no break 
case Broccoli:             // was written here 
  cout << "Greens!" << endl; 
  break; 
default: 
  cout << "Not greens!" << endl; 
  break; 
} 
```

在这种情况下，`Zucchini`会掉下来并执行与`Broccoli`相同的代码。

非绿色蔬菜位于`default` case 标签中。为了防止穿透，您必须记住在每个`case`标签后插入显式的`break`语句。

我们可以编写另一个版本的相同开关，它不会让 Zucchini 掉下来，而是在开关中明确使用`break`关键字：

```cpp
switch( veg ) 
{ 
case Zucchini:              // zucchini no longer falls due to break 
  cout << "Zucchini is a green" << endl; 
  break;// stops case zucchini from falling through 
case Broccoli:               // was written here 
  cout << "Broccoli is a green" << endl; 
  break; 
default: 
  cout << "Not greens!" << endl; 
  break; 
} 
```

请注意，即使它是最后一个列出的情况，`break` `default` case 也是良好的编程实践。

# 练习

完成以下程序，其中有一个`enum`对象，其中有一系列可供选择的坐骑。编写一个`switch`语句，为所选的坐骑打印以下消息：

| `Horse` | 这匹骏马是勇敢而强大的。 |
| --- | --- |
| `Mare` | 这匹母马是白色和美丽的。 |
| `Mule` | 你被给了一匹骡子骑。你对此感到愤慨。 |
| `Sheep` | 咩！这只羊几乎无法支撑您的重量。 |
| `Chocobo` | Chocobo! |  |

请记住，`enum`对象实际上是一个`int`语句。`enum`对象中的第一个条目默认为`0`，但您可以使用`=`运算符为`enum`对象指定任何起始值。`enum`对象中的后续值是按顺序排列的`ints`。

# 解决方案

上一个练习的解决方案显示在以下代码中：

```cpp
#include <iostream> 
using namespace std; 
enum Mount 
{ 
  Horse=1, Mare, Mule, Sheep, Chocobo 
  // Since Horse=1, Mare=2, Mule=3, Sheep=4, and Chocobo=5\. 
}; 
int main() 
{ 
  int mount;  // We'll use an int variable for mount 
              // so cin works 
  cout << "Choose your mount:" << endl; 
  cout << Horse << " Horse" << endl; 
  cout << Mare << " Mare" << endl; 
  cout << Mule << " Mule" << endl; 
  cout << Sheep << " Sheep" << endl; 
  cout << Chocobo << " Chocobo" << endl; 
  cout << "Enter a number from 1 to 5 to choose a mount" << endl; 
  cin >> mount; 
    // Describe what happens 
    // when you mount each animal in the switch below 
  switch( mount ) 
  { 
    default: 
      cout << "Invalid mount" << endl; 
      break; 
  } 
return 0; 
} 
```

# 位移的枚举

在`enum`对象中常见的做法是为每个条目分配一个位移值：

```cpp
enum   WindowProperties   
{   
    Bordered    = 1 << 0, // binary 001   
    Transparent = 1 << 1, // binary 010   
    Modal       = 1 << 2  // binary 100   
};   
```

位移值应该能够组合窗口属性。分配将如下所示：

```cpp
//   bitwise OR combines properties   
WindowProperties   wp = Bordered | Modal;   
```

检查已设置哪些`WindowProperties`涉及使用`按位 AND`进行检查：

```cpp
//   bitwise AND checks to see if wp is Modal   
if( wp   & Modal )   
{   
    cout << "You are looking at a modal window" << endl;
}   
```

位移是一种略微超出本书范围的技术，但我包含了这个提示，只是让您知道它。

# 我们在虚幻引擎中的第一个示例

我们需要开始使用虚幻引擎。

警告：当您打开第一个虚幻项目时，您会发现代码看起来非常复杂。不要灰心。只需专注于突出显示的部分。在您作为程序员的职业生涯中，您经常需要处理包含您不理解的部分的非常庞大的代码库。然而，专注于您理解的部分将使本节变得富有成效。

首先，您需要下载启动器以安装引擎。转到[`www.unrealengine.com/en-US/what-is-unreal-engine-4`](https://www.unrealengine.com/en-US/what-is-unreal-engine-4)，当您单击立即开始或下载时，您必须在下载启动器之前创建一个免费帐户。

下载启动器后，打开 Epic Games Launcher 应用程序。选择启动虚幻引擎 4.20.X（到您阅读此内容时可能会有新版本），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/04daefd6-113d-4bca-b666-9978e61e8f50.png)

如果您没有安装引擎，您需要转到虚幻引擎选项卡并下载一个引擎（~7 GB）。

一旦引擎启动（可能需要几秒钟），你将进入虚幻项目浏览器屏幕，就像下面的截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/2f95b850-6c0b-4430-8406-180d2d8c046c.png)

现在，在 UE4 项目浏览器中选择“新项目”标签页。选择 C++标签页并选择 Puzzle 项目。这是一个比较简单的项目，代码不是太多，所以很适合入门。我们稍后会转到 3D 项目。

在这个屏幕上有几件事情要注意：

+   确保你在“新项目”标签页中。

+   当你点击 Puzzle 时，确保它是 C++标签页上的一个，而不是蓝图标签页上的一个。

+   在“名称”框中输入项目名称`Puzzle`（这对我稍后给你的示例代码很重要）。

+   如果你想更改存储文件夹（比如更改到另一个驱动器），点击文件夹旁边的...按钮，这样浏览窗口就会出现。然后，找到你想要存储项目的目录。

完成所有这些后，选择创建项目。

注意：如果它告诉你无法创建项目，因为你没有安装 Windows 8.1 SDK，你可以从[`developer.microsoft.com/en-us/windows/downloads/sdk-archive`](https://developer.microsoft.com/en-us/windows/downloads/sdk-archive)下载它。

Visual Studio 2017 将打开你的项目代码，以及虚幻编辑器，就像下面的截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a1f96d5d-3788-4084-af56-7b2642074bb6.png)

看起来复杂吗？哦，天哪，它确实复杂！我们稍后会探索一些工具栏中的功能。现在，只需选择播放，就像前面的截图中所示的那样。

这将启动游戏。它应该是这个样子的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/a8243275-3064-4ce4-a989-5047adb97709.png)

现在，尝试点击方块。一旦你点击一个方块，它就会变成橙色，这会增加你的分数。你可以通过点击“停止”或在键盘上按*Esc*来结束你的游戏会话。

我们要做的是找到这个部分并稍微改变一下行为。

找到并打开`PuzzleBlock.cpp`文件。在 C++类|拼图下找到 PuzzleBlock，双击它以在 IDE 中打开它。

在 Visual Studio 中，项目中的文件列表位于“解决方案资源管理器”中。如果你的“解决方案资源管理器”被隐藏了，只需点击顶部菜单中的“查看/解决方案资源管理器”。

在这个文件中，向下滚动到底部，你会找到一个以以下单词开头的部分：

```cpp
void APuzzleBlock::BlockClicked(UPrimitiveComponent* ClickedComp, FKey ButtonClicked)
```

`APuzzleBlock`是类名（我们稍后会介绍类），`BlockClicked`是函数名。每当一个拼图块被点击时，从起始`{`到结束`}`的代码部分就会运行。希望这发生的方式稍后会更有意义。

这在某种程度上有点像`if`语句。如果点击了一个拼图块，那么这组代码就会为该拼图块运行。

我们将逐步介绍如何使方块在被点击时翻转颜色（因此，第二次点击将把方块的颜色从橙色改回蓝色）。

以最大的小心进行以下步骤：

1.  打开`PuzzleBlock.h`文件。在包含以下代码的行之后：

```cpp
/** Pointer to blue material used on inactive blocks */
  UPROPERTY()
  class UMaterialInstance* BlueMaterial;

  /** Pointer to orange material used on active blocks */
  UPROPERTY()
  class UMaterialInstance* OrangeMaterial;
```

1.  现在，打开`PuzzleBlock.cpp`文件。查找以下代码：

```cpp
BlueMaterial = ConstructorStatics.BlueMaterial.Get();
OrangeMaterial = ConstructorStatics.OrangeMaterial.Get()
```

1.  在`PuzzleBlock.cpp`中，用以下代码替换 void `APuzzleBlock::BlockClicked`代码部分的内容：

```cpp
void APuzzleBlock::BlockClicked(UPrimitiveComponent* ClickedComp, FKey ButtonClicked) 
{ 
  // --REPLACE FROM HERE-- 
  bIsActive = !bIsActive; // flip the value of bIsActive 
  // (if it was true, it becomes false, or vice versa) 
  if ( bIsActive ) 
  { 
    BlockMesh->SetMaterial(0, OrangeMaterial); 
  } 
  else 
  { 
    BlockMesh->SetMaterial(0, BlueMaterial); 
  } 
  // Tell the Grid 
  if(OwningGrid != NULL) 
  { 
    OwningGrid->AddScore(); 
  } 
  // --TO HERE-- 
}
```

只替换`void APuzzleBlock::BlockClicked(UPrimitiveComponent* ClickedComp, FKey ButtonClicked)`语句内部。

不要替换以`void APuzzleBlock::BlockClicked`开头的那一行。你可能会出现错误（如果你没有将项目命名为`Puzzle`）。如果是这样，你可以通过使用正确的名称创建一个新项目来重新开始。

按下播放按钮，看看你的更改生效了！所以，让我们分析一下。这是第一行代码：

```cpp
bIsActive = !bIsActive; // flip the value of bIsActive 
```

这行代码只是翻转了`bIsActive`的值。`bIsActive`变量是一个`bool`变量（它在`APuzzleBlock.h`中创建），用于跟踪方块是否处于活动状态并且应该显示为橙色。这就像翻转开关一样。如果`bIsActive`为`true`，`!bIsActive`将为`false`。因此，每当这行代码被执行（通过点击任何方块时会发生），`bIsActive`的值就会被反转（从`true`到`false`或从`false`到`true`）。

让我们考虑下一段代码：

```cpp
if ( bIsActive ) 
  { 
    BlockMesh->SetMaterial(0, OrangeMaterial); 
  } 
  else 
  { 
    BlockMesh->SetMaterial(0, BlueMaterial); 
  } 
```

我们只是改变了方块的颜色。如果`bIsActive`为`true`，那么方块就会变成橙色。否则，方块就会变成蓝色。

# 总结

在本章中，您学会了如何分支代码。分支使代码可以朝不同的方向发展，而不是一直向下执行。

在下一章中，我们将继续讨论一种不同类型的控制流语句，它将允许您返回并重复执行一行代码一定次数。重复执行的代码部分将被称为循环。


# 第四章：循环

在上一章中，我们讨论了`if`语句。`if`语句使您能够对一块代码的执行设置条件。

在本章中，我们将探讨循环，这些是代码结构，使您能够在某些条件下重复执行一块代码。一旦条件变为 false，我们就停止重复执行该代码块。

在本章中，我们将探讨以下主题：

+   while 循环

+   do/while 循环

+   for 循环

+   虚幻引擎中实际循环的简单示例

# while 循环

`while`循环用于重复运行代码的一部分。如果您有一组必须重复执行以实现某个目标的操作，这将非常有用。例如，以下代码中的`while`循环重复打印变量`x`的值，从`1`递增到 5：

```cpp
int x = 1; 
while( x <= 5 ) // may only enter the body of the while when x<=5 
{ 
  cout << "x is " << x << endl; 
  x++; 
} 
cout << "Finished" << endl; 
```

这是上述程序的输出：

```cpp
x is 1 
x is 2 
x is 3 
x is 4 
x is 5 
Finished 
```

在代码的第一行，创建了一个整数变量`x`并将其设置为`1`。然后，我们进入`while`条件。`while`条件表示，只要`x`小于或等于`5`，您必须留在后面的代码块中。

循环的每次迭代（迭代意味着执行`{`和`}`之间的所有内容一次）都会完成一些任务（打印数字`1`到`5`）。我们编程循环在任务完成后自动退出（当`x <= 5`不再为真时）。

与上一章的`if`语句类似，只有在满足`while`循环括号内的条件时（在上面的例子中为`x <= 5`），才允许进入以下块。您可以尝试在以下代码中将`while`循环的位置替换为`if`循环，如下所示：

```cpp
int x = 1; 
if( x <= 5 ) // you may only enter the block below when x<=5 
{ 
  cout << "x is " << x << endl; 
  x = x + 1; 
} 
cout << "End of program" << endl; 
```

上面的代码示例将只打印`x is 1`。因此，`while`循环与`if`语句完全相同，只是它具有自动重复自身直到`while`循环括号内的条件变为 false 的特殊属性。

我想用一个视频游戏来解释`while`循环的重复。如果您不了解 Valve 的*Portal*，您应该玩一下，即使只是为了理解循环。查看[`www.youtube.com/watch?v=TluRVBhmf8w`](https://www.youtube.com/watch?v=TluRVBhmf8w)以获取演示视频。

`while`循环在底部有一种魔法传送门，导致循环重复。以下屏幕截图说明了我的意思：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/f688cd95-3a2c-4e18-91c1-a54c37fe99dd.png)

在 while 循环的末尾有一个传送门，可以将您带回起点

在上面的屏幕截图中，我们从橙色传送门（标记为`O`）回到蓝色传送门（标记为`B`）。这是我们第一次能够返回代码。这就像时间旅行，只不过是针对代码的。多么令人兴奋！

通过`while`循环块的唯一方法是不满足入口条件。在上面的例子中，一旦`x`的值变为 6（因此`x <= 5`变为 false），我们将不再进入`while`循环。由于橙色传送门在循环内部，一旦`x`变为 6，我们就能够退出循环。

# 无限循环

您可能会永远被困在同一个循环中。考虑以下代码块中修改后的程序（您认为输出会是什么？）：

```cpp
int x = 1; 
while( x <= 5 ) // may only enter the body of the while when x<=5 
{ 
  cout << "x is " << x << endl; 
} 
cout << "End of program" << endl; 
```

输出将如下所示：

```cpp
x is 1 
x is 1 
x is 1 
. 
. 
. 
(repeats forever) 
```

循环会永远重复，因为我们删除了改变`x`值的代码行。如果`x`的值保持不变且不允许增加，我们将被困在`while`循环的主体内。这是因为如果`x`在循环主体内部不发生变化，则无法满足循环的退出条件（`x`的值变为 6）。

只需单击窗口上的 x 按钮即可关闭程序。

以下练习将使用前几章中的所有概念，例如`+=`和递减操作。如果您忘记了某些内容，请返回并重新阅读前几节。

# 练习

让我们来看几个练习：

1.  编写一个`while`循环，将打印数字`1`到`10`

1.  编写一个`while`循环，将倒序打印从 10 到 1 的数字

1.  编写一个`while`循环，将打印 2 到 20 的数字，每次增加 2（例如 2、4、6、8）

1.  编写一个`while`循环，将打印数字 1 到 16 及其平方

以下是练习 4 的示例程序输出：

| `1` | `1` |
| --- | --- |
| `2` | `4` |
| `3` | `9` |
| `4` | `16` |
| `5` | `25` |

# 解决方案

前面练习的代码解决方案如下：

1.  `while`循环打印从`1`到`10`的数字的解决方案如下：

```cpp
int x = 1; 
while( x <= 10 ) 
{ 
  cout << x << endl; 
  x++; 
}
```

1.  `while`循环的解决方案，倒序打印从`10`到`1`的数字如下：

```cpp
int x = 10; // start x high 
while( x >= 1 ) // go until x becomes 0 or less 
{ 
  cout << x << endl; 
  x--; // take x down by 1 
} 
```

1.  `while`循环打印从`2`到`20`的数字，每次增加`2`的解决方案如下：

```cpp
int x = 2; 
while( x <= 20 ) 
{ 
  cout << x << endl; 
  x+=2; // increase x by 2's 
} 
```

1.  `while`循环的解决方案，打印从`1`到`16`的数字及其平方如下：

```cpp
int x = 1; 
while( x <= 16 ) 
{ 
  cout << x << "   " << x*x << endl; // print x and it's  
   square 
  x++; 
} 
```

# do/while 循环

`do`/`while`循环与`while`循环几乎相同。以下是一个等效于我们检查的第一个`while`循环的`do`/`while`循环的示例：

```cpp
int x = 1; 
do 
{ 
  cout << "x is " << x << endl; 
  x++; 
} while( x <= 5 ); // may only loop back when x<=5 
cout << "End of program" << endl; 
```

唯一的区别在于，我们在第一次进入循环时不必检查`while`条件。这意味着`do`/`while`循环的体至少会执行一次（而`while`循环如果第一次进入时条件为 false，则可以完全跳过）。

这里有一个例子：

```cpp
int val = 5;
while (val < 5)
{
    cout << "This will not print." << endl;
}
do {
    cout << "This will print once." << endl;
} while (val < 5);
```

# for 循环

`for`循环的解剖略有不同于`while`循环，但两者都非常相似。

让我们比较`for`循环的解剖和等效的`while`循环。以以下代码片段为例：

| `for`循环 | 等效的`while`循环 |
| --- | --- |
| for( int x = 1; x <= 5; x++ ){      cout << x << endl;} | int x = 1;while( x <= 5 ){     cout << x << endl;     x++;} |

`for`循环在其括号内有三个语句。让我们按顺序检查它们。

`for`循环的第一个语句(`int x = 1;`)只在我们第一次进入`for`循环体时执行一次。它通常用于初始化循环的计数变量的值（在本例中是变量`x`）。`for`循环括号内的第二个语句(`x <= 5;`)是循环的重复条件。只要`x <= 5`，我们必须继续留在`for`循环的体内。`for`循环括号内的最后一个语句(`x++;`)在每次完成`for`循环体后执行。

以下一系列图表解释了`for`循环的进展：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/de84ff9a-68b1-49b7-b067-c112b9c42efd.png)

# 练习

让我们来看一些练习：

1.  编写一个`for`循环，将收集从`1`到`10`的数字的总和

1.  编写一个`for`循环，将打印`6`到`30`的`6`的倍数（6、12、18、24 和 30）

1.  编写一个`for`循环，将以`2`的倍数打印 2 到 100 的数字（例如，2、4、6、8 等）

1.  编写一个`for`循环，将打印数字`1`到`16`及其平方

# 解决方案

以下是前面练习的解决方案：

1.  打印从`1`到`10`的数字的总和的`for`循环的解决方案如下：

```cpp
int sum = 0; 
for( int x = 1; x <= 10; x++ ) 
{ 
  sum += x; 
} 
cout << sum << endl; 
```

1.  打印从`6`到`30`的`6`的倍数的`for`循环的解决方案如下：

```cpp
for( int x = 6; x <= 30; x += 6 ) 
{ 
  cout << x << endl; 
} 
```

1.  打印从`2`到`100`的数字的`2`的倍数的`for`循环的解决方案如下：

```cpp
for( int x = 2; x <= 100; x += 2 ) 
{ 
  cout << x << endl; 
}
```

1.  打印从`1`到`16`的数字及其平方的`for`循环的解决方案如下：

```cpp
for( int x = 1; x <= 16; x++ ) 
{ 
  cout << x << " " << x*x << endl; 
} 
```

# 使用虚幻引擎进行循环

在您的代码编辑器中，从第三章打开您的虚幻`Puzzle`项目，*If, Else, and Switch*。

有几种方法可以打开您的虚幻项目。在 Windows 上，最简单的方法可能是导航到`Unreal Projects`文件夹（默认情况下位于用户的`Documents`文件夹中），然后在 Windows 资源管理器中双击`.sln`文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/4f035cee-9c4b-43d3-806e-b5ea1e5394fa.png)

在 Windows 中，打开`.sln`文件以编辑项目代码。您也可以直接打开 Visual Studio，它会记住您最近使用过的项目，并显示它们，这样您就可以从中点击打开。您还需要从 Epic Games Launcher 中打开 Unreal Editor 中的项目进行测试。

现在，打开`PuzzleBlockGrid.cpp`文件。在这个文件中，向下滚动到以下语句开头的部分：

```cpp
void APuzzleBlockGrid::BeginPlay() 
```

请注意，这里有一个`for`循环来生成最初的九个方块，如下面的代码所示：

```cpp
// Loop to spawn each block 
for( int32 BlockIndex=0; BlockIndex < NumBlocks; BlockIndex++ ) 
{ 
  // ... 
} 
```

由于`NumBlocks`（用于确定何时停止循环）计算为`Size*Size`，我们可以通过改变`Size`变量的值来轻松改变生成的方块数量。转到`PuzzleBlockGrid.cpp`的第 24 行，将`Size`变量的值更改为`4`或`5`。然后，再次运行代码（确保您在 Unreal Editor 中按下编译按钮以使用更新后的代码）。

您应该看到屏幕上的方块数量增加（尽管您可能需要滚动才能看到它们全部），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-bd-gm-ue4/img/9c230a33-a53b-4439-a60b-7f5fb96d89c2.png)

将大小设置为`14`会创建更多的方块。

# 摘要

在本章中，您学会了如何通过循环代码来重复执行代码行，从而使您可以多次运行它。这可以用于重复使用相同的代码行以完成任务。想象一下，如果不使用循环，打印从`1`到`10`（或 10,000！）的数字会是什么样子。

在下一章中，我们将探讨函数，这是可重复使用代码的基本单元。
