# 使用 C++、C# 和 Lua 的 CryENGINE 游戏编程（一）

> 原文：[`zh.annas-archive.org/md5/9DE4C1E310A0B5A13812B9CEED44823A`](https://zh.annas-archive.org/md5/9DE4C1E310A0B5A13812B9CEED44823A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

开发和维护游戏的过程在过去几年中发生了非常快速的变化。越来越普遍的是游戏开发者许可第三方游戏引擎，如 CryENGINE，以便完全专注于游戏本身。

作为第一个以纯**所见即所得**（**WYSIWYP**）理念出货的游戏引擎，CryENGINE 专注于通过允许开发人员直接进入他们的游戏，预览变化并且不等待级别和资产构建来提高生产力和迭代。

对于程序员来说，CryENGINE 是理想的工具集。可以使用慷慨的 API 在 C++中进行开发，使开发人员可以直接进入代码并编写性能优越的代码，而不受限于晦涩的脚本语言。有了想法？启动 Visual Studio，立即开始工作。

# 本书涵盖的内容

第一章，“介绍和设置”，涵盖了通过简要概述引擎，详细介绍其优势，提供的可能性，并逐步指南设置您的环境来加快速度的过程。

第二章，“使用 Flowgraph 进行可视化脚本编程”，向您介绍了可视化脚本工具，以便以一种易于访问的视觉方式创建游戏逻辑。

第三章，“创建和利用自定义实体”，涵盖了实体系统以及如何利用它来为您带来好处。用从简单的物理化对象到复杂的天气模拟管理器的实体填充您的游戏世界。

第四章，“游戏规则”，为您提供了对游戏规则系统的深入了解，为您提供了一个统一的模板，用于全面的游戏和会话逻辑。它还教授如何在各种语言中实现自定义游戏模式。

第五章，“创建自定义角色”，详细介绍了为玩家控制的实体和人工智能的基础创建自定义角色类的过程。

第六章，“人工智能”，涵盖了使用内置人工智能解决方案创建一个生动而有活力的世界的过程。

第七章，“用户界面”，详细介绍了使用 Flash 和 Autodesk Scaleform 来为您的界面增添色彩，从简单的屏幕位图到在游戏世界中呈现交互式 Flash 元素。

第八章，“多人游戏和网络”，涵盖了将引擎在线化的工作，并学习如何在网络上同步游戏世界的背后工作。

第九章，“物理编程”，涵盖了物理系统的内部工作原理，以及为从最大的车辆到最小的粒子效果的一切物理相互作用的创建过程。

第十章，“渲染编程”，帮助您了解渲染系统的工作原理，以及如何使用它来创建和扩展从渲染节点到多个视口的一切。

第十一章，“效果和声音”，详细介绍了 CryENGINE 使用的 FMod 声音引擎的工作原理，使您能够为您的项目实现令人信服的声音。

第十二章，“调试和性能分析”，涵盖了调试游戏的常见方法，以及使用控制台的基础知识。

# 您需要为本书做好的准备

+   CryENGINE 3 免费 SDK v3.5.4

+   CryMono v0.7 for CryENGINE 3.5.4

+   Visual Studio Express 2012

+   Notepad++

+   FMod

# 本书的受众

这本书是为具有基本 CryENGINE 和其编辑器使用知识的开发人员编写的，在某些情况下，会假设读者了解非常基本的功能，比如在编辑器中加载关卡和放置实体。如果您以前从未使用过 CryENGINE，我们建议您自己玩一下 CryENGINE Free SDK，或者购买 Sean Tracy 和 Paul Reindell 的《CryENGINE 3 游戏开发：初学者指南》。

# 约定

在这本书中，您将找到许多不同类型信息的文本样式。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码单词显示如下："`GFx`元素确定应加载哪个 Flash 文件用于该元素。"

代码块设置如下：

```cs
<events>
  <event name="OnBigButton" fscommand="onBigButton" desc="Triggered when a big button is pressed">    
    <param name="id" desc="Id of the button" type="string" />
  </event>
</events>
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这种形式出现在文本中："一旦启动，UI 图将被激活，假设它包含一个**UI:Action:Start**节点，如下所示："

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种形式出现。


# 第一章：介绍和设置

CryENGINE 因其展示各种令人印象深刻的视觉效果和游戏玩法而被认为是最具可扩展性的引擎之一。这使得它成为程序员手中的无价工具，唯一的限制就是创造力。

在本章中，我们将涵盖以下主题：

+   安装**Visual Studio Express 2012 for Windows Desktop**

+   下载 CryENGINE 示例安装或使用自定义引擎安装

+   在[`www.crydev.net`](http://www.crydev.net)注册账户，这是官方的 CryENGINE 开发门户网站

+   编译精简的 CryGame 库

+   附加和使用调试器

# 安装 Visual Studio Express 2012

为了编译游戏代码，您需要一份 Visual Studio 的副本。在本演示中，我们将使用 Visual Studio Express 2012 for Windows Desktop。

### 注意

如果您已经安装了 Visual Studio 2012，则可以跳过此步骤。

![安装 Visual Studio Express 2012](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_01_01.jpg)

要安装 Visual Studio，请按照以下步骤操作：

1.  访问[`www.microsoft.com/visualstudio/`](http://www.microsoft.com/visualstudio/)，然后下载 Visual Studio Express 2012 for Windows Desktop。

1.  下载可执行文件后，安装该应用程序，并在重新启动计算机后继续下一步。

# 选择 CryENGINE 安装类型

现在我们已经安装了 Visual Studio，我们需要下载一个 CryENGINE 版本进行开发。

我们为本书创建了一个精简的示例安装，推荐给刚开始使用引擎的用户。要下载，请参阅*下载本书的 CryENGINE 示例安装*部分。

如果您更愿意使用 CryENGINE 的其他版本，比如最新的 Free SDK 版本，请参阅本章后面的*使用自定义或更新的 CryENGINE 安装*部分。本节将介绍如何自行集成 CryMono。

# 下载本书的 CryENGINE 示例安装

对于本书，我们将使用自定义的 CryENGINE 示例作为学习引擎工作原理的基础。本书中的大多数练习都依赖于这个示例；然而，您从中获得的工作知识可以应用于默认的 CryENGINE Free SDK（可在[`www.crydev.net`](http://www.crydev.net)上获得）。

要下载示例安装，请按照以下步骤操作：

1.  访问[`github.com/inkdev/CryENGINE-Game-Programming-Sample`](https://github.com/inkdev/CryENGINE-Game-Programming-Sample)，然后单击**Download ZIP**按钮，以下载包含示例的压缩存档。

1.  下载完成后，将存档内容提取到您选择的文件夹中。为了示例，我们将其提取到`C:\Crytek\CryENGINE-Programming-Sample`。

## 刚才发生了什么？

现在您应该有我们示例 CryENGINE 安装的副本。您现在可以运行和查看示例内容，这将是本书大部分内容的使用内容。

# 使用自定义或更新的 CryENGINE 安装

本节帮助选择使用自定义或更新版本的引擎的读者。如果您对此过程不确定，我们建议阅读本章中的*下载本书的 CryENGINE 示例安装*部分。

## 验证构建是否可用

在开始之前，您应该验证您的 CryENGINE 版本是否可用，以便您可以在本书的章节中运行和创建基于代码。

### 注意

请注意，如果您使用的是旧版或新版引擎，某些章节可能提供了更改系统的示例和信息。请记住这一点，并参考前面提到的示例，以获得最佳的学习体验。

一个检查的好方法是启动编辑器和启动器应用程序，并检查引擎是否按预期运行。

## 集成 CryMono（C#支持）

如果您有兴趣使用以 C#为主题编写的示例代码和章节内容，您需要将第三方 CryMono 插件集成到 CryENGINE 安装中。

### 注意

请注意，CryMono 默认集成在我们专门为本书创建的示例中。

要开始集成 CryMono，请打开引擎根文件夹中的`Code`文件夹。我们将把源文件放在这里，放在一个名为`CryMono/`的子文件夹中。

要下载源代码，请访问[`github.com/inkdev/CryMono`](https://github.com/inkdev/CryMono)并单击**Download Zip**（或者如果您更喜欢使用 Git 版本控制客户端，则单击**Clone in Desktop**）。

下载后，将内容复制到我们之前提到的`Code/CryMono`文件夹中。如果该文件夹不存在，请先创建它。

文件成功移动后，您的文件夹结构应该类似于这样：

![集成 CryMono（C#支持）](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_01_Folder_Structure.jpg)

### 编译 CryMono 项目

现在我们有了 CryMono 源代码，我们需要编译它。

首先，使用 Visual Studio 打开`Code/CryMono/Solutions/CryMono.sln`。

### 注意

确保使用`CryMono.sln`而不是`CryMono Full.sln`。后者仅在需要重新构建整个 Mono 运行时时使用，该运行时已经与 CryMono 存储库预编译。

在编译之前，我们需要修改引擎的`SSystemGlobalEnvironment`结构（这是使用全局`gEnv`指针公开的）。

为此，请在`Code/CryEngine/CryCommon/`文件夹中打开`ISystem.h`。通过搜索结构`SSystemGlobalEnvironment`的定义来找到结构的定义。

然后将以下代码添加到结构的成员和函数的最后：

```cs
struct IMonoScriptSystem*
  pMonoScriptSystem;
```

### 注意

不建议修改接口，如果您没有完整的引擎源代码，因为其他引擎模块是使用默认接口编译的。但是，在这个结构的末尾添加是相对无害的。

完成后，打开您打开`CryMono.sln`的 Visual Studio 实例并开始编译。

### 注意

项目中的自动化后构建步骤应在成功编译后自动将编译文件移动到构建的`Bin32`文件夹中。

要验证 CryMono 是否成功编译，请在您的`Bin32`文件夹中搜索`CryMono.dll`。

### 通过 CryGame.dll 库加载和初始化 CryMono

现在我们在我们的`Bin32`文件夹中有了 CryMono 二进制文件，我们只需要在游戏启动时加载它。这是通过 CryGame 项目，通过`CGameStartup`类来完成的。

首先，打开位于`Code/Solutions/`中的`Code/Solutions/`中的 CryEngine 或 CryGame 解决方案文件（.`sln`）。

#### 包括 CryMono 接口文件夹

在修改游戏启动代码之前，我们需要告诉编译器在哪里找到 CryMono 接口。

首先，在 Visual Studio 的**Solution Explorer**中右键单击 CryGame 项目，然后选择**Properties**。这将显示以下**CryGame Property Pages**窗口：

![包括 CryMono 接口文件夹](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_01_02.jpg)

现在，点击**C/C++**并选择**General**。这将显示一屏幕一般的编译器设置，我们将使用它来添加一个额外的包含文件夹，如下面的屏幕截图所示：

![包括 CryMono 接口文件夹](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_01_03.jpg)

现在我们只需要将`..\..\CryMono\MonoDll\Headers`添加到**Additional Include Directories**菜单中。这将告诉编译器在使用`#include`宏时搜索 CryMono 的`Headers`文件夹，从而使我们能够找到 CryMono 的 C++接口。

#### 在启动时初始化 CryMono

在 CryGame 项目中打开`GameStartup.h`，并将以下内容添加到类声明的底部：

```cs
static HMODULE
m_cryMonoDll;
```

然后打开`GameStartup.cpp`并在`CGameStartup`构造函数之前添加以下内容：

```cs
HMODULE CGameStartup::m_cryMonoDll = 0;
```

现在导航到`CGameStartup`析构函数并添加以下代码：

```cs
if(m_cryMonoDll)
{
  CryFreeLibrary(m_cryMonoDll);
  m_cryMonoDll = 0;
}
```

现在导航到`CGameStartup::Init`函数声明，并在`REGISTER_COMMAND("g_loadMod", RequestLoadMod,VF_NULL,"");`片段之前添加以下内容：

```cs
m_cryMonoDll = CryLoadLibrary("CryMono.dll");
if(!m_cryMonoDll)
{
  CryFatalError("Could not locate CryMono DLL! %i", GetLastError());
  return false;
}

auto InitMonoFunc = (IMonoScriptSystem::TEntryFunction)CryGetProcAddress(m_cryMonoDll, "InitCryMono");
if(!InitMonoFunc)
{
  CryFatalError("Specified CryMono DLL is not valid!");
  return false;
}

InitMonoFunc(gEnv->pSystem, m_pFramework);
```

现在我们只需编译 CryGame，就可以在启动时加载和初始化 CryMono。

#### 注册流节点

由于流系统的最近更改，流节点必须在游戏启动的某个时刻注册。为了确保我们的 C#节点已注册，我们需要从`IGame::RegisterGameFlowNodes`中调用`IMonoScriptSysetm::RegisterFlownodes`。

要做到这一点，打开`Game.cpp`并在`CGame::RegisterGameFlowNodes`函数内添加以下内容：

```cs
GetMonoScriptSystem()->RegisterFlownodes();
```

现在，在编译后，所有托管流节点应该出现在 Flowgraph 编辑器中。

# 注册您的 CryDev 帐户

CryENGINE 免费 SDK 需要 CryDev 帐户才能启动应用程序。这可以通过[`www.crydev.net`](http://www.crydev.net)轻松获取，方法如下：

1.  在您选择的浏览器中访问[`www.crydev.net`](http://www.crydev.net)。

1.  单击右上角的**注册**。

1.  阅读并接受使用条款。

1.  选择您的用户名数据。

## 刚刚发生了什么？

您现在拥有自己的 CryDev 用户帐户。在运行 CryENGINE 免费 SDK 应用程序（参见*运行示例应用程序*）时，您将被提示使用刚刚注册的详细信息登录。

# 运行示例应用程序

在开始构建游戏项目之前，我们将介绍默认 CryENGINE 应用程序的基础知识。

### 注意

所有可执行文件都包含在`Bin32`或`Bin64`文件夹中，具体取决于构建架构。但是，我们的示例只包括一个`Bin32`文件夹，以保持简单和构建存储库的大小。

## 编辑器

这是开发人员将使用的主要应用程序。编辑器作为引擎的直接接口，用于各种开发人员特定的任务，如关卡设计和角色设置。

编辑器支持**WYSIWYP**（**所见即所得**）功能，允许开发人员通过按下快捷键*Ctrl* + *G*或导航到**游戏**菜单，并选择**切换到游戏**来预览游戏。

### 启动编辑器

打开主示例文件夹，并导航到`Bin32`文件夹。一旦到达那里，启动`Editor.exe`。

![启动编辑器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_01_04.jpg)

编辑器加载完成后，您将看到 Sandbox 界面，可用于创建游戏的大多数视觉方面（不包括模型和纹理）。

要创建新关卡，打开**文件**菜单，并选择**新建**选项。这应该呈现给您**新建关卡**消息框。只需指定您的关卡名称，然后单击**确定**，编辑器将创建并加载您的空关卡。

要加载现有关卡，打开**文件**菜单，并选择**打开**选项。这将呈现给您**打开关卡**消息框。选择您的关卡并单击**打开**以加载您的关卡。

## 启动器

这是最终用户看到的应用程序。启动器启动时显示游戏的主菜单，以及允许用户加载关卡和配置游戏的不同选项。

启动器的游戏上下文通常称为**纯游戏模式**。

### 启动启动器

打开主示例文件夹，并进入`Bin32`文件夹。一旦到达那里，启动`Launcher.exe`。

![启动启动器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_01_05.jpg)

当您启动应用程序时，您将看到默认的主菜单。此界面允许用户加载关卡并更改游戏设置，如视觉和控制。

当您想要像最终用户一样玩游戏时，启动器比编辑器更可取。另一个好处是快速启动时间。

## 专用服务器

专用服务器用于启动其他客户端连接的多人游戏服务器。专用服务器不会初始化渲染器，而是作为控制台应用程序运行。

![专用服务器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_01_06.jpg)

# 编译 CryGame 项目（C++）

CryENGINE Free SDK 提供了对游戏逻辑库`CryGame.dll`的完整源代码访问。这个动态库负责游戏功能的主要部分，以及初始游戏启动过程。

### 注意

库是一组现有的类和函数，可以集成到其他项目中。在 Windows 中，库的最常见形式是**动态链接库**，或**DLL**，它使用`.dll`文件扩展名。

首先，打开主样本文件夹，并导航到`Code/Solutions/`，其中应该存在一个名为`CE Game Programming Sample.sln`的 Visual Studio 解决方案文件。双击该文件，Visual Studio 应该启动，并显示包含的项目（请参阅以下分解）。

### 注意

**解决方案**是 Visual Studio 中组织项目的结构。**解决方案**包含关于项目的信息，存储在基于文本的`.sln`文件中，以及一个`.suo`文件（用户特定选项）。

要构建项目，只需按下*F7*或右键单击**解决方案资源管理器**中的 CryGame 项目，然后选择**构建**。

## 刚刚发生了什么？

您刚刚编译了`CryGame.dll`，现在应该在二进制文件夹中存在（32 位编译为`Bin32`，64 位为`Bin64`）。启动示例应用程序现在将加载包含您编译的源代码的`.dll`文件。

## CE 游戏编程示例解决方案分解

解决方案包括以下三个项目，其中一个编译为`.dll`文件。

### CryGame

CryGame 项目包括引擎使用的基础游戏逻辑。这将编译为`CryGame.dll`。

### CryAction

CryAction 项目包括对`CryAction.dll`的部分源代码，它负责大量的系统，如演员、UI 图形和游戏对象。这个项目不会编译为`.dll`文件，而是仅用于接口访问。

### CryCommon

CryCommon 项目是一个助手，包含所有共享的 CryENGINE 接口。如果有子系统需要访问，请在这里查找其公开的接口。

# CryENGINE 文件夹结构

请参阅以下表格，了解 CryENGINE 文件夹结构的解释：

| 文件夹名称 | 描述 |
| --- | --- |
| `Bin32` | 包含引擎使用的所有 32 位可执行文件和库。 |
| `Bin64` | 包含引擎使用的所有 64 位可执行文件和库。 |
| `Editor` | 编辑器配置文件夹，包含常见的编辑器助手、样式等。 |
| `Engine` | 用作引擎本身使用的资产的中央文件夹，而不是任何特定的游戏。着色器和配置文件存储在这里。 |
| `Game` | 每个游戏都包含一个游戏文件夹，其中包括所有的资产、脚本、关卡等。不一定要命名为`Game`，但取决于`sys_game_folder`控制台变量的值。 |
| `Localization` | 包含本地化资产，如每种语言的本地化声音和文本。 |

## PAK 文件

引擎附带**CryPak**模块，允许以压缩或未压缩的存档中存储游戏内容文件。存档使用`.pak`文件扩展名。

当游戏内容被请求时，CryPak 系统将查询所有找到的`.pak`文件，以找到文件。

### 文件查询优先级

PAK 系统优先考虑松散文件夹结构中找到的文件，而不是 PAK 中的文件，除非引擎是在发布模式下编译的。在这种情况下，PAK 系统中存储的文件优先于松散的文件。

如果文件存在于多个`.pak`存档中，则使用具有最近文件系统创建日期的存档。

### 附加调试器

Visual Studio 允许您将**调试器**附加到应用程序。这使您可以使用**断点**等功能，让您在 C++源代码中的特定行停止，并逐步执行程序。

要开始调试，请打开`CE Game Programming Sample.sln`并按下*F5*，或者单击 Visual Studio 工具栏上的绿色播放图标。如果出现**找不到 Editor.exe 的调试符号**消息框，只需单击**确定**。

## 刚刚发生了什么？

CryENGINE Sandbox 编辑器现在应该已经启动，并且已连接了 Visual Studio 调试器。我们现在可以在代码中设置断点，并且当执行特定行的代码时，程序执行会暂停。

# 总结

在本章中，我们已经下载并学习了如何使用 CryENGINE 安装。您现在应该了解了编译和调试 CryGame 项目的过程。

我们现在已经掌握了继续学习 CryENGINE 编程 API 的基本知识。

如果您想了解更多关于 CryENGINE 本身的知识，除了编程知识之外，可以随时启动 Sandbox 编辑器并尝试使用级别设计工具。这将帮助您为将来的章节做好准备，在那里您将需要利用编辑器视口等工具。


# 第二章：使用 Flowgraph 进行可视脚本编写

CryENGINE flowgraph 是一个强大的基于节点的可视脚本系统，帮助开发人员快速原型化功能，并创建特定于关卡的逻辑，而无需处理复杂的代码库。

在本章中，我们将：

+   讨论 flowgraph 的概念

+   创建新的 flowgraph

+   调试我们的 flowgraph

+   在 Lua、C#和 C++中创建自定义 flowgraph 节点（flownode）

# flowgraph 的概念

多年来，编写代码一直是创建游戏行为和逻辑的主要方法，如果不是唯一的方法。让我们以一个关卡设计师为例，为最新的游戏创建一个战斗部分。

传统上，设计师必须要求程序员为这种情况创建逻辑。这有几个问题：

+   这会导致设计和实现之间的脱节

+   程序员被迫花费时间，这实际上是设计师的工作

+   设计师无法立即了解他/她的部分如何进行

这是 CryENGINE 的**flowgraph**，通常称为**FG**，解决的问题。它提供了一组 flownode，最好将其视为方便的逻辑乐高积木，设计师可以利用它们来拼凑整个场景。不再需要向游戏代码团队发送请求；设计师可以立即实现他们的想法！我们将稍后更详细地讨论创建节点本身，但现在让我们看一些简单的 flowgraph，这样您就可以迈出 CryENGINE 游戏逻辑的第一步！

# 打开 Flowgraph 编辑器

要开始，我们需要打开 Sandbox。Sandbox 包含 Flowgraph 编辑器作为其众多有用工具之一，可以通过**视图**|**打开视图窗格**来打开它。

### 注意

在打开 Flowgraph 编辑器时，您应该始终加载一个关卡，因为 flowgraph 是与关卡相关的。如果您忘记了如何创建新关卡，请返回到第一章*介绍和设置*！

![打开 Flowgraph 编辑器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_01.jpg)

您刚刚访问了您的第一个 Sandbox 工具！您应该会看到一个新窗口，其中有许多子部分和功能，但不要担心，让我们逐个解决它们。

# Flowgraph 编辑器之旅

flowgraph 被保存在磁盘上作为 XML 文件，但可以被 Flowgraph 编辑器解析和编辑，以提供创建游戏逻辑过程的可视界面。

![Flowgraph 编辑器之旅](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_02.jpg)

## 组件

编辑器的这一部分包含项目中的所有 flownode，组织成整洁的类别。让我们快速查看一下这个，打开**Misc**文件夹。您应该会看到一组节点，分配到不同的类别：

![组件](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_03.jpg)

### 术语

+   **图**：这指的是包含一组相互链接的节点的上下文。

+   **节点**：这是一个类的可视表示，它可以从其输入端口接收数据和事件，也可以通过其输出端口发送数据。它连接到图中的其他节点以创建逻辑。

+   **端口**：这是一个函数的可视表示。节点可以指定多个输入和输出端口，然后可以从中发送或接收事件。

### 组件类别

您可能会错过这里标记为**调试**的节点；CryENGINE 为节点分配类别，以指示它们适合在哪里使用。

+   **发布**：此节点适用于生产

+   **高级**：虽然此节点适用于生产，但在某些情况下可能具有复杂的行为

+   **调试**：此节点只应用于内部测试

+   **过时**：不应使用此节点，此节点将不会在组件列表中可见

例如，在制作一个打算发布给公众的关卡时，您可能不希望意外包含任何调试节点！我们可以通过**视图**|**组件**来启用或禁用 Flowgraph 编辑器中的前三个类别的查看：

![组件类别](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_04.jpg)

## 流程图类型

在创建新的流程图之前，我们需要知道我们的目的最相关的类型是什么。不同的流程图类型允许专门化，例如，创建处理玩家用户界面的**UI 图形**。

![流程图类型](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_05.jpg)

### AI 操作

这些是您可以创建的流程图，将 AI 行为封装成方便的节点，可以在其他地方重复使用。当您学习**人工智能**（**AI**）时，我们稍后会讨论这些。

### UI 操作

CryENGINE 允许您使用流程图脚本化用户界面和游戏中的抬头显示，通过 UI 事件系统。我们将在第七章中讨论这些，*用户界面*。

### 材质 FX

CryENGINE 支持方便的可设计的流程图，用于控制如何处理材质事件，例如，在附近射击地面时生成一个灰尘粒子并用一层灰尘遮挡玩家的屏幕。

### FG 模块

您可以将流程图打包成方便的模块，以便在不同情况下重复使用。我们稍后会详细描述这些。

### 实体

这是我们在本章中将花费大部分时间的地方！90%的时间，流程图都分配给一个实体，也就是**图实体**，这个逻辑发生在游戏世界中。

### 预制件

CryENGINE 支持预制件，这是一组实体打包成一个方便的文件以供重复使用。预制件中的任何实体流程图都将显示在此文件夹中。

# 创建流程图

现在我们对流程图编辑器的工作原理有了基本的了解，让我们立即开始创建我们的第一个流程图！您可以暂时关闭流程图编辑器。

## 流程图实体

流程图实体是一个极其轻量级的 CryENGINE 对象，设计用于在您需要一个不应用于任何特定实体的流程图时使用。与所有实体一样，它可以在 Sandbox 的**RollupBar**中找到。

### 注意

如果您不确定实体是什么，请跳过本节，直到您阅读完第三章为止，*创建和使用自定义实体*。

![流程图实体](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_06.jpg)

### 生成 FlowgraphEntity

选择**流程图实体**，然后双击并再次单击视口，或单击并将其拖动到级别中。您现在应该在**RollupBar**中看到一整套新选项，包括实体参数、材质层，但对我们来说最重要的是**实体：流程图实体**部分。

## 附加一个新的流程图

在**实体：流程图实体**部分，我们需要找到**流程图**子部分，然后单击**创建**按钮：

![附加新的流程图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_07.jpg)

从这里，您将有选择将您的流程图分配给一个组。现在是否这样做并不重要，但在处理较大项目时，将相关图形分组在一起是很有用的。

### 注意

组用于为流程图创建结构，允许开发人员将不同的图形分类到文件夹中。

完成后，您应该看到流程图编辑器出现在背景上叠加了淡淡的网格。我们现在准备开始创建逻辑！

## 将节点添加到流程图中

将节点添加到新图形的最简单方法是浏览**组件**列表并拖动新节点。但是，如果您知道要添加的节点的名称，这并不是很有效。因此，您还可以在流程图编辑器中使用*Q*快捷键来调出搜索功能，然后只需输入要添加的节点的名称。

在我们的情况下，我们将从**Misc:Start**节点开始，这是一个简单的节点，用于在加载级别时或编辑器测试会话启动时触发其他事件：

![将节点添加到流程图中](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_08.jpg)

## 输入和输出端口

放置节点后，您应该看到节点输入和输出端口的第一个示例。在这种情况下，我们有两个输入值**InGame**和**InEditor**，以及一个单一的输出端口，在这种情况下方便地命名为**output**：

![输入和输出端口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_09.jpg)

输入端口用于向节点提供数据或触发事件，输出端口用于将数据和事件传递给图中的其他节点。在这个例子中，**Misc:Start**节点可以被编辑以定义它将在哪些游戏上下文中实际执行。也许您有一些调试逻辑只想在编辑器中运行，这种情况下我们可以将**InGame**设置为 false 或零。

### 端口类型

为了指定端口将处理什么类型的数据，我们需要知道它的端口类型。我们可以通过查看端口的颜色在 Flowgraph 编辑器中确定端口的类型。

以下是可用端口类型的列表：

+   **Void**：用于不传递特定值的端口，但激活以发出事件信号

+   **Int**：当端口应该只接收整数值时使用

+   **Float**：用于指示端口处理浮点值

+   **EntityId**：这表示端口期望一个实体标识符。（有关实体 ID 的更多信息，请参阅第三章，“创建和利用自定义实体”）

+   **Vec3**：用于处理三维向量的端口

+   **String**：在这种情况下，端口期望一个字符串

+   **Bool**：当端口期望真或假的布尔值时使用

### 注意

链接具有不同类型的端口将自动转换值。

## 目标实体

流节点可以具有目标实体，允许用户将当前级别中的实体链接到流节点。这对于旨在影响游戏世界中的实体的节点非常有用，例如**Entity:GetPos**节点，如下面的截图所示，获取指定实体的世界变换。

### 注意

我们还可以通过将**EntityId**输出端口链接到**Choose Entity**端口来动态指定实体。

![目标实体](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_10.jpg)

有两种分配实体给支持它的节点的方法：

+   通过将另一个流节点的**EntityId**输出链接到**Choose Entity**输入

+   通过右键单击**Choose Entity**输入并选择：

+   **分配选定的实体**：这将链接节点到编辑器视口中当前选定的实体

+   **分配图形实体**：这将链接节点到分配给该图形的实体

## 链接流节点

单个流节点并不能做太多事情；让我们连接两个，并构建一个适当的图！为了演示目的，我们将使用**Time:TimeOfDay**节点：

![链接流节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_11.jpg)

要创建端口之间的链接，只需单击输出端口，按住鼠标按钮拖动光标到输入端口，然后释放鼠标，连接就会创建！

我们还编辑了**Time**输入端口的值；输入端口可以通过输出端口提供数据，也可以直接在编辑器中编辑它们的值。只需单击节点，查看 Flowgraph 编辑器的**Inputs**部分。从那里，您可以简单地编辑这些值：

![链接流节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_12.jpg)

您还可以查看有关节点的有价值的信息：例如，在这里我们可以看到这个节点用于设置白天的时间，以及游戏中时间流逝的速度。

完成这一步后，您可以暂时关闭 Flowgraph 编辑器。Flowgraphs 不需要手动保存；它们会自动保存在关卡中。

### 注意

尽管流图与关卡一起保存，但最好经常手动保存，以避免丢失工作。

## 测试我们的流图

正如我们在上一章中学到的，使用 Sandbox 在 CryENGINE 中测试逻辑非常简单。只需按下*Ctrl* + *G*快捷键组合，然后观察您进入游戏模式。现在，当您这样做时，您应该看到级别的照明和一般氛围发生变化，因为您刚刚改变了白天的时间！

恭喜，您刚刚迈出了使用 CryENGINE 创建游戏的第一步！现在看起来可能不是很多，但让我们让这个图表做更多事情。

# 存储的 flownode 概述

为了做一些更复杂的事情，我们需要了解 CryENGINE 默认提供的节点。

## 构建时钟

我们可以访问的最有用的节点之一，至少用于调试目的，是**HUD:DisplayDebugMessage**节点。它允许您在游戏窗口中显示信息，可选地带有超时。考虑到这一点，让我们基于我们之前学到的时间信息构建一个小的调试时钟。

**Time:TimeOfDay**节点以 CryENGINE 时间格式输出当前时间，该格式定义为小时加上分钟除以 60。例如，下午 1:30 会在 CryENGINE 时间中表示为 13.5。我们现在知道我们将需要一些数学运算，所以是时候检查 Math flownode 类别了。

我们要做的第一件事是通过将当前时间向下取整来获取小时数。为此，将**Math:Floor**放置在**Time:TimeOfDay**节点的**CurTime**输出上，然后将其连接到 Floor 的**A**输入端口。然后，将其馈送到 Debug Message 节点：

![构建时钟](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_13.jpg)

现在立即进入游戏，您应该在屏幕上看到当前的小时数。

然后我们需要从原始值中减去我们的新值以获得分钟部分。为此，我们需要**Math:Sub**来从原始**CurTime**值中减去四舍五入的小时数。之后，**Math:Mul**节点将新时间放大 60 倍，因此您的图应该如下所示：

![构建时钟](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_14.jpg)

记得将第二个 Debug 节点的**posY**设置为向下移动，这样您就可以同时看到两者。

如果您再次进入游戏，现在应该看到当前的小时和分钟被打印出来！

## 监听玩家输入

如果现在我们想要允许玩家测试不同时间的移动怎么办？一般来说，设置一个按键监听器是最简单的方法，在这里我们在按下某个键时触发一个事件。幸运的是，CryENGINE 将这个功能封装得很好，放入了一个单一的节点**Input:Key**。

现在让我们设置按下*P*键会使时间快速移动，按下*O*键会再次停止时间。

### 注意

**Input:Key**节点是一个调试节点。通常认为在生产中使用调试节点是一个不好的做法，因为可能会出现意外的结果，所以请不要将此节点用于实际游戏逻辑。

我们需要设置**Time:TimeOfDay**节点的**Speed**值，但在这种情况下，我们还需要输入两个值！CryENGINE 提供了一个名为**Logic:Any**的节点，它具有多个输入端口，并且只是传递给它的任何数据，我们可以在这里使用它来接收两个输入值。我们使用两个调用**Math:SetNumber**节点的关键节点，然后**Logic:Any**节点将这些信息传递给我们的**Time:TimeOfDay**节点，并调用**SetSpeed**：

![监听玩家输入](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_15.jpg)

现在进入游戏，按*P*键开始一天的运行！再次按*O*键，白天的时间应该会停止。

## 在循环中执行

您可能已经注意到我们的时钟不再正确更新。这是因为大多数节点不会输出数据，除非触发；在这种情况下，如果我们不触发**GetTime**或**SetTime**，我们将得不到任何输出。我们有两种调用的选择：我们可以使用**Time:Time**每帧执行它，或者**Time:Timer**。

后者可以控制 tick 的粒度，但在这种情况下，我们可能希望在快速移动时每帧更新，所以让我们保持简单。将**tick**输出连接到我们的**GetTime**输入，我们的时钟应该再次正确更新！

![在循环中执行](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_16.jpg)

# 流程图模块

流程图模块系统允许将流程图导出为可以从另一个图中触发的模块。

通过创建模块，我们可以在多个级别中重用逻辑，而无需维护相同图的多个版本。还可以以非常模块化的方式发送和接收模块的唯一数据，实现动态逻辑。

## 创建模块

要开始创建自己的模块，打开流程图编辑器，选择**文件** | **新建 FG 模块...** | **全局**：

![创建模块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_17.jpg)

在结果的**保存**对话框中，使用您选择的名称保存模块。然后，您将看到模块的默认视图：

![创建模块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_18.jpg)

该模块默认包含两个节点；**Module:Start_MyModule**和**Module:End_MyModule**。

+   **Module:Start_MyModule**包含三个输出端口：

+   **开始**：当模块加载时调用

+   **更新**：当模块应更新时调用

+   **取消**：当模块应取消时调用，它默认连接到**Module:End_MyModule**的**取消**输入

+   **Module:End_MyModule**包含两个输入端口：

+   **成功**：当完成模块时应调用此函数，并将“成功”状态传递给调用者

+   **取消**：用于提前结束模块，并将“取消”状态传递给调用者

最后，要填充您的模块逻辑，只需将**Start**输出端口连接到您的逻辑节点。

## 调用模块

要调用现有模块，请在模块节点类别中找到相关节点。调用节点的名称为`Module:Call_<ModuleName>`：

![调用模块](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_19.jpg)

然后简单地触发**Call**端口以激活您的模块，**Cancel**以中止它。

## 模块参数/端口

根据我们之前学到的知识，我们能够使用 void 端口调用模块。这在所有情况下都不是最佳选择，因为您可能希望向模块传递附加数据。

为了实现这一点，模块系统公开了模块参数。通过在流程图编辑器中选择**工具** | **编辑模块...**，我们可以为我们的模块添加一组参数：

![模块参数/端口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_20.jpg)

此操作将打开**模块端口**窗口，允许我们添加和删除端口：

![模块参数/端口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_21.jpg)

通过选择**新输入**或**新输出**，我们将能够添加新的端口，可以在激活模块时使用。

![模块参数/端口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_22.jpg)

添加新的输入或输出将自动输出其**Module:Start_MyModule**或**Module:End_MyModule**节点，允许您接收数据：

![模块参数/端口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_23.jpg)

所有**Module:Call_MyModule**节点也会自动更新，让您立即访问新参数：

![模块参数/端口](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_24.jpg)

# 自定义流节点

总之，CryENGINE 默认提供了许多有用的节点，涵盖了整个功能范围。然而，作为程序员，您经常会发现设计师会要求访问一些默认情况下流程图无法提供的隐藏功能。

例如，假设您正在创建一个角色扮演游戏，并且有一个经验系统。在您编写的代码中，有很多方法可以奖励玩家的经验，但级别设计师还希望能够在关卡的任意点使用这个功能。

在这种情况下，你可以很好地创建一个自定义流节点；你可以创建一个简化的代码中存在的系统的表示，也许允许设计师简单地指定在触发节点时奖励给玩家的经验点数。

不过，现在我们要看一些更简单的东西。假设我们没有现有的 CryENGINE 节点可供使用，我们想要实现我们之前看到的**Math:Mul**节点。简而言之，它只是一个在流程图中实现乘法的简单节点。

![自定义流节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_25.jpg)

# 在 C++中创建自定义节点

回到第一章, *介绍和设置*，我们首次编译和运行 GameDLL，这里打包为 Visual Studio 的`MiniMonoGameSample.sln`。让我们再次加载它，确保任何 CryENGINE 实例，比如启动器或沙盒，都已关闭，因为我们将要覆盖运行时使用的`CryGame.dll`文件。

## 组织节点

CryENGINE 游戏的标准做法是在 GameDLL 项目**CryGame**中有一个名为**Nodes**的过滤器。如果不存在，现在就创建它。

![组织节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_26.jpg)

## 创建一个新的节点文件

节点在项目的其他区域中从未被引用，所以可以简单地将节点实现为一个单独的`.cpp`文件，而不需要头文件。

在我们的情况下，让我们只添加一个新文件`TutorialNode.cpp`，并创建基本结构：

```cs
#include "stdafx.h"
#include "Nodes/G2FlowBaseNode.h"

  class CTutorialNode : public CFlowBaseNode<eNCT_Instanced>
  {

  };

  REGISTER_FLOW_NODE("Tutorial:Multiplier", CTutorialNode);
```

### 代码分解

首先，我们包含了`stdafx.h`；这提供了文件的常见功能和一些标准化的“包含”。这也是编译文件所需的。

之后，我们包含了第二个文件，`Nodes/G2FlowBaseNode.h`。虽然它不是严格意义上的 CryENGINE 组件，但这个文件在 CryENGINE 游戏中被广泛使用，将节点功能封装成一个易于访问的基类。

然后我们创建我们的实际类定义。我们从前面提到的基本节点继承，然后指定我们的节点是一个实例化节点；一般来说，你会在 CryENGINE 中使用实例化节点。

### 注意

CryENGINE 使用一些有限的匈牙利命名前缀，就像你在这里看到的那样。类是`CMyClass`，结构体变成`SMyData`，接口是`IMyInterface`。

对于字段，如`m_memberVariable`，通常使用`m_`前缀，对于指针变量，如`*pAnInstance`，通常使用`p`。

为了使节点注册更容易，CryENGINE 暴露了`REGISTER_FLOW_NODE`预处理宏。这个系统将在启动时自动处理节点的注册。

## 节点函数概述

对于我们正在创建的节点，我们不需要存储任何私有信息，所以只需使用 C++修饰符将所有节点信息公开为类内的第一行：

```cs
public:
```

然后我们开始实现两个函数，构造函数和`Clone`方法。我们在这两个函数中都不需要任何逻辑，所以实现非常简单；构造函数不初始化任何东西，`Clone`只是返回当前节点的一个新实例：

```cs
  CTutorialNode(SActivationInfo *pActInfo)
  {
  }

  virtual IFlowNodePtr Clone(SActivationInfo *pActInfo)
  {
    return new CTutorialNode(pActInfo);
  }
```

在这里，我们还第一次介绍了`SActivationInfo`。这个结构包含了关于节点当前状态的信息，以及它所包含的图表，我们稍后会在其他地方使用它。

现在，我们的节点至少需要三个额外的函数才能编译：

```cs
  virtual void ProcessEvent(EFlowEvent evt, SActivationInfo *pActInfo)
  {
  }

  virtual void GetConfiguration(SFlowNodeConfig &config)
  {
  }

  virtual void GetMemoryUsage(ICrySizer *s) const
  {
    s->Add(*this);
  }
```

`ProcessEvent`是我们将要做大部分节点逻辑的地方；当有有趣的事情发生在我们的节点上时，比如端口被触发，就会调用这个函数。`GetConfiguration`控制节点的显示方式，以及它包含的输入和输出端口。`GetMemoryUsage`不需要我们额外的实现，所以我们可以只是为内存使用跟踪添加对这个节点的引用。

现在，验证你的代码是否能编译是一个好的起点；如果不能，检查你是否正确声明了所有函数签名，并包含了头文件。

## 实现 GetConfiguration

如前所述，`GetConfiguration`是我们设置节点在 Flowgraph Editor 中如何使用的地方。首先，让我们设置`enum`来描述我们的输入端口；我们将使用两个值，左和右，以及一个激活端口来触发计算。在类内部声明：

```cs
  enum EInput
  {
    EIP_Activate,
    EIP_Left,
    EIP_Right
  };
```

当然，我们还需要一个用于计算的输出端口，因此让我们也创建一个单一值的`enum`。虽然不是必需的，但保持一致是一个好习惯，大多数节点将具有多个输出：

```cs
  enum EOutput
  {
    EOP_Result
  };
```

### 创建端口

有了这些声明，我们就可以开始构建我们的节点。端口被定义为`GetConfiguration`中声明的常量静态数组中的条目，并且使用一些辅助函数进行构造，即`InputPortConfig<T>`用于特定类型的值，以及`InputPortConfig_AnyType`用于允许所有值，以及`InputPortConfig_Void`用于不使用数据的端口。

考虑到这一点，我们知道除了两个浮点模板端口外，我们的触发输入还需要一个 void 输入。我们还需要一个浮点输出。

```cs
  virtual void GetConfiguration(SFlowNodeConfig &config)
  {
    static const SInputPortConfig inputs[] =
    {
      InputPortConfig_Void("Activate", "Triggers the calculation"),
      InputPortConfig<float>("Left", 0, "The left side of the calculation"),
      InputPortConfig<float>("Right", 0, "The right side of the calculation"),
      {0}
    };
  }
```

正如您所看到的，我们可以指定端口的名称、描述，以及对使用数据的端口设置默认值。它们应该与我们之前声明的枚举的顺序相匹配。

### 注意

更改已使用的节点的端口名称将破坏现有的图表。填写可选的`humanName`参数以更改显示名称。

现在我们重复该过程，只是使用输出函数集：

```cs
  static const SOutputPortConfig outputs[] =
  {
    OutputPortConfig<float>("Result", "The result of the calculation"),
    {0}
  };
```

### 将数组分配给节点配置

在创建端口的过程之后，我们需要将这些数组分配给我们的`config`参数，并提供描述和类别：

```cs
  config.pInputPorts = inputs;
  config.pOutputPorts = outputs;
  config.sDescription = _HELP("Multiplies two numbers");
  config.SetCategory(EFLN_APPROVED);
```

如果现在编译代码，节点应该完全显示在编辑器中。但是正如您将看到的那样，它还没有做任何事情；为了解决这个问题，我们必须实现`ProcessEvent`！

#### flownode 配置标志

`SFlowNodeConfig`结构允许您为 flownode 分配可选标志，如下所示列出：

+   `EFLN_TARGET_ENTITY`：这用于指示此节点应支持目标实体。要获取当前分配的目标实体，请查看`SActivationInfo::pEntity`。

+   `EFLN_HIDE_UI`：这将在 flowgraph UI 中隐藏节点。

+   `EFLN_UNREMOVEABLE`：这禁用了用户删除节点的功能。

要在`GetConfiguration`中添加一个标志，以支持目标实体，只需将标志添加到`nFlags`变量中：

```cs
  config.nFlags |= EFLN_TARGET_ENTITY;
```

## 实现 ProcessEvent

`ProcessEvent`是我们捕获节点的所有有趣事件的地方，例如触发端口。在我们的情况下，我们希望在触发我们的`Activate`端口时执行计算，因此我们需要检查端口的激活。不过，首先，我们可以通过检查我们想要处理的事件来节省一些处理时间。

```cs
  virtual void ProcessEvent(EFlowEvent evt, SActivationInfo *pActInfo)
  {
    switch (evt)
    {
      case eFE_Activate:
      {

      }
      break;
    }
  }
```

通常，您将处理多个事件，因此养成在此处使用`switch`语句的习惯是很好的。

在其中，让我们看一下我们用来检查激活、检索数据，然后触发输出的各种 flownode 函数：

```cs
  if (IsPortActive(pActInfo, EIP_Activate))
  {
    float left = GetPortFloat(pActInfo, EIP_Left);
    float right = GetPortFloat(pActInfo, EIP_Right);
    float answer = left * right;

    ActivateOutput(pActInfo, EOP_Result, answer);
  }
```

总之，我们在所有这些函数中使用我们的激活信息来表示当前状态。然后，我们可以使用`GetPort*`函数检索各种端口类型的值，然后触发带有数据的输出。

是时候加载编辑器并进行测试了；如果一切顺利，您应该能够在教程类别中看到您的节点。恭喜，您刚刚为 CryENGINE 编写了您的第一个 C++代码！

![实现 ProcessEvent](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_27.jpg)

# 在 C#中创建自定义节点

CryMono 还支持使用 C#开发人员熟悉的习惯用法来创建自定义节点，例如属性元编程。要开始使用 C# CryENGINE 脚本，请打开`Game/Scripts/CryGameCode.sln`中的示例脚本解决方案。在 flownodes 文件夹中添加一个新的`.cs`文件，然后我们将开始在 C#中创建相同的节点，以便您可以看到创建方式的不同。

首先，让我们创建一个基本的骨架节点。我们需要为我们的节点引入正确的命名空间，以及为我们的节点设置一些基本属性：

```cs
  using CryEngine.Flowgraph;

  namespace CryGameCode.FlowNodes
  {
    [FlowNode(Name = "Multiplier", Category = "CSharpTutorial", Filter = FlowNodeFilter.Approved)]
    public class TutorialNode : FlowNode
    {

    }
  }
```

与 C++一样，节点在项目中没有其他引用，因此我们为我们的节点分配了一个单独的命名空间，以防止它们污染主要命名空间。

我们使用`FlowNodeAttribute`类来设置节点的元数据，例如正确的类别和可见性级别，而不是使用`GetConfiguration`。您的节点必须包括此属性，并从`FlowNode`继承，以便被 CryENGINE 注册；不需要任何手动注册调用。

### 注意

请记住，属性可以放置在其名称的最后一个`Attribute`之外。例如，`FlowNodeAttribute`可以放置为`[FlowNodeAttribute]`和`[FlowNode]`。

## 添加输入

在 CryMono 中，输入被定义为函数，并且它们接受定义数据类型的单个参数，或者对于 void 端口，不接受参数。它们还需要用`Port`属性进行修饰。在我们的情况下，让我们设置与节点的 C++版本中相同的三个输入：

```cs
  [Port]
  public void Activate()
  {
  }

  [Port]
  public void Left(float value)
  {
  }

  [Port]
  public void Right(float value)
  {
  }
```

我们将在接下来的实现中回到`Activate`。虽然你可以通过在属性中设置可选参数来覆盖端口名称，但更容易的方法是让你的函数名称定义节点在编辑器中的显示方式。

## 添加输出

输出被存储为`OutputPort`或`OutputPort<T>`的实例，如果需要值。让我们现在将我们的`Result`输出作为类的属性添加进去：

```cs
  public OutputPort<float> Result { get; set; }
```

## 实现激活

让我们回到我们的`Activate`输入；同样，我们需要检索我们的两个值，然后触发一个输出。`FlowNode`类有方便的函数来实现这些：

```cs
  var left = GetPortValue<float>(Left);
  var right = GetPortValue<float>(Right);
  var answer = left * right;

  Result.Activate(answer);
```

就是这样！下次您打开流程图编辑器时，您将看到您的新的**CSharpTutorial:Multiplier**节点，具有与您之前实现的 C++等效节点完全相同的功能：

![实现激活](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_02_28.jpg)

再次恭喜你，因为你已经迈出了使用.NET 平台和 CryENGINE 编写游戏代码的第一步！

## 目标实体

在 CryMono 中添加对目标实体的支持很容易，只需将您的`FlowNode`属性中的`TargetsEntity`属性设置为 true 即可。

```cs
  [FlowNode(TargetsEntity = true)]
```

然后，您可以通过`FlowNode.TargetEntity`获取实体实例，假设它是在包含节点的流程图中分配的。

# 摘要

在本章中，我们已经学会了为什么流程图对设计师有用，并创建了我们自己的流程图。

我们还调查了 CryENGINE 提供的一些现有节点，然后用两种编程语言创建了我们自己的节点。现在，您应该对流程图系统有了很好的理解，并且知道如何利用它。

在未来的章节中，我们将探讨流程图可以实现的一些其他功能，包括设计用户界面、实现材质效果、创建特殊的流节点来表示世界中的实体，并将 AI 功能封装成方便的可重用模块。

如果您想更多地探索流程图的世界，为什么不试着找出如何实现更多的标准节点呢？熟悉一下编写 C++和 C#节点之间的区别，看看你更喜欢哪个。

如果您特别想尝试 CryMono，请尝试编辑您的节点脚本，并在运行 Sandbox 时保存它们；您可能会惊喜地发现它们在后台重新编译和重新加载！这应该帮助您测试新的节点想法，而不会因为编译时间和重新启动而受到阻碍。


# 第三章：创建和利用自定义实体

CryENGINE 实体系统提供了创建从简单的物理对象到复杂的天气模拟管理器的一切的手段。

在本章中我们将：

+   详细介绍实体系统的基本概念和实现

+   在 Lua、C#和 C++中创建我们的第一个自定义实体

+   了解游戏对象系统

# 介绍实体系统

实体系统存在是为了在游戏世界中生成和管理实体。实体是逻辑容器，允许在运行时进行行为上的重大改变。例如，实体可以在游戏的任何时刻改变其模型、位置和方向。

考虑一下；你在引擎中与之交互的每个物品、武器、车辆，甚至玩家都是实体。实体系统是引擎中最重要的模块之一，经常由程序员处理。

通过`IEntitySystem`接口访问的实体系统管理游戏中的所有实体。实体使用`entityId`类型定义进行引用，允许在任何给定时间有 65536 个唯一实体。

如果实体被标记为删除，例如`IEntity::Remove(bool bNow = false)`，实体系统将在下一帧开始更新之前删除它。如果`bNow`参数设置为 true，则实体将立即被移除。

## 实体类

实体只是实体类的实例，由`IEntityClass`接口表示。每个实体类都被分配一个标识其的名称，例如，SpawnPoint。

类可以通过`IEntityClassRegistry::RegisterClass`注册，或者通过`IEntityClassRegistry::RegisterStdClass`注册以使用默认的`IEntityClass`实现。

## 实体

`IEntity`接口用于访问实体实现本身。`IEntity`的核心实现包含在`CryEntitySystem.dll`中，不能被修改。相反，我们可以使用游戏对象扩展（查看本章中的*游戏对象扩展*部分）和自定义实体类来扩展实体。

### entityId

每个实体实例都被分配一个唯一的标识符，该标识符在游戏会话的持续时间内保持不变。

### EntityGUID

除了`entityId`参数外，实体还被赋予全局唯一标识符，与`entityId`不同，这些标识符可以在游戏会话之间持续存在，例如在保存游戏等情况下。

## 游戏对象

当实体需要扩展功能时，它们可以利用游戏对象和游戏对象扩展。这允许更多的功能可以被任何实体共享。

游戏对象允许处理将实体绑定到网络、序列化、每帧更新以及利用现有（或创建新的）游戏对象扩展，如库存和动画角色。

在 CryENGINE 开发中，游戏对象通常只对更重要的实体实现（如演员）是必要的。演员系统在第五章中有更详细的解释，以及`IActor`游戏对象扩展。

## 实体池系统

实体池系统允许对实体进行“池化”，从而有效地控制当前正在处理的实体。这个系统通常通过流图访问，并允许根据事件在运行时基于事件禁用/启用实体组。

### 注意

池还用于需要频繁创建和释放的实体，例如子弹。

一旦实体被池系统标记为已处理，它将默认隐藏在游戏中。在实体准备好之前，它不会存在于游戏世界中。一旦不再需要，最好释放实体。

例如，如果有一组 AI 只需要在玩家到达预定义的检查点触发器时被激活，可以使用`AreaTrigger`（及其包含的流节点）和`Entity:EntityPool`流节点来设置。

# 创建自定义实体

现在我们已经学会了实体系统的基础知识，是时候创建我们的第一个实体了。在这个练习中，我们将演示在 Lua、C#和最后 C++中创建实体的能力。

## 使用 Lua 创建实体

Lua 实体相当简单设置，并围绕两个文件展开：实体定义和脚本本身。要创建新的 Lua 实体，我们首先必须创建实体定义，以告诉引擎脚本的位置：

```cs
<Entity
  Name="MyLuaEntity"
  Script="Scripts/Entities/Others/MyLuaEntity.lua"
/>
```

只需将此文件保存为`MyLuaEntity.ent`，放在`Game/Entities/`目录中，引擎将在`Scripts/Entities/Others/MyLuaEntity.lua`中搜索脚本。

现在我们可以继续创建 Lua 脚本本身！首先，在之前设置的路径创建脚本，并添加一个与实体同名的空表：

```cs
  MyLuaEntity = { }
```

在解析脚本时，引擎首先搜索与实体相同名称的表，就像您在`.ent`定义文件中定义的那样。这个主表是我们可以存储变量、编辑器属性和其他引擎信息的地方。

例如，我们可以通过添加一个字符串变量来添加我们自己的属性：

```cs
  MyLuaEntity = {
    Properties = {
      myProperty = "",
    },
  }
```

### 注意

可以通过在属性表中添加子表来创建属性类别。这对于组织目的很有用。

完成更改后，当在编辑器中生成类的实例时，您应该看到以下屏幕截图，通过**RollupBar**默认情况下位于编辑器的最右侧：

![使用 Lua 创建实体](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_03_01.jpg)

### 常见的 Lua 实体回调

脚本系统提供了一组回调，可以用于触发实体事件上的特定逻辑。例如，`OnInit`函数在实体初始化时被调用：

```cs
  function MyEntity:OnInit()
  end
```

## 在 C#中创建实体

第三方扩展**CryMono**允许在.NET 中创建实体，这使我们能够演示在 C#中创建我们自己的实体的能力。

首先，打开`Game/Scripts/Entities`目录，并创建一个名为`MyCSharpEntity.cs`的新文件。这个文件将包含我们的实体代码，并且在引擎启动时将在运行时编译。

现在，打开您选择的脚本（`MyCSharpEntity.cs`）IDE。我们将使用 Visual Studio 来提供**IntelliSense**和代码高亮。

一旦打开，让我们创建一个基本的骨架实体。我们需要添加对 CryENGINE 命名空间的引用，其中存储了最常见的 CryENGINE 类型。

```cs
  using CryEngine;

  namespace CryGameCode
  {
    [Entity]
    public class MyCSharpEntity : Entity
    {
    }
  }
```

现在，保存文件并启动编辑器。您的实体现在应该出现在**RollupBar**中的**默认**类别中。将**MyEntity**拖到视口中以生成它：

![在 C#中创建实体](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_03_02.jpg)

我们使用实体属性（`[Entity]`）作为为实体注册进度提供额外信息的一种方式，例如，使用`Category`属性将导致使用自定义编辑器类别，而不是**默认**。

```cs
  [Entity(Category = "Others")]
```

### 添加编辑器属性

编辑器属性允许关卡设计师为实体提供参数，也许是为了指示触发区域的大小，或者指定实体的默认健康值。

在 CryMono 中，可以通过使用`EditorProperty`属性来装饰支持的类型（查看以下代码片段）。例如，如果我们想添加一个新的`string`属性：

```cs
  [EditorProperty]
  public string MyProperty { get; set; }
```

现在，当您启动编辑器并将**MyCSharpEntity**拖到视口中时，您应该看到**MyProperty**出现在**RollupBar**的下部。

C#中的`MyProperty`字符串变量将在用户通过编辑器编辑时自动更新。请记住，编辑器属性将与关卡一起保存，允许实体在纯游戏模式中使用关卡设计师定义的编辑器属性。

![添加编辑器属性](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_03_03.jpg)

#### 属性文件夹

与 Lua 脚本一样，CryMono 实体可以将编辑器属性放置在文件夹中以进行组织。为了创建文件夹，您可以使用`EditorProperty`属性的`Folder`属性，如下所示：

```cs
  [EditorProperty(Folder = "MyCategory")]
```

现在您知道如何使用 CryMono 创建具有自定义编辑器属性的实体！这在为关卡设计师创建简单的游戏元素并在运行时进行放置和修改时非常有用，而无需寻找最近的程序员。

## 在 C++中创建实体

在 C++中创建实体比使用 Lua 或 C#更复杂，可以根据实体所需的内容进行不同的操作。在本例中，我们将详细介绍通过实现`IEntityClass`来创建自定义实体类。

### 创建自定义实体类

实体类由`IEntityClass`接口表示，我们将从中派生并通过`IEntityClassRegistry::RegisterClass(IEntityClass *pClass)`进行注册。

首先，让我们为我们的实体类创建头文件。在 Visual Studio 中右键单击项目或其任何筛选器，并转到上下文菜单中的**添加** | **新项目**。在提示时，创建您的头文件（.h）。我们将称之为`CMyEntityClass`。

现在，打开生成的`MyEntityClass.h`头文件，并创建一个从`IEntityClass`派生的新类：

```cs
  #include <IEntityClass.h>

  class CMyEntityClass : public IEntityClass
  {
  };
```

现在，我们已经设置了类，我们需要实现从`IEntityClass`继承的纯虚拟方法，以便我们的类能够成功编译。

对于大多数方法，我们可以简单地返回空指针、零或空字符串。但是，有一些方法我们必须处理才能使类正常运行：

+   `Release()`: 当类应该被释放时调用，应该简单执行"delete this;"来销毁类

+   `GetName()`: 这应该返回类的名称

+   `GetEditorClassInfo()`: 这应该返回包含编辑器类别、帮助和图标字符串的`ClassInfo`结构到编辑器

+   `SetEditorClassInfo()`: 当需要更新刚才解释的编辑器`ClassInfo`时调用

`IEntityClass`是实体类的最低限度，尚不支持编辑器属性（稍后我们将稍后介绍）。

要注册实体类，我们需要调用`IEntityClassRegistry::RegisterClass`。这必须在`IGameFramework::CompleteInit`调用之前完成。我们将在`GameFactory.cpp`中的`InitGameFactory`函数中执行：

```cs
  IEntityClassRegistry::SEntityClassDesc classDesc;

  classDesc.sName = "MyEntityClass";
  classDesc.editorClassInfo.sCategory = "MyCategory";

  IEntitySystem *pEntitySystem = gEnv->pEntitySystem;

  IEntityClassRegistry *pClassRegistry = pEntitySystem->GetClassRegistry();

  bool result = pClassRegistry->RegisterClass(new CMyEntityClass(classDesc));
```

#### 实现属性处理程序

为了处理编辑器属性，我们将不得不通过新的`IEntityPropertyHandler`实现来扩展我们的`IEntityClass`实现。属性处理程序负责处理属性的设置、获取和序列化。

首先创建一个名为`MyEntityPropertyHandler.h`的新头文件。以下是`IEntityPropertyHandler`的最低限度实现。为了正确支持属性，您需要实现`SetProperty`和`GetProperty`，以及`LoadEntityXMLProperties`（后者需要从`Level` XML 中读取属性值）。

然后创建一个从`IEntityPropertyHandler`派生的新类：

```cs
  class CMyEntityPropertyHandler : public IEntityPropertyHandler
  {
  };
```

为了使新类编译，您需要实现`IEntityPropertyHandler`中定义的纯虚拟方法。关键的方法可以如下所示：

+   `LoadEntityXMLProperties`: 当加载关卡时，启动器会调用此方法，以便读取编辑器保存的实体的属性值

+   `GetPropertyCount`: 这应该返回注册到类的属性数量

+   `GetPropertyInfo`: 这是在编辑器获取可用属性时调用的，应该返回指定索引处的属性信息

+   `SetProperty`: 这是用来设置实体的属性值的

+   `GetProperty`: 这是用来获取实体的属性值的

+   `GetDefaultProperty`：调用此方法以检索指定索引处的默认属性值

要使用新的属性处理程序，创建一个实例（将请求的属性传递给其构造函数）并在`IEntityClass::GetPropertyHandler()`中返回新创建的处理程序。

我们现在有了一个基本的实体类实现，可以很容易地扩展以支持编辑器属性。这种实现非常灵活，可以用于各种用途，例如，稍后看到的 C#脚本只是简单地自动化了这个过程，减轻了程序员的很多代码责任。

# 实体流节点

在上一章中，我们介绍了流图系统以及流节点的创建。您可能已经注意到，在图表内右键单击时，上下文选项之一是**添加所选实体**。此功能允许您在级别内选择一个实体，然后将其实体流节点添加到流图中。

默认情况下，实体流节点不包含任何端口，因此在右侧显示时基本上没有用处。

然而，我们可以很容易地创建自己的实体流节点，以在所有三种语言中都针对我们选择的实体。

![实体流节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_03_04.jpg)

## 在 Lua 中创建实体流节点

通过扩展我们在*使用 Lua 创建实体*部分中创建的实体，我们可以添加其自己的实体流节点：

```cs
  function MyLuaEntity:Event_OnBooleanPort()
  BroadcastEvent(self, "MyBooleanOutput");end

  MyLuaEntity.FlowEvents =
  {
    Inputs =
    {
      MyBooleanPort = { MyLuaEntity.Event_OnBooleanPort, "bool" },
    },
    Outputs =
    {
      MyBooleanOutput = "bool",
    },
  }
```

![在 Lua 中创建一个实体流节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_03_05.jpg)

我们刚刚为我们的`MyLuaEntity`类创建了一个实体流节点。如果您启动编辑器，生成您的实体，然后在流图中单击**添加所选实体**，您应该会看到节点出现。

## 使用 C#创建实体流节点

由于实现几乎与常规流节点完全相同，因此在 C#中创建实体流节点非常简单。要为您的实体创建一个新的流节点，只需从`EntityFlowNode<T>`派生，其中`T`是您的实体类名称：

```cs
  using CryEngine.Flowgraph;

  public class MyEntity : Entity { }

  public class MyEntityNode : EntityFlowNode<MyEntity>
  {
    [Port]
    public void Vec3Test(Vec3 input) { }

    [Port]
    public void FloatTest(float input) { }

    [Port]
    public void VoidTest()
    {
    }

    [Port]
    OutputPort<bool> BoolOutput { get; set; }
  }
```

![使用 C#创建实体流节点](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_03_06.jpg)

我们刚刚在 C#中创建了一个实体流节点。这使我们可以轻松地使用我们从上一章学到的内容，并在新节点的逻辑中利用`TargetEntity`。

## 在 C++中创建实体流节点

### 注意

本节假定您已阅读了第二章中的*在 C++中创建自定义节点*部分。

简而言之，实体流节点在实现上与常规节点相同。不同之处在于节点的注册方式，以及实体支持`TargetEntity`的先决条件（有关更多信息，请参阅上一章）。

### 注册实体节点

我们使用与以前注册实体节点相同的方法，唯一的区别是类别必须是实体，节点名称必须与其所属的实体相同：

```cs
REGISTER_FLOW_NODE("entity:MyCppEntity", CMyEntityFlowNode);
```

### 最终代码

最后，根据我们现在和上一章学到的知识，我们可以很容易地在 C++中创建我们的第一个实体流节点：

```cs
  #include "stdafx.h"

  #include "Nodes/G2FlowBaseNode.h"

  class CMyEntityFlowNode : public CFlowBaseNode<eNCT_Instanced>
  {
    enum EInput
    {
      EIP_InputPort,
    };

    enum EOutput
    {
      EOP_OutputPort
    };

  public:
    CMyEntityFlowNode(SActivationInfo *pActInfo)
    {
    }

    virtual IFlowNodePtr Clone(SActivationInfo *pActInfo)
    {
      return new CMyEntityFlowNode(pActInfo);
    }

    virtual void ProcessEvent(EFlowEvent evt, SActivationInfo *pActInfo)
    {
    }

    virtual void GetConfiguration(SFlowNodeConfig &config)
    {
      static const SInputPortConfig inputs[] =
      {
        InputPortConfig_Void("Input", "Our first input port"),
        {0}
      };
      static const SOutputPortConfig outputs[] =
      {
        OutputPortConfig_Void("Output", "Our first output port"),
        {0}
      };

      config.pInputPorts = inputs;
      config.pOutputPorts = outputs;
      config.sDescription = _HELP("Entity flow node sample");

      config.nFlags |= EFLN_TARGET_ENTITY;
    }

    virtual void GetMemoryUsage(ICrySizer *s) const
    {
      s->Add(*this);
    }
  };

  REGISTER_FLOW_NODE("entity:MyCppEntity", CMyEntityFlowNode);
```

# 游戏对象

正如在本章开头提到的，当实体需要绑定到网络时，游戏对象用于需要更高级功能的实体。

有两种实现游戏对象的方法，一种是通过`IGameObjectSystem::RegisterExtension`直接注册实体（从而在实体生成时自动创建游戏对象），另一种是通过利用`IGameObjectSystem::CreateGameObjectForEntity`方法在运行时为实体创建游戏对象。

## 游戏对象扩展

通过创建扩展来扩展游戏对象，可以让开发人员钩入多个实体和游戏对象回调。例如，这就是演员默认实现的方式，我们将在第五章中进行介绍，*创建自定义演员*。

我们将在 C++中创建我们的游戏对象扩展。我们在本章前面创建的 CryMono 实体是由`CryMono.dll`中包含的自定义游戏对象扩展实现的，目前不可能通过 C#或 Lua 创建更多的扩展。

### 在 C++中创建游戏对象扩展

CryENGINE 提供了一个辅助类模板用于创建游戏对象扩展，称为`CGameObjectExtensionHelper`。这个辅助类用于避免重复常见代码，这些代码对于大多数游戏对象扩展是必要的，例如基本的 RMI 功能（我们将在第八章中介绍，*多人游戏和网络*）。

要正确实现`IGameObjectExtension`，只需从`CGameObjectExtensionHelper`模板派生，指定第一个模板参数为你正在编写的类（在我们的例子中为`CMyEntityExtension`），第二个参数为你要派生的`IGameObjectExtension`。

### 注意

通常，第二个参数是`IGameObjectExtension`，但对于特定的实现，比如`IActor`（它又从`IGameObjectExtension`派生而来），可能会有所不同。

```cs
  class CMyGameObjectExtension
    : public CGameObjectExtensionHelper<CMyGameObjectExtension, IGameObjectExtension>
    {
    };
```

现在你已经从`IGameObjectExtension`派生出来，你需要实现所有它的纯虚方法，以避免一堆未解析的外部。大多数可以用空方法重写，返回空或 false，而更重要的方法已经列出如下：

+   Init: 这是用来初始化扩展的。只需执行`SetGameObject(pGameObject)`；然后返回 true。

+   `NetSerialize`: 这是用来在网络上序列化东西的。这将在第八章中介绍，*多人游戏和网络*，但现在它只会简单地返回 true。

你还需要在一个新的类中实现`IGameObjectExtensionCreatorBase`，这个类将作为你实体的扩展工厂。当扩展即将被激活时，我们工厂的`Create()`方法将被调用以获取新的扩展实例：

```cs
  struct SMyGameObjectExtensionCreator
    : public IGameObjectExtensionCreatorBase
  {
    virtual IGameObjectExtension *Create() { return new CMyGameObjectExtension(); }

    virtual void GetGameObjectExtensionRMIData(void **ppRMI, size_t *nCount) { return CMyGameObjectExtension::GetGameObjectExtensionRMIData(ppRMI, nCount); }
  };
```

现在你已经创建了你的游戏对象扩展实现，以及游戏对象创建者，只需注册扩展：

```cs
static SMyGameObjectExtensionCreator creator;
  gEnv->pGameFramework->GetIGameObjectSystem()->RegisterExtension("MyGameObjectExtension", &creator, myEntityClassDesc);
```

### 注意

通过将实体类描述传递给`IGameObjectSystem::RegisterExtension`，你告诉它为你创建一个虚拟实体类。如果你已经这样做了，只需将最后一个参数`pEntityCls`传递为`NULL`，以便它使用你之前注册的类。

### 激活我们的扩展

为了激活你的游戏对象扩展，你需要在实体生成后调用`IGameObject::ActivateExtension`。一种方法是使用实体系统接收器`IEntitySystemSink`，并监听`OnSpawn`事件。

我们现在已经注册了我们自己的游戏对象扩展。当实体生成时，我们的实体系统接收器的`OnSpawn`方法将被调用，允许我们创建我们的游戏对象扩展的实例。

# 总结

在本章中，我们学习了核心实体系统的实现和暴露，并创建了我们自己的自定义实体。

你现在应该了解为你的实体创建附加的流程节点，并了解围绕游戏对象及其扩展的工作知识。

我们将在后面的章节中介绍现有的游戏对象扩展和实体实现，例如，通过创建我们自己的角色并实现基本的 AI。

如果你想更熟悉实体系统，为什么不试着自己创建一个稍微复杂的实体呢？

在下一章中，我们将介绍游戏规则系统。


# 第四章：游戏规则

角色和实体是游戏的组成部分，但游戏规则是将它们联系在一起的东西。游戏规则系统管理所有初始玩家事件，如 OnConnect、OnDisconnect 和 OnEnteredGame。

使用游戏规则系统，我们可以创建自定义游戏流程来控制和联系我们的游戏机制。

在本章中，我们将：

+   学习游戏模式的基本概念

+   在 C++中创建我们的`IGameRules`实现

+   用 Lua 和 C#编写游戏规则脚本

# 游戏规则简介

在考虑游戏时，我们通常会将思绪引向游戏机制，如处理死亡和游戏结束条件。根据我们在前几章中学到的知识，由于每个实体和角色都不影响更大的方案，我们实际上无法实现这一点。

游戏规则确切地做了其名称所暗示的事情；控制游戏的规则。规则可以很简单，比如一个角色射击另一个角色时会发生什么，或者更复杂，例如开始和结束回合。

CryENGINE 游戏规则实现围绕着两种听起来非常相似但实际上有很大不同的类型：

+   **游戏规则**：这是通过 C++中的`IGameRules`接口实现的，它处理诸如`OnClientConnect`和`OnClientDisconnect`之类的回调。

+   **游戏模式**：这依赖于游戏规则实现，但通过添加额外的功能（如支持多个玩家）扩展了游戏规则实现的默认行为。例如，我们可以有两种游戏模式；单人游戏和死亡竞赛，它们都依赖于`IGameRules`实现提供的默认行为，但每种游戏模式都添加了额外的功能。

## IGameRules 接口 - 游戏规则

在第三章结束时，我们学习了游戏对象扩展。在本章中，我们将利用这些知识来实现`IGameRules`，这是一个游戏对象扩展，用于初始化游戏上下文并将游戏机制联系在一起。

### 注意

始终记住当前活动的游戏模式是一个实体。这有时可以通过请求实体事件来滥用。例如，在 Crytek 游戏 Crysis 中，一个常见的黑客技巧是围绕在游戏模式上发送子弹或杀死事件。这实质上“杀死”了游戏规则实体，并导致服务器严重崩溃。

`IGameRules`实现通常负责游戏模式的最基本行为，并将其他所有内容转发到其 C#或 Lua 脚本。

## 脚本 - 游戏模式

在注册我们的`IGameRules`实现之后，我们需要注册一个使用它的游戏模式。这是使用`IGameRulesSystem::RegisterGameRules`函数完成的（通常在`IGame::Init`中完成）。

```cs
pGameRulesSystem->RegisterGameRules("MyGameMode", "GameRules");
```

在处理了前面的片段之后，游戏规则系统将意识到我们的游戏模式。当`sv_gamerules`控制台变量更改为`MyGameMode`时，系统将创建一个新的实体，并激活其名为`GameRules`的游戏对象扩展（在前一节中注册）。

### 注意

`sv_gamerules`控制台变量在 CryENGINE 启动时设置为`sv_gamerulesdefault`的值，除非在专用服务器上运行。

此时，游戏将自动搜索名为你的游戏模式的 Lua 脚本，位于`Scripts/GameRules/`中。对于前面的片段，它会找到并加载`Scripts/GameRules/MyGameMode.lua`。

通过使用脚本，游戏规则实现可以将游戏事件（如新玩家连接）转发到 Lua 或 C#，允许每个游戏模式根据其内部逻辑专门化行为。

## 加载关卡

当使用地图控制台命令加载关卡时，游戏框架会在`Game/Levels`中搜索关卡。

通过使用`IGameRulesSystem::AddGameRulesLevelLocation`，我们可以在`Game/Levels`中添加子目录，当寻找新关卡时将会搜索这些子目录。例如：

```cs
gEnv->pGameFramework->GetIGameRulesSystem()->AddGameRulesLevelLocation("MyGameMode", "MGM_Levels");
```

当加载一个将 `sv_gamerules` 设置为 `MyGameMode` 的关卡时，游戏框架现在会在 `Levels/MGM_Levels/` 目录中搜索关卡目录。

这允许游戏模式特定的关卡被移动到 `Game/Levels` 目录中的子目录中，这样可以更容易地按游戏模式对关卡进行排序。

# 实现游戏规则接口

现在我们知道了游戏规则系统的基本工作原理，我们可以尝试创建一个自定义的 `IGameRules` 实现。

### 注意

在开始之前，请考虑你是否真的需要为你的游戏创建一个自定义的 `IGameRules` 实现。随游戏一起提供的默认 GameDLL 是专门为**第一人称射击游戏**（**FPS**）专门化的 `IGameRules` 实现。如果你的游戏前提类似于 FPS，或者你可以重用现有功能，那么可能更好地编写一个实现。

首先，我们需要创建两个新文件；`GameRules.cpp` 和 `GameRules.h`。完成后，打开 `GameRules.h` 并创建一个新的类。我们将命名为 `CGameRules`。

类就位后，我们必须从 `IGameRules` 派生。如前所述，游戏规则被处理为游戏对象扩展。因此，我们必须使用 `CGameObjectExtensionHelper` 模板类：

```cs
class CGameRules 
  : public CGameObjectExtensionHelper<CGameRules, IGameRules>
  {
  };
```

第三个可选的 `CGameObjectExtensionHelper` 参数定义了这个游戏对象支持多少个 RMIs。我们将在第八章 *多人游戏和网络*中进一步讨论它。

有了这个类，我们可以开始实现 `IGameRules` 和 `IGameObjectExtension` 结构中定义的所有纯虚方法。与实体一样，我们可以实现返回空、nullptr、零、false 或空字符串的虚拟方法。需要单独处理的方法如下：

| 函数名 | 描述 |
| --- | --- |
| `IGameObjectExtension::Init` | 用于初始化游戏对象扩展。应该调用 `IGameRulesSystem::SetCurrentGameRules(this)` |
| `IGameRules::OnClientConnect` | 当新客户端连接时在服务器上调用，必须使用 `IActorSystem::CreateActor` 创建一个新的角色 |
| `IGameRules::OnClientDisconnect` | 当客户端断开连接时在服务器上调用，必须包含对 `IActorSystem::RemoveActor` 的调用 |
| `IGameObjectExtension::Release / 析构函数` | `Release` 函数应该删除扩展实例，并通过其析构函数调用 `IGameRulesSystem::SetCurrentGameRules(nullptr)` |

## 注册游戏对象扩展

完成后，使用 `REGISTER_FACTORY` 宏注册游戏规则实现。

游戏对象扩展必须在游戏初始化过程中尽早注册，因此通常在 `IGame::Init` 函数中完成（通过默认 GameDLL 中的 `GameFactory.cpp`）：

```cs
  REGISTER_FACTORY(pFramework, "GameRules", CGameRules, false);
```

## 创建自定义游戏模式

要开始，我们需要注册我们的第一个游戏模式。

### 注意

注意 `IGameRules` 实现和游戏模式本身之间的区别。游戏模式依赖于 `IGameRules` 实现，并且需要单独注册。

要注册自定义游戏模式，CryENGINE 提供了 `IGameRulesSystem::RegisterGameRules` 函数：

```cs
  gEnv->pGameFramework->GetIGameRulesSystem()->RegisterGameRules("MyGameMode", "GameRules");

```

前面的代码将创建一个名为 `MyGameMode` 的游戏模式，它依赖于我们之前注册的 `GameRules` 游戏对象扩展。

当加载一个将 `sv_gamerules` 设置为 `MyGameMode` 的地图时，游戏规则实体将被创建并分配名称 `MyGameMode`。生成后，我们之前创建的 `IGameRules` 扩展将被构造。

### 注意

如果你只是创建一个现有游戏模式的副本或子类，例如从 `SinglePlayer.lua` 派生的默认 `DeathMatch.lua` 脚本，你需要单独注册 `DeathMatch` 游戏模式。

# 脚本

游戏模式通常是面向脚本的，游戏流程如生成、杀死和复活通常委托给 Lua 或 C# 等第二语言。

## Lua 脚本

由于 Lua 脚本已集成到 CryENGINE 中，我们无需进行任何额外的加载即可使其工作。要访问您的脚本表（基于与您的游戏模式同名的 Lua 文件在`Game/Scripts/GameRules`中）：

```cs
  m_script = GetEntity()->GetScriptTable();
```

### 调用方法

要在您的脚本表上调用方法，请参阅`IScriptSystem BeginCall`和`EndCall`函数：

```cs
  IScriptSystem *pScriptSystem = gEnv->pScriptSystem;

  pScriptSystem->BeginCall(m_script, "MyMethod");
  pScriptSystem->EndCall();
```

执行上述代码时，我们将能够在我们游戏模式的脚本表中包含的名为`MyMethod`的函数中执行 Lua 代码。表的示例如下所示：

```cs
  MyGameMode = { }

  function MyGameMode:MyMethod()
  end
```

### 调用带参数的方法

要为您的 Lua 方法提供参数，请在脚本调用的开始和结束之间使用`IScriptSystem::PushFuncParam`：

```cs
  pScriptSystem->BeginCall(m_script, name);
  pScriptSystem->PushFuncParam("myStringParameter");
  pScriptSystem->EndCall();
```

### 注意

`IScriptSystem::PushFuncParam`是一个模板函数，尝试使用提供的值创建一个`ScriptAnyValue`对象。如果默认的`ScriptAnyValue`构造函数不支持您的类型，将出现编译器错误。

恭喜，您现在已经使用字符串参数调用了 Lua 函数：

```cs
  function MyGameMode:MyMethod(stringParam)
  end
```

### 从 Lua 获取返回值

你还可以通过向`IScriptSystem::EndCall`传递一个额外的参数来从 Lua 函数中获取返回值。

```cs
  int result = 0;
  pScriptSystem->EndCall(&result);
  CryLog("MyMethod returned %i!", result);
```

### 获取表值

有时直接从 Lua 表中获取值可能是必要的，可以使用`IScriptTable::GetValue`来实现：

```cs
  bool bValue = false;
  m_script->GetValue("bMyBool", &bValue);
```

上述代码将在脚本中搜索名为`bMyBool`的变量，如果成功，则将其值设置为本机`bValue`变量。

## CryMono 脚本

要在`IGameObjectExtension::Init`实现中创建 CryMono 脚本的实例，请参阅`IMonoScriptSystem::InstantiateScript`：

```cs
  IMonoObjaect *pScript = GetMonoScriptSystem()->InstantiateScript(GetEntity()->GetClass()->GetName(), eScriptFlag_GameRules);
```

这段代码将查找一个具有当前游戏模式名称的 CryMono 类，并返回一个新的实例。

### 注意

无需同时使用 Lua 和 CryMono 游戏规则脚本。决定哪种对您的用例最好。

### 调用方法

现在您已经有了类实例，可以使用`IMonoObject::CallMethod`助手调用其中一个函数：

```cs
  m_pScript->CallMethod("OnClientConnect", channelId, isReset, playerName)
```

这段代码将搜索具有匹配参数的名为`OnClientConnect`的方法，并调用它：

```cs
  public bool OnClientConnect(int channelId, bool isReset = false, string playerName = "")
  {
  }
```

### 返回值

`IMonoObject::CallMethod`默认返回一个`mono::object`类型，表示一个装箱的托管对象。要获取本机值，我们需要将其解包：

```cs
  mono::object result = m_pScript->CallMethod("OnClientConnect", channelId, isReset, playerName);

  IMonoObject *pResult = *result;
  bool result = pResult->Unbox<bool>();
```

### 属性

要获取托管对象的属性值，请查看`IMonoObject::GetPropertyValue`：

```cs
  mono::object propertyValue = m_pScript->GetPropertyValue("MyFloatProperty");

  if(propertyValue)
  {
    IMonoObject *pObject = *propertyValue;

    float value = pObject->Unbox<float>();
  }
```

也可以直接设置属性值：

```cs
  float myValue = 5.5f;

  mono::object boxedValue = GetMonoScriptSystem()->GetActiveDomain()->BoxAnyValue(MonoAnyValue(myValue));

  m_pScript->SetPropertyValue("MyFloatProperty", boxedValue);
```

### 字段

也可以通过使用`IMonoObject`方法`GetFieldValue`和`SetFieldValue`以与属性相同的方式获取和设置字段的值。

# 在 C#中创建基本游戏模式

现在我们已经掌握了创建迷你游戏所需的基本知识，为什么不开始呢？首先，我们将致力于创建一个非常基本的用于生成演员和实体的系统。

## 定义我们的意图

首先，让我们明确我们想要做什么：

1.  生成我们的演员。

1.  将我们的演员分配给两个可能的团队之一。

1.  检查当演员进入对方的`Headquarters`实体时，并结束它。

## 创建演员

我们需要做的第一件事是生成我们的演员，这在我们拥有演员之前是无法完成的。为此，我们需要在`Game/Scripts`目录中的某个地方创建一个`MyActor.cs`文件，然后添加以下代码：

```cs
  public class MyActor : Actor 
  {
  }
```

这段代码片段是注册演员所需的最低限度。

我们还应该更新我们演员的视图，以确保玩家进入游戏时能看到一些东西。

```cs
  protected override void UpdateView(ref ViewParams viewParams)
  {
    var fov = MathHelpers.DegreesToRadians(60);

    viewParams.FieldOfView = fov;
    viewParams.Position = Position;
    viewParams.Rotation = Rotation;
  }
```

上述代码将简单地将摄像机设置为使用玩家实体的位置和旋转，视野为 60。

### 注意

要了解更多关于创建演员和视图的信息，请参阅第五章，*创建自定义演员*。

现在我们有了我们的演员，我们可以继续创建游戏模式：

```cs
  public class ReachTheHeadquarters : CryEngine.GameRules
  {
  }
```

与`Game/Scripts/`目录中找到的所有 CryMono 类型一样，我们的游戏模式将在 CryENGINE 启动后不久自动注册，即在调用`IGameFramework::Init`之后。

在继续创建特定于游戏的逻辑之前，我们必须确保我们的角色在连接时被创建。为此，我们实现一个`OnClientConnect`方法：

```cs
  public bool OnClientConnect(int channelId, bool isReset = false,  string playerName = "Dude")
  {
    // Only the server can create actors.
    if (!Game.IsServer)
      return false;

    var actor = Actor.Create<MyActor>(channelId, playerName);
    if (actor == null)
    {
      Debug.LogWarning("Failed to create the player.");
      return false;
    }

    return true;
  }
```

然而，由于脚本函数不是自动化的，我们需要修改我们的`IGameRules`实现的`OnClientConnect`方法，以确保我们在 C#中接收到这个回调：

```cs
  bool CGameRules::OnClientConnect(int channelId, bool isReset)
  {
  const char *playerName;
  if (gEnv->bServer && gEnv->bMultiplayer)
  {
    if (INetChannel *pNetChannel = gEnv->pGameFramework->GetNetChannel(channelId))
      playerName = pNetChannel->GetNickname();
  }
    else
      playerName = "Dude";

  return m_pScript->CallMethod("OnClientConnect", channelId, isReset, playerName) != 0;
  }
```

现在，当新玩家连接到服务器时，我们的`IGameRules`实现将调用`ReachTheHeadquarters.OnClientConnect`，这将创建一个新的`MyActor`类型的角色。

### 注意

请记住，游戏模式的`OnClientConnect`在非常早期就被调用，就在新客户端连接到服务器时。如果在`OnClientConnect`退出后没有为指定的`channelId`创建角色，游戏将抛出致命错误。

## 生成角色

当客户端连接时，角色现在将被创建，但是如何将角色重新定位到一个**SpawnPoint**呢？首先，在`Scripts`目录中的某个地方创建一个新的`SpawnPoint.cs`文件：

```cs
  [Entity(Category = "Others", EditorHelper = "Editor/Objects/spawnpointhelper.cgf")]
  public class SpawnPoint : Entity
  {
    public void Spawn(EntityBase otherEntity)
    {
      otherEntity.Position = this.Position;
      otherEntity.Rotation = this.Rotation;
    }
}
```

在重新启动编辑器后，这个实体现在应该出现在**RollupBar**中。我们将调用`spawnPoint.Spawn`函数来生成我们的角色。

首先，我们需要打开我们的`ReachTheHeadquarters`类，并添加一个新的`OnClientEnteredGame`函数：

```cs
  public void OnClientEnteredGame(int channelId, EntityId playerId, bool reset)
  {
    var player = Actor.Get<MyActor>(channelId);
    if (player == null)
    {
      Debug.LogWarning("Failed to get player");
      return;
    }
    var random = new Random();

 // Get all spawned entities off type SpawnPoint
    var spawnPoints = Entity.GetByClass<SpawnPoint>();

// Get a random spawpoint
    var spawnPoint = spawnPoints.ElementAt(random.Next(spawnPoints.Count()));
    if(spawnPoint != null)
    {
     // Found one! Spawn the player here.
      spawnPoint.Spawn(player);
    }
  }
```

这个函数将在客户端进入游戏时被调用。在启动器模式下，这通常发生在玩家完成加载后，而在编辑器中，它是在玩家按下*Ctrl* + *G*后切换到**纯游戏模式**时调用的。

在当前状态下，我们首先会获取我们玩家的`MyActor`实例，然后在随机选择的`SpawnPoint`处生成。

### 注意

不要忘记从你的`IGameRules`实现中调用你的脚本的`OnClientEnteredGame`函数！

## 处理断开连接

我们还需要确保玩家断开连接时角色被移除：

```cs
  public override void OnClientDisconnect(int channelId)
  {
    Actor.Remove(channelId);
  }
```

不要忘记从你的`IGameRules`实现中调用`OnClientConnect`函数！

### 注意

在断开连接后未能移除玩家将导致角色在游戏世界中持续存在，并且由于相关玩家不再与服务器连接，可能会出现更严重的问题。

## 将玩家分配到一个队伍

现在玩家可以连接和生成了，让我们实现一个基本的队伍系统，以跟踪每个玩家所属的队伍。

首先，让我们向我们的游戏模式添加一个新的`Teams`属性：

```cs
  public virtual IEnumerable<string> Teams
  {
    get
    {
      return new string[] { "Red", "Blue" };
    }
  }
```

这段代码简单地确定了我们的游戏模式允许的队伍，即`红队`和`蓝队`。

现在，让我们还向我们的`MyActor`类添加一个新属性，以确定角色所属的队伍：

```cs
  public string Team { get; set; }
```

太好了！然而，我们还需要将相同的片段添加到`SpawnPoint`实体中，以避免生成相同队伍的玩家相邻。

完成这些操作后，打开`ReachTheHeadquarters`游戏模式类，并导航到我们之前创建的`OnClientEnteredGame`函数。我们要做的是扩展`SpawnPoint`选择，只使用属于玩家队伍的生成点。

看一下以下片段：

```cs
// Get all spawned entities of type SpawnPoint
  var spawnPoints = Entity.GetByClass<SpawnPoint>(); 

```

现在，用以下代码替换这个片段：

```cs
// Get all spawned entities of type SpawnPoint belonging to the players team
  var spawnPoints = Entity.GetByClass<SpawnPoint>().Where(x => x.Team == player.Team);
```

这将自动删除所有`Team`属性与玩家不相等的生成点。

但等等，我们还需要把玩家分配到一个队伍！为了做到这一点，在获取生成点之前添加以下内容：

```cs
  player.Team = Teams.ElementAt(random.Next(Teams.Count()));
```

当玩家进入游戏时，我们将随机选择一个队伍分配给他们。如果你愿意，为什么不扩展这一点，以确保队伍始终保持平衡？例如，如果红队比蓝队多两名玩家，就不允许新玩家加入红队。

### 注意

在继续之前，随意玩弄当前的设置。你应该能够在游戏中生成！

## 实现总部

最后，让我们继续创建我们的游戏结束条件；总部。简单来说，每个队伍都会有一个`总部`实体，当玩家进入对方队伍的总部时，该玩家的队伍就赢得了比赛。

### 添加游戏结束事件

在创建`Headquarters`实体之前，让我们在`ReachTheHeadquarters`类中添加一个新的`EndGame`函数：

```cs
  public void EndGame(string winningTeam)
  {
    Debug.LogAlways("{0} won the game!", winningTeam);
  }
```

我们将从`Headquarters`实体中调用此函数，以通知游戏模式游戏应该结束。

### 创建总部实体

现在，我们需要创建我们的`Headquarters`实体（请参阅以下代码片段）。该实体将通过 Sandbox 放置在每个级别中，每个队伍一次。我们将公开三个编辑器属性；`Team`，`Minimum`和`Maximum`：

+   `Team`：确定`Headquarters`实例属于哪个队伍，在我们的例子中是蓝队或红队

+   `Minimum`：指定触发区域的最小大小

+   `Maximum`：指定触发区域的最大大小

```cs
  public class Headquarters : Entity
  {
    public override void OnSpawn()
    {
      TriggerBounds = new BoundingBox(Minimum, Maximum);
    }

    protected override void OnEnterArea(EntityId entityId, int areaId, EntityId areaEntityId)
    {
    }

    [EditorProperty]
    public string Team { get; set; }

    [EditorProperty]
    public Vec3 Minimum { get; set; }

    [EditorProperty]
    public Vec3 Maximum { get; set; }
  }
```

太棒了！现在我们只需要扩展`OnEnterArea`方法，在游戏结束时通知我们的游戏模式：

```cs
  protected override void OnEnterArea(EntityId entityId, int areaId, EntityId areaEntityId)
  {
    var actor = Actor.Get<MyActor>(entityId);
    if (actor == null)
      return;

    if (actor.Team != Team)
    {
      var gameMode = CryEngine.GameRules.Current;
      var rthGameRules = gameMode as ReachTheHeadquarters;

      if (rthGameRules != null)
        rthGameRules.EndGame(actor.Team);
    }
  }
```

`Headquarters`实体现在将在对立队伍的实体进入时通知游戏模式。

#### 绕道 - 触发器边界和实体区域

实体可以通过注册区域接收区域回调。这可以通过将实体链接到形状实体或手动创建触发器代理来完成。在 C#中，您可以通过设置`EntityBase.TriggerBounds`属性来手动创建代理，就像我们在之前的代码片段中所做的那样。

当实体位于或靠近该区域时，它将开始接收该实体上的事件。这允许创建特定实体，可以跟踪玩家何时以及何地进入特定区域，以触发专门的游戏逻辑。

请参阅以下表格，了解可通过 C++实体事件和 C# `Entity`类中的虚拟函数接收的可用区域回调列表：

| 回调名称 | 描述 |
| --- | --- |
| 当一个实体进入与该实体链接的区域时调用`OnEnterArea`。 |
| `OnLeaveArea` | 当存在于与该实体链接的区域内的实体离开时触发 |
| `OnEnterNearArea` | 当实体靠近与该实体链接的区域时触发 |
| `OnMoveNearArea` | 当实体靠近与该实体链接的区域时调用 |
| `OnLeaveNearArea` | 当实体离开与该实体链接的附近区域时调用 |
| `OnMoveInsideArea` | 当实体重新定位到与该实体链接的区域内时触发 |

## 填充级别

基本示例现在已经完成，但需要一些调整才能使其正常工作！首先，我们需要创建一个新级别，并为每个队伍放置`Headquarters`。

首先，打开 Sandbox 编辑器，并通过导航到**文件** | **新建**来创建一个新级别：

![Populating the level](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_04_01.jpg)

这将弹出**新级别**对话框，在其中我们可以设置级别名称和地形设置。

点击**确定**后，您的级别将被创建，然后加载。完成后，现在是时候开始向我们的级别添加必要的游戏元素了！

首先，打开**RollupBar**并通过将其拖入视口中生成**Headquarters**实体：

![Populating the level](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_04_02.jpg)

生成后，我们必须设置在**Headquarters**类中创建的编辑器属性。

将**Team**设置为**红色**，**Maximum**设置为**10,10,10**。这会告诉类`Headquarters`属于哪个队伍，并且我们将查询以检测另一个玩家是否进入了该区域的最大大小。

![Populating the level](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_04_03.jpg)

完成后，生成另一个**Headquarters**实体（或复制现有实体），然后按照相同的过程进行操作，只是这次将**Team**属性设置为**蓝色**。

现在，我们只需要为每个队伍生成一个 SpawnPoint 实体，然后我们就可以开始了！再次打开**RollupBar**，然后转到**其他** | **SpawnPoint**：

![Populating the level](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_04_04.jpg)

现在，将实体拖放到视口中，以与生成**Headquarters**相同的方式生成它。生成后，将**Team**属性设置为**红色**，然后为蓝队重复该过程：

![Populating the level](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cryeng-gm-prog-cpp-cs-lua/img/5909_04_05.jpg)

完成了！现在你应该能够使用 *Ctrl* + *G* 进入游戏，或者通过导航到 **游戏** | **切换到游戏**。然而，由于我们还没有添加任何类型的玩家移动，玩家将无法朝着敌方总部移动以结束游戏。

学习如何处理玩家输入和移动，请参考下一章，第五章，*创建自定义角色*。

# 总结

在本章中，我们学习了游戏规则系统的基本行为，并创建了自己的`IGameRules`实现。

在注册了自己的游戏模式并在 C#中创建了`Headquarters`示例之后，你应该对游戏规则系统有了很好的理解。

我们已经创建了第一个游戏模式，现在可以继续下一章了。记住未来章节中游戏规则的目的，这样你就可以将需要在游戏中创建的所有游戏机制联系在一起。

对游戏规则还不满意？为什么不尝试在你选择的脚本语言中创建一个基本的游戏规则集，或者扩展我们之前创建的示例。在下一章中，我们将看到如何创建自定义角色。
