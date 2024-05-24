# 精通 Kotlin 安卓开发（一）

> 原文：[`zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5`](https://zh.annas-archive.org/md5/5ADF07BDE12AEC5E67245035E25F68A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Android 是移动设备最流行的平台。每年都有越来越多的开发人员参与 Android 开发。Android 框架使得可以为手机、平板电脑、电视等开发应用成为可能！到目前为止，所有的开发都是用 Java 完成的。最近，Google 宣布 Kotlin 作为开发人员可以使用的第二种语言。因此，鉴于 Kotlin 日益增长的受欢迎程度，我们决定介绍使用 Kotlin 作为其主要开发编程语言的 Android。

有了 Kotlin，你可以做任何你用 Java 做的事情，但更加愉快和有趣！我们将向你展示如何在 Android 和 Kotlin 中玩耍，以及如何创造令人惊叹的东西！多亏了 Kotlin，可以肯定 Android 平台会进一步发展。在不久的将来，Kotlin 有可能成为该平台的主要开发语言。坐稳，准备开始一段伟大的旅程吧！

# 本书涵盖的内容

第一章，“开始 Android”，教你如何使用 Kotlin 开始 Android 开发，以及如何设置你的工作环境。

第二章，“构建和运行”，向你展示如何构建和运行你的项目。它将演示如何记录和调试应用程序。

第三章，“屏幕”，从 UI 开始。在这一章中，我们将为我们的应用程序创建第一个屏幕。

第四章，“连接屏幕流”，解释了如何连接屏幕流并定义与 UI 的基本用户交互。

第五章，“外观和感觉”，涵盖了 UI 的主题。我们将向你介绍 Android 主题的基本概念。

第六章，“权限”，解释了为了利用某些系统功能，需要获取适当的系统权限，这将在本章中讨论。

第七章，“使用数据库”，向你展示如何使用 SQLite 作为应用程序的存储。你将创建一个数据库来存储和共享数据。

第八章，“Android 偏好设置”，指出并非所有数据都应存储在数据库中；一些信息可以存储在共享偏好设置中。我们将解释原因和方法。

第九章，“Android 中的并发”，解释了如果你熟悉编程中的并发，那么你会知道在软件中许多事情是同时发生的。Android 也不例外！

第十章，“Android 服务”，介绍了 Android 服务以及如何使用它们。

第十一章，“消息”，说在 Android 中，你的应用程序可以监听各种事件。如何做到这一点将在本章中得到解答。

第十二章，“后端和 API”，连接到远程后端实例以获取数据。

第十三章，“为高性能进行调优”，是一个完美的章节，当你不确定你的应用程序是否足够快时，它会给你答案。

第十四章，“测试”，提到在发布任何东西之前，我们必须对其进行测试。在这里，我们将解释如何为你的应用程序编写测试。

第十五章，“迁移到 Kotlin”，指导你如果计划将现有的 Java 代码库迁移到 Kotlin。

第十六章，“部署你的应用程序”，指导你完成部署过程。我们将发布本书中开发的所有内容。

# 本书所需内容

对于本书，需要运行 Microsoft Windows、Linux 或 macOS 的现代计算机。您需要安装 Java JDK、Git 版本控制系统和 Android Studio。

为了运行所有代码示例和您编写的代码，您需要一部运行 Android 操作系统版本>= 5 的 Android 手机。

# 本书适合对象

本书旨在希望以简单有效的方式构建令人惊叹的 Android 应用程序的开发人员。假定具有 Kotlin 的基本知识，但不熟悉 Android 开发。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL 和用户输入显示如下：“我们将为`Application`类的每个生命周期事件和我们创建的屏幕（活动）添加适当的日志消息。”

代码块设置如下：

```kt
    override fun onCreate(savedInstanceState: Bundle?) { 
      super.onCreate(savedInstanceState) 
      setContentView(R.layout.activity_main) 
      Log.v(tag, "[ ON CREATE 1 ]") 
    } 
```

任何命令行输入或输出都是这样写的。输入命令可能会被分成几行以增加可读性，但需要作为一个连续的行输入到提示符中：

```kt
sudo apt-get install libc6:i386 libncurse
libstdc++6:i386 lib32z1 libbz2-1.0:i386
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会出现在文本中，如下所示：“选择**工具**|**Android**|**AVDManager**或单击工具栏中的 AVDManager 图标。”

警告或重要说明会出现在这样。

提示和技巧会出现在这样。


# 第一章：从 Android 开始

**Kotlin**已被 Google 正式宣布为 Android 的一流编程语言。了解为什么 Kotlin 是新手的最佳工具，以及为什么高级 Android 开发人员首先采用 Kotlin。

在本章中，您将学习如何设置工作环境。您将安装和运行 Android Studio，并设置 Android SDK 和 Kotlin。在这里，您还将介绍一些重要和有用的工具，如**Android 调试桥**（**adb**）。

由于您尚未拥有项目，您将设置它。您将初始化一个 Git 存储库以跟踪代码中的更改，并创建一个空项目。您将使其支持 Kotlin，并添加我们将使用的其他库的支持。

在我们初始化了存储库和项目之后，我们将浏览项目结构并解释 IDE 生成的每个文件。最后，您将创建您的第一个屏幕并查看它。

本章将涵盖以下要点：

+   为 Git 和 Gradle 基础开发环境设置

+   使用 Android 清单

+   Android 模拟器

+   Android 工具

# 为什么选择 Kotlin？

在我们开始我们的旅程之前，我们将回答章节标题中的问题--为什么选择 Kotlin？Kotlin 是由 JetBrains 开发的一种新的编程语言，该公司开发了 IntelliJ IDEA。Kotlin 简洁易懂，与 Java 一样将所有内容编译为字节码。它还可以编译为 JavaScript 或本机代码！

Kotlin 来自行业专业人士，并解决程序员每天面临的问题。它易于开始和采用！IntelliJ 配备了一个 Java 到 Kotlin 转换器工具。您可以逐个文件转换 Java 代码文件，一切仍将无缝运行。

它是可互操作的，并且可以使用任何现有的 Java 框架或库。可互操作性无可挑剔，不需要包装器或适配器层。Kotlin 支持构建系统，如 Gradle、Maven、Kobalt、Ant 和 Griffon，并提供外部支持。

对我们来说，关于 Kotlin 最重要的是它与 Android 完美配合。

一些最令人印象深刻的 Kotlin 功能如下：

+   空安全

+   异常是未经检查的

+   类型推断在任何地方都适用

+   一行函数占一行

+   开箱即用生成的 getter 和 setter

+   我们可以在类外定义函数

+   数据类

+   函数式编程支持

+   扩展函数

+   Kotlin 使用 Markdown 而不是 HTML 来编写 API 文档！ Dokka 工具是 Javadoc 的替代品，可以读取 Kotlin 和 Java 源代码并生成组合文档

+   Kotlin 比 Java 有更好的泛型支持

+   可靠且高性能的并发编程

+   字符串模式

+   命名方法参数

# Kotlin for Android - 官方

2017 年 5 月 17 日，Google 宣布将 Kotlin 作为 Java 虚拟机的一种静态类型编程语言，成为编写 Android 应用程序的一流语言。

下一个版本的 Android Studio（3.0，当前版本为 2.3.3）将直接支持 Kotlin。Google 将致力于 Kotlin 的未来。

重要的是要注意，这只是一种附加语言，而不是现有 Java 和 C++支持的替代品（目前）。

# 下载和配置 Android Studio

为了开发我们的应用程序，我们将需要一些工具。首先，我们需要一个集成开发环境。为此，我们将使用 Android Studio。Android Studio 提供了在各种类型的 Android 设备上构建应用程序的最快速工具。

Android Studio 提供专业的代码编辑、调试和性能工具。这是一个灵活的构建系统，可以让您专注于构建高质量的应用程序。

设置 Android Studio 只需点击几下。在我们继续之前，您需要为您的操作系统下载以下版本：

[`developer.android.com/studio/index.html`](https://developer.android.com/studio/index.html)

以下是 macOS、Linux 和 Windows 的说明：

**macOS**：

要在 macOS 上安装它，请按照以下步骤操作：

1.  启动 Android Studio 的 DMG 文件。

1.  将 Android Studio 拖放到“应用程序”文件夹中。

1.  启动 Android Studio。

1.  选择是否要导入以前的 Android Studio 设置。

1.  单击确定。

1.  按照说明进行，直到 Android Studio 准备就绪。

**Linux：**要在 Linux 上安装它，请按照以下步骤进行：

1.  将下载的存档解压到适合您的应用程序的位置。

1.  导航到`bin/directory/`。

1.  执行`/studio.sh`。

1.  选择是否要导入以前的 Android Studio 设置。

1.  单击确定。

1.  按照说明进行，直到 Android Studio 准备就绪。

1.  可选地，从菜单栏中选择工具|创建桌面条目。

如果您正在运行 Ubuntu 的 64 位版本，则需要使用以下命令安装一些 32 位库：

使用`sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 lib32z1 libbz2-1.0:i386`命令安装所需的 32 位库。

如果您正在运行 64 位的 Fedora，则命令如下：

`**sudo yum install zlib.i686 ncurses-libs.i686 bzip2-libs.i686**`

**Windows：**要在 Windows 上安装它，请按照以下步骤进行：

1.  执行您下载的`.exe`文件。

1.  按照说明进行，直到 Android Studio 准备就绪。

# 设置 Android 模拟器

Android SDK 带有能够运行我们开发的应用程序的**模拟器**。我们需要它来进行我们的项目！模拟器的目的是模拟设备并在计算机上显示其所有活动。我们可以用它做什么？我们可以进行原型设计、开发和测试——所有这些都不需要硬件设备。您可以模拟手机、平板电脑、可穿戴设备和电视设备。您可以创建自己的设备定义，或者您可以使用预定义的模拟器。

模拟器的好处是速度快。在许多情况下，运行应用程序的模拟器实例所需的时间比在真实硬件设备上运行要少。

使用模拟器与真实硬件设备一样容易。对于手势，您可以使用鼠标，对于输入，您可以使用键盘。

模拟器可以做任何真实手机可以做的事情！您可以轻松发送来电和短信！您可以指定设备的位置，发送指纹扫描，调整网络速度和状态，甚至模拟电池属性。模拟器可以有一个虚拟 SD 卡和内部数据存储，您可以使用它们来发送真实文件到该空间。

**Android 虚拟设备**（**AVD**）配置用于定义模拟器。每个 AVD 实例都作为一个完全独立的设备！为了创建和管理 AVD，我们使用 AVD Manager。AVD 定义包含硬件配置文件、系统映像、存储区域、外观和其他重要属性。

让我们来玩一下！要运行 AVD Manager，请执行以下操作之一：

选择**工具**|**Android**|**AVDManager**或单击工具栏中的**AVDManager**图标：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/03be9bd5-d234-4dec-bd94-e61931a76689.png)

它显示您已经定义的所有 AVD。正如您所看到的，我们还没有任何 AVD！

我们在这里可以做什么？我们可以做以下事情：

+   创建一个新的 AVD

+   编辑现有的 AVD

+   删除现有的 AVD

+   创建硬件配置文件

+   编辑现有的硬件配置文件

+   删除现有的硬件配置文件

+   导入/导出定义

+   启动或停止 AVD

+   清除数据并重置 AVD

+   访问文件系统上的 AVD`.ini`和`.img`文件

+   查看 AVD 配置详细信息

要获取 AVD 实例，您可以从头开始创建一个新的 AVD，也可以复制现有的 AVD 并根据需要进行修改。

# 创建一个新的 AVD 实例

从 AVD Manager 的**您的虚拟设备**中，单击创建虚拟设备（您可以在 Android Studio 中运行应用程序时执行相同操作，方法是单击运行图标，然后在选择部署目标对话框中选择创建新模拟器）。请参考以下截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/74eb1559-6335-4d0f-89f1-e02bf0ff0c05.png)

选择一个硬件配置文件，然后单击下一步，如前面的截图所示。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/97a46a76-95f7-4af6-b69d-326d7548f2d5.png)

如果您注意到系统映像旁边的下载链接，则必须单击它。下载过程开始，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/66e46867-20b8-48ed-9789-36fbf3d490f5.png)

我们必须注意目标设备的 API 级别非常重要！您的应用程序无法在其 API 级别低于应用程序所需级别的系统映像上运行。该属性在您的 Gradle 配置中指定。稍后我们将详细介绍 Gradle。

最后，出现“验证配置”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/1ca71d03-a12e-4c21-981c-4ba2fe970635.png)

如有需要，请更改 AVD 属性，然后单击“完成”以完成向导。新创建的 AVD 将显示在“您的虚拟设备”列表或“选择部署目标”对话框中，具体取决于您从何处访问向导。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/3c7bf1a9-d7ed-4da8-81a4-141b0c6cd5bc.png)

如果您需要创建现有 AVD 的副本，请按照以下说明进行操作：

1.  打开 AVD 管理器，右键单击 AVD 实例，然后选择“复制”。

1.  按照向导的指示，在您修改所需内容后，单击“完成”。

1.  我们的 AVD 列表中出现了一个新的修改版本。

我们将通过从头开始创建一个新的硬件配置文件来演示处理硬件配置文件。要创建新的硬件配置文件，请按照以下说明进行操作。在“选择硬件”中，单击“新硬件配置文件”。请参考以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/c34dc3f9-363f-43e9-b4f5-bb38980fa738.png)

配置硬件配置文件出现。根据需要调整硬件配置文件属性。单击“完成”。您新创建的硬件配置文件将显示。

# 通过复制现有的 AVD 并根据需要进行修改

如果您需要基于现有硬件配置文件的硬件配置文件，请按照以下说明进行操作：

1.  选择现有的硬件配置文件，然后单击“克隆设备”。

1.  根据您的需求更新硬件配置文件属性。要完成向导，请单击“完成”。

1.  您的配置文件将显示在硬件配置文件列表中。

让我们回到 AVD 列表。在这里，您可以对任何现有的 AVD 执行以下操作：

+   单击“编辑”进行编辑

+   通过右键单击并选择删除来删除

+   通过右键单击 AVD 实例并选择在磁盘上显示来访问磁盘上的.ini 和.img 文件

+   要查看 AVD 配置详细信息，请右键单击 AVD 实例，然后选择“查看详细信息”

既然我们已经涵盖了这一点，让我们回到硬件配置文件列表。在这里，我们可以执行以下操作：

+   通过选择它并选择编辑设备来编辑硬件配置文件

+   通过右键单击并选择删除来删除硬件配置文件

您无法编辑或删除预定义的硬件配置文件！

然后，我们可以运行或停止模拟器，或者清除其数据，如下所示：

+   要运行使用 AVD 的模拟器，请双击 AVD 或只需选择“启动”

+   右键单击它并选择停止以停止它

+   要清除模拟器的数据，并将其返回到首次定义时的状态，请右键单击 AVD 并选择“擦除数据”

我们将继续介绍与`* -`一起使用的命令行功能，您可以使用这些功能。

要启动模拟器，请使用模拟器命令。我们将向您展示一些从终端启动虚拟设备的基本命令行语法：

```kt
emulator -avd avd_name [ {-option [value]} ... ]
```

另一个命令行语法如下：

```kt
emulator @avd_name [ {-option [value]} ... ]
```

让我们看一下以下示例：

```kt
$ /Users/vasic/Library/Android/sdk/tools/emulator -avd Nexus_5X_API_23 -netdelay none -netspeed full
```

您可以在启动模拟器时指定启动选项；稍后，您无法设置这些选项。

如果您需要可用 AVD 的列表，请使用此命令：

```kt
emulator -list-avds
```

结果是从 Android 主目录中列出 AVD 名称。您可以通过设置`ANDROID_SDK_HOME`环境变量来覆盖默认主目录。

停止模拟器很简单-只需关闭其窗口。

重要的是要注意，我们也可以从 Android Studio UI 运行 AVD！

# Android 调试桥

要访问设备，您将使用从终端执行的`adb`命令。我们将研究常见情况。

列出所有设备：

```kt
adb devices
```

控制台输出：

```kt
List of devices attached
emulator-5554 attached
emulator-5555 attached
```

获取设备的 shell 访问：

```kt
adb shell
```

访问特定设备实例：

```kt
adb -s emulator-5554 shell
```

其中`-s`代表设备来源。

从设备复制文件：

```kt
adb pull /sdcard/images ~/images
adb push ~/images /sdcard/images
```

卸载应用程序：

```kt
adb uninstall <package.name>  
```

`adb`最大的特点之一是你可以通过 telnet 访问它。使用`telnet localhost 5554`连接到你的模拟器设备。使用`quit`或`exit`命令终止你的会话。

让我们玩玩`adb`：

+   连接到设备：

```kt
        telnet localhost 5554
```

+   改变电源等级：

```kt
        power status full
        power status charging
```

+   或模拟一个电话：

```kt
        gsm call 223344556677
```

+   发送短信：

```kt
        sms send 223344556677 Android rocks
```

+   设置地理位置：

```kt
        geo fix 22 22  
```

使用`adb`，你还可以拍摄屏幕截图或录制视频！

# 其他重要工具

我们将介绍一些你在日常 Android 开发中需要的其他工具。

让我们从以下开始：

+   `adb dumpsys`：要获取系统和运行应用程序的信息，使用`adb dumpsys`命令。要获取内存状态，执行以下命令--`adb shell dumpsys meminfo <package.name>`。

下一个重要的工具如下：

+   `adb shell procrank`：`adb shell procrank`按照它们的内存消耗顺序列出了所有的应用程序。这个命令在实时设备上不起作用；你只能连接模拟器。为了达到同样的目的，你可以使用--`adb shell dumpsys meminfo`。

+   对于电池消耗，你可以使用--`adb shell dumpsys batterystats`--charged `<package-name>`。

+   下一个重要的工具是**Systrace**。为了分析你的应用程序的性能，通过捕获和显示执行时间，你将使用这个命令。

当你遇到应用程序故障问题时，Systrace 工具将成为一个强大的盟友！

它不适用于低于 20 的 Android SDK 工具！要使用它，你必须安装和配置 Python。

让我们试试吧！

要从 UI 访问它，打开 Android Studio 中的 Android Device Monitor，然后选择 Monitor：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/4725d134-3af5-45c5-bbf9-3ededd23281a.png)

有时，从终端（命令行）访问它可能更容易：

Systrace 工具有不同的命令行选项，取决于你设备上运行的 Android 版本。

让我们看一些例子：

一般用法：

```kt
$ python systrace.py [options] [category1] [category2] ... [categoryN]
```

+   Android 4.3 及更高版本：

```kt
        $ python systrace.py --time=15 -o my_trace_001.html 
        sched gfx  view wm
```

+   Android 4.2 及更低版本的选项：

```kt
        $ python systrace.py --set-tags gfx,view,wm
        $ adb shell stop
        $ adb shell start
        $ python systrace.py --disk --time=15 -o my_trace_001.html
```

我们要介绍的最后一个重要工具是`sdkmanager`。它允许你查看、安装、更新和卸载 Android SDK 的包。它位于`android_sdk/tools/bin/`中。

让我们看一些常见的使用示例：

列出已安装和可用的包：

```kt
sdkmanager --list [options]
```

+   安装包：

```kt
        sdkmanager packages [options]
```

你可以发送从`--list`命令得到的包。

+   卸载：

```kt
        sdkmanager --uninstall packages [options]
```

+   更新：

```kt
        sdkmanager --update [options]
```

在 Android 中还有一些其他工具可以使用，但我们只展示了最重要的工具。

# 初始化一个 Git 仓库

我们已经安装了 Android Studio 并介绍了一些重要的 SDK 工具。我们还学会了如何处理将运行我们的代码的模拟设备。现在是时候开始着手我们的项目了。我们将开发一个用于笔记和待办事项的小应用程序。这是每个人都需要的工具。我们将给它起一个名字--`Journaler`，它将是一个能够创建带有提醒的笔记和待办事项并与我们的后端同步的应用程序。

开发的第一步是初始化一个 Git 仓库。Git 将是我们的代码版本控制系统。你可以决定是否使用 GitHub、BitBucket 或其他远程 Git 实例。创建你的远程仓库并准备好它的 URL 以及你的凭据。那么，让我们开始吧！

进入包含项目的目录：

```kt
Execute: git init .
```

控制台输出将会是这样的：

```kt
Initialized empty Git repository in <directory_you_choose/.git>
```

我们初始化了仓库。

让我们添加第一个文件--`vi notes.txt`。

填充`notes.txt`并保存一些内容。

执行`git add .`来添加所有相关文件。

+   然后：`git commit -m "Journaler: First commit"`

控制台输出将会是这样的：

```kt
[master (root-commit) 5e98ea4]  Journaler: First commit
1 file changed, 1 insertion(+)
create mode 100644 notes.txt
```

你记得，你准备好了带有凭据的远程 Git 仓库`url`。将`url`复制到剪贴板中。现在，执行以下操作：

```kt
git remote add origin <repository_url> 
```

这将设置新的远程。

+   然后：`git remote -v`

这将验证新的远程 URL。

+   最后，将我们所有的东西推送到远程：`git push -u origin master`

如果要求输入凭据，请输入并按*Enter*确认。

# 创建 Android 项目

我们初始化了我们的代码仓库。现在是创建项目的时候了。启动 Android Studio 并选择以下内容：

开始一个新的 Android Studio 项目或文件 | 新建 | 新项目。

创建新项目，会出现一个窗口。

填写应用信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/8a36da05-3057-4868-8470-33ea224f5028.png)

然后，点击下一步。

勾选手机和平板选项，然后选择 Android 5.0 作为最低 Android 版本，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/45875cb2-148b-47a2-96d5-784235a8ebe0.png)

再次点击下一步。

选择添加无活动，然后点击完成，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/2ec3717d-dcb5-48af-a610-5181dee08b24.png)

等待项目创建完成。

你会注意到一个关于检测到未注册的 VCS 根的消息。点击添加根或转到首选项 | 版本控制 | ，然后从列表中选择我们的 Git 仓库，点击+图标，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/6c43b03b-7217-4fb7-928d-51febe52a8a8.png)

要确认一切，点击应用和确定。

在提交和推送之前，更新你的`.gitignore`文件。`.gitignore`文件的目的是允许你忽略文件，比如编辑器备份文件、构建产品或本地配置覆盖，你永远不想提交到仓库中。如果不符合`.gitignore`规则，这些文件将出现在 Git 状态输出的`未跟踪文件`部分中。

打开位于项目`root`目录的`.gitignore`并编辑它。要访问它，点击 Android Studio 左侧的项目，然后从下拉菜单中选择项目，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/15cfa9bb-76e5-4eaf-99d8-91f3661fc73d.png)

让我们添加一些行：

```kt
.idea
.gradle
build/
gradle*
!gradle-plugins*
gradle-app.setting
!gradle-wrapper.jar
.gradletasknamecache
local.properties
gen
```

然后，编辑位于`app`模块目录中的`.gitignore`：

```kt
*.class
.mtj.tmp/

*.jar
*.war
*.ear
 hs_err_pid*
.idea/*
.DS_Store
.idea/shelf
/android.tests.dependencies
/confluence/target
/dependencies
/dist
/gh-pages
/ideaSDK
/android-studio/sdk
out
tmp
workspace.xml
*.versionsBackup
/idea/testData/debugger/tinyApp/classes*
/jps-plugin/testData/kannotator
ultimate/.DS_Store
ultimate/.idea/shelf
ultimate/dependencies
ultimate/ideaSDK
ultimate/out
ultimate/tmp
ultimate/workspace.xml
ultimate/*.versionsBackup
.idea/workspace.xml
.idea/tasks.xml
.idea/dataSources.ids
.idea/dataSources.xml
.idea/dataSources.local.xml
.idea/sqlDataSources.xml
.idea/dynamic.xml
.idea/uiDesigner.xml
.idea/gradle.xml
.idea/libraries
.idea/mongoSettings.xml
*.iws
/out/
.idea_modules/
atlassian-ide-plugin.xml
com_crashlytics_export_strings.xml
crashlytics.properties
crashlytics-build.properties
fabric.properties
target/
pom.xml.tag
pom.xml.releaseBackup
pom.xml.versionsBackup
pom.xml.next
release.properties
dependency-reduced-pom.xml
buildNumber.properties
.mvn/timing.properties
!/.mvn/wrapper/maven-wrapper.jar
samples/*
build/*
.gradle/*
!libs/*.jar
!Releases/*.jar

credentials*.gradle
gen
```

你可以使用前面的`.gitignore`配置。现在我们可以提交和推送，在 macOS 上按*cmd* + *9*，在 Windows/Linux 上按*ctrl* + *9*（View | Tool Windows | Version Control 的快捷键）。展开未版本化的文件，选择它们，右键单击添加到 VCS。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/e5585919-893d-4466-ba70-60a24ba7bd6e.png)

按*Cmd* + *K*（或 Windows/Linux 上的*Ctrl* + *K*），勾选所有文件，输入提交消息，然后从提交下拉菜单中选择提交和推送。如果出现换行符警告，选择修复并提交。推送提交窗口将出现。勾选推送标签，选择当前分支，然后推送。

# 设置 Gradle

Gradle 是一个构建系统。你可以在没有它的情况下构建你的 Android 应用程序，但在那种情况下，你必须自己使用几个 SDK 工具。这并不简单！这是你需要 Gradle 和 Android Gradle 插件的部分。

Gradle 接收所有源文件并通过我们提到的工具处理它们。然后，它将所有内容打包成一个带有`.apk`扩展名的压缩文件。APK 可以解压缩。如果你将它的扩展名改为`.zip`，你可以提取内容。

每个构建系统都有自己的约定。最重要的约定是将源代码和资产放在具有适当结构的适当目录中。

Gradle 是基于 JVM 的构建系统，这意味着你可以用 Java、Groovy、Kotlin 等编写自己的脚本。此外，它是一个基于插件的系统，易于扩展。一个很好的例子是谷歌的 Android 插件。你可能在项目中注意到了`build.gradle`文件。它们都是用 Groovy 编写的，所以你写的任何 Groovy 代码都会被执行。我们将定义我们的 Gradle 脚本来自动化构建过程。让我们开始构建吧！打开`settings.gradle`并查看它：

```kt
include ":App" 
```

这个指令告诉 Gradle 它将构建一个名为`App`的模块。`App`模块位于我们项目的`app`目录中。

现在打开项目`root`中的`build.gradle`并添加以下行：

```kt
    buildscript { 
      repositories { 
        jcenter() 
        mavenCentral() 
      } 
      dependencies { 
        classpath 'com.android.tools.build:gradle:2.3.3' 
        classpath 'org.jetbrains.kotlin:kotlin-gradle-plugin:1.1.3' 
      } 
    } 

    repositories { 
      jcenter() 
      mavenCentral() 
    } 
```

我们定义了我们的构建脚本将从 JCenter 和 Maven Central 仓库解析其依赖项。相同的仓库将用于解析项目依赖项。主要依赖项被添加到目标，以便针对我们将拥有的每个模块：

+   Android Gradle 插件

+   Kotlin Gradle 插件

在更新了主`build.gradle`配置之后，打开位于`App 模块`目录中的`build.gradle`并添加以下行：

```kt
    apply plugin: "com.android.application" 
    apply plugin: "kotlin-android" 
    apply plugin: "kotlin-android-extensions" 
    android { 
      compileSdkVersion 26 
      buildToolsVersion "25.0.3" 
      defaultConfig { 
        applicationId "com.journaler" 
        minSdkVersion 19 
        targetSdkVersion 26 
        versionCode 1 
        versionName "1.0" 
        testInstrumentationRunner  
        "android.support.test.runner.AndroidJUnitRunner" 
      }  
       buildTypes {     
         release {   
           minifyEnabled false    
           proguardFiles getDefaultProguardFile('proguard- 
           android.txt'), 'proguard-rules.pro'    
         }
       }    
       sourceSets {   
         main.java.srcDirs += 'src/main/kotlin'  
       }}
       repositories { 
         jcenter()  
         mavenCentral()
       }dependencies {
          compile "org.jetbrains.kotlin:kotlin-stdlib:1.1.3"  
          compile 'com.android.support:design:26+'  
          compile 'com.android.support:appcompat-v7:26+'}
```

我们设置的配置使 Kotlin 成为项目和 Gradle 脚本的开发语言。然后，它定义了应用程序所需的最小和目标 sdk 版本。在我们的情况下，最小值是`19`，目标是`26`。重要的是要注意，在默认配置部分，我们还设置了应用程序 ID 和版本参数。依赖项部分为 Kotlin 本身和一些稍后将解释的 Android UI 组件设置了依赖项。

# 解释目录结构

Android Studio 包含构建应用程序所需的一切。它包含源代码和资产。所有目录都是由我们用来创建项目的向导创建的。要查看它，请在 IDE 的左侧打开项目窗口（单击查看 | 工具窗口 | 项目），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/b3847c62-65ac-49e5-b948-e99f4deaf4f8.png)

项目模块代表一组源文件、资产和构建设置，将项目分成离散的功能部分。`模块`的最小数量是一个。您的项目可以拥有的`模块`的最大数量没有实际限制。`模块`可以独立构建、测试或调试。正如您所看到的，我们定义了 Journaler 项目，只有一个名为 app 的模块。 

要添加新模块，请按照以下步骤进行：

转到文件 | 新建 | 新建模块。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/105d3754-d922-4893-8dc8-002cbfce41ea.png)

可以创建以下`模块`：

+   Android 应用程序模块代表应用程序源代码、资源和设置的容器。默认模块名称是 app，就像我们创建的示例中一样。

+   手机和平板电脑模块。

+   Android Wear 模块。

+   玻璃模块。

+   Android 电视模块。

+   `Library`模块代表可重用代码的容器--一个库。该模块可以作为其他应用程序模块的依赖项使用，或者导入其他项目。构建时，该模块具有 AAR 扩展名--Android 存档，而不是 APK 扩展名。

创建新模块窗口提供以下选项：

+   **Android 库**：在 Android 项目中支持所有类型。此库的构建结果是**Android 存档**（**AAR**）。

+   **Java 库**：仅支持纯 Java。此库的构建结果是**Java 存档**（**JAR**）。

+   **Google Cloud 模块**：定义了 Google Cloud 后端代码的容器。

重要的是要理解，Gradle 将`模块`称为单独的项目。如果您的应用程序代码依赖于名为**Logger**的 Android 库的代码，那么在**build.config**中，您必须包含以下指令：

```kt
    dependencies { 
      compile project(':logger') 
    } 
```

让我们浏览项目结构。Android Studio 默认使用的视图来显示项目文件是 Android 视图。它不代表磁盘上的实际文件层次结构。它隐藏了一些不经常使用的文件或目录。

Android 视图呈现如下内容：

+   所有与构建相关的配置文件

+   所有清单文件

+   所有其他资源文件都在一个组中

在每个应用程序中，模块内容分为以下组：

+   清单和`AndroidManifest.xml`文件。

+   应用程序和测试的 Java 和 Kotlin 源代码。

+   `res`和 Android UI 资源。

+   要查看项目的实际文件结构，请选择项目视图。要执行此操作，请单击 Android 视图，然后从下拉菜单中选择项目。

通过这样做，您将看到更多的文件和目录。其中最重要的是：

+   `module-name/`：这是模块的名称

+   `build/`：这是构建输出的保存位置

+   `libs/`：这保存私有库

+   `src/`：这保存模块的所有代码和资源文件，组织在以下子目录中：

+   `main`：这保存`main`源集文件——所有构建变体共享的源代码和资源（我们稍后会解释构建变体）

+   `AndroidManifest.xml`：这定义了我们的应用程序及其各个组件的性质

+   `java`：这保存 Java 源代码

+   `kotlin`：这保存 Kotlin 源代码

+   `jni`：这保存使用**Java Native Interface**（**JNI**）的本机代码

+   `gen`：这保存 Android Studio 生成的 Java 文件

+   `res`：这保存应用程序资源，例如**drawable**文件、布局文件、字符串等

+   `assets`：这保存应该编译成`.apk`文件的文件，不进行修改

+   `test`：这保存测试源代码

+   `build.gradle`：这是模块级别的构建配置

+   `build.gradle`：这是项目级别的构建配置

选择文件|项目结构以更改以下屏幕截图中项目的设置：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/67d1bc33-5015-43da-b9aa-16218dd7e137.png)

它包含以下部分：

+   SDK 位置：这设置项目使用的 JDK、Android SDK 和 Android NDK 的位置。

+   项目：这设置 Gradle 和 Android Gradle 插件版本

+   模块：这编辑特定于模块的构建配置

模块部分分为以下选项卡：

+   属性：这设置模块构建所需的 SDK 和构建工具的版本

+   签名：这设置 APK 签名的证书

+   口味：这为模块定义口味

+   构建类型：这为模块定义构建类型

+   依赖项：这设置模块所需的依赖项

请参考以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/c985a074-a164-4a44-b980-2619cd9fe97e.png)

# 定义构建类型和口味

我们正在接近项目的重要阶段——为我们的应用程序定义构建变体。构建变体代表 Android 应用程序的唯一版本。

它们是独特的，因为它们覆盖了一些应用程序属性或资源。

每个构建变体都是在模块级别配置的。

让我们扩展我们的`build.gradle`！将以下代码放入`build.gradle`文件的`android`部分：

```kt
    android { 
      ... 
      buildTypes { 
        debug { 
          applicationIdSuffix ".dev" 
        } 
        staging { 
          debuggable true 
          applicationIdSuffix ".sta" 
        } 
        preproduction { 
          applicationIdSuffix ".pre" 
        } 
           release {} 
        } 
       ... 
    }  
```

我们为我们的应用程序定义了以下`buildTypes`——`debug`、`release`、`staging`和`preproduction`。

产品口味的创建方式与`buildTypes`类似。您需要将它们添加到`productFlavors`并配置所需的设置。以下代码片段演示了这一点：

```kt
    android { 
      ... 
      defaultConfig {...} 
      buildTypes {...} 
      productFlavors { 
        demo { 
          applicationIdSuffix ".demo" 
          versionNameSuffix "-demo" 
        } 
        complete { 
          applicationIdSuffix ".complete" 
          versionNameSuffix "-complete" 
        } 
        special { 
          applicationIdSuffix ".special" 
          versionNameSuffix "-special" 
        } 
       } 
    } 
```

创建和配置`productFlavors`后，单击通知栏中的立即同步。

您需要等待一段时间才能完成该过程。构建变体的名称是通过`<product-flavor><Build-Type>`约定形成的。以下是一些示例：

```kt
    demoDebug 
    demoRelease 
    completeDebug 
    completeRelease 
```

您可以将构建变体更改为要构建和运行的构建变体。转到 Build，选择 Build Variant，然后从下拉菜单中选择`completeDebug`。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/c97ef034-fda4-4f99-82ef-bc807325851a.png)

`Main/source`集在您的应用程序的所有构建变体之间共享。如果您需要创建新的源集，可以为特定的构建类型、产品口味及其组合进行操作。

所有源集文件和目录必须以特定方式组织，类似于`Main/Source`集。特定于您的*debug*构建类型的 Kotlin 类文件必须位于`src/debug/kotlin/directory`中。

为了学习如何组织您的文件，打开终端窗口（View | ToolWindows | Terminal）并执行以下命令行：

```kt
./gradlew sourceSets
```

仔细查看输出。报告是可以理解和自解释的。Android Studio 不会创建`sourceSets`目录。这是您必须完成的工作。

如果需要，可以使用`sourceSets`块更改 Gradle 查找源集的位置。让我们更新我们的构建配置。我们将更新以下预期的源代码路径：

```kt
    android { 
      ... 
      sourceSets { 
       main { 
       java.srcDirs = [ 
                'src/main/kotlin', 
                'src/common/kotlin', 
                'src/debug/kotlin', 
                'src/release/kotlin', 
                'src/staging/kotlin', 
                'src/preproduction/kotlin', 
                'src/debug/java', 
                'src/release/java', 
                'src/staging/java', 
                'src/preproduction/java', 
                'src/androidTest/java', 
                'src/androidTest/kotlin' 
        ] 
        ... 
     } 
```

您希望仅与某些配置一起打包的代码和资源，可以存储在`sourceSets`目录中。这里提供了使用`demoDebug`构建变体的示例；此构建变体是`demo`产品风味和`debug`构建类型的产物。在 Gradle 中，对它们给予以下优先级：

```kt
    src/demoDebug/ (build variant source set) 
    src/debug/ (build type source set) 
    src/demo/ (product flavor source set) 
    src/main/ (main source set) 
```

这是 Gradle 在构建过程中使用的优先顺序，并在应用以下构建规则时考虑它：

+   它将`java/`和`kotlin/`目录中的源代码一起编译

+   它将清单合并到一个单一的清单中

+   它合并了`values/`目录中的文件

+   它合并了`res/`和`asset/`目录中的资源

资源和清单与库模块依赖项一起包含的优先级最低。

# 附加库

我们配置了构建类型和风味，现在我们需要一些第三方库。我们将使用并添加对 Retrofit、OkHttp 和 Gson 的支持。以下是它们的说明：

+   Retrofit 是 Square, Inc.为 Android 和 Java 开发的一种类型安全的 HTTP 客户端。Retrofit 是 Android 最受欢迎的 HTTP 客户端库之一，因为它与其他库相比，简单易用且性能出色。

+   `OkHttp`是一个默认情况下高效的 HTTP 客户端--HTTP/2 支持允许所有请求与同一主机共享套接字。

+   Gson 是一个 Java 库，可用于将 Java 对象转换为其 JSON 表示。它还可以用于将 JSON 字符串转换为等效的 Java 对象。Gson 可以处理包括您没有源代码的现有对象在内的任意 Java 对象。

有一些开源项目可以将 Java 对象转换为 JSON。在本书的后面，我们将添加 Kotson 以为 Kotlin 提供 Gson 绑定。

让我们通过添加 Retrofit 和 Gson 的依赖项来扩展`build.gradle`：

```kt
    dependencies { 
      ... 
      compile 'com.google.code.gson:gson:2.8.0' 
      compile 'com.squareup.retrofit2:retrofit:2.2.0' 
      compile 'com.squareup.retrofit2:converter-gson:2.0.2' 
      compile 'com.squareup.okhttp3:okhttp:3.6.0' 
      compile 'com.squareup.okhttp3:logging-interceptor:3.6.0' 
      ... 
    } 
```

在更新 Gradle 配置后，当要求时再次同步它！

# 熟悉 Android 清单

每个应用程序必须有一个`AndroidManifest.xml`文件，文件必须具有确切的名称。它的位置在其`root`目录中，在每个模块中，它包含有关应用程序的基本信息。`manifest`文件负责定义以下内容：

+   为应用程序命名一个包

+   描述应用程序的组件--活动（屏幕）、服务、广播接收器（消息）和内容提供程序（数据库访问）

+   应用程序必须具有的权限，以便访问 Android API 的受保护部分

+   其他应用程序必须具有的权限，以便与应用程序的组件进行交互，如内容提供程序

以下代码片段显示了`manifest`文件的一般结构和它可以包含的元素：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <manifest> 
      <uses-permission /> 
      <permission /> 
      <permission-tree /> 
      <permission-group /> 
      <instrumentation /> 
      <uses-sdk /> 
      <uses-configuration />   
      <uses-feature />   
      <supports-screens />   
      <compatible-screens />   
      <supports-gl-texture />   

      <application> 
        <activity> 
          <intent-filter> 
            <action /> 
              <category /> 
                <data /> 
            </intent-filter> 
            <meta-data /> 
        </activity> 

        <activity-alias> 
          <intent-filter> . . . </intent-filter> 
          <meta-data /> 
        </activity-alias> 

        <service> 
          <intent-filter> . . . </intent-filter> 
          <meta-data/> 
        </service> 

        <receiver> 
          <intent-filter> . . . </intent-filter> 
          <meta-data /> 
        </receiver> 
        <provider> 
          <grant-uri-permission /> 
          <meta-data /> 
          <path-permission /> 
        </provider> 

        <uses-library /> 
      </application> 
    </manifest> 
```

# 主应用程序类

每个 Android 应用程序都定义了其主要的`Application`类。Android 中的`Application`类是 Android 应用程序中包含所有其他组件（如`activities`和`services`）的基类。`Application`类或`Application`类的任何子类在创建应用程序/包的进程时都会首先实例化。

我们将为 Journaler 创建一个`Application`类。找到主要源目录。展开它，如果没有 Kotlin 源目录，请创建它。然后，创建`package com`和子包 journaler；为此，请右键单击 Kotlin 目录，然后选择**New** | **Package**。创建包结构后，右键单击**journaler**包，然后选择 New | KotlinFile/Class。命名为`Journaler`。创建了`Journaler.kt`。

每个`Application`类必须扩展 Android Application 类，就像我们的示例中所示的那样：

```kt
    package com.journaler 

    import android.app.Application 
    import android.content.Context 

    class Journaler : Application() { 

      companion object { 
        var ctx: Context? = null 
      } 

      override fun onCreate() { 
        super.onCreate() 
        ctx = applicationContext 
      } 

    } 
```

目前，我们的主`Application`类将为我们提供对应用程序上下文的静态访问。这个上下文将在以后解释。但是，Android 在清单中提到它之前不会使用这个类。打开`app`模块`android 清单`并添加以下代码块：

```kt
    <manifest http://www.w3.org/1999/xhtml" class="koboSpan" id="kobo.49.1">    res/android" package="com.journaler"> 

    <application 
        android:name=".Journaler" 
        android:allowBackup="false" 
        android:icon="@mipmap/ic_launcher" 
        android:label="@string/app_name" 
        android:roundIcon="@mipmap/ic_launcher_round" 
        android:supportsRtl="true" 
        android:theme="@style/AppTheme"> 

    </application> 
    </manifest> 
```

通过`android:name=".Journaler"`，我们告诉 Android 要使用哪个类。

# 你的第一个屏幕

我们创建了一个没有屏幕的应用程序。我们不会浪费时间，我们会创建一个！创建一个名为`activity`的新包，其中将定义所有我们的屏幕类，并创建您的第一个`Activity`类，名为`MainActivity.kt`。我们将从一个简单的类开始：

```kt
    package com.journaler.activity 

    import android.os.Bundle 
    import android.os.PersistableBundle 
    import android.support.v7.app.AppCompatActivity 
    import com.journaler.R 

    class MainActivity : AppCompatActivity() { 
      override fun onCreate(savedInstanceState: Bundle?,
      persistentState: PersistableBundle?) { 
        super.onCreate(savedInstanceState, persistentState) 
        setContentView(R.layout.activity_main) 
      } 
    } 
```

很快，我们将解释所有这些行的含义。现在，重要的是要注意`setContentView(R.layout.activity_main)`将 UI 资源分配给我们的屏幕，`activity_main`是定义它的 XML 的名称。由于我们还没有它，我们将创建它。在`main`目录下找到`res`目录。如果那里没有布局文件夹，请创建一个，然后通过右键单击`布局`目录并选择新建|布局资源文件来创建一个名为`activity_main`的新布局。将`activity_main`指定为其名称，`LinearLayout`指定为其根元素。文件的内容应该类似于这样：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout http://www.w3.org/1999/xhtml" class="koboSpan" id="kobo.34.1">     apk/res/android" 
      android:orientation="vertical" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent"> 

   </LinearLayout> 
```

在我们准备运行应用程序之前，还有一件事要做：我们必须告诉清单关于这个屏幕。打开`主清单`文件并添加以下代码：

```kt
    <application ... > 
      <activity 
        android:name=".activity.MainActivity" 
        android:configChanges="orientation" 
        android:screenOrientation="portrait"> 
        <intent-filter> 
          <action android:name="android.intent.action.MAIN" /> 
          <category android:name="android.intent.category.LAUNCHER" /> 
        </intent-filter> 
      </activity> 
    </application> 
```

我们很快会解释所有这些属性；现在你需要知道的是你的应用程序已经准备好运行了。但是，在此之前，`提交并推送`你的工作。你不想丢失它！

# 总结

在本章中，我们介绍了 Android 的基础知识，并展示了 Kotlin 的一瞥。我们配置了一个工作环境，并制作了我们应用程序的第一个屏幕。

在下一章中，我们将深入探讨 Android 的问题。您将学习如何构建您的应用程序并自定义不同的变体。我们还将介绍运行应用程序的不同方式。


# 第二章：构建和运行

在这一点上，您已成功创建了一个包含一个屏幕的 Android 项目。在上一章中，您还学会了如何设置您的工作环境。我们向您展示了使用 Android 工具是多么简单。您还定义了一些风味和构建类型。让我们控制它！现在是时候进行您的第一个构建并在设备或模拟器上运行它了。您将尝试使用所有构建类型和风味组合。

本章将涵盖以下内容：

+   在模拟器和/或实际硬件设备上运行您的应用程序

+   Logcat 简介

+   Gradle 工具

# 运行您的第一个 Android 应用程序

我们制作了我们的第一个屏幕，并为应用程序本身定义了一些具体内容。为了确保我们迄今为止所做的一切都没问题，我们将构建并运行我们的应用程序。我们将运行 completeDebug 构建变体。如果您忘记了如何切换到这个构建变体，我们会提醒您。打开 Android Studio 和`Journaler`项目。通过单击 Android Studio 窗口左侧的 Build Variants 窗格或选择 View | Tool Windows | Build Variants 来打开 Build Variants 窗格。Build Variants 窗格将出现。选择下拉列表中的 completeDebug，如屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/11d63f63-a319-436b-b3c9-582e52699a2e.png)

我们将使用这个构建变体作为我们的主要构建变体进行尝试执行，对于生产构建，我们将使用 completeDebug 构建变体。在我们从下拉列表中选择构建变体之后，Gradle 需要一些时间来构建所选择的变体。

我们现在将运行我们的应用程序。我们将首先在模拟器上运行，然后在实际设备上运行。通过打开 AVD Manager 来启动您的模拟器实例。单击 AVD Manager 图标来打开它。这是最快的打开方式。双击 AVD 实例。直到您的模拟器准备就绪，这需要一些时间。模拟器执行 Android 系统引导，然后加载默认应用程序启动器。

您的模拟器已启动并准备运行应用程序。为了运行应用程序，单击运行图标或导航到 Run | Run 'app'。

有一个键盘快捷键；在 macOS 上，它是*Ctrl* + *R*。

当应用程序运行时，会出现“选择部署目标”对话框。如果您有多个实例可以运行应用程序，您可以选择其中一个，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/7c3c0c18-8682-4c61-a468-9b3a11ef7a21.png)

选择您的部署目标并单击“确定”。如果您想记住您的选择，请勾选“将来启动时使用相同的选择”。应用程序需要一些时间来运行，但几秒钟后，您的应用程序就会出现！

# 了解 Logcat

Logcat 是日常开发的重要组成部分。它的目的是显示来自您设备的所有日志。它显示来自模拟器或连接的实际设备的日志。Android 有几个级别的日志消息：

+   断言

+   冗长的

+   调试

+   信息

+   警告

+   错误

您可以通过这些日志级别（例如，当您需要仅查看错误--应用程序崩溃堆栈跟踪时）或日志标签（我们稍后会解释）或关键字、正则表达式或应用程序包来过滤日志消息。在应用任何过滤器之前，我们将配置 Android Studio，以便日志消息以不同的颜色显示。

选择 Android Studio | Preferences。在搜索字段中输入`Logcat`。Logcat 着色首选项将出现，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/57490132-7256-442c-9d06-32aa4651e288.png)

要编辑颜色，您必须保存当前颜色主题的副本。从下拉列表中选择您的主题，然后选择“另存为”。选择一个合适的名称并确认：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/2b8bb47d-87a0-4041-96b7-72166b35e787.png)

从列表中选择断言，并取消选中使用继承的属性以覆盖颜色。确保前景选项被选中，并点击位于复选框右侧的颜色来选择日志文本的新颜色。我们将选择一些粉色的色调，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/bfbdcad0-4196-47da-acf6-1bff905e7c06.png)

对于断言级别，你可以手动输入十六进制代码：`FF6B68`。为了最大的可读性，我们建议以下颜色：

+   断言：`#FF6B68`

+   冗长：`#BBBBBB`

+   调试：`#F4F4F4`

+   信息：`#6D82E3`

+   警告：`#E57E15`

+   错误：`#FF1A11`

要应用更改，点击应用，然后点击确定。

打开 Android Monitor（View | Tool Windows | Android Monitor）并查看在 Logcat 窗格中打印的消息。它们以不同的色调着色，每个日志级别都不同，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/438b8ce2-45ce-4232-9177-5c5222e5f4cf.png)

现在我们将定义我们自己的日志消息，这也是一个与 Android 生命周期一起工作的好机会。我们将为我们创建的`Application`类和屏幕（活动）的每个生命周期事件放置适当的日志消息。

打开你的主`Application`类，`Journaler.kt`。扩展代码如下：

```kt
    class Journaler : Application() { 

      companion object { 
        val tag = "Journaler" 
        var ctx: Context? = null 
      } 

      override fun onCreate() { 
        super.onCreate() 
        ctx = applicationContext 
        Log.v(tag, "[ ON CREATE ]") 
      } 

      override fun onLowMemory() { 
        super.onLowMemory() 
        Log.w(tag, "[ ON LOW MEMORY ]") 
      } 

      override fun onTrimMemory(level: Int) { 
        super.onTrimMemory(level) 
        Log.d(tag, "[ ON TRIM MEMORY ]: $level") 
     } 
    } 
```

在这里，我们引入了一些重要的更改。我们重写了`onCreate()`应用程序的主要生命周期事件。我们还重写了另外两个方法：`onLowMemory()`，在内存紧张的情况下触发（正在运行的进程应该减少内存使用），以及`onTrimMemory()`，当内存被修剪时。

为了记录我们应用程序中的事件，我们使用`Log`类的静态方法，每个方法都暴露了适当的日志级别。基于此，我们有以下方法暴露：

+   对于冗长级别：

```kt
        v(String tag, String msg) 
        v(String tag, String msg, Throwable tr) 
```

+   对于调试级别：

```kt
        d(String tag, String msg) 
        d(String tag, String msg, Throwable tr) 
```

+   对于信息级别：

```kt
        i(String tag, String msg) 
        i(String tag, String msg, Throwable tr) 
```

+   对于警告级别：

```kt
        w(String tag, String msg) 
        w(String tag, String msg, Throwable tr) 
```

+   对于错误级别：

```kt
        e(String tag, String msg) 
        e(String tag, String msg, Throwable tr) 
```

方法接受以下参数：

+   `标签`：用于标识日志消息的来源

+   `message`: 这是我们想要记录的消息

+   `throwable`: 这代表要记录的异常

除了这些日志方法，还有一些其他方法可以使用：

+   `wtf(String tag, String msg)`

+   `wtf(String tag, Throwable tr)`

+   `wtf(String tag, String msg, Throwable tr)`

**Wtf**代表**What a Terrible Failure**！`Wtf`用于报告不应该发生的异常！

我们将继续使用`Log`类。打开到目前为止创建的唯一屏幕，并使用以下更改更新`MainActivity`类：

```kt
    class MainActivity : AppCompatActivity() { 
      private val tag = Journaler.tag 

      override fun onCreate( 
        savedInstanceState: Bundle?,  
        persistentState: PersistableBundle? 
       ) { 
          super.onCreate(savedInstanceState, persistentState) 
          setContentView(R.layout.activity_main) 
          Log.v(tag, "[ ON CREATE ]") 
         } 

       override fun onPostCreate(savedInstanceState: Bundle?) { 
         super.onPostCreate(savedInstanceState) 
         Log.v(tag, "[ ON POST CREATE ]") 
       } 

       override fun onRestart() { 
         super.onRestart() 
         Log.v(tag, "[ ON RESTART ]") 
       } 

       override fun onStart() { 
         super.onStart() 
         Log.v(tag, "[ ON START ]") 
       } 

       override fun onResume() { 
         super.onResume() 
         Log.v(tag, "[ ON RESUME ]") 
       } 

       override fun onPostResume() { 
         super.onPostResume() 
         Log.v(tag, "[ ON POST RESUME ]") 
       } 

       override fun onPause() { 
        super.onPause() 
        Log.v(tag, "[ ON PAUSE ]") 
      } 

      override fun onStop() { 
        super.onStop() 
        Log.v(tag, "[ ON STOP ]") 
      } 

      override fun onDestroy() { 
        super.onDestroy() 
        Log.v(tag, "[ ON DESTROY ]") 
      } 
    } 
```

我们按照活动生命周期中它们执行的顺序重写了所有重要的生命周期方法。对于每个事件，我们打印适当的日志消息。让我们解释生命周期的目的和每个重要事件。

在这里，你可以看到来自 Android 开发者网站的官方图表，解释了活动的生命周期：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/41a10a88-8f9d-4fcb-b24a-28f5f348faf0.png)

你可以在[`developer.android.com/images/activity_lifecycle.png`](https://developer.android.com/images/activity_lifecycle.png)找到这张图片：

+   `onCreate()`: 当活动第一次创建时执行。这通常是我们初始化主要 UI 元素的地方。

+   `onRestart()`: 如果你的活动在某个时刻停止然后恢复，这将被执行。例如，你关闭手机屏幕（锁定它），然后再次解锁。

+   `onStart()`: 当屏幕对应用程序用户可见时执行。

+   `onResume()`: 当用户开始与活动交互时执行。

+   `onPause()`: 在我们恢复之前的活动之前，这个方法在当前活动上执行。这是一个保存所有你在下次恢复时需要的信息的好地方。如果有任何未保存的更改，你应该在这里保存它们。

+   `onStop()`: 当活动对应用程序用户不再可见时执行。

+   `onDestroy()`：这是在 Android 销毁活动之前执行的。例如，如果有人执行了`Activity`类的`finish()`方法，就会发生这种情况。要知道活动是否在特定时刻结束，Android 提供了一个检查的方法：`isFinishing()`。如果活动正在结束，该方法将返回布尔值`true`。

现在，当我们使用 Android 生命周期编写了一些代码并放置了适当的日志消息后，我们将执行两个用例，并查看 Logcat 打印出的日志。

# 第一种情况

运行您的应用程序。然后只需返回并离开。关闭应用程序。打开 Android Monitor，并从设备下拉列表中选择您的设备实例（模拟器或真实设备）。从下一个下拉列表中，选择 Journaler 应用程序包。观察以下 Logcat 输出：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/cecbe102-def8-4013-9a3c-c1e5b8c06d2e.png)

您会注意到我们在源代码中放置的日志消息。

让我们检查一下在我们与应用程序交互期间我们进入`onCreate()`和`onDestroy()`方法的次数。将光标放在搜索字段上，然后键入`on create`。观察内容的变化--我们预期会有两个条目，但只有一个：一个是主`Application`类的条目，另一个是主活动的条目。为什么会发生这种情况？我们稍后会找出原因：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/e799dc39-8f47-4598-a9a0-d873f3736f18.png)

我们的输出包含什么？它包含以下内容：

`06-27`：这是事件发生的日期。

`11:37:59.914`：这是事件发生的时间。

`6713-6713/?`：这是带有包的进程和线程标识符。如果应用程序只有一个线程，进程和线程标识符是相同的。

`V/Journaler`：这是日志级别和标记。

`[ ON CREATE ]`：这是日志消息。

将过滤器更改为`on destroy`。内容更改为以下内容：

`**06-27 11:38:07.317 6713-6713/com.journaler.complete.dev V/Journaler: [ ON DESTROY ]**`

在你的情况下，你会有不同的日期、时间和 pid/tid 值。

从下拉列表中，将过滤器从 Verbose 更改为 Warn。保持过滤器的值！您会注意到您的 Logcat 现在是空的。这是因为没有警告消息包含`on destroy`的消息文本。删除过滤器文本并返回到 Verbose 级别。

运行您的应用程序。锁定屏幕并连续解锁几次。然后，关闭并终止 Journaler 应用程序。观察以下 Logcat 输出：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/eac186f5-fbbf-4970-ac93-48a010ae8480.png)

正如您所看到的，它明显地进入了暂停和恢复的生命周期状态。最后，我们终止了我们的应用程序，并触发了一个`onDestroy()`事件。您可以在 Logcat 中看到它。

如果对您来说更容易，您可以从终端使用 Logcat。打开终端并执行以下命令行：

```kt
adb logcat
```

# 使用 Gradle 构建工具

在我们的开发过程中，我们需要构建不同的构建变体或运行测试。如果需要，这些测试可以仅针对某些构建变体执行，或者针对所有构建变体执行。

在以下示例中，我们将涵盖一些最常见的 Gradle 用例。我们将从清理和构建开始。

正如您记得的，Journaler 应用程序定义了以下构建类型：

+   调试

+   发布

+   暂存

+   预生产

Journaler 应用程序中还定义了以下构建风味：

+   演示

+   完成

+   特殊

打开终端。要删除到目前为止构建的所有内容和所有临时构建派生物，请执行以下命令行：

```kt
./gradlew clean
```

清理需要一些时间。然后执行以下命令行：

```kt
./gradlew assemble.
```

这将组装所有--我们应用程序中拥有的所有构建变体。想象一下，如果我们正在处理一个非常庞大的项目，它可能会产生什么时间影响。因此，我们将`隔离`构建命令。要仅构建调试构建类型，请执行以下命令行：

```kt
./gradlew assembleDebug 
```

这将比上一个例子执行得快得多！这为调试构建类型构建了所有的 flavor。为了更有效，我们将指示 Gradle 我们只对调试构建类型的完整构建 flavor 感兴趣。执行这个：

```kt
./gradlew assembleCompleteDebug
```

这将执行得更快。在这里，我们将提到几个更重要的 Gradle 命令：

要运行所有单元测试，请执行：

```kt
./gradlew test 
```

如果你想为特定的构建变体运行单元测试，请执行以下命令：

```kt
./gradlew testCompleteDebug
```

在 Android 中，我们可以在真实设备实例或模拟器上运行测试。通常，这些测试可以访问一些 Android 组件。要执行这些（仪器）测试，你可以使用以下示例中显示的命令：

```kt
./gradlew connectedCompleteDebug
```

你将在本书的最后章节中找到更多关于测试和测试 Android 应用程序的内容。

# 调试你的应用程序

现在，我们知道如何记录重要的应用程序消息。在开发过程中，当分析应用程序行为或调查 bug 时，仅仅记录消息是不够的。

对我们来说，能够在真实的 Android 设备或模拟器上执行应用程序代码时进行调试是很重要的。所以，让我们来调试一些东西！

打开主`Application`类，并在我们记录`onCreate()`方法的行上设置断点，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/c08f7d7a-eabc-4c78-9442-00549f6bce2b.png)

正如你所看到的，我们在第 18 行设置了断点。我们将添加更多断点。让我们在我们的主（也是唯一的）活动中添加。在我们执行日志记录的行上的每个生命周期事件中放置一个断点。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/d5bd3bbf-b390-4c1c-a975-0cb06dfcfc66.png)

我们在第 18、23、28、33、38 行设置了断点。通过点击调试图标或选择运行|调试应用程序，在调试模式下运行应用程序。应用程序以调试模式启动。稍等一会儿，调试器很快就会进入我们设置的第一个断点。

以下的截图说明了这一点：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/f8821a88-c161-468e-83e5-b756a456f73d.png)

正如你所看到的，`Application`类的`onCreate()`方法是我们进入的第一个方法。让我们检查一下我们的应用程序是否按预期进入了生命周期方法。点击调试器窗格中的恢复程序图标。你可能会注意到，我们没有进入主活动的`onCreate()`方法！我们在主`Application`类的`onCreate()`方法之后进入了`onStart()`。恭喜你！你刚刚发现了你的第一个 Android bug！为什么会发生这种情况呢？我们使用了错误的`onCreate()`方法版本，而不是使用以下代码行：

```kt
    void onCreate(@Nullable Bundle savedInstanceState) 
```

我们不小心重写了这个：

```kt
     onCreate(Bundle savedInstanceState, PersistableBundle 
     persistentState) 
```

多亏了调试，我们发现了这个！通过点击调试器窗格中的停止图标来停止调试器并修复代码。将代码行更改为这样：

```kt
    override fun onCreate(savedInstanceState: Bundle?) { 
      super.onCreate(savedInstanceState) 
      setContentView(R.layout.activity_main) 
      Log.v(tag, "[ ON CREATE 1 ]") 
    } 

    override fun onCreate(savedInstanceState: Bundle?, 
    persistentState: PersistableBundle?) { 
      super.onCreate(savedInstanceState, persistentState) 
      Log.v(tag, "[ ON CREATE 2 ]") 
    } 
```

我们更新了我们的日志消息，这样我们就可以跟踪进入`onCreate()`方法的两个版本。保存你的更改，并以调试模式重新启动应用程序。不要忘记为两个`onCreate()`方法重写设置断点！逐个通过断点。现在我们按预期的顺序进入了所有断点。

要查看所有断点，请点击查看断点图标。断点窗口会出现，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/02511c6a-2efb-4eb7-9be8-626cf161c46a.png)

双击断点，你将定位到设置断点的行。停止调试器。

想象一下，您可以继续开发您的应用程序两年。您的应用程序变得非常庞大，并且还执行一些昂贵的操作。直接在调试模式下运行它可能非常困难和耗时。直到它进入我们感兴趣的断点之前，我们将浪费大量时间。我们能做些什么呢？在调试模式下运行的应用程序速度较慢，而我们的应用程序又又大又慢。如何跳过我们正在浪费宝贵时间的部分？我们将进行演示。通过单击运行图标或选择运行|运行'app'来运行您的应用程序。应用程序在我们的部署目标（真实设备或模拟器）上执行并启动。通过单击附加调试器到 Android 进程图标或选择运行|附加调试器到 Android 来将调试器附加到您的应用程序。选择出现的进程窗口：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/fe6a2ead-2e17-4ef6-be40-deb9a66ad8ad.png)

通过双击其包名称来选择我们的应用程序过程。调试器窗格出现。从您的应用程序中，尝试返回。**调试器**进入主活动的`onPause()`方法。停止调试器。

# 总结

在这一章中，您学会了如何从 Android Studio IDE 或直接从终端构建和运行应用程序。我们还分析了一些来自模拟器和真实设备的日志。最后，我们进行了一些调试。

在下一章中，我们将熟悉一些 UI 组件--屏幕，更准确地说。我们将向您展示如何创建新屏幕以及如何为它们添加一些时尚细节。我们还将讨论按钮和图像的复杂布局。


# 第三章：屏幕

一个只有简单用户界面的屏幕一点也不令人兴奋。然而，在你进行眼睛糖样式和*哇*效果之前，你需要创建更多包含专业开发应用程序必须具有的所有元素的屏幕。你在日常生活中使用的现代应用程序中都可以看到这一点。在上一章中，我们构建并运行了我们的项目。这种技能很重要，这样我们才能继续我们的进展。现在你将在你的应用程序中添加一个 UI！

在本章中，我们将涵盖以下主题：

+   分析模拟

+   定义应用程序活动

+   Android 布局

+   Android 上下文

+   片段、片段管理器和堆栈

+   视图翻页器

+   事务、对话框片段和通知

+   其他重要的 UI 组件

# 分析模拟计划

事情正在变得有趣！我们准备开始一些严肃的开发！我们将为我们的应用程序创建所有的屏幕。然而，在我们创建它们之前，我们将创建并分析一个模拟，这样我们就知道我们将创建什么。模拟将代表基本的应用程序线框，没有设计。它只是屏幕和它们之间的关系的布局。要创建一个带有线框的好模拟，你需要一个工具。任何能够画线的工具都可以胜任。为了绘制我们的模拟，我们使用了**Pencil**。Pencil 是一个提供 GUI 原型的免费开源应用程序。

让我们来看看我们的模拟：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/4a326c99-c11c-47a3-8633-6e16ed711c6b.png)

正如你所看到的，模拟呈现了一个相对简单的应用程序，具有一些屏幕。这些屏幕将包含不同的组件，我们将在每个屏幕中解释这些组件。让我们来看看模拟。

第一个屏幕，标题为登陆界面，将是我们的主要应用程序屏幕。每次进入应用程序时，都会出现此屏幕。我们已经定义了`MainActivity`类。这个活动将代表这个屏幕。很快，我们将扩展代码，使活动完全按照模拟进行。

屏幕的中心部分将是包含我们创建的所有项目的列表。每个项目将包含基本属性，如标题或日期和时间。我们将能够按类型过滤项目。我们将只能过滤笔记或 TODO。笔记和 TODO 之间的区别在于 TODO 将代表具有分配的*日期*和*时间*的任务。我们还将支持一些功能，如长按事件。在每个项目上的长按事件将呈现一个弹出菜单，其中包含编辑、删除或完成选项。点击编辑将打开更新屏幕。

在右下角，我们将有一个+按钮。该按钮的目的是打开选项对话框，用户可以选择他们想要创建笔记还是 TODO 任务。根据选项，用户可以选择出现的屏幕之一--添加笔记屏幕或添加 TODO 屏幕。

登陆界面还包含位于左上角的滑动菜单按钮。点击该按钮将打开滑动菜单，其中包含以下项目：

+   一个带有应用程序标题和版本的应用程序图标

+   一个今天的按钮，用于仅过滤分配给当前日期的 TODO 项目

+   一个下一个 7 天的按钮，用于过滤分配给下一个 7 天的 TODO 项目，包括当前的日期

+   一个 TODO 按钮仅过滤 TODO 项目

+   笔记按钮将仅过滤笔记项目

应用一些过滤器将影响我们通过点击登陆界面右上角获得的弹出菜单中的复选框。此外，选中和取消选中这些复选框将修改当前应用的过滤器。

滑动菜单中的最后一项是立即同步。点击此按钮将触发同步，并将所有未同步的项目与后端进行同步。

现在我们将解释两个负责创建（或编辑）笔记和 TODO 的屏幕：

+   添加/编辑笔记屏幕：用于创建新的笔记或更新现有内容。当编辑文本字段聚焦时，键盘将打开。由于我们计划立即应用我们所做的所有更改，因此没有保存或更新按钮。在此屏幕上，左上角和右上角的按钮也被禁用。

+   添加/编辑 TODO 屏幕：用于创建新的 TODO 应用程序或更新现有内容。键盘将像前面的示例一样打开。也没有像前面的示例中显示的保存或更新按钮。左上角和右上角的按钮也被禁用。在标题视图之后，我们有按钮来选择日期和时间。默认情况下，它们将设置为当前日期和时间。打开键盘将推动这些按钮。

我们已经涵盖了基本的 UI 和通过分析这个模型我们想要实现的内容。现在是时候创建一些新的屏幕了。

# 定义应用程序活动

总之，我们将有三个活动：

+   登陆活动（`MainActivty.kt`）

+   添加/编辑笔记屏幕

+   添加/编辑 TODO 屏幕

在 Android 开发中，通常会创建一个活动，作为所有其他活动的父类，因为这样，我们将减少代码库，并同时与多个活动共享。在大多数情况下，Android 开发人员称之为`BaseActivity`。我们将定义我们自己的`BaseActivity`版本。创建一个名为`BaseActivity`的新类；创建`BaseActivity.kt`文件。确保新创建的类位于项目的`Activity`包下。

`BaseActivity`类必须扩展 Android SDK 的`FragmentActivity`类。我们将扩展`FragmentActivity`，因为我们计划在`MainActivity`类中使用片段。片段将与 ViewPager 一起使用，以在不同的过滤器之间导航（今天，接下来的 7 天等）。我们计划当用户从我们的侧滑菜单中点击其中一个时，ViewPager 会自动切换到包含由所选条件过滤的数据的片段的位置。我们将从包`android.support.v4.app.FragmentActivity`扩展`FragmentActivity`。

Android 提供了支持多个 API 版本的方法。因为我们计划这样做，我们将使用支持库中的`FragmentActivity`版本。这样，我们最大化了兼容性！要为 Android 支持库添加支持，请在`build.gradle`配置中包含以下指令：

```kt
    compile 'com.android.support:appcompat-v7:26+' 
```

您可能还记得，我们已经这样做了！

让我们继续！由于我们正在为所有活动引入一个基类，我们现在必须对我们现有的唯一活动进行一些小的重构。我们将`tag`字段从`MainActivity`移动到`BaseActivity`。由于它必须对`BaseActivity`的子类可访问，我们将更新其可见性为`protected`。

我们希望每个`Activity`类都有其独特的标签。我们将使用活动具体化来选择其标签的值。因此，`tag`字段变为`abstract`，没有分配默认值：

```kt
    protected abstract val tag : String 
```

此外，所有活动中还有一些共同的东西。每个活动都将有一个布局。布局在 Android 中由整数类型的 ID 标识。在`BaseActivity`类中，我们将创建一个`abstract`方法，如下：

```kt
    protected abstract fun getLayout(): Int 
```

为了优化代码，我们将把`onCreate`从`MainActivity`移动到`BaseActivity`。我们将不再直接传递 Android 生成的资源中布局的 ID，而是传递`getLayout()`方法的结果值。我们也会移动所有其他生命周期方法的覆盖。

根据这些更改更新您的类，并按以下方式构建和运行应用程序：

```kt
    BasicActivity.kt:
    package com.journaler.activity 
    import android.os.Bundle 
    import android.support.v4.app.FragmentActivity 
    import android.util.Log 

    abstract class BaseActivity : FragmentActivity() { 
      protected abstract val tag : String 
      protected abstract fun getLayout(): Int 

      override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        setContentView(getLayout()) 
        Log.v(tag, "[ ON CREATE ]") 
      } 

      override fun onPostCreate(savedInstanceState: Bundle?) { 
        super.onPostCreate(savedInstanceState) 
        Log.v(tag, "[ ON POST CREATE ]") 
      } 

      override fun onRestart() { 
        super.onRestart() 
        Log.v(tag, "[ ON RESTART ]") 
      } 

      override fun onStart() { 
        super.onStart() 
        Log.v(tag, "[ ON START ]") 
      } 

      override fun onResume() { 
        super.onResume() 
        Log.v(tag, "[ ON RESUME ]") 
      } 

      override fun onPostResume() { 
        super.onPostResume() 
        Log.v(tag, "[ ON POST RESUME ]") 
      } 

      override fun onPause() { 
        super.onPause() 
        Log.v(tag, "[ ON PAUSE ]") 
      } 

      override fun onStop() { 
        super.onStop() 
        Log.v(tag, "[ ON STOP ]") 
      } 

      override fun onDestroy() { 
        super.onDestroy() 
        Log.v(tag, "[ ON DESTROY ]") 
      } 

    } 
    MainActivity.kt:
    package com.journaler.activity 
    import com.journaler.R 

    class MainActivity : BaseActivity() { 
      override val tag = "Main activity" 
      override fun getLayout() = R.layout.activity_main 
    }
```

现在，我们准备定义其余的屏幕。我们必须创建一个用于添加和编辑笔记的屏幕，以及一个用于 TODO 的相同功能的屏幕。这些屏幕之间有很多共同之处。目前唯一的区别是 TODO 屏幕有日期和时间的按钮。我们将为这些屏幕共享的所有内容创建一个通用类。每个具体化都将扩展它。创建一个名为`ItemActivity`的类。确保它位于`Activity`包中。再创建两个类--`NoteActivity`和`TodoActivity`。`ItemActivity`扩展我们的`BaseActivity`类，`NoteActivity`和`TodoActivity`活动类扩展`ItemActivity`类。您将被要求覆盖成员。请这样做。为我们在日志中使用的标签赋予一些有意义的值。要分配适当的布局 ID，首先我们必须创建它！

找到我们为主屏幕创建的布局。现在，使用相同的原则，创建另外两个布局：

+   `activity_note.xml`，如果被问到，让它成为`LinearLayout`类。

+   `activity_todo.xml`，如果被问到，让它成为`LinearLayout`类

在 Android 中，任何布局或布局成员都会在构建过程中由 Android 生成的`R`类中获得唯一的 ID 作为`integer`表示。我们应用程序的`R`类如下：

```kt
    com.journaler.R 
```

要访问布局，请使用以下代码行：

```kt
    R.layout.layout_you_are_interested_in 
```

我们使用静态访问。因此，让我们更新我们的类具体化以访问布局 ID。类现在看起来像这样：

```kt
    ItemActivity.kt:
    abstract class ItemActivity : BaseActivity()
    For now, this class is short and simple.
    NoteActivity.kt:
    package com.journaler.activity
    import com.journaler.R
    class NoteActivity : ItemActivity(){
      override val tag = "Note activity"
      override fun getLayout() = R.layout.activity_note 
    }
    Pay attention on import for R class!
    TodoActivity.kt: 
    package com.journaler.activity 
    import com.journaler.Rclass TodoActivity : ItemActivity(){
      override val tag = "Todo activity" 
      override fun getLayout() = R.layout.activity_todo
    }
```

最后一步是在`view groups`中注册我们的屏幕（活动）。打开`manifest`文件并添加以下内容：

```kt
    <activity 
      android:name=".activity.NoteActivity" 
      android:configChanges="orientation" 
      android:screenOrientation="portrait" /> 

      <activity 
        android:name=".activity.TodoActivity" 
        android:configChanges="orientation" 
        android:screenOrientation="portrait" /> 
```

两个活动都锁定为“竖屏”方向。

我们取得了进展！我们定义了我们的应用程序屏幕。在下一节中，我们将用 UI 组件填充屏幕。

# Android 布局

我们将继续通过定义每个屏幕的布局来继续我们的工作。在 Android 中，布局是用 XML 定义的。我们将提到最常用的布局类型，并用常用的布局组件填充它们。

每个布局文件都有一个布局类型作为其顶级容器。布局可以包含其他具有 UI 组件等的布局。我们可以嵌套它。让我们提到最常用的布局类型：

+   **线性布局**：这将以线性顺序垂直或水平对齐 UI 组件

+   **相对布局**：这些 UI 组件相对地对齐

+   **列表视图布局**：所有项目都以列表形式组织

+   **网格视图布局**：所有项目都以网格形式组织

+   **滚动视图布局**：当其内容变得高于屏幕的实际高度时，用于启用滚动

我们刚刚提到的布局元素是`view groups`。每个视图组包含其他视图。`View groups`扩展了`ViewGroup`类。在顶部，一切都是`View`类。扩展`View`类但不扩展`ViewGroup`的类（视图）不能包含其他元素（子元素）。这样的例子是`Button`，`ImageButton`，`ImageView`和类似的类。因此，例如，可以定义一个包含`LinearLayout`的`RelativeLayout`，该`LinearLayout`包含垂直或水平对齐的其他多个视图等。

我们现在将突出显示一些常用的视图：

+   `Button`：这是一个与我们定义的`onClick`操作相关联的`Base`类按钮

+   `ImageButton`：这是一个带有图像作为其视觉表示的按钮

+   `ImageView`：这是一个显示从不同来源加载的图像的视图

+   `TextView`：这是一个包含单行或多行不可编辑文本的视图

+   `EditText`：这是一个包含单行或多行可编辑文本的视图

+   `WebView`：这是一个呈现从不同来源加载的渲染 HTML 页面的视图

+   `CheckBox`：这是一个主要的两状态选择视图

每个`View`和`ViewGroup`都支持杂项 XML 属性。一些属性仅适用于特定的视图类型。还有一些属性对所有视图都是相同的。我们将在本章后面的屏幕示例中突出显示最常用的视图属性。

为了通过代码或其他布局成员访问视图，必须定义一个唯一标识符。要为视图分配 ID，请使用以下示例中的语法：

```kt
    android:id="@+id/my_button" 
```

在这个例子中，我们为一个视图分配了`my_button` ID。要从代码中访问它，我们将使用以下方法：

```kt
    R.id.my_button 
```

`R`是一个生成的类，为我们提供对资源的访问。要创建按钮的实例，我们将使用 Android `Activity`类中定义的`findViewById()`方法：

```kt
    val x = findViewById(R.id.my_button) as Button 
```

由于我们使用了 Kotlin，我们可以直接访问它，如本例所示：

```kt
    my_button.setOnClickListener { ... } 
```

IDE 会询问您有关适当的导入。请记住，其他布局资源文件可能具有相同名称的 ID 定义。在这种情况下，可能会发生错误的导入！如果发生这种情况，您的应用程序将崩溃。

字符串开头的`@`符号表示 XML 解析器应解析并扩展 ID 字符串的其余部分，并将其标识为 ID 资源。`+`符号表示这是一个新的资源名称。当引用 Android 资源 ID 时，不需要`+`符号，如本例所示：

```kt
    <ImageView 
      android:id="@+id/flowers" 
      android:layout_width="fill_parent" 
      android:layout_height="fill_parent" 
      android:layout_above="@id/my_button" 
    /> 
```

让我们为主应用程序屏幕构建我们的 UI！我们将从一些先决条件开始。在值资源目录中，创建`dimens.xml`来定义我们将使用的一些尺寸：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <resources> 
      <dimen name="button_margin">20dp</dimen> 
      <dimen name="header_height">50dp</dimen> 
    </resources> 
```

Android 以以下单位定义尺寸：

+   **像素（pixels）**：这对应于屏幕上的实际像素

+   **英寸（inches）**：这是基于屏幕的物理尺寸，即 1 英寸=2.54 厘米

+   **毫米（millimeters）**：这是基于屏幕的物理尺寸

+   **点（points）**：这是基于屏幕的物理尺寸的 1/72

对我们来说最重要的是以下内容：

+   **dp（密度无关像素）**：这代表一个基于屏幕物理密度的抽象单位。它们相对于 160 DPI 的屏幕。一个 dp 在 160 DPI 屏幕上等于一个像素。dp 到像素的比率会随着屏幕密度的变化而改变，但不一定成正比。

+   **sp（可伸缩像素）**：这类似于 dp 单位，通常用于字体大小。

我们必须定义一个将包含在所有屏幕上的页眉布局。创建`activity_header.xml`文件并像这样定义它：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <RelativeLayout   xmlns:android=
    "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="@dimen/header_height"> 
    <Button 
      android:id="@+id/sliding_menu" 
      android:layout_width="@dimen/header_height" 
      android:layout_height="match_parent" 
      android:layout_alignParentStart="true" /> 

    <TextView 
      android:layout_centerInParent="true" 
      android:id="@+id/activity_title" 
      android:layout_width="wrap_content" 
      android:layout_height="wrap_content" /> 

    <Button 
      android:id="@+id/filter_menu" 
      android:layout_width="@dimen/header_height" 
      android:layout_height="match_parent" 
      android:layout_alignParentEnd="true" /> 

    </RelativeLayout> 
```

让我们解释其中最重要的部分。首先，我们将`RelativeLayout`定义为我们的主容器。由于所有元素都相对于父元素和彼此定位，我们将使用一些特殊属性来表达这些关系。

对于每个视图，我们必须有宽度和高度属性。其值可以如下：

+   在尺寸资源文件中定义的尺寸，例如：

```kt
        android:layout_height="@dimen/header_height" 
```

+   直接定义的尺寸值，例如：

```kt
        android:layout_height="50dp" 
```

+   匹配父级的大小（`match_parent`）

+   或者包装视图的内容（`wrap_content`）

然后，我们将使用子视图填充布局。我们有三个子视图。我们将定义两个按钮和一个文本视图。文本视图对齐到布局的中心。按钮对齐到布局的边缘——一个在左边，另一个在右边。为了实现文本视图的中心对齐，我们使用了`layout_centerInParent`属性。传递给它的值是布尔值 true。为了将按钮对齐到布局的左边缘，我们使用了`layout_alignParentStart`属性。对于右边缘，我们使用了`layout_alignParentEnd`属性。每个子视图都有一个适当的 ID 分配。我们将在`MainActivity`中包含这个：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout xmlns:android=
    "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:orientation="vertical"> 

    <include layout="@layout/activity_header" /> 

    <RelativeLayout 
        android:layout_width="match_parent" 
        android:layout_height="match_parent"> 
     <ListView 
        android:id="@+id/items" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:background="@android:color/darker_gray" /> 

     <android.support.design.widget.FloatingActionButton 
        android:id="@+id/new_item" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_alignParentBottom="true" 
        android:layout_alignParentEnd="true" 
        android:layout_margin="@dimen/button_margin" /> 

    </RelativeLayout> 
    </LinearLayout> 
```

`Main activity`的主容器是`LinearLayout`。`LinearLayout`的方向属性是强制性的：

```kt
    android:orientation="vertical" 
```

可以分配给它的值是垂直和水平。作为`Main activity`的第一个子元素，我们包含了`activity_header`布局。然后我们定义了`RelativeLayout`，它填充了屏幕的其余部分。

`RelativeLayout`有两个成员，`ListView`将呈现所有的项目。我们为它分配了一个背景。我们没有在颜色资源文件中定义自己的颜色，而是使用了 Android 中预定义的颜色。我们在这里的最后一个视图是`FloatingActionButton`，和你在 Gmail Android 应用程序中看到的一样。按钮将被定位在屏幕底部对齐右侧的项目列表上。我们还设置了一个边距，将从四面包围按钮。看一下我们使用的属性。

在我们再次运行应用程序之前，我们将做一些更改。打开`BaseActivity`并更新其代码如下：

```kt
    ... 
    protected abstract fun getActivityTitle(): Int 

    override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        setContentView(getLayout()) 
        activity_title.setText(getActivityTitle()) 
        Log.v(tag, "[ ON CREATE ]") 
    } 
    ... 
```

我们引入了一个`abstract`方法，它将为每个活动提供一个适当的标题。我们将`access`在`activity_header.xml`中定义的`activity_title`视图，它包含在我们的活动中，并赋予我们执行该方法得到的值。

打开`MainActivity`并重写以下方法：

```kt
    override fun getActivityTitle() = R.string.app_name
```

在`ItemActivity`中添加相同的行。最后，运行应用程序。你的主屏幕应该是这样的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/5ff9331e-6609-466a-9375-7fbeb062a8af.png)

让我们为其余的屏幕定义布局。对于笔记、添加/编辑笔记屏幕，我们将定义以下布局：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <ScrollView xmlns:android=
     "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:fillViewport="true" > 

    <LinearLayout 
      android:layout_width="match_parent" 
      android:layout_height="wrap_content" 
      android:orientation="vertical"> 

      <include layout="@layout/activity_header" /> 

      <EditText 
        android:id="@+id/note_title" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:hint="@string/title" 
        android:padding="@dimen/form_padding" /> 

      <EditText 
        android:id="@+id/note_content" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:gravity="top" 
        android:hint="@string/your_note_content_goes_here" 
        android:padding="@dimen/form_padding" /> 

    </LinearLayout> 
    </ScrollView> 
```

有一些重要的事情我们必须强调。我们会逐一解释它们。我们将`ScrollView`作为我们布局的顶级容器。由于我们将填充多行注释，它的内容可能会超出屏幕的物理限制。如果发生这种情况，我们将能够滚动内容。我们使用了一个非常重要的属性--`fillViewport`。这个属性告诉容器要拉伸到整个屏幕。所有子元素都使用这个空间。

# 使用 EditText 视图

我们引入了`EditText`视图来输入可编辑的文本内容。你可以在这里看到一些新的属性：

+   **hint**：这定义了将呈现给用户的默认字符串值

+   **padding**：这是视图本身和其内容之间的空间

+   **gravity**：这定义了内容的方向；在我们的例子中，所有的文本都将粘在父视图的顶部

请注意，对于所有的字符串和尺寸，我们在`strings.xml`文件和`dimens.xml`文件中定义了适当的条目。

现在字符串资源文件看起来是这样的：

```kt
    <resources> 
      <string name="app_name">Journaler</string> 
      <string name="title">Title</string> 
      <string name="your_note_content_goes_here">Your note content goes 
      here.</string> 
    </resources> 
    Todos screen will be very similar to this: 
    <?xml version="1.0" encoding="utf-8"?> 
    <ScrollView xmlns:android=
    "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:fillViewport="true"> 

    <LinearLayout 
      android:layout_width="match_parent" 
      android:layout_height="wrap_content" 
      android:orientation="vertical"> 

    <include layout="@layout/activity_header" /> 

    <EditText 
      android:id="@+id/todo_title" 
      android:layout_width="match_parent" 
      android:layout_height="wrap_content" 
      android:hint="@string/title" 
      android:padding="@dimen/form_padding" /> 

    <LinearLayout 
      android:layout_width="match_parent" 
      android:layout_height="wrap_content" 
      android:orientation="horizontal" 
      android:weightSum="1"> 

   <Button 
      android:id="@+id/pick_date" 
      android:text="@string/pick_a_date" 
      android:layout_width="0dp" 
      android:layout_height="wrap_content" 
      android:layout_weight="0.5" /> 

   <Button 
      android:id="@+id/pick_time" 
      android:text="@string/pick_time" 
      android:layout_width="0dp" 
      android:layout_height="wrap_content" 
      android:layout_weight="0.5" /> 

   </LinearLayout> 

   <EditText 
      android:id="@+id/todo_content" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:gravity="top" 
      android:hint="@string/your_note_content_goes_here" 
      android:padding="@dimen/form_padding" />  
   </LinearLayout> 
   </ScrollView> 
```

再次，顶级容器是`ScrollView`。与之前的屏幕相比，我们引入了一些不同之处。我们添加了一个容器来容纳日期和时间选择的按钮。方向是水平的。我们设置了父容器属性`weightSum`，以定义可以被子视图分割的权重值，这样每个子视图都可以占据其自己权重定义的空间量。所以，`weightSum`是 1。第一个按钮的`layout_weight`是`0.5`。它将占据水平空间的 50%。第二个按钮也是相同的值。我们实现了视图分割成两半。定位到 XML 的底部，点击 Design 切换到 Design 视图。你的按钮应该是这样的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/f065d15d-1b8e-4818-a721-f6a7c5532f48.png)

我们为我们的屏幕定义了布局。为了表达这些屏幕应该是什么样子，我们依赖于许多不同的属性。这只是我们可以使用的可用属性的一小部分。为了使这一部分完整，我们将向您介绍一些其他重要的属性，这些属性在日常开发中会用到。

# 边距属性

边距接受维度资源或直接维度值，支持以下支持的单位之一：

+   `layout_margin`

+   `layout_marginTop`

+   `layout_marginBottom`

+   `layout_marginStart`

+   `layout_marginEnd`

# 填充属性

填充接受维度资源或直接维度值，支持以下支持的单位之一：

+   `padding`

+   `paddingTop`

+   `paddingBottom`

+   `paddingStart`

+   `paddingEnd`

# 检查重力属性

视图重力：

+   **重力（视图内内容的方向）**：这接受以下内容--`top`，`left`，`right`，`start`，`end`，`center`，`center_horizontal`，`center_vertical`，以及许多其他

+   **`layout_gravity`（视图父级内内容的方向）**：这接受以下内容--`top`，`left`，`right`，`left`，`start`，`end`，`center`，`center_horizontal`，`center_vertical`，以及许多其他

可以将重力的值组合如下：

```kt
    android:gravity="top|center_horizontal" 
```

# 查看其他属性

我们刚刚看到了我们将使用的最重要的属性。现在是时候看看其他你可能会发现方便的属性了。其他属性如下：

+   `src`：这是要使用的资源：

```kt
        android:src="img/icon" 
```

+   `background`：视图的背景，十六进制颜色或颜色资源如下：

```kt
        android:background="#ddff00" 
        android:background="@color/colorAccent" 
```

+   `onClick`：这是当用户点击视图（通常是按钮）时要调用的方法

+   `visibility`：这是视图的可见性，接受以下参数--gone（不可见且不占用任何布局空间），invisible（不可见但占用布局空间），visible

+   `hint`：这是视图的提示文本，它接受一个字符串值或字符串资源

+   `text`：这是视图的文本，它接受一个字符串值或字符串资源

+   `textColor`：这是文本的颜色，十六进制颜色或颜色资源

+   `textSize`：这是支持单位的文本大小--直接单位值或尺寸资源

+   `textStyle`：这是定义要分配给视图的属性的样式资源，如下：

```kt
        style="@style/my_theme" 
        ...
```

在这一部分，我们介绍了使用属性。没有它们，我们无法开发我们的 UI。在本章的其余部分，我们将向您介绍安卓上下文。

# 理解安卓上下文

我们所有的主屏幕现在都有了它们的布局定义。现在我们将解释安卓上下文，因为我们刚刚创建的每个屏幕都代表一个`Context`实例。如果您查看类定义并遵循类扩展，您将意识到我们创建的每个活动都扩展了`Context`类。

`Context`代表应用程序或对象的当前状态。它用于访问应用程序的特定类和资源。例如，考虑以下代码行：

```kt
    resources.getDimension(R.dimen.header_height) 
    getString(R.string.app_name) 
```

我们展示的访问是由`Context`类提供的，它显示了我们的活动是如何扩展的。当我们需要启动另一个活动、启动服务或发送广播消息时，需要`Context`。当时机合适时，我们将展示这些方法的使用。我们已经提到，安卓应用的每个屏幕（`Activity`）都代表一个`Context`实例。活动并不是唯一代表上下文的类。除了活动，我们还有服务上下文类型。

安卓上下文有以下目的：

+   显示对话框

+   启动活动

+   充气布局

+   启动服务

+   绑定到服务

+   发送广播消息

+   注册广播消息

+   而且，就像我们在前面的例子中已经展示的那样，加载资源

`Context`是安卓的重要组成部分，也是框架中最常用的类之一。在本书的后面，您将遇到其他`Context`类。然而，在那之前，我们将专注于片段及其解释。

# 理解片段

我们已经提到，我们的主屏幕的中心部分将包含一个经过筛选的项目列表。我们希望有几个页面应用不同的筛选集。用户将能够向左或向右滑动以更改筛选内容并浏览以下页面：

+   所有显示的

+   今天的事项

+   未来 7 天的事项

+   只有笔记

+   只有待办事项

为了实现这个功能，我们需要定义片段。片段是什么，它们的目的是什么？

片段是`Activity`实例界面的一部分。您可以使用片段创建多平面屏幕或具有视图分页的屏幕，就像我们的情况一样。

就像活动一样，片段也有自己的生命周期。片段生命周期在以下图表中呈现：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/d658d3db-bfe9-469b-a79a-d1736ce31949.png)

有一些活动没有的额外方法：

+   `onAttach()`: 当片段与活动关联时执行。

+   `onCreateView()`: 这实例化并返回片段的视图实例。

+   `onActivityCreated()`: 当活动的`onCreate()`被执行时执行。

+   `onDestroyView()`: 当视图被销毁时执行；当需要进行一些清理时很方便。

+   `onDetach()`: 当片段与活动解除关联时执行。为了演示片段的使用，我们将`MainActivity`的中心部分放入一个单独的片段中。稍后，我们将把它移到`ViewPager`并添加更多页面。

创建一个名为`fragment`的新包。然后，创建一个名为`BaseFragment`的新类。根据此示例更新您的`BaseFragment`类：

```kt
    package com.journaler.fragment 

    import android.os.Bundle 
    import android.support.v4.app.Fragment 
    import android.util.Log 
    import android.view.LayoutInflater 
    import android.view.View 
    import android.view.ViewGroup 

    abstract class BaseFragment : Fragment() { 
      protected abstract val logTag : String 
      protected abstract fun getLayout(): Int 

    override fun onCreateView( 
      inflater: LayoutInflater?, container: ViewGroup?,
      savedInstanceState: Bundle? 
      ): View? { 
        Log.d(logTag, "[ ON CREATE VIEW ]") 
        return inflater?.inflate(getLayout(), container, false) 
     } 

     override fun onPause() { 
        super.onPause() 
        Log.v(logTag, "[ ON PAUSE ]") 
     } 

     override fun onResume() { 
        super.onResume() 
        Log.v(logTag, "[ ON RESUME ]") 
     } 

     override fun onDestroy() { 
        super.onDestroy() 
        Log.d(logTag, "[ ON DESTROY ]") 
     } 

    } 
```

注意导入：

```kt
    import android.support.v4.app.Fragment 
```

我们希望最大限度地提高兼容性，因此我们正在从 Android 支持库中导入片段。

正如您所看到的，我们做了与`BaseActivity`相似的事情。创建一个新的片段，一个名为`ItemsFragment`的类。根据此示例更新其代码：

```kt
    package com.journaler.fragment 
    import com.journaler.R 

    class ItemsFragment : BaseFragment() { 
      override val logTag = "Items fragment" 
      override fun getLayout(): Int { 
        return R.layout.fragment_items 
      } 
    } 
```

我们引入了一个实际包含我们在`activity_main`中的列表视图的新布局。创建一个名为`fragment_items`的新布局资源：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <RelativeLayout xmlns:android=
     "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

    <ListView 
      android:id="@+id/items" 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:background="@android:color/darker_gray" /> 

    <android.support.design.widget.FloatingActionButton 
      android:id="@+id/new_item" 
      android:layout_width="wrap_content" 
      android:layout_height="wrap_content" 
      android:layout_alignParentBottom="true" 
      android:layout_alignParentEnd="true" 
      android:layout_margin="@dimen/button_margin" /> 

    </RelativeLayout> 
```

您已经看到了这个。这只是我们从`activity_main`布局中提取出来的一部分。除此之外，我们将以下内容放入`activity_main`布局中：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout xmlns:android=
     "http://schemas.android.com/apk/res/android" 
     android:layout_width="match_parent" 
     android:layout_height="match_parent" 
     android:orientation="vertical"> 
    <include layout="@layout/activity_header" /> 

    <FrameLayout 
       android:id="@+id/fragment_container" 
       android:layout_width="match_parent" 
       android:layout_height="match_parent" /> 
    </LinearLayout> 
```

`FrameLayout`将是我们的`fragment`容器。要在`fragment_container``FrameLayout`中显示新片段，请按照以下方式更新`MainActivity`的代码：

```kt
    class MainActivity : BaseActivity() { 

      override val tag = "Main activity" 
      override fun getLayout() = R.layout.activity_main 
      override fun getActivityTitle() = R.string.app_name 

      override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        val fragment = ItemsFragment() 
        supportFragmentManager 
                .beginTransaction() 
                .add(R.id.fragment_container, fragment) 
                .commit() 
     } 
    } 
```

我们访问了`supportFragmentManager`。如果我们选择不使用 Android 支持库，我们将使用`fragmentManager`。然后，我们开始片段事务，我们添加一个新的片段实例，该实例将与`fragment_container` `FrameLayout`相关联。`commit`方法执行此事务。如果我们现在运行我们的应用程序，我们不会注意到任何不同，但是，如果我们查看日志，我们可能会注意到片段生命周期已被执行：

```kt
    V/Journaler: [ ON CREATE ] 
    V/Main activity: [ ON CREATE ] 
    D/Items fragment: [ ON CREATE VIEW ] 
    V/Main activity: [ ON START ] 
    V/Main activity: [ ON POST CREATE ] 
    V/Main activity: [ ON RESUME ] 
    V/Items fragment: [ ON RESUME ] 
    V/Main activity: [ ON POST RESUME ] 
```

我们在界面中添加了一个简单的片段。在下一节中，您将了解有关片段管理器及其目的的更多信息。然后，我们将做一些非常有趣的事情--我们将创建一个`ViewPager`。

# 片段管理器

负责与当前活动中的片段进行交互的组件是**片段管理器**。我们可以使用两种不同导入形式的`FragmentManager`：

+   `android.app.FragmentManager`

+   `android.support.v4.app.Fragment`

建议从 Android 支持库导入。

使用`beginTransaction()`方法开始片段事务以执行一系列编辑操作。它将返回一个事务实例。要添加一个片段（通常是第一个），请使用`add`方法，就像我们的示例中一样。该方法接受相同的参数，但如果已经添加，则替换当前片段。如果我们计划通过片段向后导航，需要使用`addToBackStack`方法将事务添加到返回堆栈。它接受一个名称参数，如果我们不想分配名称，则为 null。

最后，我们通过执行`commit()`来安排事务。这不是瞬时操作。它安排在应用程序的主线程上执行操作。当主线程准备好时，事务将被执行。在规划和实施代码时，请考虑这一点！

# 碎片堆栈

为了说明片段和返回堆栈的示例，我们将进一步扩展我们的应用程序。我们将创建一个片段来显示包含文本`Lorem ipsum`的用户手册。首先，我们需要创建一个新的片段。创建一个名为`fragment_manual`的新布局。根据此示例更新布局：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout xmlns:android=
     "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:orientation="vertical"> 

    <TextView 
      android:layout_width="match_parent" 
      android:layout_height="match_parent" 
      android:layout_margin="10dp" 
      android:text="@string/lorem_ipsum_sit_dolore" 
      android:textSize="14sp" /> 
    </LinearLayout> 
```

这是一个简单的布局，包含了跨越整个父视图的文本视图。将使用这个布局的片段将被称为`ManualFragment`。为片段创建一个类，并确保它具有以下内容：

```kt
     package com.journaler.fragment 
     import com.journaler.R 

     class ManualFragment : BaseFragment() { 
      override val logTag = "Manual Fragment" 
      override fun getLayout() = R.layout.fragment_manual 
    } 
```

最后，让我们将其添加到片段返回堆栈。更新`MainActivity`的`onCreate()`方法如下：

```kt
    override fun onCreate(savedInstanceState: Bundle?) { 
      super.onCreate(savedInstanceState) 
      val fragment = ItemsFragment() 
      supportFragmentManager 
                .beginTransaction() 
                .add(R.id.fragment_container, fragment) 
                .commit() 
      filter_menu.setText("H") 
      filter_menu.setOnClickListener { 
        val userManualFrg = ManualFragment() 
        supportFragmentManager 
                    .beginTransaction() 
                    .replace(R.id.fragment_container, userManualFrg) 
                    .addToBackStack("User manual") 
                    .commit() 
        } 
    } 
```

构建并运行应用程序。右上角的标题按钮将标签为`H`；点击它。包含`Lorem ipsum`文本的片段填充视图。点击返回按钮，片段消失。这意味着你成功地将片段添加到返回堆栈并移除了它。

我们还需要尝试一件事--连续两到三次点击同一个按钮。点击返回按钮。然后再次。再次。你将通过返回堆栈直到达到第一个片段。如果你再次点击返回按钮，你将离开应用程序。观察你的 Logcat。

你还记得生命周期方法执行的顺序吗？你可以认识到每次一个新的片段被添加到顶部时，下面的片段会暂停。当我们按下返回按钮开始后退时，顶部的片段暂停，下面的片段恢复。从返回堆栈中移除的片段最终进入`onDestroy()`方法。

# 创建 View Pager

正如我们提到的，我们希望我们的项目显示在可以滑动的几个页面上。为此，我们需要`ViewPager`。`ViewPager`使得在片段集合的一部分之间进行滑动成为可能。我们将对我们的代码进行一些更改。打开`activity_main`布局并像这样更新它：

```kt
    <?xml version="1.0" encoding="utf-8"?> 
    <LinearLayout xmlns:android=
     "http://schemas.android.com/apk/res/android" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:orientation="vertical"> 
    <android.support.v4.view.ViewPager  xmlns:android=
    "http://schemas.android.com/apk/res/android" 
        android:id="@+id/pager" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" /> 

    </LinearLayout> 
```

我们将`FrameLayout`替换为`ViewPager`视图。然后，打开`MainActivity`类，并像这样更新它：

```kt
    class MainActivity : BaseActivity() { 
      override val tag = "Main activity" 
      override fun getLayout() = R.layout.activity_main 
      override fun getActivityTitle() = R.string.app_name 

      override fun onCreate(savedInstanceState: Bundle?) { 
        super.onCreate(savedInstanceState) 
        pager.adapter = ViewPagerAdapter(supportFragmentManager) 
    } 

    private class ViewPagerAdapter(manager: FragmentManager) :  
    FragmentStatePagerAdapter(manager) { 
      override fun getItem(position: Int): Fragment { 
        return ItemsFragment() 
      } 

      override fun getCount(): Int { 
        return 5 
      } 
     } 
    } 
```

我们工作的主要部分是为分页器定义`adapter`类。我们必须扩展`FragmentStatePagerAdapter`类；它的构造函数接受将处理片段事务的片段管理器。为了正确完成工作，重写`getItem()`方法，返回片段的实例和`getCount()`返回预期片段的总数。其余的代码非常清晰--我们访问分页器（我们分配的`ViewPager`的 ID）并将其分配给适配器的新实例。

运行你的应用程序，尝试左右滑动。在你滑动时，观察 Logcat 和生命周期日志。

# 使用过渡制作动画

为了在片段之间制作动画过渡，需要为事务实例分配一些动画资源。正如你记得的，当我们开始片段事务后，我们得到一个事务实例。然后我们可以访问这个实例并执行以下方法：

+   `setCustomAnimations (int enter, int exit, int popEnter, int popExit)`

或者，我们可以使用这个方法：

+   `setCustomAnimations (int enter, int exit)`

这里，每个参数代表此事务中使用的动画。我们可以定义自己的动画资源，或者使用预定义的动画之一：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-dev-kt/img/26f2bac6-99df-4c27-9afa-f482bdfd75d1.png)

# 对话框片段

如果你需要显示任何浮动在应用程序 UI 上方的片段，那么`DialogFragment`就非常适合你。你所需要做的就是定义片段，非常类似于我们到目前为止所做的。定义一个扩展`DialogFragment`的类。重写`onCreateView()`方法，这样你就可以定义布局。你也可以重写`onCreate()`。你所需要做的最后一件事就是按照以下方式显示它：

```kt
    val dialog = MyDialogFragment() 
    dialog.show(supportFragmentManager, "dialog") 
```

在这个例子中，我们向片段管理器传递了实例和事务的名称。

# 通知

如果您计划呈现给最终用户的内容很短，那么，您应该尝试通知而不是对话框。我们可以以许多不同的方式自定义通知。在这里，我们将介绍一些基本的自定义。创建和显示通知很容易。这需要比我们迄今为止学到的更多关于 Android 的知识。不要担心；我们会尽力解释。您将在以后的章节中遇到许多这些类。

我们将演示如何使用通知如下：

1.  定义一个`notificationBuilder`，并传递一个小图标、内容标题和内容文本如下：

```kt
        val notificationBuilder = NotificationCompat.Builder(context) 
                .setSmallIcon(R.drawable.icon) 
                .setContentTitle("Hello!") 
                .setContentText("We love Android!") 
```

1.  为应用程序的活动定义`Intent`。（关于意图的更多内容将在下一章中讨论）：

```kt
        val result = Intent(context, MyActivity::class.java)
```

1.  现在定义包含活动后退堆栈的堆栈构建器对象如下：

```kt
        val builder = TaskStackBuilder.create(context) 
```

1.  为意图添加后退堆栈：

```kt
        builder.addParentStack(MyActivity::class.java) 
```

1.  在堆栈顶部添加意图：

```kt
        builder.addNextIntent(result) 
        val resultPendingIntent = builder.getPendingIntent( 
          0, 
          PendingIntent.FLAG_UPDATE_CURRENT )Define ID for the   
          notification and notify:
        val id = 0 
        notificationBuilder.setContentIntent(resultPendingIntent) 
        val manager = getSystemService(NOTIFICATION_SERVICE) as
        NotificationManager 
        manager.notify(id, notificationBuilder.build()) 
```

# 其他重要的 UI 组件

Android 框架庞大而强大。到目前为止，我们已经涵盖了最常用的`View`类。然而，还有很多`View`类我们没有涵盖。其中一些将在以后涵盖，但一些不太常用的将只是提及。无论如何，知道这些视图存在并且是进一步学习的好起点是很好的。让我们举一些例子来给你一个概念：

+   ConstraintLayout：这种视图以灵活的方式放置和定位子元素

+   CoordinatorLayout：这是 FrameLayout 的一个非常高级的版本

+   SurfaceView：这是一个用于绘图的视图（特别是在需要高性能时）

+   VideoView：这是设置播放视频内容的

# 摘要

在本章中，您学会了如何创建分成部分的屏幕，现在您可以创建包含按钮和图像的基本和复杂布局。您还学会了如何创建对话框和通知。在接下来的章节中，您将连接所有屏幕和导航操作。
