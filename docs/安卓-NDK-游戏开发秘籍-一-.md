# 安卓 NDK 游戏开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/713F9F8B01BD9DC2E44DADEE702661F7`](https://zh.annas-archive.org/md5/713F9F8B01BD9DC2E44DADEE702661F7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

移动性和对高性能计算的需求往往是紧密相连的。当前的移动应用程序执行许多计算密集型操作，如 3D 和立体渲染、图像和音频识别、视频解码和编码，尤其是随着增强现实等新技术诞生。这包括移动游戏、3D 用户界面软件和社交软件，涉及媒体流处理。

在某种意义上，移动游戏开发由于硬件能力的限制、内存带宽的不足和宝贵的电池资源，迫使我们回到几年前，但也让我们重新考虑与用户互动的基本形式。

基于手势输入、互联网访问、环境音效、高质量的文本和图形的流畅且响应迅速的用户界面是成功移动应用程序的要素。

所有主流的移动操作系统都为软件开发者提供了不同方式接近硬件的开发可能。谷歌提供了 Android 原生开发工具包（NDK），以简化将其他平台上的现有应用程序和库移植到 Android，并利用现代移动设备提供的底层硬件性能。C 语言，尤其是 C++，都因其难学难写用户界面代码而闻名。这确实是事实，但仅当有人试图从零开始编写一切时。在这本书中，我们使用 C 和 C++编程语言，并将它们与久经考验的第三方库链接起来，以允许创建具有现代触摸界面和访问诸如 Facebook、Twitter、Flickr、Picasa、Instagram 等流行网站的代表性状态转移（REST）API 的内容丰富的应用程序。

尽管关于如何在用 Java 或.NET 语言编写的应用程序中使用互联网资源的信息已经很多，但在 C++编程语言中这样做却鲜有讨论。现代 OpenGL 版本要求投入足够努力来创建和使用最新的扩展。使用 OpenGL API 的编程通常在文献中以特定平台的方式描述。对于移动版本 OpenGL ES，事情变得更加复杂，因为开发者必须调整现有的着色器程序，使它们能在移动图形处理单元（GPU）上运行。在 C++中使用标准的 Android 设施进行声音播放也不是那么直接，例如，需要采取措施复用现有的 PC 代码以便于 OpenAL 库的使用。这本书试图阐明这些主题，并将许多有用的食谱结合起来，简化使用 Android NDK 的多平台友好开发。

Android 是一个基于 Linux 内核的移动操作系统，专为智能手机、平板电脑、上网本和其他便携设备设计。Android 的初步开发由 Android Inc 开始，该公司于 2005 年被 Google 收购。2007 年 11 月，第一个版本公布，然而，第一款基于 Android 的商业智能手机 HTC Dream 在 2008 年几乎一年后发布。

除了数字编号，Android 版本还有官方的代号名称——每个主要版本都是以甜点命名。以下是与 NDK 相关的 Android 平台技术和功能的一些重要里程碑：

+   **版本 1.5（纸杯蛋糕）**：这个 Android 版本首次发布了支持 ARMv5TE 指令的 Android 本地开发工具包。

+   **版本 1.6（甜甜圈）**：首次引入了 OpenGL ES 1.1 本地库支持。

+   **版本 2.0（闪电泡芙）**：支持 OpenGL ES 2.0 本地库。

+   **版本 2.3（姜饼）**：

    +   Dalvik VM 中的并发垃圾收集器。这提供了更快的游戏性能和改进的 OpenGL ES 操作效率。

    +   本地开发工具包的功能得到了极大的扩展，包括传感器访问、本地音频 OpenSL ES、EGL 库、活动生命周期管理和对资产的本地访问。

+   **版本 3.0（蜂巢）**：

    +   支持大型触摸屏的平板电脑

    +   支持多核处理器

+   **版本 4.0（冰淇淋三明治）**：

    +   统一的智能手机和平板界面

    +   硬件加速的 2D 渲染。VPN 客户端 API

+   **版本 4.1** 和 **4.2（果冻豆）**：

    +   这提高了渲染性能和三重缓冲

    +   支持外部显示器，包括通过 Wi-Fi 连接的外部显示器

    +   它们支持高动态范围相机

    +   新内置的开发者选项，用于调试和性能分析。Dalvik VM 运行时优化。

+   **版本 4.3（果冻豆）**：支持 OpenGL ES 3.0 本地库。

+   **版本 4.4（奇巧）**：从 NDK 引入了 RenderScript 的访问。此功能与运行 Android 2.2 或更高版本的任何设备向后兼容。

Android 本地开发工具包（NDK）用于需要 Dalvik 无法提供的性能的多媒体应用程序，以及直接访问本地系统库。NDK 也是可移植性的关键，反过来，它允许使用熟悉的工具（如 GCC 和 Clang 工具链或类似工具）进行相当舒适的开发和调试过程。NDK 的典型使用决定了本书的范围——集成一些最常用的 C/C++ 库，用于图形、声音、网络和资源存储。

最初，NDK 是基于 Bionic 库的。这是由 Google 为 Android 开发的 BSD 标准 C 库（libc）的一个衍生品。Bionic 的主要目标如下：

+   **许可**：原始 GNU C 库（glibc）是 GPL 许可的，而 Bionic 拥有 BSD 许可。

+   **大小**：与 GNU C 库相比，Bionic 的体积要小得多。

+   **速度**：Bionic 针对相对低时钟频率的移动 CPU 设计。例如，它有一个自定义的 pthreads 实现。

Bionic 在完整 libc 实现中缺少许多重要特性，例如 RTTI 和 C++ 异常处理支持。然而，NDK 提供了几个带有不同 C++ 辅助运行时的库，这些库实现了这些特性。这些包括 GAbi++ 运行时、STLport 运行时和 GNU 标准 C++库。除了基本的 POSIX 特性外，Bionic 还支持 Android 特定的机制，如日志记录。

NDK 是一种非常有效的方式来复用大量的现有 C 和 C++ 代码。

# 本书涵盖的内容

第一章，*建立构建环境*，解释了如何在 Microsoft Windows 和 Ubuntu/Debian Linux 发行版上安装和配置 Android SDK 和 NDK，以及如何在基于 Android 的设备上构建和运行你的第一个应用程序。你将学习如何使用 Android NDK 附带的不同的编译器和工具链。本章还涵盖了使用 adb 工具进行调试和部署应用程序的内容。

第二章，*移植通用库*，包含一系列将久经考验的 C++ 项目和 API 移植到 Android NDK 的方法，例如 FreeType 字体渲染库、FreeImage 图像加载库、libcurl 和 OpenSSL（包括编译 libssl 和 libcrypto）、OpenAL API、libmodplug 音频库、Box2D 物理库、Open Dynamics Engine (ODE)、libogg 和 libvorbis。其中一些需要对源代码进行修改，这将在文中解释。这些库中的大多数将在后续章节中使用。

第三章，*网络编程*，展示了如何使用知名的 libcurl 库通过 HTTP 协议下载文件，以及如何使用 C++ 代码直接向流行的 Picasa 和 Flickr 在线服务形成请求和解析响应。如今，大多数应用程序在某种程度上都会使用网络数据传输。HTTP 协议是所有流行网站（如 Facebook、Twitter、Picasa、Flickr、SoundCloud 和 YouTube）API 的基础。本章的剩余部分致力于 Web 服务器开发。在应用程序中拥有一个迷你 Web 服务器可以让开发者远程控制软件，监视其运行时，而不使用特定于操作系统的代码。本章开头还介绍了用于后台下载处理的任务队列和简单的智能指针，以允许跨线程高效交换数据。这些线程原语在第四章，*组织虚拟文件系统*和第五章，*跨平台音频流*中会被使用。

第四章, *组织虚拟文件系统*，完全致力于异步文件处理、资源代理和资源压缩。许多程序将其数据存储为一系列文件。在不阻塞整个程序的情况下加载这些文件是一个重要的问题。所有现代操作系统的人机界面指南规定应用程序开发者应避免在程序工作流程中出现任何延迟或“冻结”（在 Android 中称为应用程序无响应(ANR)错误）。Android 程序包只是带有.apk 扩展名的熟悉 ZIP 算法压缩的归档文件。为了允许直接从.apk 读取应用程序的资源文件，我们必须使用 zlib 库解压.zip 格式。另一个重要的话题是虚拟文件系统概念，它允许我们对底层的操作系统文件和文件夹结构进行抽象，并在 Android 和 PC 版本的应用程序之间共享资源。

第五章, *跨平台音频流*，从使用 OpenAL 库组织音频流开始。这之后，我们继续学习 RIFF WAVE 文件格式的读取，以及 OGG Vorbis 流的解码。最后，我们学习如何使用 libmodplug 播放一些追踪音乐。最近的 Android NDK 包括了 OpenSL ES API 的实现。然而，我们正在寻找一个完全可移植的实现，以便在桌面 PC 和其他移动平台之间实现无缝的游戏调试功能。为此，我们将 OpenAL 实现预编译成一个静态库，然后在 libogg 和 libvorbis 之上组织一个小型的多线程声音流库。

第六章，*统一 OpenGL ES 3 和 OpenGL 3*，介绍了桌面 OpenGL 3 和移动 OpenGL ES 3.0 的基本渲染循环。将应用程序重新部署到移动设备是一项耗时的操作，这阻止了开发者进行快速的功能测试和调试。为了允许在 PC 上开发游戏逻辑并进行调试，我们提供了一种技术，可以在移动 OpenGL ES 中使用桌面 GLSL 着色器。

第七章，*跨平台 UI 和输入系统*，将教你如何以可移植的方式实现多触摸事件处理和手势识别。如今，移动设备几乎与基于手势的触摸输入同义。没有图形用户界面（GUI）的现代面向用户的应用程序是无法存在的。组织交互有两个基本问题：输入和文本渲染。为了便于测试和调试，我们还展示了如何在配备了多个鼠标设备的 Windows 7 PC 上模拟多触摸输入。由于我们的目标是开发交互式游戏应用，我们必须以熟悉的方式实现用户输入。我们将系统地教你如何创建一个屏幕上的游戏手柄 UI。在一个全球多元文化环境中，任何应用程序拥有一个多语言文本渲染器是非常理想的。我们将展示如何使用 FreeType 库来渲染拉丁文、西里尔文和从左到右的文本。将介绍一个基于字典的方法来组织多语言 UTF-8 本地化界面。

第八章，*编写消除游戏*，将把我们介绍的所有技术整合在一起，编写一个简单的消除游戏，包括使用 OpenGL ES 进行渲染，处理输入，资源打包，以及 PC 端的调试。该游戏也可以在 Windows 桌面 PC 上运行和调试，并且可以轻松地移植到其他移动平台。

第九章，*编写拼图游戏*，将提供一个更复杂的示例，整合上述所有内容。关于图形和输入的所有上述元素都将使用本地网络库和 API 从 Picasa 在线服务下载图片。

# 本书中所需准备

本书以 Windows PC 为中心。由于模拟器在 3D 图形和原生音频方面的限制，建议使用 Android 智能手机或平板电脑。

### 注意

本书中的源代码基于开源的 Linderdaum 引擎，并提炼了该引擎中使用的一些方法和技巧。你可以访问[`www.linderdaum.com`](http://www.linderdaum.com)获取。

假设读者具备 C 或 C++的基础知识，包括指针操作、多线程和基本的面向对象编程概念。读者还应熟悉高级编程概念，如线程和同步原语，并对 GCC 工具链有基本的了解。我们还希望读者不害怕在没有 IDE（是的，在没有自动补全功能的 IDE 中开发绝对是一项技能）的情况下，例如从终端/FarManager/Notepad/SublimeText 进行开发。

本书不涉及 Android Java 开发。你需要阅读其他资料来熟悉这方面的内容。

对线性代数和 3D 空间中的仿射变换有一些实际了解对于理解 OpenGL 编程和手势识别很有帮助。

# 这本书适合谁

您想要将现有的 C/C++应用程序移植到 Android 吗？您是一位有经验的 C++开发者，想要跳入现代移动开发吗？您想要提高基于 Java 的 Android 应用程序的性能吗？您想在您的 Android 应用程序中使用 C++编写的优秀库吗？您想通过在 PC 上调试移动游戏来提高您的生产力吗？

如果您对这些问题中的任何一个回答“是”，那么这本书就是为您准备的。

# 构建源代码

本书的代码包中的示例可以使用以下命令进行编译：

+   对于 Windows：make all

+   对于 Android：ndk-buildant copy-common-media debug

# 约定

在这本书中，您会发现多种文本样式，这些样式用于区分不同类型的信息。以下是一些样式示例，以及它们含义的解释。

文本中的代码字会像这样显示："`JAVA_HOME`变量应指向 Java 开发工具包文件夹。"

代码块如下排版：

```kt
package com.packtpub.ndkcookbook.app1;
import android.app.Activity;
public class App1Activity extends Activity
{
};
```

当我们希望引起您对某行代码的注意时，相关的行会像这样被强调：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">App1</string>
</resources>
```

所有的命令行输入或输出都如下书写：

```kt
>adb.exe logcat -v time > 1.txt
```

**新术语**和**重要词汇**会用粗体显示。您在屏幕上看到的词，例如菜单或对话框中的，会像这样出现在文本中："选择是否安装这个设备软件，您应该点击**安装**按钮"。

### 注意

警告或重要说明会像这样出现在一个框里。

### 提示

提示和技巧会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对这本书的看法——您喜欢或可能不喜欢的内容。读者的反馈对我们开发您真正能从中获得最大收益的标题非常重要。

如果您想要给我们发送一般性的反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果您在某个主题上有专业知识，并且您有兴趣撰写或为书籍做贡献，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然您现在是 Packt 图书的骄傲拥有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载本书的示例代码

您可以从您的账户下载您购买的所有 Packt 图书的示例源代码文件，网址是[`www.PacktPub.com`](http://www.PacktPub.com)。如果您在其他地方购买了这本书，可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)注册，我们会直接将文件通过电子邮件发送给您。我们努力为这本书编写和调试源代码。事实上，在现实生活中，代码中总是潜伏着 bug，需要在发布后修复。

我们建立了一个 GitHub 仓库，这样每个人都可以下载最新的源代码包，并通过提交 pull 请求来提交错误修复和改进。该仓库可以从以下位置克隆：[`github.com/corporateshark/Android-NDK-Game-Development-Cookbook`](https://github.com/corporateshark/Android-NDK-Game-Development-Cookbook)。我们源代码包的最新快照可以在以下链接获取：[`www.linderdaum.com/Android-NDK-Game-Development-Cookbook-SourceCodeBungle.zip`](http://www.linderdaum.com/Android-NDK-Game-Development-Cookbook-SourceCodeBungle.zip)。

## 错误更正

尽管我们已经尽力确保内容的准确性，但错误仍然会发生。如果你在我们的书中发现错误——可能是文本或代码中的错误——我们非常感激你能向我们报告。这样做，你可以让其他读者免受挫折，并帮助我们改进本书的后续版本。如果你发现任何错误，请通过访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 报告，选择你的书，点击错误更正提交表单链接，并输入错误详情。一旦你的错误更正被验证，你的提交将被接受，错误更正将在我们网站的相应标题下的错误更正部分上传或添加到现有错误列表中。任何现有的错误更正可以通过从 [`www.packtpub.com/support`](http://www.packtpub.com/support) 选择你的标题来查看。

## 盗版

在互联网上，版权材料的盗版是一个所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果你在互联网上以任何形式发现我们作品非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

请在提供疑似盗版材料链接的情况下，联系我们 `<copyright@packtpub.com>`。

我们感谢您保护我们的作者，以及我们为您带来有价值内容的能力。

## 问题

如果你在这本书的任何方面遇到问题，可以联系我们 `<questions@packtpub.com>`，我们将尽力解决。


# 第一章：建立构建环境

|   | *一些 LinkedIn 个人资料说使用特定 IDE 进行开发是一种技能。**不！不使用任何 IDE 进行开发才是真正的技能！** |   |
| --- | --- | --- |
|   | --*谢尔盖·科萨列夫斯基* |

在本章中，我们将涵盖以下内容：

+   在 Windows 上安装 Android 开发工具

+   在 Linux 上安装 Android 开发工具

+   手动创建应用程序模板

+   向你的应用程序添加本地 C++代码

+   切换 NDK 工具链

+   支持多种 CPU 架构

+   使用 OpenGL ES 进行基本渲染

+   跨平台开发

+   统一跨平台代码

+   链接与源代码组织

+   签名发布 Android 应用程序

# 引言

本章介绍如何在 Microsoft Windows 或 Ubuntu/Debian Linux 上安装和配置 Android NDK，以及如何在基于 Android 的设备上构建和运行你的第一个应用程序。我们将学习如何设置不同的编译器和随 Android NDK 提供的**工具链**。此外，我们还将展示如何设置 Windows 上的 GCC 工具链以构建你的项目。本章的其余部分致力于使用 C++进行跨平台开发。

# 在 Windows 上安装 Android 开发工具

要开始为 Android 开发游戏，你需要在系统上安装一些基本工具。

## 准备就绪

以下是开始为 Android 开发游戏所需的所有先决条件列表：

+   Android SDK 位于[`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html)。

    ### 注意

    本书基于 Android SDK 修订版 22.3，并使用 Android API Level 19 进行测试。

+   Android NDK 位于[`developer.android.com/tools/sdk/ndk/index.html`](http://developer.android.com/tools/sdk/ndk/index.html)（我们使用的是 Android NDK r9b）。

+   Apache Ant 位于[`ant.apache.org`](http://ant.apache.org)。这是一个 Java 命令行工具，C++开发者可能不太熟悉。它的目的是构建 Java 应用程序，由于每个 Android 应用程序都有一个 Java 包装器，因此此工具将帮助我们打包成部署就绪的存档（这些被称为`.apk`包，代表**Android Package**）。

+   Java SE 开发工具包位于[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)。

早期版本的 Windows SDK/NDK 需要安装**Cygwin**环境，这是一种类似于 Linux 的 Windows 环境。最新版本的这些工具可以在 Windows 上本机运行，无需任何中间层。我们将重点介绍无 Cygwin 环境，并且将在不使用 IDE 的情况下进行所有开发。你没听错，我们将仅使用命令行。本书中的所有示例都是在 Windows PC 上编写和调试的。

要编译本书中介绍的本地 Windows 应用程序，你需要一个像样的 C++编译器，例如带有 GCC 工具链的 MinGW 包。使用 Microsoft Visual Studio 也是可行的。

### 注意

**Windows 的最小化 GNU**（**MinGW**）是一个使用**GNU 编译器集合**（**GCC**）端口的 Windows 应用程序的最小开发环境。

## 如何操作...

1.  Android SDK 和 NDK 应安装到名称中不包含任何空格的文件夹中。

    ### 注意

    这个要求源于 Android SDK 中脚本的限制。StackOverflow 上有一个很好的讨论，解释了这些限制背后的部分原因，请见[`stackoverflow.com/q/6603194/1065190`](http://stackoverflow.com/q/6603194/1065190)。

1.  其他工具可以安装到它们的默认位置。我们在 Windows 7 系统上使用了以下路径：

| 工具 | 路径 |
| --- | --- |
| Android SDK | `D:\android-sdk-windows` |
| Android NDK | `D:\ndk` |
| Apache Ant | `D:\ant` |
| Java 开发工具包 | `C:\Program Files\Java\jdk1.6.0_33` |

所有工具都有相当不错的 GUI 安装程序（请看以下图片，展示了 SDK R21 的 Android SDK 管理器），所以你不必使用命令行。

![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_02_1.jpg)

对于 Windows 环境，你需要 MinGW GCC 工具链。易于安装的一体化软件包可以在[`www.equation.com`](http://www.equation.com)的**编程工具**部分，**Fortran, C, C++**子部分找到。或者，你也可以从[`www.mingw.org`](http://www.mingw.org)下载官方安装程序。我们将使用来自[www.equation.com](http://www.equation.com)的版本。

## 还有更多内容...

你需要设置一些环境变量，让工具知道文件的位置。`JAVA_HOME`变量应指向 Java 开发工具包文件夹。`NDK_HOME`变量应指向 Android NDK 安装文件夹，而`ANDROID_HOME`应指向 Android SDK 文件夹（注意双反斜杠）。我们使用了以下环境变量值：

`JAVA_HOME=D:\Java\jdk1.6.0_23`

`NDK_HOME=D:\ndk`

`ANDROID_HOME=D:\\android-sdk-windows`

最终配置类似于以下截图所示，展示了 Windows 的**环境变量**对话框：

![还有更多内容...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_02_2.jpg)

安装 MinGW 成功后，你还需要将其安装文件夹中的`bin`文件夹添加到`PATH`环境变量中。例如，如果 MinGW 安装在`C:\MinGW`，那么`PATH`应该包含`C:\MinGW\bin`文件夹。

# 在 Linux 上安装 Android 开发工具

在 Linux 上安装基本工具与在 Windows 上一样简单。在本教程中，我们将看到如何在*nix 系统上安装基本的 Android 开发工具。

## 准备就绪

我们假设你已经有一个带有`apt`包管理器的 Ubuntu/Debian 系统。详情请参考[`wiki.debian.org/Apt`](http://wiki.debian.org/Apt)。

## 如何操作...

执行以下步骤来安装所需的基本工具：

1.  通过运行以下命令，确保你为你的操作系统使用了最新版本的软件包：

    ```kt
    >sudo apt-get update

    ```

1.  安装 OpenJDK 6+：

    ```kt
    >sudo apt-get install openjdk-6-jdk

    ```

1.  安装 Apache Ant 构建自动化工具：

    ```kt
    >sudo apt-get install ant

    ```

1.  从[`developer.android.com`](http://developer.android.com)下载官方的 Android SDK。旁边有一个更大的包，其中包含 Eclipse IDE 的 ADT 插件。然而，由于我们所有的开发都是通过命令行进行的，所以我们不需要它。运行以下命令：

    ```kt
    >wget http://dl.google.com/android/android-sdk_r22.2.1-linux.tgz

    ```

1.  解压下载的`.tgz`文件（实际版本可能有所不同，截至 2013 年 10 月，22.2.1 是最新版本）：

    ```kt
    >tar -xvf android-sdk_r22.2.1-linux.tgz

    ```

1.  使用`~/<sdk>/tools/android`安装最新的 Platform Tools 和所有 SDKs——就像在 Windows 情况下一样。

    如果不这样做，在尝试使用 Ant 工具构建任何 Android 应用程序时将出现错误。

1.  从[`developer.android.com`](http://developer.android.com)获取官方的 Android NDK：

    ```kt
    >wget http://dl.google.com/android/ndk/android-ndk-r9b-linux-x86_64.tar.bz2

    ```

1.  解压下载的 NDK `.tgz`文件：

    ```kt
    >tar -xvf android-ndk-r9b-linux-x86_64.tar.bz2

    ```

1.  将`NDK_ROOT`环境变量设置为你的 Android NDK 目录（例如，在我们的情况下是`~/android-ndk-r9b`）：

    ```kt
    >NDK_ROOT=/path/to/ndk

    ```

    如果这些设置适用于系统的所有用户，将这行和`JAVA_HOME`的定义放到`/etc/profile`或`/etc/environment`中是有用的。

1.  如果你运行的是 64 位系统，你必须确保你也安装了 32 位的 Java 运行时。

1.  运行以下命令以安装库。如果不这样做可能会导致`adb`和`aapt`工具出现错误：

    ```kt
    >sudo apt-get install ia32-libs

    ```

## 还有更多...

有一个很好的单行脚本可以帮助你自动检测 OpenJDK 的主目录。它本质上解析了`/usr/bin/javac`链接到完整路径，并返回路径的目录部分。

```kt
 JAVA_HOME=$(readlink -f /usr/bin/javac | sed "s:bin/javac::")

```

# 手动创建应用程序模板

首先，我们将为我们的应用程序创建一个基本模板。通过 Android SDK 构建的每个 Android 应用程序都应该包含预定义的目录结构和配置`.xml`文件。这可以使用 Android SDK 工具和 IDE 完成。在本教程中，我们将学习如何手动完成。我们稍后会把这些文件作为所有示例的起点。

## 准备工作

让我们设置项目的目录结构（见下截图）：

![准备工作](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_02_3.jpg)

这是一般 Android 项目的典型结构。我们将手动创建所有必需的文件，而不是使用 Android 工具。

## 如何操作...

将 Java `Activity`代码放入`App1\src\com\packtpub\ndkcookbook\app1\App1Activity.java`文件中，其内容应如下所示：

```kt
package com.packtpub.ndkcookbook.app1;
import android.app.Activity;
public class App1Activity extends Activity
{
};
```

可本地化的应用程序名称应放入`App1\res\values\strings.xml`。在`AndroidManifest.xml`文件中，字符串参数`app_name`用于指定我们应用程序的用户可读名称，如下代码所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">App1</string>
</resources>
```

现在我们需要为 Apache Ant 和 Android SDK 构建系统编写更多脚本。它们是构建应用程序的`.apk`包所必需的。

1.  下面是`App1/project.properties`文件：

    ```kt
    target=android-15
    sdk.dir=d:/android-sdk-windows
    ```

1.  我们还需要为 Ant 准备两个文件。以下是`App1/AndroidManifest.xml`：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <manifest 
      package="com.packtpub.ndkcookbook.app1"
      android:versionCode="1"
      android:versionName="1.0.0">
      <supports-screens
         android:smallScreens="false"
         android:normalScreens="true"
         android:largeScreens="true"
         android:xlargeScreens="true"
         android:anyDensity="true" />
      <uses-sdk android:minSdkVersion="8" />
      <uses-sdk android:targetSdkVersion="18" />
    ```

    我们的示例至少需要 OpenGL ES 2。让 Android 知道这一点：

    ```kt
      <uses-feature android:glEsVersion="0x00020000"/>
      <application android:label="@string/app_name"
                   android:icon="@drawable/icon"
                   android:installLocation="preferExternal"
                   android:largeHeap="true"
                   android:debuggable="false">
      <activity android:name="com.packtpub.ndkcookbook.app1.App1Activity"
    android:launchMode="singleTask"
    ```

    创建一个横屏方向的全屏应用程序：

    ```kt
                      android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
                      android:screenOrientation="landscape"
                      android:configChanges="orientation|keyboardHidden"
                      android:label="@string/app_name">
        <intent-filter>
          <action android:name="android.intent.action.MAIN" />
          <category android:name="android.intent.category.LAUNCHER" />
         </intent-filter>
       </activity>
     </application>
    </manifest>
    ```

    第二个文件是`App1/build.xml`：

    ```kt
    <?xml version="1.0" encoding="UTF-8"?>
    <project name="App1" default="help">
        <property file="ant.properties" />
        <loadproperties srcFile="project.properties" />
        <import file="${sdk.dir}/tools/ant/build.xml" />
    </project>
    ```

## 工作原理...

将所有列出的文件就位后，我们现在可以构建项目并将其安装在 Android 设备上，具体步骤如下：

1.  从`App1`文件夹运行：

    ```kt
    >ant debug

    ```

1.  之前命令输出的末尾应如下所示：

    ```kt
    BUILD SUCCESSFUL
    Total time: 12 seconds

    ```

1.  构建的调试`.apk`包位于`bin/App1-debug.apk`。

1.  要安装应用，请运行：

    ```kt
    >adb install App1-debug.apk

    ```

    ### 注意

    在运行此命令之前，不要忘记通过 USB 连接设备并在 Android 设置中打开 USB 调试。

1.  您应该看到来自`adb`的输出，类似于以下命令：

    ```kt
    * daemon not running. starting it now on port 5037 *
    * daemon started successfully *
    1256 KB/s (8795 bytes in 0.006s)
     pkg: /data/local/tmp/App1-debug.apk
    Success

    ```

应用程序现在可以从您的 Android 启动器（名为`App1`）启动。您将看到一个黑色屏幕。您可以使用**返回**按钮退出应用程序。

## 还有更多...

不要忘记将应用图标放入`App1\res\drawable\icon.png`。如果您想快速构建应用程序，可以参考本书的代码包，或者放置自己的图标。72 x 72 32 位即可。您可以在[`developer.android.com/design/style/iconography.html`](http://developer.android.com/design/style/iconography.html)找到官方的 Android 图标指南。

关于`AndroidManifest.xml`文件的官方文档可以在[`developer.android.com/guide/topics/manifest/manifest-intro.html`](http://developer.android.com/guide/topics/manifest/manifest-intro.html)找到。

此外，您可以使用以下方式通过`adb -r`命令行开关更新应用程序，而无需卸载之前的版本：

```kt
>adb install -r App1-debug.apk

```

否则，在安装应用程序的新版本之前，您必须使用以下命令卸载现有版本：

```kt
>adb uninstall <package-name>

```

## 另请参阅...

+   *签名发布 Android 应用程序*

# 向您的应用程序添加本地 C++代码

让我们扩展之前食谱中讨论的最小化 Java 模板，以便为我们的本地 C++代码创建一个占位符。

## 准备就绪

我们需要将`App1`项目中的所有文件复制过来，以便在创建初始项目文件时节省时间。这个食谱将重点介绍需要修改`App1`项目以添加 C++代码的内容。

## 如何操作...

执行以下步骤为我们的 C++代码创建占位符：

1.  添加包含以下代码的`jni/Wrappers.cpp`文件：

    ```kt
    #include <stdlib.h>
    #include <jni.h>
    #include <android/log.h>
    #define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "App2", __VA_ARGS__))

    extern "C"
    {
      JNIEXPORT void JNICALL
    Java_com_packtpub_ndkcookbook_app2_App2Activity_onCreateNative( JNIEnv* env, jobject obj )
        {
          LOGI( "Hello World!" );
        }
    }
    ```

1.  我们需要修改前一个食谱中的`Activity`类，以便通过以下代码利用我们在上一节中添加的本机代码：

    ```kt
    package com.packtpub.ndkcookbook.app2;

    import android.app.Activity;
    import android.os.Bundle;

    public class App2Activity extends Activity
    {
        static
        {
    ```

    在这里我们加载名为`libApp2.so`的本机库。注意省略的`lib`前缀和`.so`扩展名：

    ```kt
          System.loadLibrary( "App2" );
        }
        @Override protected void onCreate( Bundle icicle )
        {
          super.onCreate( icicle );
          onCreateNative();
        }
        public static native void onCreateNative();
    };
    ```

1.  告诉 NDK 构建系统如何处理`.cpp`文件。创建`jni/Android.mk`文件。`Android.mk`文件由 Android NDK 构建系统使用，以了解如何处理项目的源代码：

    ```kt
    TARGET_PLATFORM := android-7
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_ARM_MODE := arm
    LOCAL_MODULE     := App2
    LOCAL_SRC_FILES += Wrappers.cpp
    LOCAL_ARM_MODE := arm
    COMMON_CFLAGS := -Werror -DANDROID -DDISABLE_IMPORTGL \
    -isystem $(SYSROOT)/usr/include/
    ifeq ($(TARGET_ARCH),x86)
    	LOCAL_CFLAGS   := $(COMMON_CFLAGS)
      else
    	LOCAL_CFLAGS   := -mfpu=vfp -mfloat-abi=softfp \
      -fno-short-enums $(COMMON_CFLAGS)
    endif
    LOCAL_LDLIBS     := -llog -lGLESv2 -Wl,-s
    LOCAL_CPPFLAGS += -std=gnu++0x
    include $(BUILD_SHARED_LIBRARY)
    ```

    注意 `ifeq ($(TARGET_ARCH),x86)` 部分。在这里，我们为 ARMv7 上的浮点支持指定了架构特定的编译器标志。这将在 ARM 架构上为您提供硬件浮点支持，并在 x86 Android 目标架构上提供无警告的日志。

1.  将以下代码粘贴到 `jni/Application.mk` 文件中：

    ```kt
    APP_OPTIM := release
    APP_PLATFORM := android-7
    APP_STL := gnustl_static
    APP_CPPFLAGS += -frtti 
    APP_CPPFLAGS += -fexceptions
    APP_CPPFLAGS += -DANDROID
    APP_ABI := armeabi-v7a
    APP_MODULES := App2
    NDK_TOOLCHAIN_VERSION := clang
    ```

## 工作原理...

1.  首先，我们需要编译本地代码。从 `App2` 项目的根目录运行以下命令：

    ```kt
    >ndk-build

    ```

1.  您应该看到以下输出：

    ```kt
    Compile++ arm: App2 <= Wrappers.cpp
    SharedLibrary: libApp2.so
    Install      : libApp2.so => libs/armeabi-v7a/libApp2.so

    ```

1.  现在，像上一个食谱一样，通过运行以下命令开始创建 `.apk`：

    ```kt
    >ant debug

    ```

1.  您的 `libApp2.so` 本地共享库将被打包进 `App2-debug.apk` 文件中。安装并运行它，它将在设备日志中输出 `Hello World!` 字符串。

## 还有更多...

您可以使用 `adb` 命令查看设备日志。使用以下命令可以创建一个带有时间戳的整洁格式化日志：

```kt
>adb logcat -v time > 1.txt

```

从您的设备实际输出的内容将类似于以下命令：

```kt
05-22 13:00:13.861 I/App2    ( 2310): Hello World!

```

# 切换 NDK 工具链

工具链是一组用于构建项目的工具。工具链通常包括编译器、汇编器和链接器。Android NDK 提供了不同版本的 GCC 和 Clang 不同的工具链。它有一种方便简单的方式来切换它们。

## 准备就绪

在继续操作之前，请查看可用的工具链列表。您可以在 `$(NDK_ROOT)/toolchains/` 文件夹中找到所有可用的工具链。

## 如何操作...

`Application.mk` 中的参数 `NDK_TOOLCHAIN_VERSION` 对应于可用的工具链之一。在 NDK r9b 中，您可以在三个 GCC 版本之间切换—4.6 和 4.7（已被标记为不推荐使用，并将在下一个 NDK 版本中移除），以及 4.8。还有两个 Clang 版本—Clang3.2（也已标记为不推荐使用）和 Clang3.3。NDK r9b 中的默认工具链仍然是 GCC 4.6。

从 NDK r8e 开始，您只需将 `clang` 指定为 `NDK_TOOLCHAIN_VERSION` 的值。此选项将选择可用的最新 Clang 工具链版本。

## 还有更多...

工具链是由 `$(NDK_ROOT)/build/core/init.mk` 脚本发现的，因此您可以在名为 `<ABI>-<ToolchainName>` 的文件夹中定义自己的工具链，并在 `Application.mk` 中使用它。

# 支持多种 CPU 架构

Android NDK 支持不同的 CPU 架构，例如基于 ARMv5TE 和 ARMv7 的设备、x86 和 MIPS（大端架构）。我们可以创建能在任何支持平台上运行的**胖**二进制文件。

## 准备就绪

查找基于 Android 的设备的架构。您可以使用以下 `adb` 命令进行操作：

```kt
>adb shell cat /proc/cpuinfo

```

## 如何操作...

以下是选择适当 CPU 架构集的两种方法：

1.  默认情况下，NDK 将为基于 ARMv5TE 的 CPU 生成代码。在 `Application.mk` 中使用参数 `APP_ABI` 选择不同的架构，例如（从以下列表中选择一行）：

    ```kt
    APP_ABI := armeabi-v7a
    APP_ABI := x86
    APP_ABI := mips
    ```

1.  我们可以指定多个架构，通过以下命令创建一个胖二进制文件，以便在任何架构上运行：

    ```kt
    APP_ABI := armeabi armeabi-v7a x86 mips
    ```

## 还有更多内容...

胖二进制的主要缺点是生成的`.apk`大小，因为为每个指定的架构编译了单独的本地代码版本。如果你的应用程序大量使用第三方库，那么包大小可能会成为问题。请明智地规划你的交付物。

# 使用 OpenGL ES 的基本渲染

让我们为示例 Android 应用程序`App2`添加一些图形。在这里，我们展示了如何创建一个离屏位图，然后使用你 Android 设备上可用的 OpenGL ES 版本 2 或 3 将其复制到屏幕上。

### 注意

有关完整源代码，请参考书中可下载代码包中的`App3`示例。

## 准备工作

我们假设读者对 OpenGL 和**GL 着色语言**（**GLSL**）有一定的了解。有关桌面 OpenGL 的文档，请参考[`www.opengl.org/documentation`](http://www.opengl.org/documentation)，有关移动 OpenGL ES 的文档，请参考[`www.khronos.org/opengles`](http://www.khronos.org/opengles)。

## 如何操作...

1.  我们需要编写一个简单的顶点和片段 GLSL 着色器，它将使用 OpenGL ES 在屏幕上渲染我们的帧缓冲区。我们将它们直接作为字符串放入`jni/Wrappers.cpp`中。以下代码显示了顶点着色器：

    ```kt
    static const char g_vShaderStr[] =
       "#version 100\n"
       "precision highp float;\n"
       "attribute vec3 vPosition;\n"
       "attribute vec3 vCoords;\n"
       "varying vec2 Coords;\n"
       "void main()\n"
       "{\n"
       "   Coords = vCoords.xy;\n"
       "   gl_Position = vec4( vPosition, 1.0 );\n"
       "}\n";
    ```

1.  片段着色器如下：

    ```kt
    static const char g_fShaderStr[] =
       "#version 100\n"
       "precision highp float;\n"
       "varying vec2 Coords;\n"
       "uniform sampler2D Texture0;\n"
       "void main()\n"
       "{\n"
       "   gl_FragColor = texture2D( Texture0, Coords );\n"
       "}\n";
    ```

1.  我们还需要以下帮助函数来将着色器加载到 OpenGL ES 中：

    ```kt
    static GLuint LoadShader( GLenum type, const char* shaderSrc )
    {
       GLuint shader = glCreateShader( type );
       glShaderSource ( shader, 1, &shaderSrc, NULL );
       glCompileShader ( shader );
       GLint compiled;
       glGetShaderiv ( shader, GL_COMPILE_STATUS, &compiled );
       GLsizei MaxLength = 0;
       glGetShaderiv( shader, GL_INFO_LOG_LENGTH, &MaxLength );
       char* InfoLog = new char[MaxLength];
       glGetShaderInfoLog( shader, MaxLength, &MaxLength, InfoLog );
       LOGI( "Shader info log: %s\n", InfoLog );
       return shader;
    }
    ```

## 工作原理...

在这里，我们不会详细介绍 OpenGL ES 编程的所有细节，而是专注于一个最小的应用程序（`App3`），它应该在 Java 中初始化`GLView`；创建片段和顶点程序，创建并填充由两个三角形组成的单一四边形的顶点数组，然后用纹理渲染它们，该纹理是从`g_FrameBuffer`内容更新的。就是这样——只需绘制离屏帧缓冲区。以下代码展示了用离屏缓冲区内容绘制全屏四边形的纹理：

```kt
  const GLfloat vVertices[] = { -1.0f, -1.0f, 0.0f,
                                -1.0f,  1.0f, 0.0f,
                                 1.0f, -1.0f, 0.0f,
                                -1.0f,  1.0f, 0.0f,
                                1.0f, -1.0f, 0.0f,
                                1.0f,  1.0f, 0.0f
                              };

  const GLfloat vCoords[]   = {  0.0f,  0.0f, 0.0f,
                                 0.0f,  1.0f, 0.0f,
                                 1.0f,  0.0f, 0.0f,
                                 0.0f,  1.0f, 0.0f,
                                 1.0f,  0.0f, 0.0f,
                                 1.0f,  1.0f, 0.0f
                              };
  glUseProgram ( g_ProgramObject );
```

这些属性变量在顶点着色器中声明。请参考前面代码中的`g_vShaderStr[]`的值。

```kt
  GLint Loc1 = glGetAttribLocation(g_ProgramObject,"vPosition");
  GLint Loc2 = glGetAttribLocation(g_ProgramObject,"vCoords");

  glBindBuffer( GL_ARRAY_BUFFER, 0 );
  glBindBuffer( GL_ELEMENT_ARRAY_BUFFER, 0 );
  glVertexAttribPointer(
    Loc1, 3, GL_FLOAT, GL_FALSE, 0, vVertices );
  glVertexAttribPointer(
    Loc2, 3, GL_FLOAT, GL_FALSE, 0, vCoords   );
  glEnableVertexAttribArray( Loc1 );
  glEnableVertexAttribArray( Loc2 );

  glDisable( GL_DEPTH_TEST );
  glDrawArrays( GL_TRIANGLES, 0, 6 );
  glUseProgram( 0 );
  glDisableVertexAttribArray( Loc1 );
  glDisableVertexAttribArray( Loc2 );
```

我们还需要一些 JNI 回调。第一个处理表面大小变化，如下代码所示：

```kt
  JNIEXPORT void JNICALLJava_com_packtpub_ndkcookbook_app3_App3Activity_SetSurfaceSize(JNIEnv* env, jclass clazz, int Width, int Height )
  {
    LOGI( "SurfaceSize: %i x %i", Width, Height );
    g_Width  = Width;
    g_Height = Height;
    GLDebug_LoadStaticProgramObject();
    glGenTextures( 1, &g_Texture );
    glBindTexture( GL_TEXTURE_2D, g_Texture );
```

通过以下代码禁用纹理映射：

```kt
    glTexParameteri( GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA,ImageWidth, ImageHeight, 0, GL_RGBA,GL_UNSIGNED_BYTE, g_FrameBuffer );
  }
```

第二个回调实际执行帧渲染：

```kt
  JNIEXPORT void JNICALL Java_com_packtpub_ndkcookbook_app3_App3Activity_DrawFrame( JNIEnv* env, jobject obj )
  {
```

通过以下代码调用我们的帧渲染回调：

```kt
    OnDrawFrame();

    glActiveTexture( GL_TEXTURE0 );
    glBindTexture( GL_TEXTURE_2D, g_Texture );
    glTexSubImage2D( GL_TEXTURE_2D, 0, 0, 0,ImageWidth, ImageHeight, GL_RGBA,GL_UNSIGNED_BYTE, g_FrameBuffer );
    GLDebug_RenderTriangle();
  }
```

# 跨平台开发

主要思想是在 What You See (在 PC 上) is What You Get (在设备上) 的跨平台开发可能性，当大部分应用程序逻辑可以在像 Windows 这样的熟悉桌面环境中开发，并且必要时可以使用 NDK 为 Android 构建。

## 准备工作

要实现我们刚才讨论的内容，我们必须在 NDK、POSIX 和 Windows API 之上实现某种抽象。这种抽象至少应该具备以下特点：

+   **能够在屏幕上渲染缓冲区内容**：我们的框架应该提供函数，将离屏 framebuffer（一个 2D 像素数组）的内容构建到屏幕上（对于 Windows，我们将窗口称为“屏幕”）。

+   **事件处理**：框架必须能够处理多点触控输入以及虚拟/物理按键按下（一些 Android 设备，如东芝 AC 100，或者 Ouya 游戏机以及其他游戏设备具有物理按钮），定时事件以及异步操作完成。

+   **文件系统、网络和音频播放**：这些实体的抽象层需要你完成大量工作，因此实现在第三章，*网络编程*，第四章，*组织虚拟文件系统*，以及第五章，*跨平台音频流*中介绍。

## 如何进行...

1.  让我们继续为 Windows 环境编写一个最小应用程序，因为我们已经有了 Android 的应用程序（例如，`App1`）。一个最小化的 Windows GUI 应用程序是指创建单一窗口并启动事件循环的应用程序（见以下`Win_Min1/main.c`中的示例）：

    ```kt
    #include <windows.h>

    LRESULT CALLBACK MyFunc(HWND h, UINT msg, WPARAM w, LPARAM p)
    {
      if(msg == WM_DESTROY) { PostQuitMessage(0); }
      return DefWindowProc(h, msg, w, p);
    }

    char WinName[] = "MyWin";
    ```

1.  入口点与 Android 不同。但其目的依然不变——初始化表面渲染并调用回调：

    ```kt
    int main()
    {
      OnStart();

      const char WinName[] = "MyWin";

      WNDCLASS wcl;
      memset( &wcl, 0, sizeof( WNDCLASS ) );
      wcl.lpszClassName = WinName;
      wcl.lpfnWndProc = MyFunc;
      wcl.hCursor = LoadCursor( NULL, IDC_ARROW );

      if ( !RegisterClass( &wcl ) ) { return 0; }

      RECT Rect;

      Rect.left = 0;
      Rect.top = 0;
    ```

1.  窗口客户区的尺寸预定义为`ImageWidth`和`ImageHeight`常量。然而，WinAPI 函数`CreateWindowA()`接受的并非客户区的尺寸，而是包括标题栏、边框和其他装饰的窗口尺寸。我们需要通过以下代码调整窗口矩形，以将客户区设置为期望的尺寸：

    ```kt
      Rect.right  = ImageWidth;
      Rect.bottom = ImageHeight;

      DWORD dwStyle = WS_OVERLAPPEDWINDOW;

      AdjustWindowRect( &Rect, dwStyle, false );

      int WinWidth  = Rect.right  - Rect.left;
      int WinHeight = Rect.bottom - Rect.top;

      HWND hWnd = CreateWindowA( WinName, "App3", dwStyle,100, 100, WinWidth, WinHeight,0, NULL, NULL, NULL );
      ShowWindow( hWnd, SW_SHOW );

      HDC dc = GetDC( hWnd );
    ```

1.  通过以下代码创建离屏设备上下文和位图，该位图保存我们的离屏 framebuffer：

    ```kt
      hMemDC = CreateCompatibleDC( dc );
      hTmpBmp = CreateCompatibleBitmap( dc,ImageWidth, ImageHeight );
      memset( &BitmapInfo.bmiHeader, 0,sizeof( BITMAPINFOHEADER ) );
      BitmapInfo.bmiHeader.biSize = sizeof( BITMAPINFOHEADER );
      BitmapInfo.bmiHeader.biWidth = ImageWidth;
      BitmapInfo.bmiHeader.biHeight = ImageHeight;
      BitmapInfo.bmiHeader.biPlanes = 1;
      BitmapInfo.bmiHeader.biBitCount = 32;
      BitmapInfo.bmiHeader.biSizeImage = ImageWidth*ImageHeight*4;
      UpdateWindow( hWnd );
    ```

1.  创建应用程序窗口后，我们必须运行一个典型的消息循环：

    ```kt
      MSG msg;
      while ( GetMessage( &msg, NULL, 0, 0 ) )
      {
        TranslateMessage( &msg );
        DispatchMessage( &msg );
      }
      …
    }
    ```

1.  这个程序只处理窗口销毁事件，并不渲染任何内容。编译此程序只需以下单一命令：

    ```kt
    >gcc -o main.exe main.c -lgdi32
    ```

## 它是如何工作的...

要在屏幕上渲染一个 framebuffer，我们需要创建一个所谓的设备上下文以及相关的位图，并在窗口函数中添加`WM_PAINT`事件处理程序。

为了处理键盘和鼠标事件，我们在之前程序的`switch`语句中添加了`WM_KEYUP`和`WM_MOUSEMOVE`的情况。实际的事件处理在外部提供的例程`OnKeyUp()`和`OnMouseMove()`中执行，这些例程包含了我们的游戏逻辑。

以下是程序完整的源代码（省略的部分与之前的示例相似）。函数`OnMouseMove()`、`OnMouseDown()`和`OnMouseUp()`接受两个整数参数，用于存储鼠标指针的当前坐标。函数`OnKeyUp()`和`OnKeyDown()`接受一个参数——按下的（或释放的）键码：

```kt
#include <windows.h>

HDC hMemDC;
HBITMAP hTmpBmp;
BITMAPINFO BmpInfo;
```

在以下代码中，我们存储全局 RGBA 帧缓冲区：

```kt
unsigned char* g_FrameBuffer;
```

我们在这个回调中完成所有与操作系统无关的帧渲染。我们绘制一个简单的 XOR 图案（[`lodev.org/cgtutor/xortexture.html`](http://lodev.org/cgtutor/xortexture.html)）到帧缓冲区中，如下所示：

```kt
void DrawFrame()
{
  int x, y;
  for (y = 0 ; y < ImageHeight ; y++)
  {
    for (x = 0 ; x < ImageWidth ; x++)
    {
      int Ofs = y * ImageWidth + x;
      int c = (x ^ y) & 0xFF;
      int RGB = (c<<16) | (c<<8) | (c<<0) | 0xFF000000;
      ( ( unsigned int* )g_FrameBuffer )[ Ofs ] =	RGB;
    }
  }
}
```

以下代码展示了`WinAPI`窗口函数：

```kt
LRESULT CALLBACK MyFunc(HWND h, UINT msg, WPARAM w, LPARAM p)
{
  PAINTSTRUCT ps;
  switch(msg)
  {
  case WM_DESTROY:
    PostQuitMessage(0);
break;
  case WM_KEYUP:
    OnKeyUp(w);
break;
  case WM_KEYDOWN:
    OnKeyDown(w);
break;
  case WM_LBUTTONDOWN:
    SetCapture(h);
    OnMouseDown(x, y);
break;
  case WM_MOUSEMOVE:
    OnMouseMove(x, y);
break;
  case WM_LBUTTONUP:
    OnMouseUp(x, y);
    ReleaseCapture();
break;
  case WM_PAINT:
    dc = BeginPaint(h, &ps);
    DrawFrame();         
```

通过以下代码将`g_FrameBuffer`传输到位图：

```kt
    SetDIBits(hMemDC, hTmpBmp, 0, Height,g_FrameBuffer, &BmpInfo, DIB_RGB_COLORS);
    SelectObject(hMemDC, hTmpBmp);
```

并通过以下代码将其复制到窗口表面：

```kt
    BitBlt(dc, 0, 0, Width, Height, hMemDC, 0, 0, SRCCOPY);
    EndPaint(h, &ps);
break;
  }
  return DefWindowProc(h, msg, w, p);
}
```

由于我们的项目包含一个 make 文件，因此可以通过单个命令完成编译：

```kt
>make all

```

运行此程序应产生如下截图所示的结果，显示了在 Windows 上运行的**Win_Min2**示例：

![工作原理…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_02_4.jpg)

## 还有更多…

安卓和 Windows 对主循环的实现主要区别可以概括如下。在 Windows 中，我们控制主循环。我们声明一个循环，从系统中获取消息，处理输入，更新游戏状态，并渲染帧（在以下图中以绿色标记）。每个阶段调用我们可移植游戏中的适当回调（以下图中以蓝色表示）。相反，安卓部分的工作方式完全不同。主循环从本地代码中移出，并存在于**Java Activity**和**GLSurfaceView**类中。它调用我们在封装本地库中实现的 JNI 回调（以下图中以红色显示）。本地封装器调用我们的可移植游戏回调。以下是这样总结的：

![还有更多…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_02_05.jpg)

书的其余部分以此类架构为中心，游戏功能将在这些可移植**On...()**回调中实现。

还有一个重要的注意事项。对定时器事件做出响应以创建动画，在 Windows 上可以通过`SetTimer()`调用和`WM_TIMER`消息处理程序来完成。我们在第二章，*移植公共库*中讨论刚体物理模拟时会涉及到这一点。然而，组织一个固定时间步长主循环会更好，这在本书的后面会解释。

## 另请参阅

+   第六章，*统一 OpenGL ES 3 和 OpenGL 3*

+   第八章，*编写消除类游戏*中的食谱*实现主循环*

# 统一跨平台代码

现在，我们有一个简单程序的两个不同版本（`Win_Min2`和`App3`）。让我们看看如何统一代码的公共部分。

## 准备就绪

在 Android 中，应用程序初始化阶段是不同的，由于我们采用了混合 Java 和 C++的方法，入口点也会有所不同。在 C++中，我们依赖于`int main()`或`DWORD WinMain()`函数；而在 Android 中，我们可以从 Java 启动代码中调用我们选择的 JNI 函数。事件处理和初始化代码的渲染也有很大差异。为此，我们使用预处理器定义标记代码部分，并将不同操作系统的代码放入不同的文件中——`Wrappers_Android.h`和`Wrappers_Windows.h`。

## 如何操作...

我们使用标准宏来检测程序正在编译的目标操作系统：针对 Windows 的编译器提供`_WIN32`符号定义，而任何基于 Linux 的操作系统（包括 Android）都会定义`__linux__`宏。然而，`__linux__`的定义还不够，因为 Android 中缺少一些 API。`ANDROID`是一个非标准宏，我们向编译器传递`-DANDROID`开关，以便在我们的 C++代码中识别 Android 目标。为了对每个源文件执行此操作，我们修改了`Android.mk`文件中的`CFLAGS`变量。

最后，当我们编写低级代码时，检测看起来如下面的代码所示：

```kt
#if defined(_WIN32)
// windows-specific code
#elif defined(ANDROID)
// android-specific code
#endif
```

例如，为了使 Android 和 Windows 版本的入口点看起来相同，我们编写以下代码：

```kt
#if defined(_WIN32)
#  define APP_ENTRY_POINT()  int main()
#elif defined(ANDROID)
#  define APP_ENTRY_POINT() int App_Init()
#endif
```

稍后我们将用`APP_ENTRY_POINT()`宏替换`int main()`的定义。

## 还有更多...

为了检测更多的操作系统、编译器和 CPU 架构，查看一下[`predef.sourceforge.net`](http://predef.sourceforge.net)上预定义的宏列表会很有帮助。

# 链接和源代码组织

在之前的食谱中，我们学习了如何创建基本的包装器，以允许我们的应用程序在 Android 和 Windows 上运行。然而，由于源代码量较少且适合放在单个文件中，我们采用了临时方法。我们必须以适合在 Windows 和 Android 上构建大型项目代码的方式组织我们的项目源文件。

## 准备工作

回顾一下`App3`项目的文件夹结构。我们在`App2`文件夹中拥有`src`和`jni`文件夹。`jni/Android.mk`、`jni/Application.mk`和`build.xml`文件指定了 Android 构建过程。为了启用 Windows 可执行文件的创建，我们添加了一个名为`Makefile`的文件，该文件引用了`main.cpp`文件。

## 如何操作...

下面是`Makefile`的内容：

```kt
CC = gcc
all:
  $(CC) -o main.exe main.cpp -lgdi32 -lstdc++
```

当我们添加越来越多的与操作系统无关的逻辑时，代码位于`.cpp`文件中，这些文件不引用任何特定于操作系统的头文件或库。对于前几章，这个简单的框架足够了，它将帧渲染和事件处理委托给可移植的、与操作系统无关的函数（`OnDrawFrame()`、`OnKeyUp()`等）。

## 工作原理...

后续章节中的所有示例都可以通过命令行在 Windows 上使用单个 `make all` 命令进行构建。Android 原生代码也可以通过单个 `ndk-build` 命令构建。我们将在本书的其余部分使用这个约定。

# 签名发布 Android 应用程序

现在，我们可以创建一个跨平台应用程序，在 PC 上进行调试，并将其部署到 Android 设备上。然而，我们还不能将其上传到 Google Play，因为它还没有（尚未）使用发布密钥正确签名。

## 准备就绪

Android 上签名过程的详细说明在开发者手册中有提供，地址是 [`developer.android.com/tools/publishing/app-signing.html`](http://developer.android.com/tools/publishing/app-signing.html)。我们将专注于从命令行进行签名，并通过批处理文件自动化整个流程。

## 如何操作...

首先，我们需要重新构建项目，并创建 `.apk` 包的发布版本。让我们用 `App2` 项目来完成这个操作：

```kt
>ndk-build -B
>ant release

```

你应该会看到来自 `Ant` 的很多文本输出，最后类似以下命令：

```kt
-release-nosign:
[echo] No key.store and key.alias properties found in build.properties.
[echo] Please sign App2\bin\App2-release-unsigned.apk manually
[echo] and run zipalign from the Android SDK tools.

```

让我们使用 JDK 中的 `keytool` 通过以下命令生成一个自签名的发布密钥：

```kt
>keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000

```

填写创建密钥所需的所有字段，如下面的命令所示：

```kt
Enter keystore password:
Re-enter new password:
What is your first and last name?
 [Unknown]:  Sergey Kosarevsky
What is the name of your organizational unit?
 [Unknown]:  SD
What is the name of your organization?
 [Unknown]:  Linderdaum
What is the name of your City or Locality?
 [Unknown]:  St.Petersburg
What is the name of your State or Province?
 [Unknown]:  Kolpino
What is the two-letter country code for this unit?
 [Unknown]:  RU
Is CN=Sergey Kosarevsky, OU=SD, O=Linderdaum, L=St.Petersburg, ST=Kolpino, C=RU correct?
 [no]:  yes

Generating 2048 bit RSA key pair and self-signed certificate (SHA1withRSA) with a validity of 10000 days
 for: CN=Sergey Kosarevsky, OU=SD, O=Linderdaum, L=St.Petersburg, ST=Kolpino, C=RU
Enter key password for <alias_name>
 (RETURN if same as keystore password):
[Storing my-release-key.keystore]

```

现在我们准备进行实际的应用程序签名。使用 JDK 中的 `jarsigner` 工具通过以下代码进行操作：

```kt
>jarsigner -verbose -sigalg MD5withRSA -digestalg SHA1 -keystore my-release-key.keystore bin\App2-release-unsigned.apk alias_name

```

这个命令是交互式的，它将要求用户输入密钥库密码和密钥密码。然而，我们可以通过以下方式在批处理文件中提供密码：

```kt
>jarsigner -verbose -sigalg MD5withRSA -digestalg SHA1 -keystore my-release-key.keystore -storepass 123456 –keypass 123456 bin\App2-release-unsigned.apk alias_name

```

密码应与创建发布密钥和密钥库时输入的信息相匹配。

在我们能够安全地在 Google Play 上发布 `.apk` 包之前，还有一步需要完成。Android 应用程序可以使用 `mmap()` 调用访问 `.apk` 中的未压缩内容。然而，`mmap()` 可能会对底层数据施加一些对齐限制。我们需要将 `.apk` 中的所有未压缩数据按照 4 字节边界对齐。Android SDK 提供了 `zipalign` 工具来完成这个任务，如下面的命令所示：

```kt
>zipalign -v 4 bin\App2-release-unsigned.apk App2-release.apk

```

现在，我们的 `.apk` 已经准备好发布。

## 另请参阅

+   第二章，*移植通用库*


# 第二章： 移植通用库

在本章中，我们将涵盖：

+   为 Windows 编译本地静态库

+   为 Android 编译本地静态库

+   编译 libcurl 网络库

+   编译 OpenAL 库

+   编译 libvorbis、libmodplug 和 libtheora

+   使用 FreeImage 图形库

+   使用 FreeType 库进行文本渲染

+   在物理中实现定时

+   在 2D 中渲染图形

+   设置 Box2D 模拟

+   构建 ODE 物理库

# 引言

本章介绍如何使用**Android NDK**将现有的流行 C/C++库移植到 Android。这些库广泛应用于在 C++中完全实现具有图形、声音和物理模拟的富特性应用程序。仅仅编译库并没有多大意义。因此，与 FreeImage、FreeType 和 Box2D 相关的部分提供了最小示例，以演示每个库的功能。音频和网络库将在后续章节中详细讨论。我们将向您展示如何编译库，当然也会提供一些简短的示例和关于如何开始使用它们的提示。

在不同的处理器和操作系统间移植库时典型的陷阱包括内存访问（结构对齐/填充）、字节序（大小端）、调用约定和浮点问题。下面描述的所有库都很好地处理了这些问题，即使其中一些库并不正式支持 Android NDK，修复这些问题也只是几个编译器开关的问题。

要构建上述任何库，我们需要为 Windows 版本创建 makefile，并为 Android NDK 创建一对`Android.mk`和`Application.mk`文件。库的源文件被编译成目标文件。一系列目标文件组合成一个存档，这也称为静态库。稍后，这个静态库可以作为链接器的输入传递。我们从 Windows 版本开始，因为`Android.mk`和`Application.mk`文件是基于标准 makefile 构建的。

# 为 Windows 编译本地静态库

要构建 Windows 版本的库，我们需要一个 C++编译器。我们使用第一章中描述的 GCC 工具链的 MinGW。对于每个库，我们有一系列的源代码文件，并且我们需要得到静态库，一个带有`.a`扩展名的文件。

## 准备就绪

假设`src`目录包含我们需要为 Android 构建的库的源代码。

## 如何操作...

1.  让我们从编写 makefile 开始：

    ```kt
    CFLAGS = -I src
    ```

    这行定义了一个变量，其中包含编译器命令行参数的列表。在我们的例子中，我们指示编译器在`src`目录中查找头文件。如果库的源代码跨越许多目录，我们需要为每个目录添加`–I`开关。

1.  接下来，我们为每个源文件添加以下行：

    ```kt
    <SourceFile>.o:
      gcc $(CFLAGS) –c <SourceFile>.cpp –o <SourceFile>.o
    ```

    `<SourceFile>`应该被替换为实际的`.cpp`源文件名，并且针对每个源文件都要编写这些行。

1.  现在，我们添加目标文件列表：

    ```kt
    ObjectFiles = <SourceFile1>.o <SourceFile2>.o ...
    ```

1.  最后，我们编写库的目标：

    ```kt
    <LibraryName>:
      ar –rvs <LibraryName>.a $(ObjectList)
    ```

    ### 注意

    makefile 中的每一行，除了空行和目标名称，都应该以制表符开头。

1.  要构建库，请调用以下命令：

    ```kt
    >make <LibraryName>.a
    ```

    当在程序中使用库时，我们将`LibraryName.a`文件作为参数传递给`gcc`。

## 工作原理...

Makefiles 由类似于编程语言中的子例程的目标组成，通常每个目标都会生成一个目标文件。例如，我们已经看到，库的每个源文件都被编译成相应的目标文件。

目标名称可能包含文件名模式，以避免复制和粘贴，但在最简单的情况下，我们只需列出所有的源文件，并替换`SourceFile`为适当的文件名，复制这些行。`gcc`命令后的`–c`开关是编译源文件的选项，`–o`指定输出目标文件的名字。`$(CFLAGS)`符号表示将`CFLAGS`变量的值替换到命令行中。

Windows 的 GCC 工具链包括`AR`工具，这是归档器的缩写。我们库的 makefiles 调用此工具来创建库的静态版本。这是在 makefile 的最后几行完成的。

## 还有更多...

下面是一些编写 makefiles 的技巧：

1.  当带有目标文件列表的行变得过长时，可以使用反斜杠符号进行拆分，如下所示：

    ```kt
    ObjectFileList = File1.o \
       ... \
       FileN.o
    ```

    ### 注意

    反斜杠后面不应该有空格。这是`make`工具的一个限制。

1.  有时需要注释。这可以通过编写以井号开头的行来完成：

    ```kt
    # This line is a comment
    ```

如果库的头文件不在源文件所在的目录中，我们必须将这些目录添加到`CFLAGS`列表中。

# 为 Android 编译本地静态库

Android NDK 包括针对每种支持处理器的多个 GCC 和 Clang 工具链。

## 准备就绪

从源代码构建静态库时，我们遵循与 Windows 版本类似的步骤。

## 如何操作...

1.  创建一个名为`jni`的文件夹，并创建一个`Application.mk`文件，其中包含适当的编译器开关，并相应地设置库的名称。例如，FreeImage 库的一个示例应如下所示：

    ```kt
    APP_OPTIM := release
    APP_PLATFORM := android-8
    APP_STL := gnustl_static
    APP_CPPFLAGS += -frtti 
    APP_CPPFLAGS += -fexceptions
    APP_CPPFLAGS += -DANDROID
    APP_ABI := armeabi-v7a x86
    APP_MODULES := FreeImage
    ```

1.  `Android.mk`文件与我们之前章节为示例应用程序编写的类似，但有一些例外。在文件的顶部，必须定义一些必要的变量。让我们看看 FreeImage 库的`Android.mk`文件可能如下所示：

    ```kt
    # Android API level
    TARGET_PLATFORM := android-8
    # local directory
    LOCAL_PATH := $(call my-dir)
    # the command to reset the compiler flags to the empty state
    include $(CLEAR_VARS)
    # use the complete ARM instruction set
    LOCAL_ARM_MODE := arm
    # define the library name and the name of the .a file
    LOCAL_MODULE     := FreeImage
    # add the include directories
    LOCAL_C_INCLUDES += src \
    # add the list of source files
    LOCAL_SRC_FILES += <ListOfSourceFiles>
    ```

1.  定义一些常见的编译器选项：将所有警告视为错误（`-Werror`），定义`ANDROID`预处理符号，设置`system`包含目录：

    ```kt
    COMMON_CFLAGS := -Werror -DANDROID -isystem $(SYSROOT)/usr/include/
    ```

1.  编译标志根据选定的 CPU 架构而定：

    ```kt
    ifeq ($(TARGET_ARCH),x86)
      LOCAL_CFLAGS   := $(COMMON_CFLAGS)
    else
      LOCAL_CFLAGS   := -mfpu=vfp -mfloat-abi=softfp -fno-short-enums $(COMMON_CFLAGS)
    endif
    ```

1.  由于我们正在构建一个静态库，我们需要在 makefile 文件末尾添加以下行：

    ```kt
    include $(BUILD_STATIC_LIBRARY)
    ```

## 工作原理...

Android NDK 开发者提供了一组自己的规则来构建应用程序和库。在前一章中，我们看到了如何构建带有`.so`扩展名的共享对象文件。在这里，我们只需将`BUILD_SHARED_LIBRARY`符号替换为`BUILD_STATIC_LIBRARY`，并明确列出构建每个对象文件所需的源文件。

### 注意

当然，你可以构建一个共享库并以动态方式将你的应用程序链接到它。然而，这通常是在库位于系统内并被多个应用程序共享时是一个不错的选择。在我们的情况下，由于我们的应用程序是库的唯一用户，静态链接将使项目链接和调试更加容易。

# 编译 libcurl 网络库

libcurl 库是处理众多网络协议的本机应用程序的实际标准。在 Windows 主机上为 Android 编译 libcurl 需要进行一些额外的步骤。我们在此食谱中解释它们。

## 准备工作

从库主页下载 libcurl 源代码：[`curl.haxx.se/libcurl/`](http://curl.haxx.se/libcurl/)。

## 如何操作...

1.  由于 libcurl 库的构建过程基于`Autoconf`，我们实际上在构建库之前需要生成一个`curl_config.h`文件。从包含未打包的 libcurl 发行包的文件夹中运行`configure`脚本。交叉编译命令行标志应设置为：

    ```kt
    --host=arm-linux CC=arm-eabi-gcc
    ```

1.  `CPPFLAGS`变量的`-I`参数应指向你的 NDK 文件夹中的`/system/core/include`子文件夹，在我们的情况下：

    ```kt
    CPPFLAGS=”-I D:/NDK/system/core/include”
    ```

1.  libcurl 库可以通过多种方式进行定制。我们使用这组参数（除了 HTTP 之外禁用所有协议）：

    ```kt
    >configure CC=arm-eabi-gcc --host=arm-linux --disable-tftp --disable-sspi --disable-ipv6 --disable-ldaps --disable-ldap --disable-telnet --disable-pop3 --disable-ftp --without-ssl --disable-imap --disable-smtp --disable-pop3 --disable-rtsp --disable-ares --without-ca-bundle --disable-warnings --disable-manual --without-nss --enable-shared --without-zlib --without-random --enable-threaded-resolver
    ```

1.  `configure`脚本将生成一个有效的`curl_config.h`头文件。你可以在配套材料中找到它。

1.  进一步编译需要一套常规的`Android.mk/Application.mk`文件，这些文件也包含在配套材料中。

## 工作原理…

一个简单的使用示例如下所示：

```kt
CURL* Curl = curl_easy_init();
curl_easy_setopt( Curl, CURLOPT_URL, “http://www.google.com” );
curl_easy_setopt( Curl, CURLOPT_FOLLOWLOCATION, 1 );
curl_easy_setopt( Curl, CURLOPT_FAILONERROR, true );
curl_easy_setopt( Curl, CURLOPT_WRITEFUNCTION, &MemoryCallback );
curl_easy_setopt( Curl, CURLOPT_WRITEDATA, 0 );
curl_easy_perform( Curl );
curl_easy_cleanup( Curl );
```

在这里，`MemoryCallback()`是处理接收到的数据的函数。将网络响应转储到终端的最小化不安全实现可以如下所示：

```kt
size_t MemoryCallback( void* P, size_t Size, size_t Num, void* )
{
  printf( (unsigned char*)P) );
}
```

在 Windows 应用程序中，检索到的数据将在屏幕上打印。同样的代码在 Android 中将像一个哑巴一样工作，不会产生任何可见的副作用。

## 还有更多…

为了处理 SSL 加密连接，我们需要告诉 libcurl 我们的系统证书位于何处。这可以在`curl_config.h`文件开头通过定义`CURL_CA_BUNDLE`来完成：

```kt
#define CURL_CA_BUNDLE “/etc/ssl/certs/ca-certificates.crt”
```

## 另请参阅

+   第三章，*网络通信*

# 编译 OpenAL 库

OpenAL 是一个跨平台的音频库，被许多游戏引擎使用。以下是如何为 Android 构建它的注意事项。

## 准备工作

从 Martins Mozeiko 的页面下载他移植的源代码：[`pielot.org/2010/12/14/openal-on-android/`](http://pielot.org/2010/12/14/openal-on-android/)。

库的主页如下：[`github.com/AerialX/openal-soft-android`](http://github.com/AerialX/openal-soft-android)。

## 如何操作...

1.  为了渲染生成的或保存的音频流，我们使用 OpenAL 库，它是使用随附材料中包含的标准`Android.mk`和`Application.mk`配置文件编译的。

1.  该库的 Android 端口实际上是由 Martins Mozeiko 为 Android Java 类`android.media.AudioTrack`使用 JNI 制作的一个包装器。代码是在 GNU Library General Public License 下授权的，并包含在本书的补充材料中。

## 工作原理…

初始化和反初始化 OpenAL 的最小源代码如下所示：

```kt
ALCdevice* Device = alcOpenDevice( NULL );
ALCcontext* Context = alcCreateContext( Device, NULL );
alcMakeContextCurrent( Context );
…
alcDestroyContext( Context );
alcCloseDevice( Device );
```

## 另请参阅

+   第五章，*跨平台音频流传输*

# 编译 libvorbis、libmodplug 和 libtheora

对于音频流的加载，我们使用**libogg**、**libvorbis**和**libmodplug**。视频流的处理方式类似，使用**libtheora**库。在这里，我们仅提供如何从源代码构建库的一般性提示，因为一旦你有了我们的典型`Android.mk`和`Application.mk`文件，实际的构建过程是非常简单的。

## 准备工作

从[`www.xiph.org/downloads`](http://www.xiph.org/downloads)下载 libvorbis 和 libtheora 编解码器的源代码，以及从[`modplug-xmms.sourceforge.net`](http://modplug-xmms.sourceforge.net)下载 libmodplug 库。

## 如何操作...

1.  libvorbis 和 libtheora 都依赖于 libogg。使用提供的 makefiles 和包含源文件列表的标准`Android.mk`文件，这些库的编译是非常简单的。

    ### 注意

    libvorbis 和 libtheora 库的 Makefiles 必须引用 libogg 的包含目录。

1.  libmodplug 是 Olivier Lapicque 开发的开源跟踪音乐解码器。我们提供了他库的简化版本，包含最流行的跟踪文件格式的加载器。它仅由三个文件组成，并且对 Android 和 Linux 的支持非常出色。该库在大端 CPU 上没有任何问题。

# 使用 FreeImage 图形库

FreeImage 是一个可移植的图形库，它统一了诸如 JPEG、TIFF、PNG、TGA、高动态范围 EXR 图像等流行图像格式的加载和保存。

## 准备工作

从库的主页[`freeimage.sourceforge.net`](http://freeimage.sourceforge.net)下载最新的 FreeImage 源代码。我们使用的是 2012 年 10 月发布的 Version 3.15.4。

## 如何操作...

1.  `Android.mk`和`Application.mk`文件都是相当标准的。前者应该包含以下`GLOBAL_CFLAGS`的定义：

    ```kt
    GLOBAL_CFLAGS   := -O3 -DHAVE_CONFIG_H=1 -DFREEIMAGE_LIB-isystem $(SYSROOT)/usr/include/ 
    ```

1.  不幸的是，Android NDK 运行时库中缺少了 FreeImage 内部使用的`lfind()`函数（该函数在 LibTIFF4 库中使用，而 FreeImage 又使用了该库）。以下是它的实现方法：

    ```kt
    void* lfind( const void * key, const void * base, size_t num, size_t width, int (*fncomparison)(const void *, const void * ) )
    {
      char* Ptr = (char*)base;
      for ( size_t i = 0; i != num; i++, Ptr+=width )
      {
        if ( fncomparison( key, Ptr ) == 0 ) return Ptr;
      }
      return NULL;
    }
    ```

1.  现在，一个命令就能完成这项工作：

    ```kt
    >ndk-build 
    ```

## 工作原理...

图像是作为原始像素数据集合的 2D 数组表示，但存储这个数组的方法有很多：可能会应用一些压缩，可能会涉及一些非 RGB 色彩空间，或者非平凡的像素布局。为了避免处理所有这些复杂性，我们建议使用 Herve Drolon 的 FreeImage 库。

我们需要能够将图像文件数据作为内存块处理，而 FreeImage 支持这种输入方式。假设我们有一个名为`1.jpg`的文件，我们使用`fread()`或`ifstream::read()`调用将其读取到数组`char Buffer[]`中。数组的大小存储在`Size`变量中。然后，我们可以创建`FIBITMAP`结构，并使用`FreeImage_OpenMemory()` API 调用将缓冲区加载到这个`FIBITMAP`结构中。`FIBITMAP`结构几乎是我们想要的 2D 数组，包含了像素布局和图像大小的额外信息。要将它转换为 2D 数组，FreeImage 提供了函数`FreeImage_GetRowPtr()`，它返回指向第*i*行原始 RGB 数据的指针。反之，我们的帧缓冲区或任何其他 2D RGB 图像也可以使用`FreeImage_SaveMemory()`编码到内存块中，并通过单个`fwrite()`或`ofstream::write()`调用保存到文件。

下面是加载 FreeImage 支持的任何图片格式（例如 JPEG、TIFF 或 PNG）并将其转换为 24 位 RGB 图像的代码。其他支持的像素格式，如 RGBA 或浮点数 EXR，将被自动转换为 24 位颜色格式。为了简洁起见，此代码中我们不处理错误。

让我们声明一个结构体，用于保存图像尺寸和像素数据：

```kt
struct sBitmap
{
  int Width;
  int Height;
  void* RGBPixels;
};
```

从内存块到`sBitmap`结构体解码图像的方式如下：

```kt
void FreeImage_LoadImageFromMemory( unsigned char* Data, unsigned 
  int Size, sBitmap* OutBitmap )
{
  FIMEMORY* Mem = FreeImage_OpenMemory( Data, Size );

  FREE_IMAGE_FORMAT FIF=FreeImage_GetFileTypeFromMemory(Mem, 0);

  FIBITMAP* Bitmap = FreeImage_LoadFromMemory( FIF, Mem, 0 );
  FIBITMAP* ConvBitmap;

  FreeImage_CloseMemory( Mem );

  ConvBitmap = FreeImage_ConvertTo24Bits( Bitmap );

  FreeImage_Unload( Bitmap );

  Bitmap = ConvBitmap;

  OutBitmap->Width  = FreeImage_GetWidth( Bitmap );
  OutBitmap->Height = FreeImage_GetHeight( Bitmap );

  OutBitmap->RGBPixels = malloc( OutBitmap->Width * OutBitmap->Height * 3 );

	FreeImage_ConvertToRawBits( OutBitmap->RGBPixels, Bitmap, OutBitmap->Width * 3, 24, 0, 1, 2, false );

  FreeImage_Unload( Bitmap );
}
```

保存图像甚至更简单。保存表示图像的数组`img`，其宽度为`W`，高度为`H`，包含每像素`BitsPP`位：

```kt
void FreeImage_Save( const char* fname, unsigned char* img, int W, int H, int BitsPP )
{
  // Create the FIBITMAP structure
  // using the source image data
  FIBITMAP* Bitmap = FI_ConvertFromRawBits(img,
    W, H, W * BitsPP / 8,
    BitsPP, 0, 1, 2, false);
  // save PNG file using the default parameters

  FI_Save( FIF_PNG, Bitmap, fname, PNG_DEFAULT );
  FI_Unload( Bitmap );
}
```

将`FIF_PNG`更改为`FIF_BMP`、`FIF_TIFF`或`FIF_JPEG`中的任何一个，将输出文件格式分别更改为 BMP、TIFF 或 JPEG。

## 还有更多...

要理解从内存块中读取图像的重要性，我们应牢记两点。诸如**Picasa**和**Flickr**之类的网络服务提供了图像的 URL，然后使用第三章*网络通信*中的技术将这些图像下载到内存中。为了避免浪费时间，我们不将这个内存块保存到磁盘，而是直接使用 FreeImage 库从内存中解码。从压缩档案中读取图像文件也同样适用。

## 另请参阅

+   第四章，*组织虚拟文件系统*

# 使用 FreeType 库进行文本渲染

FreeType 已成为高质量文本渲染的实际标准。该库本身非常易于使用，静态版本的编译依赖于与其他本章库类似的 makefile。

## 准备开始

从库的主页下载最新的源代码：[`www.freetype.org`](http://www.freetype.org)。

FreeType 的主要概念包括：字体面、字形和位图。字体面是针对给定编码的字体中所有字符的集合。这正是存储在 `.ttf` 文件中的内容（除了版权信息和其他类似的元信息）。每个字符称为字形，使用几何基本元素表示，如样条曲线。这些字形不是我们可以逐像素复制到屏幕或帧缓冲区的东西。我们需要使用 FreeType 光栅化函数来生成字形的位图。

让我们来看一个单独的字形：

![准备开始](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_03_1.jpg)

FreeType 字形度量

`xMin`、`xMax`、`yMin` 和 `yMax` 值定义了字形在逻辑坐标中的尺寸，而前进值显示了如果没有字距调整，下一个字形开始的位置。一旦我们想要在屏幕上渲染，我们需要将 FreeType 使用的逻辑坐标转换为屏幕坐标。FreeType 避免使用浮点计算，并将所有内容存储在 26.6 定点格式中（[`www.freetype.org/freetype2/docs/glyphs/glyphs-6.html`](http://www.freetype.org/freetype2/docs/glyphs/glyphs-6.html)）。为了转换从 FreeType 获取的这些复杂值，我们将这些值向右移动六位（相当于整数除以 64），得到我们可以轻松使用的值。

单独渲染每个字符的图像是不够的。有时字符在相互靠近渲染时看起来更好，某些字母组合甚至可能产生新的字形。屏幕上字符间距离的变化称为**字距调整**，FreeType 提供了计算字形之间偏移量的函数。将几个字形组合成一个字形称为**连字**，这超出了本书的范围（详情和参考资料请见[`en.wikipedia.org/wiki/Typographic_ligature`](http://en.wikipedia.org/wiki/Typographic_ligature))。在第七章，*跨平台 UI 和输入系统*中，我们仅使用简单的字距调整，这对于我们的交互式应用程序来说已经足够好了。

为了展示 FreeType 的基本使用方法，我们将在本食谱中编写代码实现：

+   使用**等宽字体**的 ASCII 字符串渲染器。

+   用于等宽字体的基于 FreeType 的纹理生成器。

后面，我们将回到涉及比例字体、UTF-8 编码和字距调整的高级 FreeType 使用方法。

## 如何操作...

1.  对于等宽字体和 8 位 ASCII 字符集，我们可以使用一个包含所有 256 个字符的单一预渲染位图来简化渲染代码。为了制作这个位图，我们编写了一个小工具，它读取 TrueType 字体，并输出一个 512 x 512 像素的方形位图，其中包含 16 × 16 字符网格：

    ```kt
    #include <stdio.h>
    #include <string.h>
    ```

1.  包含 FreeType 头文件：

    ```kt
    #include <ft2build.h>
    #include FT_FREETYPE_H
    ```

1.  声明每侧的字符数以及每个字符的大小：

    ```kt
    #define CHAR_SIZE 16
    #define SLOT_SIZE 32
    ```

1.  声明一个数组以 RGBA 格式存储输出位图：

    ```kt
    #define WIDTH CHAR_SIZE*SLOT_SIZE
    #define HEIGHT CHAR_SIZE*SLOT_SIZE
    unsigned char image[HEIGHT][WIDTH][4];
    ```

1.  使用 FreeImage 库声明一个外部定义的例程来保存`.bmp`文件：

    ```kt
    void write_bmp(const char *fname, int w, int h, int bits_pp, unsigned char *img);
    ```

1.  声明在位置`(x, y)`处渲染`FT_Bitmap`的渲染器如下：

    ```kt
    void draw_bitmap( FT_Bitmap* bitmap, FT_Int x, FT_Int y)
    {
      FT_Int i, j, p, q;
      FT_Int x_max = x + bitmap->width, y_max = y + bitmap->rows;
    ```

1.  遍历源位图的像素：

    ```kt
    for ( i = x, p = 0; i < x_max; i++, p++ )
    for ( j = y, q = 0; j < y_max; j++, q++ )
    {
      if (i < 0 || j < 0 ||
          i >= WIDTH || j >= HEIGHT ) continue;
    ```

1.  从位图中读取值`v`并将四个 RGBA 组件的每一个复制到输出中：

    ```kt
      unsigned char v = bitmap->buffer[q * bitmap->width + p];
      for(int k = 0 ; k < 4 ; k++) image[j][i][k] = v;
        }
      }
    ```

1.  应用程序的主函数`main()`如下所示：

    ```kt
    int main()
    {
    ```

1.  将位图清除为黑色：

    ```kt
      memset( &image[0][0][0], 0, sizeof(image) );
    ```

1.  初始化 FreeType 库：

    ```kt
      FT_Library   library;
      FT_Init_FreeType( &library );              
    ```

1.  创建面(face)对象：

    ```kt
      FT_Face      face;
      FT_New_Face( library, “font.ttf”, 0, &face ); 
    ```

1.  设置字符大小。我们声明了`CHAR_SIZE`来表示位图中单个字符的像素数。乘数`64`是使用的，因为 FreeType 的单位等于 1/64 点。值`100`对应于每英寸 100 个点的水平分辨率：

    ```kt
      FT_Set_Char_Size( face, CHAR_SIZE * 64, 0, 100, 0 );
      FT_GlyphSlot slot = face->glyph;
    ```

1.  渲染 ASCII 表中的每个字符：

    ```kt
      for ( int n = 0; n < 256; n++ )
      {
    ```

1.  加载下一个字形图像到槽中，覆盖之前的图像，并忽略错误：

    ```kt
        if( FT_Load_Char( face, n, FT_LOAD_RENDER ) )
          { continue; }
    ```

1.  计算字形在结果位图中的非变换原点：

    ```kt
      FT_Vector pen;
          pen.x = (n % 16) * SLOT_SIZE * 64;
          pen.y = ( HEIGHT - (n / 16) * SLOT_SIZE) * 64;
    ```

1.  现在，转换位置，绘制到我们的目标位图：

    ```kt
        draw_bitmap( &slot->bitmap,
          (pen.x/64)+slot->bitmap_left,
          EIGHT-(pen.y / 64) - slot->bitmap_top );
      }
    ```

1.  将生成的字体纹理保存为矩形`.bmp`图像文件：

    ```kt
      write_bmp( “font.bmp”, WIDTH, HEIGHT, 32,
        (unsigned char*)image );
    ```

1.  清除字体面并释放库分配的资源：

    ```kt
      FT_Done_Face(face);
      FT_Done_FreeType(library);

      return 0;
    }
    ```

1.  现在，我们有一个以左至右书写的 ASCII 字符串，我们想要构建这个字符串的图形表示。我们遍历字符串中的字符来逐个渲染它们。在每次迭代结束时，我们将当前字符的位图复制到帧缓冲区，然后使用固定的字体宽度（即`SLOT_SIZE`值）增加当前位置。

1.  这是使用预渲染位图字体来呈现文本字符串的完整代码。我们使用字体数组来存储我们字体的 RGB 位图：

    ```kt
    unsigned char* font;
    ```

1.  输出帧缓冲区的宽度和高度定义如下：

    ```kt
    int w = 1000;
    int h = 1000;
    int fw, fh;
    int char_w, char_h;
    ```

1.  将单个字符渲染到位图缓冲区：

    ```kt
    void render_char(unsigned char* buf, char ch,
     int x, int y, int col)
    {
      int u = (ch % 16) * char_w;
      int v = char_h / 2 + ((((int)ch) >> 4) - 1) * char_h;
    ```

1.  遍历当前字符的像素：

    ```kt
      for (int y1 = v ; y1 < v + char_h ; y1++ )
        for (int x1 = u ; x1 <= u + char_w ; x1++ )
        {
          int m_col = get_pixel(font, fw, fh, x1, y1);
    ```

1.  只绘制非零像素。这将保留帧缓冲区中的现有内容：

    ```kt
         if(m_col != 0)
           put_pixel(buf, w, h, x+x1-u, y+y1-v, col);
        }
    }
    ```

1.  将完整的 ASCII 文本行渲染到缓冲区：

    ```kt
    void render_text(unsigned char* buf, const char* str,
     int x, int y, int col)
    {
      const char* c = str;
      while (*c)
      {
        render_char(buf, *c, x, y, col);
        c++;
    ```

1.  以固定数量的像素前进：

    ```kt
        x += char_w;
      }
    }
    ```

## 工作原理…

让我们读取 FreeType 字体生成器的输出。我们使用以下代码来测试它：

```kt
font = read_bmp( “font.bmp”, &fw, &fh );
char_w = fw / CHAR_SIZE;
char_h = fh / CHAR_SIZE;
```

分配并清除输出 3 通道 RGB 位图：

```kt
unsigned char* bmp = (unsigned char* )malloc( w * h * 3 );
memset( bmp, 0, w * h * 3 );
```

在位置`(10,10)`处渲染白色文本行：

```kt
render_text( bmp, “Test string”, 10, 10, 0xFFFFFF );
```

将结果位图保存到文件：

```kt
write_bmp( “test.bmp”, w, h, bmp );
free( bmp );
```

## 还有更多...

我们鼓励读者访问[`www.1001freefonts.com`](http://www.1001freefonts.com)寻找一些免费字体，使用所描述的 FreeType 字体生成器为这些字体创建`.bmp`文件，并使用预渲染的字符来渲染字符串。

# 在物理中实现计时

本章的其余部分专门介绍两个物理模拟库：Box2D（2D 模拟）和 Open Dynamics Engine（3D 模拟）。构建这些并不困难，因此我们将重点放在如何实际使用它们。Box2D 和 ODE 的 API 仅提供计算模拟中刚体当前位置的函数。首先，我们必须调用计算例程。然后，我们必须将身体的物理坐标转换成与屏幕相关的坐标系。将物理模拟与渲染和计时连接起来是本节处理的主要问题。

## 准备就绪

几乎每个刚体物理库都提供了世界、物体（或身体）、约束（或关节）以及形状的抽象。这里的世界只是一个包含身体和附着在身体上的关节的集合。形状定义了身体如何碰撞。

要基于物理模拟创建动态应用程序，我们必须能够在任何时刻渲染物理场景。同时，我们还需要将离散的计时器事件转换成看似连续的物体位置计算过程。

在这里，我们解释了计时和渲染，然后提供了一个使用 Box2D 库的完整示例，即`App4`。

## 如何操作...

1.  为了在屏幕上动画化所有内容，我们需要设置一个计时器。在 Android 中，我们尽可能快地进行时间步进，并且在渲染循环的每次迭代中，我们只需调用`GetSeconds()`函数并计算前一个时间与当前时间之间的差值。`Wrappers_Android.h`文件中的`GetSeconds()`函数代码使用了标准的**POSIX** `gettimeofday()`函数：

    ```kt
    double GetSeconds()
    {
    ```

1.  将时间从微秒转换为秒的系数：

    ```kt
      const unsigned usec_per_sec = 1000000;
    ```

1.  获取当前时间：

    ```kt
      struct timeval Time;
      gettimeofday( &Time, NULL );
    ```

1.  计算微秒数：

    ```kt
    int64_t T1 = Time.tv_usec + Time.tv_sec * usec_per_sec;
    ```

1.  返回当前时间（秒）。这里需要`double`精度，因为计时器从系统启动时刻开始计时，32 位的`float`精度不够：

    ```kt
      return (double)( T1 ) / (double)usec_per_sec;
    }
    ```

1.  我们使用三个变量来记录当前时间、之前的时间和总时间。首先，我们初始化`g_OldTime`和`g_NewTime`时间计数器：

    ```kt
    g_OldTime = GetSeconds();
    g_NewTime = g_OldTime;
    ```

1.  在开始之前，总时间计数器应设为零：

    ```kt
    g_ExecutionTime = 0;
    ```

1.  每帧我们调用`GenerateTicks()`方法来设置动画：

    ```kt
    void GenerateTicks()
    {
      g_NewTime = GetSeconds();
    ```

1.  计算自上次更新以来经过的时间：

    ```kt
      float DeltaSeconds = static_cast<float>(g_NewTime-g_OldTime);
      g_OldTime = g_NewTime;
    ```

1.  使用非零秒数调用`OnTimer()`例程：

    ```kt
      if (DeltaSeconds > 0) { OnTimer(DeltaSeconds); }
    }
    ```

1.  对于 Windows 版本，使用`SetTimer()`函数进行时间步进，该函数每隔 10 毫秒启用一个系统计时器事件：

    ```kt
    SetTimer( hWnd, 1, 10, NULL);
    ```

1.  每次这些毫秒经过，`WM_TIMER`事件会被发送到我们的窗口函数。我们在`switch`构造中添加另一个`case`，只需调用`OnTimer()`方法：

    ```kt
    LRESULT CALLBACK MyFunc( HWND h, UINT msg, WPARAM w, LPARAM p )
      ...
      case WM_TIMER:
    ```

1.  由于我们即将改变状态，重新绘制一切：

    ```kt
        InvalidateRect(h, NULL, 1);
    ```

1.  使用 0.01 秒的时间片重新计算一切：

    ```kt
        OnTimer(0.01);
        break;
    ```

如第二章，*移植通用库*所述，新的`OnTimer()`回调函数与 Windows 或 Android 的特定内容无关。

## 工作原理...

现在，当我们有了为我们生成的时间器事件时，我们可以继续计算刚体的位置。这是一个解决运动方程的复杂过程。简单来说，给定当前的位置和方向，我们想要计算场景中所有刚体的新位置和方向：

```kt
positions_new = SomeFunction(positions_old, time_step);
```

在这个伪代码中，`positions_new`和`positions_old`是与刚体位置和方向的新旧数组，而`time_step`是我们应该推进时间计数器的秒数值。通常，我们需要使用`0.05`秒或更低的时间步长更新一切，以确保我们以足够高的精度计算位置和方向。对于每个逻辑计时器事件，我们可能需要进行一个或多个计算步骤。为此，我们引入了`TimeCounter`变量，并实现了所谓的**时间分片**：

```kt
const float TIME_STEP = 1.0f / 60.0f;
float TimeCounter = 0;

void OnTimer (float Delta)
{
  g_ExecutionTime += Delta;

  while (g_ExecutionTime > TIME_STEP)
  {
```

调用 Box2D 的`Step()`方法，重新计算刚体的位置，并将时间计数器减一：

```kt
    g_World->Step(Delta);
    g_ExecutionTime -= TIME_STEP;
  }
}
```

所提供的代码保证了对于时间值`t`，`Step()`方法会被调用`t / TIME_STEP`次，且物理时间和逻辑时间之间的差值不会超过`TIME_STEP`秒。

## 另请参阅…

+   第八章，*编写一个匹配 3 游戏*

# 在 2D 环境中渲染图形

为了渲染一个 2D 场景，我们使用线框模式。这只需要实现`Line2D()`过程，其原型如下：

```kt
Line2D(int x1, int y1, int x2, int y2, int color);
```

## 准备开始

这可以是对 Bresenham 算法的简单实现（[`en.wikipedia.org/wiki/Bresenham’s_line_algorithm`](http://en.wikipedia.org/wiki/Bresenham’s_line_algorithm)），本书中没有提供代码以节省空间。有关`App4`的`Rendering.h`和`Rendering.cpp`文件，请参见随书附带的材料。该书的补充材料可以从[www.packtpub.com/support](http://www.packtpub.com/support)下载。

## 如何操作…

1.  为了将模拟物理世界中的对象转换到 Box2D 库的 2D 环境中，我们必须设置一个坐标变换：

    ```kt
    [x, y]  [X_screen, Y_screen]
    ```

1.  为此，我们引入了几个系数，`XScale`，`YScale`，`XOfs`，`YOfs`，以及两个公式：

    ```kt
    X_screen = x * XScale + XOfs
    Y_screen = y * YScale + YOfs
    ```

1.  它们的工作原理如下：

    ```kt
    int XToScreen(float x)
    {
      return Width / 2 + x * XScale + XOfs;
    }
    int YToScreen(float y)
    {
      return Height / 2 - y * YScale + YOfs;
    }
    float ScreenToX(int x)
    {
      return ((float)(x - Width / 2)  - XOfs) / XScale;
    }
    float ScreenToY(int y)
    {
      return -((float)(y - Height / 2) - YOfs) / YScale;
    }
    ```

1.  我们还引入了`Line2D()`例程的快捷方式，使用 Box2D 库的`Vec2`类型直接处理向量值参数：

    ```kt
    void LineW(float x1, float y1, float x2, float y2, int col)
    {
      Line( XToScreen(x1),YToScreen(y1),
      XToScreen(x2),YToScreen(y2),col );
    }
    void Line2DLogical(const Vec2& p1, const Vec2& p2)
    {
      LineW(p1.x, p1.y, p2.x, p2.y);
    }
    ```

## 工作原理…

为了渲染一个单独的盒子，我们只需要绘制连接角点的四条线。如果一个刚体的角度是`Alpha`，质心坐标是`x`和`y`，且尺寸由宽度`w`和高度`h`指定，那么角点的坐标计算如下：

```kt
Vec2 pt[4];
pt[0] = x + w * cos(Alpha) + h * sin(Alpha)
pt[1] = x - w * cos(Alpha) + h * sin(Alpha)
pt[2] = x - w * cos(Alpha) - h * sin(Alpha)
pt[3] = x + w * cos(Alpha) - h * sin(Alpha)
```

最后，将盒子渲染为四条线：

```kt
for(int i = 0 ; i < 4 ; i++)
{
  Line2DLogical(pt[i], pt[(i+1)%4]);
}
```

## 另请参阅…

+   第六章，*统一 OpenGL ES 3 和 OpenGL 3*

# 设置 Box2D 模拟

Box2D 是一个纯 C++库，不依赖于 CPU 架构，因此使用与前面章节中类似的简单`makefile`和`Android.mk`脚本就足以构建该库。我们使用前面章节中描述的技术来设置一个模拟。我们还有上一章中的帧缓冲区，仅使用 2D 线条渲染盒子。

## 准备就绪

作为奖励，库的作者 Erin Catto 提供了一个 Box2D 的简化版本。一旦你满足于仅使用现有的盒子，你可以限制自己使用**BoxLite**版本。

从库的主页下载最新的源代码：[`box2d.org`](http://box2d.org)。

## 如何操作...

1.  为了开始使用 Box2D，我们采用了本书材料中包含的经过略微修改的 BoxLite 版本的标准示例。首先，我们声明全局的`World`对象：

    ```kt
    World* g_World = NULL;
    ```

1.  在`OnStartup()`例程的最后初始化它：

    ```kt
    g_World = new World(Vec2(0,0), 10);
    Setup(g_World);
    ```

1.  `OnTimer()`回调（之前食谱中使用的）通过调用`Step()`方法使用`TIME_STEP`常量更新`g_World`对象。

1.  `OnDrawFrame()`回调将每个刚体的参数传递给`DrawBody()`函数，该函数渲染刚体的边界框：

    ```kt
    void OnDrawFrame()
    {
      Clear(0xFFFFFF);
      for (auto b = g_World->bodies.begin();
      b !=g_World->bodies.end(); b++ )
      {
        DrawBody(*b);
      }
    ```

1.  渲染每个关节：

    ```kt
    for ( auto j = g_World->joints.begin() ;
      j != g_World->joints.end() ; j++ )
    {
      DrawJoint(*j);
    }
    ```

1.  尽可能快地更新状态：

    ```kt
        GenerateTicks();
      }
    ```

对`GenerateTicks()`函数的调用为 Android 版本实际更新定时。它是使用本章中“在物理中实现定时”食谱中的想法来实现的。

## 它是如何工作的...

`Setup()`函数是对 Box2D 原始示例代码的修改，用于设置一个物理场景。修改包括定义一些快捷方式以简化场景组装。

函数`CreateBody()`和`CreateBodyPos()`根据指定的位置、方向、尺寸和质量创建刚体。函数`AddGround()`向`g_World`添加一个静态不可移动的物体，而函数`CreateJoint()`则创建一个将一个刚体附着到另一个刚体的新物理连接。

在这个示例场景中，还有一些关节连接着这些刚体。

应用程序`App4`在 Android 和 Windows 上产生相同的结果，如下面的图像所示，这是其中一个模拟步骤：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_03_2.jpg)

## 还有更多...

作为练习，我们建议你尝试调整设置，并在`App4`示例中添加更多自己的 2D 场景。

## 另请参阅

+   在物理中实现定时

# 构建 ODE 物理库

本食谱致力于构建开源**ODE**（**开放动力学引擎**）物理模拟库，这是互动应用中最古老的刚体模拟器之一。

## 准备就绪

从库的主页下载最新的源代码：[`www.ode.org/download.html`](http://www.ode.org/download.html)。

## 如何操作...

1.  编译 ODE 与其他库没有区别。一个微妙的点是选择`single`和`double`浮点精度。标准编译涉及`autoconf`和`automake`工具，但这里我们只需像往常一样准备`Android.mk`、`makefile`和`odeconfig.h`。我们需要在那里定义`dDOUBLE`或`dSINGLE`符号，以启用`single`或`double`精度计算。在`odeconfig.h`文件的开头有这一行：

    ```kt
    #define dSINGLE
    ```

1.  它启用了单精度、32 位浮点计算，这对于简单的交互式应用程序来说已经足够了。将值更改为`dDOUBLE`可以启用双精度、64 位浮点计算：

    ```kt
    #define dDOUBLE
    ```

1.  ODE 是相当复杂的软件，它包含了**Ice**碰撞检测库，不幸的是，在使用 Clang 编译器的最严格设置时，它会有编译问题。但是，通过注释掉`OPCODE/Ice/IceUtils.h`文件中的`_prefetch`函数内容，可以轻松修复。

## 工作原理...

由于 ODE 在 3D 空间中计算刚体的位置和方向，因此我们必须在我们在本章中完成的简单 2D 渲染之上建立一个小型的 3D 渲染管道。为了演示 ODE 库，我们不可避免地需要一些 3D 数学知识。场景（世界）中的所有对象都有其坐标和方向，由 3D 向量和四元数组成的一对值指定。我们将它们转换为 4x4 仿射变换矩阵。然后，我们遵循坐标变换链：我们将**对象空间**转换为**世界空间**，世界空间转换为**相机空间**，然后通过乘以投影矩阵将相机空间转换为**透视后空间**。

最后，第一个透视坐标`x`和`y`被转换成标准化设备坐标，以适应我们的 2D 帧缓冲区，就像在 Box2D 示例中一样。摄像机固定在一个静止点上，其观察方向在我们的简单应用程序中无法更改。投影矩阵也是固定的，但没有其他限制。

## 还有更多...

3D 物理模拟是一个非常复杂的话题，需要阅读许多书籍。我们鼓励读者查看 ODE 社区维基页面，在[`ode-wiki.org/wiki`](http://ode-wiki.org/wiki)可以找到官方文档和开源示例。通过 Packt Publishing 出版的《*使用 Bullet Physics 和 OpenGL 学习游戏物理*》一书，可以开始游戏物理的好学习：[`www.packtpub.com/learning-game-physics-with-bullet-physics-and-opengl/book`](http://www.packtpub.com/learning-game-physics-with-bullet-physics-and-opengl/book)。

## 另请参阅

+   设置 Box2D 模拟
