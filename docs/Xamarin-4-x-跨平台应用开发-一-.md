# Xamarin 4.x 跨平台应用开发（一）

> 原文：[`zh.annas-archive.org/md5/183290FB388A7F8EC527693139A6FD11`](https://zh.annas-archive.org/md5/183290FB388A7F8EC527693139A6FD11)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Xamarin 为 C#开发 iOS 和 Android 应用程序打造了优秀的产品：Xamarin Studio，Visual Studio 的插件，Xamarin.iOS 和 Xamarin.Android。Xamarin 让你直接访问每个平台的本地 API，并具有共享 C#代码的灵活性。使用 Xamarin 和 C#，相比于 Java 或 Objective-C，你可以获得更高的生产效率，并且与 HTML 或 JavaScript 解决方案相比，仍然保持出色的性能。

在本书中，我们将开发一个现实世界的示例应用程序，以展示你可以使用 Xamarin 技术做什么，并在 iOS 和 Android 的核心平台概念上进行构建。我们还将涵盖高级主题，如推送通知、获取联系人、使用相机和 GPS 定位。随着 Xamarin 3 的推出，引入了一个名为 Xamarin.Forms 的新框架。我们将介绍 Xamarin.Forms 的基础知识以及如何将其应用于跨平台开发。最后，我们将介绍提交应用程序到 Apple App Store 和 Google Play 需要做些什么。

# 本书涵盖的内容

第一章，*Xamarin 设置*，是关于安装适合进行跨平台开发的 Xamarin 软件和本地 SDK 的指南。指导 Windows 用户如何在本地网络中连接 Mac，以便在 Visual Studio 中进行 iOS 开发。

第二章， *平台你好！*，带你一步步在 iOS 和 Android 上创建一个简单的计算器应用程序，同时也涵盖了每个平台的一些基本概念。

第三章，*iOS 和 Android 之间的代码共享*，介绍了可以使用 Xamarin 的代码共享技术和项目设置策略。

第四章， *XamSnap - 一个跨平台应用*，介绍了一个示例应用程序，我们将在整本书中构建它。在本章中，我们将为该应用程序编写所有共享代码，并完成单元测试。

第五章， *iOS 的 XamSnap*，展示了如何为 XamSnap 实现 iOS 用户界面，并涵盖了各种 iOS 开发概念。

第六章， *安卓的 XamSnap*，展示了如何实现 XamSnap 的 Android 版本，并介绍了 Android 特定的开发概念。

第七章， *在设备上部署和测试*，带你经历将第一个应用程序部署到设备的痛苦过程。我们还讨论为什么在真实设备上测试应用程序很重要。

第八章，*联系人、相机和位置*，介绍了库 Xamarin.Mobile，作为跨平台方式访问用户的联系人、相机和 GPS 位置，并将这些功能添加到我们的 XamSnap 应用程序中。

第九章，*带有推送通知的 Web 服务*，展示了如何使用 Windows Azure 实现 XamSnap 的真实后端 Web 服务，利用 Azure Functions 和 Azure Notification Hubs。

第十章，*第三方库*，涵盖了使用 Xamarin 的各种第三方库选项，以及如何甚至利用原生 Java 和 Objective-C 库。

第十一章，*Xamarin.Forms*，帮助我们探索 Xamarin 的最新框架 Xamarin.Forms，以及如何利用它构建跨平台应用程序。

第十二章，*应用商店提交*，将引导我们完成将你的应用提交到苹果 App Store 和 Google Play 的过程。

# 你需要为这本书准备什么

对于这本书，你需要一台运行至少 OS X 10.10 的 Mac 电脑。苹果要求 iOS 应用程序必须在 Mac 上编译，因此 Xamarin 也有同样的要求。你可以使用 Xamarin Studio（最适合 Mac）或 Visual Studio（最适合 Windows）作为 IDE。在 Windows 上的开发人员可以通过连接到本地网络上的 Mac 来在 Visual Studio 上开发 iOS 应用程序。访问[`xamarin.com/download`](https://xamarin.com/download)或[`visualstudio.com/download`](https://visualstudio.com/download)以下载合适的软件。

# 这本书适合谁

这本书适合已经熟悉 C#并希望学习使用 Xamarin 进行移动开发的开发人员。如果你在 ASP.NET、WPF、WinRT、Windows Phone 或 UWP 方面有过工作经验，那么使用这本书来开发原生 iOS 和 Android 应用程序将会非常得心应手。

# 约定

在这本书中，你会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 处理方式如下所示："使用`await`关键字在 C#中运行异步代码。"

一段代码如下设置：

```kt
class ChuckNorris
{
    void DropKick()
    {
        Console.WriteLine("Dropkick!");
    }
}
```

当我们希望引起您对代码块中特定部分的注意时，相关的行或项目会以粗体显示：

```kt
class ChuckNorris
{
    void DropKick()
    {
        Console.WriteLine("Dropkick!");
    }
}
```

任何命令行输入或输出都如下编写：

```kt
# xbuild MyProject.csproj

```

**新术语**和**重要词汇**以粗体显示。你在屏幕上看到的词，例如菜单或对话框中的，文本中会像这样显示："为了下载新模块，我们将转到**文件** | **设置** | **项目名称** | **项目解释器**。"

### 注意

警告或重要提示会以这样的框显示。

### 提示

提示和技巧会像这样显示。

# 读者反馈

我们欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出你真正能从中获得最大收益的标题。要给我们发送一般反馈，只需发送电子邮件到 feedback@packtpub.com，并在邮件的主题中提及书籍的标题。如果你对某个主题有专业知识，并且有兴趣撰写或为书籍做贡献，请查看我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然你现在拥有一本 Packt 的书，我们有很多方法可以帮助你充分利用你的购买。

## 下载示例代码

你可以从你的账户在[`www.packtpub.com`](http://www.packtpub.com)下载本书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

你可以通过以下步骤下载代码文件：

1.  使用你的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标悬停在顶部**支持**标签上。

1.  点击**代码下载 &勘误**。

1.  在**搜索**框中输入书籍名称。

1.  选择你想要下载代码文件的那本书。

1.  从下拉菜单中选择你购买本书的地方。

1.  点击**代码下载**。

文件下载后，请确保你使用最新版本的软件解压或提取文件夹：

+   对于 Windows 系统，使用 WinRAR / 7-Zip。

+   对于 Mac 系统，使用 Zipeg / iZip / UnRarX。

+   对于 Linux 系统，使用 7-Zip / PeaZip。

本书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Xamarin 4x-Cross-Platform-Application-Development-Third-Edition`](https://github.com/PacktPublishing/Xamarin%204x-Cross-Platform-Application-Development-Third-Edition)。我们还有其他丰富的书籍和视频代码包，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。请查看！

## 下载本书的色彩图片

我们还为你提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的色彩图片。色彩图片将帮助你更好地理解输出的变化。你可以从[`www.packtpub.com/sites/default/files/downloads/Xamarin4xCrossPlatformApplicationDevelopmentThirdEdition_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/Xamarin4xCrossPlatformApplicationDevelopmentThirdEdition_ColorImages.pdf)下载这个文件。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然在所难免。如果你在我们的书中发现了一个错误——可能是文本或代码中的错误，如果你能向我们报告，我们将不胜感激。这样做可以避免其他读者产生困扰，并帮助我们改进本书后续版本。如果你发现任何勘误信息，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择你的书籍，点击**勘误提交表单**链接，并输入你的勘误详情。一旦你的勘误信息被核实，你的提交将被接受，并且勘误信息将被上传到我们的网站，或者添加到该书标题下的现有勘误列表中。

要查看之前提交的勘误信息，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书籍名称。所需信息将显示在**勘误**部分。

## 盗版

在互联网上对版权材料的盗版是所有媒体持续存在的问题。在 Packt，我们非常重视保护我们的版权和许可。如果你在互联网上以任何形式遇到我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如果你怀疑有盗版材料，请通过 copyright@packtpub.com 联系我们，并提供相关链接。

我们感谢你帮助保护我们的作者和我们为你提供有价值内容的能力。

## 问题

如果你对本书的任何方面有问题，可以通过 questions@packtpub.com 联系我们，我们将尽力解决问题。


# 第一章：Xamarin 设置

如果你正在阅读这本书，你可能已经深深爱上了 C#、.NET 和像 Microsoft Visual Studio 这样的工具。当你考虑到学习新平台、新 IDE、新的应用程序模型，或许还有一两种编程语言的困难时，使用本地 SDK 的移动开发似乎令人畏惧。Xamarin 旨在用 C#为.NET 开发者提供开发本地 iOS、Android 和 Mac 应用程序的工具。

选择 Xamarin 而不是在 Android 上使用 Java，在 iOS 上使用 Objective-C/Swift 开发移动应用程序有很多优势。你可以在这两个平台之间共享代码，并且可以利用 C#和.NET 基类库的高级语言功能来提高生产效率。否则，你将不得不为 Android 和 iOS 分别编写整个应用程序。

与其他使用 JavaScript 和 HTML 开发跨平台应用程序的技术相比，Xamarin 具有一些独特的优势。C#通常比 JavaScript 性能更好，Xamarin 让开发者可以直接访问每个平台的本地 API。这使得 Xamarin 应用程序能够拥有类似于 Java 或 Objective-C 对应程序的本地外观和性能。Xamarin 的工具通过将 C#编译成本地 ARM 可执行文件，该文件可以作为 iOS 或 Android 应用程序进行打包。它将一个精简版的 Mono 运行时与你的应用程序捆绑在一起，只包括你的应用程序使用的基类库功能。

在本章中，我们将介绍使用 Xamarin 进行开发所需的一切。到本章结束时，我们将安装所有适当的 SDK 和工具，以及应用程序商店提交所需的所有开发者账户。

在本章中，我们将涵盖：

+   Xamarin 工具和技术介绍

+   安装 Xcode，苹果的 IDE

+   安装所有 Xamarin 工具和软件

+   将 Visual Studio 连接到 Mac

+   设置 Android 模拟器

+   加入 iOS 开发者计划

+   注册 Google Play

# 了解 Xamarin

Xamarin 开发了三个用于开发跨平台应用程序的核心产品：**Xamarin Studio**，**Xamarin.iOS**和**Xamarin.Android**。Xamarin Studio 是一个 C# IDE，而**Xamarin.iOS**和**Xamarin.Android**是使 C#应用程序能够在 iOS 和 Android 上运行的核心工具。这些工具允许开发者利用 iOS 和 Android 上的本地库，并建立在 Mono 运行时之上。

**Mono**，一个开源的 C#和.NET 框架实现，最初由 Novell 开发，用于 Linux 操作系统。由于 iOS 和 Android 同样基于 Linux，Novell 能够开发 MonoTouch 和 Mono for Android 作为针对新移动平台的产品。发布后不久，一家更大的公司收购了 Novell，Mono 团队离开成立了一家主要针对移动开发的新公司。Xamarin 因此成立，专注于使用 C#在 iOS 和 Android 上进行开发的这些工具。

为跨平台应用开发准备开发机器可能需要一些时间。更糟糕的是，苹果和谷歌各自对其平台上的开发都有不同的要求。如果你计划在 Windows 上使用 Visual Studio 进行开发，那么你的设置将与在 Mac OS X 上有所不同。请记住，在 Windows 上进行 iOS 开发需要在你的本地网络上有一台 Mac。让我们看看你的机器上需要安装哪些内容。

在 Mac OS X 上进行 Xamarin 开发的构建块如下：

+   **Xcode**：这是苹果用于用 Objective-C 开发 iOS 和 Mac 应用程序的核心 IDE。

+   **Mac 上的 Mono 运行时**：在 OS X 上编译和运行 C#程序需要这个

+   **Java**：这是在 OS X 上运行 Java 应用程序的核心运行时

+   **Android SDK**：这包含了谷歌的标准 SDK、设备驱动程序和用于原生 Android 开发的模拟器

+   **Xamarin.iOS**：这是 Xamarin 用于 iOS 开发的核心产品

+   **Xamarin.Android**：这是 Xamarin 用于 Android 开发的核心产品

在 Windows 上进行 Xamarin 开发所需的软件如下：

+   **Visual Studio 或 Xamarin Studio**：这两个 IDE 都可以用于 Windows 上的 Xamarin 开发。

+   **.NET Framework 4.5 或更高版本**：这随 Visual Studio 或 Windows 的最新版本一起提供。

+   **Java**：这是在 Windows 上运行 Java 应用程序的核心运行时。

+   **Android SDK**：这包含了谷歌的标准 SDK、设备驱动程序和用于原生 Android 开发的模拟器。

+   **本地网络上设置为 Xamarin.iOS 开发的 Mac**：作为苹果许可协议的一部分，苹果要求在 OS X 上进行 iOS 开发。需要按照上述列表设置一台 Mac 用于 Xamarin.iOS 开发。

+   **Xamarin for Windows**：这是 Xamarin 用于 Windows 的核心产品，包括 Xamarin.Android 和 Xamarin.iOS。

每个安装都需要一些时间来下载和安装。如果你能访问快速的网络连接，这将有助于加快安装和设置过程。准备好一切后，让我们一步一步地继续前进，希望我们可以避开你可能遇到的几个死胡同。

# 安装 Xcode

为了让事情进行得更顺利，让我们首先为 Mac 安装 Xcode。除了 Apple 的 IDE，它还将安装 Mac 上最常用的开发工具。确保你至少有 OS X 10.10（Yosemite）版本，并在 App Store 中找到 Xcode，如下面的截图所示：

![安装 Xcode](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00190.jpeg)

这将需要一些时间来下载和安装。我建议你可以利用这段时间享受一杯美味的咖啡，或者同时进行另一个项目。

安装 Xcode 会安装 iOS SDK，这是进行 iOS 开发的一般要求。由于 Apple 的限制，iOS SDK 只能在 Mac 上运行。Xamarin 已经尽一切可能确保他们遵循 Apple 的 iOS 指南，例如动态代码生成。Xamarin 的工具还尽可能利用 Xcode 的特性，以避免重新发明轮子。

# 在 Mac OS X 上安装 Xamarin

安装 Xcode 之后，需要安装其他几个依赖项，然后才能使用 Xamarin 的工具进行开发。幸运的是，Xamarin 通过创建一个简单的一体化安装程序改善了这一体验。

通过执行以下步骤来安装 Xamarin：

1.  访问[`xamarin.com`](http://xamarin.com)，点击大型的**下载 Xamarin**按钮。

1.  填写一些关于你自己的基本信息，然后点击**下载适用于 OS X 的 Xamarin Studio**。

1.  下载`XamarinInstaller.dmg`并挂载磁盘映像。

1.  启动`Xamarin.app`，并接受出现的任何 OS X 安全警告。

1.  按照安装程序进行操作；默认选项将正常工作。你可以选择安装`Xamarin.Mac`，但本书不涉及该主题。

Xamarin 安装程序将下载并安装所需的前提条件，如 Mono 运行时、Java、Android SDK（包括 Android 模拟器和工具）以及你开始运行所需的一切。

最后你会得到类似于以下截图所示的内容，然后我们可以继续学习跨平台开发中的更多高级主题：

![在 Mac OS X 上安装 Xamarin](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00191.jpeg)

# 设置 Android 模拟器

历史上，Android 模拟器在性能上一直比物理设备开发要慢。为了解决这个问题，Google 生产了一个支持在桌面电脑上进行硬件加速的 x86 模拟器。它默认没有在**Android Virtual Device**（**AVD**）管理器中安装，所以让我们来设置它。

通过执行以下步骤可以安装 x86 Android 模拟器：

1.  打开 Xamarin Studio。

1.  启动**工具** | **打开 Android SDK 管理器...**。

1.  滚动到**Extras**；安装**Intel x86 Emulator Accelerator (HAXM 安装程序)**。

1.  滚动到**Android 6.0 (API 23)**；安装**Intel x86 Atom System Image**。

1.  可选步骤，安装你感兴趣的其他软件包。至少确保你已经安装了 Android SDK 管理器默认为你选择安装的所有内容。

1.  关闭**Android SDK Manager**并导航到你的 Android SDK 目录，默认位于`~/Library/Developer/Xamarin/android-sdk-macosx`。

1.  导航到`extras/intel/Hardware_Accelerated_Execution_Manager`并启动`IntelHAXM_6.0.3.dmg`来安装 HAXM 驱动。

1.  切换回 Xamarin Studio 并启动**工具** | **打开 Google Emulator Manager...**。

1.  点击**创建...**。

1.  输入你选择的 AVD 名称，例如`x86 Emulator`。

1.  选择一个适合你显示器的通用设备，例如**Nexus 5**。

1.  在**CPU/ABI**中，确保你选择支持**Intel Atom (x86)**的选项。

1.  创建设备后，继续点击**启动...**以确保模拟器正常运行。

### 提示

这些说明在 Windows 上应该非常相似。默认情况下，Android SDK 在 Windows 上的安装路径为`C:\Program Files (x86)\Android\android-sdk`。同样，HAXM 安装程序在 Windows 上名为`intelhaxm-android.exe`。

模拟器启动需要一些时间，因此在处理 Android 项目时，让模拟器保持运行是一个好主意。Xamarin 在这里使用标准的 Android 工具，因此即使是 Java 开发者也会感受到缓慢模拟器的痛苦。如果一切正常启动，你会看到一个 Android 启动屏幕，然后是一个虚拟的 Android 设备，可以从 Xamarin Studio 部署应用程序，如下面的截图所示：

![设置 Android 模拟器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00192.jpeg)

市面上有许多 Android 模拟器选项，例如 Genymotion 或 Visual Studio Android Emulator。使用 Xamarin 不会限制你在 Android 模拟器中的选择，所以如果默认的 Android 模拟器不适用于你，可以自由尝试。

# 在 Windows 上安装 Xamarin

自从 2016 年微软收购 Xamarin 以来，任何版本的 Visual Studio 都包含了 Xamarin。版本如下：

+   **Visual Studio Community**：这是一个任何人都可以免费使用的版本。对于公司使用这个版本有一些限制。

+   **Visual Studio Professional**：这是公司应该使用的通用版本。在 Visual Studio 方面，它包括了 Team Foundation Server 的功能。

+   **Visual Studio Enterprise**：包含了 Visual Studio 和 Xamarin 的额外功能。Xamarin 的特性包括嵌入式程序集、实时 Xamarin 检查器和 Xamarin 分析器。

当首次在 Windows PC 上为 Xamarin 开发设置环境时，有两个选择需要考虑。如果你已经安装了 Visual Studio，那么你可以仅使用 Xamarin 安装程序，将必要的 Visual Studio 扩展和项目模板添加到现有安装中。如果你还没有安装 Visual Studio，那么在 Visual Studio 2015 安装程序中有一个简单的选项可以安装 Xamarin。

如果你想要通过 Visual Studio 安装程序进行安装：

1.  从[`www.visualstudio.com/downloads/`](https://www.visualstudio.com/downloads/)下载你所需的 Visual Studio 版本。

1.  运行 Visual Studio 安装程序。

1.  在**跨平台移动开发**下，确保选择**C#/.NET (Xamarin v4.1.0)**（版本号将根据你使用的版本而变化）。这将自动选择你需要用于 Xamarin 开发的 Android SDK 和其他组件。

1.  你还可以选择安装其他有用的工具，比如针对 Windows 10 的**Microsoft Web 开发工具**或**通用 Windows 应用开发**工具。

在你点击**下一步**之前，你的安装程序应该看起来像这样：

![在 Windows 上安装 Xamarin](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00193.jpeg)

安装 Xamarin 的第二种选择是从 Xamarin 官网进行：

1.  从 [`xamarin.com/download`](https://xamarin.com/download) 下载适用于 Windows 的 Xamarin 安装程序。

1.  运行 `XamarinInstaller.exe`，它将在你的电脑上下载并安装所有必需的组件。

Xamarin 安装程序与你在 Mac OS X 上看到的过程非常相似，应该非常简单直接。如果需要，它会将 Xamarin 添加到现有的 Visual Studio 安装中，并安装 Xamarin Studio。

# 为 iOS 开发将 Visual Studio 连接到 Mac

iOS 开发需要运行在 Mac OS X 上的 Xcode。幸运的是，Xamarin 已经使从 Windows 电脑进行远程开发成为可能。

要将你的电脑连接到 Mac：

1.  首先打开或创建一个 Xamarin.iOS 项目。

1.  Visual Studio 会自动提示**Xamarin Mac 代理说明**。

1.  按照 Visual Studio 中的详细说明和截图，在 Mac 上启用远程登录。

1.  应该会出现一个列出你 Mac 地址的**Xamarin Mac 代理**对话框。

1.  点击**连接...**，并输入你在 Mac 上的用户名和密码。

连接后，你应该会看到如下截图所示的内容：

![为 iOS 开发将 Visual Studio 连接到 Mac](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00194.jpeg)

连接后，你可以直接按下播放按钮，针对 iOS 模拟器或你选择的 iOS 设备调试你的项目。在 Visual Studio 中你期望的所有功能也可以用于 iOS 开发：断点、鼠标悬停评估、添加监视等。

# 加入 iOS 开发者计划

要部署到 iOS 设备，Apple 要求加入其 iOS 开发者计划。会员费用为每年 99 美元，你可以使用它来部署 200 个用于开发目的的设备。你还可以访问测试服务器，以实施更高级的 iOS 功能，如应用内购买、推送通知和 iOS 游戏中心。在物理设备上测试你的 Xamarin.iOS 应用是很重要的，因此我建议你在开始 iOS 开发之前先获得一个账户。在桌面运行的模拟器与实际移动设备上的性能差异很大。还有一些仅在实际设备上运行时才会发生的特定于 Xamarin 的优化。我们将在后面的章节中详细介绍在设备上测试应用的原因。

### 提示

自从 iOS 9 以来，苹果创建了一种可以从任何 Apple ID 在 iOS 设备上侧载应用程序的方法。建议仅用于在少量设备上进行测试，并且无法测试高级功能，如应用内购买或推送通知。然而，如果你只是想试试 iOS，这是一种无需支付 99 美元开发者费用的入门好方法。

通过以下步骤可以注册 iOS 开发者计划：

1.  前往[`developer.apple.com/programs/ios`](https://developer.apple.com/programs/ios)。

1.  点击**注册**。

1.  使用现有的 iTunes 账户登录或创建一个新的账户。以后无法更改，所以请选择适合你公司的账户。

1.  可以选择以个人或公司身份注册。两者的价格都是 99 美元，但作为公司注册需要将文件传真给苹果公司，并需要你公司会计师的协助。

1.  审阅开发者协议。

1.  填写苹果的开发者调查问卷。

1.  购买 99 美元的开发者注册。

1.  等待确认电子邮件。

你应该在两个工作日内收到一封看起来类似于以下截图的电子邮件：

![注册 iOS 开发者计划](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00195.jpeg)

从这里，你可以继续设置你的账户：

1.  从你收到的电子邮件中点击**立即登录**，或者前往[`itunesconnect.apple.com`](https://itunesconnect.apple.com)。

1.  使用你的 iTunes 账户登录。

1.  同意在仪表盘主页上出现的任何附加协议。

1.  从 iTunes Connect 仪表盘前往**协议、税务和银行信息**。

1.  在这一部分，你将看到三列，分别是**联系方式**、**银行信息**和**税务信息**。

1.  在这些部分中为你的账户填写适当的信息。对于公司账户，很可能会需要会计师的协助。

当一切完成后，你的**协议、税务和银行信息**部分应该看起来类似于以下截图：

![注册 iOS 开发者计划](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00196.jpeg)

成功注册 iOS 开发者账户后，你现在可以部署到 iOS 设备并将你的应用发布到苹果 App Store。

# 注册成为 Google Play 开发者。

与 iOS 不同，将你的应用程序部署到 Android 设备是免费的，只需要在设备设置中进行一些更改。Google Play 开发者账户只需一次性支付 25 美元，并且不需要每年续费。但是，与 iOS 一样，如果你打算将应用提交到 Google Play 或需要实现这些功能之一，你需要一个 Google Play 账户。

要注册成为 Google Play 的开发者，请执行以下步骤：

1.  前往[`play.google.com/apps/publish`](https://play.google.com/apps/publish)。

1.  使用现有 Google 账户登录，或者创建一个新的账户。这之后无法更改，所以如果需要，请选择适合你公司的账户。

1.  同意协议并输入你的信用卡信息。

1.  选择一个开发者名称并输入账户的其他重要信息。同样，选择适合你公司的名称，以便用户在应用商店中看到。

如果一切填写正确，你将得到如下 Google Play 开发者控制台：

![注册成为 Google Play 开发者](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00197.jpeg)

如果你打算销售付费应用或应用内购买，在这一点上，我建议你设置你的**Google 商家账户**。这将使 Google 能够根据你所在国家的适当税法支付你的应用销售收益。如果这是为你的公司设置的，我建议寻求公司会计师或簿记员的帮助。

以下是设置 Google 商家账户的步骤：

1.  点击**设置商家账户**按钮。

1.  第二次使用你的 Google 账户登录。

1.  填写销售应用所需的信息：地址、电话号码、税务信息以及显示在客户信用卡账单上的名称。

完成后，你会注意到开发者控制台中关于设置商家账户的帮助提示现在不见了，如下截图所示：

![注册成为 Google Play 开发者](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00198.jpeg)

在这一点上，你可能会认为我们的账户已经完全设置好了，但在能够销售应用之前，还有一个关键步骤：我们必须输入银行信息。

使用以下步骤可以为你的 Google 商家账户设置银行：

1.  返回到[`play.google.com/apps/publish`](https://play.google.com/apps/publish)的 Google Play **开发者控制台**。

1.  点击**财务报告**部分。

1.  点击标题为**访问你的商家账户以获取详细信息**的小链接。

1.  你应该会看到一个警告，提示你没有设置银行账户。点击**指定银行账户**链接开始操作。

1.  输入你的银行信息。同样，可能需要公司的会计师。

1.  几天后，在你的账户中寻找来自 Google 的小额存款。

1.  通过访问[`checkout.google.com/sell`](http://checkout.google.com/sell)确认金额。

1.  点击**设置**标签，然后是**财务**。

1.  接下来，点击**验证账户**。

1.  输入你银行账户中出现的金额，并点击**验证存款**。

你的 Google 商家账户也是你可以取消或退款客户订单的地方。Google Play 与 iOS App Store 的不同之处在于，所有客户问题都直接指向开发者。

# 摘要

在本章中，我们讨论了 Xamarin 的核心产品，无论你是在使用 Mac OS X 还是 Windows PC，都可以用 C#开发 Android 和 iOS 应用程序。我们安装了 Xcode，然后运行了 Xamarin 一站式安装程序，它安装了 Java、Android SDK、Xamarin Studio、Xamarin.iOS 和 Xamarin.Android。在 Windows 上，我们在 Visual Studio 内设置了 Xamarin，并在本地网络上连接了一台 Mac 用于 iOS 开发。我们为调试应用程序时获得更快、更流畅的体验而设置了 x86 Android 模拟器。最后，我们设置了 iOS 和 Google Play 开发者账户，以便分发我们的应用程序。

在本章中，你应该已经获得了使用 Xamarin 构建跨平台应用程序所需的一切。你的开发计算机应该已经准备就绪，你应该已经安装了所有本地 SDK，准备开发下一个风靡全球的应用程序。

本章中的概念将为我们奠定更高级主题的基础，这需要安装适当的软件以及拥有苹果和谷歌的开发者账户。我们将把应用程序部署到真实设备上，并实现更高级的功能，如推送通知。在下一章中，我们将创建我们的第一个 iOS 和 Android 应用程序，并介绍每个平台的基础知识。


# 第二章：你好，平台！

如果你熟悉在 Windows 上使用 Visual Studio 开发应用程序，那么使用 Xamarin Studio 应该非常直接。Xamarin 使用相同的概念，即一个**解决方案**包含一个或多个**项目**，并且它为 iOS 和 Android 应用程序创建了几种新的项目类型。还有几个项目模板可以让你快速启动常见应用程序的开发。

Xamarin Studio 支持多种开箱即用的项目类型，包括标准的.NET 类库和控制台应用程序。你无法在 Mac 上的 Xamarin Studio 中本地开发 Windows 应用程序，但你可以肯定的是，可以在 Xamarin Studio 中开发应用程序的共享代码部分。我们将在后面的章节中关注共享代码，但请记住，Xamarin 使你能够在支持 C#的大部分平台之间共享一个通用的 C#后端。

在本章中，我们将涵盖：

+   为 iOS 创建一个简单的计算器应用程序

+   苹果的 MVC 模式

+   Xcode 和故事板

+   为安卓创建计算器应用程序

+   安卓活动

+   Xamarin 的安卓设计师

# 建立你的第一个 iOS 应用程序

启动 Xamarin Studio 并开始一个新的解决方案。与 Visual Studio 一样，**新建解决方案**对话框中有许多可以创建的项目类型。Xamarin Studio（前称**MonoDevelop**）支持开发许多不同类型的项目，如针对 Mono 运行时或.NET Core 的 C#应用程序、NUnit 测试项目，甚至除了 C#之外的其他语言，如 VB 或 C++。

Xamarin Studio 支持以下 iOS 项目类型：

+   **单视图应用**: 这是一个基本的项目类型，它设置了一个 iOS 故事板以及一个单一视图和控制器。

+   **主从应用**: 一种项目类型，其中包含你可以点击查看详细信息的项目列表。在 iPhone/iPod 上，它将使用多个控件占据整个屏幕区域，而在 iPad 上使用 iOS 的`UISplitViewController`。

+   **标签应用**: 这种项目类型会自动为具有标签布局的应用程序设置`UITabViewController`。

+   **基于页面的应用**: 这种项目类型会自动设置`UIPageViewController`，以便在屏幕间以轮播的方式分页。

+   **WebView 应用**: 这种项目类型用于创建“混合”应用程序，部分是 HTML，部分是原生应用。该应用程序设置为利用 Xamarin Studio 的 Razor 模板功能。

+   **类库**: 这是一个在其他 iOS 应用程序项目中使用的类库。

+   **绑定库**: 这是一个 iOS 项目，可以为 Objective-C 库创建 C#绑定。

+   **UI 测试应用**: 用于运行 UI 测试的 NUnit 测试项目，可以在本地或 Xamarin Test Cloud 上运行。

+   **单元测试应用**: 这是一个特殊的 iOS 应用程序项目，可以运行 NUnit 测试。

要开始，请创建一个新解决方案，并导航到**iOS** | **App**，然后创建一个如以下截图所示的**单视图应用**：

![构建你的第一个 iOS 应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00199.jpeg)

### 提示

在 Visual Studio 中，你可以在新解决方案对话框中从**Visual C# | iOS | Universal | 单视图应用**创建正确类型的项目。

在下一步中，我们将需要：

1.  选择一个**应用名称**。

1.  选择一个**组织标识符**，这是一个“反向”域名，用来唯一标识你的应用。

1.  选择你想要支持的 iOS 设备；你可以保留默认设置。

1.  选择你想要支持的最低 iOS 版本；你可以保留默认设置。

1.  最后一步，选择一个目录来放置你的项目，然后点击**创建**。

### 提示

在 Visual Studio 中，你可以通过打开 iOS 项目的**项目选项**来访问这些设置。Xamarin Studio 在其新项目对话框中有额外的步骤，但事后你总是可以编辑这些设置。

你会注意到，项目模板会自动创建几个文件和文件夹。这些文件如下：

+   `References`：这是你熟知的.NET 其他库的标准引用。

+   `Components`：这个文件夹将包含从 Xamarin 组件商店添加的任何组件。有关 Xamarin 组件商店的更多信息，请参见第九章，*带推送通知的 Web 服务*。

+   `Resources`：这个目录将包含任何你想要直接复制到应用程序包中的图片或普通文件。

+   `AppDelegate.cs`：这是苹果用于处理应用中应用程序级别事件的主类。

+   `Entitlements.plist`：这是一个设置文件，苹果用它来声明某些 iOS 功能（如推送通知和 iCloud）的权限。通常你只有在使用高级 iOS 功能时才需要使用它。

+   `*ViewController.cs`：这是表示应用中第一个屏幕的控制器。它将与你的项目同名。

+   `Info.plist`：这是苹果版本的一个**清单**文件，可以声明应用程序的各种设置，如应用标题、图标、启动画面和其他常见设置。

+   `LaunchScreen.storyboard`：这是一个用于布局应用程序启动画面的 Storyboard 文件。默认情况下，Xamarin 的项目模板在这里放置你的项目名称。

+   `Main.cs`：这个文件包含了 C#程序的标准入口点：`static void Main()`。你很可能不需要修改这个文件。

+   `MainStoryboard.storyboard`：这是你的应用程序的 Storyboard 定义文件。它将包含你的应用中的视图布局、控制器列表以及应用内导航的过渡效果。Storyboard 正如其名：是你 iOS 应用程序中不同屏幕的图解/流程图。

现在，让我们运行应用程序，看看从项目模板中默认得到什么。点击 Xamarin Studio 左上角的大播放按钮。你将看到模拟器正在运行你的第一个 iOS 应用程序，如下截图所示：

![构建你的第一个 iOS 应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00200.jpeg)

到目前为止，你的应用只是一个纯白色的屏幕，这并不令人兴奋或有用。在继续前进之前，让我们对 iOS 开发有更多的了解。

根据你的应用程序支持的最低 iOS 版本，你也可以在不同的 iOS 模拟器版本上运行应用程序。苹果还提供了针对 iPad 以及市场上所有不同 iOS 设备的模拟器。重要的是要知道这些是模拟器而非仿真器。仿真器将运行封装版的移动操作系统（就像 Android 那样）。仿真器通常性能较慢，但能更接近真实操作系统的复制。苹果的模拟器作为本地 Mac 应用程序运行，并不是真正的操作系统。其好处是相较于 Android 仿真器，它们运行得非常快。

# 理解苹果的 MVC 模式

在深入 iOS 开发之前，了解苹果公司在 iOS 开发中的设计模式是非常重要的。你可能在其他技术（如**ASP.NET**）中使用过**模型视图控制器（MVC）**模式，但苹果公司对此范式的实现略有不同。苹果为开发 iOS 应用程序的用户界面提供了一套核心 API，称为 UIKit。Xamarin 应用程序可以通过直接使用 C#中的这些 API 来充分利用 UIKit。UIKit 主要基于 MVC 设计模式。

**MVC**设计模式包括以下内容：

+   **模型**：这是驱动应用程序的后端业务逻辑。这可以是任何代码，例如，向服务器发起网络请求或保存数据到本地**SQLite**数据库。

+   **视图**：这是屏幕上实际的用户界面。在 iOS 的术语中，这是从`UIView`派生的任何类。例如工具栏、按钮，以及用户在屏幕上看到和与之交互的任何其他内容。

+   **控制器**：这是**MVC**模式中的工作马。控制器与**模型**层交互，并将结果更新到**视图**层。与**视图**层类似，任何控制器类都将从`UIViewController`派生。这是 iOS 应用程序中大部分代码所在的地方。

下图展示了 MVC 设计模式：

![理解苹果的 MVC 模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00201.jpeg)

为了更好地理解这个模式，让我们通过以下常见场景的示例来一步步了解：

1.  我们有一个 iOS 应用程序，其中包含一个搜索框，需要查询网站上的职位列表。

1.  用户将在`UITextField`文本框中输入一些文本，并点击`UIButton`按钮开始搜索。这是**视图**层。

1.  某些代码将响应按钮与**视图**交互，显示一个`UIActivityIndicatorView`加载指示器，并调用另一个类中的方法来执行搜索。这是**控制器**层。

1.  被调用的类中将发起一个网络请求，并异步返回一个职位列表。这是**模型**层。

1.  **控制器**随后将使用职位列表更新**视图**，并隐藏加载指示器。

### 注意

有关 Apple 的 MVC 模式的更多信息，请访问[`developer.apple.com/library/mac/documentation/general/conceptual/devpedia-cocoacore/MVC.html`](https://developer.apple.com/library/mac/documentation/general/conceptual/devpedia-cocoacore/MVC.html)的文档网站。

需要注意的是，你可以自由地应用中模型层做任何想做的事情。这里我们可以使用普通的 C#类，这些类可以在其他平台如 Android 上复用。这包括使用 C#的**基类库**（**BCL**）的任何功能，比如与网络服务或数据库交互。我们将在书中深入探讨跨平台架构和代码共享概念。

# 使用 iOS 设计师

由于我们纯白色的应用程序相当乏味，让我们通过一些控件来修改应用程序的视图层。为此，我们将在 Xamarin Studio 或 Visual Studio 中修改项目中的`MainStoryboard.storyboard`文件。可选地，你也可以在 Xcode 中打开故事板文件，这在 Xamarin.iOS 设计师之前是编辑故事板文件的方法。如果 Xamarin 设计师中不存在 iOS 故事板的功能，或者你需要编辑较旧的 iOS 格式如 XIB 文件，使用 Xcode 仍然有用。但是，Xcode 的体验并不好，因为 Xcode 中的自定义控件呈现为普通的白色方块。Xamarin 的设计师实际上运行你的自定义控件中的绘图代码，因此你可以准确地看到应用程序在运行时的样子。

让我们通过执行以下步骤向我们的应用程序添加一些控件：

1.  在 Xamarin Studio 中打开本章早前创建的项目。

1.  双击`MainStoryboard.storyboard`文件。

1.  iOS 设计师界面将会打开，你可以看到应用程序中单一控制器的布局。

1.  在右侧的**文档大纲**标签页中，你会看到你的控制器在其布局层次结构中包含了一个单一视图。

1.  在左上角，你会注意到一个工具箱，其中包含多种类型的对象，你可以将它们拖放到控制器的视图中。

1.  在搜索框中搜索`UILabel`，并将标签拖动到屏幕顶部居中位置。

1.  双击标签以将标签文本编辑为零（**0**）。你也可以从右下角的**属性**标签页中填写这个值。

1.  同样，搜索 `UIButton` 并创建 10 个编号为**0-9**的按钮，以形成一个数字键盘。你可以通过使用**属性**标签来编辑按钮上的文本。你也可以使用**复制/粘贴**来加速创建过程。双击按钮会添加一个点击事件处理程序，这对于在其他平台上使用 Visual Studio 进行开发的人来说可能很熟悉。

1.  运行应用程序。

你的应用程序应该看起来更像一个真正的应用程序（计算器），如下面的截图所示：

![使用 iOS 设计器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00202.jpeg)

### 提示

在 Windows 上的 Visual Studio 中，这些步骤与 Mac 上的 Xamarin Studio 相同。请记住，要使用 Xamarin.iOS 设计器，你必须保持与本地网络上的 Mac 连接。有关连接到 Mac 的说明，请参见第一章，*Xamarin 设置*。

此时你可能会想知道如何为应用添加用户交互选项。在 Xcode 的 iOS 设计器中，你会创建一个**出口**，使每个视图在 C#中可见。出口是引用故事板或 XIB 文件中的视图的引用，在运行时将用视图的实例填充。你可以将这个概念与其他技术中为控件命名的概念进行比较，例如**ASP.NET**、**WebForms**或**WPF**（**Windows Presentation Foundation**）。幸运的是，Xamarin 的 iOS 设计器比在 Xcode 中设置出口要简单一些。你只需在**属性**标签的**名称**字段中填写，Xamarin Studio 就会在**部分类**中生成一个属性，使你能够从控制器访问标签和按钮。此外，你还可以从故事板文件中连接一个**动作**，这是一个在事件发生时将被调用的方法。Xamarin Studio 将 iOS 动作作为部分方法公开，以便在你的类中实现。

让我们按照以下方式为应用添加一些交互：

1.  切换回 Xamarin Studio。

1.  再次双击 `MainStoryboard.storyboard` 文件。

1.  选择你之前创建的标签，并导航到**属性**窗格，确保你已选择**小部件**标签页。

1.  在**名称**字段中输入 `label`。

1.  创建一个带有文本**+**的按钮用于加法。

1.  切换到**事件**标签页。

1.  在**Up Inside**字段中输入名称 `OnAdd`。你可以将此视为按钮的“点击”事件。

1.  Xamarin Studio 将指导你将 `OnAdd` 方法放置在 `UIViewController` 中的位置。

1.  对每个数字按钮重复此过程，但将**Up Inside**事件命名为 `OnNumber`。

1.  为计算器创建一个带有文本**=**的新按钮。

1.  切换到**事件**标签页。

1.  在**Up Inside**字段中输入名称 `OnEquals`。

Xamarin 在这方面已经大大改善了从 Xcode 中的体验。对于更熟悉 Visual Studio 等工具的人来说，Xcode 有一个奇怪的界面。创建出口的方法涉及到点击并从控件拖动到 Objective-C 头文件。仅仅填写一个**名称**字段对于有 C#背景的开发者来说要简单得多，也更直观。

既然我们已经定义了两个出口，你的控制器将可以使用两个新的属性。在你的解决方案中展开`*ViewController.cs`文件并打开`*ViewController.designer.cs`文件。你会看到你的属性定义如下：

```kt
[Outlet] 
[GeneratedCode ("iOS Designer", "1.0")] 
MonoTouch.UIKit.UILabel label { get; set; } 

```

修改这个文件不是一个好主意，因为如果你在设计师或 Xcode 中做出进一步更改，IDE 会重新构建它。尽管如此，了解幕后实际工作原理是一个好习惯。

打开你的`*ViewController.cs`文件，让我们在你的控制器方法中输入以下代码：

```kt
partial void OnAdd(UIButton sender) 
{ 
    if (!string.IsNullOrEmpty(label.Text)) 
    { 
        label.Text += "+"; 
    } 
} 

partial void OnNumber(UIButton sender) 
{ 
    if (string.IsNullOrEmpty(label.Text) || label.Text == "0") 
    { 
        label.Text = sender.CurrentTitle; 
    } 
    else 
    { 
        label.Text += sender.CurrentTitle; 
    } 
} 

partial void OnEquals(UIButton sender) 
{ 
    //Simple logic for adding up the numbers 
    string[] split = label.Text.Split('+'); 
    int sum = 0; 
    foreach (string text in split) 
    { 
        int x; 
        if (int.TryParse(text, out x)) 
            sum += x; 
    } 
    label.Text = sum.ToString(); 
} 

```

这段代码的大部分只是用于实现计算器操作的通用 C#逻辑。在`OnAdd`方法中，如果标签文本非空，我们会添加一个`+`符号。在`OnNumber`方法中，我们适当地替换或追加标签文本。最后，在`OnEquals`方法中，我们使用字符串分割操作和整数转换计算标签中的表达式。然后，我们将结果放入标签文本中。

运行你的应用，你将能够与计算器进行交互，如下面的截图所示：

![使用 iOS 设计师](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00203.jpeg)

现在是一个自己完成这个练习并完成计算器的好时机。添加减法、乘法、除法按钮以及一个"清除"按钮，这将完成简单计算器。这应该能让你掌握使用 Apple 的`UIButton`、`UILabel` API 以及 UIKit 框架的基础知识。

既然我们已经介绍了在 Xamarin 的 iOS 设计师中布局控件以及在 C#中与出口交互的基础知识，那么让我们来了解一下 iOS 应用程序的标准生命周期。处理应用程序级事件的主要位置是在`AppDelegate`类中。

如果你打开你的`AppDelegate.cs`文件，你可以重写以下方法：

+   `FinishedLaunching`：这是应用程序的第一个入口点，应该返回`true`。

+   `DidEnterBackground`：这意味着用户点击了设备上的主页按钮，或者有其他应用，如电话，切换到前台。你应该执行任何需要保存用户进度或 UI 状态的操作，因为 iOS 可能会在应用退到后台时杀死你的应用。当你的应用在后台时，用户可能正在浏览主屏幕或打开其他应用。你的应用实际上是在内存中被暂停，直到被用户恢复。

+   `WillEnterForeground`：这意味着用户已经从后台重新打开了你的应用程序。你可能需要在这里执行其他操作，比如刷新屏幕上的数据等。

+   `OnResignActivation`：当操作系统在应用程序顶部显示系统弹窗时会发生这种情况。例如日历提醒或用户从屏幕顶部向下滑动的菜单。

+   `OnActivated`：这发生在`OnResignActivation`方法执行后，用户返回到你的应用时立即发生。

+   `ReceiveMemoryWarning`：这是操作系统发出的警告，要求释放应用程序中的内存。由于 C#的垃圾收集器，这在 Xamarin 中通常不需要，但如果应用程序中有任何重对象，如图片等，这是一个处理它们的好地方。如果无法释放足够的内存，操作系统可能会终止你的应用程序。

+   `HandleOpenUrl`：如果你实现了**URL 方案**，这是会调用的，它是 iOS 平台上相当于桌面平台的文件扩展名关联。如果你注册了你的应用程序以打开不同类型的文件或 URL，这个方法将被调用。

同样，在你的`*ViewController.cs`文件中，你可以在控制器上覆盖以下方法：

+   `ViewDidLoad`：当与你的控制器关联的视图加载时，会发生这种情况。在运行 iOS 6 或更高版本的设备上，它只发生一次。

+   `ViewWillAppear`：这发生在你的视图在屏幕上出现之前。如果应用程序导航过程中有任何视图需要刷新，这通常是最好的地方。

+   `ViewDidAppear`：这发生在任何过渡动画完成后，你的视图在屏幕上显示之后。在某些不常见的情况下，你可能需要在这里而不是在`ViewWillAppear`中执行操作。

+   `ViewWillDisappear`：在您的视图被隐藏之前会调用此方法。你可能需要在这里执行一些清理操作。

+   `ViewDidDisappear`：这发生在完成显示屏幕上不同控制器的过渡动画之后。与出现的 方法一样，这发生在`ViewWillDisappear`之后。

还有更多可以覆盖的方法，但许多方法在新版本的 iOS 中已被弃用。熟悉苹果的文档网站 [`developer.apple.com/library/ios`](http://developer.apple.com/library/ios)。在尝试理解苹果 API 的工作原理时，阅读每个类和方法的文档非常有帮助。学习如何阅读（不一定是编写）Objective-C 也是一个有用的技能，这样你在开发 iOS 应用程序时能够将 Objective-C 示例转换为 C#。

# 构建你的第一个 Android 应用程序

在 Xamarin Studio 中设置 Android 应用程序与在 iOS 上一样简单，并且与 Visual Studio 中的体验非常相似。Xamarin Studio 包含了几个特定的 Android 项目模板，以便快速开始开发。

Xamarin Studio 包含以下项目模板：

+   **Android 应用**：一个标准的 Android 应用程序，目标是安装在机器上的最新 Android SDK。

+   **Wear 应用**：一个针对 Android Wear，适用于智能手表设备的项目。

+   **WebView 应用**：一个使用 HTML 实现部分功能的混合应用的工程模板。支持 Razor 模板。

+   **类库**：只能被 Android 应用程序项目引用的类库。

+   **绑定库**：一个用于设置可以从 C# 调用的 Java 库的项目。

+   **UI 测试应用**：一个 NUnit 测试项目，用于在本地或 Xamarin Test Cloud 上运行 UI 测试。

+   **单元测试应用**：这是一个特殊的 Android 应用程序项目，可以运行 NUnit 测试。

启动 Xamarin Studio 并开始一个新的解决方案。在**新建解决方案**对话框中，在**Android**部分创建一个新的**Android 应用**。选择

最终你将得到一个类似于以下截图的解决方案：

![构建你的第一个 Android 应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00204.jpeg)

### 提示

在 Visual Studio 中，Android 项目模板位于**Android | 空白应用**下。

你会注意到，以下特定于 Android 的文件和文件夹已经为你创建：

+   `Components` 文件夹。这与 iOS 项目相同，是添加来自 Xamarin 组件商店的组件的地方。

+   `Assets` 文件夹：这个目录将包含具有 `AndroidAsset` 构建动作的文件。这个文件夹将包含要随 Android 应用程序捆绑的原始文件。

+   `Properties/AndroidManifest.xml`：这个文件包含了关于你的 Android 应用程序的标准声明，如应用程序名称、ID 和权限。

+   `Resources` 文件夹：资源包括可以经由 Android 资源系统加载的图片、布局、字符串等。每个文件将在 `Resources.designer.cs` 中生成一个 ID，你可以使用它来加载资源。

+   `Resources/drawable` 文件夹：通常将应用程序使用的任何图片放在这里。

+   `Resources/layout` 文件夹：这包含了 Android 用来声明 UI 的 `*.axml`（Android XML）文件。布局可以是整个**活动**、**片段**、**对话框**或要在屏幕上显示的**子控件**。

+   `Resources/mipmap-*` 文件夹：包含在不同 Android 设备主屏幕上显示的应用程序图标。这些文件夹中的应用图标因为它们用于与设备当前密度不同的分辨率。

+   `Resources/values` 文件夹：这包含了声明应用程序中字符串（和其他类型）的键值对的 XML 文件。这是在 Android 上通常设置多语言本地化的方式。

+   `MainActivity.cs`：这是`MainLauncher`操作和你的安卓应用程序的第一个活动。在 Android 应用中没有`static void Main`函数；执行从设置了`MainLauncher`为`true`的活动开始。

现在让我们执行以下步骤来运行应用程序：

1.  点击播放按钮编译并运行应用程序。

1.  可能会出现一个**选择设备**对话框。

1.  选择你喜欢的模拟器，并点击**启动模拟器**。如果你在第一章，*Xamarin 设置*中设置了 x86 模拟器，我建议使用它。

1.  等待几秒钟让模拟器启动。一旦启动，建议在你从事 Android 项目工作时让它保持运行。这将为你节省大量等待时间。

1.  你现在应该在设备列表中看到已启用的模拟器；选择它，然后点击**确定**。

1.  第一次将应用部署到模拟器或设备时，Xamarin Studio 需要安装一些东西，比如 Mono 共享运行时和 Android 平台工具。

1.  切换到安卓模拟器。

1.  你的应用程序将会出现。

### 提示

在 Windows 上的 Visual Studio 中，你也可以尝试使用**Visual Studio Emulator for Android**。这是一个不错的模拟器，预装在 Visual Studio 2015 中。

当所有工作完成后，你已经部署了你的第一个安卓应用程序，其中包括一个单一按钮。你的应用看起来将如下截图所示：

![构建你的第一个安卓应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00205.jpeg)

# 了解安卓活动

安卓操作系统非常注重活动（Activity）这一概念。活动是用户在屏幕上可以执行的任务或工作单元。例如，用户会进行**拨号活动**来拨打一个号码，并进行第二个活动与通讯录互动以找到该号码。每个安卓应用程序都是由一个或多个活动组成，用户可以启动这些活动，并通过按下设备上的硬件返回键来退出或取消。用户的历史记录保存在安卓的**后退堆栈**中，在特殊情况下，你可以通过代码操作它。当一个新的活动开始时，前一个活动会被暂停并保存在内存中供以后使用，除非操作系统内存不足。

活动之间是松耦合的；在某种程度上，你可以认为它们在内存中拥有完全独立的状态。静态类、属性和字段将保持应用程序的生命周期，但常见做法是将状态通过安卓**捆绑包**传递。这对于传递列表中显示的项目的标识符，以便在新活动中编辑该项目非常有用。

活动有以下生命周期回调方法，你可以重写：

+   `OnCreate`: 当你的活动被创建时，这是第一个被调用的方法。在这里设置你的视图并执行其他加载逻辑。最重要的是，你将在这里调用`SetContentView`来设置你的活动视图。

+   `OnResume`: 当你的活动视图在屏幕上可见时会被调用。如果活动是第一次显示，或者用户从另一个活动返回到它时，都会调用此方法。

+   `OnPause`: 当用户离开你的活动时会被调用。它可能发生在导航到应用内的新活动之前、锁屏或按下主页按钮时。假设用户可能不会返回，因此你需要在这里保存用户所做的任何更改。

+   `OnStart`: 当活动的视图即将在屏幕上显示时，紧随`OnResume`之前发生。当活动开始或用户从另一个活动返回到它时，会发生此方法。

+   `OnStop`: 当活动的视图不再在屏幕上显示时，紧随`OnPause`之后发生。

+   `OnRestart`: 当用户从上一个活动返回到你的活动时，会发生此方法。

+   `OnActivityResult`: 此方法用于在 Android 上与其他应用程序中的活动进行通信。它与`StartActvityForResult`结合使用；例如，你可以用这个方法与 Facebook 应用程序交互以登录用户。

+   `OnDestroy`: 当你的活动即将从内存中释放时会被调用。在这里执行任何可能帮助操作系统的额外清理工作，例如处理活动使用的任何其他重量级对象。

Android 生命周期的流程图如下：

![理解 Android 活动](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00206.jpeg)

与 iOS 不同，Android 并未对其开发者实施任何设计模式。然而，在一定程度上理解 Android 活动生命周期是不可或缺的。活动中许多概念与 iOS 上的控制器有相似之处；例如，`OnStart`相当于`ViwWillAppear`，而`OnResume`则相当于`ViewDidAppear`。

在处理活动时需要注意的其他方法如下：

+   `StartActivity(Type type)`: 此方法在应用程序内启动一个新活动，并不向活动传递任何额外信息。

+   `StartActivity(Intent intent)`: 这是一个用于通过`Intent`启动新活动的重载方法。它使你能够向新活动传递额外信息，并且你也可以启动其他应用程序中的活动。

+   `StartActivityForResult`: 此方法启动一个新活动，并预期在活动操作完成后收到`OnActivityResult`。

+   `Finish`: 这将关闭当前活动，并在完全关闭且不再在屏幕上显示时调用`OnDestroy`。根据后退栈上当前的内容，用户将返回到上一个活动或主屏幕。

+   `SetContentView`：此方法设置要为活动显示的主要视图。它应该在活动在屏幕上显示之前在`OnCreate`方法内调用。

+   `FindViewById`：这是一个用于定位在活动中显示的视图的方法。它有一个泛型版本，用于返回适当类型的视图。

你可以将`intent`视为描述从一个活动过渡到另一个活动的对象。你还可以通过意图传递附加数据，以及修改活动的显示方式和用户的导航历史。

除了活动之外，Android 还有片段（fragment）的概念。你可以将片段视为在父活动中显示的微型活动。片段对于在应用中复用不同的 UI 部分非常有用，还可以帮助你实现在平板电脑上的分屏导航。

# Xamarin 的 Android 设计师

Android 项目的默认模板比 iOS 具有更多内置功能，因此我们稍后会有一些控件需要删除。Android 用户界面布局在 XML 文件中定义，这些文件对人类可读和可编辑。然而，Xamarin Studio 提供了一个优秀的设计工具，允许你拖放控件来定义你的 Android 布局。让我们为你的应用程序添加更多功能，并开始使用 Android 设计师。

返回 Xamarin Studio，执行以下步骤为你的应用添加功能：

1.  在 Xamarin Studio 中打开本章前面创建的 Android 项目。

1.  在项目中的**资源** | **布局**下，打开`Main.axml`。

1.  你会看到 Android 设计师在 Xamarin Studio 中打开。

1.  删除 Android 项目模板中现有的标签和按钮。

1.  从右侧的**工具箱**部分拖动一个**TextView**到空白布局中。

1.  在标签中输入一些默认文本，如`0`。

1.  在右侧的**属性**窗格中，你会看到**id**值设置为`@+id/textView1`。我们将它改为`@+id/text`，以便稍后可以用 C#与标签交互。

1.  现在，从**工具箱**部分拖动一个**GridLayout**，并在**属性**面板下设置**行数**为 4 和**列数**为 3。

1.  从**工具箱**部分拖动 10 个**Button**控件，并将它们的文本编号为**0-9**。

1.  将它们的**id**设置为从**0-9**编号的`@+id/button0`。

1.  创建两个更多带有 id `@+id/plus` 和 `@+id/equals` 的按钮，将它们的文本分别设置为**+** 和 **=**。

### 提示

在 Visual Studio 中，Xamarin.Android 设计器与其 Xamarin Studio 对应部分基本相同。主要区别在于编辑控件属性时，使用的是标准的 Visual Studio 属性编辑器。你可能会发现通过**属性**窗格的工具栏按钮在**A 到 Z**和分组排序之间切换很有用。

现在，如果你尝试编译并运行你的应用程序，你可能会注意到一些编译错误。现在，打开 `MainActivity.cs` 并删除 `OnCreate` 方法中的代码，除了调用 `SetContentView` 的那一行。

你的 `MainActivity` 应该看起来像这样：

```kt
[Activity(Label = "Calculator", MainLauncher = true, Icon = "@mipmap/icon")] 
public class MainActivity : Activity 
{
  protected override void OnCreate(Bundle savedInstanceState) 
  {
    base.OnCreate(savedInstanceState);
    SetContentView(Resource.Layout.Main); 
  }
}

```

现在，启动你的 Android 应用程序，它应该与你设计师所做的更改完全相同，如下所示：

![Xamarin 的 Android 设计器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00207.jpeg)

切换回 Xamarin Studio 并打开 `MainActivity.cs` 文件。我们将修改活动以与在 Xamarin.Android 设计器中设置好的布局进行交互。我们使用 `FindViewById` 方法通过我们在布局文件中设置的 ID 来获取视图。Xamarin Studio 还自动生成了一个名为 `Resource` 的静态类，以便引用你的标识符。

首先，在 `MainActivity.cs` 中声明一个类级别的私有字段：

```kt
TextView text; 

```

让我们在 `OnCreate` 中通过以下代码获取 **TextView** 字段的实例：

```kt
text = FindViewById<TextView>(Resource.Id.text); 

```

`Resource` 类是一个静态类，Xamarin 设计器会为你填充它。为了将来的参考，你可能需要构建你的 Android 项目，以便新的 IDs 和其他资源在 Xamarin Studio 的 C# 文件中显示。

在 `MainActivity.cs` 中创建一个我们将用于点击事件的方法，它将与我们在 iOS 上所做的非常相似：

```kt
private void OnNumber(object sender, EventArgs e) 
{ 
    var button = (Button)sender; 
    if (string.IsNullOrEmpty(text.Text) || text.Text == "0") 
    { 
        text.Text = button.Text; 
    } 
    else 
    { 
        text.Text += button.Text; 
    } 
}

```

接下来，让我们在活动中的 `OnCreate` 方法里为 `number1` 绑定 `Click` 事件：

```kt
var button = FindViewById<Button>(Resource.Id.number1); 
button.Click += OnNumber; 

```

为所有的数字按钮 **0-9** 重复这段代码。

接下来，让我们为 "add" 和 "equals" 按钮设置事件处理程序，就像我们在 iOS 应用中所做的那样：

```kt
private void OnAdd(object sender, EventArgs e) 
{ 
    if (!string.IsNullOrEmpty(text.Text)) 
    { 
        text.Text += "+"; 
    } 
} 

private void OnEquals(object sender, EventArgs e) 
{ 
    //This is the same simple calculator logic as on iOS 
    string[] split = text.Text.Split('+'); 
    int sum = 0;  
    foreach (string text in split) 
    { 
        int x; 
        if (int.TryParse(text, out x)) 
            sum += x; 
    } 
    text.Text = sum.ToString(); 
} 

```

接下来，让我们在活动中的 `OnCreate` 方法里为这些按钮绑定 `Click` 事件：

```kt
var add = FindViewById<Button>(Resource.Id.add); 
add.Click += OnAdd; 
var equals = FindViewById<Button>(Resource.Id.equals); 
equals.Click += OnEquals;; 

```

现在，如果我们运行应用程序，我们将得到一个与本章前面展示的 iOS 计算器功能完全相同的 Android 应用：

![Xamarin 的 Android 设计器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00208.jpeg)

# 总结：

在本章中，我们在 Xamarin Studio 中创建了第一个 iOS 应用程序。我们介绍了苹果的 MVC 设计模式，以更好地理解 `UIViewController` 和 `UIView` 之间的关系，同时也介绍了如何在 Xamarin Studio 中使用 iOS 设计器编辑 storyboard 文件。接下来，我们在 Xamarin Studio 中创建了第一个 Android 应用程序，并学习了 Android 中的活动生命周期。我们还使用了 Xamarin 的 Android 设计器来修改 Android XML 布局。

从本章涵盖的主题来看，你应该能够使用 Xamarin 的工具为 iOS 和 Android 开发简单的应用程序，并且信心满满。你应该对原生 SDK 和设计模式有一个基本的了解，以完成在 iOS 和 Android 上的任务。

在下一章中，我们将介绍使用 Xamarin Studio 在平台之间共享代码的各种技术。我们将讨论架构跨平台应用程序的不同方法，以及如何在 Visual Studio 或 Xamarin Studio 中设置项目和解决方案。


# 第三章：iOS 与 Android 之间的代码共享

Xamarin 的工具承诺在可能的情况下利用每个平台的本地 API，在 iOS 和 Android 之间共享大部分代码。这样做更多的是软件工程的实践，而不是编程技能或对每个平台的知识。为了构建一个支持代码共享的 Xamarin 应用程序，必须将应用程序分离为不同的层次。我们将介绍基础知识以及针对特定情况考虑的具体选项。

在本章中，我们将涵盖以下内容：

+   用于代码共享的 MVVM 设计模式

+   项目和解决方案的组织策略

+   可移植类库（PCLs）

+   针对特定平台代码的预处理器语句

+   依赖注入（DI）简化

+   控制反转（IoC）

# 学习 MVVM 设计模式

**模型-视图-视图模型**（**MVVM**）设计模式最初是为了使用**XAML**的**WPF**（**Windows Presentation Foundation**）应用程序而发明的，用于将 UI 与业务逻辑分离，并充分利用**数据绑定**。以这种方式构建的应用程序有一个独特的视图模型层，它与用户界面没有依赖关系。这种架构本身针对单元测试以及跨平台开发进行了优化。由于应用程序的视图模型类对 UI 层没有依赖，你可以轻松地将 iOS 用户界面替换为 Android 界面，并针对视图模型层编写测试。MVVM 设计模式与前面章节讨论的 MVC 设计模式也非常相似。

MVVM 设计模式包括以下内容：

+   **模型**：模型层是驱动应用程序的后端业务逻辑以及任何伴随的业务对象。这可以是任何从向服务器发起网络请求到使用后端数据库的内容。

+   **视图**：这一层是屏幕上实际看到用户界面。在跨平台开发中，它包括任何特定于平台的代码，用于驱动应用程序的用户界面。在 iOS 上，这包括整个应用程序中使用的控制器，在 Android 上，则包括应用程序的活动。

+   **视图模型**：这一层在 MVVM 应用程序中充当粘合剂。视图模型层协调视图和模型层之间的操作。视图模型层将包含视图获取或设置的属性，以及每个视图上用户可以进行的每个操作的函数。如果需要，视图模型还将在模型层上调用操作。

下图展示了 MVVM 设计模式：

![学习 MVVM 设计模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00209.jpeg)

需要注意的是，视图(View)和视图模型(ViewModel)层之间的交互传统上是通过 WPF 的数据绑定来创建的。然而，iOS 和 Android 没有内置的数据绑定机制，因此本书将采用的方法是从视图手动调用视图模型层。有几个框架提供了数据绑定功能，例如**MVVMCross**和**Xamarin.Forms**。

为了更好地理解这一模式，让我们实现一个常见场景。假设我们在屏幕上有一个搜索框和一个搜索按钮。当用户输入一些文本并点击按钮时，将向用户显示产品和价格列表。在我们的示例中，我们将使用 C# 5 中可用的**async**和**await**关键字来简化异步编程。

要实现此功能，我们将从一个简单的`model`类（也称为`business`对象）开始，如下所示：

```kt
public class Product 
{ 
    public int Id { get; set; } //Just a numeric identifier 
    public string Name { get; set; } //Name of the product 
    public float Price { get; set; } //Price of the product 
} 

```

接下来，我们将根据搜索词实现我们的模型层以检索产品。这里执行业务逻辑，表达实际需要如何执行搜索。以下代码行中可以看到这一点：

```kt
// An example class, in the real world would talk to a web 
// server or database. 
public class ProductRepository 
{ 
  // a sample list of products to simulate a database 
  private Product[] products = new[] 
  { 
    new Product { Id = 1, Name = "Shoes", Price = 19.99f }, 
    new Product { Id = 2, Name = "Shirt", Price = 15.99f }, 
    new Product { Id = 3, Name = "Hat", Price = 9.99f }, 
  }; 

  public async Task<Product[]> SearchProducts(string searchTerm) 
  { 
    // Wait 2 seconds to simulate web request 
    await Task.Delay(2000); 

    // Use Linq-to-objects to search, ignoring case 
    searchTerm = searchTerm.ToLower(); 

    return products.Where(p =>
      p.Name.ToLower().Contains(searchTerm)) 
      .ToArray(); 
  } 
} 

```

需要注意的是，`Product`和`ProductRepository`类都被认为是跨平台应用程序模型层的一部分。有些人可能认为`ProductRepository`是一个**服务**，通常是一个自包含的用于获取数据的类。将此功能分为两个类是一个好主意。`Product`类的任务是保存有关产品的信息，而`ProductRepository`负责检索产品。这是**单一职责原则**的基础，该原则指出每个类应该只有一个工作或关注点。

接下来，我们将按以下方式实现一个`ViewModel`类：

```kt
public class ProductViewModel 
{ 
  private readonly ProductRepository repository =
      new ProductRepository(); 

  public string SearchTerm 
  { 
    get; 
    set; 
  } 

  public Product[] Products 
  { 
    get; 
    private set; 
  } 

  public async Task Search() 
  { 
    if (string.IsNullOrEmpty(SearchTerm)) 
      Products = null; 
    else 
      Products = await repository.SearchProducts(SearchTerm); 
  } 
} 

```

从这里开始，你的特定平台代码就开始了。每个平台将处理管理`ViewModel`类的实例，设置`SearchTerm`属性，并在点击按钮时调用`Search`。当任务完成后，用户界面层将更新屏幕上显示的列表。

如果你熟悉与 WPF 一起使用的 MVVM 设计模式，你可能会注意到我们没有为数据绑定实现`INotifyPropertyChanged`。由于 iOS 和 Android 没有数据绑定的概念，我们省略了此功能。如果你计划为移动应用程序提供一个 WPF 或 Windows UWP 版本，或者使用提供数据绑定的框架，你应在需要的地方实现支持。

### 提示

要了解更多关于`INotifyPropertyChanged`的信息，请查看 MSDN 上的这篇文章：[`msdn.microsoft.com/en-us/library/system.componentmodel.inotifypropertychanged`](https://msdn.microsoft.com/en-us/library/system.componentmodel.inotifypropertychanged)

# 比较项目组织策略

在这一点上，你可能会问自己，如何在 Xamarin Studio 中设置解决方案以处理共享代码，同时也有特定平台的项目？Xamarin.iOS 应用程序只能引用 Xamarin.iOS 类库；因此，设置解决方案可能会遇到问题。有几种设置跨平台解决方案的策略，每种策略都有其自身的优点和缺点。

跨平台解决方案的选项如下：

+   **文件链接**：对于这个选项，你可以从普通的.NET 4.0 或.NET 4.5 类库开始，该类库包含所有共享代码。然后，你需要为每个希望应用运行的平台创建一个新项目。每个特定平台的项目将包含一个子目录，其中链接了第一个类库中的所有文件。要设置这个，将现有文件添加到项目中，并选择**添加对文件的链接**选项。任何单元测试都可以针对原始类库运行。文件链接的优点和缺点如下：

    +   **优点**：这种方法非常灵活。你可以选择链接或不链接某些文件，并且可以使用如`#if IPHONE`之类的预处理器指令。你还可以在 Android 和 iOS 上引用不同的库。

    +   **缺点**：你必须在三个项目中管理文件的存在：核心库、iOS 和 Android。如果这是一个大型应用程序，或者有很多人在处理它，这可能会很麻烦。自从共享项目出现后，这个选项也有些过时了。

+   **克隆项目文件**：这非常类似于文件链接，主要的区别在于除了主项目之外，每个平台都有一个类库。将 iOS 和 Android 项目放在主项目同一目录下，文件可以添加而无需链接。你可以通过右键单击解决方案并选择**显示选项** | **显示所有文件**轻松地添加文件。单元测试可以针对原始类库或特定平台的版本运行：

    +   **优点**：这种方法与文件链接一样灵活，但你不需要手动链接任何文件。你仍然可以使用预处理器指令，并在每个平台上引用不同的库。

    +   **缺点**：你仍然需要在三个项目中管理文件的存在。此外，还需要一些手动文件整理来设置这个。你最终在每个平台上还要管理一个额外的项目。自从共享项目出现后，这个选项也有些过时了。

+   **共享项目**：从 Visual Studio 2013 开始，微软创建了共享项目的概念，以实现 Windows 8 和 Windows Phone 应用程序之间的代码共享。Xamarin 也在 Xamarin Studio 中实现了共享项目，作为实现代码共享的另一种选项。共享项目实际上与文件链接相同，因为添加对共享项目的引用实际上将其文件添加到你的项目中：

    +   **优点**：这种方法与文件链接相同，但更加整洁，因为你的共享代码位于一个单一的项目中。Xamarin Studio 还提供了一个下拉菜单，可以在引用的每个项目之间切换，这样你就可以看到预处理器语句在代码中的效果。

    +   **缺点**：由于共享项目中的所有文件都会被添加到每个平台的主项目中，因此在共享项目中包含特定平台的代码可能会变得不美观。如果你有一个大型团队，或者团队成员经验不足，预处理语句可能会迅速失控。共享项目也不会编译成 DLL，所以如果没有源代码，就没有办法分发这种类型的项目。

+   **便携式类库**：一旦你对 Xamarin 更加熟悉，这将是最佳选择；你从创建一个所有共享代码的**便携式**类库（**PCL**）项目开始解决方案。这是一种特殊的项目类型，允许多个平台引用同一个项目，使你可以使用每个平台中可用的 C#和.NET 框架的最小子集。每个特定平台的项目将直接引用这个库，以及任何单元测试项目：

    +   **优点**：你所有的共享代码都在一个项目中，所有平台都使用相同的库。由于不可能使用预处理器语句，PCL 库的代码通常更整洁。特定平台的代码通常通过接口或抽象类进行抽象。

    +   **缺点**：根据你面向的平台数量，你将受限于.NET 的一个子集。特定平台的代码需要使用**依赖注入**，这对于不熟悉这一主题的开发者来说可能是一个更高级的话题。

# 设置共享项目

为了完全理解每个选项以及何种情况需要它，让我们为共享项目和便携式类库定义一个解决方案结构。让我们使用本章前面提到的产品搜索示例，并为每种方法设置一个解决方案。

要设置共享项目，请执行以下步骤：

1.  打开 Xamarin Studio 并开始一个新解决方案。

1.  在**多平台 | 应用**部分下选择一个新的**单视图应用**。

1.  将应用命名为`ProductSearch`，并选择**使用共享库**。

1.  完成这个新项目向导，Xamarin Studio 将生成三个项目：`ProductSearch`、`ProductSearch.Droid`和`ProductSearch.iOS`。

1.  将`Product`、`ProductRepository`和`ProductViewModel`类添加到本章前面提到的`ProductSearch`项目中。你需要在需要的地方添加`using System.Threading.Tasks;`和`using System.Linq;`。

1.  点击顶部菜单中的**构建** | **构建全部**来再次检查一切，这样你就成功设置了一个跨平台解决方案。

完成后，你将得到一个解决方案树，其外观类似于以下截图所示：

![设置共享项目](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00210.jpeg)

共享项目是开始跨平台开发的一个很好的起点。使用它们不会出错，并且它们提供了最大的灵活性，可以在共享代码中使用`#if`。共享项目可能不是最佳选择的情况，可能是因为你需要将共享项目分发给其他人，或者拥有非常大的团队或代码库。如果放任不管，预处理器指令确实可能会失控。

### 提示

在 Visual Studio 中，跨平台应用程序的项目模板可以在**跨平台 | 空白应用（原生共享）**下找到。需要注意的是，它还会生成一个 Windows Phone 项目，如果不需要，你可以简单地移除它。

# 使用便携式类库进行工作。

**便携式类库**（**PCL**）是一个 C#库项目，能够在包括 iOS、Android、Windows、Windows Store 应用、Windows Phone、Silverlight 和 Xbox 360 在内的多个平台上得到支持。PCL 是微软为简化不同.NET 框架版本间开发而做出的努力。Xamarin 也为 iOS 和 Android 增加了对 PCL 的支持。许多流行的跨平台框架和开源库开始开发 PCL 版本，如 Json.NET 和 MVVMCross。

要设置一个共享项目，请执行以下步骤：

1.  打开 Xamarin Studio 并开始一个新的解决方案。

1.  在**多平台 | 应用**部分下选择新的**单视图应用**。或者在 Visual Studio 中，选择**跨平台 | 空白应用（原生便携式）**。

1.  将应用命名为`ProductSearch`，并选择**使用便携式库**。

1.  完成这个新项目向导，Xamarin Studio 将生成三个项目：`ProductSearch`、`ProductSearch.Droid`和`ProductSearch.iOS`。

1.  将本章前面提到的`Product`、`ProductRepository`和`ProductViewModel`类添加到`ProductSearch`项目中。你需要在需要的地方添加`using System.Threading.Tasks;`和`using System.Linq;`。

1.  点击顶部菜单中的**构建** | **构建全部**以再次检查一切，这样你就成功设置了一个 PCL 跨平台解决方案。

如果你需要将项目作为 DLL 或 NuGet 包共享，PCL 是最佳选择。它还帮助你将特定平台的关注点分离，因为它迫使你使用接口或基类，并结合**依赖注入（DI）**。如果你需要在 iOS 或 Android 上使用类似本地的库，如 Facebook SDK，也会出现类似的问题。

### 提示

在撰写本文时，微软刚刚发布了.NET Core 和新的.NET Standard。这将影响未来 PCLs 的工作方式，但不会破坏现有的 Xamarin.iOS 和 Xamarin.Android 项目。不过，这将使你能够继续与.NET Core 和 ASP.NET Core 项目共享代码。

# 使用预处理器语句

当使用共享项目时，你最有力的工具之一就是使用预处理器语句。如果你不熟悉它们，C# 有能力定义预处理器变量，如 `#define IPHONE`，然后使用 `#if IPHONE` 或 `#if !IPHONE`。

下面是使用该技术的简单示例：

```kt
#if IPHONE 
  Console.WriteLine("I am running on iOS"); 
#elif ANDROID 
  Console.WriteLine("I am running on Android"); 
#else 
  Console.WriteLine("I am running on ???"); 
#endif 

```

在 Xamarin Studio 中，你可以在项目选项的 **构建** | **编译器** | **定义符号** 下定义预处理器变量，用分号分隔。这些变量将被应用到整个项目。请注意，你必须为解决方案中的每个配置设置（**调试** 和 **发布**）设置这些变量；这是一个容易遗漏的步骤。你还可以在任何 C# 文件的顶部通过声明 `#define IPHONE` 来定义这些变量，但它们只会在 C# 文件内应用。

让我们再看一个例子，假设我们想要在每个平台上实现一个打开 URL 的类：

```kt
public static class Utility 
{ 
  public static void OpenUrl(string url) 
  { 
    //Open the url in the native browser 
  } 
} 

```

前面的例子是使用预处理器语句的完美候选者，因为它非常特定于每个平台，而且是一个相当简单的函数。要在 iOS 和 Android 上实现该方法，我们需要利用一些本地 API。重构类，使其如下所示：

```kt
#if IPHONE 
  //iOS using statements 
  using MonoTouch.Foundation; 
  using MonoTouch.UIKit; 
#elif ANDROID 
  //Android using statements 
  using Android.App; 
  using Android.Content; 
  using Android.Net; 
#else 
  //Standard .Net using statement 
  using System.Diagnostics; 
#endif 

public static class Utility 
{ 
  #if ANDROID 
    public static void OpenUrl(Activity activity, string url) 
  #else 
    public static void OpenUrl(string url) 
  #endif 
  { 
    //Open the url in the native browser 
    #if IPHONE 
      UIApplication.SharedApplication.OpenUrl(
         NSUrl.FromString(url)); 
    #elif ANDROID 
      var intent = new Intent(Intent.ActionView,
         Uri.Parse(url)); 
      activity.StartActivity(intent); 
    #else 
      Process.Start(url); 
    #endif 
  } 
} 

```

前一个类别支持三种不同类型的项目：Android、iOS 和标准的 Mono 或 .NET 框架类库。在 iOS 的情况下，我们可以使用苹果 API 中可用的静态类来执行功能。Android 稍微有些复杂，需要 `Activity` 对象来本地启动浏览器。我们通过修改 Android 上的输入参数来解决这一问题。最后，我们有一个纯 .NET 版本，它使用 `Process.Start()` 来启动一个 URL。需要注意的是，使用第三种选项在 iOS 或 Android 上本地是无法工作的，这就需要我们使用预处理器语句。

使用预处理器语句通常不是跨平台开发中最干净或最好的解决方案。它们通常最好在困境中使用，或用于非常简单的函数。代码很容易失控，如果有很多 `#if` 语句，代码可能会变得非常难以阅读，因此适度使用总是更好的。当类大多数是特定于平台的时候，使用继承或接口通常是更好的解决方案。

# 简化依赖注入

**依赖注入** 一开始看起来可能是一个复杂的话题，但大部分情况下它是一个简单的概念。它是一个设计模式，旨在使你的应用程序中的代码更加灵活，以便在需要时可以替换某些功能。这个想法围绕在应用程序中设置类之间的依赖关系，以便每个类只与接口或基类/抽象类交互。这给了你在需要实现本地功能时在每个平台上覆盖不同方法的自由。

这个概念源自于**SOLID**面向对象设计原则，如果你对软件架构感兴趣，这是一组你可能想要研究的规定。SOLID 中的**D**代表**依赖关系**。具体来说，该原则声明程序应依赖于抽象，而不是具体（具体类型）。

为了建立这个概念，让我们通过以下例子来逐步了解：

1.  假设我们需要在应用程序中存储一个设置，以确定声音是开还是关。

1.  现在我们来声明一个简单的设置接口：`interface ISettings { bool IsSoundOn { get; set; } }`。

1.  在 iOS 上，我们想使用`NSUserDefaults`类来实现这个接口。

1.  同样，在 Android 上，我们会使用`SharedPreferences`来实现这一点。

1.  最后，任何需要与这个设置交互的类只需引用`ISettings`，这样每个平台上的实现都可以被替换。

作为参考，这个例子的完整实现看起来如下片段所示：

```kt
public interface ISettings 
{ 
  bool IsSoundOn 
  { 
    get; 
    set; 
  } 
} 

//On iOS 
using UIKit; 
using Foundation; 

public class AppleSettings : ISettings 
{ 
  public bool IsSoundOn 
  { 
    get 
    { 
      return NSUserDefaults.StandardUserDefaults 
        .BoolForKey("IsSoundOn"); 
    } 
    set 
    { 
      var defaults = NSUserDefaults.StandardUserDefaults; 
      defaults.SetBool(value, "IsSoundOn"); 
      defaults.Synchronize(); 
    } 
  } 
} 

//On Android 
using Android.Content; 

public class DroidSettings : ISettings 
{ 
  private readonly ISharedPreferences preferences; 

  public DroidSettings(Context context) 
  { 
    preferences = context.GetSharedPreferences(
       context.PackageName, FileCreationMode.Private); 
  } 

  public bool IsSoundOn 
  { 
    get 
    { 
      return preferences.GetBoolean("IsSoundOn", true); 
    } 
    set 
    { 
      using (var editor = preferences.Edit()) 
      { 
        editor.PutBoolean("IsSoundOn", value); 
        editor.Commit(); 
      } 
    } 
  } 
} 

```

现在，按照 MVVM 模式，你可能会有一个`ViewModel`类，它只引用`ISettings`，如下面的代码片段所示：

```kt
public class SettingsViewModel 
{ 
  private readonly ISettings settings; 

  public SettingsViewModel(ISettings settings) 
  { 
    this.settings = settings; 
  } 

  public bool IsSoundOn 
  { 
    get; 
    set; 
  } 

  public void Save() 
  { 
    settings.IsSoundOn = IsSoundOn; 
  } 
} 

```

对于这样一个简单的例子来说，使用 ViewModel 层并不一定需要，但如果你需要进行其他任务，如输入验证，你可以看到它将非常有用。一个完整的应用程序可能会有更多的设置，并且可能需要向用户展示加载指示器。抽象出你的设置的实现会给你的应用程序带来其他好处，增加灵活性。比如说，你突然需要将 iOS 上的`NSUserDefaults`替换为 iCloud 版本；你可以通过实现一个新的`ISettings`类轻松做到这一点，其余的代码将保持不变。这还将帮助你针对新的平台，比如 Windows UWP，你可能选择以特定于平台的方式实现`ISettings`。

# 实现控制反转

在这一点上，你可能会问自己，如何切换不同的类，比如`ISettings`的例子？**控制反转**（**IoC**）是一种设计模式，旨在补充依赖注入并解决这个问题。基本原则是，在应用程序中创建的许多对象都由一个单独的类来管理和创建。在应用程序中，不是使用标准的 C#构造函数来创建你的`ViewModel`或`Model`类，而是由服务定位器或工厂类来管理它们。

IoC 有许多不同的实现和风格，所以让我们实现一个简单的服务定位器类，以供本书的其余部分使用，如下所示：

```kt
public static class ServiceContainer 
{ 
  static readonly Dictionary<Type, Lazy<object>> services = 
    new Dictionary<Type, Lazy<object>>(); 

  public static void Register<T>(Func<T> function) 
  { 
    services[typeof(T)] = new Lazy<object>(() => function()); 
  } 

  public static T Resolve<T>() 
  { 
    return (T)Resolve(typeof(T)); 
  } 

  public static object Resolve(Type type) 
  { 
    Lazy<object> service; 
    if (services.TryGetValue(type, out service)) 
    { 
      return service.Value; 
    } 
    throw new Exception("Service not found!"); 
  } 
} 

```

这个类受到 XNA/MonoGame 的`GameServiceContainer`类的简单性的启发，并遵循**服务定位器**模式。主要区别在于使用泛型和它是一个静态类。

要使用我们的`ServiceContainer`类，我们只需通过调用`Register`声明应用中要使用的`ISettings`或其他接口的版本，如下面的代码所示：

```kt
//iOS version of ISettings 
ServiceContainer.Register<ISettings>(() =>
   new AppleSettings()); 

//Android version of ISettings 
ServiceContainer.Register<ISettings>(() => 
   new DroidSettings(this)); 

//You can even register ViewModels 
ServiceContainer.Register<SettingsViewModel>(() => 
   new SettingsViewModel()); 

```

在 iOS 上，您可以将此注册代码放在`static void Main()`方法中，或者放在`AppDelegate`类的`FinishedLaunching`方法中。这些方法总是在应用程序启动之前调用。

在 Android 上，情况稍微复杂一些。您不能将此代码放在作为主启动器的活动的`OnCreate`方法中。在某些情况下，Android OS 可能会关闭您的应用程序，但稍后会在另一个活动中重新启动它。这种情况会导致您的应用程序崩溃，因为它会尝试访问尚未注册的容器中的服务。将此代码放在自定义的 Android `Application`类中是安全的，该类有一个在应用程序中任何活动创建之前调用的`OnCreate`方法。下面的代码展示了`Application`类的使用：

```kt
[Application] 
public class Application : Android.App.Application 
{ 
  //This constructor is required 
  public Application(IntPtr javaReference, JniHandleOwnership
      transfer): base(javaReference, transfer) 
  { 

  } 

  public override void OnCreate() 
  { 
    base.OnCreate(); 

    //IoC Registration here 
  } 
} 

```

要从`ServiceContainer`类中获取服务，我们可以重写`SettingsViewModel`类的构造函数，如下面的代码所示：

```kt
public SettingsViewModel() 
{ 
  this.settings = ServiceContainer.Resolve<ISettings>(); 
} 

```

同样，您可以使用泛型`Resolve`方法从 iOS 上的控制器或 Android 上的活动中调用任何需要的`ViewModel`类。这是管理应用程序内部依赖关系的很好且简单的方法。

当然，有一些优秀的开源库实现了 C#应用程序的 IoC。如果您需要更高级的服务定位功能，或者只是想过渡到一个更复杂的 IoC 容器，您可以考虑切换到其中之一。

这里有一些与 Xamarin 项目一起使用的库：

+   **TinyIoC**：[`github.com/grumpydev/TinyIoC`](https://github.com/grumpydev/TinyIoC)

+   **Ninject**：[`www.ninject.org/`](http://www.ninject.org/)

+   **MvvmCross**：[`github.com/MvvmCross/MvvmCross`](https://github.com/MvvmCross/MvvmCross) 包括完整的 MVVM 框架以及 IoC。

+   **Autofac**：[`autofac.org`](https://autofac.org)

# 概要

在本章中，我们了解了 MVVM 设计模式以及如何使用它来更好地构建跨平台应用程序。我们比较了管理包含 iOS 和 Android 项目的 Xamarin Studio 解决方案的几种项目组织策略。我们讨论了可移植类库作为共享代码的首选选项，以及如何使用预处理器语句作为实现平台特定代码的快速而简单的方法。

完成本章节后，你应该已经掌握了使用 Xamarin Studio 在 iOS 和 Android 应用之间共享代码的几种技术。采用 MVVM 设计模式可以帮助你区分共享代码和特定平台的代码。我们还介绍了设置跨平台 Xamarin 解决方案的几种选项。你也应该牢固掌握使用依赖注入和控制反转技术，使共享代码能够访问每个平台的本地 API。在下一章节中，我们将开始编写跨平台应用程序，并深入探讨这些技术的使用。


# 第四章：XamSnap - 一个跨平台应用

在我看来，真正学会一项编程技能的最佳方式是接受一个需要运用该技能的简单项目。这给新开发者提供了一个可以专注于他们试图学习的概念的项目，而无需处理修复错误或遵循客户需求的负担。为了加深我们对 Xamarin 和跨平台开发的理解，让我们为 iOS 和 Android 开发一个名为 XamSnap 的简单应用。

在本章中，我们将涵盖以下主题：

+   我们的示例应用概念

+   我们应用的模型层

+   模拟网络服务

+   我们应用的 ViewModel 层

+   编写单元测试

# 启动我们的示例应用概念

这个概念很简单：流行的聊天应用 Snapchat 的一个简单克隆。由于短信成本和诸如 iPod Touch 或 iPad 等设备的支持，Apple App Store 中有几个这样的流行应用。这应该是一个对用户可能有用且涵盖为 iOS 和 Android 开发应用的具体主题的实用现实示例。

在开始开发之前，让我们列出我们需要的一组界面：

+   **登录/注册**：这个界面将包括用户的标准化登录和注册过程。

+   **对话列表**：这个界面将包括一个启动新对话的按钮。

+   **好友列表**：这个界面将提供一种在开始新对话时添加新好友的方法。

+   **对话**：这个界面将展示你与其他用户之间的消息列表，并提供回复选项。

+   **相机**：除了文本消息，Snapchat 还具有发送照片的功能。我们将添加使用设备相机或照片库发送照片的选项。

因此，一个快速的应用程序线框布局可以帮助我们更好地理解应用程序的布局。下图展示了应用中应包含的一组屏幕：

![启动我们的示例应用概念](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00211.jpeg)

# 开发我们的模型层

既然我们已经对应用有了很好的了解，下一步就是开发这个应用的商业对象或模型层。让我们首先定义几个类，这些类将包含整个应用中使用的数据。为了组织方便，建议将这些类添加到项目中的 `Models` 文件夹中。

让我们从表示用户的类开始。该类可以按以下方式创建：

```kt
public class User 
{ 
  //NOTE: we will treat this as a unique name 
  public string Name { get; set; } 

  //NOTE: we'll try to use this in a secure way 
  public string Password { get; set; } 
} 

```

到目前为止非常直观；接下来，我们按照以下方式创建表示对话和消息的类：

```kt
public class Conversation 
{ 
  public string Id { get; set; } 

  public string UserName { get; set; } 
} 

public class Message 
{ 
  public string Id { get; set; } 

  //NOTE: the Id of a Conversation 
  public string Conversation { get; set; }  

  public string UserName { get; set; } 

  public string Text { get; set; }

//NOTE: some messages will include photos 
  public string Image { get; set; } 
} 

```

请注意，我们将字符串用作各种对象的标识符；这将简化我们与在后续章节中作为 Azure Function 运行的后端的集成。`UserName` 是应用程序设置的值，用于更改与对象关联的用户。

现在让我们继续执行以下步骤来设置我们的解决方案：

1.  从创建一个新的解决方案开始，作为 iOS 和 Android 的**多平台 | 应用 | 单视图应用**项目。

1.  将项目命名为`XamSnap`，并确保已选择**使用可移植类库**。

1.  你也可以选择为这个项目使用**共享项目**，但我更倾向于使用可移植类库。

1.  点击**创建**，在指定目录中创建你的解决方案。

### 提示

与前面的章节一样，Visual Studio 的步骤略有不同。你需要创建一个作为可移植类库的解决方案，并*然后*添加 iOS 和 Android 项目。不要忘记在 iOS 和 Android 项目中都添加对 PCL 的引用。

# 编写模拟网络服务。

在开发移动应用时，你可能需要在真正的后端网络服务可用之前就开始开发你的应用。为了防止开发完全停滞，一个好的方法可能是开发一个服务的模拟版本。这在需要编写单元测试，或者等待另一个团队为你的应用开发后端时也很有帮助。

首先，让我们分解一下我们的应用将对网络服务器执行的操作。操作如下：

1.  使用用户名和密码登录。

1.  注册一个新账户。

1.  获取用户的朋友列表。

1.  通过他们的用户名添加朋友。

1.  获取用户的现有会话列表。

1.  获取会话中的消息列表。

1.  发送消息。

现在让我们定义一个接口，为每个场景提供一个方法。方法如下：

```kt
public interface IWebService 
{ 
  Task<User> Login(string userName, string password); 

  Task<User> Register(User user); 

  Task<User[]> GetFriends(string userName); 

  Task<User> AddFriend(string username, string friendName); 

  Task<Conversation[]> GetConversations(string userName); 

  Task<Message[]> GetMessages(string conversation); 

  Task<Message> SendMessage(Message message); 
} 

```

如你所见，我们通过利用.NET 基类库中的**TPL**（**任务并行库**）简化了与网络服务的任何异步通信。

由于与网络服务通信可能是一个漫长的过程，因此使用`Task<T>`类进行这些操作总是一个好主意。否则，你可能无意中在用户界面线程上运行一个耗时的任务，这将导致在操作期间无法接收用户输入。对于网络请求来说，`Task`绝对是必需的，因为用户可能正在 iOS 和 Android 上使用蜂窝网络连接，这将使我们能够以后使用`async`和`await`关键字。

### 提示

如果你不太熟悉 C#中用于简化异步编程的 async/await，查看 MSDN 上的相关主题会很有帮助：[`msdn.microsoft.com/en-us/library/mt674882.aspx`](https://msdn.microsoft.com/en-us/library/mt674882.aspx)

现在让我们实现一个实现了此接口的**伪**服务。将如`FakeWebService`这样的类放在项目的`Fakes`文件夹中。让我们从类声明和接口的第一个方法开始：

```kt
public class FakeWebService : IWebService
{
  public int SleepDuration { get; set; }

  public FakeWebService()
  {
    SleepDuration = 1000;
  }

  private Task Sleep()
  {
    return Task.Delay(SleepDuration);
  }

  public async Task<User> Login(string userName, string password)
  {
    await Sleep(); 
    return new User { Name = userName }; 
  }
}

```

我们从一个名为`SleepDuration`的属性开始，用于存储毫秒数。这用于模拟与 Web 服务器的交互，这可能需要一些时间。在不同情况下更改`SleepDuration`值也很有用。例如，在编写单元测试时，你可能希望将此值设置得较小，以便测试快速执行。

接下来，我们实现了一个简单的`Sleep`方法，该方法返回一个引入了若干毫秒延迟的任务。这个方法将在伪服务中用于在每个操作上造成延迟。

最后，`Login`方法只是在`Sleep`方法上使用了`await`调用，并返回了一个具有适当`Name`的新`User`对象。目前，任何用户名或密码组合都可以使用；但是，你可能希望在这里编写一些代码来检查特定的凭据。

现在，让我们按照以下方式继续实现`FakeWebService`类的几个更多方法：

```kt
public async Task<User[]> GetFriends(string userId)
{
  await Sleep();
  return new[] 
  { 
    new User { Name = "bobama" }, 
    new User { Name = "bobloblaw" }, 
    new User { Name = "georgemichael" }, 
  };
}

public async Task<User> AddFriend(
  string username, string friendName)
{
  await Sleep(); 
  return new User { Name = friendName };
}

```

对于这些方法中的每一个，我们都遵循了与`Login`方法完全相同的模式。每个方法都将延迟并返回一些示例数据。请随意用你自己的值混合这些数据。

现在，让我们按照以下方式实现接口所需的`GetConversations`方法：

```kt
public async Task<Conversation[]> GetConversations(
  string userName)
{
  await Sleep();
  return new[] 
  { 
    new Conversation { Id = "1", UserName = "bobama" },
    new Conversation { Id = "2", UserName = "bobloblaw" }, 
    new Conversation { Id = "3", UserName = "georgemichael" }, 
  };
}

```

基本上，我们只是创建了一个新的`Conversation`对象数组，这些对象的 ID 是任意的。我们还确保将`UserName`值与我们到目前为止在`User`对象上使用的值相匹配。

接下来，让我们按照以下方式实现`GetMessages`以获取消息列表：

```kt
public async Task<Message[]> GetMessages(string conversation) 
{ 
  await Sleep(); 

  return new[] 
  { 
    new Message 
    { 
      Id = "1", 
      Conversation = conversation, 
      UserName = "bobloblaw", 
      Text = "Hey", 
    }, 
    new Message 
    { 
      Id = "2", 
      Conversation = conversation, 
      UserName = "georgemichael", 
      Text = "What's Up?", 
    }, 
    new Message 
    { 
      Id = "3", 
      Conversation = conversation, 
      UserName = "bobloblaw", 
      Text = "Have you seen that new movie?", 
    }, 
    new Message 
    { 
      Id = "4", 
      Conversation = conversation, 
      UserName = "georgemichael", 
      Text = "It's great!", 
    }, 
  }; 
} 

```

再次，我们在这里添加了一些任意数据，主要确保`UserId`和`ConversationId`与我们到目前为止的现有数据相匹配。

最后，我们将再编写一个如下所示发送消息的方法：

```kt
public async Task<Message> SendMessage(Message message) 
{ 
  await Sleep(); 

  return message; 
} 

```

这些方法中的大多数都非常直接。请注意，服务不必完美无缺；它应该只是在延迟后成功地完成每个操作。每个方法还应返回某种测试数据以在 UI 中显示。这将使我们能够在填充 Web 服务的同时实现我们的 iOS 和 Android 应用程序。

接下来，我们需要为持久化应用程序设置实现一个简单的接口。让我们按照以下方式定义一个名为`ISettings`的接口：

```kt
public interface ISettings 
{ 
  User User { get; set; } 

  void Save(); 
} 

```

我们正在使`ISettings`同步，但如果你计划将设置存储在云端，你可能想要将`Save`方法设置为异步并返回`Task`。由于我们的应用程序只会在本地保存设置，所以实际上我们并不需要这样做。

稍后，我们将在每个平台上使用 Android 和 iOS API 实现此接口。现在，让我们仅实现一个伪版本，稍后在编写单元测试时使用。使用以下代码行实现接口：

```kt
public class FakeSettings : ISettings 
{ 
  public User User { get; set; } 

  public void Save() { } 
} 

```

请注意，伪版本实际上不需要执行任何操作；我们只需要提供一个实现接口的类，并且不抛出任何意外的错误。

这完成了应用程序的模型层。以下是我们到目前为止实现的最终类图：

![编写一个模拟网络服务](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00212.jpeg)

# 编写 ViewModel 层

既然我们已经实现了模型层，现在可以继续编写 ViewModel 层了。ViewModel 负责将每个操作呈现给 UI，并提供由视图层填充的属性。这一层的其他常见职责包括输入验证和显示忙碌指示器的简单逻辑。

在此阶段，将上一章中的`ServiceContainer`类包含到我们的`XamSnap` PCL 项目中会是一个好主意，因为我们将会通过 ViewModels 与模型层交互时使用它。我们将用它作为一个简单的选项来支持依赖注入和控制反转；然而，你也可以选择你偏好的另一个库来实现这一点。

通常，我们首先为项目中所有 ViewModel 层编写一个基类。这是一个放置所有子类使用的代码部分的好地方，例如：通知变更、方法或常用的接口。

在项目中的新`ViewModels`文件夹中放置以下代码片段：

```kt
public class BaseViewModel 
{ 
  protected readonly IWebService service = 
     ServiceContainer.Resolve<IWebService>(); 
  protected readonly ISettings settings = 
     ServiceContainer.Resolve<ISettings>(); 

  public event EventHandler IsBusyChanged = (sender, e) => { }; 

  private bool isBusy = false; 

  public bool IsBusy 
  { 
    get { return isBusy; } 
    set 
    { 
      isBusy = value; 
      IsBusyChanged(this, EventArgs.Empty); 
    } 
  } 
} 

```

`BaseViewModel`类是放置你打算在应用程序中重复使用的任何公共功能的好地方。对于这个应用，我们只需要实现一种方法来指示 ViewModel 层是否忙碌。我们提供了一个属性和一个事件，UI 将能够订阅并在屏幕上显示等待指示器。我们还添加了一些需要的服务字段。另一个可能添加的常见功能是对用户输入的验证；然而，这个应用程序并不真正需要它。

## 实现我们的 LoginViewModel 类

既然我们已经为所有的 ViewModel 层创建了一个基类，我们可以实现应用程序第一个屏幕的 ViewModel，即**登录**屏幕。

现在我们按照以下方式实现一个`LoginViewModel`类：

```kt
public class LoginViewModel : BaseViewModel 
{ 
  public string UserName { get; set; } 

  public string Password { get; set; } 

  public async Task Login() 
  { 
    if (string.IsNullOrEmpty(UserName)) 
      throw new Exception("Username is blank."); 

    if (string.IsNullOrEmpty(Password)) 
      throw new Exception("Password is blank."); 

    IsBusy = true; 
    try 
    { 
      settings.User = await service.Login(UserName, Password); 
      settings.Save(); 
    } 
    finally 
    { 
      IsBusy = false; 
    } 
  } 
} 

```

在这个类中，我们实现了以下功能：

+   我们继承了`BaseViewModel`，以获取`IsBusy`和包含公共服务的字段

+   我们添加了`UserName`和`Password`属性，由视图层设置

+   我们添加了一个`User`属性，以在登录过程完成后设置

+   我们实现了一个从视图调用的`Login`方法，对`UserName`和`Password`属性进行验证

+   我们在调用`IWebService`上的`Login`方法期间设置`IsBusy`

+   我们通过等待网络服务的`Login`方法的结果来设置`User`属性

基本上，这是我们将在应用程序的其余 ViewModel 中遵循的模式。我们为视图层提供由用户输入设置的属性，以及调用各种操作的方法。如果这是一个可能需要一些时间的方法，比如网络请求，你应当始终返回`Task`，并使用`async`和`await`关键字。

### 提示

请注意，我们使用了`try`和`finally`块来将`IsBusy`设置回`false`。这将确保即使在抛出异常时也能正确重置。我们计划在 View 层处理错误，这样我们就可以向用户显示本地弹窗，并显示一条消息。

## 实现我们的 RegisterViewModel 类

既然我们已经完成了用于登录的`ViewModel`类的编写，我们现在需要创建一个用于用户注册的类。

让我们实现另一个 ViewModel 来注册新用户：

```kt
public class RegisterViewModel : BaseViewModel 
{ 
  public string UserName { get; set; } 

  public string Password { get; set; } 

  public string ConfirmPassword { get; set; } 
} 

```

这些属性将处理用户的输入。接下来，我们需要按照以下方式添加一个`Register`方法：

```kt
public async Task Register() 
{ 
  if (string.IsNullOrEmpty(UserName)) 
    throw new Exception("Username is blank."); 

  if (string.IsNullOrEmpty(Password)) 
    throw new Exception("Password is blank."); 

  if (Password != ConfirmPassword) 
    throw new Exception("Passwords do not match."); 

  IsBusy = true; 
  try 
  { 
    settings.User = await service.Register(new User  
    {  
      Name = UserName, 
      Password = Password,  
    }); 
    settings.Save(); 
  } 
  finally 
  { 
    IsBusy = false; 
  } 
} 

```

`RegisterViewModel`类与`LoginViewModel`类非常相似，但它增加了一个`ConfirmPassword`属性，以便 UI 设置。关于何时拆分 ViewModel 层的功能，一个好的规则是：当 UI 有新屏幕时，始终创建一个新类。这有助于保持代码整洁，并在一定程度上遵循类的**单一职责原则（SRP）**。**SRP**指出，一个类应该只有一个目的或责任。我们将尝试遵循这一概念，使我们的类保持小而有序，这在跨平台共享代码时尤为重要。

## 实现我们的 FriendViewModel 类

接下来是处理用户朋友列表的 ViewModel 层。我们需要一个方法来加载用户的朋友列表并添加新朋友。

现在我们按照以下方式实现`FriendViewModel`：

```kt
public class FriendViewModel : BaseViewModel 
{ 
  public User[] Friends { get; private set; } 

  public string UserName { get; set; } 
} 

```

现在我们需要一种加载朋友列表的方法。该方法如下：

```kt
public async Task GetFriends() 
{ 
  if (settings.User == null) 
    throw new Exception("Not logged in."); 

  IsBusy = true; 
  try 
  { 
    Friends = await service.GetFriends(settings.User.Name); 
  } 
  finally 
  { 
    IsBusy = false; 
  } 
} 

```

最后，我们需要一个添加新朋友并更新本地朋友列表的方法：

```kt
public async Task AddFriend()
{
  if (settings.User == null)
    throw new Exception("Not logged in.");
  if (string.IsNullOrEmpty(UserName))
    throw new Exception("Username is blank.");
  IsBusy = true; 

  try 
  { 
    var friend = await service
      .AddFriend(settings.User.Name, UserName); 
    //Update our local list of friends 
    var friends = new List<User>(); 
    if (Friends != null)
      friends.AddRange(Friends); 
    friends.Add(friend); 
    Friends =  friends.OrderBy(f => f.Name).ToArray(); 
  } 
  finally 
  { 
    IsBusy =  false; 
  }
}

```

同样，这个类相当直接。这里唯一的新东西是，我们添加了一些逻辑，在客户端应用程序中更新朋友列表并对其进行排序，而不是在服务器上。如果你有充足的理由，也可以选择重新加载整个朋友列表。

## 实现我们的 MessageViewModel 类

我们最终需要的 ViewModel 层将处理消息和对话。我们需要创建一种加载对话和消息的方法，并发送新消息。

让我们开始按照以下方式实现我们的`MessageViewModel`类：

```kt
public class MessageViewModel : BaseViewModel 
{ 
  public Conversation[] Conversations { get; private set; } 

  public Conversation Conversation { get; set; } 

  public Message[] Messages { get; private set; } 

  public string Text { get; set; } 
} 

```

接下来，让我们按照以下方式实现获取对话列表的方法：

```kt
public async Task GetConversations() 
{ 
  if (settings.User == null) 
    throw new Exception("Not logged in."); 

  IsBusy = true; 
  try 
  { 
    Conversations = await service
       .GetConversations(settings.User.Name); 
  } 
  finally 
  { 
    IsBusy = false; 
  } 
} 

```

同样，我们需要获取对话中的消息列表。我们需要将对话 ID 传递给服务，如下所示：

```kt
public async Task GetMessages() 
{ 
  if (Conversation == null) 
    throw new Exception("No conversation."); 

  IsBusy = true; 
  try 
  { 
    Messages = await service
       .GetMessages(Conversation.Id); 
  } 
  finally 
  { 
    IsBusy = false; 
  } 
} 

```

最后，我们需要编写一些代码来发送消息并更新本地消息列表，如下所示：

```kt
public async Task SendMessage() 
{ 
  if (settings.User == null) 
    throw new Exception("Not logged in."); 

  if (Conversation == null) 
    throw new Exception("No conversation."); 

  if (string.IsNullOrEmpty (Text)) 
    throw new Exception("Message is blank."); 

  IsBusy = true; 
  try 
  { 
    var message = await service.SendMessage(new Message  
    {  
        UserName = settings.User.Name,
         Conversation = Conversation.Id, 
        Text = Text 
    }); 

    //Update our local list of messages 
    var messages = new List<Message>(); 
    if (Messages != null) 
      messages.AddRange(Messages); 
    messages.Add(message); 

    Messages = messages.ToArray(); 
  } 
  finally 
  {
    IsBusy = false; 
  } 
} 

```

这结束了我们应用程序的 ViewModel 层以及 iOS 和 Android 上使用的所有共享代码。对于`MessageViewModel`类，你也可以选择将`GetConversations`和`Conversations`属性放在它们自己的类中，因为它们可以被认为是一个单独的责任，但这并不是绝对必要的。

这是我们的 ViewModel 层的最终类图：

![实现我们的 MessageViewModel 类](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00213.jpeg)

# 编写单元测试

由于我们迄今为止编写的所有代码都不依赖于用户界面，我们可以轻松地针对我们的类编写单元测试。这一步通常在`ViewModel`类的首次实现之后进行。**测试驱动开发**（**TDD**）的倡导者会建议先编写测试，然后再实现功能，所以选择最适合你的方法。无论如何，在从视图层开始使用它们之前，针对共享代码编写测试是一个好主意，这样你可以在它们阻碍 UI 开发之前捕捉到错误。

Xamarin 项目利用了一个名为**NUnit**的开源测试框架。它最初源自一个名为**JUnit**的 Java 测试框架，是进行 C#应用程序单元测试的事实标准。Xamarin Studio 提供了几个使用**NUnit**编写测试的项目模板。

## 设置一个用于单元测试的新项目

让我们通过执行以下步骤为单元测试设置一个新项目：

1.  在 Xamarin Studio 的**其他 | .Net**部分，向你的解决方案中添加一个新的**NUnit 库**项目。如果使用 Visual Studio，则创建一个.NET 类库并添加 NUnit NuGet 包。

1.  将项目命名为`XamSnap.Tests`以保持一致性。

1.  在项目引用上右键点击，选择**编辑引用**。

1.  在**项目**选项卡下，向**XamSnap**添加一个引用，这是你现有的可移植类库。

1.  现在，打开`Test.cs`文件，注意以下构成使用 NUnit 单元测试的必要属性：

+   `using NUnit.Framework`：这个属性是使用 NUnit 时要使用的主要语句。

+   `[TestFixture]`：这个属性装饰一个类，表示该类有一系列用于运行测试的方法。

+   `[Test]`：这个属性装饰一个方法，表示这是一个测试。

除了必要的 C#属性之外，还有其他几个在编写测试时很有用的属性，如下所示：

+   `[TestFixtureSetUp]`：这个属性装饰一个方法，该方法在测试固件类中包含的所有测试之前运行。

+   `[SetUp]`：这个属性装饰一个方法，该方法在测试固件类中的每个测试前运行。

+   `[TearDown]`：这个属性装饰一个方法，该方法在测试固件类中的每个测试后运行。

+   `[TestFixtureTearDown]`：这个属性装饰一个方法，该方法在测试固件类中的所有测试完成后运行。

+   `[ExpectedException]`：这个属性装饰一个预期会抛出异常的方法。它用于测试那些应该失败的用例。

+   `[Category]`：这个属性装饰一个测试方法，可以用来组织不同的测试；例如，你可能将快速测试和慢速测试进行分类。

## 编写断言

下一个要学习的概念是使用 NUnit 编写测试时如何编写**断言**。断言是一个方法，如果某个值不是真的，它将抛出一个异常。这将导致测试失败，并给出发生情况的描述性解释。NUnit 有几组不同的断言 API；然而，我们将使用更易读、更流畅的 API 版本。

流畅风格 API 的基本语法是使用 `Assert.That` 方法。以下示例展示了这一点：

```kt
Assert.That(myVariable, Is.EqualTo(0)); 

```

同样，你可以断言相反的情况：

```kt
Assert.That(myVariable, Is.Not.EqualTo(0)); 

```

或者以下任意一项：

+   `Assert.That(myVariable, Is.GreaterThan(0));`

+   `Assert.That(myBooleanVariable, Is.True);`

+   `Assert.That(myObject, Is.Not.Null);`

自由探索 APIs。在 Xamarin Studio 中，有了代码补全功能，你应该能够发现 `Is` 类中有用的静态成员或方法，以便在测试中使用。

在为我们应用程序编写特定的测试之前，让我们编写一个静态类和方法，以创建在整个测试中使用的全局设置；你可以将 `Test.cs` 重写如下：

```kt
public class BaseTest 
{ 
  [SetUp] 
  public virtual void SetUp() 
  { 
    ServiceContainer.Register<IWebService>(() =>
       new FakeWebService { SleepDuration = 0 }); 
    ServiceContainer.Register<ISettings>(() =>
       new FakeSettings()); 
  } 
} 

```

我们将在测试中使用此方法来设置模型层中的假服务。此外，这会替换现有的服务，以便我们的测试针对这些类的新实例执行。这是单元测试中的一个好习惯，以确保之前的测试没有留下旧数据。还要注意，我们将 `SleepDuration` 设置为 `0`。这将使我们的测试运行得非常快。

首先，在测试项目中创建一个名为 `ViewModels` 的文件夹，并添加一个名为 `LoginViewModelTests` 的类，如下所示：

```kt
[TestFixture] 
public class LoginViewModelTests : BaseTest 
{ 
  LoginViewModel loginViewModel; 
  ISettings settings; 

  [SetUp] 
  public override void SetUp() 
  { 
    base.SetUp(); 

    settings = ServiceContainer.Resolve<ISettings>(); 
    loginViewModel = new LoginViewModel(); 
  } 

  [Test] 
  public async Task LoginSuccessfully() 
  { 
    loginViewModel.UserName = "testuser"; 
    loginViewModel.Password = "password"; 

    await loginViewModel.Login(); 

    Assert.That(settings.User, Is.Not.Null); 
  } 
} 

```

注意我们使用了 `SetUp` 方法。我们重新创建每个测试中使用的对象，以确保之前的测试运行没有留下旧数据。另一点需要注意的是，当在测试方法中使用 `async`/`await` 时，你必须返回一个 `Task`。否则，NUnit 将无法知道测试何时完成。

要运行测试，请使用默认停靠在 Xamarin Studio 右侧的 NUnit 菜单。使用带有齿轮图标的**运行测试**按钮来运行测试；你应该会得到一个类似以下截图所示的成功结果：

![编写断言](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00214.jpeg)

你还可以查看**测试结果**窗格，如果测试失败，它会显示扩展的详细信息；如下面的截图所示：

![编写断言](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00215.jpeg)

### 提示

如果使用 Visual Studio，你将需要从 Visual Studio 库安装 **NUnit 测试适配器** 扩展。你可以在 **工具 | 扩展和更新** 菜单下找到此选项。Visual Studio 中的单元测试运行器与 Xamarin Studio 一样直观；然而，它默认只支持 MsTest。

要查看测试失败时会发生什么，请继续修改你的测试，按照以下方式针对错误值进行断言：

```kt
//Change Is.Not.Null to Is.Null 
Assert.That(settings.User, Is.Null); 

```

你会在**测试结果**窗格中得到一个非常详细的错误，如下面的截图所示：

![编写断言](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/xmr-4x-xplat-app-dev/img/image00216.jpeg)

现在我们为`LoginViewModel`类实现另一个测试；确保如果用户名和密码为空，我们能得到适当的结果。测试实现如下：

```kt
[Test] 
public async Task LoginWithNoUsernameOrPassword() 
{ 
  //Throws an exception 
  await loginViewModel.Login(); 
} 

```

如果我们按原样运行测试，将会捕获到一个异常，测试将失败。由于我们预期会发生异常，我们可以通过以下方式装饰该方法，使得只有当异常发生时测试才能通过：

```kt
[Test,  
  ExpectedException(typeof(Exception),  
  ExpectedMessage = "Username is blank.")] 

```

### 提示

请注意，在我们的视图模型中，如果**字段为空**，则会抛出一个通用的`Exception`类型异常。在预期异常类型不同的情况下，你也可以更改预期异常的类型。

随书附带的示例代码中包含了更多测试。建议针对每个`ViewModel`类上的每个公共操作编写测试。此外，针对任何验证或其他重要的业务逻辑编写测试。我还建议针对模型层编写测试；然而，在我们的项目中还不需要，因为我们只有假的实现。

# 总结

在本章中，我们概述了一个示例应用程序的概念，这个应用程序将在整本书中构建，名为 XamSnap。我们还为应用程序在模型层实现了核心业务对象。由于我们还没有服务器来支持这个应用程序，我们实现了一个假的网络服务。这使得我们可以在不构建服务器应用程序的情况下继续开发应用程序。我们还实现了视图模型层。这一层将向视图层以简单的方式暴露操作。最后，我们使用 NUnit 编写了覆盖我们至今为止编写的代码的测试。在跨平台应用程序中对共享代码编写测试可能非常重要，因为它是多个应用程序的支柱。

在完成本章之后，你应该已经完整地完成了我们跨平台应用程序的共享库。你应该对应用程序的架构以及其独特的模型层和视图模型层有一个非常牢固的理解。你还应该了解如何编写应用程序部分可能还未能实现的假的版本。在下一章中，我们将实现 XamSnap 的 iOS 版本。
