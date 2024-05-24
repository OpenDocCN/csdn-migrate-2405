# Android Studio 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/4884403F3172F01088859FB8C5497CF5`](https://zh.annas-archive.org/md5/4884403F3172F01088859FB8C5497CF5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Android Studio 是开发 Android 应用程序的最佳 IDE，任何想要开发专业 Android 应用程序的人都可以免费使用。

现在有了 Android Studio，我们有了一个稳定和更快的 IDE，它带来了很多很酷的东西，比如 Gradle、更好的重构方法和更好的布局编辑器。如果您曾经使用过 Eclipse，那么您一定会喜欢这个 IDE。

简而言之，Android Studio 真的带回了移动开发的乐趣，在这本书中，我们将看到如何做到这一点。

# 本书涵盖的内容

第一章，欢迎来到 Android Studio，演示了如何配置 Android Studio 和 Genymotion，这是一个非常快速的模拟器。

第二章，具有基于云的后端的应用程序，解释了如何使用 Parse 在很短的时间内开发使用基于云的后端的应用程序。

第三章，Material Design，解释了材料设计的概念以及如何使用 RecycleViews、CardViews 和过渡来实现它。

第四章，Android Wear，涵盖了 Android Wear API 以及如何开发自己的手表表盘或其他在智能手表上运行的应用程序。

第五章，Size Does Matter，演示了如何使用片段和其他资源来帮助您创建能够在手机、平板电脑、平板电脑甚至电视上运行的应用程序。我们将即时连接到 YouTube API，使示例更有趣。

第六章，Capture and Share，是关于使用新的 Camera2 API 捕获和预览图像的深入教程。它还告诉您如何在 Facebook 上分享捕获的图像。

第七章，内容提供程序和观察者，解释了如何从使用内容提供程序来显示和观察持久数据中受益。

第八章，Improving Quality，详细介绍了应用模式、单元测试和代码分析工具。

第九章，Improving Performance，介绍了如何使用设备监视器来优化应用程序的内存管理，以及如何使用手机上的开发者选项来检测过度绘制和其他性能问题。

第十章，Beta Testing Your Apps，指导您完成一些最后步骤，例如使用构建变体（类型和风味）和在 Google Play 商店上进行测试版分发。除此之外，它还涵盖了 Android Marshmallow（6.0）提供的运行时权限与安装权限的不同之处。

# 您需要为本书准备什么

对于这本书，您需要下载并设置 Android Studio 和最新的 SDK。Android Studio 是免费的，适用于 Windows、OSX 和 Linux。

强烈建议至少拥有一部手机、平板电脑或平板电脑，但在第一章，欢迎来到 Android Studio 中，我们将向您介绍 Genymotion，一个非常快速的模拟器，在大多数情况下可以代替真实设备使用。

最后，对于一些示例，您需要拥有 Google 开发者帐户。如果您还没有，请尽快获取一个。毕竟，您需要一个才能将您的应用程序放入 Play 商店。

# 这本书是为谁准备的

这本书适合任何已经熟悉 Java 语法并可能已经开发了一些 Android 应用程序的人，例如使用 Eclipse IDE。

这本书特别解释了使用 Android Studio 进行 Android 开发的概念。为了演示这些概念，提供了真实世界的示例。而且，通过真实世界的应用程序，我指的是连接到后端并与 Google Play 服务或 Facebook 等进行通信的应用程序。

# 部分

在本书中，您会经常看到几个标题（准备工作、如何做、它是如何工作的、还有更多和另请参阅）。

为了清晰地说明如何完成食谱，我们使用以下这些部分：

## 准备工作

本节告诉您在食谱中可以期待什么，并描述如何设置所需的任何软件或任何预备设置。

## 如何做…

本节包含了遵循食谱所需的步骤。

## 它是如何工作的…

本节通常包括对前一节发生的事情的详细解释。

## 还有更多…

本节包括有关食谱的额外信息，以使读者更加了解食谱。

## 另请参阅

本节提供了有关食谱的其他有用信息的有用链接。

# 约定

所有针对 Android Studio 的屏幕截图、快捷方式和其他元素都基于 OSX 上的 Android Studio。

OSX 被使用的主要原因是因为它允许我们在同一台机器上为 Android 和 iOS 开发应用程序。除此之外，选择特定操作系统的原因除了个人（或公司）的偏好之外没有其他原因。

虽然屏幕截图是基于 OSX 上的 Android Studio，但如果您的操作系统是 Windows 或 Linux，您也不难弄清楚事情。

在需要时，还会提及 Windows 的快捷键。

在本书中，您会发现一些区分不同类型信息的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄都会以这种方式显示："我们可以通过使用 include 指令包含其他上下文"。

代码块设置如下：

```kt
public void onSectionAttached(int number) {
    switch (number) {
        case 0:
            mTitle = getString(  
             R.string.title_section_daily_notes);
            break;

        case 1:
            mTitle = getString( 
             R.string.title_section_note_list);
             break;
    }
}
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的菜单或对话框中的单词会以这种方式出现在文本中："单击**下一步**按钮将您移至下一个屏幕"。

### 注

警告或重要提示会以这种方式显示在一个框中。

### 提示

技巧和窍门会以这种方式出现。


# 第一章：欢迎来到 Android Studio

在本章中，我们将涵盖与 Android Studio 相关的一些基本任务。在阅读本章和其他章节时，您将学习如何有效地使用 Android Studio。

在本章中，您将学习以下配方：

+   创建您的第一个名为`Hello Android Studio`的应用程序。

+   使用 Gradle 构建脚本

+   使用名为 Genymotion 的模拟器测试您的应用程序

+   重构您的代码

# 介绍

本章是对 Android Studio 的介绍，并提供了这个**集成开发环境（IDE）**所配备的不同工具的概览。除此之外，还将在这里讨论一些其他重要的工具，比如 Genymotion，我强烈建议您使用它来测试您的应用在不同类型的设备上。

使用 Android Studio，您可以创建任何您喜欢的应用程序。手机应用程序、平板电脑应用程序、手表和其他可穿戴设备应用程序、谷歌眼镜、电视应用程序，甚至汽车应用程序。

如果您已经有移动编程经验，甚至以前使用过 Android 应用程序和 Eclipse，并且想要了解如何创建拍照、播放媒体、在任何设备上工作、连接到云端或者您能想到的其他任何功能的应用程序，那么这本书就适合您！

本书中描述的所有配方都是基于 Mac 上的 Android Studio；但是，如果您使用的是 Windows 或 Linux 上的 Android Studio，这一点完全没有问题。所有平台的术语都是相同的。只是每个配方提供的截图可能看起来有点不同，但我相信您可以通过一点努力找出来。如果 Windows 有任何重大差异，我会告诉您的。

## 为什么我们应该使用 Android Studio

Android Studio 是开发 Android 应用程序的推荐 IDE，对于任何开发专业 Android 应用程序的人来说都是免费的。Android Studio 基于 JetBrains IntelliJ IDEA 软件，这可能解释了为什么即使 Android Studio 的预览和测试版本都比 Eclipse 更好，以及为什么许多 Android 开发人员从一开始就使用它作为他们的 IDE。

Android Studio 的第一个稳定版本于 2014 年 12 月发布，取代了 Eclipse（带有 Android 开发工具）成为 Android 开发的主要 IDE。现在，有了 Android Studio，我们不仅拥有了一个更稳定和更快的 IDE，而且还有了一些很酷的东西，比如 Gradle、更好的重构方法和更好的布局编辑器，仅举几例。

好吧，我偶尔还是会遇到一些奇怪的问题（我想这就是作为移动开发人员有时会遇到的情况），但我肯定不会像在使用 Eclipse 时那样感到沮丧。如果您只是使用 Eclipse 进行普通的 Java 开发，我想那也还好；但是，它与 Android 不兼容。如果您以前在 Java 开发任务中使用过 IntelliJ IDEA，那么 Android Studio 对您来说会看起来非常熟悉。

Android Studio 真的让移动开发变得有趣起来。如果您目前正在使用 Eclipse，那么您应该立即切换到 Android Studio！要亲自看看，请从[`developer.android.com/sdk/index.html`](https://developer.android.com/sdk/index.html)获取它，并立即开始使用 Android Studio 构建酷炫的应用程序。

## 碎片化

留下的是 Android 开发中需要处理的碎片化挑战。有许多设备运行在许多 Android 版本和版本上。

有很多 Android 版本，导致了碎片化。因此，您不能期望所有设备都能运行在最新的 Android 版本上。事实上，大多数设备都没有。许多设备仍在运行 Android 4.x（甚至更旧的版本）。

在这里，您可以看到一个包含所有相关 Android 版本和分发数字的表格。这个表格中的数字表明，如果您决定支持 Android 4.0 及以后的版本，您将能够触及 88.7%的所有 Android 用户。在这个例子中，显示了 2015 年第二季度的数字，这解释了为什么**Android Marshmallow (6.0)**在这里没有列出。如果您在 Android Studio 中创建一个新项目，您可以通过在**创建新项目**向导对话框中点击**帮助我选择**链接来获取实际的数字，这将在接下来的章节中找出。

让我们来看一下下面的屏幕截图，描述了不同 Android 平台版本的累积分布以及它们的 API 级别：

![碎片化](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_01_05.jpg)

除了软件碎片化之外，还有许多硬件碎片化需要注意。编写 Android 应用程序并不难，但编写一个能够在任何 Android 设备上正常运行的应用程序确实很难。

一个好的应用程序应该能够在尽可能多的不同设备上运行。例如，想象一个拍照的应用程序。Android 设备可能有一个摄像头，多个摄像头，或者根本没有摄像头。根据您的应用程序提供的其他功能，您可能还需要担心其他事情，比如设备是否能够录制声音等。

我可以想象你想要触及尽可能多的受众，所以你应该始终问自己，你的应用功能需求中哪些是必须的，哪些是不必要的。如果设备没有摄像头，用户可能无法拍照，但这真的是不允许用户使用应用的理由吗？

在 Android Marshmallow (6.0)中引入运行时权限使您更加重视在应用程序中提供某种后备功能。至少您需要解释为什么某个特定功能在您的应用程序中不可用。例如，用户设备不支持它或用户没有为其授予权限。

这本书将帮助您处理 Android 碎片化和其他问题。

# 创建您的第一个名为 Hello Android Studio 的应用程序

下载 Android Studio 后，安装并按照设置向导进行操作。向导会检查一些要求，例如**Java 开发工具包**（JDK）是否可用，以及其他重要的元素，安装向导会引导您完成这些操作。

安装完成后，是时候使用 Android Studio 开发您的第一个 Android 应用程序了，只是为了检查一切是否已正确安装并且正常运行。这可能不会让人感到意外，这就是 Hello Android Studio 教程的用武之地。

## 准备就绪

要完成这个教程，你需要一个运行中的 Android Studio IDE，一个 Android 软件开发工具包（SDK）和一个 Android 设备。不需要其他先决条件。

## 如何做...

让我们使用 Android Studio 创建我们的第一个 Android 应用程序，以检查一切是否正常运行，以下是帮助的步骤：

1.  启动 Android Studio。几秒钟后，**欢迎使用 Android Studio**对话框将显示给您。

1.  选择**开始一个新的 Android Studio 项目**选项。然后，**配置您的新项目**对话框将出现。

1.  对于**应用程序名称**，输入`HelloAndroidStudio`；对于**公司域**字段，输入`packtpub.com`（或者如果您愿意，可以使用您自己公司的域名）。

1.  建议使用`packtpub.com`和`helloandroidstudio`等包名称，并在输入时进行更新。如果愿意，可以在单击“下一步”按钮之前编辑**项目位置**。

1.  在**目标 Android 设备**对话框中，选中**手机和平板电脑**选项。不要选择其他选项。稍后我们将创建一些其他有趣的目标，比如 Android Wear 应用程序。对于**最低 SDK**，请选择**API 14**。如果该选项尚未（尚）可用，请单击其他可用的 SDK。单击**下一步**按钮继续。

1.  在下一个对话框中**为移动设备添加活动**，选择**空白活动**选项，然后单击**下一步**按钮。

1.  在此之后将显示最终对话框**自定义活动**。保持所有值不变，然后单击**完成**按钮。

1.  Android Studio 现在将为您创建这个新应用程序。过一会儿，项目视图、一个**MainActivity**类和一个**activity_main.xml**布局将显示出来。如果您通过单击左侧 Android Studio 上显示绿色小安卓人和文字为**Android**的按钮，将项目视图的视角从**Android**更改为**项目**，布局看起来会更像您习惯的样子，也就是说，如果您以前使用过 Eclipse。

1.  双击**app**文件夹以展开它。您会注意到一个名为`build.gradle`的文件（请注意，此文件也存在于根级别）。

1.  双击`build.gradle`文件以打开它，并查看`compileSdkVersion`、`minSdkVersion`和`targetSdkVersion`的值。默认情况下，`compileSdkVersion`的值始终与最新（可用）的 SDK 相关。`minSdkVersion`的值是您在**目标 Android 设备**对话框中选择的值。

### 注意

如果您希望使用不同的 SDK 进行编译，您必须更改`compileSdkVersion`的值。您选择的版本可能需要先安装。如果您对当前的配置满意，请立即转到第 14 步。

1.  如果您想要检查已安装了哪些 SDK，请从主菜单中选择**工具**选项，然后从**SDK Manager**子菜单中选择**Android**。![如何操作...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_01_04.jpg)

1.  **Android** **SDK Manager**对话框显示了已安装的 SDK。如果您需要安装其他 SDK，您可以选中所需的元素，然后单击**安装 n 个软件包...**按钮。

1.  安装所需的 SDK 并配置好您的`build.gradle`文件后，您现在可以运行您的应用程序了。

1.  如果您要用物理设备进行 Android 开发，您需要先解锁开发者选项。在您的设备上，启动**设置**应用程序，然后转到**设备信息**选项。（此选项可能位于**常规**选项卡或部分，或者根据您的设备运行的 Android 版本和风格而在其他位置）。

### 注意

如果您没有真实设备，我强烈建议您尽快获取一个。您现在可以使用模拟器。您可以使用 Android SDK 附带的模拟器，或者您可以先阅读有关 Genymotion 的教程，了解如何使用模拟设备。

1.  在**设备信息**视图中，向下滚动直到看到**构建号**选项。现在，点击七（7）次**构建号**以解锁（启用）开发者模式。（不，这不是一个玩笑）。您现在已经解锁了开发者菜单。

### 注意

在较旧的 Android 版本（4.2 以下），此步骤可能会被跳过，或者如果开发者选项已经作为设置应用程序中的菜单项可用，此步骤可能会被跳过。

1.  现在您的**设置**应用程序中有一个名为**开发者选项**的新选项，请单击它并查看。重要的是您在此菜单中启用**USB 调试**选项。此外，您可能希望启用或禁用其他一些选项。

1.  通过单击 Android Studio 旁边的下拉框中读取应用程序的绿色三角形，连接您的设备并从 Android Studio 运行您的应用程序。或者，从**运行**菜单中选择**运行...**选项。然后，**选择设备**对话框将出现。您的设备现在应该出现在**选择运行设备**选项的列表中。（如果您的设备未出现在列表中，请重新连接您的设备。）

1.  点击**确定**按钮。（对于 Windows，在您能够连接设备之前，通常需要先安装驱动程序。）

1.  在您的设备上，可能会弹出一个对话框，要求您接受指纹。选择**允许**以继续。

应用程序现在正在部署到您的设备上。如果一切顺利，您的新应用程序现在将显示在您的设备上，上面写着**Hello world!**万岁！我承认这并不是一个非常令人兴奋的应用程序，但至少我们现在知道 Android Studio 和您的设备已经正确配置。

## 它是如何工作的...

Android Studio 将处理应用程序设置的基本部分。您只需要选择应用程序的目标和最低 SDK。目前使用 API 级别 14（Android 4.0）是最佳选择，因为这将使您的应用程序能够在大多数 Android 设备上运行。

应用程序将由 Android Studio 针对所选择的（编译）SDK 进行编译。

应用程序将被复制到您的设备上。启用**USB 调试**选项将有助于您解决任何问题，我们稍后将会发现。

# Gradle 构建脚本的使用

Android Studio 使用 Gradle 构建脚本。它是一个项目自动化工具，使用**领域特定语言**（**DSL**）而不是更常见的 XML 形式来创建项目的配置。

项目附带一个顶级构建文件和每个模块的构建文件。这些文件称为`build.gradle`。大多数情况下，只有应用程序模块的构建文件需要您的注意。

### 注意

您可能会注意到，以前在 Android 清单文件中找到的一些属性，例如目标 SDK 和版本属性，现在在构建文件中定义，并且应该仅驻留在构建文件中。

典型的`build.gradle`文件可能如下所示：

```kt
applylugin: 'com.android.application'
android {
  compileSdkVersion 21
  buildToolsVersion "21.0.0"
  defaultConfig {
  minSdkVersion 8
  targetSdkVersion 21
  versionCode 1
  versionName "0.1"
  } 
}
dependencies {
  compile fileTree(dir: 'libs', include: ['*.jar'])
}
```

Gradle 构建系统现在不是您需要过多担心的东西。在以后的教程中，我们将看到它的真正威力。该系统还设计用于支持在创建 Android 应用程序时可能面临的复杂场景，例如处理为各种客户定制的相同应用程序的版本（构建风格）或为不同设备类型或不同 Android OS 版本创建多个 APK 文件。

目前，只需知道这是我们将定义`compileSdkVersion`，`targetSdkVersion`和`minSdkVersion`的地方，就像您之前在使用 Eclipse 时在清单文件中所做的那样。

此外，这也是我们定义`versionCode`和`versionName`的地方，这反映了您的应用程序的版本，如果有人要更新您编写的应用程序，这将非常有用。

Gradle 功能的另一个有趣的关键元素是依赖关系。依赖关系可以是本地或远程库和 JAR 文件。项目依赖于它们以便能够编译和运行。在您将在上一个文件夹中找到的`app`文件夹中的`build.gradle`文件中，您将找到库所在的定义的存储库。`jCenter`是默认存储库。

例如，如果您希望添加`Parse`功能，这是我们将在下一章的教程中做的事情，以下依赖声明将向您的项目添加本地 Parse 库：

```kt
dependencies {
compile fileTree(dir: 'libs', include: 'Parse-*.jar')compile project(':Parse-1.9.1')
}
```

使用外部库变得更加容易。例如，如果你想添加`UniversalImageLoader`，一个用于从互联网加载图像的知名库，或者如果你想要使用`Gson`库的功能，它基本上是 JSON 数据的对象包装器，那么以下依赖声明将使这些库可用于项目：

```kt
dependencies {
compile 'com.google.code.gson:gson:2.3+'
compile 'com.nostra13.universalimageloader:universal-image-loader:1.9.3'
}
```

## 还有更多...

下一章的食谱中将解释一些其他 Gradle 概念。Gradle 是一个可以写一本书的话题，如果你想了解更多关于它的信息，你可以在互联网上找到许多有趣的深入教程。

## 另请参阅

+   有关 Gradle 构建脚本的更多信息，请参阅第二章，*带有基于云的后端的应用程序*

# 使用名为 Genymotion 的模拟器测试你的应用程序

测试你的应用程序的最佳方法是使用真实设备。Android 模拟器非常慢，而且没有提供真实设备所具有的所有功能，比如相机和各种传感器。

我可以想象你可能只有一个或几个设备。有成千上万的 Android 设备可用，许多品牌和型号都在定制的（例如三星设备）或纯净的（如 Nexus 设备）Android OS 版本上运行，而且你能想到的任何 Android 版本上进行真机测试都会变得非常昂贵。

例如，如果你正在创建一个应该在 Android 2.3、Android 4.x 和 Android 5.x 上运行良好的应用程序，使用模拟设备可能会很方便。不幸的是，默认的模拟器非常慢。在模拟器上启动 Android 需要很长时间，调试也可能非常慢。为了让模拟器快一点，你可以尝试安装**硬件加速执行管理器**（**HAXM**）。有一些关于如何做到这一点的主题在互联网上，然而，有一个更好的解决方案，那就是 Genymotion。

Genymotion 是一个真实、快速、易于使用的模拟器，并且具有许多真实设备配置。你可以在其网站[www.genymotion.com](http://www.genymotion.com)上了解更多关于 Genymotion 的信息。它有免费和付费版本可用。免费版本对于起步来说是可以的。

## 准备工作

确保你有互联网访问权限和足够的硬盘空间。我们需要下载 VirtualBox 和 Genymotion。之后，你就可以准备创建你的第一个虚拟设备了。让魔法开始吧。

## 如何做...

让我们安装 Genymotion 以准备 Android Studio 与运行流畅的模拟设备一起使用：

1.  需要安装 Oracle 的 VirtualBox 和 Genymotion 应用程序。这是因为 Genymotion 在后台使用**Oracle 虚拟机**（**VM**）VirtualBox 的虚拟化技术来虚拟化各种 Android 操作系统。如果你的计算机上还没有安装 Oracle VM VirtualBox（或者你的 VirtualBox 版本低于 4.1.1，不兼容 Genymotion），你需要先安装它。

从 VirtualBox 下载页面下载适用于 OS X 主机（或 Windows）的 VirtualBox，网址为[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)。

安装 VirtualBox，然后重新启动计算机。

从 Genymotion 的网页[`www.genymotion.com/#!/download`](https://www.genymotion.com/#!/download)下载 Genymotion。

1.  现在，打开并安装下载的文件。

1.  运行 Genymotion。然后会有一个对话框询问你是否要创建一个新设备。点击**是**按钮来创建。之后，你可以通过在主屏幕上点击*+*（加号）按钮来创建额外的设备。

1.  在对话框的左侧下拉列表中选择 Android OS 版本。

1.  从中心的下拉列表中选择一个虚拟设备（品牌和型号），然后点击**下一步**按钮。

1.  给您的设备命名。建议您在设备名称中包括设备和操作系统版本，以便在以后使用时可以轻松识别您正在测试的内容。

1.  单击**下一步**按钮确认名称。您的虚拟设备将被创建，并出现在 Genymotion 主屏幕的列表中。根据需要创建多个虚拟设备。

1.  要运行虚拟设备，请选择它，然后单击**播放**按钮。它将启动 Genymotion 模拟器，以便您可以与 Android Studio 一起使用。启动后，您可以解锁设备，使其准备好使用。

1.  如果您再次点击 Android Studio 中的**运行**按钮，您会注意到正在运行的虚拟设备显示在**选择设备**对话框中的可用设备列表中。只需单击**确定**按钮，魔法就会开始。您的 Android 应用程序将在模拟器上启动。

它运行得又快又顺畅！相当酷，不是吗？

以下是 Genymotion 主屏幕的示例，列出了已创建的一些虚拟设备：

![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_01_01.jpg)

## 还有更多...

Genymotion 配备了模拟的前端和/或后端摄像头，具体取决于所选择的配置。要启用它们，请单击相机图标。一个新的对话框出现，您可以在其中将滑块更改为**打开**，并为虚拟设备的前端和后端摄像头选择一个真实相机。

选择相机后，您可以关闭对话框。相机按钮旁边现在会出现一个绿色复选框。现在，每当应用程序需要使用相机时，它将使用所选的相机，我这里是笔记本电脑上的网络摄像头。要检查这是否有效，请在虚拟设备上选择相机应用程序。

Genymotion 的付费版本提供了额外的功能，包括模拟传感器，如 GPS 和加速计。如果愿意，您可以在[`www.genymotion.com/#!/store`](https://www.genymotion.com/#!/store)上查看差异。

请记住，虽然使用虚拟设备进行测试目的在 Genymotion 上非常出色，但始终重要的是在多个真实设备上进行测试。一些问题，特别是与内存管理相关的问题，稍后在本书中我们将看到，很容易在真实设备上重现，但在虚拟设备上可能会更难一些。

除此之外，真实设备更加像素完美，一些问题可能只会出现在特定设备上，因此在查看艺术品外观时，您将需要一些设备。

当您的应用程序几乎完成时，您可能会对 Testdroid 的（付费）服务感兴趣，这是一个基于云的服务，允许在许多真实设备上运行（自动化）测试。访问[www.testdroid.com](http://www.testdroid.com)了解更多关于这项伟大服务的信息！

以下截图提供了一个示例，显示了在 Genymotion 上运行的虚拟 Nexus 5 设备上运行的 Hello Android Studio 应用程序：

![还有更多...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_01_02.jpg)

# 重构您的代码

优秀的软件工程师会不断地重构他们的工作。方法和成员的名称应始终指示它们正在做什么。由于业务需求在开发过程中经常发生变化，特别是在采用敏捷方法时，您的应用程序也会发生变化。

如果您选择正确的名称，并遵守方法长度必须限制在最多一页滚动以查看整个方法的规则，通常您不需要许多注释来解释您的代码在做什么。如果很难为特定方法想出一个好的名称，那么它可能做得太多了。

由于更改名称可能令人恐惧，因为它可能破坏你的代码，开发人员通常选择不这样做。或者，他们决定以后再做。提前这样做可以节省几分钟。如果其他人查看你的代码，或者一年后再看你的代码，你的代码可能很难理解。查找方法的功能可能非常耗时。方法的描述性名称可以解决这个问题。

好消息是，使用 Android Studio，重构是轻松而相当容易的。只需高亮显示成员或方法的名称，右键单击它，然后从弹出的上下文菜单中选择**重构**项目。

在选择**重构**项目时出现的**重构**子菜单中，你会发现许多有趣的选项。在这里你将使用的一个选项，也是你将经常使用的选项是**重命名…**选项。

## 操作步骤…

以下步骤描述了如何在“重构”子菜单中重命名方法：

1.  高亮显示您想要重命名的方法的名称。

1.  从上下文菜单中选择**重构**。

1.  从子菜单中选择**重命名** (或使用快捷键*Shift* + *F6*)。

1.  现在，你可以就地重命名你的方法或成员，并通过按下*Enter*按钮应用更改。Android Studio 会为你提供一些建议，你可以接受这些建议，或者你可以输入你想要的名称。

### 提示

如果重复步骤 2 和 3，将会出现一个对话框，你可以在其中编辑名称。(或者使用快捷键*Shift* + *F6*两次)。

1.  单击**预览**按钮，查看重命名的效果。

1.  在屏幕底部，会出现一个新视图，显示重命名在每个文件（类、资源或其他）中的影响。

1.  在该视图中单击**执行重构**按钮以应用所有更改。

以下截图显示了就地重构(重命名)的示例。

![操作步骤…](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_01_03.jpg)

## 它是如何工作的…

Android Studio 会负责在整个项目中重命名方法或成员以及对它的任何引用。这包括 Java 类、布局、可绘制对象，以及你能想到的任何其他东西。

**重构**菜单中还有许多其他有趣的选项可供使用。其中一些将在下一章的示例中讨论，它们将会派上用场。

现在，让我们继续下一章，构建一个真正的应用程序，好吗？

## 另请参阅

+   有关重构代码的更多信息，请参阅第八章, *提高质量*。


# 第二章：具有基于云的后端的应用程序

本章将教您如何构建一个不需要自己的后端但使用基于云的解决方案的应用程序。

在本章中，您将学习以下食谱：

+   设置 Parse

+   从云端获取数据

+   将数据提交到云端

# 介绍

许多应用程序需要后端解决方案，允许用户与服务器或彼此通信，例如在社交应用程序中，哪个应用程序今天不是社交应用程序呢？您还可以考虑业务应用程序，例如用于物流目的的应用程序。

当然，我们可以编写自己的 API，在某个地方托管它，并编写一些 Android 代码与之通信，包括查询、缓存和应用程序需要支持的所有其他功能。不幸的是，开发所有这些可能是一个非常耗时的过程，而且由于这通常是最有价值的资产，必须有另一种方法来做到这一点。

好消息是，您不必自己做所有这些事情。互联网上有几种现成的移动后端解决方案，例如 QuickBlox、Firebase、Google 应用引擎和 Parse 等，只是其中最知名的几种。

这些解决方案各自擅长特定事情；尽管如此，一个解决方案可能比另一个更合适。例如，以 QuickBlox 为例，它提供了设置事物的最快方式，但需要付出代价。它也不像其他选项那样灵活。Firebase，最近被 Google 收购，是一个非常好的解决方案，特别是如果您需要实时支持；例如，用于聊天应用程序。Parse，被 Facebook 收购，没有实时选项，但更灵活，并且有一些有趣的第三方集成可供选择。

当选择特定解决方案时，当然还有其他考虑因素。提供这种解决方案的各方（Facebook 和 Google）可能可以访问您存储在云中的数据，包括您的用户群，这不一定是坏事，但可能会对您选择的策略产生影响。还要考虑诸如可扩展性和数据锁定等问题，这两者都是奢侈问题，但当您的应用程序变得更受欢迎时，仍然可能成为问题。

Parse 是我最喜欢的，因为它目前是大多数用途最灵活的解决方案。它没有数据锁定（所有数据都可以导出），但它是可扩展的（如果您选择付费计划而不是免费计划），它适用于所有相关的移动平台，甚至允许我们创建云模块（在云中运行的方法，可以定期安排，并且/或者可以被应用程序访问）。在所有可用的热门服务中，这个服务提供了将后端附加到移动应用程序的最简单方法。

### 注意

将来可能会发生变化，特别是对于 Android 开发人员，如果 Google 应用引擎（顺便说一句，也可以用于 iOS 应用程序）与 Android Studio 的集成得到进一步改进。您已经可以在**构建**菜单中找到**部署模块到应用引擎**选项。

# 设置 Parse

想象一个这样的场景：在一个中心点，订单正在被收集并将被准备运输。商品需要被送达，客户收到他们订购的商品后需要在应用程序中签名。每个司机都有一个移动设备和一个应用程序来在数字化过程中支持这个过程。

这是我们将提供接下来的三个食谱的过程，我们将使用 Parse 进行，因为它是我们将要创建的解决方案最合适的后端。

即将介绍的食谱描述了如何设置 Parse，如何从 Parse 中获取数据到您的 Android 应用程序，以及如何发送数据，例如应用程序中的签名，到 Parse。

## 准备就绪

要完成这个食谱，您需要运行 Android Studio 并具有互联网访问权限。就是这样。

## 如何做...

让我们首先创建一个连接到 Parse 后端的应用程序，这样我们就有了一个可以构建应用程序的基础。让我们将应用程序命名为`CloudOrder`。接下来的步骤如下：

1.  启动 Android Studio 并开始一个新的 Android Studio 项目。将应用程序命名为`CloudOrder`，并为**公司域**字段输入`packtpub.com`或适合您或您公司的任何其他名称。然后，单击**下一步**按钮。

1.  选择**手机和平板电脑**选项，可选择更改**最低 SDK**字段。在我的情况下，这将是 API 14（Android 4.x），这在撰写时是尽可能覆盖尽可能多的受众并从我们需要的 SDK 功能中受益的最佳选择。确保至少将目标定位到 API 级别 9，因为 Parse 不支持低于此级别的级别。单击**下一步**按钮继续。

1.  接下来，选择**空白活动**，然后单击**下一步**按钮。在下一页上，只需单击**完成**按钮。Android Studio 将为您设置新项目。

1.  现在，让我们转到[www.parse.com](http://www.parse.com)创建一个新帐户和一个应用程序。使用[www.Parse.com](http://www.Parse.com)注册。输入您的姓名、电子邮件地址和选择的密码，然后单击**注册**按钮。

1.  [www.Parse.com](http://www.Parse.com)上的下一页是**开始**页面。在显示有关您的应用程序名称的字段中输入`CloudOrder`或类似的内容。选择适合您情况的**公司类型**的值，并根据所选择的值完成任何其他字段。完成后，单击**开始使用 Parse**按钮。选择**数据**作为您要开始使用的产品。选择**移动**作为您的环境。接下来，选择一个平台。选择**Android**，在下一个视图中，选择**本机（Java）**选项。

1.  选择**现有项目**选项。我们正在创建一个新项目；但是，为了知道这里发生了什么，我们将自己做以下事情。

1.  现在，下载 SDK。在下载时，切换到 Android Studio，并将项目视图透视从**Android**更改为**项目**。然后，展开`app`文件夹。请注意，其中一个基础文件夹称为`libs`。

1.  将`Parse-x.x.x.jar`文件（其中`x.x.x`表示版本号）拖放到 Android Studio 中的`libs`文件夹中。如果出现**非项目文件访问**对话框，只需单击**确定**按钮。这样做后，`Parse-x.x.x.jar`将出现在`libs`文件夹下。

1.  在第一章中，*欢迎来到 Android Studio*，我们需要告诉 Gradle 关于这个 Parse 库。双击打开`apps`文件夹中的`build.gradle`文件。在依赖项部分，我们需要添加两行，所以它看起来就像下面的例子一样。在已经存在的两行之后，添加`bolts`和`parse`库的依赖项：

```kt
dependencies {
    compile 'com.android.support:appcompat-v7:22.0.0'
    compile 'com.parse.bolts:bolts-android:1.+'
    compile fileTree(dir: 'libs', include: 'Parse-*.jar')
}
```

### 注意

除了通过步骤 6 到 8 中描述的使用本地 JAR 文件，我们还可以使用类似于此的依赖项：

```kt
dependencies {
…
    compile 'com.parse:android:1.8.2'}
```

1.  在`AndroidManifest.xml`文件中，添加访问互联网所需的权限。`Manifest`文件将位于`/app/src/main`文件夹中。双击打开它。按照下面的例子添加访问互联网和访问网络状态的权限。还要为`包名`+`CloudOrderApplication`应用程序定义名称：

```kt
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.packtpub.cloudorder" >
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name= "android.permission.ACCESS_NETWORK_STATE" />
<application
    android:name="com.packtpub.cloudorder.CloudOrderApplication"
```

1.  选择并展开`src/main/java/com.packt.cloudorder`文件夹。右键单击此文件夹。在弹出的上下文菜单中，选择**新建**，在子菜单中选择**Java 类**。在显示的对话框中，将`CloudOrderApplication`输入到**名称**字段中。然后，单击**确定**按钮。

1.  使新类成为`Application`类的子类，并重写`onCreate`方法。在`onCreate`方法中，在`super.OnCreate()`之后，添加 Parse 的初始化，如 Parse 使用以下代码所示：

```kt
Parse.initialize(this, "your application Id", "your client Id");
```

1.  Android Studio 还不太满意。您会注意到 Android Studio IDE 中代码中的 Parse 部分被标记为红色。这是因为您的应用程序不知道这个类。每当您更改`gradle`文件时，您的项目都需要进行同步。要这样做，请单击带有工具提示“与 Gradle 文件同步项目”的按钮。您会在导航栏上找到这个按钮。或者，您也可以单击**立即同步**链接。![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_02_01.jpg)

1.  同步之后，Android Studio 将了解 Parse 类，但您仍然需要为此添加一个导入子句。如果您将鼠标悬停在代码中读取`Parse`的部分上，您会注意到 Android Studio 建议这可能是指`com.parse.Parse`。按下*Alt* + *Enter*接受此建议，或者自己添加`import com.parse.Parse`行。最后，您的类将如下所示：

```kt
package com.packt.cloudorder; 
import android.app.Application;
import com.parse.Parse;
public class CloudOrderApplication extends Application{
    @Override
    public void onCreate(){
        super.onCreate();
        Parse.enableLocalDatastore(this);
        Parse.initialize(this, "your application Id", "your client Id");
    }
}
```

1.  我们几乎完成了配置基于 Parse 的应用程序。打开`MainActivity`文件，并将以下行添加到您的`onCreate`方法中：

```kt
ParseObject testObject = new ParseObject("CloudOrder");
testObject.put("customer", "Packt Publishing Ltd");
testObject.saveInBackground();
```

1.  不要忘记添加适当的导入语句。运行您的应用程序。如果一切设置成功，`CloudOrder`类的新对象将被发送到 Parse 并在 Parse 中创建。

1.  在 parse 网页上，点击导航栏顶部的**Core**按钮。查看网页左侧的**Data**部分。**CloudOrder**应该出现在那里，如果您点击它，您将看到包含您刚刚发送的属性（字段）的条目（行）。

这是[www.Parse.com](http://www.Parse.com)上的数据部分的样子：

![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_02_02.jpg)

如果这个测试成功，删除你在`MainActivity`的`onCreate`方法中添加的三行代码，因为我们不再需要它们了。

干得好！你刚刚创建了你的第一个 Parse 应用！让我们继续看看如何扩展`CloudOrder`应用程序！

## 它是如何工作的...

Parse SDK 将负责检索或发送数据。使用`ParseObject`类、`Query`和其他 Parse 类，所有数据通信都将自动进行。

## 还有更多...

在[www.parse.com](http://www.parse.com)上，您将找到有关缓存策略、将数据保存到云端和其他有趣功能的其他信息。

# 从云端获取数据

我们的基于 Parse 的应用程序已经启动运行。现在，让我们看看如何从 Parse 获取订单并在列表中显示它们。

## 准备工作

要完成本教程，您需要先前的教程正在运行，互联网访问以及一些咖啡，尽管我必须承认最后一个不是绝对必要的。茶也可以。

## 如何做...

让我们看看如何通过使用以下步骤从 Parse 后端获取订单并使用列表视图显示它们来扩展我们的`CloudOrder`应用程序：

1.  在*设置 Parse*步骤的最后一步中，我们正在查看新创建的 Parse 实体和其中的数据。实体可以像我们所做的那样在应用程序中即时创建或扩展，但我们也可以在网页上定义列并在这里添加数据。点击**+Col**按钮，将新列添加到`CargoOrder`实体中。

1.  在模态中，显示**添加列**，从**选择类型**中选择**字符串**，并将新列命名为`address`。然后，点击**创建列**按钮。新列将被添加到已经可用的行中（您可能需要向右滚动以查看此内容）。

1.  添加另一列。从类型下拉框中选择**文件**，并将此字段命名为`signature`。最后，添加一个带有**数字**类型和`Status`名称的最后一列。现在，我们为每个**CargoOrder**行添加了三个新的自定义列。

1.  点击**地址**列并输入一个地址；例如，假设订单的送货地址应该是`1600 Amphitheatre Pkwy, Mountain View, CA 94043, United States`（这是谷歌总部的地址，但你当然可以在这里输入任何地址）。

1.  点击**+行**按钮创建一个新的**Cargo Order**行，并为**customer**和**address**字段输入其他值。重复几次以确保我们的应用程序中有一些数据可供使用。

1.  要从**CargoOrder**条目中检索行，我们首先需要创建一个表示订单的模型。在`MainActivity`和`CloudOrderApplication`类所在的位置创建一个新类。右键单击包名，选择**新建**和**Java 类**。命名你的新类为`CloudOrder`，然后点击**确定**按钮。将你的模型设置为`ParseObject`类的子类，并指示该类映射到哪个实体。你的类应该是这样的：

```kt
package com.packt.cloudorder; 
import com.parse.ParseClassName;
import com.parse.ParseObject;
@ParseClassName("CloudOrder")
public class CloudOrder extends ParseObject {...
```

1.  使用以下代码为我们在 Parse 中创建的列添加获取器和设置器：

```kt
public void setCustomer (String value) {
    put("customer", value);
}
public String getCustomer (){
    return getString("customer");
}
public void setAddress (String value) {
    put("address", value);
}
public String getAddress (){
    return getString("address");
}
```

1.  现在，告诉 Parse 关于这个新类。在`CloudOrderApplication`类中，在`Parse.Initialize`行之前添加这一行：

```kt
ParseObject.registerSubclass(CloudOrder.class); 
```

1.  为了在我们的应用程序中获取云订单，我们需要定义一个查询，指示我们究竟在寻找什么。在其最基本的形式中，查询看起来像以下代码片段。将其添加到`MainActivity`的`onCreate`方法中：

```kt
ParseQuery<ParseObject> query = ParseQuery.getQuery("CloudOrder");
```

1.  我们将使用`findInBackground`方法告诉 Parse 我们要异步执行这个查询。添加以下行来实现：

```kt
query.findInBackground(new FindCallback<ParseObject>() {
    public void done(List<ParseObject> items, ParseException e) {
        if (e==null){
            Log.i("TEST", String.format("%d objects found", items.size()));
        }
    }
});
```

1.  运行应用程序并检查**LogCat**（使用快捷键*Cmd* + *6*）。它会显示已找到的对象数量。这应该返回你在[www.parse.com](http://www.parse.com)为**CargoOrder**创建的行数。

1.  太好了！现在，如果我们有一个适配器可以让这些项目在列表视图中可用就好了。创建一个新类，命名为`CloudOrderAdapter`。将其设置为`CloudOrder`类型的数组适配器子类：

```kt
public class CloudOrderAdapter extends ArrayAdapter<CloudOrder> { …
```

1.  实现构造函数，创建一个视图持有者，并为所有需要被重写的方法添加实现。最终，你的适配器将是这样的：

```kt
public class CloudOrderAdapter extends ArrayAdapter<CloudOrder> {
    private Context mContext;
    private int mAdapterResourceId;
    public ArrayList<CloudOrder> mItems = null;
    static class ViewHolder{
        TextView customer;
        TextView address;
    }
    @Override	
    public int getCount(){
        super.getCount();
        int count = mItems !=null ? mItems.size() : 0;
        return count;
    }
    public CloudOrderAdapter (Context context, int adapterResourceId, ArrayList<CloudOrder>items) {
        super(context, adapterResourceId, items);
        this.mItems = items;
        this.mContext = context;
        this.mAdapterResourceId = adapterResourceId;
    }
    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View v = null;
        v = convertView;
        if (v == null){
            LayoutInflater vi = (LayoutInflater)this.getContext().getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            v = vi.inflate(mAdapterResourceId, null);
            ViewHolder holder = new ViewHolder();
            holder.customer = (TextView) v.findViewById(R.id.adapter_main_customer);
            holder.address = (TextView)v.findViewById(R.id.adapter_main_address);
            v.setTag(holder);
        }
        final CloudOrder item = mItems.get(position);
        if(item != null){
            final ViewHolder holder = (ViewHolder)v.getTag();
            holder.customer.setText(item.getCustomer());
            holder.address.setText(item.getAddress());
        }
        return v;
    }
}
```

1.  返回`MainActivity`类，并修改查询回调的代码，以便我们可以在那里用结果来填充我们新创建的适配器，如下所示：

```kt
ParseQuery<ParseObject> query = ParseQuery.getQuery("CloudOrder");
query.findInBackground(new FindCallback<ParseObject>(){
    public void done(List<ParseObject> items, ParseException e) {
        Object result = items;
        if (e == null){
            ArrayList<CloudOrder> orders = (ArrayList<CloudOrder>) result;
            Log.i("TEST", String.format("%d objects found", orders.size()));
            CloudOrderAdapter adapter = new CloudOrderAdapter(getApplicationContext(), R.layout.adapter_main, orders);
            ListView listView = (ListView)findViewById(R.id.main_list_orders);
            listView.setAdapter(adapter);;
        }
    }
});
```

1.  为了在我们的应用程序中显示订单，我们必须为其创建一个布局。展开`layout`文件夹，双击`activity_main.xml`文件以打开它。默认情况下，会显示布局的预览。通过点击 Android Studio 底部的**Text**选项卡，将布局显示为 XML。

1.  删除显示`Hello world`的**TextView**小部件，并添加一个列表视图：

```kt
<ListView
android:id="@+id/main_list_orders"
android:layout_width="wrap_content"
android:layout_height="match_parent"/>
```

1.  再次选择`layout`文件夹，右键单击它。从菜单中选择**新建**，然后从子菜单中选择**布局资源**。选择`adapter_main`作为文件名，然后点击**确定**按钮。将创建一个新的布局文件。将视角从设计更改为文本。

1.  在布局中添加两个文本视图，以便我们可以显示客户姓名和地址，并添加一些格式，如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout 
    android:orientation="vertical" android:layout_width="match_parent"
    android:padding="8dp" android:layout_height="match_parent">
    <TextView
        android:text="(Customer)"
        android:textStyle="bold"
        android:textSize="20sp"
        android:textColor="@android:color/black"
        android:id="@+id/adapter_main_customer"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
    <TextView
        android:text="(Address)"
        android:textSize="16sp"
        android:textColor="@android:color/darker_gray"
        android:id="@+id/adapter_main_address"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
</LinearLayout>
```

1.  你已经完成了。运行你的应用程序。如果一切顺利，你会看到一个输出，就像下面的截图所示，这就是你从[www.parse.com](http://www.parse.com)获取订单后列表视图的样子：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_02_03.jpg)

1.  如果你遇到`class exception error`，再看一下第 8 步。你是否注册了`ParseOrder`子类？如果你遇到其他错误，请仔细重复每一步，检查是否有任何遗漏或不匹配的地方。

## 还有更多...

这个示例只是对 Parse 的简要介绍。在[www.parse.com](http://www.parse.com)上，您将找到更多关于如何从云中检索数据的信息，包括在查询中使用**where**和**order by**语句。它还为您提供了创建关系或复合查询所需的信息。

# 提交数据到云

现在我们已经完成了之前的示例，并且将使用我们的`CloudOrder`应用程序的司机知道去哪里获取特定订单，如果一旦货物交付，司机将能够选择该订单并要求客户在设备上签名。

在这个最后的示例中，我们将实现代码，让客户在设备上签名。签名将作为图像发送到 Parse，并且`CloudOrder`记录将被更新。

## 准备工作

要完成这个示例，您需要先运行之前的示例。

## 如何做…

1.  创建一个新的类，命名为`SignatureActivity`。

1.  创建一个新的布局，命名为`activity_signature.xml`。

1.  切换布局为**文本**。将**TextView**和**Button**小部件添加到布局中。确保布局看起来像这样：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout 
    android:orientation="vertical" android:layout_width="match_parent"
    android:padding="8dp" android:layout_height="match_parent">
    <TextView
        android:id="@+id/signature_text"
        android:text=" Please sign here:"
        android:textSize="24sp"
        android:textColor="@android:color/black"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
    <Button
        android:id="@+id/signature_button"
        android:text="Send signature"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
</LinearLayout>
```

1.  为了让客户签名，我们需要创建一个自定义小部件。

1.  在`com.packt.cloudorder`包的下面，创建一个新包，命名为`widget`。

1.  在这个新包中，创建一个新类，命名为`SignatureView`。

1.  使`SignatureView`类从`View`类继承，并覆盖`onDraw`方法，以在屏幕上放置手指或触控笔时绘制路径。覆盖`onTouch`方法以创建路径。创建路径的代码段如下所示：

```kt
package com.packt.cloudorder.widget;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
public class SignatureView extends View {
    private Paint paint = new Paint();
    private Path path = new Path();
    public SignatureView(Context context, AttributeSet attrs) {
        super(context, attrs);
        paint.setAntiAlias(true);
        paint.setStrokeWidth(3f);
        paint.setColor(Color.BLACK);
        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeJoin(Paint.Join.ROUND);
    }
    @Override
    protected void onDraw(Canvas canvas) {
        canvas.drawPath(path, paint);
    }
    @Override
    public boolean onTouchEvent(MotionEvent event) {
        float eventX = event.getX();
        float eventY = event.getY();
        switch (event.getAction()) {
            case MotionEvent.ACTION_DOWN:
                path.moveTo(eventX, eventY);
                return true;
            case MotionEvent.ACTION_MOVE:
                path.lineTo(eventX, eventY);
                break;
            case MotionEvent.ACTION_UP: 
                break;
            default:
                return false;
        }
        invalidate();
        return true;
    } 
```

1.  将`getSignatureBitmap`方法添加到`SignatureView`类中，以便我们可以从`Signature view`小部件获取签名作为位图：

```kt
public Bitmap getSignatureBitmap() {
        Bitmap result = Bitmap.createBitmap(getWidth(), getHeight(), Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(result);
        Drawable bgDrawable =getBackground();
        if (bgDrawable!=null) {
            bgDrawable.draw(canvas);
        }else {
            canvas.drawColor(Color.WHITE);
            draw(canvas);
        }
        return result;
    }
} 
```

1.  返回`signature_activity`布局，并在文本视图和按钮之间添加签名视图：

```kt
<com.packt.cloudorder.widget.SignatureView
    android:id="@+id/signature_view"
    android:layout_width="match_parent"
	android:layout_height="200dp"
	android:layout_marginLeft="3dp"
	android:layout_marginTop="3dp"
	android:layout_marginRight="0dp"
	android:layout_marginBottom="18dp"/>
```

1.  构建项目。它应该消除任何渲染问题。

1.  实现`SignatureActivity`类。首先，将其设置为`Activity`的子类，并覆盖`onCreate`方法。将内容视图设置为我们刚刚创建的布局，并在布局中的按钮上添加一个`onClick`实现，如下所示：

```kt
public class SignatureActivity  extends Activity {
    @Override
	protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_signature);
        findViewById(R.id.signature_button).setOnClickListener(new View.OnClickListener(){
            @Override
			public void onClick(View v) {
            }
        });
    }
}
```

1.  在`MainActivity`声明之后，将活动添加到清单文件中，如下所示：

```kt
<activity android:name=".SignatureActivity"/>
```

1.  如果司机选择了任何订单，我们需要显示签名活动，然后需要知道选择了哪个订单。转到`MainActivity`类，并在`OnCreate`方法的末尾，在`Query.findInBackground`调用之后，添加`OnItemClickListener`到列表视图上：

```kt
((ListView)findViewById(R.id.main_list_orders)).setOnItemClickListener(new AdapterView.OnItemClickListener() {
    @Override
	public void onItemClick(AdapterView<?> parent, View view, int position, long id) {        }
});
```

1.  在`onItemClick`事件中，使用以下代码段找出选择了哪个订单：

```kt
ListView listView = (ListView)findViewById(R.id.main_list_orders);
CloudOrder order = (CloudOrder)listView.getAdapter().getItem(position);
gotoSignatureActivity(order);
```

1.  在`gotoSignatureActivity`方法中，我们希望使用意图启动`Signature`活动，并将从`MainActivity`传递到`SignatureActivity`的选择订单，使用如下所示的捆绑：

```kt
private void gotoSignatureActivity(CloudOrder order){
    Intent intent = new Intent(this, SignatureActivity.class);
    Bundle extras = new Bundle();
    extras.putString("orderId", order.getObjectId());
    intent.putExtras(extras);
    this.startActivity(intent);
}
```

1.  在`SignatureActivity`类中，将以下内容添加到按钮的`OnClick`实现中：

```kt
sendSignature();  
```

1.  对于`sendSignature`方法的实现，我们将创建一个新的`ParseFile`对象，并将来自签名视图的位图数据传递给它。我们将使用`saveInBackground`方法将文件发送到 Parse：

```kt
private void sendSignature() {
    final Activity activity = this; 
    SignatureView signatureView = (SignatureView)findViewById(R.id.signature_view); 
    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    signatureView.getSignatureBitmap().compress(Bitmap.CompressFormat.PNG, 100, stream);
    byte[] data = stream.toByteArray();
    final ParseFile file = new ParseFile("signature.jpg", data); 
    file.saveInBackground(new SaveCallback() {
        @Override
		public void done(com.parse.ParseException e) {
        }
    });
}
```

1.  保存完成后，我们希望更新订单的信息，例如我们创建的文件和状态，例如`10`，这可能表示订单已完成或类似的状态。这里实际的值并不重要。

1.  如果在保存过程中没有发生错误，我们使用`ParseObject`类的`createWithoutData`方法，这样我们就可以传递正确的对象 ID 和我们想要更新的字段。我们也会保存这些更改，以便在 Parse 上更新记录。（为了简单起见，我们使用这种方法；尽管我们也可以使用`CloudOrder`对象来完成相同的事情）完成回调的实现如下：

```kt
if (e == null) {
 Bundle extras = getIntent().getExtras();
ParseObject order = ParseObject.createWithoutData("CloudOrder", extras.getString("orderId"));
                order.put("signature", file);
                order.put("status", 10);
order.saveInBackground(new SaveCallback() {
                    @Override
                    public void done(ParseException e) {
                        if (e==null){
                            Toast.makeText(activity, "Signature has been sent!", Toast.LENGTH_SHORT).show();
                        }
                    }
                });
```

1.  运行应用程序，选择一个订单，签名，然后单击**发送签名**按钮。如果一切顺利，将显示一个 toast，指示签名已发送。

这是顾客签名后签名的样子：

![操作步骤…](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_02_04.jpg)

1.  自己去[www.parse.com](http://www.parse.com)看看。刷新**Cloud order**的视图。注意，在应用程序中选择的订单中，`signature.jpg`文件出现在签名列中。双击它以查看其内容。在向其提交签名图像后，您的数据行可能如下所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_02_05.jpg)

实际上，您应该使用字符串资源而不是硬编码的值。通过重用字符串资源（或常量值），不仅可以用于类和字段名称，还可以用于其他文本，从而减少由拼写错误引起的错误数量。这将提高您的应用程序的质量。它也将使以后本地化应用程序变得更加容易。（在最后三章中，我们将更多地关注这些内容，但现在就开始使用这些好的实践。）以下步骤使用了字符串资源：

1.  查看`strings.xml`文件。它位于`res/values`文件夹中。想象一下，如果我们在步骤 19 中显示的 toast 中包含了文本。您的`strings.xml`文件可能如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
…<string name="app_name">Cloud order</string><string name="parse_class_cargo_order">CargoOrder</string>
    <string name="signature_send">Your signature has been sent.</string>
```

1.  在您的代码中，您可以使用`getString`方法引用字符串资源。例如，您可以用字符串引用替换步骤 19 中显示的 toast 的硬编码字符串，如下所示：

```kt
Toast.makeText(activity, getString(R.string.signature_send), Toast.LENGTH_SHORT).show();
```

1.  在您的布局文件中，您也可以引用这个字符串资源，例如，在一个文本视图中：

```kt
<TextView
    android:text="@string/signature_send"
	android:layout_width="wrap_content"
	android:layout_height="match_parent" />
```

我们将在以后深入介绍如何使用字符串、颜色、尺寸和其他类型的资源，但您可以通过用字符串资源引用替换本教程中的所有硬编码字符串，或在适用的情况下使用常量值来熟悉这些概念。

通过实现这个步骤，我们已经完成了我们的`CloudOrder`应用程序。随意进行进一步的定制，并在需要的地方进行增强。

## 工作原理...

自定义小部件在视图上绘制路径，然后将创建一个位图。使用`ParseFile`对象，位图数据将被发送到 Parse（然后将文件存储在 Amazon 并保留对文件的引用）。

如果成功，我们将更新适用于签名的**CloudOrder**行，指明**signature**列中的图像指向哪个文件。

## 还有更多...

请查看[www.parse.com](http://www.parse.com)上的文档。那里有一些有趣的功能可用，包括`saveEventually`方法和云代码选项。

如果没有可用的互联网连接，`saveEventually`方法将在本地存储更新，这对于移动应用程序是常见的情况。一旦恢复了互联网连接，这个方法将开始发送已排队等待发送到云端的数据。这个选项将为您节省大量麻烦和时间。

还要查看其他功能，比如云代码和各种可用的第三方集成，比如 Twilio，如果您想发送文本或语音消息（这对于入职流程中的确认目的可能很方便），以及 SendGrid，这是一个用于电子邮件传递的工具。

在本章的示例中，我们只需付出少许努力就实现了一些非常有趣的功能，这真的很棒！然而，该应用程序目前还不够吸引人。通过应用下一章将解释的材料设计概念，我们可以使应用程序看起来更加出色，并且更加直观易用。

## 另请参阅

+   有关更多信息，请参阅第三章 *材料设计*。


# 第三章：Material Design

这一章将教你什么是 Material Design，为什么它是一个很大的改进，以及为什么你应该在你的应用中使用它。

在这一章中，你将学到：

+   回收视图和卡片视图

+   涟漪和高程

+   出色的过渡

# 介绍

随着 Material Design 的引入，Android 应用的外观终于成熟了。它们可以与 iOS 设计很好地竞争。Android Material 应用具有扁平设计，但也有一些有趣的区别，比如高程。例如考虑下面的图：

![Introduction](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_03_01.jpg)

把它想象成多张纸片。它是基于，嗯，材料的。每张纸片都有特定的高程。所以，环境实际上是一个有光和阴影等效果的 3D 世界。任何动作都应该具有真实世界的行为，就好像移动的元素是真实的物体一样。动画是 Material Design 的另一个重要元素。

首先看一下[`www.google.co.in/design/spec/material-design/introduction.html`](https://www.google.co.in/design/spec/material-design/introduction.html)来了解 Material Design 的全部内容。当然，对设计师来说有很多有趣的东西，而你可能只对所有这些美丽的东西的实现感兴趣；然而，这个链接为你提供了更多关于 Material Design 的背景信息。

长时间以来，大多数 Android 应用都受到糟糕的设计的困扰，或者在早期根本没有设计。或者，它们看起来与为 iPhone 制作的应用非常相似，包括所有 iOS 典型的元素。

看一下下一个应用的截图：

![Introduction](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_03_03.jpg)

使用 Material Design，这就是现在大多数谷歌应用的外观。

现在许多谷歌的 Android 应用都使用 Material Design。它们都遵循相同的交互和设计准则。界面是极简主义的，正如人们对谷歌所期望的那样。此外，界面变得更加统一，使得更容易理解和使用。

以前，响应性是你自己要注意的事情。Material Design 带来了涟漪和其他效果，做着同样的事情，即提供用户输入的反馈，但它更容易实现，更加优雅。

至于组件，Material Design 规定了例如特定情况下按钮应该是什么样子。想想用于操作的浮动按钮，或者用于对话框中的扁平按钮。它还用**RecyclerView**替换了**ListView**，这样可以更灵活地显示列表。**CardViews**是常见的元素，你可以经常在谷歌应用中看到它们的使用。各种动画提供了更自然的过渡，比如用于导航或滚动目的的动画。

Material Design 不仅适用于最新和最好的。虽然它随 Android Lollipop（5.0）和更高版本一起发布，但大多数 Material Design 功能可以通过`v7 支持`库在 Android 2.1 及更高版本中使用，这使我们能够应用 Material Design 并仍然支持几乎所有的 Android 设备。

总的来说，Material Design 为你的应用美化提供了很多。人们也想变得更美丽。健康应用因此而蓬勃发展。找出健康的饮食，建议多喝水，以及建议跑步或健身锻炼是这类应用的常见目标。为了展示 Material Design 的美丽，我们将创建一个可以帮助人们变得更健康的应用。

那么，`喝水并自拍`应用怎么样？人们需要更经常地喝水，如果他们这样做，他们就能看到效果。美丽的人们应该有一个美丽的应用。这是有道理的，不是吗？

# 回收视图和卡片视图

`RecyclerView`取代了传统的列表视图。它提供了更多的灵活性，可以以网格形式或水平或垂直项目的形式显示列表的元素。现在，我们可以选择在合适的地方显示卡片，而不是行。

在我们的应用中，每个卡片应该显示有关条目的一些文本和我们拍摄的图片的缩略图。这就是本教程的全部内容。

## 准备工作

要完成本教程，您需要运行 Android。还要确保您已安装了最新的 SDK。（您可以通过打开 SDK 管理器来检查是否安装了最新的 SDK）。为此，打开**工具**菜单，选择**Android**，然后选择**SDK 管理器**选项。

## 如何做...

让我们使用以下步骤来调查如何使用`recycler view`和卡片：

1.  启动 Android Studio 并开始一个新项目。将应用程序命名为`WaterApp`，并在**公司域**字段中输入`packtpub.com`。然后，点击**下一步**按钮。

1.  在下一个对话框中选择**空白活动**，然后点击**下一步**按钮。

1.  在下一个对话框中，点击**完成**按钮。

1.  在`app`文件夹中的`build.gradle`文件中，如下所示，在`dependencies`部分添加`recycler view`的依赖项：

```kt
dependencies {
    compile fileTree(dir: 'libs', include: ['*.jar'])
    compile 'com.android.support:appcompat-v7:22.1.1'
    compile 'com.android.support:recyclerview-v7:+'
}
```

1.  在`build.gradle`文件中将`minSdkVersion`更改为至少`21`。

### 注意

这不一定是最小所需的版本，但由于用于向后兼容目的的支持库不包含所有的 Material 设计功能，我选择在这里选择 API 级别 21，以确保安全。

1.  通过单击`build.gradle`文件编辑后出现的黄色条上的**立即同步**标签来同步您的项目，或者如果没有出现，请单击工具栏上的**同步项目与 Gradle 文件**按钮。

1.  打开`activity_main.xml`布局文件，删除`Hello World TextView`，并向布局中添加一个`RecyclerView`标签，如下所示：

```kt
<android.support.v7.widget.RecyclerView
    android:id="@+id/main_recycler_view"
    android:scrollbars="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent"/>
```

1.  在您的`MainActivity`类中，在`setContentView`之后的`onCreate`方法中添加以下内容：

```kt
RecyclerView recyclerView = (RecyclerView) 
 findViewById(R.id.main_recycler_view);
```

1.  `RecyclerView`类还不是一个已知的类。使用*Alt* + *Enter*快捷键添加正确的导入语句，或者自己添加以下行：

```kt
import android.support.v7.widget.RecyclerView;
```

1.  我们将在这个教程中使用线性布局管理器。在第 9 步中添加的行后添加以下行：

```kt
LinearLayoutManager layoutManager = new LinearLayoutManager(this);
recyclerView.setLayoutManager(layoutManager);
```

1.  创建一个新的包并将其命名为`models`，在该包中创建一个新的`Drink`类，如下所示：

```kt
package com.packt.waterapp.models;import java.util.Date;
public class Drink {
    public Date dateAndTime;
    public String comments;
    public String imageUri;
}
```

这里，`Date`类指的是`java.util.Date`包（这是指定的，因为还有一个同名的与 SQL 相关的类）。

1.  让我们创建一个布局来显示这些项目。在项目树中的`layout`包上右键单击，创建一个新的资源文件。为此，从菜单中选择**新建**和**新建布局资源文件**。将其命名为`adapter_main.xml`，然后点击**确定**按钮。

1.  将布局切换到**文本**模式，将`LinearLayout`的方向从`垂直`改为`水平`，为其添加一些填充，并向其添加一个图像视图，如下面的代码片段所示。我们还将添加一个默认图像，以便我们有东西可以查看：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout 
android:orientation="horizontal" android:layout_width="match_parent"
android:padding="8dp" android:layout_height="match_parent">
<ImageView android:id="@+id/main_image_view"
android:src="img/ic_menu_camera"
android:scaleType="center"
android:layout_width="90dp"
android:layout_height="90dp" />
</LinearLayout>
```

1.  在图像旁边，我们想要使用两个`TextView`小部件显示日期和时间以及评论，这两个小部件包裹在另一个`LinearLayout`小部件中。在`ImageView`标签之后添加这些：

```kt
<LinearLayoutandroid:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="wrap_content">
    <TextView
        android:id="@+id/main_date_time_textview"
		android:layout_marginTop="8dp"
		android:textSize="12sp"
		android:textColor="@color/material_blue_grey_800"
		android:layout_width="match_parent"
		android:layout_height="wrap_content" />
    <TextView
        android:id="@+id/main_comment_textview"
		android:layout_marginTop="16dp"
		android:maxLines="3"
		android:textSize="16sp"
		android:textColor="@color/material_deep_teal_500"
		android:layout_width="match_parent"
		android:layout_height="wrap_content" />
	</LinearLayout>
```

1.  创建另一个包并将其命名为`adapters`。在该包中创建`MainAdapter`类，该类将使用`ViewHolder`类，帮助我们将数据显示在我们想要的位置。我们还包括所有需要被重写的方法，比如`onBindViewHolder`方法和`getItemCount`方法：

```kt
public class MainAdapter extends RecyclerView.Adapter<MainAdapter.ViewHolder> {
    private ArrayList<Drink> mDrinks;private Context mContext;public static class ViewHolder extends        RecyclerView.ViewHolder {
        public TextView mCommentTextView;
        public TextView mDateTimeTextView;
        public ImageView mImageView;
        public ViewHolder(View v) {
            super(v);
        }
    }
    public MainAdapter(Context context, 
      ArrayList<Drink> drinks) {
        mDrinks = drinks;
        mContext = context;
    }
    @Override
    public MainAdapter.ViewHolder  
     onCreateViewHolder(ViewGroup parent,  int viewType) {
        View v = LayoutInflater.from(
         parent.getContext()).inflate(
          R.layout.adapter_main, parent, false);
        ViewHolder viewHolder = new ViewHolder(v);
        viewHolder.mDateTimeTextView =  
         (TextView)v.findViewById(
          R.id.main_date_time_textview);
        viewHolder.mCommentTextView =  
         (TextView)v.findViewById(
          R.id.main_comment_textview);
        viewHolder.mImageView = 
         (ImageView)v.findViewById(
          R.id.main_image_view);
        return viewHolder;
    }
    @Override
    public int getItemCount() {
        return mDrinks.size();
    }
}
```

1.  我们还有更多的事情要做。添加`onBindViewHolder`方法，并添加实现以将数据实际绑定到正确的小部件上：

```kt
@Override
public void onBindViewHolder(ViewHolder holder,int position) {
    Drink currentDrink = mDrinks.get(position);
    holder.mCommentTextView.setText(
     currentDrink.comments);
    holder.mDateTimeTextView.setText(
     currentDrink.dateAndTime.toString());
    if (currentDrink.imageUri != null){
        holder.mImageView.setImageURI(
         Uri.parse(currentDrink.imageUri));
    }
}
```

1.  在`MainActivity`文件中，我们需要有一个适配器的实例和一些要显示的数据。添加一个私有适配器和一个包含`Drink`项目的私有数组列表：

```kt
private MainAdapter mAdapter;private ArrayList<Drink> mDrinks;
```

1.  在`onCreate`方法的末尾，告诉`recyclerView`使用哪个适配器，并告诉适配器使用哪个数据集：

```kt
mAdapter = new MainAdapter(this, mDrinks);
recyclerView.setAdapter(mAdapter);

```

1.  在`MainActivity`文件中，我们想添加一些虚拟数据，以便我们对事情将会是什么样子有一些想法。在我们创建`MainAdapter`类之前的`onCreate`方法中添加以下内容：

```kt
mDrinks = new ArrayList<Drink>();
Drink firstDrink = new Drink();
firstDrink.comments = "I like water with bubbles most of the time...";
firstDrink.dateAndTime = new Date();
mDrinks.add(firstDrink);Drink secondDrink = new Drink();
secondDrink.comments = "I also like water without bubbles. It depends on my mood I guess ;-)";
secondDrink.dateAndTime = new Date();
mDrinks.add(secondDrink);
```

使用*Alt* + *enter*快捷键导入所需的包。

运行您的应用程序以验证到目前为止一切都进行得很顺利。您的应用程序将显示两个包含我们在上一步中创建的示例数据的条目。

### **使用卡片视图**

应用程序看起来还可以，但我不想称其为美丽。让我们看看是否可以稍微改进一下。以下步骤将帮助我们使用卡片视图创建应用程序：

1.  在`app`文件夹中的`build.gradle`文件中添加一个`CardView`依赖项，就在对`recycler view`的依赖项之后：

```kt
compile 'com.android.support:cardview-v7:+'
```

然后再次同步您的项目。

### 注意

顺便说一句，如果这个应用是真的，那么避免不愉快的惊喜，通过指定确切的版本而不是在版本号中使用`+`号来解决任何依赖项可能存在的问题。目前，对于这个特定的依赖项，版本号是`21.0.0`，但在您阅读本文时，可能已经有了新版本。

1.  如果出现错误提示 Gradle 无法解析卡片视图依赖项，则单击**安装存储库并同步项目**链接，接受许可证，并单击**下一步**按钮。等待一段时间，直到下载完成并安装完成。完成后，单击**完成**按钮。再次同步您的项目。

1.  创建一个新的布局并命名为`adapter_main_card_view.xml`。在`LinearLayout`标签中添加一些填充，在`LinearLayout`标签内部添加一个`CardView`：

```kt
<?xml version="1.0" encoding="utf-8"?><LinearLayout 
    android:orientation="vertical"   
    android:layout_width="match_parent"
    android:padding="4dp"  
    android:layout_height="match_parent">
    <android.support.v7.widget.CardView
        xmlns:card_view=
        "http://schemas.android.com/apk/res-auto"android:id="@+id/card_view"
        android:layout_gravity="center"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"card_view:cardCornerRadius="4dp"></android.support.v7.widget.CardView>
</LinearLayout>
```

1.  从先前的布局`adapter_main.xml`文件中，复制`ImageView`和两个`TextView`小部件（但不包括包含这两个`TextView`小部件的`LinearLayout`），并将它们粘贴到您已添加到`adapter_main_card_view.xml`文件中的`CardView`中。

1.  因为`CardView`的行为就像`FrameLayout`，所以您需要为文本标签设置边距。为两个文本视图添加左边距。还修改`TextView`评论的顶部边距：

```kt
<TextView
    android:id="@+id/main_date_time_textview"
	android:layout_marginTop="8dp"
	android:layout_marginLeft="100dp"
	android:textSize="12sp"
	android:textColor="@color/material_blue_grey_800"
	android:layout_width="match_parent"
	android:layout_height="wrap_content" />
<TextView
    android:id="@+id/main_comment_textview"
	android:layout_marginTop="32dp"
	android:layout_marginLeft="100dp"
	android:maxLines="3"
	android:textSize="16sp"
	android:textColor="@color/material_deep_teal_500"
	android:layout_width="match_parent"
	android:layout_height="wrap_content" />
```

1.  现在，通过更改`onCreateViewHolder`方法中的布局 ID，告诉`MainAdapter`类使用这个布局：

```kt
View v = LayoutInflater.from(parent.getContext()). inflate(R.layout.adapter_main_card_view, parent, false);
```

再次运行应用程序，我们将看到这次它会是什么样子：

![使用卡片视图](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_03_04.jpg)

1.  在下一个教程中，我们将添加一个提升的浮动按钮，并创建一个新的活动，允许我们的应用程序的用户添加饮料、评论和自拍。

## 还有更多...

有很多关于材料设计的文档。浏览各种网站上提供的各种示例，比如[`www.materialup.com`](https://www.materialup.com)，[`materialdesignblog.com`](http://materialdesignblog.com)或[`material-design.tumblr.com`](http://material-design.tumblr.com)。

或者，下载一些在 Play 商店中可用的材料设计应用程序，例如 Inbox、Google+、Wunderlist、Evernote、LocalCast 和 SoundCast 应用程序。

# 涟漪和高程

尽管高程和涟漪并不一定会使人们更加美丽，但将这些和其他材料设计原则应用到我们的应用程序中肯定会有助于美化它。

在上一个教程中，我们创建了一个列表来显示所有已登录的饮料。在这个教程中，我们将添加一个提升的按钮来添加新条目。此外，我们将创建一个新的活动。

对于每个条目，用户可以描述一些关于他喝的东西的想法。当然，用户必须能够每次都自拍，以便以后他可以检查喝那么多水或绿茶（或者啤酒）是否确实对他的健康和外貌产生了积极的影响。

## 准备工作

对于这个指南，如果您已经完成了上一个指南，那将是很好的，因为这将建立在我们以前的成就之上。

## 如何做...

让我们添加一个浮动按钮，并创建一个新的活动来编辑新条目：

1.  在`res/drawable`文件夹中添加一个新的可绘制资源文件，命名为`button_round_teal_bg.xml`，然后点击**OK**按钮。

1.  使用 XML，我们将为按钮创建一个圆形椭圆形状。首先删除选择器标签（如果有）。将其包装在`ripple`标签中。`ripple`在按钮被按下时提供可见反馈；我选择了一种蓝绿色的材料设计变体作为颜色，但您当然可以选择任何您喜欢的颜色。作为灵感，您可以查看[`www.google.com/design/spec/style/color.html`](http://www.google.com/design/spec/style/color.html)。文件的内容如下例所示：

```kt
<ripple android:color="#009789">
    <item>
        <shape android:shape="oval">
            <solid android:color="?android:colorAccent"/>
        </shape>
    </item>
</ripple>
```

### 提示

如果遇到任何错误，请检查`build.gradle`文件中的`minSdkVersion`。有关更多信息，请参考第一条指南的第 5 步。

1.  在`activity_main.xml`布局文件中的循环视图后添加一个按钮：

```kt
<ImageButton
    android:id="@+id/main_button_add"
	android:elevation="1dp"
	android:layout_width="48dp"
    android:layout_height="48dp"
    android:layout_alignParentBottom="true"
    android:layout_alignParentRight="true"
    android:layout_margin="16dp"
    android:tint="@android:color/white"
    android:background="@drawable/button_round_teal_bg"
    android:src="img/ic_input_add"/>
```

### 注意

颜色应该在单独的颜色资源文件中定义。此外，高程和边距应该放在尺寸资源文件中。由于这超出了本指南的范围，我建议您稍后再做这些。

1.  接下来，我们希望有一些阴影，还希望在按钮被按下或释放时改变高程。在`res`文件夹中创建一个新的目录，命名为`anim`。在此文件夹中，创建一个新的动画资源文件。将文件命名为`button_elevation.xml`，然后点击**OK**按钮：

```kt
<selector >
    <item android:state_pressed="true">
        <objectAnimator
            android:propertyName="translationZ"android:duration="@android:integer/config_shortAnimTime"
            android:valueFrom="1dp"
            android:valueTo="4dp"android:valueType="floatType"/></item>
    <item>
        <objectAnimator
            android:propertyName="translationZ"android:duration="@android:integer/config_shortAnimTime"
            android:valueFrom="4dp"
            android:valueTo="1dp"
            android:valueType="floatType"/>
    </item>
</selector>
```

1.  通知图像按钮有关这个新的资源文件。在您的`activity_main.xml`布局中，为图像按钮添加以下行：

```kt
android:stateListAnimator="@anim/button_elevation"
```

1.  在 MainActivity 类的 onCreate 方法末尾，为我们刚刚创建的按钮添加一个`OnClickListener`，并调用`showEntry`方法，我们将在一两分钟内创建：

```kt
findViewById(R.id.main_button_add).setOnClickListener(new  
 View.OnClickListener() {
    @Override
    public void onClick(View v) {
        showEntry();}
});
```

1.  创建一个新的布局资源文件，命名为`activity_entry.xml`，并将`FrameLayout`用作根元素。然后点击**OK**按钮。

1.  为评论添加一个`EditText`小部件，一个拍照按钮和另一个保存条目的按钮。然后将这些元素包装在`CardView`小部件中。在`CardView`小部件之后添加一个`ImageView`小部件，就像这样：

```kt
<?xml version="1.0" encoding="utf-8"?> <FrameLayout xmlns:android= 
 "http://schemas.android.com/apk/res/android"
    android:padding="8dp" android:layout_width="match_parent"   
    android:layout_height="match_parent">
    <android.support.v7.widget.CardView 
        android:id="@+id/card_view"
        android:layout_width="match_parent"
        android:layout_height="200dp"
        card_view:cardCornerRadius="4dp">
    <EditText                                                                                                  android:id="@+id/entry_edit_text_comment"android:lines="6"android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginRight="60dp"/>
    <ImageButton 
	    android:id="@+id/entry_image_button_camera"
        android:src="img/ic_menu_camera"
        android:layout_gravity="right"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />
    <Button 
	    android:id="@+id/entry_button_add"
        android:layout_gravity="bottom"
        android:text="Add entry"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
    </android.support.v7.widget.CardView>
    <ImageView
        android:id="@+id/entry_image_view_preview"
        android:scaleType="fitCenter"
        android:layout_marginTop="210dp"
        android:layout_width="match_parent"
        android:layout_height="match_parent" />
</FrameLayout>
```

1.  创建一个新的类，命名为`EntryActivity`，然后点击**OK**按钮。

1.  使您的类从`Activity`继承，重写`onCreate`方法，并将内容视图设置为您刚刚创建的布局：

```kt
public class EntryActivity extends Activity {
    @Override
	protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_entry);
    }
}
```

1.  不要忘记在`AndroidManifest.xml`文件中添加新的活动：

```kt
<activity android:name=".EntryActivity"/>
```

1.  在`MainActivity`类中，添加`showEntry`方法和显示新活动所需的实现。我们将在这里使用`startActivityForResult`方法，因为这将允许`EntryActivity`稍后返回数据：

```kt
private int REQUEST_NEW_ENTRY = 1;
private void showEntry(){
    Intent intent = new Intent(this, EntryActivity.class);
    startActivityForResult(intent, REQUEST_NEW_ENTRY);
}
```

现在，如果您运行应用程序并按下按钮，您将注意到视觉反馈。为了正确看到效果，您可能需要使用触控笔或放大按钮的大小。如果您释放按钮，您将看到条目布局。在布局中，如果您按住**添加条目**按钮（或相机按钮），您将注意到涟漪效果。我们不必为此做任何特殊处理。随着 Lollipop 的推出（以及之前的描述），这是按钮的默认行为。但是，这些按钮看起来有点无聊，就像您在浮动按钮中看到的那样，有很多自定义选项可用。让我们按照下一步操作：

1.  在`EntryActivity`类中，为相机按钮设置`OnClickListener`，并对`add`按钮执行相同的操作：

```kt
findViewById(R.id.entry_image_button_camera).setOnClickListener( 
 new View.OnClickListener() {
    @Override
    public void onClick(View v) {
        takePicture();
    }
});
findViewById(R.id.entry_button_add).setOnClickListener(new 
 View.OnClickListener() {
    @Override
    public void onClick(View v) {
    }
}
);
```

1.  添加一个私有成员，用于包含我们将要拍摄的照片的 URI：

```kt
private Uri mUri;
```

1.  创建一个`takePicture`方法并为其添加实现。我们将使用时间戳提前创建一个带有唯一图像名称的文件，并告诉图像捕获意图使用`Uri`来访问该文件：

```kt
private int REQUEST_IMAGE_CAPTURE = 1;
private void takePicture(){
    File  filePhoto = new  
    File(Environment.getExternalStorageDirectory(),String.valueOf(new Date().getTime())+"selfie.jpg");
    mUri = Uri.fromFile(filePhoto);
    Intent intent = new   
     Intent("android.media.action.IMAGE_CAPTURE");
    intent.putExtra(MediaStore.EXTRA_OUTPUT, mUri);
    startActivityForResult(intent, REQUEST_IMAGE_CAPTURE);
}
```

1.  重写`onActivityResult`方法，一旦拍照就会触发。如果一切顺利，我们需要创建刚刚拍摄的文件的位图，并显示其预览：

```kt
@Override
    protected void onActivityResult(int requestCode, int resultCode,Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == REQUEST_IMAGE_CAPTURE &&
        resultCode == RESULT_OK){
        Bitmap bitmap = getBitmapFromUri();
        ImageView preview = (ImageView)  
          findViewById(R.id.entry_image_view_preview);
        preview.setImageBitmap(bitmap);}
}
```

1.  接下来，实现`getBitmapFromUri`方法：

```kt
public Bitmap getBitmapFromUri() {
    getContentResolver().notifyChange(mUri, null);
    ContentResolver resolver = getContentResolver();
    Bitmap bitmap;
    try {
        bitmap = android.provider.MediaStore.Images.Media.getBitmap(  
         resolver, mUri);
        return bitmap;
    } 
    catch (Exception e) {
        Toast.makeText(this, e.getMessage(),  
         Toast.LENGTH_SHORT).show();
       return null;}
}
```

1.  在`AndroidManifest.xml`文件中添加适当的权限和功能：

```kt
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission  
  android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-feature android:name="android.hardware.camera" />
```

1.  现在让我们实现`submitEntry`方法。我们将返回评论和图片的`uri`，然后结束活动：

```kt
private void submitEntry(){
    EditText editComment =  (EditText)
      findViewById(R.id.entry_edit_text_comment);
    Intent intent = new Intent();
    intent.putExtra("comments", editComment.getText().toString());
    if (mUri != null) {
        intent.putExtra("uri", "file://" +   
          mUri.getPath().toString());}
    setResult(Activity.RESULT_OK, intent);
    finish();
}
```

1.  为`add`按钮的`onClick`事件添加实现。只需调用`submitEntry`方法：

```kt
findViewById(R.id.entry_button_add).setOnClickListener(new View.OnClickListener() {
    @Override
    public void onClick(View v) {
        submitEntry();
    }
});
```

1.  在`MainActivity`类中，我们将通过重写`onActivityResult`方法来处理返回的结果。将创建一个新的饮料并添加到饮料列表中。最后，我们将通过添加以下片段通知适配器需要显示更新：

```kt
@Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == REQUEST_NEW_ENTRY && 
        resultCode == RESULT_OK) {
        Bundle bundle = data.getExtras();
        Drink newDrink = new Drink();
        newDrink.comments = bundle.getString("comments");
        newDrink.imageUri = bundle.getString("uri");
        newDrink.dateAndTime = new Date();
        mDrinks.add(newDrink);
        mAdapter.notifyDataSetChanged();
}
```

1.  在`MainAdapter`类中，我们需要做一些工作来显示每个图像的缩略图。将以下内容添加到`onBindViewHolder`方法的末尾：

```kt
if (currentDrink.imageUri != null){
    Bitmap bitmap =    
     getBitmapFromUri(Uri.parse(currentDrink.imageUri));
    holder.mImageView.setImageBitmap(bitmap);
}
```

1.  如果已知项目的`Uri`，我们需要为其显示缩略图。我们将在`MainAdapter`中以稍有不同的方式实现`getBitmapFromUri`。方法如下：

```kt
public Bitmap getBitmapFromUri(Uri uri) {
    mContext.getContentResolver().notifyChange(uri, null);
    ContentResolver cr = mContext.getContentResolver();
    try {
       Bitmap bitmap =   
android.provider.MediaStore.Images.Media.getBitmap(cr, uri);
       return bitmap;
    }
    catch (Exception e) {
        Toast.makeText(mContext, e.getMessage(),  
         Toast.LENGTH_SHORT).show();
        return null;
    }
}
```

现在，运行应用程序。您可以使用真实设备或 Genymotion。如果您使用 Genymotion，您需要启用相机，如第一章*欢迎使用 Android Studio*中所述。单击**添加**按钮，喝一杯水，输入一些评论，然后自拍。点击**添加条目**按钮，使其出现在列表中。

太棒了！您现在已经完成了。该应用程序远非完美，但我们已经做出了一些有趣的举措。美化需要时间。在下一个示例中，我们将通过添加过渡来实现一些令人惊叹的东西。

### 注意

在某些设备上，但不是所有设备，图片可能会被旋转。这是 Android 开发面临的挑战之一，我们将在第六章*捕获和分享*中涵盖这个主题。

## 还有更多…

除了在应用程序的生命周期内，条目列表尚未持久化。如果需要，可以通过将条目存储在 SQLite 数据库中或最终使用 Parse 来使条目持久化，这在第二章*具有基于云的后端的应用程序*中讨论。由于持久性不是本示例的目标，这里不会进一步讨论。在第七章*内容提供程序和观察者*中，将讨论 SQLite 和内容提供程序。

### 注意

自 API 级别 23 以来，有一个可用的 FloatingActionButton 小部件。它有两种大小：默认和迷你。

## 另请参阅

+   第二章*具有基于云的后端的应用程序*

+   第六章*捕获和分享*

+   第七章*内容提供程序和观察者*

# 出色的过渡

如果单击任何卡片，它将再次显示条目视图，其中包括评论和我们之前拍摄的图片的预览。

我们不仅希望从列表视图转到详细视图。Material design 还负责出色的自然过渡。这个示例将应用这一点。

## 准备就绪

要完成这个示例，您需要先运行之前的示例。这个示例将为其添加一些动画。

## 如何做…

以下步骤将帮助我们为应用程序添加动画：

1.  在`MainAdapter`类的`ViewHolder`中添加一个`mDrink`成员：

```kt
public Drink mDrink;
```

1.  在`onBindViewHolder`方法中的同一文件中，在`currentDrink`初始化后，通知`view holder`有关实际饮料的信息：

```kt
Drink currentDrink = mDrinks.get(position);
holder.mDrink = currentDrink;
```

1.  在`onCreateViewHolder`方法中，添加一个`OnClickListener`到末尾：

```kt
v.setTag(viewHolder);
v.setOnClickListener(new View.OnClickListener() {
    @Override
	    public void onClick(View view) {
        ViewHolder holder = (ViewHolder) view.getTag();
        if (view.getId() == holder.itemView.getId()) 
        {
        }
    }
});
```

1.  如果视图被点击，我们希望`EntryActivity`类显示所选的饮料条目。为了能够通知条目有关选择，我们需要将`Drink`模型设为`parcelable`类：

```kt
public class Drink implements Parcelable
```

1.  我们需要实现一些方法：

```kt
@Override
public int describeContents() {
    return 0;
}
@Override
public void writeToParcel(Parcel out, int flags) {
    out.writeLong(dateAndTime.getTime());
    out.writeString(comments);
    out.writeString(imageUri);
}
public static final Parcelable.Creator<Drink> CREATOR = new 
 Parcelable.Creator<Drink>() {
    public Drink createFromParcel(Parcel in) {
        return new Drink(in);
    }
    public Drink[] newArray(int size) {
        return new Drink[size];
    }
};
```

1.  为`Drink`类添加两个构造函数——一个默认的和一个带有 parcel 的，这样我们就可以重新创建对象并用适当的值填充它：

```kt
public Drink(){
}
public Drink(Parcel in) {
    dateAndTime = new Date(in.readLong());
    comments = in.readString();
    imageUri = in.readString();
}
```

1.  在`MainAdapter`类中，添加一个用于请求的私有变量。这种方法使您的代码更易读：

```kt
private int REQUEST_EDIT_ENTRY = 2;
```

### 提示

所谓的魔术数字很容易被误解，应尽量避免使用。这些和其他的示例仅用于演示目的，但在现实世界中，您应尽可能使用自解释的常量。在这里，`REQUEST_EDIT_ENTRY`比在代码中的某个地方只放置数字`2`更有意义。

1.  现在，在`MainAdapter`的`onCreateViewHolder`方法中我们之前创建的`onClick`方法中，我们可以启动一个新的条目活动并将所选的饮料作为参数传递。`onClick`方法的实现现在将如下所示：

```kt
v.setOnClickListener(new View.OnClickListener() {
    @Override
	    public void onClick(View view) {
        ViewHolder holder = (ViewHolder) view.getTag();
        if (view.getId() == holder.itemView.getId()) {
            Intent intent = new Intent(mContext,    
             EntryActivity.class);
            intent.putExtra("edit_drink", holder.mDrink);
    ((Activity)mContext).startActivityForResult(intent,  
              REQUEST_EDIT_ENTRY); }
    }
});
```

1.  在`EntryActivity`类的`onCreate`方法中，我们将检索并显示所选饮料的属性。将此实现添加到方法的末尾：

```kt
Intent intent = getIntent();
if (intent.hasExtra("edit_drink")) {
    Drink editableDrink = intent.getParcelableExtra("edit_drink");
    EditText editComment =    
     (EditText)findViewById(R.id.entry_edit_text_comment);
    editComment.setText(editableDrink.comments);
    if (editableDrink.imageUri != null) {
        mUri = Uri.parse(editableDrink.imageUri);
        Bitmap bitmap = getBitmapFromUri();
        ImageView preview = (ImageView) 
         findViewById(R.id.entry_image_view_preview);
        preview.setImageBitmap(bitmap);
    }
}
```

评论的 EditText 将填充评论，以便用户可以编辑它们。如果饮料条目附有图像，它将显示在预览图像视图中。现在，如果我们有一种简单而酷的方法将图像的缩略图动画到预览中：

1.  惊喜！有。在`res/values`文件夹中的`strings.xml`文件中添加一个新的字符串资源：

```kt
<string name="transition_preview">transition_preview 
  </string>
```

1.  在`MainAdapter`类的`onCreateViewHolder`方法中，在`onClick`实现中，并且在`startActivityForResult`方法之前，我们将使用`ActivityOptionsCompat`类来创建从缩略图（holder 的`mImageView`成员）到条目活动布局中预览图像的过渡：

```kt
ActivityOptionsCompat options =  
 ActivityOptionsCompat.makeSceneTransitionAnimation(
  ((Activity)mContext), holder.mImageView,    
   mContext.getString (R.string.transition_preview));
```

1.  通过用这个实现替换下一行上的`startActivityForResult`调用来提供这些选项：

```kt
ActivityCompat.startActivityForResult(((Activity) mContext),  
 intent, REQUEST_EDIT_ENTRY, options.toBundle());
```

1.  打开`adapter_main_card_view.xml`布局文件，并将此行添加到图像视图（具有`main_image_view`ID 的小部件）：

```kt
android:transitionName="@string/transition_preview"
```

1.  在`activity_entry.xml`布局中，也将此行添加到`ImageView`小部件（具有`entry_image_view_preview`ID 的小部件）。这样 Android 就知道缩略图到更大的预览图像的过渡应该去哪里）。

### 注意

使用字符串资源是一个好的实践。我们可以在这里使用这些资源，以确保我们在代码的任何地方都在谈论相同的过渡，但这也对本地化目的非常有用。

现在，如果您运行您的应用程序并点击`MainActivity`类中的任何卡片，您将看到缩略图被放大并适合于`EntryActivity`类的布局中预览图像的占位符。如果选择返回按钮，则显示反向过渡。在以前的版本中，我们不能只用几行代码来做到这一点！

### 主题

作为奖励，让我们按照以下步骤进行一些主题设置：

1.  访问[`www.materialpalette.com`](http://www.materialpalette.com)并选择两种颜色。主题设置出现了一个颜色集，我们可以将其用作主题，如下截图所示：![Theming](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_03_06.jpg)

1.  在`res/values`文件夹中创建一个`color.xml`文件，并添加建议的颜色名称和值。我在网站上选择了蓝色和靛蓝色，所以我的颜色资源文件看起来像这样：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="primary_dark">#1976d2</color><color name="primary">#2193f3</color>
    <color name="light_primary">#bbdefb</color>
    <color name="text">#ffffff</color>
    <color name="accent">#536dfe</color>
    <color name="primary_text">#212121</color>
    <color name="secondary_text">#727272</color>
    <color name="divider_color">#b6b6b6</color>
</resources>
```

1.  编辑`res/values`文件夹中的`styles.xml`文件，并使其看起来像这样：

```kt
<resources><style name="AppTheme" parent="Theme.AppCompat.Light">
      <item name="android:colorPrimary">@color/primary</item>
      <item name="android:colorPrimaryDark">@color/primary_dark 
      /item>
      <item name="android:colorAccent">@color/accent</item>
      <item name="android:textColor">@color/text</item>
      <item name="android:textColorPrimary">@color/primary_text 
      </item>
     <item name="android:textColorSecondary">
        @color/secondary_text
      </item>
  </style></resources>
```

上述代码的输出如下截图所示：

![Theming](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_03_07.jpg)

1.  修改您的布局文件并更改文本视图和其他元素，以便它可以反映颜色方案。运行应用程序。

## 它是如何工作的...

Android 的活动转换将处理一切。我们只需要告诉它什么，哪里以及如何。只需几行代码，API 就可以让您在活动之间创建有意义的转换，这将大大改善应用程序的用户体验。

每一步都让你的应用程序看起来越来越好！不幸的是，这就是材料设计介绍的结束。无论你想要在哪里进行改进，都可以随意尝试并享受乐趣！动画，用户体验和布局是高质量应用程序的重要元素。

对于可穿戴应用程序来说，这可能更加重要，正如我们将在下一章中看到的那样。但是，我们如何在如此小的屏幕上实现出色的用户体验呢？

## 还有更多...

我们只看到了材料设计的一些方面。还有很多东西等待我们去发现。

进一步改善应用程序的外观和用户体验，将实现添加到`MainActivity`类中以处理您添加的饮料条目的数据，并在需要时进行增强。或者，您可以查看现有的应用程序，看看如何将它们实现。


# 第四章：Android Wear

本章将向您介绍 Android Wear 以及它如何作为手表和其他设备实现的现象。

在本章中，您将学习以下内容：

+   可穿戴设备

+   全屏可穿戴应用

+   表盘

+   通知

# 可穿戴设备

Android Wear 是许多可穿戴设备运行的系统。您可能自己有一块智能手表。可穿戴设备会成为继手机、平板电脑之后的下一个热潮吗？还是智能手表会成为更大事物的一部分，比如**物联网**（**IoT**）？

Android Wear 是 Android SDK 的一个特殊版本，专门用于通常在硬件和可用传感器方面更受限制、屏幕更小的可穿戴设备。可穿戴设备可能出现为手表、眼镜，或者将来可能会出现为隐形眼镜、纹身或服装。

目前，我们看到可穿戴设备主要出现在手表上，但您可以想到还有许多其他可穿戴设备。然而，人们需要一些时间来接受这项新技术。例如，想想谷歌眼镜项目。这是一个很棒的解决方案，但主要是因为内置摄像头，人们对它有严重的反对意见。在旧金山，他们甚至为此创造了一个词：glass hole。嗯。这真的不太讨人喜欢，对吧？让我们看看以下设备：

![可穿戴设备](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_01.jpg)

设备不一定要是可穿戴的。当讨论 IOT 时，项目 Brillo 就会浮现在脑海中。它将 Android 平台扩展到您能想到的任何连接设备上。未来，Brillo 和 Android Wear 甚至可能会合并。

想象一个炎热的夏日；冰箱通知我们即将用完气泡水（还是啤酒？）。酷！学习型恒温器在您回家前一小时将温度设定为 18°C。更酷！客厅的灯光自动调暗，因为现在是晚上；您正在播放一些浪漫的音乐，系统知道您刚刚打开了一瓶葡萄酒-嗯。奇怪。这是一个完全不同的故事，Brillo 现在也是如此。

相反，让我们找出我们可以为智能手表构建哪些应用，比如全新的表盘或健康应用程序，不时显示通知。在接下来的步骤中，我们将看到为此需要做些什么。

首先，让我们看看我们是否可以在可穿戴设备上运行起来。在前两个步骤中，您不需要拥有真正的智能手表。我们将在第一个步骤中创建一个虚拟的智能手表。

# 全屏可穿戴应用

可穿戴全屏应用程序确实有手机（或其他手持设备）和可穿戴组件。用户在手机上安装手持应用程序，可穿戴组件会自动推送到配对的可穿戴设备上。

这是探索为可穿戴设备开发应用程序的有趣世界的一个很好的开始，因为它们基本上与 Android 手机应用程序相同。然而，谷歌鼓励您将应用程序与 Android Wear 的上下文流集成在一起。这个上下文流包含各种有趣的信息。可以将它们视为收件箱中的新邮件、天气、今天走的步数或心率。我们将在有关通知的食谱中了解更多信息。

## 准备就绪

要完成这个食谱，您需要确保 Android Studio 已经运行起来。还要确保您已安装了最新的 SDK，包括 Android Wear SDK。当您打开 SDK 管理器时，可以检查是否已经安装了这些（导航到**工具**菜单，**Android SDK 管理器**），如下截图所示： 

![准备就绪](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_02.jpg)

## 如何做...

让我们看看如何创建我们自己的可穿戴应用，并通过以下步骤在虚拟设备上运行它：

1.  开始一个新的 Android Studio 项目。将应用命名为`WatchApp`，并在**公司域**字段中输入`packtpub.com`。然后，点击**下一步**按钮。

1.  在下一个对话框中，勾选**手机和平板电脑**。还要勾选**可穿戴设备**选项。

1.  对于这两个选项，选择**API 21**或更高版本，然后点击**下一步**按钮。

1.  在**添加到 wear 的活动**对话框中，选择**空白 wear 活动**，然后点击**下一步**按钮。

1.  选择**空白活动**，然后点击**下一步**按钮。

1.  将您的新活动命名为`PhoneActivity`，然后点击**下一步**按钮。

1.  选择**空白 wear 活动**，然后点击**下一步**按钮，如下一个截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_03.jpg)

1.  将您的新 wear 活动命名为`WatchActivity`，然后点击**完成**按钮。

1.  Android Studio 将创建两个模块：`mobile`和`wear`。移动模块在智能手机（或平板电脑或平板电脑）上运行。wear 应用程序将被推送到配对的可穿戴设备，例如您的智能手表。项目视图现在看起来像这样：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_04.jpg)

1.  让我们看看默认情况下它在智能手机上的样子。为此，我们将创建一个可穿戴虚拟设备。从**工具**菜单中，选择**Android**选项，然后选择**AVD Manager**选项。

1.  然后，点击**创建虚拟设备**按钮。

1.  在弹出的对话框中，在**类别**列表中选择**Wear**。在旁边的列表中选择**Android Wear Round**设备，然后点击**下一步**按钮，如下一个截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_05.jpg)

1.  在下一个对话框中，选择一个系统镜像，例如**棒棒糖**，**API 级别 21**，**x86**（如果可用，也可以选择更高级别。您可能需要先点击**下载**链接）。然后，点击**下一步**按钮继续。

1.  给您的虚拟设备起一个好听的名字，然后点击**完成**按钮。您的新 Android wear 设备现在将出现在列表中，如下一个截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_06.jpg)

1.  点击播放图标启动设备。

1.  虚拟设备启动后，将配置更改为**wear**，然后点击工具栏旁边的**运行**按钮。![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_07.jpg)

应用程序安装完成后，将如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_08.jpg)

如果**Hello Round World!**消息没有立即出现，那么该应用程序可能已安装，但可能尚不可见。多次滑动屏幕以检查是否存在。

如果您的应用程序已经运行，那么现在是时候探索更有趣的东西了。让我们在下一个教程中创建一个表盘。

## 还有更多...

在撰写本文时，Genymotion 尚不支持可穿戴设备。这就是为什么在本教程中我们使用默认的模拟器。

但那个太慢了！您可能会说。这是真的，但通过安装 HAXM，您可以使它快一点。关于这个主题有一些有趣的信息，可以在[`developer.android.com/tools/devices/emulator.html`](http://developer.android.com/tools/devices/emulator.html)找到。

如果您确实有真实设备，当然也可以在智能手表上部署您的应用程序。如果要这样做，您还需要在手持设备上安装 Android wear 配套应用程序，因为您无法直接在其上安装和测试可穿戴应用程序。

您可以从 Google Play 获取这个配套应用。下载应用程序，安装它，并通过 USB 连接您的手持设备。

## 另请参阅

+   参考第一章中的*使用名为 Genymotion 的模拟器测试您的应用程序*部分，*欢迎使用 Android Studio*

# 表盘

您的 Android 智能手表默认配备了各种表盘，还有许多其他表盘可供下载。它们以任何形状或类型提供：方形和圆形，模拟和数字。实际上，甚至还有另一种形状 - 所谓的平坦轮胎形状 - 就像 Moto 360 设备上看到的那样。

有许多自定义选项，但所有的表盘都是为了以简单的方式显示时间和日期信息。这首先是手表的用途，不是吗？

他们应该注意到即将到来的通知，还需要为系统指示器腾出空间，例如电池寿命图标和**Ok Google**文本。有关更多信息，请访问[`developer.android.com/design/wear/watchfaces.html`](https://developer.android.com/design/wear/watchfaces.html)。

在即将创建的示例中，我们将创建一个手表表盘，告诉你时间，例如**七点半**或**十点五分钟**。

## 准备工作

要完成本示例，您需要运行 Android Studio。还要确保已安装了最新的 SDK，包括 Android Wear SDK。您可以通过打开 SDK 管理器来检查是否已安装，该管理器可在**工具**菜单下的**Android**中找到，该菜单项位于**SDK Manager**下。

## 操作步骤

让我们按以下步骤创建一个手表表盘应用的新 Android 项目：

1.  创建一个新的 Android Studio 项目。

1.  将应用命名为`HelloTime`，或者您想要的应用名称。在**公司域**字段中输入`packtpub.com`，然后单击**下一步**按钮。

1.  在下一个对话框中，勾选**手机和平板**。还要勾选**Wear**选项。

1.  对于这两个选项，选择**API 21**或更高版本，然后单击**下一步**按钮。

1.  选择**空白活动**，并单击**下一步**按钮。

1.  将新的活动命名为`PhoneActivity`，并单击**下一步**按钮。

1.  选择**表盘**，并单击**下一步**按钮。

1.  将表盘命名为`HelloTimeWatchFace`，并选择**数字**作为**样式**。之后，点击**完成**按钮。

1.  Android Studio 将为手机或平板和可穿戴设备创建必要的模块。

1.  在项目视图中，打开`wear`模块的`HelloTimeWatchFace`类。

1.  在`wear`模块的`res/values`文件夹中打开`strings.xml`文件，并将`my_digital_name`的字符串更改为`Hello Time!`

1.  让我们看看我们到目前为止得到了什么。启动虚拟（或真实的）可穿戴设备。如果你不知道如何创建虚拟可穿戴设备，请参考上一个示例。

1.  虚拟设备启动后，将配置更改为**Wear**，并单击工具栏旁边的**运行**按钮，如下图所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_09.jpg)

1.  在可穿戴设备上，滑动查看**设置**图标并点击它。

1.  向下滑动到**更改表盘**，并点击它。

1.  向右滑动，直到看到**Hello Time!**表盘，然后点击它。

1.  您现在将看到 Android Studio 为您创建的数字表盘。

让我们稍微检查一下这段代码。为你创建的`HelloTimeWatchFace`类扩展了`CanvasWatchFaceService`，并添加了一个内部的`Engine`类。引擎有一个处理程序，以便可以更新时间。它还有一个广播接收器，将处理用户在旅行时移动到另一个时区的情况。

`Engine`类有一些有趣的方法。`onCreate`方法分配了两个`Paint`对象：一个用于背景，一个用于前景（文本）。`onVisibilityChanged`方法将在用户显示或隐藏表盘时调用。`onApplyWindowInSets`方法用于确定应用是否在圆形或方形屏幕上运行。

接下来是`onPropertiesChanged`方法，一旦可穿戴设备的硬件属性已知，例如是否支持低位环境模式，就会调用该方法。`onAmbientModeChanged`方法非常重要，因为它可以节省电池。它还可以用于应用防烧屏保护。在这里，您可能想要更改背景或前景的颜色。

让我们改变时间的显示方式：

1.  添加一个以口语语言返回当前时间的方法，类似于这样：

```kt
private String[] getFullTextTime(){
    String time = "";Calendar cal = Calendar.getInstance();
   int minute = cal.get(Calendar.MINUTE);
   int hour = cal.get(Calendar.HOUR);
   if (minute<=7){
        time = String.format("%s o'clock",   getTextDigit(hour));
    }
   else if (minute<=15){
        time = String.format("ten past %s",    getTextDigit(hour));
    }
   else if (minute<=25){
       time = String.format("Quarter past %s", getTextDigit(hour));
    }
   else if (minute<=40){
       time = String.format("Half past %s", getTextDigit(hour));
   }
  else if (minute<53){
       time = String.format("Quarter to %s",  
       getTextDigit(hour));
  }
  else {
       time = String.format("Almost %d o'clock", (hour<=11)? hour+1: 1);
  }
  return time.split(" ");
}
```

1.  添加此方法以将数字转换为文本：

```kt
private String getTextDigit(int digit){
    String[] texts ={ "twelve", "one", "two", "three",  
     "four", "five", "six", "seven", "eight", "nine",       
       "eleven"};
     return texts[digit];
```

1.  在`onDraw`方法中，用这里显示的行替换`canvas.DrawText`部分。此方法显示口语语言中当前时间的多行：

```kt
String[] timeTextArray = getFullTextTime();
float y = mYOffset;
for (String timeText : timeTextArray){
    canvas.drawText(timeText, mXOffset, y, mTextPaint);
    y+=65;
}
```

### 注意

**魔术并不总是很酷...**

等等！在上一步中那个魔术数字是在做什么？65 实际上并没有意义。这是什么意思？它是做什么的？在您的类中的某个地方创建一个常量值，并使用该变量名称（在这里最好将值放在尺寸资源文件中，但我们稍后会看到这一点，所以现在让我们暂时忘记它）：

```kt
private static final int ROW_HEIGHT  = 65;
y+= ROW_HEIGHT;
```

1.  转到`onCreate`方法，并添加此行以使文本以漂亮的绿色显示（是的，`GREEN`也是一个常量）：

```kt
mTextPaint.setColor(Color.GREEN);
```

再次运行您的应用程序。它会看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_10.jpg)

为了以后准备好 Play 商店的手表表盘，您需要在完成后拍摄屏幕截图。您需要为方形和圆形手表提供屏幕截图。在`res/drawable`文件夹中，您会找到 Android Studio 为您创建的默认预览图像。

目前，您只是以最基本的形式创建了您的第一个手表表盘应用程序。在下一个食谱中，我们将看到通知到来时会发生什么。

## 还有更多...

本食谱中的手表表盘应用程序远非完美。文本未对齐；它没有正确响应环境模式的更改，您可能希望将其本地化以以您自己的语言显示时间。

要了解这可能会发展成什么样，您可以查看 Play 商店中已经可用的许多手表表盘。

# 通知

Android Wear 与在手机或平板上运行的应用程序有所不同。 Android Wear 使用卡片，而不是图标和列表，这是我们在介绍材料设计基本概念的食谱中已经看到的东西。

根据上下文，并且只在相关时刻，一旦新通知到达，就会向卡片流中添加一张卡片。这被称为上下文流，其中包含各种有趣的信息。将它们视为收件箱中的电子邮件，天气，今天走的步数，心率，以及其他事件或提醒。

还记得上一章的饮水应用程序吗？例如，我们可以创建一个提醒我们更频繁饮水并为其添加新卡片的通知。这将是一个很好的功能。

## 准备工作

此食谱需要安装 Android Studio 和最新的 SDK，包括 wear SDK。有关更多信息，请查看上一个食谱。

您还需要一台运行 Android Lollipop 或更高版本的手持设备，该设备已安装`Android Wear`应用程序，并且通过蓝牙连接到您的手持设备的可穿戴设备。

## 如何做...

让我们看看如何触发通知以及如何在智能手表上漂亮地显示它们：

1.  在 Android Studio 中创建一个新项目。将其命名为`WaterNowNotification`，然后单击**下一步**按钮。

1.  选择**手机和平板电脑**作为智能手表平台。不要选择**Wear**选项。然后单击**下一步**按钮。

1.  选择**空白活动**，然后单击**下一步**按钮。

1.  将您的活动命名为`WaterNowActivity`，然后单击**完成**按钮。

1.  在您的应用中打开`build.gradle`文件。将其添加到依赖项部分并应用适当的版本：

```kt
compile 'com.android.support:support-v4:22.0+'
```

1.  单击工具栏上可以找到的**与 Gradle 文件同步项目**按钮。

1.  打开`activity_water_now.xml`文件，并使用 Android Studio 底部的选项卡将其更改为**文本**模式。

1.  创建一个带有按钮的布局，我们将用它来发送测试通知：

```kt
<LinearLayout

android:layout_width="match_parent"
android:layout_height="match_parent"
android:orientation="vertical"
tools:context=".WaterNowActivity">
<Button
android:layout_width="wrap_content"
android:layout_height="wrap_content"
android:text="Drink water now!"
android:id="@+id/water_now_button"
android:layout_gravity="center" />
</LinearLayout>
```

1.  在`WaterNowActivity`类的`onCreate`方法中，添加一个`onClick`处理程序，用于刚刚创建的按钮。根据需要使用*Alt* + *Enter*快捷键添加导入语句：

```kt
Button waterNowButton = (Button)findViewById(R.id.water_now_button);
waterNowButton.setOnClickListener(new View.OnClickListener() {
@Override
        public void onClick(View v) {
        sendNotification();   }
});
```

1.  创建`sendNotification`方法：

```kt
private void sendNotification(){
    NotificationCompat.Builder notificationBuilder =
    new NotificationCompat.Builder(   
      WaterNowActivity.this)
      .setContentTitle("Water app!")
      .setSmallIcon(R.drawable.icon)
      .setContentText("Hey there! Drink water now!");
    NotificationManagerCompat notificationManager =NotificationManagerCompat.from(  
      WaterNowActivity.this);
    notificationManager.notify(1 ,   
     notificationBuilder.build());
}
```

1.  通知确实需要一个图标，所以在`res/drawable`文件夹中创建一个。创建一个 drawable `icon.xml`文件，并添加实现以创建一个漂亮的蓝色圆圈：

```kt
<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android= "http://schemas.android.com/apk/res/android"android:shape="oval">
<corners android:radius="10dip"/>
<stroke android:color="#0000FF" android:width="15dip"/>
<solid android:color="#0000FF"/>
</shape>
```

1.  连接你的手持设备；确保可穿戴设备已连接（使用`Android wear`应用来检查），然后运行应用。你会看到类似以下截图的输出：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_11.jpg)

1.  点击应用内的**现在喝水**按钮。

1.  手机上会显示类似以下截图的通知。如果通知没有立刻出现，屏幕顶部会有一些指示。在这种情况下，打开通知中心查看。![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_12.jpg)

1.  如果一切正常并且配置正确，同样的通知会出现在可穿戴设备上，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-cb/img/B04299_04_13.jpg)

1.  如果通知在你的手机上显示，但在你的可穿戴设备上没有出现，那么请验证**通知访问**设置。打开**设置**应用，选择**声音和消息**。接下来，选择**通知访问**，并检查**Android Wear**选项是否已被选中。

对于其他 Android 版本或特定品牌（定制的 Android 版本），你要找的设置可能在其他地方，或者可能有不同的名称。

## 还有更多...

接下来怎么办？你可以将这个通知配方与第三章中的 Water 应用配方相结合，创造出更酷的东西，或者你可以检查是否可以找到一种自定义通知的方法。

智能手表、手机、平板手机和平板电脑都配备了各种尺寸和形状的屏幕。我们如何从更大的屏幕中受益，或者如何为较小的屏幕提供智能导航，并在一个应用中保持相同的功能和代码？

不同 Android 版本的不同布局？多个布局与多个片段的结合正是我们需要的。这就是下一章中的配方发挥作用的地方。

## 另请参阅

+   参考第三章中的*RecyclerView*和*CardView*部分，*材料设计*

+   参考第五章, *尺寸很重要*
