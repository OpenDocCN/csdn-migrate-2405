# 构建 Cocos2dx 安卓游戏（一）

> 原文：[`zh.annas-archive.org/md5/C5B09CE8256BCC61162F0F46EF01CFDE`](https://zh.annas-archive.org/md5/C5B09CE8256BCC61162F0F46EF01CFDE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Cocos2d-x 是最常使用的开源游戏框架。它得到了微软对其移动和桌面平台官方支持，其小巧的核心运行速度比其他框架快，使得它能在低端 Android 设备上表现出色。目前，它由一个活跃的开源开发社区维护，该社区由原始 Cocos2d for iPhone 的作者和触控科技领导。

这本入门书籍将指导你从零开始创建一个简单的二维 Android 游戏。在这个过程中，你将学习 Cocos2d-x C++跨平台游戏框架的基础知识，如何处理精灵，为游戏添加物理效果，播放声音，显示文本，使用粒子系统生成逼真的爆炸效果，以及如何使用 Java Native Interface (JNI)添加原生 Android 功能。

# 这本书涵盖的内容

第一章，*配置你的开发环境*，逐步指导你配置 Cocos2d-x 及其所有先决条件。

第二章，*图形*，介绍了如何处理背景、精灵，以及如何使用精灵表提升性能来动画化它们。

第三章，*理解游戏物理*，展示了基于 Chipmunk 的新 Cocos2d-x 物理引擎的基础知识，该引擎在 Cocos2d-x 3.0 版本中引入。我们将创建基于物理的物体，为它们添加重力，并检测碰撞。

第四章，*用户输入*，我们在这里为游戏添加交互功能，使其能够通过触摸监听器和加速度计与用户互动。

第五章，*处理文本和字体*，证明了处理文本对于游戏开发至关重要。无论你的游戏复杂性如何，你都有可能显示信息，有时需要使用外文字符集。这一章展示了如何使用简单的 TrueType 字体和更具风格的位图字体，使你的游戏看起来更专业。

第六章，*音频*，说明了玩游戏时的情感部分来自于音乐和音效。在这一章中，你将学习如何使用 CocosDenshion 音频引擎为你的游戏添加背景音乐和音效，该音频引擎自原始 Cocos2d iPhone 游戏引擎以来一直存在。这一章还涵盖了如何使用新的音频引擎播放媒体，并突出了它们之间的主要区别。

第七章，*创建粒子系统*，说明了如何使用内置的粒子系统引擎创建逼真的爆炸、火焰、雪和雨效果。这一章还展示了当你需要定制效果时，如何创建自己的粒子系统，使用最受欢迎的工具。

第八章，*添加原生 Java 代码*，在你需要为 Cocos2d-x 游戏活动内部创建和调用 Android 特定行为时为你提供帮助。我们通过使用 Android 平台可用的 Java 原生接口（JNI）机制来实现这一点。

# 你需要这本书的内容

为了跟随本书的叙述并能够重现所有步骤，你需要一台装有 Windows 7 或更高版本操作系统的 PC，任何 Linux 发行版或运行 OS X 10.10 Yosemite 的 Mac。我们将在书中使用的许多工具都是可以免费下载的。我们解释了如何下载和安装它们。

# 本书适合的读者

这本书是为那些在游戏编程方面几乎没有经验，但具备 C++编程语言知识，并且愿意以非常全面的方式创建他们的第一款 Android 游戏的人编写的。

# 约定

在这本书中，你会发现多种文本样式，这些样式区分了不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码字、文件夹名、文件名、文件扩展名、路径名、虚拟 URL 和用户输入如下所示："为了向我们的游戏添加加速度计支持，我们首先将在`HelloWorldScene.h`头文件中添加以下方法声明。"

代码块设置如下：

```java
void HelloWorld::movePlayerByTouch(Touch* touch, Event* event)
{
  Vec2 touchLocation = touch->getLocation();
  if(_sprPlayer->getBoundingBox().containsPoint(touchLocation)){
    movePlayerIfPossible(touchLocation.x);
  }
}
```

当我们希望引起你对代码块中某个特定部分的注意时，相关的行或项目会以粗体显示：

```java
   Size screenSize = glview->getFrameSize();
   Size designSize(768, 1280);
   std::vector<std::string> searchPaths;   
   searchPaths.push_back("sounds");

```

任何命令行输入或输出都如下编写：

```java
cocos new MyGame -p com.your_company.mygame -l cpp -d NEW_PROJECTS_DIR

```

**新术语**和**重要词汇**以粗体显示。你在屏幕上看到的内容，例如菜单或对话框中的单词，在文本中如下所示："点击**下一步**按钮，你会进入下一个屏幕。"

### 注意

警告或重要注意事项会像这样出现在一个框中。

### 提示

技巧和诀窍会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或可能不喜欢的内容。读者的反馈对我们来说很重要，它帮助我们开发出你真正能从中获得最大收益的图书。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果你在一个主题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然你现在拥有了 Packt 的一本书，我们有一系列的事情可以帮助你从购买中获得最大收益。

## 下载示例代码

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的账户下载你所购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

## 错误更正

尽管我们已经尽力确保内容的准确性，但错误仍然会发生。如果你在我们的书中发现错误——可能是文本或代码中的错误——我们会非常感激你能向我们报告。这样做，你可以让其他读者免受挫折，并帮助我们在后续版本中改进这本书。如果你发现任何错误更正，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择你的书，点击**错误更正提交表单**链接，并输入你的更正详情。一旦你的更正被验证，你的提交将被接受，并且更正将在我们网站的相应标题下的错误更正部分上传或添加到现有的错误更正列表中。任何现有的错误更正可以通过在[`www.packtpub.com/support`](http://www.packtpub.com/support)选择你的标题来查看。

## 盗版

网络上的版权材料盗版问题在所有媒体中持续存在。在 Packt，我们非常重视保护我们的版权和许可。如果你在互联网上以任何形式遇到我们作品非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如发现疑似盗版材料，请通过`<copyright@packtpub.com>`联系我们，并提供相关链接。

我们感谢你帮助保护我们的作者，以及我们为你提供有价值内容的能力。

## 问题

如果你在这本书的任何方面遇到问题，可以通过`<questions@packtpub.com>`联系我们，我们将尽力解决。


# 第一章：设置你的开发环境

在本章中，我们将解释如何下载并设置所有需要的工具，以便开始为 Android 平台构建游戏的环境。尽管 Mac OS 和 Windows 开发环境之间有很大的相似性，但我们将涵盖这两个操作系统安装的所有细节。

本章节将涵盖以下主题：

+   Cocos2d-x 概述

+   安装 Java

+   安装 Android SDK

+   安装 Android 原生开发工具包（NDK）

+   安装 Apache Ant

+   安装 Python

+   安装 Cocos2d-x

+   安装 Eclipse IDE

+   模板代码演练

# Cocos2d-x 概述

Cocos2d-x 是流行的 iOS 游戏框架 Cocos2d 的 C++跨平台移植版本。它最初于 2010 年 11 月发布，并在 2011 年被北京一家移动游戏公司触控科技收购。尽管如此，它仍然由一个超过 40 万开发者的活跃社区维护，包括原始 Cocos2d iPhone 引擎的创造者 Ricardo Quesada。

这个框架封装了所有游戏细节，如声音、音乐、物理、用户输入、精灵、场景和过渡等，因此开发者只需关注游戏逻辑，而无需重新发明轮子。

# 安装 Java

Android 平台技术栈基于 Java 技术；因此，首先要下载的是 Java 开发工具包（JDK）。尽管在撰写本书时 Java JDK 8 是最新版本，但它并不被所有 Android 版本官方支持，因此我们将下载 JDK 6，所有由 Cocos2d-x 生成的模板 Java 代码都可以用这个版本成功编译。

### 注意

Java 运行环境（JRE）对于构建 Android 应用程序来说是不够的，因为它只包含了运行 Java 应用程序所需的文件，但它不包括构建 Java 应用程序所需的工具。

你可以从 Oracle 的[`www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-javase6-419409.html`](http://www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-javase6-419409.html)下载 JDK 6，无论你的开发环境是什么。

如果你的当前环境是 Windows，那么在安装 JDK 之后，你需要将二进制文件所在路径添加到 PATH 环境变量中。这个路径看起来像这样：`C:\Program Files\Java\jdk1.6.0_45\bin`。

打开一个新的系统控制台，输入 `javac –version`，如果显示了 Java 编译器的版本号，那么你已经成功在你的系统中安装了 JDK。

### 注意

JDK 7 是用于构建针对 Android 5.0 及以上版本应用程序所需的。如果你针对的是最新 Android 版本，应该下载这个版本。但是，如果你想你的游戏兼容低于 4.4 的 Android 版本，那么你应该选择 JDK 6。

# 安装 Android SDK

Android SDK 包含构建 Android 应用所需的所有命令行工具。它有适用于 Windows、Mac 和 GNU/Linux 操作系统的版本。

Android Studio 现在是唯一官方支持的 IDE；尽管如此，Cocos2d-x 3.4 只提供对 Eclipse 的即开即用支持，Eclipse 是之前的官方 Android 开发 IDE。它不再可供下载，因为它已经不再积极开发，但你可以手动下载 Eclipse 并按照以下步骤安装 **Android Development Tools** (**ADT**)。

## 下载 Android SDK

你可以从链接 [`developer.android.com/sdk`](http://developer.android.com/sdk) 下载 Android SDK。在页面底部，在 **Other Download Options** 下，你会找到下载 SDK 工具的选项。选择与你的操作系统相匹配的版本。

在撰写本书时，SDK 的最新版本是 24.0.2。

运行 Android SDK 安装程序并在你的计算机上安装 Android SDK。

安装完 Android SDK 后，它还不能立即用来构建 Android 应用。因此，在安装向导的最后一屏，勾选 **Start SDK Manager** 的复选框，以便你可以下载构建游戏所需的组件，如下面的截图所示：

![下载 Android SDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_01_01.jpg)

当 Android SDK 管理器启动后，从 `Tools` 文件夹中选择 **Android SDK Platform-tools** 和 **Android SDK Build-tools**。然后选择你所需 API 级别中的 **SDK Platform**，如下面的截图所示：

![下载 Android SDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_01_02.jpg)

## 下载 Eclipse

从 [`www.eclipse.org/downloads`](http://www.eclipse.org/downloads) 下载 Eclipse IDE for Java Developers 的最新版本。它会推荐与你的当前操作系统兼容的下载版本，选择最适合你的操作系统平台的版本，可以是 32 位或 64 位。

在撰写本书时，Eclipse Luna (4.4.1) 是最新版本。

## 设置 Eclipse ADT 插件

打开 Eclipse，导航到 **Help** | **Install new Software** 并添加 Eclipse ADT 下载位置，即 `https://dl-ssl.google.com/android/eclipse/`，如下面的截图所示：

![设置 Eclipse ADT 插件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_01_03.jpg)

点击 **OK**，然后勾选 **Developer Tools** 复选框，点击 **Next** 以完成 ADT 安装向导。

# 设置 Android 原生开发工具包

我们已经下载了允许你使用 Java 技术创建 Android 应用的 Android SDK；尽管如此，Cocos2d-x 框架是用 C++ 编写的，因此你需要 Android 原生开发工具包（NDK）以便为 Android 平台构建 C++ 代码。

### 注意

Android 的官方文档明确指出，你应该在特定情况下使用这个本地工具包，但不要仅仅因为熟悉 C++ 语言或希望应用程序运行更快而使用它。制造商提出这个建议是因为 Android 核心 API 只对 Java 语言可用。

下载最新的 NDK 版本。在本书编写时，最新的版本是 10d。这个版本的 NDK 将允许你为所有 Android 平台构建，包括最新的。

你可以从以下链接下载适用于所有平台的最新版本 Android NDK：

[`developer.android.com/tools/sdk/ndk`](https://developer.android.com/tools/sdk/ndk)

下载后，运行可执行文件。它将在当前路径解压 Android NDK 目录；你需要记住这个路径，因为你稍后需要用到。

# 设置 Apache Ant

Apache Ant 是一个广泛用于自动化 Java 项目构建过程的构建管理工具。从 Cocos2d-x 3.0 开始引入，用于为 Android 平台构建框架。它简化了 Android 的构建过程，并增强了跨平台构建。在 Cocos2d-x 2.x 时代，在 Windows 操作系统内构建 Android 应用需要通过使用 Cygwin 模拟 UNIX 环境。这需要一些小的修改才能成功构建代码，其中许多修改在官方 Cocos2d-x 网站上仍然没有记录。

这个工具可以从以下链接下载：[`www.apache.org/dist/ant/binaries/`](https://www.apache.org/dist/ant/binaries/)

在编写本书时，最新的版本是 1.9.4。这个工具是一个跨平台工具，所以一个下载文件可以在任何支持 Java 技术的操作系统上工作。

为了安装这个工具，只需解压文件。记住这个路径，因为你在 Cocos2d-x 设置过程中需要用到。

# 设置 Python

所有 Cocos2d-x 配置文件都是用 Python 编写的。如果你使用的是 Mac OS 或任何 Linux 发行版，你的操作系统已经预装了 Python。因此，你可以跳过这一部分。

如果你使用的是 Windows 系统，你需要从以下链接下载 Python 2：[`www.python.org/ftp/python/2.7.8/python-2.7.8.msi`](https://www.python.org/ftp/python/2.7.8/python-2.7.8.msi)。

请考虑 Python 和 Cocos2d-x 同时支持版本 2 和版本 3。Cocos2d-x 只支持 Python 2。在编写本书时，2.x 分支的最新版本是 2.7.8。

安装程序设置完成后，你应该手动将 Python 安装路径添加到 PATH 环境变量中。默认的安装路径是`C:\Python27`。

打开一个新的系统控制台并输入`python`，如果出现如下截图所示的 Python 控制台，那么意味着 Python 已经正确安装：

![设置 Python](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_01_04.jpg)

### 注意

在 Windows 上设置环境变量，点击**开始**按钮并输入：`编辑系统环境`变量，点击它然后点击**环境变量**按钮，接着将显示环境变量配置对话框。

# 设置 Cocos2d-x

既然你已经拥有了构建 Android 平台上的第一款 Cocos2d-x 游戏所需的所有前提条件，你将需要下载 Cocos2d-x 3.4 框架，并按照以下步骤进行设置：

1.  你可以从[`www.cocos2d-x.org/download`](http://www.cocos2d-x.org/download)下载源代码。请注意，此页面还提供了下载 Cocos2d-x 分支 2 的链接，本书不涉及此分支，而且制造商已正式宣布新特性仅在分支 3 中提供。

1.  下载压缩的 Cocos2d-x 源代码后，将其解压到你想要的位置。

1.  为了配置 Cocos2d-x，打开你的系统终端，定位到你解压它的路径，并输入`setup.py`。这将需要你指定`ANDROID_NDK_PATH`，在这里你需要指定之前在前面章节解压的 NDK 的根目录。其次，它将需要你指定`ANDROID_SDK_ROOT`，这里你需要指定在安装过程中你选择安装 Android SDK 的目录路径。然后，它将需要你设置`ANT_ROOT`，在这里你需要指定 ant 安装的根目录。最后，关闭终端，并打开一个新的终端，以便更改生效。

## 创建你的第一个项目

现在，Cocos2d-x 已经设置好了，可以开始创建你的第一个项目了。你可以通过输入以下命令来完成：

```java
 cocos new MyGame -p com.your_company.mygame -l cpp -d NEW_PROJECTS_DIR

```

此脚本为你创建了一个 Android 模板代码，你的游戏将运行在所有包含 Android API 9 或更高版本的 Android 设备上，即 Android 2.3（姜饼）及更高版本。

需要注意的是，包名应该恰好包含两个点，如示例所示，如果少于或多于两个点，项目创建脚本将无法工作。`–l cpp`参数意味着新项目将使用 C++作为编程语言，这是本书唯一涵盖的语言。

与 2.x 分支相反，Cocos2d-x 3.x 允许你在框架目录结构之外创建你的项目。因此，你可以在任何位置创建你的项目，而不仅仅是像之前版本那样在`projects`目录内。

这将需要一些时间，因为它会将所有框架文件复制到你的新项目路径中。完成后，将你的 Android 设备连接到电脑上，然后你可以在新项目路径中通过输入以下命令轻松运行模板`HelloWorld`代码：

```java
cocos run -p android

```

或者，无论你当前在终端的路径如何，都可以运行以下命令：

```java
cocos run -p android /path/to/project

```

### 注意

要为 Windows 构建和运行 Cocos2d-x 3.4，您需要 Microsoft Visual Studio 2012 或 2013。

现在，您应该能够看到 Cocos2d-x 的标志和显示**Hello World**的文字，如下面的图片所示：

![创建您的第一个项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_01_05.jpg)

## 设置 Eclipse IDE

Cocos2d-x 3 分支显著改进了安卓构建过程。

在 2 分支中，需要在 IDE 中手动配置许多环境变量，导入许多核心项目，并处理依赖关系。即使完成所有步骤后，Cygwin Windows UNIX 端口与 Eclipse 的集成也从未完善，因此需要一些小的修改。

在 Eclipse 中构建 Cocos2d-x 3.4 就像导入项目并点击**运行**按钮一样简单。为了实现这一点，在 ADT 中，转到**文件** | **导入** | **通用** | **将现有项目导入工作空间**，选择 Cocos2d-x 在上一个部分创建新项目的路径。然后点击**完成**。

### 提示

Cocos2d-x 安卓模板项目是使用 API 级别 10 作为目标平台创建的。如果您系统上没有安装这个版本，您应该通过从包浏览器中右键点击项目，点击**属性**，并从**项目构建目标**框中选择您喜欢的已安装的安卓 API 版本来进行更改。

现在，在包浏览器中右键点击项目名称，点击**作为运行**，最后点击**安卓应用程序**。将会显示以下弹出窗口，要求您指定要启动 Cocos2d-x 游戏的安卓设备：

![设置 Eclipse IDE](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_01_06.jpg)

选择您的安卓设备后，您将看到我们在前一部分运行**运行**命令时所显示的 HelloWorld 游戏场景。

# 模板代码演练

在这一部分，我们将解释由项目创建脚本在上一个部分生成的 Cocos2d-x 模板代码的主要部分。

## Java 类

我们的项目中现在有一个名为`AppActivity`的 Java 类，它没有成员并从核心库中的`Cocos2dxActivity`类继承。我们还可以看到项目中引用了核心库中的 22 个 Java 类。这段代码旨在使我们的 C++代码工作，我们完全不需要修改它。

## 安卓应用程序配置

生成的`AndroidManifest.xml`是 Android 配置文件，它需要`android.permission.INTERNET`权限，该权限允许你的 Android 应用程序使用设备上的互联网连接；然而，由于我们的简单游戏代码没有互联网交互，所以并不需要这个权限。因此，如果你愿意，可以删除`AndroidManifest.xml`文件中的这一行。你的游戏默认会以横屏显示，但如果你希望创建一个在竖屏模式下运行的游戏，那么你应该将`android:screenOrientation`的值从`landscape`更改为`portrait`。

为了更改 Android 应用程序名称，你可以修改位于`strings.xml`文件中的`app_name`值；这将影响启动器图标上的文字和 Android 系统内的应用程序标识符。

当你创建自己的游戏时，你将不得不创建自己的类，这些类通常会比脚本创建的两个类多。每次你创建一个新类时，都需要将其名称添加到新项目目录结构中`jni`文件夹内的`Android.mk`制作文件的`LOCAL_SRC_FILES`属性中。这样，当你的`cpp`代码由 C++ 构建工具构建时，它会知道应该编译哪些文件。

## C++ 类

已经创建了两个 C++ 类：`AppDelegate`和`HelloWorldScene`。第一个负责启动 Cocos2d-x 框架并将控制权传递给开发者。框架加载过程发生在这个类中。如果 Cocos2d-x 核心框架在目标设备上成功启动，它将运行`applicationDidFinishLaunching`方法，这是要运行的首个游戏特定功能。

代码非常直观，并且有详细的文档，以便你可以轻松理解其逻辑。我们对代码的第一次小改动将是隐藏默认显示在示例游戏中的调试信息。你可以猜测，为了实现这一点，你只需为`director`单例实例中的`setDisplayStats`方法调用发送`false`作为参数，如下面的代码清单所示：

```java
bool AppDelegate::applicationDidFinishLaunching() {
    // initialize director
    auto director = Director::getInstance();
    auto glview = director->getOpenGLView();
    if(!glview) {
        glview = GLViewImpl::create("My Game");
        director->setOpenGLView(glview);
    }
    // turn on display FPS
    director->setDisplayStats(false);
    // set FPS. the default value is 1.0/60 if you don't call this
    director->setAnimationInterval(1.0 / 60);
    // create a scene. it's an autorelease object
    auto scene = HelloWorld::createScene();
    // run
    director->runWithScene(scene);
    return true;
}
```

### 提示

**下载示例代码**

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的账户中下载你所购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

## 场景

在本书后续章节中，我们将介绍 Cocos2d-x 如何处理场景概念，就像电影一样；电影由场景组成，Cocos2d-x 游戏也是如此。我们可以将加载、主菜单、世界选择、游戏关卡、结束字幕等不同的屏幕可视化为不同的场景。每个场景都有一个定义其行为的类。模板代码只有一个名为`HelloWorld`的场景，该场景在`AppDelegate`类内部初始化并启动。正如我们在之前的代码中所见，场景流程由游戏导演管理。`Director`类拥有驱动游戏的所有基本特性，就像电影中的导演一样。有一个导演类的单一共享实例在整个应用程序范围内被使用。

`HelloWorldScene`包含了代表我们运行 HelloWorld 应用程序时出现的所有可见区域的层，即，hello world 标签，Cocos2d-x 标志和显示退出选项的菜单。

在`init`方法中，我们实例化视觉元素，并使用从`Node`核心类继承的`addChild`方法将其添加到场景中。

# 总结

在本章中，我们介绍了 Cocos2d-x 3.4 游戏框架，并解释了如何下载和安装它。我们还解释了所有它的先决条件。我们配置了工作环境，将我们的第一个 Android 应用程序部署到实际设备上，并通过脚本生成的模板代码快速概览了其主要方面。

在下一章中，我们将介绍如何创建和操作所有的游戏图形，例如主角、敌人、障碍物、背景等。


# 第二章：图形

在本章中，我们将介绍如何创建和处理所有游戏图形。我们将创建场景，使用游戏导演处理这些场景之间的过渡，创建精灵，将它们定位到所需的位置，使用动作移动它们，以及使用动画为角色赋予生命。

本章将涵盖以下主题：

+   创建场景

+   理解节点

+   理解精灵

+   理解动作

+   动画精灵

+   添加游戏菜单

+   处理多种屏幕分辨率

# 创建场景

场景概念在 Cocos2d-x 游戏引擎中非常重要，因为游戏中所有显示的屏幕都被视为场景。如果将 Cocos2d-x 与 Android 原生 Java 开发进行类比，我们可以说 Cocos2d-x 的场景相当于 Android 所称的活动。

在上一章中，我们介绍了`AppDelegate`类，并解释了它有责任在设备上加载框架，然后执行游戏特定的代码。这个类包含了`ApplicationDidFinishLaunching`方法，这是我们代码的入口点。在这个方法中，我们实例化了将在游戏中首次显示的场景，然后请求`director`加载它，如下面的代码清单所示：

```java
bool AppDelegate::applicationDidFinishLaunching() {
    auto director = Director::getInstance();
  // OpenGL initialization done by cocos project creation script
    auto glview = director->getOpenGLView();
    auto scene = HelloWorld::createScene();
    director->runWithScene(scene);
    return true;
}
```

### 注意

所有 C++代码都在一个单一的 Android 活动中运行；尽管如此，我们仍然可以向游戏中添加原生活动。

## 理解图层

场景本身不是一个对象容器，因此它应该至少包含一个`Layer`类的实例，这样我们才能向其中添加对象。这个图层创建过程在框架宏`CREATE_FUNC`中被封装。你只需调用宏并将类名作为参数传递，它就会生成图层创建代码。

在框架的前一个版本中，图层操作与事件处理有关多种用途；然而，在 3.0 版本中，事件分发引擎被完全重写。Cocos2d-x 3.4 中仍然存在图层概念的唯一原因是兼容性。框架创建者官方宣布，他们可能会在后续版本中移除图层概念。

## 使用导演

场景由 Cocos2d-x 导演控制，这是一个处理游戏流程的类。它应用了单例设计模式，确保类只有一个实例。它通过场景堆栈控制应该呈现的场景类型，类似于 Android 处理场景的方式。

这意味着最后一个推送到堆栈的场景是即将呈现给用户的那一个。当场景被移除时，用户将能够看到之前可见的场景。

当我们在单个函数中使用单一导演实例不止一次时，我们可以将它的引用存储在局部变量中，如下所示：

```java
auto director = Director::getInstance();
```

我们也可以将其存储在类属性中，以便在类的各个部分都可以访问。这样做可以让我们少写一些代码，同时也代表了性能的提升，因为我们每次想要访问单例实例时，不需要多次调用`getInstance`静态方法。

Director 实例还可以为我们提供有用的信息，比如屏幕尺寸和调试信息，在我们的 Cocos 项目中默认是启用的。

# 暂停游戏

让我们开始创建我们的游戏。我们要添加的第一个功能是暂停和恢复游戏的功能。让我们开始构建——首先设置当我们暂停游戏时将显示的屏幕。

我们将通过向场景堆栈中添加一个新的暂停场景来实现这一点。当这个屏幕从堆栈中移除时，HelloWorld 场景将显示出来，因为它是在暂停场景推入场景堆栈之前显示的屏幕。以下代码清单展示了我们如何轻松地暂停游戏：

## 组织我们的资源文件

当我们创建 Cocos2d-x 项目时，一些资源，比如图片和字体，默认被添加到我们项目的`Resources`文件夹中。我们将组织它们，以便更容易处理。为此，我们将在`Resources`目录中创建一个`Image`文件夹。在这个新文件夹中，我们将放置所有的图片。在本章稍后，我们将解释如何根据 Android 设备屏幕分辨率来组织每个图片的不同版本。

在本章附带资源中，我们为你提供了构建本章代码所需的图片。

## 创建我们的暂停场景头文件

首先，让我们创建我们的暂停场景头文件。我们是参考`HelloWorld.h`头文件创建它的：

```java
#ifndef __Pause_SCENE_H__
#define __Pause_SCENE_H__

#include "cocos2d.h"

class Pause : public cocos2d::Layer
{
public:
    static cocos2d::Scene* createScene();
    virtual bool init();
  void exitPause(cocos2d::Ref* pSender);
    CREATE_FUNC(Pause);
private:
  cocos2d::Director *_director;
  cocos2d::Size _visibleSize;
};

#endif // __Pause_SCENE_H__
```

### 提示

你可以通过输入`using namespace cocos2d`来避免每次引用`cocos2d`命名空间中的 Cocos2d-x 类时输入`cocos2d`，然而，在头文件中使用它被认为是一个坏习惯，因为当包含的命名空间中有重复的字段名时，代码可能无法编译。

## 创建暂停场景实现文件

现在，让我们创建我们的暂停场景实现文件。类似于前一部分的做法，我们将基于项目创建脚本生成的`HelloWorld.cpp`文件来创建这个文件。

在以下代码中，你会发现 Cocos2d-x 模板项目中捆绑的菜单创建代码。我们将在本章的后续部分解释如何创建游戏菜单，你还将学习字体创建，这将在第五章《处理文本和字体》中详细解释。

```java
#include "PauseScene.h"

USING_NS_CC;

Scene* Pause::createScene()
{
    auto scene = Scene::create();
    auto layer = Pause::create();
    scene->addChild(layer);
    return scene;
}

bool Pause::init()
{
    if ( !Layer::init() )
    {
      return false;
    }
  _director = Director::getInstance();
  _visibleSize = _director->getVisibleSize();
  Vec2 origin = _director->getVisibleOrigin();
  auto pauseItem = MenuItemImage::create("play.png", "play_pressed.png", CC_CALLBACK_1(Pause::exitPause, this));
  pauseItem->setPosition(Vec2(origin.x + _visibleSize.width -pauseItem->getContentSize().width / 2, origin.y + pauseItem->getContentSize().height / 2));
  auto menu = Menu::create(pauseItem, nullptr);
  menu->setPosition(Vec2::ZERO);
  this->addChild(menu, 1);
  auto label = Label::createWithTTF("PAUSE", "fonts/Marker Felt.ttf", 96);
  label->setPosition(origin.x + _visibleSize.width/2, origin.y + _visibleSize.height /2);
  this->addChild(label, 1);
  return true;
}

void Pause::exitPause(cocos2d::Ref* pSender){
  /*Pop the pause scene from the Scene stack.
  This will remove current scene.*/
  Director::getInstance()->popScene();
}
```

在生成的`HelloWorldScene.h`场景中，我们现在在`menuCloseCallback`方法定义后添加以下代码行：

```java
void pauseCallback(cocos2d::Ref* pSender);
```

现在，让我们在`HelloWorldScene.cpp`实现文件中为`pauseCallBack`方法创建实现：

```java
void HelloWorld::pauseCallback(cocos2d::Ref* pSender){
  _director->pushScene(Pause::createScene());
}
```

最后，通过使`closeItem`调用`pauseCallBack`方法而不是`menuCloseCallBack`方法来修改其创建，这样这行代码将看起来像这样：

```java
    auto closeItem = MenuItemImage::create("pause.png", "pause_pressed.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));
```

现在，我们已经创建了一个简单的暂停场景，当按下关闭按钮时，它会被推送到场景堆栈中，当从暂停场景中按下蓝色按钮时，它会被关闭。

现在，我们将`PauseScene.cpp`文件添加到 eclipse 项目中`jni`文件夹下的名为`Android.mk`的 Android makefile 中，位于`LOCAL_SRC_FILES`部分的`HelloWorldScene.cpp`上方。

### 过渡

导演还负责在切换场景时播放过渡效果，Cocos2d-x 3.4 目前提供超过 35 种不同的场景过渡效果，例如渐变、翻转、翻页、分裂和缩放等。

Transition 是`Scene`类的子类，这意味着你可以将过渡实例传递给任何接收场景对象的方法，如`director`类的`runWithScene`、`replaceScene`或`pushScene`方法。

当从游戏场景切换到暂停场景时，让我们使用一个简单的过渡效果。我们只需通过创建`TransitionFlipX`类的新实例并将其传递给导演的`pushScene`方法来实现这一点：

```java
void HelloWorld::pauseCallback(cocos2d::Ref* pSender){
  _director->pushScene(TransitionFlipX::create(1.0, Pause::createScene()));
}
```

# 理解节点

Node 表示屏幕上所有的可见对象，实际上它是所有场景元素的超类，包括场景本身。它是基础框架类，具有处理图形特性的基本方法，如位置和深度。

# 理解精灵

在我们的游戏中，精灵代表我们场景的图像，就像背景、敌人和我们的玩家。

在第四章《用户输入》中，我们将向场景添加事件监听器，使其能够与用户交互。

## 创建精灵

Cocos2d-x 的核心类实例化非常简单。我们已经看到`scene`类有一个`create`方法；同样，`sprite`类也有一个同名静态方法，如下面的代码片段所示：

```java
auto sprBomb = Sprite::create("bomb.png");
```

Cocos2d-x 目前支持 PNG、JPG 和 TIF 图像格式的精灵；然而，我们强烈建议使用 PNG 图像，因为它具有透明度能力，而 JPG 或 TIF 格式没有，同时也因为这种格式在合理的文件大小下提供的图像质量。这就是为什么你会看到所有 Cocos2d-x 生成的模板和示例都使用这种图像格式。

## 定位精灵

创建我们自己的精灵后，我们可以通过使用`setPosition`方法轻松地在屏幕上定位它，但在这样做之前，我们将解释锚点的概念。

### 设置锚点

所有精灵都有一个称为**锚点**的参考点。当我们使用`setPosition`方法定位一个精灵时，框架实际所做的是将指定的二维位置设置到锚点，从而影响整个图像。默认情况下，锚点被设置为精灵的中心，正如我们在以下图片中看到的：

![设置锚点](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_02_01.jpg)

### 理解 Cocos2d-x 坐标系统

与大多数计算机图形引擎不同，Cocos2d-x 的坐标系统在屏幕左下角有原点(0,0)，正如我们在以下图片中看到的：

![理解 Cocos2d-x 坐标系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_02_02.jpg)

因此，如果我们想将精灵定位在原点(0,0)，我们可以通过调用精灵类中的`setPosition`方法来实现。它是重载的，所以它可以接收两个表示 x 和 y 位置的浮点数，一个`Point`类实例，或者一个`Vec2`实例。尽管生成的代码中使用`Vec2`实例，但官方 Cocos2d-x 文档指出，传递浮点数最多可以快 10 倍。

```java
sprBomb -> setPosition(0,0);
```

执行此代码后，我们可以看到只有精灵的右上区域可见，这仅占其大小的 25%，正如我们在以下图片中所示：

![理解 Cocos2d-x 坐标系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_02_03.jpg)

如果你希望精灵显示在原点，有多种方法可以选择，比如将精灵定位在对应精灵高度一半和宽度一半的点，这可以通过使用精灵方法`getContentSize`来确定，它返回一个包含精灵高度和宽度属性的大小对象。另一个可能更简单的方法是将精灵的锚点重置为(0,0)，这样当精灵在屏幕原点定位时，它完全可见并且位于屏幕左下角区域。《setAnchorPoint》方法接收一个`Vec2`实例作为参数。在以下代码清单中，我们传递了一个指向原点(0,0)的`Vec2`实例：

```java
sprBomb -> setAnchorPoint(Vec2(0,0));
sprBomb -> setPosition(0,0);
```

### 注意

`Vec2`类有一个不接受参数的构造函数，它会创建一个初始值为 0,0 的`Vec2`对象。

当我们执行代码时，得到以下结果：

![理解 Cocos2d-x 坐标系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_02_04.jpg)

### 提示

默认锚点位于精灵中心的原因是，这样更容易将其定位在屏幕中心。

### 将精灵添加到场景中

在创建并定位了我们的精灵对象之后，我们需要使用`addChild`方法将其添加到场景中，该方法包含两个参数：要添加到场景中的节点的指针和一个表示其在*z*轴位置的整数。*z*值最高的节点将显示在那些值较低的节点之上：

```java
  this->addChild(sprBomb,1);
```

现在让我们向`HelloWorld`场景添加背景图像：我们将在`init`方法中将炸弹定位在屏幕左下区域时所用的相同步骤来完成它：

```java
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2());
  bg->setPosition(0,0);
  this->addChild(bg, -1);
```

我们已经在*z*位置为-1 的地方添加了背景，因此任何位置为 0 或更高的节点都将显示在背景之上，如下面的图片所示：

![向场景中添加精灵](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_02_05.jpg)

### 在可见区域外定位精灵

现在我们有一个位于屏幕底部的炸弹，它不会移动。我们现在将其定位在屏幕顶部中心区域，位于可见区域之外，这样当我们让这个精灵移动时，它看起来就像是下炸弹雨。

正如我们之前提到的，让我们将炸弹定位在可见区域内，然后在下一节中我们将使用动作功能使其向地面移动：

```java
sprBomb->setPosition(_visibleSize.width / 2, _visibleSize.height + sprBomb->getContentSize().height/2);
```

我们移除了`setAnchorPoint`语句；现在，炸弹拥有默认的锚点，并且我们修改了`setPosition`语句，现在将其正好定位在可见区域内。

### 定位玩家精灵

现在让我们创建并定位我们的玩家精灵。

```java
auto player = Sprite::create("player.png");
player->setPosition(_visibleSize.width / 2, _visibleSize.height* 0.23);
this->addChild(player, 0);
```

在之前的代码中，我们创建了一个玩家精灵。我们使用了默认的锚点，它直接指向图像的中心，并通过将其定位在屏幕宽度的一半和屏幕高度的 23%，使其水平居中，因为本章提供的背景图像是在这些比例下绘制的。我们以 z 值为 0 添加它，这意味着它将被显示在背景中。

现在让我们来处理炸弹，将其放置在可见区域内，然后在下一节中，我们将使用动作功能使其向地面移动：

```java
sprBomb->setPosition(_visibleSize.width / 2, _visibleSize.height + sprBomb->getContentSize().height/2);
```

我们移除了`setAnchorPoint`语句；现在，炸弹拥有默认的锚点，并且我们修改了`setPosition`语句，现在将其放置在可见区域内。

在本章中，我们使用了许多图像，正如我们之前提到的，这些图像存储在我们的 Cocos2d-x 项目的`Resources`文件夹中。你可以创建子文件夹来组织你的文件。

# 理解动作

我们可以轻松地让精灵执行具体的动作，如跳跃、移动、倾斜等。只需要几行代码就能让我们的精灵执行所需的动作。

## 移动精灵

我们可以通过创建一个`MoveTo`动作，使精灵移动到屏幕的特定区域，然后让精灵执行该动作。

在下面的代码清单中，我们通过简单地编写以下代码行，使炸弹掉落到屏幕底部：

```java
  auto moveTo = MoveTo::create(2, Vec2(sprBomb->getPositionX(), 0 - sprBomb->getContentSize().height/2));
  sprBomb->runAction(moveTo);
```

我们创建了一个`moveTo`节点，它将把炸弹精灵移动到当前的横向位置，同时也会把它移动到屏幕底部直到不可见。为了实现这一点，我们让它移动到精灵高度负一半的 y 位置。由于锚点被设置为精灵的中心点，将其移动到其高度的负一半就足以让它移动到屏幕可见区域之外。

如你所见，它与我们的玩家精灵相撞，但炸弹只是继续向下移动，因为它仍然没有检测到碰撞。在下一章中，我们将为游戏添加碰撞处理。

### 注意

Cocos2d-x 3.4 拥有自己的物理引擎，其中包括一个易于检测精灵之间碰撞的机制。

如果我们想将精灵移动到相对于其当前位置的位置，我们可以使用`MoveBy`类，它接收我们想要精灵在水平和垂直方向上移动多少的参数：

```java
  auto moveBy = MoveBy::create(2, Vec2(0, 250));
  sprBomb->runAction(moveBy);
```

### 注意

你可以使用`reverse`方法使精灵向相反方向移动。

## 创建序列

有时我们有一个预定义的动作序列，我们希望在代码的多个部分执行它，这可以通过序列来处理。顾名思义，它由一系列按预定义顺序执行的动作组成，如有必要可以反向执行。

在使用动作时经常使用序列，因此在序列中我们添加了`moveTo`节点，然后是一个函数调用，该调用在移动完成后执行一个方法，这样它将允许我们从内存中删除精灵，重新定位它，或者在视频游戏中执行任何其他常见任务。

在以下代码中，我们创建了一个序列，首先要求炸弹移动到地面，然后请求执行`moveFinished`方法：

```java
  //actions
  auto moveFinished = CallFuncN::create(CC_CALLBACK_1(HelloWorld::moveFinished, this));
  auto moveTo = MoveTo::create(2, Vec2(sprBomb->getPositionX(), 0 - sprBomb->getContentSize().height/2));
  auto sequence = Sequence::create(moveTo, moveFinished, nullptr);
  sprBomb->runAction(sequence);
```

请注意，在序列的末尾我们传递了一个`nullptr`参数，所以当 Cocos2d-x 看到这个值时，它会停止执行序列中的项目；如果你不指定它，这可能会导致你的游戏崩溃。

### 注意

自从 3.0 版本以来，Cocos2d-x 建议使用`nullptr`关键字来引用空指针，而不是使用传统的 NULL 宏，后者仍然有效，但不是在 C++中认为的最佳实践。

# 制作精灵动画

为了使我们的游戏看起来更加专业，我们可以使精灵具有动画效果，这样就不会一直显示静态图像，而是显示动画角色、敌人和障碍物。Cocos2d-x 提供了一种简单机制，可以将这类动画添加到我们的精灵中，如下面的代码清单所示：

```java
//Animations
Vector<SpriteFrame*> frames;
Size playerSize = sprPlayer->getContentSize();
frames.pushBack(SpriteFrame::create("player.png", Rect(0, 0, playerSize.width, playerSize.height)));
frames.pushBack(SpriteFrame::create("player2.png", Rect(0, 0, playerSize.width, playerSize.height)));
auto animation = Animation::createWithSpriteFrames(frames,0.2f);
auto animate = Animate::create(animation);
sprPlayer->runAction(RepeatForever::create(animate));
```

## 使用精灵表提高性能

尽管我们可以基于位于多个文件中的图像创建精灵动画，就像我们在之前的代码中所做的那样，但加载大量文件将非常低效。这就是为什么我们更愿意加载包含多个图像的单个文件。为了实现这一点，一个带有`plist`扩展名的纯文本文件指出了文件中每个图像的确切位置，Cocos2d-x 能够读取这个纯文本文件，并从一个单一的精灵表文件中提取所有图像。有许多工具可以让你创建自己的精灵表，最受欢迎的是纹理打包器，你可以从[`www.codeandweb.com/texturepacker`](https://www.codeandweb.com/texturepacker)下载并在 Windows 或 Mac OS 上免费试用。

在本章中，我们包含的资源有：一个名为`bunny.plist`的`plist`文件和用纹理打包器创建的`bunny_ss.png`精灵表。你可以使用以下代码加载此表的任何帧：

```java
SpriteFrameCache* cache = SpriteFrameCache::getInstance();
cache->addSpriteFramesWithFile("bunny.plist");
auto sprBunny = Sprite::createWithSpriteFrameName("player3.png");
sprBunny -> setAnchorPoint(Vec2());
```

# 游戏菜单

在我们游戏的一部分中拥有菜单是很常见的，比如主屏幕和配置屏幕。这个框架为我们提供了一种简单的方法将菜单添加到游戏中。

下面的代码清单显示了菜单创建过程：

```java
auto closeItem = MenuItemImage::create("pause.png", "CloseSelected.png", CC_CALLBACK_1(HelloWorld::pause_pressed, this));
closeItem->setPosition(Vec2(_visibleSize.width – closeItem->getContentSize().width/2 , closeItem-> getContentSize().height/2));
auto menu = Menu::create(closeItem, nullptr);
menu->setPosition(Vec2::ZERO);
this->addChild(menu, 1);
```

从前面的列表中我们可以看到，我们首先通过实例化`MenuItemImage`类并传递三个参数给`create`方法来创建一个菜单项：第一个参数表示菜单项应该显示的图像，第二个是选中图像时应该显示的图像，第三个参数指定当选择菜单项时应调用的方法。

### 注意

Cocos2d-x 分支 3 现在允许程序员使用 lambda 表达式来处理菜单项。

## 处理多屏幕分辨率

在创建游戏时，你需要决定打算支持哪些屏幕分辨率，然后创建所有图像的大小，使其在高分辨率屏幕上不会显得像素化，在低性能设备上加载时也不会影响性能。所有这些版本的图像应该有相同的名称，但它们应该存储在`Resources`文件夹中的不同目录里。

在这个例子中，我们有三个目录：第一个包含高分辨率的图像，第二个包含中等分辨率的图像，第三个包含低分辨率的图像。

在准备好适合所有分辨率需求的所有图像大小之后，我们必须编写根据设备屏幕分辨率选择正确图像集的代码。正如我们之前提到的，`AppDelegate`类包含`applicationDidFinishLaunching`，该函数在 Cocos2d-x 框架在设备上加载后立即启动。在这个方法中，我们将编写多屏幕分辨率的代码，如下面的代码清单所示：

```java
bool AppDelegate::applicationDidFinishLaunching() {
  auto director = Director::getInstance();
  // OpenGL initialization done by cocos project creation script
  auto glview = director->getOpenGLView();
  Size screenSize = glview->getFrameSize();
  Size designSize = CCSizeMake(768, 1280);
  std::vector<std::string> searchPaths;

if (screenSize.height > 800){
  //High Resolution
  searchPaths.push_back("images/high");
  director->setContentScaleFactor(1280.0f / designSize.height);
}
else if (screenSize.height > 600){
  //Mid resolution
  searchPaths.push_back("images/mid");
  director->setContentScaleFactor(800.0f / designSize.height);
}
else{
  //Low resolution
  searchPaths.push_back("images/low");
  director->setContentScaleFactor(320.0f / designSize.height);
}
  FileUtils::getInstance()->setSearchPaths(searchPaths);
  glview->setDesignResolutionSize(designSize.width, designSize.height, ResolutionPolicy::NO_BORDER );
  auto scene = HelloWorld::createScene();
  director->runWithScene(scene);
  return true;
}
```

通过将`AndroidManifest.xml`文件中的`android:screenOrientation`值设置为`portrait`来进行修改。

# 将所有内容整合到一起

这是`HelloWorldScene.cpp`实现文件的完整代码，我们在其中创建并定位了背景、动画玩家和移动的炸弹：

```java
#include "HelloWorldScene.h"
#include "PauseScene.h"

USING_NS_CC;

Scene* HelloWorld::createScene()
{
  // 'scene' is an autorelease object
  auto scene = Scene::create();

  // 'layer' is an autorelease object
  auto layer = HelloWorld::create();

  // add layer as a child to scene
  scene->addChild(layer);

  // return the scene
  return scene;
}
```

接下来在`init`函数中，我们将实例化和初始化我们的精灵：

```java
bool HelloWorld::init()
{
  if ( !Layer::init() )
  {
    return false;
  }
  _director = Director::getInstance();
  _visibleSize = _director->getVisibleSize();
  auto origin = _director->getVisibleOrigin();
  auto closeItem = MenuItemImage::create("pause.png", "pause_pressed.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));

  closeItem->setPosition(Vec2(_visibleSize.width - closeItem->getContentSize().width/2 ,
  closeItem->getContentSize().height/2));

  auto menu = Menu::create(closeItem, nullptr);
  menu->setPosition(Vec2::ZERO);
  this->addChild(menu, 1);
  auto sprBomb = Sprite::create("bomb.png");
  sprBomb->setPosition(_visibleSize.width / 2, _visibleSize.height + sprBomb->getContentSize().height/2);
  this->addChild(sprBomb,1);
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2::Zero);
  bg->setPosition(0,0);
  this->addChild(bg, -1);
  auto sprPlayer = Sprite::create("player.png");
  sprPlayer->setPosition(_visibleSize.width / 2, _visibleSize.height * 0.23);
  this->addChild(sprPlayer, 0);
```

接下来，我们将使用以下代码添加动画：

```java
  Vector<SpriteFrame*> frames;
  Size playerSize = sprPlayer->getContentSize();
  frames.pushBack(SpriteFrame::create("player.png", Rect(0, 0, playerSize.width, playerSize.height)));
  frames.pushBack(SpriteFrame::create("player2.png", Rect(0, 0, playerSize.width, playerSize.height)));
  auto animation = Animation::createWithSpriteFrames(frames,0.2f);
  auto animate = Animate::create(animation);
  sprPlayer->runAction(RepeatForever::create(animate));
```

在这里，我们将创建一个序列，该序列将把炸弹从屏幕顶部移动到底部。移动完成后，我们将指定调用`moveFinished`方法。我们只是出于测试目的使用它来打印一条日志信息：

```java
  //actions
  auto moveFinished = CallFuncN::create(CC_CALLBACK_1(HelloWorld::moveFinished, this));
  auto moveTo = MoveTo::create(2, Vec2(sprBomb->getPositionX(), 0 - sprBomb->getContentSize().height/2));
  auto sequence = Sequence::create(moveTo, moveFinished, nullptr);
  sprBomb->runAction(sequence);
  return true;
}

void HelloWorld::moveFinished(Node* sender){
  CCLOG("Move finished");
}

void HelloWorld::pauseCallback(cocos2d::Ref* pSender){
  _director->pushScene(TransitionFlipX::create(1.0, Pause::createScene()));
}
```

下图展示了在本章中完成所有代码后，我们的游戏看起来是什么样子：

![将所有内容整合到一起](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_02_06.jpg)

# 总结

在本章中，我们了解了如何创建游戏场景，以及如何向其中添加精灵和菜单。我们还学会了如何轻松地动画化精灵并在屏幕上移动它们。

在下一章中，我们将学习如何使用内置的物理引擎以更真实的方式移动我们的精灵；通过它，我们将轻松配置运动并为游戏添加碰撞检测。


# 第三章：理解游戏物理

在本章中，我们将介绍如何通过使用基于流行的 Chipmunk 框架的 Cocos2d-x 内置引擎，向游戏中添加物理效果。我们将解释以下主题：

+   设置物理世界

+   检测碰撞

+   处理重力

+   处理物理属性

有关 Chipmunk 物理引擎的更多信息，你可以访问[`chipmunk-physics.net`](https://chipmunk-physics.net)。

物理引擎封装了与给场景真实运动相关的所有复杂性，例如给物体添加重力使其被吸引到屏幕底部，或检测实体之间的碰撞等等。

在处理物理时，我们应该记住我们在场景中处理的是一个物理世界，所有参与世界的物理元素都被称为物理实体。这些实体具有质量、位置和旋转等属性。这些属性可以更改以自定义实体。一个物理实体可以通过关节定义附着在另一个实体上。

需要注意的是，从物理学的角度来看，物理实体并不知道物理世界外的精灵和其他对象，但我们将在这章中看到如何将精灵与物理实体连接起来。

视频游戏最常见的特征之一是碰撞检测；我们经常需要知道物体何时与其他物体发生碰撞。这可以通过定义代表每个实体碰撞区域的形状轻松完成，然后指定一个碰撞监听器，我们将在本章后面展示如何操作。

最后，我们将介绍 Box2D 物理引擎，这是一个完全独立的物理引擎，与 Chipmunk 无关。Box2D 是用 C++编写的，而 Chipmunk 是用 C 编写的。

# 设置物理世界

为了在游戏中启用物理，我们需要向我们的`HelloWorldScene.h`头文件中添加以下几行：

```java
cocos2d::Sprite* _sprBomb;
  void initPhysics();
  bool onCollision(cocos2d::PhysicsContact& contact);
  void setPhysicsBody(cocos2d::Sprite* sprite);
```

在这里，我们为`_sprBomb`变量创建了一个实例变量，这样它就可以被所有实例方法访问。在这种情况下，我们希望能够在每次检测到物理实体之间的碰撞时调用的`onCollision`方法中访问炸弹实例，这样我们只需将它的可见属性设置为 false，就可以让炸弹消失。

现在，让我们转到我们的`HelloWorld.cpp`实现文件，并进行一些更改以设置我们的物理世界。

首先，让我们修改我们的`createScene`方法，现在它看起来应如下所示：

```java
Scene* HelloWorld::createScene()
{
  auto scene = Scene::createWithPhysics();
  scene->getPhysicsWorld()->setGravity(Vect(0,0));
  auto layer = HelloWorld::create();
  //enable debug draw
  scene->getPhysicsWorld()->setDebugDrawMask(PhysicsWorld::DEBUGDRAW_ALL);
  scene->addChild(layer);
  return scene;
}
```

### 注意

在 Cocos2d-x 3 分支的早期版本中，你需要指定当前场景层将要使用的物理世界。但在 3.4 版本中，这不再必要，`Layer`类中移除了`setPhysicsWorld`方法。

在这里，我们可以看到我们现在是通过`Scene`类中的`createWithPhysics`静态方法创建场景实例，而不是使用简单的创建方法。

我们接下来要进行的第二步是将重力设置为（0,0），这样物理世界的重力就不会将我们的精灵吸引到屏幕底部。

然后，我们将启用物理引擎的调试绘制功能，这样我们就能看到所有的物理实体。这个选项将有助于我们在开发阶段，我们将使用 COCOS2D_DEBUG 宏，使其仅在调试模式下运行时显示调试绘制，如下所示：

```java
#if COCOS2D_DEBUG
  scene->getPhysicsWorld()->setDebugDrawMask(PhysicsWorld::DEBUGDRAW_ALL);
#endif
```

在以下屏幕截图中，我们可以看到围绕炸弹和玩家精灵的红色圆形。这表示附加到每个玩家精灵的物理实体：

![设置物理世界](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_03_01.jpg)

现在，让我们实现我们的`setPhysicsBody`方法，它接收一个指向我将添加物理实体的精灵对象的指针作为参数。此方法将创建一个表示物理实体和碰撞区域的圆形。该圆形的半径将是精灵宽度的一半，以尽可能覆盖精灵的面积。

```java
void HelloWorld::setPhysicsBody(cocos2d::Sprite* sprite){
  auto body = PhysicsBody::createCircle(sprite->getContentSize().width/2);
  body->setContactTestBitmask(true);
  body->setDynamic(true);
  sprite -> setPhysicsBody(body);
}
```

### 注意

圆形通常用于检测碰撞，因为它们在每个帧中检测碰撞所需的 CPU 努力较小；然而，在某些情况下，它们的精度可能无法接受。

现在，让我们在`init`方法中为我们的玩家和炸弹精灵添加物理实体。为此，我们将在每个精灵初始化后调用我们的实例方法 setPhysicsBody。

# 碰撞检测

首先，让我们实现我们的`onCollision`实例方法。每次检测到两个物理实体之间的碰撞时，都会调用它。正如在下面的代码中我们可以看到，当炸弹物理实体与我们的玩家碰撞时，它使炸弹变得不可见：

```java
bool HelloWorld::onCollision(PhysicsContact& contact){
  _sprBomb->setVisible(false);
  return false;
}
```

### 注意

在开发过程中，这里是一个放置一些日志的好地方，以了解何时检测到碰撞。在 Cocos2d-x 3.4 中，你可以使用`CCLOG`宏打印日志消息。通过以下方式定义宏`COCOS2D_DEBUG`可以开启它：`#define COCOS2D_DEBUG 1`。

如我们所见，这个方法返回一个布尔值。它表示这两个实体是否可以再次碰撞。在这个特定的情况下，我们将返回 false，表示一旦这两个物理实体碰撞，它们就不应该继续碰撞。如果我们返回 true，那么这两个对象将继续碰撞，这将导致我们的玩家精灵移动，从而给我们的游戏带来不希望出现的视觉效果。

现在，让我们使我们的游戏能够在炸弹与玩家碰撞时检测到。为此，我们将创建一个`EventListenerPhysicsContact`实例，我们将设置它，以便当两个物理体开始碰撞时，它应该调用我们的`onCollision`实例方法。然后，我们将事件监听器添加到事件分发器中。我们将在`initPhysics`实例方法中创建这三个简单步骤。所以，我们的代码将如下所示：

```java
void HelloWorld::initPhysics()
{
  auto contactListener = EventListenerPhysicsContact::create();
  contactListener->onContactBegin = CC_CALLBACK_1(HelloWorld::onCollision,this);
  getEventDispatcher() ->addEventListenerWithSceneGraphPriority(contactListener,this);
}
```

我们的`init`方法的代码将如下所示：

```java
bool HelloWorld::init() {
  if( !Layer::init() ){
    return false;
  }
  _director = Director::getInstance();
  _visibleSize = _director->getVisibleSize();
  auto origin = _director->getVisibleOrigin();
  auto closeItem = MenuItemImage::create("pause.png", "pause_pressed.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));
  closeItem->setPosition(Vec2(_visibleSize .width - closeItem->getContentSize().width/2, closeItem->getContentSize().height/2));

  auto menu = Menu::create(closeItem, nullptr);
  menu->setPosition(Vec2::ZERO);
  this->addChild(menu, 1);
  _sprBomb = Sprite::create("bomb.png");
  _sprBomb->setPosition(_visibleSize .width/2, _visibleSize .height + _sprBomb->getContentSize().height/2);
  this->addChild(_sprBomb,1);
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2());
  bg->setPosition(0,0);
  this->addChild(bg, -1);
  auto sprPlayer = Sprite::create("player.png");
  sprPlayer->setPosition(_visibleSize .width / 2, _visibleSize .height * 0.23);
  setPhysicsBody(sprPlayer);
  this->addChild(sprPlayer, 0);
  //Animations
  Vector<SpriteFrame*> frames;
  Size playerSize = sprPlayer->getContentSize();
  frames.pushBack(SpriteFrame::create("player.png", Rect(0, 0, playerSize.width, playerSize.height)));
  frames.pushBack(SpriteFrame::create("player2.png", Rect(0, 0, playerSize.width, playerSize.height)));
  auto animation = Animation::createWithSpriteFrames(frames,0.2f);
  auto animate = Animate::create(animation);
  sprPlayer->runAction(RepeatForever::create(animate));
  setPhysicsBody(_sprBomb);
  initPhysics();
  return true;
}
```

# 处理重力

既然我们已经成功使用内置物理引擎来检测碰撞，那么让我们来玩弄一下重力。转到`createScene`方法，并修改我们发送到构造函数的参数。在我们的游戏中，我们使用了`(0,0)`值，因为我们不希望我们的世界有任何在*x*或*y*轴上移动我们物体的重力。

现在，尝试一下，将值改为正数或负数。当我们在*x*轴上使用负值时，它会将物体吸引向左，而在*y*轴上使用负值时，它会将物体吸引向下。

### 注意

改变这些值并理解添加到我们游戏中的物理可能会为你的下一个游戏提供一些想法。

## 处理物理属性

既然我们已经创建了对应于物理世界的场景，我们现在有能力改变物理属性，比如每个物体的速度、线性阻尼、力、冲量和扭矩。

### 应用速度

在上一章中，我们设法使用`MoveTo`动作将炸弹从屏幕顶部移动到底部。现在我们使用了内置的物理引擎，只需为炸弹设置速度就能实现同样的效果。这可以通过简单地调用炸弹精灵物理体的`setVelocity`方法来完成。速度是一个矢量量；因此，提到的方法接收一个`Vect`实例作为参数。*x*的值表示其水平分量；在这个轴上，正值意味着物体将向右移动，负值意味着物体将向左移动。*y*值影响垂直运动。正值将物体向屏幕顶部移动，负值将物体向屏幕底部移动。

我们在`HelloWorld.cpp`实现文件的`init`方法中，在返回语句之前添加了以下行：

```java
  _sprBomb->getPhysicsBody()->setVelocity(Vect(0,-100));
```

记得删除请求炸弹精灵执行`MoveTo`动作的代码行，以便确认炸弹现在是因为其速度参数而移动。

现在让我们转到`onCollision`方法，当炸弹与我们的玩家精灵发生碰撞时，我们将把炸弹的速度设置为零。

```java
  _sprBomb -> getPhysicsBody()->setVelocity(Vect());
```

### 注意

与`Vec2`类相似，空构造函数会将所有向量值初始化为零。

### 线性阻尼

我们可以降低物理体的速度，以产生摩擦效果。实现这一目标的方法之一是调用`linearDamping`方法，并指定身体速度的变化率。该值应该是一个介于`0.0`和`1.0`之间的浮点数。

你可以通过将炸弹物理体的值设置为`0.1f`来测试线性阻尼，并观察炸弹速度如何降低。

```java
  _sprBomb->getPhysicsBody()->setLinearDamping(0.1f);
```

测试线性阻尼后，记得记录或删除这行代码，以防止游戏出现预期之外的行为。

### 应用力

我们可以通过简单地调用想要施加力的物理体的`applyForce`方法，来立即对物体施加力。与前面章节中解释的方法类似，它接收一个向量作为参数，这意味着力有垂直和水平分量。

我们可以通过在`onCollision`方法中给炸弹施加一个力来测试这个方法，使它在与玩家精灵碰撞后立即向右移动。

```java
  _sprBomb->getPhysicsBody()->applyForce(Vect(1000,0));
```

### 应用冲量

在上一节中，我们给物理体添加了一个即时力，现在我们可以通过调用`applyImpulse`方法对其施加一个连续力。

在`onCollision`方法中对物理体施加即时力之后，添加以下代码行：

```java
  _sprBomb->getPhysicsBody()->applyImpulse(Vect(10000,0));
```

现在运行游戏，你将看到炸弹向右移动。

![应用冲量](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_03_02.jpg)

删除在`onCollision`方法中给炸弹添加力和冲量的代码行。

### 应用扭矩

最后，让我们在炸弹与玩家精灵碰撞后，使炸弹旋转。我们可以通过使用`applyTorque`方法给炸弹的物理体施加一个扭矩力，该方法接收一个浮点数；如果是正数，它将使物理体逆时针旋转。

让我们在`onCollision`方法中的返回语句之前，添加一个任意的正扭矩：

```java
  auto body = _sprBomb -> getPhysicsBody();
body->applyTorque(100000);
```

现在给`applyTorque`方法添加一个负值，你将看到物理体如何顺时针旋转。

# 把所有东西放在一起

经过所有修改后，我们的`onCollision`方法看起来像这样：

```java
bool HelloWorld::onCollision(PhysicsContact& contact){
  auto body = _sprBomb -> getPhysicsBody();
  body->setVelocity(Vect());
  body->applyTorque(100900.5f);
  return false;
}
```

我们现在的`init`方法看起来像这样：

```java
bool HelloWorld::init()
{
  if( !Layer::init() ){
    return false;
  }
  _director = Director::getInstance();
  _visibleSize = _director->getVisibleSize();
  auto origin = _director->getVisibleOrigin();
  auto closeItem = MenuItemImage::create("CloseNormal.png", "CloseSelected.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));
  closeItem->setPosition(Vec2(_visibleSize .width - closeItem->getContentSize().width/2, closeItem->getContentSize().height/2));

  auto menu = Menu::create(closeItem, nullptr);
  menu->setPosition(Vec2::ZERO);
  this->addChild(menu, 1);
  _sprBomb = Sprite::create("bomb.png");
  _sprBomb->setPosition(_visibleSize .width/2, _visibleSize .height + _sprBomb->getContentSize().height/2);
  this->addChild(_sprBomb,1);
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2());
  bg->setPosition(0,0);
  this->addChild(bg, -1);
  auto sprPlayer = Sprite::create("player.png");
  sprPlayer->setPosition(_visibleSize .width/2, _visibleSize .height * 0.23);
  setPhysicsBody(sprPlayer);

  this->addChild(sprPlayer, 0);
  //Animations
  Vector<SpriteFrame*> frames;
  Size playerSize = sprPlayer->getContentSize();
  frames.pushBack(SpriteFrame::create("player.png", Rect(0, 0, playerSize.width, playerSize.height)));
  frames.pushBack(SpriteFrame::create("player2.png", Rect(0, 0, playerSize.width, playerSize.height)));
  auto animation = Animation::createWithSpriteFrames(frames,0.2f);
  auto animate = Animate::create(animation);
  sprPlayer->runAction(RepeatForever::create(animate));

  setPhysicsBody(_sprBomb);
  initPhysics();
  _sprBomb->getPhysicsBody()->setVelocity(Vect(0,-100));
  return true;
}
```

下面的截图展示了我们对游戏进行修改后的样子：

![把所有东西放在一起](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_03_03.jpg)

### 提示

**Box2D 物理引擎**

到目前为止，我们使用了框架提供的内置物理引擎，该引擎基于 chipmunk C 物理库；然而，Cocos2d-x 也在其 API 中集成了 Box2D 物理引擎。

为了创建一个 Box2D 世界，我们实例化`b2World`类，然后向其构造函数传递一个表示世界重力的`b2Vec`对象。世界实例有一个用于创建`b2Bodies`的实例方法。Sprite 类有一个名为`setB2Body`的方法，它允许我们将 Box2D 物理体关联到任何给定的精灵。这比框架的第二个分支中的处理要平滑得多；之前需要更多的代码才能将`b2Body`与精灵绑定。

尽管 Box2D 集成使用起来很方便，但我强烈建议使用内置的物理引擎，因为 Box2D 集成已不再积极开发中。

# 总结

我们通过创建物理世界和代表炸弹及玩家精灵的物理体，向游戏中添加了物理效果，并且在很少的步骤内使用了内置物理引擎提供的碰撞检测机制。我们还展示了如何更改重力参数，以便物理体根据重力力量移动。我们可以轻松地更改物体的物理属性，例如速度、摩擦力、力、冲量和扭矩，每个属性只需一行代码。到目前为止，我们的玩家忽略了用户事件。在下一章中，我们将介绍如何向游戏中添加用户交互。


# 第四章：用户输入

到目前为止，我们已经添加了在屏幕上移动并相互碰撞的图形，但这还不够有趣，因为玩家无法控制我们的主角，除非用户能够与之互动，否则它就不能算是一个游戏。在本章中，我们将向游戏中添加用户交互。本章将涵盖以下主题：

+   理解事件分发机制

+   处理触摸事件

+   处理加速计事件

+   保持屏幕活跃

+   处理 Android 返回键按下事件

# 理解事件分发机制

从 Cocos2d-x 的先前版本（版本 2）开始，事件处理现在有所不同。从 3.0 版本开始，我们现在有一个统一的事件分发机制，称为事件分发器，它处理游戏中可能发生的各种用户输入事件。

我们可以处理多种类型的用户输入事件，例如触摸、键盘按键按下、加速度和鼠标移动。在以下各节中，我们将介绍如何处理与移动游戏相关的用户输入事件，例如触摸和加速计。

有许多类允许我们监听之前提到的事件；一旦我们实例化了这些类中的任何一个，我们需要将其添加到事件分发器中，以便在触发用户事件时，它会调用相应监听器定义的方法。

你可以通过从`Node`类继承的`_eventDispatcher`实例属性访问事件分发器，或者调用位于 Cocos2d-x API `Director`类中的`getEventDispatcher`静态方法。

### 注意

Cocos2d-x 的事件分发机制使用了观察者设计模式，这是用于处理 Android 原生应用程序上用户输入事件的模式。

# 处理触摸事件

在游戏和用户之间创建交互的最常见方式是通过触摸事件。在 Cocos2d-x 中处理触摸事件非常直接。

在本节中，我们将允许用户通过触摸并移动到所需位置来移动我们的玩家精灵。

我们首先要做的是在`HelloWorldScene.h`类头文件中创建`initTouch`、`movePlayerByTouch`和`movePlayerIfPossible`方法，正如我们以下代码清单中看到的那样：

```java
void initTouch();
void movePlayerByTouch(cocos2d::Touch* touch, cocos2d::Event* event);
void movePlayerIfPossible(float newX);
```

现在让我们将初始化代码添加到实现文件`HelloWorldScene.cpp`中的`initTouch`方法中。在这个简单的游戏中，我们将使用单一触摸来四处移动我们的兔子角色，不需要处理多点触控。

为了处理单一触摸，我们将创建`EventListenerTouchOneByOne`类的新实例，然后我们将指定当触摸事件开始、移动和结束时游戏应该做什么。在以下代码清单中，实例化`EventListenerTouchOneByOne`类之后，我们将指定当触发`onTouchBegan`、`onTouchMoved`和`onTouchEnded`事件时应调用的方法。出于当前游戏的目的，我们只使用`onTouchMoved`事件。为此，我们将创建一个回调到我们的方法`movePlayerByTouch`，对于另外两个方法，我们将通过 lambda 函数创建空的结构。你可以通过链接[`en.cppreference.com/w/cpp/language/lambda`](http://en.cppreference.com/w/cpp/language/lambda)了解更多关于 C++ lambda 函数的信息。

```java
void HelloWorld::initTouch() {
  auto listener = EventListenerTouchOneByOne::create();
  listener->onTouchBegan = [](Touch* touch, Event* event){return true;
  }
  listener->onTouchMoved = CC_CALLBACK_2(HelloWorld::movePlayerByTouch,this);
  listener->onTouchEnded = ={};
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}
```

### 注意

按照约定，所有的 C++成员变量都使用下划线前缀命名。

既然我们已经将所有触摸监听器初始化代码封装到一个方法中，让我们在方法的末尾添加以下行来调用它，我们称之为`init`方法：

```java
  initTouch();
```

我们现在将创建`movePlayerIfPossible`方法。这个方法只会在水平轴上的新请求位置没有超出屏幕限制时移动玩家精灵，正如我们可以在插图中看到的那样。这个方法将用于通过触摸输入事件移动我们的玩家精灵，并且在下一节中我们也将使用它通过加速度计移动我们的玩家精灵。

```java
void HelloWorld::movePlayerIfPossible(float newX){
  float sprHalfWidth = _sprPlayer->getBoundingBox().size.width/2;
  if(newX >= sprHalfWidth && newX < visibleSize.width - sprHalfWidth){
    _sprPlayer->setPositionX(newX);
  }
}
```

![处理触摸事件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_04_01.jpg)

### 注意

在这个方法中，我们采用了“告诉，不要询问”的设计原则，通过在验证玩家是否超出屏幕的方法中进行验证。这使我们避免了在触摸和加速度事件处理方法中重复验证玩家精灵是否超出屏幕的逻辑。

最后，我们现在将创建`movePlayerByTouch`方法，该方法将在触发触摸事件后立即由事件调度器调用。在这个方法中，我们将评估屏幕上的位置，以及用户触摸屏幕的地方是否与精灵的边界矩形相交：

```java
void HelloWorld::movePlayerByTouch(Touch* touch, Event* event){
  auto touchLocation = touch->getLocation();
  if(_sprPlayer->getBoundingBox().containsPoint(touchLocation)){
    movePlayerIfPossible(touchLocation.x);
  }
}
```

## 处理多点触控事件

在前面的部分中，我们启用了这个游戏所需的触摸事件，这是一个单一触摸；然而，Cocos2d-x 也处理多点触控功能，我们将在本节中介绍。

尽管我们的游戏不需要多点触控功能，但我们将创建一个测试代码，以便我们可以同时移动我们的玩家精灵和炸弹。为了做到这一点，我们将在`HelloWorldScene.h`头文件的末尾添加`initMultiTouch`和`moveByMultitouch`方法，如下所示：

```java
void initMultiTouch();
void moveByMultiTouch(const std::vector<cocos2d::Touch*>& touches, cocos2d::Event* event);
```

现在，让我们将实现添加到`HelloWorldScene.cpp`实现文件中。我们将从`initMultiTouch`初始化方法开始：

```java
void HelloWorld::initMultiTouch() {
  auto listener = EventListenerTouchAllAtOnce::create();
  listener->onTouchesBegan = [](const std::vector<Touch*>& touches, Event* event){};
  listener->onTouchesMoved = CC_CALLBACK_2(HelloWorld::moveByMultiTouch,this);
  listener->onTouchesEnded = [](const std::vector<Touch*>& touches, Event* event){};
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}
```

在这里，我们可以找到与之前单点触控初始化方法的相似之处，但有许多不同之处，最显著的是我们现在实例化的是`EventListenerTouchAllAtOnce`类，而不是像之前那样实例化`EventListenerTouchOneByOne`类。尽管它的事件属性与单点触控版本命名相似，但您可能注意到它们现在是用复数形式书写的，因此现在指的是 touches 而不是 touch，例如`onTouchesBegan`。现在，它也将期待一组不同的参数，因为我们将处理多点触控，事件方法将接收一个`std::vector`参数，其中包含同时发生的触控集合。

如之前的代码所示，每当玩家移动触控时，我们将调用我们的`moveByMultiTouch`方法，因此我们现在展示此方法的实现代码：

```java
void HelloWorld::moveByMultiTouch(const std::vector<Touch*>& touches, Event* event){
  for(Touch* touch: touches){
    Vec2 touchLocation = touch->getLocation();
    if(_sprPlayer->getBoundingBox().containsPoint(touchLocation)){
      movePlayerIfPossible(touchLocation.x);
    }else if(_sprBomb->getBoundingBox().containsPoint(touchLocation)){
      _sprBomb->setPosition(touchLocation);
    }
  }
}
```

如您在前面的代码中所见，我们现在正在处理多点触控，在`moveByMultiTouch`方法中，我们正在遍历所有的触控，并对每一个触控进行验证，看它是否触摸到我们的炸弹或兔子玩家精灵，如果是，那么它将把被触摸的精灵移动到触摸位置。

最后，让我们在`init`方法的末尾调用`initMultiTouch`初始化方法，如下所示：

```java
initMultiTouch();
```

如前所述，本节的目的是向您展示处理多点触控事件是多么简单；然而，由于我们的游戏中不会使用它，一旦您完成多点触控功能的测试，就可以从我们的`init`方法中删除对`initMultiTouch`方法的调用。

# 处理加速度计事件

游戏与玩家之间互动的另一种常见方式是加速度计，它允许我们通过移动手机来移动我们的角色，以达到游戏的目标，从而获得数小时的乐趣。

为了将加速度计支持添加到我们的游戏中，我们首先将在`HelloWorldScene.h`头文件中添加以下方法声明：

```java
void movePlayerByAccelerometer(cocos2d::Acceleration* acceleration, cocos2d::Event* event);
void initAccelerometer();
```

现在，让我们为对应的加速度计初始化创建`HelloWorld.cpp`实现文件中的代码。我们首先要做的是通过调用`Device`类上的静态方法`setAccelerometerEnabled`来启用设备上的加速度计传感器，然后我们将创建一个事件监听器来监听加速度计的事件，最后，我们将它添加到事件分发器中，如下面的代码所示：

```java
void HelloWorld::initAccelerometer(){
  Device::setAccelerometerEnabled(true);
  auto listener = EventListenerAcceleration::create(CC_CALLBACK_2(HelloWorld::movePlayerByAccelerometer, this));
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}
```

### 注意

向分发器添加事件监听器的最常见方式是通过`addEventListenerWithSceneGraphPriority`方法，该方法将把作为第二个参数传递的节点的*z*顺序作为其优先级。当我们有多个同时被触发的监听器，而想要指定哪个代码应该首先运行时，这非常有用。

在此阶段，我们已经初始化了加速度计，并且在上一节中创建了`movePlayerIfPossible`方法，该方法将移动玩家精灵，并确保其不会超出屏幕限制。现在我们将要为`movePlayerByAccelerometer`方法编写实现代码，该方法将在加速度计事件触发后立即被调用。由于我们获得的加速度值非常低，因此我们将其乘以十，以便我们的玩家精灵移动得更快。

```java
void HelloWorld::movePlayerByAccelerometer(cocos2d::Acceleration* acceleration, cocos2d::Event* event){
  int accelerationMult = 10;
  movePlayerIfPossible(_sprPlayer->getPositionX() + (acceleration->x * accelerationMult));
}
```

最后，让我们在`HelloWorldScene.cpp`实现文件的`init`方法末尾调用我们的加速度计初始化代码，如下所示：

```java
initAccelerometer();
```

# 保持屏幕常亮

在上一节中，我们向游戏中添加了加速度计交互，这意味着我们的玩家是通过移动手机而不是触摸屏幕来控制主角的，这将导致许多 Android 设备在一段时间不活动（不触摸屏幕）后关闭屏幕。当然，没有人希望我们的 Android 设备的屏幕突然变黑；为了防止这种情况发生，我们将调用`setKeepScreenOnJni`方法，这是在框架的前一个版本 3.3 中引入的。在此版本之前，这种恼人的情况被认为是框架的缺陷，现在终于得到了修复。

首先，我们需要在`HelloWorldScene.cpp`头文件中包含助手，如下所示：

```java
#include "../cocos2d/cocos/platform/android/jni/Java_org_cocos2dx_lib_Cocos2dxHelper.h"
```

然后，我们将在`HelloWorldScene.cpp`实现文件的`init`方法末尾添加以下行：

```java
setKeepScreenOnJni(true);
```

# 处理 Android 后退键按下事件

我在很多使用 Cocos2d-x 开发的游戏中看到的一个常见错误是，当按下后退按钮时游戏不做任何反应。Android 用户习惯于在想要返回上一个活动时按下后退按钮。如果应用程序在按下后退按钮时没有任何反应，那么它会让用户感到困惑，因为这不符合预期行为，经验不足的用户甚至可能很难退出游戏。

我们可以通过向事件分发器中添加`EventListenerKeyboard`方法，轻松地在用户按下后退按钮时触发自定义代码。

首先，我们将在`HelloWorldScene.h`头文件中添加`initBackButtonListener`和`onKeyPressed`方法的声明，如下代码清单所示：

```java
void initBackButtonListener();
void onKeyPressed(cocos2d::EventKeyboard::KeyCode keyCode, cocos2d::Event* event);
```

现在，让我们在`HelloWorldScene.cpp`实现文件中添加`initBackButtonListener`的实现代码。我们首先实例化`EventListenerKeyboard`类，然后需要指定在`onKeyPressed`事件和`onKeyReleased`事件发生时要调用的方法，否则我们将遇到运行时错误。我们将创建一个空的方法实现，并通过 C++11 的 lambda 表达式将其分配给`onKeyPressed`属性，然后我们将为监听器的`onKeyReleased`属性添加一个回调到我们的`onKeyPressed`方法。然后，像之前所做的那样，我们将这个监听器添加到事件分发机制中：

```java
void HelloWorld::initBackButtonListener(){
  auto listener = EventListenerKeyboard::create();
  listener->onKeyPressed = ={};
  listener->onKeyReleased = CC_CALLBACK_2(HelloWorld::onKeyPressed, this);
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}
```

我们现在将实现`onKeyPressed`方法的代码。这将告诉`Director`，如果按下的键是后退按钮键，则结束游戏：

```java
void HelloWorld::onKeyPressed(EventKeyboard::KeyCode keyCode, Event* event){
  if(keyCode == EventKeyboard::KeyCode::KEY_BACK){
    Director::getInstance()->end();
  }
}
```

最后，我们将在`init`方法的末尾调用`initBackButtonListener`方法，如下所示：

```java
initBackButtonListener();
```

### 注意

请注意，你应该在每个想要捕获后退按钮按下事件的场景中，将`EventListenerKeyboard`监听器添加到事件分发器中。

# 将所有内容整合到一起

在本章中添加了所有代码之后，现在我们的`HelloWorldScene.h`头文件将如下所示：

```java
#ifndef __HELLOWORLD_SCENE_H__
#define __HELLOWORLD_SCENE_H__
#include "cocos2d.h"
class HelloWorld : public cocos2d::Layer
{
public:
  static cocos2d::Scene* createScene();
  virtual bool init();
  void pauseCallback(cocos2d::Ref* pSender);
  CREATE_FUNC(HelloWorld);
private:
  cocos2d::Director *_director;
  cocos2d::Size visibleSize;
  cocos2d::Sprite* _sprBomb;
  cocos2d::Sprite* _sprPlayer;
  void initPhysics();
  bool onCollision(cocos2d::PhysicsContact& contact);
  void setPhysicsBody(cocos2d::Sprite* sprite);
  void initTouch();
  void movePlayerByTouch(cocos2d::Touch* touch, cocos2d::Event* event);
  void movePlayerIfPossible(float newX);
  void movePlayerByAccelerometer(cocos2d::Acceleration* acceleration, cocos2d::Event* event);
  void initAccelerometer();
  void initBackButtonListener();
  void onKeyPressed(cocos2d::EventKeyboard::KeyCode keyCode, cocos2d::Event* event);
};

#endif // __HELLOWORLD_SCENE_H__
```

最终的`HelloWorldScene.cpp`实现文件将如下所示：

```java
#include "HelloWorldScene.h"
#include "PauseScene.h"
#include "../cocos2d/cocos/platform/android/jni/Java_org_cocos2dx_lib_Cocos2dxHelper.h"

USING_NS_CC;
Scene* HelloWorld::createScene()
{
  auto scene = Scene::createWithPhysics();
  scene->getPhysicsWorld()->setGravity(Vect(0,0));
  auto layer = HelloWorld::create();
  //enable debug draw
  //scene->getPhysicsWorld()->setDebugDrawMask(PhysicsWorld::DEBUGDRAW_ALL);
  scene->addChild(layer);
  return scene;
}
```

接下来，我们将尝试移动玩家，使其不会移出屏幕外：

```java
void HelloWorld::movePlayerIfPossible(float newX){
  float sprHalfWidth = _sprPlayer->getBoundingBox().size.width/2;
  if(newX >= sprHalfWidth && newX < visibleSize.width - sprHalfWidth){
    _sprPlayer->setPositionX(newX);
  }
}
void HelloWorld::movePlayerByTouch(Touch* touch, Event* event)
{
  Vec2 touchLocation = touch->getLocation();
  if(_sprPlayer->getBoundingBox().containsPoint(touchLocation)){
    movePlayerIfPossible(touchLocation.x);
  }
}
```

如你所见，在以下两个方法`initTouch`和`initAccelerometer`中，我们为每个初始化任务创建了函数。这将使我们能够简化代码，使其更容易阅读：

```java
void HelloWorld::initTouch()
{
  auto listener = EventListenerTouchOneByOne::create();
  listener->onTouchBegan = [](Touch* touch, Event* event){return true;};
  listener->onTouchMoved = CC_CALLBACK_2(HelloWorld::movePlayerByTouch,this);
  listener->onTouchEnded = ={};
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}
void HelloWorld::initAccelerometer()
{
  Device::setAccelerometerEnabled(true);
  auto listener = EventListenerAcceleration::create(CC_CALLBACK_2(HelloWorld::movePlayerByAccelerometer, this));
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}

void HelloWorld::movePlayerByAccelerometer(cocos2d::Acceleration* acceleration, cocos2d::Event* event)
{
  movePlayerIfPossible(_sprPlayer->getPositionX() + (acceleration->x * 10));
}
```

现在，我们将初始化物理引擎。为此，我们将在`init()`方法中调用`initPhysics()`方法：

```java
bool HelloWorld::init()
{
  if( !Layer::init() ){
    return false;
  }
  _director = Director::getInstance();
  visibleSize = _director->getVisibleSize();
  auto origin = _director->getVisibleOrigin();
  auto closeItem = MenuItemImage::create("pause.png", "pause_pressed.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));
  closeItem->setPosition(Vec2(visibleSize.width - closeItem->getContentSize().width/2, closeItem->getContentSize().height/2));

  auto menu = Menu::create(closeItem, nullptr);
  menu->setPosition(Vec2::ZERO);
  this->addChild(menu, 1);
  _sprBomb = Sprite::create("bomb.png");
  _sprBomb->setPosition(visibleSize.width/2, visibleSize.height + _sprBomb->getContentSize().height/2);
  this->addChild(_sprBomb,1);
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2());
  bg->setPosition(0,0);
  this->addChild(bg, -1);
  _sprPlayer = Sprite::create("player.png");
  _sprPlayer->setPosition(visibleSize.width/2, visibleSize.height * 0.23);
  setPhysicsBody(_sprPlayer);

  this->addChild(_sprPlayer, 0);
  //Animations
  Vector<SpriteFrame*> frames;
  Size playerSize = _sprPlayer->getContentSize();
  frames.pushBack(SpriteFrame::create("player.png", Rect(0, 0, playerSize.width, playerSize.height)));
  frames.pushBack(SpriteFrame::create("player2.png", Rect(0, 0, playerSize.width, playerSize.height)));
  auto animation = Animation::createWithSpriteFrames(frames,0.2f);
  auto animate = Animate::create(animation);
  _sprPlayer->runAction(RepeatForever::create(animate));

  setPhysicsBody(_sprBomb);
  initPhysics();
  _sprBomb->getPhysicsBody()->setVelocity(Vect(0,-100));
  initTouch();
  initAccelerometer();
  setKeepScreenOnJni(true);
  initBackButtonListener();
  return true;
}

void HelloWorld::pauseCallback(cocos2d::Ref* pSender){
  _director->pushScene(TransitionFlipX::create(1.0, Pause::createScene()));
}
void HelloWorld::initBackButtonListener(){
  auto listener = EventListenerKeyboard::create();
  listener->onKeyPressed = ={};
  listener->onKeyReleased = CC_CALLBACK_2(HelloWorld::onKeyPressed, this);
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}

void HelloWorld::onKeyPressed(EventKeyboard::KeyCode keyCode, Event* event){
  if(keyCode == EventKeyboard::KeyCode::KEY_BACK){
    Director::getInstance()->end();
  }
}
```

如下图所示，我们最终让兔子在屏幕上移动并离开了它的初始中心位置。

![将所有内容整合到一起](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_04_02.jpg)

### 注意

请注意，在之前的代码列表中，我们省略了与本章不相关的代码部分。如果你想了解到目前为止完整的代码列表是什么样子，你可以查看随书附带的资源材料。

# 总结

在本章中，我们允许用户通过两种不同的输入机制来控制游戏，即触摸屏幕和移动手机以使用加速度传感器；同时，我们还实现了按下后退按钮时游戏暂停的功能。

在下一章，我们将介绍向游戏中添加文本的不同方法。


# 第五章：处理文本和字体

在我们的游戏中，添加文本以向玩家显示信息是非常常见的。这可以通过使用 TrueType 字体或位图字体来完成，这将给我们带来更大的灵活性，实际上，这是专业游戏中使用最广泛的字体类型，因为它允许我们为游戏定制外观。本章将涵盖以下主题：

+   创建 TrueType 字体标签

+   添加标签效果

+   创建系统字体

+   创建位图字体标签

# 创建 TrueType 字体标签

使用 TrueType 字体添加文本非常简单。打开我们在第二章*图形*中创建的`PauseScene.cpp`实现文件。在`init`方法中，你会看到我们通过调用静态方法`createWithTTF`创建了一个`Label`类的实例。这个方法接收三个参数，第一个是我们想要绘制的字符串，第二个是表示你想要使用的字体文件的字符串，包括它在`Resources`文件夹中的路径，第三个是字体大小。

### 注意

`Label`类在 Cocos2d-x 3.x 版本中引入。它将 TrueType 字体和位图字体处理合并到一个单一类中。然而，尽管已弃用，为了兼容性，之前的标签处理类仍然在 API 中可用。

现在，让我们将`createWithTTF`方法中的第三个参数值从 24 更改为 96，使字体变得更大：

```java
auto label = Label::createWithTTF("PAUSE", "fonts/Marker Felt.ttf", 96);
```

### 注意

`cocos new`命令生成的模板 Cocos2d-x 项目中包含了 Marker Felt 字体。

## 创建我们的 GameOverScene

现在是创建游戏结束场景的时候了，一旦炸弹与我们的`bunny`精灵相撞，就会显示这个场景。

我们将通过复制`Classes`目录中的`PauseScene.cpp`和`PauseScene.h`文件，并将它们分别重命名为`GameOverScene.cpp`和`GameOverScene.h`来完成这一操作。

### 提示

请记住，每次你向 Cocos2d-x 文件夹添加新的源文件时，都需要将类添加到`jni`文件夹中的`Android.mk`文件中，这样在下次构建时就会编译这个新的源文件。

现在，在`GameOverScene.h`和`GameOverScene.cpp`文件中，对这两个文件执行查找和替换操作，将单词`Pause`替换为单词`GameOver`。

最后，将`GameOverScene.cpp`实现文件中的前几行代码替换为以下内容：

```java
#include "GameOverScene.h"
#include "HelloWorldScene.h"
```

在`GameOverScene.cpp`实现文件中的`exitPause`方法体内，我们将用以下这行代码替换这个方法中的唯一一行：

```java
   Director::getInstance()->replaceScene(TransitionFlipX:: create(1.0, HelloWorld::createScene()));;
```

## 当玩家失败时调用我们的 GameOverScene

我们已经创建了游戏结束场景；现在让我们在炸弹与我们的`player`精灵相撞时立即显示它。为了实现这一点，我们将在`HelloWorld`类中的`onCollision`方法中添加以下代码行。

```java
_director->replaceScene(TransitionFlipX::create(1.0, GameOver::createScene()));
```

现在，通过在`HelloWorldScene.h`头文件的开始处添加以下行，将游戏结束场景头文件包含到我们的`gameplay`类中：

```java
#include "GameOverScene.h"
```

## 自定义`GameOverScene`

现在，我们不希望有黑色背景，所以我们将添加我们在第二章*图形*中在游戏玩法中使用的相同背景：

```java
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2());
  bg->setPosition(0,0);
  this->addChild(bg, -1);
```

现在，我们将更改从`PauseScene`复制的 TrueType 字体标签，它现在将显示为`Game Over`。在下一节中，我们将给这个标签添加一些效果。

```java
   auto label = Label::createWithTTF("Game Over", "fonts/Marker Felt.  ttf", 96);
```

## 添加标签效果

现在，我们将添加仅适用于 TrueType 字体的效果。

让我们为我们的字体启用轮廓。`Label`类的`enableOutline`方法接收两个参数，一个`Color4B`实例和一个整数，表示轮廓大小——数字越大，轮廓越粗：

```java
  label->enableOutline(Color4B(255, 0, 0, 100),6);
```

现在，让我们给字体添加一些发光效果：

```java
  label->enableGlow(Color4B(255, 0, 0, 255));
```

最后，让我们给标签添加阴影效果，目前所有三种标签类型都支持这一效果。

```java
  label->enableShadow();
```

你会从以下屏幕截图中注意到，效果相互重叠，所以请决定哪个效果看起来更好：

![添加标签效果](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_05_01.jpg)

`Color4B`构造方法接收四个参数。前三个是**红、绿、蓝**（**RGB**）分量，第四个是`alpha`分量。这将允许我们添加一些透明度效果，其值可以从 0 到 255。标签实例不支持自定义效果，例如给文本中的每个单词着不同的颜色，为单个文本使用不同的字体，或者在标签中嵌入图像。

### 提示

如果你有兴趣在你的游戏中添加这些字体效果，你可以使用 Luma Stubma 创建的`CCRichLabelTTF`类。这可以在[`github.com/stubma/cocos2dx-better`](https://github.com/stubma/cocos2dx-better)找到。

# 创建系统字体

你可以创建使用宿主操作系统的字体的标签；因此，不需要提供字体文件。建议只将这种标签用于测试目的，因为它会降低框架的灵活性，因为选定的字体可能不在用户的 Android 操作系统版本上可用。

为了测试，在我们当前文本下方，我们将在`GameOverScene.cpp`实现文件的`init`方法中添加以下标签：

```java
auto label2 = Label::createWithSystemFont("Your score is", "Arial", 48);
label2->setPosition(origin.x + visibleSize.width/2,origin.y + visibleSize.height /2.5);
this->addChild(label2, 1);
```

这段代码产生了以下结果：

![创建系统字体](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_05_02.jpg)

# 创建位图字体标签

到目前为止，我们已经看到了如何通过使用 TrueType 和系统字体轻松创建标签，现在我们将执行一些额外步骤，以使我们的标签具有更专业的风格。如前所述，位图字体是专业游戏中最常用的标签类型。

如其名称所示，位图字体是由代表每个字符的图像生成的，这将允许我们绘制任何我们想要的字体，但它将具有位图的所有缺点，例如标签可能被像素化的风险，处理不同尺寸时的灵活性不足，以及处理这类字体所需的磁盘和 RAM 额外空间。

有多种应用程序可用于创建位图字体。最常见的是**Glyph Designer**，你可以在[`71squared.com`](https://71squared.com)获取它。这个应用程序最初是为 Mac OS 发布的，但在 2015 年初，也为 Windows 发布了**Glyph Designer X**。你还可以使用免费的在线应用程序**Littera**来创建自己的位图字体。它可以在[`kvazars.com/littera`](http://kvazars.com/littera)找到。为了本书的需要，我们在章节中包含了位图字体的代码。我们将使用这个位图字体代码在游戏结束场景中显示玩家的总分。

## 向我们的游戏中添加更多炸弹

考虑到现在我们有一个游戏结束场景，让我们通过添加更多炸弹使这个游戏变得稍微困难一些。我们将使用 Cocos2d-x 调度器机制，它将允许我们在每个给定的时间段内调用一个方法。我们将`addBombs`方法添加到`HelloWorldScene`类中，并在前述类的`init`方法内调度它，使其每八秒被调用一次：

```java
schedule(CC_SCHEDULE_SELECTOR(HelloWorld::addBombs), 8.0f);
```

我们将向场景中添加三个随机位置的炸弹，每次调用`addBombs`方法时都会发生这种情况：

```java
void HelloWorld::addBombs(float dt)
{
   Sprite* bomb = nullptr;
   for(int i = 0 ; i < 3 ; i++)
   {
         bomb = Sprite::create("bomb.png");
         bomb->setPosition(CCRANDOM_0_1() * visibleSize.width,   visibleSize.height + bomb->getContentSize().height/2);
         this->addChild(bomb,1);
         setPhysicsBody(bomb);
         bomb->getPhysicsBody()->setVelocity(Vect(0, ( (CCRANDOM_0_1() + 0.2f) * -250) ));
   }
}
```

这段代码产生了以下结果：

![向我们的游戏中添加更多炸弹](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_05_03.jpg)

### 注意

使用`CC_SCHEDULE_SELECTOR`宏，我们创建了一个自定义选择器，在这种情况下称为**自定义时间间隔**。所选函数应该接收一个`float`参数，代表自上次调用和当前调用之间经过的时间，以便你可以独立于硬件处理速度计算统一的游戏节奏。如果你没有将第二个`float`参数传递给调度函数，那么它将在每个帧中执行所选函数。

在场景中，我们还将向调度器添加另一个方法，该方法每三秒调用一次，并将为玩家的分数增加 10 分。因此，玩家能够避免被炸弹击中的时间越长，他的得分就越高。

现在我们有超过两个物理体，这意味着我们必须修改我们的`onCollision`方法，使其只有在`player`精灵参与碰撞时才切换到`gameOverScene`。为此，我们将在方法开始处添加以下代码行：

```java
auto playerShape = _sprPlayer->getPhysicsBody()->getFirstShape();
if(playerShape != contact.getShapeA() && playerShape != contact.getShapeB())
   {
      return false;
   }
```

如果该方法没有返回，这意味着玩家精灵确实参与了碰撞。因此，我们将使用 Cocos2d-x 内置的存储机制来写入存储在成员变量`_score`中的玩家分数：

```java
UserDefault::getInstance()->setIntegerForKey("score",_score);
```

### 注意

`UserDefault`类使我们能够访问 Cocos2d-x 的数据存储机制。它可以存储`bool`、`int`、`float`、`double`和`string`类型的值。通过使用此类存储的数据可以通过调用`flush`方法来持久化，该方法将数据存储在 XML 文件中。

我们可以像创建 TrueType 字体和系统字体那样创建我们的位图字体。我们将在`GameOverScene.cpp`实现文件的`init`方法中添加以下代码行：

```java
char scoreText[32];
int score = UserDefault::getInstance()->getIntegerForKey("score",0);
sprintf(scoreText, "%d", score);
auto label3 = Label::createWithBMFont("font.fnt", scoreText);
label3->setPosition(origin.x + visibleSize.width/2,origin.y + visibleSize.height /3.5);
this->addChild(label3, 1);
```

上述代码将产生以下结果：

![向我们的游戏中添加更多炸弹](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_05_04.jpg)

# 把所有内容放在一起

在我们所有的修改之后，这就是我们的`HelloWorldScene.h`头文件的样子：

```java
#ifndef __HELLOWORLD_SCENE_H__
#define __HELLOWORLD_SCENE_H__

#include "cocos2d.h"

#include "PauseScene.h"
#include "GameOverScene.h"

```

在本章中，我们对这个头文件唯一做的更改是包含了`GameOverScene.h`：

```java
class HelloWorld : public cocos2d::Layer
{
public:
    static cocos2d::Scene* createScene();
    virtual bool init();
    void pauseCallback(cocos2d::Ref* pSender);
    CREATE_FUNC(HelloWorld);
private:
   cocos2d::Director *_director;
   cocos2d::Size visibleSize;
   cocos2d::Sprite* _sprBomb;
   cocos2d::Sprite* _sprPlayer;
   int _score;
   void initPhysics();
   bool onCollision(cocos2d::PhysicsContact& contact);
   void setPhysicsBody(cocos2d::Sprite* sprite);
   void initTouch();
   void movePlayerByTouch(cocos2d::Touch* touch, cocos2d::Event*  event);
   void movePlayerIfPossible(float newX);
   void movePlayerByAccelerometer(cocos2d::Acceleration*  acceleration, cocos2d::Event* event);
   void initAccelerometer();
   void initBackButtonListener();
   void onKeyPressed(cocos2d::EventKeyboard::KeyCode keyCode,    cocos2d::Event* event);
   void updateScore(float dt);
   void addBombs(float dt);   
};

#endif // __HELLOWORLD_SCENE_H__
```

现在，我们的`HelloWorldScene.cpp`实现文件看起来像这样：

```java
#include "HelloWorldScene.h"
#include "../cocos2d/cocos/platform/android/jni/Java_org_cocos2dx_lib_Cocos2dxHelper.h"

USING_NS_CC;

Scene* HelloWorld::createScene()
{
   auto scene = Scene::createWithPhysics();   
   scene->getPhysicsWorld()->setGravity(Vect(0,0));
   auto layer = HelloWorld::create();
   //enable debug draw
   //scene->getPhysicsWorld()->setDebugDrawMask(PhysicsWorld::DEBUGDR  AW_ALL);
   scene->addChild(layer);
   return scene;
}
```

我们现在将添加事件和物理的代码：

```java
void HelloWorld::updateScore(float dt)
{
   _score += 10;
}

void HelloWorld::addBombs(float dt)
{
   Sprite* bomb = nullptr;
   for(int i = 0 ; i < 3 ; i++)
   {
      bomb = Sprite::create("bomb.png");   
      bomb->setPosition(CCRANDOM_0_1() * visibleSize.width,  visibleSize.height + bomb->getContentSize().height/2);
      this->addChild(bomb,1);
      setPhysicsBody(bomb);
      bomb->getPhysicsBody()->setVelocity(Vect(0,  ( (CCRANDOM_0_1() + 0.2f) * -250) ));
   }
}

}

bool HelloWorld::init()
{
    if ( !Layer::init() )
    {
        return false;
    }
   _score = 0;
   _director = Director::getInstance();
   visibleSize = _director->getVisibleSize();
   auto origin = _director->getVisibleOrigin();
   auto closeItem = MenuItemImage::create("pause.png", "pause_pressed.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));

   closeItem->setPosition(Vec2(visibleSize.width - closeItem-  >getContentSize().width/2, closeItem->getContentSize().height/2));

   auto menu = Menu::create(closeItem, nullptr);
   menu->setPosition(Vec2::ZERO);
   this->addChild(menu, 1);
   _sprBomb = Sprite::create("bomb.png");
   _sprBomb->setPosition(visibleSize.width / 2,  visibleSize.height + _sprBomb->getContentSize().height/2);
   this->addChild(_sprBomb,1);
   auto bg = Sprite::create("background.png");
   bg->setAnchorPoint(Vec2());
   bg->setPosition(0,0);
   this->addChild(bg, -1);
   _sprPlayer = Sprite::create("player.png");   
   _sprPlayer->setPosition(visibleSize.width / 2, visibleSize.height * 0.23);
   setPhysicsBody(_sprPlayer);
   this->addChild(_sprPlayer, 0);
   //Animations
   Vector<SpriteFrame*> frames;
   Size playerSize = _sprPlayer->getContentSize();
   frames.pushBack(SpriteFrame::create("player.png",  Rect(0, 0, playerSize.width, playerSize.height)));
   frames.pushBack(SpriteFrame::create("player2.png",  Rect(0, 0, playerSize.width, playerSize.height)));
   auto animation =  Animation::createWithSpriteFrames(frames,0.2f);
   auto animate = Animate::create(animation);
   _sprPlayer->runAction(RepeatForever::create(animate));   

   setPhysicsBody(_sprBomb);   
   initPhysics();   
   _sprBomb->getPhysicsBody()->setVelocity(Vect(0,-100));   
   initTouch();
   initAccelerometer();   
   setKeepScreenOnJni(true);
   initBackButtonListener();
   schedule(CC_SCHEDULE_SELECTOR (HelloWorld::updateScore), 3.0f);
   schedule(CC_SCHEDULE_SELECTOR (HelloWorld::addBombs), 8.0f);
   return true;
}

void HelloWorld::pauseCallback(cocos2d::Ref* pSender){
   _director->pushScene(TransitionFlipX::create(1.0, Pause::createScene()));
}
```

我们的`GameOverScene.h`头文件现在看起来像这样：

```java
#ifndef __GameOver_SCENE_H__
#define __GameOver_SCENE_H__

#include "cocos2d.h"
#include "HelloWorldScene.h"

class GameOver : public cocos2d::Layer
{
public:
    static cocos2d::Scene* createScene();
    virtual bool init();    
    void exitPause(cocos2d::Ref* pSender);
    CREATE_FUNC(GameOver);
private:
   cocos2d::Sprite* sprLogo;
   cocos2d::Director *director;
   cocos2d::Size visibleSize;   
};

#endif // __Pause_SCENE_H__
```

最后，我们的`GameOverScene.cpp`实现文件将看起来像这样：

```java
#include "GameOverScene.h"

USING_NS_CC;

Scene* GameOver::createScene()
{
    auto scene = Scene::create();
    auto layer = GameOver::create();
    scene->addChild(layer);
    return scene;
}

bool GameOver::init()
{
    if ( !Layer::init() )
    {
        return false;
    }
   director = Director::getInstance();  
   visibleSize = director->getVisibleSize();
   Vec2 origin = director->getVisibleOrigin();
   auto pauseItem = MenuItemImage::create("play.png", "play_pressed.png", CC_CALLBACK_1(GameOver::exitPause, this));
   pauseItem->setPosition(Vec2(origin.x + visibleSize.width -   pauseItem->getContentSize().width / 2, origin.y + pauseItem-  >getContentSize().height / 2));
   auto menu = Menu::create(pauseItem, NULL);
   menu->setPosition(Vec2::ZERO);
   this->addChild(menu, 1);
   auto bg = Sprite::create("background.png");
   bg->setAnchorPoint(Vec2());
   bg->setPosition(0,0);
   this->addChild(bg, -1);
```

在以下代码行中，我们创建了在本章中介绍的三种字体类型：

```java
   auto label = Label::createWithTTF("Game Over", "fonts/Marker  Felt.ttf", 96);
   label->enableOutline(Color4B(255, 0, 0, 100),6);
   label->enableGlow(Color4B(255, 0, 0, 255));
   label->enableShadow();
   label->setPosition(origin.x + visibleSize.width/2,  origin.y + visibleSize.height /2);
   this->addChild(label, 1);
   auto label2 = Label::createWithSystemFont("Your score is",  "Arial", 48);
   label2->setPosition(origin.x + visibleSize.width/2,origin.y  + visibleSize.height/2.5);
   this->addChild(label2, 1);
   char scoreText[32];
   int score = UserDefault::getInstance()- >getIntegerForKey("score",0);
   sprintf(scoreText, "%d", score);
   auto label3 = Label::createWithBMFont("font.fnt", scoreText);
   label3->setPosition(origin.x + visibleSize.width/2,origin.y  + visibleSize.height /3.5);
   this->addChild(label3, 1);
   return true;
}

void GameOver::exitPause(cocos2d::Ref* pSender){
   Director::getInstance()- >replaceScene(TransitionFlipX::create(1.0, HelloWorld::createScene()));
}
```

# 总结

在本章中，我们了解了如何使用 TrueType 字体、系统字体和位图字体向游戏中添加文本，以及如何为这些文本添加效果。标签创建非常简单；您只需要调用其创建的静态方法，并将其添加到场景中后，就可以像在屏幕上定位精灵一样在屏幕上定位它们。

在下一章中，我们将介绍在版本 3 中从头开始编写的新音频引擎，以替代自其前身`cocos2d` for iPhone 以来与引擎捆绑的传统`CocosDenshion`音频引擎。
