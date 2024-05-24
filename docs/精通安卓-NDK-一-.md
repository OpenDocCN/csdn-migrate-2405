# 精通安卓 NDK（一）

> 原文：[`zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947`](https://zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书是 2013 年 Packt Publishing 出版的《Android NDK 游戏开发手册》的续集。它从相当不寻常的角度涵盖了 NDK 开发：以可移植的方式构建你的移动 C++应用程序，以便它们可以在桌面计算机上开发和调试。这种方法大大减少了迭代和内容集成的时间，这对于专业移动软件开发领域至关重要。

# 本书涵盖的内容

第一章，*使用命令行工具*，指导你如何使用命令行安装和配置 Android 原生开发的基本工具，以及如何从零开始手动编写基本的 Android 应用程序配置文件，而无需依赖图形化 IDE。

第二章，*原生库*，向你展示如何构建流行的 C/C++库，并使用 Android NDK 将它们链接到你的应用程序中。这些库是实现图像、视频、声音和网络完全在 C++中丰富的功能应用程序的构建块。我们将展示如何编译库，当然也会给出一些关于如何开始使用它们的示例和提示。其中一些库在后续章节中会有更详细的讨论。

第三章，*网络编程*，重点关注如何从原生 C/C++代码处理网络相关功能。网络任务是异步的，就时间而言是不可预测的。即使底层连接是使用 TCP 协议建立的，也不能保证交付时间，且应用程序在等待数据时没有任何防冻措施。我们将详细探讨以可移植方式实现基本异步机制的方法。

第四章，*组织虚拟文件系统*，实现了低级别的抽象来处理与操作系统无关的文件和文件系统的访问。我们将展示如何在不依赖任何内置 API 的情况下，实现对`.apk`文件中打包的 Android 资源的可移植和透明访问。在构建可在桌面环境中调试的多平台应用程序时，这种方法是必要的。

第五章, *跨平台音频流*，基于 OpenAL 库为 Android 和桌面 PC 实现了一个真正可移植的音频子系统。代码使用了来自第三章，*网络编程*的多线程材料。

第六章，*OpenGL ES 3.1 与跨平台渲染*，专注于如何在 OpenGL 4 和 OpenGL ES 3 之上实现一个抽象层，以使我们的 C++图形应用程序能够在 Android 和桌面计算机上运行。

第七章，*跨平台 UI 与输入系统*，详细描述了一种渲染几何原语和 Unicode 文本的机制。章节的第二部分描述了一个多页图形用户界面，适合作为构建多平台应用程序界面的基石。这一章以一个 SDL 应用程序作为结尾，展示了我们 UI 系统在实际中的能力。

第八章，*编写渲染引擎*，将带你进入实际的渲染领域，并使用在第六章，*OpenGL ES 3.1 与跨平台渲染*中讨论的薄抽象层，来实现一个能够渲染从文件中加载的几何体，并使用材质、光线和阴影的 3D 渲染框架。

第九章，*实现游戏逻辑*，介绍了一种常见的组织游戏代码与程序用户界面部分交互的方法。这一章从 Boids 算法的实现开始，然后继续扩展我们在之前章节中实现的用户界面。

第十章，*编写小行星游戏*，继续将之前章节的材料整合在一起。我们将使用前几章介绍的技术和代码片段，实现一个具有 3D 图形、阴影、粒子和声音的小行星游戏。

# 你需要为这本书准备什么

本书假设你拥有一台基于 Windows 的 PC。由于模拟器在 3D 图形和原生音频方面的限制，建议使用 Android 智能手机或平板。

### 注意事项

本书中的源代码基于开源的 Linderdaum 引擎，并提炼了引擎中使用的一些方法和技巧。你可以在[`www.linderdaum.com`](http://www.linderdaum.com)获取它。

假设你具备 C 或 C++的基础知识，包括指针操作、多线程和基本的面向对象编程概念。你应该熟悉高级编程概念，如线程和同步原语，并对 GCC 工具链有一定的基本了解。本书不涉及 Android Java 开发，你需要阅读其他资料来熟悉它。

对线性代数以及 3D 空间中的仿射变换有一定的了解将有助于理解 3D 图形相关的章节。

# 本书的目标读者

本书面向已经熟悉 Android NDK 基础知识的现有 Android 开发者，他们希望在使用 Android NDK 进行游戏开发方面获得专业知识。读者必须具有合理的 Android 应用程序开发经验。

# 约定

在这本书中，您会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 处理程序将如下显示："编译 Android 静态库需要一组常规的`Android.mk`和`Application.mk`文件。"

代码块设置如下：

```java
std::string ExtractExtension( const std::string& FileName )
{
  size_t pos = FileName.find_last_of( '.' );
  return ( pos == std::string::npos ) ?
    FileName : FileName.substr( pos );
}
```

当我们希望引起您对代码块中某个特定部分的注意时，相关的行或项目会以粗体显示：

```java
std::string ExtractExtension( const std::string& FileName )
{
  size_t pos = FileName.find_last_of( '.' );
  return ( pos == std::string::npos ) ?
    FileName : FileName.substr( pos );
}
```

任何命令行输入或输出都如下编写：

```java
>ndk-build
>ant debug
>adb install -r bin/App1-debug.apk

```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词，例如菜单或对话框中的，会在文本中以这样的形式出现："检查打印到 Android 系统日志中的行**Hello Android NDK!**。"

### 注意

警告或重要注意事项会像这样出现在一个框中。

### 提示

技巧和窍门会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对这本书的看法——您喜欢或可能不喜欢的内容。读者的反馈对我们开发您真正能充分利用的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果您在某个主题上有专业知识，并且有兴趣撰写或为书籍做贡献，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然您已经拥有了 Packt 的一本书，我们有许多方法可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您的账户[`www.packtpub.com`](http://www.packtpub.com)下载您购买的所有 Packt 图书的示例代码文件。如果您在别处购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会将文件直接通过电子邮件发送给您。源代码也可以从这个 GitHub 仓库地址[`github.com/corporateshark/Mastering-Android-NDK`](https://github.com/corporateshark/Mastering-Android-NDK)获取。查看它以获取源代码的最新版本。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然在所难免。如果您在我们的书中发现错误——可能是文本或代码中的错误——若您能向我们报告，我们将不胜感激。这样做可以避免其他读者产生困扰，并帮助我们改进本书后续版本。如果您发现任何勘误信息，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表单**链接，并输入您的勘误详情。一旦您的勘误信息得到验证，您的提交将被接受，勘误信息将会被上传到我们的网站，或添加到该标题勘误部分现有的勘误列表中。任何现有的勘误信息可以通过选择您的标题从[`www.packtpub.com/support`](http://www.packtpub.com/support)进行查看。

## 盗版问题

互联网上版权材料的盗版问题在所有媒体中持续存在。在 Packt，我们非常重视保护我们的版权和许可。如果您在任何形式下在互联网上发现我们作品非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如发现疑似盗版材料，请通过 `<copyright@packtpub.com>` 联系我们，并提供相关链接。

我们感谢您帮助保护我们的作者，以及我们向您提供有价值内容的能力。

## 问题咨询

如果您在书的任何方面遇到问题，可以通过 `<questions@packtpub.com>` 联系我们，我们将尽力解决。


# 第一章：使用命令行工具

在本章中，我们将介绍主要与 Android 应用程序的创建和打包相关的命令行工具。我们将学习如何在 Microsoft Windows、Apple OS X 和 Ubuntu/Debian Linux 上安装和配置 Android NDK，以及如何在 Android 设备上构建和运行你的第一个本地应用程序。使用命令行工具构建项目对于使用 C++进行跨平台移动开发至关重要。

### 注意

本书基于 Android SDK 修订版 24.3.3 和 Android NDK r10e。源代码已使用 Android API 级别 23（Marshmallow）进行测试。

我们的主要关注点将是命令行为中心和平台无关的开发过程。

### 注意

Android Studio 是一个非常不错的新便携式开发 IDE，最近已更新至 1.4 版本。然而，它对 NDK 的支持仍然非常有限，本书将不对其进行讨论。

# 在 Windows 上使用 Android 命令行工具

要在 Microsoft Windows 环境中开始开发 Android 的原生 C++应用程序，你需要在系统上安装一些基本工具。

使用以下所需前提条件的列表开始为 Android 开发 NDK：

+   Android SDK：你可以在[`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html)找到它。我们使用修订版 24。

+   Android NDK：你可以在[`developer.android.com/tools/sdk/ndk/index.html`](http://developer.android.com/tools/sdk/ndk/index.html)找到它。我们使用版本 r10e。

+   **Java 开发工具包**（**JDK**）：你可以在[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)找到它。我们使用 Oracle JDK 版本 8。

+   Apache Ant：你可以在[`ant.apache.org`](http://ant.apache.org)找到它。这是用于构建 Java 应用程序的工具。

+   Gradle：你可以在[`www.gradle.org`](https://www.gradle.org)找到它。与 Ant 相比，这是一个更现代的 Java 构建自动化工具，能够管理外部依赖。

这些工具的当前版本在 Windows 上运行时无需使用任何中间兼容层；它们不再需要 Cygwin。

尽管这让我们感到痛苦，但 Android SDK 和 NDK 仍应安装到不包含空格的文件夹中。这是 Android SDK 内部构建脚本的限制；未加引号的环境变量内容会根据制表符、空格和新行字符分割成单词。

我们将把 Android SDK 安装到`D:\android-sdk-windows`，Android NDK 安装到`D:\ndk`，其他软件安装到它们的默认位置。

为了编译我们可移植的 C++代码以在 Windows 上运行，我们需要一个像样的工具链。我们推荐使用 Equation 软件包提供的最新版 MinGW，可在[`www.equation.com`](http://www.equation.com)获取。你可以根据需要选择 32 位或 64 位版本。

将所有工具放入各自的文件夹后，你需要设置环境变量以指向这些安装位置。`JAVA_HOME` 变量应指向 Java 开发工具包文件夹：

```java
JAVA_HOME="D:\Program Files\Java\jdk1.8.0_25"

```

`NDK_HOME` 变量应指向 Android NDK 安装目录：

```java
NDK_HOME=D:\NDK

```

`ANDROID_HOME` 应指向 Android SDK 文件夹：

```java
ANDROID_HOME=D:\\android-sdk-windows

```

### 注意

注意最后一行中的双反斜杠。

NDK 和 SDK 将会不定期推出新版本，因此如果需要在文件夹名称中包含版本号，并按项目管理 NDK 文件夹可能会有帮助。

# 在 OS X 上使用 Android 命令行工具

在 OS X 上安装 Android 开发工具非常直接。首先，你需要从 [`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html) 下载所需的官方 SDK 和 NDK 包。由于我们使用的是命令行工具，我们可以使用在 [`dl.google.com/android/android-sdk_r24.0.2-macosx.zip`](http://dl.google.com/android/android-sdk_r24.0.2-macosx.zip) 可用的 SDK 工具包。至于 NDK，OS X Yosemite 可以使用 64 位 Android NDK，可以从 [`developer.android.com/tools/sdk/ndk/index.html`](http://developer.android.com/tools/sdk/ndk/index.html) 下载。

我们将所有这些工具安装到用户的 home 文件夹中；在我们的例子中，它是 `/Users/sk`。

要获取 Apache Ant 和 Gradle，最好的方式是安装包管理器 Homebrew，访问 [`brew.sh`](http://brew.sh) 并使用以下命令安装所需的工具：

```java
$ brew install ant
$ brew install gradle

```

这样你就不会被安装路径和其他低级配置问题所困扰。以下是安装包和设置路径的步骤：

### 注意

由于这本书的理念是通过命令行执行操作，我们确实会采取较为复杂的方式。不过，我们建议你实际上在浏览器中访问下载页面，[`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html)，检查 Android SDK 和 NDK 的更新版本。

1.  从官方网站下载适用于 OS X 的 Android SDK 并将其放入你的 home 目录：

    ```java
    >curl -o android-sdk-macosx.zip http://dl.google.com/android/android-sdk_r24.0.2-macosx.zip

    ```

1.  解压它：

    ```java
    >unzip android-sdk-macosx.zip

    ```

1.  然后，下载 Android NDK。它是一个自解压的二进制文件：

    ```java
    >curl -o android-ndk-r10e.bin http://dl.google.com/android/ndk/android-ndk-r10e-darwin-x86_64.bin

    ```

1.  因此，只需将其设置为可执行并运行：

    ```java
    >chmod +x android-ndk-r10e.bin
    >./android-ndk-r10e.bin

    ```

1.  包已就位。现在，在你的 home 目录中的 `.profile` 文件中添加工具的路径以及所有必要的环境变量：

    ```java
    export PATH=/Users/sk/android-ndk-r10e:/Users/sk/android-ndk-r10e/prebuilt/darwin-x86_64/bin:/Users/sk/android-sdk-macosx/platform-tools:$PATH

    ```

1.  在 Android 脚本和工具中使用这些变量：

    ```java
    export NDK_ROOT="/Users/sk/android-ndk-r10e"
    export ANDROID_SDK_ROOT="/Users/sk/android-sdk-macosx"

    ```

1.  编辑 `local.properties` 文件以按项目设置路径。

# 在 Linux 上使用 Android 命令行工具

在 Linux 上的安装与 OS X 一样简单。

### 注意

实际上，由于所有工具链和 Android 开源项目都基于 Linux 工具，Linux 开发环境确实是所有类型 Android 开发的原生环境。

在这里，我们仅指出一些不同之处。首先，我们不需要安装 Homebrew。只需使用可用的包管理器。在 Ubuntu 上，我们更愿意使用 `apt`。以下是安装包以及设置 Linux 上的路径的步骤：

1.  首先，我们来更新所有的 `apt` 包并安装默认的 Java 开发工具包：

    ```java
    $ sudo apt-get update
    $ sudo apt-get install default-jdk

    ```

1.  安装 Apache Ant 构建自动化工具：

    ```java
    $ sudo apt-get install ant

    ```

1.  安装 Gradle：

    ```java
    $ sudo apt-get install gradle

    ```

1.  从 [`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html) 下载适合你 Linux 版本的官方 Android SDK，并将其解压到你的主目录下的一个文件夹中：

    ```java
    $ wget http://dl.google.com/android/android-sdk_r24.0.2-linux.tgz
    $ tar –xvf android-sdk_r24.0.2-linux.tgz

    ```

1.  下载适合你 Linux 系统（32 位或 64 位）的官方 NDK 包并运行它：

    ```java
    $ wget http://dl.google.com/android/ndk/android-ndk-r10e-linux-x86_64.bin
    $ chmod +x android-ndk-r10e-linux-x86_64.bin
    $ ./android-ndk-r10e-linux-x86_64.bin

    ```

    该可执行文件将把 NDK 包的内容解压到当前目录。

1.  现在，你可以设置环境变量以指向实际的文件夹：

    ```java
    NDK_ROOT=/path/to/ndk
    ANDROID_HOME=/path/to/sdk

    ```

    ### 注意

    将环境变量定义添加到 `/etc/profile` 或 `/etc/environment` 中很有用。这样，这些设置将适用于系统的所有用户。

# 手动创建基于 Ant 的应用程序模板

让我们从最低级别开始，创建一个可使用 Apache Ant 构建的应用程序模板。每个要使用 Apache Ant 构建的应用程序都应包含预定义的目录结构和配置 `.xml` 文件。这通常使用 Android SDK 工具和 IDE 完成。我们将解释如何手动完成，以让你了解幕后的机制。

### 提示

**下载示例代码**

你可以从 [`www.packtpub.com`](http://www.packtpub.com) 的账户下载你购买的所有 Packt Publishing 书籍的示例代码文件。如果你在其他地方购买了这本书，可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，我们会直接将文件通过电子邮件发送给你。

对于这本书，源代码文件也可以从以下 GitHub 仓库下载或派生：[`github.com/corporateshark/Mastering-Android-NDK`](https://github.com/corporateshark/Mastering-Android-NDK)

我们最小化项目的目录结构如下截图所示（完整的源代码请参见源代码包）：

![手动创建基于 Ant 的应用程序模板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00212.jpeg)

我们需要在此目录结构中创建以下文件：

+   `res/drawable/icon.png`

+   `res/values/strings.xml`

+   `src/com/packtpub/ndkmastering/App1Activity.java`

+   `AndroidManifest.xml`

+   `build.xml`

+   `project.properties`

图标 `icon.png` 应该在那里，目前包含一个安卓应用程序的示例图像：

![手动创建基于 Ant 的应用程序模板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00213.jpeg)

文件`strings.xml`是使用 Android 本地化系统所必需的。在`AndroidManifest.xml`清单文件中，我们使用字符串参数`app_name`而不是实际的应用程序名称。文件`strings.xml`将此参数解析为人类可读的字符串：

```java
<?xml version="1.0" encoding="utf-8"?>
<resources>
  <string name="app_name">AntApp1</string>
</resources>
```

最小可构建应用程序的 Java 源代码在`App1Activity.java`文件中：

```java
package com.packtpub.ndkmastering;
import android.app.Activity;
public class App1Activity extends Activity
{
};
```

其他三个文件`AndroidManifest.xml`、`build.xml`和`project.properties`，包含了 Ant 构建项目所需的描述。

清单文件`AndroidManifest.xml`如下所示：

```java
<?xml version="1.0" encoding="utf-8"?>
<manifest 
package="com.packtpub.ndkmastering"
android:versionCode="1"
android:versionName="1.0.0">
```

我们的应用程序将需要 Android 4.4（API 级别 19），并且已经在 Android 6.0（API 级别 23）上进行了测试：

```java
<uses-sdk android:minSdkVersion="19" android:targetSdkVersion="23" />
```

本书中的大多数示例将需要 OpenGL ES 3。在此提及一下：

```java
<uses-feature android:glEsVersion="0x00030000"/>
<application android:label="@string/app_name"
android:icon="@drawable/icon"
android:installLocation="preferExternal"
android:largeHeap="true"
android:allowBackup="true">
```

这是主活动的名称：

```java
<activity android:name="com.packtpub.ndkmastering.App1Activity"
android:launchMode="singleTask"
```

我们希望应用程序在全屏模式下，且为横屏方向：

```java
android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
android:screenOrientation="landscape"
```

我们的应用程序可以从系统启动器中启动。应用程序的可显示名称存储在`app_name`参数中：

```java
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

### 注意

你可以在[`developer.android.com/guide/topics/manifest/manifest-intro.html`](http://developer.android.com/guide/topics/manifest/manifest-intro.html)阅读官方关于应用程序清单的 Google 文档。

文件`build.xml`要简单得多，主要与 Android 工具生成的类似：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project name="App1" default="help">
  <loadproperties srcFile="project.properties" />
  <fail message="sdk.dir is missing. Make sure to generate local.properties using 'android update project' or to inject it through an env var"
    unless="sdk.dir"/>
  <import file="${sdk.dir}/tools/ant/build.xml" />
</project>
```

与 Android SDK Tools 相比，这里我们没有使用`ant.properties`。这样做只是为了简单起见，仅具有教育目的。

文件`project.properties`同样包含特定平台的声明，情况类似：

```java
target=android-19
sdk.dir=d:/android-sdk-windows

```

现在，我们的第一个应用程序（甚至还没有包含任何本地代码）已经准备好构建了。使用以下命令行构建它：

```java
$ ant debug

```

如果一切操作都正确，你应该会看到类似于以下的输出尾部：

![手动创建基于 Ant 的应用程序模板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00214.jpeg)

要从命令行安装`.apk`文件，请运行`adb install -r bin/App1-debug.apk`以将新构建的`.apk`安装到你的设备上。从启动器（**AntApp1**）启动应用程序，并享受黑色的屏幕。你可以使用**BACK**键退出应用程序。

# 手动创建基于 Gradle 的应用程序模板

相比于 Ant，Gradle 是一个更加多功能的 Java 构建工具，它能轻松地处理外部依赖和仓库。

### 注意

我们建议在继续使用 Gradle 之前，观看 Google 提供的[`www.youtube.com/watch?v=LCJAgPkpmR0`](https://www.youtube.com/watch?v=LCJAgPkpmR0)这个视频，并阅读官方的命令行构建手册[`developer.android.com/tools/building/building-cmdline.html`](http://developer.android.com/tools/building/building-cmdline.html)。

近期的 Android SDK 版本与 Gradle 紧密集成，Android Studio 就是使用它作为其构建系统的。让我们扩展之前的`1_AntApp`应用程序，使其能够用 Gradle 构建。

首先，进入项目的根目录，并创建一个包含以下内容的`build.gradle`文件：

```java
buildscript {
  repositories {
    mavenCentral()
  }
  dependencies {
    classpath 'com.android.tools.build:gradle:1.0.0'
  }
}
apply plugin: 'com.android.application'
android {
  buildToolsVersion "19.1.0"
  compileSdkVersion 19
  sourceSets {
    main {
      manifest.srcFile 'AndroidManifest.xml'
      java.srcDirs = ['src']
      resources.srcDirs = ['src']
      aidl.srcDirs = ['src']
      renderscript.srcDirs = ['src']
      res.srcDirs = ['res']
      assets.srcDirs = ['assets']
    }
  }
  lintOptions {
    abortOnError false
  }
}
```

完成后，运行命令`gradle init`。输出结果应类似于以下内容：

```java
>gradle init
:init
The build file 'build.gradle' already exists. Skipping build initialization.
:init SKIPPED
BUILD SUCCESSFUL
Total time: 5.271 secs

```

当前文件夹中将创建`.gradle`子文件夹。现在，运行以下命令：

```java
>gradle build

```

输出的末尾应如下所示：

```java
:packageRelease
:assembleRelease
:assemble
:compileLint
:lint
Ran lint on variant release: 1 issues found
Ran lint on variant debug: 1 issues found
Wrote HTML report to file:/F:/Book_MasteringNDK/Sources/Chapter1/2_GradleApp/build/outputs/lint-results.html
Wrote XML report to F:\Book_MasteringNDK\Sources\Chapter1\2_GradleApp\build\outputs\lint-results.xml
:check
:build
BUILD SUCCESSFUL
Total time: 9.993 secs

```

生成的`.apk`包可以在`build\outputs\apk`文件夹中找到。尝试在您的设备上安装并运行`2_GradleApp-debug.apk`。

# 嵌入本地代码

让我们继续这本书的主题，为我们的模板应用程序编写一些本地 C++代码。我们将从包含单个函数定义的`jni/Wrappers.cpp`文件开始：

```java
#include <stdlib.h>
#include <jni.h>
#include <android/log.h>
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "NDKApp", __VA_ARGS__))
extern "C"
{
  JNIEXPORT void JNICALL Java_com_packtpub_ndkmastering_AppActivity_onCreateNative( JNIEnv* env, jobject obj )
  {
    LOGI( "Hello Android NDK!" );
  }
}
```

这个函数将通过 JNI 机制从 Java 中调用。如下更新`AppActivity.java`：

```java
package com.packtpub.ndkmastering;
import android.app.Activity;
import android.os.Bundle;
public class AppActivity extends Activity
{
  static
  {
    System.loadLibrary( "NativeLib" );
  }
  @Override protected void onCreate( Bundle icicle )
  {
    super.onCreate( icicle );
    onCreateNative();
  }
  public static native void onCreateNative();
};
```

现在，我们需要将这段代码构建成一个可安装的`.apk`包。为此我们需要几个配置文件。第一个是`jni/Application.mk`，它包含平台和工具链信息：

```java
APP_OPTIM := release
APP_PLATFORM := android-19
APP_STL := gnustl_static
APP_CPPFLAGS += -frtti
APP_CPPFLAGS += -fexceptions
APP_CPPFLAGS += -DANDROID
APP_ABI := armeabi-v7a-hard
APP_MODULES := NativeLib
NDK_TOOLCHAIN_VERSION := clang
```

我们使用最新版本的 Clang 编译器——即在我们编写这些内容时的 3.6 版本，以及`armeabi-v7a-hard`目标，它支持硬件浮点计算和通过硬件浮点寄存器传递函数参数，从而实现更快的代码。

第二个配置文件是`jni/Android.mk`，它指定了我们想要编译的`.cpp`文件以及应使用的编译器选项：

```java
TARGET_PLATFORM := android-19
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := NativeLib
LOCAL_SRC_FILES += Wrappers.cpp
LOCAL_ARM_MODE := arm
COMMON_CFLAGS := -Werror -DANDROID -DDISABLE_IMPORTGL
ifeq ($(TARGET_ARCH),x86)
  LOCAL_CFLAGS := $(COMMON_CFLAGS)
else
  LOCAL_CFLAGS := -mfpu=vfp -mfloat-abi=hard -mhard-float -fno-short-enums -D_NDK_MATH_NO_SOFTFP=1 $(COMMON_CFLAGS)
endif
LOCAL_LDLIBS := -llog -lGLESv2 -Wl,-s
LOCAL_CPPFLAGS += -std=gnu++11
include $(BUILD_SHARED_LIBRARY)
```

在这里，我们链接到 OpenGL ES 2，为非 x86 目标启用硬件浮点数的编译器开关，并列出所需的`.cpp`源文件。

使用以下命令从项目根目录构建本地代码：

```java
>ndk-build

```

输出结果应如下所示：

```java
>ndk-build
[armeabi-v7a-hard] Compile++ arm  : NativeLib <= Wrappers.cpp
[armeabi-v7a-hard] SharedLibrary  : libNativeLib.so
[armeabi-v7a-hard] Install        : libNativeLib.so => libs/armeabi-v7a/libNativeLib.so

```

最后，我们需要告诉 Gradle，我们希望将生成的本地库打包进`.apk`。编辑`build.gradle`文件，在`sourceSets`的`main`部分添加以下行：

```java
jniLibs.srcDirs = ['libs']

```

现在，如果我们运行命令`gradle build`，生成的包`build\outputs\apk\3_NDK-debug.apk`将包含所需的`libNativeLib.so`文件。您可以像往常一样安装并运行它。使用`adb logcat`检查 Android 系统日志中打印的**Hello Android NDK!**这一行。

### 注意

那些不想在这样的小项目中处理 Gradle 的人可以使用古老的 Apache Ant。只需运行命令`ant debug`即可实现。这种方式不需要额外的配置文件将共享的 C++库放入`.apk`。

# 构建并签署发布版的 Android 应用

我们已经学习了如何使用命令行创建带有本地代码的 Android 应用。让我们在命令行工具的话题上画上圆满的句号，学习如何准备并签署应用程序的发布版本。

关于在 Android 上签名过程的详细解释，可以在开发者手册中找到，地址是 [`developer.android.com/tools/publishing/app-signing.html`](http://developer.android.com/tools/publishing/app-signing.html)。让我们使用 Ant 和 Gradle 来完成签名。

首先，我们需要重新构建项目并创建 `.apk` 包的发布版本。让我们用 `3_NDK` 项目来做这件事。我们使用以下命令调用 `ndk-build` 和 Apache Ant：

```java
>ndk-build
>ant release

```

Ant 输出的末尾如下所示：

```java
-release-nosign:
[echo] No key.store and key.alias properties found in build.properties.
[echo] Please sign F:\Book_MasteringNDK\Sources\Chapter1\3_NDK\bin\App1-release-unsigned.apk manually
[echo] and run zipalign from the Android SDK tools.
[propertyfile] Updating property file: F:\Book_MasteringNDK\Sources\Chapter1\3_NDK\bin\build.prop
[propertyfile] Updating property file: F:\Book_MasteringNDK\Sources\Chapter1\3_NDK\bin\build.prop
[propertyfile] Updating property file: F:\Book_MasteringNDK\Sources\Chapter1\3_NDK\bin\build.prop
[propertyfile] Updating property file: F:\Book_MasteringNDK\Sources\Chapter1\3_NDK\bin\build.prop
-release-sign:
-post-build:
release:
BUILD SUCCESSFUL
Total time: 2 seconds

```

让我们用 Gradle 做同样的事情。也许您已经注意到，当我们运行 gradle build 时，`build/outputs/apk` 文件夹中有一个 `3_NDK-release-unsigned.apk` 文件。这正是我们所需要的。这将是我们签名过程的原材料。

现在，我们需要一个有效的发布密钥。我们可以使用 Java 开发工具包中的 `keytool` 创建自签名的发布密钥，使用以下命令：

```java
$ keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000

```

这将要求我们填写创建 `release key` 和 `keystore` 时所需的所有字段。

```java
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

现在，我们准备进行实际的 `.apk` 包签名。使用 Java 开发工具包中的 `jarsigner` 工具来完成这个操作：

```java
>jarsigner -verbose -sigalg MD5withRSA -digestalg SHA1 -keystore my-release-key.keystore 3_NDK-release-unsigned.apk alias_name

```

这个命令是交互式的，它将要求用户输入 `keystore` 和 `key passwords`。但是，我们可以以下面的方式将这两个密码作为参数提供给这个命令：

```java
>jarsigner -verbose -sigalg MD5withRSA -digestalg SHA1 -keystore my-release-key.keystore -storepass 123456 –keypass 123456 3_NDK-release-unsigned.apk alias_name

```

当然，密码应与您在创建 `release key` 和 `keystore` 时输入的密码相匹配。

在我们能够安全地在 Google Play 上发布 `.apk` 包之前，还有一件重要的事情要做。Android 应用程序可以使用内存映射文件和 `mmap()` 系统调用来访问 `.apk` 中的未压缩内容，但 `mmap()` 可能会对底层数据施加一些对齐限制。我们需要将 `.apk` 中的所有未压缩数据按照 4 字节边界对齐。Android SDK 有 `zipalign` 工具来完成这个操作，如下面的命令所示：

```java
>zipalign -v 4 3_NDK-release-unsigned.apk 3_NDK-release.apk

```

现在，我们的 `.apk` 已准备好在 Google Play 上发布。

# 组织跨平台代码

本书延续了我们之前出版的《*Android NDK 游戏开发手册*, *Packt Publishing*> 的思想：即使用“所见即所得”原则进行跨平台开发的可能。大部分应用程序逻辑可以在熟悉的桌面环境如 Windows 中开发并测试，手头拥有所有必要的工具，必要时可以构建为 Android 使用 NDK。

为了组织和维护跨平台的 C++ 源代码，我们需要将所有内容分为平台特定和平台独立部分。我们的 Android 特定本地代码将存储在项目的 `jni` 子文件夹中，这与我们之前的简约示例完全相同。共享的平台独立 C++ 代码将放入 `src-native` 子文件夹。

# 使用 TeamCity 持续集成服务器与 Android 应用程序

TeamCity 是一个强大的持续集成和部署服务器，可用于自动化你的 Android 应用构建。这可以在 [`www.jetbrains.com/teamcity`](https://www.jetbrains.com/teamcity) 找到。

### 注意

TeamCity 对最多需要 20 个构建配置和 3 个构建代理的小型项目是免费的，对于开源项目则是完全免费的。在 [`www.jetbrains.com/teamcity/buy`](https://www.jetbrains.com/teamcity/buy) 申请开源许可。

服务器安装过程非常直接。Windows、OS X 或 Linux 机器可以作为服务器或构建代理。这里，我们将展示如何在 Windows 上安装 TeamCity。

从 [`www.jetbrains.com/teamcity/download`](https://www.jetbrains.com/teamcity/download) 下载最新版本的安装程序，并使用以下命令运行它：

```java
>TeamCity-9.0.1.exe

```

安装所有组件并将其作为 **Windows 服务** 运行。为了简单起见，我们将在一台机器上同时运行服务器和代理，如下面的屏幕截图所示：

![在 Android 应用程序中使用 TeamCity 持续集成服务器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00215.jpeg)

选择所需的 TeamCity 服务器端口。我们将使用默认的 HTTP 端口 80。在 `SYSTEM` 账户下运行 **TeamCity 服务器** 和 **代理** 服务。

一旦服务器上线，打开你的浏览器并通过地址 `http://localhost` 连接到它。创建一个新项目和构建配置。

### 注意

要使用 TeamCity，你应该将你的项目源代码放入版本控制系统。Git 和 GitHub 将是一个不错的选择。

如果你的项目已经在 GitHub 上，你可以创建一个指向你的 GitHub 仓库 URL 的 Git 版本控制系统根目录，如下所示 `https://github.com/<你的登录名>/<你的项目>.git`。

添加一个新的命令行构建步骤并输入脚本的内容：

```java
ndk-build
ant release

```

你也可以在这里添加使用 `jarsigner` 的签名，并使用 `zipalign` 工具创建最终的 `.apk` 生产文件。

现在，进入 **通用设置** 步骤并将工件路径添加到 `bin/3_NDK-release.apk`。项目已准备好进行持续集成。

# 概括

在本章中，我们学习了如何使用命令行安装和配置 Android 原生开发的基本工具，以及如何不依赖图形 IDE 而手动编写 Android 应用基本配置文件。在后续章节中，我们将练习这些技能并构建一些项目。


# 第二章：本地库

在本章中，你将学习如何使用 Android NDK 构建流行的 C/C++库，并将它们链接到你的应用程序中。这些库是实现图像、视频、声音、物理模拟和完全在 C++中网络功能的丰富功能应用程序的构建块。我们将提供最小示例来演示每个库的功能。音频和网络库将在后续章节中详细讨论。我们将向你展示如何编译库，当然也会提供一些简短的示例和如何开始使用它们的提示。

在不同处理器和操作系统间移植库的典型陷阱包括内存访问（结构对齐和填充）、字节序（大小端）、调用约定和浮点问题。前面章节中描述的所有库都很好地解决了这些问题，即使其中一些库没有正式支持 Android NDK，修复这些问题也只是几个编译器开关的问题。

为了构建上述库，我们需要为 Windows、Linux 和 OS X 创建 makefile，并为 NDK 创建一对`Android.mk/Application.mk`文件。库的源文件被编译成目标文件。一系列目标文件组合成一个档案，这也称为静态库。之后，这个静态库可以作为链接器的输入。我们从桌面版本开始，首先为 Windows。

为了构建特定于 Windows 的库版本，我们需要一个 C++编译器。我们将使用来自 MinGW 的 GCC 工具链，该工具链在第一章，*使用命令行工具*中描述。对于每个库，我们有一系列源代码文件，我们需要得到静态库，一个带有`.a`扩展名的文件。

# 处理预编译的静态库

将我们需要的库在不同平台构建的源代码放入`src`目录中。Makefile 脚本应该如下开始：

```java
CFLAGS = -O2 -I src
```

这行定义了一个变量`CFLAGS`，其中包含编译器命令行参数的列表。在我们的例子中，我们指示编译器在`src`目录中查找头文件。如果库源代码跨越多个目录，我们需要为每个目录添加`–I`开关。`-O2`开关告诉编译器启用 2 级优化。接下来，我们为每个源文件添加以下行：

```java
<SourceFileName>.o:
gcc $(CFLAGS) –c <SourceFile>.cpp –o <SourceFile>.o
```

字符串`<SourceFileName>`应该被替换为实际的`.cpp`源文件名，并且这些行应该针对每个源文件编写。

现在，我们添加目标文件列表：

```java
ObjectFiles = <SourceFile1>.o <SourceFile2>.o
```

最后，我们将编写我们库的目标：

```java
<LibraryName>:
ar –rvs <LibraryName>.a $(ObjectList)
```

Makefile 脚本中除了空行和目标名称以外的每一行都应该以制表符开头。要构建库，请调用以下命令：

```java
>make <LibraryName>.a

```

当在我们的程序中使用库时，我们将`LibraryName.a`文件作为参数传递给`gcc`。

Makefile 由类似于编程语言中子例程的目标组成，通常每个目标都会生成一个目标文件。例如，我们已经看到，库的每个源文件都编译成相应的目标文件。

目标名称可能包括文件名模式以避免复制粘贴，但在最简单的情况下，我们只需列出所有源文件，并复制这些行，将`SourceFileName`字符串替换为适当的文件名。`gcc`命令后的`–c`开关是编译源文件的选项，而`–o`指定输出目标文件的名字。`$(CFLAGS)`符号表示将`CFLAGS`变量的值代入命令行。

Windows 的 GCC 工具链包括`ar`工具，它是归档器的缩写。我们库的 Makefile 调用此工具来创建库的静态版本。这将在 Makefile 脚本的最后几行完成。

当带有目标文件列表的一行变得过长时，可以使用反斜杠符号将其分成多行，如下所示：

```java
ObjectFileList = FileName1.o \
                 ... \
                 FileNameN.o
```

反斜杠后面不应该有空白，因为这是`make`工具的限制。`make`工具是可移植的，因此同样的规则精确适用于我们使用的所有桌面操作系统：Windows、Linux 和 OS X。

现在，我们能够使用 Makefiles 和命令行构建大多数库。让我们为 Android 构建它们。首先，创建一个名为`jni`的文件夹，并创建一个`jni/Application.mk`文件，其中包含适当的编译器开关并相应地设置库的名称。例如，Theora 库的一个应该如下所示：

```java
APP_OPTIM := release
APP_PLATFORM := android-19
APP_STL := gnustl_static
APP_CPPFLAGS += -frtti
APP_CPPFLAGS += -fexceptions
APP_CPPFLAGS += -DANDROID
APP_ABI := armeabi-v7a-hard
APP_MODULES := Theora
NDK_TOOLCHAIN_VERSION := clang
```

### 注意

在这里，我们将使用`armeabi-v7a-hard`作为支持最广泛的现代 ABI 之一。Android NDK 支持许多其他架构和 CPU。请参考 NDK 程序员指南以获取完整且最新的列表。

它将使用安装的 NDK 中可用的最新版本的 Clang 编译器。`jni/Android.mk`文件与我们之前章节为`3_NDK`示例应用程序编写的文件类似，但有一些例外。在文件顶部，必须定义一些必要的变量。让我们看看 OpenAL-Soft 库的`Android.mk`文件可能的样子：

```java
TARGET_PLATFORM := android-19
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_MODULE := OpenAL
LOCAL_C_INCLUDES += src
LOCAL_SRC_FILES += <ListOfSourceFiles>
```

定义一些常见的编译器选项：将所有警告视为错误（`-Werror`），定义`ANDROID`预处理符号：

```java
COMMON_CFLAGS := -Werror -DANDROID
```

编译标志根据选定的 CPU 架构定义：

```java
ifeq ($(TARGET_ARCH),x86)
  LOCAL_CFLAGS := $(COMMON_CFLAGS)
else
  LOCAL_CFLAGS := -mfpu=vfp -mfloat-abi=hard -mhard-float -fno-short-enums -D_NDK_MATH_NO_SOFTFP=1 $(COMMON_CFLAGS)
endif
```

在我们所有的示例中，我们将使用硬件浮点 ABI `armeabi-v7a-hard`，因此让我们相应地构建库。

### 注意

armeabi-v7a-hard 和 armeabi-v7a 之间的主要区别在于，硬件浮点 ABI 在 FPU 寄存器内部传递浮点函数参数。在浮点密集型应用程序中，这可以显著提高代码的性能，其中浮点值在不同的函数之间传递。

由于我们正在构建静态库，我们需要在`Android.mk`文件末尾添加以下行：

```java
include $(BUILD_STATIC_LIBRARY)
```

现在构建静态库只需调用一次`ndk-build`脚本。在对动态链接和 Windows 平台做一点简短的说明之后，我们继续编译实际的库。

# 在 Windows 平台上的动态链接

本章考虑的库可以作为 Windows 的动态链接库进行构建。我们不提供这样做的方法，因为每个项目已经包含了所有必要的说明，而且 Windows 开发不是本书的重点。唯一的例外是 libcurl 和 OpenSSL 库。我们建议您从官方库网站下载预构建的 DLL 文件。

在 FreeImage、FreeType 和 Theora 的示例代码中，我们使用函数指针，这些指针使用 WinAPI 的`GetProcAddress()`和`LoadLibrary()`函数进行初始化。在 Android 上使用相同的函数指针，但在这种情况下，它们指向静态库中的相应函数。

例如，函数`FreeImage_OpenMemory()`声明如下：

```java
typedef FIMEMORY* ( DLL_CALLCONV* PFNFreeImage_OpenMemory )
  ( void*, unsigned int );
PFNFreeImage_OpenMemory  FI_OpenMemory = nullptr;
```

在 Windows 上，我们使用`GetProcAddress()`调用来初始化指针：

```java
FI_OpenMemory = (PFNFreeImage_OpenMemory)
  GetProcAddress (hFreeImageDLL,"FreeImage_OpenMemory");
```

在 Android、OSX 和 Linux 上，这是一个重定向：

```java
FI_OpenMemory = &FreeImage_OpenMemory;
```

示例代码仅引用了`FI_OpenMemory()`，因此对于 Android 和 Windows 来说是一样的。

# Curl

libcurl 库[`curl.haxx.se/libcurl`](http://curl.haxx.se/libcurl)是一个免费且易于使用的客户端 URL 传输库。它是处理众多网络协议的本机应用程序的实际标准。Linux 和 OS X 用户可以在他们的系统上享受这个库，并且可以使用`-lcurl`开关与之链接。在 Windows 主机上为 Android 编译 libcurl 需要执行一些额外的步骤，我们在这里解释这些步骤。

libcurl 库的构建过程基于`autoconf`；在实际构建库之前，我们需要生成`curl_config.h`文件。从包含未打包的 libcurl 发行包的文件夹中运行配置脚本。交叉编译命令行标志应设置为：

```java
--host=arm-linux CC=arm-eabi-gcc

```

`CPPFLAGS`变量的`-I`参数应指向 NDK 文件夹中的`/system/core/include`子文件夹，在我们的例子中：

```java
CPPFLAGS="-I D:/NDK/system/core/include"

```

libcurl 库可以通过多种方式进行定制。我们使用以下这组参数（除了 HTTP 和 HTTPS 之外禁用所有协议）：

```java
>configure CC=arm-eabi-gcc --host=arm-linux --disable-tftp --disable-sspi --disable-ipv6 --disable-ldaps --disable-ldap --disable-telnet --disable-pop3 --disable-ftp --without-ssl --disable-imap --disable-smtp --disable-pop3 --disable-rtsp --disable-ares --without-ca-bundle --disable-warnings --disable-manual --without-nss --enable-shared --without-zlib --without-random --enable-threaded-resolver --with-ssl

```

`--with-ssl`参数允许使用 OpenSSL 库来提供安全的 HTTPS 传输。这个库将在本章进一步讨论。然而，为了处理 SSL 加密连接，我们需要告诉 libcurl 我们的系统证书位于何处。这可以在`curl_config.h`文件开头通过定义`CURL_CA_BUNDLE`来完成：

```java
#define CURL_CA_BUNDLE "/etc/ssl/certs/ca-certificates.crt"

```

配置脚本将生成一个有效的`curl_config.h`头文件。你可以在书的源代码包中找到它。编译 Android 静态库需要一个通常的`Android.mk`和`Application.mk`文件集，这也包含在`1_Curl`示例中。在下一章，我们将学习如何使用 libcurl 库通过 HTTPS 从互联网下载实际内容。然而，以下是一个简化使用示例来检索 HTTP 页面：

```java
CURL* Curl = curl_easy_init();
curl_easy_setopt( Curl, CURLOPT_URL, "http://www.google.com" );
curl_easy_setopt( Curl, CURLOPT_FOLLOWLOCATION, 1 );
curl_easy_setopt( Curl, CURLOPT_FAILONERROR, true );
curl_easy_setopt( Curl, CURLOPT_WRITEFUNCTION, &MemoryCallback );
curl_easy_setopt( Curl, CURLOPT_WRITEDATA, 0 );
curl_easy_perform( Curl );
curl_easy_cleanup( Curl );
```

在这里`MemoryCallback()`是一个处理接收到的数据的函数。它可以小到像下面的代码片段：

```java
size_t MemoryCallback( void* P, size_t Size, size_t Num, void* )
{
  if ( !P ) return 0;
  printf( "%s\n", P );
}
```

检索到的数据将在你的桌面应用程序上显示在屏幕上。同样的代码在 Android 中会像哑巴一样工作，不会产生任何可见的副作用，因为`printf()`函数在那里只是一个占位符。

# OpenSSL

OpenSSL 是一个开源库，实现了安全套接字层（SSL v2/v3）和传输层安全（TLS）协议，以及一个功能强大的通用加密库。可以在[`www.openssl.org`](https://www.openssl.org)找到它。

在这里，我们将构建 OpenSSL 版本 1.0.1j，其中包含对 Heartbleed 漏洞的修复([`heartbleed.com`](http://heartbleed.com))。

Heartbleed 漏洞是流行的 OpenSSL 加密软件库中一个严重的安全漏洞。这个弱点使得在正常情况下受 SSL/TLS 加密保护的信息可以被窃取，而这种加密被用于确保互联网的安全。

如果你尝试将应用程序静态链接到一个旧版本的 OpenSSL，并在 Google Play 上发布，你可能会看到以下安全警报：

![OpenSSL](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00216.jpeg)

到这本书出版时，即使是 OpenSSL 的 1.0.0j 版本也可能已经过时了。因此，下载最新的源代码并相应地更新 NDK Makefile 对你来说将是一个很好的练习。以下是如何进行的一个简要概述。

OpenSSL 被编译为两个相互协作的静态库：`libssl`和`libcrypto`。查看源代码包，并查看文件夹`2_OpenSSL/lib/crypto/jni`和`2_OpenSSL/ssl/jni`。这两个库都应该被链接到使用带有 SSL 功能的 libcurl 版本的应用程序中。

通常，为此准备的`Android.mk`文件可以像下面的列表这样开始：

```java
include $(CLEAR_VARS)
LOCAL_MODULE := libCurl
LOCAL_SRC_FILES := ../../../Libs.Android/libcurl.$(TARGET_ARCH_ABI).a
include $(PREBUILT_STATIC_LIBRARY)
include $(CLEAR_VARS)
LOCAL_MODULE := libCrypto
LOCAL_SRC_FILES := ../../../Libs.Android/libCrypto.$(TARGET_ARCH_ABI).a
include $(PREBUILT_STATIC_LIBRARY)
include $(CLEAR_VARS)
LOCAL_MODULE := libSSL
LOCAL_SRC_FILES := ../../../Libs.Android/libSSL.$(TARGET_ARCH_ABI).a
include $(PREBUILT_STATIC_LIBRARY)
```

在这个文件的最后，只需链接所有的库：

```java
LOCAL_STATIC_LIBRARIES += libCurl
LOCAL_STATIC_LIBRARIES += libSSL
LOCAL_STATIC_LIBRARIES += libCrypto
```

到此为止，你现在可以处理 SSL 连接了。

# FreeImage

FreeImage 是一个流行的位图操作库，Unity 游戏引擎是该库的用户之一（[`freeimage.sourceforge.net/users.html`](http://freeimage.sourceforge.net/users.html)）。该库是 `libpng`、`libjpeg`、`libtiff` 等之上的全功能封装，提供了快速图像加载例程，无需回退到 Java 代码。

FreeImage 包含一套完整的 Makefiles，适用于不同的平台。按照 *处理预编译静态库* 部分的说明，编译 Android 的库非常直接。`Application.mk` 文件与 Curl 的同名文件在一行上有所不同：

```java
APP_MODULES := FreeImage
```

在 `Android.mk` 文件中，我们将更改 C 编译标志：

```java
GLOBAL_CFLAGS   := -O3 -DHAVE_CONFIG_H=1 -DFREEIMAGE_LIB -DDISABLE_PERF_MEASUREMENT
```

在以下示例中，我们将实现两个简单的例程，以在各种文件格式中从内存块加载和保存图像。

我们从 `FreeImage_LoadFromMemory()` 例程开始，它接收 `Data` 数组和其 `Size` 作为输入参数，并将这个数组解码成一个包含位图像素的 `std::vector<char>`。尺寸信息，宽度和高度，存储在 `W` 和 `H` 参数中。颜色深度信息被放入 `BitsPerPixel` 参数中。可选的 `DoFlipV` 参数指示代码垂直翻转加载的图像，这在与不同图形 API 的图像存储约定（从上到下或从下到上）打交道时可能需要：

```java
bool FreeImage_LoadFromStream( void* Data,unsigned int Size,
  std::vector<ubyte>& OutData,int& W,
  int& H,int& BitsPerPixel,bool DoFlipV )
{
```

我们创建内部内存块，它可以被 FreeImage 例程读取。

```java
  FIMEMORY* Mem = FI_OpenMemory(( unsigned char* )Data,
    static_cast<unsigned int>( Size ) 
  );
```

在读取位图之前，我们将以以下方式检测其格式（例如，`.jpg`、`.bmp`、`.png` 等）：

```java
  FREE_IMAGE_FORMAT FIF = FI_GetFileTypeFromMemory( Mem, 0 );
```

然后，解码后的位图被读取到临时的 `FIBITMAP` 结构中：

```java
  FIBITMAP* Bitmap = FI_LoadFromMemory( FIF, Mem, 0 );
  FI_CloseMemory( Mem );
  FIBITMAP* ConvBitmap;
```

如果总位数超过 32 位，例如，每个颜色通道占用超过 8 位，我们很可能处理的是浮点数图像，这将需要一些额外的处理：

```java
  bool FloatFormat = FI_GetBPP( Bitmap ) > 32;
  if ( FloatFormat )
  {
```

本书并未广泛使用浮点数图像，但了解 FreeImage 支持 OpenEXR 格式下的高动态范围图像是有用的。

### 注意

OpenEXR 格式以支持每个通道 16 位的浮点数值而著称，并可用于游戏中存储不同 HDR 效果的纹理。

```java
    ConvBitmap = FI_ConvertToRGBF( Bitmap );
  }
  else
  {
```

使用透明度信息来转换图像。如果图像不是透明的，则忽略 alpha 通道：

```java
    ConvBitmap = FI_IsTransparent( Bitmap ) ? FI_ConvertTo32Bits( Bitmap ) : FI_ConvertTo24Bits( Bitmap );
  }
  FI_Unload( Bitmap );
  Bitmap = ConvBitmap;
```

如有必要，我们以下列方式对图像进行垂直翻转：

```java
  if ( DoFlipV ) FI_FlipVertical( Bitmap );
```

提取图像尺寸和颜色信息：

```java
  W = FI_GetWidth( Bitmap );
  H = FI_GetHeight( Bitmap );
  BitsPP = FI_GetBPP( Bitmap );
```

一旦我们知道尺寸，我们可以调整输出缓冲区的大小，如下所示：

```java
  OutData.resize( W * H * ( BitsPerPixel / 8 ) );
```

最后，我们可以将原始未对齐的位图数据提取到我们的 `OutData` 向量中。每行紧密排列的数据大小为 `W*BitsPP/8` 字节：

```java
  FI_ConvertToRawBits( &OutData[0],Bitmap, W * BitsPP / 8, BitsPP, 0, 1, 2, false );
```

临时位图对象被删除，函数优雅地返回：

```java
  FI_Unload( Bitmap );
  return true;
}
```

位图保存例程可以以类似的方式实现。首先，我们在 FreeImage 库中分配 FIBITMAP 结构来表示我们的图像：

```java
bool FreeImage_SaveToMemory( const std::string& Ext,ubyte* RawBGRImage,int Width,int Height,int BitsPP,std::vector<ubyte>& OutData )
{
  FIBITMAP* Bitmap = FI_Allocate(Width, Height, BitsPP, 0, 0, 0);
```

原始位图数据被复制到 FIBITMAP 结构中：

```java
  memcpy( FI_GetBits( Bitmap ), RawBGRImage, Width * Height * BitsPP / 8 );
```

FreeImage 使用倒置的垂直扫描线顺序，因此在保存之前我们应该垂直翻转图像：

```java
  FI_FlipVertical( Bitmap );
```

然后，我们将使用用户指定的文件扩展名来检测输出图像的格式：

```java
  int OutSubFormat;
  FREE_IMAGE_FORMAT OutFormat;
  FileExtToFreeImageFormats( Ext, OutSubFormat, OutFormat );
```

为了保存图像，我们将分配一个动态内存块：

```java
  FIMEMORY* Mem = FI_OpenMemory( nullptr, 0);
```

`FI_SaveToMemory()`调用根据选定的格式将我们的原始位图编码成压缩表示形式：

```java
  if ( !FI_SaveToMemory( OutFormat,Bitmap, Mem, OutSubFormat ) )
  {
    return false;
  }
```

编码后，我们将直接访问 FreeImage 内存块：

```java
  ubyte* Data = NULL;
  uint32_t Size = 0;
  FI_AcquireMemory( Mem, &Data, &Size );
```

然后，我们将字节复制到我们的`OutData`向量中：

```java
  OutData.resize( Size );
  memcpy( &OutData[0], Data, Size );
```

需要进行一些清理。我们删除内存块和 FIBITMAP 结构：

```java
  FI_CloseMemory( Mem );
  FI_Unload( Bitmap );
  return true;
}
```

辅助的`FileExtToFreeImageFormats()`函数将文件扩展名转换为内部的 FreeImage 格式说明符，并提供多个选项。代码很直观。我们将提供的文件扩展名与多个预定义值进行比较，并填充`FIF_FORMAT`和`SAVE_OPTIONS`结构：

```java
static void FileExtToFreeImageFormats( std::string Ext,int& OutSubFormat, FREE_IMAGE_FORMAT& OutFormat )
{
  OutSubFormat = TIFF_LZW;
  OutFormat = FIF_TIFF; std::for_each( Ext.begin(), Ext.end(),[]( char& in )
  { 
    in = ::toupper( in );
  } 
  );
  if ( Ext == ".PNG" )
  {
    OutFormat = FIF_PNG;
    OutSubFormat = PNG_DEFAULT;
  }
  else if ( Ext == ".BMP" )
  {
    OutFormat = FIF_BMP;
    OutSubFormat = BMP_DEFAULT;
  }
  else if ( Ext == ".JPG" )
  {
    OutFormat = FIF_JPEG;
    OutSubFormat = JPEG_QUALITYSUPERB | JPEG_BASELINE |JPEG_PROGRESSIVE | JPEG_OPTIMIZE;
  }
  else if ( Ext == ".EXR" )
  {
    OutFormat = FIF_EXR;
    OutSubFormat = EXR_FLOAT;
  }
}
```

这可以根据您的需要进行扩展和自定义。

# 加载和保存图像

为了使前面的代码可用，我们添加了两个更多例程，它们从磁盘文件中保存和加载图像。第一个，`FreeImage_LoadBitmapFromFile()`，加载位图：

```java
bool FreeImage_LoadBitmapFromFile( const std::string& FileName, std::vector<ubyte>& OutData, int& W, int& H, int& BitsPP )
{
  std::ifstream InFile( FileName.c_str(),
  std::ios::in | std::ifstream::binary );
  std::vector<char> Data(
    ( std::istreambuf_iterator<char>( InFile ) ), std::istreambuf_iterator<char>() );
  return FreeImage_LoadFromStream(
    ( ubyte* )&Data[0], ( int )data.size(),
    OutData, W, H, BitsPP, true );
}
```

我们使用一个简单的函数来提取文件扩展名，它作为文件类型标签：

```java
std::string ExtractExtension( const std::string& FileName )
{
  size_t pos = FileName.find_last_of( '.' );
  return ( pos == std::string::npos ) ?
    FileName : FileName.substr( pos );
}
```

`FreeImage_SaveBitmapToFile()`函数使用标准的`std::ofstream`流保存文件：

```java
bool FreeImage_SaveBitmapToFile( const std::string& FileName, ubyte* ImageData, int W, int H, int BitsPP )
{
  std::string Ext = ExtractExtension( FileName );
  std::vector<ubyte> OutData;
  if ( !FreeImage_SaveToMemory( Ext, ImageData, W, H, BitsPP, OutData ) )
  {
    return false;
  }
  std::ofstream OutFile( FileName.c_str(),
  std::ios::out | std::ofstream::binary );
  std::copy( OutData.begin(), OutData.end(), std::ostreambuf_iterator<char>( OutFile ) );
  return true;
}
```

这段代码足以涵盖图像加载库的所有基本使用情况。

# FreeType

FreeType 库是一个事实上的标准，用于使用 TrueType 字体渲染高质量文本。由于在几乎任何图形程序中输出文本都是不可避免的，我们给出一个如何使用从等宽 TrueType 文件生成的固定大小字体来渲染文本字符串的例子。

我们将固定大小字体存储在`16x16`网格中。此演示应用程序的源字体名为`Receptional Receipt`，从[`1001freefonts.com`](http://1001freefonts.com)下载。以下图像显示了结果`16x16`网格的四行：

![FreeType](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00217.jpeg)

单个字符占用一个矩形区域，我们将这个区域称为*槽*。字符矩形的坐标是使用字符的 ASCII 码计算的。网格中的每个槽占用`SlotW x SlotH`像素，字符本身居中，大小为`CharW x CharH`像素。为了演示，我们简单假设`SlotW`是`CharW`大小的两倍：

![FreeType](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00218.jpeg)

我们限制自己使用最简单的可能使用场景：8 位 ASCII 字符，固定大小的字符字形。为了渲染字符串，我们将遍历其字符并调用尚未编写的`RenderChar()`函数：

```java
void RenderStr( const std::string& Str, int x, int y )
{
  for ( auto c: Str )
  {
    RenderChar( c, x, y );
    x += CharW;
  }
}
```

字符渲染例程是一个简单的双循环，将字形像素复制到输出图像中：

```java
void RenderChar( char c, int x, int y )
{
  int u = ( c % 16 ) * SlotW;
  int v = ( c / 16 ) * SlotH;
  for ( int y1 = 0 ; y1 < CharH ; y1++ )
    for ( int x1 = 0 ; x1 <= CharW ; x1++ )
      PutPixel( g_OutBitmap, W, H,
        x + x1, y + y1,
        GetPixel( Font, FontW, FontH,
          x1 + u + CharW, y1 + v)
      );
}
```

`PutPixel()`和`GetPixel()`例程分别设置和获取位图中的像素。每个像素都是 24 位 RGB 格式：

```java
int GetPixel( const std::vector<unsigned char>& Bitmap, int W, int H, int x, int y )
{
  if ( y >= H || x >= W || y < 0 || x < 0 ) { return 0; }
```

在这里，假设扫描线的宽度等于图像宽度，RGB 三元组的颜色分量数量为 3：

```java
  int Ofs = ( y * W + x ) * 3;
```

使用位运算移位来构建结果的 RGB 值：

```java
  return (Bitmap[Ofs+0] << 16) +
    (Bitmap[Ofs+1] <<  8) +
    (Bitmap[Ofs+2]);
}
```

```java
void PutPixel( std::vector<unsigned char>& Bitmap,int W, int H, int x, int y, int Color )
{
  if ( y < 0 || x < 0 || y > H - 1 || x > W - 1 ) { return; }
  int Ofs = ( y * W + x ) * 3;
```

位运算移位和掩码完成了提取工作：

```java
  buffer[Ofs + 0] = ( Color ) & 0xFF;
  buffer[Ofs + 1] = ( Color >> 8 ) & 0xFF;
  buffer[Ofs + 2] = ( Color >> 16 ) & 0xFF;
}
```

另外还有一个辅助函数`Greyscale()`，它使用位运算移位为给定的强度计算 RGB 灰度颜色：

```java
inline int Greyscale( unsigned char c )
{
  return ( (255-c) << 16 ) + ( (255-c) << 8 ) + (255-c);
}
```

对于前面的代码，我们并不需要 FreeType。我们真正只需要该库来生成字体。我们将加载字体数据文件，为其前 256 个字符渲染字形，然后使用生成的字体位图来渲染文本字符串。代码的第一部分生成字体。我们将使用几个变量来存储字体的尺寸：

```java
/// Horizontal size of the character
const int CharW = 32;
const int CharH = 64;
/// Horizontal size of the character slot
const int SlotW = CharW * 2;
const int SlotH = CharH;
const int FontW = 16 * SlotW;
const int FontH = 16 * SlotH;
std::vector<unsigned char> g_FontBitmap;
```

我们将字体存储在一个标准向量中，可以传递给`TestFontRendering()`例程：

```java
void TestFontRendering( const std::vector<char>& Data )
{
  LoadFreeImage();
  LoadFreeType();
  FT_Library Library;
  FT_Init_FreeTypePTR( &Library );
  FT_Face Face;
  FT_New_Memory_FacePTR( Library,
    (const FT_Byte*)Data.data(),
    (int)Data.size(), 0, &face );
```

将字符大小固定在 100 dpi：

```java
  FT_Set_Char_SizePTR( Face, CharW * 64, 0, 100, 0 );
  g_FontBitmap.resize( FontW * FontH * 3 );
  std::fill( std::begin(g_FontBitmap), std::end(g_FontBitmap), 0xFF );
```

我们将在循环中逐个渲染 256 个 ASCII 字符：

```java
  for ( int n = 0; n < 256; n++ )
  {
```

将字形图像加载到槽中：

```java
    if ( FT_Load_CharPTR( Face, n , FT_LOAD_RENDER ) )
      continue;
    FT_GlyphSlot Slot = Face->glyph;
    FT_Bitmap Bitmap = Slot->bitmap;
```

计算每个字符的矩形左上角的坐标：

```java
    int x = (n % 16) * SlotW + CharW + Slot->bitmap_left;
    int y = (n / 16) * SlotH - Slot->bitmap_top + 3*CharH/4;
```

字符的笔形被复制到`g_FontBitmap`位图中：

```java
    for ( int i = 0 ; i < ( int )Bitmap.width; i++ )
    for ( int j = 0 ; j < ( int )Bitmap.rows; j++ )
    PutPixel( g_FontBitmap, FontW, FontH,i + x, j + y,
      Greyscale( Bitmap.buffer[j * Bitmap.width + i])
    );
  }
```

我们将生成的`Font`位图保存到文件中：

```java
  FreeImage_SaveBitmapToFile( "test_font.png",
    g_FontBitmap.data(), FontW, FontH, 24 );
```

在字体位图生成结束时，我们将清除与 FreeType 库相关的所有内容：

```java
  FT_Done_FacePTR    ( Face );
  FT_Done_FreeTypePTR( Library );
```

为了使用我们的等宽字体，我们将声明字符串，计算其在屏幕像素中的宽度，并分配输出位图：

```java
  std::string Str = "Test string";
  W = Str.length() * CharW;
  H = CharH;
  g_OutBitmap.resize( W * H * 3 );
  std::fill( std::begin(g_OutBitmap), std::end(g_OutBitmap), 0xFF );
```

`TestFontRendering()`例程的末尾只是调用了`RenderStr()`：

```java
  RenderStr( Str, 0, 0 );
```

然后将生成的图像保存到文件中：

```java
  FreeImage_SaveBitmapToFile( "test_str.png",
    g_OutBitmap.data(), W, H, 24 );
}
```

结果应该看起来像以下图像：

![FreeType](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00219.jpeg)

通常在位图字体渲染方面，你不想自己编写位图生成的代码。建议您使用第三方工具来完成这项工作。这样一款免费工具是 AngelCode，可以在[`www.angelcode.com/products/bmfont`](http://www.angelcode.com/products/bmfont)找到。它可以以最优的方式将字形打包到位图中，并生成处理生成的位图所需的数据。

# Theora（注：此处 Theora 为一种视频压缩格式的名称，不翻译）

Theora 是来自 Xiph.Org 基金会的一个免费且开源的视频压缩格式。与我们的所有多媒体技术一样，它可以用来在线和光盘上分发电影和视频，而无需像许多其他视频格式那样支付许可和版税费用，或受到任何其他供应商的锁定。它可以在[`www.theora.org`](http://www.theora.org)获取。

为了避免混淆，我们将介绍一些术语。我们所说的**比特流**是指一些字节的序列。逻辑比特流是对视频或音频数据的某种表示。**编解码器**，或编码器-解码器，是一组将逻辑比特流编码和解码成一组名为打包比特流的紧凑表示的函数。由于通常的多媒体数据包含多个逻辑比特流，紧凑表示必须被分割成小块，这些小块被称为包。每个**包**都有一个特定的尺寸、时间戳和与之相关的校验和，以保证包的完整性。比特流和包的方案在以下图像中显示：

![Theora](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00220.jpeg)

逻辑包和打包比特流的包相互混合，形成一个线性序列，保持每个独立比特流的包的顺序。这称为复用。Ogg 库读取`.ogg`文件并将其分割成打包比特流。每个比特流都可以使用 Theora、Vorbis 或其他解码器进行解码。

### 注意

在我们之前的书籍中，*Android NDK Game Development Cookbook*，*Packt Publishing* ([`www.packtpub.com/game-development/android-ndk-game-development-cookbook`](https://www.packtpub.com/game-development/android-ndk-game-development-cookbook))，我们通过示例教大家如何解码 Ogg Vorbis 音频流。

在本章中，我们只解决了从文件中提取媒体信息的最简单问题。即使这个简单的操作的代码可能看起来又长又复杂。然而，它可以用不到十个步骤来描述：

1.  初始化 OGG 流读取器。

1.  开始一个包构建循环：从源文件中读取一堆字节。

1.  检查是否有足够的数据来生成另一个逻辑包。

1.  如果形成了新的包，检查它是否是`BoS`（流开始）包。

1.  尝试使用`BoS`包初始化 Theora 或 Vorbis 解码器。

1.  如果我们没有足够的音频和视频流来解码，请转到步骤 2。

1.  如果我们没有足够的流信息，继续读取次要流包。

1.  初始化 Theora 解码器并提取视频帧信息。

### 注意

Ogg 流还有一个复杂性级别，因为包被分组形成逻辑页。在前面的伪代码中，我们指的是实际上是页面的包。尽管如此，方案保持不变：读取字节，直到有足够的数据让解码器生成另一个视频帧，或者在我们的情况下，读取视频信息。

我们使用标准的 C++ I/O 流并实现了三个简单的函数：`Stream_Read()`、`Stream_Seek()`和`Stream_Size()`。在后面的第四章，*组织虚拟文件系统*中，我们将使用自己的 I/O 抽象层重新实现这些方法。让我们打开文件流：

```java
std::ifstream Input( "test.ogv", std::ios::binary );
```

这是一个从输入流中读取指定字节数的函数：

```java
int Stream_Read( char* OutBuffer, int Size )
{
  Input.read( OutBuffer, Size );
  return Input.gcount();
}
```

使用以下代码寻找指定位置：

```java
int Stream_Seek( int Offset )
{
  Input.seekg( Offset );
  return (int)Input.tellg();
}
```

要确定文件大小，请使用以下代码：

```java
int Stream_Size()
{
  Input.seekg (0, input.end);
  int Length = Input.tellg();
  Input.seekg( 0, Input.beg );
  return Length;
}
```

首先，应该声明一些变量来存储解码过程的状态、同步对象、当前页面以及音频和视频流：

```java
ogg_sync_state   OggSyncState;
ogg_page         OggPage;
ogg_stream_state VorbisStreamState;
ogg_stream_state TheoraStreamState;
```

Theora 解码器状态：

```java
th_info          TheoraInfo;
th_comment       TheoraComment;
th_setup_info*   TheoraSetup;
th_dec_ctx*      TheoraDecoder;
```

Vorbis 解码器状态：

```java
vorbis_info      VorbisInfo;
vorbis_dsp_state VorbisDSPState;
vorbis_comment   VorbisComment;
vorbis_block     VorbisBlock;
```

函数`Theora_Load()`读取文件头并从中提取视频帧信息：

```java
bool Theora_Load()
{
  Stream_Seek( 0 );
```

当前的 Ogg 包将被读取到`TempOggPacket`结构中：

```java
  ogg_packet TempOggPacket;
```

需要对一些简单但必要的状态变量进行初始化：

```java
  memset( &VorbisStreamState, 0, sizeof( ogg_stream_state ) );
  memset( &TheoraStreamState, 0, sizeof( ogg_stream_state ) );
  memset( &OggSyncState,   0, sizeof( ogg_sync_state ) );
  memset( &OggPage,        0, sizeof( ogg_page ) );
  memset( &TheoraInfo,     0, sizeof( th_info ) );
  memset( &TheoraComment,  0, sizeof( th_comment ) );
  memset( &VorbisInfo,     0, sizeof( vorbis_info ) );
  memset( &VorbisDSPState, 0, sizeof( vorbis_dsp_state ) );
  memset( &VorbisBlock,    0, sizeof( vorbis_block ) );
  memset( &VorbisComment,  0, sizeof( vorbis_comment ) );
  OGG_sync_init   ( &OggSyncState );
  TH_comment_init ( &TheoraComment );
  TH_info_init    ( &TheoraInfo );
  VORBIS_info_init( &VorbisInfo );
  VORBIS_comment_init( &VorbisComment );
```

我们开始读取文件，并使用`Done`标志在文件结束或我们有足够的数据获取信息时终止：

```java
  bool Done = false;
  while ( !Done )
  {
    char* Buffer = OGG_sync_buffer( &OggSyncState, 4096 );
    int BytesRead = ( int )Stream_Read( Buffer, 4096 );
    OGG_sync_wrote( &OggSyncState, BytesRead );
    if ( BytesRead == 0 )
    {
      break;
    }
    while (OGG_sync_pageout( &OggSyncState, &OggPage ) > 0)
    {
```

当我们最终遇到一个完整的包时，我们将检查它是否是`BOS`标记，并将数据输出到其中一个解码器：

```java
      ogg_stream_state OggStateTest;
      if ( !OGG_page_bos( &OggPage ) )
      {
        if ( NumTheoraStreams > 0 )
        {
          OGG_stream_pagein( &TheoraStreamState, &OggPage );
        }
        if ( NumVorbisStreams > 0 )
          {
            OGG_stream_pagein( VorbisStreamState, &OggPage );
          }
          Done = true;
          break;
        }
        OGG_stream_init( &OggStateTest,
        OGG_page_serialno( &OggPage ) );
        OGG_stream_pagein( &OggStateTest, &OggPage );
        OGG_stream_packetout( &OggStateTest, &TempOggPacket );
```

我们将使用两个变量`NumTheoraStreams`和`NumVorbisStreams`分别计算视频和音频流的数量。在以下几行中，我们将 Ogg 包提供给两个解码器，并查看解码器是否对此有异议：

```java
        if ( NumTheoraStreams == 0 )
        {
          int Ret = TH_decode_headerin( &TheoraInfo, &TheoraComment, &TheoraSetup, &TempOggPacket );
          if ( Ret > 0 )
          {
```

下面是 Theora 头信息：

```java
            memcpy( &TheoraStreamState, &OggStateTest, sizeof( OggStateTest ) );
            NumTheoraStreams = 1;
            continue;
          }
        }
        if ( NumVorbisStreams == 0 )
        {
          int Ret = VORBIS_synthesis_headerin( &VorbisInfo, &VorbisComment, &TempOggPacket );
          if ( Ret >= 0 )
          {
```

这是 Vorbis 头：

```java
            memcpy( &VorbisStreamState, &OggStateTest, sizeof( OggStateTest ) );
            NumVorbisStreams = 1;
            continue;
          }
        }
```

因为我们只需要 Theora 流信息，所以忽略其他编解码器并丢弃头信息：

```java
        OGG_stream_clear( &OggStateTest );
      }
    }
```

之前的代码基本上只是计算了流的数量，现在我们应该已经完成了。如果流的数量仍然不足，我们将继续读取并检查次级流头：

```java
    while((( NumTheoraStreams > 0 ) && ( NumTheoraStreams < 3 )) || (( NumVorbisStreams > 0 ) && ( NumVorbisStreams < 3 )))
    {
      int Success = 0;
```

我们将读取所有可用的包，并检查它是否是一个新的 Theora 流的开始：

```java
      while (( NumTheoraStreams > 0 ) &&
        ( NumTheoraStreams < 3 ) &&
        ( Success = OGG_stream_packetout( &TheoraStreamState, &TempOggPacket ) ) )
      {
        if ( Success < 0 ) return false;
        if ( !TH_decode_headerin( &TheoraInfo, &TheoraComment, &TheoraSetup, &TempOggPacket ) ) return false;
        ++NumTheoraStreams;
      }
```

同样的方法，我们将寻找下一个 Vorbis 流的开始：

```java
      while ( NumVorbisStreams < 3 && ( Success = OGG_stream_packetout( &VorbisStreamState, &TempOggPacket ) ) )
      {
        if ( Success < 0 ) return false;
        if ( VORBIS_synthesis_headerin( &VorbisInfo, &VorbisComment, &TempOggPacket ) )
        return false;
        ++NumVorbisStreams;
      }
```

`while (!Done)`循环的最后一步是检查具有实际帧数据的包，或者如果下一个包不可用，从流中读取更多字节：

```java
      if ( OGG_sync_pageout( &OggSyncState, &OggPage ) > 0 )
      {
        if ( NumTheoraStreams > 0 )
        {
          OGG_stream_pagein( &TheoraStreamState, &OggPage );
        }
        if ( NumVorbisStreams > 0 )
        {
          OGG_stream_pagein( &VorbisStreamState, &OggPage );
        }
      }
      else
      {
        char* Buffer = OGG_sync_buffer( &OggSyncState, 4096 );
        int BytesRead = (int)Stream_Read( Buffer, 4096 );
        OGG_sync_wrote( &OggSyncState, BytesRead );
        if ( BytesRead == 0 ) return false;
      }
    }
```

到目前为止，我们已经找到了所有的流头，并准备好初始化 Theora 解码器。初始化后，我们获取帧宽和帧高：

```java
    TheoraDecoder = TH_decode_alloc( &TheoraInfo, TheoraSetup );
    Width  = TheoraInfo.frame_width;
    Height = TheoraInfo.frame_height;
    return true;
  }
```

最后，我们清除编解码器的内部结构以避免内存泄漏：

```java
  void Theora_Cleanup()
  {
    if ( TheoraDecoder )
    {
      TH_decode_free( TheoraDecoder );
      TH_setup_free( TheoraSetup );
      VORBIS_dsp_clear( &VorbisDSPState );
      VORBIS_block_clear( &VorbisBlock );
      OGG_stream_clear( &TheoraStreamState );
      TH_comment_clear( &TheoraComment );
      TH_info_clear( &TheoraInfo );
      OGG_stream_clear( &VorbisStreamState );
      VORBIS_comment_clear( &VorbisComment );
      VORBIS_info_clear( &VorbisInfo );
      OGG_sync_clear( &OggSyncState );
    }
  }
```

到此为止，我们已经读取了视频参数。在接下来的章节中，一旦我们有了基本的图形和音频渲染能力，我们将回到音频和视频的解码和播放。

代码更为复杂，但与我们的示例非常相似，它被广泛用于`LibTheoraPlayer`库源代码中，该代码可在[`libtheoraplayer.cateia.com`](http://libtheoraplayer.cateia.com)获取。

在本章的示例中，我们将使用大写的函数名称来区分动态库使用和静态链接。如果您想静态链接`ogg`、`vorbis`和`theora`库，可以通过将每个`OGG`函数前缀重命名为`ogg`来实现。就是这样，只需将大写字母替换为小写字母。

对于示例 Theora 视频内容，我们将参考官方网站，[`www.theora.org/content`](http://www.theora.org/content)，您可以在那里下载`.ogv`文件。

# OpenAL

OpenAL 是一个跨平台的音频 API。它旨在高效地渲染多通道三维定位音频，并在许多桌面平台的众多游戏引擎和应用程序中广泛使用。许多移动平台提供了不同的音频 API，例如，OpenSL ES 是一个强有力的竞争者。但是，当可移植性受到威胁时，我们应该选择一个能够在所有所需平台上运行的 API。OpenAL 在 Windows、Linux、OS X、Android、iOS、BlackBerry 10 以及许多其他平台上都有实现。在所有这些操作系统中，除了 Windows 和 Android，OpenAL 都是一等公民，所有库在系统中都可用。在 Windows 上，有一个来自 Creative 的实现。在 Android 上，我们需要自己构建库。我们将使用 Martins Mozeiko 的移植版本[`pielot.org/2010/12/14/openal-on-android/`](http://pielot.org/2010/12/14/openal-on-android/)。这个库可以通过对`Android.mk`和`Application.mk`文件进行少量调整来编译为 Android 版本。以下是`Android.mk`文件：

```java
TARGET_PLATFORM := android-19
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_MODULE := OpenAL
LOCAL_C_INCLUDES := $(LOCAL_PATH) $(LOCAL_PATH)/../include $(LOCAL_PATH)/../OpenAL32/Include
LOCAL_SRC_FILES  := ../OpenAL32/alAuxEffectSlot.c \
                    ../OpenAL32/alBuffer.c \
                    ../OpenAL32/alDatabuffer.c \
                    ../OpenAL32/alEffect.c \
                    ../OpenAL32/alError.c \
                    ../OpenAL32/alExtension.c \
                    ../OpenAL32/alFilter.c \
                    ../OpenAL32/alListener.c \
                    ../OpenAL32/alSource.c \
                    ../OpenAL32/alState.c \
                    ../OpenAL32/alThunk.c \
                    ../Alc/ALc.c \
                    ../Alc/alcConfig.c \
                    ../Alc/alcEcho.c \
                    ../Alc/alcModulator.c \
                    ../Alc/alcReverb.c \
                    ../Alc/alcRing.c \
                    ../Alc/alcThread.c \
                    ../Alc/ALu.c \
                    ../Alc/android.c \
                    ../Alc/bs2b.c \
                    ../Alc/null.c
```

`-D`定义是正确编译所需的：

```java
GLOBAL_CFLAGS := -O3 -DAL_BUILD_LIBRARY -DAL_ALEXT_PROTOTYPES -DHAVE_ANDROID=1
```

此`if`块是一种在您想要为 Android 构建 x86 版本的库时，区分 ARM 和 x86 编译器开关的方法：

```java
ifeq ($(TARGET_ARCH),x86)
  LOCAL_CFLAGS := $(GLOBAL_CFLAGS)
else
  LOCAL_CFLAGS := -mfpu=vfp -mfloat-abi=hard -mhard-float -fno-short-enums -D_NDK_MATH_NO_SOFTFP=1 $(GLOBAL_CFLAGS)
endif
include $(BUILD_STATIC_LIBRARY)
```

`Application.mk`文件是标准的，如下所示：

```java
APP_OPTIM := release
APP_PLATFORM := android-19
APP_STL := gnustl_static
APP_CPPFLAGS += -frtti
APP_CPPFLAGS += -fexceptions
APP_CPPFLAGS += -DANDROID
APP_MODULES := OpenAL
APP_ABI := armeabi-v7a-hard x86
NDK_TOOLCHAIN_VERSION := clang
```

为了方便您，我们在`6_OpenAL`示例中提供了所有的源代码和配置文件。此外，本书中使用的所有库都已为 Android 预编译，您可以在本书源代码包中的`Libs.Android`文件夹中找到它们。

# 将库链接到您的应用程序

在我们继续讨论更多主题之前，本章还有一件事需要讨论。实际上，我们学习了如何构建库，但还没学习如何将您的 Android 应用程序与它们链接。为此，我们需要修改您的应用程序的`Android.mk`文件。让我们看看`3_FreeImage_Example`示例及其`Application.mk`。它以声明预构建的静态库指向二进制文件的声明开始：

```java
include $(CLEAR_VARS)
LOCAL_MODULE := libFreeImage
LOCAL_SRC_FILES :=../../../Libs.Android/libFreeImage.$(TARGET_ARCH_ABI).a
include $(PREBUILT_STATIC_LIBRARY)
```

在这里，我们在路径中使用`$(TARGET_ARCH_ABI)`变量，以透明地处理`armeabi-v7a-hard`和`x86`版本的库。您可以轻松地添加更多架构。

一旦声明了库，让我们将应用程序与其链接。看看`Application.mk`的底部：

```java
LOCAL_STATIC_LIBRARIES += FreeImage
include $(BUILD_SHARED_LIBRARY)
```

`LOCAL_STATIC_LIBRARIES`变量包含了所有必要的库。为了方便起见，您可以省略前缀`lib`。

# 概括

在本章中，我们学习了如何在 Android 上处理预编译的静态库，同样的方法也适用于 OS X 和 Linux，以及如何在 Windows 上进行动态链接，同时不破坏代码的多平台功能。我们学习了如何构建 `libcurl` 和 `OpenSSL`，这样你就可以从 C++ 代码中访问 SSL 连接。FreeImage 和 FreeType 的几个示例展示了如何加载和保存光栅字体图像。使用 libtheora 的示例相当全面；然而，结果却很谦虚，我们只是从视频文件中读取元信息。OpenAL 将作为我们音频子系统的基础框架。


# 第三章：网络功能

在本章中，我们将学习如何从本地 C/C++代码处理与网络相关的功能。网络任务是异步的，就时间而言是不可预测的。即使底层连接是通过 TCP 协议建立的，也不能保证交付时间，应用程序在等待数据时完全有可能冻结。在 Android SDK 中，这一点被大量的类和设施所隐藏。而在 Android NDK 中，*相反地*，你必须自己克服这些困难，没有来自任何特定平台帮助者的协助。为了开发响应迅速且安全的应用程序，必须解决许多问题：我们需要完全控制下载过程，限制下载数据的大小，并优雅地处理发生的错误。不过，我们不会深入探讨 HTTP 和 SSL 协议实现的细节，我们将使用 libcurl 和 OpenSSL 库，专注于与应用程序开发相关的高级任务。然而，我们将会更详细地了解如何以可移植的方式实现基本异步机制。本章的前几个例子仅适用于桌面，其目的是展示如何实现跨平台同步原语。但是，在本章的最后，我们将看到如何将这些部分整合到一个移动应用程序中。

# 侵入式智能指针

在多线程环境中跟踪所有本地内存分配是一个出了名困难的流程，特别是在涉及在不同线程间传递对象所有权时。在 C++中，可以使用智能指针自动化内存管理。标准的`std::shared_ptr`类是个不错的起点。然而，我们想要关注更有趣且轻量级的技术。我们也不会使用 Boost 库，因为我们在编译时间上真的想要保持精简。

### 注意

最新版本的 Android NDK 已完全支持 C++ 11 标准库。如果你对`std::shared_ptr`或 Boost 库中的侵入式指针感到更熟悉，可以自由使用这些库中的智能指针。

如其名所示，侵入式智能指针中，引用计数被嵌入到对象中。实现这一点的最简单方式是通过继承以下基类：

```java
class iIntrusiveCounter
{
private:
  std::atomic<long> m_RefCounter;
public:
  iIntrusiveCounter( ) : m_RefCounter( 0 ) {}
  virtual ~iIntrusiveCounter( ) {}
  long GetReferenceCounter( ) const volatile 
  { return m_RefCounter; }
```

它使用标准原子变量来保存计数器的值。在 C++ 11 标准库被广泛采用之前，实现一个可移植的原子计数器需要使用特定平台的原子操作，比如 POSIX 或 Windows。如今，使用 C++ 11 可以编写适用于所有平台的干净代码；无论是 Android、Windows、Linux、OS X、iOS，甚至是黑莓 10，如果你愿意的话。以下是我们可以如何增加计数器的示例：

```java
  void IncRefCount( )
  {
    m_RefCounter.fetch_add( 1, std::memory_order_relaxed );
  }
```

使用 `++` 运算符替代 `fetch_add()` 是完全可行的。然而，编译器要求以这种方式递增原子整数变量需要是顺序一致的，这可能在生成的汇编代码中插入冗余的内存屏障。由于我们不对递增值进行任何决策，这里的内存屏障是不必要的，可以放宽内存排序，只要求变量的原子性。这正是 `fetch_add()` 使用 `std::memory_order_relaxed` 标志所做的，在一些非 x86 平台上可以生成更快的代码。递减要更复杂一些。确实，我们需要决定何时移除对象，只有在引用计数递减到零时才这样做。

这是正确执行操作的代码：

```java
  void DecRefCount()
  {
    if ( m_RefCounter.fetch_sub( 1, std::memory_order_release ) == 1 )
    {
```

`std::memory_order_release` 标志意味着对内存位置的运算需要所有先前的内存写入对所有执行相同位置获取操作的线程可见。进入 `if` 块后，我们将通过插入适当的内存屏障来执行获取操作：

```java
      std::atomic_thread_fence( std::memory_order_acquire );
```

在这一点之后，我们现在可以允许对象执行自杀操作：

```java
      delete this;
    }
  }
};
```

`delete this` 习惯用法在 [`isocpp.org/wiki/faq/freestore-mgmt#delete-this`](https://isocpp.org/wiki/faq/freestore-mgmt#delete-this) 有解释。

### 注意

`iIntrusiveCounter` 类是我们引用计数机制的核心。代码可能看起来非常简单；然而，这个实现的背后逻辑比看起来要复杂得多。有关所有详细细节，请参考 Herb Sutter 的 *C++ and Beyond 2012: Herb Sutter - atomic<> Weapons, 1 of 2* 演讲：

[`channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-1-of-2`](http://channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-1-of-2)

[`channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-2-of-2`](http://channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-2-of-2)

现在，我们可以实现一个轻量级的 RAII 泛型智能指针类，它使用我们刚刚编写的计数器基类：

```java
template <class T> class clPtr
{
public:
  /// default constructor
  clPtr(): FObject( 0 ) {}
  /// copy constructor
  clPtr( const clPtr& Ptr ): FObject( Ptr.FObject )
  {
    LPtr::IncRef( FObject );
  }
```

在这里，复制构造函数没有直接调用 `FObject->IncRefCount()` 方法。而是调用一个辅助函数 `LPtr::IncRef()`，它接受 `void*` 并将对象作为参数传递给该函数。这样做是为了允许我们的侵入式智能指针与那些已声明但尚未定义的类一起使用：

```java
  /// move constructor
  clPtr( clPtr&& Ptr :): FObject( Ptr.FObject )
  {
    Ptr.FObject = nullptr;
  }
  template <typename U> clPtr( const clPtr<U>& Ptr )): FObject( Ptr.GetInternalPtr() )
  {
    LPtr::IncRef( FObject );
  }
```

从 `T*` 的隐式构造函数很有用：

```java
  clPtr( T* const Object ): FObject( Object )
  {
    LPtr::IncRef( FObject );
  }
```

与构造函数类似，析构函数使用辅助函数来递减引用计数：

```java
  ~clPtr()
  {
    LPtr::DecRef( FObject );
  }
```

若干个命名辅助函数可用于检查智能指针的状态：

```java
  /// check consistency
  inline bool IsValid() const
  {
    return FObject != nullptr;
  }
  inline bool IsNull() const
  {
    return FObject == nullptr;
  }
```

与其他方法相比，赋值运算相当慢：

```java
  /// assignment of clPtr
  clPtr& operator = ( const clPtr& Ptr )
  {
    T* Temp = FObject;
    FObject = Ptr.FObject;
    LPtr::IncRef( Ptr.FObject );
    LPtr::DecRef( Temp );
    return *this;
  }
```

但是不包括 `move` 赋值运算符：

```java
  clPtr& operator = ( clPtr&& Ptr )
  {
    FObject = Ptr.FObject;
    Ptr.FObject = nullptr;
    return *this;
  }
```

`->` 运算符对于每个智能指针类都是必不可少的：

```java
  inline T* operator -> () const
  {
    return FObject;
  }
```

这是一个有点棘手的问题：一个自动类型转换运算符，用于将智能指针转换为私有类 `clProtector` 的实例：

```java
  inline operator clProtector* () const
  {
    if ( !FObject ) return nullptr;
    static clProtector Protector;
    return &Protector;
  }
```

这种类型转换用于允许像`if ( clPtr )`这样的安全空指针检查。这是安全的，因为您不能对生成的指针执行任何操作。内部的私有类`clProtector`没有实现`delete()`运算符，因此使用它将产生编译错误：

```java
private:
  class clProtector
  {
private:
    void operator delete( void* ) = delete;
  };
```

### 注意事项

本书的源代码包没有使用 C++ 11 的`= delete`表示法来删除函数，只是让它未实现。这是为了与旧编译器保持兼容性。如果你针对的是最新版本的 GCC/Clang 和 Visual Studio，使用`= delete`将是非常好的。

让我们回到我们的`clPtr`类。不幸的是，标准`dynamic_cast<>`运算符不能以原始方式使用，因此我们需要进行替换：

```java
public:
  /// cast
  template <typename U> inline clPtr<U> DynamicCast() const
  {
    return clPtr<U>( dynamic_cast<U*>( FObject ) );
  }
```

这是我们的智能指针在语法上与原始指针唯一不同的地方。此外，我们需要一组比较运算符，以使我们的类在不同的容器中更有用：

```java
  template <typename U> inline bool operator == ( const clPtr<U>&Ptr1 ) const
  {
    return FObject == Ptr1.GetInternalPtr();
  }
  template <typename U> inline bool operator == ( const U* Ptr1 )const
  {
    return FObject == Ptr1;
  }
  template <typename U> inline bool operator != ( const clPtr<U>&Ptr1 ) const
  {
    return FObject != Ptr1.GetInternalPtr();
  }
```

这是一个函数，用于简化智能指针与接受原始指针的 API 之间的连接。到基础`T*`类型的转换应该是显式的：

```java
  inline T* GetInternalPtr() const
  {
    return FObject;
  }
```

当处理低级指针问题时，一些辅助函数可能很有用。删除对象，不要释放它：

```java
  inline void Drop()
  {
    FObject = nullptr;
  }
```

清除对象，减少引用计数，类似于将其赋值为`nullptr`：

```java
  inline void Clear()
  {
    *this = clPtr<T>();
  }
```

最后但同样重要的是，指针本身：

```java
private:
  T* FObject;
};
```

从此，我们可移植的侵入式智能指针是自包含的，可以用于实际应用中。还有一件事要做，那就是一种语法糖。C++ 11 典型的使用`auto`关键字，这样可以在表达式中只写一次类型名称。但是，下面的实例化将不起作用，因为当我们希望`p`的类型是`clPtr< clSomeObject>`时，推导出的`p`的类型将是`clSomeObject*`：

```java
auto p = new clSomeObject( a, b, c );
```

使用标准共享指针时，通过使用`std::make_shared()`模板辅助函数来解决此问题，该函数返回正确的类型（并在幕后进行一些有用的计数器存储优化）：

```java
auto p = std::make_shared<clSomeObject>( a, b, c );
```

在这里，`p`的推导类型是`std::shared_ptr<clSomeObject>`，最终符合我们的预期。我们可以使用 C++ 11 提供的完美转发机制和`std::forward()`函数创建一个类似的辅助函数：

```java
template< class T, class... Args > clPtr<T> make_intrusive( Args&&... args )
{
  return clPtr<T>( new T( std::forward<Args>( args )... ) );
}
```

这种用法是 C++11 风格的，很自然：

```java
auto p = make_intrusive<clSomeObject>( a, b, c );
```

智能指针的完整源代码可以在`1_IntrusivePtr`示例中找到。现在，我们可以进一步使用这个类作为我们多线程内存管理的基石。

# 可移植的多线程原语

在撰写本文时，C++11 标准中期待已久的`std::thread`在 MinGW 工具链中尚不可用，并且它不具备调整线程优先级的能力，这对于网络来说很重要。因此，我们实现了一个简单的类`iThread`，带有虚拟方法`Run()`，以允许在我们的代码中进行可移植的多线程：

```java
class iThread
{
```

内部`LPriority`枚举定义了线程优先级类：

```java
public:
  enum LPriority
  {
    Priority_Idle         = 0,
    Priority_Lowest       = 1,
    Priority_Low          = 2,
    Priority_Normal       = 3,
    Priority_High         = 4,
    Priority_Highest      = 5,
    Priority_TimeCritical = 6
  };
```

构造函数和析构函数的代码很简单：

```java
  iThread(): FThreadHandle( 0 ), FPendingExit( false )
  {}
  virtual ~iThread()
  {}
```

`Start()`方法创建一个特定于操作系统的线程句柄并开始执行。在这本书的所有示例中，我们不需要推迟线程执行；我们只需使用默认参数调用`_beginthreadex()`和`pthread_create()`系统例程。`EntryPoint()`方法稍后定义：

```java
  void Start()
  {
    void* ThreadParam = reinterpret_cast<void*>( this );
    #ifdef _WIN32
      unsigned int ThreadID = 0;
      FThreadHandle = ( uintptr_t )_beginthreadex( nullptr, 0, &EntryPoint, ThreadParam, 0, &ThreadID );
    #else
      pthread_create( &FThreadHandle, nullptr, EntryPoint, ThreadParam );
      pthread_detach( FThreadHandle );
    #endif
  }
```

系统相关的线程句柄和布尔原子变量（指示此线程是否应停止执行）在类的私有部分中声明：

```java
private:
  thread_handle_t FThreadHandle;
  std::atomic<bool> FpendingExit;
```

本地线程 API 仅支持 C 函数，因此我们必须声明一个静态包装方法`EntryPoint()`，该方法将`void*`参数转换为`iThread`并调用类的`Run()`方法。线程函数的调用约定和结果类型在 POSIX 和 Windows 上有所不同：

```java
  #ifdef _WIN32
    #define THREAD_CALL unsigned int __stdcall
  #else
    #define THREAD_CALL void*
  #endif
    static THREAD_CALL EntryPoint( void* Ptr );
```

受保护的部分定义了`Run()`和`NotifyExit()`虚拟方法，这些方法在子类中被重写。`GetHandle()`方法允许子类访问特定平台的线程句柄：

```java
protected:
  virtual void Run() = 0;
  virtual void NotifyExit() {};
  thread_handle_t GetHandle() { return FThreadHandle; }
```

要停止线程，我们将设置`FPendingExit`标志并调用`NotifyExit()`方法通知线程所有者。可选的`Wait`参数强制该方法等待线程的实际终止：

```java
  void Exit( bool Wait )
  {
    FPendingExit = true;
    NotifyExit();
    if ( !Wait ) { return; }
```

我们必须确保`Exit()`不要从同一线程的`Run()`方法中调用，以避免死锁，因此我们将调用`GetCurrentThread()`并将结果与我们的句柄进行比较：

```java
    if ( GetCurrentThread() != FThreadHandle )
    {
```

对于 Windows，我们将通过调用`WaitForSingleObject()`来模拟`join`操作，然后通过`CloseHandle()`终止线程：

```java
      #ifdef _WIN32
        WaitForSingleObject(( HANDLE )FThreadHandle, INFINITE );
        CloseHandle( ( HANDLE )FThreadHandle );
      #else
        pthread_join( FThreadHandle, nullptr );
      #endif
    }
  }
```

在 Android 上，`GetCurrentThread()`方法的实现与典型的 POSIX 版本略有不同。因此，这个方法包含了一个三重的`#ifdef`子句：

```java
  native_thread_handle_t iThread::GetCurrentThread()
  {
    #if defined( _WIN32)
      return GetCurrentThreadId();
    #elif defined( ANDROID )
      return gettid();
    #else
      return pthread_self();
    #endif
  }
```

`EntryPoint()`方法是将我们面向对象的`iThread`包装类与特定平台的 C 风格线程 API 联系在一起的粘合剂：

```java
  THREAD_CALL iThread::EntryPoint( void* Ptr )
  {
    iThread* Thread = reinterpret_cast<iThread*>( Ptr );
    if ( Thread )
    {
      Thread->Run();
    }
    #ifdef _WIN32
      _endthreadex( 0 );
      return 0;
    #else
      pthread_exit( 0 );
    return nullptr;
    #endif
  }
```

最后一个细节是`SetPriority()`方法，该方法用于控制线程的 CPU 时间分配。在 Windows 中，该方法的主要部分是将我们的`LPriority`枚举转换为`windows.h`头文件中定义的数值：

```java
  void iThread::SetPriority( LPriority Priority )
  {
    #ifdef _WIN32
      int P = THREAD_PRIORITY_IDLE;
      switch(Priority)
      {
        case Priority_Lowest:
          P = THREAD_PRIORITY_LOWEST; break;
        case Priority_Low:
          P = THREAD_PRIORITY_BELOW_NORMAL; break;
        case Priority_Normal:
          P = THREAD_PRIORITY_NORMAL; break;
        case Priority_High:
          P = THREAD_PRIORITY_ABOVE_NORMAL; break;
        case Priority_Highest:
          P = THREAD_PRIORITY_HIGHEST; break;
        case Priority_TimeCritical:
          P = THREAD_PRIORITY_TIME_CRITICAL; break;
      }
      SetThreadPriority( ( HANDLE )FThreadHandle, P );
    #else
```

对于 POSIX，我们将我们的优先级值重新缩放到操作系统中可用的最小和最大优先级之间的整数：

```java
      int SchedPolicy = SCHED_OTHER;
      int MaxP = sched_get_priority_max( SchedPolicy );
      int MinP = sched_get_priority_min( SchedPolicy );
      sched_param SchedParam;
      SchedParam.sched_priority = MinP + (MaxP - MinP) / (Priority_TimeCritical - Priority + 1);
      pthread_setschedparam( FThreadHandle, SchedPolicy, &SchedParam );
    #endif
  }
```

现在，我们可以使用`iThread`类来构建更有用的高级线程原语。为了实现类似`std::mutex`的跨平台轻量级对象，我们将使用 Marcus Geelnard 的 TinyThread 库，该库可以在[`tinythreadpp.bitsnbites.eu`](http://tinythreadpp.bitsnbites.eu)下载。但是，如果你不需要与旧编译器兼容，也可以自由使用标准互斥锁。

让我们继续处理任务队列。

# 任务队列

为了处理逻辑工作单元，我们将声明具有`Run()`方法的`iTask`类，该方法可以执行耗时的操作。类的声明在视觉上与`iThread`有些相似。然而，其实例实现了一些相对简短的操作，并且可以在不同的线程中执行：

```java
  class iTask: public iIntrusiveCounter
  {
  public:
    iTask()
    : FIsPendingExit( false )
    , FTaskID( 0 )
    , FPriority( 0 )
    {};
```

纯虚方法`Run()`应该在子类中被重写以执行实际工作：

```java
    virtual void Run() = 0;
```

下面的方法可选择性地取消任务，与`iThread`类中的方法类似。它们的作用是通知宿主线程应取消此任务：

```java
    virtual void Exit()
    {
      FIsPendingExit = true;
    }
    virtual bool IsPendingExit() const volatile
    {
      return FIsPendingExit;
    }
```

`GetTaskID()`和`SetTaskID()`方法访问任务的内部唯一标识符，用于取消执行：

```java
    virtual void SetTaskID( size_t ID )
    { FTaskID = ID; };
    virtual size_t GetTaskID() const
    { return FTaskID; };
```

`GetPriority()`和`SetPriority()`方法由任务调度程序使用，以确定执行任务的顺序：

```java
    virtual void SetPriority( int P )
    {
      FPriority = P;
    };
    virtual int GetPriority() const
    {
      return FPriority;
    };
```

类的私有部分包含一个原子退出标志，任务 ID 值和任务优先级：

```java
  private:
    std::atomic<bool> FIsPendingExit;
    size_t FTaskID;
    int FPriority;
  };
```

任务的管理由`clWorkerThread`类完成。基本上，它是一组`iTask`实例的集合，通过`AddTask()`方法进行输入。类的私有部分包含`iTask`的`std::list`和几个同步基元：

```java
  class clWorkerThread: public iThread
  {
  private:
    std::list< clPtr<iTask> >   FPendingTasks;
    clPtr<iTask>                FCurrentTask;
    mutable tthread::mutex      FTasksMutex;
    tthread::condition_variable FCondition;
```

`FCurrentTask`字段在内部用于跟踪正在进行的任务。`FTasksMutex`字段是一个互斥锁，用于确保对`FPendingTasks`的线程安全访问。`FCondition`条件变量用于通知列表中任务的可可用性。

`AddTask()`方法将新任务插入列表中，并通知`Run`方法任务已可用：

```java
    virtual void   AddTask( const clPtr<iTask>& Task )
    {
      tthread::lock_guard<tthread::mutex> Lock( FTasksMutex );
      FPendingTasks.push_back( Task );
      FCondition.notify_all();
    }
```

为了检查是否有未完成的任务，我们将定义`GetQueueSize()`方法。该方法使用`std::list.size()`，并在当前有活动任务正在运行时增加返回的值：

```java
    virtual size_t GetQueueSize() const
    {
      tthread::lock_guard<tthread::mutex> Lock( FTasksMutex );
      return FPendingTasks.size() + ( FCurrentTask ? 1 : 0 );
    }
```

有一个`CancelTask()`方法来取消单个任务，以及一个`CancelAll()`方法来一次性取消所有任务：

```java
    virtual bool   CancelTask( size_t ID )
    {
      if ( !ID ) { return false; }
      tthread::lock_guard<tthread::mutex> Lock( FTasksMutex );
```

首先，我们检查是否有正在运行的任务，并且其 ID 与我们想要取消的 ID 匹配：

```java
      if ( FCurrentTask && FCurrentTask->GetTaskID() == ID )
        FCurrentTask->Exit();
```

然后，我们将遍历任务列表，并请求给定 ID 的任务退出，从待处理任务列表中移除它们。这可以通过使用简单的 lambda 表达式来完成：

```java
      FPendingTasks.remove_if(
        ID
        {
          if ( T->GetTaskID() == ID )
          {
            T->Exit();
            return true;
          }
          return false;
        }
      );
```

最后，我们通知所有人列表已更改：

```java
      FCondition.notify_all();
      return true;
    }
```

`CancelAll()`方法要简单得多。迭代任务列表，请求每个项目终止；这之后，清空容器并发送通知：

```java
    virtual void CancelAll()
    {
      tthread::lock_guard<tthread::mutex> Lock( FTasksMutex );
      if ( FcurrentTask )
      {
        FcurrentTask->Exit();
      }
      for ( auto& Task: FpendingTasks )
      {
        Task->Exit();
      }
      FpendingTasks.clear();
      Fcondition.notify_all();
    }
```

主要工作在`Run()`方法中完成，该方法等待下一个任务到达并执行它：

```java
    virtual void Run()
    {
```

外层循环使用`iThread::IsPendingExit()`例程检查我们是否需要停止这个工作线程：

```java
    while ( !IsPendingExit() )
    {
```

`ExtractTask()`方法从列表中提取下一个任务。它会等待条件变量直到任务实际可用：

```java
      FCurrentTask = ExtractTask();
```

如果任务有效且未请求取消，我们可以开始执行任务：

```java
      if ( FCurrentTask &&
        !FCurrentTask->IsPendingExit())
      FCurrentTask->Run();
```

任务完成工作后，我们将清除状态以确保正确的`GetQueueSize()`操作：

```java
      FCurrentTask = nullptr;
    }
  }
```

`ExtractTask()`方法在`FPendingTasks`列表中实现了一个线程安全的线性搜索，以选择具有最高优先级的`iTask`实例：

```java
  clPtr<iTask> ExtractTask()
  {
    tthread::lock_guard<tthread::mutex> Lock( FTasksMutex );
```

为了避免进行忙等（spinlock）并耗尽 CPU 周期，将检查条件变量：

```java
    while ( FPendingTasks.empty() && !IsPendingExit() )
      FCondition.wait( FTasksMutex );
```

如果列表为空，将返回空智能指针：

```java
    if ( FPendingTasks.empty() )
      return clPtr<iTask>();
```

`Best`变量存储了要执行的选择任务：

```java
    auto Best = FPendingTasks.begin();
```

遍历`FPendingTask`列表，并将优先级值与`Best`变量中的值进行比较，我们将选择任务：

```java
    for ( auto& Task : FPendingTasks )
    {
      if ( Task->GetPriority() >
        ( *Best )->GetPriority() ) *Best = Task;
    }
```

最后，我们将从容器中删除选定的任务并返回结果。需要临时变量以确保我们的智能指针不会将引用计数减为零：

```java
    clPtr<iTask> Result = *Best;
    FPendingTasks.erase( Best );
    Return Result;
  }
```

现在，我们已经有了处理异步任务的类。在我们可以继续实际的异步网络连接——异步回调之前，还有一件至关重要的事情要做。

# 消息泵和异步回调

在上一节中，我们定义了`clWorkerThread`和`iTask`类，它们允许我们在 C++代码中在 UI 线程之外执行耗时操作。为了组织一个响应式界面，我们最后需要的能力是在不同线程之间传递事件。为此，我们需要一个可调用的接口，它可以封装传递给方法的参数，以及一个线程安全的机制来传递这样的胶囊。

一个很好的候选胶囊是`std::packaged_task`，但它在最新的 MinGW 工具链中不受支持。因此，我们将定义自己的轻量级引用计数抽象类`iAsyncCapsule`，它实现了一个单一的方法，`Invoke()`：

```java
  class iAsyncCapsule: public iIntrusiveCounter
  {
  public:
    virtual void Invoke() = 0;
  };
```

我们将包裹在`clPtr`中的`iAsyncCapsule`实例的优先级集合称为*异步队列*。`clAsyncQueue`类实现了`DemultiplexEvents()`方法，该方法将在处理传入事件的线程中调用。

### 注意

这被称为反应器模式。其文档可以在[`en.wikipedia.org/wiki/Reactor_pattern`](http://en.wikipedia.org/wiki/Reactor_pattern)找到。

解复用包括调用所有通过`EnqueueCapsule()`方法从其他线程添加的累积`iAsyncCapsule`。这两种方法应该是线程安全的，实际上也是。然而，`DemultiplexEvents()`在意义上不是可重入的，也就是说，两个线程不应当对同一对象调用`DemultiplexEvents()`。这一限制是性能优化的一部分，我们将在后面看到。我们使用两个`iAsyncCapsule`容器，并在每次调用`DemultiplexEvents()`时切换它们。这使得`EnqueueCapsule()`执行更快，因为我们不需要复制队列内容以确保线程安全。否则，由于在互斥锁锁定时我们不应该调用`Invoke()`，所以进行复制是必要的。

类的私有部分包含当前使用的队列索引`FCurrentQueue`，两个`iAsyncCapsule`容器，指向当前队列的指针以及用于防止同时访问`FAsyncQueues`数组的互斥锁：

```java
  class clAsyncQueue
  {
  private:
    using CallQueue = std::vector< clPtr<iAsyncCapsule> >;
    size_t FCurrentQueue;
    std::array<CallQueue, 2> FAsyncQueues;
    /// switched for shared non-locked access
    CallQueue* FAsyncQueue;
    tthread::mutex FDemultiplexerMutex;
```

构造函数初始化当前队列指针和索引：

```java
  public:
    clAsyncQueue()
    : FDemultiplexerMutex()
    , FCurrentQueue( 0 )
    , FAsyncQueues()
    , FAsyncQueue( &FAsyncQueues[0] )
    {}
```

`EnqueueCapsule()`方法与`WorkerThread::AddTask()`类似。首先，我们创建一个作用域内的`lock_guard`对象，然后调用`push_back()`以将`iAsyncCapsule`对象入队：

```java
    virtual void EnqueueCapsule(
      const clPtr<iAsyncCapsule>& Capsule )
    {
      tthread::lock_guard<tthread::mutex>
        Lock( FDemultiplexerMutex );
      FAsyncQueue->push_back( Capsule );
    }
```

`DemultiplexEvents()`方法保存对当前队列的引用：

```java
    virtual void DemultiplexEvents()
    {
```

`DemultiplexEvents()`被设计为只在单个线程上运行。此时不需要加锁：

```java
      CallQueue& LocalQueue = FAsyncQueues[ FCurrentQueue ];
```

然后，交换当前队列指针。这是一个原子操作，因此我们使用互斥锁来防止访问`FAsyncQueue`指针和索引：

```java
      {
        tthread::lock_guard<tthread::mutex>
          Lock( FDemultiplexerMutex );
        FCurrentQueue = ( FCurrentQueue + 1 ) % 2;
        FAsyncQueue = &FAsyncQueues[ FCurrentQueue ];
      }
```

最后，当前队列中的每个`iAsyncCapsule`都会被调用，并且`LocalQueue`会被清空：

```java
      for ( auto& i: LocalQueue ) i->Invoke();
      LocalQueue.clear();
    }
  };
```

典型的使用场景是在一个线程向另一个线程发布回调。这里考虑的一个小示例使用了`clResponseThread`类，该类有一个无尽循环作为主线程：

```java
  class clResponseThread: public iThread, public clAsyncQueue
  {
  public:
    virtual void Run()
    {
      for (;;) DemultiplexEvents();
    }
  };
```

示例`clRequestThread`类每秒产生两次事件：

```java
  class clRequestThread: public iThread
  {
  public:
    explicit clRequestThread( clAsyncQueue* Target )
    : FTarget(Target)
    {}
    virtual void Run()
    {
      int id = 0;
      for (;;)
      {
        FTarget->EnqueueCapsule( make_intrusive<clTestCall>( id++ ) );
        OS_Sleep( 500 );
      }
    }
  private:
    clAsyncQueue* FTarget;
  };
```

测试调用仅打印带有`clTestCall` ID 的消息：

```java
  class clTestCall: public iAsyncCapsule
  {
  private:
    int id;
  public:
    explicit clTestCall( int i ): id(i) {}
    virtual void Invoke()
    {
      std::cout "Test " << id << std::endl;
    }
  };
```

在`main()`函数中，我们创建两个线程并开始一个无限循环：

```java
  clResponseThread Responder;
  clRequestThread Requester( &Responder );
  Responder.Start();
  Requester.Start();
  for (;;) {}
```

在下一节中，我们将使用类似的方法通知主线程下载结果。`clResponseThread`类成为 UI 线程，而`clRequestThread`是一个`WorkerThread`方法，其中每个执行的下载任务一旦下载完成就会触发一个事件。

# 使用 libcurl 进行异步网络操作

在第二章 *本地库* 中展示了 libcurl 的简单使用。现在，我们使用之前提到的多线程原语来扩展代码，以允许异步下载。

这里引入的`clDownloadTask`类跟踪下载过程，并在过程完成时调用回调函数：

```java
  class clDownloadTask: public iTask
  {
  public:
```

构造函数接受要下载资源的 URL、唯一的任务标识符、回调函数以及指向 downer 实例的指针：

```java
    clDownloadTask( const std::string& URL,
      size_t TaskID, 
      const clPtr<clDownloadCompleteCallback>& CB,
      clDownloader* Downloader );
```

我们将关注`Run()`、`Progress()`和`InvokeCallback()`方法，因为它们构成了此类的主要逻辑：

```java
    virtual void Run() override;
  private:
    void Progress( double TotalToDownload,
      double NowDownloaded,
      double TotalToUpload,
      double NowUploaded );
    void InvokeCallback();
  };
```

`Run()`方法在下载线程上运行；它初始化并使用 libcurl 实际执行资源的下载：

```java
  void clDownloadTask::Run()
  {
```

此硬引用是必需的，以防止任务在外部被销毁（如果任务被取消）：

```java
    clPtr<clDownloadTask> Guard( this );
    CURL* Curl = curl_easy_init_P();
```

libcurl 的初始化代码在这里。所有可能的参数可以在官方文档中找到，地址为[`curl.haxx.se/libcurl/c/curl_easy_setopt.html`](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html)：

```java
    curl_easy_setopt_P( Curl, CURLOPT_URL, FURL.c_str() );
    curl_easy_setopt_P( Curl, CURLOPT_FOLLOWLOCATION, 1 );
    curl_easy_setopt_P( Curl, CURLOPT_NOPROGRESS, false );
    curl_easy_setopt_P( Curl, CURLOPT_FAILONERROR, true );
    curl_easy_setopt_P( Curl, CURLOPT_MAXCONNECTS, 10 );
    curl_easy_setopt_P( Curl, CURLOPT_MAXFILESIZE, DownloadSizeLimit );
    curl_easy_setopt_P( Curl, CURLOPT_WRITEFUNCTION,
      &MemoryCallback );
    curl_easy_setopt_P( Curl, CURLOPT_WRITEDATA, this );
    curl_easy_setopt_P( Curl, CURLOPT_PROGRESSFUNCTION, &ProgressCallback );
    curl_easy_setopt_P( Curl, CURLOPT_PROGRESSDATA, this );
```

以下行设置尝试连接时要等待的秒数。使用零值表示无限期等待：

```java
    curl_easy_setopt_P( Curl, CURLOPT_CONNECTTIMEOUT, 30 );
```

在这里，我们设置允许 libcurl 函数执行的最大秒数：

```java
    curl_easy_setopt_P( Curl, CURLOPT_TIMEOUT, 600 );
```

禁用 OpenSSL 对证书的验证，这将允许访问具有自签名证书的站点。然而，在生产代码中，你可能想要删除此模式，以减少中间人攻击的可能性：

```java
    curl_easy_setopt_P( Curl, CURLOPT_SSL_VERIFYPEER, 0 );
    curl_easy_setopt_P( Curl, CURLOPT_SSL_VERIFYHOST, 0 );
    curl_easy_setopt_P( Curl, CURLOPT_HTTPGET, 1 );
```

### 注意

在协商 SSL 连接时，服务器会发送一个证书来标识其身份。Curl 验证证书是否真实——也就是说，你可以信任服务器就是证书所说的那个实体。这种信任基于一系列数字签名，根植于你提供的认证机构（CA）证书。

你可以在以下 URL 找到文档：

[`curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html`](http://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html)

[`curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html`](http://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYHOST.html)

执行实际下载：

```java
    FCurlCode = curl_easy_perform_P( Curl );
    curl_easy_getinfo_P( Curl, CURLINFO_RESPONSE_CODE, &FRespCode );
    curl_easy_cleanup_P( Curl );
```

让下载器处理此任务的结果。我们很快就会跟随这段代码：

```java
    if ( FDownloader ) { FDownloader->CompleteTask( this ); }
  }
```

私有的`InvokeCallback()`成员函数可以被友类`clDownloader`访问：

```java
  void clDownloadTask::InvokeCallback()
  {
    tthread::lock_guard<tthread::mutex> Lock( FExitingMutex );
```

本质上，这只是对`FCallback->Invoke()`的调用，并增加了两个运行时检查。第一个检查任务是是否没有被取消：

```java
    if ( !IsPendingExit() )
    {
      if ( FCurlCode != 0 )
      {
        FResult = nullptr;
      }
```

第二个检查回调的可用性并准备所有参数：

```java
      if ( FCallback )
      {
        FCallback->FTaskID = GetTaskID();
        FCallback->FResult = FResult;
        FCallback->FTask = clPtr<clDownloadTask>( this );
        FCallback->FCurlCode = FCurlCode;
        FCallback->Invoke();
        FCallback = nullptr;
      }
    }
  }
```

需要注意的是，回调的调用是在互斥锁锁定的情况下进行的。这样做是为了确保正确的取消行为。然而，`InvokeCallback()`并不是直接从`clDownloadTask`中调用的。相反，是通过`Run()`方法中的`FDownloader->CompleteTask( this )`进行间接调用。让我们看看它里面的内容，以及`clDownloader`类的核心部分：

```java
  class clDownloader: public iIntrusiveCounter
  {
  public:
    explicit clDownloader( const clPtr<clAsyncQueue>& Queue );
    virtual ~clDownloader();
```

这个方法是我们公共下载 API 最重要的部分：

```java
    virtual clPtr<clDownloadTask> DownloadURL(
      const std::string& URL, size_t TaskID,
      const clPtr<clDownloadCompleteCallback>& CB );
    virtual bool CancelLoad( size_t TaskID );
    virtual void CancelAll();
    virtual size_t GetNumDownloads() const;
```

下面是处理间接调用的代码：

```java
  private:
    void CompleteTask( clPtr<clDownloadTask> Task );
    friend class clDownloadTask;
```

这是在其中运行`clDownloadTask`的线程：

```java
    clPtr<clWorkerThread> FDownloadThread;
```

外部事件队列通过构造函数参数进行初始化：

```java
    clPtr<clAsyncQueue> FEventQueue;
  };
```

然而，`DownloadURL()`方法是关键的，其实现却出奇地简单：

```java
  clPtr<clDownloadTask> DownloadURL( const std::string& URL,size_t TaskID,const clPtr<clDownloadCompleteCallback>& CB )
  {
    if ( !TaskID || !CB ) { return clPtr<clDownloadTask>(); }
    auto Task = make_intrusive<clDownloadTask>(URL, TaskID, CB, this );
    FDownloadThread->AddTask( Task );
    return Task;
  }
```

实际上，所有繁重的工作都是在前面提到的方法`clDownloadTask::Run()`中完成的。在这里，我们只是将新构建的任务排入工作线程队列中。最有趣的事情发生在`CompleteTask()`内部：

```java
  void clDownloader::CompleteTask( clPtr<clDownloadTask> Task )
  {
    if ( !Task->IsPendingExit() )
    {
      if ( FEventQueue )
      {
```

这里，一个回调包装器被插入到事件队列中：

```java
        FEventQueue->EnqueueCapsule(
          make_intrusive<clCallbackWrapper>(Task) );
      }
    }
  }
```

辅助类调用了`FTask->InvokeCallback()`方法。记住，该方法是在正确的线程上被调用的，它是由事件队列分派的：

```java
  class clCallbackWrapper: public iAsyncCapsule
  {
  public:
    explicit clCallbackWrapper(
      const clPtr<clDownloadTask> T ):FTask(T) {}
    virtual void Invoke() override
    {
      FTask->InvokeCallback();
    }
  private:
    clPtr<clDownloadTask> FTask;
  };
```

使用示例可以在源代码包的`3_Downloader`文件夹中找到。它就像这段代码一样简单：

```java
  int main()
  {
    Curl_Load();
```

这个队列将处理下载结果：

```java
    auto Events = make_intrusive<clAsyncQueue>();
    auto Downloader = make_intrusive<clDownloader>( Events );
    clPtr<clDownloadTask> Task = Downloader->DownloadURL(
      http://downloads.sourceforge.net/freeimage/FreeImage3160.zip,
      1, make_intrusive<clTestCallback>() );
    while ( !g_ShouldExit ) { Events->DemultiplexEvents(); }
    return 0;
  }
```

`clTestCallback`类打印下载进度并将结果保存到文件中，在我们的示例中是一个`.zip`文件。

### 注意

我们使用`LUrlParser`库从给定的 URL 中提取文件名，[`github.com/corporateshark/LUrlParser`](https://github.com/corporateshark/LUrlParser)。

示例代码可以通过输入 `make all` 使用 MinGW 编译。同样的代码可以在 Android 上运行，无需更改，使用从第二章，*原生库*编译的 Curl 库。我们建议您在 Android 上尝试此代码，并直接从 C++代码进行一些下载操作。

# 原生应用中的 Android 授权

本章的大部分内容已经致力于 C++中的低级网络功能，这对于编写多平台代码至关重要。然而，在本章中省略一些 Android 特定的事项是不公平的。让我们通过授权机制来学习如何将其移入 C++代码。为此，我们将需要大量与 Java 代码交互，因为所有授权功能都是 Java 独有的。

### 注意

在这里，我们假设您已经熟悉如何在 Java 中进行授权检查。官方 Google 文档可以在这里找到：

[`developer.android.com/google/play/licensing/setting-up.html`](http://developer.android.com/google/play/licensing/setting-up.html)

[`developer.android.com/google/play/licensing/adding-licensing.html`](http://developer.android.com/google/play/licensing/adding-licensing.html)

本示例的源代码位于 `4_Licensing` 文件夹中。首先，让我们定义基本常量，这些值应该与 Android SDK 中的匹配。请查看 `License.h` 文件：

```java
  constexpr int LICENSED = 0x0100;
  constexpr int NOT_LICENSED = 0x0231;
  constexpr int RETRY = 0x0123;
  constexpr int ERROR_INVALID_PACKAGE_NAME = 1;
  constexpr int ERROR_NON_MATCHING_UID = 2;
  constexpr int ERROR_NOT_MARKET_MANAGED = 3;
  constexpr int ERROR_CHECK_IN_PROGRESS = 4;
  constexpr int ERROR_INVALID_PUBLIC_KEY = 5;
  constexpr int ERROR_MISSING_PERMISSION = 6;
```

然后，`Callbacks.h` 声明了从授权检查器调用的回调：

```java
  void OnStart();
  void OnLicensed( int Reason );
  void OnLicenseError( int ErrorCode );
```

主源文件包含那些回调的实现：

```java
  #include <stdlib.h>
  #include "Callbacks.h"
  #include "License.h"
  #include "Log.h"
  void OnStart()
  {
    LOGI( "Hello Android NDK!" );
  }
  void OnLicensed( int Reason )
  {
    LOGI( "OnLicensed: %i", Reason );
```

在这里，只有当我们确实未获得授权时才终止应用程序：

```java
    if ( Reason == NOT_LICENSED )
    {
      exit( 255 );
    }
  }
  void OnLicenseError( int ErrorCode )
  {
    LOGI( "ApplicationError: %i", ErrorCode );
  }
```

让我们深入到 JNI 和 Java 代码中，看看这些回调是如何被调用的。`LicenseChecker.cpp` 文件包含了对前面提到的回调的静态 Java 方法的一对一映射：

```java
  extern "C"
  {
    JNIEXPORT void JNICALL Java_com_packtpub_ndkmastering_AppActivity_Allow(
      JNIEnv* env, jobject obj, int Reason )
    {
      OnLicensed( Reason );
    }
    JNIEXPORT void JNICALL Java_com_packtpub_ndkmastering_AppActivity_DontAllow(
      JNIEnv* env, jobject obj, int Reason )
    {
      OnLicensed( Reason );
    }
    JNIEXPORT void JNICALL Java_com_packtpub_ndkmastering_AppActivity_ApplicationError(
      JNIEnv* env, jobject obj, int ErrorCode )
    {
      OnLicenseError( ErrorCode );
    } 
  }
```

我们跟随代码进入 `AppActivity.java` 文件，该文件声明了 `CheckLicense()`：

```java
  public void CheckLicense( String BASE64_PUBLIC_KEY,
    byte[] SALT )
  {
    String deviceId = Secure.getString( getContentResolver(), Secure.ANDROID_ID );
```

构造 `LicenseCheckerCallback` 对象。Google 授权库在完成后会调用它：

```java
    m_LicenseCheckerCallback = new AppLicenseChecker();
```

使用 `Policy` 构造 `LicenseChecker`：

```java
    m_Checker = new LicenseChecker( this,
      new ServerManagedPolicy(this,
        new AESObfuscator( SALT,
        getPackageName(), deviceId) ),
      BASE64_PUBLIC_KEY);
    m_Checker.checkAccess( m_LicenseCheckerCallback );
  }
```

回调的 Java 部分就在这里，位于类声明的底部：

```java
  public static native void Allow( int reason );
  public static native void DontAllow( int reason );
  public static native void ApplicationError( int errorCode );
```

`AppLicenseChecker` 类只是调用这些静态方法，将事件路由到 JNI 代码。多么简单！现在，您可以在 C++代码中以可移植的方式处理（和测试）对授权检查事件的反应。使用以下命令为 Android 构建示例，亲自看看吧：

```java
>ndk-build
>ant debug

```

运行时日志可以通过 `logcat` 访问。桌面版本可以通过 `make all` 命令构建，正如本书中的所有示例一样。

# Flurry 分析

让我们再接触一个与 Java 相关的事项及其与原生 C++代码的绑定。Flurry.com 是一个流行的应用内分析服务。通过向 Flurry.com 发送信息，可以完成对应用中最常用功能的确定，之后可以通过他们的网页访问收集到的统计数据。

例如，您的应用程序中有几种不同的游戏模式选项：战役、单级别或在线。用户选择其中一种模式，就会生成并发送一个事件到 Flurry.com。我们希望从 C++代码发送这些事件。

请查看 `5_Flurry` 文件夹中的示例应用程序。`main.cpp` 文件包含了一个典型的使用示例：

```java
  void OnStart()
  {
    TrackEvent( "FlurryTestEvent" );
  }
```

`TrackEvent()` 的定义以及 Android 与桌面实现的区别位于 `Callbacks.cpp` 文件中：

```java
  extern "C"
  {
    void Android_TrackEvent( const char* EventID );
  };
  void TrackEvent( const char* EventID )
  {
    #if defined(ANDROID)
      Android_TrackEvent( EventID );
    #else
      printf( "TrackEvent: %s\n", EventID );
    #endif
  }
```

Android 实现需要一些 JNI 代码才能工作。请查看以下 `jni/JNI.c` 文件：

```java
  void Android_TrackEvent( const char* EventID )
  {
    JAVA_ENTER();
    jstring jstr = (*env)->NewStringUTF( env, EventID );
    FindJavaStaticMethod( env, &Class, &Method,
      "com/packtpub/ndkmastering/AppActivity",
      "Callback_TrackEvent", "(Ljava/lang/String;)V" );
    (*env)->CallStaticVoidMethod( env, Class, Method, jstr );
    JAVA_LEAVE();
  }
```

`Callback_TrackEvent()` 在主活动中定义如下：

```java
  public static void Callback_TrackEvent( String EventID )
  {
    if ( m_Activity == null ) return;
    m_Activity.TrackEvent( EventID );
  }
  public void TrackEvent( String EventID )
  {
    FlurryAgent.logEvent( EventID );
  }
```

Flurry 分析 API 的其他部分也可以通过类似的方式从 C++路由到 Java，反之亦然。我们建议您在 Flurry 上注册一个账户，获取应用密钥，并尝试自己运行示例。只需替换 `FlurryAgent.init()` 和 `FlurryAgent.onStartSession()` 的应用密钥，即可在 Android 上运行应用程序。构建过程很简单，只需使用 `ndk-build` 和 `ant debug`。

# 总结

在本章中，我们学习了如何实现精简且可移植的多线程原语，例如引用计数侵入式智能指针、工作线程和消息泵，并使用它们创建简单的可移植 C++网络访问框架。我们还稍微涉及了 Java，以展示如何在本地代码中处理许可和用量分析。在下一章中，我们将从网络方面抽身，学习如何使用虚拟文件系统抽象来处理异构文件系统。
