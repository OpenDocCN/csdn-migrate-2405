# 安卓 NDK 初学者指南第二版（一）

> 原文：[`zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE`](https://zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Android NDK 通过利用这些移动设备的最大速度，将高性能和可移植代码注入你的移动应用中。Android NDK 允许你为密集型任务编写快速代码，并将现有代码移植到 Android 和非 Android 平台。另外，如果你有一个包含多行 C 代码的应用程序，使用 NDK 可以显著减少项目开发过程。这是多媒体和游戏中最有效的操作系统之一。

这本初学者指南将向你展示如何创建由 C/C++支持的应用程序，并将它们与 Java 集成。通过使用这个实用的分步指南，并逐步使用教程、技巧和窍门来练习你的新技能，你将学会如何在 Java 应用程序中嵌入 C/C++代码，或者在一个独立的应用程序中运行。

本书首先会教你如何访问一些最成功的 Android 应用程序中使用的原生 API 和端口库。接下来，你将通过完整实现一个原生 API 和移植现有的第三方库，来创建一个真正的原生应用程序项目。随着章节的深入，你将详细了解使用 OpenGL ES 和 OpenSL ES 渲染图形和播放声音的细节，这些正在成为移动领域的新标准。继续前进，你将学会如何访问键盘和输入外设，以及读取加速度计或方向传感器。最后，你将深入探讨更高级的主题，如 RenderScript。

到本书结束时，你将足够熟悉关键要素，开始利用原生代码的强大功能和可移植性。

# 本书内容

第一章，*设置你的环境*，涵盖了我们系统上安装的所有必备软件包。这一章还介绍了安装 Android Studio 软件包，其中包含了 Android Studio IDE 和 Android SDK。

第二章，*开始一个原生 Android 项目*，讨论了如何使用命令行工具构建我们的第一个示例应用程序，以及如何将其部署在 Android 设备上。我们还将使用 Eclipse 和 Android Studio 创建我们的第一个原生 Android 项目。

第三章，*使用 JNI 接口 Java 和 C/C++*，介绍了如何让 Java 与 C/C++通信。我们还处理在本地代码中使用全局引用的 Java 对象引用，并了解局部引用的差异。最后，我们在本地代码中引发并检查 Java 异常。

第四章，*从本地代码调用 Java*，使用 JNI 反射 API 从本地代码调用 Java 代码。我们还借助 JNI 以本地方式处理位图，并手动解码视频馈送。

第五章，*编写完全本地应用程序*，讨论了创建`NativeActivity`以相应地开始或停止本地代码轮询活动事件。我们还以本地方式访问显示窗口，例如位图以显示原始图形。最后，我们获取时间，使应用程序能够使用单调时钟适应设备速度。

第六章，*使用 OpenGL ES 渲染图形*，涵盖了如何初始化 OpenGL ES 上下文并将其绑定到 Android 窗口。然后，我们了解如何将`libpng`转换为一个模块，并从 PNG 资源中加载纹理。

第七章，*使用 OpenSL ES 播放声音*，涵盖了如何在 Android 上初始化 OpenSL ES。然后，我们学习如何从编码文件播放背景音乐以及使用声音缓冲队列在内存中播放声音。最后，我们了解到如何以线程安全和非阻塞的方式录制和播放声音。

第八章，*处理输入设备和传感器*，讨论了多种从本地代码与 Android 交互的方式。更准确地说，我们了解到如何将输入队列附加到 Native App Glue 事件循环。

第九章，*将现有库移植到 Android*，涵盖了如何在 NDK makefile 系统中通过一个简单的标志激活 STL。我们将 Box2D 库移植为一个可在 Android 项目中重复使用的 NDK 模块。

第十章，*使用 RenderScript 进行密集计算*，介绍了 RenderScript，这是一种用于并行化密集计算任务的高级技术。我们还了解如何使用预定义的 RenderScript 与内置的 Intrinsics，这目前主要用于图像处理。

# 本书所需的条件

要运行本书中的示例，需要以下软件：

+   系统：Windows，Linux 或 Mac OS X

+   JDK：Java SE 开发工具包 7 或 8

+   Cygwin：仅在 Windows 上

# 本书适合的读者

你是一个需要更高性能的 Android Java 程序员吗？你是一个不想为 Java 及其失控的垃圾收集器复杂性而烦恼的 C/C++开发者吗？你想创建快速、密集的多媒体应用程序或游戏吗？如果你对这些问题中的任何一个回答了“是”，那么这本书就是为你准备的。有了对 C/C++开发的一些基本了解，你将能够一头扎进本地 Android 开发。

# 部分

在本书中，你会发现有几个经常出现的标题（动手时间，刚才发生了什么？，小测验，以及尝试英雄）。

为了清楚地说明如何完成一个过程或任务，我们按照以下方式使用这些部分：

# 动手时间——标题

1.  动作 1

1.  动作 2

1.  动作 3

指令通常需要一些额外的解释以确保它们有意义，因此它们后面会跟着这些部分：

## *刚才发生了什么？*

本节解释了你刚刚完成的任务或指令的工作原理。

你在书中还会找到一些其他的学习辅助工具，例如：

## 尝试英雄——标题

这些是实践挑战，它们可以启发你尝试所学的知识。

# 约定

你还会发现一些文本样式，它们可以区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 处理程序会以下面的形式显示："最后，创建一个新的 Gradle 任务`ndkBuild`，它将手动触发`ndk-build`命令。"

代码块设置如下：

```java
#include <unistd.h>
…
sleep(3); // in seconds
```

当我们希望引起你注意代码块中的某个特定部分时，相关的行或项目会以粗体显示：

```java
    if (mGraphicsManager.start() != STATUS_OK) return STATUS_KO;

    mAsteroids.initialize();
    mShip.initialize();

    mTimeManager.reset();
    return STATUS_OK;
```

任何命令行输入或输出都会以下面的形式编写：

```java
adb shell stop
adb shell setprop dalvik.vm.checkjni true

```

**新** **术语**和**重要** **词汇**会以粗体显示。你在屏幕上看到的词，比如菜单或对话框中的，会在文本中像这样出现："如果一切正常，当你的应用程序启动时，Logcat 中会出现一个消息**Late-enabling – Xcheck:jni**。"

### 注意

警告或重要注意事项会像这样出现在一个框里。

### 提示

提示和技巧会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出你真正能从中获得最大收益的标题。

要向我们发送一般反馈，只需发送电子邮件到`<feedback@packtpub.com>`，并在邮件的主题中提及书籍的标题。

如果你有一个有专业知识的主题，并且你对于写作或为书籍做贡献感兴趣，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)的作者指南。

# 客户支持

既然你现在拥有了 Packt 的一本书，我们有一些事情可以帮助你最大限度地利用你的购买。

## 下载示例代码

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的账户下载你所购买的 Packt Publishing 书籍的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然可能发生。如果您在我们的书中发现了一个错误——可能是文本或代码中的错误——如果您能向我们报告，我们将不胜感激。这样做可以节省其他读者的时间，并帮助我们在后续版本中改进这本书。如果您发现任何勘误信息，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**Errata Submission Form**链接，并输入您的勘误详情。一旦您的勘误信息被验证，您的提交将被接受，并且勘误信息将被上传到我们的网站或添加到该标题下的现有勘误列表中。

要查看之前提交的勘误信息，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书名。所需信息将在**Errata**部分下显示。

## 盗版

互联网上对版权材料的盗版是一个所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上以任何形式遇到我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如果您有疑似盗版材料的链接，请通过`<copyright@packtpub.com>`联系我们。

我们感谢您帮助保护我们的作者以及我们为您提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`联系我们，我们将尽力解决问题。


# 第一章：设置你的开发环境

> *你准备好接受移动开发挑战了吗？你的电脑打开了，鼠标和键盘插上了，屏幕照亮了你的桌子吗？那么我们不要再等一分钟了！*
> 
> *开发 Android 应用程序需要一套特定的工具。你可能已经了解到了用于纯 Java 应用程序的 Android 软件开发工具包（SDK）。然而，要完全访问 Android 设备的强大功能，还需要更多：Android 原生开发工具包（NDK）。*

设置一个合适的 Android 环境并不是那么复杂，但它可能相当棘手。实际上，Android 仍然是一个不断发展的平台，最近的添加内容，如 Android Studio 或 Gradle，在 NDK 开发方面支持得并不好。尽管有这些烦恼，任何人都可以在一个小时内拥有一个可以立即工作的环境。

在第一章中，我们将要：

+   安装必备软件包

+   设置一个 Android 开发环境

+   启动一个 Android 模拟器

+   连接一个用于开发的 Android 设备

# 开始 Android 开发

区分人类与动物的是工具的使用。Android 开发者，你所属的真正物种，也不例外！

要在 Android 上开发应用程序，我们可以使用以下三个平台中的任何一个：

+   微软 Windows（XP 及更高版本）

+   苹果 OS X（版本 10.4.8 或更高版本）

+   Linux（使用 GLibc 2.7 或更高版本的发行版，如最新版本的 Ubuntu）

这些系统在 x86 平台（即使用 Intel 或 AMD 处理器的 PC）上支持 32 位和 64 位版本，Windows XP 除外（仅 32 位）。

这是一个不错的开始，但除非你能像说母语一样读写二进制代码，否则仅有一个原始操作系统是不够的。我们还需要专门用于 Android 开发的软件：

+   一个**JDK**（**Java 开发工具包**）

+   一个 Android SDK（软件开发工具包）

+   一个 Android NDK（原生开发工具包）

+   一个**IDE**（**集成开发环境**），如 Eclipse 或 Visual Studio（或为硬核程序员准备的 vi）。尽管 Android Studio 和 IntelliJ 为原生代码提供了基本支持，但它们还不适合 NDK 开发。

+   一个好的旧命令行终端来操作所有这些工具。我们将使用 Bash。

既然我们知道与 Android 工作需要哪些工具，那么让我们开始安装和设置过程。

### 注意

以下部分专门针对 Windows。如果你是 Mac 或 Linux 用户，可以跳到*设置 OS X*或*设置 Linux*部分。

## 设置 Windows

在安装必要工具之前，我们需要正确设置 Windows 以承载我们的 Android 开发工具。尽管 Windows 并不是 Android 开发的最自然选择，但它仍然提供了一个功能齐全的环境。

以下部分将解释如何在 Windows 7 上设置必备软件包。这个过程同样适用于 Windows XP、Vista 或 8。

# 动手操作——为 Android 开发准备 Windows

要在 Windows 上使用 Android NDK 进行开发，我们需要设置一些先决条件：Cygwin、JDK 和 Ant。

1.  访问[`cygwin.com/install.html`](http://cygwin.com/install.html)并下载适合你环境的 Cygwin 安装程序。下载完成后，执行它。

1.  在安装窗口中，点击**下一步**然后选择**从互联网安装**。![准备在 Windows 上开发 Android 的动作时间](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_22.jpg)

    跟随安装向导屏幕操作。考虑选择一个在你国家下载 Cygwin 软件包的下载站点。

    然后，当提议时，包括**Devel**、**Make**、**Shells**和**bash**软件包：

    ![准备在 Windows 上开发 Android 的动作时间](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_23.jpg)

    跟随安装向导直到完成。根据你的互联网连接，这可能需要一些时间。

1.  从 Oracle 官网[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载 Oracle JDK 7（或者 JDK 8，尽管在本书编写时它还未正式支持）。启动并按照安装向导直到完成。

1.  从 Ant 的官网[`ant.apache.org/bindownload.cgi`](http://ant.apache.org/bindownload.cgi)下载 Ant，并将其二进制包解压到你选择的目录中（例如，`C:\Ant`）。

1.  安装后，在环境变量中定义 JDK、Cygwin 和 Ant 的位置。为此，打开 Windows **控制面板** 并进入 **系统** 面板（或者在 Windows 开始菜单中右键点击 **计算机** 项，选择 **属性**）。

    然后，进入**高级系统设置**。将出现**系统属性**窗口。最后，选择**高级**标签，点击**环境变量**按钮。

1.  在环境变量窗口中，系统变量列表内添加：

    +   设置`CYGWIN_HOME`变量，其值为`Cygwin`安装目录（例如，`C:\Cygwin`）

    +   设置`JAVA_HOME`变量，其值为 JDK 安装目录

    +   设置`ANT_HOME`变量，其值为 Ant 安装目录（例如，`C:\Ant`）

    在你的`PATH`环境变量开头添加`%CYGWIN_HOME%\bin;%JAVA_HOME%\bin;%ANT_HOME%\bin;`，每个路径之间用分号隔开。

    ![准备在 Windows 上开发 Android 的动作时间](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_49.jpg)

1.  最后，启动 Cygwin 终端。第一次启动时将创建你的配置文件。检查`make`版本以确保 Cygwin 正常工作：

    ```java
    make –version

    ```

    你将看到以下输出：

    ![准备在 Windows 上开发 Android 的动作时间](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_27.jpg)

1.  通过运行 Java 并检查其版本，确保 JDK 已正确安装。仔细检查以确保版本号与刚安装的 JDK 相符：

    ```java
    java –version

    ```

    你将在屏幕上看到以下输出：

    ![准备在 Windows 上开发 Android 的动作时间](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_28.jpg)

1.  从经典的 Windows 终端，检查 Ant 版本以确保其正常工作：

    ```java
    ant -version

    ```

    你将在终端上看到以下内容：

    ![准备在 Windows 上进行 Android 开发的行动时间](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_48.jpg)

## *刚才发生了什么？*

Windows 现在已设置好所有必要的软件包，以容纳 Android 开发工具：

+   Cygwin 是一个开源软件集合，它允许 Windows 平台模拟类似 Unix 的环境。它的目标是原生地将基于 POSIX 标准（如 Unix、Linux 等）的软件集成到 Windows 中。它可以被视为起源于 Unix/Linux（但在 Windows 上原生重新编译）的应用程序与 Windows 操作系统本身之间的中间层。Cygwin 包括`Make`，这是 Android NDK 编译系统构建原生代码所需的。

    ### 提示

    即使 Android NDK R7 引入了原生的 Windows 二进制文件，不需要 Cygwin 运行时，但为了调试目的，仍然建议安装后者。

+   JDK 7，它包含了在 Android 上构建 Java 应用程序以及运行 Eclipse IDE 和 Ant 所需的运行时和工具。在安装 JDK 时，你可能遇到的唯一真正麻烦是一些来自之前安装的干扰，比如现有的**Java 运行时环境**（**JRE**）。通过`JAVA_HOME`和`PATH`环境变量可以强制使用正确的 JDK。

    ### 提示

    定义`JAVA_HOME`环境变量不是必须的。然而，`JAVA_HOME`是 Java 应用程序（包括 Ant）中的一个流行约定。它首先在`JAVA_HOME`（如果已定义）中查找`java`命令，然后才在`PATH`中查找。如果你稍后在其他位置安装了最新的 JDK，不要忘记更新`JAVA_HOME`。

+   Ant 是一个基于 Java 的构建自动化工具。虽然这不是一个必需品，但它允许从命令行构建 Android 应用程序，如我们将在第二章，*开始一个原生 Android 项目*中看到的。它也是设置持续集成链的一个好解决方案。

下一步是设置 Android 开发工具包。

## 在 Windows 上安装 Android 开发工具

Android 需要特定的开发工具包来开发应用程序：Android SDK 和 NDK。幸运的是，谷歌考虑到了开发者社区，并免费提供所有必要的工具。

在以下部分，我们将安装这些工具，开始在 Windows 7 上开发原生的 Android 应用程序。

# 行动时间——在 Windows 上安装 Android SDK 和 NDK

Android Studio 软件包已经包含了 Android SDK。让我们来安装它。

1.  打开你的网络浏览器，从[`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html)下载 Android Studio 软件包。

    运行下载的程序，并按照安装向导操作。当被请求时，安装所有 Android 组件。

    ![行动时间——在 Windows 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_29.jpg)

    然后，选择 Android Studio 和 Android SDK 的安装目录（例如，`C:\Android\android-studio`和`C:\Android\sdk`）。

1.  启动 Android Studio 以确保其正常工作。如果 Android Studio 提出从之前的安装导入设置，选择你偏好的选项并点击**OK**。![行动时间——在 Windows 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_26.jpg)

    此时应该会出现 Android Studio 的欢迎屏幕。关闭它。

    ![行动时间——在 Windows 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_25.jpg)

1.  访问[`developer.android.com/tools/sdk/ndk/index.html`](http://developer.android.com/tools/sdk/ndk/index.html)，下载适合你环境的 Android NDK（不是 SDK！），将压缩文件解压到你选择的目录中（例如，`C:\Android\ndk`）。

1.  为了从命令行轻松访问 Android 工具，让我们将 Android SDK 和 NDK 声明为环境变量。从现在开始，我们将这些目录称为`$ANDROID_SDK`和`$ANDROID_NDK`。

    打开**环境变量**系统窗口，就像我们之前做的那样。在系统变量列表中添加以下内容：

    +   `ANDROID_SDK`变量应包含 SDK 安装目录（例如，C:\Android\sdk）。

    +   `ANDROID_NDK`变量应包含 NDK 安装目录（例如，C:\Android\ndk）。

    在你的`PATH`环境变量开头添加`%ANDROID_SDK%\tools;%ANDROID_SDK%\platform-tools;%ANDROID_NDK%;`，用分号隔开。

    ![行动时间——在 Windows 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_24.jpg)

1.  当启动 Cygwin 时，所有 Windows 环境变量都应该自动被导入。打开一个 Cygwin 终端，使用`adb`列出连接到电脑的 Android 设备（即使当前没有连接的设备也要这样做），以检查 SDK 是否正常工作。不应该出现错误：

    ```java
    adb devices

    ```

    ![行动时间——在 Windows 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_46.jpg)

1.  检查`ndk-build`版本，以确保 NDK 正常工作。如果一切正常，应该会出现`Make`版本：

    ```java
    ndk-build -version

    ```

    ![行动时间——在 Windows 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_47.jpg)

1.  打开位于 ADB 捆绑目录根目录的**Android SDK Manager**。![行动时间——在 Windows 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_45.jpg)

    在打开的窗口中，点击**New**选择所有包，然后点击**Install packages...**按钮。在弹出的窗口中接受许可协议，点击**Install**按钮开始安装 Android 开发包。

    经过几分钟的等待，所有包都已下载完毕，出现一条确认信息，表明 Android SDK 管理器已更新。

    确认并关闭管理器。

## *刚才发生了什么？*

Android Studio 现在已安装在系统上。虽然它现在是官方的 Android IDE，但由于它对 NDK 的支持不足，我们在本书中不会大量使用它。然而，完全可以用 Android Studio 进行 Java 开发，以及使用命令行或 Eclipse 进行 C/C++ 开发。

Android SDK 通过 Android Studio 包进行了设置。另一种解决方案是手动部署 Google 提供的 SDK 独立包。另一方面，Android NDK 是从其归档文件手动部署的。通过几个环境变量，SDK 和 NDK 都可以通过命令行使用。

为了获得一个完全功能性的环境，所有 Android 包都已通过 Android SDK 管理器下载，该管理器旨在管理通过 SDK 可用的所有平台、源、示例和仿真功能。当新的 SDK API 和组件发布时，这个工具极大地简化了环境的更新。无需重新安装或覆盖任何内容！

然而，Android SDK 管理器不管理 NDK，这就是为什么我们要单独下载它，以及为什么将来你需要手动更新它。

### 提示

安装所有 Android 包并不是严格必要的。真正需要的是您的应用程序所针对的 SDK 平台（可能还有 Google APIs）版本。不过，安装所有包可能会在导入其他项目或示例时避免麻烦。

您的 Android 开发环境安装尚未完成。我们还需要一个东西，才能与 NDK 舒适地开发。

### 注意

这是一段专门介绍 Windows 设置的章节的结束。下一章节将专注于 OS X。

## 设置 OS X

Apple 电脑以其简单易用而闻名。我必须说，在 Android 开发方面，这个谚语是相当正确的。实际上，作为基于 Unix 的系统，OS X 很适合运行 NDK 工具链。

下一节将解释如何在 Mac OS X Yosemite 上设置前提条件包。

# 行动时间 - 准备 OS X 进行 Android 开发

要在 OS X 上使用 Android NDK 进行开发，我们需要设置一些前提条件：JDK、开发者工具和 Ant。

1.  OS X 10.6 Snow Leopard 及以下版本预装了 JDK。在这些系统上，Apple 的 JDK 是版本 6。由于这个版本已被弃用，建议安装更新的 JDK 7（或 JDK 8，尽管在本书编写时它没有得到官方支持）。

    另一方面，OS X 10.7 Lion 及以上版本没有默认安装 JDK。因此，安装 JDK 7 是强制性的。

    为此，从 Oracle 网站下载 Oracle JDK 7，网址为 [`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)。启动 `DMG` 并按照安装向导直到结束。

    ![行动时间 - 准备 OS X 进行 Android 开发](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_25.jpg)

    检查 Java 版本以确保 JDK 已正确安装。

    ```java
    java -version

    ```

    ![动手操作——为 Android 开发准备 OS X](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_76.jpg)

    ### 提示

    要知道是否安装了 JDK 6，请检查通过转到 Mac 上的**应用程序** | **实用工具**找到的**Java 偏好设置.app**。如果你有 JDK 7，检查**系统偏好设置**下是否有**Java**图标。

1.  所有开发者工具都包含在 XCode 安装包中（在本书编写时为版本 5）。XCode 在 AppStore 上免费提供。从 OS X 10.9 开始，开发者工具包可以通过终端提示符使用以下命令单独安装：

    ```java
    xcode-select --install

    ```

    ![动手操作——为 Android 开发准备 OS X](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_65.jpg)

    然后，从弹出的窗口中选择**安装**。

1.  要使用 Android NDK 构建本地代码，无论是否安装了 XCode 或单独的开发者工具包，我们都需要`Make`。打开终端提示符并检查`Make`版本以确保它能正常工作：

    ```java
    make –version

    ```

    ![动手操作——为 Android 开发准备 OS X](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_62.jpg)

1.  在 OS X 10.9 及以后的版本中，需要手动安装 Ant。从 Ant 的官方网站[`ant.apache.org/bindownload.cgi`](http://ant.apache.org/bindownload.cgi)下载 Ant，并将其二进制包解压到您选择的目录中（例如，`/Developer/Ant`）。

    然后，创建或编辑文件`~/.profile`，并通过添加以下内容使 Ant 在系统路径上可用：

    ```java
    export ANT_HOME="/Developer/Ant"
    export PATH=${ANT_HOME}/bin:${PATH}
    ```

    从当前会话注销并重新登录（或重启计算机），并通过命令行检查 Ant 版本以确认 Ant 是否正确安装：

    ```java
    ant –version

    ```

    ![动手操作——为 Android 开发准备 OS X](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_60.jpg)

## *刚才发生了什么？*

我们的 OS X 系统现在已设置好必要的软件包以支持 Android 开发工具：

+   JDK 7，它包含了在 Android 上构建 Java 应用程序以及运行 Eclipse IDE 和 Ant 所需的运行时和工具。

+   开发者工具包，它包含了各种命令行工具。它包括 Make，这是 Android NDK 编译系统构建本地代码所需的。

+   Ant，这是一个基于 Java 的构建自动化工具。尽管这不是必须的，但它允许我们从命令行构建 Android 应用程序，如我们将在第二章，*开始一个本地 Android 项目*中看到的。它也是设置持续集成链的一个好解决方案。

下一步是设置 Android 开发工具包。

## 在 OS X 上安装 Android 开发工具包

Android 开发应用程序需要特定的开发工具包：Android SDK 和 NDK。幸运的是，Google 考虑到了开发者社区，并免费提供所有必要的工具。

在接下来的部分，我们将安装这些工具包，开始在 Mac OS X Yosemite 上开发本地 Android 应用程序。

# 动手操作——在 OS X 上安装 Android SDK 和 NDK

Android Studio 软件包已经包含了 Android SDK。我们来安装它。

1.  打开您的网络浏览器，从[`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html)下载 Android Studio 软件包。

1.  运行下载的`DMG`文件。在出现的窗口中，将**Android Studio**图标拖到**应用程序**中，等待 Android Studio 完全复制到系统上。![行动时间 – 在 OS X 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_66.jpg)

1.  从 Launchpad 运行 Android Studio。

    如果出现错误**无法找到有效的 JVM**（因为 Android Studio 在启动时找不到合适的 JRE），您可以通过命令行以下方式运行 Android Studio（使用适当的 JDK 路径）：

    ```java
    export STUDIO_JDK=/Library/Java/JavaVirtualMachines/jdk1.7.0_71.jdk
    open /Applications/Android\ Studio.apps

    ```

    ### 提示

    为了解决 Android Studio 启动问题，您也可以安装苹果提供的旧版 JDK 6。注意！这个版本已经过时，因此不推荐使用。

    如果 Android Studio 提示您从之前的安装导入设置，选择您偏好的选项并点击**确定**。

    ![行动时间 – 在 OS X 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_63.jpg)

    在出现的下一个**设置向导**屏幕中，选择**标准**安装类型并继续安装。

    ![行动时间 – 在 OS X 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_75.jpg)

    完成安装直到出现 Android Studio 欢迎屏幕。然后关闭 Android Studio。

    ![行动时间 – 在 OS X 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_77.jpg)

1.  访问[`developer.android.com/tools/sdk/ndk/index.html`](http://developer.android.com/tools/sdk/ndk/index.html)并下载适合您环境的 Android NDK（不是 SDK！）归档文件。将其解压到您选择的目录中（例如，`~/Library/Android/ndk`）。

1.  为了从命令行轻松访问 Android 实用工具，我们将 Android SDK 和 NDK 声明为环境变量。从现在开始，我们将这些目录称为`$ANDROID_SDK`和`$ANDROID_NDK`。假设您使用默认的`Bash`命令行外壳，在您的家目录中创建或编辑`.profile`（这是一个隐藏文件！）并在最后添加以下指令（根据您的安装调整路径）：

    ```java
    export ANDROID_SDK="~/Library/Android/sdk"
    export ANDROID_NDK="~/Library/Android/ndk"
    export PATH="${ANDROID_SDK}/tools:${ANDROID_SDK}/platform-tools:${ANDROID_NDK}:${PATH}"
    ```

1.  从当前会话注销并重新登录（或者重启电脑）。使用`adb`列出连接到电脑的 Android 设备（即使当前没有连接的设备），以检查 Android SDK 是否正常工作。不应该出现错误：

    ```java
    adb devices

    ```

    ![行动时间 – 在 OS X 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_68.jpg)

1.  检查`ndk-build`版本以确保 NDK 正常工作。如果一切正常，应该会显示`Make`版本：

    ```java
    ndk-build -version

    ```

    ![行动时间 – 在 OS X 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_69.jpg)

1.  打开终端，使用以下命令启动 Android SDK 管理器：

    ```java
    android

    ```

    ![行动时间 – 在 OS X 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_70.jpg)

    在打开的窗口中，点击**新建**以选择所有软件包，然后点击**安装软件包...**按钮。在弹出的窗口中接受许可协议，并通过点击**安装**按钮开始安装所有 Android 软件包。

    几分钟后，所有软件包下载完毕，出现一条确认信息，表明 Android SDK 管理器已更新。

    验证并关闭管理器。

## *刚才发生了什么？*

Android Studio 现在已安装在系统上。尽管它现在是官方的 Android IDE，但由于它对 NDK 的支持不足，我们在书中不会过多地使用它。然而，完全可以用 Android Studio 进行 Java 开发，以及使用命令行或 Eclipse 进行 C/C++开发。

Android SDK 已经通过 Android Studio 软件包进行了设置。另一种解决方案是手动部署由 Google 提供的 SDK 独立软件包。另一方面，Android NDK 则是从其归档文件中手动部署的。通过几个环境变量，SDK 和 NDK 都可以通过命令行使用。

### 提示

在处理环境变量时，OS X 会有些棘手。它们可以在`.profile`中轻松声明，供从终端启动的应用程序使用，正如我们刚才所做的。也可以使用`environment.plist`文件为那些不是从 Spotlight 启动的 GUI 应用程序声明。

为了获得一个完全可用的环境，所有 Android 软件包都通过 Android SDK 管理器下载，该管理器旨在管理通过 SDK 提供的所有平台、源、示例和仿真功能。当新的 SDK API 和组件发布时，这个工具可以大大简化你的环境更新工作。无需重新安装或覆盖任何内容！

然而，Android SDK 管理器并不管理 NDK，这就是为什么我们要单独下载 NDK，以及将来你需要手动更新它的原因。

### 提示

安装所有 Android 软件包并不是绝对必要的。真正需要的是你的应用程序所针对的 SDK 平台（可能还有 Google APIs）。不过，安装所有软件包可以避免在导入其他项目或示例时遇到麻烦。

你的 Android 开发环境安装尚未完成。我们还需要一个东西，以便更舒适地使用 NDK 进行开发。

### 注意

这是一段专门针对 OS X 设置的章节的结束。下一节将专门介绍 Linux。

## 设置 Linux

Linux 非常适合进行 Android 开发，因为 Android 工具链是基于 Linux 的。实际上，作为基于 Unix 的系统，Linux 非常适合运行 NDK 工具链。但是要注意，安装软件包的命令可能会根据你的 Linux 发行版而有所不同。

下一节将解释如何在 Ubuntu 14.10 Utopic Unicorn 上设置必备软件包。

# 动手时间——为 Android 开发准备 Ubuntu

要在 Linux 上使用 Android NDK 进行开发，我们需要设置一些先决条件：Glibc、Make、OpenJDK 和 Ant。

1.  从命令提示符中检查是否安装了 Glibc（GNU C 标准库）2.7 或更高版本，通常 Linux 系统默认会安装：

    ```java
    ldd -–version

    ```

    ![行动时间 - 准备 Ubuntu 以进行 Android 开发](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_31.jpg)

1.  `Make` 也需要用来构建本地代码。从 build-essential 软件包中安装它（需要管理员权限）：

    ```java
    sudo apt-get install build-essential

    ```

    运行以下命令以确保正确安装了 `Make`，如果安装正确，将显示其版本：

    ```java
    make –version

    ```

    ![行动时间 - 准备 Ubuntu 以进行 Android 开发](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_32.jpg)

1.  在 64 位 Linux 系统上，安装 32 位库兼容性软件包，因为 Android SDK 只有编译为 32 位的二进制文件。在 Ubuntu 13.04 及更早版本上，只需安装 `ia32-libs` 软件包即可：

    ```java
    sudo apt-get install ia32-libs

    ```

    在 Ubuntu 13.10 64 位及以后的版本中，这个软件包已经被移除。因此，手动安装所需的软件包：

    ```java
    sudo apt-get install lib32ncurses5 lib32stdc++6 zlib1g:i386 libc6-i386

    ```

1.  安装 Java OpenJDK 7（或者 JDK 8，尽管在本书编写时它没有得到官方支持）。Oracle JDK 也可以：

    ```java
    sudo apt-get install openjdk-7-jdk

    ```

    通过运行 Java 并检查其版本，确保 JDK 正确安装：

    ```java
    java –version

    ```

    ![行动时间 - 准备 Ubuntu 以进行 Android 开发](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_33.jpg)

1.  使用以下命令安装 Ant（需要管理员权限）：

    ```java
    sudo apt-get install ant

    ```

    检查 Ant 是否正常工作：

    ```java
    ant -version

    ```

    ![行动时间 - 准备 Ubuntu 以进行 Android 开发](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_34.jpg)

## *刚才发生了什么？*

我们的 Linux 系统现在已准备好必要的软件包以支持 Android 开发工具：

+   build-essential 软件包是 Linux 系统上用于编译和打包的最小工具集。它包括 Make，这是 Android NDK 编译系统构建本地代码所必需的。**GCC**（**GNU C 编译器**）也包括在内，但不是必需的，因为 Android NDK 已经包含了自己的版本。

+   64 位系统上的 32 位兼容库，因为 Android SDK 仍然使用 32 位二进制文件。

+   JDK 7，其中包含在 Android 上构建 Java 应用程序以及在 Eclipse IDE 和 Ant 中运行所需的运行时和工具。

+   Ant 是一个基于 Java 的构建自动化工具。尽管这不是一个硬性要求，但它允许我们从命令行构建 Android 应用程序，正如我们将在第二章《*开始一个本地 Android 项目*》中看到的那样。它也是设置持续集成链的一个好解决方案。

下一步是设置 Android 开发工具包。

## 在 Linux 上安装 Android 开发工具包

Android 开发应用程序需要特定的开发工具包：Android SDK 和 NDK。幸运的是，Google 已经考虑到了开发者社区，并免费提供所有必要的工具。

在以下部分，我们将安装这些工具包，以便在 Ubuntu 14.10 Utopic Unicorn 上开始开发本地 Android 应用程序。

# 行动时间 - 在 Ubuntu 上安装 Android SDK 和 NDK

Android Studio 包已经包含了 Android SDK。让我们来安装它。

1.  打开你的网页浏览器，从 [`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html) 下载 Android Studio 包。将下载的归档文件解压到你选择的目录中（例如，`~/Android/Android-studio`）。

1.  运行 Android Studio 脚本 `bin/studio.sh`。如果 Android Studio 提出从之前的安装导入设置，选择你偏好的选项并点击 **确定**。![行动时间——在 Ubuntu 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_04.jpg)

    在出现的下一个 **设置** **向导** 屏幕上，选择 **标准** 安装类型并继续安装。

    ![行动时间——在 Ubuntu 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_01.jpg)

    完成安装直到出现 Android Studio 欢迎屏幕。然后关闭 Android Studio。

    ![行动时间——在 Ubuntu 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_02.jpg)

1.  访问 [`developer.android.com/tools/sdk/ndk/index.html`](http://developer.android.com/tools/sdk/ndk/index.html) 并下载适合你环境的 Android NDK（不是 SDK！）归档文件。将其解压到你选择的目录中（例如，`~/Android/Ndk`）。

1.  为了从命令行轻松访问 Android 实用工具，让我们将 Android SDK 和 NDK 声明为环境变量。从现在开始，我们将这些目录称为 `$ANDROID_SDK` 和 `$ANDROID_NDK`。编辑你主目录中的 `.profile` 文件（注意这是一个隐藏文件！），并在文件末尾添加以下变量（根据你的安装目录调整它们的路径）：

    ```java
    export ANDROID_SDK="~/Android/Sdk"
    export ANDROID_NDK="~/Android/Ndk"
    export PATH="${ANDROID_SDK}/tools:${ANDROID_SDK}/platform-tools:${ANDROID_NDK}:${PATH}"
    ```

1.  从当前会话中注销并重新登录（或者重启你的电脑）。使用 `adb` 列出连接到电脑的 Android 设备（即使当前没有连接也要列出），以检查 Android SDK 是否正常工作。不应该出现错误：

    ```java
    adb devices

    ```

    ![行动时间——在 Ubuntu 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_35.jpg)

1.  检查 `ndk-build` 的版本以确保 NDK 正在运行。如果一切正常，应该会出现 `Make` 的版本：

    ```java
    ndk-build -version

    ```

    ![行动时间——在 Ubuntu 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_32.jpg)

1.  打开终端，使用以下命令启动 Android SDK 管理器：

    ```java
    android

    ```

    ![行动时间——在 Ubuntu 上安装 Android SDK 和 NDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_03.jpg)

    在打开的窗口中，点击 **新建** 以选择所有包，然后点击 **安装包...** 按钮。在出现的弹出窗口中接受许可协议，并通过点击 **安装** 按钮开始所有 Android 包的安装。

    经过一些漫长的等待，所有包都已下载完毕，出现一条确认信息表明 Android SDK 管理器已更新。

    确认并关闭管理器。

## *刚才发生了什么？*

现在系统上已经安装了 Android Studio。尽管它现在是官方的安卓 IDE，但由于它对 NDK 的支持不足，我们在本书中不会大量使用它。然而，完全可以用 Android Studio 进行 Java 开发，用命令行或 Eclipse 进行 C/C++开发。

安卓 SDK 已经通过 Android Studio 软件包进行了设置。另一种解决方案是手动部署谷歌提供的 SDK 独立安装包。另一方面，安卓 NDK 则是从其归档文件中手动部署的。通过几个环境变量，SDK 和 NDK 都可以在命令行中使用。

为了获得一个完全功能的环境，所有安卓软件包都是通过安卓 SDK 管理器下载的，该管理器旨在管理通过 SDK 提供的所有平台、源代码、示例和仿真功能。当新的 SDK API 和组件发布时，这个工具可以极大地简化环境的更新。无需重新安装或覆盖任何内容！

然而，安卓 SDK 管理器并不管理 NDK，这就是为什么我们要单独下载 NDK，以及为什么将来需要手动更新它的原因。

### 提示

安装所有的安卓软件包并非严格必要。真正需要的是您的应用程序所针对的 SDK 平台（可能还有 Google APIs）。不过，安装所有软件包可能会在导入其他项目或示例时避免麻烦。

安卓开发环境的安装还没有结束。我们还需要一个东西，才能更舒适地使用 NDK 进行开发。

### 注意

这是一段专门针对 Linux 设置的章节的结束。下一节适用于所有操作系统。

## 安装 Eclipse IDE

由于 Android Studio 的限制，Eclipse 仍然是最适合在安卓上开发本地代码的 IDE 之一。然而，使用 IDE 并非必须；命令行爱好者或`vi`狂热者可以跳过这一部分！

在下一节中，我们将了解如何设置 Eclipse。

# 行动时间 – 在您的操作系统上安装带有 ADT 的 Eclipse

自从最新的安卓 SDK 发布以来，Eclipse 及其插件（ADT 和 CDT）需要手动安装。为此，执行以下步骤：

1.  访问[`www.eclipse.org/downloads/`](http://www.eclipse.org/downloads/)并下载适用于 Java 开发者的 Eclipse。将下载的压缩文件解压到您选择的目录中（例如，在 Windows 上的`C:\Android\eclipse`，Linux 上的`~/Android/Eclipse`，Mac OS X 上的`~/Library/Android/eclipse`）。

    然后，运行 Eclipse。如果 Eclipse 在启动时询问工作空间（其中包含 Eclipse 设置和项目），请定义您选择的位置或保留默认设置，然后点击**确定**。

    当 Eclipse 加载完毕后，关闭欢迎页面。应该会出现以下窗口：

    ![行动时间 – 在您的操作系统上安装带有 ADT 的 Eclipse](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_71.jpg)

1.  转到 **帮助** | **安装新软件…**。在 **工作空间:** 字段中输入 `https://dl-ssl.google.com/android/eclipse` 并验证。几秒钟后，会出现一个 **开发者工具** 插件。选择它并点击 **下一步** 按钮。

    ### 提示

    如果在访问更新站点时此步骤失败，请检查您的互联网连接。您可能是断开连接或通过代理连接。在后一种情况下，您可以从 ADT 网页上单独下载 ADT 插件存档并手动安装，或者配置 Eclipse 通过代理连接。

    ![操作时间 – 在您的操作系统上安装带有 ADT 的 Eclipse](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_73.jpg)

    按照向导提示操作，并在询问时接受条件。在向导的最后一页，点击**完成**以安装 ADT。可能会出现警告，提示插件内容未签名。忽略它并点击**确定**。完成后，按照请求重启 Eclipse。

1.  返回到 **帮助** | **安装新软件…**。打开 **工作空间** 下拉框，并选择包含 Eclipse 版本名称的项（这里为 Luna）。然后，勾选 **只显示适用于目标环境的软件** 选项。在插件树中找到 **编程语言** 并展开它。最后，勾选所有 C/C++ 插件并点击 **下一步**。![操作时间 – 在您的操作系统上安装带有 ADT 的 Eclipse](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_72.jpg)

    按照向导提示操作，并在询问时接受条件。在向导的最后一页，点击**完成**。等待安装完成并重启 Eclipse。

1.  转到 **Windows** | **首选项...**（在 Mac OS X 上为 **Eclipse** | **首选项...**），然后在左侧树中选择 **Android**。如果一切正常，SDK 位置应该已填写 Android SDK 路径。![操作时间 – 在您的操作系统上安装带有 ADT 的 Eclipse](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_78.jpg)

    然后，在同一个窗口中，转到 **Android** | **NDK**。**NDK 位置**字段应为空。填写 Android NDK 路径并验证。如果路径错误，Eclipse 会提示目录无效。

    ![操作时间 – 在您的操作系统上安装带有 ADT 的 Eclipse](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_74.jpg)

## *刚才发生了什么？*

现在 Eclipse 已经配置好相应的 SDK 和 NDK 并运行起来了。由于 Google 不再提供 ADT 包，因此需要手动在 Eclipse 中安装 Android 开发插件 ADT 和 C/C++ Eclipse 插件 CDT。

请注意，Eclipse 已经被 Google 弃用，并由 Android Studio 替换。遗憾的是，目前 Android Studio 对 C/C++ 和 NDK 的支持相当有限。构建本地代码的唯一方式是通过 Gradle，这个新的 Android 构建系统，其 NDK 功能仍然不稳定。如果舒适的 IDE 对您至关重要，您仍然可以使用 Android Studio 进行 Java 开发，使用 Eclipse 进行 C/C++ 开发。

如果您在 Windows 上工作，可能您是 Visual Studio 的熟练用户。在这种情况下，我建议您注意一些项目，如下所示，将 Android NDK 开发带到了 Visual Studio：

+   Android++是一个免费的 Visual Studio 扩展，可以在[`android-plus-plus.com/`](http://android-plus-plus.com/)找到。尽管在本书编写时仍处于测试阶段，但 Android++看起来相当有前景。

+   NVidia Nsight 可以在 Nvidia 开发者网站[`developer.nvidia.com/nvidia-nsight-tegra`](https://developer.nvidia.com/nvidia-nsight-tegra)（如果你有 Tegra 设备）用开发者账户下载。它将 NDK、一个稍微定制版的 Visual Studio 和一个不错的调试器打包在一起。

+   可以在[`github.com/gavinpugh/vs-android`](https://github.com/gavinpugh/vs-android)找到的 VS-Android 是一个有趣的开放源代码项目，它将 NDK 工具带到了 Visual Studio 中。

我们的开发环境现在几乎准备好了。尽管如此，还缺少最后一块：运行和测试我们应用程序的环境。

## 设置 Android 模拟器

Android SDK 提供了一个模拟器，以帮助希望加快部署-运行-测试周期的开发者，或者希望测试例如不同类型的分辨率和操作系统版本的开发者。让我们看看如何设置它。

# 行动时间 – 创建 Android 虚拟设备

Android SDK 提供了我们轻松创建新的模拟器**Android Virtual Device** (**AVD**)所需的一切：

1.  从终端运行以下命令打开**Android SDK Manager**：

    ```java
    android

    ```

1.  转到**工具** | **管理 AVD...**。或者，在 Eclipse 的主工具栏中点击专用的**Android Virtual Device Manager**按钮。

    然后，点击**新建**按钮创建一个新的 Android 模拟器实例。用以下信息填写表单并点击**确定**：

    ![行动时间 – 创建 Android 虚拟设备](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_40.jpg)

1.  新创建的虚拟设备现在显示在**Android Virtual Device Manager**列表中。选择它并点击**启动...**。

    ### 注意

    如果你在 Linux 上遇到与`libGL`相关的错误，请打开命令提示符并运行以下命令以安装 Mesa 图形库：`sudo apt-get install libgl1-mesa-dev`。

1.  **启动选项**窗口出现。根据需要调整显示大小，然后点击**启动**。模拟器启动，一段时间后，你的虚拟设备将加载完毕：![行动时间 – 创建 Android 虚拟设备](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_41.jpg)

1.  默认情况下，模拟器的 SD 卡是只读的。虽然这是可选的，但你可以通过从提示符发出以下命令来将其设置为写入模式：

    ```java
    adb shell
    su
    mount -o rw,remount rootfs /
    chmod 777 /mnt/sdcard
    exit

    ```

## *刚才发生了什么？*

安卓模拟器可以通过安卓虚拟设备管理器轻松管理。我们现在能够在代表性的环境中测试我们即将开发的应用程序。更妙的是，我们现在可以在多种条件和分辨率下进行测试，而无需昂贵的设备。然而，如果模拟器是有用的开发工具，请记住模拟并不总是完全具有代表性，并且缺少一些功能，尤其是硬件传感器，这些传感器只能部分模拟。

安卓虚拟设备管理器并非我们管理模拟器的唯一场所。我们还可以使用安卓 SDK 提供的命令行工具 emulator。例如，要从终端直接启动先前创建的 Nexus4 模拟器，请输入以下内容：

```java
emulator -avd Nexus4

```

在创建`Nexus4` AVD 时，敏锐的读者可能已经注意到我们将 CPU/ABI 设置为 Intel Atom（x86），而大多数安卓设备运行在 ARM 处理器上。实际上，由于 Windows、OS X 和 Linux 都运行在 x86 上，只有 x86 安卓模拟器镜像可以受益于硬件和 GPU 加速。另一方面，ARM ABI 在没有加速的情况下可能会运行得相当慢，但它可能更符合你的应用程序可能运行的设备。

### 提示

若要使用 X86 AVD 获得完全硬件加速，你需要在 Windows 或 Mac OS X 系统上安装英特尔**硬件加速执行管理器**（**HAXM**）。在 Linux 上，你可以安装 KVM。这些程序只有在你的 CPU 支持虚拟化技术时才能工作（如今大多数情况下都是如此）。

敏锐的读者可能还会惊讶于我们没有选择最新的安卓平台。原因仅仅是并非所有安卓平台都提供 x86 镜像。

### 注意

快照选项允许在关闭模拟器之前保存其状态。遗憾的是，这个选项与 GPU 加速不兼容。你必须选择其中之一。

最后需要注意的是，在创建 AVD 以在有限的硬件条件下测试应用程序时，自定义其他选项（如 GPS、摄像头等的设置）也是可能的。屏幕方向可以通过快捷键*Ctrl* + *F11*和*Ctrl* + *F12*进行切换。有关如何使用和配置模拟器的更多信息，请访问安卓网站：[`developer.android.com/tools/devices/emulator.html`](http://developer.android.com/tools/devices/emulator.html)。

## 使用安卓设备进行开发

尽管模拟器可以提供帮助，但它们显然无法与真实设备相比。因此，请拿起你的安卓设备，打开它，让我们尝试将其连接到我们的开发平台。以下步骤可能会因你的制造商和手机语言而有所不同。因此，请参阅你的设备文档以获取具体说明。

# 行动时间——设置安卓设备

设备配置取决于你的目标操作系统。为此：

1.  如果适用，请在你的操作系统上配置设备驱动：

    +   如果你使用的是 Windows，开发设备的安装是特定于制造商的。更多信息可以在[`developer.android.com/tools/extras/oem-usb.html`](http://developer.android.com/tools/extras/oem-usb.html)找到，那里有设备制造商的完整列表。如果你的 Android 设备附带有驱动 CD，你可以使用它。请注意，Android SDK 也包含一些 Windows 驱动程序，位于`$ANDROID_SDK\extras\google\usb_driver`目录下。针对 Google 开发手机，Nexus One 和 Nexus S 的具体说明可以在[`developer.android.com/sdk/win-usb.html`](http://developer.android.com/sdk/win-usb.html)找到。

    +   如果你使用的是 OS X，只需将你的开发设备连接到你的 Mac 应该就足以让它工作了！你的设备应该会立即被识别，无需安装任何东西。Mac 的易用性并非传说。

    +   如果你是一个 Linux 用户，将你的开发设备连接到你的发行版（至少在 Ubuntu 上）应该就足以让它工作了！

1.  如果你的移动设备运行的是 Android 4.2 或更高版本，从应用程序列表屏幕，进入**设置** | **关于手机**，并在列表末尾多次点击**构建编号**。经过一番努力后，**开发者选项**将神奇地出现在你的应用程序列表屏幕中。

    在 Android 4.1 设备及其早期版本上，**开发者选项**应该默认可见。

1.  仍然在你的设备上，从应用程序列表屏幕，进入**设置** | **开发者选项**，并启用**调试**和**保持唤醒**。

1.  使用数据连接线将你的设备连接到计算机。注意！有些线缆是仅供充电的，不能用于开发！根据你的设备制造商，它可能显示为 USB 磁盘。

    在 Android 4.2.2 设备及其后续版本上，手机屏幕上会出现一个**允许 USB 调试？**的对话框。选择**始终允许从此计算机**以永久允许调试，然后点击**确定**。

1.  打开命令提示符并执行以下操作：

    ```java
    adb devices

    ```

    ![行动时间——设置 Android 设备](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_50.jpg)

    在 Linux 上，如果出现**?????????**而不是你的设备名称（这很可能会发生），那么`adb`没有适当的访问权限。一个可能的解决方案是以 root 权限重启`adb`（风险自负！）：

    ```java
    sudo $ANDROID_SDK/platform-tools/adb kill-server
    sudo $ANDROID_SDK/platform-tools/adb devices

    ```

    另一个找到你的 Vendor ID 和 Product ID 的解决方案可能是必要的。Vendor ID 是每个制造商的固定值，可以在 Android 开发者网站[`developer.android.com/tools/device.html`](http://developer.android.com/tools/device.html)上找到（例如，HTC 是`0bb4`）。设备的产品 ID 可以通过`lsusb`命令的结果找到，我们在其中查找 Vendor ID（例如，这里的 0c87 是 HTC Desire 的产品 ID）：

    ```java
    lsusb | grep 0bb4

    ```

    ![行动时间——设置 Android 设备](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_01_51.jpg)

    然后，使用 root 权限创建一个文件`/etc/udev/rules.d/51-android.rules`，并填入你的 Vendor ID 和 Product ID，然后将文件权限改为 644：

    ```java
    sudo sh -c 'echo SUBSYSTEM==\"usb\", SYSFS{idVendor}==\"<Your Vendor ID>\", ATTRS{idProduct}=\"<Your Product ID>\", GROUP=\"plugdev\", MODE=\"0666\" > /etc/udev/rules.d/52-android.rules'
    sudo chmod 644 /etc/udev/rules.d/52-android.rules

    ```

    最后，重启`udev`服务和`adb`：

    ```java
    sudo service udev restart
    adb kill-server
    adb devices

    ```

1.  启动 Eclipse 并打开**DDMS**透视图（**窗口** | **打开透视图** | **其他...**）。如果正常工作，你的手机应该列在**设备**视图中。

    ### 提示

    Eclipse 是由许多视图组成的，例如包资源管理器视图、调试视图等。通常，它们大多数已经可见，但有时并非如此。在这种情况下，通过主菜单导航到**窗口** | **显示视图** | **其他…**来打开它们。Eclipse 中的视图被组织在**透视图**中，这些透视图存储工作区布局。可以通过转到**窗口** | **打开透视图** | **其他…**来打开它们。请注意，某些上下文菜单可能只在某些透视图可用。

## *刚才发生了什么？*

我们的 Android 设备已切换到开发模式，并通过 Android 调试桥守护进程连接到工作站。第一次从 Eclipse 或命令行调用 ADB 时，它会自动启动。

我们还启用了**保持唤醒**选项，以防止在手机充电或开发时自动关闭屏幕！而且，比任何事情都重要的是，我们发现 HTC 代表的是高技术计算机！玩笑归玩笑，在 Linux 上的连接过程可能会很棘手，尽管现在应该不会遇到太多麻烦。

仍然遇到不情愿的 Android 设备的问题？这可能意味着以下任何一种情况：

+   ADB 出现故障。在这种情况下，重启 ADB 守护进程或以管理员权限执行它。

+   你的开发设备工作不正常。在这种情况下，尝试重启你的设备或禁用并重新启用开发模式。如果仍然不起作用，那么购买另一个设备或使用模拟器。

+   你的主机系统没有正确设置。在这种情况下，仔细检查你的设备制造商的说明，确保必要的驱动程序已正确安装。检查硬件属性，看它是否被识别，并打开 USB 存储模式（如果适用），看它是否被正确检测。请参考你的设备文档。

    ### 提示

    当激活仅充电模式时，SD 卡中的文件和目录对手机上安装的 Android 应用可见，但对电脑不可见。相反，当激活磁盘驱动器模式时，这些文件和目录只对电脑可见。当你的应用无法在 SD 卡上访问其资源文件时，请检查你的连接模式。

## 关于 ADB 的更多信息

ADB 是一个多功能的工具，用作开发环境和设备之间的中介。它包括以下部分：

+   在模拟器和设备上运行的后台进程，用于接收来自工作站的任务或请求。

+   工作站上与连接设备和模拟器通信的后台服务器。列出设备时，会涉及到 ADB 服务器。调试时，会涉及到 ADB 服务器。与设备进行任何通信时，都会涉及到 ADB 服务器！

+   在你的工作站上运行的客户端，通过 ADB 服务器与设备通信。我们与之交互列出设备的 ADB 客户端。

ADB 提供了许多有用的选项，其中一些在以下表格中：

| 命令 | 描述 |
| --- | --- |
| `adb help` | 获取详尽的帮助，包括所有可用的选项和标志 |
| `adb bugreport` | 打印整个设备的状态 |
| `adb devices` | 列出当前连接的所有 Android 设备，包括模拟器 |
| `adb install [-r] <apk path>` | 安装应用程序包。添加`-r`以重新安装已部署的应用程序并保留其数据 |
| `adb kill-server` | 终止 ADB 守护进程 |
| `adb pull <device path> <local path>` | 将文件传输到你的电脑 |
| `adb push <local path> <device path>` | 将文件传输到你的设备或模拟器 |
| `adb reboot` | 以编程方式重启 Android 设备 |
| `adb shell` | 在 Android 设备上启动 shell 会话（更多内容请见第二章，*开始一个本地 Android 项目*) |
| `adb start-server` | 启动 ADB 守护进程 |
| `adb wait-for-device` | 等待直到设备或模拟器连接到你的电脑（例如，在脚本中） |

当同时连接多个设备时，ADB 还提供了可选的标志来定位特定设备：

| `-s <device id>` | 通过设备的名称（可以在 adb devices 中找到）来定位一个特定的设备 |
| --- | --- |
| `-d` | 如果只连接了一个物理设备，则定位当前物理设备（或者会引发错误信息） |
| `-e` | 如果只连接了一个模拟器，则定位当前运行的模拟器（或者会引发错误信息） |

例如，当设备连接时同时转储模拟器状态，执行以下命令：

```java
adb -e bugreport

```

这只是 ADB 功能的概述。更多信息可以在 Android 开发者网站找到，网址是[`developer.android.com/tools/help/adb.html`](http://developer.android.com/tools/help/adb.html)。

# 总结

设置我们的 Android 开发平台可能有些繁琐，但希望这是一劳永逸的！

总之，我们在系统上安装了所有必备的软件包。其中一些是特定于目标操作系统的，例如 Windows 上的 Cygwin，OS X 上的 Developer Tools，或者 Linux 上的 build-essential 软件包。然后，我们安装了包含 Android Studio IDE 和 Android SDK 的 Android Studio 捆绑包。Android NDK 需要单独下载和设置。

即使我们在这本书中不会经常使用它，Android Studio 仍然是纯 Java 开发的最佳选择之一。它由谷歌维护，当 Gradle NDK 的集成更加成熟时，它可能成为一个不错的选择。

同时，最简单的解决方案是使用 Eclipse 进行 NDK 开发。我们安装了带有 ADT 和 CDT 插件的 Eclipse。这些插件能够很好地整合在一起，它们允许将 Android Java 和本地 C/C++ 代码的强大功能结合到一个单一的 IDE 中。

最后，我们启动了一个 Android 模拟器，并通过 Android 调试桥接器将一个 Android 设备连接到我们的开发平台。

### 提示

由于 Android NDK 是“开放的”，任何人都可以构建自己的版本。Crystax NDK 是由 Dmitry Moskalchuk 创建的特殊 NDK 包。它带来了 NDK 不支持的高级功能（最新的工具链、开箱即用的 Boost…最初支持异常的是 CrystaxNDK）。高级用户可以在 Crystax 网站上找到它，网址为[`www.crystax.net/en/android/ndk`](https://www.crystax.net/en/android/ndk)。

现在我们手中有了塑造我们移动想法所需的工具。在下一章中，我们将驯服它们来创建、编译并部署我们的第一个 Android 项目！


# 第二章：开始一个本地 Android 项目

> 拥有最强大工具的人，若不知如何使用，实则手无寸铁。Make、GCC、Ant、Bash、Eclipse……—任何新的 Android 程序员都需要处理这个技术生态系统。幸运的是，其中一些名字可能已经听起来很熟悉。实际上，Android 是基于许多开源组件构建的，由 Android 开发工具包及其特定的工具集：ADB、AAPT、AM、NDK-Build、NDK-GDB...掌握它们将赋予我们创建、构建、部署和调试我们自己的 Android 应用程序的能力。

在下一章深入探讨本地代码之前，让我们通过启动一个新的具体 Android 项目来发现这些工具，该项目包含本地 C/C++代码。尽管 Android Studio 是新的官方 Android IDE，但它对本地代码的支持不足，促使我们主要关注 Eclipse。

因此，在本章中，我们将要：

+   构建一个官方示例应用程序并将其部署在 Android 设备上

+   使用 Eclipse 创建我们的第一个本地 Android 项目

+   使用 Java Native Interfaces 接口将 Java 与 C/C++连接起来

+   调试一个本地 Android 应用程序

+   分析本地崩溃转储

+   使用 Gradle 设置包含本地代码的项目

到本章结束时，你应该知道如何独立开始一个新的本地 Android 项目。

# 构建 NDK 示例应用程序

开始使用新的 Android 开发环境的简单方法之一是编译和部署 Android NDK 提供的示例之一。一个可能的（而且*polygonful*！）选择是 2004 年由 Jetro Lauha 创建的**San Angeles**演示，后来被移植到 OpenGL ES（更多信息请访问[`jet.ro/visuals/4k-intros/san-angeles-observation/`](http://jet.ro/visuals/4k-intros/san-angeles-observation/)）。

# 行动时间 – 编译和部署 San Angeles 示例

让我们使用 Android SDK 和 NDK 工具来构建一个可工作的 APK：

1.  打开命令行提示符，进入 Android NDK 中的 San Angeles 示例目录。所有后续步骤都必须从这个目录执行。

    使用`android`命令生成 San Angeles 项目文件：

    ```java
    cd $ANDROID_NDK/samples/san-angeles
    android update project -p ./
    ```

    ![行动时间 – 编译和部署 San Angeles 示例](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_19.jpg)

    ### 提示

    执行此命令时，你可能会遇到以下错误：

    ```java
    Error: The project either has no target set or the target is invalid.
    Please provide a --target to the 'android update' command.

    ```

    这意味着你可能没有按照第一章，*设置你的环境*中指定的那样安装所有的 Android SDK 平台。在这种情况下，你可以使用`Android 管理工具`安装它们，或者指定你自己的项目目标，例如，`android update project --target 18 -p ./`。

1.  使用`ndk-build`编译 San Angeles 本地库：![行动时间 – 编译和部署 San Angeles 示例](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_20.jpg)

1.  以**调试**模式构建和打包 San Angeles 应用程序：

    ```java
    ant debug

    ```

    ![行动时间 – 编译和部署 San Angeles 示例](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_21.jpg)

1.  确保你的 Android 设备已连接或已启动模拟器。然后部署生成的包：

    ```java
    ant installd

    ```

    ![行动时间 – 编译和部署 San Angeles 示例](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_22.jpg)

1.  在您的设备或模拟器上启动 `SanAngeles` 应用程序：

    ```java
    adb shell am start -a android.intent.action.MAIN -n com.example.SanAngeles/com.example.SanAngeles.DemoActivity

    ```

    ![行动时间 – 编译和部署 San Angeles 示例](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_23.jpg)

    ### 提示

    **下载示例代码**

    您可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 的账户下载您购买的所有 Packt Publishing 书籍的示例代码文件。如果您在别处购买了这本书，可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，我们会直接将文件通过电子邮件发送给您。

## *刚才发生了什么？*

充满平面阴影多边形和怀旧气息的旧式 San Angeles 演示现在正在您的设备上运行。仅通过几行命令，涉及大部分 Android 开发所需的工具，就生成了一个包含原生 C/C++ 代码的完整应用程序，并编译、构建、打包、部署和启动。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_24.jpg)

让我们详细看看这个过程。

## 使用 Android 管理器生成项目文件

我们利用 Android 管理器从现有代码库生成了项目文件。以下关于此过程的详细信息：

+   `build.xml`：这是 Ant 文件，描述了如何编译并打包最终的 APK 应用程序文件（即 *Android PacKage*）。此构建文件主要包含属性和核心 Android Ant 构建文件的链接。

+   `local.properties`：这个文件包含了 Android SDK 的位置。每次 SDK 位置发生变化时，都应该重新生成这个文件。

+   `proguard-project.txt`：这个文件包含了 **Proguard** 的默认配置，Proguard 是用于 Java 代码的代码优化器和混淆器。关于它的更多信息可以在 [`developer.android.com/tools/help/proguard.html`](http://developer.android.com/tools/help/proguard.html) 找到。

+   `project.properties`：这个文件包含了应用程序的目标 Android SDK 版本。此文件默认从 `project` 目录中的预存在 `default.properties` 文件生成。如果没有 `default.properties`，则必须在 `android create` 命令中添加额外的 `–target <API Target>` 标志（例如，`--target 4` 表示 Android 4 Donut）。

### 注意

目标 SDK 版本与最低 SDK 版本不同。第一个版本描述了应用程序构建的最新 Android 版本，而后者表示应用程序允许运行的最低 Android 版本。两者都可以在 `AndroidManifest.xml` 文件（条款 `<uses-sdk>`）中可选声明，但只有目标 SDK 版本在 `project.properties` 中“重复”。

### 提示

当创建 Android 应用程序时，请仔细选择您希望支持的最低和目标 Android API，因为这可能会极大地改变您应用程序的功能以及您的受众范围。实际上，由于碎片化，目标往往在 Android 上移动得更快更多！

不以最新 Android 版本为目标的应用并不意味着它不能在该版本上运行。然而，它将无法使用所有最新的功能以及最新的优化。

Android 管理器是 Android 开发者的主要入口点。其职责与 SDK 版本更新、虚拟设备管理和项目管理相关。通过执行 `android –help` 可以从命令行详尽列出。由于我们在第一章，*设置你的环境*中已经了解了 SDK 和 AVD 管理，现在让我们关注其项目管理能力：

1.  `android create project` 允许从命令行空手起家创建新的 Android 项目。生成的项目只包含 Java 文件，不包含与 NDK 相关的文件。为了正确生成，必须指定一些额外的选项，例如：

    | 选项 | 描述 |
    | --- | --- |
    | `-a` | 主活动名称 |
    | `-k` | 应用程序包 |
    | `-n` | 项目名称 |
    | `-p` | 项目路径 |
    | `-t` | 目标 SDK 版本 |
    | `-g` 和 `-v` | 生成 Gradle 构建文件而不是 Ant，并指定其插件版本 |

    创建新项目的命令行示例如下：

    ```java
    android create project -p ./MyProjectDir -n MyProject -t android-8 -k com.mypackage -a MyActivity

    ```

1.  `android update project` 从现有源代码创建项目文件，如前面的教程所示。然而，如果它们已经存在，它还可以将项目目标升级到新的 SDK 版本（即 `project.properties` 文件）并更新 Android SDK 位置（即 `local.properties` 文件）。可用的标志略有不同：

    | 选项 | 描述 |
    | --- | --- |
    | `-l` | 要添加的库项目 |
    | `-n` | 项目名称 |
    | `-p` | 项目路径 |
    | `-t` | 目标 SDK 版本 |
    | `-s` | 更新子文件夹中的项目 |

    我们还可以使用 `-l` 标志附加新的库项目，例如：

    ```java
    android update project -p ./ -l ../MyLibraryProject

    ```

1.  `android create lib-project` 和 `android update lib-project` 管理库项目。这类项目并不适合原生 C/C++ 开发，尤其是在调试时，因为 NDK 有自己复用原生库的方式。

1.  `android create test-project`、`android update test-project` 和 `android create uitest-project` 管理单元测试和 UI 测试项目。

关于所有这些选项的更多详细信息可以在 Android 开发者网站找到，网址为 [`developer.android.com/tools/help/android.html`](http://developer.android.com/tools/help/android.html)。

## 使用 NDK-Build 编译原生代码

生成项目文件后，我们使用 `ndk-build` 编译第一个原生 C/C++ 库（也称为*模块*）。这个命令是 NDK 开发中最需要了解的基本命令，它实际上是一个 Bash 脚本，可以：

+   基于 GCC 或 CLang 设置 Android 原生编译工具链。

+   包装 `Make` 以控制原生代码构建，借助用户定义的 `Makefiles`：`Android.mk` 和可选的 `Application.mk`。默认情况下，`NDK-`

+   `Build`会在`jni`项目目录中查找，按照惯例本地 C/C++代码通常位于此处。

NDK-Build 从 C/C++源文件（在`obj`目录中）生成中间对象文件，并在`libs`目录中生成最终的二进制库（`.so`）。可以通过以下命令删除与 NDK 相关的构建文件：

```java
ndk-build clean

```

有关 NDK-Build 和 Makefiles 的更多信息，请参阅第九章，*将现有库迁移到 Android*。

## 使用 Ant 构建和打包应用程序

一个 Android 应用程序不仅仅由本地 C/C++代码组成，还包括 Java 代码。因此，我们有：

+   使用`Javac`(Java 编译器)编译位于`src`目录中的 Java 源文件。

+   Dexed 生成的 Java 字节码，即使用 DX 将其转换为 Android Dalvik 或 ART 字节码。实际上，Dalvik 和 ART 虚拟机（关于这些内容将在本章后面介绍）都基于一种特定的字节码运行，这种字节码以优化的格式存储，称为**Dex**。

+   使用 AAPT 打包 Dex 文件、Android 清单、资源（如图片等）以及最终的 APK 文件中的本地库，AAPT 也称为**Android 资源打包工具**。

所有这些操作都可以通过一个 Ant 命令汇总：`ant debug`。结果是在`bin`目录中生成一个调试模式的 APK。其他构建模式也可用（例如，发布模式），可以通过`ant help`列出。如果你想删除与 Java 相关的临时构建文件（例如，`Java .class`文件），只需运行以下命令行：

```java
ant clean

```

## 使用 Ant 部署应用程序包

使用 Ant 通过**ADB**可以部署打包的应用程序。可用的部署选项如下：

+   `ant installd` 用于调试模式

+   `ant installr` 用于发布模式

请注意，如果来自不同来源的同一应用程序的旧 APK 不能被新 APK 覆盖。在这种情况下，首先通过执行以下命令行删除先前的应用程序：

```java
ant uninstall

```

安装和卸载也可以直接通过 ADB 执行，例如：

+   `adb install` <应用程序 APK 的路径>：用于首次安装应用程序（例如，对于我们示例中的`bin/DemoActivity-debug.apk`）。

+   `adb install -r` <应用程序 APK 的路径>：用于重新安装应用程序并保留设备上的数据。

+   `adb uninstall` <应用程序包名>：用于卸载通过应用程序包名标识的应用程序（例如，对于我们示例中的`com.example.SanAngeles`）。

## 使用 ADB Shell 启动应用程序

最后，我们通过**活动管理器**（**AM**）启动了应用程序。用于启动 San Angeles 的 AM 命令参数来自`AndroidManifest.xml`文件：

+   `com.example.SanAngeles` 是应用程序包名（与我们之前展示的卸载应用程序时使用的相同）。

+   `com.example.SanAngeles.DemoActivity`是启动活动的规范类名（即简单类名与其包名相连）。以下是如何使用它们的一个简短示例：

    ```java
    <?xml version="1.0" encoding="utf-8"?>
    <manifest 
          package="com.example.SanAngeles"
          android:versionCode="1"
          android:versionName="1.0">
    ...
            <activity android:name=".DemoActivity"
                      android:label="@string/app_name">
    ```

因为 AM 位于你的设备上，所以需要通过 ADB 来运行。为此，ADB 提供了一个有限的类 Unix shell，它包含一些经典命令，如`ls`、`cd`、`pwd`、`cat`、`chmod`或`ps`以及一些 Android 特有的命令，如下表所示：

| `am` | 活动管理器不仅可以启动活动，还可以杀死活动，广播意图，开始/停止分析器等。 |
| --- | --- |
| `dmesg` | 用于转储内核信息。 |
| `dumpsys` | 用于转储系统状态。 |
| `logcat` | 用于显示设备日志信息。 |
| `run-as <用户 id> <命令>` | 使用`用户 id`权限运行命令。`用户 id`可以是应用程序包名，这可以访问应用程序文件（例如，`run-as com.example.SanAngeles ls`）。 |
| `sqlite3 <db 文件>` | 用于打开 SQLite 数据库（可以与`run-as`结合使用）。 |

ADB 可以通过以下方式之一启动：

+   使用参数中的命令，如步骤 5 中的 AM 所示，在这种情况下，Shell 运行单个命令并立即退出。

+   使用不带参数的`adb shell`命令，你可以将其作为一个经典 Shell 使用（例如，调用`am`和其他任何命令）。

ADB Shell 是一个真正的'*瑞士军刀*'，它允许你在设备上进行高级操作，特别是有了 root 权限。例如，可以观察部署在“沙箱”目录中的应用程序（即`/data/data`目录）或者列出并杀死当前运行中的进程。如果没有手机的 root 权限，可能执行的操作会更有限。更多信息请查看[`developer.android.com/tools/help/adb.html`](http://developer.android.com/tools/help/adb.html)。

### 提示

如果你了解一些关于 Android 生态系统的知识，你可能听说过已 root 的手机和未 root 的手机。**Root**手机意味着获取管理员权限，通常使用破解方法。Root 手机可以用来安装自定义的 ROM 版本（例如优化或修改过的**Cyanogen**）或者执行任何 root 用户能做的（尤其是危险的）操作（例如访问和删除任何文件）。Root 本身并不是非法操作，因为你是在修改自己的设备。然而，并不是所有制造商都欣赏这种做法，这通常会使得保修失效。

## 更多关于 Android 工具的信息

构建 San Angeles 示例应用程序可以让你一窥 Android 工具的能力。然而，在它们略显'原始'的外观背后，还有更多可能性。你可以在 Android 开发者网站找到更多信息，网址是[`developer.android.com/tools/help/index.html`](http://developer.android.com/tools/help/index.html)。

# 创建你的第一个本地 Android 项目

在本章的第一部分，我们了解了如何使用 Android 命令行工具。然而，使用 Notepad 或 VI 进行开发并不吸引人。编程应该是乐趣！为了使之有趣，我们需要我们喜欢的 IDE 来执行无聊或不实用的任务。现在，我们将了解如何使用 Eclipse 创建一个本地 Android 项目。

### 注意

本书提供的项目结果名为`Store_Part1`。

# 动手操作时间——创建一个本地 Android 项目

Eclipse 提供了一个向导来帮助我们设置项目：

1.  启动 Eclipse。在主菜单中，前往**File** | **New** | **Project…**。

1.  然后，在打开的**New project**向导中，选择**Android** | **Android Application Project**并点击**Next**。

1.  在下一个屏幕中，按如下所示输入项目属性并再次点击**Next**：![Time for action – creating a native Android project](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_01.jpg)

1.  点击**Next**两次，保留默认选项，以进入**Create activity**向导屏幕。选择**Blank activity with Fragment**并点击**Next**。

1.  最后，在**Blank Activity**屏幕中，按如下方式输入活动属性：![Time for action – creating a native Android project](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_02.jpg)

1.  点击**Finish**以验证。几秒钟后，向导消失，Eclipse 中会显示项目**Store**。

1.  为项目添加本地 C/C++支持。在**Package Explorer**视图中选择项目**Store**，并从其右键菜单中选择**Android Tools** | **Add Native Support...**。

1.  在打开的**Add Android Native Support**弹出窗口中，将库名称设置为`com_packtpub_store_Store`并点击**Finish**。![Time for action – creating a native Android project](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_03.jpg)

1.  项目目录中创建了`jni`和`obj`目录。第一个目录包含一个 makefile `Android.mk`和一个 C++源文件 `com_packtpub_store_Store.cpp`。

    ### 提示

    添加本地支持后，Eclipse 可能会自动将你的视角切换到 C/C++。因此，如果你的开发环境看起来与平时不同，只需检查 Eclipse 右上角的角度即可。你可以从 Java 或 C/C++的角度无障碍地处理 NDK 项目。

1.  在`src/com/packtpub/store/`目录下创建一个新的 Java 类`Store.java`。从静态代码块中加载`com_packtpub_store_Store`本地库：

    ```java
    package com.packtpub.store;

    public class Store {
     static {
     System.loadLibrary("com_packtpub_store_Store");
     }
    }

    ```

1.  编辑`src/com/packtpub/store/StoreActivity.java`。在活动的`onCreate()`中声明并初始化`Store`的新实例。由于我们不需要它们，可以删除可能由 Eclipse 项目创建向导创建的`onCreateOptionsMenu()`和`onOptionsItemSelected()`方法：

    ```java
    package com.packtpub.store;
    ...
    public class StoreActivity extends Activity {
     private Store mStore = new Store();

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_store);

            if (savedInstanceState == null) {
                getFragmentManager().beginTransaction()
                                    .add(R.id.container,
                                         new PlaceholderFragment())
                                    .commit();
            }
        }

        public static class PlaceholderFragment extends Fragment {
            public PlaceholderFragment() {
            }

            @Override
            public View onCreateView(LayoutInflater inflater,
                                     ViewGroup container,
                                     Bundle savedInstanceState)
            {
                View rootView = inflater.inflate(R.layout.fragment_store,
                                                 container, false);
                return rootView;
            }
        }
    }
    ```

1.  连接你的设备或模拟器并启动应用程序。在**Package Explorer**视图中选择`Store`，然后从 Eclipse 主菜单导航至**Run** | **Run As** | **Android Application**。或者，点击 Eclipse 工具栏中的**Run**按钮。

1.  选择应用程序类型 **Android Application** 并点击 **OK**，进入以下界面：![行动时间——创建原生 Android 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_04.jpg)

## *刚才发生了什么？*

在几个步骤中，我们的第一个原生 Android 项目已经通过 Eclipse 创建并启动了。

1.  Android 项目创建向导可以帮助你快速入门。它生成了一个简单 Android 应用程序所需的最小代码。然而，默认情况下，新的 Android 项目只支持 Java 语言。

1.  借助 ADT，一个 Android Java 项目可以轻松地转变为支持原生 C/C++ 的混合项目。它生成了 NDK-Build 编译原生库所需的最小文件：

    `Android.mk` 是一个 Makefile，描述了要编译哪些源文件以及如何生成最终的原生库。

    `com_packtpub_store_Store.cpp` 是一个几乎为空的文件，包含了一个单一的包含指令。我们将在本章的下一部分解释这一点。

1.  项目设置完成后，动态加载原生库只需调用一次 `System.loadLibrary()`。这很容易在一个静态块中完成，确保在类初始化之前一次性加载库。请注意，这只有在容器类是从单个 Java 类加载器加载时才有效（通常情况下是这样的）。

使用像 Eclipse 这样的 IDE 真的可以大幅提高生产效率，让编程变得更加舒适！但如果你是一个命令行爱好者，或者想要锻炼你的命令行技能，那么第一部分，*构建 NDK 示例应用程序*，可以很容易地应用在这里。

### 介绍 Dalvik 和 ART。

说到 Android，不得不提一下 **Dalvik** 和 **ART**。

Dalvik 是一个 **虚拟机**，在其中解释 Dex 字节码（不是原生代码！）。它是任何在 Android 上运行的应用程序的核心。Dalvik 被设计为符合移动设备的限制性要求。它特别优化以使用更少的内存和 CPU。它位于 Android 内核之上，内核为硬件提供了第一层抽象（进程管理、内存管理等）。

ART 是新的 Android 运行时环境，自 Android 5 Lollipop 起取代了 Dalvik。与 Dalvik 相比，它大大提高了性能。实际上，Dalvik 在应用程序启动时 `即时` 解释字节码，而 ART 则是在应用程序安装期间 `提前` 将字节码预编译成原生代码。ART 与为早期 Dalvik 虚拟机打包的应用程序向后兼容。

Android 在设计时考虑了速度。因为大多数用户不希望在等待应用程序加载的同时，其他应用程序仍在运行，因此系统能够快速实例化多个 Dalvik 或 ART VM，这要归功于**Zygote**进程。Zygote（其名称来自生物体中第一个生物细胞，从中产生子细胞）在系统启动时开始运行。它预加载（或“预热”）所有应用程序共享的核心库以及虚拟机实例。要启动新应用程序，只需分叉 Zygote，初始 Dalvik 实例因此被复制。通过尽可能多地共享进程之间的库，降低内存消耗。

Dalvik 和 ART 本身是由为目标 Android 平台（ARM、X86 等）编译的原生 C/C++代码构成的。这意味着，只要使用相同的**应用程序二进制接口**（**ABI**）（它基本上描述了应用程序或库的二进制格式），就可以轻松地将这些虚拟机与原生 C/C++库进行接口交互。这就是 Android NDK 的作用。更多信息，请查看**Android 开源项目**（**AOSP**），即 Android 源代码，在[`source.android.com/`](https://source.android.com/)。

# Java 与 C/C++接口

原生 C/C++代码能够释放应用程序的强大功能。为此，Java 代码需要调用并运行其原生对应部分。在本部分，我们将把 Java 和原生 C/C++代码接口在一起。

### 注意

本书提供的项目名为`Store_Part2`。

# 行动时间 - 从 Java 调用 C 代码

让我们创建第一个原生方法，并从 Java 端调用它：

1.  打开`src/com/packtpub/store/Store.java`文件，并为`Store`声明一个查询原生方法。此方法返回`int`类型的条目数量。无需定义方法体：

    ```java
    package com.packtpub.store;

    public class Store {
        static {
            System.loadLibrary("com_packtpub_store_Store");
        }

     public native int getCount();
    }
    ```

1.  打开`src/com/packtpub/store/StoreActivity.java`文件，并初始化商店。使用其`getCount()`方法的值来初始化应用程序标题：

    ```java
    public class StoreActivity extends Activity {
        ...
        public static class PlaceholderFragment extends Fragment {
     private Store mStore = new Store();
         ...
            public PlaceholderFragment() {
            }

            @Override
            public View onCreateView(LayoutInflater inflater,
                                     ViewGroup container,
                                     Bundle savedInstanceState)
            {
                View rootView = inflater.inflate(R.layout.fragment_store,
                                                 container, false);
     updateTitle();
                return rootView;
            }

     private void updateTitle() {
     int numEntries = mStore.getCount();
     getActivity().setTitle(String.format("Store (%1$s)",
     numEntries));
            }
        }
    }
    ```

1.  从`Store`类生成 JNI 头文件。转到 Eclipse 主菜单，选择**运行** | **外部工具** | **外部工具配置…**。使用以下参数创建一个新的**程序**配置，如下截图所示：![行动时间 - 从 Java 调用 C 代码](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_05.jpg)

    **位置**指的是`javah`的绝对路径，这是特定于操作系统的。在 Windows 上，你可以输入`${env_var:JAVA_HOME}\bin\javah.exe`。在 Mac OS X 和 Linux 上，通常是`/usr/bin/javah`。

1.  在**刷新**标签中，勾选**完成后刷新资源**，并选择**特定资源**。使用**指定资源…**按钮，选择`jni`文件夹。最后，点击**运行**以执行`javah`。然后会生成一个名为`jni/com_packtpub_store_Store.h`的新文件。这包含了 Java 端期望的原生方法`getCount()`的原型：

    ```java
    /* DO NOT EDIT THIS FILE - it is machine generated */
    #include <jni.h>
    /* Header for class com_packtpub_store_Store */

    #ifndef _Included_com_packtpub_store_Store
    #define _Included_com_packtpub_store_Store
    #ifdef __cplusplus
    extern "C" {
    #endif
    /*
     * Class:     com_packtpub_store_Store
     * Method:    getCount
     * Signature: ()I
     */
    JNIEXPORT jint JNICALL Java_com_packtpub_store_Store_getCount
      (JNIEnv *, jobject);

    #ifdef __cplusplus
    }
    #endif
    #endif
    ```

1.  我们现在可以实现在`jni/com_packtpub_store_Store.cpp`中的方法，使其在调用时返回`0`。方法签名来自生成的头文件（你可以替换之前的任何代码），不过这里明确指定了参数名称：

    ```java
    #include "com_packtpub_store_Store.h"

    JNIEXPORT jint JNICALL Java_com_packtpub_store_Store_getCount
      (JNIEnv* pEnv, jobject pObject) {
        return 0;
    }
    ```

1.  编译并运行应用程序。

## *刚才发生了什么？*

Java 现在可以与 C/C++对话了！在上一部分，我们创建了一个混合 Android 项目。在这一部分，我们通过 Java 本地接口（JNI）将 Java 与本地代码接口。这种合作是通过**Java Native Interfaces**（**JNI**）建立的。JNI 是连接 Java 与 C/C++的桥梁。这个过程主要分为三个步骤。

在 Java 端定义本地方法原型，使用 native 关键字标记。这些方法没有方法体，就像抽象方法一样，因为它们是在本地端实现的。本地方法可以有参数、返回值、可见性（私有、保护、包保护或公共），并且可以是静态的：就像普通的 Java 方法一样。

本地方法可以在 Java 代码的任何地方被调用，前提是在调用之前已经加载了包含本地库。如果未能做到这一点，将会抛出类型为`java.lang.UnsatisfiedLinkError`的异常，这个异常是在首次调用本地方法时产生的。

使用`javah`生成一个带有相应本地 C/C++原型的头文件。尽管这不是强制的，但 JDK 提供的`javah`工具对于生成本地原型非常有用。实际上，JNI 约定既繁琐又容易出错（关于这一点在第三章，*使用 JNI 接口 Java 和 C/C++*中有更多介绍）。JNI 代码是从`.class`文件生成的，这意味着你的 Java 代码必须首先被编译。

编写本地 C/C++代码实现以执行预期操作。在这里，当查询`Store`库时，我们简单地返回`0`。我们的本地库在`libs/armeabi`目录（针对 ARM 处理器的目录）中编译，并命名为`libcom_packtpub_store_Store.so`。编译过程中生成的临时文件位于`obj/local`目录中。

尽管表面看起来很简单，但将 Java 与 C/C++接口比看上去要复杂得多。在第三章，*使用 JNI 接口 Java 和 C/C++*中，将更详细地探讨如何在本地端编写 JNI 代码。

# 调试本地 Android 应用程序

在深入探讨 JNI 之前，还有一个任何 Android 开发者都需要知道如何使用的最后一个重要工具：**调试器**。官方 NDK 提供的调试器是 GNU 调试器，也称为**GDB**。

### 注意

本书提供的项目名为`Store_Part3`。

# 动手实践——调试一个本地 Android 应用程序

1.  创建文件`jni/Application.mk`，内容如下：

    ```java
    APP_PLATFORM := android-14
    APP_ABI := armeabi armeabi-v7a x86
    ```

    ### 提示

    这些并不是 NDK 提供的唯一 ABI；还有更多的处理器架构，如 MIPS 或变体如 64 位或硬浮点。这里使用的这些是你应该关注的主要架构。它们可以轻松地在模拟器上进行测试。

1.  打开**项目属性**，进入**C/C++构建**，取消勾选**使用默认构建命令**并输入`ndk-build NDK_DEBUG=1`:![行动时间——调试本地 Android 应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_06.jpg)

1.  在`jni/com_packtpub_store_Store.cpp`中，通过在 Eclipse 编辑器边栏双击，在`Java_com_packtpub_store_Store_getCount()`方法内部设置一个断点。

1.  在**包浏览器**或**项目浏览器**视图中选择`Store`项目，并选择**调试为** | **Android 本地应用程序**。应用程序开始运行，但可能会发现什么也没有发生。实际上，在 GDB 调试器能够附加到应用程序进程之前，很可能会达到断点。

1.  离开应用程序，并从你的设备应用菜单重新打开它。这次，Eclipse 会在本地断点处停止。查看你的设备屏幕，UI 应该已经冻结，因为主应用程序线程在本地代码中暂停了。![行动时间——调试本地 Android 应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_08.jpg)

1.  在**变量**视图中检查变量，并在**调试**视图中查看调用堆栈。在**表达式**视图中输入`*pEnv.functions`并打开结果表达式，以查看`JNIEnv`对象提供的各种函数。

1.  通过 Eclipse 工具栏或快捷键*F6*来**单步跳过**当前指令（也可以使用快捷键*F7*进行**单步进入**）。以下指令将被高亮：

    +   通过 Eclipse 工具栏或快捷键*F8*来**恢复**执行。应用程序界面将再次显示在你的设备上。

    +   通过 Eclipse 工具栏或快捷键*Ctrl*+*F2*来**终止**应用程序。应用程序被杀死，**调试**视图会被清空。

## *刚才发生了什么？*

这个有用的生产力工具——调试器，现在是我们工具箱中的资产。我们可以轻松地在任何点停止或恢复程序执行，单步进入、跳过或离开本地指令，并检查任何变量。这种能力得益于 NDK-GDB，它是命令行调试器 GDB（手动使用可能比较麻烦）的包装脚本。幸运的是，GDB 得到了 Eclipse CDT 的支持，进而也得到了 Eclipse ADT 的支持。

在 Android 系统上，以及更普遍的嵌入式设备上，GDB 被配置为客户端/服务器模式，而程序作为服务器在设备上运行（`gdbserver`，它是由 NDK-Build 在`libs`目录中生成的）。远程客户端，即开发者的工作站上的 Eclipse，连接并发送远程调试命令。

## 定义 NDK 全应用设置

为了帮助 NDK-Build 和 NDK-GDB 完成它们的工作，我们创建了一个新的`Application.mk`文件。这个文件应被视为一个全局 Makefile，定义了应用程序范围的编译设置，例如以下内容：

+   `APP_PLATFORM`：应用程序针对的 Android API。这个信息应该是`AndroidManifest.xml`文件中`minSdkVersion`的重复。

+   `APP_ABI`：应用程序针对的 CPU 架构。应用程序二进制接口指定了可执行文件和库二进制文件的二进制代码格式（指令集、调用约定等）。ABIs 因此与处理器密切相关。可以通过额外的设置，如`LOCAL_ARM_CODE`来调整 ABI。

当前 Android NDK 支持的主要 ABI 如下表所示：

| **armeabi** | 这是默认选项，应该与所有 ARM 设备兼容。Thumb 是一种特殊的指令集，它将指令编码为 16 位而不是 32 位，以提高代码大小（对于内存受限的设备很有用）。与 ArmEABI 相比，指令集受到严重限制。 |
| --- | --- |
| **armeabi**（当`LOCAL_ARM_CODE = arm`时） | （或 ARM v5）应该能在所有 ARM 设备上运行。指令编码为 32 位，但可能比 Thumb 代码更简洁。ARM v5 不支持浮点加速等高级扩展，因此比 ARM v7 慢。 |
| **armeabi-v7a** | 支持如 Thumb-2（类似于 Thumb，但增加了额外的 32 位指令）和 VFP 等扩展，以及一些可选扩展，如 NEON。为 ARM V7 编译的代码不能在 ARM V5 处理器上运行。 |
| **armeabi-v7a-hard** | 这个 ABI 是 armeabi-v7a 的扩展，它支持硬件浮点而不是软浮点。 |
| **arm64-v8a** | 这是专为新的 64 位处理器架构设计的。64 位 ARM 处理器向后兼容旧的 ABI。 |
| **x86 和 x86_64** | 针对类似“PC”的处理器架构（即 Intel/AMD）。这些是在模拟器上使用的 ABI，以便在 PC 上获得硬件加速。尽管大多数 Android 设备是 ARM，但其中一些现在基于 X86。x86 ABI 用于 32 位处理器，而 x86_64 用于 64 位处理器。 |
| **mips 和 mips64** | 针对由 MIPS Technologies 制造的处理器设计，现在属于 Imagination Technologies，后者以 PowerVR 图形处理器而闻名。在撰写本书时，几乎没有设备使用这些 ABI。mips ABI 用于 32 位处理器，而 mips64 用于 64 位处理器。 |
| **all, all32 和 all64** | 这是一个快捷方式，用于为所有 32 位或 64 位 ABI 构建 ndk 库。 |

每个库和中间对象文件都会针对每个 ABI 重新编译。它们存储在各自独立的目录中，可以在`obj`和`libs`文件夹中找到。

在`Application.mk`内部还可以使用更多的标志。我们将在第九章《*将现有库移植到 Android*》中详细了解这一点。

`Application.mk`标志并不是确保 NDK 调试器工作的唯一设置；还需要手动传递`NDK_DEBUG=1`给 NDK-Build，这样它才能编译调试二进制文件并正确生成 GDB 设置文件（`gdb.setup`和`gdbserver`）。请注意，这应该更多地被视为 Android 开发工具的缺陷，而不是一个真正的配置步骤，因为通常它应该能自动处理调试标志。

## NDK-GDB 的日常使用

NDK 和 Eclipse 中的调试器支持是近期才出现的，并且在 NDK 的不同版本之间有了很大的改进（例如，之前无法调试纯本地线程）。然而，尽管现在调试器已经相当可用，但在 Android 上进行调试有时可能会出现错误、不稳定，并且相对较慢（因为它需要与远程的 Android 设备进行通信）。

### 提示

NDK-GDB 有时可能会出现疯狂的现象，在一个完全不正常的堆栈跟踪处停止在断点。这可能与 GDB 在调试时无法正确确定当前的 ABI 有关。要解决这个问题，只需在`APP_ABI`子句中放入对应设备的 ABI，并移除或注释掉其他的。

NDK 调试器在使用上也可能有些棘手，例如在调试本地启动代码时。实际上，GDB 启动不够快，无法激活断点。克服这个问题的简单方法是让本地代码在应用程序启动时暂停几秒钟。为了给 GDB 足够的时间来附加应用程序进程，我们可以例如这样做：

```java
#include <unistd.h>
…
sleep(3); // in seconds.
```

另一个解决方案是启动一个调试会话，然后简单地离开并从设备上重新启动应用程序，正如我们在之前的教程中看到的那样。这是可行的，因为 Android 应用程序的生命周期是这样的：当应用程序在后台时，它会保持存活，直到需要内存。不过，这个技巧只适用于应用程序在启动过程中没有崩溃的情况。

# 分析本地崩溃转储

每个开发人员都有过一天在他们的应用程序中遇到意外的崩溃。不要为此感到羞愧，我们所有人都经历过。作为 Android 本地开发的新手，这种情况还会发生很多次。调试器是查找代码问题的巨大工具。遗憾的是，它们在程序运行时的“实时”工作。面对难以复现的致命错误时，它们变得无效。幸运的是，有一个工具可以解决这个问题：**NDK-Stack**。NDK-Stack 可以帮助你读取崩溃转储，以分析应用程序在崩溃那一刻的堆栈跟踪。

### 注意

本书提供的示例项目名为`Store_Crash`。

# 动手时间——分析一个本地崩溃转储

让我们的应用程序崩溃，看看如何读取崩溃转储：

1.  在`jni/com_packtpub_store_Store.cpp`中模拟一个致命错误：

    ```java
    #include "com_packtpub_store_Store.h"

    JNIEXPORT jint JNICALL Java_com_packtpub_store_Store_getCount
      (JNIEnv* pEnv, jobject pObject) {
     pEnv = 0;
     return pEnv->CallIntMethod(0, 0);
    }
    ```

1.  在 Eclipse 中打开 **LogCat** 视图，选择 **所有消息（无筛选）** 选项，然后运行应用程序。日志中出现了崩溃转储。这看起来不美观！如果你仔细查看，应该能在其中找到带有应用程序崩溃时刻调用栈快照的 `backtrace` 部分。然而，它没有给出涉及的代码行：![行动时间 – 分析原生崩溃转储](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_07.jpg)

1.  从命令行提示符进入项目目录。通过使用 `logcat` 作为输入运行 NDK-Stack，找到导致崩溃的代码行。NDK-Stack 需要对应于应用程序崩溃的设备 ABI 的 `obj` 文件，例如：

    ```java
    cd <projet directory>
    adb logcat | ndk-stack -sym obj/local/armeabi-v7a

    ```

    ![行动时间 – 分析原生崩溃转储](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_09.jpg)

## *刚才发生了什么？*

Android NDK 提供的 NDK-Stack 工具可以帮助你定位应用程序崩溃的源头。这个工具是不可或缺的帮助，当发生严重的崩溃时，应被视为你的急救包。然而，如果它能指出*在哪里*，那么找出*为什么*就是另一回事了。

**堆栈跟踪**只是崩溃转储的一小部分。解读转储的其余部分很少是必要的，但理解其含义对提高一般文化素养有帮助。

## 解读崩溃转储

崩溃转储不仅是为了那些在二进制代码中看到穿红衣服女孩的过于有才华的开发者，也是为了那些对汇编器和处理器工作方式有基本了解的人。这个跟踪的目标是尽可能多地提供程序在崩溃时的当前状态信息。它包含：

+   第一行：**构建指纹**是一种标识符，表示当前运行的设备/Android 版本。在分析来自不同来源的转储时，这些信息很有趣。

+   第三行：**PID** 或进程标识符在 Unix 系统上唯一标识一个应用程序，以及 **TID**，即线程标识符。当在主线程上发生崩溃时，线程标识符可能与进程标识符相同。

+   第四行：表示为 **信号** 的崩溃源头是一个经典的段错误（**SIGSEGV**）。

+   **处理器寄存器**的值。寄存器保存处理器可以立即操作的值或指针。

+   **回溯**（即堆栈跟踪）与方法调用，这些调用导致了崩溃。

+   **原始堆栈**与回溯类似，但包含了堆栈参数和变量。

+   围绕主要寄存器的一些**内存字**（仅针对 ARM 处理器提供）。第一列指示内存行的位置，而其他列指示以十六进制表示的内存值。

处理器寄存器在不同处理器架构和版本之间是不同的。ARM 处理器提供：

| **rX** | **整数寄存器**，程序在这里放置它要处理的值。 |
| --- | --- |
| **dX** | **浮点寄存器**，程序在这里放置它要处理的值。 |
| **fp（或 r11）** | **帧指针**在过程调用期间保存当前堆栈帧的位置（与堆栈指针配合使用）。 |
| **ip（或 r12）** | **过程内调用暂存寄存器**可能用于某些子程序调用；例如，当链接器需要一个薄层（一小段代码）以在分支时指向不同的内存区域时。实际上，跳转到内存中其他位置的分支指令需要一个相对于当前位置的偏移量参数，这使得分支范围只有几 MB，而不是整个内存。 |
| **sp（或 r13）** | **堆栈指针**保存堆栈顶部的位置。 |
| **lr（或 r14）** | **链接寄存器**临时保存程序计数器值，以便稍后恢复。其使用的一个典型例子是函数调用，它跳转到代码中的某个位置，然后返回到其先前的位置。当然，多个链式子程序调用需要将链接寄存器入栈。 |
| **pc（或 r15）** | **程序计数器**保存着将要执行的下一个指令的地址。程序计数器在执行顺序代码时只是递增以获取下一个指令，但它会被分支指令（如 if/else，C/C++函数调用等）改变。 |
| **cpsr** | **当前程序状态寄存器**包含有关当前处理器工作模式的一些标志和额外的位标志，用于条件码（如操作结果为负值的 N，结果为 0 或相等的 Z 等），中断和指令集（拇指或 ARM）。 |

### 提示

请记住，寄存器的主要使用是一种约定。例如，苹果 iOS 在 ARMS 上使用`r7`作为帧指针，而不是`r12`。因此，在编写或重用汇编代码时一定要非常小心！

另一方面，X86 处理器提供：

| **eax** | **累加器寄存器**用于例如算术或 I/O 操作。 |
| --- | --- |
| **ebx** | **基址寄存器**是用于内存访问的数据指针。 |
| **ecx** | **计数器寄存器**用于迭代操作，如循环计数器。 |
| **edx** | **数据寄存器**是配合`eax`使用的次要累加寄存器。 |
| **esi** | **源索引寄存器**与`edi`配合使用，用于内存数组的复制。 |
| **edi** | **目的索引寄存器**与`esi`配合使用，用于内存数组的复制。 |
| **eip** | **指令指针**保存下一个指令的偏移量。 |
| **ebp** | **基指针**在过程调用期间保存当前堆栈帧的位置（与堆栈指针配合使用）。 |
| **esp** | **堆栈指针**保存堆栈顶部的位置。 |
| **xcs** | **代码段**帮助寻址程序运行的内存段。 |
| **xds** | **数据段**帮助寻址数据内存段。 |
| **xes** | **额外段**是用于寻址内存段的附加寄存器。 |
| **xfs** | **附加段**，这是一个通用数据段。 |
| **xss** | **堆栈段**保存堆栈内存段。 |

### 提示

许多 X86 寄存器是**遗留**的，这意味着它们失去了创建时的初衷。对它们的描述要持谨慎态度。

解读堆栈跟踪不是一件容易的事，它需要时间和专业知识。如果你还无法理解它的每一部分，不必过于烦恼。这只在万不得已的情况下才需要。

# 设置 Gradle 项目以编译原生代码

Android Studio 现在是官方支持的 Android IDE，取代了 Eclipse。它带有**Gradle**，这是新的官方 Android 构建系统。Gradle 引入了一种基于 Groovy 的特定语言，以便轻松定义项目配置。尽管其对 NDK 的支持还初步，但它不断改进，变得越来越可用。

现在让我们看看如何使用 Gradle 创建一个编译原生代码的 Android Studio 项目。

### 注意

本书提供的项目名为`Store_Gradle_Auto`。

# 行动时间 – 创建原生 Android 项目

通过 Android Studio 可以轻松创建基于 Gradle 的项目：

1.  启动 Android Studio。在欢迎屏幕上，选择**新建项目…**（如果已经打开了一个项目，则选择**文件** | **新建项目…**）。

1.  在**新建项目**向导中，输入以下配置并点击**下一步**：![行动时间 – 创建原生 Android 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_51.jpg)

1.  然后，选择最小的 SDK（例如，API 14：冰激凌三明治），并点击**下一步**。

1.  选择**带片段的空白活动**并点击**下一步**。

1.  最后，按照以下方式输入**活动名称**和**布局名称**，然后点击**完成**：![行动时间 – 创建原生 Android 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_52.jpg)

1.  然后，Android Studio 应该会打开项目：![行动时间 – 创建原生 Android 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/1529_02_55.jpg)

1.  修改`StoreActivity.java`文件，并按照本章中*Java 与 C/C++接口*部分（步骤 1 和 2）创建`Store.java`。

1.  创建`app/src/main/jni`目录。复制本章*Java 与 C/C++接口*部分（步骤 4 和 5）中创建的 C 和头文件。

1.  编辑 Android Studio 生成的`app/build.gradle`文件。在`defaultConfig`中插入一个`ndk`部分来配置模块（即库）名称：

    ```java
    apply plugin: 'com.android.application'

    android {
        compileSdkVersion 21
        buildToolsVersion "21.1.2"

        defaultConfig {
            applicationId "com.packtpub.store"
            minSdkVersion 14
            targetSdkVersion 21
            versionCode 1
            versionName "1.0"
     ndk {
     moduleName "com_packtpub_store_Store"
            }
        }
        buildTypes {
            release {
                minifyEnabled false
                proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
            }
        }
    }

    dependencies {
        compile fileTree(dir: 'libs', include: ['*.jar'])
        compile 'com.android.support:appcompat-v7:21.0.3'
    }
    ```

1.  通过点击 Android Studio 中**Gradle 任务**视图下的**installDebug**，编译并在你的设备上安装项目。

    ### 提示

    如果 Android Studio 抱怨找不到 NDK，请确保项目根目录中的`local.properties`文件包含可以指向你的 Android SDK 和 NDK 位置的`sdk.dir`和`ndk.dir`属性。

## *刚才发生了什么？*

我们创建了一个通过 Gradle 编译本地代码的第一个 Android Studio 项目。NDK 属性在 `build.gradle` 文件（例如，模块名称）的特定于 `ndk` 的部分配置。

下表展示了多个可用的设置：

| 属性 | 描述 |
| --- | --- |
| **abiFilter** | 要编译的目标 ABI 列表；默认情况下，编译所有 ABI。 |
| **cFlags** | 传递给编译器的自定义标志。关于这方面的更多信息，请参见第九章，*将现有库移植到 Android*。 |
| **ldLibs** | 传递给链接器的自定义标志。关于这方面的更多信息，请参见第九章，*将现有库移植到 Android*。 |
| **moduleName** | 这是将要构建的模块名称。 |
| **stl** | 这是用于编译的 STL 库。关于这方面的更多信息，请参见第九章，*将现有库移植到 Android*。 |

你可能已经注意到，我们没有重用 `Android.mk` 和 `Application.mk` 文件。这是因为如果在编译时给 `ndk-build` 提供了输入，Gradle 会自动生成构建文件。在我们的示例中，你可以在 `app/build/intermediates/ndk/debug` 目录下看到为 `Store` 模块生成的 `Android.mk` 文件。

NDK 自动 Makefile 生成使得在简单项目上编译本地 NDK 代码变得容易。但是，如果你想要在本地构建上获得更多控制，你可以创建自己的 Makefiles，就像本章中在“Java 与 C/C++接口”部分创建的那样。让我们看看如何操作。

### 注意

本书提供的项目名为 `Store_Gradle_Manual`。

# 动手时间 – 使用你自己的 Makefiles 与 Gradle

使用你手工制作的 Makefiles 与 Gradle 有点棘手，但并不复杂：

1.  将本章中在“Java 与 C/C++接口”部分创建的 `Android.mk` 和 `Application.mk` 文件复制到 `app/src/main/jni` 目录。

1.  编辑 `app/build.gradle` 文件。

1.  添加对 `OS` “类”的导入，并删除前一个部分中我们创建的第一个 `ndk` 部分：

    ```java
    import org.apache.tools.ant.taskdefs.condition.Os

    apply plugin: 'com.android.application'

    android {
        compileSdkVersion 21
        buildToolsVersion "21.1.2"

        defaultConfig {
            applicationId "com.packtpub.store"
            minSdkVersion 14
            targetSdkVersion 21
            versionCode 1
            versionName "1.0"
        }
        buildTypes {
            release {
                minifyEnabled false
                proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
            }
        }
    ```

1.  仍然在 `app/build.gradle` 文件的 android 部分，插入一个包含以下内容的 `sourceSets.main` 部分： 

    +   `jniLibs.srcDir`，定义了 Gradle 将找到生成的库的位置。

    +   `jni.srcDirs`，设置为空数组以通过 Gradle 禁用本地代码编译。

        ```java
            ...
            sourceSets.main {
                jniLibs.srcDir 'src/main/libs'
                jni.srcDirs = []
            }
        ```

1.  最后，创建一个新的 Gradle 任务 `ndkBuild`，它将手动触发 `ndk-build` 命令，指定自定义目录 `src/main` 作为编译目录。

    声明 `ndkBuild` 任务与 Java 编译任务之间的依赖关系，以自动触发本地代码编译：

    ```java
        ...

     task ndkBuild(type: Exec) {
     if (Os.isFamily(Os.FAMILY_WINDOWS)) {
     commandLine 'ndk-build.cmd', '-C', file('src/main').absolutePath
     } else {
     commandLine 'ndk-build', '-C', file('src/main').absolutePath
     }
     }

     tasks.withType(JavaCompile) {
     compileTask -> compileTask.dependsOn ndkBuild
     }
    }

    dependencies {
        compile fileTree(dir: 'libs', include: ['*.jar'])
        compile 'com.android.support:appcompat-v7:21.0.3'
    }
    ```

1.  通过点击 Android Studio 中的 **installDebug** 在 **Gradle 任务** 视图下编译并安装项目到你的设备上。

## *刚才发生了什么？*

Android Gradle 插件进行的 Makefile 生成和原生源代码编译可以轻松禁用。诀窍是简单地指出没有可用的原生源代码目录。然后我们可以利用 Gradle 的强大功能，它允许轻松定义自定义构建任务及其之间的依赖关系，以执行`ndk-build`命令。这个技巧允许我们使用自己的 NDK makefiles，从而在构建原生代码时给我们提供更大的灵活性。

# 总结

创建、编译、构建、打包和部署应用程序项目可能不是最激动人心的任务，但它们是无法避免的。掌握它们将使您能够提高效率并专注于真正的目标：**编写代码**。

综上所述，我们使用命令行工具构建了第一个示例应用程序，并将其部署在 Android 设备上。我们还使用 Eclipse 创建了第一个原生 Android 项目，并通过 Java 本地接口（JNI）将 Java 与 C/C++进行接口。我们使用 NDK-GDB 调试了原生 Android 应用程序，并分析了原生崩溃转储以在源代码中找到其根源。最后，我们使用 Android Studio 创建了类似的项目，并使用 Gradle 构建它。

这首次使用 Android NDK 的实验使您对原生开发的工作方式有了很好的了解。在下一章中，我们将专注于代码，并深入探讨 JNI 协议。


# 第三章：用 JNI 实现 Java 与 C/C++的接口

> \*Android 与 Java 密不可分。其内核和核心库是原生的，但 Android 应用框架几乎完全是用 Java 编写的，或者至少在 Java 的薄层中包装。不要期望直接在 C/C++中构建你的 Android GUI！大多数 API 只能从 Java 访问。最多，我们可以将其隐藏在封面下... 因此，如果无法将 Java 和 C/C++连接在一起，Android 上的原生 C/C++代码将毫无意义。\
> 
> \*这个角色是专门为 Java Native Interface API 准备的。JNI 是一个标准化规范，允许 Java 调用原生代码，原生代码也可以回调 Java。它是 Java 和原生代码之间的双向桥梁；将 C/C++的强大功能注入你的 Java 应用程序的唯一方式。\
> 
> \*得益于 JNI，人们可以像调用任何 Java 方法一样从 Java 调用 C/C++函数，将 Java 原始类型或对象作为参数传递，并将它们作为原生调用的结果接收。反之，原生代码可以通过类似反射的 API 访问、检查、修改 Java 对象或抛出异常。JNI 是一个需要小心使用的微妙框架，任何误用都可能导致灾难性的结局…\

在本章中，我们将实现一个基本的关键/值存储来处理各种数据类型。一个简单的 Java GUI 将允许定义一个由键（字符串）、类型（整数、字符串等）和与选定类型相关的值组成的*条目*。条目在固定大小的条目数组中检索、插入或更新（不支持删除），该数组将驻留在原生侧。

为了实现这个项目，我们将要：

+   初始化一个原生的 JNI 库

+   在原生代码中转换 Java 字符串

+   将 Java 原始数据传递给原生代码

+   在原生代码中处理 Java 对象引用

+   在原生代码中管理 Java 数组

+   在原生代码中引发和检查 Java 异常。

在本章结束时，你应该能够使用任何 Java 类型进行原生调用并使用异常。

JNI 是一个非常技术性的框架，需要小心使用，因为任何误用都可能导致灾难性的结局。本章并不试图详尽无遗地介绍它，而是专注于桥接 Java 和 C++之间差距的基本知识。

# 初始化一个原生的 JNI 库

在访问它们的原生方法之前，必须通过 Java 调用`System.loadLibrary()`来加载原生库。JNI 提供了一个钩子`JNI_OnLoad()`，以便插入你自己的初始化代码。让我们重写它以初始化我们的原生存储。

### 注意

本书提供了名为`Store_Part4`的项目作为结果。

# 动手实践——定义一个简单的 GUI

让我们为我们的`Store`创建一个 Java 图形用户界面，并将其绑定到我们将要创建的原生存储结构：

1.  重写`res/fragment_layout.xml`布局以定义如下图形界面。它定义了：

    +   一个**键** `TextView`标签和`EditText`以输入键

    +   一个**值** `TextView`标签和`EditText`以输入与键匹配的值

    +   一个**类型** `TextView` 标签和 `Spinner` 以定义值的类型

    +   一个**获取值**和一个**设置值**的 `Button` 以在存储中检索和更改值

        ```java
        <LinearLayout 

          a:layout_width="match_parent" a:layout_height="match_parent"
          a:orientation="vertical"
        tools:context="com.packtpub.store.StoreActivity$PlaceholderFragment">
          <TextView
            a:layout_width="match_parent" a:layout_height="wrap_content"
            a:text="Save or retrieve a value from the store:" />
          <TableLayout
            a:layout_width="match_parent" a:layout_height="wrap_content"
            a:stretchColumns="1" >
            <TableRow>
              <TextView a:id="@+id/uiKeyLabel" a:text="Key : " />
              <EditText a:id="@+id/uiKeyEdit" ><requestFocus /></EditText>
            </TableRow>
            <TableRow>
              <TextView a:id="@+id/uiValueLabel" a:text="Value : " />
              <EditText a:id="@+id/uiValueEdit" />
            </TableRow>
            <TableRow>
              <TextView a:id="@+id/uiTypeLabel" a:layout_height="match_parent"
                        a:gravity="center_vertical" a:text="Type : " />
              <Spinner a:id="@+id/uiTypeSpinner" />
            </TableRow>
          </TableLayout>
          <LinearLayout
            a:layout_width="wrap_content" a:layout_height="wrap_content"
            a:layout_gravity="right" >
            <Button a:id="@+id/uiGetValueButton" a:layout_width="wrap_content"
                    a:layout_height="wrap_content" a:text="Get Value" />
            <Button a:id="@+id/uiSetValueButton" a:layout_width="wrap_content"
                    a:layout_height="wrap_content" a:text="Set Value" />
          </LinearLayout>
        </LinearLayout>
        ```

    最终结果应如下所示：

    ![动手操作——定义一个简单的 GUI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_03_02.jpg)

1.  在 `StoreType.java` 中创建一个新的类，带有一个空的枚举：

    ```java
    package com.packtpub.store;

    public enum StoreType {
    }
    ```

1.  GUI 和本地存储需要绑定在一起。这是由 `StoreActivity` 类承担的角色。为此，当在 `onCreateView()` 中创建 `PlaceholderFragment` 时，初始化布局文件中先前定义的所有 GUI 组件：

    ```java
    public class StoreActivity extends Activity {
        ...
        public static class PlaceholderFragment extends Fragment {
            private Store mStore = new Store();
     private EditText mUIKeyEdit, mUIValueEdit;
     private Spinner mUITypeSpinner;
            private Button mUIGetButton, mUISetButton;
            private Pattern mKeyPattern;

            ...

            @Override
            public View onCreateView(LayoutInflater inflater,
                                     ViewGroup container,
                                     Bundle savedInstanceState)
            {
                View rootView = inflater.inflate(R.layout.fragment_store,
                                                 container, false);
                updateTitle();

     // Initializes text components.
     mKeyPattern = Pattern.compile("\\p{Alnum}+");
     mUIKeyEdit = (EditText) rootView.findViewById(
     R.id.uiKeyEdit);
     mUIValueEdit = (EditText) rootView.findViewById(
     R.id.uiValueEdit);

    ```

1.  `Spinner` 内容绑定到 `StoreType` 枚举。使用 `ArrayAdapter` 将 `Spinner` 和 `enum` 值绑定在一起。

    ```java
                ...
     ArrayAdapter<StoreType> adapter =
     new ArrayAdapter<StoreType>(getActivity(),
     android.R.layout.simple_spinner_item,
     StoreType.values());
     adapter.setDropDownViewResource(
     android.R.layout.simple_spinner_dropdown_item);
     mUITypeSpinner = (Spinner) rootView.findViewById(
     R.id.uiTypeSpinner);
     mUITypeSpinner.setAdapter(adapter);
                    ...
    ```

1.  **获取值**和**设置值**按钮触发私有方法 `onGetValue()` 和 `onSetValue()`，它们分别从存储中拉取数据和向存储推送数据。使用 `OnClickListener` 将按钮和方法绑定在一起：

    ```java
                ...
     mUIGetButton = (Button) rootView.findViewById(
     R.id.uiGetValueButton);
     mUIGetButton.setOnClickListener(new OnClickListener() {
     public void onClick(View pView) {
     onGetValue();
     }
     });
     mUISetButton = (Button) rootView.findViewById(
     R.id.uiSetValueButton);
     mUISetButton.setOnClickListener(new OnClickListener() {
     public void onClick(View pView) {
     onSetValue();
     }
     });
                return rootView;
            }
            ...
    ```

1.  在 `PlaceholderFragment` 中，定义 `onGetValue()` 方法，该方法将根据 GUI 中选择的 `StoreType` 从存储中检索条目。现在先让 switch 语句为空，因为它暂时不会处理任何类型的条目：

    ```java
            ...
            private void onGetValue() {
                // Retrieves key and type entered by the user.
                String key = mUIKeyEdit.getText().toString();
                StoreType type = (StoreType) mUITypeSpinner
                                                       .getSelectedItem();
                // Checks key is correct.
                if (!mKeyPattern.matcher(key).matches()) {
                    displayMessage("Incorrect key.");
                    return;
                }

                // Retrieves value from the store and displays it.
                // Each data type has its own access method.
                switch (type) {
                    // Will retrieve entries soon...
                }
            }
            ...
    ```

1.  然后，在 `PlaceholderFragment` 中，定义 `StoreActivity` 的 `onSetValue()` 方法，以在存储中插入或更新条目。如果值格式不正确，将显示一条消息：

    ```java
            ...
            private void onSetValue() {
                // Retrieves key and type entered by the user.
                String key = mUIKeyEdit.getText().toString();
                String value = mUIValueEdit.getText().toString();
                StoreType type = (StoreType) mUITypeSpinner
                                                       .getSelectedItem();
                // Checks key is correct.
                if (!mKeyPattern.matcher(key).matches()) {
                    displayMessage("Incorrect key.");
                    return;
                }

                // Parses user entered value and saves it in the store.
                // Each data type has its own access method.
                try {
                    switch (type) {
                        // Will put entries soon...
                    }
                } catch (Exception eException) {
                    displayMessage("Incorrect value.");
                }
                updateTitle();
            }
            ...
    ```

1.  最后，`PlaceholderFragment` 中的一个小助手方法 `displayMessage()` 将帮助在出现问题时警告用户。它显示一个简单的 Android Toast 消息：

    ```java
            ...
            private void displayMessage(String pMessage) {
                Toast.makeText(getActivity(), pMessage, Toast.LENGTH_LONG)
                     .show();
            }
        }
    }
    ```

## *刚才发生了什么？*

我们使用 Android 框架的几个视觉组件在 Java 中创建了一个基本的图形用户界面。如您所见，这里没有 NDK 的特定内容。故事的核心是本地代码可以与任何现有的 Java 代码集成。

显然，我们还需要做些工作，让我们的本地代码为 Java 应用程序执行一些有用的操作。现在让我们切换到本地端。

# 动手操作时间——初始化本地存储

我们需要创建并初始化我们将在本章下一部分使用的所有结构：

1.  创建 `jni/Store.h` 文件，该文件定义了存储数据结构：

    +   `StoreType` 枚举将反映相应的 Java 枚举。现在先让它为空。

    +   `StoreValue` 联合体将包含可能的存储值中的任何一个。现在也先让它为空。

    +   `StoreEntry` 结构包含存储中的一条数据。它由一个键（由 `char*` 制作的原始 C 字符串）、一个类型（`StoreType`）和一个值（`StoreValue`）组成。

        ### 注意

        请注意，我们将在第九章，*将现有库移植到 Android*中了解如何设置和使用 C++ STL 字符串。

    +   `Store` 是一个主要结构，定义了一个固定大小的条目数组和长度（即已分配的条目数）：

        ```java
        #ifndef _STORE_H_
        #define _STORE_H_

        #include <cstdint>

        #define STORE_MAX_CAPACITY 16

        typedef enum {
        } StoreType;

        typedef union {
        } StoreValue;

        typedef struct {
            char* mKey;
            StoreType mType;
            StoreValue mValue;
        } StoreEntry;

        typedef struct {
            StoreEntry mEntries[STORE_MAX_CAPACITY];
            int32_t mLength;
        } Store;
        #endif
        ```

        ### 提示

        包含保护（即`#ifndef`, `#define`, 和 `#endif`），它们确保头文件在编译期间只被包含一次，可以用非标准（但广泛支持的）预处理器指令`#pragma once`来替换。

1.  在`jni/com_packtpub_Store.cpp`中，实现`JNI_OnLoad()`初始化钩子。在内部，将`Store`数据结构的唯一实例初始化为一个静态变量：

    ```java
    #include "com_packtpub_store_Store.h"
    #include "Store.h"

    static Store gStore;

    JNIEXPORT jint JNI_OnLoad(JavaVM* pVM, void* reserved) {
     // Store initialization.
     gStore.mLength = 0;
     return JNI_VERSION_1_6;
    }
    ...
    ```

1.  相应地更新本地`store getCount()`方法，以反映分配给商店的条目数量：

    ```java
    ...
    JNIEXPORT jint JNICALL Java_com_packtpub_store_Store_getCount
      (JNIEnv* pEnv, jobject pObject) {
     return gStore.mLength;
    }
    ```

## *刚才发生了什么？*

我们用简单的 GUI 和本地内存中的数据数组构建了商店项目的基石。包含的本地库可以通过以下调用加载：

+   `System.load()`，它接收库的全路径作为参数。

+   `System.loadLibrary()`，它只需要库名称，不需要路径、前缀（即`lib`）或扩展名。

本地代码初始化在`JNI_OnLoad()`钩子中发生，该钩子在本地代码的生命周期内只被调用一次。这是初始化和缓存全局变量的完美位置。JNI 元素（类、方法、字段等）也经常在`JNI_OnLoad()`中被缓存，以提高性能。我们将在本章和下一章中了解更多相关信息。

请注意，在 Android 中，由于无法保证在进程终止之前卸载库，因此在 JNI 规范中定义的挂起调用`JNI_OnUnload()`几乎是没用的。

`JNI_OnLoad()`签名被系统地定义如下：

```java
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved);
```

使得`JNI_OnLoad()`如此有用的原因是它的`JavaVM`参数。通过它，你可以按照以下方式检索**JNIEnv 接口指针**：

```java
JNIEXPORT jint JNI_OnLoad(JavaVM* pVM, void* reserved) {
 JNIEnv *env;
 if (pVM->GetEnv((void**) &env, JNI_VERSION_1_6) != JNI_OK) {
 abort();
    }
    ...
    return JNI_VERSION_1_6;
}
```

### 提示

在 JNI 库中的`JNI_OnLoad()`定义是可选的。但是，如果省略它，你可能会在启动应用程序时在**Logcat**中看到警告**No JNI_OnLoad found in <mylib>.so**。这绝对没有后果，可以安全地忽略。

`JNIEnv`是所有 JNI 调用的主要入口点，这就是为什么它会被传递给所有本地方法的原因。它提供了一系列方法，以便从本地代码访问 Java 原始类型和数组。它还通过类似反射的 API，使本地代码能够完全访问 Java 对象。我们将在本章和下一章中更详细地了解其特性。

### 提示

`JNIEnv`接口指针是线程特定的。你绝对不能在线程之间共享它！只能在获取它的线程上使用它。只有 JavaVM 元素是线程安全的，可以在线程之间共享。

# 在本地代码中转换 Java 字符串

我们将处理的第一种条目是字符串。字符串在 Java 中作为（几乎）经典的对象表示，可以通过 JNI 在本地端操作并转换为本地字符串，即原始字符数组。尽管字符串由于其异构表示的复杂性而显得复杂，但它们是一等公民。

在这一部分，我们将把 Java 字符串发送到原生端，并将其转换为对应的原生字符串。我们还会将它们重新转换回 Java 字符串。

### 注意

本书提供了名为`Store_Part5`的项目，其中包含此结果。

# 行动时间——处理原生存储中的字符串

让我们处理存储中的字符串值：

1.  打开`StoreType.java`并在枚举中指定我们存储处理的新字符串类型：

    ```java
    public enum StoreType {
     String
    }
    Open Store.java and define the new functionalities our native key/value store provides (for now, only strings):
    public class Store {
        ...
        public native int getCount();

     public native String getString(String pKey);
     public native void setString(String pKey, String pString);
    }
    ```

1.  在`StoreActivity.java`中，在`onGetValue()`方法中从原生`Store`获取字符串条目。根据当前在 GUI 中选定的`StoreType`类型进行操作（尽管目前只有一个可能的类型）：

    ```java
    public class StoreActivity extends Activity {
        ...
        public static class PlaceholderFragment extends Fragment {
            ...
            private void onGetValue() {
                ...
                switch (type) {
     case String:
     mUIValueEdit.setText(mStore.getString(key));
     break;
                }
            }
            ...
    ```

1.  在`onSetValue()`方法中插入或更新存储中的字符串条目：

    ```java
            ...
            private void onSetValue() {
                ...
                try {
                    switch (type) {
     case String:
     mStore.setString(key, value);
     break;
                    }
                } catch (Exception eException) {
                    displayMessage("Incorrect value.");
                }
                updateTitle();
            }
            ...
        }
    }
    ```

1.  在`jni/Store.h`中，包含一个新的`header jni.h`以访问 JNI API。

    ```java
    #ifndef _STORE_H_
    #define _STORE_H_

    #include <cstdint>
    #include "jni.h"
    ...
    ```

1.  接下来，将字符串集成到原生的`StoreType`枚举和`StoreValue`联合体中：

    ```java
    ...
    typedef enum {
     StoreType_String
    } StoreType;

    typedef union {
     char*     mString;
    } StoreValue;
    ...
    ```

1.  通过声明用于检查、创建、查找和销毁条目的实用方法来结束。`JNIEnv`和`jstring`是在`jni.h`头文件中定义的 JNI 类型：

    ```java
    ...
    bool isEntryValid(JNIEnv* pEnv, StoreEntry* pEntry, StoreType pType);

    StoreEntry* allocateEntry(JNIEnv* pEnv, Store* pStore, jstring pKey);

    StoreEntry* findEntry(JNIEnv* pEnv, Store* pStore, jstring pKey);

    void releaseEntryValue(JNIEnv* pEnv, StoreEntry* pEntry);
    #endif
    ```

1.  创建一个新文件`jni/Store.cpp`以实现所有这些实用方法。首先，`isEntryValid()`仅检查条目是否已分配并具有预期的类型：

    ```java
    #include "Store.h"
    #include <cstdlib>
    #include <cstring>

    bool isEntryValid(JNIEnv* pEnv, StoreEntry* pEntry, StoreType pType) {
        return ((pEntry != NULL) && (pEntry->mType == pType));
    }
    ...
    ```

1.  `findEntry()`方法通过将传入的参数与存储中的每个键进行比较，直到找到匹配项。它不使用传统的原生字符串（即`char*`），而是接收一个`jstring`参数，这是在原生端对 Java `String`的直接表示。

1.  要从 Java `String`中恢复原生字符串，请使用 JNI API 中的`GetStringUTFChars()`获取一个临时字符缓冲区，其中包含转换后的 Java 字符串。然后可以使用标准的 C 语言例程操作其内容。`GetStringUTFChars()`必须与`ReleaseStringUTFChars()`的调用配对，以释放在`GetStringUTFChars()`中分配的临时缓冲区：

    ### 提示

    Java 字符串在内存中以 UTF-16 字符串的形式存储。当在原生代码中提取其内容时，返回的缓冲区以修改后的 UTF-8 编码。修改后的 UTF-8 与标准 C 字符串函数兼容，后者通常在由 8 位每个字符组成的字符串缓冲区上工作。

    ```java
    ...
    StoreEntry* findEntry(JNIEnv* pEnv, Store* pStore, jstring pKey) {
        StoreEntry* entry = pStore->mEntries;
        StoreEntry* entryEnd = entry + pStore->mLength;

        // Compare requested key with every entry key currently stored
        // until we find a matching one.
        const char* tmpKey = pEnv->GetStringUTFChars(pKey, NULL);
        while ((entry < entryEnd) && (strcmp(entry->mKey, tmpKey) != 0)) {
            ++entry;
        }
        pEnv->ReleaseStringUTFChars(pKey, tmpKey);

        return (entry == entryEnd) ? NULL : entry;
    }
    ...
    ```

    ### 提示

    JNI 不会原谅任何错误。例如，如果你在`GetStringUTFChars()`中将`NULL`作为第一个参数传递，虚拟机将立即终止。此外，Android JNI 并不完全遵守 JNI 规范。尽管 JNI 规范指出，如果无法分配内存，`GetStringUTFChars()`可能会返回`NULL`，但在这种情况下，Android VM 会直接终止。

1.  实现`allocateEntry()`，该方法要么创建一个新的条目（即增加存储长度并返回最后一个元素），要么如果键已存在则释放其先前值后返回现有条目。

    如果条目是新的，请将其键转换为可以在内存中保留的原生字符串。实际上，原始 JNI 对象在其方法调用的持续时间内存在，并且不能在其作用域之外保留：

    ```java
    ...
    StoreEntry* allocateEntry(JNIEnv* pEnv, Store* pStore, jstring pKey) {
        // If entry already exists in the store, releases its content
        // and keep its key.
        StoreEntry* entry = findEntry(pEnv, pStore, pKey);
        if (entry != NULL) {
            releaseEntryValue(pEnv, entry);
        }
        // If entry does not exist, create a new entry
        // right after the entries already stored.
        else {
            entry = pStore->mEntries + pStore->mLength;

            // Copies the new key into its final C string buffer.
            const char* tmpKey = pEnv->GetStringUTFChars(pKey, NULL);
            entry->mKey = new char[strlen(tmpKey) + 1];
            strcpy(entry->mKey, tmpKey);
            pEnv->ReleaseStringUTFChars(pKey, tmpKey);

            ++pStore->mLength;
        }
        return entry;
    }
    ...
    ```

1.  编写最后一个方法`releaseEntryValue()`，该方法在需要时释放为值分配的内存：

    ```java
    ...
    void releaseEntryValue(JNIEnv* pEnv, StoreEntry* pEntry) {
        switch (pEntry->mType) {
        case StoreType_String:
            delete pEntry->mValue.mString;
            break;
        }
    }
    ```

1.  使用上一章中看到的`javah`刷新 JNI 头文件`jni/com_packtpub_Store.h`。你应在其中看到两个新方法`Java_com_packtpub_store_Store_getString()`和`Java_com_packtpub_store_Store_setString()`。

1.  在`jni/com_packtpub_Store.cpp`中，插入`cstdlib`头文件：

    ```java
    #include "com_packtpub_store_Store.h"
    #include <cstdlib>
    #include "Store.h"
    ...
    ```

1.  借助之前生成的 JNI 头文件，实现原生方法`getString()`。此方法在存储区中查找传递的键并返回其对应的字符串值。如果出现任何问题，将返回默认的`NULL`值。

1.  Java 字符串并非真正的原始数据类型。我们之前已经看到，类型`jstring`和`char*`不能互换使用。要从原生字符串创建 Java `String`对象，请使用 JNI API 中的`NewStringUTF()`：

    ```java
    ...
    JNIEXPORT jstring JNICALL Java_com_packtpub_store_Store_getString
      (JNIEnv* pEnv, jobject pThis, jstring pKey) {
        StoreEntry* entry = findEntry(pEnv, &gStore, pKey);
        if (isEntryValid(pEnv, entry, StoreType_String)) {
            // Converts a C string into a Java String.
            return pEnv->NewStringUTF(entry->mValue.mString);
        } else {
            return NULL;
        }
    }
    ...
    ```

1.  然后，实现`setString()`方法，该方法分配一个条目（即，在存储区中创建一个新的条目，如果存在具有相同键的条目则重用），并将转换后的 Java 字符串值存储在其中。

1.  字符串值使用 JNI API 的`GetStringUTFLength()`和`GetStringUTFRegion()`方法直接从 Java 字符串翻译到我们自己的字符串缓冲区。这是之前使用的`GetStringUTFChars()`的替代方法。最后，我们一定不要忘记添加`null`字符，这是原始 C 字符串的标准：

    ```java
    ...
    JNIEXPORT void JNICALL Java_com_packtpub_store_Store_setString
      (JNIEnv* pEnv, jobject pThis, jstring pKey, jstring pString) {
        // Turns the Java string into a temporary C string.
        StoreEntry* entry = allocateEntry(pEnv, &gStore, pKey);
        if (entry != NULL) {
            entry->mType = StoreType_String;
            // Copy the temporary C string into its dynamically allocated
            // final location. Then releases the temporary string.
            jsize stringLength = pEnv->GetStringUTFLength(pString);
            entry->mValue.mString = new char[stringLength + 1];
            // Directly copies the Java String into our new C buffer.
            pEnv->GetStringUTFRegion(pString, 0, stringLength,
                                     entry->mValue.mString);
            // Append the null character for string termination.
            entry->mValue.mString[stringLength] = '\0';    }
    }
    ```

1.  最后，更新`Android.mk`文件以编译`Store.cpp`：

    ```java
    LOCAL_PATH := $(call my-dir)

    include $(CLEAR_VARS)

    LOCAL_MODULE    := com_packtpub_store_Store
    LOCAL_SRC_FILES := com_packtpub_store_Store.cpp Store.cpp

    include $(BUILD_SHARED_LIBRARY)
    ```

## *刚才发生了什么？*

运行应用程序。尝试使用不同的键和值保存几个条目。然后尝试从原生存储区获取它们。我们已经实现了在 Java 和 C/C++之间传递和检索字符串。这些值作为原生字符串保存在原生内存中。然后可以根据其键从存储区将条目作为 Java 字符串检索。

Java 和 C 字符串是完全不同的。Java 字符串需要一个具体的转换，以原生字符串的形式允许使用标准的 C 字符串例程处理它们的内容。实际上，`jstring`不是经典的`char*`数组的表示，而是对 Java `String`对象的引用，只能从 Java 代码中访问。

在这一部分中，我们发现了两种将 Java 字符串转换为原生字符串的方法：

+   通过预先分配一个内存缓冲区，将转换后的 Java 字符串复制到其中。

+   通过在由 JNI 管理的内存缓冲区中检索转换后的 Java 字符串。

选择哪种解决方案取决于客户端代码如何处理内存。

## 原生字符编码

JNI 提供了两种处理字符串的方法：

+   名称中包含 UTF 且处理修改后的 UTF-8 字符串的那些方法

+   名称中不包含 UTF 且处理 UTF-16 编码的那些方法

修改后的 UTF-8 和 UTF-16 字符串是两种不同的字符编码：

+   **修改后的 UTF-8**是 Java 特有的轻微变体的 UTF-8。这种编码可以表示标准 ASCII 字符（每个字符一个字节）或者可以扩展到 4 个字节来表示扩展字符（阿拉伯语、西里尔语、希腊语、希伯来语等）。标准 UTF-8 和修改后的 UTF-8 之间的区别在于对`null`字符的不同表示，后者根本不存在这个字符。这样，这些字符串可以用标准的 C 例程处理，而 C 例程使用`null`字符作为结束标志。

+   **UTF-16**是真正用于 Java 字符串的编码。每个字符用两个字节表示，因此 Java `char`的大小如此。因此，在本地代码中使用 UTF-16 而不是修改后的 UTF-8 更有效率，因为它们不需要转换。缺点是，经典的 C 字符串例程无法处理它们，因为它们不是以`null`结尾的。

字符编码是一个复杂的主题，你可以访问[`www.oracle.com/technetwork/articles/javase/supplementary-142654.html`](http://www.oracle.com/technetwork/articles/javase/supplementary-142654.html)和[`developer.android.com/training/articles/perf-jni.html#UTF_8_and_UTF_16_strings`](http://developer.android.com/training/articles/perf-jni.html#UTF_8_and_UTF_16_strings)的 Android 文档获取更多信息。

## JNI 字符串 API

JNI 提供了几种方法来处理本地端的 Java 字符串：

+   `GetStringUTFLength()`计算修改后的 UTF-8 字符串的长度（以字节为单位，因为 UTF-8 字符串的字符大小不同），而`GetStringLength()`计算 UTF-16 字符串的字符数（不是字节，因为 UTF-16 字符的大小是固定的）：

    ```java
    jsize GetStringUTFLength(jstring string)
    jsize GetStringLength(jstring string)
    ```

+   `GetStringUTFChars()`和`GetStringChars()`通过 JNI 分配一个新的内存缓冲区，用于存储 Java 到本地（分别是修改后的 UTF-8 和 UTF-16）字符串转换的结果。当你想转换整个字符串而不想处理内存分配时，请使用它。最后一个参数`isCopy`，如果不为`null`，表示字符串是否被 JNI 内部复制，或者返回的缓冲区是否指向实际的 Java 字符串内存。在 Android 中，对于`GetStringUTFChars()`返回的`isCopy`值通常是`JNI_TRUE`，对于`GetStringChars()`则是`JNI_FALSE`（后者确实不需要编码转换）：

    ```java
    const char* GetStringUTFChars(jstring string, jboolean* isCopy)
    const jchar* GetStringChars(jstring string, jboolean* isCopy)
    ```

    ### 提示

    尽管 JNI 规范指出`GetStringUTFChars()`可能返回 NULL（这意味着操作可能因为例如无法分配内存而失败），但实际上，这种检查是没有用的，因为 Dalvik 或 ART VM 在这种情况下通常会终止。所以，尽量避免进入这种情况！如果你的代码旨在移植到其他 Java 虚拟机上，你仍然应该保留 NULL 检查。

+   `ReleaseStringUTFChars()`和`ReleaseStringChars()`方法用于释放`GetStringUTFChars()`和`GetStringChars()`分配的内存缓冲区，当客户端处理完毕后。这些方法必须始终成对调用：

    ```java
    void ReleaseStringUTFChars(jstring string, const char* utf)
    void ReleaseStringChars(jstring string, const jchar* chars)
    ```

+   `GetStringUTFRegion()`和`GetStringRegion()`获取 Java 字符串的全部或部分区域。它作用于由客户端代码提供和管理的字符串缓冲区。当您想要管理内存分配（例如，重用现有的内存缓冲区）或需要访问字符串的小部分时使用它：

    ```java
    void GetStringRegion(jstring str, jsize start, jsize len, jchar* buf)
    void GetStringUTFRegion(jstring str, jsize start, jsize len, char* buf)
    ```

+   `GetStringCritical()`和`ReleaseStringCritical()`与`GetStringChars()`和`ReleaseStringChars()`类似，但仅适用于 UTF-16 字符串。根据 JNI 规范，`GetStringCritical()`更有可能返回一个直接指针，而不进行任何复制。作为交换，调用者不得执行阻塞操作或 JNI 调用，并且不应长时间持有字符串（就像线程中的临界区）。实际上，Android 似乎不管你是否使用关键功能都表现相似（但这可能会改变）：

    ```java
    const jchar* GetStringCritical(jstring string, jboolean* isCopy)
    void ReleaseStringCritical(jstring string, const jchar* carray)
    ```

这是您需要了解的通过 JNI 处理 Java 字符串的基本知识。

# 将 Java 基本类型传递给本地代码

我们可以使用 JNI 处理的最简单的元素是 Java 基本类型。实际上，Java 端和本地端几乎使用相同的数据表示，这种数据不需要任何特定的内存管理。

在这一部分，我们将了解如何将整数传递到本地端，并将它们发送回 Java 端。

### 注意

本书提供的项目名为`Store_Part6`。

# 动手实践时间——在本地存储中处理基本类型。

1.  在`StoreType.java`中，将新管理的整数类型添加到枚举中：

    ```java
    public enum StoreType {
        Integer,
        String
    }
    ```

1.  打开`Store.java`文件，定义我们的本地存储提供的新整数功能：

    ```java
    public class Store {
        ...
        public native int getCount();

     public native int getInteger(String pKey);
     public native void setInteger(String pKey, int pInt);

        public native String getString(String pKey);
        public native void setString(String pKey, String pString);
    }
    ```

1.  在`StoreActivity`类中，更新`onGetValue()`方法，以便在 GUI 中选择整数条目时从存储中检索它们：

    ```java
    public class StoreActivity extends Activity {
        ...
        public static class PlaceholderFragment extends Fragment {
            ...
            private void onGetValue() {
                ...
                switch (type) {
     case Integer:
     mUIValueEdit.setText(Integer.toString(mStore
     .getInteger(key)));
     break;
                case String:
                    mUIValueEdit.setText(mStore.getString(key));
                    break;
                }
            }
            ...
    ```

1.  同时，在`onSetValue()`方法中插入或更新存储中的整数条目。在将条目数据传递到本地端之前，需要对其进行解析：

    ```java
            ...
            private void onSetValue() {
                ...
                try {
                    switch (type) {
     case Integer:
     mStore.setInteger(key, Integer.parseInt(value));
     break;
                    case String:
                        mStore.setString(key, value);
                        break;
                    }
                } catch (Exception eException) {
                    displayMessage("Incorrect value.");
                }
                updateTitle();
            }
            ...
        }
    }
    ```

1.  在`jni/Store.h`文件中，向本地`StoreType`枚举和`StoreValue`联合体中添加整数类型：

    ```java
    ...
    typedef enum {
     StoreType_Integer,
        StoreType_String
    } StoreType;
    typedef union {
     int32_t   mInteger;
        char*     mString;
    } StoreValue;
    ...
    ```

1.  使用`javah`刷新 JNI 头文件`jni/com_packtpub_Store.h`。应该出现两个新方法`Java_com_packtpub_store_Store_getInteger()`和`Java_com_packtpub_store_Store_setInteger()`。

1.  在`jni/com_packtpub_Store.cpp`文件中，借助生成的 JNI 头文件实现`getInteger()`方法。该方法仅返回条目的整数值，除了从`int32_t`隐式转换为`jint`外，不进行任何特定的转换。如果在检索过程中出现任何问题，将返回默认值：

    ```java
    ...
    JNIEXPORT jint JNICALL Java_com_packtpub_store_Store_getInteger
      (JNIEnv* pEnv, jobject pThis, jstring pKey) {
        StoreEntry* entry = findEntry(pEnv, &gStore, pKey);
        if (isEntryValid(pEnv, entry, StoreType_Integer)) {
            return entry->mValue.mInteger;
        } else {
            return 0;
        }
    }
    ...
    ```

1.  第二个方法`setInteger()`将给定的整数值存储在分配的条目中。注意，传递的 JNI 整数同样可以反向转换为 C/C++整数：

    ```java
    ...
    JNIEXPORT void JNICALL Java_com_packtpub_store_Store_setInteger
      (JNIEnv* pEnv, jobject pThis, jstring pKey, jint pInteger) {
        StoreEntry* entry = allocateEntry(pEnv, &gStore, pKey);
        if (entry != NULL) {
            entry->mType = StoreType_Integer;
            entry->mValue.mInteger = pInteger;
        }
    }
    ```

## *刚才发生了什么？*

运行应用程序。尝试使用不同的键、类型和值保存几个条目。然后尝试从本地存储中获取它们。这次我们已经实现了从 Java 到 C/C++ 传递和检索整数原始数据。

在本地调用期间，整数原始数据有多种形式；首先，Java 代码中的 `int`，然后是从/到 Java 代码传输期间的 `jint`，最后是本地代码中的 `int` 或 `int32_t`。显然，如果我们愿意，可以保留本地代码中的 JNI 表示形式 `jint`，因为所有这些类型实际上是等价的。换句话说，`jint` 只是一个别名。

### 提示

`int32_t` 类型是由 C99 标准库通过 `typedef` 引入的，旨在提高可移植性。与标准 `int` 类型的区别在于，它的字节大小对所有编译器和平台都是固定的。更多的数字类型在 `stdint.h`（在 C 中）或 `cstdint`（在 C++ 中）中定义。

所有原始类型在 JNI 中都有其适当的别名：

| Java 类型 | JNI 类型 | C 类型 | Stdint C 类型 |
| --- | --- | --- | --- |
| `boolean` | `Jboolean` | `unsigned char` | `uint8_t` |
| `byte` | `Jbyte` | `signed char` | `int8_t` |
| `char` | `Jchar` | `unsigned short` | `uint16_t` |
| `double` | `Jdouble` | `double` | `N/A` |
| `float` | `jfloat` | `float` | `N/A` |
| `int` | `jint` | `Int` | `int32_t` |
| `long` | `jlong` | `long long` | `int64_t` |
| `short` | `jshort` | `Short` | `int16_t` |

你可以完全像在这一部分中使用整数一样使用它们。关于 JNI 中原始类型更多信息可以在 [`docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html`](http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html) 找到

## 动手英雄——传递和返回其他原始类型

当前存储只处理整数和字符串。基于此模型，尝试为其他原始类型实现存储方法：`boolean`、`byte`、`char`、`double`、`float`、`long` 和 `short`。

### 注意

最终项目与此书一同提供，名称为 `Store_Part6_Full`。

# 从本地代码引用 Java 对象

如前一部分所述，我们知道在 JNI 中字符串由 `jstring` 表示，实际上它是一个 Java 对象，这意味着可以通过 JNI 交换任何 Java 对象！然而，由于本地代码不能直接理解或访问 Java，所有 Java 对象都有相同的表示形式，即 `jobject`。

在这一部分，我们将重点介绍如何在本地端保存对象以及如何将其发送回 Java。作为一个例子，我们将使用自定义对象 `Color`，尽管任何其他类型的对象也可以。

### 注意

最终项目与此书一同提供，名称为 `Store_Part7`。

# 动手时间——在本地存储中保存对象引用

1.  创建一个新的 Java 类 `com.packtpub.store.Color`，封装一个表示颜色的整数值。这个整数是通过 `android.graphics.Color` 类从包含 HTML 代码的 `String`（例如，`#FF0000`）解析得到的。

    ```java
    package com.packtpub.store;
    import android.text.TextUtils;
    public class Color {
        private int mColor;
        public Color(String pColor) {
            if (TextUtils.isEmpty(pColor)) {
                throw new IllegalArgumentException();
            }
            mColor = android.graphics.Color.parseColor(pColor);
        }
        @Override
        public String toString() {
            return String.format("#%06X", mColor);
        }
    }
    ```

1.  在 `StoreType.java` 中，将新的 Color 数据类型添加到枚举中：

    ```java
    public enum StoreType {
        Integer,
        String,
     Color
    }
    ```

1.  在 `Store` 类中，添加两个新的本地方法以获取和保存 `Color` 对象：

    ```java
    public class Store {
        ...
     public native Color getColor(String pKey);
     public native void setColor(String pKey, Color pColor);
    }
    ```

1.  打开 `StoreActivity.java` 文件，并更新方法 `onGetValue()` 和 `onSetValue()` 以解析和显示 `Color` 实例：

    ```java
    public class StoreActivity extends Activity {
        ...
        public static class PlaceholderFragment extends Fragment {
            ...
            private void onGetValue() {
                ...
                switch (type) {
                ...
     case Color:
     mUIValueEdit.setText(mStore.getColor(key)
                                    .toString());
     break;
                }
            }
            private void onSetValue() {
                ...
                try {
                    switch (type) {
                    ...
     case Color:
     mStore.setColor(key, new Color(value));
     break;
                    }
                } catch (Exception eException) {
                    displayMessage("Incorrect value.");
                }
                updateTitle();
            }
            ...
        }
    }
    ```

1.  在 `jni/Store.h` 中，将新的颜色类型添加到 `StoreType` 枚举中，并在 `StoreValue` 联合体中添加一个新成员。但是你应该使用什么类型呢？`Color` 是只在 Java 中已知的对象。在 JNI 中，所有 Java 对象都有相同的类型；`jobject`，一个（间接）对象引用：

    ```java
    ...
    typedef enum {
        ...
        StoreType_String,
     StoreType_Color
    } StoreType;
    typedef union {
        ...
        char*     mString;
     jobject   mColor;
    } StoreValue;
    ...
    ```

1.  使用 `javah` 重新生成 JNI 头文件 `jni/com_packtpub_Store.h`。你应在其中看到两个新的方法 `Java_com_packtpub_store_Store_getColor()` 和 `Java_com_packtpub_store_Store_setColor()`。

1.  打开 `jni/com_packtpub_Store.cpp` 并实现两个新生成的 `getColor()` 和 `setColor()` 方法。第一个方法只是简单地返回存储条目中保留的 Java Color 对象，如下代码所示：

    ```java
    ...
    JNIEXPORT jobject JNICALL Java_com_packtpub_store_Store_getColor
      (JNIEnv* pEnv, jobject pThis, jstring pKey) {
        StoreEntry* entry = findEntry(pEnv, &gStore, pKey);
        if (isEntryValid(pEnv, entry, StoreType_Color)) {
            return entry->mValue.mColor;
        } else {
            return NULL;
        }
    }
    ...
    ```

    第二个方法 `setColor()` 中引入了真正的细微差别。实际上，乍一看，简单地将 `jobject` 值保存在存储条目中似乎就足够了。然而，这种假设是错误的。在参数中传递或在 JNI 方法内创建的对象是局部引用。局部引用不能在本地方法范围之外（如对于字符串）的本地代码中保存。

1.  为了允许在本地方法返回后在本地代码中保留 Java 对象引用，它们必须被转换为全局引用，以通知 Dalvik VM 它们不能被垃圾收集。为此，JNI API 提供了 `NewGlobalRef()` 方法：

    ```java
    ...
    JNIEXPORT void JNICALL Java_com_packtpub_store_Store_setColor
      (JNIEnv* pEnv, jobject pThis, jstring pKey, jobject pColor) {
        // Save the Color reference in the store.
        StoreEntry* entry = allocateEntry(pEnv, &gStore, pKey);
        if (entry != NULL) {
            entry->mType = StoreType_Color;
            // The Java Color is going to be stored on the native side.
            // Need to keep a global reference to avoid a potential
            // garbage collection after method returns.
            entry->mValue.mColor = pEnv->NewGlobalRef(pColor);
        }
    }
    ```

1.  在 `Store.cpp` 中，修改 `releaseEntryValue()` 方法，当条目被新条目替换时删除全局引用。这是通过 `DeleteGlobalRef()` 方法完成的，它是 `NewGlobalRef()` 的对应方法：

    ```java
    ...
    void releaseEntryValue(JNIEnv* pEnv, StoreEntry* pEntry) {
        switch (pEntry->mType) {
        case StoreType_String:
            delete pEntry->mValue.mString;
            break;
     case StoreType_Color:
     // Unreferences the object for garbage collection.
     pEnv->DeleteGlobalRef(pEntry->mValue.mColor);
     break;
        }
    }
    ```

## *刚才发生了什么？*

运行应用程序。输入并保存一个颜色值，如 **#FF0000** 或 **red**，这是 Android 颜色解析器允许的预定义值。从存储中获取条目。我们设法在本地端引用了一个 Java 对象！Java 对象不是也不能转换为 C++ 对象。它们本质上是不同的。因此，要在本地端保留 Java 对象，我们必须使用 JNI API 保留对它们的引用。

来自 Java 的所有对象都由 `jobject` 表示，甚至 `jstring`（实际上内部是 `jobject` 的 `typedef`）。`jobject` 只是一个没有智能垃圾收集机制的“指针”（毕竟，我们至少部分想要摆脱 Java）。它不直接给你 Java 对象内存的引用，而是间接引用。实际上，与 C++ 对象相反，Java 对象在内存中没有固定的位置。它们在其生命周期内可能会被移动。无论如何，在内存中处理 Java 对象表示都是一个坏主意。

## 局部引用

本地调用的作用域限制在方法内，这意味着一旦本地方法结束，虚拟机将再次接管。JNI 规范利用这一事实，将对象引用限制在方法边界内。这意味着 `jobject` 只能在它被赋予的方法内安全使用。一旦本地方法返回，Dalvik VM 无法知道本地代码是否还持有对象引用，并且可以在任何时间决定收集它们。

这种类型的引用称为**本地**引用。当本地方法返回时，它们会自动释放（指的是引用，而不是对象，尽管垃圾收集器可能会这样做），以允许在后面的 Java 代码中进行适当的垃圾收集。例如，以下代码段应该是严格禁止的。在 JNI 方法外部保留这样的引用最终会导致未定义的行为（内存损坏、崩溃等）：

```java
static jobject gMyReference;
JNIEXPORT void JNICALL Java_MyClass_myMethod(JNIEnv* pEnv,
                                     jobject pThis, jobject pRef) {
    gMyReference = pRef;
    ...
}

// Later on...
env->CallVoidMethod(gMyReference, ...);
```

### 提示

对象作为本地引用传递给本地方法。由 JNI 函数返回的每个 `jobject`（除了 `NewGlobalRef()`）都是一个本地引用。请记住，默认情况下一切都是本地引用。

JNI 提供了几种用于管理本地引用的方法：

1.  `NewLocalRef()` 可以显式地创建一个本地引用（例如，从一个全局引用），尽管这在实践中很少需要：

    ```java
    jobject NewLocalRef(jobject ref)
    ```

1.  `DeleteLocalRef()` 方法可以在不再需要时用来删除一个本地引用：

    ```java
    void DeleteLocalRef(jobject localRef)
    ```

### 提示

本地引用不能在方法作用域之外使用，也不能在即使是单个本地调用期间在各个线程间共享！

你不需要显式删除本地引用。然而，根据 JNI 规范，JVM 只需要同时存储 16 个本地引用，并且可能会拒绝创建更多（这是特定于实现的）。因此，尽早释放未使用的本地引用是良好的实践，特别是在处理数组时。

幸运的是，JNI 提供了一些其他方法来帮助处理本地引用。

1.  `EnsureLocalCapacity()` 告诉 VM 它需要更多的本地引用。当此方法无法保证请求的容量时，它返回 `-1` 并抛出 Java `OutOfMemoryError`：

    ```java
    jint EnsureLocalCapacity(jint capacity)
    ```

1.  `PushLocalFrame()` 和 `PopLocalFrame()` 提供了第二种分配更多本地引用的方法。这可以理解为批量分配本地槽和删除本地引用的方式。当此方法无法保证请求的容量时，它也会返回 `-1` 并抛出 Java `OutOfMemoryError`：

    ```java
    jint PushLocalFrame(jint capacity)
    jobject PopLocalFrame(jobject result)
    ```

    ### 提示

    直到 Android 4.0 冰激凌三明治版本，本地引用实际上是直接指针，这意味着它们可以保持在其自然作用域之外并且仍然有效。现在不再是这样，这种有缺陷的代码应该避免。

## 全局引用

要能在方法作用域之外使用对象引用或长时间保存它，引用必须被设置为**全局**。全局引用还允许在各个线程间共享对象，而本地引用则不能。

JNI 提供了两个为此目的的方法：

1.  使用`NewGlobalRef()`创建全局引用，防止回收指向的对象，并允许其在线程间共享。同一个对象的两个引用可能是不同的：

    ```java
    jobject NewGlobalRef(jobject obj)
    ```

1.  使用`DeleteGlobalRef()`删除不再需要全局引用。如果没有它，Dalvik VM 会认为对象仍然被引用，永远不会回收它们：

    ```java
    void DeleteGlobalRef(jobject globalRef)
    ```

1.  使用`IsSameObject()`比较两个对象引用，而不是使用`==`，后者不是比较引用的正确方式：

    ```java
    jboolean IsSameObject(jobject ref1, jobject ref2)
    ```

### 提示

切记要配对使用`New<Reference Type>Ref()`和`Delete<Reference Type>Ref()`。否则会导致内存泄漏。

## 弱引用

弱引用是 JNI 中可用的最后一种引用类型。它们与全局引用相似，可以在 JNI 调用之间保持并在线程间共享。然而，与全局引用不同，它们不会阻止垃圾回收。因此，这种引用必须谨慎使用，因为它可能随时变得无效，除非每次在使用之前从它们创建全局或局部引用（并在使用后立即释放！）。

### 提示

当适当使用时，弱引用有助于防止内存泄漏。如果你已经进行了一些 Android 开发，你可能已经知道最常见的泄漏之一：从后台线程（通常是`AsyncTask`）保持对 Activity 的“硬”引用，以便在处理完成后通知 Activity。的确，在发送通知之前，Activity 可能会被销毁（例如，因为用户旋转了屏幕）。当使用弱引用时，Activity 仍然可以被垃圾回收，从而释放内存。

`NewWeakGlobalRef()`和`DeleteWeakGlobalRef()`是创建和删除弱引用所需仅有的方法：

```java
jweak NewWeakGlobalRef(JNIEnv *env, jobject obj);
void DeleteWeakGlobalRef(JNIEnv *env, jweak obj);
```

这些方法返回一个`jweak`引用，如果需要，可以将其强制转换为输入对象（例如，如果你创建了一个到`jclass`的引用，那么返回的`jweak`可以强制转换为`jclass`或`jobject`）。

然而，你不应直接使用它，而应将其传递给`NewGlobalRef()`或`NewLocalRef()`，并像平常一样使用它们的结果。要确保从弱引用发出的局部或全局引用有效，只需检查`NewGlobalRef()`或`NewLocalRef()`返回的引用是否为`NULL`。完成对象操作后，你可以删除全局或局部引用。每次重新使用该弱对象时，请重新开始这个过程。例如：

```java
jobject myObject = ...;
// Keep a reference to that object until it is garbage collected.
jweak weakRef = pEnv->NewWeakGlobalRef(myObject);
...

// Later on, get a real reference, hoping it is still available.
jobject localRef = pEnv->NewLocalRef(weakRef);
if (!localRef) {
// Do some stuff...
pEnv->DeleteLocalRef(localRef);
} else {
   // Object has been garbage collected, reference is unusable...
}

...
// Later on, when weak reference is no more needed.
pEnv->DeleteWeakGlobalRef(weakRef);
```

要检查弱引用本身是否指向一个对象，请使用`IsSameObject()`将`jweak`与`NULL`进行比较（不要使用`==`）：

```java
jboolean IsSameObject(jobject ref1, jobject ref2)
```

在创建全局或局部引用之前，不要试图检查弱引用的状态，因为指向的对象可能会被并发地回收。

### 提示

在 Android 2.2 Froyo 之前，弱引用根本不存在。直到 Android 4.0 Ice Cream Sandwich，除了`NewGlobalRef()`或`NewLocalRef()`之外，它们不能在 JNI 调用中使用。尽管这不再是强制性的，但在其他 JNI 调用中直接使用弱引用应被视为一种不良实践。

若要了解更多关于此主题的信息，请查看 JNI 规范，链接为：[`docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/jniTOC.html`](http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/jniTOC.html)。

# 管理 Java 数组

还有一种我们尚未讨论的数据类型：**数组**。数组在 Java 和 JNI 中都有其特定的位置。它们具有自己的类型和 API，尽管 Java 数组在本质上也是对象。

在这一部分，我们将通过允许用户在输入项中同时输入一组值来改进我们的存储。这组值将作为 Java 数组传递给本地存储，然后以传统的 C 数组形式存储。

### 注意事项

最终的项目作为本书的一部分提供，名为`Store_Part8`。

# 动手实践——在本地存储中处理 Java 数组

为了帮助我们处理数组操作，让我们下载一个辅助库，**Google Guava**（在撰写本书时为 18.0 版本），可在[`code.google.com/p/guava-libraries/`](http://code.google.com/p/guava-libraries/)获取。Guava 提供了许多用于处理原语和数组，以及执行“伪函数式”编程的有用方法。

将`guava jar`复制到项目`libs`目录中。打开**属性**项目，并转到**Java 构建路径** | **库**。通过点击**添加 JARs...**按钮并验证，引用 Guava jar。

1.  编辑`StoreType.java`枚举，并添加三个新值：`IntegerArray`、`StringArray`和`ColorArray`：

    ```java
    public enum StoreType {
        ...
        Color,
        IntegerArray,
        StringArray,
        ColorArray
    }
    ```

1.  打开`Store.java`文件，并添加新的方法以获取和保存`int`、`String`和`Color`数组：

    ```java
    public class Store {
        ...
     public native int[] getIntegerArray(String pKey);
     public native void setIntegerArray(String pKey, int[] pIntArray);
     public native String[] getStringArray(String pKey);
     public native void setStringArray(String pKey,
     String[] pStringArray);
     public native Color[] getColorArray(String pKey);
     public native void setColorArray(String pKey,Color[] pColorArray);
    }
    ```

1.  编辑`StoreActivity.java`，将本地方法连接到 GUI。

    修改`onGetValue()`方法，使其根据其类型从存储中检索数组，使用分号分隔符（得益于 Guava 连接器）连接其值，并最终显示它们：

    ```java
    public class StoreActivity extends Activity {
        ...
        public static class PlaceholderFragment extends Fragment {
            ...
            private void onGetValue() {
                ...
                switch (type) {
                ...
     case IntegerArray:
     mUIValueEdit.setText(Ints.join(";", mStore
     .getIntegerArray(key)));
     break;
     case StringArray:
     mUIValueEdit.setText(Joiner.on(";").join(
     mStore.getStringArray(key)));
     break;
     case ColorArray:
     mUIValueEdit.setText(Joiner.on(";").join(mStore
     .getColorArray(key)));
     break;            case IntegerArray:
                }
            }
            ...
    ```

1.  改进`onSetValue()`方法，在将值列表传输到`Store`之前将其转换成数组（得益于 Guava 的转换特性）：

    ```java
            ...
            private void onSetValue() {
                ...
                try {
                    switch (type) {
                    ...
                    case IntegerArray:
     mStore.setIntegerArray(key, Ints.toArray(
     stringToList(new Function<String, Integer>() {
     public Integer apply(String pSubValue) {
     return Integer.parseInt(pSubValue);
     }
     }, value)));
     break;
     case StringArray:
     String[] stringArray = value.split(";");
     mStore.setStringArray(key, stringArray);
     break;
     case ColorArray:
     List<Color> idList = stringToList(
     new Function<String, Color>() {
     public Color apply(String pSubValue) {
     return new Color(pSubValue);
     }
     }, value);
     mStore.setColorArray(key, idList.toArray(
     new Color[idList.size()]));
     break;
                    }
                } catch (Exception eException) {
                    displayMessage("Incorrect value.");
                }
                updateTitle();
            }
            ...
    ```

1.  编写一个辅助方法`stringToList()`，帮助您将字符串转换为目标类型的列表：

    ```java
            ...
            private <TType> List<TType> stringToList(
                            Function<String, TType> pConversion,
                            String pValue) {
                String[] splitArray = pValue.split(";");
                List<String> splitList = Arrays.asList(splitArray);
                return Lists.transform(splitList, pConversion);
            }
        }
    }
    ```

1.  在`jni/Store.h`中，将新的数组类型添加到`StoreType`枚举中。同时，在`StoreValue`联合体中声明新字段`mIntegerArray`、`mStringArray`和`mColorArray`。存储数组以原始 C 数组（即一个指针）的形式表示：

    ```java
    ...
    typedef enum {
        ...
        StoreType_Color,
     StoreType_IntegerArray,
     StoreType_StringArray,
     StoreType_ColorArray
    } StoreType;

    typedef union {
        ...
        jobject   mColor;
     int32_t*  mIntegerArray;
     char**    mStringArray;
     jobject*  mColorArray;
    } StoreValue;
    ...
    ```

1.  我们还需要记住这些数组的长度。在`StoreEntry`中的新字段`mLength`中输入此信息：

    ```java
    ...
    typedef struct {
        char* mKey;
        StoreType mType;
        StoreValue mValue;
     int32_t mLength;
    } StoreEntry;
    ...
    ```

1.  在`jni/Store.cpp`中，为新的数组类型在`releaseEntryValue()`中插入案例。实际上，当相应的条目被释放时，必须释放分配的数组。由于颜色是 Java 对象，删除每个数组项中保存的全局引用，否则永远不会进行垃圾回收（导致内存泄漏）：

    ```java
    void releaseEntryValue(JNIEnv* pEnv, StoreEntry* pEntry) {
        switch (pEntry->mType) {
        ...
     case StoreType_IntegerArray:
     delete[] pEntry->mValue.mIntegerArray;
     break;
     case StoreType_StringArray:
     // Destroys every C string pointed by the String array
     // before releasing it.
     for (int32_t i = 0; i < pEntry->mLength; ++i) {
     delete pEntry->mValue.mStringArray[i];
     }
     delete[] pEntry->mValue.mStringArray;
     break;
     case StoreType_ColorArray:
     // Unreferences every Id before releasing the Id array.
     for (int32_t i = 0; i < pEntry->mLength; ++i) {
     pEnv->DeleteGlobalRef(pEntry->mValue.mColorArray[i]);
     }
     delete[] pEntry->mValue.mColorArray;
     break;
        }
    }
    ...
    ```

1.  使用`Javah`重新生成 JNI 头文件`jni/com_packtpub_Store.h`。在`jni/com_packtpub_Store.cpp`中实现所有这些新方法。为此，首先添加`csdtint`包含。

    ```java
    #include "com_packtpub_store_Store.h"
    #include <cstdint>
    #include <cstdlib>
    #include "Store.h"
    ...
    ```

1.  然后，缓存`String`和`Color`的 JNI 类，以便在后续步骤中能够创建这些类型的对象数组。类可以通过`JNIEnv`自身的反射访问，并且可以从传递给`JNI_OnLoad()`的`JavaVM`中获取。

    我们需要检查找到的类是否为 null，以防它们无法加载。如果发生这种情况，虚拟机会引发异常，以便我们可以立即返回：

    ```java
    ...
    static jclass StringClass;
    static jclass ColorClass;

    JNIEXPORT jint JNI_OnLoad(JavaVM* pVM, void* reserved) {
     JNIEnv *env;
     if (pVM->GetEnv((void**) &env, JNI_VERSION_1_6) != JNI_OK) {
     abort();
     }
     // If returned class is null, an exception is raised by the VM.
     jclass StringClassTmp = env->FindClass("java/lang/String");
     if (StringClassTmp == NULL) abort();
     StringClass = (jclass) env->NewGlobalRef(StringClassTmp);
     env->DeleteLocalRef(StringClassTmp);
     jclass ColorClassTmp = env->FindClass("com/packtpub/store/Color");
     if (ColorClassTmp == NULL) abort();
     ColorClass = (jclass) env->NewGlobalRef(ColorClassTmp);
     env->DeleteLocalRef(ColorClassTmp);
        // Store initialization.
        gStore.mLength = 0;
        return JNI_VERSION_1_6;
    }
    ...
    ```

1.  编写`getIntegerArray()`的实现。JNI 整数数组用`jintArray`类型表示。如果`int`等同于`jint`，那么`int*`数组绝对不等同于`jintArray`。第一个是指向内存缓冲区的指针，而第二个是对对象的引用。

    因此，为了在这里返回`jintArray`，使用 JNI API 方法`NewIntArray()`实例化一个新的 Java 整数数组。然后，使用`SetIntArrayRegion()`将本地`int`缓冲区内容复制到`jintArray`中：

    ```java
    ...
    JNIEXPORT jintArray JNICALL
    Java_com_packtpub_store_Store_getIntegerArray
      (JNIEnv* pEnv, jobject pThis, jstring pKey) {
        StoreEntry* entry = findEntry(pEnv, &gStore, pKey);
        if (isEntryValid(pEnv, entry, StoreType_IntegerArray)) {
            jintArray javaArray = pEnv->NewIntArray(entry->mLength);
            pEnv->SetIntArrayRegion(javaArray, 0, entry->mLength,
                                    entry->mValue.mIntegerArray);
            return javaArray;
        } else {
            return NULL;
        }
    }
    ...
    ```

1.  为了在本地代码中保存 Java 数组，存在逆操作`GetIntArrayRegion()`。分配合适内存缓冲的唯一方式是使用`GetArrayLength()`测量数组大小：

    ```java
    ...
    JNIEXPORT void JNICALL Java_com_packtpub_store_Store_setIntegerArray
      (JNIEnv* pEnv, jobject pThis, jstring pKey,
       jintArray pIntegerArray) {
        StoreEntry* entry = allocateEntry(pEnv, &gStore, pKey);
        if (entry != NULL) {
            jsize length = pEnv->GetArrayLength(pIntegerArray);
            int32_t* array = new int32_t[length];
            pEnv->GetIntArrayRegion(pIntegerArray, 0, length, array);

            entry->mType = StoreType_IntegerArray;
            entry->mLength = length;
            entry->mValue.mIntegerArray = array;
        }
    }
    ...
    ```

Java 对象数组与 Java 基本数组不同。它们是用类类型（这里，缓存的`String jclass`）实例化的，因为 Java 数组是单类型的。对象数组本身用`jobjectArray`类型表示，可以通过 JNI API 方法`NewObjectArray()`创建。

与基本数组不同，不可能同时处理所有元素。相反，使用`SetObjectArrayElement()`逐个设置对象。这里，本地数组被填充了在本地存储的`String`对象，这些对象保持全局引用。因此，除了对新分配字符串的引用外，这里无需删除或创建任何引用。

```java
...
JNIEXPORT jobjectArray JNICALL
Java_com_packtpub_store_Store_getStringArray
  (JNIEnv* pEnv, jobject pThis, jstring pKey) {
    StoreEntry* entry = findEntry(pEnv, &gStore, pKey);
    if (isEntryValid(pEnv, entry, StoreType_StringArray)) {
        // An array of String in Java is in fact an array of object.
        jobjectArray javaArray = pEnv->NewObjectArray(entry->mLength,
                StringClass, NULL);
        // Creates a new Java String object for each C string stored.
        // Reference to the String can be removed right after it is
        // added to the Java array, as the latter holds a reference
        // to the String object.
        for (int32_t i = 0; i < entry->mLength; ++i) {
            jstring string = pEnv->NewStringUTF(
                    entry->mValue.mStringArray[i]);
            // Puts the new string in the array
            pEnv->SetObjectArrayElement(javaArray, i, string);
            // Do it here to avoid holding many useless local refs.
            pEnv->DeleteLocalRef(string);
        }
        return javaArray;
    } else {
        return NULL;
    }
}
...
```

在`setStringArray()`方法中，通过`GetObjectArrayElement()`逐个获取数组元素。返回的引用是局部的，应当将其变为全局引用，以便在本地安全地存储它们。

```java
...
JNIEXPORT void JNICALL Java_com_packtpub_store_Store_setStringArray
  (JNIEnv* pEnv, jobject pThis, jstring pKey,
   jobjectArray pStringArray) {
    // Creates a new entry with the new String array.
    StoreEntry* entry = allocateEntry(pEnv, &gStore, pKey);
    if (entry != NULL) {
        // Allocates an array of C string.
        jsize length = pEnv->GetArrayLength(pStringArray);
        char** array = new char*[length];
        // Fills the C array with a copy of each input Java string.
        for (int32_t i = 0; i < length; ++i) {
            // Gets the current Java String from the input Java array.
            // Object arrays can be accessed element by element only.
            jstring string = (jstring)
                         pEnv->GetObjectArrayElement(pStringArray, i);
            jsize stringLength = pEnv->GetStringUTFLength(string);
            array[i] = new char[stringLength + 1];
            // Directly copies the Java String into our new C buffer.
            pEnv->GetStringUTFRegion(string,0,stringLength, array[i]);
            // Append the null character for string termination.
            array[i][stringLength] = '\0';
            // No need to keep a reference to the Java string anymore.
            pEnv->DeleteLocalRef(string);
        }
        entry->mType = StoreType_StringArray;
        entry->mLength = length;
        entry->mValue.mStringArray = array;
    }
}
```

以`getColorArray()`开始，对颜色执行相同的操作。由于字符串和颜色在 Java 端都是对象，所以可以使用`NewObjectArray()`以相同的方式创建返回的数组。

使用 JNI 方法`SetObjectArrayElement()`将每个保存的`Color`引用放置在数组内。由于颜色在本地作为全局 Java 引用存储，无需创建或删除局部引用：

```java
...
JNIEXPORT jobjectArray JNICALL
Java_com_packtpub_store_Store_getColorArray
  (JNIEnv* pEnv, jobject pThis, jstring pKey) {
    StoreEntry* entry = findEntry(pEnv, &gStore, pKey);
    if (isEntryValid(pEnv, entry, StoreType_ColorArray)) {
        // Creates a new array with objects of type Id.
        jobjectArray javaArray = pEnv->NewObjectArray(entry->mLength,
                ColorClass, NULL);
        // Fills the array with the Color objects stored on the native
        // side, which keeps a global reference to them. So no need
        // to delete or create any reference here.
        for (int32_t i = 0; i < entry->mLength; ++i) {
            pEnv->SetObjectArrayElement(javaArray, i,
                                        entry->mValue.mColorArray[i]);
        }
        return javaArray;
    } else {
        return NULL;
    }
}
...
```

在`setColorArray()`中，颜色元素也是通过`GetObjectArrayElement()`逐个检索的。同样，返回的引用是局部的，应该使其全局化以在本地安全存储：

```java
...
JNIEXPORT void JNICALL Java_com_packtpub_store_Store_setColorArray
  (JNIEnv* pEnv, jobject pThis, jstring pKey,
   jobjectArray pColorArray) {
    // Saves the Color array in the store.
    StoreEntry* entry = allocateEntry(pEnv, &gStore, pKey);
    if (entry != NULL) {
        // Allocates a C array of Color objects.
        jsize length = pEnv->GetArrayLength(pColorArray);
        jobject* array = new jobject[length];
        // Fills the C array with a copy of each input Java Color.
        for (int32_t i = 0; i < length; ++i) {
            // Gets the current Color object from the input Java array.
            // Object arrays can be accessed element by element only.
            jobject localColor = pEnv->GetObjectArrayElement(
                    pColorArray, i);
            // The Java Color is going to be stored on the native side
            // Need to keep a global reference to avoid a potential
            // garbage collection after method returns.
            array[i] = pEnv->NewGlobalRef(localColor);
            // We have a global reference to the Color, so we can now
            // get rid of the local one.
            pEnv->DeleteLocalRef(localColor);
        }
        entry->mType = StoreType_ColorArray;
        entry->mLength = length;
        entry->mValue.mColorArray = array;
    }
}
```

## *刚才发生了什么？*

我们从 Java 传输数组到本地侧，反之亦然。Java 数组是只能通过专用的 JNI API 操作的 Java 对象。它们不能被转换为原生的 C/C++数组，也不能以同样的方式使用。

我们还了解了如何利用`JNI_OnLoad()`回调来缓存 JNI 类描述符。类描述符，类型为`jclass`（在幕后也是`jobject`），相当于 Java 中的`Class<?>`。它们允许我们定义我们想要的数组类型，有点像 Java 中的反射 API。我们将在下一章回到这个主题。

## 原始数组

可用的原始数组类型有`jbooleanArray`，`jbyteArray`，`jcharArray`，`jdoubleArray`，`jfloatArray`，`jlongArray`和`jshortArray`。这些类型表示对真实 Java 数组的引用。

这些数组可以使用 JNI 提供的多种方法进行操作：

1.  使用`New<Primitive>Array()`创建新的 Java 数组：

    ```java
    jintArray NewIntArray(jsize length)
    ```

1.  `GetArrayLength()`检索数组的长度：

    ```java
    jsize GetArrayLength(jarray array)
    ```

1.  `Get<Primitive>ArrayElements()`将整个数组检索到由 JNI 分配的内存缓冲区中。最后一个参数`isCopy`，如果不为空，表示 JNI 是否内部复制了数组，或者返回的缓冲区指针指向实际的 Java 字符串内存：

    ```java
    jint* GetIntArrayElements(jintArray array, jboolean* isCopy)
    ```

1.  `Release<Primitive>ArrayElements()`释放由`Get<Primitive>ArrayElements()`分配的内存缓冲区。总是成对使用。最后一个参数模式与`isCopy`参数相关，表示以下内容：

    +   如果设置为 0，那么 JNI 应该将修改后的数组复制回初始的 Java 数组，并告诉 JNI 释放其临时内存缓冲区。这是最常见的标志。

    +   如果设置`JNI_COMMIT`，那么 JNI 应该将修改后的数组复制回初始数组，但不释放内存。这样，客户端代码在将结果传回 Java 的同时，仍可以在内存缓冲区中继续处理。

    +   如果设置`JNI_ABORT`，那么 JNI 必须丢弃内存缓冲区中进行的任何更改，并保持 Java 数组不变。如果临时本地内存缓冲区不是副本，这将无法正确工作。

        ```java
        void ReleaseIntArrayElements(jintArray array, jint* elems, jint mode)
        ```

1.  `Get<Primitive>ArrayRegion()`将数组的全部或部分内容检索到由客户端代码分配的内存缓冲区中。例如，对于整数：

    ```java
    void GetIntArrayRegion(jintArray array, jsize start, jsize len,
                           jint* buf)
    ```

1.  `Set<Primitive>ArrayRegion()`从由客户端代码管理的本地缓冲区初始化 Java 数组的全部或部分内容。例如，对于整数：

    ```java
    void SetIntArrayRegion(jintArray array, jsize start, jsize len,
                           const jint* buf)
    ```

1.  `Get<Primitive>ArrayCritical()`和`Release<Primitive>ArrayCritical()`与`Get<Primitive>ArrayElements()`和`Release<Primitive>ArrayElements()`相似，但仅供直接访问目标数组（而不是副本）使用。作为交换，调用者不得执行阻塞或 JNI 调用，并且不应长时间持有数组（如线程的关键部分）。同样，所有基本类型都提供这两个方法：

    ```java
    void* GetPrimitiveArrayCritical(jarray array, jboolean* isCopy)
    void ReleasePrimitiveArrayCritical(jarray array, void* carray, jint mode)
    ```

## 尝试英雄——处理其他数组类型

利用新获得的知识，你可以为其他数组类型实现存储方法：`jbooleanArray`、`jbyteArray`、`jcharArray`、`jdoubleArray`、`jfloatArray`、`jlongArray`和`jshortArray`。

例如，你可以使用`GetBooleanArrayElements()`和`ReleaseBooleanArrayElements()`而不是`GetBooleanArrayRegion()`，为`jbooleanArray`类型编写`setBooleanArray()`方法。结果应该如下所示，两种方法与`memcpy()`配对调用：

```java
...
JNIEXPORT void JNICALL Java_com_packtpub_store_Store_setBooleanArray
  (JNIEnv* pEnv, jobject pThis, jstring pKey,
   jbooleanArray pBooleanArray) {
    // Finds/creates an entry in the store and fills its content.
    StoreEntry* entry = allocateEntry(pEnv, &gStore, pKey);
    if (entry != NULL) {
        entry->mType = StoreType_BooleanArray;
        jsize length = pEnv->GetArrayLength(pBooleanArray);
        uint8_t* array = new uint8_t[length];
        // Retrieves array content.
 jboolean* arrayTmp = pEnv->GetBooleanArrayElements(
 pBooleanArray, NULL);
        memcpy(array, arrayTmp, length * sizeof(uint8_t));
        pEnv->ReleaseBooleanArrayElements(pBooleanArray, arrayTmp, 0);
        entry->mType = StoreType_BooleanArray;
        entry->mValue.mBooleanArray = array;
        entry->mLength = length;
    }
}
...
```

### 注意

最终的项目以`Store_Part8_Full`的名字随本书提供。

## 对象数组

在 JNI 中，对象数组被称为`jobjectArray`，代表对 Java 对象数组的引用。对象数组是特殊的，因为与基本数组不同，每个数组元素都是对对象的引用。因此，每次在数组中插入对象时，都会自动注册一个新的全局引用。这样，本地调用结束时，引用就不会被垃圾回收。注意，对象数组不能像基本类型那样转换为“本地”数组。

对象数组可以使用 JNI 提供的几种方法进行操作：

1.  `NewObjectArray()`创建一个新的对象数组实例：

    ```java
    jobjectArray NewObjectArray(jsize length, jclass elementClass, jobject initialElement);
    ```

1.  `GetArrayLength()`检索数组的长度（与基本类型相同的方法）：

    ```java
    jsize GetArrayLength(jarray array)
    ```

1.  `GetObjectArrayElement()`从 Java 数组中检索单个对象引用。返回的引用是局部的：

    ```java
    jobject GetObjectArrayElement(jobjectArray array, jsize index)
    ```

1.  `SetObjectArrayElement()`将单个对象引用放入 Java 数组中。隐式创建全局引用：

    ```java
    void SetObjectArrayElement(jobjectArray array, jsize index, jobject value)
    ```

有关 JNI 功能的更详尽列表，请参见[`docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/functions.html`](http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/functions.html)。

# 引发和检查 Java 异常

在 Store 项目中处理错误并不令人满意。如果找不到请求的键，或者检索到的值类型与请求的类型不匹配，将返回默认值。不要尝试使用 Color 条目。我们确实需要一种方法来指示发生了错误！还有什么比异常更好的错误指示方法呢？

JNI 提供了必要的 API，在 JVM 级别抛出异常。这些异常是你在 Java 中可以捕获的异常。它们与你在其他程序中可以找到的常规 C++异常（我们将在第九章，*将现有库移植到 Android*中进一步了解）在语法和流程上没有任何共同之处。

在这一部分，我们将了解如何从本地代码抛出 JNI 异常到 Java 端。

### 注意

本书提供的项目成果名为`Store_Part9`。

# 动手实践时间——在本地存储中抛出和捕获异常

1.  按照以下方式创建类型为`Exception`的 Java 异常`com.packtpub.exception.InvalidTypeException`：

    ```java
    package com.packtpub.exception;

    public class InvalidTypeException extends Exception {
        public InvalidTypeException(String pDetailMessage) {
            super(pDetailMessage);
        }
    }
    ```

    对另外两个异常重复该操作：类型为`Exception`的`NotExistingKeyException`和类型为`RuntimeException`的`StoreFullException`。

1.  打开`Store.java`文件，并在`Store`类中的`getInteger()`方法上声明抛出的异常（`StoreFullException`是`RuntimeException`，不需要声明）：

    ```java
    public class Store {
        ...
        public native int getInteger(String pKey)
     throws NotExistingKeyException, InvalidTypeException;
        public native void setInteger(String pKey, int pInt);
        ...
    ```

    对所有其他 getter 方法的原型（字符串、颜色等）重复该操作。

1.  这些异常需要被捕获。在`onGetValue()`中捕获`NotExistingKeyException`和`InvalidTypeException`：

    ```java
    public class StoreActivity extends Activity {
        ...
        public static class PlaceholderFragment extends Fragment {
            ...
            private void onGetValue() {
                ...
                try {
                    switch (type) {
                    ...
                }
     // Process any exception raised while retrieving data.
     catch (NotExistingKeyException eNotExistingKeyException) {
     displayMessage(eNotExistingKeyException.getMessage());
     } catch (InvalidTypeException eInvalidTypeException) {
     displayMessage(eInvalidTypeException.getMessage());
                }
            }
    ```

1.  在`onSetValue()`方法中捕获`StoreFullException`，以防因为存储空间耗尽导致条目无法插入：

    ```java
            private void onSetValue() {
                ...
                try {
                    ...
                } catch (NumberFormatException eNumberFormatException) {
                    displayMessage("Incorrect value.");
     } catch (StoreFullException eStoreFullException) {
     displayMessage(eStoreFullException.getMessage());
                } catch (Exception eException) {
                    displayMessage("Incorrect value.");
                }
                updateTitle();
            }
            ...
        }
    }
    ```

1.  打开之前部分创建的`jni/Store.h`文件，并定义三个新的辅助方法来抛出异常：

    ```java
    ...
    void throwInvalidTypeException(JNIEnv* pEnv);

    void throwNotExistingKeyException(JNIEnv* pEnv);

    void throwStoreFullException(JNIEnv* pEnv);
    #endif
    ```

1.  编辑`jni/Store.cpp`文件，当从存储中获取不适当的条目时抛出`NotExistingKeyException`和`InvalidTypeException`。在用`isEntryValid()`检查条目时抛出它们是一个好地方：

    ```java
    ...
    bool isEntryValid(JNIEnv* pEnv, StoreEntry* pEntry, StoreType pType) {
        if (pEntry == NULL) {
            throwNotExistingKeyException(pEnv);
        } else if (pEntry->mType != pType) {
            throwInvalidTypeException(pEnv);
        }
        return !pEnv->ExceptionCheck();
    }
    ...
    ```

1.  `StoreFullException`显然是在插入新条目时抛出的。修改同一文件中的`allocateEntry()`，以检查条目插入：

    ```java
    ...
    StoreEntry* allocateEntry(JNIEnv* pEnv, Store* pStore, jstring pKey) {
        // If entry already exists in the store, releases its content
        // and keep its key.
        StoreEntry* entry = findEntry(pEnv, pStore, pKey);
        if (entry != NULL) {
            releaseEntryValue(pEnv, entry);
        }
        // If entry does not exist, create a new entry
        // right after the entries already stored.
        else {
            // Checks store can accept a new entry.
     if (pStore->mLength >= STORE_MAX_CAPACITY) {
     throwStoreFullException(pEnv);
     return NULL;
            }
            entry = pStore->mEntries + pStore->mLength;
            // Copies the new key into its final C string buffer.
            ...
        }
        return entry;
    }
    ...
    ```

实现`throwNotExistingException()`。为了抛出一个 Java 异常，首先需要找到对应的类（就像使用 Java 反射 API 一样）。由于我们可以假设这些异常不会被频繁抛出，我们可以不缓存类引用。然后，使用`ThrowNew()`抛出异常。一旦我们不再需要异常类引用，可以使用`DeleteLocalRef`()来释放它。

```java
...
void throwNotExistingKeyException(JNIEnv* pEnv) {
    jclass clazz = pEnv->FindClass(
                    "com/packtpub/exception/NotExistingKeyException");
    if (clazz != NULL) {
        pEnv->ThrowNew(clazz, "Key does not exist.");
    }
    pEnv->DeleteLocalRef(clazz);
}
```

对另外两个异常重复该操作。代码是相同的（即使是抛出一个运行时异常），只有类名会改变。

## *刚才发生了什么？*

启动应用程序，尝试获取一个不存在的键的条目。重复该操作，但这次是存储中存在的条目，但其类型与 GUI 中选择的类型不同。在这两种情况下，都会出现错误信息。尝试在存储中保存超过 16 个引用，你将再次得到错误。在每种情况下，都在本地端抛出了异常，并在 Java 端捕获。

在本地代码中引发异常并不是一个复杂的任务，但也不是微不足道的。异常使用类型为`jclass`的类描述符实例化。JNI 需要这个类描述符来实例化适当的异常类型。JNI 异常与 JNI 方法原型中未声明，因为它们与 C++异常无关（C 中无法声明的异常）。这就解释了为什么我们没有重新生成 JNI 头文件以适应`Store.java`文件中的更改。

## 在异常状态下执行代码

一旦引发异常，你在使用 JNI 调用时需要非常小心。实际上，在此之后的任何后续调用都会失败，直到发生以下任一事件：

1.  方法返回，并传播一个异常。

1.  异常被清除。清除异常意味着该异常已被处理，因此不会传播到 Java。例如：

    ```java
    // Raise an exception
    jclass clazz = pEnv->FindClass("java/lang/RuntimeException");
    if (clazz != NULL) {
      pEnv->ThrowNew(clazz, "Oups an exception.");
    }
    pEnv->DeleteLocalRef(clazz);

    ...

    // Detect and catch the exception by clearing it.
    jthrowable exception = pEnv->ExceptionOccurred();
    if (exception) {
      // Do something...
      pEnv->ExceptionDescribe();
      pEnv->ExceptionClear();
      pEnv->DeleteLocalRef(exception);
    }
    ```

在引发异常后，仍然可以安全调用少数几个 JNI 方法：

| `DeleteGlobalRef` | `PopLocalFrame` |
| --- | --- |
| `DeleteLocalRef` | `PushLocalFrame` |
| `DeleteWeakGlobalRef` | `Release<Primitive>ArrayElements` |
| `ExceptionCheck` | `ReleasePrimitiveArrayCritical` |
| `ExceptionClear` | `ReleaseStringChars` |
| `ExceptionDescribe` | `ReleaseStringCritical` |
| `ExceptionOccurred` | `ReleaseStringUTFChars` |
| `MonitorExit` |   |

不要尝试调用其他 JNI 方法。本地代码应尽快清理其资源并将控制权交还给 Java（或者自行处理异常）。实际上，JNI 异常与 C++异常没有任何共同之处。它们的执行流程完全不同。当从本地代码引发 Java 异常时，后者可以继续其处理。但是，一旦本地调用返回并将控制权交还给 Java VM，后者就会像往常一样传播异常。换句话说，从本地代码引发的 JNI 异常只影响 Java 代码（以及之前未列出的其他 JNI 调用）。

## 异常处理 API

JNI 提供了几种用于管理异常的方法，其中包括：

1.  使用`ThrowNew()`来引发异常本身，分配一个新的实例：

    ```java
    jint ThrowNew(jclass clazz, const char* message)
    ```

1.  使用`Throw()`来引发已经分配的异常（例如，重新抛出）：

    ```java
    jint Throw(jthrowable obj)
    ```

1.  使用`ExceptionCheck()`来检查是否有待处理的异常，无论是由谁引发的（本地代码还是 Java 回调）。返回一个简单的`jboolean`，这使得它适合进行简单的检查：

    ```java
    jboolean ExceptionCheck()
    ```

1.  使用`ExceptionOccurred()`获取引发异常的`jthrowable`引用：

    ```java
    jthrowable ExceptionOccurred()
    ```

1.  `ExceptionDescribe()`相当于 Java 中的`printStackTrace()`：

    ```java
    void ExceptionDescribe()
    ```

1.  使用`ExceptionClear()`可以在本地端将异常标记为已捕获：

    ```java
    void ExceptionClear()
    ```

学会如何使用这些方法来编写健壮的代码至关重要，特别是在从本地代码回调 Java 时。我们将在下一章中更深入地学习这个主题。

# 总结

在本章中，我们了解了如何让 Java 与 C/C++进行通信。现在 Android 几乎可以说双语了！Java 可以使用任何类型的数据或对象调用 C/C++代码。

我们首先使用 `JNI_OnLoad` 钩子初始化了一个原生的 JNI 库。然后，在原生代码内部转换 Java 字符串，并了解了修改后的 UTF-8 与 UTF-16 字符编码之间的区别。我们还传递了 Java 基本类型到原生代码。这些基本类型每个都有它们可以转换为的 C/C++ 等效类型。

我们还在原生代码中使用全局引用处理了 Java 对象引用，并学习了全局引用与局部引用之间的区别。前者必须谨慎删除以确保适当的垃圾回收，而后者的作用域为原生方法，并且由于默认数量有限，也必须小心管理。

我们还讨论了如何在原生代码中管理 Java 数组，以便我们可以像操作原生数组一样访问它们的内容。在原生代码中操作数组时，虚拟机可能会也可能不会复制数组。这个性能开销必须考虑在内。

最后，我们在原生代码中抛出并检查了 Java 异常。我们了解到它们的标准 C++ 异常流程是不同的。当异常发生时，只有少数几个清理的 JNI 方法是安全的调用。JNI 异常是 JVM 级别的异常，这意味着它们的流程与标准 C++ 异常完全不同。

然而，还有更多内容等待我们去探索。任何 Java 对象、方法或字段都可以被原生代码调用或检索。让我们在下一章中看看如何从 C/C++ 代码中调用 Java。
