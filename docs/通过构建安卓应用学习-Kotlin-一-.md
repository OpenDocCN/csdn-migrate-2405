# 通过构建安卓应用学习 Kotlin（一）

> 原文：[`zh.annas-archive.org/md5/201D65C8BC4C6A97336C0B7173DD6D6D`](https://zh.annas-archive.org/md5/201D65C8BC4C6A97336C0B7173DD6D6D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

“教育的目的是培养具有技能和专业知识的优秀人才。真正的教育提升了人的尊严，增加了他或她的自尊。如果每个人都能意识到真正的教育，并在人类活动的各个领域中不断推进，世界将会变得更美好。”

— ***Dr. APJ Abdul Kalam***

每天有超过 20 亿的 Android 用户活跃，这种数据覆盖全球数十亿人口，为我们提供了实现改变的真正机会。手机不再仅仅是一种语音通信设备，而是一种能够赋能和赋权给下一个十亿 Android 设备用户的重要角色。

技术的目的是赋能人类，强大设备的可用性为创新提供了机会，可以通过技术改善人们的生活。无论是为农民建立的提供有关天气或作物价格的有用信息的应用，还是为有特殊需求的儿童建立的表达自己的应用，或者为经济困难的妇女建立的经营小型家庭企业的应用，未来的机会是丰富而令人兴奋的。

本书旨在使希望探索 Android 的力量并体验和享受构建 Android 应用的旅程的开发人员能够实现这一目标。这些章节已经组织得很好，使新手开发人员能够理解并从基础开始，或者如果您是经验丰富的开发人员，可以提前了解并探索 Kotlin 的强大之处。

为了使这个应用开发之旅更加有趣和轻松，谷歌已将 Kotlin 作为 Android 应用开发的官方语言之一。Kotlin 表达力强，简洁而强大。它还确保与现有的 Android 语言（如 Java 和运行时）无缝互操作。

# 这本书适合谁

这本书对于任何刚开始学习 Android 应用开发的人都会很有用。学习 Android 应用开发从未如此令人兴奋，因为我们有多种选择的官方支持语言。本书逐步介绍了使用 Kotlin 进行 Android 应用开发所需的所有细节，并使读者在进步的过程中体验这一旅程。

这本书也一定会帮助那些已经使用 Java 进行 Android 应用开发并试图转换到 Kotlin 或评估 Kotlin 易用性的人。熟悉 Java 的 Android 应用开发人员将发现 Java 和 Kotlin 代码之间的比较非常有用，并将能够欣赏 Kotlin 的强大之处。

# 本书内容

本书的目标是确保使用 Java 的高级 Android 应用开发人员和刚开始学习 Android 应用开发的人都能享受阅读本书的乐趣。

第一章提供了有关为 Android 应用开发设置系统的逐步信息，列出了开始所需的所有细节。

第二章详细介绍了为 Kotlin 配置环境所需的步骤。尽管最新稳定版本的 Android Studio 已经内置了 Kotlin 支持，但本章的信息将帮助您配置您选择的开发 IDE。

第三章介绍和讨论了 Kotlin 语言构造的细节，如数据类型、变量和常量。

第四章进一步增强了对语言构造的讨论，提供了有关类和对象的信息，并解释了如何定义和处理它们。

第五章，*类型检查和空安全*，讨论了 Kotlin 的显著特性-类型检查和空安全。Kotlin 通过其设计完全消除了空引用。

第六章，*函数和 Lambda*，提供了有关定义函数并在程序中使用它的信息。本章还讨论了 Lambda 并提供了有关它们使用的信息。

第七章，*开发您的基于位置的闹钟*，讨论了 Google 基于位置的服务的基本原理，使用 Google 地图 API 以及在地图上自定义标记。

第八章，*使用 Google 的位置服务*，展示了如何使用基于位置的服务构建应用程序，并解释了如何构建我们自己的基于位置的闹钟。

第九章，*连接外部世界-网络*，涵盖了网络和与外部世界通信的概念。我们讨论了 Android 框架提供的开箱即用选项，以及像 Picasso 和 Glide 这样的第三方库。

第十章，*开发一个简单的待办事项列表应用程序*，讨论了使用 Android Studio 构建用户界面的方法，并提供了有关使用 ListViews 和 Dialogs 的信息。

第十一章，*使用数据库持久化*，简要介绍了关系数据库，详细讨论了 SQLite 上的 CRUD 操作，并研究了 ORM 的使用，特别是来自 Google 的 Room ORM。

第十二章，*为任务设置提醒*，讨论了如何设置并向用户推送应用程序的通知。它还解释了如何利用 Firebase 和 Amazon SNS 等云服务。我们还讨论了服务和广播接收器。

第十三章，*测试和持续集成*，讨论了测试的重要性，Android Studio 通过 Android 测试支持库提供的开箱即用支持，如何使用 Crashlytics 跟踪崩溃报告以及 Beta 测试。本章还介绍了 CI，并详细介绍了诸如 Jenkins、Bamboo 和 Fastlane 等工具的使用步骤。

第十四章，*使您的应用程序面向全球*，解释了如何将您的应用程序发布到 Google Play 商店和亚马逊应用商店。

第十五章，*使用 Google Faces API 构建应用程序*，讨论了使用 Google Faces API 以及如何构建使用它的应用程序。本章还提供了有关创建 Paint 实例并使用画布绘制图像的信息。本章还讨论了在图像上绘制矩形等形状。

# 要充分利用本书

具有面向对象编程和 Android 活动生命周期知识将很有用，但不是强制性的。

Android Studio 的最新稳定版本（发布时为 3.1.3 版）提供了对 Kotlin 的开箱即用支持。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

文件下载完成后，请确保您使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learning-Kotlin-by-building-Android-Applications`](https://github.com/PacktPublishing/Learning-Kotlin-by-building-Android-Applications)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。以下是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```kt
<dimen name="board_padding">16dp</dimen>
<dimen name="cell_margin">2dp</dimen>
<dimen name="large_text">64sp</dimen>
```

任何命令行输入或输出都是这样写的：

```kt
brew cask install fastlane
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的词在文本中会出现如此。以下是一个例子：“从管理面板中选择系统信息。”

警告或重要说明看起来像这样。

提示和技巧看起来像这样。


# 第一章：为 Android 开发进行设置

Java 是全球使用最广泛的语言之一，直到最近，它还是 Android 开发的首选语言。Java 在其所有伟大之处仍然存在一些问题。多年来，我们看到了许多试图解决 Java 问题的 JVM 语言的发展。其中一个相当新的是 Kotlin。Kotlin 是由 JetBrains 开发的一种新的编程语言，JetBrains 是一家生产软件开发工具的软件开发公司（他们的产品之一是 Android Studio 基于的 IntelliJ IDEA）。

在本章中，我们将看看：

+   Kotlin 在 Android 开发中的优势

+   为 Android 开发做好准备

# 为什么要用 Kotlin 开发 Android？

在所有的 JVM 语言中，Kotlin 是唯一一个为 Android 开发者提供了更多功能的语言。Kotlin 是除了 Java 之外唯一一个与 Android Studio 集成的 JVM 语言。

让我们来看看一些 Kotlin 的惊人特性。

# 简洁

Java 最大的问题之一是冗长。任何尝试在 Java 中编写一个简单的“hello world”程序的人都会告诉你需要多少行代码。与 Java 不同，Kotlin 不是一种冗长的语言。Kotlin 消除了很多样板代码，比如`getters`和`setters`。例如，让我们比较一下 Java 中的 POJO 和 Kotlin 中的 POJO。

**Java 中的学生 POJO**：

```kt
public class Student {

    private String name;

    private String id;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
```

**Kotlin 中的学生 POJO**：

```kt
class Student() {
  var name:String
  var id:String
}
```

正如您所看到的，相同功能的 Kotlin 代码要少得多。

# 告别 NullPointerException

使用 Java 和其他语言的主要痛点之一是访问空引用。这可能导致您的应用程序崩溃，而不向用户显示充分的错误消息。如果您是 Java 开发人员，我相信您对`NullPointerException`非常熟悉。关于 Kotlin 最令人惊讶的一点是空安全性。

使用 Kotlin，`NullPointerException`只能由以下原因之一引起：

+   外部 Java 代码

+   显式调用抛出`NullPointerException`

+   使用`!!`运算符（我们稍后将学习更多关于这个运算符的知识）

+   关于初始化的数据不一致

这有多酷？

# Java 的互操作性

Kotlin 被开发成能够与 Java 舒适地工作。对于开发人员来说，这意味着您可以使用用 Java 编写的库。您还可以放心地使用传统的 Java 代码。而且，有趣的部分是您还可以在 Java 中调用 Kotlin 代码。

这个功能对于 Android 开发者来说非常重要，因为目前 Android 的 API 是用 Java 编写的。

# 设置您的环境

在开始 Android 开发之前，您需要做一些准备工作，使您的计算机能够进行 Android 开发。我们将在本节中逐一介绍它们。

如果您对 Android 开发不是很了解，可以跳过本节。

# Java

由于 Kotlin 运行在 JVM 上，我们必须确保我们的计算机上安装了**Java 开发工具包**（JDK）。如果您没有安装 Java，请跳转到安装 JDK 的部分。如果您不确定，可以按照以下说明检查您的计算机上安装的 Java 版本。

在 Windows 上：

1.  打开 Windows 开始菜单

1.  在 Java 程序列表下，选择关于 Java

1.  将会显示一个弹出窗口，其中包含计算机上 Java 版本的详细信息：![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4a49056b-26e4-482d-a202-f0933799b944.png)

在 Mac 或其他 Linux 机器上：

1.  打开终端应用程序。要做到这一点，打开启动台并在搜索框中输入`终端`。终端应用程序将显示如下截图所示。选择它：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/564cd114-cbd6-44b0-b8aa-58374caa7b39.png)

1.  在终端中，输入以下命令来检查您的计算机上的 JDK 版本：`java -version`

1.  如果你已经安装了 JDK，Java 的版本将会显示在下面的截图中：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/eec560b1-e3c5-4ec0-9112-71bc5b58a0ff.png)

# 安装 JDK

1.  打开浏览器，转到 Java 网站：[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

1.  在“下载”选项卡下，单击 JDK 下的**下载**按钮，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/dc5d2c84-a3e9-4ead-bd29-f3db47e02beb.png)

1.  在下一个屏幕上，选择“接受许可协议”复选框，然后单击与您的操作系统匹配的产品的下载链接

1.  下载完成后，继续安装 JDK

1.  安装完成后，您可以再次运行版本检查命令，以确保您的安装成功

# Android Studio

许多**IDE**支持 Android 开发，但最好和最常用的 Android IDE 是 Android Studio。 Android Studio 基于由 JetBrains 开发的 IntelliJ IDE。

# 安装 Android Studio

转到 Android Studio 页面，[`developer.android.com/sdk/installing/studio.html`](https://developer.android.com/sdk/installing/studio.html)，然后单击“下载 Android Studio”按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b6f19183-98fc-402d-919d-d6242c53fed9.png)

在弹出窗口上，阅读并接受条款和条件，然后单击**下载适用于 Mac 的 Android Studio**按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/82780a3a-bd4f-4e0b-91ff-74c635bc6615.png)

按钮的名称因使用的操作系统而异。

下载将开始，并且您将被重定向到一个说明页面（[`developer.android.com/studio/install`](https://developer.android.com/studio/install)）。

按照您的操作系统的指定说明安装 Android Studio。安装完成后，打开 Android Studio 并开始设置过程。

# 准备 Android Studio

在完整安装屏幕上，请确保选择了“我没有以前的 Studio 版本”或“我不想导入我的设置”选项，然后单击“确定”按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/fd000e7f-e483-4041-a4e1-0ecf44ff09fb.png)

在欢迎屏幕上，单击“下一步”转到安装类型屏幕：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/8172f9df-9d64-4d31-be41-d9dd01fe6821.png)

然后，选择标准选项，然后单击“下一步”继续：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2abf755b-e3c6-4752-8e05-1d9dd00a73b1.png)

在“验证设置”屏幕上，通过单击“完成”按钮确认您的设置：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/1d604ecf-f60a-4e84-b9c1-7bc4cf009bf1.png)

在“验证设置”屏幕上，列出的 SDK 组件将开始下载。您可以单击“显示详细信息”按钮查看正在下载的组件的详细信息：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/7de2a4a6-bf91-4e1e-9154-5c763c61c461.png)

下载和安装完成后，单击“完成”按钮。就是这样。您已经完成了安装和设置 Android Studio。

# 创建您的第一个 Android 项目

在欢迎使用 Android Studio 屏幕上，单击“开始新的 Android Studio 项目”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d6fa10c7-a42f-4ea1-899a-342b2744b84e.png)

这将启动创建新项目向导。在配置新项目屏幕上，将`TicTacToe`输入为应用程序名称。指定公司域。包名称是从公司域和应用程序名称生成的。

将项目位置设置为您选择的位置，然后单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a08bc2ea-00ab-4798-8ec6-5b2476a35c9f.png)

# 选择 SDK

在目标 Android 设备屏幕上，您必须选择设备类型和相应的最低 Android 版本，以便运行您的应用程序。 Android**软件开发工具包（SDK）**提供了构建 Android 应用程序所需的工具，无论您选择的语言是什么。

每个新版本的 SDK 都带有一组新功能，以帮助开发人员在其应用程序中提供更多令人敬畏的功能。然而，困难在于 Android 在非常广泛的设备范围上运行，其中一些设备无法支持最新版本的 Android。这使开发人员在实施出色的新功能或支持更广泛的设备范围之间陷入困境。

Android 试图通过提供以下内容来使这个决定更容易：

+   提供有关使用特定 SDK 的设备百分比的数据，以帮助开发人员做出明智的选择。要在 Android Studio 中查看此数据，请单击最低 SDK 下拉菜单下的“帮助我选择”。这将显示当前支持的 Android SDK 版本列表及其支持的功能，以及如果将其选择为最低 SDK，则应用程序将支持的 Android 设备的百分比：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/0c08ec03-33f9-44cb-b45e-7e64079ca2ca.png)

您可以在 Android 开发者仪表板（[`developer.android.com/about/dashboards/`](https://developer.android.com/about/dashboards/)）上查看最新和更详细的数据。

+   Android 还提供了支持库，以帮助向后兼容某些新功能，这些功能是在较新的 SDK 版本中添加的。每个支持库都向后兼容到特定的 API 级别。支持库通常根据其向后兼容的 API 级别进行命名。一个例子是 appcompat-v7，它提供了对 API 级别 7 的向后兼容性。

我们将在后面的部分进一步讨论 SDK 版本。现在，您可以选择 API 15：Android 4.0.3（冰淇淋三明治）并单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c71d48d9-26d3-4a4c-9b33-6b522d2282a6.png)

接下来的屏幕是“在移动屏幕上添加活动”。这是您选择默认活动的地方。 Android Studio 提供了许多选项，从空白屏幕的活动到带有登录屏幕的活动。现在，选择“基本活动”选项，然后单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6995117e-8d9c-4727-acb3-d4e699534398.png)

在下一个屏幕上，输入活动的名称和标题，以及活动布局的名称。然后，单击**完成**：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/1c55aafe-481a-4e00-82db-da02d9260196.png)

# 构建您的项目

单击“完成”按钮后，Android Studio 会在后台为您生成和配置项目。 Android Studio 执行的后台进程之一是配置 Gradle。

# Gradle

Gradle 是一个易于使用的构建自动化系统，可用于自动化项目的生命周期，从构建和测试到发布。在 Android 中，它接受您的源代码和配置的 Android 构建工具，并生成一个**Android Package** **Kit** (**APK**)文件。

Android Studio 生成了构建初始项目所需的基本 Gradle 配置。让我们来看看这些配置。打开`build.gradle`：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6d7ec561-2c9b-49b9-a16f-93a91945c2a7.png)

Android 部分指定了所有特定于 Android 的配置，例如：

+   `compileSdkVersion`：指定应用程序应使用的 Android API 级别进行编译。

+   `buildToolsVersion`：指定应用程序应使用的构建工具版本。

+   `applicationId`：在发布到 Play 商店时用于唯一标识应用程序。您可能已经注意到，它目前与创建应用程序时指定的包名称相同。在创建时，`applicationId`默认为包名称，但这并不意味着您不能使它们不同。您可以。只是记住，在发布应用程序的第一个版本后，不应再次更改`applicationId`。包名称可以在应用程序的清单文件中找到。

+   `minSdkVersion`：如前所述，这指定了运行应用程序所需的最低 API 级别。

+   `targetSdkVersion`：指定用于测试应用的 API 级别。

+   `versionCode`：指定应用的版本号。在发布之前，每个新版本都应更改此版本号。

+   `versionName`：为您的应用指定一个用户友好的版本名称。

依赖项部分指定了构建应用程序所需的依赖项。

# Android 项目的各个部分

我们将看看项目的不同部分。屏幕截图显示了我们的项目：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/049af957-80d6-464e-83db-de7e64e52102.png)

让我们进一步了解项目的不同部分：

+   `manifests/AndroidManifest.xml`：指定 Android 系统运行应用程序所需的有关应用程序的重要细节。其中一些细节是：

+   包名

+   描述应用程序的组件，包括活动，服务等等

+   声明应用程序所需的权限

+   `res`目录：包含应用程序资源，如图像，xml 布局，颜色，尺寸和字符串资源：

+   `res/layout`目录：包含定义应用程序**用户界面**（**UI**）的 xml 布局

+   `res/menu`目录：包含定义应用程序菜单内容的布局

+   `res/values`目录：包含资源，如颜色（`res/values/colors.xml`）和字符串（`res/values/strings.xml`）

+   以及您的 Java 和/或 Kotlin 源文件

# 运行您的应用程序

Android 使您能够在将应用程序发布到 Google Play 商店之前，就可以在实际设备或虚拟设备上运行您的应用程序。

# Android 模拟器

Android SDK 配备了一个在计算机上运行并利用其资源的虚拟移动设备。这个虚拟移动设备称为模拟器。模拟器基本上是一个可配置的移动设备。您可以配置其 RAM 大小，屏幕大小等。您还可以运行多个模拟器。当您想要在不同的设备配置（如屏幕大小和 Android 版本）上测试应用程序，但又负担不起实际设备时，这是非常有帮助的。

您可以在开发者页面上阅读有关模拟器的更多信息，网址为[`developer.android.com/studio/run/emulator`](https://developer.android.com/studio/run/emulator)。

# 创建 Android 模拟器

Android 模拟器可以从**Android 虚拟设备（AVD）**管理器创建。您可以通过单击 Android Studio 工具栏上的图标来启动 AVD 管理器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/277e67e3-b435-45d8-b687-3854126f325a.png)

或者，通过从菜单中选择工具| Android | AVD 管理器：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d557c18f-0f51-4402-89af-9830d68b1103.png)

在“您的虚拟设备”屏幕上，单击“创建虚拟设备...”按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/df251bfe-c63f-4231-9244-f0acda1c34ec.png)

如果您已经创建了模拟器，按钮将位于屏幕底部：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/9a6ec546-854e-496b-bbd0-70edaca3e78d.png)

下一步是选择要模拟的设备类型。AVD 管理器允许您为电视，手机，平板电脑和 Android 穿戴设备创建模拟器。

确保在屏幕左侧的类别部分中选择“手机”。浏览屏幕中间的设备列表并选择一个。然后，单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4e86bf56-ba32-487c-9826-58ce6e0a4a53.png)

在系统映像屏幕上，选择您希望设备运行的 Android 版本，然后单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c522fc7b-4038-46c4-b48e-231fa030b970.png)

如果您想要模拟的 SDK 版本尚未下载，请单击其旁边的下载链接以下载它。

在验证配置屏幕上，通过单击“完成”按钮来确认虚拟设备设置：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2baedaa3-d90e-4bbf-b949-5ace2d8fe445.png)

您将被发送回“您的虚拟设备”屏幕，您的新模拟器将显示如下：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4178f043-6110-4f5f-b821-d2e16a0d2196.png)

您可以单击“操作”选项卡下的播放图标来启动模拟器，或者单击铅笔图标来编辑其配置。

让我们继续通过单击播放图标来启动刚刚创建的模拟器：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/64294223-858a-495b-bf18-0abfa0823d13.png)

您可能已经注意到，虚拟设备右侧带有一个工具栏。该工具栏称为**模拟器工具栏**。它使您能够模拟功能，如关闭、屏幕旋转、音量增加和减少以及缩放控件。

单击工具栏底部的 More(...)图标还可以让您访问额外的控件，以模拟指纹、设备位置、消息发送、电话呼叫和电池电量等功能：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/79b3d884-c4e7-41cb-a3ea-1c91d9168797.png)

# 从模拟器运行

从模拟器运行您的应用程序非常容易。单击 Android Studio 工具栏上的播放图标，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2b305cd1-b362-4c4a-a312-4f357abde8d6.png)

在弹出的“选择部署目标”屏幕上，选择要在其上运行应用程序的设备，然后单击“确定”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/8405a62d-497c-4a9e-b218-3f8bbcacb4ff.png)

Android Studio 将在模拟器上构建和运行您的应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/5aecaf19-654f-454f-8213-6e658bab6a2e.png)

如果您尚未运行模拟器，您的模拟器将显示在***可用虚拟设备***部分下。选择它们将启动模拟器，然后在其上运行您的应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/088f6a76-9f8b-4257-9a33-d0d6e2a38ed7.png)

# 在实际设备上运行

要在实际设备上运行您的应用程序，您可以构建并将 APK 复制到设备上，并从那里运行。为此，Android 要求设备启用允许从未知来源安装应用程序的选项。请执行以下步骤：

1.  在您的设备上打开“设置”应用程序。

1.  选择“安全”。

1.  查找并打开“未知来源”选项。

1.  您将收到有关从未知来源安装应用程序的危险的提示。仔细阅读并单击“确定”以确认。

1.  就是这样。您现在可以上传您的 APK 并在手机上运行它。

您可以通过返回到“设置”|“安全”并关闭该选项来轻松禁用“未知来源”设置。

我们都可以同意以这种方式运行您的应用程序并不是非常理想的，特别是用于调试。考虑到这一点，Android 设备具有在不必将应用程序上传到设备的情况下非常轻松地运行和调试应用程序的能力。这可以通过连接设备使用 USB 电缆来完成。为此，Android 要求启用开发者模式。请按照以下说明启用开发者模式：

1.  在您的设备上打开“设置”应用程序。

1.  向下滚动并选择“关于手机”。

1.  在“手机状态”屏幕上，向下滚动并点击“版本号”多次，直到看到一个提示，上面写着“您现在是开发者！”

1.  返回到“设置”屏幕。现在应该会看到“开发人员选项”条目。

1.  选择“开发人员选项”。

1.  在“开发人员选项”屏幕上，打开屏幕顶部的开关。如果关闭，您将收到一个“允许开发设置？”对话框。单击“确定”以确认。

1.  向下滚动并打开 USB 调试。您将收到一个**允许 USB 调试？**对话框。单击“确定”以确认。

1.  接下来，通过 USB 将您的设备连接到计算机。

1.  您将收到另一个***允许 USB 调试？***对话框，其中包含您计算机的 RSA 密钥指纹。选择“始终允许此计算机”选项，然后单击“确定”以确认。

您现在可以在设备上运行您的应用程序。再次单击工具栏上的“运行”按钮，在“选择部署目标”对话框中选择您的设备，并单击“确定”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b3f241b8-d7b1-4747-be3b-c305f8c68bad.png)

就是这样。您现在应该在您的设备上看到您的应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/5f305bda-f5ac-4a32-81cf-87927112b045.png)

# 摘要

在本章中，我们经历了检查和安装 JDK 的过程，这是 Android 开发所必需的。我们还安装并设置了我们的 Android Studio 环境。我们创建了我们的第一个 Android 应用程序，并学会在模拟器和实际设备上运行它。

在下一章中，我们将学习如何配置和设置 Android Studio 和我们的项目以使用 Kotlin 进行开发。


# 第二章：为 Kotlin 配置您的环境

在本章中，我们将介绍准备 Android Studio 和配置我们在上一章中创建的项目以进行 Kotlin 开发的过程。

在这个过程中，我们将学习如何：

+   在 Android Studio 中下载并安装 Kotlin 插件

+   在 Android 项目中配置 Kotlin

+   在 Kotlin 类中引用 Java 代码，反之亦然

+   将 Java 类转换为 Kotlin 类

# 安装 Kotlin 插件

要在项目中使用 Kotlin，首先必须在 Android Studio 中安装 Kotlin 插件：

1.  选择 Android Studio | 首选项，并在首选项窗口中选择插件：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6eeca930-ba23-4cba-9262-9e4593ecaf45.png)

1.  在插件窗口上，点击屏幕底部的“安装 JetBrains 插件...”按钮：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/fbe19542-89f2-4282-a428-71b6b3ba60ac.png)

1.  在 Jetbrains 插件浏览屏幕上，搜索`Kotlin`并从选项列表中选择 Kotlin。然后，点击**安装**按钮：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/fcff73cc-716a-4821-acc3-22f88a3cfe8d.png)

1.  下载和安装完成后，点击“重新启动 Android Studio”按钮以重新启动 IDE。

最新版本的 Android Studio 和 3.0 以上的版本提供了对 Kotlin 的全面支持。在 3.0 以下的版本中，可以通过安装插件来启用 Kotlin 支持，如前所示。

# 使我们的项目准备好使用 Kotlin

要能够开始向我们的项目添加 Kotlin 代码，首先必须配置我们的项目以支持 Kotlin。

1.  首先，选择工具 | Kotlin | 配置项目中的 Kotlin：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/7b44bfcd-6216-469f-b715-425541d334a2.png)

1.  接下来，在选择配置器弹出窗口中选择带 Gradle 的 Android 选项：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/84bd81bf-8e66-44a3-8405-37b1770dff0f.png)

1.  在带 Gradle 的 Android 中配置 Kotlin 弹出窗口中，选择要使用的 Kotlin 版本，然后点击确定：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e4f8234b-101b-466a-b2c2-6964455982c4.png)

建议保留默认选择的版本，因为这通常是最新版本。

这将导致项目中的`build.gradle`文件发生一些变化：

+   在项目的`build.gradle(Project:TicTacToe)`文件中，应用了以下更改：

+   声明项目中使用的 Kotlin 插件的版本

+   Kotlin Gradle 插件被声明为项目的类路径依赖之一：！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/74bb5c89-3e61-479d-bba4-f95c7d7eafa5.png)

+   在应用模块的`build.gradle(Module:app)`文件中，应用了以下更改：

+   `kotlin-android`插件应用于模块

+   Kotlin 的`Standard`库被声明为应用模块的`compile`时依赖：！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/43fba6df-86e6-4d68-bc59-435746142b29.png)

+   点击**立即同步**以构建项目

从 Android Studio 3.0 开始，Android Studio 内置了 Kotlin 支持。因此，您无需安装 Kotlin 插件即可使用它。

现在我们已经完全配置了 Kotlin，让我们试试它。

# Kotlin 和 Java 并存？

Kotlin 的一个令人惊奇的特点是它能够与 Java 在同一个项目中共存和工作。

让我们尝试创建一个 Kotlin 类。Android Studio Kotlin 插件使这一过程与创建 Java 类一样简单。选择**文件** | **新建** | **Kotlin 文件/类**：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/cb81df55-069c-4ff5-bbd4-86c507398631.png)

在**新建 Kotlin 文件/类**弹出窗口中，输入类的名称，从**种类**下拉菜单中选择`Class`，然后点击确定：

！[](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/0587550e-c61c-42d0-a07a-a892ade2b6ef.png)

新类看起来是这样的：

```kt
package com.packtpub.eunice.tictactoe

class HelloKotlin {
}
```

Kotlin 中的默认可见性修饰符是 public，因此无需像在 Java 类中那样指定 public 修饰符。

让我们在我们的新 Kotlin 类中添加以下方法：

```kt
fun displayMessage(view: View) {
    Snackbar.make(view, "Hello Kotlin!!", Snackbar.LENGTH_LONG).setAction("Action", null).show()
}
```

前面的方法将一个 Android 视图（`android.view.View`）作为参数，并将其与消息一起传递给 Snackbar 的`make()`方法以显示消息。

Kotlin 能够使用 Java 代码的能力称为**互操作性**。这个功能也可以反过来工作，允许从 Java 类调用 Kotlin 代码。让我们试试看：

打开`MainActivity.java`。在`onCreate()`方法中，用以下代码替换以下行：

```kt
Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG).setAction("Action", null).show();
```

用以下内容替换：

```kt
new HelloKotlin().diplayMessage(view);
```

代码的前一行创建了`HelloKotlin`类的一个实例，并调用了它的`displayMessage()`方法。

构建并运行您的应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/267e173e-9907-49f9-b95b-556a5f8d1910.png)

是的，就是这么简单。

# Kotlin 转 Java？

到目前为止，我们已经学习了创建 Kotlin 类并在`MainActivity.java`类中访问其方法的过程。我们的项目目前包括一个 Java 类和一个 Kotlin 类，但我们希望整个项目都是 Kotlin。那么，我们该怎么办？我们需要将`MainActivity.java`类重写为 Kotlin 吗？不需要。Kotlin 插件添加到 Android Studio 的功能之一是能够将 Java 代码转换为 Kotlin 的能力。

要做到这一点，请打开`MainActivity.java`类，然后转到“代码”|“将 Java 文件转换为 Kotlin 文件”：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/6c02e694-1bd4-424b-9880-e4dea0958994.png)

您将收到有关转换准确性的警告消息。目前，我们不需要担心这个问题。只需单击“确定”继续：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/892ad161-1aad-4260-84fd-a0261b1784f4.png)

您的`MainActivity.java`类现在应该是这样的：

```kt
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val toolbar = findViewById(R.id.toolbar) as Toolbar
        setSupportActionBar(toolbar)

        val fab = findViewById(R.id.fab) as FloatingActionButton
        fab.setOnClickListener { view ->   
    HelloKotlin().displayKotlinMessage(view) }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is   
       //present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        val id = item.itemId

        return if (id == R.id.action_settings) {
            true
        } else super.onOptionsItemSelected(item)

    }
}
```

您还会注意到文件的扩展名也已更改为`.kt`。

再次构建并运行您的应用程序：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/673bf8ad-1f55-43ea-bcd7-846405f8d22d.png)

# 总结

在本章中，我们学习了如何为 Kotlin 开发配置 Android Studio 和 Android 项目。我们还学习了如何从 Java 创建和调用 Kotlin 类。我们还学习了使用 Kotlin 插件将 Java 源文件转换为 Kotlin。如果您有用 Java 编写的旧代码，并且想逐渐转换为 Kotlin，这些功能特别有帮助。

在使用`Convert Java to Kotlin`功能时，请记住，在某些情况下，您需要对生成的 Kotlin 文件进行一些更正。

在接下来的几章中，我们将为我们的项目添加更多功能（您可能已经猜到，这是一个简单的**井字棋**游戏）。在这个过程中，我们将更深入地了解 Kotlin 作为一种语言的基础知识。我们将涵盖诸如数据类型、类、函数、协程和空安全等主题。


# 第三章：数据类型、变量和常量

在本章中，我们将开始构建我们的井字游戏，同时学习 Kotlin 中的数据类型、变量和常量。

到本章结束时，我们将有：

+   检查了应用程序的当前 UI

+   设计了游戏的 UI

+   在 Kotlin 中学习了基本类型

# 用户界面

在 Android 中，应用程序 UI 的代码是用 XML 编写的，并存储在布局文件中。让我们来看看在创建项目时创建的默认 UI。

打开 `res/layout/activity_main.xml`。确保在屏幕底部选择了 Text。Android Studio 应该会显示右侧的预览和 UI 的 XML 代码：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/b0b66a1e-2348-4f1c-b91f-44361838752a.png)

如果您在右侧看不到预览，请转到 View | Tool Windows | Preview 启用它。

现在，让我们来看看主活动布局的各个元素：

1.  父元素是 `CoordinatorLayout`。`CoordinatorLayout` 在 Android 5.0 中作为设计库的一部分引入。它提供了更好的控制，可以在其子视图之间进行触摸事件。当单击按钮时，我们已经看到了这种功能是如何工作的，`SnackBar` 出现在 `FloatingActionButton` 下方（而不是覆盖它）。

1.  标记为 `2` 的元素是 `Toolbar`，它充当应用程序的顶部导航。通常用于显示应用程序的标题、应用程序标志、操作菜单和导航按钮。

1.  `include` 标签用于将一个布局嵌入到另一个布局中。在这种情况下，`res/layout/content_main.xml` 文件包含了我们在运行应用程序时看到的 `TextView`（显示 Hello World! 消息）。我们的大多数 UI 更改将在 `res/layout/content_main.xml` 文件中完成。

1.  `FloatingActionButton`，您可能已经注意到，是一个可操作的浮动在屏幕上的 `ImageView`。

# 构建我们的游戏 UI

我们的井字游戏屏幕将包括游戏板（一个 3x3 的网格）、显示轮到谁了的 `TextView` 和用于重新开始游戏的 `FloatingActionButton`。

我们将使用 `TableLayout` 来设计游戏板。打开 `res/layout/content_main.xml` 文件，并将 `TextView` 声明替换为 `TableLayout` 声明，如下所示：

```kt
<TableLayout
    android:id="@+id/table_layout"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    app:layout_constraintBottom_toBottomOf="parent"
    app:layout_constraintLeft_toLeftOf="parent"
    app:layout_constraintRight_toRightOf="parent"
    app:layout_constraintTop_toTopOf="parent"
    android:gravity="center">

    <TableRow
        android:id="@+id/r0"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:gravity="center_horizontal"
        android:background="@android:color/black">
        <TextView
            android:layout_width="100dp"
            android:layout_height="100dp"
            android:gravity="center"
            android:background="@android:color/white"
            android:layout_marginBottom="2dp"
            android:layout_marginTop="0dp"
            android:layout_column="0"
            android:layout_marginRight="2dp"
            android:layout_marginEnd="2dp"
            android:textSize="64sp"
            android:textColor="@android:color/black"
            android:clickable="true"/>
        <TextView
            android:layout_width="100dp"
            android:layout_height="100dp"
            android:gravity="center"
            android:background="@android:color/white"
            android:layout_marginBottom="2dp"
            android:layout_marginTop="0dp"
            android:layout_column="2"
            android:layout_marginRight="2dp"
            android:layout_marginEnd="2dp"
            android:textSize="64sp"
            android:textColor="@android:color/black"
            android:clickable="true"/>
        <TextView
            android:layout_width="100dp"
            android:layout_height="100dp"
            android:gravity="center"
            android:background="@android:color/white"
            android:layout_marginBottom="2dp"
            android:layout_marginTop="0dp"
            android:layout_column="2"
            android:layout_marginRight="2dp"
            android:layout_marginEnd="2dp"
            android:textSize="64sp"
            android:textColor="@android:color/black"
            android:clickable="true"/>
    </TableRow>

    </TableLayout>
```

这里有几件事情需要注意：

+   `TableRow` 元素表示表格的一行。从前面的代码中，行的每个元素都由一个 `TextView` 表示。

+   每个 `TextView` 都具有相似的属性。

+   前面的代码声明了一个 1x3 的表格，换句话说，是一个具有一行和三列的表格。由于我们想要创建一个 3x3 的网格，我们需要添加另外两个 `TableRow` 元素。

前面的代码已经包含了很多重复的代码。我们需要找到一种方法来减少重复的数量。这就是 `res/values` 的作用所在。

在添加两个额外的 `TableRow` 元素之前，让我们更好地组织我们的代码。打开 `res/values/styles.xml` 并添加以下代码：

```kt
<!--Table Row Attributes-->
<style name="TableRow">
    <item name="android:layout_width">match_parent</item>
    <item name="android:layout_height">wrap_content</item>
    <item name="android:gravity">center_horizontal</item>
    <item name="android:background">@android:color/black</item>
</style>

<!--General Cell Attributes-->
<style name="Cell">
    <item name="android:layout_width">100dp</item>
    <item name="android:layout_height">100dp</item>
    <item name="android:gravity">center</item>
    <item name="android:background">@android:color/white</item>
    <item name="android:layout_marginTop">@dimen/cell_margin</item>
    <item name="android:layout_marginBottom">@dimen/cell_margin</item>
    <item name="android:textSize">@dimen/large_text</item>
    <item name="android:textColor">@android:color/black</item>
    <item name="android:clickable">true</item>

</style>

<!--Custom Left Cell Attributes-->
<style name="Cell.Left">
    <item name="android:layout_column">0</item>
    <item name="android:layout_marginRight">@dimen/cell_margin</item>
</style>

<!--Custom Middle Cell Attributes-->
<style name="Cell.Middle">
    <item name="android:layout_column">1</item>
    <item name="android:layout_marginRight">@dimen/cell_margin</item>
    <item name="android:layout_marginLeft">@dimen/cell_margin</item>
</style>

<!--Custom Right Cell Attributes-->
<style name="Cell.Right">
    <item name="android:layout_column">2</item>
    <item name="android:layout_marginLeft">@dimen/cell_margin</item>
</style>
```

您可以通过以 **Parent.child** 的格式命名它们来创建继承自父级的子样式，例如，`Cell.Left`、`Cell.Middle` 和 `Cell.Right` 都继承了 `Cell` 样式的属性。

接下来，打开 `res/values/dimens.xml`。这是您在布局中声明的尺寸。将以下代码添加到资源元素中：

```kt
<dimen name="board_padding">16dp</dimen>
<dimen name="cell_margin">2dp</dimen>
<dimen name="large_text">64sp</dimen>
```

现在，打开 `res/values/strings.xml`。这是您在应用程序中声明所需的字符串资源。在资源元素中添加以下代码：

```kt
<string name="x">X</string>
<string name="o">O</string>
<string name="turn">%1$s\'s Turn</string>
<string name="winner">%1$s Won</string>
<string name="draw">It\'s a Draw</string>
```

然后，打开 `res/layout/content_main.xml` 文件，并将 `TableRow` 声明替换为以下内容：

```kt
<TableRow
    android:id="@+id/r0"
    style="@style/TableRow">
    <TextView
        style="@style/Cell.Left"
        android:layout_marginTop="0dp"/>
    <TextView
        style="@style/Cell.Middle"
        android:layout_marginTop="0dp"/>
    <TextView
        style="@style/Cell.Right"
        android:layout_marginTop="0dp"/>
</TableRow>
<TableRow
    android:id="@+id/r1"
    style="@style/TableRow">
    <TextView
        style="@style/Cell.Left"/>
    <TextView
        style="@style/Cell.Middle"/>
    <TextView
        style="@style/Cell.Right"/>
</TableRow>

<TableRow
    android:id="@+id/r2"
    style="@style/TableRow">

    <TextView
        style="@style/Cell.Left"
        android:layout_marginBottom="0dp"/>
    <TextView
        style="@style/Cell.Middle"
        android:layout_marginBottom="0dp"/>
    <TextView
        style="@style/Cell.Right"
        android:layout_marginBottom="0dp"/>
</TableRow>
```

我们现在已经声明了所有三行。正如您所看到的，我们的代码看起来更有组织性。

构建并运行以查看到目前为止的进展：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/5d316414-e6f5-479e-961e-2cc66ae1f21b.png)

让我们继续添加一个 `TextView`，用于显示轮到谁了。打开 `res/layout/activity_main.xml` 并在 `include` 元素之前添加以下 `TextView` 声明：

```kt
<TextView
    android:id="@+id/turnTextView"
    app:layout_behavior="@string/appbar_scrolling_view_behavior"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:text="@string/turn"
    android:textSize="64sp"
    android:textAlignment="center"
    android:layout_marginTop="@dimen/fab_margin"/>
```

通过替换以下代码来改变`FloatingActionButton`的图标和背景颜色：

```kt
app:srcCompat="@android:drawable/ic_dialog_email" 
```

使用以下内容：

```kt
app:srcCompat="@android:drawable/ic_input_add"
app:backgroundTint="@color/colorPrimary"
```

再次构建和运行：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/1eeca583-e07a-4afc-9d8a-8b44dec6da87.png)

就这样。我们完成了 UI 设计。

# 基本类型

在 Kotlin 中，没有原始数据类型的概念。所有类型都是带有成员函数和属性的对象。

# 变量和常量

使用`var`关键字声明变量，并使用`val`关键字声明常量。在声明变量或常量时，不必显式定义其类型。类型将从上下文中推断出来。`val`只能初始化一次。只有在明确声明为可空类型时，变量或常量才能被赋予空值。通过在类型的末尾添加`?`来声明可空类型：

```kt
var a: String = "Hello"
var b = "Hello"

val c = "Constant"
var d: String? = null // nullable String

b = null // will not compile

b = 0 // will not compile
c = "changed" // will not compile
```

例如，在上面的代码中，`a`和`b`都将被视为`String`。当尝试重新分配推断类型的变量时，不同类型的值将引发错误。`val`只能初始化一次。

# 属性

在 Kotlin 中，通过简单地引用名称来访问属性。尽管`getter`和`setter`不是必需的，但你也可以创建它们。属性的`getter`和/或`setter`可以作为其声明的一部分创建。如果属性是`val`，则不允许有`setter`。属性需要在创建时初始化：

```kt
var a: String = ""              // required
    get() = this.toString()     // optional
    set(v) {                    // optional
        if (!v.isEmpty()) field = v
    }
```

让我们继续声明一些我们在`MainActivity`类中需要的属性：

```kt
var gameBoard : Array<CharArray> = Array(3) { CharArray(3) } // 1
var turn = 'X' // 2
var tableLayout: TableLayout? = null // 3
var turnTextView: TextView? = null // 4

```

1.  `gameBoard`是一个 3x3 的矩阵，表示一个井字棋游戏板。它将用于存储棋盘上每个单元格的值。

1.  `turn`是一个 char 类型的变量，用于存储当前是谁的回合，X 还是 O。

1.  `tableLayout`是一个`android.widget.TableLayout`，将在`onCreate()`方法中用 xml 布局中的视图进行初始化。

1.  `turnTextView`是一个`android.widget.TextView`，用于显示当前是谁的回合。这也将在`onCreate()`方法中用 xml 布局中的视图进行初始化。

# 总结

在本章中，我们为简单的井字棋游戏设计了用户界面。我们还学习了如何在 Kotlin 中使用变量和常量。

在下一章中，我们将继续实现游戏逻辑，同时学习类和对象。


# 第四章：类和对象

在本章中，我们将继续在学习 Kotlin 中的类和对象的同时继续开发我们的 TicTacToe 游戏。

在本章结束时，我们将有：

+   在 Kotlin 中学习了类和对象

+   为游戏的一部分逻辑工作

# 类的结构

就像 Java 一样，在 Kotlin 中，使用`class`关键字声明类。类的基本结构包括：

+   `class`关键字

+   类的名称

+   页眉

+   类的主体用大括号括起来

页眉可以由主构造函数、父类（如果适用）和要实现的接口（如果适用）组成。

在四个部分中，只有前两个是强制的。如果类没有主体，您可以跳过大括号。

# 构造函数

就像在 Java 中一样，类可以有多个构造函数，但是在 Kotlin 中，主构造函数可以作为类的页眉的一部分添加。

例如，让我们向`HelloKotlin`类添加一个构造函数：

```kt
import kotlinx.android.synthetic.main.activity_main.*

class HelloKotlin constructor(message: String) {

    fun displayKotlinMessage(view: View) {
        Snackbar.make(view, "Hello Kotlin!!",
        Snackbar.LENGTH_LONG).setAction("Action", null).show()
    }
}
```

在先前的代码中，`HelloKotlin`类具有一个主构造函数，该构造函数接受一个名为`message`的字符串。

由于构造函数没有任何修饰符，因此我们可以完全摆脱`constructor`关键字：

```kt
class HelloKotlin (message: String) {

    fun displayKotlinMessage(view: View) {
        Snackbar.make(view, "Hello Kotlin!!", 
        Snackbar.LENGTH_LONG).setAction("Action", null).show()
    }

}
```

在 Kotlin 中，次要构造函数必须调用主构造函数。让我们看一下代码：

```kt
class HelloKotlin (message: String) {

    constructor(): this("Hello Kotlin!!")

    fun displayKotlinMessage(view: View) {
        Snackbar.make(view, "Hello Kotlin!!", 
        Snackbar.LENGTH_LONG).setAction("Action", null).show()
    }
}
```

关于次要构造函数的一些注意事项：

+   它不接受任何参数。

+   它使用默认消息调用主构造函数。

+   它不使用大括号。这是因为它没有主体，因此不需要大括号。如果我们添加一个主体，我们将需要使用大括号。

如果`displayKotlinMessage()`方法想要使用构造函数中传递的`message`参数，该怎么办？

有两种方法可以解决这个问题。您可以在`HelloKotlin`中创建一个字段，并使用传递的`message`参数进行初始化：

```kt
class HelloKotlin (message: String) {

    private var msg = message

    constructor(): this("Hello Kotlin!!")

    fun displayKotlinMessage(view: View) {
        Snackbar.make(view, msg, 
        Snackbar.LENGTH_LONG).setAction("Action", null).show()
    }
}
```

您还可以向`message`参数添加适当的关键字，使其成为类的字段：

```kt
class HelloKotlin (private var message: String) {

    constructor(): this("Hello Kotlin!!")

    fun displayKotlinMessage(view: View) {
        Snackbar.make(view, message, 
        Snackbar.LENGTH_LONG).setAction("Action", null).show()
    }
}
```

让我们试一下我们所做的更改。在`MainActivity`类的`onCreate()`方法中，让我们替换`HelloKotlin`初始化：

```kt
HelloKotlin().displayKotlinMessage(view)
```

我们将其替换为一个初始化，该初始化还传递了一条消息：

```kt
HelloKotlin("Get ready for a fun game of Tic Tac Toe").displayKotlinMessage(view)
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/cfb906c5-b284-4f86-846e-1f1ea1bb9db6.png)

单击 FloatingActionButton 时，传递的消息将显示在底部。

# 数据类

构建应用程序时，我们大多数时候需要的是仅用于存储数据的类。在 Java 中，我们通常使用 POJO。在 Kotlin 中，有一个称为**数据类**的特殊类。

假设我们想为我们的 TicTacToe 游戏保留一个记分牌。我们将如何存储每个游戏会话的数据？

在 Java 中，我们将创建一个 POJO，用于存储有关游戏会话的数据（游戏结束时的板和游戏的获胜者）：

```kt
public class Game {

    private char[][] gameBoard;
    private char winner;

    public Game(char[][] gameBoard, char winner) {
        setGameBoard(gameBoard);
        setWinner(winner);
    }

    public char[][] getGameBoard() {
        return gameBoard;
    }

    public void setGameBoard(char[][] gameBoard) {
        this.gameBoard = gameBoard;
    }

    public char getWinner() {
        return winner;
    }

    public void setWinner(char winner) {
        this.winner = winner;
    }
}
```

在 Kotlin 中，这大大简化为：

```kt
data class Game(var gameBoard: Array<CharArray>, var winner: Char)
```

前一行代码与前面的 26 行 Java 代码执行相同的操作。它声明了一个`Game`类，该类在其主构造函数中接受两个参数。正如前面所述，不需要`getters`和`setters`。

Kotlin 中的数据类还带有许多其他方法：

+   `equals()`/`hashCode()`对

+   `toString()`

+   `copy()`

如果您曾经编写过任何 Java 代码，您应该熟悉`equals()`、`hashCode()`和`toString()`。让我们继续讨论`copy()`。

当您想要创建对象的副本，但部分数据已更改时，`copy()`方法非常方便，例如：

```kt
data class Student(var name: String, var classRoomNo: Int, var studentId: Int) // 1

var anna = Student("Anna", 5, 1) // 2
var joseph = anna.copy("Joseph", studentId = 2) // 3
```

在前面的代码片段中：

1.  我们声明了一个名为`Student`的数据类。它在其主构造函数中接受三个参数：`name`、`classRoomNo`和`studentId`。

1.  `anna`变量是`Student`的一个实例，具有以下属性：`name:Anna`、`classRoomNo:5`和`studentId:1`。

1.  变量`joseph`是通过复制`anna`并更改两个属性——`name`和`studentId`而创建的。

# 对象

在我们深入讨论对象之前，让我们对 TicTacToe 游戏进行一些添加。让我们初始化我们的视图。将以下代码添加到`MainActivity`类中的`onCreate()`方法：

```kt
turnTextView = findViewById(R.id.turnTextView) as TextView // 1

tableLayout = findViewById(R.id.table_layout) as TableLayout // 2

startNewGame(true)
```

将以下方法添加到`MainActivity`类中：

```kt
private fun startNewGame(setClickListener: Boolean) {
    turn = 'X'
    turnTextView?.text = 
    String.format(resources.getString(R.string.turn), turn)
    for (i in 0 until gameBoard.size) {
        for (j in 0 until gameBoard[i].size) {
            gameBoard[i][j] = ' '
            val cell = (tableLayout?.getChildAt(i) as 
            TableRow).getChildAt(j) as TextView
            cell.text = ""
            if (setClickListener) {
            }
        }
    }
}

private fun cellClickListener(row: Int, column: Int) {
    gameBoard[row][column] = turn
    ((tableLayout?.getChildAt(row) as TableRow).getChildAt(column) as TextView).text = turn.toString()
    turn = if ('X' == turn) 'O' else 'X'
    turnTextView?.text = String.format(resources.getString(R.string.turn), turn)
}
```

1.  在一和二中，我们使用 XML 布局中对应的视图初始化`turnTextView`和`tableLayout`。

1.  在`startNewGame()`中：

+   我们重新初始化`turn`

+   我们将`turnTextView`设置为显示`turn`的值

+   我们重置了`gameBoard`的所有值

+   我们将`tableLayout`的所有单元格重置为空字符串

1.  在`cellClickListener()`中：

+   我们根据传递给`cellClickListener()`的参数将`turn`的值设置为`gameBoard`的特定元素

+   我们还将`tableLayout`上对应单元格的值更改为`turn`

+   我们根据`turn`的先前值将`turn`的值更改为下一个玩家

+   我们将`turnTextView`上显示的值更改为`turn`的新值

每次单元格被点击时，我们需要调用`cellClickListener()`。为此，我们需要为每个单元格添加一个点击侦听器。在 Android 中，我们使用`View.OnClickListener`。由于`View.OnClickListener`是一个接口，我们通常创建一个实现其方法的类，并将该类设置为我们的点击侦听器。

Java 和 Kotlin 都有简化此过程的方法。在 Java 中，您可以通过使用**匿名内部类**来绕过它。匿名内部类允许您同时声明和创建类的实例：

```kt
// Java Anonymous Inner Class
cell.setOnClickListener(new View.OnClickListener() {
    @Override
    public void onClick(View v) {

    }
});
```

在上述代码中，我们声明并创建了一个实现`View.OnClickListener`接口的类的实例。

在 Kotlin 中，这是使用**对象表达式**完成的。

将以下代码添加到`startNewGame()`方法中`if(setClickListener)`语句的主体中：

```kt
cell.setOnClickListener(object : View.OnClickListener {
    override fun onClick(v: View?) {
        cellClickListener(i, j)
    }
})
```

Kotlin 允许我们进一步简化先前的代码行。我们将在第六章中讨论这一点，*函数和 Lambda*，当我们谈论**Lambda**时。

构建并运行。现在，当您点击任何单元格时，其中的文本将更改为`turnTextView`的文本，并且`turnTextView`的值也将更改为下一个玩家的值：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/da55dc44-f34e-4334-9a05-80533dcae777.png) ![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a841870d-23cd-4b56-9c44-a4dd9e6b791e.png)

# 摘要

在本章中，我们学习了类、数据类和对象表达式，同时初始化了我们的视图并为我们的游戏应用程序添加了额外的逻辑。

在下一章中，我们将深入讨论类型检查和空安全性，以及为什么 Kotlin 的这些特性使其成为最安全的语言之一。


# 第五章：类型检查和空安全

如第一章*所述，为 Android 开发设置*，Kotlin 带来的一个伟大特性是**空安全**。在本章中，我们将学习 Kotlin 是如何成为一个空安全语言的，以及我们如何充分利用它。

在本章结束时，我们将学到：

+   非空和可空类型

+   安全调用操作符

+   Elvis 操作符

+   `!!`操作符

+   安全和不安全的类型转换操作符

# 空安全

Java 和其他许多语言中开发者最常见的痛点之一是访问空引用的成员。在大多数语言中，这会导致运行时的空引用异常。大多数 Java 开发者将其称为`NullPointerException`。

Kotlin 旨在尽可能消除空引用和异常的可能性。如第一章中所述，*为 Android 开发设置*，在 Kotlin 中，你可能遇到`NullPointerException`的四个可能原因：

+   外部 Java 代码

+   显式调用抛出`NullPointerException`

+   使用`!!`操作符（我们稍后会学到更多关于这个操作符的知识）

+   关于初始化的数据不一致性

那么 Kotlin 是如何确保这一点的呢？

# 可空和非空类型

**可空类型**是允许保存`null`值的引用，而**非空类型**是不能保存`null`值的引用。

Kotlin 的类型系统设计用于区分这两种引用类型。可空类型通过在类型末尾添加`?`来声明。例如：

```kt
var name: String = "Anna" // non-nullable String
var gender: String? = "Female" //nullable String

name = null // will not compile
gender = null // will compile

print("Length of name is ${name.length}") // will compile

print("Length of gender is ${gender.length}") // will not compile

```

在先前的代码中有一些需要注意的事项：

+   `name`不能被赋予`null`值，因为它是非空类型

+   另一方面，`gender`可以被赋予`null`值，因为它声明为可空类型

+   无法像访问`name`的成员方法或属性一样访问`gender`的成员方法或属性

有多种方式可以访问可空类型的方法或属性。你可以在条件中检查`null`并访问方法或属性。例如：

```kt
if (gender != null) {
    print("Length of gender is ${gender.length}") 
}
```

编译器跟踪`null`检查的结果，因此允许在`if`条件的主体中调用`length`。这是一个**智能转换**的例子：

+   使用安全调用操作符(`?.`)

+   使用 Elvis 操作符(`?:`)

+   使用`!!`操作符

+   执行智能转换

智能转换是 Kotlin 中的一个智能功能，编译器会跟踪`if`语句的结果，并在需要时自动执行转换。

# 安全调用操作符

访问可空类型的方法或属性的另一种方式是使用安全调用操作符：

```kt
val len = gender?.length
print("Length of gender is $len")
```

在先前的代码中，如果 gender 不为`null`，则`len`的值将是`gender.length`的结果。否则，`len`的值将为`null`。

如果在`gender`为`null`时不需要执行任何操作，使用安全调用操作符是很好的。如果我们想在`gender`为`null`时为`len`赋予不同的值，我们可以将安全调用操作符与**Elvis 操作符**结合使用。

# Elvis 操作符

Elvis 操作符类似于 Java 中的三元`if`操作符。它是简化`if-else`语句的一种方式。例如：

```kt
val len = if (gender != null) gender.length else 0
```

代码可以简化为：

```kt
val len = gender?.length ?: 0
```

在先前的代码中，如果`gender?.length`的值为`null`，则`len`的值将为`0`。

# !!操作符

如果我们不在乎遇到空指针异常，那么我们可以使用`!!`操作符。例如：

```kt
val len = gender!!.length
```

如果`gender`为`null`，则会导致空指针异常。

只有在确定变量的值或者不在乎遇到空指针异常时才使用`!!`操作符。

# 类型检查

就像在 Java 中一样，你可以确认变量的类型。在 Kotlin 中，使用`is`操作符来实现。例如：

```kt
if (gender is String) {
    println("Length of gender is ${gender.length}") // gender is automatically cast to a String
}
```

就像之前的 `null` 检查一样，编译器会跟踪类型检查的结果，并自动将 `gender` 转换为 `String`，从而允许调用 `gender.length`。这被称为智能转换。

# 转换运算符

要将变量转换为另一种类型，您必须使用转换运算符（`as`）：

```kt
var fullname: String = name as String
```

如果您尝试将变量转换为的类型不是您要转换的类型，则转换运算符将抛出错误。为了防止这种情况，您可以使用**安全转换运算符**（`as?`）：

```kt
var gen: String? = gender as? String
```

安全转换运算符不会抛出错误，而是在转换不可能时返回 `null`。

# 总结

在本章中，我们学习了 Kotlin 如何帮助使您的代码具有空安全性的不同方式。 Kotlin 中有不同的运算符用于实现这一点，我们讨论了如何使用它们。

在下一章中，我们将在学习 Kotlin 中的函数和 lambda 的同时完成我们的井字棋游戏。


# 第六章：函数和 Lambda

在本章中，我们将完成 TicTacToe 游戏的工作，并了解 Kotlin 中的函数。

在这个过程中，我们将：

+   了解函数

+   了解高阶函数及其使用方法

+   了解 lambda 及其使用方法

# 函数

在 Kotlin 中，函数的声明格式如下：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/7a43c5b1-8044-4d90-a432-6aadd65fc9b7.png)

**return**类型和**parameters**是可选的。没有`return`类型的函数默认返回`Unit`。`Unit`相当于 Java 中的`void`。

作为其主体的单个表达式的函数也可以省略大括号：

```kt
fun addStudent(name: String, age:Int, classRoomNo: Int = 1, studentId: Int) : Student = Student(name, classRoomNo, studentId, age)
```

如果类型可以被编译器推断出来，则`return`类型也可以省略：

```kt
fun addStudent(name: String, age:Int, classRoomNo: Int = 1, studentId: Int) = Student(name, classRoomNo, studentId, age)
```

# 参数

在 Kotlin 中，使用帕斯卡符号（**parameter_name:Type**）定义函数参数。每个参数的类型都必须明确声明。函数声明中的参数可以被赋予默认值。格式为：**parameter_name:Type = defaultValue**。例如：

```kt
data class Student(var name: String, var classRoomNo: Int, var studentId: Int, var age: Int)

fun addStudent(name: String, age:Int, classRoomNo: Int = 1, studentId: Int) : Student {

 return Student(name, classRoomNo, studentId, age)
}

var anna = addStudent("Anna", 18, 2, 1)
var joseph = addStudent(name = "Joseph", age = 19, studentId = 2)
```

在这个例子中：

+   在调用`addStudent()`函数时，可以省略`classRoomNo`参数。例如，`joseph`将具有默认的`classRoomNo`值为`1`。

+   在某些情况下，如果没有将所有参数传递给函数，则传递的参数必须在其参数名称之前。

# 高阶函数和 lambda

术语**高阶函数**指的是一个函数，它要么接受另一个函数作为参数，要么返回一个函数，或者两者兼而有之。例如：

```kt
// 1
fun logStudent(name: String, age:Int, createStudent:(String, Int) -> Student) {
    Log.d("student creation", "About to create student with name $name")
    val student = createStudent(name, age)
    Log.d("student creation", "Student created with name ${student.name} and age ${student.age}")
}

// 2
logStudent(name = "Anna", age = 20, createStudent = { name: String, age: Int -> Student(name, 1, 3, age)})
```

在这里，`logStudent()`函数接受三个参数：`name`，`age`和`createStudent`。`createStudent`是一个函数，它接受一个`String`和一个`Int`作为参数，并返回一个`Student`对象。

`createStudent`函数未声明，而是作为表达式传递给`logStudent()`函数。这称为**lambda 表达式**。

# Lambda 表达式

Lambda 表达式是一个匿名函数，它不是声明的，而是立即作为表达式传递的。

让我们继续在 TicTacToe 应用程序中使用 lambda 表达式。打开`MainActivity.kt`。在`startNewGame()`函数中，替换以下代码行：

```kt
cell.setOnClickListener(object : View.OnClickListener {
    override fun onClick(v: View?) {
        cellClickListener(i, j)
    }
})
```

用以下代码替换它们：

```kt
cell.setOnClickListener { cellClickListener(i, j) } 
```

在前面的代码行中，我们有一个匿名对象，它实现了一个具有单个抽象方法（`onClick()`）的 Java 接口。所有这些都可以用一个简单的 lambda 表达式来替代。

**单个抽象方法**（**SAM**），通常指的是接口中的功能方法。该接口通常只包含一个称为 SAM 或功能方法的抽象方法。

现在，构建并运行以查看应用程序的状态：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/529b1022-a3fd-4096-896b-e620e549a24c.png)

让我们继续利用我们迄今为止学到的所有知识，以便完成游戏的工作。

Android Studio 提供了一个默认的工具链，支持大多数 JAVA 8 功能，包括 lambda 表达式。强烈建议您使用默认的工具链，并禁用所有其他选项，如 jackoptions 和 retrolambda。

# 实现游戏状态检查

在本节中，我们将处理一些函数，以帮助我们找出游戏的赢家。

首先，将以下函数添加到`MainActivity`类中：

```kt
private fun isBoardFull(gameBoard:Array<CharArray>): Boolean {
    for (i in 0 until gameBoard.size) { 
        for (j in 0 until gameBoard[i].size) { 
            if(gameBoard[i][j] == ' ') {
                return false
            }
        }
    }
    return true
}
```

此函数用于检查游戏板是否已满。在这里，我们遍历棋盘上的所有单元格，如果有任何一个单元格为空，则返回`false`。如果没有一个单元格为空，则返回`true`。

接下来，添加`isWinner()`方法：

```kt
private fun isWinner(gameBoard:Array<CharArray>, w: Char): Boolean {
    for (i in 0 until gameBoard.size) {
        if (gameBoard[i][0] == w && gameBoard[i][1] == w && 
        gameBoard[i][2] == w) {
            return true
        }

        if (gameBoard[0][i] == w && gameBoard[1][i] == w && 
        gameBoard[2][i] == w) {
            return true
        }
    }
    if ((gameBoard[0][0] == w && gameBoard[1][1] == w && gameBoard[2]
    [2] == w) ||
            (gameBoard[0][2] == w && gameBoard[1][1] == w && 
        gameBoard[2][0] == w)) {
        return true
    }
    return false
}
```

在这里，您可以检查传递的字符是否是赢家。如果字符在水平、垂直或对角线行中出现三次，则该字符是赢家。

现在添加`checkGameStatus()`函数：

```kt
private fun checkGameStatus() {
    var state: String? = null
    if(isWinner(gameBoard, 'X')) {
        state = String.format(resources.getString(R.string.winner), 'X')
    } else if (isWinner(gameBoard, 'O')) {
        state = String.format(resources.getString(R.string.winner), 'O')
    } else {
        if (isBoardFull(gameBoard)) {
            state = resources.getString(R.string.draw)
        }
    }

    if (state != null) {
        turnTextView?.text = state
        val builder = AlertDialog.Builder(this)
        builder.setMessage(state)
        builder.setPositiveButton(android.R.string.ok, { dialog, id ->
            startNewGame(false)

        })
        val dialog = builder.create()
        dialog.show()

    }
}
```

上述函数利用`isBoardFull()`和`isWinner()`函数来确定游戏的赢家是谁。如果 X 和 O 都没有赢，而且棋盘已满，则是平局。显示一个警报，显示游戏的赢家或告诉用户游戏是平局的消息。

接下来，在`cellClickListener()`函数的末尾添加一个调用`checkGameStatus()`。

构建并运行：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/60fca23e-aee9-4834-9797-a9bc33c7a48b.png)

最后，实现**FloatingActionButton**的功能。在`onCreate()`函数中，将以下内容替换为：

```kt
fab.setOnClickListener { view -> HelloKotlin("Get ready for a fun game of Tic Tac Toe").displayKotlinMessage(view) }
```

将其替换为：

```kt
fab.setOnClickListener {startNewGame(false)}
```

再次构建并运行。现在，当您点击**FloatingActionButton**时，棋盘将被清空，以便您重新开始游戏：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/4c213cc7-02c2-4256-aac7-5693c4995769.png)

# 总结

在本章中，我们学习了如何在 Kotlin 中使用函数和 lambda，并完成了对我们的 TicTacToe 游戏的工作。

在接下来的几章中，我们将学习如何在 Android 上使用 Google 位置服务以及执行网络调用，同时致力于创建基于位置的闹钟。


# 第七章：开发您的基于位置的闹钟

了解用户位置并为他们提供定制服务是 Android 设备的强大功能之一。 Android 应用程序开发人员可以利用这一强大功能，为其应用程序的用户提供迷人的服务。因此，了解 Google 位置服务、Google Maps API 和位置 API 对于 Android 应用程序的开发人员非常重要。

在本章中，我们将开发我们自己的**基于位置的闹钟**（**LBA**），并在开发应用程序的过程中，我们将了解以下内容：

+   基于 Android 活动创建地图

+   在 Android 应用程序中使用 Google Maps

+   注册并获取 Google Maps 活动所需的密钥的过程

+   为用户提供输入的屏幕

+   在下一章中，通过添加闹钟功能并使用 Google 位置服务来完成我们的应用程序并创建一个可行的模型

# 创建一个项目

我们将看看创建 LBA 所涉及的步骤。我们将使用我们最喜欢的 IDE，Android Studio，来开发 LBA。

让我们开始启动 Android Studio。一旦它启动并运行，点击开始一个新的 Android Studio 项目。如果您已经打开了一个项目，请点击文件|新建项目。

在下一个屏幕上，输入这里显示的详细信息：

+   **应用程序名称**：`LocationAlarm`。

+   **公司域**：Android Studio 使用域名来生成我们开发的应用程序的包名。包确保我们的应用程序在 Play 商店中获得唯一标识符。通常，包名将是域名的反向，例如，在这种情况下将是`com.natarajan.locationalarm`。

+   **项目位置**：我们希望开发和保存项目代码的路径。您可以选择并选择您正在开发应用程序的路径。由于我们正在使用 Kotlin 开发我们的应用程序，因此我们必须选择包括 Kotlin 支持：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/730f30c7-4125-4be5-bfa2-2da610d797bd.png)

在接下来的屏幕上，我们将根据以下内容做出关于我们针对的 Android 设备的决定：

+   它们提供的 API

+   表单因素

对于我们的应用程序，我们将选择手机和平板电脑，并选择 API 为 API 15。 API 选择框下方的文本告诉我们，通过选择 API 15 及更高版本，我们将选择使我们的应用程序在大约 100%的设备上运行。

帮助我选择选项将帮助您了解按 Android 版本（API）分组的全球 Android 设备的分布。

我们不会在任何其他表单因素上运行我们的应用程序；因此，我们可以跳过这些选择区域，然后点击下一步：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/a03eeb24-e179-4e91-9767-4479079768d9.png)

在下一个屏幕上，我们将有一个选项来向我们的应用程序添加一个活动。

Android Studio 通过提供最常用的活动的现成模板，使开发人员更容易地包含他们的应用程序所需的活动类型。

我们正在开发 LBA，因此我们需要一个显示设置了闹钟的位置的地图。

点击**Google Maps Activity**，然后点击下一步：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2a73de5b-a2a7-4727-b45c-0166738c9413.png)

我们将在下一个屏幕上配置活动。一般来说，原生 Android 应用程序是由 Kotlin/Java 类和 XML 定义的用户界面组合而成。屏幕上提供了以下输入来配置我们的应用程序：

+   **活动名称**：这是我们地图活动的 Kotlin 类的名称。当我们选择地图活动时，默认情况下会显示名称 MapsActivity，我们将在这里使用相同的名称。

+   **布局名称**：我们将用于设计用户界面的 XML 布局的名称。

+   **标题**：我们希望应用程序为此活动显示的标题。我们将保留此标题为 Map，这是默认显示的。

完成这些条目后，点击完成按钮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e64162cd-046e-4798-8c82-20e4bdb8dac7.png)

点击按钮后，我们将看到“构建'LocationAlarm' Gradle 项目信息”屏幕。

# 生成 Google Maps API 密钥

一旦构建过程完成，我们将看到以下资源文件屏幕默认打开并由 Android Studio 显示：

文件默认命名为`google_maps_api.xml`。该文件清楚地指示在运行应用程序之前，我们需要获取 Google Maps API 密钥。获取应用程序的 Google Maps API 密钥的过程将详细列出。

生成的密钥应该替换文件中提到的占位符 YOUR_KEY_HERE：

```kt
<resources>
 <!--
TODO: Before you run your application, you need a Google Maps API key.

To get one, follow this link, follow the directions and press "Create" at the end:

https://console.developers.google.com/flows/enableapi?apiid=maps_android_backend&keyType=CLIENT_SIDE_ANDROID&r=00:ED:1B:E2:03:B9:2E:F4:A9:0F:25:7A:2F:40:2E:D2:89:96:AD:2D%3Bcom.natarajan.locationalarm

You can also add your credentials to an existing key, using these values:
Package name:
 00:ED:1B:E2:03:B9:2E:F4:A9:0F:25:7A:2F:40:2E:D2:89:96:AD:2D
SHA-1 certificate fingerprint:
 00:ED:1B:E2:03:B9:2E:F4:A9:0F:25:7A:2F:40:2E:D2:89:96:AD:2D

Alternatively, follow the directions here:
 https://developers.google.com/maps/documentation/android/start#get-key

Once you have your key (it starts with "AIza"), replace the "google_maps_key"
 string in this file.
 -->
<string name="google_maps_key" templateMergeStrategy="preserve" translatable="false">YOUR_KEY_HERE</string>
 </resources>
```

我们将使用文件中提供的链接生成我们应用程序所需的密钥。

[`console.developers.google.com`](https://console.developers.google.com/apis/dashboard) 需要用户使用他们的 Google ID 进行登录。一旦他们登录，将会出现创建项目和启用 API 的选项。

选择并复制完整的链接（[`console.developers.google.com/flows/enableapi?apiid=maps_android_backend&keyType=CLIENT_SIDE_ANDROID&r=00:ED:1B:E2:03:B9:2E:F4:A9:0F:25:7A:2F:40:2E:D2:89:96:AD:2D;com.natarajan.locationalarm`](https://console.developers.google.com/flows/enableapi?apiid=maps_android_backend&keyType=CLIENT_SIDE_ANDROID&r=00:ED:1B:E2:03:B9:2E:F4:A9:0F:25:7A:2F:40:2E:D2:89:96:AD:2D;com.natarajan.locationalarm)）并在您喜欢的浏览器中输入：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/d94b1a65-5970-4aee-aa60-14b56ea58f32.png)

一旦用户登录到控制台，用户将被要求在 Google API 控制台中为 Google Maps Android API 注册应用程序。

我们将看到一些选项：

+   选择一个项目

+   创建一个项目

如下文本所示，在选择应用程序将注册的项目时，用户可以使用一个项目来管理所有开发的应用程序的 API 密钥，或者选择为每个应用程序使用不同的项目。

使用一个项目来管理各种 Android 应用程序所需的所有 API 密钥，或者为每个应用程序使用一个项目，这取决于用户。在撰写本文时，默认情况下，用户将被允许免费创建 12 个项目。

接下来，您需要阅读并同意 Google Play Android 开发者 API 和 Firebase API/服务条款的条款和条件（[`console.developers.google.com/flows/enableapi?apiid=maps_android_backend&keyType=CLIENT_SIDE_ANDROID&r=00:ED:1B:E2:03:B9:2E:F4:A9:0F:25:7A:2F:40:2E:D2:89:96:AD:2D;com.natarajan.locationalarm`](https://console.developers.google.com/flows/enableapi?apiid=maps_android_backend&keyType=CLIENT_SIDE_ANDROID&r=00:ED:1B:E2:03:B9:2E:F4:A9:0F:25:7A:2F:40:2E:D2:89:96:AD:2D;com.natarajan.locationalarm) )：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/bf107574-6da2-4e5f-b34c-97cdf75ca2d7.png)

选择创建一个项目并同意条款和条件。完成后，点击**同意并继续**：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/dc592428-7e92-4030-877e-874c5e0b50db.png)

一旦项目创建成功，用户将看到一个屏幕。屏幕上显示“项目已创建，已启用 Google Maps Android API。接下来，您需要创建一个 API 密钥以调用 API。”用户还将看到一个按钮，上面写着**创建 API 密钥**：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/c8873375-6a3f-4d8e-b51a-f0d22c2edea6.png)

单击创建 API 密钥按钮后，用户将看到一个控制台，上面弹出一个消息，显示 API 密钥已创建。这是我们需要在应用程序中使用的 API 密钥：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/44c63930-3055-4847-a8ba-f0279d8fb298.png)

复制 API 密钥，然后用生成的 API 密钥替换`google_maps_api.xml`文件中的 YOUR_API_KEY 文本，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/66097bc6-8513-42c9-b691-06dbf048d28f.png)

生成的带有生成的 Google Maps API 密钥的文件应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/3ac786d7-90d2-427b-bd2c-f8f1a6994396.png)

开发人员可以通过登录 Google API 控制台来检查生成的 API 密钥，并交叉检查为项目专门生成的正确 API 密钥的使用情况：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/ae855389-1b7c-4ee5-9ac5-d1f2f79ca290.png)

现在我们已经生成了 API 密钥并修改了文件以反映这一点，我们已经准备好分析代码并运行应用程序。

快速回顾一下，我们创建了包括 Google Maps 活动的应用程序，并创建了布局文件。然后我们生成了 Google Maps API 密钥并替换了文件中的密钥。

# 运行应用程序

要运行应用程序，请转到 Run | Run app 或单击**播放**按钮。

Android Studio 将提示我们选择部署目标，即具有开发人员选项和 USB 调试启用的物理设备，或者用户设置的虚拟设备，也称为模拟器。

一旦我们选择其中一个选项并点击“确定”，应用程序将构建并运行到部署目标上。应用程序将启动并运行，我们应该看到地图活动加载了悉尼的标记：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/ca5f912d-0ac1-4a11-89c6-a52da0f5a02b.png)

# 了解代码

我们成功运行了应用程序，现在是时候深入了解代码，了解它是如何工作的。

让我们从`MapsActivity.kt` Kotlin 类文件开始。

`MapActivity`类扩展了`AppCompatActivity`类，并实现了`OnMapReadCallback`接口。我们有一对变量，`GoogleMap`，`mMap`和`btn`按钮初始化。

重写`onCreate`方法，当应用程序启动时，将从 XML 文件`activity_maps.xml`中加载内容。

从资源文件设置`mapFragment`和`btn`的资源：

```kt
class MapsActivity : AppCompatActivity(), OnMapReadyCallback {

private lateinit var mMap: GoogleMap
 override fun onCreate(savedInstanceState: Bundle?) {
super.onCreate(savedInstanceState)
         setContentView(R.layout.activity_maps)
// Obtain the SupportMapFragment and get notified when the map is ready to be used.
val mapFragment = supportFragmentManager
.findFragmentById(R.id.map) as SupportMapFragment
         mapFragment.getMapAsync(this)
     }

 }
```

# 自定义代码

默认生成的代码显示了悉尼的市场。这里显示的`onMapReady`方法在地图准备就绪并加载并显示标记时被调用。位置是根据提到的`LatLng`值找到的：

```kt
override fun onMapReady(googleMap: GoogleMap) {
 mMap = googleMap
// Add a marker in Sydney and move the camera
val sydney= LatLng(-33.852,151.211)
mMap.addMarker(MarkerOptions().position(sydney).title("Marker in Sydney"))
mMap.moveCamera(CameraUpdateFactory.newLatLng(sydney))
}
```

现在让我们自定义此代码以在印度泰米尔纳德邦金奈上显示标记。要进行更改，第一步是了解`Lat`和`Lng`代表什么。

纬度和经度一起用于指定地球上任何部分的精确位置。在 Android 中，`LatLng`类用于指定位置。

# 查找地点的纬度和经度

在浏览器中使用 Google Maps 可以轻松找到地点的纬度和经度。为了我们的目的，我们将在我们喜欢的浏览器中启动 Google Maps。

搜索您需要找到纬度和经度的位置。在这里，我们搜索位于印度泰米尔纳德邦金奈的智障儿童特殊学校 Vasantham。

一旦我们找到了我们搜索的位置，我们可以在 URL 中看到纬度和经度的值，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/8cb68afc-f61c-4acd-b428-f1332d7342e9.png)

我们搜索到的地方的纬度和经度值分别为 13.07 和 80.17。让我们继续在代码中进行以下更改。

在`onMapReady`方法中，让我们进行以下更改：

+   将`Sydney`变量重命名为`chennai`

+   将 Lat 和 Lng 从悉尼更改为金奈

+   将`Marker`文本更改为`马德拉斯的标记`

+   将`newLatLng`更改为以`chennai`作为输入值

```kt
override fun onMapReady(googleMap: GoogleMap) {
 mMap = googleMap
// Add a marker in Chennai and move the camera
val chennai = LatLng(13.07975, 80.1798347)
 //val chennai = LatLng(-34.0, 151.0)
mMap.addMarker(MarkerOptions().position(chennai).title("Marker in Chennai"))
 mMap.moveCamera(CameraUpdateFactory.newLatLng(chennai))
 }
```

当我们保存所做的更改并再次运行应用程序时，我们将能够看到地图现在加载了位于印度金奈的标记：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/51949d18-eff8-4e7f-83f1-98c0b97d0bc3.png)

一旦我们触摸标记，我们应该能够看到“马德拉斯的标记”文本显示在红色标记的顶部：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/755f5fcc-207d-4fdb-a149-3c968e98feb6.png)

# XML 布局

我们已经详细查看了 Kotlin 类，以及自定义 Lat 和 Lng 输入的方法。

让我们快速检查 XML 布局文件。我们还将了解添加一个按钮的过程，该按钮将带我们到一个屏幕，通过该屏幕用户将能够输入警报的 Lat 和 Lng 输入。

在`activity_maps.xml`文件中，我们有地图片段和按钮元素包装在`LinearLayoutCompat`中，如下所示。我们将按钮元素链接到`onClickSettingsButton`方法：

```kt
<android.support.v7.widget.LinearLayoutCompat 

android:layout_width="match_parent"
android:layout_height="match_parent"
android:orientation="vertical"
android:layout_weight="1.0"><fragment
android:id="@+id/map"
android:layout_weight="0.8"
android:name="com.google.android.gms.maps.SupportMapFragment"
android:layout_width="match_parent"
android:layout_height="match_parent"
tools:context="com.natarajan.locationalarm.MapsActivity" />

<Button
android:layout_width="wrap_content"
android:layout_height="wrap_content"
android:layout_weight="0.2"
android:id="@+id/settingsbtn"
android:onClick="onClickSettingsButton"
android:text="@string/Settings"/>

 </android.support.v7.widget.LinearLayoutCompat>
```

在`MapsActivity` Kotlin 类中，我们可以定义一个名为`onClickSettingsButton`的方法，并在调用相同的方法时启动另一个名为`SETTINGACTVITY`的活动，如下所示：

```kt
fun onClickSettingsButton(view: View) {
 val intent = Intent("android.intent.action.SETTINGACTIVITY")
 startActivity(intent)
 }
```

# 开发用户输入屏幕

当点击`Settings`按钮时，我们的应用程序将带用户进入一个屏幕，用户可以在该屏幕上输入新位置的纬度和经度值，用户希望为该位置设置警报。

我们有一个非常简单的输入屏幕。我们有一个包含一对`EditText`的`LinearLayout`，一个用于纬度输入，另一个用于经度输入。这些编辑文本后面跟着一个按钮，允许用户提交输入的新位置坐标。

我们还有一个与按钮关联的`onClickButton`方法，当用户点击按钮时调用：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout 
android:layout_width="match_parent"
android:layout_height="match_parent"
android:orientation="vertical">

     <EditText
android:id="@+id/latText"
android:layout_width="wrap_content"
android:layout_height="wrap_content"
android:ems="10"
android:hint='Latitude'
android:inputType="numberDecimal" />

     <EditText
android:id="@+id/langText"
android:layout_width="wrap_content"
android:layout_height="wrap_content"
android:ems="10"
android:hint="Longitude"
android:inputType="numberDecimal" />

     <Button
android:id="@+id/alarmbtn"
android:layout_width="wrap_content"
android:layout_height="wrap_content"
android:onClick="onClickButton"
android:text="Ok" />

 </LinearLayout>
```

我们已经准备好用户输入的 XML 布局；现在让我们创建一个新的 Kotlin 活动类，该类将使用这个设置的 XML 并与用户交互。

`SettingsActivity`类扩展了`AppCompatActivity`，包含了一对编辑文本元素和初始化的按钮元素。变量通过它们的 ID 从资源文件中识别和设置为正确的资源。当活动被调用和加载时，活动加载`settings_activity` XML。

在`onClickButton`方法中，我们有一个简单的 Toast 消息，显示警报已设置。在接下来的章节中，我们将保存输入的内容，并在用户进入感兴趣的位置时触发警报：

```kt
class SettingsActivity : AppCompatActivity() {

public override fun onCreate(savedInstanceState: Bundle?) {
super.onCreate(savedInstanceState)
         setContentView(R.layout.settings_activity)

}
fun onClickButton(view: View) {
         Toast.makeText(this, "Alarm Set", Toast.*LENGTH_LONG*).show()
     }
}
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/e21e552f-6b2e-470a-b34d-79272293a859.png)

当用户在输入纬度和经度后点击`OK`按钮时，将显示 Toast 消息，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/lrn-kt-bd-andr-app/img/2ef9237f-56b1-4017-baa9-3cb85efa06cd.png)

# AndroidManifest 文件

清单文件是项目中最重要的文件之一。在这个文件中，我们必须列出我们打算在应用程序中使用的所有活动，并提供有关我们用于 Google Maps API 的 API 密钥的详细信息。

在清单文件中，我们有以下重要的指针：

+   我们的应用程序使用`ACCESS_FINE_LOCATION`权限。这是为了获取用户位置的详细信息；我们需要这样做以便在用户到达设置的位置时启用警报。

`ACCESS_COARSE_LOCATION`是启用应用程序获取`NETWORK_PROVIDER`提供的位置详细信息的权限。`ACCESS_FINE_LOCATION`权限使应用程序能够获取`NETWORK_PROVIDER`和`GPS_PROVIDER`提供的位置详细信息。

+   我们有 Android geo API 密钥的元数据，这只是我们生成并放置在`google_maps_api.xml`中的 API 密钥。

+   我们有一个启动器 MAIN 活动，它在钦奈位置上启动带有标记的地图。

+   我们还有默认的活动设置，当点击`提交`按钮时触发：

```kt
*<?*xml version="1.0" encoding="utf-8"*?>* <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.natarajan.locationalarm">
*<!--
          T*he ACCESS_COARSE/FINE_LOCATION permissions are not required to use
          Google Maps Android API v2, but you must specify either coarse or fine
          location permissions for the 'MyLocation' functionality. 
     --><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />

     <application android:allowBackup="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_round" android:supportsRtl="true" android:theme="@style/AppTheme">
*<!--
        *      The API key for Google Maps-based APIs is defined as a string resource.
              (See the file "res/values/google_maps_api.xml").
              Note that the API key is linked to the encryption key used to sign the APK.
              You need a different API key for each encryption key, including the release key that is used to
              sign the APK for publishing.
              You can define the keys for the debug and release targets in src/debug/ and src/release/. *-->* <meta-data android:name="com.google.android.geo.API_KEY" android:value="@string/google_maps_key" />

         <activity android:name=".MapsActivity" android:label="@string/title_activity_maps">
             <intent-filter>
                 <action android:name="android.intent.action.MAIN" />
                 <category android:name="android.intent.category.LAUNCHER" />
             </intent-filter>
         </activity>

         <activity android:name=".SettingsActivity">
             <intent-filter>
                 <action android:name="android.intent.action.SETTINGACTIVITY" />
                 <category android:name="android.intent.category.DEFAULT" />
             </intent-filter>
         </activity>

     </application>

 </manifest>
```

# Build.gradle

`build.gradle`文件包括所需的 Google Maps 服务的依赖项。我们必须包括来自 Google Play 服务的 Play 服务地图。从 Google Play 服务中，我们包括我们感兴趣的服务。在这里，我们希望有一个地图服务可用，因此我们包括`play-services-maps`：

```kt
apply plugin: 'com.android.application' apply plugin: 'kotlin-android' apply plugin: 'kotlin-android-extensions' android {
     compileSdkVersion 26
defaultConfig {
         applicationId "com.natarajan.locationalarm" minSdkVersion 15
targetSdkVersion 26
versionCode 1
versionName "1.0" testInstrumentationRunner "android.support.test.runner.AndroidJUnitRunner" }
     buildTypes {
         release {
             minifyEnabled false proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro' }
     }
 }

 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
     implementation"org.jetbrains.kotlin:kotlin-stdlib-jre7:$kotlin_version" implementation 'com.android.support:appcompat-v7:26.1.0'
 implementation 'com.google.android.gms:play-services-maps:11.8.0' testImplementation 'junit:junit:4.12' androidTestImplementation 'com.android.support.test:runner:1.0.1' androidTestImplementation 'com.android.support.test.espresso:espresso-core:3.0.1' }
```

# 总结

在本章中，我们讨论并学习了如何创建自己的 LBA。我们了解了 Google Maps API 的细节，API 密钥的生成，地图用户界面的创建，向地图添加标记，自定义标记，为用户输入创建用户界面屏幕等等。

我们还讨论了清单文件、`build.gradle`文件和 XML 布局文件以及相应的 Kotlin 类中的重要组件。在下一章中，我们将使用共享首选项保存从用户那里收到的输入，使用 Google API 的基于位置的服务，并在用户进入位置时启用和触发警报。
