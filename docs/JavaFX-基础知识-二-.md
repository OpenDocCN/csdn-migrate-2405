# JavaFX 基础知识（二）

> 原文：[`zh.annas-archive.org/md5/E51DD19915A0979B8B23880AAD773381`](https://zh.annas-archive.org/md5/E51DD19915A0979B8B23880AAD773381)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：为 iOS 开发 JavaFX 应用程序

苹果在移动和 PC /笔记本世界拥有很大的市场份额，拥有许多不同的设备，从 iPhone 等手机到 iPod 等音乐设备和 iPad 等平板电脑。

它拥有一个快速增长的应用市场，称为 Apple Store，为其社区提供服务，可用应用程序的数量每天都在增加。移动应用程序开发人员应该为这样的市场做好准备。

同时针对 iOS 和 Android 的移动应用程序开发人员面临许多挑战。仅仅比较这两个平台的本机开发环境，就会发现它们存在实质性的差异。

根据苹果的说法，iOS 开发基于 Xcode IDE（[`developer.apple.com/xcode/`](https://developer.apple.com/xcode/)）及其编程语言。传统上是 Objetive-C，2014 年 6 月，苹果推出了 Swift（[`developer.apple.com/swift/`](https://developer.apple.com/swift/)）；另一方面，根据谷歌的定义，Android 开发基于 Intellij IDEA IDE 和 Java 编程语言。

没有多少开发人员精通两种环境。此外，这些差异排除了平台之间的任何代码重用。

JavaFX 8 正在填补平台之间可重用代码的差距，正如我们将在本章中看到的，通过在两个平台上共享相同的应用程序。

通过本章结束时，您将掌握以下一些技能：

+   安装和配置 iOS 环境工具和软件

+   创建 iOS JavaFX 8 应用程序

+   模拟和调试 JavaFX 移动应用程序

+   在 iOS 移动设备上打包和部署应用程序

# 使用 RoboVM 在 iOS 上运行 JavaFX

RoboVM 是从 Java 到 Objetive-C 的桥梁。使用它，开发运行在基于 iOS 的设备上的 JavaFX 8 应用程序变得容易，因为 RoboVM 项目的最终目标是解决这个问题，而不会影响开发人员体验或应用程序用户体验。

正如我们在前一章关于 Android 中看到的，使用 JavaFXPorts 生成 APK 是一个相对容易的任务，因为 Android 是基于 Java 和 Dalvik VM 的。

相反，iOS 没有为 Java 提供虚拟机，并且不允许动态加载本机库。

需要另一种方法。RoboVM 开源项目试图通过创建一个桥梁来解决 Java 开发人员的差距，该桥梁使用一个“提前编译”编译器，将 Java 字节码转换为本机 ARM 或 x86 机器代码。

## 特点

让我们来看看 RoboVM 的特点：

+   将 Java 和其他 JVM 语言（如 Scala、Clojure 和 Groovy）带到基于 iOS 的设备上

+   提前将 Java 字节码转换为机器代码，以便在 CPU 上直接进行快速执行，而不会产生任何开销

+   主要目标是 iOS 和 ARM 处理器（32 位和 64 位），但也支持在 x86 CPU 上运行的 Mac OS X 和 Linux（32 位和 64 位）

+   不对开发人员可访问的 Java 平台功能施加任何限制，如反射或文件 I/O

+   支持标准的 JAR 文件，让开发人员重用第三方 Java 库的庞大生态系统

+   通过 Java 到 Objective-C 桥接提供对完整本机 iOS API 的访问，实现具有真正本机 UI 和完整硬件访问的应用程序开发

+   与 NetBeans、Eclipse、Intellij IDEA、Maven 和 Gradle 等最流行的工具集成

+   App Store 准备就绪，已有数百款应用程序在商店中

## 限制

主要是由于 iOS 平台的限制，使用 RoboVM 时存在一些限制：

+   不支持在运行时加载自定义字节码。应用程序的所有类文件都必须在开发者机器上的编译时可用。

+   Java 本机接口技术通常在桌面或服务器上使用，从动态库加载本机代码，但是苹果不允许将自定义动态库与 iOS 应用一起发布。RoboVM 支持基于静态库的 JNI 变体。

+   另一个重要限制是，RoboVM 是一个处于开发中的 Alpha 状态项目，目前尚不建议用于生产。

### 注意

RoboVM 完全支持反射。

## 工作原理

如第四章中所述，自 2015 年 2 月以来，RoboVM 和 JavaFXPorts 背后的公司之间已经达成协议，现在一个名为 jfxmobile-plugin 的单一插件允许我们从相同的代码库构建三个平台的应用程序-桌面、Android 和 iOS。

JavaFXMobile 插件为您的 Java 应用程序添加了许多任务，允许您创建可以提交到 Apple Store 的.ipa 包。

Android 主要使用 Java 作为主要开发语言，因此很容易将您的 JavaFX 8 代码与其合并。在 iOS 上，情况在内部完全不同，但使用类似的 Gradle 命令。

该插件将下载并安装 RoboVM 编译器，并使用 RoboVM 编译器命令在`build/javafxports/ios`中创建 iOS 应用程序。

# 入门

在本节中，您将学习如何使用`JavaFXMobile`插件安装 RoboVM 编译器，并通过重用我们之前在第四章中开发的相同应用程序 Phone Dial 版本 1.0，确保工具链正确工作，*为 Android 开发 JavaFX 应用程序*。

## 先决条件

为了使用 RoboVM 编译器构建 iOS 应用程序，需要以下工具：

+   Oracle 的 Java SE JDK 8 更新 45。参考第一章，*开始使用 JavaFX 8*，*安装 Java SE 8 JDK*部分。

+   构建应用程序需要 Gradle 2.4 或更高版本的`jfxmobile`插件。参考第四章，*为 Android 开发 JavaFX 应用程序*，*安装 Gradle 2.4*部分。

+   运行**Mac OS X** 10.9 或更高版本的 Mac。

+   来自 Mac App Store 的 Xcode 6.x（[`itunes.apple.com/us/app/xcode/id497799835?mt=12`](https://itunes.apple.com/us/app/xcode/id497799835?mt=12)）。

### 提示

第一次安装**Xcode**，以及每次更新到新版本时，都必须打开它一次以同意 Xcode 条款。

## 为 iOS 准备项目

我们将重用我们之前在第四章中为 Android 平台开发的项目，因为在针对 iOS 时，代码、项目结构或 Gradle 构建脚本没有任何区别。

它们共享相同的属性和特性，但使用针对 iOS 开发的不同 Gradle 命令，并对 RoboVM 编译器的 Gradle 构建脚本进行了微小更改。

因此，我们将看到**WORA** *一次编写，到处运行*的强大功能，使用相同的应用程序。

### 项目结构

基于第四章中 Android 示例的相同项目结构，*为 Android 开发 JavaFX 应用程序*，我们的 iOS 应用程序的项目结构应如下图所示：

![项目结构](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_05_01.jpg)

### 应用程序

我们将重用第四章中开发的相同应用程序，*为 Android 开发 JavaFX 应用程序*：Phone DialPad 版本 2.0 JavaFX 8 应用程序：

![应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_05_02.jpg)

正如您所看到的，重用相同的代码库是一个非常强大和有用的功能，特别是当您同时开发以针对许多移动平台，如 iOS 和 Android。

#### 与低级 iOS API 的互操作性

为了具有与在 Android 中本机调用默认 iOS 电话拨号器相同的功能，我们必须提供 iOS 的本机解决方案，如以下`IosPlatform`实现：

```java
import org.robovm.apple.foundation.NSURL;
import org.robovm.apple.uikit.UIApplication;
import packt.taman.jfx8.ch4.Platform;

public class IosPlatform implements Platform {

  @Override
  public void callNumber(String number) {
    if (!number.equals("")) {
      NSURL nsURL = new NSURL("telprompt://" + number);
      UIApplication.getSharedApplication().openURL(nsURL);
    }
  }
}
```

### Gradle 构建文件

我们将使用与第四章中使用的相同的 Gradle 构建脚本文件，*为 Android 开发 JavaFX 应用程序*，但通过在脚本末尾添加以下行进行微小更改：

```java
jfxmobile {
  ios {
    forceLinkClasses = [ 'packt.taman.jfx8.ch4.**.*' ]
  }
  android {
    manifest = 'lib/android/AndroidManifest.xml' 
  }
}
```

安装和使用`robovm`编译器的所有工作都由`jfxmobile`插件完成。

这些行的目的是为 RoboVM 编译器提供主应用程序类的位置，该类必须在运行时加载，因为默认情况下编译器看不到它。

`forceLinkClasses`属性确保在 RoboVM 编译期间链接这些类。

#### 构建应用程序

在我们已经添加了必要的配置集以构建 iOS 脚本之后，现在是时候构建应用程序以将其部署到不同的 iOS 目标设备。为此，我们必须运行以下命令：

```java
$ gradle build

```

我们应该有以下输出：

```java
BUILD SUCCESSFUL

Total time: 44.74 secs
```

我们已经成功构建了我们的应用程序；接下来，我们需要生成`.ipa`文件，并且在生产环境中，您需要通过将其部署到尽可能多的 iOS 版本来测试它。

#### 生成 iOS .ipa 软件包文件

为了为我们的 JavaFX 8 应用程序生成最终的.ipa iOS 软件包，这对于最终分发到任何设备或 AppStore 是必要的，您必须运行以下`gradle`命令：

```java
gradle ios 

```

这将在目录`build/javafxports/ios`中生成`.ipa`文件。

### 部署应用程序

在开发过程中，我们需要在 iOS 模拟器上检查我们的应用程序 GUI 和最终应用程序原型，并在不同设备上测量应用程序的性能和功能。这些程序非常有用，特别是对于测试人员。

让我们看看在模拟器上运行我们的应用程序或在真实设备上运行是一个非常容易的任务。

#### 部署到模拟器

在模拟器上，您可以简单地运行以下命令来检查您的应用程序是否正在运行：

```java
$ gradle launchIPhoneSimulator 

```

此命令将打包并在*iPhone 模拟器*中启动应用程序，如下截图所示：

![部署到模拟器](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_05_03.jpg)

DialPad2 JavaFX 8 应用程序在 iOS 8.3/iPhone 4s 模拟器上运行

此命令将在 iPad 模拟器中启动应用程序：

```java
$ gradle launchIPadSimulator 

```

#### 部署到苹果设备

为了打包 JavaFX 8 应用程序并将其部署到苹果设备，只需运行以下命令：

```java
$ gradle launchIOSDevice 

```

此命令将在连接到您的台式机/笔记本电脑的设备中启动 JavaFX 8 应用程序。

然后，一旦应用程序在您的设备上启动，输入任何号码，然后点击呼叫。

iPhone 将请求使用默认移动拨号器拨号；点击**确定**。默认移动拨号器将启动，并显示号码，如下图所示：

![部署到苹果设备](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_05_04.jpg)

默认移动拨号器

### 注意

要能够在您的设备上测试和部署您的应用程序，您需要与苹果开发者计划订阅。访问苹果开发者门户网站，[`developer.apple.com/register/index.action`](https://developer.apple.com/register/index.action)，进行注册。您还需要为开发配置您的设备。您可以在苹果开发者门户网站上找到有关设备配置的信息，或者按照此指南操作：[`www.bignerdranch.com/we-teach/how-to-prepare/ios-device-provisioning/`](http://www.bignerdranch.com/we-teach/how-to-prepare/ios-device-provisioning/)。

# 摘要

本章使我们对如何使用 RoboVM 开发和定制基于 JavaFX 的应用程序以在苹果平台上运行应用程序有了很好的理解。

您了解了 RoboVM 的特点和限制，以及它的工作原理；您还获得了用于开发的技能。

然后，您学会了如何安装 iOS 开发所需的软件和工具，以及如何启用 Xcode 以及 RoboVM 编译器，以在 OS 模拟器上打包和安装基于 JavaFX-8 的 Phone Dial 应用程序。

我们已经看到了如何重复使用我们在第四章中已经开发的相同应用程序，证明了 Java WORA 范式的有效性。

最后，我们提供了关于如何在真实设备上运行和部署应用程序的技巧。

下一章将为我们打开物联网开发世界的一扇窗户；我们将看到如何购买树莓派 2 型，安装和配置用于开发的 raspbian-wheezy 操作系统，以及如何安装用于嵌入式设备的 Java SE。然后，我们将开发一个 JavaFX 8 应用程序，该应用程序将在我们的信用卡大小的微型计算机上运行。


# 第六章：在树莓派上运行 JavaFX 应用程序

欢迎来到**物联网**（**Internet of Things**）世界。毫无疑问，你总是听到这个术语。物联网最近成为一个热门话题，也是有充分理由的。一些估计将当前连接的小型设备数量约为 90 亿台；预计到 2020 年将跃升至 240 亿台。尽管预测各不相同，但评估确实如此：就数量而言，物联网将超越以往任何计算模型。

与物联网世界密切相关的是树莓派——由树莓派基金会设计的一款信用卡大小的微型计算机，用于实验和教育。

关于树莓派，你应该知道的是它只是一台小型计算机。小功率需求，小物理尺寸，小内存，最重要的是低成本设备。关于它的一切都很小，但它仍然只是一台计算机，它使用 Linux。

Java 从诞生的第一天起就是为物联网而生的。Java 的创造是有着明确的愿景：控制电视机顶盒等小型设备。随着物联网的爆发，Java 回归到了它的根基。

你可能会认为 JavaFX，一个用于丰富客户端开发的平台，会错过物联网的盛会——但事实并非如此！根据 Oracle 技术网络上的*JavaFX 概述*页面：

> *"它旨在提供一个轻量级、硬件加速的 Java UI 平台"*

这个声明揭示了图形丰富和强大的 JavaFX 的关键：硬件加速；幸运的是，树莓派配备了强大的 GPU。

在这一章中，我们将学习关于：

+   购买、准备和配置树莓派

+   为 JavaFX 8 准备树莓派

+   远程连接到树莓派

+   在树莓派上安装和配置 Java SE 8

+   在树莓派上开发和运行 JavaFX 8 应用程序

+   使用 NetBeans 与树莓派

激动吗？需要玩得开心！好的，让我们直接开始玩我们的树莓派吧。

### 注意

自 2015 年 1 月发布 ARM 版本的 JDK 8u33 以来，Oracle 已经从 ARM 发行版中移除了 JavaFX 嵌入式。请参阅[`www.oracle.com/technetwork/java/javase/jdk-8u33-arm-relnotes-2406696.html#CACHGFJC`](http://www.oracle.com/technetwork/java/javase/jdk-8u33-arm-relnotes-2406696.html#CACHGFJC)和[`jaxenter.com/jdk-arm-without-javafx-end-javafx-embedded-114212.html`](http://jaxenter.com/jdk-arm-without-javafx-end-javafx-embedded-114212.html)。

JavaFX 嵌入式的代码已经提供给了开源项目 OpenJFX（[`wiki.openjdk.java.net/display/OpenJFX/Main`](https://wiki.openjdk.java.net/display/OpenJFX/Main)）。建议寻找 JavaFX 嵌入式替代方案的开发人员加入并为该项目做出贡献。

在这一章中，我们将学习一些克服这个问题的方法。

# 什么是树莓派？

正如我们之前提到的，树莓派是一台非常小型和低成本的计算机。事实上，它大约是信用卡大小。不要被它的大小所欺骗；正如我们所知，好东西都是包装在小盒子里的。然而，树莓派根本没有包装。

它没有外壳，其电路板和芯片完全可见，如下图所示。你可以将树莓派插入数字电视或显示器，并使用 USB 键盘和鼠标，非常容易使用。由于其小巧的尺寸，你可以轻松地将它带到任何地方。

树莓派是一台功能强大的设备，可以让各个年龄段的人探索计算，并学习如何使用 Java、JavaFX、Python 和 Scratch 等语言进行编程。此外，它可以做任何台式电脑可以做的事情——从浏览互联网和播放高清视频或游戏到处理电子表格或文字处理软件。

![什么是树莓派？](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_01.jpg)

新的树莓派 2 型 B

## 你可以用它做什么？

树莓派为您提供了构建和控制设备的机会，使其按照您的意愿进行操作。例如，您可以部署自己的机器人手臂，由您编写的程序控制。您可以设计和创建自己的角色扮演游戏，或者通过编写代码制作美丽的计算机艺术或音乐。

此外，树莓派基金会的主要目标是让全世界的孩子们学会编程并了解计算机的工作原理，让学习变得有趣。

# 为什么树莓派是 JavaFX 的完美选择？

那么，树莓派为何如此适合 Java 和 JavaFX？答案可以从以下几点中找到：

+   它比规格表所显示的要快。正如所述，树莓派的默认时钟速度为 900 MHz。但是，凭借其 900 MHz 的时钟速度，可以安全地超频到 1 GHz 以及 1GB 的 RAM，这台小型计算机可以运行更大更强大的应用程序。

+   非常明智地，基金会选择了一个带有浮点支持的 CPU，通常被称为硬浮点，它比所谓的仅支持软浮点的芯片具有更高的性能。树莓派可用的操作系统利用了这种额外的功率和速度。

+   最后，树莓派具有相当强大的图形处理单元（GPU），具有快速的 3D 核心，能够以 40MBits/s 的速度使用 H.264 进行蓝光质量的播放（[`www.raspberrypi.org/help/faqs/#generalSoCUsed`](https://www.raspberrypi.org/help/faqs/#generalSoCUsed)）。

# 您应该购买哪个模块？

在撰写本文时，树莓派有五个型号：A，A+，B，B+，以及自 2015 年 2 月以来的新型号 Pi 2 B 型号。以下是 A+和 2B 型号之间的比较。

| A+型号 | 2B 型号 |
| --- | --- |
| 成本约 25 美元 | 成本约 35 美元 |
| 一个 USB 端口 | 四个 USB 端口 |
| 没有以太网 | 标准以太网连接 |
| 256MB RAM | 1GB RAM |

A+型号更便宜，但只有一个 USB 端口和没有以太网连接。这可能不是问题。如果您将一个带电源的 USB 集线器连接到 A+型号，然后使用 USB 到 WiFi 适配器，您就拥有了 B+型号的所有网络功能。两个型号之间的一个主要区别是 RAM 的数量。A+型号有 256MB 的 RAM。B+型号有 512MB 的 RAM，2B 型号有 1GB 的 RAM。这两个型号都无法升级。

所有树莓派微型计算机都配备了一个 SD 存储卡插槽，音频输出插孔，RCA 和 HDMI 的视频端口，以及一排用于通用输入和输出的引脚。还有两个用于显示和摄像头的附加连接器，但两者都需要高度专门化的硬件。鉴于价格上的小差异，通常为 10 到 25 美元，我建议首先购买 2B 型号。如果您要购买多个，比如用于教室，A+型号可能就足够了。

您可以从任何在线商店购买一个包含所有所需物品的套件，价格不会超过 100 美元，其中包括：

+   新的树莓派 2（RPi2）四核 900 MHz 1GB RAM 和 CanaKit WiFi 适配器

+   高品质的 6 英尺 HDMI 电缆，GPIO 到面包板接口板，排线，面包板，跳线，GPIO 快速参考卡和电阻颜色快速参考卡

+   8GB 三星 MicroSD 卡（树莓派基金会推荐的预装有 NOOBS 的 MicroSD 卡），高质量的树莓派 2 外壳和散热片

+   RGB LED，8 个 LED（蓝色/红色/黄色/绿色），15 个电阻，2 个按钮开关，以及初学者电子元件通用指南

+   2.5A USB 电源适配器，带 5 英尺的 micro USB 电缆，专为树莓派 2 设计（UL 认证）

![您应该购买哪个模块？](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_02.jpg)

树莓派 B 型 2 的典型套件组件

## 购买树莓派

英国的树莓派基金会制造了树莓派。不幸的是，它有一段时间的缺货历史。幸运的是，您可以从几家供应商那里购买，其中一些列在[`www.raspberrypi.org/`](https://www.raspberrypi.org/)的主页上。您也可以从[`www.amazon.com`](http://www.amazon.com)购买，尽管价格会稍高一些。价格会有所不同。

最后，查看[`www.adafruit.com`](http://www.adafruit.com)。它们价格合理，还提供一些您未来项目中需要的有用配件。在这些商店中，您还可以找到包括树莓派和启动所需组件的入门套件。

## 相关网站和文档

互联网上有大量关于树莓派的信息。当您研究更高级的主题时，知道在哪里找到答案将会很有帮助。

树莓派基金会的官方网站是[`www.rasberrypi.org`](http://www.rasberrypi.org)。它列出了购买树莓派微型计算机的来源。它有各种教程和有用的论坛。

有关树莓派上运行的 Linux 版本的更多信息，请访问[`elinux.org/index.php?title=RPi_Hub&redirect=no`](http://elinux.org/index.php?title=RPi_Hub&redirect=no)。这里有关于通用和输入/输出引脚的信息；Raspbian Wheezy，专为树莓派设计的 Linux 版本；以及示例项目的信息。您还会找到有关其他嵌入式系统的信息，如**Minnow board**和**BeagleBoard**。

Neil Black 创建了一份出色的树莓派初学者指南，值得一致好评。如果在设置过程中感到困惑，请访问[`neil-black.co.uk/the-updated-raspberry-pi-beginners-guide`](http://neil-black.co.uk/the-updated-raspberry-pi-beginners-guide)。

最后，访问[`www.adafruit.com`](http://www.adafruit.com)购买树莓派以及电源适配器、电机控制板和实验套件。如果您无法在当地购买零件，这个网站是购买配件和其他组件的绝佳地方。

# 为 JavaFX 8 准备树莓派

没有操作系统，您的树莓派将无法运行，操作系统是从 SD 卡加载的。我们需要一种方法来与之交互，首先安装支持的操作系统，我们的情况下是 Raspbian Wheezy；所有 Pi 的官方支持操作系统都在链接[`www.raspberrypi.org/downloads/`](http://www.raspberrypi.org/downloads)上列出并可从中下载。

然后，我们将配置我们的 Pi 的网络设置，以便远程连接。最后，我们将检查默认安装的 Java SE 8 版本，并继续检查更新，如果操作系统没有预先打包。

如前所述，最新更新不包括 JavaFX，因此我们将找到一种方法来添加它。让我们开始准备我们的 SD 卡，安装 Raspbian Wheezy 操作系统，让树莓派运行起来。

## 创建可启动的 SD 卡

现在，我们将准备我们的 SD 卡，安装 Raspbian Wheezy 操作系统，这将允许我们与我们的树莓派进行交互。这是一个非常重要的步骤。有两种方法可以做到这一点：

### 使用 NOOBS

NOOBS 是一个简单的操作系统安装程序，其中包含 Raspbian。但是精简版不包含 Raspbian。它还提供了一系列备选操作系统，然后从互联网上下载并安装。

初学者应该从 NOOBS 方法开始，但它需要一个速度良好的互联网连接来下载首选操作系统。

如果你购买的套件配有预装的 NOOBS SD 卡，你可以跳到下一步。或者，如果你需要一个 SD 卡，你可以从 Swag 商店[`swag.raspberrypi.org/products/noobs-8gb-sd-card`](http://swag.raspberrypi.org/products/noobs-8gb-sd-card)订购，甚至自己下载并设置到你的 SD 卡上。所有步骤都在链接[`www.raspberrypi.org/help/noobs-setup/`](http://www.raspberrypi.org/help/noobs-setup/)中提供。

将 Raspbian Wheezy 操作系统烧录到你的 SD 卡：

这是我最喜欢的设置，因为我已经下载了操作系统，将直接将其烧录到我的 SD 卡上；以下是在 Mac OS X 上执行此操作的步骤（确保你有一个有效的 SD 卡，容量为 4/8/16GB，等级为 10）：

我们需要将 SD 卡格式化为 FAT32。我们可以使用 SD Formatter 4.0 轻松实现这一点，它适用于 Windows 或 Mac，可以从 SD 协会的网站[`www.sdcard.org/downloads/formatter_4/eula_mac/index.html`](https://www.sdcard.org/downloads/formatter_4/eula_mac/index.html)下载。

按照安装软件包的说明进行操作：

1.  将你的 SD 卡插入计算机或笔记本电脑的 SD 卡读卡器，并*记下*分配给它的驱动器号—例如，在我的情况下是`/disk2`。

1.  在**SDFormatter**中，选择你的 SD 卡的驱动器号，转到**格式选项**并选择**覆盖格式**，命名为`RaspWheezy`（可选），然后点击**格式化**。根据卡的大小，格式化 SD 可能需要一些时间。![使用 NOOBS](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_03.jpg)

使用 SDFormatter 应用程序格式化 SD 卡

1.  格式化完成后，关闭 SDFormatter。如果你在 Mac 或 Linux 上，从终端运行以下命令行来检查磁盘号和格式类型：

```java
$ diskutil list

```

在这种情况下，SD 卡是`/dev/disk2`，格式类型为`DOS_FAT_32`，名称为`RASPWHEEZY`。在 Windows 上，打开 Windows 资源管理器并检查驱动器。

### 注意

不要搞错了，否则可能会破坏错误的`磁盘/卡/驱动器`上的所有数据。

1.  从链接[`downloads.raspberrypi.org/raspbian_latest`](http://downloads.raspberrypi.org/raspbian_latest)下载 Raspbian Wheezy 操作系统，解压缩，你应该会得到`2015-02-16-raspbian-wheezy.img`文件。

1.  在 Mac 或 Linux 的命令行上，卸载磁盘但不要弹出：

```java
$ diskutil unmountDisk /dev/disk2

```

1.  然后使用`dd`命令将镜像写入 SD 卡：

```java
$ sudo dd if=/path/to/2015-02-16-raspbian-wheezy.img of=/dev/rdisk2 bs=1m

```

输入密码后，写入过程开始，你需要等待直到再次获得提示。由于这将需要几分钟，在 Windows 上，你可以使用 Win32DiskImager（可以从[`www.raspberry-projects.com/pi/pi-operating-systems/win32diskimager`](http://www.raspberry-projects.com/pi/pi-operating-systems/win32diskimager)下载）。

1.  `dd`命令完成后，弹出卡：

```java
$ sudo diskutil eject /dev/rdisk2

```

### 注意

请注意，`dd`在没有错误或完成之前不会反馈任何信息；完成后将显示信息并重新挂载磁盘。但是，如果你希望查看进度，可以使用*Ctrl* + *T*快捷键。这会生成**SIGINFO**，你的`tty`的状态参数，并显示有关该进程的信息。

恭喜，现在将你的 SD 卡安装到树莓派上，并连接到合适的显示器上启动它。

## 配置树莓派

现在，我们需要为第一次启动设置 Pi，并配置一个静态 IP 以便从我们的笔记本电脑和远程连接到它：

1.  挂载我们之前准备好的 SD 卡。

1.  连接键盘、鼠标和显示器电缆。

1.  将 WiFi 适配器插入其中一个 USB 端口。

1.  现在，将电源线插入 Pi。

1.  你应该在屏幕上看到一些详细的输出，启动 Raspbian 操作系统。大胆前行，毫无畏惧。

1.  在第一次启动时，树莓派配置屏幕将显示，并为你提供一系列选项，你可以用它们来配置你的树莓派。基本上，你会想要设置你的时区和本地配置。查看在 CPU 和 GPU 之间的内存分配设置，或者启用 SSH。但在大部分情况下，你可以简单地忽略它们，用箭头键移动到最后一步，然后按回车键。

1.  如果在配置过程中选择了你不喜欢的东西，你可以通过在控制台中输入`sudo raspi-config`来重新启动配置。

1.  如果树莓派配置正确，你会看到一系列 Linux 启动消息滚动，然后会出现一个登录请求。默认用户登录是`pi`，密码是`raspberry`。现在，你将看到一个标准的 Linux 提示符。恭喜，你的树莓派已经启动运行。

1.  Wheezy 带有图形用户界面。只需输入`sudo startx`，你就会看到一个色彩丰富的用户界面，包括游戏、文字处理器和网页浏览器，如下面的截图所示：![配置树莓派](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_04.jpg)

树莓派桌面

树莓派桌面是**轻量级 X11 桌面环境**（**LXDE**）。花一些时间来探索它。你会发现它非常熟悉，尽管比你的高性能台式电脑慢一些。

当你完成 LXDE 后，只需注销，你就会回到 Linux 提示符。为了保存在 SD 卡上的信息，优雅地关闭你的树莓派是很重要的。在你拔掉电源线之前，发出一个关闭命令：

```java
$ Sudo shutdown -h now.

```

这将确保在关闭所有进程之前将所有内容写入 SD 卡。现在，你可以安全地拔掉电源线，这就是树莓派的开关的全部功能。

恭喜，你已经完成了你的第一个树莓派会话。

## 远程连接到树莓派

通常，你会使用外围设备和显示器连接到你的树莓派，但这并不总是情况，因为在开发阶段或树莓派本身被用作控制家用电器的酷炫服务器时，你需要从你的计算机、浏览器甚至移动设备上控制你的树莓派。

给树莓派分配固定的网络地址并不是必需的，但强烈建议这样做。这样做意味着你总是使用相同的地址（或名称，如果你在主机文件中创建了一个条目）连接到你的树莓派，因此它会从你的开发过程中删除一个潜在的变量。

更新网络 DHCP 设备/路由器与树莓派的 IP 地址也是一个好主意，这样它就不会尝试将其分配给网络上的另一个设备。执行此操作所需的步骤将因交换机/路由器制造商而异。

我们将在树莓派上安装 VNC 服务器。**虚拟网络计算**（**VNC**）允许你通过网络控制一台计算机。它提供了一个图形用户界面，包括鼠标和键盘。在我们的情况下，它将允许我们看到和使用树莓派的 GUI，而无需连接到树莓派的物理键盘和鼠标。

目前，这是一个便利，如果你对当前的鼠标、键盘和显示器设置满意，你可以跳过这一部分。当你开始尝试需要一个或多个 USB 端口的设备时，VNC 将成为必需品。

设置 VNC 有五个步骤：

1.  连接到家庭 WiFi 互联网。

1.  在树莓派上安装 VNC。

1.  设置开机启动。

1.  设置静态 IP 地址。

1.  使用客户端连接 VNC。

远程连接到 WiFi 互联网，Raspbian Wheezy 包括一个 WiFi 配置实用程序。此外，2012 年 10 月 28 日之后发布的所有 Raspbian 都预装了此实用程序。

### 注意

设置 WiFi 要求你的路由器正在广播 SSID。确保你的路由器上设置了*广播 SSID*！这不适用于私人 SSID 设置。

现在，让我们远程连接树莓派：

1.  从 Raspbian 桌面，转到**菜单** | **首选项** | **WiFi 配置**，如下屏幕截图所示：![远程连接树莓派](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_05.jpg)

选择 WiFi 配置实用程序

1.  双击图标，您将看到以下窗口：![远程连接树莓派](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_06.jpg)

WiFi 配置实用程序 GUI

1.  单击**扫描**按钮，将打开第二个窗口。在列表中找到您的无线接入点，并双击它。这将打开另一个窗口：![远程连接树莓派](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_07.jpg)

接入点列表

1.  在`PSK`字段中输入密码，然后单击**添加**。当您查看第一个窗口时，您应该看到连接已经设置好可以使用。![远程连接树莓派](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_08.jpg)

添加接入点的最终状态

您可以使用按钮连接或断开连接。您可以在前面的屏幕截图中看到树莓派的 IP 地址显示在窗口底部。

请注意，有一个手动程序可以在终端上设置 WiFi 连接。这需要编辑`config`文件并手动添加网络的 SSID 和密码。有关更多信息，请访问[`www.raspberrypi.org/documentation/configuration/wireless/wireless-cli.md`](https://www.raspberrypi.org/documentation/configuration/wireless/wireless-cli.md)。

恭喜，您的树莓派已连接到互联网。现在让我们安装 VNC 服务器。

### 在树莓派上安装 VNC

现在您已经连接到互联网，可以在树莓派上安装 VNC 服务器。如果您使用的是 Raspbian Wheezy，这很简单。在命令提示符下，输入以下命令：

```java
$ sudo apt-get install tightvncserver

```

您将收到消息：**您想继续吗？是或否？**

让我们用大写*Y*回答并休息一下。安装完成后，输入以下命令：

```java
$ vncserver

```

您将被要求创建一个密码，我使用*raspberry*。它指出密码长度超过八个字符；继续重新输入`raspberry`。接下来，您将被问到：**您想输入只读密码吗？**输入*N*表示否。

恭喜，您已在树莓派上运行 VNC。

#### 设置 VNC 在启动时启动

随着您变得更加高级，您可能并不总是需要 VNC，但让我们假设您希望每次启动树莓派时都运行 VNC：

1.  使用以下命令从 Pi **LX 终端**编辑`rc.local`文件：

```java
$ sudo nano /etc/rc.local

```

1.  滚动到底部，在`exit 0`上面添加以下行：

```java
su -c "/usr/bin/tightvncserver -geometry 1280x1024" pi

```

1.  保存文件并使用以下命令重新启动树莓派：

```java
$ sudo shutdown -r now

```

1.  现在，每次启动树莓派时，VNC 都将可用。

### 设置静态 IP 地址

通过 VNC 连接树莓派需要一个静态 IP 地址，即不会更改的 IP 地址。我将向您展示如何在接下来的几个步骤中为有线和无线网络获取静态 IP 地址：

1.  如果您在家庭网络上，您需要发现一个可用的 IP 地址。为此，转到您的树莓派，打开 Pi LX 终端，然后输入：

```java
mohamed_taman$ ifconfig –a

```

然后，输入以下命令：

```java
mohamed_taman$ netstat -nr

```

1.  收集以下信息：*当前 IP*（如果您想保留它），*子网掩码*，*网关*，*目的地*和*广播*。记下这些，您很快会需要它们！

1.  在树莓派上，通过运行以下命令备份`/etc/network/interfaces`：

```java
$ sudo cp /etc/network/interfaces /etc/network/interfaces.org

```

1.  使用以下命令修改`interfaces`文件：

```java
$ sudo nano /etc/network/interfaces

```

1.  从以下更改`interfaces`文件：![设置静态 IP 地址](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_09.jpg)

编辑前的 interfaces 文件

1.  选择适合您网络的 IP 号码；还要将`wpa-ssid`更改为您的无线网络名称，将`wpa-psk`更改为无线密码：![设置静态 IP 地址](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_10.jpg)

编辑后的 interfaces 文件

1.  保存文件并重新启动树莓派。这些设置适用于有线和无线连接。恭喜，您现在可以使用 VNC 客户端连接到您的树莓派。

### 树莓派的自动登录

像大多数人一样，你可能买了树莓派来为家庭或办公室构建自己的设备。接下来你应该做的是设置树莓派，连接你的外围设备，并安装或开发必要的软件。

你在项目结束时想要的是打开设备并看到你期望的所有魔术。

当 Pi 引导到登录提示并等待你输入用户名和密码时，问题就来了。所以，让我们自动化树莓派登录：

1.  从你的 Pi 上，打开一个终端并使用以下命令编辑`inittab`文件：

```java
sudo nano /etc/inittab

```

1.  通过导航到`inittab`中的以下行来禁用`getty`程序：

```java
1:2345:respawn:/sbin/getty 115200 tty1

```

1.  在该行的开头添加`#`来注释掉它，如下一行所示：

```java
#1:2345:respawn:/sbin/getty 115200 tty1

```

1.  在注释行下方添加一个登录程序到`inittab`：

```java
1:2345:respawn:/bin/login -f pi tty1 </dev/tty1 >/dev/tty1 2>&1

```

1.  这将使用`pi`用户运行登录程序，而无需任何身份验证。

1.  按*Ctrl* + *X*保存并退出，然后按*Y*保存文件，然后按*Enter*确认文件名。

重新启动 Pi，它将直接引导到 shell 提示符`pi@raspberrypi`，而不会提示你输入用户名或密码。

### 使用客户端连接 VNC

在继续之前，让我们确保一切都正常工作。为此，你需要一个 VNC 客户端。如果你使用的是带有最新版本 Mac OS X 的 Macintosh，这很简单。

转到**Finder** | **前往** | **连接到服务器**。输入`vnc://`和你给树莓派分配的 IP 地址。在我的情况下，是 192.168.2.150 后跟一个冒号和数字 5901，如下截图所示。完整的 URL 应该是**vnc://192.168.2.150:5901**。

![使用客户端连接 VNC](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_11.jpg)

连接到 Pi VNC 服务器。

如图所示，`5901`是树莓派 VNC 服务器正在监听的端口号。点击**连接**。不用担心屏幕共享加密，再次点击**连接**。现在输入之前创建的密码（`raspberry`）。如果一切正常，你会看到一个大的树莓。恭喜！

如果你不是在 Macintosh 电脑上，你需要下载一个 VNC 客户端。你可以从[`realvnc.com/`](http://realvnc.com/)获取免费的查看器。有 Windows、iOS、Android 和 Chrome 浏览器的客户端。是的，你可以用手机控制你的树莓派。

# JavaFX 8 开发先决条件

现在，我们已经为开发设置和配置了我们的树莓派，我们需要在我们的开发机器和 Pi 上安装相同正确匹配的 JDK 8 构建版本。这对于在运行我们的 JavaFX 8 应用程序时避免库/版本问题非常重要，这就是我们接下来要做的事情。

## 在树莓派上安装 Java SE 8

在撰写本文时，Raspbian Wheezy 预装了 JDK 8。要检查，只需在 Pi 命令提示符下输入以下内容：

```java
pi@raspberrypi ~ $ java –version

```

你会看到类似于这样的东西，取决于当前安装和可访问的版本：

![在树莓派上安装 Java SE 8](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_12.jpg)

树莓派 Wheezy 上的 Java 版本

重要的是第二行：如果它不是 1.8.n，你需要安装 JDK8。

## 安装 Java SE 8

我们已经在之前安装了我们的 JDK 8，并且所有必要的步骤都在第一章的*安装 Java SE 8 JDK*部分中描述。

## 添加 JavaFX

如前所述，Oracle 已经撤销了对 JavaFX 嵌入式的支持。如果你安装了 JDK 8u45 或预装在 Raspbian Wheezy 上的版本，没有`jfxrt.jar`捆绑，所以我们需要提供它以便在我们的 Pi 上运行 JavaFX 应用程序。

一种方法是按照[`wiki.openjdk.java.net/display/OpenJFX/Cross+Building+for+ARM+Hard+Float`](https://wiki.openjdk.java.net/display/OpenJFX/Cross+Building+for+ARM+Hard+Float)上的教程，为 ARM 交叉构建 OpenJFX。这是给非常高级的开发者。

一个更简单的方法是下载一个预构建的发行版，比如托管在 JavaFXPorts 项目上的`armv6hf-sdk.zip`（[`bitbucket.org/javafxports/arm/downloads`](https://bitbucket.org/javafxports/arm/downloads)）。

一旦你下载了`armv6hf-sdk.zip`，解压它并添加这个命令行选项，将外部源附加到`classpath`上，使用扩展机制：

```java
-Djava.ext.dirs=<path to armv6hf-sdk>/rt/lib/ext

```

或者，你可以将这个 zip 文件中`rt/lib/ext`和`rt/lib/arm`的内容复制到你的 JVM 文件夹中，避免使用扩展机制。

## 为树莓派配置 NetBeans

NetBeans 8 增加了指向远程 JDK 并使用它来远程调试和执行你在本地开发机器上编写的程序的能力。它甚至可以自动无缝地部署你的应用程序。正如 José Pereda 在他的文章[`netbeans.dzone.com/articles/nb-8-raspberry-pi-end2end`](http://netbeans.dzone.com/articles/nb-8-raspberry-pi-end2end)中所记录的，你可以通过以下步骤启用这个功能。

1.  在你的机器上启动 NetBeans。

1.  从菜单栏选择**工具**，然后选择**Java 平台**。点击**添加平台**按钮。

1.  选择**远程 Java 标准版**单选按钮，然后点击**下一步**。

1.  提供以下条目（如下截图所示）：

**平台名称**：`JavaFX on Raspberry Pi JDK 8`

**主机**：输入你之前分配的树莓派的静态 IP 地址或主机名

**用户名**：`pi`

**密码**：`raspberry`

**远程 JRE 路径**：`/usr/lib/jvm/jdk-8-oracle-arm-vfp-hflt/jre`

![为树莓派配置 NetBeans](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_13.jpg)

为 Pi 设置远程平台

1.  点击**完成**按钮，等待 NetBeans 建立和配置远程 JDK 连接。

1.  一旦远程 JDK 就位，点击**关闭**按钮。

现在我们已经完成了设置，你应该拥有一个开发环境，它是为开发 JavaFX 8 应用程序为树莓派提供的最好的之一。那么让我们开始吧！

# 开关应用程序

开关应用程序在其本质上非常简单，但主要分为两个要点：如何在树莓派上运行 JavaFX 8 应用程序，以及如何从树莓派的**通用输入/输出**（**GPIO**）控制外部世界。我们将使用一个名为**Pi4j**的项目来实现这个目的。

这个想法很简单；我们将创建一个 JavaFX 应用程序，它将充当一个开关控制器，用于控制连接到你的树莓派的电路上的 LED。

以下截图显示了应用程序处于开启和关闭状态：

![开关应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_14.jpg)

开启应用程序开关状态

为树莓派配置 NetBeans

![开关应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_15.jpg)

关闭应用程序开关状态

## 什么是 Pi4J 库？

Pi4j 库（[`pi4j.com`](http://pi4j.com)）是一个旨在提供本地库和 Java 之间的桥梁，以完全访问树莓派功能和控制的项目，因此你可以轻松地访问 GPIO 引脚用于你的 Java 项目。

访问[`pi4j.com/pins/model-2b-rev1.html`](http://pi4j.com/pins/model-2b-rev1.html)查看树莓派 2 型 B（J8 头）的 GPIO 引脚编号。此外，你的套件的 GPIO 适配器可能附带 GPIO 引脚头的快速参考。

对于这个例子，你将需要一些基本的电子元件，比如 LED、电阻和面包板。如果你的套件中没有包括这些，你可以从网上商店购买。

### 电路设置

现在我们需要通过在面包板上添加一个带有 220 欧姆上拉电阻的 LED 来设置我们的电路，并将阳极连接到 GPIO 引脚＃1，阴极连接到 GPIO GND 引脚，如下图所示（CanaKit 附带了一个常用电子零件的通用组装指南）：

![电路设置](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_16.jpg)

开关器应用电路设置

## 应用程序

如前所述，应用程序 UI 包含两个按钮。**退出！**负责关闭 GPIO 控制器并关闭应用程序。第二个按钮是一个切换按钮（**开**/**关**），可以作为开关使用。它有两种状态：选中时，其状态为 true，当未选中时，其状态为 false。此外，我们通过编程方式更改其标签，以指示当前受控 LED 的状态。

此外，还有一个圆形形状，模仿了物理 LED 状态。因此，当切换按钮打开时，圆圈将填充为红色。关闭时，它变成黑色，这是默认状态。

最后，在应用程序场景的底部，我们添加一个名为 Pi 信息的`TitledPane`，显示一些树莓派信息。

通过查看`SwitchUIController.java`类，您会发现在与`Pi4J`库交互之前，我们有一些非常重要的字段要声明：

```java
private GpioController gpio;
private GpioPinDigitalOutput pin;
```

第一行负责创建一个新的 GPIO 控制器实例，这是通过`initialize()`方法通过`GpioFactory`完成的，因为它包括一个`createInstance`方法来创建 GPIO 控制器：

```java
gpio = GpioFactory.getInstance();
```

### 注意

您的项目应该只实例化一个 GPIO 控制器实例，并且该实例应该在整个项目中共享。

要访问 GPIO 引脚，必须首先配置引脚。配置根据您打算如何使用它来配置引脚。配置可以自动导出引脚，设置其方向，并为基于中断的事件设置任何边缘检测：

```java
// provision gpio pin #01 as an output pin and turn on
pin = gpio.provisionDigitalOutputPin(GPIO_01);
```

这是如何配置输出引脚＃1。您的程序将只能控制那些配置为输出引脚的引脚的状态。输出引脚用于控制继电器、LED 和晶体管。

现在我们想要做的就是使用切换按钮从我们的应用程序控制 LED。这是通过注册到切换按钮的`doOnOff()`事件函数来完成的，如下面的代码所示：

```java
    @FXML
    private void doOnOff(ActionEvent event) {
        if (switchTgl.isSelected()) {
            pin.high();
            led.setFill(RED);
            switchTgl.setText("OFF");
            System.out.println("Switch is On");
        } else {
            pin.low();
            led.setFill(BLACK);
            switchTgl.setText("ON");
            System.out.println("Switch is Off");
        }
    }
```

`P14J`库提供了许多方便的方法来控制或向 GPIO 引脚写入状态。在我们的应用程序中，我们使用`pin.high()`来打开 LED，使用`pin.low()`来关闭 LED。

最后，当应用程序退出时，我们必须关闭 GPIO 控制器。Pi4J 项目提供了一个实现，可以在应用程序终止时自动将 GPIO 引脚状态设置为非活动状态。

这对于确保 GPIO 引脚状态在程序关闭时不活动或保持某些活动是有用的。我们可以简单地使用我们之前创建的 GPIO 实例的以下代码行来实现这一点：

```java
gpio.shutdown();
```

当您按下切换按钮以打开 LED 时，您会看到绿色 LED 发光。当它关闭时，您会看到 LED 变暗。

![应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_17.jpg)

应用电路-LED 关闭

![应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_18.jpg)

应用电路-LED 开启

接下来，让我们配置我们的项目，从 NetBeans 直接在树莓派上运行我们的 JavaFX 开关应用程序。

# 在 NetBeans 中使用 Pi

在讨论了我们的应用程序逻辑并了解了它的工作原理之后，现在是最好的部分：使用 NetBeans 构建您的应用程序并在树莓派上运行它。步骤如下：

1.  在 NetBeans 的**项目**选项卡中右键单击`Chapter6`项目，然后选择**属性**。

1.  从**项目属性**框中，从左侧的**类别**菜单中选择**运行**。您将看到一个类似于以下截图的对话框：![在 NetBeans 中使用 Pi](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_19.jpg)

项目属性对话框和运行实例

1.  单击所选“配置”右侧的“新建”按钮。为“新配置”（`Pi Remote Config`）设置一个名称，然后单击“确定”按钮，如下面的屏幕截图所示：![使用 NetBeans 与 Pi](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_20.jpg)

新配置

1.  现在您必须将远程 JDK 与远程配置关联起来。要这样做，单击标记为“运行平台”的组合框，并选择您之前配置的`JavaFX on Raspberry Pi JDK 8`。不要忘记在“VM 选项”中添加`jfxrt.jar`的路径：![使用 NetBeans 与 Pi](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_06_21.jpg)

远程 Pi JDK 关联

1.  最后一步是构建并部署应用程序到树莓派。要这样做，转到“运行”菜单，选择“运行项目”，并观看 NetBeans 输出窗口/选项卡。在运行应用程序时，如果您留意 Pi 的屏幕，您将看到以下输出消息：

```java
jfx-deployment-script:
jfx-deployment:
jar:
Connecting to 192.168.2.150:22
cmd : mkdir -p '/home/pi/NetBeansProjects/Chapter6/dist'
Connecting to 192.168.2.150:22
done.
profile-rp-calibrate-passwd:
Connecting to 192.168.2.150:22
cmd : cd '/home/pi/NetBeansProjects/Chapter6';
'/usr/lib/jvm/jdk-8-oracle-arm-vfp-hflt/jre/bin/java'  -Dfile.encoding=UTF-8 -jar /home/pi/NetBeansProjects/Chapter6/dist/Chapter6.jar
```

# 摘要

在本章中，我们将信用卡大小的微型计算机（不大于一副扑克牌）转变为一个 JavaFX 开关控制器机。在此过程中，您学会了关于树莓派的知识，如何创建可引导的 SD 卡，如何将操作系统安装到其中，如何为其配置最佳性能和远程连接性，如何为其分配固定的网络（IP）地址，以及如何从开发机连接到 Pi。

我们还重新讨论了如何在树莓派和开发机上安装 JDK 8/ JavaFX 8，并学会了如何在开发机上安装和配置 NetBeans，以便它可以使用 Pi 上的 JDK 作为远程平台进行调试和执行。

在您的开发机和树莓派都准备就绪后，我们讨论了使用 JavaFX 和一些选择的工具/ API（包括 Pi4j）开发一个简单但很棒的应用程序来控制树莓派外部世界所需的原则。

最后，您学会了如何从 NetBeans 远程部署应用程序到树莓派，只需点击几下即可。

在下一章中，我们将监控一个温度传感器，从 Arduino 板上测量您的血液有多热。


# 第七章：使用 JavaFX 监控和控制 Arduino

**Arduino**是一种基于简单可编程微控制器板的开源电子工具，可以使用免费开源 IDE 进行编程。单独或连接到计算机，它可以创建可以通过从各种开关或传感器获取输入来感知，并可以通过控制各种灯、电机和其他输出物理设备来执行的交互式设备。

作为第一批**物联网**（**IoT**）设备之一，它是在 2005 年创建的。它从物联网概念的最初阶段就存在。

Arduino 可以独立运行，也可以与计算机上运行的软件（Java、JavaFX、Python 等）进行通信，板可以手工组装或购买预装的。

事实上，Arduino 简化了与微控制器的工作过程。对于教师、学生和有兴趣的业余爱好者来说，它比其他系统更具吸引力，因为它*价格低廉*——Arduino 板的成本低于 50 美元。

简单、清晰、易于使用的编程环境；开源和可扩展的软件；以及开源和可扩展的硬件等功能，使 Arduino 支持自己动手和与他人一起动手的概念，这是制造运动的定义。

本章将向您展示如何使用 JavaFX 开发桌面应用程序以及 Arduino 板，以监视来自真实世界温度传感器的数据，并在图表上报告它，“你到底有多热血！”

在本章中，您将：

+   熟悉 Arduino 板及其组件

+   安装和准备 Arduino 软件和环境、IDE 和驱动程序

+   开发 Arduino 血糖仪草图以控制和监视电路

+   使用串行通信将 Arduino 数据读入 JavaFX 应用程序

+   使用 JavaFX 图表 API 呈现数据

# Arduino 板是什么？

Arduino Uno 是最知名的 Arduino 板，是基于 ATmega328 数据表（[`www.atmel.com/dyn/resources/prod_documents/doc8161.pdf`](http://www.atmel.com/dyn/resources/prod_documents/doc8161.pdf)）的微控制器板，这是板的大脑。它大约 3 x 2 英寸大小。它有 14 个数字输入/输出引脚，6 个模拟输入引脚和 32 千字节的闪存内存。

每个板都有一个复位按钮。此外，它包括一个 USB 端口，因此当连接到计算机时，它成为电源和通信工具。如果未连接到计算机，可以使用备用电源，例如 AC 9 至 12V DC 适配器，可以通过将 2.1 毫米中心正极插头插入板的电源插孔，或 9V 电池包连接。

带有波浪符号的六个数字引脚旁边的引脚是允许**脉宽调制**（**PWM**）的引脚，这是一种用于控制电源并在数字输入引脚上模拟模拟信号的技术。使用这些引脚的原因之一可能是控制 LED 的亮度。

Arduino Uno 的官方规格可以在[`arduino.cc`](http://arduino.cc)网站的[`arduino.cc/en/Main/ArduinoBoardUno`](http://arduino.cc/en/Main/ArduinoBoardUno)上找到。访问[`www.arduino.cc/en/Main/Products`](http://www.arduino.cc/en/Main/Products)以获取有关其他 Arduino 板的信息，例如 Mega，Due 或 Yun，以及下一个发布的 Tre 和 Zero。

以下图片显示了 Arduino Uno R3 板：

![什么是 Arduino 板？](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_01.jpg)![什么是 Arduino 板？](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_02.jpg)

## 你可以用它做什么？

您的 Arduino 板可能很小，但不要让它的大小欺骗您。它功能强大，有很大的发展空间。它特别强大，因为它是建立在开放硬件和开放软件平台上的。我们不会花时间讨论开源；简而言之，这意味着有关硬件和软件的信息是免费提供的，易于找到。

Arduino 可以用来通过接收输入来感知环境。它也可以控制输出，如灯、电机、传感器等。

你可以使用开源的 Arduino 编程语言对板上的微控制器进行编程。

### 相关网站和文档

开源和开放硬件平台的一个很大的优势是你可以在互联网上找到信息。

寻找关于 Arduino 信息的好地方是官方页面：[`arduino.cc`](http://arduino.cc)网站的[`arduino.cc/en/Guide/HomePage`](http://arduino.cc/en/Guide/HomePage)。随着你的技能增长，你会想要研究更高级的主题，知道在哪里找到答案会很有帮助。

另一个很棒的网站是[`adafruit.com`](http://adafruit.com)。这个网站有教程、示例、有用的论坛，还有一个可以购买你需要的零件的商店。

对于孩子们来说，另一个有趣的应用是将**乐高 Mindstorm**传感器和电机与 Arduino 结合使用。我推荐网站[`wayneandlayne.com`](http://wayneandlayne.com)，因为它一直是我整合乐高和 Arduino 的灵感和起点。如果你正在寻找零件和项目，这是一个很好的网站。

## 设置你的 Arduino

如果这是你第一次接触 Arduino，我强烈建议你从套件开始，而不是组装所有的单个组件。

本章中的大部分活动都可以使用来自 arduino.cc 的 Arduino 入门套件完成，如下图所示。它包括了 Arduino Uno R3 和其他组件，可以完成大部分预先打包的项目。有关套件的完整描述，请访问[`store.arduino.cc/product/K000007`](http://store.arduino.cc/product/K000007)。

![设置你的 Arduino](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_03.jpg)

Arduino 入门套件（包括零件、板和项目书）

### 购买 Arduino

虽然 Arduino Uno 的成本约为 25 美元，但你可以购买不同的套件，包括板，从基本的 Budget Pack（50 美元）到 Arduino Starter Pack（65 美元）的[`adafruit.com`](http://adafruit.com)，或者从[`arduino.cc`](http://arduino.cc)购买 Starter Kit（90 美元）。这些套件与 Budget Pack 具有相同的组件，但它们还包括一些额外的高级调试工具。

从[`arduino.cc`](http://arduino.cc)的入门套件中获得的一个很好的优势是，它包括了一个指导书，其中包括了 15 个不同难度的项目。

如果你是亚马逊用户，通常可以在他们的网站上找到相同的套件，但价格可能会有所不同。

大多数板的核心组件位置相同。因此，更高级的板已经加长以容纳额外的组件。

以下是一些购买零件和书籍的网站：[`arduino.cc`](http://arduino.cc), [`Adafruit.com`](http://Adafruit.com), [`makershed.com`](http://makershed.com), [`sparkfun.com`](http://sparkfun.com), 和 [`Amazon.com`](http://Amazon.com)。

### 你将需要的其他组件

除了 Arduino，你还需要一台带有 Windows、Mac OS 或 Linux 的计算机，带有 USB 端口，用于将计算机连接到板上。

对于血糖仪项目，你将需要一些已经包含在 Arduino 入门套件中的零件。以下是你应该准备好的零件的简短清单。

一台带有 USB 端口的计算机，一根 USB 电缆，一个无焊面包板，柔性导线，一个 TMP36 温度传感器，三个 220 欧姆电阻，和三个 LED 灯（黄色、蓝色和红色），如下图所示：

![你将需要的其他组件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_04.jpg)

血糖仪项目的工具和材料

### Arduino 集成开发环境

为了与 Arduino 微控制器进行交互和编程，我们需要下载并安装 Arduino 集成开发环境。

Arduino 软件包括您编写代码所需的所有组件，文本编辑器和编译器将其转换为机器语言，并将其上传到您的板并运行代码。

#### 下载 IDE

在撰写本文时，Arduino IDE 版本为 1.6.3，但您可以从链接[`www.arduino.cc/en/Main/Software`](http://www.arduino.cc/en/Main/Software)获取 Arduino 软件的最新版本。除了以下截图中显示的 Arduino 版本外，还要单击首选操作系统链接；在我的情况下，我选择了 Mac OS X。

从捐赠页面，要么捐赠，要么只需单击**JUST DOWNLOAD**链接即可开始下载 IDE；在我的情况下，我选择了`arduino-1.6.4-macosx.zip`。

下载后，解压文件并将`Arduino.app`文件复制到 Mac 上的应用程序文件夹，或者将 Arduino 可执行文件链接到您方便访问的位置。

一旦您下载了 IDE，您仍然需要解决一些硬件问题，然后才能开始编程。

![下载 IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_05.jpg)

下载 Arduino IDE 1.6.4

#### 安装驱动程序

首先，您需要使用 USB 电缆将 Arduino 板连接到计算机。绿色 LED 电源指示灯（标有 PWR 或 ON）应亮起。

##### Windows 设置

让我们在 Windows 中设置 Arduino：

1.  插入您的板，并等待 Windows 开始其驱动程序安装过程。

1.  单击**开始菜单**，然后打开**控制面板**。

1.  从**控制面板**，导航到**系统和安全**。接下来，单击**系统**。打开系统窗口后，选择**设备管理器**。

1.  查看**端口（COM 和 LPT）**。您应该看到一个名为`Arduino UNO（COMxx）`的开放端口。如果没有**COM 和 LPT**部分，请在**其他设备**下查找**未知设备**。

1.  右键单击**Arduino UNO（COMxx）**端口，然后选择**更新驱动程序软件**选项。

1.  接下来选择**浏览我的计算机以查找驱动程序软件**选项。

1.  最后，导航并选择名为`arduino.inf`的驱动程序文件，该文件位于 Arduino 软件下载的`Drivers`文件夹中（而不是`FTDI USB Drivers`子目录）。

1.  Windows 将完成驱动程序安装。

### 提示

如果您使用的是 Windows 8，驱动程序安装不完整，请尝试禁用驱动程序签名强制执行。

##### Mac OS X 和 Linux 设置

对于 Mac OS X 和 Linux 操作系统，不需要安装驱动程序。

对于 Mac OS X，当您连接 Arduino 板时，您应该在`/dev/tty.usbmodemXXXX 或/dev/tty.usbserialXXXX`下看到它列出。

在 Linux 上，当您连接 Arduino 板时，您应该在`/dev/ttyACMX 或/dev/ttyUSBX`下看到它列出。

#### 探索 IDE 和草图

假设您的安装成功结束，双击 Arduino 应用程序，您应该看到以下屏幕：

![探索 IDE 和草图](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_06.jpg)

Arduino IDE，首次运行为空草图

现在，您需要做两件重要的事情，以便正确连接和上传草图到 Arduino 板。首先，通过导航到**工具** | **板**来选择您的板。然后，通过转到**工具** | **串行端口**来选择 Arduino 板的串行端口。

最后的验证步骤是运行 Arduino 的`Hello world`，您可以通过在**文件** | **示例** | **1.Basics** | **Blink**中打开 LED 闪烁示例草图来实现。

现在，只需在环境中单击**上传**按钮。如果上传成功，状态栏中将出现消息**上传完成**。

等待几秒钟，您将看到板上的**RX**和**TX** LED 闪烁。

如果您遇到任何问题，请查看[`arduino.cc/en/Guide/Troubleshooting`](http://arduino.cc/en/Guide/Troubleshooting)上的故障排除建议。

恭喜，您的 Arduino 已经启动运行！

## 血糖仪项目

在这个项目中，我们将使用温度传感器来测量你的皮肤温度，然后根据温度来开启（或关闭）LED 灯。

首先，我们将调整我们的板子，并准备好使用*其他你需要的组件*部分中描述的组件进行项目。然后，我们将编写草图来读取传感器数据，并根据你的皮肤温度的数据，来开启和关闭 LED 灯。

最后，我们将用温度传感器数据来供给我们的 JavaFX 应用，并使用图表 API 显示结果，以指示你的皮肤温度水平。

### 调整电路

现在，我们将调整我们的血糖仪电路，如下图所示。首先，通过连接跳线线将 Arduino UNO 和面包板连接起来。我已经将 TMP36 温度传感器连接到了面包板上，所以传感器的圆形部分远离 Arduino。引脚的顺序非常重要！请注意，我们已经将左边的引脚连接到电源，右边的引脚接地，中间输出电压的引脚连接到板子上的模拟引脚 A0。如下图所示：

![调整电路](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_07.jpg)

血糖仪示例的电路布局

最后，我已经连接了三个 LED 灯和电阻，并将它们连接到数字 PMW~引脚排的 Arduino 引脚 4、~3 和 2。

像往常一样，我已经将面包板的+行连接到电源（5V），-行连接到地（GND）。

### 注意

记得在设置组件时保持板子未插电。

#### 草图

在我们调整了电路并配置了一切之后，我们需要对微控制器进行编程。这就是草图将发挥作用的地方：

```java
/*
  Chapter 7 example
  Project  - Blood-Meter

  This sketch is written to accompany Project in the
  JavaFX 8 essentials book

  Parts required:
  1 TMP36 temperature sensor
  3 red LEDs
  3 220 ohm resistors

  Created 5 April 2015
  by Mohamed Mahmoud Taman
  */

// named constant for the pin the sensor is connected to
const int sensorPin = A0;
// Room temperature in Celsius
const float baselineTemp = 25.0;

void setup() {
  // open a serial connection to display values
  Serial.begin(9600);
  // set the LED pins as outputs
  // the for() loop saves some extra coding
  for (int pinNumber = 2; pinNumber < 5; pinNumber++) {
    pinMode(pinNumber, OUTPUT);
    digitalWrite(pinNumber, LOW);
  }
}

void loop() {
  // read the value on AnalogIn pin 0
  // and store it in a variable
  int sensorVal = analogRead(sensorPin);

  // send the 10-bit sensor value out the serial port
  Serial.print("Sensor Value: ");
  Serial.print(sensorVal);

  // convert the ADC reading to voltage
  float voltage = (sensorVal / 1024.0) * 5.0;

  // Send the voltage level out the Serial port
  Serial.print(", Volts: ");
  Serial.print(voltage);

  // convert the voltage to temperature in degrees C
  // the sensor changes 10 mV per degree
  // the datasheet says there's a 500 mV offset
  // ((voltage - 500mV) times 100)
  Serial.print(", degrees C: ");
  float temperature = (voltage - .5) * 100;
  Serial.println(temperature);

  // if the current temperature is lower than the baseline
  // turn off all LEDs
  if (temperature < baselineTemp) {
    digitalWrite(2, LOW);
    digitalWrite(3, LOW);
    digitalWrite(4, LOW);
  } // if the temperature rises 2-4 degrees, turn an LED on
  else if (temperature >= baselineTemp + 2 && temperature < baselineTemp + 4) {
    digitalWrite(2, HIGH);
    digitalWrite(3, LOW);
    digitalWrite(4, LOW);
  } // if the temperature rises 4-6 degrees, turn a second LED on
  else if (temperature >= baselineTemp + 4 && temperature < baselineTemp + 6) {
    digitalWrite(2, HIGH);
    digitalWrite(3, HIGH);
    digitalWrite(4, LOW);
  } // if the temperature rises more than 6 degrees, turn all LEDs on
  else if (temperature >= baselineTemp + 6) {
    digitalWrite(2, HIGH);
    digitalWrite(3, HIGH);
    digitalWrite(4, HIGH);
  }
  delay(100);
}
```

#### 工作原理

如果你阅读每行的注释，你会理解代码。不深入细节，以下是草图的主要要点。

每个 Arduino 草图都有两个主要的方法：`setup()`和`loop()`。第一个方法用于初始化引脚为输入或输出，打开串行端口，设置它们的速度等。第二个方法在微控制器内部重复执行任务。

一开始，我们有一对有用的常量：一个引用模拟输入，另一个保存基准温度。对于每*2 度*高于这个基准温度，一个 LED 将打开。

在`setup()`方法中，我们将串行端口初始化为每秒 9,600 位的速度，并使用`for`循环将一些引脚设置为方向（输出引脚）并关闭它们。

在`loop()`方法中，我们开始读取温度传感器的电压数值，范围在 0 到 1,023 之间，然后使用`Serial.print()`将传感器数值发送到串行端口，以便任何连接的设备（例如我们的计算机）可以读取。这些模拟读数可以测量房间的温度或者如果你触摸传感器的话，也可以测量你的皮肤温度。

我们需要使用以下方程将模拟传感器读数转换为电压值：

```java
voltage = (sensorVal / 1024.0) * 5.0
```

从数据表中，我们使用传感器规格将电压转换为温度的方程：

```java
temperature = (voltage - .5) * 100
```

根据实际温度，你可以设置一个`if else`语句来点亮 LED 灯。使用基准温度作为起点，每增加 2 度温度，你将打开一个 LED 灯。

当你在温度刻度上移动时，你会寻找一系列数值。

**模拟到数字转换器**（**ADC**）读取速度非常快（以微秒为单位），建议在`loop()`函数的末尾设置 1 毫秒的延迟。但考虑到这将被发送到串行端口，最终设置了 100 毫秒的延迟。

#### 测试、验证并将草图上传到 Arduino

将代码上传到 Arduino 后，点击串行监视器图标，如下图所示：

![测试、验证并将草图上传到 Arduino](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_08.jpg)

Arduino IDE 工具栏图标

您应该看到一系列数值以如下格式输出：

```java
Sensor Value: 158, Volts: 0.77, degrees C: 27.15
```

现在尝试在传感器插入面包板时用手指触摸传感器周围，看看串行监视器中的数值会发生什么变化。

在传感器放在空气中时记下温度。关闭串行监视器并将 `baselineTemp` 常量更改为您之前观察到的值。再次上传代码并尝试再次握住传感器；随着温度的升高，您应该看到 LED 逐个打开。

恭喜，热门！

### 从串行端口读取数据

在 Java 中没有标准的方法来读取串行端口，因为这是一个硬件特定的任务，违反了 Java 的多平台概念。因此，我们需要一个第三方库来完成这项任务，并且它应该是用 Java 编写的，以便与我们的应用程序集成。

Arduino IDE 使用了第一个串行通信库，称为 **RXTX**。最初来自 Trent Jarvi，并在 LGPL v2.1+ Linking Over Controlled Interface 许可下分发，直到 1.5.5 beta 版本与板通信。然而，它非常慢，现在已经不推荐使用。

新的 **Java Simple Serial Connector** (**jSSC**) 库由 Alexey Sokolov 开发，根据 GNU Lesser GPL 许可。自 1.5.6 beta 版本以来，Arduino IDE 使用新库进行板通信，因为它比之前的版本更快。

该库的另一个重要优势是，它作为单个 `jssc.jar` 文件进行分发，其中包括所有平台的本地接口，以减少每个平台和操作系统的本地安装的痛苦。它会在运行时将它们添加到 `classpath` 中，如下截图所示：

![从串行端口读取数据](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_09.jpg)

jSSC 2.8.0 本地库

您可以从[`github.com/scream3r/java-simple-serial-connector/releases`](https://github.com/scream3r/java-simple-serial-connector/releases)下载最新版本。在撰写本文时，jSSC 版本为 2.8.0。

### JavaFX 血糖监测应用程序

我们将设计一个 JavaFX 8 应用程序，该应用程序从温度传感器中获取读数，并在折线图中显示数值。我们还将展示模拟板 LED 的一组形状的变化。为了清晰起见，我们将使用两个类，一个用于串行读数，另一个用于 JavaFX UI 和主应用程序 `BloodMeterFX` 文件，包括图表 API。

我们将使用一个包含从串行端口读取的最后一行的 StringProperty 来绑定这些类（Serial 和 BloodMeterFX）。通过在 JavaFX 线程中监听此属性的更改，我们将知道何时有新的读数要添加到图表中。

完整的项目代码可以从 *Packt Publishing* 网站下载。

#### Java 中的串行通信

让我们首先解释 `Serial.java` 类。这个类的代码大部分来自 *JavaFX 8 Introduction By Example, Apress*，但核心读取函数有所改变，如下面的代码片段所示：

您应该将 `jSSC.jar` 文件包含到您的类路径中，可以通过将其添加到 Linux 或 Windows 的 `<JAVA_HOME>/jre/lib/ext`（或 Mac 上的 `/Library/Java/Extensions`）中，或者更好地将其添加到您的项目库中，如前面的截图所示，如果您打算分发您的应用程序。

为了能够读取串口，我们需要导入以下 jSSC 类：

```java
import jssc.SerialPort;
import static jssc.SerialPort.*;
import jssc.SerialPortException;
import jssc.SerialPortList;
```

为了动态读取端口，如果您不知道通过这个类的构造函数设置的确切端口名称，我们有一组端口名称可帮助您选择 Arduino 板可以连接到的适当端口。

```java
private static final List<String> USUAL_PORTS = Arrays.asList(
  "/dev/tty.usbmodem", "/dev/tty.usbserial", //Mac OS X
  "/dev/usbdev", "/dev/ttyUSB", "/dev/ttyACM", "/dev/serial", //Linux
  "COM3", "COM4", "COM5", "COM6" //Windows
);

private final String ardPort;

public Serial() {
      ardPort = "";
}

public Serial(String port) {
      ardPort = port;
}
```

`connect()`方法会查找一个有效的串行端口，如果没有连接到 Arduino 板，则会设置一个。如果找到了有效的串行端口，就会打开它并添加一个监听器。这个监听器负责每次从 Arduino 输出返回一行时获取输入读数。`stringProperty`会被设置为这一行。我们使用`StringBuilder`来存储字符，并在找到`'\r\n'`时提取行内容。我们在这里使用了 lambda 表达式提供的集合批量操作，以便简单地查找端口列表并根据操作系统返回有效的端口。

通过`set()`方法将找到的每一行设置为`line`变量，以便通过注册的 change 监听器事件对`line`变量进行必要的更改，这通过`getLine()`方法暴露出来。代码如下：

```java
public boolean connect() {
  out.println("Serial port is openning now...");
  Arrays.asList(SerialPortList.getPortNames()).stream()
  .filter(name -> ((!ardPort.isEmpty() && name.equals(ardPort))|| (ardPort.isEmpty() && USUAL_PORTS.stream()
  .anyMatch(p -> name.startsWith(p)))))
  .findFirst()
  .ifPresent(name -> {
  try {
    serPort = new SerialPort(name);
      out.println("Connecting to " + serPort.getPortName());
      if (serPort.openPort()) {
        serPort.setParams(BAUDRATE_9600,
        DATABITS_8,
        STOPBITS_1,
        PARITY_NONE);
        serPort.setEventsMask(MASK_RXCHAR);
        serPort.addEventListener(event -> {
         if (event.isRXCHAR()) {
           try {
             sb.append(serPort.readString(event.getEventValue()));
             String ch = sb.toString();
             if (ch.endsWith("\r\n")) {
               line.set(ch.substring(0, ch.indexOf("\r\n")));
               sb = new StringBuilder();
             }
           } catch (SerialPortException e) {
             out.println("SerialEvent error:" + e.toString());
           }
         }
       });
     }
  } catch (SerialPortException ex) {
    out.println("ERROR: Port '" + name + "': " + ex.toString());
  }});
  return serPort != null;
}
```

最后，`disconnect()`方法负责从端口中移除监听器并关闭端口连接，以释放应用程序使用的资源。代码如下：

```java
public void disconnect() {
  if (serPort != null) {
    try {
      serPort.removeEventListener();
      if (serPort.isOpened()) {
        serPort.closePort();
      }
      } catch (SerialPortException ex) {
      out.println("ERROR closing port exception: " + ex.toString());
    }
    out.println("Disconnecting: comm port closed.");
  }
}
```

#### 应用程序逻辑和图表 API

我们应用程序的主要组件是`LineChart<Number, Number>`图表类 API，它将用于在 Y 轴上绘制您的血温水平，而在 X 轴上绘制时间。

自 JavaFX 2 以来，具有两个轴（如线条、条形和区域图表）的图表已经可用，并且它们是`Node`类的类型，这使得将它们添加到`Scene`中像其他节点一样变得容易。

在我们的应用程序中，我们将添加以下`createBloodChart()`方法，它负责创建和准备图表，并将其返回以添加到主应用程序场景中。

在应用程序的开始，我们有实例变量：一个`Serial`对象来处理 Arduino 的连接和读数；`listener`用于注册到`Serial`线对象；`BooleanProperty`用于跟踪连接状态；以及三个浮点属性，分别用于跟踪所有传感器数据的实际值、电压转换，最后是将电压转换为摄氏度温度。代码如下：

```java
private final Serial serial = new Serial();
private ChangeListener<String> listener;
private final BooleanProperty connection = new SimpleBooleanProperty(false);
private final FloatProperty bloodTemp = new SimpleFloatProperty(0);
private final FloatProperty volts = new SimpleFloatProperty(0);
private final FloatProperty sensorVal = new SimpleFloatProperty(0);
```

我们将添加`LineChart`来绘制温度传感器的温度水平，其中有一个`Series`，它接受一对数字来绘制在每个轴上；这些是`NumberAxis`实例。`XYChart.Data`被添加到系列数据中，作为每个点的*X*和*Y*值对来绘制读数。

每当`Series`的大小大于 40 个点时，为了内存效率，将删除前面的值。代码如下：

```java
private LineChart<Number, Number> createBloodChart() {
  final NumberAxis xAxis = new NumberAxis();
  xAxis.setLabel("Temperature Time");
  xAxis.setAutoRanging(true);
  xAxis.setForceZeroInRange(false);
  xAxis.setTickLabelFormatter(new StringConverter<Number>() {
    @Override
    public String toString(Number t) {
      return new SimpleDateFormat("HH:mm:ss").format(new Date(t.longValue()));
    }
    @Override
    public Number fromString(String string) {
      throw new UnsupportedOperationException("Not supported yet.");
    }
  });
  final NumberAxis yAxis = new NumberAxis("Temperature value", baselineTemp - 10, 40.0, 10);
  final LineChart<Number, Number> bc = new LineChart<>(xAxis, yAxis);
  bc.setTitle("Blood temperature vs time");
  bc.setLegendVisible(false);

  Series series = new Series();
  series.getData().add(new Data(currentTimeMillis(), baselineTemp));
  bc.getData().add(series);

  listener = (ov, t, t1) -> {
    runLater(() -> {
      String[] values = t1.split(",");
      if (values.length == 3) {
        sensorVal.set(parseFloat(values[0].split(":")[1].trim()));
        volts.set(parseFloat(values[1].split(":")[1].trim()));
        bloodTemp.set(parseFloat(values[2].split(":")[1].trim()));
        series.getData().add(new Data(currentTimeMillis(),
        bloodTemp.getValue()));

        if (series.getData().size() > 40) {
          series.getData().remove(0);
        }
      }

    });
  };
  serial.getLine().addListener(listener);

  return bc;
}
```

这里最有趣的部分是使用 lambda 表达式创建的 change 监听器`listener = (ov, t, t1) -> {}`，它将被注册到我们之前描述的`Serial`类`line`对象上。通过这样做，我们能够在检测到 Arduino 的任何输入时改变图表数据。

为此，我们将*X*坐标值设置为添加读数的毫秒时间（在图表上，它将被格式化为*HH:MM:SS*），*Y*坐标值是 Arduino 报告的温度级别的浮点测量值在字符串`t1`中。

### 注意

`Platform.runLater()`的主要用途是将填充系列数据的任务放在 JavaFX 线程中，但它也为`Scene`图形提供了所需的时间来渲染图表，如果值添加得太快，则会跳过值。

我添加了四个`Circle`类型的形状，它们将用于根据温度水平模拟电路 LED 的开和关，一旦通过 change 监听器对`FloatProperty` `bloodTemp`进行了任何更改。代码如下：

```java
Circle IndicatorLevel1 = new Circle(26.0, Color.BLACK);
bloodTemp.addListener((ol, ov, nv) -> {
  tempLbl.setText("Degrees C: ".concat(nv.toString()));

  // if the current temperature is lower than the baseline turn off all LEDs
  if (nv.floatValue() < baselineTemp +2) {
    IndictorLevel1.setFill(Paint.valueOf("Black"));
    IndictorLevel2.setFill(Paint.valueOf("Black"));
    IndictorLevel3.setFill(Paint.valueOf("Black"));
  } // if the temperature rises 1-3 degrees, turn an LED on
  else if (nv.floatValue() >= baselineTemp + 1 && nv.floatValue()< baselineTemp + 3) {
      IndictorLevel1.setFill(Paint.valueOf("RED"));
      IndictorLevel2.setFill(Paint.valueOf("Black"));
      IndictorLevel3.setFill(Paint.valueOf("Black"));
    } // if the temperature rises 3-5 degrees, turn a second LED on
    else if (nv.floatValue() >= baselineTemp + 4 && nv.floatValue() < baselineTemp + 6) {
      IndictorLevel1.setFill(Paint.valueOf("RED"));
      IndictorLevel2.setFill(Paint.valueOf("RED"));
      IndictorLevel3.setFill(Paint.valueOf("Black"));
    }//if the temperature rises more than 6 degrees, turn all LEDs on
    else if (nv.floatValue() >= baselineTemp + 6 {
    IndictorLevel1.setFill(Paint.valueOf("RED"));
    IndictorLevel2.setFill(Paint.valueOf("RED"));
    IndictorLevel3.setFill(Paint.valueOf("RED"));
  }
});
```

最后，主 UI 是由`loadMainUI()`方法创建的，它负责创建整个 UI 并将所有必需的变量绑定到 UI 控件，以便动态地与来自 Arduino 输入的事件交互。

一旦场景根（`BorderPane`）对象通过`loadMainUI()`准备和设置好，我们就创建场景并将其添加到舞台中，以便运行我们的应用程序如下：

```java
Scene scene = new Scene(loadMainUI(), 660, 510);
stage.setTitle("Blood Meter v1.0");
stage.setScene(scene);
stage.show();
//Connect to Arduino port and start listening
connectArduino();
```

最后，从`Application`类继承的重写的`stop()`方法将通过关闭`Serial`端口连接和从线对象中移除`listener`来处理任何资源释放。代码如下：

```java
@Override
public void stop() {
  System.out.println("Serial port is closing now...");
  serial.getLine().removeListener(listener);
  if (connection.get()) {
  serial.disconnect();
  connection.set(false);
}}
```

#### 运行应用程序

当一切就绪时——具有早期描述的类和添加到其中的`jSSC.jar`库的 JavaFX 项目——编译并运行您的应用程序，同时您的 Arduino 板连接到您的笔记本电脑/PC。如果一切正常，您将看到以下截图，显示了图表上的温度值与时间值，这将基于您的室温。

恭喜，您现在正在监视 Arduino 输入，并且可以通过`jSSC.jar`库与 Arduino 进行交互控制。

![运行应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_10.jpg)

初始血液计应用读数，温度为 24.71 度

尝试用手指拿住传感器并监视图表上的读数。在我的情况下，它达到了 30.57 度。还要注意工具栏上的指示器水平和板上的 LED。您应该看到类似于以下截图：

![运行应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_07_11.jpg)

血液计应用读数，温度为 30.57 度

# 总结

在本章中，您了解了通过结合 Arduino 和 JavaFX 可以实现什么。您首先学习了关于 Arduino 的知识，它的不同板，主要规格，购买地点和组件。然后，我们讨论了更多项目灵感的网站。

接下来，您学会了如何下载和设置 Arduino IDE 与 Arduino 通信。在了解了如何在 IDE 中加载示例之后，您有机会尝试自己动手，通过使用 Arduino Uno 和温度传感器构建一个简单的电路来创建一个草图，并在 IDE 串行监视器中读取温度水平。

然后，您学会了如何使用 Java Simple Serial Connector 库从计算机读取串行端口数据。

您学会了如何使用 JavaFX Line Chart API 来监视和显示 Arduino 读数。然后，您看到了一个示例，其中使用 Arduino 板从串行端口绘制了一个 JavaFX 图表，使用温度传感器来测量血液温度水平。

在下一章中，您将学习如何通过手势控制您的 JavaFX 应用程序与计算机进行无触控交互，而无需任何输入设备，如键盘、鼠标，甚至触控设备。


# 第八章：使用 JavaFX 进行交互式 Leap Motion 应用程序

现在我们来到了本书最激动人心的部分，我们将通过身体语言转化为命令来控制周围的物体和计算机，进入新的无触摸时代的计算机人交互。

每天我们都注意到输入界面的崛起，它们不再以鼠标为中心，而更倾向于无触摸输入。*手势*是人类如今可以自然地与机器交流的一种方式。

几十年来，动作控制一直在我们对未来的设想中占据着坚定的位置。我们看到了流行媒体中的超级英雄、疯狂科学家和太空牛仔只需挥动手就能控制数字体验。

![使用 JavaFX 进行交互式 Leap Motion 应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_1.jpg)

汤姆·克鲁斯通过手势进行计算

我们被这些强大、自然和直观的交互所吸引——想象一下如果我们能在自己的指尖上拥有这种力量会是什么样子。例如，*《星际迷航》的全息甲板*和*《未来报告》中的预犯预测计算机*。你还记得汤姆·克鲁斯在后者中是如何通过透明显示屏上的手势进行计算的吗？所有这些都散发着一种力量和掌控感，同时又具有矛盾的简单、轻松、直观和人性化的感觉。简单地说，这些体验都是神奇的。

市场上有几种设备实际上允许我们仅使用身体的一些部分与计算机进行交互：许多**Xbox**游戏，微软游戏机，使用**Kinect**控制器来识别用户的身体动作。肌电臂带可以检测你肌肉的运动并将其转化为手势，以便你可以与计算机交互。Leap Motion 控制器可以识别用户的手和手指，并将动作和手势转化为计算机上的操作。

在本章中，您将学习使用**Leap Motion**设备进行手势识别，这是一种令人敬畏的设备，可以以无触摸的方式开发增强的 JavaFX 应用程序。

以下是本章将讨论的一些主题：

+   介绍 Leap 控制器，它的工作原理以及如何获取

+   获取和安装 SDK，配置其驱动程序，并验证其是否正常工作

+   基于 Leap 的应用程序构建基础知识

+   开发令人惊叹的无触摸 JavaFX 应用程序

# Leap Motion 控制器

这是一个非常小的设备，高度为 13 毫米，宽度为 30 毫米，深度为 76 毫米，重量为 45 克（*最终尺寸：0.5 英寸 x 1.2 英寸 x 3 英寸*）。只需将 Leap Motion 软件运行在您的计算机上，将控制器插入 Mac 或 PC 上的 USB 接口，您就可以开始使用了（无需外部电源）。

它可以捕捉你手和手指的个别动作，几乎实时（200-300 fps），并将手势转化为计算机上运行的应用程序的不同操作。这款 79.99 美元的设备于 2013 年推出，称为 Leap Motion 控制器。

![Leap Motion 控制器](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_2.jpg)

Leap Motion 与人手的大小比较

从开发者的角度来看，这个设备允许设计应用程序，可以通过用户的*手*和*手指*的手势和动作来控制，就像*未来报告*中一样！

它能感知你自然的手部动作，并让你以全新的方式使用计算机——指向、挥动、伸手、抓取或拿起东西并移动。你可以做一些你从未梦想过的事情。

检查一下你的手；一只手有 29 根骨头，29 个关节，123 条韧带，48 条神经和 30 条动脉。这是复杂而复杂的。控制器已经非常接近完全弄清楚这一切。

实际上，当你考虑它时，Leap Motion 的魔力在于软件，但公司也在努力开发硬件来提供他们的技术。自 2011 年开始开发以来，它已经有了很大的进步，如下图所示：

![Leap Motion 控制器](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_3.jpg)

Leap Motion 控制器的演变

## 它是如何工作的

Leap Motion 的技术依赖于特殊的接收器硬件和定制软件，可以跟踪到 1/100 毫米的运动，没有可见的延迟时间。Leap Motion 控制器具有*150 度*的视野，并以 290fps 跟踪单独的手部和所有 10 个手指。

该设备的主要硬件由三个红外 LED 和两个单色红外（IR）摄像头组成。LED 产生红外光的 3D 点阵，摄像头以近乎 290fps 的速度扫描反射数据。在 50 厘米半径内的所有内容都将被扫描和处理，分辨率为 0.01 毫米。设备的主要组件如下图所示：

![它是如何工作的](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_4.jpg)

Leap Motion 控制器硬件层和内部组件

这是计算机交互的未来，Leap Motion 的非常快速和准确的自然用户界面以非常精确的方式将所有运动数据发送到计算机。数据将通过 Leap Motion 专有软件检测算法在主机计算机上进行分析，并且任何启用 Leap 的应用程序都可以直接进行接口连接，而无需使用任何其他物理输入设备。

### 坐标系统

在应用程序中使用 Leap Motion 控制器时，将从控制器接收的坐标值映射到适当的 JavaFX 坐标系统是一项基本任务。

从前面的讨论中，您可以观察到该设备可以在超宽的 150 度视野和深度的 z 轴内检测手部、手指和反射工具。这意味着您可以像在现实世界中一样在 3D 中移动您的手。

设备坐标系统使用右手笛卡尔坐标系，原点位于设备中心。如下图所示：

![坐标系统](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_6.jpg)

以设备为中心的坐标系统

每次设备扫描和分析您的手部运动数据时，都会生成一个包含所有已处理和跟踪数据的列表的 Frame 对象（手部、手指和工具），包括在帧中找到的一组运动手势（*滑动、点击或圈*）。

正如您可能已经注意到的，y 轴的正方向与大多数计算机图形系统（包括 JavaFX）中的向下方向相反。

然而，数据是指设备位置而不是屏幕，这与我们习惯于鼠标和触摸事件的方式发生了根本性的变化。

幸运的是，API 提供了几种有用的方法，可以随时找到我们的手和手指指向的位置。

## 获取设备

由于我们受到了这项令人惊叹的技术的启发，我们需要参与并开始使用该设备开发一些东西。因此，我们首先需要获得一个。

该设备可以从亚马逊、百思买等许多供应商处购买。但是，您也可以从 Leap Motion 商店([`store-world.leapmotion.com`](http://store-world.leapmotion.com))购买。

我在 2014 年底购买了我的设备，现在可能可以在一些商店找到特别折扣。

### 包内容

当您购买 Leap Motion 套装时，至少应包含以下图像中显示的物品：

![包内容](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_7.jpg)

Leap Motion 包内容

在撰写本文时，该套装包括：

+   Leap Motion 控制器

+   两根定制长度的 USB 2.0 电缆

+   欢迎卡

+   重要信息指南

## 使用 Leap SDK 入门

现在我们已经有了硬件，我们需要安装软件并开始开发。这是一项非常简单的任务；只需将鼠标指向您喜欢的浏览器的地址栏，输入 URL [`developer.leapmotion.com/downloads`](https://developer.leapmotion.com/downloads)，然后点击*Enter*键。

在撰写本文时，最新版本是 SDK 2.2.6.29154。单击您的操作系统图标以开始下载支持的版本。或者，只需单击带有标签**Download SDK 2.2.6.29154 for OSX**（适用于 Mac OS X）的绿色按钮。这将检测您的 PC /笔记本电脑操作系统，并允许您下载适合您操作系统的 SDK。

### 安装控制器驱动程序和软件

安装过程和准备好与设备交互需要一些简单的步骤。下载`zip`内容后，提取它，安装软件安装程序，一切都应该就位：

1.  下载，提取并运行软件安装程序。

1.  安装后，连接您的 Leap Motion 控制器并打开可视化器，如下面的屏幕截图所示：![安装控制器驱动程序和软件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_8.jpg)

运行可视化器

1.  SDK 包括`LeapJava.jar`库和一堆用于控制器集成的本机库。在您的系统上集成`LeapJava.jar`的一种简单方法是将 JAR 添加到 Linux 或 Windows 的`<JAVA_HOME>/jre/lib/ext`（或 Mac 上的`/Library/Java/Extensions`）。

1.  将本机库（Windows 的`LeapJava.dll`，`Leap.dll`和`Leapd.dll`；Mac 的`libLeapJava.dylib`和`libLeap.dylib`；Linux 的`libLeapJava.so`和`libLeap.so`）复制到`<JAVA_HOME>/jre/bin`文件夹中。

1.  或者，您可以将 JAR 作为依赖项添加到每个项目中，并将本机库作为 VM 参数`-Djava.library.path=<native library path>`加载。

### 注意

SDK 还包括许多基于支持语言的示例，包括`HelloWorld.java`示例，这是一个非常好的起点，可以帮助您了解如何将控制器与 Java 应用程序集成。

#### 验证是否有效

如果一切正常，一个小的 Leap Motion 图标应该出现在任务栏通知区域（Windows）或菜单栏（Mac）上，并且应该是绿色的，就像前面的屏幕截图所示。设备上的 LED 指示灯应该亮起绿色，并且*面向您以正确定位设备*。

如果您能够与可视化器交互并看到手指和手的可视化，就像下面的屏幕截图所示，那么现在是开始开发的时候了。

![验证是否有效](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_9.jpg)

Leap Motion 诊断可视化器应用程序

## 支持的语言

在深入研究我们的应用程序之前，我想简单提一下，Leap Motion SDK 支持许多语言，包括 Java 和其他语言，如 JavaScript 用于 Web，C＃，C ++，Python，Unity，Objective-C 和虚幻游戏引擎。

# Leap JavaFX 应用程序

像您一样，我迫不及待地想要开始开发过程，现在您将学习如何与连接到 Leap motion 设备的 JavaFX 8 基于 3D 的应用程序进行无触摸交互。

鉴于本书迄今为止尚未涵盖 3D API，这是一个很好的机会，简要描述 3D API 并将 Leap Motion v2 骨骼建模（3D 手）与一些 3D 交互带入我们的 JavaFX 应用程序。

Leap Motion API v2.0 引入了一个新的骨骼跟踪模型，提供有关手和手指的额外信息，预测不清晰可见的手指和手的位置，并改进整体跟踪数据。有关 API 的更多信息，请访问[`developer.leapmotion.com/documentation/java/devguide/Intro_Skeleton_API.html?proglang=java`](https://developer.leapmotion.com/documentation/java/devguide/Intro_Skeleton_API.html?proglang=java)。

我们将展示如何将 Leap Motion v2 的新骨骼模型轻松集成到 JavaFX 3D 场景中。我们将使用 JavaFX 提供的预定义 3D 形状 API，快速创建 3D 对象。这些形状包括盒子、圆柱体和球体，我们将在我们的应用程序中使用它们。

## 一览 JavaFX 3D API

3D 意味着*三维*或者拥有*宽度*、*高度*和*深度*（或*长度*）的东西。我们的物理环境是三维的，我们每天都在三维空间中移动。

JavaFX 3D 图形库包括 Shape3D API，JavaFX 中有两种类型的 3D 形状：

+   **预定义的形状**：这些形状是提供的，以便让你更快地创建 3D 对象。这些形状包括盒子、圆柱体和球体。

+   **用户定义的形状**：JavaFX Mesh 类层次结构包含`TriangleMesh`子类。三角网格是 3D 布局中最常见的网格类型。

在我们的应用程序中，我们将使用预定义的形状。有关 JavaFX 3D API 和示例的更多信息，请访问[`docs.oracle.com/javase/8/javafx/graphics-tutorial/javafx-3d-graphics.htm`](http://docs.oracle.com/javase/8/javafx/graphics-tutorial/javafx-3d-graphics.htm)。

## 更多学习资源

在 SDK 中捆绑的`HelloWorld.java`示例是一个丰富的资源，它将帮助你在 Leap Motion 控制器和普通 Java 应用程序之间的开发和集成过程中。

另一个讨论与 Java 集成的资源是 Leap Motion 文档中的*Getting Started with Java Development*部分，网址为[`developer.leapmotion.com/documentation/java/devguide/Leap_Guides.html`](https://developer.leapmotion.com/documentation/java/devguide/Leap_Guides.html)。

## 基本应用程序结构

在查看了`HelloWorld.java`示例和文档示例之后，你会注意到以下几点：

+   我们需要一个`Controller`对象，允许 Leap 设备和应用程序之间的连接。

+   我们需要一个`Listener`子类来处理来自控制器的事件。

+   手势跟踪在`onConnect()`方法中启用。

+   这个类中的主要方法是`onFrame()`，这是一个`callback`方法，当一个新的带有运动跟踪数据的`Frame`对象可用时被调用。这个对象包含手、手指或工具的列表，以及它们的位置、方向和运动速度的几个向量。

+   如果启用了手势，我们还将得到一个基于最后几帧分析的手势列表。此外，你将知道手势的状态，无论它是刚开始、正在进行中还是已经结束。

### JavaFX 8 3D 应用程序

我们将讨论的应用程序是一个复杂的 JavaFX 8 3D 应用程序，它将帮助你了解基于 Leap 的应用程序开发结构，与设备交互以识别*手部位置*，并与*手势*交互以在 3D 环境中建模我们的手。

你可以在后面的示例部分找到更多资源，包括开发基于 Leap 的 JavaFX 应用程序的更高级概念。

在这个应用程序中，我们将检测骨骼、手臂和关节（位置和方向），以圆柱体和球体的形式在我们的 JavaFX 应用程序`SubScene`中建模我们的手。然后，我们将检测它们的位置，以在 Leap Motion 设备上建模我们真实的手部运动。

我们还将添加原始的`image`，这样你就可以在应用程序的背景中看到模型和你的真实手。

该应用程序由三个类组成：

+   `LeapListener.java`：这个类是监听器，它与 Leap Motion 控制器线程交互，将所有分析的数据（手臂、骨骼、手指和关节）传输到 JavaFX 应用程序中。

+   `LeapJavaFX.java`：这个类是一个 JavaFX 应用程序线程，它将与`LeapListener.java`交互，以便在每一帧中创建 3D 形状，而不需要跟踪以前的形状。由于 Observable JavaFX bean 属性的强大功能，它允许从 Leap 线程传输的数据被渲染到 JavaFX 线程中。

+   `Pair.java`：这是一个小的便利类，用于存储每个关节中链接的两根骨头。

所以，让我们开始看看我们如何做到这一点。

### 提示

您必须通过在“跃动”控制面板中勾选“**允许图像**”选项并确保在“**跟踪**”选项卡下禁用“**鲁棒模式**”选项来启用 Leap Motion 控制面板上的图像。

### 工作原理

首先，我们将解释我们的应用程序的主要桥梁，即 Leap 事件监听器`LeapListener.java`。

开发 JavaFX 应用程序时的主要问题是如何将 JavaFX 线程与其他非 JavaFX 线程混合，而在我们的情况下是 Leap Motion 事件`Listener`子类，它以非常高的速率处理事件。

为了将这些事件传递到 JavaFX 线程，我们将在`LeapListener.java`类中使用`BooleanProperty`对象。由于我们只会监听`doneList`对象的更改，因此我们不需要列表也是可观察的，因为它们将在任何更改时触发事件（添加一个骨骼）。

因此它们是普通列表，我们只使用一个布尔可观察属性，在创建每个 Leap`Frame`对象中的所有列表后将其设置为 true：

```java
private final BooleanProperty doneList= new
SimpleBooleanProperty(false);
private final List<Bone> bones=new ArrayList<>();
private final List<Arm> arms=new ArrayList<>();
private final List<Pair> joints=new ArrayList<>();
private final List<WritableImage> raw =new ArrayList<>();
```

要获取原始图像，我们必须在`onInit()`中设置此策略，并且出于隐私原因，用户还必须在 Leap Motion 控制面板中启用该功能，以便任何应用程序都可以获取原始摄像头图像。

```java
@Override
public void onInit(Controller controller){
 controller.setPolicy(Controller.PolicyFlag.POLICY_IMAGES);
}
```

（*如您所知，如果要处理手势，这是您启用此功能的地方，因此也许您可以将它们保持注释状态。*）

让我们继续创建 Frame 方法：

```java
@Override
public void onFrame(Controller controller) {
  Frame frame = controller.frame();
  doneList.set(false);
  doneList.set(!bones.isEmpty() || !arms.isEmpty());
}
public BooleanProperty doneListProperty() {
  return doneList;
}
```

对于每一帧，重置`doneList`，处理数据，最后如果我们有骨骼或手臂，则将其设置为`true`（如果没有手放在 Leap 上，帧仍在处理中）。将属性公开以便在 JavaFX 应用程序中进行监听。

现在处理帧对象数据。首先是图像（这可以在最后完成）。在每一帧上清除列表，然后检索图像（从左右摄像头）。如果您想了解其工作原理，Leap 文档非常有帮助。访问[`developer.leapmotion.com/documentation/java/devguide/Leap_Images.html`](https://developer.leapmotion.com/documentation/java/devguide/Leap_Images.html)。

实际上，这段代码是第一个示例的一部分，添加了`PixelWriter`以生成 JavaFX 图像。由于 Leap 提供了明亮的像素，我对它们进行了否定处理*(1- (r|g|b))*以获得负图像，在手部更加清晰可见。此外，我将图像从左到右翻转，如下所示：

```java
(newPixels[i*width+(width-j-1)]).raw.clear();
ImageList images = frame.images();
for(Image image : images){
  int width = (int)image.width();
  int height = (int)image.height();
  int[] newPixels = new int[width * height];
  WritablePixelFormat<IntBuffer> pixelFormat = PixelFormat.getIntArgbPreInstance();
  WritableImage wi=new WritableImage(width, height);
  PixelWriter pw = wi.getPixelWriter();
  //Get byte array containing the image data from Image object
  byte[] imageData = image.data();

  //Copy image data into display object
  for(int i = 0; i < height; i++){
  for(int j = 0; j < width; j++){
    //convert to unsigned and shift into place
    int r = (imageData[i*width+j] & 0xFF) << 16;
    int g = (imageData[i*width+j] & 0xFF) << 8;
    int b = imageData[i*width+j] & 0xFF;
    // reverse image
    newPixels[i*width+(width-j-1)] = 1- (r | g | b);
  }
  }
  pw.setPixels(0, 0, width, height, pixelFormat, newPixels, 0,width);
  raw.add(wi);
}
```

然后清除骨骼、手臂和关节列表，如下所示的代码：

```java
bones.clear();
arms.clear();
joints.clear();
if (!frame.hands().isEmpty()) {
Screen screen = controller.locatedScreens().get(0);
if (screen != null && screen.isValid()){
```

获取骨骼列表；对于找到的每个手指，迭代该手指的骨骼类型（最多 5 个），以避免戒指和中指的掌骨。代码如下：

```java
for(Finger finger : frame.fingers()){
  if(finger.isValid()){
  for(Bone.Type b : Bone.Type.values()) {
    if((!finger.type().equals(Finger.Type.TYPE_RING) &&!finger.type().equals(Finger.Type.TYPE_MIDDLE)) ||!b.equals(Bone.Type.TYPE_METACARPAL)){
          bones.add(finger.bone(b));
      }
    }
  }
}
```

现在我们将遍历手列表以获取每只手臂，并将其添加到手臂列表中，如下所示：

```java
for(Hand h: frame.hands()){
  if(h.isValid()){
  // arm
  arms.add(h.arm());
```

现在获取手指关节。详细解释如何获取每个关节有点复杂。基本上，我找到每只手的手指，识别除拇指以外的其他四只手指。代码如下：

```java
FingerList fingers = h.fingers();
Finger index=null, middle=null, ring=null, pinky=null;
for(Finger f: fingers){
  if(f.isFinger() && f.isValid()){
    switch(f.type()){
    case TYPE_INDEX: index=f; break;
    case TYPE_MIDDLE: middle=f; break;
    case TYPE_RING: ring=f; break;
    case TYPE_PINKY: pinky=f; break;
    }
  }
}
```

一旦我识别出手指，我就定义了它们之间的每对关节（前三个关节）和手腕的关节（最后一个）。代码如下：

```java
// joints
if(index!=null && middle!=null){
  Pair p=new Pair(index.bone(Bone.Type.TYPE_METACARPAL).nextJoint(),middle.bone(Bone.Type.TYPE_METACARPAL).nextJoint());
  joints.add(p);
  }
  if(middle!=null && ring!=null){
    Pair p=new Pair(middle.bone(Bone.Type.TYPE_METACARPAL).nextJoint(),
    ring.bone(Bone.Type.TYPE_METACARPAL).nextJoint());
    joints.add(p);
  }
  if(ring!=null && pinky!=null){
    Pair p=new Pair(ring.bone(Bone.Type.TYPE_METACARPAL).nextJoint(),
    pinky.bone(Bone.Type.TYPE_METACARPAL).nextJoint());
    joints.add(p);
  }
  if(index!=null && pinky!=null){
    Pair p=new Pair(index.bone(Bone.Type.TYPE_METACARPAL).prevJoint(),pinky.bone(Bone.Type.TYPE_METACARPAL).prevJoint());
    joints.add(p);
  }
```

最后，上述代码返回骨骼集合的新副本，以避免在迭代此列表时出现并发异常。请注意，Leap 的帧速率非常高。在一台性能强大的计算机上，它几乎是 5-10 毫秒。代码如下：

```java
public List<Bone> getBones(){
 return bones.stream().collect(Collectors.toList());
}
```

这比 JavaFX 脉冲更快（60 fps，或大约 16 毫秒），因此在渲染骨骼时可以更改列表。通过这种*clone*方法，我们避免了任何并发问题。

LeapJavaFX 应用程序的 Listener 方法如下：

```java
Override
  public void start(Stage primaryStage) {
    listener = new LeapListener();
    controller = new Controller();
    controller.addListener(listener);
```

初始化 Leap 监听器类和控制器，然后添加监听器：

```java
final PerspectiveCamera camera = new PerspectiveCamera();
camera.setFieldOfView(60);
camera.getTransforms().addAll(new Translate(-320,-480,-100));
final PointLight pointLight = new PointLight(Color.ANTIQUEWHITE);
pointLight.setTranslateZ(-500);
root.getChildren().addAll(pointLight);
```

为 3D`subScene`创建一个透视摄像机，将其平移到屏幕中间底部，并对用户进行翻译。还要添加一些点光源。代码如下：

```java
rawView=new ImageView();
rawView.setScaleY(2);
```

为 Leap 图像创建一个`ImageView`，尺寸为 640 x 240，鲁棒模式关闭（在 Leap 控制面板中取消选中该选项），因此我们在 Y 轴上进行缩放以获得更清晰的图像。代码如下：

```java
Group root3D=new Group();
root3D.getChildren().addAll(camera, root);
SubScene subScene = new SubScene(root3D, 640, 480, true,
SceneAntialiasing.BALANCED);
subScene.setCamera(camera);
StackPane pane=new StackPane(rawView,subScene);
Scene scene = new Scene(pane, 640, 480);
```

创建一个带有相机的组，并将光源作为`subScene`的根。请注意，启用了深度缓冲和抗锯齿以获得更好的渲染效果。相机也添加到了`subScene`。

主根将是一个`StackPane`：背面是`ImageView`，前面是透明的`SubScene`。代码如下：

```java
final PhongMaterial materialFinger = new PhongMaterial(Color.BURLYWOOD);
final PhongMaterial materialArm = new PhongMaterial(Color.CORNSILK);
```

为手指和手臂设置材料，使用漫射颜色：

```java
listener.doneListProperty().addListener((ov,b,b1)->{
  if(b1){
    ...
  }
});
```

我们监听`doneList`的变化。每当它为`true`（每帧之后！），我们处理 3D 手部渲染：

```java
List<Bone> bones=listener.getBones();
List<Arm> arms=listener.getArms();
List<Pair> joints=listener.getJoints();
List<WritableImage> images=listener.getRawImages();
```

首先，获取骨骼、手臂和关节集合的最新副本。然后，如果在 JavaFX 线程中有有效图像，我们将图像设置在`ImageView`上，并删除除光源之外的所有根节点（因此我们重新创建手部骨骼）：

```java
Platform.runLater(()->{
    if(images.size()>0){
    // left camera
    rawView.setImage(images.get(0));
  }
  if(root.getChildren().size()>1){
    // clean old bones
    root.getChildren().remove(1,root.getChildren().size()-1);
}
```

骨骼 迭代列表并将骨骼添加到场景中。如果集合发生变化，我们在其副本上进行迭代时不会出现并发异常。

```java
bones.stream().filter(bone -> bone.isValid() && bone.length()>0).forEach(bone -> {
```

现在我们为每根骨骼创建一个圆柱体。这涉及一些计算。如果你想深入了解，可以将每根骨骼视为一个带有位置和方向的向量。创建一个垂直圆柱体，其半径为骨骼宽度的一半，高度与长度相同。然后，分配材料。代码如下：

```java
final Vector p=bone.center();
// create bone as a vertical cylinder and locate it at its center position
Cylinder c=new Cylinder(bone.width()/2,bone.length());
c.setMaterial(materialFinger);
```

然后，我们用真实骨骼方向与垂直方向进行叉乘；这给出了旋转的垂直向量。（符号是由于坐标系的变化）。`ang`对象是这两个向量之间的角度。可以应用一个转换，将其旋转到`ang`围绕给定向量的中心。代码如下：

```java
// translate and rotate the cylinder towards its direction
final Vector v=bone.direction();
Vector cross = (new Vector(v.getX(),-v.getY(), v.getZ())).cross(new Vector(0,-1,0));
double ang=(new Vector(v.getX(),-v.getY(),-v.getZ())).angleTo(new Vector(0,-1,0));
c.getTransforms().addAll(new Translate(p.getX(),-p.getY(),-p.getZ()),new Rotate(-Math.toDegrees(ang), 0, 0, 0, new Point3D(cross.getX(),-cross.getY(),cross.getZ())));
  // add bone to scene
root.getChildren().add(c);
```

现在在每根骨骼的开头和结尾都有球体：

```java
// add sphere at the end of the bone
Sphere s=new Sphere(bone.width()/2f);
s.setMaterial(materialFinger);
s.getTransforms().addAll(new Translate(p.getX(),-p.getY()+bone.length()/2d,-p.getZ()),new Rotate(-Math.toDegrees(ang), 0, -bone.length()/2d, 0, new Point3D(cross.getX(),-cross.getY(),cross.getZ())));
  // add sphere to scene
  root.getChildren().add(s);
  // add sphere at the beginning of the bone
  Sphere s2=new Sphere(bone.width()/2f);
  s2.setMaterial(materialFinger);
  s2.getTransforms().addAll(new Translate(p.getX(),-p.getY()-bone.length()/2d,-p.getZ()),new Rotate(Math.toDegrees(ang), 0, bone.length()/2d, 0, new Point3D(cross.getX(),-cross.getY(),cross.getZ())));
  // add sphere to scene
  root.getChildren().add(s2);
});
```

现在对于关节；我们再次使用圆柱体。连接的两个元素之间的距离给出长度，我们获取位置和方向来生成和转换圆柱体。代码如下：

```java
joints.stream().forEach(joint->{
  double length=joint.getV0().distanceTo(joint.getV1());
  Cylinder c=new Cylinder(bones.get(0).width()/3,length);
  c.setMaterial(materialArm);
  final Vector p=joint.getCenter();
  final Vector v=joint.getDirection();
  Vector cross = (new Vector(v.getX(),-v.getY(), v.getZ())).cross(new Vector(0,-1,0));
  double ang = (new Vector(v.getX(),-v.getY(),-v.getZ())).angleTo(new Vector(0,-1,0));
  c.getTransforms().addAll(new Translate(p.getX(),-p.getY(),-p.getZ()), new Rotate(-Math.toDegrees(ang), 0, 0, 0, new Point3D(cross.getX(),-cross.getY(),cross.getZ())));
  // add joint to scene
  root.getChildren().add(c);
});
```

最后，我们从肘部到手腕的距离中获取长度。所有这些都在 API 中：[`developer.leapmotion.com/documentation/java/api/Leap.Arm.html`](https://developer.leapmotion.com/documentation/java/api/Leap.Arm.html)。代码如下：

```java
arms.stream().
filter(arm->arm.isValid()).
forEach(arm->{
  final Vector p=arm.center();
  // create arm as a cylinder and locate it at its center position
  Cylinder c=new Cylinder(arm.width()/2,arm.elbowPosition().
  minus(arm.wristPosition()).magnitude());
  c.setMaterial(materialArm);
  // rotate the cylinder towards its direction
  final Vector v=arm.direction();
  Vector cross = (new Vector(v.getX(),-v.getY(),-v.getZ())).cross(new Vector(0,-1,0));
  double ang=(new Vector(v.getX(),-v.getY(),-v.getZ())).
  angleTo(new Vector(0,-1,0));
  c.getTransforms().addAll(new Translate(p.getX(),-p.getY(),-p.getZ()),new Rotate(- Math.toDegrees(ang), 0, 0, 0, new Point3D(cross.getX(),- cross.getY(),cross.getZ())));
  // add arm to scene
  root.getChildren().add(c);
});
```

### 运行应用程序

恭喜！现在连接您的 Leap 控制器（leap 图标应该是绿色的）并运行您的应用程序。如果一切正常，您应该最初看到一个空的应用程序场景，如下截图所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_10.jpg)

Leap JavaFX 应用程序的初始运行

移动并挥动你的手，你的手的骨骼建模应该出现在你真实的手背景中，响应你的真实动作如下所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_11.jpg)

Leap JavaFX 应用程序与 Leap 控制器的交互

尝试不同的手臂或手部模式和位置；您应该在 JavaFX 应用程序场景中看到这一复制，如下截图所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_08_12.jpg)

Leap JavaFX 应用程序与 Leap 控制器的交互，具有不同的手部模式

# 更多示例

有关使用 JavaFX 与 Leap Motion 设备的更多示例，请参考在线资源，如[`www.parleys.com/share.html#play/525467d6e4b0a43ac12124ad`](http://www.parleys.com/share.html#play/525467d6e4b0a43ac12124ad)或[`jperedadnr.blogspot.com.es/2013/06/leap-motion-controller-and-javafx-new.html`](http://jperedadnr.blogspot.com.es/2013/06/leap-motion-controller-and-javafx-new.html)。有关与其他编程语言的交互，请访问[`developer.leapmotion.com/gallery`](https://developer.leapmotion.com/gallery)。

# 总结

在本章中，你了解了令人印象深刻的 Leap Motion 设备，以及使用它来增强 JavaFX 应用程序所产生的非常好的组合效果。

你开始学习关于设备及其工作原理。接下来，我们讨论了它的 Java SDK，并探讨了一个简单的应用程序，在这个应用程序中，你学会了如何在一个线程中监听和处理 Leap 设备的数据，同时在 JavaFX 线程中触发事件来处理场景图中的数据。

在下一章中，我将提供给真正的 JavaFX 专家们使用的高级工具和资源。
