# 安卓纸板 VR 项目（一）

> 原文：[`zh.annas-archive.org/md5/94E6723D45DBCC15CF10E16526443AE5`](https://zh.annas-archive.org/md5/94E6723D45DBCC15CF10E16526443AE5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

谷歌纸板是一种低成本、入门级的媒介，用于体验虚拟 3D 环境。它的应用与移动智能手机应用程序本身一样广泛和多样。本书为您提供了使用原生 Java SDK 为谷歌纸板实现各种有趣项目的机会。目的是教育您最佳实践和方法，以制作适用于设备及其预期用户的纸板兼容移动 VR 应用，并指导您制作高质量的内容。

# 本书涵盖的内容

第一章，“每个人的虚拟现实”，定义了谷歌纸板，探讨了它，并讨论了它的用途以及它如何适应虚拟现实设备的范围。

第二章，“骨架纸板项目”，审查了安卓纸板应用程序的结构，介绍了 Android Studio，并通过引入纸板 Java SDK 帮助您构建一个起始纸板项目。

第三章，“纸板盒”，讨论了如何从头开始构建一个基于谷歌的宝藏猎人示例的纸板安卓应用程序，其中包括 3D 立方体模型、变换、立体摄像机视图和头部旋转。本章还包括对 3D 几何、Open GL ES、着色器、矩阵数学和渲染管线的讨论。

第四章，“启动器大堂”，帮助您构建一个应用程序，用于在手机上启动其他纸板应用。这个项目不使用 3D 图形，而是在屏幕空间中模拟立体视图，并实现了凝视选择。

第五章，“RenderBox 引擎”，向您展示了如何创建一个小型图形引擎，用于通过将低级别的 OpenGL ES API 调用抽象为一套`Material`、`RenderObject`、`Component`和`Transform`类来构建新的纸板 VR 应用程序。该库将在后续项目中被使用和进一步开发。

第六章，“太阳系”，通过添加太阳光源、具有纹理映射材料和着色器的球形行星，以及它们在太阳系轨道上的动画和银河星空，构建了一个太阳系模拟科学项目。

第七章，“360 度画廊”，帮助您构建一个用于常规和 360 度照片的媒体查看器，并帮助您将手机相机文件夹中的照片加载到缩略图图像网格中，并使用凝视选择来选择要查看的照片。它还讨论了如何添加进程线程以改善用户体验，并支持 Android 意图以查看来自其他应用程序的图像。

第八章，“3D 模型查看器”，帮助您构建一个用于 OBJ 文件格式的 3D 模型的查看器，使用我们的 RenderBox 库进行渲染。它还向您展示了如何通过移动头部来交互控制模型的视图。

第九章，“音乐可视化器”，构建了一个基于手机当前音频播放器的波形和 FFT 数据进行动画的 VR 音乐可视化器。我们实现了一个通用架构，用于添加新的可视化，包括几何动画和动态纹理着色器。然后，我们添加了一个迷幻轨迹模式和多个并发可视化，随机过渡进出。

# 您需要什么来阅读本书

在整本书中，我们使用 Android Studio IDE 开发环境来编写和构建 Android 应用程序。您可以免费下载 Android Studio，如第二章，“骨架纸板项目”中所述。您需要一部安卓手机来运行和测试您的项目。强烈建议您拥有一个谷歌纸板查看器，以体验立体虚拟现实中的应用程序。

# 本书适合谁

本书适用于对学习和开发使用 Google Cardboard 原生 SDK 的 Google Cardboard 应用程序感兴趣的 Android 开发人员。我们假设读者对 Android 开发和 Java 语言有一定了解，但可能对 3D 图形、虚拟现实和 Google Cardboard 还不熟悉。初学者开发人员或不熟悉 Android SDK 的人可能会发现本书难以入门。那些没有 Android 背景的人可能更适合使用 Unity 等游戏引擎创建 Cardboard 应用程序。

# 惯例

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“编辑`MainActivity` Java 类，使其扩展`CardboardActivity`并实现`CardboardView.StereoRenderer`。”

代码块设置如下：

```kt
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        CardboardView cardboardView = (CardboardView) findViewById(R.id.cardboard_view);
        cardboardView.setRenderer(this);
        setCardboardView(cardboardView);
    }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```kt
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        CardboardView cardboardView = (CardboardView) findViewById(R.id.cardboard_view);
 cardboardView.setRenderer(this);
 setCardboardView(cardboardView);
    }
```

任何命令行输入或输出均按以下方式编写：

```kt
git clone https://github.com/googlesamples/cardboard-java.git

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，以这种方式出现在文本中：“在 Android Studio 中，选择**文件**|**新建**|**新建模块…**。选择**导入.JAR/.AAR 包**。”

### 注意

警告或重要提示以这样的框出现。

### 提示

技巧和窍门看起来像这样。



# 第一章：每个人的虚拟现实

欢迎来到令人兴奋的虚拟现实世界！我们相信，作为一名安卓开发者，您想要立即开始构建可以使用谷歌纸板查看的酷东西。然后您的用户只需将他们的智能手机放入观看器中，就可以进入您的虚拟创作。在本书的其余部分中，让我们在代码和技术方面深入讨论之前，让我们先来看看 VR、谷歌纸板及其安卓 SDK 的外部结构。在本章中，我们将讨论以下主题：

+   为什么叫纸板？

+   虚拟现实设备的范围

+   VR 的入口

+   低端 VR 的价值

+   卡片硬件

+   配置您的纸板观看器

+   为纸板开发应用程序

+   VR 最佳实践概述

# 为什么叫纸板？

一切始于 2014 年初，当时谷歌员工大卫·科兹和达米安·亨利在业余时间为安卓智能手机制作了一个简单而廉价的立体观看器。他们设计了一个可以用普通纸板制作的设备，再加上一些适合眼睛的镜片，以及一个触发按钮“点击”的机制。这个观看器真的是用纸板做的。他们编写了一个软件，可以呈现一个分屏的 3D 场景：一个视图给左眼，另一个视图，带有偏移，给右眼。透过这个设备，你会真正感受到对计算机生成场景的 3D 沉浸。它奏效了！该项目随后被提议并批准为“20%项目”（员工可以每周工作一天进行创新），得到资金支持，并有其他员工加入。

### 注意

关于纸板诞生背后的故事的两个“权威”来源如下：

+   [`www.wired.com/2015/06/inside-story-googles-unlikely-leap-cardboard-vr/`](http://www.wired.com/2015/06/inside-story-googles-unlikely-leap-cardboard-vr/)

+   [`en.wikipedia.org/wiki/Google_Cardboard`](https://en.wikipedia.org/wiki/Google_Cardboard)

事实上，纸板效果非常好，以至于谷歌决定继续前进，将该项目提升到下一个级别，并在几个月后在 2014 年的谷歌 I/O 上向公众发布。下图显示了一个典型的未组装的谷歌纸板套件：

![为什么叫纸板？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_01.jpg)

自问世以来，谷歌纸板一直对黑客、业余爱好者和专业开发者都是开放的。谷歌开源了观看器设计，任何人都可以下载图纸并制作自己的观看器，可以用披萨盒或者任何他们周围有的东西。甚至可以开展业务，直接向消费者出售预制套件。下图显示了一个已组装的纸板观看器：

![为什么叫纸板？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_02.jpg)

纸板项目还包括一个**软件开发工具包**（**SDK**），可以轻松构建 VR 应用程序。谷歌已经不断改进了软件，包括一个本地的 Java SDK 以及一个用于 Unity 3D 游戏引擎的插件（[`unity3d.com/`](https://unity3d.com/)）。

自纸板发布以来，已经开发了大量的应用程序，并在谷歌 Play 商店上提供。在 2015 年的谷歌 I/O 上，2.0 版本推出了升级设计、改进软件和对苹果 iOS 的支持。

谷歌纸板在市场上的形象迅速从一个几乎可笑的玩具发展成为某些类型的 3D 内容和 VR 体验的严肃新媒体设备。谷歌自己的纸板演示应用程序已经从谷歌 Play 商店下载了数百万次。《纽约时报》在 2015 年 11 月 8 日的星期日发行的一期中分发了大约一百万个纸板观看器。

纸板适用于查看 360 度照片和玩低保真度的 3D VR 游戏。它几乎可以被任何人普遍接触，因为它可以在任何安卓或 iOS 智能手机上运行。

开发者现在正在将 3D VR 内容直接整合到 Android 应用中。Google Cardboard 是一种体验虚拟现实的方式，它将会长期存在。

# VR 设备的谱系

和大多数技术一样，虚拟现实产品也有一个从最简单和最便宜到非常先进的产品的谱系。

## 老式立体镜

Cardboard 处于 VR 设备谱系的低端。如果考虑你小时候玩过的 ViewMaster，甚至是 1876 年的历史性立体镜观看器（B.W. Kilborn & Co, New Hampshire 州的 Littleton），你甚至可以再低一些，如下图所示：

![老式立体镜](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_03.jpg)

在这些老式的观看器中，一对照片为左右眼显示两个分离的视图，略微偏移以创建视差。这会让大脑误以为它正在看到一个真正的三维视图。设备中包含了每只眼睛的独立镜片，让你可以轻松地聚焦在照片上。

同样，渲染这些并排的立体视图是 Google Cardboard 应用的首要任务。（借助他们的传统，Mattel 最近发布了与 Cardboard 兼容的 ViewMaster 品牌 VR 观看器，使用智能手机，可以在[`www.view-master.com/`](http://www.view-master.com/)找到）。

## Cardboard 是移动 VR

Cardboard 相对于立体观看器的明显优势，就像数字照片相对于传统照片的优势一样。数字媒体可以在我们的智能手机内动态存储、加载和操作。这本身就是一个强大的飞跃。

除此之外，Cardboard 还利用手机中的运动传感器，当你左右或上下转头时，图像会相应调整，有效地消除了图像的传统边框。构图是传统视觉媒体的一个非常重要的部分，比如绘画、摄影和电影摄影。几个世纪以来，艺术家和导演们一直在使用这个矩形框架建立视觉语言。

然而，在 VR 中并非如此。当你在 VR 中移动头部时，你的视线方向会改变，场景会随之更新，就好像摄像机随着你的旋转而旋转，提供了完全沉浸式的视图。你可以水平旋转 360 度，左右观看，垂直旋转 180 度，上下观看。换句话说，你可以随意观看任何地方。在 VR 中没有框架！（尽管你的外围视野可能会受到光学和显示器尺寸的限制，这些决定了设备的视野范围）。因此，设计考虑可能更类似于雕塑、环形剧场，甚至是建筑设计。我们需要考虑整个空间，让游客沉浸其中。

Google Cardboard 设备只是一个用来放置智能手机的外壳。它使用智能手机的技术，包括以下内容：

+   显示

+   CPU（主处理器）

+   GPU（图形处理器）

+   IMU（运动传感器）

+   磁力计和/或触摸屏（触发传感器）

我们稍后会详细讨论这一切是如何运作的。

使用移动智能手机进行 VR 意味着有很多好处，比如易于使用，但也有一些烦人的限制，比如有限的电池寿命，较慢的图形处理，以及较低的精度/更高的延迟运动传感器。

三星 Gear VR 是一款比简单的 Cardboard 观看器更智能的移动 VR 头盔。基于 Android，但不兼容 Cardboard 应用（只能与三星手机的特定型号配合使用），它有一个内置的更高精度 IMU（运动传感器），增加了头部运动跟踪的准确性，并有助于减少更新显示时的运动到像素延迟。它还经过人体工程学设计，可以更长时间地使用，并配备了一个带子。

## 桌面 VR 及更多

在消费者虚拟现实设备的高端是 Oculus Rift、HTC Vive 和索尼 PlayStation VR 等产品。这些产品之所以能做到 Cardboard 无法做到的事情，是因为它们不受智能手机能力的限制。有时被称为“桌面 VR”，这些设备是连接到外部 PC 或游戏机的**头戴式显示器**（**HMD**）。

在桌面 VR 上，桌面强大的 CPU 和 GPU 进行实际计算和图形渲染，并将结果发送到 HMD。此外，HMD 具有更高质量的运动传感器和其他功能，有助于在更新显示时减少延迟，比如每秒 90 帧（FPS）。我们将在本书中了解到，减少延迟和保持高 FPS 对所有 VR 开发以及 Cardboard 上的用户舒适度都是重要的关注点。

桌面 VR 设备还增加了*位置跟踪*。Cardboard 设备可以检测 X、Y 和 Z 轴上的旋转运动，但不幸的是它无法检测位置运动（例如沿着这些轴的滑动）。Rift、Vive 和 PSVR 可以。例如，Rift 使用外部摄像头通过 HMD 上的红外灯来跟踪位置（*外部跟踪*）。另一方面，Vive 使用 HMD 上的传感器来跟踪房间中放置的一对激光发射器的位置（*内部跟踪*）。Vive 还使用这个系统来跟踪一对手柄的位置和旋转。这两种策略都能实现类似的结果。用户在被跟踪的空间内有更大的自由度，同时在虚拟空间内移动。Cardboard 无法做到这一点。

请注意，创新不断被引入。很可能，在某个时候，Cardboard 将包含位置跟踪功能。例如，我们知道谷歌的 Project Tango 使用传感器、陀螺仪和对物理空间的认知来实现视觉惯性测距（VIO），从而为移动应用提供运动和位置跟踪。参考[`developers.google.com/project-tango/overview/concepts`](https://developers.google.com/project-tango/overview/concepts)。移动设备公司，如 LG 和三星，正在努力研究如何实现移动位置跟踪，但（在撰写本文时）尚不存在通用的、低延迟的解决方案。谷歌的 Project Tango 显示出一些希望，但尚不能实现流畅、舒适的 VR 体验所需的像素延迟。延迟过大会让你感到不适！

在非常高端的是成千上万甚至数百万美元的工业和军用级系统，这些不是消费者设备，我相信它们可以做一些非常棒的事情。我可以告诉你更多，但那样我就得杀了你。这些解决方案自上世纪 80 年代以来就已经存在。VR 并不是新的——消费者 VR 是新的。

VR 设备的光谱在下图中有所体现：

![桌面 VR 及更高级别](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_04.jpg)

当我们为 Cardboard 开发时，重要的是要记住它相对于其他 VR 设备能做什么，不能做什么。Cardboard 可以显示立体视图。Cardboard 可以跟踪头部的旋转运动。它不能进行位置跟踪。它在图形处理能力、内存和电池寿命方面存在限制。

# VR 的入口

在它上市的短时间内，这一代消费者虚拟现实已经表现出自己是瞬间引人入胜、沉浸式、娱乐性强，对于试用过的几乎每个人来说都是“改变游戏规则”的产品。谷歌 Cardboard 特别容易获得，使用门槛很低。你只需要一部智能手机，一个低成本的 Cardboard 观看器（低至 5 美元），以及从 Google Play（或者 iOS 的 Apple App Store）下载的免费应用程序。

谷歌 Cardboard 被称为 VR 的**通道**，也许是指大麻作为更危险的非法药物滥用的“通道药物”？我们可以玩一下这个类比，尽管有些颓废。也许 Cardboard 会让你略尝 VR 的潜力。你会想要更多。然后再多一些。这将帮助你满足对更好、更快、更强烈和更沉浸式虚拟体验的渴望，这些只能在更高端的 VR 设备中找到。也许在这一点上，也许就没有回头的余地了；你上瘾了！

然而，作为 Rift 用户，我仍然喜欢 Cardboard。它快速。它容易。它有趣。而且真的有效，只要我运行适合该设备的应用程序。

在假期拜访家人时，我在背包里带了一个 Cardboard 观看器。每个人都很喜欢。我的许多亲戚甚至都没有通过标准的谷歌 Cardboard 演示应用程序，尤其是它的 360 度照片查看器。那足够吸引人，让他们一段时间内感到愉快。其他人则玩了一两个游戏，或者更多。他们想继续玩并尝试新的体验。也许这只是新奇。或者，也许这是这种新媒体的本质。关键是，谷歌 Cardboard 提供了一种令人沉浸的体验，令人愉快，有用，而且非常容易获得。简而言之，它很棒。

然后，向他们展示 HTC Vive 或 Oculus Rift。天哪！那真的太棒了！好吧，对于这本书，我们不是来讨论更高端的 VR 设备，只是与 Cardboard 进行对比，并保持透视。

一旦你尝试了桌面 VR，再回到移动 VR 会很难吗？有些人这样说。但这几乎是愚蠢的。事实是它们确实是两种不同的东西。

正如前面讨论的，桌面 VR 配备了更高的处理能力和其他高保真功能，而移动 VR 受到智能手机的限制。如果开发人员试图直接将桌面 VR 应用程序移植到移动设备，你很可能会感到失望。

最好将每个视为一个独立的媒体。就像桌面应用程序或游戏机游戏不同于但类似于移动应用程序一样。设计标准可能是相似的但不同。技术是相似的但不同。用户期望是相似的但不同。移动 VR 可能类似于桌面 VR，但它是不同的。

### 注意

为了强调 Cardboard 与桌面 VR 设备的不同，值得指出谷歌已经将以下内容写入了他们的制造商规格和指南中：

“不要在您的观看器中包括头带。当用户用手将 Cardboard 贴在脸上时，他们的头部旋转速度受到躯干旋转速度的限制（比颈部旋转速度慢得多）。这减少了由渲染/IMU 延迟引起的“VR 晕动病”的机会，并增加了 VR 的沉浸感。”

这意味着 Cardboard 应用程序应该设计为更短、更简单、更固定的体验。在本书中，我们将阐明这些和其他提示和最佳实践，当你为移动 VR 媒体开发时。

现在让我们考虑 Cardboard 是通往 VR 的其他方式。

我们预测 Android 将继续成为未来虚拟现实的主要平台。越来越多的技术将被塞进智能手机。而这项技术将包括对 VR 有利的特性：

+   更快的处理器和移动 GPU

+   更高分辨率的屏幕

+   更高精度的运动传感器

+   优化的图形管线

+   更好的软件

+   更多的 VR 应用程序

移动 VR 不会让位给桌面 VR；甚至可能最终取代它。

此外，我们很快将看到专门的移动 VR 头显，内置智能手机的功能，而无需支付无线通信合同的费用。不需要使用自己的手机。不会再因为来电或通知而在虚拟现实中被打断。不再因为需要接听重要电话或者使用手机而节约电池寿命。所有这些专用的 VR 设备可能都是基于 Android 的。

# 低端 VR 的价值

与此同时，Android 和 Google Cardboard 已经出现在我们的手机上，放在我们的口袋里，我们的家里，办公室，甚至我们的学校里。

例如，Google Expeditions 是 Google 的 Cardboard 教育项目（[`www.google.com/edu/expeditions/`](https://www.google.com/edu/expeditions/)），它允许 K-12 学生进行虚拟实地考察，去“校车无法到达的地方”，就像他们所说的，“环游世界，登陆火星表面，潜入珊瑚礁，或者回到过去。”套件包括 Cardboard 观看器和每个班级学生的 Android 手机，以及老师的 Android 平板电脑。它们通过网络连接。老师可以引导学生进行虚拟实地考察，提供增强内容，并创造远远超出教科书或课堂视频的学习体验，如下图所示：

![低端 VR 的价值](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_05.jpg)

在另一个创意营销的例子中，2015 年夏天，Kellogg's 开始销售 Nutri-Grain 零食棒，包装盒可以变成 Google Cardboard 观看器。这与一个应用程序相连，显示各种极限运动 360 度视频（[`www.engadget.com/2015/09/09/cereal-box-vr-headset/`](http://www.engadget.com/2015/09/09/cereal-box-vr-headset/)），如下图所示：

![低端 VR 的价值](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_06.jpg)

整个互联网可以被视为一个全球发布和媒体分发网络。它是一个由超链接页面、文本、图像、音乐、视频、JSON 数据、网络服务等组成的网络。它也充斥着 360 度照片和视频。还有越来越多的三维内容和虚拟世界。你会考虑写一个今天不显示图像的 Android 应用吗？可能不会。你的应用程序很可能也需要支持声音文件、视频或其他媒体。所以请注意。支持 Cardboard 的三维内容正在迅速到来。你现在可能对阅读这本书感兴趣，因为 VR 看起来很有趣。但很快，这可能会成为你下一个应用程序的客户驱动需求。

一些流行的 Cardboard 应用类型的例子包括：

+   例如，Google 的 Cardboard 演示（[`play.google.com/store/apps/details?id=com.google.samples.apps.cardboarddemo`](https://play.google.com/store/apps/details?id=com.google.samples.apps.cardboarddemo)）和 Cardboard Camera（[`play.google.com/store/apps/details?id=com.google.vr.cyclops`](https://play.google.com/store/apps/details?id=com.google.vr.cyclops)）的 360 度照片查看

+   例如，Cardboard 剧院（[`play.google.com/store/apps/details?id=it.couchgames.apps.cardboardcinema`](https://play.google.com/store/apps/details?id=it.couchgames.apps.cardboardcinema)）的视频和电影观看

+   例如，VR 过山车和惊险游戏，如 VR 过山车（[`play.google.com/store/apps/details?id=com.frag.vrrollercoaster`](https://play.google.com/store/apps/details?id=com.frag.vrrollercoaster)）

+   例如，卡通式 3D 游戏，如 Lamber VR（[`play.google.com/store/apps/details?id=com.archiactinteractive.LfGC&hl=en_GB`](https://play.google.com/store/apps/details?id=com.archiactinteractive.LfGC&hl=en_GB)）

+   例如，第一人称射击游戏，如 Battle 360 VR（[`play.google.com/store/apps/details?id=com.oddknot.battle360vr`](https://play.google.com/store/apps/details?id=com.oddknot.battle360vr)）

+   **令人毛骨悚然的东西**，例如，Sisters（[`play.google.com/store/apps/details?id=com.otherworld.Sisters`](https://play.google.com/store/apps/details?id=com.otherworld.Sisters)）

+   **教育体验**，例如，太空巨人（[`play.google.com/store/apps/details?id=com.drashvr.titansofspacecb&hl=en_GB`](https://play.google.com/store/apps/details?id=com.drashvr.titansofspacecb&hl=en_GB)）

+   营销经验，例如，沃尔沃现实（[`play.google.com/store/apps/details?id=com.volvo.volvoreality`](https://play.google.com/store/apps/details?id=com.volvo.volvoreality)）

还有更多；成千上万。最受欢迎的应用已经有数十万次下载（Cardboard 演示应用本身已经有数百万次下载）。

本书中的项目是您今天可以自己构建的不同类型的 Cardboard 应用程序的示例。

# Cardware！

让我们来看看不同的 Cardboard 设备。种类繁多。

显然，原始的谷歌设计实际上是用硬纸板制成的。制造商也效仿，直接向消费者提供硬纸板 Cardboard 产品，如 Unofficial Cardboard，DODOCase 和 IAmCardboard 等品牌是最早的。

谷歌免费提供规格和原理图（参见[`www.google.com/get/cardboard/manufacturers/`](https://www.google.com/get/cardboard/manufacturers/)）。例如，2.0 版查看器外壳原理图如下所示：

![Cardware!](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_07.jpg)

基本的查看器设计包括一个外壳、两个镜片和一个输入机制。*与 Google Cardboard 兼容*认证计划表示特定的查看器产品符合谷歌的标准，并且与 Cardboard 应用程序配合良好。

查看器外壳可以由任何材料制成：硬纸板、塑料、泡沫、铝等。它应该轻便，并且能够很好地阻挡环境光。

镜片（I/O 2015 版）是 34 毫米直径的非球面单镜头，视场角为 80 度，还有其他指定参数。

输入触发器（“点击器”）可以是几种替代机制之一。最简单的是没有，用户必须直接用手指触摸智能手机屏幕来触发点击。这可能不太方便，因为手机放在查看器外壳内，但它可以工作。许多查看器只包括一个孔，可以伸进手指。另外，原始的 Cardboard 使用了一个小环状磁铁，固定在查看器外部，由嵌入式圆形磁铁固定在位。用户可以滑动环状磁铁，手机的磁力计会感应到磁场的变化，并被软件识别为“点击”。这种设计并不总是可靠，因为磁力计的位置在手机之间有所不同。此外，使用这种方法，更难以检测“按住”交互，这意味着在您的应用程序中只有一种类型的用户输入“事件”可供使用。

Cardboard 2.0 版引入了一个由导电“条”和粘贴在基于 Cardboard 的“锤子”上的“枕头”构成的按钮输入。当按钮被按下时，用户的体电荷被传递到智能手机屏幕上，就好像他直接用手指触摸屏幕一样。这个巧妙的解决方案避免了不可靠的磁力计解决方案，而是使用了手机的原生触摸屏输入，尽管是间接的。

值得一提的是，由于您的智能手机支持蓝牙，可以使用手持蓝牙控制器与您的 Cardboard 应用程序配对。这不是 Cardboard 规格的一部分，需要一些额外的配置：使用第三方输入处理程序或应用程序内置的控制器支持。下图显示了一个迷你蓝牙控制器：

![Cardware!](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_08.jpg)

Cardboard 观众不一定是用硬纸板制成的。塑料观众可能会相对昂贵。虽然它们比硬纸板更坚固，但它们基本上具有相同的设计（组装）。一些设备允许您调整镜片到屏幕的距离和/或您的眼睛之间的距离（IPD 或瞳距）。蔡司 VR One、Homido 和 Sunnypeak 设备是最早流行的设备之一。

一些制造商已经超越了 Cardboard 设计（打趣），创新并不一定符合 Google 的规格，但提供了超越 Cardboard 设计的功能。一个显著的例子是 Wearality 观众（[`www.wearality.com/`](http://www.wearality.com/)），它包括一个拥有专利的 150 度视场（FOV）双菲涅耳透镜。它非常便携，可以像一副太阳镜一样折叠起来。Wearality 观众的预发布版本如下图所示：

![Cardware!](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_09.jpg)

# 配置您的 Cardboard 观众

由于 Cardboard 设备种类繁多，镜片距离、视场、畸变等方面存在差异，Cardboard 应用必须配置为特定设备的属性。Google 也提供了解决方案。每个 Cardboard 观众都配有一个独特的 QR 码和/或 NFC 芯片，您可以扫描以配置该设备的软件。如果您有兴趣校准自己的设备或自定义参数，请查看[`www.google.com/get/cardboard/viewerprofilegenerator/`](https://www.google.com/get/cardboard/viewerprofilegenerator/)上的配置文件生成工具。

要将手机配置为特定的 Cardboard 观众，请打开标准的 Google Cardboard 应用，并选择屏幕底部中心部分显示的设置图标，如下图所示：

配置您的 Cardboard 观众

然后将相机对准您特定的 Cardboard 观众的 QR 码：

![配置您的 Cardboard 观众](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_11.jpg)

您的手机现在已配置为特定的 Cardboard 观众参数。

# 为 Cardboard 开发应用

在撰写本书时，Google 为 Cardboard 提供了两个 SDK：

+   Android 的 Cardboard SDK（[`developers.google.com/cardboard/android`](https://developers.google.com/cardboard/android)）

+   Unity 的 Cardboard SDK（[`developers.google.com/cardboard/unity`](https://developers.google.com/cardboard/unity)）

首先让我们考虑 Unity 选项。

## 使用 Unity

Unity（[`unity3d.com/`](http://unity3d.com/)）是一款流行的功能齐全的 3D 游戏引擎，支持在多种平台上构建游戏，从 PlayStation 和 XBox 到 Windows 和 Mac（还有 Linux！），再到 Android 和 iOS。

Unity 由许多独立的工具组成，集成到一个统一的可视化编辑器中。它包括用于图形、物理、脚本、网络、音频、动画、UI 等的工具。它包括先进的计算机图形渲染、着色、纹理、粒子和照明，提供各种优化性能和调整图形质量的选项，适用于 2D 和 3D。如果这还不够，Unity 还拥有一个庞大的资产商店，充斥着由其庞大的开发者社区创建的模型、脚本、工具和其他资产。

Cardboard SDK for Unity 提供了一个插件包，您可以将其导入 Unity 编辑器，其中包含预制对象、C#脚本和其他资产。该包为您提供了在虚拟 3D 场景中添加立体摄像机并将项目构建为 Android（和 iOS）上的 Cardboard 应用所需的内容。Unity 计划将 Cardboard SDK 直接集成到引擎中，这意味着通过在构建设置中勾选一个框即可添加对 Cardboard 的支持。

### 注意

如果您有兴趣了解如何使用 Unity 构建 Cardboard 的 VR 应用程序，请查看 Packt Publishing 的另一本书《Unity 虚拟现实项目》（https://www.packtpub.com/game-development/unity-virtual-reality-projects）。

## 原生开发

那么，为什么不只是使用 Unity 进行 Cardboard 开发呢？好问题。这取决于您想要做什么。当然，如果您的项目需要 Unity 的所有功能和特性，那就是这样做的方式。

但代价是什么？伟大的力量伴随着伟大的责任（本·帕克说）。学起来很快，但要精通需要一生的时间（围棋大师说）。但说真的，Unity 是一个强大的引擎，可能对许多应用程序来说过于强大。要充分利用，您可能需要额外的建模、动画、关卡设计、图形和游戏机制方面的专业知识。

使用 Unity 构建的 Cardboard 应用程序体积庞大。为 Android 构建的空的 Unity 场景生成一个最小为 23 兆字节的.apk 文件。相比之下，在第二章中我们构建的简单的原生 Cardboard 应用程序.apk 文件*骨架 Cardboard 项目*不到 1 兆字节。

随着这种庞大的应用程序大小，加载时间可能会很长，可能超过几秒钟。它会影响内存使用和电池使用。除非您已经购买了 Unity Android 许可证，否则您的应用程序总是以*Made With Unity*启动画面开始。这些可能不是您可以接受的限制。

一般来说，您离硬件越近，您的应用程序性能就会越好。当您直接为 Android 编写时，您可以直接访问设备的功能，对内存和其他资源有更多的控制，并有更多的定制和优化机会。这就是为什么原生移动应用程序往往优于移动 Web 应用程序。

最后，使用原生 Android 和 Java 开发的最好原因可能是最简单的。您现在就想构建一些东西！如果您已经是 Android 开发人员，那就使用您已经知道和喜爱的东西！从这里到那里走最直接的道路。

如果您熟悉 Android 开发，那么 Cardboard 开发将会很自然。使用 Cardboard SDK for Android，您可以使用基于 Jet Brains 的 InteliJ IDEA 的 Android Studio IDE（集成开发环境）进行 Java 编程。

正如我们将在本书中看到的那样，您的 Cardboard Android 应用程序与其他 Android 应用程序一样，包括清单、资源和 Java 代码。与任何 Android 应用程序一样，您将实现一个`MainActivity`类，但您的类将扩展`CardboardActivity`并实现`CardboardView.StereoRenderer`。您的应用程序将利用 OpenGL ES 2.0 图形、着色器和 3D 矩阵数学。它将负责在每一帧更新显示，也就是说，根据用户在特定时间片段所看的方向重新渲染您的 3D 场景。在 VR 中尤为重要，但在任何 3D 图形环境中，都要根据显示器允许的速度重新渲染新的帧，通常为 60 FPS。您的应用程序将通过 Cardboard 触发器和/或凝视控制处理用户输入。我们将在接下来的章节中详细介绍所有这些主题。

这就是您的应用程序需要做的。但是，仍然有更多细枝末节的细节必须处理才能使 VR 工作。正如 Google Cardboard SDK 指南中所指出的（https://developers.google.com/cardboard/android/），SDK 简化了许多这些常见的 VR 开发任务，包括以下内容：

+   镜头畸变校正

+   头部跟踪

+   3D 校准

+   并排渲染

+   立体几何配置

+   用户输入事件处理

SDK 提供了处理这些任务的功能。

构建和部署应用程序进行开发、调试、分析和最终发布到 Google Play 也遵循您可能已经熟悉的相同的 Android 工作流程。这很酷。

当然，构建应用程序不仅仅是简单地按照示例进行。我们将探讨诸如使用数据驱动的几何模型、抽象着色器和 OpenGL ES API 调用以及使用凝视选择构建用户界面元素等技术。除此之外，还有一些重要的建议最佳实践，可以使您的 VR 体验更加流畅，并避免常见的错误。

# VR 最佳实践概述

每天都有更多的关于为 VR 设计和开发时的 dos 和 don'ts 的发现和撰写。Google 提供了一些资源，以帮助开发人员构建出色的 VR 体验，包括以下内容：

+   《为 Google Cardboard 设计》是一份最佳实践文件，它可以帮助您专注于整体可用性，并避免常见的 VR 陷阱（[`www.google.com/design/spec-vr/designing-for-google-cardboard/a-new-dimension.html`](http://www.google.com/design/spec-vr/designing-for-google-cardboard/a-new-dimension.html)）。

+   《Cardboard Design Lab》是一个 Cardboard 应用程序，直接演示了为 VR 设计的原则，您可以在 Cardboard 中探索。在 2016 年 Vision Summit 上，Cardboard 团队宣布他们已经发布了源代码（Unity）项目，供开发人员检查和扩展（[`play.google.com/store/apps/details?id=com.google.vr.cardboard.apps.designlab`](https://play.google.com/store/apps/details?id=com.google.vr.cardboard.apps.designlab)和[`github.com/googlesamples/cardboard-unity/tree/master/Samples/CardboardDesignLab`](https://github.com/googlesamples/cardboard-unity/tree/master/Samples/CardboardDesignLab)）。

VR 晕动病是一种真实的症状和虚拟现实中的一个关注点，部分原因是屏幕更新的滞后或延迟，当您移动头部时。您的大脑期望您周围的世界与您的实际运动完全同步变化。任何可察觉的延迟都会让您感到不舒服，至少会让您可能感到恶心。通过更快地渲染每一帧来减少延迟，以保持推荐的每秒帧数。桌面 VR 应用程序要求保持 90FPS 的高标准，由自定义 HMD 屏幕实现。在移动设备上，屏幕硬件通常将刷新率限制在 60FPS，或在最坏的情况下为 30FPS。

VR 晕动病和其他用户不适的原因还有其他，可以通过遵循这些设计准则来减轻：

+   始终保持头部跟踪。如果虚拟世界似乎冻结或暂停，这可能会让用户感到不适。

+   在 3D 虚拟空间中显示用户界面元素，如标题和按钮。如果以 2D 形式呈现，它们似乎会“粘在您的脸上”，让您感到不舒服。

+   在场景之间过渡时，淡出到黑色。切换场景会让人感到非常迷茫。淡出到白色可能会让用户感到不舒服。

+   用户应该在应用程序内保持对其移动的控制。自己启动摄像机运动的某些东西有助于减少晕动病。尽量避免“人为”旋转摄像机。

+   避免加速和减速。作为人类，我们感受到加速，但不感受到恒定速度。如果在应用程序内移动摄像机，请保持恒定速度。过山车很有趣，但即使在现实生活中，它们也会让你感到不舒服。

+   让用户保持稳定。在虚拟空间中漂浮可能会让您感到不适，而感觉自己站在地面上或坐在驾驶舱中则会提供稳定感。

+   保持 UI 元素（如按钮和准星光标）与眼睛的合理距离。如果物体太近，用户可能需要斜视，并可能会感到眼睛紧张。一些太近的物体可能根本不会汇聚，导致“双重视觉”。

虚拟现实的应用程序在其他方面也不同于传统的 Android 应用程序，例如：

+   当从 2D 应用程序转换为 VR 时，建议您为用户提供一个头戴式设备图标，用户可以点击，如下图所示：![VR 最佳实践概述](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_01_12.jpg)

+   要退出 VR，用户可以点击系统栏中的返回按钮（如果有）或主页按钮。Cardboard 示例应用程序使用“向上倾斜”手势返回到主菜单，这是一个很好的方法，如果您想允许“返回”输入而不强迫用户从设备中取出手机。

+   确保您的应用程序以全屏模式运行（而不是在 Android 的 Lights Out 模式下运行）。

+   不要执行任何会向用户显示 2D 对话框的 API 调用。用户将被迫从观看设备中取出手机以做出回应。

+   提供音频和触觉（振动）反馈以传达信息，并指示应用程序已识别用户输入。

所以，假设您已经完成了您的精彩 Cardboard 应用程序，并且准备发布。现在怎么办？您可以在`AndroidManifest`文件中放入一行标记应用程序为 Cardboard 应用程序。Google 的 Cardboard 应用程序包括一个用于查找 Cardboard 应用程序的 Google Play 商店浏览器。然后，就像为任何普通的 Android 应用程序一样发布它。

# 摘要

在本章中，我们首先定义了 Google Cardboard，并看到它如何适应消费者虚拟现实设备的范围。然后，我们将 Cardboard 与更高端的 VR 设备进行对比，如 Oculus Rift、HTC Vive 和 PlayStation VR，提出低端 VR 作为一种独立媒介的观点。市场上有各种 Cardboard 观看设备，我们看了如何使用 QR 码为您的观看设备配置智能手机。我们谈了一些关于为 Cardboard 开发的内容，并考虑了使用 Unity 3D 游戏引擎与使用 Cardboard SDK 编写 Java 原生 Android 应用程序的原因和不原因。最后，我们快速调查了开发 VR 时的许多设计考虑因素，我们将在本书中更详细地讨论，包括如何避免晕动病和如何将 Cardboard 与 Android 应用程序整合的技巧。

在下一章中，我们开始编码。耶！为了一个共同的参考点，我们将花一点时间介绍 Android Studio IDE 并审查 Cardboard Android 类。然后，我们将一起构建一个简单的 Cardboard 应用程序，为本书中其他项目的结构和功能奠定基础。


# 第二章：Cardboard 项目的骨架

在本章中，你将学习如何构建一个 Cardboard 项目的骨架，这可以成为本书中其他项目的起点。我们将首先介绍 Android Studio、Cardboard SDK 和 Java 编程。我们希望确保你对工具和 Android 项目有所了解。然后，我们将指导你设置一个新的 Cardboard 项目，这样我们就不需要在每个项目中重复这些细节。如果这些内容对你来说已经很熟悉了，太好了！你可能可以略过它。在本章中，我们将涵盖以下主题：

+   一个 Android 应用程序中有什么？

+   Android 项目结构

+   开始使用 Android Studio

+   创建一个新的 Cardboard 项目

+   添加 Cardboard Java SDK

+   编辑清单、布局和`MainActivity`

+   构建和运行应用程序

# 一个 Android 应用程序中有什么？

对于我们的项目，我们将使用强大的 Android Studio IDE（集成开发环境）来构建在 Android 设备上运行的 Google Cardboard 虚拟现实应用程序。*哇哦！* Android Studio 在一个平台下整合了许多不同的工具和流程。

开发 Android 应用程序的所有辛勤工作的结果是一个 Android 应用程序包或`.apk`文件，通过 Google Play 商店或其他方式分发给用户。这个文件会安装在他们的 Android 设备上。

我们马上就会跳到 Android Studio 本身。然而，为了阐明这里发生了什么，让我们先考虑这个最终结果`.apk`文件。它到底是什么？我们是如何得到它的？了解构建过程将有所帮助。

记住这一点，为了好玩和获得视角，让我们从最后开始，从 APK 文件通过构建管道到我们的应用源代码。

## APK 文件

APK 文件实际上是一堆不同文件的压缩包，包括编译后的 Java 代码和非编译资源，比如图片。

APK 文件是为特定的 Android *目标*版本构建的，但它也指示了一个*最低*版本。一般来说，为较旧版本的 Android 构建的应用程序将在更新的 Android 版本上运行，但反之则不然。然而，为较旧版本的 Android 构建意味着新功能将不可用于该应用程序。你需要选择支持你需要的功能的最低 Android 版本，以便能够针对尽可能多的设备。或者，如果出于性能原因，你想要支持较小的设备子集，你可能会选择一个人为设定的较高的最低 API 版本。

在 Android Studio 中构建项目并创建 APK 文件，你需要点击**Build 菜单**选项并选择**Make Project**（或者点击绿色箭头图标来构建、部署和在设备上或**Android 虚拟设备**（**AVD**）中运行应用程序），这将启动 Gradle 构建过程。你可以构建一个版本来开发和调试，或者构建一个更优化的发布版本的应用程序。你可以通过点击**Build**菜单并选择**Select Build Variant...**来选择这样做。

## Gradle 构建过程

Android Studio 使用一个名为**Gradle**的工具从项目文件中构建 APK 文件。以下是从 Android 文档中获取的 Gradle 构建过程的流程图（[`developer.android.com/sdk/installing/studio-build.html`](http://developer.android.com/sdk/installing/studio-build.html)）。实际上，大部分图示细节对我们来说并不重要。重要的是看到这么多部分以及它们如何组合在一起。

![Gradle 构建过程](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_01.jpg)

在前面图表的最底部方框中，您可以看到构建的结果是一个经过签名和对齐的`.apk`文件，这是我们应用程序的最终版本，已经从之前的构建过程中编译（从源代码转换）、压缩（压缩）和签名（用于认证）。最后一步，zipalign，将压缩资源沿着 4 字节边界对齐，以便在运行时快速访问它们。基本上，这最后一步使应用程序加载更快。

在图表的中间，您将看到`.apk`（未签名，未压缩）文件是由`.dex`文件、编译的 Java 类和其他资源（如图像和媒体文件）组装而成。

`.dex`文件是 Java 代码，已经编译成在您设备上的**Dalvik** **虚拟机**（**DVM**）上运行的格式（Dalvik 字节码）。这是您程序的可执行文件。您在模块构建中包含的任何第三方库和编译的 Java 源代码文件（`.class`）都会被转换为`.dex`文件，以便打包到最终的`.apk`文件中。

如果这对您来说是新的，不要太在意细节。重要的是，我们将在我们的 Google Cardboard 项目中使用许多不同的文件。了解它们在构建过程中的使用情况将对我们有所帮助。

例如，带有 Cardboard SDK 的`common.aar`文件（二进制 Android 库存档）是我们将使用的第三方库之一。您项目的`res/`目录的内容，例如`layout/activity_main.xml`，会通过**Android 资产打包工具**（aapt）进行处理。

## 一个 Java 编译器

`.dex`文件的输入是什么？Java 编译器将 Java 语言源代码生成包含字节码的`.dex`文件。通过参考前面的 Gradle 构建流程图，在图表的顶部，您将看到 Java 编译器的输入包括以下内容：

+   您应用程序的 Java 源代码

+   您应用程序的 XML 资源，例如使用**aapt**编译的`AndroidManifest.xml`文件，并用于生成`R.java`文件

+   您的应用程序的 Java 接口（**Android 接口定义语言**`.aidl`文件），使用**aidl**工具编译

在本书的其余部分，我们将大量讨论这些源代码文件。那就是你写的东西！那就是你施展魔法的地方！那就是我们程序员生活的世界。

现在让我们来看看你的 Android 项目源代码的目录结构。

# Android 项目结构

您的 Android 项目的根目录包含各种文件和子目录。或者，我应该说，您的 Android 项目的根文件夹包含各种文件和*子文件夹*。*哈哈*。在本书中，我们将在整个过程中交替使用“文件夹”和“目录”这两个词，就像 Android Studio 似乎也在做的一样（实际上，这是有区别的，如[`stackoverflow.com/questions/29454427/new-directory-vs-new-folder-in-android-studio`](http://stackoverflow.com/questions/29454427/new-directory-vs-new-folder-in-android-studio)中所讨论的那样）。

如 Android 层次结构所示，在以下示例 Cardboard 项目中，根目录包含一个`app/`子目录，该子目录又包含以下子目录：

+   `app/manifests/`：这包含了指定应用程序组件（包括活动（UI）、设备权限和其他配置）的`AndroidManifest.xml`清单文件

+   `app/java/`：这包含了实现应用程序`MainActivity`和其他类的应用程序 Java 文件的子文件夹

+   `app/res/`：这包含了包括布局 XML 定义文件、值定义（`strings.xml`、`styles.xml`等）、图标和其他资源文件在内的资源子文件夹！Android 项目结构

这些目录与前面 Gradle 构建过程图表最上面一行中的方框相对应并不是巧合；它们提供了要通过 Java 编译器运行的源文件。

此外，在根目录下有 Gradle 脚本，不需要直接编辑，因为 Android Studio IDE 提供了方便的对话框来管理设置。在某些情况下，直接修改这些文件可能更容易。

请注意层次结构窗格左上角有一个选项卡选择菜单。在前面的屏幕截图中，它设置为**Android**，只显示 Android 特定的文件。还有其他视图可能也很有用，比如**Project**，它列出了项目根目录下的所有文件和子目录，如下一个屏幕截图所示，用于同一个应用程序。**Project**层次结构显示文件的实际文件系统结构。其他层次结构会人为地重新构造项目，以便更容易处理。

![Android 项目结构](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_03.jpg)

### 提示

您可能需要在**Android**视图和**Project**视图之间切换。

# 开始使用 Android Studio

在为 Android 开发 Cardboard 应用程序时，有很多东西需要跟踪，包括所有文件和文件夹、Java 类和对象、函数和变量。您需要一个正确组织的 Java 程序结构和有效的语言语法。您需要设置选项并管理进程以构建和调试应用程序。*哇！*

谢天谢地，我们有 Android Studio，一个功能强大的**IDE**（**集成开发环境**）。它是基于 JetBrains 的 IntelliJ IDEA 构建的，后者是一套受欢迎的智能 Java 开发工具套件。

它是智能的，因为它在您编写代码时实际上会给出相关的建议（*Ctrl* + *Space*），帮助在相关引用和文件之间导航（*Ctrl* + *B*，*Alt* + *F7*），并自动执行重构操作，比如重命名类或方法（*Alt* + *Enter*）。在某些方面，它可能知道您正在尝试做什么，即使您自己不知道。*多么聪明啊！*

## 安装 Android Studio

如果您的开发机器上尚未安装 Android Studio，您还在等什么？前往 Android 开发者页面（[`developer.android.com/develop/index.html`](http://developer.android.com/develop/index.html)）并将其下载到您的系统。它适用于 Windows、Mac OS X 或 Linux。您可以安装完整的 Android Studio 软件包，而不仅仅是 SDK 工具。然后，遵循安装说明。

## Android Studio 用户界面

Android Studio 有很多功能。在大多数情况下，我们将在实例的帮助下进行解释。但让我们花点时间来回顾一些功能，特别是与 Cardboard 开发相关的功能。只要确保在需要时阅读 Android 开发工具页面上提供的文档（[`developer.android.com/tools/studio/index.html`](http://developer.android.com/tools/studio/index.html)）。

对于初学者来说，Android Studio 的用户界面可能看起来令人生畏。而默认界面只是开始；编辑器主题和布局可以根据您的喜好进行自定义。更糟糕的是，随着新版本的发布，界面往往会发生变化，因此教程可能会显得过时。虽然这可能会使您在特定场合难以找到所需的内容，但基本功能并没有发生太大变化。在大多数情况下，Android 应用程序就是 Android 应用程序。我们在本书中使用的是 Windows 版的 Android Studio 2.1（尽管一些屏幕截图来自早期版本，但界面基本相同）。

### 注意

在使用 Android Studio 时，您可能会收到新的更新通知。我们建议您不要在项目进行中升级，除非您确实需要新的改进。即便如此，确保您有备份以防兼容性问题。

让我们简要地浏览一下 Android Studio 窗口，如下图所示：

![Android Studio 用户界面](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_04.jpg)

Android Studio 的菜单有：

+   顶部是主菜单栏（**＃1**），其中包含下拉菜单和拉出菜单，几乎包括所有可用功能。

+   在菜单栏下方是一个方便的主工具栏（**＃2**），其中包含常用功能的快捷方式。将鼠标悬停在图标上会显示工具提示，说明其功能。

+   工具栏下方是主编辑窗格（**＃3**）。当没有文件打开时，它会显示**没有打开的文件**。当打开多个文件时，主编辑窗格在顶部有选项卡。

+   层次结构导航器窗格位于左侧（**＃4**）。

+   层次结构导航器窗格在左侧有选项卡（垂直选项卡，**＃5**），用于在项目的各种视图之间进行选择。

### 注意

请注意层次结构窗格左上角的选择菜单。在前面的截图中，它设置为**Android**，只显示特定于 Android 的文件。还有其他视图可能也很有用，比如**项目**，它显示项目根目录下的所有文件和子目录，就像前面提到的那样。

+   底部是另一个工具栏（**＃6**），用于选择您可能需要的其他动态工具，包括终端窗口、构建消息、调试信息，甚至待办事项列表。也许最重要的是 Android Monitor 的**logcat**选项卡，它提供了一个窗口，用于收集和查看系统调试输出的 Android 日志系统。

### 注意

对于您来说，注意**可调试应用程序**下拉菜单、**日志级别**和**logcat**中的其他过滤器将是有帮助的，以便过滤掉会使您难以找到所需输出的“日志垃圾”。另外，请注意，即使在高端计算机上使用快速 CPU，这个日志视图也会使 Android Studio 变得非常缓慢。建议您在不使用时隐藏此视图，特别是如果您打开了多个 Android Studio 实例。

+   每个窗格的角落中的控件通常用于管理 IDE 窗格本身。

浏览一下 Android Studio 提供的各种不同功能会很有趣。要了解更多，请单击**帮助** | **帮助主题**菜单项（或工具栏上的**?**图标）以打开 IntelliJ IDEA 帮助文档（[`www.jetbrains.com/idea/help/intellij-idea.html`](https://www.jetbrains.com/idea/help/intellij-idea.html)）。

请记住，Android Studio 是建立在 IntelliJ IDE 之上的，它不仅可以用于 Android 开发。因此，这里有很多功能；有些您可能永远不会使用；其他一些您可能需要，但可能需要搜索。

### 提示

这里有一个建议：伴随着强大的力量而来的是巨大的责任（我以前在哪里听过这句话？）。实际上，对于如此多的用户界面功能，一点点的专注会很有用（是的，我刚刚编造了这句话）。当您需要使用时，专注于您需要使用的功能，不要为其他细节而烦恼。

在我们继续之前，让我们来看一下主菜单栏。它看起来像下面的截图：

![Android Studio 用户界面](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_05.jpg)

从左到右阅读，菜单项的组织方式与应用程序开发过程本身有些类似：创建、编辑、重构、构建、调试和管理。

+   **文件**：这些是项目文件和设置

+   **编辑**：这包括剪切、复制、粘贴和宏选项等

+   **视图**：这允许我们查看窗口、工具栏和 UI 模式

+   **导航**：这指的是基于内容的文件之间的导航

+   **代码**：这些是代码编辑的快捷方式

+   **分析**：这用于检查和分析代码中的错误和低效。

+   **重构**：用于跨语义相关文件编辑代码

+   **构建**：构建项目

+   **运行**：用于运行和调试

+   **工具**：这是与外部和第三方工具进行交互的界面。

+   **VCS**：指的是版本控制（即`git`）命令

+   **窗口**：管理 IDE 用户界面

+   **帮助**：包括文档和帮助链接

现在，是不是很可怕？

如果您还没有这样做，您可能希望尝试构建来自 Google Developers 网站 Android SDK 入门页面的 Cardboard Android 演示应用程序（参考[`developers.google.com/cardboard/android/get-started`](https://developers.google.com/cardboard/android/get-started)）。

在撰写本书时，演示应用程序称为**寻宝**，并且有关如何从其 GitHub 存储库克隆项目的说明。只需克隆它，打开 Android Studio，然后点击绿色播放按钮进行构建和运行。**入门**页面的其余部分将引导您了解解释关键元素的代码。

太酷了！在下一章中，我们将从头开始并重建几乎相同的项目。

# 创建一个新的 Cardboard 项目

安装了 Android Studio 后，让我们创建一个新项目。这是本书中任何项目都会遵循的步骤。我们只需创建一个空的框架，并确保它可以构建和运行：

1.  打开 IDE 后，您将看到一个**欢迎**屏幕，如下图所示：![创建一个新的 Cardboard 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_06.jpg)

1.  选择**开始一个新的 Android Studio 项目**，然后会出现**新项目**屏幕，如下所示：![创建一个新的 Cardboard 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_07.jpg)

1.  填写您的**应用程序名称**，例如`Skeleton`，和您的**公司域**，例如`cardbookvr.com`。您还可以更改**项目位置**。然后，点击“下一步”：![创建一个新的 Cardboard 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_08.jpg)

1.  在“目标 Android 设备”屏幕上，确保“手机和平板电脑”复选框已选中。在“最低 SDK”中，选择“API 19：Android 4.4（KitKat）”。然后，点击“下一步”：![创建一个新的 Cardboard 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_09.jpg)

1.  在“为移动添加活动”屏幕上，选择“空活动”。我们将从头开始构建这个项目。然后，点击“下一步”：![创建一个新的 Cardboard 项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_10.jpg)

1.  保留建议的名称`MainActivity`。然后，点击“完成”。

您全新的项目将在 Studio 上显示。如果需要，按*Alt* + *1*打开**项目视图**（Mac 上为*Command* + *1*）。

# 添加 Cardboard Java SDK

现在是将 Cardboard SDK 库`.aar`文件添加到您的项目中的好时机。在本书的基本项目中，您需要的库（撰写时为 v0.7）是：

+   `common.aar`

+   `core.aar`

### 注意

请注意，SDK 包括我们在本书中未使用但对您的项目可能有用的其他库。`audio.aar`文件用于支持空间音频。`panowidget`和`videowidget`库用于希望进入 VR 的 2D 应用程序，例如查看 360 度图像或视频。

在撰写本文时，要获取 Cardboard Android SDK 客户端库，您可以克隆`cardboard-java` GitHub 存储库，如 Google Developers Cardboard 入门页面上所述的那样，[`developers.google.com/cardboard/android/get-started#start_your_own_project`](https://developers.google.com/cardboard/android/get-started#start_your_own_project)上的**开始您自己的项目**主题。通过运行以下命令克隆`cardboard-java` GitHub 存储库：

```kt
git clone https://github.com/googlesamples/cardboard-java.git

```

要使用与此处使用的相同 SDK 版本 0.7 的确切提交，`checkout`提交：

```kt
git checkout 67051a25dcabbd7661422a59224ce6c414affdbc -b sdk07

```

或者，SDK 0.7 库文件包含在 Packt Publishing 的每个下载项目的`.zip`文件中，并且在本书的 GitHub 项目中[`github.com/cardbookvr`](https://github.com/cardbookvr)。

一旦您在本地拥有库的副本，请确保在文件系统中找到它们。要将库添加到我们的项目中，请执行以下步骤：

1.  对于所需的每个库，创建新模块。在 Android Studio 中，选择**文件**|**新建**|**新模块...**。选择**导入.JAR/.AAR 包**：![添加 Cardboard Java SDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_14.jpg)

1.  找到其中一个 AAR 并导入它。![添加 Cardboard Java SDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_15.jpg)

1.  通过导航到**文件**|**项目****结构**|**模块**（在左侧）|**应用程序**（您的应用程序名称）|**依赖项**|**+**|**模块依赖项**，将新模块作为主应用程序的依赖项添加进去：![添加 Cardboard Java SDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_16.jpg)

现在我们可以在我们的应用程序中使用 Cardboard SDK。

# AndroidManifest.xml 文件

新的空应用程序包括一些默认文件，包括`manifests/AndroidManifest.xml`文件（如果您已激活**Android**视图。在**Project**视图中，它在`app/src/main`）。每个应用程序必须在其清单目录中有一个`AndroidManifest.xml`文件，告诉 Android 系统运行应用程序代码所需的内容，以及其他元数据。

### 注意

有关此信息的更多信息，请访问[`developer.android.com/guide/topics/manifest/manifest-intro.html`](http://developer.android.com/guide/topics/manifest/manifest-intro.html)。

让我们首先设置这个。在编辑器中打开您的`AndroidManifest.xml`文件。修改它以读取如下内容：

```kt
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.cardbookvr.skeleton" >

   <uses-permission android:name="android.permission.NFC" />
   <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
	<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.VIBRATE" />

    <uses-sdk android:minSdkVersion="16" 
    android:targetSdkVersion="19"/>
    <uses-feature android:glEsVersion="0x00020000" android:required="true" />
    <uses-feature android:name="android.hardware.sensor.accelerometer" android:required="true"/>
    <uses-feature android:name="android.hardware.sensor.gyroscope" android:required="true"/>

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme" >
        <activity
            android:name=".MainActivity"

            android:screenOrientation="landscape"
            android:configChanges="orientation|keyboardHidden|screenSize" >

            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
                <category android:name="com.google.intent.category.CARDBOARD" />
            </intent-filter>
        </activity>
    </application>

</manifest>
```

在前面的清单中显示的软件包名称`package="com.cardbookvr.skeleton"`可能与您的项目不同。`<uses-permission>`标签表示项目可能正在使用 NFC 传感器，Cardboard SDK 可以使用该传感器来检测已插入 Cardboard 查看器设备的智能手机。互联网和读/写存储权限是 SDK 下载、读取和写入配置设置选项所需的。我们需要做更多工作来正确处理权限，但这将在另一个文件中进行讨论。

`<uses-feature>`标签指定我们将使用 OpenGL ES 2.0 图形处理库（[`developer.android.com/guide/topics/graphics/opengl.html`](http://developer.android.com/guide/topics/graphics/opengl.html)）。

还强烈建议包括加速计和陀螺仪传感器`uses-feature`标签。太多用户的手机缺少这两个传感器中的一个或两个。当应用程序无法正确跟踪他们的头部运动时，他们可能会认为是应用程序的问题而不是他们的手机的问题。在`<application>`标签（在创建文件时生成的默认属性）中，有一个名为`.MainActivity`的`<activity>`定义和屏幕设置。在这里，我们将`android:screenOrientation`属性指定为我们的 Cardboard 应用程序使用正常（左）横向方向。我们还指定`android:configChanges`，表示活动将自行处理。

这些和其他属性设置可能会根据您的应用程序要求而变化。例如，使用`android:screenOrientation="sensorLandscape"`将允许基于手机传感器的正常或反向横向方向（并在屏幕翻转时触发`onSurfaceChanged`回调）。

我们在`<intent-filter>`标签中指定了我们的*intent*元数据。在 Android 中，**intent**是一种消息对象，用于促进应用程序组件之间的通信。它还可以用于查询已安装的应用程序并匹配某些意图过滤器，如在应用程序清单文件中定义的那样。例如，想要拍照的应用程序将广播一个带有`ACTION_IMAGE_CAPTURE`动作过滤器的意图。操作系统将响应一个包含可以响应此类动作的活动的已安装应用程序列表。

定义了`MainActivity`类之后，我们将指定它可以响应标准的`MAIN`动作并匹配`LAUNCHER`类别。`MAIN`表示此活动是应用程序的入口点；也就是说，当您启动应用程序时，将创建此活动。`LAUNCHER`表示应用程序应该出现在主屏幕的启动器中，作为顶级应用程序。

我们添加了一个意图，以便此活动也匹配`CARDBOARD`类别，因为我们希望其他应用程序将其视为 Cardboard 应用程序！

Google 在 Android 6.0 Marshmallow（API 23）中对权限系统进行了重大更改。虽然您仍然必须在`AndroidManifest.xml`文件中包含您想要的权限，但现在您还必须调用一个特殊的 API 函数来在运行时请求权限。这样做有很多原因，但其想法是给用户更精细的控制应用程序权限，并避免在安装和运行时请求长列表的权限。这一新功能还允许用户在授予权限后有选择地撤销权限。这对用户来说很好，但对我们应用程序开发人员来说很不幸，因为这意味着当我们需要访问这些受保护的功能时，我们需要做更多的工作。基本上，您需要引入一个步骤来检查特定权限是否已被授予，并在没有授予时提示用户。一旦用户授予权限，将调用回调方法，然后您可以自由地执行需要权限的任何操作。或者，如果权限一直被授予，您可以继续使用受限功能。

在撰写本文时，我们的项目代码和当前版本的 Cardboard SDK 尚未实现这个新的权限系统。相反，我们将强制 Android Studio 针对较旧版本的 SDK（API 22）构建我们的项目，以便我们绕过新功能。未来，Android 可能会破坏与旧权限系统的向后兼容性。但是，您可以在 Android 文档中阅读有关如何使用新权限系统的非常清晰的指南（参见[`developer.android.com/training/permissions/requesting.html`](http://developer.android.com/training/permissions/requesting.html)）。我们希望在在线 GitHub 存储库中解决这个问题和任何未来问题，但请记住，文本中的代码和提供的 zip 文件可能无法在最新版本的 Android 上运行。这就是软件维护的性质。

让我们将这个解决方法应用到针对 SDK 版本 22 的构建中。很可能您刚刚安装了 Android Studio 2.1 或更高版本，其中包含 SDK 23 或更高版本。每当您创建一个新项目时，Android Studio 确实会询问您想要针对哪个最低 SDK 版本，但不会让您选择用于编译的 SDK。这没关系，因为我们可以在`build.gradle`文件中手动设置这一点。不要害怕；构建工具集很庞大且复杂，但我们只是稍微调整了项目设置。请记住，您的项目中有几个`build.gradle`文件。每个文件都将位于文件系统中相应的模块文件夹中，并且将在项目视图的 Gradle 脚本部分中相应地标记。我们要修改`app`模块的`build.gradle`。将其修改为如下所示：

```kt
apply plugin: 'com.android.application'

android {
    compileSdkVersion 22
    ...

    defaultConfig {
        minSdkVersion 19
        targetSdkVersion 22
        ...
    }
    ...
}

dependencies {
    compile 'com.android.support:appcompat-v7:22.1.0'
    ...
}
```

重要的更改是 compileSdkVersion、minSdkVersion、targetSdkVersion 以及依赖项中的最后一个，在那里我们更改了我们链接到的支持存储库的版本。从技术上讲，我们可以完全消除这种依赖关系，但项目模板包括了一堆对它的引用，这些引用很难删除。然而，如果我们保留默认设置，Gradle 很可能会因为版本不匹配而向我们抱怨。一旦您进行了这些更改，编辑器顶部应该会出现一个黄色的条，上面有一个写着**立即同步**的链接。立即同步。如果幸运的话，Gradle 同步将成功完成，您就可以继续愉快地进行下去了。如果不幸的话，您可能会缺少 SDK 平台或其他依赖项。**消息**窗口应该有可点击的链接，可以适当地安装和更新 Android 系统。如果遇到错误，请尝试重新启动 Android Studio。

从这一点开始，您可能希望避免更新 Android Studio 或您的 SDK 平台版本。特别注意当您在另一台计算机上导入项目或在更新 Android Studio 后发生的情况。您可能需要让 IDE 操作您的 Gradle 文件，并且它可能会修改您的编译版本。这个权限问题很隐蔽，它只会在运行时在运行 6.0 及以上版本的手机上显露出来。您的应用程序可能在运行旧版本的 Android 的设备上看起来运行良好，但实际上在新设备上可能会遇到麻烦。

# activity_main.xml 文件

我们的应用程序需要一个布局，我们将在其中定义一个画布来绘制我们的图形。Android Studio 创建的新项目在`app/res/layout/`文件夹中创建了一个默认的布局文件（使用 Android 视图或`app/src/main/res/layout`使用**项目**视图）。找到`activity_main.xml`文件并双击打开进行编辑。

在 Android Studio 编辑器中，布局文件有两种视图：**设计**和**文本**，通过窗格左下角的选项卡进行选择。如果选择了**设计**视图选项卡，您将看到一个交互式编辑器，其中包括一个模拟的智能手机图像，左侧是 UI 组件的调色板，右侧是**属性**编辑器。我们不会使用这个视图。如果需要，选择`activity_main.xml`编辑窗格底部的**文本**选项卡以使用文本模式。

Cardboard 应用程序应该在全屏上运行，因此我们会删除任何填充。我们还将删除默认的我们不打算使用的`TextView`。而是用`CardboardView`来替换它，如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<RelativeLayout 

    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">

    <com.google.vrtoolkit.cardboard.CardboardView
        android:id="@+id/cardboard_view"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent"
        android:layout_alignParentTop="true"
        android:layout_alignParentLeft="true" />

</RelativeLayout>
```

`AndroidManifest.xml`文件引用了名为`MainActivity`的主要活动。现在让我们来看看。

# MainActivity 类

使用`Empty Activity`生成的默认项目还创建了一个默认的`MainActivity.java`文件。在层次结构窗格中，找到包含名为`com.cardbookvr.skeleton`的子目录的`app/java/`目录。

### 注意

请注意，这与`androidTest`版本的目录不同，我们不使用那个！（根据您创建项目时给定的实际项目和域名，您的名称可能会有所不同。）

在这个文件夹中，双击`MainActivity.java`文件以进行编辑。默认文件如下所示：

```kt
package com.cardbookvr.skeleton;

import ...

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}
```

您应该注意到的第一件事是扩展`AppCompatActivity`类（或`ActionBarActivity`）以使用内置的 Android 操作栏。我们不需要这个。我们将把活动定义为扩展`CardboardActivity`并实现`CardboardView.StereoRenderer`接口。修改代码中的类声明行，如下所示：

```kt
public class MainActivity extends CardboardActivity implements CardboardView.StereoRenderer {
```

由于这是一个 Google Cardboard 应用程序，我们需要将`MainActivity`类定义为 SDK 提供的`CardboardActivity`类的子类。我们使用`extends`关键字来实现这一点。

`MainActivity`还需要实现至少一个被定义为`CardboardView.StereoRender`的立体渲染器接口。我们使用`implements`关键字来实现这一点。

Android Studio 的一个好处是在编写代码时为你自动完成工作。当你输入`extends CardboardActivity`时，IDE 会自动在文件顶部添加`CardboardActivity`类的`import`语句。当你输入`implements CardboardView.StereoRenderer`时，它会添加一个`import`语句到`CardboardView`类。

随着我们继续添加代码，Android Studio 将识别出我们需要额外的导入语句，并自动为我们添加它们。因此，我不会在接下来的代码中显示`import`语句。偶尔它可能会找到错误的引用，例如，在你的库中有多个`Camera`或`Matrix`类时，你需要将其解析为正确的引用。

现在我们将用一些函数存根填充`MainActivity`类的主体，这些函数是我们将需要的。我们使用的`CardboardView.StereoRenderer`接口定义了许多抽象方法，我们可以重写这些方法，如 Android API 参考中对该接口的文档所述（参见[`developers.google.com/cardboard/android/latest/reference/com/google/vrtoolkit/cardboard/CardboardView.StereoRenderer`](https://developers.google.com/cardboard/android/latest/reference/com/google/vrtoolkit/cardboard/CardboardView.StereoRenderer)）。

在 Studio 中可以通过多种方式快速完成。可以使用智能感知上下文菜单（灯泡图标）或转到**代码** | **实现方法…**（或*Ctrl* + *I*）。将光标放在红色错误下划线处，按*Alt* + *Enter*，你也可以达到同样的目标。现在就做吧。系统会要求你确认要实现的方法，如下面的截图所示：

![MainActivity 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_12.jpg)

确保所有都被选中，然后点击**确定**。

以下方法的存根将被添加到`MainActivity`类中：

+   `onSurfaceCreated`：在表面被创建或重新创建时调用此方法。它应该创建需要显示图形的缓冲区和变量。

+   `onNewFrame`：在准备绘制新帧时调用此方法。它应该更新从一个帧到下一个帧变化的应用程序数据，比如动画。

+   `onDrawEye`：为当前相机视点渲染一个眼睛的场景（每帧调用两次，除非你有三只眼睛！）。

+   `onFinishFrame`：在帧完成之前调用此方法。

+   `onRenderShutdown`：当渲染器线程关闭时调用此方法（很少使用）。

+   `onSurfaceChanged`：当表面尺寸发生变化时（例如检测到纵向/横向旋转）调用此方法。

我按照 Cardboard Android 应用程序的生命周期顺序列出了这些方法。

`@Override`指令表示这些函数最初是在`CardboardView.StereoRenderer`接口中定义的，我们在这里的`MainActivity`类中替换（覆盖）它们。

## 默认的`onCreate`

所有 Android 活动都公开一个`onCreate()`方法，在活动第一次创建时调用。这是你应该做所有正常的静态设置和绑定的地方。立体渲染器接口和 Cardboard 活动类是 Cardboard SDK 的基础。

默认的`onCreate`方法对父活动进行了标准的`onCreate`调用。然后，它将`activity_main`布局注册为当前内容视图。

通过添加`CardboadView`实例来编辑`onCreate()`，如下所示：

```kt
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        CardboardView cardboardView = (CardboardView) findViewById(R.id.cardboard_view);
        cardboardView.setRenderer(this);
        setCardboardView(cardboardView);
    }
```

为了设置应用程序的`CardboardView`实例，我们通过在`activity_main.xml`中给定的资源 ID 查找其实例，然后使用一些函数调用设置它。

这个对象将对显示进行立体渲染，所以我们调用`setRenderer(this)`来指定它作为`StereoRenderer`接口方法的接收者。

### 注意

请注意，您的活动不必实现该接口。您可以让任何类定义这些方法，比如我们将在本书后面看到的抽象渲染器。

然后我们通过调用`setCardboardView(cardboardView)`将`CardboardView`类与这个活动关联起来，这样我们就能接收到任何必需的生命周期通知，包括`StereoRenderer`接口方法，比如`onSurfaceCreated`和`onDrawEye`。

## 构建和运行

让我们构建并运行它：

1.  转到**Run** | **Run 'app'**，或者简单地使用工具栏上的绿色三角形**Run**图标。

1.  如果您进行了更改，Gradle 将进行构建。

1.  选择 Android Studio 窗口底部的**Gradle Console**选项卡以查看 Gradle 构建消息。然后，假设一切顺利，APK 将安装在您连接的手机上（连接并打开了吗？）。

1.  选择底部的**Run**选项卡以查看上传和启动消息。

您不应该收到任何构建错误。但当然，该应用实际上并没有做任何事情或在屏幕上绘制任何东西。嗯，这并不完全正确！通过`CardboardView.StereoRenderer`，Cardboard SDK 提供了一个带有垂直线和齿轮图标的立体分屏，如下截图所示：

![构建和运行](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_02_13.jpg)

垂直线将用于在 Cardboard 查看器设备上正确放置您的手机。

齿轮图标打开标准配置设置实用程序，其中包括扫描 QR 码以配置 SDK 以适应镜片和您特定设备的其他物理属性的功能（如第一章中所解释的，“每个人的虚拟现实”，在“配置 Cardboard 查看器”部分）。

现在，我们已经为 Android 构建了一个 Google Cardboard 应用的框架。您将遵循类似的步骤来启动本书中的每个项目。

# 摘要

在本章中，我们研究了 Android 上 Cardboard 应用的结构以及涉及的许多文件，包括 Java 源代码、XML 清单、`.aar`库和最终构建的 APK，该 APK 在您的 Android 设备上运行。我们安装并简要介绍了 Android Studio 开发环境。然后，我们将引导您完成创建新的 Android 项目、添加 Cardboard Java SDK 以及定义`AndroidManifest.xml`文件和布局，以及一个存根的`MainActivity` Java 类文件的步骤。在本书中，您将遵循类似的步骤来启动每个 Cardboard 项目。

在下一章中，我们将从头开始构建一个名为`CardboardBox`的 Google Cardboard 项目，其中包含一些简单几何图形（三角形和立方体）、3D 变换和渲染图形到您的 Cardboard 设备的着色器。


# 第三章：Cardboard Box

还记得小时候开心地玩纸板盒吗？这个项目甚至可能比那更有趣！我们的第一个 Cardboard 项目将是一个简单的场景，有一个盒子（一个几何立方体），一个三角形，还有一点用户交互。我们称之为“CardboardBox”。懂了吗？

具体来说，我们将创建一个新项目，构建一个简单的应用程序，只绘制一个三角形，然后增强该应用程序以绘制阴影的 3D 立方体，并通过在观察时突出显示立方体来说明一些用户交互。

在本章中，您将会：

+   创建一个新的 Cardboard 项目

+   向场景添加三角形对象，包括几何、简单着色器和渲染缓冲区

+   使用 3D 相机、透视和头部旋转

+   使用模型变换

+   制作和绘制立方体对象

+   添加光源和阴影

+   旋转立方体

+   添加地板

+   突出显示用户正在查看的对象

本章中的项目源自 Google Cardboard 团队提供的一个示例应用程序，名为*寻宝游戏*。最初，我们考虑让您简单地下载寻宝游戏，然后我们会在代码中引导您解释其工作原理。相反，我们决定从头开始构建一个类似的项目，并在进行过程中进行解释。这也减轻了谷歌在本书出版后更改或甚至替换该项目的可能性。

该项目的源代码可以在 Packt Publishing 网站和 GitHub 上找到，网址为[`github.com/cardbookvr/cardboardbox`](https://github.com/cardbookvr/cardboardbox)（每个主题作为单独的提交）。

Android SDK 版本对于您的成品应用程序很重要，但您的桌面环境也可以以多种方式设置。我们之前提到，我们使用 Android Studio 2.1 构建了本书中的项目。我们还使用了 Java SDK 版本 8（1.8）。对于您来说，安装这个版本很重要（您可以并排安装许多版本），以便导入项目。与任何开发环境一样，对 Java 或 Android Studio 所做的任何更改可能会在将来“破坏”导入过程，但实际的源代码应该可以编译和运行多年。

# 创建一个新项目

如果您想了解有关这些步骤的更多详细信息和解释，请参考第二章中的*创建新的 Cardboard 项目*部分，*骨架 Cardboard 项目*，并跟随那里进行：

1.  打开 Android Studio，创建一个新项目。让我们将其命名为`CardboardBox`，并针对**Android 4.4 KitKat (API 19)**使用**空活动**。

1.  将 Cardboard SDK 的`common.aar`和`core.aar`库文件作为新模块添加到项目中，使用**文件** | **新建** | **新建模块...**。

1.  将库模块设置为项目应用程序的依赖项，使用**文件** | **项目结构**。

1.  根据第二章中的说明编辑`AndroidManifest.xml`文件，*骨架 Cardboard 项目*，要小心保留此项目的`package`名称。

1.  根据第二章中的说明编辑`build.gradle`文件，*骨架 Cardboard 项目*，以便编译 SDK 22。

1.  根据第二章中的说明编辑`activity_main.xml`布局文件，*骨架 Cardboard 项目*。

1.  编辑`MainActivity` Java 类，使其`extends` `CardboardActivity`并`implement` `CardboardView.StereoRenderer`。修改类声明行如下：

```kt
public class MainActivity extends CardboardActivity implements CardboardView.StereoRenderer {
```

1.  添加接口的存根方法覆盖（使用智能实现方法或按下*Ctrl* + *I*）。

1.  在`MainActivity`类的顶部，添加以下注释作为我们将在此项目中创建的变量的占位符：

```kt
CardboardView.StereoRenderer {
   private static final String TAG = "MainActivity";

   // Scene variables
   // Model variables
   // Viewing variables
   // Rendering variables
```

1.  最后，通过以下方式编辑`onCreate()`，添加`CardboadView`实例：

```kt
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        CardboardView cardboardView = (CardboardView) findViewById(R.id.cardboard_view);
        cardboardView.setRenderer(this);
        setCardboardView(cardboardView);  
    }
```

# 你好，三角形！

让我们在场景中添加一个三角形。是的，我知道三角形甚至不是一个盒子。然而，我们将从非常简单的提示开始。三角形是所有 3D 图形的基本构件，也是 OpenGL 可以渲染的最简单的形状（即以三角形模式）。

## 引入几何图形

在继续之前，让我们谈谈几何图形。

虚拟现实在很大程度上是关于创建 3D 场景。复杂的模型被组织为具有顶点、面和网格的三维数据，形成可以按层次组装成更复杂模型的对象。目前，我们采用了一个非常简单的方法——一个由三个顶点组成的三角形，存储为一个简单的 Java 数组。

三角形由三个顶点组成（这就是为什么它被称为**三角形**！）。我们将把我们的三角形定义为顶部（0.0, 0.6），左下角（-0.5, -0.3），右下角（0.5, -0.3）。第一个顶点是三角形的最顶点，具有*X=0.0*，因此它位于中心，*Y=0.6*向上。

顶点的顺序或三角形的绕组非常重要，因为它指示了三角形的正面方向。OpenGL 驱动程序希望它以逆时针方向绕组，如下图所示：

![引入几何图形](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_03_01.jpg)

如果顶点是顺时针定义的，着色器将假定三角形朝向相反方向，远离摄像头，因此不可见且不会被渲染。这是一种优化称为**剔除**，它允许渲染管线轻松丢弃在物体背面的几何图形。也就是说，如果对摄像头不可见，甚至不要尝试绘制它。话虽如此，您可以设置各种剔除模式，选择只渲染正面、背面或两者。

请参阅[`learnopengl.com/#!Advanced-OpenGL/Face-culling`](http://learnopengl.com/#!Advanced-OpenGL/Face-culling)上的创作共用来源。

### 提示

*OpenGL 编程指南*，作者 Dave Shreiner，Graham Sellers，John M. Kessenich，Bill Licea-Kane，“按照惯例，在屏幕上顶点逆时针顺序出现的多边形被称为正面朝向”。这是由全局状态模式确定的，默认值为`GL_CCW`（[`www.opengl.org/wiki/Face_Culling`](https://www.opengl.org/wiki/Face_Culling)）。

三维点或顶点是用*x*、*y*和*z*坐标值定义的。例如，在 3D 空间中，三角形由三个顶点组成，每个顶点都有*x*、*y*和*z*值。

我们的三角形位于与屏幕平行的平面上。当我们在场景中添加 3D 视图（本章后面会介绍）时，我们需要一个*z*坐标将其放置在 3D 空间中。为了预期，我们将三角形设置在*Z=-1*平面上。OpenGL 中的默认摄像头位于原点（0,0,0），并朝着负*z*轴方向。换句话说，场景中的物体朝着正*z*轴向摄像头看。我们将三角形放置在离摄像头一单位远的地方，这样我们就可以在*Z=-1.0*处看到它。

## 三角形变量

将以下代码片段添加到`MainActivity`类的顶部：

```kt
    // Model variables
    private static final int COORDS_PER_VERTEX = 3;
    private static float triCoords[] = {
        // in counter-clockwise order
        0.0f,  0.6f, -1.0f, // top
       -0.5f, -0.3f, -1.0f, // bottom left
        0.5f, -0.3f, -1.0f  // bottom right
    };

    private final int triVertexCount = triCoords.length / COORDS_PER_VERTEX;
    // yellow-ish color
    private float triColor[] = { 0.8f, 0.6f, 0.2f, 0.0f }; 
    private FloatBuffer triVerticesBuffer;
```

我们的三角形坐标被分配给`triCoords`数组。所有顶点都在 3D 空间中，每个顶点（`COORDS_PER_VERTEX`）有三个坐标（*x*、*y*和*z*）。预先计算的`triVertexCount`变量是三角形`triCoords`数组的长度，除以`COORDS_PER_VERTEX`。我们还为我们的三角形定义了一个任意的`triColor`值，由 R、G、B 和 A 值（红色、绿色、蓝色和 alpha（透明度））组成。`triVerticesBuffer`变量将在绘制代码中使用。

对于刚接触 Java 编程的人来说，你可能也会对变量类型感到困惑。整数声明为 `int`，浮点数声明为 `float`。这里的所有变量都被声明为 `private`，这意味着它们只能在这个类定义内部可见和使用。被声明为 `static` 的变量将在类的多个实例之间共享数据。被声明为 `final` 的变量是不可变的，一旦初始化就不会改变。

## onSurfaceCreated

这个活动代码的目的是在 Android 设备显示器上绘制东西。我们通过 OpenGL 图形库来实现这一点，它会绘制到一个表面上，一个内存缓冲区，你可以通过渲染管线绘制图形。

活动创建后（`onCreate`），会创建一个表面并调用 `onSurfaceCreated`。它有几个责任，包括初始化场景和编译着色器。它还通过为顶点缓冲区分配内存、绑定纹理和初始化渲染管线句柄来准备渲染。

这是一个方法，我们将把它分成几个私有方法，接下来我们将编写这些方法：

```kt
    @Override
    public void onSurfaceCreated(EGLConfig eglConfig) {
        initializeScene();
        compileShaders();
        prepareRenderingTriangle();
    }
```

在这一点上，场景中没有什么需要初始化的：

```kt
private void initializeScene() {
}
```

让我们继续讨论着色器和渲染。

## 介绍 OpenGL ES 2.0

现在是介绍 *图形管线* 的好时机。当 Cardboard 应用在屏幕上绘制 3D 图形时，它会将渲染交给一个单独的图形处理器（GPU）。Android 和我们的 Cardboard 应用使用 OpenGL ES 2.0 标准图形库。

OpenGL 是应用程序与图形驱动程序交互的规范。你可以说它是一长串在图形硬件中执行操作的函数调用。硬件供应商编写他们的驱动程序以符合最新的规范，而一些中间件，比如 Google，在这种情况下创建了一个库，它连接到驱动程序函数，以提供你可以从任何语言中调用的方法签名（通常是 Java、C++ 或 C#）。

OpenGL ES 是 OpenGL 的移动版，也称为嵌入式系统。它遵循与 OpenGL 相同的设计模式，但其版本历史非常不同。不同版本的 OpenGL ES 甚至同一版本的不同实现都需要不同的方法来绘制 3D 图形。因此，你的代码在 OpenGL ES 1.0、2.0 和 3.0 之间可能会有很大的不同。值得庆幸的是，大部分重大变化发生在版本 1 和 2 之间，Cardboard SDK 设定为使用 2.0。`CardboardView` 接口也与普通的 `GLSurfaceView` 稍有不同。

在屏幕上绘制图形，OpenGL 需要两个基本的东西：

+   定义如何绘制形状的图形程序，或 *着色器*（有时可以互换使用）

+   定义正在绘制的数据，或 *缓冲区*

还有一些参数，用于指定变换矩阵、颜色、向量等。你可能熟悉游戏循环的概念，这是一种设置游戏环境并启动一个循环的基本模式，该循环运行一些游戏逻辑，渲染屏幕，并在半规律的时间间隔内重复，直到游戏暂停或程序退出。`CardboardView` 为我们设置了游戏循环，基本上，我们只需要实现接口方法。

关于着色器的更多信息：至少我们需要一个顶点着色器和一个片段着色器。顶点着色器负责将对象的顶点从世界空间（它们在世界中的位置）转换到屏幕空间（它们应该在屏幕上绘制的位置）。

片段着色器在形状占据的每个像素上调用（由光栅函数确定），并返回绘制的颜色。每个着色器都是一个单一的函数，伴随着一些可以用作输入的属性。

OpenGL 将一组函数（即顶点和片段）编译成一个程序。有时，整个程序被称为着色器，但这是一种俚语，假设需要多个函数或*着色器*才能完全绘制一个对象。程序及其所有参数的值有时会被称为*材质*，因为它完全描述了它绘制的表面的材质。

着色器很酷。但是，在程序设置数据缓冲区并进行大量绘制调用之前，它们不会做任何事情。

绘制调用由**顶点缓冲对象**（**VBO**）、将用于绘制的着色器、指定应用于对象的变换的参数数量、用于绘制的纹理和任何其他着色器参数组成。

VBO 是指用于描述对象形状的任何和所有数据。一个非常基本的对象（例如三角形）只需要一个顶点数组。顶点按顺序读取，每三个空间位置定义一个三角形。稍微更高级的形状使用顶点数组和索引数组，定义了以什么顺序绘制哪些顶点。使用索引缓冲区，可以重复使用多个顶点。

虽然 OpenGL 可以绘制多种形状类型（点、线、三角形和四边形），但我们假设所有形状都是三角形。这既是性能优化，也是方便之处。如果我们想要一个四边形，我们可以绘制两个三角形。如果我们想要一条线，我们可以绘制一个非常长而细的四边形。如果我们想要一个点，我们可以绘制一个微小的三角形。这样，不仅可以将 OpenGL 保留在三角形模式下，还可以以完全相同的方式处理所有 VBO。理想情况下，您希望您的渲染代码完全不受其渲染对象的影响。

总结：

+   OpenGL 图形库的目的是让我们访问 GPU 硬件，然后根据场景中的几何图形在屏幕上绘制像素。这是通过渲染管线实现的，其中数据经过一系列着色器的转换和传递。

+   着色器是一个小程序，它接受某些输入并生成相应的输出，具体取决于管线的阶段。

+   作为一个程序，着色器是用一种特殊的类似于 C 的语言编写的。源代码经过编译后可以在 Android 设备的 GPU 上高效运行。

例如，*顶点着色器*处理单个顶点的处理，输出每个顶点的变换版本。另一个步骤是对几何图形进行光栅化，之后*片段着色器*接收光栅片段并输出彩色像素。

### 注意

我们将在后面讨论 OpenGL 渲染管线，并且您可以在[`www.opengl.org/wiki/Rendering_Pipeline_Overview`](https://www.opengl.org/wiki/Rendering_Pipeline_Overview)上阅读相关内容。

您还可以在[`developer.android.com/guide/topics/graphics/opengl.html`](http://developer.android.com/guide/topics/graphics/opengl.html)上查看 Android OpenGL ES API 指南。

暂时不要太担心这个问题，让我们跟着走就好。

注意：GPU 驱动程序实际上是根据每个驱动程序来实现整个 OpenGL 库的。这意味着 NVIDIA（或在这种情况下，可能是 Qualcomm 或 ARM）的某个人编写了编译您的着色器和读取您的缓冲区的代码。OpenGL 是关于这个 API 应该如何工作的规范。在我们的情况下，这是 Android 的 GL 类的一部分。

## 简单着色器

现在，我们将在`MainActivity`类的末尾添加以下函数。

```kt
   /**
     * Utility method for compiling a OpenGL shader.
     *
     * @param type - Vertex or fragment shader type.
     * @param resId - int containing the resource ID of the shader code file.
     * @return - Returns an id for the shader.
     */
    private int loadShader(int type, int resId){
        String code = readRawTextFile(resId);
        int shader = GLES20.glCreateShader(type);

        // add the source code to the shader and compile it
        GLES20.glShaderSource(shader, code);
        GLES20.glCompileShader(shader);

        return shader;
    }

    /**
     * Converts a raw text file into a string.
     *
     * @param resId The resource ID of the raw text file about to be turned into a shader.
     * @return The content of the text file, or null in case of error.
     */
    private String readRawTextFile(int resId) {
        InputStream inputStream = getResources().openRawResource(resId);
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            reader.close();
            return sb.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
```

我们将调用`loadShader`来加载一个着色器程序（通过`readRawTextFile`）并对其进行编译。这段代码在其他项目中也会很有用。

现在，我们将在`res/raw/simple_vertex.shader`和`res/raw/simple_fragment.shader`文件中编写一些简单的着色器。

在 Android Studio 左侧的**项目文件**层次结构视图中，定位`app/res/`资源文件夹，右键单击它，转到**新建** | **Android 资源目录**。在**新资源目录**对话框中，从**资源类型：**中选择**Raw**，然后单击**确定**。

右键单击新的`raw`文件夹，转到**新建** | **文件**，并将其命名为`simple_vertex.shader`。添加以下代码：

```kt
attribute vec4 a_Position;
void main() {
    gl_Position = a_Position;
}
```

同样，对于片段着色器，右键单击`raw`文件夹，转到**新建** | **文件**，并将其命名为`simple_fragment.shader`。添加以下代码：

```kt
precision mediump float;
uniform vec4 u_Color;
void main() {
    gl_FragColor = u_Color;
}
```

基本上，这些是恒等函数。顶点着色器通过给定的顶点，片段着色器通过给定的颜色。

注意我们声明的参数的名称：`simple_vertex`中的属性名为`a_Position`，`simple_fragment`中的统一变量名为`u_Color`。我们将从`MainActivity onSurfaceCreated`方法中设置这些属性。属性是每个顶点的属性，当我们为它们分配缓冲区时，它们必须都是相等长度的数组。您将遇到的其他属性是顶点法线、纹理坐标和顶点颜色。统一变量将用于指定适用于整个材质的信息，例如在这种情况下，应用于整个表面的固体颜色。

另外，注意`gl_FragColor`和`gl_Position`变量是 OpenGL 正在寻找你设置的内置变量名称。把它们想象成着色器函数的返回值。还有其他内置的输出变量，我们稍后会看到。

## compileShaders 方法

现在我们准备实现`onSurfaceCreated`调用的`compileShaders`方法。

在`MainActivity`的顶部添加以下变量：

```kt
    // Rendering variables
    private int simpleVertexShader;
    private int simpleFragmentShader;
```

实现`compileShaders`，如下：

```kt
    private void compileShaders() {
        simpleVertexShader = loadShader(GLES20.GL_VERTEX_SHADER, R.raw.simple_vertex);
        simpleFragmentShader = loadShader(GLES20.GL_FRAGMENT_SHADER, R.raw.simple_fragment);
    }
```

## prepareRenderingTriangle 方法

`onSurfaceCreated`方法通过为顶点缓冲区分配内存，创建 OpenGL 程序和初始化渲染管道句柄来准备渲染。现在我们将为我们的三角形形状执行此操作。

在`MainActivity`的顶部添加以下变量：

```kt
    // Rendering variables
    private int triProgram;
    private int triPositionParam;
    private int triColorParam;
```

以下是函数的框架：

```kt
    private void prepareRenderingTriangle() {
        // Allocate buffers
        // Create GL program
        // Get shader params
    }
```

我们需要准备一些内存缓冲区，当每帧被渲染时，它们将被传递给 OpenGL。这是我们的三角形和简单着色器的第一次尝试；现在我们只需要一个顶点缓冲区：

```kt
        // Allocate buffers
        // initialize vertex byte buffer for shape coordinates (4 bytes per float)
        ByteBuffer bb = ByteBuffer.allocateDirect(triCoords.length * 4);
        // use the device hardware's native byte order
        bb.order(ByteOrder.nativeOrder());

        // create a floating point buffer from the ByteBuffer
        triVerticesBuffer = bb.asFloatBuffer();
        // add the coordinates to the FloatBuffer
        triVerticesBuffer.put(triCoords);
        // set the buffer to read the first coordinate
        triVerticesBuffer.position(0);
```

这五行代码导致了`triVerticesBuffer`值的设置，如下所示：

+   分配一个足够大的`ByteBuffer`，以容纳我们的三角形坐标值。

+   二进制数据被排列以匹配硬件的本机字节顺序

+   为浮点格式化缓冲区，并将其分配给我们的`FloatBuffer`顶点缓冲区

+   三角形数据被放入其中，然后我们将缓冲区光标位置重置到开头

接下来，我们构建 OpenGL ES 程序可执行文件。使用`glCreateProgram`创建一个空的 OpenGL ES 程序，并将其 ID 分配为`triProgram`。这个 ID 也将在其他方法中使用。我们将任何着色器附加到程序中，然后使用`glLinkProgram`构建可执行文件：

```kt
        // Create GL program
        // create empty OpenGL ES Program
        triProgram = GLES20.glCreateProgram();
        // add the vertex shader to program
        GLES20.glAttachShader(triProgram, simpleVertexShader);
        // add the fragment shader to program
        GLES20.glAttachShader(triProgram, simpleFragmentShader);
        // build OpenGL ES program executable
        GLES20.glLinkProgram(triProgram);
        // set program as current
        GLES20.glUseProgram(triProgram);
```

最后，我们获得了渲染管道的句柄。调用`glGetAttribLocation`的`a_Position`检索顶点缓冲区参数的位置，`glEnableVertexAttribArray`允许访问它，并调用`glGetUniformLocation`的`u_Color`检索颜色组件的位置。一旦我们到达`onDrawEye`，我们会很高兴我们这样做了：

```kt
        // Get shader params
        // get handle to vertex shader's a_Position member
        triPositionParam = GLES20.glGetAttribLocation(triProgram, "a_Position");
        // enable a handle to the triangle vertices
        GLES20.glEnableVertexAttribArray(triPositionParam);
        // get handle to fragment shader's u_Color member
        triColorParam = GLES20.glGetUniformLocation(triProgram, "u_Color");
```

因此，我们在这个函数中隔离了准备绘制三角形模型所需的代码。首先，它为顶点设置了缓冲区。然后，它创建了一个 GL 程序，附加了它将使用的着色器。然后，我们获得了在着色器中使用的参数的句柄，用于绘制。

## onDrawEye

*准备，设置和开始！* 如果您认为我们迄今为止所写的内容是“准备就绪”部分，那么现在我们要做“开始”部分！ 也就是说，应用程序启动并创建活动，调用`onCreate`。 创建表面并调用`onSurfaceCreated`来设置缓冲区和着色器。 现在，随着应用程序的运行，每帧都会更新显示。 开始吧！

`CardboardView.StereoRenderer`接口委托这些方法。 我们可以处理`onNewFrame`（稍后会处理）。 现在，我们只需实现`onDrawEye`方法，该方法将从眼睛的角度绘制内容。 此方法将被调用两次，每只眼睛一次。

现在，`onDrawEye`所需要做的就是渲染我们可爱的三角形。 尽管如此，我们将其拆分为一个单独的函数（稍后会有意义）：

```kt
    @Override
    public void onDrawEye(Eye eye) {
        drawTriangle();
    }

    private void drawTriangle() {
        // Add program to OpenGL ES environment
        GLES20.glUseProgram(triProgram);

        // Prepare the coordinate data
        GLES20.glVertexAttribPointer(triPositionParam, COORDS_PER_VERTEX,
                GLES20.GL_FLOAT, false, 0, triVerticesBuffer);

        // Set color for drawing
        GLES20.glUniform4fv(triColorParam, 1, triColor, 0);

        // Draw the model
        GLES20.glDrawArrays(GLES20.GL_TRIANGLES, 0, triVertexCount);
    }
```

我们需要通过调用`glUseProgram`来指定我们使用的着色器程序。 调用`glVertexAttribPointer`将我们的顶点缓冲区设置到管道中。 我们还使用`glUniform4fv`来设置颜色（`4fv`指的是我们的统一变量是一个具有四个浮点数的向量）。 然后，我们使用`glDrawArrays`来实际绘制。

## 构建和运行

就是这样。 *耶哈！* 这并不那么糟糕，是吧？ 实际上，如果您熟悉 Android 开发和 OpenGL，您可能已经轻松完成了这一步。

让我们构建并运行它。 转到**运行** | **运行'app'**，或者只需使用工具栏上的绿色三角形**运行**图标。

Gradle 将执行其构建操作。 选择 Android Studio 窗口底部的**Gradle 控制台**选项卡以查看 Gradle 构建消息。 然后，假设一切顺利，APK 文件将安装在您连接的手机上（连接并打开了，对吧？）。 选择底部的**运行**选项卡以查看上传和启动消息。

这就是它显示的内容：

![构建和运行](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_03_02.jpg)

实际上，它看起来有点像万圣节南瓜雕刻！ *阴森*。 但在 VR 中，您只会看到一个单独的三角形。

请注意，虽然三角形的顶点坐标定义了直线边缘，但`CardboardView`以桶形畸变呈现它，以补偿头盔中的透镜光学。 此外，左图像与右图像不同，每只眼睛一个。 当您将手机插入 Google Cardboard 头盔时，左右立体视图将显示为一个三角形，浮在空间中，边缘笔直。

太棒了！ 我们刚刚从头开始为 Android 构建了一个简单的 Cardboard 应用程序。 与任何 Android 应用程序一样，需要定义许多不同的部分才能使基本功能正常运行，包括`AndroidManifest.xml`，`activity_main.xml`和`MainActivity.java`文件。

希望一切都按计划进行。 像一个好的程序员一样，您可能在进行增量更改后构建和运行应用程序，以解决语法错误和未处理的异常。 稍后，我们将调用 GLError 函数来检查来自 OpenGL 的错误信息。 一如既往，要密切关注 logcat 中的错误（尝试过滤正在运行的应用程序）和变量名称。 您的着色器可能存在语法错误，导致编译失败，或者在尝试访问句柄时，属性/统一名称可能存在拼写错误。 这些问题不会导致任何编译时错误（着色器在运行时编译），并且您的应用程序将运行，但可能不会渲染任何内容。

# 3D 相机，透视和头部旋转

尽管这很棒（*哈哈*），但我们的应用有点无聊，不太像 Cardboard。 具体来说，它是立体的（双视图）并具有透镜畸变，但它还不是 3D 透视视图，也不会随着您的头部移动。 我们现在要修复这个问题。

## 欢迎来到矩阵

在谈论为虚拟现实开发时，我们不能不谈论用于 3D 计算机图形的矩阵数学。

什么是矩阵？答案就在那里，Neo，它正在寻找你，如果你愿意，它会找到你。没错，是时候了解矩阵了。一切都将不同。你的视角即将改变。

我们正在构建一个三维场景。空间中的每个位置由 X、Y 和 Z 坐标描述。场景中的物体可以由 X、Y 和 Z 顶点构成。通过移动、缩放和/或旋转其顶点，可以对物体进行变换。这种变换可以用一个包含 16 个浮点值的矩阵来数学表示（每行四个浮点数）。

矩阵可以通过相乘来组合。例如，如果你有一个表示对象缩放（比例）的矩阵和另一个用于重新定位（平移）的矩阵，那么你可以通过将两者相乘来创建第三个矩阵，表示缩放和重新定位。但是，你不能只使用原始的`*`运算符。另外，需要注意的是，与简单的标量乘法不同，矩阵乘法不是可交换的。换句话说，我们知道*a * b = b * a*。然而，对于矩阵 A 和 B，*AB ≠ BA*！Matrix Android 类库提供了执行矩阵运算的函数。以下是一个例子：

```kt
// allocate the matrix arrays
float scale[] = new float[16];
float translate[] = new float[16];
float scaleAndTranslate[] = new float[16];

// initialize to Identity
Matrix.setIdentityM(scale, 0);
Matrix.setIdentityM(translate, 0);

// scale by 2, move by 5 in Z
Matrix.scaleM(scale, 0, 2.0, 2.0, 2.0);
Matrix.translateM(translate, 0, 0, 0.0, 0.0, 5.0);

// combine them with a matrix multiply
Matrix.multipyMM(scaleAndTranslate, 0, translate, 0, scale, 0);
```

需要注意的是，由于矩阵乘法的工作方式，将向量乘以结果矩阵将产生与首先将其乘以缩放矩阵（右侧）相同的效果，然后将其乘以平移矩阵（左侧）。这与你可能期望的相反。

### 注意

Matrix API 的文档可以在[`developer.android.com/reference/android/opengl/Matrix.html`](http://developer.android.com/reference/android/opengl/Matrix.html)找到。

这些矩阵的东西将被大量使用。值得在这里提到的一点是精度损失。如果你反复缩放和平移组合矩阵，可能会出现与实际值的“漂移”，因为浮点计算由于四舍五入而丢失信息。这不仅是计算机图形的问题，也是银行和比特币挖掘的问题！（还记得电影《办公空间》吗？）

这种矩阵数学的一个基本用途是立即将场景转换为用户视角的屏幕图像（投影）。

在 Cardboard 虚拟现实应用中，为了从特定视角渲染场景，我们考虑一个朝向特定方向的摄像机。摄像机像任何其他物体一样具有 X、Y 和 Z 位置，并旋转到其视角方向。在虚拟现实中，当你转动头部时，Cardboard SDK 读取手机中的运动传感器，确定当前的头部姿势（视角和角度），并给你的应用程序相应的变换矩阵。

事实上，在虚拟现实中，对于每一帧，我们渲染两个稍微不同的透视视图：每只眼睛一个，偏移了实际的眼睛间距（瞳距）。

此外，在虚拟现实中，我们希望使用透视投影（而不是等距投影）来渲染场景，以便靠近你的物体比远处的物体更大。这也可以用 4x4 矩阵来表示。

我们可以将这些变换组合起来，将它们相乘以获得`modelViewProjection`矩阵：

```kt
modelViewProjection = modelTransform X camera  X  eyeView  X  perspectiveProjection
```

完整的`modelViewProjection`（MVP）变换矩阵是任何模型变换（例如，在场景中缩放或定位模型）与摄像机视角和透视投影的组合。

当 OpenGL 开始绘制一个对象时，顶点着色器可以使用`modelViewProjection`矩阵来渲染几何图形。整个场景从用户的视角绘制，朝向他的头部指向，每只眼睛都有透视投影，通过你的 Cardboard 观看器呈现立体效果。虚拟现实 MVP FTW！

## MVP 顶点着色器

我们之前编写的超级简单的顶点着色器并不会变换每个顶点；它只是将它传递到管道的下一步。现在，我们希望它能够具有 3D 感知能力，并使用我们的`modelViewProjection`（MVP）变换矩阵。创建一个着色器来处理它。

在层次结构视图中，右键单击`app/res/raw`文件夹，转到**新建** | **文件**，输入名称`mvp_vertex.shader`，然后单击**确定**。编写以下代码：

```kt
uniform mat4 u_MVP;
attribute vec4 a_Position;
void main() {
   gl_Position = u_MVP * a_Position;
}
```

这个着色器几乎和`simple_vertex`一样，但是通过`u_MVP`矩阵来变换每个顶点。（请注意，虽然在 Java 中用`*`来乘矩阵和向量是不起作用的，但在着色器代码中是可以的！）

将`compleShaders`函数中的着色器资源替换为使用`R.raw.mvp_vertex`：

```kt
simpleVertexShader = loadShader(GLES20.GL_VERTEX_SHADER, R.raw.mvp_vertex)
```

## 设置透视视图矩阵

为了将摄像机和视图添加到我们的场景中，我们定义了一些变量。在`MainActivity.java`文件中，在`MainActivity`类的开头添加以下代码：

```kt
// Viewing variables
private static final float Z_NEAR = 0.1f;
private static final float Z_FAR = 100.0f;
private static final float CAMERA_Z = 0.01f;

private float[] camera;
private float[] view;
private float[] modelViewProjection;

// Rendering variables
private int triMVPMatrixParam;
```

`Z_NEAR`和`Z_FAR`常量定义了后面用于计算摄像机眼睛的透视投影的深度平面。`CAMERA_Z`将是摄像机的位置（例如，在 X=0.0，Y=0.0 和 Z=0.01 处）。

`triMVPMatrixParam`变量将用于在我们改进的着色器中设置模型变换矩阵。

`camera`、`view`和`modelViewProjection`矩阵将是 4x4 矩阵（16 个浮点数的数组），用于透视计算。

在`onCreate`中，我们初始化了`camera`、`view`和`modelViewProjection`矩阵：

```kt
    protected void onCreate(Bundle savedInstanceState) {
        //...

        camera = new float[16];
        view = new float[16];
        modelViewProjection = new float[16];
    }
```

在`prepareRenderingTriangle`中，我们初始化了`triMVPMatrixParam`变量：

```kt
// get handle to shape's transformation matrix
triMVPMatrixParam = GLES20.glGetUniformLocation(triProgram, "u_MVP");
```

### 提示

OpenGL 中的默认摄像机位于原点（0,0,0），并朝向负*Z*轴。换句话说，场景中的物体朝着摄像机的正*Z*轴。为了将它们放在摄像机前面，给它们一个带有一些负 Z 值的位置。

在 3D 图形世界中有一个长期存在的（且毫无意义的）关于哪个轴是上的争论。我们可以在某种程度上都同意*X*轴是左右移动的，但*Y*轴是上下移动的，还是*Z*轴是呢？许多软件选择*Z*作为上下方向，并将*Y*定义为指向屏幕内外。另一方面，Cardboard SDK、Unity、Maya 和许多其他软件选择了相反的方式。如果你把坐标平面想象成在图纸上绘制，那么这取决于你把纸放在哪里。如果你把图形想象成从上面往下看，或者在白板上绘制，那么*Y*就是垂直轴。如果图形放在你面前的桌子上，那么*缺失的* *Z*轴就是垂直的，指向上下。无论如何，Cardboard SDK，因此本书中的项目，将 Z 视为*前后*轴。

## 透视渲染

现在，设置好了，我们现在可以处理每一帧重新绘制屏幕的工作。

首先，设置摄像机位置。它可以像在`onCreate`中那样定义一次。但是，在 VR 应用程序中，场景中的摄像机位置通常会发生变化，因此我们需要在每一帧中重置它。

在新的一帧开始时，首先要做的是重置摄像机矩阵，使其指向一个通用的正面方向。定义`onNewFrame`方法如下：

```kt
    @Override
    public void onNewFrame(HeadTransform headTransform) {
        // Build the camera matrix and apply it to the ModelView.
        Matrix.setLookAtM(camera, 0, 0.0f, 0.0f, CAMERA_Z, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f);
    }
```

### 提示

注意，当你写`Matrix`时，Android Studio 会想要自动导入包。确保你选择的导入是`android.opengl.Matrix`，而不是其他矩阵库，比如`android.graphic.Matrix`。

现在，当需要从每只眼睛的视角绘制场景时，我们会计算透视视图矩阵。修改`onDrawEye`如下：

```kt
    public void onDrawEye(Eye eye) {
        GLES20.glEnable(GLES20.GL_DEPTH_TEST);
        GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT | GLES20.GL_DEPTH_BUFFER_BIT);

        // Apply the eye transformation to the camera
        Matrix.multiplyMM(view, 0, eye.getEyeView(), 0, camera, 0);

        // Get the perspective transformation
        float[] perspective = eye.getPerspective(Z_NEAR, Z_FAR);

        // Apply perspective transformation to the view, and draw
        Matrix.multiplyMM(modelViewProjection, 0, perspective, 0, view, 0);

        drawTriangle();
    }
```

我们添加的前两行重置了 OpenGL 深度缓冲区。当渲染 3D 场景时，除了每个像素的颜色外，OpenGL 还会跟踪占据该像素的对象与眼睛的距离。如果为另一个对象渲染相同的像素，深度缓冲区将知道它是否应该可见（更近）或忽略（更远）。 （或者，也许颜色以某种方式组合在一起，例如透明度）。我们在渲染每只眼睛的任何几何图形之前清除缓冲区。实际上，也清除了屏幕上实际看到的颜色缓冲区。否则，在这种情况下，您最终会用纯色填满整个屏幕。

现在，让我们继续进行查看转换。`onDrawEye`接收当前的`Eye`对象，该对象描述了眼睛的立体渲染细节。特别是，`eye.getEyeView()`方法返回一个包括头部跟踪旋转、位置移动和瞳距移动的变换矩阵。换句话说，眼睛在场景中的位置以及它所看的方向。尽管 Cardboard 不提供位置跟踪，但眼睛的位置会发生变化，以模拟虚拟头部。您的眼睛不会围绕中心轴旋转，而是您的头部围绕颈部旋转，这是眼睛的一定距离。因此，当 Cardboard SDK 检测到方向变化时，两个虚拟摄像头会在场景中移动，就好像它们是实际头部中的实际眼睛一样。

我们需要一个代表该眼睛位置的摄像机透视视图的变换。如前所述，这是如下计算的：

```kt
modelViewProjection = modelTransform  X  camera  X  eyeView  X  perspectiveProjection
```

我们将`camera`乘以眼睛视图变换（`getEyeView`），然后将结果乘以透视投影变换（`getPerspective`）。目前，我们不对三角形模型本身进行变换，而是将`modelTransform`矩阵排除在外。

结果（`modelViewProjection`）被传递给 OpenGL，供渲染管线中的着色器使用（通过`glUniformMatrix4fv`）。然后，我们绘制我们的东西（通过之前写的`glDrawArrays`）。

现在，我们需要将视图矩阵传递给着色器程序。在`drawTriangle`方法中，添加如下内容：

```kt
    private void drawTriangle() {
        // Add program to OpenGL ES environment
        GLES20.glUseProgram(triProgram);

        // Pass the MVP transformation to the shader
        GLES20.glUniformMatrix4fv(triMVPMatrixParam, 1, false, modelViewProjection, 0);

        // . . .
```

## 构建和运行

让我们构建并运行它。转到**运行** | **运行'app'**，或者直接使用工具栏上的绿色三角形**运行**图标。现在，移动手机将改变与您的视图方向同步的显示。将手机插入 Google Cardboard 查看器中，就像 VR 一样（*有点像*）。

请注意，如果您的手机在应用程序启动时平放在桌子上，则我们场景中的摄像头将面向三角形的正下方而不是向前。更糟糕的是，当您拿起手机时，中性方向可能不会正对着您的前方。因此，每次在本书中运行应用程序时，先拿起手机，这样您就可以在 VR 中向前看，或者将手机支撑在位置上（我个人使用的是 Gekkopod，可在[`gekkopod.com/`](http://gekkopod.com/)上购买）。

另外，请确保您的手机在**设置**对话框中未设置为**锁定竖屏**。

# 重新定位三角形

我们的矩阵技术确实让我们走得更远了。

我想把三角形移到一边。我们将通过设置另一个变换矩阵来实现这一点，然后在绘制时将其用于模型。

添加两个名为`triTransform`和`triView`的新矩阵：

```kt
    // Model variables
    private float[] triTransform;

    // Viewing variables
    private float[] triView;
```

在`onCreate`中初始化它们：

```kt
        triTransform = new float[16];
        triView = new float[16];
```

让我们在`initializeScene`方法中设置定位三角形的模型矩阵（由`onSurfaceCreated`调用）。我们将其在 X 轴上偏移 5 个单位，并在 Z 轴上向后偏移 5 个单位。在`initializeScene`中添加以下代码：

```kt
       // Position the triangle
        Matrix.setIdentityM(triTransform, 0);
        Matrix.translateM(triTransform, 0, 5, 0, -5);
```

最后，我们使用模型矩阵在`onDrawEye`中构建`modelViewProjection`矩阵。修改`onDrawEye`如下：

```kt
    public void onDrawEye(Eye eye) {
        ...
        // Apply perspective transformation to the view, and draw
        Matrix.multiplyMM(triView, 0, view, 0, triTransform, 0);
        Matrix.multiplyMM(modelViewProjection, 0, perspective, 0, triView, 0);
        drawTriangle();
    }
```

构建并运行它。现在，您将看到三角形离得更远，偏向一侧。

### 注意

再次总结一下：`modelViewProjection`矩阵是三角形位置变换（`triTransform`）、摄像机位置和方向（`camera`）、基于手机运动传感器的`CardboardView`当前眼睛的视点（`eye.getEyeView`）以及`perspective`投影的组合。这个 MVP 矩阵被传递给顶点着色器，以确定在屏幕上绘制三角形时的实际位置。

# 你好，立方体！

在 3D 空间中漂浮的平面三角形可能很惊人，但与我们接下来要做的事情相比，简直不值一提：一个 3D 立方体！

## 立方体模型数据

为了保持示例简单，三角形只有三个顶点，声明在`MainActivity`类中。现在，我们将引入更复杂的几何形状。我们将把它放在一个名为`Cube`的类中。

好吧，它只是由八个不同的顶点组成的立方体，形成了六个面，对吧？

好吧，GPU 更喜欢渲染三角形而不是四边形，因此将每个面细分为两个三角形；总共有 12 个三角形。要单独定义每个三角形，总共需要 36 个顶点，带有适当的绕组方向，定义我们的模型，如`CUBE_COORDS`中所示。为什么不只定义八个顶点并重用它们？我们稍后会告诉你如何做。

### 注意

请记住，我们始终需要小心顶点的绕组顺序（逆时针），以便每个三角形的可见面朝外。

在 Android Studio 中，在左侧的 Android 项目层次结构窗格中，找到您的 Java 代码文件夹（例如`com.cardbookvr.cardboardbox`）。右键单击它，然后转到**新建** | **Java 类**。然后，设置**名称：Cube**，然后单击**确定**。然后，编辑文件，如下所示（请记住，本书项目的代码可以从出版商网站和书籍的公共 GitHub 存储库中下载）：

```kt
package com.cardbookvr.cardboardbox;

public class Cube {

    public static final float[] CUBE_COORDS = new float[] {
        // Front face
        -1.0f, 1.0f, 1.0f,
        -1.0f, -1.0f, 1.0f,
        1.0f, 1.0f, 1.0f,
        -1.0f, -1.0f, 1.0f,
        1.0f, -1.0f, 1.0f,
        1.0f, 1.0f, 1.0f,

        // Right face
        1.0f, 1.0f, 1.0f,
        1.0f, -1.0f, 1.0f,
        1.0f, 1.0f, -1.0f,
        1.0f, -1.0f, 1.0f,
        1.0f, -1.0f, -1.0f,
        1.0f, 1.0f, -1.0f,

        // Back face
        1.0f, 1.0f, -1.0f,
        1.0f, -1.0f, -1.0f,
        -1.0f, 1.0f, -1.0f,
        1.0f, -1.0f, -1.0f,
        -1.0f, -1.0f, -1.0f,
        -1.0f, 1.0f, -1.0f,

        // Left face
        -1.0f, 1.0f, -1.0f,
        -1.0f, -1.0f, -1.0f,
        -1.0f, 1.0f, 1.0f,
        -1.0f, -1.0f, -1.0f,
        -1.0f, -1.0f, 1.0f,
        -1.0f, 1.0f, 1.0f,

        // Top face
        -1.0f, 1.0f, -1.0f,
        -1.0f, 1.0f, 1.0f,
        1.0f, 1.0f, -1.0f,
        -1.0f, 1.0f, 1.0f,
        1.0f, 1.0f, 1.0f,
        1.0f, 1.0f, -1.0f,

        // Bottom face
        1.0f, -1.0f, -1.0f,
        1.0f, -1.0f, 1.0f,
        -1.0f, -1.0f, -1.0f,
        1.0f, -1.0f, 1.0f,
        -1.0f, -1.0f, 1.0f,
        -1.0f, -1.0f, -1.0f,
    };
}
```

## 立方体代码

返回`MainActivity`文件，我们将只是复制/粘贴/编辑三角形代码，并将其重用于立方体。显然，这并不理想，一旦我们看到一个好的模式，我们可以将其中一些抽象出来成为可重用的方法。此外，我们将使用与三角形相同的着色器，然后在下一节中，我们将用更好的光照模型替换它们。也就是说，我们将实现光照或 2D 艺术家可能称之为**着色**的东西，这是我们到目前为止还没有做的。

与三角形一样，我们声明了一堆我们将需要的变量。顶点数显然应该来自新的`Cube.CUBE_COORDS`数组：

```kt
    // Model variables
    private static float cubeCoords[] = Cube.CUBE_COORDS;
    private final int cubeVertexCount = cubeCoords.length / COORDS_PER_VERTEX;
    private float cubeColor[] = { 0.8f, 0.6f, 0.2f, 0.0f }; // yellow-ish
    private float[] cubeTransform;
    private float cubeDistance = 5f;

    // Viewing variables
    private float[] cubeView;

    // Rendering variables
    private FloatBuffer cubeVerticesBuffer;
    private int cubeProgram;
    private int cubePositionParam;
    private int cubeColorParam;
    private int cubeMVPMatrixParam;
```

将以下代码添加到`onCreate`中：

```kt
        cubeTransform = new float[16];
        cubeView = new float[16];
```

将以下代码添加到`onSurfaceCreated`中：

```kt
        prepareRenderingCube();
```

编写`prepareRenderingCube`方法，如下所示：

```kt
private void prepareRenderingCube() {
        // Allocate buffers
        ByteBuffer bb = ByteBuffer.allocateDirect(cubeCoords.length * 4);
        bb.order(ByteOrder.nativeOrder());
        cubeVerticesBuffer = bb.asFloatBuffer();
        cubeVerticesBuffer.put(cubeCoords);
        cubeVerticesBuffer.position(0);

        // Create GL program
        cubeProgram = GLES20.glCreateProgram();
        GLES20.glAttachShader(cubeProgram, simpleVertexShader);
        GLES20.glAttachShader(cubeProgram, simpleFragmentShader);
        GLES20.glLinkProgram(cubeProgram);
        GLES20.glUseProgram(cubeProgram);

        // Get shader params
        cubePositionParam = GLES20.glGetAttribLocation(cubeProgram, "a_Position");
        cubeColorParam = GLES20.glGetUniformLocation(cubeProgram, "u_Color");
        cubeMVPMatrixParam = GLES20.glGetUniformLocation(cubeProgram, "u_MVP");

        // Enable arrays
        GLES20.glEnableVertexAttribArray(cubePositionParam);
    }
```

我们将把立方体定位在 5 个单位之外，并在对角轴（1,1,0）上旋转 30 度。没有旋转，我们只会看到正面的正方形。将以下代码添加到`initializeScene`中：

```kt
        // Rotate and position the cube
        Matrix.setIdentityM(cubeTransform, 0);
        Matrix.translateM(cubeTransform, 0, 0, 0, -cubeDistance);
        Matrix.rotateM(cubeTransform, 0, 30, 1, 1, 0);
```

将以下代码添加到`onDrawEye`中以计算 MVP 矩阵，包括`cubeTransform`矩阵，然后绘制立方体：

```kt
        Matrix.multiplyMM(cubeView, 0, view, 0, cubeTransform, 0);
        Matrix.multiplyMM(modelViewProjection, 0, perspective, 0, cubeView, 0);
        drawCube();
```

编写`drawCube`方法，它与`drawTri`方法非常相似，如下所示：

```kt
    private void drawCube() {
        GLES20.glUseProgram(cubeProgram);
        GLES20.glUniformMatrix4fv(cubeMVPMatrixParam, 1, false, modelViewProjection, 0);
        GLES20.glVertexAttribPointer(cubePositionParam, COORDS_PER_VERTEX,
                GLES20.GL_FLOAT, false, 0, cubeVerticesBuffer);
        GLES20.glUniform4fv(cubeColorParam, 1, cubeColor, 0);
        GLES20.glDrawArrays(GLES20.GL_TRIANGLES, 0, cubeVertexCount);
    }
```

构建并运行它。现在您将看到立方体的 3D 视图，如下截图所示。它需要着色。

![Cube code](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_03_03.jpg)

# 光照和着色

我们需要在场景中引入光源并提供一个将使用它的着色器。为此，立方体需要额外的数据，定义每个顶点的法向量和颜色。

### 注意

顶点颜色并不总是需要用于着色，但在我们的情况下，渐变非常微妙，不同颜色的面将帮助您区分立方体的边缘。我们还将在顶点着色器中进行着色计算，这是一种更快的方法（顶点比光栅像素少），但对于球体等光滑对象效果不佳。要进行顶点光照，您需要在管道中使用顶点颜色，因此对这些颜色做点什么也是有意义的。在这种情况下，我们选择立方体的每个面使用不同的颜色。在本书的后面，您将看到像素级光照的示例以及它带来的差异。

现在我们将构建应用程序来处理我们的光照立方体。我们将通过执行以下步骤来完成：

+   编写并编译用于光照的新着色器

+   生成和定义立方体顶点法线矢量和颜色

+   为渲染分配和设置数据缓冲区

+   定义和设置用于渲染的光源

+   生成和设置用于渲染的变换矩阵

## 添加着色器

让我们编写一个增强的顶点着色器，可以使用模型的光源和顶点法线。

在项目层次结构中的`app/res/raw`文件夹上右键单击，转到**新建** | **文件**，并命名为`light_vertex.shader`。添加以下代码：

```kt
uniform mat4 u_MVP;
uniform mat4 u_MVMatrix;
uniform vec3 u_LightPos;

attribute vec4 a_Position;
attribute vec4 a_Color;
attribute vec3 a_Normal;

const float ONE = 1.0;
const float COEFF = 0.00001;

varying vec4 v_Color;

void main() {
   vec3 modelViewVertex = vec3(u_MVMatrix * a_Position);
   vec3 modelViewNormal = vec3(u_MVMatrix * vec4(a_Normal, 0.0));

   float distance = length(u_LightPos - modelViewVertex);
   vec3 lightVector = normalize(u_LightPos - modelViewVertex);
   float diffuse = max(dot(modelViewNormal, lightVector), 0.5);

   diffuse = diffuse * (ONE / (ONE + (COEFF * distance * distance)));
   v_Color = a_Color * diffuse;
   gl_Position = u_MVP * a_Position;
}
```

不要详细介绍编写光照着色器的细节，您可以看到顶点颜色是根据与光线和表面之间的角度以及光源与顶点之间的距离相关的公式计算的。请注意，我们还引入了`ModelView`矩阵以及 MVP 矩阵。这意味着您需要访问流程的两个步骤，并且在完成后不能覆盖/丢弃 MV 矩阵。

请注意，我们使用了一个小优化。数字文字（例如，`1.0`）使用统一空间，在某些硬件上可能会导致问题，因此我们改为声明常量（参考[`stackoverflow.com/questions/13963765/declaring-constants-instead-of-literals-in-vertex-shader-standard-practice-or`](http://stackoverflow.com/questions/13963765/declaring-constants-instead-of-literals-in-vertex-shader-standard-practice-or)）。

与早期简单着色器相比，此着色器中要设置的变量更多，用于光照计算。我们将把这些发送到绘制方法中。

我们还需要一个略有不同的片段着色器。在项目层次结构中的`raw`文件夹上右键单击，转到**新建** | **文件**，并命名为`passthrough_fragment.shader`。添加以下代码：

```kt
precision mediump float;
varying vec4 v_Color;

void main() {
    gl_FragColor = v_Color;
}
```

片段着色器与简单着色器的唯一区别在于，我们用 varying `vec4 v_Color`替换了 uniform `vec4 u_Color`，因为颜色现在是从管道中的顶点着色器传递的。现在顶点着色器获得了一个颜色数组缓冲区。这是我们需要在设置/绘制代码中解决的新问题。

然后，在`MainActivity`中添加这些变量：

```kt
    // Rendering variables
    private int lightVertexShader;
    private int passthroughFragmentShader;
```

在`compileShaders`方法中编译着色器：

```kt
        lightVertexShader = loadShader(GLES20.GL_VERTEX_SHADER,
                R.raw.light_vertex);
        passthroughFragmentShader = loadShader(GLES20.GL_FRAGMENT_SHADER,
                R.raw.passthrough_fragment);
```

## 立方体法线和颜色

立方体的每个面朝向不同的方向，与面垂直。矢量是 XYZ 坐标。将其归一化为长度为 1 的矢量可用于指示此方向，并称为**法向量**。

我们传递给 OpenGL 的几何图形是由顶点定义的，而不是面。因此，我们需要为面的每个顶点提供一个法向量，如下图所示。严格来说，并非给定面上的所有顶点都必须面向同一方向。这在一种称为**平滑着色**的技术中使用，其中光照计算给出了曲面的错觉，而不是平面的错觉。我们将对每个面使用相同的法线（**硬边缘**），这也节省了我们在指定法线数据时的时间。我们的数组只需要指定六个矢量，可以扩展为 36 个法向量的缓冲区。颜色值也是如此。

![立方体法线和颜色](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_03_04.jpg)

每个顶点也有一个颜色。假设立方体的每个面都是一个实色，我们可以将该面的每个顶点分配相同的颜色。在`Cube.java`文件中，添加以下代码：

```kt
    public static final float[] CUBE_COLORS_FACES = new float[] {
        // Front, green
        0f, 0.53f, 0.27f, 1.0f,
        // Right, blue
        0.0f, 0.34f, 0.90f, 1.0f,
        // Back, also green
        0f, 0.53f, 0.27f, 1.0f,
        // Left, also blue
        0.0f, 0.34f, 0.90f, 1.0f,
        // Top, red
        0.84f,  0.18f,  0.13f, 1.0f,
        // Bottom, also red
        0.84f,  0.18f,  0.13f, 1.0f,
    };

    public static final float[] CUBE_NORMALS_FACES = new float[] {
        // Front face
        0.0f, 0.0f, 1.0f,
        // Right face
        1.0f, 0.0f, 0.0f,
        // Back face
        0.0f, 0.0f, -1.0f,
        // Left face
        -1.0f, 0.0f, 0.0f,
        // Top face
        0.0f, 1.0f, 0.0f,
        // Bottom face
        0.0f, -1.0f, 0.0f,
    };
```

对于立方体的每个面，我们定义了一个实色（`CUBE_COLORS_FACES`）和一个法向量（`CUBE_NORMALS_FACES`）。

现在，编写一个可重复使用的方法`cubeFacesToArray`，以生成`MainActivity`中实际需要的浮点数组。将以下代码添加到您的`Cube`类中：

```kt
    /**
     * Utility method for generating float arrays for cube faces
     *
     * @param model - float[] array of values per face.
     * @param coords_per_vertex - int number of coordinates per vertex.
     * @return - Returns float array of coordinates for triangulated cube faces.
     *               6 faces X 6 points X coords_per_vertex
     */
    public static float[] cubeFacesToArray(float[] model, int coords_per_vertex) {
        float coords[] = new float[6 * 6 * coords_per_vertex];
        int index = 0;
        for (int iFace=0; iFace < 6; iFace++) {
            for (int iVertex=0; iVertex < 6; iVertex++) {
                for (int iCoord=0; iCoord < coords_per_vertex; iCoord++) {
                    coords[index] = model[iFace*coords_per_vertex + iCoord];
                    index++;
                }
            }
        }
        return coords;
    }
```

将这些数据添加到`MainActivity`中的其他变量中，如下所示：

```kt
    // Model variables
    private static float cubeCoords[] = Cube.CUBE_COORDS;
    private static float cubeColors[] = Cube.cubeFacesToArray(Cube.CUBE_COLORS_FACES, 4);
    private static float cubeNormals[] = Cube.cubeFacesToArray(Cube.CUBE_NORMALS_FACES, 3);
```

您还可以删除`private float cubeColor[]`的声明，因为现在不再需要它。

有了法向量和颜色，着色器可以计算对象占据的每个像素的值。

## 准备顶点缓冲区

渲染管道要求我们为顶点、法向量和颜色设置内存缓冲区。我们已经有了顶点缓冲区，现在需要添加其他缓冲区。

添加变量，如下所示：

```kt
    // Rendering variables
    private FloatBuffer cubeVerticesBuffer;
    private FloatBuffer cubeColorsBuffer;
    private FloatBuffer cubeNormalsBuffer;
```

准备缓冲区，并将以下代码添加到`prepareRenderingCube`方法（从`onSurfaceCreated`调用）。 （这是完整的`prepareRenderingCube`方法的前半部分）：

```kt
    private void prepareRenderingCube() {
        // Allocate buffers
        ByteBuffer bb = ByteBuffer.allocateDirect(cubeCoords.length * 4);
        bb.order(ByteOrder.nativeOrder());
        cubeVerticesBuffer = bb.asFloatBuffer();
        cubeVerticesBuffer.put(cubeCoords);
        cubeVerticesBuffer.position(0);

        ByteBuffer bbColors = ByteBuffer.allocateDirect(cubeColors.length * 4);
 bbColors.order(ByteOrder.nativeOrder());
 cubeColorsBuffer = bbColors.asFloatBuffer();
 cubeColorsBuffer.put(cubeColors);
 cubeColorsBuffer.position(0);

 ByteBuffer bbNormals = ByteBuffer.allocateDirect(cubeNormals.length * 4);
 bbNormals.order(ByteOrder.nativeOrder());
 cubeNormalsBuffer = bbNormals.asFloatBuffer();
 cubeNormalsBuffer.put(cubeNormalParam);
 cubeNormalsBuffer.position(0);

        // Create GL program
```

## 准备着色器

已经定义了`lighting_vertex`着色器，我们需要添加参数句柄来使用它。在`MainActivity`类的顶部，添加四个变量到光照着色器参数：

```kt
    // Rendering variables
    private int cubeNormalParam;
    private int cubeModelViewParam;
    private int cubeLightPosParam;
```

在`prepareRenderingCube`方法中（由`onSurfaceCreated`调用），附加`lightVertexShader`和`passthroughFragmentShader`着色器，而不是简单的着色器，获取着色器参数，并启用数组，使其现在读取如下。（这是`prepareRenderingCube`的后半部分，从前一节继续）：

```kt
        // Create GL program
        cubeProgram = GLES20.glCreateProgram();
        GLES20.glAttachShader(cubeProgram, lightVertexShader);
        GLES20.glAttachShader(cubeProgram, passthroughFragmentShader);
        GLES20.glLinkProgram(cubeProgram);
        GLES20.glUseProgram(cubeProgram);

        // Get shader params
        cubeModelViewParam = GLES20.glGetUniformLocation(cubeProgram, "u_MVMatrix");
        cubeMVPMatrixParam = GLES20.glGetUniformLocation(cubeProgram, "u_MVP");
        cubeLightPosParam = GLES20.glGetUniformLocation(cubeProgram, "u_LightPos");

        cubePositionParam = GLES20.glGetAttribLocation(cubeProgram, "a_Position");
        cubeNormalParam = GLES20.glGetAttribLocation(cubeProgram, "a_Normal");
 cubeColorParam = GLES20.glGetAttribLocation(cubeProgram, "a_Color");

        // Enable arrays
        GLES20.glEnableVertexAttribArray(cubePositionParam);
        GLES20.glEnableVertexAttribArray(cubeNormalParam);
 GLES20.glEnableVertexAttribArray(cubeColorParam);

```

如果您参考我们之前编写的着色器代码，您会注意到这些对`glGetUniformLocation`和`glGetAttribLocation`的调用对应于那些脚本中声明的`uniform`和`attribute`参数，包括`cubeColorParam`从`u_Color`到现在的`a_Color`的更改。OpenGL 不需要这种重命名，但它有助于我们区分顶点属性和统一性。

引用数组缓冲区的着色器属性必须启用。

## 添加光源

接下来，我们将在场景中添加一个光源，并在绘制时告诉着色器它的位置。光源将被放置在用户的正上方。

在`MainActivity`的顶部，添加光源位置的变量：

```kt
    // Scene variables
    // light positioned just above the user
    private static final float[] LIGHT_POS_IN_WORLD_SPACE = new float[] { 0.0f, 2.0f, 0.0f, 1.0f };
    private final float[] lightPosInEyeSpace = new float[4];
```

通过添加以下代码到`onDrawEye`来计算光的位置：

```kt
        // Apply the eye transformation to the camera
        Matrix.multiplyMM(view, 0, eye.getEyeView(), 0, camera, 0);

        // Calculate position of the light
        Matrix.multiplyMV(lightPosInEyeSpace, 0, view, 0, LIGHT_POS_IN_WORLD_SPACE, 0);
```

请注意，我们使用`view`矩阵（眼睛`view *` `camera`）使用`Matrix.multiplyMV`函数将光的位置转换为当前视图空间。

现在，我们只需告诉着色器光源的位置和它所需的视图矩阵。修改`drawCube`方法（由`onDrawEye`调用），如下所示：

```kt
    private void drawCube() {
        GLES20.glUseProgram(cubeProgram);

        // Set the light position in the shader
 GLES20.glUniform3fv(cubeLightPosParam, 1, lightPosInEyeSpace, 0);

        // Set the ModelView in the shader, used to calculate lighting
 GLES20.glUniformMatrix4fv(cubeModelViewParam, 1, false, cubeView, 0);

        GLES20.glUniformMatrix4fv(cubeMVPMatrixParam, 1, false, modelViewProjection, 0);

        GLES20.glVertexAttribPointer(cubePositionParam, COORDS_PER_VERTEX,
                GLES20.GL_FLOAT, false, 0, cubeVerticesBuffer);
        GLES20.glVertexAttribPointer(cubeNormalParam, 3, GLES20.GL_FLOAT, false, 0,
 cubeNormalsBuffer);
 GLES20.glVertexAttribPointer(cubeColorParam, 4, GLES20.GL_FLOAT, false, 0,
 cubeColorsBuffer);

        GLES20.glDrawArrays(GLES20.GL_TRIANGLES, 0, cubeVertexCount);
    }
```

## 构建和运行应用程序

我们现在准备好了。构建并运行应用程序时，您将看到类似以下截图的屏幕：

！[构建和运行应用程序]（img/B05144_03_05.jpg）

# 旋转立方体

下一步很快。让我们让立方体旋转。这是通过在每帧中稍微旋转`cubeTransform`矩阵来实现的。我们可以为此定义一个`TIME_DELTA`值。添加静态变量，如下所示：

```kt
    // Viewing variables
    private static final float TIME_DELTA = 0.3f;
```

然后，修改每帧的`cubeTransform`，并将以下代码添加到`onNewFrame`方法：

```kt
Matrix.rotateM(cubeTransform, 0, TIME_DELTA, 0.5f, 0.5f, 1.0f);
```

`Matrix.rotateM`函数根据角度和轴向量对变换矩阵应用旋转。在这种情况下，我们围绕轴向量（0.5,0.5,1）旋转`TIME_DELTA`的角度。严格来说，您应该提供一个归一化的轴，但重要的是向量的方向而不是大小。

构建并运行它。现在立方体正在旋转。*令人惊叹！*

# 你好，地板！

在虚拟现实中，有一种脚踏实地的感觉可能很重要。感觉像站着（或坐着）要比像一个无身体的眼球漂浮在空间中更舒服得多。因此，让我们在场景中添加一个地板。

现在这应该更加熟悉了。我们将有一个类似于立方体的着色器、模型和渲染管道。所以，我们将不做太多解释，就这样做吧。

## 着色器

地板将使用我们的`light_shader`进行一些小修改和一个新的片段着色器。

通过添加`v_Grid`变量来修改`light_vertex.shader`，如下所示：

```kt
uniform mat4 u_Model;
uniform mat4 u_MVP;
uniform mat4 u_MVMatrix;
uniform vec3 u_LightPos;

attribute vec4 a_Position;
attribute vec4 a_Color;
attribute vec3 a_Normal;

varying vec4 v_Color;
varying vec3 v_Grid;

const float ONE = 1.0;
const float COEFF = 0.00001;

void main() {
 v_Grid = vec3(u_Model * a_Position);

    vec3 modelViewVertex = vec3(u_MVMatrix * a_Position);
    vec3 modelViewNormal = vec3(u_MVMatrix * vec4(a_Normal, 0.0));

    float distance = length(u_LightPos - modelViewVertex);
    vec3 lightVector = normalize(u_LightPos - modelViewVertex);
    float diffuse = max(dot(modelViewNormal, lightVector), 0.5);

    diffuse = diffuse * (ONE / (ONE + (COEFF * distance * distance)));
    v_Color = a_Color * diffuse;
    gl_Position = u_MVP * a_Position;
}
```

在`app/res/raw`中创建一个名为`grid_fragment.shader`的新着色器，如下所示：

```kt
precision mediump float;
varying vec4 v_Color;
varying vec3 v_Grid;

void main() {
    float depth = gl_FragCoord.z / gl_FragCoord.w; // Calculate world-space distance.

    if ((mod(abs(v_Grid.x), 10.0) < 0.1) || (mod(abs(v_Grid.z), 10.0) < 0.1)) {
        gl_FragColor = max(0.0, (90.0-depth) / 90.0) * vec4(1.0, 1.0, 1.0, 1.0)
                + min(1.0, depth / 90.0) * v_Color;
    } else {
        gl_FragColor = v_Color;
    }
}
```

这可能看起来很复杂，但我们所做的只是在一个纯色着色器上绘制一些网格线。`if`语句将检测我们是否在 10 的倍数的 0.1 单位内。如果是，我们将绘制一个颜色，介于白色（1,1,1,1）和`v_Color`之间，根据该像素的深度或其与相机的距离。`gl_FragCoord`是一个内置值，它给出了我们在窗口空间中渲染的像素的位置，以及深度缓冲区（`z`）中的值，该值将在范围[0,1]内。第四个参数`w`本质上是相机绘制距离的倒数，当与深度值结合时，给出了像素的世界空间深度。`v_Grid`变量实际上已经让我们根据顶点着色器中引入的本地顶点位置和模型矩阵，访问了当前像素的世界空间位置。

在`MainActivity`中，添加一个新的片段着色器变量：

```kt
    // Rendering variables
    private int gridFragmentShader;
```

在`compileShaders`方法中编译着色器，如下所示：

```kt
        gridFragmentShader = loadShader(GLES20.GL_FRAGMENT_SHADER,
                R.raw.grid_fragment);
```

## 地板模型数据

在项目中创建一个名为`Floor`的新的 Java 文件。添加地板平面坐标、法线和颜色：

```kt
    public static final float[] FLOOR_COORDS = new float[] {
        200f, 0, -200f,
        -200f, 0, -200f,
        -200f, 0, 200f,
        200f, 0, -200f,
        -200f, 0, 200f,
        200f, 0, 200f,
    };

    public static final float[] FLOOR_NORMALS = new float[] {
        0.0f, 1.0f, 0.0f,
        0.0f, 1.0f, 0.0f,
        0.0f, 1.0f, 0.0f,
        0.0f, 1.0f, 0.0f,
        0.0f, 1.0f, 0.0f,
        0.0f, 1.0f, 0.0f,
    };

    public static final float[] FLOOR_COLORS = new float[] {
            0.0f, 0.34f, 0.90f, 1.0f,
            0.0f, 0.34f, 0.90f, 1.0f,
            0.0f, 0.34f, 0.90f, 1.0f,
            0.0f, 0.34f, 0.90f, 1.0f,
            0.0f, 0.34f, 0.90f, 1.0f,
            0.0f, 0.34f, 0.90f, 1.0f,
    };
```

## 变量

将我们需要的所有变量添加到`MainActivity`中：

```kt
    // Model variables
    private static float floorCoords[] = Floor.FLOOR_COORDS;
    private static float floorColors[] = Floor.FLOOR_COLORS;
    private static float floorNormals[] = Floor.FLOOR_NORMALS;
    private final int floorVertexCount = floorCoords.length / COORDS_PER_VERTEX;
    private float[] floorTransform;
    private float floorDepth = 20f;

    // Viewing variables
    private float[] floorView;

    // Rendering variables
    private int gridFragmentShader;

    private FloatBuffer floorVerticesBuffer;
    private FloatBuffer floorColorsBuffer;
    private FloatBuffer floorNormalsBuffer;
    private int floorProgram;
    private int floorPositionParam;
    private int floorColorParam;
    private int floorMVPMatrixParam;
    private int floorNormalParam;
    private int floorModelParam;
    private int floorModelViewParam;
    private int floorLightPosParam;
```

## onCreate

在`onCreate`中分配矩阵：

```kt
        floorTransform = new float[16];
        floorView = new float[16];
```

## onSurfaceCreated

在`onSufraceCreated`中添加对`prepareRenderingFloor`的调用，我们将其编写如下：

```kt
        prepareRenderingFloor();
```

## initializeScene

在`initializeScene`方法中设置`floorTransform`矩阵：

```kt
        // Position the floor
        Matrix.setIdentityM(floorTransform, 0);
        Matrix.translateM(floorTransform, 0, 0, -floorDepth, 0);
```

## prepareRenderingFloor

这是完整的`prepareRenderingFloor`方法：

```kt
    private void prepareRenderingFloor() {
        // Allocate buffers
        ByteBuffer bb = ByteBuffer.allocateDirect(floorCoords.length * 4);
        bb.order(ByteOrder.nativeOrder());
        floorVerticesBuffer = bb.asFloatBuffer();
        floorVerticesBuffer.put(floorCoords);
        floorVerticesBuffer.position(0);

        ByteBuffer bbColors = ByteBuffer.allocateDirect(floorColors.length * 4);
        bbColors.order(ByteOrder.nativeOrder());
        floorColorsBuffer = bbColors.asFloatBuffer();
        floorColorsBuffer.put(floorColors);
        floorColorsBuffer.position(0);

        ByteBuffer bbNormals = ByteBuffer.allocateDirect(floorNormals.length * 4);
        bbNormals.order(ByteOrder.nativeOrder());
        floorNormalsBuffer = bbNormals.asFloatBuffer();
        floorNormalsBuffer.put(floorNormals);
        floorNormalsBuffer.position(0);

        // Create GL program
        floorProgram = GLES20.glCreateProgram();
        GLES20.glAttachShader(floorProgram, lightVertexShader);
        GLES20.glAttachShader(floorProgram, gridFragmentShader);
        GLES20.glLinkProgram(floorProgram);
        GLES20.glUseProgram(floorProgram);

        // Get shader params
        floorPositionParam = GLES20.glGetAttribLocation(floorProgram, "a_Position");
        floorNormalParam = GLES20.glGetAttribLocation(floorProgram, "a_Normal");
        floorColorParam = GLES20.glGetAttribLocation(floorProgram, "a_Color");

        floorModelParam = GLES20.glGetUniformLocation(floorProgram, "u_Model");
        floorModelViewParam = GLES20.glGetUniformLocation(floorProgram, "u_MVMatrix");
        floorMVPMatrixParam = GLES20.glGetUniformLocation(floorProgram, "u_MVP");
        floorLightPosParam = GLES20.glGetUniformLocation(floorProgram, "u_LightPos");

        // Enable arrays
        GLES20.glEnableVertexAttribArray(floorPositionParam);
        GLES20.glEnableVertexAttribArray(floorNormalParam);
        GLES20.glEnableVertexAttribArray(floorColorParam);
    }
```

## onDrawEye

在`onDrawEye`中计算 MVP 并绘制地板：

```kt
        Matrix.multiplyMM(floorView, 0, view, 0, floorTransform, 0);
        Matrix.multiplyMM(modelViewProjection, 0, perspective, 0, floorView, 0);
        drawFloor();
```

## 绘制地板

定义一个`drawFloor`方法，如下所示：

```kt
    private void drawFloor() {
        GLES20.glUseProgram(floorProgram);
        GLES20.glUniform3fv(floorLightPosParam, 1, lightPosInEyeSpace, 0);
        GLES20.glUniformMatrix4fv(floorModelParam, 1, false, floorTransform, 0);
        GLES20.glUniformMatrix4fv(floorModelViewParam, 1, false, floorView, 0);
        GLES20.glUniformMatrix4fv(floorMVPMatrixParam, 1, false, modelViewProjection, 0);
        GLES20.glVertexAttribPointer(floorPositionParam, COORDS_PER_VERTEX,
                GLES20.GL_FLOAT, false, 0, floorVerticesBuffer);
        GLES20.glVertexAttribPointer(floorNormalParam, 3, GLES20.GL_FLOAT, false, 0,
                floorNormalsBuffer);
        GLES20.glVertexAttribPointer(floorColorParam, 4, GLES20.GL_FLOAT, false, 0,
                floorColorsBuffer);
        GLES20.glDrawArrays(GLES20.GL_TRIANGLES, 0, floorVertexCount);
    }
```

构建并运行它。现在它看起来像以下的截图：

![drawFloor](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_03_06.jpg)

*哇！*

# 嘿，看这个！

在项目的最后部分，我们添加了一个功能，当您看着一个物体（立方体）时，它会用不同的颜色进行高亮显示。

这是通过`CardboardView`接口方法`onNewFrame`来实现的，该方法传递当前头部变换信息。

## isLookingAtObject 方法

让我们从最有趣的部分开始。我们将从 Google 的寻宝演示中借用`isLookingAtObject`方法。它通过计算对象在眼睛空间中的位置来检查用户是否正在看着一个对象，并在用户看着对象时返回 true。在`MainActivity`中添加以下代码：

```kt
/**
     * Check if user is looking at object by calculating where the object is in eye-space.
     *
     * @return true if the user is looking at the object.
     */
    private boolean isLookingAtObject(float[] modelView, float[] modelTransform) {
        float[] initVec = { 0, 0, 0, 1.0f };
        float[] objPositionVec = new float[4];

        // Convert object space to camera space. Use the headView from onNewFrame.
        Matrix.multiplyMM(modelView, 0, headView, 0, modelTransform, 0);
        Matrix.multiplyMV(objPositionVec, 0, modelView, 0, initVec, 0);

        float pitch = (float) Math.atan2(objPositionVec[1], -objPositionVec[2]);
        float yaw = (float) Math.atan2(objPositionVec[0], -objPositionVec[2]);

        return Math.abs(pitch) < PITCH_LIMIT && Math.abs(yaw) < YAW_LIMIT;
    }
```

该方法接受两个参数：我们要测试的对象的`modelView`和`modelTransform`变换矩阵。它还引用了`headView`类变量，我们将在`onNewFrame`中设置。

一个更精确的方法是从相机向场景中的方向发射一条射线，并确定它是否与场景中的任何几何体相交。这将非常有效，但也非常消耗计算资源。

相反，这个函数采用了更简单的方法，甚至不使用对象的几何形状。它使用对象的视图变换来确定对象距离屏幕中心有多远，并测试该向量的角度是否在一个狭窄的范围内（`PITCH_LIMIT`和`YAW_LIMIT`）。*是的，我知道，人们获得博士学位来想出这些东西！*

让我们按照以下方式定义我们需要的变量：

```kt
    // Viewing variables
    private static final float YAW_LIMIT = 0.12f;
    private static final float PITCH_LIMIT = 0.12f;

    private float[] headView;
```

在`onCreate`中分配`headView`：

```kt
        headView = new float[16];
```

在每一帧新的`headView`值。在`onNewFrame`中添加以下代码：

```kt
        headTransform.getHeadView(headView, 0);
```

然后，修改`drawCube`以检查用户是否正在看着立方体，并决定使用哪种颜色：

```kt
        if (isLookingAtObject(cubeView, cubeTransform)) {
            GLES20.glVertexAttribPointer(cubeColorParam, 4, GLES20.GL_FLOAT, false, 0,
                    cubeFoundColorsBuffer);
        } else {
            GLES20.glVertexAttribPointer(cubeColorParam, 4, GLES20.GL_FLOAT, false, 0,
                    cubeColorsBuffer);
        }
```

*就是这样！*除了一个（微小的）细节：我们需要第二组顶点颜色用于突出显示模式。我们将通过使用相同的黄色绘制所有面来突出显示立方体。为了实现这一点，需要进行一些更改。

在`Cube`中，添加以下 RGBA 值：

```kt
    public static final float[] CUBE_FOUND_COLORS_FACES = new float[] {
        // Same yellow for front, right, back, left, top, bottom faces
        1.0f,  0.65f, 0.0f, 1.0f,
        1.0f,  0.65f, 0.0f, 1.0f,
        1.0f,  0.65f, 0.0f, 1.0f,
        1.0f,  0.65f, 0.0f, 1.0f,
        1.0f,  0.65f, 0.0f, 1.0f,
        1.0f,  0.65f, 0.0f, 1.0f,
    };
```

在`MainActivity`中，添加这些变量：

```kt
    // Model variables
    private static float cubeFoundColors[] = Cube.cubeFacesToArray(Cube.CUBE_FOUND_COLORS_FACES, 4);

    // Rendering variables
    private FloatBuffer cubeFoundColorsBuffer;
```

将以下代码添加到`prepareRenderingCube`方法中：

```kt
        ByteBuffer bbFoundColors = ByteBuffer.allocateDirect(cubeFoundColors.length * 4);
        bbFoundColors.order(ByteOrder.nativeOrder());
        cubeFoundColorsBuffer = bbFoundColors.asFloatBuffer();
        cubeFoundColorsBuffer.put(cubeFoundColors);
        cubeFoundColorsBuffer.position(0);
```

构建并运行它。当你直接看着立方体时，它会被突出显示。

### 提示

如果立方体不那么接近，可能会更有趣和具有挑战性。尝试将`cubeDistance`设置为*12f*。

就像寻宝演示一样，尝试每次看着它时设置一个新的随机立方体位置。现在，你有了一个游戏！

# 摘要

在本章中，我们从头开始构建了一个 Cardboard Android 应用，从一个新项目开始，逐渐添加 Java 代码。在我们的第一个构建中，我们有一个三角形的立体视图，你可以在 Google Cardboard 头盔中看到。

然后我们添加了模型变换、3D 摄像机视图、透视和头部旋转变换，并讨论了一些关于矩阵数学的内容。我们建立了一个立方体的 3D 模型，然后创建了着色器程序，使用光源来渲染带有阴影的立方体。我们还为立方体添加了动画，并添加了一个地板网格。最后，我们添加了一个功能，当用户看着立方体时，它会被突出显示。

在这个过程中，我们享受了关于 3D 几何、OpenGL、着色器、用于渲染管线的几何法线和数据缓冲区的良好讨论。我们还开始思考如何将代码中的常见模式抽象为可重用的方法。

在下一章中，我们将采用不同的方法来使用 Android 布局视图进行立体渲染，构建一个有用的“虚拟大厅”，可以用作 3D 菜单系统或通往其他世界的门户。
