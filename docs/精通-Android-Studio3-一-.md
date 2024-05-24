# 精通 Android Studio3（一）

> 原文：[`zh.annas-archive.org/md5/9a1caf285755ef105f618b7b4d6fcfa9`](https://zh.annas-archive.org/md5/9a1caf285755ef105f618b7b4d6fcfa9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读《掌握 Android Studio 3》，这是对最新和最复杂的 Android 开发环境的全面指南。无论您是 IDE 的新手还是想要从其他 IDE（如 Eclipse）迁移，本书都使用实际示例来演示 Android Studio 如何促进开发的每个阶段。

本书从工作区本身的介绍开始，然后探索了 IDE 提供的各种 UI 设计工具，包括强大的可视化布局编辑器、自动约束布局工具和动画材料图标。

一旦掌握了 IDE 的设计工具，本书将继续探讨使用 Android Studio 进行代码开发以及其许多有用和创新的编程工具，例如代码完成、模板定制，以及最重要的是提供的 Android Studio 3 的出色测试和分析工具。

Android Studio 不仅是一个用于基本编码的好工具；它还提供了各种插件和扩展，支持诸如 C++和 Kotlin 等语言的本地语言支持。正是这种本地 SDK 的可扩展性使得掌握 Android Studio 3 成为任何移动开发人员的必备技能，本书详细介绍了其中最有用和最受欢迎的内容，使读者能够掌握当今最令人兴奋的开发工具之一。

# 本书内容

第一章《工作区结构》介绍了整体工作区。它涵盖了主要功能，对于那些全新于 IDE 的人来说将非常有用。

第二章《UI 设计》介绍了 UI 设计和开发的主题，着眼于布局编辑器的自动化和节省时间的功能。

第三章《UI 开发》继续使用 UI 开发工具，探讨了更复杂的布局以及如何使用打包在支持存储库中的代码库轻松实现这些布局。

第四章《设备开发》扩展了之前的工作，探讨了针对物理设备和形态因素的开发，涵盖了屏幕旋转和适用于可穿戴设备的形状感知布局等主题。

第五章《资源和资产》着眼于资源管理，特别是 Android 对材料图标和矢量资产的使用。它演示了 Android Studio 为开发的这一方面提供了很好的节省时间的功能。

第六章《模板和插件》是关于扩展 Android Studio 的两章中的第一章。在这里，我们将看到现成的和免费提供的代码样本，不仅在 IDE 中提供，还通过第三方插件提供。

第七章《语言支持》延续了前一章的主题。在这里，我们将看到如何无缝地包含 C++和 Kotlin 代码。

第八章《测试和分析》探讨了 IDE 提供的强大测试和分析工具，以及如何使用它们来测试和微调我们的工作。

第九章《打包和分发》涵盖了开发周期的最后方面。这涉及仔细研究 Gradle 并涵盖了货币化技术。

# 本书所需内容

Android Studio SDK 都是开源的，可以从[developer.android.com](https://developer.android.com/index.html)下载。

本书中提到了各种第三方插件，以及相关的下载位置。

# 本书适合对象

本书适用于任何经验水平的 Android 开发人员，他们希望迁移到或简单掌握 Android Studio 3。

# 惯例

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："在前面的例子中，我们使用`app:srcCompat`而不是`android:src`。"

代码块设置如下：

```kt
public class ExampleUnitTest 
    { 
      @Test 
        public void addition_isCorrect() throws Exception { 
               assertEquals(4, 2 + 2); 
   } 
} 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示。

```kt
buildTypes { 
release { 
         . . .  
         } 
    } 
    productFlavors { 
        flavorDimensions "partial", "full" 
```

任何命令行输入或输出都以以下方式编写：

```kt
gradlew clean 
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："除了 MakeBuild 和 Analyze 之外，Build 菜单还有其他有用的条目，例如 Clean Project 项目，它会从构建目录中删除构建工件"

警告或重要说明会以这种方式出现。

技巧和窍门显示如下。


# 第一章：工作区结构

Android Studio 是一个功能强大且复杂的开发环境，专门用于开发、测试和打包 Android 应用程序。它可以作为一个单一的软件包，与 Android SDK 一起下载，但正如我们将在本书中看到的那样，它实际上是一组工具和组件，其中许多是独立安装和更新的。

Android Studio 并不是开发 Android 应用程序的唯一方式；还有其他 IDE，比如 Eclipse 和 NetBeans，甚至可以仅使用记事本和命令行来开发完整的应用程序，尽管这种方法会非常缓慢和繁琐。

无论您是从其他 IDE 迁移还是只是想充分利用 Android Studio，本书将按照开发应用程序的过程中遇到的顺序，带您了解其最有用的功能，从 UI 开发开始，逐步进行编码和测试，到构建和分发。Android Studio 在这段旅程的每一步都为我们提供了一些有用和智能的工具。

Android Studio 是为了一个目的而构建的，吸引了越来越多的第三方插件，提供了大量有价值的功能，这些功能无法直接通过 IDE 获得。这些包括加快构建时间的插件，通过 Wi-Fi 调试项目等。其中最有用和最受欢迎的将在相关章节中介绍。在整本书中，我们将找到使用这些插件和 Android Studio 内置组件加快繁琐和困难任务的方法。

在本章中，您将涉及以下主题：

+   探索 Studio 和其他 IDE 之间的差异

+   进行简要的导览

+   了解工作区的结构

+   探索编辑器窗口

+   创建材料主题

+   理解工具窗口

+   探索设备文件系统

+   使用即时运行来加快构建过程

+   探索 SDK 管理器

+   介绍虚拟设备管理器

+   从其他 IDE 导入项目

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/eb10778e-c457-47ca-8774-080d20db2e86.png)

Android Studio

如果您已经熟悉 Android Studio，那么您可能希望跳过本介绍章节的一些部分，因为它更多地是针对那些从其他 IDE 迁移的人。然而，您可能之前没有遇到过一些方便的技巧。

尽管可以说是一种更优越的工具，但有一些非常好的理由可以坚持使用另一个 IDE，比如 Eclipse。许多开发人员开发多个平台，这使得 Eclipse 成为一个很好的工具选择。每个开发人员都有截止日期要满足，熟悉陌生软件可能会在一开始大大减慢他们的速度。这本书将加快这种过渡，以便迁移开发人员可以尽可能少地中断地开始利用 Android Studio 提供的附加功能。

# Android Studio 的不同之处

Android Studio 与其他 IDE 和开发工具有许多不同之处。其中一些差异相当微妙，比如支持库的安装方式，而其他差异，例如构建过程和 UI 设计，则是完全不同的。

在更仔细地了解 IDE 本身之前，首先了解一些重要的区别是一个好主意。主要的区别列在这里：

+   **UI 开发**：Studio 和其他 IDE 之间最重要的区别是其布局编辑器，它比任何竞争对手都要优秀，提供文本、设计和蓝图视图，最重要的是，为每个活动或片段提供约束布局工具，易于使用的主题和样式编辑器，以及拖放设计功能。布局编辑器还提供了许多其他地方无法获得的工具，例如全面的预览功能，可以在多种设备上查看布局，以及易于使用的主题和翻译编辑器。

+   **项目结构：**尽管底层目录结构保持不变，但 Android Studio 组织每个项目的方式与其前身有很大不同。Studio 使用模块而不是 Eclipse 中的工作区，这样可以更轻松地一起工作而无需切换工作区。

在 Eclipse 中称为工作区的东西在 Studio 中称为项目，在 Eclipse 中称为项目的东西在 Studio 中称为模块。

这种结构上的差异起初可能看起来不寻常，但任何 Eclipse 用户一旦熟悉起来就会看到它可以节省多少时间。

+   **代码补全和重构：** Android Studio 智能地在您输入时完成代码的方式使其成为一种愉悦。它经常能够预测您即将输入的内容，通常只需两三次按键就可以输入整行代码。重构也比 Eclipse 和 NetBeans 等替代 IDE 更容易和更广泛。几乎任何东西都可以重命名，从局部变量到整个包。

+   **仿真：** Studio 配备了灵活的虚拟设备编辑器，允许开发人员创建设备仿真器来模拟任意数量的真实设备。这些仿真器可以高度定制，无论是在外形因素还是硬件配置方面，虚拟设备都可以从许多制造商那里下载。其他 IDE 的用户可能已经熟悉 Android AVD，尽管他们肯定会喜欢 Design 选项卡中的预览功能。

+   **构建工具：** Android Studio 采用了 Gradle 构建系统，它执行与许多 Java 开发人员熟悉的 Apache Ant 系统相同的功能。然而，它提供了更多的灵活性，并允许定制构建，使开发人员能够轻松创建可上传到 TestFlight 的 APK，或者制作应用的演示版本。正是 Gradle 系统使得之前讨论的模块化成为可能。Studio 不是将每个库或第三方 SDK 编译为 JAR 文件，而是使用 Gradle 构建每个库或 SDK。

这些是 Android Studio 与其他 IDE 之间最深远的差异，但还有更多独特的功能。Studio 提供了强大的 JUnit 测试功能，允许云平台支持甚至 Wi-Fi 调试。它也比 Eclipse 快得多，公平地说，Eclipse 必须满足更广泛的开发需求，而不仅仅是一个，而且它可以在性能较低的机器上运行。

Android Studio 还提供了一个令人惊叹的节省时间的工具，即即时运行。这个功能巧妙地只构建了项目中已编辑的部分，这意味着开发人员可以测试代码的小改动，而不必等待每次测试都进行完整的构建。这个功能可以将等待时间从几分钟减少到几乎零。

无论您是新手还是想更多地了解 Android Studio，第一步都是广泛了解其最突出的结构。

# 工作区结构

Android Studio 的整体结构与其他 IDE 并无不同。有用于编辑文本和屏幕组件的窗口，用于导航项目结构的窗口，以及用于监视和调试的窗口。这个 IDE 非常灵活，可以根据许多特定的需求和偏好进行配置。典型的布局可能是这样的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/23ec00ec-4f89-4a55-94fe-6f1e8425b2cf.png)

典型的工作区布局

尽管这些窗口可以按照我们的意愿进行排列，但一般来说，在上一张截图中，四个窗格可能具有以下功能：

1.  导航项目、模块或库

1.  编辑文本和设计布局

1.  定义组件属性或屏幕预览

1.  监视和调试

有时打开大量窗格可能会分散注意力；对于这些时候，Studio 有一个无干扰模式，只显示当前编辑器窗口，可以从视图菜单中进入。

我们可以从许多不同的角度看待我们的项目，并有许多组织它们的方式。了解每种方式的最佳方法是依次查看每种方式。

# 编辑器窗口

在 IDE 中最重要的窗口当然是我们创建和修改所有应用程序代码的窗口。我们不仅使用编辑器来编辑 XML 和 Java，还有其他编辑器用于简化其他资源，如翻译和主题。然而，无论编辑器多么图形化，所有 Android 资源最终都以 XML 文件的形式出现在`res`目录中。

在大多数情况下，我们可以在不写任何代码的情况下创建大多数 Android 资源。只需点击几下鼠标，就可以使用相应的编辑器创建主题。然而，如果我们要自认为是专家，了解底层代码以及 Studio 存储这些资源的方式和位置是很重要的。以下示例演示了如何使用主题编辑器创建新的 Android 主题：

1.  启动或打开 Android Studio 项目。

1.  从工具|Android|主题编辑器中打开主题编辑器。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/e63a5dd7-9448-4329-8f51-8bde45a5b56b.png)

主题编辑器

1.  在编辑器右上角的主题下拉菜单中，选择创建新主题，并在新主题对话框中输入名称。

1.  将主题父级字段保持不变。

1.  点击 colorPrimary 缩略图。

1.  从结果色板中选择一个你喜欢的颜色，权重为`500`。

1.  以相同的方式，为辅助颜色选择权重为`700`的相同颜色。

1.  选择一个权重为`100`的颜色，与主色对比鲜明。

1.  打开预览或设计编辑器以查看这些更改。

在前面的示例中，我们创建了一个新的主题，该主题将自动应用于整个应用程序。我们本可以简单地编辑默认的`AppTheme`，但如果以后决定使用多个主题，这种方法将简化问题。IDE 通过向`res/values/styles.xml`文件添加以下行来立即应用这些更改：

```kt
<style name="MyTheme" parent="AppTheme" /> 
```

实际的颜色更改可以在`res/values/colors.xml`文件中找到。

主题编辑器相当好地展示了 Studio 编辑器如何在我们只需点击几下鼠标后创建和修改代码。

所有编辑器都可以使用*Ctrl* + *Shift* +*F12*进行最大化。使用相同的键返回到原始布局。

还可以通过从文件菜单中选择设置|编辑器|颜色和字体来更改 IDE 本身的主题，如下图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/7638891a-bf99-43d7-a1ce-f3388b81b58f.png)

Studio 主题对话框

Android Studio 只配备了一个备选颜色方案*Darcula*。这个主题在黑色背景上呈现浅色文本，因此对眼睛来说比默认设置要容易得多，尤其是对于那些长时间的深夜开发。还有其他在线可用的方案，设计自己的方案也很有趣。然而，为了制作印刷材料，我们将在这里坚持使用默认的 IDE 主题。

另一个很好的子编辑器示例是 Translations 编辑器，这也是展示项目结构与其他 IDE 不同的好方法。以下步骤展示了如何实现这一点：

1.  右键单击`res/values/strings.xml`文件，从菜单中选择并打开 Translations 编辑器。也可以在设计 XML 编辑器的语言下拉菜单中找到。

1.  点击编辑器左上角附近的地球图标，并从列表中选择一种语言。

1.  在顶部窗格中选择要翻译的字符串，并在下方窗格中输入值，如图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/6858e36e-95f4-4c8e-b406-5747bfeb78d1.png)

翻译编辑器

这是一个非常简单的练习，其目的是演示 Android Studio 如何存储这些资源以及如何显示它们。编辑器已经创建了一个新的`strings.xml`文件，除了翻译文本的字符串值之外，它在所有方面都与我们的原始文件相同。这个文件将自动被任何将该语言设置为用户默认语言的设备自动引用。

通过项目资源管理器，人们可能会认为在值目录中有一个名为`strings.xml`的项目目录，并且其中包含两个`strings.xml`文件。实际上，这样呈现只是为了帮助我们组织资源。检查磁盘上的`project`文件夹将显示实际上`res`目录中有两个（或更多）名为`values`和`values-fr`的文件夹。这不仅有助于组织我们的工作，还有助于减少应用程序在设备上占用的空间，因为只有需要的资源文件才会安装在最终设备上。

实际的文件夹层次结构可以直接从主工具栏下方的导航栏中确定。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/8bf62d90-ddad-4bc7-b486-742d1facb642.png)

导航栏

主题和翻译是两个最不重要的编辑器，但它们很好地介绍了 Android Studio 如何管理应用程序资源。开发人员的大部分时间都是在使用代码编辑器，当然，这将在整本书中深入介绍。然而，虽然编辑器构成了 IDE 的核心，但还有许多其他有用甚至至关重要的工具可供我们使用，其中最常用的工具可以从工具边缘获得。

# 工具窗口

我们至少有十几个工具窗口可供使用，如果安装了插件，还有更多。它们可以通过查看|工具窗口菜单、工作区底部状态栏最左侧的工具图标，或按*Alt*和相应的数字键来打开特定的工具窗口。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/79898bf0-fc31-401e-a80a-8ac2475abcfe.png)

工具窗口菜单

工具窗口是高度可配置的，每个窗口都可以设置为停靠、浮动或包含在自己的窗口中。

状态栏上的工具窗口图标可用于隐藏和显示工具窗口标签，围绕工作区的边框。

当使用多个屏幕时，这是特别有用的：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/0b1f7d34-9826-42b7-b09d-a6d468a2dbd8.png)一个停靠的、浮动的和窗口化的工具窗口

在本书的整个过程中，我们将深入介绍所有这些工具。不过，以下是对最常用的工具的简要介绍：

+   **消息**：*Alt* + *0*。这个工具生成了 Gradle 构建过程的简化版本。更详细的输出可以在 Gradle 控制台中找到。

+   **项目**：*Alt* + *1*。通常停靠在工作区的左侧，这个工具是我们的主要导航工具。

+   **收藏夹**：*Alt* + *2*。这是一个非常方便的组织工具，可以快速访问常用的类和组件。要将任何文件添加到收藏夹列表中，只需在项目窗口中右键单击该文件，然后从下拉菜单中选择“添加到收藏夹”。

+   **运行**：*Alt* + *3*。这是一个强大的诊断工具，在应用程序在设备或模拟器上运行时可用。

+   **Android**：*Alt* + *4*。这是 Studio 的主要调试窗口，用于监视运行应用程序的日志输出和截图。

+   **内存监视器**：*Alt* + *5*。这个非常有用的工具可以在应用程序运行时生成内存使用情况的实时图表。

+   **结构**：*Alt* + *6*。这个工具提供了关于当前编辑器的详细信息，显示了该特定文件中包含的类、变量和其他组件的分层视图。

最有用的工具窗口之一是设备文件浏览器工具。这使我们能够浏览任何连接设备或模拟器的文件系统。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/0662e7f2-c0b3-4bd1-86d2-7b715ded4558.png)

设备文件浏览器工具。

所有应用程序文件都可以在`data/data`中找到。

工具窗口非常有用，使我们能够配置集成开发环境以适应我们正在进行的特定任务。能够选择适当的工具是 Android Studio 最有用的功能之一。当然，Android Studio 只不过是一个前端界面，允许我们连接到 Android 背后的真正力量，即 SDK。

# Android SDK

从技术上讲，可以将**软件开发工具包**（**SDK**）描述为不是 Android Studio 的一部分，因为它被其他集成开发环境使用。然而，没有它，集成开发环境将毫无用处，现在是一个很好的时机来快速了解一下它及其管理器。

Android SDK 是一个庞大的 API 集合，包括组织成复杂但逻辑的层次结构的 Java 类和接口，以及其他实用工具，如 USB 驱动程序和硬件加速器。

SDK 及其组件的更新频率远远超过操作系统本身，用户应该对此毫不知情。Android 用户以 Lollipop 或 Honeycomb 为单位；作为开发人员，我们以 SDK 级别来看待 Android 世界。

SDK 由 SDK Manager 控制，可以通过主工具栏或从文件菜单的设置|外观和行为|系统设置|Android SDK 中访问。还有一个独立的 SDK Manager，可以在没有 Android Studio 的情况下运行。这可以在以下目录中找到：`\AppData\Local\Android\sdk`。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/9ece20b0-2071-4b75-81e4-99d85c46d451.png)

Android SDK 独立管理器

SDK 管理器有三个部分：工具、平台和额外。至少，您需要安装最新的 SDK 工具、平台工具和构建工具。您还需要安装最新的平台和任何其他您打算直接定位的平台。您还需要为您希望创建的任何虚拟设备安装系统映像以及 Google USB 驱动程序和 HAXM 硬件加速器。

如果您一直在使用 Eclipse 开发 Android 应用程序，您将熟悉 Android 支持库。在使用 Android Studio 时，应安装支持存储库。

管理各种更新的最简单方法是将它们设置为自动安装，可以在设置对话框（*Ctrl + Alt + S*）中的外观和行为|系统设置|更新下完成。

SDK 构成了我们开发环境的支柱，但无论我们掌握得多么好，我们仍然需要一种方式来测试我们的创作，在没有大量真实设备的情况下，这取决于使用 Android 设备模拟器创建虚拟设备。

# 虚拟设备

市场上有如此多的 Android 设备，要在很多真实设备上彻底测试我们的应用几乎是不可能的。正因为如此，系统允许我们使用虚拟设备管理器创建模拟设备。

AVD 管理器允许我们从头开始创建形态因素和硬件配置文件，并提供几个现成的虚拟设备和系统映像，可以从各个制造商的网站上下载。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a8d66bbc-1eba-4306-9320-6a83ee719b57.png)

AVD 配置屏幕

Android 模拟器可能非常慢，即使在非常强大的机器上也是如此，这是可以预料的，因为创建一个完全功能的虚拟设备是一个非常复杂的任务。然而，可以通过设计每个虚拟设备以匹配我们正在开发的应用程序的特定任务来加快速度。例如，如果您的应用程序不使用设备摄像头，则不要在配置中包含它。同样，不要分配比应用程序本身需要的内存多得多。

Android 虚拟设备并不是我们唯一的选择，还有一些少量但不断增长的第三方模拟器。其中许多是专为游戏玩家而不是开发人员设计的；尽管 Genymotion 是一个专门的开发工具，它包含更多功能，通常比原生模拟器更快。它的唯一缺点是只能免费供个人使用，并且只提供手机和平板电脑的系统映像，而不是可穿戴设备或大屏幕设备，如电视。

现实世界的设备自然比任何模拟器反应更快，当测试基本功能时，使用我们自己的设备会提供更快的结果。这种方法非常适合测试应用程序的基本功能，但几乎没有提供关于我们的应用程序在 Android 设备上可能具有的各种屏幕尺寸、形状和密度的反馈。

使用真实设备是测试应用程序逻辑的快速方法，但为特定型号甚至通用大小和形状开发应用程序将不可避免地需要创建虚拟设备。幸运的是，Android Studio 配备了一个加速构建过程：Instant Run。

# Instant Run

在较早的 Android Studio 版本中，每次在任何设备上运行项目时，都必须执行完整的构建。即使我们只对代码进行了微小的更改，我们仍然必须等待整个应用程序重新构建和重新安装。这可能非常耗时，特别是在性能较差的机器上。这种缓慢通常导致不得不一次性测试多个修改，导致比理想情况更复杂的调试过程。

Instant Run 尝试仅构建自上次构建以来已更改的那些类或活动，并且只要清单文件没有被编辑，应用程序甚至不会被重新安装，有些情况下，启动活动甚至不会被重新启动。

由于 Instant Run 是一项最近的创新，遗憾的是它并不适用于所有版本的 Android，并且要充分利用它，您需要将最低 SDK 级别设置为 API 21 或更高级别，尽管它的一些元素将与 API 级别 15 及更高级别一起工作。在 Android Studio 中，此级别是从`build.gradle（Module：app）`文件中设置的，如下所示：

```kt
android { 
    compileSdkVersion 25 
    buildToolsVersion "25.0.1" 
    defaultConfig { 
        applicationId "com.mew.kyle.chapterone" 
        minSdkVersion 21 
        targetSdkVersion 25 
        versionCode 1 
        versionName "1.0" 
        testInstrumentationRunner "android.support.test.runner.AndroidJUnitRunner" 
    } 
```

我们往往会尽可能使我们的应用程序向后兼容，开发一个只能在 API 级别 21 或更高级别上运行的应用程序将严重限制我们能够触及的用户数量。然而，Instant Run 为我们节省的时间使得值得测试和调试 API 21 或更高级别的应用程序，然后稍后重新组装以匹配我们希望目标的版本。

在决定要针对哪些 Android 版本时，一个有用的仪表板显示了平台和屏幕的最新使用数据。它可以在`developer.android.com/about/dashboards/index.html`找到。

从另一个 IDE 迁移到 Android Studio 不需要是一个困难的过渡，一旦完成将会非常有价值。但是，您可能有在其他 IDE 中开发的项目，希望继续使用 Studio 进行开发。幸运的是，这是一个简单的任务，如下一节所示。

# 将项目导入到 Android Studio

Eclipse 毫无疑问是最好的开发工具之一，15 年来，我们中的许多人对它非常熟悉。在开发各种平台时，Eclipse 是一个很棒的工具，但在开发 Android 应用程序时无法与 Android Studio 竞争。

如果您从 Eclipse 迁移，您很可能有一些项目希望导入到 Studio 中。以下步骤演示了如何完成此操作：

1.  首先确保您的 Eclipse ADT 根目录包含`src`和`res`目录以及`AndroidManifest.xml`文件。

1.  记下您使用过的 Eclipse 第三方插件，因为您需要在 Studio 中安装相应的插件。

1.  打开 Android Studio 并从欢迎屏幕或文件|新建|导入项目中选择导入项目。

1.  选择包含清单的文件夹并准备一个目标文件夹，然后按照提示完成导入。

导入过程会完整复制项目，原始项目不受影响，这意味着如果您愿意，仍然可以在 Eclipse 中进行工作。不幸的是，无法导入第三方插件，但 Studio 有大量不断增长的插件可用，很可能您能找到相应的插件。这些可以从文件|设置|插件中浏览。

如果您在同一个工作空间中有几个 Eclipse 项目，那么您应该将一个项目导入为项目，其余的导入为模块。

当我们进行项目配置时，我们将再次查看这个过程，但除此之外，从现在开始，我们将假设所有项目都是在 Android Studio 中开始的。

# 总结

本章对于那些不熟悉 Android Studio 的读者来说，作为一个简短但完整的介绍。我们探讨了工作空间的结构以及我们可以使用的各种编辑器。这次探索使我们创建了一个 Material Design 主题，使用工具窗口执行各种有用的任务，并应用了“即时运行”来加快原本耗时的构建过程。

本章以快速查看虚拟设备以及如何从其他 IDE 导入项目结束。有了这个介绍，接下来的章节将深入探讨布局编辑器本身，我们将看到如何设计适用于最广泛形态的应用界面。


# 第二章：UI 设计

Android Studio 中最突出的一个特性，包括 Gradle 构建系统在内，就是强大的用户界面（UI）开发工具。该 IDE 提供了多种设计视图，允许我们在 UI 开发中结合拖放构建和硬编码。Android Studio 还配备了全面的预览系统，可以让我们在实际设备上运行项目之前在任何设备上测试我们的设计。除了这些功能，Android Studio 还包括有用的支持库，如用于创建材料设计布局的设计库和用于简化复杂比例设计的百分比支持库。

这一章是四章中的第一章，涵盖了 UI 开发。在这一章中，我们将更仔细地研究 Studio 的布局编辑器和工具。我们将使用最有用的布局/ViewGroup 类构建工作界面，并设计和管理屏幕旋转。本章还将探讨 Studio 的预览系统以及 XML 布局资源的存储和应用。最后，本章将回顾主题、材料设计和设计支持库。

在本章中，您将学习如何：

+   探索布局编辑器

+   应用线性和相对布局

+   安装约束库

+   创建`ConstraintLayout`

+   应用约束

+   使用图形约束编辑器

+   添加约束指南

+   对齐`TextView`基线

+   应用偏差

+   使用自动连接

+   为虚拟设备构建硬件配置文件

+   创建虚拟 SD 卡

# 布局编辑器

如果有一个理由使用 Android Studio，那就是布局编辑器及其相关工具和预览系统。一旦打开一个项目，差异就显而易见。布局和蓝图视图之间的差异也在下图中显示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/6d69c83c-2fb0-4383-a0c0-689c018bdb3c.png)

设计和蓝图布局视图

蓝图模式是 Android Studio 2.0 的新功能，它展示了我们 UI 的简化轮廓视图。在编辑复杂布局的间距和比例时，这是特别有用的，而不会受到内容的干扰。默认情况下，IDE 会并排显示设计和蓝图视图，但编辑器的工具栏允许我们只查看一个视图，在大多数情况下，我们会选择最适合当前任务的模式。

*B*键可用于在设计、蓝图和组合视图之间切换，作为工具栏图标的替代方法。

完全可以使用这些图形视图为项目生成所需的每个布局，而不需要了解底层代码。不过，这并不是一个非常专业的方法，了解底层 XML 的知识对于良好的测试和调试至关重要，而且如果我们知道自己在做什么，通常调整代码比拖放对象更快。

负责前一个布局的 XML 如下：

```kt
<LinearLayout  

    android:id="@+id/layout_main" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:orientation="vertical"> 

    <TextView 
        android:id="@+id/text_view_top" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_weight="1" /> 

    <TextView 
        android:id="@+id/text_view_center" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_weight="3" /> 

    <TextView 
        android:id="@+id/text_view_bottom" 
        android:layout_width="match_parent" 
        android:layout_height="0dp" 
        android:layout_weight="2" /> 

</LinearLayout> 
```

希望您对前面代码中使用的术语很熟悉。`layout_weight`的使用经常与线性布局一起使用，用于分配比例，在开发具有略有不同纵横比的屏幕时节省了大量时间。

直到最近，我们创建更复杂 UI 的唯一选择是线性和相对布局。这两种布局都不是理想的选择，要么是不必要的昂贵，要么是琐碎的。Android Studio 2 引入了约束布局，为这些问题提供了一个优雅的解决方案。为了更好地理解其价值，首先看一下旧的类是有意义的，这些类在许多简单的设计中仍然有用。

# 线性和相对布局类

线性布局相对较轻，对于基于单行或单列的布局非常有用。然而，更复杂的布局需要在彼此内部嵌套布局，这很快就会变得资源密集。看一下下面的布局：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/d483da95-3c6d-4df7-920f-e12192336edc.png)

嵌套线性布局

前面的布局只使用了线性布局，可以从以下组件树中看到：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/76d6e913-677d-4b6b-aa83-4b253436db6d.png)

组件树

尽管这种布局完全可行且易于理解，但它的效率不如可能。即使是一个额外的布局嵌套层也会对性能产生影响。在约束布局出现之前，这个问题是通过相对布局解决的。

如其名称所示，相对布局允许我们将屏幕组件放置在彼此之间的关系中，使用诸如`layout_toStartOf`或`layout_below`之类的标记。这使我们能够扁平化视图层次结构，并且前面的布局可以仅使用一个单独的相对根视图组来重新创建。以下代码演示了如何在不嵌套任何新布局的情况下生成前一个布局中的图像行：

```kt
<ImageView 
    android:id="@+id/image_header_1" 
    android:layout_width="128dp" 
    android:layout_height="128dp" 
    android:layout_alignParentStart="true" 
    android:layout_below="@+id/text_title" 
    app:srcCompat="@drawable/pizza_01" /> 

<ImageView 
    android:id="@+id/image_header_2" 
    android:layout_width="128dp" 
    android:layout_height="128dp" 
    android:layout_below="@+id/text_title" 
    android:layout_toEndOf="@+id/image_header_1" 
    app:srcCompat="@drawable/pizza_02" /> 

<ImageView 
    android:id="@+id/image_header_3" 
    android:layout_width="128dp" 
    android:layout_height="128dp" 
    android:layout_alignParentEnd="true" 
    android:layout_below="@+id/text_title" 
    app:srcCompat="@drawable/pizza_03" /> 

<ImageView 
    android:id="@+id/image_header_4" 
    android:layout_width="128dp" 
    android:layout_height="128dp" 
    android:layout_alignParentStart="true" 
    android:layout_below="@+id/text_title" 
    app:srcCompat="@drawable/pizza_04" /> 
```

即使您是 Android Studio 的新手，也假定您熟悉线性布局和相对布局。您可能不太可能遇到约束布局，它是专门为 Studio 开发的，以弥补这些旧方法的缺点。

在前面的示例中，我们使用了`app:srcCompat`而不是`android:src`。这在这里并不是严格要求的，但如果我们希望对图像应用任何着色并希望将应用程序分发给较旧的 Android 版本，这个选择将使这成为可能。

# 约束布局

约束布局类似于相对布局，它允许我们生成复杂的布局，而无需创建占用内存的视图组层次结构。Android Studio 使得创建这样的布局变得更加容易，因为它提供了一个可视化编辑器，使我们不仅可以拖放屏幕组件，还可以拖放它们的连接。能够如此轻松地尝试布局结构为我们提供了一个很好的沙盒环境，用于开发新的布局。

以下练习将带您完成安装约束库的过程，以便您可以开始自己进行实验。

1.  从 Android Studio 3.0 开始，默认情况下会下载`ConstraintLayout`，但如果要更新早期项目，则需要打开 SDK 管理器。约束布局和约束求解器都可以在 SDK 工具选项卡下找到，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/42d28968-df7b-4f04-8a7e-afc6f001b10c.png)

约束布局 API

1.  勾选显示包详细信息框，并记下版本号，因为这很快将需要。

1.  接下来，将`ConstraintLayout`库添加到我们的依赖项中。最简单的方法是选择您的模块，然后选择项目结构对话框的依赖项选项卡，该对话框可以从文件菜单中访问。

1.  单击+按钮，然后选择 1 Library dependency 并从列表中选择约束库。

1.  最后，从工具栏、构建菜单或*Ctrl* + *Alt* + *Y*同步您的项目。

这是添加模块依赖项的最简单方法，但作为开发人员了解底层发生的事情总是很好。在这种情况下，我们可以通过打开模块级`build.gradle`文件并将以下突出显示的文本添加到`dependencies`节点来手动添加库：

```kt
dependencies { 
    compile fileTree(dir: 'libs', include: ['*.jar']) 
    androidTestCompile('com.android.support.test.espresso:espresso-
                        core:2.2.2', { 
        exclude group: 'com.android.support', module: 'support-annotations' 
    }) 
    compile 'com.android.support:appcompat-v7:25.1.0' 
    compile 'com.android.support.constraint:constraint-layout:1.0.0-beta4' 
    testCompile 'junit:junit:4.12' 
```

那些使用相对布局开发的人将熟悉诸如`layout_toRightOf`或`layout_toTopOf`之类的命令。这些属性仍然可以应用于`ConstraintLayout`，但还有更多。特别是，`ConstraintLayout`允许我们基于单个边来定位视图，例如`layout_constraintTop_toBottomOf`，它将我们的视图的顶部与指定视图的底部对齐。

有关这些属性的有用文档可以在以下网址找到：[developer.android.com/reference/android/widget/RelativeLayout.LayoutParams.html](https://developer.android.com/reference/android/widget/RelativeLayout.LayoutParams.html)。

# 创建约束布局

有两种方法可以创建 ConstraintLayout。第一种是将现有布局转换为 ConstraintLayout，可以通过右键单击组件树或图形编辑器中的布局，然后选择转换选项来完成。然后会出现以下对话框：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/2333857b-14b5-4d2d-a0f7-65c57f242b5a.png)

转换为 ConstraintLayout 对话框

通常最好同时检查这两个选项，但值得注意的是，这些转换并不总是会产生期望的结果，通常视图尺寸需要进行一些微调才能忠实地复制原始布局。

当它起作用时，以前的方法提供了一个快速的解决方案，但是如果我们要掌握这个主题，我们需要知道如何从头开始创建约束布局。这一点特别重要，因为一旦我们熟悉了约束布局的工作方式，我们将会发现这是设计界面最简单、最灵活的方式。

ConstraintLayout 与布局编辑器完美结合，可以设计任何布局而无需编写任何 XML。然而，我们将密切关注图形和文本两个方面，以便更深入地了解这项技术。

您可以从项目资源管理器的上下文菜单中的 res/layout 目录中创建一个新的 ConstraintLayout，作为一个具有以下根元素的新布局资源文件：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/d2bc3fc1-d778-434b-8134-c7b5315cb046.png)

添加新的 ConstraintLayout

这将生成以下 XML：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<android.support.constraint.ConstraintLayout 

    android:layout_width="match_parent" 
    android:layout_height="match_parent"> 

</android.support.constraint.ConstraintLayout> 
```

与其他布局类型一样，约束层提供了在其中定位和对齐视图和小部件的机制。这主要通过可以在图形上定位以调整大小和对齐视图的手柄来完成。

# 应用约束

了解其工作原理的最佳方法是尝试一下，这几个简单的步骤将进行演示。按照前面描述的方式创建 ConstraintLayout，并从调色板拖放一个或两个视图或小部件到蓝图屏幕上，类似于以下图示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/34893a39-2340-4710-ae6c-9b7b94addbed.png)

约束手柄

每个视图的角落和边上都有约束手柄。角落上的手柄用于简单地调整视图的大小，而边上的手柄用于创建约束。这些位置视图是相对于其父级或彼此的，与相对布局并没有太大不同。

由于这主要是一种图形形式的编辑，最好通过操作来进行演示。将视图的左侧锚点拖向布局的左侧，并按照提示释放鼠标按钮以创建父约束。这是一个包含其他内容的布局，将成为父约束。

当您尝试使用约束时，您会注意到边距会自动粘附到创意设计指南推荐的值。

如果现在打开文本编辑器，您将看到约束如下所示：

```kt
app:layout_constraintLeft_toLeftOf="parent" 
```

您还会注意到从代码中生成了一个错误。这是因为每个视图都需要垂直和水平约束。可以通过以下方式实现：

```kt
app:layout_constraintTop_toTopOf="parent" 
```

也可以使用相同的拖放技术在子视图之间创建约束，或者：

```kt
app:layout_constraintTop_toBottomOf="@+id/image_view" 
```

在视图的四个边上设置约束将使其居中在其容器中。

约束可用于对齐兄弟视图以及连接两个相邻的边，生成以下代码：

```kt
app:layout_constraintLeft_toLeftOf="@+id/image_view" 
```

可以通过在任一编辑模式下单击其起始手柄来简单地删除约束。

这种拖放方法并不是 Android Studio 独有的，但是 Android Studio 提供了一个可编辑的示意图视图，通过属性工具来实现。

# 图形属性工具

当选择 ConstraintLayout 视图时，属性窗口中会弹出一个视图的图解表示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a0e2a02c-07a2-4221-9001-356602d5156d.png)

属性示意图。

这个工具允许通过单击来编辑大小和位置属性，并且可以立即以简单的示意图形式理解输出。学习起来只需要几秒钟，可以大大加快界面设计的速度，特别是在尝试不同的布局时。

在代表我们视图的中央正方形内，有四条线，单击它们会循环显示以下三种状态：

+   **实线**：视图是精确的宽度，例如`240dp`

+   **模糊线**：视图可以是任何大小（取决于偏差），`match_parent`

+   **有向线**：视图匹配其自身内容，`wrap_content`

通常，我们不希望将视图约束到其容器的边缘。例如，我们可能希望将布局分成两个或多个部分，并在其中组织视图。指南允许我们将屏幕分成几个部分，并且可以像父边缘一样使用。看下面的例子：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/6a533c49-852b-47ac-b844-6c7e14d366d4.png)

约束指南

像这样的指南最容易从设计编辑器顶部的约束工具栏中添加。指南被添加为 XML 组件，看起来像这样：

```kt
<android.support.constraint.Guideline 
    android:id="@+id/gl_vertical" 
    android:layout_width="wrap_content" 
    android:layout_height="311dp" 
    android:orientation="vertical" 
    app:layout_constraintGuide_begin="175dp" /> 
```

现在我们可以使用这些指南来根据整个布局或我们创建的四个窗格之一来居中元素，而无需嵌套任何布局。在下面的屏幕截图中，我们有一个居中的标题和侧边栏，另一个视图包含在一个单独的窗格中，当然我们可以对这些部分应用偏差：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/46252969-e6c1-41f2-a286-77d40759f680.png)

应用约束指南

如果这个系统还没有提供足够的优势，那就还有更多。首先，当对齐文本以及一种称为偏差的更强大的定位技术时，它被证明非常有用，它执行与权重属性类似的功能，但在设计多个屏幕时更好。我们首先来看一下文本对齐约束。

# 基线对齐

使用它们的基线将文本对齐到多个视图可能有些麻烦，特别是当文本大小不同时。幸运的是，约束布局提供了一种简单而轻松的方法来实现这一点。

任何受约束的视图或设计用于包含文本的小部件，都会在其中心处有一条横杠。将鼠标悬停在此处片刻，直到它闪烁，然后将其拖动到您希望将其文本与之对齐的视图，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/c95dfcb4-4527-4277-8214-63f694d4f3a0.png)

基线对齐。

您可能已经熟悉相对布局类使用的重力属性来控制位置。

基线约束只能连接到其他基线。

约束布局引入了一种新的方法，允许我们控制视图两侧的相对距离。

# 使用偏差控制位置

在这里，偏差最好理解为百分比值，但与其根据中心或角落的位置，它是它两侧空间的百分比。因此，如果向上的偏差为 33％，则下方的边距将是下方边距的两倍。

设置偏差甚至比理解它更容易，因为一旦在视图的任何对立面上设置了约束，属性编辑器中将出现一个关联的滑块：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/8c2997bb-0521-4554-9160-70ef9728306e.png)

使用 GUI 应用偏差

快速浏览生成的代码，显示了该属性的格式如下：

```kt
app:layout_constraintHorizontal_bias="0.33" 
```

使用偏差来定位屏幕元素的价值部分在于其简单的方法，但其真正价值在于开发多个屏幕时。有这么多型号可用，它们似乎都有稍微不同的比例。这可能使得在所有这些屏幕上看起来很棒的设计布局非常耗时，即使是 720 x 1280 和 768 x 1280 这样相似的形状在使用相同的布局进行测试时也可能产生不良结果。使用偏差属性在很大程度上解决了这些问题，我们将在稍后看到更多内容，当我们看到布局预览和百分比库时。

编辑器的设计和文本模式可以使用*Alt* +左或右进行切换。

好像所有这些都没有使设计布局变得足够简单，约束布局还有另外两个非常方便的功能，几乎可以自动化 UI 设计：自动连接和推断。

# 约束工具栏

尽管我们总是希望花费大量时间完善我们的最终设计，但开发周期的大部分时间将用于实验和尝试新想法。我们希望尽快测试这些单独的设计，这就是自动连接和推断的用武之地。这些功能可以通过约束工具栏访问，其中包含其他有用的工具，值得详细了解。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/b1c5a472-32d7-461c-9786-b7c28f60f3fb.png)

约束工具栏

从左到右，工具栏分解如下。

+   显示约束：显示所有约束，而不仅仅是所选组件的约束。

+   自动连接：启用此功能后，新视图和小部件的约束将根据它们放置的位置自动设置。

+   清除所有约束：顾名思义，一键解决方案。这可能会导致一些意想不到的结果，因此应该小心使用。

+   推断约束：设计布局后应用此功能。它将自动应用约束，类似于自动连接，但它会一次性对所有视图应用约束。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/4db07488-596a-4494-9c89-cdf2b755a3c2.png)

推断过程

+   默认边距：设置整个布局的边距。

+   Pack：提供一系列分布模式，帮助均匀扩展或收缩所选项目使用的区域。

+   对齐：此下拉菜单提供了最常用的组对齐选项。

+   指南：允许快速插入指南。

自动连接和推断都提供了智能和快速的构建约束布局的方法，虽然它们是测试想法的绝佳工具，但它们远非完美。这些自动化经常会包括不必要的约束，需要删除。此外，如果您在使用这些技术之后检查 XML，您会注意到一些值是硬编码的，您会知道这不是最佳实践。

希望您在本节中已经看到，Android Studio 和 ConstraintLayout 确实是为彼此而生的。这并不是说它应该在所有情况下取代线性和相对布局。在简单列表方面，线性布局仍然是最有效的。对于只有两个或三个子元素的布局，相对布局通常也更便宜。

`ConstraintLayout`类还有更多内容，比如分布链接和运行时约束修改，我们将在整本书中经常回到这个主题，但现在我们将看看 Android Studio 的另一个独特而强大的工具，设备预览和仿真。

# 多屏幕预览

Android 开发人员面临的最有趣的挑战之一是使用它的设备数量令人困惑。从手表到宽屏电视，各种设备都在使用。我们很少希望开发一个单一的应用程序在这样的范围内运行，但即使为所有手机开发布局也是一项艰巨的任务。

幸运的是，SDK 允许我们将屏幕形状、大小和密度等功能分类到更广泛的组中，从而帮助这一过程。Android Studio 还添加了另一个强大的 UI 开发工具，即复杂的预览系统。这可以用于预览许多流行的设备配置，同时也允许我们创建自定义配置。

在前面的部分中，我们看了 ConstraintLayout 工具栏，但正如您可能已经注意到的那样，还有一个更通用的设计编辑器工具栏：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/36bb732a-af2c-4949-a5f1-ab60d7a03376.png)

设计编辑器工具栏

这些工具中的大多数都是不言自明的，您可能已经使用过其中的许多。然而，其中有一两个值得更仔细地研究，特别是如果您是 Android Studio 的新手。

迄今为止，我们可以使用的最有用的设计工具之一是编辑器中的设备工具，在前面的图中显示为 Nexus 4。这使我们能够预览我们的布局，就像它们在任意数量的设备上显示一样，而无需编译项目。下拉菜单提供了一系列通用和真实世界的配置文件，我们可能创建的任何 AVD，以及添加我们自己的设备定义的选项。现在我们将看看这个选项。

# 硬件配置文件

从编辑器中的设备下拉菜单中选择“添加设备定义...”将打开 AVD 管理器。要创建新的硬件配置文件，请单击“创建虚拟设备...”按钮。选择硬件对话框允许我们安装和编辑前面下拉菜单中列出的所有设备配置文件，以及创建或导入定义的选项。

AVD 管理器的独立版本可以从`user\AppData\Local\Android\sdk\`运行。这对于性能较低的机器非常有用，因为 AVD 可以在没有 Studio 运行的情况下启动。

通常更容易采用现有的定义并根据我们的需求进行调整，但为了更深入地了解操作，我们将通过单击“选择硬件”对话框中的“新硬件配置文件”按钮，从头开始创建一个。这将带您进入“配置硬件配置文件”对话框，在那里您可以选择硬件仿真器，如摄像头和传感器，以及定义内部和外部存储选项。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/68d3e3c6-b08f-46dc-9357-e8a96d74ed43.png)

硬件配置

一旦您完成配置文件并点击“完成”，您将返回到硬件选择屏幕，在那里您的配置文件现在已被添加到列表中。然而，在继续之前，我们应该快速看一下如何模拟存储硬件。

# 虚拟存储

每个配置文件都包含一个 SD 卡磁盘映像来模拟外部存储，显然这是一个有用的功能。然而，如果我们能够移除这些卡并与其他设备共享，那将更加有用。幸运的是，Android Studio 有一些非常方便的命令行工具，我们将在本书中遇到。这里我们感兴趣的命令是`mksdcard`。

`mksdcard`可执行文件位于`sdk/tools/`中，创建虚拟 SD 卡的格式为：

```kt
mksdcard <label> <size> <file name> 
```

例如：

```kt
mksdcard -l sharedSdCard 1024M sharedSdCard.img 
```

在大量虚拟设备上测试应用程序时，能够共享外部存储器可以节省大量时间，当然，这样的映像可以存储在实际的 SD 卡上，这不仅使它们更加便携，还可以减轻硬盘的负担。

我们的配置文件现在已准备好与系统映像结合，形成 AVD，但首先我们将导出它，以便更好地了解它是如何组合的。这将保存为 XML 文件，并且可以通过右键单击硬件选择屏幕的主表中的配置文件来实现。这不仅提供了洞察力，也是跨网络共享设备的便捷方式，而且编辑本身也非常快速简单。

配置本身可能会相当长，因此以下是一个示例节点，以提供一个想法：

```kt
<d:screen> 
    <d:screen-size>xlarge</d:screen-size> 
    <d:diagonal-length>9.94</d:diagonal-length> 
    <d:pixel-density>xhdpi</d:pixel-density> 
    <d:screen-ratio>notlong</d:screen-ratio> 
    <d:dimensions> 
        <d:x-dimension>2560</d:x-dimension> 
        <d:y-dimension>1800</d:y-dimension> 
    </d:dimensions> 
    <d:xdpi>314.84</d:xdpi> 
    <d:ydpi>314.84</d:ydpi> 
    <d:touch> 
        <d:multitouch>jazz-hands</d:multitouch> 
        <d:mechanism>finger</d:mechanism> 
        <d:screen-type>capacitive</d:screen-type> 
    </d:touch> 
</d:screen> 
```

在这里定义屏幕的方式，为我们提供了一个有用的窗口，可以了解在开发多个设备时需要考虑的功能和定义。

要查看我们的配置文件的实际效果，我们需要将其连接到系统映像并在模拟器上运行。这是通过选择配置文件并点击“下一步”来完成的。

要彻底测试应用程序，通常最好为要发布应用程序的每个 API 级别、屏幕密度和硬件配置创建一个 AVD。

选择图像后，您将有机会调整硬件配置文件，然后创建 AVD：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/94b22b0f-4f29-4e67-9e72-d68afd45efac.png)

Android AVD

模拟最新的移动设备是一项令人印象深刻的任务，即使对于最坚固的计算机来说，即使使用 HAXM 硬件加速，速度仍然可能令人沮丧地慢，尽管即时运行的添加大大加快了这个过程。除了 Genymotion 之外，几乎没有其他选择，Genymotion 提供了更快的虚拟设备和一些在本机模拟器上无法使用的功能。这些功能包括拖放安装、实时窗口调整大小、工作网络连接和一键模拟位置设置。唯一的缺点是 Android Wear、TV 或 Auto 没有系统映像，并且仅供个人免费使用。

本节展示了我们如何在许多形态因素上预览我们的布局，以及如何构建一个虚拟设备以匹配任何目标设备的精确规格，但这只是故事的一部分。在下一章中，我们将看到如何为所有目标设备创建布局文件。

# 总结

在本章中，我们介绍了界面开发的基础知识，这在很大程度上是使用和理解各种布局类型的问题。本章的大部分内容都致力于约束布局，因为这是最新和最灵活的视图组之一，并且在 Android Studio 中配备了直观的可视化工具。

本章最后介绍了如何将完成的布局在模拟器上查看，并使用自定义的硬件配置文件。

在接下来的章节中，我们将更深入地研究这些布局，并看到协调布局是如何用来协调多个子组件一起工作的，而我们几乎不需要编写任何代码。


# 第三章：UI 开发

在上一章中，我们看到安卓工作室为快速简单地设计布局提供了许多宝贵的工具。然而，我们只关注了静态 UI 的设计。当然，这是一个必不可少的第一步，但我们的界面可以，也应该是动态的。根据材料设计指南，用户交互应该通过运动和颜色直观地展示，比如点击按钮时产生的涟漪动画。

要了解如何做到这一点，我们需要看一个实际的例子，并开始构建一个简单但功能的应用程序。但首先，我们将研究一两种应用我们想要的外观和感觉的方式，并且安卓用户期望将其应用到我们的设计中。这个过程在很大程度上得到了支持库的帮助，特别是 AppCompat 和 Design 库。

我们将从查看安卓工作室如何通过基于材料的视觉主题编辑器和设计支持库来实现材料设计开始本章。

在本章中，您将学习以下内容：

+   生成材料样式和主题

+   使用 XML 字体

+   创建 XML 字体系列

+   使用基本代码完成

+   应用协调布局

+   协调设计组件

+   创建一个可折叠的应用栏

+   部署原始资源

+   使用百分比支持库

我们在上一章中看到，当使用设计编辑器调整约束布局的屏幕元素的大小和移动时，我们的视图往往会粘在一组特定的尺寸上。这些尺寸是根据 Material 设计指南选择的。如果您不知道，Material 是一种设计语言，由谷歌规定，基于传统的设计和动画技术，旨在通过移动和位置来清理用户界面的过程。

# 材料设计

虽然 Material 设计并不是必不可少的，如果您正在开发全屏应用程序，比如游戏，它通常有自己的设计规则，可以完全忽略它，但它仍然是一种优雅的设计范式，并且被用户群广泛认可和理解。

实施材料的一个非常好的理由是，许多其特性，如卡片视图和滑动抽屉，都可以通过相关的支持库非常容易地应用。

我们需要做的第一个设计决定之一是，我们想要将什么颜色方案或主题应用到我们的应用程序中。关于我们主题的色调和对比度，有一两个材料指南。幸运的是，安卓工作室的主题编辑器确实非常简单地生成符合材料的主题。

# 安卓样式

图形属性，如背景颜色、文本大小和高程，都可以在任何 UI 组件上单独设置。将属性组合到一起成为一个样式通常是有意义的。安卓将这些样式存储在 values 目录中的`styles.xml`文件中的 XML 中。一个例子如下：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<resources> 
    <style name="TextStyle" parent="TextAppearance.AppCompat"> 
        <item name="android:textColor">#8000</item> 
        <item name="android:textSize">48sp</item> 
    </style> 
</resources> 
```

这样的样式可以简单地应用到视图和小部件上，而无需指定每个属性，如下所示：

```kt
<TextView 
    . . .  
    android:textAppearance="@style/TextStyle" 
    . . . /> 
```

完全可以通过定义所有属性来从头开始创建任何样式，但更实际的做法是从现有样式中继承并仅修改我们希望更改的属性。这是通过设置`parent`属性来完成的，可以在前面的例子中看到。

我们也可以继承自我们自己的样式，而无需设置父属性，例如：

```kt
<style name="TextStyle.Face"> 
    <item name="android:typeface">monospace</item> 
</style> 
```

之前，我们创建了一个新的资源文件，但我们也可以将一个新的`<style>`节点添加到现有的`styles.xml`文件中。

如果您是 Android Studio 的新手，您会注意到代码完成下拉框在您输入时出现，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/3d5fccfd-3aa0-40ec-90c3-dad520a25a92.png)

代码完成

这是一个非常有价值的工具，我们将在稍后更详细地看一下。现在，知道代码完成存在三个级别是有用的，如此简要地概述：

+   **基本**：*Ctrl* + 空格; 显示下一个单词的可能性。

+   **智能**：*Ctrl* + *Shift* + 空格; 上下文敏感建议。

+   **语句**：*Ctrl* + *Shift* + *Enter*; 完成整个语句。

连续两次调用基本和智能代码完成将扩大建议的范围。

创建和应用这样的样式是微调应用程序外观的好方法，而无需进行大量额外的编码，但有时我们也希望将外观和感觉应用于整个应用程序，为此，我们使用主题。

# 材料主题

在为应用程序创建整体主题时，我们有两个相反的目标。一方面，我们希望我们的应用程序脱颖而出，并且容易被识别；另一方面，我们希望它符合用户对平台的期望，并且希望他们发现控件熟悉且简单易用。主题编辑器在个性和一致性之间取得了很好的折衷。

在最简单的情况下，材料主题采用两种或三种颜色，并在整个应用程序中应用这些颜色，以使其具有一致的感觉，这可能是使用主题的主要好处。作为重点选择的颜色将用于着色复选框和突出显示文本，并且通常选择以突出显示并吸引注意。另一方面，主要颜色将应用于工具栏，并且与早期版本的 Android 不同，还将应用于状态栏和导航栏。例如：

```kt
<color name="colorPrimary">#ffc107</color>
<color name="colorPrimaryDark">#ffa000</color>
<color name="colorAccent">#80d8ff</color>
```

这使我们能够在应用程序运行时控制整个屏幕的颜色方案，避免与任何本机控件发生丑陋的冲突。

选择这些颜色的一般经验法则是选择主要值的两种色调和一个对比但互补的颜色作为重点。谷歌对要使用哪些色调和颜色更加精确，没有硬性规定来决定哪些颜色与其他颜色搭配得好。然而，有一些有用的指南可以帮助我们，但首先我们将看一下谷歌的材料调色板。

# 主题编辑器

谷歌规定在 Android 应用程序和 Material 设计网页中使用 20 种不同的色调。每种色调有十种阴影，如下例所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/79d9278b-aebe-4f18-955e-a21a060a34e0.png)

材料调色板

完整的调色板以及可下载的样本可以在以下网址找到：[material.io/guidelines/style/color.html#color-color-palette](http://material.io/guidelines/style/color.html#color-color-palette)。

材料指南建议我们使用 500 和 700 的阴影作为我们的主要和深色主要颜色，以及 100 作为重点。幸运的是，我们不必过分关注这些数字，因为有工具可以帮助我们。

这些工具中最有用的是主题编辑器。这是另一个图形编辑器，可以从主菜单中的工具 | Android | 主题编辑器中访问。

一旦打开主题编辑器，您将看到它分为两个部分。右侧是颜色属性列表，左侧是显示这些选择对各种界面组件的影响的面板，为我们提供了方便的预览和快速直观地尝试各种组合的机会。

正如您所看到的，不仅有两种主要颜色和一个重点。实际上有 12 种，涵盖文本和背景颜色，以及深色和浅色主题的替代方案。这些默认设置为`styles.xml`文件中声明的父主题的颜色。

要快速设置自定义材料主题，请按照以下步骤进行：

1.  开始一个新的 Studio 项目或打开一个您希望应用主题的项目。

1.  从工具 | Android 菜单中打开主题编辑器。

1.  选择 colorPrimary 字段左侧的实色块。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/3fb9816f-7996-405a-8e58-b72b5db26543.png)

1.  在资源对话框的右下角选择一个纯色块，然后单击“确定”。

1.  打开 colorPrimaryDark 对话框，然后在右侧的颜色选择选项下选择唯一的建议块。它将是相同的色调，但是 700 的阴影。

1.  选择重点属性，然后从建议的颜色中选择一个。

这些选择可以立即在编辑器左侧的预览窗格中看到，也可以从布局编辑器中看到。

正如你所看到的，这些颜色并不是直接声明的，而是引用了`values/colors.xml`文件中指定的值。

编辑器不仅帮助通过建议可接受的颜色来创建材料主题，还可以帮助我们选择自己选择的颜色。在“选择资源”窗口的颜色表中的任何位置单击都会提示选择最接近的材料颜色。

在选择重点颜色时，有几种思路。根据色彩理论，可以使用色轮创建与任何颜色和谐互补色的几种方法，例如以下色轮：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/cdbe5c7e-21de-4645-b7c7-c7d5bcdc50d2.png)

RYB 色轮显示和谐互补色

计算和谐颜色的最简单方法是取色轮上与我们相对的颜色（称为直接互补色）。然而，具有艺术视野的人认为这有些显而易见，缺乏微妙之处，并更喜欢所谓的分裂互补色。这意味着从那些与直接互补色紧密相邻的颜色中进行选择，如前所示。

当选择重点颜色时，主题编辑器在颜色选择器下方建议几种分裂互补色。然而，它也建议类似的和谐色。这些颜色与原色接近，虽然看起来很好，但不适合作为重点颜色的选择，因为对比度小，用户可能会错过重要的提示。

有一个非常令人愉悦的 JetBrains 插件可用，可以将材料主题应用于 IDE 本身。它可以在以下网址找到：[plugins.jetbrains.com/androidstudio/plugin/8006-material-theme-ui](https://plugins.jetbrains.com/plugin/8006-material-theme-ui)。

正如我们刚才看到的，主题编辑器在生成材料主题时非常有帮助。还有越来越多的在线工具可以通过几次点击生成完整的 XML 材料主题。MaterialUps 可以在以下网址找到：[www.materialpalette.com](http://www.materialpalette.com)。

这将生成以下`colors.xml`文件：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<resources> 
    <color name="primary">#673AB7</color> 
    <color name="primary_dark">#512DA8</color> 
    <color name="primary_light">#D1C4E9</color> 
    <color name="accent">#FFEB3B</color> 
    <color name="primary_text">#212121</color> 
    <color name="secondary_text">#757575</color> 
    <color name="icons">#FFFFFF</color> 
    <color name="divider">#BDBDBD</color> 
</resources> 
```

乍一看，这看起来像是选择主题属性的快速方法，但是如果查看文本颜色，你会发现它们是灰色的阴影。根据材料设计指南，这是不正确的，应该使用 alpha 通道使用透明度创建阴影。当文本放在纯色背景上时，这没有什么区别，但当放在图像上时，灰度文本可能更难阅读，特别是浅色阴影，如此所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/c741db61-a0df-40d4-9a33-0cb0cc0293d1.png)

灰度与透明度

Android 主题允许我们以颜色的形式定义应用程序的外观，但通常我们希望做的不仅仅是自定义文本的颜色，能够以与其他资源类似的方式包含字体是最近非常有用的补充。

# XML 字体

从 API 级别 26 开始，可以将字体作为 XML 资源包含在`res`目录中。这一特性简化了在应用程序中使用非默认字体的任务，并使该过程与其他资源管理保持一致。

添加 XML 字体非常简单，如下练习所示：

1.  右键单击`res`目录，然后选择“新建|Android 资源目录”。

1.  从资源类型下拉菜单中选择字体，然后单击“确定”。

1.  右键单击新创建的字体文件夹，然后选择在资源管理器中显示。

1.  重命名您的字体文件，使其只包含可允许的字符。例如，`times_new_roman.ttf`而不是`TimesNewRoman.ttf`。

1.  将所选字体放入字体目录中。

1.  现在可以直接从编辑器中预览这些。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/6bb1077d-554b-40f9-b5f3-b89139305ce1.png)

XML 字体。

在布局中使用这些字体甚至比将它们添加为资源更简单。只需使用`fontFamily`属性，如下所示：

```kt
<TextView
         . . .
        android:fontFamily="@font/just_another_hand"
         . . . />
```

在处理字体时，通常希望以各种方式强调单词，比如使用更粗的字体或使文本变斜体。与其为每个版本依赖不同的字体，更方便的做法是能够引用字体组或字体系列。只需右键单击您的`font`文件夹，然后选择新建|字体资源文件。这将创建一个空的字体系列文件，然后可以按照以下方式填写：

```kt
<?xml version="1.0" encoding="utf-8"?>
<font-family >
    <font
        android:fontStyle="bold"
        android:fontWeight="400"
        android:font="@font/some_font_bold" />

    <font
        android:fontStyle="italic"
        android:fontWeight="400"
        android:font="@font/some_font_italic" />
</font-family>
```

当然，设计语言远不止于选择正确的颜色和字体。关于间距和比例有惯例，通常还有一些特别设计的屏幕组件。在材料的情况下，这些组件采用小部件和布局的形式，例如 FAB 和滑动抽屉。这些不是作为原生 SDK 的一部分提供的，而是包含在设计支持库中。

# 设计库

如前所述，设计支持库提供了在材料应用程序中常见的小部件和视图。

正如您所知，设计库和其他支持库一样，需要在模块级`build.gradle`文件中作为 gradle 依赖项包含，如下所示：

```kt
dependencies { 
    compile fileTree(include: ['*.jar'], dir: 'libs') 
    androidTestCompile('com.android.support.test.espresso:espresso-
      core:2.2.2', { 
          exclude group: 'com.android.support', module: 'support-
                annotations' 
    }) 
    compile 'com.android.support:appcompat-v7:25.1.1' 
    testCompile 'junit:junit:4.12' 
    compile 'com.android.support:design:25.1.1' 
} 
```

虽然了解事情是如何做的总是有用的，但实际上，有一个很好的快捷方式可以将支持库添加为项目依赖项。从文件菜单中打开项目结构对话框，然后选择您的模块和依赖项选项卡。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/27b24fa4-b5ac-4490-937b-f8f2fced5073.png)

项目结构对话框

您可以通过单击右上角的添加图标并从下拉菜单中选择库依赖项来选择您想要的库。

可以使用*Ctrl* + *Alt* + *Shift* + *S*键来召唤项目结构对话框。

使用这种方法还有另外两个优点。首先，IDE 将自动重建项目，其次，它将始终导入最新的修订版本。

许多开发人员通过使用加号来预防未来的修订，如下所示：`compile 'com.android.support:design:25.1.+'`。这样可以应用未来的次要修订。但是，这并不总是保证有效，并且可能会导致崩溃，因此最好手动保持版本最新，即使这意味着发布更多更新。

除了导入设计库之外，如果您计划开发材料应用程序，您很可能还需要`CardView`和`RecyclerView`库。

熟悉 IDE 的最佳方法是通过实际示例进行操作。在这里，我们将制作一个简单的天气应用程序。它不会很复杂，但它将带领我们完成应用程序开发的每个阶段，并且将遵循材料设计准则。

# 协调布局

设计库提供了三个布局类。有一个用于设计表格活动，一个用于工具栏，但最重要的布局是`CoordinatorLayout`，它充当材料感知容器，自动执行许多材料技巧，例如当用户滚动到列表顶部时扩展标题，或者在弹出的小吃栏出现时确保 FAB 滑出。

协调布局应放置在活动的根布局中，并且通常看起来像以下行：

```kt
<android.support.design.widget.CoordinatorLayout  

    android:id="@+id/coordinator_layout" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:fitsSystemWindows="true"> 

    . . . 

</android.support.design.widget.CoordinatorLayout> 
```

属性`fitsSystemWindows`特别有用，因为它将状态栏设置为部分透明。这样可以使我们的设计主导本机控件，而不会完全隐藏它们，同时避免与系统颜色发生冲突。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/bb5d710f-3e6e-4f7f-b6cb-129f809aedd1.png)

在状态栏后面绘制

还可以使用`colorPrimaryDark`来分配状态栏的颜色，将`fitsSystemWindows`与我们自己选择的颜色结合起来。

导航栏的颜色也可以使用`navigationBarColor`属性进行更改，但这并不建议，因为具有软导航控件的设备正在变得越来越少。

`CoordinatorLayout`与`FrameLayout`非常相似，但有一个重要的例外。协调布局可以使用`CoordinatorLayout.Behavior`类直接控制其子项。最好的方法是通过一个例子来看看它是如何工作的。

# Snackbar 和浮动操作按钮

Snackbar 和**浮动操作按钮**（**FABs**）是最具代表性的 Material 小部件之一。尽管它并不完全取代 toast 小部件，但 Snackbar 提供了一种更复杂的活动通知形式，允许控件和媒体而不仅仅是文本，而这是 toast 的情况。FABs 执行与传统按钮相同的功能，但使用它们的位置来指示它们的功能。

如果没有协调布局来控制行为，`Snackbar`从屏幕底部升起会遮挡其后的任何视图或小部件。如果小部件能够优雅地滑出去，这将更可取，这是你在设计良好的 Material 应用中经常看到的情况。以下练习解释了如何实现这一点：

1.  在 Android Studio 中开始一个新项目。

1.  在这里用`CoordinatorLayout`替换主活动的根布局：

```kt
<android.support.design.widget.CoordinatorLayout  

    android:id="@+id/coordinator_layout" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:fitsSystemWindows="true"> 
```

1.  添加以下按钮：

```kt
<Button 
    android:id="@+id/button" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:layout_gravity="top|start" 
    android:layout_marginStart= 
            "@dimen/activity_horizontal_margin" 
    android:layout_marginTop= 
            "@dimen/activity_vertical_margin" 
    android:text="Download" />
```

1.  接着是`Snackbar`：

```kt
<android.support.design.widget.FloatingActionButton 
    android:id="@+id/fab" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:layout_gravity="bottom|end" 
    android:layout_marginBottom= 
            "@dimen/activity_vertical_margin" 
    android:layout_marginEnd= 
            "@dimen/activity_horizontal_margin" 
    app:srcCompat="@android:drawable/stat_sys_download" /> 
```

1.  打开主活动的 Java 文件，并扩展类声明以实现点击监听器，如下所示：

```kt
public class MainActivity 
    extends AppCompatActivity 
    implements View.OnClickListener 
```

1.  这将生成一个错误，然后会出现一个红色的灯泡（称为快速修复）。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/9d50dbb5-d39a-4ab4-a132-302acbc0fa43.png)

快速修复

1.  选择实现方法以添加`OnClickListener`。

1.  在类中添加以下字段：

```kt
private Button button; 
private CoordinatorLayout coordinatorLayout; 
```

1.  在`onCreate()`方法中为这些组件创建引用：

```kt
coordinatorLayout = (CoordinatorLayout)  
    findViewById(R.id.coordinator_layout); 
button = (Button) 
    findViewById(R.id.button); 
```

1.  将按钮与监听器关联，如下所示：

```kt
button.setOnClickListener(this); 
```

1.  然后按照以下方式完成监听器方法：

```kt
@Override 
public void onClick(View v) { 
    Snackbar.make(coordinatorLayout, 
            "Download complete", 
            Snackbar.LENGTH_LONG).show(); 
    } 
} 
```

现在可以在模拟器或真实设备上测试这段代码。单击按钮将临时显示`Snackbar`，并将 FAB 滑开以便显示。

`Snackbar`在之前的演示中的行为与 toast 完全相同，但`Snackbar`是`ViewGroup`而不是像 toast 那样的视图；作为布局，它可以充当容器。要查看如何实现这一点，请用以下方法替换之前的监听器方法：

```kt
@Override 
public void onClick(View v) { 
    Snackbar.make(coordinatorLayout, 
            "Download complete", 
            Snackbar.LENGTH_LONG) 
            .setAction("Open", new View.OnClickListener() { 

                @Override 
                public void onClick(View v) { 
                    // Perform action here 
                } 

            }).show(); 
    } 
} 

```

FAB 如何在`Snackbar`的遮挡下自动移开是由父协调布局自动处理的，对于所有设计库小部件和 ViewGroups 都是如此。我们很快将看到，当包含原生视图时，如文本视图和图像，我们必须定义自己的行为。我们也可以自定义设计组件的行为，但首先我们将看一下其他设计库组件。

# 可折叠的应用栏

另一个广为人知的 Material 设计特性是可折叠的工具栏。通常包含相关的图片和标题。当用户滚动到内容顶部时，这种类型的工具栏将填充屏幕的大部分空间，当用户希望查看更多内容并向下滚动时，它会巧妙地躲开。这个组件有一个有用的目的，它提供了一个很好的品牌机会，让我们的应用在视觉上脱颖而出，但它不会占用宝贵的屏幕空间。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/e8444936-2ecf-4ca5-a266-7ad55a6728c6.png)

一个可折叠的应用栏

查看它的构造方式最好的方法是查看其背后的 XML 代码。按照以下步骤重新创建它：

1.  在 Android Studio 中开始一个新的项目。我们将创建以下布局：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/749cc7ea-4917-435a-8ed7-2aa1454447a0.png)

项目组件树

1.  首先打开`styles.xml`文件。

1.  确保父主题不包含操作栏，如下所示：

```kt
<style name="AppTheme" 
    parent="Theme.AppCompat.Light.NoActionBar"> 
```

1.  如果要使用半透明状态栏，请添加以下行：

```kt
<item name="android:windowTranslucentStatus">true</item> 
```

1.  与以前一样，创建一个以`CoordinatorLayout`为根的布局文件。

1.  接下来，嵌套以下`AppBarLayout`：

```kt
<android.support.design.widget.AppBarLayout 
    android:id="@+id/app_bar" 
    android:layout_width="match_parent" 
    android:layout_height="300dp" 
    android:fitsSystemWindows="true" 
    android:theme="@style/ThemeOverlay 
        .AppCompat 
        .Dark 
        .ActionBar"> 
```

1.  在其中，添加`CollapsingToolbarLayout`：

```kt
<android.support.design.widget.CollapsingToolbarLayout 
    android:id="@+id/collapsing_toolbar" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:fitsSystemWindows="true" 
    app:contentScrim="?attr/colorPrimary" 
    app:expandedTitleMarginEnd="64dp" 
    app:expandedTitleMarginStart="48dp" 
    app:layout_scrollFlags="scroll|exitUntilCollapsed" 
    app:> 
```

1.  在工具栏中，添加这两个小部件：

```kt
<ImageView 
    android:id="@+id/image_toolbar" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:fitsSystemWindows="true" 
    android:scaleType="centerCrop" 
    app:layout_collapseMode="parallax" 
    app:srcCompat="@drawable/some_image" /> 

<android.support.v7.widget.Toolbar 
    android:id="@+id/toolbar" 
    android:layout_width="match_parent" 
    android:layout_height="?attr/actionBarSize" 
    app:layout_collapseMode="pin" 
    app:popupTheme="@style/ThemeOverlay.AppCompat.Light" /> 
```

1.  在`AppBarLayout`下面，放置`NestedScrollView`和`TextView`：

```kt
<android.support.v4.widget.NestedScrollView 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    app:layout_behavior= 
        "@string/appbar_scrolling_view_behavior"> 

    <TextView 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" 
        android:padding="@dimen/activity_horizontal_margin" 
        android:text="@string/some_string" 
        android:textSize="16sp" /> 

</android.support.v4.widget.NestedScrollView> 
```

1.  最后添加一个 FAB：

```kt
<android.support.design.widget.FloatingActionButton 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:layout_margin="@dimen/activity_horizontal_margin" 
    app:layout_anchor="@id/app_bar" 
    app:layout_anchorGravity="bottom|end" 
    app:srcCompat="@android:drawable/ic_menu_edit" /> 
```

如果现在在设备或模拟器上测试这个，你会看到工具栏会自动折叠和展开，无需任何编程，这就是设计库的美妙之处。要在没有它的情况下编写这种行为将是一个漫长而常常困难的过程。

前面的大部分 XML 都是不言自明的，但有一两个点值得一看。

# 原始文本资源

为了演示滚动行为，前面文本视图中使用了一个较长的字符串。这个字符串放在了`strings.xml`文件中，虽然这样做完全没有问题，但并不是管理长文本的优雅方式。这种文本最好作为可以在运行时读取的文本文件资源来处理。

以下步骤演示了如何做到这一点：

1.  准备一个纯文本文件。

1.  通过右键单击项目资源管理器中的`res`文件夹并选择`New | Directory`来创建一个名为`raw`的目录。

1.  将文本文件添加到此目录。

可以从资源管理器上下文菜单快速打开项目目录。

1.  打开包含要填充文本视图的 java 活动，并添加此函数：

```kt
private StringBuilder loadText(Context context) throws IOException { 
    final Resources resources = this.getResources(); 
    InputStream stream = resources 
        .openRawResource(R.raw.weather); 
    BufferedReader reader =  
        new BufferedReader( 
        new InputStreamReader(stream)); 
    StringBuilder stringBuilder = new StringBuilder(); 
    String text; 

    while ((text = reader.readLine()) != null) { 
        stringBuilder.append(text); 
    } 

    reader.close(); 
    return stringBuilder; 
} 
```

1.  最后，将此代码添加到`onCreate()`方法中：

```kt
TextView textView = (TextView) 
    findViewById(R.id.text_view); 

StringBuilder builder = null; 

try { 
    builder = loadText(this); 
} catch (IOException e) { 
    e.printStackTrace(); 
} 

textView.setText(builder); 
```

在前面的演示中，另一个要点是在扩展工具栏的高度上使用了硬编码值，即`android:layout_height="300dp"`。这在被测试的模型上运行得很好，但要在所有屏幕类型上实现相同的效果可能需要创建大量的替代布局。一个更简单的解决方案是只重新创建`dimens`文件夹，例如，可以简单地复制和粘贴`dimens-hdpi`，然后只编辑适当的值。甚至可以创建一个单独的文件来包含这个值。另一种解决这个问题的方法是使用专为这种情况设计的支持库。

# 百分比库

百分比支持库只提供了两个布局类`PercentRelativeLayout`和`PercentFrameLayout`。需要将其添加到 gradle 构建文件中作为依赖项，如下所示：

```kt
compile 'com.android.support:percent:25.1.1' 
```

为了重新创建上一节中的布局，我们需要将`AppBarLayout`放在`PercentRelativeLayout`中。然后我们可以使用百分比值来设置我们应用栏的最大高度，如下所示：

```kt
<android.support.percent.PercentRelativeLayout 

  android:layout_width="match_parent" 
  android:layout_height="match_parent"> 

    <android.support.design.widget.AppBarLayout 
        android:id="@+id/app_bar" 
        android:layout_width="match_parent" 
        android:layout_height="30%" 
        android:fitsSystemWindows="true" 
        android:theme="@style/ThemeOverlay 
            .AppCompat 
            .Dark 
            .ActionBar"> 

        . . .  

    </android.support.design.widget.AppBarLayout> 

</android.support.percent.PercentRelativeLayout>    
```

这种方法节省了我们不得不创建大量替代布局来在众多设备上复制相同效果的麻烦，尽管总是需要生成多个。

实现这种统一性的另一种有效方法是创建我们的图像可绘制对象，使其在 dp 中具有所需的确切高度，并在 XML 中将布局高度设置为`wrap_content`。然后我们只需要为每个所需的指定资源目录创建一个图像，这是我们很可能会做的事情。

总之，前面的工具使得设计材料界面变得简单直观，并提供了减少为用户提供的令人困惑的设备准备布局所需的时间的方法。

# 总结

在本章中，我们在上一章的基础上探讨了如何使用协调布局及其相关库来轻松构建更复杂的布局，这些库可以为我们做很多工作，比如自动折叠工具栏和防止小部件重叠。

我们通过探讨另一个宝贵的设计库——百分比库来结束了本章，它可以在开发针对非常不同的屏幕尺寸和形状时解决大量的设计问题。

下一章将在本章的基础上扩展，探讨更多用于界面开发的动态元素，如屏幕旋转、为可穿戴设备开发和读取传感器。


# 第四章：设备开发

Android Studio 提供了一些非常强大的布局工具，使我们能够快速轻松地尝试和开发用户界面。然而，任何 Android 开发人员面临的最大挑战可能是他们的应用程序可能在多种形态因素上运行的令人困惑的数量。

我们在之前的章节中看到了一些类，例如约束布局和百分比库等，可以帮助我们设计统一和一致的布局。然而，这些技术只提供了一般解决方案，我们都会遇到一些似乎并没有真正考虑我们设备的应用程序。通过一点知识和努力，这些设计缺陷可以很容易地避免。

在本章中，您将学习：

+   创建替代布局文件

+   提取字符串资源

+   管理屏幕旋转

+   配置资源

+   创建可穿戴 UI

+   构建形状感知布局

+   读取传感器数据

+   使用虚拟传感器

+   应用 Studio 的模板

+   创建调试过滤器

+   监视设备

在研究如何开发我们的 UI，使其在所有用户设备上都能看起来很棒之前，我们需要探索我们将遇到的最重要的布局情况：在纵向和横向模式之间旋转屏幕。

# 屏幕方向

大量为手机和平板设计的 Android 应用程序都设计为在横向和纵向模式下都能工作，并且通常会自动在这两种模式之间切换。许多活动，比如视频，在横向模式下观看效果最佳，而列表通常在纵向模式下更容易扫描；然而，有一些活动，甚至整个应用程序，其方向是固定的。

有一些布局无论以哪种方式查看都很好，但这并不经常发生；大多数情况下，我们都希望为每种方向设计一个布局。Android Studio 通过为我们节省从头开始开发替代布局的任务，简化并加快了这个过程。

以这里的简单布局为例：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/b68e6b36-0318-4852-8875-94af4d3edc75.png)

纵向布局

可以通过在设计编辑器顶部的布局变体工具中单击一次来创建横向变体，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/19fba689-187b-4295-83ce-8e0026bb9d00.png)

布局变体工具。

如果您重新创建此练习或创建自己的等效练习，您很快会发现，这样的布局在旋转时看起来并不好，您将不得不重新调整视图以最适合这个纵横比。如果您尝试使用约束布局，您将发现它的一些弱点，而且最终的布局可能会非常混乱。

您如何重新创建这些布局取决于您自己的艺术和设计技能，但值得注意的是 Android Studio 存储和呈现这些文件的方式，这可能有点令人困惑，特别是如果您正在从管理方式不同的 Eclipse 迁移。

如果您在项目资源管理器中打开刚刚创建的项目，在 Android 下，您将在`activity_main.xml (land)`中找到横向变体，显然在`activity_main.xml`目录中。Studio 以这种方式呈现它，因为将所有布局放在一个地方很方便，但这并不是它们的存储方式。将项目资源管理器切换到项目视图将显示实际的文件结构，如下所示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/e32b1477-579f-4676-921e-8ac8adb9b3ce.png)

项目结构。

这种结构也可以从 IDE 顶部的导航栏中确定。

如果您创建类似这样的布局变体，将视图移动到更令人愉悦的配置，并为两个版本赋予相同的 ID，当用户旋转其设备时，这些将自动在它们的两个状态之间进行动画。我们将在后面看到如何构建我们自己的自定义动画，但往往默认动画是最好的选择，因为它们有助于促进统一的用户体验。

如果你重新创建了上面的示例，你可能已经注意到 IDE 执行的一个非常巧妙的技巧，以加快提供文本资源的过程。

你可能已经知道，使用硬编码字符串是强烈不推荐的。像许多编程范式一样，Android 开发旨在使数据和代码分开创建和处理。硬编码字符串也几乎不可能进行翻译。

我们之前看到快速修复功能如何让我们自动实现方法。在这里，我们可以使用它来创建字符串资源，甚至无需打开`strings.xml`文件。

只需在布局文件中输入硬编码的字符串，然后按照快速修复提示将其提取为字符串资源。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/b830abda-83eb-49a7-a67e-f1bcad19159f.png)

字符串资源提取。

布局编辑器提供了两个现成的变体，横向和超大，但我们可以创建适合任何形态因素的自定义变体。

现在我们已经开始添加一些动态元素，比如屏幕旋转，布局编辑器已经不够用了，我们需要在设备或仿真器上运行我们的应用程序。

# 虚拟设备

很长一段时间以来，Android 虚拟设备（AVD）一直以有 bug 和运行极慢而闻名。硬件加速的引入带来了很大的改变，但仍建议使用一台性能强大的计算机，特别是如果你想同时运行多个 AVD，这种情况经常发生。

Android 仿真的最大变化不是硬件加速，而是替代仿真器的出现。正如我们将很快看到的，其中一些提供了与本机仿真器不同的优势，但 AVD 不应被忽视。尽管存在缺点，Android 仿真器是唯一可以在所有 Android 版本上运行的仿真器，包括最新的仅供开发者使用的版本。不仅如此，Android 仿真器是最可定制的，任何可能的硬件或软件配置都可以通过一点努力重新创建。

在开发过程的早期阶段，能够快速测试我们的想法非常重要，使用一两个真实设备可能是最好的选择；然而，迟早我们需要确保我们的布局在所有可能的设备上看起来很棒。

# 布局和图像资格

这里有两个问题需要考虑：屏幕密度和纵横比。如果你之前做过任何 Android 开发，你会了解 DPI 和屏幕大小分组。这些指定的文件夹提供了方便的快捷方式，以适应各种可用的形态因素，但我们都会遇到布局在我们设备上不太适用的应用。这是完全可以避免的，尽管我们需要付出一些努力来对抗它，但这将避免那些可能损害收入流的差评。

很容易产生一个能在尽可能多的形态因素上运行的应用程序的诱惑，而 Android Studio 偶尔会鼓励你这样思考。实际上，我们必须考虑设备的使用时间和地点。如果我们在等公交车，那么我们可能想要一个可以轻松开关并且可以快速完成任务的游戏。尽管也有例外，但这些不是人们选择在大屏幕上长时间玩耍的游戏。选择正确的平台是至关重要的，尽管这可能听起来违反直觉，但通常排除一个平台比仅仅假设它可能赚取更多收入更明智。

考虑到这一点，我们将考虑一个仅设计用于手机和平板电脑的应用程序；然而，除了查看屏幕大小和密度等熟悉的功能之外，我们还将看到如何为许多其他配置问题提供定制资源。

最常用的资源指定是屏幕大小和密度。Android 提供了以下四种大小指定。

+   `layout-small`：从两到四英寸，320 x 420dp 或更大

+   `layout-normal`：从三到五英寸，320 x 480dp 或更大

+   `layout-large`：从四到七英寸，480 x 640dp 或更大

+   `layout-xlarge`：从七到十英寸，720 x 960dp 或更大

如果您正在为 Android 3.0（API 级别 11）或更低版本开发，这个范围较低的设备通常会被错误地分类。唯一的解决方案是为单独的设备进行配置，或者根本不开发这些设备。

一般来说，我们需要为上述每种尺寸制作一个布局。

使用**密度无关像素**（**dp**或**dip**）意味着我们不需要为每个密度设置设计新的布局，但我们必须为每个密度类提供单独的可绘制资源，如下所示。

+   `drawable-ldpi` 〜120dpi

+   `drawable-mdpi` 〜160dpi

+   `drawable-hdpi` 〜240dpi

+   `drawable-xhdpi` 〜320dpi

+   `drawable-xxhdpi` 〜480dpi

+   `drawable-xxxhdpi` 〜640dpi

上述列表中的 dpi 值告诉我们我们的资源需要的像素相对大小。例如，`drawable-xhdpi`目录中的位图需要是`drawable-mdpi`文件夹中相应位图大小的两倍。

实际上不可能在每台设备上创建完全相同的输出，这甚至不可取。人们购买高端设备是因为他们想要令人惊叹的图像和精细的细节，我们应该努力提供这种质量水平。另一方面，许多人购买小型和价格较低的设备是出于便利和预算的原因，我们应该在设计中反映这些选择。与其试图在所有设备上完全复制相同的体验，我们应该考虑人们选择设备的原因以及他们想要从中获得什么。

以下简短的练习演示了这些差异如何在不同的屏幕配置中表现出来。这将让读者有机会看到如何最好地利用用户选择的设备，利用他们自己的艺术和设计才能。

1.  选择任何高分辨率图像，最好是一张照片。

1.  使用您选择的任何工具，创建一个宽度和高度为原始尺寸一半的副本。

1.  打开一个新的 Android Studio 项目。

1.  从项目资源管理器中，在 res 目录内创建两个名为`drawable-mdpi`和`drawable-hdpi`的新文件夹。

1.  将准备好的图像放入这些文件夹中。

1.  构建一个带有图像视图和一些文本的简单布局。

1.  创建两个虚拟设备，一个密度为`mdpi`，一个为`hdpi`。

1.  最后，在每个设备上运行应用程序以观察差异。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/c32e343f-ac39-4a5b-a430-c4cbe157edba.png)

密度为 mdpi 和 hdpi 的设备。

这实际上并不是我们可以使用的唯一密度限定符。为电视设计的应用程序通常使用`tvdpi`限定符。这个值介于`mdpi`和`hdpi`之间。还有`nodpi`限定符，当我们需要精确的像素映射时使用，以及`anydpi`，当所有艺术作品都是矢量可绘制时使用。

还有很多其他限定符，完整列表可以在以下网址找到：

[developer.android.com/guide/topics/resources/providing-resources.html](http://developer.android.com/guide/topics/resources/providing-resources.html)

现在值得看一下一些更有用的限定符。

# 比例和平台

像之前讨论过的那样的概括限定符非常有用，适用于大多数情况，并且节省了我们大量的时间。然而，有时我们需要更精确的关于我们的应用程序运行设备的信息。

我们想要了解的最重要的功能之一是屏幕尺寸。我们已经遇到了诸如小型、普通和大型之类的限定符，但我们也可以配置更精确的尺寸。其中最简单的是可用宽度和可用高度。例如，`res/layout/w720dp`中的布局只有在可用宽度至少为 720dp 时才会被填充，而`res/layout/h1024dp`中的布局则在屏幕高度等于或大于 1024dp 时被填充。

另一个非常方便的功能是配置平台版本号的资源。这是基于 API 级别的。因此，当在 Android Jelly Bean 设备上运行时，可以使用`v16`的限定符来使用资源。

能够为如此广泛的硬件选择和准备资源意味着我们可以为那些能够显示它们的设备提供丰富的资源，对于容量较小的设备则提供更简单的资源。无论我们是为预算手机还是高端平板开发，我们仍然需要一种测试应用程序的方法。我们已经看到了 AVDs 的灵活性，但很值得快速看一下其他一些选择。

# 替代模拟器

最好的替代模拟器之一可能是 Genymotion。不幸的是，这个模拟器不是免费的，也不像原生 AVDs 那样及时更新，但它速度快，支持拖放文件安装和移动网络功能。它可以在以下网址找到：

[www.genymotion.com](http://www.genymotion.com)

另一个快速且易于使用的模拟器是 Manymo。这是一个基于浏览器的模拟器，其主要目的是测试 Web 应用程序，但对于移动应用程序也非常有效。它也不是免费的，但它有各种各样的预制形态因子。它可以在以下网址找到：

[www.manymo.com](http://www.manymo.com)

在这方面还有一个类似的工具是 Appetize，它位于：

[appetize.io](http://appetize.io)

这样的模拟器越来越多，但上面提到的那些可能是从开发的角度来看最功能齐全的。以下列表将读者引向其他一些模拟器：

+   [www.andyroid.net](http://www.andyroid.net)

+   [www.bluestacks.com/app-player.html](http://www.bluestacks.com/app-player.html)

+   [www.droid4x.com](http://www.droid4x.com)

+   [drive.google.com/file/d/0B728YkPxkCL8Wlh5dGdiVXdIS0k/edit](http://drive.google.com/file/d/0B728YkPxkCL8Wlh5dGdiVXdIS0k/edit)

有一种情况下，这些替代方案都不合适，我们被迫使用 AVD 管理器，那就是当我们想要为可穿戴设备（如智能手表）开发时，这是我们接下来要看的内容。

# Android Wear

可穿戴设备最近变得非常流行，Android Wear 已完全整合到 Android SDK 中。设置 Wear 项目比其他项目稍微复杂一些，因为可穿戴设备实际上是作为应用程序的伴侣设备，应用程序本身是从移动设备上运行的。

尽管有这种轻微的复杂性，为可穿戴设备开发可能会非常有趣，至少因为它们经常为我们提供访问一些很酷的传感器，比如心率监测器。

# 连接到可穿戴 AVD

也许您有可穿戴设备，但在以下练习中我们将使用模拟器。这是因为这些设备有两种类型：方形和圆形。

当要将这些模拟器之一与手机或平板配对时，可以使用真实设备或另一个模拟器，但最好使用真实设备，因为这会对计算机造成较小的压力。这两种方法略有不同。以下练习假设您正在将可穿戴模拟器与真实设备配对，并解释了如何在最后与模拟移动设备配对。

1.  在做任何其他事情之前，打开 SDK 管理器并检查是否已下载了 Android Wear 系统镜像：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/b4f5a271-696e-46cb-91f8-93235d4ccf00.png)

1.  打开 AVD 管理器并创建两个 AVD，一个是圆形的，一个是方形的。

1.  在手机上从 Play 商店安装 Android Wear 应用程序，并将其连接到计算机。

1.  找到并打开包含`adb.exe`文件的目录。这可以在`\AppData\Local\Android\Sdk\platform-tools\`中找到。

1.  发出以下命令：

```kt
adb -d forward tcp:5601 tcp:5601
```

1.  在手机上启动伴侣应用程序，并按照屏幕上的说明配对设备。

每次重新连接手机时，您都需要执行端口转发命令。

如果要将可穿戴设备与虚拟手机配对，该过程非常类似，唯一的区别是伴侣应用程序的安装方式。按照以下步骤来实现这一点：

1.  启动或创建一个目标为 Google APIs 的 AVD。

1.  下载`com.google.android.wearable.app-2.apk`。有很多在线地方可以找到这个文件，比如 www.file-upload.net/download。

1.  将文件放入 platform-tools 文件夹中，并使用以下命令进行安装：

```kt
adb install com.google.android.wearable.app-2.apk 
```

1.  启动可穿戴 AVD 并在命令提示符（或者如果您在 Mac 上，则在终端）中输入`adb devices`来检查两个设备是否可见。

1.  输入`adb telnet localhost 5554`，其中`5554`是手机模拟器。

1.  最后输入`adb redir add tcp:5601:5601`。您现在可以像之前的练习一样在模拟手机上使用穿戴应用程序配对设备。

尽管它是自动为我们添加的，但重要的是要理解 Android Wear 应用程序需要一个支持库。这可以通过检查`build.gradle`文件中的模块级别来看到。

```kt
 compile 'com.google.android.gms:play-services-wearable:10.2.0' 
```

现在我们的设备已经配对，我们可以开始实际开发和设计我们的可穿戴应用程序了。

# 可穿戴布局

在 Android Wear UI 开发中最有趣的挑战之一是这些智能手表的两种不同形状。我们可以以两种方式来解决这个问题。

其中一种类似于我们之前管理事物的方式，并涉及为每种形态因素设计布局，而另一种技术使用一种产生适用于任何形状的布局的方法。

除了这些技术之外，可穿戴支持库还配备了一些非常方便的小部件，适用于曲面和圆形布局以及列表。

Android Studio 最有用和有教育意义的功能之一是在项目首次设置时提供的项目模板。这些模板有很好的选择，它们为大多数项目提供了良好的起点，特别是穿戴应用程序。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a15c089f-644e-4bfa-bdd4-5cc873a653a6.png)

穿戴模板

从这种方式开始一个项目可能是有帮助和启发性的，甚至空白的活动模板设置了 XML 和 Java 文件，创建了一个非常可信的起点。

如果您从空白的穿戴活动开始一个项目，您会注意到，我们之前只有一个模块（默认称为 app），现在有两个模块，一个称为 mobile，取代了 app，另一个名为 wear。这两个模块的结构与我们之前遇到的相同，包含清单、资源目录和 Java 活动。

# WatchViewStub 类

空白的穿戴活动模板应用了我们之前讨论的管理不同设备形状的第一种技术。这采用了`WatchViewStub`类的形式，可以在`wear/src/main/res/layout`文件夹中找到。

```kt
<?xml version="1.0" encoding="utf-8"?> 
<android.support.wearable.view.WatchViewStub  

    android:id="@+id/watch_view_stub" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    app:rectLayout="@layout/rect_activity_main" 
    app:roundLayout="@layout/round_activity_main" 
    tools:context="com.mew.kyle.wearable.MainActivity" 
    tools:deviceIds="wear" /> 
```

如前面的示例所示，主要活动将系统引导到两种形状的布局之一，模板也提供了这两种布局。

正如您所看到的，这不是我们之前选择正确布局的方式，这是因为`WatchViewStub`的操作方式不同，并且需要一个专门的监听器，一旦`WatchViewStub`检测到手表的类型，它就会填充我们的布局。这段代码也是模板在主活动 Java 文件中提供的：

```kt
@Override 
protected void onCreate(Bundle savedInstanceState) { 
    super.onCreate(savedInstanceState); 
    setContentView(R.layout.activity_main); 

    final WatchViewStub stub = (WatchViewStub) 
            findViewById(R.id.watch_view_stub); 

    stub.setOnLayoutInflatedListener(new WatchViewStub.OnLayoutInflatedListener() { 

        @Override 
        public void onLayoutInflated(WatchViewStub stub) { 
            mTextView = (TextView) stub.findViewById(R.id.text); 
        } 

    }); 
} 
```

诱人的是认为`WatchViewStub`是我们设计可穿戴布局所需的全部。它允许我们独立设计两个表盘，这正是我们想要做的。然而，可穿戴布局通常非常简单，复杂的设计被强烈不鼓励。因此，对于一个简单的设计，几乎只有一张图片和一个按钮，拥有一个`shape-aware`类，根据设备的形状分发其内容，只是一种方便。这就是`BoxInsetLayout`类的工作原理。

# 形状感知布局

`BoxInsetLayout`类是 Wear UI 库的一部分，允许我们设计一个布局，可以优化自身适应方形和圆形表盘。它通过在任何圆形框架内充气最大可能的正方形来实现这一点。这是一个简单的解决方案，但`BoxInsetLayout`还非常好地确保我们选择的任何背景图像始终填充所有可用空间。正如我们将在一会儿看到的，如果您将组件水平放置在屏幕上，`BoxInsetLayout`类会自动分发它们以实现最佳适配。

在使用 Android Studio 开发时，您将想要做的第一件事情之一是利用布局编辑器提供的强大预览系统。这提供了每种可穿戴设备的预览，以及您可能创建的任何 AVD。这在测试布局时节省了大量时间，因为我们可以直接从 IDE 中查看，而无需启动 AVD。

预览工具可以从`View | Tool Windows`菜单中访问；或者，如果布局文本编辑器打开，可以在右侧边距中找到，默认情况下。

与`WatchViewStubs`不同，`BoxInsetLayout`类不是由任何模板提供的，必须手动编码。按照以下简短步骤，使用`BoxInsetLayout`类构建动态的 Wear UI。

1.  将以下`BoxInsetLayout`创建为 wear 模块中主 XML 活动的根容器：

```kt
<android.support.wearable.view.BoxInsetLayout  

    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:background="@drawable/snow" 
    android:padding="15dp"> 

</android.support.wearable.view.BoxInsetLayout> 
```

1.  将这个`FrameLayout`放在`BoxInsetLayout`类中：

```kt
<FrameLayout 
    android:id="@+id/wearable_layout" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:padding="5dp" 
    app:layout_box="all"> 

</FrameLayout> 
```

1.  在`FrameLayout`中包括这些小部件（或您自己选择的小部件）：

```kt
<TextView 
    android:layout_width="match_parent" 
    android:layout_height="wrap_content" 
    android:gravity="center" 
    android:text="@string/weather_warning" 
    android:textAppearance= 
        "@style/TextAppearance.WearDiag.Title" 
    tools:textColor="@color/primary_text_light" /> 

<ImageView 
    android:layout_width="60dp" 
    android:layout_height="60dp" 
    android:layout_gravity="bottom|start" 
    android:contentDescription= 
        "@string/generic_cancel" 
    android:src="img/ic_full_cancel" /> 

<ImageView 
    android:layout_width="60dp" 
    android:layout_height="60dp" 
    android:layout_gravity="bottom|end" 
    android:contentDescription= 
        "@string/buttons_rect_right_bottom" 
    android:src="img/ic_full_sad" />
```

1.  最后，在圆形和方形模拟器上运行演示：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/b138abb9-7ed0-4478-8ea6-7473de6a2740.png)

BoxInsetLayout

`BoxInsetLayout`类非常易于使用。它不仅节省我们的时间，还可以保持应用的内存占用量，因为即使是最简单的布局也有一定的成本。在圆形视图中，它可能看起来有些浪费空间，但是 Wear UI 应该是简洁和简化的，空白空间不是应该避免的东西；一个设计良好的可穿戴 UI 应该能够被用户快速理解。

Android Wear 最常用的功能之一是心率监测器，因为我们正在处理可穿戴设备，现在是时候看看如何访问传感器数据了。

# 访问传感器

佩戴在手腕上的设备非常适合健身应用，许多型号中都包含心率监测器，使它们非常适合这样的任务。SDK 管理所有传感器的方式几乎相同，因此了解一个传感器的工作方式也适用于其他传感器。

以下练习演示了如何在可穿戴设备上读取心率传感器的数据：

1.  打开一个带有移动和可穿戴模块的 Android Wear 项目。

1.  创建您选择的布局，确保包括一个`TextView`来显示输出。

1.  在可穿戴模块的`Manifest`文件中添加以下权限：

```kt
<uses-permission 
    android:name="android.permission.BODY_SENSORS" /> 
```

1.  在可穿戴模块的`MainActivity.java`文件中添加以下字段：

```kt
private TextView textView; 
private SensorManager sensorManager; 
private Sensor sensor; 
```

1.  让`Activity`实现传感器事件监听器，如下所示：

```kt
public class MainActivity extends Activity implements SensorEventListener { 
```

1.  实现所需的方法。

1.  编辑`onCreate()`方法如下：

```kt
@Override 
protected void onCreate(Bundle savedInstanceState) { 
    super.onCreate(savedInstanceState); 
    setContentView(R.layout.activity_main); 

    textView = (TextView) findViewById(R.id.text_view); 

    sensorManager = ((SensorManager) getSystemService(SENSOR_SERVICE)); 
    sensor = sensorManager 
        .getDefaultSensor(Sensor 
        .TYPE_HEART_RATE); 
} 
```

1.  在`onResume()`方法中注册监听器，当活动启动或重新启动时：

```kt
@Override 
protected void onResume() { 
    super.onResume(); 

sensorManager.registerListener(this, this.sensor, 3); 
}
```

1.  然后添加`onPause()`方法，以确保在不需要时关闭监听器：

```kt
@Override 
protected void onPause() { 
    super.onPause() 

sensorManager.unregisterListener(this); 
} 
```

1.  最后，编辑`onSensorChanged()`回调，如下所示：

```kt
@Override 
public void onSensorChanged(SensorEvent event) { 
   textView.setText("" + (int) event.values[0] + "bpm"); 
} 
```

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/60de7bbe-5ab2-4429-b973-f89155262741.png)

如前所述，所有传感器都可以以相同的方式访问，尽管它们输出的值根据其目的而异。关于这一点的完整文档可以在以下网址找到：

[developer.android.com/reference/android/hardware/Sensor.html](http://developer.android.com/reference/android/hardware/Sensor.html)

现在，当然，读者会认为这个练习没有实际传感器的实际设备是没有意义的。幸运的是，在模拟器中弥补这种硬件缺乏的方法不止一种。

# 传感器仿真

如果您有一段时间没有使用 Android 模拟器，或者是第一次使用它们，您可能会错过每个 AVD 的扩展控件。这些可以从模拟器工具栏的底部访问。

这些扩展控件提供了许多有用的功能，比如轻松设置模拟位置和替代输入方法的能力。我们感兴趣的是虚拟传感器。这些允许我们直接模拟各种传感器和输入值：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/e797a1c2-3b12-4f31-91ad-515b15a08f87.png)

虚拟传感器

在模拟设备上运行传感器还有其他几种方法。其中大多数依赖于连接真实设备并使用它们的硬件。这些 SDK 控制器传感器可以从 Play 商店下载。GitHub 上也有一些很棒的传感器模拟器，我个人最喜欢的是：

[github.com/openintents/sensorsimulator](http://github.com/openintents/sensorsimulator)

既然我们开始开发不仅仅是静态布局，我们可以开始利用一些 Studio 更强大的监控工具。

# 设备监控

通常，只需在设备或模拟器上运行应用程序就足以告诉我们我们设计的东西是否有效，以及我们是否需要更改任何内容。但是，了解应用程序行为的实时监控情况总是很好的，而在这方面，Android Studio 有一些很棒的工具。

我们将在下一个模块中详细介绍调试，但现在玩一下**Android Debug Bridge**（**ADB**）和 Android Studio 的设备监视器工具是选择 IDE 而不是其他替代品的最重要的好处之一。

这一部分还提供了一个很好的机会来更仔细地查看项目模板，这是 Android Studio 的另一个很棒的功能。

# 项目模板

Android Studio 提供了许多有用的项目模板。这些模板设计用于一系列典型的项目类型，例如全屏应用程序或 Google 地图项目。模板是部分完成的项目，包括代码、布局和资源，可以作为我们自己创作的起点。材料设计的不断出现使得`导航抽屉活动`模板成为最常用的模板之一，也是我们将用来检查设备监视器工具的模板。

`导航抽屉活动`模板在几个方面都很有趣和有用。首先，请注意，有四个布局文件，包括我们熟悉的`activity_main.xml`文件。检查这段代码，您会注意到以下节点：

```kt
<include 
    layout="@layout/app_bar_main" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" /> 
```

这个节点的目的很简单，`app_bar_main.xml`文件包含了我们在本书前面介绍过的协调布局和其他视图。使用`<include>`标签并不是必需的，但如果我们想在另一个活动中重用该代码，它是非常有用的，当然，它会产生更清晰的代码。

这个模板中另一个值得关注的地方是在 drawable 目录中使用矢量图形。我们将在下一章中详细讨论这些，但现在知道它们提供了一个很好的方法来解决为每个屏幕密度组提供单独图像的问题，因为它们可以缩放到任何屏幕。

在我们看一下如何监视应用程序行为之前，快速查看一下主活动 Java 代码。这很好地展示了各种功能的编码方式。这些示例功能可能不符合我们的要求，但可以很容易地替换和编辑以适应我们的目的，并且可以从这个起点构建整个应用程序。

# 监控和分析

所有开发人员都希望能够在运行时监视应用程序的能力。观察用户操作对硬件组件（如内存和处理器）的实时影响是识别可能的瓶颈和其他问题的绝佳方式。Android Studio 拥有一套复杂的分析工具，将在下一个模块中进行全面讨论。然而，Android Profiler 对 UI 开发以及编码都很有用，因此在这里简要地看一下是值得的。

Android Profiler 可以从“查看|工具窗口”菜单、工具栏或按*Alt* + *6*打开。它默认出现在 IDE 底部，但可以使用设置图标进行自定义以适应个人偏好：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/0a8ad435-927c-4150-b9e8-fb2d72c87053.png)

Android Profiler

通过运行配置对话框可以使用高级分析选项；这将在下一个模块中介绍。目前还有另一个简单的调试/监控工具，对 UI 设计和开发非常有用。

分析器提供的视觉反馈提供了大量有用的信息，但这些信息是瞬息万变的，尽管高级分析允许我们记录非常详细的检查，但通常我们只需要确认特定事件发生了，或者某些事件发生的顺序。

对于这一点，我们可以使用另一个工具窗口 logcat，当我们只需要获取关于我们的应用程序如何以及在做什么的基本文本反馈时，我们可以为此创建一个 logcat 筛选器。

执行以下步骤来完成这个过程：

1.  通过“查看|工具窗口”菜单或边距打开 logcat 工具窗口。

1.  从右侧的筛选下拉菜单中选择“编辑筛选配置”。

1.  按照以下方式完成对话框：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/f67419bf-c7de-48fa-a070-2a55df527520.png)

创建 logcat 筛选器

1.  将以下字段添加到您的`main`活动中：

```kt
private static final String DEBUG_TAG = "tag"; 
```

1.  包括以下导入：

```kt
import android.util.Log;
```

1.  最后，在以下代码中添加突出显示的行：

```kt
FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab); 
fab.setOnClickListener(new View.OnClickListener() { 

    @Override 
    public void onClick(View view) { 
        Snackbar.make(view, "Replace with your own action", 
            Snackbar.LENGTH_LONG) 
                .setAction("Action", null) 
                .show(); 
        Log.d(DEBUG_TAG, "FAB clicked"); 
    } 

}); 
```

1.  在打开 logcat 并点击 FAB 运行应用程序时，将产生以下输出。

```kt
...com.mew.kyle.devicemonitoringdemo D/tag: FAB clicked 
```

尽管这个例子很简单，但这种技术的强大是显而易见的，这种调试形式是检查简单 UI 行为、程序流程和活动生命周期状态的最快、最简单的方式。

# 摘要

本章涵盖了很多内容；我们已经在之前的章节中介绍了 Android 布局的工作，并开始探索如何将这些布局从静态图形转变为更动态的结构。我们已经看到 Android 提供了使开发适应不同屏幕比其他 IDE 更容易的类和库，以及模拟器可以用来生成所有可能的形态，包括最新的平台。

在我们转向编码之前，这个模块中只剩下一个关于布局和设计的章节；在其中，我们将介绍如何管理我们可用的众多资源以及 Android Studio 如何协助我们进行管理。
