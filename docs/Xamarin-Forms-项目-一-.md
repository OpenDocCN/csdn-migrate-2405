# Xamarin.Forms 项目（一）

> 原文：[`zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA`](https://zh.annas-archive.org/md5/BCF2270FBE70F13E76739867E1CF82CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

*Xamarin.Forms 项目*是一本实践性的书，您将从头开始创建七个应用程序。您将获得设置环境所需的基本技能，我们将解释 Xamarin 是什么，然后过渡到 Xamarin.Forms，真正利用真正的本地跨平台代码。

阅读本书后，您将真正了解创建一个可以持续发展并经得起时间考验的应用程序需要什么。

我们将涵盖动画，增强现实，消费 REST 接口，使用 SignalR 进行实时聊天，以及使用设备 GPS 进行位置跟踪等内容。还有机器学习和必备的待办事项清单。

愉快的编码！

# 这本书适合谁

这本书适合熟悉 C#和 Visual Studio 的开发人员。您不必是专业程序员，但应该具备使用.NET 和 C#进行面向对象编程的基本知识。典型的读者可能是想探索如何使用 Xamarin，特别是 Xamarin.Forms，来使用.NET 和 C#创建应用程序的人。

不需要预先了解 Xamarin 的知识，但如果您曾在传统的 Xamarin 中工作并希望迈出向 Xamarin.Forms 的步伐，那将是一个很大的帮助。

# 本书涵盖内容

第一章，*Xamarin 简介*，解释了 Xamarin 和 Xamarin.Forms 的基本概念。它帮助您了解如何创建真正的跨平台应用程序的构建模块。这是本书唯一的理论章节，它将帮助您入门并设置开发环境。

第二章，*构建我们的第一个 Xamarin.Forms 应用程序*，指导您了解 Model-View-ViewModel 的概念，并解释如何使用控制反转简化视图和视图模型的创建。我们将创建一个支持导航、过滤和向列表添加待办事项的待办事项应用程序，并渲染一个利用 Xamarin.Forms 强大数据绑定机制的用户界面。

第三章，*使用动画创建丰富用户体验的匹配应用程序*，让您深入了解如何使用动画和内容放置定义更丰富的用户界面。它还涵盖了自定义控件的概念，将用户界面封装成自包含的组件。

第四章，*使用 GPS 和地图构建位置跟踪应用程序*，涉及使用设备 GPS 的地理位置数据以及如何在地图上绘制这些数据的图层。它还解释了如何使用后台服务长时间跟踪位置，以创建您花费时间的热图。

第五章，*为多种形式因素构建天气应用程序*，涉及消费第三方 REST 接口，并以用户友好的方式显示数据。我们将连接到天气服务，获取当前位置的预报，并在列表中显示结果。

第六章，*使用 Azure 服务为聊天应用程序设置后端*，是两部分章节中的第一部分，我们将设置一个聊天应用程序。本章解释了如何使用 Azure 服务创建一个后端，通过 SignalR 公开功能，以建立应用程序之间的实时通信渠道。

第七章，*构建实时聊天应用程序*，延续了前一章的内容，涵盖了应用程序的前端，即 Xamarin.Forms 应用程序，它连接到中继消息的后端，实现用户之间的消息传递。本章重点介绍了如何在客户端设置 SignalR，并解释了如何创建一个服务模型，通过消息和事件抽象化这种通信。

第八章，*创建增强现实游戏*，将两种不同的 AR API 绑定到一个 UrhoSharp 解决方案中。Android 使用 ARCore 处理增强现实，iOS 使用 ARKit 执行相同的操作。我们将通过自定义渲染器下降到特定于平台的 API，并将结果公开为 Xamarin.Forms 应用程序消耗的通用 API。

第九章，*使用机器学习识别热狗或非热狗*，涵盖了创建一个应用程序，该应用程序使用机器学习来识别图像是否包含热狗。

# 从本书中获得最大收益

我们建议您阅读第一章，以确保您对 Xamarin 的基本概念有所了解。之后，您可以选择任何您喜欢的章节来学习更多。每一章都是独立的，但章节按复杂性排序；您在书中的位置越深，应用程序就越复杂。

这些应用程序适用于实际应用，但某些部分被省略，例如适当的错误处理和分析，因为它们超出了本书的范围。然而，您应该对如何创建应用程序的基本构建块有所了解。

话虽如此，如果您是 C#和.NET 开发人员已经有一段时间了，那么会有所帮助，因为许多概念实际上并不是特定于应用程序，而是一般的良好实践，例如 Model-View-ViewModel 和控制反转。

但最重要的是，这是一本可以帮助您通过专注于最感兴趣的章节来启动 Xamarin.Forms 开发学习曲线的书籍。

# 下载示例代码文件

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Xamarin.Forms-Projects`](https://github.com/PacktPublishing/Xamarin.Forms-Projects)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789537505_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781789537505_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“打开`DescriptionGenerator.cs`文件，并添加一个构造函数，如下面的代码所示。”

代码块设置如下：

```cs
public class DescriptionGenerator
{
  private string[] _adjectives = { "nice", "horrible", "great",
                                   "terribly old", "brand new" };
  private string[] _other = { "picture of grandpa", "car", "photo
                               of a forest", "duck" };
  private static Random random = new Random();
  public string Generate()
{
  var a = _adjectives[random.Next(_adjectives.Count())];
  var b = _other[random.Next(_other.Count())];
  return $"A {a} {b}";
}
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cs
{
    TabLayoutResource = Resource.Layout.Tabbar;
    ToolbarResource = Resource.Layout.Toolbar;

    base.OnCreate(savedInstanceState);

    global::Xamarin.Forms.Forms.Init(this, savedInstanceState);
    Xamarin.Essentials.Platform.Init(this, savedInstanceState);
    LoadApplication(new App());
}
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会以这种形式出现。

提示和技巧会显示在这样的形式下。


# 第一章：Xamarin 简介

本章主要介绍 Xamarin 是什么以及可以从中期望什么。这是唯一的纯理论章节；其他章节将涵盖实际项目。您不需要在此时编写任何代码，而是简单地阅读本章，以开发对 Xamarin 是什么以及 Xamarin.Forms 与 Xamarin 的关系的高层理解。

我们将首先定义什么是原生应用程序以及.NET 作为一种技术带来了什么。之后，我们将看一下 Xamarin.Forms 如何适应更大的图景和

学习何时适合使用传统的 Xamarin 和 Xamarin.Forms。我们经常使用术语*传统的 Xamarin*来描述不使用 Xamarin.Forms 的应用程序，尽管 Xamarin.Forms 应用程序是通过传统的 Xamarin 应用程序引导的。

在本章中，我们将涵盖以下主题：

+   原生应用程序

+   Xamarin 和 Mono

+   Xamarin.Forms

+   设置开发机器

让我们开始吧！

# 原生应用程序

术语**原生应用程序**对不同的人有不同的含义。对一些人来说，这是使用平台创建者指定的工具开发的应用程序，例如使用 Objective-C 或 Swift 开发的 iOS 应用程序，使用 Java 或 Kotlin 开发的 Android 应用程序，或使用.NET 开发的 Windows 应用程序。其他人使用术语*原生应用程序*来指代编译为本机机器代码的应用程序。在本书中，我们将定义原生应用程序为具有本机用户界面、性能和 API 访问的应用程序。以下列表详细解释了这三个概念：

+   **原生用户界面**：使用 Xamarin 构建的应用程序使用每个平台的标准控件。这意味着，例如，使用 Xamarin 构建的 iOS 应用程序将看起来和行为与 iOS 用户期望的一样，使用 Xamarin 构建的 Android 应用程序将看起来和行为与 Android 用户期望的一样。

+   **原生性能**：使用 Xamarin 构建的应用程序经过本地性能编译，可以使用特定于平台的硬件加速。

+   **原生 API 访问：**原生 API 访问意味着使用 Xamarin 构建的应用程序可以使用目标平台和设备为开发人员提供的一切。

# Xamarin 和 Mono

Xamarin 是一个开发平台，用于开发 iOS（Xamarin.iOS）、Android（Xamarin.Android）和 macOS（Xamarin.Mac）的原生应用程序。它在这些平台的顶部技术上是一个绑定层。绑定到平台 API 使.NET 开发人员可以使用 C#（和 F#）开发具有每个平台完整功能的原生应用程序。我们在使用 Xamarin 开发应用程序时使用的 C# API 与平台 API 几乎相同，但它们是*.NET 化*的。例如，API 通常定制以遵循.NET 命名约定，并且 Android 的`set`和`get`方法通常被属性替换。这样做的原因是 API 应该更容易供.NET 开发人员使用。

Mono（[`www.mono-project.com`](https://www.mono-project.com/)）是 Microsoft .NET 框架的开源实现，基于 C#和公共语言运行时（CLR）的**欧洲计算机制造商协会**（**ECMA**）标准。Mono 的创建是为了将.NET 框架带到 Windows 以外的平台。它是.NET 基金会（[`www.dotnetfoundation.org`](http://www.dotnetfoundation.org/)）的一部分，这是一个支持涉及.NET 生态系统的开放发展和协作的独立组织。

通过 Xamarin 平台和 Mono 的组合，我们将能够同时使用所有特定于平台的 API 和.NET 的所有平台无关部分，包括例如命名空间、系统、`System.Linq`、`System.IO`、`System.Net`和`System.Threading.Tasks`。

有几个原因可以使用 Xamarin 进行移动应用程序开发，我们将在以下部分中看到。

# 代码共享

如果有一个通用的编程语言适用于多个移动平台，甚至服务器平台，那么我们可以在目标平台之间共享大量代码，如下图所示。所有与目标平台无关的代码都可以与其他.NET 平台共享。通常以这种方式共享的代码包括业务逻辑、网络调用和数据模型：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/a2fe69f7-b69c-49d3-a132-71120bc830bc.png)

除了围绕.NET 平台的大型社区外，还有大量的第三方库和组件可以从 NuGet（[`nuget.org`](https://nuget.org)）下载并在.NET 平台上使用。

跨平台的代码共享将导致更短的开发时间。这也将导致更高质量的应用程序，因为我们只需要编写一次业务逻辑的代码。出现错误的风险会降低，我们还能够保证计算将返回相同的结果，无论用户使用什么平台。

# 利用现有知识

对于想要开始构建原生移动应用程序的.NET 开发人员来说，学习新平台的 API 比学习新旧平台的编程语言和 API 更容易。

同样，想要构建原生移动应用程序的组织可以利用其现有的具有.NET 知识的开发人员来开发应用程序。因为.NET 开发人员比 Objective-C 和 Swift 开发人员更多，所以更容易找到新的开发人员来进行移动应用程序开发项目。

# Xamarin.iOS

Xamarin.iOS 用于使用.NET 构建 iOS 应用程序，并包含了之前提到的 iOS API 的绑定。Xamarin.iOS 使用**提前编译**（**AOT**）将 C#代码编译为**高级精简机器**（**ARM**）汇编语言。Mono 运行时与 Objective-C 运行时一起运行。使用.NET 命名空间的代码，如`System.Linq`或`System.Net`，将由 Mono 运行时执行，而使用 iOS 特定命名空间的代码将由 Objective-C 运行时执行。Mono 运行时和 Objective-C 运行时都运行在由苹果开发的类 Unix 内核**X is Not Unix**（**XNU**）（[`en.wikipedia.org/wiki/XNU`](https://en.wikipedia.org/wiki/XNU)）之上。以下图表显示了 iOS 架构的概述：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/9e678a4e-5d11-4c85-b899-307cf14ca8ed.png)

# Xamarin.Android

Xamarin.Android 用于使用.NET 构建 Android 应用程序，并包含了对 Android API 的绑定。Mono 运行时和 Android 运行时并行运行在 Linux 内核之上。Xamarin.Android 应用程序可以是**即时编译**（**JIT**）或 AOT 编译的，但要对其进行 AOT 编译，需要使用 Visual Studio Enterprise。

Mono 运行时和 Android 运行时之间的通信通过**Java 本地接口**（**JNI**）桥接发生。有两种类型的 JNI 桥接：**管理可调用包装器**（**MCW**）和**Android 可调用包装器**（**ACW**）。当代码需要在**Android 运行时**（**ART**）中运行时，使用**MCW**，当**ART**需要在 Mono 运行时中运行代码时，使用**ACW**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/0518e509-0678-47a7-a27f-0c938156cd28.png)

# Xamarin.Mac

Xamarin.Mac 用于使用.NET 构建 macOS 应用程序，并包含了对 macOS API 的绑定。Xamarin.Mac 与 Xamarin.iOS 具有相同的架构，唯一的区别是 Xamarin.Mac 应用程序是 JIT 编译的，而不像 Xamarin.iOS 应用程序是 AOT 编译的。如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/8bf5e05e-0103-4f2c-b6db-884bc295e604.png)

# Xamarin.Forms

**Xamarin.Forms**是建立在 Xamarin（用于 iOS 和 Android）和**通用 Windows 平台**（**UWP**）之上的 UI 框架。**Xamarin.Forms**使开发人员能够使用一个共享的代码库为 iOS、Android 和 UWP 创建 UI，如下图所示。如果我们正在使用**Xamarin.Forms**构建应用程序，我们可以使用 XAML、C#或两者的组合来创建 UI：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/01a60523-6c5f-4b50-b0e4-43aa8e316150.png)

# **Xamarin.Forms**的架构

**Xamarin.Forms**基本上只是每个平台上的一个抽象层。**Xamarin.Forms**有一个共享层，被所有平台使用，以及一个特定于平台的层。特定于平台的层包含渲染器。渲染器是一个将**Xamarin.Forms**控件映射到特定于平台的本机控件的类。每个**Xamarin.Forms**控件都有一个特定于平台的渲染器。

以下图示了当在 iOS 应用中使用共享的 Xamarin.Forms 代码时，**Xamarin.Forms**中的输入控件是如何渲染为**UIKit**命名空间中的**UITextField**控件的。在 Android 中相同的代码会渲染为**Android.Widget**命名空间中的**EditText**控件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/ce6bbb96-42b4-4064-b80d-456b22ec7ae4.png)

# 使用 XAML 定义用户界面

在 Xamarin.Forms 中声明用户界面的最常见方式是在 XAML 文档中定义它。也可以通过 C#创建 GUI，因为 XAML 实际上只是用于实例化对象的标记语言。理论上，您可以使用 XAML 来创建任何类型的对象，只要它具有无参数的构造函数。XAML 文档是具有特定模式的**可扩展标记语言**(**XML**)文档。

# 定义一个标签控件

作为一个简单的例子，让我们来看一下以下 XAML 代码片段：

```cs
<Label Text="Hello World!" />
```

当 XAML 解析器遇到这个代码片段时，它将创建一个`Label`对象的实例，然后设置与 XAML 中的属性对应的对象的属性。这意味着如果我们在 XAML 中设置了`Text`属性，它将设置在创建的`Label`对象的实例上的`Text`属性。上面例子中的 XAML 将产生与以下相同的效果：

```cs
var obj = new Label()
{
    Text = "Hello World!"
};
```

XAML 的存在是为了更容易地查看您需要创建的对象层次结构，以便创建 GUI。GUI 的对象模型也是按层次结构设计的，因此 XAML 支持添加子对象。您可以简单地将它们添加为子节点，如下所示：

```cs
<StackLayout>
    <Label Text="Hello World" />
    <Entry Text="Ducks are us" />
</StackLayout>
```

`StackLayout`是一个容器控件，它将在该容器内垂直或水平地组织子元素。垂直组织是默认值，除非您另行指定。还有许多其他容器，如`Grid`和`FlexLayout`。这些将在接下来的章节中的许多项目中使用。

# 在 XAML 中创建页面

单个控件没有容器来承载它是不好的。让我们看看整个页面会是什么样子。在 XAML 中定义的完全有效的`ContentPage`是一个 XML 文档。这意味着我们必须从一个 XML 声明开始。之后，我们必须有一个，且只有一个，根节点，如下面的代码所示：

```cs
<?xml version="1.0" encoding="UTF-8"?>
<ContentPage
     xmlns="http://xamarin.com/schemas/2014/forms"
     xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml"
     x:Class="MyApp.MainPage">

    <StackLayout>
        <Label Text="Hello world!" />
    </StackLayout>
</ContentPage>
```

在上面的例子中，我们定义了一个`ContentPage`，它在每个平台上都会被翻译成一个视图。为了使它成为有效的 XAML，您必须指定一个默认命名空间(`)然后添加`x`命名空间(`)。

默认命名空间允许您创建对象而无需为它们加前缀，就像`StackLayout`对象一样。`x`命名空间允许您访问属性，如`x:Class`，它告诉 XAML 解析器在创建`ContentPage`对象时实例化哪个类来控制页面。

`ContentPage`只能有一个子元素。在这种情况下，它是一个`StackLayout`控件。除非您另行指定，默认的布局方向是垂直的。因此，`StackLayout`可以有多个子元素。稍后，我们将介绍更高级的布局控件，如`Grid`和`FlexLayout`控件。

在这个特定的例子中，我们将创建一个`Label`控件作为`StackLayout`的第一个子元素。

# 在 C#中创建页面

为了清晰起见，以下代码展示了相同的内容在 C#中的写法：

```cs
public class MainPage : ContentPage
{
}
```

`page`是一个从`Xamarin.Forms.ContentPage`继承的类。如果你创建一个 XAML 页面，这个类会自动生成，但如果你只用代码，那么你就需要自己定义它。

让我们使用以下代码创建与之前定义的 XAML 页面相同的控件层次结构：

```cs
var page = new MainPage();

var stacklayout = new StackLayout();
stacklayout.Children.Add(
    new Label()
    {
        Text = "Welcome to Xamarin.Forms"
    });

page.Content = stacklayout;
```

第一条语句创建了一个`page`。理论上，你可以直接创建一个`ContentPage`类型的新页面，但这会禁止你在其后写任何代码。因此，最好的做法是为你计划创建的每个页面创建一个子类。

紧接着第一条语句的是创建包含添加到`Children`集合中的`Label`控件的`StackLayout`控件的代码块。

最后，我们需要将`StackLayout`分配给页面的`Content`属性。

# XAML 还是 C#？

通常使用 XAML 会给你一个更好的概览，因为页面是对象的分层结构，而 XAML 是定义这种结构的一种非常好的方式。在代码中，结构会被颠倒，因为你必须先定义最内部的对象，这样就更难读取页面的结构。这在本章的早些例子中已经展示过了。话虽如此，如何定义 GUI 通常是一种偏好。本书将在以后的项目中使用 XAML 而不是 C#。

# Xamarin.Forms 与传统 Xamarin

虽然本书是关于 Xamarin.Forms 的，但我们将强调使用传统 Xamarin 和 Xamarin.Forms 之间的区别。当开发使用 iOS 和 Android SDK 而没有任何抽象手段的应用程序时，使用传统的 Xamarin。例如，我们可以创建一个 iOS 应用程序，在故事板或直接在代码中定义其用户界面。这段代码将无法在其他平台上重用，比如 Android。使用这种方法构建的应用程序仍然可以通过简单引用.NET 标准库来共享非特定于平台的代码。这种关系在下图中显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/7344a947-57f3-4259-804a-7610cd0ffb78.png)

另一方面，Xamarin.Forms 是 GUI 的抽象，它允许我们以一种与平台无关的方式定义用户界面。它仍然建立在 Xamarin.iOS、Xamarin.Android 和所有其他支持的平台之上。Xamarin.Forms 应用程序可以创建为.NET 标准库或共享代码项目，其中源文件被链接为副本，并在当前构建的平台的同一项目中构建。这种关系在下图中显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/e626305f-5a27-434c-a805-c29ee3f90c5f.png)

话虽如此，没有传统的 Xamarin，Xamarin.Forms 就无法存在，因为它是通过每个平台的应用程序引导的。这使您能够通过接口将自定义渲染器和特定于平台的代码扩展到每个平台上的 Xamarin.Forms。我们将在本章后面详细讨论这些概念。

# 何时使用 Xamarin.Forms

我们可以在大多数情况下和大多数类型的应用中使用 Xamarin.Forms。如果我们需要使用 Xamarin.Forms 中没有的控件，我们可以随时使用特定于平台的 API。然而，有一些情况下 Xamarin.Forms 是无法使用的。我们可能希望避免使用 Xamarin.Forms 的最常见情况是，如果我们正在构建一个希望在目标平台上看起来非常不同的应用程序。

# 设置开发机器

开发一个适用于多个平台的应用程序对我们的开发机器提出了更高的要求。其中一个原因是我们经常希望在开发机器上运行一个或多个模拟器或仿真器。不同的平台对于开始开发所需的要求也不同。无论我们使用的是 Mac 还是 Windows，Visual Studio 都将是我们的集成开发环境。Visual Studio 有几个版本，包括免费的社区版。请访问[`visualstudio.microsoft.com/`](https://visualstudio.microsoft.com/)比较可用的 Visual Studio 版本。以下列表总结了我们为每个平台开始开发所需的内容：

+   **iOS**：要为 iOS 开发应用程序，我们需要一台 Mac。这可以是我们正在开发的机器，也可以是我们网络上的一台机器（如果我们正在使用）。我们需要连接到 Mac 的原因是我们需要 Xcode 来编译和调试应用程序。Xcode 还提供了 iOS 模拟器。

+   **Android**：Android 应用可以在 macOS 或 Windows 上开发。包括 SDK 和模拟器在内的一切都将与 Visual Studio 一起安装。

+   **UWP**：UWP 应用只能在 Windows 机器上的 Visual Studio 中开发。

# 设置 Mac

在 Mac 上开发使用 Xamarin 开发 iOS 和 Android 应用程序需要两个主要工具。这些工具是 Visual Studio for Mac（如果我们只开发 Android 应用程序，这是我们唯一需要的工具）和 Xcode。在接下来的部分中，我们将看看如何为应用程序开发设置 Mac。

# 安装 Xcode

在安装 Visual Studio 之前，我们需要下载并安装 Xcode。Xcode 是苹果的官方开发 IDE，包含了他们为 iOS 开发提供的所有工具，包括 iOS、macOS、tvOS 和 watchOS 的 SDK。

我们可以从苹果开发者门户([`developer.apple.com`](https://developer.apple.com))或苹果应用商店下载 Xcode。我建议您从应用商店下载，因为这将始终为您提供最新的稳定版本。从开发者门户下载 Xcode 的唯一原因是，如果我们想要使用 Xcode 的预发布版本，例如为 iOS 的预发布版本进行开发。

第一次安装后，以及每次更新 Xcode 后，打开它很重要。Xcode 经常需要在安装或更新后安装额外的组件。您还需要打开 Xcode 以接受与苹果的许可协议。

# 安装 Visual Studio

要安装 Visual Studio，我们首先需要从[`visualstudio.microsoft.com`](https://visualstudio.microsoft.com)下载它。

当我们通过下载的文件启动 Visual Studio 安装程序时，它将开始检查我们的机器上已安装了什么。检查完成后，我们将能够选择要安装的平台和工具。请注意，Xamarin Inspector 需要 Visual Studio 企业许可证。

一旦我们选择了要安装的平台，Visual Studio 将下载并安装我们使用 Xamarin 开始应用程序开发所需的一切，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/e0283eac-aad0-47d5-bfa5-28ba0fee9a90.png)

# 配置 Android 模拟器

Visual Studio 将使用 Google 提供的 Android 模拟器。如果我们希望模拟器运行速度快，那么我们需要确保它是硬件加速的。要对 Android 模拟器进行硬件加速，我们需要安装**Intel Hardware Accelerated Execution Manager**（**HAXM**），可以从[`software.intel.com/en-us/articles/intel-hardware-accelerated-execution-manager-intel-haxm`](https://software.intel.com/en-us/articles/intel-hardware-accelerated-execution-manager-intel-haxm)下载。

下一步是创建一个 Android 模拟器。首先，我们需要确保已安装了 Android 模拟器和 Android 操作系统映像。要做到这一点，请按照以下步骤进行：

1.  转到工具选项卡安装 Android 模拟器：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/8d7b72e8-7184-48e4-a971-f01877061f10.png)

1.  我们还需要安装一个或多个图像以与模拟器一起使用。例如，如果我们想要在不同版本的 Android 上运行我们的应用程序，我们可以安装多个图像。我们将选择具有 Google Play 的模拟器（如下面的屏幕截图所示），以便在模拟器中运行应用程序时可以使用 Google Play 服务。例如，如果我们想要在应用程序中使用 Google 地图，则需要这样做：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/007644d2-f786-499f-9e19-43cbe66ac4c1.png)

1.  然后，要创建和配置模拟器，请转到 Visual Studio 中的工具选项卡中的 Android 设备管理器。从 Android 设备管理器，如果我们已经创建了一个模拟器，我们可以启动一个模拟器，或者我们可以创建新的模拟器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/5e485948-27b2-4b9f-9587-6b3829d7d952.png)

1.  如果单击“新设备”按钮，我们可以创建一个具有我们需要的规格的新模拟器。在这里创建新模拟器的最简单方法是选择与我们需求匹配的基础设备。这些基础设备将被预先配置，通常足够。但是，也可以编辑设备的属性，以便获得与我们特定需求匹配的模拟器。

因为我们不会在具有 ARM 处理器的设备上运行模拟器，所以我们必须选择 x86 处理器或 x64 处理器，如下面的屏幕截图所示。如果我们尝试使用 ARM 处理器，模拟器将非常慢：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/f20ac9a7-abd5-4799-9a96-c59d1f76198c.png)

# 设置 Windows 机器

我们可以使用虚拟或物理 Windows 机器进行 Xamarin 开发。例如，我们可以在 Mac 上运行虚拟 Windows 机器。我们在 Windows 机器上进行应用程序开发所需的唯一工具是 Visual Studio。

# 安装 Visual Studio 的 Xamarin

如果我们已经安装了 Visual Studio，我们必须首先打开 Visual Studio 安装程序；否则，我们需要转到[`visualstudio.microsoft.com`](https://visualstudio.microsoft.com)下载安装文件。

在安装开始之前，我们需要选择要安装的工作负载。

如果我们想要为 Windows 开发应用程序，我们需要选择通用 Windows 平台开发工作负载，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/555232f0-58a2-4465-95f2-bd91630d08f0.png)

对于 Xamarin 开发，我们需要安装带有.NET 的移动开发。如果您想要使用 Hyper-V 进行硬件加速，我们可以在左侧的.NET 移动开发工作负载的详细描述中取消选择 Intel HAXM 的复选框，如下面的屏幕截图所示。当我们取消选择 Intel HAXM 时，Android 模拟器也将被取消选择，但我们可以稍后安装它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/b1ec5c90-089a-4391-be25-2030819a270a.png)

当我们首次启动 Visual Studio 时，将询问我们是否要登录。除非我们想要使用 Visual Studio 专业版或企业版，否则我们不需要登录，否则我们必须登录以便验证我们的许可证。

# 将 Visual Studio 与 Mac 配对

如果我们想要运行，调试和编译我们的 iOS 应用程序，那么我们需要将其连接到 Mac。我们可以手动设置 Mac，如本章前面描述的那样，或者我们可以使用自动 Mac 配置。这将在我们连接的 Mac 上安装 Mono 和 Xamarin.iOS。它不会安装 Visual Studio IDE，但如果您只想将其用作构建机器，则不需要。但是，我们需要手动安装 Xcode。

要能够连接到 Mac（无论是手动安装的 Mac 还是使用自动 Mac 配置），Mac 需要通过我们的网络访问，并且我们需要在 Mac 上启用远程登录。要做到这一点，转到设置 | 共享，并选择远程登录的复选框。在窗口的左侧，我们可以选择允许连接远程登录的用户，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/ade641e3-b0e9-4f90-8516-95895b732961.png)

从 Visual Studio 连接到 Mac，可以在工具栏中使用“连接到 Mac”按钮（如下截图所示），或者在顶部菜单中选择工具 | iOS，最后选择连接到 Mac：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/8abe2796-8856-489d-a5ff-f2cc6e85060f.png)

将显示一个对话框，显示可以在网络上找到的所有 Mac。如果 Mac 不出现在可用 Mac 列表中，我们可以使用左下角的“添加 Mac”按钮输入 IP 地址，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/d964085d-d4bd-45dd-ae24-349ffb07293c.png)

如果 Mac 上安装了您需要的一切，那么 Visual Studio 将连接，我们可以开始构建和调试我们的 iOS 应用程序。如果 Mac 上缺少 Mono，将会出现警告。此警告还将给我们安装它的选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/9148b63d-f1ad-46b0-b828-649fd206c73a.png)

# 配置 Android 模拟器和硬件加速

如果我们想要一个运行流畅的快速 Android 模拟器，就需要启用硬件加速。这可以使用 Intel HAXM 或 Hyper-V 来实现。Intel HAXM 的缺点是它不能在装有**AMD**处理器的机器上使用；你必须有一台装有 Intel 处理器的机器。我们不能同时使用 Intel HAXM 和 Hyper-V。

因此，Hyper-V 是在 Windows 机器上硬件加速 Android 模拟器的首选方式。要在 Android 模拟器中使用 Hyper-V，我们需要安装 2018 年 4 月更新（或更高版本）的 Windows 和 Visual Studio 15.8 版本（或更高版本）。要启用 Hyper-V，需要按照以下步骤进行：

1.  打开开始菜单，键入“打开或关闭 Windows 功能”。单击出现的选项以打开它，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/ec50af38-1f5e-4eac-87d0-82598cc258f4.png)

1.  要启用 Hyper-V，选择 Hyper-V 复选框。此外，展开 Hyper-V 选项并选中 Hyper-V 平台复选框。我们还需要选择 Windows Hypervisor Platform 复选框，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/f42fe911-996d-4ad2-999d-1c192743f9e8.png)

1.  当 Windows 提示时重新启动机器。

因为在安装 Visual Studio 时我们没有安装 Android 模拟器，所以现在需要安装它。转到 Visual Studio 的工具菜单，点击 Android，然后点击 Android SDK Manager。

在 Android SDK Manager 的工具中，我们可以通过选择 Android 模拟器来安装模拟器，如下截图所示。此外，我们应该确保安装了最新版本的 Android SDK 构建工具：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/d709c8c4-25b6-40c8-bf65-592fc3d78761.png)

我们建议安装**NDK**（**Native Development Kit**）。NDK 使得可以导入用 C 或 C++编写的库。如果我们想要 AOT 编译应用程序，也需要 NDK。

Android SDK 允许同时安装多个模拟器映像。例如，如果我们想要在不同版本的 Android 上运行我们的应用程序，我们可以安装多个映像。选择带有 Google Play 的模拟器（如下截图所示），这样我们可以在模拟器中运行应用程序时使用 Google Play 服务。

如果我们想在应用程序中使用谷歌地图，就需要这样做：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/eddbd280-3ed0-45ae-9af0-41413e7181df.png)

下一步是创建一个虚拟设备来使用模拟器图像。要创建和配置模拟器，请转到 Android 设备管理器，我们将从 Visual Studio 的工具选项卡中打开。从设备管理器，我们可以启动模拟器（如果我们已经创建了一个），或者我们可以创建新的模拟器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/5475de4c-2f72-4b8e-9701-e67c79807ed1.png)

如果我们点击“新设备”按钮，我们可以创建一个符合我们需求的新模拟器。在这里创建新模拟器的最简单方法是选择符合我们需求的基础设备。这些基础设备将被预先配置，通常已经足够了。但是，我们也可以编辑设备的属性，以便获得符合我们特定需求的模拟器。

我们必须选择 x86 处理器（如下图所示）或 x64 处理器，因为我们不会在 ARM 处理器的设备上运行模拟器。如果我们尝试使用 ARM 处理器，模拟器将非常慢：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/41d02e83-cec8-48f0-b248-850440d3f10d.png)

# 配置 UWP 开发者模式

如果我们想开发 UWP 应用程序，我们需要在开发机器上激活开发者模式。要做到这一点，请转到“设置”|“更新和安全”|“开发人员”，然后点击“开发人员模式”，如下图所示。这样我们就可以通过 Visual Studio 侧载和调试应用程序了。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/6bd60b6b-e5ad-4794-bff4-46c5b771ccfa.png)

如果我们选择侧载应用程序而不是开发者模式，我们只能安装应用程序，而不需要经过 Microsoft Store。如果我们有一台用于测试而不是调试我们的应用程序的机器，我们可以选择侧载应用程序。

# 总结

阅读完本章后，您应该对 Xamarin 是什么以及 Xamarin.Forms 与 Xamarin 本身的关系有了一些了解。

在本章中，我们确定了我们对本地应用程序的定义，其中包括以下元素：

+   本地用户界面

+   本地性能

+   本地 API 访问

我们谈到了 Xamarin 是基于 Mono 构建的，Mono 是 .NET 框架的开源实现，并讨论了在其核心，Xamarin 是一组绑定到特定平台 API 的工具。然后我们详细了解了 Xamarin.iOS 和 Xamarin.Android 是如何工作的。

之后，我们开始接触本书的核心主题，即 Xamarin.Forms。我们首先概述了平台无关控件如何渲染为特定于平台的控件，以及如何使用 XAML 定义控件层次结构来组装页面。

然后我们花了一些时间来看 Xamarin.Forms 应用程序和传统 Xamarin 应用程序之间的区别。

传统的 Xamarin 应用程序直接使用特定于平台的 API，除了 .NET 添加的平台之外没有其他抽象。

Xamarin.Forms 是建立在传统 Xamarin API 之上的 API，允许我们在 XAML 或代码中定义平台无关的 GUI，然后渲染为特定于平台的控件。Xamarin.Forms 还有更多功能，但这是它的核心功能。

在本章的最后部分，我们讨论了如何在 Windows 或 macOS 上设置开发机器。

现在是时候将我们新获得的知识付诸实践了！我们将从头开始创建一个待办事项应用程序，这将是下一章的内容。我们将研究诸如 Model-View-ViewModel（MVVM）等概念，以实现业务逻辑和用户界面的清晰分离，以及 SQLite.NET，以将数据持久保存到设备上的本地数据库。我们将同时为三个平台进行开发，敬请期待！


# 第二章：构建我们的第一个 Xamarin.Forms 应用程序

在本章中，我们将创建一个待办事项列表应用程序，并在此过程中探讨构建应用程序的各个方面。我们将研究创建页面，向这些页面添加内容，导航之间切换，并创建一个令人惊叹的布局。嗯，*令人惊叹*可能有点牵强，但我们一定会设计应用程序，以便在完成后您可以根据自己的需求进行调整！

本章将涵盖以下主题：

+   设置项目

+   在设备上本地持久化数据

+   使用存储库模式

+   MVVM 是什么以及为什么它非常适合 Xamarin.Forms

+   使用 Xamarin.Forms 页面（作为视图）并在它们之间导航

+   在 XAML 中使用 Xamarin.Forms 控件

+   使用数据绑定

+   在 Xamarin.Forms 中使用样式

# 技术要求

为了能够完成这个项目，我们需要安装 Visual Studio for Mac 或 PC，以及 Xamarin 组件。有关如何设置您的环境的更多详细信息，请参阅 Xamarin 简介。

# 项目概述

每个人都需要一种跟踪事物的方式。为了启动我们的 Xamarin.Forms 开发学习曲线，我们决定一个待办事项列表应用程序是最好的开始方式，也可以帮助您跟踪事物。一个简单的，经典的，双赢的场景。

我们将首先创建项目，并定义一个存储库，用于存储待办事项列表的项目。我们将以列表形式呈现这些项目，并允许用户使用详细的用户界面对其进行编辑。我们还将看看如何通过**SQLite-net**在设备上本地存储待办事项，以便在退出应用程序时不会丢失。

此项目的构建时间约为两个小时。

# 开始项目

是时候开始编码了！然而，在继续之前，请确保您已按照 Xamarin 简介中描述的设置好开发环境。

本章将是一个经典的文件|新建项目章节，将逐步指导您创建您的第一个待办事项列表应用程序的过程。完全不需要下载。

# 设置项目

Xamarin 应用程序基本上可以使用两种代码共享策略之一来创建：

+   作为共享项目

+   作为.NET 标准库

第一个选择，**共享项目**，将创建一个项目类型，实质上是其中每个文件的链接副本。文件存在于一个共同的位置，并在构建时链接。这意味着我们在编写代码时无法确定运行时，并且只能访问每个目标平台上可用的 API。它确实允许我们使用条件编译，在某些情况下可能有用，但对于以后阅读代码的人来说可能也会令人困惑。选择共享项目选项也可能是一个不好的选择，因为它将我们的代码锁定到特定的平台。

我们将使用第二个选择，**.NET 标准库**。当然，这是一个选择的问题，两种方式仍然有效。稍加想象力，即使选择了共享项目，您仍然可以遵循本章的内容。

让我们开始吧！

# 创建新项目

第一步是创建一个新的 Xamarin.Forms 项目。打开 Visual Studio 2017，然后单击文件|新建|项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/0968d7e6-303e-4f48-886e-6bdac6b71cbd.png)

这将打开新项目对话框。展开 Visual C#节点，然后单击跨平台。在列表中选择移动应用程序（Xamarin.Forms）项目。通过命名项目并单击确定来完成表单。确保命名项目为`DoToo`以避免命名空间问题：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/bd6167ef-879a-4903-99a3-52c864466596.png)

下一步是选择一个项目模板和代码共享策略。选择空白应用程序以创建一个裸的 Xamarin.Forms 应用程序，并将代码共享策略更改为.NET 标准。点击确定完成设置，并等待 Visual Studio 创建必要的项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/831eed3d-b0da-47d5-b6ba-bb04056ab66f.png)

恭喜，我们刚刚创建了我们的第一个 Xamarin.Forms 应用程序！

# 检查文件

所选模板现在已创建了四个项目：

+   DoToo:这是一个.NET 标准库，目标是.NET 标准 2.0。它可以被支持这个版本的.NET 标准的任何运行时导入。

+   DoToo.Android:这是一个用于在 Android 上引导 Xamarin.Forms 的 Android 应用程序。

+   DoToo.iOS:这是一个用于在 iOS 上引导 Xamarin.Forms 的 iOS 应用程序。

+   DoToo.UWP:这是一个用于在 UWP 上引导 Xamarin.Forms 的**Universal Windows Platform**（**UWP**）应用程序。

这三个特定平台的库引用了.NET 标准库。我们的大部分代码将在.NET 标准库中编写，只有一小部分特定平台的代码将被添加到每个目标平台。

项目现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/76f6af76-cc51-4298-961f-31dbfd108828.png)

我们将重点介绍每个项目中的一些重要文件，以便我们对它们有一个基本的了解。我们将逐个项目进行介绍。

# DoToo

这是.NET 标准库，所有特定平台的项目都引用它，大部分我们的代码将被添加到这里。以下截图显示了.NET 标准库的结构：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/337ef0a9-629d-4ec7-a6a8-ecbcc20f73f8.png)

在依赖项下，我们将找到对外部依赖项（如 Xamarin.Forms）的引用。我们将在*更新 Xamarin.Forms 包*部分中更新 Xamarin.Forms 包的版本。随着我们在本章中的进展，我们将添加更多依赖项。

`App.xaml`文件是一个代表应用程序的 XAML 文件。这是放置应用程序范围资源的好地方，我们稍后会这样做。我们还可以看到`App.xaml.cs`文件，其中包含启动代码和一些生命周期事件，我们可以在其中添加自定义代码，例如`OnStart`或`OnSleep`。

如果我们打开`App.xaml.cs`，我们可以看到我们的 Xamarin.Forms 应用程序的起点：

```cs
public partial class App : Application
{
    public App()
    {
        InitializeComponent();
        MainPage = new DoToo.MainPage();
    }

    protected override void OnStart()
    {
        // Handle when your app starts
    }

    // code omitted for brevity
}
```

将页面分配给`MainPage`属性特别重要，因为这决定了用户首先将显示哪个页面。在模板中，这是`DoToo.MainPage()`类。

最后两个文件是`MainPage.xaml`文件，其中包含应用程序的第一个页面，以及称为`MainPage.xaml.cs`的代码后台文件。为了符合**Model-View-ViewModel**（**MVVM**）命名标准，这些文件将被删除。

# DoToo.Android

这是 Android 应用程序。它只有一个文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/e61e5203-3712-4ef3-9b7b-62f81f601a4e.png)

这里的重要文件是`MainActivity.cs`。如果我们在 Android 设备上运行应用程序，这个文件包含应用程序的入口点方法。Android 应用程序的入口点方法是`OnCreate(...)`。

如果您打开`MainActivity.cs`并检查`OnCreate(...)`方法，它应该看起来像这样：

```cs
protected override void OnCreate(Bundle bundle)
{
    TabLayoutResource = Resource.Layout.Tabbar;
    ToolbarResource = Resource.Layout.Toolbar;
    base.OnCreate(bundle);
    global::Xamarin.Forms.Forms.Init(this, bundle);
    LoadApplication(new App());
}
```

前两行为`Tabbar`和`Toolbar`分配资源。然后我们调用基本方法，接着是 Xamarin.Forms 的强制初始化。最后，我们调用加载我们在.NET 标准库中定义的 Xamarin.Forms 应用程序。

我们不需要详细了解这些文件，只需记住它们对于我们应用程序的初始化很重要。

# DoToo.iOS

这是 iOS 应用程序。它包含的文件比其 Android 对应文件多一些：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/64c398b1-b14b-4851-b11e-4e2342e5152b.png)

`AppDelegate.cs`文件是 iOS 应用程序的入口点。这个文件包含一个叫做`FinishedLaunching(...)`的方法，这是我们开始编写代码的地方：

```cs
public override bool FinishedLaunching(UIApplication app, NSDictionary options)
{
    global::Xamarin.Forms.Forms.Init();
    LoadApplication(new App());
    return base.FinishedLaunching(app, options);
}
```

代码从初始化 Xamarin.Forms 开始，然后从.NET 标准库加载应用程序。之后，它将控制返回到 iOS。必须在 17 秒内完成此操作，否则应用程序将被操作系统终止。

`info.plist`文件是一个 iOS 特定的文件，包含有关应用程序的信息，例如捆绑 ID 及其配置文件。它有一个图形编辑器，但也可以在任何文本编辑器中编辑，因为它是一个标准的 XML 文件。

`Entitlements.plist`文件也是一个 iOS 特定的文件，用于配置我们希望应用程序利用的权限，例如**应用内购买**或**推送通知**。

与 Android 应用程序的启动代码一样，我们不需要详细了解这里发生了什么，只需知道这对于我们应用程序的初始化非常重要。

# DoToo.UWP

要检查的最后一个项目是 UWP 应用程序。项目的文件结构如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/a326f5d0-d1d7-40e4-8a1d-946afe2be4f9.png)

它有一个`App.xaml`文件，类似于.NET 标准库中的文件，但特定于 UWP 应用程序。它还有一个名为`App.xaml.cs`的相关文件。其中包含一个名为`OnLaunched(...)`的方法，是 UWP 应用程序的入口点。这个文件非常大，所以我们不会在这里打印出来，但是打开它，看看我们是否可以在其中找到 Xamarin.Forms 初始化代码。

# 更新 Xamarin.Forms 软件包

创建项目后，我们应该始终将 Xamarin.Forms 软件包更新到最新版本。要执行此操作，请按照以下步骤进行：

1.  在解决方案资源管理器中右键单击我们的解决方案。

1.  单击“管理解决方案的 NuGet 软件包...”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/b16aacf6-cee3-4980-9ac8-cf1940d124bb.png)

1.  这将在 Visual Studio 中打开 NuGet 软件包管理器：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/add08ce1-c4cd-4a91-b7a6-b1678169e278.png)

要将 Xamarin.Forms 更新到最新版本，请执行以下操作：

1.  单击“更新”选项卡

1.  检查 Xamarin.Forms 并单击更新

1.  接受任何许可协议

密切关注输出窗格，并等待所有软件包更新。但是，请确保不要手动更新任何 Android 软件包，因为这可能会破坏您的应用程序。

# 删除 MainPage 文件

在 Xamarin.Forms 中，我们有页面的概念。然而，对于 MVVM 架构模式来说并非如此，它使用视图的概念。视图与页面是相同的，但它们没有后缀-Page，因此我们将删除模板生成的`MainPage`。我们将很快详细介绍 MVVM，但目前，我们将从解决方案中删除`MainPage.cs`类。可以按照以下步骤完成：

1.  在`DoToo`项目（.NET 标准库）中右键单击`MainPage.xaml`文件

1.  单击删除并确认删除操作

# 创建存储库和 TodoItem 模型

任何良好的架构都涉及抽象。在这个应用程序中，我们需要存储和检索待办事项列表中的项目。这些将稍后存储在 SQLite 数据库中，但是直接从负责 GUI 的代码中添加对数据库的引用通常是一个坏主意。

相反，我们需要的是将数据库从 GUI 中抽象出来。对于这个应用程序，我们选择使用简单的存储库模式。这个存储库只是一个简单的类，位于 SQLite 数据库和我们即将到来的`ViewModels`之间。这是处理与视图的交互的类，而视图又处理 GUI。

存储库将公开用于获取项目、添加项目和更新项目的方法，以及允许应用程序其他部分对存储库中更改做出反应的事件。它将隐藏在接口后面，以便我们稍后可以替换整个实现，而不必修改应用程序初始化中的代码行以外的任何内容。这是由**Autofac**实现的。

# 定义待办事项列表项目

我们将首先创建一个`TodoItem`类，它将表示列表中的单个项目。这将是一个简单的**Plain Old CLR Object**（**POCO**）类，其中**CLR**代表**Common Language Runtime**。换句话说，这将是一个没有依赖于第三方程序集的.NET 类。要创建该类，请按照以下步骤：

1.  在.NET Standard 库项目中，创建一个名为`Models`的文件夹。

1.  在该文件夹中创建一个名为`TodoItem.cs`的类，并输入以下代码：

```cs
public class TodoItem
{
    public int Id { get; set; }
    public string Title { get; set; }
    public bool Completed { get; set; }
    public DateTime Due { get; set; }
}
```

代码非常简单易懂；这是一个简单的**Plain Old CLR Object**（**POCO**）类，只包含属性而没有逻辑。我们有一个`Title`描述我们想要完成的任务，一个标志（`Completed`）确定待办事项是否已完成，一个`Due`日期我们期望完成它，以及一个我们以后需要用到的唯一`id`。

# 创建存储库及其接口

现在我们有了`TodoItem`类，让我们定义一个描述存储待办事项的存储库的接口：

1.  在.NET Standard 库项目中，创建一个名为`Repositories`的文件夹。

1.  在`Repositories`文件夹中创建一个名为`ITodoItemRepository.cs`的接口，并编写以下代码：

```cs
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using DoToo.Models; 

namespace DoToo.Repositories
{
    public interface ITodoItemRepository
    { 
        event EventHandler<TodoItem> OnItemAdded;
        event EventHandler<TodoItem> OnItemUpdated;

        Task<List<TodoItem>> GetItems();
        Task AddItem(TodoItem item);
        Task UpdateItem(TodoItem item);
        Task AddOrUpdate(TodoItem item);
    }
}
```

敏锐的读者可能会注意到，我们在这个接口中没有定义`Delete`方法。这绝对是真实世界应用程序中应该有的内容。虽然我们在本章中创建的应用程序不支持删除项目，但我们相当确定，如果您愿意，您可以自行添加这个功能！

这个接口定义了我们应用程序所需的一切。它用于在存储库的实现和存储库的用户之间创建逻辑隔离。如果应用程序的其他部分需要`TodoItemRepository`的实例，我们可以传递任何实现`ITodoItemRepository`的对象，而不管它是如何实现的。

说到这一点，让我们实现`ITodoItemRepository`：

1.  创建一个名为`TodoItemRepository.cs`的类。

1.  输入以下代码：

```cs
using DoToo.Models;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace DoToo.Repositories
{
    public class TodoItemRepository : ITodoItemRepository
    {
        public event EventHandler<TodoItem> OnItemAdded;
        public event EventHandler<TodoItem> OnItemUpdated;

        public async Task<List<TodoItem>> GetItems()
        {
        }

        public async Task AddItem(TodoItem item)
        {
        }

        public async Task UpdateItem(TodoItem item)
        {
        }

        public async Task AddOrUpdate(TodoItem item)
        {
            if (item.Id == 0)
            {
                await AddItem(item);
            }
            else
            {
                await UpdateItem(item);
            }
        }
    }
}
```

这段代码是接口的最基本实现，除了`AddOrUpdate(...)`方法。这处理了一个小段逻辑，即如果项目的 ID 为`0`，则它是一个新项目。任何 ID 大于`0`的项目都存储在数据库中。这是因为当我们在表中创建行时，数据库会分配一个大于零的值。

在上述代码中还定义了两个事件。这将用于通知任何订阅者项目已更新或已添加。

# 连接 SQLite 以持久化数据

我们现在有一个接口和一个实现该接口的骨架。完成本节的最后一件事是在存储库的实现中连接 SQLite。

# 添加 SQLite NuGet 包

要在此项目中访问 SQLite，我们需要向.NET Standard 库项目添加一个名为 sqlite-net-pcl 的 NuGet 包。要做到这一点，请右键单击解决方案的 DoToo 项目节点下的依赖项，然后单击管理 NuGet 包：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/9325577f-3323-4e97-b089-91787f868c17.png)

您可能会注意到 NuGet 包的后缀为-pcl。这是命名约定出错时发生的情况。这个包实际上支持.NET Standard 1.0，尽管名称中说的是**Portable Class Library**（**PCL**），这是.NET Standard 的前身。

这会弹出 NuGet 包管理器：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/9bb454fb-b159-4236-8fb3-6d5dc3500318.png)

1.  点击浏览并在搜索框中输入 sqlite-net-pcl

1.  选择 Frank A. Krueger 的包，然后单击安装

等待安装完成。然后我们将向`TodoItem`类和存储库添加一些代码。

# 更新 TodoItem 类

由于 SQLite 是一个关系型数据库，它需要知道一些关于如何创建将存储我们对象的表的基本信息。这是使用属性完成的，这些属性在 SQLite 命名空间中定义：

1.  打开`Models/TodoItem`。

1.  在文件的开头下面的现有`using`语句之后添加一个`using SQLite`语句，如下面的代码所示：

```cs
using System;
using SQLite;
```

1.  在 ID 属性之前添加`PrimaryKey`和`AutoIncrement`属性，如下面的代码所示：

```cs
[PrimaryKey, AutoIncrement]
public int Id { get; set; }
```

`PrimaryKey`属性指示 SQLite`Id`属性是表的主键。`AutoIncrement`属性将确保`Id`的值对于添加到表中的每个新的`TodoItem`类都会增加一。

# 创建与 SQLite 数据库的连接

现在，我们将添加所有与数据库通信所需的代码。我们首先需要定义一个连接字段，用于保存与数据库的连接：

1.  打开`Repositories/TodoItemRepository`文件。

1.  在文件的开头下面的现有`using`语句之后添加一个**`using SQLite`**语句，如下面的代码所示：

```cs
using DoToo.Models;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using SQLite
```

1.  在类声明的下面添加以下字段：

```cs
private SQLiteAsyncConnection connection;
```

连接需要初始化。一旦初始化，它就可以在存储库的整个生命周期内重复使用。由于该方法是异步的，不能从构造函数中调用它而不引入锁定策略。为了保持简单，我们将简单地从每个由接口定义的方法中调用它：

1.  将以下代码添加到`TodoItemRepository`类中。

1.  在文件的开头添加一个`using System.IO`语句，以便我们可以使用`Path.Combine(...)`：

```cs
private async Task CreateConnection()
{
    if (connection != null)
    {
        return;
    }

    var documentPath = Environment.GetFolderPath(
                       Environment.SpecialFolder.MyDocuments);
    var databasePath = Path.Combine(documentPath, "TodoItems.db"); 

    connection = new SQLiteAsyncConnection(databasePath);
    await connection.CreateTableAsync<TodoItem>();

    if (await connection.Table<TodoItem>().CountAsync() == 0)
    {
        await connection.InsertAsync(new TodoItem() { Title = 
        "Welcome to DoToo" });
    }
} 
```

该方法首先检查我们是否已经有连接。如果有，我们可以简单地返回。如果我们没有设置连接，我们定义一个磁盘上的路径来指示我们希望数据库文件位于何处。在这种情况下，我们将选择`MyDocuments`文件夹。Xamarin 将在我们针对的每个平台上找到与此最接近的匹配项。

然后，我们创建连接并将该连接的引用存储在`connection`字段中。我们需要确保 SQLite 已创建一个与`TodoItem`表的模式相匹配的表。为了使应用程序的开发更加简单，如果`TodoItem`表为空，我们将添加一个默认的待办事项。

# 实现获取、添加和更新方法

在存储库中剩下的唯一事情是实现获取、添加和更新项目的方法：

1.  在`TodoItemRepository`类中找到`GetItems()`方法。

1.  使用以下代码更新`GetItems()`方法：

```cs
public async Task<List<TodoItem>> GetItems()
{
    await CreateConnection();
    return await connection.Table<TodoItem>().ToListAsync();
}

```

为了确保与数据库的连接有效，我们调用了在上一节中创建的`CreateConnection()`方法。当此方法返回时，我们可以确保它已初始化并且`TodoItem`表已创建。

然后，我们使用连接访问`TodoItem`表，并返回一个包含数据库中所有待办事项的`List<TodoItem>`。

SQLite 支持使用**语言集成查询**（**LINQ**）查询数据。在项目完成后，您可以尝试使用它来更好地了解如何在应用程序内部使用数据库。

添加项目的代码甚至更简单：

1.  在`TodoItemRepository`类中找到`AddItem()`方法。

1.  使用以下代码更新`AddItem()`方法：

```cs
public async Task AddItem(TodoItem item)
{
    await CreateConnection();
    await connection.InsertAsync(item);
    OnItemAdded?.Invoke(this, item);
}
```

对`CreateConnection()`的调用确保我们以与`GetItems()`方法相同的方式建立连接。之后，我们使用连接对象上的`InsertAsync(...)`方法在数据库中执行实际的插入操作。在项目被插入到表中后，我们调用`OnItemAdded`事件通知任何订阅者。

更新项目的代码基本上与`AddItem()`方法相同，但还包括对`UpdateAsync`和`OnItemUpdated`的调用。让我们通过使用以下代码更新`UpdateItem()`方法来完成：

1.  在`TodoItemRepository`类中找到`UpdateItem()`方法。

1.  使用以下代码更新`UpdateItem()`方法：

```cs
public async Task UpdateItem(TodoItem item)
{
    await CreateConnection();
    await connection.UpdateAsync(item);
    OnItemUpdated?.Invoke(this, item);
}
```

在下一节中，我们将开始使用 MVVM。来杯咖啡，让我们开始吧。

# 使用 MVVM - 创建视图和视图模型

MVVM 的关键在于关注点的分离。每个部分都有特定的含义：

+   **模型**：这与表示数据并可以由`ViewModel`引用的任何东西有关

+   **视图**：这是可视化组件。在 Xamarin.Forms 中，这由一个页面表示

+   **ViewModel**：这是在模型和视图之间充当中介的类

在我们的应用程序中，我们可以说模型是存储库和它返回的待办事项列表项。`ViewModel`引用这个存储库并公开属性，供视图绑定。基本规则是任何逻辑都应该驻留在 ViewModel 中，视图中不应该有任何逻辑。视图应该知道如何呈现数据，比如将布尔值转换为“是”或“否”。

MVVM 可以以许多方式实现，有很多框架可以使用。在本章中，我们选择保持简单，以纯净的方式实现 MVVM，而不使用任何框架。

# 定义一个 ViewModel 基类

`ViewModel`是视图和模型之间的中介。通过为所有`ViewModels`创建一个通用的基类，我们可以获得很大的好处。要做到这一点，请按照以下步骤操作：

1.  在 DoToo .NET Standard 项目中创建一个名为`ViewModels`的文件夹。

1.  在 ViewModels 文件夹中创建一个名为`ViewModel`的类。

1.  解决对`System.ComponentModel`和 Xamarin.Forms 的引用，并添加以下代码：

```cs
public abstract class ViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler PropertyChanged;

    public void RaisePropertyChanged(params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            PropertyChanged?.Invoke(this, new 
            PropertyChangedEventArgs(propertyName));
        }
    }

    public INavigation Navigation { get; set; }
} 
```

`ViewModel`类是所有`ViewModels`的基类。这不是要单独实例化的，所以我们将其标记为抽象。它实现了`INotifyPropertyChanged`，这是在.NET 基类库中的`System.ComponentModel`中定义的一个接口。这个接口只定义了一件事：`PropertyChanged`事件。我们的`ViewModel`必须在我们希望 GUI 意识到属性的任何更改时引发此事件。这可以通过手动添加代码到属性的 setter 中来完成，也可以使用**中间语言**（**IL**）编织器，比如`PropertyChanged.Fody`。我们将在下一节详细讨论这个问题。

我们还在这里采取了一个小捷径，通过在`ViewModel`中添加一个`INavigation`属性。这将在以后帮助我们进行导航。这也是可以（也应该）抽象的，因为我们不希望`ViewModel`依赖于 Xamarin.Forms，以便能够在任何平台上重用`ViewModels`。

# 介绍 PropertyChanged.Fody

实现`ViewModel`的传统方式是从基类（比如我们之前定义的`ViewModel`）继承，然后添加以下代码：

```cs
public class MyTestViewModel : ViewModel
{
    private string name;
    public string Name 
    {
       get { return name; }
       set { name = value; RaisePropertyChanged(nameof(Name)); }
    }
}
```

我们想要添加到`ViewModel`的每个属性都会产生六行代码。你可能会认为这并不太糟糕。然而，考虑到一个`ViewModel`可能潜在地包含 10 到 20 个属性，这很快就会变成大量的代码。我们可以做得更好。

只需几个简单的步骤，我们就可以使用一个名为`PropertyChanged.Fody`的工具，在构建过程中自动注入几乎所有的代码：

1.  在.NET Standard 库中，安装`PropertyChanged.Fody` NuGet 包。

1.  创建一个名为`FodyWeavers.xml`的文件，并添加以下 XML 代码：

```cs
<?xml version="1.0" encoding="utf-8" ?>
<Weavers>
    <PropertyChanged />
</Weavers>
```

`PropertyChanged.Fody`将扫描程序集，查找实现`INotifyPropertyChanged`接口的任何类，并添加所需的代码来引发`PropertyChanged`事件。它还会处理属性之间的依赖关系，这意味着如果您有一个属性根据其他两个属性返回值，那么如果这两个值中的任何一个发生变化，它都会被引发。

结果是我们之前的测试类每个属性的代码都被简化为一行。这使得代码更易读，因为一切都是在幕后发生的：

```cs
public class MyTestViewModel : ViewModel
{
    public string Name { get; set; }
}
```

值得注意的是，有许多不同的插件可以用来使 Fody 自动化任务，例如日志记录或方法装饰。查看[`github.com/Fody/Fody`](https://github.com/Fody/Fody)获取更多信息。

# 创建 MainViewModel

到目前为止，我们主要是在准备编写构成应用程序本身的代码。`MainViewModel`是将显示给用户的第一个视图的`ViewModel`。它将负责为待办事项列表提供数据和逻辑。随着我们在本章中的进展，我们将创建基本的`ViewModels`并向其中添加代码：

1.  在`ViewModels`文件夹中创建一个名为`MainViewModel`的类。

1.  添加以下模板代码并解决引用：

```cs
public class MainViewModel : ViewModel
{
    private readonly TodoItemRepository repository;

    public MainViewModel(TodoItemRepository repository)
    {
        this.repository = repository;
        Task.Run(async () => await LoadData());
    }

    private async Task LoadData()
    {
    }
}
```

这个类中的结构是我们将来会重用的所有`ViewModels`。

让我们总结一下我们希望`ViewModel`具有的重要功能：

+   我们从`ViewModel`继承以获得共享逻辑，例如`INotifyPropertyChanged`接口和常见导航代码。

+   所有对其他类的依赖项，例如存储库和服务，都通过`ViewModel`的构造函数传递。这将由**依赖注入**模式处理，更具体地说，由我们使用的依赖注入实现 Autofac 处理。

+   我们使用异步调用`LoadData()`作为初始化`ViewModel`的入口点。不同的 MVVM 库可能以不同的方式执行此操作，但基本功能是相同的。

# 创建 TodoItemViewModel

`TodoItemViewModel`是在`MainView`上表示待办事项列表中每个项目的`ViewModel`。它不会有自己的整个视图（尽管可能会有），而是将由`ListView`中的模板呈现。当我们为`MainView`创建控件时，我们将回到这一点。

这里重要的是，这个`ViewModel`将代表一个单个项目，无论我们选择在哪里呈现它。

让我们创建`TodoItemViewModel`：

1.  在`ViewModels`文件夹中创建一个名为`TodoItemViewModel`的类。

1.  添加以下模板代码并解决引用：

```cs
public class TodoItemViewModel : ViewModel
{
    public TodoItemViewModel(TodoItem item) => Item = item;

    public event EventHandler ItemStatusChanged;
    public TodoItem Item { get; private set; }
    public string StatusText => Item.Completed ? "Reactivate" : 
    "Completed";
}
```

与任何其他`ViewModel`一样，我们从`ViewModel`继承`TodoItemViewModel`。我们遵循在构造函数中注入所有依赖项的模式。在这种情况下，我们在构造函数中传递`TodoItem`类的实例，`ViewModel`将使用它来向视图公开。

`ItemStatusChanged`事件处理程序将在以后用于向视图发出信号，表明`TodoItem`的状态已更改。`Item`属性允许我们访问传入的项目。

`StatusText`属性用于使待办事项的状态在视图中可读。

# 创建 ItemViewModel

`ItemViewModel`表示待办事项列表中的项目，可用于创建新项目和编辑现有项目的视图：

1.  在`ViewModels`文件夹中，创建一个名为`ItemViewModel`的类。

1.  按照以下代码添加代码：

```cs
using DoToo.Models;
using DoToo.Repositories;
using System;
using System.Windows.Input;
using Xamarin.Forms;

namespace DoToo.ViewModels
{
    public class ItemViewModel : ViewModel
    {
        private TodoItemRepository repository;

        public ItemViewModel(TodoItemRepository repository)
        {
            this.repository = repository;
        } 
    }
}
```

模式与前两个`ViewModels`相同：

+   我们使用依赖注入将`TodoItemRepository`传递给`ViewModel`

+   我们使用从`ViewModel`基类继承来添加基类定义的公共功能

# 创建 MainView

现在我们已经完成了`ViewModels`，让我们创建视图所需的骨架代码和 XAML。我们要创建的第一个视图是`MainView`，这是将首先加载的视图：

1.  在.NET Standard 库中创建一个名为`Views`的文件夹。

1.  右键单击`Views`文件夹，选择添加，然后单击新建项....

1.  在左侧的 Visual C# Items 节点下选择 Xamarin.Forms。

1.  选择 Content Page 并将其命名为`MainView`。

1.  单击添加以创建页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/675b96dd-3e2c-4935-afe2-cda0047cfcf9.png)

让我们向新创建的视图添加一些内容：

1.  打开`MainView.xaml`。

1.  删除`ContentPage`根节点下面的所有模板代码，并在以下代码中添加标记为粗体的 XAML 代码：

```cs
<?xml version="1.0" encoding="utf-8"?>
<ContentPage xmlns="http://xamarin.com/schemas/2014/forms" 
             xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml" 
             xmlns:local="clr-namespace:DoToo"
             x:Class="DoToo.Views.MainView" 
             Title="Do Too!">

 <ContentPage.ToolbarItems>
 <ToolbarItem Text="Add" />
 </ContentPage.ToolbarItems>

 <Grid>
 <Grid.RowDefinitions>
 <RowDefinition Height="auto" />
 <RowDefinition Height="*" />
 </Grid.RowDefinitions>

 <Button Text="Toggle filter" />

 <ListView Grid.Row="1">
 </ListView>
 </Grid>
</ContentPage> 
```

为了能够访问自定义转换器，我们需要添加对本地命名空间的引用。行`为我们定义了这个命名空间。在这种情况下，我们不会直接使用它，但定义本地命名空间是一个好主意。如果我们创建自定义控件，我们可以通过编写类似`<local:MyControl />`的方式来访问它们。

`ContentPage`上的`Title`属性为页面提供标题。根据我们运行的平台不同，标题的显示方式也不同。例如，如果我们使用标准导航栏，它将在 iOS 和 Android 的顶部显示。页面应该始终有一个标题。

`ContentPage.Toolbar`节点定义了一个工具栏项，用于添加新的待办事项。它也会根据平台的不同而呈现不同的样式，但它始终遵循特定于平台的 UI 指南。

Xamarin.Forms 页面（以及一般的 XML 文档）只能有一个根节点。Xamarin.Forms 页面中的根节点将填充页面本身的`Content`属性。由于我们希望我们的`MainView`包含一个项目列表和页面顶部的按钮来切换过滤器（在所有项目和仅活动项目之间切换），我们需要添加一个`Layout`控件来定位它们在页面上的位置。`Grid`是一个控件，允许您根据行和列来划分可用空间。

对于我们的`MainView`，我们想要添加两行。第一行是由按钮的高度计算出的空间（`Height="auto"`），第二行占用所有剩余的可用空间用于`Listview`（`Height="*"`）。像`ListView`这样的元素是使用`Grid.Row`和`Grid.Column`属性在网格中定位的。如果未指定这些属性，这两个属性都默认为`0`，就像`Button`一样。

如果您对`Grid`的工作原理感兴趣，您应该在互联网上搜索有关 Xamarin.Forms `Grid`的更多信息，或者学习官方文档[`docs.microsoft.com/en-us/xamarin/xamarin-forms/user-interface/layouts/grid`](https://docs.microsoft.com/en-us/xamarin/xamarin-forms/user-interface/layouts/grid)。

我们还需要将`ViewModel`与视图连接起来。这可以通过在视图的构造函数中传递`ViewModel`来完成：

1.  通过展开解决方案资源管理器中的`MainView.xaml`文件，打开`MainView`的代码后文件。

1.  在以下文件的顶部添加`using DoToo.ViewModels`语句，以及现有的`using`语句。

1.  通过添加下面代码中标记为粗体的代码，修改类的构造函数如下：

```cs
public MainView(MainViewModel viewModel)
{ 
    InitializeComponent();
    viewModel.Navigation = Navigation;
 BindingContext = viewModel;
}
```

我们通过与`ViewModels`相同的模式，通过构造函数传递任何依赖项来实现。视图始终依赖于`ViewModel`。为了简化项目，我们还将页面的`Navigation`属性直接分配给`ViewModel`基类中定义的`Navigation`属性。在较大的项目中，我们可能还希望将此属性抽象化，以确保我们将`ViewModels`与 Xamarin.Forms 完全分离。但是，对于这个应用程序来说，直接引用它是可以的。

最后，我们将`ViewModel`分配给页面的`BindingContext`。这告诉 Xamarin.Forms 绑定引擎使用我们的`ViewModel`来创建后续的绑定。

# 创建 ItemView

接下来是第二个视图。我们将用它来添加和编辑待办事项列表项：

1.  创建一个新的 Content Page（与我们创建`MainView`的方式相同），并将其命名为`ItemView`。

1.  编辑 XAML，并使其看起来像以下代码：

```cs
 <?xml version="1.0" encoding="UTF-8"?>
 <ContentPage xmlns="http://xamarin.com/schemas/2014/forms" 
              xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml" 
              x:Class="DoToo.Views.ItemView"
              Title="New todo item">

 <ContentPage.ToolbarItems>
 <ToolbarItem Text="Save" />
 </ContentPage.ToolbarItems>

 <StackLayout Padding="14">
 <Label Text="Title" />
 <Entry />
 <Label Text="Due" />
 <DatePicker />
 <StackLayout Orientation="Horizontal">
 <Switch />
 <Label Text="Completed" />
 </StackLayout>
 </StackLayout>
 </ContentPage> 
```

与`MainView`一样，我们需要一个标题。我们现在将为其提供一个默认标题`"New todo item"`，但以后当我们重用此视图进行编辑时，我们将将其更改为`"Edit todo item"`。用户必须能够保存新的或编辑后的项目，因此我们添加了一个工具栏保存按钮。页面的内容使用`StackLayout`来组织控件。`StackLayout`根据它计算出的元素占用的空间，垂直（默认选项）或水平地添加元素。这是一个 CPU 密集型的过程，因此我们应该只在布局的小部分上使用它。在`StackLayout`中，我们添加一个`Label`，它将是`Entry`控件下面的一行文本。`Entry`控件是一个文本输入控件，将包含待办事项列表项的名称。然后我们有一个`DatePicker`的部分，用户可以在其中选择待办事项的截止日期。最后一个控件是一个`Switch`控件，它呈现一个切换按钮来控制项目何时完成，并在其旁边有一个标题。由于我们希望这些控件在水平方向上显示在一起，因此我们使用水平`StackLayout`来实现这一点。

视图的最后一步是将`ItemViewModel`连接到`ItemView`：

1.  通过展开解决方案资源管理器中的`ItemView.xaml`文件来打开`ItemView`的代码文件。

1.  修改类的构造函数，使其看起来像以下代码。添加粗体标记的代码。

1.  在现有的`using`语句下面的文件顶部添加`DoToo.ViewModels`语句：

```cs
public ItemView (ItemViewModel viewmodel)
{
    InitializeComponent ();
 viewmodel.Navigation = Navigation;
 BindingContext = viewmodel;
}
```

这段代码与我们为`MainView`添加的代码相同，只是`ViewModel`的类型不同。

# 通过 Autofac 进行依赖注入的连接

早些时候，我们讨论了依赖注入模式，该模式规定所有依赖项（例如存储库和视图模型）必须通过类的构造函数传递。这有几个好处：

+   它增加了代码的可读性，因为我们可以快速确定所有外部依赖关系

+   它使依赖注入成为可能

+   它通过模拟类使单元测试成为可能

+   我们可以通过指定对象是单例还是每次解析都是一个新实例来控制对象的生命周期

依赖注入是一种模式，它让我们能够在运行时确定在创建对象时应将对象的哪个实例传递给构造函数。我们通过定义一个容器来注册所有类的类型来实现这一点。我们让我们正在使用的框架解析它们之间的任何依赖关系。假设我们要求容器提供`MainView`。容器负责解析`MainViewModel`和类之间的任何依赖关系。

为了设置这一点，我们需要引用一个名为 Autofac 的库。还有其他选择，所以请随意切换到更适合您需求的选项。我们还需要一个入口点来将类型解析为实例。为此，我们将定义一个基本的`Resolver`类。为了将所有内容包装起来，我们需要一个引导程序，我们将调用它来初始化依赖注入配置。

# 向 Autofac 添加引用

我们需要引用 Autofac 才能开始。我们将使用 NuGet 来安装所需的软件包：

1.  通过右键单击解决方案节点并单击“管理解决方案的 NuGet 软件包”来打开 NuGet 管理器。

1.  单击浏览，然后在搜索框中键入`autofac`。

1.  在项目下的所有复选框中打勾，然后向下滚动，单击安装：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/2454a7ee-4123-4a08-8ddf-e7dcc11be688.png)

# 创建解析器

解析器将负责根据我们请求的类型为我们创建对象。让我们创建解析器：

1.  在.NET Standard 库项目的根目录中，创建一个名为`Resolver.cs`的新文件。

1.  将以下代码添加到文件中：

```cs
using Autofac;

namespace DoToo
{
    public static class Resolver
    {
        private static IContainer container;

        public static void Initialize(IContainer container)
        {
            Resolver.container = container;
        }

        public static T Resolve<T>()
        {
            return container.Resolve<T>();
        }
    }
}
```

`IContainer`类型的`container`属性在`Autofac`中定义，并表示一个保存如何解析类型的配置的容器。`Initialize`方法接受实现`IContainer`接口的对象的实例，并将其分配给`container`属性。`Resolve`方法使用`container`将类型解析为对象的实例。虽然一开始可能会觉得奇怪使用这个，但随着经验的增加，它会变得更容易。

# 创建 bootstrapper

bootstrapper 的责任是初始化 Autofac。它将在应用程序启动时被调用。我们可以按以下方式创建它：

1.  在.NET Standard 库的根目录中，创建一个名为`Bootstrapper.cs`的新文件。

1.  输入以下代码：

```cs
using Autofac;
using System.Linq;
using Xamarin.Forms;
using DoToo.Views;
using DoToo.Repositories;
using DoToo.ViewModels;

namespace DoToo
{
    public abstract class Bootstrapper
    {
        protected ContainerBuilder ContainerBuilder { get; private 
        set; }

        public Bootstrapper()
        {
            Initialize();
            FinishInitialization();
        }

        protected virtual void Initialize()
        {
            var currentAssembly = Assembly.GetExecutingAssembly();
            ContainerBuilder = new ContainerBuilder();

            foreach (var type in currentAssembly.DefinedTypes
                      .Where(e => 
                             e.IsSubclassOf(typeof(Page)) ||
                             e.IsSubclassOf(typeof(ViewModel)))) 
            {
                ContainerBuilder.RegisterType(type.AsType());
            }

            ContainerBuilder.RegisterType<TodoItemRepository>().SingleInstance();
        }

        private void FinishInitialization()
        {
            var container = ContainerBuilder.Build();
            Resolver.Initialize(container);
        }
    }
}
```

`Bootstrapper`将被每个平台继承，因为这是应用程序执行的起点。这也给了我们添加特定于平台的配置的选项。为了确保我们从该类继承，我们将其定义为抽象的。

`ContainerBuilder`是在`Autofac`中定义的一个类，它在我们完成配置后负责为我们创建`container`。`container`的构建发生在最后定义的`FinishInitialization`方法中，并且在构造函数调用虚拟的`Initialize`方法后立即调用。我们可以重写`Initialize`方法在每个平台上添加自定义注册。

`Initialize`方法扫描程序集中从`Page`或`ViewModel`继承的任何类型，并将它们添加到`container`中。它还将`TodoItemRepository`作为单例添加到`container`中。这意味着每次我们请求`TodoItemRepository`时，我们将获得相同的实例。Autofac 的默认行为（这可能在不同的库之间有所不同）是每次解析时获得一个新实例。

# 在 iOS 上添加 bootstrapper

iOS 的`Bootstrapper`是.NET Standard 库中通用 bootstrapper 的简单包装器，但增加了一个`Init`方法，在启动时将被调用：

1.  在 iOS 项目的根目录中，创建一个名为`Bootstrapper.cs`的新类。

1.  向其中添加以下代码：

```cs
public class Bootstrapper : DoToo.Bootstrapper 
{
    public static void Init()
    {
        var instance = new Bootstrapper();
    }
} 
```

`Init`方法可能看起来很奇怪，因为我们没有保留对我们创建的实例的引用。但请记住，我们确实在`Resolver`类内部保留对`Resolver`实例的引用，而`Resolver`本身是一个单例。

iOS 的最后一步是在正确的位置调用`Init`方法：

1.  打开`AppDelegate.cs`。

1.  找到`FinishedLaunching`方法并添加粗体代码：

```cs
public override bool FinishedLaunching(UIApplication app, NSDictionary options)
{
    global::Xamarin.Forms.Forms.Init();
    Bootstrapper.Init();
    LoadApplication(new App());

    return base.FinishedLaunching(app, options);
}
```

# 在 Android 中添加 bootstrapper

与 iOS 一样，Android 的`Bootstrapper`是.NET Standard 库中通用 bootstrapper 的简单包装器，但增加了一个在启动时将被调用的`Init`方法：

1.  在 Android 项目的根目录中，创建一个名为`Bootstrapper.cs`的新类。

1.  向其中添加以下代码：

```cs
public class Bootstrapper : DoToo.Bootstrapper
{
    public static void Init()
    {
        var instance = new Bootstrapper();
    }
}
```

然后我们需要调用这个`Init`方法。在`OnCreate`中调用`LoadApplication`之前做这件事是一个好地方：

1.  打开`MainActivity.cs`。

1.  找到`OnCreate`方法并添加粗体代码：

```cs
protected override void OnCreate(Bundle bundle)
{
    TabLayoutResource = Resource.Layout.Tabbar;
    ToolbarResource = Resource.Layout.Toolbar;

    base.OnCreate(bundle);

    global::Xamarin.Forms.Forms.Init(this, bundle);
    Bootstrapper.Init();
    LoadApplication(new App());
}
```

# 在 UWP 中添加 bootstrapper

UWP 的 bootstrapper 与其他平台相同：

1.  在 UWP 项目的根目录中，创建一个名为`Bootstrapper.cs`的新类。

1.  向其中添加以下代码：

```cs
public class Bootstrapper : DoToo.Bootstrapper
{
    public static void Init()
    {
        var instance = new Bootstrapper();
    }
}
```

与其他平台一样，我们需要在适当的位置调用`Init`方法：

1.  在 UWP 项目中，打开`App.xaml.cs`文件。

1.  找到对`Xamarin.Forms.Forms.Init()`方法的调用，并添加粗体代码：

```cs
Xamarin.Forms.Forms.Init(e);
Bootstrapper.Init();
```

# 使应用程序运行

我们可以按以下方式首次启动应用程序：

1.  通过展开.NET Standard 库中的`App.xaml`节点，打开`App.xaml.cs`。

1.  找到构造函数。

1.  添加`using`语句以使用`DoToo.Views`，并添加以下粗体代码行：

```cs
public App ()
{
    InitializeComponent();
    MainPage = new NavigationPage(Resolver.Resolve<MainView>());
}
```

添加的行解决了`MainView`（以及所有依赖项，包括`MainViewModel`和`TodoItemRepository`）并将其包装成`NavigationPage`。`NavigationPage`是 Xamarin.Forms 中定义的一个页面，它添加了导航栏并允许用户导航到其他视图。

就是这样！此时，您的项目应该启动。根据您使用的平台不同，它可能看起来像下面的截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/xmr-frm-pj/img/4adb68f9-ea33-467f-96c3-1a0bc8c7c3f7.png)

# 添加数据绑定

数据绑定是 MVVM 的核心。这是`Views`和`ViewModel`相互通信的方式。在 Xamarin.Forms 中，我们需要两样东西来实现数据绑定：

1.  我们需要一个对象来实现`INotifyPropertyChanged`。

1.  我们需要将页面的`BindingContext`设置为该对象。我们已经在`ItemView`和`MainView`上都这样做了。

数据绑定的一个非常有用的特性是它允许我们进行双向通信。例如，当将文本绑定到`Entry`控件时，数据绑定对象上的属性将直接更新。考虑以下 XAML：

```cs
<Entry Text="{Binding Title} />
```

为了使其工作，我们需要在对象上有一个名为`Title`的字符串属性。我们必须查看文档，定义一个对象，并让**Intellisense**为我们提供提示，以找出我们的属性应该是什么类型。

执行某种操作的控件，比如`Button`，通常会公开一个名为`Command`的属性。这个属性是`ICommand`类型的，我们可以返回一个`Xamarin.Forms.Command`或我们自己的实现。`Command`属性将在下一节中解释，我们将使用它来导航到`ItemView`。

# 从`MainView`导航到`ItemView`以添加新项目

在`MainView`中有一个`Addtoolbar`按钮。当用户点击此按钮时，我们希望导航到`ItemView`。这样做的 MVVM 方式是定义一个命令，然后将该命令绑定到按钮。让我们添加代码：

1.  打开`ViewModels/MainViewModel.cs`。

1.  为`System.Windows.Input`，`DoToo.Views`和`Xamarin.Forms`添加`using`语句。

1.  将以下属性添加到类中：

```cs
public ICommand AddItem => new Command(async () =>
{
    var itemView = Resolver.Resolve<ItemView>();
    await Navigation.PushAsync(itemView);
}); 
```

所有命令都应公开为通用的`ICommand`。这样可以抽象出实际的命令实现，这是一个很好的一般实践。命令必须是一个属性；在我们的情况下，我们正在创建一个新的`Command`对象，然后将其分配给这个属性。该属性是只读的，对于`Command`来说通常是可以的。命令的操作（当执行命令时要运行的代码）被传递给`Command`对象的构造函数。

命令的操作通过`Resolver`创建一个新的`ItemView`，并且 Autofac 构建必要的依赖项。一旦创建了新的`ItemView`，我们只需告诉`Navigation`服务为我们将其推送到堆栈上。

之后，我们只需将`ViewModel`中的`AddItem`命令与视图中的添加按钮连接起来：

1.  打开`Views/MainView.xaml`。

1.  为`ToolbarItem`添加`Command`属性：

```cs
<ContentPage.ToolbarItems>
    <ToolbarItem Text="Add" Command="{Binding AddItem}" />
</ContentPage.ToolbarItems>
```

运行应用程序并点击“添加”按钮以导航到新项目视图。请注意，返回按钮会自动出现。

# 向列表中添加新项目

现在我们已经完成了导航到新项目的添加。现在让我们添加所需的代码来创建一个新项目并将其保存到数据库中：

1.  打开`ViewModels/ItemViewModel.cs`。

1.  在粗体中添加以下代码。

1.  解决对`System.Windows.Input`的引用：

```cs
public class ItemViewModel : ViewModel
{
    private TodoItemRepository repository;

    public TodoItem Item { get; set; }

    public ItemViewModel(TodoItemRepository repository)
    {
        this.repository = repository;
        Item = new TodoItem() { Due = DateTime.Now.AddDays(1) };
    }

 public ICommand Save => new Command(async () => 
 {
 await repository.AddOrUpdate(Item);
 await Navigation.PopAsync();
 });
}
```

`Item`属性保存对我们要添加或编辑的当前项目的引用。在构造函数中创建一个新项目，当我们想要编辑一个项目时，我们可以简单地将我们自己的项目分配给这个属性。除非我们执行最后定义的`Save`命令，否则新项目不会添加到数据库中。项目添加或更新后，我们将视图从导航堆栈中移除，并再次返回到`MainView`。

由于导航将页面保留在堆栈中，框架声明了反映可以在堆栈上执行的操作的方法。从堆栈中移除顶部项目的操作称为**弹出堆栈**，因此我们有`PopAsync()`而不是`RemoveAsync()`。要将页面添加到导航堆栈中，我们将其推送，因此该方法称为`PushAsync()`。

现在我们已经用必要的命令和属性扩展了`ItemViewModel`，是时候在 XAML 中对它们进行数据绑定了：

1.  打开`ViewModels/ItemView.xaml`。

1.  添加粗体标记的代码：

```cs
<?xml version="1.0" encoding="UTF-8"?>
<ContentPage  

             x:Class="DoToo.Views.ItemView">
    <ContentPage.ToolbarItems>
        <ToolbarItem Text="Save" Command="{Binding Save}" />
    </ContentPage.ToolbarItems>

    <StackLayout Padding="14">
        <Label Text="Title" />
        <Entry Text="{Binding Item.Title}" />
        <Label Text="Due" />
        <DatePicker Date="{Binding Item.Due}" />
        <StackLayout Orientation="Horizontal">
            <Switch IsToggled="{Binding Item.Completed}" />
            <Label Text="Completed" />
        </StackLayout>
    </StackLayout>

</ContentPage> 
```

对`ToolbarItems`命令属性的绑定会在用户点击`Save`链接时触发`ItemViewModel`公开的`Save`命令。值得再次注意的是，任何名为`Command`的属性都表示将发生某种操作，我们必须将其绑定到实现`ICommand`接口的对象的实例。

代表标题的`Entry`控件被数据绑定到`ItemViewModel`的`Item.Title`属性，`Datepicker`和`Switch`控件以类似的方式绑定到它们各自的属性。

我们本可以直接在`ItemViewModel`上公开`Title`、`Due`和`Complete`作为属性，但选择重用已经存在的`TodoItem`作为引用。只要`TodoItem`对象的属性实现了`INotifyPropertyChange`接口，这是可以的。

# 在 MainView 中绑定 ListView

没有项目列表的待办事项列表没有多大用处。让我们用项目列表扩展`MainViewModel`：

1.  打开`ViewModels/MainViewModel.cs`。

1.  添加`System.Collections.ObjectModel`和`System.Linq`的`using`语句。

1.  为待办事项列表项添加一个属性：

```cs
public ObservableCollection<TodoItemViewModel> Items { get; set; }
```

`ObservableCollection`就像普通集合，但它有一个有用的超能力。它可以通知监听器列表中的更改，例如添加或删除`items`。`Listview`将侦听列表中的更改，并根据这些更改自动更新自身。

现在我们需要一些数据：

1.  打开`ViewModels/MainViewModel.cs`。

1.  替换（或完成）`LoadData`方法，并创建`CreateTodoItemViewModel`和`ItemStatusChanged`方法。

1.  通过添加`using`语句解析对`DoToo.Models`的引用：

```cs
private async Task LoadData()
{
    var items = await repository.GetItems();
    var itemViewModels = items.Select(i =>  
    CreateTodoItemViewModel(i));
    Items = new ObservableCollection<TodoItemViewModel>  
    (itemViewModels); 
}

private TodoItemViewModel CreateTodoItemViewModel(TodoItem item)
{
    var itemViewModel = new TodoItemViewModel(item);
    itemViewModel.ItemStatusChanged += ItemStatusChanged;
    return itemViewModel;
}

private void ItemStatusChanged(object sender, EventArgs e)
{
}
```

`LoadData`方法调用存储库以获取所有项目。然后我们将每个待办事项包装在`TodoItemViewModel`中。这将包含特定于视图的更多信息，我们不希望将其添加到`TodoItem`类中。将普通对象包装在`ViewModel`中是一个很好的做法；这样可以更简单地向其添加操作或额外的属性。`ItemStatusChanged`是一个存根，当我们将待办事项的状态从*活动*更改为*已完成*或反之时将调用它。

我们还需要连接一些来自存储库的事件，以了解数据何时发生变化：

1.  打开`ViewModels/MainViewModel.cs`。

1.  添加以下粗体代码：

```cs
public MainViewModel(TodoItemRepository repository)
{
   repository.OnItemAdded += (sender, item) => 
 Items.Add(CreateTodoItemViewModel(item));
 repository.OnItemUpdated += (sender, item) => 
 Task.Run(async () => await LoadData());

    this.repository = repository;

    Task.Run(async () => await LoadData());
}   
```

当项目添加到存储库时，无论是谁添加的，`MainView`都会将其添加到项目列表中。由于项目集合是可观察集合，列表将会更新。如果项目得到更新，我们只需重新加载列表。

让我们将我们的项目数据绑定到`ListView`：

1.  打开`MainView.xaml`并找到`ListView`元素。

1.  修改以反映以下代码：

```cs
<ListView Grid.Row="1"
 RowHeight="70"
          ItemsSource="{Binding Items}">
    <ListView.ItemTemplate>    
        <DataTemplate>
            <ViewCell>
                <Grid Padding="15,10">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="10" />
                        <ColumnDefinition Width="*" />
                    </Grid.ColumnDefinitions>

                    <BoxView Grid.RowSpan="2" />
                    <Label Grid.Column="1"
                           Text="{Binding Item.Title}"
                           FontSize="Large" />
                    <Label Grid.Column="1"
                           Grid.Row="1"
                           Text="{Binding Item.Due}"
                           FontSize="Micro" />
                    <Label Grid.Column="1" 
 Grid.Row="1" 
 HorizontalTextAlignment="End" 
 Text="Completed" 
                           IsVisible="{Binding Item.Completed}"
                           FontSize="Micro" />
                </Grid>
            </ViewCell>
        </DataTemplate>
    </ListView.ItemTemplate>
</ListView>
```

`ItemsSource`绑定告诉`ListView`在哪里找到要迭代的集合，并且是本地的`ViewModel`。然而，在`ViewCell`节点内部的任何绑定都是针对我们在列表中迭代的每个项目的本地绑定。在这种情况下，我们绑定到`TodoItemViewModel`，其中包含名为`Item`的属性。这又有诸如`Title`、`Due`和`Completed`之类的属性。在定义绑定时，我们可以毫无问题地导航到对象的层次结构。

`DataTemplate`定义了每一行的外观。我们使用网格来分割空间，就像我们之前做的那样。

# 为项目状态创建一个 ValueConverter

有时，我们希望绑定到原始值的表示对象。这可能是基于布尔值的文本片段。例如，我们可能希望写*Yes*和*No*，或者返回一个颜色，而不是*true*和*false*。这就是`ValueConverter`派上用场的地方。它可以用于将一个值转换为另一个值。我们将编写一个`ValueConverter`，将待办事项的状态转换为颜色：

1.  在.NET Standard 库项目的根目录下，创建一个名为`Converters`的文件夹。

1.  创建一个名为`StatusColorConverter.cs`的类，并添加以下代码：

```cs
using System;
using System.Globalization;
using Xamarin.Forms;

namespace DoToo.Converters
{
    public class StatusColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType,
                              object parameter, CultureInfo  
                              culture)
        {
          return (bool)value ?   
          (Color)Application.Current.Resources["CompletedColor"]: 

          (Color)Application.Current.Resources["ActiveColor"];
        }

        public object ConvertBack(object value, Type targetType, 
                                  object parameter, CultureInfo 
                                  culture)
        {
            return null;
        }
    }
}
```

`ValueConverter`是实现`IValueConverter`的类。这只有两个方法被定义。当视图从`ViewModel`读取数据时，将调用`Convert`方法，而当`ViewModel`从视图获取数据时，将使用`ConvertBack`方法。`ConvertBack`方法仅用于从纯文本返回数据的控件，例如`Entry`控件。

如果我们查看`Convert`方法的实现，我们会注意到传递给该方法的任何值都是对象类型。这是因为我们不知道用户将什么类型绑定到我们正在添加`ValueConverter`的属性。我们还可能注意到，我们从资源文件中获取颜色。我们本可以在代码中定义颜色，但这是不推荐的，所以我们走了额外的路程，并将它们添加为`App.xaml`文件中的全局资源。资源是在完成本章后再次查看的好东西：

1.  在.NET Standard 库项目中打开`App.xaml`。

1.  添加以下`ResourceDictionary`：

```cs
 <Application ...>
     <Application.Resources>
 <ResourceDictionary>
 <Color x:Key="CompletedColor">#1C8859</Color>
 <Color x:Key="ActiveColor">#D3D3D3</Color>
 </ResourceDictionary>
     </Application.Resources>
 </Application> 
```

`ResourceDictionary`可以定义各种不同的对象。我们只需要两种颜色，这两种颜色可以从`ValueConverter`中访问。请注意，这些可以通过给定的键访问，并且还可以使用静态资源绑定从任何其他 XAML 文件中访问。`ValueConverter`本身将被引用为静态资源，但来自本地范围。

# 使用 ValueConverter

我们想要在`MainView`中使用我们全新的`StatusColorConverter`。不幸的是，我们必须经过一些步骤才能实现这一点。我们需要做三件事：

+   在 XAML 中定义命名空间

+   定义一个表示转换器实例的本地资源

+   在绑定中声明我们要使用该转换器

让我们从命名空间开始：

1.  打开`Views/MainView.xaml`。

1.  在页面中添加以下命名空间：

```cs
<ContentPage xmlns="http://xamarin.com/schemas/2014/forms"
             xmlns:x="http://schemas.microsoft.com/winfx/2009/xaml"
             xmlns:converters="clr-namespace:DoToo.Converters"
             x:Class="DoToo.Views.MainView"
             Title="Do Too!>
```

在`MainView.xaml`文件中添加`Resource`节点：

1.  打开 Views/MainView.Xaml。

1.  在 XAML 文件的根元素下添加以下`ResourceDictionary`，显示为粗体：

```cs
<ContentPage ...>
    <ContentPage.Resources>
 <ResourceDictionary>
 <converters:StatusColorConverter  
             x:Key="statusColorConverter" />
 </ResourceDictionary>
 </ContentPage.Resources>    <ContentPage.ToolBarItems>
        <ToolbarItem Text="Add" Command="{Binding AddItem}" />
    </ContentPage.ToolbarItems>
    <Grid ...>
    </Grid>
</ContentPage>
```

这与全局资源字典具有相同的形式，但由于这个资源字典是在`MainView`中定义的，因此只能从那里访问。我们本可以在全局资源字典中定义这个，但通常最好将只在一个地方使用的对象定义在尽可能接近该位置的地方。

最后一步是添加转换器：

1.  在 XAML 中找到`BoxView`节点。

1.  添加粗体标记的`BackgroundColor` XAML：

```cs
<BoxView Grid.RowSpan="2" 
   BackgroundColor="{Binding Item.Completed, 
                     Converter={StaticResource  
                     statusColorConverter}}" />
```

我们在这里所做的是将一个布尔值绑定到一个接受`Color`对象的属性。然而，在数据绑定发生之前，`ValueConverter`将布尔值转换为颜色。这只是`ValueConverter`派上用场的许多情况之一。在定义 GUI 时请记住这一点。

# 使用命令导航到项目

我们希望能够查看所选待办事项的详细信息。当我们点击一行时，我们应该导航到该行中的项目。

为此，我们需要添加以下代码：

1.  打开`ViewModels/MainViewModel.cs`。

1.  在类中添加`SelectedItem`属性和`NavigateToItem`方法：

```cs
public TodoItemViewModel SelectedItem
{
    get { return null; }
    set 
    {
        Device.BeginInvokeOnMainThread(async () => await 
        NavigateToItem(value));
        RaisePropertyChanged(nameof(SelectedItem));
    }
}

private async Task NavigateToItem(TodoItemViewModel item)
{
    if (item == null)
    {
        return;
    }

    var itemView = Resolver.Resolve<ItemView>();
    var vm = itemView.BindingContext as ItemViewModel;
    vm.Item = item.Item;

    await Navigation.PushAsync(itemView);
}
```

`SelectedItem`属性是我们将数据绑定到`ListView`的属性。当我们在`ListView`中选择一行时，此属性将设置为表示该行的`TodoItemViewModel`。由于我们实际上不能在这里使用 Fody 来执行其`PropertyChanged`魔法，因为需要在 setter 中进行方法调用，所以我们需要老式地手动添加一个 getter 和一个 setter。

然后调用`NavigateToItem`，它使用`Resolver`创建一个新的`ItemView`。我们从新创建的`ItemView`中提取`ViewModel`并分配`TodoItemViewModel`包含的当前`TodoItem`。困惑吗？请记住，`TodoItemViewModel`实际上包装了一个`TodoItem`，我们要传递的就是这个项目到`ItemView`。

我们还没有完成。现在我们需要将新的`SelectedItem`属性数据绑定到视图中的正确位置：

1.  打开`Views/MainView.xaml`。

1.  找到`ListView`并添加以下属性：

```cs
<ListView x:Name="ItemsListView"
          Grid.Row="1"
          RowHeight="70"
          ItemsSource="{Binding Items}"
          SelectedItem="{Binding SelectedItem}">
```

`SelectedItem`属性将`ListView`的`SelectedItem`属性绑定到`ViewModel`属性。当`ListView`中的项目选择发生变化时，`ViewModels`的`SelectedItem`属性将被调用，我们将导航到新的和令人兴奋的视图。

`x:Name`属性用于命名`ListView`，因为我们确实需要进行一个小的丑陋的黑客来使其工作。导航完成后，`ListView`实际上将保持选定状态。当我们导航回来时，除非我们选择另一行，否则无法再次选择它。为了减轻这种情况，我们需要连接到`ListView`的`ItemSelected`事件，并直接重置`ListView`上的选定项目。这并不推荐，因为我们实际上不应该在我们的`Views`中有任何逻辑，但有时我们别无选择：

1.  打开`Views/MainView.xaml.cs`。

1.  在粗体中添加以下代码：

```cs
public MainView(MainViewModel viewmodel)
{
    InitializeComponent();
    viewmodel.Navigation = Navigation;
    BindingContext = viewmodel;

    ItemsListView.ItemSelected += (s, e) => 
    ItemsListView.SelectedItem = null;
}
```

现在我们应该能够导航到列表中的项目。

# 使用命令将项目标记为完成

我们需要添加一个功能，允许我们在*完成*和*活动*之间切换项目。可以导航到待办事项列表项的详细视图，但这对用户来说太麻烦了。相反，我们将在`ListView`中添加一个`ContextAction`。例如，在 iOS 中，可以通过向左滑动一行来访问它：

1.  打开`ViewModel/TodoItemViewModel.cs`。

1.  添加`using`语句以使用`System.Windows.Input`和`Xamarin.Forms`。

1.  添加一个命令来切换项目的状态和描述状态的一小段文本：

```cs
public ICommand ToggleCompleted => new Command((arg) =>
{
    Item.Completed = !Item.Completed;
    ItemStatusChanged?.Invoke(this, new EventArgs());
});
```

在这里，我们已经添加了一个命令来切换项目的状态。当执行时，它会反转当前的状态并触发`ItemStatusChanged`事件，以便通知订阅者。为了根据状态更改上下文操作按钮的文本，我们添加了一个`StatusText`属性。这不是一个推荐的做法，因为我们正在添加仅因特定 UI 情况而存在的代码到`ViewModel`中。理想情况下，这应该由视图处理，也许可以使用`ValueConverter`。然而，为了节省实现这些步骤的时间，我们将其留作一个字符串属性：

1.  打开`Views/MainView.xaml`。

1.  找到`ListView.ItemTemplate`节点并添加以下`ViewCell.ContextActions`节点：

```cs
<ListView.ItemTemplate>
    <DataTemplate>
        <ViewCell>
 <ViewCell.ContextActions>
 <MenuItem Text="{Binding StatusText}" 
 Command="{Binding ToggleCompleted}" />
 </ViewCell.ContextActions>
        <Grid Padding="15,10">
        ...
        </Grid>
    </DataTemplate>
</ListView.ItemTemplate>
```

# 使用命令创建过滤器切换功能

我们希望能够在查看仅活动项目和所有项目之间切换。我们将创建一个简单的机制来实现这一点。

在`MainViewModel`中进行更改：

1.  打开`ViewModels/MainViewModel.cs`并找到`ItemStatusChangeMethod`。

1.  添加`ItemStatusChanged`方法的实现和一个名为`ShowAll`的属性来控制过滤：

```cs
private void ItemStatusChanged(object sender, EventArgs e)
{
 if (sender is TodoItemViewModel item)
 {
 if (!ShowAll && item.Item.Completed)
 {
 Items.Remove(item);
 }

 Task.Run(async () => await 
        repository.UpdateItem(item.Item));
 }
} 

public bool ShowAll { get; set; }
```

当我们使用上一部分的上下文操作时，`ItemStatusChanged`事件处理程序会被触发。由于发送者始终是一个对象，我们尝试将其转换为`TodoItemViewModel`。如果成功，我们检查是否可以从列表中删除它，如果`ShowAll`不为真的话。这是一个小优化；我们本可以调用`LoadData`并重新加载整个列表，但由于 Items 列表是一个`ObservableCollection`，它会通知`ListView`列表中已删除了一个项目。我们还调用存储库来更新项目以保持状态的更改。

`ShowAll`属性控制着我们的筛选器处于哪种状态。我们需要调整`LoadData`方法以反映这一点：

1.  在`MainViewModel`中找到`Load`方法。

1.  添加标记为粗体的代码行：

```cs
private async Task LoadData()
{
    var items = await repository.GetItems();

    if (!ShowAll)
    {
 items = items.Where(x => x.Completed == false).ToList();
    }

    var itemViewModels = items.Select(i => 
    CreateTodoItemViewModel(i));
    Items = new ObservableCollection<TodoItemViewModel>  
    (itemViewModels);
}
```

如果`ShowAll`为假，则我们将列表的内容限制为尚未完成的项目。我们可以通过两种方法来实现这一点，即`GetAllItems()`和`GetActiveItems()`，或者使用可以传递给`GetItems()`的筛选参数。花一分钟时间思考一下我们将如何实现这一点。

让我们添加代码来切换筛选器：

1.  打开`ViewModels/MainViewModel.cs`。

1.  添加`FilterText`和`ToggleFilter`属性：

```cs
public string FilterText => ShowAll ? "All" : "Active";

public ICommand ToggleFilter => new Command(async () =>
{
    ShowAll = !ShowAll;
    await LoadData();
});
```

`FilterText`属性是一个只读属性，用于以人类可读的形式显示状态的字符串。我们本可以使用`ValueConverter`来实现这一点，但为了节省时间，我们简单地将其公开为一个属性。`ToggleFilter`命令的逻辑是状态的简单反转，然后调用`LoadData`。这反过来会导致列表的重新加载。

在我们可以筛选项目之前，我们需要连接筛选按钮：

1.  打开`Views/MainView.xaml`。

1.  找到控制筛选的`Button`（文件中唯一的按钮）。

1.  调整代码以反映以下代码：

```cs
<Button Text="{Binding FilterText, StringFormat='Filter: {0}'}"
        Command="{Binding ToggleFilter}" />
```

就这个功能而言，应用现在已经完成了！但它并不是很吸引人；我们将在接下来的部分处理这个问题。

# 布置内容

最后一部分是让应用看起来更加漂亮。我们只是浅尝辄止，但这应该能给你一些关于样式工作原理的想法。

# 设置应用程序范围的背景颜色

样式是将样式应用于元素的一种很好的方法。它们可以应用于类型的所有元素，也可以应用于由键引用的元素，如果您添加了`x:Key`属性：

1.  打开.NET Standard 项目中的`App.xaml`。

1.  将以下 XAML 添加到文件中，该部分为粗体：

```cs
<ResourceDictionary>
    <Style TargetType="NavigationPage">
 <Setter Property="BarBackgroundColor" Value="#A25EBB" />
 <Setter Property="BarTextColor" Value="#FFFFFF" />
 </Style>  <Style x:Key="FilterButton" TargetType="Button">
 <Setter Property="Margin" Value="15" />
 <Setter Property="BorderWidth" Value="1" />
 <Setter Property="BorderRadius" Value="6" /> 
 <Setter Property="BorderColor" Value="Silver" />
 <Setter Property="TextColor" Value="Black" />
 </Style>

    <Color x:Key="CompletedColor">#1C8859</Color>
    <Color x:Key="ActiveColor">#D3D3D3</Color>        
</ResourceDictionary>
```

我们要应用的第一个样式是导航栏中的新背景颜色和文本颜色。第二个样式将应用于筛选按钮。我们可以通过设置`TargetType`来定义样式，指示 Xamarin.Forms 可以将此样式应用于哪种类型的对象。然后，我们可以添加一个或多个要设置的属性。结果与我们直接在 XAML 代码中添加这些属性的效果相同。

没有`x:Key`属性的样式将应用于`TargetType`中定义的类型的所有实例。具有键的样式必须在用户界面的 XAML 中显式分配。当我们在下一部分定义筛选按钮时，我们将看到这种情况的例子。

# 布置 MainView 和 ListView 项目

在本节中，我们将改进`MainView`和`ListView`的外观。打开`Views/MainView.xaml`，并在 XAML 代码中的每个部分后面应用粗体中的更改。

# 筛选按钮

筛选按钮允许我们切换列表的状态，只显示活动的待办事项和所有待办事项。让我们对其进行样式设置，使其在布局中更加突出：

1.  找到筛选按钮。

1.  进行以下更改：

```cs
<Button Style="{StaticResource FilterButton}"
        Text="{Binding FilterText, StringFormat='Filter: {0}'}" 
        BackgroundColor="{Binding ShowAll, Converter={StaticResource 
        statusColorConverter}}"
        TextColor="Black"
        Command="{Binding ToggleFilter}">

<Button.Triggers>
 <DataTrigger TargetType="Button" Binding="{Binding ShowAll}"  
      Value="True">
 <Setter Property="TextColor" Value="White" />
 </DataTrigger>
 </Button.Triggers>
</Button>
```

使用`StaticResource`应用样式。在资源字典中定义的任何内容，无论是在`App.xaml`文件中还是在本地 XAML 文件中，都可以通过它访问。然后我们根据`MainViewModel`的`ShowAll`属性设置`BackgroundColor`，并将`TextColor`设置为`Black`。

`Button.Triggers`节点是一个有用的功能。我们可以定义多种类型的触发器，当满足某些条件时触发。在这种情况下，我们使用数据触发器来检查`ShowAll`的值是否更改为 true。如果是，我们将`TextColor`设置为白色。最酷的部分是，当`ShowAll`再次变为 false 时，它会切换回之前的颜色。

# 触摸 ListView

`ListView`可能需要进行一些微小的更改。第一个更改是将到期日期字符串格式化为更加人性化、可读的格式，第二个更改是将已完成标签的颜色更改为漂亮的绿色色调：

1.  打开`Views/MainView.xaml`。

1.  找到在`ListView`中绑定`Item.Due`和`Item.Completed`的标签：

```cs
<Label Grid.Column="1"
       Grid.Row="1" 
       Text="{Binding Item.Due, StringFormat='{0:MMMM d, yyyy}'}" 
       FontSize="Micro" />

<Label Grid.Column="1" 
       Grid.Row="1" 
       HorizontalTextAlignment="End" 
       Text="Completed" 
       IsVisible="{Binding Item.Completed}"
       FontSize="Micro" 
       TextColor="{StaticResource CompletedColor}" /> 
```

我们在绑定中添加了字符串格式化，以使用特定格式格式化日期。在这种情况下，`0:MMMM d, yyyy`格式将日期显示为字符串，格式为 2019 年 5 月 5 日。

我们还为`Completed`标签添加了一个文本颜色，只有在项目完成时才可见。我们通过在`App.xaml`中引用我们的字典来实现这一点。

# 摘要

现在，我们应该对从头开始创建 Xamarin.Forms 应用程序的所有步骤有了很好的掌握。我们已经了解了项目结构和新创建项目中的重要文件。我们谈到了依赖注入，使用 Autofac，并通过创建所需的所有`Views`和`ViewModels`来学习了 MVVM 的基础知识。我们还涵盖了在 SQLite 中进行数据存储，以便以快速和安全的方式在设备上持久保存数据。利用本章所学的知识，现在您应该能够创建任何您喜欢的应用程序的骨架。

下一章将重点介绍创建一个更丰富的用户体验，创建一个可以在屏幕上移动的图像匹配应用程序。我们将更仔细地研究 XAML 以及如何创建自定义控件。
