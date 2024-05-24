# 使用 UNO 平台创建跨平台 C# 应用（一）

> 原文：[`zh.annas-archive.org/md5/1FD2D236733A02B9975D919E422AEDD3`](https://zh.annas-archive.org/md5/1FD2D236733A02B9975D919E422AEDD3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

开发人员越来越多地被要求构建在多个操作系统和浏览器上运行的本机应用程序。过去，这意味着学习新技术并制作多个应用程序副本。但是 Uno 平台允许您使用已经熟悉的用于构建 Windows 应用程序的工具、语言和 API 来开发也可以在其他平台上运行的应用程序。本书将帮助您创建面向客户以及业务线的应用程序，这些应用程序可以在您选择的设备、浏览器或操作系统上使用。

这本实用指南使开发人员能够利用他们的 C#和 XAML 知识，使用 Uno 平台编写跨平台应用程序。本书充满了技巧和实际示例，将帮助您构建常见场景的应用程序。您将首先通过逐步解释基本概念来了解 Uno 平台，然后开始为不同的业务线创建跨平台应用程序。在本书中，您将使用示例来教您如何结合您现有的知识来管理常见的开发环境并实现经常需要的功能。

通过本 Uno 平台开发书的学习，您将学会如何使用 Uno 平台编写自己的跨平台应用程序，并使用其他工具和库来加快应用程序开发过程。

# 本书适合的读者

本书适用于熟悉 Windows 应用程序开发并希望利用其现有技能构建跨平台应用程序的开发人员。要开始阅读本书，需要具备 C#和 XAML 的基本知识。任何具有使用 WPF、UWP 或 WinUI 进行应用程序开发的基本经验的人都可以学会如何使用 Uno 平台创建跨平台应用程序。

# 本书涵盖内容

第一章《介绍 Uno 平台》介绍了 Uno 平台，解释了它的设计目的以及何时使用它。之后，本章将介绍如何设置开发机器并安装必要的工具。

第二章《编写您的第一个 Uno 平台应用程序》介绍了创建您的第一个 Uno 平台应用程序，并涵盖了应用程序的结构。通过本章结束时，您将已经编写了一个可以在不同平台上运行并根据应用程序运行的操作系统显示内容的小型 Uno 平台应用程序。

第三章《使用表单和数据》将带您开发一个以数据为重点的虚构公司 UnoBookRail 的业务线应用程序。本章涵盖了显示数据，对表单进行输入验证以及将数据导出为 PDF。

第四章《使您的应用程序移动化》介绍了使用 Uno 平台开发移动应用程序。除此之外，本章还涵盖了在具有不稳定互联网连接的设备上使用远程数据，根据应用程序运行的平台对应用程序进行样式设置，以及使用设备功能，如相机。

第五章《使您的应用程序准备好迎接现实世界》涵盖了编写面向外部客户的移动应用程序。作为其中的一部分，它涵盖了在设备上本地持久化数据，本地化您的应用程序，并使用 Uno 平台编写可访问的应用程序。

第六章《在图表和自定义 2D 图形中显示数据》探讨了在 Uno 平台应用程序中显示图形和图表。本章涵盖了使用诸如 SyncFusion 之类的库以及使用 SkiaSharp 创建自定义图形。最后，本章介绍了编写响应屏幕尺寸变化的用户界面。

*第七章*，*测试您的应用程序*，向您介绍了使用 Uno.UITest 进行 UI 测试。此外，本章还涵盖了使用 WinAppDriver 编写自动化 UI 测试，为应用程序的 Windows 10 版本编写单元测试，以及测试应用程序的可访问性。

*第八章*，*部署您的应用程序并进一步*，将指导您将 Xamarin.Forms 应用程序带到 Uno 平台上，并将 WASM Uno 平台应用程序部署到 Azure。之后，本章将介绍部署 Uno 平台应用程序并加入 Uno 平台社区。

# 充分利用本书

在本书中，我们将使用 Windows 10 上的 Visual Studio 2019 和.NET CLI 来开发 Uno 平台应用程序。我们将介绍安装必要的扩展和 CLI 工具；但是，安装 Visual Studio 和.NET CLI 将不在范围之内。要安装所需的软件，您需要一个正常的互联网连接。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/B17132_Preface_Table_1.jpg)

**如果您使用本书的数字版本，我们建议您自己输入代码或从书的 GitHub 存储库中访问代码（下一节中提供了链接）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从 GitHub 上的[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform)下载本书的示例代码文件。如果代码有更新，将在 GitHub 存储库中更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快来看看吧！

# 代码实战

本书的“代码实战”视频可在[`bit.ly/3yHTfYL`](https://bit.ly/3yHTfYL)上观看

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图和图表的彩色图像。您可以在此处下载：[`static.packt-cdn.com/downloads/9781801078498_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781801078498_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“在`UnoAutomatedTestsApp`文件夹内，创建一个名为`UnoAutomatedTestsApp.UITests`的文件夹。”

代码块设置如下：

```cs
private void ChangeTextButton_Click(object sender,
                                    RoutedEventArgs e)
{
    helloTextBlock.Text = "Hello from code behind!";
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cs
<skia:SKXamlCanvas 
xmlns:skia="using:SkiaSharp.Views.UWP" 
PaintSurface="OnPaintSurface" />
```

任何命令行输入或输出都以以下方式编写：

```cs
dotnet new unoapp -o MyApp
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词以**粗体**显示。这是一个例子：“单击菜单栏中的**View**，然后单击**Test Explorer**，打开**Test Explorer**。”

提示或重要说明

以这种方式出现。


# 第一部分：了解 Uno 平台

本书的这一部分将为您提供关于 Uno 平台的所有信息，以及如何确定哪些项目适合使用它的知识。然后，它将详细介绍如何设置开发环境以构建 Uno 平台的应用程序，并指导您创建您的第一个应用程序。然后，它将探讨使用 Uno 平台构建的应用程序的基础知识，并展示您如何使用您已经熟悉的工具和技能。此外，它将向您展示开发人员在大多数应用程序中需要执行的一些最常见任务。

在本节中，我们包括以下章节：

+   第一章，介绍 Uno 平台

+   第二章，编写您的第一个 Uno 平台应用程序


# 第一章：介绍 Uno 平台

**Uno 平台**是一个跨平台、单一代码库解决方案，用于开发在各种设备和操作系统上运行的应用程序。它在丰富的 Windows 开发 API 和工具基础上构建。这使您可以利用您已经拥有的 Windows 应用程序开发技能，并将其用于构建 Android、iOS、macOS、WebAssembly、Linux 等应用程序。

本书将是您学习 Uno 平台的指南。它将向您展示如何使用 Uno 平台的功能来构建各种解决现实场景的不同应用程序。

在本章中，我们将涵盖以下主题：

+   了解 Uno 平台是什么

+   使用 Uno 平台

+   设置您的开发环境

通过本章结束时，您将了解为什么要使用 Uno 平台开发应用程序，以及它最适合帮助您构建哪些类型的应用程序。您还将能够设置您的环境，以便在阅读本书后续章节时准备开始构建应用程序。

# 技术要求

在本章中，您将被引导完成设置开发机器的过程。要在本书中的所有示例中工作，您需要运行以下任何一种操作系统的机器：

+   **Windows 10**（1809）或更高版本

+   **macOS 10.15**（Catalina）或更高版本

如果您只能访问一个设备，您仍然可以跟随本书的大部分内容。本书将主要假设您正在使用 Windows 机器。我们只会在绝对必要时展示使用 Mac 的示例。

本章没有源代码。但是，其他章节的代码可以在以下网址找到：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform)。

# 了解 Uno 平台是什么

根据网站（[`platform.uno/`](https://platform.uno/)），Uno 平台是“*用于 Windows、WebAssembly、iOS、macOS、Android 和 Linux 的单一代码库应用程序的第一个和唯一 UI 平台*。”

这是一个复杂的句子，让我们分解一下关键元素：

+   作为一个 UI 平台，它是一种构建具有**用户界面**（**UI**）的应用程序的方式。这与那些基于文本并从命令行（或等效方式）运行、嵌入在硬件中或以其他方式进行交互的平台形成对比，比如通过语音。

+   使用*单一代码库*意味着您只需编写一次代码，即可在多个设备和操作系统上运行。具体来说，这意味着相同的代码可以为应用程序将在的每个平台编译。这与将代码转换或转译为另一种编程语言然后编译为另一个平台的工具形成对比。它也是唯一的单一代码库，而不是输出。一些可比较的工具在每个操作系统上创建一个独特的包，或者在 HTML 和 JavaScript 中创建所有内容，并在嵌入式浏览器中运行。Uno 平台都不这样做。相反，它为每个平台生成本机应用程序包。

+   Windows 应用程序基于 Windows 10 的**Universal Windows Platform**（**UWP**）。微软目前正在进行工作，将**WinUI 3**作为 UWP 的继任者。Uno 平台已与微软合作，以确保 Uno 平台可以在 WinUI 3 达到可比较的操作水平时轻松过渡。

+   Windows 支持还包括由 SkiaSharp 提供支持的**Windows Presentation Foundation**（**WPF**），用于需要在较旧版本的 Windows（7.1 或 8.1）上运行的应用程序。

+   在 WebAssembly 中运行的应用程序将所有代码编译为在 Web 浏览器中运行。这意味着它们可以在任何兼容浏览器的设备上访问，而无需在服务器上运行代码。

+   通过支持 iOS，创建的应用程序可以在 iPhone 和 iPad 上运行。

+   对于 macOS 的支持，应用程序可以在 MacBook、iMac 或 Mac Mini 上运行。

+   对 Android 的支持适用于运行 Android 操作系统的手机和平板电脑。

+   Linux 支持适用于特定的 Linux PC 等价发行版，并由 SkiaSharp 提供支持。

Uno 平台通过重用 Microsoft 为构建 UWP 应用程序创建的工具、API 和 XAML 来完成所有这些工作。

回答“Uno 平台是什么？”的另一种方式是，它是一种*一次编写代码，到处运行*的方式。 “到处”这个确切的定义并不精确，因为它不包括每个能够运行代码的嵌入式系统或微控制器。然而，许多开发人员和企业长期以来一直希望一次编写代码，并在多个平台上轻松运行。Uno 平台使这成为可能。

微软的 UWP 早期的批评之一是它只在 Windows 上是*通用*的。有了 Uno 平台，开发人员现在可以真正地使他们的 UWP 应用程序变得真正通用。

## Uno 平台的简要历史

随着当今跨平台工具的多样化，很容易忘记 2013 年的选择有多有限。那时，没有通用工具可以轻松构建在多个操作系统上运行的本地应用程序。

就在那时，加拿大软件设计和开发公司**nventive**([`nventive.com/`](https://nventive.com/))面临着一个挑战。他们在为 Windows 和 Microsoft 工具构建应用程序方面拥有大量知识和经验，但他们的客户也要求他们为 Android 和 iOS 设备创建应用程序。他们发明了一种方法，将他们为 Windows Phone（后来是 UWP）应用程序编写的代码编译并转移到其他平台，而不是重新培训员工或通过为不同平台构建多个版本的相同软件来复制工作。

到 2018 年，很明显这种方法对他们来说是成功的。然后他们做了以下两件事：

1.  他们将他们创建的工具转变为一个开源项目，称之为 Uno 平台。

1.  他们增加了对 WebAssembly 的支持。

作为一个开源项目，这使得其他开发人员解决同样的问题可以共同合作。Uno 平台自那时以来已经看到了来自 200 多名外部贡献者的数千次贡献，并且参与度已经扩展到支持更多平台，并为最初支持的平台添加额外功能。

作为一个开源项目，它是免费使用的。此外，它得到了一家商业模式由 Red Hat 广泛采用的公司的支持。使用是免费的，并且有一些免费的公共支持。然而，专业支持、培训和定制开发只能通过付费获得。

## Uno 平台的工作原理

Uno 平台以不同的方式工作，并使用多种基础技术，具体取决于您要构建的平台。这些总结在*图 1.1*中：

+   如果您正在为 Windows 10 构建应用程序，Uno 平台不会做任何事情，而是让所有 UWP 工具编译和执行您的应用程序。

+   如果您正在为 iOS、macOS 或 Android 构建应用程序，Uno 平台会将您的 UI 映射到本机平台等效，并使用本机`Xamarin`库调用其正在运行的操作系统。它会为每个操作系统生成适当的本机包。

+   如果您正在构建一个 WebAssembly 应用程序，Uno 平台会将您的代码编译成`mono.wasm`运行时，并将 UI 映射到 HTML 和 CSS。然后，它将其打包成一个`.NET`库，作为静态 Web 内容与 Uno 平台 Web 引导程序一起启动。

+   为了创建 Linux 应用程序，Uno 平台将您的代码转换为`.NET`等效，并使用**GTK3**的`.NET5`应用程序来呈现 UI。

+   Uno 平台通过将编译后的代码包装在一个简单的**WPF**（**NETCore 3.1**）应用程序中，并使用**SkiaSharp**来渲染 UI，从而创建了 Windows 7 和 8 的应用程序。

请参考以下图表：

![图 1.1 - Uno 平台的高级架构](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_1.01_B17132.jpg)

图 1.1 - Uno 平台的高级架构

无论您要构建的操作系统或平台是什么，Uno 平台都使用该平台的本机控件。这使您的应用程序能够获得完全本机应用程序的体验和性能。唯一的例外是它使用 SkiaSharp。通过使用 SkiaSharp，Uno 平台在画布上绘制所有 UI 内容，而不是使用平台本机控件。Uno 平台不会向正在运行的应用程序添加额外的抽象层（就像使用容器的跨平台解决方案可能会在外壳应用程序中使用嵌入的 WebView 一样）。

Uno 平台使您能够使用单个代码库做很多事情。但它能做到一切吗？

## 它是灵丹妙药吗？

编写代码一次并在所有地方运行该代码的原则既强大又吸引人。然而，有必要意识到以下两个关键点：

+   并非所有应用程序都应该为所有平台创建。

+   这并不是不了解应用程序将在哪些平台上运行的借口。

此外，并非所有事情都需要应用程序。假设您只想分享一些不经常更新的信息。在这种情况下，静态网页的网站可能更合适。

*只是因为你能做某事并不意味着你应该*这个教训也适用于应用程序。当您看到创建可以在多个平台上运行的应用程序是多么容易时，您可能会被诱惑在您可以的所有地方部署您的应用程序。在这样做之前，您需要问一些重要的问题：

+   *应用程序是否在所有平台上都需要或想要？*人们是否希望并需要在您提供的所有平台上使用它？如果不是，您可能会浪费精力将其放在那里。

+   *应用程序在所有平台上都有意义吗？*假设应用程序的关键功能涉及在户外捕捉图像。在 PC 或 Mac 上提供它是否有意义？相反，如果应用程序需要输入大量信息，这是人们愿意在手机的小屏幕上做的吗？您对应用程序在哪里可用的决定应该由其功能和将使用它的人员决定。不要让您的决定仅基于可能性。

+   *您能在所有平台上支持它吗？*通过在平台上发布、维护和支持应用程序来获得的价值是否能够证明在该平台上释放、维护和支持应用程序的时间和精力？如果只有少数人在特定类型的设备上使用应用程序，但他们产生了许多支持请求，重新评估您对这些设备的支持是可以的。

没有技术能为所有场景提供完美的解决方案，但希望您已经看到 Uno 平台提供的机会。现在让我们更仔细地看看为什么以及何时您可能希望使用它。

# 使用 Uno 平台

现在您知道了 Uno 平台是什么，我们将看看在选择是否使用它时需要考虑什么。有四个因素需要考虑：

+   您已经知道的知识。

+   您希望针对哪些平台？

+   应用程序所需的功能。

+   与其他选择相比如何。

让我们探讨 Uno 平台与这些因素的关系。

## Uno 平台允许您使用您已经知道的知识

Uno 平台最初是为在**Visual Studio**中使用 C#和 XAML 的开发人员创建的。如果这对您来说很熟悉，那么开始使用 Uno 平台将会很容易，因为您将使用您已经知道的软件。

如果您已经熟悉 UWP 开发，差异将是最小的。如果您熟悉 WPF 开发，XAML 语法和可用功能会有轻微差异。在阅读本书的过程中，您将学到构建 Uno 平台所需的一切。只要您不期望一切都像 WPF 中那样工作，您就会没问题。此外，由于 WinUI 和 Uno 平台团队正在努力消除存在的轻微差异，您可能永远不会注意到差异。

如果您不了解 C#或 XAML，Uno 平台可能仍然适合您，但是由于本书假定您熟悉这些语言，您可能会发现先阅读* C# 9 and .NET 5 – Modern Cross-Platform Development – Fifth Edition, Mark J. Price, Packt Publishing*和*Learn WinUI 3.0, Alvin Ashcraft, Packt Publishing*会有所帮助。

## Uno 平台支持许多平台

Uno 平台的一个伟大之处在于它允许您为多个平台构建应用程序。Uno 平台支持最常见的平台，但如果您需要构建在小众平台或专用设备上运行的应用程序，那么它可能不适合您。此外，如果您需要支持旧版本的平台或操作系统，您可能需要找到解决方法或替代方案。以下表格显示了您可以使用 Uno 平台构建的受支持平台的版本：

![图 1.2 - Uno 平台支持的最低受支持平台版本](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_1.02_B17132.jpg)

图 1.2 - Uno 平台支持的最低受支持平台版本

支持多个平台也可能是有利的，即使您希望在不同平台上实现非常不同的应用行为或功能。可以通过创建多个解决方案来支持多个平台，而不是将所有内容合并到单个解决方案中。

Uno 平台声称可以实现高达 99%的代码和 UI 重用。当您需要在所有设备上使用相同的内容时，这非常有用。但是，如果您需要不同的行为或针对不同平台高度定制的 UI（这是我们将在未来章节中探讨的内容），则在不同的解决方案中构建不同的应用程序可能会更容易，而不是在代码中放置大量的条件逻辑。对于有多少条件代码是太多，没有硬性规定，这取决于项目和个人偏好。只需记住，如果您发现您的代码充满了使其难以管理的条件注释，那么这仍然是一个选择。

因此，也可以使用 Uno 平台为单个平台构建应用程序。您可能不希望创建一个可以在任何地方运行的应用程序。您可能只对单个平台感兴趣。如果是这种情况，您也可以使用 Uno 平台。如果您的需求发生变化，未来还可以轻松添加其他平台。

## Uno 平台是否能够满足您的应用程序的所有需求？

Uno 平台能够重用 UWP API 构建其他平台的核心在于它具有将 UWP API 映射到其他平台上的等效代码。由于时间、实用性和优先级的限制，并非所有 API 都适用于所有平台。一般指导方针是，最常见的 API 在最广泛的平台上都是可用的。假设您需要使用更专业的功能或针对的不是 Android、iOS、Mac 或 WebAssembly 的其他内容，建议您检查您所需的功能是否可用。

提示

我们建议在开始编写代码之前确认您的应用程序所需的功能是否可用。这将使您能够避免在开发过程的后期出现任何不愉快的惊喜。

由于印刷书籍的永久性以及新功能的频繁添加和更多 API 的支持，不适合在此列出支持的内容。相反，您可以在以下 URL 查看支持功能的高级列表：[`platform.uno/docs/articles/supported-features.html`](https://platform.uno/docs/articles/supported-features.html)。还有一个支持的 UI 元素列表，位于以下 URL：[`platform.uno/docs/articles/implemented-views.html`](https://platform.uno/docs/articles/implemented-views.html)。当然，确认可用和不可用的最终方法是检查以下 URL 的源代码：[`github.com/unoplatform/uno`](https://github.com/unoplatform/uno)。

如果您尝试使用不受支持的 API，您将在 Visual Studio 中看到提示，如*图 1.3*所示。如果您在运行时尝试使用此 API，您要么什么也不会得到（`NOOP`），要么会得到`NotSupported`异常：

![图 1.3 - Visual Studio 中指示不受支持的 API 的示例](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_1.03_B17132.jpg)

图 1.3 - Visual Studio 中指示不受支持的 API 的示例

如有必要，您可以使用`Windows.Foundation.Metadata.ApiInformation`类在运行时检查支持的功能。

作为一个开源项目，您也可以选择自己添加任何当前不受支持的功能。将这样的添加贡献回项目总是受到赞赏的，团队也始终欢迎新的贡献者。

## Uno Platform 与其他替代方案相比如何？

如前所述，有许多工具可用于开发在多个平台上运行的应用程序。我们不打算讨论所有可用的选项，因为它们可以与前面的三个要点进行评估和比较。但是，由于本书旨在面向已经熟悉 C＃、XAML 和 Microsoft 技术的开发人员，因此适当提及`Xamarin.Forms`。

`Xamarin.Forms`是在大约与 Uno Platform 同时创建的，并且有几个相似之处。其中两个关键点是使用 C＃和 XAML 来创建在多个操作系统上运行的应用程序。两者都通过提供对包含 C＃绑定的`Xamarin.iOS`和`Xamarin.Android`库的抽象来实现这一点。

Uno Platform 与`Xamarin.Forms`之间的两个最大区别如下：

+   Uno Platform 支持构建更多平台的应用。

+   Uno Platform 重用了 UWP API 和 XAML 语法，而不是构建自定义 API。

第二点对于已经熟悉 UWP 开发的开发人员来说很重要。许多`Xamarin.Forms`元素和属性的名称听起来相似，因此记住这些变化可能是具有挑战性的。

`Xamarin.Forms`的第 5 版于 2020 年底发布，预计将是`Xamarin.Forms`的最后一个版本。它将被**.NET 多平台应用 UI**（**MAUI**）所取代，作为.NET 6 的一部分。.NET MAUI 将支持从单个代码库构建 iOS、Android、Windows 和 Mac 的应用程序。但是，它将不包括构建 WebAssembly 的能力。微软已经拥有 Blazor 用于构建 WebAssembly，因此不打算将此功能添加到.NET MAUI 中。

.NET 6 将带来许多新的功能。其中一些功能是专门为.NET MAUI 添加的。一旦成为.NET 6 的一部分，这些功能将不仅限于.NET MAUI。它们也将适用于 Uno Platform 应用。其中最明显的新功能之一是拥有一个可以为不同平台生成不同输出的单个项目。这将大大简化所需的解决方案结构。

重要提示

在我们撰写本书时，微软正在准备发布**WinUI 3**作为下一代 Windows 开发平台。这将建立在 UWP 之上，是**Project Reunion**努力的一部分，旨在使所有 Windows 功能和 API 对开发人员可用，无论他们使用的 UI 框架或应用程序打包技术如何。

由于 WinUI 3 是 UWP 开发的继任者，Uno 平台团队已经公开表示，计划和准备正在进行中，Uno 平台将过渡到使用 WinUI 3 作为其构建基础。这是与微软合作完成的，允许 Uno 平台团队获取 WinUI 代码并修改以在其他地方工作。您可以放心，您现在制作的任何东西都将有过渡路径，并利用 WinUI 带来的好处和功能。

另一个类似的跨平台解决方案，使用 XAML 来定义应用程序的 UI 的是 Avalonia ([`avaloniaui.net/`](https://avaloniaui.net/))。然而，它不同之处在于它只专注于桌面环境的应用程序。

现在您已经对 Uno 平台是什么以及为什么要使用它有了扎实的了解，您需要设置好您的机器，以便编写代码和创建应用程序。

# 设置您的开发环境

现在您已经熟悉 Uno 平台，无疑渴望开始编写代码。我们将在下一章开始，但在那之前，您需要设置好开发环境。

Visual Studio 是开发 Uno 平台应用程序最流行的**集成开发环境**（**IDE**）。其中一个重要原因是它具有最广泛的功能集，并且对构建 UWP 应用程序的支持最好。

## 使用 Visual Studio 进行开发

使用 Visual Studio 构建 Uno 平台应用程序，您需要做以下三件事：

+   确保您有**Visual Studio 2019**版本**16.3**或更高版本，尽管建议使用最新版本。

+   安装必要的工作负载。

+   安装项目和项目模板。

### 安装所需的工作负载

作为 Visual Studio 的一部分可以安装的许多工具、库、模板、SDK 和其他实用程序统称为**组件**。有超过 100 个可用的组件，相关组件被分组到工作负载中，以便更容易选择所需的内容。您可以在**Visual Studio 安装程序**中选择工作负载，这些显示在*图 1.4*中：

![图 1.4 - Visual Studio 安装程序显示各种工作负载选项](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_1.04_B17132.jpg)

图 1.4 - Visual Studio 安装程序显示各种工作负载选项

要构建 Uno 平台应用程序，您需要安装以下工作负载：

+   **通用 Windows 平台开发**

+   **使用.NET 进行移动开发**

+   **ASP.NET 和 Web 开发**

+   .NET Core 跨平台开发

### 从市场安装所需的模板

为了更容易构建您的 Uno 平台应用程序，提供了多个项目和项目模板。这些作为**Uno 平台解决方案模板**扩展的一部分安装。您可以从 Visual Studio 内部安装这个，或者直接从市场安装。

#### 从 Visual Studio 内部安装模板

要安装包含模板的扩展，请在 Visual Studio 中执行以下操作：

1.  转到**扩展**>**管理扩展**。

1.  搜索`Uno`。它应该是第一个结果。

1.  点击**下载**按钮。

1.  点击**关闭**，让扩展安装程序完成，然后重新启动**Visual Studio**。

![图 1.5 - 在“管理扩展”对话框中显示的 Uno 平台解决方案模板](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_1.05_B17132.jpg)

图 1.5 - 在“管理扩展”对话框中显示的 Uno 平台解决方案模板

#### 从市场安装模板

按照以下步骤从市场安装扩展：

1.  转到[`marketplace.visualstudio.com`](https://marketplace.visualstudio.com)并搜索`Uno`。它应该是返回的第一个结果。

或者，直接转到以下网址：[`marketplace.visualstudio.com/items?itemName=nventivecorp.uno-platform-addin`](https://marketplace.visualstudio.com/items?itemName=nventivecorp.uno-platform-addin)。

1.  点击**下载**按钮。

1.  双击下载的`.vsix`文件以启动安装向导。

1.  按照向导中的步骤操作。

安装了工作负载和模板后，您现在可以开始构建应用程序了。但是，如果您想要开发 iOS 或 Mac 应用，您还需要设置 Mac 设备，以便您可以从 Windows 上的 Visual Studio 连接到它。

## 使用其他编辑器和 IDE

在 Windows PC 上使用 Visual Studio 2019 并不是强制的，Uno 平台团队已经努力使构建 Uno 平台应用程序尽可能灵活。因此，您可以在现有的工作模式和偏好中使用它。

### 使用命令行安装所需的模板

除了在 Visual Studio 中使用模板外，还可以通过命令行安装它们以供使用。要以这种方式安装它们，请在命令行或终端中运行以下命令：

```cs
dotnet new -i Uno.ProjectTemplates.Dotnet
```

完成此命令后，它将列出所有可用的模板。您应该看到多个以*uno*开头的短名称条目。

### 使用 Visual Studio for Mac 构建 Uno 平台应用程序

要使用 Visual Studio for Mac 构建 Uno 平台应用程序，您将需要以下内容：

+   **Visual Studio** for Mac 版本 8.8 或更高（建议使用最新版本）。

+   **Xcode 12.0**或更高（建议使用最新版本）。

+   Apple ID。

+   **.NET Core 3.1**和**5.0 SDK**。

+   **GTK+3**（用于运行**Skia/GTK**项目）。

+   安装的模板（参见上一节）。

+   通过打开**首选项**菜单选项，然后选择**其他**>**预览功能**并选中**在新项目对话框中显示所有.NET Core 模板**，可以使模板在 Visual Studio for Mac 中可见。

所有这些的链接都可以在以下网址找到：[`platform.uno/docs/articles/get-started-vsmac.html`](https://platform.uno/docs/articles/get-started-vsmac.html)。

### 使用 Visual Studio Code 构建 Uno 平台应用程序

您可以使用 Visual Studio Code 在 Windows、Linux 或 Mac 上构建 WebAssembly 应用程序。目前尚不支持使用它构建其他平台的应用程序。

要使用 Visual Studio Code 构建 Uno 平台应用程序，您将需要以下内容：

+   **Visual Studio Code**（建议使用最新版本）

+   Mono

+   **.NET Core 3.1**和**5.0 SDK**。

+   安装的模板（参见上一节）

+   **Visual Studio Code**的**C#**扩展

+   **Visual Studio Code**的**JavaScript Debugger**（夜间版）扩展

所有这些的链接都可以在以下网址找到：[`platform.uno/docs/articles/get-started-vscode.html`](https://platform.uno/docs/articles/get-started-vscode.html)。

### 使用 JetBrains Rider 构建 Uno 平台应用程序

可以在 Windows、Mac 和 Linux 上使用**JetBrains Rider**，但并非所有版本都可以构建所有平台。

要使用 JetBrains Rider 构建 Uno 平台应用程序，您将需要以下内容：

+   **Rider 版本 2020.2**或更高，建议使用最新版本

+   **Rider Xamarin Android Support Plugin**

+   .NET Core 3.1 和 5.0 SDK

+   安装的模板（参见上一节）

在使用 JetBrains Rider 时，还有一些额外的注意事项，如下所示：

+   目前还无法从 IDE 内部调试 WebAssembly 应用程序。作为一种解决方法，可以使用 Chromium 浏览器中的调试器。

+   如果在 Mac 上构建**Skia/GTK**项目，还需要安装**GTK+3**。

+   如果您希望在 Windows PC 上构建 iOS 或 Mac 应用程序，您将需要连接的 Mac（就像使用 Visual Studio 一样）。

所有这些链接和更多详细信息都可以在以下 URL 中找到：[`platform.uno/docs/articles/get-started-rider.html`](https://platform.uno/docs/articles/get-started-rider.html)。

重要提示

还可以使用 Blend for Visual Studio（在 Windows 上）来处理代码，就像对常规 UWP 应用程序一样。但是，Blend 不支持 Uno Platform 解决方案包含的所有项目类型。您可能会发现，有一个不包含这些项目的解决方案的单独版本，并且可以在 Blend 中访问该版本，这是有益的。

## 检查您的设置

Uno Platform 有一个**dotnet 全局工具**，可以检查您的机器是否设置正确，并引导您解决它发现的任何问题。它被称为**uno-check**，非常简单易用，如下所示：

1.  打开开发人员命令提示符、终端或 PowerShell 窗口。

1.  通过输入以下内容安装该工具：

```cs
dotnet tool install --global Uno.Check
```

1.  通过输入以下内容运行该工具：

```cs
uno-check
```

1.  按照它给出的任何提示，并享受查看以下消息：**恭喜，一切看起来都很棒！**

## 调试您的设置

无论您使用哪种 IDE 或代码编辑器，都会有许多部分，使用多个工具、SDK 甚至机器可能会让人难以知道在出现问题时从何处开始。以下是一些通用提示，可帮助找出问题所在。其中一些可能看起来很明显，但我宁愿因为提醒您检查一些明显的东西而显得愚蠢，也不愿让您浪费时间在未经检查的假设上：

+   尝试重新启动您的机器。是的，我知道，如果它经常不起作用，那将会很有趣。

+   仔细阅读任何错误消息，然后再次阅读。它们有时可能会有所帮助。

+   检查您是否已正确安装*所有*内容。

+   有什么改变了吗？即使您没有直接做，也可能已经自动或在您不知情的情况下进行了更改（包括但不限于操作系统更新、安全补丁、IDE 更新、其他应用程序的安装或卸载以及网络安全权限更改）。

+   如果有一个东西已经更新了，所有依赖项和引用的组件也已经更新了吗？通常情况下，当事物相互连接、共享引用或通信时，它们必须一起更新。

+   任何密钥或许可证已过期吗？

+   如果以前创建的应用程序出现问题，您可以创建一个新的应用程序并编译和运行吗？

+   您可以创建一个新的应用程序，并确认它在每个平台上都可以编译和运行吗？

+   如果在 Windows 上，您可以创建一个新的空白 UWP 应用程序，然后编译和调试它吗？

尝试使用其他工具进行等效操作或创建等效应用程序通常会产生不同的错误消息。此外，您还可能找到解决方案的路径，可以修复 Uno Platform 项目设置中的问题：

+   如果使用 WebAssembly 应用程序，您可以创建一个新的空白**ASP.NET** Web 应用程序或**Blazor**项目，并编译和调试吗？

+   如果 WebAssembly 应用程序在一个浏览器中无法工作，浏览器日志或调试窗口中是否显示错误消息？它在另一个浏览器中工作吗？

+   对于`Xamarin.Forms`应用程序？

+   如果存在特定于 Android 的问题，您可以使用 Android Studio 创建和调试应用程序吗？

+   如果使用 Mac，您可以使用 Xcode 创建和调试空白应用程序吗？

有关解决常见设置和配置问题的其他提示可以在以下两个 URL 中找到：

+   [`platform.uno/docs/articles/get-started-wizard.html#common-issues`](https://platform.uno/docs/articles/get-started-wizard.html#common-issues)

+   [`platform.uno/docs/articles/uno-builds-troubleshooting.html`](https://platform.uno/docs/articles/uno-builds-troubleshooting.html)

如果问题来自从 PC 连接到 Mac，Xamarin 文档可能会有所帮助。它可以在以下 URL 找到：[`docs.microsoft.com/en-us/xamarin/ios/get-started/installation/windows/connecting-to-mac/`](https://docs.microsoft.com/en-us/xamarin/ios/get-started/installation/windows/connecting-to-mac/)。这也可以帮助识别和解决 Uno Platform 项目中的问题。

有关特定 Uno 平台相关问题答案的详细信息可以在*第八章*中找到，*部署您的应用程序并进一步*。

# 总结

在本章中，我们了解了 Uno 平台是什么，它设计解决的问题以及我们可以将其用于哪些项目类型。然后，我们看了如何设置开发环境，使其准备好以便使用 Uno 平台构建第一个应用程序。

在下一章中，我们将构建我们的第一个 Uno 平台应用程序。我们将探索生成解决方案的结构，看看如何在不同环境中进行调试，并在这些不同环境中运行应用程序时进行自定义。我们将看看如何创建可在未来的 Uno 平台项目中使用的可重用库。最后，我们将看看创建 Uno 平台应用程序的其他可用选项。

# 进一步阅读

本章前面提到了以下标题，如果您对使用 C#和 XAML 不熟悉，这些标题可能提供有用的背景信息：

+   *C# 9 and .NET 5 – Modern Cross-Platform Development – Fifth Edition，Price，Packt Publishing（2020 年）*

+   *学习 WinUI 3.0，Ashcraft，Packt Publishing（2021 年）*


# 第二章：编写您的第一个 Uno 平台应用程序

在本章中，您将学习如何创建新的 Uno 平台应用程序，并了解典型的 Uno 平台应用程序的结构。首先，我们将介绍默认的 Uno 平台应用程序模板，包括不同的项目，并让您在 Windows 10 上运行您的第一个 Uno 平台应用程序。之后，我们将深入探讨在不同平台上运行和调试应用程序的方法，包括如何使用模拟器和调试应用程序的 WebAssembly（Wasm）版本。

由于 Uno 平台支持众多平台，并且越来越多的平台被添加到支持的平台列表中，因此在本书中，我们将只开发一部分支持的平台。以下平台是最突出和广泛使用的平台，因此我们将以它们为目标：Windows 10，Android，Web/Wasm，macOS 和 iOS。

虽然在本章中我们提到了其他平台以保持完整性，但其他章节将只包括前面提到的平台。这意味着我们不会向您展示如何在**Linux**、**Tizen**或**Windows 7/8**上运行或测试您的应用程序。

在本章中，我们将涵盖以下主题：

+   创建 Uno 平台应用程序并了解其结构

+   运行和调试您的应用程序，包括使用**XAML 热重载**和**C#编辑和继续**

+   使用 C#编译器符号和**XAML**前缀的特定于平台的代码

+   除了 Uno 平台应用程序之外的其他项目类型

在本章结束时，您将已经编写了您的第一个 Uno 平台应用程序，并根据运行平台进行了定制。除此之外，您将能够使用不同的 Uno 平台项目类型。

# 技术要求

本章假设您已经设置好了开发环境，包括安装了项目模板，就像在*第一章*中介绍的那样，*介绍 Uno 平台*。您可以在此处找到本章的源代码：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter02`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter02)。

查看以下视频以查看代码的实际操作：[`bit.ly/37Dt0Hg`](https://bit.ly/37Dt0Hg)

注意

如果您使用本书的数字版本，我们建议您自己输入代码或从书的 GitHub 存储库中访问代码。这样做将有助于避免与复制和粘贴代码相关的任何潜在错误。

# 创建您的第一个应用程序

创建项目的不同方式，因此我们将从使用 Visual Studio 的最常见方式开始。

## 使用 Uno 平台解决方案模板创建您的项目

创建 Uno 平台应用程序项目的过程与在 Visual Studio 中创建其他项目类型的过程相同。根据安装的扩展和项目模板，当过滤**Uno 平台**时，您将看到*图 2.1*中的选项列表。请注意，对于*图 2.1*，只安装了**Uno 平台解决方案模板**扩展：

![图 2.1 - 新项目对话框中 Uno 平台项目模板的列表](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_2.01_B17132.jpg)

图 2.1 - 新项目对话框中 Uno 平台项目模板的列表

使用**多平台应用程序（Uno 平台）**项目模板是开始使用 Uno 平台的最简单方式，因为它包含了构建和运行 Uno 平台应用程序所需的所有项目。 

让我们通过选择**多平台应用程序（Uno Platform）**项目类型并单击**下一步**来开始创建您的应用程序。 请注意，您不要选择**多平台库（Uno Platform）**选项，因为那将创建一个不同的项目类型，我们将在*超越默认跨平台应用程序结构*部分中介绍。 现在，您需要选择项目的名称、位置和解决方案名称，如*图 2.2*中所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_2.02_B17132.jpg)

图 2.2 - 配置多平台应用程序（Uno Platform）

在我们的案例中，我们将称我们的项目为`HelloWorld`，并将其保存在`D:\Projects`下，这意味着项目将存储在`D:\Projects\HelloWorld`中，而`HelloWorld.sln`解决方案将是顶级元素。 当然，您可以在任何您想要的文件夹中创建项目； `D:\Projects`只是一个例子。 请注意，您应尽可能靠近驱动器根目录创建项目，以避免路径过长的问题。 单击**创建**后，Visual Studio 将为您创建项目并打开解决方案。 您将在**Solution Explorer**中看到所有生成的项目。

如果您在 Visual Studio for Mac 中创建项目，生成的解决方案将包括**Windows Presentation Foundation**（**WPF**）和**Universal Windows Platform**（**UWP**）应用程序的项目头。 项目或平台头是在为特定平台编译应用程序时将被编译的相应项目。 因此，在 Windows 10 的情况下，将编译 UWP 头。 您需要使用 Windows PC 来构建这些应用程序。 如果您不想为这些平台构建，可以从解决方案中删除这些项目。 如果您将在 Windows 机器上单独构建这些项目，请在 Mac 上工作时从解决方案中卸载它们。

由于您的应用程序可能不针对 Uno Platform 支持的每个平台，您可能希望为您的应用程序删除那些头。 要做到这一点，请通过右键单击项目视图中的项目并单击**删除**来从解决方案中删除这些项目，如*图 2.3*所示：

![图 2.3 - 从解决方案中删除 Skia.Tizen 头](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.03_B17132.jpg)

图 2.3 - 从解决方案中删除 Skia.Tizen 头

从解决方案中删除项目后，项目仍然存在于磁盘上。 要完全删除它，您必须打开项目文件夹并删除相应的文件夹。 由于我们只针对 Windows 10、Android、Web、macOS 和 iOS，您可以从解决方案中删除`Skia.GTK`、`Skia.Tizen`、`Skia.Wpf`和`Skia.WpfHost`项目。

## 使用.NET CLI 创建您的项目

当然，您不必使用 Visual Studio 来创建您的 Uno Platform 应用程序。 您还可以使用 Uno Platform 的`dotnet new`模板。 您可以通过打开终端并输入以下内容来创建新项目：

```cs
dotnet new unoapp -o MyApp
```

这将创建一个名为**MyApp**的新项目。 您可以在 Uno Platform 的模板文档中找到所有 dotnet new 模板的概述（[`platform.uno/docs/articles/get-started-dotnet-new.html`](https://platform.uno/docs/articles/get-started-dotnet-new.html)）。

当然，并非每个人都希望将其应用程序针对每个平台，也不是每个应用程序都适合在每个平台上运行。 您可以通过在命令中包含特定标志来选择不为特定平台创建目标项目（下一节将详细介绍这些内容）。 例如，使用以下命令，您将创建一个不在 Linux 和其他 Skia 平台上运行的新项目，因为我们排除了 Skia 头：

```cs
dotnet new unoapp -o MyApp -skia-wpf=false -skia-gtk=false     -st=false
```

要获取`unoapp`模板的所有可用选项列表，可以运行`dotnet new unoapp -h`。

## 项目结构和头

在 Windows 上使用 Uno 平台解决方案模板在 Visual Studio 中创建项目时，`Platforms`文件夹和`HelloWorld.Shared`共享 C#项目中有两个不同的顶级元素。请注意，在解决方案视图中，这些是两个顶级元素，但是`Platforms`文件夹在磁盘上不存在。相反，所有项目，包括共享项目，都有自己的文件夹，如*图 2.4*所示：

![图 2.4 - 文件资源管理器中的 HelloWorld 项目](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.04_B17132.jpg)

图 2.4 - 文件资源管理器中的 HelloWorld 项目

在生成的解决方案的根目录中有一个名为`.vsconfig`的文件。该文件包含了与生成的项目一起使用所需的所有 Visual Studio 组件的列表。如果您按照*第一章*中介绍 Uno 平台的方式设置了您的环境，那么您将拥有所需的一切。但是，如果您看到*图 2.5*中的提示，请单击**安装**链接并添加缺少的工作负载：

![图 2.5 - 在 Visual Studio 中缺少组件的警告](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.05_B17132.jpg)

图 2.5 - 在 Visual Studio 中缺少组件的警告

在`Platforms`解决方案文件夹下，您将找到每个受支持平台的`C#`项目：

+   `HelloWorld.Droid.csproj` 用于 Android

+   `HelloWorld.iOS.csproj` 用于 iOS

+   `HelloWorld.macOS.csproj` 用于 macOS

+   `HelloWorld.Skia.Gtk.csproj` 用于带有 GTK 的 Linux

+   `HelloWorld.Skia.Tizen.csproj` 用于 Tizen

+   `HelloWorld.Skia.Wpf.csproj`：用于 Windows 7 和 Windows 8 的基本项目

+   `HelloWorld.Skia.Wpf.WpfHost.csproj`：用于 Windows 7 和 Windows 8 上的`HelloWorld.Skia.Wpf`项目的主机

+   `HelloWorld.UWP.csproj` 用于 Windows 10

+   `HelloWorld.Wasm.csproj` 用于 WebAssembly（WASM）

这些项目也被称为 iOS 的`UIApplication`，在 macOS 上创建和显示`NSApplication`，或在 WASM 上启动应用程序。

基于平台的一些特定设置和配置，例如应用程序所需的权限，将根据平台而异。一些平台允许您无任何限制地使用 API。相反，其他平台更加禁止，并要求您的应用程序事先指定这些 API 或要求用户授予权限，这是您必须在头项目中配置的内容。由于这些配置需要在各个头项目中完成，因此在不同平台上的体验将有所不同。在*第三章*中配置平台头时，我们将仅涵盖部分这些差异，*使用表单和数据*（Mac、WASM 和 UWP），以及*第四章*，*使您的应用程序移动*（Android 和 iOS）作为为这些平台开发应用程序的一部分。

与头项目相比，**共享项目**是几乎所有应用程序代码的所在地，包括页面和视图、应用程序的核心逻辑以及任何资源或图像等资产，这些资产将在每个平台上使用。共享项目被所有平台头引用，因此放在那里的任何代码都将在所有平台上使用。如果您不熟悉 C#共享项目，共享项目只不过是一个在编译引用共享项目的项目时将被包含的文件列表。

像我们的**Hello World**应用程序这样的新创建的跨平台应用程序已经在共享项目中带有一些文件：

+   `App.xaml.cs`：这是应用程序的入口点；它将加载 UI 并导航到`MainPage`。在这里，您还可以通过取消注释`InitializeLogging`函数中的相应行来配置事件的日志记录。

+   `App.xaml`：这包含了常见的 XAML 资源列表，如资源字典和主题资源。

+   `MainPage.xaml.cs`：这个文件包含了你的`MainPage`的 C#代码。

+   `MainPage.xaml`：这是您可以放置`MainPage`的 UI 的地方。

+   `Assets/SharedAssets.md`：这是一个演示资产文件，用于展示在 Uno 平台应用程序中如何使用资产。

+   `Strings/en/Resources.resw`：这也是一个演示资产文件，您可以使用它来开始在 Uno 平台应用程序中进行本地化。

现在您已经熟悉了您的第一个 Uno 平台应用程序的项目结构，让我们深入了解如何构建和运行您的应用程序。

# 构建和运行您的第一个 Uno 平台应用程序

既然您熟悉了 Uno 平台应用程序的结构，我们可以开始构建和运行您的第一个 Uno 平台应用程序了！在本节中，我们将介绍构建和运行应用程序的不同方法。

## 在 Windows 上使用 Visual Studio 运行和调试您的应用程序

从 Visual Studio 中运行您的 Uno 平台应用程序与运行常规的 UWP、`Xamarin.Forms`或 WASM 应用程序完全相同。要在特定设备或模拟器上构建和运行应用程序，可以从启动项目下拉菜单中选择相应的头。请注意，根据所选的配置、目标平台和架构，不是每个项目都会编译成预期的输出，甚至可能根本不会被编译。例如，UWP 项目始终针对明确的架构进行编译，因此在选择**任意 CPU**架构时将编译为 x86。这意味着并非所有目标架构和项目的组合都会编译成指定的内容，而是会退回到默认架构，例如在 UWP 的情况下是 x86。

要运行 UWP 应用程序，如果尚未选择**HelloWorld.UWP**项目作为启动项目，请从启动项目下拉菜单中选择**HelloWorld.UWP**，如*图 2.6*所示：

![图 2.6 - Visual Studio 中的配置、架构、启动项目和目标机器选项](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.06_B17132.jpg)

图 2.6 - Visual Studio 中的配置、架构、启动项目和目标机器选项

之后，选择适合您的计算机架构和要运行的运行配置、调试或发布。由于我们将在下一节中调试应用程序，请暂时选择**调试**。之后，您可以选择要部署到的目标设备，即本地计算机、连接的设备或模拟器。要做到这一点，请使用*图 2.7*中项目列表右侧的下拉菜单：

![图 2.7 - Visual Studio 中的 Android 模拟器列表](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.07_B17132.jpg)

图 2.7 - Visual Studio 中的 Android 模拟器列表

然后，您可以通过单击绿色箭头或按下*F5*来启动项目。应用程序将构建，然后您应该会看到类似*图 2.8*的东西：

![图 2.8 - 运行在 Windows 10 上的 HelloWorld 应用程序的屏幕截图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_2.08_B17132.jpg)

图 2.8 - 运行在 Windows 10 上的 HelloWorld 应用程序的屏幕截图

恭喜，您刚刚运行了您的第一个 Uno 平台应用程序！当然，在 Windows 上运行应用程序并不是开发跨平台应用程序的唯一部分。在 Android、iOS 和其他平台上运行和调试您的应用程序对于编写跨平台应用程序来说是至关重要的，以确保您的应用程序在所有支持的平台上都能正常运行。

对于 Android 开发，有多种不同的方法可以尝试和运行您的应用程序。一种可能性是使用 Visual Studio 附带的 Android 模拟器。为此，只需从目标列表下拉菜单中选择 Android 模拟器，如*图 2.7*所示。

注意

如果您还没有添加 Android 模拟器设备映像，您将只看到**Android 模拟器**作为选项。要了解如何添加和配置设备，Visual Studio 文档([`docs.microsoft.com/en-us/xamarin/android/get-started/installation/android-emulator/device-manager`](https://docs.microsoft.com/en-us/xamarin/android/get-started/installation/android-emulator/device-manager))介绍了如何创建新设备并根据您的需求进行配置。

如果您已将 Android 手机连接到计算机，它将显示在可用目标设备列表中。可以在*图 2.7*中看到 Samsung 设备的示例。

注意

为了获得与 Visual Studio 的最佳开发体验，在编辑 C#或 XAML 文件时，请确保 Visual Studio 将使用 UWP 头进行智能感知，否则智能感知可能无法正常工作。为此，在打开 C#或 XAML 文件时，从下拉菜单中选择已打开文件的选项卡名称下方的 UWP 头。

### 将 Windows 的 Visual Studio 与 Mac 配对

对于测试和调试 iOS 头，您可以直接在 Mac 上开发，我们将在下一节中介绍，或者您可以将 Windows 的 Visual Studio 与 Mac 配对，以远程调试 iOS 头。

在 Visual Studio 中的*使用.NET 进行移动开发*工作负载包括连接到 Mac 所需的软件。但是，需要三个步骤才能完全配置它：

1.  在 Mac 上安装**Xcode**和**Visual Studio for Mac**，并打开这些应用程序以确保安装了所有依赖项。

1.  在 Mac 上启用**远程登录**。

1.  从 Visual Studio 连接到 Mac。

在 Mac 上启用远程登录需要以下步骤：

1.  在**系统偏好设置**中打开**共享**窗格。

1.  检查**远程登录**并指定**允许访问的用户：**。

1.  根据提示更改防火墙设置。

要从 Visual Studio 连接，请执行以下操作：

+   转到**工具**>**iOS**>**配对到 Mac**。

+   如果您是第一次这样做，请选择**添加 Mac…**并输入 Mac 名称或 IP 地址，然后在提示时输入用户名和密码。

+   如果 Mac 已列出，请选择它并单击**连接**。

该工具将检查 Mac 上安装和可用的所有必需内容，然后打开连接。

如果出现问题，它将告诉您如何解决。

注意。

有关将 Visual Studio 配对到 Mac 以及解决可能遇到的任何问题的更详细说明，请访问[`docs.microsoft.com/xamarin/ios/get-started/installation/windows/connecting-to-mac/`](https://docs.microsoft.com/xamarin/ios/get-started/installation/windows/connecting-to-mac/)。

现在，Visual Studio 已成功与您的 Mac 配对，您可以从 Windows 机器调试应用程序，并在远程 iOS 模拟器上运行它。

## 使用 Visual Studio for Mac 运行和调试应用程序

如果您主要在 Mac 上工作，使用 Visual Studio for Mac 是开发 Uno 平台应用程序的最简单方法。

使用 Visual Studio for Mac 运行 Uno 平台应用程序与运行其他应用程序相同。您需要在启动项目列表中选择正确的头项目（例如，`HelloWorld.macOS`或`HelloWorld.iOS`），选择正确的目标架构来运行应用程序，并选择设备或模拟器来运行应用程序。

当然，除了在本地机器上运行应用程序之外，您还可以在模拟器上运行 Android 或 iOS 应用程序。您可以在 Windows 的 Visual Studio 中将任何适用的设备作为目标，包括任何模拟器或仿真器。

由于 Uno 平台应用程序的 WASM 版本的调试将在 Visual Studio 和 Visual Studio for Mac 之外进行，我们将在下一节中介绍这一点。

## 调试应用程序的 WASM 头

在撰写本文时，从 Visual Studio 或 Visual Studio for Mac 内部调试 WASM 的支持并不是很好，但是有替代选项。因此，当使用 Visual Studio for Windows 或 Visual Studio for Mac 时，WASM 的调试体验将在浏览器中进行。为了获得最佳的调试体验，我们建议使用最新的 Google Chrome Canary 版本。这可以从[`www.google.com/chrome/canary/`](https://www.google.com/chrome/canary/)获取。由于 WASM 的调试仍处于实验阶段，因此可能会发生变化，我们强烈建议访问官方文档([`platform.uno/docs/articles/debugging-wasm.html`](https://platform.uno/docs/articles/debugging-wasm.html))获取最新信息。您可以在这里了解有关使用 Visual Studio 调试 WASM 头的更多信息：[`platform.uno/blog/debugging-uno-platform-webassembly-apps-in-visual-studio-2019/`](https://platform.uno/blog/debugging-uno-platform-webassembly-apps-in-visual-studio-2019/)。

或者，您可以使用 Visual Studio Code 来调试应用程序的 WASM 版本。为了获得最佳体验，您应该使用`dotnet new`CLI 创建 Uno Platform 应用程序。您必须包括`–vscodeWasm`标志，如下所示，因为它将添加您可以在 Visual Studio Code 中使用的构建配置：

```cs
dotnet new unoapp -o HelloWorld -ios=false -android=false 
 -macos=false -uwp=false --vscodeWasm
```

请注意，通过前面的`dotnet new`命令，我们选择了不使用其他头部，因为在撰写本文时，只有 WASM 版本可以在 Visual Studio Code 中进行调试。

如果您已经创建了应用程序，请按照文档中显示的步骤进行操作[`platform.uno/docs/articles/get-started-vscode.html#updating-an-existing-application-to-work-with-vs-code`](https://platform.uno/docs/articles/get-started-vscode.html#updating-an-existing-application-to-work-with-vs-code)。当您的项目中已经存在其他平台的头部时，这也适用。

要使用 Visual Studio 启动应用程序并进行调试，首先使用`dotnet restore`恢复 NuGet 包。之后，您需要启动开发服务器。要做到这一点，打开 Visual Studio Code 左侧的三角形图标，显示**运行和调试**面板，如*图 2.9*所示：

![图 2.9 - Visual Studio Code 的运行和调试视图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.09_B17132.jpg)

图 2.9 - Visual Studio Code 的运行和调试视图

单击箭头，将运行**.NET Core Launch**配置，该配置将构建应用程序并启动开发服务器。开发服务器将托管您的应用程序。检查终端输出，以查看您可以在本地计算机上访问 WASM 应用程序的 URL，如*图 2.10*所示：

![图 2.10 - 开发服务器的终端输出](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.10_B17132.jpg)

图 2.10 - 开发服务器的终端输出

如果您只想启动应用程序并在没有调试功能的情况下继续，那么您已经完成了。但是，如果您想利用调试和断点支持，您还需要选择**在 Chrome 中的.NET Core Debug Uno Platform WebAssembly**配置。在**运行和调试**面板中选择启动配置后，启动它，这将启动调试服务器。然后，调试服务器会打开一个浏览器窗口，其中包含您的 Uno Platform WASM 应用程序。

注意

默认情况下，调试服务器将使用最新的稳定版 Google Chrome 启动。如果您没有安装稳定版的 Google Chrome，服务器将无法启动。如果您希望改用最新的稳定版 Edge，可以更新`.vscode/launch.json`文件，并将`pwa-chrome`更改为`pwa-msedge`。

调试服务器启动并准备好接收请求后，它将根据您的配置在 Chrome 或 Edge 中打开网站。您在 Visual Studio Code 中放置的任何断点都将被浏览器所尊重，并暂停您的 WASM 应用程序，类似于在非 WASM 项目上使用 Visual Studio 时断点的工作方式。

成功完成这些步骤后，您可以在所选的浏览器中打开应用程序，它将看起来像*图 2.11*：

![图 2.11–在浏览器中运行的 HelloWorld 应用程序](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.11_B17132.jpg)

图 2.11–在浏览器中运行的 HelloWorld 应用程序

现在我们已经介绍了运行和调试应用程序，让我们快速介绍一下使用 Uno Platform 进行开发的两个非常有用的功能：XAML Hot Reload 和 C#编辑和继续。

## XAML Hot Reload 和 C#编辑和继续

为了使开发更加简单和快速，特别是 UI 开发，Uno Platform 在使用 Visual Studio 进行开发时支持 XAML Hot Reload 和 C#编辑和继续。XAML Hot Reload 允许您修改视图和页面的 XAML 代码，运行的应用程序将实时更新，而 C#编辑和继续允许您修改 C#代码，而无需重新启动应用程序以捕获更改。

由于您的应用程序的 UWP 头部是使用 UWP 工具链构建的，因此您可以使用 XAML Hot Reload 和 C#编辑和继续。由于在撰写本文时，UWP 是唯一支持两者的平台，因此我们将使用 UWP 来展示它。其他平台不支持 C#编辑和继续，但是支持 XAML Hot Reload。

### XAML Hot Reload

要尝试 XAML Hot Reload，请在共享项目中打开`MainPage.xaml`文件。页面的内容将只是一个`Grid`和一个`TextBlock`：

```cs
<Grid Background="{ThemeResource 
                   ApplicationPageBackgroundThemeBrush}">
    <TextBlock Text="Hello, world!"
        Margin="20" FontSize="30" />
</Grid>
```

现在让我们通过用**Hello from hot reload!**替换文本来更改我们的页面，保存文件（*Ctrl* + *S*），我们的应用程序现在看起来像*图 2.12*所示，而无需重新启动应用程序！

![图 2.12–我们的 HelloWorld 应用程序使用 XAML Hot Reload 更改](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_2.12_B17132.jpg)

图 2.12–我们的 HelloWorld 应用程序使用 XAML Hot Reload 更改

XAML Hot Reload 可以在 UWP、iOS、Android 和 WebAssembly 上运行。但是，并非所有类型的更改都受支持，例如，更改控件的事件处理程序不受 XAML Hot Reload 支持，需要应用程序重新启动。除此之外，更新`ResourceDictionary`文件也不会更新应用程序，需要应用程序重新启动。

### C#编辑和继续

有时，您还需要对“*code-behind*”进行更改，这就是 C#编辑和继续将成为您的朋友的地方。请注意，您需要使用应用程序的 UWP 头部，因为它是唯一支持 C#编辑和继续的平台。在继续尝试 C#编辑和继续之前，您需要添加一些内容，因为我们的 HelloWorld 应用程序尚不包含太多 C#代码。首先，您需要关闭调试器和应用程序，因为 C#编辑和继续不支持以下代码更改。通过将`MainPage`内容更改为以下内容，更新您的页面以包含具有`Click`事件处理程序的按钮：

```cs
<StackPanel Background="{ThemeResource 
                   ApplicationPageBackgroundThemeBrush}">
    <TextBlock x:Name="helloTextBlock"
         Text="Hello from hot reload!" Margin="20"
         FontSize="30" />
    <Button Content="Change text"
        Click="ChangeTextButton_Click"/>
</StackPanel>
```

现在，在您的`MainPage`类中，添加以下代码：

```cs
private void ChangeTextButton_Click(object sender,
                                    RoutedEventArgs e)
{
    helloTextBlock.Text = "Hello from code behind!";
}
```

当您运行应用程序并单击按钮时，文本将更改为**Hello from code behind!**。现在单击*图 2.13*中突出显示的**全部中断**按钮，或按*Ctrl* + *Alt* + *Break*：

![图 2.13–全部中断按钮](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.13_B17132.jpg)

图 2.13–全部中断按钮

您的应用程序现在已暂停，您可以对 C#代码进行更改，当您通过单击`Click`事件处理程序来恢复应用程序时，这些更改将被捕获为`Hello from C# Edit and Continue!`：

```cs
private void ChangeTextButton_Click(object sender,
                                    RoutedEventArgs e)
{
    helloTextBlock.Text = 
        "Hello from C# Edit and Continue!";
}
```

然后恢复应用程序。如果现在点击按钮，文本将更改为**Hello from C# Edit and Continue!**。

但是，对于编辑和继续，有一些限制；并非所有代码更改都受支持，例如，更改对象的类型。有关不受支持更改的完整列表，请访问官方文档（[`docs.microsoft.com/en-us/visualstudio/debugger/supported-code-changes-csharp`](https://docs.microsoft.com/en-us/visualstudio/debugger/supported-code-changes-csharp)）。请注意，在撰写本文时，C#编辑和继续仅在 UWP 和 Skia 头部的 Windows 上运行。

现在我们已经讨论了构建和运行应用程序，让我们谈谈条件代码，即特定于平台的 C#和 XAML。

# 特定于平台的 XAML 和 C#

虽然 Uno 平台允许您在任何平台上运行应用程序，而无需担心底层特定于平台的 API，但仍然存在一些情况，您可能希望编写特定于平台的代码，例如访问本机平台 API。

## 特定于平台的 C#

编写特定于平台的 C#代码类似于编写特定于架构或特定于运行时的 C#代码。Uno 平台附带了一组编译器符号，这些符号将在为特定平台编译代码时定义。这是通过使用预处理器指令实现的。预处理器指令只有在为编译设置了符号时，编译器才会尊重它们，否则编译器将完全忽略预处理器指令。

在撰写本文时，Uno 平台附带了以下预处理器指令：

+   `NETFX_CORE`用于 UWP

+   `__ANDROID__`用于 Android

+   `__IOS__`用于 iOS

+   `HAS_UNO_WASM`（或`__WASM__`）用于使用 WebAssembly 的 Web

+   `__MACOS__`用于 macOS

+   `HAS_UNO_SKIA`（或`__SKIA__`）用于基于 Skia 的头

请注意，WASM 和 Skia 有两个不同的符号可用。两者都是有效的，除了它们的名称之外没有区别。

您可以像使用`DEBUG`一样使用这些符号，甚至可以组合它们，例如`if __ANDROID__ || __ MACOS__`。让我们在之前的示例中尝试一下，并使用 C#符号使`TextBlock`元素指示我们是在桌面、网络还是移动设备上：

```cs
private void ChangeTextButton_Click(object sender,
                                    RoutedEventArgs e)
{
#if __ANDROID__ || __IOS__
    helloTextBlock.Text = "Hello from C# on mobile!";
#elif HAS__UNO__WASM
    helloTextBlock.Text = "Hello from C# on WASM!";
#else
    helloTextBlock.Text = "Hello from C# on desktop!";
#endif
}
```

如果您运行应用程序的 UWP 头并单击按钮，然后文本将更改为设置的`NETFX_CORE`符号。现在，如果您在 Android 或 iOS 模拟器（或设备）上运行应用程序并单击按钮，它将显示`__ANDROID__`或`__IOS__`符号。

## 特定于平台的 XAML

虽然特定于平台的 C#代码很棒，但也有一些情况需要在特定平台上呈现控件。这就是特定于平台的 XAML 前缀发挥作用的地方。XAML 前缀允许您仅在特定平台上呈现控件，类似于 UWP 的条件命名空间。

在撰写本文时，您可以使用以下 XAML 前缀：

![图 2.14 - 命名空间前缀表，支持的平台及其命名空间 URI](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.14_B17132.jpg)

图 2.14 - 命名空间前缀表，支持的平台及其命名空间 URI

要在 XAML 中包含特定的 XAML 前缀，您必须在 XAML 文件的顶部与所有其他命名空间声明一起添加`xmlns:[prefix-name]=[namespace URI]`。**前缀名称**是 XAML 前缀（*图 2.14*中的第 1 列），而**命名空间 URI**是应与之一起使用的命名空间的 URI（*图 2.14*中的第 3 列）。

对于将从 Windows 中排除的前缀，您需要将前缀添加到`mc:Ignorable`列表中。这些前缀是`android`、`ios`、`wasm`、`macos`、`skia`、`xamarin`、`netstdref`、`not_netstdref`和`not_win`，因此所有不在`http://schemas.microsoft.com/winfx/2006/xaml/presentation`中的前缀。

现在让我们尝试一下通过更新我们的 HelloWorld 项目来使用一些平台 XAML 前缀，使`TextBlock`元素仅在 WASM 上呈现。为此，我们将首先将前缀添加到我们的`MainPage.xaml`文件中（请注意，我们省略了一些定义）：

```cs
<Page
    x:Class="HelloWorld.MainPage"
    ... 
    xmlns:win="http ://schemas.microsoft.com/winfx/2006/xaml/
             presentation"
    xmlns:android="http ://uno.ui/android"
    xmlns:ios="http ://uno.ui/ios"
    xmlns:wasm="http ://uno.ui/wasm"
    xmlns:macos="http ://uno.ui/macos"
    xmlns:skia="http ://schemas.microsoft.com/winfx/2006/xaml/
              presentation"
    ...
    mc:Ignorable="d android ios wasm macos skia">
    ...
</Page>
```

由于 Android、iOS、WASM、macOS 和 Skia XAML 前缀将在 Windows 上被排除，因此我们需要将它们添加到`mc:Ignorable`列表中。这是因为它们不是标准 XAML 规范的一部分，否则将导致错误。添加它们后，我们可以添加仅在应用程序在特定平台上运行时呈现的控件，例如 WASM 或 iOS。要尝试这一点，我们将添加一个`TextBlock`元素来欢迎用户：

```cs
<StackPanel>
     <TextBlock x:Name="helloTextBlock"
         Text="Hello World!" Margin="20"
         FontSize="30" />
     <win:TextBlock Text="Welcome on Windows!"/>
     <android:TextBlock Text="Welcome on Android!"/>
     <ios:TextBlock Text="Welcome on iOS!"/>
     <wasm:TextBlock Text="Welcome on WASM!"/>
     <macos:TextBlock Text="Welcome on Mac OS!"/>
     <skia:TextBlock Text="Welcome on Skia!"/>
     <Button Content="Change test"
         Click="ChangeTextButton_Click"/>
</StackPanel>
```

现在，如果您启动应用程序的 WASM 头并在浏览器中打开应用程序（如果尚未打开），应用程序将显示`TextBlock`元素，如*图 2.15*左侧所示。如果您现在启动应用程序的 UWP 头，应用程序将显示**欢迎使用 Windows！**，如*图 2.15*右侧所示：

![图 2.15 - 使用 WASM（左）和使用 UWP（右）运行的 HelloWorld 应用程序](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.15_B17132.jpg)

图 2.15 - 使用 WASM（左）和使用 UWP（右）运行的 HelloWorld 应用程序

如果您在跨目标库中使用 XAML 前缀，例如`跨目标库（Uno 平台）`项目模板，这将在下一节中介绍，XAML 前缀的行为会略有不同。由于跨目标库的工作方式，`wasm`和`skia`前缀将始终计算为 false。跨目标库的一个示例是`跨运行时库`项目类型，我们将在下一节中介绍。这是因为两者都编译为.NET Standard 2.0，而不是 WASM 或 Skia 头。除了这些前缀，您还可以使用`netstdref`前缀，其命名空间 URI 为`http://uno.ui/netstdref`，如果在 WASM 或 Skia 上运行，则计算为 true。此外，还有`not_netstdref`前缀，其命名空间 URI 为`http://uno.ui/not_netstdref`，它与`netstdref`完全相反。请注意，您需要将这两个前缀都添加到`mc:Ignorable`列表中。现在您已经了解了使用 C#编译器符号和 XAML 前缀编写特定于平台的代码，让我们来看看其他项目类型。

# 超越默认的跨平台应用程序结构

到目前为止，我们已经创建了一个包含每个平台头的跨平台应用程序。但是，您还可以使用不同的项目类型来编写 Uno 平台应用程序，我们将在本节中介绍。

注意

如果您现在使用`dotnet` CLI，请打开终端并运行`dotnet new -i Uno.ProjectTemplates.Dotnet`，因为我们将在本章的其余部分中使用这些内容。

## 多平台库项目类型

除了**多平台应用程序（Uno 平台）**项目类型之外，最重要的项目类型之一是**跨平台库（Uno 平台）**类型。**跨平台库（Uno 平台）**项目类型允许您编写可以被 Uno 平台应用程序使用的代码。了解项目类型的最简单方法是创建一个新的跨平台库。我们将通过在现有的 HelloWorld 解决方案中创建一个新项目来实现这一点。

注意

为了能够使用`dotnet new` CLI 安装的所有项目模板，您需要允许 Visual Studio 在项目类型列表中包含`dotnet new`模板。您可以通过在**工具 > 选项**下打开**环境**下的**预览功能**部分，勾选**在新项目对话框中显示所有.NET Core 模板**来实现这一点。之后，您需要重新启动 Visual Studio 以使更改生效。

启用该选项后，重新启动 Visual Studio 并通过右键单击解决方案视图中的解决方案并单击**添加** > **新建项目**来打开新项目对话框。对话框将如*图 2.16*所示：

![图 2.16 - Visual Studio 中的添加新项目对话框](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_2.16_B17132.jpg)

图 2.16 - Visual Studio 中的添加新项目对话框

接下来，选择`HelloWorld.Helpers`。输入名称后，单击**创建**。

这将在您的解决方案中创建一个新的跨平台 Uno 平台库。在磁盘上，该库有自己的文件夹，以自己的名称命名，您的解决方案视图将如*图 2.17*所示：

![图 2.17 - HelloWorld 解决方案视图](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.17_B17132.jpg)

图 2.17 - HelloWorld 解决方案视图

现在让我们向我们的跨平台库添加一些代码。我们将把类`Class1`重命名为`Greetings`，并引入一个新的公共静态函数，名为`GetStandardGreeting`，它将返回字符串`"Hello from a cross-platform library!"`：

```cs
public class Greetings
{
    public static string GetStandardGreeting()
    {
        return "Hello from a cross-platform library!";
    }
}
```

除了创建库之外，您还必须在要在其中使用该项目的每个头项目中添加对它的引用。添加对库的引用的过程对所有头项目都是相同的，这就是为什么我们只会向您展示如何向 UWP 头添加引用。

要向 UWP 头添加引用，请在“解决方案资源管理器”中右键单击 UWP 项目。在上下文菜单中，您将找到**添加**类别，其中包含**引用…**选项，该选项也显示在*图 2.18*中：

![图 2.18 - 添加|引用…选项，用于 UWP 头](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.18_B17132.jpg)

图 2.18 - 添加|引用…选项，用于 UWP 头

单击**引用…**后，将打开一个新对话框，您可以在其中选择要添加的引用。在我们的情况下，您需要选择该项目，如*图 2.19*所示：

![图 2.19 - UWP 头的参考管理器](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_2.19_B17132.jpg)

图 2.19 - UWP 头的参考管理器

在检查了`HelloWorld.Helpers`项目后，单击**确定**以保存更改。现在我们可以在应用程序的 UWP 版本中使用我们的库。让我们更新平台条件代码部分的事件处理程序，以使用 Greetings 辅助类，如下所示：

```cs
private void ChangeTextButton_Click(object sender,
                                    RoutedEventArgs e)
{
#if __ANDROID__ || __IOS__
    helloTextBlock.Text = "Hello from C# on mobile!";
#elif __WASM__
    helloTextBlock.Text = "Hello from C# on WASM!";
#else
    helloTextBlock.Text=
        HelloWorld.Helpers.Greetings.GetStandardGreeting();
#endif
}
```

如果现在运行 UWP 版本的应用程序并单击按钮，应用程序将在`HelloWorld 命名空间`中显示`Helpers 命名空间`。这是因为我们尚未从 macOS 头添加对库的引用。对于您计划在其中使用库的任何平台，您都需要在该平台的头中添加对库的引用。该过程也适用于作为 NuGet 包引用的库；您需要在要在其中使用库的每个平台头中添加对 NuGet 包的引用。与 Uno 平台应用程序项目不同，其中大部分源代码位于共享项目中，**跨平台库**项目类型是一个多目标项目。

## 其他项目类型

除了跨平台库项目类型，还有其他 Uno 平台项目模板。我们将在本节中广泛介绍它们。要能够从 Visual Studio 中创建它们，请按照上一节所示，启用在 Visual Studio 中显示`dotnet`新模板。

如果您已经熟悉使用 XAML 和 MVVM 模式进行应用程序开发，您可能已经了解 Prism ([`prismlibrary.com/`](https://prismlibrary.com/))，这是一个框架，用于构建“松散耦合、可维护和可测试的 XAML 应用程序”。Uno 平台模板中还包括**跨平台应用程序（Prism）（Uno 平台）**模板，它将创建一个 Prism Uno 平台应用程序。创建 Prism Uno 平台应用程序与创建“普通”多平台 Uno 应用程序相同。

除了 Uno 平台 Prism 应用程序模板之外，还有一个 Uno 平台模板，用于构建**WinUI 3**应用程序。但是，您可以创建一个使用 Windows 10 预览版 WinUI 3 的 Uno 平台应用程序。要使用 WinUI 3 创建 Uno 平台应用程序，在新项目对话框中，选择**跨平台应用程序（WinUI）（Uno 平台）**模板。

另一个将会很有用的项目类型，特别是在开发将使用 NuGet 进行发布的库时，是**跨运行时库（Uno 平台）**项目类型，它将创建一个跨运行时库。与跨平台库不同，Skia 和 WASM 版本不会分别构建，也无法区分，跨运行时库将为 WASM 和 Skia 分别编译项目，允许使用 XAML 前缀和编译器符号编写特定于 WASM 和 Skia 的代码。

除此之外，我们还有**跨平台 UI 测试库**。跨平台 UI 测试库允许您编写可以在多个平台上运行的 UI 测试，只需使用一个代码库。由于我们将在《第七章》中更全面地介绍测试，即《测试您的应用程序》，我们将在那里介绍该项目类型。

最后但并非最不重要的是，我们将在《第八章》中涵盖使用 WebAssembly 和 Uno 平台将`Xamarin.Forms`应用程序部署到 Web 上，即《部署您的应用程序并进一步》。

# 总结

在本章中，您学会了如何创建、构建和运行您的第一个 Uno 平台应用程序，并了解了一般解决方案结构以及平台头的工作原理。我们还介绍了如何使用 Visual Studio 和 Visual Studio Code 在不同平台上构建、运行和调试应用程序。除此之外，您还学会了如何使用 XAML 热重载和 C#编辑和继续功能，以使开发更加轻松。

在接下来的部分中，我们将为 UnoBookRail 编写应用程序，该公司运营 UnoBookCity 的公共交通。我们将从《第三章》开始，即《使用表单和数据》，为 UnoBookRail 编写一个任务管理应用程序，该应用程序允许在桌面和 Web 上输入、过滤和编辑数据。


# 第二部分：编写和开发 Uno 平台应用程序

在接下来的四章中，我们将介绍四个不同的应用程序，展示 Uno 平台构建的应用程序可用的不同功能。这些应用程序是为同一个虚构的业务（UnoBookRail）创建的，该业务是虚构城市（UnoBookCity）的公共交通管理局的一部分。

该业务负责城市轻轨网络中使用的所有技术。轻轨网络是电力驱动的只运载乘客的火车，在世界许多城市存在。它们被称为地铁、快速交通、地铁、地铁、地下铁路、地铁和许多其他名称。

不用担心，你不需要了解这些火车或它们是如何运行的。下图显示了网络地图，让你了解我们在谈论什么。你会看到主线从机场向西沿着河流前进。当它到达城市中心时，它会沿着海岸向北和向南分支。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Section2unobookcity-map.jpg)

UnoBookRail 网络站点的地图

这四个应用程序将展示 Uno 平台如何用于创建不同场景的应用程序，并展示在适当场景中使用不同功能。

在本节中，我们包括以下章节：

+   *第三章*, *使用表单和数据*

+   *第四章*, *使您的应用程序移动化*

+   *第五章*, *使您的应用程序准备好面对现实世界*

+   *第六章*, *在图表中显示数据和使用自定义 2D 图形*


# 第三章：使用表单和数据

在这一章中，我们将为虚构公司 UnoBookRail 编写我们的第一个应用程序，该应用程序将针对桌面和 Web 进行定位。我们将编写一个典型的**业务线**（LOB）应用程序，允许我们查看、输入和编辑数据。除此之外，我们还将介绍如何以 PDF 格式导出数据，因为这是 LOB 应用程序的常见要求。

在本章中，我们将涵盖以下主题：

+   编写以桌面为重点的 Uno 平台应用程序

+   编写表单并验证用户输入

+   在您的 Uno 平台应用程序中使用 Windows 社区工具包

+   以编程方式生成 PDF 文件

到本章结束时，您将创建一个以桌面为重点的应用程序，也可以在 Web 上运行，显示数据，允许您编辑数据，并以 PDF 格式导出数据。

# 技术要求

本章假设您已经设置好了开发环境，并安装了项目模板，就像我们在*第一章*中介绍的那样，*介绍 Uno 平台*。本章的源代码可以在[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter03`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/Chapter03)找到。

本章的代码使用了以下库：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary)。

查看以下视频以查看代码的运行情况：[`bit.ly/3fWYRai`](https://bit.ly/3fWYRai)

# 介绍应用程序

在本章中，我们将构建 UnoBookRail **ResourcePlanner**应用程序，该应用程序将在 UnoBookRail 内部使用。UnoBookRail 的员工将能够使用这个应用程序来管理 UnoBookRail 内部的任何资源，比如火车和车站。在本章中，我们将开发应用程序的问题管理部分。虽然这个应用程序的真实版本会有更多的功能，但在本章中，我们只会开发以下功能：

+   创建一个新问题

+   显示问题列表

+   以 PDF 格式导出问题

由于这个应用程序是一个典型的业务线应用程序，该应用程序将针对 UWP、macOS 和 WASM。让我们继续创建这个应用程序。

## 创建应用程序

让我们开始创建应用程序的解决方案：

1.  在 Visual Studio 中，使用**多平台应用程序（Uno 平台）**模板创建一个新项目。

1.  将项目命名为**ResourcePlanner**。如果您愿意，也可以使用其他名称，但在本章中，我们将假设项目名为**ResourcePlanner**。

1.  删除除**UWP**、**macOS**和**WASM**之外的所有项目头。

1.  为了避免写更多的代码，我们需要从[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/tree/main/SharedLibrary)下载共享库项目，并添加引用。为此，在`UnoBookRail.Common.csproj`文件中右键单击解决方案节点，然后单击**打开**。

1.  现在我们已经将项目添加到解决方案中，我们需要在特定于平台的项目中添加对库的引用。为此，在**解决方案资源管理器**中右键单击**UWP**项目节点，选择**添加 > 引用... > 项目**，选中**UnoBookRail.Common**条目，然后单击确定。*对 macOS 和 WASM 项目重复此过程*。

1.  最后，在`LinkerConfig.xml`文件的闭合链接标签之前添加以下代码，在`LinkerConfig.xml`文件中告诉 WebAssembly 链接器包括编译源代码中的类型，即使这些类目前没有被使用。如果我们不指定这些条目，那么程序集中定义的类型将不会被包括，因为链接器会删除代码。这是因为它找不到直接的引用。当使用其他包或库时，您可能还需要为这些库指定条目。不过，在本章中，前面的条目就足够了。

对于我们的应用程序，我们将使用**Model-View-ViewModel**（**MVVM**）模式。这意味着我们的应用程序将主要分为三个区域：

+   **Model**：**Model**包含应用程序的数据和业务逻辑。例如，这将处理从数据库加载数据或运行特定业务逻辑。

+   **ViewModel**：**ViewModel**充当视图和模型之间的层。它以适合视图的方式呈现应用程序的数据，提供视图与模型交互的方式，并通知视图模型的更改。

+   **View**：**View**代表用户的数据，并负责屏幕上的表示内容。

为了使开发更容易，我们将使用**Microsoft.Toolkit.MVVM**包，现在我们将添加它。这个包帮助我们编写我们的 ViewModel，并处理 XAML 绑定所需的样板代码：

1.  首先，在**解决方案**视图中右键单击解决方案节点，然后选择**管理解决方案的 NuGet 包...**。

1.  现在，搜索**Microsoft.Toolkit.MVVM**，并从列表中选择该包。

1.  从项目列表中选择**macOS**、**UWP**和**WASM**项目，然后单击**安装**。

1.  由于我们稍后会使用它们，还要创建三个名为**Models**、**ViewModels**和**Views**的文件夹。为此，在**ResourcePlanner.Shared**共享项目中右键单击，选择**添加 > 新文件夹**，并命名为**Models**。对于**ViewModels**和**Views**，重复此过程。

现在我们已经设置好了项目，让我们从向我们的应用程序添加第一部分代码开始。与业务应用程序一样，我们将使用**MenuBar**控件作为切换视图的主要方式：

1.  首先，在**ViewModels**文件夹中创建一个名为**NavigationViewModel**的新类。

1.  现在，用以下代码替换`NavigationViewModel.cs`文件中的代码：

```cs
using Microsoft.Toolkit.Mvvm.ComponentModel;
using Microsoft.Toolkit.Mvvm.Input;
using System.Windows.Input;
using Windows.UI.Xaml;
namespace ResourcePlanner.ViewModels
{
    public class NavigationViewModel :
        ObservableObject
    {
        private FrameworkElement content;
        public FrameworkElement Content
        {
            Get
            {
                return content;
            }
            Set
            {
                SetProperty(ref content, value);
            }
        }
        public ICommand Issues_OpenNewIssueViewCommand
            { get; }
        public ICommand Issues_ExportIssueViewCommand 
            { get; }
        public ICommand Issues_OpenAllIssuesCommand {
            get; }
        public ICommand Issues_OpenTrainIssuesCommand
            { get; }
        public ICommand 
            Issues_OpenStationIssuesCommand { get; }
        public ICommand Issues_Open OtherIssuesCommand
            { get; }
        public NavigationViewModel()
        {
            Issues_OpenNewIssueViewCommand = 
                new RelayCommand(() => { });
            Issues_ExportIssueViewCommand = 
                new RelayCommand(() => { });
            Issues_OpenAllIssuesCommand =
                new RelayCommand(() => { });
            Issues_OpenAllTrainIssuesCommand = 
                new RelayCommand(() => { });
            Issues_OpenAllStationIssuesCommand =
                new RelayCommand(() =>{ });
            Issues_OpenAllOtherIssuesCommand = 
                new RelayCommand(() =>{ });
        }
    }
}
```

这是处理导航到不同控件的类。随着我们在本章后面实现更多视图，我们将更新`Command`对象，使其指向正确的视图。

1.  现在，在`MainPage`类中添加以下代码：

```cs
using ResourcePlanner.ViewModels;
...
private NavigationViewModel navigationVM = new NavigationViewModel();
```

这将在`MainPage`类中添加一个`NavigationViewModel`对象，我们可以在 XAML 中绑定它。

1.  最后，用以下内容替换您的`MainPage.xaml`文件的内容：

```cs
    ...
    xmlns:muxc="using:Microsoft.UI.Xaml.Controls">
    <Grid Background="{ThemeResource 
        ApplicationPageBackgroundThemeBrush}">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <muxc:MenuBar>
            <muxc:MenuBar.Items>
                <muxc:MenuBarItem Title="Issues">
                    <MenuFlyoutItem Text="New" 
                        Command="{x:Bind
                        navigationVM.Issues_
                        OpenNewIssueViewCommand}"/>
                    <MenuFlyoutItem Text="Export to 
                        PDF" Command="{x:Bind 
                        navigationVM.Issues_
                        ExportIssueViewCommand}"/>
                    <MenuFlyoutSeparator/>
                    <MenuFlyoutItem Text="All" 
                        Command="{x:Bind 
                        navigationVM.Issues_
                        OpenAllIssuesCommand}"/>
                    <MenuFlyoutItem Text="Train 
                        issues" Command="{x:Bind 
                        navigationVM.Issues_
                        OpenTrainIssuesCommand}"/>
                    <MenuFlyoutItem Text="Station 
                        issues" Command="{x:Bind 
                        navigationVM.Issues_
                        OpenStationIssuesCommand}"/>
                    <MenuFlyoutItem Text="Other 
                         issues" Command="{x:Bind 
                         navigationVM.Issues_
                         OpenOtherIssuesCommand}"/>
                </muxc:MenuBarItem>
                <muxc:MenuBarItem Title="Trains"
                    IsEnabled="False"/>
                <muxc:MenuBarItem Title="Staff"
                    IsEnabled="False"/>
                <muxc:MenuBarItem Title="Depots"
                    IsEnabled="False"/>
                <muxc:MenuBarItem Title="Stations"
                    IsEnabled="False"/>
            </muxc:MenuBar.Items>
        </muxc:MenuBar>
        <ContentPresenter Grid.Row="1"
            Content="{x:Bind navigationVM.Content,
                Mode=OneWay}"/>
    </Grid>
```

此代码添加了`MenuBar`，用户可以使用它导航到不同的视图。底部的`ContentPresenter`用于显示导航到的内容。

现在，如果启动应用程序，您将看到类似以下的内容：

![图 3.1 - 运行带有 MenuBar 导航的 ResourcePlanner 应用程序](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Author_Figure_3.01_B17132.jpg)

图 3.1 - 运行带有 MenuBar 导航的 ResourcePlanner 应用程序

在下一节中，我们将向应用程序添加第一个视图，允许用户创建新问题。

# 输入和验证数据

业务应用程序的典型要求是输入数据并为所述数据提供输入验证。Uno 平台提供了各种不同的控件，允许用户输入数据，除了支持 Uno 平台的数十个库。

注意

在撰写本文时，尚无内置的输入验证支持，但 Uno 平台计划支持输入验证。这是因为目前 UWP 和 WinUI 3 都不完全支持输入验证。要了解有关即将到来的输入验证支持的更多信息，请查看 WinUI 存储库中的以下问题：[`github.com/microsoft/microsoft-ui-xaml/issues/179`](https://github.com/microsoft/microsoft-ui-xaml/issues/179)。Uno 平台正在跟踪此问题的进展：[`github.com/unoplatform/uno/issues/4839`](https://github.com/unoplatform/uno/issues/4839)。

为了使我们的开发过程更加简单，首先让我们添加对 Windows 社区工具包控件的引用：

1.  首先，在**解决方案**视图中右键单击解决方案节点，然后选择**管理解决方案的 NuGet 包…**。

1.  搜索**Microsoft.Toolkit.UI.Controls**并选择该包。

1.  在项目列表中选择**UWP**头，并单击**安装**。

1.  对**Microsoft.Toolkit.UI.Controls.DataGrid**包重复*步骤 2*和*3*。

1.  现在，搜索**Uno.Microsoft.Toolkit.UI.Controls**并选择该包。

注意

虽然 Windows 社区工具包仅支持 UWP，但由于 Uno 平台团队的努力，我们也可以在所有支持的平台上在 Uno 平台应用程序中使用 Windows 社区工具包。Uno 平台团队根据原始包维护了与 Uno 平台兼容的 Windows 社区工具包版本，并相应地更新它们。

1.  从项目列表中选择**macOS**和**WASM**头，并单击**安装**。

1.  最后，对**Uno.Microsoft.Toolkit.UI.Controls.DataGrid**包重复*步骤 5*和*6*。

这使我们能够在应用程序中使用 Windows 社区工具包控件。由于我们还希望在 macOS 和 WASM 上使用这些控件，因此我们还安装了这两个包的 Uno 平台版本。由于我们添加了**Windows 社区工具包**控件包，我们可以开始创建“创建问题”视图：

1.  首先，在`Models`文件夹内创建`IssueRepository.cs`类，并将以下代码添加到其中：

```cs
using System.Collections.Generic;
using UnoBookRail.Common.Issues;
namespace ResourcePlanner.Models
{
    public class IssuesRepository
    {
        private static List<Issue> issues = new
            List<Issue>();
        public static List<Issue> GetAllIssues()
        {
            return issues;
        }
        public static void AddIssue(Issue issue)
        {
            issues.Add(issue);
        }
    }
}
```

这是收集问题的模型。在现实世界的应用程序中，此代码将与数据库或 API 通信以持久化问题，但为简单起见，我们只会将它们保存在列表中。

1.  接下来，在`ViewModels`文件夹中创建`CreateIssueViewModel.cs`类，并使用来自 GitHub 的以下代码：[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter03/ResourcePlanner.Shared/ViewModels/CreateIssueViewModel.cs`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter03/ResourcePlanner.Shared/ViewModels/CreateIssueViewModel.cs)

现在我们已经创建了必要的模型和视图模型，接下来我们将继续添加用户界面以创建新问题。

对于用户界面，我们将实现输入验证，因为这在业务应用程序的数据输入表单中是典型的。为此，我们将实现以下行为：如果用户单击“创建问题”按钮，我们将使用代码后台中的函数验证数据。如果我们确定数据有效，我们将创建一个新问题；否则，我们将在每个未通过自定义验证的字段下方显示错误消息。除此之外，我们将在输入更改时验证输入字段。

让我们继续创建用户界面：

1.  在`Views`文件夹内创建一个名为`CreateIssueView.xaml`的新`UserControl`，并用以下内容替换 XAML：

```cs
<UserControl
    x:Class="ResourcePlanner.Views.CreateIssueView"
     xmlns="http://schemas.microsoft.com/winfx/2006
           /xaml/presentation"
     xmlns:x="http://schemas.microsoft.com/
              winfx/2006/xaml" 
    xmlns:local="using:ResourcePlanner.Views"
    xmlns:d="http://schemas.microsoft.com/
            expression/blend/2008"
    xmlns:mc="http://schemas.openxmlformats.org/
             markup-compatibility/2006"
    xmlns:wctcontrols="using:Microsoft.Toolkit.
                       Uwp.UI.Controls"
    xmlns:wctui="using:Microsoft.Toolkit.Uwp.UI"
    xmlns:ubrcissues="using:UnoBookRail.Common.Issues"
    mc:Ignorable="d"
    d:DesignHeight="300"
    d:DesignWidth="400">
    <StackPanel Orientation="Vertical" Padding="20">
        <TextBlock Text="Create new issue"
            FontSize="24"/>
        <Grid ColumnSpacing="10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="200"/>
                <ColumnDefinition Width="200"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition />
                <RowDefinition />
            </Grid.RowDefinitions>
            <TextBox x:Name="TitleTextBox"
                Header="Title"
                Text="{x:Bind createIssueVM.Title,
                       Mode=TwoWay}"
                HorizontalAlignment="Stretch" 
                TextChanged="FormInput_TextChanged"/>
            <TextBlock x:Name="titleErrorNotification" 
                Grid.Row="1"Foreground="{ThemeResource
                    SystemErrorTextColor}"/>
            <ComboBox Header="Type" Grid.Column="1"
                ItemsSource="{wctui:EnumValues 
                    Type=ubrcissues:IssueType}"
                HorizontalAlignment="Stretch"
                SelectedItem="{x:Bind 
                    createIssueVM.IssueType, 
                    Mode=TwoWay}"/>
        </Grid>
        <TextBox Header="Description"
            Text="{x:Bind createIssueVM.Description,
                Mode=TwoWay}"
            MinWidth="410" MaxWidth="800" 
            HorizontalAlignment="Left"/>
        <Button Content="Create new issue"
            Margin="0,20,0,0" Width="410" 
            HorizontalAlignment="Left"
            Click="CreateIssueButton_Click"/>
    </StackPanel>
</UserControl>
```

这是一个基本的用户界面，允许用户输入标题和描述，并让用户选择问题的类型。请注意，我们在文本输入下方添加了一个`TextBlock`控件，以便在提供的输入无效时向用户显示错误消息。除此之外，我们还为`Title`添加了一个`TextChanged`监听器，以便在文本更改时更新错误消息。

1.  现在，用以下代码替换`CreateIssueView.xaml.cs`文件的内容：

```cs
using ResourcePlanner.ViewModels;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
namespace ResourcePlanner.Views
{
    public sealed partial class CreateIssueView :
        UserControl
    {
        private CreateIssueViewModel createIssueVM;
        public CreateIssueView(CreateIssueViewModel
            viewModel)
        {
            this.createIssueVM = viewModel;
            this.InitializeComponent();
        }
        private void FormInput_TextChanged(object 
            sender, TextChangedEventArgs args)
        {
            EvaluateFieldsValid(sender);
        }
        private bool EvaluateFieldsValid(object
            sender)
        {
            bool allValid = true;
            if(sender == TitleTextBox || sender ==
               null)
            {
                if (TitleTextBox.Text.Length == 0)
                {
                    allValid = false;
                    titleErrorNotification.Text = 
                        "Title must not be empty.";
                }
                Else
                {
                    titleErrorNotification.Text = "";
                }
            }
            return allValid;
        }
        private void CreateIssueButton_Click(object
            sender, RoutedEventArgs args)
        {
            if (EvaluateFieldsValid(null))
            {                
                createIssueVM.CreateIssueCommand.
                    Execute(null);
            }
        }
    }
}
```

使用这段代码，我们现在在输入字段的文本更改或用户点击`CreateIssueCommand`时，将运行输入验证。

1.  最后，在`NavigationViewModel.cs`文件中，用以下代码替换`Issues_OpenNewIssueViewCommand`对象的创建，并添加必要的`using`语句。这样，当命令被调用时，`CreateIssueView`将被显示：

```cs
Issues_OpenNewIssueViewCommand = new RelayCommand(() =>
{
     Content = new CreateIssueView(new 
         CreateIssueViewModel(this));
});
```

现在，如果您启动应用程序并单击**问题**下拉菜单中的**新问题**选项，您将看到类似以下*图 3.2*的内容：

![图 3.2 - 创建新问题界面](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_3.02_B17132.jpg)

图 3.2 - 创建新问题界面

如果您尝试单击**创建新问题**按钮，您将在标题输入字段下方看到一条简短的消息，指出“标题不能为空”。在**标题**字段中输入文本后，消息将消失。虽然我们已经添加了简单的输入，但现在我们将使用 Windows Community Toolkit 添加更多的输入选项。

## 使用 Windows Community Toolkit 控件

到目前为止，用户只能输入标题和描述，并选择问题的类型。但是，我们还希望允许用户根据问题的类型输入特定的数据。为此，我们将使用 Windows Community Toolkit 提供的控件之一：**SwitchPresenter**。**SwitchPresenter**控件允许我们根据已设置的属性呈现 UI 的特定部分，类似于 C#中的 switch case 的工作方式。

当然，**SwitchPresenter**不是来自 Windows Community Toolkit 的唯一控件；还有许多其他控件，例如**GridSplitter**，**MarkdownTextBlock**和**DataGrid**，我们将在*使用 DataGrid 显示数据*部分中使用。由于我们在本章的早些时候已经安装了必要的软件包，我们将向用户界面添加控件。让我们开始吧：

1.  在`CreateIssueView.xaml`的描述`TextBox`控件下方添加以下 XAML 代码：

```cs
<wctcontrols:SwitchPresenter Value="{x:Bind createIssueVM.IssueType, Mode=OneWay}">
    <wctcontrols:SwitchPresenter.SwitchCases>
        <wctcontrols:Case Value="{x:Bind
            ubrcissues:IssueType.Train}">
            <StackPanel Orientation="Horizontal"
                Spacing="10">
                <StackPanel MinWidth="410" 
                    MaxWidth="800">
                    <TextBox x:Name=
                        "TrainNumberTextBox" 
                        Header="Train number" 
                        Text="{x:Bind
                          createIssueVM.TrainNumber,
                            Mode=TwoWay}"
                        HorizontalAlignment="Stretch"
                        TextChanged=
                          "FormInput_TextChanged"/>
                    <TextBlock x:Name=
                        "trainNumberErrorNotification"
                        Foreground="{ThemeResource 
                          SystemErrorTextColor}"/>
                </StackPanel>
            </StackPanel>
        </wctcontrols:Case>
        <wctcontrols:Case Value="{x:Bind 
            ubrcissues:IssueType.Station}">
            <StackPanel MinWidth="410" MaxWidth="800"
                HorizontalAlignment="Left">
                <TextBox x:Name="StationNameTextBox"
                  Header="Station name" Text="{x:Bind
                    createIssueVM.StationName,
                      Mode=TwoWay}"
                    HorizontalAlignment="Stretch"
                        TextChanged=
                            "FormInput_TextChanged"/>
                <TextBlock x:Name=
                    "stationNameErrorNotification" 
                        Foreground="{ThemeResource
                            SystemErrorTextColor}"/>
            </StackPanel>
        </wctcontrols:Case>
        <wctcontrols:Case Value="{x:Bind 
            ubrcissues:IssueType.Other}">
            <StackPanel MinWidth="410" MaxWidth="800"
                HorizontalAlignment="Left">
                <TextBox x:Name="LocationTextBox" 
                    Header="Location" Text="{x:Bind
                        createIssueVM.Location, 
                            Mode=TwoWay}"
                    HorizontalAlignment="Stretch"
                        TextChanged=
                            "FormInput_TextChanged"/>
                <TextBlock x:Name=
                    "locationErrorNotification"
                        Foreground="{ThemeResource 
                            SystemErrorTextColor}"/>
            </StackPanel>
        </wctcontrols:Case>
    </wctcontrols:SwitchPresenter.SwitchCases>
</wctcontrols:SwitchPresenter>
```

这使我们能够根据用户选择的问题类型显示特定的输入字段。这是因为`SwitchPresenter`根据已设置的`Value`属性呈现特定的`Case`。由于我们将其绑定到 ViewModel 的`IssueType`属性，所以每当用户更改问题类型时，它都会相应地更新。请注意，只有在我们将模式指定为`OneWay`时，此绑定才有效，因为`x:Bind`的默认绑定模式是`OneTime`，因此不会更新。

1.  现在，在`CreateIssueViewModel.xaml.cs`中的`EvaluateFields`函数的返回语句之前添加以下代码：

```cs
if (sender == TrainNumberTextBox || sender == null)
{
    if (TrainNumberTextBox.Text.Length == 0)
    {
        if (createIssueVM.IssueType ==
            UnoBookRail.Common.Issues.IssueType.Train)
        {
            allValid = false;
        }
        trainNumberErrorNotification.Text = 
            "Train number must not be empty.";
    }
    else
    {
        trainNumberErrorNotification.Text = "";
    }
}
if (sender == StationNameTextBox || sender == null)
{
    if (StationNameTextBox.Text.Length == 0)
    {
        if (createIssueVM.IssueType ==
          UnoBookRail.Common.Issues.IssueType.Station)
        {
            allValid = false;
        }
        stationNameErrorNotification.Text = 
            "Station name must not be empty.";
    }
    else
    {
        stationNameErrorNotification.Text = "";
    }
}
if (sender == LocationTextBox || sender == null)
{
    if (LocationTextBox.Text.Length == 0)
    {
        if (createIssueVM.IssueType == 
            UnoBookRail.Common.Issues.IssueType.Other)
        {
            allValid = false;
        }
        locationErrorNotification.Text = 
            "Location must not be empty.";
    }
    else
    {
        locationErrorNotification.Text = "";
    }
}
```

现在，我们的输入验证也将考虑到新增的输入字段。请注意，只有当与问题相关的输入不符合验证过程时，我们才会阻止创建问题。例如，如果问题类型是`Train`，我们将忽略位置文本是否通过验证，用户可以创建新问题，无论位置输入是否通过验证阶段。

现在，如果您启动应用程序并导航到**创建新问题**视图，您将看到类似以下*图 3.3*的内容：

![图 3.3 - 更新的问题创建视图。左：选择了问题 Train 类型；右：选择了问题 Station 类型](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_3.03_B17132.jpg)

图 3.3 - 更新的问题创建视图。左：选择了问题 Train 类型；右：选择了问题 Station 类型

当您更改问题类型时，您会注意到表单会更改，并根据问题类型显示正确的输入字段。虽然我们允许用户创建新问题，但我们目前无法显示它们。在下一节中，我们将通过添加新视图来改变这一点，以显示问题列表。

# 使用 DataGrid 显示数据

由于 UnoBookRail 员工将使用此应用程序来管理现有问题，对于他们来说，查看所有问题以便轻松了解其当前状态非常重要。虽然没有内置的 UWP 和 Uno Platform 控件可以轻松实现这一点，但幸运的是，Windows Community Toolkit 包含了适合这种情况的正确控件：**DataGrid**。

**DataGrid**控件允许我们将数据呈现为表格，指定要显示的列，并允许用户根据列对表格进行排序。然而，在开始使用**DataGrid**控件之前，我们需要创建 ViewModel 并准备视图：

1.  首先，在`ViewModels` `Solution`文件夹中创建一个名为`IssueListViewModel.cs`的新类，并向其中添加以下代码：

```cs
using System.Collections.Generic;
using UnoBookRail.Common.Issues;
namespace ResourcePlanner.ViewModels
{
    public class IssueListViewModel
    {
        public readonly IList<Issue> Issues;
        public IssueListViewModel(IList<Issue> issues)
        {
            this.Issues = issues; 
        }
    }
}
```

由于我们只想显示问题的一个子集，例如导航到列车问题列表时，要显示的问题列表将作为构造函数参数传递。

1.  现在，在`Views`文件夹中创建一个名为`IssueListView.xaml`的新`UserControl`。

1.  最后，在`NavigationViewModel`类的构造函数中，用以下代码替换创建`Issues_OpenAllIssuesCommand`，`Issues_OpenTrainIssuesCommand`，`Issues_OpenTrainIssuesCommand`和`Issues_OpenTrainIssuesCommand`对象：

```cs
Issues_OpenAllIssuesCommand = new RelayCommand(() =>
{
    Content = new IssueListView(new IssueListViewModel
        (IssuesRepository.GetAllIssues()), this);
});
Issues_OpenTrainIssuesCommand = new RelayCommand(() =>
{
    Content = new IssueListView(new IssueListViewModel
        (IssuesRepository.GetAllIssues().Where(issue
            => issue.IssueType == 
                IssueType.Train).ToList()), this);
});
Issues_OpenStationIssuesCommand = new RelayCommand(() =>
{
    Content = new IssueListView(new IssueListViewModel
        (IssuesRepository.GetAllIssues().Where(issue
            => issue.IssueType == 
                IssueType.Station).ToList()), this);
});
Issues_OpenOtherIssuesCommand = new RelayCommand(() =>
{
    Content = new IssueListView(new IssueListViewModel
        (IssuesRepository.GetAllIssues().Where(issue 
            => issue.IssueType == 
                IssueType.Other).ToList()), this);
});
```

这使用户可以在用户从导航中单击相应元素时导航到问题列表，同时确保我们只显示与导航选项相关的列表中的问题。请注意，我们选择使用内联 lambda 创建命令。但是，您也可以声明函数并使用它们来创建`RelayCommand`对象。

现在我们已经添加了必要的 ViewModel 并更新了`NavigationViewModel`以允许我们导航到问题列表视图，我们可以继续编写我们的问题列表视图的 UI。

## 使用 DataGrid 控件显示数据

在我们实现问题列表视图之前，让我们快速介绍一下我们将使用的 DataGrid 的基本功能。有两种方法可以开始使用 DataGrid：

+   让 DataGrid 自动生成列。这样做的缺点是，列标题将使用属性名称，除非您在`AutoGeneratingColumn`内部更改它们。虽然它们对于开始使用 DataGrid 控件是很好的，但通常不是最佳选择。此外，使用此方法，您无法选择要显示的列；相反，它将显示所有列。

+   通过手动指定要包含的属性来指定要包含的属性。这种选项的优点是我们可以控制要包含的属性，并且还可以指定列名。当然，这也意味着我们必须确保我们的绑定是正确的，这是潜在的错误原因。

通过设置 DataGrid 的`Columns`属性并提供`DataGridColumn`对象的集合来指定 DataGrid 的列。对于某些数据类型，已经有内置的列可以使用，例如`DataGridTextColumn`用于基于文本的数据。每列都允许您通过指定`Header`属性以及用户是否可以通过`CanUserSort`属性对列进行排序来自定义显示的标题。对于没有内置`DataGridColumn`类型的更复杂数据，您还可以实现自己的`DataGridColumn`对象。或者，您还可以使用`DataGridTemplateColumn`，它允许您基于指定的模板呈现单元格。为此，您可以指定一个`CellTemplate`对象，用于呈现单元格，并一个`CellEditTemplate`对象，用于让用户编辑当前单元格的值。

除了指定列之外，DataGrid 控件还有更多您可以自定义的功能。例如，DataGrid 允许您选择行并自定义行和单元格背景。现在，让我们继续编写我们的问题列表。

现在我们已经介绍了 DataGrid 的基础知识，让我们继续编写我们的问题列表显示界面：

1.  为此，请将以下代码添加到`IssueListView.xaml.cs`文件中：

```cs
using Microsoft.Toolkit.Uwp.UI.Controls;
using ResourcePlanner.ViewModels;
using UnoBookRail.Common.Issues;
using Windows.UI.Xaml.Controls;
namespace ResourcePlanner.Views
{
    public sealed partial class IssueListView :
        UserControl
    {
        private IssueListViewModel issueListVM;
        private NavigationViewModel navigationVM;
        public IssueListView(IssueListViewModel
            viewModel, NavigationViewModel 
                navigationViewModel)
        {
            this.issueListVM = viewModel;
            this.navigationVM = navigationViewModel;
            this.InitializeComponent();
        }
        private void IssueList_SelectionChanged(object
            sender, SelectionChangedEventArgs e)
        {
            navigationVM.SetSelectedIssue((sender as 
                DataGrid).SelectedItem as Issue);
        }
    }
}
```

这允许我们从 DataGrid 创建到问题列表的绑定。请注意，我们还将添加一个`SelectionChanged`处理程序函数，以便我们可以通知`NavigationViewModel`是否已选择问题。我们这样做是因为某些选项只有在选择问题时才有意义。其中一个选项是**导出为 PDF**选项，我们将在*以 PDF 格式导出问题*部分中实现。

1.  将以下 XAML 命名空间定义添加到`IssueListView.xaml`文件中：

```cs
xmlns:wct="using:Microsoft.Toolkit.Uwp.UI.Controls"
```

1.  现在，请用以下 XAML 替换`IssueListView.xaml`文件中的`Grid`：

```cs
<wct:DataGrid
    SelectionChanged="IssueList_SelectionChanged"
    SelectionMode="Single"
    AutoGenerateColumns="False"
    ItemsSource="{x:Bind 
        issueListVM.Issues,Mode=OneWay}">
    <wct:DataGrid.Columns>
        <wct:DataGridTextColumn Header="Title"
            Binding="{Binding Title}" 
           IsReadOnly="True" CanUserSort="True"/>
        <wct:DataGridTextColumn Header="Type"
            Binding="{Binding IssueType}" 
            IsReadOnly="True" CanUserSort="True"/>
        <wct:DataGridTextColumn Header="Creator" 
            Binding="{Binding OpenedBy.FormattedName}"
            IsReadOnly="True" CanUserSort="True"/>
        <wct:DataGridTextColumn Header="Created on" 
            Binding="{Binding OpenDate}" 
            IsReadOnly="True" CanUserSort="True"/>
        <wct:DataGridCheckBoxColumn Header="Open" 
            Binding="{Binding IsOpen}" 
            IsReadOnly="True" CanUserSort="True"/>
        <wct:DataGridTextColumn Header="Closed by" 
            Binding="{Binding ClosedBy.FormattedName}"
            IsReadOnly="True" CanUserSort="True"/>
        <wct:DataGridTextColumn Header="Closed on" 
            Binding="{Binding CloseDateReadable}" 
            IsReadOnly="True" CanUserSort="True"/>
    </wct:DataGrid.Columns>
</wct:DataGrid>
```

在这里，我们为问题的最重要字段添加了列。请注意，我们只允许更改标题，因为其他字段需要比 DataGrid 表格布局更容易显示的更多逻辑。由于在这种情况下不支持`x:Bind`，我们使用`Binding`将属性绑定到列。

现在，如果您启动应用程序并创建一个问题，您将看到类似于以下*图 3.4*的内容：

![图 3.4 - DataGrid 显示演示问题](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_3.04_B17132.jpg)

图 3.4 - DataGrid 显示演示问题

在本节中，我们只涵盖了使用 Windows Community Toolkit DataGrid 控件的基础知识。如果您希望了解更多关于 DataGrid 控件的信息，官方文档包含了涵盖不同可用 API 的实际示例。您可以在这里找到更多信息：[`docs.microsoft.com/en-us/windows/communitytoolkit/controls/datagrid`](https://docs.microsoft.com/en-us/windows/communitytoolkit/controls/datagrid)。现在我们可以显示现有问题列表，接下来我们将编写问题的 PDF 导出。作为其中的一部分，我们还将学习如何编写一个自定义的 Uno Platform 控件，我们将仅在 Web 上使用。

# 以 PDF 格式导出问题

除了能够在业务应用程序的界面中查看数据之外，通常还希望能够导出数据，例如作为 PDF，以便可以打印或通过电子邮件发送。为此，我们将编写一个允许用户将给定问题导出为 PDF 的接口。由于没有内置的 API 可用，我们将使用**iText**库。请注意，如果您想在应用程序中使用该库，您需要遵循 AGPL 许可证或购买该库的商业许可证。但是，在我们编写生成 PDF 的代码之前，我们需要准备项目：

1.  首先，我们需要安装**iText** NuGet 包。为此，请右键单击解决方案并搜索**iText**。选择该包。然后，从项目列表中选择**macOS**、**UWP**和**WASM**头，并单击**安装**。

1.  现在，在`ViewModels`文件夹中创建一个名为`ExportIssueViewModel.cs`的类，其中包含以下代码：

```cs
using iText.Kernel.Pdf;
using iText.Layout;
using iText.Layout.Element;
using Microsoft.Toolkit.Mvvm.Input;
using System;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Windows.Input;
using UnoBookRail.Common.Issues;
namespace ResourcePlanner.ViewModels
{
    public class ExportIssueViewModel
    {
        public readonly Issue Issue;
        public ICommand SavePDFClickedCommand;
        public ExportIssueViewModel(Issue issue)
        {
            Issue = issue;
            SavePDFClickedCommand = 
               new RelayCommand(async () => { });
        }
    }
}
```

请注意，我们现在添加这些`using`语句，因为我们稍后在本节中会用到它们。

1.  现在，在**Views**文件夹中创建一个名为`ExportIssueView.xaml`的新`UserControl`。

1.  请用以下内容替换`ExportIssueView.xaml.cs`中的代码：

```cs
using ResourcePlanner.ViewModels;
using Windows.UI.Xaml.Controls;
namespace ResourcePlanner.Views
{
    public sealed partial class ExportIssueView : 
        UserControl
    {
        private ExportIssueViewModel exportIssueVM;
        public ExportIssueView(ExportIssueViewModel 
            viewModel)
        {
            this.exportIssueVM = viewModel;
            this.InitializeComponent();
        }
    }
}
```

1.  请用 GitHub 上的代码替换`ExportIssueView.xaml`中的代码：

[`github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter03/ResourcePlanner.Shared/Views/ExportIssueView.xaml`](https://github.com/PacktPublishing/Creating-Cross-Platform-C-Sharp-Applications-with-Uno-Platform/blob/main/Chapter03/ResourcePlanner.Shared/Views/ExportIssueView.xaml)

1.  最后，在`NavigationViewModel.cs`文件中用以下代码替换`Issue_ExportIssueViewCommand`的创建：

```cs
Issues_ExportIssueViewCommand = new RelayCommand(() =>
{
    Content = new ExportIssueView(new 
        ExportIssueViewModel(this.selectedIssue));
});
```

现在我们已经添加了必要的接口，接下来我们将编写将问题导出为 PDF 的代码。由于桌面上的行为与网络上的行为不同，我们将先介绍桌面版本。

## 在桌面上导出

由于我们已经编写了用户界面，允许用户导出问题，唯一剩下的就是更新`ExportIssueViewModel`以生成 PDF 并为用户提供访问方式。在桌面上，我们将 PDF 文件写入本地文件系统并打开它。由于应用程序也是 UWP 应用程序，我们将文件写入应用程序的本地文件夹。现在，让我们更新`ExportIssueViewModel`：

1.  首先，在`ExportIsseuViewModel`类内创建一个名为`GeneratePDF`的新函数，代码如下：

```cs
public byte[] GeneratePDF()
{
    byte[] bytes;
    using (var memoryStream = new MemoryStream())
    {       
        bytes = memoryStream.ToArray();
    }
    return bytes;
}
```

1.  现在，在`using`块内的赋值之前添加以下代码：

```cs
var pdfWriter = new PdfWriter(memoryStream);
var pdfDocument = new PdfDocument(pdfWriter);
var document = new Document(pdfDocument);
document.Close();
```

这将创建一个新的`PdfWriter`和`PdfDocument`，它将使用`MemoryStream`对象写入到字节数组中。

1.  在添加`PDFWriter`，`PDFDocument`和`Document`之后，添加以下代码来编写文档的标题：

```cs
var header = new Paragraph("Issue export: " +
    Issue.Title)
     .SetTextAlignment(
        iText.Layout.Properties.TextAlignment.CENTER)
     .SetFontSize(20);
document.Add(header);
```

这将创建一个新的段落，其中包含文本“**问题导出：**”和问题的标题。它还设置了文本对齐和字体大小，以便更容易区分为文档的标题。

1.  由于我们还想导出有关问题的信息，请在调用`document.Close()`之前添加以下代码：

```cs
var issueType = new Paragraph("Type: " + Issue.IssueType);
document.Add(issueType);
switch (Issue.IssueType)
{
    case IssueType.Train:
        var trainNumber = new Paragraph("Train number: "
             + Issue.TrainNumber);
        document.Add(trainNumber);
        break;
    case IssueType.Station:
        var stationName = new Paragraph("Station name: "
             + Issue.StationName);
        document.Add(stationName);
        break;
    case IssueType.Other:
        var location = new Paragraph("Location: " + 
            Issue.Location);
        document.Add(issueType);
        break;
}
var description = new Paragraph("Description: " + Issue.Description);
document.Add(description);
```

这将根据问题的类型向 PDF 文档添加必要的段落。除此之外，我们还将问题的描述添加到 PDF 文档中。

注意

由于在向文档添加第一个元素时出现`NullReferenceException`的错误。不幸的是，在撰写本书时，没有已知的解决方法。这只会在调试器附加时发生，并且不会在应用程序运行时造成任何问题。在调试器附加时运行应用程序，您可以通过工具栏点击**继续**来继续调试应用程序。

1.  最后，用以下代码替换`SavePDFClickedCommand`的创建：

```cs
SavePDFClickedCommand = new RelayCommand(async () =>
{
#if !__WASM__
    var bytes = GeneratePDF();
    var tempFileName = 
        $"{Path.GetFileNameWithoutExtension
            (Path.GetTempFileName())}.pdf";
    var folder = Windows.Storage.ApplicationData.
        Current.TemporaryFolder;
    await folder.CreateFileAsync(tempFileName, 
        Windows.Storage.CreationCollisionOption.
            ReplaceExisting);
    var file = await
        folder.GetFileAsync(tempFileName);
    await Windows.Storage.FileIO.WriteBufferAsync
        (file, bytes.AsBuffer());
    await Windows.System.Launcher.LaunchFileAsync
        (file);
#endif
});
```

这将创建一个 PDF，将其保存到`apps`临时文件夹，并使用默认的 PDF 处理程序打开它。

注意

在本章中，我们将文件写入临时文件夹，并使用默认的 PDF 查看器打开它。根据您的应用程序和用例，`FileSavePicker`和其他文件选择器可能非常合适。您可以在这里了解更多关于`FileSavePicker`和其他可用文件选择器的信息：[`platform.uno/docs/articles/features/windows-storage-pickers.html`](https://platform.uno/docs/articles/features/windows-storage-pickers.html)。

要尝试问题导出，请启动应用程序并创建一个新问题。之后，从问题列表中选择问题，并从顶部的**问题**下拉菜单中单击**导出为 PDF**。现在，如果单击**创建 PDF**，PDF 将被创建。之后不久，PDF 将在您的默认 PDF 查看器中打开。PDF 应该看起来像这样：

![图 3.5 - 演示问题导出 PDF](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_3.05_B17132.jpg)

图 3.5 - 演示问题导出 PDF

由于在 WASM 上运行应用程序时无法将文件写入用户的本地文件系统，因此在接下来的部分中，我们将通过编写自定义 HTML 元素控件来更新我们的应用程序，以在 WASM 上提供下载链接，而不是使用**创建 PDF**按钮。

## 通过下载链接在网络上导出

Uno Platform 的主要功能是运行在所有平台上的代码，它还允许开发人员编写特定于平台的自定义控件。您可以利用这一点来使用特定于平台的控件。在我们的情况下，我们将使用它来创建一个 HTML `a-tag`，为我们应用程序的 WASM 版本提供下载链接。我们将使用`Uno.UI.Runtime.WebAssembly.HtmlElement`属性来实现这一点：

1.  首先，在`Views`文件夹中创建一个名为`WasmDownloadElement.cs`的新类，并添加以下代码：

```cs
using System;
using System.Collections.Generic;
using System.Text;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
namespace ResourcePlanner.Views
{
#if __WASM__
    [Uno.UI.Runtime.WebAssembly.HtmlElement("a")]
    public class WasmDownloadElement : ContentControl
    {
    }
#endif
}
```

这将是我们的`a`标签，我们将使用它来允许用户下载问题导出的 PDF。由于我们只希望在 WASM 上使用此控件，因此我们将其放在`#if __WASM__`预处理指令内。

1.  为了能够自定义下载的 MIME 类型和下载文件的名称，请将以下代码添加到`WasmDownloadElement`类中：

```cs
public static readonly DependencyProperty MimeTypeProperty = DependencyProperty.Register(
    "MimeType", typeof(string),
        typeof(WasmDownloadElement), new
        PropertyMetadata("application/octet-stream",
        OnChanged));
public string MimeType
{
    get => (string)GetValue(MimeTypeProperty);
    set => SetValue(MimeTypeProperty, value);
}
public static readonly DependencyProperty FileNameProperty = DependencyProperty.Register(
    "FileName", typeof(string),
        typeof(WasmDownloadElement), new 
        PropertyMetadata("filename.bin", OnChanged));
public string FileName
{
    get => (string)GetValue(FileNameProperty);
    set => SetValue(FileNameProperty, value);}
private string _base64Content;
public void SetBase64Content(string content)
{
    _base64Content = content;
    Update();
}
private static void OnChanged(DependencyObject dependencyobject, DependencyPropertyChangedEventArgs args)
{
    if (dependencyobject is WasmDownloadElement wd)
    {
        wd.Update();
    }
}
private void Update()
{
    if (_base64Content?.Length == 0)
    {
        this.ClearHtmlAttribute("href");
    }
    else
    {
        var dataUrl =
           $"data:{MimeType};base64,{_base64Content}";
        this.SetHtmlAttribute("href", dataUrl);
        this.SetHtmlAttribute("download", FileName);
    }
}
```

尽管这是很多代码，但我们只在`WasmDownloadElement`类上创建了两个`DependencyProperty`字段，即`MimeType`和`FileName`，并允许它们设置将要下载的内容。其余的代码处理在底层控件上设置正确的属性。

1.  最后，在`ExportIssueView`的构造函数中添加以下代码，调用`this.InitializeComponent()`后：

```cs
#if __WASM__
    this.WASMDownloadLink.MimeType =
       "application/pdf";
    var bytes = exportIssueVM.GeneratePDF();
    var b64 = Convert.ToBase64String(bytes);
    this.WASMDownloadLink.SetBase64Content(b64);
#endif
```

这将在下载链接上设置正确的 MIME 类型，并设置正确的内容进行下载。请注意，我们在本章前面在`ExportIssueView.xaml`文件中定义了`WASMDownloadLink`元素。

要测试这一点，请启动应用程序的 WASM 头。加载完成后，创建一个问题，然后从问题列表中选择它，然后通过**问题**选项点击**导出为 PDF**。现在，您应该看到**下载 PDF**选项，而不是**创建 PDF**按钮，如*图 3.6*所示：

![图 3.6 - 在 WASM 上导出 PDF](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/crt-xplat-cs-app-uno-plat/img/Figure_3.06_B17132.jpg)

图 3.6 - 在 WASM 上导出 PDF

点击链接后，PDF 导出将被下载。

# 总结

在本章中，我们构建了一个桌面应用程序，可以在 Windows、macOS 和 Web 上使用 WASM。我们介绍了如何编写带有输入验证的数据输入表单以及如何使用 Windows Community Toolkit。之后，我们学习了如何使用 Windows Community Toolkit DataGrid 控件显示数据。最后，我们介绍了如何以 PDF 格式导出数据，并通过编写自定义 HTML 控件提供了下载链接。

在下一章中，我们将构建一个移动应用程序。虽然它也将被设计用于 UnoBookRail 的员工使用，但主要重点将放在在移动设备上运行应用程序。除其他事项外，我们将利用这个应用程序来研究如何处理不稳定的连接以及使用设备功能，如相机。
